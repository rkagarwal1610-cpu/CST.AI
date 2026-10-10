import os, re, secrets, time, threading
import xml.etree.ElementTree as ET
from functools import wraps
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import requests

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY') or secrets.token_urlsafe(48)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax', SESSION_COOKIE_SECURE=os.environ.get('COOKIE_SECURE','true').lower() == 'true', PERMANENT_SESSION_LIFETIME=60*60*8)
SOAP_NS = 'http://schemas.xmlsoap.org/soap/envelope/'
SF_NS = 'urn:partner.soap.sforce.com'
API_VERSION = os.environ.get('SALESFORCE_API_VERSION', '65.0')
# Salesforce session IDs stay server-side; only a random key is stored in the browser cookie.
SF_SESSIONS = {}
LOCK = threading.Lock()


def xml_escape(s):
    return (str(s).replace('&','&amp;').replace('<','&lt;').replace('>','&gt;').replace('"','&quot;').replace("'",'&apos;'))


def soap_login(login_url, username, password, token):
    endpoint = login_url.rstrip('/') + '/services/Soap/u/64.0'
    envelope = f'''<?xml version="1.0" encoding="utf-8"?>
<env:Envelope xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:env="{SOAP_NS}">
<env:Body><n1:login xmlns:n1="{SF_NS}"><n1:username>{xml_escape(username)}</n1:username><n1:password>{xml_escape(password + token)}</n1:password></n1:login></env:Body></env:Envelope>'''
    r = requests.post(endpoint, data=envelope.encode(), headers={'Content-Type':'text/xml; charset=UTF-8','SOAPAction':'login'}, timeout=30)
    try: root = ET.fromstring(r.text)
    except ET.ParseError: r.raise_for_status(); raise RuntimeError('Salesforce returned an unreadable login response.')
    fault = root.find('.//{http://schemas.xmlsoap.org/soap/envelope/}Fault')
    if fault is not None:
        msg = fault.findtext('.//faultstring') or 'Salesforce authentication failed.'
        raise RuntimeError(msg[:500])
    r.raise_for_status()
    sid = root.findtext('.//{urn:partner.soap.sforce.com}sessionId')
    server = root.findtext('.//{urn:partner.soap.sforce.com}serverUrl')
    userinfo = root.find('.//{urn:partner.soap.sforce.com}userInfo')
    org = userinfo.findtext('{urn:partner.soap.sforce.com}organizationId') if userinfo is not None else None
    sf_username = userinfo.findtext('{urn:partner.soap.sforce.com}userName') if userinfo is not None else None
    user_id = userinfo.findtext('{urn:partner.soap.sforce.com}userId') if userinfo is not None else None
    if not sid or not server: raise RuntimeError('Salesforce login response did not contain a session.')
    return sid, server, org, sf_username, user_id


def current_sf():
    key = session.get('sf_key')
    if not key: return None
    with LOCK: return SF_SESSIONS.get(key)


def sf_request(method, path, params=None, json_body=None):
    sf = current_sf()
    if not sf: raise RuntimeError('Salesforce is not connected in this server session. Connect again; a Render restart may clear in-memory sessions.')
    m = re.match(r'^(https?://[^/]+)', sf['server_url'])
    if not m: raise RuntimeError('Invalid Salesforce server URL.')
    url = m.group(1) + path if path.startswith('/') else path
    r = requests.request(method, url, params=params, json=json_body,
        headers={'Authorization':'Bearer '+sf['session_id'], 'Accept':'application/json'}, timeout=60)
    if r.status_code == 401:
        raise RuntimeError('Salesforce session expired. Please reconnect.')
    if not r.ok:
        try: detail = r.json()
        except Exception: detail = r.text[:300]
        raise RuntimeError(f'Salesforce API error ({r.status_code}): {str(detail)[:600]}')
    return r.json() if r.content else {}


def query(soql): return sf_request('GET', f'/services/data/v{API_VERSION}/query', {'q':soql})
def describe(obj):
    if not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]*', obj or ''): raise RuntimeError('Invalid Salesforce object name.')
    return sf_request('GET', f'/services/data/v{API_VERSION}/sobjects/{obj}/describe')


def require_app_login(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get('app_user'): return jsonify(ok=False, error='Please sign in to the MIS application.'), 401
        return fn(*args, **kwargs)
    return wrapped

@app.get('/health')
def health(): return jsonify(status='ok', app='Salesforce MIS Cloud')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        data = request.get_json(silent=True) or request.form
        user = os.environ.get('APP_USERNAME','team')
        password = os.environ.get('APP_PASSWORD','')
        if not password: return jsonify(ok=False, error='Deployment is not configured: set APP_PASSWORD in hosting environment.'), 503
        if secrets.compare_digest(str(data.get('username','')), user) and secrets.compare_digest(str(data.get('password','')), password):
            session.clear(); session['app_user'] = user; session.permanent = True
            return jsonify(ok=True)
        return jsonify(ok=False, error='Invalid application username or password.'), 401
    if session.get('app_user'): return redirect('/')
    return render_template('login.html')

@app.post('/logout')
def logout():
    key=session.get('sf_key')
    if key:
        with LOCK: SF_SESSIONS.pop(key, None)
    session.clear()
    return jsonify(ok=True)

@app.get('/')
def index():
    if not session.get('app_user'): return redirect('/login')
    return render_template('index.html', connected=bool(current_sf()), app_user=session.get('app_user'))

@app.post('/connect')
@require_app_login
def connect():
    data=request.get_json(silent=True) or {}
    url=(data.get('url') or '').strip().rstrip('/')
    username=(data.get('username') or '').strip(); password=data.get('password') or ''; token=data.get('token') or ''
    if not all([url,username,password,token]): return jsonify(ok=False,error='Enter Salesforce URL, username, password and security token.'),400
    if not re.match(r'^https://[A-Za-z0-9.-]+(?::\d+)?$',url): return jsonify(ok=False,error='Enter a valid HTTPS Salesforce login URL.'),400
    try:
        sid, server_url, org_id, sf_username, sf_user_id = soap_login(url,username,password,token)
        key=session.get('sf_key') or secrets.token_urlsafe(32)
        # Replace any prior connection for this browser session only after SOAP login succeeds.
        with LOCK:
            SF_SESSIONS[key]={'session_id':sid,'server_url':server_url,'org_id':org_id,
                              'username':sf_username or username,'user_id':sf_user_id,'created':time.time()}
        session['sf_key']=key
        session.permanent=True
        # Verify the actual REST API session and permissions with a lightweight request.
        limits=sf_request('GET',f'/services/data/v{API_VERSION}/limits')
        return jsonify(ok=True,organization_id=org_id or 'Connected',
                       salesforce_username=sf_username or username, salesforce_user_id=sf_user_id,
                       api_version=API_VERSION, verified=True,
                       message='Salesforce login and REST API verification succeeded.')
    except Exception as e: return jsonify(ok=False,error=str(e)),400

@app.get('/status')
@require_app_login
def status():
    sf=current_sf()
    return jsonify(ok=True, app_user=session.get('app_user'), connected=bool(sf),
                   organization_id=(sf or {}).get('org_id'),
                   salesforce_username=(sf or {}).get('username'),
                   connected_at=(sf or {}).get('created'),
                   api_version=API_VERSION)

@app.get('/dashboard')
@require_app_login
def dashboard():
    if not current_sf(): return jsonify(ok=False,error='Connect Salesforce first.'),401
    # Keep counts as separate SOQL queries; SOQL does not support SQL CASE expressions in SUM.
    specs={
      'inward_today':("SELECT COUNT() FROM Case WHERE CreatedDate = TODAY",'Cases created today'),
      'resolved_today':("SELECT COUNT() FROM Case WHERE IsClosed = TRUE AND ClosedDate = TODAY",'Cases closed today'),
      'closed_yesterday':("SELECT COUNT() FROM Case WHERE IsClosed = TRUE AND ClosedDate = YESTERDAY",'Cases closed yesterday'),
      'open_now':("SELECT COUNT() FROM Case WHERE IsClosed = FALSE",'Open cases now'),
      'forward_today':("SELECT COUNT() FROM CaseHistory WHERE CreatedDate = TODAY AND Field = 'Owner'",'Owner changes today')
    }
    metrics={}; errors=[]
    for key,(soql,label) in specs.items():
        try:
            data=query(soql); metrics[key]={'label':label,'value':data.get('totalSize',0)}
        except Exception as e: metrics[key]={'label':label,'value':None,'error':str(e)}; errors.append(label+': '+str(e))
    # Agent load is calculated client-side from returned case records to avoid unsupported aggregate CASE logic.
    try:
        data=query("SELECT Id, CaseNumber, Subject, Status, IsClosed, OwnerId, Owner.Name, CreatedDate, ClosedDate, Priority, Account.Name, Type, Origin, Reason, LastModifiedDate FROM Case ORDER BY CreatedDate DESC LIMIT 2000")
        records=data.get('records',[]); agents={}
        for c in records:
            owner=(c.get('Owner') or {}).get('Name') or 'Unassigned'
            a=agents.setdefault(owner,{'agent':owner,'total_in_sample':0,'open_in_sample':0,'closed_in_sample':0})
            a['total_in_sample']+=1
            if c.get('IsClosed'): a['closed_in_sample']+=1
            else: a['open_in_sample']+=1
        metrics['agent_load']={'label':'Agent workload (latest 2,000 cases)','records':sorted(agents.values(),key=lambda x:x['open_in_sample'],reverse=True)}
        metrics['recent_cases']={'records':[{k:v for k,v in c.items() if k!='attributes'} for c in records[:100]]}
    except Exception as e: metrics['agent_load']={'records':[],'error':str(e)}; metrics['recent_cases']={'records':[]}; errors.append('Agent workload: '+str(e))
    # Yesterday closing is surfaced as closed yesterday here; opening/closing backlog is not inferred from this count.
    return jsonify(ok=True,metrics=metrics,errors=errors,notes=['Agent workload is based on the latest 2,000 cases returned by Salesforce.','Owner changes are a forwarding proxy; validate transfer rules and first-assigned-group attribution before using for official L1/L2 reporting.','Closed yesterday is not the same as yesterday end-of-day open backlog.'])

@app.get('/objects')
@require_app_login
def objects():
    if not current_sf(): return jsonify(ok=False,error='Connect Salesforce first.'),401
    try:
        data=sf_request('GET',f'/services/data/v{API_VERSION}/sobjects')
        rows=[{'name':o.get('name'),'label':o.get('label'),'labelPlural':o.get('labelPlural'),'custom':o.get('custom',False),'queryable':o.get('queryable',False)} for o in data.get('sobjects',[]) if o.get('queryable')]
        rows.sort(key=lambda x:(not x['custom'],(x['label'] or x['name'] or '').lower()))
        return jsonify(ok=True,objects=rows,count=len(rows))
    except Exception as e:return jsonify(ok=False,error=str(e)),400

@app.post('/describe')
@require_app_login
def describe_route():
    if not current_sf(): return jsonify(ok=False,error='Connect Salesforce first.'),401
    data=request.get_json(silent=True) or {}; obj=(data.get('object') or 'Case').strip()
    try:
        d=describe(obj); fields=[]; rels=[]
        for f in d.get('fields',[]):
            fields.append({'name':f.get('name'),'label':f.get('label') or f.get('name'),'type':f.get('type'),'custom':f.get('custom',False),'filterable':f.get('filterable',False),'sortable':f.get('sortable',False),'relationshipName':f.get('relationshipName'),'referenceTo':f.get('referenceTo') or []})
            if f.get('referenceTo'): rels.append({'fieldLabel':f.get('label') or f.get('name'),'apiName':f.get('name'),'relationshipName':f.get('relationshipName') or '', 'targets':f.get('referenceTo')})
        return jsonify(ok=True,object=d.get('name'),label=d.get('label'),fields=fields,relationships=rels)
    except Exception as e:return jsonify(ok=False,error=str(e)),400

@app.post('/data')
@require_app_login
def data_route():
    if not current_sf(): return jsonify(ok=False,error='Connect Salesforce first.'),401
    body=request.get_json(silent=True) or {}; obj=(body.get('object') or 'Case').strip(); limit=max(1,min(int(body.get('limit',100)),500))
    try:
        d=describe(obj); allowed={f.get('name'):f for f in d.get('fields',[]) if f.get('name')}
        requested=body.get('fields') or []
        if not requested: requested=[f['name'] for f in d.get('fields',[]) if f.get('name') and f.get('name') in ['Id','Name','CaseNumber','Subject','Status','IsClosed','OwnerId','CreatedDate','ClosedDate','Priority','AccountId','LastModifiedDate']]
        requested=[x for x in requested if x in allowed and not (allowed[x].get('type')=='address')][:80]
        if not requested: return jsonify(ok=False,error='Select at least one valid field.'),400
        soql='SELECT '+', '.join(requested)+' FROM '+obj+' LIMIT '+str(limit)
        result=query(soql); return jsonify(ok=True,object=obj,label=d.get('label'),fields=[{'name':x,'label':allowed[x].get('label') or x,'type':allowed[x].get('type')} for x in requested],records=result.get('records',[]),totalSize=result.get('totalSize',0),done=result.get('done',True))
    except Exception as e:return jsonify(ok=False,error=str(e)),400

@app.post('/soql')
@require_app_login
def soql_route():
    if not current_sf(): return jsonify(ok=False,error='Connect Salesforce first.'),401
    body=request.get_json(silent=True) or {}; soql=(body.get('soql') or '').strip()
    if not soql.upper().startswith('SELECT ') or ';' in soql: return jsonify(ok=False,error='Only a single read-only SELECT query is allowed.'),400
    if re.search(r'\b(INSERT|UPDATE|DELETE|UPSERT|MERGE|CALL|FIND)\b',soql,re.I): return jsonify(ok=False,error='Only read-only SELECT queries are allowed.'),400
    try:return jsonify(ok=True,result=query(soql))
    except Exception as e:return jsonify(ok=False,error=str(e)),400

@app.errorhandler(413)
def too_large(e): return jsonify(ok=False,error='Request too large.'),413

if __name__=='__main__':
    app.run(host='0.0.0.0',port=int(os.environ.get('PORT','5000')),debug=False)
