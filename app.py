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


def query(soql, max_records=50000):
    """Run read-only SOQL and follow Salesforce queryMore pages.

    Salesforce REST queries can return multiple pages. This helper combines them
    so dashboard counts and record-based calculations are not silently limited to
    the first response page. max_records is a safety cap for interactive use.
    """
    result = sf_request('GET', f'/services/data/v{API_VERSION}/query', {'q': soql})
    records = list(result.get('records', []) or [])
    done = bool(result.get('done', True))
    while not done and result.get('nextRecordsUrl') and len(records) < max_records:
        page = sf_request('GET', result['nextRecordsUrl'])
        records.extend(page.get('records', []) or [])
        done = bool(page.get('done', True))
        result = page
    # For aggregate COUNT() responses there are no row pages; totalSize is the count.
    result['records'] = records[:max_records]
    result['recordsFetched'] = len(result['records'])
    result['paginationComplete'] = done or len(records) >= max_records
    return result
def describe(obj):
    if not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]*', obj or ''): raise RuntimeError('Invalid Salesforce object name.')
    return sf_request('GET', f'/services/data/v{API_VERSION}/sobjects/{obj}/describe')

def first_assigned_group_api_name():
    """Resolve the Case field by label, or use an explicitly configured API name.

    Set FIRST_ASSIGNED_GROUP_FIELD in Render if Salesforce describe returns an
    ambiguous/no label match. This avoids guessing a custom field API name.
    """
    configured = os.environ.get('FIRST_ASSIGNED_GROUP_FIELD', '').strip()
    if configured:
        if not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]*', configured):
            raise RuntimeError('FIRST_ASSIGNED_GROUP_FIELD is not a valid Salesforce API field name.')
        return configured
    fields = describe('Case').get('fields', [])
    matches = [f.get('name') for f in fields
               if (f.get('label') or '').strip().casefold() == 'first assigned group' and f.get('name')]
    matches = list(dict.fromkeys(matches))
    if len(matches) == 1:
        return matches[0]
    if not matches:
        raise RuntimeError("Could not find a Case field labelled 'First Assigned Group'. Set FIRST_ASSIGNED_GROUP_FIELD in Render to its API name.")
    raise RuntimeError("Multiple Case fields are labelled 'First Assigned Group'. Set FIRST_ASSIGNED_GROUP_FIELD in Render to the correct API name.")


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
      'inward_today':(None,'Cases created today — ERP Helpdesk L1/L2'),
      'resolved_today':("SELECT COUNT() FROM Case WHERE IsClosed = TRUE AND ClosedDate = TODAY",'Cases closed today'),
      'closed_yesterday':("SELECT COUNT() FROM Case WHERE IsClosed = TRUE AND ClosedDate = YESTERDAY",'Cases closed yesterday'),
      'open_now':("SELECT COUNT() FROM Case WHERE IsClosed = FALSE",'Open cases now'),
      'forward_today':("SELECT COUNT() FROM CaseHistory WHERE CreatedDate = TODAY AND Field = 'Owner'",'Owner changes today')
    }
    metrics={}; errors=[]
    for key,(soql,label) in specs.items():
        try:
            if key == 'inward_today':
                group_field = first_assigned_group_api_name()
                # Match the two report filter values exactly; SOQL string values are escaped.
                group_values = "'ERP Helpdesk-L1','ERP Helpdesk-L2'"
                soql = f"SELECT COUNT() FROM Case WHERE CreatedDate = TODAY AND {group_field} IN ({group_values})"
            data=query(soql); metrics[key]={'label':label,'value':data.get('totalSize',0)}
        except Exception as e: metrics[key]={'label':label,'value':None,'error':str(e)}; errors.append(label+': '+str(e))
    # Agent workload uses a Salesforce aggregate across the full visible Case set,
    # rather than pretending the latest 2,000 records represent all cases.
    try:
        grouped = query(
            "SELECT OwnerId, IsClosed, COUNT(Id) caseCount "
            "FROM Case GROUP BY OwnerId, IsClosed"
        )
        owner_ids = list(dict.fromkeys(
            row.get('OwnerId') for row in grouped.get('records', []) if row.get('OwnerId')
        ))
        owner_names = {}
        for prefix, obj in (('005', 'User'), ('00G', 'Group')):
            ids = [oid for oid in owner_ids if oid.startswith(prefix)]
            for offset in range(0, len(ids), 100):
                batch = ids[offset:offset + 100]
                if not batch:
                    continue
                literals = ','.join("'" + x.replace("'", "\\'") + "'" for x in batch)
                try:
                    owner_result = query(f"SELECT Id, Name FROM {obj} WHERE Id IN ({literals})")
                    owner_names.update({r.get('Id'): r.get('Name') for r in owner_result.get('records', [])})
                except Exception:
                    # Continue with IDs if this owner type is not accessible.
                    pass
        agents = {}
        for row in grouped.get('records', []):
            owner_id = row.get('OwnerId')
            owner = owner_names.get(owner_id) or owner_id or 'Unassigned'
            closed = bool(row.get('IsClosed'))
            item = agents.setdefault(owner, {
                'agent': owner, 'total_cases': 0, 'open_cases': 0, 'closed_cases': 0
            })
            count = int(row.get('caseCount') or 0)
            item['total_cases'] += count
            if closed:
                item['closed_cases'] += count
            else:
                item['open_cases'] += count
        metrics['agent_load'] = {
            'label': 'Current case workload (all visible cases)',
            'records': sorted(agents.values(), key=lambda x: x['open_cases'], reverse=True),
            'source': 'SOQL aggregate'
        }
        recent = query(
            "SELECT Id, CaseNumber, Subject, Status, IsClosed, OwnerId, Owner.Name, "
            "CreatedDate, ClosedDate, Priority, Account.Name, Type, Origin, Reason, "
            "LastModifiedDate FROM Case ORDER BY CreatedDate DESC LIMIT 100"
        )
        metrics['recent_cases'] = {'records': recent.get('records', [])}
    except Exception as e:
        metrics['agent_load'] = {'records': [], 'error': str(e)}
        metrics['recent_cases'] = {'records': []}
        errors.append('Agent workload: ' + str(e))
    # Yesterday closing is surfaced as closed yesterday here; opening/closing backlog is not inferred from this count.
    return jsonify(ok=True,metrics=metrics,errors=errors,notes=['Agent workload counts are grouped across all Case records visible to the connected Salesforce user; they describe current ownership, not historical processed-ticket attribution.','New tickets today is filtered by First Assigned Group = ERP Helpdesk-L1 or ERP Helpdesk-L2; the field API name is resolved from the Case field label or FIRST_ASSIGNED_GROUP_FIELD.','Closed yesterday is not the same as yesterday end-of-day open backlog.'])


@app.get('/diagnostics')
@require_app_login
def diagnostics():
    """Compare Salesforce TODAY literals with explicit Asia/Kolkata boundaries.

    This endpoint is diagnostic only; it does not change dashboard counts.
    Salesforce report filters and report running-user context must still be
    compared separately with the connected user and report definition.
    """
    if not current_sf():
        return jsonify(ok=False, error='Connect Salesforce first.'), 401
    from datetime import datetime, timedelta, timezone
    from zoneinfo import ZoneInfo

    sf = current_sf() or {}
    now_ist = datetime.now(ZoneInfo('Asia/Kolkata'))
    start_ist = now_ist.replace(hour=0, minute=0, second=0, microsecond=0)
    end_ist = start_ist + timedelta(days=1)
    start_utc = start_ist.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    end_utc = end_ist.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

    checks = {
        'created_today_literal': "SELECT COUNT() FROM Case WHERE CreatedDate = TODAY",
        'created_yesterday_literal': "SELECT COUNT() FROM Case WHERE CreatedDate = YESTERDAY",
        'created_explicit_ist_day': (
            "SELECT COUNT() FROM Case WHERE CreatedDate >= " + start_utc +
            " AND CreatedDate < " + end_utc
        ),
        'open_now': "SELECT COUNT() FROM Case WHERE IsClosed = FALSE",
        'closed_today_literal': "SELECT COUNT() FROM Case WHERE IsClosed = TRUE AND ClosedDate = TODAY",
    }
    results = {}
    for name, soql in checks.items():
        try:
            result = query(soql)
            results[name] = {'count': result.get('totalSize'), 'soql': soql}
        except Exception as exc:
            results[name] = {'error': str(exc), 'soql': soql}

    user_info = {}
    user_id = sf.get('user_id')
    if user_id:
        try:
            u = sf_request('GET', f'/services/data/v{API_VERSION}/sobjects/User/{user_id}')
            for field in ('Id', 'Username', 'Name', 'TimeZoneSidKey', 'LocaleSidKey', 'LanguageLocaleKey', 'ProfileId', 'UserRoleId', 'IsActive'):
                if field in u: user_info[field] = u[field]
        except Exception as exc:
            user_info = {'error': str(exc)}

    return jsonify(
        ok=True,
        diagnostic_only=True,
        connected_username=sf.get('username'),
        organization_id=sf.get('org_id'),
        server_today_context='Salesforce SOQL TODAY literal',
        explicit_comparison_timezone='Asia/Kolkata',
        explicit_start_utc=start_utc,
        explicit_end_utc_exclusive=end_utc,
        generated_at_ist=now_ist.isoformat(),
        connected_user=user_info,
        checks=results,
        next_step='Compare these counts with the Salesforce report filters, date field, running user, and report time zone. Do not change official dashboard metrics until the report definition is matched.'
    )

@app.get('/reports')
@require_app_login
def reports_route():
    """List saved Salesforce reports visible to the connected user."""
    if not current_sf(): return jsonify(ok=False,error='Connect Salesforce first.'),401
    try:
        data=sf_request('GET',f'/services/data/v{API_VERSION}/analytics/reports')
        rows=[]
        for r in (data if isinstance(data,list) else data.get('reports', [])):
            rows.append({k:r.get(k) for k in ('id','name','format','folderName','ownerName','lastRunDate','namespace') if r.get(k) is not None})
        rows.sort(key=lambda x: ((x.get('folderName') or '').lower(),(x.get('name') or '').lower()))
        return jsonify(ok=True,reports=rows,count=len(rows),source='Salesforce Analytics Reports API')
    except Exception as e:
        return jsonify(ok=False,error='Could not list Salesforce reports. Confirm the connected user has report access and API access. '+str(e)),400

@app.get('/reports/<report_id>/describe')
@require_app_login
def report_describe_route(report_id):
    if not current_sf(): return jsonify(ok=False,error='Connect Salesforce first.'),401
    if not re.fullmatch(r'[A-Za-z0-9]{15,18}', report_id or ''):
        return jsonify(ok=False,error='Invalid Salesforce report ID.'),400
    try:
        data=sf_request('GET',f'/services/data/v{API_VERSION}/analytics/reports/{report_id}/describe')
        md=data.get('reportMetadata',{})
        ext=data.get('reportExtendedMetadata',{})
        cols=ext.get('detailColumnInfo',{})
        return jsonify(ok=True,report_id=report_id,name=md.get('name'),format=md.get('reportFormat'),detail_columns=[{'name':k,'label':(v or {}).get('label',k),'dataType':(v or {}).get('dataType')} for k,v in cols.items()],report_metadata=md)
    except Exception as e:
        return jsonify(ok=False,error='Could not describe this report. '+str(e)),400

@app.post('/reports/<report_id>/run')
@require_app_login
def report_run_route(report_id):
    """Execute a saved report using Salesforce's Reports API; read-only."""
    if not current_sf(): return jsonify(ok=False,error='Connect Salesforce first.'),401
    if not re.fullmatch(r'[A-Za-z0-9]{15,18}', report_id or ''):
        return jsonify(ok=False,error='Invalid Salesforce report ID.'),400
    body=request.get_json(silent=True) or {}
    include_details=bool(body.get('includeDetails', True))
    try:
        result=sf_request('GET',f'/services/data/v{API_VERSION}/analytics/reports/{report_id}',params={'includeDetails':str(include_details).lower()})
        md=result.get('reportMetadata',{})
        ext=result.get('reportExtendedMetadata',{})
        col_info=ext.get('detailColumnInfo',{})
        col_names=md.get('detailColumns',[]) or list(col_info.keys())
        columns=[{'name':n,'label':(col_info.get(n) or {}).get('label',n),'dataType':(col_info.get(n) or {}).get('dataType')} for n in col_names]
        # Report API stores detail rows inside factMap. Flatten the detail section without inventing values.
        records=[]
        fact_map=result.get('factMap',{}) or {}
        detail_facts = [fact_map['T!']] if 'T!' in fact_map else list(fact_map.values())
        seen_rows = set()
        for fact in detail_facts:
            for row in (fact or {}).get('rows',[]) or []:
                cells=row.get('dataCells',[]) or []
                normalized={columns[i]['name'] if i < len(columns) else f'Column_{i+1}': (cell or {}).get('label', (cell or {}).get('value')) for i,cell in enumerate(cells)}
                row_key=repr(normalized)
                if row_key not in seen_rows:
                    seen_rows.add(row_key); records.append(normalized)
        report_fact={}
        for key,fact in fact_map.items():
            aggregates=(fact or {}).get('aggregates')
            if aggregates:
                report_fact[key]=[{'label':a.get('label'),'value':a.get('value')} for a in aggregates]
        return jsonify(ok=True,report_id=report_id,name=md.get('name'),format=md.get('reportFormat'),columns=columns,records=records,record_count=len(records),fact_map=report_fact,report_metadata=md,has_detail_rows=bool(records),message=('Report executed; detail rows returned.' if records else 'Report executed, but no detail rows were returned. Check report format, filters, and whether detail rows are enabled. Summary totals are included when available.'))
    except Exception as e:
        return jsonify(ok=False,error='Salesforce could not run this report. Check report permissions, report type, and API access. '+str(e)),400

@app.get('/schema/required')
@require_app_login
def required_schema():
    """Inspect the actual live Salesforce API schema for the MIS source objects.

    Report-type labels are not assumed to be queryable object names. The response
    explicitly separates objects available in this org from missing/non-queryable
    sources and maps useful Case fields by label.
    """
    if not current_sf():
        return jsonify(ok=False, error='Connect Salesforce first.'), 401
    object_catalogue = sf_request('GET', f'/services/data/v{API_VERSION}/sobjects')
    by_name = {o.get('name'): o for o in object_catalogue.get('sobjects', [])}
    candidates = [
        ('Case', ['Case']),
        ('CaseHistory', ['Case History']),
        ('CaseMilestone', ['Case Milestone']),
        ('Case_Aging__c', ['Case Aging', 'Case Agings']),
        ('Feedback__c', ['Feedback']),
        ('Time_Log__c', ['Time Log', 'Time Logs']),
        ('Account', ['Account']),
    ]
    sources = []
    for api_name, labels in candidates:
        obj = by_name.get(api_name)
        item = {
            'api_name': api_name,
            'expected_labels': labels,
            'available': bool(obj),
            'label': (obj or {}).get('label'),
            'queryable': bool((obj or {}).get('queryable')),
            'custom': bool((obj or {}).get('custom')),
            'fields': [],
            'error': None
        }
        if obj and obj.get('queryable'):
            try:
                desc = describe(api_name)
                item['fields'] = [
                    {'name': f.get('name'), 'label': f.get('label'),
                     'type': f.get('type'), 'filterable': f.get('filterable'),
                     'referenceTo': f.get('referenceTo') or [],
                     'relationshipName': f.get('relationshipName')}
                    for f in desc.get('fields', [])
                ]
            except Exception as exc:
                item['error'] = str(exc)
        sources.append(item)

    case_fields = []
    if by_name.get('Case'):
        try:
            desc = describe('Case')
            wanted = ('first assigned group', 'priority', 'type', 'status', 'application',
                      'application module', 'owner', 'created date', 'closed date',
                      'resolved date', 'account')
            for f in desc.get('fields', []):
                label = (f.get('label') or '').strip().casefold()
                if any(term in label for term in wanted):
                    case_fields.append({
                        'name': f.get('name'), 'label': f.get('label'),
                        'type': f.get('type'), 'filterable': f.get('filterable'),
                        'referenceTo': f.get('referenceTo') or [],
                        'relationshipName': f.get('relationshipName')
                    })
        except Exception:
            pass
    return jsonify(ok=True, sources=sources, case_field_candidates=case_fields,
                   note='Joined Salesforce report types such as “Case Agings with Case” may not be direct API objects. Use the returned API names and relationships; do not infer custom object names from report labels.')

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
