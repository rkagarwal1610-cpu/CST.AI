# Salesforce MIS — Cloud Web Application

A browser-based Flask application with a green, management-style dashboard inspired by the supplied dashboard video. Designed for team and management access through an HTTPS cloud URL.

## Included
- Responsive Pulse MIS dashboard: ticket flow, open-ticket health, priority queue and team snapshot.
- Agent performance, SLA & ageing, ticket journal, issue trends, Data Explorer, and Salesforce connection sections.
- Existing Salesforce connection approach retained: SOAP login v64.0 and REST/SOQL API v65.0 by default.
- Read-only Salesforce object/field discovery and CSV export.
- Render deployment blueprint and environment template.

## Deploy to Render
1. Extract this folder and push its contents to a private GitHub repository.
2. In Render, create a Blueprint from that repository and apply `render.yaml`.
3. Set `APP_PASSWORD` to a strong secret and `FLASK_SECRET_KEY` to a long random secret in Render's environment settings. Do not commit these values.
4. Deploy, open the generated HTTPS URL, sign in, and use **Salesforce connection** to connect.
5. Validate counts and filters against trusted Salesforce reports before using for management decisions.

## Environment
- `APP_USERNAME` — application login username (default `team`)
- `APP_PASSWORD` — required application password
- `FLASK_SECRET_KEY` — required stable secret in production
- `SALESFORCE_API_VERSION` — defaults to `65.0`
- `COOKIE_SECURE` — defaults to `true`; keep true on HTTPS hosting

## Important production notes
- This package is a deployable starter, not a production-certified multi-user service. Current app login uses one shared application username/password. For team/management deployment, replace this with company SSO or individual accounts and role-based access.
- Salesforce session IDs are held in server memory. Use a single app instance unless you implement shared session storage. Reconnect if the instance restarts or the Salesforce session expires.
- The chart trend, SLA donut, queue distribution and example priority rows are illustrative preview content. The current backend supplies live top-level case counts, a latest-2,000-case owner workload sample and recent cases; it does not yet calculate official historical trends, SLA milestones, end-of-day backlog, L1/L2 attribution, agent availability, RCA categories or forwarding rate.
- Do not use preview values for official reporting. Configure and validate business rules, Salesforce field mappings, time zone, business hours, queues and CaseMilestone rules first.
- Use a least-privilege Salesforce account and rotate any credentials/tokens previously exposed in messages. Never commit Salesforce credentials to source control.
