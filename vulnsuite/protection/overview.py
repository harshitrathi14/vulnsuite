"""Read-only aggregation across the protection store and configured assessment API."""
import json
import os
import time
from pathlib import Path
from urllib.parse import urlsplit

import httpx


async def bounded_json(client, path, params=None):
    async with client.stream('GET', path, params=params) as response:
        response.raise_for_status()
        payload=bytearray()
        async for chunk in response.aiter_bytes():
            payload.extend(chunk)
            if len(payload)>2*1024*1024:
                raise ValueError('assessment response too large')
        return json.loads(payload)


async def overview(store, config):
    now = time.time()
    with store.connect() as db:
        alerts = [dict(r) for r in db.execute(
            "SELECT a.*,coalesce(r.status,'open') AS review_status, CASE WHEN s.alert_id IS NULL THEN 0 ELSE 1 END AS suppressed "
            "FROM alerts a LEFT JOIN alert_reviews r ON r.alert_id=a.id LEFT JOIN suppressed_alerts s ON s.alert_id=a.id "
            "ORDER BY a.id DESC LIMIT 200")]
        hosts=[]
        for row in db.execute('SELECT host,status,policy,metadata,last_seen,rotated FROM enrolled_hosts ORDER BY host'):
            item=dict(row)
            policy=json.loads(item.pop('policy'))
            item['metadata']=json.loads(item['metadata'])
            item['stale']=not item['last_seen'] or now-item['last_seen']>120
            item['desired_version']=policy.get('desired_version')
            item['version_drift']=bool(item['desired_version'] and item['metadata'].get('agent_version') != item['desired_version'])
            item['sensors']=[{**dict(r), 'stale': now-r['received']>120} for r in db.execute(
                'SELECT sensor,status,detail,received FROM sensors WHERE host=?',(item['host'],))]
            hosts.append(item)
        deliveries=[dict(r) for r in db.execute('SELECT connector,status,count(*) AS count FROM deliveries GROUP BY connector,status')]
        responses=[dict(r) for r in db.execute('SELECT id,host,action,status,created,expires,result FROM response_jobs ORDER BY created DESC LIMIT 100')]
        counters={r['status']:r['n'] for r in db.execute('SELECT status,count(*) AS n FROM incidents GROUP BY status')}
        reviewed=db.execute("SELECT count(*) FROM alert_reviews").fetchone()[0]
        false_positive=db.execute("SELECT count(*) FROM alert_reviews WHERE status='false_positive'").fetchone()[0]
        response_time=db.execute("SELECT avg(at-alerts.created) FROM alert_reviews JOIN alerts ON alerts.id=alert_reviews.alert_id").fetchone()[0]
    assessment={'status':'not_configured','findings':[],'summary':{}}
    backend=config.get('assessment_api')
    if backend:
        parsed=urlsplit(backend['base_url'])
        if not (parsed.scheme=='https' or (parsed.scheme=='http' and parsed.hostname in ('127.0.0.1','::1'))) or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError('assessment_api requires a fixed HTTPS base URL')
        token=os.environ.get(backend.get('token_env', ''))
        if backend.get('token_file'):
            try:
                token=Path(backend['token_file']).read_text().strip()
            except OSError:
                token=None
        if not token:
            assessment['status']='credentials_unavailable'
        else:
            try:
                async with httpx.AsyncClient(base_url=backend['base_url'].rstrip('/'),timeout=10,trust_env=False,
                        follow_redirects=False,headers={'Authorization':f'Bearer {token}','X-Tenant-Id':backend['tenant_id']}) as client:
                    findings=await bounded_json(client,'/api/v1/findings',{'limit':200})
                    summary=await bounded_json(client,'/api/v1/findings/summary')
                    if not isinstance(findings,list) or len(findings)>200 or not isinstance(summary,dict):
                        raise ValueError('invalid assessment response')
                    assessment={'status':'connected','findings':findings,'summary':summary,'limit':200}
            except (httpx.HTTPError,ValueError):
                assessment['status']='unavailable'
    return {'generated_at':now,'alerts':alerts,'hosts':hosts,'incidents':store.incident_list(),
            'delivery_status':deliveries,'responses':responses,'assessment':assessment,
            'metrics':{'incident_counts':counters,'reviewed_alerts':reviewed,'false_positive_reviews':false_positive,
                       'mean_first_review_seconds':response_time}}
