"""Incident, enrollment, policy and reviewed-playbook routes for one organisation."""
import json
import secrets
import time
from uuid import uuid4
from pathlib import Path

from fastapi import Depends, HTTPException, Request
from fastapi.responses import FileResponse

from .operations_models import (EnrollmentRequest,EnrollmentRedeem,HostPolicy,IncidentCreate,
                                IncidentUpdate,ReviewRequest,SuppressionCreate,PlaybookRequest,PlaybookReceipt)
from .overview import overview


def mount_operations(app, store, cfg, read, write, admin, agent, body):
    def record(db, action, actor, data):
        store.audit(db,action,actor['sub'],json.dumps(data))

    def refresh_addresses():
        store.host_addresses={address:name for name,policy in store.host_policies().items()
                              for address in policy.get('addresses',[])}

    def addresses_available(db, name, policy):
        for row in db.execute("SELECT host,policy FROM enrolled_hosts WHERE status!='revoked' AND host!=?",(name,)):
            if set(policy.addresses) & set(json.loads(row['policy']).get('addresses',[])):
                raise HTTPException(409,'address already assigned to another enrolled host')

    @app.get('/console',include_in_schema=False)
    def console():
        return FileResponse(Path(__file__).with_name('console.html'),headers={
            'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'",
            'X-Content-Type-Options':'nosniff','Cache-Control':'no-store'})

    @app.get('/console.js',include_in_schema=False)
    def console_script():
        return FileResponse(Path(__file__).with_name('console.js'),media_type='text/javascript')

    @app.get('/console.css',include_in_schema=False)
    def console_style():
        return FileResponse(Path(__file__).with_name('console.css'),media_type='text/css')

    @app.get('/v1/overview',dependencies=[Depends(read)])
    async def operational_overview():
        return await overview(store,cfg)

    @app.post('/v1/enrollment-tokens',status_code=201)
    async def enrollment_token(request:Request,actor=Depends(admin)):
        data=await body(request,EnrollmentRequest)
        token=secrets.token_urlsafe(48); now=time.time()
        with store.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            existing=db.execute('SELECT status FROM enrolled_hosts WHERE host=?',(data.host,)).fetchone()
            if existing and existing['status']!='revoked':
                raise HTTPException(409,'host already exists; revoke before re-enrollment')
            addresses_available(db,data.host,data.policy)
            db.execute("INSERT INTO enrolled_hosts(host,status,policy,created,rotated) VALUES(?,'pending',?,?,?) "
                       "ON CONFLICT(host) DO UPDATE SET status='pending',token_hash=NULL,policy=excluded.policy,"
                       "metadata='{}',last_seen=NULL,created=excluded.created,rotated=excluded.rotated",
                       (data.host,data.policy.model_dump_json(),now,now))
            db.execute('DELETE FROM sensors WHERE host=?',(data.host,))
            db.execute('UPDATE enrollment_tokens SET used=1 WHERE host=?',(data.host,))
            db.execute('INSERT INTO enrollment_tokens VALUES(?,?,?,0)',
                       (store.token_hash(token),data.host,now+data.ttl_seconds))
            record(db,'enrollment_issued',actor,{'host':data.host})
        return {'host':data.host,'enrollment_token':token,'expires_at':now+data.ttl_seconds}

    @app.post('/v1/enroll',status_code=201)
    async def enroll(request:Request):
        data=await body(request,EnrollmentRedeem)
        now=time.time(); credential=secrets.token_urlsafe(48)
        with store.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT * FROM enrollment_tokens WHERE token_hash=? AND used=0 AND expires>?',
                           (store.token_hash(data.token),now)).fetchone()
            if not row:
                raise HTTPException(401,'invalid or expired enrollment token')
            host=db.execute('SELECT status FROM enrolled_hosts WHERE host=?',(row['host'],)).fetchone()
            if not host or host['status']!='pending':
                raise HTTPException(409,'host is not pending enrollment')
            db.execute("UPDATE enrolled_hosts SET status='active',token_hash=?,rotated=? WHERE host=?",
                       (store.token_hash(credential),now,row['host']))
            db.execute('UPDATE enrollment_tokens SET used=1 WHERE token_hash=?',(store.token_hash(data.token),))
            store.audit(db,'agent_enrolled',row['host'],'one-time enrollment completed')
        refresh_addresses()
        return {'host':row['host'],'token':credential}

    @app.post('/v1/agents/{host}/revoke')
    def revoke(host:str,actor=Depends(admin)):
        with store.connect() as db:
            if not db.execute('SELECT 1 FROM enrolled_hosts WHERE host=?',(host,)).fetchone():
                raise HTTPException(404,'host not found')
            db.execute("UPDATE enrolled_hosts SET status='revoked',token_hash=NULL WHERE host=?",(host,))
            db.execute('UPDATE enrollment_tokens SET used=1 WHERE host=?',(host,))
            db.execute("UPDATE commands SET status='cancelled' WHERE host=? AND status='pending'",(host,))
            db.execute("UPDATE response_jobs SET status='cancelled' WHERE host=? AND status IN ('requested','approved') AND attempts=0",(host,))
            db.execute("UPDATE response_jobs SET expires=? WHERE host=? AND action='cloud_waf_block' AND attempts>0 AND status NOT IN ('rolled_back','failed')",(time.time(),host))
            record(db,'agent_revoked',actor,{'host':host})
        refresh_addresses()
        return {'status':'revoked'}

    @app.post('/v1/agents/{host}/rotate')
    def rotate(host:str,actor=Depends(admin)):
        token=secrets.token_urlsafe(48)
        with store.connect() as db:
            cursor=db.execute("UPDATE enrolled_hosts SET token_hash=?,rotated=? WHERE host=? AND status='active'",
                              (store.token_hash(token),time.time(),host))
            if cursor.rowcount!=1:
                raise HTTPException(404,'active host not found')
            record(db,'agent_token_rotated',actor,{'host':host})
        return {'host':host,'token':token}

    @app.put('/v1/agents/{host}/policy')
    async def policy_update(host:str,request:Request,actor=Depends(admin)):
        policy=await body(request,HostPolicy)
        with store.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            addresses_available(db,host,policy)
            cursor=db.execute("UPDATE enrolled_hosts SET policy=? WHERE host=? AND status!='revoked'",
                              (policy.model_dump_json(),host))
            if cursor.rowcount!=1:
                raise HTTPException(404,'host not found')
            version=db.execute('INSERT INTO policy_history(host,policy,actor,at) VALUES(?,?,?,?)',
                               (host,policy.model_dump_json(),actor['sub'],time.time())).lastrowid
            record(db,'agent_policy_updated',actor,{'host':host,'version':version})
        refresh_addresses()
        return {'host':host,'version':version}

    @app.get('/v1/agent/policy')
    def agent_policy(host=Depends(agent)):
        policy=store.host_policies()[host]
        return {'host':host,'policy':policy}

    @app.get('/v1/incidents',dependencies=[Depends(read)])
    def incidents():
        return {'incidents':store.incident_list()}

    @app.post('/v1/incidents',status_code=201)
    async def create_incident(request:Request,actor=Depends(write)):
        data=await body(request,IncidentCreate)
        now=time.time(); identifier=uuid4().hex
        with store.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            for alert_id in set(data.alert_ids):
                if not db.execute('SELECT id FROM alerts WHERE id=?',(alert_id,)).fetchone():
                    raise HTTPException(404,'alert not found')
            db.execute("INSERT INTO incidents VALUES(?,?,?,'open',?,?,?,1)",
                       (identifier,data.title,data.owner,data.severity,now,now))
            db.executemany('INSERT INTO incident_alerts VALUES(?,?)',[(identifier,a) for a in set(data.alert_ids)])
            record(db,'incident_created',actor,{'incident_id':identifier,'alert_ids':data.alert_ids})
            store.queue_notifications(db,'incident.created',{'id':identifier,**data.model_dump()})
        return {'id':identifier,'version':1,'status':'open'}

    @app.patch('/v1/incidents/{identifier}')
    async def update_incident(identifier:str,request:Request,actor=Depends(write)):
        data=await body(request,IncidentUpdate)
        now=time.time()
        with store.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT * FROM incidents WHERE id=?',(identifier,)).fetchone()
            if not row: raise HTTPException(404,'incident not found')
            if row['version']!=data.version: raise HTTPException(409,'incident was changed; reload before updating')
            db.execute('UPDATE incidents SET status=?,owner=?,updated=?,version=version+1 WHERE id=?',
                       (data.status,data.owner,now,identifier))
            db.execute('INSERT INTO incident_notes(incident_id,actor,at,note) VALUES(?,?,?,?)',
                       (identifier,actor['sub'],now,data.note))
            record(db,'incident_updated',actor,{'incident_id':identifier,'status':data.status,'owner':data.owner})
            store.queue_notifications(db,'incident.updated',{'id':identifier,**data.model_dump()})
        return {'id':identifier,'version':data.version+1,'status':data.status}

    @app.get('/v1/incidents/{identifier}/timeline',dependencies=[Depends(read)])
    def timeline(identifier:str):
        with store.connect() as db:
            if not db.execute('SELECT 1 FROM incidents WHERE id=?',(identifier,)).fetchone():
                raise HTTPException(404,'incident not found')
            return {'notes':[dict(r) for r in db.execute('SELECT actor,at,note FROM incident_notes WHERE incident_id=? ORDER BY id',(identifier,))],
                    'alerts':[dict(r) for r in db.execute('SELECT a.* FROM alerts a JOIN incident_alerts i ON a.id=i.alert_id WHERE i.incident_id=? ORDER BY a.created',(identifier,))]}

    @app.post('/v1/alerts/{identifier}/review')
    async def review(identifier:int,request:Request,actor=Depends(write)):
        data=await body(request,ReviewRequest)
        with store.connect() as db:
            if not db.execute('SELECT id FROM alerts WHERE id=?',(identifier,)).fetchone():
                raise HTTPException(404,'alert not found')
            db.execute('INSERT INTO alert_reviews VALUES(?,?,?,?,?) ON CONFLICT(alert_id) DO UPDATE SET '
                       'status=excluded.status,actor=excluded.actor,reason=excluded.reason',
                       (identifier,data.status,actor['sub'],time.time(),data.reason))
            record(db,'alert_reviewed',actor,{'alert_id':identifier,**data.model_dump()})
        return {'status':data.status}

    @app.post('/v1/suppressions',status_code=201)
    async def suppress(request:Request,actor=Depends(admin)):
        data=await body(request,SuppressionCreate)
        if data.host not in store.host_policies(): raise HTTPException(404,'active host not found')
        identifier=uuid4().hex; now=time.time()
        with store.connect() as db:
            db.execute('INSERT INTO suppressions VALUES(?,?,?,?,?,?,?,?,0)',
                       (identifier,data.rule,data.host,data.ip,now+data.duration_seconds,data.reason,actor['sub'],now))
            record(db,'suppression_created',actor,{'id':identifier,**data.model_dump()})
        return {'id':identifier,'expires_at':now+data.duration_seconds}

    @app.get('/v1/suppressions',dependencies=[Depends(read)])
    def suppressions():
        with store.connect() as db:
            return {'suppressions':[dict(r) for r in db.execute('SELECT * FROM suppressions ORDER BY created DESC LIMIT 200')]}

    @app.delete('/v1/suppressions/{identifier}')
    def revoke_suppression(identifier:str,actor=Depends(admin)):
        with store.connect() as db:
            db.execute('UPDATE suppressions SET revoked=1 WHERE id=?',(identifier,))
            record(db,'suppression_revoked',actor,{'id':identifier})
        return {'status':'revoked'}

    # Response plans and their immutable evidence are reviewed before a distinct admin approves.
    @app.post('/v1/playbooks',status_code=201)
    async def request_playbook(request:Request,actor=Depends(write)):
        data=await body(request,PlaybookRequest)
        now=time.time(); identifier=uuid4().hex
        with store.connect() as db:
            alert=db.execute('SELECT * FROM alerts WHERE id=?',(data.alert_id,)).fetchone()
            if not alert: raise HTTPException(404,'alert not found')
            if data.action not in ('restore_file','release_host') and now-alert['created']>3600: raise HTTPException(409,'requires an alert from the last hour')
            if alert['host'] not in store.host_policies(): raise HTTPException(409,'host no longer active')
            policy=cfg.get('response',{}).get('hosts',{}).get(alert['host'],{})
            target_platform=policy.get('platform','linux')
            if data.action!='cloud_waf_block' and target_platform not in ('linux','windows'):
                raise HTTPException(403,'unsupported host response platform')
            evidence={}
            try: evidence=json.loads(alert['detail'])
            except (ValueError,TypeError): pass
            if data.action=='cloud_waf_block':
                from .integrations import CloudflareWAFConnector
                cloud=cfg.get('response',{}).get('cloud_waf')
                if not cloud or not cloud.get('enabled'): raise HTTPException(403,'cloud WAF response disabled')
                try: plan=CloudflareWAFConnector(cloud).prepare_block(alert['ip'],data.duration_seconds,identifier,now=now)
                except (ValueError,TypeError) as exc: raise HTTPException(403,'cloud response denied by policy') from exc
            elif data.action=='quarantine_file':
                if not policy.get('enabled') or 'quarantine_file' not in policy.get('allowed_actions',[]):
                    raise HTTPException(403,'quarantine disabled')
                if alert['rule']!='malware_detected' or not evidence.get('sha256') or not evidence.get('path'):
                    raise HTTPException(409,'quarantine needs malware path/hash evidence')
                plan={'path':evidence['path'],'sha256':evidence['sha256'],'request_id':identifier}
            elif data.action=='isolate_host':
                if not policy.get('enabled') or 'isolate_host' not in policy.get('allowed_actions',[]):
                    raise HTTPException(403,'isolation disabled')
                if target_platform=='windows':
                    from .windows_isolation import prepare_windows_isolation as prepare_isolation
                else:
                    from .playbooks import prepare_isolation
                try: plan=prepare_isolation(policy.get('isolation',{}),data.duration_seconds,identifier,now=now)
                except ValueError as exc: raise HTTPException(403,'isolation policy invalid') from exc
            else:
                previous=db.execute("SELECT * FROM response_jobs WHERE id=? AND host=? AND status IN ('applied','failed')",
                                    (data.previous_job_id,alert['host'])).fetchone()
                expected='quarantine_file' if data.action=='restore_file' else 'isolate_host'
                if not previous or previous['action']!=expected: raise HTTPException(409,'matching applied or failed attempt required')
                previous_plan=json.loads(previous['plan'])
                if previous_plan.get('platform','linux')!=target_platform:
                    raise HTTPException(409,'rollback platform differs from the original action')
                if not policy.get('enabled') or data.action not in policy.get('allowed_actions',[]):
                    raise HTTPException(403,'rollback action disabled')
                plan={'request_id':previous['id'],'previous_plan':previous_plan}
            if data.action!='cloud_waf_block':
                plan['platform']=target_platform
            plan['reason']=data.reason
            expires=now+min(300,data.duration_seconds) if data.action not in ('isolate_host','cloud_waf_block') else plan.get('expires_at',now+data.duration_seconds)
            plan['expires_at']=expires
            db.execute('INSERT INTO response_jobs(id,host,action,alert_id,plan,status,requested_by,created,expires) '
                       "VALUES(?,?,?,?,?,'requested',?,?,?)",(identifier,alert['host'],data.action,data.alert_id,json.dumps(plan),actor['sub'],now,expires))
            record(db,'playbook_requested',actor,{'id':identifier,'action':data.action,'plan':plan})
        return {'id':identifier,'status':'requested','plan':plan,'expires_at':expires}

    @app.post('/v1/playbooks/{identifier}/approve')
    def approve_playbook(identifier:str,actor=Depends(admin)):
        with store.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT * FROM response_jobs WHERE id=?',(identifier,)).fetchone()
            if not row: raise HTTPException(404,'job not found')
            if row['requested_by']==actor['sub']: raise HTTPException(403,'a different administrator must approve')
            if row['status']!='requested' or row['expires']<=time.time(): raise HTTPException(409,'request is not awaiting approval or expired')
            db.execute("UPDATE response_jobs SET status='approved',approved_by=? WHERE id=?",(actor['sub'],identifier))
            record(db,'playbook_approved',actor,{'id':identifier})
        return {'id':identifier,'status':'approved'}

    @app.get('/v1/playbooks',dependencies=[Depends(read)])
    def playbooks():
        with store.connect() as db:
            return {'jobs':[dict(r) for r in db.execute('SELECT * FROM response_jobs ORDER BY created DESC LIMIT 200')]}

    @app.get('/v1/playbooks/commands')
    def playbook_commands(host=Depends(agent)):
        with store.connect() as db:
            return {'commands':[{'id':r['id'],'action':r['action'],'plan':json.loads(r['plan'])} for r in db.execute(
                "SELECT * FROM response_jobs WHERE host=? AND status='approved' AND action!='cloud_waf_block' AND expires>? ORDER BY created LIMIT 20",(host,time.time()))]}

    @app.post('/v1/playbooks/{identifier}/receipt')
    async def playbook_receipt(identifier:str,request:Request,host=Depends(agent)):
        data=await body(request,PlaybookReceipt)
        # Evidence from a host is bounded and stored as JSON, never executed as a command.
        if len(json.dumps(data.result))>16000: raise HTTPException(413,'receipt too large')
        with store.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row=db.execute('SELECT * FROM response_jobs WHERE id=? AND host=? AND action!=?',(identifier,host,'cloud_waf_block')).fetchone()
            if not row: raise HTTPException(404,'job not found')
            expected = {'quarantine_file': ('applied','quarantined'), 'restore_file': ('rolled_back','restored'),
                        'isolate_host': ('applied','isolated'), 'release_host': ('rolled_back','isolation_released')}
            if data.status == 'failed':
                if data.detail not in ('policy_denied','execution_failed'): raise HTTPException(422,'invalid failed receipt')
            elif (data.status,data.detail) != expected.get(row['action']):
                raise HTTPException(422,'receipt does not match approved action')
            if data.result.get('status',data.status) != data.status or data.result.get('detail',data.detail) != data.detail:
                raise HTTPException(422,'inconsistent receipt evidence')
            plan=json.loads(row['plan'])
            if data.result.get('platform',plan.get('platform','linux'))!=plan.get('platform','linux'):
                raise HTTPException(422,'receipt platform differs from the approved plan')
            canonical = {**data.result, 'detail': data.detail}
            if row['status'] not in ('approved','applied','failed','rolled_back'): raise HTTPException(409,'job not approved')
            if row['status'] in ('applied','failed','rolled_back'):
                if row['status']!=data.status or json.loads(row['result'] or '{}')!=canonical: raise HTTPException(409,'receipt already recorded')
                return {'status':row['status']}
            db.execute('UPDATE response_jobs SET status=?,result=? WHERE id=?',(data.status,json.dumps(canonical),identifier))
            store.audit(db,'playbook_receipt',host,json.dumps({'id':identifier,'status':data.status}))
        return {'status':data.status}
