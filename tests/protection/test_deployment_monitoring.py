import json
import time
from pathlib import Path

from vulnsuite.protection.agent import collect


def test_delivery_health_refreshes_during_successful_idle_collection():
    state = {'delivery': {'status': 'ok'}, 'sensor_states': {'delivery': {'status': 'ok', 'detail': 'collected', 'sent': time.time()-180}}}
    collect({'logs': [], 'watch_files': []}, state)
    assert any(e.get('sensor') == 'delivery' and e.get('sensor_status') == 'ok' for e in state['outbox'])


def test_monitor_health_detects_stale_snapshot(tmp_path, monkeypatch):
    import threading
    import urllib.request
    import urllib.error
    from http.server import ThreadingHTTPServer
    from vulnsuite.monitoring import server
    monkeypatch.setattr(server,'STATE',tmp_path)
    (tmp_path/'snapshot.json').write_text(json.dumps({'collected_at':time.time()-300}))
    httpd=ThreadingHTTPServer(('127.0.0.1',0),server.Handler)
    thread=threading.Thread(target=httpd.serve_forever,daemon=True);thread.start()
    try:
        try:
            urllib.request.urlopen(f'http://127.0.0.1:{httpd.server_port}/VulnSuite/health')
            assert False, 'Stale health should fail'
        except urllib.error.HTTPError as exc:
            assert exc.code==503
            assert json.load(exc)['status']=='stale'
    finally:
        httpd.shutdown();httpd.server_close();thread.join()
