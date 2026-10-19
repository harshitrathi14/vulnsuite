"""Bounded assessment aggregation and truthful sensor freshness."""
import asyncio
import time

import httpx
import pytest

import vulnsuite.protection.overview as overview_module
from vulnsuite.protection.store import Store


def test_overview_flags_stale_sensor_even_while_agent_is_connected(tmp_path):
    store = Store(str(tmp_path / 'events.db'))
    store.seed_hosts({'web': {'token': 'x'*40}})
    with store.connect() as db:
        db.execute("UPDATE enrolled_hosts SET last_seen=?", (time.time(),))
        db.execute("INSERT INTO sensors VALUES('web','telemetry','ok','collected',?)", (time.time()-300,))
    result = asyncio.run(overview_module.overview(store, {}))
    assert not result['hosts'][0]['stale']
    assert result['hosts'][0]['sensors'][0]['stale']


@pytest.mark.parametrize('scenario', ['connected', 'oversized', 'redirect', 'unauthorized'])
def test_assessment_reads_are_fixed_bounded_and_do_not_expose_credentials(tmp_path, monkeypatch, scenario):
    requests = []
    secret = 'read-only-fixture-secret'
    monkeypatch.setenv('TEST_ASSESSMENT_TOKEN', secret)

    def handle(request):
        requests.append(request)
        assert request.headers['authorization'] == 'Bearer '+secret
        assert request.headers['x-tenant-id'] == 'test-tenant'
        if scenario == 'oversized':
            return httpx.Response(200, content=b' '* (2*1024*1024+1))
        if scenario == 'redirect':
            return httpx.Response(302, headers={'location': 'https://unexpected.example/receive'})
        if scenario == 'unauthorized':
            return httpx.Response(401, text=secret)
        return httpx.Response(200, json=[{'title': 'Fixture finding'}] if request.url.path.endswith('/findings') else {'total': 1})

    client_type = httpx.AsyncClient
    monkeypatch.setattr(overview_module.httpx, 'AsyncClient',
                        lambda **kwargs: client_type(transport=httpx.MockTransport(handle), **kwargs))
    result = asyncio.run(overview_module.overview(Store(str(tmp_path / 'events.db')), {
        'assessment_api': {'base_url': 'https://assessment.example', 'token_env': 'TEST_ASSESSMENT_TOKEN',
                           'tenant_id': 'test-tenant'}}))
    assert secret not in str(result)
    assert all(r.url.host == 'assessment.example' for r in requests)
    assert requests[0].url.params['limit'] == '200'
    if scenario == 'connected':
        assert result['assessment']['status'] == 'connected'
        assert result['assessment']['findings'][0]['title'] == 'Fixture finding'
        assert [r.url.path for r in requests] == ['/api/v1/findings', '/api/v1/findings/summary']
    else:
        assert result['assessment']['status'] == 'unavailable'
        assert len(requests) == 1
