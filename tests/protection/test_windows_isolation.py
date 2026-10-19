"""Windows policy mathematics and native-helper contract, without live firewall calls."""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
from unittest.mock import patch
from uuid import uuid4

import pytest

from vulnsuite.protection import windows_isolation as windows


@pytest.fixture
def policy():
    return {'management_networks': ['10.10.0.5/32', 'fd00::5/128'],
            'management_ports': [443, 3389], 'state_dir': r'C:\ProgramData\VulnSuite\Isolation',
            'helper_sha256': hashlib.sha256(windows.HELPER.read_bytes()).hexdigest()}


def address_matches(value, ranges):
    address = ipaddress.ip_address(value)
    for item in ranges:
        if '/' in item:
            if address in ipaddress.ip_network(item):
                return True
        elif '-' in item:
            start, end = (ipaddress.ip_address(part) for part in item.split('-'))
            if address.version == start.version and int(start) <= int(address) <= int(end):
                return True
        elif address == ipaddress.ip_address(item):
            return True
    return False


def port_matches(port, ranges):
    if ranges is None:
        return True
    return any(int(parts[0]) <= port <= int(parts[-1])
               for item in ranges if (parts := item.split('-')))


def matching_rules(rules, address, protocol=6, local_port=50000, remote_port=443, kind=None, direction=2):
    return [rule for rule in rules if rule['direction'] == direction and rule['protocol'] == protocol
            and address_matches(address, rule['remote_addresses'])
            and port_matches(local_port, rule.get('local_ports'))
            and port_matches(remote_port, rule.get('remote_ports'))
            and ('icmp_types' not in rule or f'{kind}:*' in rule['icmp_types'])]


def test_plan_canonical_scope_deadline_and_reason(policy):
    identifier = uuid4().hex
    plan = windows.prepare_windows_isolation(policy, 300, identifier)
    assert plan['platform'] == 'windows'
    assert plan['expires_at'] - plan['created_at'] == 300
    assert plan['management_ports'] == [443, 3389]
    assert windows._validate(policy, {**plan, 'reason': 'Reviewed'}) == plan
    with pytest.raises(ValueError):
        windows._validate({**policy, 'management_ports': [443]}, plan)
    with pytest.raises(ValueError):
        windows._validate(policy, {**plan, 'expires_at': int(time.time()) - 1})


@pytest.mark.parametrize('network', ['0.0.0.0/0', '10.0.0.0/24', 'fd00::/64', '::/0',
                                     '127.0.0.1/32', 'fe80::1/128', '224.0.0.1/32'])
def test_windows_requires_pinned_unicast_management(policy, network):
    with pytest.raises(ValueError):
        windows.prepare_windows_isolation({**policy, 'management_networks': [network]}, 300, uuid4().hex)


def test_address_complements_cover_boundaries_without_overblocking():
    for version, excluded in ((4, ['10.0.0.0/24', '10.0.0.5/32', '127.0.0.0/8']),
                              (6, ['fd00::/120', '::1/128'])):
        ranges = windows.complement_ranges(excluded, version)
        cls = ipaddress.IPv4Address if version == 4 else ipaddress.IPv6Address
        bits = cls(0).max_prefixlen
        samples = [cls(0), cls((1 << bits) - 1)]
        for text in excluded:
            network = ipaddress.ip_network(text)
            for value in (int(network.network_address)-1, int(network.network_address),
                          int(network.broadcast_address), int(network.broadcast_address)+1):
                if 0 <= value < (1 << bits):
                    samples.append(cls(value))
        for sample in samples:
            assert address_matches(str(sample), ranges) == (not any(sample in ipaddress.ip_network(n) for n in excluded))


def test_port_complement_exhaustive():
    allowed = {22, 443, 3389, 65535}
    ranges = windows.complement_ports(list(allowed))
    for port in range(65536):
        assert port_matches(port, ranges) == (port not in allowed)


@pytest.mark.parametrize('direction', [1, 2])
def test_rule_precedence_preserves_pinned_management_only(policy, direction):
    rules = windows.firewall_rules(windows.prepare_windows_isolation(policy, 300, uuid4().hex))
    assert len(rules) == 526 and len({r['name'] for r in rules}) == len(rules)
    # Windows block wins. Allowed management tuples must have NO matching block.
    for host in ('10.10.0.5', 'fd00::5'):
        for local, remote in ((50000,443), (3389,50000), (443,50000)):
            matches = matching_rules(rules, host, local_port=local, remote_port=remote, direction=direction)
            assert matches and all(r['action'] == 1 for r in matches)
        assert any(r['action'] == 0 for r in matching_rules(rules, host, local_port=50000, remote_port=445, direction=direction))
    # Binding an approved source port does not permit any unlisted remote host.
    for host in ('10.10.0.6', '8.8.8.8', 'fd00::6', '2606:4700::1111'):
        matches = matching_rules(rules, host, local_port=443, remote_port=3389, direction=direction)
        assert matches and all(r['action'] == 0 for r in matches)
    for host in ('127.0.0.1', '::1'):
        assert not matching_rules(rules, host, direction=direction)


def test_non_tcp_protocols_and_narrow_icmp_exceptions(policy):
    rules = windows.firewall_rules(windows.prepare_windows_isolation(policy, 300, uuid4().hex))
    for protocol in range(256):
        if protocol in (1,6,58):
            continue
        for host in ('10.10.0.5','8.8.8.8','fd00::5','2606:4700::1111'):
            matches = matching_rules(rules, host, protocol=protocol)
            assert matches and all(r['action'] == 0 for r in matches)
    for host in ('fe80::1','ff02::1:ff00:1','fd00::5'):
        assert all(r['action'] == 1 for r in matching_rules(rules, host, protocol=58, kind=135))
    assert any(r['action'] == 0 for r in matching_rules(rules, '2606:4700::1111', protocol=58, kind=135))
    assert all(r['action'] == 1 for r in matching_rules(rules, '2606:4700::1111', protocol=58, kind=2))
    assert any(r['action'] == 0 for r in matching_rules(rules, 'fd00::5', protocol=58, kind=128))


@pytest.mark.parametrize('path', [r'\\server\share\state', r'C:\state:ads', r'C:\state\NUL',
                                  'C:\\state\\name.', 'C:\\state\\name ', r'C:\state\..\elsewhere'])
def test_state_path_refuses_ambiguous_or_remote_locations(policy, path):
    with pytest.raises(ValueError):
        windows._state_directory({**policy, 'state_dir': path})


def test_apply_passes_data_through_stdin_and_validates_receipt(policy):
    plan = windows.prepare_windows_isolation(policy, 300, uuid4().hex)
    receipt = {'status':'applied','detail':'isolated','request_id':plan['request_id'],'expires_at':plan['expires_at']}
    result = subprocess.CompletedProcess([], 0, stdout=json.dumps(receipt), stderr='')
    with patch.object(windows, '_windows', return_value=True), \
         patch.object(windows, '_powershell_path', return_value=r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'), \
         patch.object(windows.subprocess, 'run', return_value=result) as run:
        assert windows.apply_windows_isolation(policy, plan)['expiry_mechanism'] == 'scheduled_task_watchdog'
        arguments = run.call_args.args[0]
        assert '-File' in arguments and '-Command' not in arguments and '-EncodedCommand' not in arguments
        assert 'shell' not in run.call_args.kwargs
        payload = json.loads(run.call_args.kwargs['input'])
        assert payload['plan'] == plan and len(payload['rules']) == 526
        # A successful exit with an unrelated/incorrect receipt never becomes success.
        result.stdout = json.dumps({**receipt, 'expires_at': plan['expires_at'] + 1})
        with pytest.raises(windows.WindowsIsolationError, match='effective_rules_unconfirmed'):
            windows.apply_windows_isolation(policy, plan)


def test_helper_pin_failure_precedes_native_execution(policy):
    with patch.object(windows, '_windows', return_value=True), patch.object(windows.subprocess, 'run') as run:
        with pytest.raises(ValueError, match='helper hash'):
            windows.cleanup_expired({**policy, 'helper_sha256': '0' * 64})
        run.assert_not_called()


def test_no_windows_effects_on_linux(policy):
    with patch.object(windows, '_windows', return_value=False), patch.object(windows.subprocess, 'run') as run:
        with pytest.raises(ValueError, match='Windows host'):
            windows.cleanup_expired(policy)
        run.assert_not_called()


def test_cleanup_and_release_work_when_new_actions_disabled(policy):
    identifier = str(uuid4())
    policy['enabled'] = False
    with patch.object(windows, '_invoke', return_value={'status':'cleaned','released':2}) as invoke:
        assert windows.cleanup_expired(policy) == {'status':'cleaned','released':2}
        assert invoke.call_args.args[1] == 'Cleanup'
    receipt = {'status':'rolled_back','detail':'isolation_released','request_id':identifier}
    with patch.object(windows, '_invoke', return_value=receipt):
        assert windows.release_windows_isolation(policy, identifier)['status'] == 'rolled_back'


@pytest.mark.parametrize('scenario', ['success', 'watchdog_failure', 'partial_failure',
                                      'expired_during_apply', 'retry_applied', 'retry_partial'])
def test_powershell_orchestration_with_memory_only_native_fixture(policy, tmp_path, scenario):
    executable = os.environ.get('VULNSUITE_TEST_PWSH') or shutil.which('pwsh') or shutil.which('powershell')
    if not executable:
        pytest.skip('PowerShell parser/runtime not installed; Windows staging/CI runs this fixture')
    plan = windows.prepare_windows_isolation(policy, 300, uuid4().hex, now=1000)
    payload = tmp_path / 'payload.json'
    payload.write_text(json.dumps({'plan': plan, 'rules': windows.firewall_rules(plan)}))
    fixture = Path(__file__).with_name('windows_isolation_contract.ps1')
    result = subprocess.run([executable, '-NoProfile', '-NonInteractive', '-File', str(fixture.resolve()),
                             '-HelperPath', str(windows.HELPER.resolve()), '-PayloadPath', str(payload),
                             '-Scenario', scenario, '-WorkDirectory', str(tmp_path)],
                            capture_output=True, text=True, timeout=30, check=True)
    output = json.loads(result.stdout)
    events = output['events']
    if scenario in ('success', 'retry_applied'):
        assert output['error'] is None and output['receipt']['status'] == 'applied'
        assert output['receipt']['expires_at'] == 1300
    else:
        assert output['error'] is not None
        assert output['remaining'] == 0 and output['state'] == 'released'
    if scenario == 'success':
        assert events.index('manifest_prepared') < events.index('watchdog') < events.index('add')
        assert events.index('effective_verified') < events.index('manifest_applied')
        assert events.count('add') == 526
    if scenario in ('watchdog_failure', 'retry_applied', 'retry_partial'):
        assert 'add' not in events
    if scenario == 'retry_applied':
        assert 'watchdog' not in events  # Retry cannot re-register or extend expiry.
