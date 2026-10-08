"""Regression cases use synthetic evidence and private temporary files, not host scans."""
import contextlib
import importlib.machinery
import importlib.util
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import Mock, patch

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'lib'))
from cyber_posture import paths, state
from cyber_posture import scan_exposure as exposure, scan_integrity as integrity


class SecurityCase(unittest.TestCase):
    def enterContext(self, manager):
        # unittest added this helper in Python 3.11; keep the suite usable on 3.10.
        value = manager.__enter__()
        self.addCleanup(manager.__exit__, None, None, None)
        return value

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='cyber-security-test-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.state = self.root / 'state'
        self.reports = self.root / 'reports'
        self.config = self.root / 'config'
        self.home_fixture = self.root / 'user'
        self.home_fixture.mkdir()
        self.enterContext(patch.dict(os.environ, {
            'CYBER_STATE_DIR': str(self.state), 'CYBER_REPORT_DIR': str(self.reports),
            'CYBER_CONFIG_DIR': str(self.config), 'CYBER_PROFILE': 'default', 'HOST_ROOT': '/',
        }))
        for name, value in {
            'STATE_DIR': self.state, '_REPORT_DIR': self.reports, 'BASELINE_PATH': self.state / 'baseline.json',
            'LAST_PATH': self.state / 'last-scan.json', 'DEFAULT_JSON': self.state / 'last-scan.json',
            'DEFAULT_MD': self.reports / 'latest.md', 'DEFAULT_HTML': self.reports / 'index.html',
            'KNOWN': {}, 'PROBES': {}, 'LAN_ALLOWLIST': set(), 'ACCEPTED_LAN_PORTS': set(), 'TAILNET_IPS': set(),
        }.items():
            self.enterContext(patch.object(exposure, name, value))
        self.integrity_dir = self.state / 'host-integrity'
        for name, value in {
            'STATE_DIR': self.state, 'HOST_DIR': self.integrity_dir, '_REPORT_DIR': self.reports,
            'BASELINE_PATH': self.integrity_dir / 'baseline.json', 'LAST_PATH': self.integrity_dir / 'last-integrity.json',
            'LAST_DEEP_PATH': self.integrity_dir / 'last-deep.json', 'LAST_QUICK_PATH': self.integrity_dir / 'last-quick.json',
            'WIKI_MD': self.reports / 'host-integrity.md', 'HOME': self.home_fixture, 'PROFILE': {},
        }.items():
            self.enterContext(patch.object(integrity, name, value))

    def result(self, module, detail='first', severity='HIGH', complete=True, mode='quick'):
        findings = [module.Finding(severity, 'TEST_FINDING', 'Test evidence', detail)] if severity else []
        data = dict(ts=datetime.now(timezone.utc).isoformat(), host='fixture', findings=[asdict(f) for f in findings],
                    summary=module.severity_counts(findings), fingerprint=module.fingerprint(findings), complete=complete)
        if module is integrity:
            return module.IntegrityResult(mode=mode, **data)
        return module.ScanResult(**data)

    def invoke(self, module, result, *args):
        out, err = io.StringIO(), io.StringIO()
        with patch.object(module, 'scan', return_value=result), patch.object(sys, 'argv', ['test', *args]), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = module.main()
        return rc, out.getvalue(), err.getvalue()

    def analyze(self, listeners, probes=()):
        return exposure.analyze(listeners, list(probes), [], 'active', [])

    def stub_integrity_checks(self):
        # Orchestration tests stub host evidence providers, keeping status handling real.
        for name in ('check_ld_preload', 'check_tmp_executables', 'check_fake_kernel_procs',
                     'check_suspicious_cmdline', 'check_proc_ps_gap', 'check_ssh_keys',
                     'check_user_crontab', 'check_systemd_user', 'check_world_writable_path',
                     'check_listening_unknown_high', 'check_tools_absent_summary'):
            self.enterContext(patch.object(integrity, name, return_value={}))
        self.enterContext(patch.object(integrity, 'tool_inventory', return_value={}))


class AlertTests(SecurityCase):
    def test_first_changed_repeat_and_resolved_notifications(self):
        for module in (exposure, integrity):
            with self.subTest(scanner=module.__name__):
                initial = self.result(module)
                self.assertIn('Test evidence', self.invoke(module, initial, '--quiet')[1])
                self.assertEqual('', self.invoke(module, initial, '--quiet')[1])
                changed = self.result(module, detail='different evidence, same finding title')
                self.assertIn('Test evidence', self.invoke(module, changed, '--quiet')[1])
                clean = self.result(module, severity=None)
                self.assertTrue(self.invoke(module, clean, '--quiet')[1])
                self.assertEqual('', self.invoke(module, clean, '--quiet')[1])

    def test_approved_baseline_cannot_suppress_first_notification(self):
        for module in (exposure, integrity):
            result = self.result(module)
            state.atomic_write(module.BASELINE_PATH, json.dumps({'fingerprint': result.fingerprint}))
            self.assertIn('Test evidence', self.invoke(module, result, '--quiet')[1])

    def test_initial_clean_quiet_scan_is_silent(self):
        for module in (exposure, integrity):
            self.assertEqual('', self.invoke(module, self.result(module, severity=None), '--quiet')[1])

    def test_unchanged_high_gets_daily_reminder(self):
        result = self.result(exposure)
        self.invoke(exposure, result, '--quiet')
        previous = state.load_json(self.state / 'last-alert.json')
        with patch.object(state.time, 'time', return_value=previous['emitted_at'] + 86401):
            self.assertTrue(self.invoke(exposure, result, '--quiet')[1])

    def test_force_quiet_notification(self):
        self.assertTrue(self.invoke(exposure, self.result(exposure, severity=None), '--quiet', '--full')[1])

    def test_invalid_alert_history_cannot_suppress_current_findings(self):
        for module in (exposure, integrity):
            result = self.result(module)
            alert_path = self.state / 'last-alert.json' if module is exposure else self.integrity_dir / 'last-alert-quick.json'
            for fields in ({'summary': []}, {'summary': {'HIGH': '0'}}, {'emitted_at': None},
                           {'emitted_at': float('inf')}, {'emitted_at': float('nan')},
                           {'emitted_at': True}, {'emitted_at': -1}, {'emitted_at': 10 ** 1000}):
                with self.subTest(scanner=module.__name__, fields=fields):
                    previous = {'summary': result.summary, 'fingerprint': result.fingerprint, 'emitted_at': 0, **fields}
                    state.atomic_write(alert_path, json.dumps(previous))
                    rc, out, err = self.invoke(module, result, '--quiet')
                    self.assertEqual(0, rc, err)
                    self.assertIn('Test evidence', out)

    def test_modes_have_independent_notification_history(self):
        for mode in ('quick', 'deep', 'clam'):
            args = [] if mode == 'quick' else ['--' + mode]
            result = self.result(integrity, mode=mode)
            self.assertTrue(self.invoke(integrity, result, '--quiet', *args)[1])
            self.assertEqual('', self.invoke(integrity, result, '--quiet', *args)[1])

    def test_incomplete_scan_returns_nonzero_and_reports_coverage(self):
        for module in (exposure, integrity):
            rc, out, _ = self.invoke(module, self.result(module, complete=False))
            self.assertEqual(2, rc)
            self.assertIn('False', out)

    def test_no_write_creates_no_state_or_reports(self):
        for module in (exposure, integrity):
            self.invoke(module, self.result(module), '--no-write', '--quiet')
        self.assertFalse(self.state.exists())
        self.assertFalse(self.reports.exists())

    def test_conflicting_baseline_no_write_rejected(self):
        for module in (exposure, integrity):
            with patch.object(sys, 'argv', ['test', '--no-write', '--update-baseline']), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as exc:
                module.main()
            self.assertEqual(2, exc.exception.code)
        self.assertFalse(self.state.exists())

    def test_incomplete_exposure_cannot_replace_baseline(self):
        state.atomic_write(exposure.BASELINE_PATH, '{"approved": true}')
        rc, _, _ = self.invoke(exposure, self.result(exposure, complete=False), '--update-baseline')
        self.assertEqual(2, rc)
        self.assertEqual({'approved': True}, state.load_json(exposure.BASELINE_PATH))

    def test_critical_integrity_cannot_be_baselined(self):
        result = self.result(integrity, severity='CRITICAL')
        result.coverage = {key: {'status': 'passed'} for key in ('ssh_keys', 'crontab', 'systemd_user')}
        self.assertEqual(2, self.invoke(integrity, result, '--update-baseline')[0])
        self.assertFalse(integrity.BASELINE_PATH.exists())

    def test_custom_json_preserves_canonical_latest(self):
        for module in (exposure, integrity):
            output = self.root / (module.__name__ + '.json')
            result = self.result(module)
            self.assertEqual(0, self.invoke(module, result, '--json', str(output))[0])
            self.assertEqual(output.read_text(), module.LAST_PATH.read_text())


class ProfileAndExposureTests(SecurityCase):
    def test_empty_allowlists_and_reapplication_are_respected(self):
        exposure.apply_profile({'lan_allowlist': [22], 'known_services': {8080: {'auth': 'required'}}})
        exposure.apply_profile({'lan_allowlist': [], 'accepted_lan_ports': []})
        self.assertEqual(set(), exposure.LAN_ALLOWLIST)
        self.assertEqual({}, exposure.KNOWN)

    def test_known_service_bind_and_auth_are_enforced(self):
        exposure.apply_profile({'known_services': {8080: {'name': 'api', 'expect_bind': 'loopback', 'auth': 'required'}}})
        findings = self.analyze([exposure.Listener('tcp', '0.0.0.0', 8080, 'lan_all')],
                                [{'port': 8080, 'path': '/models', 'status': 200}])
        self.assertTrue({'BIND_POLICY_VIOLATION', 'AUTH_MISSING'} <= {f.code for f in findings})
        self.assertEqual('CRITICAL', next(f.severity for f in findings if f.code == 'AUTH_MISSING'))

    def test_hub_requires_explicit_acceptance(self):
        listener = exposure.Listener('tcp', '0.0.0.0', 9093, 'lan_all')
        self.assertIn('UNKNOWN_LISTENER', {f.code for f in self.analyze([listener])})
        exposure.apply_profile({'accepted_lan_ports': [9093]})
        self.assertNotIn('UNKNOWN_LISTENER', {f.code for f in self.analyze([listener])})

    def test_protected_endpoint_cannot_mask_open_endpoint(self):
        exposure.apply_profile({'known_services': {4000: {'auth': 'required', 'expect_bind': 'any'}}})
        probes = [{'port': 4000, 'path': '/models', 'status': 200}, {'port': 4000, 'path': '/admin', 'status': 401}]
        codes = {f.code for f in self.analyze([exposure.Listener('tcp', '0.0.0.0', 4000, 'lan_all')], probes)}
        self.assertIn('AUTH_MISSING', codes)
        self.assertNotIn('AUTH_REQUEST_DENIED', codes)

    def test_explicit_public_health_endpoint_does_not_fail_auth(self):
        exposure.apply_profile({'known_services': {4000: {'auth': 'required', 'expect_bind': 'any'}}})
        probes = [{'port': 4000, 'path': '/models', 'status': 401}, {'port': 4000, 'path': '/health', 'status': 200, 'expected_auth': 'public'}]
        codes = {f.code for f in self.analyze([exposure.Listener('tcp', '127.0.0.1', 4000, 'loopback')], probes)}
        self.assertEqual({'AUTH_REQUEST_DENIED'}, codes)

    def test_unavailable_wrong_path_and_server_error_do_not_prove_auth(self):
        exposure.apply_profile({'known_services': {8443: {'auth': 'required', 'expect_bind': 'any'}}})
        for status in (0, 302, 404, 500):
            with self.subTest(status=status):
                codes = {f.code for f in self.analyze([exposure.Listener('tcp', '::', 8443, 'lan_all')], [{'port': 8443, 'path': '/', 'status': status}])}
                self.assertIn('AUTH_UNVERIFIED', codes)
                self.assertNotIn('AUTH_REQUEST_DENIED', codes)

    def test_udp_and_specific_ipv4_ipv6_binds_are_checked(self):
        for proto, addr in (('udp', '0.0.0.0'), ('tcp', '192.168.1.2'), ('udp', '2001:db8::2')):
            findings = self.analyze([exposure.Listener(proto, addr, 7777, exposure.classify_bind(addr))])
            self.assertIn('UNKNOWN_LISTENER', {f.code for f in findings})

    def test_docker_nat_publishes_are_checked_without_ss_listeners(self):
        rows = [{'name': 'fixture', 'ports': '192.168.1.2:8080->80/tcp, [::]:5353->5353/udp, 127.0.0.1:9000-9001->9000-9001/tcp'}]
        listeners = exposure.docker_listeners(rows)
        self.assertEqual([8080, 5353, 9000, 9001], [l.port for l in listeners])
        exposure.apply_profile({'known_services': {8080: {'expect_bind': 'loopback', 'auth': 'required'}}})
        codes = {f.code for f in self.analyze(listeners)}
        self.assertTrue({'BIND_POLICY_VIOLATION', 'AUTH_UNVERIFIED'} <= codes)

    def test_cgnat_is_not_implicitly_a_trusted_tailnet(self):
        self.assertEqual('specific', exposure.classify_bind('100.64.0.10'))
        self.assertEqual('specific', exposure.classify_bind('100.1.2.3'))
        exposure.TAILNET_IPS.add('100.64.0.10')
        self.assertEqual('tailnet', exposure.classify_bind('100.64.0.10'))
        self.assertEqual('loopback', exposure.classify_bind('127.2.3.4'))
        self.assertEqual('loopback', exposure.classify_bind('::ffff:127.0.0.1'))

    def test_zone_scoped_and_ipv6_socket_parsing(self):
        fixture = 'udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:*\ntcp LISTEN 0 128 [::]:8080 [::]:*\nudp UNCONN 0 0 [fe80::1%eth0]:546 [::]:*\n'
        with patch.object(exposure, 'run', return_value=fixture):
            listeners = exposure.parse_ss()
        self.assertEqual([(53, 'loopback'), (8080, 'lan_all'), (546, 'specific')], [(l.port, l.bind_class) for l in listeners])

    def test_failed_socket_collection_is_visible(self):
        with patch.object(exposure, 'lan_and_tail_ips', return_value=([], [])), patch.object(exposure, 'parse_ss', side_effect=FileNotFoundError('ss missing')), patch.object(exposure.shutil, 'which', return_value=None), patch.object(exposure, 'ufw_status', return_value='active'), patch.object(exposure, 'run_host_integrity_quick', return_value={'complete': True}):
            result = exposure.scan()
        self.assertFalse(result.complete)
        self.assertEqual('failed', result.checks['listeners']['status'])
        self.assertIn('COLLECTOR_FAILED', {f['code'] for f in result.findings})

    def test_profiles_fail_closed(self):
        self.config.mkdir()
        for content in ('known_services: [oops]', 'lan_allowlist: "22"', 'known_services: {8080: {auth: optional}}', 'probes: {8080: ["http://example.invalid/"]}', 'lan_allowlist: [70000]', '[]', 'known_services: ['):
            with self.subTest(content=content):
                (self.config / 'config.yaml').write_text(content)
                with self.assertRaises(paths.ProfileError):
                    paths.load_profile()

    def test_host_identity_comes_from_mounted_host(self):
        mounted = self.root / 'mounted'
        (mounted / 'etc').mkdir(parents=True)
        (mounted / 'etc/hostname').write_text('fixture-host\n')
        with patch.dict(os.environ, {'HOST_ROOT': str(mounted)}):
            self.assertEqual('fixture-host', paths.target_hostname())
        with patch.dict(os.environ, {'HOST_ROOT': 'relative'}), self.assertRaises(paths.ProfileError):
            paths.host_root()

    def test_missing_yaml_dependency_is_an_error(self):
        with patch.dict(sys.modules, {'yaml': None}), self.assertRaisesRegex(paths.ProfileError, 'PyYAML'):
            paths.load_profile()

    def test_named_profile_cannot_fall_back_to_unrelated_policy(self):
        self.config.mkdir()
        (self.config / 'config.yaml').write_text('name: unrelated')
        with self.assertRaises(paths.ProfileError):
            paths.load_profile('does-not-exist')
        with self.assertRaises(paths.ProfileError):
            paths.load_profile('../default')

    def test_json_profile_without_yaml_dependency(self):
        self.config.mkdir()
        (self.config / 'default.json').write_text('{"lan_allowlist": [], "known_services": {"8080": {"auth": "required"}}}')
        with patch.dict(sys.modules, {'yaml': None}):
            profile = paths.load_profile()
        self.assertEqual([], profile['lan_allowlist'])
        self.assertIn(8080, profile['known_services'])

    def test_http_probes_do_not_follow_redirects_or_retain_bodies(self):
        requests = []
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append(self.path)
                self.send_response(302 if self.path == '/redirect' else 200)
                if self.path == '/redirect':
                    self.send_header('Location', '/secret')
                self.end_headers()
                self.wfile.write(b'SYNTHETIC_SECRET')
            def log_message(self, *args):
                pass
        server = HTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with patch.dict(os.environ, {'http_proxy': 'http://127.0.0.1:1', 'HTTP_PROXY': 'http://127.0.0.1:1', 'no_proxy': '', 'NO_PROXY': ''}):
                redirected = exposure.http_probe(server.server_port, '/redirect')
                success = exposure.http_probe(server.server_port, '/public')
            self.assertEqual(302, redirected['status'])
            self.assertEqual('unknown', redirected['auth'])
            self.assertEqual(200, success['status'])
            self.assertEqual(['/redirect', '/public'], requests)
            self.assertNotIn('SYNTHETIC_SECRET', json.dumps([redirected, success]))
        finally:
            server.shutdown()
            server.server_close()
            thread.join()


class IntegrityTests(SecurityCase):
    def test_failed_clam_and_timeout_never_clean(self):
        for rc in (2, 124, 127):
            findings, checks = [], {}
            with patch.object(integrity, 'which', return_value='/fixture/clamscan'), patch.object(integrity, 'run', return_value=(rc, '', 'failure')):
                integrity.run_clam(findings, checks, [str(self.root)])
            self.assertEqual('failed', checks['clam']['status'])
            self.assertNotIn('CLAM_CLEAN', {f.code for f in findings})
            self.assertIn('CHECK_FAILED_CLAM', {f.code for f in findings})

    def test_clam_infection_exit_status_is_enough_to_alert(self):
        findings, checks = [], {}
        with patch.object(integrity, 'which', return_value='/fixture/clamscan'), patch.object(integrity, 'run', return_value=(1, '', '')):
            integrity.run_clam(findings, checks, [str(self.root)])
        self.assertIn('CLAM_INFECTED', {f.code for f in findings})

    def test_clean_clam_requires_scanned_files(self):
        for count in (0, 1):
            findings, checks = [], {}
            with patch.object(integrity, 'which', return_value='/fixture/clamscan'), patch.object(integrity, 'run', return_value=(0, f'Scanned files: {count}\nInfected files: 0\n', '')):
                integrity.run_clam(findings, checks, [str(self.root)])
            self.assertEqual(count == 1, 'CLAM_CLEAN' in {f.code for f in findings})

    def test_clam_detections_are_kept_even_with_scan_errors(self):
        findings, checks = [], {}
        with patch.object(integrity, 'which', return_value='/fixture/clamscan'), patch.object(integrity, 'run', return_value=(2, '/fixture: Test-Malware FOUND\n', 'permission denied')):
            integrity.run_clam(findings, checks, [str(self.root)])
        self.assertTrue({'CLAM_INFECTED', 'CHECK_FAILED_CLAM'} <= {f.code for f in findings})

    def test_rootkit_timeout_never_reports_ok(self):
        findings, checks = [], {}
        with patch.object(integrity, 'which', return_value='/fixture/tool'), patch.object(integrity, 'run', return_value=(124, '', 'timeout')):
            integrity.run_optional_rootkit_tools(findings, checks, True)
        self.assertFalse(any(f.code.endswith('_OK') for f in findings))
        self.assertTrue(all(meta['status'] == 'failed' for meta in checks['optional_tools'].values()))

    def test_failed_current_scan_cannot_reuse_cached_clean_result(self):
        state.atomic_write(integrity.LAST_QUICK_PATH, json.dumps(asdict(self.result(integrity, severity=None))))
        with patch.object(integrity, 'scan', side_effect=PermissionError('fixture')):
            data = exposure.run_host_integrity_quick()
        self.assertFalse(data['complete'])
        codes = {f.code for f in exposure.merge_integrity_findings([], data)}
        self.assertIn('HOST_INTEGRITY_INCOMPLETE', codes)
        self.assertNotIn('HOST_INTEGRITY_OK', codes)

    def test_stale_deep_scan_is_visible(self):
        deep = self.result(integrity, severity=None, mode='deep')
        deep.ts = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
        state.atomic_write(integrity.LAST_DEEP_PATH, json.dumps(asdict(deep)))
        with patch.object(integrity, 'scan', return_value=self.result(integrity, severity=None)):
            result = exposure.run_host_integrity_quick()
        self.assertFalse(result['complete'])
        self.assertIn('DEEP_SCAN_INCOMPLETE', {f['code'] for f in result['findings']})

    def test_corrupt_deep_scan_cannot_be_silently_ignored(self):
        deep = asdict(self.result(integrity, severity=None, mode='deep'))
        invalid_reports = [
            {**deep, 'complete': 'false'}, {**deep, 'complete': 1},
            {**deep, 'findings': None}, {**deep, 'findings': [None]},
            {**deep, 'findings': [{'severity': 'HIGH', 'code': 'CLAM_INFECTED'}]},
            {**deep, 'host': 'different-host'}, {**deep, 'mode': 'quick'},
        ]
        for content in ('{truncated', '{}', '[]', *(json.dumps(data) for data in invalid_reports)):
            state.atomic_write(integrity.LAST_DEEP_PATH, content)
            with patch.object(integrity, 'scan', return_value=self.result(integrity, severity=None)):
                result = exposure.run_host_integrity_quick()
            self.assertFalse(result['complete'])
            self.assertEqual('failed', result['coverage']['last_deep']['status'])
            self.assertIn('DEEP_SCAN_INCOMPLETE', {f['code'] for f in result['findings']})

    def test_invalid_deep_report_retains_usable_threat_evidence(self):
        deep = asdict(self.result(integrity, mode='deep'))
        deep['findings'] = [None, asdict(integrity.Finding('CRITICAL', 'CLAM_INFECTED', 'Saved infection', 'fixture evidence'))]
        state.atomic_write(integrity.LAST_DEEP_PATH, json.dumps(deep))
        with patch.object(integrity, 'scan', return_value=self.result(integrity, severity=None)):
            result = exposure.run_host_integrity_quick()
        self.assertFalse(result['complete'])
        self.assertTrue({'CLAM_INFECTED', 'DEEP_SCAN_INCOMPLETE'} <= {f['code'] for f in result['findings']})
        self.assertEqual(1, result['summary']['CRITICAL'])

    def test_valid_deep_report_is_accepted_without_importing_other_hosts(self):
        deep = asdict(self.result(integrity, severity=None, mode='deep'))
        state.atomic_write(integrity.LAST_DEEP_PATH, json.dumps(deep))
        with patch.object(integrity, 'scan', return_value=self.result(integrity, severity=None)):
            result = exposure.run_host_integrity_quick()
        self.assertTrue(result['complete'])
        self.assertEqual('passed', result['coverage']['last_deep']['status'])
        deep['host'] = 'different-host'
        deep['findings'] = [asdict(integrity.Finding('CRITICAL', 'CLAM_INFECTED', 'Foreign infection', 'fixture evidence'))]
        state.atomic_write(integrity.LAST_DEEP_PATH, json.dumps(deep))
        with patch.object(integrity, 'scan', return_value=self.result(integrity, severity=None)):
            result = exposure.run_host_integrity_quick()
        self.assertFalse(result['complete'])
        self.assertNotIn('CLAM_INFECTED', {f['code'] for f in result['findings']})

    def test_native_persistence_is_never_run_in_host_container_mode(self):
        self.stub_integrity_checks()
        self.enterContext(patch.object(integrity, 'run_clam', side_effect=lambda findings, checks, paths: checks.update(clam={'status': 'skipped'})))
        with patch.dict(os.environ, {'HOST_ROOT': '/host'}):
            result = integrity.scan(mode='deep')
        self.assertFalse(result.complete)
        for function in (integrity.check_ssh_keys, integrity.check_user_crontab, integrity.check_systemd_user, integrity.check_world_writable_path):
            function.assert_not_called()
        self.assertEqual('skipped', result.coverage['host_packages']['status'])

    def test_persistence_failure_is_an_incomplete_scan(self):
        self.stub_integrity_checks()
        integrity.check_ssh_keys.side_effect = PermissionError('fixture')
        result = integrity.scan()
        self.assertFalse(result.complete)
        self.assertEqual('failed', result.coverage['ssh_keys']['status'])

    def test_ssh_creation_deletion_modification_and_permissions(self):
        baseline = integrity.check_ssh_keys([], {}, {})
        target = self.home_fixture / '.ssh/authorized_keys'
        target.parent.mkdir()
        target.write_text('ssh-ed25519 SYNTHETIC_KEY\n')
        for change in ('create', 'content', 'permissions', 'delete'):
            if change == 'content': target.write_text('ssh-ed25519 DIFFERENT_SYNTHETIC_KEY\n')
            if change == 'permissions': target.chmod(0o600)
            if change == 'delete': target.unlink()
            findings = []
            baseline = integrity.check_ssh_keys(findings, {}, baseline)
            self.assertIn('SSH_KEYS_CHANGED', {f.code for f in findings}, change)

    def test_first_key_after_legacy_empty_baseline_is_high(self):
        target = self.home_fixture / '.ssh/authorized_keys'
        target.parent.mkdir()
        target.write_text('fixture key')
        findings = []
        integrity.check_ssh_keys(findings, {}, {'ssh_authorized_keys_hash': None})
        self.assertIn('SSH_KEYS_CHANGED', {f.code for f in findings})

    def test_cron_creation_and_deletion_from_empty_baseline(self):
        with patch.object(integrity, 'run', return_value=(1, '', 'no crontab for fixture')):
            baseline = integrity.check_user_crontab([], {}, {})
        findings = []
        with patch.object(integrity, 'run', return_value=(0, '* * * * * /fixture/job --token=SECRET\n', '')):
            baseline = integrity.check_user_crontab(findings, {}, baseline)
        self.assertIn('CRONTAB_CHANGED', {f.code for f in findings})
        self.assertNotIn('SECRET', json.dumps([asdict(f) for f in findings]))
        findings = []
        with patch.object(integrity, 'run', return_value=(1, '', 'no crontab for fixture')):
            integrity.check_user_crontab(findings, {}, baseline)
        self.assertIn('CRONTAB_CHANGED', {f.code for f in findings})

    def test_approved_absence_enables_later_drift_comparison(self):
        # Real persistence collectors run only against fixtures; other collectors are stubbed.
        for name in ('check_ld_preload', 'check_tmp_executables', 'check_fake_kernel_procs',
                     'check_suspicious_cmdline', 'check_proc_ps_gap', 'check_world_writable_path',
                     'check_listening_unknown_high', 'check_tools_absent_summary'):
            self.enterContext(patch.object(integrity, name))
        self.enterContext(patch.object(integrity, 'tool_inventory', return_value={}))
        self.enterContext(patch.object(integrity, 'run', return_value=(1, '', 'no crontab for fixture')))
        self.enterContext(patch.object(integrity, 'systemd_roots', return_value=[self.home_fixture / 'units']))
        result = integrity.scan()
        self.assertFalse(result.complete)
        self.assertEqual('skipped', result.coverage['persistence_baseline']['status'])
        self.assertEqual(0, self.invoke(integrity, result, '--update-baseline')[0])
        self.assertTrue(integrity.scan().complete)
        self.assertFalse(state.load_json(integrity.BASELINE_PATH)['baselines']['ssh_authorized_keys']['exists'])

    def test_cron_permission_error_is_not_an_empty_snapshot(self):
        with patch.object(integrity, 'run', return_value=(1, '', 'permission denied')), self.assertRaises(RuntimeError):
            integrity.check_user_crontab([], {}, {})

    def test_unit_content_and_enablement_changes_are_detected(self):
        root = self.home_fixture / 'units'
        root.mkdir()
        unit = root / 'fixture.service'
        unit.write_text('[Service]\nExecStart=/fixture/approved\n')
        with patch.object(integrity, 'systemd_roots', return_value=[root]):
            baseline = integrity.check_systemd_user([], {}, {})
            unit.write_text('[Service]\nExecStart=/fixture/changed\n')
            findings = []
            baseline = integrity.check_systemd_user(findings, {}, baseline)
            self.assertIn('SYSTEMD_USER_CHANGED', {f.code for f in findings})
            wants = root / 'default.target.wants'
            wants.mkdir()
            (wants / unit.name).symlink_to(unit)
            findings = []
            integrity.check_systemd_user(findings, {}, baseline)
            self.assertIn('SYSTEMD_USER_CHANGED', {f.code for f in findings})

    def test_tmp_exclusions_use_component_boundaries_on_host_mounts(self):
        mounted = self.root / 'mounted'
        safe = mounted / 'tmp/safe'
        unsafe = mounted / 'tmp/safe-lookalike'
        safe.mkdir(parents=True)
        unsafe.mkdir()
        for folder in (safe, unsafe):
            payload = folder / 'fixture'
            payload.write_bytes(b'\x7fELF fixture')
            payload.chmod(0o700)
        with patch.dict(os.environ, {'HOST_ROOT': str(mounted)}), patch.object(integrity, 'PROFILE', {'tmp_allow_prefixes': ['/tmp/safe/']}):
            findings, checks = [], {}
            integrity.check_tmp_executables(findings, checks, deep=False)
        self.assertEqual(1, checks['tmp_executables']['count'])
        self.assertIn('safe-lookalike', findings[0].detail)

    def test_persistence_drift_in_xdg_unit_and_control_directories(self):
        directories = {name: str(self.root / name.lower()) for name in
                       ('XDG_CONFIG_HOME', 'XDG_DATA_HOME', 'XDG_CONFIG_DIRS', 'XDG_DATA_DIRS')}
        with patch.dict(os.environ, directories):
            roots = integrity.systemd_roots()
        unit_roots = [Path(directory) / 'systemd/user' for directory in directories.values()]
        unit_roots.append(Path(directories['XDG_CONFIG_HOME']) / 'systemd/user.control')
        for root in unit_roots:
            self.assertIn(root, roots)
            root.mkdir(parents=True)
        # Exercise the discovered fixture paths without reading system unit directories.
        with patch.object(integrity, 'systemd_roots', return_value=[root for root in roots if root.is_relative_to(self.root)]):
            baseline = integrity.check_systemd_user([], {}, {})
            for root in unit_roots:
                unit = root / 'fixture.service'
                unit.write_text('[Service]\nExecStart=/fixture/unapproved\n')
                findings = []
                baseline = integrity.check_systemd_user(findings, {}, baseline)
                self.assertIn('SYSTEMD_USER_CHANGED', {f.code for f in findings}, str(root))

    def test_hash_never_silently_truncates(self):
        target = self.root / 'large'
        target.write_bytes(b'abcdef')
        self.assertIsNone(integrity.sha256_file(target, limit=5))
        self.assertIsNotNone(integrity.sha256_file(target, limit=6))


class StateAndScriptTests(SecurityCase):
    def test_named_cli_config_is_loaded_on_next_invocation(self):
        command = [sys.executable, str(REPO / 'bin/cyber-posture')]
        result = subprocess.run([*command, 'init-config', '--profile', 'example-lab'], capture_output=True, text=True)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertTrue((self.config / 'example-lab.yaml').is_file())
        result = subprocess.run([*command, '--profile', 'example-lab', 'paths'], capture_output=True, text=True)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn(str(self.config / 'example-lab.yaml'), result.stdout)

    def test_global_cli_profile_applies_to_config_initialization(self):
        command = [sys.executable, str(REPO / 'bin/cyber-posture')]
        result = subprocess.run([*command, '--profile', 'example-lab', 'init-config'], capture_output=True, text=True)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertTrue((self.config / 'example-lab.yaml').is_file())
        self.assertFalse((self.config / 'config.yaml').exists())

    def test_cli_paths_is_read_only(self):
        result = subprocess.run([sys.executable, str(REPO / 'bin/cyber-posture'), 'paths'], capture_output=True, text=True)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertFalse(self.state.exists())
        self.assertFalse(self.config.exists())

    def test_digest_does_not_present_old_success_after_scan_failure(self):
        loader = importlib.machinery.SourceFileLoader('cyber_cli_fixture', str(REPO / 'bin/cyber-posture'))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        cli = importlib.util.module_from_spec(spec)
        loader.exec_module(cli)
        state.atomic_write(self.state / 'last-scan.json', '{"host": "OLD_SUCCESS", "summary": {}}')
        out, err = io.StringIO(), io.StringIO()
        with patch.object(cli, '_run_module', return_value=2), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(2, cli.cmd_digest(None))
        self.assertNotIn('OLD_SUCCESS', out.getvalue())
        self.assertIn('incomplete', err.getvalue())

    def test_private_atomic_reports_and_symlink_rejection(self):
        output = self.root / 'private' / 'report.json'
        previous_umask = os.umask(0o022)
        try:
            state.atomic_write(output, 'one')
            self.assertEqual(0o700, stat.S_IMODE(output.parent.stat().st_mode))
            self.assertEqual(0o600, stat.S_IMODE(output.stat().st_mode))
            state.atomic_write(output, 'two')
        finally:
            os.umask(previous_umask)
        self.assertEqual('two', output.read_text())
        link = self.root / 'link'
        link.symlink_to(output)
        with self.assertRaises(OSError):
            state.atomic_write(link, 'overwrite')
        self.assertEqual('two', output.read_text())

    def test_all_new_managed_ancestors_are_private(self):
        with state.scan_lock(self.state / 'host-integrity', 'fixture'):
            pass
        self.assertEqual(0o700, stat.S_IMODE(self.state.stat().st_mode))
        self.assertEqual(0o700, stat.S_IMODE((self.state / 'host-integrity').stat().st_mode))

    def test_overlapping_scan_and_lock_symlink_rejected(self):
        with state.scan_lock(self.state, 'test'):
            with self.assertRaises(BlockingIOError), state.scan_lock(self.state, 'test'):
                pass
        link = self.state / '.unsafe.lock'
        target = self.root / 'unchanged'
        target.write_text('safe')
        link.symlink_to(target)
        with self.assertRaises(OSError), state.scan_lock(self.state, 'unsafe'):
            pass
        self.assertEqual('safe', target.read_text())

    def fake_command(self, name):
        target = self.root / 'commands' / name
        target.parent.mkdir(exist_ok=True)
        log = self.root / (name + '.json')
        target.write_text('#!/usr/bin/python3\nimport json,sys\nfrom pathlib import Path\n' + f'Path({str(log)!r}).write_text(json.dumps(sys.argv[1:]))\n')
        target.chmod(0o700)
        return log, {**os.environ, 'PATH': str(target.parent) + os.pathsep + os.environ['PATH']}

    def test_release_version_inputs_cannot_execute_shell(self):
        import yaml
        workflow = yaml.safe_load((REPO / '.github/workflows/release.yml').read_text())
        script = next(step['run'] for step in workflow['jobs']['release']['steps'] if step.get('id') == 'ver')
        marker = self.root / 'must-not-exist'
        for tag, expected in (('v1.2.3', 0), (f'$(touch {marker})', 1), ('v1.2.3\nextra=value', 1)):
            output = self.root / 'version-output'
            output.write_text('')
            env = {**os.environ, 'GITHUB_EVENT_NAME': 'workflow_dispatch', 'INPUT_TAG': tag,
                   'GITHUB_OUTPUT': str(output), 'GITHUB_SHA': 'a' * 40, 'GITHUB_REF_TYPE': 'branch'}
            result = subprocess.run(['bash', '-e', '-c', script], cwd=REPO, env=env, capture_output=True, text=True)
            self.assertEqual(expected, result.returncode, result.stderr)
            self.assertFalse(marker.exists())
            if expected == 0:
                self.assertEqual('version=1.2.3\n', output.read_text())
            else:
                self.assertEqual('', output.read_text())

    def test_hardening_defaults_only_preview(self):
        log, env = self.fake_command('ufw')
        for script in ('harden-host.sh', 'fix-hub-access.sh'):
            result = subprocess.run(['bash', str(REPO / 'scripts' / script)], env=env, text=True, capture_output=True)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertIn('Preview only', result.stdout)
            self.assertFalse(log.exists())

    def test_hub_lan_access_requires_explicit_source(self):
        result = subprocess.run(['bash', str(REPO / 'scripts/fix-hub-access.sh'), '--interface', 'eth0'], text=True, capture_output=True)
        self.assertEqual(2, result.returncode)
        self.assertIn('--from', result.stderr)

    def test_invalid_ports_are_rejected_before_apply(self):
        log, env = self.fake_command('ufw')
        for value in ('0', '65536', '22;false', '-1', '18446744073709551638', '9' * 200):
            result = subprocess.run(['bash', str(REPO / 'scripts/harden-host.sh'), '--ssh-port', value, '--apply'], env=env, text=True, capture_output=True)
            self.assertNotEqual(0, result.returncode)
            self.assertFalse(log.exists())

    def firewall_backup(self, status='active'):
        backup = self.root / 'firewall-backup'
        (backup / 'ufw').mkdir(parents=True, exist_ok=True)
        (backup / 'default-ufw').write_text('fixture default settings')
        (backup / 'status.txt').write_text(f'Status: {status}\n')
        return backup

    def restore_fixture(self, backup, **failure_env):
        # All privileged operations are stubbed; no host configuration is read or changed.
        script = '''set -eEuo pipefail
source "$1"
copy_calls=0
ufw_calls=0
require_root_ufw() { return "${REQUIRE_RC:-0}"; }
stat() { printf '0\\n'; }
cp() {
  copy_calls=$((copy_calls + 1))
  printf 'COPY:%s\\n' "$copy_calls"
  if [[ "$copy_calls" == "${COPY_FAIL_AT:-0}" ]]; then return 47; fi
  return 0
}
ufw() {
  ufw_calls=$((ufw_calls + 1))
  printf 'UFW:%s\\n' "$*"
  if [[ "$ufw_calls" == "${UFW_FAIL_AT:-0}" ]]; then return 48; fi
  return 0
}
if restore_firewall "$2"; then exit 0; else exit "$?"; fi
'''
        return subprocess.run(['bash', '-c', script, 'fixture', str(REPO / 'scripts/firewall-common.sh'), str(backup)],
                              env={**os.environ, **failure_env}, capture_output=True, text=True)

    def test_firewall_restore_errors_are_propagated_in_conditional_calls(self):
        backup = self.firewall_backup()
        for env, rc, copies, ufw_calls in (
            ({'REQUIRE_RC': '2'}, 2, 0, 0),
            ({'COPY_FAIL_AT': '1'}, 47, 1, 0), ({'COPY_FAIL_AT': '2'}, 47, 2, 0),
            ({'UFW_FAIL_AT': '1'}, 48, 2, 1), ({'UFW_FAIL_AT': '2'}, 48, 2, 2),
        ):
            with self.subTest(env=env):
                result = self.restore_fixture(backup, **env)
                self.assertEqual(rc, result.returncode, result.stderr)
                self.assertEqual(copies, result.stdout.count('COPY:'))
                self.assertEqual(ufw_calls, result.stdout.count('UFW:'))
                self.assertNotIn('Restored firewall', result.stdout)

    def test_firewall_restore_preserves_active_and_inactive_state(self):
        for status, expected_calls in (('active', ['--force enable', 'reload']), ('inactive', ['--force disable'])):
            with self.subTest(status=status):
                result = self.restore_fixture(self.firewall_backup(status))
                self.assertEqual(0, result.returncode, result.stderr)
                calls = [line.removeprefix('UFW:') for line in result.stdout.splitlines() if line.startswith('UFW:')]
                self.assertEqual(expected_calls, calls)
                self.assertIn('Restored firewall', result.stdout)

    def test_invalid_backup_status_cannot_disable_firewall(self):
        result = self.restore_fixture(self.firewall_backup('unrecognized'))
        self.assertEqual(2, result.returncode)
        self.assertIn('status is invalid', result.stderr)
        self.assertNotIn('COPY:', result.stdout)
        self.assertNotIn('UFW:', result.stdout)

    def test_apply_failure_attempts_rollback_and_reports_restore_failure(self):
        backup = self.firewall_backup()
        scripts = self.root / 'scripts'
        scripts.mkdir()
        common = (REPO / 'scripts/firewall-common.sh').read_text() + '''
require_root_ufw() { return 0; }
backup_firewall() { FIREWALL_BACKUP="$TEST_BACKUP"; }
stat() { printf '0\\n'; }
ip() { return 0; }
cp() { printf 'COPY\\n'; return "${COPY_RC:-0}"; }
ufw() {
  printf 'UFW:%s\\n' "$*"
  if [[ "$1" == allow ]]; then return 41; fi
  return 0
}
'''
        (scripts / 'firewall-common.sh').write_text(common)
        for name in ('harden-host.sh', 'fix-hub-access.sh'):
            script = scripts / name
            script.write_text((REPO / 'scripts' / name).read_text())
            for copy_rc in ('0', '47'):
                with self.subTest(script=name, copy_rc=copy_rc):
                    env = {**os.environ, 'TEST_BACKUP': str(backup), 'COPY_RC': copy_rc}
                    result = subprocess.run(['bash', str(script), '--apply'], env=env, capture_output=True, text=True)
                    self.assertEqual(41, result.returncode, result.stderr)
                    self.assertIn('Firewall update failed; restoring', result.stderr)
                    if copy_rc == '0':
                        self.assertIn('Restored firewall', result.stdout)
                        self.assertIn('UFW:reload', result.stdout)
                    else:
                        self.assertIn('Automatic restore failed', result.stderr)
                        self.assertNotIn('Restored firewall', result.stdout)
                        self.assertNotIn('UFW:reload', result.stdout)

    def test_docker_helper_uses_restricted_mounts_without_socket(self):
        log, env = self.fake_command('docker')
        env['CYBER_IMAGE'] = 'fixture@sha256:example'
        result = subprocess.run(['bash', str(REPO / 'scripts/docker-run-host.sh'), 'scan'], env=env, capture_output=True, text=True)
        self.assertEqual(0, result.returncode, result.stderr)
        args = json.loads(log.read_text())
        self.assertIn('--read-only', args)
        self.assertEqual('ALL', args[args.index('--cap-drop') + 1])
        self.assertIn('no-new-privileges', args)
        self.assertNotIn('docker.sock', ' '.join(args))
        mounts = [args[n + 1] for n, value in enumerate(args) if value == '--mount']
        self.assertTrue(all('readonly' in mount for mount in mounts if 'target=/var/lib/cyber-posture' not in mount))
        self.assertEqual('fixture@sha256:example', args[-2])


if __name__ == '__main__':
    unittest.main()
