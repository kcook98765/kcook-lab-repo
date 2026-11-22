"""Exact-root Nexus metadata controls. Synthetic index, no approval/runtime claims."""
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import official_nexus as producer
import audit_official_nexus as auditor
import official_omega
import audit_official_omega
import repository
import audit_candidate


class OfficialNexus(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='official-nexus-')
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name)
        self.now = datetime(2026, 11, 22, 12, tzinfo=timezone.utc)
        self.root = ET.fromstring('''<addon id="script.tvguide.fullscreen" version="0.1.1"><requires>
          <import addon="xbmc.python" version="3.0.0"/>
          <import addon="script.module.requests" version="2.31.0"/>
          <import addon="script.module.dateutil" version="2.8.2"/>
          <import addon="script.module.pytz" version="2023.3.0+matrix.1"/>
          <import addon="script.module.pil" version="5.1.0"/>
          <import addon="script.module.beautifulsoup4" version="4.12.2"/>
          </requires><extension point="xbmc.python.script" library="addon.py"/>
          <extension point="xbmc.service" library="service.py"/></addon>''')
        self.index = ET.fromstring('''<addons>
          <addon id="script.module.requests" version="2.31.0"><requires>
            <import addon="xbmc.python" version="3.0.0"/>
            <import addon="script.module.child" version="1.0.0+matrix.2"/></requires></addon>
          <addon id="script.module.child" version="1.0.0+matrix.10"/>
          <addon id="script.module.dateutil" version="2.8.2"/>
          <addon id="script.module.pytz" version="2023.3.0+matrix.1"/>
          <addon id="script.module.beautifulsoup4" version="4.12.2"/>
          </addons>''')
        self.builtins = {'xbmc.addon': '20.0.0', 'xbmc.python': '3.0.1'}
        self.binding = {producer.ROOT_ID: {k: producer.ROOT_BINDING[k] for k in ('source_commit', 'package_sha256')} |
                        {'source_repository': 'https://github.com/kcook98765/script.tvguide.fullscreen'}}
        self.spec = dict(schema=1, source_url=producer.SOURCE_URL, core_commit=producer.CORE_COMMIT,
                         snapshot='nexus.xml', snapshot_sha256='0' * 64,
                         retrieved_at='2026-11-22T11:00:00Z', expires_at='2026-11-29T11:00:00Z',
                         roots={producer.ROOT_ID: copy.deepcopy(producer.ROOT_BINDING)},
                         allowlist={n.get('id'): n.get('version') for n in self.index})
        self.save()

    def save(self, raw=None):
        raw = ET.tostring(self.index) if raw is None else raw
        (self.base / 'nexus.xml').write_bytes(raw)
        self.spec['snapshot_sha256'] = hashlib.sha256(raw).hexdigest()

    def resolve(self, module, manifests=None, lane='nexus'):
        return module.resolve([self.root] if manifests is None else manifests, self.builtins,
                              {'official_nexus': self.spec}, self.base, lane, self.binding, now=self.now)

    def both(self, **kwargs):
        reports = [self.resolve(m, **kwargs) for m in (producer, auditor)]
        self.assertEqual(*reports)
        return reports[0]

    def rejected(self, pattern='.', **kwargs):
        for module in (producer, auditor):
            with self.subTest(module=module.__name__), self.assertRaisesRegex(ValueError, pattern):
                self.resolve(module, **kwargs)

    def test_exact_root_all_six_imports_and_core_abi(self):
        report = self.both()
        self.assertEqual(report['external_versions'], self.spec['allowlist'])
        self.assertEqual(report['core_versions'], {'xbmc.core': '0.1.0', 'xbmc.python': '3.0.1', 'script.module.pil': '5.1.0'})
        self.assertEqual(len([e for e in report['edges'] if e['parent'] == producer.ROOT_ID]), 6)
        self.assertEqual(report['core_commit'], '4b95737efaddf7c869736e539318f18433413ff1')
        repository.dependencies([self.root], {**self.builtins, **report['core_versions']}, report['external_versions'])
        audit_candidate.check_dependencies([self.root], {**self.builtins, **report['core_versions']}, report['external_versions'])

    def test_only_nexus_and_no_foreign_root(self):
        for lane in ('matrix', 'omega', 'piers'):
            self.rejected('Nexus 20.5-only', lane=lane)
        self.root.set('id', 'skin.aura')
        self.assertFalse(self.both()['active'])
        self.spec['roots'] = {'skin.aura': self.spec['roots'][producer.ROOT_ID]}
        self.rejected('exact frozen')

    def test_exact_source_zip_root_pins_cannot_be_rebound(self):
        self.assertEqual(producer.ROOT_BINDING, auditor.ENROLLED)
        self.assertEqual(producer.ROOT_BINDING['version'], '0.1.1')
        self.assertEqual(producer.ROOT_BINDING['source_commit'], 'f936c0a514e0de126e62e24fd3d24b66b0c74097')
        self.assertEqual(producer.ROOT_BINDING['package_sha256'], '76533fcb570cd813e2deb885c919b59eea21171c6ce344d5a40ef5d8fba287b9')
        for key, value in [('source_commit', 'a' * 40), ('package_sha256', 'b' * 64), ('version', '0.1.0'),
                           ('source_commit', 'c19f256333efbe7af12418312f17e00f99792dc2'),
                           ('package_sha256', 'da5f38eed4707aa6de9ac7d9648008565ac332f51e93dc6cc5dab6f11f00f82e'),
                           ('source_commit', '42997e3c80784262be4e35c8d37e772c62bc5d6f'),
                           ('package_sha256', '0b25379c9eb71bd6e9014704114e5b3a7104c6fbbd9e209a97f5e189f7464492')]:
            old = self.spec['roots'][producer.ROOT_ID][key]
            self.spec['roots'][producer.ROOT_ID][key] = value
            self.rejected('exact frozen')
            self.spec['roots'][producer.ROOT_ID][key] = old
        for key in ('source_commit', 'package_sha256', 'source_repository'):
            old = self.binding[producer.ROOT_ID][key]
            self.binding[producer.ROOT_ID][key] = 'wrong'
            self.rejected('binding mismatch')
            self.binding[producer.ROOT_ID][key] = old

    def test_former_010_cannot_borrow_successor_enrollment(self):
        # A former manifest must fail even with the successor's spec/bindings.
        self.root.set('version', '0.1.0')
        self.rejected('manifest mismatch')
        self.root.set('version', '0.1.1')
        # A successor manifest must not launder the former source or ZIP either.
        for key, value in [('source_commit', 'c19f256333efbe7af12418312f17e00f99792dc2'),
                           ('package_sha256', 'da5f38eed4707aa6de9ac7d9648008565ac332f51e93dc6cc5dab6f11f00f82e')]:
            old = self.binding[producer.ROOT_ID][key]
            self.binding[producer.ROOT_ID][key] = value
            self.rejected('binding mismatch')
            self.binding[producer.ROOT_ID][key] = old

    def test_enrolled_manifest_is_not_a_general_script_adapter(self):
        for dep in self.root.findall('requires/import'):
            old = dep.get('version'); dep.set('version', '0.0.0')
            self.rejected('manifest mismatch'); dep.set('version', old)
        self.root.find('extension').set('library', 'other.py')
        self.rejected('manifest mismatch')

    def test_exact_source_schema_and_no_extra_keys(self):
        for key, value in [('source_url', official_omega.SOURCE_URL), ('source_url', producer.SOURCE_URL + '?x'),
                           ('core_commit', official_omega.CORE_COMMIT), ('schema', True), ('schema', 2)]:
            old = self.spec[key]; self.spec[key] = value
            self.rejected('unsupported'); self.spec[key] = old
        self.spec['extra'] = True; self.rejected('malformed')

    def test_snapshot_window_expired_future_and_too_old(self):
        for key, value in [('retrieved_at', '2026-11-23T11:00:00Z'), ('expires_at', '2026-11-22T12:00:00Z'),
                           ('expires_at', '2026-11-30T11:00:00Z'), ('retrieved_at', '2026-02-30T00:00:00Z')]:
            old = self.spec[key]; self.spec[key] = value
            self.rejected(); self.spec[key] = old
        self.now += timedelta(days=8); self.rejected('expired')

    def test_tamper_unsafe_path_link_entities_and_size(self):
        self.spec['snapshot_sha256'] = 'c' * 64; self.rejected('checksum'); self.save()
        for path in ('../nexus.xml', '/tmp/nexus.xml', 'a//b', '.hidden/x', 'x\\y', 'nexus.xml.'):
            self.spec['snapshot'] = path; self.rejected('path')
        self.spec['snapshot'] = 'nexus.xml'
        location = self.base / 'nexus.xml'; location.unlink(); location.symlink_to(ROOT / 'LICENSE')
        self.rejected('linked'); location.unlink()
        self.save(b'<!DOCTYPE addons [<!ENTITY x "test">]><addons/>'); self.rejected('entities')
        self.save(b'<addons/>'.decode().encode('utf-16')); self.rejected('UTF-8')
        self.save(b'x' * 32_000_001); self.rejected('large')

    def test_unnecessary_missing_old_and_builtin_allowlist(self):
        original = dict(self.spec['allowlist'])
        for key, val in [('script.unused', '1.0.0'), ('xbmc.python', '3.0.1'), ('script.module.child', '1.0.0')]:
            self.spec['allowlist'] = {**original, key: val}; self.rejected()
        self.spec['allowlist'] = original; del self.spec['allowlist']['script.module.child']; self.rejected('allowlist')

    def test_newest_broken_ambiguous_and_too_old_providers(self):
        self.index[1].set('version', '1.0.0+matrix.1')
        self.spec['allowlist']['script.module.child'] = '1.0.0+matrix.1'; self.save(); self.rejected('too old')
        self.index[1].set('version', '1.0.0+matrix.10')
        self.spec['allowlist']['script.module.child'] = '1.0.0+matrix.10'
        broken = ET.SubElement(self.index[1], 'extension', point='xbmc.addon.metadata')
        ET.SubElement(broken, 'broken').text = 'withdrawn'; self.save(); self.rejected('broken')
        self.index[1].remove(broken)
        duplicate = copy.deepcopy(self.index[0]); duplicate.find('requires/import').set('version', '3.1.0')
        self.index.append(duplicate); self.save(); self.rejected('ambiguous platform')
        self.index.remove(duplicate)
        ET.SubElement(self.index, 'addon', id='script.module.child', version='2.0.0')
        self.save(); self.rejected('allowlist')

    def test_dependency_cycle_duplicate_import_and_builtin_abi(self):
        group = ET.SubElement(self.index[1], 'requires')
        dep = ET.SubElement(group, 'import', addon='script.module.requests', version='2.31.0')
        self.save(); self.rejected('cycle')
        dep.set('addon', 'xbmc.python'); dep.set('version', '2.0.0'); self.save(); self.rejected('ABI')
        dep.set('version', '3.1.0'); self.save(); self.rejected('ABI')
        dep.set('version', '3.0.0'); group.append(copy.deepcopy(dep)); self.save(); self.rejected('duplicate')

    def test_available_optional_descendants_required_missing_optional_diagnostic(self):
        group = self.index[0].find('requires')
        opt = ET.SubElement(group, 'import', addon='script.optional', version='1.0.0', optional='true')
        self.save(); self.assertEqual(self.both()['unavailable_optional'][0]['addon'], 'script.optional')
        node = ET.SubElement(self.index, 'addon', id='script.optional', version='1.0.0')
        self.spec['allowlist']['script.optional'] = '1.0.0'
        ET.SubElement(ET.SubElement(node, 'requires'), 'import', addon='script.missing', version='1.0.0')
        self.save(); self.rejected('absent')
        opt.set('optional', 'bad'); self.save(); self.rejected('optional')

    def test_no_substitution_or_unrelated_borrowing(self):
        extra = ET.fromstring('<addon id="script.module.pytz" version="2023.3.0"/>')
        self.rejected('substituted', manifests=[self.root, extra])
        extra = ET.fromstring('<addon id="script.other" version="1.0.0"><requires><import addon="script.module.pytz" version="1.0.0"/></requires></addon>')
        self.rejected('unrelated', manifests=[self.root, extra])
        extra.find('requires/import').set('addon', 'script.module.pil')
        self.rejected('unrelated', manifests=[self.root, extra])
        self.builtins['xbmc.python'] = '3.1.0'; self.rejected('configured built-in')

    def test_aura_cannot_borrow_nexus_and_tvguide_cannot_borrow_aura(self):
        for module in (official_omega, audit_official_omega):
            with self.assertRaisesRegex(ValueError, 'unsupported external'):
                self.resolve(module)

    def test_all_dependency_grammars_reject_arbitrary_punctuation(self):
        for parser in (official_omega._parts, audit_official_omega.parse_version):
            for value in (None, 1, True, '', 'abc', '+', '1..0', '1.0+', '../1', '1.0\n', '2147483648.0'):
                with self.subTest(value=value, parser=parser.__module__), self.assertRaises(ValueError): parser(value)

    def test_consumer_dispatch_and_pins(self):
        (self.base / 'config').mkdir()
        (self.base / 'config/candidate.json').write_text(json.dumps({'external_dependencies': {'official_nexus': self.spec}}))
        for module in (repository, audit_candidate):
            with patch.object(module, 'ROOT', self.base), patch.object(
                    producer if module is repository else auditor, 'resolve', return_value={'active': True, 'dispatch': 'nexus'}) as call:
                self.assertEqual(module.external_dependency_report('candidate', [self.root], self.builtins, 'nexus', self.binding),
                                 {'active': True, 'dispatch': 'nexus'})
                self.assertEqual(call.call_args.args[4], 'nexus')
        with patch.object(repository, 'ROOT', self.base):
            pins = repository.dependency_toolchain('candidate')
            self.assertEqual(set(pins), {name + '_sha256' for name in ('official_nexus', 'audit_official_nexus', 'official_omega', 'audit_official_omega')})

    def test_combined_configuration_keeps_both_exact_root_adapters(self):
        (self.base / 'config').mkdir()
        (self.base / 'incoming').mkdir()
        (self.base / 'incoming/nexus.xml').write_bytes((self.base / 'nexus.xml').read_bytes())
        current = datetime.now(timezone.utc)
        self.spec['retrieved_at'] = (current - timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ')
        self.spec['expires_at'] = (current + timedelta(days=6)).strftime('%Y-%m-%dT%H:%M:%SZ')
        omega_spec = copy.deepcopy(self.spec)
        omega_spec.update(source_url=official_omega.SOURCE_URL, core_commit=official_omega.CORE_COMMIT,
            allowlist={'script.module.dateutil': '2.8.2'},
            roots={'skin.aura': {'version': '2.1.0', 'source_commit': 'a' * 40, 'package_sha256': 'b' * 64}})
        aura = ET.fromstring('''<addon id="skin.aura" version="2.1.0"><requires>
            <import addon="xbmc.gui" version="5.17.0"/><import addon="script.module.dateutil" version="2.8.2"/>
            </requires><extension point="xbmc.gui.skin"/></addon>''')
        bindings = {**self.binding, 'skin.aura': {'source_commit': 'a' * 40, 'package_sha256': 'b' * 64,
                                              'source_repository': 'https://github.com/kcook98765/skin.aura'}}
        combined = {'official_nexus': self.spec, 'official_omega': omega_spec}
        config_file = self.base / 'config/candidate.json'
        def write(spec): config_file.write_text(json.dumps({'external_dependencies': spec}))
        def run(module, manifests, builtins, lane):
            with patch.object(module, 'ROOT', self.base):
                return module.external_dependency_report('candidate', manifests, builtins, lane, bindings)
        for module in (repository, audit_candidate):
            for lane, manifests, builtins, own in (
                ('nexus', [self.root], self.builtins, 'official_nexus'),
                ('omega', [aura], {'xbmc.gui': '5.17.0', 'xbmc.python': '3.0.1'}, 'official_omega')):
                write({own: combined[own]}); single = run(module, manifests, builtins, lane)
                write(combined); self.assertEqual(single, run(module, manifests, builtins, lane))
                foreign = ET.fromstring('<addon id="script.unrelated" version="1.0.0"><requires><import addon="script.module.dateutil" version="1.0.0"/></requires></addon>')
                with self.assertRaisesRegex(ValueError, 'unrelated'):
                    run(module, manifests + [foreign], builtins, lane)
                with self.assertRaisesRegex(ValueError, 'only|own exact Omega enrollment'):
                    run(module, [aura, self.root], builtins, lane)
            write(combined)
            self.assertFalse(run(module, [], {}, 'matrix')['active'])
            # Inactive adapters must still validate their inputs and expiry.
            omega_spec['snapshot_sha256'] = 'c' * 64; write(combined)
            with self.assertRaisesRegex(ValueError, 'checksum'):
                run(module, [self.root], self.builtins, 'nexus')
            omega_spec['snapshot_sha256'] = self.spec['snapshot_sha256']
            write({**combined, 'arbitrary_provider': {}})
            with self.assertRaises((ValueError, AssertionError)):
                run(module, [], {}, 'matrix')
            write(combined)
            with patch.object(module, 'ROOT', self.base), patch.object(
                    official_omega if module is repository else audit_official_omega, 'resolve', return_value={'active': True}), patch.object(
                    producer if module is repository else auditor, 'resolve', return_value={'active': True}):
                with self.assertRaises((ValueError, AssertionError)):
                    module.external_dependency_report('candidate', [], {}, 'matrix', {})


if __name__ == '__main__': unittest.main()
