"""Focused positive/adverse controls for official Omega-only dependency evidence."""
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import importlib
from pathlib import Path
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import official_omega as producer
import audit_official_omega as auditor


class OfficialOmega(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='official-omega-')
        self.addCleanup(self.tmp.cleanup)
        self.incoming = Path(self.tmp.name)
        self.now = datetime(2026, 11, 14, 12, tzinfo=timezone.utc)
        self.aura = ET.fromstring('''<addon id="skin.aura" version="2.1.0"><requires>
            <import addon="xbmc.gui" version="5.17.0"/>
            <import addon="script.example" version="1.2.0"/>
            </requires><extension point="xbmc.gui.skin"/></addon>''')
        self.builtins = {'xbmc.gui': '5.17.0', 'xbmc.python': '3.0.1', 'xbmc.addon': '21.0.0'}
        self.index = ET.fromstring('''<addons><addon id="script.example" version="1.2.0+matrix.2">
            <requires><import addon="script.module.child" version="1.0.0+matrix.1"/></requires></addon>
            <addon id="script.module.child" version="1.0.0+matrix.3"><requires>
            <import addon="xbmc.python" version="3.0.0"/></requires></addon></addons>''')
        self.bindings = {'skin.aura': {'package_sha256': 'a' * 64, 'source_commit': 'b' * 40,
                                     'source_repository': 'https://github.com/kcook98765/skin.aura'}}
        self.spec = {'schema': 1, 'source_url': producer.SOURCE_URL, 'snapshot': 'omega-addons.xml',
                     'snapshot_sha256': '0' * 64, 'retrieved_at': '2026-11-14T11:00:00Z',
                     'expires_at': '2026-11-21T11:00:00Z', 'core_commit': producer.CORE_COMMIT,
                     'allowlist': {'script.example': '1.2.0+matrix.2', 'script.module.child': '1.0.0+matrix.3'},
                     'roots': {'skin.aura': {'version': '2.1.0', 'package_sha256': 'a' * 64, 'source_commit': 'b' * 40}}}
        self.save()

    def save(self, raw=None):
        raw = ET.tostring(self.index) if raw is None else raw
        (self.incoming / 'omega-addons.xml').write_bytes(raw)
        self.spec['snapshot_sha256'] = hashlib.sha256(raw).hexdigest()

    def both(self, selected=None, external=None, lane='omega'):
        args = (selected if selected is not None else [self.aura], self.builtins,
                {'official_omega': self.spec} if external is None else external,
                self.incoming, lane, self.bindings)
        reports = [m.resolve(*args, now=self.now) for m in (producer, auditor)]
        self.assertEqual(*reports)
        return reports[0]

    def rejected(self, expression=None, **kwargs):
        for module in (producer, auditor):
            with self.subTest(module=module.__name__), self.assertRaisesRegex(ValueError, expression or '.'):
                module.resolve(kwargs.get('selected', [self.aura]), self.builtins,
                    kwargs.get('external', {'official_omega': self.spec}), self.incoming,
                    kwargs.get('lane', 'omega'), self.bindings, now=self.now)

    def test_exact_closure_distinguishes_external_and_core(self):
        report = self.both()
        self.assertEqual(report['external_versions'], self.spec['allowlist'])
        self.assertEqual(report['core_versions'], {'xbmc.core': '0.1.0', 'xbmc.gui': '5.17.0', 'xbmc.python': '3.0.1'})
        self.assertTrue(report['active'])
        self.assertIn('no dependency installation', report['warnings'][0])

    def test_ordinary_and_other_lane_behavior_is_unchanged(self):
        self.assertFalse(self.both(external={})['active'])
        self.assertFalse(self.both(selected=[], lane='matrix')['active'])
        self.rejected('Omega-only', lane='nexus')
        self.spec['snapshot'] = '../invalid.xml'
        self.rejected('path', selected=[], lane='matrix')
        self.spec['snapshot'] = 'omega-addons.xml'
        self.spec['snapshot_sha256'] = 'c' * 64
        self.rejected('checksum', selected=[], lane='matrix')
        self.spec['unreviewed'] = True
        self.rejected('malformed', selected=[], lane='matrix')

    def test_source_scope_and_package_bindings(self):
        for key, value in [('source_commit', 'c' * 40), ('package_sha256', 'd' * 64),
                           ('source_repository', 'https://github.com/other/skin.aura')]:
            old = self.bindings['skin.aura'][key]
            self.bindings['skin.aura'][key] = value
            self.rejected('binding mismatch')
            self.bindings['skin.aura'][key] = old
        self.aura.remove(self.aura.find('extension'))
        self.rejected('not Aura')

    def test_closed_provider_origin_schema_and_root_enrollment(self):
        original = copy.deepcopy(self.spec)
        for key, value in [('source_url', 'https://evil.invalid/addons/omega/addons.xml.gz'),
                           ('source_url', producer.SOURCE_URL + '?token=x'), ('core_commit', 'c' * 40), ('schema', True)]:
            self.spec = copy.deepcopy(original);self.spec[key] = value;self.rejected()
        self.spec = copy.deepcopy(original);self.spec['roots']['script.other'] = self.spec['roots'].pop('skin.aura');self.rejected('only Aura')
        self.rejected('unsupported external', external={'other': {}})

    def test_current_seven_day_snapshot_window(self):
        for key, value in [('retrieved_at', '2026-11-15T00:00:00Z'), ('expires_at', '2026-11-14T12:00:00Z'),
                           ('expires_at', '2026-11-22T11:00:00Z'), ('retrieved_at', '2026-02-30T00:00:00Z')]:
            old = self.spec[key];self.spec[key] = value;self.rejected();self.spec[key] = old
        self.now += timedelta(days=8)
        self.rejected('expired')

    def test_hash_paths_symlinks_and_xml_entities(self):
        self.spec['snapshot_sha256'] = 'c' * 64;self.rejected('checksum');self.save()
        for name in ['../omega-addons.xml', '/tmp/index.xml', 'a//b.xml', '.private/index.xml', 'x\\y.xml', 'index.xml.']:
            self.spec['snapshot'] = name;self.rejected('path')
        self.spec['snapshot'] = 'omega-addons.xml'
        path = self.incoming / 'omega-addons.xml';path.unlink();path.symlink_to(ROOT / 'docs/REVIEW-RECORD-SCHEMA.json');self.rejected('linked');path.unlink()
        self.save('<!DOCTYPE addons [<!ENTITY bad "oops">]><addons/>'.encode('utf-16'));self.rejected('UTF-8')
        self.save(b'<!DOCTYPE addons [<!ENTITY bad "oops">]><addons/>');self.rejected('entities')

    def test_allowlist_has_no_missing_extra_or_builtin_ids(self):
        original = dict(self.spec['allowlist'])
        del self.spec['allowlist']['script.module.child'];self.rejected('allowlist')
        self.spec['allowlist'] = {**original, 'script.unused': '1.0.0'};self.rejected('unused')
        self.spec['allowlist'] = {**original, 'xbmc.python': '3.0.1'};self.rejected('allowlist')
        self.spec['allowlist'] = {**original, 'script.example': '1.2.0'};self.rejected('allowlist')

    def test_newest_provider_must_be_allowlisted_no_old_fallback(self):
        ET.SubElement(self.index, 'addon', id='script.example', version='2.0.0')
        self.save();self.rejected('allowlist')

    def test_broken_provider_and_ambiguous_platforms(self):
        extension = ET.SubElement(self.index[0], 'extension', point='xbmc.addon.metadata')
        ET.SubElement(extension, 'broken').text = 'Withdrawn'
        self.save();self.rejected('broken')
        self.index[0].remove(extension)
        duplicate = copy.deepcopy(self.index[0]);duplicate.find('requires/import').set('version', '99.0.0');self.index.append(duplicate)
        self.save();self.rejected('ambiguous platform')

    def test_missing_required_and_published_optional_descendants_fail(self):
        self.index.remove(self.index[1]);self.save();self.rejected('absent')
        self.aura.find('requires/import[@addon="script.example"]').set('optional', 'true')
        self.rejected('absent')

    def test_absent_optional_edge_is_retained_as_unavailable(self):
        ET.SubElement(self.index[0].find('requires'), 'import', addon='script.optional', version='1.0.0', optional='true')
        self.save();report = self.both();self.assertEqual(report['unavailable_optional'][0]['addon'], 'script.optional')

    def test_cycles_including_optional_branches_fail(self):
        ET.SubElement(self.index[1].find('requires'), 'import', addon='script.example', version='1.0.0', optional='true')
        self.save();self.rejected('cycle')

    def test_core_abi_and_configured_version_cannot_be_invented(self):
        self.builtins['xbmc.gui'] = '99.0.0';self.rejected('built-in');self.builtins['xbmc.gui'] = '5.17.0'
        for floor in ['0.0.0', '6.0.0']:
            self.aura.find('requires/import').set('version', floor);self.rejected('version/ABI')

    def test_external_nodes_cannot_be_substituted_or_borrowed(self):
        override = ET.fromstring('<addon id="script.example" version="1.2.0"/>')
        self.rejected(selected=[self.aura, override])
        other = ET.fromstring('<addon id="script.other" version="1.0.0"><requires><import addon="script.example" version="1.0.0"/></requires></addon>')
        self.rejected('unrelated', selected=[self.aura, other])

    def test_version_order_matches_pinned_kodi_rules(self):
        ordered = ['1.0~beta1', '1.0', '1.0+matrix.1', '1.0+matrix.2', '1.0+matrix.10', '1.0.1', '1:1.0']
        for a, b in zip(ordered, ordered[1:]):
            for module in (producer, auditor):
                self.assertLess(module.compare_versions(a, b), 0, (a, b))
                self.assertTrue(module.version_ge(b, a))
        for a, b in [('1.01', '1.1'), ('1.0+MATRIX.1', '1.0+matrix.01'), ('1.0-01', '1.0-1')]:
            self.assertEqual(producer.compare_versions(a, b), 0)
            self.assertEqual(auditor.compare_versions(a, b), 0)
        for bad in ['', '1.0/../../x', '1.0 build', '١:1.0']:
            for module in (producer, auditor):
                with self.assertRaises(ValueError):module.compare_versions(bad, '1.0')


if __name__ == '__main__':
    unittest.main()
