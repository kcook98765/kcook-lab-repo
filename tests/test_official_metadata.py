"""Retained public metadata integrity, not private package approval or native tests."""
from datetime import datetime, timedelta, timezone
import gzip
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
PUBLIC = ROOT / 'docs/official-dependencies'
sys.path.insert(0, str(ROOT / 'scripts'))
import official_nexus
import audit_official_nexus
import official_omega
import audit_official_omega
import official_matrix
import audit_official_matrix


def sha(raw): return hashlib.sha256(raw).hexdigest()
def load(name): return json.loads((PUBLIC / name).read_text())


class OfficialMetadata(unittest.TestCase):
    def test_matrix_acquisition_sidecars_and_actual_seven_day_window(self):
        entry = load('matrix-acquisition-2026-11-22.json')['matrix']
        raw = (PUBLIC / entry['file']).read_bytes()
        self.assertEqual(sha(raw), entry['sha256'])
        self.assertEqual(len(raw), entry['bytes'])
        self.assertEqual(sha(gzip.decompress(raw)), entry['xml_sha256'])
        self.assertEqual(len(gzip.decompress(raw)), entry['xml_bytes'])
        self.assertEqual(entry['source_url'], official_matrix.SOURCE_URL)
        for suffix in ('sha256', 'md5'):
            proof = entry[suffix + '_sidecar']
            sidecar = (PUBLIC / proof['file']).read_bytes()
            self.assertEqual(sha(sidecar), proof['sha256'])
            self.assertEqual(sidecar.decode().split()[0], hashlib.new(suffix, raw).hexdigest())
            self.assertTrue(proof['matched'])
        spec = load('tvguide-matrix-enrollment.json')['official_matrix']
        self.assertEqual(spec['snapshot_sha256'], entry['xml_sha256'])
        for key in ('retrieved_at', 'expires_at'): self.assertEqual(spec[key], entry[key])
        self.assertEqual(official_omega._stamp(spec['expires_at']) - official_omega._stamp(spec['retrieved_at']), timedelta(days=7))

    def test_separate_matrix_and_omega_tvguide_core_primary_sources(self):
        for filename, producer, auditor, tag in (
            ('matrix-core-provenance.json', official_matrix, audit_official_matrix, '19.4-Matrix'),
            ('omega-tvguide-core-provenance.json', official_omega, audit_official_omega, '21.3-Omega')):
            proof = load(filename)
            self.assertEqual(proof['commit'], producer.CORE_COMMIT)
            self.assertEqual(proof['commit'], auditor.REVISION)
            self.assertEqual(proof['tag'], tag)
            for relative, entry in proof['files'].items():
                self.assertIn('/' + proof['commit'] + '/', entry['source_url'])
                if 'file' not in entry:
                    self.assertTrue(relative.endswith('.cpp')); continue
                raw = (PUBLIC / entry['file']).read_bytes()
                self.assertEqual(sha(raw), entry['sha256'])
                self.assertEqual(len(raw), entry['bytes'])
                if relative.endswith('addon.xml'):
                    manifest = ET.fromstring(raw)
                    abi = manifest.find('backwards-compatibility')
                    actual = (manifest.get('version'), abi.get('abi') if abi is not None else None)
                    self.assertEqual(actual, producer.CORE[manifest.get('id')])
                    self.assertEqual(actual, auditor.PROVIDED[manifest.get('id')])

    def test_exact_downloaded_bytes_xml_and_both_sidecars(self):
        for lane, entry in load('acquisition-2026-11-22.json').items():
            with self.subTest(lane=lane):
                raw = (PUBLIC / entry['file']).read_bytes()
                self.assertEqual(sha(raw), entry['sha256'])
                self.assertEqual(len(raw), entry['bytes'])
                xml = gzip.decompress(raw)
                self.assertEqual(sha(xml), entry['xml_sha256'])
                self.assertEqual(len(xml), entry['xml_bytes'])
                self.assertEqual(entry['source_url'], f'https://mirrors.kodi.tv/addons/{lane}/addons.xml.gz')
                for suffix in ('sha256', 'md5'):
                    record = entry[suffix + '_sidecar']
                    sidecar = (PUBLIC / record['file']).read_bytes()
                    self.assertTrue(record['matched'])
                    self.assertEqual(record['http_status'], 200)
                    self.assertEqual(sha(sidecar), record['sha256'])
                    self.assertEqual(sidecar.decode().split()[0].lower(), hashlib.new(suffix, raw).hexdigest())

    def test_previous_snapshot_bytes_record_and_validity_are_retained(self):
        old = load('omega-previous-spec.json')
        retention = load('omega-previous-retention.json')
        raw = (PUBLIC / 'omega-previous-6296b9329811.xml.gz').read_bytes()
        self.assertEqual(sha(raw), retention['retained_gzip_sha256'])
        self.assertEqual(sha(gzip.decompress(raw)), old['snapshot_sha256'])
        self.assertEqual(old['retrieved_at'], '2026-11-15T01:46:57Z')
        self.assertEqual(old['expires_at'], '2026-11-22T01:46:57Z')
        current = json.loads((ROOT / 'config/production.json').read_text())['external_dependencies']['official_omega']
        unchanged = set(old) - {'snapshot', 'snapshot_sha256', 'retrieved_at', 'expires_at', 'roots', 'allowlist'}
        self.assertEqual({k: old[k] for k in unchanged}, {k: current[k] for k in unchanged})
        self.assertEqual(current['roots'], old['roots'] | {official_nexus.ROOT_ID: official_nexus.ROOT_BINDING})
        self.assertEqual(current['allowlist'], old['allowlist'] | {'script.module.pytz': '2023.3.0+matrix.1'})
        self.assertNotEqual(old['snapshot'], current['snapshot'])

    def test_actual_core_source_manifests_and_abi_proof(self):
        provenance = load('nexus-core-provenance.json')
        self.assertEqual(provenance['commit'], '4b95737efaddf7c869736e539318f18433413ff1')
        expected = {'xbmc.core': ('0.1.0', '0.1'), 'xbmc.python': ('3.0.1', '3.0.0'), 'script.module.pil': ('5.1.0', None)}
        for relative, record in provenance['files'].items():
            if relative.endswith('.cpp'):
                self.assertNotIn('file', record)
                self.assertEqual(record['sha256'], '4ffef76297df93e4f7b4e6e6b7dc64e22a62aa122af1fc868904530db66cd91b')
                self.assertIn('/' + provenance['commit'] + '/', record['source_url'])
                continue
            raw = (PUBLIC / record['file']).read_bytes()
            self.assertEqual(sha(raw), record['sha256'])
            if relative.endswith('addon.xml'):
                manifest = ET.fromstring(raw)
                abi = manifest.find('backwards-compatibility')
                self.assertEqual((manifest.get('version'), abi.get('abi') if abi is not None else None), expected[manifest.get('id')])
        self.assertEqual(official_nexus.CORE, expected)
        self.assertEqual(audit_official_nexus.PROVIDED, expected)

    def test_retained_omega_reconstructs_all_32_approved_providers_and_81_edges(self):
        spec = json.loads((ROOT / 'config/production.json').read_text())['external_dependencies']['official_omega']
        report = load('omega-refreshed-closure.json')
        # Preserve the historical Aura-only reconstruction after the separately
        # reviewed exact TV Guide root is added to the current production proposal.
        self.assertEqual({aid: spec['allowlist'][aid] for aid in report['external_versions']}, report['external_versions'])
        spec['roots'] = {'skin.aura': spec['roots']['skin.aura']}
        spec['allowlist'] = report['external_versions']
        root = ET.Element('addon', id='skin.aura', version='2.1.0')
        group = ET.SubElement(root, 'requires')
        for edge in report['edges']:
            if edge['parent'] == 'skin.aura':
                ET.SubElement(group, 'import', addon=edge['addon'], version=edge['minimum'], optional=str(edge['optional']).lower())
        ET.SubElement(root, 'extension', point='xbmc.gui.skin')
        binding = {'skin.aura': {k: spec['roots']['skin.aura'][k] for k in ('source_commit', 'package_sha256')} |
                   {'source_repository': 'https://github.com/kcook98765/skin.aura'}}
        # Deterministic reconstruction at acquisition time is historical evidence,
        # never a substitute for the fresh current-time operator checks.
        now = datetime.strptime(spec['retrieved_at'], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc) + timedelta(seconds=1)
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            target = base / spec['snapshot']; target.parent.mkdir(parents=True)
            target.write_bytes(gzip.decompress((PUBLIC / 'omega-800fc70454c9.xml.gz').read_bytes()))
            for module in (official_omega, audit_official_omega):
                actual = module.resolve([root], {'xbmc.python': '3.0.1', 'xbmc.gui': '5.17.0'},
                    {'official_omega': spec}, base, 'omega', binding, now=now)
                self.assertEqual(actual, report)
        self.assertEqual(len(report['external_versions']), 32)
        self.assertEqual(len(report['edges']), 81)
        self.assertEqual(load('omega-closure-comparison.json')['differences'], {})

    def test_frozen_nexus_and_matrix_specs_and_successor_intake(self):
        nexus = load('tvguide-nexus-enrollment.json')['official_nexus']
        addon = official_nexus.ROOT_ID
        self.assertEqual(nexus['roots'], {addon: official_nexus.ROOT_BINDING})
        self.assertEqual(nexus['roots'], {audit_official_nexus.ADDON: audit_official_nexus.ENROLLED})
        self.assertEqual(len(nexus['allowlist']), 10)
        self.assertNotIn('script.module.pil', nexus['allowlist'])
        self.assertNotIn('xbmc.python', nexus['allowlist'])

        production = json.loads((ROOT / 'config/production.json').read_text())
        providers = production['external_dependencies']
        self.assertEqual(set(providers), {'official_matrix', 'official_omega', 'official_nexus'})
        pin = official_nexus.TVGUIDE_012
        self.assertEqual(providers['official_nexus'], {**nexus, 'roots': {addon: pin}})
        self.assertEqual(providers['official_matrix'], load('tvguide-matrix-enrollment.json')['official_matrix'])
        self.assertEqual(providers['official_omega']['roots'][addon], pin)
        self.assertEqual(providers['official_omega']['roots']['skin.aura']['version'], '2.1.1')
        tv = {p['zip']: p for p in production['packages'] if 'tvguide' in p['zip']}
        self.assertEqual(set(tv), {addon + '-0.1.1.zip', addon + '-0.1.2.zip'})
        self.assertEqual(tv[addon + '-0.1.1.zip']['lanes'], ['matrix'])
        self.assertEqual(tv[addon + '-0.1.1.zip']['sha256'], official_nexus.ROOT_BINDING['package_sha256'])
        self.assertEqual(tv[addon + '-0.1.2.zip']['lanes'], ['nexus', 'omega'])
        self.assertEqual(tv[addon + '-0.1.2.zip']['sha256'], pin['package_sha256'])


if __name__ == '__main__': unittest.main()
