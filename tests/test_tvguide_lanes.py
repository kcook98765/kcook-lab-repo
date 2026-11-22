"""Focused closed-enrollment controls; no runtime or package approval assertions."""
import copy
from datetime import datetime, timedelta, timezone
import gzip
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
PUBLIC = ROOT / 'docs/official-dependencies'
sys.path.insert(0, str(ROOT / 'scripts'))
import official_matrix
import audit_official_matrix
import official_nexus
import audit_official_nexus
import official_omega
import audit_official_omega
import repository
import audit_candidate

TV = 'script.tvguide.fullscreen'
PAIRS = {'matrix': (official_matrix, audit_official_matrix),
         'nexus': (official_nexus, audit_official_nexus),
         'omega': (official_omega, audit_official_omega)}


def load(name): return json.loads((PUBLIC / name).read_text())
def digest(raw): return hashlib.sha256(raw).hexdigest()


class TVGuideLanes(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='tvguide-lanes-')
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name)
        (self.base / 'incoming/official').mkdir(parents=True)
        (self.base / 'config').mkdir()
        self.specs = {}
        for lane, filename in [('matrix', 'matrix-8473a49bffc6.xml.gz'),
                               ('nexus', 'nexus-32dc7aae6108.xml.gz'), ('omega', 'omega-800fc70454c9.xml.gz')]:
            spec = load('tvguide-' + lane + '-enrollment.json')['official_' + lane]
            self.specs['official_' + lane] = spec
            raw = gzip.decompress((PUBLIC / filename).read_bytes())
            self.assertEqual(digest(raw), spec['snapshot_sha256'])
            (self.base / 'incoming' / spec['snapshot']).write_bytes(raw)
        self.now = datetime(2026, 11, 22, 10, tzinfo=timezone.utc)
        self.consumer_now = datetime.now(timezone.utc)
        self.roots = {}
        # Reconstruct manifests from retained root edges. Separate operator
        # evidence additionally inspects the original exact-checksum real ZIPs.
        for aid, report in [(TV, load('tvguide-matrix-closure.json')),
                            ('skin.aura', load('omega-refreshed-closure.json'))]:
            node = ET.Element('addon', id=aid, version='0.1.1' if aid == TV else '2.1.0')
            group = ET.SubElement(node, 'requires')
            for edge in report['edges']:
                if edge['parent'] == aid:
                    ET.SubElement(group, 'import', addon=edge['addon'], version=edge['minimum'], optional=str(edge['optional']).lower())
            if aid == TV:
                ET.SubElement(node, 'extension', point='xbmc.python.script', library='addon.py')
                ET.SubElement(node, 'extension', point='xbmc.service', library='service.py')
            else: ET.SubElement(node, 'extension', point='xbmc.gui.skin')
            self.roots[aid] = node
        self.bindings = {aid: {k: pin[k] for k in ('source_commit', 'package_sha256')} |
                         {'source_repository': 'https://github.com/kcook98765/' + aid}
                         for aid, pin in self.specs['official_omega']['roots'].items()}
        self.config = json.loads((ROOT / 'config/repository.json').read_text())

    def manifests(self, lane): return [self.roots[TV], self.roots['skin.aura']] if lane == 'omega' else [self.roots[TV]]

    def direct(self, module, lane, manifests=None):
        return module.resolve(self.manifests(lane) if manifests is None else manifests,
            self.config['lanes'][lane]['builtins'], {'official_' + lane: self.specs['official_' + lane]},
            self.base / 'incoming', lane, self.bindings, now=self.now)

    def reject(self, lane, pattern='.', manifests=None):
        for module in PAIRS[lane]:
            with self.subTest(module=module.__name__), self.assertRaisesRegex(ValueError, pattern):
                self.direct(module, lane, manifests)

    def consumer(self, module, lane, specs=None, manifests=None):
        # Consumer dispatch uses actual current time; make synthetic validity
        # current without altering retained evidence or claiming reacquisition.
        specs = copy.deepcopy(self.specs if specs is None else specs)
        current = self.consumer_now
        for spec in specs.values():
            spec['retrieved_at'] = (current - timedelta(minutes=1)).strftime('%Y-%m-%dT%H:%M:%SZ')
            spec['expires_at'] = (current + timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%SZ')
        (self.base / 'config/candidate.json').write_text(json.dumps({'external_dependencies': specs}))
        with patch.object(module, 'ROOT', self.base):
            return module.external_dependency_report('candidate', self.manifests(lane) if manifests is None else manifests,
                self.config['lanes'][lane]['builtins'], lane, self.bindings)

    def test_retained_real_catalogs_both_reconstructions(self):
        for lane in ('matrix', 'omega'):
            actual = [self.direct(module, lane) for module in PAIRS[lane]]
            self.assertEqual(*actual)
            self.assertEqual(actual[0], load('tvguide-' + lane + '-closure.json'))
            self.assertEqual(actual[0]['core_versions']['xbmc.python'], '3.0.0' if lane == 'matrix' else '3.0.1')
            self.assertEqual(actual[0]['core_versions']['script.module.pil'], '5.1.0')
            for consumer in (repository.dependencies, audit_candidate.check_dependencies):
                consumer(self.manifests(lane), self.config['lanes'][lane]['builtins'] | actual[0]['core_versions'], actual[0]['external_versions'])

    def test_omega_root_isolation_and_unchanged_aura(self):
        report = self.direct(official_omega, 'omega')
        old = load('omega-refreshed-closure.json')
        for key, value in report['root_closures']['skin.aura'].items(): self.assertEqual(value, old[key])
        tv = report['root_closures'][TV]
        self.assertEqual(len(tv['external_versions']), 10)
        self.assertEqual(len(tv['edges']), 24)
        self.assertNotIn('xbmc.gui', tv['core_versions'])
        self.assertNotIn('script.module.pytz', report['root_closures']['skin.aura']['external_versions'])
        spec = self.specs['official_omega']
        del spec['roots']['skin.aura']
        spec['allowlist'] = tv['external_versions']
        for module in PAIRS['omega']:
            self.assertEqual(self.direct(module, 'omega', [self.roots[TV]])['root_closures'][TV], tv)

    def test_all_six_floors_extensions_version_and_optionality_are_frozen(self):
        root = self.roots[TV]
        for lane in ('matrix', 'omega'):
            for dep in root.findall('requires/import'):
                for key, value in [('version', '0.0.0'), ('version', '99.0.0'), ('optional', 'true')]:
                    old = dep.get(key); dep.set(key, value)
                    self.reject(lane, 'manifest mismatch'); dep.set(key, old)
            root.set('version', '0.1.0'); self.reject(lane, 'manifest mismatch'); root.set('version', '0.1.1')
            root.find('extension').set('library', 'wrong.py'); self.reject(lane, 'manifest mismatch')
            root.find('extension').set('library', 'addon.py')

    def test_foreign_roots_and_artifact_source_rebinding_reject(self):
        for lane in ('matrix', 'omega'):
            spec = self.specs['official_' + lane]
            for key, value in [('version', '0.1.0'), ('source_commit', 'a' * 40), ('package_sha256', 'b' * 64)]:
                old = spec['roots'][TV][key]; spec['roots'][TV][key] = value
                self.reject(lane, 'exact frozen'); spec['roots'][TV][key] = old
            spec['roots']['script.foreign'] = copy.deepcopy(spec['roots'][TV]); self.reject(lane, 'only')
            del spec['roots']['script.foreign']
            for key in ('source_commit', 'source_repository', 'package_sha256'):
                old = self.bindings[TV][key]; self.bindings[TV][key] = 'wrong'
                self.reject(lane, 'binding mismatch'); self.bindings[TV][key] = old

    def test_dispatch_requires_independently_configured_matching_current_lane(self):
        for lane in ('matrix', 'nexus', 'omega'):
            for module in (repository, audit_candidate):
                combined = self.consumer(module, lane)
                single = self.consumer(module, lane, {'official_' + lane: self.specs['official_' + lane]})
                self.assertEqual(combined, single)
                missing = {k: v for k, v in self.specs.items() if k != 'official_' + lane}
                with self.assertRaisesRegex(ValueError, 'only'):
                    self.consumer(module, lane, missing)
                bad = copy.deepcopy(self.specs); bad['official_' + lane]['roots'][TV]['package_sha256'] = 'b' * 64
                with self.assertRaisesRegex(ValueError, 'exact frozen'):
                    self.consumer(module, lane, bad)
                # A foreign Aura-only Omega enrollment cannot authorize TV Guide.
                if lane == 'omega':
                    bad = copy.deepcopy(self.specs); del bad['official_omega']['roots'][TV]
                    with self.assertRaisesRegex(ValueError, 'own exact Omega'):
                        self.consumer(module, lane, bad)

    def test_no_direct_wrong_lane_or_piers_admission(self):
        for lane, modules in PAIRS.items():
            for module in modules:
                for wrong in set(self.config['lanes']) - {lane}:
                    with self.assertRaisesRegex(ValueError, 'only'):
                        module.resolve([self.roots[TV]], {}, {'official_' + lane: self.specs['official_' + lane]},
                                       self.base / 'incoming', wrong, self.bindings, now=self.now)
        for module in (repository, audit_candidate):
            with self.assertRaisesRegex(ValueError, 'only'): self.consumer(module, 'piers')

    def test_unrelated_external_or_core_borrowing_and_substitution(self):
        for lane in ('matrix', 'omega'):
            for dependency in ('script.module.pytz', 'script.module.pil'):
                foreign = ET.fromstring(f'<addon id="script.foreign" version="1.0.0"><requires><import addon="{dependency}" version="1.0.0"/></requires></addon>')
                self.reject(lane, 'unrelated', self.manifests(lane) + [foreign])
            substitute = ET.fromstring('<addon id="script.module.requests" version="2.31.0"/>')
            self.reject(lane, 'substitut|replaced', self.manifests(lane) + [substitute])

    def test_matrix_catalog_tamper_expiry_wrong_core_abi_and_allowlist(self):
        spec = self.specs['official_matrix']
        for key, value in [('core_commit', official_nexus.CORE_COMMIT), ('source_url', official_omega.SOURCE_URL),
                           ('snapshot_sha256', 'f' * 64), ('expires_at', '2026-11-22T10:00:00Z'),
                           ('retrieved_at', '2026-11-23T10:00:00Z'), ('expires_at', '2026-11-30T10:00:00Z')]:
            old = spec[key]; spec[key] = value; self.reject('matrix'); spec[key] = old
        spec['allowlist']['script.unused'] = '1.0.0'; self.reject('matrix', 'unused'); del spec['allowlist']['script.unused']
        self.config['lanes']['matrix']['builtins']['xbmc.python'] = '3.0.1'; self.reject('matrix', 'built-in')

    def test_all_configured_inactive_adapters_still_verify_snapshot(self):
        for lane in ('matrix', 'nexus', 'omega'):
            for inactive in set(PAIRS) - {lane}:
                bad = copy.deepcopy(self.specs); bad['official_' + inactive]['snapshot_sha256'] = 'f' * 64
                for module in (repository, audit_candidate):
                    with self.assertRaisesRegex(ValueError, 'checksum'): self.consumer(module, lane, bad)

    def test_matrix_toolchain_pins_both_implementations_and_primitives(self):
        (self.base / 'config/candidate.json').write_text(json.dumps({'external_dependencies': self.specs}))
        with patch.object(repository, 'ROOT', self.base): pins = repository.dependency_toolchain('candidate')
        self.assertEqual(len(pins), 6)
        for lane in PAIRS:
            for prefix in ('official_', 'audit_official_'):
                name = prefix + lane
                self.assertEqual(pins[name + '_sha256'], digest((ROOT / 'scripts' / (name + '.py')).read_bytes()))


if __name__ == '__main__': unittest.main()
