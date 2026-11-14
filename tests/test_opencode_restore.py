"""Focused restoration and permission-boundary checks; no services or network."""
import importlib.util
import json
from pathlib import Path
import stat
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('stage_operator', ROOT / 'scripts/opencode/stage_operator.py')
restore = importlib.util.module_from_spec(spec)
spec.loader.exec_module(restore)


class RestoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.home = self.root / 'owner'
        self.dev = self.home / 'development'
        self.source = self.dev / 'source'
        self.dist = self.dev / 'distribution'
        self.toolkit = self.dev / 'toolkit'
        self.bindings = restore.bindings_for(self.home, self.dev, self.source, self.dist, self.toolkit)

    def load(self, stage, name):
        return json.loads((stage / f'{name}-profile.json').read_text())

    def test_existing_foundation_and_private_values_are_preserved(self):
        restricted = {'permission': {'*': 'deny', 'bash': 'deny', 'edit': 'deny'}}
        base = {'agent': {'kodi-release-reviewer': restricted}, 'model': 'unchanged/model',
                'default_agent': 'kodi-develop', 'mcp': {'private': {'enabled': False}},
                'provider': {'existing': {'options': {'apiKey': 'synthetic-canary-not-a-secret'}}},
                'skills': {'paths': ['/existing/skill']}, 'instructions': ['AGENTS.md']}
        before = json.loads(json.dumps(base))
        output = self.root / 'stage'
        restore.stage(output, self.bindings, {'global': base})
        merged = self.load(output, 'global')
        for key in ('model', 'default_agent', 'mcp', 'provider', 'instructions'):
            self.assertEqual(merged[key], before[key])
        self.assertEqual(merged['agent']['kodi-release-reviewer'], restricted)
        self.assertEqual(base, before)
        self.assertIn('/existing/skill', merged['skills']['paths'])
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
        self.assertTrue(all(stat.S_IMODE(p.stat().st_mode) == 0o600
                            for p in output.rglob('*') if p.is_file()))

    def test_fresh_relocated_installation_has_exact_enrollment_and_single_skill(self):
        output = self.root / 'fresh'
        restore.stage(output, self.bindings, {})
        global_profile = self.load(output, 'global')
        operator = global_profile['agent']['github-operator']
        self.assertEqual(operator['permission']['external_directory']['*'], 'deny')
        self.assertEqual(operator['permission']['bash']['*'], 'ask')
        self.assertEqual(operator['permission']['task'], 'deny')
        self.assertEqual(operator['permission']['kodi_*'], 'deny')
        self.assertEqual(operator['permission']['read'][str(self.home / '.config/**')], 'deny')
        command = global_profile['command']['kodi-release-prepare']
        self.assertEqual(command['agent'], 'github-operator')
        self.assertFalse(command['subtask'])
        source_rules = self.load(output, 'source')['agent']['github-operator']['permission']
        self.assertEqual(source_rules['external_directory'],
                         {str(self.dist): 'allow', str(self.dist) + '/**': 'allow'})
        reverse = self.load(output, 'distribution')['agent']['github-operator']['permission']
        self.assertEqual(reverse['edit'], {str(self.source): 'deny', str(self.source) + '/**': 'deny'})
        skills = list(output.rglob('SKILL.md'))
        self.assertEqual(len(skills), 1)
        self.assertTrue((skills[0].parent / 'references/intake-and-release.md').is_file())
        for p in output.rglob('*'):
            if p.is_file():
                self.assertNotIn('${USER_HOME}', p.read_text())
                self.assertNotIn('${DISTRIBUTION_ROOT}', p.read_text())
        self.assertIn('kcook98765/kcook-lab-repo', operator['prompt'])

    def test_round_trip_is_idempotent_and_retains_base_file_bytes(self):
        first = self.root / 'first'
        restore.stage(first, self.bindings, {})
        profiles = {name: self.load(first, name) for name in ('global', 'source', 'distribution')}
        second = self.root / 'second'
        restore.stage(second, self.bindings, profiles)
        for p in first.rglob('*'):
            if p.is_file():
                self.assertEqual(p.read_bytes(), (second / p.relative_to(first)).read_bytes())
        with self.assertRaises(FileExistsError):
            restore.stage(second, self.bindings, {})

    def test_broad_overlapping_and_wildcard_roots_fail_closed(self):
        for source in (self.home, self.dev, self.dist, self.dist / 'nested', self.dev / '*'):
            with self.subTest(source=source), self.assertRaises(ValueError):
                restore.bindings_for(self.home, self.dev, source, self.dist, self.toolkit)

    def test_symlinked_root_and_output_are_rejected(self):
        self.dev.mkdir(parents=True)
        self.dist.mkdir()
        linked = self.dev / 'linked'
        linked.symlink_to(self.dist, target_is_directory=True)
        with self.assertRaises(ValueError):
            restore.bindings_for(self.home, self.dev, linked, self.dist, self.toolkit)
        with self.assertRaises(ValueError):
            restore.stage(linked / 'new', self.bindings, {})

    def test_home_ancestor_is_rejected_even_with_disjoint_other_checkouts(self):
        distribution = self.root.parent / ('dist-' + self.root.name)
        toolkit = self.root.parent / ('toolkit-' + self.root.name)
        with self.assertRaisesRegex(ValueError, 'cannot contain'):
            restore.bindings_for(self.home, self.dev, self.root, distribution, toolkit)


if __name__ == '__main__':
    unittest.main()
