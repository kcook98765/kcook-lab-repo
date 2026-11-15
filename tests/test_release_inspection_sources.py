"""Real Git source scope for the restored read-only inspector, without its CLI."""
import ast
from pathlib import Path, PurePosixPath
import subprocess
import tempfile
import unittest

import check_publication


TEMPLATE = Path(__file__).resolve().parents[1] / 'scripts/opencode/release-inspect.template.py'


class InspectionSourceTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        subprocess.run(['git', 'init', '-q', str(self.root)], check=True)
        tree = ast.parse(TEMPLATE.read_text())
        constants = {'SOURCE_ROOTS', 'INTEGRATION_SOURCES'}
        functions = {'require', 'path', 'tracked_integrations', 'source_allowed'}
        nodes = [n for n in tree.body if
                 isinstance(n, ast.FunctionDef) and n.name in functions or
                 isinstance(n, ast.Assign) and any(
                     isinstance(t, ast.Name) and t.id in constants for t in n.targets)]
        self.namespace = {'ROOT': self.root, 'PurePosixPath': PurePosixPath,
                          'subprocess': subprocess}
        exec(compile(ast.Module(body=nodes, type_ignores=[]), str(TEMPLATE), 'exec'), self.namespace)

    def put(self, name, tracked):
        file = self.root / name
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text('reviewed template\n')
        if tracked:
            subprocess.run(['git', '-C', str(self.root), 'add', '--', name], check=True)

    def test_exact_seven_tracked_paths_match_publication_scope(self):
        paths = self.namespace['INTEGRATION_SOURCES']
        self.assertEqual(paths, check_publication.INTEGRATION_SOURCES)
        self.assertEqual(len(paths), 7)
        for name in paths:
            self.put(name, True)
        tracked = self.namespace['tracked_integrations']()
        self.assertEqual(tracked, paths)
        self.assertTrue(all(self.namespace['source_allowed'](n, tracked) for n in paths))

    def test_known_but_untracked_template_stays_denied(self):
        name = sorted(self.namespace['INTEGRATION_SOURCES'])[0]
        self.put(name, False)
        tracked = self.namespace['tracked_integrations']()
        self.assertNotIn(name, tracked)
        self.assertFalse(self.namespace['source_allowed'](name, tracked))

    def test_unexpected_tracked_integration_stays_denied(self):
        name = 'integrations/opencode/unreviewed.json'
        self.put(name, True)
        self.assertFalse(self.namespace['source_allowed'](name, self.namespace['tracked_integrations']()))

    def test_existing_roots_and_private_unknown_roots(self):
        self.assertTrue(self.namespace['source_allowed']('docs/APPROVAL-CONTRACT.md', set()))
        for name in ['.opencode/auth.json', 'unknown/file', '',
                     'integrations/../docs/other.md']:
            with self.subTest(name=name):
                self.assertFalse(self.namespace['source_allowed'](name, set()))

    def test_path_containment_and_symlink_guards_still_apply(self):
        for name in ['../escape', '/absolute', 'docs/../other']:
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.namespace['path'](self.root, name)
        (self.root / 'link').symlink_to(self.root.parent, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.namespace['path'](self.root, 'link/file')


if __name__ == '__main__':
    unittest.main()
