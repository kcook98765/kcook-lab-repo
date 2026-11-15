"""Real Git source selection and unchanged secret/path controls; no publishing."""
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import check_publication as publication


class SourceScopeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        subprocess.run(['git', 'init', '-q', str(self.root)], check=True)
        self.bound = patch.object(publication, 'ROOT', self.root)
        self.bound.start()
        self.addCleanup(self.bound.stop)

    def put(self, name, data=b'reviewed template\n', tracked=False):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        if tracked:
            subprocess.run(['git', '-C', str(self.root), 'add', '--', name], check=True)

    def test_exact_seven_tracked_templates_are_admitted(self):
        self.assertEqual(len(publication.INTEGRATION_SOURCES), 7)
        for name in publication.INTEGRATION_SOURCES:
            self.put(name, tracked=True)
        result = publication.source_audit()
        self.assertEqual(set(result['files']), publication.INTEGRATION_SOURCES)

    def test_untracked_known_template_is_not_implicitly_approved(self):
        self.put(sorted(publication.INTEGRATION_SOURCES)[0])
        with self.assertRaisesRegex(ValueError, 'Unreviewed source root'):
            publication.source_audit()

    def test_unexpected_tracked_integration_file_stays_rejected(self):
        self.put('integrations/opencode/unreviewed.json', tracked=True)
        with self.assertRaisesRegex(ValueError, 'Unreviewed source root'):
            publication.source_audit()

    def test_other_source_roots_stay_rejected(self):
        self.put('unexpected/file.txt', tracked=True)
        with self.assertRaisesRegex(ValueError, 'Unreviewed source root'):
            publication.source_audit()

    def test_template_content_still_gets_real_path_and_secret_scan(self):
        name = sorted(publication.INTEGRATION_SOURCES)[0]
        for raw in [b'/' + b'home/private-owner/config',
                    b'/' + b'Users/private-owner/config', b'gh' + b'p_' + b'A' * 36]:
            with self.subTest(kind=raw[:5]):
                self.put(name, raw, tracked=True)
                with self.assertRaisesRegex(ValueError, 'Private workstation path|Credential pattern'):
                    publication.source_audit()

    def test_documentation_example_passes_without_scanner_exception(self):
        guide = Path(publication.__file__).resolve().parents[1] / 'docs/OPENCODE-CROSS-REPOSITORY.md'
        self.put('docs/OPENCODE-CROSS-REPOSITORY.md', guide.read_bytes(), tracked=True)
        self.assertEqual(publication.source_audit()['file_count'], 1)

    def test_empty_git_selection_is_still_rejected(self):
        with self.assertRaisesRegex(ValueError, 'No source files selected'):
            publication.source_audit()


if __name__ == '__main__':
    unittest.main()
