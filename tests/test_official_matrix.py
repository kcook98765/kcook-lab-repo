"""Matrix-specific use of the existing adversarial single-root fixture controls."""
import test_official_nexus as nexus
import official_matrix as producer
import audit_official_matrix as auditor
import unittest


class OfficialMatrix(unittest.TestCase):
    save = nexus.OfficialNexus.save

    def setUp(self):
        nexus.OfficialNexus.setUp(self)
        self.spec.update(source_url=producer.SOURCE_URL, core_commit=producer.CORE_COMMIT)
        self.builtins = {'xbmc.addon': '19.0.0', 'xbmc.python': '3.0.0'}

    def resolve(self, module, manifests=None, lane='matrix'):
        return module.resolve([self.root] if manifests is None else manifests, self.builtins,
                              {'official_matrix': self.spec}, self.base, lane, self.binding, now=self.now)

    def both(self, **kwargs):
        reports = [self.resolve(m, **kwargs) for m in (producer, auditor)]
        self.assertEqual(*reports)
        return reports[0]

    def rejected(self, pattern='.', **kwargs):
        for module in (producer, auditor):
            with self.subTest(module=module.__name__), self.assertRaisesRegex(ValueError, pattern):
                self.resolve(module, **kwargs)

    test_cycle_duplicate_import_and_core_abi = nexus.OfficialNexus.test_dependency_cycle_duplicate_import_and_builtin_abi
    test_enrolled_manifest_cannot_be_generalized = nexus.OfficialNexus.test_enrolled_manifest_is_not_a_general_script_adapter
    test_expired_future_overlong_and_invalid_dates = nexus.OfficialNexus.test_snapshot_window_expired_future_and_too_old
    test_paths_symlink_entities_encoding_size_and_checksum = nexus.OfficialNexus.test_tamper_unsafe_path_link_entities_and_size
    test_unused_missing_old_and_builtin_allowlist = nexus.OfficialNexus.test_unnecessary_missing_old_and_builtin_allowlist
    test_newest_broken_ambiguous_old_provider = nexus.OfficialNexus.test_newest_broken_ambiguous_and_too_old_providers
    test_optional_descendants_and_missing_optional_diagnostic = nexus.OfficialNexus.test_available_optional_descendants_required_missing_optional_diagnostic
    test_substitution_unrelated_and_builtin_conflict = nexus.OfficialNexus.test_no_substitution_or_unrelated_borrowing
    test_former_010_cannot_borrow_enrollment = nexus.OfficialNexus.test_former_010_cannot_borrow_successor_enrollment


if __name__ == '__main__': unittest.main()
