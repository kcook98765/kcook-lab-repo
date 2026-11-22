"""Dependency grammar/order regressions; no add-on code or production build."""
import io
from pathlib import Path
import sys
import unittest
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import repository as builder
import audit_candidate as auditor


def files(floor='2023.3.0+matrix.1', package='1.0.0', optional=False):
    root = ET.fromstring('''<addon id="script.example" version="1.0.0" name="Example" provider-name="Test">
      <requires><import addon="script.module.pytz"/></requires>
      <extension point="xbmc.python.script" library="default.py"/>
      <extension point="xbmc.addon.metadata"><summary>Test</summary><description>Test</description>
      <platform>all</platform><license>MIT</license></extension></addon>''')
    root.set('version', package)
    dep = root.find('requires/import')
    if floor is not None:
        dep.set('version', floor)
    if optional:
        dep.set('optional', 'true')
    return {'addon.xml': ET.tostring(root), 'LICENSE.txt': b'Test fixture', 'default.py': b'# inert'}


def archive(payload):
    """Independent test packer: permits invalid manifests to reach both readers."""
    out = io.BytesIO()
    with zipfile.ZipFile(out, 'w') as z:
        for name, raw in sorted(payload.items()):
            item = zipfile.ZipInfo('script.example/' + name, (1980, 1, 1, 0, 0, 0))
            item.create_system = 3
            item.external_attr = 0o100644 << 16
            z.writestr(item, raw)
    return out.getvalue()


class DependencyVersions(unittest.TestCase):
    def test_strict_non_string_inputs_and_numeric_bounds(self):
        for value in (None, True, False, 1, 1.0, [], {}, b'1.0.0', '2147483648.0', '9' * 129):
            for parser in (builder.dependency_version, auditor.dependency_version):
                with self.subTest(value=value, parser=parser.__module__):
                    with self.assertRaises((ValueError, AssertionError)):
                        parser(value)

    def test_archive_accepts_supported_dependency_versions_in_both_consumers(self):
        for floor in ('2023.3.0+matrix.1', '1.0', '1.0.0~beta2', '1.0.0~beta3+git010cab3',
                      '1.0.0-2', '2:1.0.0-10', '1.0.0rc1'):
            for reader in (builder.inspect_zip, auditor.archive_files):
                with self.subTest(floor=floor, reader=reader.__name__):
                    manifest, _ = reader(archive(files(floor)))
                    self.assertEqual(manifest.find('requires/import').get('version'), floor)

    def test_archive_rejects_bad_dependency_versions_even_optional(self):
        for floor in (None, '', 'abc', '.', '+', '~', '1..0', '1.0.', '1.0+', '1.0~~rc1',
                      '1.0--2', ':1.0', 'x:1.0', '1:2:3', '1.0/2', '../1.0', '1\\2',
                      ' 1.0', '1.0 ', '1.0\n', '1.0\t', '1.0%20', '1.0;evil',
                      '1' * 129, '1.' + '9' * 20):
            for optional in (False, True):
                for reader in (builder.inspect_zip, auditor.archive_files):
                    with self.subTest(floor=floor, optional=optional, reader=reader.__name__):
                        with self.assertRaises((ValueError, AssertionError)):
                            reader(archive(files(floor, optional=optional)))

    def test_package_identity_remains_numeric(self):
        for package in ('1.0.0+matrix.1', '1.0.0~beta1', '1.0.0-2', '1:1.0.0', '1.0'):
            for reader in (builder.inspect_zip, auditor.archive_files):
                with self.subTest(package=package, reader=reader.__name__):
                    with self.assertRaises((ValueError, AssertionError)):
                        reader(archive(files(package=package)))

    def test_minimum_ordering_in_both_consumers(self):
        for low, high in (('2.0.0', '10.0.0'), ('1.0.0+matrix.2', '1.0.0+matrix.10'),
                          ('1.0.0~beta2', '1.0.0~beta10'), ('1.0.0~rc1', '1.0.0'),
                          ('1.0.0-2', '1.0.0-10'), ('99.0.0', '1:1.0.0'),
                          ('1.0.0', '1.0.0+matrix.1')):
            for check in (builder.dependencies, auditor.check_dependencies):
                for external in (False, True):
                    def run(floor, provider):
                        manifest = ET.fromstring(files(floor)['addon.xml'])
                        return check([manifest], {} if external else {'script.module.pytz': provider},
                                     {'script.module.pytz': provider} if external else {})
                    with self.subTest(low=low, high=high, check=check.__name__, external=external):
                        run(low, high)
                        run(high, high)
                        with self.assertRaises((ValueError, AssertionError)):
                            run(high, low)

    def test_numeric_builtin_does_not_satisfy_suffixed_floor(self):
        manifest = ET.fromstring(files('3.0.0+matrix.1')['addon.xml'])
        for check in (builder.dependencies, auditor.check_dependencies):
            with self.assertRaises((ValueError, AssertionError)):
                check([manifest], {'script.module.pytz': '3.0.0'})

    def test_missing_optional_provider_is_not_required(self):
        manifest = ET.fromstring(files(optional=True)['addon.xml'])
        builder.dependencies([manifest], {})
        auditor.check_dependencies([manifest], {})


if __name__ == '__main__':
    unittest.main()
