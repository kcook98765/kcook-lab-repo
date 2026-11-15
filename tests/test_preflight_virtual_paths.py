"""Kodi virtual URI classification must not hide real paths or credentials."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import check_publication as preflight


class VirtualPathTests(unittest.TestCase):
    def test_original_skin_virtual_icon_uri_is_not_a_host_path(self):
        preflight.scan_bytes('original XML',
            b'<value>special://home/addons/$INFO[Container.PluginName]/icon.png</value>')

    def test_virtual_prefix_does_not_hide_an_independent_host_path(self):
        virtual=b'special://home/addons/icon.png'
        for private in (b'/' + b'home/example/private', b'/' + b'Users/example/private'):
            with self.subTest(private=private), self.assertRaisesRegex(ValueError,'Private workstation path'):
                preflight.scan_bytes('mixed XML',virtual+b' '+private)

    def test_virtual_prefix_preserves_nested_host_path_suffix(self):
        for suffix in (b'/' + b'home/example/private', b'../' + b'Users/example/private'):
            with self.subTest(suffix=suffix), self.assertRaisesRegex(ValueError,'Private workstation path'):
                preflight.scan_bytes('nested XML',b'special://home/'+suffix)

    def test_unknown_or_embedded_scheme_lookalikes_remain_rejected(self):
        for prefix in (b'notspecial://',b'xspecial://',b'x_special://',b'special:///',b'/tmp/special://'):
            with self.subTest(prefix=prefix), self.assertRaisesRegex(ValueError,'Private workstation path'):
                preflight.scan_bytes('unrecognized URI',prefix+b'home/addons/icon.png')

    def test_credentials_are_checked_in_unmodified_virtual_uri_bytes(self):
        secret=b'gh'+b'p_'+b'A'*36
        with self.assertRaisesRegex(ValueError,'Credential pattern'):
            preflight.scan_bytes('credential URI',b'special://home/addons/'+secret)

    def test_real_host_paths_without_virtual_prefix_still_reject(self):
        for private in (b'/' + b'home/example/secret',b'/' + b'Users/example/secret'):
            with self.assertRaisesRegex(ValueError,'Private workstation path'):
                preflight.scan_bytes('ordinary host path',private)


if __name__ == '__main__':
    unittest.main()
