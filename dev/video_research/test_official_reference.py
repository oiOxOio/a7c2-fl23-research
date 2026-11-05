"""Synthetic tests only; importing the download runner must not open the network."""
import io
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from dev.video_research import official_reference as official


class OfficialReferenceTests(unittest.TestCase):
    URL = 'https://support.d-imaging.sony.co.jp/download/NEX/example/BODYDATA.DAT'

    def test_only_https_and_exact_sony_hosts(self):
        for url in ('http://support.d-imaging.sony.co.jp/download/BODYDATA.DAT',
                    'https://support.d-imaging.sony.co.jp.evil.test/BODYDATA.DAT',
                    'https://user@support.d-imaging.sony.co.jp/BODYDATA.DAT',
                    'https://support.d-imaging.sony.co.jp:444/BODYDATA.DAT',
                    self.URL + '#fragment'):
            with self.subTest(url=url), self.assertRaises(ValueError):
                official.trusted_url(url, package=True)
        self.assertEqual(official.trusted_url(self.URL, package=True), self.URL)

    def test_package_filename_is_required(self):
        with self.assertRaises(ValueError):
            official.trusted_url('https://www.sony.com/download/other.dat', package=True)

    def test_html_json_and_relative_download_urls(self):
        for document in (f'<a href="{self.URL}">Download</a>',
                         '{"download": "' + self.URL.replace('/', '\\/') + '"}',
                         '<a href="/download/NEX/example/BODYDATA.DAT">Download</a>'):
            with self.subTest(document=document):
                self.assertEqual(official.candidates(document, 'https://support.d-imaging.sony.co.jp/'),
                                 (self.URL,))

    def test_duplicate_urls_are_one_candidate(self):
        self.assertEqual(official.candidates(self.URL + ' ' + self.URL, self.URL), (self.URL,))

    def test_external_mirror_is_ignored(self):
        self.assertEqual(official.candidates('https://mirror.test/BODYDATA.DAT', self.URL), ())

    def test_query_is_unescaped(self):
        self.assertEqual(official.candidates(self.URL + '?a=1&amp;b=2', self.URL),
                         (self.URL + '?a=1&b=2',))

    def test_redirect_to_another_host_is_rejected(self):
        with self.assertRaises(ValueError):
            official.SonyRedirect().redirect_request(None, None, 302, '', {}, 'https://evil.test/file')

    def test_copy_exact_hash_and_bytes(self):
        out = io.BytesIO()
        digest = official.copy_exact(io.BytesIO(b'abc'), out, 3)
        self.assertEqual(out.getvalue(), b'abc')
        self.assertEqual(digest, 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')

    def test_short_and_long_downloads_fail(self):
        for raw in (b'ab', b'abcd'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                official.copy_exact(io.BytesIO(raw), io.BytesIO(), 3)

    def test_version_and_model_are_independent_requirements(self):
        official.check_header(SimpleNamespace(model=official.MODEL_CODE, versionMajor=2, versionMinor=1))
        for model, major, minor in ((0, 2, 1), (official.MODEL_CODE, 2, 0), (official.MODEL_CODE, 3, 1)):
            with self.subTest(values=(model, major, minor)), self.assertRaises(ValueError):
                official.check_header(SimpleNamespace(model=model, versionMajor=major, versionMinor=minor))

    def test_no_download_without_explicit_acceptance(self):
        with patch.object(official, 'discover') as discover, patch('sys.stderr', new_callable=io.StringIO):
            with self.assertRaises(SystemExit):
                official.main([])
            discover.assert_not_called()


if __name__ == '__main__':
    unittest.main()
