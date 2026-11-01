"""Report publication failures and races; all files are synthetic local data."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from src.video_research.cli import emit


class ReportPublicationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_unsupported_publication_does_not_leave_partial_report(self):
        path = self.root/'report.private.json'
        with patch('src.video_research.cli.os.link', side_effect=OSError('unsupported')):
            with self.assertRaises(OSError):
                emit({'ok': True}, path)
        self.assertFalse(path.exists())
        self.assertEqual(list(self.root.iterdir()), [])

    def test_concurrent_report_is_never_removed(self):
        path = self.root/'report.private.json'
        def race(source, destination):
            Path(destination).write_text('other job')
            raise FileExistsError('concurrent publisher')
        with patch('src.video_research.cli.os.link', side_effect=race):
            with self.assertRaises(FileExistsError):
                emit({'ok': True}, path)
        self.assertEqual(path.read_text(), 'other job')
        self.assertEqual(list(self.root.iterdir()), [path])

    def test_nonfinite_json_is_rejected_before_file_creation(self):
        with self.assertRaises(ValueError):
            emit({'invalid': float('nan')}, self.root/'report.private.json')
        self.assertEqual(list(self.root.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
