import hashlib
import tempfile
import unittest
from pathlib import Path


class FileIntegrityTests(unittest.TestCase):
    def test_sha256_changes_after_modification(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "sample.txt"
            path.write_text("original", encoding="utf-8")

            first = hashlib.sha256(path.read_bytes()).hexdigest()

            path.write_text("modified", encoding="utf-8")
            second = hashlib.sha256(path.read_bytes()).hexdigest()

            self.assertNotEqual(first, second)
            self.assertEqual(len(first), 64)
            self.assertEqual(len(second), 64)


if __name__ == "__main__":
    unittest.main()
