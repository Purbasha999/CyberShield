import unittest
import psutil


class ProcessMonitorTests(unittest.TestCase):
    def test_current_process_exists(self):
        current_pid = psutil.Process().pid
        self.assertIn(current_pid, psutil.pids())

    def test_process_info_fields(self):
        proc = psutil.Process()
        info = proc.as_dict(attrs=["pid", "name", "status"])
        self.assertEqual(info["pid"], proc.pid)
        self.assertTrue(info["name"])


if __name__ == "__main__":
    unittest.main()
