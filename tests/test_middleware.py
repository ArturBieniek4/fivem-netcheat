import tempfile
import textwrap
import unittest
from pathlib import Path

from middleware import MiddlewareManager


class MiddlewareManagerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def write(self, name, source):
        (self.directory / name).write_text(textwrap.dedent(source), encoding="utf-8")

    def test_forwards_unchanged(self):
        self.write("pass.py", """
            def patch(event):
                return event
        """)
        result = MiddlewareManager(self.directory).apply({"name": "hello", "data": [1]})
        self.assertEqual(result.status, "captured")
        self.assertEqual(result.event, {"name": "hello", "data": [1]})

    def test_drops_event(self):
        self.write("drop.py", """
            def patch(event):
                return None
        """)
        result = MiddlewareManager(self.directory).apply({"name": "hello"})
        self.assertIsNone(result.event)
        self.assertEqual(result.status, "blocked by middleware")

    def test_marks_in_place_change_and_does_not_mutate_caller(self):
        self.write("change.py", """
            def patch(event):
                event["data"][0] = "changed"
                return event
        """)
        original = {"name": "hello", "data": ["original"]}
        result = MiddlewareManager(self.directory).apply(original)
        self.assertEqual(result.status, "changed by middleware")
        self.assertEqual(result.event["data"], ["changed"])
        self.assertEqual(original["data"], ["original"])

    def test_failure_is_fail_open(self):
        self.write("broken.py", """
            def patch(event):
                raise RuntimeError("boom")
        """)
        result = MiddlewareManager(self.directory).apply({"name": "hello"})
        self.assertEqual(result.status, "captured")
        self.assertEqual(result.event, {"name": "hello"})

    def test_runs_in_alphabetical_filename_order(self):
        self.write("20_second.py", """
            def patch(event):
                event["order"].append("second")
                return event
        """)
        self.write("10_first.py", """
            def patch(event):
                event["order"].append("first")
                return event
        """)
        result = MiddlewareManager(self.directory).apply({"order": []})
        self.assertEqual(result.event["order"], ["first", "second"])


if __name__ == "__main__":
    unittest.main()
