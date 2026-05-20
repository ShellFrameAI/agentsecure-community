import os
import tempfile
import unittest

from agentsecure.workspace.diff import WorkspaceDiff


class WorkspaceDiffTest(unittest.TestCase):
    def test_reports_added_and_modified_files(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = os.path.join(temp_dir, ".agentsecure", "workspaces", "session_test")
            os.makedirs(workspace)
            with open(os.path.join(temp_dir, "app.py"), "w") as handle:
                handle.write("print('old')\n")
            with open(os.path.join(workspace, "app.py"), "w") as handle:
                handle.write("print('new')\n")
            with open(os.path.join(workspace, "notes.md"), "w") as handle:
                handle.write("hello\n")

            output = WorkspaceDiff().unified_diff(temp_dir, workspace, [])

            self.assertIn("real/app.py", output)
            self.assertIn("workspace/app.py", output)
            self.assertIn("print('new')", output)
            self.assertIn("workspace/notes.md", output)

    def test_skips_protected_files(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = os.path.join(temp_dir, ".agentsecure", "workspaces", "session_test")
            os.makedirs(workspace)
            with open(os.path.join(temp_dir, ".env"), "w") as handle:
                handle.write("OPENAI_API_KEY=sk-real\n")
            with open(os.path.join(workspace, ".env"), "w") as handle:
                handle.write("OPENAI_API_KEY=virt_openai_123\n")

            output = WorkspaceDiff().unified_diff(temp_dir, workspace, [".env"])

            self.assertEqual("", output)

    def test_finds_latest_workspace(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            base = os.path.join(temp_dir, ".agentsecure", "workspaces")
            os.makedirs(base)
            first = os.path.join(base, "session_first")
            second = os.path.join(base, "session_second")
            os.makedirs(first)
            os.makedirs(second)
            os.utime(first, (1, 1))
            os.utime(second, (2, 2))

            self.assertEqual(second, WorkspaceDiff().latest_workspace(temp_dir))


if __name__ == "__main__":
    unittest.main()

