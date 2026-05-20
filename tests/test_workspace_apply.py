import os
import tempfile
import unittest

from agentsecure.workspace.apply import WorkspaceApplier, WorkspaceApplyPlanner


class WorkspaceApplyTest(unittest.TestCase):
    def test_applies_new_and_modified_files_but_skips_protected_files(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = os.path.join(temp_dir, ".agentsecure", "workspaces", "session_test")
            os.makedirs(workspace)
            with open(os.path.join(temp_dir, "app.py"), "w") as handle:
                handle.write("print('old')\n")
            with open(os.path.join(temp_dir, ".env"), "w") as handle:
                handle.write("OPENAI_API_KEY=sk-real\n")
            with open(os.path.join(workspace, "app.py"), "w") as handle:
                handle.write("print('new')\n")
            with open(os.path.join(workspace, "new_file.py"), "w") as handle:
                handle.write("x = 1\n")
            with open(os.path.join(workspace, ".env"), "w") as handle:
                handle.write("OPENAI_API_KEY=bad\n")

            result = WorkspaceApplier().apply(temp_dir, workspace, [".env"])

            self.assertEqual(["app.py", "new_file.py"], result.copied)
            self.assertEqual([".env"], [change.path for change in result.skipped])
            with open(os.path.join(temp_dir, "app.py"), "r") as handle:
                self.assertEqual("print('new')\n", handle.read())
            with open(os.path.join(temp_dir, "new_file.py"), "r") as handle:
                self.assertEqual("x = 1\n", handle.read())
            with open(os.path.join(temp_dir, ".env"), "r") as handle:
                self.assertEqual("OPENAI_API_KEY=sk-real\n", handle.read())

    def test_dry_run_does_not_copy_files(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = os.path.join(temp_dir, ".agentsecure", "workspaces", "session_test")
            os.makedirs(workspace)
            with open(os.path.join(temp_dir, "app.py"), "w") as handle:
                handle.write("old\n")
            with open(os.path.join(workspace, "app.py"), "w") as handle:
                handle.write("new\n")

            result = WorkspaceApplier().apply(temp_dir, workspace, [], dry_run=True)

            self.assertEqual(["app.py"], result.copied)
            with open(os.path.join(temp_dir, "app.py"), "r") as handle:
                self.assertEqual("old\n", handle.read())

    def test_delete_is_skipped_for_mvp(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = os.path.join(temp_dir, ".agentsecure", "workspaces", "session_test")
            os.makedirs(workspace)
            with open(os.path.join(temp_dir, "deleted.py"), "w") as handle:
                handle.write("keep for now\n")

            changes = WorkspaceApplyPlanner().plan(temp_dir, workspace, [])

            self.assertEqual("skip", changes[0].action)
            self.assertEqual("deleted.py", changes[0].path)
            self.assertEqual("delete not applied", changes[0].reason)

    def test_workspace_symlinks_are_skipped(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = os.path.join(temp_dir, ".agentsecure", "workspaces", "session_test")
            os.makedirs(workspace)
            target = os.path.join(temp_dir, "target.py")
            with open(target, "w") as handle:
                handle.write("target\n")
            os.symlink(target, os.path.join(workspace, "linked.py"))

            result = WorkspaceApplier().apply(temp_dir, workspace, [])

            self.assertEqual([], result.copied)
            self.assertEqual("linked.py", result.skipped[0].path)
            self.assertEqual("workspace symlink", result.skipped[0].reason)


if __name__ == "__main__":
    unittest.main()

