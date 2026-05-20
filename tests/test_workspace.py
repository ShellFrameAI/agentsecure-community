import os
import tempfile
import unittest

from agentsecure.core.models import SecretReplacement
from agentsecure.workspace.materializer import WorkspaceMaterializer


class WorkspaceMaterializerTest(unittest.TestCase):
    def test_symlink_workspace_rewrites_dotenv_and_links_normal_files(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            env_path = os.path.join(temp_dir, ".env")
            with open(env_path, "w") as handle:
                handle.write("OPENAI_API_KEY=sk-real-openai\n")
                handle.write("DEBUG=true\n")
            app_path = os.path.join(temp_dir, "app.py")
            with open(app_path, "w") as handle:
                handle.write("print('hello')\n")

            session = WorkspaceMaterializer(".agentsecure/workspaces").create_workspace(
                temp_dir,
                [
                    SecretReplacement(
                        source=".env",
                        name="OPENAI_API_KEY",
                        real_value="sk-real-openai",
                        virtual_value="virt_openai_123",
                    )
                ],
                "2h",
            )

            with open(env_path, "r") as handle:
                self.assertIn("sk-real-openai", handle.read())
            with open(os.path.join(session.workspace_root, ".env"), "r") as handle:
                workspace_env = handle.read()
            self.assertIn("virt_openai_123", workspace_env)
            self.assertNotIn("sk-real-openai", workspace_env)
            workspace_app = os.path.join(session.workspace_root, "app.py")
            self.assertTrue(os.path.islink(workspace_app))
            with open(workspace_app, "w") as handle:
                handle.write("print('changed')\n")
            with open(app_path, "r") as handle:
                self.assertIn("changed", handle.read())

    def test_copy_workspace_keeps_normal_file_changes_in_workspace(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            app_path = os.path.join(temp_dir, "app.py")
            with open(app_path, "w") as handle:
                handle.write("print('hello')\n")

            session = WorkspaceMaterializer(".agentsecure/workspaces").create_workspace(
                temp_dir,
                [],
                "2h",
                mode="copy",
            )

            workspace_app = os.path.join(session.workspace_root, "app.py")
            self.assertFalse(os.path.islink(workspace_app))
            with open(workspace_app, "w") as handle:
                handle.write("print('changed')\n")
            with open(app_path, "r") as handle:
                self.assertIn("hello", handle.read())

    def test_rewrites_database_url_in_dotenv_copy(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            real_url = "postgres://user:password@localhost:5432/mydb"
            env_path = os.path.join(temp_dir, ".env")
            with open(env_path, "w") as handle:
                handle.write("DATABASE_URL=%s\n" % real_url)

            session = WorkspaceMaterializer(".agentsecure/workspaces").create_workspace(
                temp_dir,
                [
                    SecretReplacement(
                        source=".env",
                        name="DATABASE_URL",
                        real_value=real_url,
                        virtual_value="virt_database_123",
                    )
                ],
                "2h",
            )

            with open(env_path, "r") as handle:
                self.assertIn(real_url, handle.read())
            with open(os.path.join(session.workspace_root, ".env"), "r") as handle:
                workspace_env = handle.read()
            self.assertIn("DATABASE_URL=virt_database_123", workspace_env)
            self.assertNotIn(real_url, workspace_env)

    def test_skips_private_and_heavy_directories(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            os.makedirs(os.path.join(temp_dir, ".git"))
            os.makedirs(os.path.join(temp_dir, "node_modules"))
            with open(os.path.join(temp_dir, ".git", "config"), "w") as handle:
                handle.write("private")
            with open(os.path.join(temp_dir, "node_modules", "package.json"), "w") as handle:
                handle.write("{}")

            session = WorkspaceMaterializer(".agentsecure/workspaces").create_workspace(temp_dir, [], "2h")

            self.assertFalse(os.path.exists(os.path.join(session.workspace_root, ".git")))
            self.assertFalse(os.path.exists(os.path.join(session.workspace_root, "node_modules")))

    def test_read_only_workspace_blocks_file_creation(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with open(os.path.join(temp_dir, ".env"), "w") as handle:
                handle.write("OPENAI_API_KEY=sk-real-openai\n")
            materializer = WorkspaceMaterializer(".agentsecure/workspaces")
            session = materializer.create_workspace(temp_dir, [], "2h")
            materializer.make_read_only(session.workspace_root)

            with self.assertRaises(OSError):
                with open(os.path.join(session.workspace_root, "created.txt"), "w") as handle:
                    handle.write("blocked")

            materializer.make_writable(session.workspace_root)
            with open(os.path.join(session.workspace_root, "created.txt"), "w") as handle:
                handle.write("allowed")
            self.assertTrue(os.path.exists(os.path.join(session.workspace_root, "created.txt")))

    def test_protect_write_paths_blocks_only_selected_files(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with open(os.path.join(temp_dir, "protected.txt"), "w") as handle:
                handle.write("protected")
            with open(os.path.join(temp_dir, "editable.txt"), "w") as handle:
                handle.write("editable")
            materializer = WorkspaceMaterializer(".agentsecure/workspaces")
            session = materializer.create_workspace(
                temp_dir,
                [],
                "2h",
                protected_write_paths=["protected.txt"],
            )
            materializer.protect_write_paths(session.workspace_root, ["protected.txt"])

            with self.assertRaises(OSError):
                with open(os.path.join(session.workspace_root, "protected.txt"), "w") as handle:
                    handle.write("blocked")
            with open(os.path.join(session.workspace_root, "editable.txt"), "w") as handle:
                handle.write("allowed")

            materializer.make_writable(session.workspace_root)

    def test_prevent_new_files_allows_existing_file_edits(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with open(os.path.join(temp_dir, "existing.txt"), "w") as handle:
                handle.write("old")
            materializer = WorkspaceMaterializer(".agentsecure/workspaces")
            session = materializer.create_workspace(temp_dir, [], "2h")
            materializer.prevent_new_files(session.workspace_root)

            with open(os.path.join(session.workspace_root, "existing.txt"), "w") as handle:
                handle.write("edited")
            with self.assertRaises(OSError):
                with open(os.path.join(session.workspace_root, "new.txt"), "w") as handle:
                    handle.write("blocked")

            materializer.make_writable(session.workspace_root)


if __name__ == "__main__":
    unittest.main()
