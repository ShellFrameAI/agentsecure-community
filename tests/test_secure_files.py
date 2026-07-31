import os
import tempfile
import unittest
from unittest.mock import patch

from agentsecure.core.secure_files import write_private_json


class SecureFilesTest(unittest.TestCase):
    def test_writes_json_when_fchmod_is_unavailable(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = os.path.join(temp_dir, "private.json")

            with patch.object(os, "fchmod", None, create=True):
                write_private_json(path, {"secret": "encrypted-value"}, ".private-")

            with open(path, "r") as handle:
                self.assertEqual('{\n  "secret": "encrypted-value"\n}\n', handle.read())
            self.assertEqual([], [name for name in os.listdir(temp_dir) if name.startswith(".private-")])

    def test_closes_descriptor_before_cleaning_up_a_failed_write(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = os.path.join(temp_dir, "private.json")
            descriptor = []
            temp_paths = []
            real_mkstemp = tempfile.mkstemp

            def recording_mkstemp(*args, **kwargs):
                fd, temp_path = real_mkstemp(*args, **kwargs)
                descriptor.append(fd)
                temp_paths.append(temp_path)
                return fd, temp_path

            with patch("agentsecure.core.secure_files.tempfile.mkstemp", side_effect=recording_mkstemp):
                with patch.object(os, "fchmod", side_effect=AttributeError("fchmod unavailable"), create=True):
                    with self.assertRaises(AttributeError):
                        write_private_json(path, {}, ".private-")

            with self.assertRaises(OSError):
                os.fstat(descriptor[0])
            self.assertFalse(os.path.exists(temp_paths[0]))


if __name__ == "__main__":
    unittest.main()
