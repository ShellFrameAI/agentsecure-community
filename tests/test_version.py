import configparser
import os
import unittest

import agentsecure
from agentsecure.cli.main import build_parser


class VersionTest(unittest.TestCase):
    def test_setup_version_matches_module_version(self):
        parser = configparser.ConfigParser()
        parser.read(os.path.join(os.path.dirname(__file__), "..", "setup.cfg"))

        self.assertEqual(parser["metadata"]["version"], agentsecure.__version__)

    def test_cli_version_flag_uses_package_version(self):
        parser = build_parser()
        with self.assertRaises(SystemExit) as context:
            parser.parse_args(["--version"])
        self.assertEqual(0, context.exception.code)


if __name__ == "__main__":
    unittest.main()
