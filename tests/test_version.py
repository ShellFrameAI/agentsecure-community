import configparser
import os
import unittest

import agentsecure


class VersionTest(unittest.TestCase):
    def test_setup_version_matches_module_version(self):
        parser = configparser.ConfigParser()
        parser.read(os.path.join(os.path.dirname(__file__), "..", "setup.cfg"))

        self.assertEqual(parser["metadata"]["version"], agentsecure.__version__)


if __name__ == "__main__":
    unittest.main()
