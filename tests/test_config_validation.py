import unittest

from agentsecure.core.config import ConfigError, JsonConfigLoader


class ConfigValidationTest(unittest.TestCase):
    def test_gateway_must_be_loopback(self):
        with self.assertRaises(ConfigError):
            JsonConfigLoader().load_data({"gateway": {"host": "0.0.0.0", "port": 8765}})

    def test_gateway_port_must_be_valid(self):
        with self.assertRaises(ConfigError):
            JsonConfigLoader().load_data({"gateway": {"host": "127.0.0.1", "port": 0}})

    def test_provider_allow_paths_must_be_list(self):
        with self.assertRaises(ConfigError):
            JsonConfigLoader().load_data(
                {
                    "provider_proxy": {
                        "enabled": True,
                        "providers": {
                            "openai": {
                                "env_name": "OPENAI_API_KEY",
                                "base_url_env": "OPENAI_BASE_URL",
                                "upstream": "https://api.openai.com",
                                "local_path": "/providers/openai",
                                "allow_paths": "/v1/",
                            }
                        },
                    }
                }
            )

    def test_provider_env_must_not_override_path(self):
        with self.assertRaises(ConfigError):
            JsonConfigLoader().load_data(
                {
                    "provider_proxy": {
                        "enabled": True,
                        "providers": {
                            "openai": {
                                "env_name": "OPENAI_API_KEY",
                                "base_url_env": "PATH",
                                "upstream": "https://api.openai.com",
                                "local_path": "/providers/openai",
                                "allow_paths": ["/v1/"],
                            }
                        },
                    }
                }
            )

    def test_provider_local_paths_must_not_overlap(self):
        with self.assertRaises(ConfigError):
            JsonConfigLoader().load_data(
                {
                    "provider_proxy": {
                        "enabled": True,
                        "providers": {
                            "generic": {
                                "env_name": "GENERIC_API_KEY",
                                "base_url_env": "GENERIC_BASE_URL",
                                "upstream": "https://generic.example.invalid",
                                "local_path": "/providers/openai",
                                "allow_paths": ["/"],
                            },
                            "openai": {
                                "env_name": "OPENAI_API_KEY",
                                "base_url_env": "OPENAI_BASE_URL",
                                "upstream": "https://api.openai.com",
                                "local_path": "/providers/openai/v1",
                                "allow_paths": ["/"],
                            },
                        },
                    }
                }
            )


if __name__ == "__main__":
    unittest.main()
