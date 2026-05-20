import unittest
import time

from agentsecure.core.models import SecretGrant
from agentsecure.implementations.secrets import InMemoryTokenResolver
from agentsecure.implementations.secrets import GrantAwareTokenResolver
from agentsecure.implementations.secrets import build_token_map_from_environment
from agentsecure.core.models import SecretBinding


class MemoryAudit:
    def __init__(self):
        self.events = []

    def record(self, event_type, details):
        self.events.append((event_type, details))


class InMemoryTokenResolverTest(unittest.TestCase):
    def test_resolves_virtual_token(self):
        audit = MemoryAudit()
        resolver = InMemoryTokenResolver({"virt_test": "real"}, audit)
        self.assertEqual("real", resolver.resolve("virt_test"))
        self.assertEqual("secret_resolution", audit.events[0][0])


class MemorySecretStore:
    def get(self, secret_id):
        if secret_id == "openai_1":
            return "sk-real"
        return None


class MemoryGrantStore:
    def __init__(self, grant):
        self.grant = grant

    def get_by_virtual_token(self, virtual_token):
        if self.grant and self.grant.virtual_token == virtual_token:
            return self.grant
        return None

    def put(self, grant):
        self.grant = grant

    def list(self):
        return [self.grant] if self.grant else []

    def revoke(self, virtual_token):
        return False


class TokenMapBuilderTest(unittest.TestCase):
    def test_builds_token_map_from_local_secret_ref(self):
        bindings = {
            "virt_openai": SecretBinding(
                env_name="OPENAI_API_KEY",
                virtual_token="virt_openai",
                real_secret_ref="local:openai_1",
            )
        }
        token_map = build_token_map_from_environment(bindings, MemorySecretStore())
        self.assertEqual("sk-real", token_map["virt_openai"])


class GrantAwareTokenResolverTest(unittest.TestCase):
    def test_denies_expired_grant(self):
        audit = MemoryAudit()
        grant = SecretGrant(
            env_name="OPENAI_API_KEY",
            virtual_token="virt_openai",
            secret_ref="local:openai_1",
            provider="openai",
            inject_as="authorization_bearer",
            created_at=time.time() - 7200,
            expires_at=time.time() - 1,
        )
        resolver = GrantAwareTokenResolver(MemorySecretStore(), MemoryGrantStore(grant), audit)
        self.assertIsNone(resolver.resolve("virt_openai"))
        self.assertEqual("secret_resolution_expired", audit.events[0][0])

    def test_resolves_active_grant(self):
        audit = MemoryAudit()
        grant = SecretGrant(
            env_name="OPENAI_API_KEY",
            virtual_token="virt_openai",
            secret_ref="local:openai_1",
            provider="openai",
            inject_as="authorization_bearer",
            created_at=time.time(),
            expires_at=time.time() + 3600,
        )
        resolver = GrantAwareTokenResolver(MemorySecretStore(), MemoryGrantStore(grant), audit)
        self.assertEqual("sk-real", resolver.resolve("virt_openai"))


if __name__ == "__main__":
    unittest.main()
