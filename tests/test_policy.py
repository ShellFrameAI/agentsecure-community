import unittest

from agentsecure.core.models import Destination, NetworkPolicy, ProcessPolicy, ProcessRequest
from agentsecure.implementations.policy import DefaultPolicyEngine, StrictDestinationValidator


class StrictDestinationValidatorTest(unittest.TestCase):
    def test_allows_exact_allowlisted_domain(self):
        validator = StrictDestinationValidator(
            NetworkPolicy(
                allow_domains=["api.openai.com"],
                deny_private_networks=False,
            )
        )
        decision = validator.validate(Destination("https", "api.openai.com", 443))
        self.assertTrue(decision.allowed)

    def test_denies_unknown_domain(self):
        validator = StrictDestinationValidator(NetworkPolicy(allow_domains=["api.openai.com"]))
        decision = validator.validate(Destination("https", "evil.example", 443))
        self.assertFalse(decision.allowed)

    def test_allows_unknown_domain_without_credentials(self):
        validator = StrictDestinationValidator(
            NetworkPolicy(
                allow_domains=["api.openai.com"],
                deny_private_networks=False,
            )
        )
        decision = validator.validate(Destination("https", "downloads.example", 443, credentials_present=False))
        self.assertTrue(decision.allowed)
        self.assertEqual("network.no_credentials", decision.rule_id)

    def test_denies_ip_literal(self):
        validator = StrictDestinationValidator(NetworkPolicy(allow_domains=["1.1.1.1"]))
        decision = validator.validate(Destination("https", "1.1.1.1", 443))
        self.assertFalse(decision.allowed)

    def test_allows_wildcard_subdomain(self):
        validator = StrictDestinationValidator(
            NetworkPolicy(
                allow_domains=["*.anthropic.com"],
                deny_private_networks=False,
            )
        )
        decision = validator.validate(Destination("https", "api.anthropic.com", 443))
        self.assertTrue(decision.allowed)


class MemoryAudit:
    def __init__(self):
        self.events = []

    def record(self, event_type, details):
        self.events.append((event_type, details))


class DefaultPolicyEngineTest(unittest.TestCase):
    def test_allows_command_by_basename(self):
        validator = StrictDestinationValidator(NetworkPolicy())
        engine = DefaultPolicyEngine(validator, ProcessPolicy(["codex"]), MemoryAudit())
        decision = engine.evaluate_process(ProcessRequest(["/usr/local/bin/codex"], "/tmp"))
        self.assertTrue(decision.allowed)

    def test_process_audit_does_not_record_prompt_arguments(self):
        audit = MemoryAudit()
        validator = StrictDestinationValidator(NetworkPolicy())
        engine = DefaultPolicyEngine(validator, ProcessPolicy([]), audit)

        engine.evaluate_process(ProcessRequest(["codex", "exec", "write a detailed prompt"], "/tmp"))

        self.assertEqual(["codex"], audit.events[0][1]["argv"])
        self.assertEqual(3, audit.events[0][1]["argc"])


if __name__ == "__main__":
    unittest.main()
