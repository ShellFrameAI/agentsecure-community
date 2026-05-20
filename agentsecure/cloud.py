class CloudError(Exception):
    pass


class CloudRuntimeService:
    """Community stub for private ShellFrame AI cloud integrations."""

    def status(self):
        return {"enrolled": False}

    def runtime_defaults(self):
        return {}

    def config_profile(self):
        return {}

    def has_reportable_events(self):
        return False

    def enroll(self, api_base, enrollment_token, project=""):
        raise CloudError("cloud enrollment is not included in AgentSecure Community")

    def sync(self, *args, **kwargs):
        raise CloudError("cloud sync is not included in AgentSecure Community")

    def session_payload(self, *args, **kwargs):
        return {}

    def command_result(self, *args, **kwargs):
        raise CloudError("cloud commands are not included in AgentSecure Community")
