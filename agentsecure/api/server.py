class LocalApiServer:
    def __init__(self, host, port, services):
        self.host = host
        self.port = port
        self.services = services

    def serve_forever(self):
        raise RuntimeError("local API server is not included in AgentSecure Community")
