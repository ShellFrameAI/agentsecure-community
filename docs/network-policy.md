# Network Policy

Network policy controls where AgentSecure may inject protected credentials. In
the default MCP-first workflow, it is evaluated before a placeholder is
resolved.

It does not control every network request made by a normally running coding
agent. Requests without protected AgentSecure credentials use the agent's
ordinary network tools and permissions.

## Allow a credential destination

```bash
agentsecure network allow api.example.com
```

When a destination uses a non-standard port, pass a URL or `host:port`:

```bash
agentsecure network allow https://api.example.com:8443/v1/test
```

This adds `api.example.com` to `network.allow_domains` and `8443` to
`network.allow_ports`.

List or remove domains:

```bash
agentsecure network list
agentsecure network remove api.example.com
```

`network remove` removes the domain. It does not remove a previously added port;
edit `network.allow_ports` in `agentsecure.json` when that cleanup is needed.

Guided setup also accepts destinations:

```bash
agentsecure start --client claude \
  --approved-host https://api.example.com:8443
```

For imported secrets, the normalized host is stored both on each project alias
and in the project network allowlist.

## Evaluation order

For a credential-bearing destination, AgentSecure checks:

1. the destination port is in `allow_ports`;
2. the host does not match `deny_domains`;
3. IP literals are rejected when `deny_ip_literals` is enabled;
4. the host matches `allow_domains`;
5. DNS does not resolve to a private, loopback, link-local, or multicast
   address when `deny_private_networks` is enabled;
6. the specific secret alias is approved for the destination host when that
   alias has host restrictions.

Failure at any applicable check blocks secret resolution and injection.

## Policy shape

```json
{
  "network": {
    "allow_domains": [
      "api.example.com",
      "*.services.example.com"
    ],
    "deny_domains": [
      "blocked.example.com"
    ],
    "allow_ports": [80, 443, 8443],
    "deny_ip_literals": true,
    "deny_private_networks": true
  }
}
```

An exact domain matches only itself. A pattern beginning with `*.` matches
subdomains, not the parent domain.

## Local services

Production defaults deny IP literals and hosts that resolve to private or
loopback addresses. Testing against a local service therefore requires an
explicit policy change. Treat that as a deliberate weakening for the current
project, not a normal onboarding step.

See [MCP usage](mcp.md) for request behavior and
[advanced runtime mode](advanced-runtime.md) for proxy-specific controls.
