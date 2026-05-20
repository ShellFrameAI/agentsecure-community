# Contributing

Thanks for contributing to AgentSecure Community.

## Development Setup

```bash
python3 -m pip install -e .
python3 -m unittest discover -s tests -p 'test_*.py' -v
python3 scripts/secret_scan.py .
```

## Contribution Guidelines

- Keep community code local-first and understandable.
- Do not add hosted cloud, billing, license enforcement, enterprise policy sync, or private endpoint logic to the community release.
- Do not commit real secrets, generated `.agentsecure/` state, local `agentsecure.json`, or real `.env` files.
- Prefer small tests that demonstrate behavior without external services.
- Keep examples fake and clearly marked as demo values.

## Pull Request Checklist

- Tests pass.
- Secret scan passes.
- README or examples are updated when behavior changes.
- New config examples do not include real endpoints, customer data, private URLs, or production credentials.
