## Summary

What changed?

## Testing

- [ ] `python3 -m unittest discover -s tests -p 'test_*.py' -v`
- [ ] `python3 scripts/secret_scan.py .`

## Safety Checklist

- [ ] No real secrets, tokens, private endpoints, customer data, or generated `.agentsecure/` state.
- [ ] Community scope only: no hosted cloud sync, billing, licensing, enterprise policy distribution, or private service logic.
- [ ] README/examples updated if behavior changed.
