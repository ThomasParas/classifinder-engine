# Contributing to ClassiFinder Engine

Thanks for your interest in contributing! This is the open-source scanner engine that powers [ClassiFinder](https://classifinder.ai). Contributions that improve detection accuracy, reduce false positives, or add new secret patterns are especially welcome.

## Getting Started

```bash
git clone https://github.com/ThomasParas/classifinder-engine.git
cd classifinder-engine
python -c "from scanner import scan; print(scan('AKIAIOSFODNN7EXAMPLE'))"
```

No dependencies beyond the Python 3.12+ standard library.

## Ways to Contribute

### Report a False Positive or False Negative

If the engine misclassifies text, [open an issue](https://github.com/ThomasParas/classifinder-engine/issues) with:

- The input text (use a fake/test value — never post real secrets)
- What the engine returned
- What you expected

You can also report these via the ClassiFinder API's `POST /v1/feedback` endpoint.

### Add a New Detection Pattern

Each pattern lives in one of the category files under `patterns/`:

| File | Category |
|------|----------|
| `cloud.py` | Cloud provider credentials (AWS, GCP, Azure, etc.) |
| `payment.py` | Payment and financial (Stripe, PayPal, credit cards) |
| `vcs.py` | Version control and CI/CD (GitHub, GitLab, CircleCI) |
| `comms.py` | Communications and SaaS (Slack, Twilio, SendGrid) |
| `database.py` | Database and infrastructure (connection strings, SSH keys) |
| `generic.py` | Format-based tokens (JWT, Bearer, Basic Auth, high-entropy) |
| `ai.py` | AI/LLM provider keys (OpenAI, Anthropic, Cohere) |

To add a pattern, create a `SecretPattern` instance with:

- `id` — unique snake_case identifier
- `name` — human-readable name
- `pattern` — compiled regex
- `base_confidence` — 0.60 for format-only, 0.90 for structural, 0.95 for prefix-anchored
- `severity` — "critical", "high", "medium", or "low"
- `provider` — service name (lowercase)
- `entropy_threshold` — minimum Shannon entropy (set to `None` to skip entropy check)
- `context_keywords` — list of nearby keywords that boost confidence
- `known_test_values` — list of documented example/test values to penalize
- `recommendation` — actionable remediation advice

Then register it in `patterns/registry.py` by adding it to `PATTERN_REGISTRY`.

### Improve an Existing Pattern

If a pattern's regex is too broad (false positives) or too narrow (misses valid secrets), open a PR with the fix and include test cases showing the before/after.

## Code Style

- Python 3.12+, type hints on all functions
- No external dependencies — this engine must remain dependency-free
- No I/O of any kind — no file reads, no network calls, no logging of secret values
- PEP 8, 100-character line limit

## Pull Request Process

1. Fork the repo and create a branch from `main`
2. Make your changes
3. Include test cases for any new or modified patterns (input text + expected finding)
4. Ensure all existing tests still pass
5. Open a PR with a clear description of what changed and why

## Important: Engine Sync

This engine is mirrored in the hosted ClassiFinder API. Changes accepted here will be synced to the API server. This is handled by the maintainer — you don't need to worry about it.

## Security

If you discover a security vulnerability in the engine itself, please email security@classifinder.ai rather than opening a public issue.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
