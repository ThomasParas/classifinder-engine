#!/usr/bin/env python3
"""
Add inline source comments to Betterleaks/SPDB-attributed patterns.

Inserts a # Pattern attribution: comment directly above the regex=re.compile(
line for each pattern that doesn't already have one.

Run from classifinder-engine/ root:
    python scripts/add_source_comments.py
    python scripts/add_source_comments.py --dry-run
"""

from __future__ import annotations
import argparse
import re
from pathlib import Path

# ---------------------------------------------------------------------------
# Attribution map: pattern_id -> comment to insert above regex=re.compile(
# ---------------------------------------------------------------------------

SOURCE_COMMENTS: dict[str, str] = {
    # ai.py
    "huggingface_token":
        "# Pattern attribution: Betterleaks MIT (betterleaks.toml:3248) — hf_ vendor prefix",
    "replicate_api_token":
        "# Pattern attribution: Betterleaks MIT (betterleaks.toml:4168) — r8_ vendor prefix",
    "groq_api_key":
        "# Pattern attribution: Betterleaks MIT (betterleaks.toml:3146) — gsk_ vendor prefix",
    "deepseek_api_key":
        "# Pattern attribution: Betterleaks MIT (betterleaks.toml:695) — sk- + DeepSeek context",
    "xai_api_key":
        "# Pattern attribution: Betterleaks MIT (betterleaks.toml:4956) — xai- vendor prefix",

    # ai.py — missed in first pass
    "openai_api_key":
        "# Independently authored — sk- prefix derived from OpenAI API documentation",
    "cohere_api_key":
        "# Independently authored — context-gated 40-char format; no verbatim external source",
    "elevenlabs_api_key":
        "# Pattern attribution: secrets-patterns-db CC-BY-4.0 — context-gated [a-f0-9]{32}",
    "assemblyai_api_key":
        "# Pattern attribution: secrets-patterns-db CC-BY-4.0 — context-gated [a-f0-9]{32}",
    "deepgram_api_key":
        "# Pattern attribution: secrets-patterns-db CC-BY-4.0 — context-gated [a-f0-9]{40}",
    "langfuse_secret_key":
        "# Independently authored — sk-lf- vendor prefix per LangFuse documentation",
    "mistral_api_key":
        "# Independently authored — context-gated 32-char format; no verbatim external source",

    # cloud.py — missed in first pass + vendor/independent
    "aws_access_key":
        "# Vendor-published format — AKIA/ASIA prefix is AWS-documented IAM key format",
    "aws_secret_key":
        "# Vendor-published format — context-gated 40-char base64; AWS-documented credential",
    "gcp_api_key":
        "# Vendor-published format — AIza prefix is Google-published GCP API key format",
    "gcp_service_account_key":
        "# Vendor-published format — PEM key within JSON service account file (RFC 7468 + Google docs)",
    "azure_storage_key":
        "# Independently authored — context-gated 86-char base64 + == suffix; Azure-documented format",
    "azure_ad_client_secret":
        "# Independently authored — context-gated 34-44 char secret; Azure-documented credential",
    "fly_api_token":
        "# Independently authored — fo1_ vendor prefix per Fly.io access token documentation",
    "railway_token":
        "# Independently authored — context-gated UUID; Railway-documented deploy token format",

    # cloud.py
    "digitalocean_token":
        "# Pattern attribution: Betterleaks MIT (betterleaks.toml:738) — dop_v1_ vendor prefix",
    "heroku_api_key":
        "# Pattern attribution: Betterleaks MIT (betterleaks.toml:3220) — context-gated UUID",
    "cloudflare_api_token":
        "# Pattern attribution: Betterleaks MIT (betterleaks.toml:509) — context-gated 40-char",
    "doppler_token":
        "# Pattern attribution: Betterleaks MIT (betterleaks.toml:786) — dp.pt. vendor prefix",
    "vault_token":
        "# Pattern attribution: Betterleaks MIT (betterleaks.toml:4731) — hvs. vendor prefix",
    "pulumi_access_token":
        "# Pattern attribution: Betterleaks MIT (betterleaks.toml:4129) — pul- vendor prefix",
    "alibaba_access_key":
        "# Pattern attribution: Betterleaks MIT (betterleaks.toml:177) — LTAI vendor prefix",
    "vercel_access_token":
        "# Pattern attribution: Betterleaks MIT (betterleaks.toml:4798) — vca_ vendor prefix",
    "vercel_refresh_token":
        "# Pattern attribution: Betterleaks MIT (betterleaks.toml:4823) — vcr_ vendor prefix",
    "okta_api_token":
        "# Pattern attribution: Betterleaks MIT (betterleaks.toml:3821) — context-gated 00-prefix",
    "ibm_cloud_api_key":
        "# Pattern attribution: secrets-patterns-db CC-BY-4.0 (rules-stable.yml:~1740) — context-gated 44-char",

    # comms.py
    "slack_bot_token":
        "# Pattern attribution: Betterleaks MIT (betterleaks.toml:4394) — xoxb- vendor prefix",
    "sendgrid_api_key":
        "# Pattern attribution: Betterleaks MIT (betterleaks.toml:4230) — SG. vendor prefix",
    "mailgun_api_key":
        "# Pattern attribution: Betterleaks MIT (betterleaks.toml:3570) — key- vendor prefix",
    "newrelic_admin_api_key":
        "# Pattern attribution: secrets-patterns-db CC-BY-4.0 (rules-stable.yml:2194) — NRAA- vendor prefix",
    "newrelic_insights_key":
        "# Pattern attribution: Betterleaks MIT (betterleaks.toml:3720) — NRII-/NRIQ- vendor prefix",
    "newrelic_user_api_key":
        "# Pattern attribution: Betterleaks MIT (betterleaks.toml:3742) — NRAK- vendor prefix",
    "grafana_api_key":
        "# Pattern attribution: Betterleaks MIT (betterleaks.toml:3126) — glsa_ vendor prefix",
    "linear_api_key":
        "# Pattern attribution: Betterleaks MIT (betterleaks.toml:3438) — lin_api_ vendor prefix",
    "sentry_org_token":
        "# Pattern attribution: Betterleaks MIT (betterleaks.toml:4260) — sntrys_eyJ vendor prefix",
    "sentry_user_token":
        "# Pattern attribution: Betterleaks MIT (betterleaks.toml:4270) — sntryu_ vendor prefix",
    "datadog_api_key":
        "# Pattern attribution: Betterleaks MIT (betterleaks.toml:676) — context-gated 32-char hex",
    "mattermost_token":
        "# Pattern attribution: Betterleaks MIT (betterleaks.toml:3620) — context-gated 26-char",
    "figma_pat":
        "# Pattern attribution: secrets-patterns-db CC-BY-4.0 (rules-stable.yml:1068) — context-gated numeric+UUID",

    # comms.py — missed in first pass + vendor/independent
    "slack_user_token":
        "# Vendor-published format — xoxp- prefix is Slack-documented user token format",
    "slack_webhook_url":
        "# Vendor-published format — hooks.slack.com URL structure is Slack-documented",
    "twilio_account_sid":
        "# Vendor-published format — AC prefix is Twilio-documented Account SID format",
    "twilio_auth_token":
        "# Independently authored — context-gated 32-char hex; Twilio-documented credential",
    "telegram_bot_token":
        "# Pattern attribution: secrets-patterns-db CC-BY-4.0 — numeric_id:token Telegram bot format",
    "datadog_app_key":
        "# Pattern attribution: secrets-patterns-db CC-BY-4.0 — context-gated 40-char hex",
    "auth0_management_token":
        "# Independently authored — context-gated JWT (eyJ header); Auth0-documented token format",
    "discord_webhook_url":
        "# Vendor-published format — discord.com/api/webhooks/ URL structure is Discord-documented",
    "teams_webhook_url":
        "# Vendor-published format — webhook.office.com/webhookb2/ URL structure is Microsoft-documented",

    # payment.py
    "shopify_access_token":
        "# Pattern attribution: Betterleaks MIT (betterleaks.toml:4320) — shpat_ vendor prefix",
    "shopify_custom_token":
        "# Pattern attribution: Betterleaks MIT (betterleaks.toml:4330) — shpca_ vendor prefix",
    "shopify_private_token":
        "# Pattern attribution: Betterleaks MIT (betterleaks.toml:4340) — shppa_ vendor prefix",
    "ethereum_private_key":
        "# Pattern attribution: Betterleaks MIT (betterleaks.toml:4053) — context-gated 0x+64hex",
    "nuget_api_key":
        "# Pattern attribution: secrets-patterns-db CC-BY-4.0 (rules-stable.yml:5280) — oy2 vendor prefix",

    # payment.py — missed + vendor/independent
    "stripe_live_secret_key":
        "# Vendor-published format — sk_live_ prefix is Stripe-documented live secret key",
    "stripe_test_secret_key":
        "# Vendor-published format — sk_test_ prefix is Stripe-documented test secret key",
    "stripe_live_publishable_key":
        "# Vendor-published format — pk_live_ prefix is Stripe-documented publishable key",
    "stripe_webhook_secret":
        "# Vendor-published format — whsec_ prefix is Stripe-documented webhook signing secret",
    "stripe_restricted_key":
        "# Vendor-published format — rk_live_ prefix is Stripe-documented restricted key",
    "paypal_client_secret":
        "# Independently authored — context-gated E-prefix 50-80 char; PayPal-documented OAuth credential",
    "square_access_token":
        "# Pattern attribution: Betterleaks MIT (betterleaks.toml:922) — EAA prefix (Square-documented)",
    "credit_card_number":
        "# Vendor-published format — IIN/BIN ranges per PCI-DSS and card network specifications",
    "bitcoin_wif_key":
        "# Vendor-published format — WIF key format per BIP-0178 specification (Base58Check encoding)",
    "razorpay_key":
        "# Vendor-published format — rzp_live_/rzp_test_ prefix is Razorpay-documented API key format",

    # vcs.py
    "github_pat_classic":
        "# Pattern attribution: Betterleaks MIT (betterleaks.toml:2771) — ghp_ vendor prefix",
    "github_pat_fine_grained":
        "# Pattern attribution: Betterleaks MIT (betterleaks.toml:2717) — github_pat_ vendor prefix",
    "github_oauth_secret":
        "# Pattern attribution: Betterleaks MIT (betterleaks.toml:2744) — gho_ vendor prefix",
    "github_app_installation_token":
        "# Vendor-published format (ghs_ prefix per GitHub Apps documentation)",
    "github_user_to_server_token":
        "# Vendor-published format (ghu_ prefix per GitHub Apps documentation)",
    "gitlab_pat":
        "# Pattern attribution: Betterleaks MIT (betterleaks.toml:2925) — glpat- vendor prefix",
    "gitlab_pipeline_trigger":
        "# Pattern attribution: Betterleaks MIT (betterleaks.toml:2973) — glptt- vendor prefix",
    "npm_token":
        "# Pattern attribution: Betterleaks MIT (betterleaks.toml:3761) — npm_ vendor prefix",
    "pypi_token":
        "# Pattern attribution: Betterleaks MIT (betterleaks.toml:4139) — pypi-AgEI base64 anchor",
    "rubygems_token":
        "# Pattern attribution: Betterleaks MIT (betterleaks.toml:4192) — rubygems_ vendor prefix",

    # vcs.py — missed in first pass
    "bitbucket_app_password":
        "# Independently authored — context-gated 20-40 char; Bitbucket-documented app password format",
    "circleci_token":
        "# Pattern attribution: Betterleaks MIT (betterleaks.toml) — context-gated 40-char hex",
}

SOURCE_MARKERS = (
    "# Source:",
    "# Format per",
    "# Pattern attribution:",
    "# Independently authored",
    "# Vendor-published",
)

_ID_RE = re.compile(r'\s+id="([^"]+)"')
_REGEX_RE = re.compile(r'\s+regex=re\.compile\(')


def has_source_comment(lines: list[str], regex_line_idx: int) -> bool:
    start = max(0, regex_line_idx - 5)
    return any(
        any(marker in lines[i] for marker in SOURCE_MARKERS)
        for i in range(start, regex_line_idx)
    )


def get_indent(line: str) -> str:
    return " " * (len(line) - len(line.lstrip()))


def process_file(path: Path, dry_run: bool = False) -> int:
    content = path.read_text(encoding="utf-8")
    lines = content.splitlines(keepends=True)

    insertions: list[tuple[int, str]] = []  # (line_index, comment_line)
    current_id: str | None = None

    for i, line in enumerate(lines):
        id_match = _ID_RE.match(line)
        if id_match:
            current_id = id_match.group(1)
            continue

        if current_id and _REGEX_RE.match(line):
            comment = SOURCE_COMMENTS.get(current_id)
            if comment and not has_source_comment(lines, i):
                indent = get_indent(line)
                insertions.append((i, f"{indent}{comment}\n"))
            current_id = None

    if not insertions:
        return 0

    # Apply insertions in reverse order so indices stay valid
    for idx, comment_line in reversed(insertions):
        lines.insert(idx, comment_line)

    if not dry_run:
        path.write_text("".join(lines), encoding="utf-8")

    return len(insertions)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--path", type=Path,
                        default=Path(__file__).resolve().parent.parent / "patterns")
    args = parser.parse_args()

    total = 0
    for py_file in sorted(args.path.glob("*.py")):
        if py_file.name in ("registry.py", "__init__.py"):
            continue
        n = process_file(py_file, dry_run=args.dry_run)
        if n:
            action = "would add" if args.dry_run else "added"
            print(f"{py_file.name}: {action} {n} comment(s)")
        total += n

    print(f"\nTotal: {total} comment(s) {'to add' if args.dry_run else 'added'}")


if __name__ == "__main__":
    main()
