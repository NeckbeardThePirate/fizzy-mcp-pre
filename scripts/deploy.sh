#!/usr/bin/env bash
# Deploy fizzy-mcp to Cloudflare Workers.
# Uses wrangler.local.jsonc if present (for account-specific values),
# otherwise falls back to wrangler.jsonc.
#
# Usage:
#   ./scripts/deploy.sh [staging|production]
#
# Setup:
#   cp wrangler.local.jsonc.example wrangler.local.jsonc
#   # Fill in your account_id and KV namespace IDs

set -euo pipefail

ENV="${1:-production}"

if [[ "$ENV" != "staging" && "$ENV" != "production" ]]; then
  echo "Usage: $0 [staging|production]"
  exit 1
fi

if [ -f "wrangler.local.jsonc" ]; then
  echo "Using wrangler.local.jsonc"
  npx wrangler deploy --config wrangler.local.jsonc --env "$ENV"
else
  echo "wrangler.local.jsonc not found — falling back to wrangler.jsonc"
  echo "(Copy wrangler.local.jsonc.example to wrangler.local.jsonc and fill in your values)"
  npx wrangler deploy --env "$ENV"
fi
