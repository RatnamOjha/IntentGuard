#!/usr/bin/env bash
set -euo pipefail

VERSION=1.19.1
EXPECTED_SHA256=fb356176d8063f92920ba9d2650b2b07d0f67e4f6a10b389e2907fc3902c5a9a
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOL_DIR="$PROJECT_DIR/.tools"
TARGET="$TOOL_DIR/opa"

if [[ "$(uname -s)" != Linux || "$(uname -m)" != x86_64 ]]; then
  echo "This installer currently supports Linux x86_64 only. Use the official OPA release for this platform."
  exit 1
fi
mkdir -p "$TOOL_DIR"
curl --fail --location --retry 3 \
  "https://github.com/open-policy-agent/opa/releases/download/v$VERSION/opa_linux_amd64" \
  --output "$TARGET"
echo "$EXPECTED_SHA256  $TARGET" | sha256sum --check --status
chmod +x "$TARGET"
"$TARGET" version
echo "OPA $VERSION installed with verified SHA-256 at $TARGET"
