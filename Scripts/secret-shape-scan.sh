#!/bin/sh
set -eu
root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$root"

if git grep -nE '(BEGIN (RSA|EC|OPENSSH) PRIVATE KEY|Bearer [A-Za-z0-9._~-]{20,}|gh[pousr]_[A-Za-z0-9]{20,})' -- ':!Scripts/secret-shape-scan.sh'; then
  echo "credential-like material found" >&2
  exit 1
fi

if git grep -nE '"(access_token|refresh_token|authorization_code|private_key)"[[:space:]]*:' -- Scenario Docs README.md GOAL.md AUTHORITY.md 2>/dev/null; then
  echo "credential-shaped public evidence field found" >&2
  exit 1
fi

echo "secret-shape scan passed"
