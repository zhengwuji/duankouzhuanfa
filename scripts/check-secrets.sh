#!/usr/bin/env bash
#
# Refuse to publish credentials.
#
# This repository is public, and the relay configuration it manages is exactly
# the kind of thing that accumulates secrets: PSKs, UUIDs, console password
# hashes, SSH passwords used by the one-click deployer. A single accidental
# `git add` of a config.json or a test script would publish working credentials
# for a live relay, and rewriting history afterwards does not un-publish them.
#
# Two layers are checked:
#
#   1. Generic patterns that are recognisable without knowing the deployment:
#      private key blocks, GitHub/OpenAI/AWS token shapes, and `password = ...`
#      style assignments.
#   2. An optional deny-list of literal strings read from .secrets-denylist,
#      which is git-ignored on purpose. Real host addresses, passwords and PSKs
#      live there rather than in this file, so this script stays safe to commit
#      while still being able to catch the deployment's own values.
#
# A line may opt out with the marker `check-secrets:allow`, which is meant for
# obviously-fake fixtures (a private-key header with a body of "AAAA" is not a
# key). The opt-out is per line and greppable, so a reviewer can see exactly
# what was exempted instead of trusting a broad ignore rule.
#
# Usage:
#   scripts/check-secrets.sh              # scan tracked files in the work tree
#   scripts/check-secrets.sh --history    # scan every commit in the repository
#
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

mode="worktree"
case "${1:-}" in
    ""|--worktree) mode="worktree" ;;
    --history)     mode="history" ;;
    -h|--help)
        sed -n '2,26p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
        exit 0
        ;;
    *)
        echo "unknown argument: $1" >&2
        exit 2
        ;;
esac

# Generic shapes. `-I` skips binaries: a compiled relay embeds field names like
# "passwordHash" and "psk", which are not secrets and would drown the real hits.
#
# The private-key pattern deliberately requires a long base64 body on the same
# line. Matching the bare header would flag the obviously-fake fixture in
# internal/install/fingerprint_test.go (a header whose body is the literal
# string "AAAA") and, because that fixture is already in the published history,
# would leave --history permanently red — a check that always fails is a check
# nobody reads. A real key pasted into a line carries a long body; a real
# multi-line PEM file is caught by the standalone base64-body pattern below.
generic=(
    'BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----.[A-Za-z0-9+/]{40,}'
    '^[A-Za-z0-9+/]{60,}={0,2}$'
    'ssh-rsa AAAA[0-9A-Za-z+/]{100,}'
    'gh[pousr]_[A-Za-z0-9]{20,}'
    'github_pat_[A-Za-z0-9_]{20,}'
    'sk-[A-Za-z0-9]{20,}'
    'AKIA[0-9A-Z]{16}'
    'AIza[0-9A-Za-z_-]{35}'
    '(password|passwd|psk|secret|token|apikey|api_key)[[:space:]]*[:=][[:space:]]*"[^"$]{8,}"'
)

# A deny-list of this deployment's literal values, if the operator created one.
denylist=()
if [[ -f .secrets-denylist ]]; then
    while IFS= read -r line; do
        # Strip comments and surrounding whitespace so the file can be annotated.
        line="${line%%#*}"
        line="$(printf '%s' "$line" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
        [[ -n "$line" ]] && denylist+=("$line")
    done < .secrets-denylist
fi

patterns=("${generic[@]}")
patterns+=("${denylist[@]}")

status=0
scan() {
    local label="$1"; shift
    local found=0
    for pat in "${patterns[@]}"; do
        # -F for deny-list entries (they may contain regex metacharacters such as
        # '.' in an IP address); -E for the generic shapes.
        local grep_mode="-E"
        local in_denylist=0
        for d in "${denylist[@]:-}"; do
            [[ "$d" == "$pat" ]] && in_denylist=1 && break
        done
        [[ $in_denylist -eq 1 ]] && grep_mode="-F"

        local hits
        hits="$(git grep -I -n $grep_mode -- "$pat" "$@" 2>/dev/null || true)"
        # Drop lines that explicitly opted out, so an obviously-fake fixture
        # does not have to weaken the pattern for everyone.
        if [[ -n "$hits" ]]; then
            hits="$(printf '%s\n' "$hits" | grep -v 'check-secrets:allow' || true)"
        fi
        if [[ -n "$hits" ]]; then
            echo "  PATTERN: $pat" >&2
            printf '%s\n' "$hits" | sed 's/^/    /' >&2
            found=1
            status=1
        fi
    done
    if [[ $found -eq 0 ]]; then
        echo "  $label: clean"
    fi
}

echo "==> scanning for credentials ($mode)"
if [[ "$mode" == "history" ]]; then
    # Every commit, so a credential that was committed and later deleted is
    # still reported: it remains readable in the published history.
    scan "all commits" "$(git rev-list --all)"
else
    scan "tracked files"
    # Untracked files are not published yet, but they are one `git add -A` away.
    echo "==> untracked files that are not ignored"
    untracked="$(git ls-files --others --exclude-standard)"
    if [[ -n "$untracked" ]]; then
        printf '%s\n' "$untracked" | sed 's/^/  /'
        echo "  (review these before staging)"
    else
        echo "  none"
    fi
fi

if [[ $status -ne 0 ]]; then
    cat >&2 <<'EOF'

FAILED: credential-like content was found.

Do not commit it. Remove the value, then re-run this script. If the hit is a
test fixture, use an obviously fake value so the check stays meaningful; if the
value is real, rotate it — assume anything that reached a commit is compromised.
EOF
    exit 1
fi

echo "==> ok: no credentials found"
