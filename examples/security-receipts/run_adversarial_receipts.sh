#!/usr/bin/env bash
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
AGENTSECURE_CMD=${AGENTSECURE_CMD:-}
WORKDIR=${1:-"$(mktemp -d)"}

pass_count=0
risk_count=0
fail_count=0
skip_count=0

print_result() {
  status="$1"
  id="$2"
  name="$3"
  detail="$4"
  printf "%-9s %-3s %s\n" "$status" "$id" "$name"
  if [ -n "$detail" ]; then
    printf "          %s\n" "$detail"
  fi
}

pass() {
  pass_count=$((pass_count + 1))
  print_result "PASS" "$1" "$2" "$3"
}

risk() {
  risk_count=$((risk_count + 1))
  print_result "RISK" "$1" "$2" "$3"
}

fail() {
  fail_count=$((fail_count + 1))
  print_result "FAIL" "$1" "$2" "$3"
}

skip() {
  skip_count=$((skip_count + 1))
  print_result "SKIP" "$1" "$2" "$3"
}

contains() {
  haystack="$1"
  needle="$2"
  printf "%s" "$haystack" | grep -Fq "$needle"
}

not_contains() {
  haystack="$1"
  needle="$2"
  ! printf "%s" "$haystack" | grep -Fq "$needle"
}

run_as_string() {
  if [ -n "$AGENTSECURE_CMD" ]; then
    # shellcheck disable=SC2086
    $AGENTSECURE_CMD "$@" 2>&1
  else
    PYTHONPATH="$REPO_ROOT${PYTHONPATH:+:$PYTHONPATH}" python3 -m agentsecure "$@" 2>&1
  fi
}

mkdir -p "$WORKDIR"
cd "$WORKDIR" || exit 1

cat > .env <<'EOF'
OPENAI_API_KEY=sk-demo-local-secret-do-not-use
DATABASE_URL_PROD=postgres://demo:demo-password@example.invalid/app
EOF

cat > agentsecure.json <<'EOF'
{
  "secrets": [],
  "env_policy": {
    "OPENAI_API_KEY": {
      "mode": "virtualize",
      "reason": "Agent sees a virtual key, not the real key."
    },
    "DATABASE_URL_PROD": {
      "mode": "deny",
      "reason": "Production database secrets are blocked."
    }
  },
  "network": {
    "allow_domains": ["api.openai.com"],
    "deny_domains": [],
    "allow_ports": [80, 443],
    "deny_ip_literals": true,
    "deny_private_networks": true
  },
  "process": {
    "allowed_commands": []
  },
  "files": {
    "protect_write": [".env", "agentsecure.json"]
  },
  "gateway": {
    "host": "127.0.0.1",
    "port": 8765
  },
  "audit": {
    "path": ".agentsecure/audit.log"
  }
}
EOF

printf "AgentSecure adversarial receipts\n"
printf "Workspace: %s\n\n" "$WORKDIR"

check_command_guard_risk() {
  id="$1"
  name="$2"
  shift 2
  out="$(run_as_string run --protect-all -- "$@")"
  if contains "$out" "sk-demo-local-secret-do-not-use" ||
    contains "$out" "postgres://demo:demo-password@example.invalid/app"; then
    risk "$id" "$name" "command-guard mode can expose raw .env through this path"
  else
    pass "$id" "$name" "raw fake secrets excluded"
  fi
}

check_command_guard_risk "A1" "absolute /bin/cat read" /bin/cat .env
check_command_guard_risk "A2" "python open read" python3 -c 'print(open(".env").read(), end="")'
check_command_guard_risk "A3" "awk read" awk '{print}' .env
check_command_guard_risk "A4" "sed read" sed -n p .env

out="$(run_as_string run --runtime workspace --workspace-mode copy --protect-all -- python3 -c 'print(open(".env").read(), end="")')"
if contains "$out" "OPENAI_API_KEY=virt_openai_" &&
  not_contains "$out" "sk-demo-local-secret-do-not-use" &&
  not_contains "$out" "postgres://demo:demo-password@example.invalid/app"; then
  pass "A5" "workspace copy python read" "workspace copy mode exposes sanitized .env"
elif contains "$out" "gateway failed to start"; then
  skip "A5" "workspace copy python read" "localhost gateway bind is blocked in this environment"
else
  fail "A5" "workspace copy python read" "workspace copy mode did not sanitize as expected"
fi

out="$(run_as_string run --runtime workspace --workspace-mode copy --protect-all -- python3 -c 'import os; print(open(".env").read(), end=""); print("TRAVERSE"); print(open("../../../.env").read(), end="")')"
if contains "$out" "FileNotFoundError" &&
  not_contains "$out" "sk-demo-local-secret-do-not-use" &&
  not_contains "$out" "postgres://demo:demo-password@example.invalid/app"; then
  pass "A6" "workspace copy relative traversal" "relative traversal did not reach original .env"
elif contains "$out" "gateway failed to start"; then
  skip "A6" "workspace copy relative traversal" "localhost gateway bind is blocked in this environment"
else
  fail "A6" "workspace copy relative traversal" "relative traversal reached original .env or did not fail closed"
fi

printf "\nSummary: %s passed, %s known risks, %s failed, %s skipped\n" "$pass_count" "$risk_count" "$fail_count" "$skip_count"

if [ "$fail_count" -gt 0 ]; then
  exit 1
fi
