#!/usr/bin/env bash
# tests/smoke.sh - bythos firmware-trust posture smoke test
set -euo pipefail

_dir="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/.." && pwd)"
_bin="${1:-${_dir}/bythos}"
_pass=0
_fail=0

_test() {
  local name="$1"
  shift
  if "$@" &>/dev/null; then
    echo "  PASS  ${name}"
    ((_pass++)) || true
  else
    echo "  FAIL  ${name}"
    ((_fail++)) || true
  fi
}

_test_exit() {
  local name="$1" want="$2"
  shift 2
  local got=0
  "$@" &>/dev/null || got=$?
  if [[ "$got" -eq "$want" ]]; then
    echo "  PASS  ${name}"
    ((_pass++)) || true
  else
    echo "  FAIL  ${name} (want ${want}, got ${got})"
    ((_fail++)) || true
  fi
}

_test_posture_exit() {
  local name="$1"
  shift
  local got=0
  "$@" &>/dev/null || got=$?
  if [[ "$got" -le 1 ]]; then
    echo "  PASS  ${name}"
    ((_pass++)) || true
  else
    echo "  FAIL  ${name} (want 0|1, got ${got})"
    ((_fail++)) || true
  fi
}

_test_contains() {
  local name="$1" haystack="$2" needle="$3"
  if [[ "$haystack" == *"$needle"* ]]; then
    echo "  PASS  ${name}"
    ((_pass++)) || true
  else
    echo "  FAIL  ${name} (missing: ${needle})"
    ((_fail++)) || true
  fi
}

echo ""
echo "=== exit codes ==="
_test_exit         "--help"          0 "$_bin" --help
_test_exit         "--version"       0 "$_bin" --version
_test_exit         "positional arg"  2 "$_bin" nope
_test_exit         "unknown flag"    2 "$_bin" --no-such-flag
_test_posture_exit "bare run"          "$_bin"
_test_posture_exit "--json run"        "$_bin" --json

echo ""
echo "=== short flags ==="
_test_exit         "-h"  0 "$_bin" -h
_test_exit         "-V"  0 "$_bin" -V
_test_posture_exit "-j"    "$_bin" -j

echo ""
echo "=== help/version text ==="
_help="$("$_bin" --help)"
_test_contains "help: usage line"      "$_help"    'usage:'
_test_contains "help: --json doc"      "$_help"    '--json'
_version="$("$_bin" --version)"
_test_contains "version: bythos label" "$_version" 'bythos'

echo ""
echo "=== plain output ==="
_plain=""
_plain_rc=0
_plain="$("$_bin")" || _plain_rc=$?
if [[ "$_plain_rc" -gt 1 ]]; then
  echo "  FAIL  capture plain (exit ${_plain_rc})"
  ((_fail++)) || true
else
  echo "  PASS  capture plain (exit ${_plain_rc})"
  ((_pass++)) || true
  _test_contains "plain banner tag"    "$_plain" '[bythos]'
  _test_contains "plain banner text"   "$_plain" 'firmware trust posture'
  _test_contains "plain efi section"   "$_plain" 'efi:'
fi

echo ""
echo "=== json shape ==="
_json=""
_rc=0
_json="$("$_bin" --json)" || _rc=$?
if [[ "$_rc" -gt 1 ]]; then
  echo "  FAIL  capture --json (exit ${_rc})"
  ((_fail++)) || true
else
  echo "  PASS  capture --json (exit ${_rc})"
  ((_pass++)) || true
  _test_contains "mode firmware"      "$_json" '"mode":"firmware"'
  _test_contains "banner text"        "$_json" '"banner":"firmware trust posture"'
  _test_contains "groups key"         "$_json" '"groups":['
  _test_contains "firmware group"     "$_json" '"name":"firmware"'
  _test_contains "overall block"      "$_json" '"overall":{"state":"'
  _test_contains "counts block"       "$_json" '"counts":{"ok":'
  _test_contains "exit_code key"      "$_json" '"exit_code":'
  _test_contains "exit_meaning key"   "$_json" '"exit_meaning":'
  _test_contains "requires_root key"  "$_json" '"requires_root":'
  _test_contains "actionable key"     "$_json" '"actionable":'
  _test_contains "skip_reason NONE"   "$_json" '"skip_reason":"NONE"'
fi

echo ""
echo "=== all 10 subgroups present ==="
_test_contains "subgroup efi"               "$_json" '"name":"efi"'
_test_contains "subgroup secure boot"       "$_json" '"name":"secure boot"'
_test_contains "subgroup boot chain"        "$_json" '"name":"boot chain"'
_test_contains "subgroup esp"               "$_json" '"name":"esp"'
_test_contains "subgroup tpm"               "$_json" '"name":"tpm"'
_test_contains "subgroup luks"              "$_json" '"name":"luks"'
_test_contains "subgroup platform firmware" "$_json" '"name":"platform firmware"'
_test_contains "subgroup platform dma"      "$_json" '"name":"platform dma"'
_test_contains "subgroup cpu"               "$_json" '"name":"cpu"'
_test_contains "subgroup fwupd"             "$_json" '"name":"fwupd"'

echo ""
echo "=== always-emitted check rows ==="
_test_contains "EFI boot mode"                "$_json" '"name":"EFI boot mode"'
_test_contains "secure boot state"            "$_json" '"name":"secure boot state"'
_test_contains "bootloader version"           "$_json" '"name":"bootloader version"'
_test_contains "TPM presence"                 "$_json" '"name":"TPM presence"'
_test_contains "DA lockout"                   "$_json" '"name":"DA lockout"'
_test_contains "LUKS block devices"           "$_json" '"name":"LUKS block devices"'
_test_contains "platform firmware deep audit" "$_json" '"name":"platform firmware deep audit"'
_test_contains "IOMMU groups"                 "$_json" '"name":"IOMMU groups"'
_test_contains "CPU microcode"                "$_json" '"name":"CPU microcode"'
_test_contains "fwupd service"                "$_json" '"name":"fwupd service"'
_test_contains "auto-refresh timer"           "$_json" '"name":"auto-refresh timer"'

echo ""
echo "=== json validity ==="
if command -v python3 &>/dev/null; then
  _test "valid JSON" python3 -m json.tool <<< "$_json"
  BYTHOS_JSON="$_json" _test "state/skip_reason invariant" python3 - <<'PYEOF'
import json, os, sys
data = json.loads(os.environ['BYTHOS_JSON'])
def walk(node):
  if isinstance(node, dict):
    if 'state' in node and 'skip_reason' in node:
      state, reason = node['state'], node['skip_reason']
      name = node.get('name', '?')
      if state == 'SKIP' and reason == 'NONE':
        sys.exit('SKIP row missing skip_reason: ' + repr(name))
      if state != 'SKIP' and reason != 'NONE':
        sys.exit('non-SKIP row with skip_reason ' + reason + ': ' + repr(name))
    for v in node.values():
      walk(v)
  elif isinstance(node, list):
    for v in node:
      walk(v)
walk(data)
PYEOF
elif command -v jq &>/dev/null; then
  _test "valid JSON" jq . <<< "$_json"
else
  echo "  SKIP  no JSON validator (python3/jq) installed"
fi

echo ""
echo "==============================="
echo "  PASS: ${_pass}  FAIL: ${_fail}"
echo "==============================="

[[ "$_fail" -eq 0 ]]
