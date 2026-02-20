#!/bin/sh
#
# Functional test suite for memlimit.
# Usage: ./test.sh [path-to-memlimit]
#
# Requires test_alloc to be built first (make test handles this).
#
# Exit codes:
#   0  all tests passed
#   1  one or more tests failed

set -u

MEMLIMIT="${1:-./memlimit}"
ALLOC="./test_alloc"
PASS=0
FAIL=0

if [ ! -x "$MEMLIMIT" ]; then
    echo "FATAL: $MEMLIMIT not found or not executable"
    exit 1
fi

if [ ! -x "$ALLOC" ]; then
    echo "FATAL: $ALLOC not found or not executable (run make test)"
    exit 1
fi

pass() {
    PASS=$((PASS + 1))
    echo "  PASS: $1"
}

fail() {
    FAIL=$((FAIL + 1))
    echo "  FAIL: $1"
}

run_test() {
    echo "--- $1"
}

# ---- Tests ----

run_test "version and help"
$MEMLIMIT --version >/dev/null 2>&1 && pass "--version" || fail "--version"
$MEMLIMIT --help    >/dev/null 2>&1 && pass "--help"    || fail "--help"

run_test "basic success"
$MEMLIMIT 1G -- true >/dev/null 2>&1 && pass "true exits 0" || fail "true exits 0"

run_test "exit code propagation"
$MEMLIMIT 1G -- sh -c 'exit 42' >/dev/null 2>&1
test $? -eq 42 && pass "exit 42 propagated" || fail "exit 42 propagated"

run_test "command not found"
$MEMLIMIT 1G -- nonexistent_cmd_xyz >/dev/null 2>&1
test $? -eq 127 && pass "exit 127 for missing command" || fail "exit 127 for missing command"

run_test "invalid limit rejected"
$MEMLIMIT -1 -- true >/dev/null 2>&1
test $? -eq 2 && pass "exit 2 for invalid limit" || fail "exit 2 for invalid limit"

run_test "invalid verbose interval rejected"
$MEMLIMIT -v0 1G -- true >/dev/null 2>&1
test $? -eq 2 && pass "exit 2 for -v0" || fail "exit 2 for -v0"

$MEMLIMIT --verbose=abc 1G -- true >/dev/null 2>&1
test $? -eq 2 && pass "exit 2 for --verbose=abc" || fail "exit 2 for --verbose=abc"

run_test "grace flag short form"
$MEMLIMIT -g 2 1G -- true >/dev/null 2>&1 && pass "-g accepted" || fail "-g accepted"

$MEMLIMIT -g >/dev/null 2>&1
test $? -eq 2 && pass "-g without arg rejected" || fail "-g without arg rejected"

run_test "verbose output"
OUTPUT=$($MEMLIMIT -v1 1G -- sleep 2 2>&1)
echo "$OUTPUT" | grep -q 'memlimit:' && pass "verbose prints status" || fail "verbose prints status"
echo "$OUTPUT" | grep -q 'proc'       && pass "verbose shows proc count" || fail "verbose shows proc count"

run_test "peak report"
OUTPUT=$($MEMLIMIT 1G -- true 2>&1)
echo "$OUTPUT" | grep -q 'peak memory' && pass "peak memory reported" || fail "peak memory reported"
echo "$OUTPUT" | grep -q 'peak proc'   && pass "peak procs reported"  || fail "peak procs reported"

run_test "memory limit enforcement"
$MEMLIMIT 50M -- $ALLOC 100M 10 >/dev/null 2>&1
test $? -eq 137 && pass "exit 137 on OOM" || fail "exit 137 on OOM"

run_test "process group count"
OUTPUT=$($MEMLIMIT -v1 1G -- sh -c "$ALLOC 1M 10 & $ALLOC 1M 10 & $ALLOC 1M 10 & sleep 2; wait" 2>&1)
echo "$OUTPUT" | grep -q '\[4 procs\]' \
    && pass "reports 4 procs" || fail "reports 4 procs (got: $(echo "$OUTPUT" | grep procs | head -1))"

run_test "aggregate group memory exceeds limit"
# Each child allocates 40M (well under the 100M limit individually).
# Three children together exceed it. This verifies the limit applies to the
# sum across the process group, not to any single process.
$MEMLIMIT 100M -- sh -c '
    '"$ALLOC"' 40M 30 &
    '"$ALLOC"' 40M 30 &
    '"$ALLOC"' 40M 30 &
    wait
' >/dev/null 2>&1
test $? -eq 137 && pass "aggregate group memory killed" || fail "aggregate group memory killed"

run_test "under-limit process exits normally"
$MEMLIMIT 50M -- $ALLOC 10M 2 >/dev/null 2>&1
test $? -eq 0 && pass "under-limit exits 0" || fail "under-limit exits 0"

run_test "child killed by signal"
# Child sends itself SIGTERM.  memlimit should report 128+15 = 143.
$MEMLIMIT 1G -- sh -c 'kill -TERM $$' >/dev/null 2>&1
test $? -eq 143 && pass "exit 143 for SIGTERM'd child" || fail "exit 143 for SIGTERM'd child (got $?)"

run_test "signal forwarding"
# Send SIGINT to memlimit itself; it should forward to the child group
# and exit 130 (128 + SIGINT=2).
$MEMLIMIT 1G -- sleep 30 >/dev/null 2>&1 &
ML_PID=$!
sleep 1
kill -INT "$ML_PID" 2>/dev/null
wait "$ML_PID" 2>/dev/null
test $? -eq 130 && pass "SIGINT forwarded, exit 130" || fail "SIGINT forwarded, exit 130 (got $?)"

run_test "grace period escalation"
# Child traps SIGTERM and refuses to die.  With -g 1 (1 second grace),
# memlimit should escalate to SIGKILL after the grace period.
# The limit triggers SIGTERM; the trap ignores it; SIGKILL follows.
$MEMLIMIT -g 1 50M -- sh -c '
    trap "" TERM
    '"$ALLOC"' 100M 30
' >/dev/null 2>&1
test $? -eq 137 && pass "SIGKILL after grace period" || fail "SIGKILL after grace period (got $?)"

run_test "missing -- separator"
$MEMLIMIT 1G true >/dev/null 2>&1
test $? -eq 2 && pass "exit 2 for missing --" || fail "exit 2 for missing -- (got $?)"

run_test "no limit specified"
$MEMLIMIT -- true >/dev/null 2>&1
test $? -eq 2 && pass "exit 2 for no limit" || fail "exit 2 for no limit (got $?)"

# ---- Summary ----

TOTAL=$((PASS + FAIL))
echo ""
echo "--- $PASS/$TOTAL passed"
if [ "$FAIL" -gt 0 ]; then
    echo "--- $FAIL FAILED"
    exit 1
fi
exit 0
