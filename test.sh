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

# Helper: run a command, capture its exit code, then assert.
assert_exit() {
    expected="$1"
    label="$2"
    shift 2
    "$@" >/dev/null 2>&1
    rc=$?
    test "$rc" -eq "$expected" && pass "$label" || fail "$label (got $rc)"
}

# ---- Tests ----

run_test "version and help"
$MEMLIMIT --version >/dev/null 2>&1 && pass "--version" || fail "--version"
$MEMLIMIT --help    >/dev/null 2>&1 && pass "--help"    || fail "--help"

run_test "basic success"
$MEMLIMIT 1G -- true >/dev/null 2>&1 && pass "true exits 0" || fail "true exits 0"

run_test "exit code propagation"
assert_exit 42 "exit 42 propagated" $MEMLIMIT 1G -- sh -c 'exit 42'

run_test "command not found"
assert_exit 127 "exit 127 for missing command" $MEMLIMIT 1G -- nonexistent_cmd_xyz

run_test "invalid limit rejected"
assert_exit 2 "exit 2 for negative limit" $MEMLIMIT -1 -- true
assert_exit 2 "exit 2 for zero limit" $MEMLIMIT 0 -- true
assert_exit 2 "exit 2 for trailing garbage" $MEMLIMIT 1Mx -- true

run_test "B suffix accepted"
assert_exit 0 "1048576B accepted" $MEMLIMIT 1048576B -- true

run_test "invalid verbose interval rejected"
assert_exit 2 "exit 2 for -v0" $MEMLIMIT -v0 1G -- true
assert_exit 2 "exit 2 for --verbose=abc" $MEMLIMIT --verbose=abc 1G -- true

run_test "grace flag"
$MEMLIMIT -g 2 1G -- true >/dev/null 2>&1 && pass "-g accepted" || fail "-g accepted"
assert_exit 2 "-g without arg rejected" $MEMLIMIT -g
$MEMLIMIT --grace 2 1G -- true >/dev/null 2>&1 && pass "--grace accepted" || fail "--grace accepted"

run_test "verbose output"
OUTPUT=$($MEMLIMIT -v1 1G -- sleep 2 2>&1)
echo "$OUTPUT" | grep -q 'memlimit:' && pass "verbose prints status" || fail "verbose prints status"
echo "$OUTPUT" | grep -q 'proc'       && pass "verbose shows proc count" || fail "verbose shows proc count"

run_test "peak report"
OUTPUT=$($MEMLIMIT 1G -- true 2>&1)
echo "$OUTPUT" | grep -q 'peak memory' && pass "peak memory reported" || fail "peak memory reported"
echo "$OUTPUT" | grep -q 'peak proc'   && pass "peak procs reported"  || fail "peak procs reported"

run_test "memory limit enforcement"
assert_exit 137 "exit 137 on OOM" $MEMLIMIT 50M -- $ALLOC 100M 10

run_test "process group count"
OUTPUT=$($MEMLIMIT -v1 1G -- sh -c "$ALLOC 1M 10 & $ALLOC 1M 10 & $ALLOC 1M 10 & sleep 2; wait" 2>&1)
echo "$OUTPUT" | grep -q '\[4 procs\]' \
    && pass "reports 4 procs" || fail "reports 4 procs (got: $(echo "$OUTPUT" | grep procs | head -1))"

run_test "aggregate group memory exceeds limit"
# Each child allocates 40M (well under the 100M limit individually).
# Three children together exceed it. This verifies the limit applies to the
# sum across the process group, not to any single process.
assert_exit 137 "aggregate group memory killed" $MEMLIMIT 100M -- sh -c '
    '"$ALLOC"' 40M 30 &
    '"$ALLOC"' 40M 30 &
    '"$ALLOC"' 40M 30 &
    wait
'

run_test "under-limit process exits normally"
assert_exit 0 "under-limit exits 0" $MEMLIMIT 50M -- $ALLOC 10M 2

run_test "child killed by signal"
# Child sends itself SIGTERM.  memlimit should report 128+15 = 143.
assert_exit 143 "exit 143 for SIGTERM'd child" $MEMLIMIT 1G -- sh -c 'kill -TERM $$'

run_test "signal forwarding"
# Send SIGINT to memlimit itself; it should forward to the child group
# and exit 130 (128 + SIGINT=2).
$MEMLIMIT 1G -- sleep 30 >/dev/null 2>&1 &
ML_PID=$!
sleep 1
kill -INT "$ML_PID" 2>/dev/null
wait "$ML_PID" 2>/dev/null
rc=$?
test "$rc" -eq 130 && pass "SIGINT forwarded, exit 130" || fail "SIGINT forwarded, exit 130 (got $rc)"

run_test "grace period escalation"
# Child traps SIGTERM and refuses to die.  With -g 1 (1 second grace),
# memlimit should escalate to SIGKILL after the grace period.
# The limit triggers SIGTERM; the trap ignores it; SIGKILL follows.
assert_exit 137 "SIGKILL after grace period" $MEMLIMIT -g 1 50M -- sh -c '
    trap "" TERM
    '"$ALLOC"' 100M 30
'

run_test "missing -- separator"
assert_exit 2 "exit 2 for missing --" $MEMLIMIT 1G true

run_test "no limit specified"
assert_exit 2 "exit 2 for no limit" $MEMLIMIT -- true

run_test "command passes -- through"
OUTPUT=$($MEMLIMIT 1G -- echo -- hello 2>/dev/null)
test "$OUTPUT" = "-- hello" && pass "-- passed to child" || fail "-- passed to child (got: $OUTPUT)"

run_test "test_alloc rejects invalid sizes"
$ALLOC -1 >/dev/null 2>&1
rc=$?
test "$rc" -ne 0 && pass "test_alloc rejects negative" || fail "test_alloc rejects negative (got $rc)"
$ALLOC 0 >/dev/null 2>&1
rc=$?
test "$rc" -ne 0 && pass "test_alloc rejects zero" || fail "test_alloc rejects zero (got $rc)"

# ---- Summary ----

TOTAL=$((PASS + FAIL))
echo ""
echo "--- $PASS/$TOTAL passed"
if [ "$FAIL" -gt 0 ]; then
    echo "--- $FAIL FAILED"
    exit 1
fi
exit 0
