#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Run SCHED_DEADLINE demotion tests with ftrace enabled to see
# state machine transitions

TRACE_DIR="/sys/kernel/debug/tracing"
TEST_BIN="./dl_demotion_test"

if [ ! -d "$TRACE_DIR" ]; then
	echo "ERROR: ftrace not available at $TRACE_DIR"
	echo "Make sure debugfs is mounted and CONFIG_FTRACE is enabled"
	exit 1
fi

if [ $EUID -ne 0 ]; then
	echo "ERROR: This script must be run as root"
	exit 1
fi

if [ ! -x "$TEST_BIN" ]; then
	echo "ERROR: Test binary not found: $TEST_BIN"
	echo "Build with: make"
	exit 1
fi

echo "Setting up ftrace..."

# Clear previous trace
echo 0 > "$TRACE_DIR/tracing_on"
echo > "$TRACE_DIR/trace"

# Enable trace_printk
echo 1 > "$TRACE_DIR/options/trace_printk" 2>/dev/null || true

# Enable sched events
echo 1 > "$TRACE_DIR/events/sched/enable" 2>/dev/null || true

# Start tracing
echo 1 > "$TRACE_DIR/tracing_on"

echo "Running deadline demotion tests..."
echo "===================================="
echo ""

# Run the test
$TEST_BIN

echo ""
echo "===================================="
echo ""

# Stop tracing
echo 0 > "$TRACE_DIR/tracing_on"

# Show relevant trace entries
echo "Trace output (demotion/promotion events):"
echo "=========================================="
grep -E "dl_demote|dl_promote|dl_timer|switched_from_dl|switched_to_dl|setscheduler" \
	"$TRACE_DIR/trace" | tail -100

echo ""
echo "Full trace saved to: /tmp/dl_demotion_trace.txt"
cat "$TRACE_DIR/trace" > /tmp/dl_demotion_trace.txt

# Reset tracing
echo 0 > "$TRACE_DIR/events/sched/enable" 2>/dev/null || true
echo > "$TRACE_DIR/trace"

echo ""
echo "Done!"
