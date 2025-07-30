#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Test basic SCHED_DEADLINE functionality by scheduling a cpuhog task
# with deadline scheduling policy using chrt.
#
# This test verifies that:
# 1. SCHED_DEADLINE policy can be set via chrt
# 2. The task runs successfully under SCHED_DEADLINE
# 3. Basic deadline parameters are accepted
# 4. Bandwidth admission control works correctly

CPUHOG_PROG="./cpuhog"
TEST_DURATION=5
RUNTIME_US=50000000    # 50ms runtime
DEADLINE_US=100000000  # 100ms deadline  
PERIOD_US=100000000    # 100ms period

# Test result tracking
PASSED=0
FAILED=0

print_test_header() {
    echo "======================================"
    echo "SCHED_DEADLINE Basic Functionality Test"
    echo "======================================"
    echo
}

print_test_result() {
    local test_name="$1"
    local result="$2"
    local details="$3"
    
    if [ "$result" = "PASS" ]; then
        echo "[$result] $test_name"
        PASSED=$((PASSED + 1))
    else
        echo "[$result] $test_name"
        if [ -n "$details" ]; then
            echo "        Details: $details"
        fi
        FAILED=$((FAILED + 1))
    fi
}

check_prerequisites() {
    echo "Checking prerequisites..."
    
    # Check if cpuhog binary exists
    if [ ! -x "$CPUHOG_PROG" ]; then
        print_test_result "cpuhog binary exists" "FAIL" "Binary not found: $CPUHOG_PROG"
        return 1
    fi
    print_test_result "cpuhog binary exists" "PASS"
    
    # Check if chrt command is available
    if ! command -v chrt >/dev/null 2>&1; then
        print_test_result "chrt command available" "FAIL" "chrt command not found"
        return 1
    fi
    print_test_result "chrt command available" "PASS"
    
    # Check if we're running as root (required for SCHED_DEADLINE)
    if [ "$EUID" -ne 0 ]; then
        print_test_result "root privileges" "FAIL" "SCHED_DEADLINE requires root privileges"
        return 1
    fi
    print_test_result "root privileges" "PASS"
    
    # Check if SCHED_DEADLINE is supported by checking chrt help
    if ! chrt --help 2>&1 | grep -q deadline; then
        print_test_result "SCHED_DEADLINE support in chrt" "FAIL" "chrt doesn't support deadline scheduling"
        return 1
    fi
    print_test_result "SCHED_DEADLINE support in chrt" "PASS"
    
    echo
    return 0
}

test_basic_deadline_scheduling() {
    echo "Testing basic SCHED_DEADLINE scheduling..."
    
    # Test 1: Schedule cpuhog with SCHED_DEADLINE and run for a short time
    local test_name="Schedule cpuhog with SCHED_DEADLINE"
    
    # Start cpuhog with SCHED_DEADLINE using chrt
    # Format: chrt -d -T runtime -D deadline -P period command
    timeout $((TEST_DURATION + 2)) chrt -d -T ${RUNTIME_US} -D ${DEADLINE_US} -P ${PERIOD_US} 0 \
        $CPUHOG_PROG -t $TEST_DURATION -v &
    local timeout_pid=$!
    
    if [ $? -ne 0 ]; then
        print_test_result "$test_name" "FAIL" "Failed to start cpuhog with chrt"
        return 1
    fi
    
    # Wait a moment for the process to start
    sleep 1
    
    # Find the actual cpuhog PID (just match the process name, not full command line)
    local cpuhog_pid=$(pgrep -x cpuhog)
    if [ -z "$cpuhog_pid" ]; then
        print_test_result "$test_name" "FAIL" "Could not find cpuhog process"
        kill $timeout_pid 2>/dev/null
        return 1
    fi
    
    # Check if the process is still running
    if ! kill -0 $cpuhog_pid 2>/dev/null; then
        print_test_result "$test_name" "FAIL" "cpuhog process died unexpectedly"
        return 1
    fi
    
    # Verify the process is using SCHED_DEADLINE (policy 6)
    local sched_policy=$(cat /proc/$cpuhog_pid/sched | grep "policy" | awk '{print $3}' 2>/dev/null)
    if [ "$sched_policy" != "6" ]; then
        print_test_result "$test_name" "FAIL" "Process not using SCHED_DEADLINE (policy=$sched_policy, expected=6)"
        kill $timeout_pid 2>/dev/null
        return 1
    fi
    
    print_test_result "$test_name" "PASS"
    
    # Wait for the timeout process to complete (which includes cpuhog)
    wait $timeout_pid
    local exit_code=$?
    
    # Test 2: Verify process completed successfully
    test_name="cpuhog completes successfully with SCHED_DEADLINE"
    if [ $exit_code -eq 0 ]; then
        print_test_result "$test_name" "PASS"
    else
        print_test_result "$test_name" "FAIL" "cpuhog exited with code $exit_code"
        return 1
    fi
    
    return 0
}

test_deadline_parameter_validation() {
    echo "Testing SCHED_DEADLINE parameter validation..."
    
    # Test 3: Invalid parameters should be rejected
    local test_name="Invalid deadline parameters rejected"
    
    # Try to set invalid deadline parameters (runtime > deadline)
    if timeout 3 chrt -d -T 200000 -D 100000 -P 100000 0 $CPUHOG_PROG -t 1 >/dev/null 2>&1; then
        print_test_result "$test_name" "FAIL" "Invalid parameters were accepted (runtime > deadline)"
        return 1
    else
        print_test_result "$test_name" "PASS"
    fi
    
    # Test 4: Valid parameters should be accepted
    test_name="Valid deadline parameters accepted"
    if timeout 3 chrt -d -T 30000000 -D 100000000 -P 100000000 0 $CPUHOG_PROG -t 1 >/dev/null 2>&1; then
        print_test_result "$test_name" "PASS"
    else
        print_test_result "$test_name" "FAIL" "Valid parameters were rejected"
        return 1
    fi
    
    return 0
}

test_bandwidth_admission_control() {
    echo "Testing SCHED_DEADLINE bandwidth admission control..."
    
    # Test: Start one cpuhog task per CPU with maximum allowed bandwidth
    local test_name="Bandwidth admission control with max allowed bandwidth per CPU"
    
    # Get current RT bandwidth settings
    local rt_runtime_us=$(cat /proc/sys/kernel/sched_rt_runtime_us 2>/dev/null)
    local rt_period_us=$(cat /proc/sys/kernel/sched_rt_period_us 2>/dev/null)
    
    if [ -z "$rt_runtime_us" ] || [ -z "$rt_period_us" ]; then
        print_test_result "$test_name" "FAIL" "Could not read RT bandwidth settings"
        return 1
    fi
    
    echo "  RT bandwidth settings: runtime=${rt_runtime_us}µs, period=${rt_period_us}µs"
    
    # Calculate maximum bandwidth ratio and use the full extent
    # Available bandwidth = rt_runtime_us / rt_period_us (typically 95%)
    local max_bandwidth_percent=$((rt_runtime_us * 100 / rt_period_us))
    if [ $max_bandwidth_percent -eq 0 ]; then
        max_bandwidth_percent=1
    fi
    echo "  Using full available bandwidth: ${max_bandwidth_percent}% per task"
    
    # Calculate task parameters: runtime/period should equal the bandwidth ratio
    # Use 100ms period for easier calculation
    local task_period_us=100000000  # 100ms
    local task_runtime_us=$((task_period_us * max_bandwidth_percent / 100))
    local task_deadline_us=$task_period_us
    
    echo "  Task parameters: runtime=${task_runtime_us}µs, deadline=${task_deadline_us}µs, period=${task_period_us}µs"
    
    # Get number of online CPUs
    local num_cpus=$(nproc --all)
    echo "  Number of online CPUs: $num_cpus"
    
    local started_tasks=0
    
    # Start one cpuhog task per CPU
    for ((cpu=0; cpu<num_cpus; cpu++)); do
        echo "  Starting cpuhog task $((cpu+1))/$num_cpus..."
        
        chrt -d -T $task_runtime_us -D $task_deadline_us -P $task_period_us 0 \
            $CPUHOG_PROG >/dev/null 2>&1 &
	local cpuhog_pid=$!
        
	if kill -0 $cpuhog_pid 2>/dev/null; then
		started_tasks=$((started_tasks + 1))
		echo "    Task $((cpu+1)) started successfully"
	else
		echo "    Task $((cpu+1)) failed to start"
		return 1
	fi
    done
    
    # Wait a moment for all tasks to be scheduled
    sleep 1
    
    # Find all cpuhog processes and verify they're using SCHED_DEADLINE
    local running_tasks=0
    local cpuhog_pids=($(pgrep -x cpuhog))
    
    echo "  Found ${#cpuhog_pids[@]} cpuhog processes"
    
    for cpuhog_pid in "${cpuhog_pids[@]}"; do
        if kill -0 $cpuhog_pid 2>/dev/null; then
            # Verify this cpuhog process is using SCHED_DEADLINE (policy 6)
            local policy=$(cat /proc/$cpuhog_pid/sched 2>/dev/null | grep "policy" | awk '{print $3}')
            if [ "$policy" = "6" ]; then
                running_tasks=$((running_tasks + 1))
                echo "    cpuhog PID $cpuhog_pid confirmed using SCHED_DEADLINE"
            else
                echo "    cpuhog PID $cpuhog_pid using policy $policy (not SCHED_DEADLINE)"
            fi
        fi
    done
    
    echo "  Successfully started $started_tasks/$num_cpus tasks"
    echo "  Currently running $running_tasks SCHED_DEADLINE tasks"
    
    # Clean up background processes (cpuhog processes)
    for pid in "${cpuhog_pids[@]}"; do
        kill $pid 2>/dev/null || true
    done
    
    # Wait for cleanup
    sleep 1
    
    # Test passes if we successfully started the expected number of SCHED_DEADLINE tasks
    # (The bandwidth should be replicated per CPU, so we should be able to run one per CPU)
    if [ $started_tasks -eq $num_cpus ] && [ $running_tasks -eq $num_cpus ]; then
        print_test_result "$test_name" "PASS"
    elif [ $started_tasks -ne $num_cpus ]; then
        print_test_result "$test_name" "FAIL" "Only started $started_tasks/$num_cpus timeout processes"
        return 1
    else
        print_test_result "$test_name" "FAIL" "Started $started_tasks tasks but only $running_tasks are using SCHED_DEADLINE"
        return 1
    fi
    
    return 0
}

cleanup() {
    # Kill any remaining cpuhog processes
    pkill -f cpuhog 2>/dev/null || true
}

main() {
    print_test_header
    
    # Set up cleanup trap
    trap cleanup EXIT
    
    # Run prerequisite checks
    if ! check_prerequisites; then
        echo
        echo "Prerequisites failed. Aborting tests."
        exit 1
    fi
    
    # Run tests
    test_basic_deadline_scheduling
    echo
    
    test_deadline_parameter_validation  
    echo
    
    test_bandwidth_admission_control
    echo
    
    # Print summary
    echo "======================================"
    echo "Test Summary:"
    echo "  PASSED: $PASSED"
    echo "  FAILED: $FAILED"
    echo "======================================"
    
    if [ $FAILED -eq 0 ]; then
        echo "All tests PASSED"
        exit 0
    else
        echo "Some tests FAILED"
        exit 1
    fi
}

# Allow script to be sourced for testing individual functions
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi