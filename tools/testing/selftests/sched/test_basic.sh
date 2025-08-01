#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Basic SCHED_DEADLINE tests module
# Contains:
# - test_basic_deadline_scheduling: Test basic SCHED_DEADLINE policy setup and execution
# - test_deadline_parameter_validation: Test deadline parameter validation (valid/invalid)

test_basic_deadline_scheduling() {
    echo "Running test: Basic SCHED_DEADLINE scheduling"
    
    # Test 1: Schedule cpuhog with SCHED_DEADLINE and run for a short time
    local test_name="Schedule cpuhog with SCHED_DEADLINE"
    
    # Start cpuhog with SCHED_DEADLINE using chrt
    # Format: chrt -d -T runtime -D deadline -P period command
    timeout $((TEST_DURATION + 2)) chrt -d -T ${RUNTIME_US} -D ${DEADLINE_US} -P ${PERIOD_US} 0 \
        $(cpuhog_cmd -t $TEST_DURATION) &
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
    echo "Running test: SCHED_DEADLINE parameter validation"
    
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