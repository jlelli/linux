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
# 5. Fair_server bandwidth validation respects global RT bandwidth limits
# 6. Fair_server bandwidth increases work when global RT bandwidth is reduced

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

test_bandwidth_admission_control_overflow() {
    echo "Testing SCHED_DEADLINE bandwidth admission control overflow rejection..."
    
    # Test: Start N-1 cpuhog tasks at max bandwidth, then try to add one more at max+1% (should fail)
    local test_name="Bandwidth admission control rejects overflow"
    
    # Get current RT bandwidth settings
    local rt_runtime_us=$(cat /proc/sys/kernel/sched_rt_runtime_us 2>/dev/null)
    local rt_period_us=$(cat /proc/sys/kernel/sched_rt_period_us 2>/dev/null)
    
    if [ -z "$rt_runtime_us" ] || [ -z "$rt_period_us" ]; then
        print_test_result "$test_name" "FAIL" "Could not read RT bandwidth settings"
        return 1
    fi
    
    echo "  RT bandwidth settings: runtime=${rt_runtime_us}µs, period=${rt_period_us}µs"
    
    # Calculate maximum bandwidth ratio
    local max_bandwidth_percent=$((rt_runtime_us * 100 / rt_period_us))
    if [ $max_bandwidth_percent -eq 0 ]; then
        max_bandwidth_percent=1
    fi
    echo "  Using full available bandwidth: ${max_bandwidth_percent}% per task for N-1 tasks"
    
    # Calculate task parameters for maximum per-CPU bandwidth
    local task_period_us=100000000  # 100ms
    local task_runtime_us=$((task_period_us * max_bandwidth_percent / 100))
    local task_deadline_us=$task_period_us
    
    echo "  Max task parameters: runtime=${task_runtime_us}µs, deadline=${task_deadline_us}µs, period=${task_period_us}µs"
    
    # Get number of online CPUs
    local num_cpus=$(nproc --all)
    echo "  Number of online CPUs: $num_cpus"
    
    if [ $num_cpus -lt 2 ]; then
        print_test_result "$test_name" "SKIP" "Need at least 2 CPUs for this test"
        return 0
    fi
    
    local started_tasks=0
    local task_pids=()
    
    # Start N-1 cpuhog tasks at maximum per-CPU bandwidth
    local target_tasks=$((num_cpus - 1))
    echo "  Starting $target_tasks cpuhog tasks at max bandwidth..."
    
    for ((cpu=0; cpu<target_tasks; cpu++)); do
        echo "  Starting cpuhog task $((cpu+1))/$target_tasks..."
        
        chrt -d -T $task_runtime_us -D $task_deadline_us -P $task_period_us 0 \
            $CPUHOG_PROG >/dev/null 2>&1 &
        local cpuhog_pid=$!
        
        if kill -0 $cpuhog_pid 2>/dev/null; then
            started_tasks=$((started_tasks + 1))
            task_pids+=($cpuhog_pid)
            echo "    Task $((cpu+1)) started successfully (PID: $cpuhog_pid)"
        else
            echo "    Task $((cpu+1)) failed to start"
            # Clean up any started tasks
            for pid in "${task_pids[@]}"; do
                kill $pid 2>/dev/null || true
            done
            print_test_result "$test_name" "FAIL" "Failed to start N-1 tasks at max bandwidth"
            return 1
        fi
    done
    
    # Wait a moment for all tasks to be scheduled
    sleep 1
    
    echo "  Successfully started $started_tasks/$target_tasks tasks at max bandwidth"
    
    # Now try to start one additional task at max bandwidth + 1% (should fail)
    local overflow_runtime_us=$((task_runtime_us * 101 / 100))  # Add 1%
    echo "  Attempting to start overflow task with runtime=${overflow_runtime_us}µs (${max_bandwidth_percent}% + 1%)..."
    
    # This should fail due to bandwidth admission control
    local overflow_failed=0
    if chrt -d -T $overflow_runtime_us -D $task_deadline_us -P $task_period_us 0 \
            $CPUHOG_PROG >/dev/null 2>&1 &
    then
        local overflow_pid=$!
        # Check if it actually started and is running
        sleep 0.5
        if kill -0 $overflow_pid 2>/dev/null; then
            echo "    ERROR: Overflow task started successfully (should have been rejected)"
            kill $overflow_pid 2>/dev/null || true
            overflow_failed=0
        else
            echo "    Overflow task was started but died (likely due to bandwidth rejection)"
            overflow_failed=1
        fi
    else
        echo "    Overflow task correctly rejected by chrt"
        overflow_failed=1
    fi
    
    # Clean up background processes
    for pid in "${task_pids[@]}"; do
        kill $pid 2>/dev/null || true
    done
    
    # Wait for cleanup
    sleep 1
    
    # Test passes if:
    # 1. We successfully started N-1 tasks at max bandwidth
    # 2. The overflow task (max bandwidth + 1%) was rejected
    if [ $started_tasks -eq $target_tasks ] && [ $overflow_failed -eq 1 ]; then
        print_test_result "$test_name" "PASS"
    elif [ $started_tasks -ne $target_tasks ]; then
        print_test_result "$test_name" "FAIL" "Only started $started_tasks/$target_tasks base tasks"
        return 1
    else
        print_test_result "$test_name" "FAIL" "Overflow task was accepted when it should have been rejected"
        return 1
    fi
    
    return 0
}

# Helper function to check fair_server interface availability
# Sets global variables: FAIR_SERVER_CPU_DIR, FAIR_SERVER_RUNTIME_FILE, FAIR_SERVER_PERIOD_FILE, FAIR_SERVER_CPU_NUM
# Returns 0 on success, 1 on skip (with message printed)
fair_server_interface_check() {
    local test_name="$1"
    
    # Check if fair_server debugfs interface exists
    local fair_server_dir="/sys/kernel/debug/sched/fair_server"
    if [ ! -d "$fair_server_dir" ]; then
        print_test_result "$test_name" "SKIP" "Fair server debugfs interface not found"
        return 1
    fi
    
    # Find first available CPU
    FAIR_SERVER_CPU_DIR=""
    for cpu_path in "$fair_server_dir"/cpu*; do
        if [ -d "$cpu_path" ]; then
            FAIR_SERVER_CPU_DIR="$cpu_path"
            break
        fi
    done
    
    if [ -z "$FAIR_SERVER_CPU_DIR" ]; then
        print_test_result "$test_name" "SKIP" "No fair server CPU directories found"
        return 1
    fi
    
    FAIR_SERVER_CPU_NUM=$(basename "$FAIR_SERVER_CPU_DIR" | sed 's/cpu//')
    echo "  Testing with CPU $FAIR_SERVER_CPU_NUM"
    
    # Check required files exist
    FAIR_SERVER_RUNTIME_FILE="$FAIR_SERVER_CPU_DIR/runtime"
    FAIR_SERVER_PERIOD_FILE="$FAIR_SERVER_CPU_DIR/period"
    
    if [ ! -f "$FAIR_SERVER_RUNTIME_FILE" ] || [ ! -f "$FAIR_SERVER_PERIOD_FILE" ]; then
        print_test_result "$test_name" "SKIP" "Fair server runtime/period files not found"
        return 1
    fi
    
    return 0
}

# Helper function to read bandwidth settings
# Sets global variables: RT_RUNTIME_US, RT_PERIOD_US, FAIR_RUNTIME_NS, FAIR_PERIOD_NS
# Returns 0 on success, 1 on failure (with message printed)
read_bandwidth_settings() {
    local test_name="$1"
    
    # Get current global RT bandwidth settings
    RT_RUNTIME_US=$(cat /proc/sys/kernel/sched_rt_runtime_us 2>/dev/null)
    RT_PERIOD_US=$(cat /proc/sys/kernel/sched_rt_period_us 2>/dev/null)
    
    if [ -z "$RT_RUNTIME_US" ] || [ -z "$RT_PERIOD_US" ]; then
        print_test_result "$test_name" "FAIL" "Could not read global RT bandwidth settings"
        return 1
    fi
    
    echo "  Global RT bandwidth: runtime=${RT_RUNTIME_US}µs, period=${RT_PERIOD_US}µs"
    
    # Get current fair server settings (in nanoseconds)
    FAIR_RUNTIME_NS=$(cat "$FAIR_SERVER_RUNTIME_FILE" 2>/dev/null)
    FAIR_PERIOD_NS=$(cat "$FAIR_SERVER_PERIOD_FILE" 2>/dev/null)
    
    if [ -z "$FAIR_RUNTIME_NS" ] || [ -z "$FAIR_PERIOD_NS" ]; then
        print_test_result "$test_name" "FAIL" "Could not read current fair server settings"
        return 1
    fi
    
    echo "  Current fair server: runtime=${FAIR_RUNTIME_NS}ns, period=${FAIR_PERIOD_NS}ns"
    return 0
}

# Helper function to calculate available non-RT bandwidth
# Returns available bandwidth in microseconds
calculate_available_bandwidth() {
    echo $((RT_PERIOD_US - RT_RUNTIME_US))
}

test_fair_server_bandwidth_validation() {
    local test_name="Fair server bandwidth validation against global RT bandwidth"
    echo "Running test: $test_name"
    
    # Use helper functions for common setup
    if ! fair_server_interface_check "$test_name"; then
        return 0
    fi
    
    if ! read_bandwidth_settings "$test_name"; then
        return 1
    fi
    
    # Calculate available bandwidth and attempt excessive allocation
    local available_rt_us=$(calculate_available_bandwidth)
    
    if [ $available_rt_us -le 0 ]; then
        print_test_result "$test_name" "SKIP" "No bandwidth available for fair server (RT uses 100%)"
        return 0
    fi
    
    # Convert current period to microseconds for calculation
    local current_period_us=$((FAIR_PERIOD_NS / 1000))
    
    # Try to set fair server runtime to use more than available bandwidth
    # We'll try to use 110% of available bandwidth 
    local excessive_runtime_us=$((available_rt_us * 110 / 100))
    local excessive_runtime_ns=$((excessive_runtime_us * 1000))
    
    # If period is different from RT period, scale accordingly
    if [ $current_period_us -ne $RT_PERIOD_US ]; then
        excessive_runtime_ns=$((excessive_runtime_ns * FAIR_PERIOD_NS / (RT_PERIOD_US * 1000)))
    fi
    
    echo "  Available non-RT bandwidth: ${available_rt_us}µs per ${RT_PERIOD_US}µs period"
    echo "  Attempting to set excessive runtime: ${excessive_runtime_ns}ns (110% of available)"
    
    # Try to write the excessive runtime (this should fail)
    local write_failed=0
    if echo "$excessive_runtime_ns" > "$FAIR_SERVER_RUNTIME_FILE" 2>/dev/null; then
        echo "    ERROR: Write succeeded when it should have failed"
        write_failed=0
        # Try to restore original value
        echo "$FAIR_RUNTIME_NS" > "$FAIR_SERVER_RUNTIME_FILE" 2>/dev/null || true
    else
        echo "    Write correctly rejected"
        write_failed=1
    fi
    
    # Verify the original value is preserved
    local current_runtime_ns=$(cat "$FAIR_SERVER_RUNTIME_FILE" 2>/dev/null)
    local value_preserved=0
    if [ "$current_runtime_ns" = "$FAIR_RUNTIME_NS" ]; then
        echo "    Original runtime value preserved: ${current_runtime_ns}ns"
        value_preserved=1
    else
        echo "    ERROR: Runtime value changed from ${FAIR_RUNTIME_NS}ns to ${current_runtime_ns}ns"
        value_preserved=0
    fi
    
    # Test passes if:
    # 1. The excessive write was rejected
    # 2. The original value was preserved
    if [ $write_failed -eq 1 ] && [ $value_preserved -eq 1 ]; then
        print_test_result "$test_name" "PASS"
    elif [ $write_failed -eq 0 ]; then
        print_test_result "$test_name" "FAIL" "Fair server accepted excessive bandwidth"
        return 1
    else
        print_test_result "$test_name" "FAIL" "Original fair server value not preserved"
        return 1
    fi
    
    return 0
}

test_fair_server_bandwidth_increase_after_rt_reduction() {
    local test_name="Fair server bandwidth increase after reducing global RT bandwidth"
    echo "Running test: $test_name"
    
    # Use helper functions for common setup
    if ! fair_server_interface_check "$test_name"; then
        return 0
    fi
    
    # Check if we can write to RT bandwidth files (need root)
    if [ ! -w /proc/sys/kernel/sched_rt_runtime_us ] || [ ! -w /proc/sys/kernel/sched_rt_period_us ]; then
        print_test_result "$test_name" "SKIP" "Cannot modify global RT bandwidth (need root)"
        return 0
    fi
    
    if ! read_bandwidth_settings "$test_name"; then
        return 1
    fi
    
    # Calculate available bandwidth before modification
    local orig_available_us=$(calculate_available_bandwidth)
    echo "  Original available non-RT bandwidth: ${orig_available_us}µs"
    
    # Reduce RT bandwidth by 10% to create more space for fair_server
    local new_rt_runtime_us=$((RT_RUNTIME_US * 90 / 100))
    local new_available_us=$((RT_PERIOD_US - new_rt_runtime_us))
    local additional_available_us=$((new_available_us - orig_available_us))
    
    echo "  Reducing RT runtime to ${new_rt_runtime_us}µs (90% of original)"
    echo "  New available non-RT bandwidth: ${new_available_us}µs (+${additional_available_us}µs)"
    
    # Set new RT bandwidth
    local rt_change_failed=0
    if ! echo "$new_rt_runtime_us" > /proc/sys/kernel/sched_rt_runtime_us 2>/dev/null; then
        echo "    ERROR: Failed to reduce RT runtime"
        rt_change_failed=1
    fi
    
    if [ $rt_change_failed -eq 1 ]; then
        print_test_result "$test_name" "FAIL" "Could not reduce global RT bandwidth"
        return 1
    fi
    
    # Wait a moment for the change to take effect
    sleep 0.5
    
    # Calculate new fair_server runtime that uses some of the additional bandwidth
    # Use 50% of the additional available bandwidth
    local current_period_us=$((FAIR_PERIOD_NS / 1000))
    local additional_runtime_us=$((additional_available_us * 50 / 100))
    
    # Scale to fair_server period if different from RT period
    if [ $current_period_us -ne $RT_PERIOD_US ]; then
        additional_runtime_us=$((additional_runtime_us * current_period_us / RT_PERIOD_US))
    fi
    
    local new_fair_runtime_ns=$((FAIR_RUNTIME_NS + additional_runtime_us * 1000))
    
    echo "  Attempting to increase fair server runtime by ${additional_runtime_us}µs to ${new_fair_runtime_ns}ns"
    
    # Try to increase fair_server bandwidth (this should succeed)
    local fair_increase_failed=0
    if echo "$new_fair_runtime_ns" > "$FAIR_SERVER_RUNTIME_FILE" 2>/dev/null; then
        echo "    Fair server bandwidth increase accepted"
        fair_increase_failed=0
    else
        echo "    ERROR: Fair server bandwidth increase rejected"
        fair_increase_failed=1
    fi
    
    # Verify the new value was set
    local current_fair_runtime_ns=$(cat "$FAIR_SERVER_RUNTIME_FILE" 2>/dev/null)
    local value_set_correctly=0
    if [ "$current_fair_runtime_ns" = "$new_fair_runtime_ns" ]; then
        echo "    New fair server runtime correctly set: ${current_fair_runtime_ns}ns"
        value_set_correctly=1
    else
        echo "    ERROR: Fair server runtime not set correctly (expected: ${new_fair_runtime_ns}ns, got: ${current_fair_runtime_ns}ns)"
        value_set_correctly=0
    fi
    
    # Restore original settings
    echo "  Restoring original settings..."
    echo "$FAIR_RUNTIME_NS" > "$FAIR_SERVER_RUNTIME_FILE" 2>/dev/null || true
    echo "$RT_RUNTIME_US" > /proc/sys/kernel/sched_rt_runtime_us 2>/dev/null || true
    
    # Wait for restoration to take effect
    sleep 0.5
    
    # Verify restoration
    local restored_rt_runtime=$(cat /proc/sys/kernel/sched_rt_runtime_us 2>/dev/null)
    local restored_fair_runtime=$(cat "$FAIR_SERVER_RUNTIME_FILE" 2>/dev/null)
    
    if [ "$restored_rt_runtime" = "$RT_RUNTIME_US" ] && [ "$restored_fair_runtime" = "$FAIR_RUNTIME_NS" ]; then
        echo "    Original settings successfully restored"
    else
        echo "    WARNING: Failed to fully restore original settings"
        echo "      RT runtime: expected ${RT_RUNTIME_US}, got ${restored_rt_runtime}"
        echo "      Fair runtime: expected ${FAIR_RUNTIME_NS}, got ${restored_fair_runtime}"
    fi
    
    # Test passes if:
    # 1. RT bandwidth reduction succeeded
    # 2. Fair server bandwidth increase was accepted
    # 3. The new value was set correctly
    if [ $rt_change_failed -eq 0 ] && [ $fair_increase_failed -eq 0 ] && [ $value_set_correctly -eq 1 ]; then
        print_test_result "$test_name" "PASS"
    elif [ $rt_change_failed -eq 1 ]; then
        print_test_result "$test_name" "FAIL" "Could not reduce global RT bandwidth"
        return 1
    elif [ $fair_increase_failed -eq 1 ]; then
        print_test_result "$test_name" "FAIL" "Fair server bandwidth increase was rejected when it should have been accepted"
        return 1
    else
        print_test_result "$test_name" "FAIL" "Fair server bandwidth was not set to the correct value"
        return 1
    fi
    
    return 0
}

cleanup() {
    # Kill any remaining cpuhog processes
    pkill -f cpuhog 2>/dev/null || true
    
    # Try to restore default RT bandwidth settings if they were modified
    # Default values: 950000/1000000 (95%)
    if [ -w /proc/sys/kernel/sched_rt_runtime_us ]; then
        echo 950000 > /proc/sys/kernel/sched_rt_runtime_us 2>/dev/null || true
    fi
    if [ -w /proc/sys/kernel/sched_rt_period_us ]; then
        echo 1000000 > /proc/sys/kernel/sched_rt_period_us 2>/dev/null || true
    fi
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
    
    test_bandwidth_admission_control_overflow
    echo
    
    test_fair_server_bandwidth_validation
    echo
    
    test_fair_server_bandwidth_increase_after_rt_reduction
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