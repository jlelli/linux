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
# 7. Deadline bandwidth introspection via drgn and kernel memory access

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

# Helper function to convert percentage to kernel format
# Input: percentage (e.g., 50 for 50%)
# Output: kernel format bandwidth (percentage * 2^20 / 100)
# Based on kernel's BW_SHIFT=20 and BW_UNIT=(1<<BW_SHIFT)
decimal_to_kernel_bw() {
    local percentage="$1"
    
    # Scale percentage by 2^20 and divide by 100
    local kernel_bw=$(((1048576 * percentage) / 100))  # 1048576 = 2^20
    
    echo $kernel_bw
}

# Helper function to convert runtime/period to kernel bandwidth format
# Input: runtime_ns period_ns
# Output: kernel format bandwidth ((runtime << 20) / period)
runtime_period_to_kernel_bw() {
    local runtime_ns="$1"
    local period_ns="$2"
    
    if [ "$period_ns" -eq 0 ]; then
        echo 0
        return
    fi
    
    # Calculate (runtime << 20) / period
    # Using bc for 64-bit arithmetic to avoid overflow
    local kernel_bw=$(echo "scale=0; ($runtime_ns * 1048576) / $period_ns" | bc 2>/dev/null)
    
    if [ -z "$kernel_bw" ]; then
        # Fallback if bc is not available - use simpler calculation
        # This may lose precision for very large values
        kernel_bw=$(((runtime_ns * 1048576) / period_ns))
    fi
    
    echo $kernel_bw
}

# Helper function to calculate total bandwidth of all running SCHED_DEADLINE tasks
# Output: total bandwidth in kernel format (sum of all DEADLINE tasks' runtime/period)
# Returns 0 if no DEADLINE tasks are running or if unable to parse any task
calculate_deadline_tasks_total_bandwidth() {
    local total_bandwidth=0
    local task_count=0
    
    # Find all SCHED_DEADLINE tasks (policy DLN)
    local deadline_pids=$(ps -eo pid,policy | awk '$2 == "DLN" {print $1}' | grep -v PID)
    
    if [ -z "$deadline_pids" ]; then
        echo 0
        return 0
    fi
    
    # For each DEADLINE task, get its parameters and calculate bandwidth
    for pid in $deadline_pids; do
        # Use chrt to get deadline parameters
        local chrt_output=$(chrt -p "$pid" 2>/dev/null)
        
        if [ $? -ne 0 ]; then
            # Task might have exited, skip it
            continue
        fi
        
        # Parse runtime and period from chrt output
        # Expected format: "pid X's current runtime/deadline/period in ns: RUNTIME/DEADLINE/PERIOD"
        local params=$(echo "$chrt_output" | grep "runtime/deadline/period" | sed 's/.*: //')
        
        if [ -z "$params" ]; then
            continue
        fi
        
        # Extract runtime and period (format: runtime/deadline/period)
        local runtime_ns=$(echo "$params" | cut -d'/' -f1)
        local period_ns=$(echo "$params" | cut -d'/' -f3)
        
        # Validate that we got numeric values
        if ! echo "$runtime_ns" | grep -q '^[0-9]\+$' || ! echo "$period_ns" | grep -q '^[0-9]\+$'; then
            continue
        fi
        
        # Calculate bandwidth for this task using existing helper
        local task_bandwidth=$(runtime_period_to_kernel_bw "$runtime_ns" "$period_ns")
        
        if [ -n "$task_bandwidth" ] && [ "$task_bandwidth" -gt 0 ]; then
            total_bandwidth=$((total_bandwidth + task_bandwidth))
            task_count=$((task_count + 1))
            echo "        Task PID $pid: runtime=${runtime_ns}ns, period=${period_ns}ns, bandwidth=${task_bandwidth}" >&2
        fi
    done
    
    echo "        Calculated total bandwidth from $task_count DEADLINE tasks: $total_bandwidth" >&2
    echo $total_bandwidth
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

test_dl_bandwidth_introspection() {
    local test_name="Deadline bandwidth introspection via drgn and dl_bw_dump.py"
    echo "Running test: $test_name"
    
    # Check if drgn is available
    if ! command -v drgn >/dev/null 2>&1; then
        print_test_result "$test_name" "SKIP" "drgn not available"
        return 0
    fi
    
    # Check if dl_bw_dump.py tool exists
    # Try multiple possible locations relative to test execution
    local dl_bw_tool=""
    local possible_paths=(
        "tools/sched/dl_bw_dump.py"                   # If run from kernel root
        "../../source/tools/sched/dl_bw_dump.py"            # If run from kernel build directory
        "../../../sched/dl_bw_dump.py"                # If run from tools/testing/selftests/sched/
        "../../../../tools/sched/dl_bw_dump.py"       # Alternative path structure
    )
    
    for path in "${possible_paths[@]}"; do
        if [ -f "$path" ]; then
            dl_bw_tool="$path"
            break
        fi
    done
    
    if [ -z "$dl_bw_tool" ]; then
        print_test_result "$test_name" "SKIP" "dl_bw_dump.py tool not found in expected locations"
        return 0
    fi
    
    echo "  Found dl_bw_dump.py at: $dl_bw_tool"
    
    # Check for sufficient privileges to access kernel memory
    if [ "$(id -u)" -ne 0 ]; then
        print_test_result "$test_name" "SKIP" "Root privileges required for kernel memory access"
        return 0
    fi
    
    # Read current RT bandwidth settings to compare with kernel values
    if ! read_bandwidth_settings "$test_name"; then
        return 1
    fi
    
    # Calculate expected max_bw from RT settings
    # max_bw should reflect bandwidth available to RT and DEADLINE tasks (sched_rt_runtime_us/sched_rt_period_us)
    local expected_max_bw_kernel=$(runtime_period_to_kernel_bw $((RT_RUNTIME_US * 1000)) $((RT_PERIOD_US * 1000)))
    
    echo "  Expected max_bw from RT settings: ${RT_RUNTIME_US}µs/${RT_PERIOD_US}µs -> $expected_max_bw_kernel (kernel format)"
    echo "  Using drgn to introspect kernel deadline bandwidth information..."
    
    # Run dl_bw_dump.py via drgn and capture output
    local drgn_output=$(drgn "$dl_bw_tool" 2>&1)
    local drgn_exit_code=$?
    
    if [ $drgn_exit_code -ne 0 ]; then
        print_test_result "$test_name" "FAIL" "drgn execution failed: $drgn_output"
        return 1
    fi
    
    # Parse and validate the output
    local validation_failed=0
    local cpu_count=0
    local bandwidth_values_found=0
    local max_bw_comparisons=0
    
    # Extract bandwidth values for each CPU
    while IFS= read -r line; do
        if [[ "$line" =~ "From CPU:" ]]; then
            cpu_count=$((cpu_count + 1))
            local cpu_id=$(echo "$line" | grep -o "CPU: [0-9]*" | cut -d' ' -f2)
            echo "    Analyzing CPU $cpu_id bandwidth values:"
        elif [[ "$line" =~ running_bw ]]; then
            local running_bw_raw=$(echo "$line" | awk '{print $NF}')
            # Extract numeric value from (u64)value format - remove type annotation first
            local running_bw=$(echo "$running_bw_raw" | sed 's/(u[0-9]*)//' | sed 's/[^0-9]//g')
            bandwidth_values_found=$((bandwidth_values_found + 1))
            echo "      running_bw: $running_bw_raw -> $running_bw (kernel format)"
            
            # Validate that bandwidth value is reasonable (0 <= bw <= BW_UNIT)
            if [ -n "$running_bw" ] && ([ "$running_bw" -lt 0 ] || [ "$running_bw" -gt 1048576 ]); then
                echo "      WARNING: running_bw value $running_bw is outside expected range [0, 1048576]"
                validation_failed=1
            fi
            
        elif [[ "$line" =~ this_bw ]]; then
            local this_bw_raw=$(echo "$line" | awk '{print $NF}')
            local this_bw=$(echo "$this_bw_raw" | sed 's/(u[0-9]*)//' | sed 's/[^0-9]//g')
            bandwidth_values_found=$((bandwidth_values_found + 1))
            echo "      this_bw: $this_bw_raw -> $this_bw (kernel format)"
            
        elif [[ "$line" =~ max_bw ]]; then
            local max_bw_raw=$(echo "$line" | awk '{print $NF}')
            local max_bw=$(echo "$max_bw_raw" | sed 's/(u[0-9]*)//' | sed 's/[^0-9]//g')
            bandwidth_values_found=$((bandwidth_values_found + 1))
            max_bw_comparisons=$((max_bw_comparisons + 1))
            echo "      max_bw: $max_bw_raw -> $max_bw (kernel format)"
            
            # Compare with expected max_bw from RT settings
            if [ -n "$max_bw" ] && [ -n "$expected_max_bw_kernel" ]; then
                local tolerance=$((expected_max_bw_kernel / 10))  # Allow 10% tolerance
                local diff
                if [ $max_bw -gt $expected_max_bw_kernel ]; then
                    diff=$((max_bw - expected_max_bw_kernel))
                else
                    diff=$((expected_max_bw_kernel - max_bw))
                fi
                
                if [ $diff -le $tolerance ]; then
                    echo "        ✓ max_bw matches RT settings (diff: $diff, tolerance: $tolerance)"
                else
                    echo "        ✗ max_bw mismatch: got $max_bw, expected ~$expected_max_bw_kernel (diff: $diff > tolerance: $tolerance)"
                    validation_failed=1
                fi
            fi
            
        elif [[ "$line" =~ total_bw ]]; then
            local total_bw_raw=$(echo "$line" | awk '{print $NF}')
            local total_bw=$(echo "$total_bw_raw" | sed 's/(u[0-9]*)//' | sed 's/[^0-9]//g')
            bandwidth_values_found=$((bandwidth_values_found + 1))
            echo "      total_bw: $total_bw_raw -> $total_bw (kernel format)"
            
            # Check if there are any SCHED_DEADLINE tasks running and validate total_bw accordingly
            local deadline_tasks=$(ps -eo pid,policy,comm | awk '$2 == "DLN" {count++} END {print count+0}')
            echo "        Found $deadline_tasks SCHED_DEADLINE tasks in system"
            
            if [ "$deadline_tasks" -eq 0 ]; then
                # No deadline tasks running, total_bw should be 0
                if [ -n "$total_bw" ] && [ "$total_bw" -ne 0 ]; then
                    echo "        ✗ total_bw should be 0 when no SCHED_DEADLINE tasks are running, got: $total_bw"
                    validation_failed=1
                else
                    echo "        ✓ total_bw is 0 as expected (no SCHED_DEADLINE tasks running)"
                fi
            else
                # Deadline tasks are running, calculate expected total bandwidth and compare
                echo "        Calculating expected total bandwidth from $deadline_tasks SCHED_DEADLINE task(s):"
                local calculated_total_bw=$(calculate_deadline_tasks_total_bandwidth)
                
                if [ -n "$total_bw" ] && [ "$total_bw" -gt 0 ]; then
                    echo "        ✓ total_bw is $total_bw with $deadline_tasks SCHED_DEADLINE tasks running"
                    
                    # Compare calculated vs kernel total_bw
                    if [ "$calculated_total_bw" -eq "$total_bw" ]; then
                        echo "        ✓ Calculated total bandwidth ($calculated_total_bw) matches kernel total_bw ($total_bw)"
                    else
                        echo "        ✗ Bandwidth mismatch: calculated $calculated_total_bw vs kernel total_bw $total_bw"
                        validation_failed=1
                    fi
                else
                    echo "        ✗ total_bw is $total_bw but $deadline_tasks SCHED_DEADLINE tasks are running (expected > 0)"
                    validation_failed=1
                fi
            fi
        fi
    done <<< "$drgn_output"
    
    # Validate that we found bandwidth information
    if [ $cpu_count -eq 0 ]; then
        print_test_result "$test_name" "FAIL" "No CPU bandwidth information found in drgn output"
        return 1
    fi
    
    if [ $bandwidth_values_found -eq 0 ]; then
        print_test_result "$test_name" "FAIL" "No bandwidth values found in drgn output"
        return 1
    fi
    
    echo "  Successfully retrieved bandwidth information for $cpu_count CPUs"
    echo "  Found $bandwidth_values_found bandwidth values in kernel format"
    echo "  Performed $max_bw_comparisons max_bw comparisons with RT bandwidth settings"
    
    # Test bandwidth conversion functions with realistic values
    echo "  Testing bandwidth conversion functions:"
    
    # Test: 50% bandwidth (0.5 ratio)
    local test_ratio_50=$(decimal_to_kernel_bw 50)  # 50% as percentage
    local expected_50=$((1048576 * 50 / 100))       # 524288
    
    if [ "$test_ratio_50" -eq "$expected_50" ]; then
        echo "    ✓ 50% ratio conversion: $test_ratio_50 (expected: $expected_50)"
    else
        echo "    ✗ 50% ratio conversion failed: got $test_ratio_50, expected $expected_50"
        validation_failed=1
    fi
    
    # Test: runtime/period conversion (50ms runtime, 100ms period = 50%)
    local runtime_50ms=$((50 * 1000000))    # 50ms in nanoseconds
    local period_100ms=$((100 * 1000000))   # 100ms in nanoseconds
    local test_rt_period=$(runtime_period_to_kernel_bw $runtime_50ms $period_100ms)
    
    if [ "$test_rt_period" -eq "$expected_50" ]; then
        echo "    ✓ Runtime/period conversion: $test_rt_period (expected: $expected_50)"
    else
        echo "    ✗ Runtime/period conversion failed: got $test_rt_period, expected $expected_50"
        validation_failed=1
    fi
    
    # Test passes if:
    # 1. drgn executed successfully
    # 2. Bandwidth information was retrieved for at least one CPU
    # 3. Bandwidth values are within reasonable ranges
    # 4. max_bw values match RT bandwidth settings (within tolerance)
    # 5. Conversion functions work correctly
    if [ $validation_failed -eq 0 ]; then
        print_test_result "$test_name" "PASS"
    else
        print_test_result "$test_name" "FAIL" "Bandwidth validation, RT setting comparison, or conversion tests failed"
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
    
    test_dl_bandwidth_introspection
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