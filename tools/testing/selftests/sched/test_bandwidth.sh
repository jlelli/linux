#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Bandwidth admission control tests module
# Contains:
# - test_bandwidth_admission_control: Test bandwidth admission control with max allowed bandwidth
# - test_bandwidth_admission_control_overflow: Test bandwidth overflow rejection

test_bandwidth_admission_control() {
    echo "Running test: SCHED_DEADLINE bandwidth admission control"
    
    # Test: Start one cpuhog task per CPU with maximum allowed bandwidth
    local test_name="Bandwidth admission control with max allowed bandwidth per CPU"
    
    # Get current RT bandwidth settings
    local rt_runtime_us=$(cat /proc/sys/kernel/sched_rt_runtime_us 2>/dev/null)
    local rt_period_us=$(cat /proc/sys/kernel/sched_rt_period_us 2>/dev/null)
    
    if [ -z "$rt_runtime_us" ] || [ -z "$rt_period_us" ]; then
        print_test_result "$test_name" "FAIL" "Could not read RT bandwidth settings"
        return 1
    fi
    
    verbose_echo "  RT bandwidth settings: runtime=${rt_runtime_us}µs, period=${rt_period_us}µs"
    
    # Calculate maximum bandwidth ratio and use the full extent
    # Available bandwidth = rt_runtime_us / rt_period_us (typically 95%)
    local max_bandwidth_percent=$((rt_runtime_us * 100 / rt_period_us))
    if [ $max_bandwidth_percent -eq 0 ]; then
        max_bandwidth_percent=1
    fi
    verbose_echo "  Using full available bandwidth: ${max_bandwidth_percent}% per task"
    
    # Calculate task parameters: runtime/period should equal the bandwidth ratio
    # Use 100ms period for easier calculation
    local task_period_us=100000000  # 100ms
    local task_runtime_us=$((task_period_us * max_bandwidth_percent / 100))
    local task_deadline_us=$task_period_us
    
    verbose_echo "  Task parameters: runtime=${task_runtime_us}µs, deadline=${task_deadline_us}µs, period=${task_period_us}µs"
    
    # Get number of online CPUs
    local num_cpus=$(nproc --all)
    verbose_echo "  Number of online CPUs: $num_cpus"
    
    local started_tasks=0
    
    # Start one cpuhog task per CPU
    for ((cpu=0; cpu<num_cpus; cpu++)); do
        verbose_echo "  Starting cpuhog task $((cpu+1))/$num_cpus..."
        
        chrt -d -T $task_runtime_us -D $task_deadline_us -P $task_period_us 0 \
            $CPUHOG_PROG >/dev/null 2>&1 &
	local cpuhog_pid=$!
        
	if kill -0 $cpuhog_pid 2>/dev/null; then
		started_tasks=$((started_tasks + 1))
		verbose_echo "    Task $((cpu+1)) started successfully"
	else
		verbose_echo "    Task $((cpu+1)) failed to start"
		return 1
	fi
    done
    
    # Wait a moment for all tasks to be scheduled
    sleep 1
    
    # Find all cpuhog processes and verify they're using SCHED_DEADLINE
    local running_tasks=0
    local cpuhog_pids=($(pgrep -x cpuhog))
    
    verbose_echo "  Found ${#cpuhog_pids[@]} cpuhog processes"
    
    for cpuhog_pid in "${cpuhog_pids[@]}"; do
        if kill -0 $cpuhog_pid 2>/dev/null; then
            # Verify this cpuhog process is using SCHED_DEADLINE (policy 6)
            local policy=$(cat /proc/$cpuhog_pid/sched 2>/dev/null | grep "policy" | awk '{print $3}')
            if [ "$policy" = "6" ]; then
                running_tasks=$((running_tasks + 1))
                verbose_echo "    cpuhog PID $cpuhog_pid confirmed using SCHED_DEADLINE"
            else
                verbose_echo "    cpuhog PID $cpuhog_pid using policy $policy (not SCHED_DEADLINE)"
            fi
        fi
    done
    
    verbose_echo "  Successfully started $started_tasks/$num_cpus tasks"
    verbose_echo "  Currently running $running_tasks SCHED_DEADLINE tasks"
    
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
    echo "Running test: SCHED_DEADLINE bandwidth admission control overflow rejection"
    
    # Test: Start N-1 cpuhog tasks at max bandwidth, then try to add one more at max+1% (should fail)
    local test_name="Bandwidth admission control rejects overflow"
    
    # Get current RT bandwidth settings
    local rt_runtime_us=$(cat /proc/sys/kernel/sched_rt_runtime_us 2>/dev/null)
    local rt_period_us=$(cat /proc/sys/kernel/sched_rt_period_us 2>/dev/null)
    
    if [ -z "$rt_runtime_us" ] || [ -z "$rt_period_us" ]; then
        print_test_result "$test_name" "FAIL" "Could not read RT bandwidth settings"
        return 1
    fi
    
    verbose_echo "  RT bandwidth settings: runtime=${rt_runtime_us}µs, period=${rt_period_us}µs"
    
    # Calculate maximum bandwidth ratio
    local max_bandwidth_percent=$((rt_runtime_us * 100 / rt_period_us))
    if [ $max_bandwidth_percent -eq 0 ]; then
        max_bandwidth_percent=1
    fi
    verbose_echo "  Using full available bandwidth: ${max_bandwidth_percent}% per task for N-1 tasks"
    
    # Calculate task parameters for maximum per-CPU bandwidth
    local task_period_us=100000000  # 100ms
    local task_runtime_us=$((task_period_us * max_bandwidth_percent / 100))
    local task_deadline_us=$task_period_us
    
    verbose_echo "  Max task parameters: runtime=${task_runtime_us}µs, deadline=${task_deadline_us}µs, period=${task_period_us}µs"
    
    # Get number of online CPUs
    local num_cpus=$(nproc --all)
    verbose_echo "  Number of online CPUs: $num_cpus"
    
    if [ $num_cpus -lt 2 ]; then
        print_test_result "$test_name" "SKIP" "Need at least 2 CPUs for this test"
        return 0
    fi
    
    local started_tasks=0
    local task_pids=()
    
    # Start N-1 cpuhog tasks at maximum per-CPU bandwidth
    local target_tasks=$((num_cpus - 1))
    verbose_echo "  Starting $target_tasks cpuhog tasks at max bandwidth..."
    
    for ((cpu=0; cpu<target_tasks; cpu++)); do
        verbose_echo "  Starting cpuhog task $((cpu+1))/$target_tasks..."
        
        chrt -d -T $task_runtime_us -D $task_deadline_us -P $task_period_us 0 \
            $CPUHOG_PROG >/dev/null 2>&1 &
        local cpuhog_pid=$!
        
        if kill -0 $cpuhog_pid 2>/dev/null; then
            started_tasks=$((started_tasks + 1))
            task_pids+=($cpuhog_pid)
            verbose_echo "    Task $((cpu+1)) started successfully (PID: $cpuhog_pid)"
        else
            verbose_echo "    Task $((cpu+1)) failed to start"
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
    
    verbose_echo "  Successfully started $started_tasks/$target_tasks tasks at max bandwidth"
    
    # Now try to start one additional task at max bandwidth + 1% (should fail)
    local overflow_runtime_us=$((task_runtime_us * 101 / 100))  # Add 1%
    verbose_echo "  Attempting to start overflow task with runtime=${overflow_runtime_us}µs (${max_bandwidth_percent}% + 1%)..."
    
    # This should fail due to bandwidth admission control
    local overflow_failed=0
    if chrt -d -T $overflow_runtime_us -D $task_deadline_us -P $task_period_us 0 \
            $CPUHOG_PROG >/dev/null 2>&1 &
    then
        local overflow_pid=$!
        # Check if it actually started and is running
        sleep 0.5
        if kill -0 $overflow_pid 2>/dev/null; then
            verbose_echo "    ERROR: Overflow task started successfully (should have been rejected)"
            kill $overflow_pid 2>/dev/null || true
            overflow_failed=0
        else
            verbose_echo "    Overflow task was started but died (likely due to bandwidth rejection)"
            overflow_failed=1
        fi
    else
        verbose_echo "    Overflow task correctly rejected by chrt"
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