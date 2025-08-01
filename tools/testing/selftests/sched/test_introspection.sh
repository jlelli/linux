#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Introspection and bandwidth tracking tests module
# Contains:
# - validate_total_bw_with_drgn: Helper function to run drgn and validate total_bw
# - test_dl_bandwidth_introspection: Test deadline bandwidth introspection via drgn and dl_bw_dump.py
# - test_dl_bandwidth_tracking_with_multiple_tasks: Test SCHED_DEADLINE total_bw tracking with multiple cpuhog tasks

# Helper function to run drgn and validate total_bw
# Input: expected_total_bw (optional, if provided will validate exact match)
# Returns: 0 if validation passes, 1 otherwise
validate_total_bw_with_drgn() {
    local expected_total_bw="$1"
    local validation_failed=0
    
    verbose_echo "  Using drgn to introspect kernel deadline bandwidth information..."
    
    # Run dl_bw_dump.py via drgn and capture output
    local drgn_output=$(drgn "$DL_BW_TOOL" 2>&1)
    local drgn_exit_code=$?
    
    if [ $drgn_exit_code -ne 0 ]; then
        verbose_echo "  ERROR: drgn execution failed: $drgn_output"
        return 1
    fi
    
    local cpu_count=0
    local total_bw_found=0
    
    # Extract total_bw values for each CPU
    while IFS= read -r line; do
        if [[ "$line" =~ "From CPU:" ]]; then
            cpu_count=$((cpu_count + 1))
            local cpu_id=$(echo "$line" | grep -o "CPU: [0-9]*" | cut -d' ' -f2)
            verbose_echo "    Analyzing CPU $cpu_id bandwidth values:"
        elif [[ "$line" =~ total_bw ]]; then
            local total_bw_raw=$(echo "$line" | awk '{print $NF}')
            local total_bw=$(echo "$total_bw_raw" | sed 's/(u[0-9]*)//' | sed 's/[^0-9]//g')
            total_bw_found=$((total_bw_found + 1))
            verbose_echo "      total_bw: $total_bw_raw -> $total_bw (kernel format)"
            
            # Check if there are any SCHED_DEADLINE tasks running and validate total_bw accordingly
            local deadline_tasks=$(ps -eo pid,policy,comm | awk '$2 == "DLN" {count++} END {print count+0}')
            verbose_echo "        Found $deadline_tasks SCHED_DEADLINE tasks in system"
            
            if [ "$deadline_tasks" -eq 0 ]; then
                # No deadline tasks running, total_bw should be 0
                if [ -n "$total_bw" ] && [ "$total_bw" -ne 0 ]; then
                    verbose_echo "        ✗ total_bw should be 0 when no SCHED_DEADLINE tasks are running, got: $total_bw"
                    validation_failed=1
                else
                    verbose_echo "        ✓ total_bw is 0 as expected (no SCHED_DEADLINE tasks running)"
                fi
            else
                # Deadline tasks are running, calculate expected total bandwidth and compare
                verbose_echo "        Calculating expected total bandwidth from $deadline_tasks SCHED_DEADLINE task(s):"
                local calculated_total_bw=$(calculate_deadline_tasks_total_bandwidth)
                
                if [ -n "$total_bw" ] && [ "$total_bw" -gt 0 ]; then
                    verbose_echo "        ✓ total_bw is $total_bw with $deadline_tasks SCHED_DEADLINE tasks running"
                    
                    # If specific expected value was provided, use that, otherwise use calculated
                    local expected_bw="${expected_total_bw:-$calculated_total_bw}"
                    
                    if [ "$expected_bw" -eq "$total_bw" ]; then
                        verbose_echo "        ✓ Expected total bandwidth ($expected_bw) matches kernel total_bw ($total_bw)"
                    else
                        verbose_echo "        ✗ Bandwidth mismatch: expected $expected_bw vs kernel total_bw $total_bw"
                        validation_failed=1
                    fi
                else
                    verbose_echo "        ✗ total_bw is $total_bw but $deadline_tasks SCHED_DEADLINE tasks are running (expected > 0)"
                    validation_failed=1
                fi
            fi
        fi
    done <<< "$drgn_output"
    
    # Validate that we found total_bw information
    if [ $cpu_count -eq 0 ]; then
        verbose_echo "  ERROR: No CPU bandwidth information found in drgn output"
        return 1
    fi
    
    if [ $total_bw_found -eq 0 ]; then
        verbose_echo "  ERROR: No total_bw values found in drgn output"
        return 1
    fi
    
    verbose_echo "  Successfully validated total_bw for $cpu_count CPUs"
    
    return $validation_failed
}

test_dl_bandwidth_introspection() {
    local test_name="Deadline bandwidth introspection via drgn and dl_bw_dump.py"
    echo "Running test: $test_name"
    
    # Check prerequisites using refactored helper
    if ! check_drgn_prerequisites "$test_name"; then
        return 0
    fi
    
    # Read current RT bandwidth settings to compare with kernel values
    if ! read_bandwidth_settings "$test_name"; then
        return 1
    fi
    
    # Calculate expected max_bw from RT settings
    # max_bw should reflect bandwidth available to RT and DEADLINE tasks (sched_rt_runtime_us/sched_rt_period_us)
    local expected_max_bw_kernel=$(runtime_period_to_kernel_bw $((RT_RUNTIME_US * 1000)) $((RT_PERIOD_US * 1000)))
    
    verbose_echo "  Expected max_bw from RT settings: ${RT_RUNTIME_US}µs/${RT_PERIOD_US}µs -> $expected_max_bw_kernel (kernel format)"
    verbose_echo "  Using drgn to introspect kernel deadline bandwidth information..."
    
    # Run dl_bw_dump.py via drgn and capture output
    local drgn_output=$(drgn "$DL_BW_TOOL" 2>&1)
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
            verbose_echo "    Analyzing CPU $cpu_id bandwidth values:"
        elif [[ "$line" =~ running_bw ]]; then
            local running_bw_raw=$(echo "$line" | awk '{print $NF}')
            # Extract numeric value from (u64)value format - remove type annotation first
            local running_bw=$(echo "$running_bw_raw" | sed 's/(u[0-9]*)//' | sed 's/[^0-9]//g')
            bandwidth_values_found=$((bandwidth_values_found + 1))
            verbose_echo "      running_bw: $running_bw_raw -> $running_bw (kernel format)"
            
            # Validate that bandwidth value is reasonable (0 <= bw <= BW_UNIT)
            if [ -n "$running_bw" ] && ([ "$running_bw" -lt 0 ] || [ "$running_bw" -gt 1048576 ]); then
                verbose_echo "      WARNING: running_bw value $running_bw is outside expected range [0, 1048576]"
                validation_failed=1
            fi
            
        elif [[ "$line" =~ this_bw ]]; then
            local this_bw_raw=$(echo "$line" | awk '{print $NF}')
            local this_bw=$(echo "$this_bw_raw" | sed 's/(u[0-9]*)//' | sed 's/[^0-9]//g')
            bandwidth_values_found=$((bandwidth_values_found + 1))
            verbose_echo "      this_bw: $this_bw_raw -> $this_bw (kernel format)"
            
        elif [[ "$line" =~ max_bw ]]; then
            local max_bw_raw=$(echo "$line" | awk '{print $NF}')
            local max_bw=$(echo "$max_bw_raw" | sed 's/(u[0-9]*)//' | sed 's/[^0-9]//g')
            bandwidth_values_found=$((bandwidth_values_found + 1))
            max_bw_comparisons=$((max_bw_comparisons + 1))
            verbose_echo "      max_bw: $max_bw_raw -> $max_bw (kernel format)"
            
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
                    verbose_echo "        ✓ max_bw matches RT settings (diff: $diff, tolerance: $tolerance)"
                else
                    verbose_echo "        ✗ max_bw mismatch: got $max_bw, expected ~$expected_max_bw_kernel (diff: $diff > tolerance: $tolerance)"
                    validation_failed=1
                fi
            fi
            
        elif [[ "$line" =~ total_bw ]]; then
            local total_bw_raw=$(echo "$line" | awk '{print $NF}')
            local total_bw=$(echo "$total_bw_raw" | sed 's/(u[0-9]*)//' | sed 's/[^0-9]//g')
            bandwidth_values_found=$((bandwidth_values_found + 1))
            verbose_echo "      total_bw: $total_bw_raw -> $total_bw (kernel format)"
            
            # Check if there are any SCHED_DEADLINE tasks running and validate total_bw accordingly
            local deadline_tasks=$(ps -eo pid,policy,comm | awk '$2 == "DLN" {count++} END {print count+0}')
            verbose_echo "        Found $deadline_tasks SCHED_DEADLINE tasks in system"
            
            if [ "$deadline_tasks" -eq 0 ]; then
                # No deadline tasks running, total_bw should be 0
                if [ -n "$total_bw" ] && [ "$total_bw" -ne 0 ]; then
                    verbose_echo "        ✗ total_bw should be 0 when no SCHED_DEADLINE tasks are running, got: $total_bw"
                    validation_failed=1
                else
                    verbose_echo "        ✓ total_bw is 0 as expected (no SCHED_DEADLINE tasks running)"
                fi
            else
                # Deadline tasks are running, calculate expected total bandwidth and compare
                echo "        Calculating expected total bandwidth from $deadline_tasks SCHED_DEADLINE task(s):"
                local calculated_total_bw=$(calculate_deadline_tasks_total_bandwidth)
                
                if [ -n "$total_bw" ] && [ "$total_bw" -gt 0 ]; then
                    verbose_echo "        ✓ total_bw is $total_bw with $deadline_tasks SCHED_DEADLINE tasks running"
                    
                    # Compare calculated vs kernel total_bw
                    if [ "$calculated_total_bw" -eq "$total_bw" ]; then
                        verbose_echo "        ✓ Calculated total bandwidth ($calculated_total_bw) matches kernel total_bw ($total_bw)"
                    else
                        verbose_echo "        ✗ Bandwidth mismatch: calculated $calculated_total_bw vs kernel total_bw $total_bw"
                        validation_failed=1
                    fi
                else
                    verbose_echo "        ✗ total_bw is $total_bw but $deadline_tasks SCHED_DEADLINE tasks are running (expected > 0)"
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
    
    verbose_echo "  Successfully retrieved bandwidth information for $cpu_count CPUs"
    verbose_echo "  Found $bandwidth_values_found bandwidth values in kernel format"
    verbose_echo "  Performed $max_bw_comparisons max_bw comparisons with RT bandwidth settings"
    
    # Test bandwidth conversion functions with realistic values
    verbose_echo "  Testing bandwidth conversion functions:"
    
    # Test: 50% bandwidth (0.5 ratio)
    local test_ratio_50=$(decimal_to_kernel_bw 50)  # 50% as percentage
    local expected_50=$((1048576 * 50 / 100))       # 524288
    
    if [ "$test_ratio_50" -eq "$expected_50" ]; then
        verbose_echo "    ✓ 50% ratio conversion: $test_ratio_50 (expected: $expected_50)"
    else
        verbose_echo "    ✗ 50% ratio conversion failed: got $test_ratio_50, expected $expected_50"
        validation_failed=1
    fi
    
    # Test: runtime/period conversion (50ms runtime, 100ms period = 50%)
    local runtime_50ms=$((50 * 1000000))    # 50ms in nanoseconds
    local period_100ms=$((100 * 1000000))   # 100ms in nanoseconds
    local test_rt_period=$(runtime_period_to_kernel_bw $runtime_50ms $period_100ms)
    
    if [ "$test_rt_period" -eq "$expected_50" ]; then
        verbose_echo "    ✓ Runtime/period conversion: $test_rt_period (expected: $expected_50)"
    else
        verbose_echo "    ✗ Runtime/period conversion failed: got $test_rt_period, expected $expected_50"
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

test_dl_bandwidth_tracking_with_multiple_tasks() {
    local test_name="SCHED_DEADLINE total_bw tracking with multiple cpuhog tasks"
    echo "Running test: $test_name"
    
    # Check prerequisites using refactored helper
    if ! check_drgn_prerequisites "$test_name"; then
        return 0
    fi
    
    # Read current bandwidth settings for admission control validation
    if ! read_bandwidth_settings "$test_name"; then
        return 1
    fi
    
    # Calculate available bandwidth for deadline tasks (same pool as RT tasks)
    # DEADLINE tasks share sched_rt_runtime_us/sched_rt_period_us bandwidth with RT tasks
    local available_bw_kernel=$(runtime_period_to_kernel_bw $((RT_RUNTIME_US * 1000)) $((RT_PERIOD_US * 1000)))
    verbose_echo "  Available bandwidth for DEADLINE tasks: ${RT_RUNTIME_US}µs/${RT_PERIOD_US}µs -> $available_bw_kernel (kernel format)"
    
    # Start with baseline: no DEADLINE tasks should mean total_bw = 0
    verbose_echo "  Step 1: Validate baseline (no DEADLINE tasks)"
    if ! validate_total_bw_with_drgn; then
        print_test_result "$test_name" "FAIL" "Baseline validation failed"
        return 1
    fi
    
    # Generate random task parameters for multiple DEADLINE tasks
    local num_tasks=3
    local task_pids=()
    local expected_total_bw=0
    local task_params=()
    
    verbose_echo "  Step 2: Starting $num_tasks SCHED_DEADLINE cpuhog tasks with random parameters"
    
    for i in $(seq 1 $num_tasks); do
        # Generate random but sensible parameters
        local params=$(generate_random_deadline_params)
        local runtime_ns=$(echo "$params" | cut -d' ' -f1)
        local deadline_ns=$(echo "$params" | cut -d' ' -f2)
        local period_ns=$(echo "$params" | cut -d' ' -f3)
        
        # Calculate bandwidth in kernel format for this task
        local task_kernel_bw=$(runtime_period_to_kernel_bw "$runtime_ns" "$period_ns")
        
        # Validate bandwidth admission (ensure we don't exceed available RT/DEADLINE bandwidth)
        local new_total_bw=$((expected_total_bw + task_kernel_bw))
        
        # If this task would exceed available bandwidth, reduce its runtime
        if [ $new_total_bw -gt $available_bw_kernel ]; then
            # Scale down runtime to use at most 80% of remaining bandwidth
            local remaining_bw_kernel=$((available_bw_kernel - expected_total_bw))
            local max_task_bw_kernel=$(((remaining_bw_kernel * 80) / 100))  # 80% of remaining
            
            if [ $max_task_bw_kernel -gt 0 ] && [ $max_task_bw_kernel -lt $task_kernel_bw ]; then
                # Calculate new runtime that would give us the max allowed bandwidth
                # max_task_bw_kernel = (runtime_ns * BW_UNIT) / period_ns
                # runtime_ns = (max_task_bw_kernel * period_ns) / BW_UNIT
                local new_runtime_ns=$(((max_task_bw_kernel * period_ns) / 1048576))
                if [ $new_runtime_ns -gt 0 ] && [ $new_runtime_ns -lt $runtime_ns ]; then
                    runtime_ns=$new_runtime_ns
                    # Recalculate bandwidth based on actual runtime to avoid approximation issues
                    task_kernel_bw=$(runtime_period_to_kernel_bw "$runtime_ns" "$period_ns")
                    verbose_echo "    Reduced task $i runtime to ${runtime_ns}ns to fit available bandwidth"
                else
                    verbose_echo "    Skipping task $i: insufficient remaining bandwidth"
                    continue
                fi
            else
                verbose_echo "    Skipping task $i: insufficient remaining bandwidth"
                continue
            fi
        fi
        
        expected_total_bw=$((expected_total_bw + task_kernel_bw))
        
        verbose_echo "    Starting task $i: runtime=${runtime_ns}ns, deadline=${deadline_ns}ns, period=${period_ns}ns"
        verbose_echo "      -> Bandwidth: $task_kernel_bw (kernel format)"
        
        # Start the DEADLINE task
        chrt -d -T "$runtime_ns" -D "$deadline_ns" -P "$period_ns" 0 $CPUHOG_PROG &
        local task_pid=$!
        
        if [ $? -eq 0 ]; then
            task_pids+=("$task_pid")
            task_params+=("$runtime_ns $deadline_ns $period_ns $task_kernel_bw")
            verbose_echo "      -> Started with PID: $task_pid"
        else
            verbose_echo "      -> ERROR: Failed to start task $i"
            expected_total_bw=$((expected_total_bw - task_kernel_bw))
        fi
        
        # Small delay to ensure task startup
        sleep 0.5
    done
    
    local actual_tasks=${#task_pids[@]}
    verbose_echo "  Successfully started $actual_tasks SCHED_DEADLINE tasks"
    verbose_echo "  Expected total bandwidth: $expected_total_bw (kernel format)"
    
    if [ $actual_tasks -eq 0 ]; then
        print_test_result "$test_name" "SKIP" "No DEADLINE tasks could be started"
        return 0
    fi
    
    # Allow tasks to settle and be accounted in bandwidth tracking
    verbose_echo "  Step 3: Allowing tasks to settle (2 seconds)..."
    sleep 2
    
    # Validate total_bw tracking with running tasks
    verbose_echo "  Step 4: Validating total_bw tracking with $actual_tasks running tasks"
    local validation_result=0
    if ! validate_total_bw_with_drgn "$expected_total_bw"; then
        validation_result=1
    fi
    
    # Clean up tasks
    verbose_echo "  Step 5: Cleaning up DEADLINE tasks"
    for pid in "${task_pids[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            verbose_echo "    Terminated task PID: $pid"
        fi
    done
    
    # Wait for tasks to fully terminate and bandwidth to be released
    verbose_echo "  Step 6: Waiting for bandwidth release (2 seconds)..."
    sleep 2
    
    # Validate that total_bw returns to 0 after cleanup
    verbose_echo "  Step 7: Validating total_bw cleanup (should return to 0)"
    if ! validate_total_bw_with_drgn; then
        validation_result=1
    fi
    
    # Test passes if:
    # 1. Baseline validation passed (total_bw = 0 with no tasks)
    # 2. total_bw correctly tracked running tasks' bandwidth
    # 3. total_bw returned to 0 after task cleanup
    if [ $validation_result -eq 0 ]; then
        print_test_result "$test_name" "PASS"
        verbose_echo "  ✓ total_bw tracking validated through complete lifecycle"
        verbose_echo "  ✓ Started $actual_tasks tasks with total bandwidth: $expected_total_bw"
        verbose_echo "  ✓ Bandwidth properly released after task termination"
    else
        print_test_result "$test_name" "FAIL" "total_bw tracking validation failed"
        return 1
    fi
    
    return 0
}
