#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Fair server bandwidth tests module
# Contains:
# - test_fair_server_bandwidth_validation: Test fair server bandwidth validation against global RT bandwidth
# - test_fair_server_bandwidth_increase_after_rt_reduction: Test fair server bandwidth increase after reducing global RT bandwidth

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
    
    verbose_echo "  Available non-RT bandwidth: ${available_rt_us}µs per ${RT_PERIOD_US}µs period"
    verbose_echo "  Attempting to set excessive runtime: ${excessive_runtime_ns}ns (110% of available)"
    
    # Try to write the excessive runtime (this should fail)
    local write_failed=0
    if echo "$excessive_runtime_ns" > "$FAIR_SERVER_RUNTIME_FILE" 2>/dev/null; then
        verbose_echo "    ERROR: Write succeeded when it should have failed"
        write_failed=0
        # Try to restore original value
        echo "$FAIR_RUNTIME_NS" > "$FAIR_SERVER_RUNTIME_FILE" 2>/dev/null || true
    else
        verbose_echo "    Write correctly rejected"
        write_failed=1
    fi
    
    # Verify the original value is preserved
    local current_runtime_ns=$(cat "$FAIR_SERVER_RUNTIME_FILE" 2>/dev/null)
    local value_preserved=0
    if [ "$current_runtime_ns" = "$FAIR_RUNTIME_NS" ]; then
        verbose_echo "    Original runtime value preserved: ${current_runtime_ns}ns"
        value_preserved=1
    else
        verbose_echo "    ERROR: Runtime value changed from ${FAIR_RUNTIME_NS}ns to ${current_runtime_ns}ns"
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
    verbose_echo "  Original available non-RT bandwidth: ${orig_available_us}µs"
    
    # Reduce RT bandwidth by 10% to create more space for fair_server
    local new_rt_runtime_us=$((RT_RUNTIME_US * 90 / 100))
    local new_available_us=$((RT_PERIOD_US - new_rt_runtime_us))
    local additional_available_us=$((new_available_us - orig_available_us))
    
    verbose_echo "  Reducing RT runtime to ${new_rt_runtime_us}µs (90% of original)"
    verbose_echo "  New available non-RT bandwidth: ${new_available_us}µs (+${additional_available_us}µs)"
    
    # Set new RT bandwidth
    local rt_change_failed=0
    if ! echo "$new_rt_runtime_us" > /proc/sys/kernel/sched_rt_runtime_us 2>/dev/null; then
        verbose_echo "    ERROR: Failed to reduce RT runtime"
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
    
    verbose_echo "  Attempting to increase fair server runtime by ${additional_runtime_us}µs to ${new_fair_runtime_ns}ns"
    
    # Try to increase fair_server bandwidth (this should succeed)
    local fair_increase_failed=0
    if echo "$new_fair_runtime_ns" > "$FAIR_SERVER_RUNTIME_FILE" 2>/dev/null; then
        verbose_echo "    Fair server bandwidth increase accepted"
        fair_increase_failed=0
    else
        verbose_echo "    ERROR: Fair server bandwidth increase rejected"
        fair_increase_failed=1
    fi
    
    # Verify the new value was set
    local current_fair_runtime_ns=$(cat "$FAIR_SERVER_RUNTIME_FILE" 2>/dev/null)
    local value_set_correctly=0
    if [ "$current_fair_runtime_ns" = "$new_fair_runtime_ns" ]; then
        verbose_echo "    New fair server runtime correctly set: ${current_fair_runtime_ns}ns"
        value_set_correctly=1
    else
        verbose_echo "    ERROR: Fair server runtime not set correctly (expected: ${new_fair_runtime_ns}ns, got: ${current_fair_runtime_ns}ns)"
        value_set_correctly=0
    fi
    
    # Restore original settings
    verbose_echo "  Restoring original settings..."
    echo "$FAIR_RUNTIME_NS" > "$FAIR_SERVER_RUNTIME_FILE" 2>/dev/null || true
    echo "$RT_RUNTIME_US" > /proc/sys/kernel/sched_rt_runtime_us 2>/dev/null || true
    
    # Wait for restoration to take effect
    sleep 0.5
    
    # Verify restoration
    local restored_rt_runtime=$(cat /proc/sys/kernel/sched_rt_runtime_us 2>/dev/null)
    local restored_fair_runtime=$(cat "$FAIR_SERVER_RUNTIME_FILE" 2>/dev/null)
    
    if [ "$restored_rt_runtime" = "$RT_RUNTIME_US" ] && [ "$restored_fair_runtime" = "$FAIR_RUNTIME_NS" ]; then
        verbose_echo "    Original settings successfully restored"
    else
        verbose_echo "    WARNING: Failed to fully restore original settings"
        verbose_echo "      RT runtime: expected ${RT_RUNTIME_US}, got ${restored_rt_runtime}"
        verbose_echo "      Fair runtime: expected ${FAIR_RUNTIME_NS}, got ${restored_fair_runtime}"
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