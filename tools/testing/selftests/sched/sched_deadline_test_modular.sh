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
# 8. SCHED_DEADLINE total_bw tracking with multiple running tasks
#
# MODULAR VERSION - Functionality identical to monolithic script

# Get the directory of this script to source modules
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source common utilities first (contains globals and shared functions)
source "$SCRIPT_DIR/common_utils.sh" || {
    echo "ERROR: Failed to load common_utils.sh"
    exit 1
}

# Source test modules
source "$SCRIPT_DIR/test_basic.sh" || {
    echo "ERROR: Failed to load test_basic.sh"
    exit 1
}

source "$SCRIPT_DIR/test_bandwidth.sh" || {
    echo "ERROR: Failed to load test_bandwidth.sh"
    exit 1
}

source "$SCRIPT_DIR/test_fair_server.sh" || {
    echo "ERROR: Failed to load test_fair_server.sh"
    exit 1
}

source "$SCRIPT_DIR/test_introspection.sh" || {
    echo "ERROR: Failed to load test_introspection.sh"
    exit 1
}

# Main function - orchestrates all tests
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
    
    # Run tests in same order as original script
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
    
    test_dl_bandwidth_tracking_with_multiple_tasks
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