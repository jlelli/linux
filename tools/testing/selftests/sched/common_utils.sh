#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Common utilities and shared functions for SCHED_DEADLINE tests
# This module contains:
# - Global variables and configuration
# - Command line argument parsing
# - Utility functions (result tracking, verbose output, etc.)
# - Prerequisite checks
# - Common helper functions for bandwidth calculations
# - Cleanup functions

CPUHOG_PROG="./cpuhog"
TEST_DURATION=5
RUNTIME_US=50000000    # 50ms runtime
DEADLINE_US=100000000  # 100ms deadline  
PERIOD_US=100000000    # 100ms period

# Verbose mode (disabled by default)
VERBOSE=0

# Test result tracking
PASSED=0
FAILED=0

# Global variables for fair server interface (set by fair_server_interface_check)
FAIR_SERVER_CPU_DIR=""
FAIR_SERVER_RUNTIME_FILE=""
FAIR_SERVER_PERIOD_FILE=""
FAIR_SERVER_CPU_NUM=""

# Global variables for bandwidth settings (set by read_bandwidth_settings)
RT_RUNTIME_US=""
RT_PERIOD_US=""
FAIR_RUNTIME_NS=""
FAIR_PERIOD_NS=""

# Global variable for drgn tool path (set by check_drgn_prerequisites)
DL_BW_TOOL=""

# Usage information
usage() {
    echo "Usage: $0 [options]"
    echo "Options:"
    echo "  -v, --verbose    Enable verbose output (disabled by default)"
    echo "  -h, --help       Show this help message"
    echo
    echo "Default mode shows only test names and PASS/FAIL results."
    echo "Verbose mode shows detailed test execution information."
}

# Parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -v|--verbose)
                VERBOSE=1
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
}

# Call argument parsing with all passed arguments
parse_arguments "$@"

# Verbose echo - only prints if verbose mode is enabled
verbose_echo() {
    if [ $VERBOSE -eq 1 ]; then
        echo "$@"
    fi
}

# Helper function to construct cpuhog command with conditional verbose flag
cpuhog_cmd() {
    local args="$@"
    if [ $VERBOSE -eq 1 ]; then
        echo "$CPUHOG_PROG $args -v"
    else
        echo "$CPUHOG_PROG $args"
    fi
}

print_test_header() {
    echo "======================================"
    echo "SCHED_DEADLINE Basic Functionality Test"
    if [ $VERBOSE -eq 1 ]; then
        echo "Mode: Verbose (detailed output enabled)"
    else
        echo "Mode: Normal (test names and results only)"
        echo "Use -v or --verbose for detailed output"
    fi
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
    verbose_echo "Checking prerequisites..."
    
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
    verbose_echo "  Testing with CPU $FAIR_SERVER_CPU_NUM"
    
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
    
    verbose_echo "  Global RT bandwidth: runtime=${RT_RUNTIME_US}µs, period=${RT_PERIOD_US}µs"
    
    # Get current fair server settings (in nanoseconds)
    FAIR_RUNTIME_NS=$(cat "$FAIR_SERVER_RUNTIME_FILE" 2>/dev/null)
    FAIR_PERIOD_NS=$(cat "$FAIR_SERVER_PERIOD_FILE" 2>/dev/null)
    
    if [ -z "$FAIR_RUNTIME_NS" ] || [ -z "$FAIR_PERIOD_NS" ]; then
        print_test_result "$test_name" "FAIL" "Could not read current fair server settings"
        return 1
    fi
    
    verbose_echo "  Current fair server: runtime=${FAIR_RUNTIME_NS}ns, period=${FAIR_PERIOD_NS}ns"
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
            verbose_echo "        Task PID $pid: runtime=${runtime_ns}ns, period=${period_ns}ns, bandwidth=${task_bandwidth}" >&2
        fi
    done
    
    verbose_echo "        Calculated total bandwidth from $task_count DEADLINE tasks: $total_bandwidth" >&2
    echo $total_bandwidth
}

# Helper function to check drgn prerequisites and find dl_bw_dump.py tool
# Returns: 0 if prerequisites are met, 1 otherwise
# Sets global variable DL_BW_TOOL with the path to dl_bw_dump.py
check_drgn_prerequisites() {
    local test_name="$1"
    
    # Check if drgn is available
    if ! command -v drgn >/dev/null 2>&1; then
        print_test_result "$test_name" "SKIP" "drgn not available"
        return 1
    fi
    
    # Check if dl_bw_dump.py tool exists
    # Try multiple possible locations relative to test execution
    DL_BW_TOOL=""
    local possible_paths=(
        "tools/sched/dl_bw_dump.py"                   # If run from kernel root
        "../../source/tools/sched/dl_bw_dump.py"            # If run from kernel build directory
        "../../../sched/dl_bw_dump.py"                # If run from tools/testing/selftests/sched/
        "../../../../tools/sched/dl_bw_dump.py"       # Alternative path structure
    )
    
    for path in "${possible_paths[@]}"; do
        if [ -f "$path" ]; then
            DL_BW_TOOL="$path"
            break
        fi
    done
    
    if [ -z "$DL_BW_TOOL" ]; then
        print_test_result "$test_name" "SKIP" "dl_bw_dump.py tool not found in expected locations"
        return 1
    fi
    
    verbose_echo "  Found dl_bw_dump.py at: $DL_BW_TOOL"
    
    # Check for sufficient privileges to access kernel memory
    if [ "$(id -u)" -ne 0 ]; then
        print_test_result "$test_name" "SKIP" "Root privileges required for kernel memory access"
        return 1
    fi
    
    return 0
}

# Helper function to generate random but sensible deadline parameters
# Output: "runtime_ns deadline_ns period_ns" where runtime <= deadline <= period
generate_random_deadline_params() {
    # Generate period in range [10ms, 1000ms] (reasonable for testing)
    local period_ms=$((10 + RANDOM % 991))  # 10-1000ms
    local period_ns=$((period_ms * 1000000))
    
    # Generate deadline equal to period (common case)
    local deadline_ns=$period_ns
    
    # Generate runtime as 5-50% of period (realistic workload)
    local runtime_percent=$((5 + RANDOM % 46))  # 5-50%
    local runtime_ns=$(((period_ns * runtime_percent) / 100))
    
    echo "$runtime_ns $deadline_ns $period_ns"
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