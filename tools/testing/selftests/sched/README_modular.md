# SCHED_DEADLINE Test Suite - Modular Structure

This document describes the modular structure of the SCHED_DEADLINE test suite.

## File Structure

### Main Entry Point
- **`sched_deadline_test_modular.sh`** - Main script that orchestrates all tests
  - Maintains the same command-line interface as the original
  - Sources all modules and runs tests in the same order
  - Integrated with kselftest framework (referenced in Makefile)

### Modules

1. **`common_utils.sh`** - Common utilities and shared functions
   - Global variables and configuration
   - Command line argument parsing
   - Utility functions (verbose output, result tracking)
   - Prerequisite checks
   - Helper functions for bandwidth calculations
   - Cleanup functions

2. **`test_basic.sh`** - Basic SCHED_DEADLINE tests
   - `test_basic_deadline_scheduling()` - Test basic SCHED_DEADLINE policy setup
   - `test_deadline_parameter_validation()` - Test parameter validation

3. **`test_bandwidth.sh`** - Bandwidth admission control tests
   - `test_bandwidth_admission_control()` - Test max bandwidth per CPU
   - `test_bandwidth_admission_control_overflow()` - Test overflow rejection

4. **`test_fair_server.sh`** - Fair server bandwidth tests
   - `test_fair_server_bandwidth_validation()` - Test against global RT bandwidth
   - `test_fair_server_bandwidth_increase_after_rt_reduction()` - Test bandwidth increase

5. **`test_introspection.sh`** - Introspection and bandwidth tracking tests
   - `validate_total_bw_with_drgn()` - Helper for drgn validation
   - `test_dl_bandwidth_introspection()` - Test drgn introspection
   - `test_dl_bandwidth_tracking_with_multiple_tasks()` - Test multi-task tracking

## Usage

The modular version maintains the exact same interface as the original:

```bash
# Run all tests (normal mode)
./sched_deadline_test_modular.sh

# Run with verbose output
./sched_deadline_test_modular.sh -v

# Show help
./sched_deadline_test_modular.sh -h
```

## Integration with kselftest

The modular version is fully integrated with the kselftest framework. The main
test script is listed in `TEST_PROGS` and all module files are listed in
`TEST_FILES` in the Makefile to ensure they are copied to the build directory:

```makefile
TEST_PROGS := cs_prctl_test sched_deadline_test_modular.sh
TEST_FILES := common_utils.sh test_basic.sh test_bandwidth.sh test_fair_server.sh test_introspection.sh
```

Run from kselftest framework:

```bash
# Run from kselftest framework
make -C tools/testing/selftests/sched run_tests

# Run from sources build directory
make TARGETS=sched kselftest

# Run specific test
make -C tools/testing/selftests/sched TEST_PROGS=sched_deadline_test_modular.sh run_tests
```