// SPDX-License-Identifier: GPL-2.0
/*
 * Basic SCHED_DEADLINE functionality tests
 *
 * Validates fundamental SCHED_DEADLINE scheduler operations including
 * policy setup, parameter validation, and basic task execution.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <sched.h>
#include "dl_test.h"
#include "dl_util.h"

/*
 * Test: Basic SCHED_DEADLINE scheduling
 *
 * Verifies that a task can be successfully scheduled with SCHED_DEADLINE
 * policy and executes correctly.
 */
static enum dl_test_status test_basic_scheduling_run(void *ctx)
{
	pid_t pid;
	int policy;
	int status;
	uint64_t runtime_ns, deadline_ns, period_ns;

	/* Use reasonable deadline parameters: 30ms/100ms/100ms */
	runtime_ns = dl_ms_to_ns(30);
	deadline_ns = dl_ms_to_ns(100);
	period_ns = dl_ms_to_ns(100);

	/* Create a cpuhog process with SCHED_DEADLINE */
	pid = dl_create_cpuhog(runtime_ns, deadline_ns, period_ns, 2);
	DL_FAIL_IF(pid < 0, "Failed to create cpuhog process: %s",
		   strerror(errno));

	/* Process is now running with SCHED_DEADLINE set */
	printf("  Created cpuhog with SCHED_DEADLINE (PID %d)\n", pid);

	/* Verify it's using SCHED_DEADLINE (policy 6) */
	policy = dl_get_policy(pid);
	DL_FAIL_IF(policy < 0, "Failed to read scheduling policy");
	DL_EQ(policy, SCHED_DEADLINE);

	/* Alternative check using helper */
	DL_ASSERT(dl_is_deadline_task(pid));

	printf("  cpuhog running with SCHED_DEADLINE (PID %d)\n", pid);

	/* Wait for cpuhog to complete (2 seconds) */
	if (waitpid(pid, &status, 0) < 0) {
		dl_cleanup_cpuhog(pid);
		DL_FAIL("waitpid failed: %s", strerror(errno));
	}

	/* Verify it exited successfully */
	DL_FAIL_IF(!WIFEXITED(status), "Process did not exit normally");
	DL_EQ(WEXITSTATUS(status), 0);

	printf("  cpuhog completed successfully\n");

	return DL_TEST_PASS;
}

static struct dl_test test_basic_scheduling = {
	.name = "basic_scheduling",
	.description = "Verify basic SCHED_DEADLINE policy setup and execution",
	.run = test_basic_scheduling_run,
};
REGISTER_DL_TEST(&test_basic_scheduling);

/*
 * Test: SCHED_DEADLINE parameter validation
 *
 * Verifies that the kernel correctly validates deadline parameters,
 * rejecting invalid configurations and accepting valid ones.
 */
static enum dl_test_status test_parameter_validation_run(void *ctx)
{
	int ret;
	uint64_t runtime_ns, deadline_ns, period_ns;

	printf("  Testing invalid parameters (runtime > deadline)...\n");

	/* Invalid: runtime (200ms) > deadline (100ms) */
	runtime_ns = dl_ms_to_ns(200);
	deadline_ns = dl_ms_to_ns(100);
	period_ns = dl_ms_to_ns(100);

	ret = dl_set_sched_attr(0, runtime_ns, deadline_ns, period_ns);
	DL_FAIL_IF(ret == 0, "Invalid parameters were accepted (runtime > deadline)");
	DL_FAIL_IF(errno != EINVAL, "Expected EINVAL, got %s", strerror(errno));

	printf("  Invalid parameters correctly rejected with EINVAL\n");

	printf("  Testing valid parameters...\n");

	/* Valid: runtime (30ms) <= deadline (100ms) <= period (100ms) */
	runtime_ns = dl_ms_to_ns(30);
	deadline_ns = dl_ms_to_ns(100);
	period_ns = dl_ms_to_ns(100);

	ret = dl_set_sched_attr(0, runtime_ns, deadline_ns, period_ns);
	DL_FAIL_IF(ret < 0, "Valid parameters were rejected: %s", strerror(errno));

	printf("  Valid parameters correctly accepted\n");

	/* Reset to normal scheduling using sched_setscheduler */
	struct sched_param param = { .sched_priority = 0 };

	sched_setscheduler(0, SCHED_OTHER, &param);

	return DL_TEST_PASS;
}

static struct dl_test test_parameter_validation = {
	.name = "parameter_validation",
	.description = "Verify SCHED_DEADLINE parameter validation (accept/reject)",
	.run = test_parameter_validation_run,
};
REGISTER_DL_TEST(&test_parameter_validation);
