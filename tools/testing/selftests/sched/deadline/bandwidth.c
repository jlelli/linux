// SPDX-License-Identifier: GPL-2.0
/*
 * SCHED_DEADLINE bandwidth admission control tests
 *
 * Validates that the kernel correctly enforces bandwidth limits for
 * SCHED_DEADLINE tasks, including per-CPU bandwidth replication and
 * overflow rejection.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include "dl_test.h"
#include "dl_util.h"

/*
 * Test: Bandwidth admission control with max bandwidth per CPU
 *
 * Verifies that SCHED_DEADLINE bandwidth is replicated per CPU, allowing
 * one task per CPU to use the maximum available bandwidth (typically 95%).
 */
static enum dl_test_status test_bandwidth_admission_run(void *ctx)
{
	uint64_t rt_runtime_us, rt_period_us;
	int max_bw_percent;
	uint64_t runtime_ns, deadline_ns, period_ns;
	int num_cpus, i;
	pid_t *pids = NULL;
	int started = 0, running = 0;
	enum dl_test_status ret = DL_TEST_FAIL;

	/* Get RT bandwidth settings */
	DL_FAIL_IF(dl_get_rt_bandwidth(&rt_runtime_us, &rt_period_us) < 0,
		   "Failed to read RT bandwidth settings");

	printf("  RT bandwidth: runtime=%luµs, period=%luµs (%.0f%%)\n",
	       rt_runtime_us, rt_period_us,
	       (double)rt_runtime_us * 100.0 / rt_period_us);

	/* Show server overhead */
	int server_overhead = dl_get_server_bandwidth_overhead();

	if (server_overhead > 0)
		printf("  DL server overhead: %d%% per CPU\n", server_overhead);

	/* Calculate maximum bandwidth percentage */
	max_bw_percent = dl_calc_max_bandwidth_percent();
	DL_FAIL_IF(max_bw_percent < 0, "Failed to calculate max bandwidth");

	printf("  Available bandwidth per CPU: %d%%\n", max_bw_percent);

	/* Calculate task parameters: 100ms period for easy calculation */
	period_ns = dl_ms_to_ns(100);  /* 100ms */
	runtime_ns = (period_ns * max_bw_percent) / 100;
	deadline_ns = period_ns;

	printf("  Task params: runtime=%lums, deadline=%lums, period=%lums\n",
	       dl_ns_to_ms(runtime_ns), dl_ns_to_ms(deadline_ns),
	       dl_ns_to_ms(period_ns));

	/* Get number of CPUs */
	num_cpus = dl_get_online_cpus();
	DL_FAIL_IF(num_cpus <= 0, "Failed to get number of CPUs");

	printf("  Number of online CPUs: %d\n", num_cpus);

	/* Allocate PID array */
	pids = calloc(num_cpus, sizeof(pid_t));
	DL_FAIL_IF(!pids, "Failed to allocate PID array");

	/* Start one cpuhog per CPU at max bandwidth */
	printf("  Starting %d cpuhog tasks at max bandwidth...\n", num_cpus);

	for (i = 0; i < num_cpus; i++) {
		pids[i] = dl_create_cpuhog(runtime_ns, deadline_ns, period_ns, 0);
		if (pids[i] < 0) {
			printf("  Task %d failed to start: %s\n",
			       i + 1, strerror(errno));
			goto cleanup;
		}
		started++;
	}

	/* Brief wait for tasks to settle */
	usleep(500000);  /* 500ms */

	/* Verify all tasks are running with SCHED_DEADLINE */
	for (i = 0; i < started; i++) {
		if (pids[i] <= 0)
			continue;

		if (kill(pids[i], 0) < 0) {
			printf("  Task PID %d died unexpectedly\n", pids[i]);
			continue;
		}

		if (dl_is_deadline_task(pids[i]))
			running++;
	}

	printf("  Started %d/%d tasks, %d running with SCHED_DEADLINE\n",
	       started, num_cpus, running);

	/* Test passes if we started all N tasks and they're all running */
	if (started == num_cpus && running == num_cpus) {
		printf("  SUCCESS: All %d tasks running at max bandwidth\n",
		       num_cpus);
		ret = DL_TEST_PASS;
	} else if (started != num_cpus) {
		DL_ERR("Only started %d/%d tasks", started, num_cpus);
		ret = DL_TEST_FAIL;
	} else {
		DL_ERR("Started %d tasks but only %d using SCHED_DEADLINE",
		       started, running);
		ret = DL_TEST_FAIL;
	}

cleanup:
	/* Cleanup all started tasks */
	for (i = 0; i < started; i++) {
		if (pids[i] > 0)
			dl_cleanup_cpuhog(pids[i]);
	}

	free(pids);
	return ret;
}

static struct dl_test test_bandwidth_admission = {
	.name = "bandwidth_admission",
	.description = "Verify per-CPU bandwidth replication (N tasks at max bandwidth)",
	.run = test_bandwidth_admission_run,
};
REGISTER_DL_TEST(&test_bandwidth_admission);

/*
 * Test: Bandwidth admission control overflow rejection
 *
 * Verifies that the kernel rejects tasks that would exceed available
 * bandwidth on a CPU. Creates N-1 tasks at max bandwidth, then attempts
 * to create one more at slightly higher bandwidth (should fail).
 */
static enum dl_test_status test_bandwidth_overflow_run(void *ctx)
{
	uint64_t rt_runtime_us, rt_period_us;
	int max_bw_percent;
	uint64_t runtime_ns, deadline_ns, period_ns;
	uint64_t overflow_runtime_ns;
	int num_cpus, i;
	int target_tasks;
	pid_t *pids = NULL;
	pid_t overflow_pid;
	int started = 0;
	enum dl_test_status ret = DL_TEST_FAIL;

	/* Get RT bandwidth settings */
	DL_FAIL_IF(dl_get_rt_bandwidth(&rt_runtime_us, &rt_period_us) < 0,
		   "Failed to read RT bandwidth settings");

	printf("  RT bandwidth: runtime=%luµs, period=%luµs (%.0f%%)\n",
	       rt_runtime_us, rt_period_us,
	       (double)rt_runtime_us * 100.0 / rt_period_us);

	/* Show server overhead */
	int server_overhead = dl_get_server_bandwidth_overhead();

	if (server_overhead > 0)
		printf("  DL server overhead: %d%% per CPU\n", server_overhead);

	/* Calculate maximum bandwidth percentage */
	max_bw_percent = dl_calc_max_bandwidth_percent();
	DL_FAIL_IF(max_bw_percent < 0, "Failed to calculate max bandwidth");

	printf("  Available bandwidth per CPU: %d%%\n", max_bw_percent);

	/* Get number of CPUs */
	num_cpus = dl_get_online_cpus();
	DL_FAIL_IF(num_cpus <= 0, "Failed to get number of CPUs");

	if (num_cpus < 2) {
		printf("  Need at least 2 CPUs for this test (have %d)\n",
		       num_cpus);
		return DL_TEST_SKIP;
	}

	printf("  Number of online CPUs: %d\n", num_cpus);

	/* Calculate task parameters */
	period_ns = dl_ms_to_ns(100);  /* 100ms */
	runtime_ns = (period_ns * max_bw_percent) / 100;
	deadline_ns = period_ns;

	printf("  Task params: runtime=%lums, deadline=%lums, period=%lums\n",
	       dl_ns_to_ms(runtime_ns), dl_ns_to_ms(deadline_ns),
	       dl_ns_to_ms(period_ns));

	/* Start N-1 tasks at max bandwidth */
	target_tasks = num_cpus - 1;
	pids = calloc(target_tasks, sizeof(pid_t));
	DL_FAIL_IF(!pids, "Failed to allocate PID array");

	printf("  Starting %d tasks at max bandwidth...\n", target_tasks);

	for (i = 0; i < target_tasks; i++) {
		pids[i] = dl_create_cpuhog(runtime_ns, deadline_ns, period_ns, 0);
		if (pids[i] < 0) {
			printf("  Task %d failed to start: %s\n",
			       i + 1, strerror(errno));
			goto cleanup;
		}
		started++;
	}

	printf("  Successfully started %d/%d tasks\n", started, target_tasks);

	/* Brief wait */
	usleep(500000);  /* 500ms */

	/* Try to start one more task at max+1% bandwidth (should fail) */
	overflow_runtime_ns = (runtime_ns * 101) / 100;  /* Add 1% */

	printf("  Attempting overflow task with runtime=%lums (+1%%)...\n",
	       dl_ns_to_ms(overflow_runtime_ns));

	overflow_pid = dl_create_cpuhog(overflow_runtime_ns, deadline_ns,
					period_ns, 0);

	if (overflow_pid < 0) {
		/* Expected: admission control rejected it */
		printf("  Overflow task correctly rejected: %s\n",
		       strerror(errno));
		ret = DL_TEST_PASS;
	} else {
		/* Unexpected: it was admitted */
		usleep(100000);  /* 100ms */

		if (kill(overflow_pid, 0) == 0) {
			printf("  ERROR: Overflow task admitted and running\n");
			dl_cleanup_cpuhog(overflow_pid);
			ret = DL_TEST_FAIL;
		} else {
			/* It was admitted but died - still wrong */
			printf("  ERROR: Overflow task admitted but died\n");
			ret = DL_TEST_FAIL;
		}
	}

cleanup:
	/* Cleanup all tasks */
	for (i = 0; i < started; i++) {
		if (pids[i] > 0)
			dl_cleanup_cpuhog(pids[i]);
	}

	free(pids);
	return ret;
}

static struct dl_test test_bandwidth_overflow = {
	.name = "bandwidth_overflow",
	.description = "Verify bandwidth overflow rejection (N-1 + overflow fails)",
	.run = test_bandwidth_overflow_run,
};
REGISTER_DL_TEST(&test_bandwidth_overflow);
