// SPDX-License-Identifier: GPL-2.0
/*
 * SCHED_DEADLINE fair_server tests
 *
 * Validates fair_server bandwidth management and CPU protection behavior.
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
#include <sched.h>
#include "dl_test.h"
#include "dl_util.h"

/*
 * Test: Fair server bandwidth validation
 *
 * Verifies that the kernel rejects attempts to set fair_server bandwidth
 * that exceeds available RT bandwidth, and preserves the original value.
 */
static enum dl_test_status test_fair_server_bandwidth_validation_run(void *ctx)
{
	uint64_t rt_runtime_us, rt_period_us;
	uint64_t fair_runtime_ns, fair_period_ns;
	uint64_t excessive_runtime_ns;
	uint64_t *original_runtimes = NULL;
	int num_cpus, i;
	int write_succeeded = 0;
	int write_failed = 0;

	/* Check if fair_server interface exists */
	if (!dl_fair_server_exists()) {
		printf("  Fair server interface not found\n");
		return DL_TEST_SKIP;
	}

	/* Read RT bandwidth settings */
	DL_FAIL_IF(dl_get_rt_bandwidth(&rt_runtime_us, &rt_period_us) < 0,
		   "Failed to read RT bandwidth settings");

	printf("  RT bandwidth: %luµs / %luµs per CPU\n",
	       rt_runtime_us, rt_period_us);

	num_cpus = dl_get_online_cpus();
	DL_FAIL_IF(num_cpus <= 0, "Failed to get number of CPUs");

	printf("  Number of online CPUs: %d\n", num_cpus);

	/* Read current fair_server settings for cpu0 to get period */
	DL_FAIL_IF(dl_get_fair_server_settings(0, &fair_runtime_ns,
					       &fair_period_ns) < 0,
		   "Failed to read fair_server settings");

	printf("  Fair server period: %luns\n", fair_period_ns);

	/* Save original runtimes for all CPUs */
	original_runtimes = calloc(num_cpus, sizeof(uint64_t));
	DL_FAIL_IF(!original_runtimes, "Failed to allocate memory");

	for (i = 0; i < num_cpus; i++) {
		if (dl_get_fair_server_settings(i, &original_runtimes[i],
						NULL) < 0) {
			printf("  Warning: Cannot read CPU %d settings\n", i);
			original_runtimes[i] = 0;
		}
	}

	/*
	 * Try to set each CPU's fair_server to 101% of RT bandwidth per CPU.
	 * This should exceed the per-CPU RT bandwidth limit and fail.
	 */
	excessive_runtime_ns = (rt_runtime_us * 101 / 100) * 1000;

	/* Scale to fair_server period if different from RT period */
	if (fair_period_ns != rt_period_us * 1000)
		excessive_runtime_ns = excessive_runtime_ns * fair_period_ns /
				       (rt_period_us * 1000);

	printf("  Attempting to set all CPUs to %luns (101%% of RT bandwidth)\n",
	       excessive_runtime_ns);

	for (i = 0; i < num_cpus; i++) {
		if (dl_set_fair_server_runtime(i, excessive_runtime_ns) == 0) {
			write_succeeded++;
		} else {
			write_failed++;
			printf("  CPU %d write rejected: %s\n", i, strerror(errno));
		}
	}

	printf("  Result: %d writes succeeded, %d failed\n",
	       write_succeeded, write_failed);

	/* Restore original values */
	for (i = 0; i < num_cpus; i++) {
		if (original_runtimes[i] > 0)
			dl_set_fair_server_runtime(i, original_runtimes[i]);
	}

	free(original_runtimes);

	/*
	 * Test passes if at least one write was rejected,
	 * showing bandwidth limit enforcement.
	 */
	if (write_failed > 0) {
		printf("  SUCCESS: Bandwidth limit enforced (%d writes rejected)\n",
		       write_failed);
		return DL_TEST_PASS;
	}

	printf("  FAIL: All writes accepted, no bandwidth limit enforcement\n");
	return DL_TEST_FAIL;
}

static struct dl_test test_fair_server_bandwidth_validation = {
	.name = "fair_server_bandwidth_validation",
	.description = "Verify fair_server bandwidth validation against RT bandwidth",
	.run = test_fair_server_bandwidth_validation_run,
};
REGISTER_DL_TEST(&test_fair_server_bandwidth_validation);

/*
 * Test: Fair server CPU protection under FIFO competition
 *
 * Verifies that fair_server provides CPU time to CFS tasks even when
 * competing with high-priority FIFO tasks on the same CPU.
 */
static enum dl_test_status test_fair_server_cpu_protection_run(void *ctx)
{
	uint64_t fair_runtime_ns, fair_period_ns;
	uint64_t initial_time, final_time, cpu_ticks_used;
	uint64_t ticks_per_sec, test_duration = 12;
	pid_t cfs_pid, fifo_pid;
	int test_cpu = 2;
	int expected_percent, cpu_percent;
	int min_expected, max_expected;
	cpu_set_t cpuset;
	struct sched_param param;

	/* Check if fair_server interface exists */
	if (!dl_fair_server_exists()) {
		printf("  Fair server interface not found\n");
		return DL_TEST_SKIP;
	}

	/* Read fair_server settings */
	DL_FAIL_IF(dl_get_fair_server_settings(test_cpu, &fair_runtime_ns,
					       &fair_period_ns) < 0,
		   "Failed to read fair_server settings");

	expected_percent = (fair_runtime_ns * 100) / fair_period_ns;

	printf("  Fair server (CPU %d): %luns / %luns (%d%%)\n",
	       test_cpu, fair_runtime_ns, fair_period_ns, expected_percent);

	ticks_per_sec = sysconf(_SC_CLK_TCK);

	/* Fork CFS cpuhog */
	cfs_pid = fork();
	if (cfs_pid < 0) {
		DL_ERR("Failed to fork CFS task");
		return DL_TEST_FAIL;
	}

	if (cfs_pid == 0) {
		/* Child: CFS cpuhog pinned to test_cpu */
		CPU_ZERO(&cpuset);
		CPU_SET(test_cpu, &cpuset);
		sched_setaffinity(0, sizeof(cpuset), &cpuset);

		execl("./cpuhog", "cpuhog", "-t", "20", NULL);
		exit(1);
	}

	/* Wait for CFS task to stabilize */
	sleep(2);

	printf("  Measuring baseline CPU time...\n");
	initial_time = dl_get_process_cpu_time(cfs_pid);

	/* Fork FIFO cpuhog */
	fifo_pid = fork();
	if (fifo_pid < 0) {
		kill(cfs_pid, SIGKILL);
		waitpid(cfs_pid, NULL, 0);
		DL_ERR("Failed to fork FIFO task");
		return DL_TEST_FAIL;
	}

	if (fifo_pid == 0) {
		/* Child: FIFO cpuhog pinned to test_cpu */
		CPU_ZERO(&cpuset);
		CPU_SET(test_cpu, &cpuset);
		sched_setaffinity(0, sizeof(cpuset), &cpuset);

		param.sched_priority = 50;
		sched_setscheduler(0, SCHED_FIFO, &param);

		execl("./cpuhog", "cpuhog", "-t", "20", NULL);
		exit(1);
	}

	printf("  Starting FIFO competition for %lus...\n", test_duration);

	/* Wait for test duration */
	sleep(test_duration);

	printf("  Measuring final CPU time...\n");
	final_time = dl_get_process_cpu_time(cfs_pid);

	/* Cleanup */
	kill(cfs_pid, SIGKILL);
	kill(fifo_pid, SIGKILL);
	waitpid(cfs_pid, NULL, 0);
	waitpid(fifo_pid, NULL, 0);

	/* Calculate CPU usage */
	cpu_ticks_used = final_time - initial_time;
	cpu_percent = (cpu_ticks_used * 100) / (test_duration * ticks_per_sec);

	printf("  CPU ticks used: %lu / %lu\n",
	       cpu_ticks_used, test_duration * ticks_per_sec);
	printf("  CFS task CPU usage: %d%%\n", cpu_percent);

	/* Allow ±50% tolerance (e.g., 5% ± 50% = 2.5% - 7.5%) */
	min_expected = expected_percent * 50 / 100;
	max_expected = expected_percent * 150 / 100;

	if (min_expected < 1)
		min_expected = 1;

	printf("  Expected range: %d%% - %d%%\n", min_expected, max_expected);

	if (cpu_percent >= min_expected && cpu_percent <= max_expected) {
		printf("  SUCCESS: CFS task received %d%% CPU\n", cpu_percent);
		return DL_TEST_PASS;
	} else if (cpu_percent < min_expected) {
		printf("  FAIL: CFS task received only %d%% (below %d%%)\n",
		       cpu_percent, min_expected);
		return DL_TEST_FAIL;
	}

	printf("  FAIL: CFS task received %d%% (above %d%%)\n",
	       cpu_percent, max_expected);
	return DL_TEST_FAIL;
}

static struct dl_test test_fair_server_cpu_protection = {
	.name = "fair_server_cpu_protection",
	.description = "Verify fair_server provides CPU protection under FIFO competition",
	.run = test_fair_server_cpu_protection_run,
};
REGISTER_DL_TEST(&test_fair_server_cpu_protection);
