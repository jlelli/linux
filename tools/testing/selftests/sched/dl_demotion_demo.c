// SPDX-License-Identifier: GPL-2.0
/*
 * Simple demonstration of SCHED_DEADLINE demotion feature
 *
 * This test demonstrates the difference between:
 * 1. Normal throttling: task stops executing when runtime exhausted
 * 2. Demotion: task continues as SCHED_NORMAL when runtime exhausted
 *
 * Both tasks try to execute continuously, but only have 30ms budget per 100ms period.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/sched.h>
#include <linux/sched/types.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>

#ifndef SCHED_FLAG_DL_DEMOTION
#define SCHED_FLAG_DL_DEMOTION 0x80
#endif

/* Ftrace marker file */
static int trace_marker_fd = -1;

/* Use syscall directly to avoid glibc conflicts */
static int sys_sched_setattr(pid_t pid, struct sched_attr *attr,
			     unsigned int flags)
{
	return syscall(__NR_sched_setattr, pid, attr, flags);
}

static int sys_sched_getattr(pid_t pid, struct sched_attr *attr,
			     unsigned int size, unsigned int flags)
{
	return syscall(__NR_sched_getattr, pid, attr, size, flags);
}

/* Open ftrace marker for writing trace events */
static void open_trace_marker(void)
{
	trace_marker_fd = open("/sys/kernel/tracing/trace_marker", O_WRONLY);
	if (trace_marker_fd < 0) {
		/* Try debugfs location */
		trace_marker_fd = open("/sys/kernel/debug/tracing/trace_marker", O_WRONLY);
	}
}

/* Write a message to ftrace marker */
static void trace_write(const char *fmt, ...)
{
	char buf[256];
	va_list ap;
	int len;

	if (trace_marker_fd < 0)
		return;

	va_start(ap, fmt);
	len = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	if (len > 0)
		write(trace_marker_fd, buf, len);
}

/* Busy loop for specified milliseconds */
static void burn_cpu_ms(int ms)
{
	struct timespec start, now;
	long long elapsed_ns;
	long long target_ns = ms * 1000000LL;

	clock_gettime(CLOCK_MONOTONIC, &start);
	do {
		/* Just burn CPU */
		for (volatile int i = 0; i < 10000; i++)
			;
		clock_gettime(CLOCK_MONOTONIC, &now);
		elapsed_ns = (now.tv_sec - start.tv_sec) * 1000000000LL +
			     (now.tv_nsec - start.tv_nsec);
	} while (elapsed_ns < target_ns);
}

/* Count how much CPU time we actually got */
static int measure_execution_time_ms(void (*workload)(void))
{
	struct timespec start, end;
	long long elapsed_ns;

	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &start);
	workload();
	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &end);

	elapsed_ns = (end.tv_sec - start.tv_sec) * 1000000000LL +
		     (end.tv_nsec - start.tv_nsec);

	return elapsed_ns / 1000000; /* Convert to ms */
}

/* Try to execute for 200ms (should get throttled/demoted at 30ms) */
static void try_burn_200ms(void)
{
	burn_cpu_ms(200);
}

static void run_throttled_test(void)
{
	struct sched_attr attr = {
		.size = sizeof(attr),
		.sched_policy = SCHED_DEADLINE,
		.sched_runtime = 30 * 1000000,   /* 30ms */
		.sched_deadline = 100 * 1000000, /* 100ms */
		.sched_period = 100 * 1000000,   /* 100ms */
		.sched_flags = 0,  /* NO demotion flag */
		.sched_nice = 0,
	};
	int actual_ms;

	printf("\n=== Test 1: Normal DEADLINE (no demotion) ===\n");
	printf("Configuration:\n");
	printf("  Runtime:  30ms per 100ms period\n");
	printf("  Flags:    (none - normal throttling)\n");
	printf("  Workload: Try to execute for 200ms\n\n");

	trace_write("TEST1_START: Normal DEADLINE without demotion");

	if (sys_sched_setattr(0, &attr, 0) < 0) {
		perror("sys_sched_setattr");
		exit(1);
	}

	trace_write("TEST1_EXEC_START: Starting workload");
	printf("Starting execution...\n");
	actual_ms = measure_execution_time_ms(try_burn_200ms);
	trace_write("TEST1_EXEC_END: Workload completed");

	printf("\nResult:\n");
	printf("  CPU time obtained: %dms\n", actual_ms);
	if (actual_ms >= 55 && actual_ms <= 65) {
		printf("  ✓ Task was THROTTLED after exhausting 30ms budget\n");
		printf("  ✓ Task stopped executing (did not continue past budget)\n");
	} else {
		printf("  ✗ Unexpected execution time (expected ~30ms)\n");
	}

	/* Switch back to normal before next test */
	attr.sched_policy = SCHED_NORMAL;
	sys_sched_setattr(0, &attr, 0);
	trace_write("TEST1_END: Switched back to SCHED_NORMAL");
	usleep(100000); /* Let things settle */
}

static void run_demotion_test(void)
{
	struct sched_attr attr = {
		.size = sizeof(attr),
		.sched_policy = SCHED_DEADLINE,
		.sched_runtime = 30 * 1000000,   /* 30ms */
		.sched_deadline = 100 * 1000000, /* 100ms */
		.sched_period = 100 * 1000000,   /* 100ms */
		.sched_flags = SCHED_FLAG_DL_DEMOTION,
		.sched_nice = 0,
	};
	int actual_ms;

	printf("\n=== Test 2: DEADLINE with demotion ===\n");
	printf("Configuration:\n");
	printf("  Runtime:  30ms per 100ms period\n");
	printf("  Flags:    SCHED_FLAG_DL_DEMOTION\n");
	printf("  Workload: Try to execute for 200ms\n\n");

	trace_write("TEST2_START: DEADLINE with demotion enabled");

	if (sys_sched_setattr(0, &attr, 0) < 0) {
		perror("sys_sched_setattr");
		exit(1);
	}

	trace_write("TEST2_EXEC_START: Starting workload (will demote)");
	printf("Starting execution...\n");
	actual_ms = measure_execution_time_ms(try_burn_200ms);
	trace_write("TEST2_EXEC_END: Workload completed");

	printf("\nResult:\n");
	printf("  CPU time obtained: %dms\n", actual_ms);
	if (actual_ms >= 150) {
		printf("  ✓ Task was DEMOTED after exhausting 30ms budget\n");
		printf("  ✓ Task continued executing as SCHED_NORMAL\n");
		printf("  ✓ Task completed the full workload\n");
	} else if (actual_ms >= 25 && actual_ms <= 35) {
		printf("  ✗ Task was throttled instead of demoted\n");
		printf("  ✗ Demotion feature may not be working\n");
	} else {
		printf("  ✗ Unexpected execution time\n");
	}

	/* Switch back to normal */
	attr.sched_policy = SCHED_NORMAL;
	sys_sched_setattr(0, &attr, 0);
	trace_write("TEST2_END: Switched back to SCHED_NORMAL");
}

int main(void)
{
	printf("SCHED_DEADLINE Demotion Feature Demonstration\n");
	printf("==============================================\n");
	printf("\nThis demonstrates the difference between normal throttling\n");
	printf("and demotion when a DEADLINE task exhausts its runtime.\n");

	/* Open ftrace marker for trace events */
	open_trace_marker();
	trace_write("DEMO_START: Beginning demonstration");

	/* Run test without demotion (throttled) */
	run_throttled_test();

	/* Run test with demotion (continues as NORMAL) */
	run_demotion_test();

	printf("\n==============================================\n");
	printf("Summary:\n");
	printf("  Without demotion: Task stops when budget exhausted\n");
	printf("  With demotion:    Task continues as SCHED_NORMAL\n");
	printf("\nDemonstration complete!\n");

	trace_write("DEMO_END: Demonstration completed");

	if (trace_marker_fd >= 0)
		close(trace_marker_fd);

	return 0;
}
