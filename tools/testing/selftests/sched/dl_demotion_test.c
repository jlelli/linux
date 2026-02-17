// SPDX-License-Identifier: GPL-2.0-only
/*
 * SCHED_DEADLINE demotion/promotion test
 *
 * Tests the SCHED_FLAG_DL_DEMOTION feature which allows DEADLINE tasks
 * to be demoted to SCHED_NORMAL when they exhaust their runtime, and
 * promoted back when the replenishment timer fires.
 */

#define _GNU_SOURCE
#include <sched.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <pthread.h>

#ifndef SCHED_FLAG_DL_DEMOTION
#define SCHED_FLAG_DL_DEMOTION 0x80
#endif

#define NSEC_PER_SEC 1000000000ULL
#define USEC_PER_SEC 1000000ULL

/* Ftrace marker file */
static int trace_marker_fd = -1;

/* Wrappers for sys_sched_setattr/getattr - use syscall directly to avoid glibc conflicts */
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

/* Initialize ftrace marker for userspace tracing */
static void trace_marker_init(void)
{
	const char *paths[] = {
		"/sys/kernel/tracing/trace_marker",
		"/sys/kernel/debug/tracing/trace_marker",
		NULL
	};

	for (int i = 0; paths[i]; i++) {
		trace_marker_fd = open(paths[i], O_WRONLY);
		if (trace_marker_fd >= 0)
			break;
	}
}

/* Write a message to ftrace buffer */
static void trace_write(const char *fmt, ...)
{
	char buf[256];
	va_list args;
	int len;

	if (trace_marker_fd < 0)
		return;

	va_start(args, fmt);
	len = vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	if (len > 0)
		write(trace_marker_fd, buf, len);
}

/* Close ftrace marker */
static void trace_marker_close(void)
{
	if (trace_marker_fd >= 0) {
		close(trace_marker_fd);
		trace_marker_fd = -1;
	}
}

/* Burn CPU cycles for approximately nsec nanoseconds */
static void burn_cpu(uint64_t nsec)
{
	struct timespec start, now;
	uint64_t elapsed_ns;
	volatile uint64_t dummy = 0;

	clock_gettime(CLOCK_MONOTONIC, &start);
	do {
		for (int i = 0; i < 10000; i++)
			dummy += i;
		clock_gettime(CLOCK_MONOTONIC, &now);
		elapsed_ns = (now.tv_sec - start.tv_sec) * NSEC_PER_SEC +
			     (now.tv_nsec - start.tv_nsec);
	} while (elapsed_ns < nsec);
}

/* Get current scheduling policy */
static int get_current_policy(void)
{
	struct sched_attr attr = {0};
	attr.size = sizeof(attr);

	if (sys_sched_getattr(0, &attr, sizeof(attr), 0) < 0) {
		perror("sys_sched_getattr");
		return -1;
	}

	return attr.sched_policy;
}

/*
 * Test 1: Basic demotion when runtime exhausted
 *
 * Create a DEADLINE task with demotion flag, run it until runtime
 * is exhausted, verify it gets demoted to SCHED_NORMAL.
 */
static int test_basic_demotion(void)
{
	struct sched_attr attr = {0};
	int policy_before, policy_after;

	printf("Test 1: Basic demotion on runtime exhaustion\n");
	trace_write("TEST1: START - Basic demotion on runtime exhaustion");

	attr.size = sizeof(attr);
	attr.sched_policy = SCHED_DEADLINE;
	attr.sched_runtime = 10 * 1000 * 1000;   /* 10ms */
	attr.sched_deadline = 100 * 1000 * 1000; /* 100ms */
	attr.sched_period = 100 * 1000 * 1000;   /* 100ms */
	attr.sched_flags = SCHED_FLAG_DL_DEMOTION;
	attr.sched_nice = 0;  /* Nice value when demoted */

	if (sys_sched_setattr(0, &attr, 0) < 0) {
		if (errno == EPERM) {
			printf("  SKIP: Need CAP_SYS_NICE or root privileges\n");
			return 0;
		}
		if (errno == EINVAL) {
			printf("  SKIP: SCHED_FLAG_DL_DEMOTION not supported\n");
			return 0;
		}
		perror("  FAIL: sys_sched_setattr");
		return -1;
	}

	policy_before = get_current_policy();
	if (policy_before != SCHED_DEADLINE) {
		printf("  FAIL: Not SCHED_DEADLINE after setattr (got %d)\n",
		       policy_before);
		return -1;
	}

	/* Burn more than the runtime to trigger demotion */
	printf("  Burning CPU to exhaust runtime...\n");
	trace_write("TEST1: Burning CPU to exhaust runtime (15ms)");
	burn_cpu(15 * 1000 * 1000); /* 15ms, more than 10ms runtime */
	trace_write("TEST1: CPU burn complete, checking policy");

	/* Check if we got demoted */
	policy_after = get_current_policy();
	if (policy_after == SCHED_NORMAL) {
		printf("  PASS: Demoted to SCHED_NORMAL after runtime exhaustion\n");
		trace_write("TEST1: PASS - Task demoted to SCHED_NORMAL");
		/* Reset to normal before returning */
		attr.sched_policy = SCHED_NORMAL;
		sys_sched_setattr(0, &attr, 0);
		trace_write("TEST1: END");
		return 0;
	} else {
		printf("  FAIL: Still policy %d after runtime exhaustion (expected SCHED_NORMAL)\n",
		       policy_after);
		trace_write("TEST1: FAIL - Task not demoted (policy=%d)", policy_after);
		attr.sched_policy = SCHED_NORMAL;
		sys_sched_setattr(0, &attr, 0);
		trace_write("TEST1: END");
		return -1;
	}
}

/*
 * Test 2: Promotion when replenishment timer fires
 *
 * Get demoted, then sleep until the period expires and verify
 * we get promoted back to SCHED_DEADLINE.
 */
static int test_promotion_on_timer(void)
{
	struct sched_attr attr = {0};
	int policy_before, policy_after;

	printf("\nTest 2: Promotion on replenishment timer\n");
	trace_write("TEST2: START - Promotion on replenishment timer");

	/* Reset to SCHED_NORMAL before starting */
	attr.size = sizeof(attr);
	attr.sched_policy = SCHED_NORMAL;
	sys_sched_setattr(0, &attr, 0);

	attr.size = sizeof(attr);
	attr.sched_policy = SCHED_DEADLINE;
	attr.sched_runtime = 10 * 1000 * 1000;   /* 10ms */
	attr.sched_deadline = 200 * 1000 * 1000; /* 200ms */
	attr.sched_period = 200 * 1000 * 1000;   /* 200ms */
	attr.sched_flags = SCHED_FLAG_DL_DEMOTION;
	attr.sched_nice = 0;

	if (sys_sched_setattr(0, &attr, 0) < 0) {
		if (errno == EINVAL) {
			printf("  SKIP: SCHED_FLAG_DL_DEMOTION not supported\n");
			return 0;
		}
		perror("  FAIL: sys_sched_setattr");
		return -1;
	}

	/* Exhaust runtime to get demoted */
	printf("  Exhausting runtime...\n");
	trace_write("TEST2: Exhausting runtime to trigger demotion");
	burn_cpu(15 * 1000 * 1000); /* 15ms */
	trace_write("TEST2: CPU burn complete, checking if demoted");

	policy_before = get_current_policy();
	if (policy_before != SCHED_NORMAL) {
		printf("  FAIL: Not demoted (policy=%d)\n", policy_before);
		attr.sched_policy = SCHED_NORMAL;
		sys_sched_setattr(0, &attr, 0);
		return -1;
	}
	printf("  Demoted to SCHED_NORMAL\n");
	trace_write("TEST2: Confirmed demoted to SCHED_NORMAL");

	/* Wait for period to expire (timer should promote us) */
	printf("  Waiting for replenishment timer (250ms)...\n");
	trace_write("TEST2: Waiting for replenishment timer (250ms)");
	usleep(250 * 1000); /* 250ms, longer than 200ms period */
	trace_write("TEST2: Wait complete, checking if promoted");

	/* Check if promoted back */
	policy_after = get_current_policy();
	if (policy_after == SCHED_DEADLINE) {
		printf("  PASS: Promoted back to SCHED_DEADLINE\n");
		trace_write("TEST2: PASS - Promoted back to SCHED_DEADLINE");
		attr.sched_policy = SCHED_NORMAL;
		sys_sched_setattr(0, &attr, 0);
		trace_write("TEST2: END");
		return 0;
	} else {
		printf("  FAIL: Still policy %d after timer (expected SCHED_DEADLINE)\n",
		       policy_after);
		trace_write("TEST2: FAIL - Not promoted (policy=%d)", policy_after);
		attr.sched_policy = SCHED_NORMAL;
		sys_sched_setattr(0, &attr, 0);
		trace_write("TEST2: END");
		return -1;
	}
}

/*
 * Test 3: Explicit parameter change while demoted
 *
 * Get demoted, then explicitly change scheduling parameters.
 * This should clear the demotion state and prevent automatic promotion.
 */
static int test_param_change_while_demoted(void)
{
	struct sched_attr attr = {0};
	int policy;

	printf("\nTest 3: Explicit parameter change while demoted\n");
	trace_write("TEST3: START - Explicit parameter change while demoted");

	/* Reset to SCHED_NORMAL before starting */
	attr.size = sizeof(attr);
	attr.sched_policy = SCHED_NORMAL;
	sys_sched_setattr(0, &attr, 0);

	attr.sched_policy = SCHED_DEADLINE;
	attr.sched_runtime = 10 * 1000 * 1000;   /* 10ms */
	attr.sched_deadline = 200 * 1000 * 1000; /* 200ms */
	attr.sched_period = 200 * 1000 * 1000;   /* 200ms */
	attr.sched_flags = SCHED_FLAG_DL_DEMOTION;
	attr.sched_nice = 0;

	if (sys_sched_setattr(0, &attr, 0) < 0) {
		if (errno == EINVAL) {
			printf("  SKIP: SCHED_FLAG_DL_DEMOTION not supported\n");
			return 0;
		}
		perror("  FAIL: sys_sched_setattr");
		return -1;
	}

	/* Exhaust runtime to get demoted */
	printf("  Exhausting runtime...\n");
	trace_write("TEST3: Exhausting runtime to trigger demotion");
	burn_cpu(15 * 1000 * 1000);
	trace_write("TEST3: Checking if demoted");

	policy = get_current_policy();
	if (policy != SCHED_NORMAL) {
		printf("  FAIL: Not demoted (policy=%d)\n", policy);
		attr.sched_policy = SCHED_NORMAL;
		sys_sched_setattr(0, &attr, 0);
		return -1;
	}
	printf("  Demoted to SCHED_NORMAL\n");
	trace_write("TEST3: Confirmed demoted to SCHED_NORMAL");

	/* Explicitly change to SCHED_NORMAL (should clear demotion state) */
	printf("  Explicitly setting SCHED_NORMAL...\n");
	trace_write("TEST3: Explicitly calling sched_setattr(SCHED_NORMAL) to clear demotion state");
	attr.sched_policy = SCHED_NORMAL;
	attr.sched_nice = 5;
	if (sys_sched_setattr(0, &attr, 0) < 0) {
		perror("  FAIL: sys_sched_setattr to NORMAL");
		return -1;
	}

	/* Wait past the period - should NOT be promoted */
	printf("  Waiting past period (250ms)...\n");
	trace_write("TEST3: Waiting past period - should NOT be promoted");
	usleep(250 * 1000);
	trace_write("TEST3: Wait complete, verifying still NORMAL");

	policy = get_current_policy();
	if (policy == SCHED_NORMAL) {
		printf("  PASS: Remained SCHED_NORMAL (demotion state cleared)\n");
		trace_write("TEST3: PASS - Remained SCHED_NORMAL");
		trace_write("TEST3: END");
		return 0;
	} else {
		printf("  FAIL: Unexpected promotion to policy %d\n", policy);
		trace_write("TEST3: FAIL - Unexpected promotion to policy %d", policy);
		attr.sched_policy = SCHED_NORMAL;
		sys_sched_setattr(0, &attr, 0);
		trace_write("TEST3: END");
		return -1;
	}
}

/*
 * Test 4: Demotion disabled without flag
 *
 * Create DEADLINE task without demotion flag, exhaust runtime,
 * verify task stays SCHED_DEADLINE (throttled but not demoted).
 */
static int test_no_demotion_without_flag(void)
{
	struct sched_attr attr = {0};
	int policy;

	printf("\nTest 4: No demotion without SCHED_FLAG_DL_DEMOTION\n");
	trace_write("TEST4: START - No demotion without flag");

	/* Reset to SCHED_NORMAL before starting */
	attr.size = sizeof(attr);
	attr.sched_policy = SCHED_NORMAL;
	sys_sched_setattr(0, &attr, 0);

	attr.sched_policy = SCHED_DEADLINE;
	attr.sched_runtime = 10 * 1000 * 1000;   /* 10ms */
	attr.sched_deadline = 100 * 1000 * 1000; /* 100ms */
	attr.sched_period = 100 * 1000 * 1000;   /* 100ms */
	attr.sched_flags = 0;  /* No demotion flag */
	attr.sched_nice = 0;

	if (sys_sched_setattr(0, &attr, 0) < 0) {
		perror("  FAIL: sys_sched_setattr");
		return -1;
	}

	/* Burn CPU to exhaust runtime */
	printf("  Exhausting runtime...\n");
	trace_write("TEST4: Exhausting runtime (no demotion flag set)");
	burn_cpu(15 * 1000 * 1000);
	trace_write("TEST4: CPU burn complete, checking policy");

	/* Should still be SCHED_DEADLINE (throttled, not demoted) */
	policy = get_current_policy();
	if (policy == SCHED_DEADLINE) {
		printf("  PASS: Remained SCHED_DEADLINE (throttled, not demoted)\n");
		trace_write("TEST4: PASS - Remained SCHED_DEADLINE");
		attr.sched_policy = SCHED_NORMAL;
		sys_sched_setattr(0, &attr, 0);
		trace_write("TEST4: END");
		return 0;
	} else {
		printf("  FAIL: Changed to policy %d without demotion flag\n", policy);
		trace_write("TEST4: FAIL - Changed to policy %d", policy);
		attr.sched_policy = SCHED_NORMAL;
		sys_sched_setattr(0, &attr, 0);
		trace_write("TEST4: END");
		return -1;
	}
}

int main(void)
{
	int failures = 0;

	printf("SCHED_DEADLINE Demotion Tests\n");
	printf("==============================\n\n");

	/* Initialize ftrace marker (silently fails if not available) */
	trace_marker_init();
	trace_write("=== SCHED_DEADLINE Demotion Test Suite START ===");

	/* Run tests with pauses between them for clearer trace separation */
	if (test_basic_demotion() < 0)
		failures++;

	/* Pause between tests (300ms - longer than any test period) */
	printf("\n--- Pausing 300ms between tests ---\n");
	trace_write("=== PAUSE between tests (300ms) ===");
	usleep(300 * 1000);

	if (test_promotion_on_timer() < 0)
		failures++;

	printf("\n--- Pausing 300ms between tests ---\n");
	trace_write("=== PAUSE between tests (300ms) ===");
	usleep(300 * 1000);

	if (test_param_change_while_demoted() < 0)
		failures++;

	printf("\n--- Pausing 300ms between tests ---\n");
	trace_write("=== PAUSE between tests (300ms) ===");
	usleep(300 * 1000);

	if (test_no_demotion_without_flag() < 0)
		failures++;

	/* Summary */
	printf("\n==============================\n");
	if (failures == 0) {
		printf("All tests PASSED\n");
		trace_write("=== Test Suite PASSED ===");
		trace_marker_close();
		return 0;
	} else {
		printf("%d test(s) FAILED\n", failures);
		trace_write("=== Test Suite FAILED (%d failures) ===", failures);
		trace_marker_close();
		return 1;
	}
}
