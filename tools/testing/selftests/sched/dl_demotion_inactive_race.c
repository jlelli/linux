// SPDX-License-Identifier: GPL-2.0
/*
 * Test for SCHED_DEADLINE demotion + inactive timer race condition
 *
 * This test reproduces the bandwidth accounting underflow that occurs when
 * a task exhausts its runtime during dequeue (going to sleep):
 *
 * 1. Task starts going to sleep as DEADLINE (dequeue_task_dl)
 * 2. update_curr_dl_se() detects runtime exhaustion → task demoted
 * 3. task_non_contending() still called (dl_task=1) → inactive timer armed
 * 4. Now we have DEMOTED task with dl_non_contending=1
 * 5. Replenishment timer fires → tries to sub_running_bw()
 * 6. Inactive timer fires → also tries to sub_running_bw() → UNDERFLOW!
 *
 * The fix checks !dl_non_contending before subtracting in replenishment path.
 *
 * Expected: No bandwidth underflow warnings in dmesg
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
#include <sched.h>
#include <pthread.h>

#ifndef SCHED_FLAG_DL_DEMOTION
#define SCHED_FLAG_DL_DEMOTION 0x80
#endif

static int sys_sched_setattr(pid_t pid, struct sched_attr *attr,
			     unsigned int flags)
{
	return syscall(__NR_sched_setattr, pid, attr, flags);
}

/* Busy loop for specified nanoseconds using CPU time */
static void burn_cpu_ns(long long ns)
{
	struct timespec start, now;
	long long elapsed_ns;

	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &start);
	do {
		for (volatile int i = 0; i < 1000; i++)
			;
		clock_gettime(CLOCK_THREAD_CPUTIME_ID, &now);
		elapsed_ns = (now.tv_sec - start.tv_sec) * 1000000000LL +
			     (now.tv_nsec - start.tv_nsec);
	} while (elapsed_ns < ns);
}

int main(int argc, char **argv)
{
	struct sched_attr attr;
	int i;
	int iterations = 100;

	/* Allow user to specify number of iterations */
	if (argc > 1)
		iterations = atoi(argv[1]);

	printf("SCHED_DEADLINE demotion + inactive timer race test\n");
	printf("====================================================\n\n");

	printf("This test triggers runtime exhaustion during sleep/dequeue:\n");
	printf("  1. Task burns most of its runtime\n");
	printf("  2. Task goes to sleep with tiny runtime left\n");
	printf("  3. update_curr_dl_se() during dequeue exhausts runtime\n");
	printf("  4. Task gets demoted BUT task_non_contending() still called\n");
	printf("  5. Inactive timer armed on DEMOTED task (race condition!)\n\n");

	/* Set up DEADLINE with demotion and small runtime */
	memset(&attr, 0, sizeof(attr));
	attr.size = sizeof(attr);
	attr.sched_policy = SCHED_DEADLINE;
	attr.sched_runtime = 5 * 1000000;    /* 5ms runtime (smaller = easier to hit) */
	attr.sched_deadline = 30 * 1000000; /* 100ms deadline */
	attr.sched_period = 30 * 1000000;   /* 100ms period */
	attr.sched_flags = SCHED_FLAG_DL_DEMOTION;
	attr.sched_nice = 0;

	printf("Setting up DEADLINE task:\n");
	printf("  Runtime:  5ms\n");
	printf("  Period:   30ms\n");
	printf("  Demotion: enabled\n");
	printf("  Iterations: %d\n\n", iterations);

	if (sys_sched_setattr(0, &attr, 0) < 0) {
		perror("sched_setattr");
		printf("\nFAILED: Could not set SCHED_DEADLINE\n");
		printf("This could be due to:\n");
		printf("  1. Insufficient privileges (need root or CAP_SYS_NICE)\n");
		printf("  2. RT/DL bandwidth throttling (check /proc/sys/kernel/sched_rt_*)\n");
		printf("  3. Requested bandwidth exceeds system limits\n\n");
		printf("To disable RT throttling temporarily:\n");
		printf("  echo -1 | sudo tee /proc/sys/kernel/sched_rt_runtime_us\n\n");
		return 1;
	}

	printf("Running test iterations (trying different timing windows)...\n");

	/*
	 * Each iteration tries to hit the narrow window where runtime
	 * is exhausted during the dequeue (sleep) path.
	 * We try different amounts of remaining runtime to increase hit rate.
	 */
	for (i = 0; i < iterations; i++) {
		/*
		 * Try different runtime remainders each iteration.
		 * The right amount depends on context switch overhead.
		 * Typical values: 50-500 microseconds
		 */
		long long remainder_us[] = {50, 100, 150, 200, 300, 400, 500};
		int num_remainders = sizeof(remainder_us) / sizeof(remainder_us[0]);
		long long remainder = remainder_us[i % num_remainders];
		long long burn_time = 5000000 - (remainder * 1000); /* 5ms - remainder */

		if ((i % 10) == 0)
			printf(".");
		fflush(stdout);

		/*
		 * Burn almost all runtime, leaving just a tiny bit.
		 * We want to exhaust it precisely during update_curr_dl_se
		 * when we go to sleep.
		 */
		burn_cpu_ns(burn_time);

		/*
		 * Now go to sleep. If our timing is right, the remaining
		 * runtime will be exhausted during update_curr_dl_se() in
		 * the dequeue path, triggering demotion while task_non_contending
		 * is still about to be called.
		 */
		usleep(40000); /* Sleep 40ms (> period, lets both timers fire) */
	}
	printf(" done!\n\n");

	/* Clean up - switch back to normal */
	attr.sched_policy = SCHED_NORMAL;
	sys_sched_setattr(0, &attr, 0);

	printf("====================================================\n");
	printf("Test complete! Ran %d iterations.\n\n", iterations);
	printf("Check for bandwidth underflow warnings:\n");
	printf("  sudo dmesg | grep -i 'underflow\\|WARNING.*deadline'\n\n");
	printf("Without fix: Bandwidth underflow warnings appear\n");
	printf("With fix:    No warnings\n\n");
	printf("If no warnings appeared, try running more iterations:\n");
	printf("  sudo ./dl_demotion_inactive_race 500\n\n");
	printf("To see detailed trace (if trace_printk enabled):\n");
	printf("  sudo cat /sys/kernel/debug/tracing/trace | tail -200\n");
	printf("Look for sequence:\n");
	printf("  - dl_task_demote (runtime negative)\n");
	printf("  - task_non_contending (with demotion_state=2)\n");
	printf("  - dl_task_timer (replenishment with non_contending=1)\n");
	printf("  - inactive_timer (should not cause underflow)\n");

	return 0;
}
