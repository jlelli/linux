// SPDX-License-Identifier: GPL-2.0
/*
 * SCHED_DEADLINE ENQUEUE_REPLENISH Bug Test
 *
 * Reproduces the scenario where:
 * 1. Task B (DEADLINE, short deadline) holds a PI mutex
 * 2. Task A (DEADLINE, long deadline) blocks on Task B's mutex
 * 3. Task B doesn't inherit from Task A (B has shorter deadline = higher priority)
 * 4. sched_setscheduler() changes Task B from DEADLINE to IDLE
 * 5. Task B should now inherit DEADLINE from Task A with ENQUEUE_REPLENISH
 *
 * Without the fix, ENQUEUE_REPLENISH flag is missing, causing:
 * "DL de-boosted task PID X: REPLENISH flag missing"
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <errno.h>
#include <stdint.h>
#include <time.h>
#include <signal.h>
#include "dl_test.h"
#include "dl_util.h"

/* Thread context for the test */
struct replenish_test_ctx {
	pthread_mutex_t pi_mutex;
	pthread_barrier_t barrier;
	pthread_t holder;
	pthread_t waiter;
	volatile int holder_ready;
	volatile int waiter_blocked;
	volatile int test_done;
	volatile int timeout_occurred;
	volatile pid_t holder_tid;
	volatile pid_t waiter_tid;
};

/* Timeout handler */
static void timeout_handler(int sig)
{
	printf("\n\n!!! TIMEOUT !!!\n");
	printf("Test appears to have hung - likely due to the bug being triggered!\n");
	printf("This indicates the ENQUEUE_REPLENISH bug corrupted bandwidth accounting.\n");
	printf("\nCheck kernel log:\n");
	printf("  sudo dmesg | tail -50\n");
	printf("\nLook for:\n");
	printf("  'REPLENISH flag missing'\n");
	printf("  'dl_runtime_exceeded' or bandwidth warnings\n");
}

static void print_sched_info(const char *label, pid_t tid)
{
	struct sched_attr attr = {0};

	if (dl_get_sched_attr(tid, &attr) == 0) {
		printf("[%s] TID %d: policy=%u prio=%d",
		       label, tid, attr.sched_policy, attr.sched_priority);
		if (attr.sched_policy == SCHED_DEADLINE) {
			printf(" runtime=%llu deadline=%llu period=%llu",
			       (unsigned long long)attr.sched_runtime,
			       (unsigned long long)attr.sched_deadline,
			       (unsigned long long)attr.sched_period);
		}
		printf("\n");
	}
}

static int set_sched_idle(pid_t tid)
{
	struct sched_param param = {0};
	return sched_setscheduler(tid, SCHED_IDLE, &param);
}

/*
 * Thread B: DEADLINE task (SHORT deadline) that holds the PI mutex
 * This will be setscheduled to IDLE, triggering the bug
 */
static void *holder_thread(void *arg)
{
	struct replenish_test_ctx *ctx = arg;

	ctx->holder_tid = gettid();
	printf("\n=== HOLDER (Task B) thread started (TID %d) ===\n",
	       ctx->holder_tid);

	/* Set to DEADLINE with a SHORT deadline (high priority) */
	if (dl_set_sched_attr(ctx->holder_tid, dl_ms_to_ns(5),
			      dl_ms_to_ns(30), dl_ms_to_ns(60)) < 0) {
		perror("holder: dl_set_sched_attr");
		return NULL;
	}

	print_sched_info("HOLDER-INIT", ctx->holder_tid);

	/* Lock the mutex */
	pthread_mutex_lock(&ctx->pi_mutex);
	printf("[HOLDER] TID %d: Locked PI mutex\n", ctx->holder_tid);

	/* Signal we're ready */
	ctx->holder_ready = 1;

	/* Wait at barrier */
	pthread_barrier_wait(&ctx->barrier);

	/* Keep holding the mutex while waiter blocks and gets setscheduled */
	while (!ctx->test_done)
		usleep(10000); /* 10ms */

	printf("[HOLDER] TID %d: Unlocking PI mutex\n", ctx->holder_tid);
	pthread_mutex_unlock(&ctx->pi_mutex);

	printf("[HOLDER] TID %d: Exiting\n", ctx->holder_tid);
	return NULL;
}

/*
 * Thread A: DEADLINE task (LONG deadline) that will block on the mutex
 * This is the pi_task that holder will inherit from after setscheduler
 */
static void *waiter_thread(void *arg)
{
	struct replenish_test_ctx *ctx = arg;

	ctx->waiter_tid = gettid();
	printf("\n=== WAITER (Task A) thread started (TID %d) ===\n",
	       ctx->waiter_tid);

	/* Set to DEADLINE with a LONG deadline (low priority) */
	if (dl_set_sched_attr(ctx->waiter_tid, dl_ms_to_ns(10),
			      dl_ms_to_ns(50), dl_ms_to_ns(100)) < 0) {
		perror("waiter: dl_set_sched_attr");
		return NULL;
	}

	print_sched_info("WAITER-INIT", ctx->waiter_tid);

	/* Wait for holder to lock the mutex */
	while (!ctx->holder_ready)
		usleep(1000);

	/* Wait at barrier */
	pthread_barrier_wait(&ctx->barrier);

	printf("[WAITER] TID %d: Attempting to lock PI mutex (will block)...\n",
	       ctx->waiter_tid);

	/* This will block because holder has the lock */
	ctx->waiter_blocked = 1;
	pthread_mutex_lock(&ctx->pi_mutex);

	/* Eventually we get the lock */
	printf("[WAITER] TID %d: Acquired PI mutex\n", ctx->waiter_tid);
	print_sched_info("WAITER-AFTER", ctx->waiter_tid);

	pthread_mutex_unlock(&ctx->pi_mutex);
	printf("[WAITER] TID %d: Unlocked PI mutex\n", ctx->waiter_tid);
	printf("[WAITER] TID %d: Exiting\n", ctx->waiter_tid);

	return NULL;
}

/*
 * Test: DEADLINE ENQUEUE_REPLENISH Bug
 *
 * Verifies that when a SCHED_DEADLINE task holding a PI mutex is changed
 * to SCHED_IDLE while a lower-priority DEADLINE task is blocked on that
 * mutex, the ENQUEUE_REPLENISH flag is correctly set during PI boosting.
 */
static enum dl_test_status test_replenish_bug_run(void *arg)
{
	struct replenish_test_ctx *ctx = arg;
	struct sigaction sa;

	printf("======================================\n");
	printf("DEADLINE ENQUEUE_REPLENISH Bug Test\n");
	printf("======================================\n");
	printf("Timeout: 5 seconds\n");
	printf("\nThis test reproduces the scenario where:\n");
	printf("1. Task B (DEADLINE, short deadline) holds a PI mutex\n");
	printf("2. Task A (DEADLINE, long deadline) blocks on Task B's mutex\n");
	printf("3. Task B doesn't inherit from A (B has higher priority)\n");
	printf("4. Task B gets setscheduled to SCHED_IDLE (while A still blocked)\n");
	printf("5. Task B should now inherit from A with ENQUEUE_REPLENISH\n");
	printf("\nWithout fix: Missing ENQUEUE_REPLENISH flag causes WARNING\n");
	printf("\nCheck dmesg for:\n");
	printf("  'DL de-boosted task PID X: REPLENISH flag missing'\n");
	printf("\nNOTE: If test hangs and times out, the bug was triggered!\n");
	printf("======================================\n\n");

	/* Set up timeout handler */
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = timeout_handler;
	sigaction(SIGALRM, &sa, NULL);

	/* Set timeout (5 seconds) */
	alarm(5);

	/* Initialize barrier for 2 threads */
	DL_FAIL_IF(pthread_barrier_init(&ctx->barrier, NULL, 2) != 0,
		   "pthread_barrier_init failed");

	/* Create holder thread (will lock mutex) */
	if (pthread_create(&ctx->holder, NULL, holder_thread, ctx) != 0) {
		pthread_barrier_destroy(&ctx->barrier);
		DL_FAIL("pthread_create holder failed: %s", strerror(errno));
	}

	/* Create waiter thread (will block on mutex) */
	if (pthread_create(&ctx->waiter, NULL, waiter_thread, ctx) != 0) {
		pthread_barrier_destroy(&ctx->barrier);
		DL_FAIL("pthread_create waiter failed: %s", strerror(errno));
	}

	/* Give threads time to start */
	sleep(1);

	/* Wait for waiter to block on the mutex */
	printf("\n[MAIN] Waiting for waiter to block on mutex...\n");
	while (!ctx->waiter_blocked)
		usleep(1000);

	/* Give it a moment to actually block */
	usleep(50000); /* 50ms */

	printf("\n[MAIN] Holder TID: %d\n", ctx->holder_tid);
	print_sched_info("HOLDER-HOLDING", ctx->holder_tid);

	/*
	 * THE BUG TRIGGER:
	 * Holder (Task B) is DEADLINE with short deadline (high priority).
	 * Waiter (Task A) is DEADLINE with long deadline (low priority), blocked.
	 * Holder didn't inherit from waiter (holder has higher priority).
	 * Now change HOLDER from DEADLINE to SCHED_IDLE.
	 * Holder should inherit DEADLINE from waiter with ENQUEUE_REPLENISH,
	 * but without the fix, it doesn't.
	 */
	printf("\n[MAIN] *** Changing HOLDER (Task B) from SCHED_DEADLINE to SCHED_IDLE ***\n");
	printf("[MAIN] *** This triggers the bug! ***\n");

	if (set_sched_idle(ctx->holder_tid) < 0) {
		ctx->test_done = 1;
		pthread_join(ctx->holder, NULL);
		pthread_join(ctx->waiter, NULL);
		pthread_barrier_destroy(&ctx->barrier);
		DL_FAIL("set_sched_idle failed: %s", strerror(errno));
	}

	printf("[MAIN] Successfully changed holder to SCHED_IDLE\n");
	print_sched_info("HOLDER-SETSCHEDULED", ctx->holder_tid);

	/* Let the scenario play out */
	usleep(100000); /* 100ms */

	/* Signal threads to finish */
	ctx->test_done = 1;

	/* Wait for threads */
	pthread_join(ctx->holder, NULL);
	pthread_join(ctx->waiter, NULL);

	/* Cancel the alarm - we completed successfully */
	alarm(0);

	pthread_barrier_destroy(&ctx->barrier);

	DL_FAIL_IF(ctx->timeout_occurred, "Test timed out - bug was triggered!");

	printf("\n======================================\n");
	printf("Test completed successfully!\n");
	printf("======================================\n");
	printf("\nNo timeout occurred - fix appears to be working.\n");
	printf("\nCheck kernel log:\n");
	printf("  sudo dmesg | tail -50\n");
	printf("\nLook for:\n");
	printf("  'DL de-boosted task PID X: REPLENISH flag missing'\n");
	printf("  'dl_runtime_exceeded' or bandwidth warnings\n");
	printf("\n");

	return DL_TEST_PASS;
}

static enum dl_test_status test_replenish_bug_setup(void **ctx_ptr)
{
	struct replenish_test_ctx *ctx;
	pthread_mutexattr_t attr;

	ctx = calloc(1, sizeof(*ctx));
	DL_FAIL_IF(!ctx, "Failed to allocate test context");

	/* Initialize PI mutex */
	if (pthread_mutexattr_init(&attr) != 0) {
		free(ctx);
		DL_FAIL("pthread_mutexattr_init failed");
	}

	if (pthread_mutexattr_setprotocol(&attr, PTHREAD_PRIO_INHERIT) != 0) {
		pthread_mutexattr_destroy(&attr);
		free(ctx);
		DL_FAIL("pthread_mutexattr_setprotocol failed");
	}

	if (pthread_mutex_init(&ctx->pi_mutex, &attr) != 0) {
		pthread_mutexattr_destroy(&attr);
		free(ctx);
		DL_FAIL("pthread_mutex_init failed");
	}

	pthread_mutexattr_destroy(&attr);

	*ctx_ptr = ctx;
	return DL_TEST_PASS;
}

static void test_replenish_bug_cleanup(void *arg)
{
	struct replenish_test_ctx *ctx = arg;

	if (ctx) {
		pthread_mutex_destroy(&ctx->pi_mutex);
		free(ctx);
	}
}

static struct dl_test test_replenish_bug = {
	.name = "replenish_bug",
	.description = "Verify ENQUEUE_REPLENISH flag is set during PI boosting after setscheduler",
	.setup = test_replenish_bug_setup,
	.run = test_replenish_bug_run,
	.cleanup = test_replenish_bug_cleanup,
};
REGISTER_DL_TEST(&test_replenish_bug);
