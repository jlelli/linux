// SPDX-License-Identifier: GPL-2.0-only
/*
 * SCHED_DEADLINE demotion stress test
 *
 * Creates multiple DEADLINE tasks with demotion enabled and runs them
 * to stress test the demotion/promotion state machine, especially with
 * migration scenarios.
 */

#define _GNU_SOURCE
#include <sched.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <signal.h>

#ifndef SCHED_FLAG_DL_DEMOTION
#define SCHED_FLAG_DL_DEMOTION 0x80
#endif

#define NSEC_PER_SEC 1000000000ULL

static volatile int keep_running = 1;

/* Wrappers for sched_setattr/getattr - use syscall directly to avoid glibc conflicts */
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

/* Signal handler for clean shutdown */
static void sigint_handler(int sig)
{
	(void)sig;
	keep_running = 0;
}

/* Burn CPU cycles */
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

/* Thread function - repeatedly exhaust runtime and get demoted/promoted */
static void *worker_thread(void *arg)
{
	int thread_id = *(int *)arg;
	struct sched_attr attr = {0};
	int cycles = 0;
	cpu_set_t cpuset;

	/* Set CPU affinity to allow migration */
	CPU_ZERO(&cpuset);
	/* Allow running on CPUs 0-3 (adjust based on system) */
	for (int i = 0; i < 4 && i < sysconf(_SC_NPROCESSORS_ONLN); i++)
		CPU_SET(i, &cpuset);
	pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);

	/* Set DEADLINE with demotion */
	attr.size = sizeof(attr);
	attr.sched_policy = SCHED_DEADLINE;
	attr.sched_runtime = 20 * 1000 * 1000;   /* 20ms */
	attr.sched_deadline = 100 * 1000 * 1000; /* 100ms */
	attr.sched_period = 100 * 1000 * 1000;   /* 100ms */
	attr.sched_flags = SCHED_FLAG_DL_DEMOTION;
	attr.sched_nice = thread_id % 10;  /* Different nice values */

	if (sys_sched_setattr(0, &attr, 0) < 0) {
		perror("sched_setattr");
		return NULL;
	}

	printf("Thread %d: Started with SCHED_DEADLINE (runtime=20ms, period=100ms, nice=%d)\n",
	       thread_id, attr.sched_nice);

	while (keep_running) {
		/* Burn CPU to exhaust runtime and trigger demotion */
		burn_cpu(25 * 1000 * 1000); /* 25ms - exceeds 20ms runtime */

		/* Now we should be demoted - do some light work as NORMAL */
		usleep(10 * 1000); /* 10ms */

		/* Wait for promotion (period expiry) */
		usleep(120 * 1000); /* 120ms - exceeds 100ms period */

		cycles++;
		if (cycles % 10 == 0) {
			printf("Thread %d: Completed %d demotion/promotion cycles\n",
			       thread_id, cycles);
		}
	}

	printf("Thread %d: Exiting after %d cycles\n", thread_id, cycles);

	/* Reset to normal before exiting */
	attr.sched_policy = SCHED_NORMAL;
	sys_sched_setattr(0, &attr, 0);

	return NULL;
}

int main(int argc, char *argv[])
{
	int num_threads = 4;
	pthread_t *threads;
	int *thread_ids;
	int duration = 10; /* seconds */

	/* Parse arguments */
	if (argc > 1)
		num_threads = atoi(argv[1]);
	if (argc > 2)
		duration = atoi(argv[2]);

	if (num_threads < 1 || num_threads > 32) {
		fprintf(stderr, "Number of threads must be 1-32\n");
		return 1;
	}

	printf("SCHED_DEADLINE Demotion Stress Test\n");
	printf("====================================\n");
	printf("Threads: %d\n", num_threads);
	printf("Duration: %d seconds\n", duration);
	printf("Press Ctrl+C to stop early\n\n");

	/* Check permissions */
	struct sched_attr attr = {0};
	attr.size = sizeof(attr);
	attr.sched_policy = SCHED_DEADLINE;
	attr.sched_runtime = 10 * 1000 * 1000;
	attr.sched_deadline = 100 * 1000 * 1000;
	attr.sched_period = 100 * 1000 * 1000;

	if (sys_sched_setattr(0, &attr, 0) < 0) {
		if (errno == EPERM) {
			fprintf(stderr, "Need CAP_SYS_NICE or root privileges\n");
			return 1;
		} else if (errno == EINVAL) {
			fprintf(stderr, "SCHED_DEADLINE or SCHED_FLAG_DL_DEMOTION not supported\n");
			return 1;
		}
	}
	attr.sched_policy = SCHED_NORMAL;
	sys_sched_setattr(0, &attr, 0);

	/* Set up signal handler */
	signal(SIGINT, sigint_handler);

	/* Allocate thread arrays */
	threads = malloc(num_threads * sizeof(pthread_t));
	thread_ids = malloc(num_threads * sizeof(int));
	if (!threads || !thread_ids) {
		fprintf(stderr, "Memory allocation failed\n");
		return 1;
	}

	/* Create threads */
	for (int i = 0; i < num_threads; i++) {
		thread_ids[i] = i;
		if (pthread_create(&threads[i], NULL, worker_thread, &thread_ids[i]) != 0) {
			perror("pthread_create");
			keep_running = 0;
			break;
		}
	}

	/* Run for specified duration */
	sleep(duration);
	keep_running = 0;

	/* Wait for threads to finish */
	printf("\nWaiting for threads to finish...\n");
	for (int i = 0; i < num_threads; i++) {
		pthread_join(threads[i], NULL);
	}

	free(threads);
	free(thread_ids);

	printf("\nStress test completed successfully\n");
	return 0;
}
