// SPDX-License-Identifier: GPL-2.0-only
/*
 * cpuhog: A simple CPU intensive program for testing scheduler behavior
 *
 * This program performs busy looping to consume CPU cycles, useful for
 * testing scheduler policies like SCHED_DEADLINE.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <time.h>

static int stop_flag;

static void signal_handler(int sig)
{
	stop_flag = 1;
}

static void usage(const char *progname)
{
	printf("Usage: %s [options]\n", progname);
	printf("Options:\n");
	printf("  -t <seconds>  Run for specified seconds (default: infinite)\n");
	printf("  -v            Verbose output\n");
	printf("  -h            Show this help\n");
}

int main(int argc, char *argv[])
{
	int opt;
	int duration = 0; /* 0 means infinite */
	int verbose = 0;
	time_t start_time, current_time;
	unsigned long long iterations = 0;
	unsigned long long last_report = 0;

	while ((opt = getopt(argc, argv, "t:vh")) != -1) {
		switch (opt) {
		case 't':
			duration = atoi(optarg);
			if (duration <= 0) {
				fprintf(stderr, "Invalid duration: %s\n", optarg);
				return 1;
			}
			break;
		case 'v':
			verbose = 1;
			break;
		case 'h':
			usage(argv[0]);
			return 0;
		default:
			usage(argv[0]);
			return 1;
		}
	}

	/* Set up signal handlers for graceful shutdown */
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	if (verbose) {
		printf("cpuhog starting (PID: %d)\n", getpid());
		if (duration > 0)
			printf("Will run for %d seconds\n", duration);
		else
			printf("Will run until interrupted\n");
	}

	start_time = time(NULL);

	/* Main busy loop */
	while (!stop_flag) {
		/* Simple busy work - incrementing a counter */
		iterations++;

		/* Check if we've reached the duration limit */
		if (duration > 0) {
			current_time = time(NULL);
			if (current_time - start_time >= duration)
				break;
		}

		/* Print progress every 100M iterations if verbose */
		if (verbose && (iterations % 100000000ULL == 0)) {
			if (iterations != last_report) {
				printf("Completed %llu iterations\n", iterations);
				last_report = iterations;
			}
		}
	}

	if (verbose) {
		current_time = time(NULL);
		printf("cpuhog finished after %ld seconds and %llu iterations\n",
		       current_time - start_time, iterations);
	}

	return 0;
}
