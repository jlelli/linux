// SPDX-License-Identifier: GPL-2.0
/*
 * SCHED_DEADLINE Test Runner
 *
 * Discovers and executes all registered SCHED_DEADLINE tests.
 * Tests are statically linked and register themselves via ELF constructors.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdbool.h>
#include "dl_test.h"

const char help_fmt[] =
"Runner for SCHED_DEADLINE scheduler tests.\n"
"\n"
"All tests are statically linked and run serially. Tests require root\n"
"privileges to set SCHED_DEADLINE scheduling policy.\n"
"\n"
"Usage: %s [-t TEST] [-h]\n"
"\n"
"  -t TEST       Only run tests whose name includes this string\n"
"  -s            Include print output for skipped tests\n"
"  -l            List all available tests\n"
"  -q            Don't print the test descriptions during run\n"
"  -h            Display this help and exit\n";

static volatile int exit_req;
static bool quiet, print_skipped, list;

#define MAX_DL_TESTS 256

static struct dl_test *__dl_tests[MAX_DL_TESTS];
static unsigned int __dl_num_tests;

static void sigint_handler(int sig)
{
	exit_req = 1;
}

static void print_test_preamble(const struct dl_test *test, bool quiet)
{
	printf("===== START =====\n");
	printf("TEST: %s\n", test->name);
	if (!quiet)
		printf("DESCRIPTION: %s\n", test->description);
	printf("OUTPUT:\n");
}

static const char *status_to_result(enum dl_test_status status)
{
	switch (status) {
	case DL_TEST_PASS:
	case DL_TEST_SKIP:
		return "ok";
	case DL_TEST_FAIL:
		return "not ok";
	default:
		return "<UNKNOWN>";
	}
}

static void print_test_result(const struct dl_test *test,
			      enum dl_test_status status,
			      unsigned int testnum)
{
	const char *result = status_to_result(status);
	const char *directive = status == DL_TEST_SKIP ? "SKIP " : "";

	printf("%s %u %s # %s\n", result, testnum, test->name, directive);
	printf("=====  END  =====\n");
}

static bool should_skip_test(const struct dl_test *test, const char *filter)
{
	return filter && !strstr(test->name, filter);
}

static enum dl_test_status run_test(const struct dl_test *test)
{
	enum dl_test_status status;
	void *context = NULL;

	if (test->setup) {
		status = test->setup(&context);
		if (status != DL_TEST_PASS)
			return status;
	}

	status = test->run(context);

	if (test->cleanup)
		test->cleanup(context);

	return status;
}

static bool test_valid(const struct dl_test *test)
{
	if (!test) {
		fprintf(stderr, "NULL test detected\n");
		return false;
	}

	if (!test->name) {
		fprintf(stderr,
			"Test with no name found. Must specify test name.\n");
		return false;
	}

	if (!test->description) {
		fprintf(stderr, "Test %s requires description.\n", test->name);
		return false;
	}

	if (!test->run) {
		fprintf(stderr, "Test %s has no run() callback\n", test->name);
		return false;
	}

	return true;
}

int main(int argc, char **argv)
{
	const char *filter = NULL;
	unsigned int testnum = 0, i;
	unsigned int passed = 0, skipped = 0, failed = 0;
	int opt;

	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);

	while ((opt = getopt(argc, argv, "qslt:h")) != -1) {
		switch (opt) {
		case 'q':
			quiet = true;
			break;
		case 's':
			print_skipped = true;
			break;
		case 'l':
			list = true;
			break;
		case 't':
			filter = optarg;
			break;
		default:
			fprintf(stderr, help_fmt, argv[0]);
			return opt != 'h';
		}
	}

	for (i = 0; i < __dl_num_tests; i++) {
		enum dl_test_status status;
		struct dl_test *test = __dl_tests[i];

		if (list) {
			printf("%s\n", test->name);
			if (i == (__dl_num_tests - 1))
				return 0;
			continue;
		}

		if (should_skip_test(test, filter)) {
			/*
			 * Printing the skipped tests and their preambles can
			 * add a lot of noise to the runner output. Printing
			 * this is only really useful for CI, so let's skip it
			 * by default.
			 */
			if (print_skipped) {
				print_test_preamble(test, quiet);
				print_test_result(test, DL_TEST_SKIP, ++testnum);
			}
			continue;
		}

		print_test_preamble(test, quiet);
		status = run_test(test);
		print_test_result(test, status, ++testnum);

		switch (status) {
		case DL_TEST_PASS:
			passed++;
			break;
		case DL_TEST_SKIP:
			skipped++;
			break;
		case DL_TEST_FAIL:
			failed++;
			break;
		}

		if (exit_req) {
			fprintf(stderr, "\nInterrupted by signal\n");
			break;
		}
	}

	printf("\n\n=============================\n\n");
	printf("RESULTS:\n\n");
	printf("PASSED:  %u\n", passed);
	printf("SKIPPED: %u\n", skipped);
	printf("FAILED:  %u\n", failed);

	return failed > 0 ? 1 : 0;
}

void dl_test_register(struct dl_test *test)
{
	DL_BUG_ON(!test_valid(test), "Invalid test found");
	DL_BUG_ON(__dl_num_tests >= MAX_DL_TESTS, "Maximum tests exceeded");

	__dl_tests[__dl_num_tests++] = test;
}
