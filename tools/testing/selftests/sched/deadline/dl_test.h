/* SPDX-License-Identifier: GPL-2.0 */
/*
 * SCHED_DEADLINE Test Framework
 *
 * Provides infrastructure for testing SCHED_DEADLINE scheduler functionality.
 * Tests register themselves using REGISTER_DL_TEST() macro and are
 * automatically discovered by the runner at runtime.
 */

#ifndef __DL_TEST_H__
#define __DL_TEST_H__

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* Test status return codes */
enum dl_test_status {
	DL_TEST_PASS = 0,	/* Test passed successfully */
	DL_TEST_SKIP,		/* Test skipped (feature unavailable, etc.) */
	DL_TEST_FAIL,		/* Test failed */
};

/**
 * struct dl_test - Deadline scheduler test definition
 * @name: Short test identifier (e.g., "basic_scheduling")
 * @description: Human-readable description of what the test validates
 * @setup: Optional callback to prepare test environment
 * @run: Required callback to execute test logic
 * @cleanup: Optional callback to cleanup test resources
 *
 * Tests are defined by filling in this structure and registering with
 * REGISTER_DL_TEST(). The runner will discover and execute all registered
 * tests automatically.
 */
struct dl_test {
	/**
	 * name - The name of the test
	 *
	 * Short identifier used for filtering and reporting. Should be
	 * lowercase with underscores (e.g., "bandwidth_admission").
	 */
	const char *name;

	/**
	 * description - Human-readable test description
	 *
	 * Explains what the test validates and why it's important.
	 * Displayed when test runs unless quiet mode is enabled.
	 */
	const char *description;

	/**
	 * setup - Optional setup callback
	 * @ctx: Pointer to context pointer, can be set to pass data to run()
	 *
	 * Called before run() to prepare test environment. Can allocate
	 * resources, check prerequisites, etc.
	 *
	 * Return:
	 * - DL_TEST_PASS: Continue to run()
	 * - DL_TEST_SKIP: Skip this test (feature not available, etc.)
	 * - DL_TEST_FAIL: Abort test (setup failed)
	 *
	 * If setup() returns SKIP or FAIL, run() and cleanup() are not called.
	 */
	enum dl_test_status (*setup)(void **ctx);

	/**
	 * run - Required test execution callback
	 * @ctx: Context pointer set by setup(), or NULL if no setup
	 *
	 * Executes the actual test logic. This is the main test function.
	 *
	 * Return:
	 * - DL_TEST_PASS: Test passed
	 * - DL_TEST_SKIP: Test skipped (unlikely here, prefer setup())
	 * - DL_TEST_FAIL: Test failed
	 */
	enum dl_test_status (*run)(void *ctx);

	/**
	 * cleanup - Optional cleanup callback
	 * @ctx: Context pointer set by setup(), or NULL if no setup
	 *
	 * Called after run() to cleanup resources. Always runs if setup()
	 * succeeded, regardless of run() result. Cannot fail the test.
	 */
	void (*cleanup)(void *ctx);
};

/**
 * dl_test_register() - Register a test with the framework
 * @test: Pointer to test structure
 *
 * Called by REGISTER_DL_TEST() macro. Don't call directly.
 */
void dl_test_register(struct dl_test *test);

/**
 * REGISTER_DL_TEST() - Register a test for auto-discovery
 * @__test: Pointer to struct dl_test
 *
 * Uses ELF constructor attribute to automatically register the test
 * when the binary loads. The runner will discover and execute all
 * registered tests.
 *
 * Example:
 *   static struct dl_test my_test = {
 *       .name = "my_test",
 *       .description = "Tests something important",
 *       .run = my_test_run,
 *   };
 *   REGISTER_DL_TEST(&my_test);
 */
#define __DL_CONCAT(a, b) a##b
#define _DL_CONCAT(a, b) __DL_CONCAT(a, b)

#define REGISTER_DL_TEST(__test)					\
	__attribute__((constructor))					\
	static void _DL_CONCAT(___dlregister_, __LINE__)(void)		\
	{								\
		dl_test_register(__test);				\
	}

/* Error reporting macros */

/**
 * DL_ERR() - Print error message with file/line info
 */
#define DL_ERR(__fmt, ...)						\
	do {								\
		fprintf(stderr, "ERR: %s:%d\n", __FILE__, __LINE__);	\
		fprintf(stderr, __fmt"\n", ##__VA_ARGS__);		\
	} while (0)

/**
 * DL_FAIL() - Fail the test with a message
 *
 * Prints error message and returns DL_TEST_FAIL. Use in test run() or
 * setup() functions.
 */
#define DL_FAIL(__fmt, ...)						\
	do {								\
		DL_ERR(__fmt, ##__VA_ARGS__);				\
		return DL_TEST_FAIL;					\
	} while (0)

/**
 * DL_FAIL_IF() - Conditionally fail the test
 * @__cond: Condition to check
 * @__fmt: printf-style format string
 *
 * If condition is true, fail the test with the given message.
 */
#define DL_FAIL_IF(__cond, __fmt, ...)					\
	do {								\
		if (__cond)						\
			DL_FAIL(__fmt, ##__VA_ARGS__);			\
	} while (0)

/* Comparison assertion macros */

/**
 * DL_EQ() - Assert two values are equal
 */
#define DL_EQ(_x, _y) \
	DL_FAIL_IF((_x) != (_y), \
		   "Expected %s == %s (%lld == %lld)", \
		   #_x, #_y, (long long)(_x), (long long)(_y))

/**
 * DL_NE() - Assert two values are not equal
 */
#define DL_NE(_x, _y) \
	DL_FAIL_IF((_x) == (_y), \
		   "Expected %s != %s (%lld != %lld)", \
		   #_x, #_y, (long long)(_x), (long long)(_y))

/**
 * DL_LT() - Assert x < y
 */
#define DL_LT(_x, _y) \
	DL_FAIL_IF((_x) >= (_y), \
		   "Expected %s < %s (%lld < %lld)", \
		   #_x, #_y, (long long)(_x), (long long)(_y))

/**
 * DL_LE() - Assert x <= y
 */
#define DL_LE(_x, _y) \
	DL_FAIL_IF((_x) > (_y), \
		   "Expected %s <= %s (%lld <= %lld)", \
		   #_x, #_y, (long long)(_x), (long long)(_y))

/**
 * DL_GT() - Assert x > y
 */
#define DL_GT(_x, _y) \
	DL_FAIL_IF((_x) <= (_y), \
		   "Expected %s > %s (%lld > %lld)", \
		   #_x, #_y, (long long)(_x), (long long)(_y))

/**
 * DL_GE() - Assert x >= y
 */
#define DL_GE(_x, _y) \
	DL_FAIL_IF((_x) < (_y), \
		   "Expected %s >= %s (%lld >= %lld)", \
		   #_x, #_y, (long long)(_x), (long long)(_y))

/**
 * DL_ASSERT() - Assert condition is true
 */
#define DL_ASSERT(_x) \
	DL_FAIL_IF(!(_x), "Expected %s to be true", #_x)

/**
 * DL_BUG_ON() - Fatal assertion (for framework bugs, not test failures)
 * @__cond: Condition to check
 * @__fmt: Error message
 *
 * For internal framework consistency checks. If condition is true,
 * prints error and aborts. Use for "should never happen" cases.
 */
#define DL_BUG_ON(__cond, __fmt, ...)					\
	do {								\
		if (__cond) {						\
			fprintf(stderr, "BUG: %s:%d: " __fmt "\n",	\
				__FILE__, __LINE__, ##__VA_ARGS__);	\
			abort();					\
		}							\
	} while (0)

#endif /* __DL_TEST_H__ */
