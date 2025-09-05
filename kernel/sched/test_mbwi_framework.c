// SPDX-License-Identifier: GPL-2.0+
/*
 * General M-BWI (Multiprocessor Bandwidth Inheritance) Test Framework
 *
 * This framework provides a flexible way to define and test M-BWI scenarios
 * with SCHED_DEADLINE tasks using a simple grammar for specifying:
 * - Task parameters (runtime, period, deadline)
 * - Execution phases (work, critical sections, nested locking)
 * - Resource dependencies and blocking chains
 *
 * The framework automatically creates tasks, manages their lifecycle,
 * and collects comprehensive statistics to validate M-BWI correctness.
 *
 * Copyright (C) 2025 Red Hat, Inc.
 * Author: Juri Lelli <juri.lelli@redhat.com>
 */

#define MODULE_NAME "test_mbwi_framework"
#define pr_fmt(fmt) MODULE_NAME ": " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/sched.h>
#include <linux/sched/deadline.h>
#include <linux/mutex.h>
#include <linux/smp.h>
#include <linux/slab.h>
#include <linux/completion.h>
#include <linux/atomic.h>
#include <linux/time64.h>
#include <linux/hrtimer.h>
#include <uapi/linux/sched/types.h>
#include "mbwi_framework.h"
#include "mbwi_examples.h"

#define TEST_DURATION_SEC	30

/* Task runtime state */
struct mbwi_task {
	struct task_struct *kthread;
	struct mbwi_task_def *def;
	atomic64_t jobs_completed;
	atomic64_t deadline_misses;
	atomic64_t total_blocking_ns;
	atomic64_t max_blocking_ns;
	atomic64_t cs_acquisitions[MAX_RESOURCES];
	struct mbwi_wakeup_stats wakeup_stats;
	ktime_t period_start_time;
	u64 period_count;
	int nesting_level;		/* Current mutex nesting level for lockdep */
	bool held_locks[MAX_RESOURCES];	/* Track which locks are held for cleanup */
};

/* Test framework state */
static struct {
	struct mbwi_task tasks[MAX_TASKS];
	struct mbwi_resource resources[MAX_RESOURCES];
	int num_tasks;
	int num_resources;
	atomic_t test_running;
	struct completion test_start;
	struct completion test_complete;
} framework;


/*
 * Helper functions
 */

/*
 * Initialize wakeup statistics
 */
static void init_wakeup_stats(struct mbwi_wakeup_stats *stats)
{
	atomic64_set(&stats->total_wakeups, 0);
	atomic64_set(&stats->total_latency_ns, 0);
	atomic64_set(&stats->max_latency_ns, 0);
	atomic64_set(&stats->min_latency_ns, S64_MAX);
	atomic64_set(&stats->early_wakeups, 0);
	atomic64_set(&stats->late_wakeups, 0);
}

/*
 * Record wakeup latency statistics
 */
static void record_wakeup_latency(struct mbwi_wakeup_stats *stats, 
				  ktime_t expected, ktime_t actual, const char *task_name)
{
	s64 latency_ns = ktime_to_ns(ktime_sub(actual, expected));
	u64 abs_latency = abs(latency_ns);
	u64 old_max_latency;
	
	atomic64_inc(&stats->total_wakeups);
	atomic64_add(abs_latency, &stats->total_latency_ns);
	
	/* Update maximum latency atomically */
	do {
		old_max_latency = atomic64_read(&stats->max_latency_ns);
		if (abs_latency <= old_max_latency)
			break;  /* Not a new maximum */
	} while (atomic64_cmpxchg(&stats->max_latency_ns, old_max_latency, abs_latency) != old_max_latency);
	
	if (abs_latency > old_max_latency) {
		trace_printk("Task %s: NEW MAX wakeup latency: %llu ns (was %llu ns)\n", 
			     task_name, abs_latency, old_max_latency);
	}
	
	/* Update minimum latency atomically */
	u64 old_min_latency;
	do {
		old_min_latency = atomic64_read(&stats->min_latency_ns);
		if (abs_latency >= old_min_latency)
			break;  /* Not a new minimum */
	} while (atomic64_cmpxchg(&stats->min_latency_ns, old_min_latency, abs_latency) != old_min_latency);
	
	if (abs_latency < old_min_latency && old_min_latency != S64_MAX) {
		trace_printk("Task %s: NEW MIN wakeup latency: %llu ns (was %llu ns)\n", 
			     task_name, abs_latency, old_min_latency);
	}
	
	/* Count early vs late wakeups */
	if (latency_ns < 0)
		atomic64_inc(&stats->early_wakeups);
	else if (latency_ns > 0)
		atomic64_inc(&stats->late_wakeups);
}

/*
 * Sleep until next period using hrtimer
 */
static int sleep_until_next_period(struct mbwi_task *task)
{
	ktime_t next_period, now;
	int ret;
	
	/* Calculate next period time */
	next_period = ktime_add_ns(task->period_start_time, 
				   task->period_count * task->def->period_ns);
	
	now = ktime_get();
	
	/* Check if we're already past the next period */
	if (ktime_after(now, next_period)) {
		/* We've missed our period - this indicates a problem */
		u64 miss_ns = ktime_to_ns(ktime_sub(now, next_period));
		trace_printk("Task %s: ⚠ MISSED period %llu by %lld ns\n",
			     task->def->name, task->period_count, miss_ns);
		pr_warn("Task %s: Missed period %llu by %lld ns\n",
			task->def->name, task->period_count, miss_ns);
		
		/* Advance to next valid period to avoid catching up */
		u64 periods_missed = miss_ns / task->def->period_ns + 1;
		task->period_count += periods_missed;
		next_period = ktime_add_ns(task->period_start_time,
					   task->period_count * task->def->period_ns);
	}
	
	trace_printk("Task %s: now %llu next_period %llu\n",
		     task->def->name, now, next_period);

	set_current_state(TASK_INTERRUPTIBLE);
	ret = schedule_hrtimeout(&next_period, HRTIMER_MODE_ABS_HARD);
	
	/* Record wakeup latency (current time vs expected time) */
	now = ktime_get();
	record_wakeup_latency(&task->wakeup_stats, next_period, now, task->def->name);
	
	task->period_count++;
	return ret;
}

static void simulate_work(u64 duration_ns)
{
	ktime_t start = ktime_get();
	ktime_t end = ktime_add_ns(start, duration_ns);
	
	while (ktime_before(ktime_get(), end)) {
		cpu_relax();
		if (!atomic_read(&framework.test_running))
			break;
	}
}

static int set_dl_params(struct mbwi_task_def *def)
{
	struct sched_attr attr;
	
	memset(&attr, 0, sizeof(attr));
	attr.size = sizeof(attr);
	attr.sched_policy = SCHED_DEADLINE;
	attr.sched_runtime = def->runtime_ns;
	attr.sched_period = def->period_ns;
	attr.sched_deadline = def->deadline_ns;
	attr.sched_flags = SCHED_FLAG_RECLAIM;
	
	return sched_setattr_nocheck(current, &attr);
}

static void set_task_affinity(int cpu)
{
	struct cpumask mask;
	
	if (cpu < 0 || cpu >= num_online_cpus())
		return;
		
	cpumask_clear(&mask);
	cpumask_set_cpu(cpu, &mask);
	set_cpus_allowed_ptr(current, &mask);
}

/*
 * Release all locks held by a task (for cleanup on test termination)
 */
static void cleanup_task_locks(struct mbwi_task *task)
{
	int resource_id;
	
	/* Release locks in reverse order (LIFO) based on nesting level */
	while (task->nesting_level > 0) {
		/* Find which lock to release by scanning the held_locks array */
		for (resource_id = MAX_RESOURCES - 1; resource_id >= 0; resource_id--) {
			if (task->held_locks[resource_id]) {
				task->nesting_level--;
				task->held_locks[resource_id] = false;
				trace_printk("Task %s: CLEANUP UNLOCK R%d (nesting=%d)\n", 
					     task->def->name, resource_id, task->nesting_level);
				mutex_unlock(&framework.resources[resource_id].lock);
				break;
			}
		}
	}
	
	if (task->nesting_level != 0) {
		pr_warn("Task %s: Lock cleanup completed but nesting_level=%d\n", 
			task->def->name, task->nesting_level);
		task->nesting_level = 0;
	}
}

/*
 * Execute a sequence of phases for a task
 */
static int execute_task_phases(struct mbwi_task *task)
{
	struct exec_phase *phase;
	ktime_t period_start, cs_start, cs_end;
	u64 blocking_time;
	int i;
	bool test_terminated = false;

	period_start = ktime_get();

	for (i = 0; i < MAX_PHASES; i++) {
		phase = &task->def->phases[i];
		
		if (phase->type == PHASE_END)
			break;

		switch (phase->type) {
		case PHASE_WORK:
			trace_printk("Task %s: WORK phase %llu ns\n", 
				     task->def->name, phase->work_ns);
			simulate_work(phase->work_ns);
			break;

		case PHASE_LOCK:
			if (phase->resource_id >= MAX_RESOURCES) {
				pr_err("Invalid resource ID: %d\n", phase->resource_id);
				cleanup_task_locks(task);
				return -EINVAL;
			}
			trace_printk("Task %s: LOCK R%d (nesting=%d)\n", 
				     task->def->name, phase->resource_id, task->nesting_level);
			cs_start = ktime_get();
			/* Use nested locking to avoid lockdep complaints with nested critical sections */
			mutex_lock_nested(&framework.resources[phase->resource_id].lock, task->nesting_level);
			task->held_locks[phase->resource_id] = true;
			task->nesting_level++;
			cs_end = ktime_get();
			
			/* Track blocking statistics */
			blocking_time = ktime_to_ns(ktime_sub(cs_end, cs_start));
			if (blocking_time > 0) {
				trace_printk("Task %s: BLOCKED on R%d for %llu ns\n",
					     task->def->name, phase->resource_id, blocking_time);
				atomic64_add(blocking_time, &task->total_blocking_ns);
				
				/* Update maximum blocking time atomically */
				u64 old_max_blocking;
				do {
					old_max_blocking = atomic64_read(&task->max_blocking_ns);
					if (blocking_time <= old_max_blocking)
						break;  /* Not a new maximum */
				} while (atomic64_cmpxchg(&task->max_blocking_ns, old_max_blocking, blocking_time) != old_max_blocking);
				
				if (blocking_time > old_max_blocking) {
					trace_printk("Task %s: NEW MAX blocking time: %llu ns (was %llu ns) on R%d\n", 
						     task->def->name, blocking_time, old_max_blocking, phase->resource_id);
				}
			}
			
			atomic64_inc(&task->cs_acquisitions[phase->resource_id]);
			atomic64_inc(&framework.resources[phase->resource_id].acquisitions);
			if (blocking_time > 0)
				atomic64_inc(&framework.resources[phase->resource_id].contentions);
			break;

		case PHASE_UNLOCK:
			if (phase->resource_id >= MAX_RESOURCES) {
				pr_err("Invalid resource ID: %d\n", phase->resource_id);
				cleanup_task_locks(task);
				return -EINVAL;
			}
			if (!task->held_locks[phase->resource_id]) {
				pr_err("Task %s: Attempting to unlock R%d that is not held\n",
				       task->def->name, phase->resource_id);
				cleanup_task_locks(task);
				return -EINVAL;
			}
			task->nesting_level--;
			task->held_locks[phase->resource_id] = false;
			trace_printk("Task %s: UNLOCK R%d (nesting=%d)\n", 
				     task->def->name, phase->resource_id, task->nesting_level);
			mutex_unlock(&framework.resources[phase->resource_id].lock);
			break;

		case PHASE_WORK_CS:
			trace_printk("Task %s: WORK_CS phase %llu ns\n",
				     task->def->name, phase->work_ns);
			simulate_work(phase->work_ns);
			break;

		default:
			pr_err("Unknown phase type: %d\n", phase->type);
			cleanup_task_locks(task);
			return -EINVAL;
		}

		if (!atomic_read(&framework.test_running)) {
			test_terminated = true;
			trace_printk("Task %s: Test termination detected during phase execution\n", 
				     task->def->name);
			break;
		}
	}

	/* Clean up any held locks if test was terminated early */
	if (test_terminated) {
		trace_printk("Task %s: Cleaning up locks due to test termination\n", 
			     task->def->name);
		cleanup_task_locks(task);
		return -EINTR; /* Signal early termination */
	}

	atomic64_inc(&task->jobs_completed);

	/* Check for deadline miss */
	if (ktime_after(ktime_get(), ktime_add_ns(period_start, task->def->deadline_ns))) {
		atomic64_inc(&task->deadline_misses);
		trace_printk("Task %s: ⚠ DEADLINE MISS detected!\n", task->def->name);
		pr_warn("Task %s: Deadline miss detected!\n", task->def->name);
	}

	return 0;
}

/*
 * Generic task thread function
 */
static int mbwi_task_thread(void *data)
{
	struct mbwi_task *task = (struct mbwi_task *)data;
	int ret;

	/* Set CPU affinity if specified */
	if (task->def->cpu_affinity >= 0)
		set_task_affinity(task->def->cpu_affinity);

	/* Initialize timing and statistics */
	init_wakeup_stats(&task->wakeup_stats);
	task->period_count = 0;

	/* Wait for test start signal */
	wait_for_completion(&framework.test_start);

	trace_printk("Task %s: STARTING with DL params (runtime=%llu, period=%llu, deadline=%llu)\n",
		     task->def->name, task->def->runtime_ns, task->def->period_ns, task->def->deadline_ns);
	pr_info("Task %s: Starting with DL params (runtime=%llu, period=%llu, deadline=%llu)\n",
		task->def->name, task->def->runtime_ns, task->def->period_ns, task->def->deadline_ns);

	/* Set SCHED_DEADLINE parameters */
	ret = set_dl_params(task->def);
	if (ret) {
		pr_err("Task %s: Failed to set SCHED_DEADLINE parameters: %d\n",
		       task->def->name, ret);
		return ret;
	}

	/* Record initial period start time */
	task->period_start_time = ktime_get();
	task->period_count = 1;

	while (atomic_read(&framework.test_running)) {
		task->nesting_level = 0;
		/* Reset held locks array for new period */
		memset(task->held_locks, false, sizeof(task->held_locks));
		trace_printk("Task %s: Starting period %llu (now %llu)\n",
			     task->def->name, task->period_count, ktime_get());
		
		ret = execute_task_phases(task);
		if (ret) {
			trace_printk("Task %s: Phase execution failed: %d\n", task->def->name, ret);
			break;
		}

		ret = sleep_until_next_period(task);
		if (ret < 0 && ret != -EINTR) {
			trace_printk("Task %s: Sleep failed: %d\n", task->def->name, ret);
			break;
		}
	}

	trace_printk("Task %s: EXITING after %llu periods\n", task->def->name, task->period_count);
	pr_info("Task %s: Exiting after %llu periods\n", task->def->name, task->period_count);
	return 0;
}

/*
 * Initialize framework statistics
 */
static void init_framework_stats(void)
{
	int i, j;

	for (i = 0; i < framework.num_tasks; i++) {
		atomic64_set(&framework.tasks[i].jobs_completed, 0);
		atomic64_set(&framework.tasks[i].deadline_misses, 0);
		atomic64_set(&framework.tasks[i].total_blocking_ns, 0);
		atomic64_set(&framework.tasks[i].max_blocking_ns, 0);
		init_wakeup_stats(&framework.tasks[i].wakeup_stats);
		framework.tasks[i].period_count = 0;
		
		for (j = 0; j < MAX_RESOURCES; j++)
			atomic64_set(&framework.tasks[i].cs_acquisitions[j], 0);
	}

	for (i = 0; i < framework.num_resources; i++) {
		atomic64_set(&framework.resources[i].acquisitions, 0);
		atomic64_set(&framework.resources[i].contentions, 0);
	}
}

/*
 * Print comprehensive test results
 */
static void print_framework_results(void)
{
	int i, j;
	u64 total_deadline_misses = 0;
	bool temporal_isolation_ok = true;

	pr_info("=== M-BWI Framework Test Results ===\n");

	/* Per-task statistics */
	for (i = 0; i < framework.num_tasks; i++) {
		struct mbwi_task *task = &framework.tasks[i];
		struct mbwi_wakeup_stats *ws = &task->wakeup_stats;
		u64 deadline_misses = atomic64_read(&task->deadline_misses);
		u64 total_wakeups = atomic64_read(&ws->total_wakeups);
		u64 total_latency = atomic64_read(&ws->total_latency_ns);
		u64 avg_latency = total_wakeups > 0 ? total_latency / total_wakeups : 0;
		
		pr_info("Task %s: Jobs=%lld, Periods=%llu, Deadline_misses=%lld\n",
			task->def->name,
			atomic64_read(&task->jobs_completed),
			task->period_count,
			deadline_misses);
			
		pr_info("        Blocking: Total=%lld ns, Max=%lld ns\n",
			atomic64_read(&task->total_blocking_ns),
			atomic64_read(&task->max_blocking_ns));
			
		pr_info("        Wakeup latency: Avg=%lld ns, Max=%lld ns, Min=%lld ns\n",
			avg_latency,
			atomic64_read(&ws->max_latency_ns),
			atomic64_read(&ws->min_latency_ns) == S64_MAX ? 0 : atomic64_read(&ws->min_latency_ns));
			
		pr_info("        Wakeup timing: Early=%lld, OnTime=%lld, Late=%lld\n",
			atomic64_read(&ws->early_wakeups),
			total_wakeups - atomic64_read(&ws->early_wakeups) - atomic64_read(&ws->late_wakeups),
			atomic64_read(&ws->late_wakeups));

		/* Print per-resource CS acquisitions */
		for (j = 0; j < framework.num_resources; j++) {
			u64 acquisitions = atomic64_read(&task->cs_acquisitions[j]);
			if (acquisitions > 0) {
				pr_info("        %s acquisitions: %lld\n",
					framework.resources[j].name, acquisitions);
			}
		}

		total_deadline_misses += deadline_misses;
		
		/* Check temporal isolation for tasks with no resource access */
		if (deadline_misses > 0) {
			bool accesses_resources = false;
			for (j = 0; j < MAX_PHASES; j++) {
				if (task->def->phases[j].type == PHASE_LOCK) {
					accesses_resources = true;
					break;
				}
				if (task->def->phases[j].type == PHASE_END)
					break;
			}
			if (!accesses_resources) {
				pr_err("✗ Temporal isolation VIOLATED for task %s (no resources, but missed %lld deadlines)\n",
				       task->def->name, deadline_misses);
				temporal_isolation_ok = false;
			}
		}
	}

	/* Per-resource statistics */
	pr_info("\n=== Resource Statistics ===\n");
	for (i = 0; i < framework.num_resources; i++) {
		struct mbwi_resource *res = &framework.resources[i];
		u64 acquisitions = atomic64_read(&res->acquisitions);
		u64 contentions = atomic64_read(&res->contentions);
		
		if (acquisitions > 0) {
			pr_info("Resource %s: Acquisitions=%lld, Contentions=%lld\n",
				res->name, acquisitions, contentions);
		}
	}

	/* Overall validation */
	pr_info("\n=== M-BWI Validation Results ===\n");
	if (temporal_isolation_ok) {
		pr_info("✓ Temporal isolation maintained for non-interacting tasks\n");
	} else {
		pr_err("✗ Temporal isolation VIOLATED\n");
	}

	if (total_deadline_misses == 0) {
		pr_info("✓ All tasks met their deadlines - M-BWI working correctly\n");
	} else {
		pr_warn("⚠ %lld total deadline misses detected\n", total_deadline_misses);
	}
}

/*
 * Load a taskset definition into the framework
 */
static int load_taskset(struct mbwi_task_def *taskset, int num_tasks,
			struct mbwi_resource *resources, int num_resources)
{
	int i;

	if (num_tasks > MAX_TASKS) {
		pr_err("Too many tasks: %d (max %d)\n", num_tasks, MAX_TASKS);
		return -EINVAL;
	}

	if (num_resources > MAX_RESOURCES) {
		pr_err("Too many resources: %d (max %d)\n", num_resources, MAX_RESOURCES);
		return -EINVAL;
	}

	framework.num_tasks = num_tasks;
	framework.num_resources = num_resources;

	/* Copy task definitions */
	for (i = 0; i < num_tasks; i++) {
		framework.tasks[i].def = &taskset[i];
		framework.tasks[i].kthread = NULL;
		framework.tasks[i].nesting_level = 0;
		/* Initialize held_locks array */
		memset(framework.tasks[i].held_locks, false, sizeof(framework.tasks[i].held_locks));
	}

	/* Initialize resources */
	for (i = 0; i < num_resources; i++) {
		framework.resources[i] = resources[i];
		mutex_init(&framework.resources[i].lock);
		atomic64_set(&framework.resources[i].acquisitions, 0);
		atomic64_set(&framework.resources[i].contentions, 0);
	}

	return 0;
}

/*
 * Start the framework test
 */
static int run_framework_test(void)
{
	int i, ret = 0;

	pr_info("Starting M-BWI framework test with %d tasks, %d resources for %d seconds\n",
		framework.num_tasks, framework.num_resources, TEST_DURATION_SEC);

	init_framework_stats();
	atomic_set(&framework.test_running, 1);

	/* Create all task threads */
	for (i = 0; i < framework.num_tasks; i++) {
		framework.tasks[i].kthread = kthread_run(mbwi_task_thread,
							 &framework.tasks[i],
							 "mbwi_%s", framework.tasks[i].def->name);
		if (IS_ERR(framework.tasks[i].kthread)) {
			ret = PTR_ERR(framework.tasks[i].kthread);
			pr_err("Failed to create task %s: %d\n",
			       framework.tasks[i].def->name, ret);
			framework.tasks[i].kthread = NULL;
			goto cleanup;
		}
	}

	/* Give tasks time to set up their DL parameters */
	msleep(200);

	trace_printk("M-BWI Framework: STARTING test execution...\n");
	pr_info("Starting test execution...\n");
	complete_all(&framework.test_start);

	/* Run test for specified duration */
	msleep(TEST_DURATION_SEC * 1000);

	/* Stop the test */
	trace_printk("M-BWI Framework: STOPPING test execution after %d seconds\n", TEST_DURATION_SEC);
	atomic_set(&framework.test_running, 0);

cleanup:
	/* Wait for tasks to complete and clean up */
	for (i = 0; i < framework.num_tasks; i++) {
		if (framework.tasks[i].kthread) {
			kthread_stop(framework.tasks[i].kthread);
			framework.tasks[i].kthread = NULL;
		}
	}

	print_framework_results();
	return ret;
}

/* Current test scenario selection */
static int current_scenario = 0;

/* Test scenario definitions */
struct test_scenario {
	const char *name;
	const char *description;
	struct mbwi_task_def *taskset;
	int num_tasks;
	struct mbwi_resource *resources;
	int num_resources;
};

static struct test_scenario scenarios[] = {
	{
		.name = "basic_mbwi",
		.description = "Basic M-BWI scenario from m-bwi.txt",
		.taskset = basic_mbwi_taskset,
		.num_tasks = ARRAY_SIZE(basic_mbwi_taskset),
		.resources = basic_mbwi_resources,
		.num_resources = ARRAY_SIZE(basic_mbwi_resources),
	},
	{
		.name = "dependency_chain",
		.description = "Complex dependency chain test",
		.taskset = chain_taskset,
		.num_tasks = ARRAY_SIZE(chain_taskset),
		.resources = chain_resources,
		.num_resources = ARRAY_SIZE(chain_resources),
	},
	{
		.name = "cross_cpu_migration",
		.description = "Cross-CPU migration test",
		.taskset = migration_taskset,
		.num_tasks = ARRAY_SIZE(migration_taskset),
		.resources = migration_resources,
		.num_resources = ARRAY_SIZE(migration_resources),
	},
	{
		.name = "reader_writer",
		.description = "Reader-Writer pattern simulation",
		.taskset = rw_taskset,
		.num_tasks = ARRAY_SIZE(rw_taskset),
		.resources = rw_resources,
		.num_resources = ARRAY_SIZE(rw_resources),
	},
	{
		.name = "stress_test",
		.description = "Stress test with many tasks and resources",
		.taskset = stress_taskset,
		.num_tasks = ARRAY_SIZE(stress_taskset),
		.resources = stress_resources,
		.num_resources = ARRAY_SIZE(stress_resources),
	},
};

/*
 * Sysfs interface
 */
static ssize_t mbwi_framework_test_store(struct kobject *kobj, struct kobj_attribute *attr,
					 const char *buf, size_t count)
{
	struct test_scenario *scenario;
	int ret;

	if (atomic_read(&framework.test_running)) {
		pr_warn("M-BWI framework test already running\n");
		return -EBUSY;
	}

	if (current_scenario >= ARRAY_SIZE(scenarios)) {
		pr_err("Invalid scenario index: %d\n", current_scenario);
		return -EINVAL;
	}

	scenario = &scenarios[current_scenario];
	trace_printk("M-BWI Framework: LOADING scenario '%s': %s\n", scenario->name, scenario->description);
	pr_info("Loading scenario '%s': %s\n", scenario->name, scenario->description);

	/* Load the selected taskset */
	ret = load_taskset(scenario->taskset, scenario->num_tasks,
			   scenario->resources, scenario->num_resources);
	if (ret) {
		pr_err("Failed to load taskset: %d\n", ret);
		return ret;
	}

	ret = run_framework_test();
	if (ret)
		return ret;

	return count;
}

static ssize_t scenario_store(struct kobject *kobj, struct kobj_attribute *attr,
			      const char *buf, size_t count)
{
	int scenario_id;

	if (atomic_read(&framework.test_running)) {
		pr_warn("Cannot change scenario while test is running\n");
		return -EBUSY;
	}

	if (kstrtoint(buf, 10, &scenario_id) || 
	    scenario_id < 0 || scenario_id >= ARRAY_SIZE(scenarios)) {
		pr_err("Invalid scenario ID. Valid range: 0-%zu\n", ARRAY_SIZE(scenarios) - 1);
		return -EINVAL;
	}

	current_scenario = scenario_id;
	pr_info("Selected scenario %d: %s\n", scenario_id, scenarios[scenario_id].name);

	return count;
}

static ssize_t scenario_show(struct kobject *kobj, struct kobj_attribute *attr,
			     char *buf)
{
	int i, len = 0;

	len += sprintf(buf + len, "Available Test Scenarios\n");
	len += sprintf(buf + len, "========================\n");
	
	for (i = 0; i < ARRAY_SIZE(scenarios); i++) {
		len += sprintf(buf + len, "%s%d: %s - %s\n",
			       (i == current_scenario) ? "* " : "  ",
			       i, scenarios[i].name, scenarios[i].description);
	}
	
	len += sprintf(buf + len, "\nCurrent scenario: %d (%s)\n",
		       current_scenario, scenarios[current_scenario].name);
	len += sprintf(buf + len, "Write scenario number to change selection\n");

	return len;
}

static ssize_t mbwi_framework_test_show(struct kobject *kobj, struct kobj_attribute *attr,
					char *buf)
{
	return sprintf(buf, 
		"M-BWI Framework Test\n"
		"===================\n"
		"Write anything to start test with example taskset from m-bwi.txt:\n"
		"- τA: (3ms/10ms/10ms) - R1 access\n"
		"- τB: (4ms/12ms/12ms) - R1 access\n"
		"- τC: (5ms/15ms/15ms) - Nested R1→R2 access\n"
		"- τD: (2ms/8ms/8ms) - No resources (isolation test)\n"
		"\n"
		"Current status: %s\n",
		atomic_read(&framework.test_running) ? "RUNNING" : "STOPPED"
	);
}

static struct kobj_attribute mbwi_framework_test_attr =
	__ATTR(run_test, 0644, mbwi_framework_test_show, mbwi_framework_test_store);

static struct kobj_attribute scenario_attr =
	__ATTR(scenario, 0644, scenario_show, scenario_store);

static ssize_t taskset_info_show(struct kobject *kobj, struct kobj_attribute *attr,
				 char *buf)
{
	struct test_scenario *scenario;
	int i, j, len = 0;
	
	if (current_scenario >= ARRAY_SIZE(scenarios))
		return sprintf(buf, "Invalid scenario selected\n");
		
	scenario = &scenarios[current_scenario];
	
	len += sprintf(buf + len, "Current Scenario: %s\n", scenario->name);
	len += sprintf(buf + len, "Description: %s\n", scenario->description);
	len += sprintf(buf + len, "============================\n");
	
	for (i = 0; i < scenario->num_tasks; i++) {
		struct mbwi_task_def *def = &scenario->taskset[i];
		len += sprintf(buf + len, "Task %s: runtime=%llu ns, period=%llu ns, deadline=%llu ns",
			       def->name, def->runtime_ns, def->period_ns, def->deadline_ns);
		if (def->cpu_affinity >= 0)
			len += sprintf(buf + len, ", CPU=%d", def->cpu_affinity);
		len += sprintf(buf + len, "\n");
		
		len += sprintf(buf + len, "  Phases: ");
		for (j = 0; j < MAX_PHASES && def->phases[j].type != PHASE_END; j++) {
			switch (def->phases[j].type) {
			case PHASE_WORK:
				len += sprintf(buf + len, "WORK(%llu ns) ", def->phases[j].work_ns);
				break;
			case PHASE_LOCK:
				len += sprintf(buf + len, "LOCK(%s) ", 
					       scenario->resources[def->phases[j].resource_id].name);
				break;
			case PHASE_UNLOCK:
				len += sprintf(buf + len, "UNLOCK(%s) ",
					       scenario->resources[def->phases[j].resource_id].name);
				break;
			case PHASE_WORK_CS:
				len += sprintf(buf + len, "WORK_CS(%llu ns) ", def->phases[j].work_ns);
				break;
			default:
				break;
			}
		}
		len += sprintf(buf + len, "\n");
	}
	
	len += sprintf(buf + len, "\nResources: ");
	for (i = 0; i < scenario->num_resources; i++) {
		len += sprintf(buf + len, "%s ", scenario->resources[i].name);
	}
	len += sprintf(buf + len, "\n");
	
	return len;
}

static struct kobj_attribute taskset_info_attr =
	__ATTR(taskset_info, 0444, taskset_info_show, NULL);

static struct attribute *mbwi_framework_attrs[] = {
	&mbwi_framework_test_attr.attr,
	&scenario_attr.attr,
	&taskset_info_attr.attr,
	NULL,
};

static struct attribute_group mbwi_framework_attr_group = {
	.attrs = mbwi_framework_attrs,
};

static struct kobject *mbwi_framework_kobj;

static int __init test_mbwi_framework_init(void)
{
	int ret;

	pr_info("M-BWI test framework loaded\n");

	/* Initialize framework state */
	atomic_set(&framework.test_running, 0);
	init_completion(&framework.test_start);
	init_completion(&framework.test_complete);

	/* Create sysfs interface */
	mbwi_framework_kobj = kobject_create_and_add("mbwi_framework", kernel_kobj);
	if (!mbwi_framework_kobj) {
		pr_err("Failed to create sysfs directory\n");
		return -ENOMEM;
	}

	ret = sysfs_create_group(mbwi_framework_kobj, &mbwi_framework_attr_group);
	if (ret) {
		pr_err("Failed to create sysfs files: %d\n", ret);
		kobject_put(mbwi_framework_kobj);
		return ret;
	}

	pr_info("M-BWI framework interface created at /sys/kernel/mbwi_framework/\n");
	pr_info("Usage:\n");
	pr_info("  cat /sys/kernel/mbwi_framework/scenario        # List available scenarios\n");
	pr_info("  echo N > /sys/kernel/mbwi_framework/scenario   # Select scenario N\n");
	pr_info("  cat /sys/kernel/mbwi_framework/taskset_info    # View current taskset\n");
	pr_info("  echo 1 > /sys/kernel/mbwi_framework/run_test   # Start test\n");

	return 0;
}

static void __exit test_mbwi_framework_exit(void)
{
	/* Stop any running test */
	atomic_set(&framework.test_running, 0);

	/* Clean up sysfs interface */
	if (mbwi_framework_kobj) {
		sysfs_remove_group(mbwi_framework_kobj, &mbwi_framework_attr_group);
		kobject_put(mbwi_framework_kobj);
	}

	pr_info("M-BWI test framework unloaded\n");
}

module_init(test_mbwi_framework_init);
module_exit(test_mbwi_framework_exit);

MODULE_AUTHOR("Juri Lelli <juri.lelli@redhat.com>");
MODULE_DESCRIPTION("General M-BWI Test Framework for Proxy Execution with SCHED_DEADLINE");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");

/*
 * Usage Example:
 * 
 * To define a custom taskset, create arrays like this:
 *
 * static struct mbwi_resource my_resources[] = {
 *     DEFINE_RESOURCE(0, "SharedDB"),
 *     DEFINE_RESOURCE(1, "NetworkIO"),
 * };
 *
 * static struct mbwi_task_def my_taskset[] = {
 *     DEFINE_TASK("HighPrio", 5, 20, 20, 0)  // 5ms/20ms/20ms, CPU 0
 *         WORK(2),                           // 2ms computation
 *         LOCK(0),                          // Lock SharedDB
 *         WORK_CS(3),                       // 3ms critical section
 *         UNLOCK(0),                        // Unlock SharedDB
 *     END_TASK(),
 *     
 *     DEFINE_TASK("LowPrio", 8, 50, 50, 1)  // 8ms/50ms/50ms, CPU 1
 *         LOCK(0),                          // Lock SharedDB
 *         WORK_CS(5),                       // 5ms critical section
 *         LOCK(1),                          // Lock NetworkIO (nested)
 *         WORK_CS(2),                       // 2ms nested critical section
 *         UNLOCK(1),                        // Unlock NetworkIO
 *         UNLOCK(0),                        // Unlock SharedDB
 *         WORK(1),                          // 1ms final computation
 *     END_TASK(),
 * };
 *
 * Then call: load_taskset(my_taskset, ARRAY_SIZE(my_taskset),
 *                        my_resources, ARRAY_SIZE(my_resources));
 */
