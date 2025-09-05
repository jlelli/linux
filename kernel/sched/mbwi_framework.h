/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * M-BWI Test Framework Core Definitions
 *
 * This header provides the core data structures, enums, and macros
 * for the M-BWI test framework. It's included by both the framework
 * implementation and example taskset definitions.
 *
 * Copyright (C) 2025 Red Hat, Inc.
 * Author: Juri Lelli <juri.lelli@redhat.com>
 */

#ifndef _MBWI_FRAMEWORK_H
#define _MBWI_FRAMEWORK_H

#include <linux/mutex.h>
#include <linux/atomic.h>
#include <linux/time64.h>

/* Framework configuration */
#define MAX_TASKS		16
#define MAX_RESOURCES		8
#define MAX_PHASES		32

/* Phase types for task execution grammar */
enum phase_type {
	PHASE_WORK,		/* Pure computation work */
	PHASE_LOCK,		/* Acquire mutex */
	PHASE_UNLOCK,		/* Release mutex */
	PHASE_WORK_CS,		/* Work while holding mutex */
	PHASE_END,		/* End of phase sequence */
};

/* Execution phase definition */
struct exec_phase {
	enum phase_type type;
	union {
		u64 work_ns;		/* For PHASE_WORK, PHASE_WORK_CS */
		int resource_id;	/* For PHASE_LOCK, PHASE_UNLOCK */
	};
};

/* Task definition */
struct mbwi_task_def {
	char name[16];
	u64 runtime_ns;
	u64 period_ns;
	u64 deadline_ns;
	struct exec_phase phases[MAX_PHASES];
	int cpu_affinity;		/* -1 for no affinity */
};

/* Task wakeup statistics */
struct mbwi_wakeup_stats {
	atomic64_t total_wakeups;
	atomic64_t total_latency_ns;
	atomic64_t max_latency_ns;
	atomic64_t min_latency_ns;
	atomic64_t early_wakeups;
	atomic64_t late_wakeups;
};

/* Resource (mutex) definition */
struct mbwi_resource {
	struct mutex lock;
	char name[16];
	atomic64_t acquisitions;
	atomic64_t contentions;
};

/*
 * Grammar Macros for defining task execution patterns
 */

/* Task definition macros */
#define DEFINE_TASK(tsk_name, run_ms, per_ms, deadl_ms, cpu) \
	{ .name = tsk_name, \
	  .runtime_ns = (run_ms) * NSEC_PER_MSEC, \
	  .period_ns = (per_ms) * NSEC_PER_MSEC, \
	  .deadline_ns = (deadl_ms) * NSEC_PER_MSEC, \
	  .cpu_affinity = cpu, \
	  .phases = {

#define END_TASK() \
		{ .type = PHASE_END }, \
	} }

/* Phase definition macros */
#define WORK(dur_ms) \
	{ .type = PHASE_WORK, .work_ns = (dur_ms) * NSEC_PER_MSEC }

#define LOCK(res_id) \
	{ .type = PHASE_LOCK, .resource_id = res_id }

#define UNLOCK(res_id) \
	{ .type = PHASE_UNLOCK, .resource_id = res_id }

#define WORK_CS(dur_ms) \
	{ .type = PHASE_WORK_CS, .work_ns = (dur_ms) * NSEC_PER_MSEC }

/* Resource definition macro */
#define DEFINE_RESOURCE(res_name) \
	{ .name = res_name }

#endif /* _MBWI_FRAMEWORK_H */
