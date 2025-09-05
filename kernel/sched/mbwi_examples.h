/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * M-BWI Test Framework Examples
 *
 * This header provides example taskset definitions using the M-BWI
 * test framework grammar. These examples demonstrate various scenarios
 * for testing proxy execution with SCHED_DEADLINE tasks.
 *
 * Copyright (C) 2025 Red Hat, Inc.
 * Author: Juri Lelli <juri.lelli@redhat.com>
 */

#ifndef _MBWI_EXAMPLES_H
#define _MBWI_EXAMPLES_H

#include "mbwi_framework.h"

/*
 * Example 1: Basic M-BWI scenario from Documentation/scheduler/m-bwi.txt
 * 
 * System: 2 processors
 * Tasks:
 * - τA: (3ms, 10ms, 10ms) - Accesses R1 for 2ms
 * - τB: (4ms, 12ms, 12ms) - Accesses R1 for 1ms  
 * - τC: (5ms, 15ms, 15ms) - Nested: R1 for 3ms, then R2 for 2ms
 * - τD: (2ms, 8ms, 8ms) - No shared resources
 */

static struct mbwi_resource basic_mbwi_resources[] = {
	DEFINE_RESOURCE("R1"),
	DEFINE_RESOURCE("R2"),
};

static struct mbwi_task_def basic_mbwi_taskset[] = {
	/* τA: Simple R1 access pattern */
	DEFINE_TASK("tau_A", 3, 10, 10, -1)
		WORK(1),		/* 1ms non-critical work */
		LOCK(0),		/* Lock R1 */
		WORK_CS(2),		/* 2ms critical section work */
		UNLOCK(0),		/* Unlock R1 */
	END_TASK(),

	/* τB: Simple R1 access pattern, different timing */
	DEFINE_TASK("tau_B", 4, 12, 12, -1)
		WORK(3),		/* 3ms non-critical work */
		LOCK(0),		/* Lock R1 */
		WORK_CS(1),		/* 1ms critical section work */
		UNLOCK(0),		/* Unlock R1 */
	END_TASK(),

	/* τC: Nested critical sections */
	DEFINE_TASK("tau_C", 5, 15, 15, -1)
		LOCK(0),		/* Lock R1 */
		WORK_CS(1),		/* 1ms work in outer CS */
		LOCK(1),		/* Lock R2 (nested) */
		WORK_CS(2),		/* 2ms work in inner CS */
		UNLOCK(1),		/* Unlock R2 */
		WORK_CS(2),		/* 2ms more work in outer CS */
		UNLOCK(0),		/* Unlock R1 */
	END_TASK(),

	/* τD: Temporal isolation test - no resources */
	DEFINE_TASK("tau_D", 2, 8, 8, -1)
		WORK(2),		/* 2ms pure computation */
	END_TASK(),
};

/*
 * Example 2: Complex dependency chain
 *
 * Tests longer blocking chains with multiple resources
 * - τ1: High priority, blocks on R1 (owned by τ2)
 * - τ2: Medium priority, blocks on R2 (owned by τ3)  
 * - τ3: Low priority, owns R2, may block on R3
 * - τ4: Interference task (no resources)
 */

static struct mbwi_resource chain_resources[] = {
	DEFINE_RESOURCE("R1"),
	DEFINE_RESOURCE("R2"),
	DEFINE_RESOURCE("R3"),
};

static struct mbwi_task_def chain_taskset[] = {
	/* τ1: High priority task */
	DEFINE_TASK("HighPrio", 2, 10, 10, 0)
		WORK(1),
		LOCK(0),		/* Will block on τ2 */
		WORK_CS(1),
		UNLOCK(0),
	END_TASK(),

	/* τ2: Medium priority, creates chain R1→R2 */
	DEFINE_TASK("MedPrio", 6, 20, 20, 1)
		LOCK(0),		/* Hold R1 */
		WORK_CS(1),
		LOCK(1),		/* Will block on τ3, creating chain */
		WORK_CS(2),
		UNLOCK(1),
		WORK_CS(1),
		UNLOCK(0),
		WORK(2),
	END_TASK(),

	/* τ3: Low priority, may extend chain */
	DEFINE_TASK("LowPrio", 8, 30, 30, -1)
		LOCK(1),		/* Hold R2 */
		WORK_CS(3),
		LOCK(2),		/* Optional third level */
		WORK_CS(2),
		UNLOCK(2),
		WORK_CS(3),
		UNLOCK(1),
	END_TASK(),

	/* τ4: Interference task - should not affect others */
	DEFINE_TASK("Interference", 3, 15, 15, -1)
		WORK(3),
	END_TASK(),
};

/*
 * Example 3: Cross-CPU migration test
 *
 * Tasks with specific CPU affinities to force cross-CPU migrations
 * when dependency chains span processors
 */

static struct mbwi_resource migration_resources[] = {
	DEFINE_RESOURCE("CrossCPU_R1"),
	DEFINE_RESOURCE("CrossCPU_R2"),
};

static struct mbwi_task_def migration_taskset[] = {
	/* High priority task on CPU 0 */
	DEFINE_TASK("CPU0_High", 3, 12, 12, 0)
		WORK(1),
		LOCK(0),		/* Will trigger migration if owner on CPU 1 */
		WORK_CS(2),
		UNLOCK(0),
	END_TASK(),

	/* Low priority owner on CPU 1 */
	DEFINE_TASK("CPU1_Low", 5, 20, 20, 1)
		LOCK(0),		/* Hold resource, will be boosted */
		WORK_CS(3),
		LOCK(1),		/* Nested lock */
		WORK_CS(2),
		UNLOCK(1),
		UNLOCK(0),
	END_TASK(),

	/* Isolation test on each CPU */
	DEFINE_TASK("CPU0_Isolated", 2, 8, 8, 0)
		WORK(2),
	END_TASK(),

	DEFINE_TASK("CPU1_Isolated", 2, 8, 8, 1)
		WORK(2),
	END_TASK(),
};

/*
 * Example 4: Reader-Writer pattern simulation
 *
 * Simulates reader-writer workloads using mutexes
 * Multiple readers can work concurrently, writers need exclusive access
 */

static struct mbwi_resource rw_resources[] = {
	DEFINE_RESOURCE("ReadLock"),
	DEFINE_RESOURCE("WriteLock"),
	DEFINE_RESOURCE("DataStructure"),
};

static struct mbwi_task_def rw_taskset[] = {
	/* Reader tasks */
	DEFINE_TASK("Reader1", 3, 15, 15, -1)
		WORK(1),
		LOCK(0),		/* Acquire read access */
		LOCK(2),		/* Access data structure */
		WORK_CS(2),		/* Read data */
		UNLOCK(2),
		UNLOCK(0),
	END_TASK(),

	DEFINE_TASK("Reader2", 3, 15, 15, -1)
		WORK(1),
		LOCK(0),		/* Acquire read access */
		LOCK(2),		/* Access data structure */
		WORK_CS(2),		/* Read data */
		UNLOCK(2),
		UNLOCK(0),
	END_TASK(),

	/* Writer task - higher priority, should boost when blocked */
	DEFINE_TASK("Writer", 4, 20, 20, -1)
		WORK(1),
		LOCK(1),		/* Acquire write access */
		LOCK(2),		/* Exclusive data structure access */
		WORK_CS(3),		/* Write data */
		UNLOCK(2),
		UNLOCK(1),
	END_TASK(),

	/* Background task - temporal isolation test */
	DEFINE_TASK("Background", 2, 10, 10, -1)
		WORK(2),
	END_TASK(),
};

/*
 * Example 5: Stress test with many tasks and resources
 *
 * Tests scalability and complex interaction patterns
 */

static struct mbwi_resource stress_resources[] = {
	DEFINE_RESOURCE("DB_Primary"),
	DEFINE_RESOURCE("DB_Secondary"),
	DEFINE_RESOURCE("Network_Send"),
	DEFINE_RESOURCE("Network_Recv"),
	DEFINE_RESOURCE("FileSystem"),
};

static struct mbwi_task_def stress_taskset[] = {
	/* High frequency, high priority task */
	DEFINE_TASK("Critical", 1, 5, 5, 0)
		LOCK(0),
		WORK_CS(1),
		UNLOCK(0),
	END_TASK(),

	/* Database transaction task */
	DEFINE_TASK("DBTransaction", 8, 25, 25, -1)
		LOCK(0),		/* Primary DB */
		WORK_CS(2),
		LOCK(1),		/* Secondary DB */
		WORK_CS(3),
		UNLOCK(1),
		WORK_CS(2),
		LOCK(4),		/* Filesystem sync */
		WORK_CS(1),
		UNLOCK(4),
		UNLOCK(0),
	END_TASK(),

	/* Network processing task */
	DEFINE_TASK("Network", 6, 20, 20, 1)
		LOCK(2),		/* Send buffer */
		WORK_CS(2),
		LOCK(3),		/* Recv buffer */
		WORK_CS(2),
		UNLOCK(3),
		UNLOCK(2),
		WORK(2),
	END_TASK(),

	/* File I/O task */
	DEFINE_TASK("FileIO", 4, 30, 30, -1)
		WORK(1),
		LOCK(4),		/* Filesystem */
		WORK_CS(3),
		UNLOCK(4),
	END_TASK(),

	/* Multiple isolation test tasks */
	DEFINE_TASK("Isolated1", 1, 6, 6, -1)
		WORK(1),
	END_TASK(),

	DEFINE_TASK("Isolated2", 2, 12, 12, -1)
		WORK(2),
	END_TASK(),
};

#endif /* _MBWI_EXAMPLES_H */
