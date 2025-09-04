==========================
Proxy Execution Scheduler
==========================

:Author: Juri Lelli <juri.lelli@redhat.com>
:Date: January 2025

Overview
========

Proxy Execution is a scheduler mechanism that addresses priority inversion
problems in mutex-heavy workloads by allowing mutex owners to inherit the
scheduling context of higher-priority blocked waiters. Instead of having
high-priority tasks sleep when they block on mutexes held by lower-priority
tasks, the mutex owner runs with the blocked task's priority and scheduling
parameters.

This mechanism is particularly important for real-time and latency-sensitive
workloads where priority inversion can cause deadline misses and performance
degradation.

Problem Statement
=================

Traditional Priority Inheritance (PI) has limitations:

1. **Limited Scope**: PI only affects the immediate mutex owner, not chains
   of dependencies
2. **Cross-CPU Issues**: PI doesn't handle cases where mutex owners run on
   different CPUs than the blocked waiters
3. **Sleeping Owners**: PI cannot boost owners that have gone to sleep
4. **Complex Chains**: Long dependency chains can still cause delays

Proxy Execution solves these issues by keeping blocked tasks runnable and
using the mutex owner as the execution context while preserving the blocked
task's scheduling context.

Core Concepts
=============

Scheduling vs Execution Context Split
-------------------------------------

Proxy Execution introduces a fundamental split:

- **Scheduling Context** (``rq->donor``): The task selected by the scheduler,
  which may be blocked on a mutex
- **Execution Context** (``rq->curr``): The task that actually runs on the CPU,
  typically the mutex owner

This split allows the scheduler to make decisions based on the blocked task's
priority while running the mutex owner's code.

Task States
-----------

New blocked-on states are introduced:

.. code-block:: c

    enum blocked_on_state {
        BO_RUNNABLE,    /* Task can run normally */
        BO_BLOCKED,     /* Task is blocked on mutex */
        BO_WAKING,      /* Task is being woken up */
    };

Key Data Structures
===================

Task Structure Extensions
-------------------------

.. code-block:: c

    struct task_struct {
        enum blocked_on_state blocked_on_state;
        struct mutex *blocked_on;              /* lock we're blocked on */
        struct task_struct *blocked_donor;     /* task boosting us */
        struct list_head blocked_head;         /* tasks blocked on us */
        struct list_head blocked_node;         /* our entry on owner's blocked_head */
        struct list_head migration_node;       /* for chain migration */
        struct task_struct *sleeping_owner;    /* sleeping task we're queued on */
        raw_spinlock_t blocked_lock;           /* protects blocked_on state */
    };

Runqueue Extensions
-------------------

.. code-block:: c

    struct rq {
        struct task_struct __rcu *donor;  /* Scheduling context */
        struct task_struct __rcu *curr;   /* Execution context */
    };

Core Algorithm
==============

Main Scheduling Path
--------------------

The proxy execution logic integrates into the main ``__schedule()`` function:

1. **Task Selection**: ``pick_next_task()`` selects the highest priority task
2. **Proxy Check**: If selected task is blocked (``task_is_blocked()``), call
   ``find_proxy_task()``
3. **Chain Walking**: Follow ``blocked_on`` chain to find runnable owner
4. **Migration**: If owner is on different CPU, migrate the chain
5. **Execution**: Run the owner with the blocked task's scheduling context

Chain Walking Algorithm
-----------------------

The ``find_proxy_task()`` function implements the core logic:

.. code-block:: c

    /* Follow blocked_on chain */
    for (p = donor; task_is_blocked(p); p = owner) {
        mutex = p->blocked_on;
        
        /* Acquire locks in order: mutex->wait_lock, p->blocked_lock */
        guard(raw_spinlock)(&mutex->wait_lock);
        guard(raw_spinlock)(&p->blocked_lock);
        
        /* Validate chain hasn't changed */
        if (mutex != __get_task_blocked_on(p))
            return NULL; /* retry */
            
        owner = __mutex_owner(mutex);
        
        /* Handle different owner states */
        if (!owner) {
            /* Mutex being released, make task runnable */
            __force_blocked_on_runnable(p);
            return p;
        }
        
        if (!READ_ONCE(owner->on_rq)) {
            /* Owner sleeping, enqueue on owner's blocked_head */
            proxy_enqueue_on_owner(rq, owner, p);
            return NULL;
        }
        
        if (task_cpu(owner) != this_cpu) {
            /* Cross-CPU case, migrate chain */
            goto migrate;
        }
    }

Migration Handling
==================

Chain Migration
---------------

When dependency chains cross CPU boundaries, ``proxy_migrate_task()`` migrates
the entire chain:

.. code-block:: c

    for (; p; p = p->blocked_donor) {
        deactivate_task(rq, p, 0);
        proxy_set_task_cpu(p, target_cpu);
        list_add(&p->migration_node, &migrate_list);
    }

This ensures that scheduling contexts move toward execution contexts while
respecting CPU affinity constraints.

Return Migration
----------------

Tasks that were proxy-migrated need to return to their preferred CPUs after
mutex release. This is handled in the wakeup path and ensures proper task
placement.

Sleeping Owner Handling
=======================

When mutex owners go to sleep, blocked tasks cannot immediately run. The
system handles this by:

1. **Queueing**: Blocked tasks are moved to the owner's ``blocked_head`` list
2. **Deactivation**: Tasks are removed from runqueues but kept tracked
3. **Reactivation**: When owner wakes up, all blocked tasks are reactivated

This mechanism preserves the dependency chain even across sleep/wake cycles.

Mutex Integration
=================

Lock Path Changes
-----------------

When acquiring a mutex:

.. code-block:: c

    raw_spin_lock(&current->blocked_lock);
    __set_task_blocked_on(current, lock);
    set_current_state(state);
    
    /* Task stays runnable for proxy execution */

Unlock Path Changes
-------------------

Smart handoff logic prioritizes blocked donors:

.. code-block:: c

    if (sched_proxy_exec() && current->blocked_donor) {
        /* Force handoff if we have a blocked_donor */
        owner = MUTEX_FLAG_HANDOFF;
    }
    
    donor = current->blocked_donor;
    if (donor && __get_task_blocked_on(donor) == lock) {
        next = donor;  /* Hand off to highest priority waiter */
        __set_blocked_on_waking(donor);
    }

Load Balancer Integration
=========================

RT and Deadline Classes
-----------------------

Both scheduling classes were updated to understand the execution/scheduling
context split:

- ``find_exec_ctx()`` helper finds the actual execution context
- Load balancing considers both contexts when making migration decisions
- Push/pull operations work with execution contexts while preserving
  scheduling contexts

Validation Logic
----------------

The ``dl_revalidate_rq_state()`` and ``rt_revalidate_rq_state()`` functions
were enhanced to handle proxy execution scenarios where the selected task
may not be the one that actually runs.

Configuration and Testing
=========================

Kernel Configuration
--------------------

.. code-block:: kconfig

    config SCHED_PROXY_EXEC
        bool "Proxy Execution"
        depends on !PREEMPT_RT  # Build conflicts with RT
        depends on !SCHED_CLASS_EXT  # Conflicts with sched_ext
        help
          This option enables proxy execution, a mechanism for mutex-owning
          tasks to inherit the scheduling context of higher priority waiters.

Boot Parameter
--------------

Proxy execution can be controlled at boot time:

.. code-block:: bash

    sched_proxy_exec=0  # Disable proxy execution
    sched_proxy_exec=1  # Enable proxy execution (default)

Testing Framework
-----------------

The ``ksched_football`` test validates proxy execution behavior:

- **High Priority Defense**: Tasks that block on mutexes
- **Low Priority Holders**: Tasks that hold the mutexes
- **Medium Priority Offense**: Tasks that try to interfere

With proxy execution enabled, the low priority holders should be boosted,
preventing medium priority tasks from running and maintaining the RT
scheduling invariant.

Debug and Tracing
=================

Trace Events
------------

Comprehensive tracing support for debugging:

- ``sched_pe_migration``: Chain migration events
- ``sched_pe_return_migration``: Return migration events  
- ``sched_pe_enqueue_sleeping_task``: Tasks queued on sleeping owners
- ``sched_pe_activate_blocked_entity``: Sleeping owner wakeup events
- ``sched_start_task_selection`` / ``sched_finish_task_selection``: Task selection timing

Usage:

.. code-block:: bash

    perf trace -e sched:sched_pe_* -e sched:sched_*_task_selection

Performance Considerations
==========================

Benefits
--------

- **Eliminates Priority Inversion**: High priority tasks don't wait for low priority ones
- **Improved Latency**: Reduces worst-case latency for RT workloads
- **Chain Handling**: Resolves complex dependency chains efficiently
- **Cross-CPU Support**: Handles distributed mutex ownership

Overhead
--------

- **Additional Locking**: New ``blocked_lock`` per task
- **Chain Walking**: Traversing dependency chains during scheduling
- **Migration Costs**: Cross-CPU chain migrations
- **Memory Overhead**: Additional list heads and state per task

Limitations and Edge Cases
==========================

Current Limitations
-------------------

- **PREEMPT_RT Incompatibility**: Build conflicts with RT patches
- **sched_ext Conflicts**: Cannot coexist with BPF scheduler
- **Complex Locking**: Intricate lock ordering requirements
- **Race Conditions**: Careful handling of concurrent chain modifications

Known Issues
------------

- **dl_server Integration**: Current hack reverts conflicting dl_server changes
- **Wakeup Races**: Complex interaction with try_to_wake_up() in chain scenarios
- **Load Balancer Edge Cases**: Ongoing refinement of cross-CPU behavior

Implementation Status
=====================

The current implementation (v21) represents a mature, extensively tested
version of proxy execution. Key milestones:

- **Core Infrastructure**: Complete proxy execution framework
- **Migration Support**: Full chain migration and return migration
- **Testing**: Comprehensive test suite and tracing
- **Integration**: RT/DL class integration and load balancer support
- **Stability**: Removed EXPERT dependency, indicating production readiness

Future Work
===========

Potential areas for further development:

- **PREEMPT_RT Integration**: Resolve build conflicts with RT patches
- **sched_ext Support**: Enable coexistence with BPF schedulers
- **Performance Optimization**: Reduce overhead in common cases
- **Extended Chain Support**: Handle more complex dependency patterns
- **Memory Optimization**: Reduce per-task memory overhead

References
==========

- Original LTP sched_football test: https://github.com/linux-test-project/ltp/blob/master/testcases/realtime/func/sched_football/sched_football.c
- Kernel source: ``kernel/sched/core.c``, ``kernel/locking/mutex.c``
- Test implementation: ``kernel/sched/test_ksched_football.c``
- Configuration: ``init/Kconfig`` (``CONFIG_SCHED_PROXY_EXEC``)
