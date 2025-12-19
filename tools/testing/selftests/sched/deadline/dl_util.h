/* SPDX-License-Identifier: GPL-2.0 */
/*
 * SCHED_DEADLINE Utility Library
 *
 * Common helper functions for SCHED_DEADLINE scheduler tests.
 */

#ifndef __DL_UTIL_H__
#define __DL_UTIL_H__

#include <stdint.h>
#include <sys/types.h>
#include <stdbool.h>
#include <linux/sched/types.h>

/* SCHED_DEADLINE policy number */
#ifndef SCHED_DEADLINE
#define SCHED_DEADLINE 6
#endif

/*
 * Scheduling operations
 */

/**
 * dl_set_sched_attr() - Set SCHED_DEADLINE parameters for a task
 * @pid: Process ID (0 for current task)
 * @runtime: Runtime in nanoseconds
 * @deadline: Deadline in nanoseconds
 * @period: Period in nanoseconds
 *
 * Sets the scheduling policy to SCHED_DEADLINE with the given parameters.
 *
 * Return: 0 on success, -1 on error (errno set)
 */
int dl_set_sched_attr(pid_t pid, uint64_t runtime, uint64_t deadline,
		      uint64_t period);

/**
 * dl_get_sched_attr() - Get scheduling attributes for a task
 * @pid: Process ID (0 for current task)
 * @attr: Pointer to sched_attr structure to fill
 *
 * Return: 0 on success, -1 on error (errno set)
 */
int dl_get_sched_attr(pid_t pid, struct sched_attr *attr);

/**
 * dl_get_policy() - Get scheduling policy for a task
 * @pid: Process ID
 *
 * Reads the policy from /proc/<pid>/sched.
 *
 * Return: Policy number (e.g., 6 for SCHED_DEADLINE), -1 on error
 */
int dl_get_policy(pid_t pid);

/**
 * dl_is_deadline_task() - Check if task is using SCHED_DEADLINE
 * @pid: Process ID
 *
 * Return: true if task uses SCHED_DEADLINE, false otherwise
 */
bool dl_is_deadline_task(pid_t pid);

/*
 * Bandwidth management
 */

/**
 * dl_get_rt_bandwidth() - Read RT bandwidth settings
 * @runtime_us: Pointer to store runtime in microseconds
 * @period_us: Pointer to store period in microseconds
 *
 * Reads from /proc/sys/kernel/sched_rt_runtime_us and
 * /proc/sys/kernel/sched_rt_period_us.
 *
 * Return: 0 on success, -1 on error
 */
int dl_get_rt_bandwidth(uint64_t *runtime_us, uint64_t *period_us);

/**
 * dl_get_server_bandwidth_overhead() - Calculate total DL server overhead per CPU
 *
 * Scans /sys/kernel/debug/sched/ for server directories (fair_server, etc.) and
 * calculates the total bandwidth reserved by all DL servers per CPU.
 *
 * Return: Bandwidth percentage overhead per CPU (0-100), or -1 on error
 */
int dl_get_server_bandwidth_overhead(void);

/**
 * dl_calc_max_bandwidth_percent() - Calculate available bandwidth percentage
 *
 * Calculates the maximum bandwidth available per CPU as a percentage,
 * based on RT bandwidth settings minus DL server overhead (fair_server, etc.).
 *
 * Return: Bandwidth percentage (0-100), or -1 on error
 */
int dl_calc_max_bandwidth_percent(void);

/*
 * Process management
 */

/**
 * dl_create_cpuhog() - Fork and create a SCHED_DEADLINE cpuhog process
 * @runtime: Runtime in nanoseconds
 * @deadline: Deadline in nanoseconds
 * @period: Period in nanoseconds
 * @duration_secs: How long cpuhog should run (0 for infinite)
 *
 * Forks a cpuhog process and sets it to SCHED_DEADLINE with the given
 * parameters. The cpuhog will run for duration_secs seconds.
 *
 * Return: PID of cpuhog process, -1 on error
 */
pid_t dl_create_cpuhog(uint64_t runtime, uint64_t deadline, uint64_t period,
		       int duration_secs);

/**
 * dl_cleanup_cpuhog() - Kill and cleanup a cpuhog process
 * @pid: PID of cpuhog to kill
 *
 * Sends SIGTERM, waits briefly, then SIGKILL if needed.
 */
void dl_cleanup_cpuhog(pid_t pid);

/**
 * dl_find_cpuhogs() - Find all running cpuhog processes
 * @pids: Array to store PIDs
 * @max_pids: Size of pids array
 *
 * Uses pgrep to find all processes named "cpuhog".
 *
 * Return: Number of cpuhog PIDs found, -1 on error
 */
int dl_find_cpuhogs(pid_t *pids, int max_pids);

/**
 * dl_wait_for_pid() - Wait for a process to appear
 * @pid: Process ID to wait for
 * @timeout_ms: Timeout in milliseconds
 *
 * Polls /proc/<pid> until it exists or timeout expires.
 *
 * Return: 0 if process appeared, -1 on timeout
 */
int dl_wait_for_pid(pid_t pid, int timeout_ms);

/*
 * CPU topology operations
 */

/**
 * dl_get_online_cpus() - Get number of online CPUs
 *
 * Return: Number of online CPUs, -1 on error
 */
int dl_get_online_cpus(void);

/**
 * dl_get_hotpluggable_cpus() - Get list of hotpluggable CPUs
 * @cpus: Array to store CPU numbers
 * @max_cpus: Size of cpus array
 *
 * Returns CPUs that can be offlined (typically all except CPU0).
 *
 * Return: Number of hotpluggable CPUs, -1 on error
 */
int dl_get_hotpluggable_cpus(int *cpus, int max_cpus);

/**
 * dl_cpu_online() - Bring a CPU online
 * @cpu: CPU number to online
 *
 * Writes 1 to /sys/devices/system/cpu/cpu<N>/online.
 *
 * Return: 0 on success, -1 on error
 */
int dl_cpu_online(int cpu);

/**
 * dl_cpu_offline() - Take a CPU offline
 * @cpu: CPU number to offline
 *
 * Writes 0 to /sys/devices/system/cpu/cpu<N>/online.
 *
 * Return: 0 on success, -1 on error
 */
int dl_cpu_offline(int cpu);

/**
 * dl_is_cpu_online() - Check if CPU is online
 * @cpu: CPU number
 *
 * Return: 1 if online, 0 if offline, -1 on error
 */
int dl_is_cpu_online(int cpu);

/*
 * Time conversion helpers
 */

/**
 * dl_ms_to_ns() - Convert milliseconds to nanoseconds
 */
static inline uint64_t dl_ms_to_ns(uint64_t ms)
{
	return ms * 1000000ULL;
}

/**
 * dl_us_to_ns() - Convert microseconds to nanoseconds
 */
static inline uint64_t dl_us_to_ns(uint64_t us)
{
	return us * 1000ULL;
}

/**
 * dl_ns_to_us() - Convert nanoseconds to microseconds
 */
static inline uint64_t dl_ns_to_us(uint64_t ns)
{
	return ns / 1000ULL;
}

/**
 * dl_ns_to_ms() - Convert nanoseconds to milliseconds
 */
static inline uint64_t dl_ns_to_ms(uint64_t ns)
{
	return ns / 1000000ULL;
}

#endif /* __DL_UTIL_H__ */
