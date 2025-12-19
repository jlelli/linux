// SPDX-License-Identifier: GPL-2.0
/*
 * SCHED_DEADLINE Utility Library Implementation
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <time.h>
#include <glob.h>
#include <dirent.h>
#include "dl_util.h"

/* Syscall numbers for sched_setattr/sched_getattr */
#ifndef __NR_sched_setattr
#define __NR_sched_setattr 314
#endif

#ifndef __NR_sched_getattr
#define __NR_sched_getattr 315
#endif

/*
 * Scheduling operations
 */

static int sched_setattr(pid_t pid, const struct sched_attr *attr,
			 unsigned int flags)
{
	return syscall(__NR_sched_setattr, pid, attr, flags);
}

static int sched_getattr(pid_t pid, struct sched_attr *attr,
			 unsigned int size, unsigned int flags)
{
	return syscall(__NR_sched_getattr, pid, attr, size, flags);
}

int dl_set_sched_attr(pid_t pid, uint64_t runtime, uint64_t deadline,
		      uint64_t period)
{
	struct sched_attr attr = {
		.size = sizeof(attr),
		.sched_policy = SCHED_DEADLINE,
		.sched_flags = 0,
		.sched_runtime = runtime,
		.sched_deadline = deadline,
		.sched_period = period,
	};

	return sched_setattr(pid, &attr, 0);
}

int dl_get_sched_attr(pid_t pid, struct sched_attr *attr)
{
	memset(attr, 0, sizeof(*attr));
	attr->size = sizeof(*attr);
	return sched_getattr(pid, attr, sizeof(*attr), 0);
}

int dl_get_policy(pid_t pid)
{
	char path[256];
	char line[256];
	FILE *f;
	int policy = -1;

	snprintf(path, sizeof(path), "/proc/%d/sched", pid);
	f = fopen(path, "r");
	if (!f)
		return -1;

	while (fgets(line, sizeof(line), f)) {
		if (sscanf(line, " policy : %d", &policy) == 1)
			break;
	}

	fclose(f);
	return policy;
}

bool dl_is_deadline_task(pid_t pid)
{
	return dl_get_policy(pid) == SCHED_DEADLINE;
}

/*
 * Bandwidth management
 */

static int read_proc_uint64(const char *path, uint64_t *value)
{
	FILE *f;
	int ret;

	f = fopen(path, "r");
	if (!f)
		return -1;

	ret = fscanf(f, "%lu", value);
	fclose(f);

	return ret == 1 ? 0 : -1;
}

int dl_get_rt_bandwidth(uint64_t *runtime_us, uint64_t *period_us)
{
	int ret;

	ret = read_proc_uint64("/proc/sys/kernel/sched_rt_runtime_us",
			       runtime_us);
	if (ret < 0)
		return ret;

	return read_proc_uint64("/proc/sys/kernel/sched_rt_period_us",
				period_us);
}

int dl_get_server_bandwidth_overhead(void)
{
	glob_t globbuf;
	char pattern[512];
	size_t i;
	int total_overhead = 0;

	/* Find all *_server directories */
	snprintf(pattern, sizeof(pattern),
		 "/sys/kernel/debug/sched/*_server");

	if (glob(pattern, 0, NULL, &globbuf) != 0) {
		/* No servers found - not an error, just no overhead */
		return 0;
	}

	/*
	 * Sum overhead from cpu0 across all servers.
	 * Assumes symmetric system where all CPUs have identical server
	 * configuration. Reading only cpu0 represents the per-CPU overhead.
	 */
	for (i = 0; i < globbuf.gl_pathc; i++) {
		char runtime_path[512];
		char period_path[512];
		char *server_path = globbuf.gl_pathv[i];
		uint64_t runtime_ns = 0, period_ns = 0;
		int percent;

		/* Build paths to cpu0 runtime and period files */
		snprintf(runtime_path, sizeof(runtime_path),
			 "%s/cpu0/runtime", server_path);
		snprintf(period_path, sizeof(period_path),
			 "%s/cpu0/period", server_path);

		/* Read runtime and period for cpu0 */
		if (read_proc_uint64(runtime_path, &runtime_ns) < 0)
			continue;
		if (read_proc_uint64(period_path, &period_ns) < 0)
			continue;

		if (period_ns == 0)
			continue;

		/* Calculate percentage for this server */
		percent = (runtime_ns * 100) / period_ns;

		/* Accumulate overhead from all servers */
		total_overhead += percent;
	}

	globfree(&globbuf);
	return total_overhead;
}

int dl_calc_max_bandwidth_percent(void)
{
	uint64_t runtime_us, period_us;
	int rt_percent, server_overhead;
	int available_percent;

	if (dl_get_rt_bandwidth(&runtime_us, &period_us) < 0)
		return -1;

	if (period_us == 0)
		return -1;

	/* Calculate RT bandwidth percentage */
	rt_percent = (runtime_us * 100) / period_us;

	/* Get server overhead */
	server_overhead = dl_get_server_bandwidth_overhead();
	if (server_overhead < 0)
		server_overhead = 0;

	/* Available bandwidth = RT bandwidth - server overhead */
	available_percent = rt_percent - server_overhead;

	return available_percent > 0 ? available_percent : 1;
}

static int write_proc_uint64(const char *path, uint64_t value)
{
	FILE *f;
	int ret;

	f = fopen(path, "w");
	if (!f)
		return -1;

	ret = fprintf(f, "%lu\n", value);
	if (ret < 0) {
		fclose(f);
		return -1;
	}

	/* fclose() flushes and may return error if kernel write fails */
	if (fclose(f) != 0)
		return -1;

	return 0;
}

int dl_set_rt_bandwidth(uint64_t runtime_us, uint64_t period_us)
{
	int ret;

	ret = write_proc_uint64("/proc/sys/kernel/sched_rt_runtime_us",
				runtime_us);
	if (ret < 0)
		return ret;

	return write_proc_uint64("/proc/sys/kernel/sched_rt_period_us",
				 period_us);
}

bool dl_fair_server_exists(void)
{
	return access("/sys/kernel/debug/sched/fair_server", F_OK) == 0;
}

int dl_get_fair_server_settings(int cpu, uint64_t *runtime_ns,
				 uint64_t *period_ns)
{
	char runtime_path[256];
	char period_path[256];
	int ret;

	snprintf(runtime_path, sizeof(runtime_path),
		 "/sys/kernel/debug/sched/fair_server/cpu%d/runtime", cpu);

	ret = read_proc_uint64(runtime_path, runtime_ns);
	if (ret < 0)
		return ret;

	/* period_ns is optional */
	if (period_ns) {
		snprintf(period_path, sizeof(period_path),
			 "/sys/kernel/debug/sched/fair_server/cpu%d/period", cpu);
		return read_proc_uint64(period_path, period_ns);
	}

	return 0;
}

int dl_set_fair_server_runtime(int cpu, uint64_t runtime_ns)
{
	char path[256];

	snprintf(path, sizeof(path),
		 "/sys/kernel/debug/sched/fair_server/cpu%d/runtime", cpu);

	return write_proc_uint64(path, runtime_ns);
}

/*
 * Process management
 */

pid_t dl_create_cpuhog(uint64_t runtime, uint64_t deadline, uint64_t period,
		       int duration_secs)
{
	pid_t pid;
	char duration_str[32];

	pid = fork();
	if (pid < 0)
		return -1;

	if (pid == 0) {
		/* Child process */
		char *args[4];

		args[0] = "./cpuhog";
		if (duration_secs > 0) {
			args[1] = "-t";
			snprintf(duration_str, sizeof(duration_str), "%d",
				 duration_secs);
			args[2] = duration_str;
			args[3] = NULL;
		} else {
			args[1] = NULL;
		}

		/* Just exec - parent will set SCHED_DEADLINE */
		execvp(args[0], args);
		/* If exec fails, try without ./ */
		args[0] = "cpuhog";
		execvp(args[0], args);

		fprintf(stderr, "Failed to exec cpuhog: %s\n", strerror(errno));
		exit(1);
	}

	/* Parent process - wait for child to start then set SCHED_DEADLINE */
	if (dl_wait_for_pid(pid, 1000) < 0) {
		kill(pid, SIGKILL);
		waitpid(pid, NULL, 0);
		return -1;
	}

	/* Set SCHED_DEADLINE on the child process */
	if (dl_set_sched_attr(pid, runtime, deadline, period) < 0) {
		kill(pid, SIGKILL);
		waitpid(pid, NULL, 0);
		return -1;
	}

	return pid;
}

void dl_cleanup_cpuhog(pid_t pid)
{
	int i;

	if (pid <= 0)
		return;

	/* Try SIGTERM first */
	kill(pid, SIGTERM);

	/* Wait up to 1 second for graceful exit */
	for (i = 0; i < 10; i++) {
		if (waitpid(pid, NULL, WNOHANG) == pid)
			return;
		usleep(100000); /* 100ms */
	}

	/* Force kill */
	kill(pid, SIGKILL);
	waitpid(pid, NULL, 0);
}

int dl_find_cpuhogs(pid_t *pids, int max_pids)
{
	FILE *f;
	char line[256];
	int count = 0;

	f = popen("pgrep -x cpuhog", "r");
	if (!f)
		return -1;

	while (fgets(line, sizeof(line), f) && count < max_pids) {
		pid_t pid = atoi(line);

		if (pid > 0)
			pids[count++] = pid;
	}

	pclose(f);
	return count;
}

int dl_wait_for_pid(pid_t pid, int timeout_ms)
{
	char path[256];
	int elapsed = 0;
	int interval = 10; /* 10ms polling interval */

	snprintf(path, sizeof(path), "/proc/%d", pid);

	while (elapsed < timeout_ms) {
		if (access(path, F_OK) == 0)
			return 0;

		usleep(interval * 1000);
		elapsed += interval;
	}

	return -1;
}

uint64_t dl_get_process_cpu_time(pid_t pid)
{
	char path[256];
	char line[1024];
	FILE *f;
	uint64_t utime = 0, stime = 0;
	int i;
	char *p, *token, *saveptr;

	snprintf(path, sizeof(path), "/proc/%d/stat", pid);
	f = fopen(path, "r");
	if (!f)
		return 0;

	if (!fgets(line, sizeof(line), f)) {
		fclose(f);
		return 0;
	}

	fclose(f);

	/*
	 * Parse /proc/PID/stat format:
	 * pid (comm) state ppid ... utime stime ...
	 *
	 * The comm field (field 2) can contain spaces and is enclosed in
	 * parentheses. Find the last ')' to skip past it, then parse the
	 * remaining space-separated fields.
	 *
	 * After the closing ')', fields are:
	 * 1=state 2=ppid 3=pgrp 4=sid 5=tty_nr 6=tty_pgrp 7=flags
	 * 8=min_flt 9=cmin_flt 10=maj_flt 11=cmaj_flt 12=utime 13=stime
	 */
	p = strrchr(line, ')');
	if (!p)
		return 0;

	/* Skip past ') ' */
	p += 2;

	/* Tokenize remaining fields */
	token = strtok_r(p, " ", &saveptr);
	for (i = 1; token && i <= 13; i++) {
		if (i == 12)
			utime = strtoull(token, NULL, 10);
		else if (i == 13)
			stime = strtoull(token, NULL, 10);

		token = strtok_r(NULL, " ", &saveptr);
	}

	return utime + stime;
}

/*
 * CPU topology operations
 */

int dl_get_online_cpus(void)
{
	return (int)sysconf(_SC_NPROCESSORS_ONLN);
}

int dl_get_hotpluggable_cpus(int *cpus, int max_cpus)
{
	int cpu, count = 0;
	int max_cpu = (int)sysconf(_SC_NPROCESSORS_CONF);
	char path[256];

	for (cpu = 1; cpu < max_cpu && count < max_cpus; cpu++) {
		snprintf(path, sizeof(path),
			 "/sys/devices/system/cpu/cpu%d/online", cpu);

		/* If the online file exists, the CPU is hotpluggable */
		if (access(path, F_OK) == 0)
			cpus[count++] = cpu;
	}

	return count;
}

static int write_cpu_online(int cpu, int online)
{
	char path[256];
	FILE *f;
	int ret;

	snprintf(path, sizeof(path),
		 "/sys/devices/system/cpu/cpu%d/online", cpu);

	f = fopen(path, "w");
	if (!f)
		return -1;

	ret = fprintf(f, "%d\n", online);
	fclose(f);

	return ret > 0 ? 0 : -1;
}

int dl_cpu_online(int cpu)
{
	return write_cpu_online(cpu, 1);
}

int dl_cpu_offline(int cpu)
{
	return write_cpu_online(cpu, 0);
}

int dl_is_cpu_online(int cpu)
{
	char path[256];
	FILE *f;
	int online = -1;

	snprintf(path, sizeof(path),
		 "/sys/devices/system/cpu/cpu%d/online", cpu);

	f = fopen(path, "r");
	if (!f) {
		/* CPU0 often doesn't have an online file (always online) */
		if (cpu == 0)
			return 1;
		return -1;
	}

	if (fscanf(f, "%d", &online) != 1)
		online = -1;

	fclose(f);
	return online;
}
