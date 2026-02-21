/*
 * memlimit - memory limit enforcer for macOS and Linux
 *
 * Launches a command in its own process group, monitors the physical memory
 * footprint of the entire process group, and kills the group if it exceeds
 * a configured limit.
 *
 * On macOS: uses proc_pid_rusage() → phys_footprint (Activity Monitor metric).
 * On Linux: uses PSS from /proc/PID/smaps_rollup (kernel 4.14+).
 *
 * Copyright (c) 2026 — MIT License
 */

#if !defined(__APPLE__) && !defined(__linux__)
#error "memlimit requires macOS or Linux"
#endif

/* Ensure POSIX APIs (posix_spawn, sigaction, getpgid, nanosleep) on glibc. */
#if defined(__linux__)
#define _POSIX_C_SOURCE 200809L
#endif

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#if defined(__APPLE__)
#include <libproc.h>
#include <sys/proc_info.h>
#elif defined(__linux__)
#include <dirent.h>
#endif

/* ------------------------------------------------------------------------- */
/* Constants                                                                  */
/* ------------------------------------------------------------------------- */

#define VERSION           "1.0.0"
#define POLL_INTERVAL_US  250000   /* 250 ms */
#define REAP_POLL_US      100000   /* 100 ms */
#define MEASURE_FAIL_POLLS 4
#define PARTIAL_FAIL_POLLS 20
#define DEFAULT_VERBOSE_SEC 5
#define DEFAULT_GRACE_SEC 5
#define EXIT_OOM          137     /* 128 + SIGKILL, matches Linux OOM convention */
#define EXIT_INTERNAL     1
#define EXIT_USAGE        2
#define EXIT_NOT_EXEC     126
#define EXIT_NOT_FOUND    127
#define SIZE_BUF_LEN      32

/* ------------------------------------------------------------------------- */
/* Globals (signal handling)                                                  */
/* ------------------------------------------------------------------------- */

static volatile sig_atomic_t g_caught_signal = 0;

static void signal_handler(int sig)
{
    g_caught_signal = sig;
}

/* ------------------------------------------------------------------------- */
/* Size parsing & formatting                                                  */
/* ------------------------------------------------------------------------- */

/*
 * Parse a human-readable size string (e.g. "10G", "500M", "1024K", "8192").
 * Returns true on success and stores the result in *out.
 * Guards against integer overflow before applying the multiplier.
 */
static bool parse_size(const char *str, uint64_t *out)
{
    if (str == NULL || *str == '\0')
        return false;

    /* Reject signs/whitespace prefixes: limit must start with a digit. */
    if (str[0] < '0' || str[0] > '9')
        return false;

    char *endptr = NULL;
    errno = 0;
    unsigned long long val = strtoull(str, &endptr, 10);

    if (errno == ERANGE || endptr == str)
        return false;

    uint64_t multiplier = 1;
    if (endptr != NULL && *endptr != '\0') {
        switch (*endptr) {
        case 'G': case 'g': multiplier = (uint64_t)1 << 30; break;
        case 'M': case 'm': multiplier = (uint64_t)1 << 20; break;
        case 'K': case 'k': multiplier = (uint64_t)1 << 10; break;
        case 'B': case 'b': multiplier = 1;                  break;
        default:
            return false;
        }
        /* reject trailing garbage after the suffix */
        if (endptr[1] != '\0')
            return false;
    }

    /* overflow check: val * multiplier must fit in uint64_t */
    if (multiplier > 1 && val > UINT64_MAX / multiplier)
        return false;

    *out = (uint64_t)val * multiplier;
    return *out > 0;
}

/*
 * Format a byte count into a human-readable string.
 * buf must be at least SIZE_BUF_LEN bytes.
 */
static void format_size(uint64_t bytes, char *buf, size_t buflen)
{
    if (bytes >= ((uint64_t)1 << 30))
        snprintf(buf, buflen, "%.1fG", (double)bytes / (double)((uint64_t)1 << 30));
    else if (bytes >= ((uint64_t)1 << 20))
        snprintf(buf, buflen, "%.1fM", (double)bytes / (double)((uint64_t)1 << 20));
    else if (bytes >= ((uint64_t)1 << 10))
        snprintf(buf, buflen, "%.1fK", (double)bytes / (double)((uint64_t)1 << 10));
    else
        snprintf(buf, buflen, "%llu bytes", (unsigned long long)bytes);
}

/* ------------------------------------------------------------------------- */
/* Time / wait helpers                                                        */
/* ------------------------------------------------------------------------- */

static void sleep_for_us(unsigned int usec)
{
    struct timespec req;
    req.tv_sec = (time_t)(usec / 1000000U);
    req.tv_nsec = (long)(usec % 1000000U) * 1000L;

    while (nanosleep(&req, &req) == -1 && errno == EINTR)
        ;
}

static pid_t waitpid_noeintr(pid_t pid, int *status, int options)
{
    pid_t ret;
    do {
        ret = waitpid(pid, status, options);
    } while (ret == -1 && errno == EINTR);
    return ret;
}

static int kill_noeintr(pid_t pid, int sig)
{
    int ret;
    do {
        ret = kill(pid, sig);
    } while (ret == -1 && errno == EINTR);
    return ret;
}

/*
 * Wait for child exit with an optional timeout.
 * timeout_ms < 0 means wait forever.
 * Returns true when child is gone (reaped or already gone), false on errors
 * or timeout.  If child_status_valid is non-NULL, sets it true only when a
 * real wait status was collected.
 */
static bool wait_for_child_exit(pid_t child_pid, int *child_status,
                                bool *child_status_valid, int timeout_ms)
{
    int waited_ms = 0;

    if (child_status_valid != NULL)
        *child_status_valid = false;

    while (true) {
        pid_t w = waitpid_noeintr(child_pid, child_status, WNOHANG);
        if (w == child_pid) {
            if (child_status_valid != NULL)
                *child_status_valid = true;
            return true;
        }

        if (w == -1) {
            if (errno == ECHILD)
                return true;
            return false;
        }

        if (timeout_ms >= 0 && waited_ms >= timeout_ms)
            return false;

        sleep_for_us(REAP_POLL_US);
        waited_ms += (int)(REAP_POLL_US / 1000);
    }
}

/* ------------------------------------------------------------------------- */
/* Memory measurement (platform-specific)                                     */
/* ------------------------------------------------------------------------- */

#if defined(__APPLE__)

/*
 * macOS: Get phys_footprint for a single PID via proc_pid_rusage().
 * This is Activity Monitor's "Memory" column.  Accounts for compressed pages
 * on Apple Silicon.  Returns true on success.
 */
static bool get_pid_memory(pid_t pid, uint64_t *out_bytes)
{
    if (out_bytes == NULL)
        return false;

#if defined(RUSAGE_INFO_V4)
    {
        struct rusage_info_v4 info;
        if (proc_pid_rusage(pid, RUSAGE_INFO_V4, (rusage_info_t *)&info) == 0) {
            *out_bytes = info.ri_phys_footprint;
            return true;
        }
    }
#endif

#if defined(RUSAGE_INFO_V3)
    {
        struct rusage_info_v3 info;
        if (proc_pid_rusage(pid, RUSAGE_INFO_V3, (rusage_info_t *)&info) == 0) {
            *out_bytes = info.ri_phys_footprint;
            return true;
        }
    }
#endif

#if defined(RUSAGE_INFO_V2)
    {
        struct rusage_info_v2 info;
        if (proc_pid_rusage(pid, RUSAGE_INFO_V2, (rusage_info_t *)&info) == 0) {
            *out_bytes = info.ri_phys_footprint;
            return true;
        }
    }
#endif

    return false;
}

/*
 * macOS: Sum phys_footprint for all processes in a process group.
 * Uses proc_listallpids() to enumerate, then filters by pgid.
 * If nprocs is non-NULL, stores the number of matching processes.
 * If nmeasured is non-NULL, stores the number of processes whose memory
 * could be read successfully.
 * If backend_ok is non-NULL, stores false when enumeration failed.
 */
static uint64_t get_group_memory(pid_t pgid, int *nprocs, int *nmeasured,
                                 bool *backend_ok)
{
    if (nprocs != NULL)
        *nprocs = 0;
    if (nmeasured != NULL)
        *nmeasured = 0;
    if (backend_ok != NULL)
        *backend_ok = true;

    int count = proc_listallpids(NULL, 0);
    if (count <= 0) {
        if (backend_ok != NULL)
            *backend_ok = false;
        return 0;
    }

    /* Allocate space for the PID list. Add slack for races. */
    size_t alloc_count = (size_t)count + 64;

    if (alloc_count > SIZE_MAX / sizeof(pid_t))
        return 0;

    if (alloc_count * sizeof(pid_t) > (size_t)INT_MAX) {
        if (backend_ok != NULL)
            *backend_ok = false;
        return 0;
    }

    pid_t *pids = malloc(alloc_count * sizeof(pid_t));
    if (pids == NULL) {
        fprintf(stderr, "memlimit: malloc failed in get_group_memory\n");
        if (backend_ok != NULL)
            *backend_ok = false;
        return 0;
    }

    count = proc_listallpids(pids, (int)(alloc_count * sizeof(pid_t)));
    if (count <= 0) {
        if (backend_ok != NULL)
            *backend_ok = false;
        free(pids);
        return 0;
    }

    uint64_t total = 0;
    int procs = 0;
    int measured = 0;
    for (int i = 0; i < count; i++) {
        if (pids[i] <= 0)
            continue;

        struct proc_bsdinfo bsdinfo;
        int ret = proc_pidinfo(pids[i], PROC_PIDTBSDINFO, 0,
                               &bsdinfo, (int)sizeof(bsdinfo));
        if (ret != (int)sizeof(bsdinfo) || bsdinfo.pbi_pgid != (uint32_t)pgid)
            continue;

        procs++;
        uint64_t mem = 0;
        if (!get_pid_memory(pids[i], &mem))
            continue;

        measured++;
        if (UINT64_MAX - total < mem) {
            total = UINT64_MAX;
            break;
        }
        total += mem;
    }

    if (nprocs != NULL)
        *nprocs = procs;
    if (nmeasured != NULL)
        *nmeasured = measured;
    free(pids);
    return total;
}

#elif defined(__linux__)

/*
 * Linux: Get PSS (Proportional Set Size) for a single PID.
 * Reads /proc/PID/smaps_rollup first, then falls back to /proc/PID/smaps.
 * PSS is the closest equivalent to macOS phys_footprint because it accounts
 * for proportional sharing of pages among processes.  Returns true on success.
 */
static bool read_pss_kb(FILE *f, bool stop_at_first, uint64_t *out_pss_kb)
{
    char line[256];
    uint64_t total_kb = 0;
    bool found_pss = false;

    while (fgets(line, sizeof(line), f) != NULL) {
        if (strncmp(line, "Pss:", 4) != 0)
            continue;

        unsigned long long val = 0;
        if (sscanf(line + 4, " %llu", &val) != 1)
            continue;

        found_pss = true;
        if (stop_at_first) {
            total_kb = (uint64_t)val;
            break;
        }

        if ((uint64_t)val > UINT64_MAX - total_kb)
            total_kb = UINT64_MAX;
        else
            total_kb += (uint64_t)val;
    }

    if (!found_pss)
        return false;

    *out_pss_kb = total_kb;
    return true;
}

static bool get_pid_memory(pid_t pid, uint64_t *out_bytes)
{
    if (out_bytes == NULL)
        return false;

    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/smaps_rollup", (int)pid);

    FILE *f = fopen(path, "r");
    uint64_t pss_kb = 0;
    if (f != NULL) {
        bool ok = read_pss_kb(f, true, &pss_kb);
        fclose(f);
        if (!ok)
            return false;
    } else {
        /* Fallback for kernels/configs without smaps_rollup support. */
        snprintf(path, sizeof(path), "/proc/%d/smaps", (int)pid);
        f = fopen(path, "r");
        if (f == NULL)
            return false;

        bool ok = read_pss_kb(f, false, &pss_kb);
        fclose(f);
        if (!ok)
            return false;
    }

    /* kB → bytes, with overflow guard */
    if (pss_kb > UINT64_MAX / 1024) {
        *out_bytes = UINT64_MAX;
        return true;
    }

    *out_bytes = pss_kb * 1024;
    return true;
}

/*
 * Linux: Get the process group ID for a PID via the getpgid() syscall.
 * This avoids parsing /proc/PID/stat entirely — simpler, faster, and no
 * TOCTOU issues with comm field parsing.  Returns -1 on error.
 */
static pid_t get_pid_pgid(pid_t pid)
{
    pid_t pgid = getpgid(pid);
    return (pgid == -1) ? (pid_t)-1 : pgid;
}

/*
 * Linux: Sum PSS for all processes in a process group.
 * Scans /proc for numeric directories, filters by pgid.
 * If nprocs is non-NULL, stores the number of matching processes.
 * If nmeasured is non-NULL, stores the number of processes whose memory
 * could be read successfully.
 * If backend_ok is non-NULL, stores false when enumeration failed.
 */
static uint64_t get_group_memory(pid_t pgid, int *nprocs, int *nmeasured,
                                 bool *backend_ok)
{
    if (nprocs != NULL)
        *nprocs = 0;
    if (nmeasured != NULL)
        *nmeasured = 0;
    if (backend_ok != NULL)
        *backend_ok = true;

    DIR *proc_dir = opendir("/proc");
    if (proc_dir == NULL) {
        if (backend_ok != NULL)
            *backend_ok = false;
        return 0;
    }

    uint64_t total = 0;
    int procs = 0;
    int measured = 0;
    struct dirent *entry;

    while (true) {
        errno = 0;
        entry = readdir(proc_dir);
        if (entry == NULL) {
            if (errno != 0 && backend_ok != NULL)
                *backend_ok = false;
            break;
        }

        /* Only numeric directory names (PIDs) */
        if (entry->d_name[0] < '0' || entry->d_name[0] > '9')
            continue;

        char *endptr = NULL;
        long pid_val = strtol(entry->d_name, &endptr, 10);
        if (endptr == entry->d_name || *endptr != '\0' ||
            pid_val <= 0 || pid_val > (long)INT_MAX)
            continue;

        pid_t pid = (pid_t)pid_val;

        /* Check if this PID belongs to our process group */
        pid_t pid_pgid = get_pid_pgid(pid);
        if (pid_pgid != pgid)
            continue;

        procs++;
        uint64_t mem = 0;
        if (!get_pid_memory(pid, &mem))
            continue;

        measured++;
        if (UINT64_MAX - total < mem) {
            total = UINT64_MAX;
            break;
        }
        total += mem;
    }

    if (nprocs != NULL)
        *nprocs = procs;
    if (nmeasured != NULL)
        *nmeasured = measured;
    closedir(proc_dir);
    return total;
}

#endif /* __linux__ */

/* ------------------------------------------------------------------------- */
/* Process group killing                                                      */
/* ------------------------------------------------------------------------- */

static bool process_group_exists(pid_t pgid)
{
    if (pgid <= 0)
        return false;

    if (kill_noeintr(-pgid, 0) == 0)
        return true;

    return errno != ESRCH;
}

static bool send_signal_to_group(pid_t pgid, int sig, const char *sig_name)
{
    if (pgid <= 0)
        return false;

    if (kill_noeintr(-pgid, sig) == 0)
        return true;

    if (errno == ESRCH)
        return true;

    fprintf(stderr, "memlimit: failed to send %s to process group %d: %s\n",
            sig_name, (int)pgid, strerror(errno));
    return false;
}

/*
 * Kill an entire process group: SIGTERM first, wait up to grace_sec seconds,
 * then SIGKILL if any process is still alive.
 * Returns false if signaling failed.
 */
static bool kill_process_group(pid_t pgid, int grace_sec)
{
    if (pgid <= 0)
        return false;

    if (kill_noeintr(-pgid, SIGTERM) == -1) {
        if (errno == ESRCH)
            return true;

        fprintf(stderr, "memlimit: failed to send SIGTERM to process group %d: %s\n",
                (int)pgid, strerror(errno));
        return false;
    }

    /* Poll for group disappearance over the grace period (100 ms intervals). */
    for (int i = 0; i < grace_sec * 10; i++) {
        if (!process_group_exists(pgid))
            return true;
        sleep_for_us(REAP_POLL_US);
    }

    /* Still alive — hard kill */
    if (!process_group_exists(pgid))
        return true;

    if (kill_noeintr(-pgid, SIGKILL) == -1) {
        if (errno == ESRCH)
            return true;

        fprintf(stderr, "memlimit: failed to send SIGKILL to process group %d: %s\n",
                (int)pgid, strerror(errno));
        return false;
    }

    for (int i = 0; i < 10; i++) {
        if (!process_group_exists(pgid))
            return true;
        sleep_for_us(REAP_POLL_US);
    }

    return !process_group_exists(pgid);
}

/* ------------------------------------------------------------------------- */
/* Usage & version                                                            */
/* ------------------------------------------------------------------------- */

static void print_usage(const char *progname)
{
    fprintf(stderr,
        "Usage: %s [OPTIONS] <LIMIT> -- <COMMAND> [ARGS...]\n"
        "\n"
        "Run COMMAND with a memory limit.  If the process group's physical\n"
        "memory footprint exceeds LIMIT, the entire process group is killed.\n"
        "\n"
        "LIMIT accepts suffixes: G (GiB), M (MiB), K (KiB), or plain bytes.\n"
        "\n"
        "Options:\n"
        "  -v[N], --verbose[=N] Print memory and process count to stderr every N\n"
        "                       seconds (default: %d)\n"
        "  -g, --grace <SEC>    Grace period between SIGTERM and SIGKILL (default: %d)\n"
        "  --version            Print version and exit\n"
        "  -h, --help           Print this help and exit\n"
        "\n"
        "Exit codes:\n"
        "  <N>      Child's own exit code (on normal exit)\n"
        "  %d      Memory limit exceeded (128 + SIGKILL)\n"
        "  128+N    Child killed by signal N\n"
        "  %d      Command found but not executable / spawn failed\n"
        "  %d      Command not found\n"
        "  %d        Usage error\n",
        progname, DEFAULT_VERBOSE_SEC, DEFAULT_GRACE_SEC, EXIT_OOM,
        EXIT_NOT_EXEC, EXIT_NOT_FOUND, EXIT_USAGE);
}

static void print_version(void)
{
    printf("memlimit %s\n", VERSION);
}

/* ------------------------------------------------------------------------- */
/* Main                                                                       */
/* ------------------------------------------------------------------------- */

int main(int argc, char *argv[])
{
    int verbose_sec = 0;    /* 0 = off, >0 = interval in seconds */
    int grace_sec = DEFAULT_GRACE_SEC;
    uint64_t limit = 0;
    int cmd_start = -1;   /* index into argv where command begins */

    /* ---- Argument parsing ---- */

    if (argc < 2) {
        print_usage(argv[0]);
        return EXIT_USAGE;
    }

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0) {
            cmd_start = i + 1;
            break;
        }
        if (strcmp(argv[i], "-v") == 0) {
            verbose_sec = DEFAULT_VERBOSE_SEC;
        } else if (strncmp(argv[i], "-v", 2) == 0 && argv[i][2] >= '0'
                   && argv[i][2] <= '9') {
            /* -v5, -v10, etc. */
            char *endptr = NULL;
            errno = 0;
            long v = strtol(argv[i] + 2, &endptr, 10);
            if (errno != 0 || *endptr != '\0' || v <= 0 || v > 3600) {
                fprintf(stderr, "memlimit: invalid verbose interval: %s\n",
                        argv[i]);
                return EXIT_USAGE;
            }
            verbose_sec = (int)v;
        } else if (strcmp(argv[i], "--verbose") == 0) {
            verbose_sec = DEFAULT_VERBOSE_SEC;
        } else if (strncmp(argv[i], "--verbose=", 10) == 0) {
            char *endptr = NULL;
            errno = 0;
            long v = strtol(argv[i] + 10, &endptr, 10);
            if (errno != 0 || *endptr != '\0' || v <= 0 || v > 3600) {
                fprintf(stderr, "memlimit: invalid verbose interval: %s\n",
                        argv[i]);
                return EXIT_USAGE;
            }
            verbose_sec = (int)v;
        } else if (strcmp(argv[i], "-g") == 0
                   || strcmp(argv[i], "--grace") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "memlimit: %s requires an argument\n", argv[i]);
                return EXIT_USAGE;
            }
            i++;
            char *endptr = NULL;
            errno = 0;
            long g = strtol(argv[i], &endptr, 10);
            if (errno != 0 || endptr == argv[i] || *endptr != '\0'
                || g <= 0 || g > 3600) {
                fprintf(stderr, "memlimit: invalid grace period: %s\n", argv[i]);
                return EXIT_USAGE;
            }
            grace_sec = (int)g;
        } else if (strcmp(argv[i], "--version") == 0) {
            print_version();
            return 0;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (limit == 0) {
            if (!parse_size(argv[i], &limit)) {
                fprintf(stderr, "memlimit: invalid limit: %s\n", argv[i]);
                return EXIT_USAGE;
            }
        } else {
            fprintf(stderr, "memlimit: unexpected argument: %s\n", argv[i]);
            return EXIT_USAGE;
        }
    }

    if (limit == 0) {
        fprintf(stderr, "memlimit: no memory limit specified\n");
        print_usage(argv[0]);
        return EXIT_USAGE;
    }

    if (cmd_start < 0 || cmd_start >= argc) {
        fprintf(stderr, "memlimit: no command specified (use -- before command)\n");
        return EXIT_USAGE;
    }

    char **cmd_argv = &argv[cmd_start];

    /* ---- Signal setup ---- */

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    if (sigemptyset(&sa.sa_mask) != 0) {
        perror("memlimit: sigemptyset");
        return EXIT_INTERNAL;
    }
    sa.sa_flags = 0;   /* no SA_RESTART: signal delivery should break polling */

    if (sigaction(SIGTERM, &sa, NULL) != 0 ||
        sigaction(SIGINT,  &sa, NULL) != 0 ||
        sigaction(SIGHUP,  &sa, NULL) != 0 ||
        sigaction(SIGQUIT, &sa, NULL) != 0) {
        perror("memlimit: sigaction");
        return EXIT_INTERNAL;
    }

    /* Ensure child status is waitable even if launcher ignored SIGCHLD. */
    struct sigaction sa_chld;
    memset(&sa_chld, 0, sizeof(sa_chld));
    sa_chld.sa_handler = SIG_DFL;
    if (sigemptyset(&sa_chld.sa_mask) != 0 ||
        sigaction(SIGCHLD, &sa_chld, NULL) != 0) {
        perror("memlimit: sigaction(SIGCHLD)");
        return EXIT_INTERNAL;
    }

    /*
     * Ignore SIGTTOU and SIGTTIN so memlimit isn't stopped when it calls
     * tcsetpgrp() from a background process group, or if it writes to the
     * terminal while the child owns the foreground.
     *
     * SIG_IGN dispositions are inherited across exec, so the child would
     * also have these ignored.  We fix that below with POSIX_SPAWN_SETSIGDEF
     * to reset them to SIG_DFL in the child before exec.
     */
    struct sigaction sa_ign;
    memset(&sa_ign, 0, sizeof(sa_ign));
    sa_ign.sa_handler = SIG_IGN;
    if (sigemptyset(&sa_ign.sa_mask) != 0 ||
        sigaction(SIGTTOU, &sa_ign, NULL) != 0 ||
        sigaction(SIGTTIN, &sa_ign, NULL) != 0) {
        perror("memlimit: sigaction(SIGTTOU/SIGTTIN)");
        return EXIT_INTERNAL;
    }

    /* ---- Spawn child in its own process group ---- */

    posix_spawnattr_t attr;
    int attr_err = posix_spawnattr_init(&attr);
    if (attr_err != 0) {
        fprintf(stderr, "memlimit: posix_spawnattr_init failed: %s\n",
                strerror(attr_err));
        return EXIT_INTERNAL;
    }

    attr_err = posix_spawnattr_setflags(&attr,
            POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_SETSIGDEF);
    if (attr_err != 0) {
        fprintf(stderr, "memlimit: posix_spawnattr_setflags failed: %s\n",
                strerror(attr_err));
        posix_spawnattr_destroy(&attr);
        return EXIT_INTERNAL;
    }

    /*
     * Reset SIGTTOU and SIGTTIN to SIG_DFL in the child so it doesn't
     * inherit our SIG_IGN dispositions.  Programs with job control (shells,
     * terminal multiplexers) depend on receiving these signals.
     */
    sigset_t sigdef;
    if (sigemptyset(&sigdef) != 0 ||
        sigaddset(&sigdef, SIGTTOU) != 0 ||
        sigaddset(&sigdef, SIGTTIN) != 0) {
        perror("memlimit: sigset setup");
        posix_spawnattr_destroy(&attr);
        return EXIT_INTERNAL;
    }
    attr_err = posix_spawnattr_setsigdefault(&attr, &sigdef);
    if (attr_err != 0) {
        fprintf(stderr, "memlimit: posix_spawnattr_setsigdefault failed: %s\n",
                strerror(attr_err));
        posix_spawnattr_destroy(&attr);
        return EXIT_INTERNAL;
    }

    attr_err = posix_spawnattr_setpgroup(&attr, 0);   /* pgid = child's own PID */
    if (attr_err != 0) {
        fprintf(stderr, "memlimit: posix_spawnattr_setpgroup failed: %s\n",
                strerror(attr_err));
        posix_spawnattr_destroy(&attr);
        return EXIT_INTERNAL;
    }

    extern char **environ;
    pid_t child_pid = 0;

    int spawn_err = posix_spawnp(&child_pid, cmd_argv[0], NULL, &attr,
                                 cmd_argv, environ);
    posix_spawnattr_destroy(&attr);

    if (spawn_err != 0) {
        fprintf(stderr, "memlimit: failed to spawn '%s': %s\n",
                cmd_argv[0], strerror(spawn_err));
        if (spawn_err == ENOENT)
            return EXIT_NOT_FOUND;
        return EXIT_NOT_EXEC;
    }

    /*
     * Give the child's process group the terminal foreground so that TUI
     * applications can read from the terminal without getting SIGTTIN.
     *
     * We open /dev/tty instead of using STDIN_FILENO because stdin may be
     * redirected (e.g. "memlimit 1G -- vim < /dev/null") while the child
     * still opens /dev/tty directly for terminal input.  /dev/tty always
     * refers to the controlling terminal regardless of fd redirections.
     * If there is no controlling terminal (cron, systemd), open() fails
     * and we skip the handoff.
     *
     * We also check that memlimit currently owns the foreground before
     * handing it off, so that "memlimit ... &" (backgrounded) doesn't
     * steal the foreground from whatever the shell is running.
     *
     * There is a small race between posix_spawnp() returning and the
     * tcsetpgrp() call below: if the child reads from the terminal before
     * we grant the foreground, it will get SIGTTIN and stop.  In practice
     * the child's exec + dynamic linker startup is slower than a single
     * tcsetpgrp syscall.  This is the same race every shell has.
     */
    int tty_fd = open("/dev/tty", O_RDWR | O_NOCTTY);
    bool tty_handoff_done = false;

    if (tty_fd >= 0 && tcgetpgrp(tty_fd) == getpgrp()) {
        if (tcsetpgrp(tty_fd, child_pid) == 0)
            tty_handoff_done = true;
        else if (errno != EPERM)
            fprintf(stderr, "memlimit: warning: tcsetpgrp: %s\n",
                    strerror(errno));
    }

    /* ---- Monitor loop ---- */

    char limit_str[SIZE_BUF_LEN];
    format_size(limit, limit_str, sizeof(limit_str));

    uint64_t peak_mem = 0;
    int peak_nprocs = 0;
    int poll_count = 0;
    int verbose_polls = verbose_sec > 0
        ? verbose_sec * (int)(1000000 / POLL_INTERVAL_US) : 0;
    int exit_code = 0;
    int forwarded_signal = 0;
    bool killed_by_limit = false;
    int child_status = 0;
    bool child_status_valid = false;
    bool child_reaped = false;
    int unreadable_polls = 0;
    int partial_polls = 0;
    bool warned_unreadable = false;
    bool warned_partial = false;

    while (true) {
        /* Check if memlimit itself received a signal */
        if (g_caught_signal) {
            forwarded_signal = g_caught_signal;
            char sig_name[SIZE_BUF_LEN];
            snprintf(sig_name, sizeof(sig_name), "signal %d", g_caught_signal);
            fprintf(stderr, "memlimit: caught signal %s, forwarding to process group\n",
                    sig_name);

            bool cleanup_ok = true;

            if (!send_signal_to_group(child_pid, g_caught_signal, sig_name))
                cleanup_ok = false;

            for (int i = 0; i < grace_sec * 10; i++) {
                if (!process_group_exists(child_pid))
                    break;
                sleep_for_us(REAP_POLL_US);
            }

            if (process_group_exists(child_pid) &&
                !kill_process_group(child_pid, grace_sec)) {
                cleanup_ok = false;
            }

            if (!child_reaped) {
                bool got_status = false;
                if (!wait_for_child_exit(child_pid, &child_status, &got_status,
                                         (grace_sec + 2) * 1000)) {
                    fprintf(stderr,
                            "memlimit: error: timed out waiting for child exit "
                            "after signal forwarding\n");
                    cleanup_ok = false;
                } else {
                    child_reaped = true;
                    child_status_valid = got_status;
                }
            }

            if (!cleanup_ok && process_group_exists(child_pid))
                exit_code = EXIT_INTERNAL;

            if (exit_code != EXIT_INTERNAL) {
                if (child_status_valid) {
                    if (WIFEXITED(child_status))
                        exit_code = WEXITSTATUS(child_status);
                    else if (WIFSIGNALED(child_status))
                        exit_code = 128 + WTERMSIG(child_status);
                    else
                        exit_code = 128 + g_caught_signal;
                } else if (!cleanup_ok) {
                    exit_code = EXIT_INTERNAL;
                } else {
                    exit_code = 128 + g_caught_signal;
                }
            }
            break;
        }

        if (!child_reaped) {
            pid_t w = waitpid_noeintr(child_pid, &child_status, WNOHANG);
            if (w == child_pid) {
                child_reaped = true;
                child_status_valid = true;
            } else if (w == -1 && errno == ECHILD) {
                child_reaped = true;
            } else if (w == -1) {
                perror("memlimit: waitpid");
                exit_code = EXIT_INTERNAL;
                break;
            }
        }

        bool group_alive = process_group_exists(child_pid);
        if (!group_alive) {
            if (child_reaped)
                break;
            sleep_for_us(POLL_INTERVAL_US);
            poll_count++;
            continue;
        }

        /* Measure memory and process count */
        int nprocs = 0;
        int nmeasured = 0;
        bool backend_ok = true;
        uint64_t mem = get_group_memory(child_pid, &nprocs, &nmeasured,
                                        &backend_ok);
        if (mem > peak_mem)
            peak_mem = mem;
        if (nprocs > peak_nprocs)
            peak_nprocs = nprocs;

        bool accounting_unavailable =
            !backend_ok || nprocs == 0 || (nprocs > 0 && nmeasured == 0);

        if (accounting_unavailable) {
            unreadable_polls++;

            if (!warned_unreadable) {
                fprintf(stderr,
                        "memlimit: warning: memory accounting unavailable "
                        "(backend_ok=%s, measured=%d/%d)\n",
                        backend_ok ? "yes" : "no", nmeasured, nprocs);
                warned_unreadable = true;
            }

            if (unreadable_polls >= MEASURE_FAIL_POLLS) {
                fprintf(stderr,
                        "memlimit: error: refusing to continue without memory "
                        "accounting; killing process group\n");

                if (!kill_process_group(child_pid, grace_sec)) {
                    fprintf(stderr,
                            "memlimit: error: failed to terminate process group "
                            "after accounting failure\n");
                }

                if (!child_reaped) {
                    bool got_status = false;
                    if (!wait_for_child_exit(child_pid, &child_status, &got_status,
                                             (grace_sec + 2) * 1000)) {
                        fprintf(stderr,
                                "memlimit: error: timed out waiting for child "
                                "exit after accounting failure\n");
                    } else {
                        child_reaped = true;
                        child_status_valid = got_status;
                    }
                }

                exit_code = EXIT_INTERNAL;
                break;
            }
        } else {
            unreadable_polls = 0;

            if (nprocs > 0 && nmeasured < nprocs) {
                partial_polls++;

                if (!warned_partial) {
                    fprintf(stderr,
                            "memlimit: warning: partial memory accounting "
                            "(measured=%d/%d); monitoring may undercount\n",
                            nmeasured, nprocs);
                    warned_partial = true;
                }

                if (partial_polls >= PARTIAL_FAIL_POLLS) {
                    fprintf(stderr,
                            "memlimit: error: persistent partial accounting; "
                            "killing process group\n");

                    if (!kill_process_group(child_pid, grace_sec)) {
                        fprintf(stderr,
                                "memlimit: error: failed to terminate process "
                                "group after partial accounting failure\n");
                    }

                    if (!child_reaped) {
                        bool got_status = false;
                        if (!wait_for_child_exit(child_pid, &child_status,
                                                 &got_status,
                                                 (grace_sec + 2) * 1000)) {
                            fprintf(stderr,
                                    "memlimit: error: timed out waiting for "
                                    "child exit after partial accounting failure\n");
                        } else {
                            child_reaped = true;
                            child_status_valid = got_status;
                        }
                    }

                    exit_code = EXIT_INTERNAL;
                    break;
                }
            } else {
                partial_polls = 0;
            }
        }

        /* Verbose reporting */
        if (verbose_polls > 0 && (poll_count % verbose_polls == 0)) {
            char cur_str[SIZE_BUF_LEN];
            format_size(mem, cur_str, sizeof(cur_str));
            double pct = (limit > 0) ? ((double)mem / (double)limit) * 100.0 : 0.0;
            fprintf(stderr, "memlimit: %s / %s (%.0f%%) [%d %s]\n",
                    cur_str, limit_str, pct,
                    nprocs, nprocs == 1 ? "proc" : "procs");
        }

        /* Enforce limit */
        if (mem > limit) {
            char mem_str[SIZE_BUF_LEN];
            format_size(mem, mem_str, sizeof(mem_str));
            fprintf(stderr,
                    "memlimit: memory limit %s exceeded (group using %s), "
                    "killing process group\n", limit_str, mem_str);

            bool kill_ok = kill_process_group(child_pid, grace_sec);
            killed_by_limit = true;
            if (!kill_ok) {
                fprintf(stderr,
                        "memlimit: warning: could not confirm full process "
                        "group termination after limit exceeded\n");
            }

            /* Reap the child */
            if (!child_reaped) {
                bool got_status = false;
                if (!wait_for_child_exit(child_pid, &child_status, &got_status,
                                         (grace_sec + 2) * 1000)) {
                    fprintf(stderr,
                            "memlimit: error: timed out waiting for child "
                            "exit after limit kill\n");
                    exit_code = EXIT_INTERNAL;
                    killed_by_limit = false;
                } else {
                    child_reaped = true;
                    child_status_valid = got_status;
                }
            }

            if (!kill_ok && process_group_exists(child_pid)) {
                fprintf(stderr,
                        "memlimit: error: process group still alive after "
                        "limit kill attempts\n");
                exit_code = EXIT_INTERNAL;
                killed_by_limit = false;
            }
            break;
        }

        sleep_for_us(POLL_INTERVAL_US);
        poll_count++;
    }

    /* ---- Reclaim terminal foreground ---- */

    if (tty_fd >= 0) {
        if (tty_handoff_done && tcsetpgrp(tty_fd, getpgrp()) == -1)
            fprintf(stderr, "memlimit: warning: tcsetpgrp reclaim: %s\n",
                    strerror(errno));
        close(tty_fd);
    }

    /* ---- Report peak stats (always) ---- */

    char peak_str[SIZE_BUF_LEN];
    format_size(peak_mem, peak_str, sizeof(peak_str));
    fprintf(stderr, "memlimit: peak memory: %s, peak %s: %d\n",
            peak_str, peak_nprocs == 1 ? "proc" : "procs", peak_nprocs);

    if (exit_code == EXIT_INTERNAL)
        return EXIT_INTERNAL;

    if (killed_by_limit)
        return EXIT_OOM;

    if (forwarded_signal != 0)
        return 128 + forwarded_signal;

    if (child_status_valid) {
        if (WIFEXITED(child_status))
            return WEXITSTATUS(child_status);
        if (WIFSIGNALED(child_status))
            return 128 + WTERMSIG(child_status);
    }

    if (g_caught_signal)
        return 128 + g_caught_signal;

    return exit_code;
}
