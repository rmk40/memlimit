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

/*
 * Ensure POSIX APIs (posix_spawn, sigaction, getpgid) and BSD-origin APIs
 * (usleep) are visible on glibc.  _DEFAULT_SOURCE covers both POSIX.1-2008
 * and traditional BSD functions that glibc still provides.
 */
#if defined(__linux__)
#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <termios.h>
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
/* Memory measurement (platform-specific)                                     */
/* ------------------------------------------------------------------------- */

#if defined(__APPLE__)

/*
 * macOS: Get phys_footprint for a single PID via proc_pid_rusage().
 * This is Activity Monitor's "Memory" column.  Accounts for compressed pages
 * on Apple Silicon.  Returns 0 on error.
 */
static uint64_t get_pid_memory(pid_t pid)
{
    struct rusage_info_v4 info;
    if (proc_pid_rusage(pid, RUSAGE_INFO_V4, (rusage_info_t *)&info) == 0)
        return info.ri_phys_footprint;
    return 0;
}

/*
 * macOS: Sum phys_footprint for all processes in a process group.
 * Uses proc_listallpids() to enumerate, then filters by pgid.
 * If nprocs is non-NULL, stores the number of matching processes.
 */
static uint64_t get_group_memory(pid_t pgid, int *nprocs)
{
    if (nprocs != NULL)
        *nprocs = 0;

    int count = proc_listallpids(NULL, 0);
    if (count <= 0)
        return 0;

    /* Allocate space for the PID list. Add slack for races. */
    size_t alloc_count = (size_t)count + 64;

    if (alloc_count > SIZE_MAX / sizeof(pid_t))
        return 0;

    pid_t *pids = malloc(alloc_count * sizeof(pid_t));
    if (pids == NULL) {
        fprintf(stderr, "memlimit: malloc failed in get_group_memory\n");
        return 0;
    }

    count = proc_listallpids(pids, (int)(alloc_count * sizeof(pid_t)));
    if (count <= 0) {
        free(pids);
        return 0;
    }

    uint64_t total = 0;
    int procs = 0;
    for (int i = 0; i < count; i++) {
        if (pids[i] <= 0)
            continue;

        struct proc_bsdinfo bsdinfo;
        int ret = proc_pidinfo(pids[i], PROC_PIDTBSDINFO, 0,
                               &bsdinfo, (int)sizeof(bsdinfo));
        if (ret <= 0 || bsdinfo.pbi_pgid != (uint32_t)pgid)
            continue;

        procs++;
        uint64_t mem = get_pid_memory(pids[i]);
        if (UINT64_MAX - total < mem) {
            total = UINT64_MAX;
            break;
        }
        total += mem;
    }

    if (nprocs != NULL)
        *nprocs = procs;
    free(pids);
    return total;
}

#elif defined(__linux__)

/*
 * Linux: Get PSS (Proportional Set Size) for a single PID.
 * Reads /proc/PID/smaps_rollup (kernel 4.14+).  PSS is the closest equivalent
 * to macOS phys_footprint — it accounts for proportional sharing of pages
 * among processes.  Returns 0 on error.
 */
static uint64_t get_pid_memory(pid_t pid)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/smaps_rollup", (int)pid);

    FILE *f = fopen(path, "r");
    if (f == NULL)
        return 0;

    char line[256];
    uint64_t pss_kb = 0;
    while (fgets(line, sizeof(line), f) != NULL) {
        if (strncmp(line, "Pss:", 4) == 0) {
            unsigned long long val = 0;
            if (sscanf(line + 4, " %llu", &val) == 1)
                pss_kb = (uint64_t)val;
            break;
        }
    }
    fclose(f);

    /* kB → bytes, with overflow guard */
    if (pss_kb > UINT64_MAX / 1024)
        return UINT64_MAX;
    return pss_kb * 1024;
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
 */
static uint64_t get_group_memory(pid_t pgid, int *nprocs)
{
    if (nprocs != NULL)
        *nprocs = 0;

    DIR *proc_dir = opendir("/proc");
    if (proc_dir == NULL)
        return 0;

    uint64_t total = 0;
    int procs = 0;
    struct dirent *entry;

    while ((entry = readdir(proc_dir)) != NULL) {
        /* Only numeric directory names (PIDs) */
        if (entry->d_name[0] < '0' || entry->d_name[0] > '9')
            continue;

        char *endptr = NULL;
        long pid_val = strtol(entry->d_name, &endptr, 10);
        if (endptr == entry->d_name || *endptr != '\0' || pid_val <= 0)
            continue;

        pid_t pid = (pid_t)pid_val;

        /* Check if this PID belongs to our process group */
        pid_t pid_pgid = get_pid_pgid(pid);
        if (pid_pgid != pgid)
            continue;

        procs++;
        uint64_t mem = get_pid_memory(pid);
        if (UINT64_MAX - total < mem) {
            total = UINT64_MAX;
            break;
        }
        total += mem;
    }

    if (nprocs != NULL)
        *nprocs = procs;
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

    if (kill(-pgid, 0) == 0)
        return true;

    return errno != ESRCH;
}

/*
 * Kill an entire process group: SIGTERM first, wait up to grace_sec seconds,
 * then SIGKILL if any process is still alive.
 */
static void kill_process_group(pid_t pgid, int grace_sec)
{
    if (pgid <= 0)
        return;

    if (kill(-pgid, SIGTERM) == -1 && errno == ESRCH)
        return;

    /* Poll for group disappearance over the grace period (100 ms intervals). */
    for (int i = 0; i < grace_sec * 10; i++) {
        if (!process_group_exists(pgid))
            return;
        usleep(100000);
    }

    /* Still alive — hard kill */
    if (!process_group_exists(pgid))
        return;

    if (kill(-pgid, SIGKILL) == -1 && errno == ESRCH)
        return;
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
    sa.sa_flags = 0;   /* no SA_RESTART: we want usleep to be interrupted */

    if (sigaction(SIGTERM, &sa, NULL) != 0 ||
        sigaction(SIGINT,  &sa, NULL) != 0 ||
        sigaction(SIGHUP,  &sa, NULL) != 0 ||
        sigaction(SIGQUIT, &sa, NULL) != 0) {
        perror("memlimit: sigaction");
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
    sigemptyset(&sa_ign.sa_mask);
    sigaction(SIGTTOU, &sa_ign, NULL);
    sigaction(SIGTTIN, &sa_ign, NULL);

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
    sigemptyset(&sigdef);
    sigaddset(&sigdef, SIGTTOU);
    sigaddset(&sigdef, SIGTTIN);
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

    if (tty_fd >= 0 && tcgetpgrp(tty_fd) == getpgrp()) {
        if (tcsetpgrp(tty_fd, child_pid) == -1 && errno != EPERM)
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
    bool killed_by_limit = false;
    int child_status = 0;
    bool child_status_valid = false;
    bool child_reaped = false;

    while (true) {
        /* Check if memlimit itself received a signal */
        if (g_caught_signal) {
            char sig_name[SIZE_BUF_LEN];
            snprintf(sig_name, sizeof(sig_name), "%d", g_caught_signal);
            fprintf(stderr, "memlimit: caught signal %s, forwarding to process group\n",
                    sig_name);
            kill(-child_pid, g_caught_signal);
            kill_process_group(child_pid, grace_sec);

            pid_t wr = waitpid(child_pid, &child_status, 0);
            if (wr == child_pid) {
                child_reaped = true;
                child_status_valid = true;
                if (WIFEXITED(child_status))
                    exit_code = WEXITSTATUS(child_status);
                else if (WIFSIGNALED(child_status))
                    exit_code = 128 + WTERMSIG(child_status);
                else
                    exit_code = 128 + g_caught_signal;
            } else if (wr == -1 && errno == ECHILD) {
                child_reaped = true;
                exit_code = 128 + g_caught_signal;
            } else {
                exit_code = 128 + g_caught_signal;
            }
            break;
        }

        if (!child_reaped) {
            pid_t w = waitpid(child_pid, &child_status, WNOHANG);
            if (w == child_pid) {
                child_reaped = true;
                child_status_valid = true;
            } else if (w == -1 && errno == ECHILD) {
                child_reaped = true;
            } else if (w == -1 && errno != EINTR) {
                perror("memlimit: waitpid");
                exit_code = EXIT_INTERNAL;
                break;
            }
        }

        bool group_alive = process_group_exists(child_pid);
        if (!group_alive) {
            if (child_reaped)
                break;
            usleep(POLL_INTERVAL_US);
            poll_count++;
            continue;
        }

        /* Measure memory and process count */
        int nprocs = 0;
        uint64_t mem = get_group_memory(child_pid, &nprocs);
        if (mem > peak_mem)
            peak_mem = mem;
        if (nprocs > peak_nprocs)
            peak_nprocs = nprocs;

        /* Warn once if we cannot measure memory at all */
        if (mem == 0 && poll_count == 0 && !child_reaped) {
            fprintf(stderr,
                    "memlimit: warning: could not read memory for any process "
                    "(insufficient permissions or unsupported kernel?)\n");
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

            killed_by_limit = true;
            kill_process_group(child_pid, grace_sec);

            /* Reap the child */
            if (!child_reaped) {
                pid_t wr = waitpid(child_pid, &child_status, 0);
                if (wr == child_pid) {
                    child_reaped = true;
                    child_status_valid = true;
                } else if (wr == -1 && errno == ECHILD) {
                    child_reaped = true;
                }
            }
            break;
        }

        usleep(POLL_INTERVAL_US);
        poll_count++;
    }

    /* ---- Reclaim terminal foreground ---- */

    if (tty_fd >= 0) {
        if (tcsetpgrp(tty_fd, getpgrp()) == -1)
            fprintf(stderr, "memlimit: warning: tcsetpgrp reclaim: %s\n",
                    strerror(errno));
        close(tty_fd);
    }

    /* ---- Report peak stats (always) ---- */

    char peak_str[SIZE_BUF_LEN];
    format_size(peak_mem, peak_str, sizeof(peak_str));
    fprintf(stderr, "memlimit: peak memory: %s, peak %s: %d\n",
            peak_str, peak_nprocs == 1 ? "proc" : "procs", peak_nprocs);

    if (killed_by_limit)
        return EXIT_OOM;

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
