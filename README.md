# memlimit

Zero-dependency, single-binary memory limiter for macOS and Linux. Uses the
right metric per platform (`phys_footprint` on macOS, PSS on Linux), tracks
the entire process group, and requires no root or kernel configuration.

```bash
memlimit 8G -- some-leaky-program --flag
```

## Why

Long-running processes sometimes leak memory slowly enough that you don't
notice until your system is nearly unresponsive. By the time the OS
intervention dialog appears, it's too late: it wants to kill your terminal
emulator or other unrelated processes, not the one actually leaking.

Existing tools all have gaps:

- **`cgroups` / `systemd-run --scope`** require root and are Linux-only.
- **`ulimit -v`** caps virtual address space, not physical memory. It's
  trivially exceeded by memory-mapped files, and doesn't exist on macOS.
- **RSS-based tools** use the wrong metric. RSS counts shared pages fully for
  every process that maps them, and on macOS it ignores compressed memory
  entirely (see [Platforms](#platforms) below).

`memlimit` fills the gap: an unprivileged, cross-platform alternative that
uses the accurate memory metric on each platform and monitors the entire
process group as a unit. No root. No cgroups. No kernel modules.

## Usage

```
memlimit [OPTIONS] <LIMIT> -- <COMMAND> [ARGS...]
```

### Examples

```bash
# Kill if process group exceeds 10 GiB
memlimit 10G -- make -j8

# 500 MiB limit with verbose monitoring (every 5 seconds by default)
memlimit -v 500M -- python3 train.py

# Verbose monitoring every 1 second
memlimit -v1 500M -- python3 train.py

# Custom grace period (2 seconds between SIGTERM and SIGKILL)
memlimit --grace 2 2G -- node server.js
```

### Quick Start

Install with Homebrew:

```bash
brew install rmk40/tap/memlimit
```

Then run:

```bash
memlimit 8G -- some-command --arg
```

### Options

| Flag                     | Default | Description                                                           |
| ------------------------ | ------- | --------------------------------------------------------------------- |
| `-v[N]`, `--verbose[=N]` | off     | Print memory and process count to stderr every N seconds (default: 5) |
| `-g`, `--grace <SEC>`    | `5`     | Seconds between SIGTERM and SIGKILL on limit breach                   |
| `--version`              |         | Print version and exit                                                |
| `-h`, `--help`           |         | Print help and exit                                                   |

### Limit Format

Accepts an integer with an optional suffix (case-insensitive):

- `G` - GiB
- `M` - MiB
- `K` - KiB
- `B` or no suffix - bytes

### Exit Codes

| Code    | Meaning                                         |
| ------- | ----------------------------------------------- |
| `<N>`   | Child exited with code N                        |
| `137`   | Memory limit exceeded (128 + SIGKILL)           |
| `128+N` | Child killed by signal N                        |
| `126`   | Command found but not executable / spawn failed |
| `127`   | Command not found                               |
| `2`     | Usage error                                     |

## Platforms

The obvious metric for measuring memory is RSS (Resident Set Size), but RSS
is wrong on both platforms. It counts shared pages fully for every process
that maps them, so a system with 10 processes sharing a library reports 10x
the actual cost. On macOS it's even worse: RSS ignores compressed memory
entirely, so a process that has 2 GB of physical footprint compressed into
500 MB of RAM will report the 500 MB figure.

Each platform has a better metric, but they require different APIs:

**macOS** uses `phys_footprint` via `proc_pid_rusage()`. This is the same
number Activity Monitor shows in its "Memory" column. It accounts for
compressed pages, purgeable memory, and IOKit mappings. Process group
enumeration uses `proc_listallpids()` + `proc_pidinfo()`, which are
macOS-specific Mach interfaces.

**Linux** uses PSS (Proportional Set Size) from `/proc/PID/smaps_rollup`
(kernel 4.14+). PSS divides each shared page's cost equally among the
processes mapping it, so 10 processes sharing a 10 MB library each report
1 MB instead of 10 MB. Process group enumeration uses `opendir("/proc")` +
the `getpgid()` syscall, which is a single syscall per candidate PID with
no parsing or TOCTOU issues.

The implementation uses compile-time `#ifdef` to select the right approach
for each platform. The shared code (argument parsing, spawn, signal handling,
monitor loop, kill logic) is plain POSIX and identical on both.

## Build

```
make
```

No external dependencies. Uses only system headers and libc.

- **macOS**: requires `clang` (ships with Xcode or Command Line Tools)
- **Linux**: requires `gcc` or `clang` and kernel 4.14+ for `smaps_rollup`
- **WSL2**: fully supported (WSL2 runs a real Linux kernel)

## Install

Homebrew:

```bash
brew install rmk40/tap/memlimit
```

From source:

```
sudo make install
```

Installs to `/usr/local/bin` by default. Override with `PREFIX`:

```
sudo make install PREFIX=/opt/local
```

Uninstall:

```
sudo make uninstall
```

## How It Works

1. **Launch**: The target command is spawned via `posix_spawnp()` in its own
   process group (`POSIX_SPAWN_SETPGROUP`), so all descendants can be signaled
   as a unit. Portable POSIX, works identically on macOS and Linux.

2. **Monitor**: Every 250 ms, scan the process list for members of the child's
   process group and sum their memory:
   - **macOS**: `proc_listallpids()` + `proc_pidinfo()` for group filtering,
     `proc_pid_rusage()` for `ri_phys_footprint`.
   - **Linux**: `opendir("/proc")` + `getpgid()` for group filtering,
     `/proc/PID/smaps_rollup` for PSS.

3. **Enforce**: If the total exceeds the limit, send `SIGTERM` to the entire
   process group, wait up to `--grace` seconds, then `SIGKILL` if processes
   remain.

4. **Report**: Peak memory usage is printed to stderr on exit.

## Limitations

- **Poll-based, not kernel-enforced.** A sub-250ms memory spike could slip
  through before being detected.
- **Same-user processes only.** Both platforms can only read memory stats for
  processes owned by the same user without elevated privileges.
- **Process group escape.** If a child calls `setpgid()` to leave the process
  group, it won't be killed. Some daemonization patterns do this.

### Linux-Specific

- **Kernel 4.14+ recommended** for `/proc/PID/smaps_rollup`. On older kernels,
  `memlimit` falls back to `/proc/PID/smaps` for PSS.
- **`ptrace_scope` may restrict access.** With `kernel.yama.ptrace_scope >= 1`,
  reading `smaps_rollup` for another user's processes requires
  `CAP_SYS_PTRACE`. Same-user reads work fine under the default setting.
- **PSS reads are slower than macOS.** The kernel walks all VMAs per
  `smaps_rollup` read. Can take ~100ms for very large processes, but fine at
  the 250ms poll interval for typical workloads.

## License

MIT
