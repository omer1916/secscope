# ADR-004: Process tree control and the worker protocol

- Status: accepted (M1)
- Date: 2026-10-05

## Decisions

1. **Windows:** every managed child is created `CREATE_SUSPENDED`, assigned to its own Job
   Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, then resumed (`NtResumeProcess`).
   Grandchildren cannot escape by spawning early. Because the job handle lives in the
   parent, a *crashing* worker also takes its whole tree down (tested:
   `test_killing_the_worker_kills_its_children`).
2. **POSIX:** children start in a new session; cancel sends SIGTERM to the group, then
   SIGKILL after a grace period, then a psutil sweep over every descendant seen so far.
   **Known limitation:** if the worker is SIGKILLed by the OS (not by us), children in their
   own sessions are orphaned. Mitigations: the UI kills the worker's tree through its own
   `terminate_tree`, and the worker exits when stdin closes. Linux `PR_SET_PDEATHSIG` would only
   cover direct children; revisit with Docker isolation in M10.
3. **Worker stdin** is read with raw `os.read(0)` in a daemon thread. Reading
   `sys.stdin.buffer` from a daemon thread crashed the interpreter at shutdown on Windows
   (exit code 0xC0000005, reproduced) because the thread holds the BufferedReader lock.
4. **stdout belongs to the protocol.** The worker keeps a private handle to the binary stdout
   and points `sys.stdout` at stderr, so a stray `print` cannot corrupt the event stream.
5. Child output is decoded as UTF-8, falling back to the OS locale encoding (cp1254 on
   Turkish Windows); the CLI forces UTF-8 on its own stdout/stderr.
6. Extra (non-builtin) modules can be loaded by the worker only when
   `SECSCOPE_ALLOW_EXTRA_MODULES=1` — a test hook, not a plugin system.
