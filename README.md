# nimbox

A filesystem sandbox for Nim, backed by Linux
[Landlock](https://docs.kernel.org/userspace-api/landlock.html). Restrict a
process (and every child it spawns) to a fixed set of writable paths. No
root, no container, no helper binary, ~no runtime cost.

Landlock is a Linux Security Module any unprivileged process can apply to
itself. Once applied, the kernel enforces the policy on every syscall from
the thread and all of its descendants. `mv`, `tee`, `rm -rf`, a rogue build
script, it doesn't matter, the kernel checks every write.

## Two primitives

```nim
restrict(writable, read)   # confine this thread to writable/read-only paths
forkNimbox / exec          # fork a child, where you restrict() then exec()
```

That's the whole API. `restrict` locks the current thread down; `forkNimbox`
+ `exec` run a sandboxed child. Everything else is the kernel.

## Platform status

| Platform | Status | Mechanism |
|----------|--------|-----------|
| Linux | **works** | Landlock (Landlock + the kernel's own VFS checks) |
| macOS | alpha | Seatbelt (`sandbox-exec`) not yet wired up |
| Windows | alpha | restricted token + ACLs not yet wired up |

On non-Linux, `restrict` raises `OSError` and the CLI exits with an error.
The library structure is set up to take Seatbelt / Windows backends; see
`sandbox-research.md` for the plan.

## Requirements

- Linux 5.19+ (Landlock ABI v2, for `REFER`/`TRUNCATE`). 6.2+ covers all
  access rights used here.
- Nim 2.0+.

## As a binary

```
nimbox restrict PATH [PATH ...] -- CMD [ARGS ...]
```

Confines itself to the listed PATHs, then exec()s CMD. System directories
(`/usr`, `/bin`, `/lib`, `/etc`) are made read-only automatically so the
command's binaries stay runnable.

```sh
$ nimbox restrict /tmp /home/me/work -- ls -la
$ nimbox restrict . -- make test
```

The same binary is also the library, so a parent program can self-invoke via
`/proc/self/exe` to run a sandboxed child without a separate helper:

```nim
execCmd("/proc/self/exe restrict /tmp -- ls -la")
```

## As a library

```nim
import nimbox

# fork a child, restrict it, exec the untrusted command, wait
let pid = forkNimbox()
if pid == 0:
  restrict(["/tmp", "/home/me/work"], read = ["/usr", "/bin", "/lib"])
  exec(["ls", "-la"])
  exitnow(127)   # only if exec failed
let code = wait(pid)

# the parent never called restrict, so it stays fully privileged
```

Or just call `restrict` on yourself, if you don't need to stay free:

```nim
restrict(["/tmp", "/home/me/work"])
```

## The `restrict` proc

```nim
proc restrict(writable: openArray[string]; read: openArray[string] = [])
```

`writable` paths get full access (read, write, create, delete, rename,
execute). `read` paths get read + execute only; defaults to empty. Everything
else is denied. Each call layers a new Landlock domain; the effective access
is the intersection of all applied domains, so later calls only **narrow**
the window. Drop a path from `writable` and re-call to revoke it.

### Why there's no un-restrict

Landlock is monotonic: once a domain is applied it can only get stricter,
never looser. There is no `unrestrict`, no escape hatch, and `fork`/`exec`
inherit the domain. This is the property that makes a sandbox a sandbox.

The practical consequence: to run a sandboxed command while staying free
yourself, **fork first**, then `restrict` in the child. The parent never
restricts. That's what `forkNimbox` is for.

## What gets caught

Every filesystem mutation Landlock knows: `write`, `creat`, `unlink`,
`rename` (so `mv`), `mkdir`, `rmdir`, `symlink`, `truncate`, `ftruncate`,
`link`, cross-directory reparent. Read and execute are gated too.

Not yet restricted by Landlock (kernel caveats): `chdir`, `stat`, `flock`,
`chmod`, `chown`, `setxattr`, `utime`, `access`. Mostly safe for a coding
agent; the dangerous ops are covered.

## Running the demo

```sh
nim c --path:src -r tests/demo.nim
```

Forks a child that runs `ls` sandboxed, then shows the parent still writing
freely outside the sandbox.

## Tests

```sh
nimble test
```

CLI tests shell out to the binary; library tests fork a child per scenario
(since a Landlock domain is permanent for the thread that applies it).

## Layout

```
src/
  nimbox.nim           # library + CLI (when isMainModule)
  nimbox/
    restrict.nim       # the restrict() proc
    process.nim        # forkNimbox / exec / wait
    landlock.nim       # raw Landlock syscalls
tests/
  demo.nim
  test_sandbox.nim
```

See `sandbox-research.md` for the full prior-art survey (sandlock, Codex,
Anthropic sandbox-runtime) and why the OS primitive beats command
whitelisting.

## License

MIT.
