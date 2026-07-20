# Chunk 3: Process spawn + portable runSandboxed

## Goal

Implement the Windows spawn path in `process.nim` and make `runSandboxed` the
portable entry point. Windows has no fork: `spawnSandboxed(cmd)` calls
`CreateProcessAsUser` with the prepared restricted token, waits for the child,
then rolls back the ACLs (chunk 2) in a `defer`. On posix, `runSandboxed` keeps
using fork-restrict-exec.

## Read first

- `src/nimbox/process.nim` - current posix-only fork/exec/wait + runSandboxed
- `src/nimbox/acl.nim` - chunks 1+2: currentRestrictedToken, rollbackAcls,
  currentRestrictingSid, stampedPaths
- `src/nimbox/restrict.nim` - the restrict dispatcher
- `CROSSPLATFORM.md` lines 262-300 (process.nim on Windows, why no fork,
  recommendation b: runSandboxed is the portable entry)
- `impl-plan.md`

## Background

On posix, `restrict()` confines the current thread and children inherit it, so
the pattern is fork -> restrict-in-child -> exec. On Windows a token is applied
at `CreateProcess` time and cannot retroactively narrow the *current* process.
So Windows does it in one call: spawn the child WITH the prepared token.

Per `CROSSPLATFORM.md` recommendation (b):
- `runSandboxed(writable, cmd, read=[])` is the portable high-level helper.
- `forkNimbox`/`exec`/`wait` are posix primitives (kept for posix callers).
- Windows `runSandboxed` calls `spawnSandboxed` directly.

`CreateProcessAsUser` does NOT need `SE_ASSIGNPRIMARYTOKEN_NAME` when the token
is a restricted copy of the caller's own (MS docs).

## Instructions

### Edit `src/nimbox/process.nim`

Split the module with `when defined(windows)` / `else`. The shared surface
(`runSandboxed`, `ExitCode`) stays available on both; the fork/exec/wait procs
are posix-only.

```nim
## process: run a sandboxed command.
##
## Posix: forkNimbox/exec/wait - fork a child, restrict() in it, exec.
## Windows: spawnSandboxed - CreateProcessAsUser with the prepared token.
## runSandboxed is the portable entry that dispatches to the right one.

import std/os
type ExitCode* = distinct int
proc `$`*(e: ExitCode): string = $(int(e))

when defined(windows):
  import ./acl    # currentRestrictedToken, rollbackAcls, currentRestrictingSid

  proc spawnSandboxed*(cmd: openArray[string]): ExitCode =
    ## CreateProcessAsUser with the prepared restricted token, wait, roll
    ## back ACLs in a defer. Raises if no token was prepared (restrict()
    ## not called) or CreateProcess fails.
    if currentRestrictedToken == 0:
      raise newException(OSError, "nimbox: restrict() must be called first")
    defer:
      rollbackAcls(currentRestrictingSid)   # always clean up, even on error
    # ... CreateProcessAsUser, WaitForSingleObject, map exit code ...
else:
  # posix: existing forkNimbox/exec/wait unchanged
  import std/[posix, strutils]
  import ./restrict
  proc forkNimbox*(): Pid = ...
  proc exec*(cmd: openArray[string]) = ...
  proc wait*(pid: Pid): ExitCode = ...

template runSandboxed*(writable, cmd, read = []): ExitCode =
  when defined(windows):
    # Windows: prepare token + stamp ACLs, then spawn.
    restrict(writable, read)
    spawnSandboxed(cmd)
  else:
    # posix: fork, restrict in child, exec, wait in parent.
    block:
      let pid = forkNimbox()
      if pid == 0:
        try:
          restrict(writable, read)
          exec(cmd)
        except CatchableError as e:
          stderr.writeLine("nimbox child: " & e.msg)
        exitnow(127)
      wait(pid)
```

### CreateProcessAsUser FFI (in acl.nim or process.nim windows branch)

```nim
type
  PROCESS_INFORMATION {.pure.} = object
    hProcess: HANDLE
    hThread: HANDLE
    dwProcessId: DWORD
    dwThreadId: DWORD
  STARTUPINFO {.pure.} = object
    cb: DWORD
    # ... rest zeroed; we only need cb=sizeof
proc CreateProcessAsUserW(token, app, cmdLine, ... , &si, &pi): BOOL
    {.stdcall, dynlib: "advapi32", importc.}
proc WaitForSingleObject(h: HANDLE; ms: DWORD): DWORD
    {.stdcall, dynlib: "kernel32", importc.}
proc GetExitCodeProcess(h: HANDLE; code: ptr DWORD): BOOL
    {.stdcall, dynlib: "kernel32", importc.}
```

### Key details

- **CommandLine string**: `CreateProcessW` needs a single mutable UTF-16
  command line. Build it from `cmd` by quoting each arg (Windows quoting:
  wrap in double quotes, escape embedded quotes). Nim's `os` module may have
  a helper; check `std/os` for `quoteShellWindows` or similar.
- **Working dir**: pass NULL (inherit) or the writable path. v1: NULL.
- **Token check**: if `currentRestrictedToken == 0`, the caller forgot to
  `restrict()` first. Raise a clear error.
- **Rollback MUST run**: use `defer: rollbackAcls(...)` so it runs whether
  CreateProcess succeeds or fails and whether the child errors.
- **Exit code mapping**: `GetExitCodeProcess` gives the child's exit code
  (0-255). Map to `ExitCode` directly.
- **Don't break the posix path**: the existing `forkNimbox`/`exec`/`wait`
  keep their exact signatures and behaviour. The `tests/test_sandbox.nim`
  library tests use them on posix and must still pass.

### process.nim posix branch

The existing fork/exec/wait code moves under `else` (posix). It imports
`./restrict` and keeps working exactly as before. The `runSandboxed` template
at the bottom dispatches.

## Verification

1. Cross-compile for Windows:
   ```
   nim c --os:windows --cpu:amd64 --noLinking --path:src src/nimbox.nim
   ```
2. Linux tests (exercise the posix fork/exec/wait path):
   ```
   nimble test
   ```
3. macOS cross-compile still works:
   ```
   nim c --os:macosx --cpu:amd64 --noLinking --path:src src/nimbox.nim
   ```
4. `git diff` shows `src/nimbox/process.nim` + maybe `src/nimbox/acl.nim`.

Use the todo tool for these.

## Next step

When complete and verified, call context_clear with:
- summary: "Chunk 3 done: Windows spawnSandboxed via CreateProcessAsUser with
  ACL rollback in defer. runSandboxed dispatches to spawn (windows) or
  fork-exec (posix). Cross-compiles windows+macos, Linux tests green."
- instructions: "Read impl-4.md and execute the instructions there."
