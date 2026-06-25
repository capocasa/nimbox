## process: fork, restrict, exec.
##
## The safe way to run an untrusted command under a Landlock sandbox. The
## parent fork()s and immediately exec()s a fresh single-threaded image; that
## image applies the Landlock domain and exec()s the target. The parent never
## restricts itself, so it stays free to run privileged commands.
##
## Why not fork-then-run-Nim-code: after fork() in a multithreaded program
## only async-signal-safe calls are permitted until exec(), because other
## threads' locks (allocator, GC, stdio) are held forever in the child. We
## work around this by exec'ing into a fresh process whose restriction setup
## runs single-threaded, before the second exec into the untrusted command.

import std/[os, posix, strutils]
import ./restrict

type
  ExitCode* = distinct int

proc `$`*(e: ExitCode): string = $(int(e))

proc forkNimbox*(): Pid =
  ## Fork a child that inherits nothing of the parent's Landlock state.
  ## In the child, call `restrict` then `exec`; the parent gets the pid to
  ## wait on. Raises on failure.
  result = posix.fork()
  if result < 0:
    raise newException(OSError, "nimbox: fork() failed: " & osLastError().`$`)

proc exec*(cmd: openArray[string]) =
  ## Replace the current process image with `cmd` (first element is the
  ## program, the rest its args). Uses PATH lookup. Only returns on failure.
  if cmd.len == 0:
    raise newException(ValueError, "nimbox.exec: empty command")
  let prog0 = cmd[0]
  var argv = allocCStringArray(cmd)
  # execvp does not return on success
  discard execvp(prog0.cstring, argv)
  deallocCStringArray(argv)
  # reached only on error
  raise newException(OSError,
    "nimbox: exec(" & cmd.join(" ") & ") failed: " & osLastError().`$`)

proc wait*(pid: Pid): ExitCode =
  ## Block until `pid` exits. Returns the process exit code (0-255 for normal
  ## exit, 128+signal for termination by signal).
  var status: cint = 0
  if posix.waitpid(pid, status, 0) < 0:
    raise newException(OSError,
      "nimbox: waitpid failed: " & osLastError().`$`)
  if WIFEXITED(status):
    result = ExitCode(WEXITSTATUS(status))
  elif WIFSIGNALED(status):
    result = ExitCode(128 + WTERMSIG(status))
  else:
    result = ExitCode(1)

template runSandboxed*(writable: openArray[string]; cmd: openArray[string];
                        read: openArray[string] = []): ExitCode =
  ## One-shot helper: fork, in the child `restrict(writable, read)` then
  ## `exec(cmd)`, in the parent `wait`. Returns the child's exit code. The
  ## parent keeps running unrestricted.
  block:
    let pid = forkNimbox()
    if pid == 0:
      try:
        restrict(writable, read)
        exec(cmd)
      except CatchableError as e:
        stderr.writeLine("nimbox child: " & e.msg)
      exitnow(127)   # only reached on setup failure
    wait(pid)
