## nimbox - a filesystem sandbox backed by OS-native primitives.
##
## Linux uses Landlock; macOS uses Seatbelt (sandbox_init_with_parameters).
## The user-facing API is identical on both.
##
## As a library:
##   import nimbox
##   restrict("/tmp", "/home/me/work")
##   # this thread and all children can now only touch those paths
##
## As a binary:
##   nimbox restrict PATH [PATH ...] -- CMD [ARGS ...]
##   # confines itself to PATHs, then exec()s CMD
##
## Two primitives, exposed both ways:
##   1. restrict(paths)  - confine the current thread's filesystem access
##   2. forkSandbox/exec/wait - fork a child where you restrict() then exec()
##
## See the `restrict` and `process` modules. Low-level Landlock access in
## `landlock`.

import ./nimbox/restrict
export restrict

import ./nimbox/process
export process

# ----------------------------------------------------------------------- CLI

when isMainModule:
  import std/[os, syncio]

  const usage = """
nimbox - filesystem sandbox backed by OS-native primitives

Usage:
  nimbox restrict PATH [PATH ...] -- CMD [ARGS ...]

  Applies a Landlock domain allowing full access (read, write, create,
  delete, rename, execute) to the listed PATHs, then exec()s CMD. CMD and
  its children are confined: writes outside the paths fail with EACCES.

Examples:
  nimbox restrict /tmp /home/me/work -- ls -la
  nimbox restrict . -- make test

Landlock is monotonic: the restriction is permanent for this process and all
descendants. There is no "unrestrict".
  """

  proc cliMain(): int =
    let args = commandLineParams()
    if args.len == 0 or args[0] == "-h" or args[0] == "--help":
      stdout.writeLine(usage)
      return 0

    if args[0] != "restrict":
      stderr.writeLine(usage)
      stderr.writeLine("\nError: unknown subcommand (expected 'restrict')")
      return 2

    var
      paths: seq[string] = @[]
      cmd: seq[string] = @[]
      seenSep = false

    var i = 1
    while i < args.len:
      let a = args[i]
      if seenSep:
        cmd.add(a)
      elif a == "--":
        seenSep = true
      elif a == "-h" or a == "--help":
        stdout.writeLine(usage); return 0
      else:
        paths.add(a)
      inc i

    if paths.len == 0:
      stderr.writeLine(usage)
      stderr.writeLine("\nError: no paths given")
      return 2
    if cmd.len == 0:
      stderr.writeLine(usage)
      stderr.writeLine("\nError: no command given (use -- before the command)")
      return 2

    # System dirs are read-only so the command's binaries and libs are
    # executable but not modifiable. Writable paths come from the user.
    when defined(windows):
      # Windows cannot confine the current process; restrict() only prepares
      # the token and stamps ACLs. runSandboxed spawns the child with that
      # token and rolls the ACLs back in a defer.
      #
      # No explicit read list: the ACL backend stamps a write/delete DENY
      # on every volume root, leaving read+execute open. C:\Windows and
      # System32 stay readable and runnable without an ALLOW ACE, so the
      # command's exe and DLLs resolve. Passing [] is correct here.
      try:
        return int(runSandboxed(paths, cmd))
      except CatchableError as e:
        stderr.writeLine("nimbox: " & e.msg)
        return 127
    else:
      # posix: confine this process, then exec into CMD. Children inherit
      # the domain, so the parent restricting itself before exec is enough.
      when defined(macosx):
        # macOS has no /lib or /lib64; the seatbelt backend already adds the
        # baseline (/usr/lib, /System, /Library, /dev/*) so the dynamic linker
        # works. Just expose the user-facing binary dirs as read-only.
        restrict(paths, read = ["/usr", "/bin", "/sbin", "/etc"])
      else:
        restrict(paths, read = ["/usr", "/bin", "/lib", "/lib64", "/etc"])
      try:
        exec(cmd)
      except CatchableError as e:
        stderr.writeLine("nimbox: " & e.msg)
        return 127

  quit(cliMain())
