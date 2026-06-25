## Demo: run a command sandboxed, and show the parent stays free.
##
## Two parts:
##   1. fork() a child, restrict() it, exec() ls. Show the child is confined.
##   2. Show the parent process can still write anywhere (it never restricted).

import std/[os, posix, syncio, strutils]
import nimbox

const
  sandboxDir = "/tmp/nimbox-demo"

proc cleanup() =
  try: removeDir(sandboxDir) except CatchableError: discard
  try: removeFile(sandboxDir & ".outside") except CatchableError: discard

proc main() =
  cleanup()
  createDir(sandboxDir)

  echo "=== fork + restrict + exec ==="
  echo "parent: forking child to run 'ls /tmp' sandboxed to ", sandboxDir
  let pid = forkNimbox()
  if pid == 0:
    # child: restrict, then exec. Never returns.
    restrict([sandboxDir], read = ["/usr", "/bin", "/lib", "/etc"])
    exec(["ls", "-la", "/tmp"])
    # only reached if exec failed
    exitnow(127)
  let code = wait(pid)
  echo "parent: child exited with code ", code
  echo "  (ls saw permission denied for /tmp because only ", sandboxDir,
       " was writable)"

  echo ""
  echo "=== parent stays unrestricted ==="
  writeFile(sandboxDir & ".outside", "parent can still write anywhere")
  echo "parent wrote to ", sandboxDir, ".outside (outside the child's sandbox)"
  echo "parent can read it back: ", readFile(sandboxDir & ".outside").strip()

  cleanup()

main()
