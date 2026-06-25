## restrict: lock the current thread's filesystem access to a set of paths.
##
## Each call builds and applies a single Landlock domain. Within that domain,
## the writable paths get full access (read, write, create, delete, rename,
## execute) and the read paths get read + execute only; everything else is
## denied.
##
## The kernel intersects every applied domain, so successive calls only
## tighten: if you first restrict to {a, b, c} then to {a, b}, the effective
## set is {a, b}. A path must be allowed by *every* applied domain to remain
## accessible.
##
## No state, no init. Each call is a self-contained kernel restriction.
## On non-Linux (or kernels < 5.13) it raises.

import std/[os, sets]
import ./landlock

proc normalize(p: string): string =
  ## Absolute, symlink-resolved path. Falls back to the cleaned absolute
  ## path if it can't be resolved (e.g. does not exist yet).
  result = absolutePath(p).normalizedPath()
  try:
    if dirExists(result) or fileExists(result):
      let r = expandFilename(result)
      if r.len > 0: result = r
  except CatchableError:
    discard

proc restrict*(writable: openArray[string]; read: openArray[string] = []) =
  ## Confine the calling thread (and all future children).
  ##
  ## `writable` paths get full access (read, write, create, delete, rename,
  ## execute). `read` paths get read + execute only; defaults to empty.
  ## Everything else is denied. Each call layers a new domain; the effective
  ## access is the intersection of all applied domains, so later calls only
  ## narrow. Drop a path from `writable` and re-call to revoke it.
  if not landlock.supported():
    raise newException(OSError,
      "nimbox: restrict needs Linux Landlock (kernel 5.13+)")

  var rs = landlock.createRuleset()
  try:
    let w = landlock.writeRights()
    let r = landlock.readRights()
    let ro = read.toHashSet()
    for p in writable:
      let n = normalize(p)
      if n.len == 0: continue
      try: rs.addRule(n, w)
      except OSError: discard
    for p in ro:
      let n = normalize(p)
      if n.len == 0: continue
      try: rs.addRule(n, r)
      except OSError: discard
    rs.apply()
  except CatchableError:
    rs.close()
    raise


