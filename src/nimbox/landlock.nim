## Low-level Linux Landlock backend for nimbox.
##
## Landlock is a Linux Security Module (kernel 5.13+) that lets any
## unprivileged process restrict its own filesystem access. Once applied to a
## thread, the restriction binds to that thread and all descendants forever:
## you can only ever add *more* rules, never loosen them.
##
## This module is Linux-specific. On other platforms it compiles to no-ops so
## the rest of nimbox stays portable, but the interesting work is here.

const landlockAvailable* = defined(linux)

import std/posix
type
  AccessFds* = distinct uint64
    ## Bitmask of `LANDLOCK_ACCESS_FS_*` rights.

when defined(linux):
  import std/oserrors
  # Syscall numbers are stable on every Linux/Arch combination (UAPI).
  const
    sysLandlockCreateRuleset = 444
    sysLandlockAddRule = 445
    sysLandlockRestrictSelf = 446

    LANDLOCK_CREATE_RULESET_VERSION = 1.cuint

    # Filesystem access rights, in bit order from linux/landlock.h.
    LANDLOCK_ACCESS_FS_EXECUTE = (1'u64 shl 0)
    LANDLOCK_ACCESS_FS_WRITE_FILE = (1'u64 shl 1)
    LANDLOCK_ACCESS_FS_READ_FILE = (1'u64 shl 2)
    LANDLOCK_ACCESS_FS_READ_DIR = (1'u64 shl 3)
    LANDLOCK_ACCESS_FS_REMOVE_DIR = (1'u64 shl 4)
    LANDLOCK_ACCESS_FS_REMOVE_FILE = (1'u64 shl 5)
    LANDLOCK_ACCESS_FS_MAKE_CHAR = (1'u64 shl 6)
    LANDLOCK_ACCESS_FS_MAKE_DIR = (1'u64 shl 7)
    LANDLOCK_ACCESS_FS_MAKE_REG = (1'u64 shl 8)
    LANDLOCK_ACCESS_FS_MAKE_SOCK = (1'u64 shl 9)
    LANDLOCK_ACCESS_FS_MAKE_FIFO = (1'u64 shl 10)
    LANDLOCK_ACCESS_FS_MAKE_BLOCK = (1'u64 shl 11)
    LANDLOCK_ACCESS_FS_MAKE_SYM = (1'u64 shl 12)
    LANDLOCK_ACCESS_FS_REFER = (1'u64 shl 13)
    LANDLOCK_ACCESS_FS_TRUNCATE = (1'u64 shl 14)
    LANDLOCK_ACCESS_FS_IOCTL_DEV = (1'u64 shl 15)

  type
    RulesetAttr {.packed.} = object
      handledAccessFs: uint64
      handledAccessNet: uint64
      scoped: uint64

    PathBeneathAttr {.packed.} = object
      allowedAccess: uint64
      parentFd: cint

  proc syscall(n: clong): clong {.importc: "syscall", header: "<unistd.h>", varargs.}
  proc rawOpen(path: cstring, flags: cint): cint {.importc: "open", header: "<fcntl.h>".}
  proc rawClose(fd: cint): cint {.importc: "close", header: "<unistd.h>".}
  template checkErrno(ctx: string) =
    let e = osLastError()
    raise newException(OSError,
      "landlock: " & ctx & " failed (errno=" & $int(e) & ")")

  proc queryAbi(): int =
    let r = syscall(clong sysLandlockCreateRuleset, nil, 0.culong,
                    LANDLOCK_CREATE_RULESET_VERSION.cuint)
    if r < 0: checkErrno("create_ruleset(VERSION)")
    result = int r

  proc supportedMask(): uint64 =
    ## The set of filesystem rights *this kernel* understands. We handle all
    ## of them so anything not explicitly allowed is denied.
    result = LANDLOCK_ACCESS_FS_EXECUTE or
             LANDLOCK_ACCESS_FS_WRITE_FILE or
             LANDLOCK_ACCESS_FS_READ_FILE or
             LANDLOCK_ACCESS_FS_READ_DIR or
             LANDLOCK_ACCESS_FS_REMOVE_DIR or
             LANDLOCK_ACCESS_FS_REMOVE_FILE or
             LANDLOCK_ACCESS_FS_MAKE_CHAR or
             LANDLOCK_ACCESS_FS_MAKE_DIR or
             LANDLOCK_ACCESS_FS_MAKE_REG or
             LANDLOCK_ACCESS_FS_MAKE_SOCK or
             LANDLOCK_ACCESS_FS_MAKE_FIFO or
             LANDLOCK_ACCESS_FS_MAKE_BLOCK or
             LANDLOCK_ACCESS_FS_MAKE_SYM or
             LANDLOCK_ACCESS_FS_REFER or
             LANDLOCK_ACCESS_FS_TRUNCATE or
             LANDLOCK_ACCESS_FS_IOCTL_DEV

  proc readRights*: AccessFds =
    ## The "read" rights bundle: execute + read file + read dir.
    AccessFds(uint64(LANDLOCK_ACCESS_FS_EXECUTE or
                     LANDLOCK_ACCESS_FS_READ_FILE or
                     LANDLOCK_ACCESS_FS_READ_DIR))

  proc writeRights*: AccessFds =
    ## Everything: full read + all the mutating ops we handle. Granting this
    ## to a path makes it fully usable.
    AccessFds(uint64(readRights()) or
              LANDLOCK_ACCESS_FS_WRITE_FILE or
              LANDLOCK_ACCESS_FS_REMOVE_DIR or
              LANDLOCK_ACCESS_FS_REMOVE_FILE or
              LANDLOCK_ACCESS_FS_MAKE_CHAR or
              LANDLOCK_ACCESS_FS_MAKE_DIR or
              LANDLOCK_ACCESS_FS_MAKE_REG or
              LANDLOCK_ACCESS_FS_MAKE_SOCK or
              LANDLOCK_ACCESS_FS_MAKE_FIFO or
              LANDLOCK_ACCESS_FS_MAKE_BLOCK or
              LANDLOCK_ACCESS_FS_MAKE_SYM or
              LANDLOCK_ACCESS_FS_REFER or
              LANDLOCK_ACCESS_FS_TRUNCATE or
              LANDLOCK_ACCESS_FS_IOCTL_DEV)

proc openPath*(path: string): cint =
  when defined(linux):
    result = rawOpen(path, 0o2000000)  # O_PATH (010000000 octal)
    if result < 0: checkErrno("open('" & path & "') O_PATH")
  else:
    discard

proc closeFd*(fd: cint) =
  when defined(linux):
    if fd >= 0:
      discard rawClose(fd)

proc supported*(): bool = landlockAvailable

type
  Ruleset* = object
    ## A built but not-yet-applied Landlock ruleset.
    when defined(linux):
      fd: cint
      abi: int

proc createRuleset*(): Ruleset =
  ## Create an empty ruleset that handles every filesystem right this kernel
  ## knows. Once enacted, every handled right is denied *unless* a rule allows
  ## it on a specific path.
  when defined(linux):
    let mask = supportedMask()
    let attr = RulesetAttr(handledAccessFs: mask,
                           handledAccessNet: 0,
                           scoped: 0)
    let abi = queryAbi()
    let fd = syscall(clong sysLandlockCreateRuleset,
                     unsafeAddr attr, sizeof(attr).culong, 0.cuint)
    if fd < 0: checkErrno("create_ruleset")
    result.fd = cint fd
    result.abi = abi
  else:
    raise newException(OSError, "nimbox landlock backend requires Linux")

proc addRule*(rs: var Ruleset; path: string; allowed: AccessFds) =
  ## Add a path-beneath rule: grant `allowed` rights to the file hierarchy under
  ## `path`. The fd must point at the parent directory (or the file itself).
  when defined(linux):
    if rs.fd < 0:
      raise newException(ValueError, "nimbox: ruleset already consumed")
    let pfd = openPath(path)
    try:
      let pb = PathBeneathAttr(allowedAccess: uint64(allowed), parentFd: pfd)
      const LANDLOCK_RULE_PATH_BENEATH = 1
      let r = syscall(clong sysLandlockAddRule, rs.fd.clong,
                      LANDLOCK_RULE_PATH_BENEATH.clong,
                      unsafeAddr pb, 0.cuint)
      if r < 0: checkErrno("add_rule('" & path & "')")
    finally:
      closeFd(pfd)

proc apply*(rs: var Ruleset) =
  ## Apply the ruleset to the calling thread. Requires NO_NEW_PRIVS first.
  ## After this the restriction is permanent for this thread and all children.
  when defined(linux):
    if rs.fd < 0:
      raise newException(ValueError, "nimbox: ruleset already consumed")
    # prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
    const PR_SET_NO_NEW_PRIVS = 38
    let p = syscall(clong 157, PR_SET_NO_NEW_PRIVS.clong, 1.clong,
                    0.clong, 0.clong, 0.clong)
    if p < 0: checkErrno("prctl(NO_NEW_PRIVS)")
    let r = syscall(clong sysLandlockRestrictSelf, rs.fd.clong, 0.cuint)
    if r < 0: checkErrno("restrict_self")
    closeFd(rs.fd)
    rs.fd = -1

proc close*(rs: var Ruleset) =
  when defined(linux):
    closeFd(rs.fd)
    rs.fd = -1

proc `$`*(rs: Ruleset): string =
  when defined(linux):
    "Ruleset(fd=" & $rs.fd & ", abi=" & $rs.abi & ")"
  else:
    "Ruleset(unavailable)"
