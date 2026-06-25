## Windows restricted-token + ACL backend for nimbox. (stub - see Phase 3)
##
## The Windows backend builds a restricted token via CreateRestrictedToken,
## stamps per-path DENY/ALLOW ACEs onto volume DACLs, and spawns the child
## with CreateProcessAsUser. It is the weakest of the three platforms
## (no single syscall hook; the ACL stamping mutates the filesystem).

proc backendSupported*(): bool = false

proc backendName*(): string = "windows-acl"

proc restrictImpl*(writable, read: openArray[string]) =
  raise newException(OSError,
    "nimbox: windows acl backend not yet implemented on this build")
