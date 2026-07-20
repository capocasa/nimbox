# Chunk 2: ACL stamping with rollback

## Goal

Add DENY/ALLOW ACE stamping to the Windows backend. `restrictImpl` builds the
restricted token (from chunk 1) AND stamps ACEs: a DENY ACE for the restricting
SID on every volume root the process should not write, and ALLOW ACEs for the
restricting SID on the writable (full) and read (read+execute) paths. Every
mutation is recorded so chunk 3's spawn can roll it back.

## Read first

- `src/nimbox/acl.nim` - chunk 1's state (token FFI, currentRestrictedToken)
- `src/nimbox/paths.nim` - `normalize()`
- `CROSSPLATFORM.md` lines 200-215 (the two-access-check model, the Codex
  failure cases) and lines 330-360 (risks: ACL rollback, volume enumeration)
- `impl-plan.md`

## Background: the stamping model

The restricting SID triggers a second access check on every `NtCreateFile`.
Strategy from Codex/MS docs:

1. **Enumerate all volume roots** (`FindFirstVolumeW`/`FindNextVolumeW`). Each
   drive letter root (`C:\`, `D:\`) gets a DENY ACE for our SID for write
   rights. This makes everything write-denied by default across all drives.
2. **ALLOW on writable paths**: stamp an ALLOW ACE for our SID with
   `FILE_ALL_ACCESS` on each normalized writable path. Because two checks run,
   the ALLOW must be present or the write fails.
3. **ALLOW on read paths**: ALLOW ACE with `FILE_GENERIC_READ |
   FILE_GENERIC_EXECUTE`.
4. **The Codex lesson**: stamp EVERY ancestor of denied paths, and do NOT
   over-deny (read ACEs on system dirs the process needs to load DLLs from).
   For v1, the volume-root DENY covers the "deny everything" case; the ALLOWs
   re-open the caller paths. System dirs (C:\Windows, Program Files) stay
   write-denied by the volume DENY, which is what we want, but READ access is
   NOT denied (we only DENY write rights on the volume root), so DLL loading
   keeps working.

### ACL rollback (the dangerous part)

Stamping mutates filesystem security descriptors. If we crash or the child
misbehaves, we leave DENY ACEs on volume roots that break other processes.
Record every `(path, wasModified)` so the spawn (chunk 3) can remove our ACEs
in a `defer`. For v1 store the list of stamped paths in a module global
`stampedPaths: seq[PathRecord]`.

## Instructions

Add to `src/nimbox/acl.nim` (extend chunk 1's file):

```nim
# --- ACL types ---
type
  ACCESS_MODE = enum  # from accctrl.h
    NO_INHERITANCE = 0
    GRANT_ACCESS   # allow
    DENY_ACCESS    # deny
  TRUSTEE_TYPE = enum
    TRUSTEE_IS_UNKNOWN = 0, TRUSTEE_IS_USER, TRUSTEE_IS_GROUP
  MULTIPLE_TRUSTEE_OPERATION = enum
    NO_MULTIPLE_TRUSTEE = 0
  SE_OBJECT_TYPE = enum
    SE_FILE_OBJECT = 1

# Build a EXPLICIT_ACCESS for our SID
proc buildExplicitAccess(sid: PSID; mode: ACCESS_MODE; rights: DWORD): ...
```

The single cleanest Win32 call is `SetNamedSecurityInfo` with a DACL, OR the
older `SetEntriesInAcl` + `SetNamedSecurityInfo`. Use the `SetEntriesInAcl`
path: build an `EXPLICIT_ACCESS` array, merge into an ACL, then call
`SetNamedSecurityInfo(path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, ...)`.
`SetEntriesInAcl` is in advapi32.

Implement:

```nim
var stampedPaths: seq[string]  # paths we mutated, for rollback

proc stampAce(path, sid, mode, rights) =
  ## Add an ACE for sid to path's DACL. Records path in stampedPaths.
  ...

proc enumerateVolumeRoots(): seq[string] =
  ## FindFirstVolumeW / FindNextVolumeW. Returns ["C:\\", "D:\\", ...]
  ...

proc stampAcls(writable, read: seq[string]; sid: PSID) =
  ## DENY write on all volume roots, ALLOW full on writable, ALLOW read+exec
  ## on read paths. Record every mutated path.
  ...

proc rollbackAcls(sid: PSID) =
  ## Remove our SID's ACEs from every path in stampedPaths. Best-effort,
  ## called in a defer by the spawn in chunk 3.
  ...
```

Then extend `restrictImpl`:

```nim
proc restrictImpl*(writable, read: openArray[string]) =
  currentRestrictedToken = buildRestrictedToken()
  let sid = currentRestrictingSid   # store the SID from chunk 1
  let w = dedup(map(normalize, writable))
  let r = dedup(map(normalize, read))
  stampAcls(w, r, sid)
```

Keep `currentRestrictingSid` as a module global set by `buildRestrictedToken`
(chunk 1 needs to store it alongside the token handle).

### Key details

- **FILE_ALL_ACCESS** = 0x1F01FF. **FILE_GENERIC_READ** = 0x120089.
  **FILE_GENERIC_EXECUTE** = 0x1200A0. **FILE_GENERIC_WRITE** = 0x120116.
- **DENY rights on volume root**: stamp DENY with `FILE_GENERIC_WRITE |
  DELETE | ...` (the write/delete/create rights) NOT full deny. We must not
  deny read or the process can't even enumerate the drive.
- **Sub-container inheritance**: use `CONTAINER_INHERIT_ACE |
  OBJECT_INHERIT_ACE` in the inheritance field so the ACE applies to children.
- **SetEntriesInAcl** signature: `SetEntriesInAcl(count, entries, oldAcl,
  newAcl)`. You pass a fresh EXPLICIT_ACCESS; it merges with the existing DACL.
- **Path form**: Windows paths must use backslashes; `normalize` from std/os
  produces OS-native separators, so on Windows it gives backslashes. Good.
- **Drive root form**: `C:\` not `C:` or `C:\\`.
- **Rollback is best-effort** in v1: enumerate `stampedPaths`, rebuild the
  DACL without our SID's ACEs. It's fine if rollback can't handle a path that
  was deleted; log to stderr and continue.

## Verification

1. Cross-compile for Windows:
   ```
   nim c --os:windows --cpu:amd64 --noLinking --path:src src/nimbox.nim
   ```
2. Linux still green:
   ```
   nimble test
   ```
3. `git diff` shows only `src/nimbox/acl.nim` changed.

Use the todo tool for these.

## Next step

When complete and verified, call context_clear with:
- summary: "Chunk 2 done: ACL stamping (DENY on volume roots, ALLOW on
  writable/read) with rollback recording. restrictImpl now builds token +
  stamps. Cross-compiles windows/amd64, Linux tests green. No spawn yet."
- instructions: "Read impl-3.md and execute the instructions there."
