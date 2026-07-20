# Chunk 1: Win32 FFI foundation + restricted token

## Goal

Lay the Win32 security/token FFI and implement `buildRestrictedToken()`, which
opens the current process token and produces a restricted copy carrying a fresh
random SID. `restrictImpl` calls it and stores the token in a module global for
the spawn phase. No ACL stamping yet (chunk 2), no spawning (chunk 3). This
chunk must cross-compile for Windows from Linux.

## Read first

- `src/nimbox/acl.nim` - the current stub you are replacing
- `src/nimbox/restrict.nim` - the dispatcher that calls `acl.restrictImpl`
- `src/nimbox/paths.nim` - `normalize()`, used to canonicalise caller paths
- `CROSSPLATFORM.md` lines 215-260 (Phase 3 mechanism + the `acl.nim` sketch)
- `impl-plan.md` - overall shape

## Background: the Win32 calls (from MS Restricted Tokens docs)

1. `OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &token)`
   - get a handle to the current process's token.
2. `AllocateAndInitializeSid(...)` to make a fresh random SID. Use
   `SECURITY_NT_AUTHORITY` (S-1-5) with a random identifier authority. This
   SID is the "restricting SID": Windows runs TWO access checks on every
   `NtCreateFile` when a restricting SID is present, and BOTH must pass.
3. `CreateRestrictedToken(token, LUA_TOKEN, 0, nil, 0, nil, 0, nil, &restricted)`
   - Actually for a restricting SID we use `CreateRestrictedToken` with the
   `0` flags form that takes a list of SIDs to disable, OR we use
   `CreateRestrictedToken(baseToken, 0, disableCount, disableSids, ...)`.
   The cleanest documented path: call `CreateRestrictedToken` with the
   `DISABLE_MAX_PRIVILEGE` flag (strips privileges) and pass our fresh SID
   via the `SidstoRestrict` parameter (the last-but-one array). This makes
   it a "restricted token" in the MS sense, which triggers the two-access-
   check semantics that the ACL stamping relies on.
4. The returned `restricted` handle is what we store.

## Instructions

Rewrite `src/nimbox/acl.nim` (currently a stub). Structure:

```nim
## Windows restricted-token + ACL backend for nimbox.
## [doc comment explaining the two-access-check model, that restrictImpl
##  prepares a token applied at spawn time, and that this is the weak
##  platform - see CROSSPLATFORM.md Phase 3]

import std/[sets, strutils]
import ./paths

when defined(windows):
  # --- Win32 types ---
  type
    HANDLE = int
    BOOL = int32
    DWORD = uint32
    PSID = ptr object  # opaque
    TokenHandle {.pure.} = enum ...  # or just use DWORD consts

  # SID_IDENTIFIER_AUTHORITY is a 6-byte array
  type SidIdentifierAuthority = array[6, uint8]

  # --- Win32 consts ---
  const
    TOKEN_QUERY = 0x0008'i32
    TOKEN_DUPLICATE = 0x0002'i32
    DISABLE_MAX_PRIVILEGE = 0x1'i32
    GetCurrentProcessPseudo = (-1)  # HANDLE pseudo-handle

  # --- Win32 FFI imports ---
  proc GetCurrentProcess(): HANDLE {.stdcall, dynlib: "kernel32", importc.}
  proc OpenProcessToken(processHandle: HANDLE; desiredAccess: DWORD;
        tokenHandle: ptr HANDLE): BOOL {.stdcall, dynlib: "advapi32", importc.}
  proc AllocateAndInitializeSid(pIdentifierAuthority: ptr SidIdentifierAuthority;
        nSubAuthorityCount: uint8; ... ): BOOL {.stdcall, dynlib: "advapi32", importc.}
  proc CreateRestrictedToken(existingToken: HANDLE; flags: DWORD;
        sidToDisableCount: DWORD; sidToDisable: ptr PSID;
        privilegeToDeleteCount: DWORD; privilege: ptr pointer;
        restrictedSidCount: DWORD; sidToRestrict: ptr PSID;
        newToken: ptr HANDLE): BOOL {.stdcall, dynlib: "advapi32", importc.}
  proc CloseHandle(h: HANDLE): BOOL {.stdcall, dynlib: "kernel32", importc.}
  proc GetLastError(): DWORD {.stdcall, dynlib: "kernel32", importc.}

  var currentRestrictedToken: HANDLE = 0   # set by restrictImpl, used by spawn

  proc buildRestrictedToken(): HANDLE =
    ## Open current token, build a restricted copy carrying a fresh SID.
    ## Raises OSError on any step failing.
    ...

proc backendSupported*(): bool =
  when defined(windows): true else: false

proc backendName*(): string = "windows-acl"

when defined(windows):
  proc restrictImpl*(writable, read: openArray[string]) =
    ## Build the restricted token and store it. ACL stamping comes in chunk 2;
    ## for now just record writable/read paths normalised for the stamping
    ## pass. Canonicalise caller paths via paths.normalize now.
    currentRestrictedToken = buildRestrictedToken()
    # chunk 2 will stamp ACLs here
```

### Key details

- **Nim stdlib has Win32 bindings** in `std/windows` and `std/winlean`. Check
  what's already declared before redeclaring; reuse `HANDLE`, `DWORD`,
  `GetCurrentProcess`, `CloseHandle` from there. Only declare what's missing
  (the security/token procs are NOT in winlean). Use `import std/winlean` and
  add the advapi32 imports yourself.
- **AllocateAndInitializeSid** is variadic in C. Nim can't import variadic
  stdcall cleanly. Use a fixed-arity wrapper: declare it with the max number
  of sub-authorities you need (1 random DWORD sub-authority is enough for a
  unique SID), or use `AllocateLocallyUniqueId` + manual SID building. Simplest
  robust path: declare AllocateAndInitializeSid with a fixed 1 sub-authority.
- **Pseudo-handle**: `GetCurrentProcess()` returns -1 (a pseudo-handle). It
  does not need closing.
- **Error handling**: every BOOL return that is 0 (false) is an error; fetch
  `GetLastError()` and raise `OSError` with a message including the code.
- **No ACL stamping in this chunk.** Leave a clear comment where chunk 2 adds it.

## Verification

1. Cross-compile for Windows from Linux (we have no Windows box locally):
   ```
   nim c --os:windows --cpu:amd64 --noLinking --path:src src/nimbox.nim
   ```
   Must compile with zero errors. Fix type mismatches in the FFI.
2. Linux build + test must STILL pass (the Linux path doesn't touch acl.nim):
   ```
   nimble test
   ```
3. `git diff` to confirm only `src/nimbox/acl.nim` changed.

Use the todo tool for these verification steps.

## Next step

When this chunk is complete and verified, call context_clear with:
- summary: "Chunk 1 done: Win32 token FFI in acl.nim, buildRestrictedToken()
  implemented, restrictImpl stores token in currentRestrictedToken. Cross-
  compiles for windows/amd64, Linux tests still green. No ACL stamping yet."
- instructions: "Read impl-2.md and execute the instructions there."
