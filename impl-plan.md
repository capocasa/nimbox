# Windows backend implementation plan

## Overview

Implement the Windows backend for nimbox: restricted-token + per-path ACL
sandboxing, per `CROSSPLATFORM.md` Phase 3 and the MS Restricted Tokens docs.
The user-facing API (`restrict`, `runSandboxed`) stays the same as Linux/macOS;
Windows gets its own spawn path because there is no `fork`.

This is the weakest platform. ACL stamping mutates the filesystem and must be
rolled back. Verification on a real Windows VM is a hard gate before merge.

## Backend shape (from MS docs + Codex)

On Windows a token is applied at `CreateProcess` time, so `restrictImpl`
**prepares** a token instead of confining the current thread. The token is
applied when a child is spawned. This differs from Landlock/Seatbelt but the
public API is unchanged: callers do `restrict()` then `runSandboxed(cmd)`.

Per `CROSSPLATFORM.md`, recommendation (b): `runSandboxed` is the portable
high-level entry; `forkNimbox`/`exec`/`wait` stay posix primitives. On Windows
`runSandboxed` calls `spawnSandboxed` directly (one call, no fake fork).

## Chunks

1. **Win32 FFI foundation + restricted token.** Declare the Win32 security/
   token FFI. Implement `buildRestrictedToken()` that opens the current token
   and produces a restricted copy with a fresh random SID. `restrictImpl`
   stores it in a module global. No ACLs yet. Cross-compile check only.

2. **ACL stamping + rollback.** Implement DENY/ALLOW ACE stamping on volume
   roots and the caller paths, with `allVolumeRoots()` enumeration. Every
   mutation recorded so it can be removed. `restrictImpl` builds the token AND
   stamps ACLs. Cross-compile check only.

3. **Process spawn + portable runSandboxed.** Windows `process.nim`:
   `spawnSandboxed(cmd)` calls `CreateProcessAsUser` with the prepared token,
   waits, then rolls back ACLs in a `defer`. Make `runSandboxed` dispatch to
   posix fork-exec or windows spawn. Cross-compile check only.

4. **Windows CI job + README + integrate.** Add a windows-latest job to
   `.github/workflows/ci.yml` that builds + runs a smoke test. Update README
   platform table. Verify Linux + macOS still green.

## Hard gate

The plan doc says Windows is "not mergeable without a Windows test run".
The CI job on `windows-latest` is that test run. Do not claim Windows works
until the CI job passes there. ACL rollback correctness (no leftover DENY
ACEs) is the single most dangerous part.
