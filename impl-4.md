# Chunk 4: Windows CI job + README + integrate

## Goal

Add a Windows job to the CI workflow so the backend compiles and runs on a real
`windows-latest` runner, update the README platform table, and run a final
integration pass across all three platforms.

## Read first

- `.github/workflows/ci.yml` - current Linux + macOS jobs
- `README.md` - platform status table, layout section
- `src/nimbox.nim` - CLI usage block, system-dir defaults
- `tests/test_sandbox.nim` - test gating (posix fork tests vs CLI tests)
- `impl-plan.md` - the hard gate: not mergeable without a Windows test run

## Instructions

### 1. Add Windows job to `.github/workflows/ci.yml`

In the build matrix, add:

```yaml
          - os: windows-latest
            artifact: nimbox-windows-amd64
            ext: zip
```

The Windows job needs the same build + test steps. Watch for:
- Binary is `nimbox.exe` on Windows, not `nimbox`. The existing build step uses
  `-o:nimbox`; on Windows Nim appends `.exe` automatically but the package/
  upload steps reference `nimbox` without extension. Add a Windows-aware copy:
  use a `shell: bash` package step that copies `nimbox.exe` on Windows.

The 3code workflow's Windows package step is a good reference:
```yaml
      - name: Package (Windows)
        if: matrix.ext == 'zip'
        shell: pwsh
        run: |
          New-Item -ItemType Directory -Path ${{ matrix.artifact }} | Out-Null
          Copy-Item nimbox.exe ${{ matrix.artifact }}/
          Copy-Item README.md, LICENSE ${{ matrix.artifact }}/
          Compress-Archive -Path ${{ matrix.artifact }} -DestinationPath ${{ matrix.artifact }}.${{ matrix.ext }}
```

Make the existing Unix `Package` step `if: matrix.ext == 'tar.gz'` and add the
Windows step `if: matrix.ext == 'zip'` (mirror the 3code workflow shape).

Add the windows artifact to the release job's `gh release create` call:
`nimbox-windows-amd64.zip`.

### 2. Test gating on Windows

The library tests in `tests/test_sandbox.nim` are gated
`when defined(linux) or defined(macosx):` because they use fork. On Windows
only the CLI tests run. That's correct for now - the CLI test
("write allowed, write denied") exercises `restrict` + exec and is the
meaningful Windows test. Verify the CLI test uses `sh -c`; on Windows there's
no `sh` by default. The test invokes `sh -c 'echo ok > path'`. On a Windows
runner `sh` may not exist.

Fix: make the CLI test shell-agnostic. Use `cmd /c "echo ok > path"` on
Windows, `sh -c '...'` on posix. Edit `tests/test_sandbox.nim` to pick the
shell per-OS. Keep the posix path identical in behaviour.

ALSO: the library-test temp dirs and `nimboxExe()` helper must work on Windows
(forward vs back slashes). `std/os`'s `/` handles this, so it should be fine,
but verify.

### 3. CLI system-dir defaults

`src/nimbox.nim` line ~85 has a `when defined(macosx)` / `else` for the
read-only system dirs passed to `restrict`. Add a `defined(windows)` branch:
on Windows the ACL backend's restrictImpl ignores the `read` arg semantics
differently (it stamps ALLOW read on those paths). For the CLI, the sensible
default is to make the system dirs (where the command's exe + DLLs live)
read-only. Use `C:\Windows`, `C:\Windows\System32` - but better: on Windows
the ACL backend stamps read-access implicitly (volume DENY is write-only),
so passing an empty read list may suffice. Decide based on what the chunk 2
ACL logic does and keep the CLI working. If unsure, pass `[]` and let the
volume-root semantics handle it, with a comment.

### 4. README platform table

Update:
```
| Windows | works | restricted token + ACLs (CreateProcessAsUser) |
```
Replace the "planned" row. Update the "On Windows, restrict raises" sentence
to reflect that it now works. Update the Layout section: `acl.nim` line changes
from "(stub)" to "windows backend: restricted token + ACLs".

### 5. Final integration

- `nimble install` after building (per project convention: installed binary
  stays current).
- Commit everything. Commit message one-liner, e.g.
  "add Windows ACL backend, runSandboxed dispatch, windows CI".
- Push to main.
- Watch all three CI jobs with `gh run watch` (this is NOT pure housekeeping,
  so watch it). The Windows job is the hard gate for the Windows backend.

## Verification

Use the todo tool:
1. Linux: `nimble test` green.
2. Cross-compile: windows + macos both clean.
3. CI green on all three OSes (watch the run).
4. `git diff` shows ci.yml, README, nimbox.nim, test_sandbox.nim, acl.nim,
   process.nim.

## Next step

This is the final chunk. When the Windows CI job is green, the Windows backend
is merged. Remove the `impl-*.md` and `impl-plan.md` files (they're dev
scaffolding, not repo content) unless you want to keep them as design docs.

Final handoff: report the three green CI jobs and the state of the repo.
