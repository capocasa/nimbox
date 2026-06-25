## macOS Seatbelt backend for nimbox.
##
## Seatbelt is Apple's TrustedBSD MAC framework - the same kernel-enforced
## sandbox that backs the App Sandbox used by every Mac App Store application,
## and that Chromium, Firefox and Nix ship in production. Apple marked the
## in-process `sandbox_init` API deprecated in headers since 10.8 but it
## continues to ship, Apple's own apps use it, and there is no replacement.
##
## We generate a TinyScheme profile per call and apply it via
## `sandbox_init_with_parameters` in libSystem.dylib. The profile text is
## passed directly - no temp files, no helper binary. The restriction binds
## to the calling process and all descendants, matching Landlock's semantics.
##
## Seatbelt evaluates rules with last-match-wins per operation, so the
## `(deny default)` baseline blocks everything, and each emitted `(allow ...)`
## widens the policy for that path/op. Network is blocked by omission: we emit
## no `network-*` allow, so the default deny covers sockets.

import std/[strutils, sets]
import ./paths

const libSystem = "libSystem.dylib"

# sandbox_init_with_parameters: applies a compiled profile to the calling
# process. Profile is raw TinyScheme source. flags=0. params is an array of
# cstring (for (param "X") substitution) terminated by nil; we pass nil and
# string-substitute paths directly into the profile, matching MXC. errbuf
# receives a human-readable message on failure and must be freed.
proc sandbox_init_with_parameters(profile: cstring; flags: uint64;
        params: ptr UncheckedArray[cstring]; errbuf: ptr cstring): cint
    {.importc, dynlib: libSystem.}
proc sandbox_free_errorbuf(buf: cstring)
    {.importc, dynlib: libSystem.}

# The baseline read-only system paths every macOS process needs to start.
# From MXC's profile: the dynamic linker and standard libraries must stay
# readable or the child cannot exec. SIP independently makes /System and /usr
# read-only at the kernel level, so this only ever grants read access.
const baselineRead = [
  "/usr/lib", "/usr/libexec", "/usr/share", "/System", "/Library",
  "/private/var/db/timezone", "/private/var/db/dyld", "/private/etc",
  "/dev/null", "/dev/zero", "/dev/random", "/dev/urandom"
]

proc quote(s: string): string =
  ## TinyScheme string literal: wrap in double quotes, escape backslash and
  ## double quote. Paths from normalize are absolute and clean, so this is
  ## belt-and-braces.
  result = newStringOfCap(s.len + 2)
  result.add('"')
  for c in s:
    if c == '\\' or c == '"': result.add('\\')
    result.add(c)
  result.add('"')

proc buildProfile(writable, read: openArray[string]): string =
  ## Assemble the TinyScheme profile. Order is: (deny default), baseline read
  ## allows, caller write allows, caller read allows. Last-match-wins means
  ## each allow overrides the default deny for its path/op pair.
  result = newStringOfCap(4096)
  result.add("(version 1)\n(deny default)\n")

  # Baseline: system dirs and devices the dynamic linker needs.
  result.add("(allow file-read*")
  for p in baselineRead:
    result.add("\n  (subpath " & quote(p) & ")")
  result.add(")\n")
  # Exec stays usable for system binaries.
  result.add("(allow process-exec file-read*\n")
  result.add("  (subpath " & quote("/bin") & ")\n")
  result.add("  (subpath " & quote("/sbin") & ")\n")
  result.add("  (subpath " & quote("/usr/bin") & ")\n")
  result.add("  (subpath " & quote("/usr/sbin") & ")\n")
  result.add(")\n")

  # Caller paths. Dedup after normalising so the same dir passed in both
  # writable and read only emits one rule.
  var seen = initHashSet[string]()
  var wpaths: seq[string] = @[]
  var rpaths: seq[string] = @[]
  for p in writable:
    let n = paths.normalize(p)
    if n.len == 0 or seen.containsOrIncl(n): continue
    wpaths.add(n)
  for p in read:
    let n = paths.normalize(p)
    if n.len == 0 or seen.containsOrIncl(n): continue
    rpaths.add(n)

  if wpaths.len > 0:
    result.add("(allow file-write* file-read*")
    for p in wpaths:
      result.add("\n  (subpath " & quote(p) & ")")
    result.add(")\n")
  if rpaths.len > 0:
    result.add("(allow file-read*")
    for p in rpaths:
      result.add("\n  (subpath " & quote(p) & ")")
    result.add(")\n")

proc backendSupported*(): bool = true

proc backendName*(): string = "seatbelt"

proc restrictImpl*(writable, read: openArray[string]) =
  ## Confine the calling thread via a Seatbelt profile. Writable paths get
  ## full access, read paths get read + execute (via the file-read* allow on
  ## system dirs that makes exec work), everything else is denied. The
  ## profile is rebuilt from scratch each call - no state, matching Landlock.
  let profile = buildProfile(writable, read)
  var errbuf: cstring = nil
  let r = sandbox_init_with_parameters(profile.cstring, 0'u64, nil,
                                       addr errbuf)
  if r != 0:
    var msg = "seatbelt: profile rejected"
    if errbuf != nil:
      try: msg = "seatbelt: " & $errbuf
      except CatchableError: discard
      sandbox_free_errorbuf(errbuf)
    raise newException(OSError, "nimbox: " & msg)
