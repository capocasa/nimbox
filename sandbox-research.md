# Sandbox research

Goal: a proper sandbox for 3code that filters writes through low-level OS
mechanisms - kernel syscalls on Linux, Seatbelt on macOS, restricted tokens
on Windows. The boundary must be enforced regardless of *what* command runs
(no command whitelisting, no policy parsing per command). This rules out the
Claude Code / Anthropic `sandbox-runtime` approach, which layers excludedCommands,
proxy env-var tricks, and per-tool policy on top of the OS primitives. We want
the primitive itself.

## TL;DR recommendation

Build a tiny launcher that applies OS-native restrictions before exec'ing the
shell command, then forgets about it. The enforcement is in the kernel.

- **Linux**: Landlock ruleset (writes confined to workspace + tmp). Optional
  seccomp-bpf to kill network syscalls. No root, no container, ~5ms.
- **macOS**: Seatbelt `sandbox-exec` with a generated `.sbpl` policy. Ships
  with the OS, zero deps.
- **Windows**: restricted token via `CreateRestrictedToken` + per-path ACLs.
  Weakest of the three (no single syscall hook) but workable; Codex ships it.

A `mv` *is* caught - see "Does the kernel catch mv?" below.

## The clean prior art (small, compiled)

Two projects do exactly the primitive-only thing we want:

### sandlock (multikernel/sandlock)
Rust, Apache-2.0, ~228 stars. Linux-only, no container, no root.
Landlock + seccomp-bpf + seccomp user notification. ~5ms startup, 97% of bare
metal throughput. Has a C ABI (`libsandlock_ffi.so`) and Python ctypes bindings.
The most direct inspiration for a Linux backend - clean separation of
policy (what to allow) vs enforcement (Landlock rules + seccomp filters).
Downside: Linux-only, so macOS/Windows need separate implementations.

### Codex CLI sandbox (`codex-rs/linux-sandbox`, `seatbelt.rs`, `windows-sandbox-rs`)
The reference for all three platforms. Codex ships a separate
`codex-linux-sandbox` helper binary that applies Landlock + seccomp to its
own thread then execs the target - this is the exact pattern 3code should
copy on Linux. On macOS it generates a Seatbelt policy and runs
`/usr/bin/sandbox-exec`. On Windows it builds a restricted token and computes
allowed/denied paths.

Codex's *policy* layer (read-only / workspace-write / danger-full-access
modes, writable_roots, .git read-only inside writable roots) is good design
to borrow - it's not command whitelisting, it's path-allowlist policy
translated to OS rules.

## The nitty-gritty prior art (avoid as primary model)

### Anthropic sandbox-runtime (`@anthropic-ai/sandbox-runtime`)
TypeScript/Node, Apache-2.0, ~4.5k stars. Seatbelt (macOS) + bubblewrap (Linux).
Ships with Claude Code. Technically uses the right OS primitives but layers
heavy policy on top: `excludedCommands` (command-pattern matching to opt
commands out of the sandbox), proxy env-var injection for network, hardcoded
.git denies, a `dangerouslyDisableSandbox` escape hatch the model is prompted
to auto-retry through. This is the "command whitelisting" complexity to avoid.

It also revealed a real architectural lesson worth keeping: built-in tools
(Read/Edit/Write) bypass the OS sandbox because they run in the agent process,
not in the spawned shell. Claude's `sandbox.denyRead` did NOT stop its own Read
tool - only `permissions.deny` did (single source: claudecodecamp.com
experiment, Apr 2026). For 3code this means the sandbox must cover the
agent's own write/patch tools too, not just `bash`.

## Platform mechanisms (the clean story)

### Linux: Landlock (primary) + seccomp-bpf (network)

Landlock is a stackable Linux Security Module, available since 5.13, that any
unprivileged process can apply to *itself*. You build a ruleset, add rules
tying access rights to file hierarchies, then call `landlock_restrict_self`.
The restriction binds to the thread and all descendants, forever (only more
restrictions can be added, never removed). Three syscalls total:
`landlock_create_ruleset`, `landlock_add_rule`, `landlock_restrict_self`.

From `landlock(7)` (man-pages 6.18, the authoritative source), filesystem
access rights cover the full set of mutating ops:

- `LANDLOCK_ACCESS_FS_WRITE_FILE` - open a file with write access
- `LANDLOCK_ACCESS_FS_TRUNCATE` - truncate/ftruncate/creat/O_TRUNC
- `LANDLOCK_ACCESS_FS_REMOVE_FILE` - **unlink or rename a file**
- `LANDLOCK_ACCESS_FS_REMOVE_DIR` - **remove or rename a directory**
- `LANDLOCK_ACCESS_FS_MAKE_REG` - **create, rename, or link a regular file**
- `LANDLOCK_ACCESS_FS_MAKE_DIR` / `_MAKE_SYM` / `_MAKE_FIFO` / etc.
- `LANDLOCK_ACCESS_FS_REFER` (ABI v2+) - reparent (cross-directory link/rename)

Network (ABI v4+, kernel 6.7+): `LANDLOCK_ACCESS_NET_BIND_TCP`,
`LANDLOCK_ACCESS_NET_CONNECT_TCP`. IPC scope (ABI v6+, kernel 6.12+):
abstract Unix sockets, signals.

**Does the kernel catch `mv`? Yes.** `mv` is `rename(2)`, which Landlock
intercepts via `REMOVE_FILE`/`MAKE_REG`/`MAKE_DIR` on the respective source
and destination directories, plus `REFER` for cross-directory moves. Codex's
approach: read everywhere, write only to `/dev/null` and the writable roots.
The COW overlay (sandlock) is a nice-to-have for protecting the working dir
but not required for v1.

Known Landlock gaps: `chdir`, `stat`, `flock`, `chmod`, `chown`, `setxattr`,
`utime`, `fcntl`, `access` are NOT yet restrictable (per the man page
CAVEATS). For a coding agent this is mostly fine - the dangerous ops (write,
create, delete, rename) are all covered.

Pattern to implement (from the man page example): create ruleset handling all
fs rights, add read rules for `/usr` `/lib` `/etc`, add read+write rules for
workspace + `/tmp`, `prctl(PR_SET_NO_NEW_PRIVS)`, `landlock_restrict_self`,
then exec. For network denial, layer a seccomp-bpf filter blocking
`connect`/`bind`/`sendto` (allowing `AF_UNIX`).

### macOS: Seatbelt (sandbox-exec)

Seatbelt is Apple's TrustedBSD MAC framework, the same tech that sandboxes
Chrome renderers and App Store apps. `/usr/bin/sandbox-exec` ships with the
OS - zero install. You generate a Scheme-style `.sbpl` policy and run
`sandbox-exec -p '<policy>' <cmd>`.

Codex's `seatbelt_base_policy.sbpl` is derived from Chrome's renderer sandbox
(`; Essential permissions - based on Chrome sandbox policy` per the Claude
Code binary strings). Default-deny, then allow `file-read*` broadly,
`file-write*` only to the workspace subpath, `network-outbound` only to
localhost. The whole process tree inherits it.

Seatbelt catches the same operations Landlock does - it's a kernel MAC layer
hooking the VFS path, so rename/move/write/create are all intercepted at the
syscall level. No command whitelisting needed; the policy is path-based.

Network filtering on macOS is the weak spot. srt routes through a localhost
HTTP/SOCKS proxy with env vars; Claude Code Camp (Apr 2026) found
well-behaved clients obey `HTTPS_PROXY` but Go binaries (gh, likely docker
CLI) fail TLS verification against the proxy cert. For v1, simplest is
Seatbelt `network-outbound` deny to non-loopback (kernel blocks at the socket
layer) - strong but blunt.

### Windows: restricted token + ACLs

Weakest of the three - there is no single "intercept the write syscall" hook
equivalent to Landlock/Seatbelt. The Codex approach
(`codex-rs/windows-sandbox-rs/src/lib.rs`):

1. `CreateRestrictedToken` produces a token with reduced privileges and
   a deny-only SID list.
2. Compute allowed/denied paths from the writable roots; apply filesystem
   ACLs (deny writes outside workspace).
3. Network denial is largely env-based (proxy settings, PATH stubs) - not a
   kernel filter. This is the documented Windows limitation: strong on
   filesystem via ACLs, weak on network.

This is "good enough" not airtight. A restricted token + ACLs stops naive
file writes outside the workspace at the OS level (the ACL check happens in
the kernel's security reference monitor on `NtCreateFile`), but an
administrator-context process can still modify ACLs. For a coding agent
running as a normal user, the token restriction is the practical boundary.

## Policy model (borrow from Codex, not Claude Code)

Keep the policy layer to path rules only - no command parsing, no
excludedCommands. Codex's modes map cleanly to 3code's needs:

- `read-only`: Landlock read everywhere, no write anywhere, no network.
- `workspace-write` (default): read everywhere, write to cwd + tmp + configured
  writable_roots, `.git` read-only inside writable roots, no network by default.
- `danger-full-access`: no sandbox.

This is path-allowlist policy translated to OS rules at spawn time - the
opposite of command whitelisting. The OS enforces it on every syscall from
every descendant process, regardless of whether it's `mv`, `tee`, a build
script, or `rm -rf`.

## Open questions

1. **Single helper or per-OS modules?** sandlock is Linux-only with a C ABI.
   Codex has three separate implementations. For 3code (Nim), the cleanest is
   three small native modules: a Landlock+seccomp module (Nim can call the
   syscalls directly via `landlock_create_ruleset` etc.), a Seatbelt
   policy-generator, and a Windows token module. No external binary dependency
   on Linux/macOS; Windows is the awkward one.
2. **Network on v1?** Simplest correct answer is deny-by-default with a
   Seatbelt/bwrap backstop. Domain allowlisting (srt's proxy approach) is
   more policy complexity than v1 needs.
3. **Covering 3code's own write/patch tools.** The Claude Code lesson: built-in
   tools that run in-process bypass a shell-only sandbox. 3code's `write`/`patch`
   tools need their own path check (or route through the same policy) - the OS
   sandbox only covers spawned `bash` commands.

## Sources

- `landlock(7)` man page, man-pages 6.18 (2026-04-21) - authoritative on
  Landlock access rights, ABI versions, caveats.
  https://man7.org/linux/man-pages/man7/landlock.7.html
- Codex CLI sandbox implementation analysis (gist, 2026-01-17) - per-platform
  file map and mechanism.
  https://gist.github.com/rtzll/8ec03ad8a4cca3ae43ce3db7eb7dcc09
- OpenAI Codex sandbox docs (official, current) - policy modes, platform
  primitives overview.
  https://developers.openai.com/codex/concepts/sandboxing
- sandlock repo (multikernel/sandlock, Apache-2.0) - clean Linux-only
  Landlock+seccomp reference, Rust + C ABI.
  https://github.com/multikernel/sandlock
- Anthropic sandbox-runtime (anthropic-experimental/sandbox-runtime,
  Apache-2.0) - Seatbelt+bubblewrap, but the command-whitelisting model to
  avoid. https://github.com/anthropic-experimental/sandbox-runtime
- Claude Code Camp sandbox deep-dive (2026-04-09) - empirical findings on
  what srt actually catches; revealed the built-in-tool-bypasses-sandbox gap.
  https://www.claudecodecamp.com/p/claude-code-sandboxing-how-sandbox-works-and-what-it-doesn-t-protect
- wincent/agent-sandboxen.md gist (2026-05) - comprehensive catalog of the
  whole sandbox space, useful for orientation.
  https://gist.github.com/wincent/2752d8d97727577050c043e4ff9e386e
