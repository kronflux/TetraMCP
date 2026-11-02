# Changelog

This file records changes to TetraMCP. Each section names the Ghidra release the
build targets and links to that release's own notes, because changes to Ghidra
itself are documented there and not here.

Sections use the categories of [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
There is no unreleased section: a release is published for every successful build
of `main`, so the topmost section is what the current release carries.

## Ghidra 12.2 - 2026-11-02

Built against [Ghidra 12.2](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.2_build),
which requires Java 25.

### Added

- A release for the Ghidra version that was built is published on every
  successful build, carrying the extension zip and its SHA-256 checksum. The
  `ghidra-<version>` tag moves to the commit that built it, so the tag, the
  release and its files name the same source.
- Release notes are taken from this file, so a release says what changed.

### Changed

- The build reads the JDK, the Gradle version and the Java compile level from
  the Ghidra release that is installed instead of pinning them.
  `application.java.compiler` names the compile level, which is 21 up to Ghidra
  12.1.2 and 25 for Ghidra 12.2, and `application.gradle.min` and
  `application.gradle.max` bound the Gradle version. A new Ghidra release that
  moves either one needs no edit here.
- Dependency versions resolve at build time to the newest final release rather
  than to a pinned version, with release candidates, milestones and nightlies
  rejected. Jackson stays on its 2.x line, because Jackson 3 ships its core and
  databind under a group this build excludes to keep one copy on the classpath.
- Text files are stored with Unix line ends. A checkout edited on Windows could
  otherwise restage every tracked file and publish a `gradlew` whose first line
  the Linux build agents cannot read.
- The documentation states the Ghidra release the source builds against, the JDK
  that release requires, and how to build for an older Ghidra.

### Fixed

- Cancellation and FunctionID calls follow the APIs Ghidra 12.2 declares:
  `TaskMonitor` no longer declares `checkCanceled`, and `FidService` takes a
  `FidProgramID` where it took a `Language`. Without this the extension does not
  compile against Ghidra 12.2.
- The unit tests run on Java 25. The pinned Mockito carried a Byte Buddy that
  refuses Java 25 class files, which failed every test that mocks a Ghidra type.

## Ghidra 12.1.2 - 2026-08-16

Built against [Ghidra 12.1.2](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.1.2_build),
which requires Java 21.

### Added

- Long analyses run as background jobs with their own lifecycle, results and
  expiry, on a pool separate from the one serving tool calls. A client drives a
  job by polling alone, or receives its progress on the session that started it.
  Whole-memory byte searches and cryptographic constant sweeps run this way.
- A cancelled job reports the work it had already applied, so a cancel is not
  mistaken for no change.
- Every tool declares whether it reads, writes, or writes idempotently, rather
  than having that inferred from its name.
- Tool calls report progress to the client that made them, and the monitor they
  run under is cancellable. Memory searches, decompilation and FunctionID
  queries observe it.
- An external module registered through `ServiceLoader` is held to the
  guarantees a built-in tool has: its tool names must not collide, its schemas
  must be ones the MCP server accepts, and a throw from it costs that module
  alone.
- A client reads a program's agent work queue, and its snapshot is taken under
  the queue's own lock.
- Reading a function's tags is separate from changing them.

### Changed

- Decompiler interfaces are pooled per program instead of constructed per call,
  and a write no longer destroys the decompiler.
- Writes to a program are serialised by a per-program lock rather than on the
  Swing thread, and the background write thread is named.
- Tool handlers run on a bounded pool TetraMCP owns, and in-flight handlers are
  drained before anything they borrow from is disposed.
- A program close is learned from Ghidra's own notification rather than from a
  plugin, so cached decompilations and native decompiler processes are released
  whether or not a second plugin was enabled.
- The MCP SDK moved to 2.0.0, which validates every tool schema at build time.
- The extension zip carries the runtime artifacts only, and `verifyPackaging`
  asserts that on every build. `lib/` is staged from what resolves now, so a
  stale jar cannot shadow its replacement or ship beside it.

### Fixed

- Programs are keyed by identity, so two binaries with the same file name no
  longer collide, `instances_use` resolves through the registry, an ambiguous
  name is refused rather than resolved by guess, and a closed program leaves no
  registry entry behind.
- The consumer that `project_open_file` takes is released, so a program it
  opened can close.
- A cancelled memory scan, decompile loop, cryptographic sweep or reference scan
  reports cancellation, and a scan that could not run is told apart from one
  that found nothing.
- An expired job id reports itself as expired even when nothing observed the job
  while it ran, jobs are listed against every program Ghidra has open, and the
  job executor a finished server releases is not held.
- A write whose transaction another writer discarded fails rather than appearing
  to succeed.
- `bookmarks_delete` deletes every bookmark of the named type at the address.
- An external tool's export and rule files are deleted before the call that made
  them returns.
- The packaging allow-list no longer strips the module jar and source zip that
  Ghidra's build relocates into `lib/`, which had shipped an extension with no
  application code.

## Ghidra 12.1 - 2026-03-21

Built against [Ghidra 12.1](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.1_build),
which requires Java 21.

### Added

- First public release: a Model Context Protocol server embedded in Ghidra,
  served over Streamable HTTP by Jetty from inside the Ghidra JVM, with no
  bridge process.
- Tools for decompilation, disassembly, symbols, memory, data types, structures,
  cross-references, comments, bookmarks, control flow and call graphs, p-code
  emulation, scripting, patching, cryptographic constant detection, Cython and
  CPython recovery, FunctionID identification, and external tools such as
  `binwalk` and YARA.
- Optional AI-assisted explanation, commenting and renaming through an
  Anthropic, OpenAI or OpenAI-compatible endpoint.
- Simultaneous analysis of several open programs with per-program state.
- Shared findings and a task queue for several agents working one program.
