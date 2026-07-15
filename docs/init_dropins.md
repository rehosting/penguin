# Init drop-ins: `init.d/` and `source.d/`

Penguin runs a stack of small scripts during guest boot. You can add your own by
dropping files into two folders at the top level of your project directory — no
config authoring, no build step for scripts:

```
projects/myfw/
  init.d/       # each executable file is run at boot
  source.d/     # each file is sourced into the boot shell before init.d runs
```

Both folders are discovered automatically at config-load time and installed into
the guest under `/igloo/init.d/` and `/igloo/source.d/`. The listing is **flat**
(top level only) and processed in **sorted filename order**.

## `init.d/` — scripts run at boot

The boot runner (`/igloo/init.sh`) execs every **executable** file in
`/igloo/init.d/*`, in sorted order, before handing off to the firmware's real
init. A drop-in therefore needs two things to run:

1. **It is executable.** Drop-ins are installed `0755` for you.
2. **It has a shebang pointing at an interpreter that exists in the guest.**
   The runner execs the file directly, so the kernel resolves the `#!` line
   itself. A minimal firmware root filesystem often has no `/bin/sh` or
   `/usr/bin/python`, so Penguin normalizes drop-in shebangs to the interpreters
   it ships:

   | Drop-in                                   | In-guest interpreter   |
   |-------------------------------------------|------------------------|
   | `*.sh`                                    | `/igloo/utils/sh` (busybox) |
   | extension-less with a shell shebang       | `/igloo/utils/sh`      |
   | `*.py`                                    | `/igloo/utils/python3` *(requires in-guest Python)* |

   > **Python note:** `.py` drop-ins require the in-guest Python interpreter to
   > be staged for the target architecture. When it is, `.py` drop-ins get their
   > shebang resolved to `/igloo/utils/python3` and the [`penguest`](penguest.md)
   > guest module on their path; when no interpreter is available for the target, the build
   > fails with a clear message rather than installing a script that dies at
   > boot. The shell half (`.sh`) has no such dependency and works everywhere.

Shebang handling for `init.d/` scripts:

- **Missing shebang** → the correct `#!` line is prepended (with a warning).
- **Foreign shebang** (e.g. `#!/bin/sh`, `#!/usr/bin/env python3`) → rewritten to
  the in-guest interpreter (with a warning).
- **Already correct** (`#!/igloo/utils/sh`) → installed verbatim, untouched.

Your source file on the host is never modified; normalization happens on the
copy installed into the guest image.

Files that are **not** recognized as scripts are installed verbatim, exactly as
before:

- `*.c` → compiled with the drop-in musl toolchain and installed as a native
  binary (see [`dropin_compile.py`](../src/penguin/dropin_compile.py)). This is
  the "compileables" path.
- `*.h` → skipped (headers for the `.c` compileables).
- prebuilt binaries, `*.conf`, `*.txt`, etc. → copied unchanged. (A prebuilt
  binary you drop in extension-less still runs, since the kernel execs ELF
  directly — Penguin does not touch it.)

### Ordering

`init.d/` runs in **sorted filename order**. To force a script to run last, name
it so it sorts after the rest — the `zz_` prefix convention is used internally
(e.g. `core.startup_script` installs as `/igloo/init.d/zz_startup_script`).

## `source.d/` — shell fragments sourced before init

Every file in `source.d/*` is **sourced** into the boot shell (not executed)
before any `init.d/` script runs, so it is shell-only and needs no shebang. Use
it for environment setup that later `init.d/` scripts rely on.

## Relation to `core.startup_script`

`core.startup_script` is the single-inline-shell-body case: its body is installed
as `/igloo/init.d/zz_startup_script` with `#!/igloo/utils/sh` prepended. The
`init.d/` folder is the many-files-in-a-folder case; both coexist.

## Example

```sh
# projects/myfw/init.d/10_net.sh
ip link set eth0 up
udhcpc -i eth0
```

No shebang needed — Penguin prepends `#!/igloo/utils/sh`. Drop the file in, run
the project, and it executes at boot.
