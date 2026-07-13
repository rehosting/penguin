# Library injection (`lib_inject`)

Penguin can replace library functions in the guest at runtime by preloading a
small shared object (`/igloo/lib_inject_<abi>.so`, wired in via
`/etc/ld.so.preload`). This is how NVRAM shims work, and it is the mechanism
behind three user-facing config knobs, all under `lib_inject:`.

Because injection is a real `LD_PRELOAD`, it only affects **dynamically linked**
guest binaries; statically linked programs are unaffected.

## `lib_inject.aliases` — point a symbol at an existing shim

```yaml
lib_inject:
  aliases:
    nvram_load: nvram_init      # call nvram_load -> run the nvram_init shim
    fputs: "false"              # fputs always "fails"
```

Maps a symbol name to the name of a function already defined in the injected
library (the NVRAM shims, or the generic `libinject_ret_0` / `libinject_ret_1`
constant returns). Wired with the linker's `--defsym`.

## `lib_inject.extra` — inline custom C

```yaml
lib_inject:
  extra: |
    int my_check(void) { return 1; }
```

Raw C compiled straight into the injected library. Pair with `aliases` to route
a real symbol at your function.

## `lib_inject.d/` — hand-authored shim files

Any `.c`/`.h` file dropped in `<project>/lib_inject.d/` is compiled into the
injected library and the directory is added to the include path. This is the
file-based counterpart to `extra:` — better when you have more than a snippet.
Dotfiles and subdirectories are ignored, so `.generated/` (below) is never
double-compiled.

## `lib_inject.stubs` — declarative "just return a constant"

Forcing a function to "just return 0/1" is a constant rehosting move. `stubs:`
makes it declarative: it **compiles down to the machinery above** — one generated
C shim per stub, plus an `aliases` entry — rather than making you hand-write both.

```yaml
lib_inject:
  stubs:
    libX.so:                       # library key: a label + the glob target
      get_flag: { return: 0 }      # get_flag() -> 0
      set_mode: { return: 1, type: int }
      "nvram_*": { return: 0 }     # glob: every exported nvram_* symbol -> 0
    /lib/libc.so:                  # absolute guest path also accepted
      memcpy: { guard_null_args: [0, 1], return: 0 }
```

A stub takes one of two mutually exclusive forms.

**Symbol return** — replace a symbol globally (LD_PRELOAD), touching no binary on
disk:

- **`return`** — the constant to return. Also the value returned on the NULL path
  of a guarded stub (defaults to `0` if omitted).
- **`type`** — the C return type of the generated shim. Defaults to `long`
  (register width), which is right for most integer/pointer returns; override
  for e.g. `int` or `void *`.
- **`guard_null_args`** — zero-based argument positions to NULL-check. If any
  listed argument is NULL the shim returns `return`; otherwise it **calls through
  to the real function** (via `dlsym(RTLD_NEXT, ...)`).

**Assembly body** — overwrite the instructions at one specific location in one
specific binary:

- **`body`** — assembly assembled with keystone and written over the symbol's
  code. The stub key is `symbol` (patch at the symbol's start) or
  `symbol@offset` (`offset` is hex `0x..` or decimal, added to the symbol
  address). This form compiles down to a `static_files` `binary_patch` action —
  `binary_patch` stays the single owner of on-disk patching.
- **`mode`** — assembly mode passed to `binary_patch` (e.g. `arm`/`thumb`);
  defaults to the target arch's natural mode.
- **`expect`** — optional hex of the bytes expected at the patch site, checked
  before the overwrite.

```yaml
lib_inject:
  stubs:
    libvendor.so:
      hw_probe:        { body: "movs r0, #0\nbx lr", mode: thumb }  # return 0 in Thumb
      init_dsp@0x10:   { body: "nop" }                              # patch 16 bytes in
```

Unlike the symbol-return forms, an assembly-body stub edits exactly one binary
(the library key), not every importer of the symbol.

### Notes and limits

- **Library key.** It is an organizational label *and* the target for glob
  expansion. Aliasing itself is global (a stubbed symbol is replaced everywhere
  it is imported), matching how `lib_inject` works. An absolute path
  (`/lib/libc.so`) is matched exactly; a bare basename (`libX.so`) is searched
  for in the rootfs and must be unambiguous.
- **Globs** are expanded against the library's exported (`.dynsym`) symbols at
  build time. A glob that resolves to no library, an ambiguous basename, a
  stripped object, or zero matching symbols is a hard error — a silently-empty
  stub is worse than a loud failure.
- **`guard_null_args` call-through** preserves the first 8 integer/pointer
  register arguments only; floating-point, struct-by-value, and stack arguments
  are not carried through. It also imports `dlsym`, so use it only where a real
  dynamic linker is present (the normal LD_PRELOAD case).
- **Precedence.** A symbol may not appear in both `stubs` and `aliases`; doing so
  is a hard error, so there is exactly one owner per symbol.
- **Generated files.** The symbol-return shims are written to
  `<project>/lib_inject.d/.generated/` (regenerated on every build) so you can
  inspect the exact C that was compiled. They live under a dotfile subdir so the
  `lib_inject.d/` scanner ignores them.
- **Assembly bodies delegate to `binary_patch`.** The `body`/`symbol@offset`
  form does not invent a new patching mechanism — it resolves the symbol to a
  file offset (statically, from the rootfs) and emits a `static_files`
  `binary_patch`, which applies the edit at boot. Multiple body stubs on the same
  binary are coalesced into one action. Symbol resolution needs a non-stripped
  symbol table in the target object.
