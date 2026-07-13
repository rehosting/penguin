"""
Declarative symbol stubs -> generated C shims + ``lib_inject`` aliases.

A ``lib_inject.stubs`` config section stubs out library/object symbols. It has
two families, both of which compile down to existing machinery rather than
inventing a new one:

* **Symbol return** (``return``/``type``/``guard_null_args``) generates one tiny
  C function per stubbed symbol plus a linker ``--defsym`` alias, fed through the
  same clang build in ``pyplugins/interventions/nvram2.py``. This is a global,
  LD_PRELOAD-based replacement.
* **Assembly body** (``body`` at a ``symbol`` or ``symbol@offset`` key) resolves
  the symbol to a file offset (statically, from the rootfs) and emits a
  ``static_files`` ``binary_patch`` action -- delegating on-disk patching to its
  single owner (``pyplugins/core/live_image.py``).

This module is deliberately pure/host-side (no penguin runtime imports) so the
codegen can be unit-tested directly. The library-symbol resolver used for glob
expansion is injectable: :func:`make_fs_resolver` provides the production
default that reads a project rootfs tarball, and tests can pass a plain callable
returning a set of names.

Config shape (already validated by ``structure.Stubs``), as a plain dict::

    {
        "libX.so":     {"get_flag": {"return": 0}, "nvram_*": {"return": 0}},
        "/lib/libc.so": {"memcpy": {"guard_null_args": [0, 1], "return": 0}},
    }
"""

import fnmatch
import io
import re
import tarfile
from pathlib import Path, PurePosixPath

# Characters that make a symbol key a glob rather than a literal name.
_GLOB_CHARS = ("*", "?", "[")

# Max register-passed integer/pointer args we can thread through on the
# guard_null_args call-through path (indices 0-7).
_MAX_ARGS = 8

_ARG_LIST = ", ".join(f"long a{i}" for i in range(_MAX_ARGS))
_ARG_NAMES = ", ".join(f"a{i}" for i in range(_MAX_ARGS))
_FN_PTR_TYPE = "(*)(" + ", ".join("long" for _ in range(_MAX_ARGS)) + ")"


class StubError(Exception):
    """Raised for any invalid or unsatisfiable ``stubs`` configuration."""


def _is_glob(key):
    return any(c in key for c in _GLOB_CHARS)


def _c_ident(name):
    """Sanitize a symbol name for use inside a generated C identifier."""
    return re.sub(r"[^0-9A-Za-z_]", "_", name)


def _action_get(action, key, default=None):
    """Read a field from a stub action, accepting either a plain config dict
    (``return``/``type``/``guard_null_args``) or a validated ``StubAction``
    model (``return_``/...)."""
    if isinstance(action, dict):
        if key == "return":
            if "return" in action:
                return action["return"]
            return action.get("return_", default)
        return action.get(key, default)
    if key == "return":
        return getattr(action, "return_", default)
    return getattr(action, key, default)


# --------------------------------------------------------------------------- #
# symbol resolution (glob expansion)
# --------------------------------------------------------------------------- #
def _exported_symbols(stream):
    """Return the set of exported (defined, GLOBAL/WEAK FUNC/OBJECT) dynamic
    symbols in an ELF shared object read from ``stream``. Raises :class:`StubError`
    if the object has no dynamic symbol table (stripped / not a shared object)."""
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection

    elf = ELFFile(stream)
    dynsym = elf.get_section_by_name(".dynsym")
    if not isinstance(dynsym, SymbolTableSection):
        raise StubError("no .dynsym section (object is stripped or not dynamic)")
    names = set()
    for sym in dynsym.iter_symbols():
        if not sym.name or sym["st_shndx"] == "SHN_UNDEF":
            continue
        info = sym["st_info"]
        if info["bind"] not in ("STB_GLOBAL", "STB_WEAK"):
            continue
        if info["type"] not in ("STT_FUNC", "STT_OBJECT", "STT_GNU_IFUNC"):
            continue
        names.add(sym.name)
    if not names:
        raise StubError("no exported symbols (object is stripped)")
    return names


def _norm_guest_path(member_name):
    """Normalize a tar member name (``./usr/lib/x`` or ``usr/lib/x``) to an
    absolute guest path (``/usr/lib/x``)."""
    return "/" + str(PurePosixPath(member_name.lstrip("./"))).lstrip("/")


def _find_member(tf, library_key):
    """Locate one tar member for ``library_key`` and return ``(bytes, guest_path)``.
    An absolute key matches the exact guest path; a bare basename is searched for
    and must be unambiguous. Raises :class:`StubError` when missing or ambiguous."""
    want_abs = library_key.startswith("/")
    base = PurePosixPath(library_key).name
    matches = []
    for m in tf.getmembers():
        if not m.isfile():
            continue
        guest_path = _norm_guest_path(m.name)
        if want_abs:
            if guest_path == library_key:
                matches.append(m)
        elif PurePosixPath(guest_path).name == base:
            matches.append(m)
    if not matches:
        raise StubError(
            f"stubs: library {library_key!r} not found in rootfs"
        )
    if len(matches) > 1:
        paths = ", ".join(sorted(_norm_guest_path(m.name) for m in matches))
        raise StubError(
            f"stubs: {library_key!r} is ambiguous in rootfs ({paths}); "
            f"use an absolute guest path"
        )
    return tf.extractfile(matches[0]).read(), _norm_guest_path(matches[0].name)


def make_fs_resolver(fs_tar_path):
    """Return ``resolve(library_key) -> set[str]`` reading exported symbols out
    of a project rootfs tarball. Used for glob expansion. Raises :class:`StubError`
    when the library is missing, ambiguous, or stripped."""

    def resolve(library_key):
        with tarfile.open(fs_tar_path) as tf:
            data, _guest_path = _find_member(tf, library_key)
        try:
            return _exported_symbols(io.BytesIO(data))
        except StubError as e:
            raise StubError(f"stubs: {library_key}: {e}")

    return resolve


def _vaddr_to_file_offset(elf, vaddr):
    """Map a virtual address to a file offset using PT_LOAD program headers.
    Raises :class:`StubError` if no loadable segment contains ``vaddr``."""
    for seg in elf.iter_segments():
        if seg["p_type"] != "PT_LOAD":
            continue
        start = seg["p_vaddr"]
        end = start + seg["p_filesz"]
        if start <= vaddr < end:
            return seg["p_offset"] + (vaddr - start)
    raise StubError(f"vaddr {vaddr:#x} is not in any loadable segment")


def _symbol_file_offset(stream, symbol):
    """Return the file offset of ``symbol`` in an ELF read from ``stream``.
    Reads .symtab then .dynsym. Raises :class:`StubError` if not found."""
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection

    elf = ELFFile(stream)
    for sec_name in (".symtab", ".dynsym"):
        sec = elf.get_section_by_name(sec_name)
        if not isinstance(sec, SymbolTableSection):
            continue
        syms = sec.get_symbol_by_name(symbol)
        if syms:
            return _vaddr_to_file_offset(elf, syms[0]["st_value"])
    raise StubError(f"symbol {symbol!r} not found (no .symtab/.dynsym entry)")


def make_fs_offset_resolver(fs_tar_path):
    """Return ``resolve(library_key, symbol) -> (guest_path, file_offset)`` for
    the assembly-body form, reading the ELF out of a project rootfs tarball.
    Raises :class:`StubError` when the library or symbol can't be resolved."""

    def resolve(library_key, symbol):
        with tarfile.open(fs_tar_path) as tf:
            data, guest_path = _find_member(tf, library_key)
        try:
            off = _symbol_file_offset(io.BytesIO(data), symbol)
        except StubError as e:
            raise StubError(f"stubs: {library_key}: {e}")
        return guest_path, off

    return resolve


# --------------------------------------------------------------------------- #
# expansion + codegen
# --------------------------------------------------------------------------- #
def _is_body(action):
    return _action_get(action, "body") is not None


def _split(stubs):
    """Partition a ``stubs`` config into ``(shim_stubs, body_entries)``.

    ``shim_stubs`` keeps the ``{lib: {sym: action}}`` shape for the symbol-return
    family; ``body_entries`` is a flat ``[(lib, symkey, action)]`` list for the
    assembly-body family."""
    shim = {}
    body = []
    for libkey, syms in (stubs or {}).items():
        for symkey, action in (syms or {}).items():
            if _is_body(action):
                body.append((libkey, symkey, action))
            else:
                shim.setdefault(libkey, {})[symkey] = action
    return shim, body


def parse_symbol_key(symkey):
    """Split a body-stub key ``symbol`` or ``symbol@offset`` into
    ``(symbol, offset)``. ``offset`` accepts hex (``0x..``) or decimal and
    defaults to 0. Raises :class:`StubError` on a malformed key."""
    sym, sep, off = symkey.partition("@")
    if not sep:
        return symkey, 0
    if not sym or not off:
        raise StubError(f"stubs: malformed symbol@offset key {symkey!r}")
    try:
        return sym, int(off, 0)
    except ValueError:
        raise StubError(
            f"stubs: bad offset in key {symkey!r} (want hex 0x.. or decimal)"
        )


def expand(stubs, resolver=None):
    """Flatten the symbol-return family of a ``stubs`` config into a list of
    ``(symbol, action, library_key)`` tuples, expanding glob keys against the
    library's exported symbols via ``resolver``. Assembly-body stubs are ignored
    here (see :func:`generate_patches`). Deterministically ordered. Raises
    :class:`StubError` on a glob that matches nothing, a duplicated symbol, an
    ``@`` in a symbol-return key, or a glob with no resolver supplied."""
    shim, _body = _split(stubs)
    out = []
    seen = {}
    for libkey, syms in sorted(shim.items()):
        for symkey, action in sorted(syms.items()):
            if "@" in symkey:
                raise StubError(
                    f"stubs: 'symbol@offset' key {symkey!r} is only valid with "
                    f"a 'body' action"
                )
            if _is_glob(symkey):
                if resolver is None:
                    raise StubError(
                        f"stubs: glob {symkey!r} on {libkey!r} requires a symbol "
                        f"resolver but none is available"
                    )
                exported = resolver(libkey)
                matched = sorted(fnmatch.filter(exported, symkey))
                if not matched:
                    raise StubError(
                        f"stubs: glob {symkey!r} on {libkey!r} matched no "
                        f"exported symbols"
                    )
                resolved = [(s, action) for s in matched]
            else:
                resolved = [(symkey, action)]
            for sym, act in resolved:
                if sym in seen:
                    raise StubError(
                        f"stubs: symbol {sym!r} is stubbed more than once "
                        f"(via {seen[sym]!r} and {libkey!r}); define it once"
                    )
                seen[sym] = libkey
                out.append((sym, act, libkey))
    return out


def check_precedence(stubs, existing_aliases, resolver=None):
    """Raise :class:`StubError` if any stubbed symbol also appears in
    ``lib_inject.aliases`` (a symbol must be owned by exactly one of them)."""
    existing = set(existing_aliases or {})
    for sym, _action, libkey in expand(stubs, resolver):
        if sym in existing:
            raise StubError(
                f"stubs: symbol {sym!r} (from {libkey!r}) is also defined in "
                f"lib_inject.aliases; define it in only one place"
            )


def _shim_name(sym):
    return f"__igloo_stub_{_c_ident(sym)}"


def _gen_plain(sym, rtype, retval):
    shim = _shim_name(sym)
    return (
        f"/* generated stub: {sym} -> return {retval} */\n"
        f"{rtype} {shim}() {{ return ({rtype}){retval}; }}\n"
    )


def _gen_guard(sym, rtype, retval, guard_args):
    shim = _shim_name(sym)
    ident = _c_ident(sym)
    real = f"__igloo_real_{ident}"
    guard_expr = " || ".join(f"a{i} == 0" for i in guard_args)
    return (
        f"/* generated stub: {sym} -> return {retval} when "
        f"arg(s) {list(guard_args)} are NULL, else call through */\n"
        f"extern void *dlsym(void *handle, const char *symbol);\n"
        f"#ifndef RTLD_NEXT\n"
        f"#define RTLD_NEXT ((void *)-1L)\n"
        f"#endif\n"
        f"static {rtype} {_FN_PTR_TYPE.replace('(*)', '(*' + real + ')')};\n"
        f"{rtype} {shim}({_ARG_LIST}) {{\n"
        f"    if ({guard_expr})\n"
        f"        return ({rtype}){retval};\n"
        f"    if (!{real})\n"
        f"        {real} = ({rtype}{_FN_PTR_TYPE})dlsym(RTLD_NEXT, \"{sym}\");\n"
        f"    return {real}({_ARG_NAMES});\n"
        f"}}\n"
    )


def generate(stubs, resolver=None, existing_aliases=None):
    """Compile a ``stubs`` config into generated C shims and ``--defsym`` aliases.

    Returns ``(files, aliases)`` where ``files`` maps a filename ->
    C source (to write into the generated shim directory) and ``aliases`` maps a
    real symbol name -> generated shim function name. If ``existing_aliases`` is
    provided, the precedence rule (no symbol in both ``stubs`` and ``aliases``)
    is enforced.
    """
    pairs = expand(stubs, resolver)
    if existing_aliases is not None:
        existing = set(existing_aliases)
        for sym, _a, libkey in pairs:
            if sym in existing:
                raise StubError(
                    f"stubs: symbol {sym!r} (from {libkey!r}) is also defined in "
                    f"lib_inject.aliases; define it in only one place"
                )

    files = {}
    aliases = {}
    for sym, action, _libkey in pairs:
        rtype = (_action_get(action, "type") or "long").strip()
        retval = _action_get(action, "return")
        guard = _action_get(action, "guard_null_args") or []
        if retval is None:
            retval = 0  # guard-only stub: NULL path returns 0 by default
        if guard:
            src = _gen_guard(sym, rtype, int(retval), list(guard))
        else:
            src = _gen_plain(sym, rtype, int(retval))
        files[f"stub_{_c_ident(sym)}.c"] = src
        aliases[sym] = _shim_name(sym)
    return files, aliases


def generate_patches(stubs, offset_resolver):
    """Compile the assembly-body family of a ``stubs`` config into ``binary_patch``
    edits, grouped by target guest file.

    Returns ``dict[guest_path, list[entry]]`` where each entry is a
    ``BinaryPatchEntry`` dict (``file_offset`` + ``asm`` + optional ``mode`` /
    ``expect`` + provenance). ``offset_resolver(library_key, symbol)`` must return
    ``(guest_path, file_offset)``. Raises :class:`StubError` on a glob key, a
    malformed key, or an unresolved symbol."""
    _shim, body = _split(stubs)
    patches = {}
    for libkey, symkey, action in sorted(body, key=lambda t: (t[0], t[1])):
        if _is_glob(symkey):
            raise StubError(
                f"stubs: glob key {symkey!r} on {libkey!r} is not allowed with a "
                f"'body' action (patch one location at a time)"
            )
        sym, delta = parse_symbol_key(symkey)
        guest_path, base = offset_resolver(libkey, sym)
        entry = {
            "file_offset": base + delta,
            "asm": _action_get(action, "body"),
            "why": f"stubs: {libkey} {symkey}",
            "tag": "stubs",
        }
        mode = _action_get(action, "mode")
        if mode is not None:
            entry["mode"] = mode
        expect = _action_get(action, "expect")
        if expect is not None:
            entry["expect"] = expect
        patches.setdefault(guest_path, []).append(entry)
    return patches


def merge_patches_into_static_files(static_files, patches):
    """Merge ``generate_patches`` output into a config ``static_files`` dict.

    For each guest file, appends the edits to an existing ``binary_patch`` action
    (coalescing into its ``patches`` list) or creates a new one. Raises
    :class:`StubError` if the path already holds a non-``binary_patch`` action."""
    for guest_path, entries in patches.items():
        existing = static_files.get(guest_path)
        if existing is None:
            static_files[guest_path] = {"type": "binary_patch", "patches": list(entries)}
            continue
        if existing.get("type") != "binary_patch":
            raise StubError(
                f"stubs: cannot patch {guest_path!r}; a non-binary_patch "
                f"static_files action already targets it"
            )
        merged = existing.get("patches")
        if merged is None:
            # normalize a single-edit action into the patches-list form
            single = {k: v for k, v in existing.items() if k != "type"}
            merged = [single] if single else []
        merged = list(merged) + list(entries)
        static_files[guest_path] = {"type": "binary_patch", "patches": merged}


def write_files(gen_dir, files):
    """Write generated shim files into ``gen_dir``, replacing any previous
    contents so removed stubs don't linger. Returns the sorted list of written
    ``.c`` paths (as strings)."""
    import shutil

    gen_dir = Path(gen_dir)
    if gen_dir.exists():
        shutil.rmtree(gen_dir)
    gen_dir.mkdir(parents=True, exist_ok=True)
    paths = []
    for name, src in sorted(files.items()):
        p = gen_dir / name
        p.write_text(src)
        if p.suffix == ".c":
            paths.append(str(p))
    return sorted(paths)
