import glob
import hashlib
import os
import subprocess
from pathlib import Path
from typing import Any, Dict

import penguin
from penguin.abi_info import ARCH_ABI_INFO
from penguin.defaults import static_dir as STATIC_DIR


logger = penguin.getColoredLogger("dropin_compile")


DYLIB_DIRS = {
    "aarch64": "arm64",
    "intel64": "x86_64",
    "loongarch64": "loongarch",
    "powerpc": "ppc",
    "powerpc64": "ppc64",
    "powerpc64le": "ppc64el",
}


def _default_abi_info(arch: str) -> Dict[str, Any]:
    arch_info = ARCH_ABI_INFO[arch]
    abi = arch_info["default_abi"]
    abi_info = arch_info["abis"][abi]
    return {
        "abi": abi,
        "target_triple": abi_info.get("target_triple") or arch_info["target_triple"],
        "m_flags": abi_info["m_flags"],
    }


def _dylib_dir(arch: str) -> str:
    return DYLIB_DIRS.get(arch, arch)


def _loader_name(arch: str) -> str:
    dylib_dir = _dylib_dir(arch)
    matches = glob.glob(os.path.join(STATIC_DIR, "dylibs", dylib_dir, "ld-musl-*.so.1"))
    if not matches:
        raise FileNotFoundError(
            f"no musl loader found for {arch} in {os.path.join(STATIC_DIR, 'dylibs', dylib_dir)}"
        )
    return os.path.basename(matches[0])


def _source_signature(init_dir: Path) -> str:
    digest = hashlib.sha256()
    paths = [
        path
        for pattern in ("*.c", "*.h")
        for path in init_dir.glob(pattern)
        if path.is_file()
    ]
    for path in sorted(paths):
        digest.update(path.name.encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def compile_init_c_dropin(proj_dir: str, init_dir: str, source_path: str, config: Dict[str, Any]) -> str:
    """Compile an init.d/*.c drop-in and return its project-local binary path."""
    arch = config["core"]["arch"]
    if arch not in ARCH_ABI_INFO:
        raise ValueError(f"cannot compile C drop-in {source_path}: unsupported architecture {arch}")

    sysroot = Path(STATIC_DIR) / "sysroots" / arch
    if not sysroot.is_dir():
        raise FileNotFoundError(
            f"cannot compile C drop-in {source_path}: missing {sysroot}. "
            "Rebuild the penguin container with drop-in sysroot support."
        )

    init_path = Path(init_dir)
    source = Path(source_path)
    output_dir = Path(proj_dir) / ".dropin_build" / arch
    output_dir.mkdir(parents=True, exist_ok=True)
    output = output_dir / source.stem
    stamp = output.with_name(output.name + ".sha256")
    source_signature = _source_signature(init_path)

    if output.exists() and stamp.exists() and stamp.read_text() == source_signature:
        return str(output)

    abi_info = _default_abi_info(arch)
    loader = _loader_name(arch)
    lib_dir = sysroot / "lib"
    startup = [lib_dir / name for name in ("Scrt1.o", "crti.o", "crtbeginS.o")]
    finish = [lib_dir / name for name in ("crtendS.o", "crtn.o")]
    missing = [str(path) for path in startup + finish if not path.exists()]
    if missing:
        raise FileNotFoundError(
            f"cannot compile C drop-in {source_path}: missing startup files: {', '.join(missing)}"
        )

    cmd = [
        "clang-20",
        "--target=" + abi_info["target_triple"],
        "--sysroot=" + str(sysroot),
        "-fuse-ld=lld",
        "-Oz",
        "-nostdlib",
        "-pie",
        "-I",
        str(init_path),
        "-Wl,--dynamic-linker,/igloo/dylibs/" + loader,
        "-Wl,-rpath,/igloo/dylibs",
        "-Wl,--strip-all",
    ]
    cmd += [
        f"-m{key.replace('_', '-')}={value}"
        for key, value in abi_info["m_flags"].items()
    ]
    cmd += [str(path) for path in startup]
    tmp_output = output.with_name(output.name + ".tmp")
    cmd += [str(source), "-L" + str(lib_dir), "-lc", "-lgcc_s"]
    cmd += [str(path) for path in finish]
    cmd += ["-o", str(tmp_output)]

    logger.info(f"Compiling C drop-in {source_path} for {arch}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        if result.stdout:
            logger.error(result.stdout)
        if result.stderr:
            logger.error(result.stderr)
        raise RuntimeError(f"failed to compile C drop-in {source_path}")

    tmp_output.chmod(0o755)
    os.replace(tmp_output, output)
    stamp.write_text(source_signature)
    return str(output)
