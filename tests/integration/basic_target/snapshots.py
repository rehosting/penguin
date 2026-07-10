#!/usr/bin/env python3
"""Aggregate runner for the basic_target snapshot re-attach smokes.

Runs every ReattachSmoke (kprobe / devfs / sysctl / core_pattern) for one
(arch, kernel) against an image, reporting a pass/fail summary and exiting
non-zero if any fail. Intended for CI (one job per arch/kernel), alongside the
existing basic_target/test.py.

Each smoke does two full guest boots (save + restore), so this is minutes per
arch, not seconds — keep it to a representative arch/kernel in CI rather than
the full matrix.

Usage: python3 snapshots.py -i <image> [-a armel] [-k 4.10] [--only devfs,sysctl]
"""
import logging
import sys

import click

from _snapshot_harness import run_reattach_smoke
import snapshot_kprobe_test
import snapshot_devfs_test
import snapshot_sysctl_test
import snapshot_core_pattern_test

logger = logging.getLogger("penguin.snapsmoke")

SMOKES = {
    "kprobe": snapshot_kprobe_test.SPEC,
    "devfs": snapshot_devfs_test.SPEC,
    "sysctl": snapshot_sysctl_test.SPEC,
    "core_pattern": snapshot_core_pattern_test.SPEC,
}


@click.command()
@click.option("--image", "-i", required=True)
@click.option("--arch", "-a", default="armel")
@click.option("--kernel", "-k", default="4.10")
@click.option("--only", default=None,
              help="comma-separated subset of: " + ", ".join(SMOKES))
def main(image, arch, kernel, only):
    names = only.split(",") if only else list(SMOKES)
    results = {}
    for name in names:
        spec = SMOKES.get(name.strip())
        if spec is None:
            logger.error(f"unknown smoke {name!r}; known: {list(SMOKES)}")
            results[name] = False
            continue
        try:
            run_reattach_smoke(spec, image, arch, kernel)
            results[name] = True
        except Exception as e:
            logger.error(f"[{name}] FAILED: {e}")
            results[name] = False

    logger.info("=== snapshot smoke summary (%s/%s) ===", arch, kernel)
    for name, ok in results.items():
        logger.info("  %-14s %s", name, "PASS" if ok else "FAIL")
    if not all(results.values()):
        sys.exit(1)


if __name__ == "__main__":
    main()
