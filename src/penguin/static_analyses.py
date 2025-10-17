"""
penguin.static_analyses
=======================

Static analysis utilities for the Penguin emulation environment.

This module provides classes and helpers for analyzing extracted filesystems.
"""

# Remove FileSystemHelper from this file and import all static analysis classes for backward compatibility
from .static_analyses import (
    ArchId,
    InitFinder,
    KernelVersionFinder,
    EnvFinder,
    PseudofileFinder,
    InterfaceFinder,
    ClusterCollector,
    LibrarySymbols,
)
