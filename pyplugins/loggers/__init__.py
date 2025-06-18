"""
# Loggers

This package contains plugins for logging various system and process events in the framework.

## Overview

The loggers in this module provide persistent recording of system calls, process executions, file I/O, and other runtime events from the guest system. Each logger is implemented as a plugin and is responsible for capturing specific types of events and storing them in the database for later analysis.

### Included Loggers

- **Syscalls Logger**: Records all system call events, including arguments, return values, and error codes.
- **Read/Write Logger**: Captures file descriptor read and write operations, including buffer contents.
- **Exec Logger**: Logs process execution (exec) events, including argument vectors and environment.
- **DB Logger**: Provides a database-backed event buffer and writer for persistent storage.

These loggers enable comprehensive tracing and auditing of guest activity, supporting security analysis, debugging, and research.

## Usage

Loggers are loaded automatically as part of the plugin system. See individual logger modules for details.
"""
