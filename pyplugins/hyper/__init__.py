"""
# `hyper` Plugin Package

The `hyper` package provides a collection of plugins for the Penguin hypervisor environment. These plugins enable advanced monitoring, instrumentation, and communication between the guest system and the hypervisor, supporting a variety of use cases such as coverage analysis, environment variable tracking, command logging, and inter-plugin messaging.

## Overview

- **Purpose:**  
  The `hyper` package is designed to extend the capabilities of the Penguin hypervisor by offering modular plugins that respond to guest hypercalls, manage shared memory regions, and facilitate plugin-to-plugin communication.

- **Key Features:**  
  - Logging and auditing of shell and Bash command execution.
  - Tracking and manipulation of U-Boot environment variables.
  - Canary value monitoring for integrity checks.
  - Portal mechanism for efficient command and data transfer between plugins and the hypervisor.
  - Utilities for handling hypercall constants and plugin configuration.

- **Typical Usage:**  
  Plugins in this package are loaded by the Penguin framework and operate transparently, responding to specific events or hypercalls from the guest. Output is typically written to files in a specified output directory for later analysis.

## Included Plugins

- `bash_command`: Logs Bash command executions.
- `canary`: Monitors canary values for security/integrity.
- `consts`: Provides access to hypercall and portal constants.
- `portal`: Implements the portal communication mechanism.
- `shell`: Tracks shell script coverage and environment usage.
- `uboot`: Simulates U-Boot environment variable management.

See individual plugin modules for detailed documentation and usage examples.
"""