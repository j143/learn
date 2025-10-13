# eBPF Introduction

This folder contains example bpftrace scripts to demonstrate various eBPF concepts and use cases.

## What is eBPF?

eBPF (extended Berkeley Packet Filter) is a revolutionary technology that allows running sandboxed programs in the Linux kernel without changing kernel source code or loading kernel modules. It provides a safe and efficient way to extend kernel capabilities.

## Scripts Overview

### 1. syscalls.bt - Basic System Call Tracing

**Concept Tested**: Simple system call tracing

This script demonstrates how to trace all system calls made by processes. It shows:
- How to attach to kernel hooks for system call entry points
- Basic event counting and output formatting
- Real-time monitoring of system activity

**Usage**: `sudo bpftrace syscalls.bt`

### 2. process_fork.bt - Fork Tracepoint Example

**Concept Tested**: Tracepoint usage

This script uses kernel tracepoints to monitor process creation (fork events). It demonstrates:
- How to use predefined kernel tracepoints
- Accessing tracepoint arguments
- Monitoring process lifecycle events

**Usage**: `sudo bpftrace process_fork.bt`

### 3. openat_count.bt - Map Usage Example

**Concept Tested**: eBPF maps for data aggregation

This script counts how many times each process calls the `openat` system call using eBPF maps. It demonstrates:
- Using kprobes to hook into kernel functions
- Storing and aggregating data in eBPF maps
- Statistical analysis of kernel events

**Usage**: `sudo bpftrace openat_count.bt`

## Key Concepts Covered

### Kernel Hooks
- **kprobe**: Dynamic tracing of kernel functions
- **tracepoint**: Static instrumentation points in the kernel
- **syscall tracing**: Monitoring system call interfaces

### eBPF Maps
- Hash maps for storing key-value pairs
- Aggregating data across multiple events
- Efficient in-kernel data structures

### Use Cases
- Performance analysis and profiling
- Security monitoring and auditing
- Debugging and troubleshooting
- Network packet filtering and analysis

## Prerequisites

- Linux kernel 4.9+ (5.x+ recommended for full feature support)
- bpftrace installed (`apt install bpftrace` on Ubuntu/Debian)
- Root/sudo privileges to run eBPF programs

## References

- [eBPF Official Documentation](https://ebpf.io/)
- [bpftrace Reference Guide](https://github.com/iovisor/bpftrace/blob/master/docs/reference_guide.md)
- [Linux Tracepoints](https://www.kernel.org/doc/html/latest/trace/tracepoints.html)
