# gonet

A complete userspace implementation of the TCP/IP stack in Go using raw sockets and TUN devices. The goal is to build a networking stack from scratch without relying on high-level kernel networking abstractions.

## Architecture

The networking stack is divided into distinct layers following the OSI/TCP/IP models:
- **TUN / Raw Socket Layer**: Interacts with the Linux kernel via `/dev/net/tun` to read and write raw ethernet/IP frames.
- **IP Layer**: Handles IP packet parsing, checksum validation, assembly, and basic routing.
- **ICMP Layer**: Handles diagnostic network messages, such as ping (echo request/reply) and destination unreachable.
- **TCP Layer**: Implements the complex state machine, sliding windows, congestion control, and timers for reliable data transmission.
- **API (pkg/gonet)**: Exposes a `net.Conn`-compatible public API to easily integrate the custom stack with existing Go applications.

## Prerequisites

- Go 1.22+
- Linux Operating System
- Root privileges or `CAP_NET_ADMIN` capabilities to create and manage the TUN device.

## How to Run

1. Build the application:
   ```bash
   make build
   ```

2. Run the stack (requires root for TUN device):
   ```bash
   make run
   ```

3. Run tests:
   ```bash
   make test
   ```
