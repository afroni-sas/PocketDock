<div align="center">

<img src="docs/images/logo.svg" width="112" height="112" alt="PocketDock logo">

# PocketDock

</div>

A container engine for Android that needs no root. It pulls ordinary Docker/OCI
images from any registry and runs them on the phone, so an app written in any
language runs unchanged. It is a single static binary with no dependencies.

## Install

In Termux, or on Linux:

```bash
curl -fsSL https://raw.githubusercontent.com/afroni-sas/PocketDock/main/install.sh | sh
```

The script picks the binary for your CPU, checks its checksum and puts
`pdock` on your PATH. Binaries are also attached to each
[release](https://github.com/afroni-sas/PocketDock/releases), for 64-bit ARM
(`arm64-v8a`) and `x86_64` devices.

## Why not Docker?

Docker relies on kernel features that an unprivileged Android app cannot use:
user namespaces are usually compiled out, and `mount`, `chroot` and hard links
are forbidden by seccomp and SELinux. PocketDock gets the same result in user
space, by intercepting the system calls of the container's processes with
`ptrace`. A seccomp filter limits the stops to the calls that matter, so
`read`, `write` and `mmap` run at full speed.

## Build

Requires Zig `0.17.1`. No NDK or libc is needed.

```bash
zig build android        # zig-out/android/{arm64-v8a,x86_64}/pdock
zig build --release      # for the host
zig build test
```

## Use

```bash
pdock run -d --name web -p 8080:8000 python:3.12-alpine python -m http.server 8000
pdock ps
pdock logs -f web
pdock exec web sh -c 'python --version'
pdock stop web
pdock rm web
```

`pdock help` lists every command. `pdock doctor` reports what the
device's kernel allows. Data lives in `~/.pocketdock`, or `$POCKETDOCK_ROOT`.

## What a container gets

| | How |
|---|---|
| **Filesystem** | Its own root, copy-on-write over a read-only image. Symlinks and `..` are resolved inside the container. |
| **Volumes** | Host directories at any path, optionally read-only. |
| **Processes** | Its own PID numbers, with the app as PID 1. `ps` and `/proc` show only this container; signals cannot leave it. |
| **Root** | Processes see themselves as root (or the image's `USER`); `chown`, `setuid` and friends are emulated. |
| **Network** | A private IP and name; see below. |
| **Hostname, DNS** | Per container. |
| **Limits** | Memory, CPU and process count; see below. |
| **Lifecycle** | Restart policies, timestamped logs in the CRI format, `exec`, exit codes, `stats`. |

### Network

Containers reach each other by name (`db` or `db.internal`) on a private
`10.88.0.0/16` network. Loopback is private to each container. A port is only
visible from the LAN if it is published with `-p`, and a container cannot reach
the phone's own services.

| `--network` | Can reach |
|---|---|
| `bridge` (default) | Internet, LAN and other containers |
| `private` | Other containers only |
| `none` | Its own loopback only |

Each container port is backed by a free host port, so several containers can
use the same one, including ports below 1024. `pdock ps` shows the mapping.

### Limits

```bash
pdock run -m 512m --cpus 0.5 --cpuset-cpus 0-3 --pids-limit 200 IMAGE
```

Android gives apps no cgroups, so the tracer enforces these itself and reports
them through `/proc/meminfo`, `/proc/cpuinfo` and `sysinfo`, which lets runtimes
size their heaps and thread pools correctly.

- `--memory` is checked five times a second. Over the limit the largest process
  is killed, so a very fast allocation can briefly exceed it.
- `--cpus` stops and resumes the container's tasks, at a granularity of about
  100 ms.
- `--cpuset-cpus` and `--pids-limit` are exact.

## Limits of the engine

**This is not a security boundary.** Isolation is enforced by intercepting
system calls, for cooperative software. All containers run as the same Android
user and share the kernel, and ptrace-based sandboxes can be defeated by code
that sets out to do so. Run code you trust.

Also:

- All connections between containers appear to come from `127.0.0.1`.
- A listening socket bound to port 0 stays reachable from the LAN.
- Other UDP traffic to the private network through `sendmsg` is only handled
  with `--network private` or `none`.
- Guests resolve names through public DNS servers unless `POCKETDOCK_DNS` is set.
- 32-bit images, and images for another CPU architecture, are not supported.
- `pdock build` has no cache yet: every build runs all its steps.

## Building images

```bash
pdock build -t myapp --build-arg VERSION=1.2 .
pdock run myapp
```

Multi-stage builds, `RUN` (including `<<EOF` blocks), `COPY --from`, `ARG`,
`ENV`, `WORKDIR`, `USER`, `CMD`, `ENTRYPOINT`, `EXPOSE`, `LABEL`, `SHELL` and
`.dockerignore` are supported. `VOLUME`, `HEALTHCHECK`, `STOPSIGNAL` and
`ONBUILD` are accepted and ignored. `ADD` does not yet fetch URLs or unpack
archives; it fails with a message rather than doing something different.

A built image only stores what it changed. Its base is shared, so building
on the phone does not copy the image.

## How the filesystem works

The image is unpacked once and never modified. When a container first writes
into a directory, that directory is copied into the container's writable layer
as a complete listing whose untouched entries are zero-length stubs. From then
on the directory is an ordinary one: listing it needs no merging and deleting
needs no whiteouts. Directories nobody writes to cost nothing. A finished
writable layer can itself become a read-only layer of a new image, which is how
`pdock build` commits without copying. See [src/vfs.zig](src/vfs.zig).

## Layout

| File | Purpose |
|---|---|
| [src/tracer.zig](src/tracer.zig) | The ptrace loop and syscall emulation |
| [src/syscalls.zig](src/syscalls.zig) | Table of intercepted syscalls, also used to build the seccomp filter |
| [src/vfs.zig](src/vfs.zig) | Path resolution and copy-on-write |
| [src/registry.zig](src/registry.zig), [src/layer.zig](src/layer.zig) | OCI pull and layer extraction |
| [src/builder.zig](src/builder.zig), [src/dockerfile.zig](src/dockerfile.zig) | `pdock build` and Dockerfile parsing |
| [src/container.zig](src/container.zig) | Lifecycle, supervision, logs |
| [src/control.zig](src/control.zig) | The channel used by `exec` and `stats` |
| [src/quota.zig](src/quota.zig) | Resource accounting and limit parsing |
| [src/dns.zig](src/dns.zig) | DNS through Android's resolver daemon |

## License

Apache License 2.0. See [LICENSE](LICENSE).
