# vmexec - run a single command in a VM

[![CI](https://github.com/svenstaro/vmexec/workflows/CI/badge.svg)](https://github.com/svenstaro/vmexec/actions)
[![Crates.io](https://img.shields.io/crates/v/vmexec.svg)](https://crates.io/crates/vmexec)
[![license](http://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/svenstaro/vmexec/blob/master/LICENSE)
[![Stars](https://img.shields.io/github/stars/svenstaro/vmexec.svg)](https://github.com/svenstaro/vmexec/stargazers)
[![Lines of Code](https://tokei.rs/b1/github/svenstaro/vmexec)](https://github.com/svenstaro/vmexec)

**Run a single command in a speedy virtual machine with zero-setup**

**vmexec** is a zero-setup CLI tool that runs single commands in a throwaway virtual machines.
The idea is for you to run a command a command in VM without having think about the performance implications, how to mount files, how to forward ports, etc.

Nowadays, many are used to the convenience of container runners such as `podman` or `docker` but so far it hasn't been as covenient to run a VM, often requiring a manual set up step.

## Features

- `docker run`-inspired interface that many should already be familiar with
- Environment variables (`-e/--env`)
- Volume mounting (`-v/--volume`)
- Port forwarding (`-p/--publish`)
- Automatic image pulling (`--pull`)
- Does the right things automatically for maximum performance (sane CPU, memory, and device settings such as virtio drivers, terminal input handling)
- Memory free page reporting so that the host can easily reclaim free memory from the guest (best coupled with `--pmem` to bypass the guest page cache entirely)
- Image warmup phase with after-first-boot snapshotting for quick VM boot times (usually less than 5s)
- Doesn't need libvirt, uses QEMU directly
- Uses [vsock](https://man7.org/linux/man-pages/man7/vsock.7.html) for efficient and secure local transport

## Requirements

- [QEMU system emulator](https://www.qemu.org/)
- [virtiofsd](https://gitlab.com/virtio-fs/virtiofsd)
- [libguestfs](https://libguestfs.org/)

## How to run

### Run a basic command

    vmexec run --os archlinux -- echo hello from inside VM

This will take a long time the first time because it will download the Arch
Linux image and then warm it up by booting it, waiting until the first-boot
processes have settled, then take a snapshot and shutoff the VM. Any subsequent
runs will use this snapshot which will result in quick follow-up commands.

### Run an interactive command

    vmexec run archlinux -- bash

### Set an environment variable

    vmexec run archlinux -e HELLO=yeshello -- bash -c '$HELLO'

### Bind a directory from the host

    vmexec run archlinux -v $PWD/hostdir:/mnt -- ls -lha /mnt

### Mount a virtio-pmem device

A virtio-pmem device will allow the OS inside the VM to bypass its page cache
and use the host's page cache directly.
This allows for more efficient RAM usage as and page cache used by the guest
will be unavailable to the host and can't be reclaimed.

    vmexec run archlinux --pmem /mnt:50 -- ls -lha /mnt

This command will create a temporary sparse file on the host.
During VM boot, it's automatically formatted and mounted.

### Forward a port from the VM to the host

    vmexec run archlinux -p 8080:80 -- nc -l -p 80

## Kernel Samepage Merging (KSM)

It is strongly encouraged to enable KSM in your kernel in order to allow for
multiple similar VMs to share their pages, thereby strongly cutting their
memory costs.

To temporarily enable KSM, you can do this as root:

    echo 1 > /sys/kernel/mm/ksm/run

However, you are advised to enable this permanently by running

    vmexec ksm --enable

as root.

When running a VM or two, you can check the shared memory stats via

    vmexec ksm

which will print a few pretty stats for you.

## Other projects

If you like this kind of stuff or if this doesn't exactly fit your needs, there are also these projects:

- [quickemu](https://github.com/quickemu-project/quickemu)
- [katacontainers](https://katacontainers.io/)
- [VmChamp](https://github.com/wubbl0rz/VmChamp)
- [lima](https://github.com/lima-vm/lima)

## Releasing

This is mostly a note for me on how to release this thing:

- Make sure `CHANGELOG.md` is up to date.
- `cargo release <version>`
- `cargo release --execute <version>`
- Releases will automatically be deployed by GitHub Actions.
- Update Arch package.
