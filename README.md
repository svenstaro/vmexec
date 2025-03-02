# vmexec - run a single command in a VM

[![CI](https://github.com/svenstaro/vmexec/workflows/CI/badge.svg)](https://github.com/svenstaro/vmexec/actions)
[![Crates.io](https://img.shields.io/crates/v/vmexec.svg)](https://crates.io/crates/vmexec)
[![license](http://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/svenstaro/vmexec/blob/master/LICENSE)
[![Stars](https://img.shields.io/github/stars/svenstaro/vmexec.svg)](https://github.com/svenstaro/vmexec/stargazers)
[![Lines of Code](https://tokei.rs/b1/github/svenstaro/vmexec)](https://github.com/svenstaro/vmexec)

**Run a single command in a virtual machine with zero-setup and great performance**

**vmexec** is a zero-setup CLI tool that runs single commands in a throwaway virtual machines.
The idea is for you to run a command a command in VM without having think about the performance implications, how to mount files, how to forward ports, etc.

Nowadays, many are used to the convenience of container runners such as `podman` or `docker` but so far it hasn't been as covenient to run a VM, often requiring a manual set up step.

It has a `docker run`-inspired interface that many should already be familiar with.

## Requirements

- virtiofsd
- QEMU

## TODO

- Document/bench KSM
- Better README
