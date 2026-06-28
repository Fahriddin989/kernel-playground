# M3 HTTP Packet Logger and Blacklist Kernel Module

## 1. Project Overview

This project implements an out-of-tree Linux kernel module for the M3 Software Defined Networking assignment. This means that the module is not part of the main Linux kernel source code. Instead, it is developed separately, compiled into a loadable `.ko` file, and inserted into the running kernel at runtime. This approach allows us to extend kernel behavior without modifying or rebuilding the full Linux kernel.

The implemented module is called `snf_lkm`. It uses the Linux Netfilter framework to inspect IPv4 TCP packets before they are delivered to the local system. When a TCP packet is addressed to destination port `80`, the module classifies it as HTTP traffic. If the source IP address is not blacklisted, the packet is accepted and a kernel log message is produced. If the source IP address exists in the runtime blacklist, the packet is dropped and the drop event is logged.

The blacklist is controlled at runtime through a `/proc` interface:

```text
/proc/snf_blacklist
```

This means the module does not need to be recompiled or reloaded every time the blacklist changes. A user can write an IP address into `/proc/snf_blacklist`, and the module will immediately use that address to decide whether HTTP traffic should be accepted or dropped.

The main implementation file is:

```text
kernel/modules/snf_lkm.c
```

The module was built inside the provided container-based development environment and tested inside a QEMU virtual machine. This is important because kernel modules run with high privileges inside the kernel. Testing the module inside a VM keeps the host system safe: if the module crashes the kernel, only the virtual machine is affected, not the host operating system.

## 2. Repository Information

The project repository is located on the Ubuntu host at `~/kernel-playground`. For building and testing, the repository is mounted inside the Podman development container at `/opt/kernel-playground`. Most build commands in this project are executed from inside the container using the `/opt/kernel-playground` path.

The main implementation file of this project is:

```text
kernel/modules/snf_lkm.c
```

Screenshots and evidence images, when needed, can be stored under:

```text
docs/images/
```

## 3. Testing and Development Environment

The project was developed and tested using the environment provided by `kernel-playground`. This environment is designed for Linux kernel development and allows kernel modules to be built and tested without loading experimental code directly on the host system.

The development workflow used two isolated layers:

1. A Podman container for building the kernel module.
2. A QEMU virtual machine for loading and testing the kernel module.

The module was built inside the container environment. This container includes the required build tools, kernel headers, compiler, and project files needed to compile the out-of-tree kernel module.

The actual module execution was done inside a QEMU VM. The compiled `.ko` kernel module was mounted to the VM and loaded inside the VM kernel using `insmod`. All runtime tests, including HTTP traffic detection and blacklist-based packet dropping, were performed inside this virtual machine.

This setup is important because Linux kernel modules run inside kernel space. A bug in kernel-space code can crash the running kernel. By testing inside a QEMU VM, the experiment is isolated from the host operating system. If the module causes a crash, only the VM is affected, while the host system and development container remain safe.

In this project, the QEMU VM used a virtual network configuration where HTTP traffic reached the VM through port forwarding. During testing, the observed VM-side network values were:

```text id="dlba6o"
VM IP address:        10.0.2.15
QEMU source address:  10.0.2.10
HTTP port:            80
```

The source IP address `10.0.2.10` was later added to the runtime blacklist to verify that the module could drop HTTP traffic from a selected source.


The final delivery is intended to be available from the `main` branch of the forked repository.
