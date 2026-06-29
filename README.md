# M3 HTTP Packet Logger and Blacklist Kernel Module

## 1. Project Overview

This project implements an out-of-tree Linux kernel module for the M3 Software Defined Networking assignment. This means that the module is not part of the main Linux kernel source code. Instead, it is developed separately, compiled into a loadable `.ko` file, and inserted into the running kernel at runtime. This approach allows us to extend kernel behavior without modifying or rebuilding the full Linux kernel.

The implemented module is called `snf_lkm`. It uses the Linux Netfilter framework to inspect IPv4 TCP packets before they are delivered to the local system. When a TCP packet is addressed to destination port `80`, the module classifies it as HTTP traffic. If the source IP address is not blacklisted, the packet is accepted and a kernel log message is produced. If the source IP address exists in the runtime blacklist, the packet is dropped and the drop event is logged.


This means the module does not need to be recompiled or reloaded every time the blacklist changes. A user can write an IP address into `/proc/snf_blacklist`, and the module will immediately use that address to decide whether HTTP traffic should be accepted or dropped.

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

The actual module execution was done inside a QEMU VM. The compiled `.ko` kernel module was loaded inside the VM kernel using `insmod`. All runtime tests, including HTTP traffic detection and blacklist-based packet dropping, were performed inside this virtual machine.

This setup is important because Linux kernel modules run inside kernel space. A bug in kernel-space code can crash the running kernel. By testing inside a QEMU VM, the experiment is isolated from the host operating system. If the module causes a crash, only the VM is affected, while the host system and development container remain safe.

For the network experiment, the QEMU VM used user-mode networking with port forwarding. The relevant VM startup file was:

```text id="duwqvo"
tests/vm/run.sh
```

The QEMU network option was configured as follows:

```bash id="1fqbez"
-netdev user,host=10.0.2.10,id=mynet0,hostfwd=tcp::10022-:22,hostfwd=tcp::10080-:80
```

This configuration created a virtual network between the container side and the QEMU VM.

The option `host=10.0.2.10` made forwarded connections appear inside the VM as coming from the QEMU-side address `10.0.2.10`. This is why the kernel module logs HTTP packets with source IP `10.0.2.10`.

The forwarding rules exposed selected VM ports outside the VM:

```text id="y0sitd"
hostfwd=tcp::10022-:22    forwards port 10022 to VM port 22
hostfwd=tcp::10080-:80    forwards port 10080 to VM port 80
```

The SSH forwarding rule was useful for accessing the VM. The HTTP forwarding rule was necessary for the experiment because it allowed HTTP requests sent to port `10080` from outside the VM to reach port `80` inside the VM.

Since the kernel module detects HTTP traffic by checking TCP destination port `80`, this forwarding rule made it possible to trigger and test the Netfilter hook.

During testing, the observed VM-side network values were:

```text id="lvms9j"
VM IP address:        10.0.2.15
QEMU source address:  10.0.2.10
HTTP port:            80
```

The source IP address `10.0.2.10` was later added to the runtime blacklist to verify that the module could drop HTTP traffic from a selected source.

## 4. Module Design

The main goal of the module is to inspect incoming IPv4 TCP traffic and apply a simple HTTP filtering rule. The module does this by registering a Netfilter hook inside the Linux networking stack.

The module has two main behaviors:

```text
1. If the source IP is not blacklisted:
   - accept the HTTP packet
   - write a kernel log message showing the source IP, destination IP, source port, and destination port

2. If the source IP is blacklisted:
   - drop the HTTP packet
   - write a kernel log message showing that the blacklisted HTTP source was dropped
```

The blacklist is controlled at runtime through:

```text
/proc/snf_blacklist
```

This `/proc` interface allows the blacklist to be changed without recompiling the module and without unloading/loading it again. A user can write an IP address into `/proc/snf_blacklist`, and the module will use that address immediately when checking HTTP packets.

## 5. Implementation Details

The main implementation is located in:

```text
kernel/modules/snf_lkm.c
```

The module is written in C and uses Linux kernel APIs. The code is organized into several parts:

```text
1. Header includes
2. Constants and configuration values
3. Global module state
4. Runtime blacklist helper functions
5. /proc interface for blacklist control
6. Netfilter callback for packet inspection
7. Per-network namespace hook registration
8. Module initialization and cleanup
9. Module metadata
```

The following subsections explain each part of the module.

### 5.1 Header Includes

The module starts by including Linux kernel header files:

```c
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/proc_fs.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/spinlock.h>
#include <net/netns/generic.h>
```

These headers are needed because the module uses several kernel features.

`<linux/init.h>` is used for module initialization and cleanup annotations such as `__init` and `__exit`.

`<linux/module.h>` provides the basic infrastructure for writing loadable kernel modules, including `module_init`, `module_exit`, and module metadata such as license, author, description, and version.

`<linux/kernel.h>` provides common kernel functions and macros, including kernel logging through `printk`.

`<linux/netfilter.h>` and `<linux/netfilter_ipv4.h>` provide the Netfilter API. Netfilter is the Linux kernel framework used to inspect, accept, or drop network packets.

`<linux/ip.h>` provides access to the IPv4 header structure, `struct iphdr`. The module uses this structure to read the source IP address, destination IP address, IP version, protocol, and IP header length.

`<linux/tcp.h>` provides access to the TCP header structure, `struct tcphdr`. The module uses this structure to read the source port, destination port, and TCP flags such as `SYN` and `ACK`.

`<linux/in.h>` provides IP protocol constants such as `IPPROTO_TCP`.

`<linux/proc_fs.h>` and `<linux/fs.h>` are used to create the `/proc/snf_blacklist` file and define read/write operations for it.

`<linux/uaccess.h>` is needed because data written to `/proc/snf_blacklist` comes from userspace. The module uses `copy_from_user` to safely copy this data into kernel memory.

`<linux/spinlock.h>` provides spinlocks. The module uses a spinlock to protect the shared blacklist data because the blacklist can be read or modified while packets are being inspected.

`<net/netns/generic.h>` is used for per-network namespace data. This allows the Netfilter hook to be registered correctly inside the network namespace used by the running kernel environment.

### 5.2 Constants and Configuration Values

The module defines several constants:

```c
#define HTTP_PORT 80
#define ALLOWED_NET  0x0a000200U
#define ALLOWED_MASK 0xffffff00U
#define PROC_NAME "snf_blacklist"
#define MAX_BLACKLIST_ENTRIES 16
#define WRITE_BUF_SIZE 256
```

`HTTP_PORT` is set to `80`. This is the destination TCP port used to identify HTTP traffic in this experiment.

`ALLOWED_NET` represents the network `10.0.2.0`.

`ALLOWED_MASK` represents the subnet mask `255.255.255.0`.

Together, `ALLOWED_NET` and `ALLOWED_MASK` are used only to classify accepted log messages as coming from the allowed QEMU network range or from outside that range. They do not decide whether traffic is blocked. Blocking is controlled only by the runtime blacklist.

`PROC_NAME` defines the name of the `/proc` file created by the module:

```text
/proc/snf_blacklist
```

`MAX_BLACKLIST_ENTRIES` limits the blacklist to 16 IP addresses. This keeps the module simple and avoids dynamic memory allocation for the blacklist.

`WRITE_BUF_SIZE` limits how much text can be written to the `/proc` file at one time. In this module, the write buffer is 256 bytes.

### 5.3 Global Module State

The module then defines global variables:

```c
static unsigned int lkm_net_id;
static __be32 blacklist[MAX_BLACKLIST_ENTRIES];
static unsigned int blacklist_count;
static DEFINE_SPINLOCK(blacklist_lock);
```

`lkm_net_id` is used by the kernel to identify the module’s per-network namespace data. The module registers a Netfilter hook for the network namespace, and this ID helps retrieve the correct data for that namespace.

`blacklist` is a fixed-size array that stores blacklisted IPv4 addresses. The type `__be32` means the IP address is stored as a 32-bit value in big-endian network byte order, which is the normal format used for IP addresses inside network packets.

`blacklist_count` stores how many valid IP addresses are currently saved in the blacklist array.

`blacklist_lock` is a spinlock used to protect the blacklist and `blacklist_count`. This is necessary because the blacklist can be accessed from two different contexts:

```text
1. The /proc write operation can modify the blacklist.
2. The Netfilter callback can read the blacklist while packets are being inspected.
```

Without a lock, the module could read the blacklist while it is being updated, which may lead to inconsistent behavior.

The module also defines a per-network namespace data structure:

```c
struct lkm_netns_data {
        struct nf_hook_ops nf_hops;
};
```

This structure stores the Netfilter hook operations for a network namespace. The field `nf_hops` contains the hook configuration that tells the kernel which callback function should inspect packets, at which Netfilter stage, and for which protocol family.
