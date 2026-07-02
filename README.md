# M3 — HTTP Packet Logger Kernel Module

## Table of Contents

* [1. Project Overview](#1-project-overview)
* [2. Testing and Safety Environment](#2-testing-and-safety-environment)
* [3. Kernel Module Design](#3-kernel-module-design)
* [4. Implementation Explanation](#4-implementation-explanation)

  * [4.1 Header Files](#41-header-files)
  * [4.2 HTTP Port Constant](#42-http-port-constant)
  * [4.3 Network Namespace Data](#43-network-namespace-data)
  * [4.4 Netfilter Callback Function](#44-netfilter-callback-function)
  * [4.5 Checking That the Packet Exists](#45-checking-that-the-packet-exists)
  * [4.6 Checking the IPv4 Header](#46-checking-the-ipv4-header)
  * [4.7 Checking the TCP Protocol](#47-checking-the-tcp-protocol)
  * [4.8 Handling IPv4 Header Length](#48-handling-ipv4-header-length)
  * [4.9 Reading the TCP Header](#49-reading-the-tcp-header)
  * [4.10 Detecting HTTP Traffic](#410-detecting-http-traffic)
  * [4.11 Logging Packet Information](#411-logging-packet-information)
  * [4.12 Accepting Packets](#412-accepting-packets)
  * [4.13 Netfilter Hook Configuration](#413-netfilter-hook-configuration)
  * [4.14 Registering the Hook](#414-registering-the-hook)
  * [4.15 Unregistering the Hook](#415-unregistering-the-hook)
  * [4.16 Module Load Function](#416-module-load-function)
  * [4.17 Module Exit Function](#417-module-exit-function)
  * [4.18 Module Metadata](#418-module-metadata)
* [5. Build Steps](#5-build-steps)
* [6. Run and Test Steps](#6-run-and-test-steps)

  * [6.1 Start the QEMU VM](#61-start-the-qemu-vm)
  * [6.2 Load the Kernel Module Inside the VM](#62-load-the-kernel-module-inside-the-vm)
  * [6.3 Start an HTTP Server Inside the VM](#63-start-an-http-server-inside-the-vm)
  * [6.4 Send HTTP Traffic From Outside the VM](#64-send-http-traffic-from-outside-the-vm)
  * [6.5 Check the Kernel Log Inside the VM](#65-check-the-kernel-log-inside-the-vm)
  * [6.6 Remove the Module](#66-remove-the-module)
* [7. Results and Evidence](#7-results-and-evidence)
* [8. Development Notes](#8-development-notes)
* [9. Final Repository State](#9-final-repository-state)

## 1. Project Overview

This project implements **M3 — HTTP Packet Logger**, a Linux kernel module developed inside the `kernel-playground` repository.

The goal of this module is to inspect network traffic at kernel level and detect HTTP packets. HTTP traffic normally uses TCP destination port `80`, so the module checks IPv4 TCP packets and identifies packets whose destination port is `80`.

When an HTTP packet is detected, the module writes information about the packet to the Linux kernel log. The logged information includes:

* source IP address
* destination IP address
* source TCP port
* destination TCP port

The module is named `snf_lkm` and is implemented as an **out-of-tree kernel module**. This means it is built separately from the main Linux kernel source tree and then loaded into the running kernel as a `.ko` module.

The module uses the Linux **Netfilter** framework to receive packets while they pass through the kernel networking stack. It does not modify or block traffic. Every packet is accepted using `NF_ACCEPT`.

## 2. Testing and Safety Environment

This project is developed and tested using an isolated environment because Linux kernel modules run inside the kernel. If a kernel module contains a serious bug, it can crash the running system. For this reason, the module is not loaded directly on the host machine.

The repository is stored on the Ubuntu host machine at:

```text
~/kernel-playground
```

For building the module, the repository is mounted inside a Podman container at:

```text
/opt/kernel-playground
```

The Podman container provides the required build tools and keeps the build environment separate from the host system.

The compiled kernel module is tested inside a QEMU virtual machine. The module is loaded inside the QEMU VM, not directly on the host. This provides an extra safety layer: if the module causes a kernel crash, the crash affects only the virtual machine and not the host operating system.

The testing setup can be summarized as follows:

```text
Ubuntu host
   |
   |-- Podman container
   |      |
   |      |-- builds the kernel module
   |
   |-- QEMU virtual machine
          |
          |-- loads and tests the kernel module
```

HTTP traffic is sent to the VM using QEMU port forwarding. In this setup, host/container port `10080` forwards traffic to port `80` inside the QEMU VM.

This means that the following command, executed from outside the VM (inside the podman container):

```bash
curl http://127.0.0.1:10080
```
reaches the HTTP server running on port `80` inside the VM.

Inside the VM, the kernel log can be checked with:

```bash
dmesg | tail -n 20
```

This environment allows the module to be built, loaded, tested, and debugged safely without risking the stability of the main host system.

## 3. Kernel Module Design

The module is designed as a simple HTTP packet logger. Its purpose is to observe IPv4 TCP traffic inside the Linux kernel and log information when an HTTP packet is detected.

The module does not work as a normal user-space program. Instead, it runs inside the Linux kernel as a loadable kernel module. After it is compiled, it produces a `.ko` file that can be inserted into the kernel using `insmod`.

The module uses the Linux **Netfilter** framework. Netfilter allows kernel code to inspect network packets while they pass through the Linux networking stack.

In this project, the module registers a Netfilter hook. A hook is a function that the kernel calls automatically when a packet reaches a specific point in the networking path.

The packet inspection logic is simple:

1. The module receives a network packet from Netfilter.
2. It checks whether the packet is valid.
3. It reads the IPv4 header.
4. It checks whether the packet uses the TCP protocol.
5. It reads the TCP header.
6. It checks whether the TCP destination port is `80`.
7. If the destination port is `80`, the module logs the packet information to the kernel log.
8. The packet is accepted using `NF_ACCEPT`.

The module logs the following information:

```text
source IP address
destination IP address
source TCP port
destination TCP port
```

The module does not block, modify, or redirect packets. Its only task is to detect HTTP packets and print useful information about them.

The final packet decision is always:

```c
return NF_ACCEPT;
```

This means every packet continues normally through the network stack.

## 4. Implementation Explanation

The main implementation file for this project is:

```text
kernel/modules/snf_lkm.c
```

This file contains the full Linux kernel module. The module is responsible for registering a Netfilter hook, inspecting IPv4 TCP packets, detecting HTTP packets on destination port `80`, and logging packet information to the kernel log.

### 4.1 Header Files

At the beginning of the file, the module includes several Linux kernel headers:

```c
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <net/netns/generic.h>
```

These headers provide the kernel functions, structures, and constants needed by the module.

The most important headers are:

* `linux/module.h`: needed for creating a loadable kernel module.
* `linux/kernel.h`: provides kernel logging functions such as `printk`.
* `linux/netfilter.h`: provides the Netfilter framework.
* `linux/netfilter_ipv4.h`: provides IPv4 Netfilter hook points.
* `linux/ip.h`: provides the IPv4 header structure `struct iphdr`.
* `linux/tcp.h`: provides the TCP header structure `struct tcphdr`.
* `linux/in.h`: provides IP protocol constants such as `IPPROTO_TCP`.
* `net/netns/generic.h`: allows the module to store data per network namespace.

### 4.2 HTTP Port Constant

The module defines one main constant:

```c
#define HTTP_PORT 80
```

HTTP traffic normally uses TCP destination port `80`. The module uses this value to decide whether a TCP packet should be considered an HTTP packet.

Instead of writing the number `80` directly in the code many times, the module uses the name `HTTP_PORT`. This makes the code easier to read and easier to modify later.

### 4.3 Network Namespace Data

The module contains this global variable:

```c
static unsigned int lkm_net_id;
```

This ID is used by the kernel to identify the module's private data inside each network namespace.

The module also defines this structure:

```c
struct lkm_netns_data {
        struct nf_hook_ops nf_hops;
};
```

This structure stores the Netfilter hook operations for one network namespace.

A network namespace is an isolated networking environment inside Linux. The original `kernel-playground` style uses per-network-namespace data, so this module keeps the same design. This makes the module cleaner and more compatible with the structure of the repository.

### 4.4 Netfilter Callback Function

The most important function in the module is:

```c
static unsigned int nf_callback(void *priv, struct sk_buff *skb,
                                const struct nf_hook_state *state)
```

This function is called automatically by Netfilter whenever an IPv4 packet reaches the selected hook point.

The packet is passed to the function inside a structure called `sk_buff`, usually written as `skb`. In the Linux kernel, `sk_buff` is the main structure used to represent a network packet.

The goal of this function is:

1. check that the packet exists
2. check that the packet contains an IPv4 header
3. check that the packet is IPv4
4. check that the packet uses TCP
5. read the TCP header
6. check whether the TCP destination port is `80`
7. log the packet information if it is HTTP traffic
8. accept the packet

### 4.5 Checking That the Packet Exists

The function first checks whether `skb` is valid:

```c
if (!skb)
        return NF_ACCEPT;
```

If `skb` is empty, the module cannot inspect the packet. In this case, it simply accepts the packet and stops processing.

This is a defensive safety check. The module should not try to read packet data if the packet pointer is invalid.

### 4.6 Checking the IPv4 Header

Before reading the IPv4 header, the module checks that the packet contains enough data:

```c
if (!pskb_may_pull(skb, sizeof(struct iphdr)))
        return NF_ACCEPT;
```

The function `pskb_may_pull()` makes sure that the required amount of packet data is available before the module reads it.

After that, the module reads the IPv4 header:

```c
iph = ip_hdr(skb);
```

The IPv4 header contains important information such as:

* IP version
* source IP address
* destination IP address
* transport protocol

The module then checks that the packet is really IPv4:

```c
if (iph->version != 4)
        return NF_ACCEPT;
```

If the packet is not IPv4, the module does not process it further.

### 4.7 Checking the TCP Protocol

HTTP normally runs over TCP, so the module checks the protocol field inside the IPv4 header:

```c
if (iph->protocol != IPPROTO_TCP)
        return NF_ACCEPT;
```

If the packet is not TCP, it cannot be normal HTTP traffic on port `80`, so the module accepts it without logging.

### 4.8 Handling IPv4 Header Length

IPv4 headers can have variable length. Because of this, the module calculates the real IPv4 header length:

```c
ip_hdr_len = iph->ihl * 4;
```

The field `ihl` stores the IPv4 header length in 32-bit words. One 32-bit word is 4 bytes, so the value is multiplied by 4.

The module then checks that the calculated header length is valid:

```c
if (ip_hdr_len < sizeof(struct iphdr))
        return NF_ACCEPT;
```

If the header length is smaller than the minimum IPv4 header size, the packet is ignored and accepted.

### 4.9 Reading the TCP Header

After calculating the IPv4 header length, the module checks that the packet contains both the IPv4 header and the TCP header:

```c
if (!pskb_may_pull(skb, ip_hdr_len + sizeof(struct tcphdr)))
        return NF_ACCEPT;
```

Then the IP header is read again:

```c
iph = ip_hdr(skb);
```

This is done because `pskb_may_pull()` may adjust the internal packet data area.

The TCP header begins immediately after the IPv4 header:

```c
tcph = (struct tcphdr *)((unsigned char *)iph + ip_hdr_len);
```

The TCP header contains the source port and destination port.

### 4.10 Detecting HTTP Traffic

The Basic requirement of M3 is to detect HTTP packets on port `80`.

The module does this with the following condition:

```c
if (tcph->dest == htons(HTTP_PORT)) {
```

The field `tcph->dest` contains the TCP destination port.

The function `htons()` is used because network packet fields are stored in network byte order. The constant `HTTP_PORT` must be converted before comparing it with the value from the TCP header.

If the destination port is `80`, the module considers the packet to be HTTP traffic.

### 4.11 Logging Packet Information

When an HTTP packet is detected, the module logs information using `printk`:

```c
printk(KERN_INFO
       "snf_lkm: HTTP packet detected: src=%pI4 dst=%pI4 sport=%u dport=%u\n",
       &iph->saddr,
       &iph->daddr,
       ntohs(tcph->source),
       ntohs(tcph->dest));
```

This log message contains:

* source IP address
* destination IP address
* source TCP port
* destination TCP port

The `%pI4` format is used by the Linux kernel to print IPv4 addresses.

The function `ntohs()` converts TCP port numbers from network byte order to host byte order before printing them.

An example log message is:

```text
snf_lkm: HTTP packet detected: src=10.0.2.10 dst=10.0.2.15 sport=36386 dport=80
```

This satisfies the Intermediate requirement because the module logs the source IP address of detected HTTP packets.

### 4.12 Accepting Packets

At the end of the callback function, the module returns:

```c
return NF_ACCEPT;
```

This means the packet is accepted and continues normally through the Linux network stack.

The final version of this project does not block packets, does not drop packets, and does not modify packets. It only observes and logs HTTP packet information.

### 4.13 Netfilter Hook Configuration

The module defines a Netfilter hook configuration:

```c
static const struct nf_hook_ops lkm_nf_hook_ops_template = {
        .hook           = nf_callback,
        .hooknum        = NF_INET_PRE_ROUTING,
        .pf             = PF_INET,
        .priority       = NF_IP_PRI_FIRST,
};
```

This tells the kernel how and where the module wants to inspect packets.

The important fields are:

* `.hook = nf_callback`: the function that will be called for each packet.
* `.hooknum = NF_INET_PRE_ROUTING`: inspect packets early, before they are delivered locally.
* `.pf = PF_INET`: inspect IPv4 packets.
* `.priority = NF_IP_PRI_FIRST`: run this hook with high priority.

### 4.14 Registering the Hook

The function `netns_init()` registers the Netfilter hook:

```c
static int __net_init netns_init(struct net *net)
```

Inside this function, the module copies the hook template and registers it:

```c
memcpy(ops, &lkm_nf_hook_ops_template, sizeof(*ops));

rc = nf_register_net_hook(net, ops);
```

If registration fails, the module prints an error message:

```c
printk(KERN_ERR "snf_lkm: cannot register netfilter hook\n");
```

If registration succeeds, the module prints:

```text
snf_lkm: IPv4 HTTP packet logger registered
```

### 4.15 Unregistering the Hook

When the network namespace is removed, the module unregisters the Netfilter hook:

```c
static void __net_exit netns_exit(struct net *net)
```

The important line is:

```c
nf_unregister_net_hook(net, ops);
```

This removes the hook from Netfilter, so the callback function is no longer called for packets.

### 4.16 Module Load Function

The module initialization function is:

```c
static int __init lkm_init(void)
```

This function runs when the module is loaded using:

```bash
insmod snf_lkm.ko
```

Inside this function, the module registers its per-network-namespace operations:

```c
rc = register_pernet_subsys(&lkm_netns_ops);
```

If this succeeds, the module prints:

```text
snf_lkm: HTTP packet logger module loaded
```

### 4.17 Module Exit Function

The module cleanup function is:

```c
static void __exit lkm_exit(void)
```

This function runs when the module is removed using:

```bash
rmmod snf_lkm
```

It unregisters the per-network-namespace operations:

```c
unregister_pernet_subsys(&lkm_netns_ops);
```

Then it prints:

```text
snf_lkm: HTTP packet logger module unloaded
```

### 4.18 Module Metadata

At the end of the file, the module defines standard metadata:

```c
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Andrea Mayer / modified for M3 HTTP packet logging");
MODULE_DESCRIPTION("Linux Netfilter module for detecting IPv4 TCP HTTP packets and logging source IP addresses");
MODULE_VERSION("1.0.0");
```

This information describes the module.

The license is set to `GPL`, which is important for Linux kernel modules because many kernel symbols are only available to GPL-compatible modules.

## 5. Build Steps

The module is built inside the Podman container, not directly on the host machine.

First, enter the repository inside the container:

```bash
cd /opt/kernel-playground
```

The main module source file is located at:

```text
kernel/modules/snf_lkm.c
```

To build the kernel module, run the module build command from the repository:

```bash
make -C kernel/modules
```

After a successful build, the output should include the compiled kernel module file:

```text
snf_lkm.ko
```

The `.ko` file is the loadable kernel module. This is the file that will be inserted into the kernel inside the QEMU virtual machine.

A simplified build flow is:

```text
Source code:
kernel/modules/snf_lkm.c

        ↓ build

Kernel object:
snf_lkm.ko

        ↓ load inside QEMU VM

Running kernel module:
snf_lkm
```

The module should be loaded only inside the QEMU VM during testing. It should not be loaded directly on the host machine.

## 6. Run and Test Steps

After building the module, the next step is to test it inside the QEMU virtual machine.

The module should be loaded inside the VM, not directly on the host machine.

### 6.1 Start the QEMU VM

From the container/repository environment, start the QEMU virtual machine using the project VM tools.

From the repository VM directory, start the QEMU virtual machine using the project VM script or command provided by the `kernel-playground` setup. The important point is that the VM must boot successfully and provide a shell where the module can be loaded.

The VM is configured with port forwarding so that port `10080` outside the VM forwards to port `80` inside the VM.

This means:

```text
Outside VM: 127.0.0.1:10080
        ↓
Inside VM:  port 80
```

### 6.2 Load the Kernel Module Inside the VM

Inside the QEMU VM, the compiled kernel module was loaded from the shared directory mounted at `/mnt/shared`:

```bash
insmod /mnt/shared/snf_lkm.ko
```

The kernel log showed that the module was loaded successfully:

```text
[  614.979874] snf_lkm: IPv4 HTTP packet logger registered
[  614.989106] snf_lkm: HTTP packet logger module loaded
```

This confirms that the out-of-tree kernel module was inserted into the running VM kernel and that the Netfilter hook was registered.

### 6.3 Start an HTTP Server Inside the VM

To generate HTTP traffic, a simple BusyBox HTTP server was started inside the QEMU VM on port `80`.

```bash
mkdir -p /www
echo "hello from vm" > /www/index.html
pkill httpd 2>/dev/null
busybox httpd -p 80 -h /www
```

The server listens on port `80` inside the VM. The QEMU VM was started with port forwarding from the container to the VM:

```text
hostfwd=tcp::10080-:80
```

This means that an HTTP request sent to `127.0.0.1:10080` from outside the VM reaches port `80` inside the VM.

### 6.4 Send HTTP Traffic From Outside the VM

From the Podman container, an HTTP request was sent to the forwarded port:

```bash
curl http://127.0.0.1:10080/
```

This request reaches the HTTP server inside the VM. Since the packet is IPv4 TCP traffic with destination port `80`, the kernel module detects it as HTTP traffic.

### 6.5 Check the Kernel Log Inside the VM

Inside the QEMU VM, the kernel log was checked again:

```bash
dmesg | tail -n 20
```

The output showed that the module detected the HTTP packets:

```text
[  614.979874] snf_lkm: IPv4 HTTP packet logger registered
[  614.989106] snf_lkm: HTTP packet logger module loaded
[  641.270059] snf_lkm: HTTP packet detected: src=10.0.2.10 dst=10.0.2.15 sport=37488 dport=80
[  641.280291] snf_lkm: HTTP packet detected: src=10.0.2.10 dst=10.0.2.15 sport=37488 dport=80
[  641.287799] snf_lkm: HTTP packet detected: src=10.0.2.10 dst=10.0.2.15 sport=37488 dport=80
[  641.328260] snf_lkm: HTTP packet detected: src=10.0.2.10 dst=10.0.2.15 sport=37488 dport=80
[  641.344338] snf_lkm: HTTP packet detected: src=10.0.2.10 dst=10.0.2.15 sport=37488 dport=80
[  641.354110] snf_lkm: HTTP packet detected: src=10.0.2.10 dst=10.0.2.15 sport=37488 dport=80
```

In this result:

- `src=10.0.2.10` is the QEMU host-side address.
- `dst=10.0.2.15` is the VM address.
- `dport=80` confirms that the detected packets are HTTP traffic.
- `sport=37488` is the temporary TCP source port chosen for this connection.

The source port can be different each time the test is repeated.

### 6.6 Remove the Module

After testing, the module was removed from the VM:

```bash
rmmod snf_lkm
```

The kernel log confirmed that the Netfilter hook was unregistered and that the module cleanup function completed successfully:

```text
[  855.128674] snf_lkm: netfilter hook unregistered
[  855.170077] snf_lkm: HTTP packet logger module unloaded
```

This confirms that the module was removed cleanly and no longer hooks IPv4 HTTP traffic.

## 7. Results and Evidence

After loading the module inside the QEMU virtual machine and sending HTTP traffic to the VM, the module successfully detected HTTP packets on destination port `80`.

This result confirms that the module correctly:

1. received packets through the Netfilter hook
2. inspected IPv4 traffic
3. identified TCP packets
4. detected HTTP traffic by checking destination port `80`
5. logged packet information to the kernel log

The source IP address in the test was:

```text
10.0.2.10
```

The destination IP address in the test was:

```text
10.0.2.15
```

The destination port was:

```text
80
```

The source port can change between tests because it is dynamically selected by the TCP client.

One important observation is that a single `curl` request can produce more than one kernel log line. This happens because one HTTP request is carried over a TCP connection, and a TCP connection can contain several packets. Since this module detects packets with destination port `80`, it may log multiple packets for one HTTP request.

This behavior is expected and acceptable for this project because the Basic and Intermediate requirements are packet-based:

* detect HTTP packets on port `80`
* log HTTP packet information to the kernel log

The module does not block or modify the traffic. The HTTP request still reaches the server normally.


## 8. Development Notes

During development, the goal was to keep the module simple, understandable, and aligned with the selected M3 requirements.

The final version focuses on two main tasks:

```text
1. Detect HTTP packets on TCP destination port 80.
2. Log detected HTTP packet information to the kernel log.
```

The module was intentionally designed as a packet logger, not as a firewall.

For this reason, the module always returns:

```c
return NF_ACCEPT;
```

This means that every packet continues normally through the Linux networking stack. The module only observes packets and prints information when it detects HTTP traffic.

The final version does not include blacklist logic. It does not create a `/proc/snf_blacklist` file, does not load IP addresses from user space, and does not drop packets. This keeps the implementation focused on the Basic and Intermediate parts of the assignment.

Another important design decision is the use of QEMU for testing. Kernel modules run inside the kernel, so a programming mistake can cause a kernel crash. Testing the module inside a QEMU virtual machine protects the host machine because any crash would affect only the VM.

The module also follows the original `kernel-playground` style by using per-network-namespace operations. This is why the module uses:

```c
register_pernet_subsys(&lkm_netns_ops);
```

and stores the Netfilter hook inside a per-network-namespace structure.

This design makes the module fit better with the repository style while still keeping the packet inspection logic simple.

Overall, the project demonstrates how a Linux kernel module can use Netfilter to inspect IPv4 TCP traffic and log HTTP packet information at kernel level.

## 9. Final Repository State

The final project is kept in the root of the `kernel-playground` repository.

The main implementation file is:

```text
kernel/modules/snf_lkm.c
```

This file contains the complete `snf_lkm` kernel module for M3 HTTP packet logging.

The root README file is:

```text
README.md
```

This README is the main documentation for the project. It contains the project overview, environment explanation, design notes, implementation explanation, build steps, test steps, results, and evidence.

The final project demonstrates a simple Linux Netfilter kernel module that detects IPv4 TCP HTTP packets on destination port `80`, logs packet information to the kernel log, and accepts all packets without blocking or modifying traffic.
