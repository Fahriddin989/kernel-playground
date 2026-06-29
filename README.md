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

### 5.4 Runtime Blacklist Helper Functions

This part of the module contains helper functions used by the Netfilter callback and the `/proc` interface.

#### 5.4.1 Checking whether a source IP is from the allowed range

```c id="kgp117"
static bool src_ip_allowed(__be32 saddr)
{
        __u32 src = ntohl(saddr);

        return (src & ALLOWED_MASK) == ALLOWED_NET;
}
```

The function `src_ip_allowed` checks whether the source IP address belongs to the `10.0.2.0/24` range.

The parameter `saddr` is the source IP address taken from the IPv4 header. It is stored in network byte order, so the function first converts it using:

```c id="18srn2"
ntohl(saddr)
```

`ntohl` means “network to host long”. It converts the 32-bit IP address from network byte order into host byte order so the module can compare it with `ALLOWED_NET`.

Then the function applies the subnet mask:

```c id="c6x0mm"
src & ALLOWED_MASK
```

This keeps only the network part of the IP address. If the result equals `ALLOWED_NET`, the source IP is considered part of the allowed range.

In this project, this function is used only for logging. It decides whether the accepted packet should be logged as:

```text id="yiz9kh"
accepted from allowed range
```

or:

```text id="79roib"
accepted from outside range
```

It does not decide whether the packet is dropped. Dropping is controlled only by the blacklist.

#### 5.4.2 Checking whether an IP is blacklisted

```c id="q2u2s5"
static bool ip_blacklisted(__be32 saddr)
{
        unsigned int i;
        bool found = false;

        spin_lock_bh(&blacklist_lock);
        for (i = 0; i < blacklist_count; i++) {
                if (blacklist[i] == saddr) {
                        found = true;
                        break;
                }
        }
        spin_unlock_bh(&blacklist_lock);

        return found;
}
```

The function `ip_blacklisted` checks whether the packet source IP exists in the runtime blacklist.

It loops through the `blacklist` array from index `0` to `blacklist_count - 1`. If one stored blacklist entry equals the packet source address, the function returns `true`.

The function uses:

```c id="k52jn6"
spin_lock_bh(&blacklist_lock);
```

and:

```c id="ir67sr"
spin_unlock_bh(&blacklist_lock);
```

This protects the blacklist while it is being read. The `_bh` version is used because the Netfilter callback can run in a networking/softirq-related context. Disabling bottom halves while holding the lock helps avoid unsafe concurrent access between packet processing and `/proc` updates.

The function returns:

```text id="5u45ft"
true   if the source IP is blacklisted
false  if the source IP is not blacklisted
```

#### 5.4.3 Parsing an IPv4 address from text

```c id="bc39rq"
static int parse_ipv4(const char *text, __be32 *addr)
{
        unsigned int a, b, c, d;
        __u32 host_addr;

        if (sscanf(text, "%u.%u.%u.%u", &a, &b, &c, &d) != 4)
                return -EINVAL;

        if (a > 255 || b > 255 || c > 255 || d > 255)
                return -EINVAL;

        host_addr = (a << 24) | (b << 16) | (c << 8) | d;
        *addr = htonl(host_addr);

        return 0;
}
```

The function `parse_ipv4` converts a text IP address, such as:

```text id="l0kxgo"
10.0.2.10
```

into the binary format used by the kernel.

The function first reads four decimal numbers using `sscanf`:

```c id="ikfq1k"
sscanf(text, "%u.%u.%u.%u", &a, &b, &c, &d)
```

If the input does not contain four numbers separated by dots, the function returns:

```c id="t0c2u4"
-EINVAL
```

`-EINVAL` means “invalid argument”.

Then the function checks that each part of the IP address is between `0` and `255`. This is required because each IPv4 octet can only have values in that range.

After validation, the function builds the 32-bit IP address:

```c id="dy3dqs"
host_addr = (a << 24) | (b << 16) | (c << 8) | d;
```

Finally, it converts the address to network byte order:

```c id="uy9xvd"
*addr = htonl(host_addr);
```

`htonl` means “host to network long”. This is necessary because IP addresses in packet headers are stored in network byte order. By storing blacklist entries in the same format, the module can compare them directly with `iph->saddr`.

If parsing succeeds, the function returns `0`.

Without a lock, the module could read the blacklist while it is being updated, which may lead to inconsistent behavior.

The module also defines a per-network namespace data structure:

```c
struct lkm_netns_data {
        struct nf_hook_ops nf_hops;
};
```

### 5.4 Runtime Blacklist Helper Functions

This part of the module contains helper functions used by the Netfilter callback and the `/proc` interface.

#### 5.4.1 Checking whether a source IP is from the allowed range

```c id="kgp117"
static bool src_ip_allowed(__be32 saddr)
{
        __u32 src = ntohl(saddr);

        return (src & ALLOWED_MASK) == ALLOWED_NET;
}
```

The function `src_ip_allowed` checks whether the source IP address belongs to the `10.0.2.0/24` range.

The parameter `saddr` is the source IP address taken from the IPv4 header. It is stored in network byte order, so the function first converts it using:

```c id="18srn2"
ntohl(saddr)
```

`ntohl` means “network to host long”. It converts the 32-bit IP address from network byte order into host byte order so the module can compare it with `ALLOWED_NET`.

Then the function applies the subnet mask:

```c id="c6x0mm"
src & ALLOWED_MASK
```

This keeps only the network part of the IP address. If the result equals `ALLOWED_NET`, the source IP is considered part of the allowed range.

In this project, this function is used only for logging. It decides whether the accepted packet should be logged as:

```text id="yiz9kh"
accepted from allowed range
```

or:

```text id="79roib"
accepted from outside range
```

It does not decide whether the packet is dropped. Dropping is controlled only by the blacklist.

#### 5.4.2 Checking whether an IP is blacklisted

```c id="q2u2s5"
static bool ip_blacklisted(__be32 saddr)
{
        unsigned int i;
        bool found = false;

        spin_lock_bh(&blacklist_lock);
        for (i = 0; i < blacklist_count; i++) {
                if (blacklist[i] == saddr) {
                        found = true;
                        break;
                }
        }
        spin_unlock_bh(&blacklist_lock);

        return found;
}
```

The function `ip_blacklisted` checks whether the packet source IP exists in the runtime blacklist.

It loops through the `blacklist` array from index `0` to `blacklist_count - 1`. If one stored blacklist entry equals the packet source address, the function returns `true`.

The function uses:

```c id="k52jn6"
spin_lock_bh(&blacklist_lock);
```

and:

```c id="ir67sr"
spin_unlock_bh(&blacklist_lock);
```

This protects the blacklist while it is being read. The `_bh` version is used because the Netfilter callback can run in a networking/softirq-related context. Disabling bottom halves while holding the lock helps avoid unsafe concurrent access between packet processing and `/proc` updates.

The function returns:

```text id="5u45ft"
true   if the source IP is blacklisted
false  if the source IP is not blacklisted
```

#### 5.4.3 Parsing an IPv4 address from text

```c id="bc39rq"
static int parse_ipv4(const char *text, __be32 *addr)
{
        unsigned int a, b, c, d;
        __u32 host_addr;

        if (sscanf(text, "%u.%u.%u.%u", &a, &b, &c, &d) != 4)
                return -EINVAL;

        if (a > 255 || b > 255 || c > 255 || d > 255)
                return -EINVAL;

        host_addr = (a << 24) | (b << 16) | (c << 8) | d;
        *addr = htonl(host_addr);

        return 0;
}
```

The function `parse_ipv4` converts a text IP address, such as:

```text id="l0kxgo"
10.0.2.10
```

into the binary format used by the kernel.

The function first reads four decimal numbers using `sscanf`:

```c id="ikfq1k"
sscanf(text, "%u.%u.%u.%u", &a, &b, &c, &d)
```

If the input does not contain four numbers separated by dots, the function returns:

```c id="t0c2u4"
-EINVAL
```

`-EINVAL` means “invalid argument”.

Then the function checks that each part of the IP address is between `0` and `255`. This is required because each IPv4 octet can only have values in that range.

After validation, the function builds the 32-bit IP address:

```c id="dy3dqs"
host_addr = (a << 24) | (b << 16) | (c << 8) | d;
```

Finally, it converts the address to network byte order:

```c id="uy9xvd"
*addr = htonl(host_addr);
```

`htonl` means “host to network long”. This is necessary because IP addresses in packet headers are stored in network byte order. By storing blacklist entries in the same format, the module can compare them directly with `iph->saddr`.

If parsing succeeds, the function returns `0`.


This structure stores the Netfilter hook operations for a network namespace. The field `nf_hops` contains the hook configuration that tells the kernel which callback function should inspect packets, at which Netfilter stage, and for which protocol family.

### 5.5 `/proc` Interface for Blacklist Control

The module creates a runtime control file:

```text
/proc/snf_blacklist
```

This file allows the user to read the current blacklist and update it while the module is still loaded. This is useful because the module does not need to be recompiled or reloaded every time the blacklist changes.

The `/proc` interface has two operations:

```text
1. read  -> show the current blacklist
2. write -> load new blacklist entries or clear the blacklist
```

#### 5.5.1 Reading the blacklist

```c
static ssize_t blacklist_read(struct file *file, char __user *user_buf,
                              size_t count, loff_t *ppos)
{
        char kbuf[512];
        __be32 local_blacklist[MAX_BLACKLIST_ENTRIES];
        unsigned int local_count;
        unsigned int i;
        int len = 0;

        spin_lock_bh(&blacklist_lock);
        local_count = blacklist_count;
        memcpy(local_blacklist, blacklist, sizeof(blacklist));
        spin_unlock_bh(&blacklist_lock);

        if (local_count == 0) {
                len += scnprintf(kbuf + len, sizeof(kbuf) - len, "empty\n");
        } else {
                for (i = 0; i < local_count; i++) {
                        len += scnprintf(kbuf + len, sizeof(kbuf) - len,
                                         "%pI4\n", &local_blacklist[i]);
                }
        }

        return simple_read_from_buffer(user_buf, count, ppos, kbuf, len);
}
```

The function `blacklist_read` runs when the user reads:

```bash
cat /proc/snf_blacklist
```

The function first creates a kernel buffer:

```c
char kbuf[512];
```

This buffer is used to prepare the text that will be shown to the user.

The module then copies the current blacklist into a local temporary array:

```c
spin_lock_bh(&blacklist_lock);
local_count = blacklist_count;
memcpy(local_blacklist, blacklist, sizeof(blacklist));
spin_unlock_bh(&blacklist_lock);
```

This is done while holding the spinlock, because the real blacklist may be modified at the same time by a `/proc` write operation. After the copy is finished, the lock is released quickly. The rest of the read operation uses the local copy, which reduces the time spent holding the lock.

If the blacklist is empty, the function prints:

```text
empty
```

If the blacklist contains IP addresses, the function prints each address on a separate line. The format specifier:

```c
%pI4
```

is a Linux kernel format used to print an IPv4 address.

Finally, the function sends the prepared kernel buffer to userspace using:

```c
simple_read_from_buffer(user_buf, count, ppos, kbuf, len);
```

This safely copies the prepared text from kernel memory to the user program that is reading the `/proc` file.

#### 5.5.2 Writing the blacklist

```c
static ssize_t blacklist_write(struct file *file, const char __user *user_buf,
                               size_t count, loff_t *ppos)
{
        char kbuf[WRITE_BUF_SIZE];
        char *cursor;
        char *line;
        __be32 new_blacklist[MAX_BLACKLIST_ENTRIES];
        unsigned int new_count = 0;
```

The function `blacklist_write` runs when the user writes data into:

```bash
/proc/snf_blacklist
```

For example:

```bash
echo 10.0.2.10 > /proc/snf_blacklist
```

The user input comes from userspace, so the module cannot read it directly. First, the module limits the input size:

```c
if (count >= sizeof(kbuf))
        count = sizeof(kbuf) - 1;
```

Then it copies the user input into a kernel buffer:

```c
if (copy_from_user(kbuf, user_buf, count))
        return -EFAULT;
```

`copy_from_user` is required because kernel code must safely copy data from userspace memory. If the copy fails, the function returns:

```c
-EFAULT
```

After copying, the module adds a null terminator:

```c
kbuf[count] = '\0';
```

This makes the buffer safe to treat as a C string.

#### 5.5.3 Clearing the blacklist

The module supports a simple command for clearing the blacklist:

```c
if (strncmp(kbuf, "clear", 5) == 0) {
        spin_lock_bh(&blacklist_lock);
        blacklist_count = 0;
        memset(blacklist, 0, sizeof(blacklist));
        spin_unlock_bh(&blacklist_lock);

        printk(KERN_INFO "snf_lkm: blacklist cleared\n");
        return count;
}
```

If the user writes:

```bash
echo clear > /proc/snf_blacklist
```

the module removes all blacklist entries by setting `blacklist_count` to `0` and clearing the blacklist array.

#### 5.5.4 Loading new blacklist entries

If the input is not `clear`, the module treats it as a list of IP addresses.

```c
cursor = kbuf;

while ((line = strsep(&cursor, "\n")) != NULL) {
        __be32 addr;

        if (line[0] == '\0')
                continue;

        if (new_count >= MAX_BLACKLIST_ENTRIES) {
                printk(KERN_WARNING
                       "snf_lkm: blacklist full, ignoring extra entries\n");
                break;
        }

        if (parse_ipv4(line, &addr) != 0) {
                printk(KERN_WARNING
                       "snf_lkm: invalid blacklist entry ignored: %s\n",
                       line);
                continue;
        }

        new_blacklist[new_count++] = addr;
}
```

The function `strsep` splits the input into separate lines. This means the user can write one IP address or multiple IP addresses.

Each non-empty line is passed to:

```c
parse_ipv4(line, &addr)
```

If the IP address is valid, it is stored in the temporary `new_blacklist` array.

The module also checks the blacklist limit. If more than 16 entries are provided, extra entries are ignored and a warning is printed.

After parsing the input, the module replaces the old blacklist with the new one:

```c
spin_lock_bh(&blacklist_lock);
memset(blacklist, 0, sizeof(blacklist));
memcpy(blacklist, new_blacklist, new_count * sizeof(__be32));
blacklist_count = new_count;
spin_unlock_bh(&blacklist_lock);
```

The replacement is protected by the spinlock because the Netfilter callback may read the blacklist while packets are being inspected.

Finally, the module logs how many entries were loaded:

```c
printk(KERN_INFO "snf_lkm: loaded %u blacklist entries\n", new_count);
```

In the test, writing `10.0.2.10` into `/proc/snf_blacklist` produced:

```text
snf_lkm: loaded 1 blacklist entries
```

#### 5.5.5 Connecting read/write functions to `/proc`

The module connects the read and write functions using:

```c
static const struct proc_ops blacklist_proc_ops = {
        .proc_read  = blacklist_read,
        .proc_write = blacklist_write,
};
```

This tells the kernel:

```text
When /proc/snf_blacklist is read, call blacklist_read.
When /proc/snf_blacklist is written, call blacklist_write.
```

Later, during module initialization, these operations are attached to the actual `/proc` file.

### 5.6 Netfilter Callback for Packet Inspection

The Netfilter callback is the core of the module. It is the function that receives packets from the Linux networking stack and decides what to do with them.

```c
static unsigned int nf_callback(void *priv, struct sk_buff *skb,
                                const struct nf_hook_state *state)
{
        struct iphdr *iph;
        struct tcphdr *tcph;
        unsigned int ip_hdr_len;
```

The function receives a packet through the `skb` parameter. In the Linux kernel, network packets are stored in a structure called `struct sk_buff`. This structure contains the packet data and metadata used by the networking stack.

The module declares:

```c
struct iphdr *iph;
struct tcphdr *tcph;
```

`iph` will point to the IPv4 header, and `tcph` will point to the TCP header.

#### 5.6.1 Basic packet safety checks

The first check is:

```c
if (!skb)
        return NF_ACCEPT;
```

If the packet buffer does not exist, the module does not try to inspect it. It simply accepts the packet.

Then the module checks whether the packet contains enough data for an IPv4 header:

```c
if (!pskb_may_pull(skb, sizeof(struct iphdr)))
        return NF_ACCEPT;
```

`pskb_may_pull` makes sure that the required part of the packet is safely accessible in memory. If the packet is too short or cannot be pulled into readable memory, the module accepts it instead of risking an unsafe memory access.

#### 5.6.2 Reading and validating the IPv4 header

After the packet passes the first safety check, the module reads the IPv4 header:

```c
iph = ip_hdr(skb);
```

Then it confirms that the packet is really IPv4:

```c
if (iph->version != 4)
        return NF_ACCEPT;
```

After that, it checks whether the packet is TCP:

```c
if (iph->protocol != IPPROTO_TCP)
        return NF_ACCEPT;
```

The module only cares about IPv4 TCP traffic. Other packets, such as UDP or ICMP, are not part of this experiment and are accepted without modification.

#### 5.6.3 Finding the TCP header

IPv4 headers can have variable length because they may contain optional fields. For this reason, the module calculates the actual IP header length:

```c
ip_hdr_len = iph->ihl * 4;
```

`ihl` means Internet Header Length. It is stored in 32-bit words, so multiplying by `4` converts it into bytes.

The module then checks that the calculated header length is valid:

```c
if (ip_hdr_len < sizeof(struct iphdr))
        return NF_ACCEPT;
```

After that, it checks whether the packet contains enough data for both the IP header and the TCP header:

```c
if (!pskb_may_pull(skb, ip_hdr_len + sizeof(struct tcphdr)))
        return NF_ACCEPT;
```

If the packet is safe to inspect, the module reads the headers again:

```c
iph = ip_hdr(skb);
tcph = (struct tcphdr *)((unsigned char *)iph + ip_hdr_len);
```

The TCP header starts immediately after the IPv4 header, so the module moves forward by `ip_hdr_len` bytes from the beginning of the IP header.

#### 5.6.4 Detecting new HTTP connections

The module then checks whether the packet is a new HTTP connection request:

```c
if (tcph->dest == htons(HTTP_PORT) && tcph->syn && !tcph->ack) {
```

This condition has three parts:

```text
1. tcph->dest == htons(HTTP_PORT)
   The packet destination port must be 80.

2. tcph->syn
   The TCP SYN flag must be set.

3. !tcph->ack
   The TCP ACK flag must not be set.
```

Together, these checks identify the first packet of a new TCP connection to HTTP port `80`.

`HTTP_PORT` is `80`, but TCP ports in packet headers are stored in network byte order. Therefore, the module uses:

```c
htons(HTTP_PORT)
```

`htons` means “host to network short”. It converts the port number into the same byte order used in the TCP header.

The module checks only SYN packets without ACK because this avoids logging every packet in the HTTP connection. Instead, it logs only the connection attempt.

#### 5.6.5 Dropping blacklisted HTTP traffic

If the packet is a new HTTP connection, the module first checks whether the source IP is blacklisted:

```c
if (ip_blacklisted(iph->saddr)) {
        printk(KERN_INFO
               "snf_lkm: DROPPED blacklisted HTTP source: src=%pI4 dst=%pI4 sport=%u dport=%u\n",
               &iph->saddr,
               &iph->daddr,
               ntohs(tcph->source),
               ntohs(tcph->dest));
        return NF_DROP;
}
```

The function:

```c
ip_blacklisted(iph->saddr)
```

checks the packet source address against the runtime blacklist.

If the source IP is found in the blacklist, the module prints a kernel log message and returns:

```c
NF_DROP
```

`NF_DROP` tells Netfilter to drop the packet. This means the HTTP connection attempt is blocked before it reaches the local HTTP service.

In the experiment, after adding `10.0.2.10` to the blacklist, the module produced this log:

```text
snf_lkm: DROPPED blacklisted HTTP source: src=10.0.2.10 dst=10.0.2.15 sport=54760 dport=80
```

#### 5.6.6 Logging accepted HTTP traffic

If the source IP is not blacklisted, the module accepts the packet. Before accepting it, it logs whether the source IP belongs to the expected QEMU network range.

```c
if (src_ip_allowed(iph->saddr)) {
        printk(KERN_INFO
               "snf_lkm: HTTP connection accepted from allowed range: src=%pI4 dst=%pI4 sport=%u dport=%u\n",
               &iph->saddr,
               &iph->daddr,
               ntohs(tcph->source),
               ntohs(tcph->dest));
} else {
        printk(KERN_INFO
               "snf_lkm: HTTP connection accepted from outside range: src=%pI4 dst=%pI4 sport=%u dport=%u\n",
               &iph->saddr,
               &iph->daddr,
               ntohs(tcph->source),
               ntohs(tcph->dest));
}
```

The function `src_ip_allowed` does not block or allow traffic. It only controls the wording of the log message.

The log message includes:

```text
source IP address
destination IP address
source TCP port
destination TCP port
```

The format `%pI4` is used to print IPv4 addresses in kernel logs.

The function `ntohs` is used for TCP ports because port numbers in the TCP header are stored in network byte order. `ntohs` converts them back to host byte order before printing.

In the experiment, accepted HTTP traffic produced this log:

```text
snf_lkm: HTTP connection accepted from allowed range: src=10.0.2.10 dst=10.0.2.15 sport=53368 dport=80
```

#### 5.6.7 Default decision

At the end of the callback, the module returns:

```c
return NF_ACCEPT;
```

This means packets are accepted by default.

The module drops only one type of packet:

```text
A new TCP connection request to destination port 80 from a source IP that exists in /proc/snf_blacklist.
```

All other packets are allowed to continue through the network stack.

### 5.7 Netfilter Hook Configuration and Per-Network Namespace Registration

After defining the packet inspection callback, the module defines how that callback is connected to the Linux networking stack.

#### 5.7.1 Netfilter hook template

```c id="z2ymrv"
static const struct nf_hook_ops lkm_nf_hook_ops_template = {
        .hook           = nf_callback,
        .hooknum        = NF_INET_PRE_ROUTING,
        .pf             = PF_INET,
        .priority       = NF_IP_PRI_FIRST,
};
```

This structure tells Netfilter which function should inspect packets and where in the packet-processing path the function should run.

The field:

```c id="4ql8n5"
.hook = nf_callback
```

means that Netfilter should call the function `nf_callback` when a matching packet reaches this hook.

The field:

```c id="ievw0q"
.hooknum = NF_INET_PRE_ROUTING
```

means the callback runs at the `PRE_ROUTING` stage. This is an early stage in the packet path, before the packet is delivered locally or forwarded. In this project, it allows the module to see HTTP packets before they reach the HTTP service inside the VM.

The field:

```c id="0cm4er"
.pf = PF_INET
```

means the hook applies to IPv4 traffic.

The field:

```c id="5e39j6"
.priority = NF_IP_PRI_FIRST
```

means this hook should run with high priority, early in the Netfilter processing order.

#### 5.7.2 Getting the hook for the current network namespace

```c id="1x1k2e"
static struct nf_hook_ops *lkm_nf_hook_ops(struct net *net)
{
        struct lkm_netns_data *netns_data = net_generic(net, lkm_net_id);

        return &netns_data->nf_hops;
}
```

This helper function retrieves the module’s Netfilter hook storage for a specific network namespace.

A network namespace is an isolated network environment inside the Linux kernel. Each namespace can have its own interfaces, routing tables, and network configuration.

The function:

```c id="o18tsx"
net_generic(net, lkm_net_id)
```

gets the private data area assigned to this module for the given network namespace.

Then the function returns:

```c id="82eov1"
&netns_data->nf_hops
```

This is the `nf_hook_ops` structure that will be registered for that namespace.

#### 5.7.3 Registering the hook inside a network namespace

```c id="nxewr6"
static int __net_init netns_init(struct net *net)
{
        struct nf_hook_ops *ops = lkm_nf_hook_ops(net);
        int rc;

        memcpy(ops, &lkm_nf_hook_ops_template, sizeof(*ops));

        rc = nf_register_net_hook(net, ops);
        if (rc) {
                printk(KERN_ERR "snf_lkm: cannot register netfilter hook\n");
                return rc;
        }

        printk(KERN_INFO "snf_lkm: IPv4 HTTP netfilter hook registered\n");
        return 0;
}
```

The function `netns_init` runs when the module is initialized for a network namespace.

First, it gets the namespace-specific hook structure:

```c id="7cdv6w"
struct nf_hook_ops *ops = lkm_nf_hook_ops(net);
```

Then it copies the hook template into that structure:

```c id="gcirjl"
memcpy(ops, &lkm_nf_hook_ops_template, sizeof(*ops));
```

This gives the namespace its own Netfilter hook configuration.

After that, the module registers the hook:

```c id="al2br0"
rc = nf_register_net_hook(net, ops);
```

If registration fails, the module prints an error and returns the error code.

If registration succeeds, the module prints:

```text id="39nipg"
snf_lkm: IPv4 HTTP netfilter hook registered
```

This message was observed during testing and confirms that the hook was successfully registered.

#### 5.7.4 Unregistering the hook

```c id="yeydy4"
static void __net_exit netns_exit(struct net *net)
{
        struct nf_hook_ops *ops = lkm_nf_hook_ops(net);

        nf_unregister_net_hook(net, ops);

        printk(KERN_INFO "snf_lkm: netfilter hook unregistered\n");
}
```

The function `netns_exit` runs when the module is removed from a network namespace.

It retrieves the hook structure and unregisters it using:

```c id="nq55xk"
nf_unregister_net_hook(net, ops);
```

This is important because the kernel must stop calling the module’s callback before the module is unloaded. If the hook remained registered after unloading, the kernel could try to call code that no longer exists.

#### 5.7.5 Per-network namespace operations

```c id="j6oml0"
static struct pernet_operations lkm_netns_ops = {
        .init = netns_init,
        .exit = netns_exit,
        .id = &lkm_net_id,
        .size = sizeof(struct lkm_netns_data),
};
```

This structure connects the module to the kernel’s per-network namespace system.

The field:

```c id="xtolvz"
.init = netns_init
```

tells the kernel to call `netns_init` when the module is initialized for a network namespace.

The field:

```c id="7gl12p"
.exit = netns_exit
```

tells the kernel to call `netns_exit` when the module is removed from a network namespace.

The field:

```c id="vi1jnh"
.id = &lkm_net_id
```

lets the kernel assign an ID for this module’s namespace-specific data.

The field:

```c id="nsbk1t"
.size = sizeof(struct lkm_netns_data)
```

tells the kernel how much private data to allocate for each network namespace.

In this project, that private data contains the Netfilter hook operations structure used by the module.

### 5.8 Module Initialization, Cleanup, and Metadata

The last part of the module connects all components together: the `/proc` interface, the Netfilter hook registration, and the module metadata.

#### 5.8.1 Module initialization

```c
static int __init lkm_init(void)
{
        int rc;

        proc_create(PROC_NAME, 0666, NULL, &blacklist_proc_ops);

        rc = register_pernet_subsys(&lkm_netns_ops);
        if (rc) {
                remove_proc_entry(PROC_NAME, NULL);
                printk(KERN_ERR "snf_lkm: cannot register pernet ops\n");
                return rc;
        }

        printk(KERN_INFO "snf_lkm: HTTP detector module with blacklist loaded\n");
        printk(KERN_INFO "snf_lkm: use /proc/%s to load or clear blacklist\n",
               PROC_NAME);
        return 0;
}
```

The function `lkm_init` runs when the module is loaded using `insmod`.

The annotation:

```c
__init
```

tells the kernel that this function is used only during module initialization.

The first important operation is:

```c
proc_create(PROC_NAME, 0666, NULL, &blacklist_proc_ops);
```

This creates the runtime control file:

```text
/proc/snf_blacklist
```

The permission value `0666` means the file can be read and written. In this project, this makes it possible to update the blacklist from the VM command line.

The last argument:

```c
&blacklist_proc_ops
```

connects the `/proc` file to the read and write functions explained earlier:

```text
blacklist_read
blacklist_write
```

After creating the `/proc` file, the module registers its per-network namespace operations:

```c
rc = register_pernet_subsys(&lkm_netns_ops);
```

This step causes the kernel to call `netns_init`, which registers the Netfilter hook for the current network namespace.

If this registration fails, the module removes the `/proc` file again:

```c
remove_proc_entry(PROC_NAME, NULL);
```

This cleanup is important because the module should not leave `/proc/snf_blacklist` behind if the Netfilter hook cannot be registered.

If initialization succeeds, the module prints:

```text
snf_lkm: HTTP detector module with blacklist loaded
snf_lkm: use /proc/snf_blacklist to load or clear blacklist
```

These messages were observed during testing and confirm that the module loaded successfully.

#### 5.8.2 Module cleanup

```c
static void __exit lkm_exit(void)
{
        unregister_pernet_subsys(&lkm_netns_ops);
        remove_proc_entry(PROC_NAME, NULL);

        printk(KERN_INFO "snf_lkm: HTTP detector module unloaded\n");
}
```

The function `lkm_exit` runs when the module is removed using `rmmod`.

The annotation:

```c
__exit
```

marks this function as the module cleanup function.

The first operation is:

```c
unregister_pernet_subsys(&lkm_netns_ops);
```

This unregisters the per-network namespace operations. As part of this process, the kernel calls `netns_exit`, which unregisters the Netfilter hook.

After the Netfilter hook is removed, the module removes the `/proc` file:

```c
remove_proc_entry(PROC_NAME, NULL);
```

This ensures that `/proc/snf_blacklist` no longer exists after the module is unloaded.

Finally, the module prints:

```text
snf_lkm: HTTP detector module unloaded
```

#### 5.8.3 Connecting the init and exit functions

```c
module_init(lkm_init);
module_exit(lkm_exit);
```

These two macros tell the kernel which functions should run when the module is loaded and unloaded.

```text
module_init(lkm_init)   -> run lkm_init when the module is loaded
module_exit(lkm_exit)   -> run lkm_exit when the module is removed
```

Without these macros, the kernel would not know which functions are responsible for starting and stopping the module.

#### 5.8.4 Module metadata

```c
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Andrea Mayer / modified for HTTP detection and blacklist support");
MODULE_DESCRIPTION("Linux Netfilter module for detecting and dropping IPv4 TCP HTTP packets from blacklisted IPs");
MODULE_VERSION("1.2.0");
```

This metadata describes the module.

`MODULE_LICENSE("GPL")` tells the kernel that the module uses the GPL license. This is important because some kernel symbols are available only to GPL-compatible modules.

`MODULE_AUTHOR` identifies the original author and notes that the module was modified for HTTP detection and blacklist support.

`MODULE_DESCRIPTION` provides a short explanation of what the module does.

`MODULE_VERSION` defines the module version used for this implementation.

