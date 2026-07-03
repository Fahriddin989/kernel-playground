# M6 — Destination IP Classifier Kernel Module

**Student:** Fakhriddin Shamuratov  
**Matricola:** 0363580  
**Course:** Software Networks  
**Project Level:** Basic Level  

---

## 1. Goal

The goal of this project is to implement the **Basic Level** of **M6 — Destination IP Classifier**.

The module intercepts outgoing IPv4 packets using a Netfilter hook, extracts the destination IP address, classifies it as **Class A**, **Class B**, **Class C**, or **Other / Reserved**, and logs the result to the kernel log.

The module only observes packets. It does not drop, block, or modify traffic.

---

## 2. Project Files

The implementation is located in:

```text
kernel/modules/

Main files:

snf_lkm.c   - Netfilter kernel module source code
Makefile    - Builds the kernel module
README.md   - Project documentation
3. Implementation Overview

The module registers a Netfilter hook at:

NF_INET_LOCAL_OUT

This hook inspects locally generated outgoing IPv4 packets before they leave the Linux network stack.

For each packet, the module:

checks that the packet buffer exists;
checks that the IPv4 header is accessible;
reads the IPv4 header with ip_hdr(skb);
extracts the destination IP address from iph->daddr;
converts the address from network byte order to host byte order;
reads the first octet;
classifies the destination IP;
logs the result with pr_info;
returns NF_ACCEPT.
4. IPv4 Classification Logic

The classification is based on the first octet of the destination IPv4 address.

Class	First octet range	Example
Class A	1–126	8.8.8.8
Class B	128–191	172.217.16.14
Class C	192–223	192.168.1.1
Other / Reserved	Everything else	127.x.x.x, 224.x.x.x

Code logic:

if (first_octet >= 1 && first_octet <= 126)
        return "Class A";

if (first_octet >= 128 && first_octet <= 191)
        return "Class B";

if (first_octet >= 192 && first_octet <= 223)
        return "Class C";

return "Other / Reserved";
5. Build Instructions

Build the kernel module from the module directory:

cd kernel/modules
make

The build creates:

snf_lkm.ko

The Makefile also copies the compiled module to the shared VM folder.

6. Load the Module Inside the VM

Inside the VM, load the module:

insmod /mnt/shared/snf_lkm.ko

Expected log:

M6 Basic: Destination IP Classifier loaded

The following message may also appear:

loading out-of-tree module taints kernel

This is normal for a custom kernel module compiled outside the official Linux kernel tree.

7. Generate Test Traffic

Clear old logs:

dmesg -C

Generate outgoing IPv4 packets:

ping -c 1 8.8.8.8
ping -c 1 172.217.16.14
ping -c 1 192.168.1.1

A successful ping reply is not required. The goal is to generate outgoing packets so the NF_INET_LOCAL_OUT hook can inspect them.

8. Check Results

Check the kernel log:

dmesg | grep "M6 Basic"

Observed output:

M6 Basic: destination 8.8.8.8 classified as Class A
M6 Basic: destination 172.217.16.14 classified as Class B
M6 Basic: destination 192.168.1.1 classified as Class C

This confirms that the module correctly classifies destination IPv4 addresses.

9. Unload the Module

Remove the module:

rmmod snf_lkm

Check the final log:

dmesg | tail -n 10

Expected output:

M6 Basic: Destination IP Classifier unloaded
10. Result

The Basic Level implementation works correctly.

The module successfully:

loads into the kernel;
registers a Netfilter hook;
intercepts outgoing IPv4 packets;
extracts destination IP addresses;
classifies destination IPs as Class A, Class B, or Class C;
logs the result to dmesg;
accepts all packets with NF_ACCEPT;
unloads cleanly.
11. Limitations

This project implements only the Basic Level.

It does not implement:

packet counters per class;
/proc statistics;
IPv6 prefix classification;
traffic shaping;
packet dropping.

These features belong to the Intermediate and Advanced levels and were not required for this submission.

Final Packet Flow
Outgoing packet generated
↓
NF_INET_LOCAL_OUT hook receives packet
↓
IPv4 header is checked
↓
Destination IP is extracted
↓
First octet is read
↓
Destination class is selected
↓
Result is written to dmesg
↓
Packet is accepted with NF_ACCEPT

