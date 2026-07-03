# M6 — Destination IP Classifier (Kernel Module)

**Student:** Fakhriddin Shamuratov  
**Matricola:** 0363580  
**Course:** Software Networks  
**Level implemented:** Basic Level  

---

## 1. Project Goal

The goal of this project is to implement the **Basic Level** of project **M6 — Destination IP Classifier**.

The module intercepts outgoing IPv4 packets using a Netfilter hook, extracts the destination IP address from the IPv4 header, classifies the destination address according to the traditional IPv4 class system, and logs the result to the kernel log.

The implemented IPv4 destination classes are:

| Class | Address range |
|---|---|
| Class A | 1.0.0.0 – 126.255.255.255 |
| Class B | 128.0.0.0 – 191.255.255.255 |
| Class C | 192.0.0.0 – 223.255.255.255 |
| Other / Reserved | All other IPv4 ranges |

The module does not drop, block, or modify packets. Every packet is accepted after inspection.

---

## 2. Files

The project is implemented inside:

```text
kernel/modules/

Main files:

snf_lkm.c   - Netfilter kernel module source code
Makefile    - Builds the kernel module and copies the .ko file to the shared VM folder
README.md   - Project documentation
3. Implementation Overview

The kernel module uses a Netfilter hook registered at:

NF_INET_LOCAL_OUT

This means the module inspects packets generated locally by the VM before they leave the network stack.

For every outgoing IPv4 packet, the module:

Checks that the packet buffer exists.
Ensures the IPv4 header is accessible.
Reads the IPv4 header using ip_hdr(skb).
Extracts the destination IP address from iph->daddr.
Converts the destination address from network byte order to host byte order.
Reads the first octet of the destination IP.
Classifies the destination as Class A, Class B, Class C, or Other / Reserved.
Logs the result with pr_info.
Returns NF_ACCEPT, allowing the packet to continue normally.
4. Classification Logic

The classification is based on the first octet of the destination IPv4 address:

if (first_octet >= 1 && first_octet <= 126)
        return "Class A";

if (first_octet >= 128 && first_octet <= 191)
        return "Class B";

if (first_octet >= 192 && first_octet <= 223)
        return "Class C";

return "Other / Reserved";

This satisfies the Basic Level requirement: identify packets by destination class.

5. Build Instructions

From the module directory:

cd /opt/kernel-playground/kernel/modules
make

The Makefile builds the kernel module using the kernel source tree linked as:

kernel/modules/linux -> ../linux/

After compilation, the module file is created:

snf_lkm.ko

The Makefile also copies the compiled module to the shared VM folder:

kernel/modules/shared

This makes the module available inside the test VM.

6. Load the Module Inside the VM

Inside the VM, load the compiled module:

insmod /mnt/shared/snf_lkm.ko

Expected kernel log:

M6 Basic: Destination IP Classifier loaded

Note:

loading out-of-tree module taints kernel

This message is normal for a custom kernel module built outside the official Linux kernel tree.

7. Generate Test Traffic

The module uses the NF_INET_LOCAL_OUT hook, so locally generated outgoing packets are enough for testing.

Run:

dmesg -C

ping -c 1 8.8.8.8
ping -c 1 172.217.16.14
ping -c 1 192.168.1.1

These destinations were selected to test three different IPv4 classes:

Test destination	Expected class
8.8.8.8	Class A
172.217.16.14	Class B
192.168.1.1	Class C

A ping reply is not required for the test to be valid. The important part is that an outgoing packet is generated and inspected by the Netfilter hook.

8. Check the Kernel Log

After running the test pings:

dmesg | grep "M6 Basic"

Observed output:

M6 Basic: destination 8.8.8.8 classified as Class A
M6 Basic: destination 172.217.16.14 classified as Class B
M6 Basic: destination 192.168.1.1 classified as Class C

This confirms that the module correctly extracts destination IPv4 addresses and classifies them.

9. Unload the Module

To remove the module:

rmmod snf_lkm
dmesg | tail -n 10

Expected output:

M6 Basic: Destination IP Classifier unloaded

This confirms that the Netfilter hook was unregistered correctly.

10. Result

The Basic Level implementation works correctly.

The module successfully:

loads into the kernel;
registers a Netfilter hook;
intercepts locally generated outgoing IPv4 packets;
extracts the destination IP address;
classifies destination IPs as Class A, Class B, or Class C;
logs the classification result to dmesg;
accepts all packets without modifying or dropping them;
unloads cleanly.
11. Limitations

This implementation intentionally focuses only on the Basic Level.

It does not implement:

per-class counters;
/proc or user-space statistics;
IPv6 prefix classification;
traffic shaping;
packet dropping.

These features belong to the Intermediate or Advanced levels and were not required for this submission.

12. Final Summary
Outgoing packet generated
↓
Netfilter LOCAL_OUT hook receives packet
↓
IPv4 header is extracted
↓
Destination IP address is read
↓
First octet is checked
↓
Destination is classified as Class A / B / C / Other
↓
Result is written to dmesg
↓
Packet is accepted with NF_ACCEPT

