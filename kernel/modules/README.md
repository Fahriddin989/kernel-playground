# M6 — Destination IP Classifier (Kernel Module)

**Project Level:** Basic  
**Project Type:** Netfilter Linux Kernel Module

## Overview

This project implements the **Basic level** of **M6 — Destination IP Classifier**.

The module attaches to a Netfilter hook, inspects **outgoing IPv4 packets**, extracts the destination IP, classifies it by address class, and writes the result to kernel logs.

> ✅ The module is **passive**: it does **not** block, drop, or modify traffic.

---

## Project Structure

Path: `kernel/modules/`

| File | Description |
|---|---|
| `snf_lkm.c` | Netfilter kernel module source |
| `Makefile` | Builds the kernel module |
| `README.md` | Project documentation |

---

## How It Works

The module registers a hook at `NF_INET_LOCAL_OUT`, which sees packets generated locally before they leave the host.

For each packet, it:

1. Verifies that `skb` is valid.
2. Verifies that the IPv4 header is accessible.
3. Reads the header via `ip_hdr(skb)`.
4. Extracts destination IP from `iph->daddr`.
5. Converts address from network byte order to host byte order.
6. Reads the first octet.
7. Classifies IP as Class A/B/C or Other/Reserved.
8. Logs the result using `pr_info`.
9. Returns `NF_ACCEPT`.

---

## IPv4 Classification Rules

Classification is based on the **first octet** of the destination IPv4 address:

| Class | First octet | Example |
|---|---|---|
| Class A | `1–126` | `8.8.8.8` |
| Class B | `128–191` | `172.217.16.14` |
| Class C | `192–223` | `192.168.1.1` |
| Other / Reserved | everything else | `127.x.x.x`, `224.x.x.x` |

```c
if (first_octet >= 1 && first_octet <= 126)
    return "Class A";

if (first_octet >= 128 && first_octet <= 191)
    return "Class B";

if (first_octet >= 192 && first_octet <= 223)
    return "Class C";

return "Other / Reserved";
```

---

## Build

From repository root:

```bash
cd kernel/modules
make
```

Build output:

- `snf_lkm.ko`

The `Makefile` also copies the compiled module to the shared VM folder.

---

## Load Module (inside VM)

```bash
insmod /mnt/shared/snf_lkm.ko
```

Expected kernel log:

```text
M6 Basic: Destination IP Classifier loaded
```

Possible extra message:

```text
loading out-of-tree module taints kernel
```

This is normal for modules built outside the official kernel tree.

---

## Generate Test Traffic

Optional: clear old logs first:

```bash
dmesg -C
```

Send outgoing IPv4 packets:

```bash
ping -c 1 8.8.8.8
ping -c 1 172.217.16.14
ping -c 1 192.168.1.1
```

> Note: successful ping replies are not required.  
> The goal is only to generate outgoing packets for `NF_INET_LOCAL_OUT`.

---

## Verify Logs

```bash
dmesg | grep "M6 Basic"
```

Expected sample output:

```text
M6 Basic: destination 8.8.8.8 classified as Class A
M6 Basic: destination 172.217.16.14 classified as Class B
M6 Basic: destination 192.168.1.1 classified as Class C
```

---

## Unload Module

```bash
rmmod snf_lkm
```

Check recent logs:

```bash
dmesg | tail -n 10
```

Expected message:

```text
M6 Basic: Destination IP Classifier unloaded
```

---

## Result

Basic-level implementation is complete and working.

Implemented features:

- module loads successfully;
- Netfilter hook registration;
- outgoing IPv4 interception;
- destination IP extraction;
- destination class detection (A/B/C/Other);
- kernel logging via `dmesg`;
- `NF_ACCEPT` for all packets;
- clean module unload.

---

## Limitations (Basic Level Scope)

Not implemented in this level:

- per-class packet counters;
- `/proc` statistics;
- IPv6 prefix classification;
- traffic shaping;
- packet dropping.

These belong to intermediate/advanced stages.

---

## Full Report

📊 **[Google Docs Report](https://docs.google.com/document/d/1mwlUEQVuf8IwidXlVop9z_LoAWBrVQgimKinhN57p-w/edit?usp=sharing)**

## Packet Flow

```text
Outgoing packet generated
        ↓
NF_INET_LOCAL_OUT hook receives packet
        ↓
IPv4 header is validated
        ↓
Destination IP is extracted
        ↓
First octet is read
        ↓
Class is selected
        ↓
Result is logged to dmesg
        ↓
Packet is accepted (NF_ACCEPT)
```
