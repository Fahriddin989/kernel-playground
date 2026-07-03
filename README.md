# M6 — Destination IP Classifier

**Project Level:** Basic Level  
**Project Type:** Netfilter Kernel Module  

## Overview

This repository contains the implementation of **M6 — Destination IP Classifier**.

The project implements a Linux Netfilter kernel module that intercepts outgoing IPv4 packets, extracts the destination IP address, classifies it as **Class A**, **Class B**, **Class C**, or **Other / Reserved**, and logs the result to the kernel log.

The implementation is located in:

```text
kernel/modules/
Documentation

The full technical documentation, build instructions, test commands, and experimental results are available here:

Open M6 Kernel Module README

Main Files
kernel/modules/snf_lkm.c   - Kernel module source code
kernel/modules/Makefile    - Kernel module build file
kernel/modules/README.md   - Full project documentation
Basic Test Result

The module was tested with the following destination IP addresses:

8.8.8.8        -> Class A
172.217.16.14  -> Class B
192.168.1.1    -> Class C

Observed kernel log:

M6 Basic: destination 8.8.8.8 classified as Class A
M6 Basic: destination 172.217.16.14 classified as Class B
M6 Basic: destination 192.168.1.1 classified as Class C

