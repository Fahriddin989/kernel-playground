# M6 — Destination IP Classifier

**Project Level:** Basic Level  
**Project Type:** Netfilter Kernel Module  

## Overview

This repository contains the implementation of **M6 — Destination IP Classifier**.

The project implements a Linux Netfilter kernel module that intercepts outgoing IPv4 packets, extracts the destination IP address, classifies it as **Class A**, **Class B**, **Class C**, or **Other / Reserved**, and logs the result to the kernel log.

## Project Location

The implementation is located here:

[Open kernel/modules](kernel/modules)

Main documentation:

[Open M6 Kernel Module README](kernel/modules/README.md)

Source code:

[Open snf_lkm.c](kernel/modules/snf_lkm.c)

## Full Report

The full project report is available in Google Docs:

[Open Google Docs Report](https://docs.google.com/document/d/1mwlUEQVuf8IwidXlVop9z_LoAWBrVQgimKinhN57p-w/edit?usp=sharing)

## Basic Test Result

The module was tested with the following destination IP addresses:

| Destination IP | Expected class |
|---|---|
| 8.8.8.8 | Class A |
| 172.217.16.14 | Class B |
| 192.168.1.1 | Class C |

Observed kernel log:

```text
M6 Basic: destination 8.8.8.8 classified as Class A
M6 Basic: destination 172.217.16.14 classified as Class B
M6 Basic: destination 192.168.1.1 classified as Class C
