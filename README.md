# Kernel Playground — M3 HTTP Packet Logger Delivery

## M3 Project Documentation

This fork contains my Software Networks M3 project:

**M3 HTTP Packet Logger and Blacklist Kernel Module**

The implementation is an out-of-tree Linux kernel module that detects IPv4 TCP HTTP traffic on port 80 using the Linux Netfilter subsystem. It logs accepted HTTP connections and supports a runtime source-IP blacklist through `/proc/snf_blacklist`. HTTP traffic from a blacklisted source IP is dropped inside the kernel module.

Main implementation file:

```text
kernel/modules/snf_lkm.c
```

Project documentation:

* [Full M3 documentation](docs/m3-http-packet-logger.md)
* [Results and evidence](docs/m3-http-packet-logger.md#results-and-evidence)
* [Reproduction steps](docs/m3-http-packet-logger.md#reproduction-steps)
* [Development and design notes](docs/m3-http-packet-logger.md#design-and-development-notes)
* [Safety and isolation](docs/m3-http-packet-logger.md#safety-and-isolation)

