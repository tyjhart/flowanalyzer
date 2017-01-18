# FAQ
1. [Protocols](#protocols)
    - [Supported Protocols](#supported-protocols)
    - [Missing Templates](#missing-templates)
    - [IPFIX Sequence Numbers](#ipfix-sequence-numbers)
2. [Linux](#linux)
    - [Distributions](#distributions)
    - [VM Image](#vm-image)
3. [Support](#support)

# Protocols 
Questions we get frequently about protocols and overall protocol behavior:

## Suported Protocols
### What protocols are supported?
We support Netflow v5, Netflow v9, IPFIX (aka Netflow v10), and sFlow. See the [Ports and Protocols section](README.md#ports-and-protocols) of the README file.

## Missing Templates
### I see a message "_Missing template .... - DROPPING_" - what gives? 
Netflow v9 and IPFIX are template-based flow protocols. Your router, switch, or other device has to send a template to the collector that says what fields are in each flow record and what the sizes of those fields are. That template is then cached and used to decode the flow records. Some devices only send templates every _X_ amount of flows, or every _Y_ minutes. Some vendors allow you to configure those values, some don't. Once we get a matching template every record that comes after it will get decoded, parsed, and stored for you to analyze.

## IPFIX Sequence Numbers
### IPFIX sequence numbers are missing - where'd they go?
If you're getting output like this from the "_journalctl status ipfix_" command...
```
Missing template 258 from 192.168.88.1, sequence 11456 - DROPPING
Missing template 258 from 192.168.88.1, sequence 11461 - DROPPING
Missing template 258 from 192.168.88.1, sequence 11476 - DROPPING
Missing template 258 from 192.168.88.1, sequence 11486 - DROPPING
Missing template 258 from 192.168.88.1, sequence 11491 - DROPPING
Missing template 258 from 192.168.88.1, sequence 11492 - DROPPING
```
...you're probably wondering where sequence numbers 11456-11461, 11461-11476, etc went.

IPFIX packets have a sequence number in the header, but then each flow record _INSIDE_ the packet has to be counted as a sequence, even though the record isn't explicitely given a sequence number. This is a lot different than Netflow v9, where each packet gets a sequence number, and that number is incremented for each packet. If we're missing templates, there's no way to parse those records, and those sequences get dropped. Once a template is received they will be parsed normally.

# Linux
Questions we get frequently about Linux and overall operating system support:

## Distributions
### Do you support my particular Linux distribution?
Right now we support Ubuntu Server LTS, though we have done some development on CentOS. Canonical's Ubuntu has great support on Amazon AWS, Microsoft Azure, DigitalOcean, Linode, and others. VMware ESX, Microsoft Hyper-V, Oracle Virtualbox, and Citrix XenServer also have wonderful support for local virtual Ubuntu servers.

## VM Image
### Do you have a pre-configured VM image I can use?
No, we do not provide a pre-configured VM image. Providing a pre-built VM pulls us into the realm of system administration, OS security and patching, firewalling, and more. This is best left to your IT folks who know their networks and security requirements best. This is especially true is you have legal and compliance requirements that apply e.g. PCI-DSS, FISMA, HIPAA, or SOX.

- Ubuntu Server in [Amazon's AWS Marketplace from Canonical](https://aws.amazon.com/marketplace/seller-profile?id=565feec9-3d43-413e-9760-c651546613f2)
- Install media for Ubuntu Server from Canonical's [Ubuntu Server download page](https://www.ubuntu.com/download/server).

**Note**: Only download installation media or server images from trusted vendor and developer sources.

# Support
Questions about support for the Manito Networks Flow Analyzer:

## Do you offer professional support?
At the moment we do not, but we are in the process of exploring what it would take to provide that service at the level we expect of ourselves.

# ---
**Copyright (c) 2017, Manito Networks, LLC**
**All rights reserved.**