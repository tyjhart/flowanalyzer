# Frequently Asked Questions
Below are some frequently asked questions that we've seen on Reddit, social media, and other networking forums:

## What protocols are supported?
We support Netflow v5, Netflow v9, IPFIX (aka Netflow v10), and sFlow. See the [Ports and Protocols section](README.md#ports-and-protocols) of the README file.

## Do you support my particular Linux distribution?
Right now we support Ubuntu Server LTS, though we have done some development on CentOS. Canonical's Ubuntu has great support on Amazon AWS, Microsoft Azure, DigitalOcean, Linode, and others. VMware ESX, Microsoft Hyper-V, Oracle Virtualbox, and Citrix XenServer also have wonderful support for local virtual Ubuntu servers.

## Do you have a pre-configured VM image I can use?
No, we do not provide a pre-configured VM image. Providing a pre-built VM pulls us into the realm of system administration, OS security and patching, firewalling, and more. This is best left to your IT folks who know their networks  and security requirements best. This is especially true is you have legal and compliance requirements e.g. PCI-DSS, HIPAA, and SOX.

- Ubuntu Server in [Amazon's AWS Marketplace from Canonical](https://aws.amazon.com/marketplace/seller-profile?id=565feec9-3d43-413e-9760-c651546613f2)
- Install media for Ubuntu Server from Canonical's [Ubuntu Server download page](https://www.ubuntu.com/download/server).

**Note**: Only download installation media or server images from trusted vendor and developer sources.

## Do you offer professional support?
At the moment we do not, but we are in the process of exploring what it would take to provide that service at the level we expect of ourselves.