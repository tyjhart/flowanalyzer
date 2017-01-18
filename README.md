# Manito Networks Flow Analyzer
The Flow Analyzer is a [Netflow, IPFIX](Network%20Flow%20Basics.md), and [sFlow](sFlow.md) collector and parser, available under the [BSD 3-Clause License](#license), that stores flows in Elasticsearch and visualizes them in Kibana. It is designed to run on [Ubuntu Server](https://www.ubuntu.com/download/server), either as a single installation or as part of an Elasticsearch cluster. 

Visualizations and Dashboards are provided to support network flow analysis right out of the box.

See the [License section](#license) below for licensing details.

1. [Project Goals](#project-goals)
2. [Features](#features)
    * [Quick Installation](#quick-installation)
    * [Broad Protocol Support](#broad-protocol-support)
    * [Industry-Standard Fields](#industry-standard-fields)
    * [Service and Protocol Tagging](#service-and-protocol-tagging)
    * [DNS Reverse Lookups](#dns-reverse-lookups)
    * [MAC Address Correlation](#mac-address-correlation)
3. [Requirements](#requirements)
4. [Installation](#installation)
5. [Ports and Protocols](#ports-and-protocols)
6. [Data Access](#access)
7. [Limitations](#limitations)
8. [Debugging](#debugging)
9. [Contributing](#contributing)
10. [License](#license)
11. [Attributions](#attributions)

# Project Goals
Our goal is to provide superior Netflow and IPFIX collection, visualization, and analysis. We do that by creating:

- Efficient, accessible, and sustainable software
- Scalable solutions that can evolve as you grow
- Superior documentation from architecture through installation, configuration, tuning, and troubleshooting

One other goal is to make Elasticsearch and Kibana easy to implement and accessible to those who haven't used it before. The learning curve for distributed search systems and dashboarding software can be steap, but we think that everyone
should be able to realize the benefits of meaningful, beautiful data visualization.

# Features
The Flow Analyzer has the flow collection, tagging, and categorizing capabilities to satisfy enterprise and service provider requirements.

## Quick Installation
Go from zero to visualized flow data in less than one hour. See [the installation documentation](Install/README.md) for easy to follow step-by-step instructions.

## Broad Protocol Support
The Manito Networks Flow Analyzer supports the following flow data protocols:

- Netflow v5 (Cisco)
- Netflow v9 (Cisco)
- IPFIX (IEEE, aka Netflow v10)
- sFlow (InMon Corporation)
- Traffic Flow (Mikrotik, Netflow-equivalent)
- Netstream (Huawei Technologies, Netflow-equivalent)

If you're not familiar with Netflow or IPFIX take a look at the [Introduction to Netflow and IPFIX](Netflow.md). For information on sFlow and supported sFlow structures see the [Flow Analyzer sFlow document](sFlow.md). Our software collects Netflow, IPFIX, and sFlow data and then parses and tags it. The parsed and tagged data is stored in Elasticsearch for you to query and graph in Kibana.

## Industry-Standard Fields
The Flow Analyzer supports all Netflow v5 fields, non-proprietary Netflow v9 fields, IPFIX fields specified in the RFC, and almost all sFlow structures defined by InMon Corporation's enterprise ID. See the [Fields document](Fields.md) for a description of Netflow (v5, v9) and IPFIX fields. The [sFlow document](sFlow.md) includes descriptions of supported Flow and Counter structures.

Kibana Visualizations and Dashboards are included so you can leverage supported fields and structures right away. 

Some limitations exist, mostly around proprietary or undocumented fields in Netflow and proprietary structures in sFlow. See the [Limitations](#limitations) section for details. Efforts are made to skip over unsupported or proprietary elements and continue parsing data uninterrupted.

## Service and Protocol Tagging
Our custom Netflow, IPFIX, and sFlow collectors ingest, parse, and tag flow data. We record not only the basic protocol and port numbers but we also take it a step further and correlate the following:

- IANA protocol numbers to names (eg protocol 1 to "ICMP", 6 to "TCP", 89 to "OSPF")
- IANA-registered port numbers to services (eg port 80 to "HTTP", 53 to "DNS")
- Services to categories (eg HTTP, HTTPS, Alt-HTTP to "Web")

This tagging functionality is running by default and happens transparently in the background. For more information on tagging functionality see the [Tagging documentation](Tagging.md).

## DNS Reverse Lookups
A reverse lookup against observed IPs is done if DNS lookups are enabled. Resolved domains are cached for 30 minutes to reduce
the impact on DNS servers. Popular domains like facebook.com and cnn.com are categorized with content tags like "Social Media" and "News" to provide insight into website browsing on the network.

## MAC Address Correlation
Correlation of MAC address OUI's to top manufacturers is done to help graph traffic sources in hetergenous environments. 

Note: This feature is in beta, and the list of OUI's to be built is quite extensive.

# Requirements
See the [Requirements documentation](Requirements.md) for information on RAM, CPU, storage, and operating system requirements.

# Installation
Clone the Git repo, run the installation script, and import the pre-built Kibana objects. See the [installation documentation](Install/README.md) for more information.

# Ports and Protocols
All services listen for UDP flow packets on the following default ports:

Service     | Protocol  | Default Port  | Purpose                                   |
---         | ---       | ---           | ---                                       |
Netflow v5  | UDP       | 2055          | Basic flow monitoring                     |
Netflow v9  | UDP       | 9995          | Intermediate flow monitoring              |
IPFIX       | UDP       | 4739          | Advanced flow monitoring                  |
sFlow       | UDP       | 6343          | Advanced flow and performance monitoring  |

# Data Access
Access your flow data however you want - Kibana dashboards, Elasticsearch JSON-formatted queries, or curl HTTP requests. Access to Kibana can be restricted using Squid via a reverse proxy and the directions for setting that up are included.

See the [installation documentation](Install/README.md#kibana-authentication-optional) for more information.

# Limitations
The following protocols, vendor features, or vendor-proprietary functions are **NOT** supported by the Flow Analyzer project.

## Vendor Features and Protocols
These technologies may use a supported protocol for transport but there are proprietary fields, codes, or structures in use. Some protocols may require parsing that is undocumented or proprietary to the vendor.
- [Cisco ASA Netflow Security Event Logging (NESL)](http://www.cisco.com/c/en/us/td/docs/security/asa/asa82/configuration/guide/config/monitor_nsel.html#wp1111174)
- Cisco NAT Event Logging (NEL)
- [Cisco Streaming Telemetry](http://blogs.cisco.com/sp/streaming-telemetry-with-google-protocol-buffers)

## Protocol Limitations
- Netflow v5 does not support IPv6.

# Debugging
If you run into any issues during or after installation check out the [Debugging page](Debug.md) for helpful commands and debugging options.

# Contributing
We encourage people who use the Flow Analyzer to contribute to the project if they find a bug or documentation issue, or want to see a feature added. See the [Contributing page](CONTRIBUTING.md) for more information about contributing code to the project. Interactions between participants should be within the bounds of the [Code of Conduct](Code%20of%20Conduct.md).

# License
Copyright (c) 2016, Manito Networks, LLC
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# Attributions
Trademark, copyright, and license disclosures below:
* "_Elasticsearch_" and "_Kibana_" are registered trademarks of Elasticsearch BV.
* "_Elasticsearch_" and "_Kibana_" are distributed under the Apache 2 license by Elasticsearch BV.
* "_Ubuntu_" is a registered trademark of Canonical Ltd.
* "_sFlow_" is a registered trademark of InMon Corporation.
* "_Cisco_" is a registered trademark of Cisco Systems, Inc.
* "_Mikrotik_" is a trademark of Mikrotikls SIA.
* "_Huawei_" is a trademark of Huawei Technologies Co., Ltd.
* "_NVIDIA_" is a trademark of NVIDIA Corporation.
* "_Broadcom_" is a trademark of AVAGO TECHNOLOGIES GENERAL IP (SINGAPORE) PTE. LTD.

# ---
**Copyright (c) 2017, Manito Networks, LLC**
**All rights reserved.**