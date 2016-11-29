# Manito Networks Flow Analyzer
The Flow Analyzer is a [Netflow, IPFIX](Network%20Flow%20Basics.md), and [sFlow](sFlow.md) collector and parser, available under the [BSD 3-Clause License](#license), 
that stores flows in Elasticsearch and visualizes them in Kibana. It is designed to run on [Ubuntu Server](https://www.ubuntu.com/download/server), either as a single 
installation or as part of an Elasticsearch cluster. 

Visualizations and Dashboards are provided to support network flow analysis right out of the box.

See the [License section](#license) below for licensing details.

1. [Project Goals](#project-goals)
2. [Features](#features)
    1. [Quick Installation](#quick-installation)
    2. [Flow Monitoring Protocols](#flow-monitoring-protocols)
    3. [Fields](#fields)
    4. [Tags](#tags)
    5. [DNS Reverse Lookups](#dns-reverse-lookups)
    6. [MAC Address Lookups](#mac-address-lookups)
    7. [Development Roadmap](#development-roadmap)
3. [Requirements](#requirements)
    1. [RAM and CPU](#ram-and-cpu)
    2. [Storage](#storage)
    3. [Operating System](#operating-system)
    4. [Elasticsearch Nodes](#elasticsearch-nodes)
4. [Installation](#installation)
5. [Device Configuration](#device-configuration)
6. [Ports and Protocols](#ports-and-protocols)
7. [Access](#access)
8. [Limitations](#limitations)
9. [Debugging](#debugging)
10. [Contributing](#contributing)
11. [License](#license)
12. [Attributions](#attributions)

# Project Goals
Our goal is to provide superior Netflow and IPFIX collection, visualization, and analysis. We do that by creating:

- Efficient, accessible, and sustainable software
- Scalable solutions that can evolve as you grow
- Superior documentation from architecture through installation, configuration, tuning, and troubleshooting

One other goal of ours is to make Elasticsearch and Kibana easy to implement and accessible to those who haven't used it before. The learning curve for distributed search systems and dashboarding software can be steap, but we think that everyone
should be able to realize the benefits of meaningful, beautiful data visualization.

# Features

### Quick Installation
You can go from zero to up-and-running with graphed flow data in less than one hour. Check out [the installation documentation](Install/README.md).

### Flow Monitoring Protocols
The Manito Networks Flow Analyzer supports the following flow data protocols:

- Netflow v5 (Cisco)
- Netflow v9 (Cisco)
- IPFIX (IEEE, aka Netflow v10)
- sFlow (InMon Corporation)
- Traffic Flow (Mikrotik, Netflow-equivalent)
- Netstream (Huawei Technologies, Netflow-equivalent)

If you're not familiar with Netflow or IPFIX that's alright - take a look at [Network Flow Basics](Network%20Flow%20Basics.md). For a description of sFlow and supported sFlow structures see the [Flow Analyzer sFlow document](sFlow.md).

Our software ingests Netflow (and Netflow-equivalents), IPFIX, and sFlow data then parses and tags it, and stores it in Elasticsearch for you to query and graph in Kibana.

### Fields
The Flow Analyzer supports all defined Netflow v5 fields, all standard Netflow v9 fields, all IPFIX fields in the RFC, and almost all sFlow structures defined by InMon Corporation's enterprise ID. See the [Network Flow Basics document](Network%20Flow%20Basics.md) for a description of Netflow and IPFIX fields, and the [sFlow document](sFlow.md) for a description of supported structures.

Kibana Visualizations and Dashboards are included so you can leverage supported fields and structures right away. 

Some limitations exist, mostly around proprietary or undocumented fields in Netflow or proprietary structures in sFlow - see the [Limitations](#limitations) section for details. Efforts are made to skip over unsupported or proprietary elements and continue parsing data uninterrupted.

### Tags
Our custom Netflow, IPFIX, and sFlow collectors ingest and tag flow data. We record not only the basic protocol and port numbers, but we also take it a step further and correlate the following:

- Protocol numbers to protocol names (eg protocol 1 to "ICMP", 6 to "TCP")
- IANA-registered port numbers to services (eg port 80 to "HTTP", 53 to "DNS")
- Services to categories (eg HTTP, HTTPS, Alt-HTTP to "Web")

This tagging functionality is running by default and happens transparently in the background.

### DNS Reverse Lookups
A reverse lookup against observed IPs is done if DNS lookups are enabled. Resolved domains are cached for 30 minutes to reduce
the impact on DNS servers. Popular domains like facebook.com and cnn.com are categorized with content tags like "Social Media" and "News" to provide insight into website browsing on the network.

### MAC Address Lookups
Correlation of MAC address OUI's to top manufacturers is done to help graph traffic sources in hetergenous environments. 

Note: This feature is in beta, and the list of OUI's to be built is quite extensive.

### Development Roadmap
See the [Roadmap file](ROADMAP.md) for information on upcoming features and current development efforts.

# Requirements
At least one Ubuntu Server installation with the following **minimum** hardware specs:

### RAM and CPU
- 4GB RAM
- 2 CPU Cores

### Storage
A **minimum** of 20GB HDD space is recommended for testing the appliance, but long-term storage requirements will vary depending on a number of factors. The following should be considered when provisioning storage space and additional Elasticsearch nodes:

- Flow data retenion (default 30 days)
- Number of flow exporters (routers, switches, etc)
- Sampling rate for protocols like Netflow v9 and IPFIX
- Average network flow volume over time
- Peak network flow volume and duration

Every network is different, so it's difficult to give a hard-and-fast suggestion on the right amount of storage for your organization over the long-term. It's recommended that you start small with a couple collectors, determine your average daily index size, then scale up from there.

### Operating System
The following versions of Ubuntu Server have been tested and verified to work with the [installation](./Install/README.md) script:

- 16.04 LTS
- 16.10

**Note**: The installation script is incompatible with Ubuntu versions prior to 15.04 due to the move to SystemD.

### Elasticsearch Nodes
By default the installation script assumes you're using only one node for the collectors, Elasticsearch, and Kibana. The configuration options are included by the installation script for working in a multi-node cluster but they are commented out. This is fine for proof-of-concept or fairly small networks with low retention requirements, but it will not scale beyond a certain point. 

Additional Elasticsearch nodes will greatly increase performance and reliability in case of node failure. As your flow volume, data retention, and failover needs increase you can tune the amount of Elasticsearch shards and replicas to meet your needs.

# Installation
Install by cloning the latest Git repo, then run the Ubuntu installation script.

See the [installation documentation](Install/README.md) for more information.

# Device Configuration
Configure your devices to send Netflow and IPFIX data to the Flow Analyzer collector.

See the [Flow Management blog](http://www.manitonetworks.com/flow-management/) for more information on configuring your devices.

* [Ubiquiti IPFIX](http://www.manitonetworks.com/flow-management/2016/7/1/ubiquiti-ipfix-configuration)
* [Mikrotik Netflow v5](http://www.manitonetworks.com/flow-management/2016/7/1/mikrotik-netflow-configuration)
* [Mikrotik Netflow v9](http://www.manitonetworks.com/flow-management/2016/10/10/mikrotik-netflow-v9-configuration)
* [Cisco Netflow v9](http://www.cisco.com/c/en/us/td/docs/ios-xml/ios/netflow/configuration/15-mt/nf-15-mt-book/get-start-cfg-nflow.html#GUID-2B7E9519-66FE-4F43-B8D3-00CA38C1FA9A)

# Ports and Protocols
All services listen for UDP flow packets on the following ports:

Service     | Protocol  | Port  | Purpose                                   |
--          | --        | --    | --                                        |
Netflow v5  | UDP       | 2055  | Basic flow monitoring                     |
Netflow v9  | UDP       | 9995  | Intermediate flow monitoring              |
IPFIX       | UDP       | 4739  | Advanced flow monitoring                  |
sFlow       | UDP       | 6343  | Advanced flow and performance monitoring  |

These ports can be changed, see the [tuning documentation](Tuning.md).

# Access
You can access your flow data in a few different ways - graphically via Kibana, through Elasticsearch JSON-formatted queries, and via curl HTTP requests. Access to Kibana can optionally be restricted using Squid via a reverse proxy, and the directions for setting that up are included.

See the [installation documentation](Install/README.md#kibana-authentication-optional) for more information.

# Limitations
The following Netflow protocols or features are **NOT** supported by the Flow Analyzer project:

- [Cisco Flexible Netflow](http://www.cisco.com/c/en/us/products/ios-nx-os-software/flexible-netflow/index.html)
- [Cisco ASA Netflow Security Event Logging (NESL)](http://www.cisco.com/c/en/us/td/docs/security/asa/asa82/configuration/guide/config/monitor_nsel.html#wp1111174)
- Cisco NAT Event Logging (NEL)

These technologies may use Netflow as a transport protocol, but there are proprietary fields, codes, and structures in use that require additional parsing to handle.

# Debugging
If you run into any issues during or after installation check out the [Debugging page](Debug.md) for helpful commands and debugging options.

# Contributing
We encourage people who use the Flow Analyzer to contribute to the project if they find a bug or documentation issue, or want to see a feature added. See the [Contributing page](CONTRIBUTING.md) for more information about contributing code to the project.

# License
Copyright (c) 2016, Manito Networks, LLC
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# Attributions
"_Elasticsearch_" and "_Kibana_" are registered trademarks of Elasticsearch BV.

"_Elasticsearch_" and "_Kibana_" are distributed under the Apache 2 license by Elasticsearch BV.

"_Ubuntu_" is a registered trademark of Canonical Ltd.

_"sFlow"_ is a registered trademark of InMon Corporation.

"_Cisco_" is a registered trademark of Cisco Systems, Inc.

"_Mikrotik_" is a trademark of Mikrotikls SIA.

"_Huawei_" is a trademark of Huawei Technologies Co., Ltd.

"_NVIDIA_" is a trademark of NVIDIA Corporation.

# ---
**Copyright (c) 2016, Manito Networks, LLC**
**All rights reserved.**