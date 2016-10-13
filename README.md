# **Manito Networks Flow Analyzer**

The Flow Analyzer is a [Netflow and IPFIX](Network%20Flow%20Basics.md) collector and parser, available under the [BSD 3-Clause License](#license), 
that stores flows in Elasticsearch and visualizes them in Kibana. It is designed to run on [Ubuntu Server](https://www.ubuntu.com/download/server), either as a single 
installation or as part of an Elasticsearch cluster. 

Visualizations and Dashboards are provided to support network flow analysis right out of the box.

See the [License section](#license) below for licensing details.

# **Project Goals**

Our goal is to provide superior Netflow and IPFIX collection, visualization, and analysis. We do that by creating:

- Efficient, accessible, and sustainable software
- Scalable solutions that can evolve
- Superior documentation from architecture through installation, configuration, tuning, and troubleshooting

One other goal of ours is to make Elasticsearch and Kibana easy to implement and accessible to those who haven't used it before.
The learning curve for distributed search systems and dashboarding software can be steap, but we think that everyone
should be able to realize the benefits of meaningful, beautiful data visualization.

# **Features**

### **Quick Installation**

You can go from zero to up-and-running with graphed flow data in less than one hour. Check out [the installation documentation](Install/README.md).

### **Flow Monitoring Protocols**

The Manito Networks Flow Analyzer supports the following flow data protocols:

- Netflow v5
- Netflow v9
- IPFIX (aka Netflow v10)

If you're not familiar with Netflow or IPFIX that's alright - take a look at [Network Flow Basics](Network%20Flow%20Basics.md).

Our software ingests Netflow and IPFIX data, parses and tags it, then stores it in Elasticsearch for you to query and graph in Kibana.

### **Fields**

The Flow Analyzer supports over 60 pre-configured flow data fields, including the correct field types and analysis settings in 
Elasticsearch so you don't have to do any guessing. Kibana Visualizations and Dashboards are included, so you can analyze those 60+
fields right away. We also have dynamic support for other fields defined in the Netflow v5, v9, and IPFIX standards.

Take a look at [the Fields list](Fields.md) for a list of the pre-configured fields. 

### **Tags**

Our custom Netflow and IPFIX collectors ingest and tag flow data. We record not only the basic protocol and port numbers, but we 
also take it a step further and correlate the following:

- Protocol numbers to protocol names (eg protocol 1 to "ICMP", 6 to "TCP")
- IANA-registered port numbers to services (eg port 80 to "HTTP", 53 to "DNS")
- Services to categories (eg HTTP, HTTPS, Alt-HTTP to "Web")

This tagging functionality is running by default, and right now there is no functionality to turn it off.

### **DNS Reverse Lookups**

A reverse lookup against observed IPs is done if DNS lookups are enabled. Resolved domains are cached for 30 minutes to reduce
the impact on DNS servers. Popular domains like facebook.com and cnn.com are categorized with content tags like "Social Media" and "News"
to provide insight into website browsing on the network.

### **MAC Address Lookups**

Correlation of MAC address OUI's to top manufacturer's is done to help graph traffic sources in hetergenous environments. 

Note: This feature is in beta, and the list of OUI's to be built is quite extensive.

# **Requirements**

At least one Ubuntu Server installation with the following **minimum** hardware specs:

- 4GB RAM
- 2 CPU Cores
- 90GB HDD space

This will work for a proof of concept installation or for very small networks.
Additional Elasticsearch nodes will greatly increase performance and reliability in case of node failure.

# **Installation**

Install by cloning the latest Git repo, then run the Ubuntu installation script.

See [installation documentation](Install/README.md) for more information.

# **Device Configuration**

Configure your devices to send Netflow and IPFIX data to the Flow Analyzer collector.

See the [Flow Management blog](http://www.manitonetworks.com/flow-management/) for more information on configuring your devices.

* [Ubiquiti IPFIX](http://www.manitonetworks.com/flow-management/2016/7/1/ubiquiti-ipfix-configuration)
* [Mikrotik Netflow v5](http://www.manitonetworks.com/flow-management/2016/7/1/mikrotik-netflow-configuration)
* [Mikrotik Netflow v9](http://www.manitonetworks.com/flow-management/2016/10/10/mikrotik-netflow-v9-configuration)
* [Cisco Netflow v9](http://www.cisco.com/c/en/us/td/docs/ios-xml/ios/netflow/configuration/15-mt/nf-15-mt-book/get-start-cfg-nflow.html#GUID-2B7E9519-66FE-4F43-B8D3-00CA38C1FA9A)

# **Ports & protocols**

All services listen for UDP flow packets on the following ports:

- Netflow v5:   UDP/2055
- Netflow v9:   UDP/9995
- IPFIX:        UDP/4739

These ports can be changed, see the [tuning documentation](Tuning.md).

# **Access**

Access to Kibana is proxied through the Squid service. Putting Squid in front of Kibana allows us to restrict access to the
Kibana login page via an .htaccess file. The default login credentials are shown below:

The Kibana portal can be accessed via your favorite modern web browser:

**http://your_server_ip**

Default Username: **admin**

Default Password: **manitonetworks**

# **License**

Copyright (c) 2016, Manito Networks, LLC
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# **Attributions**

Elasticsearch is a registered trademark of Elasticsearch BV.

Kibana is a registered trademark of Elasticsearch BV.

Elasticsearch and Kibana are distributed under the Apache 2 license by Elasticsearch BV.

Ubuntu is a trademark of Canonical Ltd.

# ---
**Copyright (c) 2016, Manito Networks, LLC**
**All rights reserved.**