# **Manito Networks Flow Analyzer**

The Flow Analyzer is a freely available Netflow and IPFIX collector and parser, that stores flows in Elasticsearch and graphs flow
data in Kibana. 

Visualizations and Dashboards are provided to support network flow analysis right out of the box.

See the License section below for licensing details.

# **Project Goals**

Our goal is to provide superior Netflow and IPFIX collection, visualization, and analysis. We'll do that by creating:

- Efficient, accessible, and sustainable software
- Scalable solutions that can evolve
- Superior documentation from architecture through installation, configuration, tuning, and troubleshooting

One other goal of ours is to make Elasticsearch and Kibana easy to implement and accessible to those who haven't used it before.
The learning curve for distributed search systems and dashboarding software can be steap, but we think that everyone
should be able to realize the benefits of meaningful, beautiful data visualization.

# **Features**

### **Protocols**

The Manito Networks Flow Analyzer supports the following flow data protocols:

- Netflow v5
- Netflow v9
- IPFIX (aka Netflow v10)

It ingests Netflow and IPFIX data, parses and tags it, then stores it in Elasticsearch for you to query and graph in Kibana.

### **Fields**

The Flow Analyzer supports over 60 pre-configured flow data fields, including the correct field types and analysis settings in 
Elasticsearch so you don't have to do any guessing. Kibana Visualizations and Dashboards are included, so you can analyze those 60+
fields right away. We also have dynamic support for other fields defined in the Netflow v5, v9, and IPFIX standards.

Take a look at [Fields.md](Fields.md) for a list of the pre-configured fields. 

### **Tags**

Our custom Netflow and IPFIX collectors ingest and tag flow data. We record not only the basic protocol and port numbers, but we 
also take it a step further and correlate the following:

- Protocol numbers to protocol names (eg protocol 1 to "ICMP", 6 to "TCP")
- IANA-registered port numbers to services (eg port 80 to "HTTP", 53 to "DNS")
- Services to categories (eg HTTP, HTTPS, Alt-HTTP to "Web")

This tagging functionality is running by default, and right now there is no functionality to turn it off.

### **DNS Reverse Lookups**

A reverse lookup against observed IPs is done if DNS lookups are enabled. Resolved domains are cached for 30 minutes to reduce
the impact on DNS servers. Popular domains like facebook.com and cnn.com are categorized to provide some insight into website
browsing on the network.

DNS reverse lookups are disabled by default due to their potential impact on DNS servers in high traffic environments.

They can be enabled by changing the following default option in **netflow_options.py** once it's copied 
in the [installation script](Install/ubuntu_install.sh):

```
dns = False
```

to

```
dns = True
```

If you have a local DNS server that can resolve internal addresses in the RFC-1918 range you can also change this default option:

```
lookup_internal = False
```

to

```
lookup_internal = True
```

### **MAC Address Lookups**

Correlation of MAC address OUI's to top manufacturer's is done to help graph traffic sources in hetergenous environments. 

Note: This feature is in beta, and the list of OUI's to be built is quite extensive.

# **Requirements**

At least one Ubuntu Server installation with the following **minimum** hardware specs:

- 4GB RAM
- 2 CPU Cores
- 90GB HDD space

Additional Elasticsearch nodes will greatly increase performance and reliability in case of node failure.

# **Access**

Access to Kibana is proxied through the Squid service. Putting Squid in front of Kibana allows us to restrict access to the
Kibana login page via an .htaccess file. The default login credentials are shown below:

The Kibana portal can be accessed via the following URL:

**http://your_server_ip**

Default Username: **admin**

Default Password: **manitonetworks**

Users can be created with the following command:

```
htpasswd -bc /opt/manitonetworks/squid/.htpasswd username password
```

# **Architecture**

The Flow Analyzer is designed to run on Ubuntu Server, either as a single installation or in an Elasticsearch cluster.

Three listeners written in Python 2.x run in the background as services, one for each of the supported flow standards. 
Should a service fail they are configured to restart automatically. If you're not using particular services you can disable them. 

### **Install Location**

Install by cloning the latest Git repo:

```
git clone https://gitlab.com/thart/flowanalyzer.git
```

### **Services**

Service names correspond to their respective protocols:

- netflow_v5
- netflow_v9
- ipfix

You can view the status of the services listed above and control their operations by running the following:

```
service service_name status
service service_name start
service service_name stop
service service_name restart
```

### **Ports & protocols**

All services listen for TCP flow packets on the following ports:

- Netflow v5:   TCP/2055
- Netflow v9:   TCP/9995
- IPFIX:        TCP/4739

These ports can be changed by editing /opt/manitonetworks/netflow_options.py and restarting the services shown above.

### **Time Zone**

The Ubuntu Server's timezone is set to UTC during the install, and all events are logged into Elasticsearch with UTC timestamps.
This is for Elasticsearch purposes, and to ensure that it's possible to correlate flow data from devices across time zones and
DST implementations.

Kibana corrects for local time automatically.

### **Files**

The master configuration file is **netflow_options.py**, 
and contains all the configurable options for the system. As part of the initial configuration you 
must copy netflow_options_example.py to netflow_options.py and make any changes you'd like. 

It already has the basic, typical settings in place, including the ports listed above.

# **Tuning**

### **Elasticsearch Connection**

By default the flow collector services are configured to connect to an Elasticsearch instance running on locahost.
The setting can be found in /opt/manitonetworks/flow/netflow_options.py, as shown below:

```
elasticsearch_host = '127.0.0.1'
```

If you already have an existing Elasticsearch cluster running you can change this setting, using either an IP address or FQDN.
You will be responsible for creating the Flow index on your own cluster, and the curl command can be found in the 
[build_index.sh file](Install/build_index.sh).

### **Elasticsearch Bulk Insert**

Depending on the traffic volume you're feeding to Flow Analyzer you may need to tune a couple settings to get the best
performance.

By default, the software is configured to do a bulk upload of flow data to Elasticsearch every 700 flows. For smaller organizations
it may take some time to fill up a 700 flow buffer, and so flows won't be observed in a timely fashion. 
For medium and large organizations it may only take a few moments to fill up a 700 flow buffer, 
and bulk uploads to Elasticsearch will happen too often to keep up. This setting can be changed in the 
/opt/manitonetworks/flow/netflow_options.py file by changing the following setting:

```
bulk_insert_count = 700
```

The following bulk_insert_count settings have been found to work, but each network is different and tuning is important:

- Small enterprises: 200
- Medium enterprises and small WISPs: 700
- Large enterprises and medium WISPs: 1000

For wired ISP's that are able to push more data, and other large enterprises the bulk_insert_count may need to go higher.
Performance for those larger organizations and ISPs will also depend on the performance of their Elasticsearch cluster.

# **Attributions**

Elasticsearch is a registered trademark of Elasticsearch BV.

Kibana is a registered trademark of Elasticsearch BV.

Elasticsearch and Kibana are distributed under the Apache 2 license by Elasticsearch BV.

Ubuntu is a trademark of Canonical Ltd.

# **Copyright**

All Python and configuration files, unless otherwise noted, are copyright 2016 Manito Networks, LLC.

All rights are reserved.

# **License**

This product is licensed for commercial and non-commercial use. This product, in whole or in part, may not be resold
or redistributed without the written permission of Manito Networks, LLC.