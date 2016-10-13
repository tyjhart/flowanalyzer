# **Tuning**

The following information and options are here to help you tune the Flow Analyzer to perform in your networks. It's recommended you make incremental
changes, just in case something get set incorrectly, so troubleshooting will be easier.

### **Time Zone**

The Ubuntu Server's timezone is set to UTC during the install, and all events are logged into Elasticsearch with UTC timestamps.
This is for Elasticsearch purposes, and to ensure that it's possible to correlate flow data from devices across time zones and
DST implementations. Changing the timezone to something other than UTC isn't supported.

Kibana adjusts for local time automatically, so you don't have to do anything to see events with usable timestamps.

### **Files**

The master configuration file is **netflow_options.py**, and contains all the configurable options for the system. 
As part of the initial configuration it is copied from netflow_options_example.py. 

It already has the basic, typical settings in place, including the ports listed above and the settings that follow.

### **Services**

Service names correspond to their respective protocols:

- netflow_v5
- netflow_v9
- ipfix

You can view the status of the services listed above and control their operations by running the following:

```
systemctl status netflow_v5
systemctl start netflow_v9
systemctl stop ipfix
systemctl restart netflow_v5
```

### **Elasticsearch Connection**

By default the flow collector services are configured to connect to an Elasticsearch instance running on locahost.
The setting can be found in **netflow_options.py**, as shown below:

```
elasticsearch_host = '127.0.0.1'
```

If you already have an existing Elasticsearch cluster running you can change this setting, using either an IP address or FQDN.
You will be responsible for creating the Flow index on your own cluster, and the curl command to build the index can be found in the 
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

# ---
**Copyright (c) 2016, Manito Networks, LLC**
**All rights reserved.**