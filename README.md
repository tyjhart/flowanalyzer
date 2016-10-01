# **Manito Networks Flow Analyzer**

The Flow Analyzer is a freely available Netflow and IPFIX collector and parser, that stores flows in Elasticsearch and graphs flow
data in Kibana. 

Visualizations and Dashboards are provided to support network flow analysis right out of the box.

See the **Licensing** section below for licensing details.

## **Features**

The Manito Networks Flow Analyzer supports the following:

- Netflow v5
- Netflow v9
- IPFIX (aka Netflow v10)

It ingests Netflow and IPFIX data, parses and tags it, then stores it in Elasticsearch for you to query and graph in Kibana.

### Tags

Our custom Netflow and IPFIX collectors ingest and tag flow data. We record not only the basic protocol and port numbers, but we 
also take it a step further and correlate the following:

- Protocol numbers to protocol names (eg protocol 1 to "ICMP", 6 to "TCP")
- IANA-registered port numbers to services (eg port 80 to "HTTP", 53 to "DNS")
- Services to categories (eg HTTP, HTTPS, Alt-HTTP to "Web")

### DNS Reverse Lookups

A reverse lookup against observed IPs is done if DNS lookups are enabled. Resolved domains are cached for 30 minutes to reduce
the impact on DNS servers. Popular domains like facebook.com and cnn.com are categorized to provide some insight into website
browsing on the network.

### MAC Address Lookups

Correlation of MAC address OUI's to top manufacturer's is done to help graph traffic sources in hetergenous environments. 

Note: This feature is in beta, and the list of OUI's to be built is extensive.

## **Access**

Access to Kibana is proxied through the Squid service. Putting Squid in front of Kibana allows us to restrict access to the
Kibana login page via an .htaccess file. The default login credentials are shown below:

Username: **admin**

Password: **manitonetworks**

Users can be created with the following command:

```
htpasswd -bc /opt/manitonetworks/squid/.htpasswd username password
```

## **Architecture**

The Flow Analyzer is designed to run on Ubuntu Server, either as a single installation or in an Elasticsearch cluster.

Three listeners written in Python 2.x run in the background as services, one for each of the supported flow standards. 
Should a service fail they are configured to restart automatically. If you're not using particular services you can disable them. 

### Install Location

Flow Analyzer files and configurations are installed in the following directories:

- /opt/manitonetworks/flow
- /opt/manitonetworks/kibana
- /opt/manitonetworks/squid

### Services

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

### Ports & protocols

All services listen for TCP flow packets on the following ports:

- Netflow v5:   TCP/2055
- Netflow v9:   TCP/9995
- IPFIX:        TCP/4739

These ports can be changed by editing netflow_options.py and restarting the services shown above.

### Files

The master configuration file is **/opt/manitonetworks/flow/netflow_options.py**, 
and contains all the configurable options for the system. As part of the initial configuration you 
must copy netflow_options_example.py to netflow_options.py and make any changes you'd like. 

It already has the basic, typical settings in place, including the ports listed above.

## **Attributions**

Elasticsearch is a registered trademark of Elasticsearch BV.

Kibana is a registered trademark of Elasticsearch BV.

Elasticsearch and Kibana are distributed under the Apache 2 license by Elasticsearch BV.

Ubuntu is a trademark of Canonical Ltd.

## **Copyright**

All Python and configuration files, unless otherwise noted, are copyright 2016 Manito Networks, LLC.

All rights are reserved.