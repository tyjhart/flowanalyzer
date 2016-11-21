# Overview

The installation is orchestrated with Git, Pip, and Bash scripting. The process should require no manual intervention on your part, as
long as you're running the latest stable LTS release of Ubuntu Server.

Right now Ubuntu Server 16.04 LTS is recommended.

# Minimum Requirements

Each instance should be installed on a fresh 64-bit [Ubuntu Server](https://www.ubuntu.com/download/server) machine with **systemd support**, and at least the minimum required resources as listed in the [main README document Requirements section](../README.md#requirements).

The installation script is incompatible with Ubuntu versions prior to 15.04 due to a shift to SystemD by Canonical. Earlier versions of Ubuntu can use SystemD with a fair amount of work, but the installation script isn't supported on non-SystemD platforms with workarounds implemented.

While installing everything on one server is good for proof-of-concept or testing, additional Elasticsearch nodes will greatly increase performance and provide failover. Having additional Elasticsearch nodes will also allow you to retain more flow data, and tune overall performance to your needs.

# Installation

1. [Installation](#installation)
    1. [Clone the Git Repository](#clone-the-git-repository)
    2. [Run the Installation Script](#installation-script)
    3. [Build Elasticsearch Flow Index](#build-the-elasticsearch-flow-index)
    4. [Elasticsearch Tuning](#elasticsearch-tuning)
    5. [Firewall (Optional)](#firewall-optional)
    6. [Kibana Authentication (Optional)](#kibana-authentication-optional)
    7. [Reboot](#reboot)
2. [Configure Devices](#configure-devices)
3. [Kibana](#kibana)
    1. [Access Kibana](#access-kibana)
    2. [Configure the Default Index Pattern](#configure-the-default-index-pattern)
    3. [Set Special Byte Fields](#set-special-byte-fields)
    4. [Import Kibana Visualizations and Dashboards](#import-kibana-visualizations-and-dashboards)
4. [Tuning](#tuning)
5. [Updates](#updates)
6. [Elasticsearch Clustering](#elasticsearch-clustering)

### Clone the Git Repository

If you don't have Git installed on your Ubuntu Server machine that's OK, just run the following:

```
sudo apt-get install git
```

Clone the Git repository:

```
git clone https://gitlab.com/thart/flowanalyzer.git
```

The download should only take a moment. Move into the repo directory:

```
cd flowanalyzer
```

### Installation Script

The ubuntu_install.sh script handles almost everything, just be sure to run it with sudo privileges:

```
sudo sh ./Install/ubuntu_install.sh
```

The ubuntu_install.sh script does the following:

- Shifts the Ubuntu Server to UTC time and configures an NTP client so timestamps are accurate
- Adds software repos for Elasticsearch and Kibana
- Updates software repos and keys
- Installs Elasticsearch pre-reqs (Curl, OpenJDK 8, etc)
- Installs Elasticsearch and Kibana
- Creates the following collector services for Netflow v5/v9 and IPFIX (aka Netflow v10):
  - netflow_v5
  - netflow_v9
  - ipfix
- Registers collector services and sets auto-start
- Creates an index pruning job (>30 days old) using Curator in /etc/cron.daily
- Installs Head plugin for Elasticsearch

### Build the Elasticsearch Flow Index

The build_index.sh script creates the default index for storing data in Elasticsearch:

```
sh ./Install/build_index.sh
```

### Elasticsearch Tuning

One of the biggest ways to destroy Elasticsearch performance is to not properly allocate the right sized heap. The creators of Elasticsearch recommend setting
Elasticsearch to use [50% of the available memory](https://www.elastic.co/guide/en/elasticsearch/guide/current/heap-sizing.html#_give_less_than_half_your_memory_to_lucene) 
on a given server, up to the 32GB limit. The configuration set in the installation script sets Elasticsearch memory to 2GB, assuming a server with at least 4GB of RAM. 

That's done by setting...

```
ES_HEAP_SIZE=2g
```

...in the **/etc/default/elasticsearch** configuration file.

If you have a server with more RAM then you need to adjust this value and reboot the server (or restart Elasticsearch and then the collector services).

### Firewall (Optional)

These are examples of commands you may need to use if you're running a firewall on the Ubuntu Server installation:

```
ufw allow from xxx.xxx.xxx.xxx/xx to any port 80 proto tcp comment "Kibana interface"
ufw allow from xxx.xxx.xxx.xxx/xx to any port 9200 proto tcp comment "Elasticsearch CLI"
ufw allow from xxx.xxx.xxx.xxx/xx to any port 2055,9995,4739 proto udp comment "Netflow inbound"
```

### Kibana Authentication (Optional)
By default Kibana comes with no authentication capabilities. This typically isn't an issue if flow data is not considered confidential, and if the Flow Analyzer server is running in an isolated VLAN or network enclave.

If you need authentication for Kibana access there are two available options:

- Reverse Proxy with NGINX or Squid
- [Elastic's X-Pack commercial product](https://www.elastic.co/products/x-pack)

Putting a reverse proxy in front of Kibana blocks access to the web interface until the user has authenticated. Once successfully authenticated the user has access to all Searches, Visualizations, and Dashboards. The reverse proxy isn't integrated with Kibana, it simply sits in front of the interface.

Elastic's X-Pack commercial product is an integrated solution that works with Kibana, and provides more granular authentication, permissions, and roles. If you're looking for robust authentication, integration with Active Directory, and granular access permissions then X-Pack is the best solution available.

To use a reverse Squid proxy with Kibana perform the following steps, or run the [ubuntu_squid_install.sh](ubuntu_squid_install.sh) file.

Install Squid:
```
sudo apt-get install squid -y
```
Ensure you have a hostname entry for 127.0.0.1 in /etc/hosts file:
```
sudo echo "127.0.0.1    $(hostname)" >> /etc/hosts
```
Configure Kibana to only listen locally on 127.0.0.1 so it can't be accessed except via the reverse proxy:
```
sudo echo "server.host: \"127.0.0.1\" " >> /opt/kibana/config/kibana.yml
```
Create the Squid configuration file with the right entries for reverse proxy and basic authentication:
```
sudo echo "" > /etc/squid/squid.conf
sudo echo "### Basic Kibana authentication via Squid reverse proxy ###" >> /etc/squid/squid.conf
sudo echo "acl CONNECT method CONNECT" >> /etc/squid/squid.conf
sudo echo "auth_param basic program /usr/lib/squid3/basic_ncsa_auth /etc/squid/.htpasswd" >> /etc/squid/squid.conf
sudo echo "auth_param basic children 5" >> /etc/squid/squid.conf
sudo echo "auth_param basic realm Manito Networks Flow Analyzer" >> /etc/squid/squid.conf
sudo echo "auth_param basic credentialsttl 5 minutes" >> /etc/squid/squid.conf
sudo echo "acl password proxy_auth REQUIRED" >> /etc/squid/squid.conf
sudo echo "http_access deny !password" >> /etc/squid/squid.conf
sudo echo "http_access allow password" >> /etc/squid/squid.conf
sudo echo "http_access deny all" >> /etc/squid/squid.conf
sudo echo "http_port 80 accel defaultsite=$(hostname) no-vhost" >> /etc/squid/squid.conf
sudo echo "cache_peer $(hostname) parent 5601 0 no-query originserver" >> /etc/squid/squid.conf
```
You can also copy the [ubuntu_squid.conf](ubuntu_squid.conf) file and customize the hostname for your server.

Create the first set of credentials for authentication:
```
htpasswd -bc /etc/squid/.htpasswd admin manitonetworks
```
Set the Squid process to start automatically on boot, then start it manually the first time:
```
systemctl enable squid
systemctl start squid
```
Restart the Kibana process to force it to use the new configuration:
```
systemctl restart kibana
```

### Reboot

It's important to reboot so that we're sure the services were registered and start correctly:

```
sudo reboot
```

Once the Ubuntu instance comes back up verify that the services have started:

```
systemctl status elasticsearch
systemctl status netflow_v5
systemctl status netflow_v9
systemctl status ipfix
systemctl status kibana
```

# Configure Devices

Configure your devices to send Netflow and IPFIX data to the Flow Analyzer collector. Consult your vendor's documentation for configuring Netflow v5, Netflow v9, and IPFIX.
Also see the [Flow Management blog](http://www.manitonetworks.com/flow-management/) at manitonetworks.com for instructions on configuring Cisco, Ubiquiti, Mikrotik, and other platforms.

* [Ubiquiti IPFIX](http://www.manitonetworks.com/flow-management/2016/7/1/ubiquiti-ipfix-configuration)
* [Mikrotik Netflow v5](http://www.manitonetworks.com/flow-management/2016/7/1/mikrotik-netflow-configuration)
* [Mikrotik Netflow v9](http://www.manitonetworks.com/flow-management/2016/10/10/mikrotik-netflow-v9-configuration)
* [Cisco Netflow v9](http://www.cisco.com/c/en/us/td/docs/ios-xml/ios/netflow/configuration/15-mt/nf-15-mt-book/get-start-cfg-nflow.html#GUID-2B7E9519-66FE-4F43-B8D3-00CA38C1FA9A)

Use the following ports:

Service | Protocol | Port
-------- | -------- | -------- |
Netflow v5 | UDP | 2055 |
Netflow v9 | UDP | 9995 |
IPFIX | UDP | 4739 |

These ports can be changed, see the [tuning documentation](../Tuning.md). Make sure your devices are configured to send flow data
before moving on to [configuring Kibana](#kibana).

**Note**: Configuring devices and receiving a flow before moving onto the next step will make adding the default index in Kibana much easier.

# Kibana

A few things have to be done first in Kibana before you get to see the Visualizations and Dashboards.
Ensure that you've already [configured your devices](#configure-devices) to send flows, so by the time you get to this point there is already some flow data in the index for Kibana to recognize.

## Access Kibana

There are a couple ways to access Kibana, depending on if you're using the [reverse proxy for authentication](#kibana-authentication-optional) or not.

### No Reverse Proxy (default):

Browse to Kibana at http://your_server_ip:5601

No username or password is required.

### Using a Reverse Proxy

Browse to Kibana at http://your_server_ip

Log in with the default Squid credentials shown below:

- Username: **admin**
- Password: **manitonetworks**

## Configure Kibana

A few steps are required to point Kibana to the Flow index, import the Visualizations and Dashboards, and set some special Byte fields for better readability in KB, MB, GB, etc.

### Configure the default index pattern

The installation script has already created the Elasticsearch index, but we need to point Kibana in the right direction.

In Kibana, under **Index name or pattern** enter " flow* " without the quotes, and it should automatically parse your input.

**Note**: If you haven't already configured your devices to send flows to the collector go back and [perform that configuration](#configure-devices).

**Note**: There is currently an issue in Chrome with form validation that may cause this step not to work.
If you run into issues use Firefox or Edge to configure the Index Name.

Leave the automatically selected **Time** field under **Time-field name**.

Click the **Create** button.

Click the **Green Star** button to set the Flow index as the default index.

### Set special Byte fields

Sort field names by clicking the **name** heading

Click the **Edit** pencil icon to the far right of the **Bytes In** field

Under the **Format** drop-down choose **Bytes** so Kibana will render this field in human-readable sizes (Kb, Mb, Gb, etc)

Click **Update Field**

Perform the same steps above on the **Bytes Out** field.

### Import Kibana Visualizations and Dashboards

1. Download the [Visualization and Dashboard JSON file](../Kibana/Default.json)
2. In Kibana click Settings > Objects > Import
3. Browse to the downloaded JSON file

# Tuning

There are additional features that you can utilize, but they have to be enabled by you. This includes:

 - [Reverse DNS Lookups](../Tuning.md#lookups) & Content Tagging
 - MAC Address Prefix Tagging (Beta)

See [the tuning documentation](../Tuning.md) for how to enable these features, and recommendations for baseline settings.

# Updates

To get the latest updates do the following:

Change to the flowanalyzer directory and fetch the latest stable code via Git:

```
cd /your/directory/flowanalyzer
git fetch
```

Restart the listener services:

```
systemctl restart netflow_v5
systemctl restart netflow_v9
systemctl restart ipfix
```

# Elasticsearch Clustering

Elasticsearch works best in a cluster, and as your Elasticsearch cluster grows you'll get better performance and more storage. The default installation creates one
instance of Elasticsearch, which is fine for testing or small organizations, but you'll get the best performance from two or three (or more!) instances of Elasticsearch.
Fortunately almost everything you need is included in the default installation script, and then Elasticsearch does the rest autonomously.

The steps for adding an Elasticsearch node are shown below. Do these steps for each additional node you're adding to the cluster.

1. [Timezone and NTP](#timezone-and-ntp)
2. [Elasticsearch Configuration](#elasticsearch-configuration)
    1. [Server Installation](#server-installation)
    2. [Default Instance Configuration](#default-instance-configuration)
    3. [Additional Instance Configuration](#additional-instance-configuration)
    4. [Set Heap Size](#set-heap-size)
    5. [Enable Elasticsearch Service](#enable-elasticsearch-service)
3. [Restart Elasticsearch](#restart-elasticsearch)

## Timezone and NTP

It's extremely important for the Elasticsearch cluster that node clocks are accurate and not able to drift too much.
Also, it's important that timezones are set and remain set at UTC - Kibana takes care of adjusting timestamps for local time.
First we'll set the server timezone to UTC, then we'll set the server to update its clock via NTP:
```
timedatectl set-timezone UTC
sudo apt-get install ntp
```

## Elasticsearch Configuration

First we'll install prerequisites and Elasticsearch, then we'll configure node names and discovery IP addresses. Lastly, we'll restart
the Elasticsearch services on the nodes.

### Server Installation

On each additional Ubuntu server you want to run as an Elasticsearch node perform the following steps.

Add the Elasticsearch repository: 
```
sudo wget -qO - https://packages.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
echo "deb https://packages.elastic.co/elasticsearch/2.x/debian stable main" | sudo tee -a /etc/apt/sources.list.d/elasticsearch-2.x.list
sudo apt-get update
```
Install Elasticsearch and its dependencies:
```
sudo apt-get -y install elasticsearch openjdk-8-jre
```

It's important to set this up correctly and double-check the settings before modifying a production cluster.

### Default Instance Configuration

The /etc/elasticsearch/elasticsearch.yml file contains a line that needs **uncommented and modified**:
```
#discovery.zen.ping.unicast.hosts: ["192.168.1.10","192.168.1.11"]
```
This line tells Elasticsearch to reach out to those IP addresses and establish a connection. 
By default it's set to be commented out (because we don't know your network), so you need to uncomment it and 
add your own IP addresses of the other Elasticsearch servers. You'll then set this on every Elasticsearch node, 
pointing it to other nodes so they can discover each other. 

### Additional Instance Configuration

For example, say your network is 10.25.98.0/24, and you have the original host and two additional Elasticsearch servers:

**Node** | **IP Address** | **Node Type**
-------- | -------- | -------- |
[Master01](#master01) | 10.25.98.3 | Existing node |
[Data01](#data01) | 10.25.98.4 | New node |
[Data02](#data02) | 10.25.98.5 | New node |

Here's how your **/etc/elasticsearch/elasticsearch.yml** file will look on the three hosts:

#### Master01
```
network.host: [_local_,_site_]
node.name: Master01
cluster.name: manito_networks
discovery.zen.ping.unicast.hosts: ["10.25.98.4","10.25.98.5"]
```
#### Data01
```
network.host: [_local_,_site_]
node.name: Data01
cluster.name: manito_networks
discovery.zen.ping.unicast.hosts: ["10.25.98.3","10.25.98.5"]
```
#### Data02
```
network.host: [_local_,_site_]
node.name: Data02
cluster.name: manito_networks
discovery.zen.ping.unicast.hosts: ["10.25.98.3","10.25.98.4"]
```

## Set Heap Size
It's extremely important to set the heap size properly, so that Elasticsearch has enough memory and can retrieve your data quickly.
It's recommended that the heap size be set at [50% of the available memory,
up to 32GB per the vendor's recommendation](https://www.elastic.co/guide/en/elasticsearch/guide/current/heap-sizing.html#_give_less_than_half_your_memory_to_lucene).

For a server with 4GB of RAM, set the heap size to 2GB:
```
ES_HEAP_SIZE=2g
```

## Enable Elasticsearch Service
Set the Elasticsearch service to start automatically on server startup.
```
sudo systemctl enable elasticsearch
```

## Restart Elasticsearch

After reconfiguring Elasticsearch it's important to restart the service: 
```
sudo systemctl restart elasticsearch
```

# ---
**Copyright (c) 2016, Manito Networks, LLC**
**All rights reserved.**