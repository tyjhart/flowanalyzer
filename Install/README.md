# Preface
The installation is orchestrated with Git, Pip, and Bash scripting. The process should require no manual intervention on your part, as long as you're running the latest stable LTS release of Ubuntu Server. Kibana requires some minimal configuration, but it is all point-and-click in the Kibana interface and only needs to be done once.

# Minimum Requirements
Each instance should be installed on a fresh 64-bit [Ubuntu Server](https://www.ubuntu.com/download/server) machine with **systemd support**, and at least the minimum required resources as listed in the [main README document Requirements section](../README.md#requirements).

The installation script is incompatible with Ubuntu versions prior to 15.04 due to a shift to SystemD by Canonical. Earlier versions of Ubuntu can use SystemD with a fair amount of work, but the installation script isn't supported on non-SystemD platforms with workarounds implemented.

While installing everything on one server is good for proof-of-concept or testing, additional Elasticsearch nodes will greatly increase performance and provide failover. Having additional Elasticsearch nodes will also allow you to retain more flow data, and tune overall performance to your needs.

# Overview
1. [Installation](#installation)
    1. [Clone the Git Repository](#clone-the-git-repository)
    2. [Run the Installation Script](#installation-script)
    3. [Build Elasticsearch Indexes](#build-elasticsearch-indexes)
        1. [Netflow Index](#netflow-index)
        2. [sFlow Index](#sflow-index)
    4. [Elasticsearch Tuning](#elasticsearch-tuning)
    5. [Firewall (Optional)](#firewall-optional)
    6. [Kibana Authentication (Optional)](#kibana-authentication-optional)
    7. [Reboot](#reboot)
    8. [Verify Services](#verify-services)
    9. [Disable Unused Collector Services](#disable-unused-collector-services)
2. [Configure Devices](#configure-devices)
3. [Kibana](#kibana)
    1. [Access Kibana](#access-kibana)
    2. [Configure Index Patterns](#configure-index-patterns)
        1. [Netflow Index Pattern](#netflow-index-pattern)
        2. [sFlow Index Pattern](#sflow-index-pattern)
    3. [Set Special Byte Fields](#set-special-byte-fields)
    4. [Import Kibana Visualizations and Dashboards](#import-kibana-visualizations-and-dashboards)
4. [Tuning](#tuning)
5. [Updates](#updates)
6. [Elasticsearch Clustering](#elasticsearch-clustering)

# Installation
Follow the steps below in order and the installation should take no more than about 20 minutes. Copy-paste commands for easier installation.

## Clone the Git Repository
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

## Installation Script
The ubuntu_install_elk5.sh script handles almost everything, just be sure to run it with sudo privileges:
```
sudo sh ./Install/ubuntu_install_elk5.sh
```

The ubuntu_install_elk5.sh script does the following:

- Shifts the Ubuntu Server to UTC time and configures an NTP client so timestamps are accurate
- Adds software repos for Elasticsearch and Kibana v5
- Updates software repos and keys
- Installs Elasticsearch v5 pre-reqs (Curl, OpenJDK 8, etc)
- Installs Elasticsearch and Kibana v5
- Creates the following collector services for Netflow v5/v9, IPFIX (aka Netflow v10), and sFlow:
  - netflow_v5
  - netflow_v9
  - ipfix
  - sflow
- Registers collector services, sets auto-start on boot, and auto-restart on failure (30 seconds)
- Creates an index pruning job (>30 days old) using Curator in /etc/cron.daily

## Build Elasticsearch Indexes
Index templates need to be created in Elasticsearch, so when data is collected the fields will be assigned the right data types and proper indexing settings.

### Netflow Index
The build_netflow_index_elk5.sh script creates the default index for storing Netflow and IPFIX flow data in Elasticsearch:
```
sh ./Install/build_netflow_index_elk5.sh
```

This should output the following message, indicating the template has been created:
```
{
    "acknowledged" : true
}
```

### sFlow Index
The build_sflow_index_elk5.sh script creates the default index for storing sFlow data in Elasticsearch. A separate script and index are used because sFlow data can be very different from network flow data depending on what sFlow counter records are being exported.

Run the sFlow index script:
```
sh ./Install/build_sflow_index_elk5.sh
```

This should output the following message, indicating the template has been created:
```
{
    "acknowledged" : true
}
```

## Elasticsearch Tuning
One of the biggest ways to destroy Elasticsearch performance is to not properly allocate the right sized heap. The creators of Elasticsearch recommend setting
Elasticsearch to use [50% of the available memory](https://www.elastic.co/guide/en/elasticsearch/guide/current/heap-sizing.html#_give_less_than_half_your_memory_to_lucene) 
on a given server, up to the 32GB limit. 

The configuration set in the installation script sets Elasticsearch memory to 2GB, assuming a server with at least 4GB of RAM. If you're using a 4GB server as a PoC or just a small installation you don't need to change anything.

If you have more RAM, Heap size is increased by setting the following in the **/etc/default/elasticsearch** configuration file:
```
ES_JAVA_OPTS="-Xms2g -Xmx2g"
```

**Note**: If you have a server with more RAM then you need to adjust this value and reboot the server (or restart Elasticsearch and then the collector services).

## Firewall (Optional)
These are examples of commands you may need to use if you're running a firewall on the Ubuntu Server installation:
```
ufw allow from xxx.xxx.xxx.xxx/xx to any port 80 proto tcp comment "Kibana interface"
ufw allow from xxx.xxx.xxx.xxx/xx to any port 9200 proto tcp comment "Elasticsearch CLI"
ufw allow from xxx.xxx.xxx.xxx/xx to any port 2055,9995,4739,6343 proto udp comment "Flow data in"
```

## Kibana Authentication (Optional)
By default Kibana comes with no authentication capabilities. This typically isn't an issue if flow data is not considered confidential, and if the Flow Analyzer server is running in an isolated VLAN or management network enclave.

If you need authentication for Kibana access there are two available options:

- Reverse Proxy with NGINX or Squid
- [Elastic's X-Pack commercial product](https://www.elastic.co/products/x-pack)

Putting a reverse proxy in front of Kibana blocks access to the web interface until the user has authenticated. Once successfully authenticated the user has access to all Searches, Visualizations, and Dashboards. The reverse proxy isn't integrated with Kibana, it simply sits in front of the interface. See the [Squid.md](Squid.md) file for steps to configure the reverse proxy.

Elastic's X-Pack commercial product is an integrated solution that works with Kibana, and provides more granular authentication, permissions, and roles. If you're looking for robust authentication, integration with Active Directory, and granular access permissions then X-Pack is the best solution available.

## Reboot
It's important to reboot so that we're sure the services were registered and start correctly:
```
sudo reboot
```

## Verify Services
Once the Ubuntu instance comes back up verify that the services have started:
```
systemctl status elasticsearch
systemctl status kibana
systemctl status netflow_v5
systemctl status netflow_v9
systemctl status ipfix
systemctl status sflow
```

## Disable Unused Collector Services
By default all the collectors are configured to auto-start on boot and run in the background. This is done for your convenience, but if you're not using a particular protocol then there's no reason to keep its collector running. For example, if your devices don't support sFlow you can disable the sFlow collector:
```
sudo systemctl stop sflow
sudo systemctl disable sflow
```

If you aren't using IPFIX:
```
sudo systemctl stop ipfix
sudo systemctl disable ipfix
```

Next time the server reboots those collector processes won't start and won't use any server resources.

# Configure Devices
Configure your devices to send Netflow, IPFIX, and sFlow data to the Flow Analyzer collector. Consult your vendor's documentation for configuring Netflow v5, Netflow v9, and IPFIX. Also see the [Flow Management blog](http://www.manitonetworks.com/flow-management/) at manitonetworks.com for instructions on configuring Cisco, Ubiquiti, Mikrotik, and other platforms.

* [Ubiquiti IPFIX](http://www.manitonetworks.com/flow-management/2016/7/1/ubiquiti-ipfix-configuration)
* [Mikrotik Netflow v5](http://www.manitonetworks.com/flow-management/2016/7/1/mikrotik-netflow-configuration)
* [Mikrotik Netflow v9](http://www.manitonetworks.com/flow-management/2016/10/10/mikrotik-netflow-v9-configuration)
* [Cisco Netflow v9](http://www.cisco.com/c/en/us/td/docs/ios-xml/ios/netflow/configuration/15-mt/nf-15-mt-book/get-start-cfg-nflow.html#GUID-2B7E9519-66FE-4F43-B8D3-00CA38C1FA9A)

Use the following ports for each respective collector service:

Service     | Protocol  | Port |
--------    | --------  | -------- |
Netflow v5  | UDP       | 2055 |
Netflow v9  | UDP       | 9995 |
IPFIX       | UDP       | 4739 |
sFlow       | UDP       | 6343 |     

These ports can be changed, see the [tuning documentation](../Tuning.md). Make sure your devices are configured to send flow data before moving on to [configuring Kibana](#kibana).

**Note**: Configuring devices and receiving flows **before** moving onto the next step will make adding the default index in Kibana much easier.

# Kibana
A few things have to be done first in Kibana before you get to see the Visualizations and Dashboards.
Ensure that you've already [configured your devices](#configure-devices) to send flows, so by the time you get to this point there is already some flow data in the index for Kibana to recognize.

## Access Kibana
There are a couple ways to access Kibana, depending on if you're using the [reverse proxy for authentication](#kibana-authentication-optional) or not.

### No Reverse Proxy (default):
Browse to Kibana at http://your_server_ip:5601

### Using a Reverse Proxy (optional, only if configured)
1. Browse to Kibana at http://your_server_ip
2. Log in with the default Squid credentials you created during the [Squid configuration](Squid.md).

## Configure Index Patterns
On first logging in to Kibana you'll notice an orange **Warning** message that states:
> No default index pattern. You must select or create one to continue.

The Netflow and sFlow index scripts already created the index templates and your devices should have been sending flows already which triggers index creation, but we need to point Kibana in the right direction. 

### Netflow Index Pattern
Use the following steps to point Kibana to the Netflow index:
1. Click **Index Patterns**
2. Click the **Add New** button in the upper-left if not already placed at the **Configure an index pattern** page
3. Under **Index name or pattern** enter __flow\*__
4. Click outside the entry field and it should automatically parse your input, revealing more information below

**Note**: If you haven't already configured your devices to send flows to the collector go back and [perform that configuration](#configure-devices) because the following steps won't work.

5. Leave the automatically selected **Time** field under **Time-field name**.
6. Click the **Create** button.
7. You will be taken to the **flow\*** index pattern.

### sFlow Index Pattern
Use the following steps to point Kibana to the sFlow index:
1. Click **Index Patterns**
2. Click the **Add New** button in the upper-left if not already placed at the **Configure an index pattern** page
3. Under **Index name or pattern** enter __sflow\*__
4. Click outside the entry field and it should automatically parse your input, revealing more information below

**Note**: If you haven't already configured your devices to send flows to the collector go back and [perform that configuration](#configure-devices) because the following steps won't work.

5. Leave the automatically selected **Time** field under **Time-field name**.
6. Click the **Create** button.
7. You will be taken to the **sflow\*** index pattern.

## Set Special Byte Fields
Most flow protocols report packet and data sizes in Byte units, which is fine for computers, but isn't very helpful when trying to present a human-readable dashboard. By setting the field formatting in Kibana we can automatically have number fields with raw octets displayed in KB, MB, GB, TB, etc.

### Netflow
Perform the following steps below on the following Netflow index fields:
- Bytes In
- Bytes Out

### sFlow
Perform the following steps below on the following sFlow index fields:
- Bytes In
- Bytes Out
- Bytes Read
- Bytes Written
- Current Allocation
- Memory Buffers
- Memory Cached
- Memory Free
- Memory Shared
- Memory Total
- Memory Used
- Total Available
- Total Capacity

### Steps to Set Byte Field Formatting
1. Click **Management** on the left navigation bar
2. Click **Index Patterns** at the top of the window
4. Select the index to modify fields in
5. Sort field names by clicking the **name** heading
6. Click the **pencil icon** in the far-right **controls** column to edit the field
7. Under the **Format** drop-down choose **Bytes**
8. Click **Update Field**

## Import Kibana Visualizations and Dashboards
1. Download the Netflow JSON file for Netflow and IPFIX. There are two versions:
    - [Netflow JSON file for Kibana v5](../Kibana/netflow_elk5.json) (default, use this for fresh installs)
    - [Netflow JSON file for Kibana v2 (legacy)](../Kibana/netflow_elk2_legacy.json) for legacy installations based on ELK v2
2. Download the [sFlow JSON file](../Kibana/sflow_elk5.json) for sFlow (ELK v5 or latest version only)
3. In Kibana perform the following steps:
    1. Click **Management** on the left navigation bar
    2. Click **Saved Objects** at the top of the window
    3. Click the **Import** button
    4. Browse to the downloaded JSON file
    5. Repeat as necessary for additional JSON files

# Tuning
There are additional features that you can utilize, but they have to be enabled by you. This includes:

 - [Reverse DNS Lookups](../Tuning.md#lookups) & Content Tagging
 - MAC Address Prefix Tagging (in development)

See [the tuning documentation](../Tuning.md) for how to enable these features, and recommendations for baseline settings.

# Updates
To get the latest updates do the following:

Change to the flowanalyzer directory and fetch the latest stable code via Git from the Master branch:
```
cd /your/directory/flowanalyzer
git pull
```

Any changes to files will be shown. If nothing has changed disregard the next steps that restart the collector services.

Restart the collector services you are actively using on your network (all are listed here for documentation purposes):
```
systemctl restart netflow_v5
systemctl restart netflow_v9
systemctl restart ipfix
systemctl restart sflow
```

# Elasticsearch Clustering
Elasticsearch works best in a cluster, and as your Elasticsearch cluster grows you'll get better performance and more storage. The default installation creates one instance of Elasticsearch, which is fine for testing or small organizations, but you'll get the best performance from two or three (or more!) instances of Elasticsearch. As you sample more traffic from more devices you can grow the cluster over time.

Fortunately almost everything you need is included in the default installation script, you just need to tweak a few options and Elasticsearch does the rest automatically.

See the [Elasticsearch Cluster file for steps to configure a cluster](Cluster.md).

# ---
**Copyright (c) 2016, Manito Networks, LLC**
**All rights reserved.**