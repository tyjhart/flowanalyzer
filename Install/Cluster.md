# Preface
The steps for adding an Elasticsearch node are shown below. Do these steps for each additional node you're adding to the cluster.

1. [Timezone and NTP](#timezone-and-ntp)
2. [Elasticsearch Configuration](#elasticsearch-configuration)
    1. [Server Installation](#server-installation)
    2. [Default Instance Configuration](#default-instance-configuration)
    3. [Additional Instance Configuration](#additional-instance-configuration)
    4. [Set Heap Size](#set-heap-size)
    5. [Enable Elasticsearch Service](#enable-elasticsearch-service)
3. [Restart Elasticsearch](#restart-elasticsearch)

# Timezone and NTP
It's extremely important for the Elasticsearch cluster that node clocks are accurate and not able to drift too much.
Also, it's important that timezones are set and remain set at UTC - Kibana takes care of adjusting timestamps for local time.
First we'll set the server timezone to UTC, then we'll set the server to update its clock via NTP:
```
timedatectl set-timezone UTC
sudo apt-get install ntp
```

# Elasticsearch Configuration
First we'll install prerequisites and Elasticsearch, then we'll configure node names and discovery IP addresses. Lastly, we'll restart
the Elasticsearch services on the nodes.

## Server Installation
On each additional Ubuntu server you want to run as an Elasticsearch node perform the following steps.

Add the Elasticsearch repository: 
```
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -

sudo echo "deb https://artifacts.elastic.co/packages/5.x/apt stable main" | sudo tee -a /etc/apt/sources.list.d/elastic-5.x.list

sudo apt-get update
```

Install Elasticsearch and its dependencies:
```
sudo apt-get -y install elasticsearch openjdk-8-jre
```

It's important to set this up correctly and double-check the settings before modifying a production cluster.

## Default Instance Configuration
The /etc/elasticsearch/elasticsearch.yml file contains a line that needs **uncommented and modified**:
```
#discovery.zen.ping.unicast.hosts: ["192.168.1.10","192.168.1.11"]
```

This line tells Elasticsearch to reach out to those IP addresses and establish a connection. 
By default it's set to be commented out (because we don't know your network), so you need to uncomment it and 
add your own IP addresses of the other Elasticsearch servers. You'll then set this on every Elasticsearch node, 
pointing it to other nodes so they can discover each other. 

## Additional Instance Configuration
For example, say your network is 10.25.98.0/24, and you have the original host and two additional Elasticsearch servers:

**Node** | **IP Address** | **Node Type**
--------                | --------   | --------         |
[Master01](#master01)   | 10.25.98.3 | Existing node    |
[Data01](#data01)       | 10.25.98.4 | New node         |
[Data02](#data02)       | 10.25.98.5 | New node         |

Here's how your **/etc/elasticsearch/elasticsearch.yml** file will look on the three hosts:

### Master01
```
network.host: [_local_,_site_]
node.name: Master01
cluster.name: manito_networks
discovery.zen.ping.unicast.hosts: ["10.25.98.4","10.25.98.5"]
```

### Data01
```
network.host: [_local_,_site_]
node.name: Data01
cluster.name: manito_networks
discovery.zen.ping.unicast.hosts: ["10.25.98.3","10.25.98.5"]
```

### Data02
```
network.host: [_local_,_site_]
node.name: Data02
cluster.name: manito_networks
discovery.zen.ping.unicast.hosts: ["10.25.98.3","10.25.98.4"]
```

## Set Heap Size
It's extremely important to set the heap size properly, so that Elasticsearch has enough memory and can retrieve your data quickly. It's recommended that the heap size be set at [50% of the available memory, up to 32GB per the vendor's recommendation](https://www.elastic.co/guide/en/elasticsearch/guide/current/heap-sizing.html#_give_less_than_half_your_memory_to_lucene).

For a server with 4GB of RAM, set the heap size to 2GB:
```
ES_JAVA_OPTS="-Xms2g -Xmx2g"
```

Adjust as needed for your particular sizes of RAM.

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

OR reboot the server:
```
sudo reboot
```