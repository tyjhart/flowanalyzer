# Copyright 2016, Manito Networks, LLC. All rights reserved.
#
# Last modified 10/1/2016 

# Set up the firewall if needed
#ufw allow from 192.168.1.0/24 comment "Dev range"
#ufw allow from 192.168.90.0/24 comment "Dev range"
#ufw allow from 98.166.240.0/21 comment "Tylers home IP range"
#ufw allow from xxx.xxx.xxx.xxx/xx to any port 80 proto tcp comment "Kibana interface"
#ufw allow from xxx.xxx.xxx.xxx/xx to any port 9200 proto tcp comment "Elasticsearch CLI"
#ufw allow from xxx.xxx.xxx.xxx/xx to any port 2055,9995,4739 proto udp comment "Netflow inbound"
#ufw enable

# Allow sudo to run without a TTY
#echo "Allow sudo to run without a TTY"
#sed -i 's/Defaults    requiretty/#Defaults    requiretty/g' /etc/sudoers

# Set the hostname for Squid
echo "Set the hostname"
hostnamectl set-hostname Flow00

# Set timezone to UTC
echo "Set timezone to UTC"
timedatectl set-timezone UTC

# Add the Elasticsearch & Kibana repos
echo "Add the Elasticsearch GPG key"
wget -qO - https://packages.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
echo "Add the Elasticsearch repo"
echo "deb https://packages.elastic.co/elasticsearch/2.x/debian stable main" | sudo tee -a /etc/apt/sources.list.d/elasticsearch-2.x.list
echo "Add the Kibana repo"
echo "deb https://packages.elastic.co/kibana/4.6/debian stable main" | sudo tee -a /etc/apt/sources.list.d/kibana.list

# Install dependencies
echo "Install system dependencies"
apt-get update -y
apt-get -y install gcc wget elasticsearch kibana openjdk-8-jre squid ntp apache2-utils php-curl curl

# Resolving Python dependencies
echo "Install Python dependencies"
apt-get install python-pip -y
pip install --upgrade pip
pip install -r requirements.txt

# Set the Elasticsearch cluster details
echo "Set the Elasticsearch cluster details"
echo "network.host: [_local_,_site_]" >> /etc/elasticsearch/elasticsearch.yml
echo "node.name: Master01" >> /etc/elasticsearch/elasticsearch.yml
echo "cluster.name: manito_networks" >> /etc/elasticsearch/elasticsearch.yml
echo "#discovery.zen.ping.unicast.hosts: ["192.168.1.10","192.168.1.11"]" >> /etc/elasticsearch/elasticsearch.yml

# Set the Elasticsearch heap size to 50% of RAM (must be <= 32GB per documentation)
echo "Set the Elasticsearch heap size to 50% of RAM (must be <= 32GB per documentation)"
echo "ES_HEAP_SIZE=2g" >> /etc/default/elasticsearch

# Enabling and starting Elasticsearch service
echo "Enabling and starting Elasticsearch service"
systemctl enable elasticsearch
systemctl restart elasticsearch

set +e

# Sleep 10s so Elasticsearch service can restart before building index
sleep 10s

# Adding Kibana credentials
echo "Adding Kibana credentials"
groupadd -g 1005 kibana
useradd -u 1005 -g 1005 kibana

set -e

# Set up Kibana
echo "server.host: \"127.0.0.1\" " >> /opt/kibana/config/kibana.yml

# Prevent Kibana from blowing up /var/log/messages
echo "Prevent Kibana from blowing up /var/log/messages"
echo "logging.quiet: true" >> /opt/kibana/config/kibana.yml

# Setting up the Netflow v5 service
echo "Setting up the Netflow v5 service"
echo "[Unit]" >> /etc/systemd/system/netflow_v5.service
echo "Description=Netflow v5 listener service" >> /etc/systemd/system/netflow_v5.service
echo "After=network.target elasticsearch.service kibana.service" >> /etc/systemd/system/netflow_v5.service
echo "[Service]" >> /etc/systemd/system/netflow_v5.service
echo "Type=simple" >> /etc/systemd/system/netflow_v5.service
echo "User=root" >> /etc/systemd/system/netflow_v5.service
echo "ExecStart=/usr/bin/python $(dirname $PWD)/Python/netflow_v5.pyc" >> /etc/systemd/system/netflow_v5.service
echo "Restart=on-failure" >> /etc/systemd/system/netflow_v5.service
echo "RestartSec=30" >> /etc/systemd/system/netflow_v5.service
echo "[Install]" >> /etc/systemd/system/netflow_v5.service
echo "WantedBy=multi-user.target" >> /etc/systemd/system/netflow_v5.service

# Setting up the Netflow v9 service
echo "Setting up the Netflow v9 service"
echo "[Unit]" >> /etc/systemd/system/netflow_v9.service
echo "Description=Netflow v9 listener service" >> /etc/systemd/system/netflow_v9.service
echo "After=network.target elasticsearch.service kibana.service" >> /etc/systemd/system/netflow_v9.service
echo "[Service]" >> /etc/systemd/system/netflow_v9.service
echo "Type=simple" >> /etc/systemd/system/netflow_v9.service
echo "User=root" >> /etc/systemd/system/netflow_v9.service
echo "ExecStart=/usr/bin/python $(dirname $PWD)/Python/netflow_v9.pyc" >> /etc/systemd/system/netflow_v9.service
echo "Restart=on-failure" >> /etc/systemd/system/netflow_v9.service
echo "RestartSec=30" >> /etc/systemd/system/netflow_v9.service
echo "[Install]" >> /etc/systemd/system/netflow_v9.service
echo "WantedBy=multi-user.target" >> /etc/systemd/system/netflow_v9.service

# Setting up the IPFIX service
echo "Setting up the IPFIX service"
echo "[Unit]" >> /etc/systemd/system/ipfix.service
echo "Description=IPFIX listener service" >> /etc/systemd/system/ipfix.service
echo "After=network.target elasticsearch.service kibana.service" >> /etc/systemd/system/ipfix.service
echo "[Service]" >> /etc/systemd/system/ipfix.service
echo "Type=simple" >> /etc/systemd/system/ipfix.service
echo "User=root" >> /etc/systemd/system/ipfix.service
echo "ExecStart=/usr/bin/python $(dirname $PWD)/Python/ipfix.pyc" >> /etc/systemd/system/ipfix.service
echo "Restart=on-failure" >> /etc/systemd/system/ipfix.service
echo "RestartSec=30" >> /etc/systemd/system/ipfix.service
echo "[Install]" >> /etc/systemd/system/ipfix.service
echo "WantedBy=multi-user.target" >> /etc/systemd/system/ipfix.service

# Register new services created above
echo "Register new services created above"
systemctl daemon-reload

# Build the Netflow index in Elasticsearch
echo "Build the Flow index in Elasticsearch"
sh build_index.sh

# Set the Netflow services to automatically start
echo "Set the Netflow services to automatically start"
systemctl enable netflow_v5
systemctl enable netflow_v9
systemctl enable ipfix

# Set the Kibana service to automatically start
echo "Set the Kibana service to automatically start"
systemctl enable kibana

# Set the NTP service to automatically start
echo "Set the NTP service to automatically start"
systemctl enable ntp

# Get the squid.conf file and replace the default squid.conf
echo "Get the squid.conf file and replace the default squid.conf"
wget -O /etc/squid/squid.conf https://gitlab.com/thart/flowanalyzer/blob/master/Install/ubuntu_squid.conf

# Set the Squid service to automatically start
echo "Set the Squid service to automatically start"
systemctl enable squid

# Add the entry to /etc/hosts that Squid needs
echo "Add the entry to /etc/hosts that Squid needs"
echo "127.0.0.1    Flow00" >> /etc/hosts

# Set the default proxy password for Squid
echo "Set the default proxy password for Squid"
htpasswd -bc /etc/squid/.htpasswd admin manitonetworks

# Dynamic updating cron script, get updated Python daily if it's available
echo "Dynamic updating cron script, get updated code weekly"
echo "cd $(pwd)/flowanalyzer/" >> /etc/cron.weekly/flow-update
echo "git fetch https://gitlab.com/thart/flowanalyzer.git" >> /etc/cron.weekly/flow-update
echo "service netflow_v5 restart" >> /etc/cron.weekly/flow-update
echo "service netflow_v9 restart" >> /etc/cron.weekly/flow-update
echo "service ipfix restart" >> /etc/cron.weekly/flow-update
chmod +x /etc/cron.weekly/flow-update

# Prune old indexes
echo "curator --host 127.0.0.1 delete indices --older-than 30 --prefix "flow" --time-unit days  --timestring '%Y-%m-%d'" >> /etc/cron.daily/index_prune
chmod +x /etc/cron.daily/index_prune

# Install Head plugin for Elasticsearch for troubleshooting
echo "Install Head plugin for Elasticsearch for troubleshooting"
sh /usr/share/elasticsearch/bin/plugin install mobz/elasticsearch-head