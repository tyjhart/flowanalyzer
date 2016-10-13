# Copyright 2016, Manito Networks, LLC. All rights reserved.

# Get installation path
export flow_analyzer_dir=$(pwd)/Install

# Ensure we have the permissions we need to execute scripts
chmod -R +x ..

# Copy example netflow_options_default.py to real netflow_options.py
echo "Copy example netflow_options_default.py to real netflow_options.py"
cp $(pwd)/Python/netflow_options_default.py $(pwd)/Python/netflow_options.py

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
apt-get update
apt-get -y install gcc wget elasticsearch kibana openjdk-8-jre squid ntp apache2-utils php-curl curl

# Resolving Python dependencies
echo "Install Python dependencies"
apt-get install python-pip -y
pip install --upgrade pip
pip install -r $flow_analyzer_dir/requirements.txt

# Set the Elasticsearch cluster details
echo "Set the Elasticsearch cluster details"
echo "network.host: [_local_,_site_]" >> /etc/elasticsearch/elasticsearch.yml
echo "node.name: Master01" >> /etc/elasticsearch/elasticsearch.yml
echo "cluster.name: manito_networks" >> /etc/elasticsearch/elasticsearch.yml
echo "#discovery.zen.ping.unicast.hosts: ["192.168.1.10","192.168.1.11"]" >> /etc/elasticsearch/elasticsearch.yml

# Set the Elasticsearch heap size to 50% of RAM (must be <= 32GB per documentation)
echo "Set the Elasticsearch heap size to 50% of RAM (must be <= 32GB per documentation)"
echo "ES_HEAP_SIZE=2g" >> /etc/default/elasticsearch

# Enabling and restarting Elasticsearch service
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
#echo "User=root" >> /etc/systemd/system/netflow_v5.service
echo "ExecStart=/usr/bin/python $(dirname $PWD)/flowanalyzer/Python/netflow_v5.py" >> /etc/systemd/system/netflow_v5.service
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
#echo "User=root" >> /etc/systemd/system/netflow_v9.service
echo "ExecStart=/usr/bin/python $(dirname $PWD)/flowanalyzer/Python/netflow_v9.py" >> /etc/systemd/system/netflow_v9.service
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
#echo "User=root" >> /etc/systemd/system/ipfix.service
echo "ExecStart=/usr/bin/python $(dirname $PWD)/flowanalyzer/Python/ipfix.py" >> /etc/systemd/system/ipfix.service
echo "Restart=on-failure" >> /etc/systemd/system/ipfix.service
echo "RestartSec=30" >> /etc/systemd/system/ipfix.service
echo "[Install]" >> /etc/systemd/system/ipfix.service
echo "WantedBy=multi-user.target" >> /etc/systemd/system/ipfix.service

# Register new services created above
echo "Register new services created above"
systemctl daemon-reload

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
cp $flow_analyzer_dir/ubuntu_squid.conf /etc/squid/squid.conf

# Set the Squid service to automatically start
echo "Set the Squid service to automatically start"
systemctl enable squid

# Add the entry to /etc/hosts that Squid needs
echo "Add the entry to /etc/hosts that Squid needs"
echo "127.0.0.1    Flow00" >> /etc/hosts

# Set the default proxy password for Squid
echo "Set the default proxy password for Squid"
htpasswd -bc /etc/squid/.htpasswd admin manitonetworks

# Prune old indexes
echo "curator --host 127.0.0.1 delete indices --older-than 30 --prefix "flow" --time-unit days  --timestring '%Y-%m-%d'" >> /etc/cron.daily/index_prune
chmod +x /etc/cron.daily/index_prune

# Install Head plugin for Elasticsearch for troubleshooting
echo "Install Head plugin for Elasticsearch for troubleshooting"
sh /usr/share/elasticsearch/bin/plugin install mobz/elasticsearch-head