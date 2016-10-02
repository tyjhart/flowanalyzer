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

# Create folders
mkdir ./manitonetworks
mkdir ./manitonetworks/kibana
mkdir ./manitonetworks/flow
mkdir ./manitonetworks/squid
chmod -R 777 ./manitonetworks

# Allow sudo to run without a TTY
#echo "Allow sudo to run without a TTY"
#sed -i 's/Defaults    requiretty/#Defaults    requiretty/g' /etc/sudoers

# Set the hostname
echo "Set the hostname"
hostnamectl set-hostname Flow00

# Set timezone to UTC
echo "Set timezone to UTC"
timedatectl set-timezone UTC

# Add the Elasticsearch & Kibana repos
echo "Add the Elasticsearch GPG key"
wget -qO - https://packages.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
echo "Add the Elasticsearch repo"
echo "deb http://packages.elastic.co/elasticsearch/2.x/debian stable main" | sudo tee -a /etc/apt/sources.list.d/elasticsearch-2.x.list
echo "Add the Kibana repo"
echo "deb http://packages.elastic.co/kibana/4.5/debian stable main" | sudo tee -a /etc/apt/sources.list

# Update APT
echo "Update Ubuntu via APT"
apt-get -y update && apt-get -y upgrade

# Install dependencies
echo "Install system dependencies"
apt-get -y install gcc wget elasticsearch kibana openjdk-8-jre squid ntp apache2-utils php-curl

# Resolving Python dependencies
echo "Install Python dependencies"
apt-get install python-pip -y
pip install --upgrade pip
pip install -r requirements.txt

# Clone the latest Flow code
git clone https://gitlab.com/thart/flowanalyzer/tree/master .

# Get the latest Netflow code
#echo "Get the latest Netflow code"
#wget -N -P /opt/manitonetworks/flow/ https://s3-us-west-2.amazonaws.com/manitonetworks/Update/install.tar
#tar -xf /opt/manitonetworks/flow/install.tar -C /opt/manitonetworks/flow/ 
#rm -f /opt/manitonetworks/flow/install.tar
#python -m compileall /opt/manitonetworks/flow/
#mv /opt/manitonetworks/flow/netflow_options.py /tmp/
#rm -f /opt/manitonetworks/flow/*.py
#mv /tmp/netflow_options.py /opt/manitonetworks/flow/
#chmod -R 777 /opt/manitonetworks/flow

# Add the license file
#echo "Add the licensing file"
#echo "# Copyright Manito Networks, LLC. All rights reserved. Not for distribution or publication." >> /opt/manitonetworks/license.py
#echo "#" >> /opt/manitonetworks/license.py
#echo "# Edit the values below with the License ID and Secret provided by your Manito Networks rep" >> /opt/manitonetworks/license.py
#echo "company_license_id = 999999 # Insert your license ID in place of the numbers already in this line" >> /opt/manitonetworks/license.py
#echo "customer_secret = \"trial\" # Insert your customer secret between the quotes" >> /opt/manitonetworks/license.py
#echo "product = \"Flow Analyzer\" # Do not modify" >> /opt/manitonetworks/license.py
#echo "Get the latest updater scripts"
#wget -N -P /opt/manitonetworks/ https://s3-us-west-2.amazonaws.com/manitonetworks/Update/updater/__init__.py
#wget -N -P /opt/manitonetworks/ https://s3-us-west-2.amazonaws.com/manitonetworks/Update/updater/update.py
#python -m compileall update.py

# Set the Elasticsearch cluster details
echo "Set the Elasticsearch cluster details"
echo "network.host: [_local_,_site_]" >> /etc/elasticsearch/elasticsearch.yml
echo "node.name: Master01" >> /etc/elasticsearch/elasticsearch.yml
echo "cluster.name: manito_networks" >> /etc/elasticsearch/elasticsearch.yml
echo "#discovery.zen.ping.unicast.hosts: ["192.168.90.195","192.168.90.197"]" >> /etc/elasticsearch/elasticsearch.yml

# Set the Elasticsearch heap size to 50% of RAM (must be <= 32GB per documentation)
echo "Set the Elasticsearch heap size to 50% of RAM (must be <= 32GB per documentation)"
echo "ES_HEAP_SIZE=2g" >> /etc/default/elasticsearch

# Enabling and starting Elasticsearch service
echo "Enabling and starting Elasticsearch service"
systemctl enable elasticsearch
systemctl start elasticsearch

set +e

# Restart the Elasticsearch service
service elasticsearch restart

# Sleep 10s so Elasticsearch service can start before building index
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
echo "ExecStart=/usr/bin/python /opt/manitonetworks/flow/netflow_v5.pyc" >> /etc/systemd/system/netflow_v5.service
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
echo "ExecStart=/usr/bin/python /opt/manitonetworks/flow/netflow_v9.pyc" >> /etc/systemd/system/netflow_v9.service
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
echo "ExecStart=/usr/bin/python /opt/manitonetworks/flow/ipfix.pyc" >> /etc/systemd/system/ipfix.service
echo "Restart=on-failure" >> /etc/systemd/system/ipfix.service
echo "RestartSec=30" >> /etc/systemd/system/ipfix.service
echo "[Install]" >> /etc/systemd/system/ipfix.service
echo "WantedBy=multi-user.target" >> /etc/systemd/system/ipfix.service

# Register new services created above
echo "Register new services created above"
systemctl daemon-reload

# Build the Netflow index in Elasticsearch
echo "Build the Flow index in Elasticsearch"
sh ./Install/build_index.sh

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
wget -O /etc/squid/squid.conf https://s3-us-west-2.amazonaws.com/manitonetworks/Update/squid/ubuntu_squid.conf

# Set the Squid service to automatically start
echo "Set the Squid service to automatically start"
systemctl enable squid

# Add the entry to /etc/hosts that Squid needs
echo "Add the entry to /etc/hosts that Squid needs"
echo "127.0.0.1    Flow00" >> /etc/hosts

# Set the default proxy password for Squid
echo "Set the default proxy password for Squid"
htpasswd -bc /opt/manitonetworks/squid/.htpasswd admin manitonetworks

# Dynamic updating cron script, get updated Python daily if it's available
echo "Dynamic updating cron script, get updated code weekly"
echo "python /opt/manitonetworks/update.py" >> /etc/cron.weekly/flow-update
echo "service netflow_v5 stop" >> /etc/cron.weekly/flow-update
echo "service netflow_v9 stop" >> /etc/cron.weekly/flow-update
echo "service ipfix stop" >> /etc/cron.weekly/flow-update
echo "mv /opt/manitonetworks/flow/netflow_options.py /tmp/" >> /etc/cron.weekly/flow-update
echo "python -m compileall /opt/manitonetworks/flow" >> /etc/cron.weekly/flow-update
echo "rm -f /opt/manitonetworks/flow/*.py" >> /etc/cron.weekly/flow-update
echo "mv /tmp/netflow_options.py /opt/manitonetworks/flow/" >> /etc/cron.weekly/flow-update
echo "chmod -R 777 /opt/manitonetworks/flow" >> /etc/cron.weekly/flow-update
echo "service netflow_v5 start" >> /etc/cron.weekly/flow-update
echo "service netflow_v9 start" >> /etc/cron.weekly/flow-update
echo "service ipfix start" >> /etc/cron.weekly/flow-update
chmod +x /etc/cron.weekly/flow-update

# Prune old indexes
echo "curator --host 127.0.0.1 delete indices --older-than 30 --prefix "flow" --time-unit days  --timestring '%Y-%m-%d'" >> /etc/cron.daily/index_prune
chmod +x /etc/cron.daily/index_prune

# Install Head plugin for Elasticsearch for troubleshooting
echo "Install Head plugin for Elasticsearch for troubleshooting"
sh /usr/share/elasticsearch/bin/plugin install mobz/elasticsearch-head

# Clean up
echo "Clean up"
apt-get clean all

# Reboot
echo "Reboot"
reboot