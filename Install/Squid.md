# Preface
To use a reverse Squid proxy with Kibana perform the following steps, or run the [ubuntu_squid_install.sh](ubuntu_squid_install.sh) file.

1. Install Squid
2. Set the Hostname
3. Configure Kibana to Listen Locally Only
4. Create Squid Configuration File
5. Create Login Credentials
5. Configure the Squid Service

# Install Squid
```
sudo apt-get install squid -y
```

# Set the Hostname
Ensure you have a hostname entry for 127.0.0.1 in /etc/hosts file:
```
sudo echo "127.0.0.1    $(hostname)" >> /etc/hosts
```

# Configure Kibana to Listen Locally Only
Configure Kibana to only listen locally on 127.0.0.1 so it can't be accessed except via the reverse proxy:
```
sudo echo "server.host: \"127.0.0.1\" " >> /opt/kibana/config/kibana.yml
```

# Create Squid Configuration File
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

# Configure Login Credentials
Create the first set of credentials for authentication:
```
htpasswd -bc /etc/squid/.htpasswd admin manitonetworks
```

# Configure the Squid Service
Set the Squid process to start automatically on boot, then start it manually the first time:
```
systemctl enable squid
systemctl restart squid
```

# ---
**Copyright (c) 2016, Manito Networks, LLC**
**All rights reserved.**