# Install Squid
apt-get install squid -y

# Create the Squid configuration file in /etc/squid/squid.conf
echo "acl CONNECT method CONNECT" >> /etc/squid/squid.conf
echo "auth_param basic program /usr/lib/squid3/basic_ncsa_auth /etc/squid/.htpasswd" >> /etc/squid/squid.conf
echo "auth_param basic children 5" >> /etc/squid/squid.conf
echo "auth_param basic realm Manito Networks Flow Analyzer" >> /etc/squid/squid.conf
echo "auth_param basic credentialsttl 5 minutes" >> /etc/squid/squid.conf
echo "acl password proxy_auth REQUIRED" >> /etc/squid/squid.conf
echo "http_access deny !password" >> /etc/squid/squid.conf
echo "http_access allow password" >> /etc/squid/squid.conf
echo "http_access deny all" >> /etc/squid/squid.conf
echo "http_port 80 accel defaultsite=$(hostname) no-vhost" >> /etc/squid/squid.conf
echo "cache_peer $(hostname) parent 5601 0 no-query originserver" >> /etc/squid/squid.conf

# Set the Squid service to automatically start
echo "Set the Squid service to automatically start"
systemctl enable squid

# Set the default proxy password for Squid
echo "Set the default proxy password for Squid"
htpasswd -bc /etc/squid/.htpasswd admin manitonetworks