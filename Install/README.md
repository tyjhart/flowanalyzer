# **Overview**

The installation is orchestrated with Git, Pip, and Bash scripting. The process should require no manual intervention on your part.

# **Minimum Requirements**

Each instance should be installed on a fresh Ubuntu Server machine with the following **minimum** specs:

- 4GB RAM
- 2 CPU Cores
- 20GB+ HDD space

Additional Elasticsearch nodes will greatly increase performance and reliability in case of node failure. Having additional
Elasticsearch nodes will also allow you to retain more days of flow data.

# **Installation**

1. Installation
  1. [Clone the Git Repository](#clone-the-git-repository)
  2. [Run the Installation Script](#installation-script)
  3. [Build Elasticsearch Flow Index](#build-the-elasticsearch-flow-index)
  4. [Firewall (Optional)](#firewall-optional)
2. Kibana
  1. [Access Kibana](#access-kibana)
  2. [Configure the Default Index Pattern](#configure-the-default-index-pattern)
  3. [Set Special Byte Fields](#set-special-byte-fields)
  4. [Import Kibana Visualizations and Dashboards](#import-kibana-visualizations-and-dashboards)
3. [Configure Devices](#configure-flows)
4. [Updates](#updates)

### **Clone the Git Repository**

If you don't have Git installed on your Ubuntu Server machine that's OK, just run the following:

```
sudo apt-get install git
```

Clone the Git repository into a new directory:

```
git clone https://gitlab.com/thart/flowanalyzer.git
```

The download should only take a moment. Move into the repo directory:

```
cd flowanalyzer
```

### **Installation Script**

The ubuntu_install.sh script handles almost everything, just be sure to run it with sudo privileges:

```
sudo sh ./Install/ubuntu_install.sh
```

The ubuntu_install.sh script does the following:

- Shifts the Ubuntu Server to UTC time and configures an NTP client so timestamps are accurate
- Adds software repos for Elasticsearch and Kibana
- Updates software repos 
- Installs Elasticsearch pre-reqs (Curl, OpenJDK 8, etc)
- Installs Elasticsearch and Kibana
- Creates the following collector services for Netflow v5/v9 and IPFIX (aka Netflow v10):
  - netflow_v5
  - netflow_v9
  - ipfix
- Registers collector services and sets auto-start
- Installs Head plugin for Elasticsearch
- Installs and configures Squid
- Configures a default Squid user:
  - Username: **admin**
  - Password: **manitonetworks**
- Schedules a weekly auto-update Cron job (/etc/cron/cron.weekly)

### **Build the Elasticsearch Flow Index**

The build_index.sh script creates the default index for storing data in Elasticsearch:

```
sh ./Install/build_index.sh
```

### **Firewall (Optional)**

These are examples of commands you may need to use if you're running a firewall on the Ubuntu Server installation:

```
ufw allow from xxx.xxx.xxx.xxx/xx to any port 80 proto tcp comment "Kibana interface"

ufw allow from xxx.xxx.xxx.xxx/xx to any port 9200 proto tcp comment "Elasticsearch CLI"

ufw allow from xxx.xxx.xxx.xxx/xx to any port 2055,9995,4739 proto udp comment "Netflow inbound"
```

### **Reboot**

It's important to reboot so that we're sure the services were registered and start correctly:

```
sudo reboot
```

# **Kibana**

A few things have to be done first in Kibana before you get to see the Visualizations and Dashboards.

### **Access Kibana**

Browse to Kibana at http://your_server_ip

Log in with the default Squid credentials shown below:

Default Username: **admin**

Default Password: **manitonetworks**

### **Configure the default index pattern**

The installation script has already created the Elasticsearch index, but we need to point Kibana in the right direction.

In Kibana, under **Index name or pattern** enter " flow* " without the quotes.

Leave the automatically selected **Time** field under **Time-field name**.

Click the **Create** button.

Click the **Green Star** button to set the Flow index as the default index.

### **Set special Byte fields**

Sort field names by clicking the **names** heading

Click the **Edit** pencil icon to the right of the **Bytes In** field

Under the **Format** drop-down choose **Bytes** so Kibana will render this field in human-readable sizes (Kb, Mb, Gb, etc)

Click **Update Field**

Perform the same steps above on the **Bytes Out** field.

### **Import Kibana Visualizations and Dashboards**

1. Download the [Visualization and Dashboard JSON file](../Kibana/Default.json)
2. In Kibana click Settings > Objects > Import
3. Browse to the downloaded JSON file

### **Creating Users for Kibana Access**

Access to Kibana is proxied through the Squid service. Putting Squid in front of Kibana allows us to restrict access to the
Kibana login page via an .htaccess file. Users can be created with the following command:

```
htpasswd -bc /opt/manitonetworks/squid/.htpasswd username password
```

# **Configure Flows**

See the Flow Analyzer blog at manitonetworks.com for instructions on setting up Cisco, Ubiquiti, Mikrotik, Juniper, and other platforms.

# **Updates**

To get the latest updates do the following:

Change to the flowanalyzer directory and fetch the latest code via Git:

```
cd /your/directory/flowanalyzer
git fetch origin
git reset --hard origin
```

Restart the listener services:

```
systemctl netflow_v5 restart
systemctl netflow_v9 restart
systemctl ipfix restart
```

# ---
**Copyright (c) 2016, Manito Networks, LLC**
**All rights reserved.**