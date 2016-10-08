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
  1. [Clone the Git repository](#clone-the-git-repository)
  2. [Run the Installation Script](#installation-script)
2. Kibana
  1. [Access Kibana](#access-kibana)
  2. [Configure the default index pattern](#configure-the-default-index-pattern)
  3. [Set special Byte fields](#set-special-byte-fields)
  4. [Import Kibana Visualizations and Dashboards](#import-kibana-visualizations-and-dashboards)
3. [Configure Flows](#configure-flows)

### **Clone the Git Repository**

If you don't have Git installed on your Ubuntu Server machine that's OK, just run the following:

```
sudo apt-get install git
```

Navigate to a directory you want to run the collectors from, where you also have full read/write permissions:

```
cd /your/directory/
```

Run the command below to clone the Git repository into a new directory:

```
git clone https://gitlab.com/thart/flowanalyzer.git
```

The download should only take a moment. Move into the repo directory:

```
cd flowanalyzer
```

### **Installation Script**

The ubuntu_install.sh script handles almost everything, just be sure to run it with sudo privileges:

**Note**: The installation script does reboot at the end to ensure that all the services get a clean register and start.

```
sudo sh ./Install/ubuntu_install.sh
```

The ubuntu_install.sh script does the following:

- Shifts the Ubuntu Server to UTC time and configures an NTP client so timestamps are accurate
- Adds software repos for Elasticsearch and Kibana
- Updates the repos for the install
- Installs Elasticsearch pre-reqs (Curl, OpenJDK 8, etc)
- Installs Elasticsearch and Kibana
- Creates the following services for Netflow v5/v9 and IPFIX (aka v10):
  - netflow_v5
  - netflow_v9
  - ipfix
- Registers collector services
- Builds the Flow index in Elasticsearch
- Sets unknown field defaults in Elasticsearch
- Installs Curator for Elasticsearch
- Installs Head plugin for Elasticsearch
- Installs and configures Squid
- Configures a default Squid user:
  - Username: **admin**
  - Password: **manitonetworks**
- Schedules a weekly auto-update Cron job (/etc/cron/cron.weekly)

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

# ---
**Copyright (c) 2016, Manito Networks, LLC**
**All rights reserved.**