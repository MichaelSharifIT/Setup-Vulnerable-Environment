# Configure a Vulnerable Environment

## Table of Contents
- [Prerequisites](#prerequisites)
- [Network Topology](#network-topology)
- [Vulnerable Environment](#vulnerable-environment)
  - [Overview](#overview)
  - [Open SSH on [project-x-email-svr]](#open-ssh-on-project-x-email-svr)
  - [Open SSH on [project-x-linux-client]](#open-ssh-on-project-x-linux-client)
  - [Create Detection Alert](#create-detection-alert)
  - [Configure Email Connection from [project-x-email-svr] to [project-x-linux-client]](#configure-email-connection-from-project-x-email-svr-to-project-x-linux-client)
  - [Enable WinRM on [project-x-win-client]](#enable-winrm-on-project-x-win-client)
  - [Enable RDP on [project-x-dc]](#enable-rdp-on-project-x-dc)
  - [Setup “Sensitive File” [project-x-dc]](#setup-sensitive-file-project-x-dc)
  - [Exfiltration to [project-x-attacker]](#exfiltration-to-project-x-attacker)

## Prerequisites
1. Baseline project-x network has been provisioned and configured.
   - Guides 1 – 9 have been completed.

## Network Topology

## Vulnerable Environment

### Overview
In this guide, we are going to perform configuration changes to make our environment ‘vulnerable’.

Depending on the size, scale, and complexity of a business network, attackers will often leverage insecure and default configurations to their advantage. Even though these configurations appear to be obviously insecure, you will still see some of these in production environments. Often times, this is due to legacy systems, forgotten infrastructure, urgency, or laziness (that one would be me).

These configurations are intended for homelab use only and should not be applied in production environments. Projectsecurity.io assumes no responsibility for any communication or actions taken based on this material.

Please make sure the Setup Wazuh Section has been completed in addition to all other guides outlined in the Prerequisites.

### Open SSH on [project-x-email-svr]
Update system and install openssh if it is not yet installed (should already be installed).

sudo apt update sudo apt install openssh-server -y


Enable the SSH Server and ensure it runs on boot.

sudo systemctl start ssh sudo systemctl enable ssh


Change UFW rules to allow SSH connections:

sudo ufw allow 22 sudo ufw status


Verify SSH is running:

sudo systemctl status ssh


Enable Password Authentication. Open the SSH configuration file:

sudo nano /etc/ssh/sshd_config


Locate the line for PasswordAuthentication. Uncomment if commented.

sudo nano /etc/ssh/sshd_config


Permit root login. Navigate to the #PermitRootLogin block. Uncomment and delete prohibit-password, change to yes.

Restart SSH service:

sudo systemctl restart ssh


Set root’s password (use the password: november):

sudo passwd root


### Open SSH on [project-x-linux-client]
Update system and install openssh if it is not yet installed (should already be installed).

sudo apt update sudo apt install openssh-server -y


Enable the SSH Server and ensure it runs on boot.

sudo systemctl start ssh sudo systemctl enable ssh


Change UFW rules to allow SSH connections:

sudo ufw allow 22 sudo ufw status


Verify SSH is running:

sudo systemctl status ssh


Enable Password Authentication. Open the SSH configuration file:

sudo nano /etc/ssh/sshd_config


Locate the line for PasswordAuthentication. Uncomment if commented.

sudo nano /etc/ssh/sshd_config


Permit root login. Navigate to the #PermitRootLogin block. Uncomment and delete prohibit-password, change to yes.

Restart SSH service:

sudo systemctl restart ssh


Set root’s password (use the password: november):

sudo passwd root


### Create Detection Alert
Let’s create an alert for Failed SSH attempts. To do this, a Monitor will be set up to analyze logs. Based on certain conditions defined, a Trigger can be setup to open an Alert.

Go to “Explore” → “Alerting”.

Select the “Monitors” tab on the top left.

Select “Create monitor”.

Here we can create a new monitor. Title the Monitor “3 Failed SSH Attempts”. Leave everything else default.

Scroll down to “Data source”. Add the following for the Index, hit the Enter key after typing:

wazuh-alerts-4.x-*


For “Time Field” select:

@timestamp


Next, we can add a query to select what logs and log fields we would like to monitor.

### Configure Email Connection from [project-x-email-svr] to [project-x-linux-client]
Log into [project-x-linux-client].

Install postfix and the mailutils utility to interact with your email inbox.

sudo apt install postfix mailutils -y


Choose “Internet Site” → Leave the “System mail name:” the default linux-client.

Navigate to the /postfix/main.cf configuration file:

sudo nano /etc/postfix/main.cf


Add the following (highlighted):

my_domain = corp.project-x-dc.com mynetworks = 127.0.0.0/8 10.0.0.0/24 [::ffff:127.0.0.0]/104 [::1]/128 home_mailbox = Maildir/ virtual_alias_maps=hash:/etc/postfix/virtual


Save the file with CTRL + X + Y + Enter.

Next, create the virtual file, then we can begin mapping email accounts to user accounts to Linux system.

sudo nano /etc/postfix/virtual


Enter any email address to accept:

email-svr@smtp.corp.project-x-dc.com janed


Save and close with CTRL+X, Y, then ENTER.

Apply the mapping to the virtual file:

sudo postmap /etc/postfix/virtual sudo systemctl restart postfix


Clear the screen, create janed’s Mailbox directory:

mkdir -p ~/Maildir/{cur,new,tmp} chmod -R 700 ~/Maildir


### Enable WinRM on [project-x-win-client]
Log into [project-x-win-client], open a new Administrator Powershell session. Type the following commands to enable WinRM.

powershell -ep bypass Enable-PSRemoting -force winrm quickconfig -transport:https Set-Item wsman:\localhost\client\trustedhosts * net localgroup "Remote Management Users" /add administrator Restart-Service WinRM


### Enable RDP on [project-x-dc]
Go to “Settings” → “System” → “Remote Desktop”.

Toggle Remote Desktop to “On”.

### Setup “Sensitive File” [project-x-dc]
Log into [project-x-dc], go to C:\Users\Administrator\Documents → Right-click → New Folder → Name it “ProductionFiles”.

Navigate inside the folder → Right-click → “New” → “Text File” → Name the file “secrets”. Add whatever content you would like. For this example, I added Deeboodah!.

### Exfiltration to [project-x-attacker]
The scp (Secure Copy) command-line utility allows you to copy files and directories between two systems over the SSH protocol. This tool will be used to exfiltrate the secrets.txt file to our [project-x-attacker] machine.

Enable SSH on Kali Machine:

sudo systemctl start ssh.service


Create a new file under the Kali Machine, this is where we will copy our secrets.txt file to:

touch /home/attacker/my_exfil.txt


Success!

You can copy this and paste it into your own text editor to save as a file. Let me know if you need anything else!
