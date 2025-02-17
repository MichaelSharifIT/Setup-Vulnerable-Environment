# Configure a Vulnerable Environment

## Table of Contents
- [Prerequisites](#prerequisites)
- [Network Topology](#network-topology)
- [Vulnerable Environment Overview](#vulnerable-environment-overview)
- [Open SSH on [project-x-email-svr]](#open-ssh-on-project-x-email-svr)
- [Detection Integration (Email Server)](#detection-integration-email-server)
- [Open SSH on [project-x-linux-client]](#open-ssh-on-project-x-linux-client)
- [Detection Integration (Linux Client)](#detection-integration-linux-client)
- [Create Detection Alert (Failed SSH Attempts)](#create-detection-alert-failed-ssh-attempts)
- [Configure Email Connection from [project-x-email-svr] to [project-x-linux-client]](#configure-email-connection-from-project-x-email-svr-to-project-x-linux-client)
- [Detection Integration (Email Connection)](#detection-integration-email-connection)
- [Enable WinRM on [project-x-win-client]](#enable-winrm-on-project-x-win-client)
- [Detection Integration (WinRM)](#detection-integration-winrm)
- [Create Detection Alert (WinRM Logon)](#create-detection-alert-winrm-logon)
- [Enable RDP on [project-x-dc]](#enable-rdp-on-project-x-dc)
- [Detection Integration (RDP)](#detection-integration-rdp)
- [Setup “Sensitive File” [project-x-dc]](#setup-sensitive-file-project-x-dc)
- [Detection Integration (File Integrity Monitoring)](#detection-integration-file-integrity-monitoring)
- [Create Detection Alert (File Accssed)](#create-detection-alert-file-accssed)
- [Exfiltration to [project-x-attacker]](#exfiltration-to-project-x-attacker)
- [Additional Steps for Exfiltration](#additional-steps-for-exfiltration)

---

## Prerequisites
1. Baseline project‑x network has been provisioned and configured.  

---

## Network Topology
*(Details of the network topology are assumed to be covered elsewhere in the guide.)*

---

## Vulnerable Environment Overview
In this guide, we are going to perform configuration changes to make our environment **vulnerable**.

Depending on the size, scale, and complexity of a business network, attackers will often leverage insecure and default configurations to their advantage. Even though these configurations appear to be obviously insecure, you will still see some of these in production environments—often due to legacy systems, forgotten infrastructure, urgency, or even laziness.

> **Warning:** These configurations are intended for homelab use only and should **not** be applied in production environments.  

**Note:** Please ensure the Setup Wazuh Section has been completed in addition to all other guides outlined in the Prerequisites.

---

## Open SSH on [project-x-email-svr]
1. **Update system and install OpenSSH** (should already be installed):
   ```bash
   sudo apt update
   sudo apt install openssh-server -y
2. Enable the SSH Server and ensure it runs on boot:
```bash
sudo systemctl start ssh
sudo systemctl enable ssh
```
3. Change UFW rules to allow SSH connections:
```bash
sudo ufw allow 22
sudo ufw status
```
4. Verify SSH is running:
```bash
sudo systemctl status ssh
```
5. Enable Password Authentication. Open the SSH configuration file:
```bash
sudo nano /etc/ssh/sshd_config
```
    Locate the line for PasswordAuthentication and uncomment it if necessary.
    Locate the #PermitRootLogin block, uncomment it, and change prohibit-password to yes.

6. Restart the SSH service:
```bash
sudo systemctl restart ssh
```
7. Set root’s password (use the password: november):
```bash
    sudo passwd root
```
## Detection Integration (Email Server)

[project-x-email-svr] does not have the Wazuh agent installed. This is intentional to demonstrate how the absence of detection controls can create a gap in identifying potentially malicious activity.
## Open SSH on [project-x-linux-client]

Update system and install OpenSSH (should already be installed):
```bash
sudo apt update
sudo apt install openssh-server -y
```
Enable the SSH Server and ensure it runs on boot:
```bash
sudo systemctl start ssh
sudo systemctl enable ssh
```
Change UFW rules to allow SSH connections:
```bash
sudo ufw allow 22
sudo ufw status
```
Verify SSH is running:
```bash
sudo systemctl status ssh
```
Enable Password Authentication. Open the SSH configuration file:
```bash
sudo nano /etc/ssh/sshd_config
```
  Locate the line for PasswordAuthentication and uncomment it if necessary.
  Locate the #PermitRootLogin block, uncomment it, and change prohibit-password to yes.

Restart the SSH service:
```bash
sudo systemctl restart ssh
```
Set root’s password (use the password: november):
```
sudo passwd root
```

## Detection Integration (Linux Client)

Wazuh has a built-in rule detection to detect authentication failures from the sshd daemon.

  - Wazuh Rule ID: 5760
  - Description: sshd: authentication failed.

To view more details about this rule, navigate to Server management → Rules and look up 5760.

Tip: Generate a failed login attempt by intentionally using incorrect credentials when testing SSH.


## Create Detection Alert (Failed SSH Attempts)

To create an alert for failed SSH attempts:

  1. Navigate to Explore → Alerting.
  2. Select the Monitors tab on the top left.
  3. Click on Create monitor.
  4. Title the monitor "3 Failed SSH Attempts" and leave all other settings as default.
  5. Scroll down to Data source and add the following for the Index (press Enter after typing):

`wazuh-alerts-4.x-*`

For Time Field, select:

`@timestamp`

Next, add a query in the Data filter section to filter logs based on:

    The sshd process name.
    The authentication_failed rule group.

Add a Trigger with these conditions:

    Severity level: 3 (Medium)
    Trigger condition: more than 2 logs matching the query.

(Optional) Configure actions for notifications (Email, Slack, etc.). This guide does not cover configuring these notifications.
Scroll to the bottom and click Create to save the monitor.

## Configure Email Connection from [project-x-email-svr] to [project-x-linux-client]

This configuration allows [project-x-email-svr] to send email to itself or forward email to local hosts. To enable email routing from a workstation ([project-x-linux-client]) to the email server ([project-x-email-svr]), configure Postfix on [project-x-linux-client]:

Log into [project-x-linux-client].
Install Postfix and mailutils:
```
sudo apt install postfix mailutils -y
```
When prompted, choose Internet Site and leave the System mail name: as the default (linux-client).

Edit the Postfix configuration file:
```
sudo nano /etc/postfix/main.cf
```
Add the following lines:
```
my_domain = corp.project-x-dc.com
mynetworks = 127.0.0.0/8 10.0.0.0/24 [::ffff:127.0.0.0]/104 [::1]/128
home_mailbox = Maildir/
virtual_alias_maps = hash:/etc/postfix/virtual
```
Save the file (CTRL + X, then Y, and Enter).
Create the virtual alias file:
```
sudo nano /etc/postfix/virtual
```
Add a mapping (for example):
```
email-svr@smtp.corp.project-x-dc.com janed
```
This routes any email sent to the email-svr address to the user janed.
Apply the virtual alias mapping:
```
sudo postmap /etc/postfix/virtual
sudo systemctl restart postfix
```
Create the Maildir for user janed:
```
mkdir -p ~/Maildir/{cur,new,tmp}
chmod -R 700 ~/Maildir
```
Set the MAIL environment variable so the mail command finds the mailbox:
```
echo 'export MAIL=~/Maildir' | sudo tee -a /etc/bash.bashrc | sudo tee -a /etc/profile.d/mail.sh
source /etc/profile.d/mail.sh
```
Enable SMTP (Postfix) through UFW:
```
sudo ufw allow postfix
sudo ufw enable
sudo ufw reload
```
Restart Postfix:
```
sudo systemctl restart postfix
```
Test the email setup by sending an email from [project-x-email-svr] to [project-x-linux-client]:
```
echo "This is a test message." | mail -s "Hello!" jane@linux-client
```

## Detection Integration (Email Connection)

[project-x-email-svr] does not have the Wazuh agent installed. This intentional omission demonstrates how the absence of detection controls can create gaps in identifying potentially malicious activity.

## Enable WinRM on [project-x-win-client]

Log into [project-x-win-client] and open a new Administrator PowerShell session.
    Run the following commands:

    powershell -ep bypass
    Enable-PSRemoting -force
    winrm quickconfig -transport:https
    Set-Item wsman:\localhost\client\trustedhosts *
    net localgroup "Remote Management Users" /add administrator
    Restart-Service WinRM

## Detection Integration (WinRM)

    Note: An Event ID does not exist for enabling WinRM as a service. However, WinRM logins can be detected via Event ID 4624 with a logonProcessName of Kerberos, since WinRM uses Kerberos.
  Once Windows Security logs are enabled (as per the Setup Wazuh section), Windows Event Logs will capture these events.
    - Wazuh Rule ID: 60106
    - Description: User: Windows Logon Success
    To view more details, navigate to Server management → Rules and search for 60106.

## Create Detection Alert (WinRM Logon)

  - Navigate to Explore → Alerting.
  - Select the Monitors tab and click Create monitor.
  - Title the monitor "WinRM Logon" and leave settings as default.
  - Scroll down to Data source and add:

    `wazuh-alerts-4.x-*`

  - Then select @timestamp as the Time Field.
  - Add a query in the Data filter tab to monitor logs based on the logonProcessName and eventID fields.
  - Add a trigger with:
        Severity level: 3 (Medium)
        Trigger condition: above 1.
  - Click Create to save the monitor.

## Enable RDP on [project-x-dc]

  - Navigate to Settings → System → Remote Desktop.
  - Toggle Remote Desktop to On.

## Detection Integration (RDP)

  - Wazuh Rule ID: 92653
  - Description: User: CORP\Administrator logged using Remote Desktop Connection (RDP) from ip:10.0.0.100.
    To view more details, go to Server management → Rules and search for 92653.
    To observe logs:
        Navigate to Explore → Discover.
        Search using either 4624 or the following query:

        data.win.system.eventID: 4624 AND data.win.eventdata.logonProcessName: User32

## Setup “Sensitive File” [project-x-dc]

  Log into [project-x-dc] and navigate to:

  `C:\Users\Administrator\Documents`

  Create a new folder named ProductionFiles.
  Inside ProductionFiles, create a new text file named secrets and add any desired content (for example, "Deeboodah!").

## Detection Integration (File Integrity Monitoring)

  Navigate to Server management → Endpoint Groups and select the Windows Agent Group.
  Go to the Files tab, then open agent.conf by clicking the pencil icon.
  Add the following XML snippet at the end of the file:

    <syscheck>
      <directories check_all="yes" report_changes="yes" realtime="yes">C:\Users\Administrator\Documents\ProductionFiles</directories>
      <frequency>60</frequency>
    </syscheck>

  Next, navigate to Endpoint security → File Integrity Monitoring.
        Under Inventory, verify that the file path is populated for the [project-x-dc] agent.
        Changing the content of secrets.txt should generate an event.

## Create Detection Alert (File Accssed)

  Navigate to Server management → Rules.
  Search for local_rules.xml and click on its name.
  Add the following XML snippet at the bottom of the file:
```
<group name="syscheck">
  <rule id="100002" level="10">
    <field name="file">secrets.txt</field>
    <match>modified</match>
    <description>File integrity monitoring alert - access to sensitive.txt file detected</description>
  </rule>
</group>
```
Save the file and restart the service.
Navigate to Explore → Alerting and select the Monitors tab.
Click Create monitor and title it "File Accssed".
Scroll down to Data source and add:

    wazuh-alerts-4.x-*

    Then select @timestamp as the Time Field.
    In the Data filter tab, add a query to monitor logs that contain:
        The full_log field with the term secrets.txt
        The syscheck.event field with the value modified.
    Add a trigger with:
        Severity level: 2 (High)
        Trigger condition: above 1.
    Click Create to save the monitor.

## Exfiltration to [project-x-attacker]

  On the Kali Machine:
        Enable SSH:
```
sudo systemctl start ssh.service
```
Create a new file to receive the exfiltrated data:

        touch /home/attacker/my_exfil.txt

   Detection Integration:
        The previously configured detection will capture changes to secrets.txt.

## Additional Steps for Exfiltration

  Open File Explorer on [project-x-dc] and navigate to:

`C:\Windows\System32`

Locate gpedit (Local Group Policy Editor), right-click, and select Run as Administrator.
In the Local Group Policy Editor:

   Navigate to:

  Computer Configuration → Administrative Template → Network → Lanman Workstation

  Double-click on Enable insecure guest logons.
  Select Enabled and apply the change.

Return to PowerShell and run:
```
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name AllowInsecureGuestAuth -Value 1 -Force
```
