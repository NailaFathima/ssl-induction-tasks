# Induction 2024

###  Instructions

- No extra points for completing the tasks faster. So take your time.
- (But keep in mind that you will be burning through your
credits for the `VM`. So don’t take forever ;P)
- You can **search for things online** if you have doubts If you cant find a solution online, Ask the others from your batch
- If you still cant find a solution or have doubts, Ask a **senior admin**
- **Please spend atleast 5-10 minutes** searching for a solution yourself before asking for help from others
- You can ask others for help but **don’t ask them to do it for you.**
- You **need not** do the Optional tasks, they are just for helping you learn more.
- There is no order, but do tasks 1,2 and 3 before the rest. This is to first setup a firewall and an ssh connection so that you can work in secure environment. You need to do 1,2,3 to pass

# Tasks

### 1. Initial Setup (4 pts)

1. **Create an Ubuntu VM in Azure:** (2pts)
   - Login with NITC Mail id and claim student benefits (either through github pro pack or azure student id), or debit card connect in AWS (they have free tier VMs).
   - Use any of the following Ubuntu versions: 20.04, 22.04.
   - Update the IP of your VM in the shared document, you will be assigned a domain for that IP.

2. **System Updates and Security:** (2pts)
   - Update the system packages.
   - Set up unattended upgrades to ensure the system always receives the latest security updates.

### 2. Enhanced SSH Security (6pts)

1. **SSH Configuration:** (1+1+2+1+1pts)
   - Disable root login. 
   - Disable password-based authentication. 
   - Enable and configure public key authentication. 
   - Restrict SSH access to specific IP addresses (e.g., your local IP or a specific range).
   - Set up fail2ban to protect against brute-force attacks. **(NEW)**
   - Add our key so that we can ssh in as a user with superuser privileges(will be shared later)

2. **Multi-Factor Authentication (MFA):** _[Optional]_
   - Install and configure Google Authenticator or any other MFA tool to secure SSH login. **(NEW)**

### 3. Firewall and Network Security (4pts)

_Warning, make sure you dont lock yourself out by blocking ssh. You would most likely have to reset and start over._
1. **Firewall Configuration:**
   - Configure UFW to deny all incoming traffic except for SSH (on a non-default port, e.g., 2222), HTTP, and HTTPS. **(NEW)**
   - Ensure that the UFW logs are enabled for auditing purposes. **(NEW)**
   - Readup more about iptables and how ufw works

2. **Intrusion Detection System (IDS):** _[Optional]_
   - Install and configure an IDS like Snort or Suricata. **(NEW)**
   - Set up rules to monitor and alert on suspicious activities.**(NEW)**

### 4. User and Permission Management (7 Pts)

1. **User Setup:** (3pts)
   - Create the following users with the specified permissions:
     - `exam_1, exam_2, exam_3`: Regular users with access only to their home directories.
     - `examadmin`: User with root privileges.
     - `examaudit`: User with read-only access to all user home directories.

2. **Home Directory Security:** (2pts)
   - Ensure each user’s home directory is only accessible by that user.
   - Set up quotas to limit the disk space each user can use. **(NEW)**

3. **Backup Script:** (2pts)
   - Create a script to back up the home directories of all `exam_*` users.
   - The script should run daily and store backups in a secure, compressed format.
   - Ensure that only `examadmin` can run this script.

### 6. Web Server Deployment and Secure Configuration (10pts)

Install NginX.
1. **Reverse Proxy Configuration:** (7pts)
   - Set up NginX as a reverse proxy for applications running on the VM.
   - Ensure that the applications is not directly accessible from the internet. These apps must run from a non-privileged user. Create a non privileged user before you proceed.

      - Get `app1` from [here](https://do.edvinbasil.com/ssl/app). Verify the sha256 signature from [here](https://do.edvinbasil.com/ssl/app.sha256.sig). `app1` runs (`chmod +x app1; ./app1`) on port 8008 and it prints the path it gets from the http request
      - Get `app2` from [here](https://gitlab.com/tellmeY/issslopen). This is the IsSSLOpen app, it runs on port 3000.

   - The task is to setup an `nginx` reverse proxy such that: (1.5+1.5+4pts) 
      - [https://x.ssl.airno.de/server1/](https://x.ssl.airno.de/app1/) should print 
      `SSL Onboarding. path: /server1/`
      - [https://x.ssl.airno.de/server2/](https://x.ssl.airno.de/app2/) should print 
      `SSL Onboarding. path: /`
      -  [https://x.ssl.airno.de/sslopen](https://x.ssl.airno.de/sslopen) should open *IsSSLOpen* app. Create a token for us to edit the page. (Read the docs for that issslopen)

   - Make sure these apps are not exposed to the internet directly, they should only be accessed through https (443 port) via NginX
2. **Content Security Policy (CSP):** (3pts)
   - Configure a robust CSP to mitigate cross-site scripting (XSS) attacks. **(NEW)**

### 7. Database Security (5pts)

1. **Database Setup:** (2pts)
   - Install MariaDB.
   - Create a database named `secure_onboarding`.
   - Create a user with minimal privileges required to interact with the `secure_onboarding` database.

2. **Database Security:** **(NEW)** (3pts)
   - Disable remote root login.
   - Ensure that MariaDB is only accessible from localhost and not even from a LAN machine.
   - Set up regular automated backups of the database.

### 8. VPN Configuration (6pts)

1. **VPN Setup:**
   - Install and configure WireGuard as a VPN server.
   - Create VPN credentials for at least two users.
   - Ensure that the VPN allows access to the local network and the internet.
   - Share one credential to the admins for testing

### Optional Task: Advanced Security Practices **(NEW)**

1. **AppArmor or SELinux:**
   - Enable and configure AppArmor or SELinux to enforce mandatory access controls on the system.

2. **Logging and Auditing:**
   - Install and configure an auditing tool like auditd.
   - Ensure that all security-related events are logged and can be reviewed.

3. **Log Analysis:**
   - Set up a log analysis tool like ELK Stack (Elasticsearch, Logstash, Kibana) to aggregate and analyze logs for security incidents.

### Optional Task: Load Balancer Setup

> Note: This task is just for people who want to try new things. This is more easier if you are familiar with basic concepts of Operating Systems (Scheduling). However it requires much less work than you think and is here for getting better perspective of real world web applications.
> 


You are given a simple [app](https://0x0.st/HO3x.py) which listens for `http` requests. Using your domain, setup an `nginx` reverse proxy for [https://x.ssl.airno.de/loadBalancer/](https://x.ssl.airno.de/app1/) to this app. (Save it as a python file, run it with `python3 app.py`)

- When you type your domain in the browser, something like `8080:y` should be shown where `y` represents the number of times you refreshed/accessed the page. `y` is reset each time you restart the app.
- Make 3 extra copies of the app and rename them according to your wish. Change the port number in each of the programs to `8081,8082,8083`. Now you should have 4 programs with port numbers `8080,8081,8082,8083`. Run all of these programs in parallel (you could use a script for that).
- Modify the reverse proxy to cater the requests to those 4 programs in a **round robin fashion**. This is called load balancing, that is you divide the requests to 4 identical programs running concurrently.

On your first request,
`8080:1` should be received

on your next request,

```bash
8081:1
8082:1
8083:1
8080:2
8081:2
8082:2
8083:2 

...
```

This should be the sequence of outputs, each time you refresh the page.

