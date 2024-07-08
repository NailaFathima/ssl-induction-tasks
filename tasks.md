
# How did I survive the tasks?

A brief description of what all hurdles I faced and how I overcame them to complete (most of) the tasks assigned as part of the prestigious SSL student admin inductions.

## Task 1 - Initial Setup

1. **Create an ubuntu vm**

I headed over to yt to familiarise myself with aws.
Followed a yt tutorial and succesfully created my own vm in aws (ubuntu 22.04) and ssh into it using `ssh -i naila.pem ubuntu@13.127.213.48`

2. **System Updates and Security**

Ran the commands `sudo apt update` to update the packages, and `sudo apt upgrade` to upgrade all currently installed packages to their latest versions.

_self note: sudo apt update does not install or update any packages, but rather refreshes the list of available packages and their versions from the repositories listed in /etc/apt/sources.list and /etc/apt/sources.list.d/  
`sudo systemctl restart ssh` is used to restart the SSH (Secure Shell) service on a Linux system._

## Task 2 - Enhanced SSH Security

1. **SSH Configuration**

- Disable root login. 
- Disable password-based authentication. 
- Enable and configure public key authentication. 

`sudo nano /etc/ssh/sshd_config` open the configuration files in nano and edit the following lines:  

PermitRootLogin no  
PasswordAuthentication no  
PubkeyAuthentication yes

- Restrict SSH access to specific IP addresses (e.g., your local IP or a specific range).

edit the _/etc/hosts.allow_ file using `sudo nano /etc/hosts.allow`  and add this line  
sshd,sshdfwd-X11: 192.168.1.

2. **Set up Fail2ban**

- Install Fail2ban using the following commands:    
`sudo apt update`  
`sudo apt install fail2ban`

- Some important commands:
`sudo systemctl enable fail2ban` used to enable the Fail2ban service to start automatically at boot on Linux systems using systemd.   
`sudo systemctl start fail2ban` used to manually start the Fail2ban service immediately on a Linux system using systemd.  
`systemctl status fail2ban.service` used to check the status of fail2ban.

- Configuring fail2ban: 

`cd /etc/fail2ban`,
`head -20 jail.conf` these commands are used to diplay the first 20 lines of jail.conf.

We cannot modify the configuration files directly. Instead we will be working on the _jail.local_ file. The _jail.conf_ file will be periodically updated as Fail2ban itself is updated, and will be used as a source of default settings for which you have not created any overrides.
   
   You can create _jail.local_ by copying _jail.config_ itself.  
   `sudo cp jail.conf jail.local`
    
   now, open the jail.local file in nano and make changes.     
   `sudo nano jail.local` 

**Important Parameters:**  

   **Bantime** - length of time that a client will be banned when they have failed to authenticate correctly. Default = 10minutes.   

   **Findtime and maxretry** - The maxretry variable sets the number of tries a client has to authenticate within a window of time defined by findtime, before being banned. With the default settings, the fail2ban service will ban a client that unsuccessfully attempts to log in 5 times within a 10 minute window.

   **Action** - this parameter specifies the action Fail2ban will take when it wants to impose a ban.  
   
   Here are the steps to configure it.
- Choose default action.  To change, just override value of 'action' with the interpolation to the chosen action shortcut (e.g.  action_mw, action_mwl, etc) in jail.local
- globally (section [DEFAULT]) or per specific section.  
   _(I have configured it to be: action = %(action_mw)s ; action_mw takes action and sends an email,)_

3. **Add our key so that we can ssh in as a user with superuser privileges**.  
Copy the contents of id_ra.pub and paste it in the authorized_keys file of the instance.    
`cat id_rsa.pub`  
`nano ~/.ssh/authorized_keys`

## Task 3 - Firewall and Network Security 

1. **Firewall Configuration:**

- Configure UFW to deny all incoming traffic except for SSH (on a non-default port, e.g., 2222), HTTP, and HTTPS.

      sudo nano /etc/default/ufw  
      sudo ufw default deny incoming  
      sudo ufw default allow outgoing  
      sudo ufw app list  
      sudo ufw allow openSSH  
      sudo ufw allow 2222  
      sudo ufw show added  
      sudo ufw allow http  
      sudo ufw allow https  
      sudo ufw allow from 192.168.1.105   
      sudo ufw enable  

- Ensure that the UFW logs are enabled for auditing purposes.

`sudo nano /etc/ufw/ufw.conf` and write out _LOGLEVEL=full_  
`sudo ufw reload`  
`sudo less /var/log/ufw.log` - used to view the log files, interactively.

`sudo ufw status verbose` - to check the status of ufw (uncomplicated firewall) . The default firewall configuration tool for Ubuntu is ufw . Developed to ease iptables firewall configuration, ufw provides a user-friendly way to create an IPv4 or IPv6 host-based firewall.

## Task 4 - User and Permission Management

1. **User Setup:** 
- Create the following users with the specified permissions: `exam_1, exam_2, exam_3`: Regular users with access only to their home directories.

      sudo useradd -m exam_1
      sudo passwd exam_1 
      sudo useradd -m exam_2  
      sudo passwd exam_2  
      sudo useradd -m exam_3  
      sudo passwd exam_3

- `examadmin`: User with root privileges.   

      sudo useradd -m examadmin  
      sudo passwd examadmin  
      sudo usermod -aG sudo examadmin 

_Self Note_
usermod: A command-line utility used to modify user account properties in Linux.
-a: Appends (adds) the user to the specified group without removing them from other groups.
-G: Specifies the supplementary groups (in this case, sudo)._

- `examaudit`: User with read-only access to all user home directories.

      sudo useradd -m examaudit     
      sudo passwd examaudit      
      sudo apt update       
      sudo apt install acl (Access Control Lists)     
Run the following code to set up the required permissions for examaudit     
`for user_home in /home/exam_1 /home/exam_2 /home/exam_3; do     sudo setfacl -m u:examaudit:rx $user_home; done`

2. **Home Directory Security:**
   - Ensure each user’s home directory is only accessible by that user.

         sudo chmod 700 /home/exam_1     
         sudo chmod 700 /home/exam_2                         
         sudo chmod 700 /home/exam_3     

      execute the following command to check if the permissions have been set properly    
      `for user_home in /home/exam_1 /home/exam_2 /home/exam_3; do
         ls -ld $user_home
      done`     

      OUTPUT:

         drwx------+ 2 exam_1 exam_1 4096 Jul  7 15:00 /home/exam_1     
         drwx------+ 2 exam_2 exam_2 4096 Jul  7 15:01 /home/exam_2     
         drwx------+ 2 exam_3 exam_3 4096 Jul  7 15:02 /home/exam_3


      chmod - changing mode ; 700 - owner can rwx but no one else can.

3. **Backup Script:** 
      - Create a script to back up the home directories of all `exam_*` users.
            - The script should run daily and store backups in a secure, compressed format.
            - Ensure that only `examadmin` can run this script.

         `sudo nano /usr/local/bin/backup_exam_users.sh` and write out the following script    

               #!/bin/bash                           
               if [ "$(whoami)" != "examadmin" ]; then            
                  echo "Only examadmin can run this script."       
                  exit 1     
               fi                
               BACKUP_DIR="/var/backups/exam_users"             
               DATE=$(date +"%Y-%m-%d")      
               mkdir -p $BACKUP_DIR     
               for user_home in /home/exam_*; do      
                  user=$(basename $user_home)          
                  backup_file="$BACKUP_DIR/${user}_${DATE}.tar.gz"     
                  tar -czf $backup_file -C /home $user      
                  echo "Backup of $user home directory saved to: $backup_file"           
               done     

         `sudo chmod +x /usr/local/bin/backup_exam_users.sh` - makes the file executable       
         `sudo chown examadmin:examadmin /usr/local/bin/backup_exam_users.sh` - ensures only examadmin can run the file   
         `sudo crontab -e` - to specify the timings of backup.      
         My specifications: 
         0 5 * * * /usr/local/bin/backup_exam_users.sh (everyday at 5am).

## Task 5 - Database Security 

1. **Database Setup:** 
   - Install MariaDB.     
         `sudo mysql_secure_installation` - used to improve the     security of mySql installlation. You will be asked a couple of questions when you run this command. I answered them as follows: 

         Remove anonymous users? [Y/n] Y    
         ... Success!    
         Disallow root login remotely? [Y/n] Y    
         ... Success!     
         Remove test database and access to it? [Y/n] Y     
         Dropping test database...    
         ... Success!     
         Removing privileges on test database...     
         ... Success!

      Answer 'n' to remaining questions.        

      `sudo systemctl status mariadb` - to check the status of MariaDB.      
      `sudo mysqladmin version` - to get information about mysql server and status.      

   - Create a database named `secure_onboarding`.

      `sudo mysql -u root` - to login to MariaDB as root (-p to prompt for pw)

      `CREATE DATABASE secure_onboarding;` - to create database.

      `SHOW DATABASES;` - to show all the databases existing in MariaDB.

   - Create a user with minimal privileges required to interact with the `secure_onboarding` database.   

         CREATE USER 'user1'@'localhost' IDENTIFIED BY '23579';    
         GRANT SELECT, INSERT, UPDATE, DELETE ON secure_onboarding.* TO 'user1'@'localhost';

      `sudo mysql -u user1 -p` - to login as user1

2. **Database Security:** 
   - **Disable remote root login.** 
         Already done at the time of installation. But then wanted to overcomplicate things so started executing the following commands which ultimately I dont know what it did.       
         (**Warning:** the next 50 - 100 lines basically involves me trying to solve my self-created problem :)

            MariaDB [(none)]> UPDATE mysql.user SET Host='localhost' WHERE User='root' and Host='%';                       
            ERROR 1356 (HY000): View 'mysql.user' references invalid table(s) or column(s) or function(s) or definer/invoker of view lack rights to use them.

      I tried to make a view of the mysql.user table.

            MariaDB [(none)]> SHOW FULL TABLES IN mysql WHERE TABLE_TYPE = 'VIEW';
            +-----------------+------------+
            | Tables_in_mysql | Table_type |
            +-----------------+------------+
            | user            | VIEW       |
            +-----------------+------------+

            MariaDB [(none)]> SHOW CREATE VIEW mysql.user\G

            MariaDB [(none)]> UPDATE mysql_innodb_table.user SET Host='localhost' WHERE User='root' AND Host='%';
            ERROR 1146 (42S02): Table 'mysql_innodb_table.user' doesn't exist

            MariaDB [(none)]> DELETE FROM mysql.user WHERE User='root' AND Host='%';
            Query OK, 0 rows affected (0.001 sec)

            MariaDB [(none)]> CREATE USER 'root'@'localhost' IDENTIFIED BY '34567';
            ERROR 1396 (HY000): Operation CREATE USER failed for 'root'@'localhost'

      Now, I switched to the mysql database.

         MariaDB [mysql]> SELECT * FROM user;   

         MariaDB [mysql]> CREATE USER 'admin'@'localhost' IDENTIFIED BY 'your_password';      

         MariaDB [mysql]> GRANT ALL PRIVILEGES ON `*.*` TO 'admin'@'localhost' WITH GRANT OPTION;     
         Query OK, 0 rows affected (0.001 sec)           

         MariaDB [mysql]> FLUSH PRIVILEGES;      
         Query OK, 0 rows affected (0.001 sec)

   - **Ensure that MariaDB is only accessible from localhost and not even from a LAN machine.**

         sudo nano /etc/mysql/mariadb.conf.d/50-server.cnf    
         Write out the following to the file. (127.0.0.1 is the loop-back address or self address).
         [mysqld]
         bind-address = 127.0.0.1
         

      `sudo systemctl restart mariadb` - to restart MariaDB with new changes.

   - **Set up regular automated backups of the database.**

         sudo nano /usr/local/bin/backup_mariadb.sh
         sudo chmod +x /usr/local/bin/backup_mariadb.sh
         sudo crontab -e

      and add the following line to the crontab : `0 0 * * * /usr/local/bin/backup_mariadb.sh`

## Task 6 - VPN Configuration

1. **VPN Setup:**
   - **Install and configure WireGuard as a VPN server.**

         sudo apt update
         sudo apt install wireguard

      Important commands:

         sudo systemctl start wg-quick@wg0
         sudo systemctl enable wg-quick@wg0
         sudo systemctl status wg-quick@wg0

   - Create VPN credentials for at least two users.

         wg genkey | tee client1_private_key | wg pubkey > client1_public_key
         wg genkey | tee client2_private_key | wg pubkey > client2_public_key
         wg genkey | tee server_private_key | wg pubkey > server_public_key

      _Self Note_:  

         wg genkey: This command generates a new private key for WireGuard.    
         |: It takes the output of the command on its left (wg genkey) and passes it as input to the command on its right (tee client1_private_key).    
         tee client1_private_key: This command takes the input it receives (the private key generated by wg genkey) and writes it to a file named client1_private_key.       
         |: Another pipe. It takes the output of the tee command (which is the private key) and passes it as input to the next command (wg pubkey).      
         wg pubkey: This command reads the private key from its input and generates the corresponding public key.    
         client1_public_key: This redirects the output of the wg pubkey command (the public key) to a file named client1_public_key.

      `sudo nano /etc/wireguard/wg0.conf` and write out the following

      
         [Interface]
         Address = 10.200.200.1/24
         # IP address for the VPN server
         PrivateKey = CL/zLGEDrBnGeX8/YfzmOR1dXf3NPlxAv0GsxQCMrno=
         ListenPort = 51820
         # Port to listen for incoming connections

         # Client1 configuration
         [Peer]
         PublicKey = tMoBPVYBQer2hztI6FCA5NpAic09Hz9ELWidKiCQQS0=
         AllowedIPs = 10.200.200.2/32
         # IP address for Client1
         # Add additional AllowedIPs for local network and internet access

         # Client2 configuration
         [Peer]
         PublicKey = SnwFO01u1dOeRcvDkhRkf5Z7xReN3MZxQSu7l2vulwo=
         AllowedIPs = 10.200.200.3/32
         # IP address for Client2
         # Add additional AllowedIPs for local network and internet access

      `sudo sysctl -p /etc/sysctl.conf` - to read the /etc/sysctl.conf file and applies each of the kernel parameters specified within it.

   - **Ensure that the VPN allows access to the local network and the internet.**

      `sudo sysctl -w net.ipv4.ip_forward=1` - to enable ipv4 forwarding.
   - **Share one credential to the admins for testing**

## Task 7 - Web Server Deployment and Secure Configuration  (Pro Pain :/)

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

Installed nginx.

Created two users namely appuser and app2user.

      sudo adduser --system --group --disabled-login appuser     
      sudo adduser --system --group --disabled-login app2user

Installed app1 `wget https://do.edvinbasil.com/ssl/app.sha256.sig`     
Checked the sha256 sum of app1 and modified the inbound rules in aws to allow port 8008.

      ubuntu@ip-172-31-35-234:~$ sha256sum -c app.sha256.sig
      sha256sum: app.sha256.sig: no properly formatted SHA256 checksum lines found
      ubuntu@ip-172-31-35-234:~$ echo '52ef28f5606aa8ad4aee09e723ee9b08f62fdca0aa86c1c01c1bb4d61a46e47c app' > app.sha256.sig 
      ubuntu@ip-172-31-35-234:~$ sha256 app
      Command 'sha256' not found, but can be installed with:
      sudo apt install hashalot
      ubuntu@ip-172-31-35-234:~$ sha256sum app
      52ef28f5606aa8ad4aee09e723ee9b08f62fdca0aa86c1c01c1bb4d61a46e47c  app
      ubuntu@ip-172-31-35-234:~$ cat app.sha256.sig
      52ef28f5606aa8ad4aee09e723ee9b08f62fdca0aa86c1c01c1bb4d61a46e47c app
      ubuntu@ip-172-31-35-234:~$ sha256sum -c app.sha256.sig
      app: OK
      ubuntu@ip-172-31-35-234:~$ chmod +x app
      ubuntu@ip-172-31-35-234:~$ ./app
      Listening on port 8008

Yay!!! app1 started working on port 8008.

I tried installing app2, but idk if I installed it properly. Anyways with hope I proceed to configure my nginx. I culd not get the ssl certificate from certbot. Bro just kept on rejecting me. I tried to befriend certbot. But nah, he didnt issue me the certificate. After hours of convincing him, I gave up.













