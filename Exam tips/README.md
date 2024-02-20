
<p align="center">
  <img src="https://certifications.tcm-sec.com/wp-content/uploads/2021/09/pnpt-new.png" />
</p>

## Hints:
![](images/IMG_0576.jpg)
![](images/IMG_0597.png)
## Exam tips:

Before the exam:

- Install all the tools showed in the PEH course and try them. Or at least pick the tools you want to use and be familiar with them. Easiest is to use *pimpmykali* to install everything necessary.
- Read through the PEH, OSINT and EPP course notes once more
- The following boxes taught me something different and were good practice: THM Wreath, THM Holo, HTB Blackfield, HTB Sauna, HTB Forest, HTB Monteverde

During the exam:

- OSINT: try password and make password permutations from wordlist and found information, use [Username Anarchy](https://github.com/urbanadventurer/username-anarchy), watch this [video](https://www.youtube.com/watch?v=e2sX44PAQCw)
- AD - initial attack vectors: LLMNR poisoning, SMBRelay attack, IPv6 attack, Pass-back attack, Unauthenticated SMB Share Access
- AD - post compromise enumeration: ldapdomaindump, Bloodhound
- AD - post compromise attacks:
  - Search the quick wins:
    - Kerberoasting
    - Secretsdump
    - Pass the hash / pass the password
    - Token impersonation
  - No quick wins? Dig deep!
    - Enumerate (Bloodhound, etc.)
    - WDigest
    - GPP Credentials
    - Where does your account have access? like `sudo -l`
    - Search for passwords: in firefox go to saved password, secretsdump (lsas etc.)
    - Old vulnerabilities die hard 
    - ... Think outside the box 