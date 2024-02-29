
<p align="center">
  <img src="https://certifications.tcm-sec.com/wp-content/uploads/2021/09/pnpt-new.png" />
</p>

## Hints:
![](images/IMG_0576.jpg)
## Exam tips:

Before the exam:

- Don't spend too much time on THM and HTB, external resources are useful, but not really for this exam. 
- Spend a little bit of time learning pivoting, xfreerdp and evil-winrm.
- The exam is not technically hard!!
- Install all the tools showed in the PEH course and try them. Or at least pick the tools you want to use and be familiar with them. Easiest is to use *pimpmykali* to install everything necessary.
- Only the PEH course is necessary to pass the exam, Windows Privilege Escalation could help, but not essential
- The following boxes taught me something different and were good practice: THM Wreath, HTB Sauna

During the exam:

- OSINT: 
	- dont overthink this portion, it is more "methodology" than tools
	- use [Username Anarchy](https://github.com/urbanadventurer/username-anarchy), watch this [video](https://www.youtube.com/watch?v=e2sX44PAQCw)
	- you have 2 options:
		- try password patterns and make password permutations
		- use the provided password list (will take some time)
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
    - Where does your account have access?
    - Search for passwords: in shares, in firefox go to saved password, secretsdump (lsas etc.)
    - Old vulnerabilities die hard 
    - ... Think outside the box 