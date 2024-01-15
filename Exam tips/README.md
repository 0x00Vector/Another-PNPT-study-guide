
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
- The following boxes taught me something different and were good practice: THM Wreath, THM Holo, HTB Blackfield, HTB Sauna, HTB Forest, HTB Monteverde, HTB Sizzle

During the exam:

- AD - initial attack vectors: LLMNR poisoning, SMBRelay attack, IPv6 attack
- AD - post compromise enumeration: ldapdomaindump, Bloodhound
- AD - post compromise attacks:
  - Search the quick wins:
    - Kerberoasting
    - Secretsdump
    - Pass the hash / pass the password
  - No quick wins? Dig deep!
    - Enumerate (Bloodhound, etc.)
    - Where does your account have access?
    - Old vulnerabilities die hard 
    - ... Think outside the box 