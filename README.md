# Red Team Toolkit – Categorized Offensive Security Tools
**Created for Hack Tools Dark Community**

---

> **Disclaimer**  
> This content is intended for educational and ethical purposes only.  
> The tools listed below must only be used in environments where you have explicit permission to conduct security assessments.  
> Misuse of these tools may violate laws and lead to severe consequences.

*Red Team operations simulate real-world cyberattacks to assess and improve organizational defenses. Below is a curated and categorized toolkit commonly used by professional red teamers and ethical hackers.*

---

## 1. Privilege Escalation
- [BloodHound](https://github.com/BloodHoundAD/BloodHound) – Visualizes AD relationships for privilege escalation paths  
- [PEASS-ng](https://github.com/carlospolop/PEASS-ng) – Windows/Linux enumeration scripts (WinPEAS/LinPEAS)  
- [SharpUp](https://github.com/itm4n/SharpUp) – C# tool for privilege escalation enumeration  
- [ElevateKit](https://github.com/rasta-mouse/ElevateKit) – Elevation techniques toolkit  
- [Watson](https://github.com/rasta-mouse/Watson) – Finds vulnerable escalation opportunities  
- [SweetPotato](https://github.com/CCob/SweetPotato) – Token impersonation and privilege escalation  
- [LOLBAS](https://github.com/curated-intel/LOLBAS) – Living Off the Land Binaries list  
- [Loldrivers](https://github.com/mtth-bfft/loldrivers) – Database of vulnerable drivers  

## 2. Phishing
- [Gophish](https://github.com/gophish/gophish) – Powerful phishing campaign framework  
- [Evilginx2](https://github.com/kgretzky/evilginx2) – Phishing credentials and session cookies  
- [SEToolkit](https://github.com/trustedsec/social-engineer-toolkit) – Social engineering attacks toolkit  
- [EvilURL](https://github.com/UndeadSec/EvilURL) – IDN-based domain spoofing generator  
- [KingPhisher](https://github.com/rsmusllp/king-phisher) – Simulates real phishing campaigns  
- [Zphisher](https://github.com/htr-tech/zphisher) – Automated phishing toolkit  
- [SocialPhish](https://github.com/An0nUD4Y/SocialPhish) – GUI-based phishing tool  

## 3. Command and Control (C2)
- [Cobalt Strike](https://www.cobaltstrike.com/) – Full-featured red team threat emulation suite  
- [Sliver](https://github.com/BishopFox/sliver) – Modern open-source C2 in Go  
- [Covenant](https://github.com/cobbr/Covenant) – .NET C2 platform  
- [Pupy](https://github.com/n1nj4sec/pupy) – Cross-platform post-exploitation tool  
- [TrevorC2](https://github.com/trustedsec/trevorc2) – HTTP-based covert channel  

## 4. OSINT
- [Maltego](https://www.maltego.com/) – Graph-based OSINT analysis  
- [SpiderFoot](https://github.com/smicallef/spiderfoot) – Automated OSINT gathering  
- [OSINT Framework](https://osintframework.com/) – Index of OSINT tools and sources  
- [Recon-ng](https://github.com/lanmaster53/recon-ng) – Modular recon framework  
- [TheHarvester](https://github.com/laramies/theHarvester) – Harvest emails, subdomains, hosts  
- [PhoneInfoga](https://github.com/sundowndev/PhoneInfoga) – Investigate phone numbers  

## 5. Defense Evasion
- [AtomPePacker](https://github.com/hasherezade/atompepacker) – PE file packer for AV evasion  
- [Donut](https://github.com/TheWover/donut) – Convert .NET payloads to shellcode  
- [Mortar](https://github.com/curi0usJack/mortar) – In-memory shellcode loader  
- [MacroPack](https://github.com/sevagas/macro_pack) – Create obfuscated VBA macros  
- [TheFatRat](https://github.com/Screetsec/TheFatRat) – AV-bypassing backdoor generator  
- [Shellter](https://www.shellterproject.com/) – Dynamic PE file injection  
- [D1rkMtr Tools](https://github.com/D1rkMtr/d1rkmtr_tools) – Multiple evasion scripts and tools  

## 6. Credential Dumping
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) – Extracts Windows credentials from memory  
- [LaZagne](https://github.com/AlessandroZ/LaZagne) – Multiplatform credential recovery  
- [Pypykatz](https://github.com/skelsec/pypykatz) – Python LSASS dump parser  
- [Rubeus](https://github.com/GhostPack/Rubeus) – Advanced Kerberos abuse  
- [Responder](https://github.com/lgandx/Responder) – LLMNR, NetBIOS poisoning and credential capture  
- [SharpLAPS](https://github.com/Flangvik/SharpLAPS) – Dump local admin passwords from LAPS  
- [Dumpert](https://github.com/outflanknl/Dumpert) – LSASS dumping with direct system calls  
- [Clonevault](https://github.com/ShutdownRepo/clonevault) – Dump BitLocker recovery from AD  

## 7. Recon & Enumeration
- [Nuclei](https://github.com/projectdiscovery/nuclei) – Fast vulnerability scanner  
- [Assetfinder](https://github.com/tomnomnom/assetfinder) – Discover subdomains of a target  
- [Subfinder](https://github.com/projectdiscovery/subfinder) – Passive subdomain enumeration  
- [Nmap](https://nmap.org/) – Classic port scanner and network mapper  
- [crt.sh](https://crt.sh/) – Search certificate transparency logs  
- [Amass](https://github.com/owasp-amass/amass) – Attack surface mapping and DNS enumeration  
- [Shodan](https://www.shodan.io/) – Internet device search engine  
- [Censys](https://search.censys.io/) – Search exposed devices and certs  

## 8. Exfiltration
- [DNS-Exfiltration](https://github.com/maldevel/DNS-Exfiltration) – DNS tunneling for data exfil  
- [SharpExfiltrate](https://github.com/cedowens/SharpExfiltrate) – C# exfiltration tool  
- [DNSteal](https://github.com/maldevel/DNSteal) – Covert file exfiltration via DNS  
- [ICMPExfil](https://github.com/snovvcrash/ICMPExfil) – Transfer files via ICMP  
- [PingHexfil](https://github.com/JoelGMSec/PingHexfil) – Exfiltrate data via ping  
- [Powerexfil](https://github.com/BinaryAlert/powerexfil) – PowerShell exfiltration tool  
- [Pyexfil](https://github.com/kbandla/pyexfil) – Python-based exfiltration methods  
- [GithubC2](https://github.com/rasta-mouse/GithubC2) – GitHub-based C2 and data transfer  
- [VirusTotalC2](https://github.com/whalebone-io/VirusTotalC2) – Covert exfiltration via VirusTotal  

## 9. Exploit Development
- [IDA Pro](https://hex-rays.com/ida-pro/) – Reverse engineering and disassembly  
- [OllyDbg](http://www.ollydbg.de/) – 32-bit Windows debugger  
- [WinDbg](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/) – Microsoft debugger  
- [Immunity Debugger](https://www.immunityinc.com/products/debugger/) – Debugger with scripting support  
- [AFL Fuzzer](https://github.com/google/AFL) – Security-oriented fuzz testing  
- [GDB](https://www.gnu.org/software/gdb/) – GNU debugger for Linux  
- [Mona.py](https://github.com/corelan/mona) – Immunity Debugger plugin for exploit dev  

---

## Contribution
Have a tool you think should be here?  
Tested one in real engagements and want to share your experience?  
**Open an issue or PR to contribute – let’s build this list together.**
