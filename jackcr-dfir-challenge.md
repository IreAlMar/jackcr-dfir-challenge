# jackcr-dfir-challenge

1. Who delivered the attack?
2. Who was the attack delivered too?
3. What time was the attack delivered?
4. What time was the attack executed?
5. What is the C2 ip Address?
6. What is the name of the dropper?
7. What is the name of the backdoor?
8. What is the process name the backdoor is running in?
9. What is the process id on all the machines the backdoor is installed on?
10. What usernames were used in this attack?
11. What level of access did the attacker have?
12. How was lateral movement performed?
13. What .bat scripts were placed on the machines?
14. What are the contents of each .bat script?
15. What other tools were placed on the machines by the attacker?
16. What directory was used by the attacker to drop tools?
17. Was the directory newly created or was it there prior to the attack?
18. What were the names of the exfiltrated files?
19. What did the exfiltrated files contain?
20. What time did winrar run?
21. What is the md5sum of pump1.dwg?
22. Which machines were compromised and need to be remediated?
23. Which user accounts were compromised and need to be remediated?
24. Are there additional machines that need to be analyzed?
25. Describe how each machine was involved in this incident and overall what happened.

## Combine Timelines

* mftparser: Scan for and parse potential MFT entries:
  * --output=text Output in this format
  * -D DUMP_DIR, --dump-dir=DUMP_DIR: Directory in which to dump extracted resident files
  * --machine=MACHINE Machine name to add to timeline header
  * --output-file=OUTPUT_FILE Write output in this file
  * vol.exe -f IIS-SARIYADH-03/memdump.bin mftparser --profile=Win2003SP0x86 --output=body -D iis_files --machine=IIS --output-file=evidence/IIS_mft.body
  * vol.exe -f ENG-USTXHOU-148/memdump.bin mftparser --profile=WinXPSP3x86 --output=body -D eng_files --machine=ENG --output-file=evidence/ENG_mft.body
  * vol.exe -f FLD-SARIYADH-43/memdump.bin mftparser --profile=WinXPSP3x86 --output=body -D fld_files --machine=FLD --output-file=evidence/FLD_mft.body
  * vol.exe -f DC-USTXHOU/memdump.bin mftparser --profile=Win2003SP0x86 --output=body -D dc_files --machine=DC --output-file=evidence/DC_mft.body

* timeliner: Creates a timeline from various artifacts in memory
  * vol.exe -f IIS-SARIYADH-03/memdump.bin timeliner --profile=Win2003SP0x86 --output=body --machine=IIS --output-file=evidence/IIS_timeliner.body
  * vol.exe -f ENG-USTXHOU-148/memdump.bin timeliner --profile=WinXPSP3x86 --output=body --machine=ENG --output-file=evidence/ENG_timeliner.body
  * vol.exe -f FLD-SARIYADH-43/memdump.bin timeliner --profile=WinXPSP3x86 --output=body --machine=FLD --output-file=evidence/FLD_timeliner.body
  * vol.exe -f DC-USTXHOU/memdump.bin timeliner --profile=Win2003SP0x86 --output=body --machine=DC --output-file=evidence/DC_timeliner.body

* shellbags: Prints ShellBags info
  * vol.exe -f IIS-SARIYADH-03/memdump.bin shellbags --profile=Win2003SP0x86 --output=body --machine=IIS --output-file=evidence/IIS_shellbags.body
  * vol.exe -f ENG-USTXHOU-148/memdump.bin shellbags --profile=WinXPSP3x86 --output=body --machine=ENG --output-file=evidence/ENG_shellbags.body -> no shellbags records
  * vol.exe -f FLD-SARIYADH-43/memdump.bin shellbags --profile=WinXPSP3x86 --output=body --machine=FLD --output-file=evidence/FLD_shellbags.body -> no shellbags records
  * vol.exe -f DC-USTXHOU/memdump.bin shellbags --profile=Win2003SP0x86 --output=body --machine=DC --output-file=evidence/DC_shellbags.body

## Scripting Registry Timelines

* timelineAuto.ps1 script
  * -D DUMP_DIR, --dump-dir=DUMP_DIR Directory in which to dump extracted files
  * -i  -i, --ignore-case Ignore case in pattern match
  * -r REGEX, --regex=REGEX Dump files matching REGEX
  * [timeline.py](https://github.com/williballenthin/python-registry)
  * [log2timeline](https://code.google.com/p/log2timeline/)
  * ``vol.exe -f FLD-SARIYADH-43/memdump.bin dumpfiles -i -r config.security$ -D evidence/REG/FLD-SARIYADH-43``

* combine the timeline files associated with each host
  * ``cat ENG*.body REG/ENG*.body >> ENG_all``
  * ``cat FLD*.body REG/FLD*.body >> FLD_all``
  * ``cat DC*.body >> DC_all``
  * ``cat IIS*.body >> IIS_all``

## Finding the Initial Infection Vector

* An ids alert initially triggered on ENG-USTXHOU-148 for an established port 80 connection to a known bad ip address.
* ``python vol.py –f ENG-USTXHOU-148/memdump.bin connscan``
* From ENG.connscan:
  * Offset(P)  Local Address      Remote Address   Pid
  * 0x01ffa850 172.16.150.20:1291 58.64.132.141:80 1024
  * 0x189e8850 172.16.150.20:1291 58.64.132.141:80 1024
* pslist | grep 1024
  * Offset(V)  Name         PID   PPID   Thds   Hnds   Sess  Wow64 Start                          Exit
  * 0x820b3da0 svchost.exe 1024    680     76   1645      0      0 2012-11-26 22:03:32 UTC+0000
  * 0x82045da0 wuauclt.exe 1628   1024      3    142      0      0 2012-11-26 22:04:43 UTC+0000
  * 0x82049690 wc.exe       364   1024      1     27      0      0 2012-11-27 01:30:00 UTC+0000
* Tracking Executed Programs
  * grep
    * -i, --ignore-case ignore case distinctions
  * cut
    * -d, --delimiter=DELIM use DELIM instead of TAB for field delimiter
    * -f, --fields=LIST select only these fields
  * bash: ``grep -i pf ENG_all |grep -i exe | cut -d\| -f2``
  * PowerShell: ``Get-Content evidence/ENG_all | Select-String -Pattern pf | Select-String -Pattern exe | ForEach-Object {$_.Line.split("|")[1]}` (could be .pf instead of pf)
  * suspicious .exe
    * [ENG MFT FILE_NAME] WINDOWS\Prefetch\SL.EXE-010E2A23.pf (Offset: 0x311400)
    * [ENG MFT FILE_NAME] WINDOWS\Prefetch\GS.EXE-3796DDD9.pf (Offset: 0x311800)
    * [ENG MFT FILE_NAME] WINDOWS\Prefetch\PS.EXE-09745CC1.pf (Offset: 0x924e400)
    * [ENG MFT FILE_NAME] WINDOWS\Prefetch\SYMANTEC-1.43-1[2].EXE-3793B625.pf (Offset: 0x17779800)
  * indications of network reconnaissance
    * [ENG MFT FILE_NAME] WINDOWS\Prefetch\PING.EXE-31216D26.pf (Offset: 0x311c00)
    * [ENG MFT FILE_NAME] WINDOWS\Prefetch\NET.EXE-01A53C2F.pf (Offset: 0x12d588)
    * [ENG MFT FILE_NAME] WINDOWS\Prefetch\IPCONFIG.EXE-2395F30B.pf (Offset: 0x136ab800)
  * job scheduling
    * [ENG MFT FILE_NAME] WINDOWS\Prefetch\AT.EXE-2770DD18.pf (Offset: 0x12ab2400)
* Somehow it is extracting the iehistory to body format. vol.exe -f ENG-USTXHOU-148/memdump.bin --profile=WinXPSP3x86 iehistory --output-file=evidence/ENG_iehistory.body
  * Process: 284 explorer.exe
  * Cache type "DEST" at 0xdcb69
  * Last modified: 2012-11-26 17:01:53 UTC+0000
  * Last accessed: 2012-11-26 23:01:54 UTC+0000
  * URL: callb@http://58.64.132.8/download/Symantec-1.43-1.exe
* [sudo apt install sleuthkit](http://www.sleuthkit.org/sleuthkit/man/mactime.html); [Windows binaries](http://www.sleuthkit.org/sleuthkit/download.php)
  * ``$ mactime -b ENG_all -d -z UTC >> ENG_all.chronological``
  * ``Nov 26 2012 23:01:54,0,macb,---a-------I---,0,0,11722,"[ENG MFT FILE_NAME] WINDOWS\Prefetch\SYMANTEC-1.43-1[2].EXE-3793B625.pf (Offset: 0x17779800)"``
* ``$ strings jackcr-dfir-challenge/ENG-USTXHOU-148/memdump.bin | grep 58.64.132.141 -C 3`` equivalent in Windows/PowerShell??
Check strins chapter 17
```text
--
This is a multi-part message in MIME
Received: from ubuntu-router ([172.16.150.8]) by dc-ustxhou.petro-market.org with Microsoft SMTPSVC(6.0.3790.0);
	 Mon, 26 Nov 2012 14:00:08 -0600
Received: from d0793h (d0793h.petro-markets.info [58.64.132.141])
	by ubuntu-router (8.14.3/8.14.3/Debian-9.2ubuntu1) with SMTP id qAQK06Co005842;
	Mon, 26 Nov 2012 15:00:07 -0500
Message-ID: <FCE1C36C7BBC46AFB7C2A251EA868B8B@d0793h>
--
isd@petro-markets.info
Produced By Microsoft MimeOLE V6.00.2900.5512
Normal
from d0793h (d0793h.petro-markets.info [58.64.132.141]) by ubuntu-router (8.14.3/8.14.3/Debian-9.2ubuntu1) with SMTP id qAQK06Co005842; Mon, 26 Nov 2012 15:00:07 -0500
<FCE1C36C7BBC46AFB7C2A251EA868B8B@d0793h>

```

* Wireshark
  * ``ip.addr==58.64.132.141`` -. Gh0st........x.Kc``....@....\..L@:8..,39U! 19[.."....!(+.`.V......(Q!....`....Q...2...&..w.	.?@CI.a..8C.Q!.)B...@9....f.a........L.I.K.--..../.54.` ...1.o...Gh0st........x.c......Gh0st........x.....).)Gh0st........x.c......Gh0st........x.c......Gh0st........x.c.....
  * [Gh0st RAT](https://en.wikipedia.org/wiki/Gh0st_Rat)
  * un succesful things but useful filters
    * ip.addr==58.64.132.141 and tcp.flags.syn==1
    * http.request.method == 'GET'
