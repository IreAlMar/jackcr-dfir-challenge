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

## Initial tracks

* An ids alert initially triggered on ENG-USTXHOU-148 for an established port 80 connection to a known bad ip address.
* From eng.connscan:
  * Offset(P)  Local Address      Remote Address   Pid
  * 0x01ffa850 172.16.150.20:1291 58.64.132.141:80 1024
  * 0x189e8850 172.16.150.20:1291 58.64.132.141:80 1024
* pslist | grep 1024
  * Offset(V)  Name         PID   PPID   Thds   Hnds   Sess  Wow64 Start                          Exit
  * 0x820b3da0 svchost.exe 1024    680     76   1645      0      0 2012-11-26 22:03:32 UTC+0000
  * 0x82045da0 wuauclt.exe 1628   1024      3    142      0      0 2012-11-26 22:04:43 UTC+0000
  * 0x82049690 wc.exe       364   1024      1     27      0      0 2012-11-27 01:30:00 UTC+0000
* Wireshark
  * ``ip.addr==58.64.132.141`` -. Gh0st........x.Kc``....@....\..L@:8..,39U! 19[.."....!(+.`.V......(Q!....`....Q...2...&..w.	.?@CI.a..8C.Q!.)B...@9....f.a........L.I.K.--..../.54.` ...1.o...Gh0st........x.c......Gh0st........x.....).)Gh0st........x.c......Gh0st........x.c......Gh0st........x.c.....
  * [Gh0st RAT](https://en.wikipedia.org/wiki/Gh0st_Rat)
  * un succesful things but useful filters
    * ip.addr==58.64.132.141 and tcp.flags.syn==1
    * http.request.method == 'GET'

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
  * vol.exe -f ENG-USTXHOU-148/memdump.bin shellbags --profile=WinXPSP3x86 --output=body --machine=ENG --output-file=evidence/ENG_shellbags.body
  * vol.exe -f FLD-SARIYADH-43/memdump.bin shellbags --profile=WinXPSP3x86 --output=body --machine=FLD --output-file=evidence/FLD_shellbags.body
  * vol.exe -f DC-USTXHOU/memdump.bin shellbags --profile=Win2003SP0x86 --output=body --machine=DC --output-file=evidence/DC_shellbags.body

* timelineAuto.ps1 script
  * -D DUMP_DIR, --dump-dir=DUMP_DIR Directory in which to dump extracted files
  * -i  -i, --ignore-case Ignore case in pattern match
  * -r REGEX, --regex=REGEX Dump files matching REGEX
  * [timeline.py](https://github.com/williballenthin/python-registry)
  * [log2timeline](https://code.google.com/p/log2timeline/)
  * vol.exe -f FLD-SARIYADH-43/memdump.bin dumpfiles -i -r config.security$ -D evidence/REG/FLD-SARIYADH-43
