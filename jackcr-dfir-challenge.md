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
  * ``$ mactime -b ENG_all -d -z UTC >> ENG_all.chronological`` -> se pierden aquí archivos
  * ``Nov 26 2012 23:01:54,0,macb,---a-------I---,0,0,11722,"[ENG MFT FILE_NAME] WINDOWS\Prefetch\SYMANTEC-1.43-1[2].EXE-3793B625.pf (Offset: 0x17779800)"``

### Phishing E-mail Artifacts

* ``$ strings -td -el -a ENG-USTXHOU-148/memdump.bin > stringsUnicode.txt``
* ``$ strings -td -a jackcr-dfir-challenge/ENG-USTXHOU-148/memdump.bin > stringsAscii.txt``
* ``$ more strings.txt | grep 58.64.132.141 -A 10``
* ``$ more strings.txt | grep "Subject: Immediate Action" -A 30``
* play with grep
[PowerShell](https://www.powershellgallery.com/packages/PowerSploit/1.0.0.0/Content/ReverseEngineering%5CGet-Strings.ps1)
[Windows Sysinternals strings.exe](ttps://docs.microsoft.com/en-us/sysinternals/downloads/strings)

```bash
$ more strings.txt | grep 58.64.132.141 -A 10
<SNIP>
34435239 Received: from d0793h (d0793h.petro-markets.info [58.64.132.141])
34435306        by ubuntu-router (8.14.3/8.14.3/Debian-9.2ubuntu1) with SMTP id qAQK06Co005842;
34435388        Mon, 26 Nov 2012 15:00:07 -0500
34435422 Message-ID: <FCE1C36C7BBC46AFB7C2A251EA868B8B@d0793h>
34435477 From: "Security Department" <isd@petro-markets.info>
34435531 To: <amirs@petro-market.org>, <callb@petro-market.org>,
34435588         <wrightd@petro-market.org>
34435624 Subject: Immediate Action
34435651 Date: Mon, 26 Nov 2012 14:59:38 -0500
34435690 MIME-Version: 1.0
34435709 Content-Type: multipart/alternative;
<SNIP>

$ more strings.txt | grep "Subject: Immediate Action" -A 20
<SNIP>
417911336 Subject: Immediate Action
417911363 Date: Mon, 26 Nov 2012 14:59:38 -0500
417911402 MIME-Version: 1.0
417911421 Content-Type: multipart/alternative;
417911459       boundary="----=_NextPart_000_0015_01CDCBE6.A7B92DE0"
417911514 X-Priority: 3
417911529 X-MSMail-Priority: Normal
417911556 X-Mailer: Microsoft Outlook Express 6.00.2900.5512
417911608 X-MimeOLE: Produced By Microsoft MimeOLE V6.00.2900.5512
417911666 Return-Path: isd@petro-markets.info
417911703 X-OriginalArrivalTime: 26 Nov 2012 20:00:08.0432 (UTC) FILETIME=[A2ABBF00:01CDCC10]
417911790 This is a multi-part message in MIME format.
417911838 ------=_NextPart_000_0015_01CDCBE6.A7B92DE0
417911883 Content-Type: text/plain;
417911910       charset="iso-8859-1"
417911933 Content-Transfer-Encoding: quoted-printable
417911980 Attn: Immediate Action is Required!!
417912020 The IS department is requiring that all associates update to the new =
417912092 version of anti-virus.  This is critical and must be done ASAP!  Failure =
417912168 to update anti-virus may result in negative actions.
417912224 Please download the new anti-virus and follow the instructions.  Failure =
417912300 to install this anti-virus may result in loosing your job!
417912362 Please donwload at http://58.64.132.8/download/Symantec-1.43-1.exe
417912432 Regards,
417912442 The IS Department
<SNIP>
```

### Examining the 6to4 Service

* Suspicious activity near Symantec in ENG_all.chronological
  * I should be seeing things I am not
* 6to4
  * ``Thu May 22 2008 09:57:03,0,macb,---------------,0,0,0,"[ENG PE HEADER (dll)] 6to4ex.dll Process: svchost.exe/PID: 1024/PPID: 680/Process POffset: 0x020b3da0/DLL Base: 0x10000000"``
  * ``Fri Nov 23 2012 16:32:04,100352,.acb,---a-----------,0,0,24458,"[ENG MFT FILE_NAME] WINDOWS\system32\6to4svc.dll (Offset: 0xb3fd800)"``
  * ``Fri Nov 23 2012 16:32:04,100352,.ac.,---a-----------,0,0,24458,"[ENG MFT STD_INFO] WINDOWS\system32\6to4svc.dll (Offset: 0xb3fd800)"``

* printkey plugin

```bash
vol.exe -f ENG-USTXHOU-148/memdump.bin printkey -K "ControlSet001\Services\6to4"
Volatility Foundation Volatility Framework 2.6
Legend: (S) = Stable   (V) = Volatile
----------------------------
Registry: \Device\HarddiskVolume1\WINDOWS\system32\config\system
Key name: 6to4 (S)
Last updated: 2012-11-26 23:01:55 UTC+0000

Subkeys:
  (S) Parameters
  (S) Security
  (V) Enum

Values:
REG_DWORD     Type            : (S) 288
REG_DWORD     Start           : (S) 2
REG_DWORD     ErrorControl    : (S) 1
REG_EXPAND_SZ ImagePath       : (S) %SystemRoot%\System32\svchost.exe -k netsvcs -> not much info...
REG_SZ        DisplayName     : (S) Microsoft Device Manager
REG_SZ        ObjectName      : (S) LocalSystem
REG_SZ        Description     : (S) Service Description
```

* Get the dll

```bash
vol.exe -f ENG-USTXHOU-148/memdump.bin printkey -K "ControlSet001\Services\6to4\Parameters"
Legend: (S) = Stable   (V) = Volatile
----------------------------
Registry: \Device\HarddiskVolume1\WINDOWS\system32\config\system
Key name: Parameters (S)
Last updated: 2012-11-26 23:01:54 UTC+0000
Subkeys:
Values:
REG_EXPAND_SZ ServiceDll      : (S) C:\WINDOWS\system32\6to4ex.dll
```

* Nearby the Symantec the 6to4ex.dll was accessed
  * ``Mon Nov 26 2012 23:01:54,100895,.ac.,---a-----------,0,0,8610,"[ENG MFT FILE_NAME] WINDOWS\system32\6to4ex.dll (Offset: 0x324c800)"``
  * ``Mon Nov 26 2012 23:01:54,100895,.ac.,-h-------------,0,0,8610,"[ENG MFT STD_INFO] WINDOWS\system32\6to4ex.dll (Offset: 0x324c800)"``
* Threads are missing...???
* List process 1024 dlls
  * ``vol.exe -f ENG-USTXHOU-148/memdump.bin dlllist -p 1024`` -> ``0x10000000    0x1c000        0x1 c:\windows\system32\6to4ex.dll``
* check if there is a 6to4 service running
  * ``vol.exe -f ENG-USTXHOU-148/memdump.bin dlllist svcscan`` -> svchost.exe pid:   1024; Command line : C:\WINDOWS\System32\svchost.exe -k netsvcs; 0x10000000 0x1c000 0x1 c:\windows\system32\6to4ex.dll

## Finding an Active Attacker

* look for artifacts in close temporal proximity

```bash
Mon Nov 26 2012 23:03:10,0,macb,-------------D-,0,0,7556,"[ENG MFT FILE_NAME] WINDOWS\webui (Offset: 0x1bc21000)"
Mon Nov 26 2012 23:03:21,55808,.a..,---a-----------,0,0,24145,"[ENG MFT STD_INFO] WINDOWS\system32\ipconfig.exe (Offset: 0xc826400)"
Mon Nov 26 2012 23:06:34,0,macb,---a-----------,0,0,11710,"[ENG MFT FILE_NAME] WINDOWS\ps.exe (Offset: 0x15983800)"
Mon Nov 26 2012 23:07:53,0,macb,---a-------I---,0,0,11727,"[ENG MFT FILE_NAME] WINDOWS\Prefetch\NET.EXE-01A53C2F.pf (Offset: 0x12d588)"
```

* webui folder contents
  * mactime acting weird
  * cat ENG_all | grep -i webui | grep FILE_NAME -> output good
  * mactime -b ENG_all -d -z UTC | grep -i webui | grep FILE_NAME -> no output
  * maybe some ENG REGISTRY not well parsed

* The Policy\Secrets key of the SECURITY hive was accessed the same time as the GS.EXE file was executed. Using the cachedump plugin, gain insight into what password hashes the attacker might have been able to access
* cachedump: decrypt domain hashes

```bash
vol.exe -f ENG-USTXHOU-148/memdump.bin cachedump
administrator:00c2bcc2230054581d3551a9fdcf4893:petro-market:petro-market.org
callb:178526e1cb2fdfc36d764595f1ddd0f7:petro-market:petro-market.org
```

* gain more insight into the GS.EXE executable by extracting it from memory

```bash
vol.exe -f ENG-USTXHOU-148/memdump.bin filescan | grep -i \\gs.exe
0x00000000020bb938      1      0 R--r-d \Device\HarddiskVolume1\WINDOWS\webui\gs.exe
0x0000000018571938      1      0 R--r-d \Device\HarddiskVolume1\WINDOWS\webui\gs.exe
```

* pass that offset (0x020bb938) to the dumpfiles plugin to extract the memory manager's cached copy of this file from disk and extract strings to get insight on what the executable does.

```bash
vol.exe -f ENG-USTXHOU-148/memdump.bin dumpfiles -Q 0x020bb938 -D evidence/ENG_OUT/
Volatility Foundation Volatility Framework 2.6
ImageSectionObject 0x020bb938   None   \Device\HarddiskVolume1\WINDOWS\webui\gs.exe
DataSectionObject 0x020bb938   None   \Device\HarddiskVolume1\WINDOWS\webui\gs.exe
```

## Mapping Remote File Shares

* Artifacts a few minutes later the download
  * Ping
  * Sysinternals psexec
  * Creation of [ENG MFT FILE_NAME] WINDOWS\webui\system.dll]
  * Network registry key was modified + symbolik link creation ``[ENG SYMLINK] Z:->\Device\LanmanRedirector\;Z:00000000000003e7\172.16.223.47\z POffset: 185218568/Ptr: 1/Hnd: 0`` -> share mounted over the network
  * When Windows maps a remote drive like this, a subkey named z should be created under the Network key
* examine Network\z
  * recover the IP address of the machine that contains the remote share
  * recover the username used to connect to the remote share -> verifying the accounts that were compromised
  * 1 for ConnectionType means drive redirection, and 4 for DeferFlags means the credentials have been saved
* the attacker acquired valid credentials and used them to mount remote file shares

```bash
vol.exe -f ENG-USTXHOU-148/memdump.bin printkey -K "network\z"
Volatility Foundation Volatility Framework 2.6
Legend: (S) = Stable   (V) = Volatile

----------------------------
Registry: \Device\HarddiskVolume1\WINDOWS\system32\config\default
Key name: z (S)
Last updated: 2012-11-27 00:48:20 UTC+0000

Subkeys:

Values:
REG_SZ        RemotePath      : (S) \\172.16.223.47\z
REG_SZ        UserName        : (S) PETRO-MARKET\ENG-USTXHOU-148$
REG_SZ        ProviderName    : (S) Microsoft Windows Network
REG_DWORD     ProviderType    : (S) 131072
REG_DWORD     ConnectionType  : (S) 1
REG_DWORD     DeferFlags      : (S) 4
```

* Using handles plugin in combination with symlinscan to get the exact time when the remote share was mounted

``λ vol.exe -f ENG-USTXHOU-148\memdump.bin --profile=WinXPSP3x86 handles -t File`` -> filter by Mup or LanmanRedirector
``0x8223af28   1024     0x167c   0x100000 File             \Device\LanmanRedirector\;R:000000000000c21e\172.16.150.10\ITShare``
``0x8204b410   1024     0x180c   0x100000 File             \Device\LanmanRedirector\;Z:00000000000003e7\172.16.223.47\z``

``λ vol.exe -f ENG-USTXHOU-148\memdump.bin --profile=WinXPSP3x86 symlinkscan``
``0x000000000ab96398      1      0 2012-11-27 01:56:50 UTC+0000   R:                   \Device\LanmanRedirector\;R:0...00c21e\172.16.150.10\ITShare``
``00000b0a3608      1      0 2012-11-27 00:48:19 UTC+0000   Z:                   \Device\LanmanRedirector\;Z:00000000000003e7\172.16.223.47\z``

## Scheduled Jobs for Hash Dumping

* Inside webui folder there was also system5.bat -> [ENG MFT FILE_NAME] WINDOWS\webui\system5.bat (Offset: 0x10b97800)"

```bash
λ type eng_files\file.0x10b97800.data0.dmp
@echo off
copy c:\windows\webui\wc.exe c:\windows\system32
at 19:30 wc.exe -e -o h.out
```

* scheduled job At1.job in the timeline just after the creation of system5.bat -> [ENG MFT FILE_NAME] WINDOWS\Tasks\At1.job (Offset: 0x12ab2000)
* artifacts created: the created process, the At1.job file being accessed, the creation of the h.out file, and the creation of the WC.EXE-06BFE764.pf
* examine the contents of the "Microsoft\SchedulingAgent" key
  * ``vol.exe -f ENG-USTXHOU-148/memdump.bin printkey -K "Microsoft\SchedulingAgent"``

```bash
Registry: \Device\HarddiskVolume1\WINDOWS\system32\config\software
Key name: SchedulingAgent (S)
Last updated: 2012-11-27 01:30:00 UTC+0000

Subkeys:

Values:
REG_EXPAND_SZ TasksFolder     : (S) %SystemRoot%\Tasks
REG_EXPAND_SZ LogPath         : (S) %SystemRoot%\SchedLgU.Txt
REG_DWORD     MinutesBeforeIdle : (S) 15
REG_DWORD     MaxLogSizeKB    : (S) 32
REG_SZ        OldName         : (S) ENG-USTXHOU-148
REG_DWORD     DataVersion     : (S) 3
REG_DWORD     PriorDataVersion : (S) 0
REG_BINARY    LastTaskRun     : (S)
0x00000000  dc 07 0b 00 01 00 1a 00 13 00 1e 00 01 00 00 00   ................
```

* Gain further insight into wc.exe -> try to extract the file referenced in the bat script h.out
  * from mtfparser -> ``[ENG MFT FILE_NAME] WINDOWS\system32\h.out (Offset: 0x12ab2800)``

```bash
λ ls eng_files/*0x12ab2800*
eng_files/file.0x12ab2800.data0.dmp
λ more eng_files\file.0x12ab2800.data0.dmp
callb:PETRO-MARKET:115B24322C11908C85140F5D33B6232F:40D1D232D5F731EA966913EA458A16E7
ENG-USTXHOU-148$:PETRO-MARKET:00000000000000000000000000000000:D6717F1E5252FA87ED40AF8C46D8B1E2
sysbackup:current:C2A3915DF2EC79EE73108EB48073ACB7:E7A6F270F1BA562A90E2C133A95D2057
```

## Overlaying Attack Artifacts

* Search for similar filenames to the ENG machine within the other timelines
  * ``0|[FLD MFT FILE_NAME] WINDOWS\Prefetch\SYMANTEC-1.43-1[2].EXE-330FB7E3.pf``
  * ``0|[FLD PE HEADER (dll)] 6to4ex.dll``
  * The artifacts found in the FLD-SARIYADH-43 timeline continue to correlate closely with the events seen earlier in the ENG-USTXHOU-148 timeline, including the following
  * ``Tue Nov 27 2012 00:17:58,0,macb,---a-------I---,0,0,12011,"[FLD MFT FILE_NAME] WINDOWS\Prefetch\SYMANTEC-1.43-1[2].EXE-330FB7E3.pf (Offset: 0x1d75cc00)"``
  * ``Tue Nov 27 2012 00:17:58,0,.a..,0,0,0,0,"[FLD Registry file.4.0x822350c0.vacb] $$$PROTO.HIV\ControlSet001\Enum\Root\LEGACY_6TO4"``
  * ...
* Different artifacts placed by the attacker
  * ``[FLD MFT FILE_NAME] WINDOWS\system1.bat (Offset: 0x1787f000)`` -> set up the C:/WINDOWS/webui folder as a network share

```bash
λ ls fld_files/*0x1787f000*
fld_files/file.0x1787f000.data0.dmp

λ more fld_files\file.0x1787f000.data0.dmp
@echo off
mkdir c:\windows\webui
net share z=c:\windows\webui /GRANT:sysbackup,FULL
```

* ``[FLD MFT FILE_NAME] WINDOWS\webui\system2.bat (Offset: 0x1787fc00)`` -> run gs.exe (gsecdump.exe) and dump the output into a fake svchost.dll file -> password hash dumping

```bash
λ more fld_files\file.0x1787fc00.data0.dmp
@echo off
c:\windows\webui\gs.exe -a >> c:\windows\webui\svchost.dll
```

* ``[FLD MFT FILE_NAME] WINDOWS\webui\system3.bat (Offset: 0x1b773000)`` -> generate a file listing for all files with a dwg extension (autocad), save it into a fake https.dll file
 
```bash
λ more fld_files\file.0x1b773000.data0.dmp
@echo off
dir /S C:\*.dwg > c:\windows\webui\https.dll
```

* ``[FLD MFT FILE_NAME] WINDOWS\webui\system4.bat (Offset: 0x1b773400)`` -> use WinRAR to copy, compress, and encrypt the files found in the C:/Engineering/Designs/directory whose filename contains the word Pumps -> prepare to exfiltrate data

```bash
λ more fld_files\file.0x1b773400.data0.dmp
@echo off
c:\windows\webui\ra.exe a -hphclllsddlsdiddklljh -r c:\windows\webui\netstat.dll "C:\Engineering\Designs\Pumps" -x*.dll
```

* ``[FLD MFT FILE_NAME] WINDOWS\webui\system5.bat (Offset: 0x1b773800)`` -> persistence, copy wc.exe to system32 and run it as an scheduled job

```bash
λ more fld_files\file.0x1b773800.data0.dmp
@echo off
copy c:\windows\webui\wc.exe c:\windows\system32
at 04:30 wc.exe -e -o h.out
```

* ``[FLD MFT FILE_NAME] WINDOWS\system6.bat (Offset: 0x1787f800)`` -> reconnaisance

```bash
λ ls fld_files/*0x1787f800*
fld_files/file.0x1787f800.data0.dmp

λ more fld_files\file.0x1787f800.data0.dmp
@echo off
ipconfig /all >> c:\windows\webui\system.dll
net share >> c:\windows\webui\system.dll
net start >> c:\windows\webui\system.dll
net view >> c:\windows\webui\system.dll
```

* Connection to IIS machine ``Tue Nov 27 2012 00:46:10,0,macb,---------------,0,0,0,"[FLD SYMLINK] Z:->\Device\LanmanRedirector\;Z:00000000000003e7\172.16.223.47\z POffset: 284628328/Ptr: 1/Hnd: 0"`` -> evidence that the attackers were accessing IIS-SARIYADH-03

## Decoding the Network Data

* Wireshark
  * ``ip.addr==58.64.132.141`` -. Gh0st........x.Kc``....@....\..L@:8..,39U! 19[.."....!(+.`.V......(Q!....`....Q...2...&..w.	.?@CI.a..8C.Q!.)B...@9....f.a........L.I.K.--..../.54.` ...1.o...Gh0st........x.c......Gh0st........x.....).)Gh0st........x.c......Gh0st........x.c......Gh0st........x.c.....
  * [Gh0st RAT](https://en.wikipedia.org/wiki/Gh0st_Rat)
  * un succesful things but useful filters
    * ip.addr==58.64.132.141 and tcp.flags.syn==1
    * http.request.method == 'GET'
* command and control traffic associated with the Gh0st RAT
* can be easily decoded using Chopshop -> see the commands that the attacker issued to the machine
