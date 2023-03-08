---
title: CyberDefence - BlackEnergy
date: 2023-03-08
draft: false
categories:
  - Walkthrough
tags:
  - Writeup
  - Walkthrough
  - Mobile
  - Android
  - CyberDefence
---

# Introduction

Challenge: https://cyberdefenders.org/blueteam-ctf-challenges/99#nav-questions

Setup: Windows VM on Linux Machine

## Scenario

A multinational corporation has been hit by a cyber attack that has led to the theft of sensitive data. The attack was carried out using a variant of the BlackEnergy v2 malware that has never been seen before. The company's security team has acquired a memory dump of the infected machine, and they want you to analyze the dump to understand the attack scope and impact.


## Tool Used

- [Volatility2](https://www.volatilityfoundation.org/26) (Windows Version): An advanced memory forensics framework


# Solution

I suggest trying the challenge by yourself before reading this post.
But if you are stuck reading some write-up is a good way to learn new things.


## Q1 Which volatility profile would be best for this machine?


For the first question, I used Volatility2 inside my Windows VM.

Running the option *-h* we can see all possible commands and plugins of volatility:

```
Volatility Foundation Volatility Framework 2.6
Usage: Volatility - A memory forensics analysis platform.

Options:
  -h, --help            list all available options and their default values.
                        Default values may be set in the configuration file
                        (/etc/volatilityrc)
  --conf-file=.volatilityrc
                        User based configuration file
  -d, --debug           Debug volatility
  --plugins=PLUGINS     Additional plugin directories to use (semi-colon
                        separated)
  --info                Print information about all registered objects
  --cache-directory=C:\Users\student/.cache\volatility
                        Directory where cache files are stored
  --cache               Use caching
  --tz=TZ               Sets the (Olson) timezone for displaying timestamps
                        using pytz (if installed) or tzset
  -f FILENAME, --filename=FILENAME
                        Filename to use when opening an image
  --profile=WinXPSP2x86
                        Name of the profile to load (use --info to see a list
                        of supported profiles)
  -l LOCATION, --location=LOCATION
                        A URN location from which to load an address space
  -w, --write           Enable write support
  --dtb=DTB             DTB Address
  --shift=SHIFT         Mac KASLR shift address
  --output=text         Output in this format (support is module specific, see
                        the Module Output Options below)
  --output-file=OUTPUT_FILE
                        Write output in this file
  -v, --verbose         Verbose information
  -g KDBG, --kdbg=KDBG  Specify a KDBG virtual address (Note: for 64-bit
                        Windows 8 and above this is the address of
                        KdCopyDataBlock)
  --force               Force utilization of suspect profile
  --cookie=COOKIE       Specify the address of nt!ObHeaderCookie (valid for
                        Windows 10 only)
  -k KPCR, --kpcr=KPCR  Specify a specific KPCR address

        Supported Plugin Commands:

                amcache         Print AmCache information
                apihooks        Detect API hooks in process and kernel memory
                atoms           Print session and window station atom tables
                atomscan        Pool scanner for atom tables
                auditpol        Prints out the Audit Policies from HKLM\SECURITY\Policy\PolAdtEv
                bigpools        Dump the big page pools using BigPagePoolScanner
                bioskbd         Reads the keyboard buffer from Real Mode memory
                cachedump       Dumps cached domain hashes from memory
                callbacks       Print system-wide notification routines
                clipboard       Extract the contents of the windows clipboard
                cmdline         Display process command-line arguments
                cmdscan         Extract command history by scanning for _COMMAND_HISTORY
                connections     Print list of open connections [Windows XP and 2003 Only]
                connscan        Pool scanner for tcp connections
                consoles        Extract command history by scanning for _CONSOLE_INFORMATION
                crashinfo       Dump crash-dump information
                deskscan        Poolscaner for tagDESKTOP (desktops)
                devicetree      Show device tree
                dlldump         Dump DLLs from a process address space
                dlllist         Print list of loaded dlls for each process
                driverirp       Driver IRP hook detection
                drivermodule    Associate driver objects to kernel modules
                driverscan      Pool scanner for driver objects
                dumpcerts       Dump RSA private and public SSL keys
                dumpfiles       Extract memory mapped and cached files
                dumpregistry    Dumps registry files out to disk
                editbox         Displays information about Edit controls. (Listbox experimental.)
                envars          Display process environment variables
                eventhooks      Print details on windows event hooks
                evtlogs         Extract Windows Event Logs (XP/2003 only)
                filescan        Pool scanner for file objects
                gahti           Dump the USER handle type information
                gditimers       Print installed GDI timers and callbacks
                gdt             Display Global Descriptor Table
                getservicesids  Get the names of services in the Registry and return Calculated SID
                getsids         Print the SIDs owning each process
                handles         Print list of open handles for each process
                hashdump        Dumps passwords hashes (LM/NTLM) from memory
                hibinfo         Dump hibernation file information
                hivedump        Prints out a hive
                hivelist        Print list of registry hives.
                hivescan        Pool scanner for registry hives
                hpakextract     Extract physical memory from an HPAK file
                hpakinfo        Info on an HPAK file
                idt             Display Interrupt Descriptor Table
                iehistory       Reconstruct Internet Explorer cache / history
                imagecopy       Copies a physical address space out as a raw DD image
                imageinfo       Identify information for the image
                impscan         Scan for calls to imported functions
                joblinks        Print process job link information
                kdbgscan        Search for and dump potential KDBG values
                kpcrscan        Search for and dump potential KPCR values
                ldrmod ules      Detect unlinked DLLs
                lsadump         Dump (decrypted) LSA secrets from the registry
                machoinfo       Dump Mach-O file format information
                malfind         Find hidden and injected code
                mbrparser       Scans for and parses potential Master Boot Records (MBRs)
                memdump         Dump the addressable memory for a process
                memmap          Print the memory map
                messagehooks    List desktop and thread window message hooks
                mftparser       Scans for and parses potential MFT entries
                moddump         Dump a kernel driver to an executable file sample
                modscan         Pool scanner for kernel modules
                modules         Print list of loaded modules
                multiscan       Scan for various objects at once
                mutantscan      Pool scanner for mutex objects
                notepad         List currently displayed notepad text
                objtypescan     Scan for Windows object type objects
                patcher         Patches memory based on page scans
                poolpeek        Configurable pool scanner plugin
                printkey        Print a registry key, and its subkeys and values
                privs           Display process privileges
                procdump        Dump a process to an executable file sample
                pslist          Print all running processes by following the EPROCESS lists
                psscan          Pool scanner for process objects
                pstree          Print process list as a tree
                psxview         Find hidden processes with various process listings
                qemuinfo        Dump Qemu information
                raw2dmp         Converts a physical memory sample to a windbg crash dump
                screenshot      Save a pseudo-screenshot based on GDI windows
                servicediff     List Windows services (ala Plugx)
                sessions        List details on _MM_SESSION_SPACE (user logon sessions)
                shellbags       Prints ShellBags info
                shimcache       Parses the Application Compatibility Shim Cache registry key
                shutdowntime    Print ShutdownTime of machine from registry
                sockets         Print list of open sockets
                sockscan        Pool scanner for tcp socket objects
                ssdt            Display SSDT entries
                strings         Match physical offsets to virtual addresses (may take a while, VERY verbose)
                svcscan         Scan for Windows services
                symlinkscan     Pool scanner for symlink objects
                thrdscan        Pool scanner for thread objects
                threads         Investigate _ETHREAD and _KTHREADs
                timeliner       Creates a timeline from various artifacts in memory
                timers          Print kernel timers and associated module DPCs
                truecryptmaster Recover TrueCrypt 7.1a Master Keys
                truecryptpassphrase     TrueCrypt Cached Passphrase Finder
                truecryptsummary        TrueCrypt Summary
                unloadedmodules Print list of unloaded modules
                userassist      Print userassist registry keys and information
                userhandles     Dump the USER handle tables
                vaddump         Dumps out the vad sections to a file
                vadinfo         Dump the VAD info
                vadtree         Walk the VAD tree and display in tree format
                vadwalk         Walk the VAD tree
                vboxinfo        Dump virtualbox information
                verinfo         Prints out the version information from PE images
                vmwareinfo      Dump VMware VMSS/VMSN information
                volshell        Shell in the memory image
                windows         Print Desktop Windows (verbose details)
                wintree         Print Z-Order Desktop Windows Tree
                wndscan         Pool scanner for window stations
                yarascan        Scan process or kernel memory with Yara signatures

```

I used this command to show the info about the image:

```
volatility_2.6_win64_standalone.exe -f CYBERDEF-567078-20230213-171333.raw imageinfo
```

output:

``` 
Volatility Foundation Volatility Framework 2.6
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : WinXPSP2x86, WinXPSP3x86 (Instantiated with WinXPSP2x86)
                     AS Layer1 : IA32PagedMemory (Kernel AS)
                     AS Layer2 : FileAddressSpace (C:\Users\student\Desktop\volatility_2.6_win64_standalone\CYBERDEF-567078-20230213-171333.raw)
                      PAE type : No PAE
                           DTB : 0x39000L
                          KDBG : 0x8054cde0L
          Number of Processors : 1
     Image Type (Service Pack) : 3
                KPCR for CPU 0 : 0xffdff000L
             KUSER_SHARED_DATA : 0xffdf0000L
           Image date and time : 2023-02-13 18:29:11 UTC+0000
     Image local date and time : 2023-02-13 10:29:11 -0800

```

**The answer is:**
>WinXPSP2x86

## Q2 How many processes were running when the image was acquired?

I have used this command to show the list of the process:
```
volatility_2.6_win64_standalone.exe -f CYBERDEF-567078-20230213-171333.raw psxview
```

this is the output:
```

Volatility Foundation Volatility Framework 2.6
Offset(P)  Name                    PID pslist psscan thrdproc pspcid csrss session deskthrd ExitTime
---------- -------------------- ------ ------ ------ -------- ------ ----- ------- -------- --------
0x09a88da0 winlogon.exe            616 True   True   True     True   True  True    True
0x09aa0020 lsass.exe               672 True   True   True     True   True  True    True
0x0994a020 msmsgs.exe              636 True   True   True     True   True  True    True
0x097289a8 svchost.exe            1108 True   True   True     True   True  True    True
0x09982da0 VBoxTray.exe            376 True   True   True     True   True  True    True
0x09a9f6f8 svchost.exe             968 True   True   True     True   True  True    True
0x09aab590 svchost.exe             880 True   True   True     True   True  True    True
0x09aaa3d8 VBoxService.exe         832 True   True   True     True   True  True    True
0x09694388 wscntfy.exe             480 True   True   True     True   True  True    True
0x09730da0 svchost.exe            1060 True   True   True     True   True  True    True
0x097075d0 spoolsv.exe            1608 True   True   True     True   True  True    True
0x099adda0 svchost.exe            1156 True   True   True     True   True  True    True
0x09938998 services.exe            660 True   True   True     True   True  True    True
0x0969d2a0 alg.exe                 540 True   True   True     True   True  True    True
0x09a0fda0 DumpIt.exe              276 True   True   True     True   True  True    True
0x09733938 explorer.exe           1484 True   True   True     True   True  True    True
0x09a0d180 notepad.exe            1432 True   True   False    True   False False   False    2023-02-13 18:28:40 UTC+0000
0x09a18da0 cmd.exe                1960 True   True   False    True   False False   False    2023-02-13 18:25:26 UTC+0000
0x099e6da0 notepad.exe            1444 True   True   False    True   False False   False    2023-02-13 18:28:47 UTC+0000
0x096c5020 notepad.exe             528 True   True   False    True   False False   False    2023-02-13 18:27:46 UTC+0000
0x099dd740 rootkit.exe             964 True   True   False    True   False False   False    2023-02-13 18:25:26 UTC+0000
0x09c037f8 System                    4 True   True   True     True   False False   False
0x09a98da0 csrss.exe               592 True   True   True     True   False True    True
0x09a0b2f0 taskmgr.exe            1880 True   True   False    True   False False   False    2023-02-13 18:26:21 UTC+0000
0x09965020 smss.exe                368 True   True   True     True   False False   False

```

There are 25 processes, but only 19 are  "true" in thrdproc, because the othere still remain in memory but they already ended. In fact this process are the only one with an entry in ExitTime.

**The answer is:**
>19


## Q3 What is the process ID of cmd.exe?

In the last output,we can see the process id as well.

**The answer is:**
>1960


## Q4 What is the name of the most suspicious process?

just looking at the name should raise a red flag


**The answer is:**
>rootkit.exe


## Q5 Which process shows the highest likelihood of code injection?

with the plugin malfind
```
volatility_2.6_win64_standalone.exe -f CYBERDEF-567078-20230213-171333.raw malfind
```

we can identify 3 possible processes:

csrss.exe
winlogon.exe
svchost.exe

With a fast search on Google, I have seen that there is a lot of malware that injects into svchost.exe (https://attack.mitre.org/techniques/T1055/)

**The answer is:**
>svchost.exe


## Q6 There is an odd file referenced in the recent process. Provide the full path of that file.

I tried the plugin handles but I found too many results, so I added some filters. 
With -t file I have indicated that the type of handle is a file, and with - p 880 I indicate the process of the handle. The process id 880 was indicated by the malfind plugin for the process svchost.exe

```
volatility_2.6_win64_standalone.exe -f CYBERDEF-567078-20230213-171333.raw handles -t file -p 880
```

output:
```
Volatility Foundation Volatility Framework 2.6
Offset(V)     Pid     Handle     Access Type             Details
---------- ------ ---------- ---------- ---------------- -------
0x89a28890    880        0xc   0x100020 File             \Device\HarddiskVolume1\WINDOWS\system32
0x89a1a6f8    880       0x50   0x100001 File             \Device\KsecDD
0x89937358    880       0x68   0x100020 File             \Device\HarddiskVolume1\WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.5512_x-ww_35d4ce83
0x899d0250    880       0xbc   0x12019f File             \Device\NamedPipe\net\NtControlPipe2
0x89a17a50    880      0x100   0x100000 File             \Device\Dfs
0x89732cb8    880      0x158   0x12019f File             \Device\NamedPipe\lsarpc
0x8969fee0    880      0x274   0x12019f File             \Device\Termdd
0x89ab3478    880      0x294   0x12019f File             \Device\Termdd
0x89ab3978    880      0x29c   0x12019f File             \Device\Termdd
0x896bcd18    880      0x2b8   0x12019f File             \Device\NamedPipe\Ctx_WinStation_API_service
0x8997a248    880      0x2bc   0x12019f File             \Device\NamedPipe\Ctx_WinStation_API_service
0x899a24b0    880      0x304   0x12019f File             \Device\Termdd
0x89a00f90    880      0x33c   0x12019f File             \Device\{9DD6AFA1-8646-4720-836B-EDCB1085864A}
0x89af0cf0    880      0x340   0x12019f File             \Device\HarddiskVolume1\WINDOWS\system32\drivers\str.sys
0x89993f90    880      0x3d8   0x100020 File             \Device\HarddiskVolume1\WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.5512_x-ww_35d4ce83
0x89958b78    880      0x3e4   0x12019f File             \Device\HarddiskVolume1\WINDOWS\system32\config\systemprofile\Local Settings\Temporary Internet Files\Content.IE5\index.dat
0x899fe2e0    880      0x3f8   0x12019f File             \Device\HarddiskVolume1\WINDOWS\system32\config\systemprofile\Cookies\index.dat
0x89a492e8    880      0x400   0x12019f File             \Device\HarddiskVolume1\WINDOWS\system32\config\systemprofile\Local Settings\History\History.IE5\index.dat
0x896811d8    880      0x424   0x100020 File             \Device\HarddiskVolume1\WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.5512_x-ww_35d4ce83
0x89bbc028    880      0x488   0x100020 File             \Device\HarddiskVolume1\WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.5512_x-ww_35d4ce83
0x89999980    880      0x4a8   0x1200a0 File             \Device\NetBT_Tcpip_{B35F0A5F-EBC3-4B5D-800D-7C1B64B30F14}
```

the path *\Device\HarddiskVolume1\WINDOWS\system32\drivers\str.sys* seem strange. str.sys is a strange name for a driver and it is strange that is handled by this process.
I searched on Google and I found a lot of forums that say the Malwarebytes indicate this file as malware.

**The answer is:**
>C:\windows\system32\drivers\str.sys

## Q7 What is the name of the injected dll file loaded from the recent process?

The plugin dlllist wasn´t useful, so I tried ldrmodules for the same process:

```
volatility_2.6_win64_standalone.exe -f CYBERDEF-567078-20230213-171333.raw ldrmodules -p 880
```

output:

```
Pid      Process              Base       InLoad InInit InMem MappedPath
-------- -------------------- ---------- ------ ------ ----- ----------
     880 svchost.exe          0x6f880000 True   True   True  \WINDOWS\AppPatch\AcGenral.dll
     880 svchost.exe          0x01000000 True   False  True  \WINDOWS\system32\svchost.exe
     880 svchost.exe          0x77f60000 True   True   True  \WINDOWS\system32\shlwapi.dll
     880 svchost.exe          0x74f70000 True   True   True  \WINDOWS\system32\icaapi.dll
     880 svchost.exe          0x76f60000 True   True   True  \WINDOWS\system32\wldap32.dll
     880 svchost.exe          0x77c00000 True   True   True  \WINDOWS\system32\version.dll
     880 svchost.exe          0x5ad70000 True   True   True  \WINDOWS\system32\uxtheme.dll
     880 svchost.exe          0x76e80000 True   True   True  \WINDOWS\system32\rtutils.dll
     880 svchost.exe          0x771b0000 True   True   True  \WINDOWS\system32\wininet.dll
     880 svchost.exe          0x76c90000 True   True   True  \WINDOWS\system32\imagehlp.dll
     880 svchost.exe          0x76bc0000 True   True   True  \WINDOWS\system32\regapi.dll
     880 svchost.exe          0x77dd0000 True   True   True  \WINDOWS\system32\advapi32.dll
     880 svchost.exe          0x76f20000 True   True   True  \WINDOWS\system32\dnsapi.dll
     880 svchost.exe          0x77be0000 True   True   True  \WINDOWS\system32\msacm32.dll
     880 svchost.exe          0x7e1e0000 True   True   True  \WINDOWS\system32\urlmon.dll
     880 svchost.exe          0x68000000 True   True   True  \WINDOWS\system32\rsaenh.dll
     880 svchost.exe          0x722b0000 True   True   True  \WINDOWS\system32\sensapi.dll
     880 svchost.exe          0x76e10000 True   True   True  \WINDOWS\system32\adsldpc.dll
     880 svchost.exe          0x76b40000 True   True   True  \WINDOWS\system32\winmm.dll
     880 svchost.exe          0x773d0000 True   True   True  \WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.5512_x-ww_35d4ce83\comctl32.dll
     880 svchost.exe          0x71a50000 True   True   True  \WINDOWS\system32\mswsock.dll
     880 svchost.exe          0x5b860000 True   True   True  \WINDOWS\system32\netapi32.dll
     880 svchost.exe          0x00670000 True   True   True  \WINDOWS\system32\xpsp2res.dll
     880 svchost.exe          0x76e90000 True   True   True  \WINDOWS\system32\rasman.dll
     880 svchost.exe          0x77a80000 True   True   True  \WINDOWS\system32\crypt32.dll
     880 svchost.exe          0x71ab0000 True   True   True  \WINDOWS\system32\ws2_32.dll
     880 svchost.exe          0x77cc0000 True   True   True  \WINDOWS\system32\activeds.dll
     880 svchost.exe          0x71ad0000 True   True   True  \WINDOWS\system32\wsock32.dll
     880 svchost.exe          0x774e0000 True   True   True  \WINDOWS\system32\ole32.dll
     880 svchost.exe          0x77920000 True   True   True  \WINDOWS\system32\setupapi.dll
     880 svchost.exe          0x7e410000 True   True   True  \WINDOWS\system32\user32.dll
     880 svchost.exe          0x7c900000 True   True   True  \WINDOWS\system32\ntdll.dll
     880 svchost.exe          0x77f10000 True   True   True  \WINDOWS\system32\gdi32.dll
     880 svchost.exe          0x77120000 True   True   True  \WINDOWS\system32\oleaut32.dll
     880 svchost.exe          0x5cb70000 True   True   True  \WINDOWS\system32\shimeng.dll
     880 svchost.exe          0x74980000 True   True   True  \WINDOWS\system32\msxml3.dll
     880 svchost.exe          0x009a0000 False  False  False \WINDOWS\system32\msxml3r.dll
     880 svchost.exe          0x77e70000 True   True   True  \WINDOWS\system32\rpcrt4.dll
     880 svchost.exe          0x769c0000 True   True   True  \WINDOWS\system32\userenv.dll
     880 svchost.exe          0x7c800000 True   True   True  \WINDOWS\system32\kernel32.dll
     880 svchost.exe          0x76fd0000 True   True   True  \WINDOWS\system32\clbcatq.dll
     880 svchost.exe          0x76b20000 True   True   True  \WINDOWS\system32\atl.dll
     880 svchost.exe          0x71bf0000 True   True   True  \WINDOWS\system32\samlib.dll
     880 svchost.exe          0x77690000 True   True   True  \WINDOWS\system32\ntmarta.dll
     880 svchost.exe          0x77c10000 True   True   True  \WINDOWS\system32\msvcrt.dll
     880 svchost.exe          0x760f0000 True   True   True  \WINDOWS\system32\termsrv.dll
     880 svchost.exe          0x76fc0000 True   True   True  \WINDOWS\system32\rasadhlp.dll
     880 svchost.exe          0x76c30000 True   True   True  \WINDOWS\system32\wintrust.dll
     880 svchost.exe          0x7c9c0000 True   True   True  \WINDOWS\system32\shell32.dll
     880 svchost.exe          0x77050000 True   True   True  \WINDOWS\system32\comres.dll
     880 svchost.exe          0x76eb0000 True   True   True  \WINDOWS\system32\tapi32.dll
     880 svchost.exe          0x76a80000 True   True   True  \WINDOWS\system32\rpcss.dll
     880 svchost.exe          0x5d090000 True   True   True  \WINDOWS\system32\comctl32.dll
     880 svchost.exe          0x71aa0000 True   True   True  \WINDOWS\system32\ws2help.dll
     880 svchost.exe          0x776c0000 True   True   True  \WINDOWS\system32\authz.dll
     880 svchost.exe          0x76ee0000 True   True   True  \WINDOWS\system32\rasapi32.dll
     880 svchost.exe          0x77b20000 True   True   True  \WINDOWS\system32\msasn1.dll
     880 svchost.exe          0x75110000 True   True   True  \WINDOWS\system32\mstlsapi.dll
     880 svchost.exe          0x77fe0000 True   True   True  \WINDOWS\system32\secur32.dll
```

the only process not in memory is msxml3r.dll

**The answer is:**
>msxml3r.dll

## Q8 What is the base address of the injected dll?


Looking at the result of volatility with the plugin malfind (already executed) i have found the base address of the injected dll:

```
Process: svchost.exe Pid: 880 Address: 0x980000
Vad Tag: VadS Protection: PAGE_EXECUTE_READWRITE
Flags: CommitCharge: 9, MemCommit: 1, PrivateMemory: 1, Protection: 6

0x00980000  4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00   MZ..............
0x00980010  b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00   ........@.......
0x00980020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0x00980030  00 00 00 00 00 00 00 00 00 00 00 00 f8 00 00 00   ................

0x00980000 4d               DEC EBP
0x00980001 5a               POP EDX
0x00980002 90               NOP
0x00980003 0003             ADD [EBX], AL
0x00980005 0000             ADD [EAX], AL
0x00980007 000400           ADD [EAX+EAX], AL
0x0098000a 0000             ADD [EAX], AL
0x0098000c ff               DB 0xff
0x0098000d ff00             INC DWORD [EAX]
0x0098000f 00b800000000     ADD [EAX+0x0], BH
0x00980015 0000             ADD [EAX], AL
0x00980017 004000           ADD [EAX+0x0], AL
0x0098001a 0000             ADD [EAX], AL
0x0098001c 0000             ADD [EAX], AL
0x0098001e 0000             ADD [EAX], AL
0x00980020 0000             ADD [EAX], AL
0x00980022 0000             ADD [EAX], AL
0x00980024 0000             ADD [EAX], AL
0x00980026 0000             ADD [EAX], AL
0x00980028 0000             ADD [EAX], AL
0x0098002a 0000             ADD [EAX], AL
0x0098002c 0000             ADD [EAX], AL
0x0098002e 0000             ADD [EAX], AL
0x00980030 0000             ADD [EAX], AL
0x00980032 0000             ADD [EAX], AL
0x00980034 0000             ADD [EAX], AL
0x00980036 0000             ADD [EAX], AL
0x00980038 0000             ADD [EAX], AL
0x0098003a 0000             ADD [EAX], AL
0x0098003c f8               CLC
0x0098003d 0000             ADD [EAX], AL
0x0098003f 00               DB 0x0
```

In fact, it start ad 0x00980000

**The answer is:**
>0x980000





