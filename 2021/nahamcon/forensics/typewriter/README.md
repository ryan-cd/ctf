# Typewriter
**Category: Forensics**

448 Points

> A CONSTELLATIONS employee had his machine crash and he lost all his work. Thankfully IT managed to get a memory dump. Can you recover his work?

> Download the file below. Note, this is a large ~400MB file and may take some time to download.

The challenge includes a download which extracts to a 2GB memory dump named `image.bin`. 

## Exploring the Memory
The first thing we need to do is to work out what operating system created this dump. We can do this with `volatility`.

```
$ volatility -f image.bin imageinfo

Volatility Foundation Volatility Framework 2.6
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : Win7SP1x86_23418, Win7SP0x86, Win7SP1x86
                     AS Layer1 : IA32PagedMemoryPae (Kernel AS)
                     AS Layer2 : FileAddressSpace (/mnt/c/Users/meraxes/dev/ctf/2021/nahamcon/forensics/typewriter/image.bin)
                      PAE type : PAE
                           DTB : 0x185000L
                          KDBG : 0x8293bde8L
          Number of Processors : 1
     Image Type (Service Pack) : 1
                KPCR for CPU 0 : 0x80b97000L
             KUSER_SHARED_DATA : 0xffdf0000L
           Image date and time : 2021-02-21 16:25:49 UTC+0000
     Image local date and time : 2021-02-21 08:25:49 -0800
```

Looks like we are dealing with `Win7SP1x86_23418`. We will use this in our following volatility commands.

Next, let's take a look at what processes are running:

```
volatility -f image.bin --profile=Win7SP1x86_23418 pslist
Volatility Foundation Volatility Framework 2.6
Offset(V)  Name                    PID   PPID   Thds     Hnds   Sess  Wow64 Start                          Exit
---------- -------------------- ------ ------ ------ -------- ------ ------ ------------------------------ ------------------------------
0x84841938 System                    4      0     72      500 ------      0 2021-02-22 01:24:16 UTC+0000
... <spliced>
0x8623e030 explorer.exe           2212   2192     29      628      1      0 2021-02-21 16:24:28 UTC+0000
0x85f56a68 VBoxTray.exe           2312   2212     13      159      1      0 2021-02-21 16:24:29 UTC+0000
0x85f3bd20 StikyNot.exe           2320   2212      9      144      1      0 2021-02-21 16:24:29 UTC+0000
0x85f523d8 SearchIndexer.         2468    436     12      596      0      0 2021-02-21 16:24:29 UTC+0000
0x85fa2d20 WINWORD.EXE            2760   2212      8      316      1      0 2021-02-21 16:24:39 UTC+0000
0x85f687d8 OSPPSVC.EXE            2828    436      5      143      0      0 2021-02-21 16:24:40 UTC+0000
```

`WINWORD.EXE` (PID=2760) jumped out at me as being potentially interesting.

We can see the arguments the program was started with by using the `cmdline` option, and supplying the process ID.

```
$ volatility -f image.bin --profile=Win7SP1x86_23418 cmdline -p 2760

Volatility Foundation Volatility Framework 2.6
************************************************************************
WINWORD.EXE pid:   2760
Command line : "C:\Program Files\Microsoft Office\Office14\WINWORD.EXE" /n "C:\Users\IEUser\Desktop\CONFIDENTIAL DOCUMENT.docx
```

Well, that certainly is interesting! We can look for more information about this file, and try to extract it from the dump.

The next step is to figure out the offsets of the files in the dump:

```
$ volatility -f image.bin --profile=Win7SP1x86_23418 filescan > files.txt
```

Searching for the file in the `files.txt` output, I can find:

```
Offset(P)            #Ptr   #Hnd Access Name
------------------ ------ ------ ------ ----
...
0x000000007e841f80      8      0 RW-r-- \Device\HarddiskVolume1\Users\IEUser\Desktop\CONFIDENTIAL DOCUMENT.docx
```

Let's dump the file at that offset. This gives us the data section object (`file.None.0x85e41580.CONFIDENTIAL DOCUMENT.docx.dat`) and shared cache map (`file.None.0x85e41b30.CONFIDENTIAL DOCUMENT.docx.vacb`):
```
$ volatility -f image.bin --profile=Win7SP1x86_23418 dumpfiles -Q 0x000000007e841f80 -n -u --dump-dir=files
Volatility Foundation Volatility Framework 2.6
DataSectionObject 0x7e841f80   None   \Device\HarddiskVolume1\Users\IEUser\Desktop\CONFIDENTIAL DOCUMENT.docx
SharedCacheMap 0x7e841f80   None   \Device\HarddiskVolume1\Users\IEUser\Desktop\CONFIDENTIAL DOCUMENT.docx
```

## Examining the Document

I don't have Microsoft Word installed on my computer. Instead of trying to open this, I instead opted to manually inspect it. Word files are internally a zip of xml files. We can unzip the file to see what is inside:

```
$ unzip file.None.0x85e41580.CONFIDENTIAL\ DOCUMENT.docx.dat

Archive:  file.None.0x85e41580.CONFIDENTIAL DOCUMENT.docx.dat
  inflating: [Content_Types].xml
  inflating: _rels/.rels
  inflating: word/_rels/document.xml.rels
  inflating: word/document.xml
  inflating: word/theme/theme1.xml
  inflating: word/settings.xml
  inflating: word/webSettings.xml
  inflating: word/stylesWithEffects.xml
  inflating: docProps/core.xml
  inflating: word/styles.xml
  inflating: word/fontTable.xml
  inflating: docProps/app.xml
```

`document.xml` is what we want. After running it through an xml format beautifier we can see:

```xml
            <w:t>CONFIDENTIAL DOCUMENT</w:t>
         </w:r>
      </w:p>
      <w:p w:rsidR="001342CC" w:rsidRDefault="001342CC" w:rsidP="001342CC">
         <w:r>
            <w:t>This document contains some critical information for Constellations</w:t>
         </w:r>
      </w:p>
      <w:p w:rsidR="001342CC" w:rsidRDefault="001342CC" w:rsidP="001342CC">
         <w:proofErr w:type="gramStart" />
         <w:r w:rsidRPr="001342CC">
            <w:t>f</w:t>
         </w:r>
         <w:proofErr w:type="gramEnd" />
      </w:p>
      <w:p w:rsidR="001342CC" w:rsidRDefault="001342CC" w:rsidP="001342CC">
         <w:proofErr w:type="gramStart" />
         <w:r w:rsidRPr="001342CC">
            <w:t>l</w:t>
         </w:r>
         <w:proofErr w:type="gramEnd" />
      </w:p>
      <w:p w:rsidR="001342CC" w:rsidRDefault="001342CC" w:rsidP="001342CC">
         <w:proofErr w:type="gramStart" />
         <w:r w:rsidRPr="001342CC">
            <w:t>a</w:t>
         </w:r>
         <w:proofErr w:type="gramEnd" />
      </w:p>
      <w:p w:rsidR="001342CC" w:rsidRDefault="001342CC" w:rsidP="001342CC">
         <w:proofErr w:type="gramStart" />
         <w:r w:rsidRPr="001342CC">
            <w:t>g</w:t>
         </w:r>
         <w:proofErr w:type="gramEnd" />
      </w:p>
      ...
```

The flag is here, spelled out one character at a time in the xml blocks. We could type this out one character at a time, or make a parser to do that for us:

```sh
$ cat pretty-document.xml | grep \<w:t\>.\</w:t\> | sed 's/.*<w:t>\(.\).*/\1/' | tr --delete '\n'

flag{c442f9ee67c7ab471bb5643a9346cf5e}
```
