# Photo Album

**Category: Forensics**

This challenge provided a `photo_album.zip` file. Attempting to unzip would prompt for the password for the images. 

## Attempt 1: Dictionary Attack

I started by doing a dictionary attack on the archive using the classic [rockyou.txt](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Leaked-Databases/rockyou.txt.tar.gz) wordlist and `fcrackzip`: 

```
 $ fcrackzip -v -D -p rockyou.txt -u photo_album.zip
 ```

 No luck though, it seemed as if the password isn't a common one, and will need to be bruteforced. `fcrackzip` is slow when it comes to bruteforcing, I moved on to use `hashcat` instead to make use of my GPU.

 ## Attempt 2: Bruteforce
The first step of using hashcat is to get a hash to work with. I used `zip2john` from `John the Ripper` to extract a password hash from the zip file:

```
$ zip2john photo_album.zip > zip.tmp

$ cat zip.tmp
photo_album.zip:$pkzip2$3*2*1*0*8*24*33fb*700e*82fbc48cd8fcbe5885e734727783acf77c9c3d96e165577a5f22f67294e18a1b6b6a4391*1*0*8*24*ee39*7009*2a96ee640e56ecaccf86814fcab6573d4183016e5a042bb48615092304c8369131a42519*2*0*21*15*6b5dbfbd*9d119e7*70*0*21*6b5d*7d44*7691f6a82ce08dc64bd85e7dc7a48e6ed281371f2f207b50322ff94ff90184f66c*$/pkzip2$::photo_album.zip:photo_album/baltimore-maryland-usa-skyline-P6X43LO.jpg, photo_album/baltimore-maryland-usa-skyline-PZWQ3DP.jpg, photo_album/baltimore-maryland-usa-skyline-P2TABP6.jpg:/photo_album.zip
```

The only part we need for hashcat is the part within the `$pkzip2$` markers. I created a new file, `hash.txt`:

```
$pkzip2$3*2*1*0*8*24*33fb*700e*82fbc48cd8fcbe5885e734727783acf77c9c3d96e165577a5f22f67294e18a1b6b6a4391*1*0*8*24*ee39*7009*2a96ee640e56ecaccf86814fcab6573d4183016e5a042bb48615092304c8369131a42519*2*0*21*15*6b5dbfbd*9d119e7*70*0*21*6b5d*7d44*7691f6a82ce08dc64bd85e7dc7a48e6ed281371f2f207b50322ff94ff90184f66c*$/pkzip2$
```

According to the hashcat documentation, the following `pkzip2` formats are supported:

```
17200 | PKZIP (Compressed)                               | Archives
17220 | PKZIP (Compressed Multi-File)                    | Archives
17225 | PKZIP (Mixed Multi-File)                         | Archives
17230 | PKZIP (Mixed Multi-File Checksum-Only)           | Archives
17210 | PKZIP (Uncompressed)                             | Archives
20500 | PKZIP Master Key                                 | Archives
20510 | PKZIP Master Key (6 byte optimization)           | Archives
```

Since we have multiple files, `17220 | PKZIP (Compressed Multi-File)` looks like a good place to start.

I used the following command to process the hash:

```
$ hashcat.exe -m 17220 -a 3 -1 ?l?d ?1?1?1?1?1?1?1?1 hash.txt
```
- `-m 17220` means use mode `PKZIP (Compressed Multi-File)`
- `-a 3` means use bruteforce mode
- `-1 ?l?d ?1?1?1?1?1?1?1?1` means the password will be lowercase letters + digits of length 8

After letting that run for a bit, hashcat cracked the hash! Checking the result file showed:
```
cat hashcat.potfile

$pkzip2$3*2*1*0*8*24*33fb*700e*82fbc48cd8fcbe5885e734727783acf77c9c3d96e165577a5f22f67294e18a1b6b6a4391*1*0*8*24*ee39*7009*2a96ee640e56ecaccf86814fcab6573d4183016e5a042bb48615092304c8369131a42519*2*0*21*15*6b5dbfbd*9d119e7*70*0*21*6b5d*7d44*7691f6a82ce08dc64bd85e7dc7a48e6ed281371f2f207b50322ff94ff90184f66c*$/pkzip2$:1966umbc
```

The password is shown at the end, `1966umbc`. Using this password we can unzip the archive and view the photos. One of the photos wouldn't open. I ran `strings` on it to investigate:

```
$ strings baltimore-maryland-usa-skyline-P6X43LO.jpg
DawgCTF{P1ctur35qu3}
```
