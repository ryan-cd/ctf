# 1FA Guy
**Category: Forensics**
> https://drive.google.com/file/d/1tFys7Hh8kRtdMdPa5XDbzJz55sBxmvFw/view?usp=sharing

> We have obtained these files from a Hacker's computer known as 1FAGuy. Can you find the password of their C&C?

The download link was a compressed `AppData` folder. We can see the programs the user has installed from the folder contents:
```
$ ls AppData/*
AppData/Local:
 Adaware  'Application Data'   ConnectedDevicesPlatform   DBG   Google   History   Lavasoft   Microsoft   Microsoft_Corporation   Mozilla   Packages   PeerDistRepub   Programs   Temp  'Temporary Internet Files'

AppData/LocalLow:
BitTorrent  Microsoft  Mozilla

AppData/Roaming:
Adobe  BitTorrent  DMCache  IDM  Lavasoft  Microsoft  Mozilla  Notepad++  WinRAR
```

Considering we know we are looking for a password, the result is probably stored in a web browser's folder.

Using [HackBrowserData](https://github.com/moonD4rk/HackBrowserData) we can extract the information.

## Extracting Google Chrome Data

```
./hack-browser-data -b chrome -p ../ctf/2021/securebug-odin/forensics/1FAGuy/AppData/Local/Google/Chrome/User\ Data/Default -k ../ctf/2021/securebug-odin/forensics/1FAGuy/AppData/Local/Google/Chrome/User\ Data/Local\ State
[x]:  Get 1 download history, filename is results/chrome_download.csv
[x]:  Get 1 passwords, filename is results/chrome_password.csv
[x]:  Get 0 credit cards, filename is results/chrome_credit.csv
[x]:  Get 4 bookmarks, filename is results/chrome_bookmark.csv
[x]:  Get 6 cookies, filename is results/chrome_cookie.csv
[x]:  Get 10 history, filename is results/chrome_history.csv
```

Let's take a look at that passwords file:

```
$ cat results/chrome_password.csv
UserName,Password,LoginUrl,CreateDate
Cybercriminal,,https://secure.ssa.gov/RIL/SiView.action,2021-03-29T23:10:34.598548Z
```

There's a username, but the password could not be decrypted. We can look at the browser history to see if it has anything interesting.

```
$ cat results/chrome_history.csv
Title,Url,VisitCount,LastVisitTime
Google,https://www.google.com/,4,2021-03-29T23:11:10.166353Z
google - Google Search,https://www.google.com/search?q=google&source=hp&ei=gl5iYPHkKeSBi-gPsrec0Ak&iflsig=AINFCbYAAAAAYGJskpjbRoPB0LnxUF7lFSgq4fYqDXq7&oq=google&gs_lcp=Cgdnd3Mtd2l6EAMyCAgAELEDEIMBMggIABCxAxCDATIFCAAQsQMyBQgAELEDMgUIABCxAzICCAAyAggAMgUIABCxAzIICAAQsQMQgwEyAggAOgsILhCxAxDHARCjAjoICC4QsQMQgwFQpiJYmi9ghzRoAHAAeACAAUaIAdkCkgEBNpgBAKABAaoBB2d3cy13aXo&sclient=gws-wiz&ved=0ahUKEwjxrfb0z9bvAhXkwAIHHbIbB5oQ4dUDCAc&uact=5,2,2021-03-29T23:11:08.043081Z
Central Intelligence Agency - CIA,https://www.cia.gov/,2,2021-03-29T23:09:15.383984Z
Social Security,https://secure.ssa.gov/RIL/SiView.action,2,2021-03-29T23:10:25.915648Z
how to buy winrar - Google Search,https://www.google.com/search?q=how+to+buy+winrar&source=hp&ei=i15iYKjmFojqkgXj-JjgCw&iflsig=AINFCbYAAAAAYGJsm8wyZkZWUfa9d985F8fqZyy8lAIV&oq=how+to+buy+winrar&gs_lcp=Cgdnd3Mtd2l6EAMyAggAMgIIADICCAAyAggAMgIIADIFCAAQhgMyBQgAEIYDMgUIABCGAzoICAAQ6gIQjwE6BQgAELEDOggIABCxAxCDAToLCC4QsQMQxwEQowI6DgguELEDEIMBEMcBEKMCOgUILhCxAzoCCC5Q7g5YlTpgikJoAXAAeACAAVWIAeIHkgECMTeYAQCgAQGqAQdnd3Mtd2l6sAEK&sclient=gws-wiz&ved=0ahUKEwjo14j5z9bvAhUItaQKHWM8BrwQ4dUDCAc&uact=5,2,2021-03-29T23:11:20.015101Z
Central Intelligence Agency - CIA,https://www.cia.gov/index.html,1,2021-03-29T23:09:13.442216Z
Social Security,https://secure.ssa.gov/RIL/Si.action,1,2021-03-29T23:10:25.915648Z
Central Intelligence Agency - CIA,http://cia.gov/,1,2021-03-29T23:09:13.442216Z
WinRAR and RAR buy site,https://www.rarlab.com/shop2rarlab-index.php?prod=winrar&x-source=winraronly,1,2021-03-29T23:11:21.845056Z
"WinRAR archiver, a powerful tool to process RAR and ZIP files",https://www.rarlab.com/download.htm,1,2021-03-29T23:11:26.869327Z
```

This guy really wants to buy WinRAR! This is looking like a red herring, let's move on.

## Extracting Firefox Data
The extract tool was not recovering a password file for Firefox. I ran it in verbose mode to check why:
```
$ ./hack-browser-data -b firefox -p ../ctf/2021/securebug-odin/forensics/1FAGuy/AppData/Roaming/Mozilla/Firefox/Profiles/pwbmg6f4.default-release/ -vv
browser.go:205: debug Firefox find bookmark file success
browser.go:205: debug Firefox find cookie file success
browser.go:205: debug Firefox find history file success
browser.go:195: debug Firefox find password file failed, ERR:find logins.json failed
```

Looking in the folder it was talking about, `logins.json` was missing, but `login.json` was present. Renaming the file fixed the extraction.

```
$ ./hack-browser-data -b firefox -p ../ctf/2021/securebug-odin/forensics/1FAGuy/AppData/Roaming/Mozilla/Firefox/Profiles/pwbmg6f4.default-release/
[x]:  Get 13 bookmarks, filename is results/firefox_bookmark.csv
[x]:  Get 0 cookies, filename is results/firefox_cookie.csv
[x]:  Get 11 history, filename is results/firefox_history.csv
[x]:  Get 1 passwords, filename is results/firefox_password.csv
```

```
$ cat results/firefox_password.csv
UserName,Password,LoginUrl,CreateDate
admin,SBCTF{MuL71_f4C70R_4U7H3N71C4710n_70_7h3_r35cU3},,2021-03-29T19:14:38-04:00
```

`SBCTF{MuL71_f4C70R_4U7H3N71C4710n_70_7h3_r35cU3}`
