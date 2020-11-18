# NotRandomCMS
## Category: OSINT

This challenge contained a file, `CMS.7z` and the following description:
> A friend started to develop a CMS for his company using a PHP framework, can you check if there is any security issue? I removed the application secrets to be safe to share it.

After browsing through the files I noticed there were some debug logs under `runtime/debug`.

Looking inside one of them, I found the line:
`s:3:"url";s:49:"http://207.154.234.221/NotRandomCMS/web/index.php";s:4:"ajax";i:0;s:6:"method";s:3:"GET";s:2:"ip";s:13:"217.96.`

This gives us the public URL of the site. Maybe we can find more clues when we see it in action.

On the site, there was a link to the developer's repository: https://github.com/notrandomcms/notrandomcmsv1

The commit history has this very interesting commit titled "Removing secret files": https://github.com/notrandomcms/notrandomcmsv1/commit/6cdec47e7b78394095de5c8856fd67e2a9b6410c

The commit diff includes this line with the flag:
> 'cookieValidationKey' => 'AFFCTF{thisShouldBeASecret!}',
