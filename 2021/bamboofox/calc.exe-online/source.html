<?php
error_reporting(0);
isset($_GET['source']) && die(highlight_file(__FILE__));

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
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bulma@0.9.1/css/bulma.min.css">
    <script defer src="https://use.fontawesome.com/releases/v5.3.1/js/all.js"></script>
    <title>Calc.exe online</title>
</head>
<style>
</style>

<body>
    <section class="hero">
        <div class="container">
            <div class="hero-body">
                <h1 class="title">Calc.exe Online</h1>
            </div>
        </div>
    </section>
    <div class="container" style="margin-top: 3em; margin-bottom: 3em;">
        <div class="columns is-centered">
            <div class="column is-8-tablet is-8-desktop is-5-widescreen">
                <form>
                    <div class="field">
                        <div class="control">
                            <input class="input is-large" placeholder="1+1" type="text" name="expression" value="<?= $_GET['expression'] ?? '' ?>" />
                        </div>
                    </div>
                </form>
            </div>
        </div>
        <div class="columns is-centered">
            <?php if (isset($_GET['expression'])) : ?>
                <div class="card column is-8-tablet is-8-desktop is-5-widescreen">
                    <div class="card-content">
                        = <?= @safe_eval($_GET['expression']) ?>
                    </div>
                </div>
            <?php endif ?>
            <a href="/?source"></a>
        </div>
    </div>
</body>

</html>