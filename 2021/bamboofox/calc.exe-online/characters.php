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