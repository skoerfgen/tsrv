<?php

echo 'PHP Version: '.PHP_VERSION,"\n";
echo "Own IP: " . gethostbyname(gethostname()) . "\n";

require 'ACMECert.php';
use skoerfgen\ACMECert\ACMECert;
$ac=new ACMECert('https://pebble:14000/dir');

print_r($ac);