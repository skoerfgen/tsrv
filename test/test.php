<?php

require 'ACMECert.php';

use skoerfgen\ACMECert\ACMECert;

$ac=new ACMECert(false);

print_r($ac);


$key=$ac->generateECKey();
$ac->loadAccountKey($key);
print_r($ac->register(true));