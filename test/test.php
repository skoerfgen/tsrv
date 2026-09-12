<?php

require 'ACMECert.php';

use skoerfgen\ACMECert\ACMECert;

$ac=new ACMECert('https://pebble:14000/dir');


mkdir('foo');
file_put_contents('foo/out.txt','it works!');
print_r($ac);
echo 'ok';