<?php


echo 'PHP Version: '.PHP_VERSION,"\n";

require 'ACMECert.php';

use skoerfgen\ACMECert\ACMECert;

$ac=new ACMECert('https://pebble:14000/dir');
$keys=array();


echo '::group::Generating Keys',"\n";


if (PHP_VERSION_ID>=70100){
	$keys[]=$ac->generateECKey();
}
$keys[]=$ac->generateRSAKey();


print_r($keys);

echo '::endgroup::',"\n";