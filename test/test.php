<?php


echo 'PHP Version: '.PHP_VERSION,"\n";

require 'ACMECert.php';

use skoerfgen\ACMECert\ACMECert;

$ac=new ACMECert('https://pebble:14000/dir');
$ac->setLogger(function($txt){echo $txt;});

if (PHP_VERSION_ID>=70100){
	$key=$ac->generateECKey();
	$ac->loadAccountKey($key);
}
$key=$ac->generateRSAKey();
$ac->loadAccountKey($key);




