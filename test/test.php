<?php


echo 'PHP Version: '.PHP_VERSION,"\n";

require 'ACMECert.php';

use skoerfgen\ACMECert\ACMECert;

$ac=new ACMECert('https://pebble:14000/dir');


$ac->log('::group::Generating Keys');
if (PHP_VERSION_ID>=70100){
	$key=$ac->generateECKey();
	$ac->log($key);
	$ac->loadAccountKey($key);
}
$key=$ac->generateRSAKey();
$ac->log($key);
$ac->loadAccountKey($key);
$ac->log('::endgroup::');

$ac->log('::group::Register Account');
$ac->log(print_r($ac->register(true),true));
$ac->log('::endgroup::');



