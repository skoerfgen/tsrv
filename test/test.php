<?php


echo 'PHP Version: '.PHP_VERSION,"\n";

require 'ACMECert.php';

use skoerfgen\ACMECert\ACMECert;

$ac=new ACMECert('https://pebble:14000/dir');


echo '::group::Generating Keys',"\n";
if (PHP_VERSION_ID>=70100){
	$key=$ac->generateECKey();
	echo $key,"\n";
	$ac->loadAccountKey($key);
}
$key=$ac->generateRSAKey();
echo $key,"\n";
$ac->loadAccountKey($key);
echo '::endgroup::',"\n";

echo '::group::Register Account',"\n";
print_r($ac->register(true),true);
echo '::endgroup::',"\n";



