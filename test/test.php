<?php


echo 'PHP Version: '.PHP_VERSION,"\n";

require 'ACMECert.php';

use skoerfgen\ACMECert\ACMECert;

$ac=new ACMECert('https://pebble:14000/dir');
//$ac->setLogger(function($txt){echo $txt,"\n";});


function checkKey($key){
	global $ac;
	$ac->loadAccountKey($key);
	$ac->register(true);
}

if (PHP_VERSION_ID>=70100){
	foreach(['P-256','P-384'] as $curve){
		$ac->log('Generating '.$curve.' EC Key');
		checkKey($ac->generateECKey($curve));	
	}
}
foreach([1024,2048] as $bits){
	$ac->log('Generating '.$bits.' bits RSA Key');
	checkKey($ac->generateRSAKey($bits));	
}




