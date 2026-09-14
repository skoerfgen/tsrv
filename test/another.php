<?php

// echo 'PHP Version: '.PHP_VERSION,"\n";
// echo "Own IP: " . gethostbyname(gethostname()) . "\n";

require 'ACMECert.php';
use skoerfgen\ACMECert\ACMECert;
$ac=new ACMECert('https://pebble:14000/dir');
$ac->setLogger(function($txt){
	echo $txt,"\n";
});

print_r($ac);

foreach([2048,3072,4096] as $bits){
	open('RSA '.$bits);
	checkAccountKey($ac->generateRSAKey($bits));
	close();
}

foreach(['P-256','P-384'] as $curve){
	open('EC '.$curve);
	checkAccountKey($ac->generateECKey($curve));
	close();
}









function checkAccountKey($key){
	global $ac;
	$ac->log($key);
	$ac->loadAccountKey($key);
	$ac->register(true);
}

function open($txt){
	echo '::group::'.$txt,"\n";
}
function close(){
	echo '::endgroup::',"\n";
}