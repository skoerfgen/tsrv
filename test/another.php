<?php

echo 'PHP Version: '.PHP_VERSION,"\n";
// echo "Own IP: " . gethostbyname(gethostname()) . "\n";

require 'ACMECert.php';
use skoerfgen\ACMECert\ACMECert;
$ac=new ACMECert('https://pebble:14000/dir');
$ac->setLogger(function($txt){
	echo $txt,"\n";
});

foreach([2048,3072,4096] as $bits){
	open('Generate/Register RSA '.$bits.' Key');
	checkAccountKey($ac->generateRSAKey($bits));
	close();
}

if (PHP_VERSION_ID>=70100){
	foreach(['P-256','P-384'] as $curve){
		open('Generate/Register EC '.$curve.' Key');
		checkAccountKey($ac->generateECKey($curve));
		close();
	}
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