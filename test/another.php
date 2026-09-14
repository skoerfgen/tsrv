<?php

echo 'PHP Version: '.PHP_VERSION,"\n";
// echo "Own IP: " . gethostbyname(gethostname()) . "\n";

require 'ACMECert.php';
use skoerfgen\ACMECert\ACMECert;
$ac=new ACMECert('https://pebble:14000/dir');
$ac->setLogger(function($txt){
	echo $txt,"\n";
});

if (PHP_VERSION_ID>=70100){
	foreach(['P-256','P-384','P-521'] as $k=>$curve){
		open('Generate/Register EC '.$curve.' Key');
		$key=$ac->generateECKey($curve);
		$ac->log($key);
		if ($k===0) {
			$ac->loadAccountKey($key);
			$ac->register(true);
		}else{
			$ac->keyChange($key);
		}
		close();
	}
}

foreach([4096,3072,2048] as $bits){
	open('Generate/Register RSA '.$bits.' Key');
	checkAccountKey($ac->generateRSAKey($bits));
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