<?php

// echo 'PHP Version: '.PHP_VERSION,"\n";
// echo "Own IP: " . gethostbyname(gethostname()) . "\n";

require 'ACMECert.php';
use skoerfgen\ACMECert\ACMECert;
$ac=new ACMECert('https://pebble:14000/dir');
$ac->setLogger(function($txt){
	echo $txt,"\n";
});

open('RSA & EC Keys');


foreach([2048,3072,4096] as $bits){
	open('RSA '.$bits);
	echo 'OK',"\n";
	close();
}

foreach(['P-256','P-384'] as $curve){
	
}

print_r($ac);
close();







function open($txt){
	echo '::group::'.$txt,"\n";
}
function close(){
	echo '::endgroup::',"\n";
}