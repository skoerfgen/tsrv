<?php

// echo 'PHP Version: '.PHP_VERSION,"\n";
// echo "Own IP: " . gethostbyname(gethostname()) . "\n";

require 'ACMECert.php';
use skoerfgen\ACMECert\ACMECert;
$ac=new ACMECert('https://pebble:14000/dir');
$ac->setLogger(function($txt){
	echo $txt,"\n";
});

open('Constructor');
print_r($ac);
close();







function open($txt){
	echo '::group::'.$txt,"\n";
}
function close(){
	echo '::endgroup::',"\n";
}