<?php

// echo 'PHP Version: '.PHP_VERSION,"\n";
// echo "Own IP: " . gethostbyname(gethostname()) . "\n";

require 'ACMECert.php';
use skoerfgen\ACMECert\ACMECert;
$ac=new ACMECert('https://pebble:14000/dir');
$ac->setLogger(function($txt){
	echo $txt,"\n";
});

start('Constructor');
print_r($ac);
end();







function start($txt){
	echo '::group::'.$txt,"\n";
}
function end($txt){
	echo '::endgroup::',"\n";
}