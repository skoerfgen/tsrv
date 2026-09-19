<?php

echo 'PHP Version: '.PHP_VERSION,"\n";
// echo "Own IP: " . gethostbyname(gethostname()) . "\n";

require 'ACMECert.php';
use skoerfgen\ACMECert\ACMECert;
$ac=new ACMECert('https://127.0.0.1:14000/dir');
$ac->setLogger(function($txt){ echo $txt,"\n"; });
$ac_eab=new ACMECert('https://127.0.0.1:14001/dir');
$ac_eab->setLogger(function($txt){ echo $txt,"\n"; });
/*class AC_No_Curl extends ACMECert {
	function __construct($dir){
		parent::__construct($dir);
		$this->ch=false;
	}
}*/
runTests($ac,$ac_eab);

// generate + register + keyChange keys
function runTests($ac,$ac_eab){
	foreach([2048,3072,4096] as $k=>$bits){
		open('Generate RSA '.$bits.' Key ('.($k===0?'Register':'Account Key Rollover').') + EAB');
		$key=$ac->generateRSAKey($bits);
		echo $key;
		if ($k===0) {
			$ac->loadAccountKey($key);
			$ac->register(true);
			
		}else{
			$ac->keyChange($key);
		}
		print_r($ac->getAccount());
		$ac_eab->loadAccountKey($key);
		print_r($ac_eab->registerEAB(true,'kid-1','zWNDZM6eQGHWpSRTPal5eIUYFTu7EajVIoguysqZ9wG44nMEtx3MUAsUDkMTQ12W'));
		close();
	}

	if (PHP_VERSION_ID>=70100){
		foreach(['P-256','P-384','P-521'] as $k=>$curve){
			open('Generate EC '.$curve.' Key ('.($k===0?'Register':'Account Key Rollover').') + EAB');
			$key=$ac->generateECKey($curve);
			echo $key;
			if ($k===0) {
				$ac->loadAccountKey($key);
				$ac->register(true);
			}else{
				$ac->keyChange($key);
			}
			print_r($ac->getAccount());
			$ac_eab->loadAccountKey($key);
			print_r($ac_eab->registerEAB(true,'kid-1','zWNDZM6eQGHWpSRTPal5eIUYFTu7EajVIoguysqZ9wG44nMEtx3MUAsUDkMTQ12W'));
			close();
		}
	}
	
}

// ====================================


function open($txt){
	echo '::group::'.$txt,"\n";
}
function close(){
	echo '::endgroup::',"\n";
}

