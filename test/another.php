<?php

echo 'PHP Version: '.PHP_VERSION,"\n";
// echo "Own IP: " . gethostbyname(gethostname()) . "\n";

require 'ACMECert.php';
use skoerfgen\ACMECert\ACMECert;
$ac=new ACMECert('https://pebble:14000/dir');
$ac->setLogger(function($txt){
	echo $txt,"\n";
});

foreach([2048,3072,4096] as $k=>$bits){
	open('Generate RSA '.$bits.' Key ('.($k===0?'Register':'Account Key Rollover').')');
	$key=$ac->generateRSAKey($bits);
	echo $key,"\n";
	if ($k===0) {
		$ac->loadAccountKey($key);
		$ac->register(true);
	}else{
		$ac->keyChange($key);
	}
	print_r($ac->getAccount());
	close();
}

if (PHP_VERSION_ID>=70100){
	foreach(['P-256','P-384','P-521'] as $k=>$curve){
		open('Generate EC '.$curve.' Key ('.($k===0?'Register':'Account Key Rollover').')');
		$key=$ac->generateECKey($curve);
		echo $key,"\n";
		if ($k===0) {
			$ac->loadAccountKey($key);
			$ac->register(true);
		}else{
			$ac->keyChange($key);
		}
		print_r($ac->getAccount());
		close();
	}
}


// cert
open('Generate Certificate');
$domain_config=array(
	'*.example.net'=>array('challenge'=>'dns-01'),
	'sub.other.example.net'=>array('challenge'=>'dns-01'),
	'sub2.other.example.net'=>array('challenge'=>'tls-alpn-01'),
	'example.net'=>array('challenge'=>'http-01'),
);
$domain_config[gethostbyname('challtestsrv')]=array('challenge'=>'http-01');

$handler=function($opts) use ($ac){
	switch($opts['config']['challenge']){
		case 'dns-01':
			$ac->log('-> SET DNS '.$opts['key'].'.'.' | '.$opts['value']);
			req('set-txt',array(
				'host'=>$opts['key'].'.',
				'value'=>$opts['value']
			));
			
			return function($opts)use($ac){
				$ac->log('<- REM DNS '.$opts['key'].'.'.' | '.$opts['value']);
				req('clear-txt',array(
					'host'=>$opts['key'].'.',
				));
			};
		break;
		case 'http-01':
			$opts['key']=basename($opts['key']);
			$ac->log('-> SET TXT '.$opts['key'].'.'.' | '.$opts['value']);
			setIP(gethostbyname('challtestsrv'));
			req('add-http01',array(
				'token'=>$opts['key'],
				'content'=>$opts['value']
			));
	
			return function($opts)use($ac){
				$ac->log('<- REM TXT '.$opts['key'].'.'.' | '.$opts['value']);
				req('del-http01',array(
					'token'=>$opts['key'],
				));
			};
		break;
    case 'tls-alpn-01':
			setIP();

			file_put_contents('some_private_key.pem',$ac->generateRSAKey());
			$cert=$ac->generateALPNCertificate('file://'.'some_private_key.pem',$opts['domain'],$opts['value']);
      file_put_contents('alpn_cert.pem',$cert);
      $resource=proc_open(
        'node alpn_responder.js some_private_key.pem alpn_cert.pem',
        array(
          0=>array('pipe','r'),
          1=>array('pipe','w')
        ),
        $pipes
      );


      $ac->log(fgets($pipes[1]));

      return function($opts) use ($resource,$pipes,$ac){
        // Stop ALPN Responder
        fclose($pipes[0]);
        fclose($pipes[1]);
        proc_terminate($resource);
        proc_close($resource);
				$ac->log('ALPN TERM');
      };
    break;
	}
};


$fullchain=$ac->getCertificateChains($ac->generateRSAKey(),$domain_config,$handler,array('group'=>true,'authz_reuse'=>true));
$ret=$ac->getSAN(reset($fullchain));
print_r($ret);

foreach($fullchain as $issuer=>$chain){
	echo $issuer,"\n";
	print_r($ac->splitChain($chain));	
}
close();

if (PHP_VERSION_ID>=70201){
	open('ARI');
	print_r($ac->getARI(reset($fullchain)));
	close();
}

open('Revoke Certificate');
$ac->revoke(reset($fullchain));
close();

open('Deactivate Account');
print_r($ac->deactivateAccount());
close();

// ============================================================================

function req($path,$arr){
	static $ch=null;

	if ($ch===null){
		$ch=curl_init();
	}
	curl_setopt_array($ch,array(
		CURLOPT_URL=>'http://challtestsrv:8055/'.$path,
		CURLOPT_RETURNTRANSFER=>true,
		CURLOPT_POSTFIELDS=>json_encode($arr),
	));
	curl_exec($ch);
}

function setIP($ip=null){
	req('set-default-ipv4',array(
		'ip'=>$ip===null?gethostbyname(gethostname()):$ip
	));	
}

function open($txt){
	echo '::group::'.$txt,"\n";
}
function close(){
	echo '::endgroup::',"\n";
}