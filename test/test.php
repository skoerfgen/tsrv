<?php

echo 'PHP Version: '.PHP_VERSION,"\n";

echo "Own IP: " . gethostbyname(gethostname()) . "\n";

//var_dump(shell_exec('nohup socat TCP-LISTEN:5001,reuseaddr,fork TCP:127.0.0.1:443 >/var/log/socat.log 2>&1 &'));

require 'ACMECert.php';

use skoerfgen\ACMECert\ACMECert;

$ac=new ACMECert('https://pebble:14000/dir');

function checkKey($key){
	global $ac;
	$ac->log($key);
	$ac->loadAccountKey($key);
	$ac->register(true);
}






if (PHP_VERSION_ID>=70100){
	foreach(['P-256','P-384'] as $curve){
		$ac->log('::group::Generating '.$curve.' EC Key');
		checkKey($ac->generateECKey($curve));
		$ac->log('::endgroup::');
	}
}
foreach([2048,3072,4096] as $bits){
	$ac->log('::group::Generating '.$bits.' bits RSA Key');
	checkKey($ac->generateRSAKey($bits));	
	$ac->log('::endgroup::');
}
$ac->log('::group::Get Terms URL');
$ac->log($ac->getTermsURL());
$ac->log('::endgroup::');

$ac->log('::group::Get Profiles');
$ac->log(print_r($ac->getProfiles(),true));
$ac->log('::endgroup::');

$ac->log('::group::Get CAA Identities');
$ac->log(print_r($ac->getCAAIdentities(),true));
$ac->log('::endgroup::');


$domain_config=array(
	'*.example.net'=>array('challenge'=>'dns-01'),
	'sub.other.example.net'=>array('challenge'=>'dns-01'),
	'sub2.other.example.net'=>array('challenge'=>'tls-alpn-01'),
	'example.net'=>array('challenge'=>'http-01'),
);

$domain_config[gethostbyname('challtestsrv')]=array('challenge'=>'http-01');

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


$ac->log('::group::Generating Certificate');
$fullchain=$ac->getCertificateChains($ac->generateRSAKey(),$domain_config,$handler,array('group'=>true,'authz_reuse'=>true));
$ret=$ac->getSAN(reset($fullchain));
$ac->log(print_r($ret,true));
$ac->log(print_r($fullchain,true));
$ac->log('::endgroup::');

$ac->log('::group::Split Chain');
$ac->log(print_r($ac->splitChain(reset($fullchain)),true));
$ac->log('::endgroup::');

$ac->log('::group::getRemainingPercent');
$ac->log(print_r($ac->getRemainingPercent(reset($fullchain)),true));
$ac->log('::endgroup::');

$ac->log('::group::getRemainingDays');
$ac->log(print_r($ac->getRemainingDays(reset($fullchain)),true));
$ac->log('::endgroup::');

if (PHP_VERSION_ID>=70201){
	$ac->log('::group::ARI');
	$ac->log(print_r($ac->getARI(reset($fullchain)),true));
	$ac->log('::endgroup::');
}

$ac->log('::group::Revoking Certificate');
$ac->revoke(reset($fullchain));
$ac->log('::endgroup::');

$ac->log('::group::Get Account');
$ac->log(print_r($ac->getAccount(),true));
$ac->log('::endgroup::');

$ac->log('::group::Account Key Roll-over');
$ac->log(print_r($ac->keyChange($ac->generateRSAKey()),true));
$ac->log('::endgroup::');

$ac->log('::group::Deactivate Account');
$ac->log(print_r($ac->deactivateAccount(),true));
$ac->log('::endgroup::');
