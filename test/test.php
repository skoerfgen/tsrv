<?php

echo 'PHP Version: '.PHP_VERSION,"\n";

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
foreach([1024,2048] as $bits){
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
	'sub0.example.net'=>array('challenge'=>'dns-01'),
	'sub1.example.net'=>array('challenge'=>'http-01'),
);

$domain_config[gethostbyname('challtestsrv')]=array('challenge'=>'http-01');

$ch=curl_init();

$handler=function($opts) use ($ac,$ch){
	switch($opts['config']['challenge']){
		case 'dns-01':
			$ac->log('-> SET DNS '.$opts['key'].'.'.' | '.$opts['value']);
			curl_setopt_array($ch,array(
				CURLOPT_URL=>'http://challtestsrv:8055/set-txt',
				CURLOPT_RETURNTRANSFER=>true,
				CURLOPT_POSTFIELDS=>json_encode(array(
					'host'=>$opts['key'].'.',
					'value'=>$opts['value']
				)),
			));
			curl_exec($ch);
			
			
			return function($opts)use($ch,$ac){
				$ac->log('<- REM DNS '.$opts['key'].'.'.' | '.$opts['value']);
				curl_setopt_array($ch,array(
					CURLOPT_URL=>'http://challtestsrv:8055/clear-txt',
					CURLOPT_RETURNTRANSFER=>true,
					CURLOPT_POSTFIELDS=>json_encode(array(
						'host'=>$opts['key'].'.',
					)),
				));
				curl_exec($ch);
			};
		break;
		case 'http-01':
			$opts['key']=basename($opts['key']);
			$ac->log('-> SET TXT '.$opts['key'].'.'.' | '.$opts['value']);
			curl_setopt_array($ch,array(
				CURLOPT_URL=>'http://challtestsrv:8055/add-http01',
				CURLOPT_RETURNTRANSFER=>true,
				CURLOPT_POSTFIELDS=>json_encode(array(
					'token'=>$opts['key'],
					'content'=>$opts['value']
				)),
			));
			curl_exec($ch);
			
			
			return function($opts)use($ch,$ac){
				$ac->log('<- REM TXT '.$opts['key'].'.'.' | '.$opts['value']);
				curl_setopt_array($ch,array(
					CURLOPT_URL=>'http://challtestsrv:8055/del-http01',
					CURLOPT_RETURNTRANSFER=>true,
					CURLOPT_POSTFIELDS=>json_encode(array(
						'token'=>$opts['key'],
					)),
				));
				curl_exec($ch);
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

$ac->log('::group::ARI');
$ac->log(print_r($ac->getARI(reset($fullchain)),true));
$ac->log('::endgroup::');


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



//$ac->log('::group::');
//$ac->log('::endgroup::');

