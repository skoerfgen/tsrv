<?php

require 'ACMECert.php';

use skoerfgen\ACMECert\ACMECert;

$ac=new ACMECert('https://pebble:14000/dir');

print_r($ac);


$key=$ac->generateECKey();
$ac->loadAccountKey($key);
print_r($ac->register(true));
echo "::notice title=Account::Registration successful\n";

$domain_config=array(
	'exampledomain0.net'=>array('challenge'=>'dns-01'),
	'exampledomain1.net'=>array('challenge'=>'dns-01'),
	'exampledomain2.net'=>array('challenge'=>'dns-01'),
	'exampledomain3.net'=>array('challenge'=>'dns-01'),
	'exampledomain4.net'=>array('challenge'=>'dns-01'),
	'exampledomain5.net'=>array('challenge'=>'dns-01'),
	'exampledomain6.net'=>array('challenge'=>'dns-01'),
	'exampledomain7.net'=>array('challenge'=>'dns-01'),
	'exampledomain8.net'=>array('challenge'=>'dns-01'),
	'exampledomain9.net'=>array('challenge'=>'dns-01'),
);

$ch=curl_init();

$handler=function($opts) use ($ac,$ch){
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
	

};

$fullchain=$ac->getCertificateChain($ac->generateECKey(),$domain_config,$handler,array('group'=>true,'authz_reuse'=>true));
$ret=$ac->getSAN($fullchain);
print_r($ret);
echo "\033[32m✓ Certificate generated successfully\033[0m\n";

file_put_contents(getenv('GITHUB_STEP_SUMMARY'), 'looks good', FILE_APPEND);