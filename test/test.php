<?php

require 'ACMECert.php';

use skoerfgen\ACMECert\ACMECert;

$ac=new ACMECert('https://pebble:14000/dir');

print_r($ac);


$key=$ac->generateECKey();
$ac->loadAccokapootuntKey($key);
print_r($ac->register(true));



/*echo "::error title=Account2::Registration unsuccessful\n";
echo "::notice title=Account::Registration successful\n";
echo "::warning title=Foo::Missing semicolon or not\n";*/


$domain_config=array(
	'example.net'=>array('challenge'=>'dns-01'),
	'example.net'=>array('challenge'=>'dns-01'),
	'example.net'=>array('challenge'=>'dns-01'),
	'example.net'=>array('challenge'=>'dns-01'),
	'example.net'=>array('challenge'=>'dns-01'),
	'example.net'=>array('challenge'=>'dns-01'),
	'example.net'=>array('challenge'=>'dns-01'),
	'example.net'=>array('challenge'=>'dns-01'),
	'example.net'=>array('challenge'=>'dns-01'),
	'example.net'=>array('challenge'=>'dns-01'),
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