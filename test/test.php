<?php

require 'ACMECert.php';

use skoerfgen\ACMECert\ACMECert;

$ac=new ACMECert(false);

print_r($ac);


$key=$ac->generateECKey();
$ac->loadAccountKey($key);
print_r($ac->register(true));


$domain_config=array(
	'*.x.x.exampledomain.net'=>array('challenge'=>'dns-01'),
	'*.exampledomain.net'=>array('challenge'=>'dns-01'),
	'exampledomain.net'=>array('challenge'=>'dns-01'),
	'x.x.exampledomain.net'=>array('challenge'=>'dns-01'),
	'a.a.exampledomain.net'=>array('challenge'=>'dns-01'),
	'*.a.a.exampledomain.net'=>array('challenge'=>'dns-01'),	
	'b.b.exampledomain.net'=>array('challenge'=>'dns-01'),
	'*.b.b.exampledomain.net'=>array('challenge'=>'dns-01'),	
	'c.c.exampledomain.net'=>array('challenge'=>'dns-01'),
	'*.c.c.exampledomain.net'=>array('challenge'=>'dns-01'),	
	'd.d.exampledomain.net'=>array('challenge'=>'dns-01'),
	'*.d.d.exampledomain.net'=>array('challenge'=>'dns-01'),
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