<?php

echo 'PHP Version: '.PHP_VERSION,"\n";
// echo "Own IP: " . gethostbyname(gethostname()) . "\n";

require 'ACMECert.php';
use skoerfgen\ACMECert\ACMECert;

open('EAB');
$ac=new ACMECert('https://127.0.0.1:14000/dir');
$ac->setLogger(function($txt){
	echo $txt,"\n";
});
$ac->loadAccountKey($ac->generateRSAKey());
print_r($ac->registerEAB(true,'kid-1','zWNDZM6eQGHWpSRTPal5eIUYFTu7EajVIoguysqZ9wG44nMEtx3MUAsUDkMTQ12W'));
close();

$ac=new ACMECert('https://pebble:14000/dir');
$ac->setLogger(function($txt){
	echo $txt,"\n";
});

$ac->loadAccountKey($ac->generateRSAKey());
$ac->register(true);

// update
open('Update Account');
print_r($ac->getAccount());
$ac->update('info@example.net');
print_r($ac->getAccount());
$ac->update(['info@example.net','info2@example.net']);
print_r($ac->getAccount());
close();

open('Metadata');
print_r([
	'getTermsURL'=>$ac->getTermsURL(),
	'getCAAIdentities'=>$ac->getCAAIdentities(),
	'getProfiles'=>$ac->getProfiles(),
]);
close();

// cert
open('Generate Certificate');

$domain_config=array(
	'*.example.net'=>array('challenge'=>'dns-01'),
	'sub.other.example.net'=>array('challenge'=>'dns-01'),
	'sub2.other.example.net'=>array('challenge'=>'tls-alpn-01'),
	'example.net'=>array('challenge'=>'http-01'),
);
$domain_config[gethostbyname('challtestsrv')]=array('challenge'=>'http-01');

echo 'domain_config ';
print_r($domain_config);

$handler=function($opts) use ($ac){
	switch($opts['config']['challenge']){
		case 'dns-01':
			$ac->log('-> Set DNS TXT record '.$opts['key'].' -> '.$opts['value']);
			req('set-txt',array(
				'host'=>$opts['key'].'.',
				'value'=>$opts['value']
			));
			
			return function($opts)use($ac){
				$ac->log('<- Remove DNS record '.$opts['key'].' <- '.$opts['value']);
				req('clear-txt',array(
					'host'=>$opts['key'].'.',
				));
			};
		break;
		case 'http-01':
			$ac->log('-> Set file '.$opts['key'].' -> '.$opts['value']);
			setA($opts['domain'],gethostbyname('challtestsrv'));
			req('add-http01',array(
				'token'=>basename($opts['key']),
				'content'=>$opts['value']
			));
	
			return function($opts)use($ac){
				$ac->log('<- Remove file '.$opts['key'].' <- '.$opts['value']);
				req('del-http01',array(
					'token'=>$opts['key'],
				));
			};
		break;
    case 'tls-alpn-01':
			setA($opts['domain']);

			file_put_contents('some_private_key.pem',$ac->generateRSAKey());
			$cert=$ac->generateALPNCertificate('file://'.'some_private_key.pem',$opts['domain'],$opts['value']);
      $ac->log('-> Set ALPN certificate -> '.$opts['value']);
			echo $cert;
			file_put_contents('alpn_cert.pem',$cert);
      $resource=proc_open(
        'node alpn_responder.js some_private_key.pem alpn_cert.pem',
        array(
          0=>array('pipe','r'),
          1=>array('pipe','w')
        ),
        $pipes
      );

      $ac->log(trim(fgets($pipes[1])));

      return function($opts) use ($resource,$pipes,$ac){
        // Stop ALPN Responder
        fclose($pipes[0]);
        fclose($pipes[1]);
        proc_terminate($resource);
        proc_close($resource);
				$ac->log('ACMECert Example ALPN Responder - Terminated');
      };
    break;
	}
};

$fullchains=$ac->getCertificateChains($ac->generateRSAKey(),$domain_config,$handler);
$ret=$ac->getSAN(reset($fullchains));
echo 'Subject Alternative Names (SAN) ';
print_r($ret);

foreach($fullchains as $issuer=>$chain){
	echo 'Chain: '.$issuer.' ';
	print_r($ac->splitChain($chain));	
}

print_r([
	'getRemainingPercent'=>$ac->getRemainingPercent(reset($fullchains)),
	'getRemainingDays'=>$ac->getRemainingDays(reset($fullchains))
]);

close();

if (PHP_VERSION_ID>=70201){
	open('ACME Renewal Information (ARI)');
	$ari=$ac->getARI(reset($fullchains));
	print_r($ari);
	close();
	
	open('Using ARI');
	$fullchains=$ac->getCertificateChains($ac->generateRSAKey(),$domain_config,$handler,array('replaces'=>$ari['ari_cert_id']));
	print_r($fullchains);
	close();
}

open('Profiles');
foreach($ac->getProfiles() as $name=>$description){
	echo 'Using Profile "'.$name.'" ('.$description.')',"\n";
	$fullchains=$ac->getCertificateChains($ac->generateRSAKey(),$domain_config,$handler,array('profile'=>$name));
	print_r($fullchains);
}
close();


open('Revoke Certificate');
$ac->revoke(reset($fullchains));
close();

open('Using pre-generated CSR');
$csr=$ac->generateCSR($ac->generateRSAKey(),array_keys($domain_config));
echo 'CSR '.$csr,"\n";
$fullchains=$ac->getCertificateChains($csr,$domain_config,$handler);
print_r($fullchains);
close();


foreach([2048,3072,4096] as $k=>$bits){
	open('Generate RSA '.$bits.' Key ('.($k===0?'Register':'Account Key Rollover').')');
	$key=$ac->generateRSAKey($bits);
	echo $key;
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
		echo $key;
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
function setA($host,$ip=null){
	req('add-a',array(
		'host'=>$host,
		'addresses'=>array($ip===null?gethostbyname(gethostname()):$ip)
	));	
}

function open($txt){
	echo '::group::'.$txt,"\n";
}
function close(){
	echo '::endgroup::',"\n";
}