<?php

$arrContextOptions=array(
    "ssl"=>array(
        "verify_peer"=>false,
        "verify_peer_name"=>false,
    ),
		"http"=>array(
			'user_agent'=>'ACMECert v3.7.3 (+https://github.com/skoerfgen/ACMECert)',
			'ignore_errors'=>true,
		)
);  
$response=file_get_contents('https://pebble:14000/dir', false, stream_context_create($arrContextOptions));
var_dump($response);

$arrContextOptions=array(
    "ssl"=>array(
        "verify_peer"=>false,
        "verify_peer_name"=>false,
    ),
);  
$response=file_get_contents('http://nginx/', false, stream_context_create($arrContextOptions));
var_dump($response);