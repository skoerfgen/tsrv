<?php

$arrContextOptions=array(
		"http"=>array(
			'user_agent'=>'ACMECert v3.7.3 (+https://github.com/skoerfgen/ACMECert)',
			'ignore_errors'=>true,
		)
);  
$response=file_get_contents('https://pebble:14000/dir', false, stream_context_create($arrContextOptions));
var_dump($response);
