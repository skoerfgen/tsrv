<?php

$arrContextOptions=array(
    "ssl"=>array(
        "verify_peer"=>false,
        "verify_peer_name"=>false,
    ),
);  
$response=file_get_contents('https://pebble:14000/dir', false, stream_context_create($arrContextOptions));
var_dump($response);