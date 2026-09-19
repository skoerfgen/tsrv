<?php

echo 'PHP Version: '.PHP_VERSION,"\n";
// echo "Own IP: " . gethostbyname(gethostname()) . "\n";

require 'ACMECert.php';
use skoerfgen\ACMECert\ACMECert;

/*class AC extends ACMECert {
	function __construct($dir){
		parent::__construct($dir);
		$this->ch=false;
	}
}*/

var_dump($argv);


