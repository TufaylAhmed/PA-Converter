<?php

$data=file('flags.txt');

foreach ($data as $key=>$value){
	print "wget --no-check-certificate https://10.11.29.110/images/flags/".trim($value).".gif\n";
}

?>
