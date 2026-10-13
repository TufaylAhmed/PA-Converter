<?php

$_SERVER['DOCUMENT_ROOT'] = '/var/www/html';
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
require_once INC_ROOT.'/libs/projectdb.php';
require_once INC_ROOT .'/userManager/API/accessControl_CLI.php';
require_once INC_ROOT.'/libs/common/tools/tools.php';

// CODE STARTS HERE
// Read the log file
$path = "/tmp/";

$csvFiles = glob($path . '/*.csv');
echo "Listing files on path: ". $path .PHP_EOL;
print_r($csvFiles);
foreach ($csvFiles as $file) {
    echo "File to process : " . $file . PHP_EOL;
    $continue = readline("Continue? (Y,n) ");

    if($continue==="Y") {
        $output_file = $file . "_traffic_only.csv";
        echo "\tLooking for TRAFFIC and creating new file:" . $output_file . PHP_EOL;
        exec("grep 'TRAFFIC' $file > $output_file", $error_code);
        echo "\tCompressing processed file:" . $file . PHP_EOL;
        exec("gzip $file", $output, $error_code);
    }
}
echo "Finish" . PHP_EOL;

