<?php

/***
 * This scrip performs the following tasks:
 * Step 1- Read a given checkpoint configuration
 * Step 2- Get the file defining the gateways
 * Step 3- Edit that file to store only information from the given gateway
 * Step 4- Generate a new tar.gz file with all the original config except the gateway information
 */


// ***************                   USER VARIABLES                   ***************

$checkpoint_config_name = 'show_package-2023-03-21_11-09-23';  //Provide the checkpoint_configuration_file
$checkpoint_config_path = '/tmp/show_package-2023-03-21_11-09-23.tar.gz';  //Provide the checkpoint_configuration_file
$gateways_to_keep = [   //Determine the FW that should not be removed from the gateways file
    'DE000-UT0-FW-607013'
//    ,'DE000-UT0-FW-607014'
];

// ***************                   /USER VARIABLES                   ***************
// CODE STARTS HERE

// UTIL FUNCTIONS
function anything_to_utf8($var,$deep=TRUE){
    if(is_array($var)){
        foreach($var as $key => $value){
            if($deep){
                $var[$key] = anything_to_utf8($value,$deep);
            }elseif(!is_array($value) && !is_object($value) && !mb_detect_encoding($value,'utf-8',true)){
                $var[$key] = utf8_encode($var);
            }
        }
        return $var;
    }elseif(is_object($var)){
        foreach($var as $key => $value){
            if($deep){
                $var->$key = anything_to_utf8($value,$deep);
            }elseif(!is_array($value) && !is_object($value) && !mb_detect_encoding($value,'utf-8',true)){
                $var->$key = utf8_encode($var);
            }
        }
        return $var;
    }else{
        return (!mb_detect_encoding($var,'utf-8',true))?utf8_encode($var):$var;
    }
}
// END UTIL FUNCTIONS
echo "\n Start \n";

// delete previous execution workspace directory
if(file_exists("/tmp/". $checkpoint_config_name)) {
    exec("rm -r /tmp/" . $checkpoint_config_name);
}

// delete previous output
if(file_exists("/tmp/" . $checkpoint_config_name ."_excluding_gateways.tar.gz")) {
    exec("rm /tmp/" . $checkpoint_config_name."_excluding_gateways.tar.gz");
}

// create execution workspace directory
if (!mkdir($concurrentDirectory = "/tmp/" . $checkpoint_config_name) && !is_dir($concurrentDirectory)) {
    throw new \RuntimeException(sprintf('Directory "%s" was not created', $concurrentDirectory));
}

// extract checkpoint configuration into the execution workspace directory
exec("cd /tmp/". $checkpoint_config_name . "; tar -zxvf ". $checkpoint_config_path);

// get the config file that contains the definitions of the gateways and interfaces
$indexJson=json_decode(file_get_contents("/tmp/" . $checkpoint_config_name . "/index.json"),true);
$objectFile =$indexJson['policyPackages'][0]['htmlGatewaysFileName'];
$objectFile=str_replace(".html",".json",$objectFile);
$objectFile="/tmp/". $checkpoint_config_name . "/". $objectFile;
$handle = fopen($objectFile, 'r');
$contents = fread($handle, 1);
fclose($handle);
// get the content as a JSON file
if ($contents=="["){
    $gateways_entries[]=file_get_contents($objectFile);
}
else{
    $gateways_entries[]="[";
    $gateways_entries[]=file_get_contents($objectFile);
    $gateways_entries[]="]";
}

$json=implode("",$gateways_entries);
$json=anything_to_utf8($json);
$gateways = json_decode($json, true);

// clean the gateway file
exec ("rm " . $objectFile ."; touch " . $objectFile);

// foreach gateway save those that we want to export
if(count($gateways)>0) {
    // will store gateways to extract
    $gateways_to_keep_content = array();

    foreach ($gateways as $gateway_key => $gateway_value) {

        if(in_array($gateways[$gateway_key]['name'], $gateways_to_keep)){
            $gateways_to_keep_content[] = $gateways[$gateway_key];
            echo "\n Saved: " . $gateways[$gateway_key]['name'];
        } else {
            echo "\n Not Saved: " . $gateways[$gateway_key]['name'];
        }
    }

    // print the gateways on the file
    echo "\n Adding saved gateways to file: " . htmlspecialchars($objectFile);
    $output = json_encode($gateways_to_keep_content);
    file_put_contents($objectFile, $output);

    // generate a new tar.gz file
    echo "\n Generating TAR FILE: " . $checkpoint_config_name ."_excluding_gateways.tar.gz \n";

    $files = $scanned_directory = array_diff(scandir($concurrentDirectory), array('..', '.'));
    $files_to_string = "";
    foreach($files as $file){
        $files_to_string.= " '$file'";
    }

    exec("cd ".escapeshellarg($concurrentDirectory).";tar -czvf /tmp/" .escapeshellarg($checkpoint_config_name) ."_excluding_gateways.tar.gz ". escapeshellarg($files_to_string));

    echo "\n End \n";
}


