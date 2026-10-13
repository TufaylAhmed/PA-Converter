<?php
# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

//User management control
require_once INC_ROOT.'/userManager/start.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';

switch($_SERVER['REQUEST_METHOD']) {
    case 'GET':
        $message = check();
        echo $message;
        break;
}

function getSslPage($url, $verify=false) {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, $verify);
    curl_setopt($ch, CURLOPT_HEADER, false);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_REFERER, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT ,2);
    curl_setopt($ch, CURLOPT_TIMEOUT, 5); //
    $result = curl_exec($ch);
    curl_close($ch);
    return $result;
}

function check(){
    $xmlstr=getSslPage("https://conversionupdates.paloaltonetworks.com/ver.xml",false);
    libxml_use_internal_errors(true);
    $doc = simplexml_load_string($xmlstr);

    if (!$doc) {
        //$errors = libxml_get_errors();
        //libxml_clear_errors();
        return 0;
    }
    else{
        return (string) $doc->version;
    }
}
