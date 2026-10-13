<?php

# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
//User management control
require_once INC_ROOT.'/userManager/start.php';
include INC_ROOT.'/bin/authentication/sessionControl.php';
//Dependencies
require_once INC_ROOT.'/libs/database.php';
require_once INC_ROOT.'/libs/shared.php';
require_once INC_ROOT.'/libs/Security/OpenSSLTools.php';

require_once INC_ROOT.'/libs/objects/Response.php';

use PaloAltoNetworks\Expedition\Security\OpenSSLTools;

$request_body   = file_get_contents('php://input');
$data           = json_decode($request_body, true);

include INC_ROOT.'/bin/middleware_sanitizer.php';

//Capture request paramenters
switch($_SERVER['REQUEST_METHOD'])
{
    case 'POST':
        $deviceSerial       = $pandb->real_escape_string(isset($_POST['serial'])       ? $_POST['serial'] : '');
        $message = uploadConfig(['deviceSerial'=>$deviceSerial]);
        echo json_encode(array('success'=>$message->success ,'data' => $message->getMessages()));
        break;

    default:
        break;
}

//check the name of the uploaded Config file
function checkValidConfigFileName(STRING $name){
    if(preg_match('/^(MT-)(.)*$/', $name)) {
        echo json_encode(array('success' => false, 'msg' => "Please, rename your '$name' configuration file.<br> Make sure the configuration file is not named as \"MT-*\""));
        exit;
    }
}

function return_bytes($val)
{
    $val  = trim($val);

    $last = strtolower($val[strlen($val)-1]);
    $val  = substr($val, 0, -1); // necessary since PHP 7.1; otherwise optional

    switch($last) {
        // The 'G' modifier is available since PHP 5.1.0
        case 'g':
            $val *= 1024;
        case 'm':
            $val *= 1024;
        case 'k':
            $val *= 1024;
    }

    return $val;
}

function checkSize(STRING $field):array{
    $post_max_size = return_bytes(ini_get('post_max_size'));
    $upload_max_filesize = return_bytes(ini_get('upload_max_filesize'));
    $max = min([$post_max_size, $upload_max_filesize]);
    if (isset($_FILES[$field])) {
        if ($_FILES[$field]['size'] > $post_max_size) { //10 MB (size is also in bytes)
            // File too big
            $message =  array('success' => false, 'msg' => "This file is bigger than $max. Please update your php.ini settings (in /etc/php/7.0/apache2/php.ini)  and restart apache2 service\n");
        }
        else {
            // File within size restrictions
            $message =  array('success' => true, 'msg' => "");
        }
    }
    else{
        $message = array('success' => false, 'msg' => "There was an error. Probably the set of files is bigger than $max. Please update your post_max_size and upload_max_filesize variables php.ini settings (in /etc/php/7.0/apache2/php.ini) and restart apache2 service (sudo service apache2 restart)");
    }
    return $message;
}


function uploadConfig(array $data): Response{
    global $app;

    if(!accessControl("any", ['device.admin', 'device.create'])){
        return new Response(false, -1, new Messages(['Your account does not have the rights to manage this device']));
    }

    $deviceSerial = $data['deviceSerial'];
    if (!file_exists(USERSPACE_PATH."/devices/$deviceSerial/")) {
        mkdir(USERSPACE_PATH."/devices/$deviceSerial/", 0777, true);
    }

    if (!$deviceObj = $app->device->where("serial",$deviceSerial)->get()->first()){
        return new Response(false, -1, new Messages(['Device not found in our database']));
    }

    if (!$keyObj = $app->accessKey->where("type", "device")->where("lid", $deviceObj->id)->get()->first()){
        return new Response(false, -1, new Messages(['This device does not have encryption credentials. Please, verify general Health Checks']));
    }

    $encryptor = new OpenSSLTools($keyObj->key, $keyObj->iv);

    if (isset($_FILES['manuallyuploadconfig']) && $_FILES['manuallyuploadconfig']['name'] != "") {
        $sizeCheck = checkSize('manuallyuploadconfig');
        if($sizeCheck['success']==false){
            return new Response(false, -1, new Messages([$sizeCheck->msg]));
        }
        checkValidConfigFileName($_FILES['manuallyuploadconfig']['name']);
        $target_path = USERSPACE_PATH."/devices/$deviceSerial/ConfigBackup.xml" ;
        if (move_uploaded_file($_FILES['manuallyuploadconfig']['tmp_name'], $target_path)) {
            $encryptor->encryptFiletoFile($target_path,"$target_path.dat");
            unlink($target_path);
            $params = ['config' => 1];
            $deviceObj->update($params);
            return new Response(true, 0, new Messages(['All the minimum files have been uploaded correctly.']));
        }
        else {
            $post_max_size = return_bytes(ini_get('post_max_size'));
            $upload_max_filesize = return_bytes(ini_get('upload_max_filesize'));
            $max = min([$post_max_size, $upload_max_filesize])/1024/1024;
            return new Response(false, -1, new Messages(["Error ocurred while uploading the file. \n".PHP_EOL.
                "Check potential causes:<br>\n".
                " php.ini post_max_size and upload_max_filesize too small. Current max value: $max MB<br>\n"]));
        }
    }
    else{
        return new Response(false, -2, new Messages(['No file found']));
    }
}

