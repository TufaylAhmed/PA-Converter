<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 13/6/16 - 13:19
 */


//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

//require_once INC_ROOT.'/bin/Authentication.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';

require_once INC_ROOT.'/libs/database.php';
require_once INC_ROOT.'/libs/shared.php';
require_once INC_ROOT.'/libs/xmlapi.php';
require_once INC_ROOT.'/bin/messaging/MessageSender.php';

require_once INC_ROOT.'/libs/Security/OpenSSLTools.php';

use PaloAltoNetworks\Expedition\Security\OpenSSLTools;

if(defined('CLI')){
    require_once INC_ROOT .'/userManager/API/accessControl_CLI.php';
}
else{
    require_once INC_ROOT .'/userManager/API/accessControl.php';
    //include_once INC_ROOT.'/libs/PaloAltoNetworks/Middleware/loadCSRFControl.php';
}

$request_body   = file_get_contents('php://input');
$data           = json_decode($request_body, true);

parse_str(file_get_contents("php://input"),$post_vars);

include INC_ROOT.'/bin/middleware_sanitizer.php';

if(isset($post_vars['type'])){
    $type = $pandb->real_escape_string($post_vars['type']);
}
else {
    $deviceSerial= (string)(isset($_GET['serial'])   ? $_GET['serial'] : '');
    $mode       = (string)(isset($_GET['mode'])         ? $_GET['mode'] : '');
    $configfile = (string)(isset($_GET['configfile'])   ? $_GET['configfile'] : '');
    $jobID      = (string)(isset($_GET['jobID'])        ? $_GET['jobID'] : '');

    $deviceSerial = $pandb->real_escape_string($deviceSerial);
    $mode = $pandb->real_escape_string($mode);
    $configfile = $pandb->real_escape_string($configfile);
    $jobID = $pandb->real_escape_string($jobID);
}

if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
}

if(!checkDeviceRights($deviceSerial,'view')){
    echo json_encode([
            "success" => true,
            "code"  => -1,
            "msg"   => "You do not have rights to see this device content",
        ]
    );
    return;
}

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
    case 'POST':
        //Control CSRF on some specific POST calls via a second CRF control function. Notice that in this specific case, the CSRF token was sent via GET
        include INC_ROOT . '/libs/PaloAltoNetworks/Middleware/loadCSRFControl_fromPOST.php';
        checkCSRF($_GET);
        downloadFile($deviceSerial,$configfile, $mode);
        break;

    default:
        break;
}

function downloadFile($deviceSerial,$configfile, $mode){

    global $app;
//    $user = $app->container->sentinel->getUser();

    $deviceObj = $app->device->where("serial", $deviceSerial)->first();

    $keyObj = $app->accessKey->where("type","device")->where("lid", $deviceObj->id)->first();
    $encryptor = new OpenSSLTools($keyObj->key, $keyObj->iv);

    if(!accessControl("any", ['device.admin','deviceRole.'.$deviceSerial.'.*'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'You do not have rights to download this file';
        return $message;
    }

    $buffer = "<?xml version=\"1.0\"?>\n";
    if(preg_match(ValidFileName, $configfile, $output_array)) {
        $configfilewithoutExt = preg_replace('/\\.[^.\\s]{1,5}$/', '', $configfile);

        $filePath = USERSPACE_PATH.'/devices/'.$deviceSerial.'/'.$configfilewithoutExt.'.xml.dat';
        if (file_exists($filePath)) {
            error_reporting(0 | E_PARSE);
            if ($content = $encryptor->decryptFromFile($filePath)) {
                $buffer = $buffer . $content;
            }
        }else{
            $configfilewithoutExt = $configfile;
            $filePath = USERSPACE_PATH.'/devices/'.$deviceSerial.'/'.$configfile.'.xml';
            $content = file_get_contents($filePath);
            $buffer = $buffer . $content;
        }
    }


//    header_remove();
    header("Content-type: application/xml; charset=\"utf-8\"");
    header("Content-Length: " . strlen($buffer));
    header('Content-Disposition:attachment; filename="'.$configfilewithoutExt.'.xml"');

    print($buffer);
    error_reporting(E_ALL ^ E_WARNING | E_PARSE);
}