<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 27/5/16 - 9:16
 */

//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

//require_once INC_ROOT.'/bin/Authentication.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/API/devices/manageKeys.php';
require_once INC_ROOT.'/libs/database.php';

include_once INC_ROOT.'/libs/PaloAltoNetworks/Middleware/loadCSRFControl.php';

$request_body   = file_get_contents('php://input');
$data           = json_decode($request_body, true);

parse_str(file_get_contents("php://input"),$post_vars);

include INC_ROOT.'/bin/middleware_sanitizer.php';

if(isset($post_vars['type'])){
    $type = $pandb->real_escape_string($post_vars['type']);
}
else {
    $type       = (string)(isset($_GET['type']) ? $_GET['type'] : '');
}
$deviceSerial    = (string)(isset($_GET['serial']) ? $_GET['serial'] : '');

$type = $pandb->real_escape_string($type);
$deviceSerial = $pandb->real_escape_string($deviceSerial);

if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
}

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $message = list_AttachedKeys($deviceSerial);
        if($message['code']) {
            $totalDevices = count($message['msg']);
            echo json_encode(array('total' => $totalDevices, 'keys' => $message['msg']));
        }
        else{
            echo '{"total":"0","keys":[]}';
        }
        break;

    case 'POST':
        $message = attach_Key($data);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    case 'PUT':
        $message = update_Key($deviceSerial, $data);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    case 'DELETE':
        $message = detach_Key($deviceSerial, $data);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    default:
        break;
}

function list_AttachedKeys(String $data){
    $message = listAttachedKeys($data);
    return $message;
}

function attach_Key(ARRAY $data){
    $message = addKeyToDevice($data);
    return $message;
}

function update_Key(String $deviceSerial, ARRAY $data){
    $message = updateKeyAttachement($deviceSerial, $data);
    return $message;
}

function detach_Key(String $deviceSerial, ARRAY $data){
    $message = removeKeyFromDevice($deviceSerial, $data);
    return $message;
}