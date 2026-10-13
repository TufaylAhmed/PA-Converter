<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 20/5/16 - 9:56
 */
//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

//require_once INC_ROOT.'/bin/Authentication.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';
require_once INC_ROOT.'/libs/database.php';

require_once INC_ROOT.'/userManager/API/projects/manageDevices.php';

include_once INC_ROOT.'/libs/PaloAltoNetworks/Middleware/loadCSRFControl.php';

$request_body   = file_get_contents('php://input');
//echo var_dump($request_body);
$data           = json_decode($request_body, true);

parse_str(file_get_contents("php://input"),$post_vars);

include INC_ROOT.'/bin/middleware_sanitizer.php';

if(isset($post_vars['type'])){
    $type = $pandb->real_escape_string($post_vars['type']);
}
else {
    $type       = $pandb->real_escape_string((string)(isset($_GET['type']) ? $_GET['type'] : ''));
}
$project    = $pandb->real_escape_string((string)(isset($_GET['project'])  ? $_GET['project'] : ''));

if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
}

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $message = list_SelectedDevices($project);
        if ($message['code']) {
            $totalDevices = count($message['msg']);
            echo json_encode(array('total' => $totalDevices, 'devices' => $message['msg']));
        } else {
            echo '{"total":"0","devices":[]}';
        }
        break;

    case 'POST':
        $message = select_Device($project, $data);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    case 'PUT':
//        $message = update_Attachement($project, $data);
//        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    case 'DELETE':
        $message = deselect_Device($project, $data);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    default:
        break;
}

function list_SelectedDevices(String $project){
    $message = listSelectedDevices($project);
    return $message;
}

function select_Device($project, ARRAY $data){
    $message = selectDeviceToProject($project, $data);
    return $message;
}

function update_Attachement($project, ARRAY $data){
    $message = updateDeviceAttachement($project, $data);
    return $message;
}

function deselect_Device($project, ARRAY $data){
    if($data['id']=='all') {
        $message = deselectAllDevicesFromProject($project);
    }
    else {
        $message = deselectDeviceFromProject($project, $data);
    }
    return $message;
}
