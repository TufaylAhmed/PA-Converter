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
$view       = $pandb->real_escape_string((string)(isset($_GET['view'])     ? $_GET['view'] : ''));
$context    = $pandb->real_escape_string((string)(isset($_GET['context'])  ? $_GET['context'] : ''));

if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
}

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $message = list_AttachedDevices($project, $view, $context);
        if($view =='tree') {
            if ($message['code']) {
                $devices = array();
                foreach ($message['msg'] as $key => $item) {
                    $devices[] = $item;
                }
                if($context=='available') {
                    echo '[{"expanded":"true","devicename":"Available Devices", "children":' . json_encode($devices) . '}]';
                }
                else{
                    echo '[{"expanded":"true","devicename":"Allowed Devices", "children":' . json_encode($devices) . '}]';
                }
            }
            else{
                echo '[{"expanded":"true","devicename":"Available Devices", "children":[]}]';
            }
        }
        else{
            if ($message['code']) {
                $totalDevices = count($message['msg']);
                echo json_encode(array('total' => $totalDevices, 'devices' => $message['msg']));
            } else {
                echo '{"total":"0","devices":[]}';
            }
        }
        break;

    case 'POST':
        $message = attach_Device($project, $data, $context);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    case 'PUT':
        $message = update_Attachement($project, $data);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    case 'DELETE':
        $message = detach_Device($project, $data);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    default:
        break;
}

function list_AttachedDevices(String $data, String $view, String $context){
    switch ($view){
        case 'tree':
            $message = list_AttachedDevicesTree($data, $context);
            break;

        default:
            $message = listAttachedDevices($data);
            break;
    }
    return $message;
}

function attach_Device($project, ARRAY $data, STRING $context){
    if($context == 'allowed') {
        if(isset($data['id'])){
            $data_ = array($data);
            $data = $data_;
        }

        foreach ($data as $device) {
            $deviceAr = [
                'id' => $device['id'],
            ];
            $message = attachDeviceToProject($project, $deviceAr);
        }

        return $message;
    }
    $message = array();
    $message['code'] = true;
    $message['msg'] = '';
    return $message;
}

function update_Attachement($project, ARRAY $data){
    $message = updateDeviceAttachement($project, $data);
    return $message;
}

function detach_Device($project, ARRAY $data){
    if($data['id']=='all') {
        $message = detachAllDevicesFromProject($project);
    }
    else {
        $message = detachDeviceFromProject($project, $data);
    }
    return $message;
}

function list_AttachedDevicesTree(STRING $projectName, String $context){
    require_once INC_ROOT.'/userManager/API/devices/list.php';

    //
    $messageAttached    = listAttachedDevices($projectName);
    $messageAllDev      = listDevices('', '');

    $attachedIds = array();
    foreach ($messageAttached['msg'] as $att){
        $attachedIds[] = $att->id;
    }

    $devices = array();
    foreach ($messageAllDev['msg'] as  $device) {
        $accessValid = listViewDevice($device->devicename);
        if($accessValid){
            $device->admin = listAdminDevice($device->devicename);
            $devices[] = $device;
        }
    }

    if($context == 'allowed'){
        //remove the instances not in $messageAttached
        $attached = array();
        foreach ($devices as $device) {
            $key = $device->id;
            if (in_array($key, $attachedIds)) {
                $device->assigned = true;
                $attached[] = $device;
            }
        }
    }
    else{
        //remove the instances in $messageAttached
        $attached = array();
        foreach ($devices as $device) {
           // if($device->config == 1) {
                $key = $device->id;
                if (!in_array($key, $attachedIds)) {
                    $attached[] = $device;
                }
            //}
        }
    }
//    echo json_encode($devices);
    $message['code'] = true;
    $message['msg'] = structTree($attached, $messageAllDev['msg']);
    return $message;
}

function structTree(ARRAY $databases, $allDevices){
    $devices = array();

    //Check root devices
    foreach ($databases as $device){
        if($device->management == ''){
            $device->expanded = false;
            if($device->ispanorama=='1'){
                $device->iconCls = "icon-devices";
            }
            else{
                $device->iconCls = "icon-device";
            }
            $devices[$device->devicename] = $device;
            $device->leaf=true;
        }
    }

    foreach ($databases as $device){
        if($device->management != ''){
            if(isset($devices[$device->management])) {
                $panorama = $devices[$device->management];
            }
            else{
                $allDevicesAr = array();
                foreach ($allDevices as $deviceAr) {
                    $key = $deviceAr->serial;
                    if($key == $device->management){
                        $panorama = $deviceAr;
                        $panorama->iconCls = "icon-devices";
                        $panorama->assigned = false;
                        $panorama->expanded = true;
                        break;
                    }
                }


            }

            $device->expanded = false;
            $device->leaf=true;
            if($device->ispanorama=='1'){
                $device->iconCls = "icon-devices";
            }
            else{
                $device->iconCls = "icon-device";
            }

//            $device->iconCls = "icon_".$device->type.".png";
            $panorama->children[] = $device;
            $panorama->leaf = false;
            $devices[$device->management] = $panorama;
        }
    }

    return $devices;
}
