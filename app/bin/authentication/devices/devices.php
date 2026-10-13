<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 13/5/16 - 15:28
 */
//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';

require_once INC_ROOT.'/userManager/API/devices/list.php';
require_once INC_ROOT.'/libs/database.php';
require_once INC_ROOT.'/libs/shared.php';
require_once INC_ROOT.'/libs/xmlapi.php';

include_once INC_ROOT.'/libs/PaloAltoNetworks/Middleware/loadCSRFControl.php';
include_once INC_ROOT.'/bin/authentication/devices/device_functions.php';

$request_body   = file_get_contents('php://input');
$data           = json_decode($request_body, true);

parse_str(file_get_contents("php://input"),$post_vars);

include INC_ROOT.'/bin/middleware_sanitizer.php';

if(isset($post_vars['type'])){
    $type = $pandb->real_escape_string($post_vars['type']);
}
else {
    $type       = (string)(isset($_GET['type'])         ? $_GET['type'] : '');
    $scope      = (string)(isset($_GET['scope'])        ? $_GET['scope']: '');
    $projectName= (string)(isset($_GET['projectName'])  ? $_GET['projectName']: '');
    $skipListingFiles= ((isset($_GET['showFiles']) && $_GET['showFiles']==1)  ? 0 : 1);

    $type = $pandb->real_escape_string($type);
    $scope = $pandb->real_escape_string($scope);
    $projectName = $pandb->real_escape_string($projectName);

}

if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
}

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $message = list_Devices($scope, $projectName, $skipListingFiles);
        if($message['code']) {
            $totalDevices = count($message['msg']);
            echo json_encode(array('total' => $totalDevices, 'devices' => $message['msg']));
        }
        else{
            echo '{"total":"0","devices":[]}';
        }
        break;

    case 'POST':
        $message = register_Device($data);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    case 'PUT':
        unset($data['config']);
        unset($data['panos']);
        unset($data['threats']);
        unset($data['apps']);
        unset($data['ispanorama']);
        unset($data['appversion']);
        unset($data['appreleasedate']);
        unset($data['threatversion']);
        unset($data['threatreleasedate']);
        unset($data['urldb']);
        unset($data['wildfireversion']);
        unset($data['uptime']);
        unset($data['avversion']);
        unset($data['urlfilteringversion']);

        unset($data['created_at']);
        unset($data['updated_at']);

        $message = update_Device($data);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    case 'DELETE':
        $message = delete_Device($data);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    default:
        break;
}

function delete_Device($data){
    global $app;
    if(isset($data['action']) && $data['action'] == "delete_all"){
        require_once INC_ROOT . '/userManager/API/devices/delete.php';
        $deletedDevices = deleteAllDevices();
        $devicesName = implode(",", $deletedDevices );
        $message['code'] = true;
        $message['msg'] = "Devices in the list ($devicesName) have been deleted";
        return $message;
    }
    else {
        if (!accessControl("any", ['device.delete', 'device.admin', 'deviceRole.'.$data['serial'].'.delete'])) {
            $message = array();
            $message['code'] = false;
            $message['msg'] = 'Your account does not have device delete rights';
            return $message;
        }
        require_once INC_ROOT . '/userManager/API/devices/delete.php';
        if(!$device = $app->device->where('serial',$data['serial'])->first()){
            $message = array();
            $message['code'] = false;
            $message['msg'] = 'Device not found';
            return $message;
        }

        $deviceSerial = $device->serial;
        $devicePanos = $device->panos;
        $message = deleteDevice($data['serial']);
        if($message['code']){
            //$cmd = "rm -rf ".USERSPACE_PATH."/Templates/".$deviceSerial."-".$devicePanos.".xml";
            //shell_exec($cmd);
            $cmd = "rm -rf ".escapeshellarg(USERSPACE_PATH."/devices/".$deviceSerial);
            shell_exec($cmd);
        }
        //If a panorama, delete all the attached devices
        if($device->ispanorama == 1){
            $devicesManaged = $app->device->where('management', '=', $device->serial)->get();
            foreach ($devicesManaged as $deviceManaged){
                deleteDevice($deviceManaged->serial);
            }
        }
        return $message;
    }
}

function update_Device($data){

    if (!accessControl("any", ['device.create', 'device.admin','deviceRole.'.$data['serial'].'.update'])) {
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have device update rights';
        return $message;
    }

    if ($data['type'] == "m100") {
        $data['thumb'] = "m100.png";
        $data['ispanorama'] = 1;
    }
    elseif ($data['type'] == "m500") {
        $data['thumb'] = "m500.png";
        $data['ispanorama'] = 1;
    }
    elseif ($data['type'] == "vm-panorama") {
        $data['thumb'] = "panorama.png";
        $data['ispanorama'] = 1;
    } else {
        if ($data['type']==""){
            $data['thumb'] = "ngfw.png";
            $data['ispanorama'] = 0;
        }
        else{
            $data['thumb'] = $data['type'].".png";
            $data['ispanorama'] = 0;
        }

    }
    require_once INC_ROOT.'/userManager/API/devices/update.php';

//    $data2 = array();
//    $data2['devicename']    = $data['devicename'];
//    $data2['hostname']      = $data['hostname'];
//    $data2['type']          = $data['type'];
//    $data2['id']            = $data['id'];
//    $data2['description']   = $data['description'];
//    $data2['serial']        = $data['serial'];
//    $data2['serialHA']      = $data['serialHA'];
//    $data2['csv_path']      = $data['csv_path'];
//    $data2['logtype']       = $data['logtype'];
//    print_r($data);
//    print_r($data2);
//    if(isset($data['licenses'])) {
//        unset($data['licenses']);
//    }
//    print_r($data);
    $message = updateDevice($data);
    return $message;
}

function register_Device($data){
    require_once INC_ROOT.'/userManager/API/devices/register.php';
    $message = registerDevice($data);

    return $message;
}

function list_Devices(STRING $scope, STRING $projectName, bool $skipListingFiles){
    require_once INC_ROOT.'/userManager/API/devices/list.php';
    $message = listDevices($scope, $projectName, $skipListingFiles);

    $databases = array();
    if($message['code']) {
        foreach ($message['msg'] as $device) {
            $accessValid = listViewDevice($device->devicename);
            if ($accessValid) {
                $device->admin = listAdminDevice($device->devicename);

                $device->contents = '';
                $contents = getContents($device->serial);

                foreach ($contents['msg'] as $content){
                    if($content['filename']== "ConfigBackup.xml.dat"){
                        $device->configDate = $content['date'];
                        continue;
                    }
                }

                $databases[] = $device;
            }
        }
    }
    $message['msg'] = $databases;
    return $message;
}