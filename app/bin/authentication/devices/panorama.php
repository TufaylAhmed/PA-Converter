<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 21/6/16 - 11:52
 */

//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

//require_once INC_ROOT.'/bin/Authentication.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';
require_once INC_ROOT.'/libs/projectdb.php';
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
    $mode       = $pandb->real_escape_string((string)(isset($_GET['mode'])         ? $_GET['mode']         : ''));
    $format     = $pandb->real_escape_string((string)(isset($_GET['format'])       ? $_GET['format']       : 'json'));
    $deviceSerial=$pandb->real_escape_string((string)(isset($_GET['serial'])       ? $_GET['serial']   : ''));
    $type       = $pandb->real_escape_string((string)(isset($_GET['type'])         ? $_GET['type']         : ''));
}

if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
}

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        switch ($type){
            case 'retrieveConnected':
                break;

            case 'listConnected':
            default:
                $message = getListConnected($deviceSerial);
                break;
        }
        if($message['code']) {
            echo json_encode(array('total' => count($message['msg']), 'devices' => $message['msg']));
        }
        else{
            echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        }
        break;

    case 'POST':
        break;

    case 'PUT':
        break;

    case 'DELETE':
        $message = delete_Device($data);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    default:
        break;
}

function getListConnected(STRING $deviceSerial){
    global $app;

    if(!$device = $app->device->where('serial', $deviceSerial)->where('ispanorama','1')->get()->first()){
        $message = array();
        $message['code'] = true;
        $message['msg'] = '';  //This is not a panorama device
        return $message;
    }
    
    if(!$connectedDevices = $app->device->where('management',$deviceSerial)->get()){
        $message = array();
        $message['code'] = true;
        $message['msg'] = ''; //We couldn't get any device connected to this panorama
        return $message;
    }

    $message = array();
    $message['code'] = true;
    $message['msg'] = $connectedDevices;
    return $message;

}

function getContents(STRING $deviceSerial){
    global $app;

    if(!$device = $app->device->where('serial', $deviceSerial)->get()->first()){
        $message = array();
        $message['code'] = true;
        $message['msg'] = '';
        return $message;
    }

    $downloadings = array();
    //Check if there are any pending tasks for this device
    if($jobs = $app->job->where('parentType','devices')->where('parentId',$device->id)->whereColumn('completed','<','tasks')->get()){
        foreach ($jobs as $job){
            $tasks = $job->tasks()->get();
            foreach ($tasks as $task){
                $type = $task->taskName;

//                echo "$task->taskName should be Downloading...<br>";
                $downloadings[$task->taskName]['processed'] = false;
            }
        }
    }

    $fileList = array();
    $files = scandir(INC_ROOT.'/devices/'.$device->serial);

    foreach ($files as $file){
        if($file == '.' || $file == '..') {
        }
        else {
            switch($file){
                case "ConfigBackup.xml":
                    $fileItem['type'] = 'Download Configuration';
                    break;

                case "applications-container.xml":
                    $fileItem['type'] = 'Download Application Container';
                    break;

                case (preg_match('/SharedPushedPolicy.*/', $file) ? true : false):
                    $fileItem['type'] = 'Download Configuration';
                    break;

                case "applications.xml":
                    $fileItem['type'] = 'Download Applications';
                    break;

                case "region.xml":
                    $fileItem['type'] = 'Download Regions';
                    break;

                default:
                    $fileItem['type'] ='custom';
                    break;
            }
            $fileItem['filename'] = $file;
            $fileItem['date'] = date("F d Y H:i:s", filemtime(INC_ROOT . '/devices/' . $device->serial . '/' . $file));
            $fileItem['size'] = FileSizeConvert(filesize(INC_ROOT . '/devices/' . $device->serial . '/' . $file));
//            $fileItem['link'] = INC_ROOT . '/devices/' . $device->devicename . '/' . $file;
            if(isset($downloadings[$fileItem['type']])){
                $fileItem['status'] = 'Updating...';
                $downloadings[$fileItem['type']]['processed'] = true;
            }
            else {
                $fileItem['status'] = 'downloaded';
            }
            $fileItem['available'] = true;
            $fileList[] = $fileItem;
        }
    }

    foreach ($downloadings as $key=>$downloading){
        if(!$downloading['processed']){
            $fileItem['type'] = $key;
            $fileItem['filename'] = 'unknown';
            $fileItem['date'] = 'n/a';
            $fileItem['size'] = 'n/a';
            $fileItem['status'] = 'Downloading...';
            $fileItem['available'] = false;
            $fileList[] = $fileItem;
        }
    }

    $message = array();
    $message['code'] = true;
    $message['msg'] = $fileList;
    return $message;
}

/**
 * Converts bytes into human readable file size.
 *
 * @param string $bytes
 * @return string human readable file size (2,87 Мб)
 * @author Mogilev Arseny
 */
function FileSizeConvert($bytes)
{
    $bytes = floatval($bytes);
    $arBytes = array(
        0 => array(
            "UNIT" => "TB",
            "VALUE" => pow(1024, 4)
        ),
        1 => array(
            "UNIT" => "GB",
            "VALUE" => pow(1024, 3)
        ),
        2 => array(
            "UNIT" => "MB",
            "VALUE" => pow(1024, 2)
        ),
        3 => array(
            "UNIT" => "KB",
            "VALUE" => 1024
        ),
        4 => array(
            "UNIT" => "B",
            "VALUE" => 1
        ),
    );

    foreach($arBytes as $arItem)
    {
        if($bytes >= $arItem["VALUE"])
        {
            $result = $bytes / $arItem["VALUE"];
            $result = str_replace(".", "," , strval(round($result, 2)))." ".$arItem["UNIT"];
            break;
        }
    }
    return $result;
}

function delete_Device($data){
    global $app;
    if(isset($data['action']) && $data['action'] == "delete_all"){
        require_once INC_ROOT . '/userManager/API/devices/delete.php';
        $deletedDevices = deleteManagedDevices($data);
        $message['code'] = true;
        $message['msg'] = implode(",",$deletedDevices).  " Managed Devices have been deleted";
        return $message;
    }
    else {
        if (!accessControl("any", ['device.delete', 'device.admin', 'deviceRole.'.$data['devicename'].'.delete'])) {
            $message = array();
            $message['code'] = false;
            $message['msg'] = 'Your account does not have device delete rights';
            return $message;
        }
        require_once INC_ROOT . '/userManager/API/devices/delete.php';
        $device = $app->device->where('serial',$data['serial'])->first();
        $deviceSerial = $device->serial;
        $devicePanos = $device->panos;
        $message = deleteDevice($data['serial']);
        if($message['code']){

            $cmd = "rm -rf ".escapeshellarg(USERSPACE_PATH."/Templates/".$deviceSerial."-".$devicePanos.".xml");
            shell_exec($cmd);
            $cmd = "rm -rf ".escapeshellarg(USERSPACE_PATH."/devices/".$deviceSerial);
            shell_exec($cmd);
        }

        return $message;
    }
}

function deleteManagedDevices($data){
    global $app;

    if(!accessControl("any", ['device.admin'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to delete devices';
        return $message;
    }

    $deletedDevices = array();
    $serial=$data['serial'];
    //Get all devices
    $deviceObjects = $app->device->where('management','=', $data['serial'])->get();

    foreach ($deviceObjects as $deviceObject){
        $deviceName = $deviceObject['serial'];
        $message = deleteDevice($deviceName);
        if ($message['code']){
            $deviceObject->delete();
            $deletedDevices[] = $deviceName;
        }
    }
    return $deletedDevices;
}