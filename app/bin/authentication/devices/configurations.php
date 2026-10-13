<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 31/5/16 - 16:05
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

require_once INC_ROOT.'/bin/jobs/Job.php';

include_once INC_ROOT.'/libs/PaloAltoNetworks/Middleware/loadCSRFControl.php';

$request_body   = file_get_contents('php://input');
$data           = json_decode($request_body, true);

parse_str(file_get_contents("php://input"),$post_vars);

include INC_ROOT.'/bin/middleware_sanitizer.php';

if(isset($post_vars['type'])){
    $type = $pandb->real_escape_string($post_vars['type']);
}
else {
    $type       = (string)(isset($_GET['type'])         ? $_GET['type'] : '');
    $deviceName = (string)(isset($_GET['devicename'])   ? $_GET['devicename'] : '');
    $apikeyrole = (string)(isset($_GET['role'])         ? $_GET['role'] : '');
    $configtype = (string)(isset($_GET['configtype'])   ? $_GET['configtype'] : '');
    $jobID      = (string)(isset($_GET['job-id'])       ? $_GET['job-id'] : '');
    $mode       = (string)(isset($_GET['mode'])         ? $_GET['mode'] : '');

    $type = $pandb->real_escape_string($type);
    $deviceName = $pandb->real_escape_string($deviceName);
    $apikeyrole = $pandb->real_escape_string($apikeyrole);
    $configtype = $pandb->real_escape_string($configtype);
    $jobID = $pandb->real_escape_string($jobID);
    $mode = $pandb->real_escape_string($mode);
}

if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
}

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $message = getConfigurationDownloadStatus($jobID, $mode);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    case 'POST':
        $message = getConfiguration($data);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    case 'PUT':
//        $message = update_Device($data);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    case 'DELETE':
        $message = deleteDownloadJob($data);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    default:
        break;
}

function getConfigurationDownloadStatus(STRING $jobID, STRING $mode){
    if(!accessControl("any", ['device.admin', 'device.create' ])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have job query rights';
        return $message;
    }

    $job = new Job($jobID);
    return $job->getJobStatus($mode);
}

function getConfiguration(ARRAY $data){
    global $app;

    if(!accessControl("any", ['device.admin', 'device.create' ])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have device admin rights';
        return $message;
    }

    $data_individual = $data;
    $keysControl = array();
    $keysControl['code'] = true;

    //Collect the keys from the devices
    $devices = array();
    if (is_array($data['serial'])){
        $deviceSerials = $data['serial'];
        foreach ($deviceSerials as $deviceSerial){
            if($device = $app->device->where('serial',$deviceSerial)->get()->first()){
                if ($device->management == '') {
                    if (accessControl("any", ['device.admin', 'device.create', 'deviceRole.'.$device->serial.'.admin'])) {
                        $devices[] = $device->serial;
                    }
                    $key_name = $device->serial."_admin";
                    if(!$apikey = $app->apikey->where('key_name', '=', $key_name)->get()->first()){
                        $keysControl['code'] = false;
                        $keysControl['devices'][] = $device->serial;
                    }
                }
                else{ //It has a panorama management
                    if($panorama = $app->device->where('serial',$device->management)->get()->first()){
                        if (accessControl("any", ['device.admin', 'device.create', 'deviceRole.'.$panorama->serial.'.admin'])) {
                            $devices[] = $device->serial;
                        }
                    }
                    $key_name = $panorama['serial']."_admin";
                    if(!$apikey = $app->apikey->where('key_name', '=', $key_name)->get()->first()){
                        $keysControl['code'] = false;
                        $keysControl['devices'][] = $device->serial;
                    }
                }
            }
        }
    }
    else {
        $devices[] = $data['serial'];
        if (!accessControl("any", ['device.admin', 'device.create', 'deviceRole'.$data['serial'].'admin'])) {
            $message = array();
            $message['code'] = false;
            $message['msg'] = 'Your account does not have job query rights';
            return $message;
        }
        $key_name = $data['serial']."_admin";
        if(!$apikey = $app->apikey->where('key_name', '=', $key_name)->get()->first()){
            $keysControl['code'] = false;
            $keysControl['devices'][] = $data['serial'];
        }
    }

    //Prepare the task/message information
    $user = $app->container->sentinel->getUser();
    if(!$keysControl['code']){
        $message = array();
        $message['code'] = false;
        $deviceList = array_unique($keysControl['devices']);
        $message['msg'] = 'Please, generate an "admin" APIKEY first for the device(s): '.implode(',',$deviceList);
        return $message;
    }

    $api_key= getUserApiKey($user->getAttribute("api_key")??"", $user->getAttribute("valid_til")??"",$user->getAttribute("id"));
    $data_individual['key'] = $api_key;

    //The user wants to send the order to retrieve a specific file from the FW to the MT
    if (isset($data['content'])) {
        switch ($data['content']) {
            case "SystemInfo":
                 if(count($devices) > 1){
                    $parentJobID = $jobID = registerParentJob($user, 'Bundle of Download contents');
                    foreach($devices as $deviceSerial) {
                        $data_individual['serial'] = $deviceSerial;
                        $jobID = registerJob($data_individual, $user, 'Download contents from ', $parentJobID);
                        $taskID = registerTask($data_individual, $user, $jobID, "DownloadSystemInfo", "Download System Info");
                        get_Configuration($data_individual, $user, $taskID, "DownloadSystemInfo");
                    }
                }
                else{
                    $data_individual['serial'] = $devices[0];
                    $parentJobID = registerJob($data_individual, $user, 'Download contents from ');
                    $taskID = registerTask($data_individual, $user, $parentJobID, "DownloadSystemInfo", "Download System Info");
                    get_Configuration($data_individual, $user, $taskID, "DownloadSystemInfo");
                }
                $message = array();
                $message['code'] = true;
                $message['msg'] = $parentJobID;
                break;

            case "ConfigBackup":

                if(count($devices) > 1){
                    $parentJobID = $jobID = registerParentJob($user, 'Bundle of Download Configuration from Devices');
                    foreach($devices as $deviceSerial) {
                        $data_individual['serial'] = $deviceSerial;
                        $jobID = registerJob($data_individual, $user, 'Download contents from ', $parentJobID);
                        $taskID = registerTask($data_individual, $user, $jobID, "DownloadConfigBackup", "Download Configuration");
                        get_Configuration($data_individual, $user, $taskID, "DownloadConfigBackup");
                    }
                }
                else{
                    $data_individual['serial'] = $devices[0];
                    $parentJobID = registerJob($data_individual, $user, 'Download connected devices from ');
                    $taskID = registerTask($data_individual, $user, $parentJobID, "DownloadConfigBackup", "Download Configuration");
                    get_Configuration($data_individual, $user, $taskID, "DownloadConfigBackup");
                }
                $message = array();
                $message['code'] = true;
                $message['msg'] = $parentJobID;
                break;

            case "ConfigInfo":
//                if(count($devices) > 1){
//                    $parentJobID = $jobID = registerParentJob($user, 'Bundle of Download Configuration from Devices');
//                    foreach($devices as $deviceName) {
//                        $data_individual['devicename'] = $deviceName;
//                        $jobID = registerJob($data_individual, $user, 'Download contents from ', $parentJobID);
//                        $taskID = registerTask($data_individual, $user, $jobID, "DownloadConfigBackup", "Download Configuration");
//                        get_Configuration($data_individual, $user, $taskID, "DownloadConfigBackup");
//                    }
//                }
//                else{
//                    $data_individual['devicename'] = $devices[0];
//                    $parentJobID = registerJob($data_individual, $user, 'Download connected devices from ');
//                    $taskID = registerTask($data_individual, $user, $parentJobID, "DownloadConfigBackup", "Download Configuration");
//                    get_Configuration($data_individual, $user, $taskID, "DownloadConfigBackup");
//                }
//                $message = array();
//                $message['code'] = true;
//                $message['msg'] = $parentJobID;
                break;

            case "ConnectedDevices":
                if(count($devices) > 1){
                    $parentJobID = $jobID = registerParentJob($user, 'Bundle of Download Connected Devices');
                    foreach($devices as $deviceSerial) {
                        $data_individual['serial'] = $deviceSerial;
                        $jobID = registerJob($data_individual, $user, 'Download connected devices from ', $parentJobID);
                        $taskID = registerTask($data_individual, $user, $jobID, "DownloadConnectedDevices", "Download Connected");
                        get_Configuration($data_individual, $user, $taskID, "DownloadConnectedDevices");
                    }
                }
                else{
                    $data_individual['serial'] = $devices[0];
                    $parentJobID = registerJob($data_individual, $user, 'Download connected devices from ');
                    $taskID = registerTask($data_individual, $user, $parentJobID, "DownloadConnectedDevices", "Download Connected");
                    get_Configuration($data_individual, $user, $taskID, "DownloadConnectedDevices");
                }
                $message = array();
                $message['code'] = true;
                $message['msg'] = $parentJobID;
                break;

            case "Applications":
                if(count($devices) > 1){
                    $parentJobID = $jobID = registerParentJob($user, 'Bundle of Download Applications from Devices');
                    foreach($devices as $deviceSerial) {
                        $data_individual['serial'] = $deviceSerial;
                        $jobID = registerJob($data_individual, $user, 'Download contents from ', $parentJobID);
                        $taskID = registerTask($data_individual, $user, $jobID, "DownloadApplications", "Download Applications");
                        get_Configuration($data_individual, $user, $taskID, "DownloadApplications");
                    }
                }
                else{
                    $data_individual['serial'] = $devices[0];
                    $parentJobID = registerJob($data_individual, $user, 'Download connected devices from ');
                    $taskID = registerTask($data_individual, $user, $parentJobID, "DownloadApplications", "Download Applications");
                    get_Configuration($data_individual, $user, $taskID, "DownloadApplications");
                }
                $message = array();
                $message['code'] = true;
                $message['msg'] = $parentJobID;
                break;

            case "ApplicationContainer":
                if(count($devices) > 1){
                    $parentJobID = $jobID = registerParentJob($user, 'Bundle of Download ApplicationsContainer from Devices');
                    foreach($devices as $deviceSerial) {
                        $data_individual['serial'] = $deviceSerial;
                        $jobID = registerJob($data_individual, $user, 'Download contents from ', $parentJobID);
                        $taskID = registerTask($data_individual, $user, $jobID, "DownloadApplicationsContainer", "Download Applications Container");
                        get_Configuration($data_individual, $user, $taskID, "DownloadApplicationsContainer");
                    }
                }
                else{
                    $data_individual['serial'] = $devices[0];
                    $parentJobID = registerJob($data_individual, $user, 'Download connected devices from ');
                    $taskID = registerTask($data_individual, $user, $parentJobID, "DownloadApplicationsContainer", "Download Applications Container");
                    get_Configuration($data_individual, $user, $taskID, "DownloadApplicationsContainer");
                }
                $message = array();
                $message['code'] = true;
                $message['msg'] = $parentJobID;
                break;

            case "Regions":
                if(count($devices) > 1){
                    $parentJobID = $jobID = registerParentJob($user, 'Bundle of Download Regions from Devices');
                    foreach($devices as $deviceSerial) {
                        $data_individual['serial'] = $deviceSerial;
                        $jobID = registerJob($data_individual, $user, 'Download contents from ', $parentJobID);
                        $taskID = registerTask($data_individual, $user, $jobID, "DownloadRegions", "Download Regions");
                        get_Configuration($data_individual, $user, $taskID, "DownloadRegions");
                    }
                }
                else{
                    $data_individual['serial'] = $devices[0];
                    $parentJobID = registerJob($data_individual, $user, 'Download connected devices from ');
                    $taskID = registerTask($data_individual, $user, $parentJobID, "DownloadRegions", "Download Regions");
                    get_Configuration($data_individual, $user, $taskID, "DownloadRegions");
                }
                $message = array();
                $message['code'] = true;
                $message['msg'] = $parentJobID;
                break;

            default:
                $parentJobID = -1;
                $message = array();
                $message['code'] = true;
                $message['msg'] = $parentJobID;
                break;
        }
    }
    else {
        $parentJobID = $jobID = registerParentJob($user, 'Bundle of Download contents');
        foreach($devices as $deviceSerial) {
            $device = $app->device->where('serial',$deviceSerial)->get()->first();
            $data_individual['serial'] = $deviceSerial;
            //if ($device->ispanorama == '1') {
            //    $jobID = registerJob($data_individual, $user, 'Download connected devices from ', $parentJobID);
            //    $taskID = registerTask($data_individual, $user, $jobID, "DownloadConnectedDevices", "Download Connected");
            //    get_Configuration($data_individual, $user, $taskID, "DownloadConnectedDevices");
            //}

            $jobID = registerJob($data_individual, $user, 'Download contents from ', $parentJobID);

            $taskID = registerTask($data_individual, $user, $jobID, "DownloadConfigBackup", "Download Configuration");
            get_Configuration($data_individual, $user, $taskID, "DownloadConfigBackup");

            $taskID = registerTask($data_individual, $user, $jobID, "DownloadSystemInfo", "Download System Info");
            get_Configuration($data_individual, $user, $taskID, "DownloadSystemInfo");

            $taskID = registerTask($data_individual, $user, $jobID, "DownloadApplications", "Download Applications");
            get_Configuration($data_individual, $user, $taskID, "DownloadApplications");

            $taskID = registerTask($data_individual, $user, $jobID, "DownloadApplicationsContainer", "Download Application Container");
            get_Configuration($data_individual, $user, $taskID, "DownloadApplicationsContainer");

            $taskID = registerTask($data_individual, $user, $jobID, "DownloadRegions", "Download Regions");
            get_Configuration($data_individual, $user, $taskID, "DownloadRegions");

            $taskID = registerTask($data_individual, $user, $jobID, "DownloadLicenses", "Download Licenses");
            get_Configuration($data_individual, $user, $taskID, "DownloadLicenses");
        }
        $message = array();
        $message['code'] = true;
        $message['msg'] = $parentJobID;
    }

    return $message;
}

function deleteDownloadJob(ARRAY $data){
    if(!accessControl("any", ['device.admin', 'deviceRole'.$data['devicename'].'admin'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have job query rights';
        return $message;
    }

    $jobID = $data['job-id'];

    $job = new Job($jobID);
    return $job->delete();
}



//--------------------------------------------------------------------------------
//--------------------------------------------------------------------------------
//--------------------------------------------------------------------------------

function registerJob(ARRAY $data, $user, STRING $description, INT $parentJob=null){
    global $app;

    $device = $app->device->where('serial',$data['serial'])->first();
    $params = [
        'user_id'       => $user->id,
        'parentType'    => 'devices',
        'parentId'      => $device->id,
        'description'   => $description .' '.$data['serial'],
        'parentJob'     => $parentJob,
    ];
    if(!$job = $app->job->create($params)){
        return -1;
    }

    return $job->id;
}

function registerParentJob($user, STRING $description){
    global $app;

    $params = [
        'user_id'       => $user->id,
        'parentType'    => 'devices',
        'description'   => $description,
    ];
    if(!$job = $app->job->create($params)){
        return -1;
    }

    return $job->id;
}

function registerTask(ARRAY $data, $user, INT $jobID, STRING $processCode, STRING $processName){
    global $app;

    if(!isset($data['params'])){
        $data['params'] = '';
    }
    $data['userId'] = $user->id;

    $params = [
        'job_id'        => $jobID,
        'taskType'      => 'Configuration Download',
        'taskName'      => $processName,
        'processCode'   => $processCode,
        'statusMessage' => 'Pending...',
        'statusCode'    => '0',
        'params'        => json_encode($data),
    ];

    if(!$task = $app->task->create($params)){
        return -1;
    }

    $job = $app->job->where('id', $jobID)->first();
    $jobParams = [
        'tasks' => $job->tasks +1,
    ];
    $job->update($jobParams);

    if($job->parentJob != ''){
        $parentJob = $app->job->where('id', $job->parentJob)->first();
        $parentJobParams = [
            'tasks' => $parentJob->tasks +1,
        ];
        $parentJob->update($parentJobParams);
    }

    return $task->id;
}

function get_Configuration(ARRAY $data, $user, INT $taskID, STRING $process){
    $configtype = (isset($data['configtype'])) ? $data['configtype'] : 'running';
    $message = [
        'sender'        => $user->id,
        'proccessCode'  => $process,
        'params'        => [
            'serial'    => $data['serial'],
            'configtype'    => $configtype,
            'taskId'        => $taskID,
            'userId'        => $user->id,
            'key'           => $data['key']
        ]
    ];

    sendMessage($message);

    $message = array();
    $message['code'] = true;
    $message['msg'] = 'Done';
    return $message;
}

function sendMessage($message){
    $messageSender = new MessageSender($message);
    $messageSender->send();
}