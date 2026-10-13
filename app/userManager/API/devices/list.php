<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 12/5/16 - 16:43
 */

require_once INC_ROOT.'/libs/common/device/CsvFilesLister.php';

use \PaloAltoNetworks\Sentinel\Devices\CsvFilesLister;

if(defined('CLI')){
    require_once INC_ROOT .'/userManager/API/accessControl_CLI.php';
}
else{
    require_once INC_ROOT .'/userManager/API/accessControl.php';
    require_once INC_ROOT.'/bin/authentication/sessionControl.php';
}

function listDevices(STRING $scope, STRING $projectName, bool $skip_FileScan=true){
//    if($skip_FileScan)
//        echo "I skip";
//    else
//        echo "I dont skip";
    require_once INC_ROOT .'/libs/database.php';
    global $app;
    global $pandbRBAC;

    if(!accessControl("any", ['device.create','role.admin', 'device.user', 'device.view'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have device listing rights';
        return $message;
    }

    $devicesReturn = array();

    switch($scope) {
        case "direct":
            if($projectName == '') {
                $devices = $app->container->device
                    ->where('active', '=', '1')
                    ->where('management', '')
                    ->orWhereNull('management')
                    ->orderBy('devicename')
                    ->get();
            }
            else{
                if (!($project = $app->project->where('name', '=', $projectName)->get()->first() )) {
                    $message['code'] = false;
                    $message['msg'] = [];
                    return $message;
                }
                $devices = $project->getDevices();
            }
            break;
        case "none":
            $devices = array();
            break;
        default:
            if($projectName == '') {
                $devices = $app->container->device->where('active', '=', '1')->orderBy('devicename')->get();
            }
            else{
                if (!($project = $app->project->where('name', '=', $projectName)->get()->first() )) {
                    $message['code'] = false;
                    $message['msg'] = [];
                    return $message;
                }
                $devices = $project->getDevices();
            }
            break;
    }

    if (!$skip_FileScan) {
        if (!defined('MAX_DEVICES_TO_SCAN')) {
            define("MAX_DEVICES_TO_SCAN", 20);
        }
        if (count($devices) > MAX_DEVICES_TO_SCAN) { //Even if we were told not to skip the file listing, prevent the listing if there are more than 20 devices to process
            $skip_FileScan = true;
        }
    }

    $mlSettings = new \ML_Settings($pandbRBAC);
    $message = $mlSettings->get();
    $mlParams_arr = $message['msg'];
    if(count($mlParams_arr)>0)          $ExpeditionML = $mlParams_arr[0]['server'];
    else                                $ExpeditionML = $_SERVER['SERVER_ADDR'];
    //Before making the listing request. Check that ML is alive
    $connectionStatus = $mlSettings->checkAlive();
    if(!isset($connectionStatus->alive) || $connectionStatus->alive!=true){
        $skip_FileScan = true;
    }

    foreach ($devices as $device){
        $device = json_decode(json_encode($device));

        if($device->panos == ''){
            $device->panos = 'undefined';
        }

        if($device->type == ''){
            $device->type = 'undefined';
        }

        if(!$skip_FileScan) {
            $filesLister = new CsvFilesLister($device->serial);
            $files = $filesLister->list_LogFiles();
            $device->numberofnewlogs = isset($files['news']) ? count($files['news']) : 0;
            $device->newlogs = isset($files['news']) ? $files['news'] : array();
        }
        else{
            $device->numberofnewlogs = 0;
            $device->newlogs = array();
        }

        $myPanoramaSerial = $device->management;
        if($myPanoramaSerial != '') {
            $myPanorama = $app->device->where("serial", $myPanoramaSerial)->get()->first();
            $device->panorama_csv_path = $myPanorama->csv_path;

            # Check if this is a valid csv_path or we should use it's Panorama path
            if(!isset($device->csv_path) || $device->csv_path=='') {
                $device->csv_path = $myPanorama->csv_path;
            }
        }
        else{
            $device->panorama_csv_path = '';
        }

        $warnings = array();

        # Check Databases age
        $today =  time();
        $appDate = strtotime($device->appreleasedate);
        $threatsDate = strtotime($device->threatreleasedate);
        if($device->appreleasedate != '0000-00-00 00:00:00') {
            $appsDays = round((($today - $appDate) / (60 * 60 * 24)));
            if ($appsDays > 30) {
                $warnings[] = 'Application Database is more than 30 days old.';
            }
        }
        if($device->threatreleasedate != '0000-00-00 00:00:00') {
            $threatsDays = round((($today - $threatsDate) / (60 * 60 * 24)));
            if ($threatsDays > 30) {
                $warnings[] = 'Threats Database is more than 30 days old.';
            }
        }

        if(strtolower($device->urldb) == 'brightcloud'){
            $warnings[] = 'Url-Categories is not defined as brightcloud. PaloAltoNetworks is a more complete database of Url-Categories';
        }

        # Add licenses
        $getLicense=$pandbRBAC->query("SELECT * FROM licenses WHERE serial='$device->serial'");
        if ($getLicense->num_rows>0){
            $licenses=array();
            while($getLicenseData=$getLicense->fetch_object()){
                $licenses[]=$getLicenseData;
            }
            $device->licenses = $licenses;
        }
        else{
            $device->licenses=null;
        }

        $device->warning = json_encode($warnings);
        $devicesReturn[] = $device;
    }

    $message = array();
    $message['code'] = true;
    $message['msg'] = $devicesReturn;

//    var_dump($message['msg']);

    return $message;
}

function listAdminDevice(STRING $device){
    if(!accessControl("any", ['device.admin',                'deviceRole.'.$device.'.admin'])){
        return false;
    }
    return true;
}

function listUserDevice(STRING $device){
    if(!accessControl("any", ['device.admin','device.create','deviceRole.'.$device.'.admin','deviceRole.'.$device.'.user'])){
        return false;
    }
    return true;
}

function listViewDevice(STRING $device){
    if(!accessControl("any", ['device.admin','device.create','deviceRole.'.$device.'.*'])){
        return false;
    }
    return true;
}