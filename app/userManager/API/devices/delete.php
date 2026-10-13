<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 12/5/16 - 16:44
 */
if(defined('CLI')){
    require_once INC_ROOT .'/userManager/API/accessControl_CLI.php';
}
else{
    require_once INC_ROOT .'/userManager/API/accessControl.php';
    require_once INC_ROOT.'/bin/authentication/sessionControl.php';
}

function deleteDevice(String $deviceSerial){
    global $app;

//    $device = $data['devicename'];
    if(!accessControl("any", ['device.admin','deviceRole.'.$deviceSerial.'.delete'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to delete the device';
        return $message;
    }

    if (!($deviceObject = $app->device->where('serial', '=', $deviceSerial)->first())) {
        $message['code'] = false;
        $message['msg'] = 'Device not found in our registry';
        return $message;
    }

//    $name = $device;
    $slug = "PANDevice_".$deviceSerial;
    $v = $app->roleValidation;
    $v->validate([
        'device'   => [$slug."_admin", 'required|alnumDash|max(240)|existsRoleSlug'],
    ]);

    if ($v->passes()){
        $roleViewer = $app->container->sentinel->findRoleBySlug($slug.'_viewer');
        $roleUser   = $app->container->sentinel->findRoleBySlug($slug.'_user');
        $roleAdmin  = $app->container->sentinel->findRoleBySlug($slug.'_admin');

        //Deattach users from these roles
        //Delete the roles for the project

        if ($roleViewer!=""){
            $roleViewer->users()->detach();
            $roleViewer->delete();
        }

        if ($roleUser!=""){
            $roleUser->users()->detach();
            $roleUser->delete();
        }

        if ($roleAdmin!=""){
            $roleAdmin->users()->detach();
            $roleAdmin->delete();
        }

        //Delete the RealTimeUpdates from this device
        deleteRealTimeUpdates($deviceSerial);

        if($accessKeyObj = $app->accessKey->where("type", "device")->where("lid", $deviceObject->id)->first()){
            $accessKeyObj->delete();
        }

        //If a panorama, delete all the attached devices
        if($deviceObject->ispanorama == 1){
            $devicesManaged = $app->device->where('management', '=', $deviceObject->serial)->get();
            foreach ($devicesManaged as $deviceManaged){
                deleteDevice($deviceManaged->serial);
            }
        }

        //Delete device itself
        $deviceObject->delete();

        //Delete Firewall folder
        #$timeNow = time();
        #exec('tar -czf '. USERSPACE_PATH.'/DeviceBackups/'.$deviceSerial.'_'.$timeNow.'.tar.gz --directory='.USERSPACE_PATH.'/devices '.$deviceSerial);

        $DevicePATHCOMPLETE = USERSPACE_PATH.'/devices/'.$deviceSerial;
        if (is_dir($DevicePATHCOMPLETE)) {
            rm_folder_recursively($DevicePATHCOMPLETE);
        }

        $message = array();
        $message['code'] = true;
        $message['msg'] = 'Device correctly deleted';
        return $message;
    }
    else{
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Device not found';
        return $message;
    }
}

function deleteRealTimeUpdates(STRING $deviceSerial){
    global $app;
    $RealTimeUpdates = selectDatabase('RealTimeUpdates');
    if(!accessControl("any", ['device.admin','deviceRole.'.$deviceSerial.'.delete'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to delete the device RealTimeUpdates information';
        return $message;
    }
    if (!($deviceObject = $app->device->where('serial', '=', $deviceSerial)->first())) {
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Device not found in our registry';
        return $message;
    }
    else {

        $query = "UPDATE firewallUpdates SET active=-5 WHERE deviceID='$deviceSerial'";
        $RealTimeUpdates->query($query);

        $message = array();
        $message['code'] = true;
        $message['msg'] = 'Device removed from the RealTimeUpdates';
    }
    return $message;
}


function deleteAllDevices(){
    global $app;

    if(!accessControl("any", ['device.admin'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to delete devices';
        return $message;
    }

    $deletedDevices = array();

    //Get all devices
    $deviceObjects = $app->device->get();

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

function rm_folder_recursively($dir) {
    foreach (scandir($dir) as $file) {
        if ('.' === $file || '..' === $file)
            continue;
        if (is_dir("$dir/$file"))
            rm_folder_recursively("$dir/$file");
        else
            unlink("$dir/$file");
    }
    rmdir($dir);
    return true;
}