<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 20/5/16 - 10:01
 */

if(defined('CLI')){
    require_once INC_ROOT .'/userManager/API/accessControl_CLI.php';
}
else{
    require_once INC_ROOT .'/userManager/API/accessControl.php';
    require_once INC_ROOT.'/bin/authentication/sessionControl.php';
}

function listAttachedDevices(String $data){
    global $app;

    $projectName = $data;

    if(!accessControl("any", ['project.admin', 'projectRole.'.$projectName.'.*'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to view devices in this project';
        return $message;
    }

    if (!($project = $app->project->where('name', '=', $projectName)->get()->first() )) {
        $message['code'] = false;
        $message['msg'] = 'Project not found in our registry';
        return $message;
    }

    $devicelist = $project->getDevices();

    $message = array();
    $message['code'] = true;
    $message['msg'] = $devicelist;
    return $message;
}

function attachDeviceToProject($project, ARRAY $data){
    global $app;
    $attached_devices = array();

    $projectName = $project;
    $deviceID = $data['id'];

    if(!accessControl("any", ['project.admin', 'projectRole.'.$projectName.'.admin'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to assign a device in this project';
        return $message;
    }

    if (!($project = $app->project->where('name', '=', $projectName)->get()->first() )) {
        $message['code'] = false;
        $message['msg'] = 'Project not found in our registry';
        return $message;
    }

    if ($deviceEntity = $app->device->where('id', '=', $deviceID)->get()->first() ) {
        //Check the device is in the Project already
        if ($dev = $project->devices->where('id',$deviceID)->first()){
            $message = array();
            $message['code'] = true;
            $message['msg']['warning'] = false;
            $message['msg']['content'] = "The Device ".implode(",", $attached_devices)." was already in the project $projectName";
        }
        else {
            $project->devices()->attach($deviceEntity);
            $attached_devices[] = $deviceEntity->devicename;
            $message = array();
            $message['code'] = true;
            if ($deviceEntity->appversion > $project->appversion){
                $message['msg']['warning'] = true;
                $message['msg']['content'] = "The device ".implode(",", $attached_devices)." has a higher app-version $deviceEntity->appversion than your base-config $project->appversion. ";
            }
            else{
                $message['msg']['warning'] = false;
                $message['msg']['content'] = "The Device ".implode(",", $attached_devices)." has been attached to the project $projectName";
            }
        }
    }
    else{
        $message = array();
        $message['code'] = false;
        $message['msg'] = "We could not find the device ".$deviceID." to be attached to the project.";
        return $message;
    }

    return $message;
}

function detachAllDevicesFromProject(STRING $projectName){
    global $app;

    if(!accessControl("any", ['project.admin', 'projectRole.'.$projectName.'.admin'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to detele devices in this project';
        return $message;
    }

    if (!($project = $app->project->where('name', '=', $projectName)->get()->first() )) {
        $message['code'] = false;
        $message['msg'] = 'Project not found in our registry';
        return $message;
    }

    $project->devices()->detach();

    $message = array();
    $message['code'] = true;
    $message['msg'] = "All devices have been detached from $projectName";
    return $message;
}

function detachDeviceFromProject($project, ARRAY $data){
    global $app;

    if(!accessControl("any", ['project.admin', 'projectRole.'.$project.'.admin'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to detele devices in this project';
        return $message;
    }

    $detached_devices = array();

    $projectName = $project;
    if (!($project = $app->project->where('name', '=', $projectName)->get()->first() )) {
        $message['code'] = false;
        $message['msg'] = 'Project not found in our registry';
        return $message;
    }

    foreach($data as $value){
        $deviceID = $value['id'];
        if ($deviceEntity = $app->device->where('id', '=', $deviceID)->get()->first() ) {
            $project->devices()->detach($deviceEntity);
            $detached_devices[] = $deviceEntity->devicename;
        }
    }

    $message = array();
    $message['code'] = true;
    $message['msg'] = "The Devices ".implode(",", $detached_devices)." have been detached from the project $projectName";
    return $message;
}

function listSelectedDevices(String $data){
    global $app;

    $projectName = $data;

    if(!accessControl("any", ['project.admin', 'projectRole.'.$projectName.'.*'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to view devices in this project';
        return $message;
    }

    if (!($project = $app->project->where('name', '=', $projectName)->get()->first() )) {
        $message['code'] = false;
        $message['msg'] = 'Project not found in our registry';
        return $message;
    }

    $devicelist = $project->getDevices();
    $user = $app->container->sentinel->getUser();
    $userID = $user->id;

    if($userSettings = $app->userSettings->where('user_id','=',$userID)->where('project_id','=',$project->id)->first()){
        $selectedDevicesID = explode(',',$userSettings->selectedDevices);
    }
    else{
        $selectedDevicesID = array();
    }

    $devices = array();
    foreach ($devicelist as $device){
        if(in_array($device->id, $selectedDevicesID)){
            $device->selected = true;
            $devices[] = $device;
        }
        else{
            $device->selected = false;
            $devices[] = $device;
        }
    }

    $message = array();
    $message['code'] = true;
    $message['msg'] = $devicelist;
    return $message;
}

function selectDeviceToProject($project, ARRAY $data){
    global $app;
    $detached_devices = array();

    $projectName = $project;
    $deviceID = $data['id'];

    $user = $app->container->sentinel->getUser();
    $userID = $user->id;

    if (!($project = $app->project->where('name', '=', $projectName)->get()->first() )) {
        $message['code'] = false;
        $message['msg'] = 'Project not found in our registry';
        return $message;
    }


    if($userSettings = $app->userSettings->where('user_id','=',$userID)->where('project_id','=',$project->id)->first()){
        $selectedDevicesID = explode(',',$userSettings->selectedDevices);
        $selectedDevicesID[]= $deviceID;
        $selectedDevicesID = array_unique($selectedDevicesID);
        $selectedDevicesID = array_filter($selectedDevicesID, function($value) { return $value !== ''; });

        $newCredentials = [
            'selectedDevices'  => implode(',',$selectedDevicesID),
        ];

        $userSettings->update($newCredentials);
    }
    else{
        $selectedDevicesID = array();
        $selectedDevicesID[]= $deviceID;
        $newCredentials = [
            'user_id' =>$userID,
            'project_id' =>$project->id,
            'selectedDevices'  => implode(',',$selectedDevicesID),
        ];
        $app->container->userSettings->create($newCredentials);
    }



    $message = array();
    $message['code'] = true;
    $message['msg'] = "The Device ".implode(",", $detached_devices)." has been selected as a target from the project $projectName";
    return $message;
}

function deselectAllDevicesFromProject(STRING $projectName){
    global $app;

    if (!($project = $app->project->where('name', '=', $projectName)->get()->first() )) {
        $message['code'] = false;
        $message['msg'] = 'Project not found in our registry';
        return $message;
    }

    $project->devices()->detach();

    $message = array();
    $message['code'] = true;
    $message['msg'] = "All devices have been detached from $projectName";
    return $message;
}

function deselectDeviceFromProject($project, ARRAY $data){
    global $app;
    $detached_devices = array();

    $projectName = $project;
    $deviceID = $data['id'];

    $user = $app->container->sentinel->getUser();
    $userID = $user->id;

    if (!($project = $app->project->where('name', '=', $projectName)->get()->first() )) {
        $message['code'] = false;
        $message['msg'] = 'Project not found in our registry';
        return $message;
    }


    $userSettings = $app->userSettings->where('user_id','=',$userID)->where('project_id','=',$project->id)->first();
    $selectedDevicesID = explode(',',$userSettings->selectedDevices);
    $key = array_search($deviceID,$selectedDevicesID);
    unset($selectedDevicesID[$key]);

    $newCredentials = [
        'selectedDevices'  => implode(',',$selectedDevicesID),
    ];

    $userSettings->update($newCredentials);

    $message = array();
    $message['code'] = true;
    $message['msg'] = "The Device ".implode(",", $detached_devices)." has been deselected as a target from the project $projectName";
    return $message;
}