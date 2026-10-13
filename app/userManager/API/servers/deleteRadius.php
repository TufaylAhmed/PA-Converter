<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 5/5/16 - 17:13
 */
use Cartalyst\Sentinel\Native\Facades\Sentinel;

if(defined('CLI')){
    require_once INC_ROOT .'/userManager/API/accessControl_CLI.php';
}
else{
    require_once INC_ROOT .'/userManager/API/accessControl.php';
    require_once INC_ROOT.'/bin/authentication/sessionControl.php';
}

function deleteRadius(ARRAY $params){

    global $app;

    accessControl("any", ['server.admin']);

    if (!($server = $app->radiusserver->where('id', $params['id'])->get(['id'])->first())) {
        $message['code'] = false;
        $message['msg'] = 'Server not found in our registry';
        return $message;
    }

    //Disable users that authenticate to this server
    $users = $app->container->sentinel->getUserRepository()
        ->where("location_type","=","radius")
        ->where("location_id","=",$server['id'])
        ->get(['id']);

    $newCredentials['active'] = false;
    $newCredentials['location_type'] = "";
    $newCredentials['location_id'] = "";

    foreach ($users as $user){
        Sentinel::update($user, $newCredentials);
    }

    $server->delete();

    $message['code'] = true;
    $message['msg'] = "Server unregistered correctly";
    return $message;
}