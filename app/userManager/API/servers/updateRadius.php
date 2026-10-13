<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 29/4/16 - 10:50
 */
//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

//function updateRadius(STRING $server_name, STRING $server_address, STRING $server_port, STRING $shared_key,
//                      STRING $active)

if(defined('CLI')){
    require_once INC_ROOT .'/userManager/API/accessControl_CLI.php';
}
else{
    require_once INC_ROOT .'/userManager/API/accessControl.php';
    require_once INC_ROOT.'/bin/authentication/sessionControl.php';
}

function updateRadius(ARRAY $params)
{
    global $app;

    if(!accessControl("any", ['server.admin'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have server-update rights';
        return $message;
    }

    $v = $app->serverRadiusValidation;
    $v->validate([
        'name'          => [$params['name'],       'required|uniqueName('.$params['id'].')|xssSave'],
        'address'       => [$params['address'],    'required|xssSave'],
        'port'          => [$params['port'],       'required|isValidPort'],
        'shared_key'    => [$params['shared_key'], 'required'],
    ]);

    if ($v->passes()) {
        if (!($server = $app->radiusserver->where('id', $params['id'])->get(['id'])->first())) {
            $message['code'] = false;
            $message['msg'] = 'Server not found in our registry';
            return $message;
        }

        $server->update($params);

        $message = array();
        $message['code'] = true;
        $message['msg'] = "Server information updated successfully";
        return $message;
    }

    $message['code'] = false;
    $message['msg'] = $v->errors()->all();
    return $message;
}