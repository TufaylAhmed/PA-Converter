<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 27/4/16 - 14:10
 */

use Cartalyst\Sentinel\Native\Facades\Sentinel;
if(defined('CLI')){
    require_once INC_ROOT .'/userManager/API/accessControl_CLI.php';
}
else{
    require_once INC_ROOT .'/userManager/API/accessControl.php';
}

function disable_user(ARRAY $data){
    $message = change_active($data, 0);
    if ($message['code']) {
        $message['msg'] = 'User <b>'.$data['first_name'].' '.$data['last_name'].'</b>successfully disabled';
    }
    return $message;
}

function enable_user(ARRAY $data){
    $message = change_active($data, 1);
    if ($message['code']) {
        $message['msg'] = 'User <b>'.$data['first_name'].' '.$data['last_name'].'</b>successfully enabled';
    }
    return $message;
}

function change_active(ARRAY $data, INT $status){
    global $app;

    if(!accessControl("any", ['user.admin', 'admin.*'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have activation/deactivation rights';
        return $message;
    }

    $credentials = [
        'email' => $data['email'],
    ];


    if (!( $user = $app->sentinel->findByCredentials($credentials))){
        $message = "User not found!";
        $app->flash('global', $message);
        $message['code'] = false;
        $message['msg'] = 'User not found in our registry';
        return $message;
    }

    $newCredentials = [
        'active' => $status
    ];

    Sentinel::update($user, $newCredentials);

    $message = array();
    $message['code'] = true;
    return $message;
}

