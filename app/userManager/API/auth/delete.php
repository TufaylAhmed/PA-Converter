<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 6/5/16 - 11:03
 */

use Cartalyst\Sentinel\Native\Facades\Sentinel;
if(defined('CLI')){
    require_once INC_ROOT .'/userManager/API/accessControl_CLI.php';
}
else{
    require_once INC_ROOT .'/userManager/API/accessControl.php';
}

function delete_user(ARRAY $data)
//function register(STRING $email, STRING $first_name, STRING $last_name, $password, $passwordConfirm,$location,$role ,$timezone )
{
    global $app;

    if(!accessControl("any", ['user.admin'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have user management rights';
        return $message;
    }

    $credentials = [
        'email' => $data['email'],
    ];

    if (!($user = $app->sentinel->findByCredentials($credentials))) {
        $message['code'] = false;
        $message['msg'] = 'User not found in our registry';
        return $message;
    }

    if($user->id ==1){
        $message = array();
        $message['code'] = false;
        $message['msg'] = "For security reasons, the default \"admin\" account cannot be deleted.";
        return $message;
    }

    if (!($userObj = $app->user->where('email',$data['email'])->first())) {
        $message['code'] = false;
        $message['msg'] = 'User not found in our registry';
        return $message;
    }

    $userObj->settings()->detach();

    $user->delete();

    $message = array();
    $message['code'] = true;
    $message['msg'] = "User deleted correctly.";
    return $message;

}