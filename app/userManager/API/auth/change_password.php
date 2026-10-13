<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 6/5/16 - 13:37
 */

use Cartalyst\Sentinel\Native\Facades\Sentinel;

if(defined('CLI')){
    require_once INC_ROOT .'/userManager/API/accessControl_CLI.php';
}
else{
    require_once INC_ROOT .'/userManager/API/accessControl.php';
}

function change_password(ARRAY $params){
    global $app;

    if(accessControl("any", ['user.admin'])) {
        $credentials = [
            'email' => $params['email'],
        ];

        if (!($user = $app->sentinel->findByCredentials($credentials))) {
            $message['code'] = false;
            $message['msg'] = 'User not found in our registry';
            return $message;
        }

        if ($user->location_type != "local"){
            $message['code'] = false;
            $message['msg'] = "This is not a local user. Contact your server adminstrator.";
            return $message;
        }

        $v = $app->userValidation;

        $v->validate([
            'password'          => [$params['password'], 'required|min(10)'],
            'password_confirm'  => [$params['password_confirm'], 'required|matches(password)'],
        ]);

        if ($v->passes()) {
            $newCredentials = [
                'email'     => $user->email,
                'password'  => $params['password'],
            ];

            $app->container->sentinel->update($user, $newCredentials);

            $message = array();
            $message['code'] = true;
            $message['msg'] = "User information updated successfully";
            return $message;
        }
        $message['code'] = false;
        $message['msg'] = $v->errors()->all();
        return $message;

    }
    else{
        //Not admin. Can change his/her own password
        $user = $app->container->sentinel->getUser();
        if ($user) {

            if($user->location_type != "local"){
                $message = array();
                $message['code'] = false;
                $message['msg'] = "This is not a local user. Contact your server adminstrator.";
                return $message;
            }

            $credentials = [
                'email'     => $user->email,
                'password'  => $params['password_old'],
            ];

            if (! ($app->container->sentinel->authenticate($credentials)) ){
                $message = array();
                $message['code'] = false;
                $message['msg'] = "Username or password incorrect";
                return $message;
            }

            $v = $app->userValidation;

            $v->validate([
                'password'          => [$params['password'], 'required|min(10)'],
                'password_confirm'  => [$params['password_confirm'], 'required|matches(password)'],
            ]);

            if ($v->passes()) {
                $newCredentials = [
                    'email'     => $user->email,
                    'password'  => $params['password'],
                ];

                $app->container->sentinel->update($user, $newCredentials);
                $message = array();
                $message['code'] = true;
                $message['msg'] = "User information updated successfully";
                return $message;

            }

            $message['code'] = false;
            $message['msg'] = $v->errors()->all();
            return $message;

        }
        $message = array();
        $message['code'] = false;
        $message['msg'] = "Your session has expired";
        return $message;
    }

}