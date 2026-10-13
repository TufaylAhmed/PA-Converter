<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 28/4/16 - 13:54
 */

use Cartalyst\Sentinel\Native\Facades\Sentinel;
if(defined('CLI')){
    require_once INC_ROOT .'/userManager/API/accessControl_CLI.php';
}
else{
    require_once INC_ROOT .'/userManager/API/accessControl.php';
}

function update_user(ARRAY $params){
    global $app;

    /** @var $me  */
    $me = $app->container->sentinel->getUser();

    if(!accessControl("any", ['user.admin'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have activation/deactivation rights';
        return $message;
    }

    $is_external = ($params['location_type'] != "" && $params['location_type'] != "local") ? true : false;

    $v = $app->userValidation;
    if (!$is_external) {
        $v->validate([
            'email'             => [$params['email'],           'required|uniqueEmail('.$params['id'].')|xssSave'],
            'last_name'         => [$params['last_name'],       'required|xssSave'],
            'first_name'        => [$params['first_name'],      'required|xssSave'],
            'timezone'          => [$params['timezone'],        'required'],
        ]);
    } 
    else {
        $v->validate([
            'email'             => [$params['email'],           'required|uniqueEmail('.$params['id'].')|xssSave'],
            'last_name'         => [$params['last_name'],       'required|xssSave'],
            'first_name'        => [$params['first_name'],      'required|xssSave'],
            'location_type'     => [$params['location_type'],   'required'],
            'location_id'       => [$params['location_id'],     'required'],
            'timezone'          => [$params['timezone'],        'required'],
        ]);
    }

    if ($v->passes()) {
        $credentials = [
            'email' => $params['email'],
        ];

        if (!($user = $app->sentinel->findByCredentials($credentials))) {
            $message['code'] = false;
            $message['msg'] = 'User not found in our registry';
            return $message;
        }

//        $server = explode(".", $params['location_id']);
//        $params['location_id'] = $server[1];
//        $params['location_type'] = $server[0];

        if ($server = $app->ldapserver->where('name','=',$params['location_name'])->get()->first()){
            $params['location_id'] = $server->id;
            $params['location_type'] = 'ldap';
        }
        elseif($server = $app->radiusserver->where('name','=',$params['location_name'])->get()->first()){
            $params['location_id'] = $server->id;
            $params['location_type'] = 'radius';
        }
        else{
            $params['location_id'] = 0;
            $params['location_type'] = 'local';
        }

        Sentinel::update($user, $params);

        $userId = $user->id;
        //Update role

        if($me->id == $user->id && $params['roles'] != 'Super User'){
            $message['code'] = false;
            $message['msg'] = 'AutoRole change not allowed for Super Users. Request another Super User to change your role';
            return $message;
        }

        remove_AllRoles($userId);
        assign_userRole($userId, $params['roles']);

        $message = array();
        $message['code'] = true;
        $message['msg'] = "User information updated successfully";
        return $message;
    }
    $message['code'] = false;
    $message['msg'] = $v->errors()->all();
    return $message;
}

function remove_AllRoles(String $userId){
    global $app;

    if(!accessControl("any", ['user.admin'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to manage this user';
        return $message;
    }

    $slug = "admin";
    $role_user = $app->sentinel->findRoleBySlug($slug);
    $user = $app->sentinel->findById($userId);
    $role_user->users()->detach($user);

    $slug = "user";
    $role_user = $app->sentinel->findRoleBySlug($slug);
    $user = $app->sentinel->findById($userId);
    $role_user->users()->detach($user);

    $slug = "superuser";
    $role_user = $app->sentinel->findRoleBySlug($slug);
    $user = $app->sentinel->findById($userId);
    $role_user->users()->detach($user);

    $message = array();
    $message['code'] = true;
    $message['msg'] = "Done";
    return $message;
}

function assign_userRole(String $userId, $role){
    global $app;

    if(!accessControl("any", ['user.admin'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to manage this user';
        return $message;
    }

    $role_user = $app->sentinel->findRoleByName($role);
    $user = $app->sentinel->findById($userId);
    $role_user->users()->attach($user);

    $message = array();
    $message['code'] = true;
    $message['msg'] = "Done";
    return $message;
}