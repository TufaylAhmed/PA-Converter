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

function registerDevice(ARRAY $data){

    global $app;

    if(!accessControl("any", ['device.create', 'device.admin'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to create devices';
        return $message;
    }

    // is down, repeated :-/

    //Checks before Device creation
    //Check that the deviceName is not taken
    //$v = $app->deviceValidation;
    //$v->validate([
    //    'devicename'      => [$data['devicename'],      'required|uniqueSerial('.$data['id'].')'],
    //    'description'     => [$data['description'],     'xssSave']
    //]);


    //if (!$v->passes()) {
    //    $message = array();
    //    $message['code'] = false;
    //    $message['msg'] = $v->errors()->all();
    //    return $message;
    //}

    //Check that the deviceRoles are not taken
//    $devicename = $data['devicename'];
    $serial = $data['serial'];
//    $slug = "PANDevice_".$data['devicename'];
    $slug = "PANDevice_".$data['serial'];

    $v = $app->deviceValidation;
    $v->validate([
        'serial'          => [$serial,                  'required|uniqueSerial('.$serial.')'],
        'devicename'      => [$data['devicename'],      'required|uniqueSerial('.$data['id'].')'],
        'description'     => [$data['description'],     'xssSave']
    ]);
    if (!$v->passes()){
        $message = array();
        $message['code'] = false;
        $message['msg'] = $v->errors()->all();
        return $message;
    }

    $v = $app->roleValidation;
    $v->validate([
        'device'   => [$slug."_admin",     'required|alnumDash|max(240)|uniqueRoleSlug'],
    ]);
    if (!$v->passes()){
        $message = array();
        $message['code'] = false;
        $message['msg'] = $v->errors()->all();
        return $message;
    }



    if ($data['type'] == "m100") {
        $data['thumb'] = "m100.png";
        $data['ispanorama'] = 1;
    }
    elseif ($data['type'] == "m500") {
        $data['thumb'] = "m500.png";
        $data['ispanorama'] = 1;
    }
    elseif ($data['type'] == "vm-panorama") {
        $data['thumb'] = "panorama.png";
        $data['ispanorama'] = 1;
    } else {
        $data['thumb'] = $data['type'].".png";
        $data['ispanorama'] = 0;
    }

    if(!isset($data['csv_path'])){
        $data['csv_path']='';
    }
    //Initial values if not set
    if (!isset($data['appreleasedate'])){       $data['appreleasedate']     = "0000-00-00 00:00:00";}
    if (!isset($data['threatreleasedate'])){    $data['threatreleasedate']  = "0000-00-00 00:00:00";}

    //Create device and related roles
    $device = $app->device->create($data);

    //Create the admin role for the device
    $role_admin = $app->container->sentinel->getRoleRepository()->createModel()->create(array(
        'name' => "admin",
        'slug' => $slug."_admin",
        'permissions' => array(
            'deviceRole.'.$serial.'.admin'  => true,
            'deviceRole.'.$serial.'.delete' => true,
            'deviceRole.'.$serial.'.update' => true,
            'deviceRole.'.$serial.'.view'   => true,
        ),
    ));

    //Create the user role for the device
    $role_user =$app->container->sentinel->getRoleRepository()->createModel()->create(array(
        'name' => "user",
        'slug' => $slug."_user",
        'permissions' => array(
            'deviceRole.'.$serial.'.admin'  => false,
            'deviceRole.'.$serial.'.delete' => false,
            'deviceRole.'.$serial.'.update' => true,
            'deviceRole.'.$serial.'.view'   => true,
        ),
    ));

    //Create the viewer role for the device
    $role_viewer =$app->container->sentinel->getRoleRepository()->createModel()->create(array(
        'name' => "viewer",
        'slug' => $slug."_viewer",
        'permissions' => array(
            'deviceRole.'.$serial.'.admin'  => false,
            'deviceRole.'.$serial.'.delete' => false,
            'deviceRole.'.$serial.'.update' => false,
            'deviceRole.'.$serial.'.view'   => true,
        ),
    ));

    //Create the keys for this device
    $random_password = $app->randomlib->generateString(128);
    $random_iv = $app->randomlib->generateString(16);
    $keyData = [
        "type"  => "device",
        "lid"   => $device->id,
        "key"   => $random_password,
        "iv"    => $random_iv
    ];
    $keys = $app->accessKey->create($keyData);

    $user = $app->container->sentinel->getUser();
    $role_admin->users()->attach($user);

    $message = array();
    $message['code'] = true;
    $message['msg'] = 'Device created successfully';
    return $message;
}