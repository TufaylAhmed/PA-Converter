<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 23/5/16 - 16:17
 */

if(defined('CLI')){
    require_once INC_ROOT .'/userManager/API/accessControl_CLI.php';
}
else{
    require_once INC_ROOT .'/userManager/API/accessControl.php';
    require_once INC_ROOT.'/bin/authentication/sessionControl.php';
}

function listAttachedKeys(String $data){
    global $app;

    $deviceSerial = $data;

    if(!accessControl("any", ['device.*', 'device.create'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to view keys in this device';
        return $message;
    }

    if (!($device = $app->device->where('serial', '=', $deviceSerial)->get()->first() )) {
        $message['code'] = false;
        $message['msg'] = 'Device not found in our registry';
        return $message;
    }

    $keylist = $device->getApiKeys();

    $message = array();
    $message['code'] = true;
    $message['msg'] = $keylist;
    return $message;
}

function getKeyFromDevice(String $deviceSerial, String $role){
    global $app;

//    if(!accessControl("any", ['device.*', 'device.create', 'deviceRole.'.$device.'.view'])){
//        $message = array();
//        $message['code'] = false;
//        $message['msg'] = 'Your account does not have the rights to view keys from '.$device;
//        return $message;
//    }

    if (!$deviceObj = $app->device->where('serial', '=', $deviceSerial)->get()->first() ){
        $message = array();
        $message['code'] = false;
        $message['msg'] = "Device not found";
        return $message;
    }
//    $deviceSerial = $deviceObj->serial;

    $key_name = $deviceSerial."_".$role;

    if (!$key = $app->apikey->where('key_name', '=', $key_name)->get()->first() ) {
        $message = array();
        $message['code'] = false;
        $message['msg'] = "Key $key_name not found for device ".$deviceObj->devicename;
        return $message;
    }

    $message = array();
    $message['code'] = true;
    $message['msg'] = $key->api_key;
    return $message;
}

function addKeyToDevice(ARRAY $data){
    global $app;

    $deviceSerial = $data['serial'];

    if(!accessControl("any", ['device.admin', 'device.create'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to manage this device';
        return $message;
    }

    if (!($device = $app->device->where('serial', '=', $deviceSerial)->get()->first() )) {
        $message['code'] = false;
        $message['msg'] = 'Device not found in our registry';
        return $message;
    }

    if ($data['api_key'] == "") {
        $hostname = $device->hostname;
        $username = $data['user_name'];
        $password = $data['user_password'];
        $port = $device->port;
        require_once INC_ROOT . '/libs/xmlapi.php';
        $api_key = generate_key($hostname, $username, $password, $port);

        $data['api_key'] = $api_key;
    }

    if($data['all_roles'] == 1){
        $data['key_name'] = $deviceSerial . "_%";
        $app->apikey->where('key_name', 'LIKE', $data['key_name'])->delete();

        $params = [
            'key_name'  => $deviceSerial . "_admin",
            'device_id' => $device->id,
            'api_key'   => $data['api_key'],
            'role'      => 'admin',
        ];
        $app->apikey->create($params);

        $params = [
            'key_name'  => $deviceSerial . "_user",
            'device_id' => $device->id,
            'api_key'   => $data['api_key'],
            'role'      => 'user',
        ];
        $app->apikey->create($params);

        $params = [
            'key_name'  => $deviceSerial . "_viewer",
            'device_id' => $device->id,
            'api_key'   => $data['api_key'],
            'role'      => 'viewer',
        ];
        $app->apikey->create($params);
    }
    else {
        $data['key_name'] = $deviceSerial . "_" . $data['role'];

//        if($apikey = $app->apikey->where('key_name', '=', $data['key_name'])->get()->first()){
//            $apikey->delete();
//        }
        $app->apikey->where('key_name', '=', $data['key_name'])->delete();

//        $v = $app->apikeyValidation;
//        $v->validate([
//            'key_name' => [$data['key_name'], 'required|uniqueKeyNameInDevice(' . $data['id'] . ')'],
//            'device_id' => [$device->id, 'required'],
//            'api_key' => [$data['api_key'], 'required'],
//            'role' => [$data['role'], 'required'],
//        ]);
//
//        if ($v->passes()) {
            $params = [
                'key_name'  => $data['key_name'],
                'device_id' => $device->id,
                'api_key'   => $data['api_key'],
//            'user_name' => $data['user_name'],
//            'user_password' => $data['user_password'],
                'role'      => $data['role'],
            ];

            $app->apikey->create($params);

            $message = array();
            $message['code'] = true;
            $message['msg'] = "The Key has been added to the device";
            return $message;
//        } else {
//            $message = array();
//            $message['code'] = false;
//            $message['msg'] = $v->errors()->all();
//            return $message;
//        }
    }
}

function removeAllKeysFromDevice(STRING $deviceSerial){
    global $app;

    if(!accessControl("any", ['device.admin', 'device.create'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to manage this device';
        return $message;
    }

    if (!($device = $app->device->where('serial', '=', $deviceSerial)->get()->first() )) {
        $message['code'] = false;
        $message['msg'] = 'Device with serial '.$deviceSerial.' not found in our registry';
        return $message;
    }

    $device->keys()->detach();

    $message = array();
    $message['code'] = true;
    $message['msg'] = "All keys have been removed from ".$device->devicename;
    return $message;
}

function removeKeyFromDevice(String $deviceSerial, ARRAY $data){
    global $app;

    if(!accessControl("any", ['device.admin', 'device.create'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to manage this device';
        return $message;
    }

    if (!($device = $app->device->where('serial', '=', $deviceSerial)->get()->first() )) {
        $message['code'] = false;
        $message['msg'] = 'Device with serial '.$deviceSerial.' not found in our registry';
        return $message;
    }

    $data['key_name'] = $deviceSerial."_".$data['role'];

    if (!$key = $app->apikey->where('key_name', '=', $data['key_name'])->get()->first() ) {
        $message = array();
        $message['code'] = false;
        $message['msg'] = "Key not found";
        return $message;
    }
    $key->delete();

    $message = array();
    $message['code'] = true;
    $message['msg'] = "The key has been detached from the device ".$device->devicename;
    return $message;
}

function updateKeyAttachement(String $deviceSerial, ARRAY $data){
    global $app;

    if(!accessControl("any", ['device.admin', 'device.create'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to manage this device';
        return $message;
    }

    if (!($device = $app->device->where('serial', '=', $deviceSerial)->get()->first() )) {
        $message['code'] = false;
        $message['msg'] = 'Device not found in our registry';
        return $message;
    }

    $data['key_name'] = $deviceSerial."_".$data['role'];

    if (!$key = $app->apikey->where('key_name', '=', $data['key_name'])->get()->first() ) {
        $message = array();
        $message['code'] = false;
        $message['msg'] = "Key not found";
        return $message;
    }

    $v = $app->apikeyValidation;

    $v->validate([
        'key_name'      => [$data['key_name'],  'required|uniqueKeyNameInDevice('.$data['id'].')'],
        'device_id'     => [$device->id,        'required'],
        'api_key'       => [$data['api_key'],   'required'],
        'role'          => [$data['role'],      'required'],
    ]);

    if($v->passes()) {
        $params = [
            'key_name' => $data['key_name'],
            'device_id' => $device->id,
            'api_key' => $data['api_key'],
            'user_name' => $data['user_name'],
            'user_password' => $data['user_password'],
            'role' => $data['role'],
        ];

        $key->update($params);

        $message = array();
        $message['code'] = true;
        $message['msg'] = "The Key has been updated";
        return $message;
    }
    else{
        $message = array();
        $message['code'] = false;
        $message['msg'] = $v->errors()->all();
        return $message;
    }
}