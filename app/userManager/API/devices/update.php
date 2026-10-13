<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 30/5/16 - 11:52
 */
if(defined('CLI')){
    require_once INC_ROOT .'/userManager/API/accessControl_CLI.php';
}
else{
    require_once INC_ROOT .'/userManager/API/accessControl.php';
    require_once INC_ROOT.'/bin/authentication/sessionControl.php';
}

function updateDevice(ARRAY $params)
{
    global $app;

    $v = $app->deviceValidation;

    $v->validate([
        'description'     => [$params['description'],     'xssSave']
//        'tag'           => [$params['tag'],             'required'],
//        'active'        => [$params['active'],          'isBoolean'],
    ]);

    $deviceName = $params['serial'];

    if (!accessControl("any", ['device.create', 'device.admin', 'deviceRole.'.$deviceName.'.admin'])) {
        $message = array();
        $message['code'] = false;
        $message['msg'] = "Your account does not have the rights to manage this device '$deviceName'";
        return $message;
    }

    //Remove blank spaces
    $params['csv_path'] = trim($params['csv_path']);
    unset($params['config']);

    if ($v->passes()) {
        if (!($device = $app->device->where('serial','=',$deviceName)->get()->first() )) {
            $message['code'] = false;
            $message['msg'] = 'Device not found in our registry';
            return $message;
        }

        $myPanoramaSerial = $device->management;
        if($myPanoramaSerial != ''){
            $myPanorama = $app->device->where("serial", $myPanoramaSerial)->get()->first();
            if($myPanorama->csv_path == $params['csv_path']){
                $params['csv_path'] = '';
            }
        }

        $device->update($params);

        if(isset($params['override']) && $params['override']==true){ //Override all managed device settings if required in this Panorama Update call
            if ($managedDevices = $app->device->where("management", $device->serial)->get()) {
                $paramChildren['csv_path'] = $params['csv_path'];
                $paramChildren['afterProcess'] = $params['afterProcess'];
                $paramChildren['avoidToday'] = $params['avoidToday'];
                $paramChildren['autoProcessCSV'] = $params['autoProcessCSV'];

                foreach ($managedDevices as $managedDevice) {
                    $managedDevice->update($paramChildren);
                }
            }
        }

        $message = array();
        $message['code'] = true;
        $message['msg'] = "Device information updated successfully";
        return $message;
    }

    $message['code'] = false;
    $message['msg'] = $v->errors()->all();
    return $message;
}