<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 18/5/16 - 16:09
 */


namespace PaloAltoNetworks\Validation;

use PaloAltoNetworks\Sentinel\Devices\Device;
use Violin\Violin;

class DeviceValidator extends Violin
{
    protected $device;

    public function __construct(Device $device)
    {
        $this->device = $device;

        $this->addFieldMessages([
            'devicename' => [
                'uniqueName' => '<br>This <b>Device Name</b> is already taken'
            ],
            'active' => [
                'isBoolean' => '<br><b>The Active</b> field should be a boolean'
            ],
            'serial' => [
                'uniqueSerial'  => '<br>This <b>Device Serial</b> is already taken',
                'required'      => '<br>Enter a <b>Device Serial</b>'
            ],
            'description' => [
                'xssSave' => 'This is not a valid description'
            ]
        ]);
    }

    public function validate_uniqueSerial($value, $input, $args)
    {
        $id = $args[0];
        $server = $this->device->where('serial', $value)->where('id',"!=",$id);
        return ($server->count()== 0) ? true: false;
    }

    public function validate_isBoolean($value, $input, $args)
    {
        if ($value==0) return true;
        if ($value==1) return true;
        return false;
    }

    public function validate_xssSave($value, $input, $args){
        if($value != htmlspecialchars($value, ENT_QUOTES, 'UTF-8')){
            return false;
        }
        return true;
    }


}