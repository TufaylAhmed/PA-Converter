<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 22/3/16 - 16:03
 */

namespace PaloAltoNetworks\Validation;

use PaloAltoNetworks\Sentinel\Server\RadiusServer;
use Violin\Violin;

class RadiusServerValidator extends Violin
{
    protected $server;

    public function __construct(RadiusServer $server)
    {
        $this->server = $server;

        $this->addFieldMessages([
            'name' => [
                'uniqueName' => 'This <b>Name</b> is already taken',
                'required'       => '<br>Enter the server\'s <b>name</b>',
                'xssSave'        => 'This is not a valid name'
            ],
            'address' => [
                'required'       => '<br>Enter the server\'s <b>address</b>',
                'xssSave'        => 'This is not a valid address'
            ],
            'port' => [
                'required'       => '<br>Enter the server\'s <b>port</b>',
                'isValidPort'  => 'The <b>Port</b> is not valid',
                'xssSave'        => 'This is not a valid port'
            ],
            'shared_key' => [
                'required'       => '<br>Enter the server\'s <b>shared key</b>'
            ],
        ]);

//        $this->addRuleMessages([
//            'matchesCurrentPassword' => 'You have not entered the correct current password.'
//        ]);
    }

    public function validate_uniqueName($value, $input, $args)
    {
        $id = $args[0];
        $server = $this->server->where('name', $value)->where('id',"!=",$id);
        return ($server->count()== 0) ? true: false;
    }

    public function validate_isValidPort($value, $input, $args){
        if (!is_numeric($value)) return false;
        if ($value < 0) return false;
        if ($value > 65535) return false;
        return true;
    }

    public function validate_xssSave($value, $input, $args){
        if($value != htmlspecialchars($value, ENT_QUOTES, 'UTF-8')){
            return false;
        }
        return true;
    }

}