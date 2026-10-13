<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 21/3/16 - 15:39
 */

namespace PaloAltoNetworks\Validation;

use PaloAltoNetworks\Sentinel\Server\LDAPServer;
use Violin\Violin;

class LDAPServerValidator extends Violin
{
    protected $server;

    public function __construct(LDAPServer $server)
    {
        $this->server = $server;

        $this->addFieldMessages([
            'name' => [
                'uniqueName' => 'This <b>Name</b> is already taken',
                'required'       => '<br>Enter the server\'s <b>Name</b>',
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
            'dn' => [
                'required'       => '<br>Enter the server\'s <b>dn</b>'
            ],
            'admin_user' => [
                'required'       => '<br>Enter the server\'s <b>admin user</b>'
            ],
            'admin_password' => [
                'required'       => '<br>Enter the server\'s <b>admin password</b>'
            ],
            'ldap_type' => [
                'required'       => '<br>Enter the server <b>type</b>'
            ],
            'uses_ssl' => [
                'isBoolean' => '<b>Uses_ssl</b> field should be a boolean',
            ],
            'uses_tsl' => [
                'isBoolean' => '<b>Uses_tsl</b> field should be a boolean'
            ],
            'active' => [
                'isBoolean' => 'The <b>Active</b> field should be a boolean'
            ],
            'account_prefix' => [
                'xssSave'        => 'This is not a valid account prefix'
            ],
            'account_suffix' => [
                'xssSave'        => 'This is not a valid account suffix'
            ],
            'dn' => [
                'xssSave'        => 'This is not a valid dn'
            ],
        ]);
    }

    public function validate_uniqueName($value, $input, $args)
    {
        $id = $args[0];
        $server = $this->server->where('name', $value)->where('id',"!=",$id);
        return ($server->count()== 0) ? true: false;
    }

    public function validate_isBoolean($value, $input, $args)
    {
        if ($value==0) return true;
        if ($value==1) return true;
        return false;
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