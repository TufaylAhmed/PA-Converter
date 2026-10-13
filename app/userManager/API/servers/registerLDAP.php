<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 28/4/16 - 15:05
 */

use Adldap\Adldap;
use Adldap\AdldapException;

if(defined('CLI')){
    require_once INC_ROOT .'/userManager/API/accessControl_CLI.php';
}
else{
    require_once INC_ROOT .'/userManager/API/accessControl.php';
    require_once INC_ROOT.'/bin/authentication/sessionControl.php';
}

function registerLDAP(ARRAY $params){
    global $app;

    if(!accessControl("any", ['server.admin'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have server creation rights';
        return $message;
    }

    $params['uses_ssl'] = $params['crypto'] == 'SSL'? 1: 0;
    $params['uses_tls'] = $params['crypto'] == 'TLS'? 1: 0;

    $v = $app->serverValidation;
    $v->validate([
        'name'              => [$params['name'],            'required|uniqueName('.$params['id'].')|xssSave'],
        'address'           => [$params['address'],         'required|xssSave'],
        'port'              => [$params['port'],            'required|isValidPort'],
        'dn'                => [$params['dn'],              'required|xssSave'],
        'account_prefix'    => [$params['account_prefix'],  'xssSave'],
        'account_suffix'    => [$params['account_suffix'],  'xssSave'],
//        'admin_user'    => [$params['admin_user'],      'required'],
//        'admin_password'=> [$params['admin_password'],  'required'],
//        'ldap_type'     => [$params['ldap_type'],       'required'],
        'uses_ssl'      => [$params['uses_ssl'],        'isBoolean'],
        'uses_tls'      => [$params['uses_tls'],        'isBoolean'],
        'active'        => [$params['active'],          'isBoolean'],
    ]);

    if ($v->passes()){
        $server = $app->ldapserver->create($params);

        $message['code'] = true;
        $message['msg'] = "Server registered correctly";
        return $message;
    }

    $message['code'] = false;
    $message['msg'] = array_merge(["The following errors have ocurred:"],$v->errors()->all());
    return $message;
}

function validateLDAP(ARRAY $params)
{
    global $app;


    if(!accessControl("any", ['server.admin'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have server-update rights';
        return $message;
    }


    if (!($server = $app->ldapserver->where('id', $params['id'])->get()->first())) {
        $message['code'] = false;
        $message['msg'] = 'Server not found in our registry';
        return $message;
    }

    $config = [
        'account_suffix'        =>  $server->account_suffix,
        'domain_controllers'    => [$server->address],
        'port'                  =>  $server->port,
        'base_dn'               =>  $server->dn,
        'admin_username'        =>  $params['identifier'],
        'admin_password'        =>  $params['password'],
//            'admin_username'        =>  $identifier,
//            'admin_password'        =>  $password,
        'use_ssl'               => ($server->uses_ssl == 0) ? false : true,
        'use_tls'               => ($server->uses_tsl == 0) ? false : true,
        'use_sso'               => ($server->uses_sso == 0) ? false : true,
    ];

    try {
        $adldap = new Adldap($config);
        $message = array();
        $message['code'] = true;
        $message['msg'] = "Connection tested successfully";
    }
    catch (AdldapException $e) {
        $message = array();
        $message['code'] = false;
        $message['msg'] = $e->getMessage().". <a href=\"https://live.paloaltonetworks.com/t5/Expedition-Articles/Authentication-via-LDAP-server/ta-p/219609\" target='_blank'>More info ...</a>";
    }
    catch (Exception $e){
        $error= $e;
        $message = array();
        $message['code'] = false;
        $message['msg'] = $e->getMessage(). ". <a href=\"https://live.paloaltonetworks.com/t5/Expedition-Articles/Authentication-via-LDAP-server/ta-p/219609\" target='_blank'>More info ...</a>";
    }

    return $message;
}