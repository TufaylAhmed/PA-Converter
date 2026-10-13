<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 29/4/16 - 10:50
 */
//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
require_once INC_ROOT.'/userManager/start.php';

if(defined('CLI')){
    require_once INC_ROOT .'/userManager/API/accessControl_CLI.php';
}
else{
    require_once INC_ROOT .'/userManager/API/accessControl.php';
    require_once INC_ROOT.'/bin/authentication/sessionControl.php';
}
function updateLDAP(ARRAY $params)
{
    global $app;

    if(!accessControl("any", ['server.admin'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have server-update rights';
        return $message;
    }

    unset($params['uses_ssl']);
    unset($params['uses_tsl']);
    unset($params['uses_tls']);
    $params['uses_ssl'] = $params['crypto'] == 'SSL'? 1:0;
    $params['uses_tls'] = $params['crypto'] == 'TLS'? 1:0;

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

    if ($v->passes()) {
        if (!($server = $app->ldapserver->where('id', $params['id'])->get(['id'])->first())) {
            $message['code'] = false;
            $message['msg'] = 'Server not found in our registry';
            return $message;
        }

        //print_r($params);
        $server->update($params);

        $message = array();
        $message['code'] = true;
        $message['msg'] = "Server information updated successfully";
        return $message;
    }

    $message['code'] = false;
    $message['msg'] = $v->errors()->all();
    return $message;
}