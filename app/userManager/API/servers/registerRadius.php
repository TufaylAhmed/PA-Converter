<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 28/4/16 - 15:05
 */

if(defined('CLI')){
    require_once INC_ROOT .'/userManager/API/accessControl_CLI.php';
}
else{
    require_once INC_ROOT .'/userManager/API/accessControl.php';
    require_once INC_ROOT.'/bin/authentication/sessionControl.php';
}

function registerRadius(ARRAY $params){

    global $app;

    if(!accessControl("any", ['server.admin'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have server creation rights';
        return $message;
    }

    $v = $app->serverRadiusValidation;
    $v->validate([
        'name'          => [$params['name'],       'required|uniqueName('.$params['id'].')|xssSave'],
        'address'       => [$params['address'],    'required|xssSave'],
        'port'          => [$params['port'],       'required|isValidPort'],
        'shared_key'    => [$params['shared_key'], 'required'],
    ]);

    if ($v->passes()){
        $server = $app->radiusserver->create($params);

        $message['code'] = true;
        $message['msg'] = "Server registered correctly";
        return $message;
    }

    $message['code'] = false;
    $message['msg'] = array_merge(["The following errors have ocurred:"],$v->errors()->all());
    return $message;
}

function validateRadius(ARRAY $params)
{
    global $app;


    if(!accessControl("any", ['server.admin'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have server-update rights';
        return $message;
    }

    if (!$server = $app->container->radiusserver->where('id', '=', $params['id'])->first()){
        $message['code'] = false;
        $message['msg'] = 'Server not found in our registry';
        return $message;
    }

    $ip_address     = $server->address;
    $port           = $server->port;
    $shared_secret  = $server->shared_key;;

    $radius = radius_auth_open();
    define("PALO_ALTO_RADIUS_ID", 25461);
    define('RADIUS_PROXY_STATE', 33);
    define('RADIUS_USER_NAME', 1);
    radius_put_vendor_string($radius, PALO_ALTO_RADIUS_ID, RADIUS_USER_NAME, "expedition-vm");
    radius_add_server($radius, $ip_address, $port, $shared_secret, 5, 3);

    radius_create_request($radius, RADIUS_ACCESS_REQUEST);
    radius_put_attr($radius, RADIUS_USER_NAME, $params['identifier']);
    radius_put_attr($radius, RADIUS_USER_PASSWORD, $params['password']);

    $result = radius_send_request($radius);

    switch ($result) {
        case RADIUS_ACCESS_ACCEPT:
            // An Access-Accept response to an Access-Request indicating that the RADIUS server authenticated the user successfully.
            $message = array();
            $message['code'] = true;
            $message['msg'] = "Connection tested successfully";
            break;

        case RADIUS_ACCESS_REJECT:
            $message = array();
            $message['code'] = false;
            $message['msg'] = "Error: Access Reject. <a href=\"https://live.paloaltonetworks.com/t5/Expedition-Articles/Authentication-via-LDAP-server/ta-p/219609\" target='_blank'>More info ...</a>";
            break;

        case RADIUS_ACCESS_CHALLENGE:
            $message = array();
            $message['code'] = false;
            $message['msg'] = "Error: Access Challenge. <a href=\"https://live.paloaltonetworks.com/t5/Expedition-Articles/Authentication-via-LDAP-server/ta-p/219609\" target='_blank'>More info ...</a>";
            break;

        case false:
            $message = array();
            $message['code'] = false;
            $message['msg'] = "Error: No reply received from the server $ip_address:$port";
            break;


        default:
            $message = array();
            $message['code'] = false;
            $message['msg'] = "Error: $result";
            break;
    }

    return $message;

}