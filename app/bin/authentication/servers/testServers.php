<?php
/*******************************************************************************
 * Copyright (c) 2018 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: 10/8/18 12:02 PM
 ******************************************************************************/

require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';

require_once INC_ROOT.'/userManager/API/auth/user_activation.php';
require_once INC_ROOT.'/userManager/API/auth/login.php';
require_once INC_ROOT.'/userManager/API/auth/logout.php';
require_once INC_ROOT.'/userManager/API/auth/register.php';
require_once INC_ROOT.'/userManager/API/auth/list_all_users.php';
require_once INC_ROOT.'/userManager/API/auth/update_user.php';
require_once INC_ROOT.'/userManager/API/roles/list_all_roles.php';
require_once INC_ROOT.'/userManager/API/servers/list_all_servers.php';

use Adldap\Adldap;
use Adldap\AdldapException;

include_once INC_ROOT.'/libs/PaloAltoNetworks/Middleware/loadCSRFControl.php';

include INC_ROOT.'/bin/middleware_sanitizer.php';

switch($_SERVER['REQUEST_METHOD'])
{
    case 'POST':
        $action = "post";
        $request_body = file_get_contents('php://input');
        $data = json_decode($request_body, true);
        $message = test($data);
        echo json_encode(["success" => $message['code'], "msg" => $message['msg']]);
        break;

    case 'GET':
    case 'PUT':
    case 'DELETE':
    default:
        echo json_encode(["success" => 'false', "msg" => 'HTTP method not supported']);
        break;
}

function test(array $params){

    $type = $params['type'];
    $id = $params['id'];
    $identifier = $params['admin_user'];
    $password = $params['admin_password'];

    require_once INC_ROOT . "/bin/Authentication.php"; //Validate and renew session
    require_once INC_ROOT . '/userManager/API/servers/registerLDAP.php';
    require_once INC_ROOT . '/userManager/API/servers/registerRadius.php';

    switch ($type) {
        case "LDAP":
            $message = testLDAP(['id' => $id, 'identifier' => $identifier, 'password' => $password]);
            break;

        case "Radius":
            $message = validateRadius(['id' => $id, 'identifier' => $identifier, 'password' => $password]);
            break;

        default:
            $message = [
                'success' => false,
                'msg'     => 'Server type not supported'
            ];
            break;
    }

    return $message;
}

function testLDAP(ARRAY $params)
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
        'account_prefix'        =>  $server->account_prefix,
        'account_suffix'        =>  $server->account_suffix,
        'hosts'                 =>  [$server->address],
        'port'                  =>  $server->port,
        'base_dn'               =>  $server->dn,
        'use_ssl'               => ($server->uses_ssl == 0) ? false : true,
        'use_tls'               => ($server->uses_tsl == 0) ? false : true,
        'follow_referrals' => false,
//        'version'          => 2,
//        'timeout'          => 5,
        'custom_options' => [
            // See: http://php.net/ldap_set_option
            //LDAP_OPT_X_TLS_REQUIRE_CERT => LDAP_OPT_X_TLS_NEVER
        ]
    ];

//    print_r($config);


    try {

        $adldap = new Adldap();
        $adldap->addProvider($config);

        $provider = $adldap->getDefaultProvider();

        try {

            // Attempt to connect and bind to the provider
            if ($provider->connect()) {

                if ($provider->auth()->attempt($params['identifier'], $params['password'])) {
                    $message = array();
                    $message['code'] = true;
                    $message['msg'] = "Connection tested successfully";
                } else {
                    $message = array();
                    $message['code'] = false;
                    $message['msg'] = "Invalid credentials";
                }
            } else {
                $message = array();
                $message['code'] = false;
                $message['msg'] = 'Unable to connect to LDAP server';
            }
        } catch (\Adldap\Auth\UsernameRequiredException $e) {
            $message = array();
            $message['code'] = false;
            $message['msg'] = "The user didn't supply a username";
        } catch (\Adldap\Auth\PasswordRequiredException $e) {
            $message = array();
            $message['code'] = false;
            $message['msg'] = "The user didn't supply a password";
        }

    }
    catch (AdldapException $e) {
        $message = array();
        $message['code'] = false;
        $message['msg'] = $e->getMessage().". <a href=\"https://live.paloaltonetworks.com/t5/Expedition-Articles/Authentication-via-LDAP-server/ta-p/219609\" target='_blank'>More info ...</a>";

    }
    catch (Exception $e){
        $message = array();
        $message['code'] = false;
        $message['msg'] = $e->getMessage().". <a href=\"https://live.paloaltonetworks.com/t5/Expedition-Articles/Authentication-via-LDAP-server/ta-p/219609\" target='_blank'>More info ...</a>";
    }

    return $message;
}
