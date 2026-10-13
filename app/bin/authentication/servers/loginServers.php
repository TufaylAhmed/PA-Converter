<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 29/4/16 - 12:34
 */
//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';
require_once INC_ROOT.'/libs/database.php';

require_once INC_ROOT.'/userManager/API/auth/user_activation.php';
require_once INC_ROOT.'/userManager/API/auth/login.php';
require_once INC_ROOT.'/userManager/API/auth/logout.php';
require_once INC_ROOT.'/userManager/API/auth/register.php';
require_once INC_ROOT.'/userManager/API/auth/list_all_users.php';
require_once INC_ROOT.'/userManager/API/auth/update_user.php';
require_once INC_ROOT.'/userManager/API/roles/list_all_roles.php';
require_once INC_ROOT.'/userManager/API/servers/list_all_servers.php';

include_once INC_ROOT.'/libs/PaloAltoNetworks/Middleware/loadCSRFControl.php';

include INC_ROOT.'/bin/middleware_sanitizer.php';

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $action = $pandb->real_escape_string((string)  (isset($_GET['action'])      ? $_GET['action'] : 'get'));
//        $action     = (string)  (isset($_GET['action'])    ? $_GET['action'] : '');
        $type       = $pandb->real_escape_string((string)  (isset($_GET['type'])      ? $_GET['type'] : '')); // zip / xml / device
        $project    = $pandb->real_escape_string((string)  (isset($_GET['project'])   ? $_GET['project'] : ''));
        $start      = $pandb->real_escape_string((integer) (isset($_GET['start'])     ? $_GET['start'] : ''));
        $limit      = $pandb->real_escape_string((integer) (isset($_GET['limit'])     ? $_GET['limit'] : ''));
        $server_name    = $pandb->real_escape_string((string)  (isset($_GET['server_name'])       ? $_GET['server_name'] : ''));
        $server_address = $pandb->real_escape_string((string)  (isset($_GET['server_address'])    ? $_GET['server_address'] : ''));
        $account_suffix = $pandb->real_escape_string((string)  (isset($_GET['account_suffix'])    ? $_GET['account_suffix'] : ''));
        $server_port    = $pandb->real_escape_string((string)  (isset($_GET['server_port'])       ? $_GET['server_port'] : ''));
        $search_DN      = $pandb->real_escape_string((string)  (isset($_GET['search_DN'])         ? $_GET['search_DN'] : ''));
        $admin_user     = $pandb->real_escape_string((string)  (isset($_GET['admin_user'])        ? $_GET['admin_user'] : ''));
        $admin_password = $pandb->real_escape_string((string)  (isset($_GET['admin_password'])    ? $_GET['admin_password'] : ''));
        $server_ldap_type= $pandb->real_escape_string((string) (isset($_GET['server_ldap_type'])  ? $_GET['server_ldap_type'] : ''));
        $uses_ssl       = $pandb->real_escape_string((string)  (isset($_GET['uses_ssl'])          ? $_GET['uses_ssl'] : ''));
        $uses_tsl       = $pandb->real_escape_string((string)  (isset($_GET['uses_tsl'])          ? $_GET['uses_tsl'] : ''));
        $active         = $pandb->real_escape_string((string)  (isset($_GET['active'])            ? $_GET['active'] : ''));
        $shared_key     = $pandb->real_escape_string((string)  (isset($_GET['shared_key'])        ? $_GET['shared_key'] : ''));

        $id             = (int)     (isset($_GET['id'])                ? $_GET['id']:null);
        $identifier     = $pandb->real_escape_string((string)  (isset($_GET['admin_user'])        ? $_GET['admin_user']:''));
        $password       = $pandb->real_escape_string((string)  (isset($_GET['admin_password'])    ? $_GET['admin_password']:''));
        break;
    case 'POST':
        $action = "post";
        $request_body = file_get_contents('php://input');
        $data = json_decode($request_body, true);
        $type       = $pandb->real_escape_string((string)  (isset($_GET['type'])      ? $_GET['type'] : '')); // zip / xml / device
        break;

    case 'PUT':
        $action = "put";
        $request_body = file_get_contents('php://input');
        $data = json_decode($request_body, true);
        $type       = $pandb->real_escape_string((string)  (isset($_GET['type'])      ? $_GET['type'] : '')); // zip / xml / device
        break;
    case 'DELETE':
        $action = 'delete';
        $request_body = file_get_contents('php://input');
        $data = json_decode($request_body, true);
        $type       = $pandb->real_escape_string((string)  (isset($_GET['type'])      ? $_GET['type'] : '')); // zip / xml / device
        break;
    default:
        break;
}



if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
}

if ($action == "get") {
    require_once INC_ROOT . "/bin/Authentication.php"; //Validate and renew session
    require_once INC_ROOT . '/userManager/API/servers/list_all_servers.php';

    switch($type){
        case "serverList":
            $msg = list_all_servers();
            break;

        case "serverLDAP":
            $msg = list_servers_LDAP();
            break;

        case "serverRadius":
            $msg = list_servers_Radius();
            break;

        default:
            $msg['code'] = false;
            break;
    }
    if($msg['code']) {
        $count = count($msg['msg']);
        echo '{"total":"' . $count . '","servers":' . json_encode($msg['msg']) . '}';
    }
    else{
        echo '{"total":"0","servers":""}';
    }
}
elseif ($action == "test"){
    require_once INC_ROOT . "/bin/Authentication.php"; //Validate and renew session
    require_once INC_ROOT . '/userManager/API/servers/registerLDAP.php';
    require_once INC_ROOT . '/userManager/API/servers/registerRadius.php';

    switch($type) {
        case "LDAP":
            $message = validateLDAP(['id'=>$id, 'identifier'=>$identifier, 'password'=>$password]);
            echo json_encode(["success" => $message['code'], "msg"=> $message['msg']]);
            break;

        case "Radius":
            $message = validateRadius(['id'=>$id, 'identifier'=>$identifier, 'password'=>$password]);
            echo json_encode(["success" => $message['code'], "msg"=> $message['msg']]);
            break;

        default:
            $msg['code'] = false;
            break;
    }
}
elseif ($action == "post") {
    require_once INC_ROOT . "/bin/Authentication.php"; //Validate and renew session

    if ($type == "serverLDAP") {
        require_once INC_ROOT . '/userManager/API/servers/registerLDAP.php';
        $message = registerLDAP($data);
        echo json_encode(array("success" => $message['code'], "msg" => $message['msg']));
    }
    elseif ($type == "serverRadius") {
        require_once INC_ROOT . '/userManager/API/servers/registerRadius.php';
        $message = registerRadius($data);
        echo json_encode(array("success" => $message['code'], "msg" => $message['msg']));
    }
}
elseif ($action == "put"){
    if($type == "serverLDAP"){
        require_once INC_ROOT .'/userManager/API/servers/updateLDAP.php';
        $message = updateLDAP($data);
        echo json_encode(array("success" => $message['code'], "msg" => $message['msg']));
    }
    elseif($type == "serverRadius"){
        require_once INC_ROOT .'/userManager/API/servers/updateRadius.php';
        $message = updateRadius($data);
        echo json_encode(array("success" => $message['code'], "msg" => $message['msg']));
    }
}
elseif ( $action == "delete"){
    if($type == "serverLDAP"){
        require_once INC_ROOT .'/userManager/API/servers/deleteLDAP.php';
        $message = deleteLDAP($data);
        echo json_encode(array("success" => $message['code'], "msg" => $message['msg']));
    }
    elseif($type == "serverRadius"){
        require_once INC_ROOT .'/userManager/API/servers/deleteRadius.php';
        $message = deleteRadius($data);
        echo json_encode(array("success" => $message['code'], "msg" => $message['msg']));
    }
}
