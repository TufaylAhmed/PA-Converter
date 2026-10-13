<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 6/5/16 - 10:03
 */
//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

//User management control
require_once INC_ROOT.'/userManager/start.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';

require_once INC_ROOT.'/userManager/API/auth/user_activation.php';
require_once INC_ROOT.'/userManager/API/auth/login.php';
require_once INC_ROOT.'/userManager/API/auth/logout.php';
//require_once INC_ROOT.'/userManager/API/auth/register.php';
//require_once INC_ROOT.'/userManager/API/auth/list_all_users.php';
//require_once INC_ROOT.'/userManager/API/auth/update_user.php';
//require_once INC_ROOT.'/userManager/API/roles/list_all_roles.php';
//require_once INC_ROOT.'/userManager/API/servers/list_all_servers.php';

include_once INC_ROOT.'/libs/PaloAltoNetworks/Middleware/loadCSRFControl.php';

$request_body   = file_get_contents('php://input');
$data           = json_decode($request_body, true);

parse_str(file_get_contents("php://input"),$post_vars);

include INC_ROOT.'/bin/middleware_sanitizer.php';

if(isset($post_vars['type'])){
    $type = $post_vars['type'];
}
else {
    $type = (string)(isset($_GET['type']) ? $_GET['type'] : '');
}

if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
}

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
//        $action = "get";
        if ($type == "users") {
            require_once INC_ROOT.'/userManager/API/auth/list_all_users.php';
            $users = list_all_users();
            $count = count($users);
            echo '{"total":"' . $count . '","users":' . json_encode($users) . '}';
        }
        elseif($type == "local_roles"){
            require_once INC_ROOT.'/userManager/API/roles/list_all_roles.php';
            $roles = list_local_roles();
            $count = count($roles);
            echo '{"total":"' . $count . '","roles":' . json_encode($roles) . '}';
        }
        break;

    case 'POST':
//        $action = "post";
        if ($type == "users") {
            $message = registerUser($data);
            echo json_encode(array("success" => $message['code'], "msg" => $message['msg']));
        }
        break;

    case 'PUT':
//        $action = "put";
        switch($type) {
            case "users":
                $message = updateUser($data);
                echo json_encode(array("success" => $message['code'], "msg" => $message['msg']));
                break;
            case "changePassword":
                $message = changePassword($post_vars);
                echo json_encode(array("success" => $message['code'], "msg" => $message['msg']));
                break;
            default:
                echo json_encode(array("success" => false, "msg" => "Action unknown"));
                break;
        }
        break;

    case 'DELETE':
//        $action = 'delete';
        if($type == "users"){
            $message = deleteUser($data);
            echo json_encode(array("success" => $message['code'], "msg" => $message['msg']));
        }
        break;

    default:
        break;
}


//if ($action == "get") {
////    require_once INC_ROOT . "/bin/Authentication.php"; //Validate and renew session
//    if ($type == "users") {
//        require_once INC_ROOT.'/userManager/API/auth/list_all_users.php';
////        require_once INC_ROOT.'/userManager/API/servers/list_all_servers.php';
//        $users = list_all_users();
//        $count = count($users);
//        echo '{"total":"' . $count . '","users":' . json_encode($users) . '}';
//    }
//    elseif($type == "local_roles"){
//        require_once INC_ROOT.'/userManager/API/roles/list_all_roles.php';
//        $roles = list_local_roles();
//        $count = count($roles);
//        echo '{"total":"' . $count . '","roles":' . json_encode($roles) . '}';
//    }
//}
//elseif ($action == "post") {
////    require_once INC_ROOT . "/bin/Authentication.php"; //Validate and renew session
//
//    if ($type == "users") {
//        $message = registerUser($data);
////        require_once INC_ROOT.'/userManager/API/auth/register.php';
////        $message = register($data);
//        echo json_encode(array("success" => $message['code'], "msg" => $message['msg']));
//    }
//}
//elseif ($action == "put"){
//    switch($type) {
//        case "users":
//            $message = updateUser($data);
////            require_once INC_ROOT .'/userManager/API/auth/update_user.php';
////            $message = update_user($data);
//            echo json_encode(array("success" => $message['code'], "msg" => $message['msg']));
//            break;
//        case "changePassword":
//            $message = changePassword($post_vars);
////            require_once INC_ROOT .'/userManager/API/auth/change_password.php';
////            $message = change_password($post_vars);
//            echo json_encode(array("success" => $message['code'], "msg" => $message['msg']));
//            break;
//        default:
//            echo json_encode(array("success" => false, "msg" => "Action unknown"));
//            break;
//    }
//}
//elseif ( $action == "delete"){
//    if($type == "users"){
//        $message = deleteUser($data);
//        echo json_encode(array("success" => $message['code'], "msg" => $message['msg']));
////        require_once INC_ROOT .'/userManager/API/auth/delete.php';
////        $message = delete_user($data);
////        echo json_encode(array("success" => $message['code'], "msg" => $message['msg']));
//    }
//}


function deleteUser($data){
    require_once INC_ROOT .'/userManager/API/auth/delete.php';
    $message = delete_user($data);
    return $message;
}

function updateUser($data){
    require_once INC_ROOT .'/userManager/API/auth/update_user.php';
    $message = update_user($data);
    return $message;
}

function changePassword($data){
    require_once INC_ROOT .'/userManager/API/auth/change_password.php';
    $message = change_password($data);
    return $message;
}

function registerUser($data){
    require_once INC_ROOT.'/userManager/API/auth/register.php';
    $message = register($data);
    return $message;
}