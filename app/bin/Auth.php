<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Modified by didacgil
 * Date: 29/3/16 -11:32
 */

//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
$authenticationMethod = "userManagement";

require_once INC_ROOT.'/libs/shared.php';

require_once INC_ROOT."/libs/utils.php";
//require_once INC_ROOT."/libs/sns/sns.php";

include_once INC_ROOT."/libs/PaloAltoNetworks/Middleware/NoCSRF.php";

if($authenticationMethod == "legacy") {
    require_once INC_ROOT.'/libs/database.php';
    session_start();
}
elseif ($authenticationMethod == "userManagement") {
    require_once INC_ROOT.'/userManager/start.php';
    require_once INC_ROOT.'/userManager/API/auth/user_activation.php';
    require_once INC_ROOT.'/userManager/API/auth/login.php';
    require_once INC_ROOT.'/userManager/API/auth/logout.php';
    require_once INC_ROOT.'/userManager/API/auth/register.php';
    require_once INC_ROOT.'/userManager/API/auth/list_all_users.php';
    require_once INC_ROOT.'/userManager/API/auth/update_user.php';
    require_once INC_ROOT.'/userManager/API/roles/list_all_roles.php';
    require_once INC_ROOT.'/userManager/API/servers/list_all_servers.php';

    if(defined('CLI')){
        require_once INC_ROOT .'/userManager/API/accessControl_CLI.php';
    }
    else{
        require_once INC_ROOT .'/userManager/API/accessControl.php';
    }
}

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $action     = (string)  (isset($_GET['action'])     ? $_GET['action'] : '');
        $type       = (string)  (isset($_GET['type'])       ? $_GET['type'] : ''); // zip / xml / device
        //$project    = (string)  (isset($_GET['project'])    ? $_GET['project'] : '');
        //$start      = (integer) (isset($_GET['start'])      ? $_GET['start'] : '');
        //$limit      = (integer) (isset($_GET['limit'])      ? $_GET['limit'] : '');
        $user       = (string)  (isset($_GET['user'])       ? $_GET['user'] : '');
        $password   = (string)  (isset($_GET['password'])   ? $_GET['password'] : '');
        //$id         = (string)  (isset($_GET['id'])         ? $_GET['id'] : '');
        //$ids        =           (isset($_GET['ids'])        ? $_GET['ids'] : '');
        $disable    = (string)  (isset($_GET['disable'])    ? $_GET['disable'] : '');
        $email      = (string)  (isset($_GET['email'])      ? $_GET['email'] : '');
        $first_name = (string)  (isset($_GET['first_name']) ? $_GET['first_name'] : '');
        $last_name  = (string)  (isset($_GET['last_name'])  ? $_GET['last_name'] : '');
        $password   = (string)  (isset($_GET['password'])   ? $_GET['password'] : '');
        $passwordConfirm= (string)  (isset($_GET['password_confirm'])   ? $_GET['password_confirm'] : '');
        $location   = (string)  (isset($_GET['location'])   ? $_GET['location'] : '');
        $role       = (string)  (isset($_GET['role'])       ? $_GET['role'] : '');
        $timezone   = (string)  (isset($_GET['timezone'])   ? $_GET['timezone'] : '');
        $server_location=(string)(isset($_GET['server_location']) ? $_GET['server_location'] : '');
        break;
    case 'POST':
        $action     = (string)  (isset($_POST['action'])    ? $_POST['action'] : '');
        $type       = (string)  (isset($_POST['type'])      ? $_POST['type'] : ''); // zip / xml / device
        //$project    = (string)  (isset($_POST['project'])   ? $_POST['project'] : '');
        //$start      = (integer) (isset($_POST['start'])     ? $_POST['start'] : '');
        //$limit      = (integer) (isset($_POST['limit'])     ? $_POST['limit'] : '');
        $user       = (string)  (isset($_POST['user'])      ? $_POST['user'] : '');
        $password   = (string)  (isset($_POST['password'])  ? $_POST['password'] : '');
        //$id         = (string)  (isset($_POST['id'])        ? $_POST['id'] : '');
        //$ids        =           (isset($_POST['ids'])       ? $_POST['ids'] : '');
        $disable    = (string)  (isset($_POST['disable'])   ? $_POST['disable'] : '');
        $email      = (string)  (isset($_POST['email'])     ? $_POST['email'] : '');
        $first_name = (string)  (isset($_POST['first_name'])? $_POST['first_name'] : '');
        $last_name  = (string)  (isset($_POST['last_name']) ? $_POST['last_name'] : '');
        $password   = (string)  (isset($_POST['password'])  ? $_POST['password'] : '');
        $passwordConfirm= (string)  (isset($_POST['password_confirm'])   ? $_POST['password_confirm'] : '');
        $location   = (string)  (isset($_POST['location'])  ? $_POST['location'] : '');
        $role       = (string)  (isset($_POST['role'])      ? $_POST['role'] : '');
        $timezone   = (string)  (isset($_POST['timezone'])  ? $_POST['timezone'] : '');
        $server_location=(string)(isset($_POST['server_location'])  ? $_POST['server_location'] : '');
        break;

    default:
        $action     = (string)  (isset($_POST['action'])    ? $_POST['action'] : '');
        $type       = (string)  (isset($_POST['type'])      ? $_POST['type'] : ''); // zip / xml / device
        //$project    = (string)  (isset($_POST['project'])   ? $_POST['project'] : '');
        //$start      = (integer) (isset($_POST['start'])     ? $_POST['start'] : '');
        //$limit      = (integer) (isset($_POST['limit'])     ? $_POST['limit'] : '');
        $user       = (string)  (isset($_POST['user'])      ? $_POST['user'] : '');
        $password   = (string)  (isset($_POST['password'])  ? $_POST['password'] : '');
        //$id         = (string)  (isset($_POST['id'])        ? $_POST['id'] : '');
        //$ids        =           (isset($_POST['ids'])       ? $_POST['ids'] : '');
        $disable    = (string)  (isset($_POST['disable'])   ? $_POST['disable'] : '');
        $email      = (string)  (isset($_POST['email'])     ? $_POST['email'] : '');
        $first_name = (string)  (isset($_POST['first_name'])? $_POST['first_name'] : '');
        $last_name  = (string)  (isset($_POST['last_name']) ? $_POST['last_name'] : '');
        $passwordConfirm= (string)  (isset($_POST['password_confirm'])   ? $_POST['password_confirm'] : '');
        $location   = (string)  (isset($_POST['location'])  ? $_POST['location'] : '');
        $role       = (string)  (isset($_POST['role'])      ? $_POST['role'] : '');
        $timezone   = (string)  (isset($_POST['timezone'])  ? $_POST['timezone'] : '');
        $server_location=(string)(isset($_POST['server_location'])  ? $_POST['server_location'] : '');
        break;
}

$action = $pandb->real_escape_string($action);
$type = $pandb->real_escape_string($type);
$user = $pandb->real_escape_string($user);
$disable = $pandb->real_escape_string($disable);
$email = $pandb->real_escape_string($email);
$first_name = $pandb->real_escape_string($first_name);
$last_name = $pandb->real_escape_string($last_name);
//$passwordConfirm = $pandb->real_escape_string($passwordConfirm);
$location = $pandb->real_escape_string($location);
$role = $pandb->real_escape_string($role);
$timezone = $pandb->real_escape_string($timezone);
$server_location = $pandb->real_escape_string($server_location);


if (isset($_SESSION['timezone'])){
//    date_default_timezone_set($_SESSION[$app->config->get('auth.session_timezone')]);
    date_default_timezone_set($_SESSION['timezone']);
}

if(!($action == 'get' && $type=='login_users')){
    /* CSRF Protection for all cases besides the login itself */
    include INC_ROOT . '/libs/PaloAltoNetworks/Middleware/loadCSRFControl.php';
//    $maxCsrfTokenTime = (isset($app->config['csrf']['maxTime']))?  $app->config['csrf']['maxTime']: 60*24;
//    if(!NoCSRF::check( 'csrfToken', apache_request_headers(), true,$maxCsrfTokenTime,true)){
//        echo json_encode(['msg'=>'Not a valid token']);   return -1;
//    }
}

if ($action == "get") {
    if($type == "get_session"){
//        $my = fopen("session.txt","a"); fwrite($my,json_encode($_SESSION)."\n");fclose($my);

        if($authenticationMethod == "legacy") {

        }
        elseif ($authenticationMethod == "userManagement"){
            $accessValid = accessControl("any", ['user.*']);

            if(!$accessValid){
                unset($_SESSION['authenticated']);
                unset($_SESSION['username']);
                unset($_SESSION['timezone']);
                session_destroy();
                echo json_encode(array("success"=>false, "msg"=>"No valid session. (0)"));
                exit();
            }
            else{
                echo json_encode(array("success" => true));
                $user = $app->container->sentinel->getUser();
                add_audit_log("ok",
                    "Renew Session",
                    "User: \"".$user->email."\" renewed session at: ".date(DATE_RFC2822),
                    "",
                    "login",
                    $user->email,
                    $user->id,
                    'users');
            }
        }        
    }
    elseif ($type == "login_users") {
        // Enable sns
        $params=array();
        // MT-2460 - Disabled call to Telemetry to avoid login issues
        // sns_init($params);
        if($authenticationMethod == "legacy") {

        }
        elseif($authenticationMethod == "userManagement"){
            $accessValid = login( $user,  $password);
            $me = $app->sentinel->getUser();
            if (!$accessValid){
                unset($_SESSION['authenticated']);
                unset($_SESSION['username']);
                unset($_SESSION['timezone']);
                session_destroy();
                echo json_encode(array("success" => false, "msg" => "Incorrect user or password."));
                exit();
            }
            else{
                $csrfToken = NoCSRF::generate( 'csrfToken' );
                echo json_encode([
                    "success"   => true,
                    'csrfToken'  =>$csrfToken
                ]);
                add_audit_log("ok","Login","User: \"".$user."\" logged in at: ".date(DATE_RFC2822),"","login",$user,$me['id'],'users');
            }
        }
    }
    elseif ($type == "users") {
        require_once ("Authentication.php"); //Validate and renew session

        if($authenticationMethod == "legacy") {
//            $getExistUser = $pandb->query("SELECT id, user, password, password AS password2, created_user, modified_user, last_login, icon, disable FROM users ;");
//
//            if ($getExistUser->num_rows > 0) {
//                while ($data = $getExistUser->fetch_object()) {
//                    $myData[] = $data;
//                }
//            } else {
//                $myData = "";
//            }
//            echo '{"total":"' . $count . '","users":' . json_encode($myData) . '}';
        }
        elseif($authenticationMethod == "userManagement"){
            //Get users from userManagement
            $users = list_all_users();
            $count = count($users);
            echo '{"total":"' . $count . '","users":' . json_encode($users) . '}';
        }
    }
//    elseif ($type == "servers"){
//        require_once ("Authentication.php"); //Validate and renew session
//        if($authenticationMethod == "userManagement"){
//            //Get users from userManagement
//            $servers = list_all_servers();
//            $count = count($servers);
//            echo '{"total":"' . $count . '","servers":' . json_encode($servers['msg']) . '}';
//        }
//    }
    elseif ($type == "all_roles"){
        require_once ("Authentication.php"); //Validate and renew session
        if($authenticationMethod == "userManagement"){
            //Get users from userManagement
            $roles = list_all_roles();
            $count = count($roles);
            echo '{"total":"' . $count . '","roles":' . json_encode($roles) . '}';
        }
    }
    elseif ($type == "local_roles"){
        require_once ("Authentication.php"); //Validate and renew session
        if($authenticationMethod == "userManagement"){
            //Get users from userManagement
            $roles = list_local_roles();
            $count = count($roles);
            echo '{"total":"' . $count . '","roles":' . json_encode($roles) . '}';
        }
    }
    
}
elseif ($action == "add") {
    require_once ("Authentication.php"); //Validate and renew session

    if($type == "new_user"){

        if($authenticationMethod == "legacy") {
//            $timezone = $_SESSION['timezone'];
//
//            $pandb->query("INSERT INTO users (user, password, created_user, modified_user, last_login, last_session, icon, disable, timezone) values ('','', NOW(), NOW(), NOW(), NOW(), '', '0', '$timezone');");
//            echo json_encode(array("success" => true));
        }
        elseif($authenticationMethod == "userManagement"){
            //Make request via GUI such as:
            //https://<server>/bin/Auth.php?action=add&type=new_user&email=i@f.f&location=ldap.1&role=admin&timezone=Europe/Amsterdam&first_name=d&last_name=ff
            $message = register($email, $first_name, $last_name, $password, $passwordConfirm,$location,$role ,$timezone);
            echo json_encode(array("success" => $message['code'], "msg" => $message['msg']));
        }
    
    }
    elseif($type == "user"){
//        $user = (string) (isset($_POST['user']) ? $_POST['user'] : $_GET['user']);
//        $password = (isset($_POST['password']) ? $_POST['password'] : $_GET['password']);
//        $id = (string) (isset($_POST['id']) ? $_POST['id'] : $_GET['id']);
//        $disable = (string) (isset($_POST['disable']) ? $_POST['disable'] : $_GET['disable']);
        if($authenticationMethod == "legacy") {
//            $getExistUser = $pandb->query("SELECT id, user FROM users WHERE user = '$user' AND id != '$id';");
//            if ($getExistUser->num_rows == 1) {
//                echo json_encode(array("success" => false));
//
//            } else {
//
//                $getDataUser = $pandb->query("SELECT id, user, password FROM users WHERE id = '$id';");
//
//                $getEUData = $getDataUser->fetch_assoc();
//                $name_user = $getEUData['user'];
//                $password_ori = $getEUData['password'];
//
//                if ($name_user == "admin") {
//                    $user = "admin";
//                }
//                if ($password != $password_ori) {
//                    $password = md5($password);
//                }
//                if ($disable == "on") {
//                    $disable = 1;
//                    if ($name_user == "admin") {
//                        $disable = 0;
//                    }
//                } else {
//                    $disable = 0;
//                }
//
//                if ($_FILES['icon_file']['name'] != "") {
//
//                    $USERSPATH = "../settings/";
//                    if (is_dir($USERSPATH)) {
//                    } else {
//                        mkdir("../settings/", 0766);
//                    }
//
//                    $USERSPATH = "../settings/users/";
//                    if (is_dir($USERSPATH)) {
//                    } else {
//                        mkdir("../settings/users/", 0766);
//                    }
//
//                    $target_path = "../settings/users/" . $_FILES['icon_file']['name'];
//                    if (move_uploaded_file($_FILES['icon_file']['tmp_name'], $target_path)) {
//
//                        $icon_file = $_FILES['icon_file']['name'];
//                        $pandb->query("UPDATE users SET user = '$user', password = '$password', modified_user = NOW(), disable = '$disable', icon = '$icon_file' WHERE id = '$id';");
//                        echo json_encode(array("success" => true));
//
//                    } else {
//                        echo json_encode(array('success' => false, 'msg' => 'Error ocurred while uploading the file'));
//                    }
//
//                } else {
//                    $pandb->query("UPDATE users SET user = '$user', password = '$password', modified_user = NOW(), disable = '$disable' WHERE id = '$id';");
//                    echo json_encode(array("success" => true));
//                }
//
//            }
        }
        elseif($authenticationMethod == "userManagement"){
            $status = ($disable == 'on') ? 0 : 1;  //status is 0 for disabled, 1 for enabled in userManagement
            $message = update_user($email, $status, $password, $timezone, $server_location,  $first_name, $last_name);
            echo json_encode(array("success" => $message['code'], "msg" => $message['msg']));
        }
    }
}
elseif($action == "remove"){
    require_once ("Authentication.php"); //Validate and renew session

    if($authenticationMethod == "legacy") {
////    $ids = (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']);
//        $getExistUser = $pandb->query("SELECT id, user FROM users WHERE id IN ($ids);");
//        if ($getExistUser->num_rows >= 1) {
//            while ($getEUData = $getExistUser->fetch_assoc()) {
//                $id = $getEUData['id'];
//                $user = $getEUData['user'];
//                if ($user != "admin") {
//                    $pandb->query("DELETE FROM users WHERE id = '$id';");
//                    $now = date("F j, Y, g:i a");
//                    add_log_pandb('ok', 'Admin Users', 'User: [' . $user . '] has removed on the ' . $now . ' ', 'No Action Required', '2');
//
//                }
//            }
//            echo json_encode(array("success" => true));
//        }
    }
    elseif($authenticationMethod == "userManagement"){
        $message = disable_user($email);
        echo json_encode(array("success" => $message['code'], "msg" => $message['msg']));
    }
}
elseif($action == "logout"){
    if($authenticationMethod == "legacy") {
//        unset($_SESSION['authenticated']);
//        unset($_SESSION['username']);
//        unset($_SESSION['timezone']);
//        session_destroy();
    }
    elseif($authenticationMethod == "userManagement"){
        $me = $app->sentinel->getUser();
        logout();
        add_audit_log("ok",
            "Logout",
            "User: \"".$me['email']."\" logged out at: ".date(DATE_RFC2822),
            "",
            "login",
            $me['email'],
            $me['id'],
            'users');
    }
    echo json_encode(array("success" => true));
}       


function cleanSQL($str) {
    global $pandb;
    
    $str = trim($str);
    if (function_exists('get_magic_quotes_gpc') && get_magic_quotes_gpc()) {
        $str = stripslashes($str);
    }
    return $pandb->real_escape_string($str);
}
?>