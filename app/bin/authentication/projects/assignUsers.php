<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 26/5/16 - 15:11
 */
//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

//require_once INC_ROOT.'/bin/Authentication.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';
require_once INC_ROOT.'/libs/database.php';

require_once INC_ROOT.'/userManager/API/projects/manageUsers.php';

include_once INC_ROOT.'/libs/PaloAltoNetworks/Middleware/loadCSRFControl.php';

$request_body   = file_get_contents('php://input');
//echo var_dump($request_body);
$data           = json_decode($request_body, true);

parse_str(file_get_contents("php://input"),$post_vars);

include INC_ROOT.'/bin/middleware_sanitizer.php';

if(isset($post_vars['type'])){
    $type = $pandb->real_escape_string($post_vars['type']);
}
else {
    $type       = $pandb->real_escape_string((string)(isset($_GET['type'])         ? $_GET['type']     : ''));
}
$project    = $pandb->real_escape_string((string)(isset($_GET['project'])      ? $_GET['project']  : ''));

if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
}

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $message = list_AttachedUsers($project);
        if($message['code']) {
            $totalDevices = count($message['msg']);
            echo json_encode(array('total' => $totalDevices, 'users' => $message['msg']));
        }
        else{
            echo '{"total":"0","users":[]}';
        }
        break;

    case 'POST':
        $message = attach_User($project, $data);
        echo json_encode(array('success' => $message['code'], 'message' => $message['msg']));
        break;

    case 'PUT':
        $message = update_Attachement($project, $data);
        echo json_encode(array('success' => $message['code'], 'message' => $message['msg']));
        break;

    case 'DELETE':
        $message = detach_User($project, $data);
        echo json_encode(array('success' => $message['code'], 'message' => $message['msg']));
        break;

    default:
        break;
}

function list_AttachedUsers(String $data){
    $message = listUsersInProject($data);
    return $message;
}

function attach_User($project, ARRAY $data){
    $message = assignUsersToProject($project, $data);
    return $message;
}

function update_Attachement($project, ARRAY $data){
    $message = updateUserAttachement($project, $data);
    return $message;
}

function detach_User($project, ARRAY $data){
    $message = removeUserFromProject($project, $data);
    return $message;
}