<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 18/10/16 - 16:36
 */
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';
require_once INC_ROOT.'/libs/database.php';
require_once INC_ROOT.'/userManager/API/projects/manageSettings.php';

include_once INC_ROOT.'/libs/PaloAltoNetworks/Middleware/loadCSRFControl.php';

$request_body   = file_get_contents('php://input');
$data           = json_decode($request_body, true);

parse_str(file_get_contents("php://input"),$post_vars);

include INC_ROOT.'/bin/middleware_sanitizer.php';

if(isset($post_vars['type'])){
    $type = $pandb->real_escape_string($post_vars['type']);
}
else {
    $type       = $pandb->real_escape_string((string)(isset($_GET['type']) ? $_GET['type'] : ''));
}
$project    = $pandb->real_escape_string((string)(isset($_GET['project'])  ? $_GET['project'] : ''));

if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
}

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $message = getUserSettings($project);
        echo json_encode(array('success' => $message['code'], 'settings' => $message['msg']));
        break;

    case 'POST':
        $message = updateUserSettings($data);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    default:
        break;
}


function getUserSettings(STRING $project){
    global $app;
    $user = $app->container->sentinel->getUser();
    $userID = $user->id;
    $message = get_UserSettings($project, $userID);
    return $message;
}


function updateUserSettings(ARRAY $data){
    global $app;
    $user = $app->container->sentinel->getUser();
    $userID = $user->id;
    $message = update_UserSettings($data, $userID);
    return $message;
}