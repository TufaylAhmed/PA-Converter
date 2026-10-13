<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 30/5/16 - 12:14
 */

//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

require_once INC_ROOT.'/userManager/start.php';
include INC_ROOT.'/bin/authentication/sessionControl.php';

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
$project    = (string)(isset($_GET['project'])      ? $_GET['project']  : '');

if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
}

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        break;

    case 'POST':
        $message = checkStatus($data);
        echo json_encode(array('percentage' => $message['code'], 'msg' => $message['msg']));
        break;

    case 'PUT':
        break;

    case 'DELETE':
        break;

    default:
        break;
}


function checkStatus(ARRAY $data){
    global $app;

    $projectName = $data['project'];

    if(!accessControl("any", ['project.admin', 'PANProject_'.$projectName.'*'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have rights to monitor this project';
        return $message;
    }

    if (!$project = $app->project->where('name','=',$projectName)->get()->first()){
        $message = array();
        $message['code'] = 0;
        $message['msg'] = 'Initializing...';
        return $message;
    }

    $message = array();
    $message['code'] = $project->percentage;
    $message['msg'] = $project->message;
    return $message;
}
?>