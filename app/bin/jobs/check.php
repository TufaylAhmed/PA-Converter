<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 20/9/16 - 10:23
 */

//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

//require_once INC_ROOT.'/bin/Authentication.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';

//require_once INC_ROOT.'/bin/jobs/Job.php';
require_once INC_ROOT.'/console/messaging/readOrdersCheck.php';

require_once INC_ROOT.'/libs/database.php';

/*
include_once INC_ROOT.'/libs/PaloAltoNetworks/Middleware/loadCSRFControl.php';
*/

$request_body   = file_get_contents('php://input');
$data           = json_decode($request_body, true);

parse_str(file_get_contents("php://input"),$post_vars);

include INC_ROOT.'/bin/middleware_sanitizer.php';

if(isset($post_vars['type'])){
    $type = $pandb->real_escape_string($post_vars['type']);
}
else {
//    $jobID      = (string)(isset($_GET['job-id'])       ? $_GET['job-id'] : '');
    $mode       = $pandb->real_escape_string((string)(isset($_GET['mode'])         ? $_GET['mode'] : ''));
    $process    = $pandb->real_escape_string((string)(isset($_GET['process'])      ? $_GET['process'] : ''));
}

if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
}

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $message = getProcessStatus($process, $mode);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    case 'POST':
        $message = setState($process, $data);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    case 'PUT':
        break;

    case 'DELETE':
        break;

    default:
        break;
}


function getProcessStatus(STRING $process, STRING $mode){
    global $app;

    if(!accessControl("any", ['*'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to check Job Agent status';
        return $message;
    }

//    $response = exec('/etc/init.d/pan-readOrders status | grep -v Running | wc -l');
    switch ($process) {
        case 'readOrders':
            $message = getStatus();
            break;

        default:
            $message = getStatus();
            break;
    }

    return $message;
}

function setState(STRING $process, ARRAY $data){
    $message = array();
    $message['code'] = false;

    switch($process){
        case 'readOrders':
            $message = setReadOrdersState($data);
            break;
        default:
            break;
    }
    return $message;
}

function setReadOrdersState(ARRAY $data){
    $action = $data['action'];

    $message = array();
    $message['code'] = false;

    if(!accessControl("any", ['expedition.admin'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to modify Expedition settings';
        return $message;
    }

    switch($action){
        case 'start':
            $message = start();
            break;
        case 'stop':
            $message = stop();
            break;

        case 'restart':
            $message = restart();
            break;

        case 'forceStart':
            $message = force_start();
            break;

        case 'status':
            $message = getStatus();
            break;

        case 'flush':
            $message = flush_Jobs();
            break;
        case 'remove':
            $message = remove_Jobs();
            break;

        default:
            break;
    }

    return $message;
}

