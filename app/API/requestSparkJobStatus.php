<?php
/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: $today.year.hour.minute
 ******************************************************************************/

ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

$request_body   = file_get_contents('php://input');
$data           = json_decode($request_body, true);

parse_str(file_get_contents("php://input"),$post_vars);

include INC_ROOT.'/bin/middleware_sanitizer.php';

$master         = (string)(isset($_GET['master'])       ? $_GET['master']   : 'local[8]');
$debug          = (string)(isset($_GET['debug'])        ? $_GET['debug']: 'false');

$taskID         = (integer)(isset($_GET['task-id'])      ? $_GET['task-id']  : '1193');

$params = [
    "master"     => $master,
    "debug"      => $debug,
    "taskID"     => $taskID,
];


if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
}

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $message = requestSparkJobStatus($params);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    default:
        echo json_encode(array('success' => false, 'msg' => "Wrong HTTP Request method"));
        break;
}

function requestSparkJobStatus(ARRAY $params){

    // Check the master is a valid master
    $pattern = '/^local\[\d+\]$/';
    if (preg_match($pattern, $params['master'])) {
        $master = $params['master'];
    } else {
        $master = "local[8]";
    }

    $command ="/opt/Spark/spark/bin/spark-submit --status ".escapeshellarg($params['taskID'])." --master ".escapeshellarg($master);
//    echo "$command";
    $response = exec("$command > /tmp/error_logCoCo 2>/tmp/error_logCoCo &");

    $message = [
        'code'  => true,
        'msg'   => $response
    ];

    return $message;
}