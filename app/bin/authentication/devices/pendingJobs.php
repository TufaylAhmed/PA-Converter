<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 22/6/16 - 14:39
 */

//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

//require_once INC_ROOT.'/bin/Authentication.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';

require_once INC_ROOT.'/libs/database.php';
require_once INC_ROOT.'/libs/shared.php';
require_once INC_ROOT.'/libs/xmlapi.php';

require_once INC_ROOT.'/bin/jobs/Job.php';

include_once INC_ROOT.'/libs/PaloAltoNetworks/Middleware/loadCSRFControl.php';

$request_body   = file_get_contents('php://input');
$data           = json_decode($request_body, true);

parse_str(file_get_contents("php://input"),$post_vars);

include INC_ROOT.'/bin/middleware_sanitizer.php';

if(isset($post_vars['type'])){
    $type = $pandb->real_escape_string($post_vars['type']);
}
else {
    $deviceName = $pandb->real_escape_string((string)(isset($_GET['devicename'])   ? $_GET['devicename'] : ''));
    $context    = $pandb->real_escape_string((string)(isset($_GET['context'])      ? $_GET['context'] : ''));
}

if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
}

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $data=[
            'devicename' => $deviceName,
            'context' => $context,
        ];
        $message = getJobs($data);
        if($message['code']) {
            echo json_encode(array('success' => true, 'msg' => $message['msg']['job-id']));
        }
        else {
            echo json_encode(array('success' => true, 'msg' => -1));
        }
        break;

    case 'POST':
        $message = getJobs($data);
        if($message['code']) {
            echo json_encode(array('success' => true, 'msg' => $message['msg']['job-id']));
        }
        else {
            echo json_encode(array('success' => true, 'msg' => -1));
        }
        break;

    case 'PUT':
        break;

    case 'DELETE':
        break;

    default:
        break;
}

function getJobs(ARRAY $data){
    global $app;

    $deviceName = $data['devicename'];
    $context = $data['context'];

    if(!accessControl("any", ['device.admin', 'device.create' ])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have job query rights';
        return $message;
    }
    if(!$device = $app->device->where('devicename',$deviceName)->get()->first()){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'The device does not exist in our database';
        return $message;
    }
    switch ($context){
        case 'content':
            if(!$job = $app->job
                ->where('parentType','devices')
                ->where('parentId',$device->id)
                ->where('description','LIKE','Download contents from %')
                ->whereColumn('completed','<','tasks')
                ->get()->last()){
                $message = array();
                $message['code'] = false;
                $message['msg'] = [
                    'job-id' => 'No job',
                ];
                return $message;
            }
            break;

        case 'devices':
            if(!$job = $app->job
                ->where('parentType','devices')
                ->where('parentId',$device->id)
                ->where('description','LIKE','Download connected devices from %')
                ->whereColumn('completed','<','tasks')
                ->get()->last()){
                $message = array();
                $message['code'] = false;
                $message['msg'] = [
                    'job-id' => 'No job',
                ];
                return $message;
            }
            break;

        case 'csvlogs':
            if(!$job = $app->job
                ->where('parentType','devices')
                ->where('parentId',$device->id)
                ->where('description','LIKE','Spark: Process CSV files to Parquet %')
                ->whereColumn('completed','<','tasks')
                ->get()->last()){
                $message = array();
                $message['code'] = false;
                $message['msg'] = [
                    'job-id' => 'No job',
                ];
                return $message;
            }
            break;

        default:
            break;
    }

    $message = array();
    $message['code'] = true;
    $message['msg'] =  [
        'job-id' => $job->id,
    ];
    return $message;

}