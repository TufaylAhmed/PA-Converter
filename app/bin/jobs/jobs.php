<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 14/6/16 - 10:47
 */

//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

//require_once INC_ROOT.'/bin/Authentication.php';
global $renewSession;
$renewSession=false;
require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';
require_once INC_ROOT.'/bin/jobs/Job.php';

use PaloAltoNetworks\Expedition\Jobs\Job;
$renewSession=true;


$request_body   = file_get_contents('php://input');
$data           = json_decode($request_body, true);

require_once INC_ROOT.'/libs/database.php';

parse_str(file_get_contents("php://input"),$post_vars);

include INC_ROOT.'/bin/middleware_sanitizer.php';

if(isset($post_vars['type'])){
    $type = $pandb->real_escape_string($post_vars['type']);
}
else {
    $jobID      = $pandb->real_escape_string((string)(isset($_GET['job-id'])       ? $_GET['job-id'] : ''));
    $mode       = $pandb->real_escape_string((string)(isset($_GET['mode'])         ? $_GET['mode'] : ''));
    $real       = $pandb->real_escape_string((string)(isset($_GET['real'])         ? $_GET['real'] : 'yes'));
}

if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
}

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $message = getJobInfo($jobID, $mode, $real);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    case 'POST':
        break;

    case 'PUT':
        break;

    case 'DELETE':
        if (!isset($data['job-id'])){
            $message = cancelPendingJobs();
            echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        }
        else{
            $job = new Job($data['job-id']);
            $message = $job->delete();
            echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        }
        break;

    default:
        break;
}

function getJobInfo(STRING $jobID, STRING $mode, STRING $real){
    if($real == 'no'){
        return [
            "success"=>true,
            "msg"=>[
                "job-id"=>"$jobID",
                "state"=>1,
                "JobMsg"=>[
                    "statusCode"=>0
                ]]];
    }

    $job = new Job($jobID);
    $message = $job->getJobStatus($mode);
    return $message;
}

function cancelPendingJobs(){
    global $app;

    $pendingJobs = $app->job->whereColumn('completed','<','tasks')->get();

    $cancelled = 0;
    foreach ($pendingJobs as $pendingJob){
        $job = new Job($pendingJob->id);
        $job->delete();
        $cancelled++;
    }
    $message = array();
    $message['code'] = true;
    $message['msg'] = "$cancelled cancelled Jobs";
}
