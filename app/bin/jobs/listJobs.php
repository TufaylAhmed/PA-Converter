<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 6/7/16 - 10:28
 */
//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

//require_once INC_ROOT.'/bin/Authentication.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';

require_once INC_ROOT.'/bin/jobs/Job.php';
require_once INC_ROOT.'/libs/jobs/JobsController.php';
require_once INC_ROOT.'/libs/definitions/taskDefinitions.php';

use PaloAltoNetworks\Expedition\Jobs\Job;
use PaloAltoNetworks\Expedition\Jobs\JobsController;

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
    $mode       = $pandb->real_escape_string((string)(isset($_GET['mode'])         ? $_GET['mode']   : ''));
    $page       = $pandb->real_escape_string((string)(isset($_GET['page'])         ? $_GET['page']   : ''));
    $limit      = $pandb->real_escape_string((string)(isset($_GET['limit'])        ? $_GET['limit']  : ''));
}

if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
}

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $jobsController = new JobsController();
        $message = $jobsController->getJobsInfo($mode, $page, $limit);
        if(!$message['code']){
            echo json_encode(array('success' => false, 'msg' => $message['msg']));
            exit();
        }
        echo json_encode(array('total' => $message['count'], 'msg' => $message['msg']));
        break;

    case 'POST':
        break;

    case 'PUT':
        break;

    case 'DELETE':
        $job = new Job($data['job-id']);
        $message = $job->delete();
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    default:
        break;
}
