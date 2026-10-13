<?php
/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: $today.year.hour.minute
 ******************************************************************************/

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
    $type = $post_vars['type'];
}
else {
    $limit      = $pandb->real_escape_string((int)(isset($_GET['limit'])           ? $_GET['limit']  : 7));
}

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $jobsController = new JobsController($limit);
        $message = $jobsController->getJobsHistogram();
        if(!$message['code']){
            echo json_encode(array('success' => false, 'msg' => $message['msg']));
            exit();
        }
        echo json_encode(array('success' => true, 'histogram' => $message['msg']));
        break;

    case 'POST':
        break;

    case 'PUT':
        break;

    case 'DELETE':
        break;

    default:
        break;
}