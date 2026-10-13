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
    $project = $pandb->real_escape_string((string)(isset($_GET['project'])   ? $_GET['project'] : ''));
    $context    = $pandb->real_escape_string((string)(isset($_GET['context'])      ? $_GET['context'] : ''));
}

if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
}

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $data = [
            'project'   => $project,
            'context'   => $context,
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

    $projectName = $data['project'];
    $context = $data['context'];


    if(!accessControl("any", ['project.admin', 'project.create', 'projectRole.'.$projectName.'.*'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have job query rights for this project';
        return $message;
    }
    if(!$projectObject = $app->project->where('name',$projectName)->first()){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'The project "'.$projectName.'" does not exist in our database';
        return $message;
    }

    switch ($context){
        case 'backup':
            if(!$job = $app->job
                ->where('parentType','devices')
                ->where('parentId',$projectObject->id)
                ->where('description','LIKE','Backup %')
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
                ->where('parentType','project')
                ->where('parentId',$projectObject->id)
                ->where('description','LIKE','Send API calls to %')
                ->whereColumn('completed','<','tasks')
                ->get()) {
                $message = array();
                $message['code'] = false;
                $message['msg'] = [
                    'job-id' => 'No job',
                ];
                return $message;
            }
            break;

        case 'autozone':
            if(!$job = $app->job
                ->where('parentType','projects')
                ->where('parentId',$projectObject->id)
                ->where('description','LIKE','Autozone on %')
//                ->whereColumn('completed','<','tasks')
                ->get()->last()) {
                $message = array();
                $message['code'] = false;
                $message['msg'] = [
                    'job-id' => 'No job',
                ];
                return $message;
            }
            break;

        case 'all':
        default:
            if(!$job = $app->job
                ->where('parentType','project')
                ->where('parentId',$projectObject->id)
                ->where('description','LIKE','Bundle %')
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
    }

    $message = array();
    $message['code'] = true;
    $message['msg'] =  [
        'job-id' => $job->id,
    ];
    return $message;

}