<?php

# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
require_once INC_ROOT.'/bin/Authentication.php';
require_once INC_ROOT.'/libs/shared.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';

require_once INC_ROOT.'/bin/messaging/MessageSender.php';

/* CSRF Protection*/
include INC_ROOT."/libs/PaloAltoNetworks/Middleware/NoCSRF.php";
$maxCsrfTokenTime = (isset($app->config['csrf']['maxTime']))?  $app->config['csrf']['maxTime']: 60*24;
if(!NoCSRF::check( 'csrfToken', apache_request_headers(), true,$maxCsrfTokenTime,true)){
    echo json_encode(['msg'=>'Not a valid token']);   return -1;
}

include INC_ROOT.'/bin/middleware_sanitizer.php';

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $action     = (string)  (isset($_GET['action'])     ? $_GET['action'] : '');
        $type       = (string)  (isset($_GET['type'])       ? $_GET['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_GET['project'])    ? $_GET['project'] : '');
        $source     = (string)  (isset($_GET['source'])     ? $_GET['source'] : '');
        $vsys       = (string)  (isset($_GET['vsys'])       ? $_GET['vsys'] : '');
        break;
    case 'POST':
        $action     = (string)  (isset($_POST['action'])    ? $_POST['action'] : '');
        $type       = (string)  (isset($_POST['type'])      ? $_POST['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_POST['project'])   ? $_POST['project'] : '');
        $source     = (string)  (isset($_POST['source'])    ? $_POST['source'] : '');
        $vsys       = (string)  (isset($_POST['vsys'])      ? $_POST['vsys'] : '');
        break;

    default:
        $action     = (string)  (isset($_POST['action'])    ? $_POST['action'] : '');
        $type       = (string)  (isset($_POST['type'])      ? $_POST['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_POST['project'])   ? $_POST['project'] : '');
        $source     = (string)  (isset($_POST['source'])    ? $_POST['source'] : '');
        $vsys       = (string)  (isset($_POST['vsys'])      ? $_POST['vsys'] : '');
        break;
}

//$project="cisco";
//$action="autozone";

require_once INC_ROOT.'/libs/projectdb.php';
$projectdb = selectDatabase($project);

$action = $projectdb->real_escape_string($action);
$type = $projectdb->real_escape_string($type);
$project = $projectdb->real_escape_string($project);
$source = $projectdb->real_escape_string($source);
$vsys = $projectdb->real_escape_string($vsys);

$user = $app->container->sentinel->getUser();
$api_key= getUserApiKey($user->getAttribute("api_key")??"", $user->getAttribute("valid_til")??"",$user->getAttribute("id"));

if ($action == "search_used") {
    if ($type == "all") {
        if(!checkProjectRights($project,'update')){
            echo json_encode([
                    "success" => true,
                    "code"  => -1,
                    "msg"   => "You do not have rights to modify this project content",
                ]
            );
            return;
        }

        //Create the Jobs and Task
        $data_individual = [
            'project'   => $project,
            'source'    => $source,
            'vsys'      => $vsys,
            'key'       => $api_key
        ];

        $jobID = registerJob($data_individual, $user, 'Calculate Unused Objects from ');
        if($jobID > 0) {
            $taskID = registerTask($data_individual, $user, $jobID, "CalculateUnusedObjects", "Calculate Unused Objects");
            sendRemoveUnusedJob($data_individual, $user, $taskID, "CalculateUnusedObjects");
        }

        $message = array();
        $message['code'] = true;
        $message['msg'] = $jobID;
        echo json_encode(array('success' => $message['code'], 'jobid' => $message['msg']));

        //check_used_objects_new();
        //echo json_encode(array("success" => true));
    }
} 
elseif ($action == "delete_unused") {

    if(!checkProjectRights($project,'update')){
        echo json_encode([
                "success" => true,
                "code"  => -1,
                "msg"   => "You do not have rights to modify this project content",
            ]
        );
        return;
    }
    //Create the Jobs and Task
    $data_individual = [
        'project'   => $project,
        'source'    => $source,
        'vsys'      => $vsys,
        'key'       => $api_key
    ];

    $jobID = registerJob($data_individual, $user, 'Remove Unused Objects from ');
    if($jobID > 0) {
        $taskID = registerTask($data_individual, $user, $jobID, "RemoveUnusedObjects", "Remove Unused Objects");
        sendRemoveUnusedJob($data_individual, $user, $taskID, "RemoveUnusedObjects");
    }

    $message = array();
    $message['code'] = true;
    $message['msg'] = $jobID;
    echo json_encode(array('success' => $message['code'], 'jobid' => $message['msg']));

//    take_snapshot_last($project);  //TODO: this should get into the background task.
//    check_used_objects_new();
//    delete_unused($source,$vsys);
//
//    echo json_encode(array("success" => true));
}

function registerJob(ARRAY $data, $user, STRING $description, INT $parentJob=null){
    global $app;

    if(!$project = $app->project->where('name',$data['project'])->first()){
        return -1;
    }

    $params = [
        'user_id'       => $user->id,
        'parentType'    => 'projects',
        'parentId'      => $project->id,
        'description'   => $description .' '.$data['project'],
        'parentJob'     => $parentJob,
    ];
    if(!$job = $app->job->create($params)){
        return -1;
    }

    return $job->id;
}

function registerTask(ARRAY $data, $user, INT $jobID, STRING $processCode, STRING $processName){
    global $app;

    if(!isset($data['params'])){
        $data['params'] = '';
    }
    $data['userId'] = $user->id;

    $params = [
        'job_id'        => $jobID,
        'taskType'      => 'Tools Massive Change',
        'taskName'      => $processName,
        'processCode'   => $processCode,
        'statusMessage' => 'Pending...',
        'statusCode'    => '0',
        'params'        => json_encode($data),
    ];

    if(!$task = $app->task->create($params)){
        return -1;
    }

    /* @var $job */
    $job = $app->job->where('id', $jobID)->first();
    $tasks = ($processCode == "RemoveUnusedObjects")?9:8;//the 8 parts from the use calculation + one delete part
    $jobParams = [
        'tasks' => $job->tasks +$tasks,
    ];

    $job->update($jobParams);

    if($job->parentJob != ''){
        $parentJob = $app->job->where('id', $job->parentJob)->first();
        $parentJobParams = [
            'tasks' => $parentJob->tasks +$tasks,
        ];
        $parentJob->update($parentJobParams);
    }

    return $task->id;
}

function sendRemoveUnusedJob(ARRAY $data, $user, INT $taskID, STRING $process){
    $message = [
        'sender'        => $user->id,
        'proccessCode'  => $process,
        'params'        => [
            'project'       => $data['project'],
            'source'        => $data['source'],
            'vsys'          => $data['vsys'],
            'taskId'        => $taskID,
            'key'           => $data['key'],
            'userId'        => $user->id
        ]
    ];

    sendMessage($message);

    $message = array();
    $message['code'] = true;
    $message['msg'] = 'Done';
    return $message;
}

function sendMessage($message){
    $messageSender = new MessageSender($message);
    $messageSender->send();
}
