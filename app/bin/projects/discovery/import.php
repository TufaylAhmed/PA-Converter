<?php
# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';
require_once INC_ROOT.'/libs/shared.php';
require_once INC_ROOT.'/libs/projectdb.php';
require_once INC_ROOT.'/libs/database.php';
require_once INC_ROOT.'/libs/common/discovery/import.php';
require_once INC_ROOT.'/libs/common/lib-objects.php';
require_once INC_ROOT.'/bin/messaging/MessageSender.php';

$request_body     = file_get_contents('php://input');
$params           = json_decode($request_body, true);

if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
}

include INC_ROOT.'/bin/middleware_sanitizer.php';
if (is_array($params)) {
    $params = array_map("escapeStringMiddleWareSanitizer", $params);
}else{
    $params = escapeStringMiddleWareSanitizer($params);
}

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        break;

    case 'POST':
        $params['project'] = $pandb->real_escape_string(isset($_POST['project']) ? $_POST['project']: '');
        $params['source'] = $pandb->real_escape_string(isset($_POST['project']) ? $_POST['source']: '');
        $params['vsys'] = $pandb->real_escape_string(isset($_POST['vsys']) ? $_POST['vsys']: 'all');
        $params['mode'] = $pandb->real_escape_string(isset($_POST['mode']) ? $_POST['mode']: '');
        $params['selection'] = $pandb->real_escape_string(isset($_POST['selection']) ? $_POST['selection']: '');
        $params['address'] = $pandb->real_escape_string(isset($_POST['address']) ? $_POST['address']: '');
        $params['services'] = $pandb->real_escape_string(isset($_POST['services']) ? $_POST['services']: '');
        $params['rules'] = $pandb->real_escape_string(isset($_POST['rules']) ? $_POST['rules']: '');
        $params['ids'] = $pandb->real_escape_string(isset($_POST['ids']) ? $_POST['ids']: '');
        $params['shared'] = $pandb->real_escape_string(isset($_POST['shared']) ? $_POST['shared']: '');
        $params['zones'] = $pandb->real_escape_string(isset($_POST['zones']) ? $_POST['zones']: '');
        $params['users'] = $pandb->real_escape_string(isset($_POST['users']) ? $_POST['users']: '');
        $params['apps'] = $pandb->real_escape_string(isset($_POST['apps']) ? $_POST['apps']: '');
        $params['sourceDensity'] = $pandb->real_escape_string(isset($_POST['sourceDensity']) ? $_POST['sourceDensity']: '');
        $params['destinationDensity'] = $pandb->real_escape_string(isset($_POST['destinationDensity']) ? $_POST['destinationDensity']: '');
        $message = import_discovered($params);
        echo json_encode(array('success' => $message['code'], 'jobid'=>$message['jobid']));
        break;

    case 'PUT':
        break;

    case 'DELETE':
        break;

    default:
        break;
}

function import_discovered($params){

    $project=$params['project'];

    ini_set('max_execution_time', PARSER_max_execution_time);
    ini_set("memory_limit",PARSER_max_execution_memory);

    $message=array();
    if(!accessControl("any", ['projectRole.'.$project.'.update'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to view this project contents';
        return $message;
    }

    # ----
    global $app;
    $user = $app->container->sentinel->getUser();
    $userID = $user->id;
    $api_key= getUserApiKey($user->getAttribute("api_key")??"", $user->getAttribute("valid_til")??"",$user->getAttribute("id"));
    $project = $app->project->where('name', '=', $project)->get()->first();

    $params['user_id']=$user->id;
    $params['key']=$api_key;
    $jobID = registerJob($params, $user, 'Importing Rules');
    $taskID = registerTask($params, $user, $jobID, "DiscoveryImportRules", "Import Rules");
    send_APICallMessage($params, $user, $taskID, "DiscoveryImportRules");


    $message = [
        'code'  => true,
        'jobid' => $jobID,
        'msg'   => 'Import Rules Job Registered'
    ];
    return $message;
    # ----
}

function registerTask(ARRAY $data, $user, INT $jobID, STRING $processCode, STRING $processName){
    global $app;

    if(!isset($data['params'])){
        $data['params'] = '';
    }
    $data['userId'] = $user->id;

    $params = [
        'job_id'        => $jobID,
        'taskType'      => 'Import Rules',
        'taskName'      => $processName,
        'processCode'   => $processCode,
        'statusMessage' => 'Pending...',
        'statusCode'    => '0',
        'params'        => json_encode($data),
    ];

    if(!$task = $app->task->create($params)){
        return -1;
    }

    $job = $app->job->where('id', $jobID)->first();
    $jobParams = [
        'tasks' => $job->tasks + 1,
    ];
    $job->update($jobParams);

    if($job->parentJob != ''){
        $parentJob = $app->job->where('id', $job->parentJob)->first();
        $parentJobParams = [
            'tasks' => $parentJob->tasks + 1,
        ];
        $parentJob->update($parentJobParams);
    }
    return $task->id;
}

function send_APICallMessage(ARRAY $data, $user, INT $taskID, STRING $process){
    $data['taskId']=$taskID;

    $message = [
        'sender'        => $user->id,
        'proccessCode'  => $process,
        'params'        => $data
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

function registerJob(ARRAY $data, $user, STRING $description, INT $parentJob=null){
    global $app;

    $params = [
        'user_id'       => $user->id,
        'parentType'    => 'Project',
        'parentId'      => $data['project'],
        'description'   => $description,
        'parentJob'     => $parentJob,
    ];
    if(!$job = $app->job->create($params)){
        return -1;
    }

    return $job->id;
}