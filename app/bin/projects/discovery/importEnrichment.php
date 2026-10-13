<?php
# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

require_once INC_ROOT.'/userManager/start.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';

require_once INC_ROOT.'/libs/shared.php';
require_once INC_ROOT.'/libs/projectdb.php';
require_once INC_ROOT.'/libs/common/discovery/import.php';
require_once INC_ROOT.'/libs/common/lib-objects.php';
require_once INC_ROOT.'/bin/messaging/MessageSender.php';

$request_body     = file_get_contents('php://input');
$params           = json_decode($request_body, true);

include INC_ROOT.'/bin/middleware_sanitizer.php';

if (is_array($params)) {
    $params = array_map("escapeStringMiddleWareSanitizer", $params);
}else{
    $params = escapeStringMiddleWareSanitizer($params);
}

if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
}

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        break;

    case 'POST':
        $params['project'] = isset($_POST['project']) ? $_POST['project']: '';
        $params['source'] = isset($_POST['project']) ? $_POST['source']: '';
        $params['vsys'] = isset($_POST['vsys']) ? $_POST['vsys']: 'all';
        $params['template'] = isset($_POST['template']) ? $_POST['template']: 'all';
        $params['from'] = isset($_POST['from']) ? $_POST['from']: '';
        $params['to'] = isset($_POST['to']) ? $_POST['to']: '';
        $params['selection'] = isset($_POST['selection']) ? $_POST['selection']: '';
        $params['src'] = isset($_POST['src']) ? $_POST['src']: '';
        $params['dst'] = isset($_POST['dst']) ? $_POST['dst']: '';
        $params['ids'] = isset($_POST['ids']) ? $_POST['ids']: '';
        $params['src_region'] = isset($_POST['src_region']) ? $_POST['src_region']: '';
        $params['dst_region'] = isset($_POST['dst_region']) ? $_POST['dst_region']: '';
        $params['users'] = isset($_POST['users']) ? $_POST['users']: '';
        $params['apps'] = isset($_POST['apps']) ? $_POST['apps']: '';
        $params['services'] = isset($_POST['services']) ? $_POST['services']: '';
        $params['combo_src'] = isset($_POST['combo_src']) ? $_POST['combo_src']: '';
        $params['combo_dst'] = isset($_POST['combo_dst']) ? $_POST['combo_dst']: '';
        $params['combo_srv'] = isset($_POST['combo_srv']) ? $_POST['combo_srv']: '';
        $params['update_to'] = isset($_POST['update_to']) ? $_POST['update_to']: '';
        $params['created_objects'] = isset($_POST['created_objects']) ? $_POST['created_objects']: '';

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

    $project = $params['project'];

    ini_set('max_execution_time', PARSER_max_execution_time);
    ini_set("memory_limit",PARSER_max_execution_memory);

    $message = array();
    if(!accessControl("any", ['projectRole.'.$project.'.update'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to view this project contents';
        return $message;
    }

    global $app;

    //echo "En import_discovered de importEnrichment: \n";
    //print_r($app);

    $user = $app->container->sentinel->getUser();
    $userID = $user->id;
    $api_key= getUserApiKey($user->getAttribute("api_key")??"", $user->getAttribute("valid_til")??"",$user->getAttribute("id"));
    $project = $app->project->where('name', '=', $project)->get()->first();

    $params['user_id'] = $user->id;
    $params['key'] = $api_key;
    //echo "-----> USER: " .$user->id. "\n";
    $jobID = registerJob($params, $user, 'Importing Rules');
    $taskID = registerTask($params, $user, $jobID, "RuleEnrichment", "Enrich Rules");
    send_APICallMessage($params, $user, $taskID, "RuleEnrichment");

    $message = [
        'code'  => true,
        'jobid' => $jobID,
        'msg'   => 'Import Rules Job Registered'
    ];
    return $message;

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

    $data['taskId'] = $taskID;

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