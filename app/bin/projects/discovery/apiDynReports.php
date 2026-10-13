<?php
# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
//Loads all global PHP definitions
#DEBUG
//$_SERVER['DOCUMENT_ROOT']="/var/www/html";
//$_SERVER['REQUEST_METHOD']="POST";
#DEBUG

require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

//User management control
require_once INC_ROOT.'/userManager/start.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';

require_once INC_ROOT.'/libs/xmlapi.php';
require_once INC_ROOT.'/libs/backups.php';
require_once INC_ROOT.'/libs/projectdb.php';
require_once INC_ROOT.'/libs/common/device/device.php';
require_once INC_ROOT.'/bin/messaging/MessageSender.php';
require_once INC_ROOT.'/libs/database.php';

$request_body   = file_get_contents('php://input');
$data           = json_decode($request_body, true);

parse_str(file_get_contents("php://input"),$post_vars);

include INC_ROOT.'/bin/middleware_sanitizer.php';

if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
}

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $objfilter      = $pandb->real_escape_string((string) (isset($_GET['objfilter']) ? $_GET['objfilter'] : ''));
        $objsearch      = $pandb->real_escape_string((string) (isset($_GET['objsearch']) ? $_GET['objsearch'] : ''));
        $project        = $pandb->real_escape_string((string) (isset($_GET['project'])   ? $_GET['project'] : ''));
        $start       = $pandb->real_escape_string((string) (isset($_GET['start'])    ? $_GET['start'] : ''));
        $limit       = $pandb->real_escape_string((string) (isset($_GET['limit'])    ? $_GET['limit'] : ''));

        $message = get_api_calls($project, $objfilter, $objsearch, '','',$start, $limit);
        if($message['code']){
            echo json_encode(["total" => $message['total'], "rows"  => $message['msg'], ]);
        }
        else{
            echo json_encode([ "total" => 0, "rows"  => '',]);
        }
        break;

    case 'POST':
        break;

    case 'PUT':
        $project = $pandb->real_escape_string((string) (isset($_GET['project'])   ? $_GET['project'] : ''));
        $message = send_api_dynreports_calls($project, $data);
        echo json_encode(array('success' => $message['code'], 'jobid' => $message['jobid'], 'msg' => $message['msg']));
        break;

    case 'DELETE':
        $project = $pandb->real_escape_string((string) (isset($_GET['project'])   ? $_GET['project'] : ''));
        $message = remove_appid_fromlog($project, $data);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    default:
        break;
}


function remove_appid_fromlog(STRING $projectName,ARRAY $data){
    if ($projectName==""){
        $projectName=$data['project'];
    }

    # Todo Add Access Control
    if(!accessControl("any", ['projectRole.'.$projectName.'.admin','project.admin'])){
        $message = array();
        $message = [
            'code'  => false,
            'msg'   => "Your account does not have the rights to delete Dynamic Report Tasks on project $projectName",
            'jobid' => 0
        ];
        return $message;
    }

    $ids = (isset($data['ids'])) ? $data['ids']: '';
    global $projectdb;
    $projectdb = selectDatabase($projectName);
    take_snapshot_last($projectName);

    if ($ids=="0"){
        $source=$data['source'];
        $vsys=$data['vsys'];
        $projectdb->query("DELETE FROM applications_from_log WHERE source='$source' AND vsys='$vsys';");
    }
    else{
        $projectdb->query("DELETE FROM applications_from_log WHERE rule_lid IN ($ids);");
    }

    $message = array();
    $message['code'] = true;
    $message['msg'] = 'Done';
    return $message;
}

function send_api_dynreports_calls(STRING $projectName, ARRAY $data){
    global $app;

//    ini_set('max_execution_time', 10000);
//    ini_set("memory_limit", "1000M");
//    $isProxy=false;
//    global $pandb;
//    $projectdb = selectDatabase($projectName);
    if ($projectName==""){
        $projectName=$data['project'];
    }
    if(!accessControl("any", ['projectRole.'.$projectName.'.admin','projectRole.'.$projectName.'.update','project.admin'])){
        $message = [
            'code'  => false,
            'msg'   => "Your account does not have the rights to create Dynamic Report Tasks on project $projectName",
            'jobid' => 0
            ];
        return $message;
    }

    $ids = (isset($data['data'])) ? $data['data']: '';

    //Get selected connectors
    $user = $app->container->sentinel->getUser();
    $userID = $user->id;
    $api_key= getUserApiKey($user->getAttribute("api_key")??"", $user->getAttribute("valid_til")??"",$user->getAttribute("id"));
    $project = $app->project->where('name', '=', $projectName)->get()->first();
    $userSettings = $app->userSettings->where('user_id','=',$userID)->where('project_id','=',$project->id)->first();
    $connector = $userSettings->selectedLogConnector;

    if ($connector==""){
        $message['code']=false;
        $message['msg']="No Log Connector Selected from PLUGINS";
        $message['jobid'] = 0;
        return $message;
    }

    $parentJobID = $jobID = registerParentJob($user, $project->id, 'Bundle of Send Dynamic Reports API Calls');

    # Esta mal el divece id se compara con el connector id?? MAL !!!!
    $data_individual = [
        'data'      => $ids,
        'project'   => $projectName,
        'connector' => $connector,
        'source'    => $data['source'],
        'vsys'      => $data['vsys'],
        'action'    => $data['action'],
        'key'       => $api_key,
    ];

    //print_r($data_individual);
    $jobID = registerJob($data_individual, $user, 'Dynamic Reports', $parentJobID);
    $taskID = registerTask($data_individual, $user, $jobID, "ApiDynReport", "Request Dynamic Reports");
    send_APICallMessage($data_individual, $user, $taskID, "ApiDynReport");


    $message = [
        'code'  => true,
        'jobid' => $parentJobID,
        'msg'   => 'Dynamic Report registered correctly'
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
        'taskType'      => 'Dynamic Reports',
        'taskName'      => $processName,
        'processCode'   => $processCode,
        'statusMessage' => 'Pending...',
        'statusCode'    => '0',
        'params'        => json_encode($data),
    ];

    if(!$task = $app->task->create($params)){
        return -1;
    }

    //Count number of API calls that will be sent
    $idsString = $data['data'];
    $project = $data['project'];

    global $projectdb;
    $projectdb = selectDatabase($project);
    if($idsString == 'all' || $idsString == '0'){
        if($data['vsys']=='all'){
            $query = "SELECT count(*) as total FROM security_rules WHERE disabled=0 AND source=".$data['source']." ;";
        }
        else{
            $query = "SELECT count(*) as total FROM security_rules WHERE disabled=0 AND source=".$data['source']." AND vsys='".$data['vsys']."';";
        }
//        $query = "SELECT count(*) as total FROM security_rules WHERE disabled=0 AND action='allow' AND source=".$data['source']." AND vsys='".$data['vsys']."';";

        $result = $projectdb->query($query);
        $dataQuery = $result->fetch_assoc();
        $number_calls = $dataQuery['total'];
    }
    else{
        $number_calls = count(explode(",",$idsString));
//        $query = "SELECT count(*) as total FROM security_rules WHERE disabled=0 AND action='allow' AND source=".$data['source']." AND vsys='".$data['vsys']."' AND id IN (".$idsString.") ;";
//        $result = $projectdb->query($query);
//        $dataQuery = $result->fetch_assoc();
//        $number_calls = $dataQuery['total'];
    }
    $job = $app->job->where('id', $jobID)->first();
    $jobParams = [
        'tasks' => $job->tasks + $number_calls,
    ];
    $job->update($jobParams);

    if($job->parentJob != ''){
        $parentJob = $app->job->where('id', $job->parentJob)->first();
        $parentJobParams = [
            'tasks' => $parentJob->tasks + $number_calls,
        ];
        $parentJob->update($parentJobParams);
    }

    return $task->id;
}

function send_APICallMessage(ARRAY $data, $user, INT $taskID, STRING $process){

    $message = [
        'sender'        => $user->id,
        'proccessCode'  => $process,
        'params'        => [
            'data'        => $data['data'],
            'connector'   => $data['connector'],
            'source'      => $data['source'],
            'vsys'        => $data['vsys'],
            'taskId'      => $taskID,
            'project'     => $data['project'],
            'userId'      => $user->id,
            'action'      => $data['action'],
            'key'         => $data['key'],
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

function registerJob(ARRAY $data, $user, STRING $description, INT $parentJob=null){
    global $app;

    $params = [
        'user_id'       => $user->id,
        'parentType'    => 'reports',
        'parentId'      => $data['connector'],
        'description'   => $description .' from '.$data['connector'],
        'parentJob'     => $parentJob,
    ];
    if(!$job = $app->job->create($params)){
        return -1;
    }

    return $job->id;
}

function registerParentJob($user, $projectID, STRING $description){
    global $app;

    $params = [
        'user_id'       => $user->id,
        'parentType'    => 'project',
        'parentId'      => $projectID,
        'description'   => $description,
    ];

    if(!$job = $app->job->create($params)){
        return -1;
    }

    return $job->id;
}

