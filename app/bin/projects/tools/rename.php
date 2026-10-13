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
require_once INC_ROOT.'/libs/common/tools/tools.php';
require_once INC_ROOT.'/bin/messaging/MessageSender.php';

$request_body     = file_get_contents('php://input');
$params           = json_decode($request_body, true);

if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
}

include INC_ROOT.'/bin/middleware_sanitizer.php';
global $pandb;

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $params['project'] = $pandb->real_escape_string(isset($_GET['project']) ? $_GET['project']: '');
        $params['source'] = $pandb->real_escape_string(isset($_GET['project']) ? $_GET['source']: '');
        $params['vsys'] = $pandb->real_escape_string(isset($_GET['vsys']) ? $_GET['vsys']: 'all');
        $params['mode'] = $pandb->real_escape_string(isset($_GET['mode']) ? $_GET['mode']: '');
        $params['selection'] = $pandb->real_escape_string(isset($_GET['selection']) ? $_GET['selection']: '');

        if ((isset($params['project'] )) AND ($params['project'] !='')) {
            $message = list_address_dns($params);
            echo json_encode(array('total' => $message['count'], 'search' => $message['msg']));
        }else{
            echo '{"total":"0","search":[]}';
        }
        break;

    case 'POST':
        $params['project'] = isset($_POST['project']) ? $_POST['project']: '';
        $params['source'] = isset($_POST['project']) ? $_POST['source']: '';
        $params['vsys'] = isset($_POST['vsys']) ? $_POST['vsys']: 'all';
        $params['mode'] = isset($_POST['mode']) ? $_POST['mode']: '';
        $params['selection'] = isset($_POST['selection']) ? $_POST['selection']: '';
        $params['ids'] = isset($_POST['ids']) ? $_POST['ids']: '';

        $message = calculate_address_dns($params);
        echo json_encode(array('success' => $message['code'], 'msg' =>$message['msg'], 'jobid' => $message['jobid']));
        break;

    case 'PUT':
        $project = $pandb->real_escape_string(isset($_GET['project']) ? $_GET['project']: '');
        $mode = $pandb->real_escape_string(isset($_GET['mode']) ? $_GET['mode']: '');
        $ids = $pandb->real_escape_string(isset($_GET['ids']) ? $_GET['ids']: '');
        $message = update_address_dns($project,$params);
        echo json_encode(array('success' => $message['code']));
        break;

    case 'DELETE':
        $message = delete_tools($params);
        echo json_encode(array('success' => $message['code']));
        break;

    default:
        break;
}

function applyFormat($project,$ids,$mode){

    if(!accessControl("any", ['projectRole.'.$project.'.update','project.create'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to view this project contents';
        return $message;
    }
    switch ($mode){

        case 'reverse':
            $message = applyFormatReverse($project, $ids);
            break;

        default:
            break;
    }

    return $message;


}

function list_address_dns(ARRAY $params){

    $project = $params['project'];
    $message=array();
    if(!accessControl("any", ['projectRole.'.$project.'.view'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to view this project contents';
        return $message;
    }
    switch ($params['mode']){

        case 'get_reverse':
            $message = getReverseDNS($project, $params);
            break;

        default:
            break;
    }

    return $message;

}

function calculate_address_dns(ARRAY $params){
    global $app;

    $project = $params['project'];

    if(!accessControl("any", ['projectRole.'.$project.'.update'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to edit this project contents';
        return $message;
    }

    $user = $app->container->sentinel->getUser();

    $message=array();
    $mode=$params['mode'];
    $params['user']=$user;
    switch ($mode){

        case 'set_reverse':
            $message = setReverseDNS($project, $params);
            break;

        case 'applyReverse':
            $message = applyFormatReverse($project, $params, $mode);
            break;

        case 'applyReverseIP':
            $message = applyFormatReverse($project, $params, $mode);
            break;

        case 'applyH_IP':
            $message = applyFormatReverse($project, $params, $mode);
            break;

        case "applyFQDN":
            $message = applyFormatReverse($project, $params, $mode);
            break;

        default:
            break;
    }


    return $message;


}

function registerJob(ARRAY $data, $user, STRING $description, INT $parentJob=null){
    global $app;

    $params = [
        'user_id'       => $user->id,
        'parentType'    => 'tools',
        'parentId'      => 0,
        'description'   => $description,
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
        'taskType'      => 'DNS Resolver',
        'taskName'      => $processName,
        'processCode'   => $processCode,
        'statusMessage' => 'Pending...',
        'statusCode'    => '0',
        'params'        => json_encode($data),
    ];

    if(!$task = $app->task->create($params)){
        return -1;
    }

    $project = $data['project'];

    global $projectdb;
    $projectdb = selectDatabase($project);

    $job = $app->job->where('id', $jobID)->first();
    $jobParams = [
        'tasks' => count($data['ids']),
    ];
    $job->update($jobParams);

    return $task->id;
}

function send_APICallMessage(ARRAY $data, $user, INT $taskID, STRING $process){
    $message = [
        'sender'        => $user->id,
        'proccessCode'  => $process,
        'params'        => [
            'source'    => $data['source'],
            'taskId'    => $taskID,
            'project'   => $data['project'],
            'userId'    => $user->id,
            'ids'       => $data['ids']
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

function update_address_dns($project,ARRAY $params){
    $message=array();
    $message['code'] = false;

    if(!accessControl("any", ['projectRole.'.$project.'.update'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to edit this project contents';
        return $message;
    }

    global $projectdb;
    $projectdb = selectDatabase($project);

    global $app;
    $user=$app->sentinel->getUser()->id;

    if (isset($params['id'])){
        $lid=$params['lid'];
        $table_name=$params['table_name'];
        $name=$params['name'];
        $reverse=$params['reverse'];

        if ( ($name!=$reverse) AND ($reverse!="")){
            $projectdb->query("UPDATE tools_rename SET reverse='$reverse' WHERE lid='$lid' AND user='$user';");
        }
    }
    else{
        foreach ($params as $key => $value){
            $lid=$value['lid'];
            $table_name=$value['table_name'];
            $name=$value['name'];
            $reverse=$value['reverse'];

            if ( ($name!=$reverse) AND ($reverse!="")){
                $projectdb->query("UPDATE tools_rename SET reverse='$reverse' WHERE lid='$lid' AND user='$user';");
            }
        }
    }

    $message['code'] = true;
    return $message;


}

function delete_tools(ARRAY $params){
    $message=array();
    $project = $params['project'];

    if(!accessControl("any", ['projectRole.'.$project.'.update'])){
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to edit this project contents';
        return $message;
    }

    switch ($params['mode']){

        default:
            break;
    }

    return $message;

}
