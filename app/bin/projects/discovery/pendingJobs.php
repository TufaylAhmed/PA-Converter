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

require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';

require_once INC_ROOT.'/libs/shared.php';
require_once INC_ROOT.'/libs/xmlapi.php';

require_once INC_ROOT.'/bin/jobs/Job.php';
require_once INC_ROOT.'/libs/database.php';

$request_body   = file_get_contents('php://input');
$data           = json_decode($request_body, true);

parse_str(file_get_contents("php://input"),$post_vars);

include INC_ROOT.'/bin/middleware_sanitizer.php';

if(isset($post_vars['type'])){
    $type = $pandb->real_escape_string($post_vars['type']);
}
else {
    $projectName = $pandb->real_escape_string((string)(isset($_GET['project'])   ? $_GET['project'] : ''));
    $mode        = $pandb->real_escape_string((string)(isset($_GET['mode'])      ? $_GET['mode'] : ''));
}

if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
}

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $data=[
            'project' => $projectName,
            'mode' => $mode,
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
    $mode     = $data['mode'];

    if(!accessControl("any", ['project.admin', 'project.create',"projectRole.$projectName.admin","projectRole.$projectName.update" ])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have job query rights for this project';
        return $message;
    }
    if(!$project = $app->project->where('name',$projectName)->get()->first()){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'The project does not exist in our database';
        return $message;
    }
    switch ($mode){
        case 'region-post':
            if(!$job = $app->job
                ->where('parentType','MLdiscoverRegions')
                ->where('parentId',$project->id)
                ->where('description','LIKE','Spark: Region post-%')
                ->whereColumn('completed','<','tasks')
                ->get()->last())
            {
                $message = array();
                $message['code'] = false;
                $message['msg'] = [
                    'job-id' => 'No job',
                ];
                return $message;
            }
            break;

        case 'region-pre':
            if(!$job = $app->job
                ->where('parentType','MLdiscoverRegions')
                ->where('parentId',$project->id)
                ->where('description','LIKE','Spark: Region pre-%')
                ->whereColumn('completed','<','tasks')
                ->get()->last())
            {
                $message = array();
                $message['code'] = false;
                $message['msg'] = [
                    'job-id' => 'No job',
                ];
                return $message;
            }
            break;

        case 'secRules-analyze':
            if(!$job = $app->job
                ->where('parentType','MLdiscoverSecurityRules')
                ->where('parentId',$project->id)
                ->where('description','LIKE','Spark: New SecurityRules Analyze%')
                ->whereColumn('completed','<','tasks')
                ->get()->last())
            {
                $message = array();
                $message['code'] = false;
                $message['msg'] = [
                    'job-id' => 'No job',
                ];
                return $message;
            }
            break;

        case 'secRules-enrich':
            if(!$job = $app->job
                ->where('parentType','MLenrichmentSecurityRules')
                ->where('parentId',$project->id)
                ->where('description','LIKE','Spark: Enrich SecurityRules %')
                ->whereColumn('completed','<','tasks')
                ->get()->last())
            {
                $message = array();
                $message['code'] = false;
                $message['msg'] = [
                    'job-id' => 'No job',
                ];
                return $message;
            }
            break;

        case 'dynamic-reports':
            if(!$job = $app->job
                ->where('parentType','project')
                ->where('parentId',$project->id)
                ->where('description','LIKE','Bundle of Send Dynamic Reports%')
                ->whereColumn('completed','<','tasks')
                ->get()->last())
            {
                $message = array();
                $message['code'] = false;
                $message['msg'] = [
                    'job-id' => 'No job',
                ];
                return $message;
            }
            break;

        default:
            $msg = [
                'code' => false,
                'msg' => [
                    'job-id' => 'No job',
                ]
            ];
            return $msg;
    }

    $message = array();
    $message['code'] = true;
    $message['msg'] =  [
        'job-id' => $job->id,
    ];
    return $message;

}