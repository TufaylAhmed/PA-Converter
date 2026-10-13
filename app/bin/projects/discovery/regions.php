<?php
/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: 31/05/17 - 10:56
 ******************************************************************************/

//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';
require_once INC_ROOT.'/libs/database.php';
require_once INC_ROOT.'/libs/shared.php';
require_once INC_ROOT.'/libs/settings/ML_Settings.php';

require_once INC_ROOT.'/libs/common/discovery/LogConnector.php';

use PaloAltoNetworks\Expedition\Discovery\LogConnector;

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
        $project    = $pandb->real_escape_string((string)  (isset($_GET['project'])    ? $_GET['project'] : ''));
        $mode       = $pandb->real_escape_string((string)  (isset($_GET['mode'])   ? $_GET['mode'] : ''));

        if(!accessControl("any", ['projectRole.'.$project.'.*'])){
            $message = [
                'code' => true,
                'count' => 0,
                'msg' => array("text"=>'',"value"=>0,"children"=>''),
            ];
            echo json_encode(array('total' => 0, 'regions' => array()));
            return;
        }

        $data=array("project"=>$project,"mode"=>$mode);
        $message = findRegions($data);
        if($message['code']) {
            $totalTags = $message['total'];
            echo json_encode(array('total' => $totalTags, 'regions' => $message['msg']));
        }
        else{
            echo '{"total":"0","regions":[]}';
        }
        break;

    case 'POST':
        $project    = $pandb->real_escape_string((string)  (isset($_POST['project'])           ? $_POST['project'] : ''));
        $mode       = $pandb->real_escape_string((string)  (isset($_POST['mode'])              ? $_POST['mode'] : ''));
        $ids        = $pandb->real_escape_string((string)  (isset($_POST['ids'])               ? $_POST['ids'] : ''));
        $mask       = $pandb->real_escape_string((string)  (isset($_POST['mask'])              ? $_POST['mask'] : '26'));
        $initDate   = $pandb->real_escape_string((string)  (isset($_POST['startdate'])         ? $_POST['startdate']   : ''));
        $endDate    = $pandb->real_escape_string((string)  (isset($_POST['enddate'])           ? $_POST['enddate']     : ''));
        $debug       = $pandb->real_escape_string((string)  (isset($_POST['debug'])            ? $_POST['debug'] : 'false'));

        if(!accessControl("any", ['projectRole.'.$project.'.update'])){
            echo json_encode(array('success' => false, 'msg' => 'You do not have permissions in this project'));
            return;
        }

        $data=[
            "project"   =>$project,
            "ids"       =>$ids,
            "mask"      =>$mask,
            "initDate"  => $initDate,
            "endDate"   => $endDate,
            "debug"     =>$debug,
        ];
        switch($mode){
            case "enable":
                $message = enable_network($data);
                echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
                break;
            case "disable":
                $message = disable_network($data);
                echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
                break;
            case "discovery":
                $message = discover_networks($data);
                echo json_encode(array('success' => $message['code'], 'msg' =>$message['msg'], 'jobid' => $message['jobid']));
                break;
            case "analyze":
                $message = analyze_networks($data);
                echo json_encode(array('success' => $message['code'], 'msg' =>$message['msg'], 'jobid' => $message['jobid']));
                break;
            default:
                $message = discover_networks($data);
                echo json_encode(array('success' => $message['code'], 'msg' =>$message['msg'], 'jobid' => $message['jobid']));
        }

        break;

    case 'PUT':
        $message = update_changes($data);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    case 'DELETE':
        $message = delete_changes($data);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    default:
        break;
}

function enable_network($params){
    $project = (isset($params['project']))? $params['project']: "";
    $projectdb = selectDatabase($project);
    $ids= (isset($params['ids']))? $params['ids']: "";
    if ($ids!=""){
        $projectdb->query("UPDATE PotentialRegions SET enable='true' WHERE id IN ($ids);");
    }
    $msg = [
        'code'  => true,
        'msg'   => 'Networks successfully Enabled.'
    ];
    return $msg;
}

function disable_network($params){
    $project = (isset($params['project']))? $params['project']: "";
    $projectdb = selectDatabase($project);
    $ids= (isset($params['ids']))? $params['ids']: "";
    if ($ids!=""){
        $projectdb->query("UPDATE PotentialRegions SET enable='false' WHERE id IN ($ids);");
    }
    $msg = [
        'code'  => true,
        'msg'   => 'Networks successfully Disabled.'
    ];
    return $msg;
}

function analyze_networks(ARRAY $data){
    $project = $data['project'];
    $mask    = $data['mask'];
    $debug = $data['debug'];
    return regionAnalyzer("post-analysis", $project, $data, $mask, $debug);
}

function discover_networks(ARRAY $data){
    $project = $data['project'];
    $mask    = $data['mask'];
    $debug = $data['debug'];
    return regionAnalyzer("pre-analysis", $project, $data, $mask, $debug);
}

function regionAnalyzer(STRING $MODE, STRING $project, ARRAY $data, $mask=null, $debug=null){
    global $app;
    global $pandbRBAC;
    if(is_null($debug)){
        $debug = "false";
    }

    $user    = $app->container->sentinel->getUser();
    $userName = $user->email;

    if (!($projectObj = $app->project->where('name', '=', $project)->get()->first() )) {
        $msg = [
            'code'  => false,
            'jobid' => -1,
            'msg'   => 'Project not found in our registry'
        ];
        return $msg;
    }

    $logConnector = new LogConnector($project);
    $devicesList = $logConnector->getDevices();

    if(count($devicesList)==0){
        $msg = [
            'code'  => false,
            'msg'   => "No devices in this project",
            'jobid' => -1
        ];
        return $msg;
    }

    $devices = implode(",", $devicesList);

    //Get the dates in the logCollector. If the user didn't override them, use the logConnector date values
    $dates = $logConnector->getTimeFrame();
    $initDate = isset($data['initDate']) ? $data['initDate'] : $dates['startDate'];
    $endDate  = isset($data['endDate'])  ? $data['endDate']  : $dates['endDate'];

    $MTSERVER = $_SERVER['SERVER_ADDR'].":3306";

    //Get number of Spark CPUs
    require_once INC_ROOT."/libs/cpu_status_functions.php";
    $MLstatus = getMLStatus();
    $sparkCPUs = 8; //Default value for Spark CPUs
    foreach ($MLstatus as $stat){
        if($stat->item =='CPUs'){
            $sparkCPUs = $stat->spark;
            break;
        }
    }
    $MASTERLOCATION="local[$sparkCPUs]";

    $mlSettings = new ML_Settings($pandbRBAC);
    $message = $mlSettings->get();
    $mlParams_arr = $message['msg'];
    if(count($mlParams_arr)>0){
        $ExpeditionML = $mlParams_arr[0]['server'];
        $parquetPath  = $mlParams_arr[0]['parquetPath'];
    }
    else{
        $ExpeditionML = $_SERVER['SERVER_ADDR'];
        $parquetPath  = "/tmp";
    }

    $connectionStatus = $mlSettings->checkAlive();

    if(isset($connectionStatus->alive) && $connectionStatus->alive==true) {

        if ($project == "") {
            $msg = [
                'code' => false,
                'jobid' => -1,
                'msg' => "No project selected"
            ];
        } else {
            //Generate JobID
            $data_individual['projectname'] = $project;
            $jobID = registerJob($data_individual, $user, "Spark: Region $MODE in");
            $API_URI = "https://$ExpeditionML/API/regionsDiscovery.php";
            $params = [
                'project' => $project,
                'mode' => $MODE,
                'master' => $MASTERLOCATION,
                'mtserver' => $MTSERVER,
                'parquetPath' => $parquetPath,
                'mask' => $mask,
                'initDate' => $initDate,
                'endDate' => $endDate,
                'debug' => $debug,
            ];
            $taskID = registerTask($params, $user, $jobID, "$API_URI", "Spark: Region $MODE");

            $url = "https://$ExpeditionML/API/regionsDiscovery.php";

            $params = array (
                "project" => $project,
                "devices" => $devices,
                "mode" => $MODE,
                "task-id" => $taskID,
                "master" => $MASTERLOCATION,
                "mtserver" => $MTSERVER,
                "mtuser" => DBUser,
                "mtpassword" => DBPass,
                "parquetPath" => $parquetPath,
                "mask" => $mask,
                "mlserver" => $ExpeditionML,
                "initDate" => $initDate,
                "endDate" => $endDate,
                "debug" => $debug,
                "user" => $userName,
                "api_key" => getUserApiKey($user->getAttribute("api_key")??"", $user->getAttribute("valid_til")??"",$user->getAttribute("id"))
            );

            // Convert the parameters to a URL-encoded string
            $urlEncodedString = http_build_query($params);

            // Build the complete URL with the encoded parameters
            $url .= '?' . $urlEncodedString;

//        echo $url;
            $tuCurl = curl_init();
            curl_setopt($tuCurl, CURLOPT_URL, $url);
            curl_setopt($tuCurl, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, 0);
            curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, 0);
            curl_exec($tuCurl);

            $msg = [
                'code' => true,
                'jobid' => $jobID,
                'msg' => "Discovering regions"
            ];
        }

    }
    else{
        $msg = [
            'code'  => false,
            'jobid'   => -2,
            'msg'   => "MLServer not reachable"
        ];
    }
    return $msg;

}

function registerJob(ARRAY $data, $user, STRING $description, INT $parentJob=null){
    global $app;

    $project = $app->project->where('name',$data['projectname'])->first();
    $params = [
        'user_id'       => $user->id,
        'parentType'    => 'MLdiscoverRegions',
        'parentId'      => $project->id,
        'description'   => $description .' '.$data['projectname'],
        'parentJob'     => $parentJob,
    ];
    if(!$job = $app->job->create($params)){
        return -1;
    }

    return $job->id;
}

function registerParentJob($user, STRING $description){
    global $app;


    $params = [
        'user_id'       => $user->id,
        'parentType'    => 'MLdiscoverRegions',
        'description'   => $description,
    ];
    if(!$job = $app->job->create($params)){
        return -1;
    }

    return $job->id;
}

function registerTask(ARRAY $data=null, $user, INT $jobID, STRING $processCode, STRING $processName){
    global $app;

    if(!isset($data['params'])){
        $data['params'] = '';
    }
    $data['userId'] = $user->id;

    $params = [
        'job_id'        => $jobID,
        'taskType'      => 'MLdiscoverRegions',
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
        'tasks' => $job->tasks +1,
    ];
    $job->update($jobParams);

    if($job->parentJob != ''){
        $parentJob = $app->job->where('id', $job->parentJob)->first();
        $parentJobParams = [
            'tasks' => $parentJob->tasks +1,
        ];
        $parentJob->update($parentJobParams);
    }

    return $task->id;
}

function findRegions(ARRAY $params){
    global $projectdb;
    $MODE    = (isset($params['mode']))? $params['mode']: "pre-analysis";
    $project = (isset($params['project']))? $params['project']: "";
    $projectdb = selectDatabase($project);
    $Data=array();
    $potential=$projectdb->query("SELECT *, INET_ATON(network) as networkLong FROM PotentialRegions WHERE timestamp in (SELECT MAX(timestamp) from PotentialRegions WHERE mode='$MODE') AND mode='$MODE' ORDER BY enable DESC;");
    if ($potential->num_rows>0){
        while($potentialData=$potential->fetch_assoc()){
            $Data[]=$potentialData;
        }
    }

    $message = array();
    $message['code'] = true;
    $message['total'] = count($Data);
    $message['msg'] = $Data;
    return $message;
}