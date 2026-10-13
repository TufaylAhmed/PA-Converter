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
require_once INC_ROOT.'/libs/database.php';
require_once INC_ROOT.'/libs/shared.php';
require_once INC_ROOT.'/libs/settings/ML_Settings.php';
require_once INC_ROOT.'/libs/common/lib-objects.php';

require_once INC_ROOT.'/userManager/API/projects/UserSettings.php';

require_once INC_ROOT.'/libs/common/discovery/LogConnector.php';

require_once INC_ROOT.'/libs/database.php';

use PaloAltoNetworks\Expedition\Discovery\LogConnector;

$request_body   = file_get_contents('php://input');
$data           = json_decode($request_body, true);

parse_str(file_get_contents("php://input"),$post_vars);

include INC_ROOT.'/bin/middleware_sanitizer.php';

$timezone='Europe/Helsinki';

if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
    $timezone=$_SESSION['timezone'];
}

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $project        = $pandb->real_escape_string((string)  (isset($_GET['project'])            ? $_GET['project'] : ''));
        $mode           = $pandb->real_escape_string((string)  (isset($_GET['mode'])               ? $_GET['mode'] : ''));
        $page           = $pandb->real_escape_string((string)(isset($_GET['page'])                 ? $_GET['page']: ''));
        $start          = $pandb->real_escape_string((string)(isset($_GET['start'])                ? $_GET['start']: ''));
        $limit          = $pandb->real_escape_string((string)(isset($_GET['limit'])                ? $_GET['limit']: ''));
        $query          = $pandb->real_escape_string((string)(isset($_GET['query'])                ? $_GET['query']: ''));

        $data=array(
            "project"=>$project,
            "mode"=>$mode,
            "page"=>$page,
            "start"=>$start,
            "limit"=>$limit,
            "query"=>$query
        );
        $message = readnewRules($data);
        if($message['code']) {
            $totalTags = $message['total'];
            echo json_encode(array( 'total' => $totalTags,
                                    'isUserGroupsRetrieved'=>$message['isGroupsRetrieved'],
                                    'isRegionsRetrieved'=>$message['isRegionsRetrieved'],
                                    'rules' => $message['msg']));
        }
        else{
            echo '{"total":"0","rules":[]}';
        }
        break;

    case 'POST':
        $project            = $pandb->real_escape_string((string)  (isset($_POST['project'])               ? $_POST['project']             : ''));
        $mode               = $pandb->real_escape_string((string)  (isset($_POST['mode'])                  ? $_POST['mode']                : ''));
        $ids                = $pandb->real_escape_string((string)  (isset($_POST['ids'])                   ? $_POST['ids']                 : ''));
        $mask               = $pandb->real_escape_string((string)  (isset($_POST['mask'])                  ? $_POST['mask']                : '32'));
        $accuracy           = $pandb->real_escape_string((string)  (isset($_POST['accuracy'])              ? $_POST['accuracy']            : '1'));
        $debug              = $pandb->real_escape_string((string)  (isset($_POST['debug'])                 ? $_POST['debug']               : 'false'));
        $initDate           = $pandb->real_escape_string((string)  (isset($_POST['startdate'])             ? $_POST['startdate']           : ''));
        $endDate            = $pandb->real_escape_string((string)  (isset($_POST['enddate'])               ? $_POST['enddate']             : ''));
        $hits               = $pandb->real_escape_string((string)  (isset($_POST['hits'])                  ? $_POST['hits']                : 1));
        $bytes              = $pandb->real_escape_string((string)  (isset($_POST['bytes'])                 ? $_POST['bytes']               : 1));
        $bytesSent          = $pandb->real_escape_string((string)  (isset($_POST['bytesSent'])             ? $_POST['bytesSent']           : 0));
        $bytesReceived      = $pandb->real_escape_string((string)  (isset($_POST['bytesReceived'])         ? $_POST['bytesReceived']       : 0));

        $scopeArray = array();
        if(isset($_POST['cloudSelected']) && $_POST['cloudSelected']=='true'){
            $scopeArray[] = "cloud";
        }
        if(isset($_POST['commonSelected']) && $_POST['commonSelected']=='true'){
            $scopeArray[] = "common";
        }
        if(isset($_POST['globalSelected']) && $_POST['globalSelected']=='true'){
            $scopeArray[] = "global";
        }
        if(isset($_POST['peer2peerSelected']) && $_POST['peer2peerSelected']=='true'){
            $scopeArray[] = "peer-to-peer";
        }
        if(isset($_POST['unknownSelected']) && $_POST['unknownSelected']=='true'){
            $scopeArray[] = "unknown";
        }

        $data=[
            "project"   => $project,
            "ids"       => $ids,
            "debug"     => $debug,
            "mode"      => $mode,
            "scope"     => implode(',',$scopeArray),
            "initDate"  => $initDate,
            "endDate"   => $endDate,
            "mask"      => $mask,
            "accuracy"  => $accuracy,
            "hits"              => $hits,
            "bytes"             => $bytes,
            "bytesSent"         => $bytesSent,
            "bytesReceived"     => $bytesReceived,
            "timezone"          => $timezone,
        ];

        $mode = ucwords($mode);
        switch($mode){
            case "Analyze":
            default:
                $message = enrich_rules($data);
                echo json_encode(array('success' => $message['code'], 'msg' =>$message['msg'], 'jobid' => $message['jobid']));
                break;
        }

        break;

    case 'PUT':
        $project    = $pandb->real_escape_string((string)  (isset($_POST['project'])    ? $_POST['project'] : ''));
        $ids        = $pandb->real_escape_string((string)  (isset($_POST['ids'])   ? $_POST['ids'] : ''));
        $data=array("project"=>$project,"ids"=>$ids);
        $message = add_NewRules($data);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    case 'DELETE':
        break;

    default:
        break;
}

function add_NewRules(ARRAY $params){
    global $projectdb;
    $project = (isset($params['project']))? $params['project']: "";
    $projectdb = selectDatabase($project);

    $message = [
        'code'  => true,
        'msg'   => "Nothing has been done. Add New Rules need to be implemented"
    ];

    return $message;
}

function readnewRules(ARRAY $params){
    global $projectdb;
    $MODE    = (isset($params['mode']))? $params['mode']: "pre-analysis";
    $project = (isset($params['project']))? $params['project']: "";
    $start  = (isset($params['start']))? $params['start']: "0";
    $limit  = (isset($params['limit']))? $params['limit']: "50";
    $projectdb = selectDatabase($project);

    $Data=array();
    $query = "SELECT id, timestamp from ML_RuleEnrichment ORDER BY id DESC LIMIT 1";
    $result = $projectdb->query($query);
    if($result->num_rows == 1){
        $data = $result->fetch_assoc();
        $lastDate = $data['timestamp'];
    }
    else{
        $message = [
            'code' => true,
            'isGroupsRetrieved' => checkGroupsRetrieved(),
            'isRegionsRetrieved'=> checkRegionsRetrieved(),
            'total' => 0,
            'msg' => [],
        ];
        return $message;
    }

    $totalrows=$projectdb->query("SELECT * FROM ML_RuleEnrichment WHERE timestamp ='$lastDate';");
    $total=$totalrows->num_rows;
    $potential=$projectdb->query("SELECT * FROM ML_RuleEnrichment WHERE timestamp ='$lastDate' ORDER BY RuleID, ServicesTCP ASC LIMIT $start, $limit;");
    if ($potential->num_rows>0){
        while($potentialData=$potential->fetch_assoc()){
            if ($potentialData['Destinations']==''){$potentialData['Destinations']="any";}
            if ($potentialData['DestinationZones']==''){$potentialData['DestinationZones']="any";}
            if ($potentialData['Sources']==''){$potentialData['Sources']="any";}
            if ($potentialData['SourcesZones']==''){$potentialData['SourcesZones']="any";}
            if ($potentialData['Users']==''){$potentialData['Users']="any";}
            if (($potentialData['ServicesTCP']=='') && ($potentialData['ServicesUDP']=='')){$potentialData['Services']="any";}
            if ($potentialData['Application']==''){$potentialData['Application']="any";}

            $destinations_exp = explode(",", $potentialData['Destinations']);
            $potentialData['Destinations'] = $destinations_exp;

            $sources_exp = explode(",", $potentialData['Sources']);
            $potentialData['Sources'] = $sources_exp;

            $destinations_regions_exp = explode(",", $potentialData['DestinationRegions']);
            $potentialData['DestinationRegions'] = $destinations_regions_exp;

            $sources_regions_exp = explode(",", $potentialData['SourcesRegions']);
            $potentialData['SourcesRegions'] = $sources_regions_exp;

            $applications_exp = explode(",", $potentialData['Application']);
            $potentialData['Application'] = $applications_exp;

            $users_exp = explode(",", $potentialData['Users']);
            $potentialData['Users'] = $users_exp;

            $destinations_zones_exp = explode(",", $potentialData['DestinationZones']);
            $potentialData['DestinationZones'] = $destinations_zones_exp;

            $sources_zones_exp = explode(",", $potentialData['SourcesZones']);
            $potentialData['SourcesZones'] = $sources_zones_exp;

            //$potentialData['Destinations']=str_replace(",",",<br>",$potentialData['Destinations']);
            //$potentialData['DestinationZones']=str_replace(",",",<br>",$potentialData['DestinationZones']);
            //$potentialData['DestinationRegions']=str_replace(",",",<br>",$potentialData['DestinationRegions']);
            //$potentialData['Sources']=str_replace(",",",<br>",$potentialData['Sources']);
            //$potentialData['SourcesZones']=str_replace(",",",<br>",$potentialData['SourcesZones']);
            //$potentialData['SourcesRegions']=str_replace(",",",<br>",$potentialData['SourcesRegions']);
            //$potentialData['Users']=str_replace(",",",<br>",$potentialData['Users']);
            //$potentialData['Application'] = str_replace(",",",<br>",$potentialData['Application']);

            if(($potentialData['ServicesTCP'] == "application-default") && ($potentialData['ServicesUDP'] == "application-default")){
                //$potentialData['Services'] = str_replace(",",",<br>",$potentialData['ServicesTCP']);
                $services_exp = explode(",", $potentialData['ServicesTCP']);
                $potentialData['Services'] = $services_exp;
            }else{
                //$potentialData['Services'] = str_replace(",",",<br>",$potentialData['ServicesTCP']) ."<br>". str_replace(",",",<br>",$potentialData['ServicesUDP']);

                $services_tcp_exp = explode(",", $potentialData['ServicesTCP']);
                $services_udp_exp = explode(",", $potentialData['ServicesUDP']);
                $services_exp = array_merge($services_tcp_exp, $services_udp_exp);

                $potentialData['Services'] = $services_exp;
            }
            $Data[] = $potentialData;
        }
    }

    $message = [
        'code' => true,
        'isGroupsRetrieved' => checkGroupsRetrieved(),
        'isRegionsRetrieved'=> checkRegionsRetrieved(),
        'total' => $total,
        'msg' => $Data
    ];
    return $message;
}

function enrich_rules(ARRAY $data){
    return securityRulesAnalyzer($data);
}


function checkGroupsRetrieved(){
    return false;
}

function checkRegionsRetrieved(){
    return false;
}

function securityRulesAnalyzer($data){ //$MODE, $project, STRING $scope="none", $debug=null){
    global $app;
    global $pandbRBAC;
    $debug      = isset($data['debug'])?    $data['debug']      : 'false';
    $project    = isset($data['project'])?  $data['project']    : '';
    $timezone    = isset($data['timezone'])?  $data['timezone'] : 'Europe/Helsinki';
    $projectdb = selectDatabase($project);

    $user    = $app->container->sentinel->getUser();

    if (!($projectObj = $app->project->where('name', '=', $project)->get()->first() )) {
        $msg = [
            'code'  => false,
            'jobid' => -1,
            'msg'   => 'Project not found in our registry'
        ];
        return $msg;
    }

    //Get LogConnector
    $logConnector = new LogConnector($project);
    $devicesList = $logConnector->getDevices();
//    $devicesList = getDevicesToLearnFrom($project);
    if(count($devicesList)==0){
        $msg = [
            'code'  => false,
            'msg'   => "No devices in this logConnector",
            'jobid'   => -1
        ];
        return $msg;
    }

    $devices = implode(",", $devicesList);

    //Get the Ids of the rules that are to be learnt from
//    $rulesToLearn = getRulesToLearnFrom($project);
    $rulesToLearn = $logConnector->getEnrichmentRules();

    if(count($rulesToLearn)==0){
        $msg = [
            'code'  => false,
            'jobid'   => -1,
            'msg'   => "No rules selected for learning"
        ];
        return $msg;
    }



    $rules = implode(",", $rulesToLearn);

    //TODO: Delete the prior results only if we are going to process the job. Meaning, make sure we do not "crash" after deleting
    //Delete prior entries of learnt rules
    $query = 'DELETE FROM ML_RuleEnrichment WHERE RuleID IN ("'.implode('","',$rulesToLearn).'")';
    $projectdb->query($query);


    $dates = $logConnector->getTimeFrame();
//    echo "From LogConnector\n";
//    print_r($dates);
    $initDate = ($data['initDate']!='') ? $data['initDate'] : $dates['startDate'];
    $endDate  = ($data['endDate'] !='') ? $data['endDate']  : $dates['endDate'];

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

    if($project == "" ){
        $msg = [
            'code'  => false,
            'jobid' => -1,
            'msg'   => "No project selected"
        ];
    }
    else{
        $MODE       = isset($data['mode'])?     $data['mode']       : '';
        $mask       = isset($data['mask'])?     $data['mask']       : '32';
        $accuracy   = isset($data['accuracy'])? $data['accuracy']   : '1';
//        $initDate   = isset($data['initDate'])? $data['initDate']   : '';
//        $endDate    = isset($data['endDate'])?  $data['endDate']    : '';
        $hits           = ($data['hits'] !='') ? $data['hits']  : 1;
        $bytes          = ($data['bytes'] !='') ? $data['bytes']  : 1;
        $bytesSent      = ($data['bytesSent'] !='') ? $data['bytesSent']  : 0;
        $bytesReceived  = ($data['bytesReceived'] !='') ? $data['bytesReceived']  : 0;

        //Generate JobID
        $data_individual['projectname'] = $project;
        $mlSettings = new ML_Settings($pandbRBAC);
        $connectionStatus = $mlSettings->checkAlive();

        if(isset($connectionStatus->alive) && $connectionStatus->alive==true){

            $jobID = registerJob($data_individual, $user, "Spark: Enrich SecurityRules in");
            $API_URI = "https://$ExpeditionML/API/secRulesEnrichment.php";
            $params = [
                'project'   => $project,
                'devices'   => $devices,
                'rules'     => $rules,
                'mode'      => $MODE,
                'master'    => $MASTERLOCATION,
                'mtserver'  => $MTSERVER,
                'mtuser'    => DBUser,
                'mtpassword'=> DBPass,
                'mlserver'  => $ExpeditionML,
                'parquetPath'=>$parquetPath,
                'mask'      => $mask,
                'accuracy'  => $accuracy,
                'initDate'  => $initDate,
                'endDate'   => $endDate,
                'hits'      => $hits,
                'bytes'     => $bytes,
                'bytesSent' => $bytesSent,
                'bytesReceived'     => $bytesReceived,
                'debug'     => $debug
            ];
            $taskID = registerTask($params, $user, $jobID, "$API_URI", "Spark: Enrich SecurityRules in");
            $url = "https://$ExpeditionML/API/secRulesEnrichment.php?".
                "project=$project&".
                "devices=$devices&".
                "rules=$rules&".
                "task-id=$taskID&".
                "master=$MASTERLOCATION&".
                "mtserver=$MTSERVER&".
                "mtuser=".DBUser."&".
                "mtpassword=".urlencode(DBPass)."&".
                "mlserver=$ExpeditionML&".
                "parquetPath=$parquetPath&".
                "mask=$mask&".
                "accuracy=$accuracy&".
                "initDate=$initDate&".
                "endDate=$endDate&".
                "hits=$hits&".
                "bytes=$bytes&".
                "bytesSent=$bytesSent&".
                "bytesReceived=$bytesReceived&".
                "debug=$debug";
            $tuCurl = curl_init();
//        curl_setopt($tuCurl,CURLOPT_URL,$url);
//        curl_setopt($tuCurl,CURLOPT_RETURNTRANSFER,true);
//        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, 0);
//        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, 0);
//        $output=curl_exec($tuCurl);


            $url = "https://$ExpeditionML/API/secRulesEnrichment.php";
            $curlParams =[
                "project"   => $project,
                "devices"   =>$devices,
                "rules"     =>$rules,
                "task-id"   =>$taskID,
                "master"    =>$MASTERLOCATION,
                "mtserver"  =>$MTSERVER,
                "mtuser"    =>DBUser,
                "mtpassword"=>urlencode(DBPass),
                "mlserver"  =>$ExpeditionML,
                "parquetPath"=>$parquetPath,
                "mask"      =>$mask,
                "accuracy"  =>$accuracy,
                "initDate"  =>$initDate,
                "endDate"   =>$endDate,
                'hits'      => $hits,
                'bytes'     => $bytes,
                'bytesSent' => $bytesSent,
                'bytesReceived'     => $bytesReceived,
                "debug"     =>$debug,
                "timezone"  =>$timezone,
            ];

            curl_setopt($tuCurl, CURLOPT_URL, $url);
            curl_setopt($tuCurl, CURLOPT_POST, 1);
            curl_setopt($tuCurl, CURLOPT_POSTFIELDS, http_build_query($curlParams));
            curl_setopt($tuCurl, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, 0);
            curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, 0);
            curl_exec($tuCurl);

            curl_close($tuCurl);

            $msg = [
                'code'  => true,
                'jobid'   => $jobID,
                'msg'   => "Discovering security rules"
            ];
        }
        else{
            $msg = [
                'code'  => false,
                'jobid'   => -2,
                'msg'   => "MLServer not reachable"
            ];
        }
    }

    return $msg;

}


function registerJob(ARRAY $data, $user, STRING $description, INT $parentJob=null){
    global $app;

    $project = $app->project->where('name',$data['projectname'])->first();
    $params = [
        'user_id'       => $user->id,
        'parentType'    => 'MLenrichmentSecurityRules',
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
        'parentType'    => 'MLenrichmentSecurityRules',
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
        'taskType'      => 'MLenrichmentSecurityRules',
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
