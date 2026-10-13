<?php
/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: $today.year.hour.minute
 ******************************************************************************/

require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
require_once INC_ROOT.'/libs/definitions/sparkVersions.php';
require_once INC_ROOT.'/API/process/TaskUpdater.php';
require_once INC_ROOT.'/API/SparkJobs/RuleAutoCompleter.php';

use \PaloAltoNetworks\Expedition\Spark\RuleAutoCompleter;

ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

$request_body   = file_get_contents('php://input');
$data           = json_decode($request_body, true);

parse_str(file_get_contents("php://input"),$post_vars);

include INC_ROOT.'/bin/middleware_sanitizer.php';

if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
}

switch($_SERVER['REQUEST_METHOD'])
{
    case "POST":
        $message = getSecRules($post_vars);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg'], 'pid' => $message['pid']));
        break;

    default:
        echo json_encode(array('success' => false, 'msg' => "Wrong HTTP Request method"));
        break;
}

function getSecRules(ARRAY $params){
    $project            = isset($params['project']) ? $params['project']:'';
    $parquetPath        = isset($params['parquetPath']) ? $params['parquetPath'] : '/tmp';
    $INPUT 		        = $parquetPath."/connections.parquet";
    $REGIONS            = $parquetPath."/".$project."/myRegions.parquet";
    $params['timezone'] = isset($params['timezone'])? $params['timezone']: 'Europe/Helsinki';

    $saveServer = isset($params['saveServer'])? $params['saveServer']: 'true';
    $initDateString = $params['initDate']; //2017-10-25T00:00:00
    if($initDateString == ''){
        $date = new DateTime('1970-01-01');
    }
    else{
        $date = new DateTime($initDateString);
    }
    $initDate = $date->format('Y-m-d');

    $endDateString  = $params['endDate'];
    $date2 = new DateTime($endDateString);  //If $endDateString is '', DateTime will provide the current time
    $endDate = $date2->format('Y-m-d');

    $sparkParams = [
        'master'        => $params['master'],
        'debug'         => $params['debug'],
        'taskID'        => $params['task-id'],
        'mlserver'      => $params['mlserver'],
        'mtserver'      => $params['mtserver'],
        'timezone'      => $params['timezone'],
        'mtuser'        => $params['mtuser'],
        'mtpassword'    => $params['mtpassword'],
        'project'       => $params['project'],
        'input'         => $INPUT,
        'devices'       => $params['devices'],
        'rules'         => $params['rules'],
        'initDate'      => $initDate,
        'endDate'       => $endDate,
        'mask'          => $params['mask'],
        'accuracy'      => $params['accuracy'],
        'hits'          => $params['hits'],
        'bytes'         => $params['bytes'],
        'bytesSent'     => $params['bytesSent'],
        'bytesReceived' => $params['bytesReceived'],
        'saveServers'   => $saveServer,
        'regions'       => $REGIONS
    ];

    if(defined('SparkRAM')){
        $sparkParams['ram'] = SparkRAM;
    }

    $ruleEnrichmentLauncher = new RuleAutoCompleter($sparkParams);
    $response = $ruleEnrichmentLauncher->execute();

    return $response;

//    $command = "/opt/Spark/spark/bin/spark-submit --class com.paloaltonetworks.tbd.RuleAutoCompleter --master localhost --deploy-mode client ".
//                "/var/www/html/OS/spark/packages/RuleAutoCompleter-".Module_version_SecurityRuleEnrichment."-SNAPSHOT.jar ".
//                "master=".escapeshellarg($params['master']). ", debug=".escapeshellarg($params['debug']).", ".
//                "taskID=".escapeshellarg($params['task-id']).", MLServer=".escapeshellarg($params['mlserver']).
//                ", MTServer=".escapeshellarg($params['mtserver']).", timeZone=".escapeshellarg($params['timezone']).", DBUser=".escapeshellarg($params['mtuser']).", DBPass=".escapeshellarg($params['mtpassword']).", project=".escapeshellarg($params['project']).", ".
//                "input=".escapeshellarg($INPUT).", devices=".escapeshellarg($params['devices']).", rules=".escapeshellarg($params['rules']).", initDate=".escapeshellarg($initDate).", endDate=".escapeshellarg($endDate).", ".
//                "mask=".escapeshellarg($params['mask']).", accuracy=".escapeshellarg($params['accuracy']).", saveServers=".escapeshellarg($saveServer).", regions=".escapeshellarg($REGIONS);
//    $my = fopen("/tmp/command.spark","a");
//    fwrite($my,"$command\n");
//    fclose($my);
//
//    $pid = exec("$command > /tmp/error_SecRulesEnrich 2>/tmp/error_SecRulesEnrich2 & echo $!;", $output);
//
//    $mysqlServer = explode(":", $params['mtserver']);
//    $serverIP = $mysqlServer[0];
//    $serverPort = isset($mysqlServer[1])?$mysqlServer[1]: '3306';
//    $taskUpdater = new TaskUpdater($params['task-id'], $serverIP, $params['mtuser'], $params['mtpassword'], $serverPort);
//    $reported=$taskUpdater->updateTaskPid($pid);
//
//    $msg = [
//        "code"      => true,
//        "msg"       => "Started",
//        "reported"  => $reported,
//        "pid"       => $pid
//    ];
//
//    return $msg;
}
