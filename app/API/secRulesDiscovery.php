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
require_once INC_ROOT.'/API/SparkJobs/RuleLearner.php';
require_once '/home/userSpace/environmentParameters.php';

use \PaloAltoNetworks\Expedition\Spark\RuleLearner;

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
    case 'POST':
        $message = getSecRules($post_vars);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
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

    $saveServer = (isset($params['saveServer']) && ($params['saveServer']=='false' || $params['saveServer']==0))? 'false': 'true';
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
        'regions'       => $REGIONS,
        'scope'         => $params['scope'],
    ];

    if(defined('SparkRAM')){
        $sparkParams['ram'] = SparkRAM;
    }

    $ruleLearnerLauncher = new RuleLearner($sparkParams);
    $response = $ruleLearnerLauncher->execute();

    return $response;
}
