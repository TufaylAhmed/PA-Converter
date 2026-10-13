<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserverd.
 *
 * Development Team: Business Development
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com).
 * Date: 31/05/2017 - 14:29
 */

require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
require_once INC_ROOT.'/libs/definitions/sparkVersions.php';
require_once INC_ROOT.'/libs/database.php';
require_once INC_ROOT.'/libs/settings/ML_Settings.php';
global $app,$pandbRBAC;
require_once INC_ROOT.'/userManager/API/accessControl_CLI.php';

ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
//error_reporting(E_ALL);

$request_body   = file_get_contents('php://input');
$data           = json_decode($request_body, true);

parse_str(file_get_contents("php://input"),$post_vars);

include INC_ROOT.'/bin/middleware_sanitizer.php';

$master         = (string)(isset($_GET['master'])       ? $_GET['master']       : 'local[8]');
$mask           = (string)(isset($_GET['mask'])         ? $_GET['mask']         : '26');
$project        = (string)(isset($_GET['project'])      ? $_GET['project']      : 'none');
$devices        = (string)(isset($_GET['devices'])      ? $_GET['devices']      : '');
$mtuser         = (string)(isset($_GET['mtuser'])       ? $_GET['mtuser']       : 'root');
$mtpass         = (string)(isset($_GET['mtpassword'])   ? urldecode($_GET['mtpassword']) : 'paloalto');
$taskID         = (string)(isset($_GET['task-id'])      ? $_GET['task-id']      : '1193');
$mode           = (string)(isset($_GET['mode'])         ? $_GET['mode']         : 'pre-analysis');
$regions        = (string)(isset($_GET['regions'])      ? $_GET['regions']      : '');
$parquetPath    = (string)(isset($_GET['parquetPath'])  ? $_GET['parquetPath']  : '/tmp');
$timeZone       = (string)(isset($_GET['timezone'])     ? $_GET['timezone']     : 'Europe/Helsinki');
$debug          = (string)(isset($_GET['debug'])        ? $_GET['debug']        : 'false');
$initDate       = (string)(isset($_GET['initDate'])     ? $_GET['initDate'] : '');
$endDate        = (string)(isset($_GET['endDate'])      ? $_GET['endDate']  : '');
$api_key        = (string)(isset($_GET['api_key'])      ? $_GET['api_key']  : '');
$user_email        = (string)(isset($_GET['user'])      ? $_GET['user']  : '');

// Check the master is a valid master
$pattern = '/^local\[\d+\]$/';
if (preg_match($pattern, $master)) {

} else {
    $master = "local[8]";
}

// Check the Expedition server
$mlSettings = new ML_Settings($pandbRBAC);
$message = $mlSettings->get();
$mlParams_arr = $message['msg'];
if(count($mlParams_arr)>0){
    $mlserver = $mlParams_arr[0]['server'];
    $parquetPath  = $mlParams_arr[0]['parquetPath'];
    $tempPath     = $mlParams_arr[0]['tempDataPath'];
    $mtserver     = $mlserver.":3306";
} else {
    $message['code'] = false;
    $message['msg'] = "Invalid Server to execute the process";
    echo json_encode($message);
    exit();
}

$params = [
    "mode"       => $mode,
    "project"    => $project,
    'devices'    => $devices,
    "version"    => Module_version_ML_LogCoCo,
    "mtserver"   => $mtserver,
    "mtuser"     => $mtuser,
    "mtpassword" => $mtpass,
    "master"     => $master,
    "taskID"     => $taskID,
    "regions"    => $regions,
    "parquetPath"=> $parquetPath,
    "mask"       => $mask,
    "timezone"   => $timeZone,
    "mlserver"   => $mlserver,
    "debug"      => $debug,
    "initDate"   => $initDate,
    "endDate"    => $endDate,
];

/*if(!isset($api_key,$user_email)){
    http_response_code(401);
    header("HTTP/1.1 401 Unauthorized");
    header("Location: /401");
    exit;
}*/

if($user = $app->user->where('email',$user_email)->where('api_key',$api_key)->where('valid_til', '>',date("Y-m-d H:i:s"))->get()->first()) {
    $app->sentinel->login($user);
}

if(!$app->container->sentinel->check() || !isset($user) ){
    $message['code'] = false;
    $message['msg'] = "Invalid Credentials to execute the process";
    echo json_encode($message);
    exit();
}

// Validations
if(!accessControl("any", ['device.*', 'device.create'])){
    $message['code'] = false;
    $message['msg'] = 'Your account does not have the rights to view logs from devices.';
    echo json_encode($message);
    exit();
}

if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
}

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $message = getRegions($params);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    default:
        echo json_encode(array('success' => false, 'msg' => "Wrong HTTP Request method"));
        break;
}

function getRegions(ARRAY $params){
    $project         = $params['project'];
    $parquetPath     = $params['parquetPath'];
    $INPUT 		=$parquetPath."/connections.parquet";
    $REGIONS    =$parquetPath."/".$project."/myRegions.parquet";

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

    $command = "/opt/Spark/spark/bin/spark-submit --class com.paloaltonetworks.tbd.RegionDiscovery --master localhost --deploy-mode client ".
        "/var/www/html/OS/spark/packages/ML-LogCoCo-".Module_version_ML_LogCoCo."-SNAPSHOT.jar ".
        "master=".escapeshellarg($params['master']). ", debug=".escapeshellarg($params['debug']).", ".
        "taskID=".escapeshellarg($params['taskID']).", MLServer=".escapeshellarg($params['mlserver']).", MTServer=".escapeshellarg($params['mtserver']).", timeZone=".escapeshellarg($params['timezone']).", DBUser=".escapeshellarg($params['mtuser']).", DBPass=".escapeshellarg($params['mtpassword']).", project=".escapeshellarg($params['project']).", ".
        "input=".escapeshellarg($INPUT).", devices=".escapeshellarg($params['devices']).", mode=".escapeshellarg($params['mode']).", initDate=".escapeshellarg($initDate).", endDate=".escapeshellarg($endDate).", ".
        "mask=".escapeshellarg($params['mask']).", regions=".escapeshellarg($REGIONS).", TableName=PotentialRegions";

    $my = fopen("/tmp/command.spark","a");
    fwrite($my,"$command\n");
    fclose($my);
    exec("$command > /tmp/error_regions 2>/tmp/error_regions &");

//    $command ="/var/www/html/OS/spark/scripts/regionDiscovery.spark ".
//        " -x ".$params['project'].
//        " -e ".$params['devices'].
//        " -m ".$params['master'].
//        " -s /var/www/html/OS/spark/packages ".
//        " -v ".$params['version'].
//        " -t ".$params['taskID'].
//        " -o ".$params['mode'].

//        " -h ".$params['mtserver'].
//        " -u ".$params['mtuser'].
//        " -p ".$params['mtpassword'].

//        " -i ".$INPUT.
//        " -r ".$REGIONS.
//        " -c ".$params['mask'].
//        " -z ".$params['timezone'].

//        " -y ".$params['mtconnection'].

//        " -d ".$params['debug'];

    $msg = [
        "code"  => true,
        "msg"   => "Started"
    ];

    return $msg;
}
