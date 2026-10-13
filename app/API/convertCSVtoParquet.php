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
global $app;
require_once INC_ROOT.'/userManager/API/accessControl_CLI.php';
require_once INC_ROOT.'/libs/objects/Response.php';
require_once INC_ROOT.'/API/SparkJobs/CSVProcesser.php';
use PaloAltoNetworks\Expedition\Spark\CSVProcesser;


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
        $message = logCollectorCompacter($post_vars);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    default:
        echo json_encode(array('success' => false, 'msg' => "Wrong HTTP Request method"));
        break;
}

function logCollectorCompacter(ARRAY $params){

    global $app;

    $MODE           ="Expedition";


    if(!isset($params['project'])      || $params['project']=='')        $params['project'] = '';
    if(!isset($params['timezone'])     || $params['timezone']=='')       $params['timezone'] = 'Europe/Helsinki';
    if(!isset($params['master'])       || $params['master']=='')         $params['master'] = 'local[8]';
    if(!isset($params['path'])         || $params['path']=='')           $params['path'] = '';
//    if(!isset($params['version'])      || $params['version']=='')        $params['version'] = Module_version_ConvertCSVtoParquet;
    if(!isset($params['debug'])        || $params['debug']=='')          $params['debug'] = 'false';
    if(!isset($params['path'])         || $params['path']=='')           $params['path'] = '/';
    if(!isset($params['parquetPath'])  || $params['parquetPath']=='')    $params['parquetPath'] = '/tmp';

    if(!isset($params['mtserver'])     || $params['mtserver']=='')       $params['mtserver'] = '127.0.0.1:3306';
    if(!isset($params['mtuser'])       || $params['mtuser']=='')         $params['mtuser'] = 'root';
    if(!isset($params['mtpassword'])   || $params['mtpassword']=='')     $params['mtpassword'] = 'paloalto';
    $mtserverArr    = explode(":",$params['mtserver']);
    if(!isset($params['mlserver']) || $params['mlserver']=='') $params['mlserver'] = $mtserverArr[0];

    if(!isset($params['parquetPath']) || $params['parquetPath']=='')     $params['parquetPath']='/tmp';
    if(!isset($params['tempPath'])    || $params['tempPath']=='')        $params['tempPath']='/tmp';

    $OUTPUT 		= $params['parquetPath']."/connections.parquet";

    $afterProcess = (isset($params['afterProcess']))? $params['afterProcess']:'nothing';

    if(!isset($params['ram'])          || $params['ram']=='')            $params['ram'] = '1g';

    if(!isset($params['api_key'],$params['user'])){
        http_response_code(401);
        header("HTTP/1.1 401 Unauthorized");
        header("Location: /401");
        exit;
    }

    // Validating the user
    $api_key = $params['api_key'];
    $user_email = $params['user'];

    if($user = $app->user->where('email',$user_email)->where('api_key',$api_key)->where('valid_til', '>',date("Y-m-d H:i:s"))->get()->first()) {
        $app->sentinel->login($user);
        // Validations
        if(!accessControl("any", ['device.*', 'device.create'])){
            $message['code'] = false;
            $message['msg'] = 'Your account does not have the rights to view logs from devices.';
            return $message;
        }
    }else{
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to view logs from devices.';
        return $message;
    }

    $sparkParams = [
        'master'        => $params['master'],
        'debug'         => $params['debug'],
        'taskID'        => $params['taskID'],
        'mlserver'      => $params['mlserver'],
        'mtserver'      => $params['mtserver'],
        'timezone'      => $params['timezone'],
        'mtuser'        => $params['mtuser'],
        'mtpassword'    => $params['mtpassword'],
        'input'         => $params['path'],
        'tempPath'      => $params['tempPath'],
        'mode'          => $MODE,
        'user'          => $params['user'],
        'ram'           => $params['ram'],
        'parquetPath'   => $params['parquetPath']
    ];

//    $my = fopen("/tmp/error1","a");
//    fwrite($my, print_r($sparkParams, true));

    $csvProcesserLauncher = new CSVProcesser($sparkParams);
    $response = $csvProcesserLauncher->execute();
    return $response;

//    $clusterMode = false;
//    if($clusterMode) {
//        $command = "/opt/Spark/spark/bin/spark-submit --master spark://machineLearning-v1:7077 --class com.paloaltonetworks.tbd.LogCollectorCompacter " .
//            "--deploy-mode client --supervise /var/www/html/OS/spark/packages/LogCoCo-".Module_version_ConvertCSVtoParquet."-SNAPSHOT.jar " .
//            "MLServer=".escapeshellarg($params['mlserver']).", " . "master=".escapeshellarg($params['master']).", " . "debug=".escapeshellarg($params['debug']).", " .
//            "taskID=".escapeshellarg($params['taskID']).", user=".escapeshellarg($params['user']).", ".
//            "dbUser=".escapeshellarg($params['mtuser']).", dbPass=".escapeshellarg($params['mtpassword']).", dbServer=".escapeshellarg($params['mtserver']).", " .
//            "timeZone=".escapeshellarg($params['timezone']).", ".
//            "mode=".escapeshellarg($MODE).", ".
//            "input=".escapeshellcmd($params['path']).", output=".escapeshellarg($OUTPUT);
//    }
//    else {
//        $command = "/opt/Spark/spark/bin/spark-submit --class com.paloaltonetworks.tbd.LogCollectorCompacter --master localhost --deploy-mode client --driver-memory ".$params['ram']." " .
//            "--supervise /var/www/html/OS/spark/packages/LogCoCo-".Module_version_ConvertCSVtoParquet."-SNAPSHOT.jar " .
//            "MLServer=".escapeshellarg($params['mlserver']).", master=".escapeshellarg($params['master']) . ", debug=".escapeshellarg($params['debug']).", ".
//            "taskID=".escapeshellarg($params['taskID']).", user=" . escapeshellarg($params['user']) . ", ".
//            "dbUser=".escapeshellarg($params['mtuser']).", dbPass=".escapeshellarg($params['mtpassword']).", dbServer=".escapeshellarg($params['mtserver']).", ".
//            "timeZone=".escapeshellarg($params['timezone']).", ".
//            "mode=".escapeshellarg($MODE).", ".
//            "input=".escapeshellcmd($params['path']).", output=".escapeshellarg($OUTPUT).", tempFolder=".escapeshellarg($params['tempPath']);
//    }

//    $my = fopen("/tmp/command.spark","a");
//    fwrite($my,"$command\n");
//    fclose($my);
//    $my = fopen("/tmp/error_logCoCo","a");
//    fwrite($my, "\n\n");



    //IF PROCESS IS CORRECT Delete Files / Compress Files / Do nothing
//    $compressCommands = array();
//    $deleteCommands = array();
//    $echoCommands = array();
//    $files = getFilesAndAction(escapeshellcmd($params['path']));
//    foreach ($files as $filePath){
//        //012801096217:9.0.0:/PALogs/myFW/PA220-Mauri63_traffic_2019_07_25_last_calendar_day.csv:0.0029296875:delete
//        $filePathParts = explode(":", $filePath);
//        switch($filePath['afterProcess']){
//            case "Delete":
//                $deleteCommands[] = "rm -f ".$filePath['file']."; ";
//                break;
//            case "Compress":
//                $compressCommands[] = "gzip ".$filePath['file']."; ";
//                break;
//            default:
//                $echoCommands[] = "echo ".$filePath['file']."; ";
//                break;
//        }
//    }
    /*switch($afterProcess) {
        case "Compress":
            $files = getFiles(escapeshellcmd($params['path']));
            if(count($files)>0) {
                $compressCommands = array();
                foreach ($files as $file) {
                    $fileParts= pathinfo($file);
                    if($fileParts['extension']=='csv') {
                        $compressCommands[] = "gzip $file; ";
                    }
                }
                $superCommand = "($command; ".implode(" ",$compressCommands).")>> \"/tmp/error_logCoCo\" 2>>/tmp/error_logCoCo &";
                fwrite($my, $superCommand."\n");
                exec($superCommand);
            }
            break;

        case "Delete":
            $files = getFiles(escapeshellcmd($params['path']));
            if(count($files)>0) {
                $deleteCommands = array();
                foreach ($files as $file) {
                    $deleteCommands[] = "rm -f $file; ";
                }
                $superCommand = "($command; ".implode(" ",$deleteCommands).")>> \"/tmp/error_logCoCo\" 2>>/tmp/error_logCoCo &";
                fwrite($my, $superCommand."\n");
                exec($superCommand);
            }
            break;

        default:
            $files = getFiles(escapeshellcmd($params['path']));

            if(count($files)>0) {
                $echoCommands = array();
                foreach ($files as $file) {
                    $echoCommands[] = "echo $file; ";
                }
                $superCommand = "($command; ".implode(" ",$echoCommands).")>> \"/tmp/error_logCoCo\" 2>>/tmp/error_logCoCo &";
                fwrite($my, $superCommand."\n");
                exec($superCommand);
            }
            else{
                exec("$command >> \"/tmp/error_logCoCo\" 2>>/tmp/error_logCoCo &");
            }
            break;

    }*/

//    $my= fopen("/tmp/command_actions.spark", "a");
//    $superCommand = "($command; ";
//    if(count($deleteCommands)>0)     $superCommand = $superCommand.implode(" ",$deleteCommands);
//    if(count($compressCommands)>0)   $superCommand = $superCommand.implode(" ",$compressCommands);
//    if(count($echoCommands)>0)       $superCommand = $superCommand.implode(" ",$echoCommands);
//    $superCommand = $superCommand.")>> \"/tmp/error_logCoCo\" 2>>/tmp/error_logCoCo &";
//
//    fwrite($my, $superCommand."\n");
//    exec($superCommand);
//    fclose($my);
//
//
//    $message = [
//        'code'  => true,
//        'msg'   => 'Task '.$params['taskID'].' launched'
//    ];
//
//    return $message;
}

function getFiles(STRING $filesArgument):array{
    $filesPath = array();
    // 012801005448:8.1.0b:/PALogs/PaloAltoSC/PA-220/PA-220_traffic_2018_04_16_last_calendar_day.csv:12123234:Delete

    $tuples = explode(",", $filesArgument);
    foreach ($tuples as $tuple){
        $fields = explode(":",$tuple);
        if(isset($fields[2])) {
            $filesPath[] = $fields[2];
        }
    }
    return $filesPath;
}

function getFilesAndAction(STRING $filesArgument):array{
    $filesPath = array();
    // 012801005448:8.1.0b:/PALogs/PaloAltoSC/PA-220/PA-220_traffic_2018_04_16_last_calendar_day.csv:12123234:Delete

    $tuples = explode(",", $filesArgument);
    $i=0;
    foreach ($tuples as $tuple){
        $fields = explode(":",$tuple);
        if(isset($fields[2])) {
            $filesPath[$i]['file'] = $fields[2];
        }
        if(isset($fields[4])) {
            $filesPath[$i]['afterProcess'] = $fields[4];
        }

        $i++;
    }
    return $filesPath;
}

function verifyFileRights(STRING $filePath):bool{
    if (is_writable(dirname($filePath))){
        return true;
    }
    return false;
}