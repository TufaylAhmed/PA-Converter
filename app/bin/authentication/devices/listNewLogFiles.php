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

require_once INC_ROOT.'/libs/projectdb.php';
require_once INC_ROOT.'/libs/database.php';

require_once INC_ROOT.'/libs/common/device/CsvFilesLister.php';
require_once INC_ROOT.'/libs/common/device/CsvFilesProcesser.php';

use \PaloAltoNetworks\Sentinel\Devices\CsvFilesLister;
use \PaloAltoNetworks\Sentinel\Devices\CsvFilesProcesser;

include_once INC_ROOT.'/libs/PaloAltoNetworks/Middleware/loadCSRFControl.php';

$request_body   = file_get_contents('php://input');
$data           = json_decode($request_body, true);


parse_str(file_get_contents("php://input"),$post_vars);

include INC_ROOT.'/bin/middleware_sanitizer.php';

if(isset($post_vars['type'])){
    $type = $pandb->real_escape_string($post_vars['type']);
}
else {
    $type       = (string)(isset($_GET['type']) ? $_GET['type'] : '');
    $type = $pandb->real_escape_string($type);
}
$deviceSerial    = (string)(isset($_GET['serial']) ? $_GET['serial'] : '');
$path            = (string)(isset($_GET['path'])   ? $_GET['path']   : '');

$deviceSerial = $pandb->real_escape_string($deviceSerial);
$path = $pandb->real_escape_string($path);

if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
}

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        if(is_null($path) || $path == ''){
            $path = null;
        }

        $message = list_NewLogFiles();
        if($message['code']) {
            echo json_encode([
                'totalProcessableDevices' => count($message['newFiles']),
                "serials"   => $message['serials'],
                "fwnames"   => $message['fwnames'],
                'news'      => $message['newFiles'],

            ]);
        }
        else{
            echo '{"total":"0","files":[]}';
        }
        break;

    case 'POST':
        $message = processNewLogFiles($post_vars);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    case 'PUT':
    case 'DELETE':
    default:
        echo json_encode(array('success' => false, 'msg' => $_SERVER['REQUEST_METHOD'].' Method not implemented'));
        break;
}


function list_NewLogFiles(){
    global $app;

    if(!accessControl("any", ['device.*', 'device.create'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to view logs from devices';
        return $message;
    }

    if (!$devicesObj = $app->device->where('logtype','=','csv')->get())
    {
        return [
            "code"  => true,
            "msg" => []
        ];
    }

    $newFiles = array();
    $serials = array();
    $fwnames = array();
    foreach ($devicesObj as $deviceObj){
        $filesLister = new CsvFilesLister($deviceObj->serial);
        $files = $filesLister->list_LogFiles();
        if(count($files['news'])>0) {
            $newFiles[$deviceObj->serial]['total'] = count($files['news']);
            $newFiles[$deviceObj->serial]['csvfiles'] = $files['news'];
            $serials[] = $deviceObj->serial;
            $fwnames[] = $deviceObj->devicename;
        }
    }

    return [
        "code"      => true,
        "serials"   => $serials,
        "fwnames"   => $fwnames,
        "newFiles"  => $newFiles
    ];
}

/***
 * @param array $serials
 * @return array
 */
function processNewLogFiles(ARRAY $data){
    global $app;

    $serial = isset($data['serials'])? $data['serials']: '';
    $serials = explode(",", $serial);

    if(count($serials)==0) {
        return [
            "code" => true,
            "msg" => []
        ];
    }



    $parameters = array();
    foreach ($serials as $serial){
        if ($device = $app->device->where('serial', '=', $serial)
            ->where(function ($query) {
                $query->where('logtype', '=', 'csv')
                    ->orWhere('logtype', '=', '');
            })
            ->get()->first()) {
            $parameters['devices'][] = [
                'serial' => $serial,
                'afterProcess' => $device->afterprocess,
                'mode' => 'false',
                'pathOverride'=> null
            ];
        }
    }

    $data = array();
    if(!defined('SparkRAM')){
        define('SparkRAM','1024m');
    }
    if(count($parameters)>0) {
        $csvProcesser = new CsvFilesProcesser('', SparkRAM, json_encode($parameters));
        $data[] = $csvProcesser->processCSVLogs()->toString();
    }
    else{
        $data = [];
    }

    return [
        "code" => true,
        "msg" => $data
    ];
}
