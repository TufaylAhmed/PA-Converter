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

//require_once INC_ROOT.'/bin/Authentication.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/API/devices/manageKeys.php';
require_once INC_ROOT.'/libs/projectdb.php';
require_once INC_ROOT.'/libs/database.php';

require_once INC_ROOT.'/libs/common/device/CsvFilesLister.php';

use PaloAltoNetworks\Sentinel\Devices\CsvFilesLister;

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
$path            = (string)(isset($_GET['path'])   ? $_GET['path']   : null);

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

        $message = list_LogFiles($deviceSerial, $path);
        if($message['code']) {
            $totalDevices = count($message['msg']);
            echo json_encode([
                'total'         => $totalDevices,
                'files'         => $message['msg'],
                'news'          => $message['news'],
                'totalNews'     => count($message['news']),
                'processed'     => $message['processed'],
                'totalProcessed'=> count($message['processed']),
                'ignored'       => $message['ignored'],
                'totalIgnored'  => count($message['ignored']),
                'errorMessage'  => $message['errorMessage'],
                'errorCode'     => $message['code']
            ]);
        }
        else{
            echo '{"total":"0","files":[]}';
        }
        break;

    case 'POST':
        $message = setLogFile($post_vars);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    case 'PUT':
        break;

    case 'DELETE':
        $message = ignoreLogFile($post_vars);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    default:
        break;
}

function list_LogFiles(STRING $serial, STRING $path=null){
    $fileLister = new CsvFilesLister($serial, $path);

    return $fileLister->list_LogFiles();
}

function setLogFile(ARRAY $data){
    return setStateLogFile($data, PROCESS);
}

function ignoreLogFile(ARRAY $data){
    return setStateLogFile($data, IGNORE);
}

function setStateLogFile($data, $status){
    $fileLister = new CsvFilesLister($data['serial']);

    return $fileLister->setStateLogFile($data['serial'], $data['files'], $status);
}
