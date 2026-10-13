<?php
/*******************************************************************************
 * Copyright (c) 2020 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: $today.year.hour.minute
 ******************************************************************************/

//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/API/devices/manageKeys.php';
require_once INC_ROOT.'/libs/projectdb.php';
require_once INC_ROOT.'/libs/database.php';
require_once INC_ROOT.'/libs/common/device/SplunkFileLister.php';

use PaloAltoNetworks\Sentinel\Devices\SplunkFileLister;

include_once INC_ROOT.'/libs/PaloAltoNetworks/Middleware/loadCSRFControl.php';

$request_body   = file_get_contents('php://input');
$data           = json_decode($request_body, true);



parse_str(file_get_contents("php://input"),$post_vars);

include INC_ROOT.'/bin/middleware_sanitizer.php';

if(isset($post_vars['type'])){
    $type = $pandb->real_escape_string($post_vars['type']);
}
else {
    $type       = $pandb->real_escape_string((string)(isset($_GET['type']) ? $_GET['type'] : ''));
}
$deviceSerial    = $pandb->real_escape_string((string)(isset($_GET['serial']) ? $_GET['serial'] : ''));
$path            = $pandb->real_escape_string((string)(isset($_GET['path'])   ? $_GET['path']   : null));

if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
}

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        if(is_null($path) || $path == ''){
            $path = null;
        }

        $message = list_SplunkFiles($deviceSerial, $path);
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
        if($post_vars['action']=='generate_queries'){
            $message = setLogFile($post_vars);
            echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        }
        elseif($post_vars['action']=='execute_queries'){
            $message = retrieveLogFile($post_vars);
            echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        }
        else{
            echo json_encode(array('success' => 'false', 'msg' => []));
        }
        break;

    case 'PUT':
        break;

    case 'DELETE':
        $message = removeRequestFile($data);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    default:
        break;
}

function list_SplunkFiles(STRING $serial, STRING $path=null){
    $fileLister = new SplunkFileLister($serial);

    return $fileLister->list_Files();
}

function setLogFile(ARRAY $parameters){
    $serial = $parameters['device'];
    //$SplunkQuery = buildQuery($serial, $parameters['serverIP'], $parameters['serverPort']);
    $start = new DateTime($parameters['startDate']);
    $end = new DateTime($parameters['endDate']);
    $end = $end->modify( '+1 day' );
    $period = new DatePeriod(
        $start,
        new DateInterval('P1D'),
        $end
    );

    $dates = [];
    foreach ($period as $key => $value) {
        $dates[]=$value->format('Y/m/d');
    }

    $fileLister = new SplunkFileLister($serial);
    $response = $fileLister->create($parameters['serverIP'], $parameters['serverPort'], $parameters['user'], $parameters['password'],  $dates, $parameters['csvpath'], $parameters['index'], $parameters['splunkVersion']);
    return [
        'code'  => $response['success'],
        'msg'   => $response
    ];
}

function retrieveLogFile(ARRAY $parameters){
    $serial = $parameters['device'];
    $fileLister = new SplunkFileLister($serial);
    $response = $fileLister->request();

    return [
        'code'  => $response['success'],
        'msg'   => $response['msg']
    ];
}

function removeRequestFile($parameters){
    $serial = $parameters['device_serial'];
    $id = $parameters['id'];
    $fileLister = new SplunkFileLister($serial);
    $response = $fileLister->remove($id);

    return [
        'code'  => $response['success'],
        'msg'   => $response
    ];
}