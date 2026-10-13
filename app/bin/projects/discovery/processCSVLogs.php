<?php
/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: 2017-07-10 09:05
 ******************************************************************************/

//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';

require_once INC_ROOT.'/libs/database.php';
require_once INC_ROOT.'/libs/shared.php';
require_once INC_ROOT.'/libs/settings/ML_Settings.php';
require_once INC_ROOT.'/userManager/API/projects/manageDevices.php';
require_once '/home/userSpace/environmentParameters.php';

require_once INC_ROOT.'/libs/common/device/CsvFilesProcesser.php';

use \PaloAltoNetworks\Sentinel\Devices\CsvFilesProcesser;

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

        $parameters = array();
        $parameters['devices'][] = [
            'serial' => isset($post_vars['device']) ? $post_vars['device'] : '',
            'afterProcess'  =>isset($post_vars['afterProcess']) ? $post_vars['afterProcess'] : null,
        ];
        $parameters['mode'] =  isset($post_vars['mode']) ? $post_vars['mode'] : 'false';
        $parameters['pathOverride'] = isset($post_vars['path']) ? $post_vars['path'] : null;

        $message = processCSVLogs($parameters);

        if($message->getSuccess()) {
            echo json_encode(array('success' => true, 'jobid' => $message->getCode()));
        }
        else{
            echo json_encode(array('success' => false, 'jobid' => 0, 'msg' => $message->getMessagesString()));
        }
        break;

    case 'GET':
    case 'PUT':
    case 'DELETE':
    default:
        echo json_encode(array('success' => false, 'msg' => $_SERVER['REQUEST_METHOD'].' Method not implemented'));
        break;
}

function processCSVLogs(ARRAY $parameters){
    $project = isset($parameters['project'])? $parameters['project']:'';

    //Verify that the SparkRAM is defined.
    if(!defined('SparkRAM')){
        define('SparkRAM','1024m');
    }

    $csvProcesser = new CsvFilesProcesser($project, SparkRAM, json_encode($parameters));

    return $csvProcesser->processCSVLogs();
}

