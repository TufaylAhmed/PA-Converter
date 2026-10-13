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
require_once INC_ROOT.'/userManager/start.php';
require_once INC_ROOT.'/libs/settings/ExpeditionSettingsParameter.php';

include_once INC_ROOT.'/libs/PaloAltoNetworks/Middleware/loadCSRFControl.php';

$request_body   = file_get_contents('php://input');
$data           = json_decode($request_body, true);

require_once INC_ROOT.'/libs/database.php';

parse_str(file_get_contents("php://input"),$post_vars);

include INC_ROOT.'/bin/middleware_sanitizer.php';

if(isset($post_vars['type'])){
    $type = $pandb->real_escape_string($post_vars['type']);
}
else {
    $param       = $pandb->real_escape_string((string)(isset($_GET['param'])         ? $_GET['param'] : ''));
}

if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
}

$knownVariables = ExpeditionSettingsParameter::getDefaults();

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $message = userSettings($knownVariables);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg'], 'total'=>$message['total']));
        break;

    case 'POST':
    case 'PUT':
        $message = updateUserSettings($data, $knownVariables);
        echo json_encode(array('success' => $message['success'], 'msg' => $message['msg'], 'failed'=>$message['failed']));
        break;

    case 'DELETE':
        $message = resetUserSettings($data, $knownVariables);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg'], 'failed'=>$message['failed']));
        break;

    default:
        break;
}

function userSettings(array &$knownVariables){
    $definitions = [];

    if(!accessControl("any", ['user.admin'])){
        return [
            'code' => false,
            'msg' => 'Your account does not rights',
            'total' =>0,
            'success' => false,
            ];
    }

    $userDefinitionsPath = fopen("/home/userSpace/userDefinitions.php","r");

    while (($line = fgets($userDefinitionsPath)) !== false) {
        preg_match('/(.*)define(\s*)\((\s*)(\')(?<variable>.*)(\')(\s*),(.*)/', $line, $output_array);
        if(isset($output_array['variable'])) {
//           echo $output_array['variable']."\n";
           $definitions[$output_array['variable']] = constant($output_array['variable']);
        }
    }

    $printableVairables = [];

    /* @var ExpeditionSettingsParameter $knownVariable */
    foreach ($knownVariables as &$knownVariable){
        if(isset($definitions[$knownVariable->getName()])){
            $knownVariable->setValue($definitions[$knownVariable->getName()]);
            $printableVairables[$knownVariable->getName()] = $definitions[$knownVariable->getName()];
        }
        else{
            $knownVariable->setValue($knownVariable->getDefaultValue());
            $printableVairables[$knownVariable->getName()] = $knownVariable->getDefaultValue();
        }
    }

    //unset($knownVariables['DBPass']);
    $knownVariables = array_values($knownVariables);


    return [
        'code' => true,
        'success'=> true,
        'total' => count($printableVairables),
        'msg' =>$knownVariables,
    ];

}

function updateUserSettings(array $data, array $knownVariables){

    if(!accessControl("any", ['user.admin'])){
        return [
            'failed'  => 'Your account does not rights',
            'msg'     => 'Your account does not rights',
            'success' => false,
        ];
    }

    if(isset($data['name']) && isset($data['value']) && isset($knownVariables[$data['name']]) && $knownVariables[$data['name']]->isModifiable()){
        $response = ExpeditionSettingsParameter::updateVariable($data['name'], $data['value']);
    }

    return [
        'success'   => true,
        'msg'       => $response->message,
        'failed'    => ''
    ];
}

function resetUserSettings(array $data, array $knownVariables){

    if(!accessControl("any", ['user.admin'])){
        return [
            'failed'  => 'Your account does not rights',
            'msg'     => 'Your account does not rights',
            'success' => false,
        ];
    }


    $response = ExpeditionSettingsParameter::resetVariable();

    return [
        'success'   => true,
        'msg'       => $response->message,
        'failed'    => ''
    ];
}
