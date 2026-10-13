<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 14/6/16 - 13:50
 */

//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

//require_once INC_ROOT.'/bin/Authentication.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';
require_once INC_ROOT.'/libs/settings/PackageVersionChecker.php';

//use PackageVersionChecker;


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

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $message = getSettings($param);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    case 'POST':
        break;

    case 'PUT':
        break;

    case 'DELETE':
        break;

    default:
        break;
}

function getSettings(STRING $param){
    global $app;

    $message = array();
    $message['code'] = true;
    $message['msg'] = '';
    
    switch($param){
        case "sessionCheckFreq":
            $message['msg'] = $app->config->get('session.checkFreqInSec')*1000;
            break;

        case "versions":
            $packageVersionChecker = new PackageVersionChecker();
            $message['msg'] = $packageVersionChecker->getVersions();
            break;

        case "ExpeditionVersion":
            $packageVersionChecker = new PackageVersionChecker();
            $message['msg'] = $packageVersionChecker->getExpeditionVersion();
            break;

        case "MLversion":
            $packageVersionChecker = new PackageVersionChecker();
            $message['msg'] = $packageVersionChecker->getExepditionMLDependenciesVersion();
            break;

        case "ExpeditionDate":
            $packageVersionChecker = new PackageVersionChecker();
            $message['msg'] = $packageVersionChecker->getExpeditionDate();
            break;

        default:
            break;

    }

    return $message;
}