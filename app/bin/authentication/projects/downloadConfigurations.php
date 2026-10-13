<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 13/6/16 - 13:19
 */


//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

//require_once INC_ROOT.'/bin/Authentication.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';

require_once INC_ROOT.'/libs/database.php';
require_once INC_ROOT.'/libs/shared.php';
require_once INC_ROOT.'/libs/xmlapi.php';
require_once INC_ROOT.'/bin/messaging/MessageSender.php';

require_once INC_ROOT.'/libs/Security/OpenSSLTools.php';

//include_once INC_ROOT.'/libs/PaloAltoNetworks/Middleware/loadCSRFControl.php';

use PaloAltoNetworks\Expedition\Security\OpenSSLTools;

if(defined('CLI')){
    require_once INC_ROOT .'/userManager/API/accessControl_CLI.php';
}
else{
    require_once INC_ROOT .'/userManager/API/accessControl.php';
}

$request_body   = file_get_contents('php://input');
$data           = json_decode($request_body, true);

parse_str(file_get_contents("php://input"),$post_vars);

include INC_ROOT.'/bin/middleware_sanitizer.php';

if(isset($post_vars['type'])){
    $type = $pandb->real_escape_string($post_vars['type']);
}
else {
    $project    = $pandb->real_escape_string((string)(isset($_GET['project'])      ? $_GET['project'] : ''));
    $mode       = $pandb->real_escape_string((string)(isset($_GET['mode'])         ? $_GET['mode'] : ''));
    $configfile = $pandb->real_escape_string((string)(isset($_GET['configfile'])   ? $_GET['configfile'] : ''));
    $jobID      = $pandb->real_escape_string((string)(isset($_GET['jobID'])        ? $_GET['jobID'] : ''));
}

if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
}

if(!checkProjectRights($project,'view')){
    echo json_encode([
            "success" => true,
            "code"  => -1,
            "msg"   => "You do not have rights to see this project content",
        ]
    );
    return;
}

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
    case 'POST':
        downloadFile($project,$configfile, $mode);
        break;

    default:
        break;
}

function downloadFile($project,$configfile, $mode){
    global $app;
//    $user = $app->container->sentinel->getUser();

    //Control CSRF on some specific POST calls via a second CRF control function. Notice that in this specific case, the CSRF token was sent via GET
    include INC_ROOT . '/libs/PaloAltoNetworks/Middleware/loadCSRFControl_fromPOST.php';
    checkCSRF($_GET);

    $projectObj = $app->project->where("name", $project)->first();
    $keyObj = $app->accessKey->where("type", "project")->where("lid", $projectObj->id)->first();
    $encryptor = new OpenSSLTools($keyObj->key, $keyObj->iv);

    if(!accessControl("any", ['project.admin','projectRole.'.$project.'.*'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'You do not have rights to download this file';
        return $message;
    }
    if ($mode=="xml"){
        $buffer = "<?xml version=\"1.0\"?>\n";
        if(preg_match(ValidFileName, $configfile, $output_array)) {
            $configfilewithoutExt = preg_replace('/\\.[^.\\s]{1,5}$/', '', $configfile);

            $filePath = USERSPACE_PATH.'/projects/'.$project.'/'.$configfilewithoutExt.'.xml.dat';
            error_reporting(0 | E_PARSE);
            if ($content = $encryptor->decryptFromFile($filePath)){
                $buffer = $buffer . $content;
            }
            header("Content-type: application/xml; charset=\"utf-8\"");
            header("Content-Length: " . strlen($buffer));
            header('Content-Disposition:attachment; filename="'.$configfilewithoutExt.'.xml"');
        }
    }
    elseif ($mode=="zip"){
        $buffer="";
        if(preg_match(ValidFileName, $configfile, $output_array)) {
            $configfilewithoutExt = preg_replace('/\\.[^.\\s]{1,5}$/', '', $configfile);

            $filePath = USERSPACE_PATH.'/projects/'.$project.'/'.$configfilewithoutExt.'.zip.dat';
            error_reporting(0 | E_PARSE);
            if ($content = $encryptor->decryptFromFile($filePath)){
                $buffer = $buffer . $content;
            }
            header("Content-type: application/zip; charset=\"utf-8\"");
            header("Content-Length: " . strlen($buffer));
            header('Content-Disposition:attachment; filename="'.$configfilewithoutExt.'.zip"');
        }
    }
    elseif($mode=="txt"){
        $buffer = "";
        if(preg_match(ValidFileName, $configfile, $output_array)) {
            $configfilewithoutExt = preg_replace('/\\.[^.\\s]{1,5}$/', '', $configfile);

            $filePath = USERSPACE_PATH.'/projects/'.$project.'/'.$configfilewithoutExt.'.txt.dat';
            error_reporting(0 | E_PARSE);
            if ($content = $encryptor->decryptFromFile($filePath)){
                $buffer = $buffer . $content;
            }
            header("Content-type: text/plain; charset=\"utf-8\"");
            header("Content-Length: " . strlen($buffer));
            header('Content-Disposition:attachment; filename="'.$configfilewithoutExt.'.txt"');
        }
    }
    elseif($mode=="export"){
        $buffer="";
        if (file_exists(USERSPACE_PATH."/projects/".$project."/EX-".$project.".zip")){

            $buffer=file_get_contents(USERSPACE_PATH."/projects/".$project."/EX-".$project.".zip");
            unlink(USERSPACE_PATH."/projects/".$project."/EX-".$project.".zip");
            header("Content-type: application/zip; charset=\"utf-8\"");
            header("Content-Length: " . strlen($buffer));
            header('Content-Disposition:attachment; filename="EX-'.$project.'.zip"');
        }
    }
    print($buffer);
    error_reporting(E_ALL ^ E_WARNING | E_PARSE);
}