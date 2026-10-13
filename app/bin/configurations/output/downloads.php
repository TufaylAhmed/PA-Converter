<?php
# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.

//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

//User management control
require_once INC_ROOT.'/userManager/start.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';

$request_body   = file_get_contents('php://input');
$data           = json_decode($request_body, true);

parse_str(file_get_contents("php://input"),$post_vars);

include INC_ROOT.'/bin/middleware_sanitizer.php';

if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
}

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $data["project"]=check_sanitize($_GET['project']);
        $message = list_Downloads($data);
        if($message['code']) {
            $totalDownloads = count($message['msg']);
            echo json_encode(array('total' => $totalDownloads, 'downloads' => $message['msg']));
        }
        else{
            echo '{"total":"0","downloads":[]}';
        }
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

function list_Downloads($data){
    $project= check_sanitize($data['project']);

    if(!checkProjectRights($project,'view')){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to see this project contents';
//        echo json_encode($message);
        return $message;
    }

    $path = USERSPACE_PATH."/projects/" . $project . "/";
    $message=array();
    $dirrule = opendir($path);
    $files = array();
    while ($config_filename = readdir($dirrule)) {
        if (preg_match("/^MT/", $config_filename)) {

            $file_parts = pathinfo($config_filename);
            $decryptedFilename = $file_parts['filename'];
            $file_parts = pathinfo($decryptedFilename);
            switch($file_parts['extension'])
            {
                case "xml":
                    $mode="xml";
                    break;

                case "txt":
                    $mode="txt";
                    break;
                case "zip":
                    $mode="zip";
                    break;
                default:
                    $mode="xml";
                    break;
            }


            $config_path = $path . $config_filename;
            $filename = $config_filename;
            if (!is_dir($path.$filename)){
                $length=human_filesize(filesize($path.$filename));
                $date=date ("F d Y H:i:s.", filemtime($path.$filename));
            }
            $files[]=array("name"=>$decryptedFilename,"filename"=>$config_path,"length"=>$length,"date"=>$date,"mode"=>$mode);
        }
    }
    $message['msg'] = $files;
    $message['code']=true;
    return $message;

}

function human_filesize($bytes, $decimals = 2) {
    $sz = 'BKMGTP';
    $factor = floor((strlen($bytes) - 1) / 3);
    return sprintf("%.{$decimals}f", $bytes / pow(1024, $factor)) . @$sz[$factor];
}