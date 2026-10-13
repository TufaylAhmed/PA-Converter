<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 13/5/16 - 15:28
 */
//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';

require_once INC_ROOT.'/libs/database.php';

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
        $project = $pandb->real_escape_string((string)(isset($_GET['project']) ? $_GET['project']: ''));


        $message = read_ironSkillet($project);
        if($message['code']) {
            echo json_encode(array('total' => $message['count'], 'ironskillet' => $message['msg']));
        }
        else{
            echo '{"total":"0","ironskillet":[]}';
        }
        break;

    case 'POST':
//        $message = create_ironSkillet($data);
//        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    case 'PUT':
        $message['code']=true;
        $message['msg']="Invalid Method";
        break;

    case 'DELETE':
        $message['code']=true;
        $message['msg']="Invalid Method";
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    default:
        break;
}



function read_ironSkillet($project){

    if(!accessControl("any", ['projectRole.'.$project.'.view'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to view this project contents';
        return $message;
    }

    $message=array();
    $message['code']=false;
    $message['count']=0;
    $message['msg']=array();

    $path = USERSPACE_PATH."/projects/" . $project . "/toImport/iron-skillet_vars.txt";

    if (file_exists($path)){
        $data=file_get_contents($path);
        $message['code']=true;
        $message['count']=1;
        $message['msg'][]=json_decode($data,true);
    }

    return $message;

}



