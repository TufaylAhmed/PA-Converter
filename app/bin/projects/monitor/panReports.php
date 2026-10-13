<?php
# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
//Loads all global PHP definitions
require_once '/var/www/html/libs/common/definitions.php';
//Dependencies
require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';
require_once INC_ROOT.'/libs/database.php';
require_once INC_ROOT.'/libs/shared.php';
require_once INC_ROOT.'/libs/projectdb.php';

if(defined('CLI')){
    require_once INC_ROOT .'/userManager/API/accessControl_CLI.php';
}
else{
    require_once INC_ROOT .'/userManager/API/accessControl.php';
}

$request_body   = file_get_contents('php://input');
$data           = json_decode($request_body, true);

ini_set('max_execution_time', PARSER_max_execution_time);
ini_set("memory_limit", PARSER_max_execution_memory);

include INC_ROOT.'/bin/middleware_sanitizer.php';

if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
}


switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $project    = $pandb->real_escape_string((string)  (isset($_GET['project'])    ? $_GET['project'] : ''));
        $data['project']=$project;

        $message = list_panReports($data);
        if($message['code']) {
            echo json_encode(array('total' => $message['count'], 'reports' => $message['msg']));
        }
        else{
            echo '{"total":"0","reports":[]}';
        }
        break;
    case 'DELETE':
        $message = delete_panReports($data);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;
    default:
        echo '{"total":"0","reports":[]}';
        break;
}

function list_panReports(ARRAY $params){
    global $projectdb;
    $projectdb = selectDatabase($params['project']);
    $project = mysqli_real_escape_string($projectdb, $params['project']);

    if(!accessControl("any", ['projectRole.'.$project.'.view'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to view this project contents';
        return $message;
    }

    $conditions=generate_query_multitable("objects");

    $getAll = $projectdb->query("SELECT count(*) as total FROM reports a $conditions;");
    $row = $getAll->fetch_assoc();
    $count = $row['total'];
    if ($count > 0) {
        $getLimit = $projectdb->query("SELECT * FROM reports a $conditions ORDER BY name ;");
    }
    if (isset($getLimit)) {
        if ($getAll->num_rows > 0){

            while ($data = $getLimit->fetch_object()) {
                $myData[] = $data;
            }
        }
    }
    if ($count == 0) {
        $myData = array();
    }
    $message = array();
    $message['code'] = true;
    $message['count'] = $count;
    $message['msg'] = $myData;
    //print_r($myData);
    return $message;

}

function delete_panReports(ARRAY $data){
    $project = $data['project'];

    take_snapshot_last($project);

    if(!accessControl("any", ['projectRole.'.$project.'.update'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to edit this project contents';
        return $message;
    }

    $projectdb = selectDatabase($project);

    $remove_references = $data['remove_references'];
    $ids = mysqli_real_escape_string($projectdb, $data['ids']);

    $projectdb->query("DELETE FROM reports WHERE id IN (".$ids.") AND dummy = 0;");

    $message = array();
    $message['code'] = true;
    $message['msg'] = '';
    return $message;

}
