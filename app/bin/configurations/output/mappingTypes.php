<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 12/9/16 - 16:15
 */
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

//User management control
require_once INC_ROOT.'/userManager/start.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';

require_once INC_ROOT.'/libs/shared.php';
require_once INC_ROOT.'/libs/database.php';
require_once INC_ROOT.'/libs/xmlapi.php';
require_once INC_ROOT.'/libs/projectdb.php';

$request_body   = file_get_contents('php://input');
$data           = json_decode($request_body, true);

parse_str(file_get_contents("php://input"),$post_vars);

include INC_ROOT.'/bin/middleware_sanitizer.php';

if(isset($post_vars['type'])){
    $type = $post_vars['type'];
}
else {
    $type       = (string)(isset($_GET['type']) ? $_GET['type'] : '');
}
$project        = (string) (isset($_GET['project'])   ? $_GET['project'] : '');

if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
}

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $message = get_groups($project);

        if($message['code']){
            echo json_encode(["total" => count($message['msg']), "rows"  => $message['msg'], ]);
        }
        else{
            echo json_encode([ "total" => 0, "rows"  => '',]);
        }
        break;

    case 'POST':
        $data = ['project'=>$_POST['project'], 'modified'=>$_POST['modified'], 'api_call' => $_POST['api_call']];
//        $message = generate_api_calls($data);
//        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    case 'PUT':
//        $message = update_Key($devicename, $data);
//        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    case 'DELETE':
        $message = remove_request($project, $data);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    default:
        break;
}


function get_groups(String $project){
    global $projectdb;

    $projectdb = selectDatabase($project);
    $myData[0] = array("name" => "All", "description"=>"All");
    $getCalls = $projectdb->query("SELECT table_name as name FROM output_mapping GROUP BY table_name ORDER BY table_name;");
    $count = $getCalls->num_rows;
    if ($count > 0) {

        while ($data = $getCalls->fetch_object()) {
            $data->description = getDescription($data->name);
            $myData[] = $data;
        }
    }
    $message = array();
    $message['code'] = true;
    $message['msg'] = $myData;
    return $message;
//    echo '{"total":"' . $count . '","rows":' . json_encode($myData) . '}';
}

function getDescription($name){
    switch ($name){
        default:
            return ucfirst(str_replace('_', ' ', $name));
    }
}