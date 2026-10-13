<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 12/7/16 - 14:42
 */
//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';

require_once INC_ROOT.'/userManager/API/devices/list.php';

require_once INC_ROOT.'/libs/shared.php';
require_once INC_ROOT.'/libs/projectdb.php';
require_once INC_ROOT.'/libs/database.php';

$request_body   = file_get_contents('php://input');
$data           = json_decode($request_body, true);

parse_str(file_get_contents("php://input"),$post_vars);

include INC_ROOT.'/bin/middleware_sanitizer.php';
global $pandb;

if(isset($post_vars['type'])){
    $type = $post_vars['type'];
}
else {
    $type           = $pandb->real_escape_string((string)(isset($_GET['type'])         ? $_GET['type'] : ''));
    $projectName    = $pandb->real_escape_string((string)(isset($_GET['project'])      ? $_GET['project']: ''));
    $action         = $pandb->real_escape_string((string)(isset($_GET['action'])       ? $_GET['action']: ''));
    $source         = $pandb->real_escape_string((string)(isset($_GET['source'])       ? $_GET['source']: ''));
    $vsys           = $pandb->real_escape_string((string)(isset($_GET['vsys'])         ? $_GET['vsys']: ''));
    $table_name     = $pandb->real_escape_string((string)(isset($_GET['table_name'])   ? $_GET['table_name']: ''));
    $id             = $pandb->real_escape_string((string)(isset($_GET['id'])           ? $_GET['id']: ''));
    $page           = $pandb->real_escape_string((string)(isset($_GET['page'])         ? $_GET['page']: ''));
    $limit          = $pandb->real_escape_string((string)(isset($_GET['limit'])        ? $_GET['limit']: ''));

    $params = [
        'type'  => $type,
        'projectName'   => $projectName,
        'source'=>$source,
        'vsys'=>$vsys,
        'table_name'=>$table_name,
        'id'=>$id,
        'page'=>$page,
        'limit'=>$limit,
        'action'=>$action
    ];}

if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
}

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        switch($action){
            case 'vsysbysource':
                $message = list_tag($params);
                if($message['code']) {
                    $totalDevices = count($message['msg']);
                    echo json_encode(array('total' => $totalDevices, 'rows' => $message['msg']));
                }
                else{
                    echo '{"total":"0","address":[]}';
                }
                break;
            case 'get_dg_devices':
                $message = list_tag($params);
                if($message['code']) {
                    $totalDevices = count($message['msg']);
                    echo json_encode(array('total' => $totalDevices, 'rows' => $message['msg']));
                }
                else{
                    echo '{"total":"0","address":[]}';
                }
                break;
        }


    case 'POST':
        $message = register_Device($data);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    case 'PUT':
        $message = update_Device($data);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    case 'DELETE':
        $message = delete_Device($data);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    default:
        break;
}

function list_tag(ARRAY $params){
    $tags = array();
    $projectdb = selectDatabase($params['projectName']);
    $conditions = array();
    $source = mysqli_real_escape_string($projectdb, $params['source']);
    $vsys   = mysqli_real_escape_string($projectdb, $params['vsys']);
    if(!isset($params['scope'])){
        $scope ='and_shared';
    }
    else {
        $scope = mysqli_real_escape_string($projectdb, $params['scope']);
    }

    $conditions[]=" source='$source'";
    if($scope!='local') {
        $conditions[] = " vsys IN ('$vsys', 'shared')";
    }
    else{
        $conditions[] = " vsys='$vsys'";
    }

    $relations = false;

    if($params['id'] !='') {
        $conditions[]="   member_lid = '".mysqli_real_escape_string($projectdb, $params['id'])."'";
        $relations= true;
    }
    if($params['table_name']!='') {
        $conditions[]="   table_name = '".mysqli_real_escape_string($projectdb, $params['table_name'])."'";
        $relations= true;
    }

    $query = "SELECT tag.* ";
    if($relations){
        $query .= "              FROM tag, tag_relations
                   WHERE ".implode(' AND ',$conditions)." AND tag.id = tag_relations.tag_id GROUP BY id";
    }
    else{
        $query .= " FROM tag WHERE ".implode(' AND ',$conditions)." GROUP BY id";
    }

    $results= $projectdb->query($query);

    while ($data = $results->fetch_assoc() ){
        $tags[] = $data;
    }

    $message = array();
    $message['code']=true;
    $message['msg'] = $tags;
    return $message;

}

