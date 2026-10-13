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
require_once INC_ROOT.'/libs/xmlapi.php';
require_once INC_ROOT.'/libs/projectdb.php';
require_once INC_ROOT.'/libs/database.php';

$request_body   = file_get_contents('php://input');
$data           = json_decode($request_body, true);

parse_str(file_get_contents("php://input"),$post_vars);

include INC_ROOT.'/bin/middleware_sanitizer.php';

if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
}

$projectName    = $pandb->real_escape_string((string)(isset($_GET['project'])      ? $_GET['project']: ''));
$source         = $pandb->real_escape_string((string)(isset($_GET['source'])       ? $_GET['source']: ''));
$vsys           = $pandb->real_escape_string((string)(isset($_GET['vsys'])         ? $_GET['vsys']: ''));
$template       = $pandb->real_escape_string((string)(isset($_GET['template'])     ? $_GET['template']: ''));
$page           = $pandb->real_escape_string((string)(isset($_GET['page'])         ? $_GET['page']: ''));
$limit          = $pandb->real_escape_string((string)(isset($_GET['limit'])        ? $_GET['limit']: ''));
$start          = $pandb->real_escape_string((string)(isset($_GET['start'])        ? $_GET['start']: ''));

$params = [
    'projectName'   => $projectName,
    'source'=>$source,
    'vsys'=>$vsys,
    'template'=>$template,
    'page'=>$page,
    'limit'=>$limit,
    'start'=>$start
];
switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $message = list_dnsproxy($params);
        if($message['code']) {
            $totalTags = $message['total'];
            echo json_encode(array('total' => $totalTags, 'dnsproxy' => $message['msg']));
        }
        else{
            echo '{"total":"0","dnsproxy":[]}';
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

function list_dnsproxy(ARRAY $params){
    $tags = array();
    $projectdb = selectDatabase($params['projectName']);
    $source = (isset($params['source']) && $params['source']!='') ? mysqli_real_escape_string($projectdb, $params['source']) : '';
    $vsys   = (isset($params['vsys']) && $params['vsys']!='') ? mysqli_real_escape_string($projectdb, $params['vsys']): 'all';
    $template   = (isset($params['template']) && $params['template']!='') ? mysqli_real_escape_string($projectdb, $params['template']): 'all';
    $start  = mysqli_real_escape_string($projectdb, $params['start']);
    $limit  = mysqli_real_escape_string($projectdb, $params['limit']);
    if($vsys != 'all'){
        $conditions[] = " vsys IN ('$vsys', 'shared') ";
    } else {
        $conditions[] = " 1=1 ";
    }

    $results=$projectdb->query("SELECT name,source,vsys,template FROM dns_proxy WHERE ".implode(" AND ",$conditions) ." AND template='$template' AND source='$source';");
    if ($results->num_rows>0){
        $tags[]=array("name"=>"None","id"=>0);
        while ($data = $results->fetch_assoc() ){
            $tags[] = $data;
        }
    }


    $message = array();
    $message['code']=true;
    $message['msg'] = $tags;
    $message['total']=count($tags);
    return $message;

}