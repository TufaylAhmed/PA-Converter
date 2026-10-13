<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by alejandradevegamir
 * Date: 23/1/17 - 11:00
 */
//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';

require_once INC_ROOT.'/libs/shared.php';
require_once INC_ROOT.'/libs/projectdb.php';

require_once INC_ROOT.'/libs/sanitize.php';

require_once INC_ROOT.'/libs/common/services/services.php';

if(defined('CLI')){
    require_once INC_ROOT .'/userManager/API/accessControl_CLI.php';
}
else{
    require_once INC_ROOT .'/userManager/API/accessControl.php';
}

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
    $mode           = $pandb->real_escape_string((string)(isset($_GET['mode'])                 ? $_GET['mode'] : ''));
    $projectName    = $pandb->real_escape_string((string)(isset($_GET['project'])              ? $_GET['project']: ''));
    $source         = $pandb->real_escape_string((string)(isset($_GET['source'])               ? $_GET['source']: ''));
    $vsys           = $pandb->real_escape_string((string)(isset($_GET['vsys'])                 ? $_GET['vsys']: ''));
    $objsearch      = $pandb->real_escape_string((string)(isset($_GET['objsearch'])            ? $_GET['objsearch']: ''));
    $objfilter      = $pandb->real_escape_string((string)(isset($_GET['objfilter'])            ? $_GET['objfilter']: 'none'));
    $hide_shared    = $pandb->real_escape_string((string)(isset($_GET['hide_shared_address'])  ? $_GET['hide_shared_address']: 'false'));
    $page           = $pandb->real_escape_string((string)(isset($_GET['page'])                 ? $_GET['page']: ''));
    $start          = $pandb->real_escape_string((string)(isset($_GET['start'])                ? $_GET['start']: ''));
    $limit          = $pandb->real_escape_string((string)(isset($_GET['limit'])                ? $_GET['limit']: ''));

    $params = [
        'mode'          => $mode,
        'project'       => $projectName,
        'source'        => $source,
        'vsys'          => $vsys,
        'objfilter'     => $objfilter,
        'objsearch'     => $objsearch,
        'hide_shared'   => $hide_shared,
        'start'         => $start,
        'page'          => $page,
        'limit'         => $limit
    ];
}

if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
}

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $message = list_services($params);
        if($message['code']) {
            echo json_encode(array('total' => $message['count'], 'services' => $message['msg']));
        }
        else{
            echo '{"total":"0","services":[]}';
        }
        break;

    case 'POST':
        $message = register_services($data);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    case 'PUT':
        $message = update_services($data);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    case 'DELETE':
        $message = delete_services($data);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    default:
        break;
}

function list_services(ARRAY $params){
    $project = $params['project'];

    if(!accessControl("any", ['projectRole.'.$project.'.view'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to view this project contents';
        return $message;
    }

    switch ($params['mode']){
        case 'services':
            $message = get_services($params);
            break;

        default:
            break;
    }

    return $message;

}

