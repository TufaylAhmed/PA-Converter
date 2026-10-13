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

require_once INC_ROOT.'/libs/common/applications/applications.php';

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
    $hide_shared    = $pandb->real_escape_string((string)(isset($_GET['hide_shared_app'])      ? $_GET['hide_shared_app']: 'false'));
    $page           = $pandb->real_escape_string((string)(isset($_GET['page'])                 ? $_GET['page']: ''));
    $start          = $pandb->real_escape_string((string)(isset($_GET['start'])                ? $_GET['start']: ''));
    $limit          = $pandb->real_escape_string((string)(isset($_GET['limit'])                ? $_GET['limit']: ''));
    $custom_only    = $pandb->real_escape_string((string)(isset($_GET['custom_only'])          ? $_GET['custom_only']: ''));
    $id_app         = $pandb->real_escape_string((string)(isset($_GET['id_app'])               ? $_GET['id_app']: ''));
    $table_name     = $pandb->real_escape_string((string)(isset($_GET['table_name'])           ? $_GET['table_name']: ''));

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
        'limit'         => $limit,
        'custom_only'   => $custom_only,
        'id_app'        => $id_app,
        'table_name'    => $table_name
    ];
}

if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
}

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $message = list_applications($params);
        if($message['code']) {
            echo json_encode(array('total' => $message['count'], 'applications' => $message['msg']));
        }
        else{
            echo '{"total":"0","applications":[]}';
        }
        break;

    case 'POST':

        $message = add_application($data);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    case 'PUT':
        $message = update_applications($data);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;


    case 'DELETE':

        $message = delete_app($data);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    default:
        break;
}

function list_applications(ARRAY $params){
    $project = $params['project'];

    if(!accessControl("any", ['projectRole.'.$project.'.view'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to view this project contents';
        return $message;
    }

    switch ($params['mode']){
        case 'applications':
            $message = get_applications($params);
            break;

        case 'applications_signatures':
            $message = get_applications_signatures($params);
            break;

        default:
            break;
    }

    return $message;

}


function add_application(ARRAY $params){

    $project = $params['project'];

    if(!accessControl("any", ['projectRole.'.$project.'.view'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to view this project contents';
        return $message;
    }

    switch ($params['mode']){
        case 'applications':
            $message = register_applications($params);
            //echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
            break;

        case 'applications_signatures':
            $message = register_applications_signature($params);
            //echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
            break;

        default:
            break;
    }

    return ['code' => $message['code'], 'msg' => $message['msg']

    ];

}


function delete_app(ARRAY $params){

    $project = $params['project'];

    if(!accessControl("any", ['projectRole.'.$project.'.view'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to view this project contents';
        return $message;
    }

    switch ($params['mode']){

        case 'applications':
            $message = delete_applications($params);
            echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
            break;

        case 'applications_signatures':
            $message = delete_applications_signatures($params);
            echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
            break;

        default:
            break;
    }


    return $message;

}

