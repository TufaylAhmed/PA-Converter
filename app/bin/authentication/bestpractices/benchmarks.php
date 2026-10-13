<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 12/6/16 - 12:33
 */
//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';
require_once INC_ROOT.'/libs/projectdb.php';
require_once INC_ROOT.'/libs/database.php';
require_once INC_ROOT .'/userManager/API/accessControl.php';
require_once INC_ROOT.'/libs/common/bestpractices/bestpractices.php';

include_once INC_ROOT.'/libs/PaloAltoNetworks/Middleware/loadCSRFControl.php';

$request_body   = file_get_contents('php://input');
$data           = json_decode($request_body, true);

parse_str(file_get_contents("php://input"),$post_vars);

include INC_ROOT.'/bin/middleware_sanitizer.php';

if(isset($post_vars['type'])){
    $type = $bestPracticesdb->real_escape_string($post_vars['type']);
}
else {
    $mode           = (string)(isset($_GET['mode'])                 ? $_GET['mode'] : '');
    $projectName    = (string)(isset($_GET['project'])              ? $_GET['project']: '');
    $source         = (string)(isset($_GET['source'])               ? $_GET['source']: '');
    $vsys           = (string)(isset($_GET['vsys'])                 ? $_GET['vsys']: '');
    $objsearch      = (string)(isset($_GET['objsearch'])            ? $_GET['objsearch']: '');
    $objfilter      = (string)(isset($_GET['objfilter'])            ? $_GET['objfilter']: 'none');
    $hide_shared    = (string)(isset($_GET['hide_shared_address'])  ? $_GET['hide_shared_address']: 'false');
    $page           = (string)(isset($_GET['page'])                 ? $_GET['page']: '');
    $start          = (string)(isset($_GET['start'])                ? $_GET['start']: '');
    $limit          = (string)(isset($_GET['limit'])                ? $_GET['limit']: '');

    $mode = $bestPracticesdb->real_escape_string($mode);
    $projectName = $bestPracticesdb->real_escape_string($projectName);
    $source = $bestPracticesdb->real_escape_string($source);
    $vsys = $bestPracticesdb->real_escape_string($vsys);
    $objsearch = $bestPracticesdb->real_escape_string($objsearch);
    $objfilter = $bestPracticesdb->real_escape_string($objfilter);
    $hide_shared = $bestPracticesdb->real_escape_string($hide_shared);
    $page = $bestPracticesdb->real_escape_string($page);
    $start = $bestPracticesdb->real_escape_string($start);
    $limit = $bestPracticesdb->real_escape_string($limit);



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
        $params['mode']="benchmarks";
        $message = list_benchmarks($params);
        if($message['code']) {
            echo json_encode(array('total' => $message['count'], 'benchmarks' => $message['msg']));
        }
        else{
            echo '{"total":"0","benchmarks":[]}';
        }
        break;

    case 'POST':
        $message = register_pack($data);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    case 'PUT':

        break;

    case 'DELETE':

        break;

    default:
        break;
}