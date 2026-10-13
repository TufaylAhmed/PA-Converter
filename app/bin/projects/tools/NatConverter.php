<?php
# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';

require_once INC_ROOT.'/libs/projectdb.php';

require_once INC_ROOT.'/libs/common/ThreatPractice/TPInternet.php';

if(defined('CLI')){
    require_once INC_ROOT .'/userManager/API/accessControl_CLI.php';
}
else{
    require_once INC_ROOT .'/userManager/API/accessControl.php';
}

$request_body   = file_get_contents('php://input');
$data           = json_decode($request_body, true);

include INC_ROOT.'/bin/middleware_sanitizer.php';

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
//        $projectName    = (string)(isset($_GET['project'])              ? $_GET['project']: '');
//        $source         = (string)(isset($_GET['source'])               ? $_GET['source']: '');
//        $template         = (string)(isset($_GET['template'])           ? $_GET['template']: '');
//        $params = [
//            'project'       => $projectName,
//            'source'        => $source,
//            'template'      => $template,
//        ];
//
//        $message = convert_snat_interface_translatedaddress($params);
//        if($message['code']) {
//            echo json_encode(array('total' => $message['count'], 'zones' => $message['msg']));
//        }
//        else{
//            echo '{"total":"0","zones":[]}';
//        }
        break;

    case 'POST':
        $projectName    = (string)(isset($_POST['project'])     ? $_POST['project']: '');
        $source         = (string)(isset($_POST['source'])      ? $_POST['source']: '');
        $vsys           = (string)(isset($_POST['vsys'])      ? $_POST['vsys']: '');
        $template       = (string)(isset($_POST['template'])    ? $_POST['template']: '');
        $tagid          = (string)(isset($_POST['tagid'])       ? $_POST['tagid']: '');
        $ids            = (string)(isset($_POST['ids'])         ? $_POST['ids']: '');
        $params = [
            'project'    => $projectName,
            'source'     => $source,
            'template'   => $template,
            'tagid'      => $tagid,
            'ids'        => $ids,
            'vsys'       => $vsys,
        ];

        $message = convert_snat_interface_translatedaddress($params);
        if($message['code']) {
            echo json_encode(array('total' => $message['count'], 'zones' => $message['msg']));
        }
        else{
            echo '{"total":"0","zones":[]}';
        }
//        $message = register_address($data);
//        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    case 'PUT':
//        $message = update_address($data);
//        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    case 'DELETE':
//        $message = delete_address($data);
//        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    default:
        break;
}

