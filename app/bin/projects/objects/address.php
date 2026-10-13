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

require_once INC_ROOT.'/libs/shared.php';
require_once INC_ROOT.'/libs/projectdb.php';

require_once INC_ROOT.'/libs/sanitize.php';

require_once INC_ROOT.'/libs/common/address/address.php';

if(defined('CLI')){
    require_once INC_ROOT .'/userManager/API/accessControl_CLI.php';
}
else{
    require_once INC_ROOT .'/userManager/API/accessControl.php';
}

require_once INC_ROOT.'/libs/database.php';

$request_body   = file_get_contents('php://input');
//print_r($request_body);
$data           = json_decode($request_body, true);
//print_r($post_vars);
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
    $hide_shared    = $pandb->real_escape_string((string)(isset($_GET['hide_shared_address'])  ? $_GET['hide_shared_address']: 'false'));
    $page           = $pandb->real_escape_string((string)(isset($_GET['page'])                 ? $_GET['page']: ''));
    $start          = $pandb->real_escape_string((string)(isset($_GET['start'])                ? $_GET['start']: ''));
    $limit          = $pandb->real_escape_string((string)(isset($_GET['limit'])                ? $_GET['limit']: ''));
    $query          = $pandb->real_escape_string((string)(isset($_GET['query'])                ? $_GET['query']: ''));

    $name           = $pandb->real_escape_string((string)(isset($_GET['name'])                ? $_GET['name']: ''));
    $names_tags     = $pandb->real_escape_string((string)(isset($_GET['names_tags'])                ? $_GET['names_tags']: ''));
    $type           = $pandb->real_escape_string((string)(isset($_GET['type'])                ? $_GET['type']: ''));
    $ipaddress      = $pandb->real_escape_string((string)(isset($_GET['ipaddress'])                ? $_GET['ipaddress']: ''));
    $cidr           = $pandb->real_escape_string((string)(isset($_GET['cidr'])                ? $_GET['cidr']: ''));
    $description    = $pandb->real_escape_string((string)(isset($_GET['description'])                ? $_GET['description']: ''));
    $id             = $pandb->real_escape_string((string)(isset($_GET['id'])                ? $_GET['id']: ''));


}

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
    'query'         => $query,
    'name'          => $name,
    'names_tags'    => $names_tags,
    'type'          => $type,
    'ipaddress'     => $ipaddress,
    'cidr'          => $cidr,
    'description'   => $description,
    'id'            => $id

    //'action'        => $action
];

//echo "PARAMS: ";
//print_r($params);


if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
}

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $message = list_address($params);
        if($message['code']) {
            echo json_encode(array('total' => $message['count'], 'address' => $message['msg']));
        }
        else{
            echo '{"total":"0","address":[]}';
        }
        break;

    case 'POST':
        $message = register_address($data);
        //echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']['content']));
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    case 'PUT':
        $message = update_address($data);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    case 'DELETE':
        $message = delete_address($data);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    default:
        break;
}

function list_address(ARRAY $params){
    $project = $params['project'];

    if(!accessControl("any", ['projectRole.'.$project.'.view'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to view this project contents';
        return $message;
    }

    switch ($params['mode']){
        case 'address':
            $message = get_address($params);
            break;

        case 'address_static':
            $message = get_addressStatic($project,'');
            break;

        case 'address_all':
            $message = get_addressAll($project,'',$params);
            break;

        case 'address_and_groups':
            break;

        case 'address_not_groups':
            break;

        case 'address_and_groups_and_external':
            $message = get_addressAndGroupsAndExternal($project,'');
            break;

        case 'address_all_override':
            $message = get_addressAll($project,'override',$params);
            break;

        case 'address_groups_override':
            $message = get_addressGroupsOverride($project,'override',$params);
            break;

        default:
            break;
    }

    return $message;

}

