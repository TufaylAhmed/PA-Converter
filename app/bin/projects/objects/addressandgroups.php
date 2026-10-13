<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 15/7/16 - 14:34
 */
//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';

require_once INC_ROOT.'/libs/shared.php';
require_once INC_ROOT.'/libs/projectdb.php';

require_once INC_ROOT.'/libs/common/panosGlobalReq.php';
require_once INC_ROOT.'/libs/common/address/address.php';
//require_once INC_ROOT.'/libs/common/addressgroups/addressgroups.php';

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
    $id             = $pandb->real_escape_string((string)(isset($_GET['id'])                   ? $_GET['id']: ''));
    $source         = $pandb->real_escape_string((string)(isset($_GET['source'])               ? $_GET['source']: ''));
    $vsys           = $pandb->real_escape_string((string)(isset($_GET['vsys'])                 ? $_GET['vsys']: ''));
    $objsearch      = $pandb->real_escape_string((string)(isset($_GET['objsearch'])            ? $_GET['objsearch']: ''));
    $objfilter      = $pandb->real_escape_string((string)(isset($_GET['objfilter'])            ? $_GET['objfilter']: 'none'));
    $hide_shared    = $pandb->real_escape_string((string)(isset($_GET['hide_shared_address'])  ? $_GET['hide_shared_address']: 'false'));
    $where_search   = $pandb->real_escape_string((string)(isset($_GET['where_search'])         ? $_GET['where_search']: ''));
    $search_in_members_p  = $pandb->real_escape_string((string)(isset($_GET['search_in_members_p'])  ? $_GET['search_in_members_p']: 'false'));
    $page           = $pandb->real_escape_string((string)(isset($_GET['page'])                 ? $_GET['page']: ''));
    $start          = $pandb->real_escape_string((string)(isset($_GET['start'])                ? $_GET['start']: ''));
    $limit          = $pandb->real_escape_string((string)(isset($_GET['limit'])                ? $_GET['limit']: ''));

    $params = [
        'mode'          => $mode,
        'project'       => $projectName,
        'id'            => $id,
        'source'        => $source,
        'vsys'          => $vsys,
        'objfilter'     => $objfilter,
        'objsearch'     => $objsearch,
        'hide_shared'   => $hide_shared,
        'where_search'  => $where_search,
        'search_in_members_p' => $search_in_members_p,
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
        $project = $params['project'];

        if(!accessControl("any", ['projectRole.'.$project.'.view'])){
            $message = array();
            $message['code'] = false;
            $message['msg'] = 'Your account does not have the rights to view this project contents';
            return $message;
        }
//        $params= [
//            'project'=> 'ciscoReference',
//            'source'=> '1',
//            'vsys'=> 'vsys1'
//        ];
        //$message = get_addressAndGroups($params);
        $message = get_addressAndGroupsOnly($project,'');
        if($message['code']) {
            echo json_encode(array('total' => $message['count'], 'address' => $message['msg']));
        }
        else{
            echo '{"total":"0","addressGroups":[]}';
        }
        break;
        
        


    case 'POST':
//        $message = register_Device($data);
//        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    case 'PUT':
//        $message = update_Device($data);
//        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    case 'DELETE':
        $message = delete_addressGroups($data);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    default:
        break;
}

function get_addressAndGroups($params){
    $addressesAndGroups = array();
    $params['start']=0;$params['limit']=10000000;

    $message = get_addressGroups($params);
    foreach ($message['msg'] as $group ){
        $member = $group;
        $member['table_name']="address_groups_id";
        $addressesAndGroups[]=$member;
    }
    $addressesAndGroups = array_merge($addressesAndGroups, $message['msg']);

    $message = get_address($params);
    foreach ($message['msg'] as $address ){
        $member = $address;
        $member->table_name="address";
        $addressesAndGroups[]=$member;
    }
    $addressesAndGroups = array_sort_recursive($addressesAndGroups);

    $message = array();
    $message['code'] = true;
    $message['count'] = count($addressesAndGroups);
    $message['msg'] = $addressesAndGroups;
    return $message;
}