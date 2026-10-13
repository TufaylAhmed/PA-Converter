<?php
# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
/**
 * Created by PhpStorm.
 * User: aestevez
 * Date: 9/19/16
 * Time: 5:13 PM
 */

//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
require_once INC_ROOT.'/bin/Authentication.php';
require_once INC_ROOT.'/libs/shared.php';

require_once INC_ROOT.'/libs/common/regions/regions.php';

require_once INC_ROOT.'/libs/database.php';

include INC_ROOT.'/bin/middleware_sanitizer.php';

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $project    = $pandb->real_escape_string((string)  (isset($_GET['project'])    ? $_GET['project'] : ''));
        $params = [
            'project'       => $project,
            'mode'          => "default_regions"
        ];
        $message = list_defaultRegions($params);
        if($message['code']) {
            echo json_encode(array('total' => $message['count'], 'regions' => $message['msg']));
        }
        else{
            echo '{"total":"0","regions":[]}';
        }
        break;
    case 'POST':
        break;

    default:
        break;
}

if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
}

function list_defaultRegions(ARRAY $params){
    $project = $params['project'];

    if(!accessControl("any", ['projectRole.'.$project.'.view'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to view this project contents';
        return $message;
    }

    switch ($params['mode']){
        case 'default_regions':
            $message = get_defaultRegions($params);
            break;

        default:
            break;
    }

    return $message;

}
