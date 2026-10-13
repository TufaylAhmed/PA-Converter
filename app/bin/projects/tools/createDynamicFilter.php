<?php
/*******************************************************************************
 * Copyright (c) 2018 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: 2/21/19 11:45 AM
 ******************************************************************************/
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
require_once INC_ROOT.'/userManager/start.php';
include INC_ROOT.'/bin/authentication/sessionControl.php';

require_once INC_ROOT.'/libs/database.php';
require_once INC_ROOT.'/libs/projectdb.php';

require_once INC_ROOT.'/libs/common/tools/filters.php';


$request_body   = file_get_contents('php://input');
$data           = json_decode($request_body, true);

include INC_ROOT.'/bin/middleware_sanitizer.php';

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        break;
    case 'POST':
        $msg = callCreateDynamicFilter($data);

        if($msg->success){
            echo json_encode(['success'=> $msg->success, 'msg'=> implode(", ",$msg->getMessages())]);
        }
        else{
            echo json_encode(['success'=> $msg->success, 'msg'=> implode(", ",$msg->getMessages())]);
        }

        break;

    default:
        break;
}



function callCreateDynamicFilter(array $data): Response{
    $objectType = isset($data['objectType'])? $data['objectType']: '';
    $objectIds  = isset($data['objectId'])? $data['objectId']: '';
    $project    = isset($data['project'])?$data['project']: '';
    $source     = isset($data['source'])?$data['source']: '';
    $vsys       = isset($data['vsys'])?$data['vsys']: '';
    $table_name = isset($data['table_name'])?$data['table_name']: '';

    if(!accessControl("any", ['projectRole.'.$project.'.update','project.create'])){
        return new Response(false, -1, new Messages(['Your account does not have the rights to modify this project contents']));
    }

    switch ($objectType){
        case "zones":
            require_once INC_ROOT.'/libs/objects/tools/ZoneObjectManager.php';
            $objectManager = new ZoneObjectManager();
            break;

        default:
            return new Response(false, -1, new Messages(['Filter option not found']));
            break;


    }
    $objectIdArray = explode(",", $objectIds);
    $message = $objectManager->applyFilter($project, $source, $vsys, $objectIdArray, $table_name);
    return $message;

}
