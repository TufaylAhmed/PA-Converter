<?php
/*******************************************************************************
 * Copyright (c) 2018 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: 2/22/19 6:36 PM
 ******************************************************************************/
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
require_once INC_ROOT.'/userManager/start.php';
include INC_ROOT.'/bin/authentication/sessionControl.php';

require_once INC_ROOT.'/libs/database.php';
require_once INC_ROOT.'/libs/projectdb.php';

require_once INC_ROOT.'/libs/common/tools/filters.php';
require_once INC_ROOT.'/libs/objects/Response.php';

$request_body   = file_get_contents('php://input');
$data           = json_decode($request_body, true);

include INC_ROOT.'/bin/middleware_sanitizer.php';
global $pandb;

switch($_SERVER['REQUEST_METHOD'])
{
    case 'DELETE':
        $objectType     = (string)  (isset($_POST['objectType'])    ? $_POST['objectType'] : '');
        $objectId       = (string)     (isset($_POST['objectId'])      ? $_POST['objectId'] : ''); // zip / xml / device
        $project        = (string)  (isset($_POST['project'])       ? $_POST['project'] : '');
        $table_name     = (string) (isset($_POST['table_name'])    ? $_POST['table_name'] : '');

        $limit      = (integer) (isset($_POST['limit'])     ? $_POST['limit'] : '');
        $vsys       = (string)  (isset($_POST['vsys'])      ? $_POST['vsys'] : '');
        $source     = (integer)  (isset($_POST['source'])    ? $_POST['source'] : 0);

        $msg = callCreateDynamicDelete($data);

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

function callCreateDynamicDelete($data): Response{
    $objectType = isset($data['objectType'])? $data['objectType']: '';
    $objectIds  = isset($data['objectId'])? $data['objectId']: '';
    $project    = isset($data['project'])?$data['project']: '';
    $source     = isset($data['source'])?$data['source']: '';
    $vsys       = isset($data['vsys'])?$data['vsys']: '';

    if(!accessControl("any", ['projectRole.'.$project.'.update','project.create'])){
        return new Response(false, -1, new Messages(['Your account does not have the rights to modify this project contents']));
    }

    switch ($objectType){
        case "zones":
            require_once INC_ROOT.'/libs/objects/tools/ZoneObjectManager.php';
            $objectManager = new ZoneObjectManager();
            break;

        default:
            return new Response(false, -1, new Messages(['Filter option '.$objectType.' not found']));
            break;


    }
    $objectIdArray = explode(",", $objectIds);
    $message = $objectManager->forceDelete($project, $source, $vsys, $objectIdArray);
    return $message;

}