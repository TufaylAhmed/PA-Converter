<?php
/**
 * Copyright (c) 2019 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 09/10/2019 - 09:15
 */
//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';

require_once INC_ROOT.'/userManager/API/devices/list.php';
require_once INC_ROOT.'/libs/database.php';
require_once INC_ROOT.'/libs/shared.php';
require_once INC_ROOT.'/libs/xmlapi.php';
require_once INC_ROOT.'/libs/common/lib-objects.php';

include_once INC_ROOT.'/libs/PaloAltoNetworks/Middleware/loadCSRFControl.php';

$request_body   = file_get_contents('php://input');
$data           = json_decode($request_body, true);

parse_str(file_get_contents("php://input"),$post_vars);

include INC_ROOT.'/bin/middleware_sanitizer.php';

if(isset($post_vars['type'])){
    $type = $pandb->real_escape_string($post_vars['type']);
}
else {
    $type       = (string)(isset($_GET['type'])         ? $_GET['type'] : '');
    $scope      = (string)(isset($_GET['scope'])        ? $_GET['scope']: '');
    $projectName= (string)(isset($_GET['project'])  ? $_GET['project']: '');
    $source = (int)(isset($_GET['source']) ? $_GET['source']: '1');

    $type = $pandb->real_escape_string($type);
    $scope = $pandb->real_escape_string($scope);
    $projectName = $pandb->real_escape_string($projectName);
    $source = $pandb->real_escape_string($source);

}

if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
}

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
//        $projectName = 'internal';
//       $source = '1';
        $message = list_DeviceTree($projectName, $source);
        if($message['code']) {
            echo json_encode($message['msg']);
        }
        else{
            echo '{"total":"0","devices":[]}';
        }
        break;

    case 'POST':
    case 'PUT':
    case 'DELETE':
    default:
        break;
}

function list_DeviceTree(String $projectName, int $source){
    $projectdb = selectDatabase($projectName);
    #$vsyses = getVsysesIDs($projectdb,'shared');

    $getPanorama=$projectdb->query("SELECT ispanorama,filename FROM device_mapping WHERE id='$source';");
    if ($getPanorama->num_rows==1){
        $getPanoramaData=$getPanorama->fetch_assoc();
        $isPanorama=$getPanoramaData['ispanorama'];
        $filename=$getPanoramaData['filename'];
    }

    if ($isPanorama==1){
        $query = "SELECT dm.vsys, dg.device_mapping_id as kidID, parent_dg as parentID
              FROM device_mapping dm, devicegroups dg 
              WHERE dm.id = dg.device_mapping_id AND dg.source = '$source' ORDER BY parentID; ";

        $result = $projectdb->query($query);
        $vsysTree = array();
        $vsysTable = array();
        $vsysNames=array();
        if($result->num_rows>0){
            while ($data = $result->fetch_object()){
                if ((!isset($start)) && ($data->parentID==0)){
                    $start=$data->kidID;
                }
                $vsysTable[$data->parentID][] = $data->kidID;
                $vsysNames[$data->kidID] = $data->vsys;
            }
        }

        //print_r($vsysTable);

        $structure =[
            'text'=>'shared',
            'id'=>'shared',
            'expanded' => true,
            'iconCls' => 'icon-devices',
            'leaf' => false,
            'children' => getMyChildren($vsysTable, $vsysNames, 0),
            'visible' => true
        ];
    }
    else{
        $query="SELECT vsys FROM device_mapping WHERE filename='$filename' AND vsys != 'shared' ORDER BY id DESC;";
        $result = $projectdb->query($query);
        if($result->num_rows>0){
            while ($data = $result->fetch_object()){
                $structure2[]=[
                    'text'=>$data->vsys,
                    'id'=>$data->vsys,
                    'expanded' => false,
                    'iconCls' => 'icon-device',
                    'leaf' => true,
                    'visible' => true
                ];
            }
        }
        $structure =[
            'text'=>'shared',
            'id'=>'shared',
            'expanded' => true,
            'iconCls' => 'icon-devices',
            'leaf' => false,
            'children' => $structure2,
            'visible' => true
        ];
    }



    $structureRoot= [
        'visible' => true,
        'expanded' => true,
        'children' => $structure,
        'text'=>'Root',
        'leaf' => false,
        'id'=>'root'
    ];

    return ['code'=>true, 'msg'=>$structureRoot];
}

function getMyChildren(array $vsysTable, array $vsysNames, int $id):array{
    $children = array();
    if (isset($vsysTable[$id])){
        foreach ($vsysTable[$id] as $child) {
            $myChildren = getMyChildren($vsysTable, $vsysNames, $child);
            if(count($myChildren)>0) {
                $children[] = [
                    'text' => $vsysNames[$child],
                    'expanded' => true,
                    'children' => $myChildren,
                    'visible'  => true,
                    'level'     => 'red',
                    'iconCls' => 'icon-devices'
                ];
            }
            else{
                $children[] = [
                    'leaf' => true,
                    'text' => $vsysNames[$child],
                    'visible'  => true,
                    "cls"=> "icon-blue",
                    'iconCls' => 'icon-device'
                ];
            }
        }
    }


    return $children;
}