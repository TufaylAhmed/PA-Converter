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
require_once INC_ROOT.'/libs/database.php';

require_once INC_ROOT.'/libs/common/services/services.php';

if(defined('CLI')){
    require_once INC_ROOT .'/userManager/API/accessControl_CLI.php';
}
else{
    require_once INC_ROOT .'/userManager/API/accessControl.php';
}

$request_body   = file_get_contents('php://input');
$data           = json_decode($request_body, true);

parse_str(file_get_contents("php://input"),$post_vars);

include INC_ROOT.'/bin/middleware_sanitizer.php';
global $pandb;

if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
}

$mode           = $pandb->real_escape_string((string)(isset($_GET['mode'])         ? $_GET['mode']     : ''));
$project        = $pandb->real_escape_string((string)(isset($_GET['project'])      ? $_GET['project']  : ''));
$source         = $pandb->real_escape_string((string)(isset($_GET['source'])       ? $_GET['source']   : ''));
$stackID        = $pandb->real_escape_string((string)(isset($_GET['stackid'])      ? $_GET['stackid']  : '0'));
$ids            = $pandb->real_escape_string((string)(isset($_GET['ids'])          ? $_GET['ids']      : ''));

$params = [
    'mode'          => $mode,
    'project'       => $project,
    'source'        => $source,
    'stackID'       => $stackID,
    'ids'           => $ids
];

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':

        $message = list_stack_templates($params);
        if($message['code']) {
            echo json_encode(array('total' => $message['count'], 'templates' => $message['msg']));
        }
        else{
            echo '{"total":"0","templates":[]}';
        }
        break;

    case 'POST':
//        $message = register_address($data);
//        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    case 'PUT':
//        $message = update_address($data);
//        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    case 'DELETE':
        $message = delete_stack_templates($post_vars);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    default:
        break;
}

function list_stack_templates($params){
    $project = $params['project'];
    $projectdb = selectDatabase($project);
    $source=$params['source'];
    $mode=$params['mode'];
    $stackID=$params['stackID'];

    if(!accessControl("any", ['projectRole.'.$project.'.view'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to view this project contents';
        return $message;
    }

    $Data=array();
    if ($mode=="members"){
        $getMembers=$projectdb->query("SELECT * FROM templates_stacks WHERE lid='$stackID';");
        if ($getMembers->num_rows>0){
            $members=array();
            while($getMembersData=$getMembers->fetch_assoc()){
                $Data[]=array("template"=>$getMembersData['name']);
            }
        }
        $message = array();
        $message['code'] = true;
        $message['count'] = count($Data);
        $message['msg'] = $Data;
        return $message;
    }
    elseif ($mode=="devices"){
        $getMembers=$projectdb->query("SELECT devices FROM templates_stacks_id WHERE id='$stackID';");
        if ($getMembers->num_rows>0){
            $Data=array();
            while($getMembersData=$getMembers->fetch_assoc()){
                if ($getMembersData['devices']!=""){
                    $device=simplexml_load_string($getMembersData['devices']);

                    foreach ($device as $entry){
                        $Data[]=array("serial"=>(string)$entry->attributes()->name);
                    }
                }
            }
        }
        $message = array();
        $message['code'] = true;
        $message['count'] = count($Data);
        $message['msg'] = $Data;
        return $message;
    }
    else{
        $getStack=$projectdb->query("SELECT * FROM templates_stacks_id WHERE source='$source';");
        if ($getStack->num_rows>0){
            $Data=array();
            $Data1=array();
            while($getStackData=$getStack->fetch_assoc()){
                $stackID=$getStackData['id'];
                $Data1=$getStackData;
                $getMembers=$projectdb->query("SELECT * FROM templates_stacks WHERE lid='$stackID';");
                if ($getMembers->num_rows>0){
                    $members=array();
                    while($getMembersData=$getMembers->fetch_assoc()){
                        $members[]=$getMembersData['name'];
                    }
                }
                $Data1['members']=implode("<br>",$members);

                if ($getStackData['devices']!=""){
                    $DataSerial=array();
                    $device=simplexml_load_string($getStackData['devices']);

                    foreach ($device as $entry){
                        $DataSerial[]="<img valign=middle src=/resources/images/icons/device.gif>&nbsp;".(string)$entry->attributes()->name;
                    }

                    $Data1['devices']=implode("<br>",$DataSerial);
                }

                $Data[]=$Data1;
            }
        }

        $message = array();
        $message['code'] = true;
        $message['count'] = count($Data);
        $message['msg'] = $Data;
        return $message;
    }


}

function delete_stack_templates($params){
    global $app;

    $project = $params['project'];

    if(!accessControl("any", ['projectRole.'.$project.'.update'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to edit this project contents';
        return $message;
    }

    $projectdb = selectDatabase($project);

    take_snapshot_last($project);
    $ids = explode(",",$params['ids']);

    foreach ($ids as $id){
        $projectdb->query("DELETE FROM templates_stacks_id WHERE id='$id';");
        $projectdb->query("DELETE FROM templates_stacks WHERE templates_mapping_id='$id';");
    }
    $message = array();
    $message['code'] = true;
    $message['msg'] = "Template-Stacks removed.";
    return $message;
}