<?php

# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.

//require_once('./Authentication.php');
//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

require_once INC_ROOT.'/userManager/start.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';

require_once INC_ROOT.'/userManager/API/projects/register.php';
require_once INC_ROOT.'/userManager/API/projects/delete.php';
require_once INC_ROOT.'/userManager/API/projects/list.php';

require_once INC_ROOT.'/libs/backups.php';

include INC_ROOT.'/bin/middleware_sanitizer.php';

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $action         = (string)  (isset($_GET['action'])         ? $_GET['action'] : '');
        $project        = (string)  (isset($_GET['project'])        ? $_GET['project'] : '');
        $connector      =           (isset($_GET['connector'])      ? $_GET['connector'] : '');
        $snapshot_save  =           (isset($_GET['snapshot_save'])  ? $_GET['snapshot_save'] : '');
        $snapshot       =           (isset($_GET['snapshot'])       ? $_GET['snapshot'] : '');
        $tag            =           (isset($_GET['tag'])            ? $_GET['tag'] : '');
        break;
    case 'POST':
        $action         = (string)  (isset($_POST['action'])        ? $_POST['action'] : '');
        $project        = (string)  (isset($_POST['project'])       ? $_POST['project'] : '');
        $connector      =           (isset($_POST['connector'])     ? $_POST['connector'] : '');
        $snapshot_save  =           (isset($_POST['snapshot_save']) ? $_POST['snapshot_save'] : '');
        $snapshot       =           (isset($_POST['snapshot'])      ? $_POST['snapshot'] : '');
        $tag            =           (isset($_POST['tag'])           ? $_POST['tag'] : '');

        break;

    default:
}

if ($project != "") {

    require_once INC_ROOT.'/libs/projectdb.php';
    $projectdb = selectDatabase($project);

    $action = $projectdb->real_escape_string($action);
    $project = $projectdb->real_escape_string($project);
    $connector = $projectdb->real_escape_string($connector);
    $snapshot_save = $projectdb->real_escape_string($snapshot_save);
    $snapshot = $projectdb->real_escape_string($snapshot);
    $tag = $projectdb->real_escape_string($tag);

    if(!checkProjectRights($project,'view')){
        $message = [
            'success' => false,
            'code'  => -1,
            'msg' => 'Your account does not have the rights to see this project contents',
            ];
        echo json_encode($message);
        return $message;
    }
//    if ($action == "create") {
//        $message= registerProject($project);
//        if($message['code']){
//            clone_db($project);
//        }
//        else{
//            echo json_encode(array("success" => false, "msg" => "You do not have permissions to create a new project. Contact your administrator."));
//        }
//    }
//    elseif ($action == "delete") {
//        $message= deleteProject($project);
//        if($message['code']){
//            delete_db($project);
//        }
//        else {
//            echo json_encode(array("success" => false, "msg" => "You do not have permissions to delete the '$project' project. Contact your administrator."));
//        }
//
//    }
//    else
    if ($action == "list_snapshots") {
        echo json_encode(list_snapshots($project));
    }
    else {
        if(!checkProjectRights($project, 'update')){
            $message = array();
            $message['code'] = false;
            $message['msg'] = 'Your account does not have the rights to modify this project contents';
            echo json_encode($message);
            return $message;
        }
        if ($action == "snapshot") {
            $msg = verifySpace($project);
            if($msg['code']) {
                take_snapshot($project, $snapshot_save);
            }
            else{
                echo json_encode(array("success" => $msg['code'], "message" => $msg['msg']));
            }
        }
        elseif ($action == "load_last_saved") {
            $msg = load_last_saved($project);
            echo json_encode(array("success" => $msg['code'], "message" => $msg['msg']));
        }
        elseif ($action == "load_next_saved") {
            $msg = load_next_saved($project);
            echo json_encode(array("success" => $msg['code'], "message" => $msg['msg']));
        }
        elseif ($action == "load_snapshot") {
            load_snapshot($project, $snapshot);
        }
        elseif ($action == "take_snapshot_last") {
            require_once INC_ROOT . '/libs/shared.php';
            require_once INC_ROOT . '/libs/database.php';
            take_snapshot_last($project);
            echo json_encode(array("success" => true));
        }
    }
//    elseif ($action == "update_log_connector") {
//        $pandb->query("UPDATE projects SET log_connector='$connector' WHERE name='$project';");
//    }
//    elseif ($action == "update_userid_connector") {
//        $pandb->query("UPDATE projects SET userid_connector='$connector' WHERE name='$project';");
//    }
} 
//else {
//    if ($action == "list") {
//        list_db($project);
//    }
//}


?>