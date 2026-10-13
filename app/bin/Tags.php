<?php

# Copyright (c) 2015 Palo Alto Networks, Inc.
# All rights reserved.
require_once('./Authentication.php');
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';
require_once INC_ROOT.'/libs/shared.php';
require_once INC_ROOT.'/libs/database.php';
require_once INC_ROOT.'/userManager/API/projects/manageSettings.php';
require_once INC_ROOT.'/libs/projectdb.php';

include INC_ROOT.'/bin/middleware_sanitizer.php';

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $action     = (string)  (isset($_GET['action'])     ? $_GET['action'] : '');
        $type       = (string)  (isset($_GET['type'])       ? $_GET['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_GET['project'])    ? $_GET['project'] : '');
        $start      = (integer) (isset($_GET['start'])      ? $_GET['start'] : '');
        $limit      = (integer) (isset($_GET['limit'])      ? $_GET['limit'] : '');
        $vsys       = (string)  (isset($_GET['vsys'])      ? $_GET['vsys'] : '');
        $source     = (string)  (isset($_GET['source'])    ? $_GET['source'] : '');

        break;

    case 'POST':
        $action     = (string)  (isset($_POST['action'])    ? $_POST['action'] : '');
        $type       = (string)  (isset($_POST['type'])      ? $_POST['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_POST['project'])   ? $_POST['project'] : '');
        $start      = (integer) (isset($_POST['start'])     ? $_POST['start'] : '');
        $limit      = (integer) (isset($_POST['limit'])     ? $_POST['limit'] : '');
        $protocol   = (string) (isset($_POST['protocol'])     ? $_POST['protocol'] : '');
        $vsys       = (string)  (isset($_POST['vsys'])      ? $_POST['vsys'] : '');
        $source     = (string)  (isset($_POST['source'])    ? $_POST['source'] : '');

        break;

    default:
        $action     = (string)  (isset($_POST['action'])    ? $_POST['action'] : '');
        $type       = (string)  (isset($_POST['type'])      ? $_POST['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_POST['project'])   ? $_POST['project'] : '');
        $start      = (integer) (isset($_POST['start'])     ? $_POST['start'] : '');
        $limit      = (integer) (isset($_POST['limit'])     ? $_POST['limit'] : '');
        $vsys       = (string)  (isset($_POST['vsys'])      ? $_POST['vsys'] : '');
        $source     = (string)  (isset($_POST['source'])    ? $_POST['source'] : '');

        break;
}

$projectdb = selectDatabase($project);

$action = $projectdb->real_escape_string($action);
$type = $projectdb->real_escape_string($type);
$project = $projectdb->real_escape_string($project);
$start = $projectdb->real_escape_string($start);
$limit = $projectdb->real_escape_string($limit);
$vsys = $projectdb->real_escape_string($vsys);
$source = $projectdb->real_escape_string($source);


global $app;
$user = $app->container->sentinel->getUser();
$user_id = $user->id;

ini_set('max_execution_time', 10000);
ini_set("memory_limit", "1000M");

if ($action == "convert") {
    if ($type == "shared") {
        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        $ids = (string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']);

        $source = $projectdb->real_escape_string($source);
        $ids = $projectdb->real_escape_string($ids);

        $remove_address = array();
        if ($ids != "") {
            take_snapshot_last($project);
            $member_tags = explode(',', $ids);
            $return = convertTagToShared($source, $member_tags, "notall");
            if($return == 1){
                echo json_encode(array("success" => true));
            }
            else{
                echo json_encode(array("success" => false));
            }
        }
    }
    elseif ($type == "clone") {
        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
        $ids = (string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']);
        $clone_to_vsys = (string) (isset($_POST['combo']) ? $_POST['combo'] : $_GET['combo']);

        $source = $projectdb->real_escape_string($source);
        $vsys = $projectdb->real_escape_string($vsys);
        $ids = $projectdb->real_escape_string($ids);
        $clone_to_vsys = $projectdb->real_escape_string($clone_to_vsys);

        if ($ids != "") {
            take_snapshot_last($project);
            $member_tags = explode(',',$ids);
            $return = cloneTags($source, $vsys, $clone_to_vsys, $member_tags);
            if($return != 0){
                echo json_encode(array("success" => true));
            }else{
                echo json_encode(array("success" => false));
            }
        }
    }
}





