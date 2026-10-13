<?php
# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';
require_once INC_ROOT.'/bin/Authentication.php';
require_once INC_ROOT.'/libs/shared.php';

include INC_ROOT.'/bin/middleware_sanitizer.php';

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $action     = (string)  (isset($_GET['action'])     ? $_GET['action'] : '');
        $type       = (string)  (isset($_GET['type'])       ? $_GET['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_GET['project'])   ? $_GET['project'] : '');
        $template   = (string)  (isset($_GET['template'])  ? $_GET['template'] : '');
        $vsys       = (string)  (isset($_GET['vsys'])      ? $_GET['vsys'] : '');
        $start      = (integer) (isset($_GET['start'])     ? $_GET['start'] : '');
        $limit      = (integer) (isset($_GET['limit'])     ? $_GET['limit'] : '');
        break;
    case 'POST':
        $action     = (string)  (isset($_POST['action'])    ? $_POST['action'] : '');
        $type       = (string)  (isset($_POST['type'])      ? $_POST['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_POST['project'])   ? $_POST['project'] : '');
        $template   = (string)  (isset($_POST['template'])  ? $_POST['template'] : '');
        $vsys       = (string)  (isset($_POST['vsys'])      ? $_POST['vsys'] : '');
        $start      = (integer) (isset($_POST['start'])     ? $_POST['start'] : '');
        $limit      = (integer) (isset($_POST['limit'])     ? $_POST['limit'] : '');
        break;

    default:
        $action     = (string)  (isset($_POST['action'])    ? $_POST['action'] : '');
        $type       = (string)  (isset($_POST['type'])      ? $_POST['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_POST['project'])   ? $_POST['project'] : '');
        $template   = (string)  (isset($_POST['template'])  ? $_POST['template'] : '');
        $vsys       = (string)  (isset($_POST['vsys'])      ? $_POST['vsys'] : '');
        $start      = (integer) (isset($_POST['start'])     ? $_POST['start'] : '');
        $limit      = (integer) (isset($_POST['limit'])     ? $_POST['limit'] : '');
        break;
}

//$action = (string) (isset($_POST['action']) ? $_POST['action'] : $_GET['action']); // upload  / get  /
//$type = (string) (isset($_POST['type']) ? $_POST['type'] : $_GET['type']); // zip / xml / device
//$project = (string) (isset($_POST['project']) ? $_POST['project'] : $_GET['project']);
//$template = (string) (isset($_POST['template']) ? $_POST['template'] : $_GET['template']);
//$vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
//$start = (integer) (isset($_POST['start']) ? $_POST['start'] : $_GET['start']);
//$limit = (integer) (isset($_POST['limit']) ? $_POST['limit'] : $_GET['limit']);

require_once INC_ROOT.'/libs/projectdb.php';
$projectdb = selectDatabase($project);

$action = $projectdb->real_escape_string($action);
$type = $projectdb->real_escape_string($type);
$project = $projectdb->real_escape_string($project);
$template = $projectdb->real_escape_string($template);
$vsys = $projectdb->real_escape_string($vsys);
$start = $projectdb->real_escape_string($start);
$limit = $projectdb->real_escape_string($limit);

if ($action=="get"){
    if ($type=="qos_interface"){
        $query=generate_query("template");
        $getAll=$projectdb->query("SELECT id FROM qos_profile $query;");
        $count=$getAll->num_rows;
        if ($count>0){
            if (($start=="") AND ($limit=="")){$start=0;$limit=0;}
            $getLimit=$projectdb->query("SELECT id,vsys,source,template,name,xml FROM qos_interface $query ORDER BY name ASC LIMIT $start, $limit;");
            if ($getLimit->num_rows>0){
                while ($data=$getLimit->fetch_object()){
                    $myData[]=$data;
                }
            }
        }
        else {
            $myData="";
        }
        echo '{"total":"'.$count.'","qos":'.json_encode($myData).'}';
    }
    elseif ($type=="qos_profile"){
        $query=generate_query("template");
        $getAll=$projectdb->query("SELECT id FROM qos_profile $query;");
        $count=$getAll->num_rows;
        if ($count>0){
            if (($start=="") AND ($limit=="")){$start=0;$limit=0;}
            $getLimit=$projectdb->query("SELECT id,vsys,source,template,name,xml FROM qos_profile $query ORDER BY name ASC LIMIT $start, $limit;");
            if ($getLimit->num_rows>0){
                while ($data=$getLimit->fetch_object()){
                    $myData[]=$data;
                }
            }
        }
        else {
            $myData="";
        }
        echo '{"total":"'.$count.'","qos":'.json_encode($myData).'}';
    }
}



?>