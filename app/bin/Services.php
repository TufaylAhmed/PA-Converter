<?php

# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';
require_once INC_ROOT.'/bin/Authentication.php';
require_once INC_ROOT.'/libs/shared.php';

require_once INC_ROOT.'/libs/projectdb.php';
require_once INC_ROOT.'/userManager/API/projects/manageSettings.php';


ini_set('max_execution_time', PARSER_max_execution_time);
ini_set("memory_limit", PARSER_max_execution_memory);

include INC_ROOT.'/bin/middleware_sanitizer.php';

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $action     = (string)  (isset($_GET['action'])    ? $_GET['action'] : '');
        $type       = (string)  (isset($_GET['type'])      ? $_GET['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_GET['project'])   ? $_GET['project'] : '');
        $devicename = (string)  (isset($_GET['devicename'])? $_GET['devicename'] : '');
        $version    = (string)  (isset($_GET['version'])   ? $_GET['version'] : '');
        $start      = (integer) (isset($_GET['start'])     ? $_GET['start'] : '');
        $limit      = (integer) (isset($_GET['limit'])     ? $_GET['limit'] : '');
        break;
    case 'POST':
        $action     = (string)  (isset($_POST['action'])    ? $_POST['action'] : '');
        $type       = (string)  (isset($_POST['type'])      ? $_POST['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_POST['project'])   ? $_POST['project'] : '');
        $devicename = (string)  (isset($_POST['devicename'])? $_POST['devicename'] : '');
        $version    = (string)  (isset($_POST['version'])   ? $_POST['version'] : '');
        $start      = (integer) (isset($_POST['start'])     ? $_POST['start'] : '');
        $limit      = (integer) (isset($_POST['limit'])     ? $_POST['limit'] : '');
        break;

    default:
        $action     = (string)  (isset($_POST['action'])    ? $_POST['action'] : '');
        $type       = (string)  (isset($_POST['type'])      ? $_POST['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_POST['project'])   ? $_POST['project'] : '');
        $devicename = (string)  (isset($_POST['devicename'])? $_POST['devicename'] : '');
        $version    = (string)  (isset($_POST['version'])   ? $_POST['version'] : '');
        $start      = (integer) (isset($_POST['start'])     ? $_POST['start'] : '');
        $limit      = (integer) (isset($_POST['limit'])     ? $_POST['limit'] : '');
        break;
}

$projectdb = selectDatabase($project);

$action = $projectdb->real_escape_string($action);
$type = $projectdb->real_escape_string($type);
$project = $projectdb->real_escape_string($project);
$devicename = $projectdb->real_escape_string($devicename);
$version = $projectdb->real_escape_string($version);
$start = $projectdb->real_escape_string($start);
$limit = $projectdb->real_escape_string($limit);

global $app;
$user = $app->container->sentinel->getUser();
$user_id = $user->id;

if ($action == "get") {
    if ($type == "services_only") {
        $query = generate_query("objects");
        if (preg_match("/WHERE/", $query)) {
            $query = $query . " AND dummy=0 ";
        } else {
            $query = $query . " WHERE dummy=0 ";
        }
        $getLimit = $projectdb->query("SELECT id as idx, name, id, if (vsys = 'shared', 'shared_services.gif', 'service.gif') AS type, 'services' as table_name, vsys FROM services $query ;");
        
        $count = $getLimit->num_rows;
        $x = 0;

        while ($data = $getLimit->fetch_object()) {
            $data->id = $x++;
            $myData[] = $data;
        }
        if ($count == 0) {
            $myData = "";
        }
        echo '{"total":"' . $count . '","services":' . json_encode($myData) . '}';
    } 
    elseif ($type == "services_only_nat") {
        $query = generate_query("objects");
        if (preg_match("/WHERE/", $query)) {
            $queryServices = $query . " AND dummy=0 ";
        } else {
            $queryServices = $query . " WHERE dummy=0 ";
        }
        $getLimit = $projectdb->query("SELECT id as idx, name, name_ext, id, if (vsys = 'shared', 'shared_services.gif', 'service.gif') AS type, 'services' as table_name, vsys, 'fa fa-cog' AS icon, if (vsys = 'shared', '#cf1cbc', '#235585') AS color FROM services $queryServices "
            . "UNION SELECT id as idx, name, name_ext, id, if (vsys = 'shared', 'shared_services_groups.gif', 'services_groups.gif') AS type, 'services_groups_id' as table_name, vsys, 'fa fa-cogs' AS icon, if (vsys = 'shared', '#cf1cbc', '#235585') AS color FROM services_groups_id $queryServices ;");
        $count = $getLimit->num_rows;
        $x = 0;
        $a = $x++;
        $myData[] = array("idx" => "0", "name" => "any", "name_ext" => "any", "id" => "$a", "type" => "service.gif", "table_name" => "services", "icon" => "fa fa-cog", "color" => "#235585");
        while ($data = $getLimit->fetch_object()) {
            $data->id = $x++;
            $myData[] = $data;
        }
        if ($count == 0) {
            $myData = "";
        }
        
        $count = count($myData);
        
        echo '{"total":"' . $count . '","services":' . json_encode($myData) . '}';
    }
    elseif ($type == "services_all") {
        $query = generate_query("objects_vsyses");
        /*if (preg_match("/WHERE/", $query)) {
            $queryServices = $query . " AND dummy=0 ";
        } else {
            $queryServices = $query . " WHERE dummy=0 ";
        }*/
        //$getLimit = $projectdb->query("SELECT id as idx, name, id, 'service.gif' as type,'services' as table_name FROM services $query UNION SELECT id as idx, name, id, 'shared_services.gif' as type,'shared_services' as table_name FROM shared_services $query UNION SELECT id as idx, name, id, 'services_groups.gif' as type,'services_groups_id' as table_name FROM services_groups_id $query UNION SELECT id as idx, name, id, 'shared_services_groups.gif' as type,'shared_services_groups_id' as table_name FROM shared_services_groups_id $query;");
        $getLimit = $projectdb->query("SELECT id as idx, name_ext, name, id, if (vsys = 'shared', 'shared_services.gif', 'service.gif') AS type, 'services' as table_name, vsys, 'fa fa-cog' AS icon, if (vsys = 'shared', '#cf1cbc', '#235585') AS color FROM services $query "
                . "UNION SELECT id as idx, name_ext, name, id, if (vsys = 'shared', 'shared_services_groups.gif', 'services_groups.gif') AS type, 'services_groups_id' as table_name, vsys, 'fa fa-cogs' AS icon, if (vsys = 'shared', '#cf1cbc', '#235585') AS color  FROM services_groups_id $query ;");

        $count = $getLimit->num_rows;
        $x = 0;

        while ($data = $getLimit->fetch_assoc()) {
            $data['id'] = $x++;
            $myData[] = $data;
        }
        if ($count == 0) {
            $myData = "";
        }
        echo '{"total":"' . $count . '","address":' . json_encode($myData) . '}';
    }
    elseif($type == "services_all_override"){
        $query = generate_query("objects_vsyses");
        /*if (preg_match("/WHERE/", $query)) {
            $queryServices = $query . " AND dummy=0 ";
        } else {
            $queryServices = $query . " WHERE dummy=0 ";
        }*/
        //$getLimit = $projectdb->query("SELECT id as idx, name, id, 'service.gif' as type,'services' as table_name FROM services $query UNION SELECT id as idx, name, id, 'shared_services.gif' as type,'shared_services' as table_name FROM shared_services $query UNION SELECT id as idx, name, id, 'services_groups.gif' as type,'services_groups_id' as table_name FROM services_groups_id $query UNION SELECT id as idx, name, id, 'shared_services_groups.gif' as type,'shared_services_groups_id' as table_name FROM shared_services_groups_id $query;");
        $query_all_services =
            "SELECT id as idx, name_ext, name, id, if (vsys = 'shared', 'shared_services.gif', 'service.gif') AS type, 'services' as table_name, vsys, 'fa fa-cog' AS icon, if (vsys = 'shared', '#cf1cbc', '#235585') AS color                                  FROM services $query ".
            "UNION  SELECT id as idx, name_ext, name, id, if (vsys = 'shared', 'shared_services_groups.gif', 'services_groups.gif') AS type, 'services_groups_id' as table_name, vsys, 'fa fa-cogs' AS icon, if (vsys = 'shared', '#cf1cbc', '#235585') AS color  FROM services_groups_id $query ;";
        $getLimit = $projectdb->query($query_all_services);

        $count = $getLimit->num_rows;
        $x = 0;

        while ($data = $getLimit->fetch_assoc()) {
            $data['id'] = $x++;
            $myData[] = $data;
        }
        if ($count == 0) {
            $myData = "";
        }
        echo '{"total":"' . $count . '","address":' . json_encode($myData) . '}';
    }
    elseif ($type == "tag") {
        $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        $idx = (string) (isset($_POST['idx']) ? $_POST['idx'] : $_GET['idx']);
        $table_name = (string) (isset($_POST['table_name']) ? $_POST['table_name'] : $_GET['table_name']);

        $vsys = $projectdb->real_escape_string($vsys);
        $source = $projectdb->real_escape_string($source);
        $idx = $projectdb->real_escape_string($idx);
        $table_name = $projectdb->real_escape_string($table_name);

        if ($idx != "") {

            $query = "SELECT tag.name as name, tag.id as id FROM tag, tag_relations 
              WHERE tag_relations.member_lid=".$idx." AND tag_relations.table_name='services' AND tag.id = tag_relations.tag_id";

            $result = $projectdb->query($query);
            $thetag = array();
            $count = 0;

            if ($result->num_rows > 0) {
                while($row = $result->fetch_assoc()){
                    $thetag[] = $row;
                }
                $count = count($thetag);
                if ($thetag == "") {
                    $count = 0;
                    $thetag = "";
                }
            }
            echo '{"total":"' . $count . '","tags":' . json_encode($thetag) . '}';
        }
    }
    elseif ($type == "protocol") {

        $myData[] = array("name" => "TCP", "protocol" => "tcp");
        $myData[] = array("name" => "UDP", "protocol" => "udp");
        if($version >= "8.1"){
            $myData[] = array("name" => "SCTP", "protocol" => "sctp");
        }
        $count = count($myData);

        echo '{"total":"' . $count . '","protocol":' . json_encode($myData) . '}';
    }
} 
elseif ($action == "convert") {
    if ($type == "shared") {
        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        $ids = (string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']);

        $source = $projectdb->real_escape_string($source);
        $ids = $projectdb->real_escape_string($ids);

        $remove_address = array();
        if ($ids != "") {
            take_snapshot_last($project);
            $member_Services = explode(',', $ids);
            $return = convertServicesToShared($source, $member_Services, "notall");
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
            $member_Services = explode(',',$ids);
            $return = cloneServices($source, $vsys, $clone_to_vsys, $member_Services);
            if($return != 0){
                echo json_encode(array("success" => true));
            }else{
                echo json_encode(array("success" => false));
            }  
        }
        
    }
}
?>
