<?php

# Copyright (c) 2014 Palo Alto Networks, Inc.
# All rights reserved.
//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';

require_once INC_ROOT.'/libs/shared.php';

//require_once INC_ROOT.'/libs/common/lib-objects.php';
require_once INC_ROOT.'/userManager/API/projects/manageSettings.php';
require_once INC_ROOT.'/libs/projectdb.php';

ini_set('max_execution_time', PARSER_max_execution_time);
ini_set("memory_limit", PARSER_max_execution_memory);

include INC_ROOT.'/bin/middleware_sanitizer.php';

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $action     = (string)  (isset($_GET['action'])    ? $_GET['action'] : '');
        $type       = (string)  (isset($_GET['type'])      ? $_GET['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_GET['project'])   ? $_GET['project'] : '');
        $start      = (integer) (isset($_GET['start'])     ? $_GET['start'] : '');
        $limit      = (integer) (isset($_GET['limit'])     ? $_GET['limit'] : '');

        $vsys       = (string)  (isset($_GET['vsys'])      ? $_GET['vsys'] : '');
        $source     = (string)  (isset($_GET['source'])    ? $_GET['source'] : '');
        $ids        = (string)  (isset($_GET['ids'])       ? $_GET['ids'] : '');
        $search     = (string)  (isset($_GET['objsearch']) ? $_GET['objsearch'] : '');
        $filter     = (string)  (isset($_GET['objfilter']) ? $_GET['objfilter'] : '');
        $hide_shared= (string)  (isset($_GET['hide_shared_address']) ? $_GET['hide_shared_address'] : '');
        $table_name = (string)  (isset($_GET['table_name'])? $_GET['table_name'] : '');
        $idx        = (string)  (isset($_GET['idx'])       ? $_GET['idx'] : '');
        $name_ext       = (string)  (isset($_GET['name_ext'])      ? $_GET['name_ext'] : '');
        $oldname    = (string)  (isset($_GET['oldname'])   ? $_GET['oldname'] : '');
        $name_int   = (string)  (isset($_GET['name'])   ? $_GET['name'] : '');
        $ipaddress  = (string)  (isset($_GET['ipaddress'])  ? $_GET['ipaddress'] : '');
        $cidr       = (string)  (isset($_GET['cidr'])       ? $_GET['cidr'] : '');
        $description = (string) (isset($_GET['description'])? $_GET['description'] : '');
        $tags       = (string)  (isset($_GET['tags'])       ? $_GET['tags'] : '');
        $clone_to_vsys=(string) (isset($_GET['combo'])      ? $_GET['combo'] : '');
        break;
    case 'POST':
        $action     = (string)  (isset($_POST['action'])    ? $_POST['action'] : '');
        $type       = (string)  (isset($_POST['type'])      ? $_POST['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_POST['project'])   ? $_POST['project'] : '');
        $start      = (integer) (isset($_POST['start'])     ? $_POST['start'] : '');
        $limit      = (integer) (isset($_POST['limit'])     ? $_POST['limit'] : '');

        $vsys       = (string)  (isset($_POST['vsys'])      ? $_POST['vsys'] : '');
        $source     = (string)  (isset($_POST['source'])    ? $_POST['source'] : '');
        $ids        = (string)  (isset($_POST['ids'])       ? $_POST['ids'] : '');
        $search     = (string)  (isset($_POST['objsearch']) ? $_POST['objsearch'] : '');
        $filter     = (string)  (isset($_POST['objfilter']) ? $_POST['objfilter'] : '');
        $hide_shared= (string)  (isset($_POST['hide_shared_address']) ? $_POST['hide_shared_address'] : '');
        $table_name = (string)  (isset($_POST['table_name'])? $_POST['table_name'] : '');
        $idx        = (string)  (isset($_POST['idx'])       ? $_POST['idx'] : '');
        $name_ext       = (string)  (isset($_POST['name_ext'])      ? $_POST['name_ext'] : '');
        $oldname    = (string)  (isset($_POST['oldname'])   ? $_POST['oldname'] : '');

        $name_int   = (string) (isset($_POST['name'])   ? $_POST['name'] : '');
        $ipaddress  = (string) (isset($_POST['ipaddress'])  ? $_POST['ipaddress'] : '');
        $cidr       = (string) (isset($_POST['cidr'])       ? $_POST['cidr'] : '');
        $description = (string)(isset($_POST['description'])? $_POST['description'] : '');
        $tags       = (string) (isset($_POST['tags'])       ? $_POST['tags'] : '');
        $clone_to_vsys=(string) (isset($_POST['combo'])     ? $_POST['combo'] : '');
        break;

    default:
        $action     = (string)  (isset($_POST['action'])    ? $_POST['action'] : '');
        $type       = (string)  (isset($_POST['type'])      ? $_POST['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_POST['project'])   ? $_POST['project'] : '');
        $start      = (integer) (isset($_POST['start'])     ? $_POST['start'] : '');
        $limit      = (integer) (isset($_POST['limit'])     ? $_POST['limit'] : '');

        $vsys       = (string)  (isset($_POST['vsys'])      ? $_POST['vsys'] : '');
        $source     = (string)  (isset($_POST['source'])    ? $_POST['source'] : '');
        $ids        = (string)  (isset($_POST['ids'])       ? $_POST['ids'] : '');
        $search     = (string)  (isset($_POST['objsearch']) ? $_POST['objsearch'] : '');
        $filter     = (string)  (isset($_POST['objfilter']) ? $_POST['objfilter'] : '');
        $hide_shared= (string)  (isset($_POST['hide_shared_address']) ? $_POST['hide_shared_address'] : '');
        $table_name = (string)  (isset($_POST['table_name'])? $_POST['table_name'] : '');
        $idx        = (string)  (isset($_POST['idx'])       ? $_POST['idx'] : '');
        $name_ext       = (string)  (isset($_POST['name_ext'])      ? $_POST['name_ext'] : '');
        $oldname    = (string)  (isset($_POST['oldname'])   ? $_POST['oldname'] : '');
        $name_int   = (string) (isset($_POST['name'])   ? $_POST['name'] : '');
        $ipaddress  = (string) (isset($_POST['ipaddress'])  ? $_POST['ipaddress'] : '');
        $cidr       = (string) (isset($_POST['cidr'])       ? $_POST['cidr'] : '');
        $description = (string)(isset($_POST['description'])? $_POST['description'] : '');
        $tags       = (string) (isset($_POST['tags'])       ? $_POST['tags'] : '');
        $clone_to_vsys=(string) (isset($_POST['combo'])     ? $_POST['combo'] : '');
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
$ids = $projectdb->real_escape_string($ids);
$search = $projectdb->real_escape_string($search);
$filter = $projectdb->real_escape_string($filter);
$hide_shared = $projectdb->real_escape_string($hide_shared);
$table_name = $projectdb->real_escape_string($table_name);
$idx = $projectdb->real_escape_string($idx);
$name_ext = $projectdb->real_escape_string($name_ext);
$oldname = $projectdb->real_escape_string($oldname);
$name_int = $projectdb->real_escape_string($name_int);
$type = $projectdb->real_escape_string($type);
$ipaddress = $projectdb->real_escape_string($ipaddress);
$cidr = $projectdb->real_escape_string($cidr);
$description = $projectdb->real_escape_string($description);
$tags = $projectdb->real_escape_string($tags);
$clone_to_vsys = $projectdb->real_escape_string($clone_to_vsys);

global $app;
$user = $app->container->sentinel->getUser();
$user_id = $user->id;

if ($action == "get") {
    if ($type == "tag") {
        if ($idx != "") {

            $query = "SELECT tag.name as name, tag.id as id FROM tag, tag_relations 
              WHERE tag_relations.member_lid='".$idx."' AND tag_relations.table_name='address' AND tag.id = tag_relations.tag_id";

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
    elseif ($type == "address_static") {
        $query = generate_query("objects");
        if (preg_match("/\bWHERE\b/", $query)) {
            $query = $query . " AND type='ip-netmask' OR type='ip-range' AND dummy=0 ";
        } else {
            $query = " WHERE type='ip-netmask' OR type='ip-range' AND dummy=0 ";
        }
        $getAll = $projectdb->query("SELECT id as idx,name_ext,name,used,id,checkit,devicegroup,vsys,type,ipaddress,cidr,description,fqdn,v4,v6,vtype,source,tag,'address' as table_name FROM address $query ;");
        $count = $getAll->num_rows;
        $getLimit = $projectdb->query("SELECT id as idx,name_ext,name,used,id,checkit,devicegroup,vsys,type,ipaddress,cidr,description,fqdn,v4,v6,vtype,source,tag,'address' as table_name FROM address $query ORDER BY name ASC;");
        $x = 0;
        while ($data = $getLimit->fetch_object()) {
            $data->id = $x++;
            $myData[] = $data;
        }
        if ($count == 0) {
            $myData = "";
        }
        echo '{"total":"' . $count . '","address":' . json_encode($myData) . '}';
    } 
    elseif ($type == "address_all") {
        $query = generate_query("objects");
        $query_all_addresses =
            "SELECT id as idx, name , id, 'regions.png' as type,'default_regions' as table_name, vsys FROM default_regions ".
            "UNION SELECT id as idx, name , id, if (vsys = 'shared', 'shared_regions.png', 'regions.png') AS type, 'regions' as table_name, vsys FROM regions $query ".
            "UNION SELECT id as idx, name , id, if (vsys = 'shared', 'shared_external_list.png', 'external_list.png') AS type, 'external_list' as table_name, vsys FROM external_list $query ".
            "UNION SELECT id as idx, name,id, if (vsys = 'shared', 'shared_address.gif', 'address.gif') AS type, 'address' as table_name, vsys FROM address ".
            "UNION SELECT id as idx, name, id, if (vsys = 'shared', 'shared_address_groups_id.gif', 'address_groups_id.gif') AS type, 'address_groups_id' as table_name, vsys FROM address_groups_id $query ;";
        
        $getLimit = $projectdb->query($query_all_addresses);
        $count = $getLimit->num_rows;
        $x = 0;
        while ($data = $getLimit->fetch_object()) {
            $data->id = $x++;
            $myData[] = $data;
        }
        if ($count == 0) {
            $myData = "";
        }
        echo '{"total":"' . $count . '","address":' . json_encode($myData) . '}';
    } 
    elseif ($type == "address_and_groups") {
        $query = generate_query("objects_vsyses");

        $getLimit = $projectdb->query("SELECT id as idx, name, name_ext, id, if (vsys = 'shared', 'shared_address.gif', 'address.gif') AS type, vsys, (CASE type WHEN 'fqdn' THEN 'fa fa-book' WHEN 'ip-range' THEN 'fa fa-sitemap' ELSE 'fa fa-desktop' END) AS icon, if (vsys = 'shared', '#cf1cbc', '#235585') AS color, 'address' AS table_name FROM address $query "
            . "UNION SELECT id as idx, name, name_ext, id, if (vsys = 'shared', 'shared_address_groups_id.gif', 'address_groups_id.gif') AS type, vsys, if (type = 'static', 'fa fa-object-ungroup', 'fa fa-object-group') AS icon, if (vsys = 'shared', '#cf1cbc', '#235585') AS color, 'address_groups_id' AS table_name FROM address_groups_id $query;");

        $count = $getLimit->num_rows;
        $x = 0;
        while ($data = $getLimit->fetch_object()) {
            $data->id = $x++;
            $myData[] = $data;
        }
        if ($count == 0) {
            $myData = "";
        }
        echo '{"total":"' . $count . '","address":' . json_encode($myData) . '}';
    } 
    elseif ($type == "address_not_groups") {
        $query = generate_query("objects");
        if (preg_match("/WHERE/", $query)) {
            $query = $query . " AND dummy=0 ";
        } else {
            $query = $query . " WHERE dummy=0 ";
        }
        $getLimit = $projectdb->query("SELECT id, name, vsys FROM address $query AND type != 'fqdn'  ;");
        $count = $getLimit->num_rows;

        while ($data = $getLimit->fetch_object()) {

            $myData[] = $data;
        }
        if ($count == 0) {
            $myData = "";
        }
        echo '{"total":"' . $count . '","address":' . json_encode($myData) . '}';
    } 
    elseif ($type == "address_and_groups_and_external") {
        $query = generate_query("objects");
        $getLimit = $projectdb->query("SELECT id as idx, name , id, if (vsys = 'shared', 'shared_external_list.png', 'external_list.png') AS type, 'external_list' as table_name, vsys FROM external_list $query "
                . "UNION SELECT id as idx,name,id, if (vsys = 'shared', 'shared_address.gif', 'address.gif') AS type, 'address' as table_name, vsys FROM address $query "
                . "UNION SELECT id as idx, name, id, if (vsys = 'shared', 'shared_address_groups_id.gif', 'address_groups_id.gif') AS type, 'address_groups_id' as table_name, vsys FROM address_groups_id $query ;");
        $count = $getLimit->num_rows;
        $x = 0;
        while ($data = $getLimit->fetch_object()) {
            $data->id = $x++;
            $myData[] = $data;
        }
        if ($count == 0) {
            $myData = "";
        }
        echo '{"total":"' . $count . '","address":' . json_encode($myData) . '}';
    }
    elseif ($type == "address_only_fqdn") {
        $query = generate_query("objects");
        if (preg_match("/WHERE/", $query)) {
            $query = $query . " AND dummy=0 ";
        } else {
            $query = $query . " WHERE dummy=0 ";
        }
        $getLimit = $projectdb->query("SELECT id, name, type, 'address' as table_name, vsys FROM address $query AND type = 'fqdn' ;");
        $count = $getLimit->num_rows;

        while ($data = $getLimit->fetch_object()) {

            $myData[] = $data;
        }
        if ($count == 0) {
            $myData = "";
        }
        echo '{"total":"' . $count . '","address":' . json_encode($myData) . '}';
    }
}
elseif ($action == "convert") {
    if ($type == "shared") {

        if ($ids != "") {
            take_snapshot_last($project);
            $members_Address = explode(',', $ids);
            $return = convertAddressToShared($source, $members_Address, "notall");
            if($return == 1){
                echo json_encode(array("success" => true));
            }else{
                echo json_encode(array("success" => false));
            }  
        }
        
    }
    elseif ($type == "clone") {

        if ($ids != "") {
            take_snapshot_last($project);
            
            $members_Address = explode(',',$ids);
            $return = cloneAddress($source, $vsys, $clone_to_vsys, $members_Address);

            if($return != 0){
                echo json_encode(array("success" => true));
            }else{
                echo json_encode(array("success" => false));
            }  
        }
    }
}
?>