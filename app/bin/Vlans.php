<?php

# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
require_once('./Authentication.php');
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';
require_once INC_ROOT.'/libs/shared.php';
require_once INC_ROOT.'/userManager/API/projects/manageSettings.php';
require_once INC_ROOT.'/libs/projectdb.php';
require_once INC_ROOT.'/libs/common/tools/filters.php';

include INC_ROOT.'/bin/middleware_sanitizer.php';

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $action     = (string)  (isset($_GET['action'])     ? $_GET['action'] : '');
        $type       = (string)  (isset($_GET['type'])       ? $_GET['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_GET['project'])    ? $_GET['project'] : '');
        $devicename = (string)  (isset($_GET['devicename']) ? $_GET['devicename'] : '');
        $template   = (string)  (isset($_GET['template'])   ? $_GET['template'] : '');
        $source     = (string)  (isset($_GET['source'])     ? $_GET['source'] : '');
        $vsys       = (string)  (isset($_GET['vsys'])       ? $_GET['vsys'] : '');
        $filter     = (string)  (isset($_GET['filter'])     ? $_GET['filter'] : '');
        $start      = (integer) (isset($_GET['start'])      ? $_GET['start'] : '');
        $limit      = (integer) (isset($_GET['limit'])      ? $_GET['limit'] : '');
        break;
    case 'POST':
        $action     = (string)  (isset($_POST['action'])     ? $_POST['action'] : '');
        $type       = (string)  (isset($_POST['type'])       ? $_POST['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_POST['project'])    ? $_POST['project'] : '');
        $devicename = (string)  (isset($_POST['devicename']) ? $_POST['devicename'] : '');
        $template   = (string)  (isset($_POST['template'])   ? $_POST['template'] : '');
        $source     = (string)  (isset($_POST['source'])    ? $_POST['source'] : '');
        $vsys       = (string)  (isset($_POST['vsys'])      ? $_POST['vsys'] : '');
        $filter     = (string)  (isset($_POST['filter'])    ? $_POST['filter'] : '');
        $start      = (integer) (isset($_POST['start'])      ? $_POST['start'] : '');
        $limit      = (integer) (isset($_POST['limit'])      ? $_POST['limit'] : '');
        break;
    default:
        $action     = (string)  (isset($_POST['action'])     ? $_POST['action'] : '');
        $type       = (string)  (isset($_POST['type'])       ? $_POST['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_POST['project'])    ? $_POST['project'] : '');
        $devicename = (string)  (isset($_POST['devicename']) ? $_POST['devicename'] : '');
        $template   = (string)  (isset($_POST['template'])   ? $_POST['template'] : '');
        $source     = (string)  (isset($_POST['source'])    ? $_POST['source'] : '');
        $vsys       = (string)  (isset($_POST['vsys'])      ? $_POST['vsys'] : '');
        $filter     = (string)  (isset($_POST['filter'])    ? $_POST['filter'] : '');
        $start      = (integer) (isset($_POST['start'])      ? $_POST['start'] : '');
        $limit      = (integer) (isset($_POST['limit'])      ? $_POST['limit'] : '');
        break;
}

$projectdb = selectDatabase($project);

$action = $projectdb->real_escape_string($action);
$type = $projectdb->real_escape_string($type);
$project = $projectdb->real_escape_string($project);
$devicename = $projectdb->real_escape_string($devicename);
$template = $projectdb->real_escape_string($template);
$source = $projectdb->real_escape_string($source);
$vsys = $projectdb->real_escape_string($vsys);
$filter = $projectdb->real_escape_string($filter);
$start = $projectdb->real_escape_string($start);
$limit = $projectdb->real_escape_string($limit);

global $app;
$user = $app->container->sentinel->getUser();
$user_id = $user->id;

if ($action == "get") {
    if ($type == "vlans") {

        $query = generate_query("template_not_vsys");

        if(($filter != "none") && ($filter != "0")){

            $params['tools_where_columns_id'] = $filter;
            $params['tools_operator_id'] = "contains";
            $params['search'] = "";
            $params['tools_where_id'] = "22";
            $params['tools_advanced_columns_id'] = "None";
            $params['is_set_sql_filter'] = "yes";
            $params['source'] = $source;
            $params['vsys'] = $vsys;
            $params['case_sensitive'] = "0";

            setFilter($project, $params);
            executeSQL($project, $params);

        }
        elseif(($filter == "none") || ($filter == "0")){
        }

        list($query, $orderby) = generateQueryFilters($project, "vlans", "", $query, $source);

        $getAll = $projectdb->query("SELECT source,vsys,template,name,id,interface as interfaces,mac,virtual_interface,l3_forwarding FROM vlans $query ORDER BY id,name;");
        $count = $getAll->num_rows;
        $getAll = $projectdb->query("SELECT source,vsys,template,name,id,interface as interfaces,mac,virtual_interface,l3_forwarding FROM vlans $query ORDER BY id,name LIMIT $start, $limit;");
        if ($count > 0) {
            
            while ($data = $getAll->fetch_object()) {
                if($data->l3_forwarding == "yes"){$data->l3_forwarding = "on";}
                $myData[] = $data;
            }
        } else {
            $myData = "";
        }
        echo '{"total":"' . $count . '","interfaces":' . json_encode($myData) . '}';
    }
    elseif ($type == "vsys_vlans") {

        $query = generate_query("template_not_vsys");

        $getAll = $projectdb->query("SELECT source,vsys,template,name,id FROM vlans $query ORDER BY id,name;");
        $count = $getAll->num_rows;
        if ($count > 0) {
            $myData[] = array("name" => "All VLANs");
            while ($data = $getAll->fetch_object()) {
                $myData[] = $data;
            }
        } else {
            $myData = "";
        }
        echo '{"total":"' . $count . '","interfaces":' . json_encode($myData) . '}';
    }
    elseif ($type == "interfaces_vlans") {
        
        //$query = generate_query("template");
        $query = "";
//        if (preg_match("/WHERE/i", $query)) {
//            $query = $query . " AND template = '$template' AND source = '$source' AND media = 'vlan' ";
//        } else {
//            $query = " WHERE template = '$template' ";
//        }
//        
//        if (preg_match("/WHERE/i", $query)) {
//            $query = $query . " AND source = '$source' ";
//        } else {
//            $query = " WHERE source = '$source'";
//        }
//        
//        if (preg_match("/WHERE/i", $query)) {
//            $query = $query . " AND media = 'vlan' ";
//        } else {
//            $query = " WHERE media = 'vlan'";
//        }
        
        $getAll = $projectdb->query("SELECT source, vsys, template, unitname, id FROM interfaces WHERE template = '$template' AND source = '$source' AND media = 'vlan' ORDER BY id, unitname;");
        //echo "SELECT source, vsys, template, unitname, id FROM interfaces WHERE template = '$template' AND source = '$source' AND media = 'vlan'  ORDER BY id, unitname;\n";
        $count = $getAll->num_rows;
        if ($count > 0) {
            while ($data = $getAll->fetch_assoc()) {
                $myData[] = $data;
            }
        } else {
            $myData = "";
        }
        echo '{"total":"' . $count . '","interfaces":' . json_encode($myData) . '}';
    }
    elseif ($type == "interfaces_layer2_name") {
        
        //$query = generate_query("template");
        $query = generate_query("template_not_vsys");
        
        if (preg_match("/WHERE/i", $query)) {
            $query = $query . " AND type = 'layer2' ";
        } else {
            $query = " WHERE type = 'layer2'";
        }
        
        $getAll = $projectdb->query("SELECT source, vsys, template, unitname, id FROM interfaces $query ORDER BY id, unitname;");
        $count = $getAll->num_rows;
        if ($count > 0) {
            while ($data = $getAll->fetch_assoc()) {
                $myData[] = $data;
            }
        } else {
            $myData = "";
        }
        echo '{"total":"' . $count . '","interfaces":' . json_encode($myData) . '}';
    }
    elseif ($type == "interfaces_layer2"){
        switch($_SERVER['REQUEST_METHOD'])
        {
            case 'GET':
                $vsys = (string) (isset($_GET['vsys']) ? $_GET['vsys'] : '');
                $idx  = (string) (isset($_GET['idx'])  ? $_GET['idx'] : '');
                break;
            case 'POST':
                $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : '');
                $idx  = (string) (isset($_POST['idx'])  ? $_POST['idx'] : '');
                break;
            default:
                $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : '');
                $idx  = (string) (isset($_POST['idx'])  ? $_POST['idx'] : '');
                break;
        }

        $vsys = $projectdb->real_escape_string($vsys);
        $idx = $projectdb->real_escape_string($idx);

        if($idx == ""){
            $idx = 0;
        }
        
        $address = array();
        $getAddress = $projectdb->query("SELECT interface FROM vlans WHERE id = '$idx' AND interface != '';");
        if ($getAddress->num_rows == 1) {
            $dataA = $getAddress->fetch_assoc();
            $add = $dataA['interface'];
            $add_explode = explode(",", $add);
            $count = count($add_explode);
            foreach ($add_explode as $key => $value) {

                $getBridgeId = $projectdb->query("SELECT id FROM edit_table WHERE name = '$value' AND type = 'interfaces_layer2' AND lid = '$idx' AND user_id = '$user_id';");
                if ($getBridgeId->num_rows == 0) {
                    $getBridgeId = $projectdb->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'interfaces_layer2' AND lid = '$idx' AND user_id = '$user_id';");
                    if ($getBridgeId->num_rows == 1) {
                       $getIdData = $getBridgeId->fetch_assoc();
                       $ids = $getIdData['ids'] + 1;
                    }else{
                        $ids = 1;
                    }
                    $projectdb->query("INSERT INTO edit_table (id, ids, lid, type, name, source, remove, user_id) "
                        . "VALUES (NULL, '$ids', '$idx', 'interfaces_layer2', '$value', '$template', '0', '$user_id');");
                }

            }
            if ($add == "") {
                $count = 0;
                $address = "";
            }
            else{
                $getLimit = $projectdb->query("SELECT id, ids, name FROM edit_table WHERE type = 'interfaces_layer2' AND remove = '0' AND user_id = '$user_id' ORDER BY ids;");
                $count = $getLimit->num_rows;
                if ($getLimit->num_rows > 0) {
                    while ($data = $getLimit->fetch_object()) {
                        $address[] = $data;
                    }
                }
            }
            echo '{"total":"' . $count . '","interfaces":' . json_encode($address) . '}';
        }
        else{
            $getLimit = $projectdb->query("SELECT id, ids, name FROM edit_table WHERE type = 'interfaces_layer2' AND remove = '0' AND user_id = '$user_id' ORDER BY ids;");
            $count = $getLimit->num_rows;
            if ($getLimit->num_rows > 0) {
                while ($data = $getLimit->fetch_object()) {
                    $address[] = $data;
                }
            }
            echo '{"total":"' . $count . '","interfaces":' . json_encode($address) . '}';
        }

    }
    elseif ($type == "interfaces_mac"){
        switch($_SERVER['REQUEST_METHOD'])
        {
            case 'GET':
                $vsys = (string) (isset($_GET['vsys']) ? $_GET['vsys'] : '');
                $idx  = (string) (isset($_GET['idx'])  ? $_GET['idx'] : '');
                break;
            case 'POST':
                $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : '');
                $idx  = (string) (isset($_POST['idx'])  ? $_POST['idx'] : '');
                break;
            default:
                $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : '');
                $idx  = (string) (isset($_POST['idx'])  ? $_POST['idx'] : '');
                break;
        }

        $vsys = $projectdb->real_escape_string($vsys);
        $idx = $projectdb->real_escape_string($idx);
        
        if($idx == ""){
            $idx = 0;
        }
        $address = array();
        $getAddress = $projectdb->query("SELECT mac_interfaces, mac FROM vlans WHERE id = '$idx' AND mac_interfaces != '';");
        if ($getAddress->num_rows == 1) {
            $dataA = $getAddress->fetch_assoc();
            $add = $dataA['mac_interfaces'];
            $add2 = $dataA['mac'];
            $add_explode = explode(",", $add);
            $add_explode2 = explode(",", $add2);
            $count = count($add_explode);
            $index_array = 0;
            foreach ($add_explode2 as $key => $value2) {

                $getBridgeId = $projectdb->query("SELECT id FROM edit_table WHERE name = '$value2' AND type = 'mac' AND lid = '$idx' AND user_id = '$user_id';");
                if ($getBridgeId->num_rows == 0) {
                    $getBridgeId = $projectdb->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'mac' AND lid = '$idx' AND user_id = '$user_id';");
                    if ($getBridgeId->num_rows == 1) {
                       $getIdData = $getBridgeId->fetch_assoc();
                       $ids = $getIdData['ids'] + 1;
                    }else{
                        $ids = 1;
                    }
                    $projectdb->query("INSERT INTO edit_table (id, ids, lid, type, name, source, remove, user_id) "
                        . "VALUES (NULL, '$ids', '$idx', 'mac', '$value2', '$template', '0', '$user_id');");

                    $projectdb->query("INSERT INTO edit_table (id, ids, lid, type, name, source, remove, user_id) "
                        . "VALUES (NULL, '$ids', '$idx', 'interfaces_mac', '$add_explode[$index_array]', '$template', '0', '$user_id');");
                }
                $index_array ++;

            }
            if ($add == "") {
                $count = 0;
                $address = "";
            }
            else{
                $getLimit = $projectdb->query("SELECT id, ids, name FROM edit_table WHERE type = 'interfaces_mac' AND remove = '0' AND user_id = '$user_id' ORDER BY ids;");
                $count = $getLimit->num_rows;
                if ($getLimit->num_rows > 0) {
                    while ($data = $getLimit->fetch_object()) {
                        $interfaces_mac = $data->name;
                        $getLimit2 = $projectdb->query("SELECT id, ids, name AS name2 FROM edit_table WHERE type = 'mac' AND remove = '0' AND ids = '$data->ids' AND user_id = '$user_id';");
                        if ($getLimit2->num_rows > 0) {
                            $data2 = $getLimit2->fetch_object();
                            $mac_address = $data2->name2;
                        }
                        $address[] = array("ids" => $data->ids, "interfaces_mac" => $interfaces_mac, "mac" => $mac_address);
                    }
                }

            }
            echo '{"total":"' . $count . '","interfaces":' . json_encode($address) . '}';
        }
        else{
            $getLimit = $projectdb->query("SELECT id, ids, name FROM edit_table WHERE type = 'interfaces_mac' AND remove = '0' AND user_id = '$user_id' ORDER BY ids;");
            if ($getLimit->num_rows > 0) {
                while ($data = $getLimit->fetch_object()) {
                    $interfaces_mac = $data->name;
                    $getLimit2 = $projectdb->query("SELECT id, ids, name AS name2 FROM edit_table WHERE type = 'mac' AND remove = '0' AND ids = '$data->ids' AND user_id = '$user_id';");
                    if ($getLimit2->num_rows > 0) {
                        $data2 = $getLimit2->fetch_object();
                        $mac_address = $data2->name2;
                    }
                    $address[] = array("ids" => $data->ids, "interfaces_mac" => $interfaces_mac, "mac" => $mac_address);
                }
            }
            echo '{"total":"' . count($address) . '","interfaces":' . json_encode($address) . '}';
        }

    }
} 
elseif ($action == "add") {
    if ($type == "vlans") {
        $projectdb->query("INSERT INTO vlans (template,source) VALUES ('$template','$source')");
        echo json_encode(array("success" => true));
    }
    elseif ($type == "interfaces_layer2"){
        switch($_SERVER['REQUEST_METHOD'])
        {
            case 'GET':
                $vsys = (string) (isset($_GET['vsys']) ? $_GET['vsys'] : '');
                $source =(string)(isset($_GET['source'])? $_GET['source'] : '');
                $idx  = (string) (isset($_GET['idx'])  ? $_GET['idx'] : '');
                $name = (string) (isset($_GET['name']) ? $_GET['name'] : '');
                break;
            case 'POST':
                $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : '');
                $source =(string)(isset($_POST['source'])? $_POST['source'] : '');
                $idx  = (string) (isset($_POST['idx'])  ? $_POST['idx'] : '');
                $name = (string) (isset($_POST['name']) ? $_POST['name'] : '');
                break;
            default:
                $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : '');
                $source =(string)(isset($_POST['source'])? $_POST['source'] : '');
                $idx  = (string) (isset($_POST['idx'])  ? $_POST['idx'] : '');
                $name = (string) (isset($_POST['name']) ? $_POST['name'] : '');
                break;
        }

        $vsys = $projectdb->real_escape_string($vsys);
        $source = $projectdb->real_escape_string($source);
        $idx = $projectdb->real_escape_string($idx);
        $name = $projectdb->real_escape_string($name);

        if($idx == ""){
            $idx = 0;
        }
        
        $getBridge = $projectdb->query("SELECT id FROM edit_table WHERE type = 'interfaces_layer2' AND name = '$name' AND user_id = '$user_id';");
        if ($getBridge->num_rows == 0) {

            $getBridgeId = $projectdb->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'interfaces_layer2' AND lid = '$idx' AND user_id = '$user_id';");
            if ($getBridgeId->num_rows == 1) {
               $getIdData = $getBridgeId->fetch_assoc();
               $ids = $getIdData['ids'] + 1;
            }else{
                $ids = 1;
            }

            $projectdb->query("INSERT INTO edit_table (id, ids, lid, type, name, source, remove, user_id) "
                . "VALUES (NULL, '$ids', '$idx', 'interfaces_layer2', '$name', '$template', '0', '$user_id');");
        }else{
            $projectdb->query("UPDATE edit_table SET remove = '0' WHERE name = '$name' AND type = 'interfaces_layer2' AND lid = '$idx' AND user_id = '$user_id';");
        }
        
    }
    elseif ($type == "interfaces_mac"){
        switch($_SERVER['REQUEST_METHOD'])
        {
            case 'GET':
                $vsys = (string) (isset($_GET['vsys']) ? $_GET['vsys'] : '');
                $source =(string)(isset($_GET['source'])? $_GET['source'] : '');
                $idx  = (string) (isset($_GET['idx'])  ? $_GET['idx'] : '');
                $mac = (string) (isset($_GET['mac']) ? $_GET['mac'] : '');
                $interfaces_mac = (string) (isset($_GET['interfaces_mac']) ? $_GET['interfaces_mac'] : '');
                break;
            case 'POST':
                $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : '');
                $source =(string)(isset($_POST['source'])? $_POST['source'] : '');
                $idx  = (string) (isset($_POST['idx'])  ? $_POST['idx'] : '');
                $mac = (string) (isset($_POST['mac']) ? $_POST['mac'] : '');
                $interfaces_mac = (string) (isset($_POST['interfaces_mac']) ? $_POST['interfaces_mac'] : '');
                break;
            default:
                $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : '');
                $source =(string)(isset($_POST['source'])? $_POST['source'] : '');
                $idx  = (string) (isset($_POST['idx'])  ? $_POST['idx'] : '');
                $mac = (string) (isset($_POST['mac']) ? $_POST['mac'] : '');
                $interfaces_mac = (string) (isset($_POST['interfaces_mac']) ? $_POST['interfaces_mac'] : '');
                break;
        }

        $vsys = $projectdb->real_escape_string($vsys);
        $source = $projectdb->real_escape_string($source);
        $idx = $projectdb->real_escape_string($idx);
        $mac = $projectdb->real_escape_string($mac);
        $interfaces_mac = $projectdb->real_escape_string($interfaces_mac);

        $mac = htmlspecialchars($mac);

        if(($mac != "") && ($interfaces_mac != "")){
            
            $getBridge = $projectdb->query("SELECT id FROM edit_table WHERE type = 'mac' AND name = '$mac' AND user_id = '$user_id';");
            if ($getBridge->num_rows == 0) {

                $getBridgeId = $projectdb->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'mac' AND lid = '$idx' AND user_id = '$user_id';");
                if ($getBridgeId->num_rows == 1) {
                   $getIdData = $getBridgeId->fetch_assoc();
                   $ids = $getIdData['ids'] + 1;
                }else{
                    $ids = 1;
                }

                $projectdb->query("INSERT INTO edit_table (id, ids, lid, type, name, source, remove, user_id) "
                    . "VALUES (NULL, '$ids', '$idx', 'mac', '$mac', '$template', '0', '$user_id');");
            }else{
                $projectdb->query("UPDATE edit_table SET remove = '0' WHERE name = '$mac' AND type = 'mac' AND lid = '$idx' AND user_id = '$user_id';");
            }

            $getBridgeId = $projectdb->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'interfaces_mac' AND lid = '$idx' AND user_id = '$user_id';");
            if ($getBridgeId->num_rows == 1) {
               $getIdData = $getBridgeId->fetch_assoc();
               $ids = $getIdData['ids'] + 1;
            }else{
                $ids = 1;
            }

            $projectdb->query("INSERT INTO edit_table (id, ids, lid, type, name, source, remove, user_id) "
                . "VALUES (NULL, '$ids', '$idx', 'interfaces_mac', '$interfaces_mac', '$template', '0', '$user_id');");

        }
    }
} 
elseif ($action == "update") {
    if ($type == "interfaces_layer2"){
        switch($_SERVER['REQUEST_METHOD'])
        {
            case 'GET':
                $vsys       = (string) (isset($_GET['vsys'])       ? $_GET['vsys'] : '');
                $source     = (string)(isset($_GET['source'])      ? $_GET['source'] : '');
                $idx        = (string) (isset($_GET['idx'])        ? $_GET['idx'] : '');
                $template   = (string) (isset($_GET['template'])   ? $_GET['template'] : '');
                $ids        = (string) (isset($_GET['ids'])        ? $_GET['ids'] : '');
                $name       = (string) (isset($_GET['name'])       ? $_GET['name'] : '');
                $oldname    = (string) (isset($_GET['oldname'])    ? $_GET['oldname'] : '');
                break;
            case 'POST':
                $vsys       = (string) (isset($_POST['vsys'])       ? $_POST['vsys'] : '');
                $source     = (string)(isset($_POST['source'])      ? $_POST['source'] : '');
                $idx        = (string) (isset($_POST['idx'])        ? $_POST['idx'] : '');
                $template   = (string) (isset($_POST['template'])   ? $_POST['template'] : '');
                $ids        = (string) (isset($_POST['ids'])        ? $_POST['ids'] : '');
                $name       = (string) (isset($_POST['name'])       ? $_POST['name'] : '');
                $oldname    = (string) (isset($_POST['oldname'])    ? $_POST['oldname'] : '');
                break;
            default:
                $vsys       = (string) (isset($_POST['vsys'])       ? $_POST['vsys'] : '');
                $source     = (string)(isset($_POST['source'])      ? $_POST['source'] : '');
                $idx        = (string) (isset($_POST['idx'])        ? $_POST['idx'] : '');
                $template   = (string) (isset($_POST['template'])   ? $_POST['template'] : '');
                $ids        = (string) (isset($_POST['ids'])        ? $_POST['ids'] : '');
                $name       = (string) (isset($_POST['name'])       ? $_POST['name'] : '');
                $oldname    = (string) (isset($_POST['oldname'])    ? $_POST['oldname'] : '');
                break;
        }

        $vsys = $projectdb->real_escape_string($vsys);
        $source = $projectdb->real_escape_string($source);
        $idx = $projectdb->real_escape_string($idx);
        $template = $projectdb->real_escape_string($template);
        $ids = $projectdb->real_escape_string($ids);
        $name = $projectdb->real_escape_string($name);
        $oldname = $projectdb->real_escape_string($oldname);
        
        if($idx == ""){
            $idx = 0;
        }
        if (($name != "") AND ($oldname != "")){
            
            $projectdb->query("UPDATE edit_table SET remove = '1' WHERE lid = '$idx' AND type = 'interfaces_layer2' AND name = '$oldname' AND user_id = '$user_id';");
            
            $getExistRemove = $projectdb->query("SELECT id FROM edit_table WHERE name = '$name' AND type = 'interfaces_layer2' AND lid = '$idx' AND remove = '1' AND user_id = '$user_id';");
            if($getExistRemove->num_rows == 1){
                $dataExist = $getExistRemove->fetch_assoc();
                $id_exist = $dataExist['id'];
                $projectdb->query("UPDATE edit_table SET remove = '0' WHERE id = '$id_exist' AND user_id = '$user_id';");
            }else{
                $getExistRemove = $projectdb->query("SELECT id FROM edit_table WHERE name = '$name' AND type = 'interfaces_layer2' AND lid = '$idx' AND remove = '0' AND user_id = '$user_id';");
                if($getExistRemove->num_rows == 0){
                    $getBridgeId = $projectdb->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'interfaces_layer2' AND user_id = '$user_id';");
                    if ($getBridgeId->num_rows == 1) {
                       $getIdData = $getBridgeId->fetch_assoc();
                       $ids = $getIdData['ids'] + 1;
                    }else{
                        $ids = 1;
                    }
                    $projectdb->query("INSERT INTO edit_table (id, ids, lid,type, name, source, remove, user_id) "
                        . "VALUES (NULL, '$ids', '$idx', 'interfaces_layer2', '$name', '$template', '0', '$user_id');");
                }
                
            }
            
            echo json_encode(array("success"=>true));
        }
        else{
            echo json_encode(array("success"=>false));
        }
        
    }
    elseif ($type == "interfaces_mac"){
        switch($_SERVER['REQUEST_METHOD'])
        {
            case 'GET':
                $vsys       = (string) (isset($_GET['vsys'])       ? $_GET['vsys'] : '');
                $source     = (string)(isset($_GET['source'])      ? $_GET['source'] : '');
                $idx        = (string) (isset($_GET['idx'])        ? $_GET['idx'] : '');
                $template   = (string) (isset($_GET['template'])   ? $_GET['template'] : '');
                $ids        = (string) (isset($_GET['ids'])        ? $_GET['ids'] : '');
                $mac        = (string) (isset($_GET['mac'])        ? $_GET['mac'] : '');
                $interfaces_mac = (string) (isset($_GET['interfaces_mac']) ? $_GET['interfaces_mac'] : '');
                $oldname    = (string) (isset($_GET['oldname'])    ? $_GET['oldname'] : '');
                break;
            case 'POST':
                $vsys       = (string) (isset($_POST['vsys'])       ? $_POST['vsys'] : '');
                $source     = (string)(isset($_POST['source'])      ? $_POST['source'] : '');
                $idx        = (string) (isset($_POST['idx'])        ? $_POST['idx'] : '');
                $template   = (string) (isset($_POST['template'])   ? $_POST['template'] : '');
                $ids        = (string) (isset($_POST['ids'])        ? $_POST['ids'] : '');
                $mac        = (string) (isset($_POST['mac'])        ? $_POST['mac'] : '');
                $interfaces_mac = (string) (isset($_POST['interfaces_mac']) ? $_POST['interfaces_mac'] : '');
                $oldname    = (string) (isset($_POST['oldname'])    ? $_POST['oldname'] : '');
                break;
            default:
                $vsys       = (string) (isset($_POST['vsys'])       ? $_POST['vsys'] : '');
                $source     = (string)(isset($_POST['source'])      ? $_POST['source'] : '');
                $idx        = (string) (isset($_POST['idx'])        ? $_POST['idx'] : '');
                $template   = (string) (isset($_POST['template'])   ? $_POST['template'] : '');
                $ids        = (string) (isset($_POST['ids'])        ? $_POST['ids'] : '');
                $mac        = (string) (isset($_POST['mac'])        ? $_POST['mac'] : '');
                $interfaces_mac = (string) (isset($_POST['interfaces_mac']) ? $_POST['interfaces_mac'] : '');
                $oldname    = (string) (isset($_POST['oldname'])    ? $_POST['oldname'] : '');
                break;
        }

        $vsys = $projectdb->real_escape_string($vsys);
        $source = $projectdb->real_escape_string($source);
        $idx = $projectdb->real_escape_string($idx);
        $template = $projectdb->real_escape_string($template);
        $ids = $projectdb->real_escape_string($ids);
        $mac = $projectdb->real_escape_string($mac);
        $interfaces_mac = $projectdb->real_escape_string($interfaces_mac);
        $oldname = $projectdb->real_escape_string($oldname);
        
        if($idx == ""){
            $idx = 0;
        }
        if (($mac != "") AND ($oldname != "") AND ($interfaces_mac != "")){
            
            $getExistRemove = $projectdb->query("SELECT ids FROM edit_table WHERE name = '$oldname' AND type = 'mac' AND lid = '$idx' AND user_id = '$user_id';");
            
            if($getExistRemove->num_rows == 1){
                
                $dataExist = $getExistRemove->fetch_assoc();
                $ids_exist = $dataExist['ids'];
                
                $projectdb->query("UPDATE edit_table SET remove = '1' WHERE lid = '$idx' AND type = 'mac' AND name = '$oldname' AND ids = '$ids_exist' AND user_id = '$user_id';");
                $projectdb->query("UPDATE edit_table SET remove = '1' WHERE lid = '$idx' AND type = 'interfaces_mac' AND ids = '$ids_exist' AND user_id = '$user_id';");
            
                $getBridgeId = $projectdb->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'mac' AND user_id = '$user_id';");
                if ($getBridgeId->num_rows == 1) {
                   $getIdData = $getBridgeId->fetch_assoc();
                   $ids = $getIdData['ids'] + 1;
                }else{
                    $ids = 1;
                }
                
                $projectdb->query("INSERT INTO edit_table (id, ids, lid,type, name, source, remove, user_id) "
                . "VALUES (NULL, '$ids', '$idx', 'mac', '$mac', '$template', '0', '$user_id');");
                
                $projectdb->query("INSERT INTO edit_table (id, ids, lid,type, name, source, remove, user_id) "
                . "VALUES (NULL, '$ids', '$idx', 'interfaces_mac', '$interfaces_mac', '$template', '0', '$user_id');");
                
                echo json_encode(array("success"=>true));
                
            }
            
        }
        else{
            echo json_encode(array("success"=>false));
        }
        
    }
    elseif ($type == "vlans") {
        switch($_SERVER['REQUEST_METHOD'])
        {
            case 'GET':
                $id         = (string) (isset($_GET['idx']) ? $_GET['idx'] : '');
                $name       = (string) (isset($_GET['name']) ? $_GET['name'] : '');
                $interfaces = (string) (isset($_GET['interfaces']) ? $_GET['interfaces'] : '');
                $mac        = (string) (isset($_GET['mac']) ? $_GET['mac'] : '');
                $virtual_interface = (string) (isset($_GET['virtual_interface']) ? $_GET['virtual_interface'] : '');
                $l3_forwarding = (string) (isset($_GET['l3_forwarding']) ? $_GET['l3_forwarding'] : '');
                break;
            case 'POST':
                $id         = (string) (isset($_POST['idx']) ? $_POST['idx'] : '');
                $name       = (string) (isset($_POST['name']) ? $_POST['name'] : '');
                $interfaces = (string) (isset($_POST['interfaces']) ? $_POST['interfaces'] : '');
                $mac        = (string) (isset($_POST['mac']) ? $_POST['mac'] : '');
                $virtual_interface = (string) (isset($_POST['virtual_interface']) ? $_POST['virtual_interface'] : '');
                $l3_forwarding = (string) (isset($_POST['l3_forwarding']) ? $_POST['l3_forwarding'] : '');
                break;
            default:
                $id         = (string) (isset($_POST['idx']) ? $_POST['idx'] : '');
                $name       = (string) (isset($_POST['name']) ? $_POST['name'] : '');
                $interfaces = (string) (isset($_POST['interfaces']) ? $_POST['interfaces'] : '');
                $mac        = (string) (isset($_POST['mac']) ? $_POST['mac'] : '');
                $virtual_interface = (string) (isset($_POST['virtual_interface']) ? $_POST['virtual_interface'] : '');
                $l3_forwarding = (string) (isset($_POST['l3_forwarding']) ? $_POST['l3_forwarding'] : '');
                break;
        }

        $id = $projectdb->real_escape_string($id);
        $name = $projectdb->real_escape_string($name);
        $interfaces = $projectdb->real_escape_string($interfaces);
        $mac = $projectdb->real_escape_string($mac);
        $virtual_interface = $projectdb->real_escape_string($virtual_interface);
        $l3_forwarding = $projectdb->real_escape_string($l3_forwarding);

        take_snapshot_last($project);

        $is_new = 0;

        if ($id == ""){
            $projectdb->query("INSERT INTO vlans (template,source) VALUES ('$template','$source')");
            $id = $projectdb->insert_id; 
            $is_new = 1;
            $projectdb->query("UPDATE edit_table SET lid = '$id' WHERE user_id = '$user_id';");
        }
            
        $interfaces_layer2_array = array();
        $interfaces_mac_array = array();
        $mac_array = array();

        $getInterfacesLayer2 = $projectdb->query("SELECT name FROM edit_table WHERE type = 'interfaces_layer2' AND lid = '$id' AND remove = '0' AND user_id = '$user_id' ORDER BY ids ASC;");
        if($getInterfacesLayer2->num_rows > 0){
            while($dataIL = $getInterfacesLayer2->fetch_assoc()){
                $interfaces_layer2_array[] = $dataIL['name'];
            }
        }

        $getInterfacesMac = $projectdb->query("SELECT name FROM edit_table WHERE type = 'interfaces_mac' AND lid = '$id' AND remove = '0' AND user_id = '$user_id' ORDER BY ids ASC;");
        if($getInterfacesMac->num_rows > 0){
            while($dataIM = $getInterfacesMac->fetch_assoc()){
                $interfaces_mac_array[] = $dataIM['name'];
            }
        }

        $getMac = $projectdb->query("SELECT name FROM edit_table WHERE type = 'mac' AND lid = '$id' AND remove = '0' AND user_id = '$user_id' ORDER BY ids ASC;");
        if($getMac->num_rows > 0){
            while($dataM = $getMac->fetch_assoc()){
                $mac_array[] = $dataM['name'];
            }
        }

        // Check the name doesn't exist!
        $getExistName = $projectdb->query("SELECT name FROM vlans WHERE id != '$id' AND BINARY name = '$name' AND source = '$source' AND template = '$template';");
        if ($getExistName->num_rows == 0){

            $getNameOld = $projectdb->query("SELECT name FROM vlans WHERE id = '$id';");
            if($getNameOld->num_rows > 0){
                $dataNO = $getNameOld->fetch_assoc();
                $name_old = $dataNO['name'];
                if($name_old != ""){
                    $projectdb->query("UPDATE interfaces SET vlan = '$name' WHERE source = '$source' AND template = '$template' AND vlan = '$name_old' ;");

                    $getVSVlans = $projectdb->query("SELECT id, vlan FROM virtual_systems WHERE source = '$source' AND template = '$template';");
                    if ($getVSVlans->num_rows > 0) {
                        while($dataVSV = $getVSVlans->fetch_assoc()){
                            $interface_vlans = $dataVSV['vlan'];
                            $id_vlans = $dataVSV['id'];
                            $add_array = explode(",", $interface_vlans);
                            if (in_array($name_old, $add_array)) {
                                $replace = str_replace($name_old, $name, $interface_vlans);
                                $projectdb->query("UPDATE virtual_systems SET vlan = '$replace' WHERE id = '$id_vlans';");
                            } 
                        }

                    }
                }
            }

            if($l3_forwarding == "on"){$l3_forwarding = "yes";}else{$l3_forwarding = "no";}

            $projectdb->query("UPDATE vlans SET name = '$name', virtual_interface = '$virtual_interface', interface = '".implode(",", $interfaces_layer2_array)."', mac = '".implode(",", $mac_array)."', mac_interfaces = '".implode(",", $interfaces_mac_array)."', l3_forwarding = '$l3_forwarding' WHERE id = '$id';");
            echo json_encode(array("success"=>true));
        }
        else{
            if($is_new == 1){
                $projectdb->query("DELETE FROM vlans WHERE id = '$id';");
            }
            echo json_encode(array("success"=>false, "msg"=>"VLAN already exists with the same name."));
        }
           
    }
} 
elseif ($action == "remove") {
    if ($type == "interfaces_layer2"){
        switch($_SERVER['REQUEST_METHOD'])
        {
            case 'GET':
                $vsys       = (string) (isset($_GET['vsys'])   ? $_GET['vsys'] : '');
                $source     = (string) (isset($_GET['source']) ? $_GET['source'] : '');
                $idx        = (string) (isset($_GET['idx'])    ? $_GET['idx'] : '');
                $ids        = (string) (isset($_GET['changes'])? $_GET['changes'] : '');
                break;
            case 'POST':
                $vsys       = (string) (isset($_POST['vsys'])   ? $_POST['vsys'] : '');
                $source     = (string) (isset($_POST['source']) ? $_POST['source'] : '');
                $idx        = (string) (isset($_POST['idx'])    ? $_POST['idx'] : '');
                $ids        = (string) (isset($_POST['changes'])? $_POST['changes'] : '');
                break;
            default:
                $vsys       = (string) (isset($_POST['vsys'])   ? $_POST['vsys'] : '');
                $source     = (string) (isset($_POST['source']) ? $_POST['source'] : '');
                $idx        = (string) (isset($_POST['idx'])    ? $_POST['idx'] : '');
                $ids        = (string) (isset($_POST['changes'])? $_POST['changes'] : '');
                break;
        }

        $vsys = $projectdb->real_escape_string($vsys);
        $source = $projectdb->real_escape_string($source);
        $idx = $projectdb->real_escape_string($idx);
        $ids = $projectdb->real_escape_string($ids);

//        $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
//        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
//        $idx = (string) (isset($_POST['idx']) ? $_POST['idx'] : $_GET['idx']);
//        $ids = (string) (isset($_POST['changes']) ? $_POST['changes'] : $_GET['changes']);

        if($idx == ""){
            $idx = 0;
        }

        if ($ids != "") {
            $data = explode(",", $ids);
            foreach ($data as $key => $value) {
                $projectdb->query("UPDATE edit_table SET remove = '1' WHERE name = '$value' AND lid = '$idx' AND type = 'interfaces_layer2' AND user_id = '$user_id';");
            }
        }
        
    }
    elseif ($type == "interfaces_mac"){
        switch($_SERVER['REQUEST_METHOD'])
        {
            case 'GET':
                $vsys       = (string) (isset($_GET['vsys'])   ? $_GET['vsys'] : '');
                $source     = (string) (isset($_GET['source']) ? $_GET['source'] : '');
                $idx        = (string) (isset($_GET['idx'])    ? $_GET['idx'] : '');
                $ids        = (string) (isset($_GET['changes'])? $_GET['changes'] : '');
                break;
            case 'POST':
                $vsys       = (string) (isset($_POST['vsys'])   ? $_POST['vsys'] : '');
                $source     = (string) (isset($_POST['source']) ? $_POST['source'] : '');
                $idx        = (string) (isset($_POST['idx'])    ? $_POST['idx'] : '');
                $ids        = (string) (isset($_POST['changes'])? $_POST['changes'] : '');
                break;
            default:
                $vsys       = (string) (isset($_POST['vsys'])   ? $_POST['vsys'] : '');
                $source     = (string) (isset($_POST['source']) ? $_POST['source'] : '');
                $idx        = (string) (isset($_POST['idx'])    ? $_POST['idx'] : '');
                $ids        = (string) (isset($_POST['changes'])? $_POST['changes'] : '');
                break;
        }

        $vsys = $projectdb->real_escape_string($vsys);
        $source = $projectdb->real_escape_string($source);
        $idx = $projectdb->real_escape_string($idx);
        $ids = $projectdb->real_escape_string($ids);

//        $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
//        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
//        $idx = (string) (isset($_POST['idx']) ? $_POST['idx'] : $_GET['idx']);
//        $ids = (string) (isset($_POST['changes']) ? $_POST['changes'] : $_GET['changes']);
        
        if ($ids != "") {
            $data = explode(",", $ids);
            foreach ($data as $key => $value) {
                $projectdb->query("UPDATE edit_table SET remove = '1' WHERE ids = '$value' AND lid = '$idx' AND type = 'mac' AND user_id = '$user_id';");
                $projectdb->query("UPDATE edit_table SET remove = '1' WHERE ids = '$value' AND lid = '$idx' AND type = 'interfaces_mac' AND user_id = '$user_id';");
            }
        }
        
    }
    elseif ($type == "vlans") {
        switch($_SERVER['REQUEST_METHOD'])
        {
            case 'GET':
                $ids                = (string) (isset($_GET['ids'])                ? $_GET['ids'] : '');
                $remove_references  = (string) (isset($_GET['remove_references'])  ? $_GET['remove_references'] : '');
                break;
            case 'POST':
                $ids                = (string) (isset($_POST['ids'])                ? $_POST['ids'] : '');
                $remove_references  = (string) (isset($_POST['remove_references'])  ? $_POST['remove_references'] : '');
                break;
            default:
                $ids                = (string) (isset($_POST['ids'])                ? $_POST['ids'] : '');
                $remove_references  = (string) (isset($_POST['remove_references'])  ? $_POST['remove_references'] : '');
                break;
        }

        $remove_references = $projectdb->real_escape_string($remove_references);
        $ids = $projectdb->real_escape_string($ids);

//        $ids = (string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']);
//        $remove_references = (string) (isset($_POST['remove_references']) ? $_POST['remove_references'] : $_GET['remove_references']);
        
        /*$data = explode(",", $ids);
        foreach ($data as $key => $value) {
            $projectdb->query("DELETE FROM vlans WHERE id IN ($ids);");
        }*/
        $msg = "";
        $are_references = 0;
        $are_references2 = 0;
        $id_not_references = array();
        $id_not_references2 = array();
              
        if($remove_references == "yes"){
            take_snapshot_last($project);
        }
        
        $getName = $projectdb->query("SELECT id, name FROM vlans WHERE id IN ($ids);");
        if($getName->num_rows > 0){
            while($dataN = $getName->fetch_assoc()){
                
                $name_principal = $dataN['name'];
                $id_principal = $dataN['id'];
                $total_name_interfaces = array();
                $total_name_virtual_system = array();
            
                if($name_principal != ""){
                
                    $getReferences = $projectdb->query("SELECT id, unitname FROM interfaces WHERE vlan = '$name_principal' AND source = '$source' AND template = '$template';");
                    if($getReferences->num_rows > 0){
                        $are_references = 1;
                        while($dataR = $getReferences->fetch_assoc()){
                            $id_tunnel = $dataR['id'];
                            $total_name_interfaces[] = $dataR['unitname'];
                        }

                        $msg .= "The VLANs [$name_principal] is being used by Interfaces [".implode(",", $total_name_interfaces)."].<br>";

                        if($remove_references == "yes"){
                            $projectdb->query("UPDATE interfaces SET vlan = '' WHERE source = '$source' AND template = '$template' AND vlan = '$name_principal' ;");
                            $projectdb->query("DELETE FROM vlans WHERE id = '$id_principal';");
                        }
                    }
                    else{
                        // Estos no tienen referencias, se pueden borrar
                        $id_not_references[] = $id_principal;
                    }

                    $getReferences2 = $projectdb->query("SELECT id, name, vlan FROM virtual_systems WHERE source = '$source' AND template = '$template';");
                    if($getReferences2->num_rows > 0){
                        while($dataR = $getReferences2->fetch_assoc()){
                            $id_vs = $dataR['id'];
                            $vlans_vs = $dataR['vlan'];

                            $add_array = explode(",", $vlans_vs);
                            if (in_array($name_principal, $add_array)) {
                                $are_references2 = 1;

                                $id_virtual_system[] = $dataR['id'];
                                $total_name_virtual_system[] = $dataR['name'];
                            }
                        }
                        if(count($total_name_virtual_system) > 0){
                            $msg .= "The VLANs [$name_principal] is being used by Virtual Systems [".implode(",", $total_name_virtual_system)."].<br>";
                        }
                        
                        if($remove_references == "yes"){
                            $getReferences3 = $projectdb->query("SELECT id, name, vlan FROM virtual_systems WHERE id IN (".implode(",", $id_virtual_system).");");
                            if($getReferences3->num_rows > 0){
                                while($dataR = $getReferences3->fetch_assoc()){
                                    $id_vs = $dataR['id'];
                                    $vlans_vs = $dataR['vlan'];

                                    $vlans_vs_explode = explode(",", $vlans_vs);
                                    $key = array_search($name_principal, $vlans_vs_explode);
                                    if (false !== $key) {
                                        unset($vlans_vs_explode[$key]);
                                    }
                                    $replace = implode(",", $vlans_vs_explode);
                                    $projectdb->query("UPDATE virtual_systems SET vlan = '$replace' WHERE source = '$source' AND template = '$template' AND id = '$id_vs' ;");
                                }
                            }

                            $projectdb->query("DELETE FROM vlans WHERE id = '$id_principal';");
                        }
                    }
                    else{
                        // Estos no tienen referencias, se pueden borrar
                        $id_not_references2[] = $id_principal;
                    }
                
                } // The name is empty
                else{
                    $projectdb->query("DELETE FROM vlans WHERE id = '$id_principal';");
                }
                
            }
        }
        $id_not_references_fin = array_intersect($id_not_references, $id_not_references2);
        
        if($remove_references == "no"){
            take_snapshot_last($project);
            if(($are_references == 1) || ($are_references2 == 1)){
                // Por si han seleccionado varios ids y alguno de éstos si que se pueden borrar directamente
                if(count($id_not_references_fin) > 0){
                    $projectdb->query("DELETE FROM vlans WHERE id IN (".implode(",", $id_not_references_fin).");");
                }
                
                $msg = $msg . "<br>Do you really want to delete the VLANs and all references?";
                echo json_encode(array("success"=>false, "msg"=>$msg));
            }
            else{
                $projectdb->query("DELETE FROM vlans WHERE id IN (".implode(",", $id_not_references).");");
                $projectdb->query("DELETE FROM vlans WHERE id IN (".implode(",", $id_not_references2).");");
                echo json_encode(array("success"=>true));
            }
        }
        else{
            echo json_encode(array("success"=>true));
        }
        
    }
}
?>