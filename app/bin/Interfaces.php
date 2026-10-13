<?php

# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';
require_once INC_ROOT.'/bin/Authentication.php';
require_once INC_ROOT.'/libs/database.php';
require_once INC_ROOT.'/libs/shared.php';

require_once INC_ROOT.'/libs/projectdb.php';
require_once INC_ROOT.'/userManager/API/projects/manageSettings.php';
require_once INC_ROOT.'/libs/common/tools/filters.php';

include INC_ROOT.'/bin/middleware_sanitizer.php';

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $action     = (string)  (isset($_GET['action'])    ? $_GET['action'] : '');
        $type       = (string)  (isset($_GET['type'])      ? $_GET['type'] : ''); // zip / xml / device
        $type2      = (string)  (isset($_GET['type2'])     ? $_GET['type2'] : '');
        $project    = (string)  (isset($_GET['project'])   ? $_GET['project'] : '');
        $devicename = (string)  (isset($_GET['devicename'])? $_GET['devicename'] : '');
        $template   = (string)  (isset($_GET['template'])  ? $_GET['template'] : '');
        $source     = (string)  (isset($_GET['source'])    ? $_GET['source'] : '');
        $start      = (integer) (isset($_GET['start'])     ? $_GET['start'] : '');
        $limit      = (integer) (isset($_GET['limit'])     ? $_GET['limit'] : '');
        $vsys       = (string)  (isset($_GET['vsys'])      ? $_GET['vsys'] : '');
        $media      = (string)  (isset($_GET['media'])     ? $_GET['media'] : '');
        $filter     = (string)  (isset($_GET['filter'])    ? $_GET['filter'] : '');
        break;
    case 'POST':
        $action     = (string)  (isset($_POST['action'])    ? $_POST['action'] : '');
        $type       = (string)  (isset($_POST['type'])      ? $_POST['type'] : ''); // zip / xml / device
        $type2      = (string)  (isset($_POST['type2'])     ? $_POST['type2'] : '');
        $project    = (string)  (isset($_POST['project'])   ? $_POST['project'] : '');
        $devicename = (string)  (isset($_POST['devicename'])? $_POST['devicename'] : '');
        $template   = (string)  (isset($_POST['template'])  ? $_POST['template'] : '');
        $source     = (string)  (isset($_POST['source'])    ? $_POST['source'] : '');
        $start      = (integer) (isset($_POST['start'])     ? $_POST['start'] : '');
        $limit      = (integer) (isset($_POST['limit'])     ? $_POST['limit'] : '');
        $vsys       = (string)  (isset($_POST['vsys'])      ? $_POST['vsys'] : '');
        $media      = (string)  (isset($_POST['media'])     ? $_POST['media'] : '');
        $filter     = (string)  (isset($_POST['filter'])    ? $_POST['filter'] : '');
        break;

    default:
        $action     = (string)  (isset($_POST['action'])    ? $_POST['action'] : '');
        $type       = (string)  (isset($_POST['type'])      ? $_POST['type'] : ''); // zip / xml / device
        $type2      = (string)  (isset($_POST['type2'])     ? $_POST['type2'] : '');
        $project    = (string)  (isset($_POST['project'])   ? $_POST['project'] : '');
        $devicename = (string)  (isset($_POST['devicename'])? $_POST['devicename'] : '');
        $template   = (string)  (isset($_POST['template'])  ? $_POST['template'] : '');
        $source     = (string)  (isset($_POST['source'])    ? $_POST['source'] : '');
        $start      = (integer) (isset($_POST['start'])     ? $_POST['start'] : '');
        $limit      = (integer) (isset($_POST['limit'])     ? $_POST['limit'] : '');
        $vsys       = (string)  (isset($_POST['vsys'])      ? $_POST['vsys'] : '');
        $media      = (string)  (isset($_POST['media'])     ? $_POST['media'] : '');
        $filter     = (string)  (isset($_POST['filter'])    ? $_POST['filter'] : '');
        break;
}

$projectdb = selectDatabase($project);

$action = $projectdb->real_escape_string($action);
$type = $projectdb->real_escape_string($type);
$type2 = $projectdb->real_escape_string($type2);
$project = $projectdb->real_escape_string($project);
$devicename = $projectdb->real_escape_string($devicename);
$template = $projectdb->real_escape_string($template);
$source = $projectdb->real_escape_string($source);
$start = $projectdb->real_escape_string($start);
$limit = $projectdb->real_escape_string($limit);
$vsys = $projectdb->real_escape_string($vsys);
$media = $projectdb->real_escape_string($media);
$filter = $projectdb->real_escape_string($filter);

global $app;
$user = $app->container->sentinel->getUser();
$user_id = $user->id;

if ($action == "get") {
    if(!checkProjectRights($project,'view')){
        echo '{"total":"0","rows":' . json_encode(array()) . '}';
        return;
    }
    if ($type == "interfaces") {
//        $media = (string) (isset($_POST['media']) ? $_POST['media'] : $_GET['media']);

        // check if the "vsys" attribute is filled with a vsys or a DG
        // if it's a DG then we need to call generate_query method without taking the vsys in consideration: we are getting a call from autozone execution, for instance
        // otherwise we need to call generate_query method taking the vsys in consideration: we are getting the call from the main grid to display virtual_routers
        $generate_query_type = "template_not_vsys_all";
        $get_vsys_array = getVsysBySourceByTemplate($source, $template);
        if (in_array($vsys,$get_vsys_array)){
            $generate_query_type = "template";
        }

        $query = generate_query($generate_query_type, $vsys);

        if ($media != "") {
            if (preg_match("/WHERE/i", $query)) {
                $query = $query . " AND media='$media'";
            } else {
                $query = " WHERE media='$media'";
            }
        }
        $name_interface_last = "";

        if ($media == "") {
            if(($filter != "none") && ($filter != "0")){

                $params['tools_where_columns_id'] = $filter;
                $params['tools_operator_id'] = "contains";
                $params['search'] = "";
                $params['tools_where_id'] = "18";
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

            list($query, $orderby) = generateQueryFilters($project, "interfaces", "", $query, $source);

        }

        $getLimit = $projectdb->query("SELECT id FROM interfaces $query;");
        $count = $getLimit->num_rows;

        //$getAll = $projectdb->query("SELECT * FROM interfaces $query ORDER BY unitname;");
        $getAll = $projectdb->query("SELECT * FROM interfaces $query ORDER BY unitname LIMIT $start, $limit;");
        //$getAll = $projectdb->query("SELECT * FROM interfaces $query ORDER BY unitname ;");

        //echo "SELECT * FROM interfaces $query ORDER BY unitname;\n";
        //$count = $getAll->num_rows;
        while ($data = $getAll->fetch_assoc()) {
            $vrid = $data['vr_id'];
            $source = $data['source'];
            
            $name_interface = $data['unitname'];
            if($name_interface_last != ""){
                if ($name_interface_last == $name_interface){
                    $data['warning'] = "1";
                }else{
                    $data['warning'] = "0";
                }
            }else{
                $data['warning'] = "0";
            }

            //TODO. Check if there are reported isssues to this interface in the monitor table
            $interface_id = $data['id'];
            $warning_query = "SELECT COUNT(*) as amount FROM logs WHERE  logs.obj_table='interfaces' AND obj_id='$interface_id' AND source = '$source'";
            $result_warning = $projectdb->query($warning_query);
            if($result_warning->num_rows>0){
                $data_warning = $result_warning->fetch_assoc();
                if($data_warning['amount']>0){
                    $data['warning'] = "1";
                }
            }


            $name_interface_last = $name_interface;
            
            if (intval($vrid) > 0) {
                $getVR = $projectdb->query("SELECT name FROM virtual_routers WHERE source='$source' AND id='$vrid';");
                if ($getVR->num_rows == 1) {
                    $theData = $getVR->fetch_assoc();
                    $data['vr'] = $theData['name'];
                }
            } else {
                $data['vr'] = "None";
            }
            $myData[] = $data;
        }
        if ($count == 0) {
            $myData = "";
        }
        echo '{"total":"' .$count. '","interfaces":' . json_encode($myData) . '}';
    }
    elseif ($type == "interfaces_with_any") {
        //$media = (string) (isset($_POST['media']) ? $_POST['media'] : $_GET['media']);
        $query = generate_query("template");
        if ($media != "") {
            if (preg_match("/WHERE/i", $query)) {
                $query = $query . " AND media='$media'";
            } else {
                $query = " WHERE media='$media'";
            }
        }
        $getAll = $projectdb->query("SELECT 'None' as vr,name,source,id,unitname,vr_id FROM interfaces $query ORDER BY unitname;");
        $count = $getAll->num_rows;
        $myData[] = array("idx" => "0", "vr" => "None", "name" => "any", "source" => "$source", "unitname" => "any", "id" => "0", "vr_id" => "0");
        while ($data = $getAll->fetch_assoc()) {
            $vrid = $data['vr_id'];
            $source = $data['source'];
            if (intval($vrid) > 0) {
                $getVR = $projectdb->query("SELECT name FROM virtual_routers WHERE source='$source' AND id='$vrid';");
                if ($getVR->num_rows == 1) {
                    $theData = $getVR->fetch_assoc();
                    $data['vr'] = $theData['name'];
                }
            } else {
                $data['vr'] = "None";
            }
            $myData[] = $data;
        }
        if ($count == 0) {
            $myData = "";
        }
        echo '{"total":"' . $count . '","interfaces":' . json_encode($myData) . '}';
    }
    elseif ($type == "interfaces_without_vsys") {
        //$media = (string) (isset($_POST['media']) ? $_POST['media'] : $_GET['media']);
        $query = generate_query("template");
        if ($media != "") {
            if (preg_match("/WHERE/i", $query)) {
                $query = $query . " AND media='$media' AND vsys=''";
            } else {
                $query = " WHERE media='$media' AND vsys=''";
            }
        } else {
            if (preg_match("/WHERE/i", $query)) {
                $query = $query . " AND vsys=''";
            } else {
                $query = " WHERE vsys=''";
            }
        }
        $getAll = $projectdb->query("SELECT 'None' as vr,name,source,id,template,type,interface_management_profile,unitname,unittag,unitipaddress,vlan,comment,vr_id,zone,aggregate_group,media,map_name,vsys,ipv4_type,dhcp_client_enable,dhcp_client_create_default_route,dhcp_client_default_route_metric,adjust_tcp_mss,untagged_sub_interface,vwire_id,mtu FROM interfaces $query ORDER BY id,name,unitname;");
        $count = $getAll->num_rows;
        while ($data = $getAll->fetch_assoc()) {
            $vrid = $data['vr_id'];
            $source = $data['source'];
            if (intval($vrid) > 0) {
                $getVR = $projectdb->query("SELECT name FROM virtual_routers WHERE source='$source' AND id='$vrid';");
                if ($getVR->num_rows == 1) {
                    $theData = $getVR->fetch_assoc();
                    $data['vr'] = $theData['name'];
                }
            } else {
                $data['vr'] = "None";
            }
            $myData[] = $data;
        }
        if ($count == 0) {
            $myData = "";
        }
        echo '{"total":"' . $count . '","interfaces":' . json_encode($myData) . '}';
    }
    elseif ($type == "interfaces_in_vsys") {
        //$media = (string) (isset($_POST['media']) ? $_POST['media'] : $_GET['media']);
        $query = generate_query("template_not_vsys");

        //$query = " WHERE source = '$source'";
        //if ($template != 0) {
        //    $query .= " AND (template = '$template')";
        //}

        if ($media != "") {
            if (preg_match("/WHERE/i", $query)) {
                $query = $query . " AND media='$media' ";
            } else {
                $query = " WHERE media='$media' ";
            }
        } else {
            if (preg_match("/WHERE/i", $query)) {
                //$query = $query . " AND vsys=''";
            } else {
                //$query = " WHERE vsys=''";
            }
        }
        $first_in = 0;
        $getAll = $projectdb->query("SELECT 'None' as vr,name,source,id,template,type,interface_management_profile,unitname,unittag,unitipaddress,vlan,comment,vr_id,zone,aggregate_group,media,map_name,vsys,ipv4_type,dhcp_client_enable,dhcp_client_create_default_route,dhcp_client_default_route_metric,adjust_tcp_mss,untagged_sub_interface,vwire_id,mtu FROM interfaces $query ORDER BY id,name,unitname;");
        //echo "SELECT 'None' as vr,name,source,id,template,type,interface_management_profile,unitname,unittag,unitipaddress,vlan,comment,vr_id,zone,aggregate_group,media,map_name,vsys,ipv4_type,dhcp_client_enable,dhcp_client_create_default_route,dhcp_client_default_route_metric,adjust_tcp_mss,untagged_sub_interface,vwire_id,mtu FROM interfaces $query ORDER BY id,name,unitname;";
        $count = $getAll->num_rows;
        if($count > 0){
            $myData[] = array("unitname" => "All Interfaces");
            while ($data = $getAll->fetch_assoc()) {
                $vrid = $data['vr_id'];
                $source = $data['source'];
                if (intval($vrid) > 0) {
                    $getVR = $projectdb->query("SELECT name FROM virtual_routers WHERE source='$source' AND id='$vrid';");
                    if ($getVR->num_rows == 1) {
                        $theData = $getVR->fetch_assoc();
                        $data['vr'] = $theData['name'];
                    }
                } else {
                    $data['vr'] = "None";
                }
                $myData[] = $data;
            }
        }
        while ($data = $getAll->fetch_assoc()) {
            $vrid = $data['vr_id'];
            $source = $data['source'];
            if (intval($vrid) > 0) {
                $getVR = $projectdb->query("SELECT name FROM virtual_routers WHERE source='$source' AND id='$vrid';");
                if ($getVR->num_rows == 1) {
                    $theData = $getVR->fetch_assoc();
                    $data['vr'] = $theData['name'];
                }
            } else {
                $data['vr'] = "None";
            }
            $myData[] = $data;
        }
        if ($count == 0) {
            $myData = "";
        }
        echo '{"total":"' . $count . '","interfaces":' . json_encode($myData) . '}';
    }
    elseif ($type == "interfaces_in_zones") {
        $query = generate_query("template");
        
        if (preg_match("/WHERE/i", $query)) {
            $query = $query . " AND zone = '' ";
        } else {
            $query = " WHERE zone = '' ";
        }
        
        $getAll = $projectdb->query("SELECT 'None' as vr,name,source,id,template,type,unitname,zone FROM interfaces $query ORDER BY id,name,unitname;");
        //echo "SELECT 'None' as vr,name,source,id,template,type,unitname,zone FROM interfaces $query ORDER BY id,name,unitname;";
        $count = $getAll->num_rows;
        if($count > 0){
            //$myData[] = array("unitname" => "All Interfaces");
            while ($data = $getAll->fetch_assoc()) {
                $myData[] = $data;
            }
        }
        if ($count == 0) {
            $myData = "";
        }
        echo '{"total":"' . $count . '","interfaces":' . json_encode($myData) . '}';
    }
    elseif ($type == "interfaces_without_vr") {
        //$media = (string) (isset($_POST['media']) ? $_POST['media'] : $_GET['media']);
        $query = generate_query("template");
        if ($media != "") {
            if (preg_match("/WHERE/i", $query)) {
                $query = $query . " AND media='$media' AND (vr_id='' OR vr_id='0') AND type='layer3'";
            } else {
                $query = " WHERE media='$media' AND (vr_id='' OR vr_id='0') AND type='layer3'";
            }
        } else {
            if (preg_match("/WHERE/i", $query)) {
                $query = $query . " AND (vr_id='' OR vr_id='0') AND type='layer3'";
            } else {
                $query = " WHERE (vr_id='' OR vr_id='0') AND type='layer3'";
            }
        }
        $getAll = $projectdb->query("SELECT 'None' as vr,name,source,id,template,type,interface_management_profile,unitname,unittag,unitipaddress,vlan,comment,vr_id,zone,aggregate_group,media,map_name,vsys,ipv4_type,dhcp_client_enable,dhcp_client_create_default_route,dhcp_client_default_route_metric,adjust_tcp_mss,untagged_sub_interface,vwire_id,mtu FROM interfaces $query ORDER BY id,name,unitname;");
        $count = $getAll->num_rows;
        while ($data = $getAll->fetch_assoc()) {
            $vrid = $data['vr_id'];
            $source = $data['source'];
            if (intval($vrid) > 0) {
                $getVR = $projectdb->query("SELECT name FROM virtual_routers WHERE source='$source' AND id='$vrid';");
                if ($getVR->num_rows == 1) {
                    $theData = $getVR->fetch_assoc();
                    $data['vr'] = $theData['name'];
                }
            } else {
                $data['vr'] = "None";
            }
            $myData[] = $data;
        }
        if ($count == 0) {
            $myData = "";
        }
        echo '{"total":"' . $count . '","interfaces":' . json_encode($myData) . '}';
    } 
    elseif ($type == "interfaces_without_vr_edit") {
        //$media = (string) (isset($_POST['media']) ? $_POST['media'] : $_GET['media']);
        $query = generate_query("template");
        if ($media != "") {
            if (preg_match("/WHERE/i", $query)) {
                $query = $query . " AND media='$media' AND (vr_id='' OR vr_id='0') AND type='layer3'";
            } else {
                $query = " WHERE media='$media' AND (vr_id='' OR vr_id='0') AND type='layer3'";
            }
        } else {
            if (preg_match("/WHERE/i", $query)) {
                $query = $query . " AND (vr_id='' OR vr_id='0') AND type='layer3'";
            } else {
                $query = " WHERE (vr_id='' OR vr_id='0') AND type='layer3'";
            }
        }
        $getAll = $projectdb->query("SELECT 'None' as vr,name,source,id,template,type,interface_management_profile,unitname,unittag,unitipaddress,vlan,comment,vr_id,zone,aggregate_group,media,map_name,vsys,ipv4_type,dhcp_client_enable,dhcp_client_create_default_route,dhcp_client_default_route_metric,adjust_tcp_mss,untagged_sub_interface,vwire_id,mtu FROM interfaces $query ORDER BY id,name,unitname;");
        $count = $getAll->num_rows;
        if($count > 0){
            $myData[] = array("unitname" => "All Interfaces","name"=>"All Interfaces","id"=>0);
            while ($data = $getAll->fetch_assoc()) {
                $vrid = $data['vr_id'];
                $source = $data['source'];
                if (intval($vrid) > 0) {
                    $getVR = $projectdb->query("SELECT name FROM virtual_routers WHERE source='$source' AND id='$vrid';");
                    if ($getVR->num_rows == 1) {
                        $theData = $getVR->fetch_assoc();
                        $data['vr'] = $theData['name'];
                    }
                } else {
                    $data['vr'] = "None";
                }
                $myData[] = $data;
            }
        }
        
        if ($count == 0) {
            $myData = "";
        }
        echo '{"total":"' . $count . '","interfaces":' . json_encode($myData) . '}';
    }
    elseif ($type == "interfaces_vwire_free") {
        $query = generate_query("template");

        if (preg_match("/WHERE/i", $query)) {
            $query = $query . " AND (vwire_id='' OR vwire_id='0') AND type='virtual-wire'";
        } else {
            $query = " WHERE (vwire_id='' OR vwire_id='0') AND type='virtual-wire'";
        }

        $getAll = $projectdb->query("SELECT 'None' as vr,name,source,id,template,type,interface_management_profile,unitname,unittag,unitipaddress,vlan,comment,vr_id,zone,aggregate_group,media,map_name,vsys,ipv4_type,dhcp_client_enable,dhcp_client_create_default_route,dhcp_client_default_route_metric,adjust_tcp_mss,untagged_sub_interface,vwire_id,mtu FROM interfaces $query ORDER BY id,name,unitname;");
        $count = $getAll->num_rows;
        while ($data = $getAll->fetch_assoc()) {
            $vrid = $data['vr_id'];
            $source = $data['source'];
            if (intval($vrid) > 0) {
                $getVR = $projectdb->query("SELECT name FROM virtual_routers WHERE source='$source' AND id='$vrid';");
                if ($getVR->num_rows == 1) {
                    $theData = $getVR->fetch_assoc();
                    $data['vr'] = $theData['name'];
                }
            } else {
                $data['vr'] = "None";
            }
            $myData[] = $data;
        }
        if ($count == 0) {
            $myData = "";
        }
        echo '{"total":"' . $count . '","interfaces":' . json_encode($myData) . '}';
    } 
    elseif ($type == "ipv4") {
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $idx = $projectdb->real_escape_string((string) (isset($_POST['idx']) ? $_POST['idx'] : $_GET['idx']));

        if($idx == ""){
            $idx = 0;
        }

        $address = array();
        $getAddress = $projectdb->query("SELECT unitipaddress FROM interfaces WHERE id = '$idx' AND unitipaddress != '';");
        if ($getAddress->num_rows == 1) {
            $dataA = $getAddress->fetch_assoc();
            $add = $dataA['unitipaddress'];
            $add_explode = explode(",", $add);
            $count = count($add_explode);
            foreach ($add_explode as $key => $value) {

                $getBridgeId = $projectdb->query("SELECT id FROM edit_table WHERE name = '$value' AND type = 'unitipaddress' AND lid = '$idx' AND user_id = '$user_id';");
                if ($getBridgeId->num_rows == 0) {
                    $getBridgeId = $projectdb->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'unitipaddress' AND lid = '$idx' AND user_id = '$user_id';");
                    if ($getBridgeId->num_rows == 1) {
                        $getIdData = $getBridgeId->fetch_assoc();
                        $ids = $getIdData['ids'] + 1;
                    }else{
                        $ids = 1;
                    }
                    $projectdb->query("INSERT INTO edit_table (id, ids, lid, type, name, source, remove, user_id) "
                        . "VALUES (NULL, '$ids', '$idx', 'unitipaddress', '$value', '$template', '0', '$user_id');");
                }

            }
            if ($add == "") {
                $count = 0;
                $address = "";
            }
            else{
                $getLimit = $projectdb->query("SELECT id, ids, name FROM edit_table WHERE type = 'unitipaddress' AND remove = '0' AND user_id = '$user_id' ORDER BY ids;");
                $count = $getLimit->num_rows;
                if ($getLimit->num_rows > 0) {
                    while ($data = $getLimit->fetch_object()) {
                        $address[] = $data;
                    }
                }
            }
            echo '{"total":"' . $count . '","elements":' . json_encode($address) . '}';
        }
        else{
            $getLimit = $projectdb->query("SELECT id, ids, name FROM edit_table WHERE type = 'unitipaddress' AND remove = '0' AND user_id = '$user_id' ORDER BY ids;");
            $count = $getLimit->num_rows;
            if ($getLimit->num_rows > 0) {
                while ($data = $getLimit->fetch_object()) {
                    $address[] = $data;
                }
            }
            echo '{"total":"' . $count . '","elements":' . json_encode($address) . '}';
        }
    }
    elseif ($type == "interface_local_ip_address"){
        
        $interface_selected = $projectdb->real_escape_string((string) (isset($_POST['interface_selected']) ? $_POST['interface_selected'] : $_GET['interface_selected']));
        
        if ($interface_selected != "") {
            $address = array();
            $getAddress = $projectdb->query("SELECT unitipaddress FROM interfaces WHERE unitname = '$interface_selected';");
            if ($getAddress->num_rows == 1) {
                $dataA = $getAddress->fetch_assoc();
                $add = $dataA['unitipaddress'];
                $add_explode = explode(",", $add);
                $count = count($add_explode);
                foreach ($add_explode as $key => $value) {
                    $address[] = array("name" => $value);
                }
                if ($add == "") {
                    $count = 0;
                    $address = "";
                }
                echo '{"total":"' . $count . '","address":' . json_encode($address) . '}';
            }
        }
        
    }
} 
elseif ($action == "set") {

    if ($type == "rename_interface") {

        $originalname = $projectdb->real_escape_string((string) (isset($_POST['originalname']) ? $_POST['originalname'] : $_GET['originalname']));
        $newname2 = $projectdb->real_escape_string((string) (isset($_POST['newname']) ? $_POST['newname'] : $_GET['newname']));
        $data = explode(";", $newname2);
        $newname = $data[0];
        $media = $data[1];
        //$media = (string) (isset($_POST['media']) ? $_POST['media'] : $_GET['media']);	
        rename_interface($originalname, $newname, $media, $source, $template);
        echo json_encode(array("success" => true));

    }
    else if ($type == "zones") {

        $ids = $projectdb->real_escape_string((string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']));
        $zone = $projectdb->real_escape_string((string) (isset($_POST['zone']) ? $_POST['zone'] : $_GET['zone']));
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));

        if(($zone != "") && ($ids != "")){

            // update the interfaces with the proper zone so get the type of zone
            $getZone = $projectdb->query("SELECT id, name, type FROM zones WHERE name = '$zone';");
            if ($getZone->num_rows == 1) {
                $dataZ = $getZone->fetch_assoc();
                $type_zone = $dataZ['type'];
            }

            // check if selected interfaces match with zone type, if not do nothing
            $query = "SELECT * FROM interfaces WHERE id IN ($ids) AND type = '$type_zone';";
            $get = $projectdb->query($query);
            if ($get->num_rows > 0 ) {

                // now update the interfaces that match the id and type zone
                $projectdb->query("UPDATE interfaces SET zone = '$zone' WHERE id IN ($ids) AND type = '$type_zone';");

                // get names of the updated interfaces to add in the zones table
                $query_get_interface = "SELECT unitname FROM interfaces WHERE id IN ($ids) AND type = '$type_zone'";
                $get_interface = $projectdb->query($query_get_interface);
                $array_unitname_interface = [];
                if ($get_interface->num_rows > 0) {
                    while ($data_interface = $get_interface->fetch_assoc()) {
                        $array_unitname_interface[] = $data_interface['unitname'];
                    }
                }

                $interface_zone = "";
                // get current zone interfaces so we can add them to the selected ones
                $query_get_zone = "SELECT interfaces FROM zones WHERE name = '$zone';";
                $get_vr = $projectdb->query($query_get_zone);
                if ($get_vr->num_rows > 0) {
                    $data_zone = $get_vr->fetch_assoc();
                    $interface_zone = $data_zone['interfaces'];
                }

                // merge both arrays and remove duplicates
                $array_existing_interfaces = explode(",", $interface_zone);
                $array_merge_interface = array_merge($array_existing_interfaces, $array_unitname_interface);
                $array_unique_interface = array_filter(array_unique($array_merge_interface));

                // update the zones with the interfaces
                $projectdb->query("UPDATE zones SET interfaces = '" . implode(",", $array_unique_interface) . "' WHERE name = '$zone';");

                // look if the interfaces are used in any other zone and remove them
                $query_get_other_zones = "SELECT interfaces,id FROM zones WHERE name != '$zone';";
                $get_other_zones = $projectdb->query($query_get_other_zones);
                if ($get_other_zones->num_rows > 0) {
                    while ($data_other_zones = $get_other_zones->fetch_assoc()) {
                        $other_zone_id = $data_other_zones['id'];
                        $interface_other_zone = $data_other_zones['interfaces'];
                        $array_other_interfaces = explode(",", $interface_other_zone);
                        $array_diff_interface = array_filter(array_diff($array_other_interfaces, $array_unitname_interface));
                        $projectdb->query("UPDATE zones SET interfaces = '" . implode(",", $array_diff_interface) . "' WHERE id = '$other_zone_id';");
                    }
                }
            }
        }
        echo json_encode(array("success" => true));
    } else if ($type == "virtual_router") {

        $ids = $projectdb->real_escape_string((string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']));
        $vr_id = $projectdb->real_escape_string((string) (isset($_POST['vr']) ? $_POST['vr'] : $_GET['vr']));
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));

        if(($vr_id != "") && ($ids != "")){
            // update the interfaces with the proper vr
            $projectdb->query("UPDATE interfaces SET vr_id = '$vr_id' WHERE id IN ($ids) AND (type = 'layer3' OR type = 'vlan');");

            // get names of the updated interfaces to add in the VR
            $query_get_interface = "SELECT unitname FROM interfaces WHERE id IN ($ids) AND (type = 'layer3' OR type = 'vlan')";
            $get_interface = $projectdb->query($query_get_interface);
            $array_unitname_interface = [];
            if ($get_interface->num_rows > 0 ) {
                while($data_interface = $get_interface->fetch_assoc()) {
                    $array_unitname_interface[] = $data_interface['unitname'];
                }
            }
            $interface_vr = "";
            // get current vr interfaces so we can add them to the selected ones
            $query_get_vr = "SELECT interfaces FROM virtual_routers WHERE id = '$vr_id';";
            $get_vr = $projectdb->query($query_get_vr);
            if ($get_vr->num_rows > 0 ) {
                $data_vr = $get_vr->fetch_assoc();
                $interface_vr = $data_vr['interfaces'];
            }
            // merge both arrays and remove duplicates
            $array_existing_interfaces = explode(",",$interface_vr);
            $array_merge_interface = array_merge($array_existing_interfaces,$array_unitname_interface);
            $array_unique_interface = array_filter(array_unique($array_merge_interface));

            // update the virtual router with the interfaces
            $projectdb->query("UPDATE virtual_routers SET interfaces = '" . implode(",", $array_unique_interface) . "' WHERE id = '$vr_id';");

            // look if the interfaces are used in any other virtual_router and remove them
            $query_get_other_vr = "SELECT interfaces,id FROM virtual_routers WHERE id != '$vr_id';";
            $get_other_vr = $projectdb->query($query_get_other_vr);
            if ($get_other_vr->num_rows > 0 ) {
                while ($data_other_vr = $get_other_vr->fetch_assoc()) {
                    $other_vr_id = $data_other_vr['id'];
                    $interface_other_vr = $data_other_vr['interfaces'];
                    $array_other_interfaces = explode(",", $interface_other_vr);
                    $array_diff_interface = array_filter(array_diff($array_other_interfaces, $array_unitname_interface));
                    $projectdb->query("UPDATE virtual_routers SET interfaces = '" . implode(",", $array_diff_interface) . "' WHERE id = '$other_vr_id';");
                }
            }

        }
        echo json_encode(array("success" => true));

    } else if ($type == "virtual_system") {

        $ids = $projectdb->real_escape_string((string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']));
        $vr_id = $projectdb->real_escape_string((string) (isset($_POST['vr']) ? $_POST['vr'] : $_GET['vr']));
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));

        if(($vsys != "") && ($ids != "")){

            $projectdb->query("UPDATE interfaces SET vsys = '$vsys' WHERE id IN ($ids) AND (type = 'layer3' OR type = 'layer2' OR type = 'vlan');");

            $getInterfaceNames = $projectdb->query("SELECT name, template, source FROM interfaces WHERE id IN ($ids) AND (type = 'layer3' OR type = 'layer2' OR type = 'vlan');");
            while($interfaceNames = $getInterfaceNames->fetch_assoc()){
                $parentInterfaceName = $interfaceNames['name'];
                $parentTemplate = $interfaceNames['template'];
                $parentSource = $interfaceNames['source'];
                $getUnits = $projectdb->query("SELECT * FROM interfaces WHERE template='$parentTemplate' AND source='$parentSource' AND media='ethernet' AND unitname!='$parentInterfaceName' AND name='$parentInterfaceName';");
                $units = [];
                while($unit = $getUnits->fetch_assoc()){
                    $units[] = $unit['id'];
                }
                if(count($units)>0){
                    $unit_ids = implode(",", $units);
                    $projectdb->query("UPDATE interfaces SET vsys = '$vsys' WHERE id IN ($unit_ids) AND (type = 'layer3' OR type = 'layer2' OR type = 'vlan');");
                }
            }


        }
        echo json_encode(array("success" => true));
    }
    else if ($type == "mgmt_profiles") {

        $ids = $projectdb->real_escape_string((string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']));
        $mgmt_profiles = $projectdb->real_escape_string((string) (isset($_POST['mgmt_profiles']) ? $_POST['mgmt_profiles'] : $_GET['mgmt_profiles']));
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));

        if(($mgmt_profiles != "") && ($ids != "")){

            $projectdb->query("UPDATE interfaces SET interface_management_profile = '$mgmt_profiles' WHERE id IN ($ids) AND (type = 'layer3' OR type = 'vlan');");

        }
        echo json_encode(array("success" => true));
    }

} 
elseif ($action == "add") {

    if ($type == "interface") {
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $template = $projectdb->real_escape_string((string) (isset($_POST['template']) ? $_POST['template'] : $_GET['template']));
        //$media = (string) (isset($_POST['media']) ? $_POST['media'] : $_GET['media']);
        if ($media == "tunnel") {
            $name = "tunnel";
        } elseif ($media == "loopback") {
            $name = "loopback";
        } elseif ($media == "vlan") {
            $name = "vlan";
        //} elseif ($media == "aggregate-ethernet") {
        //    $name = "ae";
        } else {
            $name = "";
        }
        $projectdb->query("INSERT INTO interfaces (template,vsys,source,name,media,unitname) VALUES ('$template','$vsys','$source','$name','$media','$name');");
        echo json_encode(array("success" => true));
    } 
    elseif ($type == "ipv4") {
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $idx = $projectdb->real_escape_string((string) (isset($_POST['idx']) ? $_POST['idx'] : $_GET['idx']));
        $name = $projectdb->real_escape_string((string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']));

        if($idx == ""){
            $idx = 0;
        }

        $name_unitipaddress = explode(",", $name);

        foreach ($name_unitipaddress AS $name){
            $getBridge = $projectdb->query("SELECT id FROM edit_table WHERE type = 'unitipaddress' AND name = '$name' AND user_id = '$user_id';");
            if ($getBridge->num_rows == 0) {

                $getBridgeId = $projectdb->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'unitipaddress' AND lid = '$idx' AND user_id = '$user_id';");
                if ($getBridgeId->num_rows == 1) {
                    $getIdData = $getBridgeId->fetch_assoc();
                    $ids = $getIdData['ids'] + 1;
                }else{
                    $ids = 1;
                }

                $projectdb->query("INSERT INTO edit_table (id, ids, lid, type, name, source, remove, user_id) "
                    . "VALUES (NULL, '$ids', '$idx', 'unitipaddress', '$name', '$template', '0', '$user_id');");
            }else{
                $projectdb->query("UPDATE edit_table SET remove = '0' WHERE name = '$name' AND type = 'unitipaddress' AND lid = '$idx' AND user_id = '$user_id';");
            }

        }
        echo json_encode(array("success" => true));
    }
} 
elseif ($action == "remove") {

    if ($type == "interface") {
        $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : '');
        $template = (string) (isset($_POST['template']) ? $_POST['template'] : '');
        $ids = (string) (isset($_POST['ids']) ? $_POST['ids'] : '');
        $remove_references = (string) (isset($_POST['remove_references']) ? $_POST['remove_references'] : '');
        
        //$total_name_zones = array();
        $msg = "";
        $are_references = 0;
        $id_not_references = array();
        $id_not_references2 = array();
        $id_not_references3 = array();
        $id_not_references4 = array();
        $id_not_references5 = array();
        $id_not_references6 = array();
        $id_not_references7 = array();
        $id_not_references8 = array();
        $id_not_references9 = array();
        $id_not_references10 = array();
        $id_not_references11 = array();
        $id_not_references12 = array();
        $id_not_references13 = array();
        $id_not_references14 = array();
        
        $allinterfaces = explode(",", $ids);
        
        foreach ($allinterfaces as $key => $value) {
            $getInterfaceName = $projectdb->query("SELECT id, unitname, template, zone, vr_id, vsys FROM interfaces WHERE id='$value' AND unitname != '';");
            if ($getInterfaceName->num_rows == 1) {
                
                $getInterfaceNameData = $getInterfaceName->fetch_assoc();
                $interface_id = $getInterfaceNameData['id'];
                $Itemplate = $getInterfaceNameData['template'];
                $Iname = $getInterfaceNameData['unitname'];
                $Izone = $getInterfaceNameData['zone'];
                $Ivrid = $getInterfaceNameData['vr_id'];
                $Ivsys = $getInterfaceNameData['vsys'];
                
                $total_name_zones = array();
                $total_name_virtual_routers = array();
                $total_name_virtual_systems = array();
                $total_name_vlans = array();
                $total_name_ike_gate = array();
                $total_name_ipsec_tunnel = array();
                $total_name_gre_tunnel = array();
                $total_name_virtual_wires = array();
                $total_name_nat_rules = array();
                $total_name_pbf_rules = array();
                $total_name_dos_rules = array();

                $getAnother = $projectdb->query("SELECT id FROM interfaces WHERE source='$source' AND template='$template' AND unitname='$Iname' AND id!='$value';");
                if ($getAnother->num_rows == 0) {
                    
                    #Update Zones
                    if ($Izone != "") {
                        $getInterfaces = $projectdb->query("SELECT id,name,interfaces FROM zones WHERE template='$Itemplate' AND name='$Izone'");
                        if ($getInterfaces->num_rows == 1) {
                            $getInterfacesData = $getInterfaces->fetch_assoc();
                            $zone_id = $getInterfacesData['id'];
                            $zone_name = $getInterfacesData['name'];
                            $oldInterfaces = explode(",", $getInterfacesData['interfaces']);
                            if (($key = array_search($Iname, $oldInterfaces)) !== false) {
                                $are_references = 1;
                                $total_name_zones[] = $zone_name;
                                
                                if($remove_references == "yes"){
                                    unset($oldInterfaces[$key]);
                                }
                                
                            }
                            else{
                                $id_not_references[] = $interface_id;
                            }
                            if($remove_references == "yes"){
                                $projectdb->query("UPDATE zones SET interfaces='" . implode(",", $oldInterfaces) . "' WHERE id='$zone_id'");
                            }
                        }
                    }
                    else{
                        $id_not_references[] = $interface_id;
                    }
                    
                    # Update Virtual Routers
                    if (($Ivrid != 0) AND ( $Ivrid != "")) {
                        $getInterfaces = $projectdb->query("SELECT name, interfaces FROM virtual_routers WHERE id = '$Ivrid'");
                        if ($getInterfaces->num_rows == 1) {
                            $getInterfacesData = $getInterfaces->fetch_assoc();
                            $virtual_router_name = $getInterfacesData['name'];
                            $oldInterfaces = explode(",", $getInterfacesData['interfaces']);
                            if (($key = array_search($Iname, $oldInterfaces)) !== false) {
                                $are_references = 1;
                                $total_name_virtual_routers[] = $virtual_router_name;
                                
                                if($remove_references == "yes"){
                                    unset($oldInterfaces[$key]);
                                }
                            }
                            else{
                                $id_not_references2[] = $interface_id;
                            }
                            if($remove_references == "yes"){
                                $projectdb->query("UPDATE virtual_routers SET interfaces = '" . implode(",", $oldInterfaces) . "' WHERE id = '$Ivrid'");
                                #Update Static Routes 
                                $projectdb->query("UPDATE routes_static SET tointerface = '' WHERE tointerface = '$Iname' AND vr_id = '$Ivrid';");
                            }
                        }
                    }
                    else{
                        $id_not_references2[] = $interface_id;
                    }

                    # Update Vsys
                    if ($Ivsys != "") {
                        $getInterfaces = $projectdb->query("SELECT id, name, interfaces FROM virtual_systems WHERE template='$Itemplate' AND name='$Ivsys'");
                        if ($getInterfaces->num_rows > 0) {
                            $getInterfacesData = $getInterfaces->fetch_assoc();
                            $vsysID = $getInterfacesData['id'];
                            $vsys_name = $getInterfacesData['name'];
                            $oldInterfaces = explode(",", $getInterfacesData['interfaces']);
                            if (($key = array_search($Iname, $oldInterfaces)) !== false) {
                                $are_references = 1;
                                $total_name_virtual_systems[] = $vsys_name;
                                
                                if($remove_references == "yes"){
                                    unset($oldInterfaces[$key]);
                                }
                            }
                            else{
                                $id_not_references3[] = $interface_id;
                            }
                            if($remove_references == "yes"){
                                $projectdb->query("UPDATE virtual_systems SET interfaces='" . implode(",", $oldInterfaces) . "' WHERE id = '$vsysID'");
                            }
                        }
                    }
                    else{
                        $id_not_references3[] = $interface_id;
                    }
                    
                    # Vlan
                    $getVlans = $projectdb->query("SELECT id, name, interface, mac_interfaces FROM vlans WHERE template='$Itemplate' AND source='$source' ;");
                    if ($getVlans->num_rows > 0) {
                        while($dataV = $getVlans->fetch_assoc()){
                            $vlan_id = $dataV['id'];
                            $vlan_name = $dataV['name'];
                            $oldInterfaces = explode(",", $dataV['interface']);
                            $oldInterfaces_mac = explode(",", $dataV['mac_interfaces']);
                            if (($key = array_search($Iname, $oldInterfaces)) !== false) {
                                $are_references = 1;
                                $total_name_vlans[] = $vlan_name;
                                if($remove_references == "yes"){
                                    unset($oldInterfaces[$key]);
                                }
                            }
                            else{
                                $id_not_references4[] = $interface_id;
                            }
                            if (($key2 = array_search($Iname, $oldInterfaces_mac)) !== false) {
                                $are_references = 1;
                                $total_name_vlans[] = $vlan_name;
                                if($remove_references == "yes"){
                                    unset($oldInterfaces_mac[$key2]);
                                }
                            }
                            else{
                                $id_not_references5[] = $interface_id;
                            }
                            $total_name_vlans = array_unique($total_name_vlans);

                            if($remove_references == "yes"){
                                $projectdb->query("UPDATE vlans SET interface = '" . implode(",", $oldInterfaces) . "', mac_interfaces = '" . implode(",", $oldInterfaces_mac) . "' WHERE id = '$vlan_id'");
                            }
                        }
                    }
                    else{
                        $id_not_references5[] = $interface_id;
                    }

                    # IKE Gateways
                    $getIKEGate = $projectdb->query("SELECT id, name, interface FROM ike_gateways_profiles WHERE interface = '$Iname' AND source = '$source' AND template = '$Itemplate';");
                    if($getIKEGate->num_rows > 0){
                        $are_references = 1;
                        while($dataIG = $getIKEGate->fetch_assoc()){
                            $id_ike_gate = $dataIG['id'];
                            $total_name_ike_gate[] = $dataIG['name'];
                            
                            if($remove_references == "yes"){
                                $projectdb->query("UPDATE ike_gateways_profiles SET interface = '' WHERE id = '$id_ike_gate'");
                            }
                        }
                    }
                    else{
                        $id_not_references6[] = $interface_id;
                    }
                    
                    # IPSec Tunnel
                    $getIPsecTunnel = $projectdb->query("SELECT id, name FROM ipsec_tunnel WHERE (tunnel_interface = '$Iname' OR interface = '$Iname') AND source = '$source' AND template = '$Itemplate';");
                    if($getIPsecTunnel->num_rows > 0){
                        $are_references = 1;
                        while($dataIT = $getIPsecTunnel->fetch_assoc()){
                            $id_tunnel = $dataIT['id'];
                            $total_name_ipsec_tunnel[] = $dataIT['name'];
                            
                            if($remove_references == "yes"){
                                $projectdb->query("UPDATE ipsec_tunnel SET tunnel_interface = '' WHERE tunnel_interface = '$Iname' AND id = '$id_tunnel' AND source = '$source' AND template = '$Itemplate';");
                                $projectdb->query("UPDATE ipsec_tunnel SET interface = '' WHERE interface = '$Iname' AND id = '$id_tunnel' AND source = '$source' AND template = '$Itemplate';");
                            }
                        }
                    }
                    else{
                        $id_not_references7[] = $interface_id;
                    }

                    # GRE Tunnel
                    $getGRETunnel = $projectdb->query("SELECT id, name FROM gre_tunnel WHERE (tunnel_interface = '$Iname' OR interface = '$Iname') AND source = '$source' AND template = '$Itemplate';");
                    if($getGRETunnel->num_rows > 0){
                        $are_references = 1;
                        while($dataIT = $getGRETunnel->fetch_assoc()){
                            $id_gre = $dataIT['id'];
                            $total_name_gre_tunnel[] = $dataIT['name'];

                            if($remove_references == "yes"){
                                $projectdb->query("UPDATE gre_tunnel SET tunnel_interface = '' WHERE tunnel_interface = '$Iname' AND id = '$id_gre' AND source = '$source' AND template = '$Itemplate';");
                                $projectdb->query("UPDATE gre_tunnel SET interface = '' WHERE interface = '$Iname' AND id = '$id_gre' AND source = '$source' AND template = '$Itemplate';");
                            }
                        }
                    }
                    else{
                        $id_not_references14[] = $interface_id;
                    }
                    
                    # Virtual Wires
                    $getVirtualWires = $projectdb->query("SELECT id, name FROM virtual_wires WHERE (interface1 = '$Iname' OR interface2 = '$Iname') AND source = '$source' AND template = '$Itemplate';");
                    if($getVirtualWires->num_rows > 0){
                        $are_references = 1;
                        while($dataVW = $getVirtualWires->fetch_assoc()){
                            $id_virutal_wires = $dataVW['id'];
                            $total_name_virtual_wires[] = $dataVW['name'];
                            
                            if($remove_references == "yes"){
                                $projectdb->query("UPDATE virtual_wires SET interface1 = '' WHERE interface1 = '$Iname' AND id = '$id_virutal_wires' AND source = '$source' AND template = '$Itemplate';");
                                $projectdb->query("UPDATE virtual_wires SET interface2 = '' WHERE interface2 = '$Iname' AND id = '$id_virutal_wires' AND source = '$source' AND template = '$Itemplate';");
                            }
                        }
                    }
                    else{
                        $id_not_references8[] = $interface_id;
                    }
                    
                    # NAT Rules
                    $getNatRules = $projectdb->query("SELECT id, name FROM nat_rules WHERE (op_to_interface = '$Iname' OR tp_sat_interface = '$Iname' OR tp_sat_interface_fallback = '$Iname') AND source = '$source' ;");
                    if($getNatRules->num_rows > 0){
                        $are_references = 1;
                        while($dataNR = $getNatRules->fetch_assoc()){
                            $id_nat_rules = $dataNR['id'];
                            $total_name_nat_rules[] = $dataNR['name'];
                            
                            if($remove_references == "yes"){
                                $projectdb->query("UPDATE nat_rules SET op_to_interface = '' WHERE op_to_interface = '$Iname' AND id = '$id_nat_rules' AND source = '$source' ;");
                                $projectdb->query("UPDATE nat_rules SET tp_sat_interface = '' WHERE tp_sat_interface = '$Iname' AND id = '$id_nat_rules' AND source = '$source' ;");
                                $projectdb->query("UPDATE nat_rules SET tp_sat_interface_fallback = '' WHERE tp_sat_interface_fallback = '$Iname' AND id = '$id_nat_rules' AND source = '$source' ;");
                            }
                        }
                    }
                    else{
                        $id_not_references9[] = $interface_id;
                    }

                    # PBF Rules
                    $getPBFRules = $projectdb->query("SELECT id, name FROM pbf_rules WHERE egress_interface = '$Iname' AND source = '$source' ;");
                    if($getPBFRules->num_rows > 0){
                        $are_references = 1;
                        while($dataNR = $getPBFRules->fetch_assoc()){
                            $id_pbf_rules = $dataNR['id'];
                            $total_name_pbf_rules[] = $dataNR['id'];

                            if($remove_references == "yes"){
                                $projectdb->query("UPDATE pbf_rules SET egress_interface = '' WHERE egress_interface = '$Iname' AND id = '$id_pbf_rules' AND source = '$source' ;");
                            }
                        }
                    }
                    else{
                        $id_not_references10[] = $interface_id;
                    }

                    # PBF Rules From
                    $getPBFRules = $projectdb->query("SELECT rule_lid, name FROM pbf_rules_from WHERE type = 'interface' AND name='$Iname' AND source = '$source' ;");
                    if($getPBFRules->num_rows > 0){
                        $are_references = 1;
                        while($dataNR = $getPBFRules->fetch_assoc()){
                            $id_pbf_rules = $dataNR['rule_lid'];
                            $total_name_pbf_rules[] = $dataNR['rule_lid'];

                            if($remove_references == "yes"){
                                $projectdb->query("DELETE pbf_rules_from WHERE name = '$Iname' AND type = 'interface' AND rule_lid = '$id_pbf_rules' AND source = '$source' ;");
                            }
                        }
                    }
                    else{
                        $id_not_references11[] = $interface_id;
                    }

                    # DOS Rules From
                    $getPBFRules = $projectdb->query("SELECT rule_lid, name FROM dos_rules_from WHERE type = 'interface' AND name='$Iname' AND source = '$source' ;");
                    if($getPBFRules->num_rows > 0){
                        $are_references = 1;
                        while($dataNR = $getPBFRules->fetch_assoc()){
                            $id_pbf_rules = $dataNR['rule_lid'];
                            $total_name_dos_rules[] = $dataNR['rule_lid'];

                            if($remove_references == "yes"){
                                $projectdb->query("DELETE dos_rules_from WHERE name = '$Iname' AND type = 'interface' AND rule_lid = '$id_pbf_rules' AND source = '$source' ;");
                            }
                        }
                    }
                    else{
                        $id_not_references12[] = $interface_id;
                    }

                    # DOS Rules To
                    $getPBFRules = $projectdb->query("SELECT rule_lid, name FROM dos_rules_to WHERE type = 'interface' AND name='$Iname' AND source = '$source' ;");
                    if($getPBFRules->num_rows > 0){
                        $are_references = 1;
                        while($dataNR = $getPBFRules->fetch_assoc()){
                            $id_pbf_rules = $dataNR['rule_lid'];
                            $total_name_dos_rules[] = $dataNR['rule_lid'];

                            if($remove_references == "yes"){
                                $projectdb->query("DELETE dos_rules_to WHERE name = '$Iname' AND type = 'interface' AND rule_lid = '$id_pbf_rules' AND source = '$source' ;");
                            }
                        }
                    }
                    else{
                        $id_not_references13[] = $interface_id;
                    }
                }
                else{
                    
                    // Significa que hay otra interface con el mismo nombre q se ha generado después de un merge, etc, así que se puede
                    // borrar directamente
                    take_snapshot_last($project);
                    $projectdb->query("DELETE FROM interfaces WHERE id='$value';");
                    
                }

                if($remove_references == "no"){
                    if(count($total_name_zones) > 0){
                        $msg .= "The Interface [$Iname] is being used by Zones [".implode(",", $total_name_zones)."].<br>";
                    }
                    if(count($total_name_virtual_routers) > 0){
                        $msg .= "The Interface [$Iname] is being used by Virtual Routers [".implode(",", $total_name_virtual_routers)."].<br>";
                    }
                    if(count($total_name_virtual_systems) > 0){
                        $msg .= "The Interface [$Iname] is being used by Virtual Systems [".implode(",", $total_name_virtual_systems)."].<br>";
                    }  
                    if(count($total_name_vlans) > 0){
                        $msg .= "The Interface [$Iname] is being used by VLANs [".implode(",", $total_name_vlans)."].<br>";
                    }
                    if(count($total_name_ike_gate) > 0){
                        $msg .= "The Interface [$Iname] is being used by IKE Gateways [".implode(",", $total_name_ike_gate)."].<br>";
                    }
                    if(count($total_name_ipsec_tunnel) > 0){
                        $msg .= "The Interface [$Iname] is being used by IPSec Tunnels [".implode(",", $total_name_ipsec_tunnel)."].<br>";
                    }
                    if(count($total_name_gre_tunnel) > 0){
                        $msg .= "The Interface [$Iname] is being used by GRE Tunnels [".implode(",", $total_name_gre_tunnel)."].<br>";
                    }
                    if(count($total_name_virtual_wires) > 0){
                        $msg .= "The Interface [$Iname] is being used by Virtual Wires [".implode(",", $total_name_virtual_wires)."].<br>";
                    }
                    if(count($total_name_nat_rules) > 0){
                        $msg .= "The Interface [$Iname] is being used by NAT Rules [".implode(",", $total_name_nat_rules)."].<br>";
                    }
                    if(count($total_name_pbf_rules) > 0){
                        $msg .= "The Interface [$Iname] is being used by PBF Rules [".implode(",", $total_name_pbf_rules)."].<br>";
                    }
                    if(count($total_name_dos_rules) > 0){
                        $msg .= "The Interface [$Iname] is being used by DoS Rules [".implode(",", $total_name_dos_rules)."].<br>";
                    }
                }
            }
            else{
                // Name is empty
                $projectdb->query("DELETE FROM interfaces WHERE id='$value';");
            }
        }
        if($remove_references == "no"){
            take_snapshot_last($project);
            if($are_references == 1){
                
                $id_not_references_fin = array_intersect($id_not_references, $id_not_references2, $id_not_references3, $id_not_references4, $id_not_references5, $id_not_references6, $id_not_references7, $id_not_references8, $id_not_references9);
                // Por si han seleccionado varios ids y alguno de éstos si que se pueden borrar directamente
                if(count($id_not_references_fin) > 0){
                    $projectdb->query("DELETE FROM interfaces WHERE id IN (".implode(",", $id_not_references_fin).");");
                    //echo "DELETE FROM interfaces WHERE id IN (".implode(",", $id_not_references_fin).");";
                }
                
                $msg = $msg . "<br>Do you really want to delete the Interfaces and all references?";
                echo json_encode(array("success"=>false, "msg"=>$msg));
            }
            else{
                $projectdb->query("DELETE FROM interfaces WHERE id IN (".implode(",", $id_not_references).");");
                $projectdb->query("DELETE FROM interfaces WHERE id IN (".implode(",", $id_not_references2).");");
                $projectdb->query("DELETE FROM interfaces WHERE id IN (".implode(",", $id_not_references3).");");
                $projectdb->query("DELETE FROM interfaces WHERE id IN (".implode(",", $id_not_references4).");");
                $projectdb->query("DELETE FROM interfaces WHERE id IN (".implode(",", $id_not_references5).");");
                $projectdb->query("DELETE FROM interfaces WHERE id IN (".implode(",", $id_not_references6).");");
                $projectdb->query("DELETE FROM interfaces WHERE id IN (".implode(",", $id_not_references7).");");
                $projectdb->query("DELETE FROM interfaces WHERE id IN (".implode(",", $id_not_references8).");");
                $projectdb->query("DELETE FROM interfaces WHERE id IN (".implode(",", $id_not_references9).");");
                $projectdb->query("DELETE FROM interfaces WHERE id IN (".implode(",", $id_not_references10).");");
                $projectdb->query("DELETE FROM interfaces WHERE id IN (".implode(",", $id_not_references11).");");
                $projectdb->query("DELETE FROM interfaces WHERE id IN (".implode(",", $id_not_references12).");");
                $projectdb->query("DELETE FROM interfaces WHERE id IN (".implode(",", $id_not_references13).");");
                $projectdb->query("DELETE FROM interfaces WHERE id IN (".implode(",", $id_not_references14).");");
                echo json_encode(array("success"=>true));
            }
        }
        elseif($remove_references == "yes"){
            $projectdb->query("DELETE FROM interfaces WHERE id IN ($ids);");
            echo json_encode(array("success"=>true));
        }
    }
    elseif ($type == "ipv4") {
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $idx = $projectdb->real_escape_string((string) (isset($_POST['idx']) ? $_POST['idx'] : $_GET['idx']));
        $ids = $projectdb->real_escape_string((string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']));
        $data = explode(",", $ids);
        take_snapshot_last($project);

        if($idx == ""){
            $idx = 0;
        }

        if ($ids != "") {
            $data = explode(",", $ids);
            foreach ($data as $key => $value) {
                $projectdb->query("UPDATE edit_table SET remove = '1' WHERE name = '$value' AND lid = '$idx' AND type = 'unitipaddress' AND user_id = '$user_id';");
            }
        }
        echo json_encode(array("success" => true));
    }
} 
elseif ($action == "update") {
    if ($type == "ipv4") {
        $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] :'');
        $source = (string) (isset($_POST['source']) ? $_POST['source'] : '');
        $idx = (string) (isset($_POST['idx']) ? $_POST['idx'] : '');
        $template = (string) (isset($_POST['template']) ? $_POST['template'] : '');
        $table_name = (string) (isset($_POST['table_name']) ? $_POST['table_name'] : '');
        $ids = (string) (isset($_POST['ids']) ? $_POST['ids'] : '');
        $name = (string) (isset($_POST['name']) ? $_POST['name'] : '');
        $oldname = (string) (isset($_POST['oldname']) ? $_POST['oldname'] : '');
        take_snapshot_last($project);

        if($idx == ""){
            $idx = 0;
        }

        $projectdb->query("UPDATE edit_table SET remove = '1' WHERE name = '$oldname' AND type = 'unitipaddress' AND lid = '$idx' AND user_id = '$user_id';");

        $getBridge = $projectdb->query("SELECT id FROM edit_table WHERE type = 'unitipaddress' AND name = '$name' AND user_id = '$user_id';");
        if ($getBridge->num_rows == 0) {

            $getBridgeId = $projectdb->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'unitipaddress' AND lid = '$idx' AND user_id = '$user_id';");
            if ($getBridgeId->num_rows == 1) {
                $getIdData = $getBridgeId->fetch_assoc();
                $ids = $getIdData['ids'] + 1;
            }else{
                $ids = 1;
            }

            $projectdb->query("INSERT INTO edit_table (id, ids, lid, type, name, image, source, remove, user_id) "
                . "VALUES (NULL, '$ids', '$idx', 'unitipaddress', '$name', '$oldname', '$template', '0', '$user_id');");
        }else{
            $projectdb->query("UPDATE edit_table SET remove = '0' WHERE name = '$name' AND type = 'unitipaddress' AND lid = '$idx' AND user_id = '$user_id';");
        }

        echo json_encode(array("success" => true));
    } 
    elseif ($type2 == "interfaces") {
        $vsys = (string)  (isset($_POST['vsys'])     ? $_POST['vsys'] : '');
        $source = (string) (isset($_POST['source']) ? $_POST['source'] : '');
        $id = (string) (isset($_POST['id']) ? $_POST['id'] : '');
        $name = (string) (isset($_POST['name']) ? $_POST['name'] : '');
        $unitname = (string) (isset($_POST['unitname']) ? $_POST['unitname'] : '');
        $media = (string) (isset($_POST['media']) ? $_POST['media'] : '');
        $comment = (string) (isset($_POST['comment']) ? $_POST['comment'] : '');
        $unittag = (string) (isset($_POST['unittag']) ? $_POST['unittag'] : '');
        $vr_id = (string) (isset($_POST['vr_id']) ? $_POST['vr_id'] : '');
        $vlan = (string) (isset($_POST['vlan']) ? $_POST['vlan'] : '');
        $zone = (string) (isset($_POST['zone']) ? $_POST['zone'] : '');
        $aggregate_group = (string) (isset($_POST['aggregate_group']) ? $_POST['aggregate_group'] : '');
        $vwire_id = (string) (isset($_POST['vwire_id']) ? $_POST['vwire_id'] : '');
        $ipv4_type = (string) (isset($_POST['ipv4_type']) ? $_POST['ipv4_type'] : '');
        $dhcp_client_enable = (string) (isset($_POST['dhcp_client_enable']) ? $_POST['dhcp_client_enable'] : '');
        $dhcp_client_create_default_route = (string) (isset($_POST['dhcp_client_create_default_route']) ? $_POST['dhcp_client_create_default_route'] : '');
        $dhcp_client_default_route_metric = (string) (isset($_POST['dhcp_client_default_route_metric']) ? $_POST['dhcp_client_default_route_metric'] : '');
        $interface_management_profile = (string) (isset($_POST['interface_management_profile']) ? $_POST['interface_management_profile'] : '');
        $mtu = (string) (isset($_POST['mtu']) ? $_POST['mtu'] : '');
        $link_speed = (string) (isset($_POST['link_speed']) ? $_POST['link_speed'] : '');
        $link_duplex = (string) (isset($_POST['link_duplex']) ? $_POST['link_duplex'] : '');
        $link_state = (string) (isset($_POST['link_state']) ? $_POST['link_state'] : '');
        $adjust_tcp_mss = (string) (isset($_POST['adjust_tcp_mss']) ? $_POST['adjust_tcp_mss'] : '');
        $untagged_sub_interface = (string) (isset($_POST['untagged_sub_interface']) ? $_POST['untagged_sub_interface'] : '');
        $lacp_port_priority = (string) (isset($_POST['lacp_port_priority']) ? $_POST['lacp_port_priority'] : '');

        $unitipaddress = '';
        $vr_vsys = "0";

        // Do some data validations before updating or creating the interface
        // 1) Check the VSYS
        //      Get the vsys from the virtual router selected so we make sure the interface and the virtual router has the same interface
        //      if not raise an error
        $query_vsys_from_VR = "SELECT name,vsys,source,template FROM virtual_routers where id = '$vr_id';";
        $get_vsys = $projectdb->query($query_vsys_from_VR);
        $vr_name = "";
        $vr_source = "";
        $vr_template = "";
        if ($get_vsys->num_rows > 0 ){
            $data_vsys = $get_vsys->fetch_assoc();
            $vr_vsys = $data_vsys['vsys']; // get the vsys name
            $vr_name = $data_vsys['name']; // get the vr name
            $vr_source = $data_vsys['source']; // get the source name
            $vr_template = $data_vsys['template']; // get the template name
        }

        // Check if the vr->vsys is the same as the interface->vsys
        if(($vr_vsys !== "0") && ($vsys !== "") && ($vsys !== $vr_vsys)){

            // Check if the config is from a multi vsys and vsys names are stored on virtual_systems table
            $query_vsys_from_VSYS = "SELECT name FROM virtual_systems where virtual_router = '$vr_name' and template = '$vr_template' and source = '$vr_source';";
            $get_vsys = $projectdb->query($query_vsys_from_VSYS);
            $vr_vsys_vr = array();
            $vr_vsys_vr[] = $vr_vsys;
            if ($get_vsys->num_rows > 0 ){

                while($data_vsys = $get_vsys->fetch_assoc()) {
                    $vr_vsys_vr[] = $data_vsys['name'];
                }
            }
            $vr_vsys_vr = arrayUnique($vr_vsys_vr);

            if(($vr_vsys !== "0") && ($vsys !== "") && (!in_array($vsys,$vr_vsys_vr))) {

                echo json_encode(array("success" => false, "msg" => "The Virtual Router is assigned to the VSYS [ ". implode(",", $vr_vsys_vr) ."].<br>Please go to tab DEVICE and assign the Virtual Router to the VSYS [$vsys]"));
                return -1;
            }
        }

        // 2) Check template selected is valid for the given source
        $query_template_mapping = "SELECT id FROM templates_mapping where source = '$source' and id = '$template';";
        $get_template_mapping = $projectdb->query($query_template_mapping);
        if ($get_template_mapping->num_rows === 0 ){
            echo json_encode(array("success" => false, "msg" => "The selected Template is not mapped with the selected Source.<br>Prior to edit any record, please select a proper Source/Template/DG(vsys)."));
            return -1;
        }

        if ($id == ""){
            $projectdb->query("INSERT INTO interfaces (template,vsys,source,name,media,unitname) VALUES ('$template','$vr_vsys','$source','$name','$media','$unitname');");
            $id = $projectdb->insert_id;
            $projectdb->query("UPDATE edit_table SET lid = '$id' WHERE user_id = '$user_id';");
        }

        take_snapshot_last($project);

        if (is_numeric($unitname)) {
            if ($unitname == 0) {
                $unitname = $name;
            } else {
                $unitname = $name . "." . $unitname;
            }
        }

        $getInterfaceName = $projectdb->query("SELECT unitname,template,zone,vr_id,vsys FROM interfaces WHERE id='$id';");
        if ($getInterfaceName->num_rows == 1) {
            $getInterfaceNameData = $getInterfaceName->fetch_assoc();
            $template = $getInterfaceNameData['template'];
            $Iname = $getInterfaceNameData['unitname'];
            $oldZone = $getInterfaceNameData['zone'];
            $oldvrid = $getInterfaceNameData['vr_id'];
            $oldvsys = $getInterfaceNameData['vsys'];

            if($type == 'virtual-wire'){
                $projectdb->query("UPDATE virtual_wires SET interface1='$unitname' WHERE interface1='$Iname' AND source='$source' AND template='$template';");
                $projectdb->query("UPDATE virtual_wires SET interface2='$unitname' WHERE interface2='$Iname' AND source='$source' AND template='$template';");
            }
            if($Iname != ""){
                $projectdb->query("UPDATE ipsec_tunnel SET tunnel_interface = '$unitname' WHERE source = '$source' AND template = '$template' AND tunnel_interface = '$Iname' ;");
                $projectdb->query("UPDATE ipsec_tunnel SET interface = '$unitname' WHERE source = '$source' AND template = '$template' AND interface = '$Iname' ;");

                $projectdb->query("UPDATE ike_gateways_profiles SET interface = '$unitname' WHERE source = '$source' AND template = '$template' AND interface = '$Iname' ;");
                $projectdb->query("UPDATE vlans SET virtual_interface = '$unitname' WHERE source = '$source' AND template = '$template' AND virtual_interface = '$Iname' ;");

                $projectdb->query("UPDATE gre_tunnel SET tunnel_interface = '$unitname' WHERE source = '$source' AND template = '$template' AND tunnel_interface = '$Iname' ;");
                $projectdb->query("UPDATE gre_tunnel SET interface = '$unitname' WHERE source = '$source' AND template = '$template' AND interface = '$Iname' ;");

                $projectdb->query("UPDATE nat_rules SET op_to_interface = '$unitname' WHERE source = '$source' AND vsys = '$vsys' AND op_to_interface = '$Iname' ;");
                $projectdb->query("UPDATE nat_rules SET tp_sat_interface = '$unitname' WHERE source = '$source' AND vsys = '$vsys' AND tp_sat_interface = '$Iname' ;");
                $projectdb->query("UPDATE nat_rules SET tp_sat_interface_fallback = '$unitname' WHERE source = '$source' AND vsys = '$vsys' AND tp_sat_interface_fallback = '$Iname' ;");

                $projectdb->query("UPDATE pbf_rules SET egress_interface = '$unitname' WHERE source = '$source' AND vsys = '$vsys' AND egress_interface = '$Iname' ;");

                $ids_rules = getIdsBySourceVsys("pbf_rules", $source, $vsys);
                $projectdb->query("UPDATE pbf_rules_from SET name='$unitname' WHERE name='$Iname' AND type = 'interface' AND rule_lid IN (".implode(',', $ids_rules).");");

                $ids_rules = getIdsBySourceVsys("dos_rules", $source, $vsys);
                $projectdb->query("UPDATE dos_rules_from SET name='$unitname' WHERE name='$Iname' AND type = 'interface' AND rule_lid IN (".implode(',', $ids_rules).");");
                $projectdb->query("UPDATE dos_rules_to SET name='$unitname' WHERE name='$Iname' AND type = 'interface' AND rule_lid IN (".implode(',', $ids_rules).");");

                # Update RIP Interfaces and Protocol from VirtualRouters
                $getInterfacesRIPVR = $projectdb->query("SELECT id, rip_interfaces, protocol FROM virtual_routers WHERE source = '$source' AND template = '$template';");
                if ($getInterfacesRIPVR->num_rows > 0) {
                    while($dataA = $getInterfacesRIPVR->fetch_assoc()){
                        $interface_rip = $dataA['rip_interfaces'];
                        $id_vr_rip = $dataA['id'];
                        $protocol = $dataA['protocol'];
                        $add_array = explode(",", $interface_rip);
                        if (in_array($Iname, $add_array)) {
                            $replace = str_replace($Iname, $unitname, $interface_rip);
                            $protocol = preg_replace('<entry name="'.$Iname.'">', 'entry name="'.$unitname.'"', $protocol);
                            $projectdb->query("UPDATE virtual_routers SET rip_interfaces = '$replace', protocol = '$protocol' WHERE id = '$id_vr_rip';");
                        }
                    }
                }

                if($type == "layer2"){
                    $getInterfacesVlans = $projectdb->query("SELECT id, interface FROM vlans WHERE source = '$source' AND template = '$template';");
                    if ($getInterfacesVlans->num_rows > 0) {
                        while($dataA = $getInterfacesVlans->fetch_assoc()){
                            $interface_vlans = $dataA['interface'];
                            $id_vlans = $dataA['id'];
                            $add_array = explode(",", $interface_vlans);
                            if (in_array($Iname, $add_array)) {
                                $replace = str_replace($Iname, $unitname, $interface_vlans);
                                $projectdb->query("UPDATE vlans SET interface = '$replace' WHERE id = '$id_vlans';");
                            }
                        }

                    }

                    $getMacInterfaces = $projectdb->query("SELECT id, mac_interfaces FROM vlans WHERE source = '$source' AND template = '$template';");
                    if ($getMacInterfaces->num_rows > 0) {
                        while($dataA = $getMacInterfaces->fetch_assoc()){
                            $interface_vlans = $dataA['mac_interfaces'];
                            $id_vlans = $dataA['id'];
                            $add_array = explode(",", $interface_vlans);
                            if (in_array($Iname, $add_array)) {
                                $replace = str_replace($Iname, $unitname, $interface_vlans);
                                $projectdb->query("UPDATE vlans SET mac_interfaces = '$replace' WHERE id = '$id_vlans';");
                            }
                        }

                    }
                }

                if (($Iname != $unitname) AND ( $type == "layer3")) {
                    rename_interface_unit($Iname, $unitname, $source, $template);
                }

            }
        }

        if ($type == "tap") {
            $unitipaddress = '';
            $interface_management_profile = '';
            $vr_id = '';
            $ipv4_type = '';
            $untagged_sub_interface = '';
            $vlan = "";
            $vwire_id = "";
            $aggregate_group = "";
            $dhcp_client_enable = "";
            $dhcp_client_create_default_route = "";
            $dhcp_client_default_route_metric = "";
            $adjust_tcp_mss = "";
            $lacp_port_priority = "0";
        }
        elseif ($type == "ha") {
            $zone = "";
            $vsys = "";
            $unitipaddress = '';
            $interface_management_profile = '';
            $vr_id = '';
            $ipv4_type = '';
            $untagged_sub_interface = '';
            $vlan = "";
            $vwire_id = "";
            $aggregate_group = "";
            $dhcp_client_enable = "";
            $dhcp_client_create_default_route = "";
            $dhcp_client_default_route_metric = "";
            $adjust_tcp_mss = "";
            $lacp_port_priority = "0";
        }
        elseif ($type == "virtual-wire") {
            $unitipaddress = '';
            $interface_management_profile = '';
            $vr_id = '';
            $ipv4_type = '';
            $untagged_sub_interface = '';
            $vlan = "";
            $aggregate_group = "";
            $dhcp_client_enable = "";
            $dhcp_client_create_default_route = "";
            $dhcp_client_default_route_metric = "";
            $adjust_tcp_mss = "";
            $lacp_port_priority = "0";

            $getVirtualWires = $projectdb->query("SELECT id, name, interface1, interface2 FROM virtual_wires WHERE id = '$vwire_id';");
            if($getVirtualWires->num_rows == 1){
                $getDataVW = $getVirtualWires->fetch_assoc();

                if($getDataVW['interface1'] == ""){
                    $projectdb->query("UPDATE virtual_wires SET interface1 = '$unitname' WHERE id = '$vwire_id';");
                }
                elseif ($getDataVW['interface2'] == ""){
                    $projectdb->query("UPDATE virtual_wires SET interface2 = '$unitname' WHERE id = '$vwire_id';");
                }
            }
        }
        elseif ($type == "layer2") {
            $unitipaddress = '';
            $interface_management_profile = '';
            $vr_id = '';
            $ipv4_type = '';
            $untagged_sub_interface = '';
            $vwire_id = "";
            $aggregate_group = "";
            $dhcp_client_enable = "";
            $dhcp_client_create_default_route = "";
            $dhcp_client_default_route_metric = "";
            $adjust_tcp_mss = "";
            $lacp_port_priority = "0";
        }
        elseif (($type == "layer3") || ($type == "vlan")){
            if ($ipv4_type == "ppoe") {
                $unitipaddress = '';
                $vlan = "";
                $vwire_id = "";
                $aggregate_group = "";
                $dhcp_client_enable = "";
                $dhcp_client_create_default_route = "";
                $dhcp_client_default_route_metric = "";
            }
            elseif ($ipv4_type == "static") {

                $getUnitipaddress = $projectdb->query("SELECT name, image AS oldname FROM edit_table WHERE type = 'unitipaddress' AND lid = '$id' AND remove = '0' AND user_id = '$user_id' ORDER BY ids ASC;");
                if($getUnitipaddress->num_rows > 0){
                    while($dataU = $getUnitipaddress->fetch_assoc()){
                        $unitipaddress_array[] = $dataU['name'];
                        $name_unit = $dataU['name'];
                        $oldname_unit = $dataU['oldname'];

                        if($oldname_unit != ""){
                            #Update Nat Rules
                            $projectdb->query("UPDATE nat_rules SET tp_sat_ipaddress='$name_unit' WHERE source='$source' AND tp_sat_ipaddress='$oldname_unit' AND tp_sat_interface = '$unitname';");

                            #Update IKE Gateways, IPsec Tunnels and GRE Tunnels (v9)
                            $projectdb->query("UPDATE ike_gateways_profiles SET local_address_ip = '$name_unit' WHERE source='$source' AND local_address_ip = '$oldname_unit' AND interface = '$unitname' ;");
                            $projectdb->query("UPDATE ipsec_tunnel SET local_address_ip = '$name_unit' WHERE source='$source' AND local_address_ip = '$oldname_unit' AND interface = '$unitname' ;");

                            $projectdb->query("UPDATE gre_tunnel SET local_address_ip = '$name_unit' WHERE source='$source' AND local_address_ip = '$oldname_unit' AND interface = '$unitname' ;");

                        }

                    }
                    $unitipaddress = implode(",", $unitipaddress_array);
                }else{
                    $unitipaddress = "";
                }

                # Update if remove
                $getUnitipaddress = $projectdb->query("SELECT name FROM edit_table WHERE type = 'unitipaddress' AND lid = '$id' AND remove = '1' AND user_id = '$user_id' ORDER BY ids ASC;");
                if($getUnitipaddress->num_rows > 0) {
                    while ($dataU = $getUnitipaddress->fetch_assoc()) {
                        $unitipaddress_array[] = $dataU['name'];
                        $name_unit = $dataU['name'];

                        if($name_unit != ""){
                            #Update Nat Rules
                            $projectdb->query("UPDATE nat_rules SET tp_sat_ipaddress='' WHERE source='$source' AND tp_sat_ipaddress='$name_unit' AND tp_sat_interface = '$unitname';");

                            #Update IKE Gateways, IPsec Tunnels and GRE Tunnel (v9)
                            $projectdb->query("UPDATE ike_gateways_profiles SET local_address_ip = '' WHERE source='$source' AND local_address_ip = '$name_unit' AND interface = '$unitname' ;");
                            $projectdb->query("UPDATE ipsec_tunnel SET local_address_ip = '' WHERE source='$source' AND local_address_ip = '$name_unit' AND interface = '$unitname' ;");

                            $projectdb->query("UPDATE gre_tunnel SET local_address_ip = '$name_unit' WHERE source='$source' AND local_address_ip = '$oldname_unit' AND interface = '$unitname' ;");

                        }
                    }
                }

                $vlan = "";
                $vwire_id = "";
                $aggregate_group = "";
                $dhcp_client_enable = "";
                $dhcp_client_create_default_route = "";
                $dhcp_client_default_route_metric = "";
            }
            elseif ($ipv4_type == "dhcp-client") {
                $unitipaddress = '';
                $vlan = "";
                $vwire_id = "";
                $aggregate_group = "";
            }
            if($type == "vlan"){
                $link_speed = "";
                $link_duplex = "";
                $link_state = "";
            }
            $lacp_port_priority = "0";
        }
        elseif ($type == "aggregate-group") {
            $unitipaddress = '';
            $interface_management_profile = '';
            $zone = '';
            $vr_id = '';
            $ipv4_type = '';
            $untagged_sub_interface = '';
            $vlan = "";
            $vwire_id = "";
            $dhcp_client_enable = "";
            $dhcp_client_create_default_route = "";
            $dhcp_client_default_route_metric = "";
            $adjust_tcp_mss = "";
        }
        elseif(($type == "log-card") || ($type == "decrypt-mirror")){

        }

        //If different to virtual_wire, update interfaces from table virtual_wire
        if($type != "virtual-wire"){
            $projectdb->query("UPDATE virtual_wires SET interface1 = '' WHERE interface1 = '$unitname' AND source = '$source' AND template = '$template'; ");
            $projectdb->query("UPDATE virtual_wires SET interface2 = '' WHERE interface2 = '$unitname' AND source = '$source' AND template = '$template'; ");
        }

        #Update
        if ($zone == "None") {
            $zone = "";
        }

        if ($interface_management_profile=="None"){
            $interface_management_profile='';
        }

        if ($vr_id == "0") {
            $vr_id = "";
        }


        #Update Zone
        if (($zone != $oldZone) AND ( $oldZone != "")) {
            $getInterfaces = $projectdb->query("SELECT id,interfaces FROM zones WHERE template='$template' AND name='$oldZone'");
            if ($getInterfaces->num_rows == 1) {
                $getInterfacesData = $getInterfaces->fetch_assoc();
                $zoneID = $getInterfacesData['id'];
                $oldInterfaces = explode(",", $getInterfacesData['interfaces']);
                if (($key = array_search($unitname, $oldInterfaces)) !== false) {
                    unset($oldInterfaces[$key]);
                }
                $projectdb->query("UPDATE zones SET interfaces='" . implode(",", $oldInterfaces) . "' WHERE id='$zoneID'");
            }
        }
        $getInterfaces = $projectdb->query("SELECT id,interfaces FROM zones WHERE template='$template' AND name='$zone'");
        if ($getInterfaces->num_rows == 1) {
            $getInterfacesData = $getInterfaces->fetch_assoc();
            $zoneID = $getInterfacesData['id'];
            $oldInterfaces = explode(",", $getInterfacesData['interfaces']);
            $oldInterfaces[] = $unitname;
            $unique = array_unique($oldInterfaces);
            $projectdb->query("UPDATE zones SET interfaces='" . implode(",", $unique) . "' WHERE id='$zoneID'");
        }

        #Update VR
        if (($vr_id != $oldvrid) AND ( $oldvrid != "")) {
            $getInterfaces = $projectdb->query("SELECT interfaces FROM virtual_routers WHERE id='$oldvrid'");
            if ($getInterfaces->num_rows == 1) {
                $getInterfacesData = $getInterfaces->fetch_assoc();
                $oldInterfaces = explode(",", $getInterfacesData['interfaces']);
                if (($key = array_search($unitname, $oldInterfaces)) !== false) {
                    unset($oldInterfaces[$key]);
                }
                $unique = array_unique($oldInterfaces);
                $projectdb->query("UPDATE virtual_routers SET interfaces='" . implode(",", $unique) . "' WHERE id='$oldvrid'");
            }
        }

        if (($vr_id != "") OR ( $vr_id != "0")) {
            $getInterfaces = $projectdb->query("SELECT interfaces FROM virtual_routers WHERE id='$vr_id'");
            if ($getInterfaces->num_rows == 1) {
                $getInterfacesData = $getInterfaces->fetch_assoc();
                if ($getInterfacesData['interfaces'] == "") {
                    $projectdb->query("UPDATE virtual_routers SET interfaces='" . $unitname . "' WHERE id='$vr_id'");
                } else {
                    $oldInterfaces = explode(",", $getInterfacesData['interfaces']);
                    $oldInterfaces[] = $unitname;
                    $unique = array_unique($oldInterfaces);
                    $projectdb->query("UPDATE virtual_routers SET interfaces='" . implode(",", $unique) . "' WHERE id='$vr_id'");
                }

            }
        }

        #Update VSYS
        if (($vsys != $oldvsys) AND ( $oldvsys != "")) {
            $getInterfaces = $projectdb->query("SELECT id,interfaces FROM virtual_systems WHERE name='$oldvsys' AND source='$source'");
            if ($getInterfaces->num_rows == 1) {
                $getInterfacesData = $getInterfaces->fetch_assoc();
                $oldvsysid = $getInterfacesData['id'];
                $oldInterfaces = explode(",", $getInterfacesData['interfaces']);
                if (($key = array_search($unitname, $oldInterfaces)) !== false) {
                    unset($oldInterfaces[$key]);
                }
                $unique = array_unique($oldInterfaces);
                $projectdb->query("UPDATE virtual_systems SET interfaces='" . implode(",", $unique) . "' WHERE id='$oldvsysid'");
            }
        }
        if (($vsys != "") OR ( $vsys != "None")) {
            $getInterfaces = $projectdb->query("SELECT id,interfaces FROM virtual_systems WHERE name='$vsys' AND source='$source'");
            if ($getInterfaces->num_rows == 1) {
                $getInterfacesData = $getInterfaces->fetch_assoc();
                $oldvsysid = $getInterfacesData['id'];
                if ($getInterfacesData['interfaces'] == "") {
                    $projectdb->query("UPDATE virtual_systems SET interfaces='" . $unitname . "' WHERE id='$oldvsysid'");
                } else {
                    $oldInterfaces = explode(",", $getInterfacesData['interfaces']);
                    $oldInterfaces[] = $unitname;
                    $unique = array_unique($oldInterfaces);
                    $projectdb->query("UPDATE virtual_systems SET interfaces='" . implode(",", $unique) . "' WHERE id='$oldvsysid'");
                }
            }
        }

        $projectdb->query("UPDATE interfaces SET unitipaddress='$unitipaddress',comment='$comment',link_speed='$link_speed',link_duplex='$link_duplex',link_state='$link_state',vsys='$vsys',zone='$zone',vr_id='$vr_id',ipv4_type='$ipv4_type',type='$type',interface_management_profile='$interface_management_profile',mtu='$mtu',untagged_sub_interface='$untagged_sub_interface', name='$name',unitname='$unitname',unittag='$unittag',vlan='$vlan',aggregate_group='$aggregate_group',vwire_id='$vwire_id',dhcp_client_enable='$dhcp_client_enable',dhcp_client_create_default_route='$dhcp_client_create_default_route',dhcp_client_default_route_metric='$dhcp_client_default_route_metric', adjust_tcp_mss='$adjust_tcp_mss', lacp_port_priority='$lacp_port_priority' WHERE id='$id';");

    }
}
?>