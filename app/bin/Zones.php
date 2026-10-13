<?php

# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
//require_once('./Authentication.php');
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
require_once INC_ROOT.'/userManager/start.php';
include INC_ROOT.'/bin/authentication/sessionControl.php';

require_once INC_ROOT.'/libs/database.php';
require_once INC_ROOT.'/libs/projectdb.php';
require_once INC_ROOT.'/libs/shared.php';
require_once INC_ROOT.'/libs/common/lib-rules.php';

require_once INC_ROOT.'/bin/messaging/MessageSender.php';
require_once INC_ROOT.'/userManager/API/projects/manageSettings.php';
require_once INC_ROOT.'/libs/common/tools/filters.php';

require_once INC_ROOT.'/libs/objects/tools/usage/ZoneUsage.php';

$request_body   = file_get_contents('php://input');
$data           = json_decode($request_body, true);

include INC_ROOT.'/bin/middleware_sanitizer.php';

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $action     = (string)  (isset($_GET['action'])    ? $_GET['action'] : '');
        $type       = (string)  (isset($_GET['type'])      ? $_GET['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_GET['project'])   ? $_GET['project'] : '');
        $start      = (integer) (isset($_GET['start'])     ? $_GET['start'] : '');
        $limit      = (integer) (isset($_GET['limit'])     ? $_GET['limit'] : '');
        $zonetype   = (string)  (isset($_GET['zonetype'])  ? $_GET['zonetype'] : '');
        $vsys       = (string)  (isset($_GET['vsys'])      ? $_GET['vsys'] : '');
        $source     = (string)  (isset($_GET['source'])    ? $_GET['source'] : '');
        $idx        = (string)  (isset($_GET['idx'])       ? $_GET['idx'] : '');
        $ids        = (string)  (isset($_GET['ids'])       ? $_GET['ids'] : '');
        $template   = (string)  (isset($_GET['template'])  ? $_GET['template'] : '');
        $table_name = (string)  (isset($_GET['table_name'])? $_GET['table_name'] : '');
        $total_name = (string)  (isset($_GET['name'])      ? $_GET['name'] : '');
        $name                       = (string) (isset($_GET['name'])                       ? $_GET['name'] : '');
        $id                         = (string) (isset($_GET['id'])                         ? $_GET['id'] : '');
        $zone_protection_profile    = (string) (isset($_GET['zone_protection_profile'])    ? $_GET['zone_protection_profile'] : '');
        $log_setting                = (string) (isset($_GET['log_setting'])                ? $_GET['log_setting'] : '');
        $enable_user_identification = (string) (isset($_GET['enable_user_identification']) ? $_GET['enable_user_identification'] : '');
        $log_settings_idx           = (string) (isset($_GET['log_setting_id'])             ? $_GET['log_setting_id'] : '');
        $log_settings_table_name    = (string) (isset($_GET['log_setting_table_name'])     ? $_GET['log_setting_table_name'] : '');
        $oldname    = (string) (isset($_GET['oldname'])    ? $_GET['oldname'] : '');
        $filter     = (string)  (isset($_GET['filter'])     ? $_GET['filter'] : '');
        $enable_packet_buffer_protection    = (string) (isset($_GET['enable_packet_buffer_protection'])    ? $_GET['enable_packet_buffer_protection'] : '');
        $forceDelete=   (bool)    (isset($_GET['forceDelete']) && $_GET['forceDelete']=='1')? true:false;
        $createFilters= (bool)    (isset($_GET['createFilters']) && $_GET['createFilters']=='1')? true:false;
        break;
    case 'POST':
        $action     = (string)  (isset($_POST['action'])    ? $_POST['action'] : '');
        $type       = (string)  (isset($_POST['type'])      ? $_POST['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_POST['project'])   ? $_POST['project'] : '');
        $start      = (integer) (isset($_POST['start'])     ? $_POST['start'] : '');
        $limit      = (integer) (isset($_POST['limit'])     ? $_POST['limit'] : '');
        $zonetype   = (string)  (isset($_POST['zonetype'])  ? $_POST['zonetype'] : '');
        $vsys       = (string)  (isset($_POST['vsys'])      ? $_POST['vsys'] : '');
        $source     = (string)  (isset($_POST['source'])    ? $_POST['source'] : '');
        $idx        = (string)  (isset($_POST['idx'])       ? $_POST['idx'] : '');
        $ids        = (string)  (isset($_POST['ids'])       ? $_POST['ids'] : '');
        $template   = (string)  (isset($_POST['template'])  ? $_POST['template'] : '');
        $table_name = (string)  (isset($_POST['table_name'])? $_POST['table_name'] : '');
        $total_name = (string)  (isset($_POST['name'])      ? $_POST['name'] : '');
        $name                       = (string) (isset($_POST['name'])                       ? $_POST['name'] : '');
        $id                         = (string) (isset($_POST['id'])                         ? $_POST['id'] : '');
        $zone_protection_profile    = (string) (isset($_POST['zone_protection_profile'])    ? $_POST['zone_protection_profile'] : '');
        $log_setting                = (string) (isset($_POST['log_setting'])                ? $_POST['log_setting'] : '');
        $enable_user_identification = (string) (isset($_POST['enable_user_identification']) ? $_POST['enable_user_identification'] : '');
        $log_settings_idx           = (string) (isset($_POST['log_setting_id'])             ? $_POST['log_setting_id'] : '');
        $log_settings_table_name    = (string) (isset($_POST['log_setting_table_name'])     ? $_POST['log_setting_table_name'] : '');
        $oldname    = (string) (isset($_POST['oldname'])    ? $_POST['oldname'] : '');
        $enable_packet_buffer_protection    = (string) (isset($_POST['enable_packet_buffer_protection'])    ? $_POST['enable_packet_buffer_protection'] : '');
        $filter     = (string)  (isset($_POST['filter'])    ? $_POST['filter'] : '');
        $forceDelete=   (bool)    (isset($_POST['forceDelete']) && $_POST['forceDelete']=='1')? true:false;
        $createFilters= (bool)    (isset($_POST['createFilters']) && $_POST['createFilters']=='1')? true:false;
        break;

    default:
        $action     = (string)  (isset($_POST['action'])    ? $_POST['action'] : '');
        $type       = (string)  (isset($_POST['type'])      ? $_POST['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_POST['project'])   ? $_POST['project'] : '');
        $start      = (integer) (isset($_POST['start'])     ? $_POST['start'] : '');
        $limit      = (integer) (isset($_POST['limit'])     ? $_POST['limit'] : '');
        $zonetype   = (string)  (isset($_POST['zonetype'])  ? $_POST['zonetype'] : '');
        $vsys       = (string)  (isset($_POST['vsys'])      ? $_POST['vsys'] : '');
        $source     = (string)  (isset($_POST['source'])    ? $_POST['source'] : '');
        $idx        = (string)  (isset($_POST['idx'])       ? $_POST['idx'] : '');
        $ids        = (string)  (isset($_POST['ids'])       ? $_POST['ids'] : '');
        $template   = (string)  (isset($_POST['template'])  ? $_POST['template'] : '');
        $table_name = (string)  (isset($_POST['table_name'])? $_POST['table_name'] : '');
        $total_name = (string)  (isset($_POST['name'])      ? $_POST['name'] : '');
        $name                       = (string) (isset($_POST['name'])                       ? $_POST['name'] : '');
        $id                         = (string) (isset($_POST['id'])                         ? $_POST['id'] : '');
        $zone_protection_profile    = (string) (isset($_POST['zone_protection_profile'])    ? $_POST['zone_protection_profile'] : '');
        $log_setting                = (string) (isset($_POST['log_setting'])                ? $_POST['log_setting'] : '');
        $enable_user_identification = (string) (isset($_POST['enable_user_identification']) ? $_POST['enable_user_identification'] : '');
        $log_settings_idx           = (string) (isset($_POST['log_setting_id'])             ? $_POST['log_setting_id'] : '');
        $log_settings_table_name    = (string) (isset($_POST['log_setting_table_name'])     ? $_POST['log_setting_table_name'] : '');
        $oldname    = (string) (isset($_POST['oldname'])    ? $_POST['oldname'] : '');
        $enable_packet_buffer_protection    = (string) (isset($_POST['enable_packet_buffer_protection'])    ? $_POST['enable_packet_buffer_protection'] : '');
        $filter     = (string)  (isset($_POST['filter'])    ? $_POST['filter'] : '');
        $forceDelete=   (bool)    (isset($_POST['forceDelete']) && $_POST['forceDelete']=='1')? true:false;
        $createFilters= (bool)    (isset($_POST['createFilters']) && $_POST['createFilters']=='1')? true:false;
        break;
}

//$project="TEST";
//$action="autozone";
$projectdb = selectDatabase($project);

$action = $projectdb->real_escape_string($action);
$type = $projectdb->real_escape_string($type);
$project = $projectdb->real_escape_string($project);
$start = $projectdb->real_escape_string($start);
$limit = $projectdb->real_escape_string($limit);
$zonetype = $projectdb->real_escape_string($zonetype);
$vsys = $projectdb->real_escape_string($vsys);
$source = $projectdb->real_escape_string($source);
$idx = $projectdb->real_escape_string($idx);
$ids = $projectdb->real_escape_string($ids);
$template = $projectdb->real_escape_string($template);
$table_name = $projectdb->real_escape_string($table_name);
$total_name = $projectdb->real_escape_string($total_name);
$name = $projectdb->real_escape_string($name);
$id = $projectdb->real_escape_string($id);
$zone_protection_profile = $projectdb->real_escape_string($zone_protection_profile);
$log_setting = $projectdb->real_escape_string($log_setting);
$enable_user_identification = $projectdb->real_escape_string($enable_user_identification);
$log_settings_idx = $projectdb->real_escape_string($log_settings_idx);
$log_settings_table_name = $projectdb->real_escape_string($log_settings_table_name);
$oldname = $projectdb->real_escape_string($oldname);
$enable_packet_buffer_protection = $projectdb->real_escape_string($enable_packet_buffer_protection);
$filter = $projectdb->real_escape_string($filter);

global $app;
$user = $app->container->sentinel->getUser();
$user_id = $user->id;

if ($action == "get") {
    if ($type == "zones") {
        $query = generate_query("template");
        $name_zone_last = "";
        $mylastvsys="";

        if(($filter != "none") && ($filter != "0")){

            $paramsDefineFilter['tools_where_columns_id'] = $filter;
            $paramsDefineFilter['tools_operator_id'] = "contains";
            $paramsDefineFilter['search'] = "";
            $paramsDefineFilter['tools_where_id'] = "19";
            $paramsDefineFilter['tools_advanced_columns_id'] = "None";
            $paramsDefineFilter['is_set_sql_filter'] = "yes";
            $paramsDefineFilter['source'] = $source;
            $paramsDefineFilter['vsys'] = $vsys;
            $paramsDefineFilter['case_sensitive'] = "0";

            setFilter($project, $paramsDefineFilter);
            executeSQL($project, $paramsDefineFilter);

        }
        elseif(($filter == "none") || ($filter == "0")){
        }

        list($query, $orderby) = generateQueryFilters($project, "zones", "", $query, $source);

        $getAll = $projectdb->query("SELECT id FROM zones $query;");
        $count = $getAll->num_rows;
        $getLimit = $projectdb->query("SELECT * FROM zones $query ORDER BY type,name ASC LIMIT $start, $limit;");
        if ($getLimit->num_rows > 0) {
            while ($data = $getLimit->fetch_assoc()) {
                if (($data['log_setting_id'] != "") AND ( $data['log_setting_table_name'] != "")) {
                    $id = $data['log_setting_id'];
                    $table = $data['log_setting_table_name'];
                    $getLS = $projectdb->query("SELECT name FROM $table WHERE id='$id';");
                    if ($getLS->num_rows == 1) {
                        $getLSdata = $getLS->fetch_assoc();
                        $data['log_setting'] = $getLSdata['name'];
                    }
                } else {
                    $data['log_setting'] = "None";
                }
                $myvsys=$data['vsys'];
                $name_zone = $data['name'];
                if($name_zone_last != ""){
                    if (($name_zone_last == $name_zone) AND ($myvsys == $mylastvsys)){
                        $data['warning'] = "1";
                    }else{
                        $data['warning'] = "0";
                    }
                }else{
                    $data['warning'] = "0";
                }
                $name_zone_last = $name_zone;
                //if ($data['enable_packet_buffer_protection']=="yes"){
                //    $data['enable_packet_buffer_protection']="on";
                //}
                $mylastvsys=$myvsys;
                $myData[] = $data;
            }
        }


        if ($count == 0) {
            $myData = "";
        }
        echo '{"total":"' . $count . '","zones":' . json_encode($myData) . '}';
    }
    elseif ($type == "zones_all") {

        //$query = generate_query("zones");
        $query = generate_query("template");

        $getAll = $projectdb->query("SELECT id FROM zones $query;");
        $count = $getAll->num_rows;
        $getLimit = $projectdb->query("SELECT * FROM zones $query GROUP BY name ORDER BY type,name ASC;");
        while ($data = $getLimit->fetch_assoc()) {
            if (($data['log_setting_id'] != "") AND ( $data['log_setting_table_name'] != "")) {
                $id = $data['log_setting_id'];
                $table = $data['log_setting_table_name'];
                $getLS = $projectdb->query("SELECT name FROM $table WHERE id='$id';");
                if ($getLS->num_rows == 1) {
                    $getLSdata = $getLS->fetch_assoc();
                    $data['log_setting'] = $getLSdata['name'];
                }
            } else {
                $data['log_setting'] = "None";
            }
            $myData[] = $data;
        }

        if ($count == 0) {
            $myData = "";
        }
        echo '{"total":"' . $count . '","zones":' . json_encode($myData) . '}';
    }
    elseif ($type == "zones_all_edit_rules") {

        $myData = array();
        $myData_unique = array();

        $query = generate_query("zones");

        global $app;
        $user = $app->container->sentinel->getUser();
        $userID = $user->id;

        $settings = get_UserSettings($project, $userID);

        $userSettings = $settings['msg'];

        $view = $userSettings['view'];

        $getLimit = $projectdb->query("SELECT name FROM zones $query GROUP BY name ORDER BY name ASC;");
        //echo "SELECT name FROM zones $query GROUP BY name ORDER BY name ASC;";
        if($getLimit->num_rows > 0){
            while ($data = $getLimit->fetch_assoc()) {
                $myData[] = $data;
            }
        }


        // If is a Panorama, show too zones from security_rules_from and securtiy_rules_to
        if ($view == "panorama") {

            $query_vsys = "";
            if($vsys != "all"){
                $query_vsys = " AND vsys = '$vsys' ";
            }
            $getLimit = $projectdb->query("SELECT name FROM security_rules_from $query $query_vsys GROUP BY name ORDER BY name ASC;");
            while ($data = $getLimit->fetch_assoc()) {

                if (in_array($data, $myData)) {
                } else {
                    $myData[] = $data;
                }
            }
            $getLimit = $projectdb->query("SELECT name FROM security_rules_to $query $query_vsys GROUP BY name ORDER BY name ASC;");
            while ($data = $getLimit->fetch_assoc()) {

                if (in_array($data, $myData)) {
                } else {
                    $myData[] = $data;
                }

            }
        }

        /*if ($source==0){$query="";}
        else{$query="WHERE source='$source'";}
        $getAll=$projectdb->query("SELECT id,name,master_device,devices,device_mapping_id,source,description,parent_dg FROM devicegroups $query;");
        $myData[]=array("id"=>0, "name"=>"shared", "parent_dg"=>0, "device_mapping_id"=>0,"devices"=>"");
        while ($data=$getAll->fetch_object()){
            $mapid=$data->device_mapping_id;
            $k=$projectdb->query("SELECT vsys FROM device_mapping WHERE id='$mapid';");
            if ($k->num_rows==1){
                $datas=$k->fetch_assoc();
                $data->name=$datas['vsys'];
            }
            $parent_dg=$data->parent_dg;
            $q=$projectdb->query("SELECT vsys FROM device_mapping WHERE id='$parent_dg';");
            if ($q->num_rows==1){
                $datas=$q->fetch_assoc();
                $data->parent_dg_name=$datas['vsys'];
            }else{
                $data->parent_dg_name="shared";
                $parent_dg=0;
            }

            if ($data->devices!=""){
                $DataSerial=array();
                $device=simplexml_load_string($data->devices);

                foreach ($device as $entry){
                    if (isset($entry->vsys)){
                        $DataSerial[]="<img valign=middle src=/resources/images/icons/device.gif>&nbsp;".(string)$entry->attributes()->name."/".$entry->vsys->entry->attributes()->name;
                    }
                    else{
                        $DataSerial[]="<img valign=middle src=/resources/images/icons/device.gif>&nbsp;".(string)$entry->attributes()->name;
                    }

                }

                $data->devices=implode("<br>",$DataSerial);
            }

            $myData[]=$data;
        }*/


        $count = count($myData);

        echo '{"total":"' . $count . '","zones":' . json_encode($myData) . '}';
    }
    elseif ($type == "zones_all_edit_rules_nat") {

        $myData = array();
        $myData_unique = array();

        $query = generate_query("zones");

        global $app;
        $user = $app->container->sentinel->getUser();
        $userID = $user->id;

        $settings = get_UserSettings($project, $userID);

        $userSettings = $settings['msg'];

        $view = $userSettings['view'];

        $getLimit = $projectdb->query("SELECT name FROM zones $query GROUP BY name ORDER BY name ASC;");
        if($getLimit->num_rows > 0){
            while ($data = $getLimit->fetch_assoc()) {
                $myData[] = $data;
            }
        }


        // If is a Panorama, show too zones from security_rules_from and securtiy_rules_to
        if ($view == "panorama") {
            $query_vsys = "";
            if($vsys != "all"){
                $query_vsys = " AND vsys = '$vsys' ";
            }
            $getLimit = $projectdb->query("SELECT name FROM nat_rules_from $query $query_vsys GROUP BY name ORDER BY name ASC;");
            while ($data = $getLimit->fetch_assoc()) {
                if (in_array($data, $myData)) {
                } else {
                    $myData[] = $data;
                }
            }
            $getLimit = $projectdb->query("SELECT op_zone_to AS name FROM nat_rules $query $query_vsys GROUP BY op_zone_to ORDER BY op_zone_to ASC;");
            while ($data = $getLimit->fetch_assoc()) {

                if (in_array($data, $myData)) {
                } else {
                    $myData[] = $data;
                }

            }
        }

        $count = count($myData);

        echo '{"total":"' . $count . '","zones":' . json_encode($myData) . '}';
    }
    elseif ($type == "zones_all_edit_rules_appoverride") {

        $myData = array();
        $myData_unique = array();

        $query = generate_query("zones");

        global $app;
        $user = $app->container->sentinel->getUser();
        $userID = $user->id;

        $settings = get_UserSettings($project, $userID);

        $userSettings = $settings['msg'];

        $view = $userSettings['view'];

        $getLimit = $projectdb->query("SELECT name FROM zones $query GROUP BY name ORDER BY name ASC;");
        if($getLimit->num_rows > 0){
            while ($data = $getLimit->fetch_assoc()) {
                $myData[] = $data;
            }
        }

        // If is a Panorama, show too zones from security_rules_from and securtiy_rules_to
        if ($view == "panorama") {
            $query_vsys = "";
            if($vsys != "all"){
                $query_vsys = " AND vsys = '$vsys' ";
            }
            $getLimit = $projectdb->query("SELECT name FROM appoverride_rules_from $query $query_vsys GROUP BY name ORDER BY name ASC;");
            while ($data = $getLimit->fetch_assoc()) {
                if (in_array($data, $myData)) {
                } else {
                    $myData[] = $data;
                }
            }
            $getLimit = $projectdb->query("SELECT name FROM appoverride_rules_to $query $query_vsys GROUP BY name ORDER BY name ASC;");
            while ($data = $getLimit->fetch_assoc()) {

                if (in_array($data, $myData)) {
                } else {
                    $myData[] = $data;
                }

            }
        }

        $count = count($myData);

        echo '{"total":"' . $count . '","zones":' . json_encode($myData) . '}';
    }
    elseif ($type == "zones_by_type") {
        $query = generate_query("template");
        if (preg_match("/WHERE/", $query)) {
            $query = $query . " AND type='$zonetype' ";
        } else {
            $query = "WHERE type='$zonetype' ";
        }
        $myData[]=array("id"=>"0","name"=>"None");
        $getAll = $projectdb->query("SELECT id FROM zones $query;");
        $getLimit = $projectdb->query("SELECT * FROM zones $query ORDER BY type,name ASC LIMIT $start, $limit;");
        if ($getAll->num_rows>0){
            while ($data = $getLimit->fetch_assoc()) {
                if (($data['log_setting_id'] != "") AND ( $data['log_setting_table_name'] != "")) {
                    $id = $data['log_setting_id'];
                    $table = $data['log_setting_table_name'];
                    $getLS = $projectdb->query("SELECT name FROM $table WHERE id='$id';");
                    if ($getLS->num_rows == 1) {
                        $getLSdata = $getLS->fetch_assoc();
                        $data['log_setting'] = $getLSdata['name'];
                    }
                } else {
                    $data['log_setting'] = "None";
                }
                $myData[] = $data;
            }
        }
        echo '{"total":"' . count($myData) . '","zones":' . json_encode($myData) . '}';
    }
    elseif ($type == "zones_by_type_multiedit_interfaces") {
        $query = generate_query("template");
        if($zonetype != ""){
            if (preg_match("/WHERE/", $query)) {
                $query = $query . " AND type='$zonetype' ";
            } else {
                $query = "WHERE type='$zonetype' ";
            }
        }
        $myData[]=array("id"=>"0","name"=>"None");
        $getAll = $projectdb->query("SELECT id FROM zones $query;");
        $getLimit = $projectdb->query("SELECT * FROM zones $query ORDER BY type,name ASC LIMIT $start, $limit;");
        if ($getAll->num_rows>0){
            while ($data = $getLimit->fetch_assoc()) {
                $myData[] = $data;
            }
        }
        echo '{"total":"' . count($myData) . '","zones":' . json_encode($myData) . '}';
    }
    elseif ($type == "interfaces") {

        if($idx == ""){
            $idx = 0;
        }

        $address = array();
        $getAddress = $projectdb->query("SELECT interfaces FROM zones WHERE id = '$idx' AND interfaces != '';");
        if ($getAddress->num_rows == 1) {
            $dataA = $getAddress->fetch_assoc();
            $add = $dataA['interfaces'];
            $add_explode = explode(",", $add);
            $count = count($add_explode);
            foreach ($add_explode as $key => $value) {

                $getBridgeId = $projectdb->query("SELECT id FROM edit_table WHERE name = '$value' AND type = 'interfaces' AND lid = '$idx' AND user_id = '$user_id';");
                if ($getBridgeId->num_rows == 0) {
                    $getBridgeId = $projectdb->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'interfaces' AND lid = '$idx' AND user_id = '$user_id';");
                    if ($getBridgeId->num_rows == 1) {
                        $getIdData = $getBridgeId->fetch_assoc();
                        $ids = $getIdData['ids'] + 1;
                    }else{
                        $ids = 1;
                    }
                    $projectdb->query("INSERT INTO edit_table (id, ids, lid, type, name, source, remove, user_id) "
                        . "VALUES (NULL, '$ids', '$idx', 'interfaces', '$value', '$template', '0', '$user_id');");
                }

            }
            if ($add == "") {
                $count = 0;
                $address = "";
            }
            else{
                $getLimit = $projectdb->query("SELECT id, ids, name FROM edit_table WHERE type = 'interfaces' AND remove = '0' AND user_id = '$user_id' ORDER BY ids;");
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
            $getLimit = $projectdb->query("SELECT id, ids, name FROM edit_table WHERE type = 'interfaces' AND remove = '0' AND user_id = '$user_id' ORDER BY ids;");
            $count = $getLimit->num_rows;
            if ($getLimit->num_rows > 0) {
                while ($data = $getLimit->fetch_object()) {
                    $address[] = $data;
                }
            }
            echo '{"total":"' . $count . '","elements":' . json_encode($address) . '}';
        }

    }
    elseif($type == "zones_include_list"){
        
        switch($_SERVER['REQUEST_METHOD'])
        {
            case 'GET':
                $idx        = (string)  (isset($_GET['zone_id'])   ? $_GET['zone_id'] : '');
                break;
            case 'POST':
                $idx        = (string)  (isset($_POST['zone_id'])   ? $_POST['zone_id'] : '');
                break;

            default:
                $idx        = (string)  (isset($_POST['zone_id'])   ? $_POST['zone_id'] : '');
                break;
        }

        $idx = $projectdb->real_escape_string($idx);

        if ($idx != "") {
            $thetag = array();
            $getTag = $projectdb->query("SELECT include_list FROM zones WHERE id = '$idx';");
            if ($getTag->num_rows == 1) {
                $getTagData = $getTag->fetch_assoc();
                $tags = $getTagData['include_list'];
                $tag = explode(",", $tags);
                $count = count($tag);
                foreach ($tag as $key => $value) {
                    $thetag[] = array("include_list" => $value);
                }
                if ($tags == "") {
                    $count = 0;
                    $thetag = "";
                }
                echo '{"total":"' . $count . '","zones":' . json_encode($thetag) . '}';
            }
        }
        
    }
    elseif($type == "zones_exclude_list"){
        
        switch($_SERVER['REQUEST_METHOD'])
        {
            case 'GET':
                $idx        = (string)  (isset($_GET['zone_id'])   ? $_GET['zone_id'] : '');
                break;
            case 'POST':
                $idx        = (string)  (isset($_POST['zone_id'])   ? $_POST['zone_id'] : '');
                break;

            default:
                $idx        = (string)  (isset($_POST['zone_id'])   ? $_POST['zone_id'] : '');
                break;
        }

        $idx = $projectdb->real_escape_string($idx);

        if ($idx != "") {
            $thetag = array();
            $getTag = $projectdb->query("SELECT exclude_list FROM zones WHERE id = '$idx';");
            if ($getTag->num_rows == 1) {
                $getTagData = $getTag->fetch_assoc();
                $tags = $getTagData['exclude_list'];
                $tag = explode(",", $tags);
                $count = count($tag);
                foreach ($tag as $key => $value) {
                    $thetag[] = array("exclude_list" => $value);
                }
                if ($tags == "") {
                    $count = 0;
                    $thetag = "";
                }
                echo '{"total":"' . $count . '","zones":' . json_encode($thetag) . '}';
            }
        }
        
    }
} 

elseif ($action == "set") {
    if ($type == "remove_interface") {

        if($idx == ""){
            $idx = 0;
        }

        if ($ids != "") {
            $data = explode(",", $ids);
            foreach ($data as $key => $value) {
                $projectdb->query("UPDATE edit_table SET remove = '1' WHERE name = '$value' AND lid = '$idx' AND type = 'interfaces' AND user_id = '$user_id';");
            }
        }
    }
    elseif ($type == "add_zone") {

        take_snapshot_last($project);
        $projectdb->query("INSERT INTO zones (source,vsys,template,type) VALUES ('$source','$vsys','$template','layer3');");
        echo json_encode(array("success" => true));
    }
    elseif ($type == "remove") {

        $data = explode(",", $ids);

        take_snapshot_last($project);

        if($createFilters != ''){
            require_once INC_ROOT . '/libs/common/tools/filters.php';
            switch($createFilters){
                case "general":
                    foreach ($data as $key => $value) {
                        $getZoneName = $projectdb->query("SELECT name,template,vsys FROM zones WHERE id='$value';");
                        if ($getZoneName->num_rows > 0) {
                            $getZoneNameData = $getZoneName->fetch_assoc();
                            $zoneName = $getZoneNameData['name'];

                            $paramsDefineFilter = [
                                'project' => $project,
                                'vsys' => $vsys,
                                'source' => $source,
                                'tools_where_columns_id' => 'Name',
                                'tools_operator_id' => 'contains',
                                'search' => "$zoneName",
                                'tools_where_id' => Array(19),
                                'tools_advanced_columns_id' => '',
                                'mode' => 'set_filter',
                                'is_set_sql_filter' => 'yes',
                                'case_sensitive' => ''
                            ];
                            setFilter($project, $paramsDefineFilter);

                            $paramsExecuteFilter = [
                                'project' => $project,
                                'source' => $source,
                            ];
                            executeSQL($project, $paramsExecuteFilter);
                        }
                    }
                    break;

                case "interface":

                default:
                    break;
            }
            //Create a Filter for Search And Replace

        }
        else {
            if (!$forceDelete) {
                $responseMsg = array();

                $zoneIsUsed = array();
                foreach ($data as $key => $value) {

                    $getZoneName = $projectdb->query("SELECT name,template,vsys FROM zones WHERE id='$value';");
                    if ($getZoneName->num_rows > 0) {
                        $getZoneNameData = $getZoneName->fetch_assoc();
                        $zoneName = $getZoneNameData['name'];
                        $template = $getZoneNameData['template'];
                        $vsys = $getZoneNameData['vsys'];

                        # Check if another zone exists with the same name keep all the information in interfaces and rules
                        $getAnother = $projectdb->query("SELECT id FROM zones WHERE template='$template' AND source='$source' AND name='$zoneName' AND id!='$value';");
                        if ($getAnother->num_rows == 0) {
                            $zoneUsage = new ZoneUsage($projectdb, $source, $vsys, $template);
                            $zoneUsage->setName($zoneName);
                            $zoneUsage->calculateUsage();

                            if ($zoneUsage->getTotalUsage() == 0) {
                                $projectdb->query("DELETE FROM zones WHERE id = '$value';");
                            } else {
                                $responseMsg['data'][] = [
                                    'name' => $zoneName,
                                    'id'    => $value,
                                    'interfaces' => $zoneUsage->locations()->get('interfaces')->getAmount_RiskAmount(),
                                    'security_rules_from' => $zoneUsage->locations()->get('security_rules_from')->getAmount_RiskAmount(),
                                    'security_rules_to' => $zoneUsage->locations()->get('security_rules_to')->getAmount_RiskAmount(),
                                    'nat_rules_from' => $zoneUsage->locations()->get('nat_rules_from')->getAmount_RiskAmount(),
                                    'nat_rules' => $zoneUsage->locations()->get('nat_rules')->getAmount_RiskAmount(),
                                    'appoverride_rules_from' => $zoneUsage->locations()->get('appoverride_rules_from')->getAmount_RiskAmount(),
                                    'appoverride_rules_to' => $zoneUsage->locations()->get('appoverride_rules_to')->getAmount_RiskAmount(),
                                    'authentication_rules_from' => $zoneUsage->locations()->get('authentication_rules_from')->getAmount_RiskAmount(),
                                    'authentication_rules_to' => $zoneUsage->locations()->get('authentication_rules_to')->getAmount_RiskAmount(),
                                    'decryption_rules_from' => $zoneUsage->locations()->get('decryption_rules_from')->getAmount_RiskAmount(),
                                    'decryption_rules_to' => $zoneUsage->locations()->get('decryption_rules_to')->getAmount_RiskAmount(),
                                    'dos_rules_from' => $zoneUsage->locations()->get('dos_rules_from')->getAmount_RiskAmount(),
                                    'dos_rules_to' => $zoneUsage->locations()->get('dos_rules_to')->getAmount_RiskAmount(),
                                    'qos_rules_from' => $zoneUsage->locations()->get('qos_rules_from')->getAmount_RiskAmount(),
                                    'qos_rules_to' => $zoneUsage->locations()->get('qos_rules_to')->getAmount_RiskAmount(),
                                    'pbf_rules_from' => $zoneUsage->locations()->get('pbf_rules_from')->getAmount_RiskAmount(),
                                    'tunnel_inspect_rules_from' => $zoneUsage->locations()->get('tunnel_inspect_rules_from')->getAmount_RiskAmount(),
                                    'tunnel_inspect_rules_to' => $zoneUsage->locations()->get('tunnel_inspect_rules_to')->getAmount_RiskAmount(),
                                    'total' => $zoneUsage->getTotal_TotalRiskUsage()
                                ];
                            }
                        } else {
                            //This zone is already existing with the same name, so we can safely delete this instance
                            $projectdb->query("DELETE FROM zones WHERE id = '$value';");
                        }
                    }
                }
                if (count($responseMsg['data']) > 0) {
                    $zoneUsage = new ZoneUsage($projectdb, $source, $vsys, $template);
                    $responseMsg['metadata'] = $zoneUsage->getDynamicGridMetadata("data", "Zone Usage Analysis");
                    echo json_encode(
                        [
                            "success" => false,
                            "msg" => $responseMsg,
                        ]);
                }
                else {
                    echo json_encode(array("success" => true));
                }
            }
            else {
                foreach ($data as $key => $value) {
                    $getZoneName = $projectdb->query("SELECT name,template,vsys FROM zones WHERE id='$value';");
                    if ($getZoneName->num_rows > 0) {
                        $getZoneNameData = $getZoneName->fetch_assoc();
                        $zoneName = $getZoneNameData['name'];
                        $template = $getZoneNameData['template'];
                        $vsys = $getZoneNameData['vsys'];

                        # Check if another zone exists with the same name keep all the information in interfaces and rules
                        $getAnother = $projectdb->query("SELECT id FROM zones WHERE template='$template' AND source='$source' AND name='$zoneName' AND id!='$value';");
                        if ($getAnother->num_rows == 0) {
                            #Clean From interfaces
                            $projectdb->query("UPDATE interfaces SET zone='' WHERE template='$template' AND zone='$zoneName' AND source='$source';");

                            #Clean From rules
                            $ids_rules = getIdsBySourceVsys("security_rules", $source, $vsys);
                            $projectdb->query("DELETE FROM security_rules_from WHERE name='$zoneName' AND rule_lid IN (" . implode(',', $ids_rules) . ");");
                            $projectdb->query("DELETE FROM security_rules_to WHERE name='$zoneName' AND rule_lid IN (" . implode(',', $ids_rules) . ");");

                            $ids_rules = getIdsBySourceVsys("nat_rules", $source, $vsys);
                            $projectdb->query("DELETE FROM nat_rules_from WHERE name='$zoneName' AND rule_lid IN (" . implode(',', $ids_rules) . ");");
                            $projectdb->query("UPDATE nat_rules SET op_zone_to='' WHERE source='$source' AND vsys='$vsys' AND op_zone_to='$zoneName';");

                            $ids_rules = getIdsBySourceVsys("appoverride_rules", $source, $vsys);
                            $projectdb->query("DELETE FROM appoverride_rules_from WHERE name='$zoneName' AND rule_lid IN (" . implode(',', $ids_rules) . ");");
                            $projectdb->query("DELETE FROM appoverride_rules_to WHERE name='$zoneName' AND rule_lid IN (" . implode(',', $ids_rules) . ");");

                            $ids_rules = getIdsBySourceVsys("authentication_rules", $source, $vsys);
                            $projectdb->query("DELETE FROM authentication_rules_from WHERE name='$zoneName' AND rule_lid IN (" . implode(',', $ids_rules) . ");");
                            $projectdb->query("DELETE FROM authentication_rules_to WHERE name='$zoneName' AND rule_lid IN (" . implode(',', $ids_rules) . ");");

                            $ids_rules = getIdsBySourceVsys("decryption_rules", $source, $vsys);
                            $projectdb->query("DELETE FROM decryption_rules_from WHERE name='$zoneName' AND rule_lid IN (" . implode(',', $ids_rules) . ");");
                            $projectdb->query("DELETE FROM decryption_rules_to WHERE name='$zoneName' AND rule_lid IN (" . implode(',', $ids_rules) . ");");

                            $ids_rules = getIdsBySourceVsys("dos_rules", $source, $vsys);
                            $projectdb->query("DELETE FROM dos_rules_from WHERE name='$zoneName' AND type = 'zone' AND rule_lid IN (" . implode(',', $ids_rules) . ");");
                            $projectdb->query("DELETE FROM dos_rules_to WHERE name='$zoneName' AND type = 'zone' AND rule_lid IN (" . implode(',', $ids_rules) . ");");

                            $ids_rules = getIdsBySourceVsys("qos_rules", $source, $vsys);
                            $projectdb->query("DELETE FROM qos_rules_from WHERE name='$zoneName' AND rule_lid IN (" . implode(',', $ids_rules) . ");");
                            $projectdb->query("DELETE FROM qos_rules_to WHERE name='$zoneName' AND rule_lid IN (" . implode(',', $ids_rules) . ");");

                            $ids_rules = getIdsBySourceVsys("pbf_rules", $source, $vsys);
                            $projectdb->query("DELETE FROM pbf_rules_from WHERE name='$zoneName' AND type = 'zone' AND rule_lid IN (" . implode(',', $ids_rules) . ");");

                            $ids_rules = getIdsBySourceVsys("tunnel_inspect_rules", $source, $vsys);
                            $projectdb->query("DELETE FROM tunnel_inspect_rules_from WHERE name='$zoneName' AND rule_lid IN (" . implode(',', $ids_rules) . ");");
                            $projectdb->query("DELETE FROM tunnel_inspect_rules_to WHERE name='$zoneName' AND rule_lid IN (" . implode(',', $ids_rules) . ");");

                        }
                        $projectdb->query("DELETE FROM zones WHERE id = '$value';");
                    }
                    echo json_encode(array("success" => true));
                }
            }
        }
    }
} 
elseif ($action == "add") {
    if ($type == "interfaces") {

        take_snapshot_last($project);

        if($idx == ""){
            $idx = 0;
        }

        $name_interfaces = explode(",", $name);

        foreach ($name_interfaces AS $name){
            $getBridge = $projectdb->query("SELECT id FROM edit_table WHERE type = 'interfaces' AND name = '$name' AND user_id = '$user_id';");
            if ($getBridge->num_rows == 0) {

                $getBridgeId = $projectdb->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'interfaces' AND lid = '$idx' AND user_id = '$user_id';");
                if ($getBridgeId->num_rows == 1) {
                    $getIdData = $getBridgeId->fetch_assoc();
                    $ids = $getIdData['ids'] + 1;
                }else{
                    $ids = 1;
                }

                $projectdb->query("INSERT INTO edit_table (id, ids, lid, type, name, source, remove, user_id) "
                    . "VALUES (NULL, '$ids', '$idx', 'interfaces', '$name', '$template', '0', '$user_id');");
            }else{
                $projectdb->query("UPDATE edit_table SET remove = '0' WHERE name = '$name' AND type = 'interfaces' AND lid = '$idx' AND user_id = '$user_id';");
            }

        }

        echo json_encode(array("success" => true));
    }
    else {

        take_snapshot_last($project);

        if (!isset($enable_user_identification)) {
            $enable_user_identification = "no";
        }
        if (!isset($log_settings_table_name)) {
            $log_settings_table_name = "";
        }
        if (!isset($log_settings_idx)) {
            $log_settings_idx = "0";
        }
        if (!isset($enable_packet_buffer_protection)){
            $enable_packet_buffer_protection='';
        }

        // Make sure the selected template is mapped with the selected source
        $query_validate_template = "SELECT * FROM templates_mapping where id = '$template' and source = '$source';";
        $get_valid_template = $projectdb->query($query_validate_template);
        if($get_valid_template->num_rows === 0){
            echo json_encode(array("success"=>false, "msg"=>"The template selected is not valid for the selected source!"));
            return;
        }

        $is_new = 0;

        if ($id == ""){
            $projectdb->query("INSERT INTO zones (source,vsys,template,type) VALUES ('$source','$vsys','$template','layer3');");
            $id = $projectdb->insert_id;
            $is_new = 1;
            $projectdb->query("UPDATE edit_table SET lid = '$id' WHERE user_id = '$user_id';");
        }

        $interfaces_array = array();

        $version = calcVersion($source);
        if($version === ""){$version="8";}
        $name = truncate_names_zones($name, $version);

        // Check the name doesn't exist!
        $getExistName = $projectdb->query("SELECT name FROM zones WHERE id != '$id' AND BINARY name = '$name' AND source = '$source' AND vsys = '$vsys' AND template = '$template';");
        if ($getExistName->num_rows == 0){

            $getOldname = $projectdb->query("SELECT name FROM zones WHERE id = '$id' AND name != '';");
            if ($getOldname->num_rows == 1) {
                $getOldnameData = $getOldname->fetch_assoc();
                $oldName = $getOldnameData['name'];
                if ($oldName != $name) {

                    //$ids_rules = getSecurityIdsBySourceVsys($source, $vsys);
                    $ids_rules = getIdsBySourceVsys("security_rules", $source, $vsys);
                    $projectdb->query("UPDATE security_rules_from SET name='$name' WHERE name='$oldName' AND rule_lid IN (".implode(',', $ids_rules).");");
                    $projectdb->query("UPDATE security_rules_to SET name='$name' WHERE name='$oldName' AND rule_lid IN (".implode(',', $ids_rules).");");

                    //$ids_rules_appoverride = getAppOverrideIdsBySourceVsys($source, $vsys);
                    $ids_rules = getIdsBySourceVsys("appoverride_rules", $source, $vsys);
                    $projectdb->query("UPDATE appoverride_rules_from SET name='$name' WHERE name='$oldName' AND rule_lid IN (".implode(',', $ids_rules).");");
                    $projectdb->query("UPDATE appoverride_rules_to SET name='$name' WHERE name='$oldName' AND rule_lid IN (".implode(',', $ids_rules).");");

                    $projectdb->query("UPDATE nat_rules SET op_zone_to='$name' WHERE source='$source' AND vsys='$vsys' AND op_zone_to='$oldName';");

                    //$ids_rules_nat = getNatIdsBySourceVsys($source, $vsys);
                    $ids_rules = getIdsBySourceVsys("nat_rules", $source, $vsys);
                    $projectdb->query("UPDATE nat_rules_from SET name='$name' WHERE name='$oldName' AND rule_lid IN (".implode(',', $ids_rules).");");

                    $ids_rules = getIdsBySourceVsys("authentication_rules", $source, $vsys);
                    $projectdb->query("UPDATE authentication_rules_from SET name='$name' WHERE name='$oldName' AND rule_lid IN (".implode(',', $ids_rules).");");
                    $projectdb->query("UPDATE authentication_rules_to SET name='$name' WHERE name='$oldName' AND rule_lid IN (".implode(',', $ids_rules).");");

                    $ids_rules = getIdsBySourceVsys("decryption_rules", $source, $vsys);
                    $projectdb->query("UPDATE decryption_rules_from SET name='$name' WHERE name='$oldName' AND rule_lid IN (".implode(',', $ids_rules).");");
                    $projectdb->query("UPDATE decryption_rules_to SET name='$name' WHERE name='$oldName' AND rule_lid IN (".implode(',', $ids_rules).");");

                    $ids_rules = getIdsBySourceVsys("dos_rules", $source, $vsys);
                    $projectdb->query("UPDATE dos_rules_from SET name='$name' WHERE name='$oldName' AND type = 'zone' AND rule_lid IN (".implode(',', $ids_rules).");");
                    $projectdb->query("UPDATE dos_rules_to SET name='$name' WHERE name='$oldName' AND type = 'zone' AND rule_lid IN (".implode(',', $ids_rules).");");

                    $ids_rules = getIdsBySourceVsys("qos_rules", $source, $vsys);
                    $projectdb->query("UPDATE qos_rules_from SET name='$name' WHERE name='$oldName' AND rule_lid IN (".implode(',', $ids_rules).");");
                    $projectdb->query("UPDATE qos_rules_to SET name='$name' WHERE name='$oldName' AND rule_lid IN (".implode(',', $ids_rules).");");

                    $ids_rules = getIdsBySourceVsys("pbf_rules", $source, $vsys);
                    $projectdb->query("UPDATE pbf_rules_from SET name='$name' WHERE name='$oldName' AND type = 'zone' AND rule_lid IN (".implode(',', $ids_rules).");");

                    $ids_rules = getIdsBySourceVsys("tunnel_inspect_rules", $source, $vsys);
                    $projectdb->query("UPDATE tunnel_inspect_rules_from SET name='$name' WHERE name='$oldName' AND rule_lid IN (".implode(',', $ids_rules).");");
                    $projectdb->query("UPDATE tunnel_inspect_rules_to SET name='$name' WHERE name='$oldName' AND rule_lid IN (".implode(',', $ids_rules).");");

                    $projectdb->query("UPDATE routes_static SET zone='$name' WHERE source='$source' AND template='$template' AND zone='$oldName';");
                    $projectdb->query("UPDATE interfaces SET zone='$name' WHERE source='$source' AND template='$template' AND zone='$oldName';");
                }
            }
            if (($log_setting == "None") OR ( $log_setting == "")) {
                $log_settings_table_name = "";
                $log_settings_idx = "";
            }

            $getInterfaces = $projectdb->query("SELECT name FROM edit_table WHERE type = 'interfaces' AND lid = '$id' AND remove = '0' AND user_id = '$user_id' ORDER BY ids ASC;");
            if($getInterfaces->num_rows > 0){
                while($dataI = $getInterfaces->fetch_assoc()){
                    $inteface_name = $dataI['name'];
                    $interfaces_array[] = $dataI['name'];
                    $projectdb->query("UPDATE interfaces SET zone = '$name' WHERE source = '$source' AND unitname = '$inteface_name';");
                }
            }

            // Remove zones from interfaces
            $getInterfaces = $projectdb->query("SELECT name FROM edit_table WHERE type = 'interfaces' AND lid = '$id' AND remove = '1' AND user_id = '$user_id' ORDER BY ids ASC;");
            if($getInterfaces->num_rows > 0){
                while($dataI = $getInterfaces->fetch_assoc()){
                    $inteface_name = $dataI['name'];
                    $projectdb->query("UPDATE interfaces SET zone = '' WHERE source = '$source' AND unitname = '$inteface_name';");
                }
            }

            $projectdb->query("UPDATE zones SET enable_packet_buffer_protection='$enable_packet_buffer_protection',type='$type',log_setting_id='$log_settings_idx', 
                log_setting_table_name='$log_settings_table_name',name='$name',enable_user_identification='$enable_user_identification',zone_protection_profile='$zone_protection_profile',
                interfaces = '".implode(",", $interfaces_array)."' 
                WHERE id='$id'");

            //if (strlen($name)<=15){
            if (strlen($name)<=31){
                $projectdb->query("UPDATE zones SET invalid='0' WHERE id='$id'");
            }
            echo json_encode(array("success"=>true, "msg"=>""));
        }
        else{
            if($is_new == 1){
                $projectdb->query("DELETE FROM zones WHERE id = '$id';");
            }
            echo json_encode(array("success"=>false, "msg"=>"Zone already exists with the same name."));
        }

    }
} 
elseif ($action == "update") {
    if ($type == "interfaces") {

        take_snapshot_last($project);

        if($idx == ""){
            $idx = 0;
        }

        $name_interfaces = explode(",", $name);

        foreach ($name_interfaces AS $name){
            $getBridge = $projectdb->query("SELECT id FROM edit_table WHERE type = 'interfaces' AND name = '$name' AND user_id = '$user_id';");
            if ($getBridge->num_rows == 0) {

                $getBridgeId = $projectdb->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'interfaces' AND lid = '$idx' AND user_id = '$user_id';");
                if ($getBridgeId->num_rows == 1) {
                    $getIdData = $getBridgeId->fetch_assoc();
                    $ids = $getIdData['ids'] + 1;
                }else{
                    $ids = 1;
                }

                $projectdb->query("INSERT INTO edit_table (id, ids, lid, type, name, source, remove, user_id) "
                    . "VALUES (NULL, '$ids', '$idx', 'interfaces', '$name', '$template', '0', '$user_id');");
            }else{
                $projectdb->query("UPDATE edit_table SET remove = '0' WHERE name = '$name' AND type = 'interfaces' AND lid = '$idx' AND user_id = '$user_id';");
            }

        }

        echo json_encode(array("success" => true));
    }
}
elseif($action == "remove"){
    if($type == "interfaces_in_zones"){

        take_snapshot_last($project);
        
        $getInterfaces = $projectdb->query("SELECT id, name, interfaces, template FROM zones WHERE id IN ($ids);");
        if ($getInterfaces->num_rows > 0) {
            while($dataI = $getInterfaces->fetch_assoc()){
                $zone_id = $dataI['id'];
                $zone_name = $dataI['name'];
                $interfaces = $dataI['interfaces'];
                $template = $dataI['template'];
                
                if ($interfaces != "") {
                    
                    $names_interfaces_array = explode(",", $interfaces);
                
                    foreach($names_interfaces_array AS $name_interface){
                        #Update the Interface with the Zone
                        $projectdb->query("UPDATE interfaces SET zone = '' WHERE source = '$source' AND template = '$template' AND unitname = '$name_interface';");
                    }
                }
            }
        }
        $projectdb->query("UPDATE zones SET interfaces='' WHERE id IN ($ids);");
        
        echo json_encode(array("success" => true));
    }
}

function getEntries (Mysqli $connection, String $query) : int{
    $result = $connection->query($query);
    if($result->num_rows>0) {
        $data = $result->fetch_array();
        return $data[0];
    }
    return 0;
}

function declareCellFormatHeader(String $label, String $title, bool $locked=false):array{
    return [
        "header"=> "$title",
        "dataIndex"=> "$label",
//        "width"  => 10,
        "sortable"=> true,
        "locked"    => $locked,
        "lockable"    => false,
        "checked"=> true
    ];
}


function declareCellFormat(String $label, String $title, bool $locked=false):array{
    return [
        "header"=> "$title",
        "dataIndex"=> "$label",
        "mapping"   => "amount",
        "width"  => 50,
        "sortable"=> true,
        "renderer"=> "RowRenderRed",
        "locked"    => $locked,
        "lockable"    => false
    ];
}

function declareHiddenCellFormat(String $label, String $title):array{
    return [
        "header"=> "$title",
        "dataIndex"=> "$label",
        "hidden"    => true,
        "sortable"=> true,
    ];
}
?>

