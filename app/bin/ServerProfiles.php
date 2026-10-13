<?php

# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
require_once('./Authentication.php');
require_once '../libs/database.php';
require_once '../libs/shared.php';
require_once INC_ROOT.'/libs/common/tools/filters.php';

include INC_ROOT.'/bin/middleware_sanitizer.php';

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $action     = (string)  (isset($_GET['action'])     ? $_GET['action'] : '');
        $type       = (string)  (isset($_GET['type'])       ? $_GET['type'] : ''); // zip / xml / device
        $type2      = (string)  (isset($_GET['type2'])      ? $_GET['type2'] : ''); // zip / xml / device
        $project    = (string)  (isset($_GET['project'])    ? $_GET['project'] : '');
        $search     = (string)  (isset($_GET['search'])     ? $_GET['search'] : '');
        $source     = (string)  (isset($_GET['source'])     ? $_GET['source'] : '');
        $vsys       = (string)  (isset($_GET['vsys'])       ? $_GET['vsys'] : '');
        $server_type = (string) (isset($_GET['server_type']) ? $_GET['server_type'] : '');
        $template    = (string) (isset($_GET['template'])    ? $_GET['template'] : '');
        $filter     = (string)  (isset($_GET['filter'])     ? $_GET['filter'] : '');
        $tools_where_id     = (string)  (isset($_GET['tools_where_id'])     ? $_GET['tools_where_id'] : '');
        break;
    case 'POST':
        $action     = (string)  (isset($_POST['action'])    ? $_POST['action'] : '');
        $type       = (string)  (isset($_POST['type'])      ? $_POST['type'] : ''); // zip / xml / device
        $type2      = (string)  (isset($_POST['type2'])      ? $_POST['type2'] : ''); // zip / xml / device
        $project    = (string)  (isset($_POST['project'])   ? $_POST['project'] : '');
        $search     = (string)  (isset($_POST['search'])    ? $_POST['search'] : '');
        $source     = (string)  (isset($_POST['source'])    ? $_POST['source'] : '');
        $vsys       = (string)  (isset($_POST['vsys'])      ? $_POST['vsys'] : '');
        $server_type = (string) (isset($_POST['server_type']) ? $_POST['server_type'] : '');
        $template    = (string) (isset($_POST['template'])    ? $_POST['template'] : '');
        $filter     = (string)  (isset($_POST['filter'])    ? $_POST['filter'] : '');
        $tools_where_id     = (string)  (isset($_POST['tools_where_id'])    ? $_POST['tools_where_id'] : '');
        break;

    default:
        $action     = (string)  (isset($_POST['action'])    ? $_POST['action'] : '');
        $type       = (string)  (isset($_POST['type'])      ? $_POST['type'] : ''); // zip / xml / device
        $type2      = (string)  (isset($_POST['type2'])      ? $_POST['type2'] : ''); // zip / xml / device
        $project    = (string)  (isset($_POST['project'])   ? $_POST['project'] : '');
        $search     = (string)  (isset($_POST['search'])    ? $_POST['search'] : '');
        $source     = (string)  (isset($_POST['source'])    ? $_POST['source'] : '');
        $vsys       = (string)  (isset($_POST['vsys'])      ? $_POST['vsys'] : '');
        $server_type = (string) (isset($_POST['server_type']) ? $_POST['server_type'] : '');
        $template    = (string) (isset($_POST['template'])    ? $_POST['template'] : '');
        $filter     = (string)  (isset($_POST['filter'])    ? $_POST['filter'] : '');
        $tools_where_id     = (string)  (isset($_POST['tools_where_id'])    ? $_POST['tools_where_id'] : '');
        break;
}

require_once INC_ROOT.'/libs/projectdb.php';
$projectdb = selectDatabase($project);

$action = $projectdb->real_escape_string($action);
$type = $projectdb->real_escape_string($type);
$type2 = $projectdb->real_escape_string($type2);
$project = $projectdb->real_escape_string($project);
$search = $projectdb->real_escape_string($search);
$source = $projectdb->real_escape_string($source);
$vsys = $projectdb->real_escape_string($vsys);
$server_type = $projectdb->real_escape_string($server_type);
$template = $projectdb->real_escape_string($template);
$filter = $projectdb->real_escape_string($filter);
$tools_where_id = $projectdb->real_escape_string($tools_where_id);

if($action == "get") {

    if ($type == "get_server_profiles") {

        $query = generate_query("template");


        if (preg_match("/ WHERE /i", $query)) {
            $query = $query . " AND type = '$server_type' ";
        }
        else {
            $query = $query . " WHERE type = '$server_type' ";
        }

        if(($server_type == "snmptrap") || ($server_type == "email") || ($server_type == "syslog")){
            $table_name = "log_settings";
        }
        elseif(($server_type == "radius") || ($server_type == "ldap") || ($server_type == "kerberos") || ($server_type == "netflow") || ($server_type == "tacplus") || ($server_type == "dns")){
            $table_name = "server_profile";
        }

        if(($filter != "none") && ($filter != "0")){

            if(($filter == "74") || ($filter == "75") || ($filter == "111")){
                $params['case_sensitive'] = "1";
            }else{
                $params['case_sensitive'] = "0";
            }

            $params['tools_where_columns_id'] = $filter;
            $params['tools_operator_id'] = "contains";
            $params['search'] = "";
            $params['tools_where_id'] = $tools_where_id;
            $params['tools_advanced_columns_id'] = "None";
            $params['is_set_sql_filter'] = "yes";
            $params['source'] = $source;
            $params['vsys'] = $vsys;

            setFilter($project, $params);
            executeSQL($project, $params);

        }
        elseif(($filter == "none") || ($filter == "0")){
        }

        list($query, $orderby) = generateQueryFilters($project, "$table_name", "$server_type", $query, $source);

        $count = 0;

        $getServerProfiles = $projectdb->query("SELECT id AS id_profile, id AS idx,id, '$table_name' AS table_name, vsys, source, template, type, name, xml "
            . " FROM $table_name $query;");
        $count = $getServerProfiles->num_rows;

        if($count > 0){
            while ($data = $getServerProfiles->fetch_object()) {
                $myData[] = $data;
            }
        }else{
            $myData = "";
        }

        echo '{"total":"' . $count . '","server_profiles":' . json_encode($myData) . '}';

    }
    
    
}
elseif ($action == "add") {
    if ($type2 == "server_profiles") {
        
        $source = $_POST['source'];
        $vsys = $_POST['vsys'];
        $template = $_POST['template'];
        $name = $_POST['name'];
        $type = $_POST['type'];
        $xml = $_POST['xml'];
        $server_profile_type = $_POST['server_profile_type'];
        $id = $_POST['id'];
        //$table_name = $_POST['table_name'];

        take_snapshot_last($project);

        if(($type == "snmptrap") || ($type == "email") || ($type == "syslog")){
            $table_name = "log_settings";
        }
        elseif(($type == "radius") || ($type == "ldap") || ($type == "kerberos") || ($type == "netflow") || ($type == "tacplus") || ($type == "dns")){
            $table_name = "server_profile";
        }

        if ($id != "") {
            
            $xml = preg_replace('/<entry name="(.*?)">/', '<entry name="'.$name.'">', $xml);
            //$xml = addslashes($xml);
            $xml = simplexml_load_string($xml);
            $xmlString = preg_replace('/^<\?xml.*\?>/', '', $xml->asXML());

            $conn = get_pdo($project);
            $stmt = $conn->prepare("UPDATE $table_name SET xml=?, name=?, type=? WHERE id=?;");
            $stmt->bindParam(1, $xmlString);
            $stmt->bindParam(2, $name);
            $stmt->bindParam(3, $type);
            $stmt->bindParam(4, $id);
            $stmt->execute();
        } 
        else {
            //$xml = addslashes($xml);

            $getProfile = $projectdb->query("SELECT id FROM $table_name WHERE vsys = '$vsys' AND source = '$source' AND BINARY name = '$name' AND type = '$type';");
            if ($getProfile->num_rows == 0) {
                $projectdb->query("INSERT INTO $table_name (vsys,source,template,name,type,xml) VALUES ('$vsys','$source','$template','$name','$type','$xml');");
                $conn = get_pdo($project);

                $xml = simplexml_load_string($xml);
                $xmlString = preg_replace('/^<\?xml.*\?>\n/', '', $xml->asXML());

                $stmt = $conn->prepare("INSERT INTO $table_name (vsys,source,name,type,xml) VALUES (?,?,?,?,?);");
                $stmt->bindParam(1, $vsys);
                $stmt->bindParam(2, $source);
                $stmt->bindParam(3, $name);
                $stmt->bindParam(4, $type);
                $stmt->bindParam(5, $xmlString);
                $stmt->execute();
            }
        }
        echo json_encode(array("success" => true));
    }
} 
elseif ($action == "set") {
    if ($type == "remove") {
        $ids = $_POST["ids"];
        
        if (isset($ids)) {
            take_snapshot_last($project);
            $ids_array = explode(",", $ids);
            
            foreach ($ids_array as $key => $value) {
                $values = explode(";", $value);
                $objid = $values[0];
                $objtable = $values[1];
                $objname = $values[2];
                $projectdb->query("DELETE FROM $objtable WHERE id='$objid';");
            }
            echo json_encode(array("success" => true));
        }
    }
    elseif($type == "set_combine"){

        switch($_SERVER['REQUEST_METHOD'])
        {
            case 'GET':
                $server_type = (string) (isset($_GET['server_type']) ? $_GET['server_type'] : '');
                $template    = (string) (isset($_GET['template'])    ? $_GET['template'] : '');
                $ids         = (string) (isset($_GET['ids'])         ? $_GET['ids'] : '');
                break;
            case 'POST':
                $server_type = (string) (isset($_POST['server_type']) ? $_POST['server_type'] : '');
                $template    = (string) (isset($_POST['template'])    ? $_POST['template'] : '');
                $ids         = (string) (isset($_POST['ids'])         ? $_POST['ids'] : '');
                break;
            default:
                $server_type = (string) (isset($_POST['server_type']) ? $_POST['server_type'] : '');
                $template    = (string) (isset($_POST['template'])    ? $_POST['template'] : '');
                $ids         = (string) (isset($_POST['ids'])         ? $_POST['ids'] : '');
                break;
        }

        $server_type = $projectdb->real_escape_string($server_type);
        $template = $projectdb->real_escape_string($template);
        $ids = $projectdb->real_escape_string($ids);

        $table_name_log = "log_settings";
        $table_name_server = "server_profile";

        $server_profiles = explode(",", $ids);
        $i = 0;
        $no_same_name = 0;
        take_snapshot_last($project);

        foreach ($server_profiles as $key=>$value) {

            $server_profiles_item = explode(";", $value);
            if($i == 0){
                // Cojo el nombre, vsys, source y template del primer seleccionado y si los siguientes son igual, se puede hacer el combine
                $name_server_profiles = $server_profiles_item[1];
                $vsys_server_profiles = $server_profiles_item[3];
                $source_server_profiles = $server_profiles_item[4];
                $template_server_profiles = $server_profiles_item[5];

            }

            if($i == 1){
                if(($name_server_profiles == $server_profiles_item[1]) && ($vsys_server_profiles == $server_profiles_item[3])
                    && ($source_server_profiles == $server_profiles_item[4]) && ($template_server_profiles == $server_profiles_item[5])){
                    if(($server_profiles_item[2] == "snmptrap") || ($server_profiles_item[2] == "email") || ($server_profiles_item[2] == "syslog")){
                        $projectdb->query("DELETE FROM $table_name_log WHERE id = '$server_profiles_item[0]' ;");
                    }elseif(($server_profiles_item[2] == "radius") || ($server_profiles_item[2] == "ldap") || ($server_profiles_item[2] == "kerberos")){
                        $projectdb->query("DELETE FROM $table_name_server WHERE id = '$server_profiles_item[0]' ;");
                    }
                }else{
                    $no_same_name = 1;
                }
            }
            $i = 1;
        }
        if($no_same_name == 0){
            echo json_encode(array("success"=>true));
        }else{
            echo json_encode(array("success"=>false,"msg"=>"Can't do combine because Servers Profiles don't have the same name."));
        }
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
            $data = explode(",", $ids);

            foreach ($data as $key => $value) {

                $values = explode(";", $value);
                $member_lid = $values[0];
                $table_name = $values[1];
                $name = $values[2];

                $members = explode(',', $member_lid);

                if($table_name == "server_profile"){
                    $return = convertServerProfileToShared($source, $members, "notall");
                }
                elseif($table_name == "log_settings"){
                    $return = convertLogSettingsToShared($source, $members, "notall");
                }
            }

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
        $template = (string) (isset($_POST['template']) ? $_POST['template'] : $_GET['template']);

        $source = $projectdb->real_escape_string($source);
        $vsys = $projectdb->real_escape_string($vsys);
        $ids = $projectdb->real_escape_string($ids);
        $clone_to_vsys = $projectdb->real_escape_string($clone_to_vsys);
        $template = $projectdb->real_escape_string($template);

        if ($ids != "") {
            take_snapshot_last($project);
            $data = explode(",", $ids);

            foreach ($data as $key => $value) {

                $values = explode(";", $value);
                $member_lid = $values[0];
                $table_name = $values[1];
                $name = $values[2];

                $members = explode(',', $member_lid);

                if($table_name == "server_profile"){
                    $return = cloneServerProfiles($source, $vsys, $clone_to_vsys, $members);
                }
                elseif($table_name == "log_settings"){
                    $return = cloneLogSettings($source, $vsys, $clone_to_vsys, $members, $template);
                }
            }
            if($return != 0){
                echo json_encode(array("success" => true));
            }else{
                echo json_encode(array("success" => false));
            }
        }
    }
}
