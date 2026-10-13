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
require_once INC_ROOT.'/libs/common/tools/filters.php';

include INC_ROOT.'/bin/middleware_sanitizer.php';

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $action     = (string)  (isset($_GET['action'])     ? $_GET['action'] : '');
        $type       = (string)  (isset($_GET['type'])       ? $_GET['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_GET['project'])    ? $_GET['project'] : '');
        $start      = (integer) (isset($_GET['start'])      ? $_GET['start'] : '');
        $limit      = (integer) (isset($_GET['limit'])      ? $_GET['limit'] : '');
        $template   = (string)  (isset($_GET['template'])   ? $_GET['template'] : '');
        $source     = (string)  (isset($_GET['source'])     ? $_GET['source'] : '');
        $vsys       = (string)  (isset($_GET['vsys'])      ? $_GET['vsys'] : '');
        $filter     = (string)  (isset($_GET['filter'])     ? $_GET['filter'] : '');
        break;
    case 'POST':
        $action     = (string)  (isset($_POST['action'])    ? $_POST['action'] : '');
        $type       = (string)  (isset($_POST['type'])      ? $_POST['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_POST['project'])   ? $_POST['project'] : '');
        $start      = (integer) (isset($_POST['start'])     ? $_POST['start'] : '');
        $limit      = (integer) (isset($_POST['limit'])     ? $_POST['limit'] : '');
        $template   = (string)  (isset($_POST['template'])  ? $_POST['template'] : '');
        $source     = (string)  (isset($_POST['source'])    ? $_POST['source'] : '');
        $vsys       = (string)  (isset($_POST['vsys'])      ? $_POST['vsys'] : '');
        $filter     = (string)  (isset($_POST['filter'])    ? $_POST['filter'] : '');
        break;
    default:
        $action     = (string)  (isset($_POST['action'])    ? $_POST['action'] : '');
        $type       = (string)  (isset($_POST['type'])      ? $_POST['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_POST['project'])   ? $_POST['project'] : '');
        $start      = (integer) (isset($_POST['start'])     ? $_POST['start'] : '');
        $limit      = (integer) (isset($_POST['limit'])     ? $_POST['limit'] : '');
        $template   = (string)  (isset($_POST['template'])  ? $_POST['template'] : '');
        $source     = (string)  (isset($_POST['source'])    ? $_POST['source'] : '');
        $vsys       = (string)  (isset($_POST['vsys'])      ? $_POST['vsys'] : '');
        $filter     = (string)  (isset($_POST['filter'])    ? $_POST['filter'] : '');
        break;
}

$projectdb = selectDatabase($project);

$action = $projectdb->real_escape_string($action);
$type = $projectdb->real_escape_string($type);
$project = $projectdb->real_escape_string($project);
$start = $projectdb->real_escape_string($start);
$limit = $projectdb->real_escape_string($limit);
$template = $projectdb->real_escape_string($template);
$source = $projectdb->real_escape_string($source);
$vsys = $projectdb->real_escape_string($vsys);
$filter = $projectdb->real_escape_string($filter);

global $app;
$user = $app->container->sentinel->getUser();
$user_id = $user->id;

if ($action == "get") {
    if ($type == "management_interfaces") {

        $query = generate_query("template_not_vsys");
        $myData = array();

        if(($filter != "none") && ($filter != "0")){

            $params['tools_where_columns_id'] = $filter;
            $params['tools_operator_id'] = "contains";
            $params['search'] = "";
            $params['tools_where_id'] = "29";
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

        list($query, $orderby) = generateQueryFilters($project, "interface_management_profile", "", $query, $source);

        //$myData[]=array("id"=>0,"name"=>"None");

        $getAll = $projectdb->query("SELECT id FROM interface_management_profile $query;");

        if ($getAll->num_rows > 0) {
            if (($start == "") AND ( $limit == "")) {
                $start = 0;
                $limit = 0;
            }
            $getLimit = $projectdb->query("SELECT * FROM interface_management_profile $query ORDER BY name ASC LIMIT $start, $limit;");
            if ($getLimit->num_rows > 0) {
                while ($data = $getLimit->fetch_object()) {
                    if($data->http == "yes"){$data->http = "on";}
                    if($data->https == "yes"){$data->https = "on";}
                    if($data->http_ocsp == "yes"){$data->http_ocsp = "on";}
                    if($data->ssh == "yes"){$data->ssh = "on";}
                    if($data->snmp == "yes"){$data->snmp = "on";}
                    if($data->userid_service == "yes"){$data->userid_service = "on";}
                    if($data->userid_syslog_listener_ssl == "yes"){$data->userid_syslog_listener_ssl = "on";}
                    if($data->userid_syslog_listener_udp == "yes"){$data->userid_syslog_listener_udp = "on";}
                    if($data->ping == "yes"){$data->ping = "on";}
                    if($data->response_pages == "yes"){$data->response_pages = "on";}
                    if($data->telnet == "yes"){$data->telnet = "on";}
                    $myData[] = $data;
                }
            }
        }

        echo '{"total":"' . count($myData) . '","profiles":' . json_encode($myData) . '}';
    }
    elseif ($type == "management_interfaces_none") {

        $query = generate_query("template_not_vsys");

        if(($filter != "none") && ($filter != "0")){

            $params['tools_where_columns_id'] = $filter;
            $params['tools_operator_id'] = "contains";
            $params['search'] = "";
            $params['tools_where_id'] = "29";
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

        list($query, $orderby) = generateQueryFilters($project, "interface_management_profile", "", $query, $source);

        $myData[]=array("id"=>0,"name"=>"None");

        $getAll = $projectdb->query("SELECT id FROM interface_management_profile $query;");

        if ($getAll->num_rows > 0) {
            if (($start == "") AND ( $limit == "")) {
                $start = 0;
                $limit = 0;
            }
            $getLimit = $projectdb->query("SELECT * FROM interface_management_profile $query ORDER BY name ASC LIMIT $start, $limit;");
            if ($getLimit->num_rows > 0) {
                while ($data = $getLimit->fetch_object()) {
                    if($data->http == "yes"){$data->http = "on";}
                    if($data->https == "yes"){$data->https = "on";}
                    if($data->http_ocsp == "yes"){$data->http_ocsp = "on";}
                    if($data->ssh == "yes"){$data->ssh = "on";}
                    if($data->snmp == "yes"){$data->snmp = "on";}
                    if($data->userid_service == "yes"){$data->userid_service = "on";}
                    if($data->userid_syslog_listener_ssl == "yes"){$data->userid_syslog_listener_ssl = "on";}
                    if($data->userid_syslog_listener_udp == "yes"){$data->userid_syslog_listener_udp = "on";}
                    if($data->ping == "yes"){$data->ping = "on";}
                    if($data->response_pages == "yes"){$data->response_pages = "on";}
                    if($data->telnet == "yes"){$data->telnet = "on";}
                    $myData[] = $data;
                }
            }
        }

        echo '{"total":"' . count($myData) . '","profiles":' . json_encode($myData) . '}';
    }
    elseif ($type == "zone_protection") {

        $query = generate_query("template_not_vsys");

        $getAll = $projectdb->query("SELECT id FROM zone_protection_profile $query;");
        $count = $getAll->num_rows;
        if ($count > 0) {
            if (($start == "") AND ( $limit == "")) {
                $start = 0;
                $limit = 0;
            }
            $getLimit = $projectdb->query("SELECT id,vsys,source,template,name,xml FROM zone_protection_profile $query ORDER BY name ASC LIMIT $start, $limit;");
            if ($getLimit->num_rows > 0) {
                while ($data = $getLimit->fetch_object()) {
                    $myData[] = $data;
                }
            }
        } else {
            $myData = "";
        }
        echo '{"total":"' . $count . '","profiles":' . json_encode($myData) . '}';
    }
    elseif ($type == "monitor") {

        $query = generate_query("template_not_vsys");

        if(($filter != "none") && ($filter != "0")){

            $params['tools_where_columns_id'] = $filter;
            $params['tools_operator_id'] = "contains";
            $params['search'] = "";
            $params['tools_where_id'] = "28";
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

        list($query, $orderby) = generateQueryFilters($project, "monitor_profile", "", $query, $source);

        $getAll = $projectdb->query("SELECT id, source, vsys, template, name, m_action, interva, threshold FROM monitor_profile $query ORDER BY id,name;");
        $count = $getAll->num_rows;
        $getAll = $projectdb->query("SELECT id, source, vsys, template, name, m_action, interva, threshold FROM monitor_profile $query ORDER BY id,name LIMIT $start, $limit;");
        if ($count > 0) {
            while ($data = $getAll->fetch_object()) {
                $myData[] = $data;
            }
        } else {
            $myData = "";
        }
        echo '{"total":"'.$count.'","monitor":'.json_encode($myData).'}';
        
    }
    elseif ($type == "permitted_address"){
        
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $idx = $projectdb->real_escape_string((string) (isset($_POST['idx']) ? $_POST['idx'] : $_GET['idx']));

        if($idx == ""){
            $idx = 0;
        }
        
        $address = array();
        $getAddress = $projectdb->query("SELECT permitted_ip FROM interface_management_profile WHERE id = '$idx' AND permitted_ip != '';");
        if ($getAddress->num_rows == 1) {
            $dataA = $getAddress->fetch_assoc();
            $add = $dataA['permitted_ip'];
            $add_explode = explode(",", $add);
            $count = count($add_explode);
            foreach ($add_explode as $key => $value) {

                $getBridgeId = $projectdb->query("SELECT id FROM edit_table WHERE name = '$value' AND type = 'permitted_ip' AND lid = '$idx' AND user_id = '$user_id';");
                if ($getBridgeId->num_rows == 0) {
                    $getBridgeId = $projectdb->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'permitted_ip' AND lid = '$idx' AND user_id = '$user_id';");
                    if ($getBridgeId->num_rows == 1) {
                       $getIdData = $getBridgeId->fetch_assoc();
                       $ids = $getIdData['ids'] + 1;
                    }else{
                        $ids = 1;
                    }
                    $projectdb->query("INSERT INTO edit_table (id, ids, lid, type, name, source, remove, user_id) "
                        . "VALUES (NULL, '$ids', '$idx', 'permitted_ip', '$value', '$template', '0', '$user_id');");
                }

            }
            if ($add == "") {
                $count = 0;
                $address = "";
            }
            else{
                $getLimit = $projectdb->query("SELECT id, ids, name FROM edit_table WHERE type = 'permitted_ip' AND remove = '0' AND user_id = '$user_id' ORDER BY ids;");
                $count = $getLimit->num_rows;
                if ($getLimit->num_rows > 0) {
                    while ($data = $getLimit->fetch_object()) {
                        $address[] = $data;
                    }
                }
            }
            echo '{"total":"' . $count . '","address":' . json_encode($address) . '}';
        }
        else{
            $getLimit = $projectdb->query("SELECT id, ids, name FROM edit_table WHERE type = 'permitted_ip' AND remove = '0' AND user_id = '$user_id' ORDER BY ids;");
            $count = $getLimit->num_rows;
            if ($getLimit->num_rows > 0) {
                while ($data = $getLimit->fetch_object()) {
                    $address[] = $data;
                }
            }
            echo '{"total":"' . $count . '","address":' . json_encode($address) . '}';
        }
        
        
    }
    elseif ($type == "ike_crypto"){

        $query = generate_query("template_not_vsys");

        if(($filter != "none") && ($filter != "0")){

            $params['tools_where_columns_id'] = $filter;
            $params['tools_operator_id'] = "contains";
            $params['search'] = "";
            $params['tools_where_id'] = "24";
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

        list($query, $orderby) = generateQueryFilters($project, "ike_crypto_profiles", "", $query, $source);

        $getAll = $projectdb->query("SELECT id, source, vsys, template, name, encryption, hash, dh_group, seconds, minutes, hours, days, authentication_multiple FROM ike_crypto_profiles $query ORDER BY id, name;");
        $count = $getAll->num_rows;
        $getAll = $projectdb->query("SELECT id, source, vsys, template, name, encryption, hash, dh_group, seconds, minutes, hours, days, authentication_multiple FROM ike_crypto_profiles $query ORDER BY id, name LIMIT $start, $limit;");
        if ($count > 0) {
            while ($data = $getAll->fetch_object()) {
                $myData[] = $data;
            }
        } else {
            $myData = "";
        }
        echo '{"total":"'.$count.'","ike":'.json_encode($myData).'}';
        
    }
    elseif ($type == "dh_group"){
        
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $idx = $projectdb->real_escape_string((string) (isset($_POST['idx']) ? $_POST['idx'] : $_GET['idx']));
        $table = $projectdb->real_escape_string((string) (isset($_POST['table']) ? $_POST['table'] : $_GET['table']));
        
        if($idx == ""){
            $idx = 0;
        }
        
        $address = array();
        $getAddress = $projectdb->query("SELECT dh_group FROM $table WHERE id = '$idx' AND dh_group != '';");
        //echo "2. SELECT dh_group FROM $table WHERE id = '$idx' AND dh_group != '';\n";
        if ($getAddress->num_rows == 1) {
            $dataA = $getAddress->fetch_assoc();
            $add = $dataA['dh_group'];
            $add_explode = explode(",", $add);
            $count = count($add_explode);
            foreach ($add_explode as $key => $value) {

                $getBridgeId = $projectdb->query("SELECT id FROM edit_table WHERE name = '$value' AND type = 'crypto_dh_group' AND lid = '$idx' AND user_id = '$user_id';");
                if ($getBridgeId->num_rows == 0) {
                    $getBridgeId = $projectdb->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'crypto_dh_group' AND lid = '$idx' AND user_id = '$user_id';");
                    if ($getBridgeId->num_rows == 1) {
                       $getIdData = $getBridgeId->fetch_assoc();
                       $ids = $getIdData['ids'] + 1;
                    }else{
                        $ids = 1;
                    }
                    $projectdb->query("INSERT INTO edit_table (id, ids, lid, type, name, source, remove, user_id) "
                        . "VALUES (NULL, '$ids', '$idx', 'crypto_dh_group', '$value', '$template', '0', '$user_id');");
                }

            }
            if ($add == "") {
                $count = 0;
                $address = "";
            }
            else{
                $getLimit = $projectdb->query("SELECT id, ids, name FROM edit_table WHERE type = 'crypto_dh_group' AND remove = '0' AND user_id = '$user_id' ORDER BY ids;");
                $count = $getLimit->num_rows;
                if ($getLimit->num_rows > 0) {
                    while ($data = $getLimit->fetch_object()) {
                        $address[] = $data;
                    }
                }
            }
            echo '{"total":"' . $count . '","dh_group":' . json_encode($address) . '}';
        }
        else{
            $getLimit = $projectdb->query("SELECT id, ids, name FROM edit_table WHERE type = 'crypto_dh_group' AND remove = '0' AND user_id = '$user_id' ORDER BY ids;");
            $count = $getLimit->num_rows;
            if ($getLimit->num_rows > 0) {
                while ($data = $getLimit->fetch_object()) {
                    $address[] = $data;
                }
            }
            echo '{"total":"' . $count . '","dh_group":' . json_encode($address) . '}';
        }
    }
    elseif ($type == "encryption"){
        
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $idx = $projectdb->real_escape_string((string) (isset($_POST['idx']) ? $_POST['idx'] : $_GET['idx']));
        $table = $projectdb->real_escape_string((string) (isset($_POST['table']) ? $_POST['table'] : $_GET['table']));
        
        if($idx == ""){
            $idx = 0;
        }
        
        $address = array();
        $getAddress = $projectdb->query("SELECT encryption FROM $table WHERE id = '$idx' AND encryption != '';");
        if ($getAddress->num_rows == 1) {
            $dataA = $getAddress->fetch_assoc();
            $add = $dataA['encryption'];
            $add_explode = explode(",", $add);
            $count = count($add_explode);
            foreach ($add_explode as $key => $value) {

                $getBridgeId = $projectdb->query("SELECT id FROM edit_table WHERE name = '$value' AND type = 'crypto_encryption' AND lid = '$idx' AND user_id = '$user_id';");
                if ($getBridgeId->num_rows == 0) {
                    $getBridgeId = $projectdb->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'crypto_encryption' AND lid = '$idx' AND user_id = '$user_id';");
                    if ($getBridgeId->num_rows == 1) {
                       $getIdData = $getBridgeId->fetch_assoc();
                       $ids = $getIdData['ids'] + 1;
                    }else{
                        $ids = 1;
                    }
                    $projectdb->query("INSERT INTO edit_table (id, ids, lid, type, name, source, remove, user_id) "
                        . "VALUES (NULL, '$ids', '$idx', 'crypto_encryption', '$value', '$template', '0', '$user_id');");
                }

            }
            if ($add == "") {
                $count = 0;
                $address = "";
            }
            else{
                $getLimit = $projectdb->query("SELECT id, ids, name FROM edit_table WHERE type = 'crypto_encryption' AND remove = '0' AND user_id = '$user_id' ORDER BY ids;");
                $count = $getLimit->num_rows;
                if ($getLimit->num_rows > 0) {
                    while ($data = $getLimit->fetch_object()) {
                        $address[] = $data;
                    }
                }
            }
            echo '{"total":"' . $count . '","encryption":' . json_encode($address) . '}';
        }
        else{
            $getLimit = $projectdb->query("SELECT id, ids, name FROM edit_table WHERE type = 'crypto_encryption' AND remove = '0' AND user_id = '$user_id' ORDER BY ids;");
            $count = $getLimit->num_rows;
            if ($getLimit->num_rows > 0) {
                while ($data = $getLimit->fetch_object()) {
                    $address[] = $data;
                }
            }
            echo '{"total":"' . $count . '","encryption":' . json_encode($address) . '}';
        }
    }
    elseif ($type == "authentication"){
        
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $idx = $projectdb->real_escape_string((string) (isset($_POST['idx']) ? $_POST['idx'] : $_GET['idx']));
        $table = $projectdb->real_escape_string((string) (isset($_POST['table']) ? $_POST['table'] : $_GET['table']));
        
        if($idx == ""){
            $idx = 0;
        }
        
        $address = array();
        $getAddress = $projectdb->query("SELECT hash FROM $table WHERE id = '$idx' AND hash != '';");
        if ($getAddress->num_rows == 1) {
            $dataA = $getAddress->fetch_assoc();
            $add = $dataA['hash'];
            $add_explode = explode(",", $add);
            $count = count($add_explode);
            foreach ($add_explode as $key => $value) {

                $getBridgeId = $projectdb->query("SELECT id FROM edit_table WHERE name = '$value' AND type = 'crypto_authentication' AND lid = '$idx' AND user_id = '$user_id';");
                if ($getBridgeId->num_rows == 0) {
                    $getBridgeId = $projectdb->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'crypto_authentication' AND lid = '$idx' AND user_id = '$user_id';");
                    if ($getBridgeId->num_rows == 1) {
                       $getIdData = $getBridgeId->fetch_assoc();
                       $ids = $getIdData['ids'] + 1;
                    }else{
                        $ids = 1;
                    }
                    $projectdb->query("INSERT INTO edit_table (id, ids, lid, type, name, source, remove, user_id) "
                        . "VALUES (NULL, '$ids', '$idx', 'crypto_authentication', '$value', '$template', '0', '$user_id');");
                }

            }
            if ($add == "") {
                $count = 0;
                $address = "";
            }
            else{
                $getLimit = $projectdb->query("SELECT id, ids, name FROM edit_table WHERE type = 'crypto_authentication' AND remove = '0' AND user_id = '$user_id' ORDER BY ids;");
                 $count = $getLimit->num_rows;
                if ($getLimit->num_rows > 0) {
                    while ($data = $getLimit->fetch_object()) {
                        $address[] = $data;
                    }
                }
            }
            echo '{"total":"' . $count . '","authentication":' . json_encode($address) . '}';
        }
        else{
            $getLimit = $projectdb->query("SELECT id, ids, name FROM edit_table WHERE type = 'crypto_authentication' AND remove = '0' AND user_id = '$user_id' ORDER BY ids;");
            $count = $getLimit->num_rows;
            if ($getLimit->num_rows > 0) {
                while ($data = $getLimit->fetch_object()) {
                    $address[] = $data;
                }
            }
            echo '{"total":"' . $count . '","authentication":' . json_encode($address) . '}';
        }
    }
    elseif ($type == "dh_group_name"){
        
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $version = $projectdb->real_escape_string((string) (isset($_POST['version']) ? $_POST['version'] : $_GET['version']));
        $table = $projectdb->real_escape_string((string) (isset($_POST['table']) ? $_POST['table'] : $_GET['table']));
        
        //$version_1 = explode(".", $version_data);
        //$version = $version_1[0];
        
        if(($version == "4") || ($version == "5") || ($version == "6") || ($version == "6.1")){
            $sql_version = " version <= '6' ";
        }
        elseif($version == "7"){
            $sql_version = " version = '7' ";
        }
        elseif($version == "7.1"){
            $sql_version = " version = '7' OR version = '7.1' ";
        }
        elseif($version > "7.1" && $version < "10.0"){
            $sql_version = " version = '7' OR version = '7.1' ";
        }
        elseif($version >= "10.0") {
            $sql_version = " version = '7' OR version = '7.1' OR version = '10'";
        }

        $getAll = $projectdb->query("SELECT name FROM crypto_dh_group WHERE $sql_version ORDER BY id, name;");
        //echo "SELECT name FROM crypto_dh_group WHERE $sql_version ORDER BY id, name;";
        $count = $getAll->num_rows;
        if ($count > 0) {
            if($table == "ipsec_crypto_profiles"){
                // Se añade null
                $myData[] = array("name" => "no-pfs");
            }
            while ($data = $getAll->fetch_object()) {
                $myData[] = $data;
            }
        } else {
            $myData = "";
        }
        echo '{"total":"'.$count.'","dh_group":'.json_encode($myData).'}';
    }
    elseif ($type == "encryption_name"){
        
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $version = $projectdb->real_escape_string((string) (isset($_POST['version']) ? $_POST['version'] : $_GET['version']));
        $table = $projectdb->real_escape_string((string) (isset($_POST['table']) ? $_POST['table'] : $_GET['table']));
        
        //$version_1 = explode(".", $version_data);
        //$version = $version_1[0];
        
        if(($version == "4") || ($version == "5") || ($version == "6") || ($version == "6.1")){
            $sql_version = " version <= '6' ";
        }
        elseif($version == "7"){
            $sql_version = " version = '7' ";
        }
        elseif($version == "7.1"){
            $sql_version = " version = '7' OR version = '7.1' ";
        }
        elseif($version > "7.1"){
            $sql_version = " version = '7' OR version = '7.1' ";
        }
        
        if(($table == "ike_crypto_profiles") && ($version == "7")){
            $query_name = " AND (name LIKE '%-cbc' OR name = '3des') ";   
        }elseif(($table == "ike_crypto_profiles") && ($version == "7.1")){
            $query_name = " AND (name LIKE '%-cbc' OR name = '3des' OR name = 'des') ";   
        }elseif(($table == "global_protect_app_ipsec_crypto_profiles") && ($version >= "7")){
            $query_name = " AND (name LIKE 'aes-128-cbc' OR name = 'aes-128-gcm' OR name = 'aes-256-gcm') "; 
        }elseif(($table == "ipsec_tunnel") && ($version == "7")){
            $query_name = " AND (name = '3des' OR name LIKE 'aes-128-cbc' OR name = 'aes-128-gcm' OR name = 'aes-256-gcm') "; 
        }elseif(($table == "ipsec_tunnel") && ($version == "7.1")){
            $query_name = " AND (name = '3des' OR name = 'des' OR name LIKE 'aes-128-cbc' OR name = 'aes-128-gcm' OR name = 'aes-256-gcm') "; 
        }
        else{
            $query_name = "";
        }
        
        $getAll = $projectdb->query("SELECT name FROM crypto_encryption WHERE ($sql_version) $query_name ORDER BY id, name;");
        //echo "SELECT name FROM crypto_encryption WHERE ($sql_version) $query_name ORDER BY id, name;\n";
        $count = $getAll->num_rows;
        if ($count > 0) {
            while ($data = $getAll->fetch_object()) {
                $myData[] = $data;
            }
            if(($table == "ipsec_crypto_profiles") || ($table == "ipsec_tunnel")){
                // Se añade null
                $myData[] = array("name" => "null");
            }
        } else {
            $myData = "";
        }
        echo '{"total":"'.$count.'","encryption":'.json_encode($myData).'}';
    }
    elseif ($type == "authentication_name"){
        
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $version = $projectdb->real_escape_string((string) (isset($_POST['version']) ? $_POST['version'] : $_GET['version']));
        $table = $projectdb->real_escape_string((string) (isset($_POST['table']) ? $_POST['table'] : $_GET['table']));
        
        //$version_1 = explode(".", $version_data);
        //$version = $version_1[0];
        
        if(($version == "4") || ($version == "5") || ($version == "6") || ($version == "6.1")){
            $sql_version = " version <= '6' ";
        }
        elseif($version == "7"){
            $sql_version = " version = '7' ";
        }
        elseif($version == "7.1"){
            $sql_version = " version = '7' OR version = '7.1' ";
        }
        elseif($version > "7.1"){
            $sql_version = " version = '7' OR version = '7.1' ";
        }
        
        if(($table == "global_protect_app_ipsec_crypto_profiles") && ($version >= "7")){
            $query_name = " AND name LIKE 'sha1' "; 
        }else{
            $query_name = "";
        }
        
        $getAll = $projectdb->query("SELECT name, description FROM crypto_authentication WHERE ($sql_version) $query_name ORDER BY id, name;");
        $count = $getAll->num_rows;
        if ($count > 0) {
            while ($data = $getAll->fetch_object()) {
                $myData[] = $data;
            }
            if(($table == "ipsec_crypto_profiles") || ($table == "ipsec_tunnel")){
                // Se añade null
                $myData[] = array("name" => "none", "description" => "none");
            }
        } else {
            $myData = "";
        }
        echo '{"total":"'.$count.'","authentication":'.json_encode($myData).'}';
    }
    elseif ($type == "certificate_name"){
        
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $version_data = $projectdb->real_escape_string((string) (isset($_POST['version']) ? $_POST['version'] : $_GET['version']));
        $table = $projectdb->real_escape_string((string) (isset($_POST['table']) ? $_POST['table'] : $_GET['table']));
        
        //$getAll = $projectdb->query("SELECT name FROM shared_certificate WHERE source = '$source' AND template = '$template' ORDER BY id, name;");
        $getAll = $projectdb->query("SELECT name FROM certificate WHERE source = '$source' AND vsys = 'shared' AND template = '$template' ORDER BY id, name;");
        $count = $getAll->num_rows;
        if ($count > 0) {
            $myData[] = array("name" => "None");
            while ($data = $getAll->fetch_object()) {
                $myData[] = $data;
            }
        } else {
            $myData = "";
        }
        echo '{"total":"'.$count.'","certificate":'.json_encode($myData).'}';
    }
    elseif ($type == "certificate_profile_name"){
        
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $version_data = $projectdb->real_escape_string((string) (isset($_POST['version']) ? $_POST['version'] : $_GET['version']));
        $table = $projectdb->real_escape_string((string) (isset($_POST['table']) ? $_POST['table'] : $_GET['table']));
        
        //$getAll = $projectdb->query("SELECT name FROM shared_certificate_profile WHERE source = '$source' AND template = '$template' ORDER BY id, name;");
        $getAll = $projectdb->query("SELECT name FROM certificate_profile WHERE source = '$source' AND vsys = 'shared' AND template = '$template' ORDER BY id, name;");
        $count = $getAll->num_rows;
        if ($count > 0) {
            $myData[] = array("name" => "None");
            while ($data = $getAll->fetch_object()) {
                $myData[] = $data;
            }
        } else {
            $myData = "";
        }
        echo '{"total":"'.$count.'","certificate":'.json_encode($myData).'}';
    }
    elseif ($type == "ipsec_crypto"){

        $query = generate_query("template_not_vsys");

        if(($filter != "none") && ($filter != "0")){

            $params['tools_where_columns_id'] = $filter;
            $params['tools_operator_id'] = "contains";
            $params['search'] = "";
            $params['tools_where_id'] = "26";
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

        list($query, $orderby) = generateQueryFilters($project, "ipsec_crypto_profiles", "", $query, $source);

        $getAll = $projectdb->query("SELECT id, source, vsys, template, name, encryption, hash, dh_group, seconds, minutes, hours, days, kb, mb, gb, tb, protocol FROM ipsec_crypto_profiles $query ORDER BY id, name;");
        $count = $getAll->num_rows;
        $getAll = $projectdb->query("SELECT id, source, vsys, template, name, encryption, hash, dh_group, seconds, minutes, hours, days, kb, mb, gb, tb, protocol FROM ipsec_crypto_profiles $query ORDER BY id, name LIMIT $start, $limit;");
        
        if ($count > 0) {
            while ($data = $getAll->fetch_object()) {
                $myData[] = $data;
            }
        } else {
            $myData = "";
        }
        echo '{"total":"'.$count.'","ipsec":'.json_encode($myData).'}';
        
    }
    elseif ($type == "ike_gateways"){

        $query = generate_query("template_not_vsys");

        if(($filter != "none") && ($filter != "0")){

            $params['tools_where_columns_id'] = $filter;
            $params['tools_operator_id'] = "contains";
            $params['search'] = "";
            $params['tools_where_id'] = "25";
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

        list($query, $orderby) = generateQueryFilters($project, "ike_gateways_profiles", "", $query, $source);

        $getAll = $projectdb->query("SELECT id, source, vsys, template, name, version, dpd_ikev1, ike_interval_ikev1, retry_ikev1, ike_crypto_profile_ikev1, exchange_mode_ikev1, dpd_ikev2, ike_interval_ikev2, ike_crypto_profile_ikev2, require_cookie_ikev2, local_address_ip, interface, type_authentication, pre_shared_key, pre_shared_key AS confirm_pre_shared_key, allow_id_payload_mismatch, certificate_profile, strict_validation_revocation, local_certificate, hash_and_url, base_url, nat_traversal, passive_mode, fragmentation, peer_ip_type, peer_ip_address, local_id, local_id_type, peer_id, peer_id_type, peer_id_matching, address_type FROM ike_gateways_profiles $query ORDER BY id, name;");
        $count = $getAll->num_rows;
        $getAll = $projectdb->query("SELECT id, source, vsys, template, name, version, dpd_ikev1, ike_interval_ikev1, retry_ikev1, ike_crypto_profile_ikev1, exchange_mode_ikev1, dpd_ikev2, ike_interval_ikev2, ike_crypto_profile_ikev2, require_cookie_ikev2, local_address_ip, interface, type_authentication, pre_shared_key, pre_shared_key AS confirm_pre_shared_key, allow_id_payload_mismatch, certificate_profile, strict_validation_revocation, local_certificate, hash_and_url, base_url, nat_traversal, passive_mode, fragmentation, peer_ip_type, peer_ip_address, local_id, local_id_type, peer_id, peer_id_type, peer_id_matching, address_type FROM ike_gateways_profiles $query ORDER BY id, name LIMIT $start, $limit;");
        
        if ($count > 0) {
            while ($data = $getAll->fetch_object()) {
                if($data->nat_traversal == "yes"){$data->nat_traversal = "on";}
                if($data->passive_mode == "yes"){$data->passive_mode = "on";}
                if($data->fragmentation == "yes"){$data->fragmentation = "on";}
                if($data->allow_id_payload_mismatch == "yes"){$data->allow_id_payload_mismatch = "on";}
                if($data->strict_validation_revocation == "yes"){$data->strict_validation_revocation = "on";}
                if($data->require_cookie_ikev2 == "yes"){$data->require_cookie_ikev2 = "on";}
                $myData[] = $data;
            }
        } else {
            $myData = "";
        }
        echo '{"total":"'.$count.'","ike":'.json_encode($myData).'}';
        
    }
    elseif ($type == "global_protect_ipsec_crypto"){

        $query = generate_query("template_not_vsys");

        if(($filter != "none") && ($filter != "0")){

            $params['tools_where_columns_id'] = $filter;
            $params['tools_operator_id'] = "contains";
            $params['search'] = "";
            $params['tools_where_id'] = "27";
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

        list($query, $orderby) = generateQueryFilters($project, "global_protect_app_ipsec_crypto_profiles", "", $query, $source);

        $getAll = $projectdb->query("SELECT id, source, vsys, template, name, encryption, hash FROM global_protect_app_ipsec_crypto_profiles $query ORDER BY id, name;");
        $count = $getAll->num_rows;
        $getAll = $projectdb->query("SELECT id, source, vsys, template, name, encryption, hash FROM global_protect_app_ipsec_crypto_profiles $query ORDER BY id, name LIMIT $start, $limit;");
        
        if ($count > 0) {
            while ($data = $getAll->fetch_object()) {
                $myData[] = $data;
            }
        } else {
            $myData = "";
        }
        echo '{"total":"'.$count.'","ipsec":'.json_encode($myData).'}';
        
    }
    elseif ($type == "ike_crypto_name"){

        $query = generate_query("template_not_vsys");
        
        $getAll = $projectdb->query("SELECT id, name FROM ike_crypto_profiles $query ORDER BY id, name;");
        $count = $getAll->num_rows;
        if ($count > 0) {
            while ($data = $getAll->fetch_object()) {
                $myData[] = $data;
            }
        } else {
            $myData = "";
        }
        echo '{"total":"'.$count.'","ike_crypto":'.json_encode($myData).'}';
        
    }
    elseif ($type == "interfaces"){

        $query = generate_query("template_not_vsys");
        
        if (preg_match("/WHERE/i", $query)) {
            $query = $query . " AND media != 'tunnel' ";
        } else {
            $query = " WHERE media != 'tunnel'";
        }
            
        $getAll = $projectdb->query("SELECT id, unitname, media FROM interfaces $query ORDER BY unitname;");
        $count = $getAll->num_rows;
        while ($data = $getAll->fetch_assoc()) {
            $myData[] = $data;
        }
        if ($count == 0) {
            $myData = "";
        }
        echo '{"total":"' . $count . '","interfaces":' . json_encode($myData) . '}';
    }
    elseif ($type == "local_ip_address"){
        
        $interface_ike = $projectdb->real_escape_string((string) (isset($_POST['interface_ike']) ? $_POST['interface_ike'] : $_GET['interface_ike']));
        
        if ($interface_ike != "") {
            $address = array();
            $getAddress = $projectdb->query("SELECT unitipaddress FROM interfaces WHERE unitname = '$interface_ike' AND source = '$source' AND template = '$template';");
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
    elseif ($type == "ipsec_tunnel"){

        $query = generate_query("template_not_vsys");

        if(($filter != "none") && ($filter != "0")){

            $params['tools_where_columns_id'] = $filter;
            $params['tools_operator_id'] = "contains";
            $params['search'] = "";
            $params['tools_where_id'] = "23";
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

        list($query, $orderby) = generateQueryFilters($project, "ipsec_tunnel", "", $query, $source);

        $getAll = $projectdb->query("SELECT id, source, vsys, template, name, anti_replay, copy_tos, tunnel_monitor, destination_ip, tunnel_monitor_profile, tunnel_interface, address_type, type_tunnel, ike_gateway, ipsec_crypto_profile, protocol, authentication, key_auth, key_auth AS key_auth_confirm, encryption, key_encry, key_encry AS key_encry_confirm, local_address_ip, local_address_ip AS local_address_ip2, interface, interface AS interface2, peer_ip_address, local_spi, remote_spi, external_ca, certificate_profile, local_certificate, publish_connected_routes, portal_address, disabled FROM ipsec_tunnel $query ORDER BY id, name;");
        $count = $getAll->num_rows;
        $getAll = $projectdb->query("SELECT id, source, vsys, template, name, anti_replay, copy_tos, tunnel_monitor, destination_ip, tunnel_monitor_profile, tunnel_interface, address_type, type_tunnel, ike_gateway, ipsec_crypto_profile, protocol, authentication, key_auth, key_auth AS key_auth_confirm, encryption, key_encry, key_encry AS key_encry_confirm, local_address_ip, local_address_ip AS local_address_ip2, interface, interface AS interface2, peer_ip_address, local_spi, remote_spi, external_ca, certificate_profile, local_certificate, publish_connected_routes, portal_address, disabled FROM ipsec_tunnel $query ORDER BY id, name LIMIT $start, $limit;");
        if ($count > 0) {
            while ($data = $getAll->fetch_object()) {
                if($data->copy_tos == "yes"){$data->copy_tos = "on";}
                if($data->anti_replay == "yes"){$data->anti_replay = "on";}
                if($data->publish_connected_routes == "yes"){$data->publish_connected_routes = "on";}
                if($data->external_ca == "yes"){$data->external_ca = "on";}
                
                if($data->type_tunnel == "auto-key"){
                    // Interface: Coge la interface de la IKE Gateway
                    // Peer IP: Peer address del IKE Gateway
                    $getIKE = $projectdb->query("SELECT interface, peer_ip_address, local_address_ip AS unitipaddress FROM ike_gateways_profiles WHERE name = '$data->ike_gateway' AND source = '$source' AND template = '$template';");
                    //echo "SELECT interface, peer_ip_address FROM ike_gateways_profiles WHERE name = '$data->ike_gateway';";
        
                    if ($getIKE->num_rows > 0) {
                        while ($dataIKE = $getIKE->fetch_object()) {
                            $data->interface = $dataIKE->interface;
                            $data->peer_ip_address = $dataIKE->peer_ip_address;
                            $data->unitipaddress = $dataIKE->unitipaddress;
                        }
                    }
                }
                
                $getInterfaceTunnel = $projectdb->query("SELECT vsys, zone, vr_id FROM interfaces WHERE unitname = '$data->tunnel_interface' AND source = '$source' AND template = '$template';");
        
                if ($getInterfaceTunnel->num_rows > 0) {
                    while ($dataTunnel = $getInterfaceTunnel->fetch_object()) {
                        $data->vsys = $dataTunnel->vsys;
                        $data->zone = $dataTunnel->zone;
                        $data->vr_id = $dataTunnel->vr_id;
                        
                        if($data->vr_id != 0){
                            $getVR = $projectdb->query("SELECT name FROM virtual_routers WHERE id = '$data->vr_id' AND source = '$source' AND template = '$template';");
                            if ($getVR->num_rows > 0) {
                                $dataVR = $getVR->fetch_object();
                                $data->name_vr = $dataVR->name;
                            }
                        }else{
                            $data->name_vr = "";
                        }
                        
                        
                    }
                }
                
                $myData[] = $data;
            }
        } else {
            $myData = "";
        }
        echo '{"total":"'.$count.'","ipsec_tunnel":'.json_encode($myData).'}';
        
    }
    elseif ($type == "monitor_profile_name"){

        $query = generate_query("template_not_vsys");
        
        $getAll = $projectdb->query("SELECT id, name FROM monitor_profile $query ORDER BY id, name;");
        $count = $getAll->num_rows;
        if ($count > 0) {
            $myData[] = array("name" => "None");
            while ($data = $getAll->fetch_object()) {
                $myData[] = $data;
            }
        } else {
            $myData = "";
        }
        echo '{"total":"'.$count.'","monitor":'.json_encode($myData).'}';
        
    }
    elseif ($type == "interfaces_tunnel"){

        $query = generate_query("template_not_vsys");
        
        if (preg_match("/WHERE/i", $query)) {
            $query = $query . " AND media = 'tunnel' ";
        } else {
            $query = " WHERE media = 'tunnel'";
        }
            
        $getAll = $projectdb->query("SELECT id, unitname, media FROM interfaces $query ORDER BY unitname;");
        $count = $getAll->num_rows;
        while ($data = $getAll->fetch_assoc()) {
            $myData[] = $data;
        }
        if ($count == 0) {
            $myData = "";
        }
        echo '{"total":"' . $count . '","interfaces":' . json_encode($myData) . '}';
    }
    elseif ($type == "ike_gateways_name"){

        $query = generate_query("template_not_vsys");
        
        $getAll = $projectdb->query("SELECT id, name FROM ike_gateways_profiles $query ORDER BY id, name;");
        $count = $getAll->num_rows;
        if ($count > 0) {
            while ($data = $getAll->fetch_object()) {
                $myData[] = $data;
            }
        } else {
            $myData = "";
        }
        echo '{"total":"'.$count.'","ike_gateways":'.json_encode($myData).'}';
        
    }
    elseif ($type == "ipsec_crypto_name"){

        $query = generate_query("template_not_vsys");
        
        $getAll = $projectdb->query("SELECT id, name FROM ipsec_crypto_profiles $query ORDER BY id, name;");
        $count = $getAll->num_rows;
        if ($count > 0) {
            while ($data = $getAll->fetch_object()) {
                $myData[] = $data;
            }
        } else {
            $myData = "";
        }
        echo '{"total":"'.$count.'","ipsec_crypto":'.json_encode($myData).'}';
        
    }
    elseif ($type == "proxy_id"){
        
        $ipsec_tunnel_id = $projectdb->real_escape_string((string) (isset($_POST['ipsec_tunnel_id']) ? $_POST['ipsec_tunnel_id'] : $_GET['ipsec_tunnel_id']));
        $type_v = $projectdb->real_escape_string((string) (isset($_POST['type_v']) ? $_POST['type_v'] : $_GET['type_v']));
        
        $getAll = $projectdb->query("SELECT id, name, ipsec_tunnel_id, local, remote, protocol, protocol AS protocol_render, local_port, remote_port, number, type AS type_v  FROM proxy_id_ipsec_tunnel WHERE ipsec_tunnel_id = '$ipsec_tunnel_id' AND type = '$type_v' ORDER BY id, name;");
        $count = $getAll->num_rows;
        if ($count > 0) {
            while ($data = $getAll->fetch_object()) {
                if(($data->protocol == "TCP") || ($data->protocol == "UDP")){
                    $data->protocol_render = $data->protocol ."<br>Local Port: ". $data->local_port ."<br>Remote Port: ". $data->remote_port;
                }elseif($data->protocol == "Number"){
                    $data->protocol_render = $data->protocol .": ". $data->number;
                }elseif($data->protocol == "Any"){
                    $data->protocol_render = $data->protocol;
                }
                
                $myData[] = $data;
            }
        } else {
            $myData = "";
        }
        echo '{"total":"'.$count.'","proxy":'.json_encode($myData).'}';
        
    }
    elseif ($type == "subnet"){
        
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $idx = $projectdb->real_escape_string((string) (isset($_POST['idx']) ? $_POST['idx'] : $_GET['idx']));
        
        if ($idx != "") {
            $subnet = array();
            $getAddress = $projectdb->query("SELECT publish_routes FROM ipsec_tunnel WHERE id = '$idx';");
            if ($getAddress->num_rows == 1) {
                $dataA = $getAddress->fetch_assoc();
                $add = $dataA['publish_routes'];
                $add_explode = explode(",", $add);
                $count = count($add_explode);
                foreach ($add_explode as $key => $value) {
                    $subnet[] = array("name" => $value);
                }
                if ($add == "") {
                    $count = 0;
                    $subnet = "";
                }
                echo '{"total":"' . $count . '","subnet":' . json_encode($subnet) . '}';
            }
        }
        
    }
}
elseif ($action == "set"){
    
    if ($type == "save_position_dh_group"){
        $ids = $projectdb->real_escape_string((string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']));
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));

        $all_ids = explode(',', $ids);
        if ($all_ids != "") {
            take_snapshot_last($project);
            foreach ($all_ids as $value) {
                if ($value != "") {
                    $data = explode(";", $value);
                    $new_position = $data[0];
                    $old_position = $data[1];
                    $id = $data[2];
                    $projectdb->query("UPDATE edit_table SET ids = '$new_position' WHERE id = '$id' AND type = 'crypto_dh_group' AND user_id = '$user_id';");
                }
            }
            echo json_encode(array("success" => true));
        } else {
            echo json_encode(array("success" => false));
        }
    }
    elseif ($type == "save_position_encryption"){
        $ids = $projectdb->real_escape_string((string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']));
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));

        $all_ids = explode(',', $ids);
        if ($all_ids != "") {
            take_snapshot_last($project);
            foreach ($all_ids as $value) {
                if ($value != "") {
                    $data = explode(";", $value);
                    $new_position = $data[0];
                    $old_position = $data[1];
                    $id = $data[2];
                    $projectdb->query("UPDATE edit_table SET ids = '$new_position' WHERE id = '$id' AND type = 'crypto_encryption' AND user_id = '$user_id';");
                }
            }
            echo json_encode(array("success" => true));
        } else {
            echo json_encode(array("success" => false));
        }
    }
    elseif ($type == "save_position_authentication"){
        
        $ids = $projectdb->real_escape_string((string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']));
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));

        $all_ids = explode(',', $ids);
        if ($all_ids != "") {
            take_snapshot_last($project);
            foreach ($all_ids as $value) {
                if ($value != "") {
                    $data = explode(";", $value);
                    $new_position = $data[0];
                    $old_position = $data[1];
                    $id = $data[2];
                    $projectdb->query("UPDATE edit_table SET ids = '$new_position' WHERE id = '$id' AND type = 'crypto_authentication' AND user_id = '$user_id';");
                }
            }
            echo json_encode(array("success" => true));
        } else {
            echo json_encode(array("success" => false));
        }
        
    }
}
elseif ($action == "add"){
    
    if ($type == "proxy_id"){
        
        $ipsec_tunnel_id = $projectdb->real_escape_string((string) (isset($_POST['ipsec_tunnel_id']) ? $_POST['ipsec_tunnel_id'] : $_GET['ipsec_tunnel_id']));
        $type_v = $projectdb->real_escape_string((string) (isset($_POST['type_v']) ? $_POST['type_v'] : $_GET['type_v']));
        
        take_snapshot_last($project);
        
        $projectdb->query("INSERT INTO proxy_id_ipsec_tunnel (template, source, type, ipsec_tunnel_id, protocol) VALUES ('$template', '$source', '$type_v', '$ipsec_tunnel_id', 'Any');");
        echo json_encode(array("success"=>true));
        
    }
    elseif ($type == "interface_mgmt_address"){
        
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $idx = $projectdb->real_escape_string((string) (isset($_POST['idx']) ? $_POST['idx'] : $_GET['idx']));
        $name = $projectdb->real_escape_string((string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']));
        
        if($idx == ""){
            $idx = 0;
        }
        
        $getBridge = $projectdb->query("SELECT id FROM edit_table WHERE type = 'permitted_ip' AND name = '$name' AND user_id = '$user_id';");
        if ($getBridge->num_rows == 0) {

            $getBridgeId = $projectdb->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'permitted_ip' AND lid = '$idx' AND user_id = '$user_id';");
            if ($getBridgeId->num_rows == 1) {
               $getIdData = $getBridgeId->fetch_assoc();
               $ids = $getIdData['ids'] + 1;
            }else{
                $ids = 1;
            }

            $projectdb->query("INSERT INTO edit_table (id, ids, lid, type, name, source, remove, user_id) "
                . "VALUES (NULL, '$ids', '$idx', 'permitted_ip', '$name', '$template', '0', '$user_id');");
        }else{
            $projectdb->query("UPDATE edit_table SET remove = '0' WHERE name = '$name' AND type = 'permitted_ip' AND lid = '$idx' AND user_id = '$user_id';");
        }
        
        echo json_encode(array("success" => true));
        
    }
    elseif ($type == "dh_group"){
        
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $idx = $projectdb->real_escape_string((string) (isset($_POST['idx']) ? $_POST['idx'] : $_GET['idx']));
        $name = $projectdb->real_escape_string((string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']));
        
        if($idx == ""){
            $idx = 0;
        }
        
        $getBridge = $projectdb->query("SELECT id FROM edit_table WHERE type = 'crypto_dh_group' AND name = '$name' AND user_id = '$user_id';");
        if ($getBridge->num_rows == 0) {

            $getBridgeId = $projectdb->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'crypto_dh_group' AND lid = '$idx' AND user_id = '$user_id';");
            if ($getBridgeId->num_rows == 1) {
               $getIdData = $getBridgeId->fetch_assoc();
               $ids = $getIdData['ids'] + 1;
            }else{
                $ids = 1;
            }

            $projectdb->query("INSERT INTO edit_table (id, ids, lid, type, name, source, remove, user_id) "
                . "VALUES (NULL, '$ids', '$idx', 'crypto_dh_group', '$name', '$template', '0', '$user_id');");
        }else{
            $projectdb->query("UPDATE edit_table SET remove = '0' WHERE name = '$name' AND type = 'crypto_dh_group' AND lid = '$idx' AND user_id = '$user_id';");
        }
        
    }
    elseif ($type == "encryption"){
        
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $idx = $projectdb->real_escape_string((string) (isset($_POST['idx']) ? $_POST['idx'] : $_GET['idx']));
        $name = $projectdb->real_escape_string((string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']));
        
        if($idx == ""){
            $idx = 0;
        }
        
        $getBridge = $projectdb->query("SELECT id FROM edit_table WHERE type = 'crypto_encryption' AND name = '$name' AND user_id = '$user_id';");
        if ($getBridge->num_rows == 0) {

            $getBridgeId = $projectdb->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'crypto_encryption' AND lid = '$idx' AND user_id = '$user_id';");
            if ($getBridgeId->num_rows == 1) {
               $getIdData = $getBridgeId->fetch_assoc();
               $ids = $getIdData['ids'] + 1;
            }else{
                $ids = 1;
            }

            $projectdb->query("INSERT INTO edit_table (id, ids, lid, type, name, source, remove, user_id) "
                . "VALUES (NULL, '$ids', '$idx', 'crypto_encryption', '$name', '$template', '0', '$user_id');");
        }else{
            $projectdb->query("UPDATE edit_table SET remove = '0' WHERE name = '$name' AND type = 'crypto_encryption' AND lid = '$idx' AND user_id = '$user_id';");
        }
        
    }
    elseif ($type == "authentication"){
        
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $idx = $projectdb->real_escape_string((string) (isset($_POST['idx']) ? $_POST['idx'] : $_GET['idx']));
        $name = $projectdb->real_escape_string((string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']));
        
        if($idx == ""){
            $idx = 0;
        }
        
        $getBridge = $projectdb->query("SELECT id FROM edit_table WHERE type = 'crypto_authentication' AND name = '$name' AND user_id = '$user_id';");
        if ($getBridge->num_rows == 0) {

            $getBridgeId = $projectdb->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'crypto_authentication' AND lid = '$idx' AND user_id = '$user_id';");
            if ($getBridgeId->num_rows == 1) {
               $getIdData = $getBridgeId->fetch_assoc();
               $ids = $getIdData['ids'] + 1;
            }else{
                $ids = 1;
            }

            $projectdb->query("INSERT INTO edit_table (id, ids, lid, type, name, source, remove, user_id) "
                . "VALUES (NULL, '$ids', '$idx', 'crypto_authentication', '$name', '$template', '0', '$user_id');");
        }else{
            $projectdb->query("UPDATE edit_table SET remove = '0' WHERE name = '$name' AND type = 'crypto_authentication' AND lid = '$idx' AND user_id = '$user_id';");
        }
        
    }
    elseif ($type == "subnet"){
        
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $idx = $projectdb->real_escape_string((string) (isset($_POST['idx']) ? $_POST['idx'] : $_GET['idx']));
        $table_name = $projectdb->real_escape_string((string) (isset($_POST['table_name']) ? $_POST['table_name'] : $_GET['table_name']));
        $ids = $projectdb->real_escape_string((string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']));
        $name = $projectdb->real_escape_string((string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']));
        
        $getAddress = $projectdb->query("SELECT publish_routes FROM ipsec_tunnel WHERE id = '$idx';");
        
        if ($getAddress->num_rows == 1) {
            $dataA = $getAddress->fetch_assoc();
            $publish_routes = $dataA['publish_routes'];

            if ($publish_routes != "") {
                $add_array = explode(",", $publish_routes);
                if (in_array($name, $add_array)) {
                    
                } else {
                    $add_array[] = $name;
                    $projectdb->query("UPDATE ipsec_tunnel SET publish_routes ='" . implode(",", $add_array) . "' WHERE id='$idx';");
                }
            } else {
                $projectdb->query("UPDATE ipsec_tunnel SET publish_routes ='$name' WHERE id='$idx';");
            }
        }
        echo json_encode(array("success" => true));
        
    }
}
elseif ($action == "update"){
    
    if ($type == "monitor"){
        
        $id = $projectdb->real_escape_string((string) (isset($_POST['idx']) ? $_POST['idx'] : $_GET['idx']));
        $name = $projectdb->real_escape_string((string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']));
        $interva = $projectdb->real_escape_string((string) (isset($_POST['interva']) ? $_POST['interva'] : $_GET['interva']));
        $action = $projectdb->real_escape_string((string) (isset($_POST['m_action']) ? $_POST['m_action'] : $_GET['m_action']));
        $threshold = $projectdb->real_escape_string((string) (isset($_POST['threshold']) ? $_POST['threshold'] : $_GET['threshold']));
	
        take_snapshot_last($project);
        $is_new = 0;
        
        if ($name != ""){
            
            if($id == ""){
                $projectdb->query("INSERT INTO monitor_profile (template, source, m_action, interva, threshold) VALUES ('$template', '$source', 'wait-recover','3', '5')");
                $id = $projectdb->insert_id; 
                $is_new = 1;
                $projectdb->query("UPDATE edit_table SET lid = '$id' WHERE user_id = '$user_id';");
            }
            // Check the name doesn't exist!
            $getExistName = $projectdb->query("SELECT name FROM monitor_profile WHERE id != '$id' AND BINARY name = '$name' AND source = '$source' AND template = '$template';");
            if ($getExistName->num_rows == 0){
                
                $getNameOld = $projectdb->query("SELECT name FROM monitor_profile WHERE id = '$id';");
                if($getNameOld->num_rows > 0){
                    $dataNO = $getNameOld->fetch_assoc();
                    $name_old = $dataNO['name'];
                    if($name_old != ""){
                        $projectdb->query("UPDATE ipsec_tunnel SET tunnel_monitor_profile = '$name' WHERE source = '$source' AND template = '$template' AND tunnel_monitor_profile = '$name_old' ;");
                        $projectdb->query("UPDATE pbf_rules SET monitor_profile = '$name' WHERE source = '$source' AND monitor_profile = '$name_old' ;");
                    }
                }
                
                $projectdb->query("UPDATE monitor_profile SET name = '$name', m_action = '$action', interva = '$interva', threshold = '$threshold' WHERE id = '$id';");
                echo json_encode(array("success"=>true));
            }
            else{
                if ($is_new == 1){
                    $projectdb->query("DELETE FROM monitor_profile WHERE id = '$id';");
                }
                echo json_encode(array("success"=>false, "msg"=>"The name already exist!"));
            }
        }else{
            echo json_encode(array("success"=>false));
        }
    }
    elseif ($type == "management_interfaces"){
        
        $id = $projectdb->real_escape_string((string) (isset($_POST['idx']) ? $_POST['idx'] : $_GET['idx']));
        $name = $projectdb->real_escape_string((string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']));
        $http = $projectdb->real_escape_string((string) (isset($_POST['http']) ? $_POST['http'] : ""));
        $http_ocsp = $projectdb->real_escape_string((string) (isset($_POST['http_ocsp']) ? $_POST['http_ocsp'] : ""));
        $https = $projectdb->real_escape_string((string) (isset($_POST['https']) ? $_POST['https'] : ""));
        $ping = $projectdb->real_escape_string((string) (isset($_POST['ping']) ? $_POST['ping'] : ""));
        $response_pages = $projectdb->real_escape_string((string) (isset($_POST['response_pages']) ? $_POST['response_pages'] : ""));
        $snmp = $projectdb->real_escape_string((string) (isset($_POST['snmp']) ? $_POST['snmp'] : ""));
        $ssh = $projectdb->real_escape_string((string) (isset($_POST['ssh']) ? $_POST['ssh'] : ""));
        $telnet = $projectdb->real_escape_string((string) (isset($_POST['telnet']) ? $_POST['telnet'] : ""));
        $userid_service = $projectdb->real_escape_string((string) (isset($_POST['userid_service']) ? $_POST['userid_service'] : ""));
        $userid_syslog_listener_ssl = $projectdb->real_escape_string((string) (isset($_POST['userid_syslog_listener_ssl']) ? $_POST['userid_syslog_listener_ssl'] : ""));
        $userid_syslog_listener_udp = $projectdb->real_escape_string((string) (isset($_POST['userid_syslog_listener_udp']) ? $_POST['userid_syslog_listener_udp'] : ""));
	
        $is_new = 0;
        
        take_snapshot_last($project);
        
        if ($name != ""){
            
            $permittedip_array = array();
                    
            if($id == ""){
                $projectdb->query("INSERT INTO interface_management_profile (template, source) VALUES ('$template', '$source')");
                $id = $projectdb->insert_id; 
                $is_new = 1;
                $projectdb->query("UPDATE edit_table SET lid = '$id' WHERE user_id = '$user_id';");
            }
            
            // Check the name doesn't exist!
            $getExistName = $projectdb->query("SELECT name FROM interface_management_profile WHERE id != '$id' AND BINARY name = '$name' AND source = '$source' AND template = '$template';");
            if ($getExistName->num_rows == 0){
                if($http == "on"){$http = "yes";}else{$http = "no";}
                if($http_ocsp == "on"){$http_ocsp = "yes";}else{$http_ocsp = "no";}
                if($https == "on"){$https = "yes";}else{$https = "no";}
                if($ping == "on"){$ping = "yes";}else{$ping = "no";}
                if($response_pages == "on"){$response_pages = "yes";}else{$response_pages = "no";}
                if($snmp == "on"){$snmp = "yes";}else{$snmp = "no";}
                if($ssh == "on"){$ssh = "yes";}else{$ssh = "no";}
                if($telnet == "on"){$telnet = "yes";}else{$telnet = "no";}
                if($userid_service == "on"){$userid_service = "yes";}else{$userid_service = "no";}
                if($userid_syslog_listener_ssl == "on"){$userid_syslog_listener_ssl = "yes";}else{$userid_syslog_listener_ssl = "no";}
                if($userid_syslog_listener_udp == "on"){$userid_syslog_listener_udp = "yes";}else{$userid_syslog_listener_udp = "no";}
                    
                $getNameOld = $projectdb->query("SELECT name FROM interface_management_profile WHERE id = '$id';");
                if($getNameOld->num_rows > 0){
                    $dataNO = $getNameOld->fetch_assoc();
                    $name_old = $dataNO['name'];
                    if($name_old != ""){
                        $projectdb->query("UPDATE interfaces SET interface_management_profile = '$name' WHERE source = '$source' AND template = '$template' AND interface_management_profile = '$name_old' ;");
                    }
                }
                
                $getPermittedIP = $projectdb->query("SELECT name FROM edit_table WHERE type = 'permitted_ip' AND lid = '$id' AND remove = '0' AND user_id = '$user_id' ORDER BY ids ASC;");
                if($getPermittedIP->num_rows > 0){
                    while($dataIP = $getPermittedIP->fetch_assoc()){
                        $permittedip_array[] = $dataIP['name'];
                    }
                }
                $projectdb->query("UPDATE interface_management_profile SET name = '$name', http = '$http', https = '$https', http_ocsp = '$http_ocsp', ssh = '$ssh', snmp = '$snmp', userid_service = '$userid_service', userid_syslog_listener_ssl = '$userid_syslog_listener_ssl', userid_syslog_listener_udp = '$userid_syslog_listener_udp', ping = '$ping', response_pages = '$response_pages', telnet = '$telnet', permitted_ip = '".implode(",", $permittedip_array)."'  WHERE id = '$id';");
                echo json_encode(array("success"=>true));
            }
            else{
                if ($is_new == 1){
                    $projectdb->query("DELETE FROM interface_management_profile WHERE id = '$id';");
                }
                echo json_encode(array("success"=>false, "msg"=>"The name already exist!"));
            }
        }else{
            echo json_encode(array("success"=>false));
        }
        
    }
    elseif ($type == "interface_mgmt_address"){
        
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $idx = $projectdb->real_escape_string((string) (isset($_POST['idx']) ? $_POST['idx'] : $_GET['idx']));
        $template = $projectdb->real_escape_string((string) (isset($_POST['template']) ? $_POST['template'] : $_GET['template']));
        $table_name = $projectdb->real_escape_string((string) (isset($_POST['table_name']) ? $_POST['table_name'] : $_GET['table_name']));
        $ids = $projectdb->real_escape_string((string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']));
        $name = $projectdb->real_escape_string((string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']));
        $oldname = $projectdb->real_escape_string((string) (isset($_POST['oldname']) ? $_POST['oldname'] : $_GET['oldname']));
        
        take_snapshot_last($project);
        
        if (($name != "") AND ($oldname != "")){
            
            $projectdb->query("UPDATE edit_table SET remove = '1' WHERE lid = '$idx' AND type = 'permitted_ip' AND name = '$oldname' AND user_id = '$user_id';");
            
            $getExistRemove = $projectdb->query("SELECT id FROM edit_table WHERE name = '$name' AND type = 'permitted_ip' AND lid = '$idx' AND remove = '1' AND user_id = '$user_id';");
            if($getExistRemove->num_rows == 1){
                $dataExist = $getExistRemove->fetch_assoc();
                $id_exist = $dataExist['id'];
                $projectdb->query("UPDATE edit_table SET remove = '0' WHERE id = '$id_exist' AND user_id = '$user_id';");
            }else{
                $getExistRemove = $projectdb->query("SELECT id FROM edit_table WHERE name = '$name' AND type = 'permitted_ip' AND lid = '$idx' AND remove = '0' AND user_id = '$user_id';");
                if($getExistRemove->num_rows == 0){
                    $getBridgeId = $projectdb->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'permitted_ip' AND user_id = '$user_id';");
                    if ($getBridgeId->num_rows == 1) {
                       $getIdData = $getBridgeId->fetch_assoc();
                       $ids = $getIdData['ids'] + 1;
                    }else{
                        $ids = 1;
                    }
                    $projectdb->query("INSERT INTO edit_table (id, ids, lid,type, name, source, remove, user_id) "
                        . "VALUES (NULL, '$ids', '$idx', 'permitted_ip', '$name', '$template', '0', '$user_id');");
                }
            }
            echo json_encode(array("success"=>true));
        }
        else{
            echo json_encode(array("success"=>false));
        }
    }
    elseif ($type == "dh_group"){
        
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $idx = $projectdb->real_escape_string((string) (isset($_POST['idx']) ? $_POST['idx'] : $_GET['idx']));
        $template = $projectdb->real_escape_string((string) (isset($_POST['template']) ? $_POST['template'] : $_GET['template']));
        $ids = $projectdb->real_escape_string((string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']));
        $name = $projectdb->real_escape_string((string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']));
        $oldname = $projectdb->real_escape_string((string) (isset($_POST['oldname']) ? $_POST['oldname'] : $_GET['oldname']));
        
        if (($name != "") AND ($oldname != "")){
            
            $projectdb->query("UPDATE edit_table SET remove = '1' WHERE lid = '$idx' AND type = 'crypto_dh_group' AND name = '$oldname' AND user_id = '$user_id';");
            
            $getExistRemove = $projectdb->query("SELECT id FROM edit_table WHERE name = '$name' AND type = 'crypto_dh_group' AND lid = '$idx' AND remove = '1' AND user_id = '$user_id';");
            if($getExistRemove->num_rows == 1){
                $dataExist = $getExistRemove->fetch_assoc();
                $id_exist = $dataExist['id'];
                $projectdb->query("UPDATE edit_table SET remove = '0' WHERE id = '$id_exist' AND user_id = '$user_id';");
            }else{
                $getExistRemove = $projectdb->query("SELECT id FROM edit_table WHERE name = '$name' AND type = 'crypto_dh_group' AND lid = '$idx' AND remove = '0' AND user_id = '$user_id';");
                if($getExistRemove->num_rows == 0){
                    $getBridgeId = $projectdb->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'crypto_dh_group' AND user_id = '$user_id';");
                    if ($getBridgeId->num_rows == 1) {
                       $getIdData = $getBridgeId->fetch_assoc();
                       $ids = $getIdData['ids'] + 1;
                    }else{
                        $ids = 1;
                    }
                    $projectdb->query("INSERT INTO edit_table (id, ids, lid,type, name, source, remove, user_id) "
                        . "VALUES (NULL, '$ids', '$idx', 'crypto_dh_group', '$name', '$template', '0', '$user_id');");
                }
            }
            echo json_encode(array("success"=>true));
        }
        else{
            echo json_encode(array("success"=>false));
        }
    }
    elseif ($type == "encryption"){
        
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $idx = $projectdb->real_escape_string((string) (isset($_POST['idx']) ? $_POST['idx'] : $_GET['idx']));
        $template = $projectdb->real_escape_string((string) (isset($_POST['template']) ? $_POST['template'] : $_GET['template']));
        $ids = $projectdb->real_escape_string((string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']));
        $name = $projectdb->real_escape_string((string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']));
        $oldname = $projectdb->real_escape_string((string) (isset($_POST['oldname']) ? $_POST['oldname'] : $_GET['oldname']));
        
        if (($name != "") AND ($oldname != "")){
            
            $projectdb->query("UPDATE edit_table SET remove = '1' WHERE lid = '$idx' AND type = 'crypto_encryption' AND name = '$oldname' AND user_id = '$user_id';");
            
            $getExistRemove = $projectdb->query("SELECT id FROM edit_table WHERE name = '$name' AND type = 'crypto_encryption' AND lid = '$idx' AND remove = '1' AND user_id = '$user_id';");
            if($getExistRemove->num_rows == 1){
                $dataExist = $getExistRemove->fetch_assoc();
                $id_exist = $dataExist['id'];
                $projectdb->query("UPDATE edit_table SET remove = '0' WHERE id = '$id_exist' AND user_id = '$user_id';");
            }else{
                $getExistRemove = $projectdb->query("SELECT id FROM edit_table WHERE name = '$name' AND type = 'crypto_encryption' AND lid = '$idx' AND remove = '0' AND user_id = '$user_id';");
                if($getExistRemove->num_rows == 0){
                    $getBridgeId = $projectdb->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'crypto_encryption' AND user_id = '$user_id';");
                    if ($getBridgeId->num_rows == 1) {
                       $getIdData = $getBridgeId->fetch_assoc();
                       $ids = $getIdData['ids'] + 1;
                    }else{
                        $ids = 1;
                    }
                    $projectdb->query("INSERT INTO edit_table (id, ids, lid,type, name, source, remove, user_id) "
                        . "VALUES (NULL, '$ids', '$idx', 'crypto_encryption', '$name', '$template', '0', '$user_id');");
                }
            }
            echo json_encode(array("success"=>true));
        }
        else{
            echo json_encode(array("success"=>false));
        }
        
    }
    elseif ($type == "authentication"){
        
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $idx = $projectdb->real_escape_string((string) (isset($_POST['idx']) ? $_POST['idx'] : $_GET['idx']));
        $template = $projectdb->real_escape_string((string) (isset($_POST['template']) ? $_POST['template'] : $_GET['template']));
        $ids = $projectdb->real_escape_string((string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']));
        $name = $projectdb->real_escape_string((string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']));
        $oldname = $projectdb->real_escape_string((string) (isset($_POST['oldname']) ? $_POST['oldname'] : $_GET['oldname']));
        
        if (($name != "") AND ($oldname != "")){
            
            $projectdb->query("UPDATE edit_table SET remove = '1' WHERE lid = '$idx' AND type = 'crypto_authentication' AND name = '$oldname' AND user_id = '$user_id';");
            
            $getExistRemove = $projectdb->query("SELECT id FROM edit_table WHERE name = '$name' AND type = 'crypto_authentication' AND lid = '$idx' AND remove = '1' AND user_id = '$user_id';");
            if($getExistRemove->num_rows == 1){
                $dataExist = $getExistRemove->fetch_assoc();
                $id_exist = $dataExist['id'];
                $projectdb->query("UPDATE edit_table SET remove = '0' WHERE id = '$id_exist' AND user_id = '$user_id';");
            }else{
                $getExistRemove = $projectdb->query("SELECT id FROM edit_table WHERE name = '$name' AND type = 'crypto_authentication' AND lid = '$idx' AND remove = '0' AND user_id = '$user_id';");
                if($getExistRemove->num_rows == 0){
                    $getBridgeId = $projectdb->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'crypto_authentication' AND user_id = '$user_id';");
                    if ($getBridgeId->num_rows == 1) {
                       $getIdData = $getBridgeId->fetch_assoc();
                       $ids = $getIdData['ids'] + 1;
                    }else{
                        $ids = 1;
                    }
                    $projectdb->query("INSERT INTO edit_table (id, ids, lid,type, name, source, remove, user_id) "
                        . "VALUES (NULL, '$ids', '$idx', 'crypto_authentication', '$name', '$template', '0', '$user_id');");
                }
            }
            echo json_encode(array("success"=>true));
        }
        else{
            echo json_encode(array("success"=>false));
        }
    }
    elseif ($type == "ike_crypto"){
        
        take_snapshot_last($project);
        
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $id = $projectdb->real_escape_string((string) (isset($_POST['idx']) ? $_POST['idx'] : $_GET['idx']));
        $template = $projectdb->real_escape_string((string) (isset($_POST['template']) ? $_POST['template'] : $_GET['template']));
        $name = $projectdb->real_escape_string((string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']));
        $seconds = $projectdb->real_escape_string((string) (isset($_POST['seconds']) ? $_POST['seconds'] : $_GET['seconds']));
        $minutes = $projectdb->real_escape_string((string) (isset($_POST['minutes']) ? $_POST['minutes'] : $_GET['minutes']));
        $hours = $projectdb->real_escape_string((string) (isset($_POST['hours']) ? $_POST['hours'] : $_GET['hours']));
        $days = $projectdb->real_escape_string((string) (isset($_POST['days']) ? $_POST['days'] : $_GET['days']));
        $combo_lifetime = $projectdb->real_escape_string((string) (isset($_POST['combo_lifetime']) ? $_POST['combo_lifetime'] : $_GET['combo_lifetime']));
        $authentication_multiple = $projectdb->real_escape_string((string) (isset($_POST['authentication_multiple']) ? $_POST['authentication_multiple'] : $_GET['authentication_multiple']));
        
        $is_new = 0;

        if ($name != ""){
            
            if($id == ""){
                $projectdb->query("INSERT INTO ike_crypto_profiles (template, source) VALUES ('$template', '$source')");
                $id = $projectdb->insert_id; 
                $is_new = 1;
                $projectdb->query("UPDATE edit_table SET lid = '$id' WHERE user_id = '$user_id';");
            }
            
            $encryption_array = array();
            $hash_array = array();
            $dh_group_array = array();

            $getNameExist = $projectdb->query("SELECT id FROM ike_crypto_profiles WHERE BINARY name = '$name' AND id != '$id' AND template = '$template' AND source = '$source';");
            if($getNameExist->num_rows == 0){
                
                $is_not_correct = 0; 
                
                $getCorrect = $projectdb->query("SELECT DISTINCT(type) FROM edit_table WHERE remove = '0' AND lid = '$id' AND remove = '0' AND user_id = '$user_id';");
                if($getCorrect->num_rows != 3){
                    $is_not_correct = 1; 
                    $msg = "All values ​​are required!";
                }else{
                    $getEncryption = $projectdb->query("SELECT name FROM edit_table WHERE type = 'crypto_encryption' AND lid = '$id' AND remove = '0' AND user_id = '$user_id' ORDER BY ids ASC;");
                    if($getEncryption->num_rows > 0){
                        while($dataE = $getEncryption->fetch_assoc()){
                            $encryption_array[] = $dataE['name'];
                        }
                    }

                    $getHash = $projectdb->query("SELECT name FROM edit_table WHERE type = 'crypto_authentication' AND lid = '$id' AND remove = '0' AND user_id = '$user_id' ORDER BY ids ASC;");
                    if($getHash->num_rows > 0){
                        while($dataH = $getHash->fetch_assoc()){
                            $hash_array[] = $dataH['name'];
                        }
                    }

                    $getDHGroup = $projectdb->query("SELECT name FROM edit_table WHERE type = 'crypto_dh_group' AND lid = '$id' AND remove = '0' AND user_id = '$user_id' ORDER BY ids ASC;");
                    if($getDHGroup->num_rows > 0){
                        while($dataDH = $getDHGroup->fetch_assoc()){
                            $dh_group_array[] = $dataDH['name'];
                        }
                    }
                }
                
                if($combo_lifetime == "Seconds"){
                    $minutes = 0;
                    $hours = 0;
                    $days = 0;
                    if(($seconds < 180) || ($seconds > 65535)){
                        $is_not_correct = 1;
                        $msg = "The values of Key Lifetime ​​are not correct!";
                    }
                }elseif($combo_lifetime == "Minutes"){
                    $seconds = 0;
                    $hours = 0;
                    $days = 0;
                    if(($minutes < 3) || ($minutes > 65535)){
                        $is_not_correct = 1;
                        $msg = "The values of Key Lifetime ​​are not correct!";
                    }
                }elseif($combo_lifetime == "Hours"){
                    $seconds = 0;
                    $minutes = 0;
                    $days = 0;
                    if(($hours < 1) || ($hours > 65535)){
                        $is_not_correct = 1;
                        $msg = "The values of Key Lifetime ​​are not correct!";
                    }
                }elseif($combo_lifetime == "Days"){
                    $seconds = 0;
                    $minutes = 0;
                    $hours = 0;
                    if(($days < 1) || ($days > 65535)){
                        $is_not_correct = 1;
                        $msg = "The values of Key Lifetime ​​are not correct!";
                    }
                }else{
                    $seconds = 0;
                    $minutes = 0;
                    $hours = 8;
                    $days = 0;
                }
                
                if($is_not_correct == 1){
                    if ($is_new == 1){
                        $projectdb->query("DELETE FROM ike_crypto_profiles WHERE id = '$id';");
                    }
                    echo json_encode(array("success"=>false, "msg"=>$msg));
                }else{
                    
                    $getNameOld = $projectdb->query("SELECT name FROM ike_crypto_profiles WHERE id = '$id';");
                    if($getNameOld->num_rows > 0){
                        $dataNO = $getNameOld->fetch_assoc();
                        $name_old = $dataNO['name'];
                        if($name_old != ""){
                            $projectdb->query("UPDATE ike_gateways_profiles SET ike_crypto_profile_ikev1 = '$name' WHERE source = '$source' AND template = '$template' AND ike_crypto_profile_ikev1 = '$name_old' ;");
                            $projectdb->query("UPDATE ike_gateways_profiles SET ike_crypto_profile_ikev2 = '$name' WHERE source = '$source' AND template = '$template' AND ike_crypto_profile_ikev2 = '$name_old' ;");
                        }
                    }
                    $projectdb->query("UPDATE ike_crypto_profiles SET name = '$name', encryption = '".implode(",", $encryption_array)."', hash = '".implode(",", $hash_array)."', dh_group = '".implode(",", $dh_group_array)."', seconds = '$seconds', minutes = '$minutes', hours = '$hours', days = '$days', authentication_multiple = '$authentication_multiple' WHERE id = '$id';");
                    echo json_encode(array("success"=>true));
                }
            }
            else{
                if ($is_new == 1){
                    $projectdb->query("DELETE FROM ike_crypto_profiles WHERE id = '$id';");
                }
                echo json_encode(array("success"=>false, "msg"=>"The name already exist!"));
            }
        }
        else{
            echo json_encode(array("success"=>false));
        }
        
    }
    elseif ($type == "ipsec_crypto"){
        
        take_snapshot_last($project);
        
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $id = $projectdb->real_escape_string((string) (isset($_POST['idx']) ? $_POST['idx'] : $_GET['idx']));
        $template = $projectdb->real_escape_string((string) (isset($_POST['template']) ? $_POST['template'] : $_GET['template']));
        $name = $projectdb->real_escape_string((string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']));
        $seconds = $projectdb->real_escape_string((string) (isset($_POST['seconds']) ? $_POST['seconds'] : $_GET['seconds']));
        $minutes = $projectdb->real_escape_string((string) (isset($_POST['minutes']) ? $_POST['minutes'] : $_GET['minutes']));
        $hours = $projectdb->real_escape_string((string) (isset($_POST['hours']) ? $_POST['hours'] : $_GET['hours']));
        $days = $projectdb->real_escape_string((string) (isset($_POST['days']) ? $_POST['days'] : $_GET['days']));
        $combo_lifesize = $projectdb->real_escape_string((string) (isset($_POST['combo_lifesize']) ? $_POST['combo_lifesize'] : $_GET['combo_lifesize']));
        $combo_lifetime = $projectdb->real_escape_string((string) (isset($_POST['combo_lifetime']) ? $_POST['combo_lifetime'] : $_GET['combo_lifetime']));
        $dh_group = $projectdb->real_escape_string((string) (isset($_POST['dh_group']) ? $_POST['dh_group'] : $_GET['dh_group']));
        $kb = $projectdb->real_escape_string((string) (isset($_POST['kb']) ? $_POST['kb'] : $_GET['kb']));
        $mb = $projectdb->real_escape_string((string) (isset($_POST['mb']) ? $_POST['mb'] : $_GET['mb']));
        $gb = $projectdb->real_escape_string((string) (isset($_POST['gb']) ? $_POST['gb'] : $_GET['gb']));
        $tb = $projectdb->real_escape_string((string) (isset($_POST['tb']) ? $_POST['tb'] : $_GET['tb']));
        $protocol = $projectdb->real_escape_string((string) (isset($_POST['protocol']) ? $_POST['protocol'] : $_GET['protocol']));
        $is_enable_lifesize = $projectdb->real_escape_string((string) (isset($_POST['is_enable_lifesize_IPSec-checkbox']) ? $_POST['is_enable_lifesize_IPSec-checkbox'] : ""));
        
        $is_new = 0;

        // Make sure the selected template is mapped with the selected source
        $query_validate_template = "SELECT * FROM templates_mapping where id = $template and source = $source;";
        $get_valid_template = $projectdb->query($query_validate_template);
        if($get_valid_template->num_rows === 0){
            echo json_encode(array("success"=>false, "msg"=>"The template selected is not valid for the selected source!"));
        } elseif ($name != ""){
            
            if($id == ""){
                $projectdb->query("INSERT INTO ipsec_crypto_profiles (template, source, protocol, hours, dh_group) "
               . "VALUES ('$template', '$source', 'ESP', '1', 'group2')");
                $id = $projectdb->insert_id; 
                $is_new = 1;
                $projectdb->query("UPDATE edit_table SET lid = '$id' WHERE user_id = '$user_id';");
            }
            
            $encryption_array = array();
            $hash_array = array();
            
            $getNameExist = $projectdb->query("SELECT id FROM ipsec_crypto_profiles WHERE BINARY name = '$name' AND id != '$id' AND template = '$template' AND source = '$source';");
            if($getNameExist->num_rows == 0){
                
                $is_not_correct = 0; 
                
                if($protocol == "ESP"){
                    $total_type = 2;
                }else{
                    $total_type = 1;
                }
                
                if($protocol == "ESP"){
                    $getCorrect = $projectdb->query("SELECT DISTINCT(type) FROM edit_table WHERE remove = '0' AND lid = '$id' AND type IN ('crypto_encryption', 'crypto_authentication') AND user_id = '$user_id';");
                    if($getCorrect->num_rows != $total_type){
                        $is_not_correct = 1; 
                        $msg = "All values ​​are required!";
                    }else{
                        $getEncryption = $projectdb->query("SELECT name FROM edit_table WHERE type = 'crypto_encryption' AND lid = '$id' AND remove = '0' AND user_id = '$user_id' ORDER BY ids ASC;");
                        if($getEncryption->num_rows > 0){
                            while($dataE = $getEncryption->fetch_assoc()){
                                $encryption_array[] = $dataE['name'];
                            }
                        }
                        $getHash = $projectdb->query("SELECT name FROM edit_table WHERE type = 'crypto_authentication' AND lid = '$id' AND remove = '0' AND user_id = '$user_id' ORDER BY ids ASC;");
                        if($getHash->num_rows > 0){
                            while($dataH = $getHash->fetch_assoc()){
                                $hash_array[] = $dataH['name'];
                            }
                        }
                    }
                }
                else{
                    $getCorrect = $projectdb->query("SELECT DISTINCT(type) FROM edit_table WHERE remove = '0' AND lid = '$id' AND type IN ('crypto_authentication') AND user_id = '$user_id';");
                    if($getCorrect->num_rows != $total_type){
                        $is_not_correct = 1; 
                        $msg = "All values ​​are required!";
                    }else{
                        $getHash = $projectdb->query("SELECT name FROM edit_table WHERE type = 'crypto_authentication' AND lid = '$id' AND remove = '0' AND user_id = '$user_id' ORDER BY ids ASC;");
                        if($getHash->num_rows > 0){
                            while($dataH = $getHash->fetch_assoc()){
                                $hash_array[] = $dataH['name'];
                            }
                        }
                    }
                }

                if($combo_lifetime == "Seconds"){
                    $minutes = 0;
                    $hours = 0;
                    $days = 0;
                    if(($seconds < 180) || ($seconds > 65535)){
                        $is_not_correct = 1;
                        $msg = "The values of Key Lifetime ​​are not correct!";
                    }
                }elseif($combo_lifetime == "Minutes"){
                    $seconds = 0;
                    $hours = 0;
                    $days = 0;
                    if(($minutes < 3) || ($minutes > 65535)){
                        $is_not_correct = 1;
                        $msg = "The values of Key Lifetime ​​are not correct!";
                    }
                }elseif($combo_lifetime == "Hours"){
                    $seconds = 0;
                    $minutes = 0;
                    $days = 0;
                    if(($hours < 1) || ($hours > 65535)){
                        $is_not_correct = 1;
                        $msg = "The values of Key Lifetime ​​are not correct!";
                    }
                }elseif($combo_lifetime == "Days"){
                    $seconds = 0;
                    $minutes = 0;
                    $hours = 0;
                    if(($days < 1) || ($days > 65535)){
                        $is_not_correct = 1;
                        $msg = "The values of Key Lifetime ​​are not correct!";
                    }
                }else{
                    $seconds = 0;
                    $minutes = 0;
                    $hours = 1;
                    $days = 0;
                }
                
                if($is_enable_lifesize == "on"){
                    if($combo_lifesize == "KB"){
                        $mb = 0;
                        $gb = 0;
                        $tb = 0;
                        if(($kb < 1) || ($kb > 65535)){
                            $is_not_correct = 1;
                            $msg = "The values of Key Lifesize ​​are not correct!";
                        }
                    }elseif($combo_lifesize == "MB"){
                        $kb = 0;
                        $gb = 0;
                        $tb = 0;
                        if(($mb < 1) || ($mb > 65535)){
                            $is_not_correct = 1;
                            $msg = "The values of Key Lifesize ​​are not correct!";
                        }
                    }elseif($combo_lifesize == "GB"){
                        $kb = 0;
                        $mb = 0;
                        $tb = 0;
                        if(($gb < 1) || ($gb > 65535)){
                            $is_not_correct = 1;
                            $msg = "The values of Key Lifesize ​​are not correct!";
                        }
                    }elseif($combo_lifesize == "TB"){
                        $kb = 0;
                        $mb = 0;
                        $gb = 0;
                        if(($tb < 1) || ($tb > 65535)){
                            $is_not_correct = 1;
                            $msg = "The values of Key Lifesize ​​are not correct!";
                        }
                    }
                }
                else{
                    $kb = 0;
                    $mb = 0;
                    $gb = 0;
                    $tb = 0;
                }
                
                if($is_not_correct == 1){
                    if ($is_new == 1){
                        $projectdb->query("DELETE FROM ipsec_crypto_profiles WHERE id = '$id';");
                    }
                    echo json_encode(array("success"=>false, "msg"=>$msg));
                }else{
                    
                    $getNameOld = $projectdb->query("SELECT name FROM ipsec_crypto_profiles WHERE id = '$id';");
                    if($getNameOld->num_rows > 0){
                        $dataNO = $getNameOld->fetch_assoc();
                        $name_old = $dataNO['name'];
                        if($name_old != ""){
                            $projectdb->query("UPDATE ipsec_tunnel SET ipsec_crypto_profile = '$name' WHERE source = '$source' AND template = '$template' AND ipsec_crypto_profile = '$name_old' ;");
                        }
                    }
                    $projectdb->query("UPDATE ipsec_crypto_profiles SET name = '$name', encryption = '".implode(",", $encryption_array)."', hash = '".implode(",", $hash_array)."', dh_group = '$dh_group', protocol = '$protocol', seconds = '$seconds', minutes = '$minutes', hours = '$hours', days = '$days', kb = '$kb', mb = '$mb', gb = '$gb', tb = '$tb' WHERE id = '$id';");
                    echo json_encode(array("success"=>true));
                }
                
            }
            else{
                if ($is_new == 1){
                    $projectdb->query("DELETE FROM ipsec_crypto_profiles WHERE id = '$id';");
                }
                echo json_encode(array("success"=>false, "msg"=>"The name already exist!"));
            }
        }
        else{
            echo json_encode(array("success"=>false));
        }
        
    }
    elseif ($type == "global_protect_ipsec_crypto"){
        
        take_snapshot_last($project);
        
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $id = $projectdb->real_escape_string((string) (isset($_POST['idx']) ? $_POST['idx'] : $_GET['idx']));
        $template = $projectdb->real_escape_string((string) (isset($_POST['template']) ? $_POST['template'] : $_GET['template']));
        $name = $projectdb->real_escape_string((string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']));
        
        $is_new = 0;
        
        if ($name != ""){
            
            if($id == ""){
                $projectdb->query("INSERT INTO global_protect_app_ipsec_crypto_profiles (template, source) VALUES ('$template', '$source')");
                $id = $projectdb->insert_id; 
                $is_new = 1;
                $projectdb->query("UPDATE edit_table SET lid = '$id' WHERE user_id = '$user_id';");
            }
            
            $encryption_array = array();
            $hash_array = array();
            
            $is_not_correct = 0; 
            
            $getNameExist = $projectdb->query("SELECT id FROM global_protect_app_ipsec_crypto_profiles WHERE BINARY name = '$name' AND id != '$id' AND template = '$template' AND source = '$source';");
            if($getNameExist->num_rows == 0){
                
                $getCorrect = $projectdb->query("SELECT DISTINCT(type) FROM edit_table WHERE remove = '0' AND lid = '$id' AND remove = '0' AND user_id = '$user_id';");
                if($getCorrect->num_rows != 2){
                    $is_not_correct = 1; 
                    $msg = "All values ​​are required!";
                }else{
                    $getEncryption = $projectdb->query("SELECT name FROM edit_table WHERE type = 'crypto_encryption' AND lid = '$id' AND remove = '0' AND user_id = '$user_id' ORDER BY ids ASC;");
                    if($getEncryption->num_rows > 0){
                        while($dataE = $getEncryption->fetch_assoc()){
                            $encryption_array[] = $dataE['name'];
                        }
                    }

                    $getHash = $projectdb->query("SELECT name FROM edit_table WHERE type = 'crypto_authentication' AND lid = '$id' AND remove = '0' AND user_id = '$user_id' ORDER BY ids ASC;");
                    if($getHash->num_rows > 0){
                        while($dataH = $getHash->fetch_assoc()){
                            $hash_array[] = $dataH['name'];
                        }
                    }
                }
                
                if($is_not_correct == 1){
                    if ($is_new == 1){
                        $projectdb->query("DELETE FROM global_protect_app_ipsec_crypto_profiles WHERE id = '$id';");
                    }
                    echo json_encode(array("success"=>false, "msg"=>$msg));
                }else{
                    $projectdb->query("UPDATE global_protect_app_ipsec_crypto_profiles SET name = '$name', encryption = '".implode(",", $encryption_array)."', hash = '".implode(",", $hash_array)."' WHERE id = '$id';");
                    echo json_encode(array("success"=>true));
                } 
            }
            else{
                if ($is_new == 1){
                    $projectdb->query("DELETE FROM global_protect_app_ipsec_crypto_profiles WHERE id = '$id';");
                }
                echo json_encode(array("success"=>false, "msg"=>"The name already exist!"));
            }
        }
        else{
            echo json_encode(array("success"=>false));
        }
        
    }
    elseif ($type == "ike_gateways"){
        
        take_snapshot_last($project);
        
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $id = $projectdb->real_escape_string((string) (isset($_POST['idx']) ? $_POST['idx'] : $_GET['idx']));
        $template = $projectdb->real_escape_string((string) (isset($_POST['template']) ? $_POST['template'] : $_GET['template']));
        $name = $projectdb->real_escape_string((string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']));
        $version = $projectdb->real_escape_string((string) (isset($_POST['version']) ? $_POST['version'] : $_GET['version']));
        $address_type = $projectdb->real_escape_string((string) (isset($_POST['address_type']) ? $_POST['address_type'] : $_GET['address_type']));
        
        $allow_id_payload_mismatch = $projectdb->real_escape_string((string) (isset($_POST['allow_id_payload_mismatch']) ? $_POST['allow_id_payload_mismatch'] : ""));
        $certificate_profile = $projectdb->real_escape_string((string) (isset($_POST['certificate_profile']) ? $_POST['certificate_profile'] : $_GET['certificate_profile']));
        $confirm_pre_shared_key = $projectdb->real_escape_string((string) (isset($_POST['confirm_pre_shared_key']) ? $_POST['confirm_pre_shared_key'] : $_GET['confirm_pre_shared_key']));
        $exchange_mode_ikev1 = $projectdb->real_escape_string((string) (isset($_POST['exchange_mode_ikev1']) ? $_POST['exchange_mode_ikev1'] : $_GET['exchange_mode_ikev1']));
        $fragmentation = $projectdb->real_escape_string((string) (isset($_POST['fragmentation']) ? $_POST['fragmentation'] : ""));
        $base_url = $projectdb->real_escape_string((string) (isset($_POST['base_url']) ? $_POST['base_url'] : $_GET['base_url']));
        $is_enable_http_certificate = $projectdb->real_escape_string((string) (isset($_POST['is_enable_http_certificate']) ? $_POST['is_enable_http_certificate'] : ""));
        
        $ike_crypto_profile_ikev1 = $projectdb->real_escape_string((string) (isset($_POST['ike_crypto_profile_ikev1']) ? $_POST['ike_crypto_profile_ikev1'] : $_GET['ike_crypto_profile_ikev1']));
        $ike_crypto_profile_ikev2 = $projectdb->real_escape_string((string) (isset($_POST['ike_crypto_profile_ikev2']) ? $_POST['ike_crypto_profile_ikev2'] : $_GET['ike_crypto_profile_ikev2']));
        $ike_interval_ikev1 = $projectdb->real_escape_string((string) (isset($_POST['ike_interval_ikev1']) ? $_POST['ike_interval_ikev1'] : $_GET['ike_interval_ikev1']));
        $ike_interval_ikev2 = $projectdb->real_escape_string((string) (isset($_POST['ike_interval_ikev2']) ? $_POST['ike_interval_ikev2'] : $_GET['ike_interval_ikev2']));
        
        $interface = $projectdb->real_escape_string((string) (isset($_POST['interface']) ? $_POST['interface'] : $_GET['interface']));
        $is_enable_dpd_ikev1 = $projectdb->real_escape_string((string) (isset($_POST['is_enable_dpd_IKE-checkbox']) ? $_POST['is_enable_dpd_IKE-checkbox'] : ""));
        //$is_enable_dpd_ikev2 = (string) (isset($_POST['is_enable_dpd_ikev2']) ? $_POST['is_enable_dpd_ikev2'] : "");
        $is_enable_dpd_ikev2 = $projectdb->real_escape_string((string) (isset($_POST['is_liveness_check_IKE-checkbox']) ? $_POST['is_liveness_check_IKE-checkbox'] : ""));
        
        $require_cookie_ikev2 = $projectdb->real_escape_string((string) (isset($_POST['require_cookie_ikev2']) ? $_POST['require_cookie_ikev2'] : ""));
        
        $local_address_ip = $projectdb->real_escape_string((string) (isset($_POST['local_address_ip']) ? $_POST['local_address_ip'] : $_GET['local_address_ip']));
        $local_certificate = $projectdb->real_escape_string((string) (isset($_POST['local_certificate']) ? $_POST['local_certificate'] : $_GET['local_certificate']));
        $local_id = $projectdb->real_escape_string((string) (isset($_POST['local_id']) ? $_POST['local_id'] : $_GET['local_id']));
        $local_id_type = $projectdb->real_escape_string((string) (isset($_POST['local_id_type']) ? $_POST['local_id_type'] : $_GET['local_id_type']));
        $nat_traversal = $projectdb->real_escape_string((string) (isset($_POST['nat_traversal']) ? $_POST['nat_traversal'] : ""));
        
        $passive_mode = $projectdb->real_escape_string((string) (isset($_POST['passive_mode']) ? $_POST['passive_mode'] : ""));
        
        $peer_id = $projectdb->real_escape_string((string) (isset($_POST['peer_id']) ? $_POST['peer_id'] : $_GET['peer_id']));
        $peer_id_matching = $projectdb->real_escape_string((string) (isset($_POST['peer_id_matching']) ? $_POST['peer_id_matching'] : ""));
        $peer_id_type = $projectdb->real_escape_string((string) (isset($_POST['peer_id_type']) ? $_POST['peer_id_type'] : $_GET['peer_id_type']));
        $peer_ip_address = $projectdb->real_escape_string((string) (isset($_POST['peer_ip_address']) ? $_POST['peer_ip_address'] : $_GET['peer_ip_address']));
        $peer_ip_type = $projectdb->real_escape_string((string) (isset($_POST['peer_ip_type']) ? $_POST['peer_ip_type'] : $_GET['peer_ip_type']));
        $pre_shared_key = $projectdb->real_escape_string((string) (isset($_POST['pre_shared_key']) ? $_POST['pre_shared_key'] : $_GET['pre_shared_key']));
        $retry_ikev1 = $projectdb->real_escape_string((string) (isset($_POST['retry_ikev1']) ? $_POST['retry_ikev1'] : $_GET['retry_ikev1']));
        $strict_validation_revocation = $projectdb->real_escape_string((string) (isset($_POST['strict_validation_revocation']) ? $_POST['strict_validation_revocation'] : ""));
        $type_authentication = $projectdb->real_escape_string((string) (isset($_POST['type_authentication']) ? $_POST['type_authentication'] : $_GET['type_authentication']));
        
        $is_new = 0;
        
        if ($name != ""){
            
            if($id == ""){
                $projectdb->query("INSERT INTO ike_gateways_profiles (template, source, version, dpd_ikev1, ike_interval_ikev1, retry_ikev1, exchange_mode_ikev1, ike_crypto_profile_ikev1, dpd_ikev2, ike_interval_ikev2, ike_crypto_profile_ikev2, peer_ip_type, type_authentication, address_type) "
                        . "VALUES ('$template', '$source', 'ikev1', 'yes', '5', '5', 'auto', 'default', 'yes', '5', 'default', 'static', 'pre-shared-key', 'ipv4')");
                $id = $projectdb->insert_id; 
                $is_new = 1;
                $projectdb->query("UPDATE edit_table SET lid = '$id' WHERE user_id = '$user_id';");
            }
            
            $encryption_array = array();
            $hash_array = array();
            
            $getNameExist = $projectdb->query("SELECT id FROM ike_gateways_profiles WHERE BINARY name = '$name' AND id != '$id' AND template = '$template' AND source = '$source';");
            if($getNameExist->num_rows == 0){
                
                $is_not_correct = 0; 
                
                if($nat_traversal == "on"){$nat_traversal = "yes";}else{$nat_traversal = "no";}
                if($passive_mode == "on"){$passive_mode = "yes";}
                if($fragmentation == "on"){$fragmentation = "yes";}else{$fragmentation = "no";}
                if($allow_id_payload_mismatch == "on"){$allow_id_payload_mismatch = "yes";}
                if($strict_validation_revocation == "on"){$strict_validation_revocation = "yes";}
                if($is_enable_dpd_ikev1 == "on"){$is_enable_dpd_ikev1 = "yes";}
                if($is_enable_dpd_ikev2 == "on"){$is_enable_dpd_ikev2 = "yes";}
                if($is_enable_http_certificate == "on"){$is_enable_http_certificate = "yes";}
                if($require_cookie_ikev2 == "on"){$require_cookie_ikev2 = "yes";}
                
                if($peer_ip_type == "static"){
                    if($peer_ip_address == ""){
                        $is_not_correct = 1;
                        $msg = "The value Peer IP Address are required!";
                    }
                }
                
                if($interface == ""){
                    if($peer_ip_address == ""){
                        $is_not_correct = 1;
                        $msg = "The value Peer IP Address are required!";
                    }
                }
                
                if($type_authentication == "pre-shared-key"){
                    if(($pre_shared_key == "") || ($confirm_pre_shared_key == "")){
                        $is_not_correct = 1;
                        $msg = "The value Pre-shared Key are required!";
                    }
                }
                else{
                    if(($local_certificate == "") || ($certificate_profile == "")){
                        $is_not_correct = 1;
                        $msg = "The values Local Certificate and Cerfificate Profile are required!";
                    }
                    if($peer_id == ""){
                        $is_not_correct = 1;
                        $msg = "The values are required!";
                    }
                }
                
                if($is_not_correct == 1){
                    if ($is_new == 1){
                        $projectdb->query("DELETE FROM ike_gateways_profiles WHERE id = '$id';");
                    }
                    echo json_encode(array("success"=>false, "msg"=>$msg));
                }else{
                    
                    $getNameOld = $projectdb->query("SELECT name FROM ike_gateways_profiles WHERE id = '$id';");
                    if($getNameOld->num_rows > 0){
                        $dataNO = $getNameOld->fetch_assoc();
                        $name_old = $dataNO['name'];
                        if($name_old != ""){
                            $projectdb->query("UPDATE ipsec_tunnel SET ike_gateway = '$name' WHERE source = '$source' AND template = '$template' AND ike_gateway = '$name_old' ;");
                        }
                    }
                    
                    $projectdb->query("UPDATE ike_gateways_profiles SET name = '$name', version = '$version', dpd_ikev1 = '$is_enable_dpd_ikev1', ike_interval_ikev1 = '$ike_interval_ikev1', retry_ikev1 = '$retry_ikev1', ike_crypto_profile_ikev1 = '$ike_crypto_profile_ikev1', exchange_mode_ikev1 = '$exchange_mode_ikev1', dpd_ikev2 = '$is_enable_dpd_ikev2', ike_interval_ikev2 = '$ike_interval_ikev2', require_cookie_ikev2 = '$require_cookie_ikev2', ike_crypto_profile_ikev2 = '$ike_crypto_profile_ikev2', local_address_ip = '$local_address_ip', interface = '$interface', type_authentication = '$type_authentication', pre_shared_key = '$pre_shared_key', allow_id_payload_mismatch = '$allow_id_payload_mismatch', certificate_profile = '$certificate_profile', strict_validation_revocation = '$strict_validation_revocation', hash_and_url = '$is_enable_http_certificate', base_url = '$base_url', local_certificate = '$local_certificate', nat_traversal = '$nat_traversal', passive_mode = '$passive_mode', fragmentation = '$fragmentation', peer_ip_type = '$peer_ip_type', peer_ip_address = '$peer_ip_address', local_id = '$local_id', local_id_type = '$local_id_type', peer_id = '$peer_id', peer_id_type = '$peer_id_type', peer_id_matching = '$peer_id_matching', address_type = '$address_type'  WHERE id = '$id';");
                    echo json_encode(array("success"=>true));
                }
                
            }
            else{
                if ($is_new == 1){
                    $projectdb->query("DELETE FROM ike_gateways_profiles WHERE id = '$id';");
                }
                echo json_encode(array("success"=>false, "msg"=>"The name already exist!"));
            }
        }
        else{
            echo json_encode(array("success"=>false));
        }
        
    }
    elseif ($type == "ipsec_tunnel"){
        
        take_snapshot_last($project);
        
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $id = $projectdb->real_escape_string((string) (isset($_POST['idx']) ? $_POST['idx'] : $_GET['idx']));
        $template = $projectdb->real_escape_string((string) (isset($_POST['template']) ? $_POST['template'] : $_GET['template']));
        $name = $projectdb->real_escape_string((string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']));
        $address_type = $projectdb->real_escape_string((string) (isset($_POST['address_type']) ? $_POST['address_type'] : ""));
        
        $anti_replay = $projectdb->real_escape_string((string) (isset($_POST['anti_replay']) ? $_POST['anti_replay'] : ""));
        $authentication = $projectdb->real_escape_string((string) (isset($_POST['authentication']) ? $_POST['authentication'] : $_GET['authentication']));
        $certificate_profile = $projectdb->real_escape_string((string) (isset($_POST['certificate_profile']) ? $_POST['certificate_profile'] : $_GET['certificate_profile']));
        $copy_tos = $projectdb->real_escape_string((string) (isset($_POST['copy_tos']) ? $_POST['copy_tos'] : ""));
        $destination_ip = $projectdb->real_escape_string((string) (isset($_POST['destination_ip']) ? $_POST['destination_ip'] : $_GET['destination_ip']));
        $encryption = $projectdb->real_escape_string((string) (isset($_POST['encryption']) ? $_POST['encryption'] : $_GET['encryption']));
        $ike_gateway = $projectdb->real_escape_string((string) (isset($_POST['ike_gateway']) ? $_POST['ike_gateway'] : $_GET['ike_gateway']));
        $external_ca = $projectdb->real_escape_string((string) (isset($_POST['external_ca']) ? $_POST['external_ca'] : ""));
        
        $interface = $projectdb->real_escape_string((string) (isset($_POST['interface']) ? $_POST['interface'] : $_GET['interface']));
        $interface2 = $projectdb->real_escape_string((string) (isset($_POST['interface2']) ? $_POST['interface2'] : $_GET['interface2']));
        $ipsec_crypto_profile = $projectdb->real_escape_string((string) (isset($_POST['ipsec_crypto_profile']) ? $_POST['ipsec_crypto_profile'] : $_GET['ipsec_crypto_profile']));
        $is_enable_show_advanced = $projectdb->real_escape_string((string) (isset($_POST['is_enable_show_advanced_options-checkbox']) ? $_POST['is_enable_show_advanced_options-checkbox'] : ""));
        
        $is_enable_tunnel_monitor = $projectdb->real_escape_string((string) (isset($_POST['is_enable_tunnel_monitor-checkbox']) ? $_POST['is_enable_tunnel_monitor-checkbox'] : ""));
        $key_auth = $projectdb->real_escape_string((string) (isset($_POST['key_auth']) ? $_POST['key_auth'] : $_GET['key_auth']));
        $key_auth_confirm = $projectdb->real_escape_string((string) (isset($_POST['key_auth_confirm']) ? $_POST['key_auth_confirm'] : $_GET['key_auth_confirm']));
        $key_encry = $projectdb->real_escape_string((string) (isset($_POST['key_encry']) ? $_POST['key_encry'] : $_GET['key_encry']));
        
        $key_encry_confirm = $projectdb->real_escape_string((string) (isset($_POST['key_encry_confirm']) ? $_POST['key_encry_confirm'] : $_GET['key_encry_confirm']));
        $local_address_ip = $projectdb->real_escape_string((string) (isset($_POST['local_address_ip']) ? $_POST['local_address_ip'] : $_GET['local_address_ip']));
        $local_address_ip2 = $projectdb->real_escape_string((string) (isset($_POST['local_address_ip2']) ? $_POST['local_address_ip2'] : $_GET['local_address_ip2']));
        $local_certificate = $projectdb->real_escape_string((string) (isset($_POST['local_certificate']) ? $_POST['local_certificate'] : $_GET['local_certificate']));
        $local_spi = $projectdb->real_escape_string((string) (isset($_POST['local_spi']) ? $_POST['local_spi'] : $_GET['local_spi']));
        
        $peer_ip_address = $projectdb->real_escape_string((string) (isset($_POST['peer_ip_address']) ? $_POST['peer_ip_address'] : $_GET['peer_ip_address']));
        
        $portal_address = $projectdb->real_escape_string((string) (isset($_POST['portal_address']) ? $_POST['portal_address'] : $_GET['portal_address']));
        $protocol = $projectdb->real_escape_string((string) (isset($_POST['protocol']) ? $_POST['protocol'] : $_GET['protocol']));
        $remote_spi = $projectdb->real_escape_string((string) (isset($_POST['remote_spi']) ? $_POST['remote_spi'] : $_GET['remote_spi']));
        $tunnel_interface = $projectdb->real_escape_string((string) (isset($_POST['tunnel_interface']) ? $_POST['tunnel_interface'] : $_GET['tunnel_interface']));
        $tunnel_monitor_profile = $projectdb->real_escape_string((string) (isset($_POST['tunnel_monitor_profile']) ? $_POST['tunnel_monitor_profile'] : $_GET['tunnel_monitor_profile']));
        $type_tunnel = $projectdb->real_escape_string((string) (isset($_POST['type_tunnel']) ? $_POST['type_tunnel'] : $_GET['type_tunnel']));
        $publish_connected_routes = $projectdb->real_escape_string((string) (isset($_POST['publish_connected_routes']) ? $_POST['publish_connected_routes'] : ""));
        
        $is_new = 0;
        
        if ($name != ""){
            
            if($id == ""){
                $projectdb->query("INSERT INTO ipsec_tunnel (template, source, type_tunnel, ipsec_crypto_profile, protocol, authentication, encryption, tunnel_monitor_profile, certificate_profile, local_certificate, address_type) "
                        . "VALUES ('$template', '$source', 'auto-key', 'default', 'ESP', 'none', 'null', 'None', 'None', 'None', 'ipv4')");
                $id = $projectdb->insert_id; 
                $is_new = 1;
                $projectdb->query("UPDATE edit_table SET lid = '$id' WHERE user_id = '$user_id';");
            }
            
            $getNameExist = $projectdb->query("SELECT id FROM ipsec_tunnel WHERE BINARY name = '$name' AND id != '$id' AND template = '$template' AND source = '$source';");
            if ($getNameExist->num_rows == 0){
                
                $is_not_correct = 0; 
                
                if ($copy_tos == "on"){$copy_tos = "yes";}else{$copy_tos = "";}
                if ($anti_replay == "on"){$anti_replay = "yes";}else{$anti_replay = "";}
                if ($publish_connected_routes == "on"){$publish_connected_routes = "yes";}else{$publish_connected_routes = "";}
                if ($external_ca == "on"){$external_ca = "yes";}else{$external_ca = "";}
                
                if ($type_tunnel == "auto-key"){
                    
                    $local_spi = "";
                    $remote_spi = "";
                    $encryption = "";
                    $authentication = "";
                    $protocol = "";
                    $local_certificate = "";
                    $certificate_profile = "";
                    
                    if ($ike_gateway == ""){
                        $is_not_correct = 1;
                        $msg = "The value IKE Gateway are required!";
                    }
                    
                    if ($tunnel_interface == ""){
                        $is_not_correct = 1;
                        $msg = "The value Tunnel Interface are required!";
                    }
                    
                    if ($is_enable_tunnel_monitor == "on"){
                        if ($destination_ip == ""){
                            $is_not_correct = 1;
                            $msg = "The value Destination IP are required!";
                        }else{
                            $tunnel_monitor = "on";
                        }
                    }
                    else{
                        $destination_ip = "";
                        $tunnel_monitor_profile = "";
                        $tunnel_monitor = "";
                    }
                    
                    if ($is_enable_show_advanced != "on"){
                        $copy_tos = "";
                        $anti_replay = "";
                    }
                    
                }
                elseif ($type_tunnel == "manual-key"){
                 
                    $local_certificate = "";
                    $certificate_profile = "";
                    
                    $destination_ip = "";
                    $tunnel_monitor_profile = "";
                    $tunnel_monitor = "";
                        
                    if ($tunnel_interface == ""){
                        $is_not_correct = 1;
                        $msg = "The value Tunnel Interface are required!";
                    }
                    
                    if (($local_spi == "00001000 - 1FFFFFFF") || ($local_spi == "")){
                        $is_not_correct = 1;
                        $msg = "The value Local SPI are required!";
                    }
                    
                    if (($remote_spi == "00000000 - FFFFFFFF") || ($remote_spi == "")){
                        $is_not_correct = 1;
                        $msg = "The value Remote SPI are required!";
                    }
                    
                    if ($peer_ip_address == ""){
                        $is_not_correct = 1;
                        $msg = "The value Remote Address are required!";
                    }
                    
                    if ($authentication != "none"){
                        if (($key_auth == "") || ($key_auth_confirm == "")){
                            $is_not_correct = 1;
                            $msg = "The value Key Authentication are required!";
                        }
                    }
                    
                    if ($encryption != "null"){
                        if (($key_encry == "") || ($key_encry_confirm == "")){
                            $is_not_correct = 1;
                            $msg = "The value Key Encryption are required!";
                        }
                    }
                    
                    if ($interface == ""){
                        $is_not_correct = 1;
                        $msg = "The value Interface are required!";
                    }
                    
                }
                elseif ($type_tunnel == "global-protect-satellite"){
                    
                    $local_spi = "";
                    $remote_spi = "";
                    $encryption = "";
                    $authentication = "";
                    $protocol = "";
                    $destination_ip = "";
                    $tunnel_monitor_profile = "";
                    $tunnel_monitor = "";
                    
                    if ($tunnel_interface == ""){
                        $is_not_correct = 1;
                        $msg = "The value Tunnel Interface are required!";
                    }
                    
                    if ($portal_address == ""){
                        $is_not_correct = 1;
                        $msg = "The value Portal Address are required!";
                    }
                    
                    if ($interface2 == ""){
                        $is_not_correct = 1;
                        $msg = "The value Interface are required!";
                    }else{
                        $interface = $interface2;
                    }
                    
                    $local_address_ip = $local_address_ip2;
                    
                    if ($external_ca != "yes"){
                        $local_certificate = "";
                        $certificate_profile = "";
                    }
                }
                
                if($is_not_correct == 1){
                    if ($is_new == 1){
                        $projectdb->query("DELETE FROM ipsec_tunnel WHERE id = '$id';");
                    }
                    echo json_encode(array("success"=>false, "msg"=>$msg));
                }
                else{
                        
                    $projectdb->query("UPDATE ipsec_tunnel SET name = '$name', anti_replay = '$anti_replay', copy_tos = '$copy_tos', tunnel_monitor = '$tunnel_monitor', destination_ip = '$destination_ip', tunnel_monitor_profile = '$tunnel_monitor_profile', tunnel_interface = '$tunnel_interface', address_type = '$address_type', type_tunnel = '$type_tunnel', ike_gateway = '$ike_gateway', ipsec_crypto_profile = '$ipsec_crypto_profile', protocol = '$protocol', authentication = '$authentication', encryption = '$encryption', local_address_ip = '$local_address_ip', interface = '$interface', peer_ip_address = '$peer_ip_address', local_spi = '$local_spi', remote_spi = '$remote_spi', external_ca = '$external_ca', certificate_profile = '$certificate_profile', local_certificate = '$local_certificate', publish_connected_routes = '$publish_connected_routes', portal_address = '$portal_address' WHERE id = '$id';");

                    //Update proxy_id with new id
                    $projectdb->query("UPDATE proxy_id_ipsec_tunnel SET ipsec_tunnel_id = '$id' WHERE template = '$template' AND source = '$source' AND ipsec_tunnel_id = '0';");

                    echo json_encode(array("success"=>true));
                }
                
            }
            else{
                if ($is_new == 1){
                    $projectdb->query("DELETE FROM ipsec_tunnel WHERE id = '$id';");
                }
                echo json_encode(array("success"=>false, "msg"=>"The name already exist!"));
            }
        }
        else{
            echo json_encode(array("success"=>false));
        }
        
    }
    elseif ($type == "proxy_id"){
        
        $id = $projectdb->real_escape_string((string) (isset($_POST['id']) ? $_POST['id'] : $_GET['id']));
        $name = $projectdb->real_escape_string((string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']));
        $type_v = $projectdb->real_escape_string((string) (isset($_POST['type_v']) ? $_POST['type_v'] : $_GET['type_v']));
        $ipsec_tunnel_id = $projectdb->real_escape_string((string) (isset($_POST['ipsec_tunnel_id']) ? $_POST['ipsec_tunnel_id'] : $_GET['ipsec_tunnel_id']));
        $local = $projectdb->real_escape_string((string) (isset($_POST['local']) ? $_POST['local'] : $_GET['local']));
        $local_port = $projectdb->real_escape_string((string) (isset($_POST['local_port']) ? $_POST['local_port'] : $_GET['local_port']));
        $number = $projectdb->real_escape_string((string) (isset($_POST['number']) ? $_POST['number'] : $_GET['number']));
        $protocol = $projectdb->real_escape_string((string) (isset($_POST['protocol']) ? $_POST['protocol'] : $_GET['protocol']));
        $remote = $projectdb->real_escape_string((string) (isset($_POST['remote']) ? $_POST['remote'] : $_GET['remote']));
        $remote_port = $projectdb->real_escape_string((string) (isset($_POST['remote_port']) ? $_POST['remote_port'] : $_GET['remote_port']));
	
        take_snapshot_last($project);
        
        if ($id != ""){
            
            $name = str_replace(' ', '', $name);
            
            $projectdb->query("UPDATE proxy_id_ipsec_tunnel SET name = '$name', type = '$type_v', ipsec_tunnel_id = '$ipsec_tunnel_id', local = '$local', remote = '$remote', number = '$number', protocol = '$protocol', local_port = '$local_port', remote_port = '$remote_port' WHERE id = '$id';");
            echo json_encode(array("success"=>true));
            
        }
        
    }
    elseif ($type == "subnet"){
        
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $idx = $projectdb->real_escape_string((string) (isset($_POST['idx']) ? $_POST['idx'] : $_GET['idx']));
        $template = $projectdb->real_escape_string((string) (isset($_POST['template']) ? $_POST['template'] : $_GET['template']));
        $table_name = $projectdb->real_escape_string((string) (isset($_POST['table_name']) ? $_POST['table_name'] : $_GET['table_name']));
        $ids = $projectdb->real_escape_string((string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']));
        $name = $projectdb->real_escape_string((string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']));
        $oldname = $projectdb->real_escape_string((string) (isset($_POST['oldname']) ? $_POST['oldname'] : $_GET['oldname']));
        
        take_snapshot_last($project);
        
        $getAddress = $projectdb->query("SELECT publish_routes FROM ipsec_tunnel WHERE id = '$idx';");
        if ($getAddress->num_rows == 1) {
            $dataA = $getAddress->fetch_assoc();
            $publish_routes = $dataA['publish_routes'];
            $add_array = explode(",", $publish_routes);
            if (in_array($name, $add_array)) {
                
            } else {
                $replace = str_replace($oldname, $name, $publish_routes);
                $projectdb->query("UPDATE ipsec_tunnel SET publish_routes = '$replace' WHERE id = '$idx';");
            }
        }

        echo json_encode(array("success" => true));
        
    }
    
}
elseif ($action == "remove"){
    
    if($type == "monitor"){

        $ids = $projectdb->real_escape_string((string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']));
        $remove_references = $projectdb->real_escape_string((string) (isset($_POST['remove_references']) ? $_POST['remove_references'] : $_GET['remove_references']));

        take_snapshot_last($project);

        $msg = "";
        $are_references = 0;
        $id_not_references = array();
                
        $getName = $projectdb->query("SELECT id, name, template FROM monitor_profile WHERE id IN ($ids);");
        if($getName->num_rows > 0){
            while($dataN = $getName->fetch_assoc()){
                $name_principal = $dataN['name'];
                $id_principal = $dataN['id'];
                $template = $dataN['template'];
                $total_name_tunnel = array();
                $total_name_tunnel2 = array();
            
                $getReferences = $projectdb->query("SELECT id, name FROM ipsec_tunnel WHERE tunnel_monitor_profile = '$name_principal' AND source = '$source' AND template = '$template';");
                if($getReferences->num_rows > 0){
                    $are_references = 1;
                    while($dataR = $getReferences->fetch_assoc()){
                        $id_tunnel = $dataR['id'];
                        $name_tunnel = $dataR['name'];
                        $total_name_tunnel[] = $dataR['name'];
                    }
                    
                    $msg .= "The Monitor Profile [$name_principal] is being used by IPSec Tunnels [".implode(",", $total_name_tunnel)."].<br>";

                    $getReferences = $projectdb->query("SELECT id, name FROM pbf_rules WHERE monitor_profile = '$name_principal' AND source = '$source';");
                    if($getReferences->num_rows > 0){
                        $are_references = 1;
                        while($dataR = $getReferences->fetch_assoc()){
                            $id_tunnel = $dataR['id'];
                            $name_tunnel = $dataR['name'];
                            $total_name_tunnel2[] = $dataR['name'];
                        }
                        $msg .= "The Monitor Profile [$name_principal] is being used by PBF Rules [".implode(",", $total_name_tunnel2)."].<br>";
                    }

                    if($remove_references == "yes"){
                        $projectdb->query("UPDATE ipsec_tunnel SET tunnel_monitor_profile = '' WHERE source = '$source' AND template = '$template' AND tunnel_monitor_profile = '$name_principal' ;");
                        $projectdb->query("UPDATE pbf_rules SET monitor_profile = '' WHERE source = '$source' AND monitor_profile = '$name_principal' ;");

                        $projectdb->query("DELETE FROM monitor_profile WHERE id = '$id_principal';");
                    }
                }
                else{

                    $getReferences = $projectdb->query("SELECT id, name FROM pbf_rules WHERE monitor_profile = '$name_principal' AND source = '$source';");
                    if($getReferences->num_rows > 0){
                        $are_references = 1;
                        while($dataR = $getReferences->fetch_assoc()){
                            $id_tunnel = $dataR['id'];
                            $name_tunnel = $dataR['name'];
                            $total_name_tunnel2[] = $dataR['name'];
                        }

                        $msg .= "The Monitor Profile [$name_principal] is being used by PBF Rules [".implode(",", $total_name_tunnel2)."].<br>";

                        if($remove_references == "yes"){
                            $projectdb->query("UPDATE ipsec_tunnel SET tunnel_monitor_profile = '' WHERE source = '$source' AND template = '$template' AND tunnel_monitor_profile = '$name_principal' ;");
                            $projectdb->query("UPDATE pbf_rules SET monitor_profile = '' WHERE source = '$source' AND monitor_profile = '$name_principal' ;");

                            $projectdb->query("DELETE FROM monitor_profile WHERE id = '$id_principal';");
                        }
                    }
                    else{
                        // Estos no tienen referencias, se pueden borrar
                        $id_not_references[] = $id_principal;
                    }
                }
            }
        }
        if($remove_references == "no"){
            if($are_references == 1){
                // Por si han seleccionado varios ids y alguno de éstos si que se pueden borrar directamente
                if(count($id_not_references) > 0){
                    take_snapshot_last($project);
                    $projectdb->query("DELETE FROM monitor_profile WHERE id IN (".implode(",", $id_not_references).");");
                }
                $msg = $msg . "<br>Do you really want to delete the Monitor Profile and all references?";
                echo json_encode(array("success"=>false, "msg"=>$msg));
            }
            else{
                take_snapshot_last($project);
                $projectdb->query("DELETE FROM monitor_profile WHERE id IN (".implode(",", $id_not_references).");");
                echo json_encode(array("success"=>true));
            }
        }
        else{
            echo json_encode(array("success"=>true));
        }
        
    }
    elseif ($type == "interface_mgmt"){
        
        $ids = $projectdb->real_escape_string((string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']));
        $remove_references = $projectdb->real_escape_string((string) (isset($_POST['remove_references']) ? $_POST['remove_references'] : $_GET['remove_references']));
        
        $msg = "";
        $are_references = 0;
        $id_not_references = array();
                
        $getName = $projectdb->query("SELECT id, name FROM interface_management_profile WHERE id IN ($ids);");
        if($getName->num_rows > 0){
            while($dataN = $getName->fetch_assoc()){
                $name_principal = $dataN['name'];
                $id_principal = $dataN['id'];
                $total_name_interfaces = array();
            
                if($name_principal != ""){
                    
                    $getReferences = $projectdb->query("SELECT id, name FROM interfaces WHERE interface_management_profile = '$name_principal' AND source = '$source' AND template = '$template';");
                    if($getReferences->num_rows > 0){
                        $are_references = 1;
                        while($dataR = $getReferences->fetch_assoc()){
                            $id_tunnel = $dataR['id'];
                            $name_tunnel = $dataR['name'];
                            $total_name_interfaces[] = $dataR['name'];
                        }

                        $msg .= "The Interface Mgmt [$name_principal] is being used by Interfaces [".implode(",", $total_name_interfaces)."].<br>";

                        if($remove_references == "yes"){
                            $projectdb->query("UPDATE interfaces SET interface_management_profile = '' WHERE source = '$source' AND template = '$template' AND interface_management_profile = '$name_principal' ;");
                            $projectdb->query("DELETE FROM interface_management_profile WHERE id = '$id_principal';");
                        }
                    }
                    else{
                        // Estos no tienen referencias, se pueden borrar
                        $id_not_references[] = $id_principal;
                    }
                    
                } // Name is empty
                else{
                    $projectdb->query("DELETE FROM interface_management_profile WHERE id = '$id_principal';");
                }
            }
        }
        if($remove_references == "no"){
            if($are_references == 1){
                // Por si han seleccionado varios ids y alguno de éstos si que se pueden borrar directamente
                if(count($id_not_references) > 0){
                    take_snapshot_last($project);
                    $projectdb->query("DELETE FROM interface_management_profile WHERE id IN (".implode(",", $id_not_references).");");
                }
                $msg = $msg . "<br>Do you really want to delete the Interface Mgmt and all references?";
                echo json_encode(array("success"=>false, "msg"=>$msg));
            }
            else{
                take_snapshot_last($project);
                $projectdb->query("DELETE FROM interface_management_profile WHERE id IN (".implode(",", $id_not_references).");");
                echo json_encode(array("success"=>true));
            }
        }
        else{
            echo json_encode(array("success"=>true));
        }
        
    }
    elseif ($type == "ike_crypto"){
        
        $ids = $projectdb->real_escape_string((string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']));
        $remove_references = $projectdb->real_escape_string((string) (isset($_POST['remove_references']) ? $_POST['remove_references'] : $_GET['remove_references']));
        
        $msg = "";
        $are_references = 0;
        $id_not_references = array();
                
        $getName = $projectdb->query("SELECT id, name FROM ike_crypto_profiles WHERE id IN ($ids);");
        if($getName->num_rows > 0){
            while($dataN = $getName->fetch_assoc()){
                $name_principal = $dataN['name'];
                $id_principal = $dataN['id'];
                $total_name_ike_gate = array();
            
                $getReferences = $projectdb->query("SELECT id, name FROM ike_gateways_profiles WHERE (ike_crypto_profile_ikev1 = '$name_principal' OR ike_crypto_profile_ikev2 = '$name_principal') AND source = '$source' AND template = '$template';");
                if($getReferences->num_rows > 0){
                    $are_references = 1;
                    while($dataR = $getReferences->fetch_assoc()){
                        $id_tunnel = $dataR['id'];
                        $name_tunnel = $dataR['name'];
                        $total_name_ike_gate[] = $dataR['name'];
                    }
                    
                    $msg .= "The IKE Crypto [$name_principal] is being used by IKE Gateways [".implode(",", $total_name_ike_gate)."].<br>";
                    
                    if($remove_references == "yes"){
                        $projectdb->query("UPDATE ike_gateways_profiles SET ike_crypto_profile_ikev1 = '' WHERE source = '$source' AND template = '$template' AND ike_crypto_profile_ikev1 = '$name_principal' ;");
                        $projectdb->query("UPDATE ike_gateways_profiles SET ike_crypto_profile_ikev2 = '' WHERE source = '$source' AND template = '$template' AND ike_crypto_profile_ikev2 = '$name_principal' ;");
                        $projectdb->query("DELETE FROM ike_crypto_profiles WHERE id = '$id_principal';");
                    }
                }
                else{
                    // Estos no tienen referencias, se pueden borrar
                    $id_not_references[] = $id_principal;
                }
            }
        }
        if($remove_references == "no"){
            if($are_references == 1){
                // Por si han seleccionado varios ids y alguno de éstos si que se pueden borrar directamente
                if(count($id_not_references) > 0){
                    take_snapshot_last($project);
                    $projectdb->query("DELETE FROM ike_crypto_profiles WHERE id IN (".implode(",", $id_not_references).");");
                }
                $msg = $msg . "<br>Do you really want to delete the IKE Crypto and all references?";
                echo json_encode(array("success"=>false, "msg"=>$msg));
            }
            else{
                take_snapshot_last($project);
                $projectdb->query("DELETE FROM ike_crypto_profiles WHERE id IN (".implode(",", $id_not_references).");");
                echo json_encode(array("success"=>true));
            }
        }
        else{
            echo json_encode(array("success"=>true));
        }
        
    }
    elseif ($type == "ipsec_crypto"){
        
        $ids = $projectdb->real_escape_string((string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']));
        $remove_references = $projectdb->real_escape_string((string) (isset($_POST['remove_references']) ? $_POST['remove_references'] : $_GET['remove_references']));
        
        $msg = "";
        $are_references = 0;
        $id_not_references = array();
                
        $getName = $projectdb->query("SELECT id, name FROM ipsec_crypto_profiles WHERE id IN ($ids);");
        if($getName->num_rows > 0){
            while($dataN = $getName->fetch_assoc()){
                $name_principal = $dataN['name'];
                $id_principal = $dataN['id'];
                $total_name_tunnel = array();
            
                $getReferences = $projectdb->query("SELECT id, name FROM ipsec_tunnel WHERE ipsec_crypto_profile = '$name_principal' AND source = '$source' AND template = '$template';");
                if($getReferences->num_rows > 0){
                    $are_references = 1;
                    while($dataR = $getReferences->fetch_assoc()){
                        $id_tunnel = $dataR['id'];
                        $name_tunnel = $dataR['name'];
                        $total_name_tunnel[] = $dataR['name'];
                    }
                    
                    $msg .= "The IPSec Crypto [$name_principal] is being used by IPSec Tunnels [".implode(",", $total_name_tunnel)."].<br>";
                    
                    if($remove_references == "yes"){
                        $projectdb->query("UPDATE ipsec_tunnel SET ipsec_crypto_profile = '' WHERE source = '$source' AND template = '$template' AND ipsec_crypto_profile = '$name_principal' ;");
                        $projectdb->query("DELETE FROM ipsec_crypto_profiles WHERE id = '$id_principal';");
                    }
                }
                else{
                    // Estos no tienen referencias, se pueden borrar
                    $id_not_references[] = $id_principal;
                }
            }
        }
        if($remove_references == "no"){
            if($are_references == 1){
                // Por si han seleccionado varios ids y alguno de éstos si que se pueden borrar directamente
                if(count($id_not_references) > 0){
                    take_snapshot_last($project);
                    $projectdb->query("DELETE FROM ipsec_crypto_profiles WHERE id IN (".implode(",", $id_not_references).");");
                }
                $msg = $msg . "<br>Do you really want to delete the IPSec Crypto and all references?";
                echo json_encode(array("success"=>false, "msg"=>$msg));
            }
            else{
                take_snapshot_last($project);
                $projectdb->query("DELETE FROM ipsec_crypto_profiles WHERE id IN (".implode(",", $id_not_references).");");
                echo json_encode(array("success"=>true));
            }
        }
        else{
            echo json_encode(array("success"=>true));
        }
    }
    elseif ($type == "global_protect_ipsec_crypto"){
        
        take_snapshot_last($project);
        
        $ids = $projectdb->real_escape_string((string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']));
        $projectdb->query("DELETE FROM global_protect_app_ipsec_crypto_profiles WHERE id IN ($ids);");
        
    }
    elseif ($type == "ike_gateways"){
        
        $ids = $projectdb->real_escape_string((string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']));
        $remove_references = $projectdb->real_escape_string((string) (isset($_POST['remove_references']) ? $_POST['remove_references'] : $_GET['remove_references']));
        
        $msg = "";
        $are_references = 0;
        $id_not_references = array();
                
        $getName = $projectdb->query("SELECT id, name FROM ike_gateways_profiles WHERE id IN ($ids);");
        if($getName->num_rows > 0){
            while($dataN = $getName->fetch_assoc()){
                $name_principal = $dataN['name'];
                $id_principal = $dataN['id'];
                $total_name_tunnel = array();
            
                if($name_principal != ""){
                
                    $getReferences = $projectdb->query("SELECT id, name FROM ipsec_tunnel WHERE ike_gateway = '$name_principal' AND source = '$source' AND template = '$template';");
                    if($getReferences->num_rows > 0){
                        $are_references = 1;
                        while($dataR = $getReferences->fetch_assoc()){
                            $id_tunnel = $dataR['id'];
                            $name_tunnel = $dataR['name'];
                            $total_name_tunnel[] = $dataR['name'];
                        }

                        $msg .= "The IKE Gateways [$name_principal] is being used by IPSec Tunnels [".implode(",", $total_name_tunnel)."].<br>";

                        if($remove_references == "yes"){
                            $projectdb->query("UPDATE ipsec_tunnel SET ike_gateway = '' WHERE source = '$source' AND template = '$template' AND ike_gateway = '$name_principal' ;");
                            $projectdb->query("DELETE FROM ike_gateways_profiles WHERE id = '$id_principal';");
                        }
                    }
                    else{
                        // Estos no tienen referencias, se pueden borrar
                        $id_not_references[] = $id_principal;
                    }
                    
                } // Name is empty
                else{
                    $projectdb->query("DELETE FROM ike_gateways_profiles WHERE id = '$id_principal';");
                }
            }
        }
        if($remove_references == "no"){
            if($are_references == 1){
                // Por si han seleccionado varios ids y alguno de éstos si que se pueden borrar directamente
                if(count($id_not_references) > 0){
                    take_snapshot_last($project);
                    $projectdb->query("DELETE FROM ike_gateways_profiles WHERE id IN (".implode(",", $id_not_references).");");
                }
                $msg = $msg . "<br>Do you really want to delete the IKE Gateways and all references?";
                echo json_encode(array("success"=>false, "msg"=>$msg));
            }
            else{
                take_snapshot_last($project);
                $projectdb->query("DELETE FROM ike_gateways_profiles WHERE id IN (".implode(",", $id_not_references).");");
                echo json_encode(array("success"=>true));
            }
        }
        else{
            echo json_encode(array("success"=>true));
        }
        
    }
    elseif ($type == "ipsec_tunnel"){
        
        take_snapshot_last($project);
        
        $ids = $projectdb->real_escape_string((string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']));
        $projectdb->query("DELETE FROM ipsec_tunnel WHERE id IN ($ids);");
        
    }
    elseif ($type == "proxy_id"){
        
        take_snapshot_last($project);
        
        $ids = $projectdb->real_escape_string((string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']));
        $projectdb->query("DELETE FROM proxy_id_ipsec_tunnel WHERE id IN ($ids);");
        
    }
    elseif ($type == "interface_mgmt_address"){
        
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $idx = $projectdb->real_escape_string((string) (isset($_POST['idx']) ? $_POST['idx'] : $_GET['idx']));
        $changes = $projectdb->real_escape_string((string) (isset($_POST['changes']) ? $_POST['changes'] : $_GET['changes']));
        
        $data = explode(",", $changes);
        
        if ($changes != "") {
            $data = explode(",", $changes);
            foreach ($data as $key => $value) {
                $projectdb->query("UPDATE edit_table SET remove = '1' WHERE name = '$value' AND lid = '$idx' AND type = 'permitted_ip' AND user_id = '$user_id';");
            }
        }
        echo json_encode(array("success" => true));
    }
    elseif ($type == "edit_table"){
        
        $projectdb->query("DELETE FROM edit_table WHERE user_id = '$user_id';");
        $getDeleteVR = $projectdb->query("DELETE FROM proxy_id_ipsec_tunnel WHERE ipsec_tunnel_id = '0';");
        echo json_encode(array("success" => true));
    }
    elseif ($type == "dh_group"){
        
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $idx = $projectdb->real_escape_string((string) (isset($_POST['idx']) ? $_POST['idx'] : $_GET['idx']));
        $ids = $projectdb->real_escape_string((string) (isset($_POST['changes']) ? $_POST['changes'] : $_GET['changes']));
        
        if ($ids != "") {
            $data = explode(",", $ids);
            foreach ($data as $key => $value) {
                $projectdb->query("UPDATE edit_table SET remove = '1' WHERE name = '$value' AND lid = '$idx' AND type = 'crypto_dh_group' AND user_id = '$user_id';");
            }
        }
    }
    elseif ($type == "encryption"){
        
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $idx = $projectdb->real_escape_string((string) (isset($_POST['idx']) ? $_POST['idx'] : $_GET['idx']));
        $ids = $projectdb->real_escape_string((string) (isset($_POST['changes']) ? $_POST['changes'] : $_GET['changes']));
        
        if ($ids != "") {
            $data = explode(",", $ids);
            foreach ($data as $key => $value) {
                $projectdb->query("UPDATE edit_table SET remove = '1' WHERE name = '$value' AND lid = '$idx' AND type = 'crypto_encryption' AND user_id = '$user_id';");
            }
        }
        
    }
    elseif ($type == "authentication"){
        
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $idx = $projectdb->real_escape_string((string) (isset($_POST['idx']) ? $_POST['idx'] : $_GET['idx']));
        $ids = $projectdb->real_escape_string((string) (isset($_POST['changes']) ? $_POST['changes'] : $_GET['changes']));
        
        if ($ids != "") {
            $data = explode(",", $ids);
            foreach ($data as $key => $value) {
                $projectdb->query("UPDATE edit_table SET remove = '1' WHERE name = '$value' AND lid = '$idx' AND type = 'crypto_authentication' AND user_id = '$user_id';");
            }
        }
        
    }
    elseif ($type == "subnet"){
        
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $idx = $projectdb->real_escape_string((string) (isset($_POST['idx']) ? $_POST['idx'] : $_GET['idx']));
        $changes = $projectdb->real_escape_string((string) (isset($_POST['changes']) ? $_POST['changes'] : $_GET['changes']));
        
        $data = explode(",", $changes);
        
        take_snapshot_last($project);
        
        $getAddress = $projectdb->query("SELECT publish_routes FROM ipsec_tunnel WHERE id='$idx';");
        if ($getAddress->num_rows == 1) {
            $dataA = $getAddress->fetch_assoc();
            $publish_routes = $dataA['publish_routes'];
            $add_array = explode(",", $publish_routes);
        }
        $diff = array_diff($add_array, $data);
        
        $projectdb->query("UPDATE ipsec_tunnel SET publish_routes='" . implode(",", $diff) . "' WHERE id='$idx';");
        echo json_encode(array("success" => true));
        
    }
    
    
}
elseif ($action == "rename"){
    
    if ($type == "ipsec_tunnel"){
        
        take_snapshot_last($project);
        
        $change_in_ike_gateways = $projectdb->real_escape_string((string) (isset($_POST['change_in_ike_gateways']) ? $_POST['change_in_ike_gateways'] : ""));
        $change_in_zones = $projectdb->real_escape_string((string) (isset($_POST['change_in_zones']) ? $_POST['change_in_zones'] : ""));
        $old_name = $projectdb->real_escape_string((string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']));
        $new_name = $projectdb->real_escape_string((string) (isset($_POST['new_name']) ? $_POST['new_name'] : $_GET['new_name']));
        $id = $projectdb->real_escape_string((string) (isset($_POST['id']) ? $_POST['id'] : $_GET['id']));
        
        $is_not_correct = 0;
        
        $getNameExist = $projectdb->query("SELECT id FROM ipsec_tunnel WHERE BINARY name = '$new_name' AND id != '$id' AND template = '$template' AND source = '$source';");
        if ($getNameExist->num_rows == 0){
            
            // Check the new name not exceeded 64 chars
            $new_name_ipsec = truncate_names($new_name);
            
            if($change_in_ike_gateways == "on"){
                
                $getExistIKEGWName = $projectdb->query("SELECT id, name FROM ike_gateways_profiles WHERE BINARY name = '$new_name_ipsec' AND template = '$template' AND source = '$source';");
                if ($getExistIKEGWName->num_rows == 0){
                    $projectdb->query("UPDATE ike_gateways_profiles SET name = '$new_name_ipsec' WHERE name = '$old_name' AND template = '$template' AND source = '$source';");
                }else{
                    $is_not_correct = 1;
                    $msg = "IKE Gateways with this name already exists!";
                }
                
            }
            
            if($is_not_correct == 0){
                if($change_in_zones == "on"){
                    
                    // Check the name zone not exceeded 15 chars
                    $version=calcVersion($source);
                    $new_name_zone = truncate_names_zones($new_name,$version);
                    $projectdb->query("UPDATE zones SET name = '$new_name_zone' WHERE name = '$old_name' AND template = '$template' AND source = '$source';");
                    
                    $projectdb->query("UPDATE security_rules_from SET name='$new_name_zone' WHERE source='$source' AND name='$old_name';");
                    $projectdb->query("UPDATE security_rules_to SET name='$new_name_zone' WHERE source='$source' AND name='$old_name';");
                    $projectdb->query("UPDATE appoverride_rules_from SET name='$new_name_zone' WHERE source='$source' AND name='$old_name';");
                    $projectdb->query("UPDATE appoverride_rules_to SET name='$new_name_zone' WHERE source='$source' AND name='$old_name';");
                    $projectdb->query("UPDATE nat_rules SET op_zone_to='$new_name_zone' WHERE source='$source' AND op_zone_to='$old_name';");
                    $projectdb->query("UPDATE nat_rules_from SET name='$new_name_zone' WHERE source='$source' AND name='$old_name';");

                    $projectdb->query("UPDATE routes_static SET zone='$new_name_zone' WHERE source='$source' AND template='$template' AND zone='$old_name';");
                    $projectdb->query("UPDATE interfaces SET zone='$new_name_zone' WHERE source='$source' AND template='$template' AND zone='$old_name';");
                    
                }
            }
            
            if($is_not_correct == 1){
                echo json_encode(array("success"=>false, "msg"=>$msg));
            }else{
                $projectdb->query("UPDATE ipsec_tunnel SET name = '$new_name_ipsec', ike_gateway = '$new_name_ipsec' WHERE name = '$old_name' AND template = '$template' AND source = '$source';");
                
                echo json_encode(array("success"=>true));
            }
            
        }
        else{
            echo json_encode(array("success"=>false, "msg"=>"The name already exist!"));
        }
        
    }
}
elseif ($action == "attach"){
    
    if ($type == "ike_crypto_profile_v1"){
        
        take_snapshot_last($project);
        
        $ike_profiles_attach = $projectdb->real_escape_string((string) (isset($_POST['ike_profiles_attach']) ? $_POST['ike_profiles_attach'] : $_GET['ike_profiles_attach']));
        $ids = $projectdb->real_escape_string((string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']));
        
        if($ike_profiles_attach != ""){
            $projectdb->query("UPDATE ike_gateways_profiles SET ike_crypto_profile_ikev1 = '$ike_profiles_attach' WHERE id IN ($ids) AND source = '$source';");
            echo json_encode(array("success"=>true));
        }
    }
    elseif ($type == "ike_crypto_profile_v2"){
        
        take_snapshot_last($project);
        
        $ike_profiles_attach = $projectdb->real_escape_string((string) (isset($_POST['ike_profiles_attach']) ? $_POST['ike_profiles_attach'] : $_GET['ike_profiles_attach']));
        $ids = $projectdb->real_escape_string((string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']));
        
        if($ike_profiles_attach != ""){
            $projectdb->query("UPDATE ike_gateways_profiles SET ike_crypto_profile_ikev2 = '$ike_profiles_attach' WHERE id IN ($ids) AND source = '$source';");
            echo json_encode(array("success"=>true));
        }
    }



}

?>