<?php

# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';
require_once INC_ROOT.'/bin/Authentication.php';
require_once INC_ROOT.'/libs/shared.php';
require_once INC_ROOT.'/libs/common/tools/filters.php';

include INC_ROOT.'/bin/middleware_sanitizer.php';

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $action     = (string)  (isset($_GET['action'])     ? $_GET['action'] : '');
        $vsys     = (string)  (isset($_GET['vsys'])     ? $_GET['vsys'] : '');
        $source     = (string)  (isset($_GET['source'])     ? $_GET['source'] : '');
        $type       = (string)  (isset($_GET['type'])       ? $_GET['type'] : ''); // zip / xml / device
        $type2      = (string)  (isset($_GET['type2'])      ? $_GET['type2'] : ''); // zip / xml / device
        $project    = (string)  (isset($_GET['project'])    ? $_GET['project'] : '');
        $profile_type = (string)(isset($_GET['profile_type'])? $_GET['profile_type'] : '');
        $filter     = (string)  (isset($_GET['filter'])     ? $_GET['filter'] : '');
        $tools_where_id     = (string)  (isset($_GET['tools_where_id'])     ? $_GET['tools_where_id'] : '');
        break;
    case 'POST':
        $action     = (string)  (isset($_POST['action'])    ? $_POST['action'] : '');
        $type       = (string)  (isset($_POST['type'])      ? $_POST['type'] : ''); // zip / xml / device
        $type2      = (string)  (isset($_POST['type2'])     ? $_POST['type2'] : ''); // zip / xml / device
        $project    = (string)  (isset($_POST['project'])   ? $_POST['project'] : '');
        $profile_type = (string)(isset($_POST['profile_type'])? $_POST['profile_type'] : '');
        $filter     = (string)  (isset($_POST['filter'])    ? $_POST['filter'] : '');
        $tools_where_id     = (string)  (isset($_POST['tools_where_id'])    ? $_POST['tools_where_id'] : '');
        break;
    default:
        $action     = (string)  (isset($_POST['action'])    ? $_POST['action'] : '');
        $type       = (string)  (isset($_POST['type'])      ? $_POST['type'] : ''); // zip / xml / device
        $type2      = (string)  (isset($_POST['type2'])     ? $_POST['type2'] : ''); // zip / xml / device
        $project    = (string)  (isset($_POST['project'])   ? $_POST['project'] : '');
        $profile_type = (string)(isset($_POST['profile_type'])? $_POST['profile_type'] : '');
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
$profile_type = $projectdb->real_escape_string($profile_type);
$filter = $projectdb->real_escape_string($filter);
$tools_where_id = $projectdb->real_escape_string($tools_where_id);

if ($action == "get") {
    if (($type == "profiles") AND ( $profile_type != "profiles_groups")) {

        if ($profile_type != "") {

            $query = generate_query("objects_vsyses");

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

            list($query, $orderby) = generateQueryFilters($project, "profiles", "$profile_type", $query, $source);

            if (($profile_type == "") or ( $profile_type == NULL)) {
                $where = "";
            } else {
                if (preg_match("/WHERE/i", $query)) {
                    $where = $query . " AND type = ('" . $profile_type . "') ";
                } else {
                    $where = $query . " WHERE type = ('" . $profile_type . "') ";
                }
            }
            
            $getLimit = $projectdb->query("SELECT source,devicegroup,type,id as idx,name,xml,vsys,'profiles' as table_name  "
                    . "FROM profiles $where $orderby;");

            $count = 0;

            $x = 0;

            if ($getLimit->num_rows > 0) {
                $count = $getLimit->num_rows;
                while ($data = $getLimit->fetch_object()) {
                    $data->id = $x++;
                    $myData[] = $data;
                }
            }
        }
        else {
            $count = 0;
        }
        if ($count == 0) {
            $myData = "";
        }

        $start = $_GET['start'];
        // Extracting items from start position to the end
        $myData = array_slice($myData, $start, $count);

        echo '{"total":"' . $count . '","profiles":' . json_encode($myData) . '}';
    }
    elseif (($type == "profiles1") AND ( $profile_type == "profiles")) {

        $profile_type = "log_settings";
        if ($profile_type != "") {
            $query = generate_query("objects");
            if ($profile_type == "log_settings") {
                $table = "log_settings";
                if (preg_match("/WHERE/", $query)) {
                    $query = $query . "  AND type='profiles' ";
                } else {
                    $query = " WHERE type='profiles' ";
                }
            }

            $getAll = $projectdb->query("SELECT source,devicegroup,type,id as idx,name,xml,vsys,'$table' as table_name  "
                    . "FROM $table $query ;");
            $count = $getAll->num_rows;
            $getLimit = $projectdb->query("SELECT source,devicegroup,type,id as idx,name,xml,vsys,'$table' as table_name  "
                    . "FROM $table $query ;");
            
            $x = 0;
            while ($data = $getLimit->fetch_object()) {
                $data->id = $x++;
                $myData[] = $data;
            }
        } else {
            $count = 0;
        }
        if ($count == 0) {
            $myData = "";
        }
        echo '{"total":"' . $count . '","profiles":' . json_encode($myData) . '}';
    } 
    elseif (($type == "profiles_groups") OR ( ($type == "profiles") AND ( $profile_type = "profiles_groups"))) {

        if ($profile_type != "") {

            $query = generate_query("objects_vsyses");

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

            list($query, $orderby) = generateQueryFilters($project, "profiles_groups", "", $query, $source);


            $getAll = $projectdb->query("SELECT source,devicegroup,'profiles_groups' AS type,id as idx,name,xml,vsys,'profiles_groups' as table_name  "
                    . "FROM profiles_groups $query ;");
            
            $count = $getAll->num_rows;
            $getLimit = $projectdb->query("SELECT source,devicegroup,'profiles_groups' AS type,id as idx,name,xml,vsys,'profiles_groups' as table_name  "
                    . "FROM profiles_groups $query ;");
            
            $x = 0;
            while ($data = $getLimit->fetch_object()) {
                $data->id = $x++;
                $myData[] = $data;
            }
        } else {
            $count = 0;
        }
        if ($count == 0) {
            $myData = "";
        }
        echo '{"total":"' . $count . '","profiles":' . json_encode($myData) . '}';
    }
    elseif ($type == "profiles_groups_all") {

        $myData = array();

        $query = generate_query("objects_vsyses");

        $getAll = $projectdb->query("SELECT id,name  "
            . "FROM profiles_groups $query ;");

        $count = $getAll->num_rows;
        $getLimit = $projectdb->query("SELECT id,name  "
            . "FROM profiles_groups $query ;");

        while ($data = $getLimit->fetch_object()) {
            $myData[] = $data;
        }



        echo '{"total":"' . $count . '","profiles":' . json_encode($myData) . '}';
    }
    elseif ($type == "hip-profiles") {
        $query = generate_query("objects_vsyses");
        if (preg_match("/WHERE/",$query)){
            $query=$query." AND type='hip-profiles '";
        }
        else{
            $query=" WHERE type='hip-profiles' ";
        }
        $getLimit = $projectdb->query("SELECT id as idx,name, name_ext, id, vsys, if(vsys = 'shared', 'shared_hip-profiles.gif', 'hip-profiles.png') AS type, 'profiles' as table_name "
                . "FROM profiles $query ;");
        $myData=[];
        // Todo We need to add the default action for hip-profiles "no-hip"
        $x = 0;
        
        $myData[] = array("idx" => "no-hip", "name" => "no-hip", "name_ext" => "no-hip", "id" => "no-hip", "vsys" => "no-hip", "type" => "hip-profiles.png", "table_name" => "profiles", );
                    
        while ($data = $getLimit->fetch_object()) {
            //$data->id = $x++;
            $myData[] = $data;
        }

        echo '{"total":"' .count($myData) . '","address":' . json_encode($myData) . '}';
    } 
    elseif ($type == "url-categories") {
        $query = generate_query("objects_vsyses");

        $vsyses = getVsyses($projectdb, $vsys, $source, 'quoted');
        if (count($vsyses)>0){
            $vsys_query = " AND (vsys in (".implode(",", $vsyses).")) ";
        }
        else{
            $vsys_query=" AND (vsys in ('shared'))";
        }


        $getLimit = $projectdb->query("SELECT id as idx,name, name_ext, id,'domain.png' as type,'default_url_categories' as table_name "
                . "FROM default_url_categories UNION SELECT id as idx, name, name_ext, id, 'url' as type, 'external_list' as table_name FROM external_list where type='url' $vsys_query AND source='$source' " .
            " UNION SELECT id as idx, name, name_ext, id, 'url' as type, 'custom-url-category' as table_name FROM profiles where type='custom-url-category' $vsys_query AND source='$source';");
        
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
    elseif ($type == "other") {

        if ($profile_type != "") {

            $query = generate_query("objects_vsyses");

            if ($profile_type == "log_settings") {
                $table = "log_settings";
                $type = "profiles";
                if (preg_match("/WHERE/", $query)) {
                    $query = $query . "  AND type='profiles' ";
                } else {
                    $query = " WHERE type='profiles' ";
                }
            }
            elseif ($profile_type == "external_lists") {
                $table = "external_list";
                $type = "";
            }
            elseif ($profile_type == "schedules") {
                $table = "schedules";
                $type = "";
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

            list($query, $orderby) = generateQueryFilters($project, "$table", "$type", $query, $source);

            $getLimit = $projectdb->query("SELECT source,devicegroup,type,id as idx, name,xml,vsys,'$table' as table_name  "
                    . "FROM $table $query ;");
            $count = $getLimit->num_rows;
            
            $x = 0;
            while ($data = $getLimit->fetch_object()) {
                $data->id = $x++;
                $myData[] = $data;
            }
        } else {
            $count = 0;
        }
        if ($count == 0) {
            $myData = "";
        }
        echo '{"total":"' . $count . '","profiles":' . json_encode($myData) . '}';
    }
} 
elseif ($action == "add") {
    if ($type2 == "profiles") {
        $source = $_POST['source'];
        $vsys = $_POST['vsys'];
        $name = $_POST['name'];
        $type = $_POST['type'];
        $xml = $_POST['xml'];
        //$xml = addslashes($xml);
        take_snapshot_last($project);
        $id = $_POST['id'];
        $table_name = $_POST['table_name'];

        $table = "profiles";
        
        if ($type == "profiles_groups") {
            $table = "profiles_groups";
        }

        $entryInfo = $projectdb->query("SELECT vsys, source FROM $table WHERE id='$id'");
        if($entryInfo->num_rows>0){
            $queryData = $entryInfo->fetch_assoc();
            $vsys = $queryData['vsys'];
            $source = $queryData['source'];
        }

        if ($id != "") {

            $xml = preg_replace('/<entry name="(.*?)">/', '<entry name="'.$name.'">', $xml);
            $xml = preg_replace('/\\\n\s*/', '', $xml);
            $xml = preg_replace('/\n\s*/', '', $xml);
            $xml = preg_replace('/\\\\+/', '', $xml);
            $xml = preg_replace('/>n\s</', '><', $xml);
            //$xml = addslashes($xml);
            $xml = simplexml_load_string($xml);
            $xmlString = preg_replace('/^<\?xml.*\?>\n/', '', $xml->asXML());

            $conn = get_pdo($project);
            $stmt = $conn->prepare("UPDATE $table_name SET xml=?, name=?, type=? WHERE id=?;");
            $stmt->bindParam(1, $xmlString);
            $stmt->bindParam(2, $name);
            $stmt->bindParam(3, $type);
            $stmt->bindParam(4, $id);
            $stmt->execute();

        } 
        else {
            $getProfile = $projectdb->query("SELECT id FROM $table WHERE vsys = '$vsys' AND source = '$source' AND BINARY name = '$name';");
            if ($getProfile->num_rows == 0) {
                $conn = get_pdo($project);

                $xml = simplexml_load_string($xml);
                $xmlString = preg_replace('/^<\?xml.*\?>\n/', '', $xml->asXML());

                $stmt = $conn->prepare("INSERT INTO $table (vsys,source,name,type,xml) VALUES (?,?,?,?,?);");
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
    elseif ($type2 == "other") {
        $source = $_POST['source'];
        $vsys = $_POST['vsys'];
        $name = $_POST['name'];
        $type = $_POST['type'];
        $xml = $_POST['xml'];
        $other_type = $_POST['other_type'];
        $id = $_POST['id'];
        $table_name = $_POST['table_name'];

        take_snapshot_last($project);
        
        if ($other_type == "log_settings") {
            $table = "log_settings";
            $type = "profiles";
        } 
        elseif ($other_type == "external_lists") {
            $table = "external_list";
        } 
        elseif ($other_type == "schedules") {
            $table = "schedules";
        }
        if ($id != "") {

            $name = truncate_rulenames($name);

            $xml = preg_replace('/<entry name="(.*?)">/', '<entry name="'.$name.'">', $xml);
            $xml = addslashes($xml);
            
            if($other_type == "log_settings"){
                $getOldName = $projectdb->query("SELECT name FROM $table_name WHERE id='$id';");
                if ($getOldName->num_rows > 0) {

                    $dataON = $getOldName->fetch_assoc();
                    $name_old = $dataON['name'];

                    if($name_old != ""){

                        //$ids_rules = getIdsRulesBySourceVsys("security_rules", $source, $vsys);
                        $projectdb->query("UPDATE security_rules SET log_forwarding = '$name' WHERE log_forwarding = '$name_old' AND source = '$source';");

                        //$ids_rules = getIdsRulesBySourceVsys("authentication_rules", $source, $vsys);
                        $projectdb->query("UPDATE authentication_rules SET log_forwarding = '$name' WHERE log_forwarding = '$name_old' AND source = '$source';");

                        //$ids_rules = getIdsRulesBySourceVsys("dos_rules", $source, $vsys);
                        $projectdb->query("UPDATE dos_rules SET log_forwarding = '$name' WHERE log_forwarding = '$name_old' AND source = '$source';");

                        //$ids_rules = getIdsRulesBySourceVsys("tunnel_inspect_rules", $source, $vsys);
                        $projectdb->query("UPDATE tunnel_inspect_rules SET log_forwarding = '$name' WHERE log_forwarding = '$name_old' AND source = '$source';");
                    }
                }   
            }
            elseif($other_type == "schedules"){
                $getOldName = $projectdb->query("SELECT name FROM $table_name WHERE id='$id';");
                if ($getOldName->num_rows > 0) {

                    $dataON = $getOldName->fetch_assoc();
                    $name_old = $dataON['name'];

                    if($name_old != ""){

                        //$ids_rules = getIdsRulesBySourceVsys("security_rules", $source, $vsys);
                        $projectdb->query("UPDATE security_rules SET schedule = '$name' WHERE schedule = '$name_old' AND source = '$source';");

                        //$ids_rules = getIdsRulesBySourceVsys("dos_rules", $source, $vsys);
                        $projectdb->query("UPDATE dos_rules SET schedule = '$name' WHERE schedule = '$name_old' AND source = '$source';");

                        //$ids_rules = getIdsRulesBySourceVsys("pbf_rules", $source, $vsys);
                        $projectdb->query("UPDATE pbf_rules SET schedule = '$name' WHERE schedule = '$name_old' AND source = '$source';");

                        //$ids_rules = getIdsRulesBySourceVsys("qos_rules", $source, $vsys);
                        $projectdb->query("UPDATE qos_rules SET schedule = '$name' WHERE schedule = '$name_old' AND source = '$source';");
                    }
                }
            }


            $conn = get_pdo($project);
            $xml = simplexml_load_string($xml);
            $xmlString = preg_replace('/^<\?xml.*\?>\n/', '', $xml->asXML());

            $stmt = $conn->prepare("UPDATE $table_name SET xml=?, name=?, type=? WHERE id=?;");
            $stmt->bindParam(1, $xmlString);
            $stmt->bindParam(2, $name);
            $stmt->bindParam(3, $type);
            $stmt->bindParam(4, $id);
            $stmt->execute();

            //echo "UPDATE $table_name SET xml='$xml', name='$name', type='$type' WHERE id='$id';\n";
        } 
        else {
            //$xml = addslashes($xml);
            $getProfile = $projectdb->query("SELECT id FROM $table WHERE vsys = '$vsys' AND source = '$source' AND BINARY name = '$name';");
            if ($getProfile->num_rows == 0) {
                $conn = get_pdo($project);
                $xml = simplexml_load_string($xml);
                $xmlString = preg_replace('/^<\?xml.*\?>\n/', '', $xml->asXML());
                $stmt = $conn->prepare("INSERT INTO $table (vsys,source,name,type,xml) VALUES (?,?,?,?,?);");
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
        $source = $_POST["source"];

        if (isset($ids)) {
            take_snapshot_last($project);
            $ids_array = explode(",", $ids);

            foreach ($ids_array as $key => $value) {
                $values = explode(";", $value);
                $objid = $values[0];
                $objtable = $values[1];
                $objname = $values[2];

                if($objtable != "external_list"){
                    $projectdb->query("DELETE FROM $objtable WHERE id='$objid' AND devicegroup !='predefined' AND dummy = 0;");

                    if($projectdb->affected_rows == 1){
                        #Clean References
                        $projectdb->query("DELETE FROM security_rules_profiles WHERE member_lid='$objid' AND table_name='$objtable';");

                        if($objtable == "log_settings"){
                            $projectdb->query("UPDATE security_rules SET log_forwarding = '' WHERE log_forwarding = '$objname' AND source = '$source';");
                            $projectdb->query("UPDATE authentication_rules SET log_forwarding = '' WHERE log_forwarding = '$objname' AND source = '$source';");
                            $projectdb->query("UPDATE dos_rules SET log_forwarding = '' WHERE log_forwarding = '$objname' AND source = '$source';");
                            $projectdb->query("UPDATE tunnel_inspect_rules SET log_forwarding = '' WHERE log_forwarding = '$objname' AND source = '$source';");
                        }
                        elseif($objtable == "schedules"){
                            $projectdb->query("UPDATE security_rules SET schedule = '' WHERE schedule = '$objname' AND source = '$source';");
                            $projectdb->query("UPDATE dos_rules SET schedule = '' WHERE schedule = '$objname' AND source = '$source';");
                            $projectdb->query("UPDATE pbf_rules SET schedule = '' WHERE schedule = '$objname' AND source = '$source';");
                            $projectdb->query("UPDATE qos_rules SET schedule = '' WHERE schedule = '$objname' AND source = '$source';");
                        }
                    }
                }
                elseif($objtable == "external_list"){
                    $projectdb->query("DELETE FROM $objtable WHERE id='$objid' AND devicegroup !='predefined';");

                    #Clean References
                    $projectdb->query("DELETE FROM security_rules_src WHERE member_lid='$objid' AND table_name='$objtable';");
                    $projectdb->query("DELETE FROM security_rules_dst WHERE member_lid='$objid' AND table_name='$objtable';");

                    $projectdb->query("DELETE FROM nat_rules_src WHERE member_lid='$objid' AND table_name='$objtable';");
                    $projectdb->query("DELETE FROM nat_rules_dst WHERE member_lid='$objid' AND table_name='$objtable';");
                    $projectdb->query("DELETE FROM nat_rules_translated_address WHERE member_lid='$objid' AND table_name='$objtable';");

                    $projectdb->query("DELETE FROM appoverride_rules_src WHERE member_lid='$objid' AND table_name='$objtable';");
                    $projectdb->query("DELETE FROM appoverride_rules_dst WHERE member_lid='$objid' AND table_name='$objtable';");

                    $projectdb->query("DELETE FROM authentication_rules_src WHERE member_lid='$objid' AND table_name='$objtable';");
                    $projectdb->query("DELETE FROM authentication_rules_dst WHERE member_lid='$objid' AND table_name='$objtable';");

                    $projectdb->query("DELETE FROM captiveportal_rules_src WHERE member_lid='$objid' AND table_name='$objtable';");
                    $projectdb->query("DELETE FROM captiveportal_rules_dst WHERE member_lid='$objid' AND table_name='$objtable';");

                    $projectdb->query("DELETE FROM decryption_rules_src WHERE member_lid='$objid' AND table_name='$objtable';");
                    $projectdb->query("DELETE FROM decryption_rules_dst WHERE member_lid='$objid' AND table_name='$objtable';");

                    $projectdb->query("DELETE FROM dos_rules_src WHERE member_lid='$objid' AND table_name='$objtable';");
                    $projectdb->query("DELETE FROM dos_rules_dst WHERE member_lid='$objid' AND table_name='$objtable';");

                    $projectdb->query("DELETE FROM pbf_rules_dst WHERE member_lid='$objid' AND table_name='$objtable';");
                    $projectdb->query("DELETE FROM pbf_rules_src WHERE member_lid='$objid' AND table_name='$objtable';");

                    $projectdb->query("DELETE FROM qos_rules_dst WHERE member_lid='$objid' AND table_name='$objtable';");
                    $projectdb->query("DELETE FROM qos_rules_src WHERE member_lid='$objid' AND table_name='$objtable';");

                    $projectdb->query("DELETE FROM tunnel_inspect_rules_dst WHERE member_lid='$objid' AND table_name='$objtable';");
                    $projectdb->query("DELETE FROM tunnel_inspect_rules_src WHERE member_lid='$objid' AND table_name='$objtable';");
                }
            }
            echo json_encode(array("success" => true));
        }
    }
}
elseif ($action == "convert") {
    if ($type == "shared") {
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $ids = $projectdb->real_escape_string((string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']));
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

                if($table_name == "external_list"){
                    $return = convertExternalToShared($source, $members, "notall");
                }
                elseif($table_name == "log_settings"){
                    $return = convertLogSettingsToShared($source, $members, "notall");
                }
                elseif($table_name == "schedules"){
                    $return = convertSchedulesToShared($source, $members, "notall");
                }
                elseif($table_name == "profiles"){
                    $return = convertProfilesToShared($source, $members, "notall");
                }
                elseif($table_name = "profiles_groups"){
                    $return = convertProfilesGroupsToShared($source, $members, "notall");
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
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $ids = $projectdb->real_escape_string((string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']));
        $clone_to_vsys = $projectdb->real_escape_string((string) (isset($_POST['combo']) ? $_POST['combo'] : $_GET['combo']));
        if ($ids != "") {
            take_snapshot_last($project);
            $data = explode(",", $ids);

            foreach ($data as $key => $value) {

                $values = explode(";", $value);
                $member_lid = $values[0];
                $table_name = $values[1];
                $name = $values[2];

                $members = explode(',', $member_lid);

                if($table_name == "external_list"){
                    $return = cloneExternalList($source, $vsys, $clone_to_vsys, $members);
                }
                elseif($table_name == "log_settings"){
                    $return = cloneLogSettings($source, $vsys, $clone_to_vsys, $members, "");
                }
                elseif($table_name == "schedules"){
                    $return = cloneSchedules($source, $vsys, $clone_to_vsys, $members);
                }
                elseif($table_name == "profiles"){
                    $return = cloneProfiles($source, $vsys, $clone_to_vsys, $members);
                }
                elseif($table_name = "profiles_groups"){
                    $return = cloneProfilesGroups($source, $vsys, $clone_to_vsys, $members);
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


?>