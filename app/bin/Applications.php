<?php

# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';

require_once('./Authentication.php');
require_once '../libs/shared.php';

include INC_ROOT.'/bin/middleware_sanitizer.php';

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $action     = (string)  (isset($_GET['action'])    ? $_GET['action'] : '');
        $type       = (string)  (isset($_GET['type'])      ? $_GET['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_GET['project'])   ? $_GET['project'] : '');
        $devicename = (string)  (isset($_GET['devicename'])? $_GET['devicename'] : '');
        $start      = (integer) (isset($_GET['start'])     ? $_GET['start'] : '');
        $limit      = (integer) (isset($_GET['limit'])     ? $_GET['limit'] : '');
        $names_tags  = (string)  (isset($_GET['names_tags'])   ? $_GET['names_tags'] : '');
        break;
    case 'POST':
        $action     = (string)  (isset($_POST['action'])    ? $_POST['action'] : '');
        $type       = (string)  (isset($_POST['type'])      ? $_POST['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_POST['project'])   ? $_POST['project'] : '');
        $devicename = (string)  (isset($_POST['devicename'])? $_POST['devicename'] : '');
        $start      = (integer) (isset($_POST['start'])     ? $_POST['start'] : '');
        $limit      = (integer) (isset($_POST['limit'])     ? $_POST['limit'] : '');
        $names_tags  = (string) (isset($_POST['names_tags'])   ? $_POST['names_tags'] : '');

        break;

    default:
        $action     = (string)  (isset($_POST['action'])    ? $_POST['action'] : '');
        $type       = (string)  (isset($_POST['type'])      ? $_POST['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_POST['project'])   ? $_POST['project'] : '');
        $devicename = (string)  (isset($_POST['devicename'])? $_POST['devicename'] : '');
        $start      = (integer) (isset($_POST['start'])     ? $_POST['start'] : '');
        $limit      = (integer) (isset($_POST['limit'])     ? $_POST['limit'] : '');
        $names_tags  = (string) (isset($_POST['names_tags'])   ? $_POST['names_tags'] : '');

        break;
}

require_once INC_ROOT.'/libs/projectdb.php';
$projectdb = selectDatabase($project);

$action = $projectdb->real_escape_string($action);
$type = $projectdb->real_escape_string($type);
$project = $projectdb->real_escape_string($project);
$devicename = $projectdb->real_escape_string($devicename);
$start = $projectdb->real_escape_string($start);
$limit = $projectdb->real_escape_string($limit);
$names_tags = $projectdb->real_escape_string($names_tags);

if(!checkProjectRights($project,'view')){
    echo '{"total":"0","apps":' . json_encode(array()) . '}';
    return;
}

if ($action == "get") {
    $query = generate_query("objects");
    $conditions = generate_query_multitable("objects");
    if ($type == "custom") {
        switch($_SERVER['REQUEST_METHOD'])
        {
            case 'GET':
                $search         = (string) (isset($_GET['search'])         ? $_GET['search'] : '');
                $hide_shared    = (string) (isset($_GET['hide_shared_app'])? $_GET['hide_shared_app'] : '');
                break;
            case 'POST':
                $search         = (string) (isset($_POST['search'])         ? $_POST['search'] : '');
                $hide_shared    = (string) (isset($_POST['hide_shared_app'])? $_POST['hide_shared_app'] : '');
                break;
            default:
                $search         = (string) (isset($_POST['search'])         ? $_POST['search'] : '');
                $hide_shared    = (string) (isset($_POST['hide_shared_app'])? $_POST['hide_shared_app'] : '');
                break;
        }

        $search = $projectdb->real_escape_string($search);
        $hide_shared = $projectdb->real_escape_string($hide_shared);

        $sql_search = "";

        if ($search != "") {
            if (preg_match("/WHERE/", $conditions)) {
                $conditions .= " AND a.name LIKE '%$search%'";
            } else {
                $conditions .= " WHERE a.name LIKE '%$search%'";
            }
        }

        if($hide_shared == "true"){
            if (preg_match("/WHERE/", $conditions)) {
                $conditions .= " AND a.vsys != 'shared' ";
            }
            else{
                $conditions .= " WHERE a.vsys != 'shared' ";
            }
        }
        $getAll = $projectdb->query("SELECT id as idx,source,devicegroup,vsys,name,description,category,subcategory,parent_app,risk,technology,evasive_behavior,consume_big_bandwidth,used_by_malware,able_to_transfer_file,has_known_vulnerability,tunnel_other_application,tunnel_applications,prone_to_misuse,pervasive_use,file_type_ident,virus_ident,data_ident,default_type,value,type,code,timeout,tcp_timeout,udp_timeout,spyware_ident,'applications' as table_name "
                . "FROM applications a $conditions ;");
        $count = $getAll->num_rows;
        $getLimit = $projectdb->query("SELECT id as idx,source,devicegroup,vsys,name,description,category,subcategory,parent_app,risk,technology,evasive_behavior,consume_big_bandwidth,used_by_malware,able_to_transfer_file,has_known_vulnerability,tunnel_other_application,tunnel_applications,prone_to_misuse,pervasive_use,file_type_ident,virus_ident,data_ident,default_type,value,type,code,timeout,tcp_timeout,udp_timeout,spyware_ident,'applications' as table_name "
                . "FROM applications a $conditions ORDER BY name ASC;");
        $x = 0;
        while ($data = $getLimit->fetch_object()) {
            $getSig = $projectdb->query("SELECT signature FROM applications_signatures WHERE table_name='$data->table_name' AND member_lid='$data->idx';");
            if ($getSig->num_rows == 1) {
                $getSigData = $getSig->fetch_object();
                $data->xml = addslashes($getSigData->signature);
            } else {
                $data->xml = "";
            }
            $data->uid = $x++;
            $myData[] = $data;
        }
        if ($count == 0) {
            $myData = "";
        }
        echo '{"total":"' . $count . '","apps":' . json_encode($myData) . '}';
    } 
    elseif($type == "custom_grid") {

        $search = $projectdb->real_escape_string((string) (isset($_POST['search']) ? $_POST['search'] : $_GET['search']));
        $hide_shared = $projectdb->real_escape_string((string) (isset($_POST['hide_shared_app']) ? $_POST['hide_shared_app'] : $_GET['hide_shared_app']));
        $custom_only = $projectdb->real_escape_string((string) (isset($_POST['custom_only']) ? $_POST['custom_only'] : $_GET['custom_only']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $filename_source = $projectdb->real_escape_string((string) (isset($_POST['filename_source']) ? $_POST['filename_source'] : $_GET['filename_source']));
        $applications_filters = $projectdb->real_escape_string((string) (isset($_POST['applications_filters']) ? $_POST['applications_filters'] : $_GET['applications_filters']));
        
        $sql_search = "";
        $sql_search_custom = "";

        if ($search != "") {
            //if (preg_match("/WHERE/", $query)) {
            if (preg_match("/WHERE/", $conditions)) {
                $sql_search = " AND name LIKE '%$search%'";
            } else {
                $sql_search = " WHERE name LIKE '%$search%'";
            }
            $sql_search_custom = " WHERE name LIKE '%$search%'";
        }
        
        if($hide_shared == "true"){
            if (preg_match("/WHERE/", $conditions)) {
                $conditions .= " AND a.vsys != 'shared' ";
            }
            else{
                $conditions .= " WHERE a.vsys != 'shared' ";
            }
        }
        
        if($custom_only == "false"){$sql_custom_only = " UNION SELECT '' as parent_app,id as idx, '$source' as source, '$filename_source' as devicegroup, 'all' as vsys, name, category, subcategory, risk, technology, evasive_behavior,consume_big_bandwidth,used_by_malware,able_to_transfer_file,has_known_vulnerability,tunnel_other_application,category AS tunnel_applications,prone_to_misuse,pervasive_use,category AS file_type_ident,category AS virus_ident,category AS data_ident,category AS default_type,category AS value,category AS type,category AS code,category AS timeout,category AS tcp_timeout,category AS udp_timeout,category AS spyware_ident, category AS tcp_half_closed_timeout, category AS tcp_time_wait_timeout, 'default_applications' as table_name FROM default_applications $sql_search_custom ";
        }elseif($custom_only == "true"){$sql_custom_only = ""; }

        $getAll = $projectdb->query("SELECT parent_app,id as idx, source, devicegroup, vsys, name, category, subcategory, risk, technology, evasive_behavior,consume_big_bandwidth,used_by_malware,able_to_transfer_file,has_known_vulnerability,tunnel_other_application,tunnel_applications,prone_to_misuse,pervasive_use,file_type_ident,virus_ident,data_ident,default_type,value,type,code,timeout,tcp_timeout,udp_timeout,spyware_ident,tcp_half_closed_timeout, tcp_time_wait_timeout,'applications' as table_name FROM applications a $conditions $sql_search $sql_custom_only;");
        $count = $getAll->num_rows;
        $getLimit = $projectdb->query("SELECT parent_app,id as idx, source, devicegroup, vsys, name, category, subcategory, risk, "
                . "technology, evasive_behavior,consume_big_bandwidth,used_by_malware,able_to_transfer_file,has_known_vulnerability,"
                . "tunnel_other_application,tunnel_applications,prone_to_misuse,pervasive_use,file_type_ident,virus_ident,data_ident,"
                . "default_type,value,type,code,timeout,tcp_timeout,udp_timeout,spyware_ident,tcp_half_closed_timeout, tcp_time_wait_timeout,'applications' as table_name "
                . "FROM applications a $conditions $sql_search $sql_custom_only ORDER BY name ASC;");

        
        if (isset($getLimit)) {
            $x = 0;
            if ($getLimit->num_rows>0){
                while ($data = $getLimit->fetch_object()) {
                    $getSig = $projectdb->query("SELECT signature FROM applications_signatures WHERE table_name='$data->table_name' AND member_lid='$data->idx';");
                    if ($getSig->num_rows == 1) {
                        $getSigData = $getSig->fetch_object();
                        $data->xml = addslashes($getSigData->signature);
                    } else {
                        $data->xml = "";
                    }
                    $data->uid = $x++;
                    $myData[] = $data;
                }
            }
                
        }
        
        if ($count == 0) {
            $myData = "";
        }
        echo '{"total":"' . $count . '","apps":' . json_encode($myData) . '}';
    }
    elseif ($type == "custom_all") {
        $getAll = $projectdb->query("SELECT id as idx, name, 'applications' as table_name, vsys FROM applications $query "
                . " UNION SELECT id as idx, name, 'default_applications' as table_name, 'vsys' as vsys FROM default_applications;");
        $count = $getAll->num_rows;
        while ($data = $getAll->fetch_object()) {
            $myData[] = $data;
        }
        if ($count == 0) {
            $myData = "";
        }
        echo '{"total":"' . $count . '","apps":' . json_encode($myData) . '}';
    } 
    elseif ($type == "groups") {
        
        $search = $projectdb->real_escape_string((string) (isset($_POST['search']) ? $_POST['search'] : $_GET['search']));
        $sql_search = "";
        if ($search != "") {
            if (preg_match("/WHERE/", $query)) {
                $sql_search = " AND name LIKE '%$search%'";
            } else {
                $sql_search = " WHERE name LIKE '%$search%'";
            }
        }
        $getAll = $projectdb->query("SELECT name,id,devicegroup,vsys,source,'applications_groups' as table_name FROM applications_groups $query $sql_search;");
        
        $count = $getAll->num_rows;
        $getLimit = $projectdb->query("SELECT name,id,devicegroup,vsys,source,'applications_groups' as table_name FROM applications_groups $query $sql_search ORDER BY name ASC;");
        $x = 0;
        while ($data = $getLimit->fetch_object()) {
            $data->uid = $x++;
            $myData[] = $data;
        }
        if ($count == 0) {
            $myData = "";
        }
        echo '{"total":"' . $count . '","apps":' . json_encode($myData) . '}';
    } 
    elseif ($type == "groups_name") {
        $getAll = $projectdb->query("SELECT name, id AS idx, devicegroup AS type, 'applications_groups_id' as table_name, vsys FROM applications_groups_id $query ORDER BY name ASC;");
        $count = $getAll->num_rows;
        $getLimit = $projectdb->query("SELECT name, id AS idx, devicegroup AS type, 'applications_groups_id' as table_name, vsys FROM applications_groups_id $query ORDER BY name ASC;");
        $x = 0;
        while ($data = $getLimit->fetch_object()) {
            $data->uid = $x++;
            $myData[] = $data;
        }
        if ($count == 0) {
            $myData = "";
        }
        echo '{"total":"' . $count . '","address":' . json_encode($myData) . '}';
    }
    elseif ($type == "filters_name") {
        $getAll = $projectdb->query("SELECT name, id AS idx, devicegroup AS type, 'applications_filters' as table_name, vsys FROM applications_filters $query ORDER BY name ASC;");
        $count = $getAll->num_rows;
        $getLimit = $projectdb->query("SELECT name, id AS idx, devicegroup AS type, 'applications_filters' as table_name, vsys FROM applications_filters $query ORDER BY name ASC;");
        $x = 0;
        while ($data = $getLimit->fetch_object()) {
            $data->uid = $x++;
            $myData[] = $data;
        }
        if ($count == 0) {
            $myData = "";
        }
        echo '{"total":"' . $count . '","address":' . json_encode($myData) . '}';
    }
    elseif ($type == "all_applications_without_container") {
        $getLimit = $projectdb->query("SELECT name,id,devicegroup,vsys,source,'applications' as table_name FROM applications UNION SELECT name,id,'' as devicegroup,'' as vsys,'' as source,'default_applications' as table_name FROM default_applications where functions='' ORDER BY name ASC;");
        $count = $getLimit->num_rows;
        $x = 0;
        while ($data = $getLimit->fetch_object()) {
            $data->uid = $x++;
            $myData[] = $data;
        }
        if ($count == 0) {
            $myData = "";
        }
        echo '{"total":"' . $count . '","apps":' . json_encode($myData) . '}';
    } 
    elseif ($type == "custom.full") {
        $app = $projectdb->real_escape_string((string) (isset($_POST['app']) ? $_POST['app'] : $_GET['app']));
        $getLimit = $projectdb->query("SELECT * from applications WHERE name='$app' ORDER BY name ASC;");
        $count = $getLimit->num_rows;
        while ($data = $getLimit->fetch_object()) {
            $myData[] = $data;
        }
        if ($count == 0) {
            $myData = "";
        }
        echo '{"total":"' . $count . '","apps":' . json_encode($myData) . '}';
    } 
    elseif ($type == "applications_all") {
        $query = generate_query("objects_vsyses");
        $getLimit = $projectdb->query("SELECT id as idx, name, name, id, 'application.gif' as type,'default_applications' as table_name, 'default' as vsys, 'fa fa-list-alt' AS icon, '#235585' AS color FROM default_applications "
                . "UNION SELECT id as idx, name, name, id,  'application.gif' as type,'applications' as table_name, vsys, 'fa fa-list-alt' AS icon, if (vsys = 'shared', '#cf1cbc', '#235585') AS color FROM applications $query "
                . "UNION SELECT id as idx, name, name, id, 'application-filters.png' as type,'applications_filters' as table_name, vsys, 'fa fa-filter' AS icon, if (vsys = 'shared', '#cf1cbc', '#235585') AS color FROM applications_filters $query "
                . "UNION SELECT id as idx, name, name, id, 'application_group.gif' as type,'applications_groups_id' as table_name, vsys, 'fa fa-object-group' AS icon, if (vsys = 'shared', '#cf1cbc', '#235585') AS color FROM applications_groups_id $query ;");

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
    elseif ($type == "ports") {

        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $idx = $projectdb->real_escape_string((string) (isset($_POST['idx']) ? $_POST['idx'] : $_GET['idx']));
        $table_name = $projectdb->real_escape_string((string) (isset($_POST['table_name']) ? $_POST['table_name'] : $_GET['table_name']));

        if (($idx != "") AND ( $table_name != "")) {
            $tags = array();
            //$getTag = $projectdb->query("SELECT value FROM $table_name WHERE id='$idx' AND default_type='port';");
            $getTag = $projectdb->query("SELECT ports FROM applications_ports WHERE member_lid = '$idx';");
            if ($getTag->num_rows > 0) {
                while($getTagData = $getTag->fetch_assoc()){
                    $tags[] = array("name" => $getTagData['ports']);
                }

                /*$tag = explode(",", $tags);
                $count = count($tag);
                foreach ($tag as $key => $value) {
                    $thetag[] = array("name" => $value);
                }*/
                $count = count($tags);
                if ($tags == "") {
                    $count = 0;
                    $tags = "";
                }
                echo '{"total":"' . $count . '","tags":' . json_encode($tags) . '}';
            }
        }
    }
    elseif ($type == "tag") {
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $idx = $projectdb->real_escape_string((string) (isset($_POST['idx']) ? $_POST['idx'] : $_GET['idx']));
        $table_name = $projectdb->real_escape_string((string) (isset($_POST['table_name']) ? $_POST['table_name'] : $_GET['table_name']));

        if ($idx != "") {

            $query = "SELECT tag.name as name, tag.id as id FROM tag, tag_relations 
              WHERE tag_relations.member_lid='".$idx."' AND tag_relations.table_name='applications' AND tag.id = tag_relations.tag_id";

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
} 
elseif($action == "convert"){
    if(!checkProjectRights($project,'update')){
        echo json_encode(array("success"=>false, "msg"=>"You do not have update rights in this project."));
        return;
    }
    if($type == "shared"){
        $ids = $projectdb->real_escape_string((string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']));
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        if ($ids != "") {
            take_snapshot_last($project);
            $members_Applications = explode(',',$ids);
            $return = convertApplicationsToShared($source, $members_Applications, "notall");
            if($return == 1){
                echo json_encode(array("success" => true));
            }else{
                echo json_encode(array("success" => false));
            } 
        }
    }
    elseif ($type == "clone") {
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $ids = $projectdb->real_escape_string((string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']));
        $clone_to_vsys = (string) (isset($_POST['combo']) ? $_POST['combo'] : $_GET['combo']);
        if ($ids != "") {
            take_snapshot_last($project);
            $members_Applications = explode(',',$ids);
            $return = cloneApplications($source, $vsys, $clone_to_vsys, $members_Applications);
            if($return != 0){
                echo json_encode(array("success" => true));
            }else{
                echo json_encode(array("success" => false));
            }  
        }
    }
}
?>