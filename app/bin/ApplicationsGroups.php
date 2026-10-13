<?php

# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';
require_once('./Authentication.php');
require_once '../libs/shared.php';

require_once INC_ROOT.'/libs/projectdb.php';
require_once INC_ROOT.'/userManager/API/projects/manageSettings.php';

include INC_ROOT.'/bin/middleware_sanitizer.php';

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $action      = (string)  (isset($_GET['action'])    ? $_GET['action'] : '');
        $type        = (string)  (isset($_GET['type'])      ? $_GET['type'] : ''); // zip / xml / device
        $project     = (string)  (isset($_GET['project'])   ? $_GET['project'] : '');
        $devicename  = (string)  (isset($_GET['devicename'])? $_GET['devicename'] : '');
        $start       = (integer) (isset($_GET['start'])     ? $_GET['start'] : '');
        $limit       = (integer) (isset($_GET['limit'])     ? $_GET['limit'] : '');
        $search      = (string)  (isset($_GET['search'])    ? $_GET['search'] : '');
        $hide_shared = (string)  (isset($_GET['hide_shared_app_groups'])  ? $_GET['hide_shared_app_groups'] : '');
        $applications_filters   = (string) (isset($_GET['applications_filters'])    ? $_GET['applications_filters'] : '');

        break;
    case 'POST':
        $action      = (string)  (isset($_POST['action'])    ? $_POST['action'] : '');
        $type        = (string)  (isset($_POST['type'])      ? $_POST['type'] : ''); // zip / xml / device
        $project     = (string)  (isset($_POST['project'])   ? $_POST['project'] : '');
        $devicename  = (string)  (isset($_POST['devicename'])? $_POST['devicename'] : '');
        $start       = (integer) (isset($_POST['start'])     ? $_POST['start'] : '');
        $limit       = (integer) (isset($_POST['limit'])     ? $_POST['limit'] : '');
        $search      = (string)  (isset($_POST['search'])    ? $_POST['search'] : '');
        $hide_shared = (string)  (isset($_POST['hide_shared_app_groups']) ? $_POST['hide_shared_app_groups'] : '');
        $applications_filters   = (string) (isset($_POST['applications_filters'])   ? $_POST['applications_filters'] : '');

        break;

    default:
        $action      = (string)  (isset($_POST['action'])    ? $_POST['action'] : '');
        $type        = (string)  (isset($_POST['type'])      ? $_POST['type'] : ''); // zip / xml / device
        $project     = (string)  (isset($_POST['project'])   ? $_POST['project'] : '');
        $devicename  = (string)  (isset($_POST['devicename'])? $_POST['devicename'] : '');
        $start       = (integer) (isset($_POST['start'])     ? $_POST['start'] : '');
        $limit       = (integer) (isset($_POST['limit'])     ? $_POST['limit'] : '');
        $search      = (string)  (isset($_POST['search'])    ? $_POST['search'] : '');
        $hide_shared = (string)  (isset($_POST['hide_shared_app_groups']) ? $_POST['hide_shared_app_groups'] : '');
        $applications_filters   = (string) (isset($_POST['applications_filters'])   ? $_POST['applications_filters'] : '');

        break;
}

$projectdb = selectDatabase($project);

$action = $projectdb->real_escape_string($action);
$type = $projectdb->real_escape_string($type);
$project = $projectdb->real_escape_string($project);
$devicename = $projectdb->real_escape_string($devicename);
$start = $projectdb->real_escape_string($start);
$limit = $projectdb->real_escape_string($limit);
$search = $projectdb->real_escape_string($search);
$hide_shared = $projectdb->real_escape_string($hide_shared);
$applications_filters = $projectdb->real_escape_string($applications_filters);

global $app;
$user = $app->container->sentinel->getUser();
$user_id = $user->id;

if ($action == "get") {
    
    $query = generate_query("objects");
    $conditions = generate_query_multitable("objects");
    
    if ($type == "appgroups_only_names") {
        
        if ($search != "") {
            if (preg_match("/WHERE/", $conditions)) {
                $conditions .= " AND name LIKE '%$search%'";
            } else {
                $conditions .= " WHERE name LIKE '%$search%'";
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
        $getAll = $projectdb->query("SELECT count(*) as total FROM applications_groups_id a $conditions");
        $row = $getAll->fetch_assoc();
        $count = $row['total'];
        if ($count > 0) {
            $getLimit = $projectdb->query("SELECT * FROM applications_groups_id a $conditions ORDER BY name ASC LIMIT $start, $limit;");
        }
        $i = 1;
        $arr2 = array();
        if ($count > 0) {
            $x = 0;
            while ($dataAG = $getLimit->fetch_assoc()) {
                $id_group = $dataAG['id'];
                $group_name = $dataAG['name'];
                $devicegroup = $dataAG['devicegroup'];
                $tablename_group = 'applications_groups_id';
                $source = $dataAG['source'];
                $vsys_group = $dataAG['vsys'];
                
                if ($tablename_group == "applications_groups_id") {
                    $tablename_group = "applications_groups";
                }
                
                $id_group_table_name = $id_group.";".$tablename_group;
                $icon = "fa fa-object-ungroup";
                if ($vsys_group == "shared") {
                    $img = "shared_applications_groups.gif";
                    $color = "#cf1cbc";
                }else{
                    $img = "applications_groups.gif";
                    $color = "#235585";
                }
                
                $arr2[] = '{"idx":"' . $id_group . '","uid":' . $x . ', "table_name":"' . $tablename_group . '", "id_group_table_name" : "'.$id_group_table_name.'","name":"' . $group_name . '", "name_ext":"' . $group_name . '", "vsys":"' . $vsys_group . '", "devicegroup":' . json_encode($devicegroup) . ', "img":"' . $img . '","icon":"' . $icon . '","color":"' . $color . '"}';
                $x++;
            }
            $applications_groups = implode(",", $arr2);
            echo '{"total":"' . $count . '","apps":[' . $applications_groups . ']}';
        } else {
            echo '{"total":"0","apps":[]}';
        }
        
    }
    elseif ($type == "members") {
        
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $idx = $projectdb->real_escape_string((string) (isset($_POST['idx']) ? $_POST['idx'] : $_GET['idx']));
        $table_name = $projectdb->real_escape_string((string) (isset($_POST['table_name']) ? $_POST['table_name'] : $_GET['table_name']));
        //$query = generate_query("objects");

        if($idx == ""){
            $idx = 0;
        }

        $query = "WHERE lid='$idx'";

        $getSource = $projectdb->query("SELECT id, table_name, member_lid FROM $table_name $query");
        if ($getSource->num_rows > 0) {
            $Source = array();
            while ($src = $getSource->fetch_assoc()) {
                $src_table_name = $src['table_name'];
                $src_member_lid = $src['member_lid'];
                $id = $src['id'];

                list($image, $vsys_member, $name, $myip) = getIcon("applications", $src_table_name, $src_member_lid, "");

                $getBridge = $projectdb->query("SELECT id FROM edit_table WHERE lid = '$idx' AND member_lid = '$src_member_lid' AND table_name_lid = '$src_table_name' AND type = 'members' AND name = '$name' AND user_id = '$user_id';");
                if ($getBridge->num_rows == 0) {
                    $projectdb->query("INSERT INTO edit_table (id, ids, lid, member_lid, table_name_lid, type, name, image, vsys, vsys_member, source, remove, user_id) "
                        . "VALUES ('NULL', '$id', '$idx', '$src_member_lid', '$src_table_name', 'members', '$name', '$image','$vsys', '$vsys_member','$source', '0', '$user_id');");
                }
                
                $getBridgeData = $projectdb->query("SELECT image, name, member_lid, table_name_lid, source, vsys, vsys_member, ids FROM edit_table WHERE lid = '$idx' AND type = 'members' AND remove = '0' AND user_id = '$user_id';");
                if ($getBridgeData->num_rows >= 1) {

                    while($getData = $getBridgeData->fetch_assoc()){
                        $image_sql = $getData['image'];
                        $name_sql = $getData['name'];
                        $member_lid_sql = $getData['member_lid'];
                        $table_name_sql = $getData['table_name_lid'];
                        $source_sql = $getData['source'];
                        $vsys_sql = $getData['vsys'];
                        $vsys_member = $getData['vsys_member'];
                        $ids_sql = $getData['ids'];
                        $Source[] = '{"img":"' . $image_sql . '","name":"' . $name_sql . '","member_lid":"' . $member_lid_sql . '","table_name":"' . $table_name_sql . '","source":"' . $source_sql . '","vsys":"' . $vsys_sql . '", "vsys_member":"' . $vsys_member . '", "id":"' . $ids_sql . '"}';

                    }
                }
            }

            echo '{"total":"' . $getSource->num_rows . '","rows":[' . implode(",", $Source) . ']}';
        }
        else {
            
            $getBridgeData = $projectdb->query("SELECT image, name, member_lid, table_name_lid, source, vsys, vsys_member, ids FROM edit_table WHERE lid = '$idx' AND type = 'members' AND remove = '0' AND user_id = '$user_id';");
            if ($getBridgeData->num_rows >= 1) {
            
                while($getData = $getBridgeData->fetch_assoc()){
                    $image_sql = $getData['image'];
                    $name_sql = $getData['name'];
                    $member_lid_sql = $getData['member_lid'];
                    $table_name_sql = $getData['table_name_lid'];
                    $source_sql = $getData['source'];
                    $vsys_sql = $getData['vsys'];
                    $vsys_member = $getData['vsys_member'];
                    $ids_sql = $getData['ids'];
                    $Source[] = '{"img":"' . $image_sql . '","name":"' . $name_sql . '","member_lid":"' . $member_lid_sql . '","table_name":"' . $table_name_sql . '","source":"' . $source_sql . '","vsys":"' . $vsys_sql . '", "vsys_member":"' . $vsys_member . '", "id":"' . $ids_sql . '"}';
                
                }
                echo '{"total":"' . $getSource->num_rows . '","rows":[' . implode(",", $Source) . ']}';
             
            }else{
                echo '{"total":0,"rows":[]}';
            }
        }
    }
}
elseif($action == "add"){
    
    if ($type == "member") {

        $idx = $projectdb->real_escape_string((string) (isset($_POST['idx']) ? $_POST['idx'] : $_GET['idx']));
        $name = $projectdb->real_escape_string((string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']));
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $member_lid = $projectdb->real_escape_string((string) (isset($_POST['member_lid']) ? $_POST['member_lid'] : $_GET['member_lid']));
        $member_table_name = $projectdb->real_escape_string((string) (isset($_POST['member_table_name']) ? $_POST['member_table_name'] : $_GET['member_table_name']));
        $table_name = $projectdb->real_escape_string((string) (isset($_POST['table_name']) ? $_POST['table_name'] : $_GET['table_name']));
        $is_the_same = 0;
        //control errors
        if (preg_match("/groups/i", $member_table_name)) {
            if ($table_name == "applications_groups") {
                $table_name_g = "applications_groups_id";
            } 
            if(($member_table_name == $table_name_g) && ($idx == $member_lid)){
                // Insert the same group
                $is_the_same = 1;
            }
        }
        
        if($is_the_same == 0){
            //Edit_update
            list($image, $vsys_member, $name_member, $myip) = getIcon("applications", $member_table_name, $member_lid, "");

            $getBridge = $projectdb->query("SELECT id FROM edit_table WHERE lid = '$idx' AND member_lid = '$member_lid' AND table_name_lid = '$member_table_name' AND type = 'members' AND user_id = '$user_id';");
            if ($getBridge->num_rows == 0) {

                $getBridgeId = $projectdb->query("SELECT MAX(ids) AS ids FROM edit_table WHERE lid = '$idx' AND type = 'members' AND user_id = '$user_id';");
                if ($getBridgeId->num_rows == 1) {
                   $getIdData = $getBridgeId->fetch_assoc();
                   $ids = $getIdData['ids'] + 1;
                }else{
                    $ids = 1;
                }
                $projectdb->query("INSERT INTO edit_table (id, ids,lid, member_lid, table_name_lid, type, name, image, vsys, vsys_member, source, remove, user_id) "
                    . "VALUES (NULL, '$ids','$idx', '$member_lid', '$member_table_name', 'members', '$name_member', '$image','$vsys', '$vsys_member', '$source', '0', '$user_id');");

            }else{
                $projectdb->query("UPDATE edit_table SET remove = '0' WHERE lid = '$idx' AND member_lid = '$member_lid' AND table_name_lid = '$member_table_name' AND BINARY name = '$name_member' AND type = 'members' AND user_id = '$user_id' ;");
            }
        }
        
    }
}
elseif ($action == "set"){
    
    if ($type == "remove_member") {

        $idx = $projectdb->real_escape_string((string) (isset($_POST['idx']) ? $_POST['idx'] : $_GET['idx']));
        $table_name = $projectdb->real_escape_string((string) (isset($_POST['table_name']) ? $_POST['table_name'] : $_GET['table_name']));
        $ids = $projectdb->real_escape_string((string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']));
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        
        if ($ids != "") {
            
            $data = explode(",", $ids);
            
            foreach ($data as $key => $value) {
                $projectdb->query("UPDATE edit_table SET remove = '1' WHERE ids = '$value' AND lid = '$idx' AND type = 'members' AND user_id = '$user_id';");
            }
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
            $members_ApplicationGroups = explode(',',$ids);
            $return = convertApplicationsGroupsToShared($source, $members_ApplicationGroups, "notall");
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
            $members_ApplicationGroups = explode(',',$ids);
            $return = cloneApplicationsGroups($source, $vsys, $clone_to_vsys, $members_ApplicationGroups);
            if($return != 0){
                echo json_encode(array("success" => true));
            }else{
                echo json_encode(array("success" => false));
            }  
        }
    }
}
elseif ($action == "update") {

    if($type == "member"){
        
        $name = $projectdb->real_escape_string((string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']));
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $id = $projectdb->real_escape_string((string) (isset($_POST['id']) ? $_POST['id'] : $_GET['id']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $member_lid = $projectdb->real_escape_string((string) (isset($_POST['member_lid']) ? $_POST['member_lid'] : $_GET['member_lid']));
        $table_name = $projectdb->real_escape_string((string) (isset($_POST['member_table_name']) ? $_POST['member_table_name'] : $_GET['member_table_name']));
        $idx = $projectdb->real_escape_string((string) (isset($_POST['idx']) ? $_POST['idx'] : $_GET['idx']));
        
        if (($member_lid != "") AND ($table_name != "")){
            
            $projectdb->query("UPDATE edit_table SET remove = '1' WHERE ids = '$id' AND type = 'members' AND user_id = '$user_id';");
            list($image, $vsys_member, $name_member, $myip) = getIcon("applications", $table_name, $member_lid, "");

            $getExistRemove = $projectdb->query("SELECT id FROM edit_table WHERE type = 'members' AND member_lid = '$member_lid' AND table_name_lid = '$table_name' AND lid = '$idx' AND remove = '1' AND user_id = '$user_id';");
            if($getExistRemove->num_rows == 1){
                $dataExist = $getExistRemove->fetch_assoc();
                $id_exist = $dataExist['id'];
                $projectdb->query("UPDATE edit_table SET remove = '0' WHERE id = '$id_exist' AND user_id = '$user_id';");
                
            }else{
                $getBridgeId = $projectdb->query("SELECT MAX(ids) AS ids FROM edit_table WHERE type = 'members' AND user_id = '$user_id';");
                if ($getBridgeId->num_rows == 1) {
                   $getIdData = $getBridgeId->fetch_assoc();
                   $ids = $getIdData['ids'] + 1;
                }else{
                    $ids = 1;
                }
                $getExistRemove = $projectdb->query("SELECT id FROM edit_table WHERE type = 'members' AND member_lid = '$member_lid' AND table_name_lid = '$table_name' AND lid = '$idx' AND remove = '0' AND user_id = '$user_id';");
                if($getExistRemove->num_rows == 0){
                    if(($table_name == "applications_groups_id") && ($idx == $member_lid)){
                    }else{
                        $projectdb->query("INSERT INTO edit_table (id, ids, lid, member_lid, table_name_lid, type, name, image, vsys, vsys_member, source, remove, user_id) "
                        . "VALUES (NULL, '$ids', '$idx', '$member_lid', '$table_name', 'members', '$name_member', '$image', '$vsys', '$vsys_member', '$source', '0', '$user_id');");
                    }
                }
            }
            echo json_encode(array("success"=>true));
        }
        else{
            echo json_encode(array("success"=>false));
        }
        
    }
}