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

require_once INC_ROOT.'/userManager/API/projects/manageSettings.php';
require_once INC_ROOT.'/libs/projectdb.php';

include INC_ROOT.'/bin/middleware_sanitizer.php';

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $action     = (string)  (isset($_GET['action'])    ? $_GET['action'] : '');
        $type       = (string)  (isset($_GET['type'])      ? $_GET['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_GET['project'])   ? $_GET['project'] : '');
        $vsys       = (string)  (isset($_GET['vsys'])      ? $_GET['vsys'] : '');
        $source     = (string)  (isset($_GET['source'])    ? $_GET['source'] : '');
        $filter     = (string)  (isset($_GET['filter'])    ? $_GET['filter'] : '');
        $search     = (string)  (isset($_GET['search'])    ? $_GET['search'] : '');
        $start      = (integer) (isset($_GET['start'])     ? $_GET['start'] : '');
        $limit      = (integer) (isset($_GET['limit'])     ? $_GET['limit'] : '');
        $idx        = (string)  (isset($_GET['idx'])       ? $_GET['idx'] : '');
        $table_name = (string)  (isset($_GET['table_name'])? $_GET['table_name'] : '');
        $name       = (string)  (isset($_GET['name'])      ? $_GET['name'] : '');
        $name_ext   = (string)  (isset($_GET['name_ext'])  ? $_GET['name_ext'] : '');
        $name_int   = (string)  (isset($_GET['name'])      ? $_GET['name'] : '');
        $description= (string)  (isset($_GET['description'])? $_GET['description'] : '');
        $ids        = (string)  (isset($_GET['ids'])       ? $_GET['ids'] : '');
        $member_lid = (string)  (isset($_GET['member_lid'])? $_GET['member_lid'] : '');
        $member_table_name = (string) (isset($_GET['member_table_name']) ? $_GET['member_table_name'] : '');
        $data       = (string)  (isset($_GET['data'])      ? $_GET['data'] : '');
        $id         = (string)  (isset($_GET['id'])        ? $_GET['id'] : '');
        $clone_to_vsys=(string) (isset($_GET['combo'])     ? $_GET['combo'] : '');
        $oldname    = (string)  (isset($_GET['oldname'])   ? $_GET['oldname'] : '');
        $names_tags  = (string)  (isset($_GET['names_tags'])   ? $_GET['names_tags'] : '');

        break;
    case 'POST':
        $action     = (string)  (isset($_POST['action'])    ? $_POST['action'] : '');
        $type       = (string)  (isset($_POST['type'])      ? $_POST['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_POST['project'])   ? $_POST['project'] : '');
        $vsys       = (string)  (isset($_POST['vsys'])      ? $_POST['vsys'] : '');
        $source     = (string)  (isset($_POST['source'])    ? $_POST['source'] : '');
        $filter     = (string)  (isset($_POST['filter'])    ? $_POST['filter'] : '');
        $search     = (string)  (isset($_POST['search'])    ? $_POST['search'] : '');
        $start      = (integer) (isset($_POST['start'])     ? $_POST['start'] : '');
        $limit      = (integer) (isset($_POST['limit'])     ? $_POST['limit'] : '');
        $idx        = (string)  (isset($_POST['idx'])       ? $_POST['idx'] : '');
        $table_name = (string)  (isset($_POST['table_name'])? $_POST['table_name'] : '');
        $name       = (string)  (isset($_POST['name'])      ? $_POST['name'] : '');
        $name_ext   = (string)  (isset($_POST['name_ext'])  ? $_POST['name_ext'] : '');
        $name_int   = (string)  (isset($_POST['name'])      ? $_POST['name'] : '');
        $description= (string)  (isset($_POST['description'])? $_POST['description'] : '');
        $ids        = (string)  (isset($_POST['ids'])       ? $_POST['ids'] : '');
        $member_lid = (string)  (isset($_POST['member_lid'])? $_POST['member_lid'] : '');
        $member_table_name = (string) (isset($_POST['member_table_name']) ? $_POST['member_table_name'] : '');
        $data       = (string)  (isset($_POST['data'])      ? $_POST['data'] : '');
        $id         = (string)  (isset($_POST['id'])        ? $_POST['id'] : '');
        $clone_to_vsys=(string) (isset($_POST['combo'])     ? $_POST['combo'] : '');
        $oldname    = (string)  (isset($_POST['oldname'])   ? $_POST['oldname'] : '');
        $names_tags  = (string)  (isset($_POST['names_tags'])   ? $_POST['names_tags'] : '');

        break;

    default:
        $action     = (string)  (isset($_POST['action'])    ? $_POST['action'] : '');
        $type       = (string)  (isset($_POST['type'])      ? $_POST['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_POST['project'])   ? $_POST['project'] : '');
        $vsys       = (string)  (isset($_POST['vsys'])      ? $_POST['vsys'] : '');
        $source     = (string)  (isset($_POST['source'])    ? $_POST['source'] : '');
        $filter     = (string)  (isset($_POST['filter'])    ? $_POST['filter'] : '');
        $search     = (string)  (isset($_POST['search'])    ? $_POST['search'] : '');
        $start      = (integer) (isset($_POST['start'])     ? $_POST['start'] : '');
        $limit      = (integer) (isset($_POST['limit'])     ? $_POST['limit'] : '');
        $idx        = (string)  (isset($_POST['idx'])       ? $_POST['idx'] : '');
        $table_name = (string)  (isset($_POST['table_name'])? $_POST['table_name'] : '');
        $name       = (string)  (isset($_POST['name'])      ? $_POST['name'] : '');
        $name_ext   = (string)  (isset($_POST['name_ext'])  ? $_POST['name_ext'] : '');
        $name_int   = (string)  (isset($_POST['name'])      ? $_POST['name'] : '');
        $description= (string)  (isset($_POST['description'])? $_POST['description'] : '');
        $ids        = (string)  (isset($_POST['ids'])       ? $_POST['ids'] : '');
        $member_lid = (string)  (isset($_POST['member_lid'])? $_POST['member_lid'] : '');
        $member_table_name = (string) (isset($_POST['member_table_name']) ? $_POST['member_table_name'] : '');
        $data       = (string)  (isset($_POST['data'])      ? $_POST['data'] : '');
        $id         = (string)  (isset($_POST['id'])        ? $_POST['id'] : '');
        $clone_to_vsys=(string) (isset($_POST['combo'])     ? $_POST['combo'] : '');
        $oldname    = (string)  (isset($_POST['oldname'])   ? $_POST['oldname'] : '');
        $names_tags  = (string)  (isset($_POST['names_tags'])   ? $_POST['names_tags'] : '');

        break;
}

if ($limit == "All") {
    $limit = 150000;
}

$projectdb = selectDatabase($project);

$action = $projectdb->real_escape_string($action);
$type = $projectdb->real_escape_string($type);
$project = $projectdb->real_escape_string($project);
$vsys = $projectdb->real_escape_string($vsys);
$source = $projectdb->real_escape_string($source);
$filter = $projectdb->real_escape_string($filter);
$search = $projectdb->real_escape_string($search);
$start = $projectdb->real_escape_string($start);
$limit = $projectdb->real_escape_string($limit);
$idx = $projectdb->real_escape_string($idx);
$table_name = $projectdb->real_escape_string($table_name);
$name = $projectdb->real_escape_string($name);
$name_ext = $projectdb->real_escape_string($name_ext);
$name_int = $projectdb->real_escape_string($name_int);
$description = $projectdb->real_escape_string($description);
$ids = $projectdb->real_escape_string($ids);
$member_lid = $projectdb->real_escape_string($member_lid);
$member_table_name = $projectdb->real_escape_string($member_table_name);
$data = $projectdb->real_escape_string($data);
$id = $projectdb->real_escape_string($id);
$clone_to_vsys = $projectdb->real_escape_string($clone_to_vsys);
$oldname = $projectdb->real_escape_string($oldname);
$names_tags = $projectdb->real_escape_string($names_tags);

global $app;
$user = $app->container->sentinel->getUser();
$user_id = $user->id;

if ($action == "get") {
    if ($type == "servicesgroups_only_names") {
        
        $conditions = generate_query_multitable("objects");

        $getAll = $projectdb->query("SELECT id as idx,name,vsys,if (vsys = 'shared', 'shared_services_groups_id', 'services_groups_id') AS table_name, 'fa fa-cogs' AS icon, if (vsys = 'shared', '#cf1cbc', '#235585') AS color, source,tag,used,devicegroup,name_ext,id "
            . "FROM services_groups_id a  $conditions;");
        $count = $getAll->num_rows;
        $getLimit = $projectdb->query("SELECT id as idx,name,vsys,if (vsys = 'shared', 'shared_services_groups_id', 'services_groups_id') AS table_name, 'fa fa-cogs' AS icon, if (vsys = 'shared', '#cf1cbc', '#235585') AS color, source,tag,used,devicegroup,name_ext,id "
            . "FROM services_groups_id a  $conditions ORDER BY a.name ASC LIMIT $start, $limit;");

        $i = 1;
        $arr2 = array();
        if ($count > 0) {
            $x = 0;
            while ($Tags = $getLimit->fetch_assoc()) {
                $groupname = $Tags['name'];
                $idgroup = $Tags['id'];
                $Original = $Tags['name_ext'];
                $Devicegroup = $Tags['devicegroup'];
                $tablenamegroup = $Tags['table_name'];
                $source = $Tags['source'];
                $usedgroup = $Tags['used'];
                $icon = $Tags['icon'];
                $color = $Tags['color'];
                $vsysgroup = $Tags['vsys'];
                $taggroup = $Tags['tag'];
                $idx = $Tags['idx'];
                $filtergroup = "";

                $id_group_table_name = $idgroup.";services_groups";
                
                $arr2[] = '{"idx":"' . $idx . '","uid":' . $x . ',"tag":"' . $taggroup . '","id":"' . $idgroup . '","table_name":"' . $tablenamegroup . '", "id_group_table_name" : "'.$id_group_table_name.'","name":"' . $groupname . '","name_ext":"' . $Original . '","vsys":"' . $vsysgroup . '","img":"' . $tablenamegroup . '.gif","icon":"' . $icon . '","color":"' . $color . '","used":"' . $usedgroup . '","devicegroup":' . json_encode($Devicegroup) . '}';
                $x++;
            }

            $services = implode(",", $arr2);
            echo '{"total":"' . $count . '","rows":[' . $services . ']}';
        } else {
            echo '{"total":"0","rows":[]}';
        }
    }
    elseif ($type == "tag") {
        if ($table_name == "services_groups") {
            $table_name = "services_groups_id";
        }
        if (($idx != "") AND ( $table_name != "")) {

            $query = "SELECT tag.name as name, tag.id as id FROM tag, tag_relations 
              WHERE tag_relations.member_lid=".$idx." AND tag_relations.table_name='services_groups_id' AND tag.id = tag_relations.tag_id";

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
    elseif ($type == "members") {

        //$query = generate_query("objects");

        if($idx == ""){
            $idx = 0;
        }

        $query = " WHERE lid='$idx' ";

        $getSource = $projectdb->query("SELECT id,table_name,member_lid FROM $table_name $query");
        if ($getSource->num_rows > 0) {
            $Source = array();
            while ($src = $getSource->fetch_assoc()) {
                $src_table_name = $src['table_name'];
                $src_member_lid = $src['member_lid'];
                $id = $src['id'];

                list($image, $vsys_member, $name, $myip) = getIcon("services", $src_table_name, $src_member_lid, "");

                $getBridge = $projectdb->query("SELECT id FROM edit_table WHERE lid = '$idx' AND member_lid = '$src_member_lid' AND table_name_lid = '$src_table_name' AND type = 'members' AND name = '$name' AND user_id = '$user_id';");
                if ($getBridge->num_rows == 0) {
                    $projectdb->query("INSERT INTO edit_table (id, ids, lid, member_lid, table_name_lid, type, name, image, vsys, vsys_member, source, remove, user_id) "
                        . "VALUES ('NULL', '$id', '$idx', '$src_member_lid', '$src_table_name', 'members', '$name', '$image','$vsys', '$vsys_member', '$source', '0', '$user_id');");
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
            }
            else{
                echo '{"total":0,"rows":[]}';
            }
        }
    }
}
elseif ($action == "transform"){
    if ($type == "group_to_services") {
        
        take_snapshot_last($project);
        $table_name_group = "services_groups";
        
        $remove_groups = array();

        if ($data != "") {
            $condition = " WHERE lid IN ($data) ";
        }else{
            $condition = " ";
        }

        $getAll = $projectdb->query("SELECT id, lid, member_lid, table_name, vsys,source, COUNT(lid) AS t FROM services_groups $condition GROUP BY lid HAVING t=1 ORDER BY table_name DESC;");
        //echo "1. SELECT id, lid, member_lid, table_name, vsys,source, COUNT(lid) AS t FROM services_groups $condition GROUP BY lid HAVING t=1 ORDER BY table_name;\n";

        if ($getAll->num_rows > 0) {
            while ($data = $getAll->fetch_assoc()) {
                $lid = $data['lid'];
                $member_lid = $data['member_lid'];
                $table_name = $data['table_name'];

                $projectdb->query("UPDATE services_groups SET member_lid='$member_lid', table_name='$table_name' WHERE member_lid='$lid' AND table_name='services_groups_id';");
                $projectdb->query("UPDATE security_rules_srv SET member_lid='$member_lid', table_name='$table_name' WHERE member_lid='$lid' AND table_name='services_groups_id';");
                $projectdb->query("UPDATE nat_rules SET op_service_lid='$member_lid',op_service_table='$table_name' WHERE source='$source' AND op_service_lid='$lid' AND op_service_table='services_groups_id';");
                #UPDATE LOGS TO THE NEW Rule
                $projectdb->query("UPDATE logs SET obj_id='$member_lid',obj_table='$table_name' WHERE obj_id='$lid' AND obj_table='services_groups_id' AND source='$source'");
                $remove_groups[] = $lid;

                clean_duplicated_members_merging("security_rules_srv", $member_lid, $table_name);

                $getNamePanOld = $projectdb->query("SELECT name FROM services_groups_id WHERE id = '$lid' ;");
                if ($getNamePanOld->num_rows > 0) {
                    $dataNPO = $getNamePanOld->fetch_array();
                    $name_int_old = $dataNPO['name'];
                }

                $getNamePanNew = $projectdb->query("SELECT name FROM $table_name WHERE id = '$member_lid' ;");
                if ($getNamePanNew->num_rows > 0) {
                    $dataNP = $getNamePanNew->fetch_array();
                    $name_int_new = $dataNP['name'];
                }

                require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
                $sql_vsys = prepareVsysQuery($projectdb, $vsys, $source);

                $getOtherRules = $projectdb->query("SELECT id, xml FROM other_rules WHERE source = '$source' $sql_vsys ;");

                if ($getOtherRules->num_rows > 0) {

                    $other_rules_address = array();

                    while ($dataO = $getOtherRules->fetch_array()) {

                        $is_change = 0;
                        $other_rules_service = array();

                        $xml_bbdd = $dataO['xml'];
                        $id_xml = $dataO['id'];
                        $xml = simplexml_load_string($xml_bbdd);

                        foreach ($xml->entry as $data) {

                            $other_rules_service = array();

                            if (isset($data->service)){
                                foreach($data->service->member as $member){
                                    if($member != "any") {
                                        $other_rules_service[] = $member;
                                    }
                                }
                            }

                            if (isset($data->service)){

                                $i = 0;
                                $is_change = 0;
                                $positions_to_remove = array();

                                foreach($data->service->member as $member2){
                                    if($member2 != "any"){
                                        if ($member2 == $name_int_old) {
                                            $is_change = 1;
                                            // Elimiar el grupo convertido en miembro
                                            $positions_to_remove[] = $i;
                                        }
                                    }
                                    $i++;
                                }

                                if(count($positions_to_remove) > 0){
                                    rsort($positions_to_remove);
                                    foreach($positions_to_remove AS $rm){
                                        unset($data->service->member[$rm]);
                                    }
                                }
                                if($is_change == 1){
                                    if (in_array($name_int_new, $other_rules_service)) {
                                        //echo "EXISTE YA EL MIEMBRO, NO AÑADIR!\n";
                                    }else{
                                        $data->service->addChild('member', $name_int_new);
                                    }
                                }
                            }
                        }

                        $new_xml = $xml->asXML();
                        $new_xml = str_replace('<?xml version="1.0"?>', "", $new_xml);
                        $new_xml = addslashes($new_xml);
                        $projectdb->query("UPDATE other_rules SET xml = '$new_xml' WHERE id = '$id_xml' ;");

                    }// fin while x cada other rules
                }
            }
        }

        clean_duplicated_members("services_groups");

        if (count($remove_groups) > 0) {
            $projectdb->query("DELETE FROM ".$table_name_group."_id WHERE id IN (" . implode(",", $remove_groups) . ");");
            $projectdb->query("DELETE FROM $table_name_group WHERE lid IN (" . implode(",", $remove_groups) . ");");
            
            check_used_objects_new();
        }
    } 
}
elseif ($action == "set") {
    if ($type == "remove_member") {
        if ($ids != "") {
            $data = explode(",", $ids);
            foreach ($data as $key => $value) {
                $projectdb->query("UPDATE edit_table SET remove = '1' WHERE ids = '$value' AND lid = '$idx' AND type = 'members' AND user_id = '$user_id';");
            }
        }
    }
} 
elseif ($action == "add") {
    if ($type == "member") {
        $is_the_same = 0;        
        //control errors
        if (preg_match("/groups/i", $member_table_name)) {
            if ($table_name == "services_groups") {
                $table_name_g = "services_groups_id";
            } 
            if(($member_table_name == $table_name_g) && ($idx == $member_lid)){
                // Insert the same group
                $is_the_same = 1;
            }
        }
        if($idx == ""){
            $idx = 0;
        }
        
        if($is_the_same == 0){
            //Edit_update
            list($image, $vsys_member, $name_member, $myip) = getIcon("services", $member_table_name, $member_lid, "");

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
                $projectdb->query("UPDATE edit_table SET remove = '0' WHERE lid = '$idx' AND member_lid = '$member_lid' AND table_name_lid = '$member_table_name' AND BINARY name = '$name_member' AND type = 'members' AND user_id = '$user_id';");
            }
        }
    }
}
elseif ($action == "update") {
    if($type == "member"){
        switch($_SERVER['REQUEST_METHOD'])
        {
            case 'GET':
                $table_name = (string) (isset($_GET['member_table_name']) ? $_GET['member_table_name'] : '');
                break;
            case 'POST':
                $table_name = (string) (isset($_POST['member_table_name']) ? $_POST['member_table_name'] : '');
                break;
            default:
                $table_name = (string) (isset($_POST['member_table_name']) ? $_POST['member_table_name'] : '');
                break;
        }

        $table_name = $projectdb->real_escape_string($table_name);
        
        if($idx == ""){
            $idx = 0;
        }

        $entryInfo = $projectdb->query("SELECT vsys, source FROM services_groups_id WHERE id='$idx'");
        if($entryInfo->num_rows>0){
            $queryData = $entryInfo->fetch_assoc();
            $vsys = $queryData['vsys'];
            $source = $queryData['source'];
        }
        
        if (($member_lid != "") AND ($table_name != "")){
            
            $projectdb->query("UPDATE edit_table SET remove = '1' WHERE ids = '$id' AND type = 'members' AND user_id = '$user_id';");

            list($image, $vsys_member, $name_member, $myip) = getIcon("services", $table_name, $member_lid, "");

            $getExistRemove = $projectdb->query("SELECT id FROM edit_table WHERE type = 'members' AND member_lid = '$member_lid' AND table_name_lid = '$table_name' AND lid = '$idx' AND remove = '1' AND user_id = '$user_id';");
            if($getExistRemove->num_rows == 1){
                $dataExist = $getExistRemove->fetch_assoc();
                $id_exist = $dataExist['id'];
                $projectdb->query("UPDATE edit_table SET remove = '0' WHERE id = '$id_exist';");
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
                    if(($table_name == "services_groups_id") && ($idx == $member_lid)){
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
elseif ($action == "convert") {
    if ($type == "shared") {
        $remove_address = array();
        if ($ids != "") {
            take_snapshot_last($project);
            $members_ServiceGroups = explode(',',$ids);
            $return = convertServicesGroupsToShared($source, $members_ServiceGroups, "notall");
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
            $member_ServiceGroups = explode(',',$ids);
            $return = cloneServicesGroups($source, $vsys, $clone_to_vsys, $member_ServiceGroups);
            if($return != 0){
                echo json_encode(array("success" => true));
            }else{
                echo json_encode(array("success" => false));
            }  
        }
    }
}
?>
