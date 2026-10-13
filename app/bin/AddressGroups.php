<?php

# Copyright (c) 2014 Palo Alto Networks, Inc.
# All rights reserved.
//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';

require_once INC_ROOT.'/libs/database.php';
require_once INC_ROOT.'/libs/shared.php';

require_once INC_ROOT.'/libs/projectdb.php';
require_once INC_ROOT.'/userManager/API/projects/manageSettings.php';

ini_set('max_execution_time', PARSER_max_execution_time);
ini_set("memory_limit", PARSER_max_execution_memory);

include INC_ROOT.'/bin/middleware_sanitizer.php';

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $action     = (string)  (isset($_GET['action'])     ? $_GET['action'] : '');
        $type       = (string)  (isset($_GET['type'])       ? $_GET['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_GET['project'])    ? $_GET['project'] : '');
        $vsys       = (string)  (isset($_GET['vsys'])       ? $_GET['vsys'] : '');
        $filter     = (string)  (isset($_GET['filter'])     ? $_GET['filter'] : '');
        $search     = (string)  (isset($_GET['search'])     ? $_GET['search'] : '');
        $start      = (integer) (isset($_GET['start'])      ? $_GET['start'] : 0);
        $limit      = (integer) (isset($_GET['limit'])      ? $_GET['limit'] : 0);
        break;
    case 'POST':
        $action     = (string)  (isset($_POST['action'])    ? $_POST['action'] : '');
        $type       = (string)  (isset($_POST['type'])      ? $_POST['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_POST['project'])   ? $_POST['project'] : '');
        $vsys       = (string)  (isset($_POST['vsys'])      ? $_POST['vsys'] : '');
        $filter     = (string)  (isset($_POST['filter'])    ? $_POST['filter'] : '');
        $search     = (string)  (isset($_POST['search'])    ? $_POST['search'] : '');
        $start      = (integer) (isset($_POST['start'])     ? $_POST['start'] : 0);
        $limit      = (integer) (isset($_POST['limit'])     ? $_POST['limit'] : 0);
        break;

    default:
        $action     = (string)  (isset($_POST['action'])    ? $_POST['action'] : '');
        $type       = (string)  (isset($_POST['type'])      ? $_POST['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_POST['project'])   ? $_POST['project'] : '');
        $vsys       = (string)  (isset($_POST['vsys'])      ? $_POST['vsys'] : '');
        $filter     = (string)  (isset($_POST['filter'])    ? $_POST['filter'] : '');
        $search     = (string)  (isset($_POST['search'])    ? $_POST['search'] : '');
        $start      = (integer) (isset($_POST['start'])     ? $_POST['start'] : 0);
        $limit      = (integer) (isset($_POST['limit'])     ? $_POST['limit'] : 0);
        break;
}

if ($limit == "All") {
    $limit = 150000;
}

$projectdb = selectDatabase($project);

$action = $projectdb->real_escape_string($action);
$type = $projectdb->real_escape_string($type);
$project = $projectdb->real_escape_string($project);
$start = $projectdb->real_escape_string($start);
$limit = $projectdb->real_escape_string($limit);
$vsys = $projectdb->real_escape_string($vsys);
$search = $projectdb->real_escape_string($search);
$filter = $projectdb->real_escape_string($filter);

global $app;
$user = $app->container->sentinel->getUser();
$user_id = $user->id;

#DEBUG
/*
  $project="test";
  $start=0;
  $limit=5;

  #DEBUG
 */

if ($action == "get") {
    if ($type == "addressgroups_only_names") {
        
        $query = generate_query("objects");

        if($limit === 0 || $limit === 150000) {
            $addressgroups = "SELECT id as idx,filter,vsys,used,id,name,name_ext,devicegroup, if (type = 'static', 'fa fa-object-ungroup', 'fa fa-object-group') AS icon, if (vsys = 'shared', '#cf1cbc', '#235585') AS color, if (vsys = 'shared', 'shared_address_groups_id', 'address_groups_id') AS table_name, source,tag,type,description "
                . "FROM address_groups_id $query ORDER BY name ASC; ";
        } else {
            $addressgroups = "SELECT id as idx,filter,vsys,used,id,name,name_ext,devicegroup, if (type = 'static', 'fa fa-object-ungroup', 'fa fa-object-group') AS icon, if (vsys = 'shared', '#cf1cbc', '#235585') AS color, if (vsys = 'shared', 'shared_address_groups_id', 'address_groups_id') AS table_name, source,tag,type,description "
                . "FROM address_groups_id $query ORDER BY name ASC LIMIT $start, $limit;";
        }
        $getLimit = $projectdb->query($addressgroups);
        $count = $getLimit->num_rows;
        
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
                $vsysgroup = $Tags['vsys'];
                $taggroup = $Tags['tag'];
                $typegroup = $Tags['type'];
                $icon = $Tags['icon'];
                $color = $Tags['color'];
                $description = json_encode($Tags['description']);
                $filtergroup = json_encode($Tags['filter']);

                $tablenamegroup = "address_groups";

                if ($Tags['type'] == "dynamic") {
                    $imageGroup = "dynamic_group.png";
                } else {
                    $imageGroup = $tablenamegroup . ".gif";
                }
                $id_group_table_name = $idgroup.";".$tablenamegroup;
                $arr2[] = '{"description":' . $description . ',"idx":"' . $idgroup . '","uid":' . $x . ',"type":"' . $typegroup . '","filter":' . $filtergroup . ',"tag":"' . $taggroup . '","id":"' . $idgroup . '","table_name":"' . $tablenamegroup . '", "id_group_table_name" : "'.$id_group_table_name.'","name":"' . $groupname . '","name_ext":"' . $Original . '","vsys":"' . $vsysgroup . '","img":"' . $imageGroup . '","icon":"' . $icon . '","color":"' . $color . '","used":"' . $usedgroup . '","devicegroup":' . json_encode($Devicegroup) . '}';
                $x++;
            }

            $Address = implode(",", $arr2);
            echo '{"total":"' . $count . '","rows":[' . $Address . ']}';
        } else {
            echo '{"total":"0","rows":[]}';
        }
    }
    elseif ($type == "tag") {
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $idx = $projectdb->real_escape_string((string) (isset($_POST['idx']) ? $_POST['idx'] : $_GET['idx']));
        $table_name = $projectdb->real_escape_string((string) (isset($_POST['table_name']) ? $_POST['table_name'] : $_GET['table_name']));

        if ($table_name == "address_groups") {
            $table_name = "address_groups_id";
        } 
        if (($idx != "") AND ( $table_name != "")) {

            $query = "SELECT tag.name as name, tag.id as id FROM tag, tag_relations 
              WHERE tag_relations.member_lid='".$idx."' AND tag_relations.table_name='address_groups_id' AND tag.id = tag_relations.tag_id";

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
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $idx = $projectdb->real_escape_string((string) (isset($_POST['idx']) ? $_POST['idx'] : $_GET['idx']));
        $table_name = $projectdb->real_escape_string((string) (isset($_POST['table_name']) ? $_POST['table_name'] : $_GET['table_name']));
        
        if($idx == ""){
            $idx = 0;
        }
        //$query = generate_query("objects");
        // Not necessary because is where clause with "lid"
        $query = " WHERE lid='$idx' ";

        # Load Objects inMemory
        $getSource = $projectdb->query("SELECT id, table_name, member_lid FROM $table_name WHERE lid = '$idx';");
        if ($getSource->num_rows > 0) {
            $inMemory=array();
            $listAddresses      = array();
            $listAddressGroups  = array();
            $listDefaultRegions = array();

            while ($src = $getSource->fetch_assoc()) {
                $table = $src['table_name'];
                switch ($table) {
                    case "address":
                        $listAddresses[] = $src['member_lid'];
                        break;
                    case "address_groups_id":
                        $listAddressGroups[] = $src['member_lid'];
                        break;
                    case "default_regions":
                        $listDefaultRegions[] = $src['member_lid'];
                        break;
                    default:
                        break;
                }
            }
            //Address
            if(count($listAddresses)>0) {
                $query1 = "SELECT * FROM address WHERE id in (" . implode(',', $listAddresses) . ")";
                $result = $projectdb->query($query1);
                while ($row = $result->fetch_assoc()) {
                    $inMemory['address'][$row['id']] = $row;
                }
            }
            //AddGroups
            if(count($listAddressGroups)>0) {
                $query1 = "SELECT * FROM address_groups_id WHERE id in (" . implode(',', $listAddressGroups) . ")";
                $result = $projectdb->query($query1);
                while ($row = $result->fetch_assoc()) {
                    $inMemory['address_groups_id'][$row['id']] = $row;
                }
            }

            //Default Regions
            if(count($listDefaultRegions)>0) {
                $query1 = "SELECT * FROM default_regions WHERE id in (" . implode(',', $listDefaultRegions) . ")";
                $result = $projectdb->query($query1);
                while ($row = $result->fetch_assoc()) {
                    $inMemory['default_regions'][$row['id']] = $row;
                }
            }
            /** Add Images */
            getIconMemory($inMemory);
        }

        $getSource = $projectdb->query("SELECT id, table_name, member_lid FROM $table_name $query");
        if ($getSource->num_rows > 0) {
            $Source = array();
            $inserts=array();

            $getEditTable=$projectdb->query("SELECT id FROM edit_table WHERE lid = '$idx' AND type = 'members' AND user_id = '$user_id';");
            if ($getEditTable->num_rows==0){
                while ($src = $getSource->fetch_assoc()) {
                    $src_table_name = $src['table_name'];
                    $src_member_lid = $src['member_lid'];
                    $id = $src['id'];
                    //list($image, $vsys_member, $name, $myip) = getIcon("address", $src_table_name, $src_member_lid, "");
                    $addressObject = $inMemory[$src['table_name']][$src['member_lid']];
                    $image=$addressObject['icon'];
                    $name=$addressObject['name'];
                    $vsys_member=isset($addressObject['vsys'])?$addressObject['vsys']:'';
                    $inserts[]="('NULL', '$id', '$idx', '$src_member_lid', '$src_table_name', 'members', '$name', '$image','$vsys', '$vsys_member', '$source', '0', '$user_id')";
                }
                $projectdb->query("INSERT INTO edit_table (id, ids, lid, member_lid, table_name_lid, type, name, image, vsys, vsys_member, source, remove, user_id)  VALUES ".implode(",",$inserts).";");
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
            echo '{"total":"' . $getSource->num_rows . '","rows":[' . implode(",", $Source) . ']}';
        }
        else {
            $getBridgeData = $projectdb->query("SELECT image, name, member_lid, table_name_lid, source, vsys, vsys_member, ids FROM edit_table WHERE lid = '$idx' AND type = 'members' AND remove = '0' AND user_id = '$user_id';");
            if ($getBridgeData->num_rows >= 1) {
            
                while($getData = $getBridgeData->fetch_assoc()){
                    //$thetag[] = array("name" => $getData['tag']);
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
elseif ($action == "transform") {
    if ($type == "static_to_dynamic") {

        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $data = $projectdb->real_escape_string((string) (isset($_POST['data']) ? $_POST['data'] : $_GET['data'])); // multi by , and member_lid,table_name,name by ;

        take_snapshot_last($project);

        if ($data != "") {
            $datas = explode(",", $data);
            foreach ($datas as $key => $value) {
                $datas2 = explode(";", $value);
                $addvsys = "";
                $grp_member_lid = $datas2[0];
                $grp_table_name = $datas2[1];
                $grp_name = $datas2[2];
                $array_members = array();

                $geTag = $projectdb->query("SELECT id FROM tag WHERE source='$source' AND vsys='$vsys' AND name='$grp_name';");

                if ($geTag->num_rows == 0) {
                    $projectdb->query("INSERT INTO tag (name,comments,source,vsys) VALUES ('$grp_name','Expedition created from an AddressGroup','$source','$vsys')");
                    $tag_id = $projectdb->insert_id;
                }
                else{
                    $dataT = $geTag->fetch_assoc();
                    $tag_id = $dataT['id'];
                }

                $projectdb->query("UPDATE address_groups_id SET type='dynamic', filter='\'$grp_name\'' WHERE id='$grp_member_lid';");
                $getMembers = $projectdb->query("SELECT member,member_lid,table_name FROM address_groups WHERE lid='$grp_member_lid' ;");

                if ($getMembers->num_rows > 0) {
                    while ($data3 = $getMembers->fetch_assoc()) {

                        $member_lid = $data3['member_lid'];
                        $table_name = $data3['table_name'];
                        $member_name = $data3['member'];
                        $array_members[] = $member_name;

                        $getAddress = $projectdb->query("SELECT * FROM tag_relations WHERE table_name = '$table_name' AND member_lid = '$member_lid' AND tag_id = '$tag_id' ;");

                        if ($getAddress->num_rows == 0) {
                            $projectdb->query("INSERT INTO tag_relations (table_name, member_lid, tag_id) VALUES ('$table_name', '$member_lid', '$tag_id') ;");
                        }
                    }
                    $projectdb->query("DELETE FROM address_groups WHERE lid='$grp_member_lid' ;");
                }
                add_log2('ok', 'Transform Address-Groups from Static to Dynamic', 'AddressGroup [' . $grp_name . '].', $source, 'Members [' . implode(",", $array_members) . '] have been tagged with [' . $grp_name . ']', 'objects', $grp_member_lid, 'address_groups_id');
                unset($array_members);
            }
        }
        echo json_encode(array("success" => true));
    } 
    elseif ($type == "group_to_address") {

        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $data = $projectdb->real_escape_string((string) (isset($_POST['data']) ? $_POST['data'] : $_GET['data'])); // multi by , and member_lid,table_name,name by ;
        
        take_snapshot_last($project);
        
        $table_name_group = "address_groups";
        
        $remove_groups = array();

        if ($data != "") {
            $condition = " WHERE lid IN ($data) ";
        }else{
            $condition = " ";
        }

        $getAll = $projectdb->query("SELECT id, lid, member_lid, table_name, vsys,source, COUNT(lid) AS t FROM address_groups $condition GROUP BY lid HAVING t=1 ORDER BY table_name DESC;");

        if ($getAll->num_rows > 0) {
            while ($data = $getAll->fetch_assoc()) {
                $lid = $data['lid'];
                $member_lid = $data['member_lid'];
                $table_name = $data['table_name'];

                $projectdb->query("UPDATE address_groups SET member_lid='$member_lid', table_name='$table_name' WHERE member_lid='$lid' AND table_name='address_groups_id';");
                $projectdb->query("UPDATE security_rules_src SET member_lid='$member_lid', table_name='$table_name' WHERE member_lid='$lid' AND table_name='address_groups_id';");
                $projectdb->query("UPDATE security_rules_dst SET member_lid='$member_lid', table_name='$table_name' WHERE member_lid='$lid' AND table_name='address_groups_id';");
                $projectdb->query("UPDATE nat_rules_src SET member_lid='$member_lid', table_name='$table_name' WHERE member_lid='$lid' AND table_name='address_groups_id';");
                $projectdb->query("UPDATE nat_rules_dst SET member_lid='$member_lid', table_name='$table_name' WHERE member_lid='$lid' AND table_name='address_groups_id';");
                $projectdb->query("UPDATE nat_rules_translated_address SET member_lid='$member_lid', table_name='$table_name' WHERE member_lid='$lid' AND table_name='address_groups_id';");
                $projectdb->query("UPDATE nat_rules_translated_address_fallback SET member_lid='$member_lid', table_name='$table_name' WHERE member_lid='$lid' AND table_name='address_groups_id';");
                $projectdb->query("UPDATE appoverride_rules_dst SET member_lid='$member_lid', table_name='$table_name' WHERE member_lid='$lid' AND table_name='address_groups_id';");
                $projectdb->query("UPDATE appoverride_rules_src SET member_lid='$member_lid', table_name='$table_name' WHERE member_lid='$lid' AND table_name='address_groups_id';");
                $projectdb->query("UPDATE nat_rules SET tp_dat_address_lid='$member_lid',tp_dat_address_table='$table_name' WHERE source='$source' AND tp_dat_address_lid='$lid' AND tp_dat_address_table='address_groups_id';");

                $projectdb->query("UPDATE qos_rules_src SET member_lid='$member_lid', table_name='$table_name' WHERE member_lid='$lid' AND table_name='address_groups_id';");
                $projectdb->query("UPDATE qos_rules_dst SET member_lid='$member_lid', table_name='$table_name' WHERE member_lid='$lid' AND table_name='address_groups_id';");
                $projectdb->query("UPDATE pbf_rules_src SET member_lid='$member_lid', table_name='$table_name' WHERE member_lid='$lid' AND table_name='address_groups_id';");
                $projectdb->query("UPDATE pbf_rules_dst SET member_lid='$member_lid', table_name='$table_name' WHERE member_lid='$lid' AND table_name='address_groups_id';");
                $projectdb->query("UPDATE decryption_rules_src SET member_lid='$member_lid', table_name='$table_name' WHERE member_lid='$lid' AND table_name='address_groups_id';");
                $projectdb->query("UPDATE decryption_rules_dst SET member_lid='$member_lid', table_name='$table_name' WHERE member_lid='$lid' AND table_name='address_groups_id';");
                $projectdb->query("UPDATE tunnel_inspect_rules_src SET member_lid='$member_lid', table_name='$table_name' WHERE member_lid='$lid' AND table_name='address_groups_id';");
                $projectdb->query("UPDATE tunnel_inspect_rules_dst SET member_lid='$member_lid', table_name='$table_name' WHERE member_lid='$lid' AND table_name='address_groups_id';");
                $projectdb->query("UPDATE authentication_rules_src SET member_lid='$member_lid', table_name='$table_name' WHERE member_lid='$lid' AND table_name='address_groups_id';");
                $projectdb->query("UPDATE authentication_rules_dst SET member_lid='$member_lid', table_name='$table_name' WHERE member_lid='$lid' AND table_name='address_groups_id';");
                $projectdb->query("UPDATE captiveportal_rules_src SET member_lid='$member_lid', table_name='$table_name' WHERE member_lid='$lid' AND table_name='address_groups_id';");
                $projectdb->query("UPDATE captiveportal_rules_dst SET member_lid='$member_lid', table_name='$table_name' WHERE member_lid='$lid' AND table_name='address_groups_id';");

                #UPDATE LOGS TO THE NEW Rule
                $projectdb->query("UPDATE logs SET obj_id='$member_lid',obj_table='$table_name' WHERE obj_id='$lid' AND obj_table='address_groups_id' AND source='$source'");

                $remove_groups[] = $lid;

                clean_duplicated_members_merging("security_rules_src", $member_lid, $table_name);
                clean_duplicated_members_merging("security_rules_dst", $member_lid, $table_name);
                clean_duplicated_members_merging("nat_rules_src", $member_lid, $table_name);
                clean_duplicated_members_merging("nat_rules_dst", $member_lid, $table_name);
                clean_duplicated_members_merging("nat_rules_translated_address", $member_lid, $table_name);
                clean_duplicated_members_merging("nat_rules_translated_address_fallback", $member_lid, $table_name);
                clean_duplicated_members_merging("appoverride_rules_dst", $member_lid, $table_name);
                clean_duplicated_members_merging("appoverride_rules_src", $member_lid, $table_name);
                clean_duplicated_members_merging("qos_rules_src", $member_lid, $table_name);
                clean_duplicated_members_merging("qos_rules_dst", $member_lid, $table_name);
                clean_duplicated_members_merging("pbf_rules_src", $member_lid, $table_name);
                clean_duplicated_members_merging("pbf_rules_dst", $member_lid, $table_name);
                clean_duplicated_members_merging("decryption_rules_src", $member_lid, $table_name);
                clean_duplicated_members_merging("decryption_rules_dst", $member_lid, $table_name);
                clean_duplicated_members_merging("tunnel_inspect_rules_src", $member_lid, $table_name);
                clean_duplicated_members_merging("tunnel_inspect_rules_dst", $member_lid, $table_name);
                clean_duplicated_members_merging("authentication_rules_src", $member_lid, $table_name);
                clean_duplicated_members_merging("authentication_rules_dst", $member_lid, $table_name);
                clean_duplicated_members_merging("captiveportal_rules_src", $member_lid, $table_name);
                clean_duplicated_members_merging("captiveportal_rules_dst", $member_lid, $table_name);

                $getNamePanOld = $projectdb->query("SELECT name FROM address_groups_id WHERE id = '$lid' ;");
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

                $getZones = $projectdb->query("SELECT id, include_list, exclude_list FROM zones WHERE source = '$source' $sql_vsys AND (include_list != '' OR exclude_list != '');");

                if ($getZones->num_rows > 0) {

                    while ($dataZ = $getZones->fetch_array()) {

                        $id_zone = $dataZ['id'];
                        $all_include_list = $dataZ['include_list'];
                        $all_exclude_list = $dataZ['exclude_list'];

                        $incl_exp = explode(",", $all_include_list);
                        $exc_exp = explode(",", $all_exclude_list);

                        $is_change = 0;
                        $i = 0;

                        foreach($incl_exp AS $name_int){

                            if ($name_int == $name_int_old) {
                                $is_change = 1;
                                if (in_array($name_int_new, $incl_exp)) {
                                }else{
                                    $incl_exp[] = $name_int_new;
                                }
                                unset($incl_exp[$i]);
                            }
                            $i++;
                        }

                        if($is_change == 1){
                            $projectdb->query("UPDATE zones SET include_list = '".implode(",", $incl_exp)."' WHERE id = '$id_zone' ;");
                        }

                        $is_change = 0;
                        $i = 0;

                        foreach($exc_exp AS $name_int){

                            if ($name_int == $name_int_old) {
                                $is_change = 1;
                                if (in_array($name_int_new, $exc_exp)) {
                                }else{
                                    $exc_exp[] = $name_int_new;
                                }
                                unset($exc_exp[$i]);
                            }
                            $i++;
                        }

                        if($is_change == 1){
                            $projectdb->query("UPDATE zones SET exclude_list = '".implode(",", $exc_exp)."' WHERE id = '$id_zone' ;");
                        }
                    }
                }
            }
        }

        clean_duplicated_members("address_groups");

        if (count($remove_groups) > 0) {
            $projectdb->query("DELETE FROM address_groups_id WHERE id IN (" . implode(",", $remove_groups) . ");");
            $projectdb->query("DELETE FROM address_groups WHERE lid IN (" . implode(",", $remove_groups) . ");");
            
            check_used_objects_new();
        }
        
        
    } 
    elseif ($type == "split_in_groups") {

        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $data = $projectdb->real_escape_string((string) (isset($_POST['data']) ? $_POST['data'] : $_GET['data'])); // multi by , and member_lid,table_name,name by ;

        take_snapshot_last($project);

        if ($data != "") {
            $datas = explode(",", $data);
            foreach ($datas as $key => $value) {
                $datas2 = explode(";", $value);
                $member_lid = $datas2[0];
                $table_name = $datas2[1];
                $name = $datas2[2];
                if ($table_name == "address_groups") {
                    $table_group = "address_groups_id";
                } 

                #Get Group Members
                $getMembers = $projectdb->query("SELECT ag.member_lid, ag.table_name, agi.vsys FROM address_groups ag, address_groups_id agi WHERE ag.lid='$member_lid' AND ag.lid = agi.id;");
                $max_number_group_members = 500;
                if ($getMembers->num_rows > $max_number_group_members) {

                    $getlastlid = $projectdb->query("SELECT max(id) as max FROM $table_group;");
                    $getLID1 = $getlastlid->fetch_assoc();
                    $lid = (int)$getLID1['max'] + 1; // get lid number

                    $new_group_id_members = array();
                    $new_group_members = array();
                    $groups = array();
                    $count = 0;
                    $count2 = 1;
                    while ($getMembersData = $getMembers->fetch_assoc()) {
                        $new_member_lid = $getMembersData['member_lid'];
                        $new_table_name = $getMembersData['table_name'];
                        $vsys = $getMembersData['vsys'];
                        if ($count == 0) {
                            $new_name = $name . "-" . $count2;
                            $new_group_id_members[] = "('$source','$vsys','$new_name','$new_name')";
                            //$projectdb->query("INSERT INTO $table_group (source,vsys,name_ext,name) VALUES ('$source','$vsys','$new_name','$new_name');");
                            //$lid = $projectdb->insert_id;
                            $count2++;
                            //$groups[] = $lid;
                            $groups[] ="('$source','$vsys','$lid','$table_group','$member_lid')";
                        }
                        //$projectdb->query("INSERT INTO $table_name (member_lid,table_name,source,vsys,lid) VALUES ('$new_member_lid','$new_table_name','$source','$vsys','$lid');");
                        $new_group_members[]= "('$new_member_lid','$new_table_name','$source','$vsys','$lid')";
                        $count++;
                        if ($count == $max_number_group_members) {
                            $count = 0;
                            $lid++;
                        }
                    }

                    if(count($new_group_id_members)>0) {
                        $projectdb->query("INSERT INTO $table_group (source,vsys,name_ext,name) VALUES " . implode(",", $new_group_id_members));
                    }
                    if(count($new_group_members)>0) {
                        $projectdb->query("INSERT INTO $table_name (member_lid,table_name,source,vsys,lid) VALUES " . implode(",", $new_group_members));
                    }

                    $projectdb->query("DELETE FROM $table_name WHERE lid='$member_lid';");
                    //foreach ($groups as $key => $value) {
                    //    $projectdb->query("INSERT INTO $table_name (source,vsys,member_lid,table_name,lid) VALUES ('$source','$vsys','$value','$table_group','$member_lid');");
                    //}
                    if(count($groups)>0) {
                        $projectdb->query("INSERT INTO $table_name (source,vsys,member_lid,table_name,lid) VALUES " . implode(",", $groups));
                    }
                }
                
            }
            check_used_objects_new();
        }
    }
} 
elseif ($action == "set") {
    if ($type == "remove_member") {
        global $projectdb;
        $idx = $projectdb->real_escape_string((string) (isset($_POST['idx']) ? $_POST['idx'] : $_GET['idx']));
        $table_name = $projectdb->real_escape_string((string) (isset($_POST['table_name']) ? $_POST['table_name'] : $_GET['table_name']));
        $ids = $projectdb->real_escape_string((string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']));
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));

        if ($ids != "") {
            $sql = "UPDATE edit_table SET remove = '1' WHERE ids IN ($ids) AND lid = '$idx' AND type = 'members' AND user_id = '$user_id';";
            $projectdb->query($sql);
        }
    }
    echo json_encode(array("success"=>true));
} 
elseif ($action == "add") {
    if ($type == "addressgroup") {
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));

        if ($vsys == "") {
            $vsys = "vsys1";
        }
        if (($source != 0) AND ( $vsys != "all")) {
            $projectdb->query("INSERT INTO address_groups_id (source,vsys) values ('$source','$vsys');");
            echo json_encode(array("success" => true));
        } else {
            echo json_encode(array("success" => false));
        }
    } 
    elseif ($type == "member") {
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
            if ($table_name == "address_groups") {
                $table_name_g = "address_groups_id";
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
            list($image, $vsys_member, $name_member, $myip) = getIcon("address", $member_table_name, $member_lid, "", null);

            //Edit_update
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
        
        $name = $projectdb->real_escape_string((string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']));
        $id = $projectdb->real_escape_string((string) (isset($_POST['id']) ? $_POST['id'] : $_GET['id']));
//        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        $member_lid = $projectdb->real_escape_string((string) (isset($_POST['member_lid']) ? $_POST['member_lid'] : $_GET['member_lid']));
        $table_name = $projectdb->real_escape_string((string) (isset($_POST['member_table_name']) ? $_POST['member_table_name'] : $_GET['member_table_name']));
        $idx = $projectdb->real_escape_string((string) (isset($_POST['idx']) ? $_POST['idx'] : $_GET['idx']));
        
        if($idx == ""){
            $idx = 0;
        }

        $entryInfo = $projectdb->query("SELECT vsys, source FROM address_groups_id WHERE id='$idx'");
        if($entryInfo->num_rows>0){
            $queryData = $entryInfo->fetch_assoc();
            $vsys = $queryData['vsys'];
            $source = $queryData['source'];
        }

        if (($member_lid != "") AND ($table_name != "")){
            
            $projectdb->query("UPDATE edit_table SET remove = '1' WHERE ids = '$id' AND type = 'members' AND user_id = '$user_id';");

            //$image = getImageNew("address", $table_name, $member_lid, $vsys);
            list($image, $vsys_member, $name_member, $myip) = getIcon("address", $table_name, $member_lid, "", null);

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
                    if(($table_name == "address_groups_id") && ($idx == $member_lid)){
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
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $ids = $projectdb->real_escape_string((string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']));
        if ($ids != "") {
            $members_AddressGroups = explode(',', $ids);
            take_snapshot_last($project);
            $return = convertAddressGroupsToShared($source, $members_AddressGroups, "notall");
            if ($return == 1) {
                echo json_encode(array("success" => true));
            } else {
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
            $members_AddressGroups = explode(',',$ids);
            $return = cloneAddressGroups($source, $vsys, $clone_to_vsys, $members_AddressGroups);
            if($return != 0){
                echo json_encode(array("success" => true));
            }else{
                echo json_encode(array("success" => false));
            }  
        }
    }
}
?>
