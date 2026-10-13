<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by alejandradevegamir
 * Date: 23/1/17 - 11:00
 */
require_once INC_ROOT.'/libs/common/services/ServicesGroupsQueryBuilder.php';
require_once INC_ROOT.'/libs/common/tools/filters.php';

//use PaloAltoNetworks\Services\ServicesGroupsQueryBuilder;

if(defined('CLI')){
    require_once INC_ROOT .'/userManager/API/accessControl_CLI.php';
}
else{
    require_once INC_ROOT .'/userManager/API/accessControl.php';
    require_once INC_ROOT.'/bin/authentication/sessionControl.php';
}


/*function get_servicesgroups(ARRAY $params){
    global $projectdb;

    ini_set('max_execution_time', PARSER_max_execution_time);
    ini_set("memory_limit", PARSER_max_execution_memory);

    $projectdb = selectDatabase($params['project']);

    $conditions = generate_query_multitable("objects");

    $filter = mysqli_real_escape_string($projectdb, $params['objfilter']);
    $hide_shared = mysqli_real_escape_string($projectdb, $params['hide_shared']);
    $start = mysqli_real_escape_string($projectdb, $params['start']);
    $limit = mysqli_real_escape_string($projectdb, $params['limit']);
    $source = mysqli_real_escape_string($projectdb, $params['source']);

    if($hide_shared == "true"){
        $conditions = generate_query_multitable("objects");
    }
    else{
        $conditions = generate_query_multitable("objects_vsyses");
    }

    if(($filter != "none") && ($filter != "0")){

        $params['tools_where_columns_id'] = $filter;
        $params['tools_operator_id'] = "contains";
        $params['search'] = "";
        $params['tools_where_id'] = "7";
        $params['tools_advanced_columns_id'] = "None";
        $params['is_set_sql_filter'] = "yes";
        $params['case_sensitive'] = "0";

        setFilter($params['project'], $params);
        executeSQL($params['project'], $params);

    }
    elseif(($filter == "none") || ($filter == "0")){
    }

    list($conditions, $orderby) = generateQueryFilters($params['project'], "services", "", $conditions, $source);

    $getAll = $projectdb->query("SELECT count(*) as total FROM services a $conditions");
    $row = $getAll->fetch_assoc();
    $count = $row['total'];
    if ($count > 0) {
        $getLimit = $projectdb->query("SELECT *, a.timeout AS timeout_tcp, a.timeout AS timeout_udp FROM services a $conditions $orderby LIMIT $start, $limit;");
    }
    if (isset($getLimit)) {
        if ($getAll->num_rows > 0){

            while ($data = $getLimit->fetch_object()) {

                list($data->type, $data->vsys, $name_member, $myip) = getIcon("services", "services", $data->id, "");

                $query = "SELECT tag.name as name FROM tag, tag_relations WHERE tag_relations.member_lid=".$data->id." AND tag_relations.table_name='services' AND tag.id = tag_relations.tag_id";
                $result = $projectdb->query($query);
                $tags = array();
                if ($result->num_rows > 0) {
                    while($row = $result->fetch_assoc()){
                        $tags[] = $row['name'];
                    }
                }
                $data->tag = $tags;
                $data->filter = $filter;
                $myData[] = $data;
            }
        }
    }
    if ($count == 0) {
        $myData = array();
    }
    $message = array();
    $message['code'] = true;
    $message['count'] = $count;
    $message['msg'] = $myData;
    //print_r($myData);
    return $message;
}
*/

function list_servicesgroups($params){

    global $projectdb;
    $projectdb = selectDatabase($params['project']);

    $filter = mysqli_real_escape_string($projectdb, $params['objfilter']);
    $hide_shared = mysqli_real_escape_string($projectdb, $params['hide_shared']);
    $start = mysqli_real_escape_string($projectdb, $params['start']);
    $limit = mysqli_real_escape_string($projectdb, $params['limit']);
    $source = mysqli_real_escape_string($projectdb, $params['source']);

    if($hide_shared == "true"){
        $conditions = generate_query_multitable("objects");
    }
    else{
        $conditions = generate_query_multitable("objects_vsyses");
    }

    if(($filter != "none") && ($filter != "0") && ($filter != "all")){

        if(($filter == "74") || ($filter == "75") || ($filter == "111")){
            $params['case_sensitive'] = "1";
        }else{
            $params['case_sensitive'] = "0";
        }

        $params['tools_where_columns_id'] = $filter;
        $params['tools_operator_id'] = "contains";
        $params['search'] = "";
        $params['tools_where_id'] = "8";
        $params['tools_advanced_columns_id'] = "None";
        $params['is_set_sql_filter'] = "yes";

        setFilter($params['project'], $params);
        executeSQL($params['project'], $params);

    }
    elseif(($filter == "none") || ($filter == "0")){
    }

    if($filter != "all"){
        list($conditions, $orderby) = generateQueryFilters($params['project'], "services_groups_id", "", $conditions, $source);
    }
    else{
        $orderby = " ORDER BY a.name ASC ";
    }

    $query = "SELECT count(*) as total FROM services_groups_id a $conditions;";
    $getAll = $projectdb->query($query);
    $row = $getAll->fetch_assoc();
    $count = $row['total'];
    if ($count > 0) {
        $servicesgroups = "SELECT *, 'services_groups' AS table_name, id AS idx FROM services_groups_id a $conditions $orderby LIMIT $start, $limit;";
        //echo $servicesgroups;
        $getLimit = $projectdb->query($servicesgroups);
    }

    $servicesgroupsEntries = array();
    if ($count > 0) {
        while ($groupRow = $getLimit->fetch_assoc()) {
            $idgroup = $groupRow['id'];
            $source = $groupRow['source'];

            $getGroup = $projectdb->query("SELECT member_lid,table_name FROM services_groups a WHERE lid='$idgroup';");
            $membersInGroup = array();
            while ($getMembers = $getGroup->fetch_assoc()) {
                $memberlid = $getMembers['member_lid'];
                $table2 = $getMembers['table_name'];

                if ($table2 == "services_groups_id") {
                    $query = "SELECT id as member_lid, 'services_groups_id' as 'table_name', name,used, 'group' as type, vsys FROM services_groups_id a where id='$memberlid' limit 1;";
                }
                else {
                    $query = "SELECT id as member_lid, 'services' as 'table_name', name,used,type, vsys FROM services a where id='$memberlid' limit 1";
                }
                $getData = $projectdb->query($query);
                if ($getData->num_rows == 1) {
                    $memberRow = $getData->fetch_assoc();
                    list($memberRow['img'], $memberRow['vsys'], $name_member, $myip) = getIcon("services", $table2, $memberlid, "");
                    $membersInGroup[] = $memberRow;
                }
            }

            $imageGroup = 'fa fa-cogs';

            $query = "SELECT tag.name as name FROM tag, tag_relations WHERE tag_relations.member_lid='".$idgroup."' AND tag_relations.table_name='services_groups_id' AND tag.id = tag_relations.tag_id";
            $result = $projectdb->query($query);
            $tags = array();
            if ($result->num_rows > 0) {
                while($row = $result->fetch_assoc()){
                    $tags[] = $row['name'];
                }
            }
            $groupRow['tag'] = $tags;
            $groupRow['img'] = $imageGroup;
            $groupRow['members'] = $membersInGroup;
            $groupRow['filter_tools']  = $filter;
            $servicesgroupsEntries[] = $groupRow;
        }

        $message = array();
        $message['code'] = true;
        $message['count'] = $count;
        $message['msg'] = $servicesgroupsEntries;
        return $message;
    }
    else {
        $message = array();
        $message['code'] = true;
        $message['count'] = 0;
        $message['msg'] = '';
        return $message;
    }
}



function register_servicesgroups(ARRAY $data){

    global $projectdb;
    global $app;

    ini_set('max_execution_time', PARSER_max_execution_time);
    ini_set("memory_limit", PARSER_max_execution_memory);

    $project = $data['project'];

    take_snapshot_last($project);

    if(!accessControl("any", ['projectRole.'.$project.'.update'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to edit this project contents';
        return $message;
    }

    $projectdb = selectDatabase($project);

    $user = $app->container->sentinel->getUser();
    $user_id = $user->id;

    $v = $app->addressValidation;

    $v->validate([
        'name' => [$data['name'], "required|regexnamewithbar"],
    ]);

    if (!$v->passes()) {
        $message = array();
        $message['code'] = false;
        $message['msg'] = $v->errors()->all();
        return $message;
    }

    $name = $data['name'];
    $source = $data['source'];
    $vsys = $data['vsys'];
    $names_tags = sanitizeInput($projectdb, $data['names_tags']);

    if($source <= 0 || $vsys == ''){
        $message = array();
        $message['code'] = false;
        $message['msg'] = "The specified target is not correct";
        return $message;
    }

    $getExistName = $projectdb->query("SELECT id FROM services_groups_id WHERE BINARY name = '$name' AND source = '$source' AND vsys = '$vsys' "
        . "UNION SELECT id FROM services WHERE BINARY name = '$name' AND source = '$source' AND vsys = '$vsys';");

    if ($getExistName->num_rows == 0){

        $projectdb->query("INSERT INTO services_groups_id (source,vsys)  VALUES ('$source','$vsys');");
        $id = $projectdb->insert_id;
        $is_new = 1;
        $projectdb->query("UPDATE edit_table SET lid = '$id' WHERE user_id = '$user_id';");

        $getMembers = $projectdb->query("SELECT member_lid, table_name FROM ( SELECT member_lid, table_name FROM services_groups WHERE lid='$id' UNION ALL SELECT member_lid, table_name_lid as table_name FROM edit_table WHERE lid='$id' AND user_id = '$user_id') tbl GROUP BY member_lid,table_name HAVING count(*) = 1;");
        if ($getMembers->num_rows>0){
            $edit=array();
            while($getMembersData=$getMembers->fetch_assoc()){
                $edit[]="('$source','$vsys','$id','".$getMembersData['member_lid']."','".$getMembersData['table_name']."')";
            }

            $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member_lid,table_name) VALUES ".implode(",",$edit).";");
        }

        $getMembers = $projectdb->query("SELECT lid, member_lid, table_name_lid FROM edit_table WHERE lid = '$id' AND type = 'members' AND remove = '1' AND user_id = '$user_id';");
        if ($getMembers->num_rows >= 1) {
            while ($getMemData = $getMembers->fetch_assoc()) {
                $lid = $getMemData['lid'];
                $member_lid = $getMemData['member_lid'];
                $table_name_lid = $getMemData['table_name_lid'];

                $projectdb->query("DELETE FROM services_groups WHERE member_lid = '$member_lid' AND table_name = '$table_name_lid' AND lid = '$lid' ;");
            }
        }

        $projectdb->query("UPDATE services_groups_id SET name = '$name', tag = '$names_tags' WHERE id = '$id';");

        $query = "DELETE FROM tag_relations WHERE table_name='services_groups_id' AND member_lid='$id' ";
        $projectdb->query($query);

        $names_tags_exp = explode(",", $names_tags);
        $tagPartialQuery = array();
        foreach ($names_tags_exp as $tag_id){
            $tagPartialQuery [] = "('services_groups_id', $id, $tag_id)";
        }
        if(count($tagPartialQuery)>0){
            $query = "INSERT INTO tag_relations (table_name, member_lid, tag_id) VALUES ".implode(",", $tagPartialQuery);
            $projectdb->query($query);
        }

        $message = array();
        $message['code'] = true;
        $message['msg'] = '';
        return $message;

    }
    else{
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Services or Services Groups already exists with the same name.';
        return $message;
    }

}


function update_servicesgroups(ARRAY $data){

    global $projectdb;
    global $app;

    ini_set('max_execution_time', PARSER_max_execution_time);
    ini_set("memory_limit", PARSER_max_execution_memory);

    $project = $data['project'];

    take_snapshot_last($project);

    if(!accessControl("any", ['projectRole.'.$project.'.update'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to edit this project contents';
        return $message;
    }

    $projectdb = selectDatabase($project);

    $user = $app->container->sentinel->getUser();
    $user_id = $user->id;

    $v = $app->addressValidation;

    $v->validate([
        'id'   => [$data['id'], "required|number"],
        'name' => [$data['name'], "required|regexnamewithbar"],
    ]);

    if (!$v->passes()) {
        $message = array();
        $message['code'] = false;
        $message['msg'] = $v->errors()->all();
        return $message;
    }

    $name = $data['name'];
    $source = $data['source'];
    $vsys = $data['vsys'];
    $id = $data['id'];
    $names_tags = sanitizeInput($projectdb, $data['names_tags']);

    $entryInfo = $projectdb->query("SELECT vsys, source FROM services_groups_id WHERE id='$id'");
    if($entryInfo->num_rows>0){
        $queryData = $entryInfo->fetch_assoc();
        $vsys = $queryData['vsys'];
        $source = $queryData['source'];
    }

    $getExistName = $projectdb->query("SELECT id FROM services_groups_id WHERE id != '$id' AND BINARY name = '$name' AND source = '$source' AND vsys = '$vsys' "
        . "UNION SELECT id FROM services WHERE BINARY name = '$name' AND source = '$source' AND vsys = '$vsys';");

    if ($getExistName->num_rows == 0){

        $getMembers = $projectdb->query("SELECT member_lid, table_name FROM ( SELECT member_lid, table_name FROM services_groups WHERE lid='$id' UNION ALL SELECT member_lid, table_name_lid as table_name FROM edit_table WHERE lid='$id' AND user_id = '$user_id') tbl GROUP BY member_lid,table_name HAVING count(*) = 1;");
        if ($getMembers->num_rows>0){
            $edit=array();
            while($getMembersData=$getMembers->fetch_assoc()){
                $edit[]="('$source','$vsys','$id','".$getMembersData['member_lid']."','".$getMembersData['table_name']."')";
            }

            $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member_lid,table_name) VALUES ".implode(",",$edit).";");
        }

        $getMembers = $projectdb->query("SELECT lid, member_lid, table_name_lid FROM edit_table WHERE lid = '$id' AND type = 'members' AND remove = '1' AND user_id = '$user_id';");
        if ($getMembers->num_rows >= 1) {
            while ($getMemData = $getMembers->fetch_assoc()) {
                $lid = $getMemData['lid'];
                $member_lid = $getMemData['member_lid'];
                $table_name_lid = $getMemData['table_name_lid'];

                $projectdb->query("DELETE FROM services_groups WHERE member_lid = '$member_lid' AND table_name = '$table_name_lid' AND lid = '$lid' ;");
            }
        }

        $projectdb->query("UPDATE services_groups_id SET name = '$name', tag = '$names_tags' WHERE id = '$id';");

        $query = "DELETE FROM tag_relations WHERE table_name='services_groups_id' AND member_lid='$id' ";
        $projectdb->query($query);

        $names_tags_exp = explode(",", $names_tags);
        $tagPartialQuery = array();
        foreach ($names_tags_exp as $tag_id){
            $tagPartialQuery [] = "('services_groups_id', $id, $tag_id)";
        }
        if(count($tagPartialQuery)>0){
            $query = "INSERT INTO tag_relations (table_name, member_lid, tag_id) VALUES ".implode(",", $tagPartialQuery);
            $projectdb->query($query);
        }

        $message = array();
        $message['code'] = true;
        $message['msg'] = '';
        return $message;
    }
    else{
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Services or Services Groups already exists with the same name.';
        return $message;
    }

}


function delete_servicesgroups($data){

    $project = $data['project'];

    take_snapshot_last($project);

    if(!accessControl("any", ['projectRole.'.$project.'.update'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to edit this project contents';
        return $message;
    }

    $projectdb = selectDatabase($project);

    $remove_references = $data['remove_references'];
    $ids = mysqli_real_escape_string($projectdb, $data['ids']);

    $used_in_groups = "no";
    $array_name_on_groups = array();
    $array_ids_on_groups = array();

    $getUsed = $projectdb->query("SELECT id, name, used FROM services_groups_id WHERE id in (".$ids.") AND used='0' ;");
    if ($getUsed->num_rows > 0) {
        while($getData = $getUsed->fetch_assoc()){

            $id = $getData['id'];
            $name = $getData['name'];

            $is_used = check_used_objects_in_groups($projectdb, $id, "services_groups_id", "services_groups");

            if($is_used == 0){
                $projectdb->query("DELETE FROM services_groups_id WHERE id = '$id' AND dummy = 0;");
                $projectdb->query("DELETE FROM services_groups WHERE lid = '$id';");
            }
            else{
                // is used on group
                $used_in_groups = "yes";
                $array_name_on_groups[] = $name;
                $array_ids_on_groups[] = $id;
            }
        }
    }

    if($used_in_groups == "yes"){
        if($remove_references == "no"){
            $message = array();
            $message['code'] = false;
            $message['msg'] = "These Services Groups '".implode(", ",$array_name_on_groups)."' used on Services Groups. Are you sure you want to Delete?";
            return $message;
        }
        elseif($remove_references == "yes"){
            $projectdb->query("DELETE FROM services_groups_id WHERE id IN (".implode(",", $array_ids_on_groups).") AND dummy = 0;");
            $projectdb->query("DELETE FROM services_groups WHERE lid IN (".implode(",", $array_ids_on_groups).");");
            $projectdb->query("DELETE FROM services_groups WHERE (member_lid IN (".implode(",", $array_ids_on_groups).") AND table_name = 'services_groups_id');");
        }
    }

    $message = array();
    $message['code'] = true;
    $message['msg'] = '';
    return $message;



}