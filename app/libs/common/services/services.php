<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by alejandradevegamir
 * Date: 23/1/17 - 11:00
 */
//require_once INC_ROOT.'/libs/common/services/ServicesGroupsQueryBuilder.php';
require_once INC_ROOT.'/libs/common/tools/filters.php';

//use PaloAltoNetworks\Services\ServicesGroupsQueryBuilder;

if(defined('CLI')){
    require_once INC_ROOT .'/userManager/API/accessControl_CLI.php';
}
else{
    require_once INC_ROOT .'/userManager/API/accessControl.php';
    require_once INC_ROOT.'/bin/authentication/sessionControl.php';
}

function get_services(ARRAY $params){

    global $projectdb;

    ini_set('max_execution_time', PARSER_max_execution_time);
    ini_set("memory_limit", PARSER_max_execution_memory);

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

    if(($filter != "none") && ($filter != "0")){

        if(($filter == "74") || ($filter == "75") || ($filter == "111")){
            $params['case_sensitive'] = "1";
        }else{
            $params['case_sensitive'] = "0";
        }

        $params['tools_where_columns_id'] = $filter;
        $params['tools_operator_id'] = "contains";
        $params['search'] = "";
        $params['tools_where_id'] = "7";
        $params['tools_advanced_columns_id'] = "None";
        $params['is_set_sql_filter'] = "yes";

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

            while ($data = $getLimit->fetch_assoc()) {
                $objectsInMemory['services'][$data['id']] = $data;
                list($data['type'], $data['vsys'], $name_member, $myip) = getIcon("services", "services", $data['id'], "", $objectsInMemory);

                $query = "SELECT tag.name as name FROM tag, tag_relations WHERE tag_relations.member_lid='".$data['id']."' AND tag_relations.table_name='services' AND tag.id = tag_relations.tag_id";
                $result = $projectdb->query($query);
                $tags = array();
                if ($result->num_rows > 0) {
                    while($row = $result->fetch_assoc()){
                        $tags[] = $row['name'];
                    }
                }
                $data['tag'] = $tags;
                $data['filter'] = $filter;
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


function register_services(ARRAY $data){

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

    $v = $app->servicesValidation;

    $v->validate([
        'name'              => [$data['name'], 'required|regexnamewithbar'],
        'dport'             => [$data['dport'], 'required|regexport'],
        'sport'             => [$data['sport'], 'regexport'],
        'protocol'          => [$data['protocol'], 'required|alpha'],
        'timeout_tcp'       => [$data['timeout_tcp'], 'number'],
        'timeout_udp'       => [$data['timeout_udp'], 'number'],
        'halfclose_timeout' => [$data['halfclose_timeout'], 'number'],
        'timewait_timeout'  => [$data['timewait_timeout'], 'number'],
        'override'          => [$data['override'], 'alpha'],
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
    $dport = $data['dport'];
    $sport = $data['sport'];
    $protocol = $data['protocol'];
    $timeout_tcp = $data['timeout_tcp'];
    $timeout_udp = $data['timeout_udp'];
    $halfclose_timeout = $data['halfclose_timeout'];
    $timewait_timeout = $data['timewait_timeout'];
    $override = $data['override'];

    $names_tags = sanitizeInput($projectdb, $data['names_tags']);
    $description = sanitizeInput($projectdb, $data['description']);

    if($source <= 0 || $vsys == ''){
        $message = array();
        $message['code'] = false;
        $message['msg'] = "The specified target is not correct";
        return $message;
    }

    if($protocol == "tcp"){
        $timeout = $timeout_tcp;
    }else if($protocol == "udp"){
        $timeout = $timeout_udp;
        $halfclose_timeout = "";
        $timewait_timeout = "";
    }else{
        $timeout = "";
    }

    $getExistName = $projectdb->query("SELECT id FROM services WHERE BINARY name = '$name' AND source = '$source' AND vsys = '$vsys' "
        . "UNION SELECT id FROM services_groups_id WHERE BINARY name = '$name' AND source = '$source' AND vsys = '$vsys';");

    if ($getExistName->num_rows == 0){

        $projectdb->query("INSERT INTO services (source, vsys, protocol, name, dport, sport, description, tag, override, timeout, halfclose_timeout, timewait_timeout)  
                           VALUES ('$source', '$vsys', '$protocol', '$name', '$dport', '$sport', '$description', '$names_tags', '$override', '$timeout', '$halfclose_timeout', '$timewait_timeout');");

        $id = $projectdb->insert_id;

        $names_tags_exp = explode(",", $names_tags);
        $tagPartialQuery = array();
        foreach ($names_tags_exp as $tag_id){
            $tagPartialQuery [] = "('services', $id, $tag_id)";
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


function update_services(ARRAY $data){

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

    $v = $app->servicesValidation;

    $v->validate([
        'name'              => [$data['name'], 'required|regexnamewithbar'],
        'dport'             => [$data['dport'], 'required|regexport'],
        'sport'             => [$data['sport'], 'regexport'],
        'protocol'          => [$data['protocol'], 'required|alpha'],
        'timeout_tcp'       => [$data['timeout_tcp'], 'number'],
        'timeout_udp'       => [$data['timeout_udp'], 'number'],
        'halfclose_timeout' => [$data['halfclose_timeout'], 'number'],
        'timewait_timeout'  => [$data['timewait_timeout'], 'number'],
        'override'          => [$data['override'], 'alpha'],
    ]);

    if (!$v->passes()) {
        $message = array();
        $message['code'] = false;
        $message['msg'] = $v->errors()->all();
        return $message;
    }

    // get vars from the service form
    $name = $data['name'];
    $id = $data['id'];
    $source = $data['source'];
    $vsys = $data['vsys'];
    $dport = $data['dport'];
    $sport = $data['sport'];
    $protocol = $data['protocol'];
    $timeout_tcp = $data['timeout_tcp'];
    $timeout_udp = $data['timeout_udp'];
    $halfclose_timeout = $data['halfclose_timeout'];
    $timewait_timeout = $data['timewait_timeout'];
    $override = $data['override'];
    $invalid = $data['invalid'];

    // define vars to store original names on DB
    $name_db = "";
    $description_db = "";
    $protocol_db = "";
    $sport_db = "";
    $dport_db = "";
    $timeout_tcp_db = "";
    $timeout_udp_db = "";
    $override_db = "";
    $invalid_db = 0;

    $names_tags = sanitizeInput($projectdb, $data['names_tags']);
    $description = sanitizeInput($projectdb, $data['description']);

    $entryInfo = $projectdb->query("SELECT * FROM services WHERE id='$id'");
    if($entryInfo->num_rows>0){
        $queryData = $entryInfo->fetch_assoc();
        $vsys = $queryData['vsys'];
        $source = $queryData['source'];
        $name_db = $queryData['name'];
        $description_db = $queryData['description'];
        $protocol_db = $queryData['protocol'];
        $sport_db = $queryData['sport'];
        $dport_db = $queryData['dport'];
        $timeout_tcp_db = $queryData['timeout_tcp'];
        $timeout_udp_db = $queryData['timeout_udp'];
        $override_db = $queryData['override'];
        $invalid_db = $queryData['invalid'];
    }

    if($protocol == "tcp"){
        $timeout = $timeout_tcp;
    }else if($protocol == "udp"){
        $timeout = $timeout_udp;
        $halfclose_timeout = "";
        $timewait_timeout = "";
    }else{
        $timeout = "";
    }

    $getExistName = $projectdb->query("SELECT id FROM services WHERE id != '$id' AND BINARY name = '$name' AND source = '$source' AND vsys = '$vsys' "
        . "UNION SELECT id FROM services_groups_id WHERE BINARY name = '$name' AND source = '$source' AND vsys = '$vsys';");

    if ($getExistName->num_rows == 0){

        if($invalid_db==1){
            if(
                $name_db != $name ||
                $description_db != $description ||
                $protocol_db != $protocol ||
                $sport_db != $sport ||
                $dport_db != $dport ||
                $timeout_tcp_db != $timeout_tcp ||
                $timeout_udp_db != $timeout_udp ||
                $override_db != $override
            ) {
                $invalid = 0;
            }
        }


        $projectdb->query("UPDATE services SET protocol='$protocol', name = '$name', dport='$dport', sport='$sport',
            description = '$description', tag = '$names_tags', override = '$override', timeout = '$timeout',
            halfclose_timeout = '$halfclose_timeout', timewait_timeout = '$timewait_timeout', invalid= '$invalid' WHERE id = '$id'");

        //Remove old tags
        $query = "DELETE FROM tag_relations WHERE table_name = 'services' AND member_lid = '$id' ";
        $projectdb->query($query);

        $names_tags_exp = explode(",", $names_tags);
        $tagPartialQuery = array();
        foreach ($names_tags_exp as $tag_id){
            $tagPartialQuery [] = "('services', $id, $tag_id)";
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


function delete_services(ARRAY $data){

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

    $getUsed = $projectdb->query("SELECT id, name, used FROM services WHERE id in (".$ids.") AND used = '0' AND name NOT IN ('application-default', 'service-http', 'service-https') ;");
    if ($getUsed->num_rows > 0) {
        while($getData = $getUsed->fetch_assoc()){

            $id = $getData['id'];
            $name = $getData['name'];

            $is_used = check_used_objects_in_groups($projectdb, $id, "services", "services_groups");

            if($is_used == 0){
                $projectdb->query("DELETE FROM services WHERE id = '$id' AND dummy = 0;");
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
            $message['msg'] = "These Services '".implode(", ",$array_name_on_groups)."' used on Services Groups. Are you sure you want to Delete?";
            return $message;
        }
        elseif($remove_references == "yes"){
            $projectdb->query("DELETE FROM services WHERE id IN (".implode(",", $array_ids_on_groups).") AND dummy = 0;");

            $projectdb->query("DELETE FROM services_groups WHERE (member_lid IN (".implode(",", $array_ids_on_groups).") AND table_name = 'services');");
        }
    }

    $message = array();
    $message['code'] = true;
    $message['msg'] = '';
    return $message;
}
