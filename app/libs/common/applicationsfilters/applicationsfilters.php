<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by alejandradevegamir
 * Date: 23/1/17 - 11:00
 */
require_once INC_ROOT.'/libs/common/tools/filters.php';

//use PaloAltoNetworks\Services\ServicesGroupsQueryBuilder;

if(defined('CLI')){
    require_once INC_ROOT .'/userManager/API/accessControl_CLI.php';
}
else{
    require_once INC_ROOT .'/userManager/API/accessControl.php';
    require_once INC_ROOT.'/bin/authentication/sessionControl.php';
}


function get_applicationsfilters(ARRAY $params){

    global $projectdb;

    ini_set('max_execution_time', PARSER_max_execution_time);
    ini_set("memory_limit", PARSER_max_execution_memory);

    $projectdb = selectDatabase($params['project']);

    $search = mysqli_real_escape_string($projectdb,$params['objsearch']);
    $filter = mysqli_real_escape_string($projectdb, $params['objfilter']);
    $hide_shared = mysqli_real_escape_string($projectdb, $params['hide_shared']);
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
        $params['tools_where_id'] = "10";
        $params['tools_advanced_columns_id'] = "None";
        $params['is_set_sql_filter'] = "yes";

        setFilter($params['project'], $params);
        executeSQL($params['project'], $params);

    }
    elseif(($filter == "none") || ($filter == "0")){
    }

    list($conditions, $orderby) = generateQueryFilters($params['project'], "applications_filters", "", $conditions, $source);

    $getAll = $projectdb->query("SELECT count(*) as total FROM applications_filters a $conditions;");
    $row = $getAll->fetch_assoc();
    $count = $row['total'];
    if ($count > 0) {
        $getLimit = $projectdb->query("SELECT name, id, id as idx, devicegroup, vsys, source, 'applications_filters' as table_name, category, subcategory, technology, risk, evasive_behavior, consume_big_bandwidth, prone_to_misuse, able_to_transfer_file, tunnel_other_application, used_by_malware, has_known_vulnerability, pervasive_use, merge_as_primary, used FROM applications_filters a $conditions $orderby;");
    }
    if (isset($getLimit)) {
        if ($getAll->num_rows > 0){

            while ($data = $getLimit->fetch_object()) {

                list($data->img, $data->vsys, $name_member, $myip) = getIcon("applications", "applications_filters", $data->id, "");

                $query = "SELECT tag.name as name FROM tag, tag_relations WHERE tag_relations.member_lid='".$data->id."' AND tag_relations.table_name='applications' AND tag.id = tag_relations.tag_id";
                $result = $projectdb->query($query);
                $tags = array();
                while($row = $result->fetch_assoc()){
                    $tags[]= $row['name'];
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
    return $message;
}


function delete_applicationsfilters(ARRAY $data){

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

    $getUsed = $projectdb->query("SELECT id, name, used FROM applications_filters WHERE id in (".$ids.") AND used = '0' ;");
    if ($getUsed->num_rows > 0) {
        while($getData = $getUsed->fetch_assoc()){

            $id = $getData['id'];
            $name = $getData['name'];

            $is_used = check_used_objects_in_groups($projectdb, $id, "applications_filters", "applications_groups");

            if($is_used == 0){
                $projectdb->query("DELETE FROM applications_filters WHERE id = '$id' AND dummy = 0;");
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
            $message['msg'] = "These Applications Filters '".implode(", ",$array_name_on_groups)."' used on Applications Groups. Are you sure you want to Delete?";
            return $message;
        }
        elseif($remove_references == "yes"){
            $projectdb->query("DELETE FROM applications_filters WHERE id IN (".implode(",", $array_ids_on_groups).") AND dummy = 0;");

            $projectdb->query("DELETE FROM applications_groups WHERE (member_lid IN (".implode(",", $array_ids_on_groups).") AND table_name = 'applications_filters');");
        }
    }

    $message = array();
    $message['code'] = true;
    $message['msg'] = '';
    return $message;

}
