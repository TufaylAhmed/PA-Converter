<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by aestevez
 * Date: 15/7/16 - 14:44
 */
require_once INC_ROOT.'/libs/common/tools/filters.php';
require_once INC_ROOT.'/libs/common/lib-objects.php';

if(defined('CLI')){
    require_once INC_ROOT .'/userManager/API/accessControl_CLI.php';
}
else{
    require_once INC_ROOT .'/userManager/API/accessControl.php';
    require_once INC_ROOT.'/bin/authentication/sessionControl.php';
}


function get_tags(ARRAY $params){

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
        $params['tools_where_id'] = "16";
        $params['tools_advanced_columns_id'] = "None";
        $params['is_set_sql_filter'] = "yes";

        setFilter($params['project'], $params);
        executeSQL($params['project'], $params);

    }
    elseif(($filter == "none") || ($filter == "0")){
    }

    list($conditions, $orderby) = generateQueryFilters($params['project'], "tag", "", $conditions, $source);

    $getAll = $projectdb->query("SELECT count(*) as total FROM tag a $conditions AND devicegroup!='predefined'");
    $row = $getAll->fetch_assoc();
    $count = $row['total'];
    if ($count > 0) {
        $getLimit = $projectdb->query("SELECT a.*, tc.color AS color, tc.name AS color_name FROM tag a, tag_colors tc $conditions AND a.color = tc.name AND a.devicegroup!='predefined' $orderby LIMIT $start, $limit;");
    }
    if (isset($getLimit)) {
        if ($getLimit->num_rows > 0){

            while ($data = $getLimit->fetch_object()) {

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

function get_tagsAll(ARRAY $params){

    global $projectdb;

    $count=0;
    $myData=array();

    ini_set('max_execution_time', PARSER_max_execution_time);
    ini_set("memory_limit", PARSER_max_execution_memory);

    $projectdb = selectDatabase($params['project']);

    $source = $params['source'];
    //$vsyses = getVsyses($projectdb, $params['vsys'], $source, 'quoted');

    $conditions = generate_query_multitable("objects_vsyses");

    //$search = mysqli_real_escape_string($projectdb,$params['objsearch']);
    //$filter = mysqli_real_escape_string($projectdb, $params['objfilter']);
    //$hide_shared = mysqli_real_escape_string($projectdb, $params['hide_shared']);
    $start = mysqli_real_escape_string($projectdb, $params['start']);
    $limit = mysqli_real_escape_string($projectdb, $params['limit']);


    //$conditions = " WHERE source = '$source' AND devicegroup!='predefined' ";
    $conditions .= "  AND devicegroup!='predefined' ";

    //if($params['vsys'] != "all"){
    //    $conditions .= " AND vsys IN (".implode(",", $vsyses).") ";
    //}

    $getAll = $projectdb->query("SELECT count(*) as total FROM tag a $conditions ;");
    if ($getAll->num_rows>0){
        $row = $getAll->fetch_assoc();
        $count = $row['total'];
        if ($count > 0) {
            $getLimit = $projectdb->query("SELECT * FROM tag a $conditions;");
            //$getLimit = $projectdb->query("SELECT * FROM tag a $conditions LIMIT $start, $limit;");
        }
        if (isset($getLimit)) {
            if ($getAll->num_rows > 0){

                while ($data = $getLimit->fetch_object()) {
                    $myData[] = $data;
                }
            }
        }
        if ($count == 0) {
            $myData = array();
        }
    }


    $message = array();
    $message['code'] = true;
    $message['count'] = $count;
    $message['msg'] = $myData;
    return $message;

}


function get_grouptagsAll(ARRAY $params){

    global $projectdb;

    $count=0;
    $myData=array();

    ini_set('max_execution_time', PARSER_max_execution_time);
    ini_set("memory_limit", PARSER_max_execution_memory);

    $projectdb = selectDatabase($params['project']);

    $source = $params['source'];

    $conditions = generate_query_multitable("objects_vsyses");

    $conditions .= "  AND devicegroup!='predefined' ";

    $getAll = $projectdb->query("SELECT count(*) as total FROM tag a $conditions ;");
    if ($getAll->num_rows>0){
        $row = $getAll->fetch_assoc();
        $count = $row['total'];
        if ($count > 0) {
            $getLimit = $projectdb->query("SELECT * FROM tag a $conditions;");
        }
        $myData[] = array("id"=>0,"name"=>"None");
        if (isset($getLimit)) {
            if ($getAll->num_rows > 0){

                while ($data = $getLimit->fetch_object()) {
                    $myData[] = $data;
                }
            }
        }
        if ($count == 0) {
            $myData = array();
        }
    }

    $message = array();
    $message['code'] = true;
    $message['count'] = $count;
    $message['msg'] = $myData;
    return $message;

}


function get_tagsColors(ARRAY $params){

    global $projectdb;

    $projectdb = selectDatabase($params['project']);

    $version = mysqli_real_escape_string($projectdb, $params['version']);

    $getLimit = $projectdb->query("SELECT * FROM tag_colors a WHERE version <= '$version' AND color != '';");

    $count = $getLimit->num_rows;
    if (isset($getLimit)) {
        if ($getLimit->num_rows > 0){
            while ($data = $getLimit->fetch_object()) {
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