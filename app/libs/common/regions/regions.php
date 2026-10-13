<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by aestevez
 * Date: 15/7/16 - 14:44
 */
require_once INC_ROOT.'/libs/common/tools/filters.php';

if(defined('CLI')){
    require_once INC_ROOT .'/userManager/API/accessControl_CLI.php';
}
else{
    require_once INC_ROOT .'/userManager/API/accessControl.php';
    require_once INC_ROOT.'/bin/authentication/sessionControl.php';
}

function get_defaultRegions(ARRAY $params){
    global $projectdb;
    $projectdb = selectDatabase($params['project']);

    $getDefaultRegions = $projectdb->query("SELECT id, name, help, name AS name_parser, used FROM default_regions WHERE id >= '46';");
    if ($getDefaultRegions->num_rows > 0) {
        while ($data = $getDefaultRegions->fetch_object()) {
            $data->name_parser = $data->name ." (" . $data->help . ")";
            $myData[] = $data;
        }

        $message = array();
        $message['code'] = true;
        $message['count'] = $getDefaultRegions->num_rows;
        $message['msg'] = $myData;
    }
    return $message;
}

//function get_regions(ARRAY $params){
//    global $projectdb;
//    $projectdb = selectDatabase($params['project']);
//
//    $getDefaultRegions = $projectdb->query("SELECT id, name, help, name AS name_parser, used FROM default_regions WHERE id >= '46';");
//    if ($getDefaultRegions->num_rows > 0) {
//        while ($data = $getDefaultRegions->fetch_object()) {
//            $data->name_parser = $data->name ." (" . $data->help . ")";
//            $myData[] = $data;
//        }
//
//        $message = array();
//        $message['code'] = true;
//        $message['count'] = $getDefaultRegions->num_rows;
//        $message['msg'] = $myData;
//    }
//    return $message;
//}

function get_regions(ARRAY $params){

    global $projectdb;

    ini_set('max_execution_time', PARSER_max_execution_time);
    ini_set("memory_limit", PARSER_max_execution_memory);

    $projectdb = selectDatabase($params['project']);

    $conditions = generate_query_multitable("objects_vsyses");

    $filter = mysqli_real_escape_string($projectdb, $params['objfilter']);
    $hide_shared = mysqli_real_escape_string($projectdb, $params['hide_shared']);
    $start = mysqli_real_escape_string($projectdb, $params['start']);
    $limit = mysqli_real_escape_string($projectdb, $params['limit']);
    $source = mysqli_real_escape_string($projectdb, $params['source']);

    if($hide_shared == "true"){
        if (preg_match("/WHERE/", $conditions)) {
            $conditions .= " AND a.vsys != 'shared' ";
        }
        else{
            $conditions .= " WHERE a.vsys != 'shared' ";
        }
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
        $params['tools_where_id'] = "15";
        $params['tools_advanced_columns_id'] = "None";
        $params['is_set_sql_filter'] = "yes";

        setFilter($params['project'], $params);
        executeSQL($params['project'], $params);

    }
    elseif(($filter == "none") || ($filter == "0")){
    }

    list($conditions, $orderby) = generateQueryFilters($params['project'], "regions", "", $conditions, $source);

    $getAll = $projectdb->query("SELECT count(*) as total FROM regions a $conditions");
    $row = $getAll->fetch_assoc();
    $count = $row['total'];
    if ($count > 0) {
        $getLimit = $projectdb->query("SELECT *, 'regions' AS table_name FROM regions a $conditions $orderby LIMIT $start, $limit;");
    }
    if (isset($getLimit)) {
        if ($getAll->num_rows > 0){

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
    //print_r($myData);
    return $message;
}
