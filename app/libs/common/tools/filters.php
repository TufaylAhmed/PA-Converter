<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserverd.
 */

require_once INC_ROOT.'/libs/common/panosGlobalReq.php';

if(defined('CLI')){
    require_once INC_ROOT .'/userManager/API/accessControl_CLI.php';
}
else{
    require_once INC_ROOT .'/userManager/API/accessControl.php';
    require_once INC_ROOT.'/bin/authentication/sessionControl.php';
}

require_once INC_ROOT.'/libs/common/MemberObject.php';
use PaloaltoNetworks\Policy\Objects\MemberObject;


function getWhere(STRING $projectName, STRING $scope){

    global $projectdb;
    $projectdb = selectDatabase($projectName);

    $myData = array();
    $result = $projectdb->query("SELECT * FROM tools_where ORDER BY order_by;");
    if ($result->num_rows > 0){
        while($row = $result->fetch_object()){
            $myData[]= $row;
        }
    }

    $message = array();
    $message['code'] = true;
    $message['count'] = $result->num_rows;
    $message['msg'] = $myData;

    return $message;

}


function getColumns(STRING $projectName, ARRAY $params){

    global $projectdb;
    $projectdb = selectDatabase($projectName);

    $tools_where_id = $params['tools_where_id'];
    $count = 0;
    $first = 0;
    $myData = array();
    $tools_where_columns_id_array = array();

    if($tools_where_id != ""){

        $getWC = $projectdb->query("SELECT tools_where_columns_id FROM tools_where WHERE id IN ($tools_where_id);");
        //echo "SELECT tools_where_columns_id FROM tools_where WHERE id IN ($tools_where_id);";
        if ($getWC->num_rows > 0){
            while($dataWC = $getWC->fetch_assoc()){
                $tools_where_columns_id_exp = explode(",", $dataWC['tools_where_columns_id']);

                if($first == 0){
                    $tools_where_columns_id_array = $tools_where_columns_id_exp;
                    $first = 1;
                    $only_one = 1;
                }else{
                    $result = array_intersect($tools_where_columns_id_array, $tools_where_columns_id_exp);
                    $tools_where_columns_id_array = $result;
                    $only_one = 0;
                }
                //echo "INTERSECT:\n";
                //print_r($tools_where_columns_id_array);
            }
        }

        if($only_one == 1){
            //$result = $projectdb->query("SELECT * FROM tools_where_columns WHERE id IN (".implode(",", $tools_where_columns_id_array).") ORDER BY FIELD (id, " . implode(",", $tools_where_columns_id_array) . ");");
            $result = $projectdb->query("SELECT * FROM tools_where_columns WHERE id IN (".implode(",", $tools_where_columns_id_array).") ORDER BY order_by;");
            //echo "SELECT * FROM tools_where_columns WHERE id IN (".implode(",", $tools_where_columns_id_array).") ORDER BY order_by;";

            //echo "SELECT * FROM tools_where_columns WHERE id IN (".implode(",", $tools_where_columns_id_array).") ORDER BY FIELD (id, " . implode(",", $tools_where_columns_id_array) . ");";
        }
        else{
            $result = $projectdb->query("SELECT * FROM tools_where_columns WHERE id IN (".implode(",", $tools_where_columns_id_array).") ORDER BY order_by;");
        }
        $count = $result->num_rows;
        if ($count > 0){
            while($row = $result->fetch_object()){
                $myData[]= $row;
            }
        }
    }

    $message = array();
    $message['code'] = true;
    $message['count'] = $count;
    $message['msg'] = $myData;

    return $message;

}


function getColumnsPredefined(STRING $projectName, ARRAY $params){

    global $projectdb;
    $projectdb = selectDatabase($projectName);

    $tools_where_id = $params['tools_where_id'];
    $count = 0;
    $first = 0;
    $myData = array();
    $tools_where_columns_id_array = array();

    if($tools_where_id != ""){

        $getWC = $projectdb->query("SELECT tools_where_columns_id FROM tools_where WHERE id IN ($tools_where_id);");
        //echo "SELECT tools_where_columns_id FROM tools_where WHERE id IN ($tools_where_id);";
        if ($getWC->num_rows > 0){
            while($dataWC = $getWC->fetch_assoc()){
                $tools_where_columns_id_exp = explode(",", $dataWC['tools_where_columns_id']);

                if($first == 0){
                    $tools_where_columns_id_array = $tools_where_columns_id_exp;
                    $first = 1;
                    $only_one = 1;
                }else{
                    $result = array_intersect($tools_where_columns_id_array, $tools_where_columns_id_exp);
                    $tools_where_columns_id_array = $result;
                    $only_one = 0;
                }
                //echo "INTERSECT:\n";
                //print_r($tools_where_columns_id_array);
            }
        }

        if($only_one == 1){
            //$result = $projectdb->query("SELECT * FROM tools_where_columns WHERE id IN (".implode(",", $tools_where_columns_id_array).") AND (name LIKE '%(Predefined)%' OR name LIKE '%(BP)%' OR name LIKE '%(ML)%' ) ORDER BY FIELD (id, " . implode(",", $tools_where_columns_id_array) . ");");
            $result = $projectdb->query("SELECT * FROM tools_where_columns WHERE id IN (".implode(",", $tools_where_columns_id_array).") AND (name LIKE '%(Predefined)%' OR name LIKE '%(BP)%' OR name LIKE '%(ML)%' ) ORDER BY order_by;");

            //echo "SELECT * FROM tools_where_columns WHERE id IN (".implode(",", $tools_where_columns_id_array).") ORDER BY FIELD (id, " . implode(",", $tools_where_columns_id_array) . ");";
        }
        else{
            $result = $projectdb->query("SELECT * FROM tools_where_columns WHERE id IN (".implode(",", $tools_where_columns_id_array).") AND (name LIKE '%(Predefined)%' OR name LIKE '%(BP)%' OR name LIKE '%(ML)%' ) ORDER BY order_by;");
        }
        $count = $result->num_rows;
        if ($count > 0){
            while($row = $result->fetch_object()){
                $myData[]= $row;
            }
        }
    }

    $message = array();
    $message['code'] = true;
    $message['count'] = $count;
    $message['msg'] = $myData;

    return $message;

}


function getAdvancedOptions(STRING $projectName, ARRAY $params){

    global $projectdb;
    $projectdb = selectDatabase($projectName);

    $tools_where_id = $params['tools_where_id'];
    $count = 0;
    $first = 0;
    $myData = array();
    $tool_advanced_columns_id_array = array();
    if($tools_where_id != ""){

        $getWC = $projectdb->query("SELECT tools_advanced_columns_id FROM tools_where WHERE id IN ($tools_where_id);");
        if ($getWC->num_rows > 0){
            while($dataWC = $getWC->fetch_assoc()){
                $tool_advanced_columns_id_exp = explode(",", $dataWC['tools_advanced_columns_id']);

                if($first == 0){
                    $tool_advanced_columns_id_array = $tool_advanced_columns_id_exp;
                    $first = 1;
                }else{
                    $result = array_intersect($tool_advanced_columns_id_array, $tool_advanced_columns_id_exp);
                    $tool_advanced_columns_id_array = $result;
                }
                //echo "INTERSECT:\n";
                //print_r($tools_where_columns_id_array);
            }
        }

        $result = $projectdb->query("SELECT * FROM tools_advanced_columns WHERE id IN (".implode(",", $tool_advanced_columns_id_array).");");
        $count = $result->num_rows;
        if ($count > 0){
            while($row = $result->fetch_object()){
                $myData[]= $row;
            }
        }
    }

    $message = array();
    $message['code'] = true;
    $message['count'] = $count;
    $message['msg'] = $myData;

    return $message;

}


function getOperator(STRING $projectName, ARRAY $params){

    global $projectdb;
    $projectdb = selectDatabase($projectName);

    $tools_where_id = $params['tools_where_id'];
    $count = 0;
    $first = 0;
    $myData = array();
    $tool_operator_id_array = array();

    if(($tools_where_id == "") || ($tools_where_id == "Name")){
        $tools_where_id = 1;
    }

    //$getWC = $projectdb->query("SELECT tools_operator_id FROM tools_where WHERE id IN ($tools_where_id);");
    $getWC = $projectdb->query("SELECT tools_operator_id FROM tools_where_columns WHERE id IN ($tools_where_id);");
    if ($getWC->num_rows > 0){
        while($dataWC = $getWC->fetch_assoc()){

            if($dataWC['tools_operator_id'] != ""){
                $tool_operator_id_exp = explode(",", $dataWC['tools_operator_id']);

                if($first == 0){
                    $tool_operator_id_array = $tool_operator_id_exp;
                    $first = 1;
                }else{
                    $result = array_intersect($tool_operator_id_array, $tool_operator_id_exp);
                    $tool_operator_id_array = $result;
                }
            }
        }
    }


    if(count($tool_operator_id_array) > 0){

        $result = $projectdb->query("SELECT * FROM tools_operator WHERE id IN (".implode(",", $tool_operator_id_array).");");
        $count = $result->num_rows;
        if ($count > 0){
            while($row = $result->fetch_object()){
                $myData[]= $row;
            }
        }
    }
    else{
        $myData[] = array("id" => "0", "name" => "", "operator" => "");
    }



    $message = array();
    $message['code'] = true;
    $message['count'] = $count;
    $message['msg'] = $myData;

    return $message;

}


function getFiltersTree(STRING $projectName, ARRAY $params){

    global $projectdb;
    global $app;

    $projectdb = selectDatabase($projectName);

    $user = $app->container->sentinel->getUser();
    $user_id = $user->id;

    $source = $params['source'];

    $conditions = "";
    if (preg_match("/ WHERE /", $conditions)) {
        $conditions = $conditions . " AND active = '1' ";
    } else {
        $conditions = " WHERE active = '1' ";
    }

    $master_all = array();

    $getAll = $projectdb->query("SELECT id, filter_name FROM tools_filters $conditions AND source = '$source' AND user_id = '$user_id';");
    //echo "SELECT id, filter_name FROM tools_filters $conditions AND source = '$source' AND user_id = '$user_id';";
    $count = $getAll->num_rows;
    if ($count > 0) {
        while ($data = $getAll->fetch_assoc()) {
            $filter_name = $data['filter_name'];
            $id = $data['id'];

            $master = [
                "expanded" => true,
                "id" => $id,
                "text" => $filter_name,
                "value" => "tools_filters",
                "glyph" => "xf0b0@FontAwesome",
                "leaf" => true,
                "filtername" => $filter_name,

            ];

            $master_all[] = $master;
        }
        /*$root = [
            'text' => 'Root',
            'expanded' => true,
            'children' => $master_all
        ];*/
    }

    $root = [
        'text' => 'Root',
        'expanded' => true,
        'children' => $master_all
    ];

    $message = array();
    $message['code'] = true;
    $message['count'] = $count;
    $message['msg'] = $root;
    return $message;
}

function getSQLTree(STRING $projectName, ARRAY $params){

    global $projectdb;
    global $app;

    $projectdb = selectDatabase($projectName);
    $user = $app->container->sentinel->getUser();
    $user_id = $user->id;
    $source = $params['source'];

    $firstOperators = array();

    $query = "SELECT id, parent_id, name, filter_id FROM tools_sql WHERE parent_id = '0' AND source = '$source' AND user_id = '$user_id';";
    $getParent = $projectdb->query($query);
    $count = $getParent->num_rows;
    if ($count > 0) {
        while ($dataP = $getParent->fetch_assoc()) {
            $sql_name = $dataP['name'];
            $id_sql = $dataP['id'];
            $filter_id = $dataP['filter_id'];

            if ($sql_name == "") {    $sql_name = "OR";       }

            $firstOperator = [
                "expanded" => true,
                "id" => $id_sql,
                "text" => $sql_name,
                "value" => "tools_sql",
                "glyph" => "xf0c1@FontAwesome",
                "sqlname" => $sql_name,
                "leaf" => false
            ];

            if ($filter_id != "") {  //The first branch has already leaves
                    $leaves = getChildrenFiltersTree($projectdb, $id_sql, $sql_name, $filter_id);
            }
            else{
                    $leaves = null;
            }

            $branches = getSubBranches($projectdb, $id_sql);

            if (count($branches) > 0 && $leaves!= null) {
                $firstOperator['children'] = array_merge($leaves, $branches);
            }
            elseif($leaves != null) {
                $firstOperator['children'] = $leaves;
            }
            elseif(count($branches)>0) {
                $firstOperator['children'] = $branches;
            }
            else{
                unset($firstOperator['children']);
                $firstOperator['expanded'] = false;
                $firstOperator['leaf'] = true;
            }

            $firstOperators[] = $firstOperator;
        }

    }

    $root = [
        'text' => 'Root',
        'expanded' => true,
        'children' => $firstOperators
    ];

    $message = array();
    $message['code'] = true;
    $message['count'] = $count;
    $message['msg'] = $root;
    return $message;
}

function getSubBranches(mysqli $projectdb, $id_sql){
    $branches = array();
    $query = "SELECT id, parent_id, name, filter_id FROM tools_sql WHERE parent_id = '$id_sql' ;";
    $branchesResource = $projectdb->query($query);

    while($row = $branchesResource->fetch_object()){
        $sql_name = $row->name;
        $id_sql = $row->id;
        $filter_id = $row->filter_id;

        if($sql_name == ""){   $sql_name = "OR";    }

        $branch = [
            "expanded" => true,
            "id" => $id_sql,
            "text" => $sql_name,
            "value" => "tools_sql",
            "glyph" => "xf0c1@FontAwesome",
            "sqlname" => $sql_name,
            "leaf" => false,
            "children" => array()
        ];

        if($filter_id != ""){  //The first branch has already leaves
            $leaves = getChildrenFiltersTree($projectdb, $id_sql, $sql_name, $filter_id);
        }
        else{
            $leaves = null;
        }

        $subBranches = getSubBranches($projectdb, $id_sql);

        if (count($subBranches) > 0 && $leaves!= null) {
            $branch['children'] = array_merge($leaves, $subBranches);
        } elseif($leaves != null) {
            $branch['children'] = $leaves;
        } elseif(count($subBranches)>0) {
            $branch['children'] = $subBranches;
        }else{
            unset($branch['children']);
            $branch['expanded'] = false;
            $branch['leaf'] = true;
        }

        $branches[] = $branch;
    }
    return $branches;
}

function getSQLTreeOld(STRING $projectName, ARRAY $params){

    global $projectdb;
    global $app;

    $projectdb = selectDatabase($projectName);

    $user = $app->container->sentinel->getUser();
    $user_id = $user->id;

    $conditions = generate_query("objects");

    $source = $params['source'];

    $root = "";
    $master_parent_0 = array();

    $getParent = $projectdb->query("SELECT id, parent_id, name, filter_id FROM tools_sql WHERE parent_id = '0' AND source = '$source' AND user_id = '$user_id';");
    $count = $getParent->num_rows;
    if ($count > 0) {
        while ($dataP = $getParent->fetch_assoc()) {
            $sql_name = $dataP['name'];
            $id_sql = $dataP['id'];
            $filter_id = $dataP['filter_id'];

            if($filter_id != ""){
                // Primero, parent_id 0 y luego filters
                // Si es solo un filtro

                $master = getChildrenFiltersTree($projectdb, $id_sql, $sql_name, $filter_id);
                $master_parent_0[] = $master;
            }

            //It may also contain sub boolean-combinations
            if(true){
                if($sql_name == ""){
                    $sql_name = "OR";
                }
                $have_parent_id = haveParentId($projectName, $id_sql);
                if($have_parent_id){
                    // AND anidados sin filtros
                    $master = getChildrenSQLTree($projectName, $id_sql, $sql_name);
                    $master_parent_0[] = $master;
                }
                else{
                    $master = [
                        "expanded" => true,
                        "id" => $id_sql,
                        "text" => $sql_name,
                        "value" => "tools_sql",
                        "glyph" => "xf0c1@FontAwesome",
                        "sqlname" => $sql_name,
                        "leaf" => true
                    ];

                    $master_parent_0[] = $master;
                }
            }
        }
    }

    $root = [
        'text' => 'Root',
        'expanded' => true,
        'children' => $master_parent_0
    ];

    $message = array();
    $message['code'] = true;
    $message['count'] = $count;
    $message['msg'] = $root;
    return $message;
}

function getChildrenSQLTree(STRING $projectName, $id_sql, $sql_name){

    global $projectdb;
    $projectdb = selectDatabase($projectName);

    $sql_children = array();

    $master = array();

    $getFilterChildren = $projectdb->query("SELECT id, parent_id, name, filter_id FROM tools_sql WHERE parent_id = '$id_sql' ;");
    if ($getFilterChildren->num_rows > 0) {
        while ($dataFC = $getFilterChildren->fetch_assoc()) {
            $name_sql = $dataFC['name'];
            $id_sql_child = $dataFC['id'];
            $filter_id = $dataFC['filter_id'];

            if($filter_id == ""){
                $sql_children[] = [
                    "expanded" => true,
                    "id" => $id_sql_child,
                    "text" => $name_sql,
                    "value" => "tools_sql",
                    "glyph" => "xf0c1@FontAwesome",
                    "sqlname" => $name_sql,
                    "leaf" => true
                ];
            }
            else{
                $sql_children[] = getChildrenFiltersTree($projectdb, $id_sql_child, $name_sql, $filter_id);
            }

            $master = [
                "expanded" => true,
                "id" => $id_sql,
                "text" => $sql_name,
                "value" => "tools_sql",
                "glyph" => "xf0c1@FontAwesome",
                "sqlname" => $sql_name,
                "leaf" => false,
                "children"=> $sql_children
            ];

        }
    }

    return $master;

}

function getChildrenFiltersTree(mysqli $projectdb, $id_sql, $sql_name, $filter_id){
    $master = array();

    $query = "SELECT id, filter_name FROM tools_filters WHERE id IN (".$filter_id.") ;";
    $getFilterChildren = $projectdb->query($query);

    if ($getFilterChildren->num_rows > 0) {
        while($dataFC = $getFilterChildren->fetch_assoc()) {
            $filter_name = $dataFC['filter_name'];
            $id_filter = $dataFC['id'];

            $master[] = [
                "expanded" => true,
                "id" => $id_filter,
                "text" => $filter_name,
                "value" => "tools_filters",
                "glyph" => "xf0b0@FontAwesome",
                "sqlname" => $id_sql,
                "leaf" => true
            ];
        }
    }
    return $master;
}

function getChildrenFiltersTreeOld(STRING $projectName, $id_sql, $sql_name, $filter_id){

    global $projectdb;
    $projectdb = selectDatabase($projectName);

    $master = array();
    $filters_children = array();


    $only_one_filter = strpos($filter_id, ",");

    if (($only_one_filter === false) && ($sql_name == "")){

        $getFilterChildren = $projectdb->query("SELECT id, filter_name FROM tools_filters WHERE id IN (".$filter_id.") ;");
        if ($getFilterChildren->num_rows == 1) {
        $dataFC = $getFilterChildren->fetch_assoc();

            $filter_name = $dataFC['filter_name'];
            $id_filter = $dataFC['id'];

            $master = [
                "expanded" => false,
                "id" => $id_filter,
                "text" => $filter_name,
                "value" => "tools_filters",
                "glyph" => "xf0b0@FontAwesome",
                "sqlname" => $id_sql,
                "leaf" => true
            ];
        }
    }
    else{
        if($sql_name == ""){
            $sql_name = "OR";
        }

        $getFilterChildren = $projectdb->query("SELECT id, filter_name FROM tools_filters WHERE id IN (".$filter_id.") ;");
        if ($getFilterChildren->num_rows > 0) {
            while ($dataFC = $getFilterChildren->fetch_assoc()) {

                $filter_name = $dataFC['filter_name'];
                $id_filter = $dataFC['id'];

                $filters_children[] = [
                    "expanded" => true,
                    "id" => $id_filter,
                    "text" => $filter_name,
                    "value" => "tools_filters",
                    "glyph" => "xf0b0@FontAwesome",
                    "sqlname" => $id_sql,
                    "leaf" => true
                ];
            }

            $master = [
                "expanded" => true,
                "id" => $id_sql,
                "text" => $sql_name,
                "value" => "tools_sql",
                "glyph" => "xf0c1@FontAwesome",
                "sqlname" => $sql_name,
                "leaf" => false,
                "children"=> $filters_children

            ];
        }

    }

    return $master;

}


function haveParentId(STRING $projectName, $id_sql){

    global $projectdb;
    $projectdb = selectDatabase($projectName);

    //$getParent = $projectdb->query("SELECT id, parent_id, name, filter_id FROM tools_sql WHERE parent_id = '$id_sql' AND filter_id = '';");
    $getParent = $projectdb->query("SELECT id, parent_id, name, filter_id FROM tools_sql WHERE parent_id = '$id_sql';");

    if ($getParent->num_rows == 0) {
        return false;
    }else{
        return true;
    }

}


function getExistFilter(STRING $projectName, ARRAY $params){

    global $projectdb;
    $projectdb = selectDatabase($projectName);

    $tools_where_id = $params['tools_where_id'];
    $source = $params['source'];

    $result = $projectdb->query("SELECT * FROM tools_filters WHERE tools_where_id = '$tools_where_id' AND source = '$source';");
    if ($result->num_rows > 0){
        $exist_filter = "yes";
    }else{
        $exist_filter = "no";
    }

    $message = array();
    $message['code'] = true;
    $message['count'] = $result->num_rows;
    $message['msg'] = $exist_filter;

    return $message;

}


function setFilterMultiSelection(STRING $projectName, ARRAY $params){

    global $projectdb;
    $projectdb = selectDatabase($projectName);

    $selection_all = $params['selection'];

    $selection = explode(",", $selection_all);

    foreach ($selection as $object) {

        $object_filter = explode(";", $object);

        if($object_filter[1] == "address_groups"){$tools_where_id = "6";
        }elseif($object_filter[1] == "services_groups"){$tools_where_id = "8";
        }elseif($object_filter[1] == "address"){$tools_where_id = "5";
        }elseif($object_filter[1] == "services"){$tools_where_id = "7";
        }elseif($object_filter[1] == "applications"){$tools_where_id = "9";
        }elseif($object_filter[1] == "applications_filters"){$tools_where_id = "10";
        }elseif($object_filter[1] == "applications_groups"){$tools_where_id = "11";
        }elseif($object_filter[1] == "default_applications"){$tools_where_id = "12";
        }elseif($object_filter[1] == "tags"){$tools_where_id = "16";}

        $params['tools_where_columns_id'] = "Name";
        $params['tools_operator_id'] = "1";
        $params['search'] = $object_filter[2];
        $params['tools_where_id'] = $tools_where_id;
        $params['tools_advanced_columns_id'] = "None";
        $params['case_sensitive'] = "0";

        setFilter($projectName, $params, "");

    }

    $message['code']=false;
    return $message;
}


function setFilter(STRING $projectName, ARRAY $params){

    global $projectdb;
    global $app;

    $projectdb = selectDatabase($projectName);

    $user = $app->container->sentinel->getUser();
    $user_id = $user->id;

    $tools_where_columns_id = $params['tools_where_columns_id'];
    $tools_operator_id = $params['tools_operator_id'];
    $search = $params['search'];
    $tools_where_id = $params['tools_where_id'];
    $source = $params['source'];
    $tools_advanced_columns_id = $params['tools_advanced_columns_id'];
    $case_sensitive = $params['case_sensitive'];
    $vsys = $params['vsys'];

    $case_sensitive_sql = "";

    $is_set_sql_filter = $params['is_set_sql_filter'];

    $search = preg_replace("/[^a-zA-Z0-9-_*.\/ ]+/", ";", $search);
    $search = ltrim($search, ";");
    $search_explode = explode(";", $search);

    foreach ($search_explode as $key=>$search) {

        $tool_where_columns = array();

        if(is_array($tools_where_id)){
            $tools_where_id = implode(",", $tools_where_id);
            if(empty($tools_where_id)){
                $tools_where_id = "1";
                $tools_where_id_sql = "All";
            }else{
                $getW = $projectdb->query("SELECT name FROM tools_where WHERE id IN ($tools_where_id);");
                if ($getW->num_rows > 0){
                    while($dataW = $getW->fetch_assoc()){
                        $tool_where_columns[] = $dataW['name'];
                    }
                    $tools_where_id_sql = implode(",", $tool_where_columns);
                }
            }
        }else{
            $getW = $projectdb->query("SELECT name FROM tools_where WHERE id IN ($tools_where_id);");
            if ($getW->num_rows > 0){
                while($dataW = $getW->fetch_assoc()){
                    $tool_where_columns[] = $dataW['name'];
                }
                $tools_where_id_sql = implode(",", $tool_where_columns);
            }
        }

        if(($tools_where_columns_id == "Name") || ($tools_where_columns_id == "") ){
            $tools_where_columns_id = "1";
        }
        $getWC = $projectdb->query("SELECT name FROM tools_where_columns WHERE id IN ($tools_where_columns_id);");
        if ($getWC->num_rows > 0){
            $dataWC = $getWC->fetch_assoc();
            $filter_column = $dataWC['name'];
        }

        if(($tools_operator_id == "contains") || ($tools_operator_id == "null") || (empty($tools_operator_id))){
            $tools_operator_id = "1";
        }
        $getO = $projectdb->query("SELECT name FROM tools_operator WHERE id IN ($tools_operator_id);");
        if ($getO->num_rows > 0){
            $dataO = $getO->fetch_assoc();
            $tools_operator_sql = $dataO['name'];
        }

        if(($tools_advanced_columns_id != "") && ($tools_advanced_columns_id != "None") && ($tools_advanced_columns_id != "none")){

            $getAO = $projectdb->query("SELECT name FROM tools_advanced_columns WHERE id IN ($tools_advanced_columns_id);");
            if ($getAO->num_rows > 0){
                $dataAO = $getAO->fetch_assoc();
                $advanced_options = $dataAO['name'];
                $advanced_options_sql = 'and \"'.$advanced_options.'\" ';
            }
        }
        else{
            $advanced_options_sql = "";
            $tools_advanced_columns_id = "";
        }

        if(($tools_where_columns_id != "") && ($tools_operator_id != "") ){

            if($case_sensitive == 1){
                $case_sensitive_sql = "(CS)";
            }

            //Those are predefined filters that should not present filter text
            if (($tools_where_columns_id == "73") || ($tools_where_columns_id == "74") || ($tools_where_columns_id == "75")
                || ($tools_where_columns_id == "76") || ($tools_where_columns_id == "77") || ($tools_where_columns_id == "78")
                || ($tools_where_columns_id == "79") || ($tools_where_columns_id == "80") || ($tools_where_columns_id == "81")
                || ($tools_where_columns_id == "82") || ($tools_where_columns_id == "83") || ($tools_where_columns_id == "84")
                || ($tools_where_columns_id == "86") || ($tools_where_columns_id == "87") || ($tools_where_columns_id == "88")
                || ($tools_where_columns_id == "89") || ($tools_where_columns_id == "90") || ($tools_where_columns_id == "91")
                || ($tools_where_columns_id == "92") || ($tools_where_columns_id == "93") || ($tools_where_columns_id == "94")
                || ($tools_where_columns_id == "95") || ($tools_where_columns_id == "96") || ($tools_where_columns_id == "105")
                || ($tools_where_columns_id == "106") || ($tools_where_columns_id == "107") || ($tools_where_columns_id == "108")
                || ($tools_where_columns_id == "109") || ($tools_where_columns_id == "110") || ($tools_where_columns_id == "111")
                || ($tools_where_columns_id == "112") || ($tools_where_columns_id == "113") || ($tools_where_columns_id == "114")
                || ($tools_where_columns_id == "115") || ($tools_where_columns_id == "118") || ($tools_where_columns_id == "119")
                || ($tools_where_columns_id == "120") || ($tools_where_columns_id == "121") || ($tools_where_columns_id == "122")
                || ($tools_where_columns_id == "123") || ($tools_where_columns_id == "126") || ($tools_where_columns_id == "127")  ){

                $getExistPolicyFilter = $projectdb->query("SELECT id FROM tools_filters WHERE tools_where_columns_id = '$tools_where_columns_id' "
                    . " AND tools_operator_id = '$tools_operator_id' AND search = '$search' AND tools_where_id = '$tools_where_id' AND vsys = '$vsys' AND source = '$source' AND user_id = '$user_id' AND case_sensitive = '$case_sensitive'; ");

                if ($getExistPolicyFilter->num_rows == 0) {
                    $projectdb->query("INSERT INTO tools_filters (id, filter_name, tools_where_columns_id, tools_operator_id, search, tools_where_id, vsys, source, user_id, case_sensitive) "
                        . "VALUES (NULL, '$filter_column $case_sensitive_sql on \"$tools_where_id_sql\" on vsys \"$vsys\" $advanced_options_sql', '$tools_where_columns_id', '$tools_operator_id', '$search', '$tools_where_id', '$vsys', '$source', '$user_id', '$case_sensitive'); ");
                    $params['filter_id'] = $projectdb->insert_id;
                }
                else{
                    $dataEPF = $getExistPolicyFilter->fetch_assoc();
                    $params['filter_id'] = $dataEPF['id'];
                }

            }
            else if ( ($tools_where_columns_id == "132") || ($tools_where_columns_id == "133") ) {  //Filters related to Rule Hits
                $getExistPolicyFilter = $projectdb->query("SELECT id FROM tools_filters WHERE tools_where_columns_id = '$tools_where_columns_id' "
                    . " AND tools_operator_id = '$tools_operator_id' AND search = '$search' AND tools_where_id = '$tools_where_id' AND vsys = '$vsys' AND source = '$source' AND user_id = '$user_id' AND case_sensitive = '$case_sensitive'; ");

                if ($getExistPolicyFilter->num_rows == 0) {
                    $projectdb->query("INSERT INTO tools_filters (id, filter_name, tools_where_columns_id, tools_operator_id, search, tools_where_id, vsys, source, user_id, case_sensitive) "
                        . "VALUES (NULL, '$filter_column during $case_sensitive_sql $tools_operator_sql on \"$tools_where_id_sql\" on vsys \"$vsys\" $advanced_options_sql', '$tools_where_columns_id', '$tools_operator_id', '$search', '$tools_where_id', '$vsys', '$source', '$user_id', '$case_sensitive'); ");
                    $params['filter_id'] = $projectdb->insert_id;
                }
                else{
                    $dataEPF = $getExistPolicyFilter->fetch_assoc();
                    $params['filter_id'] = $dataEPF['id'];
                }
            }
            else{

                $getExistPolicyFilter = $projectdb->query("SELECT id FROM tools_filters WHERE tools_where_columns_id = '$tools_where_columns_id'  
                    AND tools_operator_id = '$tools_operator_id' AND BINARY search = '$search' AND tools_where_id = '$tools_where_id' AND case_sensitive = '$case_sensitive'
                    AND vsys = '$vsys' AND source = '$source' AND user_id = '$user_id' ; ");

                if ($getExistPolicyFilter->num_rows == 0) {
                    $projectdb->query("INSERT INTO tools_filters (id, filter_name, tools_where_columns_id, tools_operator_id, search, tools_where_id, case_sensitive, vsys, source, user_id) "
                        . "VALUES (NULL, '$filter_column $tools_operator_sql \"$search\" $case_sensitive_sql on \"$tools_where_id_sql\" on vsys \"$vsys\" $advanced_options_sql', '$tools_where_columns_id', '$tools_operator_id', '$search', '$tools_where_id', '$case_sensitive', '$vsys', '$source', '$user_id'); ");

                    $params['filter_id'] = $projectdb->insert_id;
                }
                else{
                    $dataEPF = $getExistPolicyFilter->fetch_assoc();
                    $params['filter_id'] = $dataEPF['id'];
                }
            }
        }

        if($is_set_sql_filter == "yes"){

            $getToolsSql = $projectdb->query("SELECT id, filter_id FROM tools_sql WHERE parent_id = '0' AND user_id = '$user_id' AND source = '$source'; ");

            if ($getToolsSql->num_rows == 0) {
                $params['sql_id'] = '0';
            }
            else{
                $dataTS = $getToolsSql->fetch_assoc();

                $params['sql_id'] = $dataTS['id'];
            }

            setSQLFilter($projectName, $params, "yes");

        }

    }

    $message['code']=false;
    return $message;
}


function setSQL(STRING $projectName, ARRAY $params){

    global $projectdb;
    global $app;

    $projectdb = selectDatabase($projectName);

    $user = $app->container->sentinel->getUser();
    $user_id = $user->id;

    $type_sql = $params['type_sql'];
    $source = $params['source'];

    $getExistSQL = $projectdb->query("SELECT id FROM tools_sql WHERE source = '$source' AND user_id = '$user_id'; ");

    if ($getExistSQL->num_rows == 0) {
        // First
        $projectdb->query("INSERT INTO tools_sql (id, parent_id, name, filter_id, source, user_id) "
            . "VALUES (NULL, '0', '$type_sql', '', '$source', '$user_id'); ");
    }
    else{
        $projectdb->query("INSERT INTO tools_sql (id, parent_id, name, filter_id, source, user_id) "
            . "VALUES (NULL, '0', '$type_sql', '', '$source', '$user_id'); ");
    }

    $message['code']=false;
    return $message;
}


function setSQLFilter(STRING $projectName, ARRAY $params, $is_search_and_replace){

    global $projectdb;
    global $app;

    $projectdb = selectDatabase($projectName);

    $user = $app->container->sentinel->getUser();
    $user_id = $user->id;

    $id_old = "";
    $sql_id = $params['sql_id'];
    $source = $params['source'];

    if($is_search_and_replace == "yes"){
        $filter_id = $params['filter_id'];
        $table_name = "tools_filters";

        $changes = $filter_id.";".$table_name."; ;";
    }
    else{
        $changes = $params['changes'];
    }

    $changes_array = explode(",", $changes);

    foreach ($changes_array as $changes_data) {

        $data = explode(";", $changes_data);

        $filter_id = $data[0];
        $table_name = $data[1];
        $id_old = $data[2];


        if($table_name == "tools_filters"){
            if($sql_id == "0"){
                // After where
                $getFiltersWhere = $projectdb->query("SELECT id, filter_id, name FROM tools_sql WHERE parent_id = '0' AND source = '$source' AND user_id = '$user_id'; ");

                if ($getFiltersWhere->num_rows == 0) {
                    $projectdb->query("INSERT INTO tools_sql (id, parent_id, name, filter_id, source, user_id) "
                        . "VALUES (NULL, '0', '', $filter_id, '$source', '$user_id'); ");

                    $last_insert_id = $projectdb->insert_id;
                    $projectdb->query("UPDATE tools_filters SET tools_sql_id = '$last_insert_id' WHERE id = '$filter_id'; ");
                }
                elseif($getFiltersWhere->num_rows == 1) {
                    // Add AND between two filters
                    $dataFW = $getFiltersWhere->fetch_assoc();
                    $filters_in_where = $dataFW['filter_id'];
                    $sql_id = $dataFW['id'];
                    $name_sql_exist = $dataFW['name'];

                    if($name_sql_exist == ""){
                        $name_sql_exist = "OR";
                    }
                    if($filters_in_where != ""){
                        $filters_explode_where = explode(",", $filters_in_where);
                        $filters_explode_where[] = $filter_id;
                        $projectdb->query("UPDATE tools_sql SET filter_id = '" . implode(",", $filters_explode_where) . "', name = '$name_sql_exist' WHERE id = '$sql_id'; ");
                        //echo "Query 2: UPDATE tools_sql SET filter_id = '" . implode(",", $filters_explode_where) . "', name = 'OR' WHERE id = '$sql_id'; ";
                    }else{
                        $projectdb->query("UPDATE tools_sql SET filter_id = '$filter_id', name = '$name_sql_exist' WHERE id = '$sql_id'; ");
                    }
                    $projectdb->query("UPDATE tools_filters SET tools_sql_id = '$sql_id' WHERE id = '$filter_id'; ");
                }
                else{
                    $dataFW = $getFiltersWhere->fetch_assoc();
                    $filters_in_where = $dataFW['filter_id'];
                    $sql_id = $dataFW['id'];

                    if($filters_in_where != ""){
                        $filters_explode_where = explode(",", $filters_in_where);
                        $filters_explode_where[] = $filter_id;
                        $projectdb->query("UPDATE tools_sql SET filter_id = '" . implode(",", $filters_explode_where) . "' WHERE id = '$sql_id'; ");
                        //echo "Query3: UPDATE tools_sql SET filter_id = '" . implode(",", $filters_explode_where) . "' WHERE id = '$sql_id'; ";
                    }
                    $projectdb->query("UPDATE tools_filters SET tools_sql_id = '$sql_id' WHERE id = '$filter_id'; ");
                }

            }
            else{

                $getFilters = $projectdb->query("SELECT id, name, filter_id FROM tools_sql WHERE id = '$sql_id' AND source = '$source'; ");

                if ($getFilters->num_rows == 0) {
                    // Significa que lo han añadido mal y lo han puesto seleccionando un filter, así que añadirlo automáticamente con el sql_id del filter_id
                    $getSQLidFilter = $projectdb->query("SELECT tools_sql_id FROM tools_filters WHERE id = '$sql_id'; ");

                    if ($getSQLidFilter->num_rows > 0) {
                        $dataSQLid = $getSQLidFilter->fetch_assoc();
                        $sql_id = $dataSQLid['tools_sql_id'];
                    }
                    $getFilters = $projectdb->query("SELECT id, name, filter_id FROM tools_sql WHERE id = '$sql_id' AND source = '$source'; ");
                }
                if ($getFilters->num_rows > 0) {
                    $dataF = $getFilters->fetch_assoc();
                    $filters = $dataF['filter_id'];
                    $name_sql = $dataF['name'];
                    if($name_sql == ""){$name_sql = "OR";}
                    if($filters != ""){
                        $filters_explode = explode(",", $filters);
                        $filters_explode[] = $filter_id;
                        $filters_explode = array_unique($filters_explode);
                        $projectdb->query("UPDATE tools_sql SET filter_id = '" . implode(",", $filters_explode) . "', name = '$name_sql' WHERE id = '$sql_id'; ");
                        //echo "2. UPDATE tools_sql SET filter_id = '" . implode(",", $filters_explode) . "', name = '$name_sql' WHERE id = '$sql_id'; ";
                    }
                    else{
                        $projectdb->query("UPDATE tools_sql SET filter_id = '$filter_id', name = '$name_sql' WHERE id = '$sql_id'; ");
                        //echo "1. UPDATE tools_sql SET filter_id = '$filter_id', name = '$name_sql' WHERE id = '$sql_id';  ";
                    }

                    $projectdb->query("UPDATE tools_filters SET tools_sql_id = '$sql_id' WHERE id = '$filter_id'; ");

                    if($id_old != ""){
                        //quitar filtro del nodo al que se le ha cogido
                        $getFiltersOld = $projectdb->query("SELECT id, name, filter_id FROM tools_sql WHERE id = '$id_old'; ");

                        if ($getFiltersOld->num_rows > 0) {
                            $dataFO = $getFiltersOld->fetch_assoc();
                            $filter_id_old = explode(",", $dataFO['filter_id']);
                            if (($key = array_search($filter_id, $filter_id_old)) !== false) {
                                unset($filter_id_old[$key]);
                                $projectdb->query("UPDATE tools_sql SET filter_id='" . implode(",", $filter_id_old) . "' WHERE id = '$id_old'");
                            }
                        }
                    }
                }
            }
            $projectdb->query("UPDATE tools_filters SET active = '0' WHERE id = '$filter_id'; ");


        }
        elseif($table_name == "tools_sql"){
            // table_name tools_sql, anidar and/or
            $projectdb->query("UPDATE tools_sql SET parent_id = '$sql_id' WHERE id = '$filter_id'; ");
        }

    }

    checkEmptysSQL($projectName, $source);

    $message['code']=false;
    return $message;
}


function checkEmptysSQL(STRING $projectName, $source){

    global $projectdb;
    $projectdb = selectDatabase($projectName);

    $getEmptySQL = $projectdb->query("SELECT id FROM tools_sql WHERE name = '' AND filter_id = '' AND source = '$source'; ");

    if ($getEmptySQL->num_rows > 0) {
        while($dataESQL = $getEmptySQL->fetch_assoc()){

            $id = $dataESQL['id'];
            $projectdb->query("DELETE FROM tools_sql WHERE id = '$id'; ");

        }
    }

}


function updateSQL(STRING $projectName, ARRAY $params){

    global $projectdb;
    $projectdb = selectDatabase($projectName);

    $sql_name = $params['sql_name'];
    $sql_id = $params['sql_id'];

    $projectdb->query("UPDATE tools_sql SET name = '$sql_name' WHERE id = '$sql_id'; ");

    $message['code']=false;
    return $message;
}


function executeSQL(STRING $projectName, ARRAY $params){

    global $projectdb;
    global $app;

    $projectdb = selectDatabase($projectName);

    $user = $app->container->sentinel->getUser();
    $user_id = $user->id;

    $source = $params['source'];

    $query = "DELETE FROM tools_results WHERE source = '$source';";
    $projectdb->query($query);

    $getFiltersID = $projectdb->query("SELECT id, parent_id, name, filter_id FROM tools_sql WHERE source = '$source' AND user_id = '$user_id';");

    // 1. Caso 1: sólo hay un filtro
    // 2. Caso 2: sólo hay una rama
    // 3. Caso 3: hay dos ramas
//    echo "Numero de resultados: ".$getFiltersID->num_rows."\n";

    if($getFiltersID->num_rows > 0){

        while($dataFID = $getFiltersID->fetch_assoc()){

            $tools_sql_id = $dataFID['id'];
            $filters_id = $dataFID['filter_id'];

            if($filters_id != ""){
                $query2 =
                    "SELECT tf.id, twc.column_or_table_name AS filter_column, top.operator, top.name AS operator_name, twc.filter_type, twc.recursive, 
                      tf.search, tf.tools_where_id, tf.tools_advanced_columns_id, tf.case_sensitive, tf.vsys, tf.source 
                    FROM tools_filters tf, tools_where_columns twc, tools_operator top
                    WHERE tf.id IN ($filters_id) 
                          AND tf.tools_where_columns_id = twc.id 
                          AND tf.tools_operator_id = top.id 
                          AND tf.source = '$source';";
                $getFilters = $projectdb->query($query2);

                if($getFilters->num_rows > 0){
                    while($dataF = $getFilters->fetch_assoc()) {
                        $filter_id = $dataF['id'];
                        $filter_column = $dataF['filter_column'];
                        $operator = $dataF['operator'];
                        $operator_name = $dataF['operator_name'];
                        $vsys = $dataF['vsys'];
                        $source = $dataF['source'];

                        $recursive = $dataF['recursive'];
                        $filter_type = $dataF['filter_type'];
                        $search = $dataF['search'];
                        $tools_where_id = $dataF['tools_where_id'];
                        $tools_advanced_columns_id = $dataF['tools_advanced_columns_id'];
                        $case_sensitive = $dataF['case_sensitive'];

                        // Why????? Commented this line to resolved MT-880
                        //$search = str_replace("*", "", $search);

                        if($tools_where_id == "1"){ //all
                            $getWhere = $projectdb->query("SELECT id, table_name, type, name, image FROM tools_where WHERE id NOT IN ($tools_where_id) ;");
                        }else{
                            $getWhere = $projectdb->query("SELECT id, table_name, type, name, image FROM tools_where WHERE id IN ($tools_where_id) ;");
                        }

                        if($getWhere->num_rows > 0) {
                            while($dataW = $getWhere->fetch_assoc()) {
                                $table_name = $dataW['table_name'];
                                $type = $dataW['type'];
                                $table_name_name = $dataW['name'];
                                $image = $dataW['image'];

                                if(($filter_column == "invalid") || ($filter_column == "duplicated_name") || ($filter_column == "duplicated_name_value")
                                    || ($filter_column == "duplicated_value") || ($filter_column == "groups_with_one_member") || ($filter_column == "used")
                                    || ($filter_column == "unused") || ($filter_column == "groups_without_members") || ($filter_column == "disabled") || ($filter_column == "enabled")
                                    || ($filter_column == "select_all") || ($filter_column == "name_is_ipaddress") || ($filter_column == "members")
                                    || ($filter_column == "tags_not_used") || ($filter_column == "description_not_populated") || ($filter_column == "source_destination_any")
                                    || ($filter_column == "service_any") || ($filter_column == "log_start_enabled") || ($filter_column == "log_forwarding_not_enabled")
                                    || ($filter_column == "expired_schedule") || ($filter_column == "dsri_enabled") || ($filter_column == "ml_enabled")
                                    || ($filter_column == "rules_warnings") || ($filter_column == "apps_timeout") || ($filter_column == "match_app_override")
                                    || ($filter_column == "service_timeout") || ($filter_column == "replaced_app_service_timeout")
                                    || ($filter_column == "pre_rulebase") || ($filter_column == "post_rulebase") || ($filter_column == "duplicated_name_vs_groups")
                                    || ($filter_column == "re_enabled") || ($filter_column == "invalid_used") || ($filter_column == "invalid_name")
                                    || ($filter_column == "ghost_objects") || ($filter_column == "not_ghost_objects") || ($filter_column == "bidirectional" ) || ($filter_column == "nat_static")
                                    || ($filter_column == "nat_nonat") || ($filter_column == "nat_dynamic_ip") || ($filter_column == "nat_dynamic_ip_port")
                                    || ($filter_column == "rules_with_users") || ($filter_column == "rules_members_null")
                                    || ($filter_column == "getRulesLayer4") || ($filter_column == "getRulesLayer7")
                                    ||  $filter_column == "getAddressNotInGroups" || $filter_column == "getRulesHits" || $filter_column == "getRulesNoHits"
                                    || $filter_column == "getRulesAffectIPs" || $filter_column == "getRulesWithIPv6"
                                ){
                                    switch ($filter_column){
                                        case 'invalid':
                                            $ids_results = getInvalid($table_name, $type, $vsys, $source, $projectName);
                                            break;

                                        case 'duplicated_name':
                                            $ids_results = getDuplicatedName($table_name, $type, $vsys, $source, $case_sensitive);
                                            break;

                                        case 'duplicated_name_value':
                                            $ids_results = getDuplicatedNameValue($table_name, $type, $vsys, $source, $case_sensitive);
                                            break;

                                        case 'duplicated_value':
                                            $ids_results = getDuplicatedValue($table_name, $type, $vsys, $source);
                                            break;

                                        case 'duplicated_name_vs_groups':
                                            $ids_results = getDeplicatedNameVsGroup($table_name, $type, $vsys, $source, $filter_id, $tools_sql_id, $user_id);
                                            break;

                                        case 'groups_with_one_member':
                                            $ids_results = getGroupsWithOneMember($table_name, $type, $vsys, $source);
                                            break;

                                        case 'used':
                                            $ids_results = getUsed($table_name, $type, $vsys, $source);
                                            break;

                                        case 'unused':
                                            $ids_results = getUnused($table_name, $type, $vsys, $source);
                                            break;

                                        case 'invalid_used':
                                            $ids_results = getInvalidUsed($table_name, $type, $vsys, $source, $projectName);
                                            break;

                                        case 'invalid_name':
                                            $ids_results = getInvalidName($table_name, $type, $vsys, $source, $projectName);
                                            break;

                                        case 'groups_without_members':
                                            $ids_results = getGroupsWithoutMembers($table_name, $type, $vsys, $source);
                                            break;

                                        case 'getAddressNotInGroups':
                                            $ids_results = getAddressNotInGroups($table_name, $type, $vsys, $source);
                                            break;

                                        case 'disabled':
                                            $ids_results = getDisabled($table_name, $type, $vsys, $source);
                                            break;

                                        case 'enabled':
                                            $ids_results = getEnabled($table_name, $type, $vsys, $source);
                                            break;

                                        case 'select_all':
                                            $ids_results = getSelectAll($table_name, $type, $vsys, $source);
                                            break;

                                        case 'name_is_ipaddress':
                                            $ids_results = getNameIsIPAddress($table_name, $type, $vsys, $source);
                                            break;

                                        case 'members':
                                            $ids_results = getMembers($table_name, $type, $operator, $search, $vsys , $source);
                                            break;

                                        case 'tags_not_used':
                                            $ids_results = getTagsNotUsed($table_name, $type, $vsys, $source);
                                            break;

                                        case 'description_not_populated':
                                            $ids_results = getDescriptionNotPopulated($table_name, $type, $vsys, $source);
                                            break;

                                        case 'source_destination_any':
                                            $ids_results = getSourceDestinationAny($table_name, $type, $vsys, $source);
                                            break;

                                        case 'service_any':
                                            $ids_results = getServiceAny($table_name, $type, $vsys, $source);
                                            break;

                                        case 'log_start_enabled':
                                            $ids_results = getLogStartEnabled($table_name, $type, $vsys, $source);
                                            break;

                                        case 'log_forwarding_not_enabled':
                                            $ids_results = getLogForwardingNotEnabled($table_name, $type, $vsys, $source);
                                            break;

                                        case 'expired_schedule':
                                            $ids_results = getExpiredSchedule($table_name, $type, $vsys, $source);
                                            break;

                                        case 'dsri_enabled':
                                            $ids_results = getDsriEnabled($table_name, $type, $vsys, $source);
                                            break;

                                        case 'ml_enabled':
                                            $ids_results = getMlEnabled($table_name, $type, $vsys, $source);
                                            break;

                                        case 're_enabled':
                                            $ids_results = getReEnabled($table_name, $type, $vsys, $source);
                                            break;

                                        case 'rules_warnings':
                                            $ids_results = getRulesWarning($table_name, $type, $vsys, $source);
                                            break;

                                        case 'apps_timeout':
                                            $ids_results = getAppsTimeout($table_name, $type, $vsys, $source);
                                            break;

                                        case 'match_app_override':
                                            $ids_results = getMatchAppOverride($table_name, $type, $vsys, $source);
                                            break;

                                        case 'service_timeout':
                                            $ids_results = getServiceTimeout($table_name, $type, $vsys, $source);
                                            break;

                                        case 'replaced_app_service_timeout':
                                            $ids_results = getReplacedAppServiceTimeout($table_name, $type, $vsys, $source);
                                            break;

                                        case 'pre_rulebase':
                                            $ids_results = getPreRulebase($table_name, $type, $vsys, $source);
                                            break;

                                        case 'post_rulebase':
                                            $ids_results = getPostRulebase($table_name, $type, $vsys, $source);
                                            break;

                                        case 'ghost_objects':
                                            $ids_results = getGhostObjects($table_name, $type, $vsys, $source);
                                            break;

                                        case 'not_ghost_objects':
                                            $ids_results = getGhostObjects($table_name, $type, $vsys, $source,'0');
                                            break;

                                        case 'bidirectional':
                                            $ids_results = getBidirectional($table_name, $type, $vsys, $source);
                                            break;

                                        case 'nat_static':
                                            $ids_results = getNatStatic($projectName, $source, $vsys);
                                            break;

                                        case 'nat_nonat':
                                            $ids_results = getNatNoNat($projectName, $source, $vsys);
                                            break;

                                        case 'nat_dynamic_ip':
                                            $ids_results = getNatDynamicIp($projectName, $source, $vsys);
                                            break;

                                        case 'nat_dynamic_ip_port':
                                            $ids_results = getNatDynamicIpPort($projectName, $source, $vsys);
                                            break;

                                        case 'rules_with_users':
                                            $ids_results = getRulesWithUsers($table_name, $vsys, $source);
                                            break;

                                        case 'rules_members_null':
                                            $ids_results = getRulesMembersNull($table_name, $vsys, $source);
//                                            echo "IDs results: " .print_r($ids_results). "\n";
                                            break;

                                        case 'getRulesLayer4':
                                            $ids_results = getRulesLayer4($table_name, $vsys, $source);
//                                            echo "IDs results: " .print_r($ids_results). "\n";
                                            break;

                                        case 'getRulesLayer7':
                                            $ids_results = getRulesLayer7($table_name, $vsys, $source);
//                                            echo "IDs results: " .print_r($ids_results). "\n";
                                            break;
                                        case 'getRulesHits':
                                            $ids_results = getRulesHits($table_name, $operator_name, $vsys, $source);
                                            break;
                                        case 'getRulesNoHits':
                                            $ids_results = getRulesNoHits($table_name, $operator_name, $vsys, $source);
                                            break;

                                        case 'getRulesAffectIPs':
                                            //$vr = 1;
                                            //$templateID = 1;
                                            $ipsArray = explode(",", $search);
                                            $ids_results = getMatchingSecRules($source, $vsys, $vr, $templateID, $ipsArray, $operator_name);
                                            break;

                                        case 'getRulesWithIPv6':
                                            $ids_results = getSecRulesWithIPv6($source, $vsys, $vr, $templateID, $operator_name);
                                            break;
                                        default:
                                            break;
                                    }
                                }
                                else{
                                    if($filter_type == 1) {
                                        $ids_results = getMatchesFilterToolsSingleTable($table_name, $type, $filter_column, $operator, $operator_name, $search, $case_sensitive, $vsys, $source);
                                    }
                                    elseif($filter_type == 2){
                                        $ids_results = getMatchesFilterToolsMultiTable($table_name, $type, $filter_column, $operator, $operator_name, $recursive, $search, $case_sensitive, $vsys, $source);
                                    }
                                }
                                if(count($ids_results) != 0){
                                    $ids_results_query = [];
                                    foreach ($ids_results as $member_lid) {
                                        //$query = "INSERT INTO tools_results (filter_id, tools_sql_id, member_lid, table_name, type, table_name_name, image, source, user_id)
                                        //  VALUES ('$filter_id', '$tools_sql_id', '$member_lid', '$table_name', '$type', '$table_name_name', '$image', '$source', '$user_id'); ";
                                        $ids_results_query[] = "('$filter_id', '$tools_sql_id', '$member_lid', '$table_name', '$type', '$table_name_name', '$image', '$source', '$user_id')";
                                    }
                                    $query = "INSERT INTO tools_results (filter_id, tools_sql_id, member_lid, table_name, type, table_name_name, image, source, user_id) VALUES " .implode(",",$ids_results_query).";";
                                    $projectdb->query($query);

                                }
                                elseif(count($ids_results) == 0){
                                    $query = "INSERT INTO tools_results (filter_id, tools_sql_id, member_lid, table_name, type, table_name_name, image, source, user_id) 
                                      VALUES ('$filter_id', '$tools_sql_id', '', '$table_name', '$type', '$table_name_name', '$image', '$source', '$user_id'); ";
                                    $projectdb->query($query);
                                    //echo $query;
                                }
                            }
                        }
                    }
                }
                //checkConnectors($projectName, $source, $user_id);
            }
        }
        // Intersect AND/OR Merge of filter results
        checkConnectors($projectName, $source, $user_id);

    }

    $message['code']=false;
    return $message;

}

function checkConnectors(STRING $projectName, $source, $user_id){

    global $projectdb;
    $projectdb = selectDatabase($projectName);

    //Calculate the merge of filters
    //IF AND : array_intersect();
    //IF OR : array_merge()

    $filtered_Results = array();
    $involved_types = array();

    $getRootOperators = $projectdb->query("SELECT id, parent_id, name, filter_id FROM tools_sql WHERE parent_id = '0' AND source = '$source' AND user_id = '$user_id' ORDER BY id;");

    if($getRootOperators->num_rows > 0){
        while($data = $getRootOperators->fetch_assoc()) {

            $filterID = $data['id'];
            $connectorType = $data['name'];
            $filter_id = $data['filter_id'];

            if ($filter_id != "") {  //The first branch has already leaves
                $leaves = getLeavesResults($projectdb, $filter_id, $involved_types);
            }
            else{
                $leaves = array();
            }

            $branches = getSubBranchesResults($projectdb, $filterID, $involved_types);

            $results = array_merge($leaves, $branches);

            switch($connectorType){
                case 'AND':
                case 'and':
                case '*':
                    $filtered_Results = array_shift($results);
                    foreach ($results as $result){
                        $filtered_Results = array_intersect($filtered_Results, $result);
                    }
                    break;

                case 'OR':
                case 'or':
                case '+':
                default:
                    $filtered_Results = array_shift($results);
                    foreach ($results as $result){
                        $filtered_Results = array_merge($filtered_Results, $result);
                    }
                    break;
            }
        }
    }

//    $query ="DELETE FROM tools_results WHERE source='$source' AND user_id='$user_id' AND type='result'";
    $query ="DELETE FROM tools_results WHERE source='$source' AND user_id='$user_id'";
    $projectdb->query($query);

    $entries = array();
    if(isset($filtered_Results)) {
        foreach ($filtered_Results as $filtered_Result) {
            $entry = json_decode($filtered_Result);
            $entries[] = "('$entry->member_lid', '$entry->table_name', 'result', '$entry->table_name_name', '$entry->image', '$entry->source', '$entry->user_id')";
        }
    }

    if(count($entries)>0) {
        $query = "INSERT INTO tools_results (member_lid, table_name, type, table_name_name, image, source, user_id)
                        VALUES " . implode(",", $entries) . "; ";
        $projectdb->query($query);
    }
    else{
        foreach($involved_types as $involved_type){
            $query = "INSERT INTO tools_results (table_name, type,  source, user_id) VALUES ('$involved_type','result','$source','$user_id')";
            $projectdb->query($query);
        }
    }


//    if (count($filtered_Results) > 0) {
//        // Actualizar la table tools_results con el resultado del AND
//        $query = "DELETE FROM tools_results WHERE filter_id IN (" . implode(',', $filter_id_array) . ") AND table_name = '$table_name' AND member_lid NOT IN (" . implode(',', $filtered_Results) . ") AND source = '$source' AND user_id = '$user_id' ;";
//        $projectdb->query($query);
//
//    }
//    if (count($filtered_Results) == 0) {
//        $query = "DELETE FROM tools_results WHERE filter_id IN (" . implode(',', $filter_id_array) . ") AND table_name = '$table_name' AND source = '$source' AND user_id = '$user_id';";
//        $projectdb->query($query);
//        foreach ($filter_id_array as $filter_id) {
//            $query = "INSERT INTO tools_results (filter_id, tools_sql_id, member_lid, table_name, type, table_name_name, image, source, user_id)
//                                          VALUES ('$filter_id', '$filterID', '', '$table_name', '', '$table_name_name', '$image', '$source', '$user_id'); ";
//            $projectdb->query($query);
//        }
//    }
}

function getLeavesResults(mysqli $projectdb, string $filter_id, &$involved_types):array{
    $result = array();
    $filters = explode(',', $filter_id);
    foreach ($filters as $filter){
        $query = "SELECT * FROM tools_results WHERE filter_id = $filter ;";
        $getFilteredChildren = $projectdb->query($query);

        if($getFilteredChildren->num_rows > 0){
            $localResult = array();
            while($data = $getFilteredChildren->fetch_object()){
                $involved_types[$data->table_name]=$data->table_name;
                unset($data->id);
                unset($data->filter_id);
                unset($data->tools_sql_id);
                $localResult[$data->table_name.".".$data->member_lid] = json_encode($data);
            }
            $result[]=$localResult;
        }
    }

    return $result;
}

function getSubBranchesResults(mysqli$projectdb, int $parentFilter, &$involved_types): array{
    $filtered_Results = array();
    $getOperators = $projectdb->query("SELECT id, parent_id, name, filter_id FROM tools_sql WHERE parent_id = $parentFilter;");
    if($getOperators->num_rows > 0){
        while($data = $getOperators->fetch_assoc()) {
            $filterID = $data['id'];
            $connectorType = $data['name'];
            $filter_id = $data['filter_id'];

            if ($filter_id != "") {  //The first branch has already leaves
                $leaves = getLeavesResults($projectdb, $filter_id, $involved_types);
            }
            else{
                $leaves = array();
            }

            $branches = getSubBranchesResults($projectdb, $filterID, $involved_types);

            $results = array_merge($leaves, $branches);

            switch($connectorType){
                case 'AND':
                case 'and':
                case '*':
                    $branch_filtered_Results = array_shift($results);
                    foreach ($results as $result){
                        $branch_filtered_Results = array_intersect($branch_filtered_Results, $result);
                    }
                    break;

                case 'OR':
                case 'or':
                case '+':
                default:
                    $branch_filtered_Results = array_shift($results);
                    foreach ($results as $result){
                        $branch_filtered_Results = array_merge($branch_filtered_Results, $result);
                    }
                    break;
            }

            $filtered_Results[] = $branch_filtered_Results;
        }
    }

    return $filtered_Results;
}

function checkConnectorsOld(STRING $projectName, $source, $user_id){

    global $projectdb;
    $projectdb = selectDatabase($projectName);

    //Calculate the merge of filters
    //IF AND : array_intersect();
    //IF OR : array_merge()

    $array_member_finally = array();

    //$getFiltersID_SimpleCase = $projectdb->query("SELECT id, parent_id, name, filter_id FROM tools_sql WHERE parent_id = '0' AND filter_id != '';");
    $getFiltersID_SimpleCase = $projectdb->query("SELECT id, parent_id, name, filter_id FROM tools_sql WHERE filter_id != '' AND source = '$source' AND user_id = '$user_id' ORDER BY id DESC;");
    //echo "1. SELECT id, parent_id, name, filter_id FROM tools_sql WHERE filter_id != '' AND source = '$source' AND user_id = '$user_id' ORDER BY id DESC;\n";

    if($getFiltersID_SimpleCase->num_rows > 0){

        while($dataFID_SC = $getFiltersID_SimpleCase->fetch_assoc()) {

            $tools_sql_id = $dataFID_SC['id'];
            $name_connector = $dataFID_SC['name'];
            $filter_id_array = array();

            if($name_connector == "AND"){

                $getResultsF_SimpleCase = $projectdb->query("SELECT filter_id, table_name, table_name_name, image, source FROM tools_results WHERE tools_sql_id = '$tools_sql_id' GROUP BY table_name;");
                //echo "2. SELECT filter_id, table_name, table_name_name, image, source FROM tools_results WHERE tools_sql_id = '$tools_sql_id' GROUP BY table_name;\n";

                if ($getResultsF_SimpleCase->num_rows > 0) {

                    while ($dataRF_SC = $getResultsF_SimpleCase->fetch_assoc()) {

                        $table_name = $dataRF_SC['table_name'];

                        $getResultsF_SimpleCase2 = $projectdb->query("SELECT filter_id, table_name, table_name_name, image, source FROM tools_results WHERE tools_sql_id = '$tools_sql_id' AND table_name = '$table_name' GROUP BY filter_id;");
                        //echo "3. SELECT filter_id, table_name, table_name_name, image, source FROM tools_results WHERE tools_sql_id = '$tools_sql_id' AND table_name = '$table_name' GROUP BY filter_id;\n";

                        $first = 0;
                        $array_member_finally = array();
                        $filter_id_array = array();

                        while ($dataRF_SC2 = $getResultsF_SimpleCase2->fetch_assoc()) {

                            $filter_id = $dataRF_SC2['filter_id'];
                            $filter_id_array[] = $dataRF_SC2['filter_id'];
                            $table_name = $dataRF_SC2['table_name'];
                            $table_name_name = $dataRF_SC2['table_name_name'];
                            $image = $dataRF_SC2['image'];
                            $source = $dataRF_SC2['source'];
                            $array_member_lid = array();

                            $getResultsFMT_SimpleCase = $projectdb->query("SELECT member_lid, table_name FROM tools_results WHERE filter_id = '$filter_id' AND table_name = '$table_name' AND source = '$source';");
                            //echo "2. SELECT member_lid, table_name FROM tools_results WHERE filter_id = '$filter_id' AND table_name = '$table_name' AND source = '$source';\n";

                            if ($getResultsFMT_SimpleCase->num_rows > 0) {

                                while ($dataRFMT_SC = $getResultsFMT_SimpleCase->fetch_assoc()) {
                                    $array_member_lid[] = $dataRFMT_SC['member_lid'];

                                }
                                if($first == 0){
                                    $array_member_finally = $array_member_lid;
                                    $first = 1;
                                }
                                //echo "Array:\n";
                                //print_r($array_member_lid);
                                $array_member_finally = array_intersect($array_member_finally, $array_member_lid);

                                //echo "Array intersect:\n";
                                //print_r($array_member_finally);
                            }
                        }

                        //echo "ARRAY INTERSECT:\n";
                        //print_r($array_member_finally);

                        if (count($array_member_finally) > 0){
                            // Actualizar la table tools_results con el resultado del AND
                            $query = "DELETE FROM tools_results WHERE filter_id IN (".implode(',', $filter_id_array).") AND table_name = '$table_name' AND member_lid NOT IN (".implode(',', $array_member_finally).") AND source = '$source' AND user_id = '$user_id' ;";
                            //echo "DELETE CON MATCH: " .$query."\n";
                            $projectdb->query($query);

                        }
                        if(count($array_member_finally) == 0){
                            $query = "DELETE FROM tools_results WHERE filter_id IN (".implode(',', $filter_id_array).") AND table_name = '$table_name' AND source = '$source' AND user_id = '$user_id';";
                            //echo "DELETE: " .$query. "\n";
                            $projectdb->query($query);
                            foreach ($filter_id_array as $filter_id){
                                $query = "INSERT INTO tools_results (filter_id, tools_sql_id, member_lid, table_name, type, table_name_name, image, source, user_id) 
                                      VALUES ('$filter_id', '$tools_sql_id', '', '$table_name', '', '$table_name_name', '$image', '$source', '$user_id'); ";
                                //echo "-->INSERT: : " .$query. "\n";
                                $projectdb->query($query);
                            }
                        }
                    }
                }
            }
        }
    }

    // Check if is case: A AND (B OR C)
    $getFiltersABC = $projectdb->query("SELECT id, name FROM tools_sql WHERE parent_id = '0' AND name = 'AND' AND filter_id = '' AND source = '$source' AND user_id = '$user_id';");
    if($getFiltersABC->num_rows > 0) {

        while ($dataFABC = $getFiltersABC->fetch_assoc()) {

            $id_connector_ABC = $dataFABC['id'];

            $getResultsF_SimpleCase = $projectdb->query("SELECT filter_id, table_name, table_name_name, image, source FROM tools_results WHERE tools_sql_id IN ($id_connector_ABC + 1, $id_connector_ABC - 1) GROUP BY table_name;");
            //echo "1. SELECT filter_id, table_name, table_name_name, image, source FROM tools_results WHERE tools_sql_id IN ($id_connector_ABC + 1, $id_connector_ABC - 1) GROUP BY table_name;";

            if ($getResultsF_SimpleCase->num_rows > 0) {

                while ($dataRF_SC = $getResultsF_SimpleCase->fetch_assoc()) {

                    $table_name = $dataRF_SC['table_name'];

                    $getResultsF_SimpleCase2 = $projectdb->query("SELECT filter_id, table_name, table_name_name, image, source, tools_sql_id FROM tools_results WHERE tools_sql_id IN ($id_connector_ABC + 1, $id_connector_ABC - 1)  AND table_name = '$table_name' GROUP BY tools_sql_id;");

                    $first = 0;
                    $array_member_finally = array();
                    $filter_id_array = array();

                    while ($dataRF_SC2 = $getResultsF_SimpleCase2->fetch_assoc()) {

                        $filter_id = $dataRF_SC2['filter_id'];
                        $filter_id_array[] = $dataRF_SC2['filter_id'];
                        $table_name = $dataRF_SC2['table_name'];
                        $table_name_name = $dataRF_SC2['table_name_name'];
                        $tools_sql_id = $dataRF_SC2['tools_sql_id'];
                        $tools_sql_id_array[] = $dataRF_SC2['tools_sql_id'];
                        $image = $dataRF_SC2['image'];
                        $source = $dataRF_SC2['source'];
                        $array_member_lid = array();

                        $getResultsFMT_SimpleCase = $projectdb->query("SELECT member_lid, table_name FROM tools_results WHERE tools_sql_id = '$tools_sql_id' AND source = '$source';");

                        if ($getResultsFMT_SimpleCase->num_rows > 0) {

                            while ($dataRFMT_SC = $getResultsFMT_SimpleCase->fetch_assoc()) {
                                $array_member_lid[] = $dataRFMT_SC['member_lid'];

                            }
                            if($first == 0){
                                $array_member_finally = $array_member_lid;
                                $first = 1;
                            }
                            $array_member_finally = array_intersect($array_member_finally, $array_member_lid);
                        }
                    }

                    //echo "ARRAY INTERSECT:\n";
                    //print_r($array_member_finally);

                    if (count($array_member_finally) > 0){
                        // Actualizar la table tools_results con el resultado del AND
                        $query = "DELETE FROM tools_results WHERE tools_sql_id IN (".implode(',', $tools_sql_id_array).") AND table_name = '$table_name' AND member_lid NOT IN (".implode(',', $array_member_finally).") AND source = '$source' AND user_id = '$user_id' ;";
                        $projectdb->query($query);

                    }

                }
            }

        }



    }


    // Check global SQL with childrens
    $getFiltersGlobal = $projectdb->query("SELECT id, name FROM tools_sql WHERE parent_id = '0' AND name = 'AND' AND source = '$source' AND user_id = '$user_id';");
    //echo "1. SELECT id, name FROM tools_sql WHERE parent_id = '0' AND name = 'AND' AND source = '$source' AND user_id = '$user_id';\n";

    if($getFiltersGlobal->num_rows > 0) {

        while ($dataG = $getFiltersGlobal->fetch_assoc()) {

            $id_global = $dataG['id'];
            $filter_id_array = array();

            $getChildrensByGlobal = $projectdb->query("SELECT id, filter_id FROM tools_sql WHERE parent_id = '$id_global';");
            //echo "2. SELECT id, filter_id FROM tools_sql WHERE parent_id = '$id_global';\n";

            if ($getChildrensByGlobal->num_rows > 0) {

                $first = 0;
                $array_member_finally = array();

                while ($dataCG = $getChildrensByGlobal->fetch_assoc()) {

                    $filters_ids = $dataCG['filter_id'];
                    //echo "Los filters_ids: " .$filters_ids. "\n";
                    $filter_id_array[] = $dataCG['filter_id'];
                    $array_member_lid = array();

                    $getResultsFMT_SimpleCase = $projectdb->query("SELECT member_lid, table_name, table_name_name, image FROM tools_results WHERE filter_id IN ($filters_ids);");
                    //echo "3. SELECT member_lid, table_name, table_name_name, image FROM tools_results WHERE filter_id IN ($filters_ids);\n";

                    if ($getResultsFMT_SimpleCase->num_rows > 0) {

                        while ($dataRFMT_SC = $getResultsFMT_SimpleCase->fetch_assoc()) {

                            $array_member_lid[] = $dataRFMT_SC['member_lid'];
                            $table_name = $dataRFMT_SC['table_name'];
                            $table_name_name = $dataRFMT_SC['table_name_name'];
                            $image = $dataRFMT_SC['image'];

                        }

                        if ($first == 0) {
                            $array_member_finally = $array_member_lid;
                            $first = 1;
                        }
                        //echo "Array member lid:\n";
                        //print_r($array_member_lid);

                        $array_member_finally = array_intersect($array_member_finally, $array_member_lid);

                        //echo "array intersect:\n";
                        //print_r($array_member_finally);
                    }
                }

                //echo "ARRAY INTERSECT:\n";
                //print_r($array_member_finally);

                if (count($array_member_finally) > 0) {
                    // Actualizar la table tools_results con el resultado del AND
                    $query = "DELETE FROM tools_results WHERE filter_id IN (" . implode(',', $filter_id_array) . ") AND table_name = '$table_name' AND member_lid NOT IN (" . implode(',', $array_member_finally) . ") AND source = '$source' AND user_id = '$user_id' ;";
                    //echo "DELETE match: " .$query."\n";
                    $projectdb->query($query);

                }
                if (count($array_member_finally) == 0) {
                    $query = "DELETE FROM tools_results WHERE filter_id IN (" . implode(',', $filter_id_array) . ") AND table_name = '$table_name' AND source = '$source' AND user_id = '$user_id';";
                    //echo "DELETE sin match: " .$query. "\n";
                    $projectdb->query($query);
                    foreach ($filter_id_array as $filter_id) {
                        $query = "INSERT INTO tools_results (filter_id, tools_sql_id, member_lid, table_name, type, table_name_name, image, source, user_id) 
                                          VALUES ('$filter_id', '$tools_sql_id', '', '$table_name', '', '$table_name_name', '$image', '$source', '$user_id'); ";
                        //echo "-->INSERT: : " .$query. "\n";
                        $projectdb->query($query);
                    }
                }
            }
        }
    }

}


function getInvalid($table_name, $type, $vsys, $source, $projectName){

    global $projectdb;
    $ids_results_in = array();

    require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";

    $vsys_query = prepareVsysQuery($projectdb, $vsys, $source);
    $vsys_query_b = prepareVsysQueryB($projectdb, $vsys, $source);

    if($table_name == "address"){
        //$conditions = " WHERE ((type='ip-netmask' AND (cidr='' OR cidr='0')) OR (ipaddress='') OR (ipaddress='0') OR (ipaddress='0.0.0.0') OR invalid='1') AND dummy=0 ";
        $conditions = " 
        WHERE ( (invalid=1) OR (type = '') OR ".
            "(ipaddress='') OR ".
            "(type = 'ip-netmask' AND cidr = '0') OR ".
            "(type = 'ip-netmask' AND ipaddress = '0') OR ".
            "(type = 'ip-netmask' AND ipaddress = '') OR ".
            "(LENGTH(name) > 63) OR (ipaddress REGEXP '^[0-9]' AND type NOT IN ('ip-netmask', 'ip-range', 'fqdn', 'ip-wildcard')) OR ".
            "(type IN ('ip-netmask') AND (!IS_IPv4(ipaddress) AND !IS_IPV6(ipaddress))) OR ".
            "(type IN ('ip-range') AND 
		        NOT (
		            IS_IPv4(SUBSTRING_INDEX(ipaddress,'-',1)) AND IS_IPv4(SUBSTRING_INDEX(ipaddress,'-',-1)) 
		            OR
		            IS_IPv6(SUBSTRING_INDEX(ipaddress,'-',1)) AND IS_IPv6(SUBSTRING_INDEX(ipaddress,'-',-1))
		        )
              ) OR ".
            "(name NOT REGEXP '^[a-zA-Z0-9][a-zA-Z0-9-_. ]*$') 
        ) 
        AND dummy = 0";

        $query = "SELECT id FROM $table_name $conditions $vsys_query AND source = '$source';";
        //echo "$query";
    }
    elseif($table_name == "applications"){
        $conditions = " WHERE name in ('','insufficient-data','incomplete') ";
        $query = "SELECT id FROM $table_name $conditions $vsys_query AND source = '$source'";
//        echo $query;
    }
    elseif($table_name == "services"){
        $conditions = " WHERE (
                                (
                                    (protocol != 'tcp' AND protocol != 'udp') 
                                    OR dport = '' 
                                    OR dport = '0' 
                                    OR (dport >= 65535) 
                                    OR (LENGTH(name) > 63) 
                                    OR invalid = 1
                                 ) 
                                 AND name NOT IN ('application-default', 'service-http', 'service-https') 
                               ) AND dummy = 0 ";
        $query = "SELECT id FROM $table_name $conditions $vsys_query AND source = '$source';";
    }
    elseif(($table_name == "address_groups_id") || ($table_name == "services_groups_id") || ($table_name == "applications_groups_id")){

        if($table_name == "address_groups_id"){
            $table_name_without_id = "address_groups"; $type_sql = " AND type = 'static' ";
            $subtables = ['"address"','"address_groups_id"','"default_regions"','"regions"','"external_list"'];

        }
        elseif($table_name == "services_groups_id") {
            $table_name_without_id = "services_groups"; $type_sql = "";
            $subtables = ['"services"','"services_groups_id"'];
        }
        elseif($table_name == "applications_groups_id"){
            $table_name_without_id = "applications_groups"; $type_sql = "";
            $subtables = ['"applications"','"applications_groups_id"','"default_applications"','"applications_filters"'];
        }

        $maxMembersPerGroup = getLimitationsPanos($projectName, 'maxMembersPerGroup');
        $query = "SELECT ag.lid FROM $table_name_without_id ag, $table_name b WHERE b.id = ag.lid AND b.source = '$source' $vsys_query_b  GROUP BY ag.lid HAVING count(*) > $maxMembersPerGroup;";

//        $query2 = "SELECT id FROM $table_name WHERE source = '$source' $vsys_query $type_sql AND id NOT IN (SELECT lid FROM $table_name_without_id) OR (LENGTH(name) > 63);";
        $query2 = "SELECT distinct id FROM
                      (
                          SELECT id FROM $table_name WHERE source = '$source' $vsys_query $type_sql AND id NOT IN (SELECT lid FROM $table_name_without_id) OR (LENGTH(name) > 63)
                          UNION
                          SELECT id FROM $table_name WHERE id IN (
                                  SELECT lid 
                                  FROM $table_name_without_id 
                                  WHERE table_name NOT IN (".implode(",",$subtables).")) AND 
                                    source = '$source' $vsys_query $type_sql
                          UNION 
                          SELECT id FROM $table_name WHERE invalid = '1'          
                      ) t;";
    }
    elseif($table_name == "security_rules"){
        $conditions = " WHERE name = '' ";
        $query = "SELECT id FROM $table_name $conditions $vsys_query AND source = '$source'
                  UNION SELECT secrapp.rule_lid as id FROM applications app, security_rules_app secrapp 
                    WHERE app.name in ('insufficient-data', 'incomplete') AND
                          secrapp.member_lid = app.id AND secrapp.table_name='applications' $vsys_query AND secrapp.source = '$source';";
//        echo $query;
    }
    elseif($table_name == "nat_rules"){
        $conditions = " WHERE op_zone_to='' OR op_zone_to = 'none' OR name = '' ";
        $query = "SELECT id FROM $table_name $conditions $vsys_query AND source = '$source';";
    }
    elseif($table_name == "zones"){
        $conditions = " WHERE invalid = '1' ";
        $query = "SELECT id FROM $table_name $conditions $vsys_query AND source = '$source';";
    }
    elseif($table_name == "ipsec_tunnel"){
        // TODO
        $query = "SELECT id FROM ike_gateways_profiles WHERE ike_crypto_profile_ikev1 = '' AND version = 'ikev1' $vsys_query AND source = '$source'
          UNION SELECT id FROM ike_gateways_profiles WHERE ike_crypto_profile_ikev2 = '' AND version = 'ikev2' $vsys_query AND source = '$source'
          UNION SELECT id FROM ike_gateways_profiles WHERE ike_crypto_profile_ikev2 = '' AND ike_crypto_profile_ikev1 = '' AND version = 'ikev2-preferred' $vsys_query AND source = '$source';";

    }

    $getIdResults = $projectdb->query($query);
    //echo "Invalid: " .$query."\n";

    if ($getIdResults->num_rows != 0) {
        while ($data = $getIdResults->fetch_assoc()) {
            if(($table_name == "address_groups_id") || ($table_name == "services_groups_id") || ($table_name == "applications_groups_id")){
                $ids_results_in[] = $data['lid'];
            }else{
                $ids_results_in[] = $data['id'];
            }
        }
    }

    if(($table_name == "address_groups_id") || ($table_name == "services_groups_id") || ($table_name == "applications_groups_id")){
        $getIdResults2 = $projectdb->query($query2);
        if ($getIdResults2->num_rows != 0) {
            while ($data2 = $getIdResults2->fetch_assoc()) {
                $ids_results_in[] = $data2['id'];
            }
        }
    }

    return $ids_results_in;

}


function getInvalidUsed($table_name, $type, $vsys, $source, $projectName){

    global $projectdb;
    $ids_results_in = array();

    require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";

    $vsys_query = prepareVsysQuery($projectdb, $vsys, $source);
    $vsys_query_b = prepareVsysQueryB($projectdb, $vsys, $source);

    if($table_name == "address"){
        //$conditions = " WHERE ((type='ip-netmask' AND (cidr='' OR cidr='0')) OR (ipaddress='') OR (ipaddress='0') OR (ipaddress='0.0.0.0') OR invalid='1') AND dummy=0 ";

        $conditions = " WHERE ( (invalid=1) OR (type = '') OR (ipaddress='') OR (type = 'ip-netmask' AND cidr = '0') OR (type = 'ip-netmask' AND ipaddress = '0') 
        OR (type = 'ip-netmask' AND ipaddress = '')  OR (LENGTH(name) > 63) OR (ipaddress REGEXP '^[0-9]' AND type NOT IN ('ip-netmask', 'ip-range', 'fqdn', 'ip-wildcard')) 
        OR (ipaddress REGEXP '^[a-zA-Z]' AND type IN ('ip-netmask', 'ip-range')) OR (name REGEXP '^[a-zA-Z0-9-_. ]+/') ) AND dummy = 0";

        $query = "SELECT id FROM $table_name $conditions $vsys_query AND source = '$source' AND used = '1';";
    }
    elseif($table_name == "services"){

        $conditions = " WHERE (((protocol != 'tcp' AND protocol != 'udp') OR dport = '' OR dport = '0' OR (dport >= 65535) OR (LENGTH(name) > 63) ) AND name NOT IN ('application-default', 'service-http', 'service-https') ) AND dummy = 0 ";

        $query = "SELECT id FROM $table_name $conditions $vsys_query AND source = '$source' AND used = '1';";
    }
    elseif(($table_name == "address_groups_id") || ($table_name == "services_groups_id") || ($table_name == "applications_groups_id")){

        //if($table_name == "address_groups_id"){ $table_name_without_id = "address_groups"; $type_sql = " AND type = 'static' ";
        //}elseif($table_name == "services_groups_id") { $table_name_without_id = "services_groups"; $type_sql = "";
        //}elseif($table_name == "applications_groups_id"){ $table_name_without_id = "applications_groups"; $type_sql = "";}

        //$maxMembersPerGroup = getLimitationsPanos($projectName, 'maxMembersPerGroup');
        //$query = "SELECT lid FROM $table_name_without_id a WHERE source = '$source' $vsys_query  GROUP BY lid HAVING count(*) > $maxMembersPerGroup;";

        //$query2 = "SELECT id FROM $table_name WHERE source = '$source' AND used = '1' $vsys_query $type_sql AND id NOT IN (SELECT lid FROM $table_name_without_id) OR (LENGTH(name) > 63);";

        if($table_name == "address_groups_id"){
            $table_name_without_id = "address_groups"; $type_sql = " AND type = 'static' ";
            $subtables = ['"address"','"address_groups_id"','"default_regions"','"regions"','"external_list"'];

        }
        elseif($table_name == "services_groups_id") {
            $table_name_without_id = "services_groups"; $type_sql = "";
            $subtables = ['"services"','"services_groups_id"'];
        }
        elseif($table_name == "applications_groups_id"){
            $table_name_without_id = "applications_groups"; $type_sql = "";
            $subtables = ['"applications"','"applications_groups_id"','"default_applications"','"applications_filters"'];
        }

        $maxMembersPerGroup = getLimitationsPanos($projectName, 'maxMembersPerGroup');
        //$query = "SELECT lid FROM $table_name_without_id a WHERE source = '$source' $vsys_query  GROUP BY lid HAVING count(*) > $maxMembersPerGroup;";
        $query = "SELECT ag.lid FROM $table_name_without_id ag, $table_name b WHERE b.id = ag.lid AND b.source = '$source' AND b.used = '1' $vsys_query_b  GROUP BY ag.lid HAVING count(*) > $maxMembersPerGroup;";

        $query2 = "SELECT distinct id FROM
                      (
                          SELECT id FROM $table_name WHERE source = '$source' $vsys_query $type_sql AND id NOT IN (SELECT lid FROM $table_name_without_id) OR (LENGTH(name) > 63)
                          UNION
                          SELECT id FROM $table_name WHERE id IN (
                                  SELECT lid 
                                  FROM $table_name_without_id 
                                  WHERE table_name NOT IN (".implode(",",$subtables).")) AND 
                                    source = '$source' $vsys_query $type_sql AND used = '1'
                      ) t;";

    }

    $getIdResults = $projectdb->query($query);
    //echo "Invalid: " .$query."\n";
    //echo "Invalid groups: " .$query2."\n";

    if ($getIdResults->num_rows != 0) {
        while ($data = $getIdResults->fetch_assoc()) {
            if(($table_name == "address_groups_id") || ($table_name == "services_groups_id") || ($table_name == "applications_groups_id")){
                $ids_results_in[] = $data['lid'];
            }else{
                $ids_results_in[] = $data['id'];
            }
        }
    }

    if(($table_name == "address_groups_id") || ($table_name == "services_groups_id") || ($table_name == "applications_groups_id")){
        $getIdResults2 = $projectdb->query($query2);
        if ($getIdResults2->num_rows != 0) {
            while ($data2 = $getIdResults2->fetch_assoc()) {
                $ids_results_in[] = $data2['id'];
            }
        }
    }

    return $ids_results_in;

}


function getInvalidName($table_name, $type, $vsys, $source, $projectName){

    global $projectdb;
    $ids_results_in = array();

    require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
    $vsys_query = prepareVsysQuery($projectdb, $vsys, $source);

    $version = calcVersion($source);

    if($table_name == "address"){
        $conditions =
            " WHERE ( (LENGTH(name) > 63) OR (name NOT REGEXP '^[a-zA-Z0-9][a-zA-Z0-9-_. ]*$') ) ";
        $query = "SELECT id, name FROM $table_name $conditions $vsys_query AND source = '$source' ;";
    }
    elseif($table_name == "services" || $table_name == "applications"){
        $conditions = " WHERE LENGTH(name) > 63 ";
        $query = "SELECT id, name FROM $table_name $conditions $vsys_query AND source = '$source' ;";
    }
    elseif(($table_name == "address_groups_id") || ($table_name == "services_groups_id") || ($table_name == "applications_groups_id")){
        $conditions = " WHERE LENGTH(name) > 63 ";
        $query = "SELECT id, name FROM $table_name $conditions $vsys_query AND source = '$source' ;";
    }
    elseif(($table_name == "security_rules")  || ($table_name == "nat_rules")){
        if ($version == ""){$version = 8.1;}
        if($version >= 8.1) $max = 63;
        else                $max = 31;
        $conditions = " WHERE LENGTH(name) > $max ";
        $query = "SELECT id, name FROM $table_name $conditions $vsys_query AND source = '$source' ;";
    }

    //if ((preg_match("/[\/]+/",$member_name)) || (preg_match("/[^a-zA-Z0-9-_. ]+/",$member_name)) || (preg_match("/[\s]+/",$member_name))){
    //}

    $getIdResults = $projectdb->query($query);
    //echo "Invalid Name: " .$query."\n";

    if ($getIdResults->num_rows != 0) {
        while ($data = $getIdResults->fetch_assoc()) {
            $ids_results_in[] = $data['id'];
        }
    }

    return $ids_results_in;

}


function getDuplicatedName($table_name, $type, $vsys, $source, $case_sensitive){

    global $projectdb;
    $ids_results_in = array();

    require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
    $vsys_query = prepareVsysQuery($projectdb, $vsys, $source);

    if($case_sensitive == 1){
        $binary = "BINARY";
    }else{
        $binary = "";
    }

    if($table_name == "interfaces"){

        $query = " SELECT a.id "
            . " FROM $table_name a	"
            . " INNER JOIN ( "
            . "   SELECT id, unitname FROM $table_name WHERE source = '$source' $vsys_query GROUP BY $binary unitname HAVING count(*) > 1 	"
            . "   ) b ON a.unitname = $binary b.unitname AND source = '$source' $vsys_query ORDER BY a.unitname ASC;";
    }
    else{

        if($type == ""){
            $query = " SELECT a.id "
                . " FROM $table_name a	"
                . " INNER JOIN ( "
                . "   SELECT id, name FROM $table_name WHERE source = '$source' $vsys_query GROUP BY $binary name HAVING count(*) > 1 	"
                . "   ) b ON a.name = $binary b.name AND source = '$source' $vsys_query ORDER BY a.name ASC;";
        }
        else{
            $query = " SELECT a.id "
                . " FROM $table_name a	"
                . " INNER JOIN ( "
                . "   SELECT id, name FROM $table_name WHERE type = '$type' AND source = '$source' $vsys_query GROUP BY $binary name HAVING count(*) > 1 	"
                . "   ) b ON a.name = $binary b.name AND type = '$type' AND source = '$source' $vsys_query ORDER BY a.name ASC;";
        }

    }

    $getIdResults = $projectdb->query($query);
    //echo "Duplicated Name: " .$query."\n";

    if ($getIdResults->num_rows != 0) {
        while ($data = $getIdResults->fetch_assoc()) {
            $ids_results_in[] = $data['id'];
        }
    }

    return $ids_results_in;
}


function getDuplicatedNameValue($table_name, $type, $vsys, $source, $case_sensitive){

    global $projectdb;
    $ids_results_in = array();

    $conditions = "";

    require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
    $vsys_query = prepareVsysQuery($projectdb, $vsys, $source);

    if($case_sensitive == 1){
        $binary = "BINARY";
    }else{
        $binary = "";
    }

    if($table_name == "address"){
//        $query = " SELECT a.id FROM address a	"
//            . " INNER JOIN ( SELECT id, name, type, ipaddress, cidr FROM address WHERE source = '$source' $vsys_query GROUP BY BINARY name, type, ipaddress, cidr HAVING count(*) > 1 	"
//            . "   ) b ON (a.name = b.name AND a.type = b.type AND a.ipaddress = b.ipaddress AND a.cidr = b.cidr) $vsys_query AND source = '$source' ORDER BY a.name, a.type, a.ipaddress, a.cidr;";

        $query = "SELECT a.id FROM address a, (SELECT name, ipaddress, cidr, count(*) AS number 
                  FROM (SELECT name, ipaddress, IF(cidr='', '32', cidr) AS cidr FROM address WHERE source = '$source' $vsys_query) myTable 
                  GROUP BY $binary name, ipaddress, cidr HAVING number > 1) duplicados 
                  WHERE a.name = $binary duplicados.name AND a.ipaddress = duplicados.ipaddress AND ((a.cidr = '' AND duplicados.cidr = '32') OR (a.cidr = duplicados.cidr)) AND source = '$source' $vsys_query ORDER BY a.name, a.type, a.ipaddress, a.cidr;";

    }
    elseif($table_name == "services"){

        $version = calcVersion($source);

        if($version >= 8.1){
            $query = " SELECT a.id FROM services a	"
                . " INNER JOIN ( SELECT id, name, protocol, dport, override, timeout, halfclose_timeout, timewait_timeout FROM services WHERE source = '$source' $vsys_query GROUP BY $binary name, protocol, dport, IFNULL(NULLIF(override, ''), 'no'), timeout, halfclose_timeout, timewait_timeout HAVING count(*) > 1 	"
                . "   ) b ON ( a.name = $binary b.name AND a.protocol = b.protocol AND a.dport = b.dport AND IFNULL(NULLIF(a.override, ''), 'no') = IFNULL(NULLIF(b.override, ''), 'no') AND a.timeout = b.timeout AND a.halfclose_timeout = b.halfclose_timeout AND a.timewait_timeout = b.timewait_timeout) $vsys_query AND source = '$source' ORDER BY a.name, a.protocol, a.dport, IFNULL(NULLIF(a.override, ''), 'no'), a.timeout, a.halfclose_timeout, a.timewait_timeout;";
        }else{
            $query = " SELECT a.id FROM services a	"
                . " INNER JOIN ( SELECT id, name, protocol, dport FROM services WHERE source = '$source' $vsys_query GROUP BY $binary name, protocol, dport HAVING count(*) > 1 	"
                . "   ) b ON ($binary a.name = $binary b.name AND a.protocol = b.protocol AND a.dport = b.dport ) $vsys_query AND source = '$source' ORDER BY a.name, a.protocol, a.dport;";
        }

    }
    elseif($table_name == "regions"){
        $query = " SELECT a.id FROM regions a	"
            . " INNER JOIN ( SELECT id, name, latitude, longitude, address FROM regions WHERE source = '$source' $vsys_query GROUP BY $binary name, latitude, longitude, address HAVING count(*) > 1 	"
            . "   ) b ON ($binary a.name = $binary b.name AND a.latitude = b.latitude AND a.longitude = b.longitude AND a.address = b.address ) $vsys_query AND source = '$source' ORDER BY a.name, a.latitude, a.longitude, a.address;";
    }
    elseif($table_name == "applications_filters"){
        $query = " SELECT a.id FROM applications_filters a	"
            . " INNER JOIN ( SELECT id, name, category, subcategory, risk, technology, evasive_behavior, consume_big_bandwidth, prone_to_misuse, able_to_transfer_file, tunnel_other_application, used_by_malware, has_known_vulnerability, pervasive_use FROM applications_filters WHERE source = '$source' $vsys_query "
            . " GROUP BY $binary name, category, subcategory, risk, technology, evasive_behavior, consume_big_bandwidth, prone_to_misuse, able_to_transfer_file, tunnel_other_application, used_by_malware, has_known_vulnerability, pervasive_use HAVING count(*) > 1 	"
            . "   ) b ON ($binary a.name = $binary b.name AND a.category = b.category AND a.subcategory = b.subcategory AND a.risk = b.risk AND a.technology = b.technology AND a.evasive_behavior = b.evasive_behavior AND a.consume_big_bandwidth = b.consume_big_bandwidth "
            . " AND a.prone_to_misuse = b.prone_to_misuse AND a.able_to_transfer_file = b.able_to_transfer_file AND a.tunnel_other_application = b.tunnel_other_application AND a.used_by_malware = b.used_by_malware AND a.has_known_vulnerability = b.has_known_vulnerability AND a.pervasive_use = b.pervasive_use ) $vsys_query AND source = '$source';";
    }
    elseif(($table_name == "address_groups_id") || ($table_name == "services_groups_id") || ($table_name == "applications_groups_id")){

        if($table_name == "address_groups_id"){ $table_name_without_id = "address_groups";
        }elseif($table_name == "services_groups_id") { $table_name_without_id = "services_groups";
        }elseif($table_name == "applications_groups_id"){ $table_name_without_id = "applications_groups";}

        $projectdb->query("TRUNCATE TABLE tmp_dup_name_val;");
        $query = "SELECT * FROM $table_name a WHERE source = '$source' $vsys_query GROUP BY $binary name HAVING count(*) > 1;";
        //echo "Query 1: " .$query. "\n";
        $getAll = $projectdb->query($query);

        if ($getAll->num_rows > 0) {
            while ($getLimitData = $getAll->fetch_assoc()) {
                $name_int = $getLimitData['name'];

                $query = "SELECT * FROM $table_name a WHERE source = '$source' $vsys_query AND $binary name = '$name_int' ;";
                //echo "Query 2: " .$query. "\n";
                $getAll2 = $projectdb->query($query);

                while ($data3 = $getAll2->fetch_assoc()) {
                    $lid = $data3['id'];
                    $name_int = $data3['name'];
                    $members = $projectdb->query("SELECT table_name, member_lid FROM $table_name_without_id WHERE lid = '$lid'");
                    //echo "Query 3: SELECT table_name, member_lid FROM $table_name_without_id WHERE lid = '$lid'\n";
                    if ($members->num_rows > 0) {
                        $membername = array();
                        while ($data2 = $members->fetch_assoc()) {
                            $member_lid = $data2['member_lid'];
                            $member_table_name = $data2['table_name'];

                            if($member_table_name != "default_applications"){

                                $getMemName = $projectdb->query("SELECT name, vsys FROM $member_table_name WHERE id = '$member_lid';");
                                if ($getMemName->num_rows == 1) {
                                    $membername2 = $getMemName->fetch_assoc();
                                    $member_vsys = $membername2['vsys'];
                                    if ($member_vsys == "shared") {
                                        $name_member = $membername2['name']."&&&";
                                        $membername[] = $name_member;
                                    }else{
                                        $membername[] = $membername2['name'];
                                    }
                                }
                            }
                            else{
                                $getMemName = $projectdb->query("SELECT name FROM $member_table_name WHERE id = '$member_lid';");
                                if ($getMemName->num_rows == 1) {
                                    $membername2 = $getMemName->fetch_assoc();
                                    $membername[] = $membername2['name'];
                                }
                            }

                        }
                        asort($membername);
                        $projectdb->query("INSERT INTO tmp_dup_name_val (lid,members,table_name,name) VALUES ('$lid','" . implode(",", $membername) . "','$table_name_without_id','$name_int');");
                    }else{
                        $getLog = $projectdb->query("SELECT id FROM logs WHERE obj_id='$lid' AND obj_table='$table_name_without_id' AND obj_type='objects' AND message LIKE '%No Members%';");
                        if ($getLog->num_rows == 0) {
                            add_log2('error', 'Invalid Group', 'The '.$table_name_without_id.' Group [' . $name_int . '] has No Members', '', 'Please Remove this Group or Add some Members', 'objects', $lid, $table_name_without_id);
                        }
                    }
                }
            }
            # Get names from temp table where members are equal
            $getDup = $projectdb->query("SELECT lid, table_name, name, members, count(id) as t FROM tmp_dup_name_val GROUP BY $binary name, members HAVING t>1;");

            $sql_ids = array();
            if ($getDup->num_rows > 0) {
                while ($getnames = $getDup->fetch_assoc()) {
                    $themembers = $getnames['members'];
                    $name_duplicated = $getnames['name'];
                    $getbyMember = $projectdb->query("SELECT lid FROM tmp_dup_name_val WHERE members = '$themembers' AND name = '$name_duplicated';");
                    //echo "Query 4: SELECT lid FROM tmp_dup_name_val WHERE members = '$themembers' AND name = '$name_duplicated';\n";

                    while ($getbyMemberData = $getbyMember->fetch_assoc()) {
                        $lid = $getbyMemberData['lid'];
                        $sql_ids[] = "'$lid'";
                    }
                }
            }

            $orderby = "";
            if(count($sql_ids) > 0){
                $conditions = "WHERE id IN (" . implode(",", $sql_ids) . ") ";
                $orderby = " ORDER BY FIELD (a.id, " . implode(",", $sql_ids) . ") ";
            }
            else{
                $conditions = "WHERE id IN ('') ";
            }
            $query = "SELECT id FROM $table_name a $conditions $orderby";
        }
    }

    $getIdResults = $projectdb->query($query);
    //echo "------------->Duplicated Name Value: " .$query."\n";

    if ($getIdResults->num_rows != 0) {
        while ($data = $getIdResults->fetch_assoc()) {
            $ids_results_in[] = $data['id'];
        }
    }

    return $ids_results_in;

}


function getDuplicatedValue($table_name, $type, $vsys, $source){

    global $projectdb;
    $ids_results_in = array();
    $query = "";

    $version = calcVersion($source);

    require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
    $vsys_query = prepareVsysQuery($projectdb, $vsys, $source);

    if($table_name == "address"){
//        $query = " SELECT a.id "
//            . " FROM address a	"
//            . "  INNER JOIN ( "
//            . "   SELECT id, name, type, ipaddress, cidr FROM address WHERE source = '$source' $vsys_query GROUP BY type, ipaddress, cidr HAVING count(*) > 1 	"
//            . "   ) b ON (a.type = b.type AND a.ipaddress = b.ipaddress AND a.cidr = b.cidr) $vsys_query AND source = '$source' ORDER BY a.type, a.ipaddress, a.cidr;";

        $query = "SELECT a.id FROM address a, (SELECT ipaddress, cidr, count(*) AS number 
                  FROM (SELECT ipaddress, IF(cidr='', '32', cidr) AS cidr FROM address WHERE source = '$source' $vsys_query) myTable 
                  GROUP BY ipaddress, cidr HAVING number > 1) duplicados 
                  WHERE a.ipaddress = duplicados.ipaddress AND ((a.cidr = '' AND duplicados.cidr = '32') OR (a.cidr = duplicados.cidr)) AND source = '$source' $vsys_query ORDER BY a.type, a.ipaddress, a.cidr;";

    }
    elseif($table_name == "services"){

        if($version >= 8.1){

            $query = " SELECT a.id "
                . " FROM services a	"
                . "  INNER JOIN ( "
                . "   SELECT id, name, protocol, dport, override, timeout, halfclose_timeout, timewait_timeout FROM services WHERE source = '$source' $vsys_query GROUP BY protocol, dport, IFNULL(NULLIF(override, ''), 'no'), timeout, halfclose_timeout, timewait_timeout HAVING count(*) > 1 	"
                . "   ) b ON (a.protocol = b.protocol AND a.dport = b.dport AND IFNULL(NULLIF(a.override, ''), 'no') = IFNULL(NULLIF(b.override, ''), 'no') AND a.timeout = b.timeout AND a.halfclose_timeout = b.halfclose_timeout AND a.timewait_timeout = b.timewait_timeout) $vsys_query AND source = '$source' ORDER BY a.protocol, a.dport, IFNULL(NULLIF(a.override, ''), 'no'), a.timeout, a.halfclose_timeout, a.timewait_timeout;";
        }
        else{
            $query = " SELECT a.id "
                . " FROM services a	"
                . "  INNER JOIN ( "
                . "   SELECT id, name, protocol, dport FROM services WHERE source = '$source' $vsys_query GROUP BY protocol, dport HAVING count(*) > 1 	"
                . "   ) b ON (a.protocol = b.protocol AND a.dport = b.dport) $vsys_query AND source = '$source' ORDER BY a.protocol, a.dport;";
        }


    }
    elseif($table_name == "regions"){
        $query = " SELECT a.id "
            . " FROM regions a	"
            . "  INNER JOIN ( "
            . "   SELECT id, name, latitude, longitude, address FROM regions WHERE source = '$source' $vsys_query GROUP BY latitude, longitude, address HAVING count(*) > 1 	"
            . "   ) b ON (a.latitude = b.latitude AND a.longitude = b.longitude AND a.address = b.address ) $vsys_query AND source = '$source' ORDER BY a.latitude, a.longitude, a.address;";
    }
    elseif(($table_name == "address_groups_id") || ($table_name == "services_groups_id") || ($table_name == "applications_groups_id")){

        if($table_name == "address_groups_id"){ $table_name_without_id = "address_groups";
        }elseif($table_name == "services_groups_id") { $table_name_without_id = "services_groups";
        }elseif($table_name == "applications_groups_id"){ $table_name_without_id = "applications_groups";}


        $projectdb->query("TRUNCATE TABLE tmp_dup_name_val;");

        $query = "SELECT * FROM $table_name a WHERE source = '$source' $vsys_query;";
        $getAll = $projectdb->query($query);

        if ($getAll->num_rows > 0) {
            while ($data3 = $getAll->fetch_assoc()) {
                $lid = $data3['id'];
                $vsys_group = $data3['vsys'];
                $name_int = $data3['name'];
                $members = $projectdb->query("SELECT table_name, member_lid FROM $table_name_without_id WHERE lid = '$lid'");
                if ($members->num_rows > 0) {
                    $membername = array();
                    while ($data2 = $members->fetch_assoc()) {
                        $member_lid = $data2['member_lid'];
                        $member_table_name = $data2['table_name'];
                        $getMemName = $projectdb->query("SELECT name, vsys FROM $member_table_name WHERE id='$member_lid';");
                        if ($getMemName->num_rows == 1) {
                            $membername2 = $getMemName->fetch_assoc();
                            $member_vsys = $membername2['vsys'];
                            if ($member_vsys == "shared") {
                                $name_member = $membername2['name']."&&&";
                                $membername[] = $name_member;
                            }else{
                                $membername[] = $membername2['name'];
                            }
                        }
                    }
                    asort($membername);
                    $projectdb->query("INSERT INTO tmp_dup_name_val (lid, members, table_name, name, vsys) VALUES ('$lid', '" . implode(",", $membername) . "', '$table_name_without_id', '$name_int', '$vsys_group');");
                }
            }

            # Get names from temp table where members are equal
            $getDup = $projectdb->query("SELECT lid, table_name, name, members, count(id) as t FROM tmp_dup_name_val GROUP BY members HAVING t>1;");

            $sql_ids = array();

            if ($getDup->num_rows > 0) {
                while ($getnames = $getDup->fetch_assoc()) {
                    $themembers = $getnames['members'];
                    $getbyMember = $projectdb->query("SELECT lid FROM tmp_dup_name_val WHERE members = '$themembers';");

                    while ($getbyMemberData = $getbyMember->fetch_assoc()) {
                        $lid = $getbyMemberData['lid'];
                        $sql_ids[] = "'$lid'";
                    }
                }
            }
            $orderby = "";
            if(count($sql_ids) > 0){
                $conditions = "WHERE id IN (" . implode(",", $sql_ids) . ") ";
                $orderby = " ORDER BY FIELD (a.id, " . implode(",", $sql_ids) . ") ";
            }else{
                $conditions = "WHERE id IN ('') ";
            }
            $query = "SELECT id FROM $table_name a $conditions $orderby";
        }
    }

    if($query != ""){
        $getIdResults = $projectdb->query($query);
        //echo "Duplicated Value: " .$query."\n";

        if ($getIdResults->num_rows != 0) {
            while ($data = $getIdResults->fetch_assoc()) {
                $ids_results_in[] = $data['id'];
            }
        }
    }
    return $ids_results_in;
}


function getDeplicatedNameVsGroup($table_name, $type, $vsys, $source, $filter_id, $tools_sql_id, $user_id){

    global $projectdb;
    $ids_results_in = array();

    require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
    $vsys_query = prepareVsysQuery($projectdb, $vsys, $source);

    if(($table_name == "address") || ($table_name == "address_groups_id")) {

        if ($table_name == "address") {
            $table_name_complementaria = "address_groups_id";
            $image = "/resources/images/rules/address_group.gif";
            $table_name_name = "Address Groups";
        } elseif ($table_name == "address_groups_id") {
            $table_name_complementaria = "address";
            $image = "/resources/images/rules/address.gif";
            $table_name_name = "Address";
        }

    }
    elseif(($table_name == "services") || ($table_name == "services_groups_id")) {

        if ($table_name == "services") {
            $table_name_complementaria = "services_groups_id";
            $image = "/resources/images/rules/service_group.gif";
            $table_name_name = "Services Groups";
        } elseif ($table_name == "services_groups_id") {
            $table_name_complementaria = "services";
            $image = "/resources/images/rules/service.gif";
            $table_name_name = "Services";
        }
    }
    elseif(($table_name == "applications") || ($table_name == "applications_groups_id")) {

        if ($table_name == "applications") {
            $table_name_complementaria = "applications_groups_id";
            $image = "/resources/images/rules/applications_groups.gif";
            $table_name_name = "Applications Groups";
        } elseif ($table_name == "applications_groups_id") {
            $table_name_complementaria = "applications";
            $image = "/resources/images/rules/application.gif";
            $table_name_name = "Applications";
        }
    }

    $query = "SELECT id, name FROM $table_name WHERE source = '$source' $vsys_query AND name IN (SELECT BINARY name FROM $table_name_complementaria WHERE source = '$source' $vsys_query)";
    $getIdResults = $projectdb->query($query);
    //echo "Duplicated Name vs Groups: " .$query."\n";

    if ($getIdResults->num_rows != 0) {
        while ($data = $getIdResults->fetch_assoc()) {
            $ids_results_in[] = $data['id'];
        }
    }

    $query_complementaria = "SELECT id, name FROM $table_name_complementaria WHERE source = '$source' $vsys_query AND name IN (SELECT BINARY name FROM $table_name WHERE source = '$source' $vsys_query)";

    $getIdResultsComplementaria = $projectdb->query($query_complementaria);
    if ($getIdResultsComplementaria->num_rows != 0) {
        while ($dataC = $getIdResultsComplementaria->fetch_assoc()) {
            $member_lid = $dataC['id'];
            $query_insert = "INSERT INTO tools_results (filter_id, tools_sql_id, member_lid, table_name, type, table_name_name, image, source, user_id) 
                                      VALUES ('$filter_id', '$tools_sql_id', '$member_lid', '$table_name_complementaria', '', '$table_name_name', '$image', '$source', '$user_id'); ";
            $projectdb->query($query_insert);
        }
    }
    elseif($getIdResultsComplementaria->num_rows == 0){
        $query_insert = "INSERT INTO tools_results (filter_id, tools_sql_id, member_lid, table_name, type, table_name_name, image, source, user_id) 
                                      VALUES ('$filter_id', '$tools_sql_id', '', '$table_name_complementaria', '', '$table_name_name', '$image', '$source', '$user_id'); ";
        $projectdb->query($query_insert);
    }

    return $ids_results_in;

}


function getGroupsWithOneMember($table_name, $type, $vsys, $source){

    global $projectdb;
    $ids_results_in = array();

    require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
    $vsys_query = prepareVsysQueryB($projectdb, $vsys, $source);

    if(($table_name == "address_groups_id") || ($table_name == "services_groups_id") || ($table_name == "applications_groups_id")) {

        if ($table_name == "address_groups_id") {
            $table_name_without_id = "address_groups";
        } elseif ($table_name == "services_groups_id") {
            $table_name_without_id = "services_groups";
        } elseif ($table_name == "applications_groups_id") {
            $table_name_without_id = "applications_groups";
        }

        $query = "SELECT lid, COUNT(lid) AS t 
                    FROM $table_name_without_id a, $table_name b 
                    WHERE a.lid=b.id AND b.source = '$source' $vsys_query GROUP BY lid HAVING t=1;";
    }

    $getIdResults = $projectdb->query($query);
    //echo "Groups with one member: " .$query."\n";

    if ($getIdResults->num_rows != 0) {
        while ($data = $getIdResults->fetch_assoc()) {
            $ids_results_in[] = $data['lid'];
        }
    }

    return $ids_results_in;

}


function getAddressNotInGroups($table_name, $type, $vsys, $source){
    global $projectdb;
    $ids_results_in = array();

    require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
    $vsys_query = prepareVsysQuery($projectdb, $vsys, $source);

    $query = "SELECT id 
                FROM address 
                WHERE type='ip-netmask' AND cidr='32' AND source = '$source' $vsys_query AND dummy=0
                and id not in (SELECT member_lid FROM address_groups WHERE table_name='address') ";

    $getIdResults = $projectdb->query($query);
    //echo "Objets not in groups: " .$query."\n";

    if ($getIdResults->num_rows != 0) {
        while ($data = $getIdResults->fetch_assoc()) {
            $ids_results_in[] = $data['id'];
        }
    }

    return $ids_results_in;
}

function getGroupsWithoutMembers($table_name, $type, $vsys, $source){
    global $projectdb;
    $ids_results_in = array();

    require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
    $vsys_query = prepareVsysQuery($projectdb, $vsys, $source);

    if(($table_name == "address_groups_id") || ($table_name == "services_groups_id") || ($table_name == "applications_groups_id")) {

        if ($table_name == "address_groups_id") {
            $table_name_without_id = "address_groups";
        } elseif ($table_name == "services_groups_id") {
            $table_name_without_id = "services_groups";
        } elseif ($table_name == "applications_groups_id") {
            $table_name_without_id = "applications_groups";
        }

        $query = "SELECT id FROM $table_name WHERE source = '$source' $vsys_query AND id NOT IN (SELECT lid FROM $table_name_without_id);";

    }

    $getIdResults = $projectdb->query($query);
    //echo "Groups without members: " .$query."\n";

    if ($getIdResults->num_rows != 0) {
        while ($data = $getIdResults->fetch_assoc()) {
            $ids_results_in[] = $data['id'];
        }
    }

    return $ids_results_in;


}


function getUsed($table_name, $type, $vsys, $source){

    global $projectdb;
    $ids_results_in = array();

    require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
    $vsys_query = prepareVsysQuery($projectdb, $vsys, $source);

    //check_used_objects_new();

    $query = "SELECT id FROM $table_name a WHERE source = '$source' $vsys_query  AND used = '1';";

    $getIdResults = $projectdb->query($query);
    //echo "Used: " .$query."\n";

    if ($getIdResults->num_rows != 0) {
        while ($data = $getIdResults->fetch_assoc()) {
            $ids_results_in[] = $data['id'];
        }
    }

    return $ids_results_in;

}


function getUnused($table_name, $type, $vsys, $source){

    global $projectdb;
    $ids_results_in = array();

    require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
    $vsys_query = prepareVsysQuery($projectdb, $vsys, $source);

    //check_used_objects_new();

    $query = "SELECT id FROM $table_name a WHERE source = '$source' $vsys_query  AND used = '0';";

    $getIdResults = $projectdb->query($query);
    //echo "Unused: " .$query."\n";

    if ($getIdResults->num_rows != 0) {
        while ($data = $getIdResults->fetch_assoc()) {
            $ids_results_in[] = $data['id'];
        }
    }

    return $ids_results_in;

}


function getDisabled($table_name, $type, $vsys, $source){

    global $projectdb;
    $ids_results_in = array();

    require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
    $vsys_query = prepareVsysQuery($projectdb, $vsys, $source);

    if(($table_name == "security_rules") || ($table_name == "nat_rules") || ($table_name == "appoverride_rules")){
        $conditions = " WHERE disabled = '1'  ";
        $query = "SELECT id FROM $table_name $conditions $vsys_query AND source = '$source';";

        $getIdResults = $projectdb->query($query);
        //echo "Disabled: " .$query."\n";

        if ($getIdResults->num_rows != 0) {
            while ($data = $getIdResults->fetch_assoc()) {
                $ids_results_in[] = $data['id'];
            }
        }
    }

    return $ids_results_in;

}


function getEnabled($table_name, $type, $vsys, $source){

    global $projectdb;
    $ids_results_in = array();

    require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
    $vsys_query = prepareVsysQuery($projectdb, $vsys, $source);

    if(($table_name == "security_rules") || ($table_name == "nat_rules") || ($table_name == "appoverride_rules")){
        $conditions = " WHERE disabled = '0'  ";
        $query = "SELECT id FROM $table_name $conditions $vsys_query AND source = '$source';";

        $getIdResults = $projectdb->query($query);
        //echo "Enabled: " .$query."\n";

        if ($getIdResults->num_rows != 0) {
            while ($data = $getIdResults->fetch_assoc()) {
                $ids_results_in[] = $data['id'];
            }
        }
    }

    return $ids_results_in;

}


function getSelectAll($table_name, $type, $vsys, $source){

    global $projectdb;
    $ids_results_in = array();

    require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
    $vsys_query = prepareVsysQuery($projectdb, $vsys, $source);

    if(($table_name == "userid_group") || ($table_name == "userid_group_members") ){
        $query = "SELECT id FROM $table_name;";
    }
    elseif($table_name == "other_objects"){

        //TODO: ESTO SE TENDRÁ QUE QUITAR YA QUE SI QUE VAMOS AÑADIR LOS CONTENTS AND OTHER OBJECTS!!!!
        $query = "SELECT id FROM log_settings WHERE source = '$source' $vsys_query;";
    }
    else{
        $query = "SELECT id FROM $table_name WHERE source = '$source' $vsys_query;";
    }

    $getIdResults = $projectdb->query($query);
    //echo "Select All: " .$query."\n";

    if ($getIdResults->num_rows != 0) {
        while ($data = $getIdResults->fetch_assoc()) {
            $ids_results_in[] = $data['id'];
        }
    }

    return $ids_results_in;

}


function getNameIsIPAddress($table_name, $type, $vsys, $source){

    global $projectdb;
    $ids_results_in = array();

    require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
    $vsys_query = prepareVsysQuery($projectdb, $vsys, $source);

    $query = " SELECT id FROM $table_name WHERE INET6_ATON(name) IS NOT NULL AND source = '$source' $vsys_query 
              UNION SELECT id FROM $table_name WHERE name LIKE '%/32' AND source = '$source' $vsys_query  ";

    $getIdResults = $projectdb->query($query);
    //echo "Duplicated Name: " .$query."\n";

    if ($getIdResults->num_rows != 0) {
        while ($data = $getIdResults->fetch_assoc()) {
            $ids_results_in[] = $data['id'];
        }
    }

    return $ids_results_in;
}


function getMembers($table_name_id, $type, $operator, $search, $vsys , $source){

    global $projectdb;
    $ids_results_in = array();

    require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
    $vsys_query = prepareVsysQuery($projectdb, $vsys, $source);

    if($table_name_id == "address_groups_id"){
        $table_name = "address_groups";
    }elseif($table_name_id == "services_groups_id") {
        $table_name = "services_groups";
    }elseif($table_name_id == "applications_groups_id") {
        $table_name = "applications_groups";
    }

    if(($operator == ">=") || ($operator == "<=") || ($operator == "=")){
        if(($search == "0") && ($operator == "=")){
            $query = "SELECT id FROM $table_name_id WHERE source = '$source' $vsys_query AND id NOT IN (SELECT lid FROM $table_name);";
        }
        elseif(($operator == "<=") || (($search == "0") && ($operator == ">="))){
            $query = " SELECT lid AS id FROM $table_name WHERE source = '$source' $vsys_query  GROUP BY lid HAVING count(*) $operator $search;";
            $query2 = "SELECT id FROM $table_name_id WHERE source = '$source' $vsys_query AND id NOT IN (SELECT lid FROM $table_name);";
        }
        else{
            $query = " SELECT lid AS id FROM $table_name WHERE source = '$source' $vsys_query  GROUP BY lid HAVING count(*) $operator $search;";
        }
    }
    else{

        if($table_name_id == "address_groups_id"){

            $members_lid_address = array();
            $members_lid_address_groups_id = array();
            $query_address = "";

            $searchInAddress = $projectdb->query("SELECT id, 'address' AS table_name FROM address WHERE source = '$source' $vsys_query AND ( (ipaddress LIKE '%$search%') OR (BINARY name LIKE '%$search%') OR (type LIKE '%$search%') );");
            //echo "SELECT id, 'address' AS table_name FROM address WHERE source = '$source' $vsys_query AND ( (ipaddress LIKE '%$search%') OR (BINARY name LIKE '%$search%') OR (type LIKE '%$search%') );\n";

            if($searchInAddress->num_rows > 0){
                while ($dataSA = $searchInAddress->fetch_assoc()) {
                    $members_lid_address[] = $dataSA['id'];
                }
            }

            $searchInAddressGroupsId = $projectdb->query("SELECT id, 'address_groups_id' AS table_name FROM address_groups_id WHERE source = '$source' $vsys_query AND (BINARY name LIKE '%$search%' OR type='$search');");
            //echo "SELECT id, 'address_groups_id' AS table_name FROM address_groups_id WHERE source = '$source' $vsys_query AND (BINARY name LIKE '%$search%' OR type='$search');";

            if($searchInAddressGroupsId->num_rows > 0){
                while ($dataSAG = $searchInAddressGroupsId->fetch_assoc()) {
                    $members_lid_address_groups_id[] = $dataSAG['id'];
                }
            }

            if(count($members_lid_address) > 0){
                $query_address = " AND (member_lid IN (".implode(",", $members_lid_address).") AND table_name = 'address' ) ";
            }else{
                $query_address = " AND (member_lid IN ('') AND table_name = 'address' ) ";
            }

            if(count($members_lid_address_groups_id) > 0){
                if (preg_match("/AND/", $query_address)) {
                    $query_address = $query_address . " OR (member_lid IN (".implode(",", $members_lid_address_groups_id).") AND table_name = 'address_groups_id' )";
                }
            }

            $query = " SELECT lid AS id FROM $table_name WHERE source = '$source' $vsys_query $query_address GROUP BY lid;";

        }
        elseif($table_name_id == "services_groups_id"){

            $members_lid_services = array();
            $members_lid_services_groups_id = array();
            $query_services = "";

            $searchInServcies = $projectdb->query("SELECT id, 'services' AS table_name FROM services WHERE source = '$source' $vsys_query AND (BINARY name LIKE '%$search%') ;");
            //echo "SELECT id, 'services' AS table_name FROM services WHERE source = '$source' $vsys_query AND (BINARY name LIKE '%$search%') ;";

            if($searchInServcies->num_rows > 0){
                while ($dataSA = $searchInServcies->fetch_assoc()) {
                    $members_lid_services[] = $dataSA['id'];
                }
            }

            $searchInServicesGroupsId = $projectdb->query("SELECT id, 'services_groups_id' AS table_name FROM services_groups_id WHERE source = '$source' $vsys_query AND (BINARY name LIKE '%$search%' OR type='$search');");

            if($searchInServicesGroupsId->num_rows > 0){
                while ($dataSAG = $searchInServicesGroupsId->fetch_assoc()) {
                    $members_lid_services_groups_id[] = $dataSAG['id'];
                }
            }

            if(count($members_lid_services) > 0){
                $query_services = " AND (member_lid IN (".implode(",", $members_lid_services).") AND table_name = 'services' ) ";
            }else{
                $query_services = " AND (member_lid IN ('') AND table_name = 'services' ) ";
            }

            if(count($members_lid_services_groups_id) > 0){
                if (preg_match("/AND/", $query_services)) {
                    $query_services = $query_services . " OR (member_lid IN (".implode(",", $members_lid_services_groups_id).") AND table_name = 'services_groups_id' )";
                }
            }

            $query = " SELECT lid AS id FROM $table_name WHERE source = '$source' $vsys_query $query_services GROUP BY lid;";

        }
        elseif($table_name_id == "applications_groups_id"){

            $members_lid_app = array();
            $members_lid_app_groups_id = array();
            $members_lid_def_app_id = array();
            $members_lid_app_filters_id = array();
            $query_app = "";

            $searchInApp = $projectdb->query("SELECT id, 'applications' AS table_name FROM applications WHERE source = '$source' $vsys_query AND (BINARY name LIKE '%$search%') ;");
            //echo "SELECT id, 'services' AS table_name FROM services WHERE source = '$source' $vsys_query AND (BINARY name LIKE '%$search%') ;";

            if($searchInApp->num_rows > 0){
                while ($dataSA = $searchInApp->fetch_assoc()) {
                    $members_lid_app[] = $dataSA['id'];
                }
            }

            $searchInAppGroupsId = $projectdb->query("SELECT id, 'applications_groups_id' AS table_name FROM applications_groups_id WHERE source = '$source' $vsys_query AND (BINARY name LIKE '%$search%' OR type='$search');");

            if($searchInAppGroupsId->num_rows > 0){
                while ($dataSAG = $searchInAppGroupsId->fetch_assoc()) {
                    $members_lid_app_groups_id[] = $dataSAG['id'];
                }
            }

            $searchInDefAppId = $projectdb->query("SELECT id, 'default_applications' AS table_name FROM default_applications WHERE BINARY name LIKE '%$search%';");

            if($searchInDefAppId->num_rows > 0){
                while ($dataSAG = $searchInDefAppId->fetch_assoc()) {
                    $members_lid_def_app_id[] = $dataSAG['id'];
                }
            }

            $searchInAppFiltersId = $projectdb->query("SELECT id, 'applications_filters' AS table_name FROM applications_filters WHERE BINARY name LIKE '%$search%';");

            if($searchInAppFiltersId->num_rows > 0){
                while ($dataSAG = $searchInAppFiltersId->fetch_assoc()) {
                    $members_lid_app_filters_id[] = $dataSAG['id'];
                }
            }

            if(count($members_lid_app) > 0){
                $query_app = " AND (member_lid IN (".implode(",", $members_lid_app).") AND table_name = 'applications' ) ";
            }else{
                $query_app = " AND (member_lid IN ('') AND table_name = 'applications' ) ";
            }

            if(count($members_lid_app_groups_id) > 0){
                if (preg_match("/AND/", $query_app)) {
                    $query_app = $query_app . " OR (member_lid IN (".implode(",", $members_lid_app_groups_id).") AND table_name = 'applications_groups_id' )";
                }
            }

            if(count($members_lid_def_app_id) > 0){
                if (preg_match("/AND/", $query_app)) {
                    $query_app = $query_app . " OR (member_lid IN (".implode(",", $members_lid_def_app_id).") AND table_name = 'default_applications' )";
                }
            }

            if(count($members_lid_app_filters_id) > 0){
                if (preg_match("/AND/", $query_app)) {
                    $query_app = $query_app . " OR (member_lid IN (".implode(",", $members_lid_app_filters_id).") AND table_name = 'applications_filters' )";
                }
            }

            $query = " SELECT lid AS id FROM $table_name WHERE source = '$source' $vsys_query $query_app GROUP BY lid;";

        }


    }

    $getIdResults = $projectdb->query($query);
    //echo "Members: " .$query."\n";

    if ($getIdResults->num_rows != 0) {
        while ($data = $getIdResults->fetch_assoc()) {
            $ids_results_in[] = $data['id'];
        }
    }

    if(($operator == "<=") || (($search >= "0") && ($operator == ">="))){
        $getIdResults2 = $projectdb->query($query2);
        if ($getIdResults2->num_rows != 0) {
            while ($data2 = $getIdResults2->fetch_assoc()) {
                $ids_results_in[] = $data2['id'];
            }
        }
    }


    return $ids_results_in;
}


function getTagsNotUsed($table_name, $type, $vsys, $source){

    global $projectdb;
    $ids_results_in = array();

    require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
    $vsys_query = prepareVsysQuery($projectdb, $vsys, $source);

    if($table_name == "security_rules"){
        $query = "SELECT id FROM $table_name WHERE source = '$source' $vsys_query AND id NOT IN (SELECT rule_lid FROM security_rules_tag);";
    }

    $getIdResults = $projectdb->query($query);
    //echo "Tags not used: " .$query."\n";

    if ($getIdResults->num_rows != 0) {
        while ($data = $getIdResults->fetch_assoc()) {
            $ids_results_in[] = $data['id'];
        }
    }

    return $ids_results_in;

}


function getDescriptionNotPopulated($table_name, $type, $vsys, $source){

    global $projectdb;
    $ids_results_in = array();

    require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
    $vsys_query = prepareVsysQuery($projectdb, $vsys, $source);

    if($table_name == "security_rules"){
        $query = "SELECT id FROM $table_name WHERE source = '$source' $vsys_query AND description = '';";
    }

    $getIdResults = $projectdb->query($query);
    //echo "Description empty: " .$query."\n";

    if ($getIdResults->num_rows != 0) {
        while ($data = $getIdResults->fetch_assoc()) {
            $ids_results_in[] = $data['id'];
        }
    }

    return $ids_results_in;

}


function getSourceDestinationAny($table_name, $type, $vsys, $source){

    global $projectdb;
    $ids_results_in = array();

    $ids_results_src = array();
    $ids_results_dst = array();

    require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
    $vsys_query = prepareVsysQuery($projectdb, $vsys, $source);

    if($table_name == "security_rules"){

        $query = "SELECT id FROM $table_name WHERE source = '$source' $vsys_query AND id NOT IN (SELECT rule_lid FROM security_rules_src);";

        $getIdResultsSRC = $projectdb->query($query);

        if ($getIdResultsSRC->num_rows != 0) {
            while ($dataSRC = $getIdResultsSRC->fetch_assoc()) {
                $ids_results_src[] = $dataSRC['id'];
            }
        }

        $query = "SELECT id FROM $table_name WHERE source = '$source' $vsys_query AND id NOT IN (SELECT rule_lid FROM security_rules_dst);";

        $getIdResultsDST = $projectdb->query($query);

        if ($getIdResultsDST->num_rows != 0) {
            while ($dataDST = $getIdResultsDST->fetch_assoc()) {
                $ids_results_dst[] = $dataDST['id'];
            }
        }

        $ids_results_in = array_intersect($ids_results_src, $ids_results_dst);


    }

    return $ids_results_in;

}


function getServiceAny($table_name, $type, $vsys, $source){

    global $projectdb;
    $ids_results_in = array();

    require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
    $vsys_query = prepareVsysQuery($projectdb, $vsys, $source);

    if($table_name == "security_rules"){
        $query = "SELECT id FROM $table_name WHERE source = '$source' $vsys_query AND id NOT IN (SELECT rule_lid FROM security_rules_srv);";
    }

    $getIdResults = $projectdb->query($query);
    //echo "Services SRV: " .$query."\n";

    if ($getIdResults->num_rows != 0) {
        while ($data = $getIdResults->fetch_assoc()) {
            $ids_results_in[] = $data['id'];
        }
    }

    return $ids_results_in;

}


function getLogStartEnabled($table_name, $type, $vsys, $source){

    global $projectdb;
    $ids_results_in = array();

    require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
    $vsys_query = prepareVsysQuery($projectdb, $vsys, $source);

    if($table_name == "security_rules"){
        $query = "SELECT id FROM $table_name WHERE source = '$source' $vsys_query AND log_start = '1';";
    }

    $getIdResults = $projectdb->query($query);
    //echo "Log start enabled: " .$query."\n";

    if ($getIdResults->num_rows != 0) {
        while ($data = $getIdResults->fetch_assoc()) {
            $ids_results_in[] = $data['id'];
        }
    }

    return $ids_results_in;

}


function getLogForwardingNotEnabled($table_name, $type, $vsys, $source){

    global $projectdb;
    $ids_results_in = array();

    require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
    $vsys_query = prepareVsysQuery($projectdb, $vsys, $source);

    if($table_name == "security_rules"){
        $query = "SELECT id FROM $table_name WHERE source = '$source' $vsys_query AND log_forwarding = '';";
    }

    $getIdResults = $projectdb->query($query);
    //echo "Log Forwarding empty: " .$query."\n";

    if ($getIdResults->num_rows != 0) {
        while ($data = $getIdResults->fetch_assoc()) {
            $ids_results_in[] = $data['id'];
        }
    }

    return $ids_results_in;

}


function getExpiredSchedule($table_name, $type, $vsys, $source){

    global $projectdb;
    $ids_results_in = array();

    require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
    $vsys_query = prepareVsysQuery($projectdb, $vsys, $source);

    if($table_name == "security_rules"){

        $getScheduleSR = $projectdb->query("SELECT id, schedule FROM $table_name WHERE source = '$source' $vsys_query AND schedule != '';");

        if ($getScheduleSR->num_rows > 0) {

            while ($dataSSR = $getScheduleSR->fetch_assoc()) {

                $rule_id = $dataSSR['id'];
                $schedule = $dataSSR['schedule'];

                $getSchedule = $projectdb->query("SELECT id, xml FROM schedules WHERE source = '$source' AND name = '$schedule' ;");

                if ($getSchedule->num_rows > 0) {

                    while ($dataS = $getSchedule->fetch_assoc()) {


                        $xml_bbdd = $dataS['xml'];
                        $xml = simplexml_load_string($xml_bbdd);
                        //print_r($xml);

                        // solo tengo que mostrar las reglas que tenga los schedules que sean non-recurring y que la data expired esté ya expirada
                        if (isset($xml->{'schedule-type'}->{'non-recurring'})){
                            foreach ($xml->{'schedule-type'}->{'non-recurring'}->member as $member) {

                                //2017/09/05@15:15-2017/09/20@02:30
                                $end_date_exp = explode("-", $member);
                                $end_date = $end_date_exp[1];
                                $end_date = str_replace("@", " ", $end_date);

                                $dteStart = new DateTime("now");
                                $dteEnd   = new DateTime($end_date);

                                if($dteEnd < $dteStart){
                                    //echo "EXPIRED!";
                                    $ids_results_in[] = $rule_id;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    return $ids_results_in;

}


function getDsriEnabled($table_name, $type, $vsys, $source){

    global $projectdb;
    $ids_results_in = array();

    require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
    $vsys_query = prepareVsysQuery($projectdb, $vsys, $source);

    if($table_name == "security_rules"){
        $query = "SELECT id FROM $table_name WHERE source = '$source' $vsys_query AND dsri = '1';";
    }

    $getIdResults = $projectdb->query($query);
    //echo "Dsri enabled: " .$query."\n";

    if ($getIdResults->num_rows != 0) {
        while ($data = $getIdResults->fetch_assoc()) {
            $ids_results_in[] = $data['id'];
        }
    }

    return $ids_results_in;

}


function getMlEnabled($table_name, $type, $vsys, $source){

    global $projectdb;
    $ids_results_in = array();

    require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
    $vsys_query = prepareVsysQuery($projectdb, $vsys, $source);

    if($table_name == "security_rules"){
        $query = "SELECT id FROM $table_name WHERE source = '$source' $vsys_query AND ml = '1';";
    }

    $getIdResults = $projectdb->query($query);
    //echo "ML enabled: " .$query."\n";

    if ($getIdResults->num_rows != 0) {
        while ($data = $getIdResults->fetch_assoc()) {
            $ids_results_in[] = $data['id'];
        }
    }

    return $ids_results_in;

}


function getReEnabled($table_name, $type, $vsys, $source){

    global $projectdb;
    $ids_results_in = array();

    require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
    $vsys_query = prepareVsysQuery($projectdb, $vsys, $source);

    if($table_name == "security_rules"){
        $query = "SELECT id FROM $table_name WHERE source = '$source' $vsys_query AND re = '1';";
    }

    $getIdResults = $projectdb->query($query);
    //echo "RE enabled: " .$query."\n";

    if ($getIdResults->num_rows != 0) {
        while ($data = $getIdResults->fetch_assoc()) {
            $ids_results_in[] = $data['id'];
        }
    }

    return $ids_results_in;

}


function getRulesWarning($table_name, $type, $vsys, $source){

    global $projectdb;
    $ids_results_in = array();

    require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
    $vsys_query = prepareVsysQuery($projectdb, $vsys, $source);

    if(($table_name == "security_rules") || ($table_name == "nat_rules")){
        $query = "SELECT obj_id FROM logs WHERE obj_type = 'rules' AND obj_table = '$table_name' AND source = '$source' AND UPPER(action) NOT LIKE '%NO ACTION REQUIRED%';";
    }

    $getIdResults = $projectdb->query($query);
    //echo "Rules with warnings: " .$query."\n";

    if ($getIdResults->num_rows != 0) {
        while ($data = $getIdResults->fetch_assoc()) {
            $ids_results_in[] = $data['obj_id'];
        }
    }

    return $ids_results_in;

}


function getAppsTimeout($table_name, $type, $vsys, $source){

    global $projectdb;

    $ids_results_in = array();
    $app_id_app = array();
    $app_id_app_group = array();

    require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
    $vsys_query = prepareVsysQuery($projectdb, $vsys, $source);

    $getIdsAppTimeout = $projectdb->query("SELECT id, name, timeout, tcp_timeout, udp_timeout, tcp_half_closed_timeout, tcp_time_wait_timeout, vsys, source 
              FROM applications a WHERE (a.timeout != '' OR a.tcp_timeout != '' OR a.udp_timeout != '' OR a.tcp_half_closed_timeout != '' OR a.tcp_time_wait_timeout != '') AND source = '$source';");
    //echo "1. SELECT id, name, timeout, tcp_timeout, udp_timeout, tcp_half_closed_timeout, tcp_time_wait_timeout, vsys, source
    //          FROM applications a WHERE (a.timeout != '' OR a.tcp_timeout != '' OR a.udp_timeout != '' OR a.tcp_half_closed_timeout != '' OR a.tcp_time_wait_timeout != '') AND source = '$source';\n";

    if ($getIdsAppTimeout->num_rows != 0) {
        while ($dataIAT = $getIdsAppTimeout->fetch_assoc()) {
            $app_id_app[] = $dataIAT['id'];
        }
    }

    if(count($app_id_app) > 0){
        $getIdsAppTimeoutAG = $projectdb->query("SELECT lid, member_lid, table_name 
              FROM applications_groups WHERE (member_lid IN (".implode(",", $app_id_app).") AND table_name = 'applications') $vsys_query AND source = '$source' GROUP BY lid;");

        //echo "2. SELECT lid, member_lid, table_name
        //      FROM applications_groups WHERE (member_lid IN (".implode(",", $app_id_app).") AND table_name = 'applications') $vsys_query AND source = '$source' GROUP BY lid;\n";
    }else{
        $getIdsAppTimeoutAG = $projectdb->query("SELECT lid, member_lid, table_name 
              FROM applications_groups WHERE (member_lid IN ('') AND table_name = 'applications') $vsys_query AND source = '$source' GROUP BY lid;");

        //echo "2. SELECT lid, member_lid, table_name
        //      FROM applications_groups WHERE (member_lid IN ('') AND table_name = 'applications') $vsys_query AND source = '$source' GROUP BY lid;\n";

    }

    if ($getIdsAppTimeoutAG->num_rows != 0) {
        while ($dataIATAG = $getIdsAppTimeoutAG->fetch_assoc()) {
            $app_id_app_group[] = $dataIATAG['lid'];
        }
    }

    if(count($app_id_app) > 0){
        $query_implode = " app_id IN (".implode(",", $app_id_app).") ";
    }else{
        $query_implode = " app_id IN ('') ";
    }

    if(count($app_id_app_group) > 0){
        $query_implode_group = " app_id IN (".implode(",", $app_id_app_group).") ";
    }else{
        $query_implode_group = " app_id IN ('') ";
    }

    $query = "SELECT id FROM appoverride_rules 
              WHERE ( $query_implode AND app_table = 'applications') 
              OR ( $query_implode_group AND app_table = 'applications_groups_id') $vsys_query AND source = '$source'";

    $getIdResults = $projectdb->query($query);
    //echo "Rules with App timeout: " .$query."\n";

    if ($getIdResults->num_rows != 0) {
        while ($data = $getIdResults->fetch_assoc()) {
            $ids_results_in[] = $data['id'];
        }
    }

    return $ids_results_in;

}


function getMatchAppOverride($table_name, $type, $vsys, $source){

    global $projectdb;
    $ids_results_in = array();

    require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
    $vsys_query = prepareVsysQuery($projectdb, $vsys, $source);

    $getTags = $projectdb->query("SELECT id FROM tag WHERE vsys = 'shared' AND source = '$source' AND BINARY name = 'MATCHED APP OVERRIDE';");
    if ($getTags->num_rows == 1) {
        $dataT = $getTags->fetch_assoc();
        $id_tag = $dataT['id'];

        if($table_name == "security_rules"){
            $query = "SELECT id FROM $table_name WHERE source = '$source' $vsys_query AND id IN (SELECT rule_lid FROM security_rules_tag WHERE member_lid = '$id_tag');";
            //echo "Tags MATCH APP OVERRIDE: " .$query."\n";
            $getIdResults = $projectdb->query($query);

            if ($getIdResults->num_rows != 0) {
                while ($data = $getIdResults->fetch_assoc()) {
                    $ids_results_in[] = $data['id'];
                }
            }
        }
    }

    return $ids_results_in;

}


function getServiceTimeout($table_name, $type, $vsys, $source){

    global $projectdb;
    $ids_results_in = array();

    require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
    $vsys_query = prepareVsysQuery($projectdb, $vsys, $source);

    $getTags = $projectdb->query("SELECT id FROM tag WHERE vsys = 'shared' AND source = '$source' AND BINARY name = 'ADDED SERVICE TIMEOUT';");
    if ($getTags->num_rows == 1) {
        $dataT = $getTags->fetch_assoc();
        $id_tag = $dataT['id'];

        if($table_name == "security_rules"){
            $query = "SELECT id FROM $table_name WHERE source = '$source' $vsys_query AND id IN (SELECT rule_lid FROM security_rules_tag WHERE member_lid = '$id_tag');";
            //echo "Tags SERVICE TIMEOUT: " .$query."\n";
            $getIdResults = $projectdb->query($query);

            if ($getIdResults->num_rows != 0) {
                while ($data = $getIdResults->fetch_assoc()) {
                    $ids_results_in[] = $data['id'];
                }
            }
        }
    }

    return $ids_results_in;

}


function getReplacedAppServiceTimeout($table_name, $type, $vsys, $source){

    global $projectdb;
    $ids_results_in = array();

    require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
    $vsys_query = prepareVsysQuery($projectdb, $vsys, $source);

    $getTags = $projectdb->query("SELECT id FROM tag WHERE vsys = 'shared' AND source = '$source' AND BINARY name = 'REPLACED APP TO SERVICE TIMEOUT';");
    if ($getTags->num_rows == 1) {
        $dataT = $getTags->fetch_assoc();
        $id_tag = $dataT['id'];

        if($table_name == "appoverride_rules"){
            $query = "SELECT id FROM $table_name WHERE source = '$source' $vsys_query AND id IN (SELECT rule_lid FROM appoverride_rules_tag WHERE member_lid = '$id_tag');";
            //echo "Tags SERVICE TIMEOUT: " .$query."\n";
            $getIdResults = $projectdb->query($query);

            if ($getIdResults->num_rows != 0) {
                while ($data = $getIdResults->fetch_assoc()) {
                    $ids_results_in[] = $data['id'];
                }
            }
        }
    }

    return $ids_results_in;

}


function getPreRulebase($table_name, $type, $vsys, $source){

    global $projectdb;
    $ids_results_in = array();

    require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
    $vsys_query = prepareVsysQuery($projectdb, $vsys, $source);

    if(($table_name == "security_rules") || ($table_name == "nat_rules") || ($table_name == "appoverride_rules")){
        $conditions = " WHERE preorpost = '0'  ";
        $query = "SELECT id FROM $table_name $conditions $vsys_query AND source = '$source';";

        $getIdResults = $projectdb->query($query);
        //echo "Pre rulebase: " .$query."\n";

        if ($getIdResults->num_rows != 0) {
            while ($data = $getIdResults->fetch_assoc()) {
                $ids_results_in[] = $data['id'];
            }
        }
    }

    return $ids_results_in;

}


function getPostRulebase($table_name, $type, $vsys, $source){

    global $projectdb;
    $ids_results_in = array();

    require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
    $vsys_query = prepareVsysQuery($projectdb, $vsys, $source);

    if(($table_name == "security_rules") || ($table_name == "nat_rules") || ($table_name == "appoverride_rules")){
        $conditions = " WHERE preorpost = '1'  ";
        $query = "SELECT id FROM $table_name $conditions $vsys_query AND source = '$source';";

        $getIdResults = $projectdb->query($query);
        //echo "Pre rulebase: " .$query."\n";

        if ($getIdResults->num_rows != 0) {
            while ($data = $getIdResults->fetch_assoc()) {
                $ids_results_in[] = $data['id'];
            }
        }
    }

    return $ids_results_in;

}


function getGhostObjects($table_name, $type, $vsys, $source, $dummy='1'){

    global $projectdb;
    $ids_results_in = array();

    require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
    $vsys_query = prepareVsysQuery($projectdb, $vsys, $source);

    $query = "SELECT id FROM $table_name a WHERE source = '$source' $vsys_query  AND dummy = $dummy;";

    $getIdResults = $projectdb->query($query);
    //echo "Dummy: " .$query."\n";

    if ($getIdResults->num_rows != 0) {
        while ($data = $getIdResults->fetch_assoc()) {
            $ids_results_in[] = $data['id'];
        }
    }

    return $ids_results_in;

}


function getBidirectional($table_name, $type, $vsys, $source):array{
    global $projectdb;
    $ids_results_in = array();

    require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
    $vsys_query = prepareVsysQuery($projectdb, $vsys, $source);

    $query = "SELECT id FROM $table_name a WHERE source = '$source' $vsys_query  AND tp_sat_bidirectional = '1';";

    $getIdResults = $projectdb->query($query);

    if ($getIdResults->num_rows != 0) {
        while ($data = $getIdResults->fetch_assoc()) {
            $ids_results_in[] = $data['id'];
        }
    }

    return $ids_results_in;
}

function getRulesMembersNull($table_name, $vsys, $source){

    global $projectdb;
    $ids_results_in = array();

    $ids_results_src = array();
    $ids_results_dst = array();
    $ids_results_srv = array();
    $ids_results_app = array();
    $ids_results_tag = array();
    $ids_results_trans = array();
    $ids_results_trans_fall = array();

    require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
    $vsys_query = prepareVsysQuery($projectdb, $vsys, $source);

    if($table_name == "security_rules"){

        $getIdResultsSRC = $projectdb->query("SELECT id FROM $table_name WHERE source = '$source' $vsys_query AND id IN (SELECT rule_lid FROM security_rules_src WHERE member_lid = '0');");

        if ($getIdResultsSRC->num_rows != 0) {
            while ($dataSRC = $getIdResultsSRC->fetch_assoc()) {
                $ids_results_src[] = $dataSRC['id'];
            }
        }

        $getIdResultsDST = $projectdb->query("SELECT id FROM $table_name WHERE source = '$source' $vsys_query AND id IN (SELECT rule_lid FROM security_rules_dst WHERE member_lid = '0');");

        if ($getIdResultsDST->num_rows != 0) {
            while ($dataDST = $getIdResultsDST->fetch_assoc()) {
                $ids_results_dst[] = $dataDST['id'];
            }
        }

        $getIdResultsSRV = $projectdb->query("SELECT id FROM $table_name WHERE source = '$source' $vsys_query AND id IN (SELECT rule_lid FROM security_rules_srv WHERE member_lid = '0');");

        if ($getIdResultsSRV->num_rows != 0) {
            while ($dataSRV = $getIdResultsSRV->fetch_assoc()) {
                $ids_results_srv[] = $dataSRV['id'];
            }
        }

        $getIdResultsAPP = $projectdb->query("SELECT id FROM $table_name WHERE source = '$source' $vsys_query AND id IN (SELECT rule_lid FROM security_rules_app WHERE member_lid = '0');");

        if ($getIdResultsAPP->num_rows != 0) {
            while ($dataAPP = $getIdResultsAPP->fetch_assoc()) {
                $ids_results_app[] = $dataAPP['id'];
            }
        }

        $getIdResultsTAG = $projectdb->query("SELECT id FROM $table_name WHERE source = '$source' $vsys_query AND id IN (SELECT rule_lid FROM security_rules_tag WHERE member_lid = '0');");

        if ($getIdResultsTAG->num_rows != 0) {
            while ($dataTAG = $getIdResultsTAG->fetch_assoc()) {
                $ids_results_tag[] = $dataTAG['id'];
            }
        }

        $ids_results_in = array_merge($ids_results_src, $ids_results_dst, $ids_results_srv, $ids_results_app);

    }
    elseif($table_name == "nat_rules"){

        $getIdResultsSRC = $projectdb->query("SELECT id FROM $table_name WHERE source = '$source' $vsys_query AND id IN (SELECT rule_lid FROM nat_rules_src WHERE member_lid = '0');");

        if ($getIdResultsSRC->num_rows != 0) {
            while ($dataSRC = $getIdResultsSRC->fetch_assoc()) {
                $ids_results_src[] = $dataSRC['id'];
            }
        }

        $getIdResultsDST = $projectdb->query("SELECT id FROM $table_name WHERE source = '$source' $vsys_query AND id IN (SELECT rule_lid FROM nat_rules_dst WHERE member_lid = '0');");

        if ($getIdResultsDST->num_rows != 0) {
            while ($dataDST = $getIdResultsDST->fetch_assoc()) {
                $ids_results_dst[] = $dataDST['id'];
            }
        }

        $getIdResultsTAG = $projectdb->query("SELECT id FROM $table_name WHERE source = '$source' $vsys_query AND id IN (SELECT rule_lid FROM nat_rules_tag WHERE member_lid = '0');");

        if ($getIdResultsTAG->num_rows != 0) {
            while ($dataTAG = $getIdResultsTAG->fetch_assoc()) {
                $ids_results_tag[] = $dataTAG['id'];
            }
        }

        $getIdResultsTrans = $projectdb->query("SELECT id FROM $table_name WHERE source = '$source' $vsys_query AND id IN (SELECT rule_lid FROM nat_rules_translated_address WHERE member_lid = '0');");

        if ($getIdResultsTrans->num_rows != 0) {
            while ($dataTrans = $getIdResultsTrans->fetch_assoc()) {
                $ids_results_trans[] = $dataTrans['id'];
            }
        }

        $getIdResultsTransFall = $projectdb->query("SELECT id FROM $table_name WHERE source = '$source' $vsys_query AND id IN (SELECT rule_lid FROM nat_rules_translated_address_fallback WHERE member_lid = '0');");

        if ($getIdResultsTransFall->num_rows != 0) {
            while ($dataTransFall = $getIdResultsTransFall->fetch_assoc()) {
                $ids_results_trans_fall[] = $dataTransFall['id'];
            }
        }

        $ids_results_in = array_merge($ids_results_src, $ids_results_dst, $ids_results_trans, $ids_results_trans_fall);

    }
    elseif($table_name == "appoverride_rules"){

        $getIdResultsSRC = $projectdb->query("SELECT id FROM $table_name WHERE source = '$source' $vsys_query AND id IN (SELECT rule_lid FROM appoverride_rules_src WHERE member_lid = '0');");

        if ($getIdResultsSRC->num_rows != 0) {
            while ($dataSRC = $getIdResultsSRC->fetch_assoc()) {
                $ids_results_src[] = $dataSRC['id'];
            }
        }

        $getIdResultsDST = $projectdb->query("SELECT id FROM $table_name WHERE source = '$source' $vsys_query AND id IN (SELECT rule_lid FROM appoverride_rules_dst WHERE member_lid = '0');");

        if ($getIdResultsDST->num_rows != 0) {
            while ($dataDST = $getIdResultsDST->fetch_assoc()) {
                $ids_results_dst[] = $dataDST['id'];
            }
        }

        $getIdResultsTAG = $projectdb->query("SELECT id FROM $table_name WHERE source = '$source' $vsys_query AND id IN (SELECT rule_lid FROM appoverride_rules_tag WHERE member_lid = '0');");

        if ($getIdResultsTAG->num_rows != 0) {
            while ($dataTAG = $getIdResultsTAG->fetch_assoc()) {
                $ids_results_tag[] = $dataTAG['id'];
            }
        }

        $ids_results_in = array_merge($ids_results_src, $ids_results_dst, $ids_results_tag);

    }

    return $ids_results_in;

}

function getMatchesFilterToolsSingleTable($table_to_search, $type, $column, $operator, $operator_name, $search, $case_sensitive, $vsys, STRING $source) {

    global $projectdb;

    $ids_results_in = array();
    $binary = "";

    if(($operator_name == "contains") || ($operator_name == "contains.recursive") || ($operator_name == "not contains")){
        $search = preg_replace("/_/", "\_", $search);
        $search = "%$search%";
    }elseif($operator_name == "starts with"){
        $search = preg_replace("/_/", "\_", $search);
        $search = "$search%";
    }elseif($operator_name == "ends with"){
        $search = preg_replace("/_/", "\_", $search);
        $search = "%$search";
    }

    if($case_sensitive == 1){
        $binary = "BINARY";
    }

    require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
    $vsys_query = prepareVsysQuery($projectdb, $vsys, $source);

    if (($column == "op_zone_to") && ($search == "")){
        $query = "SELECT id FROM $table_to_search WHERE $column $operator '$search' OR $column $operator 'none' $vsys_query AND source = '$source' ;";
    }
    elseif ($column == "Name_To"){
        $query = "SELECT id FROM $table_to_search WHERE name = '' OR (op_zone_to = '' OR op_zone_to = 'none') $vsys_query AND source = '$source' ;";
    }
    else{
        if($type == ""){
            if($table_to_search == "default_applications"){
                $query = "SELECT id FROM $table_to_search WHERE $binary $column $operator '$search';";
            }else{
                $query = "SELECT id FROM $table_to_search WHERE $binary $column $operator '$search' $vsys_query AND source = '$source' ;";
            }
        }
        else{
            $query = "SELECT id FROM $table_to_search WHERE $binary $column $operator '$search' $vsys_query AND source = '$source' AND type = '$type' ;";
        }
    }

    if($query != ""){
        $getIdResults = $projectdb->query($query);
        //echo "Filter1: " .$query."\n";

        if ($getIdResults->num_rows != 0) {
            while ($data = $getIdResults->fetch_assoc()) {
                $ids_results_in[] = $data['id'];
            }
        }
    }

    return $ids_results_in;
}


function getMatchesFilterToolsMultiTable($rules_table, $type, $sub_table, $operator, $operator_name, $recursive, $search, $case_sensitive, $vsys, STRING $source){

    global $projectdb;

    $ids_rules_recursive = array();
    $ids_rules_in = array();
    $ids_rules_all = array();
    $binary = $query = "";

    if($sub_table == "security_rules_target"){
        $search_exp = explode("/", $search);
        $search = $search_exp[0];
        $device_vsys = $search_exp[1];
    }

    if($case_sensitive == 1){
        $binary = "BINARY";
    }

    if(($operator_name == "contains") || ($operator_name == "contains.recursive") || ($operator_name == "not contains")){
        $search = preg_replace("/_/", "\_", $search);
        $search = "%$search%";
    }elseif($operator_name == "starts with"){
        $search = preg_replace("/_/", "\_", $search);
        $search = "$search%";
    }elseif($operator_name == "ends with"){
        $search = preg_replace("/_/", "\_", $search);
        $search = "%$search";
    }

    require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
    $vsys_query = prepareVsysQuery($projectdb, $vsys, $source);

    if((strtolower($search) == "any") || ($search == "") || (strtolower($search) == "none")
        || (strtolower($search) == "%none%") || (strtolower($search) == "%any%") || ($search == "%%")) {

        if(($sub_table == "tp_dat_address_lid") || ($sub_table == "tp_dat_port")){
            $query = "SELECT id FROM $rules_table WHERE source = '$source' $vsys_query AND $sub_table $operator '0';";
        }else{
            if($operator == "="){
                $query = "SELECT id FROM $rules_table WHERE source = '$source' $vsys_query AND id NOT IN (SELECT rule_lid FROM $sub_table);";
            }
            elseif ($operator == "!="){
                $query = "SELECT id FROM $rules_table WHERE source = '$source' $vsys_query AND id IN (SELECT rule_lid FROM $sub_table);";
            }
        }

    }
    else{
        if ($recursive == "true"){
            if (($operator_name == "not equal") || ($operator_name == "not contains") || ($operator_name == "not in network")){
                //All the rules minus the ones that contain the member we look for
                //Initially, we get all the rules in the policy for this source
                $query = "SELECT id FROM $rules_table WHERE source = '$source';";

                //echo "Query1: " .$query. "\n";
                $getAllRules = $projectdb->query($query);
                if ($getAllRules->num_rows != 0){
                    while ($filterRow = $getAllRules->fetch_assoc()) {
                        $ids_rules_all[] = $filterRow['id'];
                    }
                }

                if ($operator_name == "not equal") $operator = "equal";
                if ($operator_name == "not contains") $operator = "contains";
                if ($operator_name == "not in network") $operator = "in network";

                if ($sub_table == "op_service_lid") {
                    $query = "SELECT id AS rule_lid, op_service_lid AS member_lid, op_service_table AS table_name FROM $rules_table WHERE source = '$source' $vsys_query ORDER by rule_lid;";
                } elseif ($sub_table == "tp_dat_address_lid") {
                    $query = "SELECT id AS rule_lid, tp_dat_address_lid AS member_lid, tp_dat_address_table AS table_name FROM $rules_table WHERE source = '$source' $vsys_query ORDER by rule_lid;";
                } else {
                    //$query = "SELECT id, rule_lid, member_lid, table_name FROM $sub_table WHERE source = '$source' $vsys_query ORDER by rule_lid;";
                    $query = "SELECT id, rule_lid, member_lid, table_name FROM $sub_table ORDER by rule_lid;";
                }

                $getSecurityRulesByTable = $projectdb->query($query);
                if ($getSecurityRulesByTable->num_rows != 0) {
                    while ($data = $getSecurityRulesByTable->fetch_assoc()) {
                        $rule_lid = $data['rule_lid'];
                        $member_lid = $data['member_lid'];
                        $table_name = $data['table_name'];
                        if($table_name != ""){
                            $rule_id = getIdsToFiltersToolsEqualContainsRecursive($member_lid, $table_name, $search, $rule_lid, $operator);
                            if ($rule_id != "") {
                                $ids_rules_recursive[] = $rule_id;
                            }
                        }
                    }
                    $ids_rules_recursive = arrayUnique($ids_rules_recursive);
                }

                $ids_rules_recursive = array_diff($ids_rules_all, $ids_rules_recursive);

                $query = "";

            }
            else{
                if ($sub_table == "op_service_lid") {
                    $query = "SELECT id AS rule_lid, op_service_lid AS member_lid, op_service_table AS table_name FROM $rules_table WHERE source = '$source' $vsys_query ORDER by rule_lid;";
                } elseif ($sub_table == "tp_dat_address_lid") {
                    $query = "SELECT id AS rule_lid, tp_dat_address_lid AS member_lid, tp_dat_address_table AS table_name FROM $rules_table WHERE source = '$source' $vsys_query ORDER by rule_lid;";
                } elseif ($sub_table == "app_id") {
                    $query = "SELECT id AS rule_lid, app_id AS member_lid, app_table AS table_name FROM $rules_table WHERE source = '$source' $vsys_query ORDER by rule_lid;";
                } elseif ($sub_table == "tag_relations") {
                    $query = "SELECT member_lid AS rule_lid, tag_id AS member_lid, 'tag' AS table_name FROM $sub_table WHERE table_name = '$rules_table'  ORDER by rule_lid;";
                }
                else {
                    //$query = "SELECT id, rule_lid, member_lid, table_name FROM $sub_table WHERE source = '$source' $vsys_query ORDER by rule_lid;";
                    $query = "SELECT id, rule_lid, member_lid, table_name FROM $sub_table ORDER by rule_lid;";
                }

                //echo "Query1: " .$query. "\n";
                $getSecurityRulesByTable = $projectdb->query($query);
                if ($getSecurityRulesByTable->num_rows != 0) {
                    while ($data = $getSecurityRulesByTable->fetch_assoc()) {
                        $rule_lid = $data['rule_lid'];

                        $member_lid = $data['member_lid'];
                        $table_name = $data['table_name'];
                        if($table_name != ""){
                            $rule_id = getIdsToFiltersToolsEqualContainsRecursive($member_lid, $table_name, $search, $rule_lid, $operator_name);
                            if ($rule_id != "") {
                                $ids_rules_recursive[] = $rule_id;
                            }
                        }
                    }
                    $ids_rules_recursive = arrayUnique($ids_rules_recursive);
                }
                $query = "";
            }
        }
        else{
            if (($operator_name == "not equal") || ($operator_name == "not contains")){
                $query = "SELECT id FROM $rules_table WHERE source = '$source';";

                $getAllRules = $projectdb->query($query);
                if ($getAllRules->num_rows != 0){
                    while ($filterRow = $getAllRules->fetch_assoc()) {
                        $ids_rules_all[] = $filterRow['id'];
                    }
                }

                if ($operator_name == "not equal") $operator = "!=";
                if ($operator_name == "not contains") $operator = "NOT LIKE";

                if($sub_table == "tp_dat_address_lid") {
                    $query = "SELECT id FROM nat_rules where tp_dat_address_lid in (select id from address WHERE  name $operator '$search') OR tp_dat_address_lid = 0;";
                }
                elseif($sub_table == "tp_dat_port"){
                    $query = "SELECT id FROM nat_rules WHERE tp_dat_port $operator '$search' AND source = '$source'";
                }else{
                    if ($operator_name == "not equal") $operator = "=";
                    if ($operator_name == "not contains") $operator = "LIKE";
                    //$query = "SELECT rule_lid as id FROM $sub_table WHERE source = '$source' $vsys_query AND name $operator '$search';";
                    $query = "SELECT rule_lid as id FROM $sub_table WHERE $binary name $operator '$search';";
                    $getRules = $projectdb->query($query);
                    if ($getRules->num_rows != 0) {
                        while ($filterRow = $getRules->fetch_assoc()) {
                            $ids_rules_recursive[] = $filterRow['id'];
                        }
                    }

                    $ids_rules_recursive = array_diff($ids_rules_all, $ids_rules_recursive);
                    $query = "";
                }
            }
            else{
                if($sub_table == "security_rules_target"){
                    if($device_vsys != ""){
                        //$query = "SELECT rule_lid as id FROM $sub_table WHERE source = '$source' $vsys_query AND (name $operator '$search' AND device_vsys $operator '%$device_vsys%');";
                        $query = "SELECT rule_lid as id FROM $sub_table WHERE ($binary name $operator '$search' AND device_vsys $operator '%$device_vsys%');";
                    }else{
                        //$query = "SELECT rule_lid as id FROM $sub_table WHERE source = '$source' $vsys_query AND name $operator '$search';";
                        $query = "SELECT rule_lid as id FROM $sub_table WHERE $binary name $operator '$search';";
                    }
                }
                elseif($sub_table == "tp_dat_address_lid"){
                    $query = "SELECT id FROM nat_rules where tp_dat_address_lid in (select id from address WHERE  name $operator '$search');";
                }
                elseif($sub_table == "tp_dat_port"){
                    $query = "SELECT id FROM nat_rules WHERE tp_dat_port LIKE '$search' AND source = '$source'";
                }
                else{
                    //$query = "SELECT rule_lid as id FROM $sub_table WHERE source = '$source' $vsys_query AND name $operator '$search';";
                    $query = "SELECT rule_lid as id FROM $sub_table WHERE $binary name $operator '$search';";
                }
            }
        }
    }

    //echo "Query1: " .$query. "\n";
    if ($query != ""){
        $getIdRules = $projectdb->query($query);
        if ($getIdRules->num_rows != 0) {
            while ($data = $getIdRules->fetch_assoc()) {
                $ids_rules_in[] = $data['id'];
            }
        }
    }

    return array_merge($ids_rules_recursive,$ids_rules_in);
}


function getIdsToFiltersToolsEqualContainsRecursive($member_lid, $table_name, $search, $rule_id, $operator) {

    global $projectdb;
    $is_network = 0;
    $match_to_filter_rule_id = "";
    $consulta = "";

    if (($operator == "equal.recursive") || ($operator == "equal") || ($operator == "not equal")) {
        if ($operator == "not equal") {
            $symbol = "!=";
            $connector = "AND";
        } else {
            $symbol = "=";
            $connector = "OR";
        }
        if ($table_name == "address") {
            $consulta = " AND (name $symbol '$search' $connector ipaddress $symbol '$search') ";
            // Comprobar si han añadido ipaddress/cidr
            if (preg_match("/\//i", $search)) {
                //$valid = filter_var($string, FILTER_VALIDATE_IP);
                $address_parts = explode("/", $search);
                if ($address_parts[1] != 32) {
                    $consulta = " AND (ipaddress = '$address_parts[0]' AND cidr = '$address_parts[1]' AND type = 'ip-netmask') ";
                } else {
                    $search = $address_parts[0];
                    $consulta = " AND (name = '$search' OR ipaddress = '$search') ";
                }
            }
        }
        else {
            $consulta = " AND name $symbol '$search' ";
        }
//        $my = fopen("search.txt", "a"); fwrite($my, "   $consulta\n"); fclose($my);
    }
    elseif (($operator == "contains.recursive") || ($operator == "contains") || ($operator == "not contains")) {

        if ($operator == "not contains") {
            $symbol = "NOT LIKE";
            $connector = "AND";
        } else {
            $symbol = "LIKE";
            $connector = "OR";
        }
        if ($table_name == "address") {
            $consulta = " AND (name $symbol '%$search%' $connector ipaddress $symbol '%$search%') ";
        } else {
            $consulta = " AND name $symbol '%$search%' ";
        }
    }
    elseif(($operator == "starts with") || ($operator == "ends with")){

        if ($table_name == "address") {
            $consulta = " AND (name LIKE '$search' OR ipaddress LIKE '$search') ";
        } else {
            $consulta = " AND name LIKE '$search' ";
        }
    }
    elseif ($operator == "in network") {

        $is_network = 1;
        $is_in_network = "";

        if (($table_name == "address") || ($table_name == "address_groups_id")) {

            // IP
            if (preg_match("/\//i", $search)) {
                //$valid = filter_var($string, FILTER_VALIDATE_IP);
                $address_parts = explode("/", $search);
                if ($address_parts[1] != 32) {
                    // Mirar si es group
                    if (preg_match("/groups/i", $table_name)) {

                        $table_name_sin_id = str_replace("_id", "", $table_name);
                        $getAddressGroupsResults = $projectdb->query("SELECT id, member_lid, table_name FROM $table_name_sin_id WHERE lid = '$member_lid' ;");

                        if ($getAddressGroupsResults->num_rows != 0) {
                            while ($data = $getAddressGroupsResults->fetch_assoc()) {
                                $member_lid_group = $data['member_lid'];
                                $table_name_group = $data['table_name'];

                                if(preg_match("/groups/i", $table_name_group)){

                                    $rule_id_return = getIdsToFiltersToolsEqualContainsRecursive($member_lid_group, $table_name_group, $search, $rule_id, $operator);

                                    if ($rule_id_return != "") {
                                        $match_to_filter_rule_id = $rule_id;
                                    }
                                }
                                else{
                                    $getAddressResultsToNetwork = $projectdb->query("SELECT id, ipaddress, cidr FROM $table_name_group WHERE id = '$member_lid_group' AND type = 'ip-netmask' ;");
                                    if ($getAddressResultsToNetwork->num_rows != 0) {
                                        $data = $getAddressResultsToNetwork->fetch_assoc();
                                        $ipaddress = $data['ipaddress'];
                                        $is_in_network = netMatchV4($search, $ipaddress);
                                        //echo "0.Is in network: " .$is_in_network. "\n";
                                        if ($is_in_network == 1) {
                                            $match_to_filter_rule_id = $rule_id;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    else {
                        $getAddressResultsToNetwork = $projectdb->query("SELECT id, ipaddress, cidr FROM $table_name WHERE id = '$member_lid' AND type = 'ip-netmask' ;");
                        if ($getAddressResultsToNetwork->num_rows != 0) {
                            $data = $getAddressResultsToNetwork->fetch_assoc();
                            $ipaddress = $data['ipaddress'];
                            $is_in_network = netMatchV4($search, $ipaddress);
                            //echo "1.Is in network: " .$is_in_network. "\n";
                            if ($is_in_network == 1) {
                                $match_to_filter_rule_id = $rule_id;
                            }
                        }
                    }
                }
                else {
                    $search = $address_parts[0];
                    $consulta = " AND (name = '$search' OR ipaddress = '$search') ";

                    $getAddressResults = $projectdb->query("SELECT id FROM $table_name WHERE id = '$member_lid' $consulta ;");

                    if ($getAddressResults->num_rows != 0) {
                        $match_to_filter_rule_id = $rule_id;
                    }
                }

            } // Name
            elseif (preg_match("/-/i", $search)) {

                if (preg_match("/groups/i", $table_name)) {

                    $table_name_sin_id = str_replace("_id", "", $table_name);
                    $getAddressGroupsResults = $projectdb->query("SELECT id, member_lid, table_name FROM $table_name_sin_id WHERE lid = '$member_lid' ;");

                    if ($getAddressGroupsResults->num_rows != 0) {
                        while ($data = $getAddressGroupsResults->fetch_assoc()) {
                            $member_lid_group = $data['member_lid'];
                            $table_name_group = $data['table_name'];

                            if(preg_match("/groups/i", $table_name_group)){

                                $rule_id_return = getIdsToFiltersToolsEqualContainsRecursive($member_lid_group, $table_name_group, $search, $rule_id, $operator);

                                if ($rule_id_return != "") {
                                    $match_to_filter_rule_id = $rule_id;
                                }
                            }
                            else{
                                $getAddressResultsToNetwork = $projectdb->query("SELECT id, ipaddress, cidr FROM $table_name_group WHERE id = '$member_lid_group' AND type = 'ip-netmask' ;");
                                if ($getAddressResultsToNetwork->num_rows != 0) {
                                    $data = $getAddressResultsToNetwork->fetch_assoc();
                                    $ipaddress = $data['ipaddress'];
                                    $is_in_network = netMatchV4($search, $ipaddress);
                                    //echo "2.Is in network: " .$is_in_network. "\n";
                                    if ($is_in_network == 1) {
                                        $match_to_filter_rule_id = $rule_id;
                                    }
                                }
                            }
                        }
                    }
                }
                else {
                    $getAddressResultsToNetwork = $projectdb->query("SELECT id, ipaddress, cidr FROM $table_name WHERE id = '$member_lid' AND type = 'ip-netmask' ;");
                    if ($getAddressResultsToNetwork->num_rows != 0) {
                        $data = $getAddressResultsToNetwork->fetch_assoc();
                        $ipaddress = $data['ipaddress'];
                        $is_in_network = netMatchV4($search, $ipaddress);
                        //echo "3.Is in network: " .$is_in_network. "\n";
                        if ($is_in_network == 1) {
                            $match_to_filter_rule_id = $rule_id;
                        }
                    }
                }
            }
            else {

                if(preg_match("/groups/i", $table_name)){

                    $table_name_sin_id = str_replace("_id", "", $table_name);
                    $getAddressGroupsResults = $projectdb->query("SELECT id, member_lid, table_name FROM $table_name_sin_id WHERE lid = '$member_lid' ;");

                    if ($getAddressGroupsResults->num_rows != 0) {
                        while ($data = $getAddressGroupsResults->fetch_assoc()) {
                            $member_lid_group = $data['member_lid'];
                            $table_name_group = $data['table_name'];

                            if (preg_match("/groups/i", $table_name_group)) {
                                $rule_id_return = getIdsToFiltersToolsEqualContainsRecursive($member_lid_group, $table_name_group, $search, $rule_id, $operator);

                                if ($rule_id_return != "") {
                                    $match_to_filter_rule_id = $rule_id;
                                }
                            }
                            else{
                                // Name or IP only
                                $consulta = " AND (name = '$search' OR ipaddress = '$search') ";

                                $getAddressResults = $projectdb->query("SELECT id FROM $table_name_group WHERE id = '$member_lid_group' $consulta ;");

                                if ($getAddressResults->num_rows != 0) {
                                    $match_to_filter_rule_id = $rule_id;
                                }
                            }
                        }
                    }
                }
                else{
                    // Name or IP only
                    $consulta = " AND (name = '$search' OR ipaddress = '$search') ";

                    $getAddressResults = $projectdb->query("SELECT id FROM $table_name WHERE id = '$member_lid' $consulta ;");

                    if ($getAddressResults->num_rows != 0) {
                        $match_to_filter_rule_id = $rule_id;
                    }
                }
            }
        }
    }

    if ($is_network == 0) {

        $getAddressResults = $projectdb->query("SELECT id FROM $table_name WHERE id = '$member_lid' $consulta ;");

        //echo "Query2: SELECT id FROM $table_name WHERE id = '$member_lid' $consulta ;\n";

        if ($getAddressResults->num_rows != 0) {
            $match_to_filter_rule_id = $rule_id;
        }

        if (preg_match("/groups/i", $table_name)) {
            // Mirar si el grupo contiene el filtro buscado:
            $getAddressGroupsIdResults = $projectdb->query("SELECT id FROM $table_name WHERE id = '$member_lid' $consulta;");

            if ($getAddressGroupsIdResults->num_rows != 0) {
                $match_to_filter_rule_id = $rule_id;
            }

            // Sólo hacer si es recursivo
            if (preg_match("/recursive/i", $operator)) {
                // Mirar ahora en los miembros de cada grupo si contiene el filtro
                $table_name_sin_id = str_replace("_id", "", $table_name);

                $getAddressGroupsResults = $projectdb->query("SELECT id, member_lid, table_name FROM $table_name_sin_id WHERE lid = '$member_lid' ;");

                if ($getAddressGroupsResults->num_rows != 0) {

                    while ($data = $getAddressGroupsResults->fetch_assoc()) {

                        $member_lid_group = $data['member_lid'];
                        $table_name_group = $data['table_name'];

                        $rule_id_return = getIdsToFiltersToolsEqualContainsRecursive($member_lid_group, $table_name_group, $search, $rule_id, $operator);

                        if ($rule_id_return != "") {
                            $match_to_filter_rule_id = $rule_id;
                        }
                    }
                }
            }
        }
    }
    //echo "HA HECHO MATCH: " .$match_to_filter_rule_id. "\n";
    return $match_to_filter_rule_id;
}


function getResultsFilters(STRING $projectName, ARRAY $params){

    global $projectdb;
    global $app;

    $projectdb = selectDatabase($projectName);

    $user = $app->container->sentinel->getUser();
    $user_id = $user->id;

    $myData = array();
    $count = 0;

    $start = mysqli_real_escape_string($projectdb, $params['start']);
    $limit = mysqli_real_escape_string($projectdb, $params['limit']);
    $source = mysqli_real_escape_string($projectdb, $params['source']);

    $getRFTotal = $projectdb->query("SELECT member_lid, table_name, table_name_name, image FROM tools_results 
                                WHERE source = '$source' AND user_id = '$user_id';");

    $getRF = $projectdb->query("SELECT member_lid, table_name, table_name_name, image FROM tools_results 
                                WHERE source = '$source' AND user_id = '$user_id' LIMIT $start, $limit;");

    //echo "SELECT member_lid, table_name, table_name_name, image FROM tools_results
    //                            WHERE source = '$source' AND user_id = '$user_id' LIMIT $start, $limit;";

    $foundObjects = array();
    if ($getRF->num_rows > 0){
        while($dataRF = $getRF->fetch_assoc()){
            //$myData[]= $row;
            $member_lid = $dataRF['member_lid'];
            if($member_lid != ""){
                $table_name = $dataRF['table_name'];
                $table_name_name = $dataRF['table_name_name'];
                $image = $dataRF['image'];

                if($table_name == "default_applications"){
                    $getResults = $projectdb->query("SELECT id AS member_lid, name, '$table_name' AS table_name, '$table_name_name' AS table_name_name, '' as vsys, used, '' AS value   
                            FROM $table_name WHERE id IN ($member_lid) ORDER BY name;");
                }
                elseif($table_name == "virtual_systems"){
                    $getResults = $projectdb->query("SELECT id AS member_lid, name, '$table_name' AS table_name, '$table_name_name' AS table_name_name, name as vsys, '2' as used, '' AS value   
                        FROM $table_name WHERE id IN ($member_lid) ORDER BY name;");
                }
                elseif(($table_name == "address") || ($table_name == "address_groups_id") || ($table_name == "services") || ($table_name == "services_groups_id")
                    || ($table_name == "applications") || ($table_name == "applications_groups_id") || ($table_name == "applications_filters")){

                    if($table_name == "address"){
                        $getResults = $projectdb->query("SELECT id AS member_lid, name, '$table_name' AS table_name, '$table_name_name' AS table_name_name, vsys, used, CONCAT(ipaddress, '/',if(cidr='',32,cidr)) AS value
                            FROM $table_name WHERE id IN ($member_lid) ORDER BY name;");
                        //echo "SELECT id AS member_lid, name, '$table_name' AS table_name, '$table_name_name' AS table_name_name, vsys, used, CONCAT(ipaddress, '/',if(cidr='',32,cidr)) as value
                        //    FROM $table_name WHERE id IN ($member_lid) ORDER BY name;\n";
                    }
                    elseif($table_name == "services"){
                        $getResults = $projectdb->query("SELECT id AS member_lid, name, '$table_name' AS table_name, '$table_name_name' AS table_name_name, vsys, used, CONCAT(protocol, '/',dport) AS value
                            FROM $table_name WHERE id IN ($member_lid) ORDER BY name;");
                    }
                    else{
                        $getResults = $projectdb->query("SELECT id AS member_lid, name, '$table_name' AS table_name, '$table_name_name' AS table_name_name, vsys, used, '' AS value
                            FROM $table_name WHERE id IN ($member_lid) ORDER BY name;");
                    }

                    //$getResults = $projectdb->query("SELECT id AS member_lid, name, '$table_name' AS table_name, '$table_name_name' AS table_name_name, vsys, used
                    //    FROM $table_name WHERE id IN ($member_lid) ORDER BY name;");
                    //echo "SELECT id AS member_lid, name, '$table_name' AS table_name, '$table_name_name' AS table_name_name, vsys, used
                    //FROM $table_name WHERE id IN ($member_lid) ORDER BY name;\n";
                }
                elseif(($table_name == "security_rules") || ($table_name == "nat_rules") ){
                    $getResults = $projectdb->query("SELECT id AS member_lid, name, '$table_name' AS table_name, '$table_name_name' AS table_name_name, vsys, disabled as used, '' AS value  
                    FROM $table_name WHERE id IN ($member_lid) ORDER BY name;");
                }
                else{
                    $getResults = $projectdb->query("SELECT id AS member_lid, name, '$table_name' AS table_name, '$table_name_name' AS table_name_name, vsys, '2' as used, '' AS value 
                    FROM $table_name WHERE id IN ($member_lid) ORDER BY name;");
                }

                if ($getResults->num_rows > 0){
                    while($row = $getResults->fetch_assoc()){
                        $uniqueID = $row['table_name'].$row['member_lid'];
                        if(!in_array($uniqueID, $foundObjects)) {
                            $row['table_name_name'] = "<img style='vertical-align: middle;' src=$image> " . $row['table_name_name'];
                            $myData[] = $row;
                            $foundObjects[] = $uniqueID;
                        }
                    }
                }
            }
        }
    }

    $message = array();
    $message['code'] = true;
    $message['count'] = $getRFTotal->num_rows;
    $message['msg'] = $myData;

    return $message;

}


function existFilters(STRING $projectName, STRING $scope){

    global $projectdb;
    $projectdb = selectDatabase($projectName);

    $getEF = $projectdb->query("SELECT id FROM tools_sql WHERE filter_id != '';");
    if ($getEF->num_rows == 0){
        $code = "false";
    }else{
        $code = "true";
    }

    $message['code'] = $code;
    return $message;

}


function checkExistFilterAndRemove(STRING $projectName, $table_name){

    global $projectdb;
    $projectdb = selectDatabase($projectName);

    $getRF = $projectdb->query("SELECT tf.tools_where_columns_id, tr.filter_id, tr.tools_sql_id
      FROM tools_results tr, tools_filters tf 
      WHERE table_name = '$table_name' 
      AND tr.filter_id = tf.id;");

    //echo "SELECT tf.tools_where_columns_id, tr.filter_id
    //  FROM tools_results tr, tools_filters tf
    //  WHERE table_name = '$table_name'
    //  AND tr.filter_id = tf.id;";

    if ($getRF->num_rows > 0) {
        while ($dataRF = $getRF->fetch_assoc()) {
            $tools_where_columns_id = $dataRF['tools_where_columns_id'];
            $filter_id = $dataRF['filter_id'];

            if (($tools_where_columns_id == "73") || ($tools_where_columns_id == "74")
                || ($tools_where_columns_id == "75") || ($tools_where_columns_id == "76")
                || ($tools_where_columns_id == "77") || ($tools_where_columns_id == "78")
                || ($tools_where_columns_id == "79") ){

                $query = "DELETE FROM tools_results WHERE filter_id = '$filter_id';";
                $projectdb->query($query);
                $query = "DELETE FROM tools_filters WHERE id = '$filter_id';";
                $projectdb->query($query);

                $getFilter = $projectdb->query("SELECT id, filter_id FROM tools_sql;");
                if ($getFilter->num_rows > 0) {
                    while($dataF = $getFilter->fetch_assoc()){
                        $id_sql = $dataF['id'];
                        $filter_id_old = explode(",", $dataF['filter_id']);
                        if (($key = array_search($filter_id, $filter_id_old)) !== false) {
                            unset($filter_id_old[$key]);
                            $projectdb->query("UPDATE tools_sql SET filter_id='" . implode(",", $filter_id_old) . "' WHERE id = '$id_sql'");
                            //echo "UPDATE tools_sql SET filter_id='" . implode(",", $filter_id_old) . "' WHERE id = '$id_sql'";
                        }
                    }
                }
            }
        }
    }
}


function checkExistFilter(STRING $projectName, $table_name){

    global $projectdb;
    $projectdb = selectDatabase($projectName);

    $filter_id = "";

    $getRF = $projectdb->query("SELECT tf.tools_where_columns_id, tr.filter_id, tr.tools_sql_id
      FROM tools_results tr, tools_filters tf 
      WHERE table_name = '$table_name' 
      AND tr.filter_id = tf.id
      GROUP BY tools_where_columns_id;");

    if ($getRF->num_rows > 0) {
        while ($dataRF = $getRF->fetch_assoc()) {
            $filter_id = $dataRF['filter_id'];
        }
    }
    return $filter_id;
}


function checkExistFilterFromWhereColumnsId(STRING $projectName, $tools_where_id, $tools_where_columns_id, $remove, $source){

    global $projectdb;
    global $app;

    $projectdb = selectDatabase($projectName);

    $user = $app->container->sentinel->getUser();
    $user_id = $user->id;

    $filter_id = "";

    $getRF = $projectdb->query("SELECT id FROM tools_filters  
      WHERE tools_where_id = '$tools_where_id'
      AND tools_where_columns_id = '$tools_where_columns_id' 
      AND source = '$source' AND user_id = '$user_id';");

    if ($getRF->num_rows > 0) {
        while ($dataRF = $getRF->fetch_assoc()) {
            $filter_id = $dataRF['id'];
            if($remove == "yes"){
                removeFilterId($projectName, $filter_id, $source, $user_id);
            }
        }
    }
    return $filter_id;
}


function checkExistFilterFromWhereId(STRING $projectName, $tools_where_id, $remove, $source){

    global $projectdb;
    global $app;

    $projectdb = selectDatabase($projectName);

    $user = $app->container->sentinel->getUser();
    $user_id = $user->id;

    $filter_id = "";

    $getRF = $projectdb->query("SELECT id FROM tools_filters  
      WHERE tools_where_id = '$tools_where_id'
      AND source = '$source' AND user_id = '$user_id';");

    if ($getRF->num_rows > 0) {
        while ($dataRF = $getRF->fetch_assoc()) {
            $filter_id = $dataRF['id'];
            if($remove == "yes"){
                removeFilterId($projectName, $filter_id, $source, $user_id);
            }
        }
    }
    return $filter_id;
}


function checkExistFilterMemberLidEmpty(STRING $projectName, $table_name){

    global $projectdb;
    $projectdb = selectDatabase($projectName);

    $filter_id = "";

    $getRF = $projectdb->query("SELECT tf.tools_where_columns_id, tr.filter_id, tr.tools_sql_id
      FROM tools_results tr, tools_filters tf 
      WHERE table_name = '$table_name' 
      AND member_lid = ''
      AND tr.filter_id = tf.id
      GROUP BY tools_where_columns_id;");

    //echo "SELECT tf.tools_where_columns_id, tr.filter_id
    //  FROM tools_results tr, tools_filters tf
    //  WHERE table_name = '$table_name'
    //  AND tr.filter_id = tf.id
    //  GROUP BY tools_where_columns_id;";

    if ($getRF->num_rows > 0) {
        while ($dataRF = $getRF->fetch_assoc()) {
            //$tools_where_columns_id = $dataRF['tools_where_columns_id'];
            $filter_id = $dataRF['filter_id'];
        }
    }
    return $filter_id;
}


function removeFilterIdwithTableName(STRING $projectName, $table_name)
{
    global $projectdb;

    $projectdb = selectDatabase($projectName);

    $getRF = $projectdb->query("SELECT tf.tools_where_columns_id, tr.filter_id, tr.tools_sql_id
      FROM tools_results tr, tools_filters tf 
      WHERE table_name = '$table_name' 
      AND tr.filter_id = tf.id;");

    if ($getRF->num_rows > 0) {
        while ($dataRF = $getRF->fetch_assoc()) {
            $tools_where_columns_id = $dataRF['tools_where_columns_id'];
            $filter_id = $dataRF['filter_id'];

            $query = "DELETE FROM tools_results WHERE filter_id = '$filter_id';";
            $projectdb->query($query);
            $query = "DELETE FROM tools_filters WHERE id = '$filter_id';";
            $projectdb->query($query);

            $getFilter = $projectdb->query("SELECT id, filter_id FROM tools_sql;");
            if ($getFilter->num_rows > 0) {
                while($dataF = $getFilter->fetch_assoc()){
                    $id_sql = $dataF['id'];
                    $filter_id_old = explode(",", $dataF['filter_id']);
                    if (($key = array_search($filter_id, $filter_id_old)) !== false) {
                        unset($filter_id_old[$key]);
                        $projectdb->query("UPDATE tools_sql SET filter_id='" . implode(",", $filter_id_old) . "' WHERE id = '$id_sql'");
                        //echo "UPDATE tools_sql SET filter_id='" . implode(",", $filter_id_old) . "' WHERE id = '$id_sql'";
                    }
                }
            }
        }
    }
}


function removeFilterId(STRING $projectName, $filter_id, $source, $user_id)
{
    global $projectdb;

    $projectdb = selectDatabase($projectName);

    $query = "DELETE FROM tools_results WHERE filter_id = '$filter_id';";
    $projectdb->query($query);
    $query = "DELETE FROM tools_filters WHERE id = '$filter_id';";
    $projectdb->query($query);

    $getFilter = $projectdb->query("SELECT id, filter_id FROM tools_sql WHERE source = '$source' AND user_id = '$user_id';");
    if ($getFilter->num_rows > 0) {
        while($dataF = $getFilter->fetch_assoc()){
            $id_sql = $dataF['id'];
            $filter_id_old = explode(",", $dataF['filter_id']);
            if (($key = array_search($filter_id, $filter_id_old)) !== false) {
                unset($filter_id_old[$key]);
                $projectdb->query("UPDATE tools_sql SET filter_id='" . implode(",", $filter_id_old) . "' WHERE id = '$id_sql'");
                //echo "UPDATE tools_sql SET filter_id='" . implode(",", $filter_id_old) . "' WHERE id = '$id_sql'";
            }
        }
    }


}


function generateQueryConsolidation(STRING $projectName, $table_name, $query, $source, $id_cons){

    global $projectdb;

    $projectdb = selectDatabase($projectName);
    $member_lid = array();

    if($id_cons != ""){
        //$getConsolidationTools = $projectdb->query("SELECT rules_lid FROM hash_rules WHERE visible = '1' AND table_name = '$table_name' AND source = '$source';");
        $getConsolidationTools = $projectdb->query("SELECT rules_lid FROM hash_rules WHERE id IN ($id_cons);");
    }
    else{
        $getConsolidationTools = $projectdb->query("SELECT rules_lid FROM hash_rules WHERE id IN ('');");
    }
    
    if ($getConsolidationTools->num_rows > 0) {

        while ($dataRT = $getConsolidationTools->fetch_assoc()){
            if($dataRT['rules_lid'] != ""){
                $member_lid[] = $dataRT['rules_lid'];
            }else{
                $member_lid[] = "";
            }
        }

        if(count($member_lid) > 0){
            $member_lid = implode(",", $member_lid);
            if (preg_match("/ WHERE /i", $query)) {
                $query = $query . " AND id IN ($member_lid) ";
            }
            else {
                $query = $query . " WHERE id IN ($member_lid) ";
            }
        }
        else{
            if (preg_match("/WHERE/", $query)) {
                $query = $query . " AND id IN ('') ";
            }
            else{
                $query = $query . " WHERE id IN ('') ";
            }
        }
    }

    return $query;

}


function generateQueryFilters(STRING $projectName, $table_name, $type, $query, $source){

    global $projectdb;
    global $app;

    $projectdb = selectDatabase($projectName);

    $user = $app->container->sentinel->getUser();
    $user_id = $user->id;

    $orderby = "";
    $member_lid = array();

    if($type != "") {
        $sql_type = " AND type = '$type' ";
    }else{
        $sql_type = "";
    }

    $getResultsTools = $projectdb->query("SELECT member_lid FROM tools_results WHERE table_name = '$table_name' $sql_type AND source = '$source' AND user_id = '$user_id';");

    if ($getResultsTools->num_rows > 0) {

        while ($dataRT = $getResultsTools->fetch_assoc()){
            if($dataRT['member_lid'] != ""){
                $member_lid[] = $dataRT['member_lid'];
            }
        }

        if(($table_name == "address") || ($table_name == "address_groups_id") || ($table_name == "services") || ($table_name == "services_groups_id")
            || ($table_name == "applications") || ($table_name == "default_applications") || ($table_name == "applications_filters") || ($table_name == "applications_groups_id")
            || ($table_name == "regions") || ($table_name == "tag") ){

            if(count($member_lid) > 0){
                if (preg_match("/ WHERE /i", $query)) {
                    $query = $query . " AND a.id IN (" . implode(',',$member_lid) . ") ";
                }
                else {
                    $query = $query . " WHERE a.id IN (" . implode(',',$member_lid) . ") ";
                }
                $orderby = " ORDER BY FIELD (a.id, " . implode(",", $member_lid) . ") ";
            }
            else{
                if (preg_match("/WHERE/", $query)) {
                    $query = $query . " AND a.id IN ('') ";
                }
                else{
                    $query = $query . " WHERE a.id IN ('') ";
                }
            }
        }
        else{
            if(count($member_lid) > 0){
                if (preg_match("/ WHERE /i", $query)) {
                    $query = $query . " AND id IN (" . implode(',',$member_lid) . ") ";
                }
                else {
                    $query = $query . " WHERE id IN (" . implode(',',$member_lid) . ") ";
                }
                $orderby = " ORDER BY FIELD (id, " . implode(",", $member_lid) . ") ";
            }
            else{
                if (preg_match("/WHERE/", $query)) {
                    $query = $query . " AND id IN ('') ";
                }
                else{
                    $query = $query . " WHERE id IN ('') ";
                }
            }
        }

    }
    else{
        if(($table_name == "address") || ($table_name == "address_groups_id") || ($table_name == "services") || ($table_name == "services_groups_id")
            || ($table_name == "applications") || ($table_name == "default_applications") || ($table_name == "applications_filters") || ($table_name == "applications_groups_id")
            || ($table_name == "regions") ){

            $orderby = " ORDER BY a.name ASC ";
        }
        elseif($table_name == "tag"){

            if (!preg_match("/WHERE/", $query)) {
                $query = " WHERE 1=1 ";
            }
            $orderby = " ORDER BY a.name ASC ";
        }

    }

    return array($query, $orderby);

}


function getInvalidNames(STRING $projectName, $table_name, $vsys, $source):array{
    global $projectdb;
    $ids_results_in = array();

    $projectdb = selectDatabase($projectName);

    require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
    $vsys_query = prepareVsysQuery($projectdb, $vsys, $source);

    $version = calcVersion($source);

    switch($table_name){
        case "address":
        case "address_groups_id":
        case "services":
        case "services_groups_id":
        case "applications":
        case "applications_groups_id":
            $max = 63;
            $field = 'name';
            break;

        case "security_rules":
        case "nat_rules":
            if($version >= 8.1) $max = 31;
            else                $max = 31;
            $field = 'name';
            break;
        default:
            $max = 63;
            break;
    }

    $query = "SELECT id FROM $table_name a WHERE source = '$source' $vsys_query  AND CHAR_LENGTH($field) > $max;";
    $getIdResults = $projectdb->query($query);

    if ($getIdResults->num_rows != 0) {
        while ($data = $getIdResults->fetch_assoc()) {
            $ids_results_in[] = $data['id'];
        }
    }

    return $ids_results_in;
}

function getNatTypes(STRING $projectName, STRING $type, $source, $vsys):array{
    global $projectdb;
    $ids_results_in = array();

    $projectdb = selectDatabase($projectName);

    require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
    $vsys_query = prepareVsysQuery($projectdb, $vsys, $source);

    $type = strtolower($type);
    switch(strtolower($type)){
        case 'static-ip':
        case 'dynamic-ip':
        case 'dynamic-ip-and-port':
            $query = "SELECT id FROM nat_rules a WHERE source = '$source' $vsys_query  AND tp_sat_type = '$type';";
            break;

        case 'none':
            $query = "SELECT id FROM nat_rules a WHERE source = '$source' $vsys_query  AND tp_sat_type = 'None' OR tp_sat_type = '';";
            break;

        case 'bidirectional':
            $query = "SELECT id FROM nat_rules a WHERE source = '$source' $vsys_query  AND tp_sat_bidirectional=1;";
            break;

        case 'destination-address-translate':
            $query = "SELECT id FROM nat_rules a WHERE source = '$source' $vsys_query  AND is_dat=1;";
            break;

        default:
            $query = "SELECT id FROM nat_rules a WHERE source = '$source' $vsys_query  AND tp_sat_type = '$type';";
            break;
    }

    //echo "Query: " .$query. "\n";
    $getIdResults = $projectdb->query($query);

    if ($getIdResults->num_rows != 0) {
        while ($data = $getIdResults->fetch_assoc()) {
            $ids_results_in[] = $data['id'];
        }
    }

    return $ids_results_in;

}

function getNatStatic(STRING $projectName, $source, $vsys):array{
    return getNatTypes($projectName, 'static-ip', $source, $vsys);
}

function getNatNoNat(STRING $projectName, $source, $vsys):array{
    return getNatTypes($projectName, 'None', $source, $vsys);
}

function getNatDynamicIp(STRING $projectName, $source, $vsys):array{
    return getNatTypes($projectName, 'dynamic-ip', $source, $vsys);
}

function getNatDynamicIpPort(STRING $projectName, $source, $vsys):array{
    return getNatTypes($projectName, 'dynamic-ip-and-port', $source, $vsys);
}

function getRulesWithUsers($table_name, $vsys, $source){

    global $projectdb;
    $ids_results_in = array();

    require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
    $vsys_query = prepareVsysQuery($projectdb, $vsys, $source);

    $query = "SELECT sru.rule_lid FROM security_rules_usr sru, security_rules sr WHERE sr.id = sru.rule_lid AND sr.source = '$source'  ;";

    $getIdResults = $projectdb->query($query);
    //echo "Rules with Users: " .$query."\n";

    if ($getIdResults->num_rows != 0) {
        while ($data = $getIdResults->fetch_assoc()) {
            $ids_results_in[] = $data['rule_lid'];
        }
    }

    return $ids_results_in;

}

function getRulesLayerX($table_name, $vsys, $source, $layer){
    global $projectdb;
    $ids_results_in = array();

    require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
    $vsys_query = prepareVsysQuery($projectdb, $vsys, $source);

    $query = "SELECT id FROM security_rules WHERE layer=$layer AND source = '$source' $vsys_query;";

    $getIdResults = $projectdb->query($query);


    if ($getIdResults->num_rows != 0) {
        while ($data = $getIdResults->fetch_assoc()) {
            $ids_results_in[] = $data['id'];
        }
    }

    return $ids_results_in;
}

function getRulesLayer4($table_name, $vsys, $source){
    return getRulesLayerX($table_name, $vsys, $source, 4);
}

function getRulesLayer7($table_name, $vsys, $source){
    return getRulesLayerX($table_name, $vsys, $source, 7);
}

function getRulesHits($table_name, $days, $vsys, $source){
    global $projectdb;
    $ids_results_in = array();

    switch($days){
        case 'last 1 days':
        case 'last 1 day':
        case '14':
            $period = 'INTERVAL 1 DAY';
            $days = 1;
            break;
        case 'last 1 week':
        case '15':
            $period = 'INTERVAL 7 DAY';
            $days = 7;
            break;
        case 'last 2 weeks':
        case '16':
            $period = 'INTERVAL 14 DAY';
            $days = 14;
            break;
        case 'last 1 month':
        case '17':
            $period = 'INTERVAL 30 DAY';
            $days = 30;
            break;
        case 'last 2 months':
        case '18':
            $period = 'INTERVAL 60 DAY';
            $days = 60;
            break;
        case 'last 6 months':
        case '19':
        default:
            $period = 'INTERVAL 180 DAY';
            $days = 180;
            break;
    }

    require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
    $vsys_query = prepareVsysQuery($projectdb, $vsys, $source);

    $query = "SELECT srh.rule_lid 
                FROM security_rules_hits srh, security_rules sr 
                WHERE sr.id = srh.rule_lid AND sr.source = '$source' AND
                      datediff(curdate(), hit_last)<$days;";
#                      hit_last BETWEEN CURDATE() - $period AND CURDATE() ;";
    //echo $query;

    $getIdResults = $projectdb->query($query);
    //echo "Rules with Users: " .$query."\n";

    if ($getIdResults->num_rows != 0) {
        while ($data = $getIdResults->fetch_assoc()) {
            $ids_results_in[] = $data['rule_lid'];
        }
    }

    return $ids_results_in;
}

function getRulesNoHits($table_name, $days, $vsys, $source){
    global $projectdb;
    $ids_results_in = array();

    switch($days){
        case 'last 1 days':
        case 'last 1 day':
        case '14':
            $period = 'INTERVAL 1 DAY';
            $days = 1;
            break;
        case 'last 1 week':
        case '15':
            $period = 'INTERVAL 7 DAY';
            $days = 7;
            break;
        case 'last 2 weeks':
        case '16':
            $period = 'INTERVAL 14 DAY';
            $days = 14;
            break;
        case 'last 1 month':
        case '17':
            $period = 'INTERVAL 30 DAY';
            $days = 30;
            break;
        case 'last 2 months':
        case '18':
            $period = 'INTERVAL 60 DAY';
            $days = 60;
            break;
        case 'last 6 months':
        case '19':
        default:
            $period = 'INTERVAL 180 DAY';
            $days = 180;
            break;
    }

    require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
    $vsys_query = prepareVsysQuery($projectdb, $vsys, $source);

    $query = "SELECT id as rule_lid FROM security_rules WHERE id NOT in (
                SELECT srh.rule_lid 
                FROM security_rules_hits srh, security_rules sr 
                WHERE sr.id = srh.rule_lid AND sr.source = '$source' AND
                      datediff(curdate(), hit_last)<$days);";


#                      hit_last BETWEEN CURDATE() - $period AND CURDATE() ;";
    //echo $query;

    $getIdResults = $projectdb->query($query);
    //echo "Rules with Users: " .$query."\n";

    if ($getIdResults->num_rows != 0) {
        while ($data = $getIdResults->fetch_assoc()) {
            $ids_results_in[] = $data['rule_lid'];
        }
    }

    return $ids_results_in;
}

/***
 *
 * Given one array of IPs, returns all the security rules that match this rules, so that would be affecting traffic from&to/both these IPs
 *
 * @param mysqli $connection
 * @param STRING $source
 * @param STRING $vsys
 * @param STRING $project
 * @param array $IPs
 */
function getMatchingSecRules(STRING $source, STRING $vsys, $vr, $templateID, array $IPs, string $section){
    require_once INC_ROOT.'/libs/shared.php';
    require_once INC_ROOT.'/libs/common/lib-rules.php';

    global $projectdb;

    switch ($section){
        case 'in source':
            $checInSrc=true;
            $checInDst=false;
            break;
        case 'in destination':
            $checInSrc=false;
            $checInDst=true;
            break;

        default:
            $checInSrc=true;
            $checInDst=true;
            break;
    }



    $memberAnyAddress = new MemberObject('', '','0.0.0.0', '0');
    $memberAnyService = new MemberObject('', '','0-65535', 'any');
    $membersToSearch = array();

    $ipMapping = getIPtoZoneRouteMapping($vsys, $source, $vr, $templateID);

    foreach($IPs as $key => $ip){
        $exploded = explode("/", $ip);
        $exploded[1] = isset($exploded[1])?$exploded[1]:'32';
        $membersToSearch[$key]['object'] = new MemberObject("","",$exploded[0], $exploded[1]);
        $membersToSearch[$key]['zone'] = getAutoZoneIP($ipMapping['ipv4'], $ip);
    }

    $vsyses = getVsyses($projectdb, $vsys, $source);

    $ids_results_in = [];

    foreach ($vsyses as $vsys) {
        $security_rules = loadInMemorySecRules($projectdb, $source, $vsys);
        foreach ($security_rules as $sec_rule_lid => $rule) {
            foreach ($membersToSearch as $key => &$member) {
                if ($checInSrc) {
//                $isZoneInFrom = isAinB_Zones($member['zone'], $security_rules[$sec_rule_lid]['from']);
//                if ($isZoneInFrom > 0) {
                    $isInSrc = isAinB([$member['object']], $security_rules[$sec_rule_lid]['src']);
                    if ($isInSrc) {
                        $member['src'][] = $sec_rule_lid;
                    }
//                }
                }

                if ($checInDst) {
//                $isZoneInTo = isAinB_Zones($member['zone'], $security_rules[$sec_rule_lid]['to']);
//                if ($isZoneInTo > 0) {
                    $isInDst = isAinB([$member['object']], $security_rules[$sec_rule_lid]['dst']);
                    if ($isInDst) {
                        $member['dst'][] = $sec_rule_lid;
                    }
//                }
                }
            }
        }

        foreach ($membersToSearch as $member) {
            if (isset($member['src'])) {
                $ids_results_in = arrayUnique(array_merge($ids_results_in, $member['src']));
            }
            if (isset($member['dst'])) {
                $ids_results_in = arrayUnique(array_merge($ids_results_in, $member['dst']));
            }
        }
    }

    return $ids_results_in;
}


/***
 *
 * Lists all the security rules that have address objects that are IPv6, either directyl consumed or as members in a group
 * @param STRING $source
 * @param STRING $vsys
 * @param $vr
 * @param $templateID
 * @param string $section
 * @return array
 */
function getSecRulesWithIPv6(STRING $source, STRING $vsys, $vr, $templateID, string $section){
//    require_once INC_ROOT.'/libs/shared.php';
    require_once INC_ROOT.'/libs/common/lib-rules.php';

    global $projectdb;

    switch ($section){
        case 'in source':
            $checInSrc=true;
            $checInDst=false;
            break;
        case 'in destination':
            $checInSrc=false;
            $checInDst=true;
            break;

        default:
            $checInSrc=true;
            $checInDst=true;
            break;
    }

    $vsyses = getVsyses($projectdb, $vsys, $source);

    $ids_results_in = [];

    foreach ($vsyses as $vsys) {
        $security_rules = loadInMemorySecRules($projectdb, $source, $vsys);
        foreach ($security_rules as $sec_rule_lid=>&$rule){
            if ($checInSrc) {
                foreach ($rule['src'] as $source_member) {
                    if (ip_version($source_member->value) === 'v6') {
                        $ids_results_in[] = $sec_rule_lid;
                        continue 2;
                    }
                }
            }
            if ($checInDst) {
                foreach ($rule['dst'] as $source_member) {
                    if (ip_version($source_member->value) === 'v6') {
                        $ids_results_in[] = $sec_rule_lid;
                        continue 2;
                    }
                }
            }
        }
    }

    return $ids_results_in;
}
