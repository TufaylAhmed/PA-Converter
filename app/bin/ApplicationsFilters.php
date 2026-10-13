<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 14/6/16 - 10:47
 */

//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

//User management control
require_once INC_ROOT.'/userManager/start.php';
include INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/libs/shared.php';

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
        break;
    case 'POST':
        $action     = (string)  (isset($_POST['action'])    ? $_POST['action'] : '');
        $type       = (string)  (isset($_POST['type'])      ? $_POST['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_POST['project'])   ? $_POST['project'] : '');
        $devicename = (string)  (isset($_POST['devicename'])? $_POST['devicename'] : '');
        $start      = (integer) (isset($_POST['start'])     ? $_POST['start'] : '');
        $limit      = (integer) (isset($_POST['limit'])     ? $_POST['limit'] : '');
        break;

    default:
        $action     = (string)  (isset($_POST['action'])    ? $_POST['action'] : '');
        $type       = (string)  (isset($_POST['type'])      ? $_POST['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_POST['project'])   ? $_POST['project'] : '');
        $devicename = (string)  (isset($_POST['devicename'])? $_POST['devicename'] : '');
        $start      = (integer) (isset($_POST['start'])     ? $_POST['start'] : '');
        $limit      = (integer) (isset($_POST['limit'])     ? $_POST['limit'] : '');
        break;
}

//$action = (string) (isset($_POST['action']) ? $_POST['action'] : $_GET['action']); // upload  / get  /
//$type = (string) (isset($_POST['type']) ? $_POST['type'] : $_GET['type']); // zip / xml / device
//$project = (string) (isset($_POST['project']) ? $_POST['project'] : $_GET['project']);
//$devicename = (string) (isset($_POST['devicename']) ? $_POST['devicename'] : $_GET['devicename']);
//$start = (integer) (isset($_POST['start']) ? $_POST['start'] : $_GET['start']);
//$limit = (integer) (isset($_POST['limit']) ? $_POST['limit'] : $_GET['limit']);

require_once INC_ROOT.'/libs/projectdb.php';
$projectdb = selectDatabase($project);

$action = $projectdb->real_escape_string($action);
$type = $projectdb->real_escape_string($type);
$project = $projectdb->real_escape_string($project);
$devicename = $projectdb->real_escape_string($devicename);
$start = $projectdb->real_escape_string($start);
$limit = $projectdb->real_escape_string($limit);

if ($action == "get") {
    
    $query = generate_query("objects");
    $conditions = generate_query_multitable("objects");
    
    if ($type == "filters") {
        switch($_SERVER['REQUEST_METHOD'])
        {
            case 'GET':
                $search                 = (string) (isset($_GET['search'])                 ? $_GET['search'] : '');
                $hide_shared            = (string) (isset($_GET['hide_shared_app'])        ? $_GET['hide_shared_app'] : '');
                $applications_filters   = (string) (isset($_GET['applications_filters'])   ? $_GET['applications_filters'] : '');
                break;
            case 'POST':
                $search                 = (string) (isset($_POST['search'])                 ? $_POST['search'] : '');
                $hide_shared            = (string) (isset($_POST['hide_shared_app'])        ? $_POST['hide_shared_app'] : '');
                $applications_filters   = (string) (isset($_POST['applications_filters'])   ? $_POST['applications_filters'] : '');
                break;
            default:
                $search                 = (string) (isset($_POST['search'])                 ? $_POST['search'] : '');
                $hide_shared            = (string) (isset($_POST['hide_shared_app'])        ? $_POST['hide_shared_app'] : '');
                $applications_filters   = (string) (isset($_POST['applications_filters'])   ? $_POST['applications_filters'] : '');
                break;
        }

        $search = $projectdb->real_escape_string($search);
        $hide_shared = $projectdb->real_escape_string($hide_shared);
        $applications_filters = $projectdb->real_escape_string($applications_filters);

        $sql_search = "";
        
        if ($search != "") {
            if (preg_match("/WHERE/", $query)) {
                $sql_search = " AND name LIKE '%$search%'";
            } else {
                $sql_search = " WHERE name LIKE '%$search%'";
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
        
        if ($applications_filters == "filter_duplicated_name") {

            $queryAll = "SELECT * FROM applications_filters a $conditions GROUP BY BINARY name HAVING count(*) > 1 ";
            $getAll = $projectdb->query($queryAll);
            $count = $getAll->num_rows;
            if ($getAll->num_rows > 0) {
                $names = array();
                while ($getLimitData = $getAll->fetch_assoc()) {
                    $name_int = $getLimitData['name'];
                    $names[] = "'$name_int'";
                }

                if (preg_match("/WHERE/", $conditions)) {
                    $conditions .= " AND BINARY a.name IN (" . implode(",", $names) . ") ";
                }
                else{
                    $conditions .= " WHERE BINARY a.name IN (" . implode(",", $names) . ") ";
                }

                $getAll = $projectdb->query("SELECT count(*) as total FROM applications_filters a $conditions");
                $row = $getAll->fetch_assoc();
                $count = $row['total'];
                if ($count > 0) {
                    $getLimit = $projectdb->query("SELECT id as idx, source, devicegroup, vsys, name, category, subcategory, risk, technology, 'applications_filters' as table_name FROM applications_filters a $conditions ORDER BY name ASC LIMIT $start, $limit;");
                }
            }
            
        }
        elseif ($applications_filters == "filter_duplicated_name_value") {
            $sqlqueryAll ="SELECT * FROM applications_filters a $conditions GROUP BY BINARY name, category, subcategory, risk, technology, evasive_behavior, consume_big_bandwidth, prone_to_misuse, able_to_transfer_file, tunnel_other_application, used_by_malware, has_known_vulnerability, pervasive_use HAVING count(*)>1;";
            $getAll = $projectdb->query($sqlqueryAll);
            $count = $getAll->num_rows;
            if ($getAll->num_rows > 0) {
                $names = array();
                while ($getLimitData = $getAll->fetch_assoc()) {
                    $name_int = $getLimitData['name'];
                    $category = $getLimitData['category'];
                    $subcategory = $getLimitData['subcategory'];
                    $risk = $getLimitData['risk'];
                    $technology = $getLimitData['technology'];
                    $evasive_behavior = $getLimitData['evasive_behavior'];
                    $consume_big_bandwidth = $getLimitData['consume_big_bandwidth'];
                    $used_by_malware = $getLimitData['used_by_malware'];
                    $able_to_transfer_file = $getLimitData['able_to_transfer_file'];
                    $has_known_vulnerability = $getLimitData['has_known_vulnerability'];
                    $tunnel_other_application = $getLimitData['tunnel_other_application'];
                    $prone_to_misuse = $getLimitData['prone_to_misuse'];
                    $pervasive_use = $getLimitData['pervasive_use'];
                    
                    $names[] = "(category = '$category' AND subcategory = '$subcategory' AND risk = '$risk' AND technology = '$technology' AND evasive_behavior = '$evasive_behavior' AND consume_big_bandwidth = '$consume_big_bandwidth' AND used_by_malware = '$used_by_malware' AND able_to_transfer_file = '$able_to_transfer_file' AND has_known_vulnerability = '$has_known_vulnerability' AND tunnel_other_application = '$tunnel_other_application' AND prone_to_misuse = '$prone_to_misuse' AND pervasive_use = '$pervasive_use' AND BINARY name = '$name_int' )";
                }
                if (preg_match("/WHERE/", $conditions)) {
                    $conditions .= " AND (" . implode(" OR ", $names) . ") ";
                } else {
                    $conditions .= " WHERE (" . implode(" OR ", $names) . ") ";
                }

                $getAll = $projectdb->query("SELECT count(*) as total FROM applications_filters a $conditions");
                $row = $getAll->fetch_assoc();
                $count = $row['total'];
                if ($count > 0) {
                    $getLimit = $projectdb->query("SELECT id as idx, source, devicegroup, vsys, name, category, subcategory, risk, technology, evasive_behavior, consume_big_bandwidth, prone_to_misuse, able_to_transfer_file, tunnel_other_application, used_by_malware, has_known_vulnerability, pervasive_use, 'applications_filters' as table_name FROM applications_filters a $conditions ORDER BY name ASC LIMIT $start, $limit;");
                }
            }
            
        }
        else{
            
            $getAll = $projectdb->query("SELECT count(*) as total FROM applications_filters a $conditions");
            $row = $getAll->fetch_assoc();
            $count = $row['total'];
            if ($count > 0) {
                $getLimit = $projectdb->query("SELECT name, id, id as idx, devicegroup, vsys, source, 'applications_filters' as table_name, category, subcategory, technology, risk, evasive_behavior, consume_big_bandwidth, prone_to_misuse, able_to_transfer_file, tunnel_other_application, used_by_malware, has_known_vulnerability, pervasive_use FROM applications_filters a $conditions ORDER BY name ASC LIMIT $start, $limit;");
            }

        }
        if (isset($getLimit)) {
            $x = 0;
            if ($getLimit->num_rows>0){
                while ($data = $getLimit->fetch_object()) {
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
        $getAll = $projectdb->query("SELECT id as idx, name, 'applications' as table_name FROM applications $query "
                . " UNION SELECT id as idx, name, 'default_applications' as table_name FROM default_applications;");
        
        $count = $getAll->num_rows;
        while ($data = $getAll->fetch_object()) {
            $myData[] = $data;
        }
        if ($count == 0) {
            $myData = "";
        }
        echo '{"total":"' . $count . '","apps":' . json_encode($myData) . '}';
    } 
     
    elseif ($type == "total_category") {
        
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $app_filters_subcategory = $projectdb->real_escape_string((string) (isset($_POST['applications_filters_subcategory']) ? $_POST['applications_filters_subcategory'] : $_GET['applications_filters_subcategory']));
        $app_filters_technology = $projectdb->real_escape_string((string) (isset($_POST['applications_filters_technology']) ? $_POST['applications_filters_technology'] : $_GET['applications_filters_technology']));
        $app_filters_risk = $projectdb->real_escape_string((string) (isset($_POST['applications_filters_risk']) ? $_POST['applications_filters_risk'] : $_GET['applications_filters_risk']));
        $app_filters_charac = $projectdb->real_escape_string((string) (isset($_POST['applications_filters_charac']) ? $_POST['applications_filters_charac'] : $_GET['applications_filters_charac']));
        $app_filter_idx = $projectdb->real_escape_string((string) (isset($_POST['app_filter_idx']) ? $_POST['app_filter_idx'] : $_GET['app_filter_idx']));
        $app_filter_table_name = $projectdb->real_escape_string((string) (isset($_POST['app_filter_table_name']) ? $_POST['app_filter_table_name'] : $_GET['app_filter_table_name']));
        $is_first = $projectdb->real_escape_string((string) (isset($_POST['app_filters_is_first']) ? $_POST['app_filters_is_first'] : $_GET['app_filters_is_first']));
        
        $category = array();
        $array_cat = array();
        
        $sql_filters = "";
        $sql_filters_default = "";
        
        $category_select_a = array();
        $filters_category = array();

        require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
        $sql_vsys = prepareVsysQuery($projectdb, $vsys, $source);
        
        if($is_first == "1"){

            if(($app_filter_idx != "") && ($app_filter_table_name != "")){

                $getSelections = $projectdb->query("SELECT category FROM $app_filter_table_name WHERE id = '$app_filter_idx';");

                if($getSelections->num_rows > 0){
                    while ($dataSelect = $getSelections->fetch_assoc()) {
                        $category_select = $dataSelect['category'];
                    }
                }

                $category_select_a = explode(",", $category_select);
                foreach ($category_select_a as $cat){
                    $filters_category[] = " '$cat' ";
                }

                if($category_select != ""){

                    $app_filters_category = implode(",", $filters_category);
                    $sql_filters = $sql_filters . " AND category IN ($app_filters_category) ";

                    if (preg_match("/WHERE/", $sql_filters_default)) {
                        $sql_filters_default = $sql_filters_default . " AND category IN ($app_filters_category) ";
                    } else {
                        $sql_filters_default = " WHERE category IN ($app_filters_category) ";
                    }

                }
                else{
                    $is_first = 0;
                }
            }
        }
        
        if($app_filters_subcategory != ""){
            
            $sql_filters = $sql_filters . " AND subcategory IN ($app_filters_subcategory) ";
            
            if (preg_match("/WHERE/", $sql_filters_default)) {
                $sql_filters_default = $sql_filters_default . " AND subcategory IN ($app_filters_subcategory) ";
            } else {
                $sql_filters_default = " WHERE subcategory IN ($app_filters_subcategory) ";
            }
            
        }
        
        if($app_filters_technology != ""){
            
            $sql_filters = $sql_filters . " AND technology IN ($app_filters_technology) ";
            
            if (preg_match("/WHERE/", $sql_filters_default)) {
                $sql_filters_default = $sql_filters_default . " AND technology IN ($app_filters_technology) ";
            } else {
                $sql_filters_default = " WHERE technology IN ($app_filters_technology) ";
            }
            
        }
        
        if($app_filters_risk != ""){
            
            $sql_filters = $sql_filters . " AND risk IN ($app_filters_risk) ";
            
            if (preg_match("/WHERE/", $sql_filters_default)) {
                $sql_filters_default = $sql_filters_default . " AND risk IN ($app_filters_risk) ";
            } else {
                $sql_filters_default = " WHERE risk IN ($app_filters_risk) ";
            }
            
        }
        
        if($app_filters_charac != ""){
            
            $app_filters_charac_exp = explode(",", $app_filters_charac);
            
            foreach($app_filters_charac_exp as $campo){
                //echo "El campo es: " . $campo . "\n";
                if (preg_match("/WHERE/", $query)) {
                    $sql_filters = $sql_filters . " AND $campo = 'yes' ";
                } else {
                    $sql_filters = " WHERE $campo = 'yes' ";
                }
                if (preg_match("/WHERE/", $sql_filters_default)) {
                    $sql_filters_default = $sql_filters_default . " AND $campo = 'yes' ";
                } else {
                    $sql_filters_default = " WHERE $campo = 'yes' ";
                }
            }
            
        }
        
        $getCat = $projectdb->query("SELECT DISTINCT(category) FROM default_applications $sql_filters_default;");
        
        if($getCat->num_rows > 0){
            while ($dataCat = $getCat->fetch_assoc()) {
                if($dataCat['category'] != ""){
                    $category[] = $dataCat['category'];
                }
            }
        }
        
        $getCat2 = $projectdb->query("SELECT DISTINCT(category) FROM applications WHERE source = '$source' $sql_vsys $sql_filters;");
        if($getCat2->num_rows > 0){
            while ($dataCat2 = $getCat2->fetch_assoc()) {
                $cat = $dataCat2['category'];
                if(!in_array($cat, $category)){
                    $category[] = $dataCat2['category'];
                }
            }
        }

        $total = 0;
        $total_all = 0;
        //$i = 1;
        foreach ($category as $key=>$value){
            
            $getId = $projectdb->query("SELECT id FROM category WHERE name = '$value' ;");
            $dataId = $getId->fetch_assoc();
            $id = $dataId['id'];
            
            $getTotalAppCat = $projectdb->query("SELECT id FROM default_applications WHERE category = '$value' $sql_filters;");
            $count_app_x_cat = $getTotalAppCat->num_rows;
            
            $getTotalAppCat2 = $projectdb->query("SELECT id FROM applications WHERE category = '$value' AND source = '$source' $sql_vsys $sql_filters;");
            $count_app_x_cat2 = $getTotalAppCat2->num_rows;
            
            $total = $count_app_x_cat + $count_app_x_cat2;
            
            $total_all += $total;
            
            $array_cat[] = '{ "id":"'.$id.'", "category":"'.$value.'", "total":"'.$total.'" , "is_first":"'.$is_first.'"}';
            
            //$i ++;
        }
        
        echo '{"total":"' . $total_all . '","total_category":['.implode(",", $array_cat).']}';
        
    } 
    elseif ($type == "total_subcategory") {
        
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $app_filters_category = $projectdb->real_escape_string((string) (isset($_POST['applications_filters_category']) ? $_POST['applications_filters_category'] : $_GET['applications_filters_category']));

        $app_filters_technology = $projectdb->real_escape_string((string) (isset($_POST['applications_filters_technology']) ? $_POST['applications_filters_technology'] : $_GET['applications_filters_technology']));
        $app_filters_risk = $projectdb->real_escape_string((string) (isset($_POST['applications_filters_risk']) ? $_POST['applications_filters_risk'] : $_GET['applications_filters_risk']));
        $app_filters_charac = $projectdb->real_escape_string((string) (isset($_POST['applications_filters_charac']) ? $_POST['applications_filters_charac'] : $_GET['applications_filters_charac']));
        
        $app_filter_idx = $projectdb->real_escape_string((string) (isset($_POST['app_filter_idx']) ? $_POST['app_filter_idx'] : $_GET['app_filter_idx']));
        $app_filter_table_name = $projectdb->real_escape_string((string) (isset($_POST['app_filter_table_name']) ? $_POST['app_filter_table_name'] : $_GET['app_filter_table_name']));
        $is_first = $projectdb->real_escape_string((string) (isset($_POST['app_filters_is_first']) ? $_POST['app_filters_is_first'] : $_GET['app_filters_is_first']));
        
        $subcategory = array();
        $array_subcat = array();
        
        $sql_filters = "";
        $sql_filters_default = "";
        
        $subcategory_select_a = array();
        $filters_subcategory = array();

        require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
        $sql_vsys = prepareVsysQuery($projectdb, $vsys, $source);
        
        if($is_first == "1"){

            if(($app_filter_idx != "") && ($app_filter_table_name != "")){

                $getSelections = $projectdb->query("SELECT subcategory FROM $app_filter_table_name WHERE id = '$app_filter_idx';");

                if($getSelections->num_rows > 0){
                    while ($dataSelect = $getSelections->fetch_assoc()) {
                        $subcategory_select = $dataSelect['subcategory'];
                    }
                }

                $subcategory_select_a = explode(",", $subcategory_select);
                foreach ($subcategory_select_a as $subcat){
                    $filters_subcategory[] = " '$subcat' ";
                }

                if($subcategory_select != ""){

                    $app_filters_subcategory = implode(",", $filters_subcategory);
                    $sql_filters = $sql_filters . " AND subcategory IN ($app_filters_subcategory) ";

                    if (preg_match("/WHERE/", $sql_filters_default)) {
                        $sql_filters_default = $sql_filters_default . " AND subcategory IN ($app_filters_subcategory) ";
                    } else {
                        $sql_filters_default = " WHERE subcategory IN ($app_filters_subcategory) ";
                    }

                }
                else{
                    $is_first = 0;
                }
            }
        }
        
        if($app_filters_category != ""){
            
            $sql_filters = $sql_filters . " AND category IN ($app_filters_category) ";
            
            if (preg_match("/WHERE/", $sql_filters_default)) {
                $sql_filters_default = $sql_filters_default . " AND category IN ($app_filters_category) ";
            } else {
                $sql_filters_default = " WHERE category IN ($app_filters_category) ";
            }
            
        }
        
        if($app_filters_technology != ""){
            
            $sql_filters = $sql_filters . " AND technology IN ($app_filters_technology) ";
            
            if (preg_match("/WHERE/", $sql_filters_default)) {
                $sql_filters_default = $sql_filters_default . " AND technology IN ($app_filters_technology) ";
            } else {
                $sql_filters_default = " WHERE technology IN ($app_filters_technology) ";
            }
            
        }
        
        if($app_filters_risk != ""){
            
            $sql_filters = $sql_filters . " AND risk IN ($app_filters_risk) ";
            
            if (preg_match("/WHERE/", $sql_filters_default)) {
                $sql_filters_default = $sql_filters_default . " AND risk IN ($app_filters_risk) ";
            } else {
                $sql_filters_default = " WHERE risk IN ($app_filters_risk) ";
            }
            
        }
        
        if($app_filters_charac != ""){
            
            $app_filters_charac_exp = explode(",", $app_filters_charac);
            
            foreach($app_filters_charac_exp as $campo){
                //echo "El campo es: " . $campo . "\n";
                if (preg_match("/WHERE/", $query)) {
                    $sql_filters = $sql_filters . " AND $campo = 'yes' ";
                } else {
                    $sql_filters = " WHERE $campo = 'yes' ";
                }
                if (preg_match("/WHERE/", $sql_filters_default)) {
                    $sql_filters_default = $sql_filters_default . " AND $campo = 'yes' ";
                } else {
                    $sql_filters_default = " WHERE $campo = 'yes' ";
                }
            }
            
        }
        
        $getCat = $projectdb->query("SELECT DISTINCT(subcategory) FROM default_applications $sql_filters_default;");
        
        if($getCat->num_rows > 0){
            while ($dataCat = $getCat->fetch_assoc()) {
                if($dataCat['subcategory'] != ""){
                    $subcategory[] = $dataCat['subcategory'];
                }
            }
        }
        
        $getCat2 = $projectdb->query("SELECT DISTINCT(subcategory) FROM applications WHERE source = '$source' $sql_vsys $sql_filters;");
        if($getCat2->num_rows > 0){
            while ($dataCat2 = $getCat2->fetch_assoc()) {
                $cat = $dataCat2['subcategory'];
                if(!in_array($cat, $subcategory)){
                    $subcategory[] = $dataCat2['subcategory'];
                }
            }
        }
        
        $total = 0;
        $total_all = 0;
        
        foreach ($subcategory as $key=>$value){
            
            $getId = $projectdb->query("SELECT id FROM subcategory WHERE name = '$value' ;");
            $dataId = $getId->fetch_assoc();
            $id = $dataId['id'];
            
            $getTotalAppCat = $projectdb->query("SELECT id FROM default_applications WHERE subcategory = '$value' $sql_filters;");
            $count_app_x_cat = $getTotalAppCat->num_rows;
            
            $getTotalAppCat2 = $projectdb->query("SELECT id FROM applications WHERE subcategory = '$value' AND source = '$source' $sql_vsys $sql_filters;");
            $count_app_x_cat2 = $getTotalAppCat2->num_rows;
            
            $total = $count_app_x_cat + $count_app_x_cat2;
            
            $total_all += $total;
            
            $array_subcat[] = '{ "id":"'.$id.'", "subcategory":"'.$value.'", "total":"'.$total.'", "is_first":"'.$is_first.'" }';
        }
        
        echo '{"total":"' . $total_all . '","total_subcategory":['.implode(",", $array_subcat).']}';
        
    }
    elseif ($type == "total_technology") {
        
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $app_filters_category = $projectdb->real_escape_string((string) (isset($_POST['applications_filters_category']) ? $_POST['applications_filters_category'] : $_GET['applications_filters_category']));
        $app_filters_subcategory = $projectdb->real_escape_string((string) (isset($_POST['applications_filters_subcategory']) ? $_POST['applications_filters_subcategory'] : $_GET['applications_filters_subcategory']));
        $app_filters_risk = $projectdb->real_escape_string((string) (isset($_POST['applications_filters_risk']) ? $_POST['applications_filters_risk'] : $_GET['applications_filters_risk']));
        $app_filters_charac = $projectdb->real_escape_string((string) (isset($_POST['applications_filters_charac']) ? $_POST['applications_filters_charac'] : $_GET['applications_filters_charac']));
        
        $app_filter_idx = $projectdb->real_escape_string((string) (isset($_POST['app_filter_idx']) ? $_POST['app_filter_idx'] : $_GET['app_filter_idx']));
        $app_filter_table_name = $projectdb->real_escape_string((string) (isset($_POST['app_filter_table_name']) ? $_POST['app_filter_table_name'] : $_GET['app_filter_table_name']));
        $is_first = $projectdb->real_escape_string((string) (isset($_POST['app_filters_is_first']) ? $_POST['app_filters_is_first'] : $_GET['app_filters_is_first']));
        
        $technology = array();
        $array_tech = array();
        
        $sql_filters = "";
        $sql_filters_default = "";
        
        $technology_select_a = array();
        $filters_technology = array();

        require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
        $sql_vsys = prepareVsysQuery($projectdb, $vsys, $source);
        
        if($is_first == "1"){

            if(($app_filter_idx != "") && ($app_filter_table_name != "")){

                $getSelections = $projectdb->query("SELECT technology FROM $app_filter_table_name WHERE id = '$app_filter_idx';");

                if($getSelections->num_rows > 0){
                    while ($dataSelect = $getSelections->fetch_assoc()) {
                        $technology_select = $dataSelect['technology'];
                    }
                }

                $technology_select_a = explode(",", $technology_select);
                foreach ($technology_select_a as $tech){
                    $filters_technology[] = " '$tech' ";
                }

                if($technology_select != ""){

                    $app_filters_technology = implode(",", $filters_technology);
                    $sql_filters = $sql_filters . " AND technology IN ($app_filters_technology) ";

                    if (preg_match("/WHERE/", $sql_filters_default)) {
                        $sql_filters_default = $sql_filters_default . " AND technology IN ($app_filters_technology) ";
                    } else {
                        $sql_filters_default = " WHERE technology IN ($app_filters_technology) ";
                    }

                }
                else{
                    $is_first = 0;
                }
            }
        }

        if($app_filters_category != ""){
            
            $sql_filters = $sql_filters . " AND category IN ($app_filters_category) ";
            
            if (preg_match("/WHERE/", $sql_filters_default)) {
                $sql_filters_default = $sql_filters_default . " AND category IN ($app_filters_category) ";
            } else {
                $sql_filters_default = " WHERE category IN ($app_filters_category) ";
            }
            
        }
        
        if($app_filters_subcategory != ""){
            
            $sql_filters = $sql_filters . " AND subcategory IN ($app_filters_subcategory) ";
            
            if (preg_match("/WHERE/", $sql_filters_default)) {
                $sql_filters_default = $sql_filters_default . " AND subcategory IN ($app_filters_subcategory) ";
            } else {
                $sql_filters_default = " WHERE subcategory IN ($app_filters_subcategory) ";
            }
            
        }
        
        if($app_filters_risk != ""){
            
            $sql_filters = $sql_filters . " AND risk IN ($app_filters_risk) ";
            
            if (preg_match("/WHERE/", $sql_filters_default)) {
                $sql_filters_default = $sql_filters_default . " AND risk IN ($app_filters_risk) ";
            } else {
                $sql_filters_default = " WHERE risk IN ($app_filters_risk) ";
            }
            
        }
        
        if($app_filters_charac != ""){
            
            $app_filters_charac_exp = explode(",", $app_filters_charac);
            
            foreach($app_filters_charac_exp as $campo){
                //echo "El campo es: " . $campo . "\n";
                if (preg_match("/WHERE/", $query)) {
                    $sql_filters = $sql_filters . " AND $campo = 'yes' ";
                } else {
                    $sql_filters = " WHERE $campo = 'yes' ";
                }
                if (preg_match("/WHERE/", $sql_filters_default)) {
                    $sql_filters_default = $sql_filters_default . " AND $campo = 'yes' ";
                } else {
                    $sql_filters_default = " WHERE $campo = 'yes' ";
                }
            }
            
        }
        
        $getCat = $projectdb->query("SELECT DISTINCT(technology) FROM default_applications $sql_filters_default;");
        
        if($getCat->num_rows > 0){
            while ($dataCat = $getCat->fetch_assoc()) {
                if($dataCat['technology'] != ""){
                    $technology[] = $dataCat['technology'];
                }
            }
        }
        
        $getCat2 = $projectdb->query("SELECT DISTINCT(technology) FROM applications WHERE source = '$source' $sql_vsys $sql_filters;");
        if($getCat2->num_rows > 0){
            while ($dataCat2 = $getCat2->fetch_assoc()) {
                $cat = $dataCat2['technology'];
                if(!in_array($cat, $technology)){
                    $technology[] = $dataCat2['technology'];
                }
            }
        }
        
        $total = 0;
        $total_all = 0;
        
        foreach ($technology as $key=>$value){
            
            $getId = $projectdb->query("SELECT id FROM technology WHERE name = '$value' ;");
            $dataId = $getId->fetch_assoc();
            $id = $dataId['id'];
            
            $getTotalAppCat = $projectdb->query("SELECT id FROM default_applications WHERE technology = '$value' $sql_filters;");
            $count_app_x_cat = $getTotalAppCat->num_rows;
            
            $getTotalAppCat2 = $projectdb->query("SELECT id FROM applications WHERE technology = '$value' AND source = '$source' $sql_vsys $sql_filters;");
            $count_app_x_cat2 = $getTotalAppCat2->num_rows;
            
            $total = $count_app_x_cat + $count_app_x_cat2;
            
            $total_all += $total;
            
            $array_tech[] = '{"id":"'.$id.'", "technology":"'.$value.'", "total":"'.$total.'", "is_first":"'.$is_first.'" }';
        }
        
        echo '{"total":"' . $total_all . '","total_technology":['.implode(",", $array_tech).']}';
        
    }
    elseif ($type == "total_risk") {
        
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $app_filters_category = $projectdb->real_escape_string((string) (isset($_POST['applications_filters_category']) ? $_POST['applications_filters_category'] : $_GET['applications_filters_category']));
        $app_filters_subcategory = $projectdb->real_escape_string((string) (isset($_POST['applications_filters_subcategory']) ? $_POST['applications_filters_subcategory'] : $_GET['applications_filters_subcategory']));
        $app_filters_technology = $projectdb->real_escape_string((string) (isset($_POST['applications_filters_technology']) ? $_POST['applications_filters_technology'] : $_GET['applications_filters_technology']));
        $app_filters_charac = $projectdb->real_escape_string((string) (isset($_POST['applications_filters_charac']) ? $_POST['applications_filters_charac'] : $_GET['applications_filters_charac']));
        
        $app_filter_idx = $projectdb->real_escape_string((string) (isset($_POST['app_filter_idx']) ? $_POST['app_filter_idx'] : $_GET['app_filter_idx']));
        $app_filter_table_name = $projectdb->real_escape_string((string) (isset($_POST['app_filter_table_name']) ? $_POST['app_filter_table_name'] : $_GET['app_filter_table_name']));
        $is_first = $projectdb->real_escape_string((string) (isset($_POST['app_filters_is_first']) ? $_POST['app_filters_is_first'] : $_GET['app_filters_is_first']));
        
        $risk = array();
        $array_risk = array();
        
        $risk_select_a = array();
        $filters_risk = array();

        $sql_filters = "";
        $sql_filters_default = "";

        require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
        $sql_vsys = prepareVsysQuery($projectdb, $vsys, $source);

        if($is_first == "1"){

            if(($app_filter_idx != "") && ($app_filter_table_name != "")){

                $getSelections = $projectdb->query("SELECT risk FROM $app_filter_table_name WHERE id = '$app_filter_idx';");

                if($getSelections->num_rows > 0){
                    while ($dataSelect = $getSelections->fetch_assoc()) {
                        $risk_select = $dataSelect['risk'];
                    }
                }

                $risk_select_a = explode(",", $risk_select);
                foreach ($risk_select_a as $risks){
                    $filters_risk[] = " '$risks' ";
                }

                if($risk_select != ""){

                    $app_filters_risk = implode(",", $filters_risk);
                    $sql_filters = $sql_filters . " AND risk IN ($app_filters_risk) ";

                    if (preg_match("/WHERE/", $sql_filters_default)) {
                        $sql_filters_default = $sql_filters_default . " AND risk IN ($app_filters_risk) ";
                    } else {
                        $sql_filters_default = " WHERE risk IN ($app_filters_risk) ";
                    }

                }
                else{
                    $is_first = 0;
                }
            }
        }
        
        if($app_filters_category != ""){
            
            $sql_filters = $sql_filters . " AND category IN ($app_filters_category) ";
            
            if (preg_match("/WHERE/", $sql_filters_default)) {
                $sql_filters_default = $sql_filters_default . " AND category IN ($app_filters_category) ";
            } else {
                $sql_filters_default = " WHERE category IN ($app_filters_category) ";
            }
            
        }
        
        if($app_filters_subcategory != ""){
            
            $sql_filters = $sql_filters . " AND subcategory IN ($app_filters_subcategory) ";
            
            if (preg_match("/WHERE/", $sql_filters_default)) {
                $sql_filters_default = $sql_filters_default . " AND subcategory IN ($app_filters_subcategory) ";
            } else {
                $sql_filters_default = " WHERE subcategory IN ($app_filters_subcategory) ";
            }
            
        }
        
        if($app_filters_technology != ""){
            
            $sql_filters = $sql_filters . " AND technology IN ($app_filters_technology) ";
            
            if (preg_match("/WHERE/", $sql_filters_default)) {
                $sql_filters_default = $sql_filters_default . " AND technology IN ($app_filters_technology) ";
            } else {
                $sql_filters_default = " WHERE technology IN ($app_filters_technology) ";
            }
            
        }
        
        if($app_filters_charac != ""){
            
            $app_filters_charac_exp = explode(",", $app_filters_charac);
            
            foreach($app_filters_charac_exp as $campo){
                //echo "El campo es: " . $campo . "\n";
                if (preg_match("/WHERE/", $query)) {
                    $sql_filters = $sql_filters . " AND $campo = 'yes' ";
                } else {
                    $sql_filters = " WHERE $campo = 'yes' ";
                }
                if (preg_match("/WHERE/", $sql_filters_default)) {
                    $sql_filters_default = $sql_filters_default . " AND $campo = 'yes' ";
                } else {
                    $sql_filters_default = " WHERE $campo = 'yes' ";
                }
            }
            
        }
        
        $getCat = $projectdb->query("SELECT DISTINCT(risk) FROM default_applications $sql_filters_default;");
        
        if($getCat->num_rows > 0){
            while ($dataCat = $getCat->fetch_assoc()) {
                if($dataCat['risk'] != "0"){
                    $risk[] = $dataCat['risk'];
                }
            }
        }
        
        $getCat2 = $projectdb->query("SELECT DISTINCT(risk) FROM applications WHERE source = '$source' $sql_vsys $sql_filters;");
        if($getCat2->num_rows > 0){
            while ($dataCat2 = $getCat2->fetch_assoc()) {
                $cat = $dataCat2['risk'];
                if(!in_array($cat, $risk)){
                    $risk[] = $dataCat2['risk'];
                }
            }
        }
        
        $total = 0;
        $total_all = 0;
        
        sort($risk);
        
        foreach ($risk as $key=>$value){
            
            $getTotalAppCat = $projectdb->query("SELECT id FROM default_applications WHERE risk = '$value' $sql_filters;");
            $count_app_x_cat = $getTotalAppCat->num_rows;
            
            $getTotalAppCat2 = $projectdb->query("SELECT id FROM applications WHERE risk = '$value' AND source = '$source' $sql_vsys $sql_filters;");
            $count_app_x_cat2 = $getTotalAppCat2->num_rows;
            
            $total = $count_app_x_cat + $count_app_x_cat2;
            
            $total_all += $total;
            
            $array_risk[] = '{ "id":"'.$value.'", "risk":"'.$value.'", "total":"'.$total.'", "is_first":"'.$is_first.'" }';
        }
        
        echo '{"total":"' . $total_all . '","total_risk":['.implode(",", $array_risk).']}';
        
    }
    elseif ($type == "total_charac") {
        
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        $app_filters_category = $projectdb->real_escape_string((string) (isset($_POST['applications_filters_category']) ? $_POST['applications_filters_category'] : $_GET['applications_filters_category']));
        $app_filters_subcategory = $projectdb->real_escape_string((string) (isset($_POST['applications_filters_subcategory']) ? $_POST['applications_filters_subcategory'] : $_GET['applications_filters_subcategory']));
        $app_filters_technology = $projectdb->real_escape_string((string) (isset($_POST['applications_filters_technology']) ? $_POST['applications_filters_technology'] : $_GET['applications_filters_technology']));
        $app_filters_risk = $projectdb->real_escape_string((string) (isset($_POST['applications_filters_risk']) ? $_POST['applications_filters_risk'] : $_GET['applications_filters_risk']));
         
        $app_filter_idx = $projectdb->real_escape_string((string) (isset($_POST['app_filter_idx']) ? $_POST['app_filter_idx'] : $_GET['app_filter_idx']));
        $app_filter_table_name = $projectdb->real_escape_string((string) (isset($_POST['app_filter_table_name']) ? $_POST['app_filter_table_name'] : $_GET['app_filter_table_name']));
        $is_first = $projectdb->real_escape_string((string) (isset($_POST['app_filters_is_first']) ? $_POST['app_filters_is_first'] : $_GET['app_filters_is_first']));
        
        $array_charac = array();
        $sql_filters = "";

        $evasive_behavior_first = "";
        $consume_big_bandwidth_first = "";
        $prone_to_misuse_first = "";
        $able_to_transfer_file_first = "";
        $tunnel_other_application_first = "";
        $used_by_malware_first = "";
        $has_known_vulnerability_first = "";
        $pervasive_use_first = "";

        require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
        $sql_vsys = prepareVsysQuery($projectdb, $vsys, $source);
        
        if($is_first == "1"){

            if(($app_filter_idx != "") && ($app_filter_table_name != "")){
                
                $getSelections = $projectdb->query("SELECT evasive_behavior, consume_big_bandwidth, prone_to_misuse, able_to_transfer_file, tunnel_other_application, used_by_malware, has_known_vulnerability, pervasive_use 
                    FROM $app_filter_table_name WHERE id = '$app_filter_idx';");

                if($getSelections->num_rows > 0){
                    while ($dataSelect = $getSelections->fetch_assoc()) {
                        $evasive_behavior_first = $dataSelect['evasive_behavior'];
                        $consume_big_bandwidth_first = $dataSelect['consume_big_bandwidth'];
                        $prone_to_misuse_first = $dataSelect['prone_to_misuse'];
                        $able_to_transfer_file_first = $dataSelect['able_to_transfer_file'];
                        $tunnel_other_application_first = $dataSelect['tunnel_other_application'];
                        $used_by_malware_first = $dataSelect['used_by_malware'];
                        $has_known_vulnerability_first = $dataSelect['has_known_vulnerability'];
                        $pervasive_use_first = $dataSelect['pervasive_use'];
                    }
                }
                
            }
        }
        
        if($app_filters_category != ""){
            $sql_filters = $sql_filters . " AND category IN ($app_filters_category) ";    
        }
        
        if($app_filters_subcategory != ""){
            $sql_filters = $sql_filters . " AND subcategory IN ($app_filters_subcategory) ";    
        }
        
        if($app_filters_technology != ""){
            $sql_filters = $sql_filters . " AND technology IN ($app_filters_technology) ";    
        }
        
        if($app_filters_risk != ""){
            $sql_filters = $sql_filters . " AND risk IN ($app_filters_risk) ";    
        }
        
        $total_EB = 0;
        $total_CBB = 0;
        $total_UBM = 0;
        $total_ATF = 0;
        $total_HKV = 0;
        $total_TOA = 0;
        $total_PTM = 0;
        $total_PU = 0;
        
        if($is_first == "1"){
            if($evasive_behavior_first == "yes"){
                /* TOTAL EVASIVE_BEHAVIOR */
                $getTotalEB = $projectdb->query("SELECT COUNT(evasive_behavior) AS total FROM default_applications WHERE evasive_behavior = 'yes' $sql_filters "
                        . "UNION SELECT COUNT(evasive_behavior) AS total FROM applications 
                        WHERE evasive_behavior = 'yes' $sql_vsys $sql_filters ;");
                if($getTotalEB->num_rows > 0){
                    while($dataEB = $getTotalEB->fetch_assoc()){
                        $total_EB += $dataEB['total'];
                    }
                }
                if($total_EB != 0){
                    $array_charac[] = '{ "id":"1", "characteristics":"Evasive", "value":"evasive_behavior", "total":"'.$total_EB.'", "is_first":"'.$is_first.'" }';
                }
            }
            
            if($consume_big_bandwidth_first == "yes"){
                /* TOTAL CONSUME BIG BANDWIDTH */
                $getTotalCBB = $projectdb->query("SELECT COUNT(consume_big_bandwidth) AS total FROM default_applications WHERE consume_big_bandwidth = 'yes' $sql_filters "
                        . "UNION SELECT COUNT(consume_big_bandwidth) AS total FROM applications 
                        WHERE consume_big_bandwidth = 'yes' $sql_filters $sql_vsys;");
                if($getTotalCBB->num_rows > 0){
                    while($dataCBB = $getTotalCBB->fetch_assoc()){
                        $total_CBB += $dataCBB['total'];
                    }
                }
                if($total_CBB != 0){
                    $array_charac[] = '{ "id":"2", "characteristics":"Excessive Bandwidth", "value":"consume_big_bandwidth", "total":"'.$total_CBB.'", "is_first":"'.$is_first.'" }';
                }
            }
         
            if($used_by_malware_first == "yes"){
                /* TOTAL USED BY MALWARE */
                $getTotalUBM = $projectdb->query("SELECT COUNT(used_by_malware) AS total FROM default_applications WHERE used_by_malware = 'yes' $sql_filters "
                        . "UNION SELECT COUNT(used_by_malware) AS total 
                        FROM applications WHERE used_by_malware = 'yes' $sql_vsys $sql_filters ;");
                if($getTotalUBM->num_rows > 0){
                    while($dataUBM = $getTotalUBM->fetch_assoc()){
                        $total_UBM += $dataUBM['total'];
                    }
                }
                if($total_UBM != 0){
                    $array_charac[] = '{ "id":"3", "characteristics":"Used by Malware", "value":"used_by_malware", "total":"'.$total_UBM.'", "is_first":"'.$is_first.'" }';
                }
            }
            
            if($able_to_transfer_file_first == "yes"){
                /* TOTAL ABLE TO TRANSFER FILE */
                $getTotalATF = $projectdb->query("SELECT COUNT(able_to_transfer_file) AS total FROM default_applications WHERE able_to_transfer_file = 'yes' $sql_filters "
                        . "UNION SELECT COUNT(able_to_transfer_file) AS total FROM applications 
                        WHERE able_to_transfer_file = 'yes' $sql_vsys $sql_filters ;");
                if($getTotalATF->num_rows > 0){
                    while($dataATF = $getTotalATF->fetch_assoc()){
                        $total_ATF += $dataATF['total'];
                    }
                }
                if($total_ATF != 0){
                    $array_charac[] = '{ "id":"4", "characteristics":"Transfers Files", "value":"able_to_transfer_file", "total":"'.$total_ATF.'", "is_first":"'.$is_first.'" }';
                }
            }
            
            if($has_known_vulnerability_first == "yes"){
                /* TOTAL HAS KNOWN VULNERABILITY */
                $getTotalHKV = $projectdb->query("SELECT COUNT(has_known_vulnerability) AS total FROM default_applications WHERE has_known_vulnerability = 'yes' $sql_filters "
                        . "UNION SELECT COUNT(has_known_vulnerability) AS total FROM applications 
                        WHERE has_known_vulnerability = 'yes' $sql_vsys $sql_filters;");
                if($getTotalHKV->num_rows > 0){
                    while($dataHKV = $getTotalHKV->fetch_assoc()){
                        $total_HKV += $dataHKV['total'];
                    }
                }
                if($total_HKV != 0){
                    $array_charac[] = '{ "id":"5", "characteristics":"Vulnerability", "value":"has_known_vulnerability", "total":"'.$total_HKV.'", "is_first":"'.$is_first.'" }';
                }
            }
            
            if($tunnel_other_application_first == "yes"){
                /* TOTAL TUNNEL OTHER APPLICATION */
                $getTotalTOA = $projectdb->query("SELECT COUNT(tunnel_other_application) AS total FROM default_applications WHERE tunnel_other_application = 'yes' $sql_filters "
                        . "UNION SELECT COUNT(tunnel_other_application) AS total FROM applications 
                        WHERE tunnel_other_application = 'yes' $sql_vsys $sql_filters;");
                if($getTotalTOA->num_rows > 0){
                    while($dataTOA = $getTotalTOA->fetch_assoc()){
                        $total_TOA += $dataTOA['total'];
                    }
                }
                if($total_TOA != 0){
                    $array_charac[] = '{ "id":"6", "characteristics":"Tunnels Other Apps", "value":"tunnel_other_application", "total":"'.$total_TOA.'", "is_first":"'.$is_first.'" }';
                }
            }
                
            if($prone_to_misuse_first == "yes"){
                /* TOTAL PRONE TO MISUSE */
                $getTotalPTM = $projectdb->query("SELECT COUNT(prone_to_misuse) AS total FROM default_applications WHERE prone_to_misuse = 'yes' $sql_filters "
                        . "UNION SELECT COUNT(prone_to_misuse) AS total FROM applications 
                        WHERE prone_to_misuse = 'yes' $sql_vsys $sql_filters ;");
                if($getTotalPTM->num_rows > 0){
                    while($dataPTM = $getTotalPTM->fetch_assoc()){
                        $total_PTM += $dataPTM['total'];
                    }
                }
                if($total_PTM != 0){
                    $array_charac[] = '{ "id":"7", "characteristics":"Prone to Misuse", "value":"prone_to_misuse", "total":"'.$total_PTM.'", "is_first":"'.$is_first.'" }';
                }               
            }
            
            if($pervasive_use_first == "yes"){
                /* TOTAL PERVASIVE USE */
                $getTotalPU = $projectdb->query("SELECT COUNT(pervasive_use) AS total FROM default_applications WHERE pervasive_use = 'yes' $sql_filters "
                        . "UNION SELECT COUNT(pervasive_use) AS total FROM applications 
                        WHERE pervasive_use = 'yes' $sql_vsys $sql_filters ;");
                if($getTotalPU->num_rows > 0){
                    while($dataPU = $getTotalPU->fetch_assoc()){
                        $total_PU += $dataPU['total'];
                    }
                }
                if($total_PU != 0){
                    $array_charac[] = '{ "id":"8", "characteristics":"Widely used", "value":"pervasive_use", "total":"'.$total_PU.'", "is_first":"'.$is_first.'" }';
                }
            }
        }
        else{
        
            /* TOTAL EVASIVE_BEHAVIOR */
            $getTotalEB = $projectdb->query("SELECT COUNT(evasive_behavior) AS total FROM default_applications WHERE evasive_behavior = 'yes' $sql_filters "
                    . "UNION SELECT COUNT(evasive_behavior) AS total FROM applications 
                    WHERE evasive_behavior = 'yes' $sql_vsys $sql_filters ;");
            
            if($getTotalEB->num_rows > 0){
                while($dataEB = $getTotalEB->fetch_assoc()){
                    $total_EB += $dataEB['total'];
                }
            }
            if($total_EB != 0){
                $array_charac[] = '{ "id":"1", "characteristics":"Evasive", "value":"evasive_behavior", "total":"'.$total_EB.'", "is_first":"'.$is_first.'" }';
            }

            /* TOTAL CONSUME BIG BANDWIDTH */
            $getTotalCBB = $projectdb->query("SELECT COUNT(consume_big_bandwidth) AS total FROM default_applications WHERE consume_big_bandwidth = 'yes' $sql_filters "
                    . "UNION SELECT COUNT(consume_big_bandwidth) AS total FROM applications 
                    WHERE consume_big_bandwidth = 'yes' $sql_vsys $sql_filters ;");
            if($getTotalCBB->num_rows > 0){
                while($dataCBB = $getTotalCBB->fetch_assoc()){
                    $total_CBB += $dataCBB['total'];
                }
            }
            if($total_CBB != 0){
                $array_charac[] = '{ "id":"2", "characteristics":"Excessive Bandwidth", "value":"consume_big_bandwidth", "total":"'.$total_CBB.'", "is_first":"'.$is_first.'" }';
            }

            /* TOTAL USED BY MALWARE */
            $getTotalUBM = $projectdb->query("SELECT COUNT(used_by_malware) AS total FROM default_applications WHERE used_by_malware = 'yes' $sql_filters "
                    . "UNION SELECT COUNT(used_by_malware) AS total FROM applications 
                    WHERE used_by_malware = 'yes' $sql_vsys $sql_filters ;");
            if($getTotalUBM->num_rows > 0){
                while($dataUBM = $getTotalUBM->fetch_assoc()){
                    $total_UBM += $dataUBM['total'];
                }
            }
            if($total_UBM != 0){
                $array_charac[] = '{ "id":"3", "characteristics":"Used by Malware", "value":"used_by_malware", "total":"'.$total_UBM.'", "is_first":"'.$is_first.'"}';
            }

            /* TOTAL ABLE TO TRANSFER FILE */
            $getTotalATF = $projectdb->query("SELECT COUNT(able_to_transfer_file) AS total FROM default_applications WHERE able_to_transfer_file = 'yes' $sql_filters "
                    . "UNION SELECT COUNT(able_to_transfer_file) AS total FROM applications 
                    WHERE able_to_transfer_file = 'yes' $sql_vsys $sql_filters ;");
            if($getTotalATF->num_rows > 0){
                while($dataATF = $getTotalATF->fetch_assoc()){
                    $total_ATF += $dataATF['total'];
                }
            }
            if($total_ATF != 0){
                $array_charac[] = '{ "id":"4", "characteristics":"Transfers Files", "value":"able_to_transfer_file", "total":"'.$total_ATF.'", "is_first":"'.$is_first.'"}';
            }

            /* TOTAL HAS KNOWN VULNERABILITY */
            $getTotalHKV = $projectdb->query("SELECT COUNT(has_known_vulnerability) AS total FROM default_applications WHERE has_known_vulnerability = 'yes' $sql_filters "
                    . "UNION SELECT COUNT(has_known_vulnerability) AS total FROM applications 
                    WHERE has_known_vulnerability = 'yes' $sql_vsys $sql_filters;");
            if($getTotalHKV->num_rows > 0){
                while($dataHKV = $getTotalHKV->fetch_assoc()){
                    $total_HKV += $dataHKV['total'];
                }
            }
            if($total_HKV != 0){
                $array_charac[] = '{ "id":"5", "characteristics":"Vulnerability", "value":"has_known_vulnerability", "total":"'.$total_HKV.'", "is_first":"'.$is_first.'" }';
            }

            /* TOTAL TUNNEL OTHER APPLICATION */
            $getTotalTOA = $projectdb->query("SELECT COUNT(tunnel_other_application) AS total FROM default_applications WHERE tunnel_other_application = 'yes' $sql_filters "
                    . "UNION SELECT COUNT(tunnel_other_application) AS total FROM applications 
                    WHERE tunnel_other_application = 'yes' $sql_vsys $sql_filters;");
            if($getTotalTOA->num_rows > 0){
                while($dataTOA = $getTotalTOA->fetch_assoc()){
                    $total_TOA += $dataTOA['total'];
                }
            }
            if($total_TOA != 0){
                $array_charac[] = '{ "id":"6", "characteristics":"Tunnels Other Apps", "value":"tunnel_other_application", "total":"'.$total_TOA.'", "is_first":"'.$is_first.'" }';
            }

            /* TOTAL PRONE TO MISUSE */
            $getTotalPTM = $projectdb->query("SELECT COUNT(prone_to_misuse) AS total FROM default_applications WHERE prone_to_misuse = 'yes' $sql_filters "
                    . "UNION SELECT COUNT(prone_to_misuse) AS total FROM applications 
                    WHERE prone_to_misuse = 'yes' $sql_vsys $sql_filters ;");
            if($getTotalPTM->num_rows > 0){
                while($dataPTM = $getTotalPTM->fetch_assoc()){
                    $total_PTM += $dataPTM['total'];
                }
            }
            if($total_PTM != 0){
                $array_charac[] = '{ "id":"7", "characteristics":"Prone to Misuse", "value":"prone_to_misuse", "total":"'.$total_PTM.'", "is_first":"'.$is_first.'" }';
            }

            /* TOTAL PERVASIVE USE */
            $getTotalPU = $projectdb->query("SELECT COUNT(pervasive_use) AS total FROM default_applications WHERE pervasive_use = 'yes' $sql_filters "
                    . "UNION SELECT COUNT(pervasive_use) AS total FROM applications 
                    WHERE pervasive_use = 'yes' $sql_vsys $sql_filters ;");
            if($getTotalPU->num_rows > 0){
                while($dataPU = $getTotalPU->fetch_assoc()){
                    $total_PU += $dataPU['total'];
                }
            }
            if($total_PU != 0){
                $array_charac[] = '{ "id":"8", "characteristics":"Widely used", "value":"pervasive_use", "total":"'.$total_PU.'", "is_first":"'.$is_first.'" }';
            }
        }
        $total_all=count($array_charac);
        echo '{"total":"' . $total_all . '","total_charac":['.implode(",", $array_charac).']}';
        
    }
    elseif($type = "applications_filters"){
        
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        
        $app_filters_category = $projectdb->real_escape_string((string) (isset($_POST['applications_filters_category']) ? $_POST['applications_filters_category'] : $_GET['applications_filters_category']));
        $app_filters_subcategory = $projectdb->real_escape_string((string) (isset($_POST['applications_filters_subcategory']) ? $_POST['applications_filters_subcategory'] : $_GET['applications_filters_subcategory']));
        $app_filters_technology = $projectdb->real_escape_string((string) (isset($_POST['applications_filters_technology']) ? $_POST['applications_filters_technology'] : $_GET['applications_filters_technology']));
        $app_filters_risk = $projectdb->real_escape_string((string) (isset($_POST['applications_filters_risk']) ? $_POST['applications_filters_risk'] : $_GET['applications_filters_risk']));
        $app_filters_charac = $projectdb->real_escape_string((string) (isset($_POST['applications_filters_charac']) ? $_POST['applications_filters_charac'] : $_GET['applications_filters_charac']));
        
        $filename_source = $projectdb->real_escape_string((string) (isset($_GET['filename_source']) ? $_GET['filename_source'] : ''));
        $sql_filters = "";
        $sql_filters_default = "";

        require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
        $sql_vsys = prepareVsysQuery($projectdb, $vsys, $source);
        
        if($app_filters_category != ""){
            if (preg_match("/WHERE/", $query)) {
                $sql_filters = $sql_filters . " AND category IN ($app_filters_category) ";
            } else {
                $sql_filters = " WHERE category IN ($app_filters_category) ";
            }
            if (preg_match("/WHERE/", $sql_filters_default)) {
                $sql_filters_default = $sql_filters_default . " AND category IN ($app_filters_category) ";
            } else {
                $sql_filters_default = " WHERE category IN ($app_filters_category) ";
            }
        }
        
        if($app_filters_subcategory != ""){
            if (preg_match("/WHERE/", $query)) {
                $sql_filters = $sql_filters . " AND subcategory IN ($app_filters_subcategory) ";
            } else {
                $sql_filters = " WHERE subcategory IN ($app_filters_subcategory) ";
            }
            if (preg_match("/WHERE/", $sql_filters_default)) {
                $sql_filters_default = $sql_filters_default . " AND subcategory IN ($app_filters_subcategory) ";
            } else {
                $sql_filters_default = " WHERE subcategory IN ($app_filters_subcategory) ";
            }
        }
        
        if($app_filters_technology != ""){
            if (preg_match("/WHERE/", $query)) {
                $sql_filters = $sql_filters . " AND technology IN ($app_filters_technology) ";
            } else {
                $sql_filters = " WHERE technology IN ($app_filters_technology) ";
            }
            if (preg_match("/WHERE/", $sql_filters_default)) {
                $sql_filters_default = $sql_filters_default . " AND technology IN ($app_filters_technology) ";
            } else {
                $sql_filters_default = " WHERE technology IN ($app_filters_technology) ";
            }
            
        }
        
        if($app_filters_risk != ""){
            if (preg_match("/WHERE/", $query)) {
                $sql_filters = $sql_filters . " AND risk IN ($app_filters_risk) ";
            } else {
                $sql_filters = " WHERE risk IN ($app_filters_risk) ";
            }
            if (preg_match("/WHERE/", $sql_filters_default)) {
                $sql_filters_default = $sql_filters_default . " AND risk IN ($app_filters_risk) ";
            } else {
                $sql_filters_default = " WHERE risk IN ($app_filters_risk) ";
            }
            
        }
        
        if($app_filters_charac != ""){
            
            $app_filters_charac_exp = explode(",", $app_filters_charac);
            
            foreach($app_filters_charac_exp as $campo){
                //echo "El campo es: " . $campo . "\n";
                if (preg_match("/WHERE/", $query)) {
                    $sql_filters = $sql_filters . " AND $campo = 'yes' ";
                } else {
                    $sql_filters = " WHERE $campo = 'yes' ";
                }
                if (preg_match("/WHERE/", $sql_filters_default)) {
                    $sql_filters_default = $sql_filters_default . " AND $campo = 'yes' ";
                } else {
                    $sql_filters_default = " WHERE $campo = 'yes' ";
                }
            }
            
        }
        
        $getAll = $projectdb->query("SELECT id as app_id, source, devicegroup, vsys, name, category, subcategory, risk, technology, IF(default_type = 'port', value, value) AS default_port, 'applications' as table_name FROM applications $query $sql_filters $sql_vsys "
                . "UNION SELECT id as app_id, '$source' as source, '$filename_source' as devicegroup, 'all' as vsys, name, category, subcategory, risk, technology, default_port, 'default_applications' as table_name FROM default_applications $sql_filters_default;");
        $count = $getAll->num_rows;
        $getLimit = $projectdb->query("SELECT id as app_id, source, devicegroup, vsys, name, category, subcategory, risk, technology, IF(default_type = 'port', value, value) AS default_port, 'applications' as table_name FROM applications $query $sql_filters $sql_vsys "
                . "UNION SELECT id as app_id, '$source' as source, '$filename_source' as devicegroup, 'all' as vsys, name, category, subcategory, risk, technology, default_port, 'default_applications' as table_name FROM default_applications $sql_filters_default ;");
        $x = 0;
        while ($data = $getLimit->fetch_object()) {
            $data->uid = $x++;
            $myData[] = $data;
            
        }
        if ($count == 0) {
            $myData = "";
        }
        
        echo '{"total":"' . $count . '","applications_filters":' . json_encode($myData) . '}';
        
    }
    
    
} 
elseif ($action == "set") {
    if ($type == "app_filters") {

        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : ''));
        $vsys_global = $projectdb->real_escape_string((string) (isset($_POST['vsys_global']) ? $_POST['vsys_global'] : ''));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : ''));
        
        $name = $projectdb->real_escape_string((string) (isset($_POST['name']) ? $_POST['name'] : ''));
        $shared = $projectdb->real_escape_string((string) (isset($_POST['shared']) ? $_POST['shared'] : ''));
        
        $app_filters_category = $projectdb->real_escape_string((string) (isset($_POST['applications_filters_category']) ? $_POST['applications_filters_category'] : ''));
        $app_filters_subcategory = $projectdb->real_escape_string((string) (isset($_POST['applications_filters_subcategory']) ? $_POST['applications_filters_subcategory'] : ''));
        $app_filters_technology = $projectdb->real_escape_string((string) (isset($_POST['applications_filters_technology']) ? $_POST['applications_filters_technology'] : ''));
        $app_filters_risk = $projectdb->real_escape_string((string) (isset($_POST['applications_filters_risk']) ? $_POST['applications_filters_risk'] : ''));
        $app_filters_charac = $projectdb->real_escape_string((string) (isset($_POST['applications_filters_charac']) ? $_POST['applications_filters_charac'] : ''));
        
        $app_filter_idx = $projectdb->real_escape_string((string) (isset($_POST['app_filter_idx']) ? $_POST['app_filter_idx'] : ''));
        $app_filter_table_name = $projectdb->real_escape_string((string) (isset($_POST['app_filter_table_name']) ? $_POST['app_filter_table_name'] : ''));
        
        $filename_source = $projectdb->real_escape_string((string) (isset($_POST['filename_source']) ? $_POST['filename_source'] : ''));
        
        $category = str_replace("'", "", $app_filters_category);
        $subcategory = str_replace("'", "", $app_filters_subcategory);

        $technology = str_replace("'", "", $app_filters_technology);
        $risk = str_replace("'", "", $app_filters_risk);
        $charac = str_replace("'", "", $app_filters_charac);

        $entryInfo = $projectdb->query("SELECT vsys, source FROM applications WHERE id='$app_filter_idx'");
        if($entryInfo->num_rows>0){
            $queryData = $entryInfo->fetch_assoc();
            $vsys = $queryData['vsys'];
            $source = $queryData['source'];
        }

        $table_name = "applications_filters";
        
        if(($app_filter_idx != "") && ($app_filter_table_name != "")){
            /* EDIT */
            $getExistName = $projectdb->query("SELECT name FROM $app_filter_table_name WHERE name = '$name' AND id != '$app_filter_idx' AND vsys = '$vsys';");

            if($getExistName->num_rows == 0){
                $projectdb->query("UPDATE $app_filter_table_name SET risk = '$risk', name = '$name', category = '$category', subcategory = '$subcategory', technology = '$technology', vsys = '$vsys' WHERE id = '$app_filter_idx'; ");

                if($charac != ""){
                    
                    $projectdb->query("UPDATE $app_filter_table_name SET evasive_behavior = '', consume_big_bandwidth = '', prone_to_misuse = '', able_to_transfer_file = '', tunnel_other_application = '', used_by_malware = '', has_known_vulnerability = '', pervasive_use = ''  WHERE id = '$app_filter_idx'; ");
                    
                    $charac_array = explode(",", $charac);
                    
                    foreach ($charac_array as $campo){
                        $projectdb->query("UPDATE $app_filter_table_name SET $campo = 'yes' WHERE id = '$app_filter_idx'; ");
                    }
                }
                
                echo json_encode(array("success" => true));
            }
            else{
                echo json_encode(array("success" => false));
            }
            
            
        }
        else{
            /* NEW APP FILTER */
            $getExistName = $projectdb->query("SELECT name FROM $table_name WHERE name = '$name' AND vsys = '$vsys';");

            if($getExistName->num_rows == 0){
            
                $projectdb->query("INSERT INTO $table_name (source, vsys, name, risk, category, subcategory, technology) VALUES ('$source', '$vsys','$name', '$risk', '$category', '$subcategory', '$technology')");
                $app_filters_id = $projectdb->insert_id;

                $charac_array = explode(",", $charac);

                foreach ($charac_array as $campo){
                    $projectdb->query("UPDATE $table_name SET $campo = 'yes' WHERE id = '$app_filters_id'; ");
                }
                echo json_encode(array("success" => true));
            }
            else{
                echo json_encode(array("success" => false));
            }
        }
    }
} 
elseif($action == "convert"){
    
    if($type == "shared"){
        
        $ids = $projectdb->real_escape_string((string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']));
        $vsys = $projectdb->real_escape_string((string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']));
        $source = $projectdb->real_escape_string((string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']));
        
        if ($ids != "") {
            take_snapshot_last($project);
            $member_ApplicationFilters = explode(',',$ids);
            $return = convertApplicationsFiltersToShared($source, $member_ApplicationFilters, "notall");
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
        $clone_to_vsys = $projectdb->real_escape_string((string) (isset($_POST['combo']) ? $_POST['combo'] : $_GET['combo']));
        if ($ids != "") {
            take_snapshot_last($project);
            $member_ApplicationFilters = explode(',',$ids);
            $return = cloneApplicationsFilters($source, $vsys, $clone_to_vsys, $member_ApplicationFilters);
            
            if($return != 0){
                echo json_encode(array("success" => true));
            }else{
                echo json_encode(array("success" => false));
            }  
        }
        
    }
    
}
?>