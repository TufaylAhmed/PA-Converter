<?php

# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';
require_once INC_ROOT.'/bin/Authentication.php';
require_once INC_ROOT.'/libs/shared.php';
require_once INC_ROOT.'/libs/projectdb.php';

include INC_ROOT.'/bin/middleware_sanitizer.php';

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $action     = (string)  (isset($_GET['action'])     ? $_GET['action'] : '');
        $type       = (string)  (isset($_GET['type'])       ? $_GET['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_GET['project'])    ? $_GET['project'] : '');
        $devicename = (string)  (isset($_GET['devicename']) ? $_GET['devicename'] : '');
        $start      = (integer) (isset($_GET['start'])      ? $_GET['start'] : '');
        $limit      = (integer) (isset($_GET['limit'])      ? $_GET['limit'] : '');
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

$projectdb = selectDatabase($project);

$action = $projectdb->real_escape_string($action);
$type = $projectdb->real_escape_string($type);
$project = $projectdb->real_escape_string($project);
$devicename = $projectdb->real_escape_string($devicename);
$start = $projectdb->real_escape_string($start);
$limit = $projectdb->real_escape_string($limit);

global $app;
$user = $app->container->sentinel->getUser();
$user_id = $user->id;

if ($action == "get") {
    if ($type == "regions_address"){
        switch($_SERVER['REQUEST_METHOD'])
        {
            case 'GET':
                $vsys       = (string) (isset($_GET['vsys'])       ? $_GET['vsys'] : '');
                $source     = (string) (isset($_GET['source'])     ? $_GET['source'] : '');
                $idx        = (string) (isset($_GET['idx'])        ? $_GET['idx'] : '');
                $table_name = (string) (isset($_GET['table_name']) ? $_GET['table_name'] : '');
                break;
            case 'POST':
                $vsys       = (string) (isset($_POST['vsys'])       ? $_POST['vsys'] : '');
                $source     = (string) (isset($_POST['source'])     ? $_POST['source'] : '');
                $idx        = (string) (isset($_POST['idx'])        ? $_POST['idx'] : '');
                $table_name = (string) (isset($_POST['table_name']) ? $_POST['table_name'] : '');
                break;

            default:
                $vsys       = (string) (isset($_POST['vsys'])       ? $_POST['vsys'] : '');
                $source     = (string) (isset($_POST['source'])     ? $_POST['source'] : '');
                $idx        = (string) (isset($_POST['idx'])        ? $_POST['idx'] : '');
                $table_name = (string) (isset($_POST['table_name']) ? $_POST['table_name'] : '');
                break;
        }

        $vsys = $projectdb->real_escape_string($vsys);
        $source = $projectdb->real_escape_string($source);
        $idx = $projectdb->real_escape_string($idx);
        $table_name = $projectdb->real_escape_string($table_name);

        //if($idx == ""){
        //    $idx = 0;
        //}
        if ($idx != "") {   
            $address = array();
            $getAddress = $projectdb->query("SELECT address FROM regions WHERE id = '$idx';");
            if ($getAddress->num_rows == 1) {
                $dataA = $getAddress->fetch_assoc();
                $add = $dataA['address'];
                
                $add_explode = explode(",", $add);
                $count = count($add_explode);
                foreach ($add_explode as $key => $value) {
                    $address[] = array("name" => $value);
                }
                if ($add == "") {
                    $count = 0;
                    $address = "";
                }
                echo '{"total":"' . $count . '","address":' . json_encode($address) . '}';
            }
        }
        else{
            $address = array();
            $getAddress = $projectdb->query("SELECT name FROM edit_table WHERE lid = '0' AND user_id = '$user_id';");
            if ($getAddress->num_rows == 1) {
                $dataA = $getAddress->fetch_assoc();
                $add = $dataA['name'];
                
                $add_explode = explode(",", $add);
                $count = count($add_explode);
                foreach ($add_explode as $key => $value) {
                    $address[] = array("name" => $value);
                }
                if ($add == "") {
                    $count = 0;
                    $address = "";
                }
                echo '{"total":"' . $count . '","address":' . json_encode($address) . '}';
            }
        }
        
    }
    elseif ($type == "default_regions"){
        switch($_SERVER['REQUEST_METHOD'])
        {
            case 'GET':
                $vsys       = (string) (isset($_GET['vsys'])       ? $_GET['vsys'] : '');
                $source     = (string) (isset($_GET['source'])     ? $_GET['source'] : '');
                break;
            case 'POST':
                $vsys       = (string) (isset($_POST['vsys'])       ? $_POST['vsys'] : '');
                $source     = (string) (isset($_POST['source'])     ? $_POST['source'] : '');
                break;

            default:
                $vsys       = (string) (isset($_POST['vsys'])       ? $_POST['vsys'] : '');
                $source     = (string) (isset($_POST['source'])     ? $_POST['source'] : '');
                break;
        }
//        $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
//        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);

        $vsys = $projectdb->real_escape_string($vsys);
        $source = $projectdb->real_escape_string($source);

        $getDefaultRegions = $projectdb->query("SELECT id, name, help, name AS name_parser, used FROM default_regions WHERE id >= '46';");
        if ($getDefaultRegions->num_rows > 0) {
            while ($data = $getDefaultRegions->fetch_object()) {
                $data->name_parser = $data->name ." (" . $data->help . ")";
                $myData[] = $data;
            }
            
            echo '{"total":"' . $count . '","regions":' . json_encode($myData) . '}';
        }
    }
    
} 
elseif ($action == "add") {
    if ($type == "regions_address"){
        switch($_SERVER['REQUEST_METHOD'])
        {
            case 'GET':
                $vsys       = (string) (isset($_GET['vsys'])       ? $_GET['vsys'] : '');
                $source     = (string) (isset($_GET['source'])     ? $_GET['source'] : '');
                $idx        = (string) (isset($_GET['idx'])        ? $_GET['idx'] : '');
                $table_name = (string) (isset($_GET['table_name']) ? $_GET['table_name'] : '');
                $ids        = (string) (isset($_GET['ids'])        ? $_GET['ids'] : '');
                $name       = (string) (isset($_GET['name'])       ? $_GET['name'] : '');
                break;
            case 'POST':
                $vsys       = (string) (isset($_POST['vsys'])       ? $_POST['vsys'] : '');
                $source     = (string) (isset($_POST['source'])     ? $_POST['source'] : '');
                $idx        = (string) (isset($_POST['idx'])        ? $_POST['idx'] : '');
                $table_name = (string) (isset($_POST['table_name']) ? $_POST['table_name'] : '');
                $ids        = (string) (isset($_POST['ids'])        ? $_POST['ids'] : '');
                $name       = (string) (isset($_POST['name'])       ? $_POST['name'] : '');
                break;

            default:
                $vsys       = (string) (isset($_POST['vsys'])       ? $_POST['vsys'] : '');
                $source     = (string) (isset($_POST['source'])     ? $_POST['source'] : '');
                $idx        = (string) (isset($_POST['idx'])        ? $_POST['idx'] : '');
                $table_name = (string) (isset($_POST['table_name']) ? $_POST['table_name'] : '');
                $ids        = (string) (isset($_POST['ids'])        ? $_POST['ids'] : '');
                $name       = (string) (isset($_POST['name'])       ? $_POST['name'] : '');
                break;
        }

        $vsys = $projectdb->real_escape_string($vsys);
        $source = $projectdb->real_escape_string($source);
        $idx = $projectdb->real_escape_string($idx);
        $table_name = $projectdb->real_escape_string($table_name);
        $ids = $projectdb->real_escape_string($ids);
        $name = $projectdb->real_escape_string($name);

        if($idx != ""){
            $getAddress = $projectdb->query("SELECT address FROM regions WHERE id = '$idx';");
        
            if ($getAddress->num_rows == 1) {
                $dataA = $getAddress->fetch_assoc();
                $permitted = $dataA['address'];

                if ($permitted != "") {
                    $add_array = explode(",", $permitted);
                    if (in_array($name, $add_array)) {

                    } else {
                        $add_array[] = $name;
                        asort($add_array);
                        $replace = implode(",",$add_array);

                        $projectdb->query("UPDATE regions SET address = '$replace' WHERE id = '$idx';");
                    }
                } else {
                    $projectdb->query("UPDATE regions SET address = '$name' WHERE id='$idx';");
                }
            }
        }
        else{
            $getAddress = $projectdb->query("SELECT name FROM edit_table WHERE lid = '0' AND user_id = '$user_id';");
        
            if ($getAddress->num_rows == 1) {
                $dataA = $getAddress->fetch_assoc();
                $permitted = $dataA['name'];

                if ($permitted != "") {
                    $add_array = explode(",", $permitted);
                    if (in_array($name, $add_array)) {

                    } else {
                        $add_array[] = $name;
                        asort($add_array);
                        $replace = implode(",",$add_array);

                        $projectdb->query("UPDATE edit_table SET name = '$replace' WHERE lid = '0' AND user_id = '$user_id';");
                    }
                } else {
                    $projectdb->query("UPDATE edit_table SET name = '$name' WHERE lid = '0' AND user_id = '$user_id';");
                }
            }
            else{
                $projectdb->query("INSERT INTO edit_table (id, lid, type, name, vsys, source, remove, user_id) "
                        . "VALUES ('NULL',  '0', 'members', '$name', '$vsys', '$source', '0', '$user_id');");
            }
        }
        
        
        echo json_encode(array("success" => true));
        
    }
    elseif ($type == "regions") {
        switch($_SERVER['REQUEST_METHOD'])
        {
            case 'GET':
                $vsys       = (string) (isset($_GET['vsys'])       ? $_GET['vsys'] : '');
                $source     = (string) (isset($_GET['source'])     ? $_GET['source'] : '');
                break;
            case 'POST':
                $vsys       = (string) (isset($_POST['vsys'])       ? $_POST['vsys'] : '');
                $source     = (string) (isset($_POST['source'])     ? $_POST['source'] : '');
                break;

            default:
                $vsys       = (string) (isset($_POST['vsys'])       ? $_POST['vsys'] : '');
                $source     = (string) (isset($_POST['source'])     ? $_POST['source'] : '');
                break;
        }
//        $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
//        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);

        $source = $projectdb->real_escape_string($source);
        $vsys = $projectdb->real_escape_string($vsys);

        if ($vsys == "") {
            $vsys = "vsys1";
        }
        if (($source != 0) AND ( $vsys != "all")) {
//            if ($vsys == "shared") {
//                $table_name = "shared_regions";
//            } else {
//                $table_name = "regions";
//            }
            $projectdb->query("INSERT INTO regions (source, vsys, devicegroup) values ('$source','$vsys', 'default');");
            echo json_encode(array("success" => true));
        } else {
            echo json_encode(array("success" => false));
        }
    }
} 
elseif ($action == "update") {
    if ($type == "regions_address"){
        switch($_SERVER['REQUEST_METHOD'])
        {
            case 'GET':
                $vsys       = (string) (isset($_GET['vsys'])       ? $_GET['vsys'] : '');
                $source     = (string) (isset($_GET['source'])     ? $_GET['source'] : '');
                $idx        = (string) (isset($_GET['idx'])        ? $_GET['idx'] : '');
                $template   = (string) (isset($_GET['template'])   ? $_GET['template'] : '');
                $table_name = (string) (isset($_GET['table_name']) ? $_GET['table_name'] : '');
                $ids        = (string) (isset($_GET['ids'])        ? $_GET['ids'] : '');
                $name       = (string) (isset($_GET['name'])       ? $_GET['name'] : '');
                $oldname    = (string) (isset($_GET['oldname'])    ? $_GET['oldname'] : '');
                break;
            case 'POST':
                $vsys       = (string) (isset($_POST['vsys'])       ? $_POST['vsys'] : '');
                $source     = (string) (isset($_POST['source'])     ? $_POST['source'] : '');
                $idx        = (string) (isset($_POST['idx'])        ? $_POST['idx'] : '');
                $template   = (string) (isset($_POST['template'])   ? $_POST['template'] : '');
                $table_name = (string) (isset($_POST['table_name']) ? $_POST['table_name'] : '');
                $ids        = (string) (isset($_POST['ids'])        ? $_POST['ids'] : '');
                $name       = (string) (isset($_POST['name'])       ? $_POST['name'] : '');
                $oldname    = (string) (isset($_POST['oldname'])    ? $_POST['oldname'] : '');
                break;

            default:
                $vsys       = (string) (isset($_POST['vsys'])       ? $_POST['vsys'] : '');
                $source     = (string) (isset($_POST['source'])     ? $_POST['source'] : '');
                $idx        = (string) (isset($_POST['idx'])        ? $_POST['idx'] : '');
                $template   = (string) (isset($_POST['template'])   ? $_POST['template'] : '');
                $table_name = (string) (isset($_POST['table_name']) ? $_POST['table_name'] : '');
                $ids        = (string) (isset($_POST['ids'])        ? $_POST['ids'] : '');
                $name       = (string) (isset($_POST['name'])       ? $_POST['name'] : '');
                $oldname    = (string) (isset($_POST['oldname'])    ? $_POST['oldname'] : '');
                break;
        }

        $vsys = $projectdb->real_escape_string($vsys);
        $source = $projectdb->real_escape_string($source);
        $idx = $projectdb->real_escape_string($idx);
        $template = $projectdb->real_escape_string($template);
        $table_name = $projectdb->real_escape_string($table_name);
        $ids = $projectdb->real_escape_string($ids);
        $name = $projectdb->real_escape_string($name);
        $oldname = $projectdb->real_escape_string($oldname);

        take_snapshot_last($project);
        
        if($idx == ""){
            $getAddress = $projectdb->query("SELECT name FROM edit_table WHERE lid = '0' AND user_id = '$user_id';");
            if ($getAddress->num_rows == 1) {
                $dataA = $getAddress->fetch_assoc();
                $permitted = $dataA['name'];
                $add_array = explode(",", $permitted);
                if (in_array($name, $add_array)) {

                } else {
                    $replace = str_replace($oldname, $name, $permitted);
                    $replace_array = explode(",", $replace);
                    asort($replace_array);
                    $replace2 = implode(",",$replace_array);
                    $projectdb->query("UPDATE edit_table SET name = '$replace2' WHERE lid = '0' AND user_id = '$user_id';");
                }
            }
        }
        else{
            $getAddress = $projectdb->query("SELECT address FROM $table_name WHERE id = '$idx';");
            if ($getAddress->num_rows == 1) {
                $dataA = $getAddress->fetch_assoc();
                $permitted = $dataA['address'];
                $add_array = explode(",", $permitted);
                if (in_array($name, $add_array)) {

                } else {
                    $replace = str_replace($oldname, $name, $permitted);
                    $replace_array = explode(",", $replace);
                    asort($replace_array);
                    $replace2 = implode(",",$replace_array);
                    $projectdb->query("UPDATE $table_name SET address = '$replace2' WHERE id = '$idx';");
                }
            }
        }
        

        echo json_encode(array("success" => true));
        
    }
    elseif ($type == "regions"){
        switch($_SERVER['REQUEST_METHOD'])
        {
            case 'GET':
                $vsys       = (string) (isset($_GET['vsys'])       ? $_GET['vsys'] : '');
                $source     = (string) (isset($_GET['source'])     ? $_GET['source'] : '');
                $id         = (string) (isset($_GET['id'])         ? $_GET['id'] : '');
                $name       = (string) (isset($_GET['name'])       ? $_GET['name'] : '');
                $name_combo = (string) (isset($_GET['name_combo']) ? $_GET['name_combo'] : '');
                $is_enable_geo_location = (string) (isset($_GET['is_enable_geo_location_expand-checkbox']) ? $_GET['is_enable_geo_location_expand-checkbox'] : '');
                $latitude   = (string) (isset($_GET['latitude'])   ? $_GET['latitude'] : '');
                $longitude  = (string) (isset($_GET['longitude'])  ? $_GET['longitude'] : '');
                $table_name = (string) (isset($_GET['table_name']) ? $_GET['table_name'] : '');
                break;
            case 'POST':
                $vsys       = (string) (isset($_POST['vsys'])       ? $_POST['vsys'] : '');
                $source     = (string) (isset($_POST['source'])     ? $_POST['source'] : '');
                $id         = (string) (isset($_POST['id'])         ? $_POST['id'] : '');
                $name       = (string) (isset($_POST['name'])       ? $_POST['name'] : '');
                $name_combo = (string) (isset($_POST['name_combo']) ? $_POST['name_combo'] : '');
                $is_enable_geo_location = (string) (isset($_POST['is_enable_geo_location_expand-checkbox']) ? $_POST['is_enable_geo_location_expand-checkbox'] : '');
                $latitude   = (string) (isset($_POST['latitude'])   ? $_POST['latitude'] : '');
                $longitude  = (string) (isset($_POST['longitude'])  ? $_POST['longitude'] : '');
                $table_name = (string) (isset($_POST['table_name']) ? $_POST['table_name'] : '');
                break;
            default:
                $vsys       = (string) (isset($_POST['vsys'])       ? $_POST['vsys'] : '');
                $source     = (string) (isset($_POST['source'])     ? $_POST['source'] : '');
                $id         = (string) (isset($_POST['id'])         ? $_POST['id'] : '');
                $name       = (string) (isset($_POST['name'])       ? $_POST['name'] : '');
                $name_combo = (string) (isset($_POST['name_combo']) ? $_POST['name_combo'] : '');
                $is_enable_geo_location = (string) (isset($_POST['is_enable_geo_location_expand-checkbox']) ? $_POST['is_enable_geo_location_expand-checkbox'] : '');
                $latitude   = (string) (isset($_POST['latitude'])   ? $_POST['latitude'] : '');
                $longitude  = (string) (isset($_POST['longitude'])  ? $_POST['longitude'] : '');
                $table_name = (string) (isset($_POST['table_name']) ? $_POST['table_name'] : '');
                break;
        }

        $vsys = $projectdb->real_escape_string($vsys);
        $source = $projectdb->real_escape_string($source);
        $id = $projectdb->real_escape_string($id);
        $name = $projectdb->real_escape_string($name);
        $name_combo = $projectdb->real_escape_string($name_combo);
        $is_enable_geo_location = $projectdb->real_escape_string($is_enable_geo_location);
        $latitude = $projectdb->real_escape_string($latitude);
        $longitude = $projectdb->real_escape_string($longitude);
        $table_name = $projectdb->real_escape_string($table_name);

        $is_not_correct = 0;
        $is_new = 0;
        
        take_snapshot_last($project);
        
        if($id == ""){
            $address = "";
            $getAddress = $projectdb->query("SELECT name FROM edit_table WHERE lid = '0' AND user_id = '$user_id';");
            if ($getAddress->num_rows == 1) {
                $dataA = $getAddress->fetch_assoc();
                $address = $dataA['name'];
            }
            $projectdb->query("INSERT INTO regions (address,source,vsys)  VALUES ('$address','$source','$vsys');");
            $id = $projectdb->insert_id;
            $is_new = 1;
            
        }
        
        if(($name == "") && ($name_combo == "")){
            echo json_encode(array("success"=>false, "msg"=>"The name is empty!"));
        }
        else{

            if($name == ""){
                $name = $name_combo;
            }

            // Check the name doesn't exist!
            $getExistName = $projectdb->query("SELECT name FROM regions WHERE id != '$id' AND BINARY name = '$name' AND source = '$source' AND vsys = '$vsys';");
            if ($getExistName->num_rows == 0){

                if($is_enable_geo_location != "on"){
                    $latitude = "";
                    $longitude = "";
                }
                else{
                    if(($latitude <= -91) || ($latitude >= 91) || ($latitude == "")){
                        $is_not_correct = 1;
                        $msg = "The values of Latitude ​​are not correct [-90.0 - 90.0]!";
                    }
                    if(($longitude <= -181) || ($longitude >= 181) || ($longitude == "")){
                        $is_not_correct = 1;
                        $msg = "The values of Longitude ​​are not correct [-180.0 - 180.0]!";
                    }
                }

                if($is_not_correct == 1){
                    echo json_encode(array("success"=>false, "msg"=>$msg));
                }else{
                    $projectdb->query("UPDATE regions SET name = '$name', latitude = '$latitude', longitude = '$longitude'  WHERE id = '$id';");
                    echo json_encode(array("success"=>true));
                }

            }
            else{
                if($is_new == 1){
                    $projectdb->query("DELETE FROM regions WHERE id = '$id';");
                }
                echo json_encode(array("success"=>false, "msg"=>"The name already exist!"));
            }
        }

    }
} 
elseif ($action == "convert") {
    if ($type == "shared") {
        switch($_SERVER['REQUEST_METHOD'])
        {
            case 'GET':
                $source = (string) (isset($_GET['source']) ? $_GET['source'] : '');
                $ids    = (string) (isset($_GET['ids'])    ? $_GET['ids'] : '');
                break;
            case 'POST':
                $source = (string) (isset($_POST['source']) ? $_POST['source'] : '');
                $ids    = (string) (isset($_POST['ids'])    ? $_POST['ids'] : '');
                break;

            default:
                $source = (string) (isset($_POST['source']) ? $_POST['source'] : '');
                $ids    = (string) (isset($_POST['ids'])    ? $_POST['ids'] : '');;
                break;
        }


        $source = $projectdb->real_escape_string($source);
        $ids = $projectdb->real_escape_string($ids);

        $remove_address = array();
        if ($ids != "") {
            take_snapshot_last($project);
            $member_Regions = explode(',',$ids);
            $return = convertRegionsToShared($source, $member_Regions, "notall");
            if($return == 1){
                echo json_encode(array("success" => true));
            }else{
                echo json_encode(array("success" => false));
            }
        }
    }
    elseif ($type == "clone") {
        switch($_SERVER['REQUEST_METHOD'])
        {
            case 'GET':
                $source         = (string) (isset($_GET['source']) ? $_GET['source'] : '');
                $vsys           = (string) (isset($_GET['vsys'])   ? $_GET['vsys'] : '');
                $ids            = (string) (isset($_GET['ids'])    ? $_GET['ids'] : '');
                $clone_to_vsys  = (string) (isset($_GET['combo'])  ? $_GET['combo'] : '');
                break;
            case 'POST':
                $source         = (string) (isset($_POST['source']) ? $_POST['source'] : '');
                $vsys           = (string) (isset($_POST['vsys'])   ? $_POST['vsys'] : '');
                $ids            = (string) (isset($_POST['ids'])    ? $_POST['ids'] : '');
                $clone_to_vsys  = (string) (isset($_POST['combo'])  ? $_POST['combo'] : '');
                break;

            default:
                $source         = (string) (isset($_POST['source']) ? $_POST['source'] : '');
                $vsys           = (string) (isset($_POST['vsys'])   ? $_POST['vsys'] : '');
                $ids            = (string) (isset($_POST['ids'])    ? $_POST['ids'] : '');
                $clone_to_vsys  = (string) (isset($_POST['combo'])  ? $_POST['combo'] : '');
                break;
        }
//        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
//        $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
//        $ids = (string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']);
//        $clone_to_vsys = (string) (isset($_POST['combo']) ? $_POST['combo'] : $_GET['combo']);

        $source = $projectdb->real_escape_string($source);
        $vsys = $projectdb->real_escape_string($vsys);
        $ids = $projectdb->real_escape_string($ids);
        $clone_to_vsys = $projectdb->real_escape_string($clone_to_vsys);

        if ($ids != "") {
            take_snapshot_last($project);
            $member_Regions = explode(',',$ids);
            $return = cloneRegions($source, $vsys, $clone_to_vsys, $member_Regions);
            if($return != 0){
                echo json_encode(array("success" => true));
            }else{
                echo json_encode(array("success" => false));
            }  
        }
        
    }
} 
elseif($action == "remove"){
    if ($type == "regions_address"){
        switch($_SERVER['REQUEST_METHOD'])
        {
            case 'GET':
                $vsys       = (string) (isset($_GET['vsys'])       ? $_GET['vsys'] : '');
                $source     = (string) (isset($_GET['source'])     ? $_GET['source'] : '');
                $idx        = (string) (isset($_GET['idx'])        ? $_GET['idx'] : '');
                $table_name = (string) (isset($_GET['table_name']) ? $_GET['table_name'] : '');
                $changes    = (string) (isset($_GET['changes'])    ? $_GET['changes'] : '');
                break;
            case 'POST':
                $vsys       = (string) (isset($_POST['vsys'])       ? $_POST['vsys'] : '');
                $source     = (string) (isset($_POST['source'])     ? $_POST['source'] : '');
                $idx        = (string) (isset($_POST['idx'])        ? $_POST['idx'] : '');
                $table_name = (string) (isset($_POST['table_name']) ? $_POST['table_name'] : '');
                $changes    = (string) (isset($_POST['changes'])    ? $_POST['changes'] : '');
                break;

            default:
                $vsys       = (string) (isset($_POST['vsys'])       ? $_POST['vsys'] : '');
                $source     = (string) (isset($_POST['source'])     ? $_POST['source'] : '');
                $idx        = (string) (isset($_POST['idx'])        ? $_POST['idx'] : '');
                $table_name = (string) (isset($_POST['table_name']) ? $_POST['table_name'] : '');
                $changes    = (string) (isset($_POST['changes'])    ? $_POST['changes'] : '');
                break;
        }

        $vsys = $projectdb->real_escape_string($vsys);
        $source = $projectdb->real_escape_string($source);
        $idx = $projectdb->real_escape_string($idx);
        $table_name = $projectdb->real_escape_string($table_name);
        $changes = $projectdb->real_escape_string($changes);

        $data = explode(",", $changes);
        
        take_snapshot_last($project);
        
        if($idx != ""){
            $getAddress = $projectdb->query("SELECT address FROM $table_name WHERE id='$idx';");
            if ($getAddress->num_rows == 1) {
                $dataA = $getAddress->fetch_assoc();
                $permitted = $dataA['address'];
                $add_array = explode(",", $permitted);
            }
            $diff = array_diff($add_array, $data);

            $projectdb->query("UPDATE $table_name SET address = '" . implode(",", $diff) . "' WHERE id='$idx';");
        }
        else{
            $getAddress = $projectdb->query("SELECT name FROM edit_table WHERE lid = '0' AND user_id = '$user_id';");
            if ($getAddress->num_rows == 1) {
                $dataA = $getAddress->fetch_assoc();
                $permitted = $dataA['name'];
                $add_array = explode(",", $permitted);
            }
            $diff = array_diff($add_array, $data);

            $projectdb->query("UPDATE edit_table SET name = '" . implode(",", $diff) . "' WHERE lid = '0' AND user_id = '$user_id';");
        }
        
        
        echo json_encode(array("success" => true));
        
    }
    elseif($type == "regions"){
        switch($_SERVER['REQUEST_METHOD'])
        {
            case 'GET':
                $source     = (string) (isset($_GET['source'])     ? $_GET['source'] : '');
                $ids        = (string) (isset($_GET['ids'])        ? $_GET['ids'] : '');
                break;
            case 'POST':
                $source     = (string) (isset($_POST['source'])     ? $_POST['source'] : '');
                $ids        = (string) (isset($_POST['ids'])        ? $_POST['ids'] : '');
                break;

            default:
                $source     = (string) (isset($_POST['source'])     ? $_POST['source'] : '');
                $ids        = (string) (isset($_POST['ids'])        ? $_POST['ids'] : '');
                break;
        }

        $source = $projectdb->real_escape_string($source);
        $ids = $projectdb->real_escape_string($ids);
        
        if ($ids != "") {
            check_used_objects_new();
            take_snapshot_last($project);
            
            $data = explode(",", $ids);
            foreach ($data as $key => $value) {
                
                $getUsed = $projectdb->query("SELECT used FROM regions WHERE id = '$value';");
                if ($getUsed->num_rows == 1) {
                    $getData = $getUsed->fetch_assoc();
                    if ($getData['used'] == 0) {
                        $projectdb->query("DELETE FROM regions WHERE id='$value';");
                    }
                }
            }
        }
    }
}


?>