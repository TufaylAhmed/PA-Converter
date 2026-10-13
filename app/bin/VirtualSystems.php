<?php

# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
require_once('./Authentication.php');
require_once INC_ROOT.'/libs/shared.php';
require_once INC_ROOT.'/libs/common/tools/filters.php';
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';

include INC_ROOT.'/bin/middleware_sanitizer.php';

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $action     = (string)  (isset($_GET['action'])    ? $_GET['action'] : '');
        $type       = (string)  (isset($_GET['type'])      ? $_GET['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_GET['project'])   ? $_GET['project'] : '');
        $devicename = (string)  (isset($_GET['devicename'])? $_GET['devicename'] : '');
        $template   = (string)  (isset($_GET['template'])  ? $_GET['template'] : '');
        $source     = (string)  (isset($_GET['source'])    ? $_GET['source'] : '');
        $start      = (integer) (isset($_GET['start'])     ? $_GET['start'] : '');
        $limit      = (integer) (isset($_GET['limit'])     ? $_GET['limit'] : '');
        $vsys       = (string)  (isset($_GET['vsys'])       ? $_GET['vsys'] : '');
        $filter     = (string)  (isset($_GET['filter'])     ? $_GET['filter'] : '');
        break;
    case 'POST':
        $action     = (string)  (isset($_POST['action'])    ? $_POST['action'] : '');
        $type       = (string)  (isset($_POST['type'])      ? $_POST['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_POST['project'])   ? $_POST['project'] : '');
        $devicename = (string)  (isset($_POST['devicename'])? $_POST['devicename'] : '');
        $template   = (string)  (isset($_POST['template'])  ? $_POST['template'] : '');
        $source     = (string)  (isset($_POST['source'])    ? $_POST['source'] : '');
        $start      = (integer) (isset($_POST['start'])     ? $_POST['start'] : '');
        $limit      = (integer) (isset($_POST['limit'])     ? $_POST['limit'] : '');
        $vsys       = (string)  (isset($_POST['vsys'])      ? $_POST['vsys'] : '');
        $filter     = (string)  (isset($_POST['filter'])    ? $_POST['filter'] : '');
        break;

    default:
        $action     = (string)  (isset($_POST['action'])    ? $_POST['action'] : '');
        $type       = (string)  (isset($_POST['type'])      ? $_POST['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_POST['project'])   ? $_POST['project'] : '');
        $devicename = (string)  (isset($_POST['devicename'])? $_POST['devicename'] : '');
        $template   = (string)  (isset($_POST['template'])  ? $_POST['template'] : '');
        $source     = (string)  (isset($_POST['source'])    ? $_POST['source'] : '');
        $start      = (integer) (isset($_POST['start'])     ? $_POST['start'] : '');
        $limit      = (integer) (isset($_POST['limit'])     ? $_POST['limit'] : '');
        $vsys       = (string)  (isset($_POST['vsys'])      ? $_POST['vsys'] : '');
        $filter     = (string)  (isset($_POST['filter'])    ? $_POST['filter'] : '');
        break;
}

require_once INC_ROOT.'/libs/projectdb.php';
$projectdb = selectDatabase($project);

$action = $projectdb->real_escape_string($action);
$type = $projectdb->real_escape_string($type);
$project = $projectdb->real_escape_string($project);
$devicename = $projectdb->real_escape_string($devicename);
$template = $projectdb->real_escape_string($template);
$source = $projectdb->real_escape_string($source);
$start = $projectdb->real_escape_string($start);
$limit = $projectdb->real_escape_string($limit);
$vsys = $projectdb->real_escape_string($vsys);
$filter = $projectdb->real_escape_string($filter);

if ($action == "get") {
    if ($type == "vsys") {

        //$query = generate_query("template");
        $query = generate_query("template_not_vsys_all");

        //$query = " WHERE source = '$source'";
        //if ($template != 0) {
        //    $query .= " AND (template = '$template')";
        //}

        if(($filter != "none") && ($filter != "0")){

            $params['tools_where_columns_id'] = $filter;
            $params['tools_operator_id'] = "contains";
            $params['search'] = "";
            $params['tools_where_id'] = "30";
            $params['tools_advanced_columns_id'] = "None";
            $params['is_set_sql_filter'] = "yes";
            $params['source'] = $source;
            $params['vsys'] = "all";
            $params['case_sensitive'] = "0";

            setFilter($project, $params);
            executeSQL($project, $params);

        }
        elseif(($filter == "none") || ($filter == "0")){
        }

        list($query, $orderby) = generateQueryFilters($project, "virtual_systems", "", $query, $source);

        /* if ($source=="0"){
          $query="";
          }
          else{
          $query=" WHERE source='$source'";
          } */

        # Remove vsys from the $query it doesnt exists in the virtual_systems table

        $query = "SELECT * FROM virtual_systems $query ORDER BY id,name;";
        //echo $query;
        $getAll = $projectdb->query($query);
        $count = $getAll->num_rows;
        if ($count > 0) {
            while ($data = $getAll->fetch_assoc()) {
                $myData[] = $data;
            }
        } else {
            // this means that the source is not a panorama then get the vsys defined for the given source
            $getFilenanme = $projectdb->query("SELECT filename, vendor, ispanorama FROM device_mapping WHERE id = '$source';");
            if ($getFilenanme->num_rows == 1) {

                $alldata = $getFilenanme->fetch_assoc();
                $filename = $alldata['filename'];
                $vendor = $alldata['vendor'];
                $ispanorama = $alldata['ispanorama'];

                if (($template == "all") || ($template == "") || ($template == "0") || ($template == "templates-all")) {
                    $query = "";
                } else {
                    $query = "AND template = '$template' ";
                }

                if ($vendor == "Paloalto Networks") {

                    $getAll = $projectdb->query("SELECT distinct(vs.name) AS vsys, vs.template as template , vs.id as id, vs.source, dm.version, dm.vendor 
                        FROM virtual_systems vs, device_mapping dm WHERE vs.name != dm.vsys AND dm.filename = '$filename' $query GROUP BY vsys ORDER BY vsys;");

                    while ($data = $getAll->fetch_assoc()) {

                        $vsys_record = [
                            "id"=>addslashes($data['id']),
                            "template"=>addslashes($data['template']),
                            "source"=>"$source",
                            "name"=> addslashes($data['vsys']),
                            "name_ext"=>"",
                            "display_name"=>"",
                            "interfaces"=>"",
                            "virtual_router"=>"",
                            "virtual_wire"=>"",
                            "vlan"=>"",
                            "max_application_override_rules"=>"0",
                            "max_concurrent_ssl_vpn_tunnels"=>"0",
                            "max_cp_rules"=>"0",
                            "max_dos_rules"=>"0",
                            "max_nat_rules"=>"0",
                            "max_pbf_rules"=>"0",
                            "max_qos_rules"=>"0",
                            "max_security_rules"=>"0",
                            "max_sessions"=>"0",
                            "max_site_to_site_vpn_tunnels"=>"0",
                            "max_ssl_decryption_rules"=>"0",
                            "visible_vsys"=>"",
                            "dns_proxy"=>"",
                            "allow_forward_decrypted_content"=>"",
                            "dummy"=>"0"
                        ];

                        $myData[] = $vsys_record;
                    }

                } else {
                    $getAll = $projectdb->query("SELECT id,vsys,version,vendor FROM device_mapping WHERE filename='$filename' ORDER BY vsys;");
                    while ($data = $getAll->fetch_assoc()) {
                        $vsys_record = [
                            "id"=>addslashes($data['id']),
                            "template"=>addslashes($template),
                            "source"=>"$source",
                            "name"=> addslashes($data['vsys']),
                            "name_ext"=>"",
                            "display_name"=>"",
                            "interfaces"=>"",
                            "virtual_router"=>"",
                            "virtual_wire"=>"",
                            "vlan"=>"",
                            "max_application_override_rules"=>"0",
                            "max_concurrent_ssl_vpn_tunnels"=>"0",
                            "max_cp_rules"=>"0",
                            "max_dos_rules"=>"0",
                            "max_nat_rules"=>"0",
                            "max_pbf_rules"=>"0",
                            "max_qos_rules"=>"0",
                            "max_security_rules"=>"0",
                            "max_sessions"=>"0",
                            "max_site_to_site_vpn_tunnels"=>"0",
                            "max_ssl_decryption_rules"=>"0",
                            "visible_vsys"=>"",
                            "dns_proxy"=>"",
                            "allow_forward_decrypted_content"=>"",
                            "dummy"=>"0"
                        ];

                        $myData[] = $vsys_record;

                    }
                }
            }else{
                $myData = "";
            }


        }

        echo '{"total":"' . $count . '","vsys":' . json_encode($myData) . '}';
    } 
    elseif ($type == "vsys_vsys") {

        $query = generate_query("template_not_vsys");
        
        $getAll = $projectdb->query("SELECT * FROM virtual_systems $query ORDER BY id,name;");
        $count = $getAll->num_rows;
        if ($count > 0) {
            $myData[] = array("name" => "All Visible vsys");
            while ($data = $getAll->fetch_assoc()) {
                $myData[] = $data;
            }
        } else {
            $myData = "";
        }
        echo '{"total":"' . $count . '","vsys":' . json_encode($myData) . '}';
    }
    elseif ($type == "interfaces") {
        $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        $idx = (string) (isset($_POST['idx']) ? $_POST['idx'] : $_GET['idx']);

        $vsys = $projectdb->real_escape_string($vsys);
        $source = $projectdb->real_escape_string($source);
        $idx = $projectdb->real_escape_string($idx);

        $filter = $projectdb->real_escape_string($filter);

        if ($idx != "") {
            $thetag = array();
            $getTag = $projectdb->query("SELECT interfaces FROM virtual_systems WHERE id='$idx';");
            if ($getTag->num_rows == 1) {
                $getTagData = $getTag->fetch_assoc();
                $tags = $getTagData['interfaces'];
                $tag = explode(",", $tags);
                $count = count($tag);
                foreach ($tag as $key => $value) {
                    $thetag[] = array("name" => $value);
                }
                if ($tags == "") {
                    $count = 0;
                    $thetag = "";
                }
                echo '{"total":"' . $count . '","elements":' . json_encode($thetag) . '}';
            }
        }
    } 
    elseif ($type == "vlans") {
        $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        $idx = (string) (isset($_POST['idx']) ? $_POST['idx'] : $_GET['idx']);

        $vsys = $projectdb->real_escape_string($vsys);
        $source = $projectdb->real_escape_string($source);
        $idx = $projectdb->real_escape_string($idx);

        if ($idx != "") {
            $thetag = array();
            $getTag = $projectdb->query("SELECT vlan FROM virtual_systems WHERE id='$idx';");
            if ($getTag->num_rows == 1) {
                $getTagData = $getTag->fetch_assoc();
                $tags = $getTagData['vlan'];
                $tag = explode(",", $tags);
                $count = count($tag);
                foreach ($tag as $key => $value) {
                    $thetag[] = array("name" => $value);
                }
                if ($tags == "") {
                    $count = 0;
                    $thetag = "";
                }
                echo '{"total":"' . $count . '","elements":' . json_encode($thetag) . '}';
            }
        }
    } 
    elseif ($type == "vwires") {
        $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        $idx = (string) (isset($_POST['idx']) ? $_POST['idx'] : $_GET['idx']);

        $vsys = $projectdb->real_escape_string($vsys);
        $source = $projectdb->real_escape_string($source);
        $idx = $projectdb->real_escape_string($idx);

        if ($idx != "") {
            $thetag = array();
            $getTag = $projectdb->query("SELECT virtual_wire FROM virtual_systems WHERE id='$idx';");
            if ($getTag->num_rows == 1) {
                $getTagData = $getTag->fetch_assoc();
                $tags = $getTagData['virtual_wire'];
                $tag = explode(",", $tags);
                $count = count($tag);
                foreach ($tag as $key => $value) {
                    $thetag[] = array("name" => $value);
                }
                if ($tags == "") {
                    $count = 0;
                    $thetag = "";
                }
                echo '{"total":"' . $count . '","elements":' . json_encode($thetag) . '}';
            }
        }
    } 
    elseif ($type == "vr") {
        $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        $idx = (string) (isset($_POST['idx']) ? $_POST['idx'] : $_GET['idx']);

        $vsys = $projectdb->real_escape_string($vsys);
        $source = $projectdb->real_escape_string($source);
        $idx = $projectdb->real_escape_string($idx);

        if ($idx != "") {
            $thetag = array();
            $getTag = $projectdb->query("SELECT virtual_router FROM virtual_systems WHERE id='$idx';");
            if ($getTag->num_rows == 1) {
                $getTagData = $getTag->fetch_assoc();
                $tags = $getTagData['virtual_router'];
                $tag = explode(",", $tags);
                $count = count($tag);
                foreach ($tag as $key => $value) {
                    $thetag[] = array("name" => $value);
                }
                if ($tags == "") {
                    $count = 0;
                    $thetag = "";
                }
                echo '{"total":"' . $count . '","elements":' . json_encode($thetag) . '}';
            }
        }
    } 
    elseif ($type == "visible") {
        $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        $idx = (string) (isset($_POST['idx']) ? $_POST['idx'] : $_GET['idx']);

        $vsys = $projectdb->real_escape_string($vsys);
        $source = $projectdb->real_escape_string($source);
        $idx = $projectdb->real_escape_string($idx);

        if ($idx != "") {
            $thetag = array();
            $getTag = $projectdb->query("SELECT visible_vsys FROM virtual_systems WHERE id='$idx';");
            if ($getTag->num_rows == 1) {
                $getTagData = $getTag->fetch_assoc();
                $tags = $getTagData['visible_vsys'];
                $tag = explode(",", $tags);
                $count = count($tag);
                foreach ($tag as $key => $value) {
                    $thetag[] = array("name" => $value);
                }
                if ($tags == "") {
                    $count = 0;
                    $thetag = "";
                }
                echo '{"total":"' . $count . '","elements":' . json_encode($thetag) . '}';
            }
        }
    }
} 
elseif ($action == "set") {
    if ($type == "remove_interface") {
        $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        $idx = (string) (isset($_POST['idx']) ? $_POST['idx'] : $_GET['idx']);
        $ids = (string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']);

        $vsys = $projectdb->real_escape_string($vsys);
        $source = $projectdb->real_escape_string($source);
        $idx = $projectdb->real_escape_string($idx);
        $ids = $projectdb->real_escape_string($ids);

        $data = explode(",", $ids);
        $getTags = $projectdb->query("SELECT interfaces,template FROM virtual_systems WHERE id='$idx';");
        if ($getTags->num_rows == 1) {
            $getTagsData = $getTags->fetch_assoc();
            $tag = $getTagsData['interfaces'];
            $template = $getTagsData['template'];
            $tag_array = explode(",", $tag);
        }
        $diff = array_diff($tag_array, $data);
        $projectdb->query("UPDATE virtual_systems SET interfaces='" . implode(",", $diff) . "' WHERE id='$idx';");

        #Update Interfaces
        foreach ($data as $key => $value) {
            $projectdb->query("UPDATE interfaces SET vsys='' WHERE source='$source' AND template='$template' AND unitname='$value';");
        }
        echo json_encode(array("success" => true));
    } 
    elseif ($type == "remove_vlan") {
        $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        $idx = (string) (isset($_POST['idx']) ? $_POST['idx'] : $_GET['idx']);
        $ids = (string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']);

        $vsys = $projectdb->real_escape_string($vsys);
        $source = $projectdb->real_escape_string($source);
        $idx = $projectdb->real_escape_string($idx);
        $ids = $projectdb->real_escape_string($ids);

        $data = explode(",", $ids);
        $getTags = $projectdb->query("SELECT vlan FROM virtual_systems WHERE id='$idx';");
        if ($getTags->num_rows == 1) {
            $getTagsData = $getTags->fetch_assoc();
            $tag = $getTagsData['vlan'];
            $tag_array = explode(",", $tag);
        }
        $diff = array_diff($tag_array, $data);
        $projectdb->query("UPDATE virtual_systems SET vlan='" . implode(",", $diff) . "' WHERE id='$idx';");
        echo json_encode(array("success" => true));
    } 
    elseif ($type == "remove_vwire") {
        $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        $idx = (string) (isset($_POST['idx']) ? $_POST['idx'] : $_GET['idx']);
        $ids = (string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']);

        $vsys = $projectdb->real_escape_string($vsys);
        $source = $projectdb->real_escape_string($source);
        $idx = $projectdb->real_escape_string($idx);
        $ids = $projectdb->real_escape_string($ids);

        $data = explode(",", $ids);
        $getTags = $projectdb->query("SELECT virtual_wire FROM virtual_systems WHERE id='$idx';");
        if ($getTags->num_rows == 1) {
            $getTagsData = $getTags->fetch_assoc();
            $tag = $getTagsData['virtual_wire'];
            $tag_array = explode(",", $tag);
        }
        $diff = array_diff($tag_array, $data);
        $projectdb->query("UPDATE virtual_systems SET virtual_wire='" . implode(",", $diff) . "' WHERE id='$idx';");
        echo json_encode(array("success" => true));
    } 
    elseif ($type == "remove_vr") {
        $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        $idx = (string) (isset($_POST['idx']) ? $_POST['idx'] : $_GET['idx']);
        $ids = (string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']);

        $vsys = $projectdb->real_escape_string($vsys);
        $source = $projectdb->real_escape_string($source);
        $idx = $projectdb->real_escape_string($idx);
        $ids = $projectdb->real_escape_string($ids);

        $data = explode(",", $ids);
        $getTags = $projectdb->query("SELECT virtual_router FROM virtual_systems WHERE id='$idx';");
        if ($getTags->num_rows == 1) {
            $getTagsData = $getTags->fetch_assoc();
            $tag = $getTagsData['virtual_router'];
            $tag_array = explode(",", $tag);
        }
        $diff = array_diff($tag_array, $data);
        $projectdb->query("UPDATE virtual_systems SET virtual_router='" . implode(",", $diff) . "' WHERE id='$idx';");
        echo json_encode(array("success" => true));
    } 
    elseif ($type == "remove_visible") {
        $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        $idx = (string) (isset($_POST['idx']) ? $_POST['idx'] : $_GET['idx']);
        $ids = (string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']);

        $vsys = $projectdb->real_escape_string($vsys);
        $source = $projectdb->real_escape_string($source);
        $idx = $projectdb->real_escape_string($idx);
        $ids = $projectdb->real_escape_string($ids);

        $data = explode(",", $ids);
        $getTags = $projectdb->query("SELECT visible_vsys FROM virtual_systems WHERE id='$idx';");
        if ($getTags->num_rows == 1) {
            $getTagsData = $getTags->fetch_assoc();
            $tag = $getTagsData['visible_vsys'];
            $tag_array = explode(",", $tag);
        }
        $diff = array_diff($tag_array, $data);
        $projectdb->query("UPDATE virtual_systems SET visible_vsys='" . implode(",", $diff) . "' WHERE id='$idx';");
        echo json_encode(array("success" => true));
    } 
    elseif ($type == "remove_vsys") {
        $ids = (string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']);
        $ids = $projectdb->real_escape_string($ids);

        $getVSYS = $projectdb->query("SELECT active,device,filename,vendor,version,baseconfig,ispanorama FROM device_mapping WHERE id='$source';");
        if ($getVSYS->num_rows == 1) {
            $data = $getVSYS->fetch_assoc();
            $source_filename = $data['filename'];
            $vendor = $data['vendor'];
        }

        $array = explode(",", $ids);
        foreach ($array as $key => $theid) {
            $getName = $projectdb->query("SELECT name FROM virtual_systems WHERE id='$theid';");
            if ($getName->num_rows == 1) {
                $data = $getName->fetch_assoc();
                $vsysname = $data['name'];
                $projectdb->query("DELETE FROM virtual_systems WHERE id ='$theid';");
                $getMore = $projectdb->query("SELECT id FROM virtual_systems WHERE name='$vsysname' AND source='$source';");
                if ($getMore->num_rows == 0) {
                    $projectdb->query("DELETE FROM device_mapping WHERE filename='$source_filename' AND vsys='$vsysname';");
                }
                
                // Check if vsysname exist in visible_vsys in virtual_systems and update
                $getVisible = $projectdb->query("SELECT id, visible_vsys FROM virtual_systems WHERE visible_vsys != '' AND source='$source';");
                if ($getVisible->num_rows == 1) {
                    while($dataV = $getVisible->fetch_assoc()){
                        $visible_vsys = $dataV['visible_vsys'];
                        $id_visible_vsys = $dataV['id'];
                        
                        $visible_vsys_array = explode(",", $visible_vsys);
                        
                        if (($key = array_search($vsysname, $visible_vsys_array)) !== false) {
                            unset($visible_vsys_array[$key]);
                            
                            $projectdb->query("UPDATE virtual_systems SET visible_vsys ='" . implode(",", $visible_vsys_array) . "' WHERE id='$id_visible_vsys';");
                        }
                        
                    }
                }
                
                
            }
        }

        $projectdb->query("DELETE FROM virtual_systems WHERE id IN(" . $ids . ");");
    }
} 
elseif ($action == "add") {
    if ($type == "interfaces") {
        $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        $idx = (string) (isset($_POST['idx']) ? $_POST['idx'] : $_GET['idx']);
        $total_name = (string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']);
        $template = (string) (isset($_POST['template']) ? $_POST['template'] : $_GET['template']);

        $vsys = $projectdb->real_escape_string($vsys);
        $source = $projectdb->real_escape_string($source);
        $idx = $projectdb->real_escape_string($idx);
        $total_name = $projectdb->real_escape_string($total_name);
        $template = $projectdb->real_escape_string($template);

        $query = generate_query("template_not_vsys");
        $set_all_interfaces = 0;
        
        $getInterfaces = $projectdb->query("SELECT template,interfaces FROM virtual_systems WHERE id='$idx';");
        if ($getInterfaces->num_rows == 1) {
            $dataI = $getInterfaces->fetch_assoc();
            $interfaces = $dataI['interfaces'];
            $template = $dataI['template'];
            
            if ($interfaces != "") {
                
                $interfaces_array = explode(",", $interfaces);
                $names_interfaces_array = explode(",", $total_name);
                
                foreach($names_interfaces_array AS $name){
                    
                    if($set_all_interfaces != 1){
                    
                        if($name == "All Interfaces"){

                            $set_all_interfaces = 1;
                            $getAllInterfaces = $projectdb->query("SELECT id,unitname FROM interfaces $query ORDER BY unitname;");
                            $count = $getAllInterfaces->num_rows;
                            if($count > 0){
                                while ($dataAI = $getAllInterfaces->fetch_assoc()) {
                                    $unitname_array[] = $dataAI['unitname'];
                                    $id_interfaces_array[] = $dataAI['id'];
                                }
                                $ids_all_interfaces = implode(",", $id_interfaces_array);
                                $projectdb->query("UPDATE virtual_systems SET interfaces='" . implode(",", $unitname_array) . "' WHERE id='$idx';");
                                $projectdb->query("UPDATE interfaces SET vsys='$vsys' WHERE template='$template' AND id IN ($ids_all_interfaces);");
                            }
                        }
                        else{
                            if (in_array($name, $interfaces_array)) {

                            } else {
                                $interfaces_array[] = $name;
                                if (($key = array_search("", $interfaces_array)) !== false) {
                                    unset($interfaces_array[$key]);
                                }
                                $projectdb->query("UPDATE virtual_systems SET interfaces='" . implode(",", $interfaces_array) . "' WHERE id='$idx';");
                                $projectdb->query("UPDATE interfaces SET vsys='$vsys' WHERE template='$template' AND unitname='$name';");
                            }
                        }
                    }
                }
            } 
            else {
                
                $projectdb->query("UPDATE virtual_systems SET interfaces='$total_name' WHERE id='$idx';");
                $names_interfaces_array = explode(",", $total_name);
                //aqui tb all interfaces
                foreach($names_interfaces_array AS $name){
                    
                    if($set_all_interfaces != 1){
                        
                        if($name == "All Interfaces"){

                            $set_all_interfaces = 1;
                            $getAllInterfaces = $projectdb->query("SELECT id,unitname FROM interfaces $query ORDER BY unitname;");
                            $count = $getAllInterfaces->num_rows;
                            if($count > 0){
                                while ($dataAI = $getAllInterfaces->fetch_assoc()) {
                                    $unitname_array[] = $dataAI['unitname'];
                                    $id_interfaces_array[] = $dataAI['id'];
                                }
                                $ids_all_interfaces = implode(",", $id_interfaces_array);
                                $projectdb->query("UPDATE virtual_systems SET interfaces='" . implode(",", $unitname_array) . "' WHERE id='$idx';");
                                $projectdb->query("UPDATE interfaces SET vsys='$vsys' WHERE template='$template' AND id IN ($ids_all_interfaces);");
                            }
                        }
                        else{
                            $projectdb->query("UPDATE interfaces SET vsys='$vsys' WHERE template='$template' AND unitname='$name';");
                        }
                    }
                }
            }
        }
        echo json_encode(array("success" => true));
    } 
    elseif ($type == "vr") {
        $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        $idx = (string) (isset($_POST['idx']) ? $_POST['idx'] : $_GET['idx']);
        $table_name = (string) (isset($_POST['table_name']) ? $_POST['table_name'] : $_GET['table_name']);
        $ids = (string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']);
        $total_name = (string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']);
        $template = (string) (isset($_POST['template']) ? $_POST['template'] : $_GET['template']);

        $vsys = $projectdb->real_escape_string($vsys);
        $source = $projectdb->real_escape_string($source);
        $idx = $projectdb->real_escape_string($idx);
        $table_name = $projectdb->real_escape_string($table_name);
        $ids = $projectdb->real_escape_string($ids);
        $total_name = $projectdb->real_escape_string($total_name);
        $template = $projectdb->real_escape_string($template);
        
        $query = generate_query("template");
        $set_all_vr = 0;
        $getVW = $projectdb->query("SELECT name,template, virtual_router FROM virtual_systems WHERE id='$idx';");
        if ($getVW->num_rows == 1) {
            $dataV = $getVW->fetch_assoc();
            $virtual_router = $dataV['virtual_router'];
            $template = $dataV['template'];
            $vsys=$dataV['name'];

            if ($virtual_router != "") {
                $virtual_router_array = explode(",", $virtual_router);
                $names_virtual_router_array = explode(",", $total_name);
                
                foreach($names_virtual_router_array AS $name){
                    if($set_all_vr != 1){
                        if($name == "All Virtual Routers"){
                            $id_vr_array = [];
                            $set_all_vr = 1;
                            $getAllVW = $projectdb->query("SELECT id,name FROM virtual_routers $query ORDER BY name;");
                            $count = $getAllVW->num_rows;
                            if($count > 0){
                                while ($dataV = $getAllVW->fetch_assoc()) {
                                    $name_array[] = $dataV['name'];
                                    $id_vr_array[] = $dataV['id'];
                                }
                                array_filter($name_array);
                                $projectdb->query("UPDATE virtual_systems SET virtual_router ='" . implode(",", $name_array) . "' WHERE id='$idx';");
                                $ids_all_vr = implode(",", $id_vr_array);
                                $projectdb->query("UPDATE virtual_routers SET vsys='$vsys' WHERE template='$template' AND id IN ($ids_all_vr);");
                                update_static_routes_vsys($id_vr_array,$vsys,$template,$source);
                            }
                        }
                        else{
                            if (in_array($name, $virtual_router_array)) {
                    
                            } else {
                                $virtual_router_array[] = $name;
                                if (($key = array_search("", $virtual_router_array)) !== false) {
                                    unset($virtual_router_array[$key]);
                                }
                                $projectdb->query("UPDATE virtual_systems SET virtual_router ='" . implode(",", $virtual_router_array) . "' WHERE id='$idx';");

                                $getVR=$projectdb->query("SELECT id FROM virtual_routers WHERE template='$template' AND name='$name';");
                                if ($getVR->num_rows==1) {
                                    $getVRData = $getVR->fetch_assoc();
                                    $vr_id[] = $getVRData['id'];
                                    $projectdb->query("UPDATE virtual_routers SET vsys='$vsys' WHERE template='$template' AND name='$name';");
                                    update_static_routes_vsys($vr_id,$vsys,$template,$source);
                                }




                            }
                        }
                    }
                }
            } 
            else {
                $projectdb->query("UPDATE virtual_systems SET virtual_router ='$total_name' WHERE id='$idx';");

                $names_virtual_wire_array = explode(",", $total_name);
                foreach($names_virtual_wire_array AS $name){
                    if($set_all_vr != 1){
                        if($name == "All Virtual Routers"){
                            $set_all_vr = 1;
                            $getAllVW = $projectdb->query("SELECT id,name FROM virtual_routers $query ORDER BY name;");
                            $count = $getAllVW->num_rows;
                            if($count > 0){
                                while ($dataVW = $getAllVW->fetch_assoc()) {
                                    $name_array[] = $dataVW['name'];
                                    $id_vr_array[] = $dataVW['id'];
                                }
                                array_filter($name_array);
                                $projectdb->query("UPDATE virtual_systems SET virtual_router='" . implode(",", $name_array) . "' WHERE id='$idx';");
                                $ids_all_vr = implode(",", $id_vr_array);
                                $projectdb->query("UPDATE virtual_routers SET vsys='$vsys' WHERE template='$template' AND id IN ($ids_all_vr);");
                                update_static_routes_vsys($id_vr_array,$vsys,$template,$source);
                            }
                        }
                        else{
                            $getVR=$projectdb->query("SELECT id FROM virtual_routers WHERE template='$template' AND name='$name';");
                            if ($getVR->num_rows==1){
                                $getVRData=$getVR->fetch_assoc();
                                $vr_id[]=$getVRData['id'];
                                update_static_routes_vsys($vr_id,$vsys,$template,$source);
                                $projectdb->query("UPDATE virtual_routers SET vsys='$vsys' WHERE template='$template' AND name='$name';");
                            }


                        }
                    }
                }
            }
        }
        
        /*$getVR = $projectdb->query("SELECT template, virtual_router FROM virtual_systems WHERE id='$idx';");
        if ($getVR->num_rows == 1) {
            $dataV = $getVR->fetch_assoc();
            $vr = $dataV['virtual_router'];
            $template = $dataV['template'];
            
            if ($vr != "") {
                $vr_array = explode(",", $vr);
                $names_vr_array = explode(",", $total_name);
                foreach($names_vr_array AS $name){
                    if (in_array($name, $vr_array)) {
                    
                    } else {
                        $vr_array[] = $name;
                        $projectdb->query("UPDATE virtual_systems SET virtual_router ='" . implode(",", $vr_array) . "' WHERE id='$idx';");
                    }
                }
            } 
            else {
                $projectdb->query("UPDATE virtual_systems SET virtual_router ='$total_name' WHERE id='$idx';");
            }
        }*/
        echo json_encode(array("success" => true));
    } 
    elseif ($type == "vlans") {
        $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        $idx = (string) (isset($_POST['idx']) ? $_POST['idx'] : $_GET['idx']);
        $table_name = (string) (isset($_POST['table_name']) ? $_POST['table_name'] : $_GET['table_name']);
        $ids = (string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']);
        $total_name = (string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']);
        $template = (string) (isset($_POST['template']) ? $_POST['template'] : $_GET['template']);

        $vsys = $projectdb->real_escape_string($vsys);
        $source = $projectdb->real_escape_string($source);
        $idx = $projectdb->real_escape_string($idx);
        $table_name = $projectdb->real_escape_string($table_name);
        $ids = $projectdb->real_escape_string($ids);
        $total_name = $projectdb->real_escape_string($total_name);
        $template = $projectdb->real_escape_string($template);
        
        $query = generate_query("template");
        $set_all_vlans = 0;
        
        $getVlans = $projectdb->query("SELECT template, vlan FROM virtual_systems WHERE id='$idx';");
        if ($getVlans->num_rows == 1) {
            $dataV = $getVlans->fetch_assoc();
            $vlan = $dataV['vlan'];
            $template = $dataV['template'];
            
            if ($vlan != "") {
                $vlan_array = explode(",", $vlan);
                $names_vlan_array = explode(",", $total_name);
                
                foreach($names_vlan_array AS $name){
                    
                    if($set_all_vlans != 1){
                    
                        if($name == "All VLANs"){

                            $set_all_vlans = 1;
                            $getAllVlans = $projectdb->query("SELECT id,name FROM vlans $query ORDER BY name;");
                            $count = $getAllVlans->num_rows;
                            if($count > 0){
                                while ($dataV = $getAllVlans->fetch_assoc()) {
                                    $name_array[] = $dataV['name'];
                                }
                                array_filter($name_array);
                                $projectdb->query("UPDATE virtual_systems SET vlan ='" . implode(",", $name_array) . "' WHERE id='$idx';");
                            }
                        }
                        else{
                            if (in_array($name, $vlan_array)) {
                    
                            } else {
                                $vlan_array[] = $name;
                                if (($key = array_search("", $vlan_array)) !== false) {
                                    unset($vlan_array[$key]);
                                }
                                $projectdb->query("UPDATE virtual_systems SET vlan ='" . implode(",", $vlan_array) . "' WHERE id='$idx';");
                            }
                        }
                    }
                }
            } 
            else {
                $projectdb->query("UPDATE virtual_systems SET vlan ='$total_name' WHERE id='$idx';");
                
                // Check if selected All Vlans
                $names_vlans_array = explode(",", $total_name);
                foreach($names_vlans_array AS $name){
                    
                    if($set_all_vlans != 1){
                        
                        if($name == "All VLANs"){

                            $set_all_vlans = 1;
                            $getAllVlans = $projectdb->query("SELECT id,name FROM vlans $query ORDER BY name;");
                            $count = $getAllVlans->num_rows;
                            if($count > 0){
                                while ($dataAI = $getAllVlans->fetch_assoc()) {
                                    $name_array[] = $dataAI['name'];
                                }
                                array_filter($name_array);
                                $projectdb->query("UPDATE virtual_systems SET vlan='" . implode(",", $name_array) . "' WHERE id='$idx';");
                            }
                        }
                    }
                }
            }
        }
        echo json_encode(array("success" => true));
    } 
    elseif ($type == "visible") {
        $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        $idx = (string) (isset($_POST['idx']) ? $_POST['idx'] : $_GET['idx']);
        $table_name = (string) (isset($_POST['table_name']) ? $_POST['table_name'] : $_GET['table_name']);
        $ids = (string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']);
        $total_name = (string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']);
        $template = (string) (isset($_POST['template']) ? $_POST['template'] : $_GET['template']);

        $vsys = $projectdb->real_escape_string($vsys);
        $source = $projectdb->real_escape_string($source);
        $idx = $projectdb->real_escape_string($idx);
        $table_name = $projectdb->real_escape_string($table_name);
        $ids = $projectdb->real_escape_string($ids);
        $total_name = $projectdb->real_escape_string($total_name);
        $template = $projectdb->real_escape_string($template);
        
        $query = generate_query("template");
        $set_all_vlans = 0;
        
        $getVlans = $projectdb->query("SELECT template, visible_vsys FROM virtual_systems WHERE id='$idx';");
        if ($getVlans->num_rows == 1) {
            $dataV = $getVlans->fetch_assoc();
            $vlan = $dataV['visible_vsys'];
            $template = $dataV['template'];
            
            if ($vlan != "") {
                $vlan_array = explode(",", $vlan);
                $names_vlan_array = explode(",", $total_name);
                
                foreach($names_vlan_array AS $name){
                    
                    if($set_all_vlans != 1){
                    
                        if($name == "All Visible vsys"){

                            $set_all_vlans = 1;
                            $getAllVlans = $projectdb->query("SELECT id,name FROM virtual_systems $query ORDER BY name;");
                            $count = $getAllVlans->num_rows;
                            if($count > 0){
                                while ($dataV = $getAllVlans->fetch_assoc()) {
                                    $name_array[] = $dataV['name'];
                                }
                                array_filter($name_array);
                                $projectdb->query("UPDATE virtual_systems SET visible_vsys ='" . implode(",", $name_array) . "' WHERE id='$idx';");
                            }
                        }
                        else{
                            if (in_array($name, $vlan_array)) {
                    
                            } else {
                                $vlan_array[] = $name;
                                if (($key = array_search("", $vlan_array)) !== false) {
                                    unset($vlan_array[$key]);
                                }
                                $projectdb->query("UPDATE virtual_systems SET visible_vsys ='" . implode(",", $vlan_array) . "' WHERE id='$idx';");
                            }
                        }
                    }
                }
            } 
            else {
                $projectdb->query("UPDATE virtual_systems SET visible_vsys ='$total_name' WHERE id='$idx';");
                
                // Check if selected All Vlans
                $names_vlans_array = explode(",", $total_name);
                foreach($names_vlans_array AS $name){
                    
                    if($set_all_vlans != 1){
                        
                        if($name == "All Visible vsys"){

                            $set_all_vlans = 1;
                            $getAllVlans = $projectdb->query("SELECT id,name FROM virtual_systems $query ORDER BY name;");
                            $count = $getAllVlans->num_rows;
                            if($count > 0){
                                while ($dataAI = $getAllVlans->fetch_assoc()) {
                                    $name_array[] = $dataAI['name'];
                                }
                                array_filter($name_array);
                                $projectdb->query("UPDATE virtual_systems SET visible_vsys='" . implode(",", $name_array) . "' WHERE id='$idx';");
                            }
                        }
                    }
                }
            }
        }
        
        /*$getTags = $projectdb->query("SELECT visible_vsys FROM virtual_systems WHERE id='$idx';");
        if ($getTags->num_rows == 1) {
            $getTagsData = $getTags->fetch_assoc();
            $tag = $getTagsData['visible_vsys'];

            if ($tag != "") {
                $tag_array = explode(",", $tag);
                if (in_array($name, $tag_array)) {
                    
                } else {
                    $tag_array[] = $name;
                    $projectdb->query("UPDATE virtual_systems SET visible_vsys='" . implode(",", $tag_array) . "' WHERE id='$idx';");
                }
            } else {
                $projectdb->query("UPDATE virtual_systems SET visible_vsys='$name' WHERE id='$idx';");
            }
        }*/
        echo json_encode(array("success" => true));
    } 
    elseif ($type == "vwires") {
        $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        $idx = (string) (isset($_POST['idx']) ? $_POST['idx'] : $_GET['idx']);
        $table_name = (string) (isset($_POST['table_name']) ? $_POST['table_name'] : $_GET['table_name']);
        $ids = (string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']);
        $total_name = (string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']);
        $template = (string) (isset($_POST['template']) ? $_POST['template'] : $_GET['template']);

        $vsys = $projectdb->real_escape_string($vsys);
        $source = $projectdb->real_escape_string($source);
        $idx = $projectdb->real_escape_string($idx);
        $table_name = $projectdb->real_escape_string($table_name);
        $ids = $projectdb->real_escape_string($ids);
        $total_name = $projectdb->real_escape_string($total_name);
        $template = $projectdb->real_escape_string($template);
        
        $query = generate_query("template");
        $set_all_vw = 0;
        
        $getVW = $projectdb->query("SELECT template, virtual_wire FROM virtual_systems WHERE id='$idx';");
        if ($getVW->num_rows == 1) {
            $dataV = $getVW->fetch_assoc();
            $virtual_wire = $dataV['virtual_wire'];
            $template = $dataV['template'];
            
            if ($virtual_wire != "") {
                $virtual_wire_array = explode(",", $virtual_wire);
                $names_virtual_wire_array = explode(",", $total_name);
                
                foreach($names_virtual_wire_array AS $name){
                    
                    if($set_all_vw != 1){
                    
                        if($name == "All Virtual Wires"){

                            $set_all_vw = 1;
                            $getAllVW = $projectdb->query("SELECT id,name FROM virtual_wires $query ORDER BY name;");
                            $count = $getAllVW->num_rows;
                            if($count > 0){
                                while ($dataV = $getAllVW->fetch_assoc()) {
                                    $name_array[] = $dataV['name'];
                                }
                                array_filter($name_array);
                                $projectdb->query("UPDATE virtual_systems SET virtual_wire ='" . implode(",", $name_array) . "' WHERE id='$idx';");
                            }
                        }
                        else{
                            if (in_array($name, $virtual_wire_array)) {
                    
                            } else {
                                $virtual_wire_array[] = $name;
                                if (($key = array_search("", $virtual_wire_array)) !== false) {
                                    unset($virtual_wire_array[$key]);
                                }
                                $projectdb->query("UPDATE virtual_systems SET virtual_wire ='" . implode(",", $virtual_wire_array) . "' WHERE id='$idx';");
                            }
                        }
                    }
                }
            } 
            else {
                $projectdb->query("UPDATE virtual_systems SET virtual_wire ='$total_name' WHERE id='$idx';");
                
                // Check if selected All Vlans
                $names_virtual_wire_array = explode(",", $total_name);
                foreach($names_virtual_wire_array AS $name){
                    
                    if($set_all_vw != 1){
                        
                        if($name == "All Virtual Wires"){

                            $set_all_vw = 1;
                            $getAllVW = $projectdb->query("SELECT id,name FROM virtual_wires $query ORDER BY name;");
                            $count = $getAllVW->num_rows;
                            if($count > 0){
                                while ($dataVW = $getAllVW->fetch_assoc()) {
                                    $name_array[] = $dataVW['name'];
                                }
                                array_filter($name_array);
                                $projectdb->query("UPDATE virtual_systems SET virtual_wire='" . implode(",", $name_array) . "' WHERE id='$idx';");
                            }
                        }
                    }
                }
            }
        }
        
        /*$getVW = $projectdb->query("SELECT template, virtual_wire FROM virtual_systems WHERE id='$idx';");
        if ($getVW->num_rows == 1) {
            $dataV = $getVW->fetch_assoc();
            $vw = $dataV['virtual_wire'];
            $template = $dataV['template'];
            
            if ($vw != "") {
                $vw_array = explode(",", $vw);
                $names_vw_array = explode(",", $total_name);
                foreach($names_vw_array AS $name){
                    if (in_array($name, $vw_array)) {
                    
                    } else {
                        $vw_array[] = $name;
                        $projectdb->query("UPDATE virtual_systems SET virtual_wire ='" . implode(",", $vw_array) . "' WHERE id='$idx';");
                    }
                }
            } 
            else {
                $projectdb->query("UPDATE virtual_systems SET virtual_wire ='$total_name' WHERE id='$idx';");
            }
        }*/
        echo json_encode(array("success" => true));
    } 
    elseif ($type == "add_new_vsys") {
        $getBC = $projectdb->query("SELECT id FROM device_mapping WHERE id='$source' AND vendor='Paloalto Networks';");
        if ($getBC->num_rows == 1) {
            $projectdb->query("INSERT INTO virtual_systems (name,source,template) VALUES ('none','$source','$template');");
            echo json_encode(array("success" => true));
        } else {
            echo json_encode(array("success" => false, "msg" => "VSYS cannot be added at this stage of the migration.<br> VSYS can only be added into an existing Palo Alto Networks configuration file."));
        }
    } 
    elseif ($type == "vsys") {
        $name = (string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']);
        $display_name = (string) (isset($_POST['display_name']) ? $_POST['display_name'] : $_GET['display_name']);
        $id = (string) (isset($_POST['id']) ? $_POST['id'] : $_GET['id']);
        $dns_proxy = (string) (isset($_POST['dns_proxy']) ? $_POST['dns_proxy'] : $_GET['dns_proxy']);
        $max_sessions = (string) (isset($_POST['max_sessions']) ? $_POST['max_sessions'] : $_GET['max_sessions']);
        $max_security_rules = (string) (isset($_POST['max_security_rules']) ? $_POST['max_security_rules'] : $_GET['max_security_rules']);
        $max_nat_rules = (string) (isset($_POST['max_nat_rules']) ? $_POST['max_nat_rules'] : $_GET['max_nat_rules']);
        $max_ssl_decryption_rules = (string) (isset($_POST['max_ssl_decryption_rules']) ? $_POST['max_ssl_decryption_rules'] : $_GET['max_ssl_decryption_rules']);
        $max_qos_rules = (string) (isset($_POST['max_qos_rules']) ? $_POST['max_qos_rules'] : $_GET['max_qos_rules']);
        $max_application_override_rules = (string) (isset($_POST['max_application_override_rules']) ? $_POST['max_application_override_rules'] : $_GET['max_application_override_rules']);
        $max_pbf_rules = (string) (isset($_POST['max_pbf_rules']) ? $_POST['max_pbf_rules'] : $_GET['max_pbf_rules']);
        $max_cp_rules = (string) (isset($_POST['max_cp_rules']) ? $_POST['max_cp_rules'] : $_GET['max_cp_rules']);
        $max_dos_rules = (string) (isset($_POST['max_dos_rules']) ? $_POST['max_dos_rules'] : $_GET['max_dos_rules']);
        $max_site_to_site_vpn_tunnels = (string) (isset($_POST['max_site_to_site_vpn_tunnels']) ? $_POST['max_site_to_site_vpn_tunnels'] : $_GET['max_site_to_site_vpn_tunnels']);
        $max_concurrent_ssl_vpn_tunnels = (string) (isset($_POST['max_concurrent_ssl_vpn_tunnels']) ? $_POST['max_concurrent_ssl_vpn_tunnels'] : $_GET['max_concurrent_ssl_vpn_tunnels']);
        $allow_forward_decrypted_content = (string) (isset($_POST['allow_forward_decrypted_content']) ? $_POST['allow_forward_decrypted_content'] : '');
        $template = (string) (isset($_POST['template']) ? $_POST['template'] : $_GET['template']);

        $name = $projectdb->real_escape_string($name);
        $display_name = $projectdb->real_escape_string($display_name);
        $id = $projectdb->real_escape_string($id);
        $dns_proxy = $projectdb->real_escape_string($dns_proxy);
        $max_sessions = $projectdb->real_escape_string($max_sessions);
        $max_security_rules = $projectdb->real_escape_string($max_security_rules);
        $max_nat_rules = $projectdb->real_escape_string($max_nat_rules);
        $max_ssl_decryption_rules = $projectdb->real_escape_string($max_ssl_decryption_rules);
        $max_qos_rules = $projectdb->real_escape_string($max_qos_rules);
        $max_application_override_rules = $projectdb->real_escape_string($max_application_override_rules);
        $max_pbf_rules = $projectdb->real_escape_string($max_pbf_rules);
        $max_cp_rules = $projectdb->real_escape_string($max_cp_rules);
        $max_dos_rules = $projectdb->real_escape_string($max_dos_rules);
        $max_site_to_site_vpn_tunnels = $projectdb->real_escape_string($max_site_to_site_vpn_tunnels);
        $max_concurrent_ssl_vpn_tunnels = $projectdb->real_escape_string($max_concurrent_ssl_vpn_tunnels);
        $allow_forward_decrypted_content = $projectdb->real_escape_string($allow_forward_decrypted_content);
        $template = $projectdb->real_escape_string($template);

        if (!isset($allow_forward_decrypted_content)) {
            $allow_forward_decrypted_content = "";
        }

        $name = htmlspecialchars($name);
        $dns_proxy = htmlspecialchars($dns_proxy);
        $display_name = htmlspecialchars($display_name);

        $getExistName = $projectdb->query("SELECT name FROM virtual_systems WHERE id != '$id' AND BINARY name = '$name' AND source = '$source' AND template = '$template';");
        if ($getExistName->num_rows == 0){
            //if (preg_match("/^vsys/i",$name)){
            $isnew = $projectdb->query("SELECT name, interfaces FROM virtual_systems WHERE id='$id';");
            if ($isnew->num_rows == 1) {
                $data = $isnew->fetch_assoc();
                $all_interfaces = $data['interfaces'];
                $vsys = $name;
                if ($data['name'] == "none") {
                    #its new check the ID vsys+name if exists
                    $getVSYS = $projectdb->query("SELECT active,device,filename,vendor,version,baseconfig,ispanorama FROM device_mapping WHERE id='$source';");
                    if ($getVSYS->num_rows == 1) {
                        $data = $getVSYS->fetch_assoc();
                        $source_filename = $data['filename'];
                        $vendor = $data['vendor'];
                        $version = $data['version'];
                        $baseconfig = $data['baseconfig'];
                        $ispanorama = $data['ispanorama'];
                        $device = $data['device'];
                        $active = $data['active'];

                        if ($template == "all") {
                            //$getTemplate = $projectdb->query("SELECT id FROM templates_mapping WHERE source='$source' AND filename='$source_filename' AND project='$project'");
                            $getTemplate = $projectdb->query("SELECT id FROM templates_mapping WHERE source='$source' AND filename='$source_filename' ;");
                            if ($getTemplate->num_rows == 1) {
                                $dataTemplate = $getTemplate->fetch_assoc();
                                $template = $dataTemplate['id'];
                            } else {
                                echo json_encode(array("success" => false, "msg" => "You must select a Template first."));
                                exit(0);
                            }
                        }

                        $getVSYS2 = $projectdb->query("SELECT id FROM device_mapping WHERE filename='$source_filename' AND vsys='$vsys';");
                        if ($getVSYS2->num_rows == 0) {
                            $projectdb->query("INSERT INTO device_mapping (device,active,version,project,vsys,filename,ispanorama,baseconfig) VALUES ('$device','$active','$version','$project','$vsys','$source_filename','$ispanorama','$baseconfig');");
                            if ($vendor == "Paloalto Networks") {
                                $projectdb->query("UPDATE virtual_systems SET  name='$vsys',display_name='$display_name',dns_proxy='$dns_proxy',max_sessions='$max_sessions',max_security_rules='$max_security_rules',max_nat_rules='$max_nat_rules',max_ssl_decryption_rules='$max_ssl_decryption_rules',max_qos_rules='$max_qos_rules',max_application_override_rules='$max_application_override_rules',max_pbf_rules='$max_pbf_rules',max_cp_rules='$max_cp_rules',max_dos_rules='$max_dos_rules',max_site_to_site_vpn_tunnels='$max_site_to_site_vpn_tunnels',max_concurrent_ssl_vpn_tunnels='$max_concurrent_ssl_vpn_tunnels',allow_forward_decrypted_content='$allow_forward_decrypted_content',allow_forward_decrypted_content='$allow_forward_decrypted_content',template='$template'  WHERE id='$id';");
                            }
                        } else {
                            //echo json_encode(array("success"=>false,"msg"=>"ID already in use."));exit(0);
                            if ($vendor == "Paloalto Networks") {
                                $projectdb->query("UPDATE virtual_systems SET  name='$vsys',display_name='$display_name',dns_proxy='$dns_proxy',max_sessions='$max_sessions',max_security_rules='$max_security_rules',max_nat_rules='$max_nat_rules',max_ssl_decryption_rules='$max_ssl_decryption_rules',max_qos_rules='$max_qos_rules',max_application_override_rules='$max_application_override_rules',max_pbf_rules='$max_pbf_rules',max_cp_rules='$max_cp_rules',max_dos_rules='$max_dos_rules',max_site_to_site_vpn_tunnels='$max_site_to_site_vpn_tunnels',max_concurrent_ssl_vpn_tunnels='$max_concurrent_ssl_vpn_tunnels',allow_forward_decrypted_content='$allow_forward_decrypted_content',allow_forward_decrypted_content='$allow_forward_decrypted_content',template='$template'  WHERE id='$id';");
                            }
                        }

                    }
                }
                else {
                    $projectdb->query("UPDATE virtual_systems SET display_name='$display_name',dns_proxy='$dns_proxy',max_sessions='$max_sessions',max_security_rules='$max_security_rules',max_nat_rules='$max_nat_rules',max_ssl_decryption_rules='$max_ssl_decryption_rules',max_qos_rules='$max_qos_rules',max_application_override_rules='$max_application_override_rules',max_pbf_rules='$max_pbf_rules',max_cp_rules='$max_cp_rules',max_dos_rules='$max_dos_rules',max_site_to_site_vpn_tunnels='$max_site_to_site_vpn_tunnels',max_concurrent_ssl_vpn_tunnels='$max_concurrent_ssl_vpn_tunnels',allow_forward_decrypted_content='$allow_forward_decrypted_content',allow_forward_decrypted_content='$allow_forward_decrypted_content'  WHERE id='$id';");
                    #Limitation vsys name is not allowed to be changed
                }

                // Update vsys from interfaces
                $all_interfaces_array = explode(",", $all_interfaces);
                foreach ($all_interfaces_array AS $interface){
                    $projectdb->query("UPDATE interfaces SET vsys='$vsys' WHERE template='$template' AND unitname='$interface';");
                    //echo "UPDATE interfaces SET vsys='$vsys' WHERE template='$template' AND unitname='$interface';\n";
                }
            }

        }
        else{
            echo json_encode(array("success"=>false, "msg"=>"The name already exist!"));
        }
            
        
        
    }
} 
elseif ($action == "update") {
    if ($type == "interfaces") {
        $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        $idx = (string) (isset($_POST['idx']) ? $_POST['idx'] : $_GET['idx']);
        $template = (string) (isset($_POST['template']) ? $_POST['template'] : $_GET['template']);
        $total_name = (string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']);
        $oldname = (string) (isset($_POST['oldname']) ? $_POST['oldname'] : $_GET['oldname']);

        $vsys = $projectdb->real_escape_string($vsys);
        $source = $projectdb->real_escape_string($source);
        $idx = $projectdb->real_escape_string($idx);
        $template = $projectdb->real_escape_string($template);
        $total_name = $projectdb->real_escape_string($total_name);
        $oldname = $projectdb->real_escape_string($oldname);

        take_snapshot_last($project);
        
        $query = generate_query("template_not_vsys");
        $set_all_interfaces = 0;
        
        if($oldname != ""){
            $getInterfaces = $projectdb->query("SELECT interfaces FROM virtual_systems WHERE id='$idx';");
            if ($getInterfaces->num_rows == 1) {
                $dataI = $getInterfaces->fetch_assoc();
                $interfaces = $dataI['interfaces'];
                $interfaces_array = explode(",", $interfaces);
                $names_interfaces_array = explode(",", $total_name);
                
                if (($key = array_search($oldname, $interfaces_array)) !== false) {
                    unset($interfaces_array[$key]);
                }
                
                foreach($names_interfaces_array AS $name){
                    
                    if($set_all_interfaces != 1){
                    
                        if($name == "All Interfaces"){

                            $set_all_interfaces = 1;
                            $getAllInterfaces = $projectdb->query("SELECT id,unitname FROM interfaces $query ORDER BY unitname;");
                            $count = $getAllInterfaces->num_rows;
                            if($count > 0){
                                while ($dataAI = $getAllInterfaces->fetch_assoc()) {
                                    $unitname_array[] = $dataAI['unitname'];
                                    $id_interfaces_array[] = $dataAI['id'];
                                }
                                $ids_all_interfaces = implode(",", $id_interfaces_array);
                                $projectdb->query("UPDATE virtual_systems SET interfaces='" . implode(",", $unitname_array) . "' WHERE id='$idx';");
                                $projectdb->query("UPDATE interfaces SET vsys='$vsys' WHERE template='$template' AND source='$source' AND id IN ($ids_all_interfaces);");
                            }
                        }
                        else{
                            if (in_array($name, $interfaces_array)) {

                            } else {
                                $interfaces_array[] = $name;
                            }
                        }
                    }
                }

                if($set_all_interfaces != 1){
                    if (($key = array_search("", $interfaces_array)) !== false) {
                        unset($interfaces_array[$key]);
                    }
                    $projectdb->query("UPDATE virtual_systems SET interfaces='" . implode(",", $interfaces_array) . "' WHERE id='$idx';");
                    $names_interfaces_array2 = explode(",", $total_name);

                    foreach($names_interfaces_array2 AS $name){
                        $projectdb->query("UPDATE interfaces SET vsys='$vsys' WHERE template='$template' AND source='$source' AND unitname='$name';");
                    }
                    $projectdb->query("UPDATE interfaces SET vsys='' WHERE template='$template' AND source='$source' AND unitname='$oldname';");
                }
            }
        }
        
        echo json_encode(array("success" => true));
    } 
    elseif ($type == "vlans") {
        $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        $idx = (string) (isset($_POST['idx']) ? $_POST['idx'] : $_GET['idx']);
        $template = (string) (isset($_POST['template']) ? $_POST['template'] : $_GET['template']);
        $table_name = (string) (isset($_POST['table_name']) ? $_POST['table_name'] : $_GET['table_name']);
        $ids = (string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']);
        $total_name = (string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']);
        $oldname = (string) (isset($_POST['oldname']) ? $_POST['oldname'] : $_GET['oldname']);

        $vsys = $projectdb->real_escape_string($vsys);
        $source = $projectdb->real_escape_string($source);
        $idx = $projectdb->real_escape_string($idx);
        $template = $projectdb->real_escape_string($template);
        $table_name = $projectdb->real_escape_string($table_name);
        $ids = $projectdb->real_escape_string($ids);
        $total_name = $projectdb->real_escape_string($total_name);
        $oldname = $projectdb->real_escape_string($oldname);

        take_snapshot_last($project);
        
        $query = generate_query("template");
        $set_all_vlans = 0;
        
        if($oldname != ""){
            $getVlans = $projectdb->query("SELECT vlan FROM virtual_systems WHERE id='$idx';");
            if ($getVlans->num_rows == 1) {
                $dataV = $getVlans->fetch_assoc();
                $vlans = $dataV['vlan'];
                $vlans_array = explode(",", $vlans);
                $names_vlans_array = explode(",", $total_name);
                
                if (($key = array_search($oldname, $vlans_array)) !== false) {
                    unset($vlans_array[$key]);
                }
                
                foreach($names_vlans_array AS $name){
                    
                    if($set_all_vlans != 1){
                    
                        if($name == "All VLANs"){

                            $set_all_vlans = 1;
                            $getAllVlans = $projectdb->query("SELECT id,name FROM vlans $query ORDER BY name;");
                            $count = $getAllVlans->num_rows;
                            if($count > 0){
                                while ($dataV = $getAllVlans->fetch_assoc()) {
                                    $name_array[] = $dataV['name'];
                                }
                                $projectdb->query("UPDATE virtual_systems SET vlan='" . implode(",", $name_array) . "' WHERE id='$idx';");
                            }
                        }
                        else{
                            if (in_array($name, $vlans_array)) {

                            } else {
                                $vlans_array[] = $name;
                            }
                        }
                    }
                }

                if($set_all_vlans != 1){
                    if (($key = array_search("", $vlans_array)) !== false) {
                        unset($vlans_array[$key]);
                    }
                    $projectdb->query("UPDATE virtual_systems SET vlan ='" . implode(",", $vlans_array) . "' WHERE id='$idx';");
                }
            }
        }
        /*$getTags = $projectdb->query("SELECT vlan FROM virtual_systems WHERE id='$idx';");
        if ($getTags->num_rows == 1) {
            $getTagsData = $getTags->fetch_assoc();
            $tag = $getTagsData['vlan'];
            $tag_array = explode(",", $tag);
            if (in_array($name, $tag_array)) {
                
            } else {
                $replace = str_replace($oldname, $name, $tag);
                $projectdb->query("UPDATE virtual_systems SET vlan='$replace' WHERE id='$idx';");
            }
        }*/

        echo json_encode(array("success" => true));
    } 
    elseif ($type == "vwires") {
        $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        $idx = (string) (isset($_POST['idx']) ? $_POST['idx'] : $_GET['idx']);
        $template = (string) (isset($_POST['template']) ? $_POST['template'] : $_GET['template']);
        $table_name = (string) (isset($_POST['table_name']) ? $_POST['table_name'] : $_GET['table_name']);
        $ids = (string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']);
        $total_name = (string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']);
        $oldname = (string) (isset($_POST['oldname']) ? $_POST['oldname'] : $_GET['oldname']);

        $vsys = $projectdb->real_escape_string($vsys);
        $source = $projectdb->real_escape_string($source);
        $idx = $projectdb->real_escape_string($idx);
        $template = $projectdb->real_escape_string($template);
        $table_name = $projectdb->real_escape_string($table_name);
        $ids = $projectdb->real_escape_string($ids);
        $total_name = $projectdb->real_escape_string($total_name);
        $oldname = $projectdb->real_escape_string($oldname);
        
        take_snapshot_last($project);
        
        $query = generate_query("template");
        $set_all_vw = 0;
        
        if($oldname != ""){
            $getVW = $projectdb->query("SELECT virtual_wire FROM virtual_systems WHERE id='$idx';");
            if ($getVW->num_rows == 1) {
                $dataV = $getVW->fetch_assoc();
                $vw = $dataV['virtual_wire'];
                $vw_array = explode(",", $vw);
                $names_vw_array = explode(",", $total_name);
                
                if (($key = array_search($oldname, $vw_array)) !== false) {
                    unset($vw_array[$key]);
                }
                
                foreach($names_vw_array AS $name){
                    
                    if($set_all_vw != 1){
                    
                        if($name == "All Virtual Wires"){

                            $set_all_vw = 1;
                            $getAllVW = $projectdb->query("SELECT id,name FROM virtual_wires $query ORDER BY name;");
                            $count = $getAllVW->num_rows;
                            if($count > 0){
                                while ($dataV = $getAllVW->fetch_assoc()) {
                                    $name_array[] = $dataV['name'];
                                }
                                $projectdb->query("UPDATE virtual_systems SET virtual_wire='" . implode(",", $name_array) . "' WHERE id='$idx';");
                                
                            }
                        }
                        else{
                            if (in_array($name, $vw_array)) {

                            } else {
                                $vw_array[] = $name;
                            }
                        }
                    }
                }

                if($set_all_vw != 1){
                    if (($key = array_search("", $vw_array)) !== false) {
                        unset($vw_array[$key]);
                    }
                    $projectdb->query("UPDATE virtual_systems SET virtual_wire ='" . implode(",", $vw_array) . "' WHERE id='$idx';");
                }
            }
        }
        
        /*if($oldname != ""){
            $getVR = $projectdb->query("SELECT virtual_wire FROM virtual_systems WHERE id='$idx';");
            if ($getVR->num_rows == 1) {
                $dataV = $getVR->fetch_assoc();
                $virtual_wire = $dataV['virtual_wire'];
                $virtual_wire_array = explode(",", $virtual_wire);
                $oldname_array = explode(",", $oldname);
                $names_vw_array = explode(",", $total_name);
                $diff_vw_array = array_diff($virtual_wire_array, $oldname_array);
                
                foreach($names_vw_array AS $name){
                    if (in_array($name, $diff_vw_array)) {

                    } else {
                        $diff_vw_array[] = $name;
                    }
                }

                $projectdb->query("UPDATE virtual_systems SET virtual_wire ='" . implode(",", $diff_vw_array) . "' WHERE id='$idx';");
            }
        }
        */
        echo json_encode(array("success" => true));
    } 
    elseif ($type == "vr") {
        $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        $idx = (string) (isset($_POST['idx']) ? $_POST['idx'] : $_GET['idx']);
        $template = (string) (isset($_POST['template']) ? $_POST['template'] : $_GET['template']);
        $table_name = (string) (isset($_POST['table_name']) ? $_POST['table_name'] : $_GET['table_name']);
        $ids = (string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']);
        $total_name = (string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']);
        $oldname = (string) (isset($_POST['oldname']) ? $_POST['oldname'] : $_GET['oldname']);

        $vsys = $projectdb->real_escape_string($vsys);
        $source = $projectdb->real_escape_string($source);
        $idx = $projectdb->real_escape_string($idx);
        $template = $projectdb->real_escape_string($template);
        $table_name = $projectdb->real_escape_string($table_name);
        $ids = $projectdb->real_escape_string($ids);
        $total_name = $projectdb->real_escape_string($total_name);
        $oldname = $projectdb->real_escape_string($oldname);
        
        take_snapshot_last($project);
        
        $query = generate_query("template");
        $set_all_vw = 0;
        $vw_array = array();
        $names_vw_array = array();
        
        if($oldname != ""){
            $getVW = $projectdb->query("SELECT virtual_router FROM virtual_systems WHERE id='$idx';");
            if ($getVW->num_rows == 1) {
                $dataV = $getVW->fetch_assoc();
                $vw = $dataV['virtual_router'];
                $vw_array = explode(",", $vw);
                $names_vw_array = explode(",", $total_name);
                
                if (($key = array_search($oldname, $vw_array)) !== false) {
                    unset($vw_array[$key]);
                }
                
                foreach($names_vw_array AS $name){
                    if($name != ""){
                        
                        if($set_all_vw != 1){
                    
                            if($name == "All Virtual Routers"){

                                $set_all_vw = 1;
                                $getAllVW = $projectdb->query("SELECT id,name FROM virtual_routers $query ORDER BY name;");
                                $count = $getAllVW->num_rows;
                                if($count > 0){
                                    while ($dataV = $getAllVW->fetch_assoc()) {
                                        $name_array[] = $dataV['name'];
                                    }
                                    $projectdb->query("UPDATE virtual_systems SET virtual_router='" . implode(",", $name_array) . "' WHERE id='$idx';");
                                }
                            }
                            else{
                                if (in_array($name, $vw_array)) {

                                } else {
                                    $vw_array[] = $name;
                                }
                            }
                        }
                    }
                    
                }

                if($set_all_vw != 1){
                    if (($key = array_search("", $vw_array)) !== false) {
                        unset($vw_array[$key]);
                    }
                    $projectdb->query("UPDATE virtual_systems SET virtual_router ='" . implode(",", $vw_array) . "' WHERE id='$idx';");
                    //echo "UPDATE virtual_systems SET virtual_router ='" . implode(",", $vw_array) . "' WHERE id='$idx';\n";
                }
            }
        }
        
        /*if($oldname != ""){
            $getVR = $projectdb->query("SELECT virtual_router FROM virtual_systems WHERE id='$idx';");
            if ($getVR->num_rows == 1) {
                $dataV = $getVR->fetch_assoc();
                $virtual_router = $dataV['virtual_router'];
                $virtual_router_array = explode(",", $virtual_router);
                $oldname_array = explode(",", $oldname);
                $names_vr_array = explode(",", $total_name);
                $diff_vr_array = array_diff($virtual_router_array, $oldname_array);
                
                foreach($names_vr_array AS $name){
                    if (in_array($name, $diff_vr_array)) {

                    } else {
                        $diff_vr_array[] = $name;
                    }
                }

                $projectdb->query("UPDATE virtual_systems SET virtual_router ='" . implode(",", $diff_vr_array) . "' WHERE id='$idx';");
            }
        }*/
        echo json_encode(array("success" => true));
    } 
    elseif ($type == "visible") {
        $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        $idx = (string) (isset($_POST['idx']) ? $_POST['idx'] : $_GET['idx']);
        $template = (string) (isset($_POST['template']) ? $_POST['template'] : $_GET['template']);
        $table_name = (string) (isset($_POST['table_name']) ? $_POST['table_name'] : $_GET['table_name']);
        $ids = (string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']);
        $total_name = (string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']);
        $oldname = (string) (isset($_POST['oldname']) ? $_POST['oldname'] : $_GET['oldname']);

        $vsys = $projectdb->real_escape_string($vsys);
        $source = $projectdb->real_escape_string($source);
        $idx = $projectdb->real_escape_string($idx);
        $template = $projectdb->real_escape_string($template);
        $table_name = $projectdb->real_escape_string($table_name);
        $ids = $projectdb->real_escape_string($ids);
        $total_name = $projectdb->real_escape_string($total_name);
        $oldname = $projectdb->real_escape_string($oldname);

        take_snapshot_last($project);
        
        $query = generate_query("template");
        $set_all_vlans = 0;
        
        if($oldname != ""){
            $getVlans = $projectdb->query("SELECT visible_vsys FROM virtual_systems WHERE id='$idx';");
            if ($getVlans->num_rows == 1) {
                $dataV = $getVlans->fetch_assoc();
                $vlans = $dataV['visible_vsys'];
                $vlans_array = explode(",", $vlans);
                $names_vlans_array = explode(",", $total_name);
                
                if (($key = array_search($oldname, $vlans_array)) !== false) {
                    unset($vlans_array[$key]);
                }
                
                foreach($names_vlans_array AS $name){
                    
                    if($set_all_vlans != 1){
                    
                        if($name == "All Visible vsys"){

                            $set_all_vlans = 1;
                            $getAllVlans = $projectdb->query("SELECT id,name FROM virtual_systems $query ORDER BY name;");
                            $count = $getAllVlans->num_rows;
                            if($count > 0){
                                while ($dataV = $getAllVlans->fetch_assoc()) {
                                    $name_array[] = $dataV['name'];
                                }
                                $projectdb->query("UPDATE virtual_systems SET visible_vsys='" . implode(",", $name_array) . "' WHERE id='$idx';");
                            }
                        }
                        else{
                            if (in_array($name, $vlans_array)) {

                            } else {                                
                                $vlans_array[] = $name;
                            }
                        }
                    }
                }

                if($set_all_vlans != 1){
                    if (($key = array_search("", $vlans_array)) !== false) {
                        unset($vlans_array[$key]);
                    }
                    $projectdb->query("UPDATE virtual_systems SET visible_vsys ='" . implode(",", $vlans_array) . "' WHERE id='$idx';");
                }
            }
        }
        /*$getTags = $projectdb->query("SELECT visible_vsys FROM virtual_systems WHERE id='$idx';");
        if ($getTags->num_rows == 1) {
            $getTagsData = $getTags->fetch_assoc();
            $tag = $getTagsData['visible_vsys'];
            $tag_array = explode(",", $tag);
            if (in_array($name, $tag_array)) {
                
            } else {
                $replace = str_replace($oldname, $name, $tag);
                $projectdb->query("UPDATE virtual_systems SET visible_vsys='$replace' WHERE id='$idx';");
            }
        }*/

        echo json_encode(array("success" => true));
    }
}

function update_static_routes_vsys($vr_id_array,$vsys,$template,$source){
    global $projectdb;
    $vrids=implode(",",$vr_id_array);
    $projectdb->query("UPDATE routes_static SET vsys='$vsys' WHERE template='$template' AND source='$source' AND vr_id IN ($vrids)");
}
?>
