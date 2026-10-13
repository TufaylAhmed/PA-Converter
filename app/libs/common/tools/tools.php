<?php

# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.

require_once INC_ROOT.'/libs/shared.php';
require_once INC_ROOT.'/libs/common/lib-objects.php';

if(defined('CLI')){
    require_once INC_ROOT .'/userManager/API/accessControl_CLI.php';
}
else{
    require_once INC_ROOT .'/userManager/API/accessControl.php';
    require_once INC_ROOT.'/bin/authentication/sessionControl.php';
}

require_once INC_ROOT.'/libs/common/lib-objects.php';
require_once INC_ROOT.'/libs/common/lib-rules.php';
require_once INC_ROOT.'/libs/common/tools/tools-rules.php';
require_once INC_ROOT.'/libs/objects/SecurityRulePANObject.php';
require_once INC_ROOT.'/libs/shared.php';

use \PaloAltoNetworks\Expedition\Tools\Merger\AddressMerger;
use \PaloAltoNetworks\Expedition\Tools\Merger\ServicesMerger;
use \PaloAltoNetworks\Expedition\Tools\Merger\RegionsMerger;
use \PaloAltoNetworks\Expedition\Tools\Merger\ApplicationsMerger;

function setPrefixSuffix(STRING $projectName, ARRAY $params){

    global $projectdb;
    $projectdb = selectDatabase($projectName);

    take_snapshot_last($projectName);

    $selection = $params['selection'];
    $text_prefix = $params['prefix'];
    $text_suffix = $params['suffix'];

    if($selection != "all"){

        $data = explode(",", $selection);

        foreach ($data as $key => $value) {

            $values = explode(";", $value);
            $id = $values[0];
            $table_name = $values[1];
            $name = $values[2];

            if((($table_name == "services") && ($name == "application-default"))
                || (($table_name == "services") && ($name == "service-http"))
                || (($table_name == "services") && ($name == "service-https"))
                || (($table_name == "profiles") && ($name == "default"))
                || ($table_name == "default_applications")
                || ($table_name == "virtual_systems")
                || ($table_name == "response_pages")){
            }
            else{
                $name_fin = addPrefixSuffixName($text_prefix, $text_suffix, $name, 63);

                $projectdb->query("UPDATE $table_name SET name = '$name_fin' WHERE id = '$id' AND dummy = '0';");
            }

        }
    }
    else{
        // All

        $getAll = $projectdb->query("SELECT DISTINCT(table_name) FROM tools_where WHERE id NOT IN (1) AND table_name NOT IN ('virtual_systems', 'default_applications', 'response_pages');");

        if($getAll->num_rows > 0) {
            while ($dataGA = $getAll->fetch_assoc()) {

                $table_name = $dataGA['table_name'];

                if($table_name == "services"){
                    $getColumns = $projectdb->query("SELECT id, name FROM $table_name WHERE name NOT IN ('application-default', 'service-http', 'service-https');");
                }
                else if($table_name == "profiles"){
                    $getColumns = $projectdb->query("SELECT id, name FROM $table_name WHERE name NOT IN ('default');");
                }
                else{
                    $getColumns = $projectdb->query("SELECT id, name FROM $table_name;");
                }

                if($getColumns->num_rows > 0) {
                    while ($dataC = $getColumns->fetch_assoc()) {

                        $id = $dataC['id'];
                        $name = $dataC['name'];

                        $name_fin = addPrefixSuffixName($text_prefix, $text_suffix, $name, 63);

                        $projectdb->query("UPDATE $table_name SET name = '$name_fin' WHERE id = '$id' AND dummy = '0';");
                    }
                }
            }
        }
    }

    $message['code']=false;
    return $message;
}


function setRename(STRING $projectName, ARRAY $params){

    global $projectdb;
    $projectdb = selectDatabase($projectName);

    take_snapshot_last($projectName);

    $selection = $params['selection'];
    $pattern_string = $params['pattern_string'];
    $replace_by = $params['replace_by'];
    $is_an_ip_address = $params['is_an_ip_address'];

    if($selection != "all"){
        $data = explode(",", $selection);

        foreach ($data as $key => $value) {
            $values = explode(";", $value);
            $id = $values[0];
            $table_name = $values[1];
            $name = $values[2];

            if ($pattern_string != ""){

                if ($is_an_ip_address == "true"){
                    $query = "SELECT ipaddress FROM $table_name WHERE id = '$id';";
                    $getIPaddress = $projectdb->query($query);
                    if ($getIPaddress->num_rows != 0) {
                        $data = $getIPaddress->fetch_assoc();
                        $ipaddress = $data['ipaddress'];
                        $name_fin = str_replace($pattern_string, $replace_by, $ipaddress);
                        $projectdb->query("UPDATE $table_name SET ipaddress = '$name_fin' WHERE id = '$id' AND dummy = '0';");
                    }
                }
                else{
                    $name_fin = str_replace($pattern_string, $replace_by, $name);
                    $projectdb->query("UPDATE $table_name SET name = '$name_fin' WHERE id = '$id' AND dummy = '0';");
                }
            }
        }
    }
    else{
        // All
        $getAll = $projectdb->query("SELECT table_name FROM tools_where WHERE id NOT IN (1) ;");

        if($getAll->num_rows != 0) {
            while ($dataGA = $getAll->fetch_assoc()) {

                $table_name = $dataGA['table_name'];

                $getColumns = $projectdb->query("SELECT id, name FROM $table_name;");
                //echo "SELECT id, name FROM $table_name;\n";

                if($getColumns->num_rows != 0) {
                    while ($dataC = $getColumns->fetch_assoc()) {

                        $id = $dataC['id'];
                        $name = $dataC['name'];

                        if ($pattern_string != ""){

                            if ($is_an_ip_address == "true"){
                                $query = "SELECT ipaddress FROM $table_name WHERE id = '$id';";
                                $getIPaddress = $projectdb->query($query);
                                if ($getIPaddress->num_rows != 0) {
                                    $data = $getIPaddress->fetch_assoc();
                                    $ipaddress = $data['ipaddress'];
                                    $name_fin = str_replace($pattern_string, $replace_by, $ipaddress);
                                    $projectdb->query("UPDATE $table_name SET ipaddress = '$name_fin' WHERE id = '$id' AND dummy = '0';");
                                }
                            }
                            else{
                                $name_fin = str_replace($pattern_string, $replace_by, $name);
                                $projectdb->query("UPDATE $table_name SET name = '$name_fin' WHERE id = '$id' AND dummy = '0';");
                            }
                        }
                    }
                }
            }
        }
    }


    $message['code']=false;
    return $message;
}


function addPrefixSuffixName($text_prefix, $text_suffix, $name_int, $max_char){

    $name_int_fin = $name_int;

    if ($text_prefix != ""){
        $text_prefix = trim($text_prefix);
        $name_int_fin = $text_prefix.$name_int;
        if (strlen($name_int_fin) > $max_char){
            $total_name_fin = strlen($name_int_fin);
            $total_subs = $total_name_fin - $max_char;
            $name_int = substr($name_int, 0, -$total_subs);
            $name_int_fin = $text_prefix.$name_int;
        }
    }
    if ($text_suffix != ""){
        $text_suffix = trim($text_suffix);
        $name_int_fin = $name_int_fin.$text_suffix;
        if (strlen($name_int_fin) > $max_char){
            $total_name_fin = strlen($name_int_fin);
            $total_subs = $total_name_fin - $max_char;
            $name_int = substr($name_int, 0, -$total_subs);
            $name_int_fin = $name_int.$text_suffix;
        }
    }
    return $name_int_fin;
}


function getFoundInGroups(STRING $projectName, ARRAY $params){

    global $projectdb;
    $projectdb = selectDatabase($projectName);

    $selection = $params['selection'];
    $source = $params['source'];
    $vsys = $params['vsys'];

    //echo "Selection: ".$selection."\n";
    $myData = array();

    if(count($selection) != 0){

        $data = explode(",", $selection);

        foreach ($data as $key => $value) {

            $values = explode(";", $value);
            $lid = $values[0];
            $table_name = $values[1];
            $name = $values[2];

            require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
            $add_vsys = prepareVsysQuerySearch($projectdb, $vsys, $source, "groups");

            if (preg_match("/address/i", $table_name)) {

                $image = getImageNew("address", $table_name, $lid, $vsys);

                $getAddressGroups = $projectdb->query("SELECT agi.id as lid, 'address_groups' AS table_name_lid, agi.name AS group_name, agi.vsys, ag.member_lid, ag.table_name "
                    . " FROM address_groups_id agi, address_groups ag "
                    . " WHERE agi.source = '$source' $add_vsys AND ag.member_lid = '$lid' AND ag.table_name = '$table_name' "
                    . " AND agi.id = ag.lid;");

                if ($getAddressGroups->num_rows > 0) {
                    while ($data = $getAddressGroups->fetch_assoc()) {
                        $data['name_object_search'] = "<img style='vertical-align: middle;' src=/resources/images/rules/$image> " .$name;
                        $data['name_object'] = $name;
                        $myData[] = $data;
                    }
                }
            }
            elseif ((preg_match("/services/i", $table_name))) {

                $image = getImageNew("services", $table_name, $lid, $vsys);

                $getServicesGroups = $projectdb->query("SELECT agi.id as lid, 'services_groups' AS table_name_lid, agi.name AS group_name, agi.vsys, ag.member_lid, ag.table_name "
                    . " FROM services_groups_id agi, services_groups ag "
                    . " WHERE agi.source = '$source' $add_vsys AND ag.member_lid = '$lid' AND ag.table_name = '$table_name' "
                    . " AND agi.id = ag.lid;");

                if ($getServicesGroups->num_rows > 0) {
                    while ($data = $getServicesGroups->fetch_assoc()) {
                        $data['name_object_search'] = "<img style='vertical-align: middle;' src=/resources/images/rules/$image> " .$name;
                        $data['name_object'] = $name;
                        $myData[] = $data;
                    }
                }
            }
            elseif ((preg_match("/applications/i", $table_name))) {

                $image = getImageNew("applications", $table_name, $lid, $vsys);

                $getAppGroups = $projectdb->query("SELECT agi.id as lid, 'applications_groups' AS table_name_lid, agi.name AS group_name, agi.vsys, ag.member_lid, ag.table_name "
                    . " FROM applications_groups_id agi, applications_groups ag "
                    . " WHERE agi.source = '$source' $add_vsys AND ag.member_lid = '$lid' AND ag.table_name = '$table_name' "
                    . " AND agi.id = ag.lid;");

                if ($getAppGroups->num_rows > 0) {
                    while ($data = $getAppGroups->fetch_assoc()) {
                        $data['name_object_search'] = "<img style='vertical-align: middle;' src=/resources/images/rules/$image> " .$name;
                        $data['name_object'] = $name;
                        $myData[] = $data;
                    }
                }
            }
        }
    }

    $message = array();
    $message['code'] = true;
    $message['count'] = count($myData);
    $message['msg'] = $myData;

    return $message;

}


function setObjectsToReplace(STRING $projectName, ARRAY $params){

    global $projectdb;

    $projectdb = selectDatabase($projectName);

    $source = $params['source'];

    $data_selected = $params['selection'];
    $locate =  $params['locate'];

    $is_the_same_object = 1;
    $objects_selected = explode(":", $data_selected);

    foreach ($objects_selected as $key => $value) {
        $objects_array[] = explode(";", $value);
    }

    $total_objects_selected = count($objects_array);

    for ($i = 0; $i < $total_objects_selected; $i ++) {

        $lid = $objects_array[$i][0];
        $table_name_lid = $objects_array[$i][1];
        $name = $objects_array[$i][2];
        $member_lid = $objects_array[$i][3];
        $table_name = $objects_array[$i][4];
        $vsys = $objects_array[$i][5];
        $position = $objects_array[$i][6];
        $name_int = $objects_array[$i][7];

        if($table_name == "zones"){

            // Hacer control de insert, si ya lo han seleccionado, no añadirlo a la tabla
            $getSearchReplaceExist = $projectdb->query("SELECT lid, table_name_lid, member_lid, table_name, name, position, locate, vsys "
                . " FROM search_replace "
                . " WHERE lid = '$lid' AND table_name_lid = '$table_name_lid' AND table_name = '$table_name' AND name = '$name' "
                . " AND position = '$position' AND locate = '$locate' AND object_replace = '$name_int';");

        }
        else{
            // Hacer control de insert, si ya lo han seleccionado, no añadirlo a la tabla
            $getSearchReplaceExist = $projectdb->query("SELECT lid, table_name_lid, member_lid, table_name, name, position, locate, vsys "
                . " FROM search_replace "
                . " WHERE lid = '$lid' AND table_name_lid = '$table_name_lid' AND member_lid = '$member_lid' AND table_name = '$table_name' AND name = '$name' "
                . " AND position = '$position' AND locate = '$locate' ;");

        }

        $count = $getSearchReplaceExist->num_rows;
        if ($count == 0) {

            // Si no existe ninguna entrada con los parametros pasados, comprobar que son del mismo tipo que han introducido anteriormente, es decir;
            // address y address_group
            // services y services_group
            // Comprobar primero que no es la primera entrada, ya que sino daría error
            $getIsFirst = $projectdb->query("SELECT id FROM search_replace; ");

            if ($getIsFirst->num_rows >= 1) {

                if (preg_match("/address/i", $table_name)) {

                    $getSameObject = $projectdb->query("SELECT table_name FROM search_replace WHERE table_name LIKE '%address%' ");
                    if ($getSameObject->num_rows >= 1) {
                        $is_the_same_object = 1;
                    } else {
                        $is_the_same_object = 0;
                    }
                }
                elseif (preg_match("/services/i", $table_name)) {

                    $getSameObject = $projectdb->query("SELECT table_name FROM search_replace WHERE table_name LIKE '%services%' ");
                    if ($getSameObject->num_rows >= 1) {
                        $is_the_same_object = 1;
                    } else {
                        $is_the_same_object = 0;
                    }
                }
                elseif (preg_match("/applications/i", $table_name)) {

                    $getSameObject = $projectdb->query("SELECT table_name FROM search_replace WHERE table_name LIKE '%applications%' ");
                    if ($getSameObject->num_rows >= 1) {
                        $is_the_same_object = 1;
                    } else {
                        $is_the_same_object = 0;
                    }
                }
                elseif (preg_match("/zones/i", $table_name)) {

                    $getSameObject = $projectdb->query("SELECT table_name FROM search_replace WHERE table_name LIKE '%zones%' ");
                    if ($getSameObject->num_rows >= 1) {
                        $is_the_same_object = 1;
                    } else {
                        $is_the_same_object = 0;
                    }
                }
            }//fin if getIsFirst

            if ($is_the_same_object == 1) {

                $projectdb->query("INSERT INTO search_replace "
                    . "(id, lid, table_name_lid, member_lid, table_name, name, locate, position, vsys, source, object_replace) "
                    . "VALUES (NULL, '$lid', '$table_name_lid', '$member_lid', '$table_name', '$name', '$locate', '$position','$vsys','$source', '$name_int');");

            }
        }
    }

    if ($is_the_same_object == 1) {
        $message['code']=true;
        return $message;
    } else {
        $message['code']=false;
        return $message;
    }
}


function getObjectsToReplace(STRING $projectName, ARRAY $params){

    global $projectdb;
    $projectdb = selectDatabase($projectName);

    $myData = array();

    $selection = $params['selection'];
    $source = $params['source'];

    // Check if objects are selected in results filters grid
    if(count($selection) != 0){
        $projectdb->query("DELETE FROM search_replace WHERE object_replace NOT IN ($selection) AND source = '$source';");
    }else{
        $projectdb->query("DELETE FROM search_replace WHERE source = '$source';");
    }

    $getSearchReplace = $projectdb->query("SELECT id AS id_replace, lid, table_name_lid, member_lid, table_name, name, position, locate, vsys, object_replace "
        . "FROM search_replace;");

    $count = $getSearchReplace->num_rows;
    while ($data = $getSearchReplace->fetch_assoc()) {
        $table_name = $data['table_name'];
        $lid = $data['member_lid'];
        $name = $data['object_replace'];

        $image = getImageTools($table_name, $lid);
        $data['object_replace'] = "<img style='vertical-align: middle;' src=/resources/images/rules/$image> " .$name;
        $myData[] = $data;
    }
    if ($count == 0) {
        $myData = "";
    }

    $message = array();
    $message['code'] = true;
    $message['count'] = $count;
    $message['msg'] = $myData;

    return $message;

}


function removeReplace(STRING $projectName, ARRAY $params){

    global $projectdb;
    $projectdb = selectDatabase($projectName);

    $data_selected = $params['selection'];
    $objects_selected = explode(";", $data_selected);

    foreach ($objects_selected as $key => $value) {
        $projectdb->query("DELETE FROM search_replace WHERE id = '$value' ;");
    }

    $message['code']=true;
    return $message;

}


function setReplace(STRING $projectName, ARRAY $params){

    global $projectdb;
    $projectdb = selectDatabase($projectName);

    $source = $params['source'];

    $data_selected = $params['selection'];
    $replace_by = $params['replace_by'];
    $replace_to = $params['replace_to'];
    $select_to_replace = $params['select_to_replace'];
    $check_split = $params['check_split'];
    $check_remove = $params['check_remove'];

    $table_name_to_replace_control = "";
    $table_name_to_replace = "";
    $id_new_to_replace = "";

    if(($replace_by != "Remove") || ($replace_by != "Members") || ($replace_by != "Zones")){
        if($select_to_replace != ""){
            $select_to_replace = explode(";", $select_to_replace);
            $id_new_to_replace = $select_to_replace[0];
            $name_int_to_replace = $select_to_replace[1];
            $table_name_to_replace = $select_to_replace[2];
        }
    }

    $is_the_same_object = 0;

    $check_the_group = 0;
    $check_the_service = 0;

    take_snapshot_last($projectName);

    $objects_selected = explode(":", $data_selected);

    foreach ($objects_selected as $key => $value) {
        $objects_array[] = explode(";", $value);
    }

    //print_r($objects_array);
    $total_objects_selected = count($objects_array);

    $lids_groups = array();
    $audit_log_sr = array();
    $audit_log_nat = array();
    $audit_log_app = array();
    $audit_log_group_serv = array();
    $audit_log_group_add = array();
    $audit_log_group_app = array();

    // Hacer un primer for para comprobar si han seleccionado un group o varios, y una security_rule y si el destino es App y
    // han seleccionado el check de Remove Service from Group
    for ($i = 0; $i < $total_objects_selected; $i ++) {
        $position = $objects_array[$i][6];
        //echo "Position: " .$position. "\n";

        if ($position == "Groups") {
            $check_the_group = 1;
            $lids_groups[] = $objects_array[$i][0];
        }
        if ($position == "Service") {
            $check_the_service = 1;
        }
    }

    $total_objects_selected = count($objects_array);

    for ($i = 0; $i < $total_objects_selected; $i ++) {

        $lid = $objects_array[$i][0];
        $table_name_lid = $objects_array[$i][1];
        // Guardar las ID's rules para el audit log;
        // Comprobar si son Security Rules, Nat o App
        if($table_name_lid == "security_rules"){
            $audit_log_sr[] = $objects_array[$i][0];
        }elseif ($table_name_lid == "nat_rules"){
            $audit_log_nat[] = $objects_array[$i][0];
        }elseif($table_name_lid == "appoverride_rules"){
            $audit_log_app[] = $objects_array[$i][0];
        }elseif($table_name_lid == "address_groups"){
            $audit_log_group_add[] = $objects_array[$i][2];
        }elseif($table_name_lid == "services_groups"){
            $audit_log_group_serv[] = $objects_array[$i][2];
        }elseif($table_name_lid == "applications_groups"){
            $audit_log_group_app[] = $objects_array[$i][2];
        }

        $name = $objects_array[$i][2];
        $member_lid = $objects_array[$i][3];
        $table_name = $objects_array[$i][4];
        $vsys = $objects_array[$i][5];
        $position = $objects_array[$i][6];
        $id_replace = $objects_array[$i][7];
        //$object_to_replace = $objects_array[$i][8];

        if (preg_match("/service/i", $table_name_lid)) {
            if (($replace_by == "Services") || ($replace_by == "Services Groups") || ($replace_by == "Applications") || ($replace_by == "Applications Groups") || ($replace_by == "Applications Filters") || ($replace_by == "Remove") || ($replace_by == "Members") ) {
                $is_the_same_object = 1;
            } else {
                $is_the_same_object = 0;
            }
        } elseif (preg_match("/address/i", $table_name_lid)) {
            if (($replace_by == "Address") || ($replace_by == "Address Groups") || ($replace_by == "Remove") || ($replace_by == "Members")) {
                $is_the_same_object = 1;
            } else {
                $is_the_same_object = 0;
            }
        } elseif (preg_match("/application/i", $table_name_lid)) {
            if (($replace_by == "Applications") || ($replace_by == "Applications Groups") || ($replace_by == "Applications Filters") || ($replace_by == "Remove") || ($replace_by == "Members")) {
                $is_the_same_object = 1;
            } else {
                $is_the_same_object = 0;
            }
        } elseif (($position == "Source") || ($position == "Destination") || ($position == "Translated Address") || ($position == "Translated Address Fallback") || ($position == "Destination Address Translation") ) {
            if (($replace_by == "Address") || ($replace_by == "Address Groups") || ($replace_by == "Remove") || ($replace_by == "Members")) {
                $is_the_same_object = 1;
            } else {
                $is_the_same_object = 0;
            }
        } elseif (($position == "Service")) {
            if (($replace_by == "Services") || ($replace_by == "Services Groups") || ($replace_by == "Applications") || ($replace_by == "Applications Groups") || ($replace_by == "Applications Filters") || ($replace_by == "Remove") || ($replace_by == "Members")) {
                $is_the_same_object = 1;
            } else {
                $is_the_same_object = 0;
            }
        } elseif (($position == "Application")) {
            if (($replace_by == "Applications") || ($replace_by == "Applications Groups") || ($replace_by == "Applications Filters") || ($replace_by == "Remove") || ($replace_by == "Members")) {
                $is_the_same_object = 1;
            } else {
                $is_the_same_object = 0;
            }
        } elseif (($position == "From") || ($position == "To")) {
            if (($replace_by == "Zones") || ($replace_by == "Remove")) {
                $is_the_same_object = 1;
            } else {
                $is_the_same_object = 0;
            }
        }

        if ($is_the_same_object == 1) {

            if ($replace_by == "Services") {
                $table_name_to_replace_control = "services";
            } elseif ($replace_by == "Services Groups") {
                $table_name_to_replace_control = "services_groups_id";
            } elseif ($replace_by == "Address") {
                $table_name_to_replace_control = "address";
            } elseif ($replace_by == "Address Groups") {
                $table_name_to_replace_control = "address_groups_id";
            } elseif ($replace_by == "Applications") {
                $table_name_to_replace_control = "applications";
            } elseif ($replace_by == "Applications Groups") {
                $table_name_to_replace_control = "applications_groups_id";
            } elseif ($replace_by == "Applications Filters") {
                $table_name_to_replace_control = "applications_filters";
            }

            // SECURITY POLICY
            if ($table_name_lid == "security_rules") {

                setReplaceOnSecurityRules($projectName, $position, $table_name_to_replace_control, $table_name_to_replace, $id_new_to_replace, $member_lid, $table_name, $lid, $id_replace, $check_split, $replace_by, $replace_to);

            }
            // NAT POLICY
            elseif ($table_name_lid == "nat_rules") {

                setReplaceOnNatRules($projectName, $position, $table_name_to_replace, $id_new_to_replace, $member_lid, $table_name, $lid, $id_replace, $replace_by, $replace_to);

            }
            // APP OVERRIDE POLICY
            elseif ($table_name_lid == "appoverride_rules") {

                setReplaceOnAppoverrideRules($projectName, $position, $table_name_to_replace, $id_new_to_replace, $member_lid, $table_name, $lid, $id_replace, $replace_by, $replace_to);

            }
            // ADDRESS GROUPS
            elseif ($table_name_lid == "address_groups") {

                setReplaceOnAddressGroups($projectName, $table_name_to_replace, $id_new_to_replace, $member_lid, $table_name, $lid, $id_replace, $table_name_lid, $replace_by);

            } // SERVICES GROUPS
            elseif ($table_name_lid == "services_groups") {

                setReplaceOnServicesGroups($projectName, $table_name_to_replace, $id_new_to_replace, $member_lid, $table_name, $lid, $id_replace, $table_name_lid, $check_remove, $check_the_group, $check_the_service, $source, $replace_by);

            }
            // APPLICATIONS GROUPS
            elseif ($table_name_lid == "applications_groups") {

                setReplaceOnApplicationsGroups($projectName, $table_name_to_replace, $id_new_to_replace, $member_lid, $table_name, $lid, $id_replace, $table_name_lid, $replace_by);

            }
        }
    }

    if ($is_the_same_object == 1) {
        $sql_log="";
        if(count($audit_log_sr) > 0){
            $rules_ids_sr = implode(",", $audit_log_sr);
            $sql_log .= "in Security RulesID [$rules_ids_sr] ";

            //Recalculate Layer
            $rulesString = implode(",", $audit_log_sr);
            $securityRulesMan = new \SecurityRulePANObject();
            $securityRulesMan->updateLayerLevel($projectdb, $rulesString, $source);
        }
        if(count($audit_log_nat) > 0){
            $rules_ids_nat = implode(",", $audit_log_nat);
            $sql_log .= "in NAT RulesID [$rules_ids_nat] ";
        }
        if(count($audit_log_app) > 0){
            $rules_ids_app = implode(",", $audit_log_app);
            $sql_log .= "in App RulesID [$rules_ids_app] ";
        }
        if(count($audit_log_group_add) > 0){
            $group_name_add = implode(",", $audit_log_group_add);
            $sql_log .= "in Address Groups [$group_name_add] ";
        }
        if(count($audit_log_group_serv) > 0){
            $group_name_srv = implode(",", $audit_log_group_serv);
            $sql_log .= "in Services Groups [$group_name_srv] ";
        }

        //TODO: cambiar el object_to_replace por otro ya que tiene la imagen
        //add_log('ok', 'Search & Replace', 'Replace ' . $position . ': ' . $object_to_replace . ' to ' . $replace_by . ': ' . $name_int_to_replace . ' '.$sql_log.' ', $source, 'No Action Required', '2');

        //check_used_objects_new();

        $message['code'] = true;

    }else{
        $message['code'] = false;
    }

    return $message;
}


// TODO with table search_replace
function setReplaceBis(STRING $projectName, ARRAY $params){

    global $projectdb;
    $projectdb = selectDatabase($projectName);

    $source = $params['source'];

    $data_selected = $params['selection'];
    $replace_by = $params['replace_by'];
    $replace_to = $params['replace_to'];
    $select_to_replace = $params['select_to_replace'];
    $check_split = $params['check_split'];
    $check_remove = $params['check_remove'];

    $table_name_to_replace_control = "";
    $table_name_to_replace = "";
    $id_new_to_replace = "";

    if(($replace_by != "Remove") || ($replace_by != "Members") || ($replace_by != "Zones")){
        if($select_to_replace != ""){
            $select_to_replace = explode(";", $select_to_replace);
            $id_new_to_replace = $select_to_replace[0];
            $name_int_to_replace = $select_to_replace[1];
            $table_name_to_replace = $select_to_replace[2];
        }
    }

    $is_the_same_object = 0;

    $check_the_group = 0;
    $check_the_service = 0;

    take_snapshot_last($projectName);

    $objects_selected = explode(":", $data_selected);

    foreach ($objects_selected as $key => $value) {
        $objects_array[] = explode(";", $value);
    }

    //print_r($objects_array);
    $total_objects_selected = count($objects_array);

    $lids_groups = array();
    $audit_log_sr = array();
    $audit_log_nat = array();
    $audit_log_app = array();
    $audit_log_group_serv = array();
    $audit_log_group_add = array();
    $audit_log_group_app = array();

    // Hacer un primer for para comprobar si han seleccionado un group o varios, y una security_rule y si el destino es App y
    // han seleccionado el check de Remove Service from Group
    for ($i = 0; $i < $total_objects_selected; $i ++) {
        $position = $objects_array[$i][6];
        //echo "Position: " .$position. "\n";

        if ($position == "Groups") {
            $check_the_group = 1;
            $lids_groups[] = $objects_array[$i][0];
        }
        if ($position == "Service") {
            $check_the_service = 1;
        }
    }

    $total_objects_selected = count($objects_array);

    for ($i = 0; $i < $total_objects_selected; $i ++) {

        $lid = $objects_array[$i][0];
        $table_name_lid = $objects_array[$i][1];
        // Guardar las ID's rules para el audit log;
        // Comprobar si son Security Rules, Nat o App
        if($table_name_lid == "security_rules"){
            $audit_log_sr[] = $objects_array[$i][0];
        }elseif ($table_name_lid == "nat_rules"){
            $audit_log_nat[] = $objects_array[$i][0];
        }elseif($table_name_lid == "appoverride_rules"){
            $audit_log_app[] = $objects_array[$i][0];
        }elseif($table_name_lid == "address_groups"){
            $audit_log_group_add[] = $objects_array[$i][2];
        }elseif($table_name_lid == "services_groups"){
            $audit_log_group_serv[] = $objects_array[$i][2];
        }elseif($table_name_lid == "applications_groups"){
            $audit_log_group_app[] = $objects_array[$i][2];
        }

        $name = $objects_array[$i][2];
        $member_lid = $objects_array[$i][3];
        $table_name = $objects_array[$i][4];
        $vsys = $objects_array[$i][5];
        $position = $objects_array[$i][6];
        $id_replace = $objects_array[$i][7];
        //$object_to_replace = $objects_array[$i][8];

        if (preg_match("/service/i", $table_name_lid)) {
            if (($replace_by == "Services") || ($replace_by == "Services Groups") || ($replace_by == "Applications") || ($replace_by == "Applications Groups") || ($replace_by == "Applications Filters") || ($replace_by == "Remove") || ($replace_by == "Members") ) {
                $is_the_same_object = 1;
            } else {
                $is_the_same_object = 0;
            }
        } elseif (preg_match("/address/i", $table_name_lid)) {
            if (($replace_by == "Address") || ($replace_by == "Address Groups") || ($replace_by == "Remove") || ($replace_by == "Members")) {
                $is_the_same_object = 1;
            } else {
                $is_the_same_object = 0;
            }
        } elseif (preg_match("/application/i", $table_name_lid)) {
            if (($replace_by == "Applications") || ($replace_by == "Applications Groups") || ($replace_by == "Applications Filters") || ($replace_by == "Remove") || ($replace_by == "Members")) {
                $is_the_same_object = 1;
            } else {
                $is_the_same_object = 0;
            }
        } elseif (($position == "Source") || ($position == "Destination") || ($position == "Translated Address") || ($position == "Translated Address Fallback") || ($position == "Destination Address Translation") ) {
            if (($replace_by == "Address") || ($replace_by == "Address Groups") || ($replace_by == "Remove") || ($replace_by == "Members")) {
                $is_the_same_object = 1;
            } else {
                $is_the_same_object = 0;
            }
        } elseif (($position == "Service")) {
            if (($replace_by == "Services") || ($replace_by == "Services Groups") || ($replace_by == "Applications") || ($replace_by == "Applications Groups") || ($replace_by == "Applications Filters") || ($replace_by == "Remove") || ($replace_by == "Members")) {
                $is_the_same_object = 1;
            } else {
                $is_the_same_object = 0;
            }
        } elseif (($position == "Application")) {
            if (($replace_by == "Applications") || ($replace_by == "Applications Groups") || ($replace_by == "Applications Filters") || ($replace_by == "Remove") || ($replace_by == "Members")) {
                $is_the_same_object = 1;
            } else {
                $is_the_same_object = 0;
            }
        } elseif (($position == "From") || ($position == "To")) {
            if (($replace_by == "Zones") || ($replace_by == "Remove")) {
                $is_the_same_object = 1;
            } else {
                $is_the_same_object = 0;
            }
        }

        if ($is_the_same_object == 1) {

            if ($replace_by == "Services") {
                $table_name_to_replace_control = "services";
            } elseif ($replace_by == "Services Groups") {
                $table_name_to_replace_control = "services_groups_id";
            } elseif ($replace_by == "Address") {
                $table_name_to_replace_control = "address";
            } elseif ($replace_by == "Address Groups") {
                $table_name_to_replace_control = "address_groups_id";
            } elseif ($replace_by == "Applications") {
                $table_name_to_replace_control = "applications";
            } elseif ($replace_by == "Applications Groups") {
                $table_name_to_replace_control = "applications_groups_id";
            } elseif ($replace_by == "Applications Filters") {
                $table_name_to_replace_control = "applications_filters";
            }

            // SECURITY POLICY
            if ($table_name_lid == "security_rules") {

                setReplaceOnSecurityRules($projectName, $position, $table_name_to_replace_control, $table_name_to_replace, $id_new_to_replace, $member_lid, $table_name, $lid, $id_replace, $check_split, $replace_by, $replace_to);

            }
            // NAT POLICY
            elseif ($table_name_lid == "nat_rules") {

                setReplaceOnNatRules($projectName, $position, $table_name_to_replace, $id_new_to_replace, $member_lid, $table_name, $lid, $id_replace, $replace_by, $replace_to);

            }
            // APP OVERRIDE POLICY
            elseif ($table_name_lid == "appoverride_rules") {

                setReplaceOnAppoverrideRules($projectName, $position, $table_name_to_replace, $id_new_to_replace, $member_lid, $table_name, $lid, $id_replace, $replace_by, $replace_to);

            }
            // ADDRESS GROUPS
            elseif ($table_name_lid == "address_groups") {

                setReplaceOnAddressGroups($projectName, $table_name_to_replace, $id_new_to_replace, $member_lid, $table_name, $lid, $id_replace, $table_name_lid, $replace_by);

            } // SERVICES GROUPS
            elseif ($table_name_lid == "services_groups") {

                setReplaceOnServicesGroups($projectName, $table_name_to_replace, $id_new_to_replace, $member_lid, $table_name, $lid, $id_replace, $table_name_lid, $check_remove, $check_the_group, $check_the_service, $source, $replace_by);

            }
            // APPLICATIONS GROUPS
            elseif ($table_name_lid == "applications_groups") {

                setReplaceOnApplicationsGroups($projectName, $table_name_to_replace, $id_new_to_replace, $member_lid, $table_name, $lid, $id_replace, $table_name_lid, $replace_by);

            }
        }
    }

    if ($is_the_same_object == 1) {
        $sql_log="";
        if(count($audit_log_sr) > 0){
            $rules_ids_sr = implode(",", $audit_log_sr);
            $sql_log .= "in Security RulesID [$rules_ids_sr] ";

            //Recalculate Layer
            $rulesString = implode(",", $audit_log_sr);
            $securityRulesMan = new \SecurityRulePANObject();
            $securityRulesMan->updateLayerLevel($projectdb, $rulesString, $source);
        }
        if(count($audit_log_nat) > 0){
            $rules_ids_nat = implode(",", $audit_log_nat);
            $sql_log .= "in NAT RulesID [$rules_ids_nat] ";
        }
        if(count($audit_log_app) > 0){
            $rules_ids_app = implode(",", $audit_log_app);
            $sql_log .= "in App RulesID [$rules_ids_app] ";
        }
        if(count($audit_log_group_add) > 0){
            $group_name_add = implode(",", $audit_log_group_add);
            $sql_log .= "in Address Groups [$group_name_add] ";
        }
        if(count($audit_log_group_serv) > 0){
            $group_name_srv = implode(",", $audit_log_group_serv);
            $sql_log .= "in Services Groups [$group_name_srv] ";
        }

        //TODO: cambiar el object_to_replace por otro ya que tiene la imagen
        //add_log('ok', 'Search & Replace', 'Replace ' . $position . ': ' . $object_to_replace . ' to ' . $replace_by . ': ' . $name_int_to_replace . ' '.$sql_log.' ', $source, 'No Action Required', '2');

        check_used_objects_new();

        $message['code'] = true;

    }else{
        $message['code'] = false;
    }

    return $message;
}


function setReplaceOnAddressGroups($projectName, $table_name_to_replace, $id_new_to_replace, $member_lid, $table_name, $lid, $id_replace, $table_name_lid, $replace_by){

    global $projectdb;
    $projectdb = selectDatabase($projectName);

    if (preg_match("/groups/i", $table_name_to_replace)) {
        $table_name_to_replace = $table_name_to_replace . "_id";
    }

    if($replace_by == "Remove"){
        $projectdb->query("DELETE FROM $table_name_lid WHERE member_lid = '$member_lid' AND table_name = '$table_name' "
            . " AND lid = '$lid';");
    }
    elseif($replace_by == "Members"){

        if($table_name == "address_groups_id"){
            $table_name_without_id = "address_groups";
        }

        $projectdb->query("DELETE FROM $table_name_lid WHERE member_lid = '$member_lid' AND table_name = '$table_name' "
            . " AND lid = '$lid';");
        //echo "1. DELETE FROM $table_name_lid WHERE member_lid = '$member_lid' AND table_name = '$table_name' "
        //    . " AND lid = '$lid';\n";

        $getMembers = $projectdb->query("SELECT member_lid, table_name FROM $table_name_without_id WHERE lid = '$member_lid'; ");
        //echo "2. SELECT member_lid, table_name FROM $table_name_without_id WHERE lid = '$member_lid'; \n";

        if ($getMembers->num_rows != 0) {
            while ($dataM = $getMembers->fetch_assoc()) {

                $member_lid_member = $dataM['member_lid'];
                $table_name_member = $dataM['table_name'];

                $getExistAddressToRule = $projectdb->query("SELECT id FROM $table_name_lid WHERE member_lid = '$member_lid_member' "
                    . " AND table_name = '$table_name_member' AND lid = '$lid' ");
                //echo "3. SELECT id FROM $table_name_lid WHERE member_lid = '$member_lid_member' "
                //    . " AND table_name = '$table_name_member' AND lid = '$lid' \n";

                if ($getExistAddressToRule->num_rows == 0) {
                    $projectdb->query("INSERT INTO $table_name_lid (member_lid, table_name, lid) 
                                            VALUES ('$member_lid_member', '$table_name_member', '$lid') ;");
                    //echo "4. INSERT INTO $table_name_lid (member_lid, table_name, lid)
                    //                        VALUES ('$member_lid_member', '$table_name_member', '$lid') ;\n";
                }
            }
        }
    }
    else{
        $getExistAddressToGroup = $projectdb->query("SELECT id FROM $table_name_lid WHERE member_lid = '$id_new_to_replace' "
            . " AND table_name = '$table_name_to_replace' AND lid = '$lid' ");

        if ($getExistAddressToGroup->num_rows == 0) {
            $projectdb->query("UPDATE $table_name_lid SET member_lid = '$id_new_to_replace', table_name = '$table_name_to_replace' "
                . " WHERE lid = '$lid' AND member_lid = '$member_lid' AND table_name = '$table_name';");
        } else {
            $projectdb->query("DELETE FROM $table_name_lid WHERE member_lid = '$member_lid' AND table_name = '$table_name' "
                . " AND lid = '$lid';");
        }
    }

    $projectdb->query("DELETE FROM search_replace WHERE id = '$id_replace' ;");

}


function setReplaceOnServicesGroups($projectName, $table_name_to_replace, $id_new_to_replace, $member_lid, $table_name, $lid, $id_replace, $table_name_lid, $check_remove, $check_the_group, $check_the_service, $source, $replace_by)
{

    global $projectdb;
    $projectdb = selectDatabase($projectName);

    if($replace_by == "Remove"){
        $projectdb->query("DELETE FROM $table_name_lid WHERE member_lid = '$member_lid' AND table_name = '$table_name' "
            . " AND lid = '$lid';");
        $projectdb->query("DELETE FROM search_replace WHERE id = '$id_replace' ;");
    }
    elseif($replace_by == "Members"){

        if($table_name == "services_groups_id"){
            $table_name_without_id = "services_groups";
        }

        $projectdb->query("DELETE FROM $table_name_lid WHERE member_lid = '$member_lid' AND table_name = '$table_name' "
            . " AND lid = '$lid';");

        $getMembers = $projectdb->query("SELECT member_lid, table_name FROM $table_name_without_id WHERE lid = '$member_lid'; ");

        if ($getMembers->num_rows != 0) {
            while ($dataM = $getMembers->fetch_assoc()) {

                $member_lid_member = $dataM['member_lid'];
                $table_name_member = $dataM['table_name'];

                $getExistAddressToRule = $projectdb->query("SELECT id FROM $table_name_lid WHERE member_lid = '$member_lid_member' "
                    . " AND table_name = '$table_name_member' AND lid = '$lid' ");

                if ($getExistAddressToRule->num_rows == 0) {
                    $projectdb->query("INSERT INTO $table_name_lid (member_lid, table_name, lid) 
                                            VALUES ('$member_lid_member', '$table_name_member', '$lid') ;");
                }
            }
        }
        $projectdb->query("DELETE FROM search_replace WHERE id = '$id_replace' ;");
    }
    else{
        if (preg_match("/applications/i", $table_name_to_replace)) {
            $table_name_lid_id = "services_groups_id";

            $lid_group = Array();
            // Cambiar en todas las reglas que tengan los grupos que contengan los servicios seleccionados, por la aplicación que han seleccionado
            $lid_group = getGroupsRecursive($lid, $table_name_lid_id);
            $lid_group[] = $lid;

            // 5. Buscar las referencias de los groupos en las security_rules_srv
            $getReferencesToRule = $projectdb->query("SELECT rule_lid FROM security_rules_srv WHERE member_lid IN (".implode(",",$lid_group).") AND table_name = '$table_name_lid_id' ");

            // Si hay referencias:
            if ($getReferencesToRule->num_rows != 0) {
                while ($data = $getReferencesToRule->fetch_assoc()) {
                    $rule_lid_references = $data['rule_lid'];
                    // 6. Clonar regla borrando srv y las apps
                    $getPosition = $projectdb->query("SELECT position, name, vsys, source, devicegroup FROM security_rules WHERE id = '$rule_lid_references' ");
                    $getPosData = $getPosition->fetch_assoc();
                    $initial_position = $getPosData['position'];
                    $initial_name = $getPosData['name'];
                    $initial_vsys = $getPosData['vsys'];
                    $initial_source = $getPosData['source'];
                    $initial_devicegroup = $getPosData['devicegroup'];
                    $final_position = $initial_position - 1;
                    $message = "";

                    // Comprobar que no existe la regla Cl-$name, si existe añadirla en ésta regla
                    $getNameRuleCl = $projectdb->query("SELECT id, name FROM security_rules WHERE name = 'Cl-$initial_name' AND disabled = '0' AND vsys = '$initial_vsys' AND source = '$initial_source' ;");
                    if ($getNameRuleCl->num_rows == 0) {
                        // 1. Crear rule, clonándola, por -1
                        $new_lid = clone_security_rule($initial_position, $final_position, $initial_vsys, $initial_source, $rule_lid_references, $message, $projectName);
                        // Primero borrar de la tabla security_rules_srv todas las referencias a services de la rule clonada y luego añadir al new_lid el replace
                        $projectdb->query("DELETE FROM security_rules_srv WHERE rule_lid = '$new_lid';");
                    } else {
                        $getData = $getNameRuleCl->fetch_assoc();
                        $new_lid = $getData['id'];
                    }
                    // Mirar que en security_rules_app no existe ya la aplicación
                    $getIsAppToReplace = $projectdb->query("SELECT id FROM security_rules_app WHERE rule_lid = '$new_lid' AND member_lid = '$id_new_to_replace' AND table_name = '$table_name_to_replace' ");

                    if ($getIsAppToReplace->num_rows == 0) {
                        $projectdb->query("INSERT INTO security_rules_app (id, source, vsys, member_lid, table_name, rule_lid, devicegroup) "
                            . "VALUES (NULL, '$initial_source', '$initial_vsys', '$id_new_to_replace', '$table_name_to_replace', '$new_lid', '$initial_devicegroup'); ");
                    }
                    // Poner application_default en el apartado de services
                    $getIdAppDef = $projectdb->query("SELECT id FROM services WHERE name LIKE '%application-default%' AND source = '$initial_source' AND vsys = 'shared' LIMIT 1;");

                    if ($getIdAppDef->num_rows > 0) {
                        $getData = $getIdAppDef->fetch_assoc();
                        $id_app_default = $getData['id'];
                        // Mirar que no existe ya la application-default
                        $getAppDefault = $projectdb->query("SELECT id FROM security_rules_srv WHERE member_lid = '$id_app_default' AND table_name = 'services' AND rule_lid = '$new_lid';");

                        if ($getAppDefault->num_rows == 0) {
                            $projectdb->query("INSERT INTO security_rules_srv (id, source, rule_lid, member_lid, table_name, vsys, counter, devicegroup) "
                                . " VALUES (NULL, '$initial_source', '$new_lid', '$id_app_default', 'services', '$initial_vsys', '0', '$initial_devicegroup'); ");
                        }

                    }

                    $projectdb->query("DELETE FROM search_replace WHERE id = '$id_replace' ;");
                }
            }
            // Si han seleccionado check de remove service to group, si vienen sólo de un group y si vienen de group y service
            if (($check_remove == "true") && ($check_the_group == "1") || ($check_the_service == "1")) {

                // 4. Borrar de cada grupo en que está, el objeto en cuestión
                $projectdb->query("DELETE FROM $table_name_lid WHERE member_lid = '$member_lid' AND table_name = '$table_name' AND lid = '$lid';");

                // Si el grupo se queda vacío, eliminarlo de services_groups_id
                $getIsGroupEmpty = $projectdb->query("SELECT id FROM $table_name_lid WHERE lid = '$lid' ");

                if ($getIsGroupEmpty->num_rows == 0) {

                    $getNameGroupRemove = $projectdb->query("SELECT name FROM $table_name_lid_id WHERE id = '$lid' ");
                    $getData = $getNameGroupRemove->fetch_assoc();
                    $name_int_group_remove = $getData['name'];

                    $projectdb->query("DELETE FROM $table_name_lid_id WHERE id = '$lid' ;");

                    //$getIsRuleIdEmptySrv = $projectdb->query("SELECT rule_lid FROM security_rules_srv WHERE member_lid = '$lid' AND table_name = '$table_name_lid_id' AND source = '$source';");
                    $getIsRuleIdEmptySrv = $projectdb->query("SELECT rule_lid FROM security_rules_srv WHERE member_lid = '$lid' AND table_name = '$table_name_lid_id' ;");

                    if ($getIsRuleIdEmptySrv->num_rows != 0) {

                        while ($getData = $getIsRuleIdEmptySrv->fetch_assoc()) {
                            $rule_lid_srv_app = $getData['rule_lid'];

                            // También, eliminar las referencias que haya en security_rules_srv al grupo en cuestión.
                            $projectdb->query("DELETE FROM security_rules_srv WHERE member_lid = '$lid' AND table_name = '$table_name_lid_id' ;");

                            $getIsAppEmpty = $projectdb->query("SELECT id FROM security_rules_app WHERE rule_lid = '$rule_lid_srv_app'; ");
                            $getIsSrvEmpty = $projectdb->query("SELECT id FROM security_rules_srv WHERE rule_lid = '$rule_lid_srv_app'; ");

                            if (($getIsAppEmpty->num_rows == 0) && ($getIsSrvEmpty->num_rows == 0)) {

                                // Si no tiene ni srv ni app asociadas, poner la rule en disabled
                                $projectdb->query("UPDATE security_rules SET disabled = '1' WHERE id = '$rule_lid_srv_app' ;");

                                add_log2('warning', 'Search & Replace', 'This RuleID [' . $rule_lid_srv_app . '] has been disabled after replace because the Rule has lost all the services and/or Applications. ', $source, 'Group Removed [' . $name_int_group_remove . '] ', 'rules', $rule_lid_srv_app, 'security_rules');
                            }
                        }
                    }
                }
            }
        }
        elseif (preg_match("/groups/i", $table_name_to_replace)) {

            $table_name_to_replace = $table_name_to_replace . "_id";

            $getExistServicesToGroup = $projectdb->query("SELECT id FROM $table_name_lid WHERE member_lid = '$id_new_to_replace' "
                . " AND table_name = '$table_name_to_replace' AND lid = '$lid' ");

            if ($getExistServicesToGroup->num_rows == 0) {
                $projectdb->query("UPDATE $table_name_lid SET member_lid = '$id_new_to_replace', table_name = '$table_name_to_replace' "
                    . " WHERE lid = '$lid' AND member_lid = '$member_lid' AND table_name = '$table_name';");
            } else {
                $projectdb->query("DELETE FROM $table_name_lid WHERE member_lid = '$member_lid' AND table_name = '$table_name' "
                    . " AND lid = '$lid';");
            }
            $projectdb->query("DELETE FROM search_replace WHERE id = '$id_replace' ;");
        }

        // Replace del service o services seleccionados del grupo en cuestión por otro service
        elseif (preg_match("/service/i", $table_name_to_replace)) {

            $getExistServicesToGroup = $projectdb->query("SELECT id FROM $table_name_lid WHERE member_lid = '$id_new_to_replace' "
                . " AND table_name = '$table_name_to_replace' AND lid = '$lid' ");

            $exist_services_o_group_to_group = $getExistServicesToGroup->num_rows;
            if ($exist_services_o_group_to_group == 0) {
                $projectdb->query("UPDATE $table_name_lid SET member_lid = '$id_new_to_replace', table_name = '$table_name_to_replace' "
                    . " WHERE lid = '$lid' AND member_lid = '$member_lid' AND table_name = '$table_name';");
            } else {
                $projectdb->query("DELETE FROM $table_name_lid WHERE member_lid = '$member_lid' AND table_name = '$table_name' "
                    . " AND lid = '$lid';");
            }
            $projectdb->query("DELETE FROM search_replace WHERE id = '$id_replace' ;");
        }
    }
}


function setReplaceOnApplicationsGroups($projectName, $table_name_to_replace, $id_new_to_replace, $member_lid, $table_name, $lid, $id_replace, $table_name_lid, $replace_by){

    global $projectdb;
    $projectdb = selectDatabase($projectName);

    if($replace_by == "Remove"){
        $projectdb->query("DELETE FROM $table_name_lid WHERE member_lid = '$member_lid' AND table_name = '$table_name' "
            . " AND lid = '$lid';");
    }
    elseif($replace_by == "Members"){

        if($table_name == "applications_groups_id"){
            $table_name_without_id = "applications_groups";
        }

        $projectdb->query("DELETE FROM $table_name_lid WHERE member_lid = '$member_lid' AND table_name = '$table_name' "
            . " AND lid = '$lid';");

        $getMembers = $projectdb->query("SELECT member_lid, table_name FROM $table_name_without_id WHERE lid = '$member_lid'; ");

        if ($getMembers->num_rows != 0) {
            while ($dataM = $getMembers->fetch_assoc()) {

                $member_lid_member = $dataM['member_lid'];
                $table_name_member = $dataM['table_name'];

                $getExistAddressToRule = $projectdb->query("SELECT id FROM $table_name_lid WHERE member_lid = '$member_lid_member' "
                    . " AND table_name = '$table_name_member' AND lid = '$lid' ");

                if ($getExistAddressToRule->num_rows == 0) {
                    $projectdb->query("INSERT INTO $table_name_lid (member_lid, table_name, lid) 
                                            VALUES ('$member_lid_member', '$table_name_member', '$lid') ;");
                }
            }
        }
    }
    else{
        $getExistAddressToGroup = $projectdb->query("SELECT id FROM $table_name_lid WHERE member_lid = '$id_new_to_replace' "
            . " AND table_name = '$table_name_to_replace' AND lid = '$lid' ");

        if ($getExistAddressToGroup->num_rows == 0) {
            $projectdb->query("UPDATE $table_name_lid SET member_lid = '$id_new_to_replace', table_name = '$table_name_to_replace' "
                . " WHERE lid = '$lid' AND member_lid = '$member_lid' AND table_name = '$table_name';");
        } else {
            $projectdb->query("DELETE FROM $table_name_lid WHERE member_lid = '$member_lid' AND table_name = '$table_name' "
                . " AND lid = '$lid';");
        }
    }

    $projectdb->query("DELETE FROM search_replace WHERE id = '$id_replace' ;");
}


function getGroupsRecursive($member_lid, $table_name){

    global $projectdb;
    $lid_groups=array();
    $getGroupsR = $projectdb->query("SELECT lid FROM services_groups WHERE member_lid = '$member_lid' AND table_name = '$table_name'; ");
    if ($getGroupsR->num_rows != 0) {
        while ($dataR = $getGroupsR->fetch_assoc()) {

            $lids = $dataR['lid'];
            $lid_groups[] = $lids;

            $result = Array();

            $result = getGroupsRecursive($lids, "services_groups_id");
            if($result != ""){
                $lid_groups = array_merge($lid_groups, $result);
            }
        }
    }

    return $lid_groups;

}


function getImageTools($table_name, $member_lid){

    global $projectdb;

    if ($table_name == "address") {
        $getSRC = $projectdb->query("SELECT name, type, vtype, ipaddress, cidr, fqdn, vsys FROM address WHERE id = '$member_lid';");
        $dataSRC = $getSRC->fetch_assoc();
        $type = $dataSRC['type'];
        $vtype = $dataSRC['vtype'];
        $vsys = $dataSRC['vsys'];

        if($vsys != "shared"){
            if ($vtype == "") {
                if ($type == "ip-netmask") {$image = "address.gif";
                } elseif ($type == "ip-range") {$image = "ip_range.gif";
                } elseif ($type == "fqdn") {$image = "domain.png";
                } else {$image = "address.gif";}
            } else {
                if (($vtype == "gateway_cluster") OR ( $vtype == "cluster_member") OR ( $vtype == "gateway_fw") OR ( $vtype == "gateway")) {
                    $image = "checkpointp.png";
                } elseif($vtype == "ip-range"){
                    $image = "ip_range.gif";
                }
                elseif ($vtype=="dummy"){
                    $image = "pan16.gif";
                }
                else {$image = "address.gif";}
            }
        }
        else{
            if ($vtype == "") {
                if ($type == "ip-netmask") {$image = "shared_address.gif";
                } elseif ($type == "ip-range") {$image = "shared-ranges.gif";
                } elseif ($type == "fqdn") {$image = "shared_domain.gif";
                } else {$image = "shared_address.gif";}
            } else {
                if (($vtype == "gateway_cluster") OR ( $vtype == "cluster_member") OR ( $vtype == "gateway_fw") OR ( $vtype == "gateway")) {
                    $image = "checkpointp.png";
                } elseif($vtype == "ip-range"){
                    $image = "ip_range.gif";
                }
                elseif ($vtype == "dummy"){
                    $image = "pan16.gif";
                }
                else {$image = "shared_address.gif";}
            }
        }
    }
    elseif ($table_name == "address_groups_id") {
        $getSRC = $projectdb->query("SELECT name, type, filter, vsys FROM address_groups_id WHERE id='$member_lid';");
        $dataSRC = $getSRC->fetch_assoc();
        $type = $dataSRC['type']; // static dynamic
        $vsys = $dataSRC['vsys'];
        if($vsys != "shared"){
            if ($type == "dynamic") {$image = "dynamic_group.png";
            } else {$image = "address_groups_id.gif";}
        }else{
            if ($type == "dynamic") {$image = "dynamic_group.png";
            } else {$image = "shared_address_groups_id.gif";}
        }
    }
    elseif ($table_name == "services") {
        $getSRC = $projectdb->query("SELECT vtype, vsys FROM services WHERE id = '$member_lid';");
        $dataSRC = $getSRC->fetch_assoc();
        $vtype = $dataSRC['vtype'];
        $vsys = $dataSRC['vsys'];
        if($vsys != "shared"){
            if ($vtype == "dummy"){$image = "pan16.gif";
            }else{$image = "service.gif";}
        }else{
            if ($vtype == "dummy"){$image = "pan16.gif";
            }else{$image = "shared_services.gif";}
        }
    }
    elseif ($table_name == "services_groups_id") {
        $getSRC = $projectdb->query("SELECT vsys FROM services_groups_id WHERE id = '$member_lid';");
        $dataSRC = $getSRC->fetch_assoc();
        $vsys = $dataSRC['vsys'];
        if($vsys != "shared"){$image = "services_groups_id.gif";
        }else{$image = "shared_services_groups_id.gif";}
    }
    elseif ($table_name == "default_applications"){ $image = "applications.gif";}
    elseif ($table_name == "applications") {
        $getSRC = $projectdb->query("SELECT vtype, vsys FROM applications WHERE id = '$member_lid';");
        $dataSRC = $getSRC->fetch_assoc();
        $vtype = $dataSRC['vtype'];
        $vsys = $dataSRC['vsys'];
        if($vsys != "shared"){
            if ($vtype == "dummy"){$image = "pan16.gif";
            }else{$image = "applications.gif";}
        }else{
            if ($vtype == "dummy"){$image = "pan16.gif";
            }else{$image = "shared_applications.gif";}
        }
    }
    elseif ($table_name == "applications_groups_id"){
        $getSRC = $projectdb->query("SELECT vsys FROM applications_groups_id WHERE id = '$member_lid';");
        $dataSRC = $getSRC->fetch_assoc();
        $vsys = $dataSRC['vsys'];
        if($vsys != "shared"){$image = "applications_groups.gif";
        }else{$image = "shared_applications_groups.gif";}
    }
    elseif ($table_name == "applications_filters"){
        $getSRC = $projectdb->query("SELECT vsys FROM applications_filters WHERE id = '$member_lid';");
        $dataSRC = $getSRC->fetch_assoc();
        $vsys = $dataSRC['vsys'];
        if($vsys != "shared"){$image = "applications_filters.png";
        }else{$image = "shared_applications_filters.gif";}
    }
    elseif ($table_name == "profiles"){
        $getSRC = $projectdb->query("SELECT vsys FROM profiles WHERE id = '$member_lid';");
        $dataSRC = $getSRC->fetch_assoc();
        $vsys = $dataSRC['vsys'];
        if($vsys != "shared"){$image = "global-protect.png";
        }else{$image = "shared_global-protect.gif";}
    }
    elseif($table_name == "zones"){
        $image = "zone.gif";
    }

    return $image;


}


function setMergeAsPrimary(STRING $projectName, ARRAY $params){

    global $projectdb;
    $projectdb = selectDatabase($projectName);

    take_snapshot_last($projectName);

    $table_name_id = $params['table_name'];
    $merge_as_primary_id = $params['merge_as_primary_id'];
    $vsys = $params['vsys'];

    if($merge_as_primary_id != ""){

        $getTableName = $projectdb->query("SELECT table_name FROM tools_where WHERE id = '$table_name_id';");

        if ($getTableName->num_rows > 0) {
            $dataTN = $getTableName->fetch_assoc();
            $table_name = $dataTN['table_name'];
        }

        if($vsys == "all"){
            $projectdb->query("UPDATE $table_name SET merge_as_primary = '1' WHERE id IN ($merge_as_primary_id) ;");
        }else{
            $projectdb->query("UPDATE $table_name SET merge_as_primary = '1' WHERE id IN ($merge_as_primary_id);");
        }
    }

    $message['code']=true;
    return $message;

}


function deselectMergeAsPrimary(STRING $projectName, ARRAY $params){

    global $projectdb;
    $projectdb = selectDatabase($projectName);

    take_snapshot_last($projectName);

    $table_name_id = $params['table_name'];
    $merge_as_primary_id = $params['merge_as_primary_id'];

    if($merge_as_primary_id != ""){

        $getTableName = $projectdb->query("SELECT table_name FROM tools_where WHERE id = '$table_name_id';");

        if ($getTableName->num_rows > 0) {
            $dataTN = $getTableName->fetch_assoc();
            $table_name = $dataTN['table_name'];
        }

        $projectdb->query("UPDATE $table_name SET merge_as_primary = '0' WHERE id IN  ($merge_as_primary_id);");
    }

    $message['code']=true;
    return $message;

}


function deselectAllMergeAsPrimary(STRING $projectName, ARRAY $params){

    global $projectdb;
    $projectdb = selectDatabase($projectName);

    take_snapshot_last($projectName);

    $table_name_id = $params['table_name'];

    $getTableName = $projectdb->query("SELECT table_name FROM tools_where WHERE id = '$table_name_id';");

    if ($getTableName->num_rows > 0) {
        $dataTN = $getTableName->fetch_assoc();
        $table_name = $dataTN['table_name'];

        $projectdb->query("UPDATE $table_name SET merge_as_primary = '0';");
    }

    $message['code']=true;
    return $message;

}


function setMergeObjects(STRING $projectName, ARRAY $params){

    $vsys = $params['vsys'];
    $source = $params['source'];
    $selection = $params['selection'];
    $cons_address_name = $params['cons_address_name'];
    $cons_address_name_value = $params['cons_address_name_value'];
    $cons_address_value = $params['cons_address_value'];
    $cons_addressgroups_name = $params['cons_addressgroups_name'];
    $cons_addressgroups_name_value = $params['cons_addressgroups_name_value'];
    $cons_addressgroups_value = $params['cons_addressgroups_value'];
    $cons_addressgroups_selection = $params['cons_addressgroups_selection'];
    $cons_services_name = $params['cons_services_name'];
    $cons_services_name_value = $params['cons_services_name_value'];
    $cons_services_value = $params['cons_services_value'];
    $cons_servicesgroups_name = $params['cons_servicesgroups_name'];
    $cons_servicesgroups_name_value = $params['cons_servicesgroups_name_value'];
    $cons_servicesgroups_value = $params['cons_servicesgroups_value'];
    $cons_servicesgroups_selection = $params['cons_servicesgroups_selection'];
    $cons_regions_name = $params['cons_regions_name'];
    $cons_regions_name_value = $params['cons_regions_name_value'];
    $cons_regions_value = $params['cons_regions_value'];
    $cons_tags_name = $params['cons_tags_name'];
    $cons_appgroups_name = $params['cons_appgroups_name'];
    $cons_appgroups_name_value = $params['cons_appgroups_name_value'];
    $cons_appgroups_value = $params['cons_appgroups_value'];
    $cons_app_name = $params['cons_app_name'];
    $cons_appfilters_name = $params['cons_appfilters_name'];

    $selection = !is_array($selection)? array_filter(explode(",", $selection)):array_filter($selection);

    if($cons_address_name == "true"){
        setMergeByNameAddress2($projectName, $selection, $vsys, $source);
    }
    elseif($cons_address_name_value == "true"){
        setMergeByNameValueAddress2($projectName, $selection, $vsys, $source);
    }
    elseif($cons_address_value == "true"){
        setMergeByValueAddress2($projectName, $selection, $vsys, $source);
    }
    elseif(($cons_addressgroups_name == "true") || ($cons_addressgroups_name_value == "true")){
        setMergeByNameGroups($projectName, $selection, $vsys, $source, "Address", "address_groups", "address_groups_id", "address", $cons_addressgroups_name_value);
    }
    elseif($cons_addressgroups_value == "true"){
        setMergeByValueGroups($projectName, $selection, $vsys, $source, "Address", "address_groups", "address_groups_id", "address");
    }
    elseif($cons_addressgroups_selection == "true"){
        setMergeBySelectionGroups($projectName, $selection, $vsys, $source, "Address", "address_groups", "address_groups_id", "address");
    }
    elseif($cons_services_name == "true"){
        setMergeByNameServices2($projectName, $selection, $vsys, $source);
    }
    elseif($cons_services_name_value == "true"){
        setMergeByNameValueServices2($projectName, $selection, $vsys, $source);
    }
    elseif($cons_services_value == "true"){
        setMergeByValueServices2($projectName, $selection, $vsys, $source);
    }
    elseif(($cons_servicesgroups_name == "true") || ($cons_servicesgroups_name_value == "true")){
        setMergeByNameGroups($projectName, $selection, $vsys, $source, "Services", "services_groups", "services_groups_id", "services", $cons_servicesgroups_name_value);
    }
    elseif($cons_servicesgroups_value == "true"){
        setMergeByValueGroups($projectName, $selection, $vsys, $source, "Services", "services_groups", "services_groups_id", "services");
    }
    elseif($cons_servicesgroups_selection == "true"){
        setMergeBySelectionGroups($projectName, $selection, $vsys, $source, "Services", "services_groups", "services_groups_id", "services");
    }
    elseif($cons_regions_name == "true"){
        setMergeByNameRegions2($projectName, $selection, $vsys, $source);
    }
    elseif($cons_regions_name_value == "true"){
        setMergeByNameValueRegions2($projectName, $selection, $vsys, $source);
    }
    elseif($cons_regions_value == "true"){
        setMergeByValueRegions2($projectName, $selection, $vsys, $source);
    }
    elseif($cons_tags_name == "true"){
        setMergeByNameTags($projectName, $selection, $vsys, $source);
    }
    elseif($cons_app_name == "true"){
        setMergeByNameApp2($projectName, $selection, $vsys, $source);
    }
    elseif(($cons_appgroups_name == "true") || ($cons_appgroups_name_value == "true")) {
        setMergeByNameGroups($projectName, $selection, $vsys, $source, "Applications", "applications_groups", "applications_groups_id", "applications", $cons_servicesgroups_name_value);
    }
    elseif($cons_appgroups_value == "true"){
        setMergeByValueGroups($projectName, $selection, $vsys, $source, "Applications", "applications_groups", "applications_groups_id", "applications");
    }
    elseif($cons_appfilters_name == "true"){
        setMergeByNameAppFilters($projectName, $selection, $vsys, $source);
    }

    $message['code']=true;
    return $message;


}


function setMergeByNameAddress(STRING $projectName, $selection, $vsys, $source){

    global $projectdb;
    global $app;

    $projectdb = selectDatabase($projectName);

    $user = $app->container->sentinel->getUser();
    $user_id = $user->id;

    $shared_member_lid = "";

    take_snapshot_last($projectName);

    $query = generate_query("objects");

    $version = calcVersion($source);

    if(count($selection) > 0) {
        $query = " WHERE id IN ($selection) ";
    }
    else{
        $getResultsTools = $projectdb->query("SELECT member_lid FROM tools_results WHERE table_name = 'address' AND source = '$source' AND user_id = '$user_id';");

        if ($getResultsTools->num_rows > 0) {

            while ($dataRT = $getResultsTools->fetch_assoc()){
                if($dataRT['member_lid'] != ""){
                    $member_lid[] = $dataRT['member_lid'];
                }else{
                    $member_lid = array();
                }
            }
            if(count($member_lid) > 0){
                $query = " WHERE id IN (" . implode(",", $member_lid) . ") ";
            }
            else{
                $query = " WHERE id IN ('') ";
            }
        }
        else{
            $query = " WHERE id IN ('') ";
        }
    }


    if ($vsys == "all") {
        #Merge and move to Shared
        $getDuplicated = $projectdb->query("SELECT id, name_ext, name, used, devicegroup, vsys, type, ipaddress, cidr, description, fqdn, v4, v6, vtype, source, tag, dummy "
            . "FROM address $query GROUP BY BINARY name ;");

        if ($getDuplicated->num_rows > 0) {

            $remove_objects = array();
            $remove_shared_objects = array();

            while ($data = $getDuplicated->fetch_assoc()) {

                $is_first_shared = true;
                $all_description = array();

                $id = $data['id'];
                $name = $data['name'];
                $name_ext = $data['name_ext'];
                $used = $data['used'];
                $devicegroup = $data['devicegroup'];
                $type = $data['type'];
                $ipaddress = $data['ipaddress'];
                $cidr = $data['cidr'];
                $description = addslashes($data['description']);
                $fqdn = $data['fqdn'];
                $v4 = $data['v4'];
                $v6 = $data['v6'];
                $vtype = $data['vtype'];
                $tag = $data['tag'];

                $duplicate_shared_member_lid = array();

                #Check if exits in shared
                $getShared = $projectdb->query("SELECT id, description FROM address $query AND source = '$source' AND BINARY name = '$name' AND vsys = 'shared' AND dummy = 0;");
                if ($getShared->num_rows == 0) {
                    $data["id"] = "";
                    $projectdb->query("INSERT INTO address (name_ext, name, used, devicegroup, vsys, type, ipaddress, cidr, description, fqdn, v4, v6, vtype, source, tag)  
                                      VALUES ('$name_ext', '$name', '$used', '$devicegroup', 'shared', '$type', '$ipaddress', '$cidr', '$description', '$fqdn', '$v4', '$v6', '$vtype', '$source', '$tag');");
                    $shared_member_lid = $projectdb->insert_id;
                    $all_description[] = $description;
                    add_log2('ok', 'Merging Duplicated Address', 'Duplicated Address [' . $name . '] merging and moving into Shared', $source, 'No Action required', 'objects', $shared_member_lid, 'address');
                }
                elseif ($getShared->num_rows == 1) {
                    $data = $getShared->fetch_assoc();
                    $shared_member_lid = $data['id'];
                    $all_description[] = $data['description'];

                    add_log2('ok', 'Merging Duplicated Address', 'Duplicated Address [' . $name . '] merging and moving into Shared', $source, 'No Action required', 'objects', $shared_member_lid, 'address');
                }
                else {
                    $error = 0;
                    # First merge in the shared space get the id from the first delete the others
                    add_log2('warning', 'Merging Duplicated Address', 'The are duplicate objects in the shared: ' . $name . '', $source, 'Merge automatically in the shared.', 'objects', $id, 'address');

                    while ($data = $getShared->fetch_assoc()) {
                        $duplicate_shared_member_lid[] = $data['id'];
                    }

                    // Check if exist selected merge as primary
                    $getPrimaryShared = $projectdb->query("SELECT id, description FROM address WHERE id IN (".implode(",", $duplicate_shared_member_lid).") AND merge_as_primary = '1' ;");
                    if ($getPrimaryShared->num_rows == 1) {
                        $dataPS = $getPrimaryShared->fetch_assoc();
                        $primary_member_lid_shared = $dataPS['id'];
                        $all_description[] = $dataPS['description'];
                        $is_first_shared = false;
                    }
                    elseif($getPrimaryShared->num_rows > 1){
                        $error = 1;
                        // Error, hay más de un selected as primary para un conjunto de duplicated name, add log
                        add_log2('warning', 'Merging Duplicated Address', 'Error when Duplicated Address [' . $name . '] merging: two or more selected as primary.', $source, 'No Action required', 'objects', $id, 'address');
                    }

                    if($error == 0) {
                        $getDupsInShared = $projectdb->query("SELECT id, description FROM address WHERE id IN (".implode(",", $duplicate_shared_member_lid).") AND merge_as_primary = '0';");
                        if ($getDupsInShared->num_rows > 0) {
                            while ($dataDIS = $getDupsInShared->fetch_assoc()) {
                                if ($is_first_shared == true) {
                                    $is_first_shared = false;
                                    $primary_member_lid_shared = $dataDIS['id'];
                                    $all_description[] = $dataDIS['description'];
                                }
                                else {
                                    #UPDATE where other address are used
                                    $member_lid = $dataDIS['id'];
                                    $all_description[] = $dataDIS['description'];

                                    updateMemberLid($projectName, $primary_member_lid_shared, $member_lid, "address");

                                    $remove_shared_objects[] = $member_lid;
                                }
                            }
                        }
                        if (count($remove_shared_objects) > 0) {
                            $projectdb->query("DELETE FROM address WHERE id IN (" . implode(",", $remove_shared_objects) . ");");
                        }
                        $shared_member_lid = $primary_member_lid_shared;
                        //finish merge in shared 2 or more address shared
                    }
                }

                $getDups = $projectdb->query("SELECT id, description FROM address $query AND source = '$source' AND BINARY name = '$name' AND vsys != 'shared' AND dummy = 0;");
                if ($getDups->num_rows > 0) {
                    while ($dataDups = $getDups->fetch_assoc()) {
                        $member_lid = $dataDups['id'];
                        $all_description[] = $dataDups['description'];

                        #UPDATE where other address are used
                        $primary_member_lid = $shared_member_lid;

                        updateMemberLid($projectName, $primary_member_lid, $member_lid, "address");

                        $remove_objects[] = $member_lid;
                    }
                }
                cleanDuplicatedMembersMerging($primary_member_lid, "address");

                $all_description = array_unique($all_description);
                $finally_description = implode(", ", $all_description);
                $finally_description = truncate_descriptions($finally_description, $version);

                $projectdb->query("UPDATE address SET merge_as_primary = '0', description = '$finally_description' WHERE id = '$primary_member_lid';");
            }
            if (count($remove_objects) > 0) {
                $projectdb->query("DELETE FROM address WHERE id IN (" . implode(",", $remove_objects) . ");");
            }

        }
    }
    else {
        #Merge in the same VSYS
        $getDuplicated = $projectdb->query("SELECT id, name FROM address $query GROUP BY BINARY name ;");

        if ($getDuplicated->num_rows > 0) {
            while ($dataD = $getDuplicated->fetch_assoc()) {
                $is_first = true;
                $error = 0;
                $remove_objects = array();
                $all_description = array();

                $name = $dataD['name'];
                $id = $dataD['id'];

                add_log2('ok', 'Merging Duplicated Address', 'Duplicated Address [' . $name . '] merging', $source, 'No Action required', 'objects', $id, 'address');

                // Check if exist selected merge as primary
                $getPrimary = $projectdb->query("SELECT id, description FROM address $query AND BINARY name = '$name' AND merge_as_primary = '1' ;");
                //echo "2. SELECT id FROM address $query AND BINARY name = '$name' AND merge_as_primary = '1' ;";
                if ($getPrimary->num_rows == 1) {
                    $dataP = $getPrimary->fetch_assoc();
                    $primary_member_lid = $dataP['id'];
                    $all_description[] = $dataP['description'];
                    $is_first = false;
                }
                elseif($getPrimary->num_rows > 1){
                    $error = 1;
                    // Error, hay más de un selected as primary para un conjunto de duplicated name, add log
                    add_log2('warning', 'Merging Duplicated Address', 'Error when Duplicated Address [' . $name . '] merging: two or more selected as primary.', $source, 'No Action required', 'objects', $id, 'address');
                }

                if($error == 0){
                    $getDupsByName = $projectdb->query("SELECT id, description FROM address $query AND BINARY name = '$name' AND merge_as_primary = '0';");

                    if ($getDupsByName->num_rows > 0) {
                        while ($dataDBN = $getDupsByName->fetch_assoc()) {
                            if ($is_first == true) {
                                $is_first = false;
                                $primary_member_lid = $dataDBN['id'];
                                $all_description[] = $dataDBN['description'];
                            }
                            else {
                                #UPDATE where other address are used
                                $member_lid = $dataDBN['id'];
                                $all_description[] = $dataDBN['description'];

                                updateMemberLid($projectName, $primary_member_lid, $member_lid, "address");

                                $remove_objects[] = $member_lid;
                            }
                        }
                        cleanDuplicatedMembersMerging($primary_member_lid, "address");

                        $all_description = array_unique($all_description);
                        $finally_description = implode(", ", $all_description);
                        $finally_description = truncate_descriptions($finally_description, $version);

                        $projectdb->query("UPDATE address SET merge_as_primary = '0', description = '$finally_description' WHERE id = '$primary_member_lid';");
                    }
                    if (count($remove_objects) > 0) {
                        $projectdb->query("DELETE FROM address WHERE id IN (" . implode(",", $remove_objects) . ");");
                    }

                }
            }
        }
    }

    check_used_objects_new();
}


function setMergeByNameAddress2(STRING $projectName, ARRAY $selection, $vsys, $source){

    global $app;
    global $projectdb;
    $projectdb = selectDatabase($projectName);

    $me = $app->sentinel->getUser();
    $addressMerger = new AddressMerger($projectName, $me['id'], $source);
    $addressMerger->setMergerByFields(['name']);

    $addressMerger->merge($selection);

}


function setMergeByNameValueAddress2(STRING $projectName, ARRAY $selection, $vsys, $source){

    global $app;
    global $projectdb;
    $projectdb = selectDatabase($projectName);

    $me = $app->sentinel->getUser();
    $addressMerger = new AddressMerger($projectName, $me['id'], $source);
    $addressMerger->setSelection($selection);
    $addressMerger->setMergerByFields(['name','type','ipaddress','cidr']);
    $addressMerger->merge($selection);

}


function setMergeByNameValueAddress(STRING $projectName, $selection, $vsys, $source){

    global $projectdb;
    global $app;

    $projectdb = selectDatabase($projectName);
    $version = calcVersion($source);

    $user = $app->container->sentinel->getUser();
    $user_id = $user->id;

    take_snapshot_last($projectName);

    if(count($selection) > 0) {
        $query = " WHERE id IN ($selection) ";
    }
    else{
        $getResultsTools = $projectdb->query("SELECT member_lid FROM tools_results WHERE table_name = 'address' AND source = '$source' AND user_id = '$user_id';");

        if ($getResultsTools->num_rows > 0) {

            while ($dataRT = $getResultsTools->fetch_assoc()){
                if($dataRT['member_lid'] != ""){
                    $member_lid[] = $dataRT['member_lid'];
                }else{
                    $member_lid = array();
                }
            }
            if(count($member_lid) > 0){
                $query = " WHERE id IN (" . implode(",", $member_lid) . ") ";
            }
            else{
                $query = " WHERE id IN ('') ";
            }
        }
        else{
            $query = " WHERE id IN ('') ";
        }
    }

//        $memoryHandler = new MemoryObjectsHandler();
//        $memoryHandler->loadAddress($projectdb, $member_lid);
//
////        print_r($memoryHandler);
//
//        $memoryHandler->address->groupBy(['name',"cidr","ipaddress"]);
//
//        die;
    $queryDuplicateds = "SELECT id, name, type, ipaddress, cidr ".
        "FROM ( ".
        "    select id, name, type, ipaddress, if(cidr='','32',cidr) as cidr from address ".  //sanitize the cidr
        ") t ".
        "$query GROUP BY BINARY name, type, ipaddress, cidr ;";
    $getDuplicated = $projectdb->query($queryDuplicateds);

    if ($getDuplicated->num_rows > 0) {
        while ($dataD = $getDuplicated->fetch_assoc()) {
            $remove_objects = array();
            $name = $dataD['name'];
            $id = $dataD['id'];
            $type = $dataD['type'];
            $ipaddress = $dataD['ipaddress'];
            $cidr = $dataD['cidr'];

            $members = array();
            $primaryLevel = INF;
            $primaryID = null;


            if(($cidr == "") || ($cidr == "32")){
                $sql_cidr = " AND (cidr = '' OR cidr = '32') ";
            }else{
                $sql_cidr = " AND cidr = '$cidr' ";
            }

            add_log2('ok', 'Merging Duplicated Address', 'Duplicated Address [' . $name . '] merging', $source, 'No Action required', 'objects', $id, 'address');

            //Checking which of the addresses is the highest one in the DG hierachy
            $getAllCopiesQuery = "SELECT id, vsys, name, ipaddress, description, source FROM address $query AND BINARY name = '$name' AND type = '$type' AND ipaddress = '$ipaddress' $sql_cidr ;";
            $allCopies = $projectdb->query($getAllCopiesQuery);
            if($allCopies->num_rows>1){
                while ($addressData = $allCopies->fetch_assoc()){
                    $addressData['vsyses'] = getVsyses($projectdb, $addressData['vsys'], $addressData['source']);
                    $addressData['max'] = count($addressData['vsyses']);
                    $members[$addressData['id']] = $addressData;
                    if($addressData['max'] < $primaryLevel){
                        $primaryLevel = $addressData['max'];
                        $primaryID = $addressData['id'];
                    }
                }
            }

            //Verify which DG is the target to host the address
            //Example
            /*                  shared                                                    shared
             *             ____/      \____                                          ____/      \____
             *         DG1                 DG2(a1)                               DG1 (a1)            DG2
             *        /                 __/   \__                               /                 __/   \__
             *    DG11              DG21(a2)     DG22(a3)                   DG11              DG21(a2)     DG22(a3)
             *
             *         we will use a1 as primary                          we will use a1 as primary, but moved to shared
             */
            $inAllVsyses = false;
            $currentVsys ='';
            while(!$inAllVsyses){
                $missing = false;
                $currentVsys = $members[$primaryID]['vsyses'][0];

                foreach ($members as $member){
                    if(!in_array($currentVsys, $member['vsyses'])){
                        array_shift($members[$primaryID]['vsyses']);
                        $missing = true;
                        break;
                    }
                }
                if(!$missing) {
                    $inAllVsyses = true;
                }
            }

            $description = array();
            $description[] = $members[$primaryID]['description'];
            if($inAllVsyses) {
                foreach ($members as $member) {
                    if ($member['id'] != $members[$primaryID]['id']) {
                        $remove_objects[] = $member['id'];
                        $description[] = $member['description'];
                    }
                }
                $all_description = array_unique($description);
                $final_description = implode(", ", $all_description);
                $final_description = truncate_descriptions($final_description, $version);

                $queryUpdateVsys = "UPDATE address set vsys='$currentVsys', description='$final_description' WHERE id = '" . $members[$primaryID]['id'] . "';";
                $projectdb->query($queryUpdateVsys);
                add_log2('ok',
                    "Merging Duplicated Address",
                    "The are duplicate objects for [$name]. Merging and moving into $currentVsys",
                    $source,
                    "Merge automatically in the $currentVsys.",
                    'objects',
                    $id,
                    'address');

                if(count($remove_objects)>0) {
                    updateMemberLidBulks($projectdb, $members[$primaryID]['id'], $remove_objects, "address");
                    $projectdb->query("DELETE FROM address WHERE id IN (" . implode(",", $remove_objects) . ");");
                }
            }
            else{
                add_log2('Warning',
                    "Merging Duplicated Address",
                    "The are duplicate objects for [$name] but there is no common DG in which could be merged",
                    $source,
                    "Invalid DG structure?",
                    'objects',
                    $id,
                    'address');
            }
        }
    }

    check_used_objects_new();
}


function setMergeByValueAddress2(STRING $projectName, ARRAY $selection, $vsys, $source)
{
    global $app;
    global $projectdb;
    $projectdb = selectDatabase($projectName);

    $me = $app->sentinel->getUser();
    $addressMerger = new AddressMerger($projectName, $me['id'], $source);
    $addressMerger->setMergerByFields(['type','ipaddress','cidr']);
    $addressMerger->merge($selection);

}


function setMergeByValueAddress(STRING $projectName, $selection, $vsys, $source){

    global $projectdb;
    global $app;

    $projectdb = selectDatabase($projectName);

    $user = $app->container->sentinel->getUser();
    $user_id = $user->id;

    take_snapshot_last($projectName);

    $query = generate_query("objects");

    $version = calcVersion($source);

    if(count($selection) > 0) {
        $query = " WHERE id IN ($selection) ";
    }
    else{
        $getResultsTools = $projectdb->query("SELECT member_lid FROM tools_results WHERE table_name = 'address' AND source = '$source' AND user_id = '$user_id';");

        if ($getResultsTools->num_rows > 0) {

            while ($dataRT = $getResultsTools->fetch_assoc()){
                if($dataRT['member_lid'] != ""){
                    $member_lid[] = $dataRT['member_lid'];
                }else{
                    $member_lid = array();
                }
            }
            if(count($member_lid) > 0){
                $query = " WHERE id IN (" . implode(",", $member_lid) . ") ";
            }
            else{
                $query = " WHERE id IN ('') ";
            }
        }
        else{
            $query = " WHERE id IN ('') ";
        }
    }

    if ($vsys == "all") {
        #Merge and move to Shared
        //$getDuplicated = $projectdb->query("SELECT id, name_ext, name, used, devicegroup, vsys, type, ipaddress, cidr, description, fqdn, v4, v6, vtype, source, tag, dummy "
        //    . "FROM address $query GROUP BY type, ipaddress, cidr ;");

        $getDuplicated = $projectdb->query("SELECT id, name_ext, name, used, devicegroup, vsys, type, ipaddress, cidr, description, fqdn, v4, v6, vtype, source, tag, dummy "
            . "FROM address $query GROUP BY type, ipaddress, cidr ;");

        //echo "1. SELECT id, name_ext, name, used, devicegroup, vsys, type, ipaddress, cidr, description, fqdn, v4, v6, vtype, source, tag, dummy "
        //    . "FROM address $query GROUP BY type, ipaddress, cidr ;\n";

        if ($getDuplicated->num_rows > 0) {

            $remove_objects = array();
            $remove_shared_objects = array();

            while ($data = $getDuplicated->fetch_assoc()) {
                $is_first_shared = true;
                $all_description = array();

                $id = $data['id'];
                $name = $data['name'];
                $name_ext = $data['name_ext'];
                $used = $data['used'];
                $devicegroup = $data['devicegroup'];
                $type = $data['type'];
                $ipaddress = $data['ipaddress'];
                $cidr = $data['cidr'];
                $description = addslashes($data['description']);
                $fqdn = $data['fqdn'];
                $v4 = $data['v4'];
                $v6 = $data['v6'];
                $vtype = $data['vtype'];
                $tag = $data['tag'];

                if(($cidr == "") || ($cidr == "32")){
                    $sql_cidr = " AND (cidr = '' OR cidr = '32') ";
                }else{
                    $sql_cidr = " AND cidr = '$cidr' ";
                }

                $duplicate_shared_member_lid = array();

                #Check if exits in shared
                $getShared = $projectdb->query("SELECT id, description FROM address WHERE source = '$source' AND type = '$type' AND ipaddress = '$ipaddress' $sql_cidr AND vsys = 'shared' AND dummy = 0;");
                if ($getShared->num_rows == 0) {
                    $data["id"] = "";
                    $projectdb->query("INSERT INTO address (name_ext, name, used, devicegroup, vsys, type, ipaddress, cidr, description, fqdn, v4, v6, vtype, source, tag)  
                                      VALUES ('$name_ext', '$name', '$used', '$devicegroup', 'shared', '$type', '$ipaddress', '$cidr', '$description', '$fqdn', '$v4', '$v6', '$vtype', '$source', '$tag');");
                    //echo "INSERT INTO address (name_ext, name, used, devicegroup, vsys, type, ipaddress, cidr, description, fqdn, v4, v6, vtype, source, tag)
                    //                  VALUES ('$name_ext', '$name', '$used', '$devicegroup', 'shared', '$type', '$ipaddress', '$cidr', '$description', '$fqdn', '$v4', '$v6', '$vtype', '$source', '$tag');\n";
                    $shared_member_lid = $projectdb->insert_id;
                    $all_description[] = $description;

                    add_log2('ok', 'Merging Duplicated Address', 'Duplicated Address [' . $name . '] merging and moving into Shared', $source, 'No Action required', 'objects', $shared_member_lid, 'address');
                }
                elseif ($getShared->num_rows == 1) {
                    $data = $getShared->fetch_assoc();
                    $shared_member_lid = $data['id'];
                    $all_description[] = $data['description'];

                    add_log2('ok', 'Merging Duplicated Address', 'Duplicated Address [' . $name . '] merging and moving into Shared', $source, 'No Action required', 'objects', $shared_member_lid, 'address');
                }
                else {
                    $error = 0;
                    # First merge in the shared space get the id from the first delete the others
                    add_log2('warning', 'Merging Duplicated Address', 'The are duplicate objects in the shared: ' . $name . '', $source, 'Merge automatically in the shared.', 'objects', $id, 'address');

                    while ($data = $getShared->fetch_assoc()) {
                        $duplicate_shared_member_lid[] = $data['id'];
                    }

                    // Check if exist selected merge as primary
                    $getPrimaryShared = $projectdb->query("SELECT id, description FROM address WHERE id IN (".implode(",", $duplicate_shared_member_lid).") AND merge_as_primary = '1' ;");
                    if ($getPrimaryShared->num_rows == 1) {
                        $dataPS = $getPrimaryShared->fetch_assoc();
                        $primary_member_lid_shared = $dataPS['id'];
                        $all_description[] = $dataPS['description'];
                        $is_first_shared = false;
                    }
                    elseif($getPrimaryShared->num_rows > 1){
                        $error = 1;
                        // Error, hay más de un selected as primary para un conjunto de duplicated name, add log
                        add_log2('warning', 'Merging Duplicated Address', 'Error when Duplicated Address [' . $name . '] merging: two or more selected as primary.', $source, 'No Action required', 'objects', $id, 'address');
                    }

                    if($error == 0) {
                        $getDupsInShared = $projectdb->query("SELECT id, description FROM address WHERE id IN (".implode(",", $duplicate_shared_member_lid).") AND merge_as_primary = '0';");
                        if ($getDupsInShared->num_rows > 0) {
                            while ($dataDIS = $getDupsInShared->fetch_assoc()) {
                                if ($is_first_shared == true) {
                                    $is_first_shared = false;
                                    $primary_member_lid_shared = $dataDIS['id'];
                                    $all_description[] = $dataDIS['description'];
                                }
                                else {
                                    #UPDATE where other address are used
                                    $member_lid = $dataDIS['id'];
                                    $all_description[] = $dataDIS['description'];

                                    updateMemberLid($projectName, $primary_member_lid_shared, $member_lid, "address");

                                    $remove_shared_objects[] = $member_lid;
                                }
                            }
                        }
                        if (count($remove_shared_objects) > 0) {
                            $projectdb->query("DELETE FROM address WHERE id IN (" . implode(",", $remove_shared_objects) . ");");
                        }
                        $shared_member_lid = $primary_member_lid_shared;
                        //finish merge in shared 2 or more address shared
                    }
                }

                $getDups = $projectdb->query("SELECT id, description FROM address $query AND source = '$source' AND type = '$type' AND ipaddress = '$ipaddress' $sql_cidr AND vsys != 'shared' AND dummy = 0;");
                //echo "3. SELECT id FROM address $query AND source = '$source' AND type = '$type' AND ipaddress = '$ipaddress' $sql_cidr AND vsys != 'shared' AND dummy = 0;\n";
                if ($getDups->num_rows > 0) {
                    while ($dataDups = $getDups->fetch_assoc()) {
                        $member_lid = $dataDups['id'];
                        $all_description[] = $dataDups['description'];

                        #UPDATE where other address are used
                        $primary_member_lid = $shared_member_lid;

                        updateMemberLid($projectName, $primary_member_lid, $member_lid, "address");

                        $remove_objects[] = $member_lid;
                    }
                }
                cleanDuplicatedMembersMerging($primary_member_lid, "address");

                $all_description = array_unique($all_description);
                $finally_description = implode(", ", $all_description);
                $finally_description = truncate_descriptions($finally_description, $version);

                $projectdb->query("UPDATE address SET merge_as_primary = '0', description = '$finally_description' WHERE id = '$primary_member_lid';");
            }
            if (count($remove_objects) > 0) {
                $projectdb->query("DELETE FROM address WHERE id IN (" . implode(",", $remove_objects) . ");");
            }

        }
    }
    else {
        #Merge in the same VSYS
        $getDuplicated = $projectdb->query("SELECT id, name, type, ipaddress, cidr FROM address $query GROUP BY type, ipaddress, cidr ;");
        //$getDuplicated = $projectdb->query("SELECT id, name, type, ipaddress, IF(cidr='', '32', cidr) AS cidr FROM address $query GROUP BY type, ipaddress, cidr ;");

        if ($getDuplicated->num_rows > 0) {
            while ($dataD = $getDuplicated->fetch_assoc()) {
                $is_first = true;
                $error = 0;
                $remove_objects = array();
                $all_description = array();

                $name = $dataD['name'];
                $id = $dataD['id'];
                $type = $dataD['type'];
                $ipaddress = $dataD['ipaddress'];
                $cidr = $dataD['cidr'];

                if(($cidr == "") || ($cidr == "32")){
                    $sql_cidr = " AND (cidr = '' OR cidr = '32') ";
                }else{
                    $sql_cidr = " AND cidr = '$cidr' ";
                }

                add_log2('ok', 'Merging Duplicated Address', 'Duplicated Address [' . $name . '] merging', $source, 'No Action required', 'objects', $id, 'address');

                // Check if exist selected merge as primary
                //$getPrimary = $projectdb->query("SELECT id FROM address $query AND type = '$type' AND ipaddress = '$ipaddress' AND cidr = '$cidr' AND merge_as_primary = '1' ;");
                $getPrimary = $projectdb->query("SELECT id, description FROM address $query AND type = '$type' AND ipaddress = '$ipaddress' $sql_cidr AND merge_as_primary = '1' ;");

                if ($getPrimary->num_rows == 1) {
                    $dataP = $getPrimary->fetch_assoc();
                    $primary_member_lid = $dataP['id'];
                    $all_description[] = $dataP['description'];
                    $is_first = false;
                }
                elseif($getPrimary->num_rows > 1){
                    $error = 1;
                    // Error, hay más de un selected as primary para un conjunto de duplicated name, add log
                    add_log2('warning', 'Merging Duplicated Address', 'Error when Duplicated Address [' . $name . '] merging: two or more selected as primary.', $source, 'No Action required', 'objects', $id, 'address');
                }

                if($error == 0){
                    //$getDupsByName = $projectdb->query("SELECT id FROM address $query AND type = '$type' AND ipaddress = '$ipaddress' AND cidr = '$cidr' AND merge_as_primary = '0';");
                    $getDupsByName = $projectdb->query("SELECT id, description FROM address $query AND type = '$type' AND ipaddress = '$ipaddress' $sql_cidr AND merge_as_primary = '0';");

                    if ($getDupsByName->num_rows > 0) {
                        while ($dataDBN = $getDupsByName->fetch_assoc()) {
                            if ($is_first == true) {
                                $is_first = false;
                                $primary_member_lid = $dataDBN['id'];
                                $all_description[] = $dataDBN['description'];
                            }
                            else {
                                #UPDATE where other address are used
                                $member_lid = $dataDBN['id'];
                                $all_description[] = $dataDBN['description'];

                                updateMemberLid($projectName, $primary_member_lid, $member_lid, "address");

                                $remove_objects[] = $member_lid;
                            }
                        }
                        cleanDuplicatedMembersMerging($primary_member_lid, "address");

                        $all_description = array_unique($all_description);
                        $finally_description = implode(", ", $all_description);
                        $finally_description = truncate_descriptions($finally_description, $version);

                        $projectdb->query("UPDATE address SET merge_as_primary = '0', description = '$finally_description' WHERE id = '$primary_member_lid';");
                    }
                    if (count($remove_objects) > 0) {
                        $projectdb->query("DELETE FROM address WHERE id IN (" . implode(",", $remove_objects) . ");");
                    }
                }
            }
        }
    }
    check_used_objects_new();

}

// User has selected all as default vysys
// that means that we could have objects coming from different vsys
// we need to check if All (meaning shared) is the common vsys to store the merged object
// to avoid sending the merged objet to the shared vsys if it's not needed
function getFirstCommonVsys($table_name_id, $sql_ids){

    global $projectdb;

    $get_vsys_query = "SELECT distinct(vsys) FROM $table_name_id where id IN (" . implode(",", $sql_ids) . ")";
    $get_vsys_result = $projectdb->query($get_vsys_query);
    if ($get_vsys_result->num_rows == 1) {
        // all objects to merge are in the same vsys then get it as the primary vsys
        $get_vsys_data = $get_vsys_result->fetch_assoc();
        $vsys = $get_vsys_data['vsys'];
    } else if($get_vsys_result->num_rows > 0){
        // Get all duplicates and look for the common vsys
        $duplicated_members = array();
        $get_vsys_dup_query = "SELECT id, vsys, source, merge_as_primary FROM $table_name_id where id IN (" . implode(",", $sql_ids) . ")";
        $get_vsys_dup_result = $projectdb->query($get_vsys_dup_query);
        $merge_as_primary = 0;
        while($get_vsys_dup_data = $get_vsys_dup_result->fetch_assoc()){

            $dup_id = $get_vsys_dup_data['id'];
            $dup_vsys = $get_vsys_dup_data['vsys'];
            $dup_source = $get_vsys_dup_data['source'];
            $dup_merge_as_primary= $get_vsys_dup_data['merge_as_primary'];

            $duplicated_members[$dup_id]['id']=$dup_id;
            $duplicated_members[$dup_id]['vsys']=$dup_vsys;
            $duplicated_members[$dup_id]['source']=$dup_source;
            $duplicated_members[$dup_id]['merge_as_primary']=$dup_merge_as_primary;

            if($merge_as_primary==0){
                $merge_as_primary = $dup_id; // first is got as primary by default
            }
            if($dup_merge_as_primary==1){
                $merge_as_primary = $dup_id; // get the primary if defined
            }

        }

        //Verify which DG is the target to host the address
        //Example
        /*                  shared                                                    shared
         *             ____/      \____                                          ____/      \____
         *         DG1                 DG2(a1)                               DG1 (a1)            DG2
         *        /                 __/   \__                               /                 __/   \__
         *    DG11              DG21(a2)     DG22(a3)                   DG11              DG21(a2)     DG22(a3)
         *
         *         we will use a1 as primary                          we will use a1 as primary, but moved to shared
         */

        $vsysesMapping = [];
        //Collect the vsyses
        foreach ($duplicated_members as &$member) {
            //Check the vsyses
            if (!isset($vsysesMapping[$member['vsys']])) {
                $vsysesMapping[$member['vsys']] = getVsyses($projectdb, $member['vsys'], $member['source']);
            }
            $member['vsyses'] = $vsysesMapping[$member['vsys']];
        }

        $inAllVsyses = false;
        $currentVsys ='';
        $empty = false;

        $vsyses = $duplicated_members[$merge_as_primary]['vsyses'];

        while(!$inAllVsyses && !$empty){
            $missing = false;
            $currentVsys = $vsyses[0];
            foreach ($duplicated_members as &$member){
                if(!in_array($currentVsys, $member['vsyses'])){
                    array_shift($duplicated_members[$merge_as_primary]['vsyses']);
                    if(is_null(array_shift($vsyses))){
                        $empty = true;
                    }
                    $missing = true;
                    break;
                }
            }
            if(!$missing) {
                $inAllVsyses = true;
            }
        }

        if(!$inAllVsyses){
            return null;
        }

        $vsys = $currentVsys;
    }

    return $vsys;
}

function setMergeByNameGroups(STRING $projectName, $selection, $vsys, $source, $type_log, $table_name, $table_name_id, $table, $nameAndValue = "true"){

    global $projectdb;
    global $app;

    $projectdb = selectDatabase($projectName);

    $user = $app->container->sentinel->getUser();
    $user_id = $user->id;

    take_snapshot_last($projectName);

    //$query = generate_query("objects");

    require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
    $vsys_query = prepareVsysQuery($projectdb, $vsys, $source);

    $version = calcVersion($source);

    $mylids = array();

    if(count($selection) > 0) {
        $query_selection = " AND id IN (".implode(",",$selection).") ";
    }
    else{
        $query_selection = "";
    }

    $projectdb->query("TRUNCATE TABLE tmp_dup_name_val;");
    $query = "SELECT * FROM $table_name_id a WHERE source = '$source' $vsys_query $query_selection GROUP BY BINARY name HAVING count(*) > 1;";
    //echo "Query 1: " .$query. "\n";
    $getAll = $projectdb->query($query);

    if ($getAll->num_rows > 0) {
        while ($getLimitData = $getAll->fetch_assoc()) {
            $name_int = $getLimitData['name'];

            $query = "SELECT * FROM $table_name_id a WHERE source = '$source' $vsys_query AND BINARY name = '$name_int' ;";
            $getAll2 = $projectdb->query($query);

            while ($data3 = $getAll2->fetch_assoc()) {
                $lid = $data3['id'];
                $name_int = $data3['name'];
                $members = $projectdb->query("SELECT table_name, member_lid FROM $table_name WHERE lid = '$lid'");
                $membername = array();
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
                }else{
                    $getLog = $projectdb->query("SELECT id FROM logs WHERE obj_id='$lid' AND obj_table='$table_name' AND obj_type='objects' AND message LIKE '%No Members%';");
                    if ($getLog->num_rows == 0) {
                        add_log2('error', 'Invalid Group', 'The '.$table_name.' Group [' . $name_int . '] has No Members', '', 'Please Remove this Group or Add some Members', 'objects', $lid, $table_name);
                    }
                }
                asort($membername);
                $projectdb->query("INSERT INTO tmp_dup_name_val (lid,members,table_name,name) VALUES ('$lid','" . implode(",", $membername) . "','$table_name','$name_int');");
            }
        }
        # Get names from temp table where members are equal
        if($nameAndValue=="true") {
            $getDup = $projectdb->query("SELECT lid, table_name, name, members, count(id) as t FROM tmp_dup_name_val GROUP BY BINARY name, members HAVING t>1;");
        }else{
            $getDup = $projectdb->query("SELECT lid, table_name, name, members, count(id) as t FROM tmp_dup_name_val GROUP BY BINARY name HAVING t>1;");
        }

        $sql_ids = array();
        if ($getDup->num_rows > 0) {
            while ($getnames = $getDup->fetch_assoc()) {
                $themembers = $getnames['members'];
                $name_duplicated = $getnames['name'];
                if($nameAndValue=="true") {
                    $getbyMember = $projectdb->query("SELECT lid FROM tmp_dup_name_val WHERE members = '$themembers' AND name = '$name_duplicated';");
                }else {
                    $getbyMember = $projectdb->query("SELECT lid FROM tmp_dup_name_val WHERE name = '$name_duplicated';");
                }
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
        //$query = "SELECT id FROM $table_name_id a $conditions $orderby";
    }

    /*if(count($selection) > 0) {
        $query = " WHERE id IN (".implode(",",$selection).") ";
    }
    else{
        $getResultsTools = $projectdb->query("SELECT member_lid FROM tools_results WHERE table_name = '$table_name_id' AND source = '$source' AND user_id = '$user_id';");

        if ($getResultsTools->num_rows > 0) {

            while ($dataRT = $getResultsTools->fetch_assoc()){
                if($dataRT['member_lid'] != ""){
                    $member_lid[] = $dataRT['member_lid'];
                }else{
                    $member_lid = array();
                }
            }
            if(count($member_lid) > 0){
                $query = " WHERE id IN (" . implode(",", $member_lid) . ") ";
            }
            else{
                $query = " WHERE id IN ('') ";
            }
        }else{
            $query = " WHERE id IN ('') ";
        }
    }*/
    $used_merge = '0';
    if(isset($sql_ids) && count($sql_ids)>0){
        // Get "used" flag instead of recalculate used object for the whole project
        $query_get_used = "SELECT id from " . $table_name_id . " where used = '1' and id IN (" . implode(",", $sql_ids) . ")";
        $get_used = $projectdb->query($query_get_used);
        if ($get_used->num_rows > 0) {
            $used_merge = '1';
        }
    }

    // User has selected all or an specific $vsys as destination $vsys
    // but we could have objects coming from different vsys
    // so we need to check what is the parent $vsys for the given duplicated objects
    // store the selected $vsys
    $selected_vsys = $vsys;
    $common_vsys = null;
    if(isset($sql_ids) && count($sql_ids)>0) {
        // get the common parent vsys for the given duplicated objects
        $common_vsys = getFirstCommonVsys($table_name_id, $sql_ids);
    }

    if(!is_null($common_vsys)) {
        // if $vsys is not shared get it
        $vsys = $common_vsys;
    }else{
        // there isn't any common parent $vsys so it should be moved to shared
        $vsys = "shared";
    }

    // if the selected $vsys is not the destination one then we need to move it to the common parent one
    if($vsys != $selected_vsys){
        $selected_vsys="all";
    }

    // if shared vsys is not still created then create it
    if($vsys=="shared" && count($sql_ids)>0){
        checkExistShared($source);
    }

    // when selected_vsys is all we are moving the merged object into shared vsys or the first common shared one
    if ($selected_vsys=="all") {

        $getDuplicated = $projectdb->query("SELECT id, name, name_ext, vsys, source, tag, type, description, used, filter, devicegroup  "
            . "FROM $table_name_id $conditions GROUP BY BINARY name;");

        if ($getDuplicated->num_rows > 0) {

            $remove_objects = array();
            $remove_shared_objects = array();
            $duplicate_shared_member_lid = array();
            $mylids = array();
            while ($dataD = $getDuplicated->fetch_assoc()) {

                $is_first_shared = true;
                $is_first = true;
                $all_description = array();

                $groupnameoriginal = $dataD['name_ext'];
                $groupname = $dataD['name'];
                $id = $dataD['id'];
                $source = $dataD['source'];
                $usedgroup = $dataD['used'];
                $typegroup = $dataD['type'];
                $description = addslashes($dataD['description']);
                $tag = $dataD['tag'];
                $filter = addslashes($dataD['filter']);
                $devicegroup = $dataD['devicegroup'];

                //if ($is_first == true) {
                //    $is_first = false;
                #Check if exits in shared
                $getShared = $projectdb->query("SELECT id, description FROM $table_name_id WHERE source = '$source' AND BINARY name = '$groupname' AND vsys = '$vsys';");
                if ($getShared->num_rows == 0) {
                    $data["id"] = "";
                    $projectdb->query("INSERT INTO $table_name_id (name_ext, name, used, devicegroup, vsys, type, filter, description, source, tag)  
                        VALUES ('$groupnameoriginal', '$groupname', '$usedgroup', '$devicegroup', '$vsys', '$typegroup', '$filter', '$description', '$source', '$tag');");
                    $shared_member_lid = $projectdb->insert_id;
                    $all_description[] = $description;

                    add_log2('ok', 'Merging Duplicated '.$type_log.' Group', 'Duplicated '.$type_log.' Group [' . $groupname . '] merging and moving into '. $vsys, $source, 'No Action required', 'objects', $shared_member_lid, $table_name_id);
                }
                elseif ($getShared->num_rows == 1) {
                    $data = $getShared->fetch_assoc();
                    $shared_member_lid = $data['id'];
                    $all_description[] = $data['description'];

                    $mylids[] = $shared_member_lid.";".$table_name.";".$groupname.";".$vsys;
                    add_log2('ok', 'Merging Duplicated '.$type_log.' Group', 'Duplicated '.$type_log.' Group [' . $groupname . '] merging and moving into '. $vsys, $source, 'No Action required', 'objects', $shared_member_lid, $table_name_id);
                }
                else {
                    # First merge in the shared space get the id from the first delete the others

                    $error = 0;
                    # First merge in the shared space get the id from the first delete the others
                    add_log2('warning', 'Merging Duplicated '.$type_log.' Group', 'The are duplicate objects in the  '. $vsys . ':' . $groupname . '', $source, 'Merge automatically in the shared.', 'objects', $id, $table_name_id);
                    $duplicate_shared_member_lid = [];
                    while ($data = $getShared->fetch_assoc()) {
                        $duplicate_shared_member_lid[] = $data['id'];
                    }

                    // Check if exist selected merge as primary
                    $getPrimaryShared = $projectdb->query("SELECT id, description FROM $table_name_id WHERE id IN (".implode(",", $duplicate_shared_member_lid).") AND merge_as_primary = '1' ;");
                    if ($getPrimaryShared->num_rows == 1) {
                        $dataPS = $getPrimaryShared->fetch_assoc();
                        $primary_member_lid_shared = $dataPS['id'];
                        $all_description[] = $dataPS['description'];
                        $mylids[] = $primary_member_lid_shared.";".$table_name.";".$groupname.";".$vsys;
                        $is_first_shared = false;
                    }
                    elseif($getPrimaryShared->num_rows > 1){
                        $error = 1;
                        // Error, hay más de un selected as primary para un conjunto de duplicated name, add log
                        add_log2('warning', 'Merging Duplicated '.$type_log.' Group', 'Error when Duplicated '.$type_log.' Group [' . $groupname . '] merging: two or more selected as primary.', $source, 'No Action required', 'objects', $id, $table_name_id);
                    }

                    if($error == 0) {
                        $getDupsInShared = $projectdb->query("SELECT id, description FROM $table_name_id WHERE id IN (".implode(",", $duplicate_shared_member_lid).") AND merge_as_primary = '0';");
                        if ($getDupsInShared->num_rows > 0) {
                            while ($dataDIS = $getDupsInShared->fetch_assoc()) {
                                if ($is_first_shared == true) {
                                    $is_first_shared = false;
                                    $primary_member_lid_shared = $dataDIS['id'];
                                    $all_description[] = $dataDIS['description'];
                                    $mylids[] = $primary_member_lid_shared.";".$table_name.";".$groupname.";".$vsys;
                                }
                                else {
                                    $member_lid = $dataDIS['id'];
                                    $all_description[] = $dataDIS['description'];

                                    updateMemberLid($projectName, $primary_member_lid_shared, $member_lid, $table_name_id);

                                    $remove_shared_objects[] = $member_lid;
                                }
                            }
                        }
                        if (count($remove_shared_objects) > 0) {
                            $projectdb->query("DELETE FROM $table_name_id WHERE id IN (" . implode(",", $remove_shared_objects) . ");");
                        }
                        $shared_member_lid = $primary_member_lid_shared;
                        //finish merge in shared 2 or more address shared
                    }
                }
                //}

                $primary_member_lid = $shared_member_lid;

                $getDups = $projectdb->query("SELECT id, description FROM $table_name_id $conditions AND source = '$source' AND BINARY name = '$groupname' AND vsys != '$vsys' AND dummy = 0;");
                if ($getDups->num_rows > 0) {
                    while ($dataDups = $getDups->fetch_assoc()) {
                        $member_lid = $dataDups['id'];
                        $all_description[] = $dataDups['description'];

                        #UPDATE where other address are used
                        $mylids[] = $primary_member_lid.";".$table_name.";".$groupname.";".$vsys;

                        updateMemberLid($projectName, $primary_member_lid, $member_lid, $table_name_id);

                        $remove_objects[] = $member_lid;
                    }
                }
                cleanDuplicatedMembersMerging($primary_member_lid, $table_name_id);

                $all_description = array_unique($all_description);
                $finally_description = implode(", ", $all_description);
                $finally_description = truncate_descriptions($finally_description, $version);

                $projectdb->query("UPDATE $table_name_id SET used='$used_merge', merge_as_primary = '0', description = '$finally_description' WHERE id = '$primary_member_lid';");

                $all_names_for_replace[] = $groupname;

                if (count($remove_objects) > 0) {
                    $projectdb->query("DELETE FROM $table_name_id WHERE id IN (" . implode(",", $remove_objects) . ");");
                }

                //if($table_name_id == "address_groups_id"){
                //    replaceAddressGroupsInOtherRulesZones($projectName, $primary_member_lid, $all_names_for_replace, $source);
                //}elseif($table_name_id == "services_groups_id"){
                //    replaceServicesGroupsInOtherRules($projectName, $primary_member_lid, $all_names_for_replace, $source);
                //}

            }// fin while duplicated names
        }
    }
    else {
        //Objects are the same vsys or they are descendents (parent->child)
        $getDuplicated = $projectdb->query("SELECT id, name, name_ext, vsys, source, tag, type, description, used, filter, devicegroup  "
            . "FROM $table_name_id $conditions GROUP BY BINARY name;");

        if ($getDuplicated->num_rows > 0) {
            $mylids = array();
            while ($dataD = $getDuplicated->fetch_assoc()) {
                $is_first = true;
                $error = 0;
                $remove_objects = array();
                $all_description = array();

                $id = $dataD['id'];
                $groupname = $dataD['name'];
                $source = $dataD['source'];

                add_log2('ok', 'Merging Duplicated '.$type_log.' Groups', 'Duplicated '.$type_log.' Groups [' . $groupname . '] merging', $source, 'No Action required', 'objects', $id, $table_name_id);

                // Check if exist selected merge as primary
                $getPrimary = $projectdb->query("SELECT id, description FROM $table_name_id $conditions AND BINARY name = '$groupname' AND merge_as_primary = '1' ;");
                if ($getPrimary->num_rows == 1) {
                    $dataP = $getPrimary->fetch_assoc();
                    $primary_member_lid = $dataP['id'];
                    $all_description[] = $dataP['description'];
                    $mylids[] = $primary_member_lid.";".$table_name.";".$groupname.";".$vsys;

                    $is_first = false;
                }
                elseif($getPrimary->num_rows > 1){
                    $error = 1;
                    // Error, hay más de un selected as primary para un conjunto de duplicated name, add log
                    add_log2('warning', 'Merging Duplicated '.$type_log.' Groups', 'Error when Duplicated '.$type_log.' Groups [' . $groupname . '] merging: two or more selected as primary.', $source, 'No Action required', 'objects', $id, $table_name_id);
                }

                if($error == 0){
                    $getDupsByName = $projectdb->query("SELECT id, description FROM $table_name_id $conditions AND BINARY name = '$groupname' AND merge_as_primary = '0';");

                    if ($getDupsByName->num_rows > 0) {
                        while ($dataDBN = $getDupsByName->fetch_assoc()) {
                            if ($is_first == true) {
                                $is_first = false;
                                $primary_member_lid = $dataDBN['id'];
                                $all_description[] = $dataDBN['description'];
                                $mylids[] = $primary_member_lid.";".$table_name.";".$groupname.";".$vsys;
                            }
                            else {
                                #UPDATE where other address are used
                                $member_lid = $dataDBN['id'];
                                $all_description[] = $dataDBN['description'];

                                updateMemberLid($projectName, $primary_member_lid, $member_lid, $table_name_id);

                                $remove_objects[] = $member_lid;
                            }
                        }
                        cleanDuplicatedMembersMerging($primary_member_lid, $table_name_id);

                        $all_description = array_unique($all_description);
                        $finally_description = implode(", ", $all_description);
                        $finally_description = truncate_descriptions($finally_description, $version);

                        $projectdb->query("UPDATE $table_name_id set used='$used_merge', merge_as_primary = '0', description = '$finally_description' WHERE id = '$primary_member_lid';");

                        $all_names_for_replace[] = $groupname;
                    }
                    if (count($remove_objects) > 0) {
                        $projectdb->query("DELETE FROM $table_name_id WHERE id IN (" . implode(",", $remove_objects) . ");");
                    }

                    /*if($table_name_id == "address_groups_id"){
                        replaceAddressGroupsInOtherRulesZones($projectName, $primary_member_lid, $all_names_for_replace, $source);
                    }elseif($table_name_id == "services_groups_id"){
                        replaceServicesGroupsInOtherRules($projectName, $primary_member_lid, $all_names_for_replace, $source);
                    }*/
                }
            }
        }
    }
    setMergeGroupsCommon($projectName, $mylids, $source, $table, $table_name_id);
}


function setMergeByValueGroups(STRING $projectName, $selection, $vsys, $source, $type_log, $table_name, $table_name_id, $table){

    global $projectdb;
    global $app;

    $projectdb = selectDatabase($projectName);

    $user = $app->container->sentinel->getUser();
    $user_id = $user->id;

    take_snapshot_last($projectName);

    $query = generate_query("objects");

    $version = calcVersion($source);

    $mylids = array();

    if(count($selection) > 0) {
        $query = " WHERE lid IN (".implode(",",$selection).") ";
    }
    else{
        $getResultsTools = $projectdb->query("SELECT member_lid FROM tools_results WHERE table_name = '$table_name_id' AND source = '$source' AND user_id = '$user_id';");

        if ($getResultsTools->num_rows > 0) {

            while ($dataRT = $getResultsTools->fetch_assoc()){
                if($dataRT['member_lid'] != ""){
                    $member_lid[] = $dataRT['member_lid'];
                }else{
                    $member_lid = array();
                }
            }
            if(count($member_lid) > 0){
                $query = " WHERE lid IN (" . implode(",", $member_lid) . ") ";
            }
            else{
                $query = " WHERE lid IN ('') ";
            }
        }
        else{
            $query = " WHERE id IN ('') ";
        }
    }

    // User has selected all as default vysys
    // that means that we could have objects coming from different vsys
    // we need to check if All (meaning shared) is the common vsys to store the merged object
    // to avoid sending the merged objet to the shared vsys if it's not needed
    $selected_vsys = $vsys;
    if ($selected_vsys == "all") {

        $getDuplicatedMembers = $projectdb->query("SELECT lid, table_name, name, members, count(id) as t 
            FROM tmp_dup_name_val $query GROUP BY members HAVING t>1;");

        if ($getDuplicatedMembers->num_rows > 0) {

            while ($dataDM = $getDuplicatedMembers->fetch_assoc()) {

                $members = $dataDM['members'];
                $lids_members_duplicated = array();

                $getLids = $projectdb->query("SELECT lid FROM tmp_dup_name_val $query AND members = '$members';");

                if ($getLids->num_rows > 0) {
                    while ($dataL = $getLids->fetch_assoc()) {
                        if($dataL['lid'] != ""){
                            $lids_members_duplicated[] = $dataL['lid'];
                        }
                    }
                }

                $common_vsys = getFirstCommonVsys($table_name_id, $lids_members_duplicated);
                if(!is_null($common_vsys)) {
                    $vsys = $common_vsys;
                } elseif($vsys=="all"){
                    $vsys = "shared";
                }

                if($vsys=="shared" && count($lids_members_duplicated)>0){
                    checkExistShared($source);
                }

                // Get "used" flag instead of recalculate used object for the whole project
                $query_get_used = "SELECT id from " . $table_name_id . " where used = '1' and id IN (" . implode(",", $lids_members_duplicated) . ")";
                $get_used = $projectdb->query($query_get_used);
                $used_merge = '0';
                if($get_used->num_rows > 0){
                    $used_merge = '1';
                }

                $getDuplicated = $projectdb->query("SELECT id, name, name_ext, vsys, source, tag, type, description, used, filter, devicegroup  "
                    . "FROM $table_name_id WHERE id IN (" . implode(",", $lids_members_duplicated) . ");");

                if ($getDuplicated->num_rows > 0) {

                    $remove_objects = array();
                    $remove_shared_objects = array();
                    $is_first = true;
                    $is_first_shared = true;
                    $duplicate_shared_member_lid = array();
                    $all_description = array();

                    while ($dataD = $getDuplicated->fetch_assoc()) {

                        $groupnameoriginal = $dataD['name_ext'];
                        $groupname = $dataD['name'];
                        $id = $dataD['id'];
                        $source = $dataD['source'];
                        $usedgroup = $dataD['used'];
                        $typegroup = $dataD['type'];
                        $description = addslashes($dataD['description']);
                        $tag = $dataD['tag'];
                        $filter = addslashes($dataD['filter']);
                        $devicegroup = $dataD['devicegroup'];

                        #Check if exits in shared
                        if ($is_first == true) {
                            $is_first = false;
                            $getShared = $projectdb->query("SELECT lid AS id FROM tmp_dup_name_val WHERE vsys = '$vsys' AND members = '$members';");
                            if ($getShared->num_rows == 0) {
                                $data["id"] = "";
                                $projectdb->query("INSERT INTO $table_name_id (name_ext, name, used, devicegroup, vsys, type, filter, description, source, tag)  
                                    VALUES ('$groupnameoriginal', '$groupname', '$usedgroup', '$devicegroup', '$vsys', '$typegroup', '$filter', '$description', '$source', '$tag');");
                                $shared_member_lid = $projectdb->insert_id;
                                $all_description[] = $description;
                                add_log2('ok', 'Merging Duplicated '.$type_log.' Group', 'Duplicated '.$type_log.' Group [' . $groupname . '] merging and moving into '. $vsys, $source, 'No Action required', 'objects', $shared_member_lid, $table_name_id);
                            }
                            elseif ($getShared->num_rows == 1) {
                                $data = $getShared->fetch_assoc();
                                $shared_member_lid = $data['id'];
                                $all_description[] = $description;
                                $mylids[] = $shared_member_lid . ";".$table_name.";" . $groupname . ";" . $vsys;
                                add_log2('ok', 'Merging Duplicated '.$type_log.' Group', 'Duplicated '.$type_log.' Group [' . $groupname . '] merging and moving into '. $vsys, $source, 'No Action required', 'objects', $shared_member_lid, $table_name_id);
                            }
                            else {
                                # First merge in the shared space get the id from the first delete the others

                                $error = 0;
                                # First merge in the shared space get the id from the first delete the others
                                add_log2('warning', 'Merging Duplicated '.$type_log.' Group', 'The are duplicate objects in the '. $vsys . ':' . $groupname . '', $source, 'Merge automatically in the '. $vsys, 'objects', $id, $table_name_id);

                                while ($data = $getShared->fetch_assoc()) {
                                    $duplicate_shared_member_lid[] = $data['id'];
                                }

                                // Check if exist selected merge as primary
                                $getPrimaryShared = $projectdb->query("SELECT id, description FROM $table_name_id WHERE id IN (" . implode(",", $duplicate_shared_member_lid) . ") AND merge_as_primary = '1' ;");
                                if ($getPrimaryShared->num_rows == 1) {
                                    $dataPS = $getPrimaryShared->fetch_assoc();
                                    $primary_member_lid_shared = $dataPS['id'];
                                    $all_description[] = $dataPS['description'];
                                    $mylids[] = $primary_member_lid_shared . ";".$table_name.";" . $groupname . ";" . $vsys;
                                    $is_first_shared = false;
                                }
                                elseif ($getPrimaryShared->num_rows > 1) {
                                    $error = 1;
                                    // Error, hay más de un selected as primary para un conjunto de duplicated name, add log
                                    add_log2('warning', 'Merging Duplicated '.$type_log.' Group', 'Error when Duplicated '.$type_log.' Group [' . $groupname . '] merging: two or more selected as primary.', $source, 'No Action required', 'objects', $id, $table_name_id);
                                }

                                if ($error == 0) {
                                    $getDupsInShared = $projectdb->query("SELECT id, description FROM $table_name_id WHERE id IN (" . implode(",", $duplicate_shared_member_lid) . ") AND merge_as_primary = '0';");
                                    if ($getDupsInShared->num_rows > 0) {
                                        while ($dataDIS = $getDupsInShared->fetch_assoc()) {
                                            if ($is_first_shared == true) {
                                                $is_first_shared = false;
                                                $primary_member_lid_shared = $dataDIS['id'];
                                                $all_description[] = $dataDIS['description'];
                                                $mylids[] = $primary_member_lid_shared . ";".$table_name.";" . $groupname . ";" . $vsys;
                                            }
                                            else {
                                                #UPDATE where other address are used
                                                $member_lid = $dataDIS['id'];
                                                $all_description[] = $dataDIS['description'];

                                                updateMemberLid($projectName, $primary_member_lid_shared, $member_lid, $table_name_id);

                                                $remove_shared_objects[] = $member_lid;
                                            }
                                        }
                                    }
                                    if (count($remove_shared_objects) > 0) {
                                        $projectdb->query("DELETE FROM $table_name_id WHERE id IN (" . implode(",", $remove_shared_objects) . ");");
                                    }
                                    $shared_member_lid = $primary_member_lid_shared;
                                    //finish merge in shared 2 or more address shared
                                }
                            }
                        }

                        $primary_member_lid = $shared_member_lid;

                        $getDups = $projectdb->query("SELECT id, description FROM $table_name_id WHERE id IN (" . implode(",", $lids_members_duplicated) . ") AND source = '$source' AND vsys != '$vsys' AND dummy = 0;");
                        if ($getDups->num_rows > 0) {
                            while ($dataDups = $getDups->fetch_assoc()) {
                                $member_lid = $dataDups['id'];
                                $all_description[] = $dataDups['description'];

                                #UPDATE where other address are used
                                $mylids[] = $primary_member_lid.";".$table_name.";".$groupname.";".$vsys;

                                updateMemberLid($projectName, $primary_member_lid, $member_lid, $table_name_id);

                                $remove_objects[] = $member_lid;
                            }
                        }
                        cleanDuplicatedMembersMerging($primary_member_lid, $table_name_id);

                        $all_description = array_unique($all_description);
                        $finally_description = implode(", ", $all_description);
                        $finally_description = truncate_descriptions($finally_description, $version);

                        $projectdb->query("UPDATE $table_name_id SET used='$used_merge', merge_as_primary = '0', description = '$finally_description' WHERE id = '$primary_member_lid';");

                        $all_names_for_replace[] = $groupname;

                        if (count($remove_objects) > 0) {
                            $projectdb->query("DELETE FROM $table_name_id WHERE id IN (" . implode(",", $remove_objects) . ");");
                        }
                        /*if($table_name_id == "address_groups_id"){
                            replaceAddressGroupsInOtherRulesZones($projectName, $primary_member_lid, $all_names_for_replace, $source);
                        }elseif($table_name_id == "services_groups_id"){
                            replaceServicesGroupsInOtherRules($projectName, $primary_member_lid, $all_names_for_replace, $source);
                        }*/
                    }// fin while duplicated names
                }
            }
        }
    }
    else {
        //the same vsys or they are descendents (parent->child)

        $getDuplicatedMembers = $projectdb->query("SELECT lid, table_name, name, members, count(id) as t 
          FROM tmp_dup_name_val $query GROUP BY members HAVING t>1;");

        if ($getDuplicatedMembers->num_rows > 0) {

            while ($dataDM = $getDuplicatedMembers->fetch_assoc()) {

                $members = $dataDM['members'];
                $lids_members_duplicated = array();

                $getLids = $projectdb->query("SELECT lid FROM tmp_dup_name_val $query AND members = '$members';");

                if ($getLids->num_rows > 0) {
                    while ($dataL = $getLids->fetch_assoc()) {
                        if ($dataL['lid'] != "") {
                            $lids_members_duplicated[] = $dataL['lid'];
                        }
                    }
                }

                // Get "used" flag instead of recalculate used object for the whole project
                $query_get_used = "SELECT id from " . $table_name_id . " where used = '1' and id IN (" . implode(",", $lids_members_duplicated) . ")";
                $get_used = $projectdb->query($query_get_used);
                $used_merge = '0';
                if($get_used->num_rows > 0){
                    $used_merge = '1';
                }

                $getDuplicated = $projectdb->query("SELECT id, name, name_ext, vsys, source, tag, type, description, used, filter, devicegroup  "
                    . "FROM $table_name_id WHERE id IN (" . implode(",", $lids_members_duplicated) . ");");

                if ($getDuplicated->num_rows > 0) {

                    while ($dataD = $getDuplicated->fetch_assoc()) {

                        $is_first = true;
                        $error = 0;
                        $remove_objects = array();
                        $all_description = array();

                        $id = $dataD['id'];
                        $groupname = $dataD['name'];
                        $source = $dataD['source'];

                        add_log2('ok', 'Merging Duplicated '.$type_log.' Groups', 'Duplicated '.$type_log.' Groups [' . $groupname . '] merging', $source, 'No Action required', 'objects', $id, $table_name_id);

                        // Check if exist selected merge as primary
                        $getPrimary = $projectdb->query("SELECT id, description FROM $table_name_id WHERE id IN (" . implode(",", $lids_members_duplicated) . ") AND merge_as_primary = '1' ;");
                        if ($getPrimary->num_rows == 1) {
                            $dataP = $getPrimary->fetch_assoc();
                            $primary_member_lid = $dataP['id'];
                            $all_description[] = $dataP['description'];
                            $mylids[] = $primary_member_lid.";".$table_name.";".$groupname.";".$vsys;

                            $is_first = false;
                        }
                        elseif($getPrimary->num_rows > 1){
                            $error = 1;
                            // Error, hay más de un selected as primary para un conjunto de duplicated name, add log
                            add_log2('warning', 'Merging Duplicated '.$type_log.' Groups', 'Error when Duplicated '.$type_log.' Groups [' . $groupname . '] merging: two or more selected as primary.', $source, 'No Action required', 'objects', $id, $table_name_id);
                        }

                        if($error == 0){
                            $getDupsByName = $projectdb->query("SELECT id, description FROM $table_name_id WHERE id IN (" . implode(",", $lids_members_duplicated) . ") AND merge_as_primary = '0';");

                            if ($getDupsByName->num_rows > 0) {
                                while ($dataDBN = $getDupsByName->fetch_assoc()) {
                                    if ($is_first == true) {
                                        $is_first = false;
                                        $primary_member_lid = $dataDBN['id'];
                                        $all_description[] = $dataDBN['description'];
                                        $mylids[] = $primary_member_lid.";".$table_name.";".$groupname.";".$vsys;
                                    }
                                    else {
                                        $member_lid = $dataDBN['id'];
                                        $all_description[] = $dataDBN['description'];

                                        updateMemberLid($projectName, $primary_member_lid, $member_lid, $table_name_id);

                                        $remove_objects[] = $member_lid;
                                    }
                                }
                                cleanDuplicatedMembersMerging($primary_member_lid, $table_name_id);

                                $all_description = array_unique($all_description);
                                $finally_description = implode(", ", $all_description);
                                $finally_description = truncate_descriptions($finally_description, $version);

                                $projectdb->query("UPDATE $table_name_id set used='$used_merge', merge_as_primary = '0', description = '$finally_description' WHERE id = '$primary_member_lid';");

                                $all_names_for_replace[] = $groupname;
                            }
                            if (count($remove_objects) > 0) {
                                $projectdb->query("DELETE FROM $table_name_id WHERE id IN (" . implode(",", $remove_objects) . ");");
                            }

                            /*if($table_name_id == "address_groups_id"){
                                replaceAddressGroupsInOtherRulesZones($projectName, $primary_member_lid, $all_names_for_replace, $source);
                            }elseif($table_name_id == "services_groups_id"){
                                replaceServicesGroupsInOtherRules($projectName, $primary_member_lid, $all_names_for_replace, $source);
                            }*/
                        }
                    }
                }
            }
        }
    }
    setMergeGroupsCommon($projectName, $mylids, $source, $table, $table_name_id);
}


function setMergeBySelectionGroups(STRING $projectName, $selection, $vsys, $source, $type_log, $table_name, $table_name_id, $table){

    global $projectdb;
    $projectdb = selectDatabase($projectName);

    take_snapshot_last($projectName);

    $mylids = array();

    if(count($selection) > 0) {
        $query = " WHERE id IN (".implode(",",$selection).") ";
    }

    if ($vsys == "all") {
    }
    else {
        //the same vsys
        $getDuplicated = $projectdb->query("SELECT id, name, name_ext, vsys, source, tag, type, description, used, filter, devicegroup  "
            . "FROM $table_name_id $query;");

        // Get "used" flag instead of recalculate used object for the whole project
        $query_get_used = "SELECT id from " . $table_name_id . " where used = '1' and id IN (" . implode(",", $selection) . ")";
        $get_used = $projectdb->query($query_get_used);
        $used_merge = '0';
        if($get_used->num_rows > 0){
            $used_merge = '1';
        }

        if ($getDuplicated->num_rows > 0) {
            $mylids = array();
            while ($dataD = $getDuplicated->fetch_assoc()) {
                $is_first = true;
                $error = 0;
                $remove_objects = array();
                $id = $dataD['id'];
                $groupname = $dataD['name'];
                $source = $dataD['source'];

                add_log2('ok', 'Merging Selected '.$type_log.' Groups', 'Selected '.$type_log.' Groups [' . $groupname . '] merging', $source, 'No Action required', 'objects', $id, $table_name_id);

                // Check if exist selected merge as primary
                $getPrimary = $projectdb->query("SELECT id FROM $table_name_id $query AND merge_as_primary = '1' ;");
                if ($getPrimary->num_rows == 1) {
                    $dataP = $getPrimary->fetch_assoc();
                    $primary_member_lid = $dataP['id'];
                    $mylids[] = $primary_member_lid.";".$table_name.";".$groupname.";".$vsys;

                    $is_first = false;
                }
                elseif($getPrimary->num_rows > 1){
                    $error = 1;
                    // Error, hay más de un selected as primary para un conjunto de duplicated name, add log
                    add_log2('warning', 'Merging Selected '.$type_log.' Groups', 'Error when Selected '.$type_log.' Groups [' . $groupname . '] merging: two or more selected as primary.', $source, 'No Action required', 'objects', $id, $table_name_id);
                }

                if($error == 0){
                    $getDupsByName = $projectdb->query("SELECT id FROM $table_name_id $query AND merge_as_primary = '0';");

                    if ($getDupsByName->num_rows > 0) {
                        while ($dataDBN = $getDupsByName->fetch_assoc()) {
                            if ($is_first == true) {
                                $is_first = false;
                                $primary_member_lid = $dataDBN['id'];
                                $mylids[] = $primary_member_lid.";".$table_name.";".$groupname.";".$vsys;
                            }
                            else {
                                #UPDATE where other address are used
                                $member_lid = $dataDBN['id'];

                                updateMemberLid($projectName, $primary_member_lid, $member_lid, $table_name_id);

                                $remove_objects[] = $member_lid;
                            }
                        }
                        cleanDuplicatedMembersMerging($primary_member_lid, $table_name_id);

                        //Limpiar si se ha añadido el mismo grupo a si mismo
                        $projectdb->query("DELETE FROM $table_name WHERE member_lid = '$primary_member_lid' AND table_name = '$table_name_id';");
                        //echo "DELETE FROM $table_name WHERE member_lid = '$primary_member_lid' AND table_name = '$table_name_id';";

                        $projectdb->query("UPDATE $table_name_id set used='$used_merge', merge_as_primary = '0' WHERE id = '$primary_member_lid';");

                        $all_names_for_replace[] = $groupname;
                    }
                    if (count($remove_objects) > 0) {
                        $projectdb->query("DELETE FROM $table_name_id WHERE id IN (" . implode(",", $remove_objects) . ");");
                    }
                    /*if($table_name_id == "address_groups_id"){
                        replaceAddressGroupsInOtherRulesZones($projectName, $primary_member_lid, $all_names_for_replace, $source);
                    }elseif($table_name_id == "services_groups_id"){
                        replaceServicesGroupsInOtherRules($projectName, $primary_member_lid, $all_names_for_replace, $source);
                    }*/
                }
            }
        }
    }
    setMergeGroupsCommon($projectName, $mylids, $source, $table, $table_name_id);
}


function setMergeByNameServices(STRING $projectName, $selection, $vsys, $source){

    global $projectdb;
    global $app;

    $projectdb = selectDatabase($projectName);

    $user = $app->container->sentinel->getUser();
    $user_id = $user->id;

    $shared_member_lid = "";

    take_snapshot_last($projectName);

    $query = generate_query("objects");

    $version = calcVersion($source);

    if(count($selection) > 0) {
        $query = " WHERE id IN ($selection) ";
    }
    else{
        $getResultsTools = $projectdb->query("SELECT member_lid FROM tools_results WHERE table_name = 'services' AND source = '$source' AND user_id = '$user_id';");

        if ($getResultsTools->num_rows > 0) {

            while ($dataRT = $getResultsTools->fetch_assoc()){
                if($dataRT['member_lid'] != ""){
                    $member_lid[] = $dataRT['member_lid'];
                }else{
                    $member_lid = array();
                }
            }
            if(count($member_lid) > 0){
                $query = " WHERE id IN (" . implode(",", $member_lid) . ") ";
            }
            else{
                $query = " WHERE id IN ('') ";
            }
        }
        else{
            $query = " WHERE id IN ('') ";
        }
    }

    if ($vsys == "all") {
        #Merge and move to Shared
        $getDuplicated = $projectdb->query("SELECT id, name_ext, name, used, vsys, devicegroup, description, sport, dport, protocol, icmp, source, tag, dummy "
            . "FROM services $query GROUP BY BINARY name ;");

        if ($getDuplicated->num_rows > 0) {

            $remove_objects = array();
            $remove_shared_objects = array();

            while ($data = $getDuplicated->fetch_assoc()) {

                $is_first_shared = true;
                $all_description = array();

                $id = $data['id'];
                $name = $data['name'];
                $name_ext = $data['name_ext'];
                $used = $data['used'];
                $devicegroup = $data['devicegroup'];
                $protocol = $data['protocol'];
                $sport = $data['sport'];
                $dport = $data['dport'];
                $description = addslashes($data['description']);
                $icmp = $data['icmp'];
                $tag = $data['tag'];

                $duplicate_shared_member_lid = array();

                #Check if exits in shared
                $getShared = $projectdb->query("SELECT id, description FROM services WHERE source = '$source' AND BINARY name = '$name' AND vsys = 'shared' AND dummy = 0;");
                if ($getShared->num_rows == 0) {
                    $data["id"] = "";
                    $projectdb->query("INSERT INTO services (name_ext, name, used, devicegroup, vsys, protocol, sport, dport, description, icmp, source, tag)  
                                      VALUES ('$name_ext', '$name', '$used', '$devicegroup', 'shared', '$protocol', '$sport', '$dport', '$description', '$icmp', '$source', '$tag');");

                    $shared_member_lid = $projectdb->insert_id;
                    $all_description[] = $description;
                    add_log2('ok', 'Merging Duplicated Services', 'Duplicated Service [' . $name . '] merging and moving into Shared', $source, 'No Action required', 'objects', $shared_member_lid, 'services');
                }
                elseif ($getShared->num_rows == 1) {
                    $data = $getShared->fetch_assoc();
                    $shared_member_lid = $data['id'];
                    $all_description[] = $data['description'];
                    add_log2('ok', 'Merging Duplicated Services', 'Duplicated Service [' . $name . '] merging and moving into Shared', $source, 'No Action required', 'objects', $shared_member_lid, 'services');
                }
                else {
                    $error = 0;
                    # First merge in the shared space get the id from the first delete the others
                    add_log2('warning', 'Merging Duplicated Services', 'The are duplicate objects in the shared: ' . $name . '', $source, 'Merge automatically in the shared.', 'objects', $id, 'services');

                    while ($data = $getShared->fetch_assoc()) {
                        $duplicate_shared_member_lid[] = $data['id'];
                    }

                    // Check if exist selected merge as primary
                    $getPrimaryShared = $projectdb->query("SELECT id, description FROM services WHERE id IN (".implode(",", $duplicate_shared_member_lid).") AND merge_as_primary = '1' ;");
                    if ($getPrimaryShared->num_rows == 1) {
                        $dataPS = $getPrimaryShared->fetch_assoc();
                        $primary_member_lid_shared = $dataPS['id'];
                        $all_description[] = $dataPS['description'];
                        $is_first_shared = false;
                    }
                    elseif($getPrimaryShared->num_rows > 1){
                        $error = 1;
                        // Error, hay más de un selected as primary para un conjunto de duplicated name, add log
                        add_log2('warning', 'Merging Duplicated Services', 'Error when Duplicated Services [' . $name . '] merging: two or more selected as primary.', $source, 'No Action required', 'objects', $id, 'services');
                    }

                    if($error == 0) {
                        $getDupsInShared = $projectdb->query("SELECT id, description FROM services WHERE id IN (".implode(",", $duplicate_shared_member_lid).") AND merge_as_primary = '0';");
                        if ($getDupsInShared->num_rows > 0) {
                            while ($dataDIS = $getDupsInShared->fetch_assoc()) {
                                if ($is_first_shared == true) {
                                    $is_first_shared = false;
                                    $primary_member_lid_shared = $dataDIS['id'];
                                    $all_description[] = $dataDIS['description'];
                                }
                                else {
                                    #UPDATE where other services are used
                                    $member_lid = $dataDIS['id'];
                                    $all_description[] = $dataDIS['description'];

                                    updateMemberLid($projectName, $primary_member_lid_shared, $member_lid, "services");

                                    $remove_shared_objects[] = $member_lid;
                                }
                            }
                        }
                        if (count($remove_shared_objects) > 0) {
                            $projectdb->query("DELETE FROM services WHERE id IN (" . implode(",", $remove_shared_objects) . ");");
                        }
                        $shared_member_lid = $primary_member_lid_shared;
                        //finish merge in shared 2 or more services shared
                    }
                }

                $getDups = $projectdb->query("SELECT id, description FROM services $query AND source = '$source' AND BINARY name = '$name' AND vsys != 'shared' AND dummy = 0;");
                if ($getDups->num_rows > 0) {
                    while ($dataDups = $getDups->fetch_assoc()) {
                        $member_lid = $dataDups['id'];
                        $all_description[] = $dataDups['description'];
                        #UPDATE where other address are used
                        $primary_member_lid = $shared_member_lid;

                        updateMemberLid($projectName, $primary_member_lid, $member_lid, "services");

                        $remove_objects[] = $member_lid;
                    }
                }
                cleanDuplicatedMembersMerging($primary_member_lid, "services");

                $all_description = array_unique($all_description);
                $finally_description = implode(", ", $all_description);
                $finally_description = truncate_descriptions($finally_description, $version);

                $projectdb->query("UPDATE services SET merge_as_primary = '0', description = '$finally_description' WHERE id = '$primary_member_lid';");
            }
            if (count($remove_objects) > 0) {
                $projectdb->query("DELETE FROM services WHERE id IN (" . implode(",", $remove_objects) . ");");
            }

        }
    }
    else {
        #Merge in the same VSYS
        $getDuplicated = $projectdb->query("SELECT id, name FROM services $query GROUP BY BINARY name ;");

        if ($getDuplicated->num_rows > 0) {
            while ($dataD = $getDuplicated->fetch_assoc()) {
                $is_first = true;
                $error = 0;
                $remove_objects = array();
                $all_description = array();

                $name = $dataD['name'];
                $id = $dataD['id'];

                add_log2('ok', 'Merging Duplicated Services', 'Duplicated Services [' . $name . '] merging', $source, 'No Action required', 'objects', $id, 'services');

                // Check if exist selected merge as primary
                $getPrimary = $projectdb->query("SELECT id, description FROM services $query AND BINARY name = '$name' AND merge_as_primary = '1' ;");
                if ($getPrimary->num_rows == 1) {
                    $dataP = $getPrimary->fetch_assoc();
                    $primary_member_lid = $dataP['id'];
                    $all_description[] = $dataP['description'];
                    $is_first = false;
                }
                elseif($getPrimary->num_rows > 1){
                    $error = 1;
                    // Error, hay más de un selected as primary para un conjunto de duplicated name, add log
                    add_log2('warning', 'Merging Duplicated Services', 'Error when Duplicated Services [' . $name . '] merging: two or more selected as primary.', $source, 'No Action required', 'objects', $id, 'services');
                }

                if($error == 0){
                    $getDupsByName = $projectdb->query("SELECT id, description FROM services $query AND BINARY name = '$name' AND merge_as_primary = '0';");

                    if ($getDupsByName->num_rows > 0) {
                        while ($dataDBN = $getDupsByName->fetch_assoc()) {
                            if ($is_first == true) {
                                $is_first = false;
                                $primary_member_lid = $dataDBN['id'];
                                $all_description[] = $dataDBN['description'];
                            }
                            else {
                                #UPDATE where other address are used
                                $member_lid = $dataDBN['id'];
                                $all_description[] = $dataDBN['description'];

                                updateMemberLid($projectName, $primary_member_lid, $member_lid, "services");

                                $remove_objects[] = $member_lid;
                            }
                        }
                        cleanDuplicatedMembersMerging($primary_member_lid, "services");

                        $all_description = array_unique($all_description);
                        $finally_description = implode(", ", $all_description);
                        $finally_description = truncate_descriptions($finally_description, $version);

                        $projectdb->query("UPDATE services set merge_as_primary = '0', description = '$finally_description' WHERE id = '$primary_member_lid';");
                    }
                    if (count($remove_objects) > 0) {
                        $projectdb->query("DELETE FROM services WHERE id IN (" . implode(",", $remove_objects) . ");");
                    }
                }
            }
        }
    }
    //clean_duplicated_members("services_groups");
    check_used_objects_new();
}


function setMergeByNameServices2(STRING $projectName, ARRAY $selection, $vsys, $source){

    global $app;
    global $projectdb;
    $projectdb = selectDatabase($projectName);

    $me = $app->sentinel->getUser();
    $servicesMerger = new ServicesMerger($projectName, $me['id'], $source);
    $servicesMerger->setMergerByFields(['name']);

    $servicesMerger->merge($selection);

}


function setMergeByNameValueServices2(STRING $projectName, ARRAY $selection, $vsys, $source){

    global $app;
    global $projectdb;
    $projectdb = selectDatabase($projectName);

    $version = calcVersion($source);

    if($version == ""){$version = "8.1";}

    $me = $app->sentinel->getUser();
    $servicesMerger = new ServicesMerger($projectName, $me['id'], $source);

    if($version >= 8.1){
        $servicesMerger->setMergerByFields(['name', 'protocol', 'dport', 'timeout', 'halfclose_timeout', 'timewait_timeout']);
    }else{
        $servicesMerger->setMergerByFields(['name', 'protocol', 'dport']);
    }

    $servicesMerger->merge($selection);

}


function setMergeByNameValueServices(STRING $projectName, $selection, $vsys, $source){

    global $projectdb;
    global $app;

    $projectdb = selectDatabase($projectName);

    $user = $app->container->sentinel->getUser();
    $user_id = $user->id;

    $shared_member_lid = "";

    take_snapshot_last($projectName);

    $query = generate_query("objects");

    $version = calcVersion($source);

    if(count($selection) > 0) {
        $query = " WHERE id IN ($selection) ";
    }
    else{
        $getResultsTools = $projectdb->query("SELECT member_lid FROM tools_results WHERE table_name = 'services' AND source = '$source' AND user_id = '$user_id';");

        if ($getResultsTools->num_rows > 0) {

            while ($dataRT = $getResultsTools->fetch_assoc()){
                if($dataRT['member_lid'] != ""){
                    $member_lid[] = $dataRT['member_lid'];
                }else{
                    $member_lid = array();
                }
            }
            if(count($member_lid) > 0){
                $query = " WHERE id IN (" . implode(",", $member_lid) . ") ";
            }
            else{
                $query = " WHERE id IN ('') ";
            }
        }
        else{
            $query = " WHERE id IN ('') ";
        }
    }

    if ($vsys == "all") {
        #Merge and move to Shared
        $getDuplicated = $projectdb->query("SELECT id, name_ext, name, used, vsys, devicegroup, description, sport, dport, protocol, icmp, source, tag, dummy, override, timeout, halfclose_timeout, timewait_timeout "
            . "FROM services $query GROUP BY BINARY name, protocol, dport, override, timeout, halfclose_timeout, timewait_timeout ;");

        if ($getDuplicated->num_rows > 0) {

            $remove_objects = array();
            $remove_shared_objects = array();

            while ($data = $getDuplicated->fetch_assoc()) {

                $is_first_shared = true;
                $all_description = array();

                $id = $data['id'];
                $name = $data['name'];
                $name_ext = $data['name_ext'];
                $used = $data['used'];
                $devicegroup = $data['devicegroup'];
                $protocol = $data['protocol'];
                $sport = $data['sport'];
                $dport = $data['dport'];
                $description = addslashes($data['description']);
                $icmp = $data['icmp'];
                $tag = $data['tag'];

                $override = $data['override'];
                $timeout = $data['timeout'];
                $halfclose_timeout = $data['halfclose_timeout'];
                $timewait_timeout = $data['timewait_timeout'];

                $duplicate_shared_member_lid = array();

                #Check if exits in shared
                $getShared = $projectdb->query("SELECT id, description FROM services WHERE source = '$source' AND BINARY name = '$name' AND protocol = '$protocol' AND dport = '$dport' AND override = '$override' AND timeout = '$timeout' AND halfclose_timeout = '$halfclose_timeout' AND timewait_timeout = '$timewait_timeout' AND vsys = 'shared' AND dummy = 0;");
                if ($getShared->num_rows == 0) {
                    $data["id"] = "";
                    $projectdb->query("INSERT INTO services (name_ext, name, used, devicegroup, vsys, protocol, sport, dport, description, icmp, source, tag, override, timeout, halfclose_timeout, timewait_timeout)  
                                      VALUES ('$name_ext', '$name', '$used', '$devicegroup', 'shared', '$protocol', '$sport', '$dport', '$description', '$icmp', '$source', '$tag', '$override', '$timeout', '$halfclose_timeout', '$timewait_timeout');");
                    $shared_member_lid = $projectdb->insert_id;
                    $all_description[] = $description;
                    add_log2('ok', 'Merging Duplicated Services', 'Duplicated Services [' . $name . '] merging and moving into Shared', $source, 'No Action required', 'objects', $shared_member_lid, 'services');
                }
                elseif ($getShared->num_rows == 1) {
                    $data = $getShared->fetch_assoc();
                    $shared_member_lid = $data['id'];
                    $all_description[] = $data['description'];
                    add_log2('ok', 'Merging Duplicated Services', 'Duplicated Services [' . $name . '] merging and moving into Shared', $source, 'No Action required', 'objects', $shared_member_lid, 'services');
                }
                else {
                    $error = 0;
                    # First merge in the shared space get the id from the first delete the others
                    add_log2('warning', 'Merging Duplicated Services', 'The are duplicate objects in the shared: ' . $name . '', $source, 'Merge automatically in the shared.', 'objects', $id, 'services');

                    while ($data = $getShared->fetch_assoc()) {
                        $duplicate_shared_member_lid[] = $data['id'];
                    }

                    // Check if exist selected merge as primary
                    $getPrimaryShared = $projectdb->query("SELECT id, description FROM services WHERE id IN (".implode(",", $duplicate_shared_member_lid).") AND merge_as_primary = '1' ;");
                    if ($getPrimaryShared->num_rows == 1) {
                        $dataPS = $getPrimaryShared->fetch_assoc();
                        $primary_member_lid_shared = $dataPS['id'];
                        $all_description[] = $dataPS['description'];
                        $is_first_shared = false;
                    }
                    elseif($getPrimaryShared->num_rows > 1){
                        $error = 1;
                        // Error, hay más de un selected as primary para un conjunto de duplicated name, add log
                        add_log2('warning', 'Merging Duplicated Services', 'Error when Duplicated Services [' . $name . '] merging: two or more selected as primary.', $source, 'No Action required', 'objects', $id, 'services');
                    }

                    if($error == 0) {
                        $getDupsInShared = $projectdb->query("SELECT id, description FROM services WHERE id IN (".implode(",", $duplicate_shared_member_lid).") AND merge_as_primary = '0';");
                        if ($getDupsInShared->num_rows > 0) {
                            while ($dataDIS = $getDupsInShared->fetch_assoc()) {
                                if ($is_first_shared == true) {
                                    $is_first_shared = false;
                                    $primary_member_lid_shared = $dataDIS['id'];
                                    $all_description[] = $dataDIS['description'];
                                }
                                else {
                                    #UPDATE where other address are used
                                    $member_lid = $dataDIS['id'];
                                    $all_description[] = $dataDIS['description'];

                                    updateMemberLid($projectName, $primary_member_lid_shared, $member_lid, "services");

                                    $remove_shared_objects[] = $member_lid;
                                }
                            }
                        }
                        if (count($remove_shared_objects) > 0) {
                            $projectdb->query("DELETE FROM services WHERE id IN (" . implode(",", $remove_shared_objects) . ");");
                        }
                        $shared_member_lid = $primary_member_lid_shared;
                        //finish merge in shared 2 or more address shared
                    }
                }

                $getDups = $projectdb->query("SELECT id, description FROM services $query AND source = '$source' AND BINARY name = '$name' AND protocol = '$protocol' AND dport = '$dport' AND override = '$override' AND timeout = '$timeout' AND halfclose_timeout = '$halfclose_timeout' AND timewait_timeout = '$timewait_timeout' AND vsys != 'shared' AND dummy = 0;");
                if ($getDups->num_rows > 0) {
                    while ($dataDups = $getDups->fetch_assoc()) {
                        $member_lid = $dataDups['id'];
                        $all_description[] = $dataDups['description'];
                        $primary_member_lid = $shared_member_lid;

                        updateMemberLid($projectName, $primary_member_lid, $member_lid, "services");

                        $remove_objects[] = $member_lid;
                    }
                }
                cleanDuplicatedMembersMerging($primary_member_lid, "services");

                $all_description = array_unique($all_description);
                $finally_description = implode(", ", $all_description);
                $finally_description = truncate_descriptions($finally_description, $version);

                $projectdb->query("UPDATE services SET merge_as_primary = '0', description = '$finally_description' WHERE id = '$primary_member_lid';");

            }
            if (count($remove_objects) > 0) {
                $projectdb->query("DELETE FROM services WHERE id IN (" . implode(",", $remove_objects) . ");");
            }

        }
    }
    else {
        #Merge in the same VSYS
        $getDuplicated = $projectdb->query("SELECT id, name, dport, protocol, override, timeout, halfclose_timeout, timewait_timeout 
            FROM services $query 
            GROUP BY BINARY name, dport, protocol, override, timeout, halfclose_timeout, timewait_timeout  ;");

        if ($getDuplicated->num_rows > 0) {
            while ($dataD = $getDuplicated->fetch_assoc()) {
                $is_first = true;
                $error = 0;
                $remove_objects = array();
                $all_description = array();

                $name = $dataD['name'];
                $id = $dataD['id'];
                $dport = $dataD['dport'];
                $protocol = $dataD['protocol'];

                $override = $dataD['override'];
                $timeout = $dataD['timeout'];
                $halfclose_timeout = $dataD['halfclose_timeout'];
                $timewait_timeout = $dataD['timewait_timeout'];

                add_log2('ok', 'Merging Duplicated Services', 'Duplicated Services [' . $name . '] merging', $source, 'No Action required', 'objects', $id, 'services');

                // Check if exist selected merge as primary
                $getPrimary = $projectdb->query("SELECT id, description FROM services $query AND BINARY name = '$name' AND protocol = '$protocol' AND dport = '$dport' AND override = '$override' AND timeout = '$timeout' AND halfclose_timeout = '$halfclose_timeout' AND timewait_timeout = '$timewait_timeout' AND merge_as_primary = '1' ;");
                if ($getPrimary->num_rows == 1) {
                    $dataP = $getPrimary->fetch_assoc();
                    $primary_member_lid = $dataP['id'];
                    $all_description[] = $dataP['description'];
                    $is_first = false;
                }
                elseif($getPrimary->num_rows > 1){
                    $error = 1;
                    // Error, hay más de un selected as primary para un conjunto de duplicated name, add log
                    add_log2('warning', 'Merging Duplicated Services', 'Error when Duplicated Services [' . $name . '] merging: two or more selected as primary.', $source, 'No Action required', 'objects', $id, 'services');
                }

                if($error == 0){
                    $getDupsByName = $projectdb->query("SELECT id, description FROM services $query AND BINARY name = '$name' AND protocol = '$protocol' AND dport = '$dport' AND override = '$override' AND timeout = '$timeout' AND halfclose_timeout = '$halfclose_timeout' AND timewait_timeout = '$timewait_timeout' AND merge_as_primary = '0';");

                    if ($getDupsByName->num_rows > 0) {
                        while ($dataDBN = $getDupsByName->fetch_assoc()) {
                            if ($is_first == true) {
                                $is_first = false;
                                $primary_member_lid = $dataDBN['id'];
                                $all_description[] = $dataDBN['description'];
                            }
                            else {
                                $member_lid = $dataDBN['id'];
                                $all_description[] = $dataDBN['description'];

                                updateMemberLid($projectName, $primary_member_lid, $member_lid, "services");

                                $remove_objects[] = $member_lid;
                            }
                        }
                        cleanDuplicatedMembersMerging($primary_member_lid, "services");

                        $all_description = array_unique($all_description);
                        $finally_description = implode(", ", $all_description);
                        $finally_description = truncate_descriptions($finally_description, $version);

                        $projectdb->query("UPDATE services set merge_as_primary = '0', description = '$finally_description' WHERE id = '$primary_member_lid';");
                    }
                    if (count($remove_objects) > 0) {
                        $projectdb->query("DELETE FROM services WHERE id IN (" . implode(",", $remove_objects) . ");");
                    }
                }
            }
        }
    }
    check_used_objects_new();

}


function setMergeByValueServices2(STRING $projectName, ARRAY $selection, $vsys, $source){

    global $app;
    global $projectdb;
    $projectdb = selectDatabase($projectName);

    $version = calcVersion($source);

    if($version == ""){$version = "8.1";}

    $me = $app->sentinel->getUser();
    $servicesMerger = new ServicesMerger($projectName, $me['id'], $source);

    if($version >= 8.1){
        $servicesMerger->setMergerByFields(['protocol', 'dport', 'timeout', 'halfclose_timeout', 'timewait_timeout']);
    }else{
        $servicesMerger->setMergerByFields(['protocol', 'dport']);
    }

    $servicesMerger->merge($selection);

}


function setMergeByValueServices(STRING $projectName, $selection, $vsys, $source){

    global $projectdb;
    global $app;

    $projectdb = selectDatabase($projectName);

    $user = $app->container->sentinel->getUser();
    $user_id = $user->id;

    $shared_member_lid = "";

    take_snapshot_last($projectName);

    $query = generate_query("objects");

    $version = calcVersion($source);

    if(count($selection) > 0) {
        $query = " WHERE id IN ($selection) ";
    }
    else{
        $getResultsTools = $projectdb->query("SELECT member_lid FROM tools_results WHERE table_name = 'services' AND source = '$source' AND user_id = '$user_id';");

        if ($getResultsTools->num_rows > 0) {

            while ($dataRT = $getResultsTools->fetch_assoc()){
                if($dataRT['member_lid'] != ""){
                    $member_lid[] = $dataRT['member_lid'];
                }else{
                    $member_lid = array();
                }
            }
            if(count($member_lid) > 0){
                $query = " WHERE id IN (" . implode(",", $member_lid) . ") ";
            }
            else{
                $query = " WHERE id IN ('') ";
            }
        }
        else{
            $query = " WHERE id IN ('') ";
        }
    }

    if ($vsys == "all") {
        #Merge and move to Shared
        $getDuplicated = $projectdb->query("SELECT id, name_ext, name, used, vsys, devicegroup, description, sport, dport, protocol, icmp, source, tag, dummy, override, timeout, halfclose_timeout, timewait_timeout "
            . "FROM services $query GROUP BY protocol, dport, override, timeout, halfclose_timeout, timewait_timeout ;");

        if ($getDuplicated->num_rows > 0) {

            $remove_objects = array();
            $remove_shared_objects = array();

            while ($data = $getDuplicated->fetch_assoc()) {

                $is_first_shared = true;
                $all_description = array();

                $id = $data['id'];
                $name = $data['name'];
                $name_ext = $data['name_ext'];
                $used = $data['used'];
                $devicegroup = $data['devicegroup'];
                $protocol = $data['protocol'];
                $sport = $data['sport'];
                $dport = $data['dport'];
                $description = addslashes($data['description']);
                $icmp = $data['icmp'];
                $tag = $data['tag'];

                $override = $data['override'];
                $timeout = $data['timeout'];
                $halfclose_timeout = $data['halfclose_timeout'];
                $timewait_timeout = $data['timewait_timeout'];

                $duplicate_shared_member_lid = array();

                #Check if exits in shared
                $getShared = $projectdb->query("SELECT id, description FROM services WHERE source = '$source' AND protocol = '$protocol' AND dport = '$dport' AND override = '$override' AND timeout = '$timeout' AND halfclose_timeout = '$halfclose_timeout' AND timewait_timeout = '$timewait_timeout' AND vsys = 'shared' AND dummy = 0;");
                if ($getShared->num_rows == 0) {
                    $data["id"] = "";
                    $projectdb->query("INSERT INTO services (name_ext, name, used, devicegroup, vsys, protocol, sport, dport, description, icmp, source, tag, override, timeout, halfclose_timeout, timewait_timeout)  
                                      VALUES ('$name_ext', '$name', '$used', '$devicegroup', 'shared', '$protocol', '$sport', '$dport', '$description', '$icmp', '$source', '$tag', '$override', '$timeout', '$halfclose_timeout', '$timewait_timeout');");
                    $shared_member_lid = $projectdb->insert_id;
                    $all_description[] = $description;
                    add_log2('ok', 'Merging Duplicated Services', 'Duplicated Services [' . $name . '] merging and moving into Shared', $source, 'No Action required', 'objects', $shared_member_lid, 'services');
                }
                elseif ($getShared->num_rows == 1) {
                    $data = $getShared->fetch_assoc();
                    $shared_member_lid = $data['id'];
                    $all_description[] = $data['description'];
                    add_log2('ok', 'Merging Duplicated Services', 'Duplicated Services [' . $name . '] merging and moving into Shared', $source, 'No Action required', 'objects', $shared_member_lid, 'services');
                }
                else {
                    $error = 0;
                    # First merge in the shared space get the id from the first delete the others
                    add_log2('warning', 'Merging Duplicated Services', 'The are duplicate objects in the shared: ' . $name . '', $source, 'Merge automatically in the shared.', 'objects', $id, 'services');

                    while ($data = $getShared->fetch_assoc()) {
                        $duplicate_shared_member_lid[] = $data['id'];
                    }

                    // Check if exist selected merge as primary
                    $getPrimaryShared = $projectdb->query("SELECT id, description FROM services WHERE id IN (".implode(",", $duplicate_shared_member_lid).") AND merge_as_primary = '1' ;");
                    if ($getPrimaryShared->num_rows == 1) {
                        $dataPS = $getPrimaryShared->fetch_assoc();
                        $primary_member_lid_shared = $dataPS['id'];
                        $all_description[] = $dataPS['description'];
                        $is_first_shared = false;
                    }
                    elseif($getPrimaryShared->num_rows > 1){
                        $error = 1;
                        // Error, hay más de un selected as primary para un conjunto de duplicated name, add log
                        add_log2('warning', 'Merging Duplicated Services', 'Error when Duplicated Services [' . $name . '] merging: two or more selected as primary.', $source, 'No Action required', 'objects', $id, 'services');
                    }

                    if($error == 0) {
                        $getDupsInShared = $projectdb->query("SELECT id, description FROM services WHERE id IN (".implode(",", $duplicate_shared_member_lid).") AND merge_as_primary = '0';");
                        if ($getDupsInShared->num_rows > 0) {
                            while ($dataDIS = $getDupsInShared->fetch_assoc()) {
                                if ($is_first_shared == true) {
                                    $is_first_shared = false;
                                    $primary_member_lid_shared = $dataDIS['id'];
                                    $all_description[] = $dataDIS['description'];
                                }
                                else {
                                    #UPDATE where other address are used
                                    $member_lid = $dataDIS['id'];
                                    $all_description[] = $dataDIS['description'];

                                    updateMemberLid($projectName, $primary_member_lid_shared, $member_lid, "services");

                                    $remove_shared_objects[] = $member_lid;
                                }
                            }
                        }
                        if (count($remove_shared_objects) > 0) {
                            $projectdb->query("DELETE FROM services WHERE id IN (" . implode(",", $remove_shared_objects) . ");");
                        }
                        $shared_member_lid = $primary_member_lid_shared;
                        //finish merge in shared 2 or more address shared
                    }
                }

                $getDups = $projectdb->query("SELECT id, description FROM services $query AND source = '$source' AND protocol = '$protocol' AND dport = '$dport' AND override = '$override' AND timeout = '$timeout' AND halfclose_timeout = '$halfclose_timeout' AND timewait_timeout = '$timewait_timeout' AND vsys != 'shared' AND dummy = 0;");
                if ($getDups->num_rows > 0) {
                    while ($dataDups = $getDups->fetch_assoc()) {
                        $member_lid = $dataDups['id'];
                        $all_description[] = $dataDups['description'];
                        $primary_member_lid = $shared_member_lid;

                        updateMemberLid($projectName, $primary_member_lid, $member_lid, "services");

                        $remove_objects[] = $member_lid;
                    }
                }
                cleanDuplicatedMembersMerging($primary_member_lid, "services");

                $all_description = array_unique($all_description);
                $finally_description = implode(", ", $all_description);
                $finally_description = truncate_descriptions($finally_description, $version);

                $projectdb->query("UPDATE services SET merge_as_primary = '0', description = '$finally_description' WHERE id = '$primary_member_lid';");

            }
            if (count($remove_objects) > 0) {
                $projectdb->query("DELETE FROM services WHERE id IN (" . implode(",", $remove_objects) . ");");
            }

        }
    }
    else {
        #Merge in the same VSYS
        $getDuplicated = $projectdb->query("SELECT id, name, dport, protocol, override, timeout, halfclose_timeout, timewait_timeout 
              FROM services $query 
              GROUP BY protocol, dport, override, timeout, halfclose_timeout, timewait_timeout;");

        if ($getDuplicated->num_rows > 0) {
            while ($dataD = $getDuplicated->fetch_assoc()) {
                $is_first = true;
                $error = 0;
                $remove_objects = array();
                $all_description = array();

                $name = $dataD['name'];
                $id = $dataD['id'];
                $dport = $dataD['dport'];
                $protocol = $dataD['protocol'];

                $override = $dataD['override'];
                $timeout = $dataD['timeout'];
                $halfclose_timeout = $dataD['halfclose_timeout'];
                $timewait_timeout = $dataD['timewait_timeout'];

                add_log2('ok', 'Merging Duplicated Services', 'Duplicated Services [' . $name . '] merging', $source, 'No Action required', 'objects', $id, 'services');

                // Check if exist selected merge as primary
                $getPrimary = $projectdb->query("SELECT id, description FROM services $query AND protocol = '$protocol' AND dport = '$dport' AND override = '$override' AND timeout = '$timeout' AND halfclose_timeout = '$halfclose_timeout' AND timewait_timeout = '$timewait_timeout' AND merge_as_primary = '1' ;");
                if ($getPrimary->num_rows == 1) {
                    $dataP = $getPrimary->fetch_assoc();
                    $primary_member_lid = $dataP['id'];
                    $all_description[] = $dataP['description'];
                    $is_first = false;
                }
                elseif($getPrimary->num_rows > 1){
                    $error = 1;
                    // Error, hay más de un selected as primary para un conjunto de duplicated name, add log
                    add_log2('warning', 'Merging Duplicated Services', 'Error when Duplicated Services [' . $name . '] merging: two or more selected as primary.', $source, 'No Action required', 'objects', $id, 'services');
                }

                if($error == 0){
                    $getDupsByName = $projectdb->query("SELECT id, description FROM services $query AND protocol = '$protocol' AND dport = '$dport' AND override = '$override' AND timeout = '$timeout' AND halfclose_timeout = '$halfclose_timeout' AND timewait_timeout = '$timewait_timeout' AND merge_as_primary = '0';");

                    if ($getDupsByName->num_rows > 0) {
                        while ($dataDBN = $getDupsByName->fetch_assoc()) {
                            if ($is_first == true) {
                                $is_first = false;
                                $primary_member_lid = $dataDBN['id'];
                                $all_description[] = $dataDBN['description'];
                            }
                            else {
                                $member_lid = $dataDBN['id'];
                                $all_description[] = $dataDBN['description'];

                                updateMemberLid($projectName, $primary_member_lid, $member_lid, "services");

                                $remove_objects[] = $member_lid;
                            }
                        }
                        cleanDuplicatedMembersMerging($primary_member_lid, "services");

                        $all_description = array_unique($all_description);
                        $finally_description = implode(", ", $all_description);
                        $finally_description = truncate_descriptions($finally_description, $version);

                        $projectdb->query("UPDATE services set merge_as_primary = '0', description = '$finally_description' WHERE id = '$primary_member_lid';");
                    }
                    if (count($remove_objects) > 0) {
                        $projectdb->query("DELETE FROM services WHERE id IN (" . implode(",", $remove_objects) . ");");
                    }
                }
            }
        }
    }
    check_used_objects_new();

}


function setMergeByNameRegions(STRING $projectName, $selection, $vsys, $source){

    global $projectdb;
    global $app;

    $projectdb = selectDatabase($projectName);

    $user = $app->container->sentinel->getUser();
    $user_id = $user->id;

    $shared_member_lid = "";

    take_snapshot_last($projectName);

    if(count($selection) > 0) {
        $query = " WHERE id IN ($selection) ";
    }
    else{
        $getResultsTools = $projectdb->query("SELECT member_lid FROM tools_results WHERE table_name = 'regions' AND source = '$source' AND user_id = '$user_id';");

        if ($getResultsTools->num_rows > 0) {

            while ($dataRT = $getResultsTools->fetch_assoc()){
                if($dataRT['member_lid'] != ""){
                    $member_lid[] = $dataRT['member_lid'];
                }else{
                    $member_lid = array();
                }
            }
            if(count($member_lid) > 0){
                $query = " WHERE id IN (" . implode(",", $member_lid) . ") ";
            }
            else{
                $query = " WHERE id IN ('') ";
            }
        }
        else{
            $query = " WHERE id IN ('') ";
        }
    }

    if ($vsys == "all") {
        #Merge and move to Shared
        $getDuplicated = $projectdb->query("SELECT id, name_ext, name, used, vsys, latitude, longitude, address "
            . "FROM regions $query GROUP BY BINARY name ;");

        if ($getDuplicated->num_rows > 0) {
            $remove_objects = array();
            $remove_shared_objects = array();
            while ($data = $getDuplicated->fetch_assoc()) {
                $is_first_shared = true;
                $id = $data['id'];
                $name = $data['name'];
                $name_ext = $data['name_ext'];
                $used = $data['used'];
                $latitude = $data['latitude'];
                $longitude = $data['longitude'];
                $address = $data['address'];

                $duplicate_shared_member_lid = array();

                #Check if exits in shared
                $getShared = $projectdb->query("SELECT id FROM regions WHERE source = '$source' AND BINARY name = '$name' AND vsys = 'shared' AND dummy = 0;");
                if ($getShared->num_rows == 0) {
                    $data["id"] = "";
                    $projectdb->query("INSERT INTO regions (name_ext, name, used, vsys,  latitude, longitude, address, source)  
                                      VALUES ('$name_ext', '$name', '$used', 'shared', '$latitude', '$longitude', '$address', '$source');");

                    $shared_member_lid = $projectdb->insert_id;
                    add_log2('ok', 'Merging Duplicated Regions', 'Duplicated Region [' . $name . '] merging and moving into Shared', $source, 'No Action required', 'objects', $shared_member_lid, 'regions');
                }
                elseif ($getShared->num_rows == 1) {
                    $data = $getShared->fetch_assoc();
                    $shared_member_lid = $data['id'];
                    add_log2('ok', 'Merging Duplicated Regions', 'Duplicated Region [' . $name . '] merging and moving into Shared', $source, 'No Action required', 'objects', $shared_member_lid, 'regions');
                }
                else {
                    $error = 0;
                    # First merge in the shared space get the id from the first delete the others
                    add_log2('warning', 'Merging Duplicated Regions', 'The are duplicate objects in the shared: ' . $name . '', $source, 'Merge automatically in the shared.', 'objects', $id, 'regions');

                    while ($data = $getShared->fetch_assoc()) {
                        $duplicate_shared_member_lid[] = $data['id'];
                    }

                    // Check if exist selected merge as primary
                    $getPrimaryShared = $projectdb->query("SELECT id FROM regions WHERE id IN (".implode(",", $duplicate_shared_member_lid).") AND merge_as_primary = '1' ;");
                    if ($getPrimaryShared->num_rows == 1) {
                        $dataPS = $getPrimaryShared->fetch_assoc();
                        $primary_member_lid_shared = $dataPS['id'];
                        $is_first_shared = false;
                    }
                    elseif($getPrimaryShared->num_rows > 1){
                        $error = 1;
                        // Error, hay más de un selected as primary para un conjunto de duplicated name, add log
                        add_log2('warning', 'Merging Duplicated Regions', 'Error when Duplicated Regions [' . $name . '] merging: two or more selected as primary.', $source, 'No Action required', 'objects', $id, 'regions');
                    }

                    if($error == 0) {
                        $getDupsInShared = $projectdb->query("SELECT id FROM regions WHERE id IN (".implode(",", $duplicate_shared_member_lid).") AND merge_as_primary = '0';");
                        if ($getDupsInShared->num_rows > 0) {
                            while ($dataDIS = $getDupsInShared->fetch_assoc()) {
                                if ($is_first_shared == true) {
                                    $is_first_shared = false;
                                    $primary_member_lid_shared = $dataDIS['id'];
                                }
                                else {
                                    #UPDATE where other services are used
                                    $member_lid = $dataDIS['id'];

                                    updateMemberLid($projectName, $primary_member_lid_shared, $member_lid, "regions");

                                    $remove_shared_objects[] = $member_lid;
                                }
                            }
                        }
                        if (count($remove_shared_objects) > 0) {
                            $projectdb->query("DELETE FROM regions WHERE id IN (" . implode(",", $remove_shared_objects) . ");");
                        }
                        $shared_member_lid = $primary_member_lid_shared;
                        //finish merge in shared 2 or more services shared
                    }
                }

                $getDups = $projectdb->query("SELECT id FROM regions $query AND source = '$source' AND BINARY name = '$name' AND vsys != 'shared' AND dummy = 0;");
                if ($getDups->num_rows > 0) {
                    while ($dataDups = $getDups->fetch_assoc()) {
                        $member_lid = $dataDups['id'];
                        #UPDATE where other address are used
                        $primary_member_lid = $shared_member_lid;

                        updateMemberLid($projectName, $primary_member_lid, $member_lid, "regions");

                        $remove_objects[] = $member_lid;
                    }
                }
                cleanDuplicatedMembersMerging($primary_member_lid, "regions");

                $projectdb->query("UPDATE regions SET merge_as_primary = '0' WHERE id = '$primary_member_lid';");
            }
            if (count($remove_objects) > 0) {
                $projectdb->query("DELETE FROM regions WHERE id IN (" . implode(",", $remove_objects) . ");");
            }

        }
    }
    else {
        #Merge in the same VSYS
        $getDuplicated = $projectdb->query("SELECT id, name FROM regions $query GROUP BY BINARY name ;");

        if ($getDuplicated->num_rows > 0) {
            while ($dataD = $getDuplicated->fetch_assoc()) {
                $is_first = true;
                $error = 0;
                $remove_objects = array();
                $name = $dataD['name'];
                $id = $dataD['id'];

                add_log2('ok', 'Merging Duplicated Regions', 'Duplicated Regions [' . $name . '] merging', $source, 'No Action required', 'objects', $id, 'regions');

                // Check if exist selected merge as primary
                $getPrimary = $projectdb->query("SELECT id FROM regions $query AND BINARY name = '$name' AND merge_as_primary = '1' ;");
                if ($getPrimary->num_rows == 1) {
                    $dataP = $getPrimary->fetch_assoc();
                    $primary_member_lid = $dataP['id'];
                    $is_first = false;
                }
                elseif($getPrimary->num_rows > 1){
                    $error = 1;
                    // Error, hay más de un selected as primary para un conjunto de duplicated name, add log
                    add_log2('warning', 'Merging Duplicated Regions', 'Error when Duplicated Regions [' . $name . '] merging: two or more selected as primary.', $source, 'No Action required', 'objects', $id, 'regions');
                }

                if($error == 0){
                    $getDupsByName = $projectdb->query("SELECT id FROM regions $query AND BINARY name = '$name' AND merge_as_primary = '0';");

                    if ($getDupsByName->num_rows > 0) {
                        while ($dataDBN = $getDupsByName->fetch_assoc()) {
                            if ($is_first == true) {
                                $is_first = false;
                                $primary_member_lid = $dataDBN['id'];
                            }
                            else {
                                #UPDATE where other address are used
                                $member_lid = $dataDBN['id'];

                                updateMemberLid($projectName, $primary_member_lid, $member_lid, "regions");

                                $remove_objects[] = $member_lid;
                            }
                        }
                        cleanDuplicatedMembersMerging($primary_member_lid, "regions");

                        $projectdb->query("UPDATE regions set merge_as_primary = '0' WHERE id = '$primary_member_lid';");
                    }
                    if (count($remove_objects) > 0) {
                        $projectdb->query("DELETE FROM regions WHERE id IN (" . implode(",", $remove_objects) . ");");
                    }
                }
            }
        }
    }
    check_used_objects_new();
}


function setMergeByNameRegions2(STRING $projectName, ARRAY $selection, $vsys, $source){

    global $app;
    global $projectdb;
    $projectdb = selectDatabase($projectName);

    $me = $app->sentinel->getUser();
    $regionsMerger = new RegionsMerger($projectName, $me['id'], $source);
    $regionsMerger->setMergerByFields(['name']);

    $regionsMerger->merge($selection);

}


function setMergeByNameValueRegions(STRING $projectName, $selection, $vsys, $source){

    global $projectdb;
    global $app;

    $projectdb = selectDatabase($projectName);

    $user = $app->container->sentinel->getUser();
    $user_id = $user->id;

    $shared_member_lid = "";

    take_snapshot_last($projectName);

    $query = generate_query("objects");

    if(count($selection) > 0) {
        $query = " WHERE id IN ($selection) ";
    }
    else{
        $getResultsTools = $projectdb->query("SELECT member_lid FROM tools_results WHERE table_name = 'regions' AND source = '$source' AND user_id = '$user_id';");

        if ($getResultsTools->num_rows > 0) {

            while ($dataRT = $getResultsTools->fetch_assoc()){
                if($dataRT['member_lid'] != ""){
                    $member_lid[] = $dataRT['member_lid'];
                }else{
                    $member_lid = array();
                }
            }
            if(count($member_lid) > 0){
                $query = " WHERE id IN (" . implode(",", $member_lid) . ") ";
            }
            else{
                $query = " WHERE id IN ('') ";
            }
        }
        else{
            $query = " WHERE id IN ('') ";
        }
    }

    if ($vsys == "all") {
        #Merge and move to Shared
        $getDuplicated = $projectdb->query("SELECT id, name_ext, name, used, vsys, source, latitude, longitude, address "
            . "FROM regions $query GROUP BY BINARY name, latitude, longitude, address ;");

        if ($getDuplicated->num_rows > 0) {
            $remove_objects = array();
            $remove_shared_objects = array();
            while ($data = $getDuplicated->fetch_assoc()) {
                $is_first_shared = true;
                $id = $data['id'];
                $name = $data['name'];
                $name_ext = $data['name_ext'];
                $used = $data['used'];
                $latitude = $data['latitude'];
                $longitude = $data['longitude'];
                $address = $data['address'];

                $duplicate_shared_member_lid = array();

                #Check if exits in shared
                $getShared = $projectdb->query("SELECT id FROM regions WHERE source = '$source' AND BINARY name = '$name' AND latitude = '$latitude' AND longitude = '$longitude' AND address = '$address' AND vsys = 'shared' AND dummy = 0;");
                if ($getShared->num_rows == 0) {
                    $data["id"] = "";
                    $projectdb->query("INSERT INTO regions (name_ext, name, used, vsys,  latitude, longitude, address, source)  
                                      VALUES ('$name_ext', '$name', '$used', 'shared', '$latitude', '$longitude', '$address', '$source');");
                    $shared_member_lid = $projectdb->insert_id;
                    add_log2('ok', 'Merging Duplicated Regions', 'Duplicated Regions [' . $name . '] merging and moving into Shared', $source, 'No Action required', 'objects', $shared_member_lid, 'regions');
                }
                elseif ($getShared->num_rows == 1) {
                    $data = $getShared->fetch_assoc();
                    $shared_member_lid = $data['id'];
                    add_log2('ok', 'Merging Duplicated Regions', 'Duplicated Regions [' . $name . '] merging and moving into Shared', $source, 'No Action required', 'objects', $shared_member_lid, 'regions');
                }
                else {
                    $error = 0;
                    # First merge in the shared space get the id from the first delete the others
                    add_log2('warning', 'Merging Duplicated Regions', 'The are duplicate objects in the shared: ' . $name . '', $source, 'Merge automatically in the shared.', 'objects', $id, 'regions');

                    while ($data = $getShared->fetch_assoc()) {
                        $duplicate_shared_member_lid[] = $data['id'];
                    }

                    // Check if exist selected merge as primary
                    $getPrimaryShared = $projectdb->query("SELECT id FROM regions WHERE id IN (".implode(",", $duplicate_shared_member_lid).") AND merge_as_primary = '1' ;");
                    if ($getPrimaryShared->num_rows == 1) {
                        $dataPS = $getPrimaryShared->fetch_assoc();
                        $primary_member_lid_shared = $dataPS['id'];
                        $is_first_shared = false;
                    }
                    elseif($getPrimaryShared->num_rows > 1){
                        $error = 1;
                        // Error, hay más de un selected as primary para un conjunto de duplicated name, add log
                        add_log2('warning', 'Merging Duplicated Regions', 'Error when Duplicated Regions [' . $name . '] merging: two or more selected as primary.', $source, 'No Action required', 'objects', $id, 'regions');
                    }

                    if($error == 0) {
                        $getDupsInShared = $projectdb->query("SELECT id FROM regions WHERE id IN (".implode(",", $duplicate_shared_member_lid).") AND merge_as_primary = '0';");
                        if ($getDupsInShared->num_rows > 0) {
                            while ($dataDIS = $getDupsInShared->fetch_assoc()) {
                                if ($is_first_shared == true) {
                                    $is_first_shared = false;
                                    $primary_member_lid_shared = $dataDIS['id'];
                                }
                                else {
                                    #UPDATE where other address are used
                                    $member_lid = $dataDIS['id'];

                                    updateMemberLid($projectName, $primary_member_lid_shared, $member_lid, "regions");

                                    $remove_shared_objects[] = $member_lid;
                                }
                            }
                        }
                        if (count($remove_shared_objects) > 0) {
                            $projectdb->query("DELETE FROM regions WHERE id IN (" . implode(",", $remove_shared_objects) . ");");
                        }
                        $shared_member_lid = $primary_member_lid_shared;
                        //finish merge in shared 2 or more address shared
                    }
                }

                $getDups = $projectdb->query("SELECT id FROM regions $query AND source = '$source' AND BINARY name = '$name' AND latitude = '$latitude' AND longitude = '$longitude' AND address = '$address' AND vsys != 'shared' AND dummy = 0;");
                if ($getDups->num_rows > 0) {
                    while ($dataDups = $getDups->fetch_assoc()) {
                        $member_lid = $dataDups['id'];
                        $primary_member_lid = $shared_member_lid;

                        updateMemberLid($projectName, $primary_member_lid, $member_lid, "regions");

                        $remove_objects[] = $member_lid;
                    }
                }
                cleanDuplicatedMembersMerging($primary_member_lid, "regions");
                $projectdb->query("UPDATE regions SET merge_as_primary = '0' WHERE id = '$primary_member_lid';");
            }
            if (count($remove_objects) > 0) {
                $projectdb->query("DELETE FROM regions WHERE id IN (" . implode(",", $remove_objects) . ");");
            }

        }
    }
    else {
        #Merge in the same VSYS
        $getDuplicated = $projectdb->query("SELECT id, name, latitude, longitude, address FROM regions $query GROUP BY BINARY name, latitude, longitude, address ;");

        if ($getDuplicated->num_rows > 0) {
            while ($dataD = $getDuplicated->fetch_assoc()) {
                $is_first = true;
                $error = 0;
                $remove_objects = array();
                $name = $dataD['name'];
                $id = $dataD['id'];
                $latitude = $dataD['latitude'];
                $longitude = $dataD['longitude'];
                $address = $dataD['address'];

                add_log2('ok', 'Merging Duplicated Regions', 'Duplicated Regions [' . $name . '] merging', $source, 'No Action required', 'objects', $id, 'regions');

                // Check if exist selected merge as primary
                $getPrimary = $projectdb->query("SELECT id FROM regions $query AND BINARY name = '$name' AND latitude = '$latitude' AND longitude = '$longitude' AND address = '$address' AND merge_as_primary = '1' ;");
                if ($getPrimary->num_rows == 1) {
                    $dataP = $getPrimary->fetch_assoc();
                    $primary_member_lid = $dataP['id'];
                    $is_first = false;
                }
                elseif($getPrimary->num_rows > 1){
                    $error = 1;
                    // Error, hay más de un selected as primary para un conjunto de duplicated name, add log
                    add_log2('warning', 'Merging Duplicated Regions', 'Error when Duplicated Regions [' . $name . '] merging: two or more selected as primary.', $source, 'No Action required', 'objects', $id, 'regions');
                }

                if($error == 0){
                    $getDupsByName = $projectdb->query("SELECT id FROM regions $query AND BINARY name = '$name' AND latitude = '$latitude' AND longitude = '$longitude' AND address = '$address' AND merge_as_primary = '0';");

                    if ($getDupsByName->num_rows > 0) {
                        while ($dataDBN = $getDupsByName->fetch_assoc()) {
                            if ($is_first == true) {
                                $is_first = false;
                                $primary_member_lid = $dataDBN['id'];
                            }
                            else {
                                $member_lid = $dataDBN['id'];

                                updateMemberLid($projectName, $primary_member_lid, $member_lid, "regions");

                                $remove_objects[] = $member_lid;
                            }
                        }
                        cleanDuplicatedMembersMerging($primary_member_lid, "regions");

                        $projectdb->query("UPDATE regions set merge_as_primary = '0' WHERE id = '$primary_member_lid';");
                    }
                    if (count($remove_objects) > 0) {
                        $projectdb->query("DELETE FROM regions WHERE id IN (" . implode(",", $remove_objects) . ");");
                    }
                }
            }
        }
    }
    check_used_objects_new();

}


function setMergeByNameValueRegions2(STRING $projectName, ARRAY $selection, $vsys, $source){

    global $app;
    global $projectdb;
    $projectdb = selectDatabase($projectName);

    $me = $app->sentinel->getUser();
    $regionsMerger = new RegionsMerger($projectName, $me['id'], $source);
    $regionsMerger->setMergerByFields(['name', 'latitude', 'longitude', 'address']);

    $regionsMerger->merge($selection);

}


function setMergeByValueRegions(STRING $projectName, $selection, $vsys, $source){

    global $projectdb;
    global $app;

    $projectdb = selectDatabase($projectName);

    $user = $app->container->sentinel->getUser();
    $user_id = $user->id;

    $shared_member_lid = "";

    take_snapshot_last($projectName);

    $query = generate_query("objects");

    if(count($selection) > 0) {
        $query = " WHERE id IN ($selection) ";
    }
    else{
        $getResultsTools = $projectdb->query("SELECT member_lid FROM tools_results WHERE table_name = 'regions' AND source = '$source' AND user_id = '$user_id';");

        if ($getResultsTools->num_rows > 0) {

            while ($dataRT = $getResultsTools->fetch_assoc()){
                if($dataRT['member_lid'] != ""){
                    $member_lid[] = $dataRT['member_lid'];
                }else{
                    $member_lid = array();
                }
            }
            if(count($member_lid) > 0){
                $query = " WHERE id IN (" . implode(",", $member_lid) . ") ";
            }
            else{
                $query = " WHERE id IN ('') ";
            }
        }
        else{
            $query = " WHERE id IN ('') ";
        }
    }

    if ($vsys == "all") {
        #Merge and move to Shared
        $getDuplicated = $projectdb->query("SELECT id, name_ext, name, used, vsys, source, latitude, longitude, address "
            . "FROM regions $query GROUP BY latitude, longitude, address ;");

        if ($getDuplicated->num_rows > 0) {
            $remove_objects = array();
            $remove_shared_objects = array();
            while ($data = $getDuplicated->fetch_assoc()) {
                $is_first_shared = true;
                $id = $data['id'];
                $name = $data['name'];
                $name_ext = $data['name_ext'];
                $used = $data['used'];
                $latitude = $data['latitude'];
                $longitude = $data['longitude'];
                $address = $data['address'];

                $duplicate_shared_member_lid = array();

                #Check if exits in shared
                $getShared = $projectdb->query("SELECT id FROM regions WHERE source = '$source' AND latitude = '$latitude' AND longitude = '$longitude' AND address = '$address' AND vsys = 'shared' AND dummy = 0;");
                if ($getShared->num_rows == 0) {
                    $data["id"] = "";
                    $projectdb->query("INSERT INTO regions (name_ext, name, used, vsys,  latitude, longitude, address, source)  
                                      VALUES ('$name_ext', '$name', '$used', 'shared', '$latitude', '$longitude', '$address', '$source');");
                    $shared_member_lid = $projectdb->insert_id;
                    add_log2('ok', 'Merging Duplicated Regions', 'Duplicated Regions [' . $name . '] merging and moving into Shared', $source, 'No Action required', 'objects', $shared_member_lid, 'regions');
                }
                elseif ($getShared->num_rows == 1) {
                    $data = $getShared->fetch_assoc();
                    $shared_member_lid = $data['id'];
                    add_log2('ok', 'Merging Duplicated Regions', 'Duplicated Regions [' . $name . '] merging and moving into Shared', $source, 'No Action required', 'objects', $shared_member_lid, 'regions');
                }
                else {
                    $error = 0;
                    # First merge in the shared space get the id from the first delete the others
                    add_log2('warning', 'Merging Duplicated Regions', 'The are duplicate objects in the shared: ' . $name . '', $source, 'Merge automatically in the shared.', 'objects', $id, 'regions');

                    while ($data = $getShared->fetch_assoc()) {
                        $duplicate_shared_member_lid[] = $data['id'];
                    }

                    // Check if exist selected merge as primary
                    $getPrimaryShared = $projectdb->query("SELECT id FROM regions WHERE id IN (".implode(",", $duplicate_shared_member_lid).") AND merge_as_primary = '1' ;");
                    if ($getPrimaryShared->num_rows == 1) {
                        $dataPS = $getPrimaryShared->fetch_assoc();
                        $primary_member_lid_shared = $dataPS['id'];
                        $is_first_shared = false;
                    }
                    elseif($getPrimaryShared->num_rows > 1){
                        $error = 1;
                        // Error, hay más de un selected as primary para un conjunto de duplicated name, add log
                        add_log2('warning', 'Merging Duplicated Regions', 'Error when Duplicated Regions [' . $name . '] merging: two or more selected as primary.', $source, 'No Action required', 'objects', $id, 'regions');
                    }

                    if($error == 0) {
                        $getDupsInShared = $projectdb->query("SELECT id FROM regions WHERE id IN (".implode(",", $duplicate_shared_member_lid).") AND merge_as_primary = '0';");
                        if ($getDupsInShared->num_rows > 0) {
                            while ($dataDIS = $getDupsInShared->fetch_assoc()) {
                                if ($is_first_shared == true) {
                                    $is_first_shared = false;
                                    $primary_member_lid_shared = $dataDIS['id'];
                                }
                                else {
                                    #UPDATE where other address are used
                                    $member_lid = $dataDIS['id'];

                                    updateMemberLid($projectName, $primary_member_lid_shared, $member_lid, "regions");

                                    $remove_shared_objects[] = $member_lid;
                                }
                            }
                        }
                        if (count($remove_shared_objects) > 0) {
                            $projectdb->query("DELETE FROM regions WHERE id IN (" . implode(",", $remove_shared_objects) . ");");
                        }
                        $shared_member_lid = $primary_member_lid_shared;
                        //finish merge in shared 2 or more address shared
                    }
                }

                $getDups = $projectdb->query("SELECT id FROM regions $query AND source = '$source' AND latitude = '$latitude' AND longitude = '$longitude' AND address = '$address' AND vsys != 'shared' AND dummy = 0;");
                if ($getDups->num_rows > 0) {
                    while ($dataDups = $getDups->fetch_assoc()) {
                        $member_lid = $dataDups['id'];
                        $primary_member_lid = $shared_member_lid;

                        updateMemberLid($projectName, $primary_member_lid, $member_lid, "regions");

                        $remove_objects[] = $member_lid;
                    }
                }
                cleanDuplicatedMembersMerging($primary_member_lid, "regions");
                $projectdb->query("UPDATE regions SET merge_as_primary = '0' WHERE id = '$primary_member_lid';");
            }
            if (count($remove_objects) > 0) {
                $projectdb->query("DELETE FROM regions WHERE id IN (" . implode(",", $remove_objects) . ");");
            }

        }
    }
    else {
        #Merge in the same VSYS
        $getDuplicated = $projectdb->query("SELECT id, name, latitude, longitude, address FROM regions $query GROUP BY latitude, longitude, address ;");

        if ($getDuplicated->num_rows > 0) {
            while ($dataD = $getDuplicated->fetch_assoc()) {
                $is_first = true;
                $error = 0;
                $remove_objects = array();
                $name = $dataD['name'];
                $id = $dataD['id'];
                $latitude = $dataD['latitude'];
                $longitude = $dataD['longitude'];
                $address = $dataD['address'];

                add_log2('ok', 'Merging Duplicated Regions', 'Duplicated Regions [' . $name . '] merging', $source, 'No Action required', 'objects', $id, 'regions');

                // Check if exist selected merge as primary
                $getPrimary = $projectdb->query("SELECT id FROM regions $query AND latitude = '$latitude' AND longitude = '$longitude' AND address = '$address' AND merge_as_primary = '1' ;");
                if ($getPrimary->num_rows == 1) {
                    $dataP = $getPrimary->fetch_assoc();
                    $primary_member_lid = $dataP['id'];
                    $is_first = false;
                }
                elseif($getPrimary->num_rows > 1){
                    $error = 1;
                    // Error, hay más de un selected as primary para un conjunto de duplicated name, add log
                    add_log2('warning', 'Merging Duplicated Regions', 'Error when Duplicated Regions [' . $name . '] merging: two or more selected as primary.', $source, 'No Action required', 'objects', $id, 'regions');
                }

                if($error == 0){
                    $getDupsByName = $projectdb->query("SELECT id FROM regions $query AND latitude = '$latitude' AND longitude = '$longitude' AND address = '$address' AND merge_as_primary = '0';");

                    if ($getDupsByName->num_rows > 0) {
                        while ($dataDBN = $getDupsByName->fetch_assoc()) {
                            if ($is_first == true) {
                                $is_first = false;
                                $primary_member_lid = $dataDBN['id'];
                            }
                            else {
                                $member_lid = $dataDBN['id'];

                                updateMemberLid($projectName, $primary_member_lid, $member_lid, "regions");

                                $remove_objects[] = $member_lid;
                            }
                        }
                        cleanDuplicatedMembersMerging($primary_member_lid, "regions");

                        $projectdb->query("UPDATE regions set merge_as_primary = '0' WHERE id = '$primary_member_lid';");
                    }
                    if (count($remove_objects) > 0) {
                        $projectdb->query("DELETE FROM regions WHERE id IN (" . implode(",", $remove_objects) . ");");
                    }
                }
            }
        }
    }
    check_used_objects_new();

}


function setMergeByValueRegions2(STRING $projectName, ARRAY $selection, $vsys, $source){

    global $app;
    global $projectdb;
    $projectdb = selectDatabase($projectName);

    $me = $app->sentinel->getUser();
    $regionsMerger = new RegionsMerger($projectName, $me['id'], $source);
    $regionsMerger->setMergerByFields(['latitude', 'longitude', 'address']);

    $regionsMerger->merge($selection);

}


function setMergeByNameTags(STRING $projectName, $selection, $vsys, $source){

    global $projectdb;
    global $app;

    $projectdb = selectDatabase($projectName);

    $user = $app->container->sentinel->getUser();
    $user_id = $user->id;

    $shared_member_lid = "";

    take_snapshot_last($projectName);

    if(count($selection) > 0) {
        $query = " WHERE id IN (".implode(",",$selection).") ";
    }
    else{
        $getResultsTools = $projectdb->query("SELECT member_lid FROM tools_results WHERE table_name = 'tag' AND source = '$source' AND user_id = '$user_id';");

        if ($getResultsTools->num_rows > 0) {

            while ($dataRT = $getResultsTools->fetch_assoc()){
                if($dataRT['member_lid'] != ""){
                    $member_lid[] = $dataRT['member_lid'];
                }else{
                    $member_lid = array();
                }
            }
            if(count($member_lid) > 0){
                $query = " WHERE id IN (" . implode(",", $member_lid) . ") ";
            }
            else{
                $query = " WHERE id IN ('') ";
            }
        }
        else{
            $query = " WHERE id IN ('') ";
        }
    }

    if ($vsys == "all") {
        #Merge and move to Shared
        $getDuplicated = $projectdb->query("SELECT id, name_ext, name, color, comments, vsys "
            . "FROM tag $query GROUP BY BINARY name ;");

        if ($getDuplicated->num_rows > 0) {
            $remove_objects = array();
            $remove_shared_objects = array();
            while ($data = $getDuplicated->fetch_assoc()) {
                $is_first_shared = true;
                $id = $data['id'];
                $name = $data['name'];
                $name_ext = $data['name_ext'];
                $color = $data['color'];
                $comments = $data['comments'];

                $duplicate_shared_member_lid = array();

                #Check if exits in shared
                $getShared = $projectdb->query("SELECT id FROM tag WHERE source = '$source' AND BINARY name = '$name' AND vsys = 'shared' AND dummy = 0;");
                if ($getShared->num_rows == 0) {
                    $data["id"] = "";
                    $projectdb->query("INSERT INTO tag (name_ext, name, vsys, color, comments, source)  
                                      VALUES ('$name_ext', '$name', 'shared', '$color', '$comments', '$source');");

                    $shared_member_lid = $projectdb->insert_id;
                    add_log2('ok', 'Merging Duplicated Tags', 'Duplicated Tag [' . $name . '] merging and moving into Shared', $source, 'No Action required', 'objects', $shared_member_lid, 'tag');
                }
                elseif ($getShared->num_rows == 1) {
                    $data = $getShared->fetch_assoc();
                    $shared_member_lid = $data['id'];
                    add_log2('ok', 'Merging Duplicated Tags', 'Duplicated Tag [' . $name . '] merging and moving into Shared', $source, 'No Action required', 'objects', $shared_member_lid, 'tag');
                }
                else {
                    $error = 0;
                    # First merge in the shared space get the id from the first delete the others
                    add_log2('warning', 'Merging Duplicated Tags', 'The are duplicate objects in the shared: ' . $name . '', $source, 'Merge automatically in the shared.', 'objects', $id, 'tag');

                    while ($data = $getShared->fetch_assoc()) {
                        $duplicate_shared_member_lid[] = $data['id'];
                    }

                    // Check if exist selected merge as primary
                    $getPrimaryShared = $projectdb->query("SELECT id FROM tag WHERE id IN (".implode(",", $duplicate_shared_member_lid).") AND merge_as_primary = '1' ;");
                    if ($getPrimaryShared->num_rows == 1) {
                        $dataPS = $getPrimaryShared->fetch_assoc();
                        $primary_member_lid_shared = $dataPS['id'];
                        $is_first_shared = false;
                    }
                    elseif($getPrimaryShared->num_rows > 1){
                        $error = 1;
                        // Error, hay más de un selected as primary para un conjunto de duplicated name, add log
                        add_log2('warning', 'Merging Duplicated Tags', 'Error when Duplicated Tag [' . $name . '] merging: two or more selected as primary.', $source, 'No Action required', 'objects', $id, 'tag');
                    }

                    if($error == 0) {
                        $getDupsInShared = $projectdb->query("SELECT id FROM tag WHERE id IN (".implode(",", $duplicate_shared_member_lid).") AND merge_as_primary = '0';");
                        if ($getDupsInShared->num_rows > 0) {
                            while ($dataDIS = $getDupsInShared->fetch_assoc()) {
                                if ($is_first_shared == true) {
                                    $is_first_shared = false;
                                    $primary_member_lid_shared = $dataDIS['id'];
                                }
                                else {
                                    #UPDATE where other services are used
                                    $member_lid = $dataDIS['id'];

                                    updateMemberLid($projectName, $primary_member_lid_shared, $member_lid, "tag");

                                    $remove_shared_objects[] = $member_lid;
                                }
                            }
                        }
                        if (count($remove_shared_objects) > 0) {
                            $projectdb->query("DELETE FROM tag WHERE id IN (" . implode(",", $remove_shared_objects) . ");");
                        }
                        $shared_member_lid = $primary_member_lid_shared;
                        //finish merge in shared 2 or more services shared
                    }
                }

                $getDups = $projectdb->query("SELECT id FROM tag $query AND source = '$source' AND BINARY name = '$name' AND vsys != 'shared' AND dummy = 0;");
                if ($getDups->num_rows > 0) {
                    while ($dataDups = $getDups->fetch_assoc()) {
                        $member_lid = $dataDups['id'];
                        #UPDATE where other address are used
                        $primary_member_lid = $shared_member_lid;

                        updateMemberLid($projectName, $primary_member_lid, $member_lid, "tag");

                        $remove_objects[] = $member_lid;
                    }
                }
                cleanDuplicatedMembersMerging($primary_member_lid, "tag");

                $projectdb->query("UPDATE tag SET merge_as_primary = '0' WHERE id = '$primary_member_lid';");
            }
            if (count($remove_objects) > 0) {
                $projectdb->query("DELETE FROM tag WHERE id IN (" . implode(",", $remove_objects) . ");");
            }

        }
    }
    else {
        #Merge in the same VSYS
        $getDuplicated = $projectdb->query("SELECT id, name FROM tag $query GROUP BY BINARY name ;");

        if ($getDuplicated->num_rows > 0) {
            while ($dataD = $getDuplicated->fetch_assoc()) {
                $is_first = true;
                $error = 0;
                $remove_objects = array();
                $name = $dataD['name'];
                $id = $dataD['id'];

                add_log2('ok', 'Merging Duplicated Tags', 'Duplicated Tag [' . $name . '] merging', $source, 'No Action required', 'objects', $id, 'tag');

                // Check if exist selected merge as primary
                $getPrimary = $projectdb->query("SELECT id FROM tag $query AND BINARY name = '$name' AND merge_as_primary = '1' ;");
                if ($getPrimary->num_rows == 1) {
                    $dataP = $getPrimary->fetch_assoc();
                    $primary_member_lid = $dataP['id'];
                    $is_first = false;
                }
                elseif($getPrimary->num_rows > 1){
                    $error = 1;
                    // Error, hay más de un selected as primary para un conjunto de duplicated name, add log
                    add_log2('warning', 'Merging Duplicated Tags', 'Error when Duplicated Tags [' . $name . '] merging: two or more selected as primary.', $source, 'No Action required', 'objects', $id, 'tag');
                }

                if($error == 0){
                    $getDupsByName = $projectdb->query("SELECT id FROM tag $query AND BINARY name = '$name' AND merge_as_primary = '0';");

                    if ($getDupsByName->num_rows > 0) {
                        while ($dataDBN = $getDupsByName->fetch_assoc()) {
                            if ($is_first == true) {
                                $is_first = false;
                                $primary_member_lid = $dataDBN['id'];
                            }
                            else {
                                #UPDATE where other address are used
                                $member_lid = $dataDBN['id'];

                                updateMemberLid($projectName, $primary_member_lid, $member_lid, "tag");

                                $remove_objects[] = $member_lid;
                            }
                        }
                        cleanDuplicatedMembersMerging($primary_member_lid, "tag");

                        $projectdb->query("UPDATE tag set merge_as_primary = '0' WHERE id = '$primary_member_lid';");
                    }
                    if (count($remove_objects) > 0) {
                        $projectdb->query("DELETE FROM tag WHERE id IN (" . implode(",", $remove_objects) . ");");
                    }
                }
            }
        }
    }
    check_used_objects_new();
}


function setMergeByNameApp2(STRING $projectName, ARRAY $selection, $vsys, $source){

    global $app;
    global $projectdb;
    $projectdb = selectDatabase($projectName);

    $me = $app->sentinel->getUser();
    $applicationsMerger = new ApplicationsMerger($projectName, $me['id'], $source);
    $applicationsMerger->setMergerByFields(['name']);

    $applicationsMerger->merge($selection);

}


function setMergeByNameApp(STRING $projectName, $selection, $vsys, $source){

    global $projectdb;
    global $app;

    $projectdb = selectDatabase($projectName);

    $user = $app->container->sentinel->getUser();
    $user_id = $user->id;

    take_snapshot_last($projectName);

    $query = generate_query("objects");

    if(count($selection) > 0) {
        $query = " WHERE id IN ($selection) ";
    }
    else{
        $getResultsTools = $projectdb->query("SELECT member_lid FROM tools_results WHERE table_name = 'applications' AND source = '$source' AND user_id = '$user_id';");

        if ($getResultsTools->num_rows > 0) {

            while ($dataRT = $getResultsTools->fetch_assoc()){
                if($dataRT['member_lid'] != ""){
                    $member_lid[] = $dataRT['member_lid'];
                }else{
                    $member_lid = array();
                }
            }
            if(count($member_lid) > 0){
                $query = " WHERE id IN (" . implode(",", $member_lid) . ") ";
            }
            else{
                $query = " WHERE id IN ('') ";
            }
        }
        else{
            $query = " WHERE id IN ('') ";
        }
    }

    if ($vsys == "all") {
        #Merge and move to Shared
        $getDuplicated = $projectdb->query("SELECT name, id, devicegroup, description, vsys, source, category, subcategory, parent_app, risk, technology, evasive_behavior, consume_big_bandwidth, used_by_malware, able_to_transfer_file, has_known_vulnerability, tunnel_other_application, tunnel_applications, prone_to_misuse,pervasive_use, file_type_ident, virus_ident, data_ident, default_type, value, type, code, timeout, tcp_timeout, udp_timeout, spyware_ident, dummy "
            . "FROM applications $query GROUP BY BINARY name ;");

        if ($getDuplicated->num_rows > 0) {
            $remove_objects = array();
            $remove_shared_objects = array();
            while ($data = $getDuplicated->fetch_assoc()) {
                $is_first_shared = true;
                $id = $data['id'];
                $name = $data['name'];
                $devicegroup = $data['devicegroup'];
                $description = $data['description'];
                $category = $data['category'];
                $subcategory = $data['subcategory'];
                $parent_app = $data['parent_app'];
                $risk = $data['risk'];
                $technology = $data['technology'];
                $evasive_behavior = $data['evasive_behavior'];
                $consume_big_bandwidth = $data['consume_big_bandwidth'];
                $used_by_malware = $data['used_by_malware'];
                $able_to_transfer_file = $data['able_to_transfer_file'];
                $has_known_vulnerability = $data['has_known_vulnerability'];
                $tunnel_other_application = $data['tunnel_other_application'];
                $tunnel_applications = $data['tunnel_applications'];
                $prone_to_misuse = $data['prone_to_misuse'];
                $pervasive_use = $data['pervasive_use'];
                $file_type_ident = $data['file_type_ident'];
                $virus_ident = $data['virus_ident'];
                $data_ident = $data['data_ident'];
                $default_type = $data['default_type'];
                $value = $data['value'];
                $type = $data['type'];
                $code = $data['code'];
                $timeout = $data['timeout'];
                $tcp_timeout = $data['tcp_timeout'];
                $udp_timeout = $data['udp_timeout'];
                $spyware_ident = $data['spyware_ident'];

                $getSignature1 = $projectdb->query("SELECT signature FROM applications_signatures WHERE table_name = 'applications' AND member_lid = '$id';");

                if ($getSignature1->num_rows > 0){
                    $dataS = $getSignature1->fetch_assoc();
                    $signature_first = $dataS['signature'];
                }

                $duplicate_shared_member_lid = array();

                #Check if exits in shared
                $getShared = $projectdb->query("SELECT id FROM applications WHERE source = '$source' AND BINARY name = '$name' AND vsys = 'shared' AND dummy = 0;");
                if ($getShared->num_rows == 0) {
                    $data["id"] = "";
                    $projectdb->query("INSERT INTO applications (name, devicegroup, description, category, subcategory, parent_app, risk, technology, evasive_behavior, consume_big_bandwidth, used_by_malware, able_to_transfer_file, has_known_vulnerability, tunnel_other_application, tunnel_applications, prone_to_misuse, pervasive_use, file_type_ident, virus_ident, data_ident, default_type, value, type, code, timeout, tcp_timeout, udp_timeout, spyware_ident, vsys, source)  "
                        . " VALUES ('$name', '$devicegroup', '$description', '$category', '$subcategory', '$parent_app', '$risk', '$technology', '$evasive_behavior', '$consume_big_bandwidth', '$used_by_malware', '$able_to_transfer_file', '$has_known_vulnerability', '$tunnel_other_application', '$tunnel_applications', '$prone_to_misuse', '$pervasive_use', '$file_type_ident', '$virus_ident', '$data_ident', '$default_type', '$value', '$type', '$code', '$timeout', '$tcp_timeout', '$udp_timeout', '$spyware_ident', 'shared', '$source');");

                    $shared_member_lid = $projectdb->insert_id;

                    $projectdb->query("INSERT INTO applications_signatures (vsys, source, devicegroup, signature, member_lid, table_name)  "
                        . "VALUES ('shared', '$source', '$devicegroup', '$signature_first', '$shared_member_lid', 'applications');");

                    add_log2('ok', 'Merging Duplicated Applications', 'Duplicated Application [' . $name . '] merging and moving into Shared', $source, 'No Action required', 'objects', $shared_member_lid, 'applications');
                }
                elseif ($getShared->num_rows == 1) {
                    $data = $getShared->fetch_assoc();
                    $shared_member_lid = $data['id'];

                    add_log2('ok', 'Merging Duplicated Applications', 'Duplicated Application [' . $name . '] merging and moving into Shared', $source, 'No Action required', 'objects', $shared_member_lid, 'applications');
                }
                else {
                    $error = 0;
                    # First merge in the shared space get the id from the first delete the others
                    add_log2('warning', 'Merging Duplicated Applications', 'The are duplicate objects in the shared: ' . $name . '', $source, 'Merge automatically in the shared.', 'objects', $id, 'applications');

                    while ($data = $getShared->fetch_assoc()) {
                        $duplicate_shared_member_lid[] = $data['id'];
                    }

                    // Check if exist selected merge as primary
                    $getPrimaryShared = $projectdb->query("SELECT id FROM applications WHERE id IN (".implode(",", $duplicate_shared_member_lid).") AND merge_as_primary = '1' ;");
                    if ($getPrimaryShared->num_rows == 1) {
                        $dataPS = $getPrimaryShared->fetch_assoc();
                        $primary_member_lid_shared = $dataPS['id'];
                        $is_first_shared = false;
                    }
                    elseif($getPrimaryShared->num_rows > 1){
                        $error = 1;
                        // Error, hay más de un selected as primary para un conjunto de duplicated name, add log
                        add_log2('warning', 'Merging Duplicated Applications', 'Error when Duplicated Applications [' . $name . '] merging: two or more selected as primary.', $source, 'No Action required', 'objects', $id, 'applications');
                    }

                    if($error == 0) {
                        $getDupsInShared = $projectdb->query("SELECT id FROM applications WHERE id IN (".implode(",", $duplicate_shared_member_lid).") AND merge_as_primary = '0';");
                        if ($getDupsInShared->num_rows > 0) {
                            while ($dataDIS = $getDupsInShared->fetch_assoc()) {
                                if ($is_first_shared == true) {
                                    $is_first_shared = false;
                                    $primary_member_lid_shared = $dataDIS['id'];
                                }
                                else {
                                    #UPDATE where other services are used
                                    $member_lid = $dataDIS['id'];

                                    updateMemberLid($projectName, $primary_member_lid_shared, $member_lid, "applications");

                                    $remove_shared_objects[] = $member_lid;
                                }
                            }
                        }
                        if (count($remove_shared_objects) > 0) {
                            $projectdb->query("DELETE FROM applications WHERE id IN (" . implode(",", $remove_shared_objects) . ");");
                            $projectdb->query("DELETE FROM applications_signatures WHERE table_name = 'applications' AND member_lid IN (" . implode(",", $remove_shared_objects) . ");");
                        }
                        $shared_member_lid = $primary_member_lid_shared;
                        //finish merge in shared 2 or more services shared
                    }
                }

                $getDups = $projectdb->query("SELECT id FROM applications $query AND source = '$source' AND BINARY name = '$name' AND vsys != 'shared' AND dummy = 0;");
                if ($getDups->num_rows > 0) {
                    while ($dataDups = $getDups->fetch_assoc()) {
                        $member_lid = $dataDups['id'];
                        #UPDATE where other address are used
                        $primary_member_lid = $shared_member_lid;

                        updateMemberLid($projectName, $primary_member_lid, $member_lid, "applications");

                        $remove_objects[] = $member_lid;
                    }
                }
                cleanDuplicatedMembersMerging($primary_member_lid, "applications");

                $projectdb->query("UPDATE applications SET merge_as_primary = '0' WHERE id = '$primary_member_lid';");
            }
            if (count($remove_objects) > 0) {
                $projectdb->query("DELETE FROM applications WHERE id IN (" . implode(",", $remove_objects) . ");");
                $projectdb->query("DELETE FROM applications_signatures WHERE table_name = 'applications' AND member_lid IN (" . implode(",", $remove_objects) . ");");
            }

        }
    }
    else {
        #Merge in the same VSYS
        $getDuplicated = $projectdb->query("SELECT id, name FROM applications $query GROUP BY BINARY name ;");

        if ($getDuplicated->num_rows > 0) {
            while ($dataD = $getDuplicated->fetch_assoc()) {
                $is_first = true;
                $error = 0;
                $remove_objects = array();
                $name = $dataD['name'];
                $id = $dataD['id'];

                add_log2('ok', 'Merging Duplicated Applications', 'Duplicated Applications [' . $name . '] merging', $source, 'No Action required', 'objects', $id, 'applications');

                // Check if exist selected merge as primary
                $getPrimary = $projectdb->query("SELECT id FROM applications $query AND BINARY name = '$name' AND merge_as_primary = '1' ;");
                if ($getPrimary->num_rows == 1) {
                    $dataP = $getPrimary->fetch_assoc();
                    $primary_member_lid = $dataP['id'];
                    $is_first = false;
                }
                elseif($getPrimary->num_rows > 1){
                    $error = 1;
                    // Error, hay más de un selected as primary para un conjunto de duplicated name, add log
                    add_log2('warning', 'Merging Duplicated Applications', 'Error when Duplicated Applications [' . $name . '] merging: two or more selected as primary.', $source, 'No Action required', 'objects', $id, 'applications');
                }

                if($error == 0){
                    $getDupsByName = $projectdb->query("SELECT id FROM applications $query AND BINARY name = '$name' AND merge_as_primary = '0';");

                    if ($getDupsByName->num_rows > 0) {
                        while ($dataDBN = $getDupsByName->fetch_assoc()) {
                            if ($is_first == true) {
                                $is_first = false;
                                $primary_member_lid = $dataDBN['id'];
                            }
                            else {
                                #UPDATE where other address are used
                                $member_lid = $dataDBN['id'];

                                updateMemberLid($projectName, $primary_member_lid, $member_lid, "applications");

                                $remove_objects[] = $member_lid;
                            }
                        }
                        cleanDuplicatedMembersMerging($primary_member_lid, "applications");

                        $projectdb->query("UPDATE applications set merge_as_primary = '0' WHERE id = '$primary_member_lid';");
                    }
                    if (count($remove_objects) > 0) {
                        $projectdb->query("DELETE FROM applications WHERE id IN (" . implode(",", $remove_objects) . ");");
                    }
                }
            }
        }
    }
    check_used_objects_new();
}


function setMergeByNameAppFilters(STRING $projectName, $selection, $vsys, $source){

    global $projectdb;
    global $app;

    $projectdb = selectDatabase($projectName);

    $user = $app->container->sentinel->getUser();
    $user_id = $user->id;

    take_snapshot_last($projectName);

    $query = generate_query("objects");

    if(count($selection) > 0) {
        $query = " WHERE id IN (".implode(",",$selection).") ";
    }
    else{
        $getResultsTools = $projectdb->query("SELECT member_lid FROM tools_results WHERE table_name = 'applications_filters' AND source = '$source' AND user_id = '$user_id';");

        if ($getResultsTools->num_rows > 0) {

            while ($dataRT = $getResultsTools->fetch_assoc()){
                if($dataRT['member_lid'] != ""){
                    $member_lid[] = $dataRT['member_lid'];
                }else{
                    $member_lid = array();
                }
            }
            if(count($member_lid) > 0){
                $query = " WHERE id IN (" . implode(",", $member_lid) . ") ";
            }
            else{
                $query = " WHERE id IN ('') ";
            }
        }
        else{
            $query = " WHERE id IN ('') ";
        }
    }

    if ($vsys == "all") {
        #Merge and move to Shared
        $getDuplicated = $projectdb->query("SELECT id as idx, name, id, devicegroup, vsys, source, category, subcategory, risk, technology, evasive_behavior, consume_big_bandwidth, used_by_malware, able_to_transfer_file, has_known_vulnerability, tunnel_other_application, prone_to_misuse,pervasive_use "
            . "FROM applications_filters $query GROUP BY BINARY name ;");

        if ($getDuplicated->num_rows > 0) {
            $remove_objects = array();
            $remove_shared_objects = array();
            while ($data = $getDuplicated->fetch_assoc()) {
                $is_first_shared = true;
                $id = $data['id'];
                $name = $data['name'];
                $devicegroup = $data['devicegroup'];
                $category = $data['category'];
                $subcategory = $data['subcategory'];
                $risk = $data['risk'];
                $technology = $data['technology'];
                $evasive_behavior = $data['evasive_behavior'];
                $consume_big_bandwidth = $data['consume_big_bandwidth'];
                $used_by_malware = $data['used_by_malware'];
                $able_to_transfer_file = $data['able_to_transfer_file'];
                $has_known_vulnerability = $data['has_known_vulnerability'];
                $tunnel_other_application = $data['tunnel_other_application'];
                $prone_to_misuse = $data['prone_to_misuse'];
                $pervasive_use = $data['pervasive_use'];

                $duplicate_shared_member_lid = array();

                #Check if exits in shared
                $getShared = $projectdb->query("SELECT id FROM applications_filters WHERE source = '$source' AND BINARY name = '$name' AND vsys = 'shared' AND dummy = 0;");
                if ($getShared->num_rows == 0) {
                    $data["id"] = "";
                    $projectdb->query("INSERT INTO applications_filters (name, devicegroup, category, subcategory, risk, technology, evasive_behavior, consume_big_bandwidth, used_by_malware, able_to_transfer_file, has_known_vulnerability, tunnel_other_application, prone_to_misuse, pervasive_use, vsys, source)  "
                        . " VALUES ('$name', '$devicegroup', '$category', '$subcategory', '$risk', '$technology', '$evasive_behavior', '$consume_big_bandwidth', '$used_by_malware', '$able_to_transfer_file', '$has_known_vulnerability', '$tunnel_other_application', '$prone_to_misuse', '$pervasive_use', 'shared', '$source');");

                    $shared_member_lid = $projectdb->insert_id;

                    add_log2('ok', 'Merging Duplicated Applications Filters', 'Duplicated Application Filters [' . $name . '] merging and moving into Shared', $source, 'No Action required', 'objects', $shared_member_lid, 'applications_filters');
                }
                elseif ($getShared->num_rows == 1) {
                    $data = $getShared->fetch_assoc();
                    $shared_member_lid = $data['id'];

                    add_log2('ok', 'Merging Duplicated Applications Filters', 'Duplicated Application Filters [' . $name . '] merging and moving into Shared', $source, 'No Action required', 'objects', $shared_member_lid, 'applications_filters');
                }
                else {
                    $error = 0;
                    # First merge in the shared space get the id from the first delete the others
                    add_log2('warning', 'Merging Duplicated Applications', 'The are duplicate objects in the shared: ' . $name . '', $source, 'Merge automatically in the shared.', 'objects', $id, 'applications_filters');

                    while ($data = $getShared->fetch_assoc()) {
                        $duplicate_shared_member_lid[] = $data['id'];
                    }

                    // Check if exist selected merge as primary
                    $getPrimaryShared = $projectdb->query("SELECT id FROM applications_filters WHERE id IN (".implode(",", $duplicate_shared_member_lid).") AND merge_as_primary = '1' ;");
                    if ($getPrimaryShared->num_rows == 1) {
                        $dataPS = $getPrimaryShared->fetch_assoc();
                        $primary_member_lid_shared = $dataPS['id'];
                        $is_first_shared = false;
                    }
                    elseif($getPrimaryShared->num_rows > 1){
                        $error = 1;
                        // Error, hay más de un selected as primary para un conjunto de duplicated name, add log
                        add_log2('warning', 'Merging Duplicated Applications Filters', 'Error when Duplicated Applications Filters [' . $name . '] merging: two or more selected as primary.', $source, 'No Action required', 'objects', $id, 'applications_filters');
                    }

                    if($error == 0) {
                        $getDupsInShared = $projectdb->query("SELECT id FROM applications_filters WHERE id IN (".implode(",", $duplicate_shared_member_lid).") AND merge_as_primary = '0';");
                        if ($getDupsInShared->num_rows > 0) {
                            while ($dataDIS = $getDupsInShared->fetch_assoc()) {
                                if ($is_first_shared == true) {
                                    $is_first_shared = false;
                                    $primary_member_lid_shared = $dataDIS['id'];
                                }
                                else {
                                    #UPDATE where other services are used
                                    $member_lid = $dataDIS['id'];

                                    updateMemberLid($projectName, $primary_member_lid_shared, $member_lid, "applications_filters");

                                    $remove_shared_objects[] = $member_lid;
                                }
                            }
                        }
                        if (count($remove_shared_objects) > 0) {
                            $projectdb->query("DELETE FROM applications_filters WHERE id IN (" . implode(",", $remove_shared_objects) . ");");
                        }
                        $shared_member_lid = $primary_member_lid_shared;
                        //finish merge in shared 2 or more services shared
                    }
                }

                $getDups = $projectdb->query("SELECT id FROM applications_filters $query AND source = '$source' AND BINARY name = '$name' AND vsys != 'shared' AND dummy = 0;");
                if ($getDups->num_rows > 0) {
                    while ($dataDups = $getDups->fetch_assoc()) {
                        $member_lid = $dataDups['id'];
                        #UPDATE where other address are used
                        $primary_member_lid = $shared_member_lid;

                        updateMemberLid($projectName, $primary_member_lid, $member_lid, "applications_filters");

                        $remove_objects[] = $member_lid;
                    }
                }
                cleanDuplicatedMembersMerging($primary_member_lid, "applications_filters");

                $projectdb->query("UPDATE applications_filters SET merge_as_primary = '0' WHERE id = '$primary_member_lid';");
            }
            if (count($remove_objects) > 0) {
                $projectdb->query("DELETE FROM applications_filters WHERE id IN (" . implode(",", $remove_objects) . ");");
            }

        }
    }
    else {
        #Merge in the same VSYS
        $getDuplicated = $projectdb->query("SELECT id, name FROM applications_filters $query GROUP BY BINARY name ;");

        if ($getDuplicated->num_rows > 0) {
            while ($dataD = $getDuplicated->fetch_assoc()) {
                $is_first = true;
                $error = 0;
                $remove_objects = array();
                $name = $dataD['name'];
                $id = $dataD['id'];

                add_log2('ok', 'Merging Duplicated Applications Filters', 'Duplicated Applications Filters [' . $name . '] merging', $source, 'No Action required', 'objects', $id, 'applications_filters');

                // Check if exist selected merge as primary
                $getPrimary = $projectdb->query("SELECT id FROM applications_filters $query AND BINARY name = '$name' AND merge_as_primary = '1' ;");
                if ($getPrimary->num_rows == 1) {
                    $dataP = $getPrimary->fetch_assoc();
                    $primary_member_lid = $dataP['id'];
                    $is_first = false;
                }
                elseif($getPrimary->num_rows > 1){
                    $error = 1;
                    // Error, hay más de un selected as primary para un conjunto de duplicated name, add log
                    add_log2('warning', 'Merging Duplicated Applications Filters', 'Error when Duplicated Applications Filters [' . $name . '] merging: two or more selected as primary.', $source, 'No Action required', 'objects', $id, 'applications_filters');
                }

                if($error == 0){
                    $getDupsByName = $projectdb->query("SELECT id FROM applications_filters $query AND BINARY name = '$name' AND merge_as_primary = '0';");

                    if ($getDupsByName->num_rows > 0) {
                        while ($dataDBN = $getDupsByName->fetch_assoc()) {
                            if ($is_first == true) {
                                $is_first = false;
                                $primary_member_lid = $dataDBN['id'];
                            }
                            else {
                                #UPDATE where other address are used
                                $member_lid = $dataDBN['id'];

                                updateMemberLid($projectName, $primary_member_lid, $member_lid, "applications_filters");

                                $remove_objects[] = $member_lid;
                            }
                        }
                        cleanDuplicatedMembersMerging($primary_member_lid, "applications_filters");

                        $projectdb->query("UPDATE applications_filters set merge_as_primary = '0' WHERE id = '$primary_member_lid';");
                    }
                    if (count($remove_objects) > 0) {
                        $projectdb->query("DELETE FROM applications_filters WHERE id IN (" . implode(",", $remove_objects) . ");");
                    }
                }
            }
        }
    }
    check_used_objects_new();
}


function setObjectsToGroup(STRING $projectName, ARRAY $params){

    global $projectdb;
    $projectdb = selectDatabase($projectName);

    take_snapshot_last($projectName);

    $group = $params['group'];
    $members = $params['members'];
    $members_groups = $params['members_groups'];
    $members_filters = $params['members_filters'];
    $vsys = $params['vsys'];
    $source = $params['source'];

    if ($group != ""){

        $groups = explode(";", $group);
        $lid = $groups[0];
        $table_name_group = $groups[1];

        if (count($members) > 0){

            $data = explode(",", $members);

            foreach ($data as $key => $value) {

                $values = explode(";", $value);
                $member_lid = $values[0];
                $table_name = $values[1];
                $getExist = $projectdb->query("SELECT id FROM $table_name_group WHERE lid = '$lid' AND member_lid = '$member_lid' AND table_name = '$table_name' ;");
                if($getExist->num_rows == 0){
                    $projectdb->query("INSERT INTO $table_name_group (id, vsys, member_lid, table_name, lid, source) VALUES (NULL, '$vsys', '$member_lid', '$table_name', '$lid', '$source');");
                }
            }
        }

        if (count($members_filters) > 0){

            $data = explode(",", $members_filters);

            foreach ($data as $key => $value) {

                $values = explode(";", $value);
                $member_lid = $values[0];
                $table_name = $values[1];
                $getExist = $projectdb->query("SELECT id FROM $table_name_group WHERE lid = '$lid' AND member_lid = '$member_lid' AND table_name = '$table_name' ;");
                if($getExist->num_rows == 0){
                    $projectdb->query("INSERT INTO $table_name_group (id, vsys, member_lid, table_name, lid, source) VALUES (NULL, '$vsys', '$member_lid', '$table_name', '$lid', '$source');");
                }
            }
        }

        if (count($members_groups) > 0){
            $data = explode(",", $members_groups);

            foreach ($data as $key => $value) {

                $values = explode(";", $value);
                $member_lid = $values[0];
                $table_name = $values[1];

                // controlar que no se pueda añadir el mismo grupo a modificar
                if(($member_lid == $lid) && ($table_name == $table_name_group)){
                }
                else{
                    if($table_name == "address_groups"){$table_name = "address_groups_id";
                    }elseif($table_name == "services_groups"){$table_name = "services_groups_id";
                    }elseif($table_name == "applications_groups"){$table_name = "applications_groups_id";}

                    $getExist = $projectdb->query("SELECT id FROM $table_name_group WHERE lid = '$lid' AND member_lid = '$member_lid' AND table_name = '$table_name' ;");
                    if($getExist->num_rows == 0){
                        $projectdb->query("INSERT INTO $table_name_group (id, vsys, member_lid, table_name, lid, source) VALUES (NULL, '$vsys', '$member_lid', '$table_name', '$lid', '$source');");
                    }
                }
            }
        }
    }

    $message['code']=true;
    return $message;

}


function setProtocol(STRING $projectName, ARRAY $params){

    global $projectdb;
    $projectdb = selectDatabase($projectName);

    take_snapshot_last($projectName);

    $members = $params['members'];
    $protocol = $params['protocol'];

    # Set Protocol to selected Services From context-menu
    if (($members!="") AND (($protocol=="udp") OR ($protocol=="tcp") OR ($protocol=="sctp"))){
        $projectdb->query("UPDATE services SET protocol='$protocol' WHERE id IN ($members);");
    }

    $message['code']=true;
    return $message;

}


function setMembersToGroup(STRING $projectName, ARRAY $params){

    global $projectdb;
    $projectdb = selectDatabase($projectName);

    take_snapshot_last($projectName);

    $group = $params['group'];
    $members_groups = $params['members_groups'];
    $table_name_id = $params['table_name_id'];
    $vsys = $params['vsys'];
    $source = $params['source'];

    if ($group != ""){

        // Si no tiene ";" --> crear new group
        if(strpos($group, ";") === false){

            $projectdb->query("INSERT INTO $table_name_id (name_ext, name, used, devicegroup, vsys, type, filter, description, source, tag)  
                        VALUES ('$group', '$group', '', '', '$vsys', 'static', '', '', '$source', '');");

            $lid = $projectdb->insert_id;
            $table_name_group = str_replace("_id", "", $table_name_id);
        }
        else{
            $groups = explode(";", $group);
            $lid = $groups[0];
            $table_name_group = $groups[1];
        }

        if (count($members_groups) > 0){

            $data = explode(",", $members_groups);

            foreach ($data as $key => $value) {

                $values = explode(";", $value);
                $member_lid = $values[0];
                $table_name = $values[1];

                $getMembers = $projectdb->query("SELECT member_lid, table_name FROM $table_name WHERE lid = '$member_lid' ;");
                if($getMembers->num_rows > 0){
                    while ($dataM = $getMembers->fetch_assoc()){
                        $member_lid_member = $dataM['member_lid'];
                        $table_name_member = $dataM['table_name'];

                        $getExist = $projectdb->query("SELECT id FROM $table_name_group WHERE lid = '$lid' AND member_lid = '$member_lid_member' AND table_name = '$table_name_member' ;");
                        if($getExist->num_rows == 0){
                            if(($member_lid_member == $lid) && ($table_name_member == $table_name_id)) {
                            }else{
                                $projectdb->query("INSERT INTO $table_name_group (id, vsys, member_lid, table_name, lid, source) 
                                              VALUES (NULL, '$vsys', '$member_lid_member', '$table_name_member', '$lid', '$source');");
                            }
                        }
                    }
                    clean_duplicated_members($table_name_group);
                }
            }
        }
    }

    $message['code']=true;
    return $message;
}


function setReplaceByGroup(STRING $projectName, ARRAY $params){

    global $projectdb;
    $projectdb = selectDatabase($projectName);

    take_snapshot_last($projectName);

    $group = $params['group'];
    $members_groups = $params['members_groups'];
    $vsys = $params['vsys'];
    $source = $params['source'];

    $all_names_for_replace = array();

    if ($group != ""){

        $groups = explode(";", $group);
        $lid = $groups[0];

        if (count($members_groups) > 0){

            $data = explode(",", $members_groups);

            foreach ($data as $key => $value) {

                $values = explode(";", $value);
                $member_lid = $values[0];
                $table_name = $values[1];
                $groupname = $values[2];

                $all_names_for_replace[] = $groupname;

                replaceMemberLid($projectName, $lid, $member_lid, $table_name);
                cleanDuplicatedMembersMerging($lid, $table_name);

                //if($table_name == "address_groups_id"){
                //    replaceAddressGroupsInOtherRulesZones($projectName, $lid, $all_names_for_replace, $source);
                //}elseif($table_name == "services_groups_id"){
                //    replaceServicesGroupsInOtherRules($projectName, $lid, $all_names_for_replace, $source);
                //}
            }
        }
    }

    $message['code']=true;
    return $message;
}


function setMergeGroupsCommon(STRING $projectName, $mylids, $source, $table, $table_name_id){

    global $projectdb;
    $projectdb = selectDatabase($projectName);

    if (count($mylids) > 0){

        $mylids_unique = array_unique($mylids);

        foreach ($mylids_unique as $key => $value) {

            $mydata = explode(";",$value);
            $table_name_final = $mydata[1];
            $lid_final = $mydata[0];
            $vsys = $mydata[3];

            if ($vsys == "all"){$vsys = "shared";}

            if($vsys == "shared"){

                if($table == "applications"){
                    $getAllmembers = $projectdb->query("SELECT member_lid, table_name, member FROM $table_name_final WHERE lid = '$lid_final' "
                        . "AND (table_name = '$table' OR table_name = '$table_name_id' OR table_name = 'applications_filters');");
                }else{
                    $getAllmembers = $projectdb->query("SELECT member_lid, table_name, member FROM $table_name_final WHERE lid = '$lid_final' "
                        . "AND (table_name = '$table' OR table_name = '$table_name_id');");
                }

                if ($getAllmembers->num_rows > 0) {
                    $members_objects = array();
                    $members_objectsgroups = array();
                    $members_objectsfilters = array();

                    while ($data = $getAllmembers->fetch_assoc()) {
                        $table_name_sql = $data['table_name'];
                        $member_lid_sql = $data['member_lid'];

                        if ($table_name_sql == $table_name_id) {
                            $members_objectsgroups[] = $member_lid_sql;
                        }
                        elseif ($table_name_sql == $table) {
                            $members_objects[] = $member_lid_sql;
                        }
                        elseif ($table_name_sql == "applications_filters") {
                            $members_objectsfilters[] = $member_lid_sql;
                        }
                    }
                    if($table == "address"){
                        if(count($members_objectsgroups)>0) {
                            convertAddressGroupsToShared($source, $members_objectsgroups, "notall");
                        }
                        if(count($members_objects)>0) {
                            convertAddressToShared($source, $members_objects, "notall");
                        }

                    }
                    elseif($table == "services"){
                        if(count($members_objectsgroups)>0) {
                            convertServicesGroupsToShared($source, $members_objectsgroups, "notall");
                        }
                        if(count($members_objects)>0) {
                            convertServicesToShared($source, $members_objects, "notall");
                        }

                    }
                    elseif($table == "applications"){
                        if(count($members_objectsgroups)>0) {
                            convertApplicationsGroupsToShared($source, $members_objectsgroups, "notall");
                        }
                        if(count($members_objects)>0) {
                            convertApplicationsToShared($source, $members_objects, "notall");
                        }
                        if(count($members_objectsfilters)>0) {
                            convertApplicationsFiltersToShared($source, $members_objectsfilters, "notall");
                        }
                    }
                }
            }

            // Limpieza members repetidos
            $ids = array();
            $getMem = $projectdb->query("SELECT id FROM $table_name_final WHERE lid = '$lid_final' GROUP BY member_lid, table_name;");
            if ($getMem->num_rows > 0) {
                while ($getMemdata = $getMem->fetch_assoc()) {
                    $ids[] = $getMemdata['id'];
                }
                $projectdb->query("DELETE FROM $table_name_final WHERE lid = '$lid_final' AND id NOT IN (" . implode(",", $ids) . ");");
            }
        }
        //check_used_objects_new(); // MT-2451 - Removed due to performance issues, instead flag used is updated over the primary object
    }
}


function setReverseDNS($project, $params){
    global $projectdb;
    global $app;

    $user=$params['user'];

    $projectdb = selectDatabase($project);
    $vsys=$params['vsys'];
    $source=$params['source'];

    $Data=array();

    $message = [
        'code'  => false,
        'jobid' => -1,
        'msg'   => 'No address to Resolve'
    ];

    $getAddressIds = $projectdb->query("SELECT member_lid FROM tools_results WHERE table_name='address';");
    if ($getAddressIds->num_rows>0){
        $ids=array();
        while($getAddressIdsData = $getAddressIds->fetch_assoc()){
            $ids[]=$getAddressIdsData['member_lid'];
        }
        if (count($ids)>0){
            $getToolsRename=$projectdb->query("SELECT lid FROM tools_rename WHERE source='$source' AND reverse!='';");
            if ($getToolsRename->num_rows>0){
                $idsAlready=array();
                while($getToolsRenameData = $getToolsRename->fetch_assoc()){
                    $idsAlready[]=$getToolsRenameData['lid'];
                }
                $ids=array_values(array_diff($ids,$idsAlready));
            }

            if (count($ids)>0){
                $projectdb->query("DELETE FROM tools_rename WHERE lid IN (".implode(",",$ids).");");
                $data_individual = [
                    'mode'      => $params['mode'],
                    'project'   => $project,
                    'source'    => $params['source'],
                    'ids'       => $ids
                ];
                $jobID = registerJob($data_individual, $user, 'Tools. DNS Resolver');
                $taskID = registerTask($data_individual, $user, $jobID, "Rename", "Request DNS Resolver");
                send_APICallMessage($data_individual, $user, $taskID, "Rename");
                $message = [
                    'code'  => true,
                    'jobid' => $jobID,
                    'msg'   => 'DNS Resolver Job registered correctly'
                ];
            }
        }
    }

    return $message;
}


function getReverseDNS($project, $params){
    global $projectdb;
    global $app;
    $user=$app->sentinel->getUser()->id;
    $projectdb = selectDatabase($project);
    $vsys=$params['vsys'];
    $source=$params['source'];
    $Data=array();
    $getAddressIds = $projectdb->query("SELECT *, INET_ATON(ipaddress) as ipaddressLong FROM tools_rename WHERE source='$source';");
    if ($getAddressIds->num_rows>0){
        while($getAddressIdsData = $getAddressIds->fetch_assoc()){
            $Data[]=$getAddressIdsData;
        }
    }

    $message = array();
    $message['code'] = true;
    $message['count'] = count($Data);
    $message['msg'] = $Data;

    return $message;
}


function applyFormatReverse($project, $params, $mode){

    global $projectdb;
    global $app;
    $user=$app->sentinel->getUser()->id;
    $projectdb = selectDatabase($project);

    if ($params['ids']!=""){
        $getRows=$projectdb->query("SELECT * FROM tools_rename WHERE id IN(".$params['ids'].") AND user='$user';");
    }
    else{
        $getRows=$projectdb->query("SELECT * FROM tools_rename WHERE user='$user';");
    }

    if ($getRows->num_rows>0){
        $executed=array();
        while($getRowsData=$getRows->fetch_assoc()){
            $lid=$getRowsData['lid'];
            $table_name=$getRowsData['table_name'];
            $reverse=$getRowsData['reverse'];
            $ipaddress=$getRowsData['ipaddress'];
            $name=$getRowsData['name'];
            switch($mode){
                case "applyReverse":
                    if (($reverse!="") AND ($reverse!=$name)){
                        $executed[]=$lid;
                        $newName=truncate_names($reverse);
                        $projectdb->query("UPDATE $table_name SET name='$newName', dummy='0', type='ip-netmask' WHERE id='$lid';");
                    }
                    break;
                case "applyReverseIP":
                    if ( (filter_var($ipaddress, FILTER_VALIDATE_IP)) AND ($reverse!="")){
                        $executed[]=$lid;
                        $newName=truncate_names($reverse."_".$ipaddress);
                        $projectdb->query("UPDATE $table_name SET name='$newName', dummy='0', type='ip-netmask' WHERE id='$lid';");
                    }
                    break;
                case "applyH_IP":
                    $executed[]=$lid;
                    $newName=truncate_names("H-".$ipaddress);
                    $projectdb->query("UPDATE $table_name SET name='$newName', dummy='0' WHERE id='$lid';");
                    break;
                case "applyFQDN":
                    if (($reverse!="") AND ($reverse!=$name)){
                        $executed[]=$lid;
                        $newName=truncate_names($reverse);
                        $projectdb->query("UPDATE $table_name SET name='$newName', ipaddress='$newName', type='fqdn', dummy='0' WHERE id='$lid';");
                    }

                break;
            }

        }
    }

    # Remove Objects from View
    $projectdb->query("DELETE FROM tools_rename WHERE lid IN (".implode(",",$executed).") AND user='$user';");

    $message = array();
    $message['code'] = true;

    return $message;

}


function transformObjectsToIPaddress(STRING $projectName, ARRAY $params){

    global $projectdb;
    global $app;

    $projectdb = selectDatabase($projectName);

    $user = $app->container->sentinel->getUser();
    $user_id = $user->id;

    $selection = $params['selection'];
    $source = $params['source'];

    take_snapshot_last($projectName);

    $query = generate_query("objects");

    if(count($selection) > 0) {
        $query = " WHERE type IN ('ip-netmask', 'ip-range') AND id IN ($selection) ";
    }
    else{
        $getResultsTools = $projectdb->query("SELECT member_lid FROM tools_results WHERE table_name = 'address' AND source = '$source' AND user_id = '$user_id';");

        if ($getResultsTools->num_rows > 0) {

            while ($dataRT = $getResultsTools->fetch_assoc()){
                if($dataRT['member_lid'] != ""){
                    $member_lid[] = $dataRT['member_lid'];
                }else{
                    $member_lid = array();
                }
            }
            if(count($member_lid) > 0){
                $query = " WHERE type IN ('ip-netmask', 'ip-range') AND id IN (" . implode(",", $member_lid) . ") ";
            }
            else{
                $query = " WHERE type IN ('ip-netmask', 'ip-range') AND id IN ('') ";
            }
        }
        else{
            $query = " WHERE type IN ('ip-netmask', 'ip-range') AND id IN ('') ";
        }
    }

    $getAddress = $projectdb->query("SELECT id, name, ipaddress, cidr, type FROM address $query;");

    if ($getAddress->num_rows > 0) {
        while ($dataA = $getAddress->fetch_assoc()) {

            $id = $dataA['id'];
            $name = $dataA['name'];
            $ipaddress = $dataA['ipaddress'];
            $cidr = $dataA['cidr'];

            if(($cidr == "32") || ($cidr == "")) {
                $new_name = $ipaddress;
            }else{
                $new_name = $ipaddress."/".$cidr;
            }

            $projectdb->query("UPDATE address SET name = '$new_name', dummy = '1' WHERE id = '$id';");

        }
    }

    $message['code']=true;
    return $message;
}


function transformIPaddressToObjects(STRING $projectName, ARRAY $params){
    global $projectdb;
    global $app;

    $projectdb = selectDatabase($projectName);

    $user = $app->container->sentinel->getUser();
    $user_id = $user->id;

    $selection = $params['selection'];
    $source = $params['source'];

    take_snapshot_last($projectName);

    $query = generate_query("objects");

    if(count($selection) > 0) {
        $query = " WHERE type IN ('ip-netmask', 'ip-range') AND id IN ($selection) ";
    }
    else{
        $getResultsTools = $projectdb->query("SELECT member_lid FROM tools_results WHERE table_name = 'address' AND source = '$source' AND user_id = '$user_id';");

        if ($getResultsTools->num_rows > 0) {

            while ($dataRT = $getResultsTools->fetch_assoc()){
                if($dataRT['member_lid'] != ""){
                    $member_lid[] = $dataRT['member_lid'];
                }else{
                    $member_lid = array();
                }
            }
            if(count($member_lid) > 0){
                $query = " WHERE type IN ('ip-netmask', 'ip-range') AND id IN (" . implode(",", $member_lid) . ") ";
            }
            else{
                $query = " WHERE type IN ('ip-netmask', 'ip-range') AND id IN ('') ";
            }
        }
        else{
            $query = " WHERE type IN ('ip-netmask', 'ip-range') AND id IN ('') ";
        }
    }

    $getAddress = $projectdb->query("SELECT id, name, ipaddress, cidr, type FROM address $query;");

    if ($getAddress->num_rows > 0) {
        while ($dataA = $getAddress->fetch_assoc()) {
            $id = $dataA['id'];
            $name = $dataA['name'];
            $newName = str_replace('/', '-', $name);
            $projectdb->query("UPDATE address SET dummy = '0', name = '$newName' WHERE id = '$id';");
        }
    }

    $message['code']=true;
    return $message;
}