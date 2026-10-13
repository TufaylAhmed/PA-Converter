<?php

# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.

require_once INC_ROOT.'/libs/shared.php';

if(defined('CLI')){
    require_once INC_ROOT .'/userManager/API/accessControl_CLI.php';
}
else{
    require_once INC_ROOT .'/userManager/API/accessControl.php';
    require_once INC_ROOT.'/bin/authentication/sessionControl.php';
}

require_once INC_ROOT.'/libs/common/lib-objects.php';
require_once INC_ROOT.'/libs/common/lib-rules.php';

use \PaloAltoNetworks\Expedition\Tools\Merger\AddressMerger;
use \PaloAltoNetworks\Expedition\Tools\Merger\ServicesMerger;
use \PaloAltoNetworks\Expedition\Tools\Merger\RegionsMerger;
use \PaloAltoNetworks\Expedition\Tools\Merger\ApplicationsMerger;


function getFoundInSecurity(STRING $projectName, ARRAY $params){

    global $projectdb;
    $projectdb = selectDatabase($projectName);

    $selection = $params['selection'];
    $source = $params['source'];
    $vsys = $params['vsys'];

    $myData = array();

    if(count($selection) != 0){

        $data = explode(",", $selection);

        foreach ($data as $key => $value) {

            $values = explode(";", $value);
            $lid = $values[0];
            $table_name = $values[1];
            $name = $values[2];

            require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
            $add_vsys = prepareVsysQuerySearch($projectdb, $vsys, $source, "security_rules");

            if ((preg_match("/address/i", $table_name)) || (preg_match("/regions/i", $table_name)) || (preg_match("/list/i", $table_name))) {

                $image = getImageNew("address", $table_name, $lid, $vsys);

                // Source
                $getSecurityByAddressSrc = $projectdb->query("SELECT sr.name, sr.id AS lid, 'security_rules' AS table_name_lid, sr.vsys, 'Source' AS position, srs.member_lid, srs.table_name "
                    . " FROM security_rules sr, security_rules_src srs "
                    . " WHERE sr.source = '$source' $add_vsys AND srs.member_lid = '$lid' AND srs.table_name = '$table_name' "
                    . " AND srs.rule_lid = sr.id;");

                if ($getSecurityByAddressSrc->num_rows > 0) {
                    while ($data = $getSecurityByAddressSrc->fetch_assoc()) {
                        $data['name_object_search'] = "<img style='vertical-align: middle;' src=/resources/images/rules/$image> " .$name;
                        $data['name_object'] = $name;
                        $myData[] = $data;
                    }
                }

                // Destination
                $getSecurityByAddressDst = $projectdb->query("SELECT sr.name, sr.id AS lid, 'security_rules' AS table_name_lid, sr.vsys, 'Destination' AS position, dst.member_lid, dst.table_name "
                    . " FROM security_rules sr, security_rules_dst dst "
                    . " WHERE sr.source = '$source' $add_vsys AND dst.member_lid = '$lid' AND dst.table_name = '$table_name' "
                    . " AND dst.rule_lid = sr.id;");

                if ($getSecurityByAddressDst->num_rows > 0) {
                    while ($data = $getSecurityByAddressDst->fetch_assoc()) {
                        $data['name_object_search'] = "<img style='vertical-align: middle;' src=/resources/images/rules/$image> " .$name;
                        $data['name_object'] = $name;
                        $myData[] = $data;
                    }
                }
            }
            elseif ((preg_match("/services/i", $table_name))) {

                $image = getImageNew("services", $table_name, $lid, $vsys);

                $getSecurityByServices = $projectdb->query("SELECT sr.name, sr.id AS lid, 'security_rules' AS table_name_lid, sr.vsys, 'Service' AS position, srv.member_lid, srv.table_name "
                    . " FROM security_rules sr, security_rules_srv srv "
                    . " WHERE sr.source = '$source' $add_vsys AND srv.member_lid = '$lid' AND srv.table_name = '$table_name' "
                    . " AND srv.rule_lid = sr.id;");

                if ($getSecurityByServices->num_rows > 0) {
                    while ($data = $getSecurityByServices->fetch_assoc()) {
                        $data['name_object_search'] = "<img style='vertical-align: middle;' src=/resources/images/rules/$image> " .$name;
                        $data['name_object'] = $name;
                        $myData[] = $data;
                    }
                }
            }
            elseif ((preg_match("/applications/i", $table_name)) || ($table_name == "default_applications")) {

                $image = getImageNew("applications", $table_name, $lid, $vsys);

                if($table_name != "default_applications"){

                    $getSecurityByApplications = $projectdb->query("SELECT sr.name, sr.id AS lid, 'security_rules' AS table_name_lid, sr.vsys, 'Application' AS position, app.member_lid, app.table_name "
                        . " FROM security_rules sr, security_rules_app app "
                        . " WHERE sr.source = '$source' $add_vsys AND app.member_lid = '$lid' AND app.table_name = '$table_name' "
                        . " AND app.rule_lid = sr.id;");
                }
                elseif ($table_name == "default_applications"){

                    $getSecurityByApplications = $projectdb->query("SELECT sr.name, sr.id AS lid, 'security_rules' AS table_name_lid, sr.vsys, 'Application' AS position, app.member_lid, app.table_name "
                        . " FROM security_rules sr, security_rules_app app "
                        . " WHERE sr.source = '$source' AND app.member_lid = '$lid' AND app.table_name = '$table_name' "
                        . " AND app.rule_lid = sr.id;");
                }

                if ($getSecurityByApplications->num_rows > 0) {
                    while ($data = $getSecurityByApplications->fetch_assoc()) {
                        $data['name_object_search'] = "<img style='vertical-align: middle;' src=/resources/images/rules/$image> " .$name;
                        $data['name_object'] = $name;
                        $myData[] = $data;
                    }
                }
            }
            elseif($table_name == "zones"){

                // From
                $getSecurityByZonesFrom = $projectdb->query("SELECT sr.name, sr.id AS lid, 'security_rules' AS table_name_lid, sr.vsys, 'From' AS position, 'zones' AS table_name "
                    . " FROM security_rules sr, security_rules_from from_sec "
                    . " WHERE sr.source = '$source' $add_vsys AND from_sec.name = '$name' "
                    . " AND from_sec.rule_lid = sr.id;");

                if ($getSecurityByZonesFrom->num_rows > 0) {
                    while ($data = $getSecurityByZonesFrom->fetch_assoc()) {
                        $data['name_object_search'] = "<img style='vertical-align: middle;' src=/resources/images/rules/zone.gif> " .$name;
                        $data['name_object'] = $name;
                        $myData[] = $data;
                    }
                }

                // To
                $getSecurityByZonesTo = $projectdb->query("SELECT sr.name, sr.id AS lid, 'security_rules' AS table_name_lid, sr.vsys, 'To' AS position, 'zones' AS table_name "
                    . " FROM security_rules sr, security_rules_to to_sec "
                    . " WHERE sr.source = '$source' $add_vsys AND to_sec.name = '$name' "
                    . " AND to_sec.rule_lid = sr.id;");

                if ($getSecurityByZonesTo->num_rows > 0) {
                    while ($data = $getSecurityByZonesTo->fetch_assoc()) {
                        $data['name_object_search'] = "<img style='vertical-align: middle;' src=/resources/images/rules/zone.gif> " .$name;
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


function getFoundInNat(STRING $projectName, ARRAY $params)
{
    global $projectdb;
    $projectdb = selectDatabase($projectName);

    $selection = $params['selection'];
    $source = $params['source'];
    $vsys = $params['vsys'];

    $myData = array();

    if(count($selection) != 0){

        $data = explode(",", $selection);

        foreach ($data as $key => $value) {

            $values = explode(";", $value);
            $lid = $values[0];
            $table_name = $values[1];
            $name = $values[2];


            require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
            $add_vsys = prepareVsysQuerySearch($projectdb, $vsys, $source, "nat_rules");

            if (preg_match("/address/i", $table_name)) {

                $image = getImageNew("address", $table_name, $lid, $vsys);

                // Source
                $getNatByAddressSrc = $projectdb->query("SELECT nr.name, nr.id AS lid, 'nat_rules' AS table_name_lid, nr.vsys, 'Source' AS position, nrs.member_lid, nrs.table_name "
                    . " FROM nat_rules nr, nat_rules_src nrs "
                    . " WHERE nr.source = '$source' $add_vsys AND nrs.member_lid = '$lid' AND nrs.table_name = '$table_name' "
                    . " AND nrs.rule_lid = nr.id;");

                if ($getNatByAddressSrc->num_rows > 0) {
                    while ($data = $getNatByAddressSrc->fetch_assoc()) {
                        $data['name_object_search'] = "<img style='vertical-align: middle;' src=/resources/images/rules/$image> " .$name;
                        $data['name_object'] = $name;
                        $myData[] = $data;
                    }
                }

                // Destination
                $getNatByAddressDst = $projectdb->query("SELECT nr.name, nr.id AS lid, 'nat_rules' AS table_name_lid, nr.vsys, 'Destination' AS position, dst.member_lid, dst.table_name "
                    . " FROM nat_rules nr, nat_rules_dst dst "
                    . " WHERE nr.source = '$source' $add_vsys AND dst.member_lid = '$lid' AND dst.table_name = '$table_name' "
                    . " AND dst.rule_lid = nr.id;");

                if ($getNatByAddressDst->num_rows > 0) {
                    while ($data = $getNatByAddressDst->fetch_assoc()) {
                        $data['name_object_search'] = "<img style='vertical-align: middle;' src=/resources/images/rules/$image> " .$name;
                        $data['name_object'] = $name;
                        $myData[] = $data;
                    }
                }

                // Translated Address
                $getNatByAddressDst = $projectdb->query("SELECT nr.name, nr.id AS lid, 'nat_rules' AS table_name_lid, nr.vsys, 'Translated Address' AS position, dst.member_lid, dst.table_name "
                    . " FROM nat_rules nr, nat_rules_translated_address dst "
                    . " WHERE nr.source = '$source' $add_vsys AND dst.member_lid = '$lid' AND dst.table_name = '$table_name' "
                    . " AND dst.rule_lid = nr.id;");

                if ($getNatByAddressDst->num_rows > 0) {
                    while ($data = $getNatByAddressDst->fetch_assoc()) {
                        $data['name_object_search'] = "<img style='vertical-align: middle;' src=/resources/images/rules/$image> " .$name;
                        $data['name_object'] = $name;
                        $myData[] = $data;
                    }
                }

                // Translated Address Fallback
                $getNatByAddressDst = $projectdb->query("SELECT nr.name, nr.id AS lid, 'nat_rules' AS table_name_lid, nr.vsys, 'Translated Address Fallback' AS position, dst.member_lid, dst.table_name "
                    . " FROM nat_rules nr, nat_rules_translated_address_fallback dst "
                    . " WHERE nr.source = '$source' $add_vsys AND dst.member_lid = '$lid' AND dst.table_name = '$table_name' "
                    . " AND dst.rule_lid = nr.id;");

                if ($getNatByAddressDst->num_rows > 0) {
                    while ($data = $getNatByAddressDst->fetch_assoc()) {
                        $data['name_object_search'] = "<img style='vertical-align: middle;' src=/resources/images/rules/$image> " .$name;
                        $data['name_object'] = $name;
                        $myData[] = $data;
                    }
                }

                // Destination Address Translation
                $getNatByAddressDstT = $projectdb->query("SELECT nr.name, nr.id AS lid, 'nat_rules' AS table_name_lid, nr.vsys, 'Destination Address Translation' AS position, nr.tp_dat_address_lid AS member_lid, nr.tp_dat_address_table AS table_name "
                    . " FROM nat_rules nr "
                    . " WHERE nr.source = '$source' $add_vsys AND nr.tp_dat_address_lid = '$lid' AND nr.tp_dat_address_table = '$table_name' ;");

                if ($getNatByAddressDstT->num_rows > 0) {
                    while ($data = $getNatByAddressDstT->fetch_assoc()) {
                        $data['name_object_search'] = "<img style='vertical-align: middle;' src=/resources/images/rules/$image> " .$name;
                        $data['name_object'] = $name;
                        $myData[] = $data;
                    }
                }

            }
            elseif ((preg_match("/services/i", $table_name))) {

                $image = getImageNew("services", $table_name, $lid, $vsys);

                // Services
                $getNatByServices = $projectdb->query("SELECT nr.name, nr.id AS lid, 'nat_rules' AS table_name_lid, nr.vsys, 'Service' AS position, nr.op_service_lid AS member_lid, nr.op_service_table AS table_name "
                    . " FROM nat_rules nr "
                    . " WHERE nr.source = '$source' $add_vsys AND nr.op_service_lid = '$lid' AND nr.op_service_table = '$table_name'; ");

                if ($getNatByServices->num_rows > 0) {
                    while ($data = $getNatByServices->fetch_assoc()) {
                        $data['name_object_search'] = "<img style='vertical-align: middle;' src=/resources/images/rules/$image> " .$name;
                        $data['name_object'] = $name;
                        $myData[] = $data;
                    }
                }
            }
            elseif($table_name == "zones"){

                // From
                $getNatByZonesFrom = $projectdb->query("SELECT nr.name, nr.id AS lid, 'nat_rules' AS table_name_lid, nr.vsys, 'From' AS position, 'zones' AS table_name "
                    . " FROM nat_rules nr, nat_rules_from from_nat "
                    . " WHERE nr.source = '$source' $add_vsys AND from_nat.name = '$name' "
                    . " AND from_nat.rule_lid = nr.id;");

                if ($getNatByZonesFrom->num_rows > 0) {
                    while ($data = $getNatByZonesFrom->fetch_assoc()) {
                        $data['name_object_search'] = "<img style='vertical-align: middle;' src=/resources/images/rules/zone.gif> " .$name;
                        $data['name_object'] = $name;
                        $myData[] = $data;
                    }
                }

                // To
                $getNatByZonesTo = $projectdb->query("SELECT nr.name, nr.id AS lid, 'nat_rules' AS table_name_lid, nr.vsys, 'To' AS position, 'zones' AS table_name "
                    . " FROM nat_rules nr "
                    . " WHERE nr.source = '$source' $add_vsys AND nr.op_zone_to = '$name'; ");

                if ($getNatByZonesTo->num_rows > 0) {
                    while ($data = $getNatByZonesTo->fetch_assoc()) {
                        $data['name_object_search'] = "<img style='vertical-align: middle;' src=/resources/images/rules/zone.gif> " .$name;
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


function getFoundInAppOverride(STRING $projectName, ARRAY $params)
{

    global $projectdb;
    $projectdb = selectDatabase($projectName);

    $selection = $params['selection'];
    $source = $params['source'];
    $vsys = $params['vsys'];

    $myData = array();

    if(count($selection) != 0){

        $data = explode(",", $selection);

        foreach ($data as $key => $value) {

            $values = explode(";", $value);
            $lid = $values[0];
            $table_name = $values[1];
            $name = $values[2];

            require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
            $add_vsys = prepareVsysQuerySearch($projectdb, $vsys, $source, "appoverride_rules");

            if (preg_match("/address/i", $table_name)) {

                $image = getImageNew("address", $table_name, $lid, $vsys);

                // Source
                $getAppoverrideByAddressSrc = $projectdb->query("SELECT ar.name, ar.id AS lid, 'appoverride_rules' AS table_name_lid, ar.vsys, 'Source' AS position, ars.member_lid, ars.table_name "
                    . " FROM appoverride_rules ar, appoverride_rules_src ars "
                    . " WHERE ar.source = '$source' $add_vsys AND ars.member_lid = '$lid' AND ars.table_name = '$table_name' "
                    . " AND ars.rule_lid = ar.id;");

                if ($getAppoverrideByAddressSrc->num_rows > 0) {
                    while ($data = $getAppoverrideByAddressSrc->fetch_assoc()) {
                        $data['name_object_search'] = "<img style='vertical-align: middle;' src=/resources/images/rules/$image> " .$name;
                        $data['name_object'] = $name;
                        $myData[] = $data;
                    }
                }

                // Destination
                $getAppoverrideByAddressDst = $projectdb->query("SELECT ar.name, ar.id AS lid, 'appoverride_rules' AS table_name_lid, ar.vsys, 'Destination' AS position, ast.member_lid, ast.table_name "
                    . " FROM appoverride_rules ar, appoverride_rules_dst ast "
                    . " WHERE ar.source = '$source' $add_vsys AND ast.member_lid = '$lid' AND ast.table_name = '$table_name' "
                    . " AND ast.rule_lid = ar.id;");

                if ($getAppoverrideByAddressDst->num_rows > 0) {
                    while ($data = $getAppoverrideByAddressDst->fetch_assoc()) {
                        $data['name_object_search'] = "<img style='vertical-align: middle;' src=/resources/images/rules/$image> " .$name;
                        $data['name_object'] = $name;
                        $myData[] = $data;
                    }
                }
            }
            elseif ((preg_match("/applications/i", $table_name)) || ($table_name == "default_applications")) {

                $image = getImageNew("applications", $table_name, $lid, $vsys);

                if($table_name != "default_applications"){

                    $getAppoverrideByApplication = $projectdb->query("SELECT ar.name, ar.id AS lid, 'appoverride_rules' AS table_name_lid, ar.vsys, 'Application' AS position, ar.app_id AS member_lid, ar.app_table AS table_name "
                        . " FROM appoverride_rules ar "
                        . " WHERE ar.source = '$source' $add_vsys AND ar.app_id = '$lid' AND ar.app_table = '$table_name' ; ");
                }
                else if($table_name == "default_applications"){

                    $getAppoverrideByApplication = $projectdb->query("SELECT ar.name, ar.id AS lid, 'appoverride_rules' AS table_name_lid, ar.vsys, 'Application' AS position, ar.app_id AS member_lid, ar.app_table AS table_name "
                        . " FROM appoverride_rules ar "
                        . " WHERE ar.source = '$source' AND ar.app_id = '$lid' AND ar.app_table = '$table_name' ; ");
                }

                if ($getAppoverrideByApplication->num_rows > 0) {
                    while ($data = $getAppoverrideByApplication->fetch_assoc()) {
                        $data['name_object_search'] = "<img style='vertical-align: middle;' src=/resources/images/rules/$image> " .$name;
                        $data['name_object'] = $name;
                        $myData[] = $data;
                    }
                }
            }
            elseif($table_name == "zones"){

                // From
                $getAppByZonesFrom = $projectdb->query("SELECT ar.name, ar.id AS lid, 'appoverride_rules' AS table_name_lid, ar.vsys, 'From' AS position, 'zones' AS table_name "
                    . " FROM appoverride_rules ar, appoverride_rules_from from_sec "
                    . " WHERE ar.source = '$source' $add_vsys AND from_sec.name = '$name' "
                    . " AND from_sec.rule_lid = ar.id;");

                if ($getAppByZonesFrom->num_rows > 0) {
                    while ($data = $getAppByZonesFrom->fetch_assoc()) {
                        $data['name_object_search'] = "<img style='vertical-align: middle;' src=/resources/images/rules/zone.gif> " .$name;
                        $data['name_object'] = $name;
                        $myData[] = $data;
                    }
                }

                // To
                $getAppByZonesTo = $projectdb->query("SELECT ar.name, ar.id AS lid, 'appoverride_rules' AS table_name_lid, ar.vsys, 'To' AS position, 'zones' AS table_name "
                    . " FROM appoverride_rules ar, appoverride_rules_to to_sec "
                    . " WHERE ar.source = '$source' $add_vsys AND to_sec.name = '$name' "
                    . " AND to_sec.rule_lid = ar.id;");

                if ($getAppByZonesTo->num_rows > 0) {
                    while ($data = $getAppByZonesTo->fetch_assoc()) {
                        $data['name_object_search'] = "<img style='vertical-align: middle;' src=/resources/images/rules/zone.gif> " .$name;
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


function getConsolidationHash(STRING $projectName, ARRAY $params){

    global $projectdb;
    $projectdb = selectDatabase($projectName);

    $table_name = $params['table_name'];
    $myData = array();

    $getRulesHash = $projectdb->query("SELECT id AS id_cons, hash, filter_hash, rules_lid, CAST(SUBSTRING(rules_lid, 1, POSITION(',' IN rules_lid)-1)as unsigned) as first FROM hash_rules WHERE table_name = '$table_name' AND fixed = '0' ORDER by first; ");

    $count = $getRulesHash->num_rows;
    if($count > 0){
        $myData = array();
        while ($data = $getRulesHash->fetch_object()) {
            $myData[] = $data;
        }
    }

    $message = array();
    $message['code'] = true;
    $message['count'] = count($myData);
    $message['msg'] = $myData;

    return $message;
}


function setReplaceOnSecurityRules($projectName, $position, $table_name_to_replace_control, $table_name_to_replace, $id_new_to_replace, $member_lid, $table_name, $lid, $id_replace, $check_split, $replace_by, $replace_to){

    global $projectdb;
    global $source;
    $projectdb = selectDatabase($projectName);

    if ($position == "Service") {
        // A TENER EN CUENTA
        // 1. Replace de Service con Service --> un simple update
        // 1. Que en la rule solo haya un servicio
        // 2. Si en la rule hay más de un servicio hay que:
        // 2.1 Hay que clonar la rule -1 con el servicio al que quieren reemplazar y añadir la App en el campo y tabla applications
        // 2.2 Hay que update la rule en cuestión sin el servicio que han clonado a app y dejar el resto de services en el campo services

        if($replace_by == "Remove"){
            $projectdb->query("DELETE FROM security_rules_srv WHERE member_lid = '$member_lid' AND table_name = '$table_name' "
                . " AND rule_lid = '$lid';");
        }
        elseif($replace_by == "Members"){

            if($table_name == "services_groups_id"){
                $table_name_without_id = "services_groups";
            }

            $projectdb->query("DELETE FROM security_rules_srv WHERE member_lid = '$member_lid' AND table_name = '$table_name' "
                . " AND rule_lid = '$lid';");

            $getMembers = $projectdb->query("SELECT member_lid, table_name FROM $table_name_without_id WHERE lid = '$member_lid'; ");

            if ($getMembers->num_rows != 0) {
                while ($dataM = $getMembers->fetch_assoc()) {

                    $member_lid_member = $dataM['member_lid'];
                    $table_name_member = $dataM['table_name'];

                    $getExistAddressToRule = $projectdb->query("SELECT id FROM security_rules_srv WHERE member_lid = '$member_lid_member' "
                        . " AND table_name = '$table_name_member' AND rule_lid = '$lid' ");

                    if ($getExistAddressToRule->num_rows == 0) {
                        $projectdb->query("INSERT INTO security_rules_srv (member_lid, table_name, rule_lid) 
                                            VALUES ('$member_lid_member', '$table_name_member', '$lid') ;");
                    }
                }
            }
        }
        else{
            if (($table_name_to_replace_control == "services") || ($table_name_to_replace_control == "services_groups_id")) {

                // Caso 1. Rule con sólo un service
                $getExistServicesToRule = $projectdb->query("SELECT id FROM security_rules_srv WHERE member_lid = '$id_new_to_replace' "
                    . " AND table_name = '$table_name_to_replace' AND rule_lid = '$lid' ");

                $exist_service_to_rule = $getExistServicesToRule->num_rows;

                if (preg_match("/groups/i", $table_name_to_replace)) {
                    $table_name_to_replace = $table_name_to_replace . "_id";
                }

                if ($exist_service_to_rule == 0) {
                    $projectdb->query("UPDATE security_rules_srv SET member_lid = '$id_new_to_replace', table_name = '$table_name_to_replace' "
                        . " WHERE rule_lid = '$lid' AND member_lid = '$member_lid' AND table_name = '$table_name';");
                } else {
                    $projectdb->query("DELETE FROM security_rules_srv WHERE member_lid = '$member_lid' AND table_name = '$table_name' "
                        . " AND rule_lid = '$lid';");
                }

                $projectdb->query("DELETE FROM search_replace WHERE id = '$id_replace' ;");

            } // Cambio por aplicación
            elseif (($table_name_to_replace_control == "applications") || ($table_name_to_replace_control == "applications_groups_id") || ($table_name_to_replace_control == "applications_filters")){

                // Split 2 rules
                if ($check_split == "true") {

                    $getSourceAndVsysFromRule = $projectdb->query("SELECT id, source, vsys, devicegroup FROM security_rules WHERE id = '$lid'; ");
                    if($getSourceAndVsysFromRule->num_rows > 0){
                        $dataSV = $getSourceAndVsysFromRule->fetch_assoc();

                        $devicegroup_srv = $dataSV['devicegroup'];
                        $source_srv = $dataSV['source'];
                        $vsys_srv = $dataSV['vsys'];
                    }

                    $getTotalSrvToReplace = $projectdb->query("SELECT id FROM security_rules_srv WHERE rule_lid = '$lid'; ");
                    $num_serv_to_rule = $getTotalSrvToReplace->num_rows;
                    //$data = $getTotalSrvToReplace->fetch_assoc();

                    // Si hay solo un servicio, hacer solo el update de la rule poniendo en application la aplicación seleccionada y eliminando el service que hay en la tabla
                    // Y añadir el application_default
                    if ($num_serv_to_rule == "1") {

                        //$devicegroup_srv = $data['devicegroup'];
                        //$source_srv = $data['source'];
                        //$vsys_srv = $data['vsys'];

                        // Delete del servicio seleccioando en la tabla security_rules_srv
                        // Update de la tabla security_rules_app
                        // $projectdb->query("DELETE FROM security_rules_srv WHERE member_lid = '$member_lid' AND table_name = '$table_name' AND rule_lid = '$lid';");
                        // Poner application_default en el apartado de services

                        $getIdAppDef = $projectdb->query("SELECT id FROM services WHERE name LIKE '%application-default%' AND source = '$source_srv' AND vsys = 'shared' LIMIT 1 ;");

                        if ($getIdAppDef->num_rows > 0) {
                            $getData = $getIdAppDef->fetch_assoc();
                            $id_app_default = $getData['id'];
                            $projectdb->query("UPDATE security_rules_srv SET member_lid = '$id_app_default', table_name = 'services' WHERE rule_lid = '$lid';");
                        }
                        // Borrar igualmente el servicio, por si no existiera el application-default. . . caso raro
                        else{
                            $projectdb->query("DELETE FROM security_rules_srv WHERE rule_lid = '$lid';");
                        }

                        // Mirar que en security_rules_app no existe ya la aplicación
                        $getIsAppToReplace = $projectdb->query("SELECT id FROM security_rules_app WHERE rule_lid = '$lid' AND member_lid = '$id_new_to_replace' AND table_name = '$table_name_to_replace'; ");

                        if ($getIsAppToReplace->num_rows == 0) {
                            $projectdb->query("INSERT INTO security_rules_app (id, source, vsys, member_lid, table_name, rule_lid, devicegroup) "
                                . "VALUES (NULL, '$source_srv', '$vsys_srv', '$id_new_to_replace', '$table_name_to_replace', '$lid', '$devicegroup_srv'); ");
                        }

                        // Delete el seleccionado de la tabla search_replace
                        $projectdb->query("DELETE FROM search_replace WHERE id = '$id_replace' ;");
                    }
                    else {
                        // Hay más de un servicio asociado a la rule, por lo tanto, clonar -1 con el nuevo servicio y update de la rule con la new app
                        // Coger vsys y source de la rule_id ya que con el search and replace pueden haber seleccionado vsys = All
                        $getPosition = $projectdb->query("SELECT position, name, vsys, source, devicegroup FROM security_rules WHERE id = '$lid'; ");
                        $getPosData = $getPosition->fetch_assoc();
                        $initial_position = $getPosData['position'];
                        $initial_name = $getPosData['name'];
                        $initial_vsys = $getPosData['vsys'];
                        $initial_source = $getPosData['source'];
                        $source = $initial_source;
                        $initial_devicegroup = $getPosData['devicegroup'];
                        $final_position = $initial_position - 1;
                        $message = "";

                        // Primero, comprobar que no existe una rule ya llamada con Cl-$name, ya que si existe, no hace falta clonarla, sino que añadir allí los cambios
                        // Mirar también si ya tiene applicaciones para añadirlas en la lista

                        $getNameRuleCl = $projectdb->query("SELECT id, name FROM security_rules WHERE name = 'Cl-$initial_name' AND disabled = '0' AND vsys = '$initial_vsys' AND source = '$initial_source' ;");

                        if ($getNameRuleCl->num_rows == 0) {
                            // 1. Crear rule, clonándola, por -1
                            $new_lid = clone_security_rule($initial_position, $final_position, $initial_vsys, $initial_source, $lid, $message, $projectName);

                            // Primero borrar de la tabla security_rules_srv todas las referencias a services de la rule clonada y luego añadir al new_lid el replace
                            $projectdb->query("DELETE FROM security_rules_srv WHERE rule_lid = '$new_lid';");
                        } else {
                            $getData = $getNameRuleCl->fetch_assoc();
                            $new_lid = $getData['id'];
                        }

                        $getIsAppToReplace = $projectdb->query("SELECT id FROM security_rules_app WHERE rule_lid = '$new_lid' AND member_lid = '$id_new_to_replace' AND table_name = '$table_name_to_replace'; ");

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

                        $projectdb->query("DELETE FROM security_rules_srv WHERE rule_lid = '$lid' AND member_lid = '$member_lid' AND table_name = '$table_name';");

                        $projectdb->query("DELETE FROM search_replace WHERE id = '$id_replace' ;");
                    }

                }
                else {

                    //$getTotalSrvToReplace = $projectdb->query("SELECT id, source, vsys, devicegroup FROM security_rules_srv WHERE rule_lid = '$lid'; ");
                    $getTotalSrvToReplace = $projectdb->query("SELECT id, source, vsys, devicegroup FROM security_rules WHERE id = '$lid'; ");

                    $data = $getTotalSrvToReplace->fetch_assoc();
                    $devicegroup_srv = $data['devicegroup'];
                    $source_srv = $data['source'];
                    $vsys_srv = $data['vsys'];

                    // Delete del servicio seleccioando en la tabla security_rules_srv
                    // Update de la tabla security_rules_app
                    $projectdb->query("DELETE FROM security_rules_srv WHERE member_lid = '$member_lid' AND table_name = '$table_name' AND rule_lid = '$lid';");


                    // Poner application_default en el apartado de services si y sólo si no hay más services
                    $getTotalServices = $projectdb->query("SELECT id FROM security_rules_srv WHERE rule_lid = '$lid'; ");

                    if ($getTotalServices->num_rows == 0) {
                        $getIdAppDef = $projectdb->query("SELECT id FROM services WHERE name LIKE '%application-default%' AND source = '$source_srv' AND vsys = 'shared' LIMIT 1; ");

                        if ($getIdAppDef->num_rows > 0) {
                            $getData = $getIdAppDef->fetch_assoc();
                            $id_app_default = $getData['id'];

                            // Mirar que no existe ya la application-default
                            $getAppDefault = $projectdb->query("SELECT id FROM security_rules_srv WHERE member_lid = '$id_app_default' AND table_name = 'services' AND rule_lid = '$lid';");

                            if ($getAppDefault->num_rows == 0) {
                                $projectdb->query("INSERT INTO security_rules_srv (id, source, rule_lid, member_lid, table_name, vsys, counter, devicegroup) "
                                    . " VALUES (NULL, '$source_srv', '$lid', '$id_app_default', 'services', '$vsys_srv', '0', '$devicegroup_srv'); ");
                            }
                        }
                    }

                    // Mirar que en security_rules_app no existe ya la aplicación
                    $getIsAppToReplace = $projectdb->query("SELECT id FROM security_rules_app WHERE rule_lid = '$lid' AND member_lid = '$id_new_to_replace' AND table_name = '$table_name_to_replace'; ");

                    if ($getIsAppToReplace->num_rows == 0) {
                        $projectdb->query("INSERT INTO security_rules_app (id, source, vsys, member_lid, table_name, rule_lid, devicegroup) "
                            . "VALUES (NULL, '$source_srv', '$vsys_srv', '$id_new_to_replace', '$table_name_to_replace', '$lid', '$devicegroup_srv'); ");
                    }

                }
            }
        }
        // Delete el seleccionado de la tabla search_replace
        $projectdb->query("DELETE FROM search_replace WHERE id = '$id_replace' ;");


    } // Address / Address Group y Source/Destination
    elseif (($position == "Source") || ($position == "Destination")) {

        if ($position == "Source") {
            $table_security_rule = "security_rules_src";
        } elseif ($position == "Destination") {
            $table_security_rule = "security_rules_dst";
        }

        if($replace_by == "Remove"){
            $projectdb->query("DELETE FROM $table_security_rule WHERE member_lid = '$member_lid' AND table_name = '$table_name' "
                . " AND rule_lid = '$lid';");
        }
        elseif($replace_by == "Members"){

            if($table_name == "address_groups_id"){
                $table_name_without_id = "address_groups";
            }

            $projectdb->query("DELETE FROM $table_security_rule WHERE member_lid = '$member_lid' AND table_name = '$table_name' "
                . " AND rule_lid = '$lid';");

            $getMembers = $projectdb->query("SELECT member_lid, table_name FROM $table_name_without_id WHERE lid = '$member_lid'; ");

            if ($getMembers->num_rows != 0) {
                while ($dataM = $getMembers->fetch_assoc()) {

                    $member_lid_member = $dataM['member_lid'];
                    $table_name_member = $dataM['table_name'];

                    $getExistAddressToRule = $projectdb->query("SELECT id FROM $table_security_rule WHERE member_lid = '$member_lid_member' "
                        . " AND table_name = '$table_name_member' AND rule_lid = '$lid' ");

                    if ($getExistAddressToRule->num_rows == 0) {
                        $projectdb->query("INSERT INTO $table_security_rule (member_lid, table_name, rule_lid) 
                                            VALUES ('$member_lid_member', '$table_name_member', '$lid') ;");
                    }
                }
            }

        }
        else{
            if (preg_match("/groups/i", $table_name_to_replace)) {
                $table_name_to_replace = $table_name_to_replace . "_id";
            }

            $getExistAddressToRule = $projectdb->query("SELECT id FROM $table_security_rule WHERE member_lid = '$id_new_to_replace' "
                . " AND table_name = '$table_name_to_replace' AND rule_lid = '$lid' ");

            if ($getExistAddressToRule->num_rows == 0) {
                $projectdb->query("UPDATE $table_security_rule SET member_lid = '$id_new_to_replace', table_name = '$table_name_to_replace' "
                    . " WHERE rule_lid = '$lid' AND member_lid = '$member_lid' AND table_name = '$table_name';");
            } else {
                $projectdb->query("DELETE FROM $table_security_rule WHERE member_lid = '$member_lid' AND table_name = '$table_name' "
                    . " AND rule_lid = '$lid';");
            }
        }
        $projectdb->query("DELETE FROM search_replace WHERE id = '$id_replace' ;");


    }
    // Aplicaciones por aplicaciones
    elseif ($position == "Application") {

        if($replace_by == "Remove"){
            $projectdb->query("DELETE FROM security_rules_app WHERE member_lid = '$member_lid' AND table_name = '$table_name' "
                . " AND rule_lid = '$lid';");
        }
        elseif($replace_by == "Members"){

            if($table_name == "applications_groups_id"){
                $table_name_without_id = "applications_groups";
            }

            $projectdb->query("DELETE FROM security_rules_app WHERE member_lid = '$member_lid' AND table_name = '$table_name' "
                . " AND rule_lid = '$lid';");

            $getMembers = $projectdb->query("SELECT member_lid, table_name FROM $table_name_without_id WHERE lid = '$member_lid'; ");

            if ($getMembers->num_rows != 0) {
                while ($dataM = $getMembers->fetch_assoc()) {

                    $member_lid_member = $dataM['member_lid'];
                    $table_name_member = $dataM['table_name'];

                    $getExistAddressToRule = $projectdb->query("SELECT id FROM security_rules_app WHERE member_lid = '$member_lid_member' "
                        . " AND table_name = '$table_name_member' AND rule_lid = '$lid' ");

                    if ($getExistAddressToRule->num_rows == 0) {
                        $projectdb->query("INSERT INTO security_rules_app (member_lid, table_name, rule_lid) 
                                            VALUES ('$member_lid_member', '$table_name_member', '$lid') ;");
                    }
                }
            }
        }
        else{
            $getExistApplicationToRule = $projectdb->query("SELECT id FROM security_rules_app WHERE member_lid = '$id_new_to_replace' "
                . " AND table_name = '$table_name_to_replace' AND rule_lid = '$lid' ");

            $exist_application_to_rule = $getExistApplicationToRule->num_rows;
            if ($exist_application_to_rule == 0) {
                $projectdb->query("UPDATE security_rules_app SET member_lid = '$id_new_to_replace', table_name = '$table_name_to_replace' "
                    . " WHERE rule_lid = '$lid' AND member_lid = '$member_lid' AND table_name = '$table_name';");
            } else {
                $projectdb->query("DELETE FROM security_rules_app WHERE member_lid = '$member_lid' AND table_name = '$table_name' "
                    . " AND rule_lid = '$lid';");
            }
        }
        $projectdb->query("DELETE FROM search_replace WHERE id = '$id_replace' ;");
    }
    elseif (($position == "From") || ($position == "To")) {

        if ($position == "From") {
            $table_security_rule = "security_rules_from";
        } elseif ($position == "To") {
            $table_security_rule = "security_rules_to";
        }

        $getObjectToReplace = $projectdb->query("SELECT object_replace FROM search_replace WHERE id = '$id_replace'; ");
        if ($getObjectToReplace->num_rows == 1) {
            $dataOR = $getObjectToReplace->fetch_assoc();
            $object_replace = $dataOR['object_replace'];
        }

        if($replace_by == "Remove"){
            $projectdb->query("DELETE FROM $table_security_rule WHERE name = '$object_replace' AND rule_lid = '$lid';");
        }
        elseif($replace_by == "Zones"){

            $getExistZoneToRule = $projectdb->query("SELECT id FROM $table_security_rule WHERE name = '$replace_to' AND rule_lid = '$lid' ");

            if ($getExistZoneToRule->num_rows == 0) {
                $projectdb->query("UPDATE $table_security_rule SET name = '$replace_to' "
                    . " WHERE rule_lid = '$lid' AND name = '$object_replace';");
            } else {
                $projectdb->query("DELETE FROM $table_security_rule WHERE name = '$object_replace' AND rule_lid = '$lid';");
            }

        }

        $projectdb->query("DELETE FROM search_replace WHERE id = '$id_replace' ;");

    }

}


function setReplaceOnNatRules($projectName, $position, $table_name_to_replace, $id_new_to_replace, $member_lid, $table_name, $lid, $id_replace, $replace_by, $replace_to)
{

    global $projectdb;
    $projectdb = selectDatabase($projectName);

    if ($position == "Service") {

        if($replace_by == "Remove"){
            $projectdb->query("UPDATE nat_rules SET op_service_lid = '', op_service_table = '' WHERE id = '$lid';");
        }

        else{
            if (preg_match("/service/i", $table_name_to_replace)) {
                $projectdb->query("UPDATE nat_rules SET op_service_lid = '$id_new_to_replace', op_service_table = '$table_name_to_replace' WHERE id = '$lid';");
            }
        }
        $projectdb->query("DELETE FROM search_replace WHERE id = '$id_replace' ;");


    } // Address / Address Group and Source/Destination/Translated Address/Translated Address Fallback/Destination Address Translation
    elseif (($position == "Source") || ($position == "Destination") || ($position == "Translated Address")
        || ($position == "Translated Address Fallback") || ($position == "Destination Address Translation")) {

        if ($position == "Source") {
            $table_nat_rule = "nat_rules_src";
        } elseif ($position == "Destination") {
            $table_nat_rule = "nat_rules_dst";
        } elseif($position == "Translated Address"){
            $table_nat_rule = "nat_rules_translated_address";
        } elseif($position == "Translated Address Fallback"){
            $table_nat_rule = "nat_rules_translated_address_fallback";
        }

        if($replace_by == "Remove"){
            if($position == "Destination Address Translation"){
                $projectdb->query("UPDATE nat_rules SET tp_dat_address_lid = '', tp_dat_address_table = '' WHERE id = '$lid';");
            }else{
                $projectdb->query("DELETE FROM $table_nat_rule WHERE member_lid = '$member_lid' AND table_name = '$table_name' "
                    . " AND rule_lid = '$lid';");
                //echo "DELETE FROM $table_nat_rule WHERE member_lid = '$member_lid' AND table_name = '$table_name' "
                //    . " AND rule_lid = '$lid';\n";
            }
        }
        elseif($replace_by == "Members"){

            if($position != "Destination Address Translation"){

                if($table_name == "address_groups_id"){
                    $table_name_without_id = "address_groups";
                }

                $projectdb->query("DELETE FROM $table_nat_rule WHERE member_lid = '$member_lid' AND table_name = '$table_name' "
                    . " AND rule_lid = '$lid';");

                $getMembers = $projectdb->query("SELECT member_lid, table_name FROM $table_name_without_id WHERE lid = '$member_lid'; ");

                if ($getMembers->num_rows != 0) {
                    while ($dataM = $getMembers->fetch_assoc()) {

                        $member_lid_member = $dataM['member_lid'];
                        $table_name_member = $dataM['table_name'];

                        $getExistAddressToRule = $projectdb->query("SELECT id FROM $table_nat_rule WHERE member_lid = '$member_lid_member' "
                            . " AND table_name = '$table_name_member' AND rule_lid = '$lid' ");

                        if ($getExistAddressToRule->num_rows == 0) {
                            $projectdb->query("INSERT INTO $table_nat_rule (member_lid, table_name, rule_lid) 
                                            VALUES ('$member_lid_member', '$table_name_member', '$lid') ;");
                        }
                    }
                }
            }
        }
        else{
            if (preg_match("/groups/i", $table_name_to_replace)) {
                $table_name_to_replace = $table_name_to_replace . "_id";
            }

            if($position == "Destination Address Translation"){
                $projectdb->query("UPDATE nat_rules SET tp_dat_address_lid = '$id_new_to_replace', tp_dat_address_table = '$table_name_to_replace' WHERE id = '$lid';");
            }else{
                $getExistAddressToRule = $projectdb->query("SELECT id FROM $table_nat_rule WHERE member_lid = '$id_new_to_replace' "
                    . " AND table_name = '$table_name_to_replace' AND rule_lid = '$lid' ");

                if ($getExistAddressToRule->num_rows == 0) {
                    $projectdb->query("UPDATE $table_nat_rule SET member_lid = '$id_new_to_replace', table_name = '$table_name_to_replace' "
                        . " WHERE rule_lid = '$lid' AND member_lid = '$member_lid' AND table_name = '$table_name';");
                } else {
                    $projectdb->query("DELETE FROM $table_nat_rule WHERE member_lid = '$member_lid' AND table_name = '$table_name' "
                        . " AND rule_lid = '$lid';");
                }
            }
        }
        $projectdb->query("DELETE FROM search_replace WHERE id = '$id_replace' ;");
    }
    elseif ($position == "From") {

        $getObjectToReplace = $projectdb->query("SELECT object_replace FROM search_replace WHERE id = '$id_replace'; ");
        if ($getObjectToReplace->num_rows == 1) {
            $dataOR = $getObjectToReplace->fetch_assoc();
            $object_replace = $dataOR['object_replace'];
        }

        if($replace_by == "Remove"){
            $projectdb->query("DELETE FROM nat_rules_from WHERE name = '$object_replace' AND rule_lid = '$lid';");
        }
        elseif($replace_by == "Zones"){

            $getExistZoneToRule = $projectdb->query("SELECT id FROM nat_rules_from WHERE name = '$replace_to' AND rule_lid = '$lid' ");

            if ($getExistZoneToRule->num_rows == 0) {
                $projectdb->query("UPDATE nat_rules_from SET name = '$replace_to' "
                    . " WHERE rule_lid = '$lid' AND name = '$object_replace';");
            } else {
                $projectdb->query("DELETE FROM nat_rules_from WHERE name = '$object_replace' AND rule_lid = '$lid';");
            }

        }

        $projectdb->query("DELETE FROM search_replace WHERE id = '$id_replace' ;");

    }
    elseif($position == "To"){

        $getObjectToReplace = $projectdb->query("SELECT object_replace FROM search_replace WHERE id = '$id_replace'; ");
        if ($getObjectToReplace->num_rows == 1) {
            $dataOR = $getObjectToReplace->fetch_assoc();
            $object_replace = $dataOR['object_replace'];
        }

        if($replace_by == "Remove"){
            $projectdb->query("UPDATE nat_rules SET op_zone_to = '' WHERE op_zone_to = '$object_replace' AND id = '$lid';");
        }
        elseif($replace_by == "Zones"){

            $projectdb->query("UPDATE nat_rules SET op_zone_to = '$replace_to' WHERE op_zone_to = '$object_replace' AND id = '$lid';");

        }

        $projectdb->query("DELETE FROM search_replace WHERE id = '$id_replace' ;");

    }
}


function setReplaceOnAppoverrideRules($projectName, $position, $table_name_to_replace, $id_new_to_replace, $member_lid, $table_name, $lid, $id_replace, $replace_by, $replace_to){

    global $projectdb;
    $projectdb = selectDatabase($projectName);

    if (($position == "Source") || ($position == "Destination")) {

        if ($position == "Source") {
            $table_appoverride_rule = "appoverride_rules_src";
        } elseif ($position == "Destination") {
            $table_appoverride_rule = "appoverride_rules_dst";
        }

        if($replace_by == "Remove"){
            $projectdb->query("DELETE FROM $table_appoverride_rule WHERE member_lid = '$member_lid' AND table_name = '$table_name' "
                . " AND rule_lid = '$lid';");
        }
        elseif($replace_by == "Members"){

            if($table_name == "address_groups_id"){
                $table_name_without_id = "address_groups";
            }

            $projectdb->query("DELETE FROM $table_appoverride_rule WHERE member_lid = '$member_lid' AND table_name = '$table_name' "
                . " AND rule_lid = '$lid';");

            $getMembers = $projectdb->query("SELECT member_lid, table_name FROM $table_name_without_id WHERE lid = '$member_lid'; ");

            if ($getMembers->num_rows != 0) {
                while ($dataM = $getMembers->fetch_assoc()) {

                    $member_lid_member = $dataM['member_lid'];
                    $table_name_member = $dataM['table_name'];

                    $getExistAddressToRule = $projectdb->query("SELECT id FROM $table_appoverride_rule WHERE member_lid = '$member_lid_member' "
                        . " AND table_name = '$table_name_member' AND rule_lid = '$lid' ");

                    if ($getExistAddressToRule->num_rows == 0) {
                        $projectdb->query("INSERT INTO $table_appoverride_rule (member_lid, table_name, rule_lid) 
                                            VALUES ('$member_lid_member', '$table_name_member', '$lid') ;");
                    }
                }
            }
        }
        else{
            $getExistAddressToRule = $projectdb->query("SELECT id FROM $table_appoverride_rule WHERE member_lid = '$id_new_to_replace' "
                . " AND table_name = '$table_name_to_replace' AND rule_lid = '$lid' ");

            if ($getExistAddressToRule->num_rows == 0) {
                $projectdb->query("UPDATE $table_appoverride_rule SET member_lid = '$id_new_to_replace', table_name = '$table_name_to_replace' "
                    . " WHERE rule_lid = '$lid' AND member_lid = '$member_lid' AND table_name = '$table_name';");
            } else {
                $projectdb->query("DELETE FROM $table_appoverride_rule WHERE member_lid = '$member_lid' AND table_name = '$table_name' "
                    . " AND rule_lid = '$lid';");
            }
        }
    }
    elseif ($position == "Application") {

        if($replace_by == "Remove"){
            $projectdb->query("UPDATE appoverride_rules SET app_id = '', app_table = '' WHERE id = '$lid';");
        }
        else{
            $projectdb->query("UPDATE appoverride_rules SET app_id = '$id_new_to_replace', app_table = '$table_name_to_replace' WHERE id = '$lid';");
        }

    }
    elseif (($position == "From") || ($position == "To")) {

        if ($position == "From") {
            $table_security_rule = "appoverride_rules_from";
        } elseif ($position == "To") {
            $table_security_rule = "appoverride_rules_to";
        }

        $getObjectToReplace = $projectdb->query("SELECT object_replace FROM search_replace WHERE id = '$id_replace'; ");
        if ($getObjectToReplace->num_rows == 1) {
            $dataOR = $getObjectToReplace->fetch_assoc();
            $object_replace = $dataOR['object_replace'];
        }

        if($replace_by == "Remove"){
            $projectdb->query("DELETE FROM $table_security_rule WHERE name = '$object_replace' AND rule_lid = '$lid';");
        }
        elseif($replace_by == "Zones"){

            $getExistZoneToRule = $projectdb->query("SELECT id FROM $table_security_rule WHERE name = '$replace_to' AND rule_lid = '$lid' ");

            if ($getExistZoneToRule->num_rows == 0) {
                $projectdb->query("UPDATE $table_security_rule SET name = '$replace_to' "
                    . " WHERE rule_lid = '$lid' AND name = '$object_replace';");
            } else {
                $projectdb->query("DELETE FROM $table_security_rule WHERE name = '$object_replace' AND rule_lid = '$lid';");
            }

        }

    }

    $projectdb->query("DELETE FROM search_replace WHERE id = '$id_replace' ;");
}


function setMergeSecurityRules(STRING $projectName, ARRAY $params, STRING $updateDescriptions){
    global $projectdb;
    global $app;

    $msg = array();

    $projectdb = selectDatabase($projectName);

    $user = $app->container->sentinel->getUser();
    $user_id = $user->id;

    $source = $params['source'];
    
    $selection = $params['selection'];
    $id_cons = $params['id_cons'];

    if(count($selection) == 0){
        
        $selectionedGroups = array();
        
        //This will identify the groups that need to be merged. hash_rules shows groups that are mergeable based on the selected fields. Visible=1 determines which groups the user wants to really merge
        //$getConsolidationTools = $projectdb->query("SELECT id, rules_lid FROM hash_rules WHERE visible = '1' AND table_name = 'security_rules';");
        $getConsolidationTools = $projectdb->query("SELECT id, rules_lid FROM hash_rules WHERE id IN ($id_cons);");
        //echo "SELECT id, rules_lid FROM hash_rules WHERE id IN ($id_cons);\n";

        if ($getConsolidationTools->num_rows > 0) {
            while ($dataRT = $getConsolidationTools->fetch_assoc()){
                if($dataRT['rules_lid'] != ""){
                    $selectionedGroups[] = $dataRT['rules_lid'];
                }
            }
        }
        else{
            //There is a second way to request merges. We need to check if this is the best way to set the filtering criteria.
            $getResultsTools = $projectdb->query("SELECT member_lid FROM tools_results WHERE table_name = 'security_rules' AND source = '$source' AND user_id = '$user_id';");
            if ($getResultsTools->num_rows > 0) {

                while ($dataRT = $getResultsTools->fetch_assoc()){
                    if($dataRT['member_lid'] != ""){
                        $member_lid[] = $dataRT['member_lid'];
                    }else{
                        $member_lid = array();
                    }
                }

                if(count($member_lid) > 0){
                    $selectionedGroups = array(implode(',',$member_lid));
                }
            }
        }


        //Given the new selection, we would have to check how to group the rules given the merge criteria. Additionally
        //Divide the rules in 4 groups within each found group:
        // app-ids, user-ids
        // app-ids, no user-ids
        // No app-ids, user-ids
        // No app-ids, no user-ids
        //print_r($selectionedGroups);
        foreach ($selectionedGroups as $selectionedGroup){
            $msg = array_merge($msg, splitAndMakeMerge($projectdb, $source, $projectName,$selectionedGroup, 'Security',$updateDescriptions));
        }
    }
    else{
        
        $msg = splitAndMakeMerge($projectdb, $source, $projectName,$selection, 'Security',$updateDescriptions);
    }

    if($id_cons != ""){
        $projectdb->query("UPDATE hash_rules SET fixed = '1' WHERE id IN ($id_cons); ");
    }

    foreach ($msg as &$entry){
        $entry = "<li>$entry</li>";
    }

    $message = array();
    $message['code'] = true;
    $message['count'] = "";
    $message['msg'] = implode("<br>",$msg);

    return $message;

}

function makeMergeNATRules(mysqli $projectdb, int $source, string $projectName, string $selection): string{
    //from, src, dest, el resto iguales
    if ($selection != "") {

        //take_snapshot_last($projectName);
        $projectdb->query("TRUNCATE TABLE tmp_dup_name_val;");

        $rule_id = explode(',', $selection);

        //Combine 2 or more rules
        if(count($rule_id) > 1){

            $first_rule = $rule_id[0];

            $lid = $first_rule;

            $sqlVar = $projectdb->query("SELECT tp_sat_bidirectional, op_zone_to, op_to_interface, is_dat, op_service_lid, op_service_table, "
                . "tp_sat_type, tp_sat_address_type, tp_sat_interface, tp_dat_port, tp_dat_address_lid, tp_dat_address_table, "
                . "implicit, preorpost, active_active_device_binding, nat_type, tp_sat_interface_fallback, tp_sat_ipaddress_fallback, tp_fallback_type FROM nat_rules WHERE id = '$first_rule';");

            //echo "1. First Rule: SELECT tp_sat_bidirectional, op_zone_to, op_to_interface, is_dat, op_service_lid, op_service_table, "
            //    . "tp_sat_type, tp_sat_address_type, tp_sat_interface, tp_dat_port, tp_dat_address_lid, tp_dat_address_table, "
            //    . "implicit, preorpost, active_active_device_binding, nat_type, tp_sat_interface_fallback, tp_sat_ipaddress_fallback, tp_fallback_type FROM nat_rules WHERE id = '$first_rule';";

            $dataV = $sqlVar->fetch_assoc();
            $tp_sat_bidirectional = $dataV['tp_sat_bidirectional'];
            $op_zone_to = $dataV['op_zone_to'];
            $op_to_interface = $dataV['op_to_interface'];
            $is_dat = $dataV['is_dat'];
            $op_service_lid = $dataV['op_service_lid'];
            $op_service_table = $dataV['op_service_table'];
            $tp_sat_type = $dataV['tp_sat_type'];
            $tp_sat_address_type = $dataV['tp_sat_address_type'];
            $tp_sat_interface = $dataV['tp_sat_interface'];
            $tp_dat_port = $dataV['tp_dat_port'];
            $tp_dat_address_lid = $dataV['tp_dat_address_lid'];
            $tp_dat_address_table = $dataV['tp_dat_address_table'];
            $implicit = $dataV['implicit'];
            $preorpost = $dataV['preorpost'];
            $active_active_device_binding = $dataV['active_active_device_binding'];
            $nat_type = $dataV['nat_type'];
            $tp_sat_interface_fallback = $dataV['tp_sat_interface_fallback'];
            $tp_sat_ipaddress_fallback = $dataV['tp_sat_ipaddress_fallback'];
            $tp_fallback_type = $dataV['tp_fallback_type'];

            // si es tp_sat_address_type = translated-address, mirar que tienen los mismo member_lid y table_name
            if($tp_sat_address_type == "translated-address"){

                $members = $projectdb->query("SELECT member_lid, table_name FROM nat_rules_translated_address WHERE rule_lid = '$first_rule';");
                if ($members->num_rows > 0) {
                    $membername = array();
                    while ($data2 = $members->fetch_assoc()) {
                        $member_lid = $data2['member_lid'];
                        $member_table_name = $data2['table_name'];
                        $getMemName = $projectdb->query("SELECT name FROM $member_table_name WHERE id = '$member_lid';");
                        if ($getMemName->num_rows == 1) {
                            $membername2 = $getMemName->fetch_assoc();
                            if (preg_match("/shared/i", $member_table_name)) {
                                $name_member = $membername2['name']."&&&";
                                $membername[] = $name_member;
                            }else{
                                $membername[] = $membername2['name'];
                            }
                        }
                    }
                    asort($membername);
                    $projectdb->query("INSERT INTO tmp_dup_name_val (lid,members,table_name,name) VALUES ('$first_rule','" . implode(",", $membername) . "','$member_table_name','tp_sat_address_type');");
                }
            }

            if($tp_fallback_type == "translated-address"){

                $members = $projectdb->query("SELECT member_lid, table_name FROM nat_rules_translated_address_fallback WHERE rule_lid = '$first_rule';");
                if ($members->num_rows > 0) {
                    $membername = array();
                    while ($data2 = $members->fetch_assoc()) {
                        $member_lid = $data2['member_lid'];
                        $member_table_name = $data2['table_name'];
                        $getMemName = $projectdb->query("SELECT name FROM $member_table_name WHERE id = '$member_lid';");
                        if ($getMemName->num_rows == 1) {
                            $membername2 = $getMemName->fetch_assoc();
                            if (preg_match("/shared/i", $member_table_name)) {
                                $name_member = $membername2['name']."&&&";
                                $membername[] = $name_member;
                            }else{
                                $membername[] = $membername2['name'];
                            }
                        }
                    }
                    asort($membername);
                    $projectdb->query("INSERT INTO tmp_dup_name_val (lid,members,table_name,name) VALUES ('$first_rule','" . implode(",", $membername) . "','$member_table_name','tp_fallback_type');");
                }
            }

            $rules_not_combine = array();
            $rules_combine = array();

            $is_first = 0;
            $the_same = 1;

            foreach ($rule_id as $rules) {

                //echo "Lid: " .$lid. "\n";
                //echo "Rules: " .$rules. "\n";

                $sqlTheSame = $projectdb->query("SELECT id, tp_sat_address_type, tp_fallback_type FROM nat_rules WHERE id = '$rules' AND tp_sat_bidirectional = '$tp_sat_bidirectional' AND op_zone_to = '$op_zone_to' AND op_to_interface = '$op_to_interface' AND is_dat = '$is_dat' AND op_service_lid = '$op_service_lid' AND op_service_table = '$op_service_table' "
                    . " AND tp_sat_type = '$tp_sat_type' AND tp_sat_address_type = '$tp_sat_address_type' AND tp_sat_interface = '$tp_sat_interface' AND tp_dat_port = '$tp_dat_port' AND tp_dat_address_lid = '$tp_dat_address_lid' AND tp_dat_address_table = '$tp_dat_address_table' "
                    . " AND implicit = '$implicit' AND preorpost = '$preorpost' AND active_active_device_binding = '$active_active_device_binding' AND nat_type = '$nat_type' AND tp_sat_interface_fallback = '$tp_sat_interface_fallback' AND tp_sat_ipaddress_fallback = '$tp_sat_ipaddress_fallback' AND tp_fallback_type = '$tp_fallback_type' ;");

                //echo "2. SELECT id, tp_sat_address_type, tp_fallback_type FROM nat_rules WHERE id = '$rules' AND tp_sat_bidirectional = '$tp_sat_bidirectional' AND op_zone_to = '$op_zone_to' AND op_to_interface = '$op_to_interface' AND is_dat = '$is_dat' AND op_service_lid = '$op_service_lid' AND op_service_table = '$op_service_table' "
                //    . " AND tp_sat_type = '$tp_sat_type' AND tp_sat_address_type = '$tp_sat_address_type' AND tp_sat_interface = '$tp_sat_interface' AND tp_dat_port = '$tp_dat_port' AND tp_dat_address_lid = '$tp_dat_address_lid' AND tp_dat_address_table = '$tp_dat_address_table' "
                //    . " AND implicit = '$implicit' AND preorpost = '$preorpost' AND active_active_device_binding = '$active_active_device_binding' AND nat_type = '$nat_type' AND tp_sat_interface_fallback = '$tp_sat_interface_fallback' AND tp_sat_ipaddress_fallback = '$tp_sat_ipaddress_fallback' AND tp_fallback_type = '$tp_fallback_type' ;";

                if (($sqlTheSame->num_rows == 1) && ($rules != $lid)){

                    // si es tp_sat_address_type = translated-address, mirar que tienen los mismo member_lid y table_name
                    $dataTS = $sqlTheSame->fetch_assoc();

                    if($dataTS['tp_sat_address_type'] == "translated-address"){

                        $members = $projectdb->query("SELECT member_lid, table_name FROM nat_rules_translated_address WHERE rule_lid = '$rules';");
                        if ($members->num_rows > 0) {
                            $membername = array();
                            while ($data2 = $members->fetch_assoc()) {
                                $member_lid = $data2['member_lid'];
                                $member_table_name = $data2['table_name'];
                                $getMemName = $projectdb->query("SELECT name FROM $member_table_name WHERE id = '$member_lid';");
                                if ($getMemName->num_rows == 1) {
                                    $membername2 = $getMemName->fetch_assoc();
                                    if (preg_match("/shared/i", $member_table_name)) {
                                        $name_member = $membername2['name']."&&&";
                                        $membername[] = $name_member;
                                    }else{
                                        $membername[] = $membername2['name'];
                                    }
                                }
                            }
                            asort($membername);
                            $projectdb->query("INSERT INTO tmp_dup_name_val (lid,members,table_name,name) VALUES ('$rules','" . implode(",", $membername) . "','$member_table_name','tp_sat_address_type');");

                        }

                        // Comprobar que tienen los mismos miembros
                        $getMembers = $projectdb->query("SELECT members, table_name FROM tmp_dup_name_val WHERE lid = '$lid' AND name = 'tp_sat_address_type';");
                        if ($getMembers->num_rows > 0) {
                            $dataM = $getMembers->fetch_assoc();

                            $members_first = $dataM['members'];
                            $table_name_first = $dataM['table_name'];

                            $getMembersS = $projectdb->query("SELECT id FROM tmp_dup_name_val WHERE lid = '$rules' AND members = '$members_first' AND table_name = '$table_name_first' AND name = 'tp_sat_address_type';");
                            if ($getMembersS->num_rows == 1) {
                                $the_same = 1;
                            }else{
                                $the_same = 0;
                            }
                        }
                    }

                    // Ahora comprobar si el tp_fallback_type es translated_address que tengan los mismos miembros
                    if ($the_same == 1){

                        if($dataTS['tp_fallback_type'] == "translated-address"){

                            $members = $projectdb->query("SELECT member_lid, table_name FROM nat_rules_translated_address_fallback WHERE rule_lid = '$rules';");
                            if ($members->num_rows > 0) {
                                $membername = array();
                                while ($data2 = $members->fetch_assoc()) {
                                    $member_lid = $data2['member_lid'];
                                    $member_table_name = $data2['table_name'];
                                    $getMemName = $projectdb->query("SELECT name FROM $member_table_name WHERE id = '$member_lid';");
                                    if ($getMemName->num_rows == 1) {
                                        $membername2 = $getMemName->fetch_assoc();
                                        if (preg_match("/shared/i", $member_table_name)) {
                                            $name_member = $membername2['name']."&&&";
                                            $membername[] = $name_member;
                                        }else{
                                            $membername[] = $membername2['name'];
                                        }
                                    }
                                }
                                asort($membername);
                                $projectdb->query("INSERT INTO tmp_dup_name_val (lid,members,table_name,name) VALUES ('$rules','" . implode(",", $membername) . "','$member_table_name','tp_fallback_type');");

                            }

                            // Comprobar que tienen los mismos miembros
                            $getMembers = $projectdb->query("SELECT members, table_name FROM tmp_dup_name_val WHERE lid = '$lid' AND name = 'tp_fallback_type';");
                            if ($getMembers->num_rows > 0) {
                                $dataM = $getMembers->fetch_assoc();

                                $members_first = $dataM['members'];
                                $table_name_first = $dataM['table_name'];

                                $getMembersS = $projectdb->query("SELECT id FROM tmp_dup_name_val WHERE lid = '$rules' AND members = '$members_first' AND table_name = '$table_name_first' AND name = 'tp_fallback_type';");
                                if ($getMembersS->num_rows == 1) {
                                    $the_same = 1;
                                }else{
                                    $the_same = 0;
                                }
                            }
                        }
                    }

                    if($the_same == 1){

                        if ($is_first == 0){
                            $rules_combine[] = $lid;
                            $is_first = 1;
                        }
                        $rules_combine[] = $rules;

                        $projectdb->query("UPDATE nat_rules_src SET rule_lid = '$lid' WHERE rule_lid = '$rules';");
                        $projectdb->query("UPDATE nat_rules_dst SET rule_lid = '$lid' WHERE rule_lid = '$rules';");
                        $projectdb->query("UPDATE nat_rules_from SET rule_lid = '$lid' WHERE rule_lid = '$rules';");
                        $projectdb->query("UPDATE nat_rules_translated_address SET rule_lid = '$lid' WHERE rule_lid = '$rules';");
                        $projectdb->query("UPDATE nat_rules_translated_address_fallback SET rule_lid = '$lid' WHERE rule_lid = '$rules';");
                        $projectdb->query("UPDATE nat_rules_tag SET rule_lid = '$lid' WHERE rule_lid = '$rules';");
                        $projectdb->query("UPDATE nat_rules_target SET rule_lid = '$lid' WHERE rule_lid = '$rules';");


                        $tagMergedID = getMergedTag($projectdb, $source);
                        $queryInsertTags = "INSERT INTO nat_rules_tag (source, member_lid, table_name, rule_lid) VALUES ('$source', $tagMergedID, 'tag', ".$lid.");";
                        $projectdb->query($queryInsertTags);

                        #Update the Descriptions
                        $getData = $projectdb->query("SELECT description FROM nat_rules WHERE id = '$rules' ");
                        $data = $getData->fetch_assoc();
                        $AddDescription = $data['description'];
                        if (($AddDescription == "") OR ( $AddDescription == null)) {

                        } else {
                            $getDescription = $projectdb->query("SELECT description FROM nat_rules WHERE id = '$lid'; ");
                            $data = $getDescription->fetch_assoc();
                            $Description = $data['description'];
                            if (($Description == "") OR ( $Description == null)) {
                                $AddDescription = addslashes($AddDescription);
                                $projectdb->query("UPDATE nat_rules SET description = '$AddDescription' WHERE id = '$lid'; ");
                            } else {
                                if ($AddDescription == $Description) {

                                } else {
                                    $AddDescription = $Description . " " . $AddDescription;
                                    $AddDescription = addslashes($AddDescription);
                                    $projectdb->query("UPDATE nat_rules SET description = '$AddDescription' WHERE id = '$lid'; ");
                                }
                            }
                        }
                        #Delete Rules
                        $projectdb->query("DELETE FROM nat_rules WHERE id = '$rules';");

                        #UPDATE LOGS TO THE NEW Rule
                        $projectdb->query("UPDATE logs SET obj_id = '$lid' WHERE obj_id = '$rules' AND obj_table = 'nat_rules';");

                    }
                    else{
                        if($rules != $lid){
                            $rules_not_combine[] = $rules;
                        }
                    }
                }
                else{
                    if($rules != $lid){
                        $rules_not_combine[] = $rules;
                    }
                }
            }

            if(count($rules_combine) > 0){

                #Delete Duplicated objects
                $tables = "nat_rules_dst,nat_rules_src,nat_rules_tag,nat_rules_translated_address,nat_rules_translated_address_fallback,nat_rules_tag";
                $array_table = explode(',',$tables);
                foreach ($array_table as $table){
                    $iRuleSrc = $projectdb->query("SELECT source, vsys, rule_lid, table_name, member_lid FROM $table WHERE rule_lid = '$lid' GROUP BY table_name,member_lid;");
                    $projectdb->query("DELETE FROM $table WHERE rule_lid = '$lid';");
                    while ($entity = $iRuleSrc->fetch_assoc()){
                        $projectdb->query("INSERT INTO $table (".implode(", ",array_keys($entity)).") VALUES ('".implode("', '",array_values($entity))."')");
                    }
                }

                $tables = "nat_rules_from";
                $array_table = explode(',',$tables);
                foreach ($array_table as $table){
                    $iRuleSrc = $projectdb->query("SELECT source, vsys, rule_lid, name FROM $table WHERE rule_lid = '$lid' GROUP BY name;");
                    $projectdb->query("DELETE FROM $table WHERE rule_lid = '$lid';");
                    while ($entity = $iRuleSrc->fetch_assoc()){
                        $projectdb->query("INSERT INTO $table (".implode(", ",array_keys($entity)).") VALUES ('".implode("', '",array_values($entity))."')");
                    }
                }

                # Target
                $tables = "nat_rules_target";
                $array_table = explode(',',$tables);
                foreach ($array_table as $table){
                    $iRuleSrc = $projectdb->query("SELECT source, vsys, rule_lid, name, device_vsys FROM $table WHERE rule_lid = '$lid' GROUP BY name, device_vsys;");
                    $projectdb->query("DELETE FROM $table WHERE rule_lid='$lid';");
                    while ($entity = $iRuleSrc->fetch_assoc()){
                        $projectdb->query("INSERT INTO $table (".implode(", ",array_keys($entity)).") VALUES ('".implode("', '",array_values($entity))."')");
                    }
                }

                add_log('ok', 'Combine Rules', 'Combine Nat RulesID [' . implode(",", $rules_combine) . '] to Rule ' . $lid . ' ', $source, 'No Action Required', '2');

                //echo json_encode(array("success"=>true));
                //echo json_encode(array("success"=>true, "msg"=>"Combine Nat RulesID [ ".  implode(",", $rules_combine) ." ] to Rule $lid. "));
                $msg = "Combine Nat RulesID [ ".  implode(",", $rules_combine) ." ] to Rule $lid. ";
            }
            else{
                $rules_not_combine[] = $lid;
                //echo json_encode(array("success"=>false, "msg"=>"The Nat Rules [ ".  implode(",", $rules_not_combine) ." ] cannot be combined because they don't share the same translation."));
                $msg = "The Nat Rules [ ".  implode(",", $rules_not_combine) ." ] cannot be combined because they don't share the same translation.";
            }
        }
        else{
            //echo json_encode(array("success"=>false, "msg"=>"Combine 2 or more Rules."));
            $msg = "Combine 2 or more Rules.";
        }

        return $msg;
    }

    return '';
}


function getMergedTag(mysqli $projectdb, int $source){
    $queryMergedTag = "SELECT id FROM tag WHERE name LIKE 'merged' AND source ='$source' AND vsys='shared' LIMIT 1";
    $resultMergedTag = $projectdb->query($queryMergedTag);
    if($resultMergedTag->num_rows==1){
        $data = $resultMergedTag->fetch_assoc();
        $tagMergedID = $data['id'];
    }
    else{
        $projectdb->query("INSERT INTO tag (name, comments, source, vsys, dummy, used, devicegroup, color) VALUES ('merged', 'Objecte created from a Merge action', '$source', 'shared', '0', '1','Expedition','color1')");
        $tagMergedID = $projectdb->insert_id;
    }

    return $tagMergedID;
}

function getProfileTypeHash(mysqli $projectdb, string $ruleId, string $profileType):string{

    $hash="";

    if($profileType==="group") {
        $query = "SELECT p.name, MD5(IFNULL(p.xml,'')) as xml FROM security_rules_profiles rp, profiles_groups p WHERE rp.table_name='profiles_groups' AND rp.member_lid = p.id AND rp.rule_lid = '$ruleId' order by p.name";
    } else{
        $query= "SELECT p.name, MD5(IFNULL(p.xml,'')) as xml FROM security_rules_profiles rp, profiles p WHERE rp.table_name='profiles' AND rp.rule_lid = '$ruleId' AND rp.member_lid = p.id order by p.name";
    }

    $results = $projectdb->query($query);
    if($results->num_rows>0){
        while($data = $results->fetch_assoc()){
            $hash.=$data['xml'];
        }
    }

    return md5($hash);
}

function splitAndMakeMerge(mysqli $projectdb, int $source, string $projectName, string $selectionedGroup, string $mergeableType, string $updateDescriptions="yes"): array {
    $cases = array();
    $msg = array();


    switch($mergeableType){
        case 'Security':
            $ruleNames = array();
            $query = "SELECT id, name, numCategories, numSources, numDestinations, numApps, numUsers, numServices, numServicesGroups, numAppDefaultService, numTo, numFrom, disabled, negate_source, negate_destination, profile_type, MD5(IFNULL(schedule,'')) as md5Schedule, schedule
                      FROM security_rules rules
                      LEFT JOIN (SELECT rule_lid, count(*) as numCategories    FROM security_rules_categories  GROUP BY rule_lid) secCat       on rules.id = secCat.rule_lid
                      LEFT JOIN (SELECT rule_lid, count(*) as numTo            FROM security_rules_to  GROUP BY rule_lid) secTo       on rules.id = secTo.rule_lid
                      LEFT JOIN (SELECT rule_lid, count(*) as numFrom          FROM security_rules_from GROUP BY rule_lid) secFrom    on rules.id = secFrom.rule_lid
                      LEFT JOIN (SELECT rule_lid, count(*) as numSources       FROM security_rules_src GROUP BY rule_lid) secSrc      on rules.id = secSrc.rule_lid
                      LEFT JOIN (SELECT rule_lid, count(*) as numDestinations  FROM security_rules_dst GROUP BY rule_lid) secDst      on rules.id = secDst.rule_lid
                      LEFT JOIN (SELECT rule_lid, count(*) as numApps          FROM security_rules_app GROUP BY rule_lid) secApp      on rules.id = secApp.rule_lid
                      LEFT JOIN (SELECT rule_lid, count(*) as numUsers         FROM security_rules_usr GROUP BY rule_lid) secUsers    on rules.id = secUsers.rule_lid
                      LEFT JOIN (SELECT rule_lid, count(*) as numServices          FROM security_rules_srv, services WHERE services.name!='application-default' AND security_rules_srv.table_name='services' and security_rules_srv.member_lid=services.id GROUP BY rule_lid) secServices on rules.id = secServices.rule_lid
                      LEFT JOIN (SELECT rule_lid, count(*) as numServicesGroups    FROM security_rules_srv, services_groups_id WHERE services_groups_id.name!='application-default' AND security_rules_srv.table_name='services_groups_id' and security_rules_srv.member_lid=services_groups_id.id GROUP BY rule_lid) secServicesGroups on rules.id = secServicesGroups.rule_lid
                      LEFT JOIN (SELECT rule_lid, count(*) as numAppDefaultService FROM security_rules_srv, services WHERE services.name='application-default' AND security_rules_srv.table_name='services' and security_rules_srv.member_lid=services.id GROUP BY rule_lid) secAppDefault on rules.id = secAppDefault.rule_lid 
                      WHERE id in ($selectionedGroup)";

            $casesFound = array();
            $results = $projectdb->query($query);
            if($results->num_rows>0){
                while($data = $results->fetch_assoc()){
                    $rule_lid = $data['id'];
                    $ruleNames[$rule_lid] = $data['name'];
                    // Case Number uses a binary filter with the following bits:
                    // xyz   x=apps, y=users, z=services.
                    //Example: a rule with apps and services is 101, which in binary states for 5
                    $caseNumber = 0;
                    unset($md5ScheduleXml,$profileType);

                    if ($data['numCategories'] > 0){
                        $caseNumber += 8192;
                        $casesFound = array_unique(array_merge($casesFound, array(27)));
                    }
                    else{
                        $casesFound = array_unique(array_merge($casesFound, array(26)));
                    }

                    if (isset($data['profile_type']) && strtolower($data['profile_type']) !== "none"){
                        $profileType="";
                        $caseNumber += 4096;
                        $profileType = strtolower($data['profile_type']); // we will check the profile type using the method getProfileTypeHash
                        $casesFound = array_unique(array_merge($casesFound, array(25)));
                    }

                    if ($data['schedule']!==""){
                        $caseNumber += 2048;
                        $md5ScheduleXml = $data['md5Schedule'];
                        $casesFound = array_unique(array_merge($casesFound, array(23)));
                    }

                    if ($data['negate_destination'] > 0){
                        $caseNumber += 1024;
                        $casesFound = array_unique(array_merge($casesFound, array(21)));
                    }
                    else{
                        $casesFound = array_unique(array_merge($casesFound, array(20)));
                    }

                    if ($data['negate_source'] > 0){
                        $caseNumber += 512;
                        $casesFound = array_unique(array_merge($casesFound, array(19)));
                    }
                    else{
                        $casesFound = array_unique(array_merge($casesFound, array(18)));
                    }

                    if ($data['disabled'] > 0){
                        $caseNumber += 256;
                        $casesFound = array_unique(array_merge($casesFound, array(17)));
                    }
                    else{
                        $casesFound = array_unique(array_merge($casesFound, array(16)));
                    }

                    if ($data['numAppDefaultService'] > 0){
                        $caseNumber += 128;
                        $casesFound = array_unique(array_merge($casesFound, array(15)));
                    }
                    else{
                        $casesFound = array_unique(array_merge($casesFound, array(14)));
                    }

                    if ($data['numTo'] > 0)       {
                        $caseNumber += 64;
                        $casesFound = array_unique(array_merge($casesFound, array(13)));
                    }
                    else{
                        $casesFound = array_unique(array_merge($casesFound, array(12)));
                    }

                    if ($data['numFrom'] > 0)       {
                        $caseNumber += 32;
                        $casesFound = array_unique(array_merge($casesFound, array(11)));
                    }
                    else{
                        $casesFound = array_unique(array_merge($casesFound, array(10)));
                    }

                    if ($data['numSources'] > 0)       {
                        $caseNumber += 16;
                        $casesFound = array_unique(array_merge($casesFound, array(9)));
                    }
                    else{
                        $casesFound = array_unique(array_merge($casesFound, array(8)));
                    }

                    if ($data['numDestinations'] > 0){
                        $caseNumber += 8;
                        $casesFound = array_unique(array_merge($casesFound, array(7)));
                    }
                    else{
                        $casesFound = array_unique(array_merge($casesFound, array(6)));
                    }

                    if ($data['numApps'] > 0){
                        $caseNumber += 4;
                        $casesFound = array_unique(array_merge($casesFound, array(5)));
                    }
                    else{
                        $casesFound = array_unique(array_merge($casesFound, array(4)));
                    }

                    if ($data['numUsers'] > 0){
                        $caseNumber += 2;
                        $casesFound = array_unique(array_merge($casesFound, array(3)));
                    }
                    else{
                        $casesFound = array_unique(array_merge($casesFound, array(2)));
                    }

                    if ($data['numServices'] > 0 || $data['numServicesGroups'] > 0){
                        $caseNumber += 1;
                        $casesFound = array_unique(array_merge($casesFound, array(1)));
                    }
                    else{
                        $casesFound = array_unique(array_merge($casesFound, array(0)));
                    }

                    //Group the cases by types
                    //Type1: Simple one where there's not a schedule neither a profile defined
                    if(!isset($md5ScheduleXml) && !isset($profileType)){
                        $cases[$caseNumber][] = $rule_lid;
                    }
                    //Type2: Schedule is defined but profile is not defined
                    else if(isset($md5ScheduleXml) && !isset($profileType)){
                        $cases[$caseNumber . "-" . $md5ScheduleXml][] = $rule_lid;
                    }
                    //Type3: Schedule is not defined but profile is defined
                    else if(!isset($md5ScheduleXml) && isset($profileType)){
                        $profileTypeHash = getProfileTypeHash($projectdb, $rule_lid, $profileType);
                        $cases[$caseNumber . "-" . $profileTypeHash][] = $rule_lid;
                    }
                    //Type4: Schedule is defined and profile is defined
                    else if(isset($md5ScheduleXml) && isset($profileType)){
                        $profileTypeHash = getProfileTypeHash($projectdb, $rule_lid, $profileType);
                        $cases[$caseNumber . "-" . $md5ScheduleXml . "-" . $profileTypeHash][] = $rule_lid;
                    }
                }
            }

            $mergeable_cases = true;
            foreach($cases as $case){
                if(count($case)>1) {
                    $ruleSubNames = [];
                    foreach ($case as $lid ){
                        $ruleSubNames[$lid] = $ruleNames[$lid];
                    }
                    $responseText = makeMergeSecurityRules($projectdb, $source, $projectName, implode(',', $case),$updateDescriptions, $ruleSubNames);
                    $msg[] = $responseText;
                }else{
                    $mergeable_cases = false;
                }
            }
            $distinctFields = array();
            if(!$mergeable_cases) {
                //print_r($casesFound);
                if (in_array(26, $casesFound) || in_array(27, $casesFound)) $distinctFields[] = "URL Category";
                if (in_array(24, $casesFound) || in_array(25, $casesFound)) $distinctFields[] = "Profile";
                if (in_array(22, $casesFound) || in_array(23, $casesFound)) $distinctFields[] = "Schedule";
                if (in_array(18, $casesFound) && in_array(19, $casesFound) || (in_array(20, $casesFound) && in_array(21, $casesFound))) $distinctFields[] = "Negated Source/Destination";
                if (in_array(16, $casesFound) && in_array(17, $casesFound)) $distinctFields[] = "Disabled";
                if (in_array(10, $casesFound) && in_array(11, $casesFound)) $distinctFields[] = "From Zone";
                if (in_array(8, $casesFound) && in_array(9, $casesFound)) $distinctFields[] = "Sources";
                if (in_array(2, $casesFound) && in_array(3, $casesFound)) $distinctFields[] = "Users";
                if (in_array(12, $casesFound) && in_array(13, $casesFound)) $distinctFields[] = "To Zone";
                if (in_array(6, $casesFound) && in_array(7, $casesFound)) $distinctFields[] = "Destinations";
                if (in_array(4, $casesFound) && in_array(5, $casesFound)) $distinctFields[] = "Applications";
                if (in_array(0, $casesFound) && in_array(1, $casesFound) || in_array(14, $casesFound) && in_array(15, $casesFound)) $distinctFields[] = "Services";
            }
            if(count($msg)==0){
                $msg[] = "<i class='fa fa-comment' style='color:#ee611f' aria-hidden='true'></i> Rules <i><b>". implode(", ", $ruleNames)."</b></i> were not merged because they combine <b>incompatible Values</b> for ".implode(", ", $distinctFields);
            }
            else if(count($distinctFields)>0){
                if(count($distinctFields)==1)
                    $msg[] = "Not all rules were "           ."merged because they combine <b>incompatible Values</b> for the field: ".implode(", ", $distinctFields);
                else
                    $msg[] = "Not all rules were "           ."merged because they combine <b>incompatible Values</b> for the fields: ".implode(", ", $distinctFields);
            }

            break;

        case 'NAT':
            $query = "SELECT id, if(op_service_lid=0, 0, 1) as numServices 
                      FROM nat_rules rules
                      WHERE id in ($selectionedGroup)";
            //LEFT JOIN (SELECT rule_lid, count(*) as numServices FROM security_rules_srv GROUP BY rule_lid) secServices on rules.id = secServices.rule_lid

            $results = $projectdb->query($query);
            if($results->num_rows>0){
                while($data = $results->fetch_assoc()){
                    $rule_lid = $data['id'];
                    $caseNumber = 0;
                    if ($data['numServices'] > 0)   $caseNumber += 1;
                    $cases[$caseNumber][]=$rule_lid;
                }
            }

            foreach($cases as $case){
                if(count($case)>1) {
                    $responseText = makeMergeNATRules($projectdb, $source, $projectName, implode(',', $case));
                    $msg[] = $responseText;
                }
            }

            if(count($msg)==0){
                $msg[] = "Rules $selectionedGroup were not merged as they have combine <b>ANY</b> and <b>Values</b> for Services";
            }
            break;
    }




    return $msg;
}

function makeMergeSecurityRules(mysqli $projectdb, int $source, String $projectName, String $selection, String $updateDescriptions="yes", array $ruleNames=[]): String{
    if ($selection != ""){

        //take_snapshot_last($projectName);
        $rule_ids = explode(',', $selection);


        $first_rule = $rule_ids[0];
        $getMaxLid = $projectdb->query("SELECT max(id) AS max FROM security_rules;");
        $getPosition = $projectdb->query("SELECT min(position) AS position FROM security_rules WHERE id in ($selection);");
        $positionArr = $getPosition->fetch_assoc();
        $position = $positionArr['position'];
        $getMax = $getMaxLid->fetch_assoc();
        $lid = intval($getMax['max'])+1;
        $sql = $projectdb->query("SELECT * FROM security_rules WHERE id = '$first_rule';");

        $entity = $sql->fetch_assoc();
        $entity["id"] = "$lid";
        $entity["description"] = addslashes($entity["description"]);
        $entity["position"] = $position;
        $firstRuleName = $entity["name"];
        $query = "INSERT INTO security_rules (".implode(", ",array_keys($entity)).") VALUES ('".implode("', '",array_values($entity))."')";
//        echo $query;
        $projectdb->query($query);



        //Mark this security rule as coming from a merge
//        $tagMergedID = $this->getMergedTag();
        $tagMergedID = getMergedTag($projectdb, $source);

        $queryInswertTags = "INSERT INTO security_rules_tag (source, member_lid, table_name, rule_lid) VALUES ('$source', $tagMergedID, 'tag', ".$entity["id"].");";
        $projectdb->query($queryInswertTags);

        // Update security_rules_profiles with the first rules from merge
        $projectdb->query("UPDATE security_rules_profiles SET rule_lid = '$lid' WHERE rule_lid = '$first_rule';");

        $projectdb->query("UPDATE security_rules_src SET rule_lid = '$lid' WHERE rule_lid in ($selection);");
        $projectdb->query("UPDATE security_rules_dst SET rule_lid = '$lid' WHERE rule_lid in ($selection);");

        $projectdb->query("UPDATE security_rules_srv SET rule_lid = '$lid' WHERE rule_lid in ($selection);");
        $projectdb->query("UPDATE security_rules_from SET rule_lid = '$lid' WHERE rule_lid in ($selection);");
        $projectdb->query("UPDATE security_rules_to SET rule_lid = '$lid' WHERE rule_lid in ($selection);");
        $projectdb->query("UPDATE security_rules_hip SET rule_lid = '$lid' WHERE rule_lid in ($selection);");
        $projectdb->query("UPDATE security_rules_tag SET rule_lid = '$lid' WHERE rule_lid in ($selection);");
        $projectdb->query("UPDATE security_rules_app SET rule_lid = '$lid' WHERE rule_lid in ($selection);");
        $projectdb->query("UPDATE security_rules_categories SET rule_lid = '$lid' WHERE rule_lid in ($selection);");
        $projectdb->query("UPDATE security_rules_usr SET rule_lid = '$lid' WHERE rule_lid in ($selection);");
        $projectdb->query("UPDATE security_rules_target SET rule_lid = '$lid' WHERE rule_lid in ($selection);");

        $projectdb->query("DELETE FROM security_rules_profiles WHERE rule_lid in ($selection);");
//        foreach ($rule_ids as $rules){
////            $projectdb->query("UPDATE security_rules_src SET rule_lid = '$lid' WHERE rule_lid = '$rules';");
////            $projectdb->query("UPDATE security_rules_dst SET rule_lid = '$lid' WHERE rule_lid = '$rules';");
////            $projectdb->query("UPDATE security_rules_srv SET rule_lid = '$lid' WHERE rule_lid = '$rules';");
////            $projectdb->query("UPDATE security_rules_from SET rule_lid = '$lid' WHERE rule_lid = '$rules';");
////            $projectdb->query("UPDATE security_rules_to SET rule_lid = '$lid' WHERE rule_lid = '$rules';");
////            $projectdb->query("UPDATE security_rules_hip SET rule_lid = '$lid' WHERE rule_lid = '$rules';");
////            $projectdb->query("UPDATE security_rules_tag SET rule_lid = '$lid' WHERE rule_lid = '$rules';");
////            $projectdb->query("UPDATE security_rules_app SET rule_lid = '$lid' WHERE rule_lid = '$rules';");
////            $projectdb->query("UPDATE security_rules_categories SET rule_lid = '$lid' WHERE rule_lid = '$rules';");
////            //$projectdb->query("UPDATE security_rules_profiles SET rule_lid = '$lid' WHERE rule_lid = '$rules';");
////            $projectdb->query("UPDATE security_rules_usr SET rule_lid = '$lid' WHERE rule_lid = '$rules';");
////            $projectdb->query("UPDATE security_rules_target SET rule_lid = '$lid' WHERE rule_lid = '$rules';");
////
////            // Delete from security_rules_profiles the next members that then update with the first rule_lid
////            $projectdb->query("DELETE FROM security_rules_profiles WHERE rule_lid = '$rules';");
//
//            #Update the Descriptions
//            $getData = $projectdb->query("SELECT description FROM security_rules WHERE id = '$rules' ");
//            $data = $getData->fetch_assoc();
//            $AddDescription = $data['description'];
//            if (($AddDescription == "") OR ($AddDescription == null)){}
//            else {
//                $getDescription = $projectdb->query("SELECT description FROM security_rules WHERE id = '$lid'; ");
//                $data = $getDescription->fetch_assoc();
//                $Description = $data['description'];
//                if (($Description == "") OR ($Description == null)){
//                    $AddDescription = addslashes($AddDescription);
//                    $projectdb->query("UPDATE security_rules SET description = '$AddDescription' WHERE id = '$lid'; ");
//                }
//                else {
//                    if ($AddDescription == $Description){}
//                    else {
//                        $AddDescription = $Description." ".$AddDescription;
//                        $AddDescription = addslashes($AddDescription);
//                        $projectdb->query("UPDATE security_rules SET description = '$AddDescription' WHERE id = '$lid'; ");
//                    }
//                }
//            }
////            #Delete Rules
////            $projectdb->query("DELETE FROM security_rules where id = '$rules';");
////
////            #UPDATE LOGS TO THE NEW Rule
////            $projectdb->query("UPDATE logs SET obj_id = '$lid' WHERE obj_id = '$rules' AND obj_table = 'security_rules';");
//        }

        #Update the Descriptions
        if ($updateDescriptions=="yes"){
            $descriptions= array();
            $names = array();
            $getData = $projectdb->query("SELECT description, name FROM security_rules WHERE id in ($selection);");
            while($data = $getData->fetch_assoc()){
                $descriptions[] = $data['description'];
                $names[] = $data['name'];
            }

            $descriptions = array_unique(array_filter($descriptions));
            if(count($descriptions)>0) {
                $FinalDescription = "From merged rules: " . implode(", ", $names) . '. ' . implode(" ", $descriptions);
            }
            else{
                $FinalDescription = "From merged rules: " . implode(", ", $names);
            }

            $FinalDescription =    truncate_descriptions($FinalDescription);

            $projectdb->query("UPDATE security_rules SET description = '$FinalDescription' WHERE id = '$lid'; ");
        }




        #Delete Rules
        $projectdb->query("DELETE FROM security_rules where id in ($selection) ;");
        #UPDATE LOGS TO THE NEW Rule
        $projectdb->query("UPDATE logs SET obj_id = '$lid' WHERE obj_id in($selection) AND obj_table = 'security_rules';");



        #Delete Duplicated objects
        $tables = "security_rules_from,security_rules_to,security_rules_categories,security_rules_usr";
        $array_table = explode(',',$tables);
        foreach ($array_table as $table){
            $iRuleSrc = $projectdb->query("SELECT source, vsys, rule_lid, name FROM $table WHERE rule_lid = '$lid' GROUP BY BINARY name;");
            $projectdb->query("DELETE FROM $table WHERE rule_lid = '$lid';");
            while ($entity = $iRuleSrc->fetch_assoc()){
                if ($table=="security_rules_usr"){
                    $entity['name']=addslashes($entity['name']);
                }
                $projectdb->query("INSERT INTO $table (".implode(", ",array_keys($entity)).") VALUES ('".implode("', '",array_values($entity))."')");
            }
        }
        $tables = "security_rules_dst,security_rules_src,security_rules_srv,security_rules_tag,security_rules_hip,security_rules_app";
        $array_table = explode(',',$tables);
        foreach ($array_table as $table){
            $iRuleSrc = $projectdb->query("SELECT source, vsys, rule_lid, table_name, member_lid FROM $table WHERE rule_lid = '$lid' GROUP BY table_name, member_lid;");
            $projectdb->query("DELETE FROM $table WHERE rule_lid = '$lid';");
            while ($entity = $iRuleSrc->fetch_assoc()){
                $projectdb->query("INSERT INTO $table (".implode(", ",array_keys($entity)).") VALUES ('".implode("', '",array_values($entity))."')");
            }
        }

        $tables = "security_rules_profiles";
        $array_table = explode(',',$tables);
        foreach ($array_table as $table){
            $iRuleSrc = $projectdb->query("SELECT source, vsys, rule_lid, member_lid, table_name, type FROM $table WHERE rule_lid = '$lid' GROUP BY table_name,member_lid;");
            $projectdb->query("DELETE FROM $table WHERE rule_lid = '$lid';");
            while ($entity = $iRuleSrc->fetch_assoc()){
                $projectdb->query("INSERT INTO $table (".implode(", ",array_keys($entity)).") VALUES ('".implode("', '",array_values($entity))."')");
            }
        }

        # Target
        $tables = "security_rules_target";
        $array_table = explode(',',$tables);
        foreach ($array_table as $table){
            $iRuleSrc = $projectdb->query("SELECT source, vsys, rule_lid, name, device_vsys FROM $table WHERE rule_lid = '$lid' GROUP BY name, device_vsys;");
            $projectdb->query("DELETE FROM $table WHERE rule_lid='$lid';");
            while ($entity = $iRuleSrc->fetch_assoc()){
                $projectdb->query("INSERT INTO $table (".implode(", ",array_keys($entity)).") VALUES ('".implode("', '",array_values($entity))."')");
            }
        }

        add_log('ok', 'Combine Rules', 'Combine Security RulesID ['.$selection.'] to Rule '.$lid.' ', $source, 'No Action Required', '2', $projectdb);

        //$msg = "Combine Security RulesID [ ".$selection." ] to Rule $lid. ";
        //$firstRuleName = array_pop($ruleNames);

        $msg = "<i class=\"fa fa-check-circle-o\" style='color:#41a83e' aria-hidden=\"true\"></i> Security Rules <i><b>".implode(", ", $ruleNames)."</b></i> (IDs[ ".implode(", ",array_keys($ruleNames))." ]) were combined into Rule <i><b>".$firstRuleName."</b></i>. New rule ID is $lid.";

        #Clean Application-Default from Services if there are more than one
        $getAppDefault=$projectdb->query("SELECT id FROM services WHERE name = 'application-default' AND vsys = 'shared' AND source = '$source';");
        if ($getAppDefault->num_rows==1){
            $data = $getAppDefault->fetch_assoc();
            $app_default_id = $data['id'];
        }
        $getServices=$projectdb->query("SELECT id FROM security_rules_srv WHERE rule_lid = '$lid';");
        if ($getServices->num_rows>1){
            $projectdb->query("DELETE FROM security_rules_srv WHERE rule_lid = '$lid' AND table_name = 'services' AND member_lid = '$app_default_id';");
        }

//        echo "$msg\n";
        return $msg;
    }

    return '';
}


function setMergeNatRules(STRING $projectName, ARRAY $params){
    global $projectdb;
    global $app;

    $msg = array();

    $projectdb = selectDatabase($projectName);
    //take_snapshot_last($projectName);
    $user = $app->container->sentinel->getUser();
    $user_id = $user->id;

    $source = $params['source'];

    $selection = $params['selection'];
    $id_cons = $params['id_cons'];

    if(count($selection) == 0){
        $selectionedGroups = array();
        //This will identify the groups that need to be merged. hash_rules shows groups that are mergeable based on the selected fields. Visible=1 determines which groups the user wants to really merge
        //$getConsolidationTools = $projectdb->query("SELECT rules_lid FROM hash_rules WHERE visible = '1' AND table_name = 'nat_rules';");
        $getConsolidationTools = $projectdb->query("SELECT id, rules_lid FROM hash_rules WHERE id IN ($id_cons);");

        if ($getConsolidationTools->num_rows > 0) {
            while ($dataRT = $getConsolidationTools->fetch_assoc()){
                if($dataRT['rules_lid'] != ""){
                    $selectionedGroups[] = $dataRT['rules_lid'];
                }
            }
        }
        else{
            //There is a second way to request merges. We need to check if this is the best way to set the filtering criteria.
            $getResultsTools = $projectdb->query("SELECT member_lid FROM tools_results WHERE table_name = 'nat_rules' AND source = '$source' AND user_id = '$user_id';");
            if ($getResultsTools->num_rows > 0) {
                while ($dataRT = $getResultsTools->fetch_assoc()){
                    if($dataRT['member_lid'] != ""){
                        $member_lid[] = $dataRT['member_lid'];
                    }else{
                        $member_lid = array();
                    }
                }

                if(count($member_lid) > 0){
                    $selectionedGroups = array(implode(',',$member_lid));
                }
            }
        }

        //Given the new selection, we would have to check how to group the rules given the merge criteria. Additionally
        //Divide the rules in 4 groups within each found group:
        // app-ids, user-ids
        // app-ids, no user-ids
        // No app-ids, user-ids
        // No app-ids, no user-ids
        foreach ($selectionedGroups as $selectionedGroup){
            $msg = array_merge($msg, splitAndMakeMerge($projectdb, $source, $projectName,$selectionedGroup, 'NAT'));
        }
    }
    else{
        $msg = splitAndMakeMerge($projectdb, $source, $projectName,$selection, 'NAT');
    }

    if($id_cons != ""){
        $projectdb->query("UPDATE hash_rules SET fixed = '1' WHERE id IN ($id_cons); ");
    }

    foreach ($msg as &$entry){
        $entry = "<li>$entry</li>";
    }

    $message = array();
    $message['code'] = true;
    $message['count'] = "";
    $message['msg'] = $msg;

    return $message;

}


function setMergeAppoverrideRules(STRING $projectName, ARRAY $params){

    global $projectdb;
    global $app;

    $projectdb = selectDatabase($projectName);
    //take_snapshot_last($projectName);
    $user = $app->container->sentinel->getUser();
    $user_id = $user->id;

    $source = $params['source'];

    $selection = $params['selection'];
    $id_cons = $params['id_cons'];

    if(count($selection) == 0){

        //$getConsolidationTools = $projectdb->query("SELECT rules_lid FROM hash_rules WHERE visible = '1' AND table_name = 'appoverride_rules';");
        $getConsolidationTools = $projectdb->query("SELECT id, rules_lid FROM hash_rules WHERE id IN ($id_cons);");

        if ($getConsolidationTools->num_rows > 0) {

            while ($dataRT = $getConsolidationTools->fetch_assoc()){
                if($dataRT['rules_lid'] != ""){
                    $selection = $dataRT['rules_lid'];
                }else{
                    $selection = "";
                }
            }
        }

        $getResultsTools = $projectdb->query("SELECT member_lid FROM tools_results WHERE table_name = 'appoverride_rules' AND source = '$source' AND user_id = '$user_id';");

        if ($getResultsTools->num_rows > 0) {

            while ($dataRT = $getResultsTools->fetch_assoc()){
                if($dataRT['member_lid'] != ""){
                    $member_lid[] = $dataRT['member_lid'];
                }else{
                    $member_lid = array();
                }
            }

            if(count($member_lid) > 0){
                $selection = implode(',',$member_lid);
            }
        }
    }

    if ($selection != ""){

        //take_snapshot_last($projectName);

        $rule_ids = explode(',', $selection);
        $first_rule = $rule_ids[0];
        $getMaxLid = $projectdb->query("SELECT max(id) AS max FROM appoverride_rules;");
        $getMax = $getMaxLid->fetch_assoc();
        $lid = intval($getMax['max'])+1;
        $sql = $projectdb->query("SELECT * FROM appoverride_rules WHERE id = '$first_rule';");
        $entity = $sql->fetch_assoc();
        $entity["id"] = "$lid";
        $projectdb->query("INSERT INTO appoverride_rules (".implode(", ",array_keys($entity)).") VALUES ('".implode("', '",array_values($entity))."')");

        foreach ($rule_ids as $rules){

            $projectdb->query("UPDATE appoverride_rules_src SET rule_lid = '$lid' WHERE rule_lid = '$rules';");
            $projectdb->query("UPDATE appoverride_rules_dst SET rule_lid = '$lid' WHERE rule_lid = '$rules';");
            $projectdb->query("UPDATE appoverride_rules_from SET rule_lid = '$lid' WHERE rule_lid = '$rules';");
            $projectdb->query("UPDATE appoverride_rules_to SET rule_lid = '$lid' WHERE rule_lid = '$rules';");
            $projectdb->query("UPDATE appoverride_rules_tag SET rule_lid = '$lid' WHERE rule_lid = '$rules';");
            $projectdb->query("UPDATE appoverride_rules_target SET rule_lid = '$lid' WHERE rule_lid = '$rules';");
            #Update the Descriptions
            $getData = $projectdb->query("SELECT description FROM security_rules WHERE id = '$rules' ");
            $data = $getData->fetch_assoc();
            $AddDescription = $data['description'];
            if (($AddDescription == "") OR ($AddDescription == null)){}
            else {
                $getDescription = $projectdb->query("SELECT description FROM appoverride_rules WHERE id = '$lid'; ");
                $data = $getDescription->fetch_assoc();
                $Description = $data['description'];
                if (($Description == "") OR ($Description == null)){
                    $AddDescription = addslashes($AddDescription);
                    $projectdb->query("UPDATE appoverride_rules SET description = '$AddDescription' WHERE id = '$lid'; ");
                }
                else {
                    if ($AddDescription == $Description){}
                    else {
                        $AddDescription = $Description." ".$AddDescription;
                        $AddDescription = addslashes($AddDescription);
                        $projectdb->query("UPDATE appoverride_rules SET description = '$AddDescription' WHERE id = '$lid'; ");
                    }
                }
            }
            #Delete Rules
            $projectdb->query("DELETE FROM appoverride_rules where id = '$rules';");
            #UPDATE LOGS TO THE NEW Rule
            $projectdb->query("UPDATE logs SET obj_id = '$lid' WHERE obj_id = '$rules' AND obj_table = 'appoverride_rules';");
        }

        #Delete Duplicated objects
        $tables = "appoverride_rules_from,appoverride_rules_to";
        $array_table = explode(',',$tables);
        foreach ($array_table as $table){
            $iRuleSrc = $projectdb->query("SELECT source, vsys, rule_lid, name FROM $table WHERE rule_lid = '$lid' GROUP BY name;");
            $projectdb->query("DELETE FROM $table WHERE rule_lid = '$lid';");
            while ($entity = $iRuleSrc->fetch_assoc()){
                $projectdb->query("INSERT INTO $table (".implode(", ",array_keys($entity)).") VALUES ('".implode("', '",array_values($entity))."')");
            }
        }
        $tables = "appoverride_rules_dst,appoverride_rules_src,appoverride_rules_tag";
        $array_table = explode(',',$tables);
        foreach ($array_table as $table){
            $iRuleSrc = $projectdb->query("SELECT source, vsys, rule_lid, table_name, member_lid FROM $table WHERE rule_lid = '$lid' GROUP BY table_name, member_lid;");
            $projectdb->query("DELETE FROM $table WHERE rule_lid = '$lid';");
            while ($entity = $iRuleSrc->fetch_assoc()){
                $projectdb->query("INSERT INTO $table (".implode(", ",array_keys($entity)).") VALUES ('".implode("', '",array_values($entity))."')");
            }
        }


        # Target
        $tables = "appoverride_rules_target";
        $array_table = explode(',',$tables);
        foreach ($array_table as $table){
            $iRuleSrc = $projectdb->query("SELECT source, vsys, rule_lid, name, device_vsys FROM $table WHERE rule_lid = '$lid' GROUP BY name, device_vsys;");
            $projectdb->query("DELETE FROM $table WHERE rule_lid='$lid';");
            while ($entity = $iRuleSrc->fetch_assoc()){
                $projectdb->query("INSERT INTO $table (".implode(", ",array_keys($entity)).") VALUES ('".implode("', '",array_values($entity))."')");
            }
        }

        add_log('ok', 'Combine Rules', 'Combine Application Override RulesID ['.$selection.'] to Rule '.$lid.' ', $source, 'No Action Required', '2');

        $msg = "Combine Application Override RulesID [ ".$selection." ] to Rule $lid. ";

    }

    if($id_cons != ""){
        $projectdb->query("UPDATE hash_rules SET fixed = '1' WHERE id IN ($id_cons); ");
    }

    $message = array();
    $message['code'] = true;
    $message['count'] = "";
    $message['msg'] = $msg;

    return $message;

}


function getConsolidationRules(STRING $projectName, ARRAY $params){

    global $projectdb;
    global $app;

    $projectdb = selectDatabase($projectName);

    $user = $app->container->sentinel->getUser();
    $user_id = $user->id;

    $vsys = $params['vsys'];
    $source = $params['source'];
    $check_action_sec = $params['check_action_sec'];
    $check_app_sec = $params['check_app_sec'];
    $check_dst_sec = $params['check_dst_sec'];
    $check_from_sec = $params['check_from_sec'];
    $check_name_sec = $params['check_name_sec'];
    $check_source_sec = $params['check_source_sec'];
    $check_srv_sec = $params['check_srv_sec'];
    $check_to_sec = $params['check_to_sec'];
    $check_target_sec = $params['check_target_sec'];

    $check_dst_nat = $params['check_dst_nat'];
    $check_from_nat = $params['check_from_nat'];
    $check_name_nat = $params['check_name_nat'];
    $check_source_nat = $params['check_source_nat'];
    $check_srv_nat = $params['check_srv_nat'];
    $check_to_nat = $params['check_to_nat'];
    $check_target_nat = $params['check_target_nat'];

    $check_from_app = $params['check_from_app'];
    $check_to_app = $params['check_to_app'];
    $check_source_app = $params['check_source_app'];
    $check_dst_app = $params['check_dst_app'];
    $check_app_app = $params['check_app_app'];
    $check_protocol_app = $params['check_protocol_app'];
    $check_port_app = $params['check_port_app'];
    $check_name_app = $params['check_name_app'];
    $check_target_app = $params['check_target_app'];



    $table_name = $params['table_name'];

    $getIdRulesToConsolidation = $projectdb->query("SELECT member_lid FROM tools_results WHERE table_name = '$table_name' AND source = '$source' AND user_id = '$user_id' ORDER BY id DESC; ");

    if($getIdRulesToConsolidation->num_rows > 0){

        $ruleids_filters = array();
        while($data = $getIdRulesToConsolidation->fetch_assoc()){
            $ruleids_filters[] = $data['member_lid'];
        }
    }
    else{
        require_once INC_ROOT."/bin/projects/tools/prepareQuery.php";
        //$vsys_query = prepareVsysQuery($projectdb, $vsys, $source);
        if($vsys == "all"){
            $vsys_query = "";
        }else{
            $vsys_query = " AND vsys = '$vsys' ";
        }

        // Hacerlo para todas las reglas
        $ruleids_filters = array();
        $getIdRules = $projectdb->query("SELECT id FROM $table_name WHERE source = '$source' $vsys_query; ");
        if($getIdRules->num_rows >0) {
            $ruleids_filters = array();
            while($data = $getIdRules->fetch_assoc()){
                $ruleids_filters[] = $data['id'];
            }
        }
    }

    $projectdb->query("DELETE FROM hash WHERE table_name = '$table_name'; ");
    $projectdb->query("DELETE FROM hash_rules WHERE table_name = '$table_name'; ");

    foreach($ruleids_filters as $key => $rule_lid){
        $array_names = array();

        if($check_source_sec == "true"){
            $array_names[] = setHashToMemberLid($rule_lid, 'security_rules_src', 'Source', $vsys, $source);
        }
        if($check_dst_sec == "true"){
            $array_names[] = setHashToMemberLid($rule_lid, 'security_rules_dst', 'Destination', $vsys, $source);
        }
        if($check_srv_sec == "true"){
            $array_names[] = setHashToMemberLid($rule_lid, 'security_rules_srv', 'Service', $vsys, $source);
        }
        if($check_app_sec == "true"){
            $array_names[] = setHashToMemberLid($rule_lid, 'security_rules_app', 'Application', $vsys, $source);
        }
        if($check_from_sec == "true"){
            $array_names[] = setHashToName($rule_lid, 'security_rules_from', 'From', $vsys, $source);
        }
        if($check_to_sec == "true"){
            $array_names[] = setHashToName($rule_lid, 'security_rules_to', 'To', $vsys, $source);
        }
        if($check_target_sec == "true"){
            $array_names[] = setHashToName($rule_lid, 'security_rules_target', 'Target', $vsys, $source);
        }
        if($check_name_sec == "true"){
            $array_names[] = setHashToName($rule_lid, 'security_rules', 'Name', $vsys, $source);
        }
        if($check_action_sec == "true"){
            $array_names[] = setHashToName($rule_lid, 'security_rules', 'Action', $vsys, $source);
        }
        if($check_source_nat == "true"){
            $array_names[] = setHashToMemberLid($rule_lid, 'nat_rules_src', 'Source', $vsys, $source);
        }
        if($check_dst_nat == "true"){
            $array_names[] = setHashToMemberLid($rule_lid, 'nat_rules_dst', 'Destination', $vsys, $source);
        }
        if($check_srv_nat == "true"){
            $array_names[] = setHashToMemberLid($rule_lid, 'nat_rules_srv', 'Service', $vsys, $source);
        }
        if($check_from_nat == "true"){
            $array_names[] = setHashToName($rule_lid, 'nat_rules_from', 'From', $vsys, $source);
        }
        if($check_to_nat == "true"){
            $array_names[] = setHashToName($rule_lid, 'nat_rules', 'To', $vsys, $source);
        }
        if($check_name_nat == "true"){
            $array_names[] = setHashToName($rule_lid, 'nat_rules', 'Name', $vsys, $source);
        }
        if($check_target_nat == "true"){
            $array_names[] = setHashToName($rule_lid, 'nat_rules_target', 'Target', $vsys, $source);
        }

        if($check_source_app == "true"){
            $array_names[] = setHashToMemberLid($rule_lid, 'appoverride_rules_src', 'Source', $vsys, $source);
        }
        if($check_dst_app == "true"){
            $array_names[] = setHashToMemberLid($rule_lid, 'appoverride_rules_dst', 'Destination', $vsys, $source);
        }
        if($check_from_app == "true"){
            $array_names[] = setHashToName($rule_lid, 'appoverride_rules_from', 'From', $vsys, $source);
        }
        if($check_to_app == "true"){
            $array_names[] = setHashToName($rule_lid, 'appoverride_rules_to', 'To', $vsys, $source);
        }
        if($check_app_app == "true"){
            $array_names[] = setHashToMemberLid($rule_lid, 'appoverride_rules_app', 'Application', $vsys, $source);
        }
        if($check_protocol_app == "true"){
            $array_names[] = setHashToName($rule_lid, 'appoverride_rules', 'Protocol', $vsys, $source);
        }
        if($check_port_app == "true"){
            $array_names[] = setHashToName($rule_lid, 'appoverride_rules', 'Port', $vsys, $source);
        }
        if($check_name_app == "true"){
            $array_names[] = setHashToName($rule_lid, 'nat_rules', 'Name', $vsys, $source);
        }
        if($check_target_app == "true"){
            $array_names[] = setHashToName($rule_lid, 'appoverride_rules_target', 'Target', $vsys, $source);
        }

        $hash = md5(json_encode($array_names));

        $projectdb->query("INSERT INTO hash (id, rule_lid, vsys, source, filter_hash, hash, visible, table_name) "
            . "VALUES (NULL, '$rule_lid', '$vsys', '$source', 'global', '$hash', '1', '$table_name'); ");

    }

    $getRulesConsolidation = $projectdb->query("SELECT COUNT(id) AS t, hash FROM hash WHERE table_name = '$table_name' GROUP BY hash HAVING t>1; ");

    $i = 1;
    while($data = $getRulesConsolidation->fetch_assoc()){
        $hash = $data['hash'];

        $getRulesHash = $projectdb->query("SELECT rule_lid FROM hash WHERE hash = '$hash' AND table_name = '$table_name'; ");
        $ruleids_hash = array();

        while($data_hash = $getRulesHash->fetch_assoc()){
            $ruleids_hash[] = $data_hash['rule_lid'];
        }
        $count_case = count($ruleids_hash);
        $projectdb->query("INSERT INTO hash_rules (id, hash, filter_hash, vsys, source, visible, table_name, rules_lid) "
            . " VALUES (NULL, '$hash', 'Case $i ($count_case Rules)', '$vsys', '$source', '1', '$table_name', '" . implode(",", $ruleids_hash) . "' ) ;");

        $i ++;
    }

}


function setVisibleHash(STRING $projectName, ARRAY $params){

    $id_cons = $params['id_cons'];

    global $projectdb;
    $projectdb = selectDatabase($projectName);

    $projectdb->query("UPDATE hash_rules SET visible = '0' ;");
    $projectdb->query("UPDATE hash_rules SET visible = '1' WHERE id IN ($id_cons); ");

    $msg = "Set visibled.";

    $message = array();
    $message['code'] = true;
    $message['count'] = "";
    $message['msg'] = $msg;

    return $message;
    
}


/*function replaceAddressGroupsInOtherRulesZones(STRING $projectName, $primary_member_lid, $all_names_for_replace, $source){

    global $projectdb;
    $projectdb = selectDatabase($projectName);

    $getNamePanNew = $projectdb->query("SELECT name FROM address_groups_id WHERE id = '$primary_member_lid'; ");
    if($getNamePanNew->num_rows > 0){
        $dataNP = $getNamePanNew->fetch_assoc();
        $name_int_new = $dataNP['name'];

        // SEARCH IN OTHER RULES
        $getOtherRules = $projectdb->query("SELECT id, xml FROM other_rules WHERE source = '$source' ;");

        if ($getOtherRules->num_rows > 0) {

            while ($dataO = $getOtherRules->fetch_array()) {

                $xml_bbdd = $dataO['xml'];
                $id_xml = $dataO['id'];
                $xml = simplexml_load_string($xml_bbdd);

                // SOURCE / DESTINATION
                foreach ($xml->entry as $data) {

                    $other_rules_address_sources = array();
                    $other_rules_address_destination = array();

                    if (isset($data->source)){
                        foreach($data->source->member as $member){
                            if($member != "any") {
                                $other_rules_address_sources[] = $member;
                            }
                        }
                    }
                    if (isset($data->destination)){
                        foreach($data->destination->member as $member){
                            if($member != "any"){
                                $other_rules_address_destination[] = $member;
                            }
                        }
                    }

                    if (isset($data->source)){

                        $i = 0;
                        $is_change_source = 0;
                        $positions_to_remove = array();

                        foreach($data->source->member as $member){
                            if($member != "any"){
                                if (in_array($member, $all_names_for_replace)) {
                                    $is_change_source = 1;
                                    $positions_to_remove[] = $i;
                                }
                            }
                            $i++;
                        }
                        if(count($positions_to_remove) > 0){
                            rsort($positions_to_remove);
                            foreach($positions_to_remove AS $rm){
                                unset($data->source->member[$rm]);
                            }
                        }
                        if($is_change_source == 1){
                            if (in_array($name_int_new, $other_rules_address_sources)) {
                            }else{
                                $data->source->addChild('member', $name_int_new);
                            }
                        }
                    }

                    if (isset($data->destination)){

                        $i = 0;
                        $is_change_destination = 0;
                        $positions_to_remove = array();

                        foreach($data->destination->member as $member){
                            if($member != "any"){
                                if (in_array($member, $all_names_for_replace)) {
                                    $is_change_destination = 1;
                                    $positions_to_remove[] = $i;
                                }
                            }
                            $i++;
                        }
                        if(count($positions_to_remove) > 0){
                            rsort($positions_to_remove);
                            foreach($positions_to_remove AS $rm){
                                unset($data->destination->member[$rm]);
                            }
                        }
                        if($is_change_destination == 1){
                            if (in_array($name_int_new, $other_rules_address_destination)) {
                            }else{
                                $data->destination->addChild('member', $name_int_new);
                            }
                        }
                    }
                }

                $new_xml = $xml->asXML();
                $new_xml = str_replace('<?xml version="1.0"?>', "", $new_xml);
                $new_xml = addslashes($new_xml);
                $projectdb->query("UPDATE other_rules SET xml = '$new_xml' WHERE id = '$id_xml' ;");

            }
        }

        // SEARCH IN ZONES
        $getZones = $projectdb->query("SELECT id, include_list, exclude_list FROM zones WHERE source = '$source' AND (include_list != '' OR exclude_list != '');");

        if ($getZones->num_rows > 0) {

            while ($dataZ = $getZones->fetch_array()) {

                $id_zone = $dataZ['id'];
                $all_include_list = $dataZ['include_list'];
                $all_exclude_list = $dataZ['exclude_list'];

                $incl_exp = explode(",", $all_include_list);
                $exc_exp = explode(",", $all_exclude_list);

                $is_change = 0;
                $i = 0;

                foreach($incl_exp AS $member){
                    if (in_array($member, $all_names_for_replace)) {
                        $is_change = 1;
                        unset($incl_exp[$i]);
                    }
                    $i++;
                }
                if($is_change == 1){
                    if (in_array($name_int_new, $incl_exp)) {
                    }else{
                        $incl_exp[] = $name_int_new;
                    }
                    $projectdb->query("UPDATE zones SET include_list = '".implode(",", $incl_exp)."' WHERE id = '$id_zone' ;");
                }
                $is_change = 0;
                $i = 0;
                foreach($exc_exp AS $member){
                    if (in_array($member, $all_names_for_replace)) {
                        $is_change = 1;
                        unset($exc_exp[$i]);
                    }
                    $i++;
                }
                if($is_change == 1){
                    if (in_array($name_int_new, $exc_exp)) {
                    }else{
                        $exc_exp[] = $name_int_new;
                    }
                    $projectdb->query("UPDATE zones SET exclude_list = '".implode(",", $exc_exp)."' WHERE id = '$id_zone' ;");
                }
            }
        }
    }
}*/


/*function replaceServicesGroupsInOtherRules(STRING $projectName, $primary_member_lid, $all_names_for_replace, $source){

    global $projectdb;
    $projectdb = selectDatabase($projectName);


    $getNamePanNew = $projectdb->query("SELECT name FROM services_groups_id WHERE id = '$primary_member_lid'; ");
    if($getNamePanNew->num_rows > 0){
        $dataNP = $getNamePanNew->fetch_assoc();
        $name_int_new = $dataNP['name'];

        // Search in other_rules, xml
        $getOtherRules = $projectdb->query("SELECT id, xml FROM other_rules WHERE source = '$source' ;");

        if ($getOtherRules->num_rows > 0) {

            while ($dataO = $getOtherRules->fetch_array()) {

                $is_change = 0;
                $other_rules_service = array();

                $xml_bbdd = $dataO['xml'];
                $id_xml = $dataO['id'];
                $xml = simplexml_load_string($xml_bbdd);

                //1. Foreach de si existe en member y si existe no hacer nada
                //2. Si no existe, añado el member
                foreach ($xml->entry as $data) {

                    $other_rules_service = array();

                    if (isset($data->service)){
                        foreach($data->service->member as $member){
                            if($member != "any") {
                                $other_rules_service[] = $member;
                            }
                        }
                    }

                    if (isset($data->service)){

                        $i = 0;
                        $is_change = 0;
                        $positions_to_remove = array();

                        foreach($data->service->member as $member){
                            if($member != "any"){
                                if (in_array($member, $all_names_for_replace)) {
                                    $is_change = 1;
                                    $positions_to_remove[] = $i;
                                }
                            }
                            $i++;
                        }
                        if(count($positions_to_remove) > 0){
                            rsort($positions_to_remove);
                            foreach($positions_to_remove AS $rm){
                                unset($data->service->member[$rm]);
                            }
                        }
                        if($is_change == 1){
                            if (in_array($name_int_new, $other_rules_service)) {
                                //echo "EXISTE YA EL MIEMBRO, NO AÑADIR!\n";
                            }else{
                                $data->service->addChild('member', $name_int_new);
                            }
                        }
                    }
                }
                $new_xml = $xml->asXML();
                $new_xml = str_replace('<?xml version="1.0"?>', "", $new_xml);
                $new_xml = addslashes($new_xml);
                $projectdb->query("UPDATE other_rules SET xml = '$new_xml' WHERE id = '$id_xml' ;");
            }
        }
    }
}*/


function removeConsolidation($projectName, ARRAY $params){

    global $projectdb;
    $projectdb = selectDatabase($projectName);
    $table_name = $params['table_name'];

    if($table_name == "all"){
        $projectdb->query("DELETE FROM hash; ");
        $projectdb->query("DELETE FROM hash_rules; ");
    }
    else{
        $projectdb->query("DELETE FROM hash WHERE table_name = '$table_name'; ");
        $projectdb->query("DELETE FROM hash_rules WHERE table_name = '$table_name'; ");
    }

}


function setOptionsRules(STRING $projectName, ARRAY $params){

    global $projectdb;
    $projectdb = selectDatabase($projectName);

    if(!accessControl("any", ['projectRole.'.$projectName.'.update'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to edit this project contents';
        return $message;
    }

    $vsys = $params['vsys'];
    $source = $params['source'];
    $type_log = $params['type_log'];
    $ids = $params['ids'];
    $table_name = $params['table_name'];
    if(isset($params['value'])){$value = $params['value'];}else{$value = '';}
    $vsys_sql = '';
    $action_sql = '';
    $title = '';

    $message = array();

    //take_snapshot_last($projectName);

    if($vsys != "all"){$vsys_sql = " AND vsys = '$vsys' ";}

    if($type_log == "start_enable"){$sql = " log_start = '1' "; $title = "Log Start Enable";
    }elseif($type_log == "start_disable"){$sql = " log_start = '0' "; $title = "Log Start Disable";
    }elseif($type_log == "end_enable"){$sql = " log_end = '1' "; $title = "Log End Enable";
    }elseif($type_log == "end_disable"){$sql = " log_end = '0' "; $title = "Log End Disable";
    }elseif($type_log == "dsri_enable"){$sql = " dsri = '1' "; $title = "DSRI Enable";
    }elseif($type_log == "dsri_disable"){$sql = " dsri = '0' "; $title = "DSRI Disable";
    }elseif($type_log == "re_enable"){$sql = " re = '1' "; $action_sql = " AND action = 'allow' "; $title = "Rule Enrichment Monitor";
    }elseif($type_log == "re_disable"){$sql = " re = '0' "; $action_sql = " AND action = 'allow' "; $title = "Rule Enrichment Stop";
    }elseif($type_log == "ml_enable"){$sql = " ml = '1' "; $title = "Machine Learning Monitor";
    }elseif($type_log == "ml_disable"){$sql = " ml = '0' "; $title = "Machine Learning Stop";
    }elseif($type_log == "enable_rule"){$sql = " disabled = '0' "; $title = "Rule Enable";
    }elseif($type_log == "disable_rule"){$sql = " disabled = '1' "; $title = "Rule Disable";
    }elseif($type_log == "pre_rules"){$sql = " preorpost = '0' "; $title = "Convert in Pre-Rules";
    }elseif($type_log == "post_rules") {$sql = " preorpost = '1' ";$title = "Convert in Post-Rules";
    }elseif($type_log == "set_log_forwarding") {$sql = " log_forwarding = '$value' "; $title = "Add Log Forwarding";
    }elseif($type_log == "enable_bidirectional") {
        $sql = " tp_sat_bidirectional = '1' "; $action_sql = " AND tp_sat_type = 'static-ip' "; $title = "Enable Bi-directional";
    }elseif($type_log == "disable_bidirectional") {
        $sql = " tp_sat_bidirectional = '0' "; $action_sql = " AND tp_sat_type = 'static-ip' ";$title = "Disable Bi-directional";
    }elseif($type_log == "set_group_tags") {
        $sql = " group_tag_id = '$value' ";
        $title = "Add Group Tag";
    }

    elseif($type_log == 'append_description'){
        $sql = " description = LTRIM(CONCAT(description, ' $value')) "; $title = "Add Description";
    }
    elseif($type_log == 'prepend_description'){
        $sql = " description = CONCAT('$value ',description) ";
    }

    if ($ids != "") {
        $query = "UPDATE $table_name SET $sql WHERE id IN ($ids) $action_sql;";
        $projectdb->query($query);
    }
    else{
        $ids = "All Rules";
        $projectdb->query("UPDATE $table_name SET $sql WHERE source = '$source' $vsys_sql $action_sql;");
        //echo "UPDATE $table_name SET $sql WHERE source = '$source' $vsys_sql $action_sql;\n";
    }

    add_log('ok', $title, ''.$title.' RulesID ['.$ids.'] in vsys = '.$vsys, $source, 'No Action Required', '2');

    $message['code'] = true;

    return $message;

}


function setOptionsRulesRelations(STRING $projectName, ARRAY $params){

    global $projectdb;
    $projectdb = selectDatabase($projectName);

    if(!accessControl("any", ['projectRole.'.$projectName.'.update'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to edit this project contents';
        return $message;
    }

    $vsys = $params['vsys'];
    $source = $params['source'];
    $type_log = $params['type_log'];
    $ids = $params['ids'];
    $type_table_name = $params['type_table_name'];
    $table_name_rules = $params['table_name_rules'];
    $member_lid_all = $params['member_lid'];
    $vsys_sql = '';
    $vsys_sql_zone = '';
    $title = '';

    $sql_array = array();

    $message = array();

    //take_snapshot_last($projectName);

    if($vsys != "all"){$vsys_sql = " AND vsys = '$vsys' ";}
    if($vsys != "all"){$vsys_sql_zone = " AND sr.vsys = '$vsys' ";}

    if($type_log == "set_tags"){$table_name = "tag"; $title = "Add Tags";
    }else if($type_log == "set_profile_groups"){$table_name = "profiles_groups"; $title = "Add Profile Groups";
    }else if($type_log == "set_zones") {$title = "Add Zones";
    }else if($type_log == "set_group_tags") {
        $title = "Add Group Tags";
    }

    $member_lids = explode(",", $member_lid_all);

    if ($ids != "") {

        if($type_log == "set_profile_groups"){
            $projectdb->query("UPDATE security_rules SET profile_type = 'group' WHERE id IN ($ids);");
            $projectdb->query("DELETE FROM security_rules_profiles WHERE rule_lid IN ($ids);");
        }

        //getVsyses();

//        if($type_log == "set_zones"){
//
//            // Get only the rules with zones
//            $getRulesWithZones = $projectdb->query("SELECT DISTINCT(rule_lid) FROM $type_table_name WHERE rule_lid IN ($ids);");
//            //echo "SELECT rule_lid FROM $type_table_name WHERE rule_lid IN ($ids);\n";
//
//            if ($getRulesWithZones->num_rows > 0) {
//                while ($dataRWZ = $getRulesWithZones->fetch_assoc()) {
//                    $rule_lids[] = $dataRWZ['rule_lid'];
//                }
//            }
//        }
//        else{
//            $rule_lids = explode(",", $ids);
//        }

        $rule_lids = explode(",", $ids);

        foreach ($rule_lids as $rule_lid){

            foreach ($member_lids as $member_lid){

                if($type_log == "set_zones"){
                    //source,name,vsys,rule_lid,devicegroup
                    $sql_array[] = "('$source','$member_lid','$vsys','$rule_lid','')";
                }else{
                    $sql_array[] = "('$source','$member_lid','$table_name','','$rule_lid','')";
                }
            }
        }
    }
    else{
        $ids = "All Rules";

        if($type_log == "set_zones"){
            $getRules = $projectdb->query("SELECT DISTINCT(sr.id) FROM security_rules sr, $type_table_name srf WHERE sr.id = srf.rule_lid AND sr.source = '$source' $vsys_sql_zone ;");
            //echo "1. SELECT sr.id FROM security_rules sr, security_rules_from srf WHERE sr.id = srf.rule_lid AND sr.source = '$source' $vsys_sql_zone ;\n";
        }
        else{
            $getRules = $projectdb->query("SELECT id FROM $table_name_rules WHERE source = '$source' $vsys_sql;");
        }


        if ($getRules->num_rows > 0) {
            while ($dataA = $getRules->fetch_assoc()) {

                $rule_lid = $dataA['id'];
                $rule_alls[] = $dataA['id'];

                foreach ($member_lids as $member_lid){

                    if($type_log == "set_zones"){
                        //source,name,vsys,rule_lid,devicegroup
                        $sql_array[] = "('$source','$member_lid','$vsys','$rule_lid','')";
                    }else{
                        $sql_array[] = "('$source','$member_lid','$table_name','','$rule_lid','')";
                    }
                }
            }

            if($type_log == "set_profile_groups"){
                $projectdb->query("UPDATE security_rules SET profile_type = 'group' WHERE id IN (" . implode(",", $rule_alls) . ");");
                $projectdb->query("DELETE FROM security_rules_profiles WHERE rule_lid IN (" . implode(",", $rule_alls) . ");");
            }
        }
    }

    //print_r($sql_array);
    if (count($sql_array) > 0) {

        if($type_log == "set_zones"){
            $projectdb->query("INSERT INTO $type_table_name (source,name,vsys,rule_lid,devicegroup) VALUES " . implode(",", $sql_array) . ";");
            //echo "\nINSERT INTO $type_table_name (source,name,vsys,rule_lid,devicegroup) VALUES " . implode(",", $sql_array) . ";";
        }else{
            $projectdb->query("INSERT INTO $type_table_name (source,member_lid,table_name,vsys,rule_lid,devicegroup) VALUES " . implode(",", $sql_array) . ";");
        }
        unset($sql_array);
    }

    clean_duplicated_members($type_table_name);

    add_log('ok', $title, ''.$title.' RulesID ['.$ids.'] on vsys'.$vsys, $source, 'No Action Required', '2');

    $message['code'] = true;

    return $message;

}


function unsetOptionsRulesRelations(STRING $projectName, ARRAY $params){

    global $projectdb;
    $projectdb = selectDatabase($projectName);

    if(!accessControl("any", ['projectRole.'.$projectName.'.update'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to edit this project contents';
        return $message;
    }

    $vsys = $params['vsys'];
    $source = $params['source'];
    $type_log = $params['type_log'];
    $ids = $params['ids'];
    $type_table_name = $params['type_table_name'];

    $member_lid_all = $params['member_lid'];
    $member_lids = "'".implode("','",explode(",", $member_lid_all))."'";
    $vsys_sql = '';
    $title = '';

    $message = array();

    //take_snapshot_last($projectName);

    if($vsys != "all"){$vsys_sql = " AND vsys = '$vsys' ";}

    if($type_log == "unset_tags"){$title = "Remove Tags";
    }else if($type_log == "unset_profile_groups"){$title = "Remove Profile Groups";
    }else if($type_log == "unset_zones"){$title = "Remove Zones";
    }

    if($ids != ""){
        if($type_log == "unset_profile_groups"){
            $projectdb->query("DELETE FROM $type_table_name WHERE rule_lid IN ($ids) AND table_name = 'profiles_groups';");
            $projectdb->query("UPDATE security_rules SET profile_type = 'None' WHERE id IN ($ids) AND profile_type = 'group';");
        }
        if($type_log == "unset_zones"){
            $projectdb->query("DELETE FROM $type_table_name WHERE rule_lid IN ($ids) AND name in (".$member_lids.");");
        }
        else{
            $projectdb->query("DELETE FROM $type_table_name WHERE rule_lid IN ($ids);");
        }
    }
    else{
        if($type_log == "unset_profile_groups"){
            $projectdb->query("DELETE FROM $type_table_name WHERE source = '$source' $vsys_sql AND table_name = 'profiles_groups';");
            $projectdb->query("UPDATE security_rules SET profile_type = 'None' WHERE source = '$source' $vsys_sql AND profile_type = 'group';");
        }
        if($type_log == "unset_zones"){
            $projectdb->query("DELETE FROM $type_table_name WHERE source = '$source' $vsys_sql AND name in (".$member_lids.");");
        }
        else{
            $projectdb->query("DELETE FROM $type_table_name WHERE source = '$source' $vsys_sql;");
        }
    }

    add_log('ok', $title, ''.$title.' RulesID ['.$ids.'] ', $source, 'No Action Required', '2');

    $message['code'] = true;

    return $message;

}


function setRuleNames(STRING $projectName, ARRAY $params){

    global $projectdb;
    $projectdb = selectDatabase($projectName);

    if(!accessControl("any", ['projectRole.'.$projectName.'.update'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to edit this project contents';
        return $message;
    }

    $vsys = $params['vsys'];
    $source = $params['source'];
    $type = $params['type'];
    $ids = $params['ids'];
    $table_name = $params['table_name'];

    //take_snapshot_last($projectName);

    $message = updateRuleNames($projectdb, $source, $vsys, $type, $ids, $table_name);

    return $message;
}


function setRuleAddressGroupsByMember(STRING $projectName, ARRAY $params){

    global $projectdb;
    $projectdb = selectDatabase($projectName);

    if(!accessControl("any", ['projectRole.'.$projectName.'.update'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to edit this project contents';
        return $message;
    }

    $message = array();

    $vsys = $params['vsys'];
    $source = $params['source'];
    $ids = $params['ids'];
    $rules = $params['rules'];
    $table_name = $params['table_name'];

    $vsys_sql = '';

    if($vsys != "all"){$vsys_sql = " AND vsys = '$vsys' ";}

    //take_snapshot_last($projectName);

    if ($ids != ""){

        $lids = explode(",", $ids);

        foreach ($lids as $key => $rule_lid){
            replace_addressgroups_by_members($vsys, $source, $rule_lid, $rules, $table_name);
        }
    }
    else{

        $getRules = $projectdb->query("SELECT id FROM security_rules WHERE source = '$source' $vsys_sql;");

        if ($getRules->num_rows > 0) {
            while ($dataA = $getRules->fetch_assoc()) {

                $rule_lid = $dataA['id'];

                replace_addressgroups_by_members($vsys, $source, $rule_lid, $rules, $table_name);
            }
        }
    }

    $message['code'] = true;

    return $message;

}


function setRuleServicesGroupsByMember(STRING $projectName, ARRAY $params){

    global $projectdb;
    $projectdb = selectDatabase($projectName);

    if(!accessControl("any", ['projectRole.'.$projectName.'.update'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to edit this project contents';
        return $message;
    }

    $message = array();

    $vsys = $params['vsys'];
    $source = $params['source'];
    $ids = $params['ids'];
    $rules = $params['rules'];
    
    $vsys_sql = '';

    if($vsys != "all"){$vsys_sql = " AND vsys = '$vsys' ";}

    //take_snapshot_last($projectName);

    if ($ids != ""){

        $lids = explode(",", $ids);

        foreach ($lids as $key => $rule_lid){
            replace_servicegroups_by_members($vsys, $source, $rule_lid, $rules);
        }
    }
    else{

        $getRules = $projectdb->query("SELECT id FROM security_rules WHERE source = '$source' $vsys_sql;");

        if ($getRules->num_rows > 0) {
            while ($dataA = $getRules->fetch_assoc()) {

                $rule_lid = $dataA['id'];

                replace_servicegroups_by_members($vsys, $source, $rule_lid, $rules);
            }
        }
    }

    $message['code'] = true;

    return $message;

}


function setOptionsObjectsRelations(STRING $projectName, ARRAY $params){

    global $projectdb;
    $projectdb = selectDatabase($projectName);

    if(!accessControl("any", ['projectRole.'.$projectName.'.update'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to edit this project contents';
        return $message;
    }

    $vsys = $params['vsys'];
    $source = $params['source'];
    $type_log = $params['type_log'];
    $ids = $params['ids'];
    $type_table_name = $params['type_table_name'];
    $table_name_objects = $params['table_name_objects'];
    $tags_id_all = $params['tags_id_all'];
    $vsys_sql = '';
    $title = '';

    $sql_array = array();

    $message = array();

    //take_snapshot_last($projectName);

    if($vsys != "all"){$vsys_sql = " AND vsys = '$vsys' ";}

    if($type_log == "set_tags"){ $title = "Add Tags";
    }

    $tags_id = explode(",", $tags_id_all);

    if ($ids != "") {
        $lids = explode(",", $ids);

        foreach ($lids as $lid){

            foreach ($tags_id as $tag_id){
                $sql_array[] = "('$table_name_objects', '$lid', '$tag_id')";
            }
        }
    }
    else{
        $ids = "All ".$table_name_objects."";

        $ids_objects = getIdsBySourceVsys($table_name_objects, $source, $vsys);

        foreach ($ids_objects as $lid){

            foreach ($tags_id as $tag_id){
                $sql_array[] = "('$table_name_objects', '$lid', '$tag_id')";
            }
        }

    }

    if (count($sql_array) > 0) {
        $projectdb->query("INSERT INTO tag_relations (table_name, member_lid, tag_id) VALUES " . implode(",", $sql_array) . ";");
        unset($sql_array);
    }

    clean_duplicated_members($type_table_name);

    add_log('ok', $title, ''.$title.' '.$table_name_objects.' ['.$ids.'] on vsys '.$vsys, $source, 'No Action Required', '2');

    $message['code'] = true;

    return $message;

}


function unsetOptionsObjectsRelations(STRING $projectName, ARRAY $params){

    global $projectdb;
    $projectdb = selectDatabase($projectName);

    if(!accessControl("any", ['projectRole.'.$projectName.'.update'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to edit this project contents';
        return $message;
    }

    $vsys = $params['vsys'];
    $source = $params['source'];
    $type_log = $params['type_log'];
    $ids = $params['ids'];
    $table_name_objects = $params['table_name_objects'];
    $vsys_sql = '';
    $title = '';

    $message = array();

    //take_snapshot_last($projectName);

    if($vsys != "all"){$vsys_sql = " AND vsys = '$vsys' ";}

    if($type_log == "unset_tags"){$title = "Remove Tags";}

    if($ids != ""){
        $projectdb->query("DELETE FROM tag_relations WHERE member_lid IN ($ids) AND table_name = '$table_name_objects';");
    }
    else{

        $ids_objects = getIdsBySourceVsys($table_name_objects, $source, $vsys);

        $projectdb->query("DELETE FROM tag_relations WHERE table_name = '$table_name_objects' AND member_lid IN (" . implode(',', $ids_objects) . ") $vsys_sql;");
        //echo "DELETE FROM tag_relations WHERE table_name = '$table_name_objects' AND member_lid IN (" . implode(',', $ids_objects) . ") $vsys_sql;";
    }

    add_log('ok', $title, ''.$title.' '.$table_name_objects.' ['.$ids.'] ', $source, 'No Action Required', '2');

    $message['code'] = true;

    return $message;

}



