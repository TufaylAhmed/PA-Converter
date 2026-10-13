<?php
# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
//Loads all global PHP definitions
require_once '/var/www/html/libs/common/definitions.php';

require_once INC_ROOT.'/bin/configurations/parsers/ServicesMapping.php';
use PaloaltoNetworks\Parsers\Utils\ServicesMapping;

//Dependencies
require_once INC_ROOT.'/libs/database.php';
require_once INC_ROOT.'/libs/shared.php';
require_once INC_ROOT.'/libs/xmlapi.php';
require_once INC_ROOT.'/libs/projectdb.php';
require_once INC_ROOT.'/libs/objects/SecurityRulePANObject.php';
//require_once INC_ROOT.'/libs/common/lib-rules.php';
//Capture request paramenters

require_once INC_ROOT.'/userManager/API/accessControl_CLI.php';
global $app;
//Capture request paramenters
include INC_ROOT.'/bin/configurations/parsers/readVars.php';

// Validations
if(!accessControl("any", ['project.admin', 'projectRole.'.$project.'.admin'])){
    http_response_code(401);
    header("HTTP/1.1 401 Unauthorized");
    header("Location: /401");
    exit;
}

global $projectdb;
$projectdb = selectDatabase($project);

//---------------------------------------------
//        Parser Logic starts here
//----------------------------------------------

$sourcesAdded = array();
global $source;

if ($action == "import") {
    ini_set('max_execution_time', PARSER_max_execution_time);
    ini_set("memory_limit",PARSER_max_execution_memory);
    
    $path = USERSPACE_PATH."/projects/" . $project . "/";
    $i = 0;
    $dirrule = opendir($path);

    update_progress($project, '0.00', 'Reading config files',$jobid);
    while ($config_filename = readdir($dirrule)) {
        //if (($config_filename != ".") && ($config_filename != "..") && ($config_filename != "parsers.txt") && ($config_filename != "Backups") && ($config_filename != "Pcaps") && ($config_filename != "Reports") AND ( $config_filename != "CPviewer.html") AND ( !preg_match("/^MT-/", $config_filename)) AND ( !preg_match("/^\._/", $config_filename))) {
        if (checkFiles2Import($config_filename)){
            $config_path = $path . $config_filename;
            $filename = $config_filename;
            $filenameParts = pathinfo($config_filename);
            $verificationName = $filenameParts['filename'];
            $isUploaded = $projectdb->query("SELECT id FROM device_mapping WHERE filename='$verificationName';");
//            $isUploaded = $projectdb->query("SELECT id FROM device_mapping WHERE filename='$config_filename';");
            if ($isUploaded->num_rows == 0) {
                import_config($config_path, $project, $config_filename,$jobid); //This will update the $source
                $sourcesAdded[] = $source;
                update_progress($project, '0.70', 'File:' . $filename . ' Phase 7 Referencing Groups',$jobid);
                GroupMember2IdAddress($config_filename);
                GroupMember2IdServices($config_filename);
            } else {
                update_progress($project, '0.00', 'This filename '.$filename.' its already uploaded. Skipping...',$jobid);
                //unlink($path.$config_filename);
            }
        }
    }

    #Calculate Layer4-7
    $queryRuleIds = "SELECT id from security_rules WHERE source = $source;";
    $resultRuleIds = $projectdb->query($queryRuleIds);
    if($resultRuleIds->num_rows>0){
        $rules = array();
        while($dataRuleIds = $resultRuleIds->fetch_assoc()){
            $rules[] = $dataRuleIds['id'];
        }
        $rulesString = implode(",", $rules);
        $securityRulesMan = new \SecurityRulePANObject();
        $securityRulesMan->updateLayerLevel($projectdb, $rulesString, $source);
    }

    // Auto split the address groups based on defined PARSER_max_number_address_per_group
    // for upgraded installations that does not have the variable in the /home/userSpace/userDefinition.php defined
    if (!defined('PARSER_max_number_address_per_group')) {
        define('PARSER_max_number_address_per_group', -1);
    }
    if(PARSER_max_number_address_per_group!=-1) {
        update_progress($project, '0.85', 'Split the address group members using as a limit defined value of '. PARSER_max_number_address_per_group . ' members', $jobid);
        splitMembersOnGroups();
    }

    #Check used
    update_progress($project, '0.90', 'File:' . $filename . ' Calculating Used Objects',$jobid);
    check_used_objects_new($sourcesAdded);
    update_progress($project, '1.00', 'Done.',$jobid);
    unlink($config_path);
}

function import_config($config_path, $project, $config_filename,$jobid) {
    global $projectdb;
    global $source;
    $filename = $config_filename;
    #CLEAN CONFIG FROM EMPTY LINES AND CTRL+M
    file_put_contents($config_path, implode(PHP_EOL, file($config_path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES)));
    #LOAD THE FILE
    #Remove break lines
    $str = file($config_path);
    $test = preg_replace("/!$\n/i", "mtreplaceme2015", $str);
    file_put_contents($config_path, $test);
    $str = file($config_path);
    $test = preg_replace("/mtreplaceme2015 /i", "", $str);
    file_put_contents($config_path, $test);

    $fortinet_config_file = file($config_path);
    $fortinet_config_file2 = str_replace("!\r ", "", $fortinet_config_file);
    file_put_contents($config_path, $fortinet_config_file2);

    $fortinet_config_file = file($config_path);

    # Capture Sources Filename+vsys(vdom)
    $invdom = false;
    $vdom_name = 'root';
    foreach ($fortinet_config_file as $line => $names_line) {
        if (preg_match("/^config vdom/i", $names_line)) {
            $invdom = true;
        }
        elseif ((preg_match("/^end/i", $names_line)) and ( $invdom == TRUE)) {
            $invdom = false;
        }
        elseif (preg_match("/config\-version=/i", $names_line)) {
            $getVer = explode(":", $names_line);
            $ver = explode("=", $getVer[0]);
            $version = $ver[1];
        }

        if (($invdom) AND ( preg_match("/^edit /i", $names_line))) {
            $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
            $vsys = $data[1];
            $getDup = $projectdb->query("SELECT id FROM device_mapping WHERE filename='$filename' AND vsys='$vsys';");
            if ($getDup->num_rows == 0) {
                $projectdb->query("INSERT INTO device_mapping (device,version,ispanorama,active,project,filename,vsys,baseconfig,vendor) VALUES ('$filename','$version',0,1,'$project','$filename','$vsys','0','Fortinet')");
                $config_filename = $projectdb->insert_id;
                $source = $config_filename;
            }
        }
        $pattern = '/vd_name=([^\/]+)/';
        if (preg_match($pattern, $names_line,$matches)) {
            $vdom_name = $matches[1];
        }

    }
    #Check if Vdoms were created or its a simple config, then create a default vsys1
    $isVdom = $projectdb->query("SELECT id,vsys FROM device_mapping WHERE filename='$filename'");
    if ($isVdom->num_rows == 0) {
        $projectdb->query("INSERT INTO device_mapping (device,version,ispanorama,active,project,filename,vsys,baseconfig,vendor) VALUES ('$filename','$version',0,1,'$project','$filename','$vdom_name','0','Fortinet')");
        $config_filename = $projectdb->insert_id;
        $source = $config_filename;
    }


    # Bucle from Devices_mappings to get Objects and Rules
    $getDM = $projectdb->query("SELECT id,vsys FROM device_mapping WHERE filename='$filename';");
    if ($getDM->num_rows == 1) {
        $ismultiornot = "singlevsys";
    } elseif ($getDM->num_rows > 1) {
        $ismultiornot = "multivsys";
        #Add Shared context
        $projectdb->query("INSERT INTO device_mapping (device,version,ispanorama,active,project,filename,vsys,baseconfig,vendor) VALUES ('$filename','$version',0,1,'$project','$filename','shared','0','Fortinet')");
    }

    #Get Source (First row for this filename)
    $getSource = $projectdb->query("SELECT id FROM device_mapping WHERE filename='$filename' GROUP by filename;");
    $getSourceData = $getSource->fetch_assoc();
    $source = $getSourceData['id'];

    #Add Defautl Services
    add_fortinet_services($ismultiornot, $source);
    add_default_services($source);
    //add_default_profiles($source);
    #Config Template
    $template_name = "default_template" . $source;
    $projectdb->query("INSERT INTO templates_mapping (project,name,filename,source) VALUES ('$project','$template_name','$filename','$source');");
    $template = $projectdb->insert_id;

    #Add Interfaces
    get_interfaces($fortinet_config_file, "", $source, $template, $ismultiornot);
    $getDM = $projectdb->query("SELECT id,vsys FROM device_mapping WHERE filename='$filename';");
    while ($data = $getDM->fetch_assoc()) {
        $vsys = $data['vsys'];
        // avoid looping for "shared" vsys, as it was created by Expedition
        if($vsys==="shared"){continue;}
        update_progress($project, '0.10', 'File:' . $filename . ' Phase 1 Reading Zones ('.$vsys.')',$jobid);
        get_zones($fortinet_config_file, $vsys, $source, $template, $ismultiornot);
        update_progress($project, '0.20', 'File:' . $filename . ' Phase 2 Reading IP Pools and VIPs ('.$vsys.')',$jobid);
        get_ippools($fortinet_config_file, $source, $vsys, $ismultiornot);
        get_vip($fortinet_config_file, $source, $vsys, $ismultiornot,'vip'); // look for config firewall vip
        get_vip($fortinet_config_file, $source, $vsys, $ismultiornot, 'vip6'); // look for config firewall vip6
        get_vipgrp($fortinet_config_file, $source, $vsys, $ismultiornot, 'vipgrp'); // look for config firewall vipgrp
        get_vipgrp($fortinet_config_file, $source, $vsys, $ismultiornot, 'vipgrp6'); // look for config firewall vipgrp6
        update_progress($project, '0.30', 'File:' . $filename . ' Phase 3 Reading Address and Groups ('.$vsys.')',$jobid);
        $regions=array();
        get_address_Fortinet($fortinet_config_file, $source, $vsys, $ismultiornot, $regions);
        get_addressv6($fortinet_config_file, $source, $vsys, $ismultiornot, $regions);
        get_address_groups($fortinet_config_file, $source, $vsys, $ismultiornot, $regions, 'addrgrp'); // look for config firewall addrgrp
        get_address_groups($fortinet_config_file, $source, $vsys, $ismultiornot, $regions, 'addrgrp6'); // look for config firewall addrgrp6
        update_progress($project, '0.40', 'File:' . $filename . ' Phase 4 Reading Services and Groups ('.$vsys.')',$jobid);
        get_services2($fortinet_config_file, $source, $vsys, $ismultiornot);
        get_services_groups($fortinet_config_file, $source, $vsys, $ismultiornot);
        clean_duplicated_services($source, $vsys, $ismultiornot);
        update_progress($project, '0.50', 'File:' . $filename . ' Phase 5 Reading Security Policies ('.$vsys.')',$jobid);
        add_nat_from_vip($fortinet_config_file, $vsys, $source, $template, $ismultiornot);
        get_security_policy($fortinet_config_file, $source, $vsys, $ismultiornot,$regions, $template);
        update_progress($project, '0.60', 'File:' . $filename . ' Phase 6 Reading Nat Policies ('.$vsys.')',$jobid);
        fix_duplicated_rulenames($source,$vsys,'security_rules',0);
        fix_duplicated_rulenames($source,$vsys,'nat_rules',0);
        remove_regions_from_nat($source,$vsys);
        #check_used_objects($source);
    }
    check_used_objects_new();
// Call function to generate initial consumptions
    deviceUsage("initial", "get", $project, "", "", $vsys, $source, $template_name);
}

function clean_duplicated_services($source, $vsys, $ismultiornot){
    
    global $projectdb;
    
    $table = "services";
    $table_group = "services_groups";
    $table_group_id = "services_groups_id";
    
    if ($ismultiornot == "multivsys") {
        $vsys = "shared";
    } else {
        $vsys = "root"; // default vsys name
        // get the defined vsys name
        $getVsys = $projectdb->query("SELECT vsys FROM device_mapping WHERE id='$source'");
        if($getVsys->num_rows > 0 )
        {
            $getVsysData = $getVsys->fetch_assoc();
            $vsys = $getVsysData['vsys'];
        }
    }

    $getDup=$projectdb->query("SELECT name,count(id) as t FROM $table WHERE source='$source' AND vsys='$vsys' GROUP BY name HAVING t>1 ORDER BY id;");
    if ($getDup->num_rows > 0){
        $srvname=[];
        while($data=$getDup->fetch_assoc()){
            $srvname[]=$data['name'];
        }
        foreach ($srvname as $name){
            $projectdb->query("DELETE FROM $table WHERE source='$source' AND vsys='$vsys' AND name='$name' AND devicegroup='predefined';");
        }
    }

    $getDup=$projectdb->query("SELECT name,count(id) as t FROM $table_group_id WHERE source='$source' AND vsys='$vsys' GROUP BY name HAVING t>1 ORDER BY id;");
    if ($getDup->num_rows > 0){
        $srvname=[];
        while($data=$getDup->fetch_assoc()){
            $srvname[]=$data['name'];
        }
        foreach ($srvname as $name){
            $getMembers=$projectdb->query("SELECT id FROM $table_group_id WHERE source='$source' AND vsys='$vsys' AND name='$name' AND devicegroup='predefined';");
            if ($getMembers->num_rows==1){
                $getMembersData=$getMembers->fetch_assoc();
                $glid=$getMembersData['id'];
                $projectdb->query("DELETE FROM $table_group_id WHERE source='$source' AND vsys='$vsys' AND name='$name' AND devicegroup='predefined';");
                $projectdb->query("DELETE FROM $table_group WHERE lid='$glid';");
            }

        }
    }

}

function get_security_policy($fortinet_config_file, $source, $vsys, $ismultiornot,&$regions, $template) {

    global $projectdb;
    $isPolicy = false;
    $isObject = false;
    $sql = array();
    $sql1 = array();
    $lid = "";
    $addressNamePan = "";
    $addressName = "";
    $nat_lid = "";
    $sql_rule = array();
    $sql_src_zone = array();
    $sql_dst_zone = array();
    $Comments = "";
    $status = 0;
    $sql_src = array();
    $sql_dst = array();
    $sql_srv = $addTag = array();
    $Action = "deny";
    $nat_activated = 0;
    $ippool = [];
    $srv_table_name = "";
    $srv_name = "";
    $srv_member_lid = "";
    $src_table_name = "";
    $src_member_lid = "";
    $dst_member_lid = "";
    $dst_table_name = "";
    $addNatDst_tmp = array();
    $addNatSrc_tmp = array();
    $addNatSrc=array();
    $addNatDst=array();
    $addNATTranslatedAddress = array();
    $addNATFrom = array();
    $zones = array();
    $multi_line_comment=false;

    $checkit = "";
    $service_array = [];
    $negate_source = "";
    $negate_destination = "";

    // for upgraded installations that does not have the variable in the /home/userSpace/userDefinition.php defined
    if (!defined('RECOMMENDED_PANOS_VERSION')) {
        define('RECOMMENDED_PANOS_VERSION', 9.1);
    }
    $version_parser = RECOMMENDED_PANOS_VERSION;

    $thecolor=1;
    $x=1;
    #Load Default Regions
    $defaultRegions=array();
    $getDFRegions=$projectdb->query("SELECT id,name FROM default_regions;");
    if ($getDFRegions->num_rows>0){
        while($getDFRegionsData=$getDFRegions->fetch_assoc()){
            $defaultRegions[$getDFRegionsData['name']]=$getDFRegionsData['id'];
        }
    }

    #Load TAGS in case we found set global-label
    $getTag=$projectdb->query("SELECT id,name FROM tag WHERE source='$source';");
    if ($getTag->num_rows>0){
        $allTags=array();
        while($getTagData=$getTag->fetch_assoc()){
            $allTags[$getTagData['name']]=$getTagData['id'];
        }
    }

    $getPosition = $projectdb->query("SELECT max(position) as t FROM security_rules WHERE vsys='$vsys' AND source='$source';");
    if ($getPosition->num_rows == 0) {
        $position = 1;
    } else {
        $ddata = $getPosition->fetch_assoc();
        $position = $ddata['t'] + 1;
    }
    if ($lid == "") {
        $getlastlid = $projectdb->query("SELECT max(id) as max FROM security_rules;");
        $getLID1 = $getlastlid->fetch_assoc();
        $lid = intval($getLID1['max']) + 1;
    }
    $getPosition = $projectdb->query("SELECT max(position) as t FROM nat_rules WHERE vsys='$vsys' AND source='$source';");
    if ($getPosition->num_rows == 0) {
        $nat_position = 1;
    } else {
        $ddata = $getPosition->fetch_assoc();
        $nat_position = $ddata['t'] + 1;
    }
    if ($nat_lid == "") {
        $getlastlid = $projectdb->query("SELECT max(id) as max FROM nat_rules;");
        if ($getlastlid->num_rows==0){
            $nat_lid = 1;
        }
        else{
            $getLID1 = $getlastlid->fetch_assoc();
            $nat_lid = intval($getLID1['max']) + 1;
        }

    }



    if ($ismultiornot == "singlevsys") {
        $START = TRUE;
        $VDOM = FALSE;
    } else {
        $START = FALSE;
        $VDOM = FALSE;
    }
    $lastline = "";
    foreach ($fortinet_config_file as $line => $names_line) {

        if ($START == FALSE) {
            if (preg_match("/^config vdom/i", $names_line)) {
                $VDOM = TRUE;
            }
            if ($VDOM == TRUE) {
                if (preg_match("/^edit $vsys/i", $names_line)) {
                    $START = TRUE;
                }
            }
            if ($ismultiornot == "singlevsys") {
                if (preg_match("/\bconfig firewall policy\b/i", $names_line) || preg_match("/\bconfig firewall security-policy\b/i", $names_line)) {
                    $START = TRUE;
                }
            }

        } else {
            if (preg_match("/^config vdom/i", $names_line)) {
                $VDOM = TRUE;
                $START = FALSE;
            }
            if (((preg_match("/^end/i", $lastline)) || (preg_match("/^next/i", $lastline))) AND ( preg_match("/^end/i", $names_line))) {
                $START = FALSE;
                $VDOM = FALSE;
            } elseif ((preg_match("/^edit/i", $lastline)) and ( preg_match("/^end/i", $names_line))) {
                $START = FALSE;
                $VDOM = FALSE;
            } elseif (
                ( preg_match("/\bconfig firewall policy\b/i", $lastline) ||  preg_match("/\bconfig firewall security-policy\b/i", $lastline) )
                and ( preg_match("/^end/i", $names_line))
            ) {
                $START = FALSE;
                $VDOM = FALSE;
            }
        }

        if ($START) {

            if (preg_match("/\bconfig firewall policy\b/i", $names_line) || preg_match("/\bconfig firewall security-policy\b/i", $names_line)) {
                $isObject = true;
            }


            if ($isObject) {
                if ($multi_line_comment===false && preg_match("/^\bend\b/i", $names_line)) {
                    $isObject = false;
                    $START = false;
                }
                if (preg_match("/\bedit\b/i", $names_line)) {
                    $isPolicy = true;
                    $multi_line_comment=false;
                    $meta = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                    $RuleName = "Rule " . trim($meta[1]);
                    $RuleNamePan = truncate_names(normalizeNames($RuleName));
                }

                if ($isPolicy) {
                    if (preg_match("/\bnext\b/i", $names_line)) {
                        $isPolicy = false;
                        $Comments = truncate_descriptions($Comments,$version_parser);
                        $sql_rule[] = "('$lid','$position','$RuleNamePan','$source','$vsys','$Comments','$Action','$status','$checkit','$negate_source','$negate_destination')";

                        if ($nat_activated == 1) {

                            // If nat is multi-service we need to use a service_group containing the listed services on the NAT rule
                            // so we need to search for an existing service_group containing only those listed services or create a new one
                            if($multi_service===true){
                                // NAT rule will be related with a service_group
                                $srv_table_name = "services_groups_id";
                                // flag to identify if we found any service_group containing the listed services
                                $found = false;

                                // search if exists a service_group with the required services
                                // get all ids for the listed services
                                $service_ids = array_column($service_array,'lid');
                                // get the number of services to make queries to db
                                $service_candidate_count = count($service_ids);
                                // below query will return all service_groups that contains the listed services, but take in mind that returned services_groups can as well contain more services
                                $service_candidates_query = "SELECT lid FROM services_groups WHERE member_lid IN (". implode(",", $service_ids)  . ") GROUP BY lid HAVING COUNT(*) = " . $service_candidate_count;
                                $service_candidates_result = $projectdb->query($service_candidates_query);
                                if($service_candidates_result->num_rows>0){
                                    // At least we have 1 or more service_groups that contains listed services
                                    // now we need to check if the returned service_groups have ONLY the listed services
                                    // do a count for each lid returned on the $service_candidates_result
                                    while($service_candidates_data = $service_candidates_result->fetch_assoc()) {
                                        // below query will return found = 1 if the queried service_group ONLY have the selected services
                                        $service_candidates_check_query = "SELECT ( ".$service_candidate_count." = (SELECT count(*) as total FROM services_groups where lid =". $service_candidates_data['lid']. ")) as found";
                                        $service_candidates_check_result = $projectdb->query($service_candidates_check_query);
                                        if($service_candidates_check_result->num_rows>0){
                                            $data = $service_candidates_check_result->fetch_assoc();
                                            if($data['found']=="1"){
                                                // we found one existing service_group with the required services
                                                $found=true;
                                                $srv_member_lid = $service_candidates_data['lid'];
                                                // get the name for log/monitor purposes
                                                $getServiceName = $projectdb->query("SELECT name FROM services_groups_id WHERE id ='". $srv_member_lid ."'");
                                                if ($getServiceName->num_rows > 0) {
                                                    $found_service_name = $getServiceName->fetch_assoc();
                                                    $srv_name = $found_service_name['name'];
                                                }
                                                // no matter if any other service_group has the same services member, we are fine with just one :)
                                                break;
                                            }
                                        }
                                    }
                                }
                                if(!$found){
                                    // create the new service_group
                                    $srv_name = truncate_names(normalizeNames("EXP_".$RuleNamePan));
                                    $projectdb->query("INSERT INTO services_groups_id (name_ext,name,source,vsys) VALUES ('$srv_name','$srv_name','$source','$vsys')");
                                    $srv_member_lid = $projectdb->insert_id;
                                    // create the relations
                                    foreach ($service_array as $services){
                                        $projectdb->query("INSERT INTO services_groups (member,table_name,member_lid,source,vsys,lid)  VALUES ('".$services['name']."','".$services['table']."','".$services['lid']."','".$source."','".$vsys."','".$srv_member_lid."')");
                                    }
                                }
                            }

                            if (count($ippool)>0) {
                                foreach($ippool as $pool) {
                                    $pool_member_lid = 0;
                                    #Do Source Nat
                                    $getPool = $projectdb->query("SELECT id FROM address WHERE BINARY(name_ext)='$pool' AND source='$source' AND vsys='$vsys';");
                                    if ($getPool->num_rows > 0) {
                                        $getPoolData = $getPool->fetch_assoc();
                                        $pool_member_lid = $getPoolData['id'];
                                        $pool_table_name = "address";
                                    } else {
                                        // check if $ippool is a valid IP
                                        // Create a new address object with the valid IP
                                        $ip_version = ip_version($pool);
                                        if ($ip_version != "noip") {
                                            $projectdb->query("INSERT INTO address (source,name_ext,name,vsys,type,vtype,fqdn,ipaddress,cidr,description,v4,v6) VALUES ('$source', '$pool', '$pool', '$vsys', 'ip-netmask', '', '', '$pool', '32', 'IPPOOL found in rule $nat_lid', '1', '0' );");
                                            $pool_member_lid = $projectdb->insert_id;
                                            $pool_table_name = "address";
                                        } else {
                                            //add_log('error', 'Phase 5: Reading NAT Policies', 'IPPOOL not found in DB Source:[' . $pool . '] in Rule [' . $nat_lid . '] vsys [' . $vsys . ']', $source, 'fix to be added');
                                            add_log2('error', 'Phase 5: Reading NAT Policies', 'IPPOOL not found in DB Source:[' . $pool . '] in Rule [' . $nat_lid . '] vsys [' . $vsys . ']', $source, 'fix to be added', 'rules', $nat_lid, 'nat_rules');
                                        }
                                    }
                                    if($pool_member_lid!==0) {
                                        $addNATTranslatedAddress[] = "('$source','$vsys','$nat_lid','$pool_member_lid','$pool_table_name')";
                                    }
                                }

                                if ($multi_service === true) {
                                    //$srv_member_lid = "";
                                    //$srv_table_name = "";
                                    add_log2('warning', 'Phase 5: Reading NAT Policies', 'More than one Service found [' .implode(",", array_column($service_array,'name')) . '] in Rule [' . $nat_lid . '] vsys [' . $vsys . ']', $source, 'Check the automatic created group ['.$srv_name.']', 'rules', $nat_lid, 'nat_rules');
                                }
                                if ($ZonaDST == "any") {
                                    $ZonaDST = "";
                                }
                                // create a disabled SNAT rule
                                $addSNAT[] = "('$source','$vsys','$nat_lid','$nat_position','$RuleNamePan','$status','$ZonaDST','',0,'$srv_member_lid','$srv_table_name','dynamic-ip-and-port','translated-address','','$Comments','')";
                                if ($ZonaSRC != "any") {
                                    $addNATFrom[] = "('$source','$vsys','$nat_lid','$ZonaSRC')";
                                }

//                                $nat_lid++;
//                                $nat_position++;

                            }
                            else {
                                #Source Nat with the External interface
                                if ($ZonaDST=="any"){
                                    add_log2('warning','Nat Rule Checking','Creating Oubound Nat from Security Rule ['.$lid.']. Unable to identify the interface to use for Outbound Nat on Nat Rule ['.$nat_lid.']',$source,'Assign The right interface.','rules',$nat_lid,'nat_rules');
                                    $addSNAT[] = "('$source','$vsys','$nat_lid','$nat_position','$RuleNamePan','$status','','',0,'$srv_member_lid','$srv_table_name','dynamic-ip-and-port','interface-address','','$Comments','')";
                                    if ($ZonaSRC!="any"){
                                        $addNATFrom[] = "('$source','$vsys','$nat_lid','$ZonaSRC')";
                                    }

                                    if ($multi_service===true){
                                        //$srv_member_lid="";$srv_table_name="";
                                        add_log2('warning', 'Phase 5: Reading NAT Policies', 'More than one Service ['.implode(",",    array_column($service_array,'name')).'] found in Rule [' . $nat_lid . '] vsys [' . $vsys . ']', $source, 'Check the created automatic group['.$srv_name.']','rules',$nat_lid,'nat_rules');
                                    }
                                }
                                else{
                                    $gettmp=$projectdb->query("SELECT interfaces FROM zones WHERE BINARY name='$ZonaDST' AND vsys='$vsys' AND source='$source' LIMIT 1;");
                                    if ($gettmp->num_rows==1){
                                        $gettmpData=$gettmp->fetch_assoc();
                                        $gettmpInt=$gettmpData['interfaces'];
                                        $interfaceName=explode(",",$gettmpInt);

                                        $getInterface = $projectdb->query("SELECT unitipaddress FROM interfaces WHERE BINARY unitname='$interfaceName[0]' AND vsys='$vsys' AND source='$source' and unitipaddress != '';");
                                        if ($getInterface->num_rows == 1) {
                                            $getInterfaceData = $getInterface->fetch_assoc();
                                            $interfacedata = $getInterfaceData['unitipaddress'];
                                        }else{
                                            $interfacedata = '';
                                            add_log2('error','Reading Security Policy with Nat Enabled','The interface used for source nat ['.$nat_lid.'] has not IP address defined'.$interfaceName[0].'. Assigning only the interface, you can force the IP address to use if you know it',$source,'Review the Rule','rules',$nat_lid,'nat_rules');
                                        }
                                        if ($multi_service===true){
                                            //$srv_member_lid="";$srv_table_name="";
                                            add_log2('warning', 'Phase 5: Reading NAT Policies', 'More than one Service ['.implode(",",array_column($service_array,'name')).'] found in Rule [' . $nat_lid . '] vsys [' . $vsys . ']', $source, 'Check the created automatic group['.$srv_name.']','rules',$nat_lid,'nat_rules');
                                        }
                                        if (preg_match("/,/",$interfacedata)){
                                            add_log2('error','Reading Security Policy with Nat Enabled','The interface used for source nat ['.$nat_lid.'] has more than one IP address '.$interfacedata.'. Assigning only the interface, you can force the IP address to use if you know it',$source,'Review the Rule','rules',$nat_lid,'nat_rules');
                                            $explodeInterface=explode(",",$interfacedata);
                                            $interfacedata='';
                                        }
                                        if ($ZonaDST=="any"){
                                            $ZonaDST="";
                                        }

                                        if ($interfacedata==""){
                                            add_log2('warning','Creating Oubound Nat from Security Rule ['.$lid.']','Unable to identify the interface to use for Outbound Nat on Nat Rule ['.$nat_lid.']',$source,'Assign The right interface.','rules',$nat_lid,'nat_rules');
                                        }
                                        $addSNAT[] = "('$source','$vsys','$nat_lid','$nat_position','$RuleNamePan','$status','$ZonaDST','',0,'$srv_member_lid','$srv_table_name','dynamic-ip-and-port','interface-address','$interfacedata','$Comments','$interfaceName[0]')";
                                        if ($ZonaSRC!="any"){
                                            $addNATFrom[] = "('$source','$vsys','$nat_lid','$ZonaSRC')";
                                        }


                                    }
                                }
                            }
                            if (is_array($addNatSrc_tmp)){
                                foreach ($addNatSrc_tmp as $key => $value) {
                                    $addNatSrc[] = $value;
                                }
                            }
                            if (is_array($addNatDst_tmp)){
                                foreach ($addNatDst_tmp as $key => $value) {
                                    $addNatDst[] = $value;
                                }
                            }

                            //$nat_lid++;
                            //$nat_position++;
                        }
                        $nat_lid++;
                        $nat_position++;
                        $lid++;
                        $position++;
                        $RuleName = "";
                        $addressNamePan = "";
                        $addressName = "";
                        $ZonaSRC = "";
                        $ZonaDST = "";
                        $Action = "deny";
                        $checkit = 0;
                        $Comments = "";
                        $status = 0;
                        $isPolicy = false;
                        $negate_destination = 0;
                        $negate_source = 0;
                        $nat_activated = 0;
                        $ippool = [];
                        $srv_table_name = "";
                        $srv_name = "";
                        $srv_member_lid = "";
                        $src_table_name = "";
                        $src_member_lid = "";
                        $dst_member_lid = "";
                        $dst_table_name = "";
                        $pool_member_lid = "";
                        $pool_table_name = "";
                        $addNatDst_tmp = array();
                        $addNatSrc_tmp = array();
                        $interfaceName = "";
                        $multi_line_comment=false;
                    }

                    if (preg_match("/\bset name\b/i", $names_line)) {
                        $meta2 = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                        $RuleNamePan = truncate_names(normalizeNames(trim($meta2[2])));
                    }

                    if (preg_match("/\bset srcintf\b/i", $names_line)) {
                        $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                        unset($data[0]);unset($data[1]);
                        foreach ($data as $zone){
                            $ZonaSRC = trim($zone);
                            if ($ZonaSRC!="any"){
                                $sql_src_zone[] = "('$source','$vsys','$ZonaSRC','$lid')";
                                $zones[]=$ZonaSRC;
                            }
                        }

                    }

                    if (preg_match("/\bset dstintf\b/i", $names_line)) {
                        $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                        unset($data[0]);unset($data[1]);
                        foreach ($data as $zone){
                            $ZonaDST = trim($zone);
                            if ($ZonaDST!="any"){
                                $sql_dst_zone[] = "('$source','$vsys','$ZonaDST','$lid')";
                                $zones[]=$ZonaDST;
                            }
                        }

                    }
                    // adding support for tag srcaddr4 and srcaddr6
                    if (preg_match("/set srcaddr /i", $names_line) || preg_match("/set srcaddr4 /i", $names_line) || preg_match("/set srcaddr6 /i", $names_line)) {
                        $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                        foreach ($data as $value => $datas) {
                            if (($datas == "set") or ( $datas == "srcaddr") or ( $datas == "srcaddr4") or ( $datas == "srcaddr6") or ( $datas == "all") or ( $datas == "Any")) {

                            }
                            else {
                                $name = $datas;
                                $getName = $projectdb->query("SELECT id FROM address WHERE source='$source' AND vsys='$vsys' AND BINARY(name_ext)='$name' LIMIT 1");
                                if ($getName->num_rows == 1) {
                                    $getit = $getName->fetch_assoc();
                                    $src_table_name = "address";
                                    $src_member_lid = $getit['id'];
                                    $sql_src[] = "('$source','$vsys','$lid','$src_member_lid','$src_table_name')";
                                    $addNatSrc_tmp[] = "('$source','$vsys','$nat_lid','$src_member_lid','$src_table_name')";
                                }
                                else {
                                    $getName = $projectdb->query("SELECT id FROM address_groups_id WHERE source='$source' AND vsys='$vsys' AND BINARY(name_ext)='$name' LIMIT 1");
                                    if ($getName->num_rows == 1) {
                                        $getit = $getName->fetch_assoc();
                                        $src_table_name = "address_groups_id";
                                        $src_member_lid = $getit['id'];
                                        $sql_src[] = "('$source','$vsys','$lid','$src_member_lid','$src_table_name')";
                                        $addNatSrc_tmp[] = "('$source','$vsys','$nat_lid','$src_member_lid','$src_table_name')";
                                    }
                                    else {
                                        if (isset($regions[$name])){
                                            $src_table_name="default_regions";
                                            $src_member_lid=$defaultRegions[$regions[$name]];
                                            $sql_src[] = "('$source','$vsys','$lid','$src_member_lid','$src_table_name')";
                                            $addNatSrc_tmp[] = "('$source','$vsys','$nat_lid','$src_member_lid','$src_table_name')";
                                        }
                                        else{
                                            add_log2('error', 'Phase 5: Reading Security Policies', 'Address not found in DB Source:[' . $name . '] in Rule [' . $lid . '] vsys [' . $vsys . ']', $source, 'Generating the Object, add IP Address','rules',$lid,'security_rules');
                                            $myname = truncate_names(normalizeNames($name));
                                            $projectdb->query("INSERT INTO address (type,name_ext,name,checkit,source,used,vtype,vsys) values('ip-netmask','$name','$myname','1','$source','1','ip-netmask','$vsys');");
                                            $src_table_name = "address";
                                            $src_member_lid = $projectdb->insert_id;
                                            $sql_src[] = "('$source','$vsys','$lid','$src_member_lid','$src_table_name')";
                                            $addNatSrc_tmp[] = "('$source','$vsys','$nat_lid','$src_member_lid','$src_table_name')";
                                        }

                                    }
                                }
                            }
                        }
                    }
                    // Adding support for tag dstaddr6
                    if (preg_match("/set dstaddr /i", $names_line) || preg_match("/set dstaddr4 /i", $names_line) || preg_match("/set dstaddr6 /i", $names_line)) {
                        $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                        foreach ($data as $value => $datas) {

                            if (($datas == "set") or ( $datas == "dstaddr") or ( $datas == "dstaddr4") or ( $datas == "dstaddr6") or ( $datas == "all") or ( $datas == "Any")) {

                            }
                            else {
                                //TODO: Check if this is a VIP object
                                $name = $datas;
                                $getName = $projectdb->query("SELECT id, name FROM fortinet_vip WHERE source='$source' AND vsys='$vsys' AND BINARY(name)='$name' LIMIT 1");
                                if ($getName->num_rows == 1) {
                                    $getit = $getName->fetch_assoc();
                                    $dst_member_lid = $getit['id'];

                                    //Also, check for the port used for the NAT
                                    $subq = "select services.* from services, fortinet_vip where 
                                             fortinet_vip.id='$dst_member_lid' AND
                                             services.name = concat(fortinet_vip.protocol,'-',fortinet_vip.extport) limit 1";
                                    $getPort = $projectdb->query($subq);
                                    if($getPort->num_rows == 1) {
                                        $getthisport = $getPort->fetch_assoc();
                                        $srv_member_lid=$getthisport['id'];
                                        $srv_table_name = "services";
                                        $sql_srv[] = "('$source','$vsys','$lid','$srv_member_lid','$srv_table_name')";
                                        add_log2('info', 'Creating Security Rules', 'VIP object ['.$getit['name'].'] found in Security Rule [' . $lid . '] vsys [' . $vsys . ']', $source, 'Placing VIP Ports in Security Rule ', 'rules', $lid, 'security_rules');
                                    }
                                }

                                $getName = $projectdb->query("SELECT id FROM address WHERE source='$source' AND vsys='$vsys' AND BINARY(name_ext)='$name' LIMIT 1");
                                if ($getName->num_rows == 1) {
                                    $getit = $getName->fetch_assoc();
                                    $dst_table_name = "address";
                                    $dst_member_lid = $getit['id'];
                                    $sql_dst[] = "('$source','$vsys','$lid','$dst_member_lid','$dst_table_name')";
                                    $addNatDst_tmp[] = "('$source','$vsys','$nat_lid','$dst_member_lid','$dst_table_name')";
                                }
                                else {
                                    $getName = $projectdb->query("SELECT id FROM address_groups_id WHERE source='$source' AND vsys='$vsys' AND BINARY(name_ext)='$name' LIMIT 1");
                                    if ($getName->num_rows == 1) {
                                        $getit = $getName->fetch_assoc();
                                        $dst_table_name = "address_groups_id";
                                        $dst_member_lid = $getit['id'];
                                        $sql_dst[] = "('$source','$vsys','$lid','$dst_member_lid','$dst_table_name')";
                                        $addNatDst_tmp[] = "('$source','$vsys','$nat_lid','$dst_member_lid','$dst_table_name')";
                                    } else {
                                        if (isset($regions[$name])) {
                                            $dst_table_name = "default_regions";
                                            $dst_member_lid = $defaultRegions[$regions[$name]];
                                            $sql_dst[] = "('$source','$vsys','$lid','$dst_member_lid','$dst_table_name')";
                                            $addNatDst_tmp[] = "('$source','$vsys','$nat_lid','$dst_member_lid','$dst_table_name')";
                                        } else {
                                            add_log2('error', 'Phase 5: Reading Security Policies', 'Address not found in DB Destination:[' . $name . '] in Rule [' . $lid . '] vsys [' . $vsys . ']', $source, 'Generating the Object, add IP Address', 'rules', $lid, 'security_rules');
                                            $myname = truncate_names(normalizeNames($name));
                                            $projectdb->query("INSERT INTO address (type,name_ext,name,checkit,source,used,vtype,vsys) values('ip-netmask','$name','$myname','1','$source','1','ip-netmask','$vsys');");
                                            $dst_table_name = "address";
                                            $dst_member_lid = $projectdb->insert_id;
                                            $sql_dst[] = "('$source','$vsys','$lid','$dst_member_lid','$dst_table_name')";
                                            $addNatDst_tmp[] = "('$source','$vsys','$nat_lid','$dst_member_lid','$dst_table_name')";
                                        }

                                    }
                                }
                            }
                        }
                    }

                    if (preg_match("/set service /i", $names_line)) {
                        # FOR NATS I have to check the number of services and if they are groups or not
                        $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                        if (count($data)>3){$multi_service=true;$service_array=[];}else{$multi_service=false;}
                        $srv_member_lid = "";
                        foreach ($data as $value => $datas) {

                            if (($datas == "set") OR ( $datas == "service") OR ( $datas == "ANY") OR ($datas == "ALL")) {

                            } else {

                                $name = $datas;
                                $getName = $projectdb->query("SELECT id FROM services WHERE source='$source' AND vsys='$vsys' AND BINARY(name_ext)='$name' LIMIT 1");
                                if ($getName->num_rows == 1) {
                                    $getit = $getName->fetch_assoc();
                                    $srv_table_name = "services";
                                    $srv_member_lid = $getit['id'];
                                    $sql_srv[] = "('$source','$vsys','$lid','$srv_member_lid','$srv_table_name')";
                                } else {
                                    $getName = $projectdb->query("SELECT id FROM services_groups_id WHERE source='$source' AND vsys='$vsys' AND BINARY(name_ext)='$name' LIMIT 1");
                                    if ($getName->num_rows == 1) {
                                        $getit = $getName->fetch_assoc();
                                        $srv_table_name = "services_groups_id";
                                        $srv_member_lid = $getit['id'];
                                        $sql_srv[] = "('$source','$vsys','$lid','$srv_member_lid','$srv_table_name')";
                                    } else {
                                        //$getName = $projectdb->query("SELECT id FROM shared_services WHERE source='$source' AND name='$name' LIMIT 1");
                                        $getName = $projectdb->query("SELECT id FROM services WHERE source='$source' AND BINARY(name_ext)='$name' AND vsys = 'shared' LIMIT 1");
                                        if ($getName->num_rows == 1) {
                                            $getit = $getName->fetch_assoc();
                                            //$srv_table_name = "shared_services";
                                            $srv_table_name = "services";
                                            $srv_member_lid = $getit['id'];
                                            $sql_srv[] = "('$source','$vsys','$lid','$srv_member_lid','$srv_table_name')";
                                        } else {
                                            //add_log('error', 'Phase 5: Reading Security Policies', 'Service not found in DB [' . $name . '] in Rule [' . $lid . '] vsys [' . $vsys . ']', $source, 'Generating the Object, add the Protocol/Port');
                                            add_log2('error', 'Phase 5: Reading Security Policies', 'Service not found in DB [' . $name . '] in Rule [' . $lid . '] vsys [' . $vsys . ']', $source, 'Generating the Object, add the Protocol/Port', 'rules', $lid, 'security_rules');

                                            $myname = truncate_names(normalizeNames($name));
                                            $projectdb->query("INSERT INTO services (name,name_ext,checkit,source,used,vsys) values ('$myname','$name','1','$source','0','$vsys');");
                                            $srv_member_lid = $projectdb->insert_id;
                                            $srv_table_name = "services";
                                            $sql_srv[] = "('$source','$vsys','$lid','$srv_member_lid','$srv_table_name')";
                                        }
                                    }
                                }
                                $service_array[$datas]['name'] = $datas;
                                $service_array[$datas]['table'] = $srv_table_name;
                                $service_array[$datas]['lid'] = $srv_member_lid;
                            }
                        }


                    }

                    if (preg_match("/set action/i", $names_line)) {
                        $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                        $Action = trim($data[2]);
                        if ($Action == "accept") {
                            $Action = "allow";
                            $checkit = 0;
                        } elseif ($Action == "deny") {
                            $Action = "deny";
                            $checkit = 0;
                        } elseif ($Action == "ipsec") {
                            $Action = "allow";
                            $checkit = 1;
                            //add_log('warning', 'Security Rule Checking', 'Security Rule ID ' . $lid . '] has action set to ipsec', $source, 'Rule was used for tunnels. Review it.');
                            add_log2('warning', 'Security Rule Checking', 'Security Rule ID ' . $lid . '] has action set to ipsec', $source, 'Rule was used for tunnels. Review it.', 'rules', $lid, 'security_rules');

                        } else {
                            $Action = "deny";
                            $checkit = 0;
                        }
                    }

                    if (preg_match("/set comments/i", $names_line) || $multi_line_comment) {
                        $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                        $count = count($data);
                        $Commentsa = "";
                        if($count>=3){
                            for($i=2;$i<$count;$i++){
                                $Commentsa.= trim($data[$i]);
                            }
                        }
                        //Check if the comments contains one than 1 line, by checking if it ends with "
                        if($multi_line_comment){
                            $Comments .= " " . normalizeComments($names_line);
                        }else {
                            $Comments = normalizeComments($Commentsa);
                        }
                        $multi_line_comment = !endsWith($names_line, "\"\n");
                    }

                    if (preg_match("/set status/i", $names_line)) {
                        $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                        $status = trim($data[2]);
                        if ($status == "enable") {
                            $status = 0;
                        } elseif ($status == "disable") {
                            $status = 1;
                        } else {
                            $status = 0;
                        }
                    }

                    if (preg_match("/set dstaddr-negate/i", $names_line)) {
                        $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                        $negate = trim($data[2]);
                        if ($negate == "enable") {
                            $negate_destination = 1;
                        } elseif ($negate == "disable") {
                            $negate_destination = 0;
                        } else {
                            $negate_destination = 0;
                        }
                    }

                    if (preg_match("/set srcaddr-negate/i", $names_line)) {
                        $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                        $negate = trim($data[2]);
                        if ($negate == "enable") {
                            $negate_source = 1;
                        } elseif ($negate == "disable") {
                            $negate_source = 0;
                        } else {
                            $negate_source = 0;
                        }
                    }

                    if (preg_match("/set application-list/i", $names_line)) {
                        $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                        if ($data[2]=="default"){
                            $checkit = 0;
                        }
                        else{
                            $app_list_name="";
                            if(isset($data[2])){
                                $app_list_name=$data[2];
                            }
                            add_log2('warning', 'Security Rule Checking', 'Security Rule ID ' . $lid . ' (' . $RuleNamePan. ') is using an application-list '. $app_list_name, $source, 'Review it.', 'rules', $lid, 'security_rules');
                            $checkit = 1;
                        }
                    }

                    if (preg_match("/set nat enable/i", $names_line)) {
                        $nat_activated = 1;
                    }

                    if (preg_match("/set poolname/i", $names_line)) {
                        $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                        $i = count($data);
                        for ($ii=2;$ii<$i;$ii++){
                            $ippool[] = $data[$ii];
                        }
                    }

                    if (preg_match("/set global-label /i", $names_line)) {
                        $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                        $tag = truncate_tags(trim($data[2]));
                        if (isset($allTags[$tag])){
                            $tagid=$allTags[$tag];
                            $addTag[]="('$source','$lid','tag','$tagid','$vsys')";
                        }
                        else{
                            # Insert new Tag
                            $color = "color" . $thecolor;
                            $projectdb->query("INSERT INTO tag (name,source,vsys,color,used) VALUES ('$tag','$source','$vsys','$color',1);");
                            $allTags[$tag]=$projectdb->insert_id;
                            if ($thecolor == 16) {
                                $thecolor = 1;
                            } else {
                                $thecolor++;
                            }
                            $tagid=$projectdb->insert_id;
                            $addTag[]="('$source','$lid','tag','$tagid','$vsys')";
                        }
                    }
                }


            }
        }

        $lastline = $names_line;
    }

    if (count($sql_rule) > 0) {
        $projectdb->query("INSERT INTO security_rules (lid,position,name,source,vsys,description,action,disabled,checkit,negate_source,negate_destination) VALUES " . implode(",", $sql_rule) . ";");

        if (count($sql_src_zone) > 0) {
            $projectdb->query("INSERT INTO security_rules_from (source,vsys,name,rule_lid) VALUES " . implode(",", $sql_src_zone) . ";");
        }
        if (count($sql_dst_zone) > 0) {
            $projectdb->query("INSERT INTO security_rules_to (source,vsys,name,rule_lid) VALUES " . implode(",", $sql_dst_zone) . ";");
        }
        if (count($sql_src) > 0) {
            $projectdb->query("INSERT INTO security_rules_src (source,vsys,rule_lid,member_lid,table_name) VALUES " . implode(",", $sql_src) . ";");
        }
        if (count($sql_dst) > 0) {
            $projectdb->query("INSERT INTO security_rules_dst (source,vsys,rule_lid,member_lid,table_name) VALUES " . implode(",", $sql_dst) . ";");
        }
        if (count($sql_srv) > 0) {
            $projectdb->query("INSERT INTO security_rules_srv (source,vsys,rule_lid,member_lid,table_name) VALUES " . implode(",", $sql_srv) . ";");
        }
        if (count($addTag)>0){
            $projectdb->query("INSERT INTO security_rules_tag (source,rule_lid,table_name,member_lid,vsys) VALUES ".implode(",",$addTag).";");
        }
        // create the used zones while creating the security policies even if they are not defined in the interfaces
        if(count($zones)>0) {
            $unique_zones = array_unique($zones);
            foreach ($unique_zones as $zone) {
                $query="INSERT INTO zones (source,template,vsys,name,type) 
                        SELECT '$source', '$template', '$vsys', '$zone', 'layer3'
                        FROM dual
                        WHERE NOT EXISTS (
                            SELECT 1
                            FROM zones
                            WHERE name = '$zone' and source = '$source' and template = '$template'
                        );";
                $projectdb->query($query);
            }
        }
    }

    if (isset($addSNAT) && count($addSNAT) > 0) {
        if ($addSNAT != "") {
            $projectdb->query("INSERT INTO nat_rules (source,vsys,id,position,name,disabled,op_zone_to,op_to_interface,is_dat,op_service_lid,op_service_table,tp_sat_type,tp_sat_address_type,tp_sat_ipaddress,description,tp_sat_interface) VALUES " . implode(",", $addSNAT) . ";");
        }

        if (count($addNATFrom) > 0) {
            $projectdb->query("INSERT INTO nat_rules_from (source,vsys,rule_lid,name) VALUES " . implode(",", $addNATFrom) . ";");
        }
        if (count($addNATTranslatedAddress) > 0) {
            $projectdb->query("INSERT INTO nat_rules_translated_address (source,vsys,rule_lid,member_lid,table_name) VALUES " . implode(",", $addNATTranslatedAddress) . ";");
        }
        if (count($addNatSrc) > 0) {
            $projectdb->query("INSERT INTO nat_rules_src (source,vsys,rule_lid,member_lid,table_name) VALUES " . implode(",", $addNatSrc) . ";");
        }
        if (count($addNatDst) > 0) {
            $projectdb->query("INSERT INTO nat_rules_dst (source,vsys,rule_lid,member_lid,table_name) VALUES " . implode(",", $addNatDst) . ";");
        }

        # Check for Regions in NAT Rules
        $getRegionSrcLid=$projectdb->query("SELECT id,rule_lid,member_lid FROM nat_rules_src WHERE source='$source' AND table_name='default_regions';");
        if ($getRegionSrcLid->num_rows>0){
            while($getRegionSrcLidData=$getRegionSrcLid->fetch_assoc()){

            }
        }

    }

    # Check if there is any Address group with Regions as Member, if yes remove from the group, search Rules where the groups was used and add the Regions where used
    # Raise and Alert to the Groups with Regions
    $getRegion=$projectdb->query("SELECT lid,member_lid FROM address_groups WHERE source='$source' AND table_name='default_regions';");
    if ($getRegion->num_rows>0){
        $grouplid=array();
        $grouplidMembers=array();
        while($getRegionData=$getRegion->fetch_assoc()){
            $grouplid[]=$getRegionData['lid'];
            $grouplidMembers[$getRegionData['lid']]['members'][]=$getRegionData['member_lid'];
        }
        $grouplid=array_unique($grouplid);
        if (count($grouplid)>0){
            $addSRC=$addDST=array();
            $getGroup=$projectdb->query("SELECT id,name FROM address_groups_id WHERE id IN (".implode(",",$grouplid).");");
            if ($getGroup->num_rows>0){
                while($getGroupData=$getGroup->fetch_assoc()){
                    $groupName=$getGroupData['name'];
                    $lid=$getGroupData['id'];
                    $grouplidMembers[$lid]['name']=$groupName;
                    add_log2("error",'Reading Address Groups','Found GEO references as Member of an Address Group named ['.$groupName.']',$source,'Expedition will replace by Regions where the group is used.','objects',$lid,'address_groups');
                }
            }

            foreach($grouplidMembers as $groupID=>$groupMembers){
                $getSecuritySRC=$projectdb->query("SELECT rule_lid FROM security_rules_src WHERE source='$source' AND table_name='address_groups_id' AND member_lid='$groupID';");
                if ($getSecuritySRC->num_rows>0){
                    while($getSecuritySRCData=$getSecuritySRC->fetch_assoc()){
                        $ruleAffected=$getSecuritySRCData['rule_lid'];
                        foreach($groupMembers['members'] as $memberRegions){
                            $addSRC[]= "('$source','default_regions','$memberRegions','$ruleAffected')";
                        }

                    }
                }
                $getSecurityDST=$projectdb->query("SELECT rule_lid FROM security_rules_dst WHERE source='$source' AND table_name='address_groups_id' AND member_lid='$groupID';");
                if ($getSecurityDST->num_rows>0){
                    while($getSecurityDSTData=$getSecurityDST->fetch_assoc()){
                        $ruleAffected=$getSecurityDSTData['rule_lid'];
                        foreach($groupMembers['members'] as $memberRegions){
                            $addDST[]= "('$source','default_regions','$memberRegions','$ruleAffected')";
                        }

                    }
                }
            }
            if (count($addSRC)>0){
                $projectdb->query("INSERT INTO security_rules_src (source,table_name,member_lid,rule_lid) VALUES ".implode(",",$addSRC).";");
            }
            if (count($addDST)>0){
                $projectdb->query("INSERT INTO security_rules_dst (source,table_name,member_lid,rule_lid) VALUES ".implode(",",$addDST).";");
            }
        }
        # Clean the Regions as Members from Groups
        $projectdb->query("DELETE FROM address_groups WHERE source='$source' AND table_name='default_regions';");
        # Check if Group now is Empty
        foreach ($grouplid as $groupID){
            $getEmpty=$projectdb->query("SELECT id FROM address_groups WHERE lid='$groupID';");
            if ($getEmpty->num_rows==0){
                $groupName=$grouplidMembers[$groupID]['name'];
                add_log2('info','Replacing Regions from Groups to Rules','While we replaced Regions where part from an Address Group into the Rules the Group became empty.',$source,'Group ['.$groupName.'] has been Removed','objects',$groupID,'address_groups_id');
                $projectdb->query("DELETE FROM security_rules_src WHERE member_lid='$groupID' AND table_name='address_groups_id';");
                $projectdb->query("DELETE FROM security_rules_dst WHERE member_lid='$groupID' AND table_name='address_groups_id';");
                $projectdb->query("DELETE FROM address_groups_id WHERE id='$groupID';");
            }
        }

    }
}

function remove_regions_from_nat($source,$vsys){
    global $projectdb;
    $RegionsFound=array();

    $getDFRegions=$projectdb->query("SELECT id,name FROM default_regions;");
    if ($getDFRegions->num_rows>0){
        while($getDFRegionsData=$getDFRegions->fetch_assoc()){
            $defaultRegions[$getDFRegionsData['id']]=$getDFRegionsData['name'];
        }
    }

    //$ids_rules = getNatIdsBySourceVsys($source, $vsys);
    $ids_rules = getIdsBySourceVsys("nat_rules", $source, $vsys);

    if(count($ids_rules)>0){
        $getRegions=$projectdb->query("SELECT rule_lid,member_lid FROM nat_rules_src WHERE table_name='default_regions' AND rule_lid IN (".implode(',', $ids_rules).");");
        if ($getRegions->num_rows>0){
            while($getRegionsData=$getRegions->fetch_assoc()){
                $rule_lid=$getRegionsData['rule_lid'];
                $member_lid=$getRegionsData['member_lid'];
                if (isset($defaultRegions[$member_lid])){
                    $regionName=$defaultRegions[$member_lid];
                    $RegionsFound[$rule_lid][]=$regionName;
                }
            }
            if (count($RegionsFound)>0){
                foreach($RegionsFound as $Rule=>$Region){
                    add_log2("warning","Removing Regions from NAT Rules",'Nat RuleID ['.$Rule.'] contains Regions ['.implode(",",$Region).']',$source,'Expedition will Remove Regions from Nat Rules','rules',$Rule,'nat_rules');
                }
                $projectdb->query("DELETE FROM nat_rules_src WHERE rule_lid IN (".implode(",",array_keys($RegionsFound))." AND table_name='default_regions')");
            }
        }

        $getRegions=$projectdb->query("SELECT rule_lid,member_lid FROM nat_rules_dst WHERE table_name='default_regions' AND rule_lid IN (".implode(',', $ids_rules).");");
        if ($getRegions->num_rows>0){
            while($getRegionsData=$getRegions->fetch_assoc()){
                $rule_lid=$getRegionsData['rule_lid'];
                $member_lid=$getRegionsData['member_lid'];
                if (isset($defaultRegions[$member_lid])){
                    $regionName=$defaultRegions[$member_lid];
                    $RegionsFound[$rule_lid][]=$regionName;
                }
            }
            if (count($RegionsFound)>0){
                foreach($RegionsFound as $Rule=>$Region){
                    add_log2("warning","Removing Regions from NAT Rules",'Nat RuleID ['.$Rule.'] contains Regions ['.implode(",",$Region).']',$source,'Expedition will Remove Regions from Nat Rules','rules',$Rule,'nat_rules');
                }
                $projectdb->query("DELETE FROM nat_rules_dst WHERE rule_lid IN (".implode(",",array_keys($RegionsFound))." AND table_name='default_regions')");
            }
        }
    }
}

function add_nat_from_vip($fortinet_config_file, $vsys, $source, $template, $ismultiornot) {
    global $projectdb;
    $nat_lid = "";
    $addDestination = "";
    $addRule=$addDestination=$addSource=$addFROM=$addTranslated=$addTag=array();
    $dnat=$snat=$uturn=$binat=false;
    $DNAT_tag=$SNAT_tag=$UTURN_tag=$BINAT_tag=0;
    $checkit=0;
    $getVIP = $projectdb->query("SELECT protocol,name,extip,extintf,portforward,mappedip,extport,mappedport,vsys,source FROM fortinet_vip WHERE vsys='$vsys' AND source='$source';");
    if ($getVIP->num_rows > 0) {
        # Create new TAGS for Nat RULEs DNAT and SNAT and U-TURN
        $getTags=$projectdb->query("SELECT id,name FROM tag WHERE name IN ('DNAT','SNAT','U-TURN','BINAT') AND source='$source' AND vsys='$vsys';");
        if ($getTags->num_rows>0){
            $dnat=$snat=$uturn=false;
            while($getTagsData=$getTags->fetch_assoc()){
                if ($getTagsData['name']=="DNAT"){
                    $dnat=true;
                    $DNAT_tag=$getTagsData['id'];
                }
                if ($getTagsData['name']=="SNAT"){
                    $snat=true;
                    $SNAT_tag=$getTagsData['id'];
                }
                if ($getTagsData['name']=="U-TURN"){
                    $uturn=true;
                    $UTURN_tag=$getTagsData['id'];
                }
                if ($getTagsData['name']=="BINAT"){
                    $binat=true;
                    $BINAT_tag=$getTagsData['id'];
                }
            }
        }

        if ($dnat==false){
            $projectdb->query("INSERT INTO tag (name,name_ext,source,vsys,devicegroup,color,comments) VALUES ('DNAT','DNAT','$source','$vsys','default','color1','Created by Expedition');");
            $DNAT_tag=$projectdb->insert_id;
        }
        if ($snat==false){
            $projectdb->query("INSERT INTO tag (name,name_ext,source,vsys,devicegroup,color,comments) VALUES ('SNAT','SNAT','$source','$vsys','default','color2','Created by Expedition');");
            $SNAT_tag=$projectdb->insert_id;
        }
        if ($uturn==false){
            $projectdb->query("INSERT INTO tag (name,name_ext,source,vsys,devicegroup,color,comments) VALUES ('U-TURN','U-TURN','$source','$vsys','default','color3','Created by Expedition');");
            $UTURN_tag=$projectdb->insert_id;
        }
        if ($binat==false){
            $projectdb->query("INSERT INTO tag (name,name_ext,source,vsys,devicegroup,color,comments) VALUES ('BINAT','BINAT','$source','$vsys','default','color4','Created by Expedition');");
            $BINAT_tag=$projectdb->insert_id;
        }

        $getPosition = $projectdb->query("SELECT max(position) as t FROM nat_rules WHERE vsys='$vsys' AND source='$source';");
        if ($getPosition->num_rows == 0) {
            $position = 0;
        } else {
            $ddata = $getPosition->fetch_assoc();
            $position = $ddata['t'] ;
        }
        if ($nat_lid == "") {
            $getlastlid = $projectdb->query("SELECT max(id) as max FROM nat_rules;");
            $getLID1 = $getlastlid->fetch_assoc();
            $nat_lid = intval($getLID1['max']);
        }

        # Load Interfaces
        $loadInterface=$projectdb->query("SELECT unitipaddress,unitname,zone FROM interfaces WHERE template='$template' AND source='$source' AND unitipaddress !='';");
        if ($loadInterface->num_rows>0){
            $interfaces=array();
            while($loadInterfaceData=$loadInterface->fetch_assoc()){
                $interfacesRaw=explode(",",$loadInterfaceData['unitipaddress']);
                foreach($interfacesRaw as $interfacesRawItem){
                    $interfaces[$interfacesRawItem]["zone"]=$loadInterfaceData['zone'];
                    $interfaces[$interfacesRawItem]["name"]=$loadInterfaceData['unitname'];
                }
            }
        }

        # Pre load Objects with the interface information
        $objectsInMemory=array();
        foreach ($interfaces as $checkNet=>$properties){
            $interfacesRaw=explode("/",$checkNet);
            $interfacesRawIP=$interfacesRaw[0];
            $interfacesRawMask=$interfacesRaw[1];
            $interfacesNet = long2ip((ip2long($interfacesRawIP)) & ((-1 << (32 - (int)$interfacesRawMask))));
            $theNetwork=$interfacesNet."/".$interfacesRawMask;
            $getAddress=$projectdb->query("SELECT id FROM address WHERE source='$source' AND (vsys='$vsys' OR vsys='shared')  AND ipaddress='$interfacesNet' AND cidr='$interfacesRawMask' LIMIT 1;");
            if ($getAddress->num_rows>0){
                $getAddressData=$getAddress->fetch_assoc();
                $objectsInMemory[$theNetwork]=$getAddressData['id'];
            }
        }

        # GET Virtual Router based on VSYS
        $getVR=$projectdb->query("SELECT id FROM virtual_routers WHERE vsys='$vsys' AND template='$template' AND source='$source';");
        if ($getVR->num_rows>0){
            $getVRDAta=$getVR->fetch_assoc();
            $vr=$getVRDAta['id'];
        }

        while ($data = $getVIP->fetch_assoc()) {
            $ruleName = $data['name'];
            $ruleNameClean=truncate_rulenames(normalizeNames($ruleName));
            $to = '';
            $from = $data['extintf'];
            $extport = $data['extport'];
            $protocol = $data['protocol'];
            $tp_dat_port = $data['mappedport'];
            $extip = $data['extip'];
            $mappedip = $data['mappedip'];
            $portforward=$data['portforward'];

            if ($from=="any"){
                $addUturn=true;
            }
            else{
                $addUturn=false;
            }

            if ($extport != "") {
                $name = $protocol . "-" . $extport;
                $getSRV = $projectdb->query("SELECT id FROM services WHERE dport='$extport' AND protocol='$protocol' AND vsys='$vsys' AND source='$source' GROUP BY dport,protocol;");
                if ($getSRV->num_rows == 0) {
                    //$name = $protocol . "-" . $extport;
                    $projectdb->query("INSERT INTO services (source,vsys,name_ext,name,dport,protocol,description) VALUES ('$source','$vsys','$name','$name','$extport','$protocol','Created by Expedition')");
                    $op_service_lid = $projectdb->insert_id;
                    $op_service_table = "services";
                }
                else {
                    $dddata = $getSRV->fetch_assoc();
                    $op_service_lid = $dddata['id'];
                    $op_service_table = "services";
                }
            } else {
                $op_service_lid = '';
                $op_service_table = '';
            }

            $getExtip = $projectdb->query("SELECT id,type FROM address WHERE BINARY(name)='$ruleName' AND ipaddress='$extip' AND vsys='$vsys' AND source='$source';");
            if ($getExtip->num_rows > 0) {
                $AddDST=true;
                $dddata = $getExtip->fetch_assoc();
                $dst_lid = $dddata['id'];
                $dst_type = $dddata['type'];
                $dst_table = "address";


            }
            else {
                $AddDST=false;
                if (preg_match("/\-/", $extip)) {
                    #Range
                    $newName = "range-" . $extip;
                    $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,description,type,vtype) VALUES ('$source','$vsys','$newName','$newName','$extip','','Created by Expedition','ip-range','')");
                    $dst_lid = $projectdb->insert_id;
                    $dst_table = "address";
                    $dst_type = "ip-range";
                }
                else {
                    #IP-netmask
                    $newName = "H-" . $extip;
                    if(ip_version($extip)=="v6"){
                        $projectdb->query("INSERT INTO address (v6,v4,source,vsys,name_ext,name,ipaddress,cidr,description,type,vtype) VALUES ('1','0','$source','$vsys','$newName','$newName','$extip','128','Created by Expedition','ip-netmask','')");
                    }else {
                        $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,description,type,vtype) VALUES ('$source','$vsys','$newName','$newName','$extip','32','Created by Expedition','ip-netmask','')");
                    }
                    $dst_lid = $projectdb->insert_id;
                    $dst_table = "address";
                    $dst_type = "ip-netmask";
                }
            }


            $getMappedip = $projectdb->query("SELECT id,type FROM address WHERE ipaddress='$mappedip' AND vsys='$vsys' AND source='$source' GROUP BY ipaddress;");
            if ($getMappedip->num_rows > 0) {
                $dddata = $getMappedip->fetch_assoc();
                $tp_dat_address_lid = $dddata['id'];
                $tp_dat_address_table = "address";
                $dat_type = $dddata['type'];
            }
            else {
                if (preg_match("/\-/", $mappedip)) {
                    #Range
                    $newName = "range-" . $mappedip;
                    $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,description,type,vtype) VALUES ('$source','$vsys','$newName','$newName','$mappedip','','Created by Expedition','ip-range','ip-range')");
                    $tp_dat_address_lid = $projectdb->insert_id;
                    $tp_dat_address_table = "address";
                    $dat_type = "ip-range";
                } else {

                    // Check if the address already exists
                    $search_address_query = "SELECT id, type from address where name = '$mappedip'";
                    $search_address_result = $projectdb->query($search_address_query);
                    if($search_address_result->num_rows>0){

                        $search_address_data = $search_address_result->fetch_assoc();
                        $tp_dat_address_lid = $search_address_data['id'];
                        $tp_dat_address_table = "address";
                        $dat_type = $search_address_data['type'];

                    }else {

                        #IP-netmask
                        $newName = "H-" . $mappedip;
                        if (ip_version($mappedip) == "v6") {
                            $projectdb->query("INSERT INTO address (v6,v4,source,vsys,name_ext,name,ipaddress,cidr,description,type,vtype) VALUES ('1','0','$source','$vsys','$newName','$newName','$mappedip','128','Created by Expedition','ip-netmask','')");
                        } else {
                            $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,description,type,vtype) VALUES ('$source','$vsys','$newName','$newName','$mappedip','32','Created by Expedition','ip-netmask','ip-netmask')");
                        }
                        $tp_dat_address_lid = $projectdb->insert_id;
                        $tp_dat_address_table = "address";
                        $dat_type = "ip-netmask";
                    }
                }
            }

            if ($addUturn==true){
                $position++;
                $nat_lid++;

                if($dat_type=="fqdn"){
                    $checkit = 1;
                    //add_log('error', 'Nat Rule Checking', 'Nat Rule ID [' . $nat_lid . '] Mismatch of destination address translation range between original address and translated address', $source, 'Probably nat based on load balance vip from Fortinet');
                    add_log2('error', 'Nat Rule Checking', 'Nat Rule ID [' . $nat_lid . '] Contains an FQDN as destination address translation.', $source, 'Please check the FQDN can be resolved', 'rules', $nat_lid, 'nat_rules');
                }

                # get The network from the Translated Address
                $foundInterface=false;
                $foundStatic=false;
                foreach($interfaces as $checkNet=>$properties){

                    if (preg_match("/\-/", $mappedip)) {
                        $mappedRaw=explode("-",$mappedip);
                        $mappedip=$mappedRaw[0];
                    }

                    if (netMatchV4($checkNet, $mappedip)==TRUE){
                        $matchedNetworkRaw=explode("/",$checkNet);
                        $matchedNetwork=$matchedNetworkRaw[0];
                        $matchedNetmask=$matchedNetworkRaw[1];
                        $matchedZone=$properties['zone'];
                        $matchedNetworkIP=$checkNet;
                        $matchedInterface=$properties['name'];
                        $interfacesNet = long2ip((ip2long($matchedNetwork)) & ((-1 << (32 - (int)$matchedNetmask))));
                        $matchedTheNetwork=$interfacesNet."/".$matchedNetmask;
                        $foundInterface=true;
                    }
                }

                if ($foundInterface==false){
                    $matchedZone="";
                    #Check if Network Object Exists
                    if (preg_match("/\-/", $mappedip)) {
                        $mappedRaw=explode("-",$mappedip);
                        $mappedip=$mappedRaw[0];
                    }

                    //add_log2('warning','Creating U-Turn Nats FROM VIPs','Unable to calculate netmask for IP/Range ['.$mappedip.'] on Nat Rule ['.$nat_lid.']',$source,'Attaching 24 as CIDR. Please review','rules',$nat_lid,'nat_rules');
                    $matchedNetmask=24;
                    $matchedNetworkIP='';
                    $matchedInterface='';
                    $interfacesNet = long2ip((ip2long($mappedip)) & ((-1 << (32 - (int)$matchedNetmask))));
                    $matchedTheNetwork=$interfacesNet."/".$matchedNetmask;
                }

                if (!isset($objectsInMemory[$matchedTheNetwork])){
                    $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,description,type,vtype) VALUES ('$source','$vsys','NET-$interfacesNet-$matchedNetmask','NET-$interfacesNet-$matchedNetmask','$interfacesNet','$matchedNetmask','Created by Expedition','ip-netmask','ip-netmask')");
                    $objectsInMemory[$matchedTheNetwork]=$projectdb->insert_id;
                }
                $member_lid=$objectsInMemory[$matchedTheNetwork];
                //$addSource[]="('$source','$vsys','$nat_lid','$member_lid','address')";
                $ruleNameUTURN=truncate_rulenames("InternalAccess-".$ruleNameClean);

                # Fix Destination Zone in case is ANY
                if ($to==""){
                    $getTO=getAutoZoneToVR($vr, $dst_lid, $dst_table, $vsys, $source);
                    if ((count($getTO)>0) AND (key($getTO)!='')){
                        $to=key($getTO);
                    }
                }

                if ($matchedZone==""){
                    $getTO=getAutoZoneToVR($vr, $member_lid, 'address', $vsys, $source);
                    if ((count($getTO)>0) AND (key($getTO)!='')){
                        $matchedZone=key($getTO);
                        if ($matchedNetworkIP==""){
                            $getInt=$projectdb->query("SELECT unitname,unitipaddress FROM interfaces WHERE zone='$matchedZone' AND source='$source' AND template='$template';");
                            if ($getInt->num_rows>0){
                                $getIntData=$getInt->fetch_assoc();
                                $matchedNetworkIP=$getIntData['unitipaddress'];
                                $matchedInterface=$getIntData['unitname'];
                            }
                        }
                    }
                }

                $addRule[] = "('0','0',$checkit,'$nat_lid','$source','$vsys','$ruleNameUTURN',1,'$position','Added from VIP','$to','','','','$tp_dat_address_lid','$tp_dat_address_table','dynamic-ip-and-port','interface-address','$matchedNetworkIP','$matchedInterface')";
                $addTag[] = "('$nat_lid','$UTURN_tag','tag')";
                $addFROM[] = "('$source','$vsys','$nat_lid','$matchedZone')";
                $addDestination[] = "('$source','$vsys','$nat_lid','$dst_lid','$dst_table')";

            }

            # Add the Destination Nat Rule
            $position++;
            $nat_lid++;

            if($dat_type=="fqdn"){
                $checkit = 1;
                //add_log('error', 'Nat Rule Checking', 'Nat Rule ID [' . $nat_lid . '] Mismatch of destination address translation range between original address and translated address', $source, 'Probably nat based on load balance vip from Fortinet');
                add_log2('error', 'Nat Rule Checking', 'Nat Rule ID [' . $nat_lid . '] Contains an FQDN as destination address translation.', $source, 'Please check the FQDN can be resolved', 'rules', $nat_lid, 'nat_rules');
            } else if ($dst_type != $dat_type) {
                $checkit = 1;
                //add_log('error', 'Nat Rule Checking', 'Nat Rule ID [' . $nat_lid . '] Mismatch of destination address translation range between original address and translated address', $source, 'Probably nat based on load balance vip from Fortinet');
                add_log2('error', 'Nat Rule Checking', 'Nat Rule ID [' . $nat_lid . '] Mismatch of destination address translation range between original address and translated address', $source, 'Probably nat based on load balance vip from Fortinet', 'rules', $nat_lid, 'nat_rules');
            }

            # In case the mapped port its a range just keep any



            if (preg_match("/-/",$tp_dat_port)){$tp_dat_port='';}

            if ($from!="any"){
                $addFROM[] = "('$source','$vsys','$nat_lid','$from')";
            }
            else{
                $from="";
            }

            if ($to=="any"){$to='';}
            if ($AddDST==true){
                $addDestination[] = "('$source','$vsys','$nat_lid','$dst_lid','$dst_table')";
                # Fix Destination Zone in case is ANY
                if ($to==""){
                    $getTO=getAutoZoneToVR($vr, $dst_lid, $dst_table, $vsys, $source);
                    if ((count($getTO)>0) AND (key($getTO)!='')){
                        $to=key($getTO);
                    }
                }
            }
            $ruleNameCleanA = truncate_rulenames("Inbound-".$ruleNameClean);
            $snat_disabled = 0;
            if($portforward==0){
                $snat_disabled = 1;
            }
            $addRule[] = "('0','$snat_disabled','$checkit','$nat_lid','$source','$vsys','$ruleNameCleanA',1,'$position','Added from VIP','$to','$op_service_lid','$op_service_table','$tp_dat_port','$tp_dat_address_lid','$tp_dat_address_table','','','','')";
            $addTag[] = "('$nat_lid','$DNAT_tag','tag')";



            if ($portforward==0){

                # If the port forward is not set we should have to create the Source Nat to force the nat like static-ip
                $position++;
                $nat_lid++;

                if (($tp_dat_address_lid!="") AND ($tp_dat_address_table!="")){
                    $addSource[]="('$source','$vsys','$nat_lid','$tp_dat_address_lid','$tp_dat_address_table')";
                }

                # Fix Destination Zone in case is ANY
                if ($to==""){
                    $getTO=getAutoZoneToVR($vr, $dst_lid, $dst_table, $vsys, $source);
                    if ((count($getTO)>0) AND (key($getTO)!='')){
                        $to=key($getTO);
                    }
                }

                if ($from==""){
                    $getFROM=getAutoZoneToVR($vr, $tp_dat_address_lid, $tp_dat_address_table, $vsys, $source);
                    if ((count($getFROM)>0) AND (key($getFROM)!='')){
                        $from=key($getFROM);
                        $addFROM[] = "('$source','$vsys','$nat_lid','$from')";
                    }
                }

                $addTranslated[] = "('$source','$vsys','$nat_lid','$dst_lid','$dst_table')";
                $ruleNameCleanB=truncate_rulenames("Outbond-".$ruleNameClean);

                if($dat_type=="fqdn"){
                    $checkit = 1;
                    //add_log('error', 'Nat Rule Checking', 'Nat Rule ID [' . $nat_lid . '] Mismatch of destination address translation range between original address and translated address', $source, 'Probably nat based on load balance vip from Fortinet');
                    add_log2('error', 'Nat Rule Checking', 'Nat Rule ID [' . $nat_lid . '] Contains an FQDN as destination address translation.', $source, 'Please check the FQDN can be resolved', 'rules', $nat_lid, 'nat_rules');
                } else if($checkit==1){
                    // inherit the warning coming from the previous NAT rule
                    add_log2('error', 'Nat Rule Checking', 'Nat Rule ID [' . $nat_lid . '] Mismatch of destination address translation range between original address and translated address', $source, 'Probably nat based on load balance vip from Fortinet', 'rules', $nat_lid, 'nat_rules');
                }
                $addRule[] = "('0','1','$checkit','$nat_lid','$source','$vsys','$ruleNameCleanB',0,'$position','Added from VIP','$to','','','','','','dynamic-ip-and-port','translated-address','','')";
                $addTag[] = "('$nat_lid','$SNAT_tag','tag')";


                // Create a bi-directional NAT rule to merge the SNAT and DNAT rule in one single rule
                $nat_lid++;
                $position++;

                if (($tp_dat_address_lid!="") AND ($tp_dat_address_table!="")){
                    $addSource[]="('$source','$vsys','$nat_lid','$tp_dat_address_lid','$tp_dat_address_table')";
                }
                if($from!=""){$addFROM[] = "('$source','$vsys','$nat_lid','$from')";}
                $addTranslated[] = "('$source','$vsys','$nat_lid','$dst_lid','$dst_table')";
                $ruleNameCleanB=truncate_rulenames("Bi-dir-".$ruleNameClean);

                if($dat_type=="fqdn"){
                    $checkit = 1;
                    //add_log('error', 'Nat Rule Checking', 'Nat Rule ID [' . $nat_lid . '] Mismatch of destination address translation range between original address and translated address', $source, 'Probably nat based on load balance vip from Fortinet');
                    add_log2('error', 'Nat Rule Checking', 'Nat Rule ID [' . $nat_lid . '] Contains an FQDN as destination address translation.', $source, 'Please check the FQDN can be resolved', 'rules', $nat_lid, 'nat_rules');
                }else if($checkit==1){
                    // inherit the warning coming from the previous NAT rule
                    add_log2('error', 'Nat Rule Checking', 'Nat Rule ID [' . $nat_lid . '] Mismatch of destination address translation range between original address and translated address', $source, 'Probably nat based on load balance vip from Fortinet', 'rules', $nat_lid, 'nat_rules');
                }
                $addRule[] = "('1','0','$checkit','$nat_lid','$source','$vsys','$ruleNameCleanB',0,'$position','Added from VIP','$to','','','','','','static-ip','','','')";
                $addTag[] = "('$nat_lid','$BINAT_tag','tag')";


                $ruleName = "";
                $ruleNameClean=$ruleNameCleanB="";
                $to = "";
                $op_service_lid = "";
                $op_service_table = "";
                $tp_dat_port = "";
                $tp_dat_address_lid = "";
                $tp_dat_address_table = "";
                $checkit = 0;
            }

            $ruleNameClean=$ruleNameCleanA=$ruleNameUTURN=$ruleNameCleanB="";
            $to = "";
            $op_service_lid = "";
            $op_service_table = "";
            $tp_dat_port = "";
            $tp_dat_address_lid = "";
            $tp_dat_address_table = "";
            $checkit = 0;

        }
        if (count($addRule) > 0) {
            $projectdb->query("INSERT INTO nat_rules (tp_sat_bidirectional,disabled,checkit,id,source,vsys,name,is_dat,position,description,op_zone_to,op_service_lid,op_service_table,tp_dat_port,tp_dat_address_lid,tp_dat_address_table,tp_sat_type,tp_sat_address_type,tp_sat_ipaddress,tp_sat_interface) VALUES " . implode(",", $addRule) . ";");
            unset($addRule);
            if ((count($addDestination) > 0) AND ($addDestination!="")) {
                $projectdb->query("INSERT INTO nat_rules_dst (source,vsys,rule_lid,member_lid,table_name) VALUES " . implode(",", $addDestination) . ";");
                unset($addDestination);
            }
            if ((count($addSource) > 0) AND ($addSource!="")) {
                $projectdb->query("INSERT INTO nat_rules_src (source,vsys,rule_lid,member_lid,table_name) VALUES " . implode(",", $addSource) . ";");
                unset($addSource);
            }
            if ((count($addFROM)>0) AND ($addFROM!="")){
                $projectdb->query("INSERT INTO nat_rules_from (source,vsys,rule_lid,name) VALUES " . implode(",", $addFROM) . ";");
                unset($addFROM);
            }
            if (count($addTranslated)>0){
                $projectdb->query("INSERT INTO nat_rules_translated_address (source,vsys,rule_lid,member_lid,table_name) VALUES ".implode(",",$addTranslated).";");
                unset($addTranslated);
            }
            if (count($addTag)>0){
                $projectdb->query("INSERT INTO nat_rules_tag (rule_lid,member_lid,table_name) VALUES ".implode(",",$addTag).";");
            }

        }

    }

}

function get_routes($fortinet_config_file, $source, $vsys, $ismultiornot, $vr_id, $template, $static) {
    global $projectdb;
    $isRouting = false;
    $isRoute = false;
    $network = "";
    $netmask = "";
    $metric = "1";
    $isDisabled=false;
    $gateway = "";
    $zoneName = "";
    $lastline = "x";
    $routes = array();
    $count = 0;
    if ($ismultiornot == "singlevsys") {
        $START = TRUE;
        $VDOM = FALSE;
    } else {
        $START = FALSE;
        $VDOM = FALSE;
    }

    foreach ($fortinet_config_file as $line => $names_line) {
        if ($START == FALSE) {
            if (preg_match("/^config vdom/i", $names_line)) {
                $VDOM = TRUE;
            }
            if ($VDOM == TRUE) {
                if (preg_match("/^edit $vsys/i", $names_line)) {
                    $START = TRUE;
                }
            }
        } else {
            if ((preg_match("/^\bend\b/i", $lastline)) AND ( preg_match("/^end/i", $names_line))) {
                $START = FALSE;
                $VDOM = FALSE;
            } elseif ((preg_match("/^edit/i", $lastline)) and ( preg_match("/^end/i", $names_line))) {
                $START = FALSE;
                $VDOM = FALSE;
            }
        }
        if ($START) {

            if (preg_match("/config router $static/i", $names_line)) {
                $isRouting = true;
            }
            if ((preg_match("/\bend\b/i", $names_line)) and ( $isRouting == true)) {
                $isRouting = false;
                break;
            };
            if ($isRouting == true) {

                if (preg_match("/\bedit\b/i", $names_line)) {
                    $isRoute = true;
                    $network = "";
                    $netmask = "";
                    $metric = "1";
                    $gateway = "";
                    $zoneName = "";
                    $ip_version = "";
                    $distance = "";
                    $nexthop_value = "";
                    $isDisabled=false;
                    $nexthop="None";
                    $destination = "";
                    $interface = "";
                    $vars = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                    if($static==='static6'){
                        $name = "Route v6 " . trim($vars[1]);
                    }else {
                        $name = "Route " . trim($vars[1]);
                    }
                }
                elseif ((preg_match("/\bnext\b/i", $names_line)) AND ($isDisabled==false) ){
                    $isRoute = false;
                    //$vars = "";
                    $vars = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);

                    if ($metric == "0") {
                        $metric = "1";
                    } else {
                        $metric = "10";
                    }

                    if (($network == "0.0.0.0") and ( $netmask == "0.0.0.0")) {
                        if ($count == 0) {
                            $routes[] = "('$source','$vr_id','$template','$ip_version','default','$destination','$interface','$nexthop','$nexthop_value','$metric','$vsys','$distance')";
                            $count++;
                        }
                        else {
                            $newRouteName = "default " . $count;
                            $routes[] = "('$source','$vr_id','$template','$ip_version','$newRouteName','$destination','$interface','$nexthop','$nexthop_value','$metric','$vsys','$distance')";
                            $count++;
                        }
                    }
                    elseif (($network == "") and ( $netmask == "") and ( $nexthop_value != "")) {
                        $destination="0.0.0.0/0";
                        $routes[] = "('$source','$vr_id','$template','$ip_version','$name','$destination','$interface','$nexthop','$nexthop_value','$metric','$vsys','$distance')";
                    }
                    elseif (($network != "") and ( $netmask != "") and ( ( $nexthop_value != "") OR ($nexthop=="discard")) ) {
                        $routes[] = "('$source','$vr_id','$template','$ip_version','$name','$destination','$interface','$nexthop','$nexthop_value','$metric','$vsys','$distance')";
                    }
                    elseif (($network != "") and ( $netmask != "") and ( $interface != "")) {
                        $routes[] = "('$source','$vr_id','$template','$ip_version','$name','$destination','$interface','$nexthop','$nexthop_value','$metric','$vsys','$distance')";
                        $interface="";
                    }
                }

                if ($isRoute == true) {
                    if (preg_match("/set distance /i", $names_line)) {
                        $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                        $distance = $data[2];
                    }

                    elseif (preg_match("/set status disable/i", $names_line)) {
                        $isDisabled = true;
                        $isRoute = false;
                    }

                    elseif (preg_match("/set metric /i", $names_line)) {
                        $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                        $metric = $data[2];
                    }
                    elseif (preg_match("/set device /i", $names_line)) {
                        $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                        $interfaceRaw = $data[2];
                        if ($interfaceRaw!=""){
                            $getInt=$projectdb->query("SELECT unitname FROM interfaces WHERE zone='$interfaceRaw' AND source='$source';");
                            if ($getInt->num_rows==1){
                                $getIntData=$getInt->fetch_assoc();
                                $interface=$getIntData['unitname'];
                            }
                        }
                    }
                    elseif (preg_match("/set dst /i", $names_line)) {
                        $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                        $network = $data[2];
                        $netmask = $data[3];
                        $cidr = mask2cidrv4($netmask);
                        $destination = $network . "/" . $cidr;
                        $ip_version = ip_version($network);
                    }
                    elseif (preg_match("/set gateway /i", $names_line)) {
                        $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                        $nexthop_value = $data[2];
                        $nexthop="ip-address";
                        $ip_version = ip_version($nexthop_value);
                    }
                    elseif (preg_match("/set blackhole enable/i",$names_line)){
                        $nexthop="discard";
                    }
                    else {

                    }
                }
            }
        }
        $lastline = $names_line;
    }
    return $routes;
}

function get_ippools($fortinet_config_file, $source, $vsys, $ismultiornot) {

    global $projectdb;
    $isObject = FALSE;
    $isAddress = FALSE;
    $addHost = array();
    $addressName="";
    $endip="";
    $startip="";
    $addressNamePan="";

    $addVIP = array();

    if ($ismultiornot == "singlevsys") {
        $START = TRUE;
        $VDOM = FALSE;
    } else {
        $START = FALSE;
        $VDOM = FALSE;
    }
    $lastline = "";
    foreach ($fortinet_config_file as $line => $names_line) {
        if ($START == FALSE) {
            if (preg_match("/^config vdom/i", $names_line)) {
                $VDOM = TRUE;
            }
            if ($VDOM == TRUE) {
                if (preg_match("/^edit $vsys/i", $names_line)) {
                    $START = TRUE;
                }
            }
        } else {
            if ((preg_match("/^end/i", $lastline)) AND ( preg_match("/^end/i", $names_line))) {
                $START = FALSE;
                $VDOM = FALSE;
            } elseif ((preg_match("/^edit/i", $lastline)) and ( preg_match("/^end/i", $names_line))) {
                $START = FALSE;
                $VDOM = FALSE;
            }
        }

        if ($START) {
            if (preg_match("/config firewall ippool/i", $names_line)) {
                $isObject = true;
            }


            if ($isObject) {
                if (preg_match("/^\bend\b/i", $names_line)) {
                    $isObject = false;
                    $START = false;
                }
                if (preg_match("/\bedit\b/i", $names_line)) {
                    $isAddress = true;
                    if (preg_match('/"([^"]+)"/', $names_line, $match)) {
                        $newname = str_replace('/', '-', $match[1]);
                        $addressNamePan = truncate_names(normalizeNames($newname));
                        $addressName = trim($match[1]);
                    }
                }

                if ($isAddress) {

                    if (preg_match("/\bstartip\b/i", $names_line)) {
                        $meta = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                        $startip = trim($meta[2]);
                    }

                    if (preg_match("/\bendip\b/i", $names_line)) {
                        $meta = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                        $endip = trim($meta[2]);
                    }
                    if (preg_match("/\bnext\b/i", $names_line)) {

                        $addVIP[] = "('$addressName','$source','$vsys','$endip','$startip')";
                        if ($startip == $endip) {
                            $addHost[] = "('$source','$vsys','$addressName','$addressNamePan','ip-netmask','$startip','32','Created from a IPPOOL','')";
                        } else {
                            $addHost[] = "('$source','$vsys','$addressName','$addressNamePan','ip-range','$startip-$endip','','Created from a IPPOOL','')";
                        }

                        $isAddress = false;
                        $endip = "";
                        $startip = "";
                        $addressNamePan = "";
                        $addressName = "";
                    }
                }
            }
        }


        $lastline = $names_line;
    }
    if (count($addVIP) > 0) {
        $projectdb->query("INSERT INTO fortinet_ippools (name,source,vsys,end_ip,start_ip) VALUES " . implode(",", $addVIP) . ";");
    }
    if (count($addHost) > 0) {
        if ($addHost != "") {
            $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,type,ipaddress,cidr,description,vtype) VALUES " . implode(",", $addHost) . ";");
        }
    }
}

function get_vip($fortinet_config_file, $source, $vsys, $ismultiornot, $vip) {

    global $projectdb;
    $isObject = FALSE;
    $isAddress = FALSE;
    $addHost = array();
    $addHost6 = array();
    $ipVipVersion = 0;
    $portforward = 0;
    $protocol = "tcp";
    $isFake = false;

    $addVIP = array();

    if ($ismultiornot == "singlevsys") {
        $START = TRUE;
        $VDOM = FALSE;
    } else {
        $START = FALSE;
        $VDOM = FALSE;
    }
    $lastline = "";
    foreach ($fortinet_config_file as $line => $names_line) {
        if ($START == FALSE) {
            if (preg_match("/^config vdom/i", $names_line)) {
                $VDOM = TRUE;
            }
            if ($VDOM == TRUE) {
                if (preg_match("/^edit $vsys/i", $names_line) AND ($isFake==false)) {
                    $START = TRUE;
                }
            }
        } else {
            if ((preg_match("/^end/i", $lastline)) AND ( preg_match("/^end/i", $names_line)) AND ($isFake==false)) {
                $START = FALSE;
                $VDOM = FALSE;
            } elseif ((preg_match("/^edit/i", $lastline)) and ( preg_match("/^end/i", $names_line)) AND ($isFake==false)) {
                $START = FALSE;
                $VDOM = FALSE;
            }
        }

        if ($START) {
            if (preg_match("/config firewall $vip/i", $names_line)) {
                $isObject = true;
                if($vip==='vip') {
                    $ipVipVersion = 4;
                }else{
                    $ipVipVersion = 6;
                }
            }

            if ($isObject) {
                if (preg_match("/^\bend\b/i", $names_line) AND ($isFake==false)) {
                    $isObject = false;
                    $START = false;
                    $ipVipVersion = 0;
                }
                if (preg_match("/\bedit\b/i", $names_line) AND ($isFake==false)) {
                    $isAddress = true;
                    if (preg_match('/"([^"]+)"/', $names_line, $match)) {
                        $newname = str_replace('/', '-', $match[1]);
                        $addressNamePan = truncate_names(normalizeNames($newname));
                        $addressName = trim($match[1]);
                        $type=$extip=$extintf=$mappedip=$mappedport=$extport="";$portforward=0;$protocol="tcp";
                        $isFake=false;
                    }
                }

                if ($isAddress) {

                    if (preg_match("/set type server-load-balance/",$names_line)){
                        $type="LB";
                    }

                    if (preg_match("/set extip /", $names_line)) {
                        $meta = explode("set extip ",$names_line);
                        $extip = trim($meta[1]);

                        if ($type=="LB"){
                            if($ipVipVersion===4) {
                                $addHost[] = "('$source','$vsys','$addressName','$addressNamePan','ip-netmask','$extip','32','Created from a VIP was Load Balancer Not supported by Expedition','')";
                            }else{
                                $addHost6[] = "('1','0','$source','$vsys','$addressName','$addressNamePan','ip-netmask','$extip','128','Created from a VIP6 was Load Balancer Not supported by Expedition','')";
                            }
                            $addressName="";
                            $type="";
                        }

                    }
                    if (preg_match("/set extintf /i", $names_line)) {
                        if (preg_match('/"([^"]+)"/', $names_line, $match)) {
                            $extintf = trim($match[1]);
                        }
                    }
                    if (preg_match("/set portforward /i", $names_line)) {
                        $meta = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                        if ($meta[2] == "enable") {
                            $portforward = 1;
                        } else {
                            $portforward = 0;
                        }
                    }
                    if (preg_match("/set mappedip /i", $names_line)) {
                        $meta = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                        $mappedip = trim($meta[2]);
                    }
                    if (preg_match("/set mapped-addr /i", $names_line)) {
                        $meta = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                        $mappedip = trim($meta[2]);
                    }
                    if (preg_match("/set extport /i", $names_line)) {
                        $meta = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                        $extport = trim($meta[2]);
                    }
                    if (preg_match("/set mappedport /i", $names_line)) {
                        $meta = explode("set mappedport ",$names_line);
                        $mappedport = trim($meta[1]);
                    }
                    if (preg_match("/set protocol /i", $names_line)) {
                        $meta = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                        $protocol = trim($meta[2]);
                    }

                    if (preg_match("/edit /",$names_line)){
                        $isFake=true;
                    }
                    if (preg_match("/next/",$names_line) AND ($isFake==true)){
                        $isFake=false;
                    }

                    if (preg_match("/\bnext\b/i", $names_line) AND ($isFake==false)) {

                        if ($addressName!=""){
                            $addVIP[] = "('$addressName','$source','$vsys','$extip','$extintf','$mappedip','$mappedport','$extport','$portforward','$protocol')";

                            if (preg_match("/\-/", $extip)) {
                                if($ipVipVersion===4) {
                                    $addHost[] = "('$source','$vsys','$addressName','$addressNamePan','ip-range','$extip','','Created from a VIP','')";
                                }else{
                                    $addHost6[] = "('1','0','$source','$vsys','$addressName','$addressNamePan','ip-range','$extip','','Created from a VIP','')";
                                }
                            } else {
                                if($ipVipVersion===4) {
                                    $addHost[] = "('$source','$vsys','$addressName','$addressNamePan','ip-netmask','$extip','32','Created from a VIP','')";
                                }else{
                                    $addHost6[] = "('1','0','$source','$vsys','$addressName','$addressNamePan','ip-netmask','$extip','128','Created from a VIP','')";
                                }
                            }

                            $isAddress = false;
                            $extip = "";
                            $extintf = "";
                            $mappedip = "";
                            $extport = "";
                            $mappedport = "";
                            $portforward = 0;
                            $addressNamePan = "";
                            $addressName = "";
                            $protocol = "tcp";
                            $type="";
                        }

                    }
                }
            }
        }


        $lastline = $names_line;
    }
    if (count($addVIP) > 0) {
        $projectdb->query("INSERT INTO fortinet_vip (name,source,vsys,extip,extintf,mappedip,mappedport,extport,portforward,protocol) VALUES " . implode(",", $addVIP) . ";");
    }
    if (count($addHost) > 0) {
        if ($addHost != "") {
            $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,type,ipaddress,cidr,description,vtype) VALUES " . implode(",", $addHost) . ";");
        }
    }
    if (count($addHost6) > 0) {
        if ($addHost6 != "") {
            $projectdb->query("INSERT INTO address (v6,v4,source,vsys,name_ext,name,type,ipaddress,cidr,description,vtype) VALUES " . implode(",", $addHost6) . ";");
        }
    }
}

function get_vipgrp($fortinet_config_file, $source, $vsys, $ismultiornot, $vipgrp) {

    global $projectdb;
    $isObject = FALSE;
    $isAddress = FALSE;
    $addVIP = array();
    $addressGroupsMembers=array();
    $addressGroup=array();
    $addressName_ext="";
    $interface="";
    $addressName_int="";
    $members=array();

    $lid=0;
    $getMaxID = $projectdb->query("SELECT max(id) as max FROM address_groups_id;");
    if ($getMaxID->num_rows == 1) {
        $max1 = $getMaxID->fetch_assoc();
        $lid = $max1['max'];
        if (($lid == null) OR ($lid == '')){
            $lid=0;
        }
        $lid++;
    }
    if ($ismultiornot == "singlevsys") {
        $START = TRUE;
        $VDOM = FALSE;
    } else {
        $START = FALSE;
        $VDOM = FALSE;
    }
    $lastline = "";
    foreach ($fortinet_config_file as $line => $names_line) {
        if ($START == FALSE) {
            if (preg_match("/^config vdom/i", $names_line)) {
                $VDOM = TRUE;
            }
            if ($VDOM == TRUE) {
                if (preg_match("/^edit $vsys/i", $names_line)) {
                    $START = TRUE;
                }
            }
        } else {
            if ((preg_match("/^end/i", $lastline)) AND ( preg_match("/^end/i", $names_line))) {
                $START = FALSE;
                $VDOM = FALSE;
            } elseif ((preg_match("/^edit/i", $lastline)) and ( preg_match("/^end/i", $names_line))) {
                $START = FALSE;
                $VDOM = FALSE;
            }
        }

        if ($START) {
            if (preg_match("/config firewall $vipgrp/i", $names_line)) {
                $isObject = true;
            }


            if ($isObject) {
                if (preg_match("/^\bend\b/i", $names_line)) {
                    $isObject = false;
                    $START = false;
                }
                if (preg_match("/\bedit\b/i", $names_line)) {
                    $isAddress = true;
                    $meta = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                    $newname = str_replace('/', '-', $meta[1]);
                    $addressName_int = truncate_names(normalizeNames($newname));
                    $addressName_ext = trim($meta[1]);
                }

                if ($isAddress) {
                    if (preg_match("/\binterface\b/i", $names_line)) {
                        $meta = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                        $interface = trim($meta[2]);
                    }
                    if (preg_match("/set member /i", $names_line)) {
                        $meta = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                        unset($meta[0]);
                        unset($meta[1]);
                        $members = $meta;
                    }

                    if (preg_match("/\bnext\b/i", $names_line)) {
                        $membersExtended=implode(",",$members);
                        $addVIP[] = "('$addressName_ext','$source','$vsys','$interface','$membersExtended')";
                        #Add AddressGroups and members
                        $addressGroup[]="('$lid','$source','$vsys','$addressName_ext','$addressName_int','static')";

                        foreach ($members as $key => $value) {
                            $addressGroupsMembers[]="('$source','$vsys','$lid','$value')";
                        }
                        $isAddress = false;
                        $members = array();
                        $interface = "";
                        $addressName_int = "";
                        $addressName_ext = "";
                        $lid++;
                    }
                }
            }
        }


        $lastline = $names_line;
    }
    if (count($addVIP) > 0) {
        if ($addVIP != "") {
            $projectdb->query("INSERT INTO fortinet_vipgrp (name,source,vsys,interface,member) VALUES " . implode(",", $addVIP) . ";");
        }
    }
    if (count($addressGroup)>0){
        $projectdb->query("INSERT INTO address_groups_id (id,source,vsys,name_ext,name,type) VALUES ".implode(",",$addressGroup).";");
        unset($addressGroup);
        if (count($addressGroupsMembers)>0){
            $projectdb->query("INSERT INTO address_groups (source,vsys,lid,member) VALUES ".implode(",",$addressGroupsMembers).";");
            unset($addressGroupsMembers);
        }
    }
}

function add_vsys($source, $projectdb, $vsys) {
# ADD VSYS
    $getVsys = $projectdb->query("SELECT name FROM virtual_systems WHERE source='$source' ORDER BY name DESC LIMIT 1;");

    if ($getVsys->num_rows == 0) {
        $vsys_name = "root";
        $projectdb->query("INSERT INTO virtual_systems (source,name,display_name) VALUES ('$source','$vsys_name','$vsys')");
    } else {
        $getVsysData = $getVsys->fetch_assoc();
        $thename = $getVsysData['name'];
        $getVsysData1 = str_replace("vsys", "", $thename);
        $result = intval($getVsysData1) + 1;
        $vsys_name = "vsys" . $result;
        $projectdb->query("INSERT INTO virtual_systems (source,name,display_name) VALUES ('$source','$vsys_name','$vsys')");
    }
}

function get_zones($fortinet_config_file, $vsys, $source, $template, $ismultiornot) {
    global $projectdb;
    $isConfigZone = FALSE;
    $zoneName = "";

    if ($ismultiornot == "singlevsys") {
        $START = TRUE;
        $VDOM = FALSE;
    } else {
        $START = FALSE;
        $VDOM = FALSE;
    }
    $lastline = "";

    $addZones = array();

    foreach ($fortinet_config_file as $line => $names_line) {
        if ($START == FALSE) {
            if (preg_match("/^config vdom/i", $names_line)) {
                $VDOM = TRUE;
            }
            if ($VDOM == TRUE) {
                if (preg_match("/^edit $vsys/i", $names_line)) {
                    $START = TRUE;
                }
            }
        } else {
            if ((preg_match("/^end/i", $lastline)) AND ( preg_match("/^end/i", $names_line))) {
                $START = FALSE;
                $VDOM = FALSE;
            } elseif ((preg_match("/^edit/i", $lastline)) and ( preg_match("/^end/i", $names_line))) {
                $START = FALSE;
                $VDOM = FALSE;
            }
        }

        if ($START) {
            if (preg_match("/config system zone/i", $names_line)) {
                $isConfigZone = TRUE;
            }
            if (($isConfigZone == TRUE) AND ( preg_match("/\bedit\b/i", $names_line))) {
                $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                $zoneName = trim($data[1]);
            }
            if (($isConfigZone == TRUE) AND ( preg_match("/set interface/i", $names_line))) {
                $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                unset($data[0]);
                unset($data[1]);
                $tmp_int=[];

                foreach ($data as $key=>$int){
                    $getInt=$projectdb->query("SELECT interfaces FROM zones WHERE BINARY name='$int' AND template='$template' AND source='$source' LIMIT 1;");
                    if ($getInt->num_rows==1){
                        $getIntData=$getInt->fetch_assoc();
                        $tmp_int[]=$getIntData['interfaces'];
                    }
                    else{
                        $tmp_int[]=$int;
                    }
                }
                $interfaces=implode(",",$tmp_int);
                $addZones[] = "('$source','$template','$vsys','$zoneName','layer3','$interfaces')";
                //$interfaces = "";
                foreach ($tmp_int as $key => $value) {
                    $projectdb->query("UPDATE interfaces SET zone='$zoneName' WHERE unitname='$value' AND template='$template' AND source='$source';");
                    $projectdb->query("UPDATE zones SET interfaces='' WHERE interfaces='$value' AND source='$source' AND template='$template';");
                }
                $zoneName = "";
            }
            if (($isConfigZone == TRUE) AND ( preg_match("/\bend\b/i", $names_line))) {
                $isConfigZone = FALSE;
                $START = FALSE;
            }
        }
        $lastline = $names_line;
    }
    if (count($addZones) > 0) {
        $unique = array_unique($addZones);
        $projectdb->query("INSERT INTO zones (source,template,vsys,name,type,interfaces) VALUES " . implode(",", $unique) . ";");
        $projectdb->query("DELETE FROM zones WHERE interfaces='' AND source='$source' AND template='$template';");
    }
}

function get_interfaces($fortinet_config_file, $vsys, $source, $template, $ismultiornot) {
    global $projectdb;
    $isConfig = FALSE;
    $isInterface = FALSE;
    $becareful = FALSE;
    $interfaceName = "";
    $status="";
    $isZone = FALSE;
    $addZones = [];
    $addInterface = [];
    $unittag="";
    $addVR = array();
    $unitipaddress1="";
    $allRoutes = array();
    $secondary = FALSE;
    $config_ipv6 = FALSE;
    $config_ipv6_prefix=FALSE;
    $myVR=array();
    $aggregate=array();
    $unitipaddress = array();
    foreach ($fortinet_config_file as $line => $names_line) {
        if (preg_match("/config system interface/i", $names_line)) {
            $isConfig = TRUE;
        }
        if ($isConfig === TRUE) {

            if ( (preg_match("/config secondaryip/i", $names_line) OR ( preg_match("/config secondary-IP/i", $names_line)) ) AND ( $isZone == TRUE)) {
                $secondary = TRUE;
                continue;
            }

            if (($secondary == TRUE) AND ( preg_match("/\bend\b/", $names_line)) ) {
                $secondary = FALSE;
                continue;
            }

            if (((preg_match("/config ip6-prefix-list/",$names_line)) || (preg_match("/ip6-extra-addr/",$names_line) )) AND ($isZone == TRUE) AND ($config_ipv6 == TRUE)){
                $config_ipv6_prefix=TRUE;
                continue;
            }

            if ((preg_match("/config ipv6/",$names_line)) AND ($isZone == TRUE) ){
                $config_ipv6=TRUE;
                continue;
            }


            if (( preg_match("/\bend\b/", $names_line)) AND ($config_ipv6_prefix==TRUE) AND ($config_ipv6==TRUE)) {
                $config_ipv6_prefix = FALSE;
                continue;
            }

            if (( preg_match("/\bend\b/", $names_line)) AND ($config_ipv6_prefix==FALSE) AND ($config_ipv6==TRUE)) {
                $config_ipv6 = FALSE;
                continue;
            }



            if ((preg_match("/\bedit\b/i", $names_line)) AND ( $isZone == FALSE) AND ( $secondary == FALSE)) {
                # MEDIA DEFAULT ETHERNET
                $media = "ethernet";
                $isZone = TRUE;
                $zoneName = "";
                $vr = "";
                $Network = "";
                $InterfaceMASK = "";
                $InterfaceIP = "";
                $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                $zoneName = trim($data[1]);
            }
            if (preg_match("/set vdom /i", $names_line)) {
                $dataDom = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                $vdom = trim($dataDom[2]);
                $vr = "vr_" . $vdom;
                $isDup = $projectdb->query("SELECT id FROM virtual_routers WHERE template='$template' AND name='$vr';");
                if ($isDup->num_rows == 0) {
                    $projectdb->query("INSERT INTO virtual_routers (name,template,source,vsys) VALUES ('$vr','$template','$source','$vdom');");
                    $vrid = $projectdb->insert_id;
                } else {
                    $get = $isDup->fetch_assoc();
                    $vrid = $get['id'];
                }
                if (!isset($myVR[$vrid])){
                    $myVR[$vrid]=array("config"=>$fortinet_config_file,"source"=>$source,"vsys"=>$vdom, "ismultiornot"=>$ismultiornot,"vr"=>$vrid,"template"=>$template);

                }
            }
            if (preg_match("/set ip /i", $names_line)) {
                $dataIp = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                $InterfaceIP = $dataIp[2];
                $InterfaceMASK = trim($dataIp[3]);
                //$ip1=ip2long($InterfaceIP);$mask1=ip2long($InterfaceMASK);$Network1=$ip1 & $mask1;$Network=long2ip($Network1);
                $cidr = mask2cidrv4($InterfaceMASK);
                $unitipaddress[] = $InterfaceIP . "/" . $cidr;
            }
            if (preg_match("/set vlanid /i", $names_line)) {
                $dataVlan = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                $unittag = $dataVlan[2];
            }
            if (preg_match("/set interface /i", $names_line)) {
                $dataVlan = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                $interfaceName = $dataVlan[2];
            }
            if (preg_match("/set status down/i", $names_line)) {
                $status="down";
            }
            if (preg_match("/set type tunnel/i",$names_line)){
                $media = "tunnel";
                continue;
            }
            if (preg_match("/set type aggregate/i",$names_line)){
                $media="aggregate-ethernet";
                $aggregate[$zoneName]=$zoneName;
                continue;
            }
            if ((preg_match("/\bnext\b/i", $names_line)) AND ( $isZone == TRUE) AND ( ( $secondary == FALSE) AND ($config_ipv6==FALSE)) ) {

                if (($zoneName != "") AND ( $vr != "") AND ($status!="down")) {
                    #Insert Interface
                    if ($interfaceName == "") {
                        $interfaceName = $zoneName;
                    }
                    if ($unittag == "") {
                        $unittag = 0;
                        $unitname = $interfaceName;
                    } else {
                        $unitname = $interfaceName . "." . $unittag;
                    }
                    if (count($unitipaddress) > 0) {
                        $unitipaddress1 = implode(",", $unitipaddress);
                    }

                    if (isset($aggregate[$interfaceName])){
                        $media="aggregate-ethernet";
                    }

                    $addInterface[] = "('$vrid','$source','$vdom','$template','$unittag','$unitname','$interfaceName','$unitipaddress1','$zoneName','$media')";
                    #Insert Zone
                    $addZones[] = "('$source','$template','$vdom','$zoneName','layer3')";

                }
                $unittag = "";
                $unitipaddress = array();
                $zoneName = "";
                $status="";
                $vr = "";
                $unitname = "";
                $unitipaddress1 = "";
                $interfaceName = "";
                $isZone = FALSE;
            }
            if (($isZone == FALSE) AND ( preg_match("/\bend\b/i", $names_line))) {
                $isConfig = FALSE;
            }
        }
    }
    if (count($addZones) > 0) {
        $unique = array_unique($addZones);
        $projectdb->query("INSERT INTO zones (source,template,vsys,name,type) VALUES " . implode(",", $unique) . ";");
    }
    if (count($addInterface) > 0) {
        $unique = array_unique($addInterface);
        $projectdb->query("INSERT INTO interfaces (vr_id,source,vsys,template,unittag,unitname,name,unitipaddress,zone,media) VALUES " . implode(",", $unique) . ";");
    }

    #Add Interfaces to the VR
    $getVR = $projectdb->query("SELECT id FROM virtual_routers WHERE template='$template';");
    while ($data = $getVR->fetch_assoc()) {
        $vr_id = $data['id'];
        $int = array();
        $getInt = $projectdb->query("SELECT unitname FROM interfaces WHERE template='$template' AND vr_id='$vr_id'");
        while ($data2 = $getInt->fetch_assoc()) {
            $int[] = $data2['unitname'];
        }
        $projectdb->query("UPDATE virtual_routers SET interfaces='" . implode(",", $int) . "' WHERE id='$vr_id';");
    }

    #Add Interfaces to the Zones
    $getVR = $projectdb->query("SELECT name FROM zones WHERE template='$template';");
    while ($data = $getVR->fetch_assoc()) {
        $zone = $data['name'];
        $int = array();
        $getInt = $projectdb->query("SELECT unitname FROM interfaces WHERE template='$template' AND zone='$zone'");
        while ($data2 = $getInt->fetch_assoc()) {
            $int[] = $data2['unitname'];
        }
        $projectdb->query("UPDATE zones SET interfaces='" . implode(",", $int) . "' WHERE name='$zone';");
    }

    # Calculate Static Rutes
    $allRoutes = array();
    $myroutes = array();
    if (count($myVR)>0){
        foreach ($myVR as $virtualRouter=>$params){
            $allRoutes[] = get_routes($params['config'], $params['source'], $params['vsys'], $params['ismultiornot'], $params['vr'], $params['template'],'static');
            $allRoutes[] = get_routes($params['config'], $params['source'], $params['vsys'], $params['ismultiornot'], $params['vr'], $params['template'],'static6');
        }
        if (count($allRoutes) > 0) {
            foreach ($allRoutes as $key => $value) {
                if (is_array($value) && count($value) > 0){
                    foreach ($value as $kkey => $vvalue) {
                        $myroutes[] = $vvalue;
                    }
                }
            }
            if (count($myroutes) > 0) {
                $unique = array_unique($myroutes);
                $projectdb->query("INSERT INTO routes_static (source,vr_id,template,ip_version,name,destination,tointerface,nexthop,nexthop_value,metric,vsys,admin_dist) VALUES " . implode(",", $unique) . ";");
            }
            $allRoutes = array();
        }
    }
}

/***
 * Removes special characters and replaces them by _. If the resulting name starts with a _, it prefixes a "s"
 * @param string $original
 * @return string
 */
function clean_name(string $original, bool $starts_with_=false):string{
    $cleaned_name = str_replace('/', '-', $original);
    $cleaned_name = preg_replace('/[^a-zA-Z0-9-. \']/', '_', $cleaned_name);
    $cleaned_name = str_replace("'", '', $cleaned_name);
    if(!$starts_with_) {
        if (starts_with($cleaned_name, "_")) {
            $cleaned_name = "s" . $cleaned_name;
        }
    }
    
    return $cleaned_name;
}

function get_last_address():int{
    global $projectdb;

    $query = "SELECT max(id) as last_entry FROM address";
    $result = $projectdb->query($query);
    if($result->num_rows>0){
        $data = $result->fetch_assoc();
        return $data['last_entry']+1;
    }
    return 1;
}

function getTag_orCreate(mysqli $projectdb, int $source, string $vsys, string $tag_name):int{
    $tag_name = normalizeNames($tag_name);
    $query = "SELECT id FROM tag WHERE name='$tag_name' AND source=$source AND vsys='$vsys' LIMIT 1";
    $result = $projectdb->query($query);
    if($result->num_rows==0){

        $query = "INSERT INTO tag (name, source, vsys, used) VALUE ('$tag_name', $source, '$vsys', 1)";
        $projectdb->query($query);
        return $projectdb->insert_id;
    }
    else{
        $data = $result->fetch_assoc();
        return $data['id'];
    }
}

function get_address_Fortinet($fortinet_config_file, $source, $vsys, $ismultiornot, &$regions) {
    global $projectdb;
    $isAddress = false;
    $isObject = false;
    $sql = array();
    $type = "ip-netmask";
    $ipaddress = "";
    $netmask = "";
    $cidr = "";
    $addressName = "";
    $addressNamePan = "";
    $description = "";
    $getRangeEnd = "";
    $getRangeStart = "";
    $fqdn = "";
    $country="";
    $multi_line_comment=false;

    $addres_lid = get_last_address();


    if ($ismultiornot == "singlevsys") {
        $START = TRUE;
        $VDOM = FALSE;
    } else {
        $START = FALSE;
        $VDOM = FALSE;
    }
    $lastline = "";
    $is_tag = false;
    foreach ($fortinet_config_file as $line => $names_line) {
        if ($START == FALSE) {
            if (preg_match("/^config vdom/i", $names_line)) {
                $VDOM = TRUE;
            }
            if ($VDOM == TRUE) {
                if (preg_match("/^edit $vsys/i", $names_line)) {
                    $START = TRUE;
                }
            }
        } else {
            if ((preg_match("/^end/i", $lastline)) AND ( preg_match("/^end/i", $names_line))) {
                $START = FALSE;
                $VDOM = FALSE;
            } elseif ((preg_match("/^edit/i", $lastline)) and ( preg_match("/^end/i", $names_line))) {
                $START = FALSE;
                $VDOM = FALSE;
            }
        }

        if ($START) {
            if (preg_match("/config firewall address/i", $names_line)) {
                $isObject = true;
            }


            if ($isObject) {
                if ($is_tag && preg_match("/^\bend\b/i", trim($names_line))) {
                    $is_tag = false;
                }
                elseif(!$is_tag) {
                    if ($multi_line_comment===false &&  preg_match("/^\bend\b/i", $names_line)) {
                        $isObject = false;
                        $START = false;
                    }
                    if (preg_match("/\bedit\b/i", $names_line)) {
                        $isAddress = true;
                        $meta = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                        $cleaned_name = clean_name($meta[1]);
                        $addressNamePan = truncate_names(normalizeNames($cleaned_name));
                        $addressName = trim($meta[1]);

                        if ($addressName == "all") {
                            $type = "";
                        }
                    }
                }

                if ($isAddress) {
                    if($is_tag){
                        if (preg_match("/set tags /i", $names_line)) {
                            $tag = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                            $tag_id = getTag_orCreate($projectdb, $source, $vsys, $tag[2]);
                            $tag_insert = "INSERT INTO tag_relations (table_name, member_lid, tag_id) VALUES ('address','$addres_lid', $tag_id)";
                            $projectdb->query($tag_insert);
                        }
                    }
                    else {
                        if (preg_match("/config tagging/i", $names_line)) {
                            $is_tag = true;
                        }
                        if (preg_match("/\bnext\b/i", $names_line)) {
                            $isAddress = false;

                            if ($type == "fqdn") {

                                if (preg_match("/^\*/", $fqdn)) {
                                    $description.= "($fqdn)";
                                    $fqdn = str_replace("*.", "", $fqdn);
                                    //add_log('error', 'FQDN Object', 'The Address [' . $addressName . '] contains an * [' . $fqdn . ']', $source, 'Wrong Content, replace this object by appropiate App-id');
                                    //add_log2('error', 'FQDN Object', 'The Address [' . $addressName . '] contains an * [' . $fqdn . ']', $source, 'Wrong Content, replace this object by appropiate App-id', 'objects', $addres_lid, 'address');
                                    add_log2('error', 'FQDN Object', 'FQDN with asterisk '.$addressName.' found. Removing * from the read FQDN.', $source, 'If the requirement is to allow web browsing to all possible subdomains of a certain domain, a Security Policy based on a custom URL category in the destination could be useful to fill the gap between an FQDN Object and a URL Filtering Security Profile.', 'objects', $addres_lid, 'address');
                                    $sql[] = "($addres_lid, '$source','$addressName','$addressNamePan','$vsys','$type','','$fqdn','$fqdn','$cidr','$description','1')";
                                }else {
                                    $sql[] = "($addres_lid, '$source','$addressName','$addressNamePan','$vsys','$type','','$fqdn','$fqdn','$cidr','$description','0')";
                                }
                                $addres_lid++;
                            }
                            elseif ($type == "ip-netmask") {
                                $sql[] = "($addres_lid, '$source','$addressName','$addressNamePan','$vsys','$type','','$fqdn','$ipaddress','$cidr','$description','0')";
                                $addres_lid++;
                            }
                            elseif ($type == "ip-range") {
                                $ipaddress = $getRangeStart . "-" . $getRangeEnd;
                                $sql[] = "($addres_lid,'$source','$addressName','$addressNamePan','$vsys','$type','','$fqdn','$ipaddress','$cidr','$description','0')";
                                $addres_lid++;
                            }
                            elseif($type=="region"){
                                $regions[$addressName]=$country;
                            }
                            elseif($type=="dynamic"){
                                $sql[] = "($addres_lid,'$source','$addressName','$addressNamePan','$vsys','ip-netmask','','','','','','1')";
                                add_log2('error', 'Address Object migrated', 'Address Object named '.$addressName.' found with not supported type ' . $type . '.', $source, 'Check it and replace by required object', 'objects', $addres_lid, 'address');
                                $addres_lid++;
                            }else{
                                $sql[] = "($addres_lid,'$source','$addressName','$addressNamePan','$vsys','ip-netmask','','','','','','1')";
                                add_log2('error', 'Address Object migrated', 'Address Object named '.$addressName.' found with not defined type.', $source, 'Check it and replace by required object', 'objects', $addres_lid, 'address');
                                $addres_lid++;
                            }

                            $type = "";
                            $ipaddress = "";
                            $netmask = "";
                            $cidr = "";
                            $addressName = "";
                            $addressNamePan = "";
                            $description = "";
                            $getRangeEnd = "";
                            $getRangeStart = "";
                            $fqdn = "";
                            $country="";
                            $multi_line_comment=false;
                        }
                        if (preg_match("/set subnet /i", $names_line)) {
                            #print "Es RED: $routes_line\n";
                            $type = "ip-netmask";
                            $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                            $ipaddress = $data[2];
                            $netmask = trim($data[3]);
                            $cidr = mask2cidrv4($netmask);
                        }
                        if (preg_match("/set type iprange/i", $names_line)) {
                            $type = "ip-range";
                        }
                        if (preg_match("/set type geography/i", $names_line)) {
                            $type = "region";
                        }

                        if (preg_match("/set country /i", $names_line)) {
                            $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                            $country = $data[2];
                        }

                        if (preg_match("/set end-ip/i", $names_line)) {
                            $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                            $getRangeEnd = $data[2];
                        }

                        if (preg_match("/set start-ip/i", $names_line)) {
                            $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                            $getRangeStart = $data[2];
                        }
                        if (preg_match("/set type fqdn/i", $names_line)) {
                            $type = "fqdn";
                        }
                        if (preg_match("/set fqdn/i", $names_line)) {
                            $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                            $fqdn = $data[2];
                        }
                        if (preg_match("/set wildcard /i", $names_line)) {
                            add_log2('warning', 'Reading Address objects', 'Type wildcard is not supported [' . $names_line . '] in Host [' . $addressName . ']', $source, 'Add the right Ip and Netmask', '', '', '');
                        }
                        if (preg_match("/set comment /i", $names_line) || $multi_line_comment) {
                                $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                                $count = count($data);
                                $Commentsa = "";
                                if($count>=3){
                                    for($i=2;$i<$count;$i++){
                                        $Commentsa.= trim($data[$i]);
                                    }
                                }
                                //Check if the comments contains one than 1 line, by checking if it ends with "
                                if($multi_line_comment){
                                    $description .= " " . normalizeComments($names_line);
                                }else {
                                    $description = normalizeComments($Commentsa);
                                }
                                $multi_line_comment = !endsWith($names_line, "\"\n");
                        }
                        if (preg_match("/set type dynamic/i", $names_line)){
                            $type = "dynamic";
                        }
                    }
                }
            }
        }


        $lastline = $names_line;
    }

    if (count($sql) > 0) {
        $projectdb->query("INSERT INTO address (id, source,name_ext,name,vsys,type,vtype,fqdn,ipaddress,cidr,description, invalid) VALUES " . implode(",", $sql) . ";");
    }
}

function get_addressv6($fortinet_config_file, $source, $vsys, $ismultiornot, &$regions) {
    global $projectdb;
    $isAddress = false;
    $isObject = false;
    $sql = array();
    $type = "ip-netmask";
    $ipaddress = "";
    $netmask = "";
    $cidr = "";
    $addressName = "";
    $addressNamePan = "";
    $description = "";
    $getRangeEnd = "";
    $getRangeStart = "";
    $fqdn = "";
    $country="";

    $addres_lid = get_last_address();

    if ($ismultiornot == "singlevsys") {
        $START = TRUE;
        $VDOM = FALSE;
    } else {
        $START = FALSE;
        $VDOM = FALSE;
    }
    $lastline = "";
    foreach ($fortinet_config_file as $line => $names_line) {
        if ($START == FALSE) {
            if (preg_match("/^config vdom/i", $names_line)) {
                $VDOM = TRUE;
            }
            if ($VDOM == TRUE) {
                if (preg_match("/^edit $vsys/i", $names_line)) {
                    $START = TRUE;
                }
            }
        } else {
            if ((preg_match("/^end/i", $lastline)) AND ( preg_match("/^end/i", $names_line))) {
                $START = FALSE;
                $VDOM = FALSE;
            } elseif ((preg_match("/^edit/i", $lastline)) and ( preg_match("/^end/i", $names_line))) {
                $START = FALSE;
                $VDOM = FALSE;
            }
        }

        if ($START) {
            if (preg_match("/config firewall address6/i", $names_line)) {
                $isObject = true;
            }


            if ($isObject) {
                if (preg_match("/^\bend\b/i", $names_line)) {
                    $isObject = false;
                    $START = false;
                }
                if (preg_match("/\bedit\b/i", $names_line)) {
                    $isAddress = true;
                    $meta = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                    $newname = str_replace('/', '-', $meta[1]);
                    $addressNamePan = truncate_names(normalizeNames($newname));
                    $addressName = trim($meta[1]);
                    $addres_lid++;
                    if ($addressName == "all") {
                        $type = "";
                    }
                }

                if ($isAddress) {
                    if (preg_match("/\bnext\b/i", $names_line)) {
                        $isAddress = false;

                        if ($type == "fqdn") {
                            $sql[] = "('$addres_lid','$source','$addressName','$addressNamePan','$vsys','$type','','$fqdn','$fqdn','$cidr','$description','0','1')";
                            if (preg_match("/^\*/", $fqdn)) {
                                //add_log('error', 'FQDN Object', 'The Address [' . $addressName . '] contains an * [' . $fqdn . ']', $source, 'Wrong Content, replace this object by appropiate App-id');
                                add_log2('error', 'FQDN Object', 'The Address [' . $addressName . '] contains an * [' . $fqdn . ']', $source, 'Wrong Content, replace this object by appropiate App-id', 'objects', $addres_lid, 'address');
                            }
                        }
                        elseif ($type == "ip-netmask") {
                            $sql[] = "('$addres_lid','$source','$addressName','$addressNamePan','$vsys','$type','','$fqdn','$ipaddress','$cidr','$description','0','1')";
                        }
                        elseif ($type == "ip-range") {
                            $ipaddress = $getRangeStart . "-" . $getRangeEnd;
                            $sql[] = "('$addres_lid','$source','$addressName','$addressNamePan','$vsys','$type','','$fqdn','$ipaddress','$cidr','$description','0','1')";
                        }
                        elseif($type=="region"){
                            $regions[$addressName]=$country;
                        }

                        $type = "";
                        $ipaddress = "";
                        $netmask = "";
                        $cidr = "";
                        $addressName = "";
                        $addressNamePan = "";
                        $description = "";
                        $getRangeEnd = "";
                        $getRangeStart = "";
                        $fqdn = "";
                        $country="";
                    }

                    if (preg_match("/set ip6 /i", $names_line)) {
                        #print "Es RED: $routes_line\n";
                        $type = "ip-netmask";
                        $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);

                        $ipaddressfull=explode("/",$data[2]);
                        $ipaddress = $ipaddressfull[0];
                        $cidr = $ipaddressfull[1];
                    }

                    if (preg_match("/set subnet /i", $names_line)) {
                        #print "Es RED: $routes_line\n";
                        $type = "ip-netmask";
                        $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                        $ipaddress = $data[2];
                        $netmask = trim($data[3]);
                        $cidr = mask2cidrv4($netmask);
                    }
                    if (preg_match("/set type iprange/i", $names_line)) {
                        $type = "ip-range";
                    }
                    if (preg_match("/set type geography/i", $names_line)) {
                        $type = "region";
                    }

                    if (preg_match("/set country /i", $names_line)) {
                        $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                        $country = $data[2];
                    }

                    if (preg_match("/set end-ip/i", $names_line)) {
                        $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                        $getRangeEnd = $data[2];
                    }

                    if (preg_match("/set start-ip/i", $names_line)) {
                        $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                        $getRangeStart = $data[2];
                    }
                    if (preg_match("/set type fqdn/i", $names_line)) {
                        $type = "fqdn";
                    }
                    if (preg_match("/set fqdn/i", $names_line)) {
                        $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                        $fqdn = $data[2];
                    }
                    if (preg_match("/set wildcard /i", $names_line)) {
                        add_log2('warning', 'Reading Address objects', 'Type wildcard is not supported [' . $names_line . '] in Host [' . $addressName . ']', $source, 'Add the right Ip and Netmask', 'objects', $addres_lid, 'address');
                    }
                    if (preg_match("/set comment /i", $names_line)) {
                        $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                        $description = addslashes($data[2]);
                    }
                }
            }
        }


        $lastline = $names_line;
    }

    if (count($sql) > 0) {
        $projectdb->query("INSERT INTO address (id, source,name_ext,name,vsys,type,vtype,fqdn,ipaddress,cidr,description,v4,v6) VALUES " . implode(",", $sql) . ";");
    }
}

function add_fortinet_services($ismultiornot, $source) {
    
    global $projectdb;

    $table = "services";
    $table_group = "services_groups";
    $table_group_id = "services_groups_id";
        
    if ($ismultiornot == "multivsys") {
        $vsys = "shared";
        //$table = "shared_services";
        //$table_group = "shared_services_groups";
        //$table_group_id = "shared_services_groups_id";
    } else {
        $vsys = "root"; //default vsys name
        // get the defined vsys name
        $getVsys = $projectdb->query("SELECT vsys FROM device_mapping WHERE id='$source'");
        if($getVsys->num_rows > 0 )
        {
            $getVsysData = $getVsys->fetch_assoc();
            $vsys = $getVsysData['vsys'];
        }
    }


//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','FTP','FTP','21','tcp')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','FTP_Get','FTP_Get','21','tcp')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','FTP_Put','FTP_Put','21','tcp')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','SSH','SSH','22','tcp')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','TELNET','TELNET','23','tcp')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','MAIL','MAIL','25','tcp')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','IMAP','IMAP','143','tcp')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','IMAPS','IMAPS','993','tcp')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','SMTP','SMTP','25','tcp')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','WHOIS','WHOIS','43','tcp')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','GOPHER','GOPHER','70','tcp')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','FINGER','FINGER','79','tcp')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','HTTP','HTTP','80','tcp')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','POP3','POP3','110','tcp')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','IDENT','IDENT','113','tcp')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','NNTP','NNTP','119','tcp')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','SMB','SMB','445','tcp')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','IMAP','IMAP','143','tcp')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','BGP','BGP','179','tcp')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','WAIS','WAIS','210','tcp')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','Internet Locator Service','Internet Locator Service','389','tcp')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','LDAP','LDAP','389','tcp')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','HTTPS','HTTPS','443','tcp')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','REXEC','REXEC','512','tcp')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','RLOGIN','RLOGIN','513','tcp')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','RSH','RSH','514','tcp')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','LPR','LPR','515','tcp')");
//
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','MS-SQL','MS-SQL','1433,1434','tcp')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','MYSQL','MYSQL','3306','tcp')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','WINFRAME','WINFRAME','1494','tcp')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','SQL*Net V2','SQL Net V2','1521','tcp')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','SQL*Net V1','SQL Net V1','1525','tcp')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','H.323','H.323','1720','tcp')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','NetMeeting','NetMeeting','1720','tcp')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','MSN','MSN','1863','tcp')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','SCCP','SCCP','2000','tcp')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','YMSG','YMSG','5050','tcp')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','VNC','VNC','5900','tcp')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','VNC_XH','VNC_XH','5901','tcp')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','VNC_guest','VNC_guest','5902','tcp')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','HTTP-EXT','HTTP-EXT','7001','tcp')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','Real Media','Real Media','7070','tcp')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','NS Global','NS Global','15397','tcp')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','NS Global PRO','NS Global PRO','15397','tcp')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','ECHO','ECHO','7','udp')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','DISCARD','DISCARD','9','udp')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','CHARGEN','CHARGEN','19','udp')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','DHCP-Relay','DHCP-Relay','67','udp')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','DHCP','DHCP','67-68','udp')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','NSM','NSM','69','udp')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','TFTP','TFTP','69','udp')");
//
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','SUN-RPC-PORTMAPPER','SUN-RPC-PORTMAPPER','111','udp')");
//
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','MS-RPC-EPM','MS-RPC-EPM','135','udp')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','NBNAME','NBNAME','137','udp')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','NBDS','NBDS','138','udp')");
//
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','IKE','IKE','500,4500','udp')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','IKE-NAT','IKE-NAT','500','udp')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','SYSLOG','SYSLOG','514','udp')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','RIP','RIP','520','udp')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','UUCP','UUCP','540','udp')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','SQL Monitor','SQL Monitor','1434','udp')");
//
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','GTP','GTP','2123','udp')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','MGCP-UA','MGCP-UA','2427','udp')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','MGCP-CA','MGCP-CA','2727','udp')");
//
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','X-WINDOWS','X-WINDOWS','6000-6063','tcp')");
//
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','MSRPC','MSRPC','135','tcp')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','SQL','SQL','1521','tcp')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','XING','XING','1558','udp')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','RADIUS','RADIUS','1812-1813','udp')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','SQUID','SQUID','3128','tcp')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','RDP','RDP','3389','tcp')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','SAMBA','SAMBA','139','tcp')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','SAMBA_UDP','SAMBA_UDP','139','udp')");
//    # Create Groups when service is TCP and UDP defined
//    $serviceName="RTSP";
//    $projectdb->query("INSERT INTO $table_group_id (source,vsys,name_ext,name) VALUES ('$source','$vsys','$serviceName','$serviceName');");
//    $glid=$projectdb->insert_id;
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','RTSP_UDP','RTSP_UDP','554','udp')");
//    $mlid=$projectdb->insert_id;
//    $projectdb->query("INSERT INTO $table_group (source,vsys,member,member_lid,table_name,lid) VALUES ('$source','$vsys','RTSP_UDP','$mlid','$table','$glid')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','RTSP_TCP','RTSP_TCP','554,7070,8554','tcp')");
//    $mlid=$projectdb->insert_id;
//    $projectdb->query("INSERT INTO $table_group (source,vsys,member,member_lid,table_name,lid) VALUES ('$source','$vsys','RTSP_TCP','$mlid','$table','$glid')");
//
//    $serviceName="DNS";
//    $projectdb->query("INSERT INTO $table_group_id (source,vsys,name_ext,name) VALUES ('$source','$vsys','$serviceName','$serviceName');");
//    $glid=$projectdb->insert_id;
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','DNS_UDP','DNS_UDP','53','udp')");
//    $mlid=$projectdb->insert_id;
//    $projectdb->query("INSERT INTO $table_group (source,vsys,member,member_lid,table_name,lid) VALUES ('$source','$vsys','DNS_UDP','$mlid','$table','$glid')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','DNS_TCP','DNS_TCP','53','tcp')");
//    $mlid=$projectdb->insert_id;
//    $projectdb->query("INSERT INTO $table_group (source,vsys,member,member_lid,table_name,lid) VALUES ('$source','$vsys','DNS_TCP','$mlid','$table','$glid')");
//
//    $serviceName="SNMP";
//    $projectdb->query("INSERT INTO $table_group_id (source,vsys,name_ext,name) VALUES ('$source','$vsys','$serviceName','$serviceName');");
//    $glid=$projectdb->insert_id;
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','SNMP_UDP','SNMP_UDP','161-162','udp')");
//    $mlid=$projectdb->insert_id;
//    $projectdb->query("INSERT INTO $table_group (source,vsys,member,member_lid,table_name,lid) VALUES ('$source','$vsys','SNMP_UDP','$mlid','$table','$glid')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','SNMP_TCP','SNMP_TCP','161-162','tcp')");
//    $mlid=$projectdb->insert_id;
//    $projectdb->query("INSERT INTO $table_group (source,vsys,member,member_lid,table_name,lid) VALUES ('$source','$vsys','SNMP_TCP','$mlid','$table','$glid')");
//
//    $serviceName="DCE-RPC";
//    $projectdb->query("INSERT INTO $table_group_id (source,vsys,name_ext,name) VALUES ('$source','$vsys','$serviceName','$serviceName');");
//    $glid=$projectdb->insert_id;
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','DCE-RPC_UDP','DCE-RPC_UDP','135','udp')");
//    $mlid=$projectdb->insert_id;
//    $projectdb->query("INSERT INTO $table_group (source,vsys,member,member_lid,table_name,lid) VALUES ('$source','$vsys','DCE-RPC_UDP','$mlid','$table','$glid')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','DCE-RPC_TCP','DCE-RPC_TCP','135','tcp')");
//    $mlid=$projectdb->insert_id;
//    $projectdb->query("INSERT INTO $table_group (source,vsys,member,member_lid,table_name,lid) VALUES ('$source','$vsys','DCE-RPC_TCP','$mlid','$table','$glid')");
//
//    $serviceName="Kerberos";
//    $projectdb->query("INSERT INTO $table_group_id (source,vsys,name_ext,name) VALUES ('$source','$vsys','$serviceName','$serviceName');");
//    $glid=$projectdb->insert_id;
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','Kerberos_UDP','Kerberos_UDP','88','udp')");
//    $mlid=$projectdb->insert_id;
//    $projectdb->query("INSERT INTO $table_group (source,vsys,member,member_lid,table_name,lid) VALUES ('$source','$vsys','Kerberos_UDP','$mlid','$table','$glid')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','Kerberos_TCP','Kerberos_TCP','88','tcp')");
//    $mlid=$projectdb->insert_id;
//    $projectdb->query("INSERT INTO $table_group (source,vsys,member,member_lid,table_name,lid) VALUES ('$source','$vsys','Kerberos_TCP','$mlid','$table','$glid')");
//
//    $serviceName="NTP";
//    $projectdb->query("INSERT INTO $table_group_id (source,vsys,name_ext,name) VALUES ('$source','$vsys','$serviceName','$serviceName');");
//    $glid=$projectdb->insert_id;
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','NTP_UDP','NTP_UDP','123','udp')");
//    $mlid=$projectdb->insert_id;
//    $projectdb->query("INSERT INTO $table_group (source,vsys,member,member_lid,table_name,lid) VALUES ('$source','$vsys','NTP_UDP','$mlid','$table','$glid')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','NTP_TCP','NTP_TCP','123','tcp')");
//    $mlid=$projectdb->insert_id;
//    $projectdb->query("INSERT INTO $table_group (source,vsys,member,member_lid,table_name,lid) VALUES ('$source','$vsys','NTP_TCP','$mlid','$table','$glid')");
//
//    $serviceName="H323";
//    $projectdb->query("INSERT INTO $table_group_id (source,vsys,name_ext,name) VALUES ('$source','$vsys','$serviceName','$serviceName');");
//    $glid=$projectdb->insert_id;
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','H323_TCP','H323_TCP','1720,1503','tcp')");
//    $mlid=$projectdb->insert_id;
//    $projectdb->query("INSERT INTO $table_group (source,vsys,member,member_lid,table_name,lid) VALUES ('$source','$vsys','H323_TCP','$mlid','$table','$glid')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','H323_UDP','H323_UDP','1719','udp')");
//    $mlid=$projectdb->insert_id;
//    $projectdb->query("INSERT INTO $table_group (source,vsys,member,member_lid,table_name,lid) VALUES ('$source','$vsys','H323_UDP','$mlid','$table','$glid')");
//
//    $serviceName="SIP";
//    $projectdb->query("INSERT INTO $table_group_id (source,vsys,name_ext,name) VALUES ('$source','$vsys','$serviceName','$serviceName');");
//    $glid=$projectdb->insert_id;
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','SIP_UDP','SIP_UDP','5060','udp')");
//    $mlid=$projectdb->insert_id;
//    $projectdb->query("INSERT INTO $table_group (source,vsys,member,member_lid,table_name,lid) VALUES ('$source','$vsys','SIP_UDP','$mlid','$table','$glid')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','SIP_TCP','SIP_TCP','5060','tcp')");
//    $mlid=$projectdb->insert_id;
//    $projectdb->query("INSERT INTO $table_group (source,vsys,member,member_lid,table_name,lid) VALUES ('$source','$vsys','SIP_TCP','$mlid','$table','$glid')");
//
//    $serviceName="L2TP";
//    $projectdb->query("INSERT INTO $table_group_id (source,vsys,name_ext,name) VALUES ('$source','$vsys','$serviceName','$serviceName');");
//    $glid=$projectdb->insert_id;
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','L2TP_UDP','L2TP_UDP','1701','udp')");
//    $mlid=$projectdb->insert_id;
//    $projectdb->query("INSERT INTO $table_group (source,vsys,member,member_lid,table_name,lid) VALUES ('$source','$vsys','L2TP_UDP','$mlid','$table','$glid')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','L2TP_TCP','L2TP_TCP','1701','tcp')");
//    $mlid=$projectdb->insert_id;
//    $projectdb->query("INSERT INTO $table_group (source,vsys,member,member_lid,table_name,lid) VALUES ('$source','$vsys','L2TP_TCP','$mlid','$table','$glid')");
//
//    $serviceName="NFS";
//    $projectdb->query("INSERT INTO $table_group_id (source,vsys,name_ext,name) VALUES ('$source','$vsys','$serviceName','$serviceName');");
//    $glid=$projectdb->insert_id;
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','NFS_UDP','NFS_UDP','111,2049','udp')");
//    $mlid=$projectdb->insert_id;
//    $projectdb->query("INSERT INTO $table_group (source,vsys,member,member_lid,table_name,lid) VALUES ('$source','$vsys','NFS_UDP','$mlid','$table','$glid')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','NFS_TCP','NFS_TCP','111,2049','tcp')");
//    $mlid=$projectdb->insert_id;
//    $projectdb->query("INSERT INTO $table_group (source,vsys,member,member_lid,table_name,lid) VALUES ('$source','$vsys','NFS_TCP','$mlid','$table','$glid')");
//
//    $serviceName="PC-Anywhere";
//    $projectdb->query("INSERT INTO $table_group_id (source,vsys,name_ext,name) VALUES ('$source','$vsys','$serviceName','$serviceName');");
//    $glid=$projectdb->insert_id;
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','PC-Anywhere_UDP','Anywhere_UDP','5632','udp')");
//    $mlid=$projectdb->insert_id;
//    $projectdb->query("INSERT INTO $table_group (source,vsys,member,member_lid,table_name,lid) VALUES ('$source','$vsys','Anywhere_UDP','$mlid','$table','$glid')");
//    $projectdb->query("insert into $table (source,vsys,name_ext,name,dport,protocol) values ('$source','$vsys','Anywhere_TCP','Anywhere_TCP','5631','tcp')");
//    $mlid=$projectdb->insert_id;
//    $projectdb->query("INSERT INTO $table_group (source,vsys,member,member_lid,table_name,lid) VALUES ('$source','$vsys','Anywhere_TCP','$mlid','$table','$glid')");

    // Add predefined services and services groups
    ServicesMapping::addPredefinedSrvAndSrvGroups($projectdb, "fortinet", $source, $vsys);

    $projectdb->query("UPDATE $table SET devicegroup='predefined' WHERE source='$source' AND vsys='$vsys';");
    $projectdb->query("UPDATE $table_group_id SET devicegroup='predefined' WHERE source='$source' AND vsys='$vsys';");

}

function get_services($fortinet_config_file, $source, $vsys, $ismultiornot) {

    global $projectdb;
    $isAddress = false;
    $isObject = false;
    $sql = array();
    $type = "";
    $ipaddress = "";
    $netmask = "";
    $cidr = "";
    $addressName = "";
    $addressNamePan = "";
    $description = "";
    $getRangeEnd = "";
    $getRangeStart = "";
    $protocol_number="";
    $tcp_src_elements_array=array();
    $fqdn = "";
    $sql = array();
    $protocol_udp = "";
    $protocol_tcp = "";
    $tcp_src_elements = "";
    $tcp_dst_elements = "";

    if ($ismultiornot == "singlevsys") {
        $START = TRUE;
        $VDOM = FALSE;
    } else {
        $START = FALSE;
        $VDOM = FALSE;
    }
    $lastline = "";
    foreach ($fortinet_config_file as $line => $names_line) {
        if ($START == FALSE) {
            if (preg_match("/^config vdom/i", $names_line)) {
                $VDOM = TRUE;
            }
            if ($VDOM == TRUE) {
                if (preg_match("/^edit $vsys/i", $names_line)) {
                    $START = TRUE;
                }
            }
        } else {
            if ((preg_match("/^end/i", $lastline)) AND ( preg_match("/^end/i", $names_line))) {
                $START = FALSE;
                $VDOM = FALSE;
            } elseif ((preg_match("/^edit/i", $lastline)) and ( preg_match("/^end/i", $names_line))) {
                $START = FALSE;
                $VDOM = FALSE;
            }
        }

        if ($START) {
            if (preg_match("/^config firewall service custom/i", $names_line)) {
                $isObject = true;
            }

            if ($isObject) {
                if (preg_match("/^end/i", $names_line)) {
                    $isObject = false;
                    $START = false;
                }
                if (preg_match("/edit /i", $names_line)) {
                    $isAddress = true;
                    $meta = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                    $addressNamePan = truncate_names(normalizeNames($meta[1]));
                    $addressName = $meta[1];
                }

                if ($isAddress) {
                    if (preg_match("/next/i", $names_line)) {
                        $isAddress = false;
                        if ((preg_match("/TCP\/UDP/i", $protocol)) OR preg_match("/TCP/i", $protocol) OR preg_match("/UDP/i", $protocol)) {
                            if (($protocol_udp == "") and ( $protocol_tcp != "")) {
                                # IS TCP ONLY
                                #destination:#source
                                $tcp = explode(":", $protocol_tcp);
                                $tcp_dst = $tcp[0];
                                if (isset($tcp[1])) {
                                    //$tcp_dst = $tcp[1];
                                    $tcp_src = $tcp[1];
                                } else {
                                    $tcp_src = "";
                                }
                                # Dst port
                                if (preg_match("/-/", $tcp_dst)) {
                                    $tcp_dst_elements = explode("-", $tcp_dst);
                                    if (trim($tcp_dst_elements[0]) == trim($tcp_dst_elements[1])) {
                                        $tcp_dst_elements = $tcp_dst_elements[0];
                                    } else {
                                        $tcp_dst_elements = $tcp_dst;
                                    }
                                } else {
                                    $tcp_dst_elements = $tcp_dst;
                                }
                                # Src Port
                                if (preg_match("/-/", $tcp_src)) {
                                    $tcp_src_elements = explode("-", $tcp_src);
                                    if ($tcp_src_elements[0] == $tcp_src_elements[1]) {
                                        $tcp_src_elements = $tcp_src_elements[0];
                                    } else {
                                        $tcp_src_elements = $tcp_src;
                                    }
                                } else {
                                    $tcp_src_elements = $tcp_src;
                                }
                                $sql[] = "('$source','$addressName','$addressNamePan','$vsys','$description','$tcp_src_elements','$tcp_dst_elements','tcp')";
                            } elseif (($protocol_udp != "") and ( $protocol_tcp == "")) {
                                # IS UDP ONLY
                                #destination:#source
                                $tcp = explode(":", $protocol_udp);
                                $tcp_dst = $tcp[0];
                                if (isset($tcp[1])) {
                                    //$tcp_dst = $tcp[1];
                                    $tcp_src = $tcp[1];
                                } else {
                                    $tcp_src = "";
                                }

                                if (preg_match("/-/", $tcp_dst)) {
                                    $tcp_dst_elements = explode("-", $tcp_dst);
                                    if ($tcp_dst_elements[0] == $tcp_dst_elements[1]) {
                                        $tcp_dst_elements = $tcp_dst_elements[0];
                                    } else {
                                        $tcp_dst_elements = $tcp_dst;
                                    }
                                } else {
                                    $tcp_dst_elements = $tcp_dst;
                                }

                                if (preg_match("/-/", $tcp_src)) {
                                    $tcp_src_elements = explode("-", $tcp_src);
                                    if ($tcp_src_elements[0] == $tcp_src_elements[1]) {
                                        $tcp_src_elements = $tcp_src_elements[0];
                                    } else {
                                        $tcp_src_elements = $tcp_src;
                                    }
                                } else {
                                    $tcp_src_elements = $tcp_src;
                                }
                                $sql[] = "('$source','$addressName','$addressNamePan','$vsys','$description','$tcp_src_elements','$tcp_dst_elements','udp')";
                            } elseif (($protocol_udp != "") and ( $protocol_tcp != "")) {
                                # IS TCP AND UDP CREATING GROUP
                                #Create Group and get ID
                                $projectdb->query("INSERT INTO services_groups_id (source,vsys,name_ext,name) VALUES ('$source','$vsys','$addressName','$addressNamePan')");
                                $grpID = $projectdb->insert_id;
                                #destination:#source
                                $tcp = explode(":", $protocol_tcp);
                                $tcp_dst = $tcp[0];
                                if (isset($tcp[1])) {
                                    //$tcp_dst = $tcp[1];
                                    $tcp_src = $tcp[1];
                                } else {
                                    $tcp_src = "";
                                }

                                if (preg_match("/-/", $tcp_dst)) {
                                    $tcp_dst_elements = explode("-", $tcp_dst);
                                    if (trim($tcp_dst_elements[0]) == trim($tcp_dst_elements[1])) {
                                        $tcp_dst_elements = $tcp_dst_elements[0];
                                    } else {
                                        $tcp_dst_elements = $tcp_dst;
                                    }
                                } else {
                                    $tcp_dst_elements = $tcp_dst;
                                }

                                if (preg_match("/-/", $tcp_src)) {
                                    $tcp_src_elements = explode("-", $tcp_src);
                                    if ($tcp_src_elements[0] == $tcp_src_elements[1]) {
                                        $tcp_src_elements = $tcp_src_elements[0];
                                    } else {
                                        $tcp_src_elements = $tcp_src;
                                    }
                                } else {
                                    $tcp_src_elements = $tcp_src;
                                }
                                if ($tcp_src_elements != "") {
                                    $srvname = "tcp-" . $tcp_src_elements . "-" . $tcp_dst_elements;
                                } else {
                                    $srvname = "tcp-" . $tcp_dst_elements;
                                }

                                $sql[] = "('$source','$srvname','$srvname','$vsys','$description','$tcp_src_elements','$tcp_dst_elements','tcp')";
                                $projectdb->query("INSERT INTO services_groups (source,vsys,member,lid) VALUES ('$source','$vsys','$srvname','$grpID')");

                                #UDP
                                $tcp_src_elements = "";
                                $tcp_dst_elements = "";

                                $tcp = explode(":", $protocol_udp);
                                $tcp_dst = $tcp[0];
                                if (isset($tcp[1])) {
                                    $tcp_src = $tcp[1];
                                } else {
                                    $tcp_src = "";
                                }

                                if (preg_match("/-/", $tcp_dst)) {
                                    $tcp_dst_elements = explode("-", $tcp_dst);
                                    if ($tcp_dst_elements[0] == $tcp_dst_elements[1]) {
                                        $tcp_dst_elements = $tcp_dst_elements[0];
                                    } else {
                                        $tcp_dst_elements = $tcp_dst;
                                    }
                                } else {
                                    $tcp_dst_elements = $tcp_dst;
                                }

                                if (preg_match("/-/", $tcp_src)) {
                                    $tcp_src_elements = explode("-", $tcp_src);
                                    if ($tcp_src_elements[0] == $tcp_src_elements[1]) {
                                        $tcp_src_elements = $tcp_src_elements[0];
                                    } else {
                                        $tcp_src_elements = $tcp_src;
                                    }
                                } else {
                                    $tcp_src_elements = $tcp_src;
                                }
                                if ($tcp_src_elements != "") {
                                    $srvname = "udp-" . $tcp_src_elements . "-" . $tcp_dst_elements;
                                } else {
                                    $srvname = "udp-" . $tcp_dst_elements;
                                }
                                $sql[] = "('$source','$srvname','$srvname','$vsys','$description','$tcp_src_elements','$tcp_dst_elements','udp')";
                                $projectdb->query("INSERT INTO services_groups (source,vsys,member,lid) VALUES ('$source','$vsys','$srvname','$grpID')");
                            }
                        } elseif ($protocol == "IP") {

                        } elseif ($protocol == "ICMP") {

                        }
                        $protocol = "";
                        $protocol_tcp = "";
                        $protocol_udp = "";
                        $description = "";
                        $tcp_src_elements = "";
                        $tcp_dst_elements = "";
                    }

                    if (preg_match("/set protocol /i", $names_line)) {
                        $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                        $protocol = $data[2]; #TCP/UDP o IP o ICMP o TCP/UDP/SCTP
                    }

                    if (preg_match("/set udp-portrange/i", $names_line)) {
                        $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                        if ($data[2] == "0:0") {

                        } else {
                            $protocol_udp = $data[2];
                            $protocol = "UDP";
                        }
                    }

                    if (preg_match("/set tcp-portrange/i", $names_line)) {
                        $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                        if ($data[2] == "0:0") {

                        } else {
                            $protocol_tcp = $data[2];
                            $protocol = "TCP";
                        }
                    }

                    if (preg_match("/set protocol-number/i", $names_line)) {
                        $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                        $protocol_number = $data[2];
                    }

                    if (preg_match("/set icmptype/i", $names_line)) {
                        $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                        $protocol_icmp_type = $data[2];
                    }

                    if (preg_match("/set icmpcode/i", $names_line)) {
                        $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                        $protocol_icmp_code = $data[2];
                    }

                    if (preg_match("/set comment/i", $names_line)) {
                        $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                        $description = $data[2];
                    }
                }
            }
        }


        $lastline = $names_line;
    }
    if (count($sql) > 0) {
        $sql_unique = array_unique($sql);
        $projectdb->query("INSERT INTO services (source,name_ext,name,vsys,description,sport,dport,protocol) VALUES " . implode(",", $sql_unique) . ";");
    }
}

function get_dst_src_service_ports($tcp_service, &$tcp_dst, &$tcp_src){
    if (strpos($tcp_service, ':') !== false) {
        list($tcp_dst, $tcp_src) = explode(':', $tcp_service);
    } else {
        $tcp_dst = $tcp_service;
    }
}

function get_port_range($tcp_port){
    if ($tcp_port!=""){
        if (preg_match("/-/", $tcp_port)) {
            $tcp_elements = explode("-", $tcp_port);
            if ($tcp_elements[0] == $tcp_elements[1]) {
                $tcp_port = $tcp_elements[0];
            }
        }
    }
    return $tcp_port;
}

function create_or_update_service($source, $vsys, $service_name, $service_name_pan, $description, $service_list, $protocol,&$service_group_id_lid, &$service_id_lid, &$sql, &$sql_groups_id, &$sql_groups, &$map_services, $both_protocols=false){
    $create_group = false;
    if($both_protocols===true || count($service_list)>1){
        $create_group = true;
    }

    if($create_group){

        if(!$both_protocols) {
            //1. Create the new group
            $service_group_id_lid++;
            $sql_groups_id[] = "('$service_group_id_lid','$source','$vsys','$service_name','$service_name_pan')";
        }
        foreach($service_list as $service) {

            $src = '';
            $dst = '';

            //1. Check if there's a src and dst port defined
            get_dst_src_service_ports($service, $dst, $src);

            //2. Check if port is range but do not allow port range like 80-80
            $dst = get_port_range($dst);
            $src = get_port_range($src);

            $map_key = $protocol."_".$dst."_".$src;

            if(isset($map_services[$map_key])){
                $id = $map_services[$map_key]['id'];
                $service_name = $map_services[$map_key]['name'];
                $sql_groups[]="('$source','$vsys','services','$service_name','$id','$service_group_id_lid')";
            }else{
                $service_name=$protocol.'_'.$dst;
                if($src!=""){
                    $service_name.="_".$src;
                }
                $map_services[$map_key]['id']=$service_id_lid;
                $map_services[$map_key]['name']=$service_name;
                $sql[] = "('$service_id_lid','$source','$service_name','$service_name','$vsys','$description','$src','$dst','$protocol')";
                $sql_groups[]="('$source','$vsys','services','$service_name','$service_id_lid','$service_group_id_lid')";
                $service_id_lid++;
            }

        } // end foreach
    // end create group
    }else{
        $src = '';
        $dst = '';

        //1. Check if there's a src and dst port defined
        get_dst_src_service_ports($service_list[0], $dst, $src);

        //2. Check if port is range but do not allow port range like 80-80
        $dst = get_port_range($dst);
        $src = get_port_range($src);

        $sql[] = "('$service_id_lid','$source','$service_name','$service_name_pan','$vsys','$description','$src','$dst','$protocol')";
        $service_id_lid++;
    }
}

function get_services2($fortinet_config_file, $source, $vsys, $ismultiornot) {

    global $projectdb;
    $isAddress = false;
    $isObject = false;
    $sql = array();
    $sql_groups = [];
    $sql_groups_id=[];
    $type = "";
    $ipaddress = "";
    $netmask = "";
    $cidr = "";
    $addressName = "";
    $protocol_number="";
    $addressNamePan = "";
    $description = "";
    $getRangeEnd = "";
    $getRangeStart = "";
    $fqdn = "";
    $sql = array();
    $protocol_udp = [];
    $protocol_tcp = [];
    $tcp_src_elements_array=array();
    $tcp_src_elements = "";
    $protocol="";
    $tcp_dst_elements = "";
    $multi_line_comment=false;

    $map_services = [];

    $service_group_id_lid=0;
    $getMaxID = $projectdb->query("SELECT max(id) as max FROM services_groups_id;");
    if ($getMaxID->num_rows == 1) {
        $max1 = $getMaxID->fetch_assoc();
        $service_group_id_lid = $max1['max'];
        if (($service_group_id_lid == null) OR ($service_group_id_lid == '')){
            $service_group_id_lid=0;
        }
        $service_group_id_lid++;
    }

    $service_id_lid=0;
    $getMaxID = $projectdb->query("SELECT max(id) as max FROM services;");
    if ($getMaxID->num_rows == 1) {
        $max1 = $getMaxID->fetch_assoc();
        $service_id_lid = $max1['max'];
        if (($service_id_lid == null) OR ($service_id_lid == '')){
            $service_id_lid=0;
        }
        $service_id_lid++;
    }

    if ($ismultiornot == "singlevsys") {
        $START = TRUE;
        $VDOM = FALSE;
    } else {
        $START = FALSE;
        $VDOM = FALSE;
    }
    $lastline = "";
    foreach ($fortinet_config_file as $line => $names_line) {
        if ($START == FALSE) {
            if (preg_match("/^config vdom/i", $names_line)) {
                $VDOM = TRUE;
            }
            if ($VDOM == TRUE) {
                if (preg_match("/^edit $vsys/i", $names_line)) {
                    $START = TRUE;
                }
            }
        } else {
            if ((preg_match("/^end/i", $lastline)) AND ( preg_match("/^end/i", $names_line))) {
                $START = FALSE;
                $VDOM = FALSE;
            } elseif ((preg_match("/^edit/i", $lastline)) and ( preg_match("/^end/i", $names_line))) {
                $START = FALSE;
                $VDOM = FALSE;
            }
        }

        if ($START) {
            if (preg_match("/^config firewall service custom/i", $names_line)) {
                $isObject = true;
            }

            if ($isObject) {
                if ($multi_line_comment===false &&  preg_match("/^end/i", $names_line)) {
                    $isObject = false;
                    $START = false;
                }
                if (preg_match("/edit /i", $names_line)) {
                    $isAddress = true;
                    $meta = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                    $addressNamePan = truncate_names(normalizeNames($meta[1]));
                    $addressName = trim($meta[1]);
                }

                if ($isAddress) {
                    if (preg_match("/next/i", $names_line)) {
                        $isAddress = false;
                        if ((preg_match("/TCP\/UDP/i", $protocol)) OR preg_match("/TCP/i", $protocol) OR preg_match("/UDP/i", $protocol)) {
                            if (   ((count($protocol_udp) == 0) AND (is_array($protocol_udp))) and  ((count($protocol_tcp) > 0) AND (is_array($protocol_tcp)))  ) {
                                # IS TCP ONLY
                                create_or_update_service($source, $vsys, $addressName, $addressNamePan, $description, $protocol_tcp, 'tcp',$service_group_id_lid, $service_id_lid, $sql, $sql_groups_id, $sql_groups, $map_services);
                            }
                            elseif ((count($protocol_udp) > 0) and ( count($protocol_tcp) == 0)) {
                                # IS UDP ONLY
                                create_or_update_service($source, $vsys, $addressName, $addressNamePan, $description, $protocol_udp, 'udp',$service_group_id_lid, $service_id_lid, $sql, $sql_groups_id, $sql_groups, $map_services);
                            }
                            elseif (  ( (count($protocol_udp) > 0) AND (is_array($protocol_udp)) )  and ( (is_array($protocol_tcp)) AND (count($protocol_tcp) > 0 )) ){
                                # IS TCP AND UDP CREATING GROUP
                                #Create Group and get ID
                                //1. Create the new group
                                $service_group_id_lid++;
                                $sql_groups_id[] = "('$service_group_id_lid','$source','$vsys','$addressName','$addressNamePan')";
                                create_or_update_service($source, $vsys, $addressName, $addressNamePan, $description, $protocol_tcp, 'tcp',$service_group_id_lid, $service_id_lid, $sql, $sql_groups_id, $sql_groups,$map_services, true);
                                create_or_update_service($source, $vsys, $addressName, $addressNamePan, $description, $protocol_udp, 'udp',$service_group_id_lid, $service_id_lid, $sql, $sql_groups_id, $sql_groups,$map_services, true);

                            }
                        }
                        else{
                            if ($protocol=="IP"){$protocol=$protocol_number;}
                            $sql[] = "('$service_id_lid','$source','$addressName','$addressNamePan','$vsys','$description','','','$protocol')";
                            $service_id_lid++;
                        }
                        $protocol = "";
                        $protocol_tcp = [];
                        $protocol_udp = [];
                        $description = "";
                        $multi_line_comment=false;
                    }

                    if (preg_match("/set protocol /i", $names_line)) {
                        $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                        $protocol = $data[2]; #TCP/UDP o IP o ICMP o TCP/UDP/SCTP
                    }

                    if (preg_match("/set udp-portrange/i", $names_line)) {
                        $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                        if ((isset($data[2])) AND ($data[2] == "0:0")) {

                        }
                        else {
                            unset($data[0]); unset($data[1]);
                            $protocol_udp = array_values($data);
                            $protocol = "UDP";
                        }
                    }

                    if (preg_match("/set tcp-portrange/i", $names_line)) {
                        $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                        if ((isset($data[2])) AND ($data[2] == "0:0")) {

                        } else {
                            unset($data[0]); unset($data[1]);
                            $protocol_tcp = array_values($data);
                            $protocol = "TCP";
                        }
                    }

                    if (preg_match("/set protocol-number/i", $names_line)) {
                        $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                        if (isset($data[2])){
                            $protocol_number = $data[2];
                        }
                        else{
                            echo "Error: ".$names_line.PHP_EOL;
                        }

                    }

                    if (preg_match("/^set icmptype/i", $names_line)) {
                        $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                        if (isset($data[2])){
                            $protocol_icmp_type = $data[2];
                        }
                        else{
                            echo "Error: ".$names_line.PHP_EOL;
                        }

                    }

                    if (preg_match("/^set icmpcode/i", $names_line)) {
                        $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                        if (isset($data[2])){
                            $protocol_icmp_code = $data[2];
                        }
                        else{
                            echo "Error: ".$names_line.PHP_EOL;
                        }

                    }

                    if (preg_match("/set comment /i", $names_line) || $multi_line_comment) {
                        $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                        $count = count($data);
                        $Commentsa = "";
                        if($count>=3){
                            for($i=2;$i<$count;$i++){
                                $Commentsa.= trim($data[$i]);
                            }
                        }
                        //Check if the comments contains one or more lines, by checking if it ends with "
                        if($multi_line_comment){
                            $description .= " " . normalizeComments($names_line);
                        }else {
                            $description = normalizeComments($Commentsa);
                        }
                        $multi_line_comment = !endsWith($names_line, "\"\n");
                    }
                }
            }
        }


        $lastline = $names_line;
    }
    if (count($sql) > 0) {
        $sql_unique = array_unique($sql);
        $projectdb->query("INSERT INTO services (id,source,name_ext,name,vsys,description,sport,dport,protocol) VALUES " . implode(",", $sql_unique) . ";");
    }
    if (count($sql_groups_id) > 0) {
        $sql_unique = array_unique($sql_groups_id);
        $projectdb->query("INSERT INTO services_groups_id (id, source,vsys,name_ext,name) VALUES " . implode(",", $sql_unique) . ";");
    }
    if (count($sql_groups) > 0) {
        $sql_unique = array_unique($sql_groups);
        $projectdb->query("INSERT INTO services_groups (source,vsys,table_name,member,member_lid,lid) VALUES " . implode(",", $sql_unique) . ";");
    }

}

function get_services_groups($fortinet_config_file, $source, $vsys, $ismultiornot) {

    global $projectdb;
    $isAddress = false;
    $isObject = false;
    $sql = array();
    $sql1 = array();
    $lid = "";
    $addressNamePan = "";
    $addressName = "";

    if ($ismultiornot == "singlevsys") {
        $START = TRUE;
        $VDOM = FALSE;
    } else {
        $START = FALSE;
        $VDOM = FALSE;
    }
    $lastline = "";
    foreach ($fortinet_config_file as $line => $names_line) {
        if ($START == FALSE) {
            if (preg_match("/^config vdom/i", $names_line)) {
                $VDOM = TRUE;
            }
            if ($VDOM == TRUE) {
                if (preg_match("/^edit $vsys/i", $names_line)) {
                    $START = TRUE;
                }
            }
        } else {
            if ((preg_match("/^end/i", $lastline)) AND ( preg_match("/^end/i", $names_line))) {
                $START = FALSE;
                $VDOM = FALSE;
            } elseif ((preg_match("/^edit/i", $lastline)) and ( preg_match("/^end/i", $names_line))) {
                $START = FALSE;
                $VDOM = FALSE;
            }
        }

        if ($START) {
            if (preg_match("/config firewall service group/i", $names_line)) {
                $isObject = true;
            }


            if ($isObject) {
                if (preg_match("/^\bend\b/i", $names_line)) {
                    $isObject = false;
                    $START = false;
                }
                if (preg_match("/\bedit\b/i", $names_line)) {
                    $isAddress = true;
                    $meta = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                    $newname = str_replace('/', '-', $meta[1]);
                    $addressNamePan = truncate_names(normalizeNames($newname));
                    $addressName = trim($meta[1]);
                    $projectdb->query("INSERT INTO services_groups_id (name_ext,name,source,vsys) VALUES ('$addressName','$addressNamePan','$source','$vsys')");
                    $lid = $projectdb->insert_id;
                }

                if ($isAddress) {
                    if (preg_match("/\bnext\b/i", $names_line)) {
                        $isAddress = false;
                        $lid = "";
                        $addressNamePan = "";
                        $addressName = "";
                    }

                    if (preg_match("/set member /i", $names_line)) {
                        $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                        foreach ($data as $value => $datos) {
                            if (($datos == "set") or ( $datos == "member")) {

                            } else {
                                $memberPan = truncate_names(normalizeNames(trim($datos)));  //TODO: Should it point to the new normalized name, or the original dirty name?
                                $sql[] = "('$datos','$source','$vsys','$lid')";
                            }
                        }
                    }
                }
            }
        }


        $lastline = $names_line;
    }
    if (count($sql) > 0) {
        $projectdb->query("INSERT INTO services_groups (member,source,vsys,lid) VALUES " . implode(",", $sql));
    }
}

function get_address_groups($fortinet_config_file, $source, $vsys, $ismultiornot, &$regions, $addrgrp) {

    global $projectdb;

    $isAddress = false;
    $isObject = false;
    $sql = array();
    $addressGroup=array();
    $defaultRegions=array();
    $addressNamePan = "";
    $addressName = "";
    $description = "";
    $multi_line_comment=false;


    #Load Default Regions
    $getDFRegions=$projectdb->query("SELECT id,name FROM default_regions;");
    if ($getDFRegions->num_rows>0){
        while($getDFRegionsData=$getDFRegions->fetch_assoc()){
            $defaultRegions[$getDFRegionsData['name']]=$getDFRegionsData['id'];
        }
    }

    $lid=0;
    $getMaxID = $projectdb->query("SELECT max(id) as max FROM address_groups_id;");
    if ($getMaxID->num_rows == 1) {
        $max1 = $getMaxID->fetch_assoc();
        $lid = $max1['max'];
        if (($lid == null) OR ($lid == '')){
            $lid=0;
        }
        $lid++;
    }
    if ($ismultiornot == "singlevsys") {
        $START = TRUE;
        $VDOM = FALSE;
        $VDOM = FALSE;
    } else {
        $START = FALSE;
        $VDOM = FALSE;
    }
    $lastline = "";
    foreach ($fortinet_config_file as $line => $names_line) {
        if ($START == FALSE) {
            if (preg_match("/^config vdom/i", $names_line)) {
                $VDOM = TRUE;
            }
            if ($VDOM == TRUE) {
                if (preg_match("/^edit $vsys/i", $names_line)) {
                    $START = TRUE;
                }
            }
        } else {
            if ((preg_match("/^end/i", $lastline)) AND ( preg_match("/^end/i", $names_line))) {
                $START = FALSE;
                $VDOM = FALSE;
            } elseif ((preg_match("/^edit/i", $lastline)) and ( preg_match("/^end/i", $names_line))) {
                $START = FALSE;
                $VDOM = FALSE;
            }
        }

        if ($START) {
            if (preg_match("/config firewall $addrgrp/i", $names_line)) {
                $isObject = true;
            }


            if ($isObject) {
                //if (preg_match("/^\bend\b/i", $names_line)) {
                if ($multi_line_comment===false && preg_match("/^\bend\b/i", $names_line)) {
                    $isObject = false;
                    $START = false;
                }
                if (preg_match("/^\s*edit /i", $names_line)) {
                    $isAddress = true;
                    $multi_line_comment=false;
                    $meta = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                    $newname = str_replace('/', '-', $meta[1]);
                    $addressNamePan = truncate_names(normalizeNames($newname));
                    $addressName = $meta[1];
                }

                if ($isAddress) {
                    if (preg_match("/set member /i", $names_line)) {
                        $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                        foreach ($data as $value => $datos) {
                            if (($datos == "set") or ( $datos == "member")) {

                            } else {
                                $member_lid="";
                                $table_name="";
                                if (isset($regions[$datos],$defaultRegions[$regions[$datos]])){
                                    $table_name="default_regions";
                                    $member_lid=$defaultRegions[$regions[$datos]];
                                }
                                if($addrgrp==='addrgrp6'){
                                    $datos = str_replace('/', '-', $datos);
                                    $cleaned_name = truncate_names(normalizeNames($datos));
                                }else{
                                    $cleaned_name = truncate_names(normalizeNames(clean_name($datos)));
                                }
//                                $cleaned_name = preg_replace('/[^a-zA-Z0-9-. \']/', '_', $datos);
//                                $cleaned_name = str_replace("'", '', $cleaned_name);
//                                if(starts_with($cleaned_name,"_")){
//                                    $cleaned_name = "s".$cleaned_name;
//                                }
                                $sql[] = "('$cleaned_name','$source','$vsys','$lid','$member_lid','$table_name')";
                            }
                        }
                    }
                    if (preg_match("/set comment /i", $names_line) || $multi_line_comment) {
                        $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                        $count = count($data);
                        $Commentsa = "";
                        if($count>=3){
                            for($i=2;$i<$count;$i++){
                                $Commentsa.= trim($data[$i]);
                            }
                        }
                        //Check if the comments contains one than 1 line, by checking if it ends with "
                        if($multi_line_comment){
                            $description .= " " . normalizeComments($names_line);
                        }else {
                            $description = normalizeComments($Commentsa);
                        }
                        $multi_line_comment = !endsWith($names_line, "\"\n");

                    }
                    if (preg_match("/\bnext\b/i", $names_line)) {
                        $isAddress = false;
                        $addressGroup[]="('$lid','$addressName','$addressNamePan','$source','$vsys','$description','static')";
                        $lid++;
                        $addressNamePan = "";
                        $addressName = "";
                        $description = "";
                        $multi_line_comment=false;
                    }
                }
            }
        }


        $lastline = $names_line;
    }

    if (count($addressGroup)>0){
        $projectdb->query("INSERT INTO address_groups_id (id,name_ext,name,source,vsys,description,type) VALUES ". implode(",",$addressGroup).";");
        unset($addressGroup);
        if (count($sql) > 0) {
            $projectdb->query("INSERT INTO address_groups (member,source,vsys,lid,member_lid,table_name) VALUES " . implode(",", $sql).";");
            unset($sql);
        }
    }
}
