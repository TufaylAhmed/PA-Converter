<?php
# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
#HEADER
//Loads all global PHP definitions
require_once '/var/www/html/libs/common/definitions.php';

//Dependencies
require_once INC_ROOT.'/bin/configurations/parsers/ServicesMapping.php';
use PaloaltoNetworks\Parsers\Utils\ServicesMapping;

//User management control
//require_once INC_ROOT.'/userManager/start.php';
//include INC_ROOT.'/bin/authentication/sessionControl.php';

//Dependencies
require_once INC_ROOT.'/libs/database.php';
require_once INC_ROOT.'/libs/shared.php';
require_once INC_ROOT.'/libs/projectdb.php';
require_once INC_ROOT.'/libs/objects/SecurityRulePANObject.php';
//require_once INC_ROOT.'/libs/common/lib-rules.php';

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

if ($action=="import"){
    ini_set('pcre.backtrack_limit','10000');
    ini_set('max_execution_time', PARSER_max_execution_time);
    ini_set("memory_limit",PARSER_max_execution_memory);
    $path = USERSPACE_PATH."/projects/".$project."/";
    $i=0;
    $dirrule = opendir($path);

    update_progress($project,'0.00','Reading config files',$jobid);
    while ($config_filename = readdir($dirrule)) {
        //if ( ($config_filename != ".") && ($config_filename != "..") && ($config_filename != "parsers.txt") && ($config_filename != "Backups") && ($config_filename != "Pcaps") && ($config_filename != "Reports") AND ($config_filename != "CPviewer.html") AND (!preg_match("/^MT-/",$config_filename))) {
        if (checkFiles2Import($config_filename)){
            $config_path = $path . $config_filename;
            $filename=$config_filename;
            $filenameParts = pathinfo($config_filename);
            $verificationName = $filenameParts['filename'];
            $isUploaded = $projectdb->query("SELECT id FROM device_mapping WHERE filename='$verificationName';");
//            $isUploaded=$projectdb->query("SELECT id FROM device_mapping WHERE filename='$config_filename';");
            if ($isUploaded->num_rows==0){
                clean_config($config_path);
                import_config($config_path,$project,$config_filename,$jobid); //This should update the $source
                //This import_config calculates used objects inside
//                $sourcesAdded[] = $source;
                update_progress($project,'0.30','File:'.$filename.' Phase 3 Referencing Groups',$jobid);

            }
            else {
                update_progress($project, '0.00', 'This filename '.$filename.' its already uploaded. Skipping...',$jobid);
                //unlink($config_path);
            }
        }
    }
    #Check used
    update_progress($project,'0.90','File:'.$filename.' Calculating Used Objects',$jobid);
//    check_used_objects_new($sourcesAdded);
    update_progress($project,'1.00','Done.',$jobid);
    unlink($config_path);
}


function clean_config($config_path){
    #CLEAN CONFIG FROM EMPTY LINES AND CTRL+M
    file_put_contents($config_path, implode(PHP_EOL, file($config_path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES)));
    $kkk= str_replace("\r\n", "\n",
        str_replace("     ", " ",
            str_replace("\\\r", "",
                str_replace("\\\n", "",
                    str_replace("\\\r\n", "",
                        str_replace("\\\n\r", "",
                            file_get_contents($config_path)
                        )))))
    );
    //$ro = preg_replace('/\s+/', ' ',$kkk);
    file_put_contents($config_path, $kkk);

}

function import_config($config_path,$project,$config_filename,$jobid){
    global $projectdb;
    global $source;
    $filename = $config_filename;

    $getVsys=$projectdb->query("SELECT id,vsys FROM device_mapping WHERE filename='$filename';");
    if ($getVsys->num_rows==0){
        $projectdb->query("INSERT INTO device_mapping (device,version,ispanorama,active,project,filename,vsys,vendor) VALUES ('$filename','',0,1,'$project','$filename','vsys1','Sidewinder')");
        $vsys="vsys1";
        $source=$projectdb->insert_id;
    }
    else{
        $getVsysData=$getVsys->fetch_assoc();
        $source=$getVsysData['id'];
    }

    #Config Template
    $getTemplate=$projectdb->query("SELECT id FROM templates_mapping WHERE filename='$filename';");
    if ($getTemplate->num_rows==0){
        $template_name=$filename."_template";
        $projectdb->query("INSERT INTO templates_mapping (project,name,filename,source) VALUES ('$project','$template_name','$filename','$source');");
        $template=$projectdb->insert_id;
    }
    else{
        $getTemplateData=$getTemplate->fetch_assoc();
        $template=$getTemplateData['id'];
    }

    update_progress($project,'0.10','Reading Network Interfaces',$jobid);
    get_interfaces($source,$vsys,$template,$config_path);
    update_progress($project,'0.20','Reading Address and Groups',$jobid);
    get_address_SIDEWINDER($source,$vsys,$template,$config_path);
    get_addressGroups($source,$vsys,$template,$config_path);
    GroupMember2IdAddress($config_filename);
    update_progress($project,'0.40','Reading Services and Groups',$jobid);
    // Add predefined services and services groups
    ServicesMapping::addPredefinedSrvAndSrvGroups($projectdb, "sidewinder", $source, $vsys);
    get_services($source,$vsys,$template,$config_path);
    get_servicesGroups($source,$vsys,$template,$config_path);
    GroupMember2IdServices($config_filename);
    update_progress($project,'0.60','Reading Security Policies',$jobid);
    get_security_policy($source,$vsys,$template,$config_path);
    update_progress($project,'0.80','Phase 8 of 10',$jobid);
    get_normalized_names($source,$vsys);

    // Auto split the address groups based on defined PARSER_max_number_address_per_group
    // for upgraded installations that does not have the variable in the /home/userSpace/userDefinition.php defined
    if (!defined('PARSER_max_number_address_per_group')) {
        define('PARSER_max_number_address_per_group', -1);
    }
    if(PARSER_max_number_address_per_group!=-1) {
        update_progress($project, '0.85', ' Split the address group members using as a limit defined value of '. PARSER_max_number_address_per_group . ' members', $jobid);
        splitMembersOnGroups();
    }

    update_progress($project,'0.9','Calculating Used Objects',$jobid);
    check_used_objects_new([$source]);
    optimization($source,$vsys,$template,$config_path);

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


    update_progress($project,'1.0','Done',$jobid);

    // Call function to generate initial consumptions
    deviceUsage("initial", "get", $project, "", "", $vsys, $source, $template_name);


}

function optimization($source,$vsys,$template,$config_path){
    global $projectdb;
    #Check if we have zones created or not. if not grab from the rules

    //$ids_rules = getSecurityIdsBySourceVsys($source, $vsys);
    $ids_rules = getIdsBySourceVsys("security_rules", $source, $vsys);

    $getZones=$projectdb->query("SELECT id FROM zones WHERE source='$source' AND template='$template';");
    if ($getZones->num_rows==0){

        $zone=array();
        $getZonesRules=$projectdb->query("SELECT name FROM security_rules_from WHERE rule_lid IN (".implode(',', $ids_rules).") GROUP BY name;");
        if ($getZonesRules->num_rows>0){
            while ($getZonesRulesData=$getZonesRules->fetch_assoc()){
                $zone[]="('Layer3','None','$source','$vsys','$template','".$getZonesRulesData['name']."')";
            }
        }
        $getZonesRules=$projectdb->query("SELECT name FROM security_rules_to WHERE rule_lid IN (".implode(',', $ids_rules).") GROUP BY name;");
        if ($getZonesRules->num_rows>0){
            while ($getZonesRulesData=$getZonesRules->fetch_assoc()){
                $zone[]="('Layer3','None','$source','$vsys','$template','".$getZonesRulesData['name']."')";
            }
        }
        $unique=array_unique($zone);
        if (count($unique)>0){
            $projectdb->query("INSERT INTO zones (type,zone_protection_profile,source,vsys,template,name) VALUES ".implode(",",$unique).";");
            unset($unique);unset($zone);
        }
    }
    else{
        $getZonesRules=$projectdb->query("SELECT name FROM security_rules_from WHERE rule_lid IN (".implode(',', $ids_rules).") GROUP BY name;");
        if ($getZonesRules->num_rows>0){
            while ($getZonesRulesData=$getZonesRules->fetch_assoc()){
                $check_zone=$getZonesRulesData['name'];
                $check=$projectdb->query("SELECT id FROM zones WHERE source='$source' AND vsys='$vsys' AND name='$check_zone';");
                if ($check->num_rows==0){
                    $zone[]="('Layer3','None','$source','$vsys','$template','".$getZonesRulesData['name']."')";
                }
            }
        }
        $getZonesRules=$projectdb->query("SELECT name FROM security_rules_to WHERE rule_lid IN (".implode(',', $ids_rules).") GROUP BY name;");
        if ($getZonesRules->num_rows>0){
            while ($getZonesRulesData=$getZonesRules->fetch_assoc()){
                $check_zone=$getZonesRulesData['name'];
                if ($check->num_rows==0) {
                    $zone[] = "('Layer3','None','$source','$vsys','$template','" . $getZonesRulesData['name'] . "')";
                }
            }
        }
        $unique=array_unique($zone);
        if (count($unique)>0){
            $projectdb->query("INSERT INTO zones (type,zone_protection_profile,source,vsys,template,name) VALUES ".implode(",",$unique).";");
            unset($unique);unset($zone);
        }
    }
}

function get_security_policy($source,$vsys,$template,$config_path){
    global $projectdb;

    $mcafee_config_file = file($config_path);

    $addRule=array();
    $addZoneFrom=array();
    $addZoneTo=array();
    $addSRV=array();
    $addTag=array();
    $addSRC=array();
    $addDST=array();
    #Get Last lid from Profiles
    $getlastlid = $projectdb->query("SELECT max(id) as max FROM security_rules;");
    $getLID1 = $getlastlid->fetch_assoc();
    $lid = intval($getLID1['max']) + 1;
    $getlastlid = $projectdb->query("SELECT max(position) as max FROM security_rules;");
    $getLID1 = $getlastlid->fetch_assoc();
    $position = intval($getLID1['max']) + 1;
    $thecolor=1;
    foreach ($mcafee_config_file as $line2 => $names_line2) {
        if (preg_match("/^policy add table=rulegroup/",$names_line2)){
            #Convert into Tags
            preg_match_all('`(\w+(=(([0-9+|\w+][\.|/|,|:|-]?)+|[\'|"].*?[\'|"]))?)`', $names_line2, $matches);
            if (count($matches) > 1) {
                $counter = 0;
                $rule=array();
                foreach ($matches[1] as $option) {
                    $counter++;
                    $option=str_replace("'","",$option);
                    $tmp = explode('=', $option);
                    $name = $tmp[0];
                    $value = '';
                    if (count($tmp) > 1) {
                        if (!empty($tmp[1])) {
                            $value = $tmp[1];
                            if (substr($value, 0, 1) == "'" and substr($value, -1, 1) == "'") {
                                $value = substr($value, 1, -1);
                            }
                            //print $tmp[0] .":". $value."\n";
                            $rule[$tmp[0]] = $value;
                        } else {
                            $value = '';
                        }
                    }
                }
                if (isset($rule["name"])) {
                    $color = "color" . $thecolor;
                    $tagname = truncate_tags($rule["name"]);
                    $projectdb->query("INSERT INTO tag (name,source,vsys,color) VALUES ('$tagname','$source','$vsys','$color');");
                    if ($thecolor == 16) {
                        $thecolor = 1;
                    } else {
                        $thecolor++;
                    }
                }
            }
        }
        if (preg_match("/^policy add table=rule /i", $names_line2)) {
            preg_match_all('`(\w+(=(([0-9+|\w+][\.|/|,|:|-]?)+|[\'|"].*?[\'|"]))?)`', $names_line2, $matches);
            if (count($matches) > 1) {
                $counter = 0;
                foreach ($matches[1] as $option) {
                    $option=str_replace("'","",$option);
                    $counter++;
                    $tmp = explode('=', $option);
                    $name = $tmp[0];
                    $value = '';
                    if (count($tmp) > 1) {
                        if (!empty($tmp[1])) {
                            $value = $tmp[1];
                            if (substr($value, 0, 1) == "'" and substr($value, -1, 1) == "'") {
                                $value = substr($value, 1, -1);
                            }
                            //print $tmp[0] .":". $value."\n";
                            $rule[$tmp[0]] = $value;
                        } else {
                            $value = '';
                        }
                    }
                }

                if (isset($rule["disable"])) {
                    if ($rule["disable"] == "yes") {
                        $RuleDisable = "1";
                    }
                    if ($rule["disable"] == "no") {
                        $RuleDisable = "0";
                    }
                } else {
                    $RuleDisable = "0";
                }

                if (isset($rule["name"])) {
                    $RuleName = truncate_names(normalizeNames($rule["name"]));
                } else {
                    $RuleName = "Rule ".$lid;
                }

                if (isset($rule["description"])) {
                    $RuleDescription = normalizeComments($rule["description"]);
                } else {
                    $RuleDescription = "";
                }

                if (isset($rule["action"])) {
                    if (($rule["action"] == "allow") or ( $rule["action"] == "deny")) {
                        $RuleAction = $rule["action"];
                    }
                } else {
                    $RuleAction = "allow";
                    add_log2('1','Phase 5: Reading Security Rules','Action other than Allow or Deny ['.$rule["action"].'] found in RuleID ['.$lid.']',$source,'No Action Required.','rules',$lid,'security_rules');
                }

                if (isset($rule["rulegroup"])){
                    $Tag=  truncate_tags($rule["rulegroup"]);
                    $getTag=$projectdb->query("SELECT id FROM tag WHERE name='$Tag' AND source='$source' AND vsys='$vsys' LIMIT 1");
                    if ($getTag->num_rows==1){
                        $getTagData=$getTag->fetch_assoc();
                        $TagId=$getTagData['id'];
                        $addTag[]="('$source','$vsys','$TagId','tag','$lid')";
                    }
                }

                if (isset($rule["source_burbs"])) {

                    if ($rule["source_burbs"] == "*") {
                        $RuleZoneSrc = "";
                    } elseif (preg_match('/,/i', $rule["source_burbs"])) {
                        $matches2 = explode(',', $rule["source_burbs"]);

                        foreach ($matches2 as $num => $combo) {
                            $members = explode(":", $combo);
                            $RuleZoneSrc = $members[1];
                            if ($combo != "") {
                                $addZoneFrom[] = "('$source','$vsys','$RuleZoneSrc','$lid')";
                            }
                        }
                    } else {
                        $matches2 = explode(',', $rule["source_burbs"]);

                        foreach ($matches2 as $num => $combo) {
                            $members = explode(":", $combo);
                            $RuleZoneSrc = $members[1];
                            if ($combo != "") {
                                $addZoneFrom[] = "('$source','$vsys','$RuleZoneSrc','$lid')";
                            }
                        }
                    }
                    unset($rule["source_burbs"]);
                }

                if (isset($rule["source_zones"])) {

                    if ($rule["source_zones"] == "*") {
                        $RuleZoneSrc = "";
                    } elseif (preg_match('/,/i', $rule["source_zones"])) {
                        $matches2 = explode(',', $rule["source_zones"]);

                        foreach ($matches2 as $num => $combo) {
                            $members = explode(":", $combo);
                            $RuleZoneSrc = $members[1];
                            if ($combo != "") {
                                $addZoneFrom[] = "('$source','$vsys','$RuleZoneSrc','$lid')";
                            }
                        }
                    } else {
                        $matches2 = explode(',', $rule["source_zones"]);

                        foreach ($matches2 as $num => $combo) {
                            $members = explode(":", $combo);
                            $RuleZoneSrc = $members[1];
                            if ($combo != "") {
                                $addZoneFrom[] = "('$source','$vsys','$RuleZoneSrc','$lid')";
                            }
                        }
                    }
                    unset($rule["source_zones"]);
                }

                if (isset($rule["dest_zones"])) {

                    if ($rule["dest_zones"] == "*") {
                        $RuleZoneDst = "";
                    } elseif (preg_match('/,/i', $rule["dest_zones"])) {
                        $matches2 = explode(',', $rule["dest_zones"]);

                        foreach ($matches2 as $num => $combo) {
                            $members = explode(":", $combo);
                            $RuleZoneDst = $members[1];
                            if ($combo != "") {
                                $addZoneTo[] = "('$source','$vsys','$RuleZoneDst','$lid')";
                            }
                        }
                    } else {
                        $matches2 = explode(',', $rule["dest_zones"]);
                        foreach ($matches2 as $num => $combo) {
                            $members = explode(":", $combo);
                            $RuleZoneDst = $members[1];
                            if ($combo != "") {
                                $addZoneTo[] = "('$source','$vsys','$RuleZoneDst','$lid')";
                            }
                        }
                    }
                    unset($rule["dest_zones"]);
                }

                if (isset($rule["dest_burbs"])) {

                    if ($rule["dest_burbs"] == "*") {
                        $RuleZoneDst = "";
                    } elseif (preg_match('/,/i', $rule["dest_burbs"])) {
                        $matches2 = explode(',', $rule["dest_burbs"]);

                        foreach ($matches2 as $num => $combo) {
                            $members = explode(":", $combo);
                            $RuleZoneDst = $members[1];
                            if ($combo != "") {
                                $addZoneTo[] = "('$source','$vsys','$RuleZoneDst','$lid')";
                            }
                        }
                    } else {
                        $matches2 = explode(',', $rule["dest_burbs"]);
                        foreach ($matches2 as $num => $combo) {
                            $members = explode(":", $combo);
                            $RuleZoneDst = $members[1];
                            if ($combo != "") {
                                $addZoneTo[] = "('$source','$vsys','$RuleZoneDst','$lid')";
                            }
                        }
                    }
                    unset($rule["dest_burbs"]);
                }

                if (isset($rule["service"])){

                    if ($rule["service"] == "*") {
                        $RuleService = "";
                    } else {
                        $matches2 = explode(',', $rule["service"]);

                        foreach ($matches2 as $num => $combo) {
                            $members = explode(":", $combo);
                            $tableService = $members[0];
                            $searchService = $members[1];

                            if ($tableService == "service") {
                                $SearchS = $projectdb->query("SELECT id FROM services WHERE BINARY name_ext='$searchService' AND source='$source' AND vsys='$vsys';");
                                if ($SearchS->num_rows == 1) {
                                    $member_ids = $SearchS->fetch_assoc();
                                    $member_id = $member_ids["id"];
                                    if ($combo != "") {
                                        $addSRV[]="('$source','$vsys','$lid','$member_id','services')";
                                    }
                                } else {
                                    #Error or 0 or more than 1 found OR i migrated to GROUP by TCP and UDP object
                                    $SearchS = $projectdb->query("SELECT id FROM services_groups_id WHERE BINARY name_ext='$searchService' AND source='$source' AND vsys='$vsys' LIMIT 1;");
                                    if ($SearchS->num_rows == 1) {
                                        $member_ids = $SearchS->fetch_assoc();
                                        $member_id = $member_ids["id"];
                                        if ($combo != "") {
                                            $addSRV[]="('$source','$vsys','$lid','$member_id','services_groups_id')";
                                        }
                                    } else {
                                        #mysql_query("INSERT INTO errors (level,source,message) values('warning','Rules','Service used in Rule $RuleID but not seen in Service Database: Name: $searchService');");
                                        #mysql_query("insert into fw1_services (name,port,protocol,used,revisar) values ('$searchService','65000','tcp','1','1');");
                                    }
                                }
                            }
                            elseif ($tableService == "servicegroup") {
                                $SearchS = $projectdb->query("SELECT id FROM services_groups_id WHERE BINARY name_ext='$searchService' AND source='$source' AND vsys='$vsys' LIMIT 1;");
                                if ($SearchS->num_rows == 1) {
                                    $member_ids = $SearchS->fetch_assoc();
                                    $member_id = $member_ids["id"];
                                    if ($combo != "") {
                                        $addSRV[] = "('$source','$vsys','$lid','$member_id','services_groups_id')";
                                    }
                                } else {
                                    #mysql_query("INSERT INTO errors (level,source,message) values('warning','Rules','Service used in Rule $RuleID but not seen in Service Database: Name: $searchService');");
                                    #mysql_query("insert into fw1_services (name,port,protocol,used,revisar) values ('$searchService','65000','tcp','1','1');");
                                }
                            } else {
                                #Unexpected Object
                                #mysql_query("INSERT INTO errors (level,source,message) values('warning','Rules','Unexpected Service Object in Rule $RuleID: Name: $searchService');");
                            }
                        }
                    }
                }

                if (isset($rule["application"])) {
                    //print "App: ".$rule["application"]."\n";
                    if (($rule["application"] == "*") or ( $rule["application"] == "application:all")) {
                        $RuleService = "";
                    } else{
                        $matches2 = explode(',', $rule["application"]);

                        foreach ($matches2 as $num => $combo) {
                            $members = explode(":", $combo);
                            $tableService = $members[0];
                            $searchService = $members[1];
                            //print "splitApp: ".$tableService.":".$searchService."\n";
                            if (($tableService == "custom") or ( $tableService == "application")) {
                                $SearchS = $projectdb->query("SELECT id FROM services WHERE BINARY name_ext='$searchService' AND source='$source' AND vsys='$vsys';");
                                if ($SearchS->num_rows == 1) {
                                    $member_ids = $SearchS->fetch_assoc();
                                    $member_id = $member_ids["id"];
                                    if ($combo != "") {
                                        $addSRV[]="('$source','$vsys','$lid','$member_id','services')";
                                    }
                                } else {
                                    #Error or 0 or more than 1 found OR i migrated to GROUP by TCP and UDP object
                                    $SearchS = $projectdb->query("SELECT id FROM services_groups_id WHERE BINARY name_ext='$searchService' AND source='$source' AND vsys='$vsys' LIMIT 1;");
                                    if ($SearchS->num_rows == 1) {
                                        $member_ids = $SearchS->fetch_assoc();
                                        $member_id = $member_ids["id"];
                                        if ($combo != "") {
                                            $addSRV[]="('$source','$vsys','$lid','$member_id','services_groups_id')";
                                        }
                                    } else {
                                        #mysql_query("INSERT INTO errors (level,source,message) values('warning','Rules','Service used in Rule $RuleID but not seen in Service Database: Name: $searchService');");
                                        #mysql_query("insert into fw1_services (name,port,protocol,used,revisar) values ('$searchService','65000','tcp','1','1');");
                                    }
                                }
                            }
                            elseif ($tableService == "appgroup") {
                                $SearchS = $projectdb->query("SELECT id FROM services_groups_id WHERE BINARY name_ext='$searchService' AND source='$source' AND vsys='$vsys' LIMIT 1;");
                                if ($SearchS->num_rows == 1) {
                                    $member_ids = $SearchS->fetch_assoc();
                                    $member_id = $member_ids["id"];
                                    if ($combo != "") {
                                        $addSRV[] = "('$source','$vsys','$lid','$member_id','services_groups_id')";
                                    }
                                } else {
                                    #mysql_query("INSERT INTO errors (level,source,message) values('warning','Rules','Service used in Rule $RuleID but not seen in Service Database: Name: $searchService');");
                                    #mysql_query("insert into fw1_services (name,port,protocol,used,revisar) values ('$searchService','65000','tcp','1','1');");
                                }
                            } else {
                                #Unexpected Object
                                #mysql_query("INSERT INTO errors (level,source,message) values('warning','Rules','Unexpected Service Object in Rule $RuleID: Name: $searchService');");
                            }
                        }
                    }
                    unset($rule["application"]);
                }

                if (isset($rule["source"])) {

                    if (($rule["source"] == "*") or ( $rule["source"] == "all:v4") or ( $rule["source"] == "all:v6") or ( $rule["source"] == "All") ) {
                        $RuleSource = "";
                    } else {
                        $matches2 = explode(',', $rule["source"]);

                        foreach ($matches2 as $num => $combo) {
                            $members = explode(":", $combo);
                            $tableSource = $members[0];
                            $searchSource = $members[1];

                            if (($tableSource == "host") OR ( $tableSource == "subnet") OR ( $tableSource == "iprange")) {
                                $SearchS = $projectdb->query("SELECT id FROM address WHERE BINARY name='$searchSource' AND source='$source' AND vsys='$vsys'");
                                if ($SearchS->num_rows == 1) {
                                    $member_ids = $SearchS->fetch_assoc();
                                    $member_id = $member_ids["id"];
                                    if ($combo != "") {
                                        $addSRC[] = "('$source','$vsys','$lid','$member_id','address')";
                                    }
                                } else {

                                    #Error or 0 or more than 1 found
                                    # mysql_query("INSERT INTO errors (level,source,message) values('warning','Rules','Source used in Rule $RuleID but not seen in Address Database: Name: $searchSource');");
                                }
                            }
                            elseif ($tableSource=="ipaddr"){
                                $SearchS = $projectdb->query("SELECT id FROM address WHERE ipaddress='$searchSource' AND source='$source' AND vsys='$vsys'");
                                if ($SearchS->num_rows == 1) {
                                    $member_ids = $SearchS->fetch_assoc();
                                    $member_id = $member_ids["id"];
                                    if ($combo != "") {
                                        $addSRC[] = "('$source','$vsys','$lid','$member_id','address')";
                                    }
                                } else {
                                    $SearchS = $projectdb->query("SELECT id FROM address WHERE BINARY name='$searchSource' AND source='$source' AND vsys='$vsys'");
                                    if ($SearchS->num_rows == 1) {
                                        $member_ids = $SearchS->fetch_assoc();
                                        $member_id = $member_ids["id"];
                                        if ($combo != "") {
                                            $addSRC[] = "('$source','$vsys','$lid','$member_id','address')";
                                        }
                                    } else {
                                        $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,type) VALUES ('$source','$vsys','H-$searchSource','H-$searchSource','$searchSource','32','host')");
                                        $member_id = $projectdb->insert_id;
                                        $addSRC[] = "('$source','$vsys','$lid','$member_id','address')";
                                    }
                                    #Error or 0 or more than 1 found
                                    # mysql_query("INSERT INTO errors (level,source,message) values('warning','Rules','Source used in Rule $RuleID but not seen in Address Database: Name: $searchSource');");
                                }
                            }
                            elseif ($tableSource == "netgroup") {
                                $SearchS = $projectdb->query("SELECT id FROM address_groups_id WHERE BINARY name_ext='$searchSource' AND source='$source' AND vsys='$vsys'");
                                if ($SearchS->num_rows == 1) {
                                    $member_ids = $SearchS->fetch_assoc();
                                    $member_id = $member_ids["id"];
                                    if ($combo != "") {
                                        $addSRC[] = "('$source','$vsys','$lid','$member_id','address_groups_id')";
                                    }
                                } else {
                                    #Error or 0 or more than 1 found
                                    #mysql_query("INSERT INTO errors (level,source,message) values('warning','Rules','HostGroup used in Rule $RuleID but not seen in HostGroup Database: Name: $searchSource');");
                                }
                            } elseif ($tableSource == "domain") {
                                #mysql_query("INSERT INTO errors (level,source,message) values('warning','Rules','Domain used in Rule $RuleID (source) but is an unsupported Object for Palo Alto Networks, Name: $searchSource');");
                            } else {
                                #Unexpected Object
                                #mysql_query("INSERT INTO errors (level,source,message) values('warning','Rules','Unexpected Source Address Object in Rule $RuleID: Name: $searchSource');");
                            }
                        }
                    }

                    unset($rule["source"]);
                }

                if (isset($rule["dest"])) {

                    if (($rule["dest"] == "*") or ( $rule["dest"] == "all:v4") or ( $rule["dest"] == "all:v6") OR ( $rule["dest"] == "All")) {
                        $RuleSource = "";
                    } else {
                        $matches2 = explode(',', $rule["dest"]);

                        foreach ($matches2 as $num => $combo) {
                            $members = explode(":", $combo);
                            $tableSource = $members[0];
                            $searchSource = $members[1];

                            if (($tableSource == "host") OR ( $tableSource == "subnet") OR ( $tableSource == "iprange")) {
                                $SearchS = $projectdb->query("SELECT id FROM address WHERE BINARY name_ext='$searchSource' AND source='$source' AND vsys='$vsys'");
                                if ($SearchS->num_rows == 1) {
                                    $member_ids = $SearchS->fetch_assoc();
                                    $member_id = $member_ids["id"];
                                    if ($combo != "") {
                                        $addDST[] = "('$source','$vsys','$lid','$member_id','address')";
                                    } else {
                                        #Error or 0 or more than 1 found
                                        # mysql_query("INSERT INTO errors (level,source,message) values('warning','Rules','Source used in Rule $RuleID but not seen in Address Database: Name: $searchSource');");
                                    }
                                }
                            }
                            elseif ($tableSource=="ipaddr"){
                                $SearchS = $projectdb->query("SELECT id FROM address WHERE ipaddress='$searchSource' AND source='$source' AND vsys='$vsys'");
                                if ($SearchS->num_rows == 1) {
                                    $member_ids = $SearchS->fetch_assoc();
                                    $member_id = $member_ids["id"];
                                    if ($combo != "") {
                                        $addDST[] = "('$source','$vsys','$lid','$member_id','address')";
                                    }
                                } else {
                                    $SearchS = $projectdb->query("SELECT id FROM address WHERE BINARY name='$searchSource' AND source='$source' AND vsys='$vsys'");
                                    if ($SearchS->num_rows == 1) {
                                        $member_ids = $SearchS->fetch_assoc();
                                        $member_id = $member_ids["id"];
                                        if ($combo != "") {
                                            $addDST[] = "('$source','$vsys','$lid','$member_id','address')";
                                        }
                                    } else {
                                        $projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,type) VALUES ('$source','$vsys','H-$searchSource','H-$searchSource','$searchSource','32','host')");
                                        $member_id = $projectdb->insert_id;
                                        $addDST[] = "('$source','$vsys','$lid','$member_id','address')";
                                        #Error or 0 or more than 1 found
                                        # mysql_query("INSERT INTO errors (level,source,message) values('warning','Rules','Source used in Rule $RuleID but not seen in Address Database: Name: $searchSource');");
                                    }
                                }
                            }
                            elseif ($tableSource == "netgroup") {
                                $SearchS = $projectdb->query("SELECT id FROM address_groups_id WHERE BINARY name_ext='$searchSource' AND source='$source' AND vsys='$vsys'");
                                if ($SearchS->num_rows == 1) {
                                    $member_ids = $SearchS->fetch_assoc();
                                    $member_id = $member_ids["id"];
                                    if ($combo != "") {
                                        $addDST[] = "('$source','$vsys','$lid','$member_id','address_groups_id')";
                                    }
                                } else {
                                    #Error or 0 or more than 1 found
                                    #mysql_query("INSERT INTO errors (level,source,message) values('warning','Rules','HostGroup used in Rule $RuleID but not seen in HostGroup Database: Name: $searchSource');");
                                }
                            } elseif ($tableSource == "domain") {
                                #mysql_query("INSERT INTO errors (level,source,message) values('warning','Rules','Domain used in Rule $RuleID (source) but is an unsupported Object for Palo Alto Networks, Name: $searchSource');");
                            } else {
                                #Unexpected Object
                                #mysql_query("INSERT INTO errors (level,source,message) values('warning','Rules','Unexpected Source Address Object in Rule $RuleID: Name: $searchSource');");
                            }
                        }
                    }

                    unset($rule["dest"]);
                }


                $addRule[]="('$source','$vsys','$lid','$position','$RuleName','$RuleDescription','$RuleAction','$RuleDisable')";
                $lid++;$position++;
            }
        }
    }
    if (count($addRule)>0){
        $projectdb->query("INSERT INTO security_rules (source,vsys,id,position,name,description,action,disabled) VALUES ".implode(",",$addRule));
        unset($addRule);

        if (count($addTag)>0){
            $projectdb->query("INSERT INTO security_rules_tag (source,vsys,member_lid,table_name,rule_lid) VALUES ".implode(",",$addTag));
            unset($addTag);
        }
        if (count($addZoneFrom)>0){
            $projectdb->query("INSERT INTO security_rules_from (source,vsys,name,rule_lid) VALUES ".implode(",",$addZoneFrom));
            unset($addZoneFrom);
        }
        if (count($addZoneTo)>0){
            $projectdb->query("INSERT INTO security_rules_to (source,vsys,name,rule_lid) VALUES ".implode(",",$addZoneTo));
            unset($addZoneTo);
        }
        if (count($addSRV)>0){
            $projectdb->query("INSERT INTO security_rules_srv (source,vsys,rule_lid,member_lid,table_name) VALUES ".implode(",",$addSRV));
            unset($addSRV);
        }
        if (count($addSRC)>0){
            $projectdb->query("INSERT INTO security_rules_src (source,vsys,rule_lid,member_lid,table_name) VALUES ".implode(",",$addSRC));
            unset($addSRC);
        }
        if (count($addDST)>0){
            $projectdb->query("INSERT INTO security_rules_dst (source,vsys,rule_lid,member_lid,table_name) VALUES ".implode(",",$addDST));
            unset($addDST);
        }

        # Update objects where ipaddress is equal to the Name as Dummy
        $projectdb->query("UPDATE address SET dummy=1 WHERE name_ext=ipaddress AND (cidr=32 OR cidr=128) AND source='$source' AND vsys='$vsys';");
    }
}

function get_interfaces($source,$vsys,$template,$config_path){
    global $projectdb;

    $mcafee_config_file=file($config_path);

    #Create a VR
    $getVR=$projectdb->query("SELECT id FROM virtual_routers WHERE template='$template';");
    if ($getVR->num_rows==0){
        $projectdb->query("INSERT INTO virtual_routers (name,source,template,vsys) VALUES ('mcafee-vr','$source','$template','$vsys');");
        $vr_id=$projectdb->insert_id;
    }
    elseif ($getVR->num_rows==1){
        $getVRData=$getVR->fetch_assoc();
        $vr_id=$getVRData['id'];
    }
    $addZone=array();
    $addInterface=array();
    $addRoutes=array();
    $routes=1;
    foreach ($mcafee_config_file as $line2 => $names_line2){

        if ( (preg_match("/^interface add entrytype=interface/i",$names_line2)) OR (preg_match("/^interface add entrytype=vlan/i",$names_line2)) ){

            $data=preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line2, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);

            $name="";$mask="";$ipaddress="";$unitipaddress="";$unittag=0;

            foreach ($data as $key=>$option) {
                $option=str_replace("'","",$option);
                if (preg_match("/^name=/",$option)){
                    $name_tmp=explode("=",$option);
                    $name=normalizeNames($name_tmp[1]);
                }
                elseif (preg_match("/^burb=/",$option)){
                    $zone_tmp=explode("=",$option);
                    $zoneName=normalizeNames($zone_tmp[1]);
                    $addZone[]="('$source','$template','$vsys','$zoneName','layer3','$name')";
                }
                elseif (preg_match("/^zone=/",$option)){
                    $zone_tmp=explode("=",$option);
                    $zoneName=normalizeNames($zone_tmp[1]);
                    $addZone[]="('$source','$template','$vsys','$zoneName','layer3','$name')";
                }
                elseif (preg_match("/^ipaddr=/",$option)){
                    $ipaddr_tmp=explode("=",$option);
                    $ipaddress=$ipaddr_tmp[1];
                }
                elseif (preg_match("/^mask=/",$option)){
                    $mask_tmp=explode("=",$option);
                    $mask=$mask_tmp[1];
                }
                elseif (preg_match("/^vlan_id=/",$option)){
                    $vlan_tmp=explode("=",$option);
                    $unittag=$vlan_tmp[1];
                }
                elseif (preg_match("/^addresses=/",$option)){
                    $ipaddr_tmp=explode("=",$option);
                    $unitipaddress=$ipaddr_tmp[1];
                }


                if (($ipaddress!="") AND ($mask!="")){
                    $mask1=mask2cidrv4($mask);
                    $unitipaddress=$ipaddress."/".$mask1;
                }
            }
            if ($unittag!=0){
                $unitName=$name.".".$unittag;
            }
            else{
                $unitName=$name;
            }
            $addInterface[]="('$name','layer3','ethernet','$source','$template','$vsys','$vr_id','$unitipaddress','$unitName','$zoneName','$unittag')";





        }
        elseif  ( (preg_match("/^route add route=/i",$names_line2)) OR (preg_match("/^static add route=/i",$names_line2))){

            $data=preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line2, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);

            $routeName="Route ".$routes;$mask="";$destination="";$network="";$metric="1";$ip_version="v4";

            foreach ($data as $key=>$option) {
                $option=str_replace("'","",$option);
                if (preg_match("/^gateway=/",$option)){
                    $gateway_tmp=explode("=",$option);
                    $gateway=$gateway_tmp[1];
                    $ip_version=ip_version($gateway);
                }
                elseif (preg_match("/^route=/",$option)){
                    $route_tmp=explode("=",$option);
                    if ($route_tmp[1] == "default"){
                        $routeName="default";
                        $destination="0.0.0.0/0";
                    }
                    else{
                        $network_netmask=explode("/",$route_tmp[1]);
                        $network=$network_netmask[0];
                        $mask=mask2cidrv4($network_netmask[1]);
                        $destination=$network."/".$mask;
                    }
                    $routes++;
                }
            }
            $addRoutes[]="('','$source','$vr_id','$template','$ip_version','$routeName','$destination','','ip-address','$gateway','$metric','$vsys')";
        }

    }

    if (count($addZone)>0){
        $projectdb->query("INSERT INTO zones (source,template,vsys,name,type,interfaces) VALUES ".implode(",",$addZone).";");
        unset($addZone);
    }
    if (count($addInterface)>0){
        $projectdb->query("INSERT INTO interfaces (name,type,media,source,template,vsys,vr_id,unitipaddress,unitname,zone,unittag) VALUES ".implode(",",$addInterface).";");
        unset($addInterface);
    }
    if (count($addRoutes)>0){
        $projectdb->query("INSERT INTO routes_static (zone,source,vr_id,template,ip_version,name,destination,tointerface,nexthop,nexthop_value,metric,vsys) VALUES ".implode(",",$addRoutes).";");
        unset($addRoutes);
    }
}

function get_address_SIDEWINDER($source,$vsys,$template,$config_path)
{
    global $projectdb;

    $mcafee_config_file = file($config_path);

    $addAddress = array();

    foreach ($mcafee_config_file as $line2 => $names_line2) {

        if (preg_match("/^ipaddr add/i", $names_line2)) {
            preg_match_all('`(\w+(=(([0-9+|\w+][\.|/|,|:|-]?)+|[\'|"].*?[\'|"]))?)`', $names_line2, $matches);
            $name = "";
            $ipaddr = "";
            $description = "";
            $name_int = "";
            $addr_type = "ip-netmask";
            $cidr = 32;

            foreach ($matches[0] as $key => $option) {
                $option=str_replace("'","",$option);
                if (preg_match("/^name=/", $option)) {
                    $name_tmp = explode("=", $option);
                    $name_int = truncate_names(normalizeNames($name_tmp[1]));
                    $name = $name_int;

                } elseif (preg_match("/^ipaddr=/", $option)) {
                    $ipaddr_tmp = explode("=", $option);
                    $ipaddr = $ipaddr_tmp[1];
                    $ip_version = ip_version($ipaddr);
                    if ($ip_version=="noip"){$ip_version="v4";}
                } elseif (preg_match("/^description=/", $option)) {
                    $ipaddr_tmp = explode("=", $option);
                    $description = normalizeComments($ipaddr_tmp[1]);

                }

            }
            $addAddress[] = "('$name','$name_int',0,'$source','$vsys','$addr_type',1,'$ipaddr','$cidr','$description')";
        }
        elseif (preg_match("/^host add/i", $names_line2)) {

            preg_match_all('`(\w+(=(([0-9+|\w+][\.|/|,|:|-]?)+|[\'|"].*?[\'|"]))?)`', $names_line2, $matches);
            $name = "";
            $ipaddr = "";
            $description = "";
            $name_int = "";
            $addr_type = "ip-netmask";
            $dnsmode = "";
            $hostname = "";
            $ipaddress = "";
            $cidr = "32";
            $ip_version = "v4";

            foreach ($matches[0] as $key => $option) {
                $option=str_replace("'","",$option);
                if (preg_match("/^name=/", $option)) {
                    $name_tmp = explode("=", $option);
                    $name = $name_tmp[1];
                    $name_int = truncate_names(normalizeNames($name_tmp[1]));
                } elseif (preg_match("/^ipaddr=/", $option)) {
                    $ipaddr_tmp = explode("=", $option);
                    $ipaddr = $ipaddr_tmp[1];
                    $ip_version = ip_version($ipaddr);
                    if ($ip_version=="noip"){$ip_version="v4";}
                    $cidr = 32;
                } elseif (preg_match("/^description=/", $option)) {
                    $ipaddr_tmp = explode("=", $option);
                    $description = normalizeComments($ipaddr_tmp[1]);

                } elseif (preg_match("/^dns_mode=/", $option)) {
                    $ipaddr_tmp = explode("=", $option);
                    $dnsmode = $ipaddr_tmp[1];
                } elseif (preg_match("/^host=/", $option)) {
                    $ipaddr_tmp = explode("=", $option);
                    $hostname = $ipaddr_tmp[1];
                } elseif (preg_match("/^ipaddrs=/", $option)) {
                    $ipaddr_tmp = explode("=", $option);
                    $ipaddress = $ipaddr_tmp[1];
                    $ip_version = ip_version($ipaddress);
                    if ($ip_version=="noip"){$ip_version="v4";}
                }

            }
            if ( (($dnsmode == "dns") OR ($dnsmode == "dns_manual_ttl")) AND ($ipaddress == "")) {
                $addr_type = "fqdn";
                $ipaddress = $hostname;
                $cidr = "";
            }
            $addAddress[] = "('$name','$name_int',0,'$source','$vsys','$addr_type',1,'$ipaddress','$cidr','$description')";
        }
        elseif (preg_match("/^iprange add/i", $names_line2)) {

            preg_match_all('`(\w+(=(([0-9+|\w+][\.|/|,|:|-]?)+|[\'|"].*?[\'|"]))?)`', $names_line2, $matches);

            $name = "";
            $ipaddr = "";
            $description = "";
            $name_int = "";
            $cidr = "";
            $addr_type = "ip-range";
            $begin = "";
            $end = "";

            foreach ($matches[0] as $key => $option) {
                $option=str_replace("'","",$option);
                if (preg_match("/^name=/", $option)) {
                    $name_tmp = explode("=", $option);
                    $name_int = truncate_names(normalizeNames($name_tmp[1]));
                    $name = $name_int;
                } elseif (preg_match("/^begin=/", $option)) {
                    $ipaddr_tmp = explode("=", $option);
                    $begin = $ipaddr_tmp[1];
                    $ip_version = ip_version($begin);
                    if ($ip_version=="noip"){$ip_version="v4";}
                } elseif (preg_match("/^end=/", $option)) {
                    $ipaddr_tmp = explode("=", $option);
                    $end = $ipaddr_tmp[1];
                } elseif (preg_match("/^description=/", $option)) {
                    $ipaddr_tmp = explode("=", $option);
                    $description = normalizeComments($ipaddr_tmp[1]);
                }

            }
            $ipaddr = $begin . "-" . $end;
            $addAddress[] = "('$name','$name_int',0,'$source','$vsys','$addr_type',1,'$ipaddr','$cidr','$description')";
        }
        elseif (preg_match("/^subnet add/i", $names_line2)) {

            preg_match_all('`(\w+(=(([0-9+|\w+][\.|/|,|:|-]?)+|[\'|"].*?[\'|"]))?)`', $names_line2, $matches);

            $name = "";
            $ipaddr = "";
            $description = "";
            $name_int = "";
            $cidr = "";
            $addr_type = "ip-netmask";
            $begin = "";
            $end = "";

            foreach ($matches[0] as $key => $option) {
                $option=str_replace("'","",$option);
                if (preg_match("/^name=/", $option)) {
                    $name_tmp = explode("=", $option);
                    $name_int = truncate_names(normalizeNames($name_tmp[1]));
                    $name = $name_int;
                } elseif (preg_match("/^subnet=/", $option)) {
                    $ipaddr_tmp = explode("=", $option);
                    $begin = $ipaddr_tmp[1];
                    $ip_version = ip_version($begin);
                    if ($ip_version=="noip"){$ip_version="v4";}
                } elseif (preg_match("/^bits=/", $option)) {
                    $ipaddr_tmp = explode("=", $option);
                    $end = $ipaddr_tmp[1];
                } elseif (preg_match("/^description=/", $option)) {
                    $ipaddr_tmp = explode("=", $option);
                    $description = normalizeComments($ipaddr_tmp[1]);
                }

            }
            $addAddress[] = "('$name','$name_int',0,'$source','$vsys','$addr_type',1,'$begin','$end','$description')";
        }
    }
    if (count($addAddress) > 0) {
        $projectdb->query("INSERT INTO address (name_ext,name,checkit,source,vsys,type,$ip_version,ipaddress,cidr,description) VALUES " . implode(",", $addAddress) . ";");
        #print "INSERT INTO address (name_ext,name,checkit,source,vsys,type,$ip_version,ipaddress,cidr,description) VALUES " . implode(",", $addAddress) . ";";
    }

}

/**
 * @param $source
 * @param $vsys
 * @param $template
 * @param $config_path
 */
function get_addressGroups($source, $vsys, $template, $config_path)
{
    global $projectdb;

    $mcafee_config_file = file($config_path);

    $addAddress = array();
    $addNewAddress = array();
    $addGroup=array();

    $getMaxid=$projectdb->query("SELECT max(id) as maxid FROM address_groups_id;");
    if ($getMaxid->num_rows>0){
        $getMaxidData=$getMaxid->fetch_assoc();
        $grplid=$getMaxidData['maxid']+1;
    }
    else{
        $grplid=1;
    }

    foreach ($mcafee_config_file as $line2 => $names_line2) {

        if (preg_match("/^netgroup add/i", $names_line2)) {
            try {
                $matches = preg_split("/'[^']*'(*SKIP)(*F)|\x20/", $names_line2);
                $name = "";
                $ipaddr = "";
                $description = "";
                $name_int = "";
                $addr_type = "ip-netmask";
                $cidr = 32;

                foreach ($matches as $key => $option) {
                    $option=str_replace("'","",$option);
                    if (preg_match("/^name=/", $option)) {
                        $name_tmp = explode("=", $option);
                        $name_int = truncate_names(normalizeNames($name_tmp[1]));
                        $name = $name_int;
                    }
                    elseif (preg_match("/^members=/", $option)) {
                        $option=str_replace("'","",$option);
                        $ipaddr_tmp = explode("=", $option);
                        $members = explode(",",$ipaddr_tmp[1]);
                        if (count($members)>0){
                            foreach ($members as $keyy=>$vvalue){
                                $members2=explode(":",$vvalue);
                                $kkkey=$members2[0];
                                if(!isset($members2[1])){
                                    continue;
                                }
                                $vvvalue=$members2[1];
                                if ($kkkey == "ipaddr") {
                                    $ipversion=ip_version($vvvalue);
                                    if (($ipversion=="v4") or ($ipversion=="v6")) {
                                        $getAddr = $projectdb->query("SELECT name FROM address WHERE ipaddress='$vvvalue' AND source='$source' AND vsys='$vsys' LIMIT 1;");
                                        if ($getAddr->num_rows == 1) {
                                            $getAddrData = $getAddr->fetch_assoc();
                                            $vvvalue = $getAddrData['name'];
                                            $addAddress[] = "('$grplid','$vvvalue','$source','$vsys')";
                                        } else {
                                            $name1 = "H-" . $vvvalue;
                                            $addNewAddress[] = "('$name1','$name1',0,'$source','$vsys','ip-netmask',1,'$vvvalue','32')";
                                            $addAddress[] = "('$grplid','$name1','$source','$vsys')";
                                        }
                                    }
                                    else {
                                        $getAddr = $projectdb->query("SELECT name FROM address WHERE name='$vvvalue' AND source='$source' AND vsys='$vsys' LIMIT 1;");
                                        if ($getAddr->num_rows == 1) {
                                            $addAddress[] = "('$grplid','$vvvalue','$source','$vsys')";
                                        }
                                    }
                                }
                                elseif ($kkkey == "host"){
                                    $getAddr = $projectdb->query("SELECT name FROM address WHERE name='$vvvalue' AND source='$source' AND vsys='$vsys' LIMIT 1;");
                                    if ($getAddr->num_rows == 1) {
                                        $addAddress[] = "('$grplid','$vvvalue','$source','$vsys')";
                                    }
                                    else{
                                        $hip_version=ip_version($vvvalue);
                                        if ($hip_version=="noip"){
                                            $name1=truncate_names(normalizeNames($vvvalue));
                                            $addNewAddress[] = "('$name1','$name1',0,'$source','$vsys','fqdn',1,'$vvvalue','')";
                                            $addAddress[] = "('$grplid','$name1','$source','$vsys')";
                                        }
                                        else{
                                            $name1=$vvvalue;
                                            if ($hip_version=="v4"){$hcidr="32";}else{$hcidr="128";}
                                            $addNewAddress[] = "('$name1','$name1',0,'$source','$vsys','ip-netmask',1,'$vvvalue','$hcidr')";
                                            $addAddress[] = "('$grplid','$name1','$source','$vsys')";
                                        }

                                    }
                                }
                                elseif ($kkkey == "geolocation") {

                                }
                                elseif ($kkkey == "domain") {

                                }
                                else {
                                    //echo $vvvalue . "-" .$kkkey."\n";
                                    $addAddress[] = "('$grplid','$vvvalue','$source','$vsys')";
                                }
                            }
                        }

                    }
                    elseif (preg_match("/^description=/", $option)) {
                        $ipaddr_tmp = explode("=", $option);
                        $description = normalizeComments($ipaddr_tmp[1]);
                    }
                }
                $addGroup[]="('$grplid','$name','$name_int','$source','$vsys','$description')";
                $grplid++;
            } catch (Exception $e) {
                echo "Caught exception when reading address Groups: $matches \n";
            }

        }

    }
    if (count($addGroup)>0){
        $projectdb->query("INSERT INTO address_groups_id (id,name_ext,name,source,vsys,description) VALUES ".implode(",",$addGroup).";");
        if (count($addAddress) > 0) {
            $projectdb->query("INSERT INTO address_groups (lid,member,source,vsys) VALUES " . implode(",", $addAddress) . ";");
        }
        if (count($addNewAddress) > 0) {
            $unique=array_unique($addNewAddress);
            $projectdb->query("INSERT INTO address (name_ext,name,checkit,source,vsys,type,v4,ipaddress,cidr) VALUES " . implode(",", $unique) . ";");
        }
        unset($addGroup);unset($addAddress);unset($addNewAddress);
    }

}

function get_services($source,$vsys,$template,$config_path)
{
    global $projectdb;

    $mcafee_config_file = file($config_path);

    $addAddress = array();

    $getMaxid=$projectdb->query("SELECT max(id) as maxid FROM services_groups_id;");
    if ($getMaxid->num_rows>0){
        $getMaxidData=$getMaxid->fetch_assoc();
        $grplid=$getMaxidData['maxid']+1;
    }
    else{
        $grplid=1;
    }

    foreach ($mcafee_config_file as $line2 => $names_line2) {

        if ( (preg_match("/^service modify /i", $names_line2)) OR (preg_match("/^service add /i", $names_line2)) OR (preg_match("/^application modify /i", $names_line2)) OR (preg_match("/^application add /i", $names_line2))){

            preg_match_all('`(\w+(=(([0-9+|\w+][\.|/|,|:|-]?)+|[\'|"].*?[\'|"]))?)`', $names_line2, $matches);

            $name = "";
            $tcp_ports = "";
            $description = "";
            $name_int = "";
            $udp_ports = "";
            $protocol="";
            $port="";

            foreach ($matches[0] as $key => $option) {
                $option=str_replace("'","",$option);

                if (preg_match("/^name=/", $option)) {
                    $name_tmp = explode("=", $option);
                    $name_int = truncate_names(normalizeNames($name_tmp[1]));
                    $name = $name_int;

                }
                elseif (preg_match("/^udp_ports=/", $option)) {
                    $ipaddr_tmp = explode("=", $option);
                    if ($ipaddr_tmp[1]!=""){
                        $udp_ports = $ipaddr_tmp[1];
                        $protocol="udp";
                        $port=$udp_ports;
                    }

                }
                elseif (preg_match("/^tcp_ports=/", $option)) {
                    $ipaddr_tmp = explode("=", $option);
                    if ($ipaddr_tmp[1]!=""){
                        $tcp_ports = $ipaddr_tmp[1];
                        $protocol="tcp";
                        $port=$tcp_ports;
                    }
                }
                elseif (preg_match("/^protocol=/", $option)) {
                    $ipaddr_tmp = explode("=", $option);
                    $protocol = $ipaddr_tmp[1];
                    $port="";
                    $port=$tcp_ports;
                }
                elseif (preg_match("/^description=/", $option)) {
                    $ipaddr_tmp = explode("=", $option);
                    $description = normalizeComments($ipaddr_tmp[1]);
                }

            }

            if (($udp_ports!="") AND ($tcp_ports!="")){
                # Convert into Group
                $addGroup[]="('$grplid','$name','$name_int','$source','$vsys','$description')";
                $newname=truncate_names("tcp-".$name);
                $addMember[]="('$grplid','$newname','$source','$vsys')";
                $addAddress[] = "('$newname','$newname',0,'$source','$vsys','tcp','$tcp_ports','$description')";
                $newname=truncate_names("udp-".$name);
                $addMember[]="('$grplid','$newname','$source','$vsys')";
                $addAddress[] = "('$newname','$newname',0,'$source','$vsys','udp','$udp_ports','$description')";
                $grplid++;
            }
            else{
                $addAddress[] = "('$name','$name_int',0,'$source','$vsys','$protocol','$port','$description')";
            }


        }
    }
    if (count($addAddress) > 0) {
        $projectdb->query("INSERT INTO services (name_ext,name,checkit,source,vsys,protocol,dport,description) VALUES " . implode(",", $addAddress) . ";");
    }
    if (count($addGroup)>0){
        $projectdb->query("INSERT INTO services_groups_id (id,name_ext,name,source,vsys,description) VALUES ".implode(",",$addGroup).";");
        if (count($addMember) > 0) {
            $projectdb->query("INSERT INTO services_groups (lid,member,source,vsys) VALUES " . implode(",", $addMember) . ";");
        }
        unset($addAddress);unset($addGroup);unset($addMember);
    }

}

function get_servicesGroups($source,$vsys,$template,$config_path)
{
    global $projectdb;

    $mcafee_config_file = file($config_path);

    $addAddress = array();
    $addNewAddress = array();
    $addGroup=array();

    $getMaxid=$projectdb->query("SELECT max(id) as maxid FROM services_groups_id;");
    if ($getMaxid->num_rows>0){
        $getMaxidData=$getMaxid->fetch_assoc();
        $grplid=$getMaxidData['maxid']+1;
    }
    else{
        $grplid=1;
    }

    foreach ($mcafee_config_file as $line2 => $names_line2) {

        if ((preg_match("/^servicegroup add/i", $names_line2)) OR (preg_match("/^appgroup add/i", $names_line2))) {

            preg_match_all('`(\w+(=(([0-9+|\w+][\.|/|,|:|-]?)+|[\'|"].*?[\'|"]))?)`', $names_line2, $matches);

            $name = "";
            $description = "";
            $name_int = "";

            foreach ($matches[0] as $key => $option) {
                $option=str_replace("'","",$option);
                if (preg_match("/^name=/", $option)) {
                    $name_tmp = explode("=", $option);
                    $name_int = truncate_names(normalizeNames($name_tmp[1]));
                    $name = $name_int;

                } elseif (preg_match("/^members=/", $option)) {
                    //$option=str_replace("'","",$option);
                    $ipaddr_tmp = explode("=", $option);
                    $members = explode(",",$ipaddr_tmp[1]);
                    foreach ($members as $keyy=>$vvalue){

                        $vvalue=str_replace("application:","",$vvalue);
                        $vvalue=str_replace("custom:","",$vvalue);

                        $addAddress[] = "('$grplid','$vvalue','$source','$vsys')";
                    }
                } elseif (preg_match("/^description=/", $option)) {
                    $ipaddr_tmp = explode("=", $option);
                    $description = normalizeComments($ipaddr_tmp[1]);

                }

            }
            $addGroup[]="('$grplid','$name','$name_int','$source','$vsys','$description')";
            $grplid++;

        }
    }

    if (count($addGroup)>0){
        $projectdb->query("INSERT INTO services_groups_id (id,name_ext,name,source,vsys,description) VALUES ".implode(",",$addGroup).";");
        if (count($addAddress) > 0) {
            $projectdb->query("INSERT INTO services_groups (lid,member,source,vsys) VALUES " . implode(",", $addAddress) . ";");
        }
        unset($addGroup);unset($addAddress);
    }

}

?>