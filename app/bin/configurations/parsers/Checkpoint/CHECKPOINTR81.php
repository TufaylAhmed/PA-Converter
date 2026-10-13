<?php
# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.

//Loads all global PHP definitions
require_once '/var/www/html/libs/common/definitions.php';

//Dependencies
require_once INC_ROOT.'/libs/database.php';
require_once INC_ROOT.'/libs/shared.php';
require_once INC_ROOT.'/libs/common/lib-rules.php';
require_once INC_ROOT.'/libs/common/MemberObject.php';
require_once INC_ROOT.'/libs/projectdb.php';
require_once INC_ROOT.'/libs/objects/SecurityRulePANObject.php';

//Dependencies
require_once INC_ROOT.'/bin/configurations/parsers/ServicesMapping.php';
use PaloaltoNetworks\Parsers\Utils\ServicesMapping;

use PaloaltoNetworks\Policy\Objects\MemberObject;

# ONLY FOR TESTING REMOVE IT
//$checkpointName="";
//$project="testing2";
//$action="import";
//$jobid=1;
# ##########################

class Schedules{
    public $name;
    public $recurrence;
    public $uid;
    public $startDate;
    public $startTime;
    public $endDate;
    public $endTime;
    public $vsys;
    public $source;

    function __construct()
    {
        $a = func_get_args();
        $i = func_num_args();
        if (method_exists($this,$f='__construct'.$i)) {
            call_user_func_array(array($this,$f),$a);
        }
    }

    public function __construct4($uid,$name,$source,$vsys){
        $this->name = $name;
        $this->uid = $uid;
        $this->source = $source;
        $this->vsys = $vsys;
    }

    public function addDateTime($startEnd,$date,$time){
        switch ($startEnd){
            case "start":
                $this->startDate=$date;
                $this->startTime=$time;
                break;
            case "end":
                $this->endDate=$date;
                $this->endTime=$time;
                break;

            default:

        }
    }

    public function addRecurrence(){

    }

}

global $app;
require_once INC_ROOT.'/userManager/API/accessControl_CLI.php';
include INC_ROOT.'/bin/configurations/parsers/readVars.php';
global $projectdb;
global $conn;

// Validations
if(!accessControl("any", ['project.admin', 'projectRole.'.$project.'.admin'])){
    http_response_code(401);
    header("HTTP/1.1 401 Unauthorized");
    header("Location: /401");
    exit;
}


$projectdb = selectDatabase($project);

$sourcesAdded = array();
global $source;

if($noDNAT=="1"){
    $skipDNAT=true;
}
else{
    $skipDNAT=false;
}

if ($action=="import") {
    ini_set('max_execution_time', PARSER_max_execution_time);
    ini_set("memory_limit", PARSER_max_execution_memory);

    update_progress($project, '0.00', 'Reading config files', $jobid);

    $index = USERSPACE_PATH . "/projects/" . $project . "/security/index.json";
    $policiesList = read_index($project, $index);

    $processNatRules = false;

    $domain = "";
    if(isset($policiesList['domain'])) {
        $domain = $policiesList['domain'];
    }
    if ($policiesList['code'] == true) {
        if ($policiesList['objects'] != "") {
            $myObjects = load_policy($policiesList['objects'], $project, $jobid);

            #Check if is the first vsys
            if ($checkpointName == "") { //We get the name of the first defined AccessLayer as the project Name
                if (isset($policiesList['accessLayers'][0]) && $policiesList['accessLayers'][0]['name'] != "") {
                    $filename = $policiesList['accessLayers'][0]['name'];
                }
//               if ($policiesList['accessLayerName']!=""){
//                    $filename=$policiesList['accessLayerName'];
//                }
                else {
                    $filename = unique_id(10);
                }

            } else {
                $filename = $checkpointName;
            }

            if(!isset($conn)) {
                $conn = get_pdo($project);
            }
            $stmt = $conn->prepare("SELECT id,vsys FROM device_mapping WHERE filename= :filename");
            $stmt->bindParam(":filename", $filename);
            $stmt->execute();
            $getVsys = $stmt->fetchAll(PDO::FETCH_ASSOC);

            //$getVsys = $projectdb->query("SELECT id,vsys FROM device_mapping WHERE filename='$filename';");
            if (count($getVsys) == 0) {
                //The objects will go to the:
                //   vsys=shared if there is more than 1 security policy
                //   vsys=name if there is only one accessLayer security policy
                $vsys = "shared";
                if (count($policiesList['accessLayers']) == 1) {

                    $vsys = normalizeNamesNew($policiesList['accessLayers']['0']['name'], "", "vsys");
                }
                //$projectdb->query("INSERT INTO device_mapping (device,version,ispanorama,active,project,filename,vsys,vendor) VALUES ('$filename','',0,1,'$project','$filename','$vsys','Checkpoint')");
                //$source = $projectdb->insert_id;
                if(!isset($conn)) {
                    $conn = get_pdo($project);
                }
                $stmt = $conn->prepare("INSERT INTO device_mapping (device,version,ispanorama,active,project,filename,vsys,vendor) VALUES (?,'',0,1,?,?,?,'Checkpoint')");
                $stmt->bindParam(1, $filename);
                $stmt->bindParam(2, $project);
                $stmt->bindParam(3, $filename);
                $stmt->bindParam(4, $vsys);
                $stmt->execute();
                $source =  $conn->lastInsertId();

                $sourcesAdded[] = $source;
            } else {
                echo "FILENAME $filename ALREADY IMPORTED. SKIPPING" . PHP_EOL;
                update_progress($project, '-1', 'configuration already imported. Skipping', $jobid);
                exit(0);
            }

            if(!isset($conn)) {
                $conn = get_pdo($project);
            }
            $stmt = $conn->prepare("SELECT filename FROM device_mapping WHERE id= :source;");
            $stmt->bindParam(":source", $source);
            $stmt->execute();
            $getFileName = $stmt->fetchAll(PDO::FETCH_ASSOC);
            $filename = $getFileName[0]['filename'];

            #Config Template
            //$getTemplate = $projectdb->query("SELECT id FROM templates_mapping WHERE filename='$filename';");
            $template_name = $filename . "_template";
            //$projectdb->query("INSERT INTO templates_mapping (project,name,filename,source) VALUES ('$project','$template_name','$filename','$source');");
            //$template = $projectdb->insert_id;

            if(!isset($conn)) {
                $conn = get_pdo($project);
            }
            $stmt = $conn->prepare("INSERT INTO templates_mapping (project,name,filename,source) VALUES (?,?,?,?)");
            $stmt->bindParam(1, $project);
            $stmt->bindParam(2, $template_name);
            $stmt->bindParam(3, $filename);
            $stmt->bindParam(4, $source);
            $stmt->execute();
            $template =  $conn->lastInsertId();

            // Add predefined services and services groups
            ServicesMapping::addPredefinedSrvAndSrvGroups($projectdb, "checkpoint", $source, $vsys);

            #Explode Members
            update_progress($project, '0.10', 'Phase 1 of 10 -  Reading Objects', $jobid);

            $myObjectsAll = explodeGroups2MembersCheckpoint($myObjects, 0);
            $getObjects = get_objects($myObjectsAll, $source, $vsys, $filename, $template);

            # Calculate Excluded Groups
            calculateExclusionGroups($source,$getObjects);

        }

//        if ($policiesList['accessLayers']!=""){
//
//            $myRules=load_policy($policiesList['accessLayers'],$project,$jobid);
//            # Read Security Rules
//            update_progress($project,'0.20','Phase 2 of 10 - Reading Access Policies',$jobid);
//            if (count($myRules)>0){
//                get_security_policies($myRules, $source, $vsys, $filename, $getObjects);
//            }
//        }
        foreach ($policiesList['accessLayers'] as $accessLayer) {
            $myRules = load_policy($accessLayer['htmlFileName'], $project, $jobid);
            $domain = $accessLayer['domain'];

            if (count($policiesList['accessLayers']) == 1) {
                $vsys = normalizeNamesNew($policiesList['accessLayers']['0']['name'], "", "vsys");
            }else{
                if($accessLayer['domainType']=="global domain"){
                    $vsys = "shared";
                }else {
                    $vsys = normalizeNamesNew($accessLayer['domain'] . "-" . $accessLayer['name'], "", "vsys");
                }
            }

            if (($accessLayer['name'] == 'Application')||($accessLayer['name'] =="Application & URL Filtering"))
                $globalDisabled = true;
            else
                $globalDisabled = false;
            $getVsys = $projectdb->query("SELECT id,vsys FROM device_mapping WHERE vsys='$vsys';");
            if ($getVsys->num_rows == 0) {
                //$projectdb->query("INSERT INTO device_mapping (device,version,ispanorama,active,project,filename,vsys,vendor) VALUES ('$filename','',0,1,'$project','$filename','$vsys','Checkpoint')");
                if(!isset($conn)) {
                    $conn = get_pdo($project);
                }
                $stmt = $conn->prepare("INSERT INTO device_mapping (device,version,ispanorama,active,project,filename,vsys,vendor) VALUES (?,'',0,1,?,?,?,'Checkpoint')");
                $stmt->bindParam(1, $filename);
                $stmt->bindParam(2, $project);
                $stmt->bindParam(3, $filename);
                $stmt->bindParam(4, $vsys);
                $stmt->execute();
            }
            # Read Security Rules
            update_progress($project, '0.20', 'Phase 2 of 10 - Reading Access Policies', $jobid);
            if (count($myRules) > 0) {
                get_security_policies($myRules, $source, $vsys, $filename, $getObjects, $skipDNAT, $globalDisabled);
                split_user_security_rules_by_source($source, $vsys, $project);
            }
        }

        #Calculate Layer4-7
        $queryRuleIds = "SELECT id from security_rules WHERE source = $source;";
        $resultRuleIds = $projectdb->query($queryRuleIds);
        if ($resultRuleIds->num_rows > 0) {
            $rules = array();
            while ($dataRuleIds = $resultRuleIds->fetch_assoc()) {
                $rules[] = $dataRuleIds['id'];
            }
            $rulesString = implode(",", $rules);
            $securityRulesMan = new \SecurityRulePANObject();
            $securityRulesMan->updateLayerLevel($projectdb, $rulesString, $source);
        }

        // Get the vsys different from "Application" or "Application & URL Filtering" policy
        if (count($policiesList['accessLayers']) > 1) {
            foreach ($policiesList['accessLayers'] as $accessLayer) {
                if (($accessLayer['name'] != 'Application') && ($accessLayer['name'] != "Application & URL Filtering") && $accessLayer['domainType']!="global domain") {
                    $vsys = normalizeNamesNew($accessLayer['domain'] . "-" . $accessLayer['name'], "", "vsys");
                    break;
                }
            }
        }

        # Import Interfaces and Routes
        get_routes($project, $source, $template, $vsys);

        if (isset($policiesList['natLayer'])) {
            $myNatRules = load_policy($policiesList['natLayer'], $project, $jobid);

            if (count($myNatRules) > 0) {

                $processNatRules = true;
                $rule_number_nat = array();
                $tag_id = "";
                $thecolor=1;
                foreach ($myNatRules as $rulebase) {

                    if (isset ($rulebase['rulebase'])) {
                        get_nat_policies($rulebase['rulebase'], $source, $vsys, $filename, $getObjects, $rule_number_nat, $tag_id, $thecolor);
                    } else {
                        get_nat_policies(array($rulebase), $source, $vsys, $filename, $getObjects, $rule_number_nat, $tag_id, $thecolor);
                    }
                }
            }
        }

        //remap_groupmembers($myObjectsAll);
        update_progress($project, '0.70', 'Phase 7 of 10 - Referencing Address Groups Members', $jobid);
        remap_groupmembers($source, $vsys, $getObjects);

        # Fix DNAT
        $query = "SELECT id FROM virtual_routers WHERE template='$template' AND source='$source';";
        $getVR = $projectdb->query($query);
        if ($getVR->num_rows == 1) {
            $getVRData = $getVR->fetch_assoc();
            $vr_id = $getVRData['id'];

            $ipMapping = array();
            $rules = array();

            if ($processNatRules == true) {
                update_progress($project, '0.80', 'Phase 8 of 10 - Calculating NAT Rules Zones based on Static Routes and Interfaces', $jobid);
                fix_Nat_Policy(-1, $project, $source, $vsys, $vr_id, $ipMapping, $rules, true, true);
                if (!$skipDNAT) {
                    update_progress($project, '0.90', 'Phase 9 of 10 - Calculating Security Rules Zones based on NAT rules, Static Routes and Interfaces', $jobid);
                    recalculate_Dst_basedOn_NAT($projectdb, $source, $vsys, $vr_id, $project, 'CheckpointR80');
                } else {
                    update_progress($project, '0.90', 'Phase 9 of 10 - SKIP Calculating Security Rules Zones based on NAT rules, Static Routes and Interfaces', $jobid);
                }
                remove_duplicated_zones($source, $vsys);
            } else {
                update_progress($project, '0.80', 'Phase 8 of 10 - Calculating NAT Rules Zones based on Static Routes and Interfaces', $jobid);
                #CALCULATE ZONESSS
                //recalculate_Dst_basedOn_NAT2($projectdb, $source, $vsys, $vr_id, $project, 'CheckpointR80');
                recalculate_Dst_basedOn_NAT($projectdb, $source, $vsys, $vr_id, $project, 'CheckpointR80');
                remove_duplicated_zones($source, $vsys);
            }

//                set_Zones_Security_Rules($source, $vsys, $vr_id, $ipMapping);
//                fix_Zones_Policies($project, $source, $vsys,$vr_id);
        }

        //Copy warnings from objects into security rules
        clone_warnings_to_sec_rules($source,$vsys);

        // Auto split the address groups based on defined PARSER_max_number_address_per_group
        // for upgraded installations that does not have the variable in the /home/userSpace/userDefinition.php defined
        if (!defined('PARSER_max_number_address_per_group')) {
            define('PARSER_max_number_address_per_group', -1);
        }
        if(PARSER_max_number_address_per_group!=-1) {
            update_progress($project, '0.90', 'Phase 9 of 10 - Split the address group members using as a limit defined value of '. PARSER_max_number_address_per_group . ' members', $jobid);
            splitMembersOnGroups();
        }
        update_progress($project, '0.95', 'Phase 10 of 10 - Checking Used and Unused Objects', $jobid);
        check_used_objects_new();

        update_progress($project, '1.0', 'Done', $jobid);

        //Delete the security folder and its content
        $path = USERSPACE_PATH."/projects/".$project."/security";
        clean_files($path);
    } else {
        # No Index file
        echo "NO INDEX FILE FOUND" . PHP_EOL;
        update_progress($project, '-1', 'NO INDEX FILE FOUND', $jobid);
        exit(0);
    }

}


class NatRule {
    public $name;
    public $position;
    public $id;
    public $disabled=0;
    public $preorpost=0;
    public $checkit=0;
    public $comments="";
    public $source;
    public $vsys;
    public $op_service_lid=0;
    public $op_service_table=0;
    public $method="None";
    public $op_zone_to="";
    public $op_to_interface="any";
    public $is_dat=0;
    public $tp_sat_interface;
    public $tp_sat_ipaddress;
    public $tp_sat_bidirectional=0;
    public $tp_fallback_type="None";
    public $tp_sat_interface_fallback;
    public $tp_sat_ipaddress_fallback;
    public $tp_dat_port;
    public $tp_dat_address_lid=0;
    public $tp_dat_address_table;
    public $tp_sat_type="None";
    public $tp_sat_address_type="";
    public $target="";

    function __construct()
    {
        $a = func_get_args();
        $i = func_num_args();
        if (method_exists($this,$f='__construct'.$i)) {
            call_user_func_array(array($this,$f),$a);
        }
    }

    public function __construct9($lid,$position,$preorpost,$checkit,$ruleName,$comments,$rule_enabled,$source,$vsys){
        $this->name = $ruleName;
        $this->id = $lid;
        $this->position = $position;
        $this->preorpost = $preorpost;
        $this->checkit = $checkit;
        $this->comments = $comments;
        $this->disabled = $rule_enabled;
        $this->source = $source;
        $this->vsys = $vsys;
    }

    public function addOPService($member_lid,$table_name){
        $this->op_service_lid=$member_lid;
        $this->op_service_table=$table_name;
    }

    public function addDat($member_lid,$table_name){
        $this->is_dat=1;
        $this->tp_dat_address_lid=$member_lid;
        $this->tp_dat_address_table=$table_name;
    }

    public function addMethod($method){
        $this->method = $method;
        if ($method=="dynamic-ip-and-port"){
            $this->tp_sat_type="dynamic-ip-and-port";
            $this->tp_sat_address_type="translated-address";
        }
        elseif ($method=="static-ip"){
            $this->tp_sat_type="static-ip";
            $this->tp_sat_address_type="translated-address";
            $this->tp_sat_bidirectional=0;
        }
    }
    public function setDisabled($disabled){
        $this->disabled=$disabled;
    }
    public function printObject() {
        var_dump(get_object_vars($this));
    }
    public function addTPService($port){
        if (intval($port)>0){$this->tp_dat_port=$port;}
    }
    public function getSQL(){
        $sql="('$this->id','$this->name','$this->position','$this->comments','$this->disabled','$this->source','$this->vsys','$this->preorpost','$this->checkit'," .
            "'$this->op_service_lid','$this->op_service_table', '$this->is_dat', '$this->tp_dat_address_lid' , '$this->tp_dat_address_table', '$this->tp_dat_port', '$this->tp_sat_type','$this->tp_sat_address_type','$this->target')";

        return $sql;
    }

    public function addTarget($target){
        $this->target = $target;

    }
}

function clone_warnings_to_sec_rules($source,$vsys){
    global $projectdb;
    $sql = [];

    $query = "  SELECT l.level, l.task, l.message, l.action, s.rule_lid FROM security_rules_dst s, logs l
                where s.member_lid = l.obj_id
                and s.table_name = l.obj_table
                and s.source = l.source
                and s.source = $source
                and s.vsys = '$vsys'
                AND UPPER(l.action) NOT LIKE '%NO ACTION REQUIRED%'
                UNION
                SELECT l.level, l.task, l.message, l.action, s.rule_lid FROM security_rules_src s, logs l
                where s.member_lid = l.obj_id
                and s.table_name = l.obj_table
                and s.source = l.source
                and s.source = $source
                and s.vsys = '$vsys'
                AND UPPER(l.action) NOT LIKE '%NO ACTION REQUIRED%'
                UNION
                SELECT l.level, l.task, l.message, l.action, s.rule_lid FROM security_rules_srv s, logs l
                where s.member_lid = l.obj_id
                and s.table_name = l.obj_table
                and s.source = l.source
                and s.source = $source
                and s.vsys = '$vsys'
                AND UPPER(l.action) NOT LIKE '%NO ACTION REQUIRED%' ";

    $getWarnings = $projectdb->query($query);

    if ($getWarnings->num_rows > 0) {
        while($getWarningsData = $getWarnings->fetch_assoc()) {
            $rule_lid = $getWarningsData['rule_lid'];
            $level = $getWarningsData['level'];
            $task = $getWarningsData['task'];
            $message = $getWarningsData['message'];
            $action = $getWarningsData['action'];

            $sql[] = "(NOW(), '$source', '$level', '$task', 'Sec Rule [$rule_lid] affected by: $message', '$action', 'rules', '$rule_lid', 'security_rules' )";
        }
    }

    $query = "INSERT into logs (datetime, source, level, task, message, action, obj_type, obj_id, obj_table) VALUES ". implode(",", $sql) .";";
    $projectdb->query($query);

}

function clean_files($path){

    if (file_exists($path)) {
        $files = array_diff(scandir($path), array('.', '..'));
        foreach ($files as $file) {
            if (is_dir($path. "/" .$file) && !is_link($path."/".$file)) {
                clean_files($path . "/" . $file);
            } else {
                unlink($path . "/" . $file);
            }
        }
        return rmdir($path);
    } else {
        return false;
    }
}

function get_nat_policies(ARRAY $myRules, $source, $vsys, $filename, &$objects, &$rule_number_nat, &$tag_id, &$thecolor){
    global $projectdb;

    $any=$objects['common']["any"];
    $original=$objects['common']["Original"];
    #Get Last lid from Rules
    $getlastlid=$projectdb->query("SELECT max(id) as max FROM nat_rules;");
    $getLID1=$getlastlid->fetch_assoc();
    $lid=intval($getLID1['max'])+1;
    $getlastlid=$projectdb->query("SELECT max(position) as max FROM nat_rules WHERE source='$source' AND vsys='$vsys';");
    $getLID1=$getlastlid->fetch_assoc();
    $position=intval($getLID1['max'])+1;

    $natRule=[];
    $rule_source=[];
    $rule_destination=[];
    $add_tag=[];
    $translated_address=[];
    foreach($myRules as $ruleSection){
        // if (isset($ruleSection['name'])){$name=$ruleSection['name'];}else{$name="Rule ";}

        //echo "DENTRO DEL FOREACH DE LA FUNCION \n";
        //print_r($ruleSection);
        if(isset ($ruleSection['rule-number'])){
            if(in_array($ruleSection['rule-number'], $rule_number_nat)){
                continue;
            }else{
                $rule_number_nat[] = $ruleSection['rule-number'];
            }
        }
        //echo ":::::::::::ARRAY DE LOS NUMBER RULE: ::::::::::::\n";
        //print_r($rule_number_nat);

        $type = $ruleSection['type'];

        switch($type){
            case "nat-section":
                if ((isset($ruleSection['rulebase'])) AND (count($ruleSection['rulebase'])>0)) {
                    $name=normalizeNames($ruleSection['name']);
                    $color = "color" . $thecolor;
                    $tag_id = add_tag($name, $source, $vsys, $color);
                    if ($thecolor == 16) {
                        $thecolor = 1;
                    }
                    else {
                        $thecolor++;
                    }
                    foreach ($ruleSection['rulebase'] as $rule){

                        if ($rule['type']=="nat-rule"){

                            $preorpost=1;
                            $checkit=0;

                            if(isset ($rule['rule-number'])){
                                if(in_array($rule['rule-number'], $rule_number_nat)){
                                    continue;
                                }else{
                                    $rule_number_nat[] = $rule['rule-number'];
                                }
                            }

                            $ruleNumber = $rule['rule-number'];
                            $ruleName = truncate_rulenames("Rule ".$ruleNumber);
                            $comments = addslashes($rule['comments']);
                            $automatic = $rule['auto-generated'];

                            if ($tag_id!=""){$add_tag[]="('$lid','$source','$tag_id','tag','$vsys')";}
                            if ($rule['enabled']===true){$rule_enabled=0;}else{$rule_enabled=1;}
                            $natRule["$lid"]=new NatRule($lid,$position,$preorpost,$checkit,$ruleName,$comments,$rule_enabled,$source,$vsys);

                            $method=$rule['method'];
                            switch($method){
                                case "hide":
                                    $natRule["$lid"]->addMethod("dynamic-ip-and-port");
                                    break;

                                case "static":
                                    $natRule["$lid"]->addMethod("static-ip");
                                    //echo "HERE 456: $ruleName\n";

                                    $tp_sat_type="";
                                    $tp_sat_address_type="";
                                    $tp_sat_interface="";
                                    $tp_sat_ipaddress="";
                                    $tp_sat_bidirectional=0;
                                    $tp_fallback_type="None";
                                    $tp_sat_interface_fallback="";
                                    $tp_sat_ipaddress_fallback="";

                                    break;
                            }

                            # Original Packet
                            if (is_array($rule['original-source'])){
                                foreach ($rule['original-source'] as $src){
                                    if ($src!=$any){
                                        list($member_lid,$table_name)=getMemberlid("address",$src,$source,$vsys,'Nat',$lid, $objects);
                                        if ($member_lid!=0){$rule_source[]="('$lid','$member_lid','$table_name','$source','$vsys')";}
                                    }
                                }
                            }
                            else{
                                $src=$rule['original-source'];
                                if ($src!=$any){
                                    list($member_lid,$table_name)=getMemberlid("address",$src,$source,$vsys,'Nat',$lid, $objects);
                                    if ($member_lid!=0){$rule_source[]="('$lid','$member_lid','$table_name','$source','$vsys')";}
                                }
                            }
                            if (is_array($rule['original-destination'])){
                                foreach ($rule['original-destination'] as $src){
                                    if ($src!=$any){

                                        if ($automatic){
                                            if ($method=="static"){
                                                $member_lid=$objects['objects'][$src]["nat"]["translated"]["member_lid"];
                                                $table_name=$objects['objects'][$src]["nat"]["translated"]["table_name"];
                                                $rule_destination[]="('$lid','$member_lid','$table_name','$source','$vsys')";
                                            }
                                        }
                                        else{
                                            list($member_lid,$table_name)=getMemberlid("address",$src,$source,$vsys,'Nat',$lid, $objects);
                                            if ($member_lid!=0){$rule_destination[]="('$lid','$member_lid','$table_name','$source','$vsys')";}
                                        }


                                    }
                                }
                            }
                            else{
                                $src=$rule['original-destination'];
                                if ($src!=$any){
                                    if ($automatic){
                                        if ($method=="static"){
                                            $member_lid=$objects['objects'][$src]["nat"]["translated"]["member_lid"];
                                            $table_name=$objects['objects'][$src]["nat"]["translated"]["table_name"];
                                            $rule_destination[]="('$lid','$member_lid','$table_name','$source','$vsys')";
                                        }
                                        else{
                                            list($member_lid,$table_name)=getMemberlid("address",$src,$source,$vsys,'Nat',$lid, $objects);
                                            if ($member_lid!=0){$rule_destination[]="('$lid','$member_lid','$table_name','$source','$vsys')";}
                                        }
                                    }
                                    else{
                                        list($member_lid,$table_name)=getMemberlid("address",$src,$source,$vsys,'Nat',$lid, $objects);
                                        if ($member_lid!=0){$rule_destination[]="('$lid','$member_lid','$table_name','$source','$vsys')";}
                                    }

//                                    list($member_lid,$table_name)=getMemberlid("address",$src,$source,$vsys,'Nat',$lid, $objects);
//                                    if ($member_lid!=0){$rule_destination[]="('$lid','$member_lid','$table_name','$source','$vsys')";}
                                }
                            }



                            if (is_array($rule['original-service'])){
                                # TODO: ERROR must be a single service or convert into a group
                                foreach ($rule['original-service'] as $src){
                                    if ($src!=$any){
                                        list($member_lid,$table_name)=getMemberlid("services",$src,$source,$vsys,'Nat',$lid, $objects);
                                        if ($member_lid!=0){$natRule["$lid"]->addOPService($member_lid,$table_name);}
                                    }
                                }
                            }
                            else{
                                $src=$rule['original-service'];
                                if ($src!=$any){
                                    list($member_lid,$table_name)=getMemberlid("services",$src,$source,$vsys,'Nat',$lid, $objects);
                                    if ($member_lid!=0){$natRule["$lid"]->addOPService($member_lid,$table_name);}
                                }
                            }

                            if ($rule['translated-source']==$original) {
                                $nat_type="None";
                            }
                            else {
                                $checkIPversion=ip_version($rule['translated-source']);
                                if ($checkIPversion=="noip"){
                                    $src=$rule['translated-source'];
                                    if ($src!=$any){
                                        if ($automatic){
                                            if ($method=="static"){
                                                $member_lid=$objects['objects'][$src]["nat"]["translated"]["member_lid"];
                                                $table_name=$objects['objects'][$src]["nat"]["translated"]["table_name"];
                                                $translated_address[]="('$lid','$member_lid','$table_name','$source','$vsys')";
                                            }
                                            else{
                                                if ($method=="hide"){
                                                    $natRule["$lid"]->setDisabled(1);
                                                    add_log2('error','Nat Rules',' RuleID ['.$lid.'] is a HIDE dynamic Rule and is using gateway as Source Address.',$source,'Please enable the Rule and assign the right object for Source Translation','rules',$lid,'nat_rules');

                                                }
                                                list($member_lid,$table_name)=getMemberlid("address",$src,$source,$vsys,'Nat',$lid, $objects);
                                                if ($member_lid!=0){
                                                    $translated_address[]="('$lid','$member_lid','$table_name','$source','$vsys')";
                                                }
                                            }
                                        }
                                        else{
                                            list($member_lid,$table_name)=getMemberlid("address",$src,$source,$vsys,'Nat',$lid, $objects);
                                            if ($member_lid!=0){
                                                $translated_address[]="('$lid','$member_lid','$table_name','$source','$vsys')";
                                            }
                                        }
                                    }
                                }
                                else {
                                    #is IP or v4 or v6 - Check if exists an object or create it.
                                    $getIP=$projectdb->query("SELECT id FROM address WHERE ipaddress='".$rule['translated-source']."' AND source='$source';");
                                    if ($getIP->num_rows==0){
                                        #Create it
                                        $translated_source = $rule['translated-source'];
                                        $name="H-$translated_source";
                                        if ($checkIPversion=="v4"){$hostCidr="32";}
                                        if ($checkIPversion=="v6"){$hostCidr="128";}
                                        $projectdb->query("INSERT into address (type,name_ext,name,checkit,source,used,ipaddress,cidr,$checkIPversion,vtype,vsys) values('ip-netmask','$name','$name','1','$source','1','$translated_source','$hostCidr','1','ip-netmask','$vsys');");
                                        $flid=$projectdb->insert_id;
                                        $translated_address[]="('$lid','$flid','address','$source','$vsys')";
                                    }
                                    else {
                                        $getData=$getIP->fetch_assoc();
                                        $flid=$getData['id'];
                                        $translated_address[]="('$lid','$flid','address','$source','$vsys')";
                                    }
                                }
                            }



                            #Destination Translation
                            if ($rule['translated-destination']==$original){}
                            else {
                                $src=$rule['translated-destination'];
                                if ($src!=$any){
                                    list($member_lid,$table_name)=getMemberlid("address",$src,$source,$vsys,'Nat',$lid, $objects);
                                    if ($member_lid!=0){
                                        $natRule["$lid"]->addDat($member_lid,$table_name);
                                    }
                                }
                            }

                            #Get the translated port
                            if ($rule['translated-service']==$original){}
                            else{
                                $getPort=$projectdb->query("SELECT dport FROM services WHERE source='$source' AND name='".$rule['translated-service']."' LIMIT 1;");
                                if ($getPort->num_rows==1){
                                    $getPortData=$getPort->fetch_assoc();
                                    $port=$getPortData['dport'];
                                    $natRule["$lid"]->addTPService($port);
                                }
                            }



                            $lid++;$position++;
                        }
                    }
                }else{
                    if(isset($ruleSection['name'])){
                        $name=normalizeNames($ruleSection['name']);
                        $color = "color" . $thecolor;
                        $tag_id = add_tag($name, $source, $vsys, $color);
                        if ($thecolor == 16) {
                            $thecolor = 1;
                        }
                        else {
                            $thecolor++;
                        }
                    }
                }
                break;

            case "nat-rule":
                $rule=$ruleSection;
                $preorpost=0;
                $checkit=0;
                $ruleNumber = $rule['rule-number'];
                $ruleName = truncate_rulenames("Rule ".$ruleNumber);
                $comments = addslashes($rule['comments']);
                $automatic = $rule['auto-generated'];

                if ($tag_id!=""){$add_tag[]="('$lid','$source','$tag_id','tag','$vsys')";}
                if ($rule['enabled']===true){$rule_enabled=0;}else{$rule_enabled=1;}

                $natRule["$lid"] = new NatRule($lid,$position,$preorpost,$checkit,$ruleName,$comments,$rule_enabled,$source,$vsys);
                $method=$rule['method'];
                switch($method){
                    case "hide":
                        //Unless is a No NAT, do dynamic-ip-and-port
                        if( $rule['translated-source']==$original &&
                            $rule['translated-destination']==$original &&
                            $rule['translated-service']==$original
                        ){
                            add_log2("info","Importing NAT Rules","NAT rule [".$lid."] may not be necessary. Check hit counts for this rule in the future.",$source,"Revise","rules",$lid,"nat_rules");
                        }
                        else{
                            $natRule["$lid"]->addMethod("dynamic-ip-and-port");
                        }
                        break;

                    case "static":
                        $natRule["$lid"]->addMethod("static-ip");
                        //echo "HERE 658: $ruleName\n";

                        $tp_sat_type="";
                        $tp_sat_address_type="";
                        $tp_sat_interface="";
                        $tp_sat_ipaddress="";
                        $tp_sat_bidirectional=0;
                        $tp_fallback_type="None";
                        $tp_sat_interface_fallback="";
                        $tp_sat_ipaddress_fallback="";

                        break;
                }

                $ruleTargetArr = array();
                if(isset($rule['install-on'])){
                    foreach ($rule['install-on'] as $targetID){
                        foreach ($objects['common'] as $common_name=>$common_value){
                            if($common_value == $targetID){
                                $ruleTargetArr[] = $common_name;
                                break 2;
                            }
                        }
                        if (isset($objects['objects'][$targetID])) {
                            if(!isset($objects['objects'][$targetID]['name'])){
                                $table_name = $objects['objects'][$targetID]['table_name'];
                                $member_lid = $objects['objects'][$targetID]['member_lid'];
                                $query ="SELECT name FROM $table_name WHERE id = '$member_lid' LIMIT 1";
                                $result = $projectdb->query($query);
                                if($result->num_rows>0) {
                                    $data = $result->fetch_assoc();
                                    $objects['objects'][$targetID]['name'] = $data['name'];
                                }
                            }
                            $ruleTargetArr[] = $objects['objects'][$targetID]['name'];
                        }
                        elseif(isset($common['Policy Targets']) && $common['Policy Targets']==$targetID){
                            //echo "This rule installs in global\n";
                        }
                        else{
                            echo "TARGET OBJECT NOT FOUND IN NAT as INSTALL-ON: $targetID".PHP_EOL;
                        }
                    }

                }
                else{
                }
                $ruleTarget = implode(", ", $ruleTargetArr);
                $natRule["$lid"]->addTarget($ruleTarget);

                # Original Packet
                if (is_array($rule['original-source'])){
                    foreach ($rule['original-source'] as $src){
                        if ($src!=$any){
                            list($member_lid,$table_name)=getMemberlid("address",$src,$source,$vsys,'Nat',$lid,$objects);
                            if ($member_lid!=0){
                                $rule_source[]="('$lid','$member_lid','$table_name','$source','$vsys')";
                            }
                        }
                    }
                }
                else{
                    $src=$rule['original-source'];
                    if ($src!=$any){
                        list($member_lid,$table_name)=getMemberlid("address",$src,$source,$vsys,'Nat',$lid, $objects);
                        if ($member_lid!=0){$rule_source[]="('$lid','$member_lid','$table_name','$source','$vsys')";}
                    }
                }
                if (is_array($rule['original-destination'])){
                    foreach ($rule['original-destination'] as $src){
                        if ($src!=$any){
                            if ($automatic){
                                if ($method=="static"){
                                    if( $rule['translated-source']==$original &&
                                        $rule['translated-destination']==$original &&
                                        $rule['translated-service']==$original
                                    ){
                                        list($member_lid,$table_name)=getMemberlid("address",$src,$source,$vsys,'Nat',$lid,$objects);
                                        if ($member_lid!=0){
                                            $rule_destination[]="('$lid','$member_lid','$table_name','$source','$vsys')";
                                        }
                                        add_log2("info","Importing NAT Rules","NAT rule [".$lid."] may not be necessary. Check hit counts for this rule in the future.",$source,"Revise and potential remove","rules",$lid,"nat_rules");
                                    }
                                    else {
                                        $member_lid = $objects['objects'][$src]["nat"]["translated"]["member_lid"];
                                        $table_name = $objects['objects'][$src]["nat"]["translated"]["table_name"];
                                        $rule_destination[] = "('$lid','$member_lid','$table_name','$source','$vsys')";
                                    }
                                }
                            }
                            else{
                                list($member_lid,$table_name)=getMemberlid("address",$src,$source,$vsys,'Nat',$lid, $objects);
                                if ($member_lid!=0){$rule_destination[]="('$lid','$member_lid','$table_name','$source','$vsys')";}
                            }
                        }
                    }
                }
                else{
                    $src=$rule['original-destination'];
                    if ($src!=$any){
                        if ($automatic){
                            if ($method=="static"){
                                if( $rule['translated-source']==$original &&
                                    $rule['translated-destination']==$original &&
                                    $rule['translated-service']==$original
                                ){
                                    list($member_lid,$table_name)=getMemberlid("address",$src,$source,$vsys,'Nat',$lid,$objects);
                                    if ($member_lid!=0){
                                        $rule_destination[]="('$lid','$member_lid','$table_name','$source','$vsys')";
                                    }
                                    add_log2("info","Importing NAT Rules","NAT rule [".$lid."] may not be necessary. Check hit counts for this rule in the future.",$source,"Revise and potential remove","rules",$lid,"nat_rules");
                                }
                                else {
                                    if(isset($objects['objects'][$src]["nat"]["translated"]["member_lid"])
                                        && isset($objects['objects'][$src]["nat"]["translated"]["table_name"])) {
                                        $member_lid = $objects['objects'][$src]["nat"]["translated"]["member_lid"];
                                        $table_name = $objects['objects'][$src]["nat"]["translated"]["table_name"];
                                        $rule_destination[] = "('$lid','$member_lid','$table_name','$source','$vsys')";
                                    } else {
                                        add_log2("info","Importing NAT Rules","NAT rule [".$lid."] has an invalid/not supported destination address object [$src]. Please review it.",$source,"Review","rules",$lid,"nat_rules");
                                    }
                                }
                            }
                            else{
                                list($member_lid,$table_name)=getMemberlid("address",$src,$source,$vsys,'Nat',$lid, $objects);
                                if ($member_lid!=0){
                                    $rule_destination[]="('$lid','$member_lid','$table_name','$source','$vsys')";
                                }
                            }
                        }
                        else{
                            list($member_lid,$table_name)=getMemberlid("address",$src,$source,$vsys,'Nat',$lid, $objects);
                            if ($member_lid!=0){
                                $rule_destination[]="('$lid','$member_lid','$table_name','$source','$vsys')";
                            }

                        }
                        $original_destination_lid = $member_lid;
                        $original_destination_table_name = $table_name;
                    }
                }
                if (is_array($rule['original-service'])){
                    # TODO: ERROR must be a single service or convert into a group
                    foreach ($rule['original-service'] as $src){
                        if ($src!=$any){
                            list($member_lid,$table_name)=getMemberlid("services",$src,$source,$vsys,'Nat',$lid, $objects);
                            if ($member_lid!=0){$natRule["$lid"]->addOPService($member_lid,$table_name);}
                        }
                    }
                }
                else{
                    $src=$rule['original-service'];
                    if ($src!=$any){
                        list($member_lid,$table_name)=getMemberlid("services",$src,$source,$vsys,'Nat',$lid, $objects);
                        if ($member_lid!=0){$natRule["$lid"]->addOPService($member_lid,$table_name);}
                    }
                }

                if( $rule['translated-source']==$original &&
                    $rule['translated-destination']==$original &&
                    $rule['translated-service']!==$original
                ){
                    if(isset($original_destination_lid,$original_destination_table_name)) {
                        $natRule["$lid"]->addDat($original_destination_lid, $original_destination_table_name);
                    }else{
                        $natRule["$lid"]->is_dat=1;
                    }

                    $getPort = $projectdb->query("SELECT dport FROM services WHERE source='$source' AND name_ext='" . $rule['translated-service'] . "' LIMIT 1;");
                    //echo "SELECT dport FROM services WHERE source='$source' AND name_ext='" . $rule['translated-service'] . "' LIMIT 1;\n";
                    if ($getPort->num_rows == 1) {
                        $getPortData = $getPort->fetch_assoc();
                        $port = $getPortData['dport'];
                        $natRule["$lid"]->addTPService($port);
                    }
                }
                else {

                    if ($rule['translated-source'] == $original) {
                        $nat_type = "None";
                    }
                    else {
                        $checkIPversion = ip_version($rule['translated-source']);
                        if ($checkIPversion == "noip") {
                            $translated_source = $rule['translated-source'];
                            if ($translated_source != $any) {

                                if ($automatic) {
                                    if ($method == "static") {
                                        if(isset($objects['objects'][$translated_source]["nat"])) {
                                            $member_lid = $objects['objects'][$translated_source]["nat"]["translated"]["member_lid"];
                                            $table_name = $objects['objects'][$translated_source]["nat"]["translated"]["table_name"];
                                        }
                                        else {
                                            $member_lid = $objects['objects'][$translated_source]["member_lid"];
                                            $table_name = $objects['objects'][$translated_source]["table_name"];
                                        }
                                        $translated_address[] = "('$lid','$member_lid','$table_name','$source','$vsys')";
                                    } else {
                                        if ($method == "hide") {
                                            //Collect object

                                            if(isset($objects['objects'][$translated_source]["nat"]["hide-behind"]) && $objects['objects'][$translated_source]["nat"]["hide-behind"] == 'ip-address') {
                                                $member_lid = $objects['objects'][$translated_source]["nat"]["translated"]["member_lid"];
                                                $table_name = $objects['objects'][$translated_source]["nat"]["translated"]["table_name"];
                                                $translated_address[] = "('$lid','$member_lid','$table_name','$source','$vsys')";
                                            }
                                            else{
                                                $natRule["$lid"]->setDisabled(1);
                                                add_log2('error', 'Nat Rules', ' RuleID [' . $lid . '] is a HIDE dynamic Rule and is using gateway as Source Address.', $source, 'Please enable the Rule and assign the right object for Source Translation', 'rules', $lid, 'nat_rules');
                                                list($member_lid, $table_name) = getMemberlid("address", $translated_source, $source, $vsys, 'Nat', $lid, $objects);
                                                if ($member_lid != 0) {
                                                    $translated_address[] = "('$lid','$member_lid','$table_name','$source','$vsys')";
                                                }
                                            }
                                        }
                                    }
                                } else {
                                    list($member_lid, $table_name) = getMemberlid("address", $translated_source, $source, $vsys, 'Nat', $lid, $objects);
                                    if ($member_lid != 0) {
                                        $translated_address[] = "('$lid','$member_lid','$table_name','$source','$vsys')";
                                    }
                                }
                            }
                        } else {
                            #is IP or v4 or v6 - Check if exists an object or create it.
                            $getIP = $projectdb->query("SELECT id FROM address WHERE ipaddress='" . $rule['translated-source'] . "' AND source='$source';");
                            if ($getIP->num_rows == 0) {
                                #Create it
                                $translated_source = $rule['translated-source'];
                                $name = "H-$translated_source";
                                if ($checkIPversion == "v4") {
                                    $hostCidr = "32";
                                }
                                if ($checkIPversion == "v6") {
                                    $hostCidr = "128";
                                }
                                $projectdb->query("INSERT into address (type,name_ext,name,checkit,source,used,ipaddress,cidr,$checkIPversion,vtype,vsys) values('ip-netmask','$name','$name','1','$source','1','$translated_source','$hostCidr','1','ip-netmask','$vsys');");
                                $flid = $projectdb->insert_id;
                                $translated_address[] = "('$lid','$flid','address','$source','$vsys')";
                            } else {
                                $getData = $getIP->fetch_assoc();
                                $flid = $getData['id'];
                                $translated_address[] = "('$lid','$flid','address','$source','$vsys')";
                            }
                        }
                    }


                    #Destination Translation
                    if ($rule['translated-destination'] == $original) {

                    }
                    else {
                        $src = $rule['translated-destination'];
                        if ($src != $any) {
                            list($member_lid, $table_name) = getMemberlid("address", $src, $source, $vsys, 'Nat', $lid, $objects);
                            if ($member_lid != 0) {
                                $natRule["$lid"]->addDat($member_lid, $table_name);
                            }
                        }
                    }

                    #Get the translated port
                    if ($rule['translated-service'] == $original) {
                    }
                    else {
                        $getPort = $projectdb->query("SELECT dport FROM services WHERE source='$source' AND ( name='" . $rule['translated-service'] . "' or name_ext='" . $rule['translated-service'] . "')LIMIT 1;");
                        if ($getPort->num_rows == 1) {
                            $getPortData = $getPort->fetch_assoc();
                            $port = $getPortData['dport'];
                            $natRule["$lid"]->addTPService($port);
                        }
                    }
                }

                $lid++;
                $position++;
                break;
            default :
                break;

        }
    }

    # Save the Nat Rules
    if (count($natRule)>0){
        $sql=[];
        foreach ($natRule as $nat){
            $sql[] = $nat->getSQL();
            // if DAT is static it could not have a group as translated address as per NGFW restriction
            if($nat->is_dat===1 && $nat->tp_dat_address_table==="address_groups_id"){
                add_log2("info","Importing NAT Rules","NAT rule [".$nat->id."] has an DAT set to static type but it is using an address-group. Please review it and change to DAT dynamic IP (with session distribution) type, if required",$source,"Review","rules",$nat->id,"nat_rules");
            }
        }
        $projectdb->query("INSERT INTO nat_rules (id,name,position,description,disabled,source,vsys,preorpost,checkit,op_service_lid,op_service_table,is_dat,tp_dat_address_lid,tp_dat_address_table,tp_dat_port,tp_sat_type,tp_sat_address_type,target) VALUES ".implode(",",$sql).";");
        //echo "\n1. INSERT INTO nat_rules (id,name,position,description,disabled,source,vsys,preorpost,checkit,op_service_lid,op_service_table,is_dat,tp_dat_address_lid,tp_dat_address_table,tp_dat_port,tp_sat_type,tp_sat_address_type) VALUES ".implode(",",$sql).";\n";
        unset($sql);unset($natRule);

        if (count($rule_source)){
            $projectdb->query("INSERT INTO nat_rules_src (rule_lid,member_lid,table_name,source,vsys) VALUES ".implode(",",$rule_source).";");
            unset($rule_source);
        }
        if (count($rule_destination)){
            $projectdb->query("INSERT INTO nat_rules_dst (rule_lid,member_lid,table_name,source,vsys) VALUES ".implode(",",$rule_destination).";");
            unset($rule_destination);
        }

        if (count($add_tag)>0){
            $projectdb->query("INSERT INTO nat_rules_tag (rule_lid,source,member_lid,table_name,vsys) VALUES ".implode(",",$add_tag).";");
            unset($add_tag);
        }

        if(count($translated_address)>0){
            $projectdb->query("INSERT INTO nat_rules_translated_address (rule_lid,member_lid,table_name,source,vsys) VALUES ".implode(",",$translated_address).";");
            unset($translated_address);
        }
    }

    //MT-1634 Expedition NAT problems: 2) NAT rules in Expedition have translation type set to "static", but the TP source and TP destination columns have "none", which is also invalid config
    $projectdb->query("UPDATE nat_rules SET tp_sat_type = 'none' WHERE tp_sat_type = 'static-ip' AND id NOT IN (SELECT rule_lid FROM nat_rules_translated_address );");
}

function load_policy($policy,$project,$jobid){

    $objectFile=str_replace(".html",".json",$policy);
    $objectFile=USERSPACE_PATH."/projects/" . $project . "/security/".$objectFile;

    $handle = fopen($objectFile, 'r');
    $contents = fread($handle, 1);
    fclose($handle);

    if ($contents=="["){
        $myRules[]=file_get_contents($objectFile);
    }
    else{
        $myRules[]="[";
        $myRules[]=file_get_contents($objectFile);
        $myRules[]="]";
    }

    # Add the brackets at the end and begining of the file and decode correctly.

    $json=implode("",$myRules);
    $json=anything_to_utf8($json);

    if (isValidJson($json)){
        $myRules=json_decode($json,true);
    }
    else{
        echo "INVALID RULES JSON FILE".PHP_EOL;
        update_progress($project,'-1','RULES - JSON FILE IS INVALID',$jobid);
        exit(0);
    }
    return $myRules;
}

function getMemberlid(String $table, String $uuid, $source,$vsys,$policy,$lid, Array &$objects){
    global $projectdb;
    if ($policy=="Nat"){$policy2="nat_rules";}
    elseif ($policy=="Security"){$policy2="security_rules";}
    else{
        $policy2="unknown:".$policy;
    }

    if(!isset($objects['objects'][$uuid]) && !isset($objects['missing_objects'][$uuid]) ){
        $insert_id = 0;
        switch($table){
            case 'address':
                // check if the address is a fqdn
                $fqdn_name = $uuid . "_fqdn1";
                if(isset($objects['objects'][$fqdn_name])){
                    return array($objects['objects'][$fqdn_name]['member_lid'] ,$objects['objects'][$fqdn_name]['table_name']);
                }
                $fqdn_name = $uuid . "_fqdn2";
                if(isset($objects['objects'][$fqdn_name])){
                    return array($objects['objects'][$fqdn_name]['member_lid'] ,$objects['objects'][$fqdn_name]['table_name']);
                }

                //it's not a previous load fqdn
                $projectdb->query("INSERT INTO address (name_ext,name,ipaddress,cidr,source,vsys,v4) VALUES ('$uuid','$uuid','1.1.1.1','32','$source','$vsys',1);");
                $insert_id = $projectdb->insert_id;
                add_log2('error','Mapping Object',$policy.' RuleID ['.$lid.'] is using an Object named ['.$uuid.'] but is not defined in my Database.',$source,'Adding to the DB [ip:1.1.1.1]. Fix IP Address','rules',$lid,$policy2);
                break;
            case 'services':
                $projectdb->query("INSERT INTO services (name_ext,name,source,vsys) VALUES ('$uuid','$uuid','$source','$vsys');");
                $insert_id = $projectdb->insert_id;
                add_log2('error','Mapping Object',$policy.' RuleID ['.$lid.'] is using an Object named ['.$uuid.'] but is not defined in my Database.',$source,'Adding to the DB. Fix Protocol/Port','rules',$lid,$policy2);
                break;
        }
        // save the missing_object into this array so we are not creating duplicates
        $objects['missing_objects'][$uuid]['member_lid'] = $insert_id;
        $objects['missing_objects'][$uuid]['table_name'] = $table;
        return array($objects['missing_objects'][$uuid]['member_lid'] ,$objects['missing_objects'][$uuid]['table_name']);

    }else if (isset($objects['missing_objects'][$uuid])) {
        // create a warning in the rule using this missing_object but do not create the missing object as it was previously created
        switch($table){
            case 'address':
                add_log2('error','Mapping Object',$policy.' RuleID ['.$lid.'] is using an Object named ['.$uuid.'] but is not defined in my Database.',$source,'Adding to the DB [ip:1.1.1.1]. Fix IP Address','rules',$lid,$policy2);
                break;
            case 'services':
                add_log2('error','Mapping Object',$policy.' RuleID ['.$lid.'] is using an Object named ['.$uuid.'] but is not defined in my Database.',$source,'Adding to the DB. Fix Protocol/Port','rules',$lid,$policy2);
                break;
        }
        return array($objects['missing_objects'][$uuid]['member_lid'], $objects['missing_objects'][$uuid]['table_name']);
    }else{
        return array($objects['objects'][$uuid]['member_lid'], $objects['objects'][$uuid]['table_name']);
    }
}

function getMemberlid_old($table,$name_ext,$source,$vsys,$policy,$lid){
    global $projectdb;

    if ($policy=="Nat"){$policy2="nat_rules";}
    elseif ($policy=="Security"){$policy2="security_rules";}
    else{
        $policy2="unknown:".$policy;
    }
    $output=array(0,0);
    if ($table=="services"){$tablegroup="services_groups_id";}
    elseif ($table=="address"){$tablegroup="address_groups_id";}
    $getID=$projectdb->query("SELECT id FROM $table WHERE name_ext='$name_ext' AND vsys='$vsys' AND source='$source' LIMIT 1;");
    if ($getID->num_rows==1){
        $getIDData=$getID->fetch_assoc();
        $output=array($getIDData['id'],$table);
    }
    else{
        $getID=$projectdb->query("SELECT id FROM $tablegroup WHERE name_ext='$name_ext' AND vsys='$vsys' AND source='$source' LIMIT 1;");
        if ($getID->num_rows==1) {
            $getIDData = $getID->fetch_assoc();
            $member_lid = $getIDData['id'];
            $output = array($getIDData['id'], $tablegroup);
        }
        else{
            # Needs to create one Raise Log as well
            if ($table=="address"){
                $checkExits=$projectdb->query("SELECT id FROM address WHERE name='$name_ext' AND source='$source';");
                if ($checkExits->num_rows==1){
                    $checkExitsData=$checkExits->fetch_assoc();
                    $output=array($checkExitsData['id'],$table);
                }
                else{
                    $projectdb->query("INSERT INTO address (name_ext,name,ipaddress,cidr,source,vsys,v4) VALUES ('$name_ext','$name_ext','1.1.1.1','32','$source','$vsys',1);");
                    $output = array($projectdb->insert_id,"address");
                    add_log2('error','Mapping Object',$policy.' RuleID ['.$lid.'] is using an Object named ['.$name_ext.'] but is not defined in my Database.',$source,'Adding to the DB [ip:1.1.1.1]. Fix IP Address','rules',$lid,$policy2);
                }
            }
            elseif($table=="services"){
                $checkExits=$projectdb->query("SELECT id FROM services WHERE name='$name_ext' AND source='$source';");
                if ($checkExits->num_rows==1){
                    $checkExitsData=$checkExits->fetch_assoc();
                    $output=array($checkExitsData['id'],$table);
                }
                else{
                    $projectdb->query("INSERT INTO services (name_ext,name,source,vsys) VALUES ('$name_ext','$name_ext','$source','$vsys');");
                    $output = array($projectdb->insert_id,"address");
                    add_log2('error','Mapping Object',$policy.' RuleID ['.$lid.'] is using an Object named ['.$name_ext.'] but is not defined in my Database.',$source,'Adding to the DB. Fix Protocol/Port','rules',$lid,$policy2);
                }
            }
            else{
                add_log2('error','Mapping Object',$policy.' RuleID ['.$lid.'] is using an Object named ['.$name_ext.'] but is not defined in my Database.',$source,'Add it manually','rules',$lid,$policy2);
            }

        }
    }
    return $output;
}

function remap_groupmembers($source,$vsys,$getObjects){
    global $projectdb;
    $getMembers=$projectdb->query("SELECT * FROM address_groups WHERE source='$source' AND vsys='$vsys';");
    if ($getMembers->num_rows>0){
        $remove=array();
        $newData=array();
        while ($data=$getMembers->fetch_assoc()){
            $uid=$data['member'];
            list($member_lid,$table_name)=getMemberlid("address",$uid,$source,$vsys,'','',$getObjects);
            $devicegroup=$data['devicegroup'];
            $lid=$data['lid'];
            $remove[]=$data['id'];
            $newData[]="('$member_lid','$table_name','$source','$vsys','$devicegroup','$lid')";
        }
        $projectdb->query("DELETE FROM address_groups WHERE id IN (".implode(",",$remove).");");unset($remove);
        $projectdb->query("INSERT INTO address_groups (member_lid,table_name,source,vsys,devicegroup,lid) VALUES ".implode(",",$newData).";");unset($newData);
    }

    $getMembers=$projectdb->query("SELECT * FROM services_groups WHERE source='$source' AND vsys='$vsys';");
    if ($getMembers->num_rows>0){
        $remove=array();
        $newData=array();
        while ($data=$getMembers->fetch_assoc()){
            $uid=$data['member'];
            list($member_lid,$table_name)=getMemberlid("services",$uid,$source,$vsys,'','',$getObjects);
            $devicegroup=$data['devicegroup'];
            $lid=$data['lid'];
            $remove[]=$data['id'];
            $newData[]="('$member_lid','$table_name','$source','$vsys','$devicegroup','$lid')";
        }
        $projectdb->query("DELETE FROM services_groups WHERE id IN (".implode(",",$remove).");");unset($remove);
        $projectdb->query("INSERT INTO services_groups (member_lid,table_name,source,vsys,devicegroup,lid) VALUES ".implode(",",$newData).";");unset($newData);
    }
}

function normalize_bond_interface($interface){
    $unitname = $interface;
    if (preg_match("/bond/",$interface)) {
        $int_tmp = str_replace("bond", "", $interface);
        $int_tmp2 = explode(".", $int_tmp);
        if (count($int_tmp2) == 1) {
            $unittag = 0;
        } else {
            $unittag = intval($int_tmp2[1]);
        }
        if ($int_tmp2[0] == 0) {
            $unitname_tmp = "1";
        } else {
            $unitname_tmp = $int_tmp2[0] + 1;
        }
        $unitname = "ae" . $unitname_tmp . "." . $unittag;
    }
    return $unitname;
}

function fix_interface_ips($project, $source, $vsys){
    global $projectdb;

    $interfaces_db_missing_array = [];

    $index = USERSPACE_PATH . "/projects/" . $project . "/security/index.json";
    $policiesList = read_index($project, $index);
    $objectFile = $policiesList['gateways'];

    $objectFile=str_replace(".html",".json",$objectFile);
    $objectFile=USERSPACE_PATH."/projects/" . $project . "/security/".$objectFile;
    $handle = fopen($objectFile, 'r');
    $contents = fread($handle, 1);
    fclose($handle);

    if ($contents=="["){
        $gateways_entries[]=file_get_contents($objectFile);
    }
    else{
        $gateways_entries[]="[";
        $gateways_entries[]=file_get_contents($objectFile);
        $gateways_entries[]="]";
    }

    $json=implode("",$gateways_entries);
    $json=anything_to_utf8($json);
    $gateways = json_decode($json, true);

    if(count($gateways)>0) {

        // Get interfaces from route file
        $interfaces_db = [];
        $interfaces_query = "SELECT id, name,type,media,source,template,vsys,vr_id,unitipaddress,unitname,zone,unittag FROM interfaces WHERE vsys='$vsys' AND source='$source'";
        $results = $projectdb->query($interfaces_query);
        if ($results->num_rows > 0) {
            while ($data = $results->fetch_assoc()) {
                $interfaces_db[$data['unitname']] = $data;
            }
        }

        // MT-2387. Interfaces could be defined into multiple gateways or "interfaces" section within the json file
        foreach ($gateways as $gateway_key => $gateway_value) {
            $gateways[$gateway_key]['name'];
            if (isset($gateways[$gateway_key]['interfaces'])){
                foreach ($gateways[$gateway_key]['interfaces'] as $interface_json) {

                    $normalized_interface_name = normalize_bond_interface($interface_json['interface-name']);

                    // MT-2387. Not all interfaces included on the route file could be defined on this gateway
                    if (isset($interfaces_db[$normalized_interface_name])) {

                        //Save the number of gateways that this interface have declared
                        $interfaces_db[$normalized_interface_name]['gateways'] = isset($interfaces_db[$normalized_interface_name]['gateways']) ? $interfaces_db[$normalized_interface_name]['gateways'] + 1 : 1;

                        //Get the ipv4 values that this gateways gives to this interface
                        if (isset($interface_json['ipv4-address'])) {
                            $interfaces_db[$normalized_interface_name]['new_ips'][] = $interface_json['ipv4-address'] . "/" . $interface_json['ipv4-mask-length'];
                        }

                        //Get the ipv6 values that this gateways gives to this interface
                        if (isset($interface_json['ipv6-address'])) {
                            $interfaces_db[$normalized_interface_name]['new_ips'][] = $interface_json['ipv6-address'] . "/" . $interface_json['ipv6-mask-length'];
                        }

                    }else{
                        // MT-2387. Include this interface as missing interface into the db
                        // same interfaces can be defined multiple times on json file
                        // we need to be sure we save all ip addresses

                        //Get the ipv4 values that this gateways gives to this interface
                        if (isset($interface_json['ipv4-address'])) {
                            $interfaces_db_missing_array[$normalized_interface_name]['new_ips'][] = $interface_json['ipv4-address'] . "/" . $interface_json['ipv4-mask-length'];
                        }

                        //Get the ipv6 values that this gateways gives to this interface
                        if (isset($interface_json['ipv6-address'])) {
                            $interfaces_db_missing_array[$normalized_interface_name]['new_ips'][] = $interface_json['ipv6-address'] . "/" . $interface_json['ipv6-mask-length'];
                        }

                        //$interfaces_db_missing_array[$normalized_interface_name]=$interface_json;
                    }
                }
            }
        }
        foreach ($interfaces_db as $interface_entry){
            if(isset($interface_entry['gateways']) && $interface_entry['gateways']>1) {
                add_log2('warning','Reading Interfaces','Interface ['.$interface_entry['unitname'].'] has been declared in more than one gateway. Multiple IPs could be collected.',$source,'Select the valid IPs','network',$interface_entry['id'],'interfaces');
            }

            if(isset($interface_entry['new_ips']) && $interface_entry['new_ips']!=false) {
                // MT-2387. We need to check if new IPS were added to the interface before doing the IP update/fixing on the DB

                // Merging routes read on route file and configuration json file
                $ips_route = explode(',',$interface_entry['unitipaddress']);
                $ips = array_merge ( $ips_route, $interface_entry['new_ips'] );
                $ips = array_unique ($ips);
                asort($ips);
                $ips_text = implode(",", $ips);

                $update_query = "UPDATE interfaces set unitipaddress='$ips_text' WHERE id = '" . $interface_entry['id'] . "' AND source='$source';";
                $projectdb->query($update_query);

            }

        }

        return $interfaces_db_missing_array;
    }

}


function get_routes($project,$source,$template,$vsys){
    #Support for ipv4 by now
    global $projectdb;
    //number of default routes read on both routes and JSON file
    $default_routes_count=0;
    //number of routes read on both routes and JSON file
    $routes_count = 0;
    // array of routes to be created on the db
    $addRoutes=array();
    //number of zones created
    $zone_count = 0;
    //number of ethernet1 subinterfaces created
    $ethernet1_count = 0;
    $unit_name_count = 1;

    $routes_file=USERSPACE_PATH."/projects/$project/routes.txt";
    $routes_out =USERSPACE_PATH."/projects/$project/routes.out";

    #Create a VR
    $getVR=$projectdb->query("SELECT id FROM virtual_routers WHERE template='$template';");
    if ($getVR->num_rows==0){
        $projectdb->query("INSERT INTO virtual_routers (name,source,template,vsys) VALUES ('chkpt-vr','$source','$template','$vsys');");
        $vr_id=$projectdb->insert_id;
    }
    else{
        $getVRData=$getVR->fetch_assoc();
        $vr_id=$getVRData['id'];
    }

    // Read all interfaces defined on routes file
    if (file_exists($routes_file)){
        #Trick to clean the file and align
        $command="cat $routes_file | awk '{print $1, $2, $3, $4, $5, $6, $7, $8}' > $routes_out";
        shell_exec($command);
        #clean the ctrl+M
        $command="tr -d \'\r\' < $routes_out > $routes_file";
        shell_exec($command);
        #Open the fixed file
        $routes = file($routes_file);
        #Log


        $which_table="";
        $fields=array();
        $fw_to_map = array();
        // Get the type of file to know how to read each line
        foreach ($routes as $line => $routes_line1){
            $routes_line=rtrim($routes_line1);
            $fields=explode(' ',$routes_line);
            if(count($fields)<3) {continue;} // Avoid comparing empty lines
            if (($fields[0] == "Destination") and ($fields[1] == "Gateway") and ($fields[2] == "Genmask")){$which_table="linux"; break;}
            elseif (preg_match("/^255./i", $fields[1])) { $which_table="other"; break; }
            elseif (($fields[0] == "Destination") and ($fields[1] == "Type") and ($fields[2] == "Ref") and ($fields[3] == "NextHop")){$which_table="gaia"; break;}
            elseif (($fields[0] == "Destination") and ($fields[1] == "Gateway") and ($fields[2] == "Flags") and ($fields[3] == "Refs")){$which_table="ipso"; break;}
            elseif (($fields[0] == "Destination") AND ($fields[1] == "Type") AND ($fields[3] == "NextHop")){$which_table="ipso2"; break;}
            elseif (preg_match("/255./i", $fields[2])) {$which_table="splat"; break;}
            else {$which_table="idontknow";
                unset($routes[$line]);
            }
        }


        foreach ($routes as $line => $routes_line) {
            $network="";
            $gateway="";
            $netmask="";
            $flags="";
            $metric="";
            $ref="";
            $use="";
            $interface="";
            $zone="";

            if ($which_table == 'linux'){
                list($network,$gateway,$netmask,$flags,$metric,$ref,$use,$interface)=explode(" ",$routes_line);
            }
            elseif ($which_table == 'splat'){
                list($network,$gateway,$netmask,$flags,$metric,$ref,$use,$interface)=explode(" ",$routes_line);
            }
            elseif ($which_table == 'other'){
                list($network,$netmask,$gateway,$flags,$metric,$ref,$use,$interface)=explode(" ",$routes_line);
            }
            elseif ($which_table == 'ipso'){
                list($network_and_mask,$gateway,$flags,$ref,$use,$interface)=explode(" ",$routes_line);
                if (($network_and_mask=="default") and ($gateway!="RCSU")){$network="default";}
                elseif(($flags=="lCGSU") or ($flags=="lCSU") or ($flags=="iCGSU") or ($flags=="lGC") or ($flags=="gCDSU")){$network="ignore";}
                elseif ($gateway=="RCSU"){$network="ignore";}
                elseif (($gateway=="rCGSU") or ($gateway=="CGUX")) {
                    #Interfaces
                    list($net,$mask)=explode("/",$network_and_mask);
                    list($a,$b,$c,$d)=explode(".",$net);
                    if ($b==""){$b=0;}
                    if ($c==""){$c=0;}
                    if ($d==""){$d=0;}
                    $network=$a.".".$b.".".$c.".".$d;
                    $netmask =convertNetmaskv4($mask);
                    $gateway ="0.0.0.0";
                    $metric=1;
                }
                elseif(($flags=="iCSU") or ($flags=="iSUW") or ($flags=="CU")){
                    if(validateIpAddress($network_and_mask,"v4")){
                        $network=$network_and_mask;
                        $netmask ="255.255.255.255";
                        $metric=1;
                    }
                    elseif (preg_match("/\//i",$network_and_mask)){
                        list($net,$mask)=explode("/",$network_and_mask);
                        list($a,$b,$c,$d)=explode(".",$net);
                        if ($b==""){$b=0;}
                        if ($c==""){$c=0;}
                        if ($d==""){$d=0;}
                        $network=$a.".".$b.".".$c.".".$d;
                        $netmask =convertNetmaskv4($mask);
                        $metric=1;
                    }
                }
            }
            elseif ($which_table == 'ipso2'){
                list($network_and_mask,$kk,$kk1,$gateway,$flags,$ref,$use,$interface)=explode(" ",$routes_line);
                if (($network_and_mask=="default") and ($gateway!="RCSU")){$network="default";}
                elseif($kk=="clon"){$network="ignore";}
                elseif (($gateway=="rCGSU") or ($gateway=="CGUX")) {
                    #Interfaces
                    list($net,$mask)=explode("/",$network_and_mask);
                    list($a,$b,$c,$d)=explode(".",$net);
                    if ($b==""){$b=0;}
                    if ($c==""){$c=0;}
                    if ($d==""){$d=0;}
                    $network=$a.".".$b.".".$c.".".$d;
                    $netmask =convertNetmaskv4($mask);
                    $gateway ="0.0.0.0";
                    $metric=1;
                }
                elseif(($flags=="iCSU") or ($flags=="iSUW") or ($flags=="CU")){
                    if(validateIpAddress($network_and_mask,"v4")){
                        $network=$network_and_mask;
                        $netmask ="255.255.255.255";
                        $metric=1;
                    }
                    elseif (preg_match("/\//i",$network_and_mask)){
                        list($net,$mask)=explode("/",$network_and_mask);
                        list($a,$b,$c,$d)=explode(".",$net);
                        if ($b==""){$b=0;}
                        if ($c==""){$c=0;}
                        if ($d==""){$d=0;}
                        $network=$a.".".$b.".".$c.".".$d;
                        $netmask =convertNetmaskv4($mask);
                        $metric=1;
                    }
                }
            }
            elseif ($which_table == 'gaia'){
                list($network_and_mask,$type,$ref,$gateway,$type2,$ref,$interface,$interface2)=explode(" ",$routes_line);
                if (($network_and_mask=="default") and ($gateway!="RCSU")){$network="default";}
                elseif($type=="clon"){$network="ignore";}
                elseif (($type=="dest") AND ($gateway=="rslv")) {
                    #Interfaces
                    list($net,$mask)=explode("/",$network_and_mask);
                    list($a,$b,$c,$d)=explode(".",$net);
                    if ($b==""){$b=0;}
                    if ($c==""){$c=0;}
                    if ($d==""){$d=0;}
                    $network=$a.".".$b.".".$c.".".$d;
                    $netmask =convertNetmaskv4($mask);
                    $gateway ="0.0.0.0";
                    $metric=1;
                }
                elseif(($type=="user") AND ($type2=="dest")){
                    if(validateIpAddress($network_and_mask,"v4")){
                        $network=$network_and_mask;
                        $netmask ="255.255.255.255";
                        $metric=1;
                    }
                    elseif (preg_match("/\//i",$network_and_mask)){
                        list($net,$mask)=explode("/",$network_and_mask);
                        list($a,$b,$c,$d)=explode(".",$net);
                        if ($b==""){$b=0;}
                        if ($c==""){$c=0;}
                        if ($d==""){$d=0;}
                        $network=$a.".".$b.".".$c.".".$d;
                        $netmask =convertNetmaskv4($mask);
                        $metric=1;
                    }
                }
            }
            elseif ($which_table == "idontknow") {
                if (preg_match("/ via /i",$routes_line)){
                    $keywords = preg_split("/[\s,]+/", $routes_line);
                    $key=array_search('via', $keywords);
                    if ($keywords[$key-1]=="0.0.0.0/0"){
                        if (validateIpAddress($keywords[$key+1],"v4")){
                            $gateway=$keywords[$key+1];
                            $network="0.0.0.0";
                            $netmask="0.0.0.0";
                        }
                    } else {
                        #check the IP address v4 or v6 and is not the default ? FIX THIS
                        $keywords = preg_split("/[\s,]+/", $routes_line);
                        $key=array_search('via', $keywords);
                        if (validateIpAddress($keywords[$key+1],"v4")){
                            $gateway=$keywords[$key+1];
                            $network_and_mask=$keywords[$key-1];
                            if (preg_match("/\//i",$network_and_mask)){
                                list($net,$mask)=explode("/",$network_and_mask);
                                list($a,$b,$c,$d)=explode(".",$net);
                                if ($b==""){$b=0;}
                                if ($c==""){$c=0;}
                                if ($d==""){$d=0;}
                                $network=$a.".".$b.".".$c.".".$d;
                                $netmask =convertNetmaskv4($mask);
                                $metric=1;
                            }
                        }
                    }

                }
                elseif (preg_match("/ is directly connected, /",$routes_line)){
                    $keywords = preg_split("/[\s,]+/", $routes_line);
                    $key=array_search('is', $keywords);
                    $network_and_mask=explode("/",$keywords[$key-1]);
                    $network=$network_and_mask[0];
                    if (validateIpAddress($network,"v4")){
                        $netmask=convertNetmaskv4($network_and_mask[1]);
                        $gateway="0.0.0.0";
                        $zone=$keywords[$key+3];
                    } else {
                        list($a,$b,$c,$d)=explode(".",$network);
                        if ($b==""){$b=0;}
                        if ($c==""){$c=0;}
                        if ($d==""){$d=0;}
                        $network=$a.".".$b.".".$c.".".$d;
                        $netmask=convertNetmaskv4($network_and_mask[1]);
                        $gateway="0.0.0.0";
                        $zone=$keywords[$key+3];
                    }
                }
            }

            $network = preg_replace('/[^(\x20-\x7F)]*/','', $network);
            $gateway = preg_replace('/[^(\x20-\x7F)]*/','', $gateway);
            $netmask = preg_replace('/[^(\x20-\x7F)]*/','', $netmask);
            $flags = preg_replace('/[^(\x20-\x7F)]*/','', $flags);
            $metric = preg_replace('/[^(\x20-\x7F)]*/','', $metric);
            $ref = preg_replace('/[^(\x20-\x7F)]*/','', $ref);
            $use = preg_replace('/[^(\x20-\x7F)]*/','', $use);
            $interface = preg_replace('/[^(\x20-\x7F)]*/','', $interface);            
	        createInterface($source, $vr_id, $template, $vsys,$network,$gateway,$netmask,$flags,$metric,$ref,$use,$interface,$addRoutes, $default_routes_count, $zone_count, $routes_count, $ethernet1_count, $unit_name_count, false);
        }

    }

    // Get interfaces from the JSON file and do:
    // a) update interfaces also defined on the route file
    // b) return a list of new interfaces to be created
    $interfaces_missing_array = fix_interface_ips($project, $source, $vsys);

    foreach ($interfaces_missing_array as $missing_interface_key => $missing_interface_value){
        // for each missing interface on the db do a call on createInterfaces

        unset($network,$netmask, $interface);
        $network = implode(",", $missing_interface_value['new_ips']);
        $interface=$missing_interface_key;

        createInterface($source, $vr_id, $template, $vsys,$network,"","","","","","",$interface,$addRoutes, $default_routes_count, $zone_count, $routes_count, $ethernet1_count, $unit_name_count, true);
    }


    if (count($addRoutes)>0){
        $unique=array_unique($addRoutes);
        $projectdb->query("INSERT INTO routes_static (zone,source,vr_id,template,ip_version,name,destination,tointerface,nexthop,nexthop_value,metric,vsys) VALUES ".implode(",",$unique).";");
        unset($addRoutes);
    }
    #Clean the vars

    $routes="";

    # Get Interfaces to VR
    $getInterface=$projectdb->query("SELECT unitname FROM interfaces WHERE template='$template' AND vr_id='$vr_id' AND source='$source';");
    if ($getInterface->num_rows>0){
        $myInterfaces = array();
        while ($data=$getInterface->fetch_assoc()){
            $myInterfaces[]=$data['unitname'];
        }
        $projectdb->query("UPDATE virtual_routers SET interfaces='".implode(",",$myInterfaces)."' WHERE id='$vr_id';");
    }

}

function createInterface($source, $vr_id, $template, $vsys, $network, $gateway, $netmask,  $flags,  $metric,  $ref,  $use,  $interface, &$addRoutes, &$default_routes_count, &$zone_count, &$routes_count, &$ethernet1_count, &$unit_name_count, $is_missing_db_interface = false){

    global $projectdb;

    $int_tmp=trim($interface);
    $interface=normalize_bond_interface($int_tmp);
    $unitname=$interface;

    if ($metric == "0"){$metric="1";}
    if ($metric==""){$metric="1";}
    if ($network == "Destination"){}
    elseif ($network == ""){}
    elseif ($network == "255.255.255.255"){}
    elseif (($flags=="CGU") or ($flags=="UW")){}
    elseif ($network == "ignore"){}
    elseif (preg_match("/\#/",$network)){}
    elseif (($gateway=="*") and ($netmask=="255.255.255.255") and ($network=="localhost")){}
    elseif (($gateway == "gCDSU") or ($gateway == "BCSU") or ($gateway == "RCGSU") or ($gateway == "lCSU") or ($gateway == "RCU") or ($gateway == "CDU") or ($gateway == "BCU") or ($gateway == "RGCU") or ($gateway == "CG") or ($gateway == "CU") or ($gateway == "CGU")){}
    elseif ($network == "Kernel"){}
    elseif (($network == "127.0.0.0") or ($network == "127.0.0.1")){
        #add_log('2','Phase 6: Reading Static-routes','Reading Contents',$project,'Ignoring loopback interface '.$network);
    }
    elseif ($network == "224.0.0.2") {
        #add_log('2','Phase 6: Reading Static-routes','Reading Contents',$project,'Ignoring Multicast interface '.$network);
    }
    elseif (($network == "0.0.0.0") and ($netmask == "0.0.0.0")) {
        $ip_version="v4";
        if (validateIpAddress($gateway,$ip_version)){

            //$interface = getInterface_from_unitname($interface);

            if ($default_routes_count==0){ // exist default into the array $addRoutes
                $addRoutes[]="('','$source','$vr_id','$template','$ip_version','default','0.0.0.0/0','$interface','ip-address','$gateway','$metric','$vsys')";
                $default_routes_count++;
            }
            else{
                $newRouteName="default ".$default_routes_count;
                $addRoutes[]="('','$source','$vr_id','$template','$ip_version','$newRouteName','0.0.0.0/0','$interface','ip-address','$gateway','$metric','$vsys')";
                $default_routes_count++;
            }

        }
        #$projectdb->query("INSERT INTO routes (network,gateway,netmask,metric,name,zone,project) values ('$network','$gateway','$netmask','$metric','default','','$project');");
        #add_log('2','Phase 6: Reading Static-routes','Reading Contents',$project,'Getting Default Gateway: '.$network.' / '.$netmask.' - '.$gateway);
    }
    elseif (($network == "0.0.0.0") and ($netmask == "255.255.255.255")) {
        #$projectdb->query("INSERT INTO routes (network,gateway,netmask,metric,name,zone,project) values ('$network','$gateway','0.0.0.0','$metric','default','','$project');");
        $ip_version="v4";
        if (validateIpAddress($gateway,$ip_version)){

            //$interface = getInterface_from_unitname($interface);

            if ($default_routes_count==0){ // exist default into the array $addRoutes
                $addRoutes[]="('','$source','$vr_id','$template','$ip_version','default','0.0.0.0/0','$interface','ip-address','$gateway','$metric','$vsys')";
                $default_routes_count++;
            }
            else{
                $newRouteName="default ".$default_routes_count;
                $addRoutes[]="('','$source','$vr_id','$template','$ip_version','$newRouteName','0.0.0.0/0','$interface','ip-address','$gateway','$metric','$vsys')";
                $default_routes_count++;
            }
        }
        #add_log('2','Phase 6: Reading Static-routes','Reading Contents',$project,'Getting Default Gateway: '.$network.' / 0.0.0.0 - '.$gateway);
    }
    elseif ($network == "default"){
        #$projectdb->query("INSERT INTO routes (network,gateway,netmask,metric,name,zone,project) values ('0.0.0.0','$gateway','0.0.0.0','$metric','default','','$project');");
        #add_log('2','Phase 6: Reading Static-routes','Reading Contents',$project,'Getting Default Gateway: '.$network.' / 0.0.0.0 - '.$gateway);
        $ip_version="v4";
        if (validateIpAddress($gateway,$ip_version)){

            //$interface = getInterface_from_unitname($interface);

            if ($default_routes_count==0){
                $addRoutes[]="('','$source','$vr_id','$template','$ip_version','default','0.0.0.0/0','','ip-address','$gateway','$metric','$vsys')";
                $default_routes_count++;
            }
            else{
                $newRouteName="default ".$default_routes_count;
                $addRoutes[]="('','$source','$vr_id','$template','$ip_version','$newRouteName','0.0.0.0/0','','ip-address','$gateway','$metric','$vsys')";
                $default_routes_count++;
            }

        }
    }
    elseif(($gateway=="*") and ($flags=="U")){
        $zone_count++;
        $zoneName="Zone".$zone_count;
        $cidr=mask2cidrv4($netmask);
        $media="ethernet";
        $unittag=0;
        if ($interface==""){$ethernet1_count++;$interface="ethernet1/".$ethernet1_count;$unitname=$interface;}
        elseif (preg_match("/bond/",$interface)){
            $int_tmp=str_replace("bond","",$interface);
            $int_tmp2=explode(".",$int_tmp);
            if (count($int_tmp2)==1){$unittag=0;}else{$unittag=intval($int_tmp2[1]);}
            if ($int_tmp2[0]==0){$unitname_tmp="1";}else{$unitname_tmp=$int_tmp2[0]+1;}

            $unitname="ae".$unitname_tmp.".".$unit_name_count;
            $interface="ae".$unitname_tmp;

        }
        else{
            $interface=trim($interface);
            $int_tmp2=explode(".",$interface);
            if (count($int_tmp2)==1){$unittag="";}else{$unittag=intval($int_tmp2[1]);}
            $interface=$int_tmp2[0];
            if (($unittag=="") OR ($unittag==0)){
                $unitname=$interface;
            }
            else{
                $unitname=$interface.".".$unittag;
                if (preg_match("/.0$/",$interface)){
                    $int_tmp2=explode(".",$interface);
                    $interface=$int_tmp2[0];
                }
            }
        }

        if(preg_match("/ae/",$interface)) {
            $media="aggregate-ethernet";
            // check if aggregate-ethernet first unittag 0 is created
            $get_ae_interfaces = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='aggregate-ethernet' AND unittag='0' AND unitname='$interface' GROUP BY name ORDER BY name");
            if ($get_ae_interfaces->num_rows === 0) {
                $zone_count++;
                $ae_zone_name = "Zone" . $zone_count;
                $projectdb->query("INSERT INTO interfaces (name,type,media,source,template,vsys,vr_id,unitipaddress,unitname,zone,unittag) VALUES ('$interface','layer3','$media','$source','$template','$vsys','$vr_id','','$interface','$ae_zone_name','0');");
                $projectdb->query("INSERT INTO zones (source,template,vsys,name,type,interfaces) VALUES ('$source','$template','$vsys','$ae_zone_name','layer3','$interface');");
            }
            $unit_name_count++;
        }

        create_or_update_interface($interface,'layer3',$media,$source,$template,$vsys,$vr_id,$network."/".$cidr,$unitname,$zoneName,$unittag);

        //$projectdb->query("INSERT INTO interfaces (name,type,media,source,template,vsys,vr_id,unitipaddress,unitname,zone,unittag) VALUES ('$interface','layer3','$media','$source','$template','$vsys','$vr_id','$network/$cidr','$unitname','$zoneName','$unittag');");
        //$projectdb->query("INSERT INTO zones (source,template,vsys,name,type,interfaces) VALUES ('$source','$template','$vsys','$zoneName','layer3','$unitname');");
        //$interface="";
        #$projectdb->query("INSERT INTO routes (network,gateway,netmask,metric,project) values ('$network','0.0.0.0','$netmask','$metric','$project');");
    }
    elseif($gateway=="0.0.0.0" && ($flags=="UH" || $flags=="U")){
        // add addresses as static routes
        $ip_version="v4";
        if (validateIpAddress($network,$ip_version)) {

            //$interface = getInterface_from_unitname($interface);

            $routes_count++;
            $name = "Route " . $routes_count;
            $cidr = mask2cidrv4($netmask);
            $addRoutes[] = "('','$source','$vr_id','$template','$ip_version','$name','$network/$cidr','$interface','None','','$metric','$vsys')";
        }
    }
    elseif(($gateway=="0.0.0.0") AND (($flags=="rCGSU") OR ($network!="0.0.0.0"))){
        $zone_count++;
        $zoneName="Zone".$zone_count;
        $cidr=mask2cidrv4($netmask);
        $media="ethernet";
        $unittag=0;
        if ($interface==""){$ethernet1_count++;$interface="ethernet1/".$ethernet1_count;$unitname=$interface;}
        elseif (preg_match("/bond/",$interface)){
            $int_tmp=str_replace("bond","",$interface);
            $int_tmp2=explode(".",$int_tmp);
            if ($int_tmp2[0]==0){$unitname_tmp="1";}else{$unitname_tmp=$int_tmp2[0]+1;}
            if (count($int_tmp2)==1){$unittag=0;}else{$unittag=intval($int_tmp2[1]);}
            $unitname="ae".$unitname_tmp.".".$unit_name_count;
            $interface="ae".$unitname_tmp;

        }
        else{
            $interface=trim($interface);
            $int_tmp2=explode(".",$interface);
            if (count($int_tmp2)==1){$unittag="";}else{$unittag=intval($int_tmp2[1]);}
            $interface=$int_tmp2[0];
            if (($unittag=="") OR ($unittag==0)){
                $unitname=$interface;
            }
            else{
                $unitname=$interface.".".$unittag;
                if (preg_match("/.0$/",$interface)){
                    $int_tmp2=explode(".",$interface);
                    $interface=$int_tmp2[0];
                }
            }

        }

        if(preg_match("/ae/",$interface)) {
            $media="aggregate-ethernet";
            // check if aggregate-ethernet first unittag 0 is created
            $get_ae_interfaces = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='aggregate-ethernet' AND unittag='0' AND unitname='$interface' GROUP BY name ORDER BY name");
            if ($get_ae_interfaces->num_rows === 0) {
                $zone_count++;
                $ae_zone_name = "Zone" . $zone_count;
                $projectdb->query("INSERT INTO interfaces (name,type,media,source,template,vsys,vr_id,unitipaddress,unitname,zone,unittag) VALUES ('$interface','layer3','$media','$source','$template','$vsys','$vr_id','','$interface','$ae_zone_name','0');");
                $projectdb->query("INSERT INTO zones (source,template,vsys,name,type,interfaces) VALUES ('$source','$template','$vsys','$ae_zone_name','layer3','$interface');");
            }
            $unit_name_count++;
        }

        create_or_update_interface($interface,'layer3',$media,$source,$template,$vsys,$vr_id,$network."/".$cidr,$unitname,$zoneName,$unittag);

        //$projectdb->query("INSERT INTO interfaces (name,type,media,source,template,vsys,vr_id,unitipaddress,unitname,zone,unittag) VALUES ('$interface','layer3','$media','$source','$template','$vsys','$vr_id','$network/$cidr','$unitname','$zoneName','$unittag');");
        //$projectdb->query("INSERT INTO zones (source,template,vsys,name,type,interfaces) VALUES ('$source','$template','$vsys','$zoneName','layer3','$unitname');");
        $interface="";
        #$projectdb->query("INSERT INTO routes (network,gateway,netmask,metric,project) values ('$network','0.0.0.0','$netmask','$metric','$project');");
    }
    elseif($is_missing_db_interface){
        // $network contains a string with IPV4/CIDR;IPV6/CIDR
        $zone_count++;
        $zoneName="Zone".$zone_count;
        $media="ethernet";
        $unittag=0;
        if ($interface==""){$ethernet1_count++;$interface="ethernet1/".$ethernet1_count;$unitname=$interface;}
        elseif (preg_match("/bond/",$interface)){
            $int_tmp=str_replace("bond","",$interface);
            $int_tmp2=explode(".",$int_tmp);
            if ($int_tmp2[0]==0){$unitname_tmp="1";}else{$unitname_tmp=$int_tmp2[0]+1;}
            if (count($int_tmp2)==1){$unittag=0;}else{$unittag=intval($int_tmp2[1]);}
            $unitname="ae".$unitname_tmp.".".$unit_name_count;
            $interface="ae".$unitname_tmp;

        }
        else{
            $interface=trim($interface);
            $int_tmp2=explode(".",$interface);
            if (count($int_tmp2)==1){$unittag="";}else{$unittag=intval($int_tmp2[1]);}
            $interface=$int_tmp2[0];
            if (($unittag=="") OR ($unittag==0)){
                $unitname=$interface;
            }
            else{
                $unitname=$interface.".".$unittag;
                if (preg_match("/.0$/",$interface)){
                    $int_tmp2=explode(".",$interface);
                    $interface=$int_tmp2[0];
                }
            }

        }

        if(preg_match("/ae/",$interface)) {
            $media="aggregate-ethernet";
            // check if aggregate-ethernet first unittag 0 is created
            $get_ae_interfaces = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='aggregate-ethernet' AND unittag='0' AND unitname='$interface' GROUP BY name ORDER BY name");
            if ($get_ae_interfaces->num_rows === 0) {
                $zone_count++;
                $ae_zone_name = "Zone" . $zone_count;
                $projectdb->query("INSERT INTO interfaces (name,type,media,source,template,vsys,vr_id,unitipaddress,unitname,zone,unittag) VALUES ('$interface','layer3','$media','$source','$template','$vsys','$vr_id','','$interface','$ae_zone_name','0');");
                $projectdb->query("INSERT INTO zones (source,template,vsys,name,type,interfaces) VALUES ('$source','$template','$vsys','$ae_zone_name','layer3','$interface');");
            }
            $unit_name_count++;
        }

        create_or_update_interface($interface,'layer3',$media,$source,$template,$vsys,$vr_id,$network,$unitname,$zoneName,$unittag);

        //$projectdb->query("INSERT INTO interfaces (name,type,media,source,template,vsys,vr_id,unitipaddress,unitname,zone,unittag) VALUES ('$interface','layer3','$media','$source','$template','$vsys','$vr_id','$network','$unitname','$zoneName','$unittag');");
        //$projectdb->query("INSERT INTO zones (source,template,vsys,name,type,interfaces) VALUES ('$source','$template','$vsys','$zoneName','layer3','$unitname');");
    }
    else {
        $routes_count++;
        $name="Route ".$routes_count;
        $ip_version="v4";
        $cidr=mask2cidrv4($netmask);

        //$interface = getInterface_from_unitname($interface);

        $addRoutes[]="('','$source','$vr_id','$template','$ip_version','$name','$network/$cidr','$interface','ip-address','$gateway','$metric','$vsys')";
    }

}

function getInterface_from_unitname($unitname){
    $interface = $unitname;
    if (preg_match("/.0$/",$unitname)){
        $int_tmp2=explode(".",$unitname);
        $interface=$int_tmp2[0];
    }
    return $interface;
}

function create_or_update_interface ($interface,$layer,$media,$source,$template,$vsys,$vr_id,$network_cidr,$unitname,$zoneName,$unittag) {
    global $projectdb;
    $getDups=$projectdb->query("SELECT id,unitipaddress FROM interfaces WHERE template='$template' AND source='$source' AND vsys='$vsys' AND name='$interface' AND unittag='$unittag'; ");
    if ($getDups->num_rows>0) {
        $getDupsData=$getDups->fetch_assoc();
        $id=$getDupsData['id'];
        $ips= explode(',',$getDupsData['unitipaddress']);
        $ips[]=$network_cidr;
        $ips = array_filter($ips); // remove empty entries if exist
        asort($ips); // order entries
        $ips_text = implode(",", $ips);
        $update_query = "UPDATE interfaces set unitipaddress='$ips_text' WHERE id = '" . $id . "' AND source='$source';";
        $projectdb->query($update_query);
    }else {
        $projectdb->query("INSERT INTO interfaces (name,type,media,source,template,vsys,vr_id,unitipaddress,unitname,zone,unittag) VALUES ('$interface','$layer','$media','$source','$template','$vsys','$vr_id','$network_cidr','$unitname','$zoneName','$unittag');");
        $projectdb->query("INSERT INTO zones (source,template,vsys,name,type,interfaces) VALUES ('$source','$template','$vsys','$zoneName','$layer','$unitname');");
    }
}

function remove_duplicated_zones($source,$vsys){
    global $projectdb;
    $getDups=$projectdb->query("SELECT id,count(id) AS t FROM security_rules_to WHERE source='$source' AND vsys='$vsys' GROUP BY name,rule_lid,source,vsys having t>1; ");
    if ($getDups->num_rows>0){
        $remove=array();
        while($getDupsData=$getDups->fetch_assoc()){
            $remove[]=$getDupsData['id'];
        }
        $projectdb->query("DELETE FROM security_rules_to WHERE id IN (".implode(",",$remove).")");
    }


}

function split_user_security_rules_by_source($source, $vsys, $project){

    // This method will check for sec rules that had originaly as source both: address and user.
    // In that case we will clone the rule so the first rule is containing the user and the second one is containing the address

    global $projectdb;
    // check if the rule has as source a user and an address
    $query_sec_rules = "select u.rule_lid from security_rules_usr u, security_rules_src s where u.rule_lid = s.rule_lid;";
    $query_sec_rules_result=$projectdb->query($query_sec_rules);
    if($query_sec_rules_result->num_rows>0){
        while ($query_sec_rules_data = $query_sec_rules_result->fetch_assoc()){
            $sec_rule_to_clone = $query_sec_rules_data['rule_lid'];
            $sec_rule_cloned  = clone_security_rule("", "", $vsys, $source, $sec_rule_to_clone, "", $project);

            $projectdb->query("DELETE from security_rules_src where rule_lid = $sec_rule_to_clone;");
            $projectdb->query("DELETE from security_rules_usr where rule_lid = $sec_rule_cloned;");

        }
    }
}

function get_security_policies(ARRAY $myRules, $source, $vsys, $filename, $getObjects, $skipDNAT, $globalDisabled= false){
    global $projectdb;
    global $jobid;
    global $project;
    global $domain;

    # Split the Objects from getObjects Array;
    $common=$zones=$objects=$schedules=$accessLayers=$accesRoles=$unsupportedObjects=array();

    if (isset($getObjects['common'])){
        $common=$getObjects['common'];
    }

    if (isset($getObjects['objects'])){
        $objects=$getObjects['objects'];
    }

    if (isset($getObjects['schedules'])){
        $schedules=$getObjects['schedules'];
    }

    if (isset($getObjects['accessLayers'])){
        $accessLayers=$getObjects['accessLayers'];
    }

    if (isset($getObjects['accessRole'])){
        $accesRoles=$getObjects['accessRole'];
    }

    if (isset($getObjects['zones'])){
        $zones=$getObjects['zones'];
    }

    if (isset($getObjects['unsupportedObjects'])){
        $unsupportedObjects=$getObjects['unsupportedObjects'];
    }

    #Get Last lid from Rules
    $getlastlid=$projectdb->query("SELECT max(id) as max FROM security_rules;");
    $getLID1=$getlastlid->fetch_assoc();
    $lid=intval($getLID1['max'])+1;
    $getlastlid=$projectdb->query("SELECT max(position) as max FROM security_rules WHERE source='$source' AND vsys='$vsys';");
    $getLID1=$getlastlid->fetch_assoc();
    $position=intval($getLID1['max'])+1;
    $uniqueRules=array();
    $add_tag=array();
    $add_rule=array();
    $add_rule_usr=array();
    $rule_From=array();
    $rule_To=array();
    $rule_source=array();
    $rule_destination=array();
    $rule_service=array();
    $rule_target=array();
    $thecolor=1;

    $ruleTags = array();

    foreach($myRules as $rule){

        if (isset($rule['header'])){
            if ($rule['header']==""){
                $name="";
            }
            else{
                $name=$rule['header'];
            }
        }
        else{
            $name="";
        }
        $type=$rule['type'];

        switch($type){
            case "access-section":
                $ruleSection=$rule;
                $ruleFrom = 0;
                $ruleTo = 0;

                if(isset($ruleSection['from']) && $ruleSection['from']!=''){
                    $ruleFrom = $ruleSection['from'];
                }
                if(isset($ruleSection['to']) && $ruleSection['to']!=''){
                    $ruleTo = $ruleSection['to'];
                }

                //if ((isset($ruleSection['rulebase'])) AND (count($ruleSection['rulebase'])>0)){
                    $color="color".$thecolor;

                    if (isset($ruleSection['name'])){
                        $name=truncate_tags($ruleSection['name']);
                        $tag_id=add_tag($name,$source,$vsys,$color);
                        if ($thecolor==16){$thecolor=1;}else {$thecolor++;}
                    }
                    else{
                        $tag_id="";
                    }

                    if(isset($ruleSection['rulebase'])) {
                        foreach ($ruleSection['rulebase'] as $ruleItem) {
                            insert_security_policy($unsupportedObjects,$skipDNAT, $ruleItem, $tag_id, $source, $vsys, $lid, $position, $add_rule, $add_rule_usr, $name, $thecolor, $add_tag,
                                $rule_From, $rule_To,$rule_source, $rule_destination, $rule_service, $zones, $objects, $accesRoles, $schedules, $accessLayers, $domain, $jobid,
                                $project, $common, $uniqueRules, $globalDisabled);
                        }
                    }
                    else{
                        echo "Rule $name does not have a ruleBase section\n";
                    }
                //}

                for($i=$ruleFrom; $i<=$ruleTo; $i++){
                    $ruleTags[$i] = $tag_id;
                }

                break;
            case "access-rule":
                $rule_number = $rule['rule-number'];
                if(isset($ruleTags[$rule_number])){
                    $tag_id = $ruleTags[$rule_number];
                }
                else{
                    $tag_id = '';
                }
                insert_security_policy($unsupportedObjects,$skipDNAT, $rule,$tag_id,$source,$vsys,$lid,$position,$add_rule,$add_rule_usr,$name,$thecolor,$add_tag,
                    $rule_From, $rule_To, $rule_source,$rule_destination,$rule_service, $zones, $objects,$accesRoles,$schedules,$accessLayers,$domain,$jobid,
                    $project,$common,$uniqueRules, $globalDisabled);

                break;
            default:
                //print_r($rule);
                break;
        }
    }

    if (count($add_rule)>0){
        $unique=array_unique($add_rule);
        $projectdb->query("INSERT INTO security_rules (id,disabled,negate_source,negate_destination,action,target,name,description,source,vsys,position,preorpost,checkit) VALUES ".implode(",",$unique).";");
        unset($add_rule);unset($unique);
    }

    if (count($add_rule_usr)>0){
        $unique=array_unique($add_rule_usr);
        $projectdb->query("INSERT INTO security_rules_usr (source,vsys,rule_lid,name,counter) VALUES ".implode(",",$unique).";");
        unset($add_rule_usr);unset($unique);
    }

    if (count($add_tag)>0){
        $unique=array_unique($add_tag);
        $projectdb->query("INSERT INTO security_rules_tag (rule_lid,source,member_lid,table_name,vsys) VALUES ".implode(",",$unique).";");
        unset($add_tag);unset($unique);
    }

    if (count($rule_From)>0){
        $unique=array_unique($rule_From);
        $projectdb->query("INSERT INTO security_rules_from (source,vsys,name,rule_lid) VALUES ".implode(",",$unique).";");
        unset($rule_From);unset($unique);
    }
    if (count($rule_To)>0){
        $unique=array_unique($rule_To);
        $projectdb->query("INSERT INTO security_rules_to (source,vsys,name,rule_lid) VALUES ".implode(",",$unique).";");
        unset($rule_To);unset($unique);
    }

    if (count($rule_source)>0){
        $unique=array_unique($rule_source);
        $projectdb->query("INSERT INTO security_rules_src (source,vsys,rule_lid,table_name,member_lid) VALUES ".implode(",",$unique).";");
        unset($rule_source);unset($unique);
    }
    if (count($rule_destination)>0){
        $unique=array_unique($rule_destination);
        $projectdb->query("INSERT INTO security_rules_dst (source,vsys,rule_lid,table_name,member_lid) VALUES ".implode(",",$unique).";");
        unset($rule_destination);unset($unique);
    }
    if (count($rule_service)>0){
        $unique=array_unique($rule_service);
        $projectdb->query("INSERT INTO security_rules_srv (source,vsys,rule_lid,table_name,member_lid) VALUES ".implode(",",$unique).";");
        unset($rule_service); unset($unique);
    }
    if (count($rule_target)>0){
        $unique=array_unique($rule_target);
        echo "INSERT INTO security_rules_target (source,vsys,rule_lid,table_name,member_lid) VALUES ".implode(",",$unique).";\n";
        $projectdb->query("INSERT INTO security_rules_target (source,vsys,rule_lid,table_name,member_lid) VALUES ".implode(",",$unique).";");
        unset($rule_destination);unset($unique);
    }
}

function getUnsupportedItem($unsupportedObjects, $key){
    if(isset($unsupportedObjects[$key])){
        $unsupportedItem= $unsupportedObjects[$key]['name'] . " | " . $unsupportedObjects[$key]['type'] . " | " . $unsupportedObjects[$key]['uid'];
    }else{
        $unsupportedItem=$key;
    }
    return $unsupportedItem;
}

function insert_security_policy($unsupportedObjects,$skipDNAT, $ruleItem,$tag_id_section,$source,$vsys,&$lid,&$position, &$add_rule, &$add_rule_usr, $name,&$thecolor,&$add_tag, &$allRule_From, &$allRule_To, &$allRule_source,
                                &$allRule_destination,&$rule_service, $zones, $objects,$accesRoles,$schedules,$accessLayers,$domain,$jobid,$project,$common,&$uniqueRules, $globalDisabled=false,
                                $rule_origFrom=array(),$rule_origTo=array(), $rule_origSource=array(), $rule_origDest=array(), $rule_origServ=array(),$rule_negated_source=0, $rule_negated_destination=0){

    global $projectdb;
    $rule_localSource = array();
    $rule_localDest   = array();
    $rule_localServ   = array();
    $rule_localFrom   = array();
    $rule_localTo     = array();

    $exists = $projectdb->query("SELECT id FROM tag WHERE name IN ('Time Object') AND source='$source' AND vsys='shared';");
    if ($exists->num_rows !== 1) {
        $tag_color = "color".$thecolor;
        $thecolor++;
        if ($thecolor==16){$thecolor=1;}else {$thecolor++;}
        $projectdb->query("INSERT INTO tag (name_ext,name,color,vsys,source,devicegroup, used) VALUES ('Time Object','Time Object','$tag_color','shared','$source','default',1);");
        $TimeObject_tagId = $projectdb->insert_id;
    }
    else{
        $data = $exists->fetch_assoc();
        $TimeObject_tagId = $data['id'];
    }

    // Prepare DNAT tag
    $query = "SELECT * FROM tag WHERE source='$source' AND vsys='$vsys' AND BINARY name='DNAT'";
    $result = $projectdb->query($query);
    if($result->num_rows==0){
        $tag_color = "color".$thecolor;
        $thecolor++;
        if ($thecolor==16){$thecolor=1;}else {$thecolor++;}
        $query = "INSERT INTO tag (source,vsys,name, color) VALUES ('$source', '$vsys','DNAT','$tag_color')";
        $projectdb->query($query);
        $tag_dnat_id = $projectdb->insert_id;
    }
    else{
        $data = $result->fetch_assoc();
        $tag_dnat_id = $data['id'];
    }

    if (isset($common["any"])){$any=trim($common["any"]);}else{$any="-1";}
    if (isset($common["all"])){$all=trim($common["all"]);}else{$all="-1";}

    $rule_origins = array();
    $rule_destinations=  array();
    $rule_services = array();
    $rule_zonesFrom=array();
    $rule_zonesTo=array();

    $uuid=$ruleItem['uid'];
    if (!isset($uniqueRules[$uuid])){
        $uniqueRules[$uuid]=$uuid;
        if ($ruleItem['type']=="access-rule"){
            $preorpost=0;
            $checkit=0;

            if ($name!=""){
                $color="color".$thecolor;
                $tag_id=add_tag($name,$source,$vsys,$color);
                if ($thecolor==16){$thecolor=1;}else {$thecolor++;}
            }
            else{
                $tag_id="";
            }

            if ($ruleItem['action']){
                $action_tmp=array_search($ruleItem['action'],$common);
                if ($action_tmp!==false){
                    $action=$action_tmp;
                    if($action === "deny"){
                        add_log2("info",
                            "Importing Security Rules",
                            "\'Reject\' action converted into \'deny\'",
                            $source,
                            "Review",
                            "rules",
                            $lid,
                            "security_rules");
                    }
                }
                else{
                    # Create Error action is not in common and add action = deny
                    $action="deny";
                    $checkit=1;
                    add_log2("info","Importing Security Rules","\'".$ruleItem['action']."\' action not recognized and converted into \'deny\'", $source,"Review","rules",$lid,"security_rules");
                }
            }

            $ruleNumber=trim($ruleItem['rule-number']);

            if (!isset($ruleItem['name']) || $ruleItem['name'] == ""){
                $ruleName=truncate_rulenames("Rule ".$ruleNumber);
            }
            else{
                $ruleName=truncate_rulenames(normalizeNames(trim($ruleItem['name'])));
            }

            if(isset($ruleItem['install-on'])){
                $ruleTargetArr = array();
                foreach ($ruleItem['install-on'] as $targetID){
                    if (isset($objects[$targetID])) {
                        if(!isset($objects[$targetID]['name'])){
                            $table_name = $objects[$targetID]['table_name'];
                            $member_lid = $objects[$targetID]['member_lid'];
                            $query ="SELECT name FROM $table_name WHERE id = '$member_lid' LIMIT 1";
                            $result = $projectdb->query($query);
                            if($projectdb->affected_rows>0) {
                                $data = $result->fetch_assoc();
                                $objects[$targetID]['name'] = $data['name'];
                            }
                        }
                        $ruleTargetArr[] = $objects[$targetID]['name'];
                    }
                    elseif(isset($common['Policy Targets']) && $common['Policy Targets']==$targetID){
                        //echo "This rule installs in global\n";
                    }
                    else{
                        echo "TARGET OBJECT NOT FOUND as INSTALL-ON: $targetID".PHP_EOL;
                        add_log2("info","Importing Security Rules","Target object not found as Install-On: $targetID", $source,"Review","rules",$lid,"security_rules");
                    }
                }

            }
            else{
            }
            $ruleTarget = implode(", ", $ruleTargetArr);

            $break_pattern = "(\n+)";

            $comments=addslashes(preg_replace($break_pattern,"<br/>",$ruleItem['comments']));
//            if($ruleItem['comments'] != $comments) {
//                echo "DISTINCT:\n";
//                echo $ruleItem['comments'] . PHP_EOL;
//                echo $comments . PHP_EOL;
//                echo "\n";
//            }
            $comments = str_replace("<br/>","\\n", $comments);
            #$comments=addslashes($ruleItem['comments']);
            if ($tag_id!=""){$add_tag[]="('$lid','$source','$tag_id','tag','$vsys')";}
            if ($tag_id_section!=""){$add_tag[]="('$lid','$source','$tag_id_section','tag','$vsys')";}
            if ($ruleItem['source-negate']===false){$negate_source=0;}else{$negate_source=1;}
            if ($ruleItem['source']){
                foreach ($ruleItem['source'] as $src){
                    if ($src!=$any){
                        if ($ruleNumber==1){
                           // print_r($src);
                        }

                        if (isset($accesRoles[$src])){
                            if(isset($accesRoles[$src]['dn'])) {
                                add_log2("warning", "Importing Security Rules", "Security Rule[$lid] includes a source[$src] defined as user", $source, 'Review user', "rules", $lid, "security_rules");
                                $userMapping[$lid][] = $accesRoles[$src]['dn'];
                            } else {
                                add_log2("error","Importing Security Rules","Security Rule[$lid] includes a source[$src] defined as user without proper DN assigned",$source,'Add user',"rules",$lid,"security_rules");
                            }
                        }
                        elseif (isset($objects[$src])){
                            $table_name=$objects[$src]['table_name'];
                            $member_lid=$objects[$src]['member_lid'];

                            $rule_localSource[]= "('$source','$vsys','$lid','$table_name','$member_lid')";

                            if($table_name=="address"){
                                $member_ipaddress=$objects[$src]['ipaddress'];
                                $member_cidr=$objects[$src]['cidr'];
                                $member = new MemberObject($member_lid, $table_name, $member_ipaddress, $member_cidr);

                                $rule_origins[] = $member;
                            }
                            else{
                                $member = new MemberObject($member_lid, $table_name);
                                $rule_origins[] = $member;
                            }

                        }
                        elseif(isset($zones[$src])){
                            $zoneName = $zones[$src];
                            $rule_localFrom[] = "('$source', '$vsys', '$zoneName','$lid')";
                            $rule_zonesFrom[] = $zoneName;
                        }
                        else{
                            $checkit=1;
                            // add log on monitor
                            $unsupportedItem=getUnsupportedItem($unsupportedObjects, $src);
                            add_log2("warning","Importing Security Rules","Security Rule[$lid] includes a source[$unsupportedItem] not found as supported object",$source,'Review',"rules",$lid,"security_rules");
                            echo "OBJECT NOT FOUND as SOURCE: $src".PHP_EOL;
                        }
                    }
                }
                if ($negate_source==1){
                    //echo "ORIGINAL SOURCE:".PHP_EOL;
                    //print_r($rule_origins);
                    //echo "NEGATING IT".PHP_EOL;
                    //print_r(negateAddress($projectdb,$rule_origins));

                }
            }

            if ($ruleItem['destination-negate']===false){$negate_destination=0;}else{$negate_destination=1;}
            if ($ruleItem['destination']){
                foreach ($ruleItem['destination'] as $src){
                    if ($src!=$any){

                        if (isset($accesRoles[$src])){
                            echo "USER AS DESTINATION on rule: ". $ruleName .PHP_EOL;
                            $unsupportedItem=getUnsupportedItem($unsupportedObjects, $src);
                            if(isset($accesRoles[$src]['dn'])) {
                                add_log2("warning", "Importing Security Rules", "Security Rule[$lid] includes a destination[$unsupportedItem] defined as user", $source, 'Review user', "rules", $lid, "security_rules");
                                $userMapping[$lid][] = $accesRoles[$src]['dn'];
                            } else {
                                add_log2("error","Importing Security Rules","Security Rule[$lid] includes a destination[$unsupportedItem] defined as user without proper DN assigned",$source,'Add user',"rules",$lid,"security_rules");
                            }

                        }
                        elseif (isset($objects[$src])){
                            $table_name=$objects[$src]['table_name'];
                            $member_lid=$objects[$src]['member_lid'];

                            $rule_localDest[]="('$source','$vsys','$lid','$table_name','$member_lid')";

                            if($table_name=="address"){
                                $member_ipaddress=$objects[$src]['ipaddress'];
                                $member_cidr=$objects[$src]['cidr'];
                                $member = new MemberObject($member_lid, $table_name, $member_ipaddress, $member_cidr);
                                $rule_destinations[] = $member;
                            }
                            else{
                                $member = new MemberObject($member_lid, $table_name);
                                $rule_destinations[] = $member;
                            }

                            // Check if SkipNAT is enabled && object destination has a defined NAT to be added as
                            // destination address into the security rule
                            if(!$skipDNAT && isset($objects[$src]["nat"]["translated"]["member_lid"])){
                                // add log on monitor
                                add_log2("warning","Correcting Destination based on DNAT","Security Rule[$lid] includes an AutoNat destination object. Adding both addresses as destinations.",$source,'No Action required',"rules",$lid,"security_rules");

                                // get translated destination information
                                $dest_nat_member_lid = $objects[$src]["nat"]["translated"]["member_lid"];
                                $dest_nat_table_name = $objects[$src]["nat"]["translated"]["table_name"];

                                $rule_localDest[]="('$source','$vsys','$lid','$dest_nat_table_name','$dest_nat_member_lid')";
                                $add_tag[]="('$lid','$source','$tag_dnat_id','tag','$vsys')";

                                // translated destination is a simple address
                                if($dest_nat_table_name=="address"){
                                    // search into the objects array for the translated IP destination
                                    foreach ($objects as $ipaddress => $item){

                                        if((int)$item["member_lid"] === $dest_nat_member_lid){
                                            // when found create a new member and add into the rules destinations
                                            $dest_nat_member_ipaddress=$ipaddress;
                                            $nat_member = new MemberObject($dest_nat_member_lid, $dest_nat_table_name, $dest_nat_member_ipaddress, "32");
                                            $rule_destinations[] = $nat_member;
                                            break;
                                        }

                                    }

                                }
                                else{
                                    // translated destination is a not an address
                                    $nat_member = new MemberObject($dest_nat_member_lid, $dest_nat_table_name);
                                    $rule_destinations[] = $nat_member;
                                }

                            }


                        }
                        elseif(isset($zones[$src])){
                            $zoneName = $zones[$src];
                            $rule_localTo[] = "('$source', '$vsys', '$zoneName','$lid')";
                            $rule_zonesTo[] = $zoneName;
                        }
                        else{
                            // add log on monitor
                            $checkit = 1;
                            $unsupportedItem=getUnsupportedItem($unsupportedObjects, $src);
                            add_log2("warning","Importing Security Rules","Security Rule[$lid] includes a destination[$unsupportedItem] not found as supported object",$source,'Review',"rules",$lid,"security_rules");
                            echo "OBJECT NOT FOUND as DESTINATION: ".$src.PHP_EOL;
                        }
                        //list($member_lid,$table_name)=getMemberlid("address",$src,$source,$vsys,'Security',$lid);
                        //$allRule_destination[]="('$source','$vsys','$lid','$table_name','$member_lid')";

                    }
                }
                if ($negate_destination==1){
                    //echo "ORIGINAL SOURCE:".PHP_EOL;
                    //print_r($rule_destinations);
                    //echo "NEGATING IT".PHP_EOL;
                    //print_r(negateAddress($projectdb,$rule_destinations));

                }
            }
            if ($ruleItem['time']){
                foreach ($ruleItem['time'] as $src){
                    if ( $src==$any || $src==$all ){}
                    else{
                        add_log2("error","Importing Security Rules","Time object found [".$schedules[$src]."] in Rule [".$lid."]",$source,"Fix it Manually","rules",$lid,"security_rules");
                        $query = "INSERT INTO security_rules_tag (source, member_lid, table_name, rule_lid, vsys) VALUES ('$source','$TimeObject_tagId','tag','$lid', '$vsys')";
                        $projectdb->query($query);
                        break; //Only add one Time Object tag and warning.
                    }
                }
            }
            if ($ruleItem['service']){
                foreach ($ruleItem['service'] as $src){
                    if ($src!=$any){
                        if (isset($objects[$src])){
                            $table_name=$objects[$src]['table_name'];
                            $member_lid=$objects[$src]['member_lid'];
                            $rule_localServ[]="('$source','$vsys','$lid','$table_name','$member_lid')";
                        }
                        else{
                            $checkit = 1;
                            $unsupportedItem=getUnsupportedItem($unsupportedObjects, $src);
                            add_log2("warning","Importing Security Rules","Security Rule[$lid] includes a service not found as supported object [$unsupportedItem]",$source,'Review',"rules",$lid,"security_rules");
                            echo "OBJECT NOT FOUND as SERVICE: ".$src.PHP_EOL;
                        }
                        //list($member_lid,$table_name)=getMemberlid("services",$src,$source,$vsys,'Security',$lid);
                        //$rule_service[]="('$source','$vsys','$lid','$table_name','$member_lid')";
                    }
                }
            }
            if ($ruleItem['service-negate']===true){
                # Generate Error Negated Service is not supported
                add_log2("error","Importing Security Rules","Negated Service found in Rule [".$lid."]",$source,"Fix it Manually","rules",$lid,"security_rules");
                $checkit=1;
            }
            if($globalDisabled) $rule_disabled=1;
            else {
                if ($ruleItem['enabled'] === true) {
                    $rule_disabled = 0;
                } else {
                    $rule_disabled = 1;
                }
            }

            if(count($rule_localFrom)==0){
                foreach ($rule_origFrom as $item){
                    $allRule_From[]="('$source', '$vsys', '$item','$lid')";
                }
            }
            else{
                //Intersect
                //TODO
                $allRule_From = array_merge($allRule_From, $rule_localFrom);
            }

            if(count($rule_localSource)==0){
                foreach ($rule_origSource as $item){
                    $allRule_source[]="('$source','$vsys','$lid','$item->location','$item->name')";
                }
                //if src is any and parent rule defines a negated source then get it
                if($rule_negated_source){$negate_source=1;}
            }
            else{
                //Intersect sources
                //TODO
                $allRule_source = array_merge($allRule_source, $rule_localSource);
                //if src is NOT any and parent rule defines a negated source then generate a warning
                if($rule_negated_source) {
                    add_log2("info", "Importing Security Rules", "Source parent rule is negated please check destination address objects", $source, "Review", "rules", $lid, "security_rules");
                }
            }

            if(count($rule_localTo)==0){
                foreach ($rule_origTo as $item) {
                    $allRule_To[] = "('$source', '$vsys', '$item','$lid')";
                }
            }
            else{
                //Intersect
                //TODO
                $allRule_To = array_merge($allRule_To, $rule_localTo);
            }

            if(count($rule_localDest)==0){
                foreach ($rule_origDest as $item){
                    $allRule_destination[]="('$source','$vsys','$lid','$item->location','$item->name')";
                }
                //if dst is any and parent rule defines a negated destination then get it
                if($rule_negated_destination){$negate_destination=1;}
            }
            else{
                //Intersect destinations
                $allRule_destination = array_merge($allRule_destination, $rule_localDest);
                //if dst is NOT any and parent rule defines a negated destination then generate a warning
                if($rule_negated_destination) {
                    add_log2("info", "Importing Security Rules", "Destination parent rule is negated please check destination address objects", $source, "Review", "rules", $lid, "security_rules");
                }
            }

            if(count($rule_localServ)==0){
                foreach ($rule_origServ as $item){
                    $rule_service[]="('$source','$vsys','$lid','$item->location','$item->name')";
                }
            }
            else{
                //Intersect services
                $rule_service = array_merge($rule_service, $rule_localServ);
            }

            if ((isset($ruleItem['inline-layer'])) AND (isset($accessLayers[$ruleItem['inline-layer']]))){
                $rule_disabled=0;
                $add_rule[]="('$lid','1','$negate_source','$negate_destination','allow','$ruleTarget','$ruleName','(Parent Rule for In-line policy) $comments','$source','$vsys','$position','$preorpost','$checkit')";
                $lid++; $position++;

                $policy2load=$accessLayers[$ruleItem['inline-layer']]['name']."-".$domain.".html";
                echo "Loading Inline Rules from: ".$policy2load." (".$ruleItem['inline-layer'].")\n";
                $loadInlineRules=load_policy($policy2load,$project,$jobid);

                get_sub_policy($unsupportedObjects,$skipDNAT, $loadInlineRules, $ruleName, $rule_disabled, $tagids, $vsys,
                    $source, $project, $rule_zonesFrom,$rule_zonesTo, $rule_origins, $rule_destinations, $rule_services,
                    $add_rule, $allRule_From, $allRule_To,$allRule_source, $allRule_destination, $rule_service, $addTag, $comments,$zones, $objects,$accesRoles,$schedules,$accessLayers,$common,$lid,$position,$add_rule_usr,
                    $globalDisabled, $negate_source, $negate_destination);
            }
            else{
                $add_rule[]="('$lid','$rule_disabled','$negate_source','$negate_destination','$action','$ruleTarget','$ruleName','$comments','$source','$vsys','$position','$preorpost','$checkit')";
                // rule contains users as source or destination
                if(isset($userMapping[$lid])){
                    // create and entry on table security_rules_usr
                    // fields source, vsys, name, rule_lid, counter
                    foreach ($userMapping[$lid] as $rule_users) {
                        foreach ($rule_users as $rule_user) {
                            $add_rule_usr[] = "('$source','$vsys','$lid','$rule_user','0')";
                        }
                    }
                }

                $lid++; $position++;
            }
        }
    }
}

function get_sub_policy($unsupportedObjects,$skipDNAT, $loadInlineRules, $ruleName, $rule_enabled, &$tagids, $vsys,
        $source, $project, $rule_origFrom,$rule_origTo,$rule_origSource, $rule_origDest, $rule_OrigServ,
        &$add_rule, &$rule_From, &$rule_To, &$rule_source, &$rule_destination, &$rule_service, &$addTag, &$comments,$zones, $objects,$accesRoles,$schedules,$accessLayers,$common,&$lid,&$position,&$add_rule_usr, $globalDisabled=false,$rule_negated_source=0, $rule_negated_destination=0){

    global $projectdb;
    global $thecolor;
    global $jobid;
    global $domain;

    //Defining variables I will globally use in this function
    $resultingSourceMembers = null;
    $resultingDestinationMembers = null;
    $resultingServices = null;

    /*echo "Entering in Subpolicy".PHP_EOL;
    echo "ORIGINAL SOURCES"; print_r($rule_origSource);
    echo "ORIGINAL DESTINATIONS"; print_r($rule_origDest);
    echo "ORIGINAL SERVICE"; print_r($rule_OrigServ);
*/
    foreach($loadInlineRules as $rule){

        if (isset($rule['header'])){
            if ($rule['header']==""){
                $name="";
            }
            else{
                $name=$rule['header'];
            }
        }
        else{
            $name="";
        }
        $type=$rule['type'];

        switch($type){
            case "access-section":
                $ruleSection=$rule;
                if ((isset($ruleSection['rulebase'])) AND (count($ruleSection['rulebase'])>0)){
                    $color="color".$thecolor;

                    if (isset($ruleSection['name'])){
                        $name=truncate_tags($ruleSection['name']);
                        $tag_id=add_tag($name,$source,$vsys,$color);
                        if ($thecolor==16){$thecolor=1;}else {$thecolor++;}
                    }
                    else{
                        $tag_id="";
                    }

                    foreach ($ruleSection['rulebase'] as $ruleItem){
                        insert_security_policy($unsupportedObjects,$skipDNAT, $ruleItem,$tag_id,$source,$vsys,$lid,$position,$add_rule,$add_rule_usr, $name,$thecolor,$add_tag,
                            $rule_From, $rule_To,$rule_source,$rule_destination,$rule_service, $zones, $objects,$accesRoles,$schedules,$accessLayers,$domain,$jobid,
                            $project,$common,$uniqueRules, $globalDisabled, $rule_origFrom,$rule_origTo,$rule_origSource, $rule_origDest, $rule_OrigServ, $rule_negated_source, $rule_negated_destination);
                    }
                }
                break;
            case "access-rule":
                insert_security_policy($unsupportedObjects,$skipDNAT, $rule,"",$source,$vsys,$lid,$position,$add_rule,$add_rule_usr, $name,$thecolor,$add_tag,
                    $rule_From, $rule_To,$rule_source,$rule_destination,$rule_service, $zones, $objects,$accesRoles,$schedules,$accessLayers,$domain,$jobid,
                    $project,$common,$uniqueRules, $globalDisabled, $rule_origFrom,$rule_origTo,$rule_origSource, $rule_origDest, $rule_OrigServ,$rule_negated_source, $rule_negated_destination);

                break;
            default:
                echo "UNCAUGHT!!! ->>>".PHP_EOL;
                //print_r($rule);
                break;
        }
    }





}

function add_tag($name,$source,$vsys,$color){
    global $projectdb;
    $name=normalizeNames($name);
    $exist=$projectdb->query("SELECT id FROM tag WHERE name='$name' AND source='$source' AND vsys='$vsys'");
    if ($exist->num_rows==0){
        $projectdb->query("INSERT INTO tag (name,source,vsys,color) VALUES ('$name','$source','$vsys','$color');");
        $id=$projectdb->insert_id;
    }
    else{
        $existsData=$exist->fetch_assoc();
        $id=$existsData['id'];
    }
    return $id;
}

function add_tag_relations($table_name,$member_lid,$tag_id){
    global $projectdb;

    $exist=$projectdb->query("SELECT id FROM tag_relations WHERE table_name='$table_name' AND member_lid='$member_lid'");
    if ($exist->num_rows==0){
        $projectdb->query("INSERT INTO tag_relations (table_name,member_lid,tag_id) VALUES ('$table_name','$member_lid','$tag_id');");
        $id=$projectdb->insert_id;
    }
    else{
        $existsData=$exist->fetch_assoc();
        $id=$existsData['id'];
    }
    return $id;
}

function calculateExclusionGroups($source,&$getObjects){

    global $projectdb;

    $getLid = $projectdb->query("SELECT id, vsys, source, devicegroup FROM address_groups_id WHERE type = 'group_with_exclusion' AND source='$source';");

    if ($getLid->num_rows > 0) {
        while ($dataLid = $getLid->fetch_assoc()) {
            $lid = $dataLid['id'];
            $vsys = $dataLid['vsys'];
            $source = $dataLid['source'];
            $devicegroup = $dataLid['devicegroup'];

            $incGroupExpanded = array();
            $exclGroupExpanded = array();
            $res = array();

            $incGroupExpanded_p = expandMembersGroups($lid, "1");
            $exclGroupExpanded_p = expandMembersGroups($lid, "4");

            // create IP mappings for all objects
            foreach($incGroupExpanded_p as $index => $object){

                if($object['table_name'] == "address_groups_id"){
                    $incGroupExpanded = expandMembersGroups($object['member_lid'], "3");
                    foreach($incGroupExpanded as $index2 => $object2){

                        $res = resolveIP_Start_End($object2['member'], $object2['member_lid'], $object2['table_name']);

                        $incGroupExpanded[$index2] = Array('object'=>$object2['member'], 'member_lid'=>$object2['member_lid'], 'table_name'=>$object2['table_name'], 'start'=>$res['start'],
                            'end'=>$res['end'], 'startip'=>long2ip($res['start']),'endip'=>long2ip($res['end']), 'status'=>0);

                    }

                }
                else{

                    $res = resolveIP_Start_End($object['member'], $object['member_lid'], $object['table_name']);

                    $incGroupExpanded[$index] = Array('object'=>$object['member'], 'member_lid'=>$object['member_lid'], 'table_name'=>$object['table_name'], 'start'=>$res['start'],
                        'end'=>$res['end'], 'startip'=>long2ip($res['start']),'endip'=>long2ip($res['end']), 'status'=>0);
                }
            }

            foreach($exclGroupExpanded_p as $index => $object){

                if($object['table_name'] == "address_groups_id"){
                    $exclGroupExpanded = expandMembersGroups($object['member_lid'], "3");

                    foreach($exclGroupExpanded as $index => $object2){

                        $res = resolveIP_Start_End($object2['member'], $object2['member_lid'], $object2['table_name']);

                        $exclGroupExpanded[$index] = Array('object'=>$object2['member'], 'member_lid'=>$object2['member_lid'], 'table_name'=>$object2['table_name'], 'start'=>$res['start'],
                            'end'=>$res['end'], 'startip'=>long2ip($res['start']),'endip'=>long2ip($res['end']) );

                    }

                }
                else{

                    $res = resolveIP_Start_End($object['member'], $object['member_lid'], $object['table_name']);

                    $exclGroupExpanded[$index] = Array('object'=>$object['member'], 'member_lid'=>$object['member_lid'], 'table_name'=>$object['table_name'], 'start'=>$res['start'],
                        'end'=>$res['end'], 'startip'=>long2ip($res['start']),'endip'=>long2ip($res['end']) );
                }
            }

            // Check if exclusion group is empty so all included objects shall be set to be included
            if(count($exclGroupExpanded)<=0){
                foreach($incGroupExpanded as &$incl) {
                    $incl['status'] = 1;
                }
            }
            //  Now we need to match all excl vs inc objects
            foreach($exclGroupExpanded as $index => &$excl){
                foreach($incGroupExpanded as &$incl){
                    // this object was already fully matched so we skip
                    if($incl['status'] == 2) continue;
                    if($incl['start'] >= $excl['start'] && $incl['end'] <= $excl['end']){
                        $incl['status'] = 2;
                    }
                    elseif( $incl['start'] >= $excl['start'] &&  $incl['start'] <= $excl['end'] || $incl['end'] >= $excl['start'] && $incl['end'] <= $excl['end']
                        || $incl['start'] <= $excl['start'] && $incl['end'] >= $excl['end'] ){
                        $incl['status'] = 1;
                    }
                }
            }//fin foreach

            // First filter is done, now we make a list of Incl objects :
            // - Partial matches, these ones will require special treatment
            // - FULL matches, these ones will not be included in final group
            // - NO matches, these ones will be included in final group
            $inclPartial = Array();
            $inclNo = Array();


            foreach( $incGroupExpanded as &$incl ){

                if(($incl['status'] == 1 ) || ($incl['status'] == 2)){
                    $inclPartial[] = &$incl;
                }elseif( $incl['status'] == 0 ){
                    $inclNo[] = &$incl;
                }
            }

            // Sort incl objects IP mappings by Start IP
            $inclMapping = Array();
            $tmp = Array();
            foreach($inclPartial as &$incl){
                $tmp[] = $incl['start'];
            }
            unset($incl);
            sort($tmp, SORT_NUMERIC);
            foreach($tmp as $value){
                foreach($inclPartial as &$incl){
                    if( $value == $incl['start'] ){
                        $inclMapping[] = $incl;
                    }
                }
            }
            unset($incl);

            // Sort excl objects IP mappings by Start IP
            $exclMapping = Array();
            $tmp = Array();
            foreach($exclGroupExpanded as &$excl){
                $tmp[] = $excl['start'];
            }
            unset($excl);
            sort($tmp, SORT_REGULAR);
            foreach($tmp as $value){
                foreach($exclGroupExpanded  as &$excl){
                    if( $value == $excl['start'] ){
                        $exclMapping[] = $excl;
                    }
                }
            }
            unset($excl);

            // Merge overlapping or Incl joint entries
            $mapKeys = array_keys($inclMapping);
            $mapCount = count($inclMapping);
            for($i=0; $i < $mapCount; $i++){
                $current = &$inclMapping[$mapKeys[$i]];
                for($j=$i+1; $j<$mapCount; $j++){
                    $compare = &$inclMapping[$mapKeys[$j]];

                    if( $compare['start'] > $current['end']+1 ){
                        break;
                    } elseif ($current['start'] <= $compare['start'] && $current['end'] >= $compare['end']) {
                        unset($inclMapping[$mapKeys[$j]]);
                        $i++;
                        break;
                    }
                    $current['end'] = $compare['end'];
                    $current['endip'] = $compare['endip'];
                    unset($inclMapping[$mapKeys[$j]]);
                    $i++;
                }
            }

            // Merge overlapping or joint Excl entries
            $mapKeys = array_keys($exclMapping);
            $mapCount = count($exclMapping);
            for($i=0; $i<$mapCount; $i++){
                $current = &$exclMapping[$mapKeys[$i]];
                for($j=$i+1; $j<$mapCount; $j++){
                    $compare = &$exclMapping[$mapKeys[$j]];

                    if( $compare['start'] > $current['end'] + 1 ) {
                        break;
                    }

                    $current['end'] = $compare['end'];
                    $current['endip'] = $compare['endip'];
                    unset($exclMapping[$mapKeys[$j]]);
                    $i++;
                }
            }

            // Calculate IP RANGE HOLES !!!
            foreach($inclMapping as $index => &$incl){
                $current = &$incl;

                foreach( $exclMapping as &$excl){
                    if($excl['start'] > $current['end'])
                        continue;
                    if($excl['start'] < $current['start'] && $excl['end'] < $current['start'])
                        continue;
                    // if this excl object is including ALL
                    if($excl['start'] <= $current['start'] && $excl['end'] >= $current['end']){
                        unset($inclMapping[$index]);
                        break;
                    }
                    elseif($excl['start'] <= $current['start'] && $excl['end'] <= $current['end']){
                        $current['start'] = $excl['end'];
                        $current['startip'] = $excl['endip'];
                    }
                    elseif($excl['start'] > $current['start'] && $excl['end'] >= $current['end']){
                        $current['end'] = $excl['start'] -1;
                        $current['endip'] = long2ip($current['end']);
                        break;
                    }
                    elseif($excl['start'] > $current['start'] && $excl['end'] < $current['end']){
                        $oldEnd = $current['end'];
                        $oldEndIP = $current['endip'];
                        $current['end'] = $excl['start']-1;
                        $current['endip'] =long2ip($current['end']);
                        unset($current);

                        $current = Array();
                        $inclMapping[] = &$current;
                        $current['start'] = $excl['end']+1;
                        $current['startip'] = long2ip($current['start']);
                        $current['end'] = $oldEnd;
                        $current['endip'] = $oldEndIP;
                    }
                }
            }

            // Sort incl objects IP mappings by Start IP
            $finalInclMapping = Array();
            $tmp = Array();
            foreach($inclMapping as &$incl3){
                $tmp[] = $incl3['start'];
            }
            unset($incl3);

            sort($tmp, SORT_NUMERIC);
            $is_first = 0;
            $members_news = array();
            // Remove duplicates
            $tmp = array_map('unserialize', array_unique(array_map('serialize', $tmp)));
            $inclMapping = array_map('unserialize', array_unique(array_map('serialize', $inclMapping)));

            foreach($tmp as $value){
                foreach($inclMapping as &$incl){
                    if($value == $incl['start']){
                        $oValue = $incl['startip']."-".$incl['endip'];

                        $oName = 'R-'.$incl['startip']."-".$incl['endip'];
                        $finalInclMapping[] = $incl;

                        $members_news[] = $oName;

                        $getExistAddress = $projectdb->query("SELECT id FROM address WHERE name = '$oName' AND type = 'ip-range' AND ipaddress = '$oValue' AND vsys = '$vsys' AND source = '$source' ");
                        if ($getExistAddress->num_rows == 1) {
                            while ($data = $getExistAddress->fetch_assoc()) {
                                $member_lid = $data['id'];
                            }
                        }else{
                            $projectdb->query("INSERT INTO address (id, name_ext, name, used, checkit, devicegroup, vsys, type, ipaddress, cidr, description, fqdn, v4, v6, vtype, source, tag, zone, invalid, modified) "
                                . "VALUES (NULL, '$oName', '$oName', '', '', '$devicegroup', '$vsys', 'ip-range','$oValue','', '', '', '', '', 'ip-range', '$source', '', '', '', '');");

                            $member_lid = $projectdb->insert_id;
                            $getObjects['objects'][$oName]['member_lid']=$member_lid;
                            $getObjects['objects'][$oName]['table_name']='address';
                        }

                        if($is_first == 0){

                            $name_int_old = array();

                            $getNameGroup = $projectdb->query("SELECT name FROM address_groups_id WHERE id = '$lid' ");
                            if ($getNameGroup->num_rows == 1) {
                                $dataNG = $getNameGroup->fetch_assoc();
                                $group_name = $dataNG['name'];
                            }

                            $getMembersGroups = $projectdb->query("SELECT member_lid, table_name FROM address_groups WHERE lid = '$lid' ");
                            if ($getMembersGroups->num_rows >= 1) {
                                while ($dataM = $getMembersGroups->fetch_assoc()) {
                                    $member_lid_g = $dataM['member_lid'];
                                    $table_name_g = $dataM['table_name'];

                                    $getMembersGroupsN = $projectdb->query("SELECT name FROM $table_name_g WHERE id = '$member_lid_g' ");
                                    if ($getMembersGroupsN->num_rows == 1) {
                                        $dataN = $getMembersGroupsN->fetch_assoc();
                                        $name_int_old[] = $dataN['name'];
                                    }
                                }
                            }

                            $projectdb->query("DELETE FROM address_groups WHERE lid = '$lid' ");
                            $is_first = 1;
                        }

                        $projectdb->query("INSERT INTO address_groups (id, used, checkit, devicegroup, vsys, member, member_lid, table_name, lid, source) "
                            . "VALUES (NULL, '', '', '$devicegroup', '$vsys', '$oName', '$member_lid', 'address', '$lid', '$source');");

                    }
                }
            }

            // Añadir el resto de miembros
            foreach($inclNo as &$incl2){

                $name_int_no = $incl2['object'];
                $member_lid_no = $incl2['member_lid'];
                $table_name_no = $incl2['table_name'];
                $getExistMember = $projectdb->query("SELECT id FROM address_groups WHERE member_lid = '$member_lid_no' AND table_name = '$table_name_no' AND lid = '$lid' AND vsys = '$vsys' AND source = '$source' ");

                if ($getExistMember->num_rows == 0) {

                    $projectdb->query("INSERT INTO address_groups (id, used, checkit, devicegroup, vsys, member, member_lid, table_name, lid, source) "
                        . "VALUES (NULL, '', '', '$devicegroup', '$vsys', '$name_int_no', '$member_lid_no', '$table_name_no', '$lid', '$source')");

                }
            }

            unset($incl);
            unset($incl2);
            unset($inclNo);

            if (count($members_news)>0){
                add_log('ok','Phase 2: Reading Address Objects and Groups','Group with exclusion '.$group_name.': The members {'.implode(",", $name_int_old).'} were replaced by {'.implode(",", $members_news).'}.', $source, '');
            }
            $projectdb->query("UPDATE address_groups_id SET type = 'static' WHERE id = '$lid'");
        }
    }// fin if lid
}

function expandMembersGroups($lid, $position){

    global $projectdb;

    $myMembers = array();

    if($position == "1"){
        $getFirstGroup = $projectdb->query("SELECT id, member, member_lid, table_name FROM address_groups WHERE lid = '$lid' ORDER BY id ASC LIMIT 1 ;");
        if ($getFirstGroup->num_rows > 0) {
            while ($data = $getFirstGroup->fetch_assoc()) {
                $myMembers[] = $data;
            }
        }
    }
    elseif($position == "2"){
        $getFirstGroup = $projectdb->query("SELECT id, member, member_lid, table_name FROM address_groups WHERE lid = '$lid' ORDER BY id DESC LIMIT 1 ;");
        if ($getFirstGroup->num_rows > 0) {
            while ($data = $getFirstGroup->fetch_assoc()) {
                $myMembers[] = $data;
            }
        }
    }
    elseif($position == "3"){
        $getFirstGroup = $projectdb->query("SELECT id, member, member_lid, table_name FROM address_groups WHERE lid = '$lid';");
        if ($getFirstGroup->num_rows > 0) {
            while ($data = $getFirstGroup->fetch_assoc()) {
                if($data['table_name']==="address_groups_id"){
                    $myMembers = array_merge($myMembers,expandMembersGroups($data['member_lid'], "3"));
                }else {
                    $myMembers[] = $data;
                }
            }
        }
    }
    elseif($position == "4"){
        # Grab all the members but the first
        $getFirstGroup = $projectdb->query("SELECT id, member, member_lid, table_name FROM address_groups WHERE lid = '$lid';");
        if ($getFirstGroup->num_rows > 0) {
            $count=0;
            while ($data = $getFirstGroup->fetch_assoc()) {
                if ($count!=0){
                    $myMembers[] = $data;
                }
                $count++;
            }
        }
    }

    return $myMembers;

}

function explodeGroups2MembersCheckpoint($members, $level=0){
    $tmp_members=array();

    foreach($members as $member){
        if ((isset($member['type'])) AND ($member['type']!="group") AND ($member['type']!="service-group")){
            $tmp_members[]=$member;
        }
        else{
            if (isset($member['members'])){
                $tmp_members[]=$member;
                $tmp_members = array_merge($tmp_members, explodeGroups2MembersCheckpoint($member['members'], $level+1));
            }
        }
    }
    $input = array_map("unserialize", array_unique(array_map("serialize", $tmp_members)));
    return $input;
}

function parseNatSummaryText(string $natSummaryText){
    $sections = explode(",", $natSummaryText);
    $ips = [];

    foreach($sections as $section){
        $section = trim($section);
        $parts = explode(":", $section);
        if($parts[0]=== 'Static'){
            $parts[1] = trim($parts[1]);
            $version = ip_version($parts[1]);
            $ips[] = [
                'method' => 'static',
                'ipv'=> $version,
                'value'=> $parts[1]
            ];
        }
        elseif(trim($parts[0])!=''){
            $ips[] = [
                'method' => trim($parts[0])
            ];
        }
    }

    return $ips;
}

function get_cluster_interfaces($source, $filename, $vsys, $interface, &$address_lid, &$cluster_members_names, &$addNetworksv4, &$addNetworksv6 , &$fullObject){
    // It's an ipv4 subnet
    // for object type cluster ipv4 address is on attribute ipv4-address
    // for object type host ipv4 address in on attribute subnet4
    if ( (isset($interface['name'], $interface['ipv4-address']) && $interface['ipv4-address']!== "")
        || (isset($interface['name'], $interface['subnet4']) && $interface['subnet4']!== "")) {

        $interface_name = normalizeNames(truncate_names($interface['name']));
        $interface_v4_ip = isset($interface['ipv4-address'])?$interface['ipv4-address']:$interface['subnet4'];
        $interface_v4_mask = "32";

        $interface_stored_name = $interface_name . "-" . $interface_v4_ip;

        if (!isset($fullObject[$interface_stored_name])) {
            $fullObject[$interface_stored_name]["table_name"] = "address";
            $fullObject[$interface_stored_name]["member_lid"] = $address_lid;
            $fullObject[$interface_stored_name]["ipaddress"] = $interface_v4_ip;
            $fullObject[$interface_stored_name]["cidr"] = $interface_v4_mask;
            $addNetworksv4[] = "('$address_lid','ip-netmask','ip-netmask','$interface_v4_ip','$interface_v4_mask','$interface_stored_name','$interface_stored_name','0','1','Interface $interface_name','$source','$filename','$vsys')";
            $address_lid++;
        }
        $cluster_members_names[] = $interface_stored_name;
    }
    // It's an ipv6 subnet
    if (isset($interface['name'], $interface['ipv6-address']) && $interface['ipv6-address']!== "") {

        $interface_name = normalizeNames(truncate_names($interface['name']));
        $interface_v6 = explode("/", $interface['ipv6-address']); //ipv6 + / + cidr

        $interface_v6_ip = "";
        if (isset($interface_v6[0])) {
            $interface_v6_ip = $interface_v6[0];
        }
        $interface_v6_mask = "";
        if (isset($interface_v6[1])) {
            $interface_v6_mask = $interface_v6[1];
        }

        $interface_stored_name = $interface_name . "-" . $interface_v6_ip . "-" . $interface_v6_mask;

        if (!isset($fullObject[$interface_stored_name])) {
            $addNetworksv6[] = "('$address_lid','ip-netmask','ip-netmask','$interface_v6_ip','$interface_v6_mask','$interface_stored_name','$interface_stored_name','0','1','Interface $interface_name','$source','$filename','$vsys')";
            $fullObject[$interface_stored_name]["table_name"] = "address";
            $fullObject[$interface_stored_name]["member_lid"] = $address_lid;
            $address_lid++;
        }
        $cluster_members_names[] = $interface_stored_name;
    }
}

function get_InMemoryDomain($fullObject, $ip){

    if(isset($fullObject["${ip}_fqdn1"])){
        return $fullObject["${ip}_fqdn1"]["member_lid"];
    }elseif (isset($fullObject["${ip}_fqdn2"])){
        return $fullObject["${ip}_fqdn2"]["member_lid"];
    }
    return null;
}

function storeNotSupportedObject($object, &$objectsNotSupported){
    $objectsNotSupported[$object['uid']]['name']=$object['name'];
    $objectsNotSupported[$object['uid']]['type']=$object['type'];
    $objectsNotSupported[$object['uid']]['uid']=$object['uid'];
}

function get_objects(ARRAY $myObjectsAll,$source,$vsys,$filename, $template){
    global $projectdb;

    $message=array();
    $common=array();
    # Max id from Address
    $get_glid=$projectdb->query("SELECT max(id) as glid FROM address;");
    if ($get_glid->num_rows==1){
        $get_glidData=$get_glid->fetch_assoc();
        $address_lid=$get_glidData['glid'] + 1;
    }
    else{$address_lid=1;}

    # Max id from Services
    $get_glid=$projectdb->query("SELECT max(id) as glid FROM services;");
    if ($get_glid->num_rows==1){
        $get_glidData=$get_glid->fetch_assoc();
        $services_lid=$get_glidData['glid'] + 1;
    }
    else{$services_lid=1;}

    # Max id for Address Groups aglid
    $get_glid=$projectdb->query("SELECT max(id) as glid FROM address_groups_id;");
    if ($get_glid->num_rows==1){
        $get_glidData=$get_glid->fetch_assoc();
        $aglid=$get_glidData['glid'] + 1;
    }
    else{$aglid=1;}

    # Max id for Services Groups sglid
    $get_glid=$projectdb->query("SELECT max(id) as glid FROM services_groups_id;");
    if ($get_glid->num_rows==1){
        $get_glidData=$get_glid->fetch_assoc();
        $sglid=$get_glidData['glid'] + 1;
    }
    else{$sglid=1;}
    $service_group_id = $sglid;

    # Init vars
    $addNetworksv4=array();
    $addNetworksv6=array();
    $addServices=array();
    $addAddressGroups=array();
    $addDynamicAddressGroups = array();
    $addAddressMembers=array();
    $addServicesGroups=array();
    $addServicesMembers=array();
    $addZones=array();

    $fullObject=array();

    $objectsNotSupported=array();
    $objectsGroups=array();
    $objectsExclusionGroups=array();
    $objectsServicesGroups=array();
    $service_group_map = array();

    $schedules=array();
    $accessRoles=array();
    $accessLayers=array();
    $zones = array();



    foreach ($myObjectsAll as $key => $object){
        $name_int=normalizeNames(truncate_names($object['name']));
        $name=$object['uid'];
        $description= "";
        if(isset($object['comments'])) {
            $description= addslashes($object['comments']);
        }
        switch($object['type']){
            case "data-center-object":{
                if ((!isset($fullObject[$name]))) {

                    // Create a default filter for the dynamic address group
                    $match = $object['name'];
                    $cloud_tag = ".";
                    $level_log = "error";

                    // We support filter creation for AWS objects typed as Tag Value and Instance
                    // for any other tag we are creating the dynamic object with an error
                    if(isset($object['data-center']['data-center-type']) && $object['data-center']['data-center-type'] == "AWS") {

                        $level_log = "warning";
                        $cloud_tag = "aws.ec2."; // AWS

                        if (isset($object['type-in-data-center']) && str_contains(strtolower($object['type-in-data-center']), "tag")) {

                            $cloud_tag .= "tag.";
                            $match = addslashes("'" . $cloud_tag . str_replace("=", ".", $object['name']) . "'");

                        } else if (isset($object['type-in-data-center']) && str_contains(strtolower($object['type-in-data-center']), "instance")) {

                            $cloud_tag .= "ami-id.am"; // AWS
                            $id = explode(" ", $object['name']);
                            $match = addslashes("'" . $cloud_tag . $id[0] . "'");

                        }
                    }
                    add_log2($level_log, 'Reading Objects', "Reading dynamic address group: [". $object['type'] . "] in Object Name: [" . $object['name'] ."]", $source, 'Review usage on original configuration', 'objects', $aglid, 'address_groups_id');



                    $addDynamicAddressGroups[] = "('$aglid','$name_int','$name','dynamic','$filename','$source','$vsys','$description','$match')";
                    $aglid++;

                    $fullObject[$name]["member_lid"] = $aglid;
                    $fullObject[$name]["table_name"] = "address_groups_id";

                }
                break;
            }
            case "CpmiIcmpService":
                if ((!isset($fullObject[$name]))){
                    $service_protocol="icmp";
                    $addServices[]="('$services_lid','$name','$name_int','$service_protocol','0','0','$description','$source','0','$filename','$vsys','no','')";
                    $fullObject[$name]["table_name"]="services";
                    $fullObject[$name]["member_lid"]=$services_lid;
                    $services_lid++;
                }
                break;
            case "service-icmp":
                if ((!isset($fullObject[$name]))){
                    $service_protocol="icmp";
                    $addServices[]="('$services_lid','$name','$name_int','$service_protocol','0','0','$description','$source','0','$filename','$vsys','no','')";
                    $fullObject[$name]["table_name"]="services";
                    $fullObject[$name]["member_lid"]=$services_lid;
                    $fullObject[$name]["protocol"]=$service_protocol;
                    $services_lid++;
                }
                break;
            case "service-dce-rpc":
                if ((!isset($fullObject[$name]))){
                    $service_protocol="rpc";
                    $addServices[]="('$services_lid','$name','$name_int','$service_protocol','0','0','$description','$source','0','$filename','$vsys','no','')";
                    $fullObject[$name]["table_name"]="services";
                    $fullObject[$name]["member_lid"]=$services_lid;
                    $fullObject[$name]["protocol"]=$service_protocol;
                    $services_lid++;
                }
                break;
            case "service-rpc":
                if ((!isset($fullObject[$name]))){
                    $service_protocol="rpc";
                    $addServices[]="('$services_lid','$name','$name_int','$service_protocol','0','0','$description','$source','0','$filename','$vsys','no','')";
                    $fullObject[$name]["table_name"]="services";
                    $fullObject[$name]["member_lid"]=$services_lid;
                    $fullObject[$name]["protocol"]=$service_protocol;
                    $services_lid++;
                }
                break;
            case "service-tcp":
                if (!isset($fullObject[$name])){
                    $service_protocol="tcp";
                    $tcp_timeout = "";
                    $tcp_override = "no";

                    // check if TCP timeout is set as default or customer defined a customized one
                    if (isset($object['use-default-session-timeout']) && !$object['use-default-session-timeout']){
                        $tcp_timeout = $object['session-timeout'];
                        $tcp_override = "yes";
                    }

                    if (!isset($object['port'])){
                        $service_port="0";
                    }
                    else{
                        $service_port=$object['port'];
                    }

                    if (preg_match("/-/i", $service_port)) {
                        $new_var=explode("-",$service_port);
                        $first_port=$new_var[0];
                        $last_port=$new_var[1];
                        $addServices[]="('$services_lid','$name','$name_int','$service_protocol','$first_port-$last_port','0','$description','$source','0','$filename','$vsys','$tcp_override','$tcp_timeout')";
                        $fullObject[$name]["table_name"]="services";
                        $fullObject[$name]["member_lid"]=$services_lid;
                        $fullObject[$name]["dport"]="$first_port-$last_port";
                        $fullObject[$name]["protocol"]=$service_protocol;
                        $services_lid++;
                    } elseif (preg_match("/>/i", $service_port)) {
                        $new_var=explode(">",$service_port);
                        $first_port=intval($new_var[1])+1;
                        $addServices[]="('$services_lid','$name','$name_int','$service_protocol','$first_port-65535','1','$description','$source','0','$filename','$vsys','$tcp_override','$tcp_timeout')";
                        $fullObject[$name]["table_name"]="services";
                        $fullObject[$name]["member_lid"]=$services_lid;
                        $fullObject[$name]["dport"]="$first_port-65535";
                        $fullObject[$name]["protocol"]=$service_protocol;
                        $services_lid++;
                    } elseif (preg_match("/</i", $service_port)) {
                        $new_var=explode("<",$service_port);
                        $first_port=intval($new_var[1])-1;
                        $addServices[]="('$services_lid','$name','$name_int','$service_protocol','0-$first_port','1','$description','$source','0','$filename','$vsys','$tcp_override','$tcp_timeout')";
                        $fullObject[$name]["table_name"]="services";
                        $fullObject[$name]["member_lid"]=$services_lid;
                        $fullObject[$name]["dport"]="0-$first_port";
                        $fullObject[$name]["protocol"]=$service_protocol;
                        $services_lid++;
                    } else {
                        $addServices[]="('$services_lid','$name','$name_int','$service_protocol','$service_port','0','$description','$source','0','$filename','$vsys','$tcp_override','$tcp_timeout')";
                        $fullObject[$name]["table_name"]="services";
                        $fullObject[$name]["member_lid"]=$services_lid;
                        $fullObject[$name]["dport"]=$service_port;
                        $fullObject[$name]["protocol"]=$service_protocol;
                        $services_lid++;
                    }
                }
                break;
            case "service-other":
                if (!isset($fullObject[$name])){
                    $service_protocol=$object['ip-protocol'];
                    $addServices[]="('$services_lid','$name','$name_int','$service_protocol','','1','$description','$source','0','$filename','$vsys','no','')";
                    $fullObject[$name]["table_name"]="services";
                    $fullObject[$name]["member_lid"]=$services_lid;
                    $fullObject[$name]["protocol"]=$service_protocol;
                    $services_lid++;
                }
                break;
            case "service-udp":
                if (!isset($fullObject[$name])){
                    $service_protocol="udp";
                    $service_port=$object['port'];
                    if (preg_match("/-/i", $service_port)) {
                        $new_var=explode("-",$service_port);
                        $first_port=$new_var[0];
                        $last_port=$new_var[1];
                        $addServices[]="('$services_lid','$name','$name_int','$service_protocol','$first_port-$last_port','0','$description','$source','0','$filename','$vsys','no','')";
                        $fullObject[$name]["table_name"]="services";
                        $fullObject[$name]["member_lid"]=$services_lid;
                        $fullObject[$name]["dport"]="$first_port-$last_port";
                        $fullObject[$name]["protocol"]=$service_protocol;
                        $services_lid++;
                    } elseif (preg_match("/>/i", $service_port)) {
                        $new_var=explode(">",$service_port);
                        $first_port=intval($new_var[1])+1;
                        $addServices[]="('$services_lid','$name','$name_int','$service_protocol','$first_port-65535','1','$description','$source','0','$filename','$vsys','no','')";
                        $fullObject[$name]["table_name"]="services";
                        $fullObject[$name]["member_lid"]=$services_lid;
                        $fullObject[$name]["dport"]="$first_port-65535";
                        $fullObject[$name]["protocol"]=$service_protocol;
                        $services_lid++;
                    } elseif (preg_match("/</i", $service_port)) {
                        $new_var=explode("<",$service_port);
                        $first_port=intval($new_var[1])-1;
                        $addServices[]="('$services_lid','$name','$name_int','$service_protocol','1-$first_port','1','$description','$source','0','$filename','$vsys','no','')";
                        $fullObject[$name]["table_name"]="services";
                        $fullObject[$name]["member_lid"]=$services_lid;
                        $fullObject[$name]["dport"]="1-$first_port";
                        $fullObject[$name]["protocol"]=$service_protocol;
                        $services_lid++;
                    } else{
                        $addServices[]="('$services_lid','$name','$name_int','$service_protocol','$service_port','0','$description','$source','0','$filename','$vsys','no','')";
                        $fullObject[$name]["table_name"]="services";
                        $fullObject[$name]["member_lid"]=$services_lid;
                        $fullObject[$name]["protocol"]=$service_protocol;
                        $services_lid++;}
                }
                break;
            case "network":
                if (!isset($fullObject[$name])){
                    if ((isset($object['subnet4'])) AND ($object['mask-length4']!="") AND ($object['subnet4']!="")){
                        $ip=$object['subnet4'];
                        $mask=$object['mask-length4'];
                        $addNetworksv4[]="('$address_lid','ip-netmask','ip-netmask','$ip','$mask','$name','$name_int','0','1','$description','$source','$filename','$vsys')";
                        $fullObject[$name]["table_name"]="address";
                        $fullObject[$name]["member_lid"]=$address_lid;
                        $fullObject[$name]["ipaddress"]=$ip;
                        $fullObject[$name]["cidr"]=$mask;
                        $address_lid++;
                    }
                    if ((isset($object['subnet6'])) AND ($object['mask-length6']!="") AND ($object['subnet6']!="")){
                        $ip=$object['subnet6'];
                        $mask=$object['mask-length6'];
                        $addNetworksv6[]="('$address_lid','ip-netmask','ip-netmask','$ip','$mask','$name','$name_int','0','1','$description','$source','$filename','$vsys')";
                        $fullObject[$name]["table_name"]="address";
                        $fullObject[$name]["member_lid"]=$address_lid;
                        $address_lid++;
                    }

                    if ((isset($object['nat-settings'])) AND ($object['nat-settings']!="") ){
                        $autoRule=false;
                        if (isset($object["nat-settings"]["auto-rule"])){
                            if ($object["nat-settings"]["auto-rule"]=="yes" || $object["nat-settings"]["auto-rule"]=="true"){
                                $autoRule=true;
                                if (isset($object["nat-settings"]["method"])){
                                    $fullObject[$name]["nat"]["method"]=$object["nat-settings"]["method"];

                                    if ($object["nat-settings"]["method"]=="hide"){
                                        if (isset($object["nat-settings"]["hide-behind"])){
                                            if ($object["nat-settings"]["hide-behind"]=="gateway"){
                                                $fullObject[$name]["nat"]["hide-behind"]="gateway";
                                            }
                                            elseif ($object["nat-settings"]["hide-behind"]=="ip-address"){
                                                //Nothing to do, the valid NATted IP is already specified
                                                $fullObject[$name]["nat"]["hide-behind"]="ip-address";
                                            }
                                            else{
                                                //print "Unexpected object: NAT-SETTINGS->HIDE->HIDE-BEHIND->".$object["nat-settings"]["hide-behind"]." Please send email to fwmigrate@paloaltonetworks.com ".PHP_EOL;
                                                echo ">>>>>>>Unexpected object: NAT-SETTINGS->HIDE->HIDE-BEHIND->".$object["nat-settings"]["hide-behind"]."on object_type[" . $object['type'] . "]::object_name[" . $object['name'] . "] Please send email to fwmigrate@paloaltonetworks.com ".PHP_EOL;
                                            }
                                        }
                                    }

                                    if ( (isset($object["nat-settings"]["install-on"])) AND ($object["nat-settings"]["install-on"]!="Any")){
                                        $fullObject[$name]["nat"]["target"]=$object["nat-settings"]["install-on"];
                                    }

                                    if ((isset($object["nat-settings"]["ipv4-address"])) AND ($object["nat-settings"]["ipv4-address"]!="")){
                                        $newObj=$object["nat-settings"]["ipv4-address"];
                                        if (!isset($fullObject["H-".$newObj])){
                                            $addNetworksv4[]="('$address_lid','ip-netmask','ip-netmask','$newObj','','H-$newObj','H-$newObj','0','1','Auto Nat','$source','$filename','$vsys')";
                                            $fullObject["H-".$newObj]["table_name"]="address";
                                            $fullObject["H-".$newObj]["member_lid"]=$address_lid;
                                            $address_lid++;
                                        }
                                        $fullObject[$name]["nat"]["translated"]["table_name"]="address";
                                        $fullObject[$name]["nat"]["translated"]["member_lid"]=$fullObject["H-".$newObj]["member_lid"];
                                    }

                                    if ((isset($object["nat-settings"]["ipv6-address"])) && ($object["nat-settings"]["ipv6-address"]!="") && ($object["nat-settings"]["ipv6-address"]!="::")){
                                        $newObj=$object["nat-settings"]["ipv6-address"];
                                        if (!isset($fullObject["H-".$newObj])){
                                            $addNetworksv6[]="('$address_lid','ip-netmask','ip-netmask','$newObj','','H-$newObj','H-$newObj','0','1','Auto Nat','$source','$filename','$vsys')";
                                            $fullObject["H-".$newObj]["table_name"]="address";
                                            $fullObject["H-".$newObj]["member_lid"]=$address_lid;
                                            $address_lid++;
                                        }
                                        $fullObject[$name]["nat"]["translated"]["table_name"]="address";
                                        $fullObject[$name]["nat"]["translated"]["member_lid"]=$fullObject["H-".$newObj]["member_lid"];

                                    }
                                }

                            }
                        }


                        $autoRule=false;
                        foreach($object['nat-settings'] as $objKey=>$newObj){
                            if ($autoRule==true){
                                if (($objKey=="ipv4-address") AND ($newObj!="")){
                                    $addNetworksv4[]="('$address_lid','ip-netmask','ip-netmask','$newObj','','H-$newObj','H-$newObj','0','1','Auto Nat','$source','$filename','$vsys')";
                                    $fullObject[$name]["table_name"]="address";
                                    $fullObject[$name]["member_lid"]=$address_lid;
                                    $address_lid++;
                                }
                                if (($objKey=="ipv6-address") && ($newObj!="") && ($newObj!="::")){
                                    $addNetworksv6[]="('$address_lid','ip-netmask','ip-netmask','$newObj','','H-$newObj','H-$newObj','0','1','Auto Nat','$source','$filename','$vsys')";
                                    $fullObject[$name]["table_name"]="address";
                                    $fullObject[$name]["member_lid"]=$address_lid;
                                    $address_lid++;
                                }
                            }
                            if (($objKey=="auto-rule") AND ($newObj==true)){
                                $autoRule=true;
                            }

                        }
                    }
                   /* if ((isset($object['nat-settings'])) AND ($object['nat-settings']!="")){
                        if (isset($object["nat-settings"]["auto-rule"])){
                            if ($object["nat-settings"]["auto-rule"]=="yes"){
                                $autoRule=true;
                                if (isset($object["nat-settings"]["method"])){
                                    $fullObject[$name]["nat"]["method"]=$object["nat-settings"]["method"];
                                    if ($object["nat-settings"]["method"]=="static"){
                                        echo "METHOD ".$object["nat-settings"]["method"].PHP_EOL;
                                    }
                                    if (isset($object["nat-settings"]["install-on"])){

                                    }
                                }

                            }
                        }


                    }*/

                    if ( (isset($object['groups'])) AND (count($object['groups'])>0) ){
                        foreach($object['groups'] as $ikey=>$newObjectGRoup){
                            if (is_array($newObjectGRoup)){
                                $objectsGroups[]=$newObjectGRoup;
                            }
                        }
                    }

                }
                break;
            case "checkpoint-host":
            case "CpmiVsNetobj":
            case "host":
                if (!isset($fullObject[$name])){

                    $host_members_names = [];
                    $host_with_interfaces = false;
                    // Host type object could define a set of interfaces, on those case the host needs
                    // to be created it as an address_group (instead as an address)
                    // containing as members the interfaces (addresses)
                    // and the defined ipv4 (address).
                    if (isset($object['interfaces'])) {
                        $host_interfaces_array = $object['interfaces'];
                        // create each defined interface as an address
                        foreach ($host_interfaces_array as $host_member_interface) {
                            get_cluster_interfaces($source, $filename, $vsys, $host_member_interface, $address_lid, $host_members_names, $addNetworksv4, $addNetworksv6, $fullObject);
                        }
                        if(count($host_members_names)>0) {
                            // flag the host contains interfaces
                            $host_with_interfaces = true;
                        }
                    }
                    if((isset($object['ipv4-address'])) AND ($object['ipv4-address']!="") && (isset($object['ipv6-address'])) AND ($object['ipv6-address']!="") AND ($object['ipv6-address']!="::")){
                        //This target device has IPv4 and IPv6
                        $ip = $object['ipv4-address'];
                        $addNetworksv4[] = "('$address_lid','ip-netmask','ip-netmask','$ip','','${name}-v4','${name_int}-v4','0','1','$description','$source','$filename','$vsys')";
                        $fullObject["${name}-v4"]["table_name"] = "address";
                        $fullObject["${name}-v4"]["member_lid"] = $address_lid;
                        $fullObject["${name}-v4"]["ipaddress"] = $ip;
                        $fullObject["${name}-v4"]["cidr"] = "32";
                        $address_lid++;

                        $ip = $object['ipv6-address'];
                        $addNetworksv6[] = "('$address_lid','ip-netmask','ip-netmask','$ip','','${name}-v6','${name_int}-v6','0','1','$description','$source','$filename','$vsys')";
                        $fullObject["${name}-v6"]["table_name"] = "address";
                        $fullObject["${name}-v6"]["member_lid"] = $address_lid;
                        $address_lid++;

                        $objectG=[
                            'icon'      => 'General/group',
                            'name'      => "$name_int",
                            'uid'       => "$name",
                            'type'      =>"group",
                            'comments'  => $description,
                            'members'   => ["${name}-v4", "${name}-v6"]
                        ];
                        $objectsGroups[]=$objectG;

                    }
                    else {
                        if ((isset($object['ipv4-address'])) and ($object['ipv4-address'] != "")) {
                            $ip = $object['ipv4-address'];
                            $name_host = $name_int;
                            $name_v4 = $name;
                            if($host_with_interfaces) {
                                // if host contains interfaces then we need to create it as an address_group
                                // that mean that object with original $name and $name_int shall be an address_group
                                // containing as member a Host with given ipv4 and all previous created interfaces
                                $name_host ="H-".$name_host;
                                $name_v4 = $name."-v4";
                                $host_members_names[]=$name_v4;
                            }
                            $addNetworksv4[] = "('$address_lid','ip-netmask','ip-netmask','$ip','','$name_v4','$name_host','0','1','$description','$source','$filename','$vsys')";
                            $fullObject[$name_v4]["table_name"] = "address";
                            $fullObject[$name_v4]["member_lid"] = $address_lid;
                            $fullObject[$name_v4]["ipaddress"] = $ip;
                            $fullObject[$name_v4]["cidr"] = "32";
                            $address_lid++;

                        }
                        if ((isset($object['ipv6-address'])) and ($object['ipv6-address'] != "") and ($object['ipv6-address'] != "::")) {
                            $ip = $object['ipv6-address'];
                            $addNetworksv6[] = "('$address_lid','ip-netmask','ip-netmask','$ip','','$name','$name_int','0','1','$description','$source','$filename','$vsys')";
                            $fullObject[$name]["table_name"] = "address";
                            $fullObject[$name]["member_lid"] = $address_lid;
                            $address_lid++;
                        }
                    }
                    //if (((isset($object['nat-settings'])) AND ($object['nat-settings']!="") ) AND !$host_with_interfaces){
                    if ((isset($object['nat-settings'])) AND ($object['nat-settings']!="") ){
                        $autoRule=false;
                        if (isset($object["nat-settings"]["auto-rule"])){
                            if ($object["nat-settings"]["auto-rule"]=="yes" || $object["nat-settings"]["auto-rule"]=="true"){
                                $autoRule=true;
                                if (isset($object["nat-settings"]["method"])){
                                    $fullObject[$name]["nat"]["method"]=$object["nat-settings"]["method"];

                                    if ($object["nat-settings"]["method"]=="hide"){
                                        if (isset($object["nat-settings"]["hide-behind"])){
                                            if ($object["nat-settings"]["hide-behind"]=="gateway"){
                                                $fullObject[$name]["nat"]["hide-behind"]="gateway";
                                            }
                                            elseif ($object["nat-settings"]["hide-behind"]=="ip-address"){
                                                //Nothing to do, the valid NATted IP is already specified
                                                $fullObject[$name]["nat"]["hide-behind"]="ip-address";
                                            }
                                            else{
                                                //print "Unexpected object: NAT-SETTINGS->HIDE->HIDE-BEHIND->".$object["nat-settings"]["hide-behind"]." Please send email to fwmigrate@paloaltonetworks.com ".PHP_EOL;
                                                echo ">>>>>>>Unexpected object: NAT-SETTINGS->HIDE->HIDE-BEHIND->".$object["nat-settings"]["hide-behind"]."on object_type[" . $object['type'] . "]::object_name[" . $object['name'] . "] Please send email to fwmigrate@paloaltonetworks.com ".PHP_EOL;
                                            }
                                        }
                                    }

                                    if ( (isset($object["nat-settings"]["install-on"])) AND ($object["nat-settings"]["install-on"]!="Any")){
                                        $fullObject[$name]["nat"]["target"]=$object["nat-settings"]["install-on"];
                                    }

                                    if ((isset($object["nat-settings"]["ipv4-address"])) AND ($object["nat-settings"]["ipv4-address"]!="")){
                                        $newObj=$object["nat-settings"]["ipv4-address"];
                                        if (!isset($fullObject["H-".$newObj])){
                                            $addNetworksv4[]="('$address_lid','ip-netmask','ip-netmask','$newObj','','H-$newObj','H-$newObj','0','1','Auto Nat','$source','$filename','$vsys')";
                                            $fullObject["H-".$newObj]["table_name"]="address";
                                            $fullObject["H-".$newObj]["member_lid"]=$address_lid;
                                            $address_lid++;
                                        }
                                        $fullObject[$name]["nat"]["translated"]["table_name"]="address";
                                        $fullObject[$name]["nat"]["translated"]["member_lid"]=$fullObject["H-".$newObj]["member_lid"];
                                    }

                                    if ((isset($object["nat-settings"]["ipv6-address"])) AND ($object["nat-settings"]["ipv6-address"]!="") AND ($object["nat-settings"]["ipv6-address"]!="::")){
                                        $newObj=$object["nat-settings"]["ipv6-address"];
                                        if (!isset($fullObject["H-".$newObj])){
                                            $addNetworksv6[]="('$address_lid','ip-netmask','ip-netmask','$newObj','','H-$newObj','H-$newObj','0','1','Auto Nat','$source','$filename','$vsys')";
                                            $fullObject["H-".$newObj]["table_name"]="address";
                                            $fullObject["H-".$newObj]["member_lid"]=$address_lid;
                                            $address_lid++;
                                        }
                                        $fullObject[$name]["nat"]["translated"]["table_name"]="address";
                                        $fullObject[$name]["nat"]["translated"]["member_lid"]=$fullObject["H-".$newObj]["member_lid"];
                                    }
                                }

                            }
                        }


                        $autoRule=false;
                        foreach($object['nat-settings'] as $objKey=>$newObj){
                            if ($autoRule==true){
                                if (($objKey=="ipv4-address") AND ($newObj!="")){
                                    $addNetworksv4[]="('$address_lid','ip-netmask','ip-netmask','$newObj','','H-$newObj','H-$newObj','0','1','Auto Nat','$source','$filename','$vsys')";
                                    $fullObject[$name]["table_name"]="address";
                                    $fullObject[$name]["member_lid"]=$address_lid;
                                    $address_lid++;
                                }
                                if (($objKey=="ipv6-address") AND ($newObj!="") AND ($newObj!="::")){
                                    $addNetworksv6[]="('$address_lid','ip-netmask','ip-netmask','$newObj','','H-$newObj','H-$newObj','0','1','Auto Nat','$source','$filename','$vsys')";
                                    $fullObject[$name]["table_name"]="address";
                                    $fullObject[$name]["member_lid"]=$address_lid;
                                    $address_lid++;
                                }
                            }
                            if (($objKey=="auto-rule") AND ($newObj==true)){
                                $autoRule=true;
                            }

                        }
                    }

                    if ( (isset($object['groups'])) AND (count($object['groups'])>0) ){
                        foreach($object['groups'] as $ikey=>$newObjectGRoup){
                            if (is_array($newObjectGRoup)){
                                $objectsGroups[]=$newObjectGRoup;
                            }
                        }
                    }
                    if($host_with_interfaces) {
                        // create the address_group with all read members (interfaces + ipv4)
                        $objectG = [
                            'icon' => 'General/group',
                            'name' => "$name_int",
                            'uid' => "$name",
                            'type' => "group",
                            'comments' => $description,
                            'members' => $host_members_names,
                        ];
                        if(isset($fullObject[$name]['nat'])){
                            $objectG['nat'] = $fullObject[$name]['nat']; // copy NAT information for the address_group
                            unset($fullObject[$name]); //remove any data from the fullObjects as it will be added later while revisiting the groups
                        }
                        $objectsGroups[] = $objectG;

                    }
                }
                break;
            case "dns-domain":  //domains could such as .google.com, which would refer to www.DOMAIN and DOMAIN (e.g. www.google.com and google.com)
                if (!isset($fullObject[$name])){
                    if ((isset($object['name'])) AND ($object['name']!="")){
                        $ip  =$object['name'];
                        $ip2 =trim($ip, ".");
                        $name_int=normalizeNames(truncate_names($object['name'],48));
                        if($ip != $ip2){ //if the name starts with a dot, this means there are two possible fits. We should create a group containing both
                            //$name = $ip2;

                            //a first reference in the group is to www.DOMAI
                            if(str_contains($ip, '.www.')){
                                $ip_new = str_replace(".www.","",$ip);
                            } else if (str_contains($ip, '.*.')){
                                $name_int = str_replace("..",".asterisk.",$name_int);
                                $ip_new = "www." . normalizeNames(str_replace(".*.","",$ip));
                                $ip2 = normalizeNames(str_replace(".*.","",$ip));
                                add_log2('info', 'Reading dns-domain object with asterisk', 'dns-domain with asterisk.'.$object['name'].' found', $source, 'Removing *.* from the read dns-domain. If the requirement is to allow web browsing to all possible subdomains of a certain domain, a Security Policy based on a custom URL category in the destination could be useful to fill the gap between an FQDN Object and a URL Filtering Security Profile.', 'objects', $aglid, 'address_groups_id');
                            }else{
                                $ip_new = "www" . normalizeNames($ip);
                            }

                            //Here we create the group that fits with the provided UUID
                            $addAddressGroups[]="('$aglid','$name','G$name_int','static','$filename','$source','$vsys','$description')";
                            $fullObject[$name]["table_name"]="address_groups_id";
                            $fullObject[$name]["member_lid"]=$aglid;

                            $ip = $ip_new;
                            // Look if the object is already in memory so we do not need to create it
                            $stored_address_lid = get_InMemoryDomain($fullObject, $ip);
                            if(isset($stored_address_lid)){
                                $addAddressMembers[] = "('$vsys','${ip}','$aglid','$source','$stored_address_lid','address')";
                            }else {
                                $fdqn1_name = truncate_names("fqdn_".$ip_new,  63);
                                $addNetworksv4[] = "('$address_lid','fqdn','fqdn','$ip','','${ip}_fqdn1','$fdqn1_name'  ,'0','1','$description','$source','$filename','$vsys')";
                                $fullObject["${ip}_fqdn1"]["table_name"] = "address";
                                $fullObject["${ip}_fqdn1"]["member_lid"] = $address_lid;
                                $fullObject["${ip}_fqdn1"]["ipaddress"] = $ip;
                                $fullObject["${ip}_fqdn1"]["cidr"] = "32";
                                $addAddressMembers[] = "('$vsys','${ip}','$aglid','$source','$address_lid','address')";
                                $address_lid++;
                            }
                            //The second refers to DOMAIN
                            $ip2 = normalizeNames($ip2);
                            // Look if the object is already in memory so we do not need to create it
                            $stored_address_lid = get_InMemoryDomain($fullObject, $ip2);
                            if(isset($stored_address_lid)){
                                $addAddressMembers[] = "('$vsys','${ip2}','$aglid','$source','$stored_address_lid','address')";
                            }else {
                                $fdqn2_name = truncate_names("fqdn_".$ip2, 63);
                                $addNetworksv4[] = "('$address_lid','fqdn','fqdn','$ip2','','${ip2}_fqdn2','$fdqn2_name','0','1','$description','$source','$filename','$vsys')";
                                $fullObject["${ip2}_fqdn2"]["table_name"] = "address";
                                $fullObject["${ip2}_fqdn2"]["member_lid"] = $address_lid;
                                $fullObject["${ip2}_fqdn2"]["ipaddress"] = $ip2;
                                $fullObject["${ip2}_fqdn2"]["cidr"] = "32";
                                $addAddressMembers[] = "('$vsys','${ip2}','$aglid','$source','$address_lid','address')";
                                $address_lid++;
                            }
                            if($object['is-sub-domain']) {
                                create_url_category($object['name'], $source, $vsys);
                                add_log2('error', 'Reading dns-domain object with subdomains enabled', 'dns-domain with subdomains enabled ['.$object['name'].'] found.', $source, 'Custom URL category required. Consider using the one with name ['.$ip2.']. To allow web browsing to all possible subdomains of a certain domain, a Security Policy based on a custom URL category in the destination could be useful to fill the gap between an FQDN Object and a URL Filtering Security Profile.', 'objects', $aglid, 'address_groups_id');
                            }else {
                                add_log2('info', 'Reading dns-domain object with subdomains disabled', 'dns-domain .' . $ip2 . ' found', $source, 'No action required. When a dns-domain object in checkpoint is defined with "is-sub-domain=false" it means that the fqdn should be only the defined url. Expedition is creating a new group with the most common fqdn domains for you (' . $ip . ',' . $ip2 . '). Note that if the requirement is to allow web browsing to all possible subdomains of a certain domain, a Security Policy based on a custom URL category in the destination could be useful to fill the gap between an FQDN Object and a URL Filtering Security Profile.', 'objects', $aglid, 'address_groups_id');
                            }
                            $aglid++;
                        }
                        else{ //If the name does not start with a dot, we enter it as it is
                            $ip = "www".normalizeNames($ip);
                            $addNetworksv4[]="('$address_lid','fqdn','fqdn','$ip','','$name','$name_int','0','1','$description','$source','$filename','$vsys')";
                            $fullObject[$name]["table_name"]="address";
                            $fullObject[$name]["member_lid"]=$address_lid;
                            $fullObject[$name]["ipaddress"]=$ip;
                            $fullObject[$name]["cidr"]="32";
                            $address_lid++;
                        }

                    }
                }
                break;
            case "security-zone":
                $zoneName = $object['name'];
                $addZones [] = "('$source','$template','$vsys','$zoneName','layer3')";
                $zones[$name]=$zoneName;
                break;
            case "CpmiVsxClusterMember":
            case "CpmiVsxClusterNetobj":
            case "CpmiVsClusterNetobj":
                if (!isset($fullObject[$name])){
                    if ((isset($object['ipv4-address'])) AND ($object['ipv4-address']!="")){
                        $ip=$object['ipv4-address'];
                        $addNetworksv4[]="('$address_lid','ip-netmask','ip-netmask','$ip','','$name','$name_int','0','1','$description','$source','$filename','$vsys')";
                        $fullObject[$name]["table_name"]="address";
                        $fullObject[$name]["member_lid"]=$address_lid;
                        $fullObject[$name]["ipaddress"]=$ip;
                        $fullObject[$name]["cidr"]="32";
                        $address_lid++;
                    }
                    if ((isset($object['ipv6-address'])) AND ($object['ipv6-address']!="") AND ($object['ipv6-address']!="::")){
                        $ip=$object['ipv6-address'];
                        $addNetworksv6[]="('$address_lid','ip-netmask','ip-netmask','$ip','','$name','$name_int','0','1','$description','$source','$filename','$vsys')";
                        $fullObject[$name]["table_name"]="address";
                        $fullObject[$name]["member_lid"]=$address_lid;
                        $address_lid++;
                    }

                    if (isset($object['natSummaryText']) && (strtolower(trim($object['natSummaryText']))!="none")){
                        $summaryParts = parseNatSummaryText($object['natSummaryText']);

                        foreach ($summaryParts as $summaryPart){
                            $fullObject[$name]["nat"]["method"]= $summaryPart['method'];
                            if(isset($summaryPart['ipv']) && $summaryPart['ipv'] ==='ipv6'){
                                $newObj = $summaryPart['value'];
                                if (!isset($fullObject["H-".$newObj])){
                                    $addNetworksv4[]="('$address_lid','ip-netmask','ip-netmask','$newObj','','H-$newObj','H-$newObj','1','0','Auto Nat','$source','$filename','$vsys')";
                                    $fullObject["H-".$newObj]["table_name"]="address";
                                    $fullObject["H-".$newObj]["member_lid"]=$address_lid;
                                    $address_lid++;
                                }
                            }
                            else if(isset($summaryPart['value'])){
                                $newObj = $summaryPart['value'];
                                if (!isset($fullObject["H-".$newObj])){
                                    $addNetworksv4[]="('$address_lid','ip-netmask','ip-netmask','$newObj','','H-$newObj','H-$newObj','0','1','Auto Nat','$source','$filename','$vsys')";
                                    $fullObject["H-".$newObj]["table_name"]="address";
                                    $fullObject["H-".$newObj]["member_lid"]=$address_lid;
                                    $address_lid++;
                                }
                            }
                            if(isset($fullObject["H-".$newObj]["member_lid"])) {
                                $fullObject[$name]["nat"]["translated"]["table_name"] = "address";
                                $fullObject[$name]["nat"]["translated"]["member_lid"] = $fullObject["H-" . $newObj]["member_lid"];
                            }
                        }
                    }

                    if ((isset($object['nat-settings'])) AND ($object['nat-settings']!="") AND (!isset($fullObject[$name]))){
                        $autoRule=false;
                        /*foreach($object['nat-settings'] as $objKey=>$newObj){
                            if ($autoRule==true){
                                if (($objKey=="ipv4-address") AND ($newObj!="")){
                                    $addNetworksv4[]="('$address_lid','ip-netmask','ip-netmask','$newObj','','H-$newObj','H-$newObj','0','1','Auto Nat','$source','$filename','$vsys')";
                                    $fullObject[$name]["table_name"]="address";
                                    $fullObject[$name]["member_lid"]=$address_lid;
                                    $address_lid++;
                                }
                                if (($objKey=="ipv6-address") AND ($newObj!="")){
                                    $addNetworksv6[]="('$address_lid','ip-netmask','ip-netmask','$newObj','','H-$newObj','H-$newObj','0','1','Auto Nat','$source','$filename','$vsys')";
                                    $fullObject[$name]["table_name"]="address";
                                    $fullObject[$name]["member_lid"]=$address_lid;
                                    $address_lid++;
                                }
                            }
                            if (($objKey=="auto-rule") AND ($newObj==true)){
                                $autoRule=true;
                            }

                        }*/
                        if ((isset($object['nat-settings'])) AND ($object['nat-settings']!="") ){
                            $autoRule=false;
                            if (isset($object["nat-settings"]["auto-rule"])){
                                if ($object["nat-settings"]["auto-rule"]=="yes" || $object["nat-settings"]["auto-rule"]=="true"){
                                    $autoRule=true;
                                    if (isset($object["nat-settings"]["method"])){
                                        $fullObject[$name]["nat"]["method"]=$object["nat-settings"]["method"];

                                        if ($object["nat-settings"]["method"]=="hide"){
                                            if (isset($object["nat-settings"]["hide-behind"])){
                                                if ($object["nat-settings"]["hide-behind"]=="gateway"){
                                                    $object["nat-settings"]["hide-behind"]="gateway";
                                                }
                                                else{
                                                    echo ">>>>>>>Unexpected object: NAT-SETTINGS->HIDE->HIDE-BEHIND->".$object["nat-settings"]["hide-behind"]."on object_type[" . $object['type'] . "]::object_name[" . $object['name'] . "] Please send email to fwmigrate@paloaltonetworks.com ".PHP_EOL;
                                                }
                                            }
                                        }

                                        if ( (isset($object["nat-settings"]["install-on"])) AND ($object["nat-settings"]["install-on"]!="Any")){
                                            $fullObject[$name]["nat"]["target"]=$object["nat-settings"]["install-on"];
                                        }

                                        if ((isset($object["nat-settings"]["ipv4-address"])) AND ($object["nat-settings"]["ipv4-address"]!="")){
                                            $newObj=$object["nat-settings"]["ipv4-address"];
                                            if (!isset($fullObject["H-".$newObj])){
                                                $addNetworksv4[]="('$address_lid','ip-netmask','ip-netmask','$newObj','','H-$newObj','H-$newObj','0','1','Auto Nat','$source','$filename','$vsys')";
                                                $fullObject["H-".$newObj]["table_name"]="address";
                                                $fullObject["H-".$newObj]["member_lid"]=$address_lid;
                                                $address_lid++;
                                            }
                                            $fullObject[$name]["nat"]["translated"]["table_name"]="address";
                                            $fullObject[$name]["nat"]["translated"]["member_lid"]=$fullObject["H-".$newObj]["member_lid"];
                                        }

                                        if ((isset($object["nat-settings"]["ipv6-address"])) AND ($object["nat-settings"]["ipv6-address"]!="") AND ($object["nat-settings"]["ipv6-address"]!="::")){
                                            $newObj=$object["nat-settings"]["ipv6-address"];
                                            if (!isset($fullObject["H-".$newObj])){
                                                $addNetworksv6[]="('$address_lid','ip-netmask','ip-netmask','$newObj','','H-$newObj','H-$newObj','0','1','Auto Nat','$source','$filename','$vsys')";
                                                $fullObject["H-".$newObj]["table_name"]="address";
                                                $fullObject["H-".$newObj]["member_lid"]=$address_lid;
                                                $address_lid++;
                                            }
                                            $fullObject[$name]["nat"]["translated"]["table_name"]="address";
                                            $fullObject[$name]["nat"]["translated"]["member_lid"]=$fullObject["H-".$newObj]["member_lid"];

                                        }
                                    }

                                }
                            }


                            $autoRule=false;
                            foreach($object['nat-settings'] as $objKey=>$newObj){
                                if ($autoRule==true){
                                    if (($objKey=="ipv4-address") AND ($newObj!="")){
                                        $addNetworksv4[]="('$address_lid','ip-netmask','ip-netmask','$newObj','','H-$newObj','H-$newObj','0','1','Auto Nat','$source','$filename','$vsys')";
                                        $fullObject[$name]["table_name"]="address";
                                        $fullObject[$name]["member_lid"]=$address_lid;
                                        $address_lid++;
                                    }
                                    if (($objKey=="ipv6-address") AND ($newObj!="") AND ($newObj!="::")){
                                        $addNetworksv6[]="('$address_lid','ip-netmask','ip-netmask','$newObj','','H-$newObj','H-$newObj','0','1','Auto Nat','$source','$filename','$vsys')";
                                        $fullObject[$name]["table_name"]="address";
                                        $fullObject[$name]["member_lid"]=$address_lid;
                                        $address_lid++;
                                    }
                                }
                                if (($objKey=="auto-rule") AND ($newObj==true)){
                                    $autoRule=true;
                                }

                            }
                        }
                    }
                }
                break;
            case "address-range":
                if (!isset($fullObject[$name])) {
                    if ((isset($object['ipv4-address-first'])) AND ($object['ipv4-address-first'] != "")) {
                        $ip=$object['ipv4-address-first']."-".$object['ipv4-address-last'];
                        $addNetworksv4[]="('$address_lid','ip-range','ip-netmask','$ip','','$name','$name_int','0','1','$description','$source','$filename','$vsys')";
                        $fullObject[$name]["table_name"]="address";
                        $fullObject[$name]["member_lid"]=$address_lid;
                        $fullObject[$name]["ipaddress"]=$ip;
                        $fullObject[$name]["cidr"]="";
                        $address_lid++;
                    }

                    if ((isset($object['ipv6-address-first'])) AND ($object['ipv6-address-first']!="")){
                        $ip=$object['ipv6-address-first']."-".$object['ipv6-address-last'];
                        $addNetworksv6[]="('$address_lid','ip-range','ip-netmask','$ip','','$name','$name_int','0','1','$description','$source','$filename','$vsys')";
                        $fullObject[$name]["table_name"]="address";
                        $fullObject[$name]["member_lid"]=$address_lid;
                        $address_lid++;
                    }

                    if ((isset($object['nat-settings'])) AND ($object['nat-settings']!="") ){
                        $autoRule=false;
                        if (isset($object["nat-settings"]["auto-rule"])){
                            if ($object["nat-settings"]["auto-rule"]=="yes" || $object["nat-settings"]["auto-rule"]=="true"){
                                $autoRule=true;
                                if (isset($object["nat-settings"]["method"])){
                                    $fullObject[$name]["nat"]["method"]=$object["nat-settings"]["method"];

                                    if ($object["nat-settings"]["method"]=="hide"){
                                        if (isset($object["nat-settings"]["hide-behind"])){
                                            if ($object["nat-settings"]["hide-behind"]=="gateway"){
                                                $fullObject[$name]["nat"]["hide-behind"]="gateway";
                                            }
                                            elseif ($object["nat-settings"]["hide-behind"]=="ip-address"){
                                                //Nothing to do, the valid NATted IP is already specified
                                                $fullObject[$name]["nat"]["hide-behind"]="ip-address";
                                            }
                                            else{
                                                //print "Unexpected object: NAT-SETTINGS->HIDE->HIDE-BEHIND->".$object["nat-settings"]["hide-behind"]." Please send email to fwmigrate@paloaltonetworks.com ".PHP_EOL;
                                                echo ">>>>>>>Unexpected object: NAT-SETTINGS->HIDE->HIDE-BEHIND->".$object["nat-settings"]["hide-behind"]."on object_type[" . $object['type'] . "]::object_name[" . $object['name'] . "] Please send email to fwmigrate@paloaltonetworks.com ".PHP_EOL;
                                            }
                                        }
                                    }

                                    if ( (isset($object["nat-settings"]["install-on"])) AND ($object["nat-settings"]["install-on"]!="Any")){
                                        $fullObject[$name]["nat"]["target"]=$object["nat-settings"]["install-on"];
                                    }

                                    if ((isset($object["nat-settings"]["ipv4-address"])) AND ($object["nat-settings"]["ipv4-address"]!="")){
                                        $newObj=$object["nat-settings"]["ipv4-address"];
                                        if (!isset($fullObject["H-".$newObj])){
                                            $addNetworksv4[]="('$address_lid','ip-netmask','ip-netmask','$newObj','','H-$newObj','H-$newObj','0','1','Auto Nat','$source','$filename','$vsys')";
                                            $fullObject["H-".$newObj]["table_name"]="address";
                                            $fullObject["H-".$newObj]["member_lid"]=$address_lid;
                                            $address_lid++;
                                        }
                                        $fullObject[$name]["nat"]["translated"]["table_name"]="address";
                                        $fullObject[$name]["nat"]["translated"]["member_lid"]=$fullObject["H-".$newObj]["member_lid"];
                                    }

                                    if ((isset($object["nat-settings"]["ipv6-address"])) AND ($object["nat-settings"]["ipv6-address"]!="") AND ($object["nat-settings"]["ipv6-address"]!="::")){
                                        $newObj=$object["nat-settings"]["ipv6-address"];
                                        if (!isset($fullObject["H-".$newObj])){
                                            $addNetworksv6[]="('$address_lid','ip-netmask','ip-netmask','$newObj','','H-$newObj','H-$newObj','0','1','Auto Nat','$source','$filename','$vsys')";
                                            $fullObject["H-".$newObj]["table_name"]="address";
                                            $fullObject["H-".$newObj]["member_lid"]=$address_lid;
                                            $address_lid++;
                                        }
                                        $fullObject[$name]["nat"]["translated"]["table_name"]="address";
                                        $fullObject[$name]["nat"]["translated"]["member_lid"]=$fullObject["H-".$newObj]["member_lid"];
                                    }
                                }

                            }
                        }


                        $autoRule=false;
                        foreach($object['nat-settings'] as $objKey=>$newObj){
                            if ($autoRule==true){
                                if (($objKey=="ipv4-address") AND ($newObj!="")){
                                    $addNetworksv4[]="('$address_lid','ip-netmask','ip-netmask','$newObj','','H-$newObj','H-$newObj','0','1','Auto Nat','$source','$filename','$vsys')";
                                    $fullObject[$name]["table_name"]="address";
                                    $fullObject[$name]["member_lid"]=$address_lid;
                                    $address_lid++;
                                }
                                if (($objKey=="ipv6-address") AND ($newObj!="") AND ($newObj!="::")){
                                    $addNetworksv6[]="('$address_lid','ip-netmask','ip-netmask','$newObj','','H-$newObj','H-$newObj','0','1','Auto Nat','$source','$filename','$vsys')";
                                    $fullObject[$name]["table_name"]="address";
                                    $fullObject[$name]["member_lid"]=$address_lid;
                                    $address_lid++;
                                }
                            }
                            if (($objKey=="auto-rule") AND ($newObj==true)){
                                $autoRule=true;
                            }

                        }
                    }

                    if ( (isset($object['groups'])) AND (count($object['groups'])>0) ){
                        foreach($object['groups'] as $ikey=>$newObjectGRoup){
                            if (is_array($newObjectGRoup)){
                                $objectsGroups[]=$newObjectGRoup;
                            }
                        }
                    }
                }

                break;
            case "CpmiGatewayPlain":
            case "CpmiClusterMember":
            case "simple-cluster":
            case "cluster-member":
            case "simple-gateway":
                // We need to assure all Address-Group has a proper uid
                // so when reading and object that was previously created as member
                // we should update its uid
                if(!isset($fullObject[$name]) && in_array($name_int, array_column($objectsGroups, 'name'), true )){
                    foreach($objectsGroups as &$group){
                        if($group['name'] === $name_int && $group['uid'] === $name_int){
                            $group['uid']=$object['uid'];
                            break;
                        }
                    }
                }
                if (!isset($fullObject[$name]) && !in_array($name_int, array_column($objectsGroups, 'name'), true )  ){

                    // We need to create an address-group with below read objects within this checkpoint type:
                    // cluster-members -> as address-group (Note: a cluster-member could have inside interfaces (networks) and ipv4 and ipv6 hosts)
                    // cluster-members -> interfaces -> as networks within cluster-member address-group
                    // ipv4 -> host
                    // ipv6 -> host

                    $members_names = array();
                    if(isset($object['cluster-members'])){

                        $cluster_member_array = $object['cluster-members'];
                        foreach($cluster_member_array as $cluster_member) {
                            $cluster_name = normalizeNames(truncate_names($cluster_member['name']));
                            // if the cluster is already created we only use it but we do not create it again
                            if(!in_array($cluster_name, array_column($objectsGroups, 'name'), true )) {
                                $cluster_members_names = array();
                                // a cluster will be always an address group
                                // it will contain its IP as a Host member
                                // and interfaces as subnet members
                                // check if the cluster has defined an ip-address v4
                                if (isset($cluster_member['ip-address']) && $cluster_member['ip-address'] !== "") {
                                    $cluster_member_name = "H-" . normalizeNames(truncate_names($cluster_member['name'])) . "-v4";
                                    $cluster_member_v4_ip = $cluster_member['ip-address'];

                                    $addNetworksv4[] = "('$address_lid','ip-netmask','ip-netmask','$cluster_member_v4_ip','','$cluster_member_name','$cluster_member_name','0','1','$description','$source','$filename','$vsys')";
                                    $fullObject[$cluster_member_name]["table_name"] = "address";
                                    $fullObject[$cluster_member_name]["member_lid"] = $address_lid;
                                    $fullObject[$cluster_member_name]["ipaddress"] = $cluster_member_v4_ip;
                                    $fullObject[$cluster_member_name]["cidr"] = "32";
                                    $address_lid++;
                                    $cluster_members_names[] = $cluster_member_name;
                                }
                                // check if the cluster has defined an ip-address v6
                                if (isset($cluster_member['ipv6-address']) && $cluster_member['ipv6-address'] !== "") {
                                    $cluster_member_name = "H-" . normalizeNames(truncate_names($cluster_member['name'])) . "-v6";
                                    $cluster_member_v6_ip = $cluster_member['ipv6-address'];

                                    $addNetworksv6[] = "('$address_lid','ip-netmask','ip-netmask','$cluster_member_v6_ip','','$cluster_member_name','$cluster_member_name','0','1','$description','$source','$filename','$vsys')";
                                    $fullObject[$cluster_member_name]["table_name"] = "address";
                                    $fullObject[$cluster_member_name]["member_lid"] = $address_lid;
                                    $address_lid++;
                                    $cluster_members_names[] = $cluster_member_name;
                                }


                                // ckeck if the cluster is defining interfaces
                                if (isset($cluster_member['interfaces'])) {

                                    $cluster_member_interfaces_array = $cluster_member['interfaces'];

                                    foreach ($cluster_member_interfaces_array as $cluster_member_interface) {
                                        get_cluster_interfaces($source, $filename, $vsys, $cluster_member_interface, $address_lid, $cluster_members_names, $addNetworksv4, $addNetworksv6, $fullObject);
                                    }

                                }
                                // if we have an address or interfaces, we will create a new address_group with the cluster_member_name
                                if (count($cluster_members_names) > 0) {
                                    $objectG = [
                                        'icon' => 'General/group',
                                        'name' => "$cluster_name",
                                        'uid' => "$cluster_name",
                                        'type' => "group",
                                        'comments' => 'Cluster containing Host and Interfaces defined by ' . $name_int,
                                        'members' => $cluster_members_names
                                    ];
                                    $objectsGroups[] = $objectG;
                                }
                            }
                            // add the cluster to the current read object
                            $members_names[] = $cluster_name;
                        }
                    }
                    if(isset($object['interfaces'])){
                        $interface_array = $object['interfaces']; // case cluster-member
                        if(isset($object['interfaces']['objects'])){
                            $interface_array = $object['interfaces']['objects']; // case simple-cluster
                        }
                        foreach ($interface_array as $interface){
                                get_cluster_interfaces($source, $filename, $vsys, $interface,$address_lid,$members_names,$addNetworksv4, $addNetworksv6 , $fullObject);
                        }
                    }

                    $ipv4_text = "ipv4-address";
                    if(isset($object['ip-address'])){
                        $ipv4_text = 'ip-address';
                    }

                    if((isset($object[$ipv4_text])) AND ($object[$ipv4_text]!="") && (isset($object['ipv6-address'])) AND ($object['ipv6-address']!="") AND ($object['ipv6-address']!="::")){
                        //This target device has IPv4 and IPv6
                        $ip = $object[$ipv4_text];

                        $addNetworksv4[] = "('$address_lid','ip-netmask','ip-netmask','$ip','','${name}-v4','${name_int}-v4','0','1','$description','$source','$filename','$vsys')";
                        $fullObject["${name}-v4"]["table_name"] = "address";
                        $fullObject["${name}-v4"]["member_lid"] = $address_lid;
                        $fullObject["${name}-v4"]["ipaddress"] = $ip;
                        $fullObject["${name}-v4"]["cidr"] = "32";
                        $address_lid++;
                        $members_names[] = "${name}-v4";

                        $ip = $object['ipv6-address'];
                        $addNetworksv6[] = "('$address_lid','ip-netmask','ip-netmask','$ip','','${name}-v6','${name_int}-v6','0','1','$description','$source','$filename','$vsys')";
                        $fullObject["${name}-v6"]["table_name"] = "address";
                        $fullObject["${name}-v6"]["member_lid"] = $address_lid;
                        $address_lid++;
                        $members_names[] = "${name}-v6";

                        $objectG=[
                            'icon'      => 'General/group',
                            'name'      => "$name_int",
                            'uid'       => "$name",
                            'type'      =>"group",
                            'comments'  => $description,
                            'members'   => $members_names
                        ];
                        $objectsGroups[]=$objectG;
                    }
                    else {
                        if(count($members_names)>1){ // We need to create the object as an address-group

                            if (  (isset($object[$ipv4_text])) && ($object[$ipv4_text] != "") ) {

                                $ip = $object[$ipv4_text];

                                $addNetworksv4[] = "('$address_lid','ip-netmask','ip-netmask','$ip','','${name}-v4','${name_int}-v4','0','1','$description','$source','$filename','$vsys')";
                                $fullObject["${name}-v4"]["table_name"] = "address";
                                $fullObject["${name}-v4"]["member_lid"] = $address_lid;
                                $fullObject["${name}-v4"]["ipaddress"] = $ip;
                                $fullObject["${name}-v4"]["cidr"] = "32";
                                $address_lid++;
                                $members_names[] = "${name}-v4";
                            }
                            if ((isset($object['ipv6-address'])) && ($object['ipv6-address'] != "") && ($object['ipv6-address'] != "::")) {
                                $ip = $object['ipv6-address'];
                                $addNetworksv6[] = "('$address_lid','ip-netmask','ip-netmask','$ip','','${name}-v6','${name_int}-v6','0','1','$description','$source','$filename','$vsys')";
                                $fullObject["${name}-v6"]["table_name"] = "address";
                                $fullObject["${name}-v6"]["member_lid"] = $address_lid;
                                $address_lid++;
                                $members_names[] = "${name}-v6";
                            }

                            // if we have read cluster or interfaces before the ipv4 or ipv6 address then
                            // we will have the list of objects that should be required to set as members
                            // for this new address_group
                            $objectG=[
                                'icon'      => 'General/group',
                                'name'      => "$name_int",
                                'uid'       => "$name",
                                'type'      =>"group",
                                'comments'  => $description,
                                'members'   => $members_names
                            ];
                            $objectsGroups[]=$objectG;
                        } else { // We need to create the object as an address

                            if (  (isset($object[$ipv4_text])) && ($object[$ipv4_text] != "") ) {

                                $ip = $object[$ipv4_text];

                                $addNetworksv4[] = "('$address_lid','ip-netmask','ip-netmask','$ip','','$name','$name_int','0','1','$description','$source','$filename','$vsys')";
                                $fullObject[$name]["table_name"] = "address";
                                $fullObject[$name]["member_lid"] = $address_lid;
                                $fullObject[$name]["ipaddress"] = $ip;
                                $fullObject[$name]["cidr"] = "32";
                                $address_lid++;
                            }
                            if ((isset($object['ipv6-address'])) and ($object['ipv6-address'] != "") && ($object['ipv6-address'] != "::")) {
                                $ip = $object['ipv6-address'];
                                $addNetworksv6[] = "('$address_lid','ip-netmask','ip-netmask','$ip','','$name','$name_int','0','1','$description','$source','$filename','$vsys')";
                                $fullObject[$name]["table_name"] = "address";
                                $fullObject[$name]["member_lid"] = $address_lid;
                                $address_lid++;
                            }
                            // When the object to create is an address it could have some information regarding NAT (example type CpmiGatewayPlain).
                            if (isset($object['natSummaryText']) && (strtolower(trim($object['natSummaryText']))!="none")){
                                $summaryParts = parseNatSummaryText($object['natSummaryText']);

                                foreach ($summaryParts as $summaryPart){
                                    $fullObject[$name]["nat"]["method"]= $summaryPart['method'];
                                    if(isset($summaryPart['ipv']) && $summaryPart['ipv'] ==='ipv6'){
                                        $newObj = $summaryPart['value'];
                                        if (!isset($fullObject["H-".$newObj])){
                                            $addNetworksv4[]="('$address_lid','ip-netmask','ip-netmask','$newObj','','H-$newObj','H-$newObj','1','0','Auto Nat','$source','$filename','$vsys')";
                                            $fullObject["H-".$newObj]["table_name"]="address";
                                            $fullObject["H-".$newObj]["member_lid"]=$address_lid;
                                            $address_lid++;
                                        }
                                    }
                                    else if(isset($summaryPart['value'])){
                                        $newObj = $summaryPart['value'];
                                        if (!isset($fullObject["H-".$newObj])){
                                            $addNetworksv4[]="('$address_lid','ip-netmask','ip-netmask','$newObj','','H-$newObj','H-$newObj','0','1','Auto Nat','$source','$filename','$vsys')";
                                            $fullObject["H-".$newObj]["table_name"]="address";
                                            $fullObject["H-".$newObj]["member_lid"]=$address_lid;
                                            $address_lid++;
                                        }
                                    }
                                    if(isset($fullObject["H-".$newObj]["member_lid"])) {
                                        $fullObject[$name]["nat"]["translated"]["table_name"] = "address";
                                        $fullObject[$name]["nat"]["translated"]["member_lid"] = $fullObject["H-" . $newObj]["member_lid"];
                                    }
                                }
                            }
                        }
                    }
                }
                break;
            case "CpmiGatewayCluster":
            case "CpmiHostCkp":
                if (!isset($fullObject[$name])){
                    if(isset($object['ipv4-address']) AND $object['ipv4-address']!="" && isset($object['ipv6-address']) AND $object['ipv6-address']!="" AND $object['ipv6-address']!="::"){
                        //This target device has IPv4 and IPv6
                        $ip = $object['ipv4-address'];
                        $addNetworksv4[] = "('$address_lid','ip-netmask','ip-netmask','$ip','','${name}-v4','${name_int}-v4','0','1','$description','$source','$filename','$vsys')";
                        $fullObject["${name}-v4"]["table_name"] = "address";
                        $fullObject["${name}-v4"]["member_lid"] = $address_lid;
                        $fullObject["${name}-v4"]["ipaddress"] = $ip;
                        $fullObject["${name}-v4"]["cidr"] = "32";
                        $address_lid++;

                        $ip = $object['ipv6-address'];
                        $addNetworksv6[] = "('$address_lid','ip-netmask','ip-netmask','$ip','','${name}-v6','${name_int}-v6','0','1','$description','$source','$filename','$vsys')";
                        $fullObject["${name}-v6"]["table_name"] = "address";
                        $fullObject["${name}-v6"]["member_lid"] = $address_lid;
                        $address_lid++;

                        $objectG=[
                            'icon'      => 'General/group',
                            'name'      => "$name_int",
                            'uid'       => "$name",
                            'type'      =>"group",
                            'comments'  => $description,
                            'members'   => ["${name}-v4", "${name}-v6"]
                        ];
                        $objectsGroups[]=$objectG;
                    }
                    else {
                        if ((isset($object['ipv4-address'])) and ($object['ipv4-address'] != "")) {
                            $ip = $object['ipv4-address'];
                            $addNetworksv4[] = "('$address_lid','ip-netmask','ip-netmask','$ip','','$name','$name_int','0','1','$description','$source','$filename','$vsys')";
                            $fullObject[$name]["table_name"] = "address";
                            $fullObject[$name]["member_lid"] = $address_lid;
                            $fullObject[$name]["ipaddress"] = $ip;
                            $fullObject[$name]["cidr"] = "32";
                            $address_lid++;
                        }
                        if ((isset($object['ipv6-address'])) and ($object['ipv6-address'] != "") && ($object['ipv6-address'] != "::")) {
                            $ip = $object['ipv6-address'];
                            $addNetworksv6[] = "('$address_lid','ip-netmask','ip-netmask','$ip','','$name','$name_int','0','1','$description','$source','$filename','$vsys')";
                            $fullObject[$name]["table_name"] = "address";
                            $fullObject[$name]["member_lid"] = $address_lid;
                            $address_lid++;
                        }
                    }

                    if (isset($object['natSummaryText']) && (strtolower(trim($object['natSummaryText']))!="none")){
                        $summaryParts = parseNatSummaryText($object['natSummaryText']);

                        foreach ($summaryParts as $summaryPart){
                            $fullObject[$name]["nat"]["method"]= $summaryPart['method'];
                            if(isset($summaryPart['ipv']) && $summaryPart['ipv'] ==='ipv6'){
                                $newObj = $summaryPart['value'];
                                if (!isset($fullObject["H-".$newObj])){
                                    $addNetworksv6[]="('$address_lid','ip-netmask','ip-netmask','$newObj','','H-$newObj','H-$newObj','1','0','Auto Nat','$source','$filename','$vsys')";
                                    $fullObject["H-".$newObj]["table_name"]="address";
                                    $fullObject["H-".$newObj]["member_lid"]=$address_lid;
                                    $address_lid++;
                                }
                            }
                            else if(isset($summaryPart['value'])){
                                $newObj = $summaryPart['value'];
                                if (!isset($fullObject["H-".$newObj])){
                                    $addNetworksv4[]="('$address_lid','ip-netmask','ip-netmask','$newObj','','H-$newObj','H-$newObj','0','1','Auto Nat','$source','$filename','$vsys')";
                                    $fullObject["H-".$newObj]["table_name"]="address";
                                    $fullObject["H-".$newObj]["member_lid"]=$address_lid;
                                    $address_lid++;
                                }
                            }
                            if(isset($fullObject["H-".$newObj]["member_lid"])) {
                                $fullObject[$name]["nat"]["translated"]["table_name"] = "address";
                                $fullObject[$name]["nat"]["translated"]["member_lid"] = $fullObject["H-" . $newObj]["member_lid"];
                            }
                        }
                    }
                }
                break;
            case "Track":
                # Generate Log so this object will not be migrated
                if ($object['name']=="Log"){
                    $common['log']=$name;
                }
                elseif($object['name']=="None"){
                    $common['none']=$name;
                }
                break;
            case "CpmiAnyObject":
                if ($object['name']=="Any"){
                    $common["any"]=$name;
                }
                elseif($object['name']=="All"){
                    $common["all"]=$name;
                }
                if (!isset($fullObject[$name])) {
                    //$name_int = 'ANY ipv4';
                    $ip='0.0.0.0';
                    $mask='0';
                    $description = 'Default ANY object';
                    $addNetworksv4[]="('$address_lid','ip-netmask','ip-netmask','$ip','$mask','$name','$name_int','0','1','$description','$source','$filename','$vsys')";
                    $fullObject[$name]["table_name"]="address";
                    $fullObject[$name]["member_lid"]=$address_lid;
                    $fullObject[$name]["ipaddress"]=$ip;
                    $fullObject[$name]["cidr"]=$mask;
                    $address_lid++;
                }

                break;
            case "RulebaseAction":
                $action=$object['name'];
                if ($action=="Accept"){$action="allow";}
                elseif($action=="Drop"){$action="drop";}
                elseif ($action=="Reject"){$action="deny";}
                $common["$action"]=$name;
                break;
            case "Global":
                $global=$object['name'];
                if ($global=="Policy Targets"){
                    $common["Policy Targets"]=$name;
                }
                elseif ($global=="Original"){
                    $common["Original"]=$name;
                }
                elseif ($global=="Inner Layer"){
                    $common["Inner Layer"]=$name;
                }
                break;
            case "time":
                //echo "Unsupported Object TIME [".$object['name']."]".PHP_EOL;
                echo "#######Unsupported Object#####: object_type[" . $object['type'] . "]::object_name[" . $object['name'] ."]\n";
                add_log2('warning', 'Reading Objects', "Unsupported Object found: [". $object['type'] . "] in Object Name: [" . $object['name'] ."]", $source, 'Review usage on original configuration', '', '', '');
                storeNotSupportedObject($object, $objectsNotSupported);
                if (!isset($schedules[$name])){
                    $schedules[$name]=trim($object['name']);
                }
                break;
            case "vpn-community-meshed":
                //echo "Unsupported Object VPN COMMUNITY MESHED [".$object['name']."]".PHP_EOL;
                echo "#######Unsupported Object#####: object_type[" . $object['type'] . "]::object_name[" . $object['name'] ."]\n";
                add_log2('warning', 'Reading Objects', "Unsupported Object found: [". $object['type'] . "] in Object Name: [" . $object['name'] ."]", $source, 'Review usage on original configuration', '', '', '');
                storeNotSupportedObject($object, $objectsNotSupported);
                #print_r($object);
                break;
//            case "CpmiLogicalServer":
//                if (!isset($fullObject[$name])){
//                    if ((isset($object['ipv4-address'])) AND ($object['ipv4-address']!="")){
//                        $ip=$object['ipv4-address'];
//                        $addNetworksv4[]="('$address_lid','ip-netmask','ip-netmask','$ip','','$name','$name_int','0','1','$description','$source','$filename')";
//                        $fullObject[$name]["table_name"]="address";
//                        $fullObject[$name]["member_lid"]=$address_lid;
//                        $address_lid++;
//                    }
//                    if ((isset($object['ipv6-address'])) AND ($object['ipv6-address']!="")){
//                        $ip=$object['ipv6-address'];
//                        $addNetworksv6[]="('$address_lid','ip-netmask','ip-netmask','$ip','','$name','$name_int','0','1','$description','$source','$filename')";
//                        $fullObject[$name]["table_name"]="address";
//                        $fullObject[$name]["member_lid"]=$address_lid;
//                        $address_lid++;
//                    }
//                }
//                break;
            case "access-role":
                if (!isset($accessRoles[$name])){
                    $accessRoles[$name]=array();
                    if (isset($object['users']) && is_array($object['users']) ){
                        foreach($object['users'] as $userObject){
                            if (isset($userObject['tooltiptext'])){
                                $tooltip=explode("\n",$userObject['tooltiptext']);
                                $Udomain=preg_replace("/\<B\>Domain Name = /", " ", $tooltip[0]);
                                $Udomain=preg_replace("/\<\/B\>/", " ", $Udomain);
                                if ($userObject['type']=="CpmiAdUser"){
                                    $tooltip1=preg_replace("/Username = /", " ", $tooltip[1]);
                                    $Uuser=trim($Udomain)."\\".trim($tooltip1);
                                    $accessRoles[$name][]=$Uuser;
                                }
                                elseif ($userObject['type']=="CpmiAdGroup"){
                                    $tooltip1=preg_replace("/Group Name = /", " ", $tooltip[1]);
                                    $Ugroup=trim($Udomain)."\\".trim($tooltip1);
                                    $accessRoles[$name][]=$Ugroup;
                                }

                            }
                            if (isset($userObject['dn'])) {
                                $accessRoles[$name]['dn'][]=$userObject['dn'];
                            }
                        }

                    }




                }
                break;
            case "Internet":

                $addNetworksv4[]="('$address_lid','ip-netmask','ip-netmask','0.0.0.0','0','$name','$name_int','1','1','$description','$source','$filename','$vsys')";
                $fullObject[$name]["table_name"]="address";
                $fullObject[$name]["member_lid"]=$address_lid;
                $fullObject[$name]["ipaddress"]='0.0.0.0';
                $fullObject[$name]["cidr"]="0";
                $address_lid++;


                break;
            case "group-with-exclusion":
                if (!isset($fullObject[$name])){
                    $objectsExclusionGroups[]=$object;
                }
                break;
            case "access-layer":
                if (!isset($accessLayers[$name])){
                    $accessLayers[$name]=$object;
                }
                break;
            default:
                if ($object['type']=="group"){
                    $objectsGroups[]=$object;
                }
                elseif ($object['type']=="service-group"){
                    $objectsServicesGroups[]=$object;
                    // MT-2374 service-group can contain members that are service-groups
                    // we need to store a map with read service-groups and assign them a db id
                    $service_group_name = normalizeNames(truncate_names($object['name']));
                    $service_group_uuid = $object['uid'];
                    $service_group_description = addslashes($object['comments']);
                    // Map is indexed by uuid to access directly to an specific service_group
                    $service_group_map[$service_group_uuid]['service_group_uuid']=$service_group_uuid;
                    $service_group_map[$service_group_uuid]['service_group_name']=$service_group_name;
                    $service_group_map[$service_group_uuid]['service_group_description']=$service_group_description;
                    $service_group_map[$service_group_uuid]['service_group_id']=$service_group_id; // calculate the db_id
                    $service_group_id++;
                }
                else{
                    echo "#######Unsupported Object#####: object_type[" . $object['type'] . "]::object_name[" . $object['name'] ."]\n";
                    add_log2('warning', 'Reading Objects', "Unsupported Object found: [". $object['type'] . "] in Object Name: [" . $object['name'] ."]", $source, 'Review usage on original configuration', '', '', '');
                    storeNotSupportedObject($object, $objectsNotSupported);
                }
                break;
        }
    }


    if (count($objectsGroups)>0){
        $missingMembersPerAddressGroup = array(); //This will be a "list" of the missing members in each group after the first pass

        $input = array_map("unserialize", array_unique(array_map("serialize", $objectsGroups)));
        $objectsGroups=$input;
        foreach ($objectsGroups as $key => &$object) {
            $name_int = normalizeNames(truncate_names($object['name']));
            $name = $object['uid'];
            $object['aglid'] = $aglid;
            if (!isset($fullObject[$name])){
                $description = addslashes($object['comments']);
                $addAddressGroups[]="('$aglid','$name','$name_int','static','$filename','$source','$vsys','$description')";
                $fullObject[$name]["member_lid"]=$aglid;
                $fullObject[$name]["table_name"]="address_groups_id";

                if(isset($object['nat'])){
                    $fullObject[$name]["nat"]=$object['nat'];
                }

                if (isset($object['members'])){
                    $parentAG=$aglid;
                    foreach ($object['members'] as $member){
                        if (is_array($member)) {
                            if ( (isset($member['uid'])) AND (isset($fullObject[$member['uid']])) ) {
                                $member_lid=$fullObject[$member['uid']]["member_lid"];
                                $table_name=$fullObject[$member['uid']]["table_name"];
                                $addAddressMembers[]="('$vsys','".$member['uid']."','$parentAG','$source','$member_lid','$table_name')";
                            }
                            else{
                                if ($member['type']=="group"){
                                    $name_int1 = normalizeNames(truncate_names($member['name']));
                                    $name1 = $member['uid'];
                                    $description = addslashes($member['comments']);
                                    $aglid++;
                                    $addAddressMembers[] = "('$vsys','" . $member['uid'] . "','$parentAG','$source','$aglid','address_groups_id')";
                                    $addAddressGroups[]="('$aglid','$name1','$name_int1','static','$filename','$source','$vsys','$description')";
                                    $fullObject[$name1]["member_lid"]=$aglid;
                                    $fullObject[$name1]["table_name"]="address_groups_id";
                                    if (isset($member['members'])) {
                                        foreach ($member['members'] as $member2) {
                                            if (is_array($member2)) {
                                                if ((isset($member2['uid'])) AND (isset($fullObject[$member2['uid']]))) {
                                                    $member_lid2 = $fullObject[$member2['uid']]["member_lid"];
                                                    $table_name2 = $fullObject[$member2['uid']]["table_name"];
                                                    $addAddressMembers[] = "('$vsys','" . $member2['uid'] . "','$aglid','$source','$member_lid2','$table_name2')";
                                                }
                                                else {
                                                    print "ERROR:";print_r($member2);
                                                }
                                            }
                                            else{
                                                if (isset($fullObject[$member2])) {
                                                    $member_lid2 = $fullObject[$member2]["member_lid"];
                                                    $table_name2 = $fullObject[$member2]["table_name"];
                                                    $addAddressMembers[] = "('$vsys','" . $member2 . "','$aglid','$source','$member_lid2','$table_name2')";
                                                } else {
                                                    //add_log2('error', 'Reading Member Groups', 'Group called ' . $name_int1 . ' is missing this member UID: ' . $member2, $source, 'Check in your Checkpoint GUI', '', '', '');
                                                    $missingMembersPerAddressGroup[$aglid]['members'][] = $member2; //This member may not have been created as a group yet
                                                    $missingMembersPerAddressGroup[$aglid]['name'] = $name_int1;
                                                }
                                            }
                                        }
                                    }
                                    $aglid++;
                                }
                                else{
                                    print "ERROR---";print_r($member);
                                }

                                // add_log2('error','Reading Member Groups','Group called '.$name_int.' is missing this member UID: '.print_r($member),$source,'Check in your Checkpoint GUI','','','');
                            }
                        }
                        else{
                            if (isset($fullObject[$member])){
                                if(isset($fullObject[$member]["member_lid"])){
                                    $member_lid=$fullObject[$member]["member_lid"];
                                    $table_name=$fullObject[$member]["table_name"];
                                    $addAddressMembers[]="('$vsys','".$member."','$aglid','$source','$member_lid','$table_name')";
                                } else {
                                    $missingMembersPerAddressGroup[$aglid]['members'][] = $member; //This member may not have been created as a group yet
                                    $missingMembersPerAddressGroup[$aglid]['name'] = $name_int;
                                }
                            }
                            else{
                                //add_log2('error','Reading Member Groups','Group called '.$name_int.' is missing this member UID: '.$member,$source,'Check in your Checkpoint GUI','','','');
                                $missingMembersPerAddressGroup[$aglid]['members'][] = $member; //This member may not have been created as a group yet
                                $missingMembersPerAddressGroup[$aglid]['name'] = $name_int;
                            }
                        }
                    }
                }
                $aglid++;

                if (isset($object['groups'])){
                    foreach ($object['groups'] as $internalgroup){
                        if (isset($internalgroup['uid'])){
                            $name_int = normalizeNames(truncate_names($internalgroup['name']));
                            $name = $internalgroup['uid'];

                            if (!isset($fullObject[$name])){
                                $description = addslashes($internalgroup['comments']);
                                $addAddressGroups[]="('$aglid','$name','$name_int','static','$filename','$source','$vsys','$description')";
                                $fullObject[$name]["member_lid"]=$aglid;
                                $fullObject[$name]["table_name"]="address_groups_id";
                                if (isset($object['members'])){
                                    $parentAG=$aglid;
                                    foreach ($internalgroup['members'] as $member){
                                        if (is_array($member)) {
                                            if ( (isset($member['uid'])) AND (isset($fullObject[$member['uid']])) ) {
                                                $member_lid=$fullObject[$member['uid']]["member_lid"];
                                                $table_name=$fullObject[$member['uid']]["table_name"];
                                                $addAddressMembers[]="('$vsys','".$member['uid']."','$parentAG','$source','$member_lid','$table_name')";
                                            }
                                            else{
                                                if ($member['type']=="group"){
                                                    $name_int1 = normalizeNames(truncate_names($member['name']));
                                                    $name1 = $member['uid'];
                                                    $description = addslashes($member['comments']);
                                                    $aglid++;
                                                    $addAddressMembers[] = "('$vsys','" . $member['uid'] . "','$parentAG','$source','$aglid','address_groups_id')";
                                                    $addAddressGroups[]="('$aglid','$name1','$name_int1','static','$filename','$source','$vsys','$description')";
                                                    $fullObject[$name1]["member_lid"]=$aglid;
                                                    $fullObject[$name1]["table_name"]="address_groups_id";
                                                    if (isset($member['members'])) {
                                                        foreach ($member['members'] as $member2) {
                                                            if (is_array($member2)) {
                                                                if ((isset($member2['uid'])) AND (isset($fullObject[$member2['uid']]))) {
                                                                    $member_lid2 = $fullObject[$member2['uid']]["member_lid"];
                                                                    $table_name2 = $fullObject[$member2['uid']]["table_name"];
                                                                    $addAddressMembers[] = "('$vsys','" . $member2['uid'] . "','$aglid','$source','$member_lid2','$table_name2')";
                                                                }
                                                                else {
                                                                    print "ERROR:";print_r($member2);
                                                                }
                                                            }
                                                            else{
                                                                if (isset($fullObject[$member2])) {
                                                                    $member_lid2 = $fullObject[$member2]["member_lid"];
                                                                    $table_name2 = $fullObject[$member2]["table_name"];
                                                                    $addAddressMembers[] = "('$vsys','" . $member2 . "','$aglid','$source','$member_lid2','$table_name2')";
                                                                } else {
                                                                    //add_log2('error', 'Reading Member Groups', 'Group called ' . $name_int1 . ' is missing this member UID: ' . $member2, $source, 'Check in your Checkpoint GUI', '', '', '');
                                                                    $missingMembersPerAddressGroup[$aglid]['members'][] = $member2; //This member may not have been created as a group yet
                                                                    $missingMembersPerAddressGroup[$aglid]['name'] = $name_int1;
                                                                }
                                                            }
                                                        }
                                                    }
                                                    $aglid++;
                                                }
                                                else{
                                                    print "ERROR---";print_r($member);
                                                }

                                                // add_log2('error','Reading Member Groups','Group called '.$name_int.' is missing this member UID: '.print_r($member),$source,'Check in your Checkpoint GUI','','','');
                                            }
                                        }
                                        else{
                                            if (isset($fullObject[$member])){
                                                $member_lid=$fullObject[$member]["member_lid"];
                                                $table_name=$fullObject[$member]["table_name"];
                                                $addAddressMembers[]="('$vsys','".$member."','$aglid','$source','$member_lid','$table_name')";
                                            }
                                            else{
                                                //add_log2('error','Reading Member Groups','Group called '.$name_int.' is missing this member UID: '.$member,$source,'Check in your Checkpoint GUI','','','');
                                                $missingMembersPerAddressGroup[$aglid]['members'][] = $member; //This member may not have been created as a group yet
                                                $missingMembersPerAddressGroup[$aglid]['name'] = $name_int;
                                            }
                                        }
                                    }
                                }
                                $aglid++;
                            }
                        }

                    }
                }

            }
            else{
                //print_r($fullObject[$object['uid']]);
            }
        }
    }

    if (count($objectsExclusionGroups)>0){
        // create a tag for address_group_with_exclusion
        $tag_id = add_tag("GROUP_WITH_EXCLUSION",$source,$vsys,"color16");

        $aglid++;
        foreach ($objectsExclusionGroups as $object) {
            $name_int = normalizeNames(truncate_names($object['name']));
            $name = trim($object['uid']);
            $addAddressGroups[]="('$aglid','$name','$name_int','group_with_exclusion','$filename','$source','$vsys','$description')";
            $fullObject[$name]["member_lid"]=$aglid;
            $fullObject[$name]["table_name"]="address_groups_id";
            add_tag_relations($fullObject[$name]["table_name"], $fullObject[$name]["member_lid"], $tag_id );
            $parentAG=$aglid;
            $aglid++;
            add_log2('info', 'Reading Exclusion Groups', "Exclusion Group '$name' found. ", $source, 'Revise that calculated members are correct.', 'objects', $aglid, 'address_groups_id');

            //Inclusion part
            if(isset($fullObject[trim($object['include']['uid'])])){
                $member_lid=$fullObject[$object['include']['uid']]["member_lid"];
                $table_name=$fullObject[$object['include']['uid']]["table_name"];
                $addAddressMembers[]="('$vsys','".$object['include']['uid']."','$parentAG','$source','$member_lid','$table_name')";
            }
            else{
                if ($object['include']['type']==="group"){
                    $name_int2 = normalizeNames(truncate_names($object['include']['name']));
                    $name2 = trim($object['include']['uid']);
                    $addAddressGroups[]="('$aglid','$name2','$name_int2','static','$filename','$source','$vsys','$description')";
                    $fullObject[$name2]["member_lid"]=$aglid;
                    $fullObject[$name2]["table_name"]="address_groups_id";
                    $newParentAG=$aglid;
                    $addAddressMembers[]="('$vsys','".$object['include']['uid']."','$parentAG','$source','$aglid','address_groups_id')";
                    $aglid++;
                    $members=trim($object['include']['members'][0]);
                    if (isset($fullObject[$members])){
                        $member_lid=$fullObject[$members]["member_lid"];
                        $table_name=$fullObject[$members]["table_name"];
                        $addAddressMembers[]="('$vsys','$members','$newParentAG','$source','$member_lid','$table_name')";
                    }
                    else{
                        add_log2('error', 'Reading Exclusion Groups', "Exclusion Group '$name' found. Member ".$object['include']['name']." [$members] was not found.", $source, 'Revise that calculated members are correct.', 'objects', $aglid, 'address_groups_id');
                        echo "Exclusion Group $name_int: The [include] Member ".$object['include']['name']." [$members] was not found in the Objects Database\n";
                        //print_r($object);
                    }
                }
            }

            //Exception part
            if(isset($fullObject[$object['except']['uid']])){
                $member_lid=$fullObject[$object['except']['uid']]["member_lid"];
                $table_name=$fullObject[$object['except']['uid']]["table_name"];
                $addAddressMembers[]="('$vsys','".$object['except']['uid']."','$parentAG','$source','$member_lid','$table_name')";
            }
            else{
                if ($object['except']['type']=="group"){
                    $name_int2 = normalizeNames(truncate_names($object['except']['name']));
                    $name2 = trim($object['except']['uid']);
                    $addAddressGroups[]="('$aglid','$name2','$name_int2','static','$filename','$source','$vsys','$description')";
                    $fullObject[$name2]["member_lid"]=$aglid;
                    $fullObject[$name2]["table_name"]="address_groups_id";
                    $newParentAG=$aglid;
                    $addAddressMembers[]="('$vsys','".$object['except']['uid']."','$parentAG','$source','$aglid','address_groups_id')";
                    $aglid++;
                    $members=trim($object['except']['members'][0]);
                    if (isset($fullObject[$members])){
                        $member_lid=$fullObject[$members]["member_lid"];
                        $table_name=$fullObject[$members]["table_name"];
                        $addAddressMembers[]="('$vsys','$members','$newParentAG','$source','$member_lid','$table_name')";
                    }
                    else{
                        add_log2('error', 'Reading Exclusion Groups', "Exclusion Group '$name' found. Member ".$object['except']['name']." [$members] was not found.", $source, 'Revise that calculated members are correct.', 'address_groups', $aglid, 'address_groups_id');
                        echo "Exclusion Group $name_int: The [except] Member ".$object['except']['name']." [$members] was not found in the Objects Database\n";
                        //print_r($object);
                    }
                }
            }
            $aglid++;
        }
    }

    //Now that we have loaded all the groups, we could try to fix those missingMembersPerAddressGroup that we could not find
    if (isset($missingMembersPerAddressGroup)){
        //print_r($missingMembersPerAddressGroup);
        //print_r($objectsExclusionGroups);
        foreach ($missingMembersPerAddressGroup as $aglid_local => $data){
            $groupName = $data['name'];
            foreach ($data['members'] as $missingMember) {
                if (isset($fullObject[$missingMember]["member_lid"])) {
                    $member_lid = $fullObject[$missingMember]["member_lid"];
                    $table_name = $fullObject[$missingMember]["table_name"];
                    $addAddressMembers[] = "('$vsys','" . $missingMember . "','$aglid_local','$source','$member_lid','$table_name')";
                }
                else{
                    $found = false;
                    foreach ($objectsGroups as $key => $object) {
                        if($object['uid'] == $missingMember){
                            $name_int = normalizeNames(truncate_names($object['name']));
                            $member_lid = $object['aglid'];
                            $table_name = "address_group_id";
                            $addAddressMembers[] = "('$vsys','" . $missingMember . "','$aglid_local','$source','$member_lid','$table_name')";
                            $found = true;
                            break;
                        }
                    }

                    if(!$found) {
                        add_log2('error', 'Reading Member Groups', 'Group called ' . $groupName . ' is missing this member UID: ' . $missingMember, $source, 'Check in your Checkpoint GUI', 'objects', $member_lid, 'address_groups_id');
                    }
                }
            }
        }
    }




    if (count($objectsServicesGroups)>0){
        $input = array_map("unserialize", array_unique(array_map("serialize", $objectsServicesGroups)));
        $objectsServicesGroups=$input;

        foreach ($objectsServicesGroups as $key => $object) {
            // MT-2374:
            // getting the service_object from the service_group_map where db id is stored
            $service_group_object = $service_group_map[$object['uid']];
            $name_int = $service_group_object['service_group_name'];
            $name = $service_group_object['service_group_uuid'];
            //$name_int = normalizeNames(truncate_names($object['name']));
            //$name = $object['uid'];
            if (!isset($fullObject[$name])){
                //$description = addslashes($object['comments']);
                $description = $service_group_object['service_group_description'];
                $sglid = $service_group_object['service_group_id'];
                $addServicesGroups[]="('$sglid','$name','$name_int','static','$filename','$source','$vsys','$description')";
                $fullObject[$name]["member_lid"]=$sglid;
                $fullObject[$name]["table_name"]="services_groups_id";
                if (isset($object['members'])) {
                    $parentSG=$sglid;
                    foreach ($object['members'] as $member) {
                        // Member could be an array
                        if (is_array($member)) {
                            if ((isset($member['uid'])) AND (isset($fullObject[$member['uid']]))) {
                                $member_lid = $fullObject[$member['uid']]["member_lid"];
                                $table_name = $fullObject[$member['uid']]["table_name"];
                                $addServicesMembers[] = "('$vsys','" . $member['uid'] . "','$parentSG','$source','$member_lid','$table_name')";
                            } else {
                                if ($member['type']=="service-group"){

                                    $name_int1 = normalizeNames(truncate_names($member['name']));
                                    $name1 = $member['uid'];
                                    $description = addslashes($member['comments']);
                                    // $sglid++; // MT-2374 if member is a service-group it is stored on $service_group_map so db_id is not calculated
                                    $service_group_object_member = $service_group_map[$member['uid']];
                                    $sglid = $service_group_object_member['service_group_id'];
                                    $addServicesMembers[] = "('$vsys','" . $member['uid'] . "','$parentSG','$source','$sglid','services_groups_id')";
                                    $addServicesGroups[]="('$sglid','$name1','$name_int1','static','$filename','$source','$vsys','$description')";
                                    $fullObject[$name1]["member_lid"]=$sglid;
                                    $fullObject[$name1]["table_name"]="services_groups_id";
                                    if (isset($member['members'])) {
                                        foreach ($member['members'] as $member2) {
                                            if (is_array($member2)) {
                                                if ((isset($member2['uid'])) AND (isset($fullObject[$member2['uid']]))) {
                                                    $member_lid2 = $fullObject[$member2['uid']]["member_lid"];
                                                    $table_name2 = $fullObject[$member2['uid']]["table_name"];
                                                    $addServicesMembers[] = "('$vsys','" . $member2['uid'] . "','$sglid','$source','$member_lid2','$table_name2')";
                                                }
                                                else {
                                                    print "ERROR:";print_r($member2);
                                                }
                                            }
                                            else{
                                                if (isset($fullObject[$member2])) {
                                                    $member_lid2 = $fullObject[$member2]["member_lid"];
                                                    $table_name2 = $fullObject[$member2]["table_name"];
                                                    $addServicesMembers[] = "('$vsys','" . $member2 . "','$sglid','$source','$member_lid2','$table_name2')";
                                                } else {
                                                    add_log2('error', 'Reading Member Groups', 'Group called ' . $name_int1 . ' is missing this member UID: ' . $member2, $source, 'Check in your Checkpoint GUI', 'objects', $sglid, 'services_groups_id');
                                                }
                                            }
                                        }
                                    }
                                    // $sglid++; // MT-2374 sglid is calculated first time reading the services-groups
                                }
                                else{
                                    print "Error: ".print_r($member);
                                }


                                //add_log2('error', 'Reading Member Groups', 'Group called ' . $name_int . ' is missing this member UID: ' . implode(",",$member), $source, 'Check in your Checkpoint GUI', '', '', '');
                            }
                        }
                        // BUT member could be also a service stored on $fullObject object
                        else if (isset($fullObject[$member])) {
                                $member_lid = $fullObject[$member]["member_lid"];
                                $table_name = $fullObject[$member]["table_name"];
                                $addServicesMembers[] = "('$vsys','" . $member . "','$sglid','$source','$member_lid','$table_name')";
                        }
                        // BUT (added with MT-2374) member could be also a service-group stored on $service_group_map
                        else if (isset($service_group_map[$member])) {
                                $service_group_object_member = $service_group_map[$member];
                                $member_lid = $service_group_object_member['service_group_id'];
                                $table_name = "services_groups_id";
                                $addServicesMembers[] = "('$vsys','" . $member . "','$sglid','$source','$member_lid','$table_name')";
                        }
                        // BUT also member could be also an object not previously read
                        else {
                            add_log2('error', 'Reading Member Groups', 'Group called ' . $name_int . ' is missing this member UID: ' . $member, $source, 'Check in your Checkpoint GUI', 'objects', $sglid, 'services_groups_id');
                        }
                    }
                }
                //$sglid++; // MT-2374 sglid is calculated first time reading the services-groups
            }
        }
    }

    # Add Address and Groups
    if (count($addNetworksv4)>0){
        $unique=array_unique($addNetworksv4);
        $query = "INSERT INTO address (id,type,vtype,ipaddress,cidr,name_ext,name,checkit,v4,description,source,devicegroup,vsys) VALUES ".implode(",",$unique).";";
        //echo "$query\n";
        $projectdb->query($query);
        unset($addNetworksv4);unset($unique);
    }
    if (count($addNetworksv6)>0){
        $unique=array_unique($addNetworksv6);
        $projectdb->query("INSERT INTO address (id,type,vtype,ipaddress,cidr,name_ext,name,checkit,v6,description,source,devicegroup,vsys) VALUES ".implode(",",$unique).";");
        unset($addNetworksv6);unset($unique);
    }
    if (count($addAddressGroups)>0){
        $projectdb->query("INSERT INTO address_groups_id (id,name_ext,name,type,devicegroup,source,vsys,description) VALUES ".implode(",",$addAddressGroups).";");
        unset($addAddressGroups);
        if (count($addAddressMembers)>0){
            $projectdb->query("INSERT INTO address_groups (vsys,member,lid,source,member_lid,table_name) VALUES ".implode(",",$addAddressMembers).";");
            unset($addAddressMembers);
        }
    }
    if (count($addDynamicAddressGroups)>0){
        $projectdb->query("INSERT INTO address_groups_id (id,name,name_ext,type,devicegroup,source,vsys,description,filter) VALUES ".implode(",",$addDynamicAddressGroups).";");
        unset($addDynamicAddressGroups);
    }

    # Add Services and Groups
    if (count($addServices)>0){
        $unique=array_unique($addServices);
        $projectdb->query("INSERT INTO services (id,name_ext,name,protocol,dport,checkit,description,source,icmp,devicegroup,vsys,override,timeout) VALUES ".implode(",",$unique).";");
        unset($services);unset($unique);
    }
    if (count($addServicesGroups)>0){
        $projectdb->query("INSERT INTO services_groups_id (id,name_ext,name,type,devicegroup,source,vsys,description) VALUES ".implode(",",$addServicesGroups).";");
        unset($addServicesGroups);
        if (count($addServicesMembers)>0){
            $projectdb->query("INSERT INTO services_groups (vsys,member,lid,source,member_lid,table_name) VALUES ".implode(",",$addServicesMembers).";");
            unset($addServicesMembers);
        }
    }

    if(count($addZones)>0){
        $projectdb->query("INSERT INTO zones (source,template,vsys,name,type) VALUES ".implode(",",$addZones).";");
        unset($addZones);
    }

    $message['common']=$common;
    $message['objects']=$fullObject;
    $message['schedules']=$schedules;
    $message['accessRole']=$accessRoles;
    $message['accessLayers']=$accessLayers;
    $message['zones']=$zones;
    $message['unsupportedObjects']=$objectsNotSupported;

    return $message;

}

function create_url_category($uri, $source, $vsys){
    global $projectdb;

    $url_category_name = normalizeNames(truncate_names(trim($uri, "."),48));
    $query="INSERT INTO profiles (source,name,name_ext,xml,type,vsys,devicegroup) 
            VALUES ($source,'$url_category_name',NULL,'<entry name=\"$url_category_name\">\n<list>\n<member>*$uri</member>\n</list>\n<type>URL List</type>\n</entry>','custom-url-category','$vsys','');";
    $projectdb->query($query);

}

function isValidJson($strJson) {
    json_decode($strJson);
    return (json_last_error() === JSON_ERROR_NONE);
}

function anything_to_utf8($var,$deep=TRUE){
    if(is_array($var)){
        foreach($var as $key => $value){
            if($deep){
                $var[$key] = anything_to_utf8($value,$deep);
            }elseif(!is_array($value) && !is_object($value) && !mb_detect_encoding($value,'utf-8',true)){
                $var[$key] = utf8_encode($var);
            }
        }
        return $var;
    }elseif(is_object($var)){
        foreach($var as $key => $value){
            if($deep){
                $var->$key = anything_to_utf8($value,$deep);
            }elseif(!is_array($value) && !is_object($value) && !mb_detect_encoding($value,'utf-8',true)){
                $var->$key = utf8_encode($var);
            }
        }
        return $var;
    }else{
        return (!mb_detect_encoding($var,'utf-8',true))?utf8_encode($var):$var;
    }
}

/**
 * Method to identify Members that belong to two groups. A group can be a Member
 * @param MemberObject[] $childMembers.
 * @param MemberObject[] $parentMembers
 * @param unknown $projectdb
 * @param unknown $source
 * @param unknown $vsys
 * @return MemberObject[]
 */
function getCommonMembers($childMembers, $parentMembers, $projectdb, $source, $vsys):array{
    //Easy parts. Either childMembers or parentMembers are ANY, or they both have the same members
    //No parent of children sources were defined, so they are ANY
    $tmp_Members = array();

    if((!isset($parentMembers) || count($parentMembers)==0) &&
        (!isset($childMembers) || count($childMembers)==0)     ){
        $member = new MemberObject('ANY', '', '0.0.0.0', '0');
        $tmp_Members=[$member];
    }
    //The Parent policy has an ANY. We use the Child's Sources's members
    elseif(!isset($parentMembers) || count($parentMembers)==0 || strcmp($parentMembers[0]->name, "ANY")==0){
        $tmp_Members=$childMembers;
    }
    //The Child policy has an ANY. We use the Parent's members.
    elseif(!isset($childMembers) || count($childMembers)==0 || strcmp($childMembers[0]->name, "ANY")==0){  //The subpolicy has ANY as a source. We use the Parents source
        $tmp_Members=$parentMembers;
    }
    //Parent and Child are equal. Therefore, these are the common members.
    elseif($parentMembers == $childMembers){  //TODO: test with array_diff instead, because order of the members could be different
        $tmp_Members = $parentMembers;
    }

    //Both the parent policy and the child have members that are not equal. We need to calculate matchings
    else{
        //To make it simple, we will explode all groups into its Members.
        $exploded_childMembers = explodeGroups2Members($childMembers,$projectdb, $source, $vsys, 0);
        $exploded_parentMembers = explodeGroups2Members($parentMembers,$projectdb, $source, $vsys, 0);

        foreach ($exploded_childMembers as $childNode){
            foreach ($exploded_parentMembers as $parentMember){
                $way = -1;
                $result = netMatchObjects2Ways($childNode, $parentMember, $way);
                if(isset($result)){
//                    echo "               We found that $result->value/$result->cidr satisfies both. We can stop for this childNode\n";
                    $tmp_Members[]=$result;
                    if($way==1){
                        break 1;
                    }
                }
            }
        }

        //In case $childMembers was a group and all its members were selected, substitute the members by the group
        //In case $parentMembers was a group and all its members were selected, substitute the members by the group
        if(isset($tmp_Members)){
            $replace_childGroup = true;
            $replace_parentGroup = true;
            foreach ($exploded_childMembers as $child){
                if(!in_array($child, $tmp_Members)){
                    $replace_childGroup = false;
                    break;
                }
            }
            foreach ($exploded_parentMembers as $parent){
                if(!in_array($parent, $tmp_Members)){
                    $replace_parentGroup = false;
                    break;
                }
            }

            if($replace_childGroup){
                foreach($exploded_childMembers as $child){
                    $key = array_search($child,$tmp_Members);
                    if($key!==false){
                        unset($tmp_Members[$key]);
                    }
                }
                $tmp_Members=$childMembers;
            }
            if($replace_parentGroup){
                foreach($exploded_parentMembers as $parent){
                    $key = array_search($parent, $tmp_Members);
                    if($key!==false){
                        unset($tmp_Members[$key]);
                    }
                }
                $tmp_Members=$parentMembers;
            }
            //All clean now with the common Members
        }
    }

//    if(is_null($tmp_Members)){
//        $my = fopen("/tmp/error2","a");
//        fwrite($my, "Child:");
//        fwrite($my, print_r($childMembers, true));
//        fwrite($my, "Parent:");
//        fwrite($my, print_r($parentMembers, true));
//        fclose($my);
//
//    }
    return $tmp_Members;
}

/**
 * Method to identify Services that belong to two groups. A group can be a Service
 * @param MemberObject[] $childServices.
 * @param MemberObject[] $parentServices
 * @param unknown $projectdb
 * @param unknown $source
 * @param unknown $vsys
 * @return MemberObject[]
 */
function getCommonServices($childServices, $parentServices, $projectdb, $source, $vsys):array{
    //Easy parts. Either childMembers or parentMembers are ANY, or they both have the same members
    //The Parent policy has an ANY. We use the Child's Sources's members
    if((!isset($parentServices) || count($parentServices)==0) &&
        (!isset($childServices) || count($childServices)==0)     ){
        $member = new MemberObject('ANY', '', '', '');
        $tmp_Services=[$member];
    }
    elseif(!isset($parentServices) || count($parentServices)==0 || strcmp($parentServices[0]->name, "ANY")==0){
        $tmp_Services=$childServices;
    }
    //The Child policy has an ANY. We use the Parent's members.
    elseif(!isset($childServices) || count($childServices)==0 || strcmp($childServices[0]->name, "ANY")==0){  //The subpolicy has ANY as a source. We use the Parents source
        $tmp_Services=$parentServices;
    }
    //Parent and Child are equal. Therefore, these are the common members.
    elseif($parentServices == $childServices){
        $tmp_Services = $parentServices;
    }

    //Both the parent policy and the child have members that are not equal. We need to calculate matchings
    else{

        //To make it simple, we will explode all groups into its Members.
        $exploded_childServices = explodeGroups2Services($childServices,$projectdb, $source, $vsys, 0);
        $exploded_parentServices = explodeGroups2Services($parentServices,$projectdb, $source, $vsys, 0);

        foreach ($exploded_childServices as $childService){
            foreach ($exploded_parentServices as $parentService){
                $way=-1;
                $result = serviceMatchObjects2Ways($childService, $parentService, $way);
                if(isset($result)){
                    $tmp_Services[]=$result;
                    if($way==1){
                        break 1;
                    }
                }
            }

        }

        //In case $childMembers was a group and all its members were selected, substitute the members by the group
        //In case $parentMembers was a group and all its members were selected, substitute the members by the group
        if(isset($tmp_Services)){
            $replace_childGroup = true;
            $replace_parentGroup = true;
            foreach ($exploded_childServices as $child){
                if(!in_array($child, $tmp_Services)){
                    $replace_childGroup = false;
                    break;
                }
            }
            foreach ($exploded_parentServices as $parent){
                if(!in_array($parent, $tmp_Services)){
                    $replace_parentGroup = false;
                    break;
                }
            }

            if($replace_childGroup){
                foreach($exploded_childServices as $child){
                    $key = array_search($child,$tmp_Services);
                    if($key!==false){
                        unset($tmp_Services[$key]);
                    }
                }
                $tmp_Services=array_merge($tmp_Services, $childServices);
            }
            if($replace_parentGroup){
                foreach($exploded_parentServices as $parent){
                    $key = array_search($parent, $tmp_Services);
                    if($key!==false){
                        unset($tmp_Services[$key]);
                    }
                }
                $tmp_Services=array_merge($tmp_Services, $parentServices);
            }
            //All clean now with the common Services
        }

    }

    return $tmp_Services;
}

function read_index($project,$index){
    $message=array();
    $message['code']=false;

    if (file_exists($index)){
        $indexJson=json_decode(file_get_contents(USERSPACE_PATH."/projects/" . $project . "/security/index.json"),true);
        $message['gateways']        =$indexJson['policyPackages'][0]['htmlGatewaysFileName'];
        $message['objects']         =$indexJson['policyPackages'][0]['objects']['htmlObjectsFileName'];
        $message['packageName']     =$indexJson['policyPackages'][0]['packageName'];
//        $message['accessLayers']    =$indexJson['policyPackages'][0]['accessLayers'][0]['htmlFileName'];
//        $message['accessLayerName'] =$indexJson['policyPackages'][0]['accessLayers'][0]['name'];
//        $message['domain']          =$indexJson['policyPackages'][0]['accessLayers'][0]['domain'];
        $message['natLayer']        =$indexJson['policyPackages'][0]['natLayer']['htmlFileName'];

        foreach ($indexJson['policyPackages'][0]['accessLayers'] as $accessLayerID){
            $name = $accessLayerID['name'];
            if(strtoupper($name) == strtoupper($message['packageName']." Application")
            || strtoupper($name) == strtoupper($message['packageName']." Application & URL Filtering")){
                continue;
            }
            $message['accessLayers'][] = [
                'domain' =>         $accessLayerID['domain'],
                'domainType' =>     $accessLayerID['domainType'],
                'name' =>           $accessLayerID['name'],
                'htmlFileName' =>   $accessLayerID['htmlFileName']
            ];
        }
        $message['code']=true;
    }

    return $message;
}
