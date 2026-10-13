<?php

# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
#HEADER
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

$natdst_content= array();

class ObjectGroup{
    public $source,$vsys,$name_int,$name_ext,$lid,$zone,$comments,$members;
    public function printMemberObject() {
        var_dump(get_object_vars($this));
    }
    function __construct(){
        $a = func_get_args();
        $i = func_num_args();
        if (method_exists($this,$f='__construct'.$i)) {
            call_user_func_array(array($this,$f),$a);
        }
    }
    public function __construct5($source,$vsys,$lid,$zone,$name_ext){
        $this->lid=$lid;
        $this->name_ext=$name_ext;
        $this->name_int=truncate_names(normalizeNames($name_ext));
        $this->source=$source;
        $this->zone=$zone;
        $this->vsys=$vsys;
        $this->comments="";
        $this->members=array();
    }
    public function addComment($comment){
        $this->comments=$comment;
    }
    public function addMember($member_lid,$table_name){
        $this->members[]=array("member_lid"=>$member_lid,"table_name"=>$table_name);
    }
    public function getAddressGroup(){

        $sql="('$this->lid','$this->name_int','$this->name_ext','$this->source','$this->vsys','$this->zone','$this->comments')";
        return $sql;
    }
    public function getLid(){
        return $this->lid;
    }
    public function getMembers(){
        $add_member=array();
        foreach($this->members as $member){
            $member_lid=$member['member_lid'];
            $table_name=$member['table_name'];
            $add_member[] = "('$this->lid','','$this->source','$this->vsys','$member_lid','$table_name')";
        }

        if (count($add_member)>0){
            return implode(",",$add_member);
        }
        return "";
    }

}

class NATEntry{

    public $source,$vsys,$template,$lid,$natdst_address_lid,$natdst_address_table,$natdst_port;

    public function printMemberObject() {
        var_dump(get_object_vars($this));
    }

    function __construct()
    {
        $a = func_get_args();
        $i = func_num_args();
        if (method_exists($this,$f='__construct'.$i)) {
            call_user_func_array(array($this,$f),$a);
        }
    }

    public function __construct7($source,$vsys,$template,$lid,$natdst_lid,$natdst_table,$natdst_port)
    {
        $this->source = $source;
        $this->vsys = $vsys;
        $this->template = $template;
        $this->lid = $lid;
        $this->natdst_address_lid = $natdst_lid;
        $this->natdst_address_table = $natdst_table;
        $this->natdst_port = $natdst_port;
    }
}

class serviceObject{
    public $name_ext,$source,$vsys,$protocol,$dport,$sport,$name_int,$lid,$timeout,$override_tmout,$members,$membersCount;
    private $logs=array();
    private $isGroup;
    public function printMemberObject() {
        var_dump(get_object_vars($this));
    }
    function __construct(){
        $a = func_get_args();
        $i = func_num_args();
        if (method_exists($this,$f='__construct'.$i)) {
            call_user_func_array(array($this,$f),$a);
        }
    }
    public function __construct4($source,$vsys,$lid,$name_ext){
        $this->lid=$lid;
        $this->name_ext=$name_ext;
        $this->name_int=truncate_names(normalizeNames($name_ext));
        $this->source=$source;
        $this->vsys=$vsys;
        $this->comments="";
        $this->override_tmout="";
        $this->timeout="";
        $this->members=array();

    }
    public function getLid(){
        return $this->lid;
    }
    public function setTimeout($timeout){
        $this->timeout=$timeout;
        $this->override_tmout="yes";
    }
    public function addMembers($protocol,$sport,$dport){
        $this->protocol=$protocol;
        $this->members[]=array("protocol"=>$protocol,"sport"=>$sport,"dport"=>$dport);
    }
    public function getServices(int $startID){
//        $dport=$sport=$protocol='';
        $sql=array();
        $service = array();
//        $service['name']= $this->name_int;
//        $service['name_ext']= $this->name_ext;


        foreach ($this->members as $memberItem){
//            if($memberItem['sport'] == '') $memberItem['sport'] = '0-65535';
            $service[$memberItem['protocol']][$memberItem['sport']][] = $memberItem['dport'];
        }

        foreach ($service as $serviceProtocol => $sourceAndDests){
            $destinationPort = '';
            foreach ($sourceAndDests as $sourcePort => $destinations){
                $destinationPort = implode(',', $destinations);
                $sql[]="('$startID','$this->name_int','','$this->name_ext','0','$this->source','0','$destinationPort','$sourcePort','$serviceProtocol','$this->vsys','$this->timeout','$this->override_tmout')";
                $startID++;
            }
        }


//        if (count($this->members)>1){
//            $protocol=$this->members[0]['protocol'];
//            $sport=$this->members[0]['sport'];
//            $dportArray=array();
//            foreach($this->members as $memberItem){
//                $dportArray[]=$memberItem['dport'];
//            }
//            $dportU=array_unique($dportArray);
//            $dport=implode(",",$dportU);
//
//        }
//        else{
//            $protocol=$this->members[0]['protocol'];
//            $sport=$this->members[0]['sport'];
//            $dport=$this->members[0]['dport'];
//        }
//        $sql="('$this->lid','$this->name_int','','$this->name_ext','0','$this->source','0','$dport','$sport','$protocol','$this->vsys','$this->timeout','$this->override_tmout')";
        return $sql;
    }

    public function getLogs(){
        return $this->logs;
    }

    public function addLog(string $type, string $task, string $message, string $action){
        $this->logs[] = [
            'type'      => $type,
            'task'      => $task,
            'message'   => $message,
            'action'    => $action
        ];
    }

    public function getServiceGroup(){

    }

}

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
                clean_config($config_path, $project, $config_filename);
                import_config($config_path, $project, $config_filename,$jobid); //This should update the $source
                $sourcesAdded[] = $source;
                update_progress($project, '0.70', 'File:' . $filename . ' Phase 7 Referencing Groups',$jobid);
                //GroupMember2IdAddress($config_filename);
                //GroupMember2IdServices($config_filename);
            } else {
                update_progress($project, '0.00', 'This filename '.$filename.' its already uploaded. Skipping...',$jobid);
                //unlink($path.$config_filename);
            }
        }
    }

    // Auto split the address groups based on defined PARSER_max_number_address_per_group
    // for upgraded installations that does not have the variable in the /home/userSpace/userDefinition.php defined
    if (!defined('PARSER_max_number_address_per_group')) {
        define('PARSER_max_number_address_per_group', -1);
    }
    if(PARSER_max_number_address_per_group!=-1) {
        update_progress($project, '0.85', 'File:' . $filename . ' Split the address group members using as a limit defined value of '. PARSER_max_number_address_per_group . ' members', $jobid);
        splitMembersOnGroups();
    }

    #Check used
    update_progress($project, '0.90', 'File:' . $filename . ' Calculating Used Objects',$jobid);
    check_used_objects_new($sourcesAdded);
    # Remove zones if they dont have a name in security and nat and appoverride rules (happens when is not a default gateway
    $projectdb->query("DELETE FROM security_rules_from WHERE name='';");
    $projectdb->query("DELETE FROM security_rules_to WHERE name='';");
    $projectdb->query("DELETE FROM nat_rules_from WHERE name='';");
    $projectdb->query("DELETE FROM appoverride_rules_from WHERE name='';");
    $projectdb->query("DELETE FROM appoverride_rules_to WHERE name='';");
    //sleep(4);
    update_progress($project, '1.00', 'Done.',$jobid);
    unlink($path.$config_filename.$filename);
}

function clean_config($config_path, $project, $config_filename) {
    $data = file_get_contents($config_path);
    $data = str_replace("'", "_", $data);
    file_put_contents($config_path, $data);
}

function import_config($config_path, $project, $config_filename,$jobid) {
    global $projectdb;
    global $source;
    $filename = $config_filename;

    #CLEAN CONFIG FROM EMPTY LINES AND CTRL+M
    file_put_contents($config_path, implode(PHP_EOL, file($config_path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES)));

    #LOAD THE FILE
    $screenos_config_file = file($config_path);

    $invdom = false;
    foreach ($screenos_config_file as $line => $names_line) {
        if (preg_match("/^set vsys /i", $names_line)) {
            $invdom = true;
            $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
            $vsys = $data[2];
            $getDup = $projectdb->query("SELECT id FROM device_mapping WHERE filename='$filename' AND vsys='$vsys';");
            if ($getDup->num_rows == 0) {
                $projectdb->query("INSERT INTO device_mapping (device,version,ispanorama,active,project,filename,vsys,baseconfig,vendor) VALUES ('$filename','',0,1,'$project','$filename','$vsys','0','Screenos')");
                $config_filename = $projectdb->insert_id;
                $source = $config_filename;
            }
        }
    }
    #Check if Vdoms were created or its a simple config, then create a default vsys1
    $isVdom = $projectdb->query("SELECT id,vsys FROM device_mapping WHERE filename='$filename' and vsys='root'");
    if ($isVdom->num_rows == 0) {
        $projectdb->query("INSERT INTO device_mapping (device,version,ispanorama,active,project,filename,vsys,baseconfig,vendor) VALUES ('$filename','',0,1,'$project','$filename','root','0','Screenos')");
        $config_filename = $projectdb->insert_id;
        $source = $config_filename;
    }

    #Get Source (First row for this filename)
    $getSource = $projectdb->query("SELECT id FROM device_mapping WHERE filename='$filename' GROUP by filename;");
    $getSourceData = $getSource->fetch_assoc();
    $source = $getSourceData['id'];

    # Bucle from Devices_mappings to get Objects and Rules
    $getDM = $projectdb->query("SELECT id,vsys FROM device_mapping WHERE filename='$filename';");
    if ($getDM->num_rows == 1) {
        if ($invdom == true) {
            $ismultiornot = "multivsys";
            $myData = $getDM->fetch_assoc();
            $vsys = $myData['vsys'];
            add_netscreen_services($source, $vsys, "singlevsys");
        } else {
            $myData = $getDM->fetch_assoc();
            $vsys = $myData['vsys'];
            $ismultiornot = "singlevsys";
            add_netscreen_services($source, $vsys, $ismultiornot);
        }
    }
    elseif ($getDM->num_rows > 1) {
        $ismultiornot = "multivsys";
        #Add Shared context
        $projectdb->query("INSERT INTO device_mapping (device,version,ispanorama,active,project,filename,vsys,baseconfig,vendor) VALUES ('$filename','',0,1,'$project','$filename','shared','0','Screenos')");
        //$projectdb->query("INSERT INTO device_mapping (device,version,ispanorama,active,project,filename,vsys,baseconfig,vendor) VALUES ('$filename','',0,1,'$project','$filename','root','0','Screenos')");
        add_netscreen_services($source, $vsys, $ismultiornot);
    }

    #Add Default Services
    add_default_services($source);

    #Config Template
    $template_name = "default_template" . $source;
    $projectdb->query("INSERT INTO templates_mapping (project,name,filename,source) VALUES ('$project','$template_name','$filename','$source');");
    $template = $projectdb->insert_id;

    $vsys="root";
    update_progress($project, '0.10', 'File:' . $filename . ' Phase 1 Reading Interfaces',$jobid);
    get_interfaces($screenos_config_file, $source, $vsys, $ismultiornot, $template);
    update_progress($project, '0.20', 'File:' . $filename . ' Phase 2 Reading Address and Groups',$jobid);
    get_address_SCREENOS($screenos_config_file, $source, $vsys, $ismultiornot);
    get_address_groups($screenos_config_file, $source, $vsys, $ismultiornot);
    update_progress($project, '0.30', 'File:' . $filename . ' Phase 3 Reading Services and Groups',$jobid);
    get_services($screenos_config_file, $source, $vsys, $ismultiornot);
    fix_services_multiple_protocol($vsys, $source);

    get_services_groups($screenos_config_file, $source, $vsys, $ismultiornot);
    #echo "Fix Services with Multiple Protocol".PHP_EOL;
    update_progress($project, '0.40', 'File:' . $filename . ' Phase 4 Reading Routes',$jobid);
    #echo "Read Routes".PHP_EOL;
    get_routes($screenos_config_file, $source, $vsys, $ismultiornot, $template);
    update_progress($project, '0.45', 'File:' . $filename . ' Phase 4.2 Mapping Virtual Router',$jobid);
    #echo "MAP VR".PHP_EOL;
    map_vr($screenos_config_file,$source,$vsys,$ismultiornot,$template);
    update_progress($project, '0.50', 'File:' . $filename . ' Phase 5 Reading Security Rules',$jobid);
    #echo "Read Security Policies".PHP_EOL;
    get_Security_Rules($screenos_config_file, $source, $vsys, $ismultiornot);
    update_progress($project, '0.60', 'File:' . $filename . ' Phase 6 Reading Nat Rules',$jobid);

    $getDM = $projectdb->query("SELECT id,vsys FROM device_mapping WHERE filename='$filename' LIMIT 1;");
    while ($data = $getDM->fetch_assoc()) {
        $vsys = $data['vsys'];
        #echo "get Nat MIP $vsys".PHP_EOL;
        get_nat_MIP($screenos_config_file, $source, $vsys, $ismultiornot, $template);
        #echo "get NAT VIP $vsys".PHP_EOL;
        get_nat_VIP($screenos_config_file, $source, $vsys, $ismultiornot, $template);
        #echo "get NAT DIP $vsys".PHP_EOL;
        get_nat_DIP($source, $vsys, $template);
        #echo "generate NAT DST $vsys".PHP_EOL;
        generate_natdst($source, $vsys);
        #echo "Fix Destination NAT $vsys".PHP_EOL;
        fix_destination_nat($source, $vsys);
        #echo "Split DNAT Rules $vsys".PHP_EOL;
        split_dnat_rules($source, $vsys, $filename);
        #echo "Check DNAT Cidr $vsys".PHP_EOL;
        check_dnat_cidr($source, $vsys, $filename);
    }
    #echo "Assign Filename to DeviceGroup".PHP_EOL;
    #Add the source file to the Devicegroup Field.
    $projectdb->query("UPDATE services SET devicegroup='$filename' WHERE source='$source';");
    $projectdb->query("UPDATE services_groups_id SET devicegroup='$filename' WHERE source='$source';");
    $projectdb->query("UPDATE address SET devicegroup='$filename' WHERE source='$source';");
    $projectdb->query("UPDATE address_groups_id SET devicegroup='$filename' WHERE source='$source';");


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


// Call function to generate initial consumptions
    deviceUsage("initial", "get", $project, "", "", $vsys, $source, $template_name);
}
/** This method checks that the existing DNAT rules are correct for being pushed to the Firewall. If not, they are marked for review.
 *
 * @global type $projectdb
 * @param type $source
 * @param type $vsys
 * @param type $filename
 * @param type $PANOSversion
 */
function check_dnat_cidr($source, $vsys, $filename, $PANOSversion=7){
    global $projectdb;

    $query = "SELECT nat.* FROM nat_rules nat "
        . "WHERE nat.is_dat='1' AND nat.source ='$source' AND nat.vsys='$vsys' ";
    $getDnatCandidates = $projectdb->query($query);

    while($natRule = $getDnatCandidates->fetch_assoc()){
        $dNATrule_id = $natRule['id'];
        $dNATrule_tp_dat_address_lid = $natRule['tp_dat_address_lid'];
        $dNATrule_tp_dat_address_table = $natRule['tp_dat_address_table'];

        //Check Range of Translated Destinations
        if ($dNATrule_tp_dat_address_table === 'address'){
            $query = "SELECT cidr FROM address WHERE id = '$dNATrule_tp_dat_address_lid';";
            $getTranslatedDst_Mem = $projectdb->query($query);
            if($getTranslatedDst_Mem->num_rows===1){
                $translatedDst = $getTranslatedDst_Mem->fetch_assoc();
                $translatedDst_cidr = $translatedDst['cidr'];
            }
            else{
                $translatedDst_cidr = -1;
                //$my = fopen("screenosDnat.txt","a");  fwrite($my, "    Processing $dNATrule_id Error TD: $translatedDst_cidr\n"); fclose($my);
                add_log2('info', 'Reading Nat Policies', 'DNAT RuleID [' . $dNATrule_id . '] does not have a Translated Destination.', $source, 'Please, Review the DNAT rule.', 'rules', $dNATrule_id, 'nat_rules');
            }
        }
        else{
            $translatedDst_cidr = -1;
            //$my = fopen("screenosDnat.txt","a");  fwrite($my, "    Processing $dNATrule_id Error TD: $translatedDst_cidr\n"); fclose($my);
            add_log2('info', 'Reading Nat Policies', 'DNAT RuleID [' . $dNATrule_id . '] has a group as a Translated Destination. It may not fit with the Destinations', $source, 'Please, Review the DNAT rule.', 'rules', $dNATrule_id, 'nat_rules');
        }


        if($translatedDst_cidr > 0){
            $query = "SELECT * FROM nat_rules_dst WHERE rule_lid='$dNATrule_id';";
            $getDstMem = $projectdb->query($query);
            if($getDstMem->num_rows === 1){
                $dstMem = $getDstMem->fetch_assoc();
                $dstMember_lid   = $dstMem['member_lid'];
                $dstMember_table = $dstMem['table_name'];
                if ($dstMember_table === 'address'){
                    $query = "SELECT cidr FROM address WHERE id = '$dstMember_lid';";
                    $getDstMemCidr = $projectdb->query($query);
                    if($getDstMemCidr->num_rows === 1){
                        $DstMemCidr = $getDstMemCidr->fetch_assoc();
                        $dst_cidr = $DstMemCidr['cidr'];
                        if( $dst_cidr != $translatedDst_cidr){
                            //$my = fopen("screenosDnat.txt","a");  fwrite($my, "    Processing $dNATrule_id DT: $translatedDst_cidr, Error DST: $dst_cidr\n"); fclose($my);
                            add_log2('info', 'Reading Nat Policies', 'DNAT RuleID [' . $dNATrule_id . '] has a destination with different CIDR than the Translated Destination.', $source, 'Please, Review the DNAT rule.', 'rules', $dNATrule_id, 'nat_rules');
                        }
                    }
                    else{
                        //$my = fopen("screenosDnat.txt","a");  fwrite($my, "    Processing $dNATrule_id DT: $translatedDst_cidr, Error DST: More than 1\n"); fclose($my);
                        add_log2('info', 'Reading Nat Policies', 'DNAT RuleID [' . $dNATrule_id . '] does not have a valid Destination. It may not fit with the Translated Destination', $source, 'Please, Review the DNAT rule.', 'rules', $dNATrule_id, 'nat_rules');
                    }
                }
                else{
                    //$my = fopen("screenosDnat.txt","a");  fwrite($my, "    Processing $dNATrule_id DT: $translatedDst_cidr, Error DST: not an address. A group\n"); fclose($my);
                    add_log2('info', 'Reading Nat Policies', 'DNAT RuleID [' . $dNATrule_id . '] has a group as a Destination. It may not fit with the Translated Destination', $source, 'Please, Review the DNAT rule.', 'rules', $dNATrule_id, 'nat_rules');
                }
            }
            else{
                //$my = fopen("screenosDnat.txt","a");  fwrite($my, "    Processing $dNATrule_id DT: $translatedDst_cidr, DST: not a defined dest\n"); fclose($my);
                add_log2('info', 'Reading Nat Policies', 'DNAT RuleID [' . $dNATrule_id . '] does not have one single Destination. It may not fit with the Translated Destination', $source, 'Please, Review the DNAT rule.', 'rules', $dNATrule_id, 'nat_rules');
            }
        }
    }
}
/** This methodsplits all the DNAT rules to have a single source in their rules. PANOS (until 7.1) does not support multiple sources in DNAT. They need to be atomic
 *
 * @global type $projectdb
 * @param int $source
 * @param String $vsys
 * @param String $filename
 * @param int $PANOSversion Version of the PANOS device in which this configuration will be uploaded to
 */
function split_dnat_rules($source, $vsys, $filename, $PANOSversion=7){
    global $projectdb;

    if($PANOSversion <= '7'){
        $limit = "HAVING count(*) > 1";
    }
    else{
        $limit = "";
    }

    //Get all the DNAT rules that have more than on source
    $query = "SELECT nat.*, count(*) as amount FROM nat_rules nat, nat_rules_dst natdst "
        . "WHERE natdst.rule_lid = nat.id AND "
        .       "nat.is_dat='1' AND nat.source ='$source' AND nat.vsys='$vsys' "
        . "GROUP BY nat.id "
        . "$limit";
    $getDnatCandidates = $projectdb->query($query);


    while($natRule = $getDnatCandidates->fetch_assoc()){
        $dNATrule_id = $natRule['id'];
        $dNATrule_amount = $natRule['amount'];

        //Check how many rules do we need to split to
        $message = "";
        $initialPosition = "";
        $finalPosition = "";
        $relations_to_delete = array();
        for($i=0; $i<$dNATrule_amount; $i++){
            $newLid = clone_nat_rule($initialPosition, $finalPosition, $vsys, $source, $dNATrule_id, $message, $filename);

            $query = "SELECT * FROM nat_rules_dst WHERE rule_lid = $newLid;";
            $getDstMem = $projectdb->query($query);
            $j =$dNATrule_amount-1;
            while($mem = $getDstMem->fetch_assoc() ){
                $dst_rel_Id = $mem['id'];
                if($i != $j){
                    $relations_to_delete[] = $dst_rel_Id;
                }
                $j--;
            }
        }

        $to_delete = implode(",", $relations_to_delete);
        $query = "DELETE FROM nat_rules_dst WHERE id in ($to_delete);";
        $projectdb->query($query);

        $query = "UPDATE nat_rules SET disabled='1' WHERE id='$dNATrule_id'";
        $projectdb->query($query);
        add_log2('info', 'Reading Security Policies', 'DNAT RuleID [' . $dNATrule_id . '] has multiple Destinations. It has been split into multiple Individual DNAT rules, below this rule. This rule is now disabled, but left for Reviewing purposes. ', $source, 'Review the new split rules.', 'rules', $dNATrule_id, 'nat_rules');

    }
}

function fix_services_multiple_protocol($vsys, $source) {
    global $projectdb;
    $getDup = $projectdb->query("SELECT name_ext,name,count(id) as duplicates FROM services WHERE source='$source' AND dport!='' AND vsys='$vsys' GROUP BY name HAVING duplicates > 1;");
    while ($names = $getDup->fetch_assoc()) {
        $name_int = $names['name'];
        $originalname = $names['name_ext'];

        $getSGDup = $projectdb->query("SELECT id FROM services_groups_id WHERE source='$source' AND BINARY name='$name_int';");
        if ($getSGDup->num_rows == 0) {
            $projectdb->query("INSERT INTO services_groups_id (name,name_ext,source,vsys) values ('$name_int','$originalname','$source','$vsys');");
            $grplid = $projectdb->insert_id;
        } else {
            #EXISTS Raise error?
        }
        //add_log('1', 'Phase 3: Reading Services Objects and Groups', 'Creating ServiceGroup [' . $name_int . ']. Original SRV contains more than one Protocol', $source, 'No Action Requierd.');
        add_log2('info','Reading Services Objects and Groups', 'Creating ServiceGroup [' . $name_int . ']. Original SRV contains more than one Protocol',$source,'No Action Requierd.','objects',$grplid,'services_groups_id');

        $getElement = $projectdb->query("SELECT id,name_ext,name,protocol FROM services WHERE source='$source' AND BINARY name='$name_int';");
        while ($data2 = $getElement->fetch_assoc()) {
            $id = $data2['id'];
            $protocol = $data2['protocol'];
            $mynewname = $name_int . "-" . $protocol;
            $mynewname_int = truncate_names(normalizeNames($mynewname));
            $projectdb->query("UPDATE services SET name_ext='$mynewname', name='$mynewname_int' WHERE id='$id';");
            //$projectdb->query("UPDATE services SET name='$mynewname_int' WHERE id='$id';");
            $projectdb->query("INSERT INTO services_groups (lid,member_lid,table_name,vsys,source) VALUES ('$grplid','$id','services','$vsys','$source')");
        }
    }
}

function get_Security_Rules($screenos_config_file, $source, $vsys, $ismultiornot) {
    global $projectdb;
    global $natdst_content;

    $oldID = "";
    $extended_args = FALSE;
    $update_rules_dst_negated = array();
    $update_rules_src_negated = array();
    $add_dst = array();
    $add_src = array();
    $add_srv = array();
    $add_log_start = array();
    $add_log_end = array();
    $add_tag = array();
    $add_from = array();
    $add_to = array();
    $add_rule = array();
    $add_action_allow = array();
    $add_action_deny = array();
    $add_disabled = array();
    $update_rule = array();
    $lid = "";
    $nat_lid = "";
    $thecolor = 1;
    $lock = array();
    $addDip = array();
    $natdst = array();
    $template="";
    #Get Positions and IDs for Security and Nat rules
    $getPosition = $projectdb->query("SELECT max(position) as t FROM security_rules WHERE vsys='$vsys' AND source='$source';");
    if ($getPosition->num_rows == 0) {
        $position = 0;
    }
    else {
        $ddata = $getPosition->fetch_assoc();
        $position = $ddata['t'];
    }
    if ($lid == "") {
        $getlastlid = $projectdb->query("SELECT max(id) as max FROM security_rules;");
        $getLID1 = $getlastlid->fetch_assoc();
        $lid = intval($getLID1['max']);
    }
    $getPosition = $projectdb->query("SELECT max(position) as t FROM nat_rules WHERE vsys='$vsys' AND source='$source';");
    if ($getPosition->num_rows == 0) {
        $nat_position = 0;
    }
    else {
        $ddata = $getPosition->fetch_assoc();
        $nat_position = $ddata['t'];
    }
    if ($nat_lid == "") {
        $getlastlid = $projectdb->query("SELECT max(id) as max FROM nat_rules;");
        $getLID1 = $getlastlid->fetch_assoc();
        $nat_lid = intval($getLID1['max']);
    }

    $vsys="root";

    $badchar=array(
        // control characters
        chr(0), chr(1), chr(2), chr(3), chr(4), chr(5), chr(6), chr(7), chr(8), chr(9), chr(10),
        chr(11), chr(12), chr(13), chr(14), chr(15), chr(16), chr(17), chr(18), chr(19), chr(20),
        chr(21), chr(22), chr(23), chr(24), chr(25), chr(26), chr(27), chr(28), chr(29), chr(30),
        chr(31),
        // non-printing characters
        chr(127),chr(194),chr(160),
    );

    foreach ($screenos_config_file as $line => $names_line) {
        $names_line = trim($names_line);
        if (preg_match("/^set vsys /i", $names_line)) {
            $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
            $vsys = $data[2];
        }

        if ($extended_args == TRUE) {
            if (preg_match("/^set dst-address negate/i", $names_line)) {
                $update_rules_dst_negated[] = "'$lid'";
            }
            elseif (preg_match("/^set dst-address /i", $names_line)) {
                $dataExt = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                $destination = $dataExt[2];

                if ((strtolower($destination) == "any") OR (strtolower($destination) == "any-ipv4") OR (strtolower($destination) == "any-ipv6")){}
                else {
                    if (preg_match("/^MIP\(/", $destination)) {
                        preg_match('#\((.*?)\)#', $destination, $match);
                        $myip = $match[1];
                        $destination = truncate_names(normalizeNames($destination));
                        $lock[] = $lid;
                    } elseif (preg_match("/^VIP\(/", $destination)) {
                        preg_match('#\((.*?)\)#', $destination, $match);
                        $myip = $match[1];
                        if (ip_version($myip) == "noip") {
                            #Then its interface name
                            $getInterface = $projectdb->query("SELECT unitipaddress FROM interfaces WHERE unitname='$myip' AND source='$source';");
                            if ($getInterface->num_rows == 1) {
                                $getInterfaceData = $getInterface->fetch_assoc();
                                $getInterfaceData1 = explode("/", $getInterfaceData['unitipaddress']);
                                $myip = $getInterfaceData1[0];
                            }
                        }
                        $destination = truncate_names(normalizeNames($destination));
                        $lock[] = $lid;
                    } else {
                        $myip = "1.1.1.1";
                    }
                    $getDestination = $projectdb->query("SELECT id FROM address WHERE source='$source' AND BINARY name_ext='$destination' AND vsys='$vsys' AND zone='$zoneTo';");
                    if ($getDestination->num_rows == 1) {
                        $mydest = $getDestination->fetch_assoc();
                        $member_lid = $mydest['id'];
                        $table_name = "address";
                        $add_dst[] = "('$lid','$source','$member_lid','$table_name','$vsys')";
                    }
                    else {
                        $getDestination = $projectdb->query("SELECT id FROM address_groups_id WHERE source='$source' AND BINARY name_ext='$destination' AND vsys='$vsys' AND zone='$zoneTo';");
                        if ($getDestination->num_rows == 1) {
                            $mydest = $getDestination->fetch_assoc();
                            $member_lid = $mydest['id'];
                            $table_name = "address_groups_id";
                            $add_dst[] = "('$lid','$source','$member_lid','$table_name','$vsys')";
                        } else {
                            if ($myip == "1.1.1.1") {
                                add_log2('error', 'Reading Security Policies', 'Security RuleID [' . $lid . '] is using an Address [' . $destination . '] that is not defined in my Database. Fix it before to finish', $source, 'Adding to the DB [ip:' . $myip . ']. Add IP Address', 'rules', $lid, 'security_rules');
                            }
                            $name_int = truncate_names(normalizeNames($destination));
                            $projectdb->query("INSERT INTO address (name_ext,name,source,checkit,ipaddress,type,vsys,zone,cidr) values('$destination','$name_int','$source','1','$myip','ip-netmask','$vsys','$zoneTo','32');");
                            $member_lid = $projectdb->insert_id;
                            $table_name = "address";
                            $add_dst[] = "('$lid','$source','$member_lid','$table_name','$vsys')";
                        }
                    }
                }
            }
            elseif (preg_match("/^set src-address negate/i", $names_line)) {
                $update_rules_src_negated[] = "'$lid'";
            }
            elseif (preg_match("/^set src-address /i", $names_line)) {
                $dataExt = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                $src = $dataExt[2];

                if ((strtolower($src) == "any") OR (strtolower($src) == "any-ipv4") OR (strtolower($src) == "any-ipv6")) {}
                else {
                    if (preg_match("/^MIP\(/", $src)) {
                        preg_match('#\((.*?)\)#', $src, $match);
                        $myip = $match[1];
                        $src = truncate_names(normalizeNames($src));
                        $lock[] = $lid;
                    } else {
                        $myip = "1.1.1.1";
                    }
                    $getSource = $projectdb->query("SELECT id FROM address WHERE source='$source' AND BINARY name_ext='$src' AND vsys='$vsys' AND zone='$zoneFrom';");
                    if ($getSource->num_rows == 1) {
                        $mydest = $getSource->fetch_assoc();
                        $member_lid = $mydest['id'];
                        $table_name = "address";
                        $add_src[] = "('$lid','$source','$member_lid','$table_name','$vsys')";
                    }
                    else {
                        $getSource = $projectdb->query("SELECT id FROM address_groups_id WHERE source='$source' AND BINARY name_ext='$src' AND vsys='$vsys' AND zone='$zoneFrom';");
                        if ($getSource->num_rows == 1) {
                            $mydest = $getSource->fetch_assoc();
                            $member_lid = $mydest['id'];
                            $table_name = "address_groups_id";
                            $add_src[] = "('$lid','$source','$member_lid','$table_name','$vsys')";
                        } else {
                            add_log2('error', 'Reading Security Policies', 'Security RuleID [' . $lid . '] is using an Address [' . $src . '] that is not defined in my Database. Fix it before to finish', $source, 'Adding to the DB [ip:' . $myip . ']. Add IP Address', 'rules', $lid, 'security_rules');
                            $name_int = truncate_names(normalizeNames($src));
                            $projectdb->query("INSERT INTO address (name_ext,name,source,checkit,ipaddress,type,vsys,zone) values('$src','$name_int','$source','1','$myip','ip-netmask','$vsys','$zoneFrom');");
                            $member_lid = $projectdb->insert_id;
                            $table_name = "address";
                            $add_src[] = "('$lid','$source','$member_lid','$table_name','$vsys')";
                        }
                    }
                }
            }
            elseif (preg_match("/^set service /i", $names_line)) {
                $dataExt = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                $service = $dataExt[2];

                if ($service == "ANY") {}
                else{
                    $getService = $projectdb->query("SELECT id FROM services WHERE source='$source' AND BINARY name_ext='$service' AND vsys='$vsys';");
                    if ($getService->num_rows == 1) {
                        $mydest = $getService->fetch_assoc();
                        $member_lid = $mydest['id'];
                        $table_name = "services";
                        $add_srv[] = "('$lid','$source','$member_lid','$table_name','$vsys')";
                    }
                    else {
                        $getService = $projectdb->query("SELECT id FROM services_groups_id WHERE source='$source' AND BINARY name_ext='$service' AND vsys='$vsys';");
                        if ($getService->num_rows == 1) {
                            $mydest = $getService->fetch_assoc();
                            $member_lid = $mydest['id'];
                            $table_name = "services_groups_id";
                            $add_srv[] = "('$lid','$source','$member_lid','$table_name','$vsys')";
                        } else {
                            //$getShared = $projectdb->query("SELECT id FROM shared_services WHERE source='$source' AND BINARY name='$service';");
                            $getShared = $projectdb->query("SELECT id FROM services WHERE source='$source' AND BINARY name_ext='$service' AND vsys = 'shared';");
                            if ($getShared->num_rows == 1) {
                                $mydest = $getShared->fetch_assoc();
                                $member_lid = $mydest['id'];
                                //$table_name = "shared_services";
                                $table_name = "services";
                                $add_srv[] = "('$lid','$source','$member_lid','$table_name','$vsys')";
                            } else {
                                add_log2('error', 'Reading Security Policies', 'Security RuleID [' . $lid . '] is using a Service [' . $service . '] that is not defined in my Database. Fix it before to finish', $source, 'Adding to the DB [dport:65000].', 'rules', $lid, 'security_rules');
                                $name_int = truncate_names(normalizeNames($service));
                                $projectdb->query("INSERT INTO services (name_ext,name,source,checkit,protocol,dport,vsys) values('$service','$name_int','$source','1','tcp','65000','$vsys');");
                                $member_lid = $projectdb->insert_id;
                                $table_name = "services";
                                add_log2('error', 'Unknown Service Created', 'While reading RuleID [' . $lid . ']', $source, 'Please Fix the Protocol and Port or Replace it by an App-ID', 'objects', $member_lid, 'services');
                                $add_srv[] = "('$lid','$source','$member_lid','$table_name','$vsys')";
                            }
                        }
                    }
                }

            }
            elseif (preg_match("/^set log session/i", $names_line)) {
                $dataExt = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                if ($dataExt[2] == "session-init") {
                    $add_log_start[] = "'$lid'";
                } elseif ($dataExt[2] == "session-close") {
                    $add_log_end[] = "'$lid'";
                }
            }
            elseif (preg_match("/^exit/i", $names_line)) {
                $extended_args = FALSE;
            }
            else {
                #print $names_line;
            }
        }

        if (preg_match("/^set policy id /i", $names_line)) {
//            echo $names_line.PHP_EOL;
//            for ($i=0; $i< strlen($names_line); $i++){
//                print("   $i->".$names_line[$i]."-".ord($names_line[$i]."\n"));
//            }
//            die;
            //build an array we can re-use across several operations

            //replace the unwanted chars
            $names_line = str_replace($badchar, '', $names_line);
            $names_line = preg_replace('/[\x00-\x1F\x7F]/u', '', $names_line);
            $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s]*|[\s]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
            $data2 = array_map('trim', $data);
            $data2 = array_filter($data2, create_function('$value', 'return $value !== "";'));
            $policyID = $data[3];
            //print_r($data);
            if ($policyID != $oldID) {
                $lid++;
                $position++;
                $add_rule[] = "('$lid','$vsys','$lid','$source','Rule ID $policyID','$data[5]')";
            }
            else {
                if (!isset($data[4])) {
                    $extended_args = TRUE;
                }
            }
            $oldID = $policyID;
            if (isset($data[4]) and ( ($data[4] == "name") OR ( $data[4] == "from") )) {

                $next = 4;
                if ($data[$next] == "name") {
                    #Add Tag
                    $color = "color" . $thecolor;
                    $tagname0 = $data[$next + 1];
                    $msplit = explode(",", $tagname0);
                    foreach ($msplit as $mkey => $mvalue) {
                        $tagname = truncate_tags(normalizeNames($mvalue));
                        $getDup = $projectdb->query("SELECT id FROM tag WHERE source='$source' AND name='$tagname' AND vsys='$vsys';");
                        if ($getDup->num_rows == 0) {
                            $projectdb->query("INSERT INTO tag (name,source,vsys,color) VALUES ('$tagname','$source','$vsys','$color');");
                            if ($thecolor == 16) {
                                $thecolor = 1;
                            } else {
                                $thecolor++;
                            }
                            $tag_id = $projectdb->insert_id;
                        } else {
                            $getDupData = $getDup->fetch_assoc();
                            $tag_id = $getDupData['id'];
                        }
                        $policyName = $tagname;
                        $add_tag[] = "('$source','$vsys','$lid','tag','$tag_id')";
                    }

                    $next = 6;
                }

                if ($data[$next] == "from") {
                    $zoneFrom = $data[$next + 1];
                    if (strtolower($zoneFrom) != "global") {
                        $add_from[] = "('$source','$lid','$zoneFrom','$vsys')";
                    }
                }

                if ($data[$next + 2] == "to") {
                    $zoneTo = $data[$next + 3];
                    if (strtolower($zoneTo) != "global") {
                        $add_to[] = "('$source','$lid','$zoneTo','$vsys')";
                    }
                }

                $src = $data[$next + 4];
                if (($src == "Any") OR ($src=="Any-IPv4") OR ($src=="Any-IPv6")){}
                else{
                    if (preg_match("/^MIP\(/", $src)) {
                        preg_match('#\((.*?)\)#', $src, $match);
                        $myip = $match[1];
                        $src = truncate_names(normalizeNames($src));
                        $lock[] = $lid;
                    } else {
                        $myip = "1.1.1.1";
                    }
                    $getSource = $projectdb->query("SELECT id FROM address WHERE source='$source' AND BINARY name_ext='$src' AND vsys='$vsys' AND zone='$zoneFrom';");
                    if ($getSource->num_rows == 1) {
                        $mydest = $getSource->fetch_assoc();
                        $member_lid = $mydest['id'];
                        $table_name = "address";
                        $add_src[] = "('$lid','$source','$member_lid','$table_name','$vsys')";
                    }
                    else {
                        $getSource = $projectdb->query("SELECT id FROM address_groups_id WHERE source='$source' AND BINARY name_ext='$src' AND vsys='$vsys' AND zone='$zoneFrom';");
                        if ($getSource->num_rows == 1) {
                            $mydest = $getSource->fetch_assoc();
                            $member_lid = $mydest['id'];
                            $table_name = "address_groups_id";
                            $add_src[] = "('$lid','$source','$member_lid','$table_name','$vsys')";
                        } else {
                            if ($myip == "1.1.1.1") {
                                add_log2('error', 'Reading Security Policies', 'Security RuleID [' . $lid . '] is using an Address [' . $src . '] that is not defined in my Database. Fix it before to finish', $source, 'Adding to the DB [ip:' . $myip . ']. Add IP Address', 'rules', $lid, 'security_rules');
                            }
                            $name_int = truncate_names(normalizeNames($src));
                            $projectdb->query("INSERT INTO address (name_ext,name,source,checkit,ipaddress,type,vsys,zone) values('$src','$name_int','$source','1','$myip','ip-netmask','$vsys','$zoneFrom');");
                            $member_lid = $projectdb->insert_id;
                            $table_name = "address";
                            $add_src[] = "('$lid','$source','$member_lid','$table_name','$vsys')";
                        }
                    }
                }

                $destination = $data[$next + 5];
                if (($destination == "Any")OR ($destination=="Any-IPv4") OR ($destination=="Any-IPv6")) {}
                else{
                    if (preg_match("/^MIP\(/", $destination)) {
                        preg_match('#\((.*?)\)#', $destination, $match);
                        $myip = $match[1];
                        $destination = truncate_names(normalizeNames($destination));
                        $lock[] = $lid;
                    }
                    elseif (preg_match("/^VIP\(/", $destination)) {
                        preg_match('#\((.*?)\)#', $destination, $match);
                        $myip = $match[1];
                        if (ip_version($myip) == "noip") {
                            #Then its interface name
                            $getInterface = $projectdb->query("SELECT unitipaddress FROM interfaces WHERE unitname='$myip' AND source='$source';");
                            if ($getInterface->num_rows == 1) {
                                $getInterfaceData = $getInterface->fetch_assoc();
                                $getInterfaceData1 = explode("/", $getInterfaceData['unitipaddress']);
                                $myip = $getInterfaceData1[0];
                            }
                        }
                        $destination = truncate_names(normalizeNames($destination));
                        $lock[] = $lid;
                    }
                    else {
                        $myip = "1.1.1.1";
                    }
                    $getDestination = $projectdb->query("SELECT id FROM address WHERE source='$source' AND BINARY name_ext='$destination' AND vsys='$vsys' AND zone='$zoneTo';");
                    if ($getDestination->num_rows == 1) {
                        $mydest = $getDestination->fetch_assoc();
                        $member_lid = $mydest['id'];
                        $table_name = "address";
                        $add_dst[] = "('$lid','$source','$member_lid','$table_name','$vsys')";
                    }
                    else {
                        $getDestination = $projectdb->query("SELECT id FROM address_groups_id WHERE source='$source' AND BINARY name_ext='$destination' AND vsys='$vsys' AND zone='$zoneTo';");
                        if ($getDestination->num_rows == 1) {
                            $mydest = $getDestination->fetch_assoc();
                            $member_lid = $mydest['id'];
                            $table_name = "address_groups_id";
                            $add_dst[] = "('$lid','$source','$member_lid','$table_name','$vsys')";
                        } else {
                            if ($myip == "1.1.1.1") {
                                add_log2('error', 'Reading Security Policies', 'Security RuleID [' . $lid . '] is using an Address [' . $destination . '] that is not defined in my Database. Fix it before to finish', $source, 'Adding to the DB [ip:' . $myip . ']. Add IP Address', 'rules', $lid, 'security_rules');
                            }
                            $name_int = truncate_names(normalizeNames($destination));
                            $projectdb->query("INSERT INTO address (name_ext,name,source,checkit,ipaddress,type,vsys,zone,cidr) values('$destination','$name_int','$source','1','$myip','ip-netmask','$vsys','$zoneTo','32');");
                            $member_lid = $projectdb->insert_id;
                            $table_name = "address";
                            $add_dst[] = "('$lid','$source','$member_lid','$table_name','$vsys')";
                        }
                    }
                }


                $service = $data[$next + 6];
                $getService = $projectdb->query("SELECT id FROM services WHERE source='$source' AND BINARY name_ext='$service' AND vsys='$vsys';");

                if ($service == "ANY") {}
                else{
                    if ($getService->num_rows == 1) {
                        $mydest = $getService->fetch_assoc();
                        $member_lid = $mydest['id'];
                        $table_name = "services";
                        $add_srv[] = "('$lid','$source','$member_lid','$table_name','$vsys')";
                    } else {
                        $getService = $projectdb->query("SELECT id FROM services_groups_id WHERE source='$source' AND BINARY name_ext='$service' AND vsys='$vsys';");
                        if ($getService->num_rows == 1) {
                            $mydest = $getService->fetch_assoc();
                            $member_lid = $mydest['id'];
                            $table_name = "services_groups_id";
                            $add_srv[] = "('$lid','$source','$member_lid','$table_name','$vsys')";
                        } else {
                            //$getShared = $projectdb->query("SELECT id FROM shared_services WHERE source='$source' AND BINARY name='$service';");
                            $getShared = $projectdb->query("SELECT id FROM services WHERE source='$source' AND BINARY name_ext='$service' AND vsys = 'shared';");
                            if ($getShared->num_rows == 1) {
                                $mydest = $getShared->fetch_assoc();
                                $member_lid = $mydest['id'];
                                //$table_name = "shared_services";
                                $table_name = "services";
                                $add_srv[] = "('$lid','$source','$member_lid','$table_name','$vsys')";
                            } else {
                                add_log2('error', 'Reading Security Policies', 'Security RuleID [' . $lid . '] is using an Service [' . $service . '] that is not defined in my Database. Fix it before to finish', $source, 'Adding to the DB [dport:65000].', 'rules', $lid, 'security_rules');
                                $name_int = truncate_names(normalizeNames($service));
                                $projectdb->query("INSERT INTO services (name_ext,name,source,checkit,protocol,dport,vsys) values('$service','$name_int','$source','1','tcp','65000','$vsys');");
                                $member_lid = $projectdb->insert_id;
                                $table_name = "services";
                                add_log2('error', 'Unknown Service Created', 'While reading RuleID [' . $lid . ']', $source, 'Please Fix the Protocol and Port or Replace it by an App-ID', 'objects', $member_lid, 'services');
                                $add_srv[] = "('$lid','$source','$member_lid','$table_name','$vsys')";
                            }
                        }
                    }
                }

                # Read NAT SRC
                if (($data[$next + 7] == "nat") AND ( $data[$next + 8] == "src")) {
                    # there is snat
                    if ($data[$next + 9] == "dip-id") {
                        $dip_id = $data[$next + 10];
                        $addDip[] = "('$source','$vsys','$lid','dip-id','$dip_id')";
                        $next2=$next+10;
                        $posNat=$next+11;
                    } else {
                        # Nat with the Interface from the TO Zone
                        $addDip[] = "('$source','$vsys','$lid','interface','')";
                        $next2=$next+9;
                        $posNat=$next+9;
                    }

                    //Check coexisting NAT SRC and DST
                    if( isset($data[$posNat]) AND ( $data[$posNat] == "dst") AND ($data[$posNat + 1] == "ip")){
                        $natdst_ip = $data[$posNat + 2];

                        if ($data[$posNat + 3] == "port") {
                            $natdst_port = $data[$posNat + 4];
                        }
                        elseif (filter_var($data[$posNat + 3], FILTER_VALIDATE_IP)) {
                            $natdst_ip = $data[$posNat + 4] . "-" . $data[$posNat + 5];
                            if ($data[$posNat + 4] == "port") {
                                $natdst_port = $data[$posNat + 5];
                            }
                        }
                        else{
                            $natdst_port = '';
                        }


                        $splitaddress = explode("-", $natdst_ip);
                        $startip = $splitaddress[0];
                        if (isset($splitaddress[1])) { $endip = $splitaddress[1];}
                        else { $endip = $splitaddress[0];}


                        if ($endip == $startip) {
                            $getAddress = $projectdb->query("SELECT id FROM address WHERE ipaddress='$startip' AND vsys='$vsys' AND source='$source';");
                            if ($getAddress->num_rows == 1) {
                                $getAddressData = $getAddress->fetch_assoc();
                                $table_name = "address";
                                $member_lid = $getAddressData['id'];
                            }
                            else {
                                $name = "H-" . $startip;
                                $projectdb->query("INSERT INTO address (name_ext,name,ipaddress,cidr,source,vsys,type,used) VALUES ('$name','$name','$startip','32','$source','$vsys','ip-netmask','1')");
                                $member_lid = $projectdb->insert_id;
                                $table_name = "address";
                            }
                        }
                        else {
                            # Its a Range
                            $getAddress = $projectdb->query("SELECT id FROM address WHERE ipaddress='$startip-$endip' AND vsys='$vsys' AND source='$source';");
                            if ($getAddress->num_rows == 1) {
                                $getAddressData = $getAddress->fetch_assoc();
                                $table_name = "address";
                                $member_lid = $getAddressData['id'];
                            }
                            else {
                                $name = "R-" . $startip;
                                $projectdb->query("INSERT INTO address (name_ext,name,ipaddress,cidr,source,vsys,type,used) VALUES ('$name','$name','$startip-$endip','','$source','$vsys','ip-range','1')");
                                $member_lid = $projectdb->insert_id;
                                $table_name = "address";
                            }
                        }

                        //$projectdb->query("INSERT INTO netscreen_natdst (source,vsys,template,rule_lid,ipaddress,port) VALUES ('$source','$vsys','$template','$lid','$natdst_ip','$natdst_port')");
                        $natdest = new NATEntry($source,$vsys,$template,$lid,$member_lid,'address',$natdst_port);
                        $natdst_content[$lid] = $natdest;  //Adding the object with NAT information in an associative array based on $lid as a key
                        $lock[] = $lid;
                    }
                }

                # Read NAT DST
                if (($data[$next + 7] == "nat") AND ( $data[$next + 8] == "dst") AND ( $data[$next + 9] == "ip")) {
                    $natdst_ip = $data[$next + 10];
                    $next2=$next+10;
                    if ($data[$next + 11] == "port") {
                        $natdst_port = $data[$next + 12];
                        $next2=$next+12;
                    } elseif (filter_var($data[$next + 11], FILTER_VALIDATE_IP)) {
                        $natdst_ip = $data[$next + 10] . "-" . $data[$next + 11];
                        $next2=$next+11;
                        if ($data[$next + 12] == "port") {
                            $natdst_port = $data[$next + 13];
                            $next2=$next+13;
                        }
                    }
                    else{
//                        echo "NEXT+ $next+11: ".$names_line."\n";
                        $natdst_port = '';
                    }
                    $projectdb->query("INSERT INTO netscreen_natdst (source,vsys,template,rule_lid,ipaddress,port) VALUES ('$source','$vsys','$template','$lid','$natdst_ip','$natdst_port')");
                    $lock[] = $lid;
                }

//                    # Read NAT SRC
//                    if (($data[$next2 + 1] == "nat") AND ( $data[$next2 + 2] == "src")) {
//                        # there is snat
//                        if ($data[$next2 + 3] == "dip-id") {
//                            $dip_id = $data[$next2 + 4];
//                            $addDip[] = "('$source','$vsys','$lid','dip-id','$dip_id')";
//                        } else {
//                            # Nat with the Interface from the TO Zone
//                            $addDip[] = "('$source','$vsys','$lid','interface','')";
//                        }
//                    }
//
//                    # Read NAT DST
//                    if (($data[$next2 + 1] == "nat") AND ( $data[$next2 + 2] == "dst") AND ( $data[$next2 + 3] == "ip")) {
//                        $natdst_ip = $data[$next2 + 4];
//                        if ($data[$next2 + 5] == "port") {
//                            $natdst_port = $data[$next2 + 6];
//                        } elseif (filter_var($data[$next2 + 5], FILTER_VALIDATE_IP)) {
//                            $natdst_ip = $data[$next2 + 4] . "-" . $data[$next2 + 5];
//                            if ($data[$next2 + 6] == "port") {
//                                $natdst_port = $data[$next2 + 7];
//                            }
//                        }
//                        $projectdb->query("INSERT INTO netscreen_natdst (source,vsys,template,rule_lid,ipaddress,port) VALUES ('$source','$vsys','$template','$lid','$natdst_ip','$natdst_port')");
//                        $lock[] = $lid;
//                    }

                if (preg_match("/\bpermit\b/", $names_line)) {
                    $action = "allow";
                    $add_action_allow[] = "'$lid'";
                } elseif (preg_match("/\bdeny\b/", $names_line)) {
                    $action = "deny";
                    $add_action_deny[] = "'$lid'";
                } elseif (preg_match("/\breject\b/", $names_line)) {
                    $action = "deny";
                    $add_action_deny[] = "'$lid'";
                } else {
                    add_log2('error', 'Reading Security Rules', 'No Action found in Rule [' . $lid . '] [' . $names_line . ']', $source, 'Using DENY.', 'rules', $lid, 'security_rules');
                    $action = "deny";
                    $add_action_deny[] = "'$lid'";
                    if (preg_match("/tunnel vpn/", $names_line)) {
                        $update_rule[] = "'$lid'";
                    }
                }
            } elseif (isset($data[4]) and ( $data[4] == "disable")) {
                $add_disabled[] = "'$lid'";
            } elseif (isset($data[4]) and ( $data[4] == "application")) {
                $app = $data[5];
                if ($app == "IGNORE") {

                } else {
                    add_log2('warning', 'Phase 5: Reading Security Rules', 'Seen Application (ALG:' . $data[5] . ') in Rule [' . $lid . ']', $source, 'Add the right APP-id to this Rule.','rules',$lid,'security_rules');
                }
            } elseif (isset($data[4]) and ( ($data[4] == "av") OR ( $data[4] == "attack"))) {
                add_log2('1', 'Phase 5: Reading Security Rules', 'Attack or AV options are omited in Rule [' . $lid . ']', $source, 'No Action Required.','rules',$lid,'security_rules');
            }
        }
        elseif (preg_match("/^set policy global id /i", $names_line)) {
            $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
            $policyID = $data[4];


            if ($policyID != $oldID) {
                $lid++;
                $position++;
                $add_rule[] = "('$lid','$vsys','$lid','$source','Rule ID $policyID','$data[6]')";
            } else {
                if (!isset($data[5])) {
                    $extended_args = TRUE;
                }
            }
            $oldID = $policyID;
            if (isset($data[5]) and ( ($data[5] == "name") OR ( $data[5] == "from") )) {

                $next = 5;
                if ($data[$next] == "name") {
                    #Add Tag
                    $color = "color" . $thecolor;
                    $tagname = truncate_tags(normalizeNames($data[$next + 1]));

                    $getDup = $projectdb->query("SELECT id FROM tag WHERE source='$source' AND name='$tagname' AND vsys='$vsys';");
                    if ($getDup->num_rows == 0) {
                        $projectdb->query("INSERT INTO tag (name,source,vsys,color) VALUES ('$tagname','$source','$vsys','$color');");
                        if ($thecolor == 16) {
                            $thecolor = 1;
                        } else {
                            $thecolor++;
                        }
                        $tag_id = $projectdb->insert_id;
                    } else {
                        $getDupData = $getDup->fetch_assoc();
                        $tag_id = $getDupData['id'];
                    }

                    $policyName = $tagname;
                    $add_tag[] = "('$source','$vsys','$lid','tag','$tag_id')";
                    $next = 7;
                }

                if ($data[$next] == "from") {
                    $zoneFrom = $data[$next + 1];
                    if (preg_match("/^Global/", $zoneFrom)) {
                        $getTag = $projectdb->query("SELECT id FROM tag WHERE name='Global Rule' AND source='$source' ANd vsys='$vsys';");
                        if ($getTag->num_rows == 0) {
                            $color = "color" . $thecolor;
                            $tagname = "Global Rule";
                            $projectdb->query("INSERT INTO tag (name,source,vsys,color) VALUES ('$tagname','$source','$vsys','$color');");
                            if ($thecolor == 16) {
                                $thecolor = 1;
                            } else {
                                $thecolor++;
                            }
                            $tag_id = $projectdb->insert_id;
                            $add_tag[] = "('$source','$vsys','$lid','tag','$tag_id')";
                        } else {
                            $datatag = $getTag->fetch_assoc();
                            $tag_id = $datatag['id'];
                            $add_tag[] = "('$source','$vsys','$lid','tag','$tag_id')";
                        }
                    } else {
                        $add_from[] = "('$source','$lid','$zoneFrom','$vsys')";
                    }
                }

                if ($data[$next + 2] == "to") {
                    $zoneTo = $data[$next + 3];
                    if (preg_match("/^Global/", $zoneTo)) {

                    } else {
                        $add_to[] = "('$source','$lid','$zoneTo','$vsys')";
                    }
                }

                $src = $data[$next + 4];
                if (($src == "Any") OR ($src=="Any-IPv4") OR ($src=="Any-IPv6")) {}
                else{
                    if (preg_match("/^MIP\(/", $src)) {
                        preg_match('#\((.*?)\)#', $src, $match);
                        $myip = $match[1];
                        $src = truncate_names(normalizeNames($src));
                        $lock[] = $lid;
                    } else {
                        $myip = "1.1.1.1";
                    }
                    $getSource = $projectdb->query("SELECT id FROM address WHERE source='$source' AND BINARY name_ext='$src' AND vsys='$vsys' AND zone='$zoneFrom';");
                    if ($getSource->num_rows == 1) {
                        $mydest = $getSource->fetch_assoc();
                        $member_lid = $mydest['id'];
                        $table_name = "address";
                        $add_src[] = "('$lid','$source','$member_lid','$table_name','$vsys')";
                    } else {
                        $getSource = $projectdb->query("SELECT id FROM address_groups_id WHERE source='$source' AND BINARY name_ext='$src' AND vsys='$vsys' AND zone='$zoneFrom';");
                        if ($getSource->num_rows == 1) {
                            $mydest = $getSource->fetch_assoc();
                            $member_lid = $mydest['id'];
                            $table_name = "address_groups_id";
                            $add_src[] = "('$lid','$source','$member_lid','$table_name','$vsys')";
                        } else {
                            if ($myip == "1.1.1.1") {
                                add_log2('error', 'Reading Security Policies', 'Security RuleID [' . $lid . '] is using an Address [' . $src . '] that is not defined in my Database. Fix it before to finish', $source, 'Adding to the DB [ip:' . $myip . ']. Add IP Address', 'rules', $lid, 'security_rules');
                            }
                            $name_int = truncate_names(normalizeNames($src));
                            $projectdb->query("INSERT INTO address (name_ext,name,source,checkit,ipaddress,type,vsys,zone) values('$src','$name_int','$source','1','$myip','ip-netmask','$vsys','$zoneFrom');");
                            $member_lid = $projectdb->insert_id;
                            $table_name = "address";
                            $add_src[] = "('$lid','$source','$member_lid','$table_name','$vsys')";
                        }
                    }
                }

                $destination = $data[$next + 5];
                if (($destination == "Any") OR ($destination=="Any-IPv4") OR ($destination=="Any-IPv6")) {}
                else{
                    if (preg_match("/^MIP\(/", $destination)) {
                        preg_match('#\((.*?)\)#', $destination, $match);
                        $myip = $match[1];
                        $destination = truncate_names(normalizeNames($destination));
                        $lock[] = $lid;
                    }
                    elseif (preg_match("/^VIP\(/", $destination)) {
                        preg_match('#\((.*?)\)#', $destination, $match);
                        $myip = $match[1];
                        if (ip_version($myip) == "noip") {
                            #Then its interface name
                            $getInterface = $projectdb->query("SELECT unitipaddress FROM interfaces WHERE unitname='$myip' AND source='$source';");
                            if ($getInterface->num_rows == 1) {
                                $getInterfaceData = $getInterface->fetch_assoc();
                                $getInterfaceData1 = explode("/", $getInterfaceData['unitipaddress']);
                                $myip = $getInterfaceData1[0];
                            }
                        }
                        $destination = truncate_names(normalizeNames($destination));
                        $lock[] = $lid;
                    }
                    else {
                        $myip = "1.1.1.1";
                    }
                    $getDestination = $projectdb->query("SELECT id FROM address WHERE source='$source' AND BINARY name_ext='$destination' AND vsys='$vsys' AND zone='$zoneTo';");
                    if ($getDestination->num_rows == 1) {
                        $mydest = $getDestination->fetch_assoc();
                        $member_lid = $mydest['id'];
                        $table_name = "address";
                        $add_dst[] = "('$lid','$source','$member_lid','$table_name','$vsys')";
                    }
                    else {
                        $getDestination = $projectdb->query("SELECT id FROM address_groups_id WHERE source='$source' AND BINARY name_ext='$destination' AND vsys='$vsys' AND zone='$zoneTo';");
                        if ($getDestination->num_rows == 1) {
                            $mydest = $getDestination->fetch_assoc();
                            $member_lid = $mydest['id'];
                            $table_name = "address_groups_id";
                            $add_dst[] = "('$lid','$source','$member_lid','$table_name','$vsys')";
                        } else {
                            if ($myip == "1.1.1.1") {
                                add_log2('error', 'Reading Security Policies', 'Security RuleID [' . $lid . '] is using an Address [' . $destination . '] that is not defined in my Database. Fix it before to finish', $source, 'Adding to the DB [ip:' . $myip . ']. Add IP Address', 'rules', $lid, 'security_rules');
                            }
                            $name_int = truncate_names(normalizeNames($destination));
                            $projectdb->query("INSERT INTO address (name_ext,name,source,checkit,ipaddress,type,vsys,zone) values('$destination','$name_int','$source','1','$myip','ip-netmask','$vsys','$zoneTo');");
                            $member_lid = $projectdb->insert_id;
                            $table_name = "address";
                            $add_dst[] = "('$lid','$source','$member_lid','$table_name','$vsys')";
                        }
                    }
                }

                $service = $data[$next + 6];
                if ($service == "ANY") {}
                else{
                    $getService = $projectdb->query("SELECT id FROM services WHERE source='$source' AND BINARY name_ext='$service' AND vsys='$vsys';");
                    if ($getService->num_rows == 1) {
                        $mydest = $getService->fetch_assoc();
                        $member_lid = $mydest['id'];
                        $table_name = "services";
                        $add_srv[] = "('$lid','$source','$member_lid','$table_name','$vsys')";
                    } else {
                        $getService = $projectdb->query("SELECT id FROM services_groups_id WHERE source='$source' AND BINARY name_ext='$service' AND vsys='$vsys';");
                        if ($getService->num_rows == 1) {
                            $mydest = $getService->fetch_assoc();
                            $member_lid = $mydest['id'];
                            $table_name = "services_groups_id";
                            $add_srv[] = "('$lid','$source','$member_lid','$table_name','$vsys')";
                        } else {
                            //$getShared = $projectdb->query("SELECT id FROM shared_services WHERE source='$source' AND BINARY name='$service';");
                            $getShared = $projectdb->query("SELECT id FROM services WHERE source='$source' AND BINARY name_ext='$service' AND vsys = 'shared';");
                            if ($getShared->num_rows == 1) {
                                $mydest = $getShared->fetch_assoc();
                                $member_lid = $mydest['id'];
                                //$table_name = "shared_services";
                                $table_name = "services";
                                $add_srv[] = "('$lid','$source','$member_lid','$table_name','$vsys')";
                            } else {
                                add_log2('error', 'Reading Security Policies', 'Security RuleID [' . $lid . '] is using an Service [' . $service . '] that is not defined in my Database. Fix it before to finish', $source, 'Adding to the DB [dport:65000].', 'rules', $lid, 'security_rules');
                                $name_int = truncate_names(normalizeNames($service));
                                $projectdb->query("INSERT INTO services (name_ext,name,source,checkit,protocol,dport,vsys) values('$service','$name_int','$source','1','tcp','65000','$vsys');");
                                $member_lid = $projectdb->insert_id;
                                $table_name = "services";
                                add_log2('error', 'Unknown Service Created', 'While reading RuleID [' . $lid . ']', $source, 'Please Fix the Protocol and Port or Replace it by an App-ID', 'objects', $member_lid, 'services');
                                $add_srv[] = "('$lid','$source','$member_lid','$table_name','$vsys')";
                            }
                        }
                    }
                }

                if (preg_match("/\bpermit\b/", $names_line)) {
                    $action = "allow";
                    $add_action_allow[] = "'$lid'";
                } elseif (preg_match("/\bdeny\b/", $names_line)) {
                    $action = "deny";
                    $add_action_deny[] = "'$lid'";
                } elseif (preg_match("/\breject\b/", $names_line)) {
                    $action = "deny";
                    $add_action_deny[] = "'$lid'";
                } else {
                    add_log2('error', 'Reading Security Rules', 'No Action found in Rule [' . $lid . '] [' . $names_line . ']', $source, 'Using DENY.', 'rules', $lid, 'security_rules');
                    $action = "deny";
                    $add_action_deny[] = "'$lid'";
                    if (preg_match("/tunnel vpn/", $names_line)) {
                        $update_rule[] = "'$lid'";
                    }
                }
            } elseif (isset($data[5]) and ( $data[5] == "disable")) {
                $add_disabled[] = "'$lid'";
            } elseif (isset($data[5]) and ( $data[5] == "application")) {
                $app = $data[6];
                if ($app == "IGNORE") {

                } else {
                    add_log2('warning', 'Phase 5: Reading Security Rules', 'Seen Application (ALG:' . $data[6] . ') in Rule [' . $lid . ']', $source, 'Add the right APP-id to this Rule.', 'rules', $lid, 'security_rules');
                }
            } elseif (isset($data[5]) and ( ($data[5] == "av") OR ( $data[5] == "attack"))) {
                add_log2('1', 'Phase 5: Reading Security Rules', 'Attack or AV options are omited in Rule [' . $lid . ']', $source, 'No Action Required.', 'rules', $lid, 'security_rules');
            }
        }
    }

    if (count($add_rule) > 0) {

        $projectdb->query("INSERT INTO security_rules (position,vsys,id,source,name,description) VALUES " . implode(",", $add_rule) . ";");
        unset($add_rule);

        if (count($addDip) > 0) {
            $projectdb->query("INSERT INTO netscreen_dip_mapping (source,vsys,rule_lid,dip_type,dip) VALUES " . implode(",", $addDip) . ";");
        }

        if (count($add_disabled) > 0) {
            $projectdb->query("UPDATE security_rules SET disabled='1' WHERE source='$source' AND id IN (" . implode(",", $add_disabled) . ");");
            unset($add_disabled);
        }

        if (count($add_action_allow) > 0) {
            $projectdb->query("UPDATE security_rules SET action='allow' WHERE source='$source' AND id IN (" . implode(",", $add_action_allow) . ");");
            unset($add_action_allow);
        }

        if (count($add_action_deny) > 0) {
            $projectdb->query("UPDATE security_rules SET action='deny' WHERE source='$source' AND id IN (" . implode(",", $add_action_deny) . ");");
            unset($add_action_deny);
        }

        if (count($add_log_start) > 0) {
            $projectdb->query("UPDATE security_rules SET log_start='1' WHERE source='$source' AND id IN (" . implode(",", $add_log_start) . ");");
            unset($add_log_start);
        }
        if (count($add_log_end) > 0) {
            $projectdb->query("UPDATE security_rules SET log_end='1' WHERE source='$source' AND id IN (" . implode(",", $add_log_end) . ");");
            unset($add_log_end);
        }
        if (count($update_rules_dst_negated) > 0) {
            $projectdb->query("UPDATE security_rules SET negate_destination='1' WHERE source='$source' AND id IN (" . implode(",", $update_rules_dst_negated) . ");");
            unset($update_rules_dst_negated);
        }
        if (count($update_rule) > 0) {
            $projectdb->query("UPDATE security_rules SET checkit='1' WHERE source='$source' AND id IN (" . implode(",", $update_rule) . ");");
            unset($update_rule);
        }
        if (count($update_rules_src_negated) > 0) {
            $projectdb->query("UPDATE security_rules SET negate_source='1' WHERE source='$source' AND id IN (" . implode(",", $update_rules_src_negated) . ");");
            unset($update_rules_src_negated);
        }
        if (count($add_dst) > 0) {
            $projectdb->query("INSERT INTO security_rules_dst (rule_lid,source,member_lid,table_name,vsys) VALUES " . implode(",", $add_dst) . ";");
            unset($add_dst);
        }
        if (count($add_src) > 0) {
            $projectdb->query("INSERT INTO security_rules_src (rule_lid,source,member_lid,table_name,vsys) VALUES " . implode(",", $add_src) . ";");
            unset($add_src);
        }
        if (count($add_srv) > 0) {
            $projectdb->query("INSERT INTO security_rules_srv (rule_lid,source,member_lid,table_name,vsys) VALUES " . implode(",", $add_srv) . ";");
            unset($add_srv);
        }
        if (count($add_tag) > 0) {
            $projectdb->query("INSERT INTO security_rules_tag (source,vsys,rule_lid,table_name,member_lid) VALUES " . implode(",", $add_tag) . ";");
            unset($add_tag);
        }
        if (count($add_from) > 0) {
            $projectdb->query("INSERT INTO security_rules_from (source,rule_lid,name,vsys) VALUES " . implode(",", $add_from) . ";");
            unset($add_from);
        }
        if (count($add_to) > 0) {
            $projectdb->query("INSERT INTO security_rules_to (source,rule_lid,name,vsys) VALUES " . implode(",", $add_to) . ";");
            unset($add_to);
        }
        #LOCK
        if (count($lock) > 0) {
            $unique = array_unique($lock);
            $projectdb->query("UPDATE security_rules SET blocked=1 WHERE id IN (" . implode(",", $lock) . ");");
        }
    }
}
/**
 *
 * @global type $projectdb
 * @param type $screenos_config_file
 * @param type $source
 * @param type $vsys
 * @param type $ismultiornot
 * @param type $template
 */
function map_vr($screenos_config_file, $source, $vsys, $ismultiornot, $template) {
    global $projectdb;

    foreach ($screenos_config_file as $line => $names_line) {
        if ((preg_match("/^set zone/", $names_line)) AND ( preg_match("/\bvrouter\b/", $names_line))) {
            $datavr = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
            $getVRID = $projectdb->query("SELECT id FROM virtual_routers WHERE name='$datavr[4]'  AND source='$source' AND template='$template';");
            if ($getVRID->num_rows > 0) {
                $getDataVR = $getVRID->fetch_assoc();
                $vrid = $getDataVR['id'];
                $projectdb->query("UPDATE interfaces SET vr_id='$vrid' WHERE zone='$datavr[2]' AND template='$template';");


                /*
                $getInt = $projectdb->query("SELECT interfaces FROM zones WHERE source='$source' AND template='$template'  AND name='$datavr[2]';");
                if ($getInt->num_rows > 0) {
                    while ($newdata = $getInt->fetch_assoc()) {
                        $inter = $newdata['interfaces'];
                        $dd = explode(",", $inter);
                        $inter = array();
                        foreach ($dd as $key => $value) {
                            $inter[] = "'$value'";
                        }
                        $projectdb->query("UPDATE interfaces SET vr_id='$vrid' WHERE name IN (" . implode(",", $inter) . ") AND template='$template' AND source='$source';");
                        #print "UPDATE interfaces SET vr_id='$vrid' WHERE name IN (".implode(",",$inter).") AND template='$template' AND source='$source';\n";
                    }
                }

                 */
            }
        }
    }

    $getVR=$projectdb->query("SELECT id FROM virtual_routers WHERE source='$source' AND template='$template';");
    if ($getVR->num_rows>0){
        while($data=$getVR->fetch_assoc()){
            $vrid=$data['id'];
            $getInt=$projectdb->query("SELECT tointerface, count(id) as t FROM routes_static WHERE template='$template' AND vr_id='$vrid' GROUP BY tointerface HAVING t > 1;");
            if ($getInt->num_rows>0){
                while($data2=$getInt->fetch_assoc()){
                    $interface=$data2['tointerface'];
                    if ($interface!=""){
                        $projectdb->query("UPDATE interfaces SET vr_id='$vrid' WHERE template='$template' AND unitname='$interface';");
                    }

                }
            }
        }
    }

    /*
    #Add Interfaces to the VR
    $getVR = $projectdb->query("SELECT id FROM virtual_routers WHERE template='$template';");
    if ($getVR->num_rows > 0) {
        while ($data = $getVR->fetch_assoc()) {
            $vr_id = $data['id'];
            $getInt = $projectdb->query("SELECT unitname FROM interfaces WHERE template='$template' AND vr_id='$vr_id';");
            $int = array();
            while ($data2 = $getInt->fetch_assoc()) {
                $int[] = $data2['unitname'];
            }
            if (count($int) > 0) {
                $projectdb->query("UPDATE virtual_routers SET interfaces='" . implode(",", $int) . "' WHERE id='$vr_id';");
                #print "UPDATE virtual_routers SET interfaces='".implode(",",$int)."' WHERE id='$vr_id';\n";
                $int = "";
            }
        }
    }
     */

    $interfaces_updated = array();
    #Add Interfaces based on the Static Routes
    $getVR = $projectdb->query("SELECT id FROM virtual_routers WHERE template='$template';");
    if ($getVR->num_rows > 0) {
        while ($data = $getVR->fetch_assoc()) {
            $vr_id = $data['id'];
            $getInt = $projectdb->query("SELECT tointerface FROM routes_static WHERE template='$template' AND vr_id='$vr_id';");
            $int = array();
            while ($data2 = $getInt->fetch_assoc()) {
                if(strcmp($data2['tointerface'],"")!=0){
                    $int[] = $data2['tointerface'];
                }
            }
            $int = array_unique($int);

            if (count($int) > 0) {
                $projectdb->query("UPDATE virtual_routers SET interfaces='" . implode(",", $int) . "' WHERE id='$vr_id';");
                foreach($int as $interface_name){
                    if (!in_array($interface_name, $interfaces_updated)){
                        $query = 'UPDATE interfaces SET vr_id='.$vr_id.' WHERE unitname="'.$interface_name.'";';
                        $projectdb->query($query);
                        $interfaces_updated[] = $interface_name;
                    }
                }
                unset($int);
            }
        }
    }

    #Add Interfaces to the VR
    $getVR = $projectdb->query("SELECT id FROM virtual_routers WHERE template='$template';");
    while ($data = $getVR->fetch_assoc()) {
        $int = array();
        $vr_id = $data['id'];
        $getInt = $projectdb->query("SELECT unitname FROM interfaces WHERE template='$template' AND vr_id='$vr_id' AND link_state!='down'");
        while ($data2 = $getInt->fetch_assoc()) {
            $int[] = $data2['unitname'];
        }
        if (count($int)>0){
            $projectdb->query("UPDATE virtual_routers SET interfaces='" . implode(",", $int) . "' WHERE id='$vr_id';");
        }
    }


}
/**
 *
 * @global type $projectdb
 * @param type $screenos_config_file
 * @param type $source
 * @param type $vsys
 * @param type $ismultiornot
 * @param type $template
 */
function get_routes($screenos_config_file, $source, $vsys, $ismultiornot, $template) {
    global $projectdb;
    $isvrouter = false;
    $param = false;
    $add_route = array();
    $x = 1;
    $count = 0;
    $vsys="root";
    foreach ($screenos_config_file as $line => $names_line) {
        if (preg_match("/^set vsys /i", $names_line)) {
            $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
            $vsys = $data[2];
        }

        if (($isvrouter == true) AND ( $param == false) AND ( preg_match("/^exit/", $names_line))) {
            $isvrouter = false;
            $x = 1;
        }

        if (($isvrouter == true) AND ( $param == false)) {
            if (preg_match("/^set route-map /i", $names_line)) {
                $param = true;
            }
            if (preg_match("/^set protocol /i", $names_line)) {
                $param = true;
            }
        }
        if (($isvrouter == true) AND ( $param == true)) {
            if (preg_match("/^exit/i", $names_line)) {
                $param = false;
            }
        }

        if (preg_match("/^set vrouter /i", $names_line)) {
            $isvrouter = true;
            $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
            if (!isset($data[3]) OR $data[3] == "sharable") {
                $vr = $data[2];
                $getDup = $projectdb->query("SELECT id FROM virtual_routers WHERE name='$vr' AND template='$template';");
                if ($getDup->num_rows == 0) {
                    $projectdb->query("INSERT INTO virtual_routers (name,template,source,vsys) VALUES ('$vr','$template','$source','$vsys');");
                    $vr_id = $projectdb->insert_id;
                } else {
                    $getData = $getDup->fetch_assoc();
                    $vr_id = $getData['id'];
                }
            }
        }

        if (($isvrouter == true) AND  preg_match("/^set route source /i", $names_line)){
            #set route source 10.10.10.0/24 interface ethernet0/2 gateway 1.1.1.1 preference 20 metric 2
            $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
            $message = "The following route should be created as a Policy Based Forwarding Rule. "
                . "<a href=\"https://FIREWALL_URL/#policies::VSYS::policies/pbf-rulebase\" target=blank>https://FIREWALL_URL/#policies::VSYS::policies/pbf-rulebase</a> "
                . "<br><b>Source</b>: $data[3]";
            $get_interface = array_search('interface', $data);
            $interface_name = $data[$get_interface+1];

            $get_destination = array_search('destination', $data);
            if($get_destination>0){
                $destination_name = $data[$get_destination+1];
                $message = "$message<br><b>Destination</b>: $destination_name";
            }
            $message = "$message<br><b>Forwarding-Egress Interface</b>: $interface_name ";

            $get_gateway = array_search('gateway', $data);
            if(isset($get_gateway)){
                $gateway_name = $data[$get_gateway+1];
                $message = "$message<br><b>Forwarding-Next Hop</b>: $gateway_name";
            }
            add_log2('error', 'Reading Route', 'Source Routes are not supported.', $source, $message, '', '', '');
        }

        elseif(($isvrouter == true) AND preg_match("/^set route (.*) vrouter (.*)/i", $names_line)){
            #set route 10.10.10.10/24 vrouter "vrt1" preference 20 metric 1
            $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);

            $network_and_mask = $data[2];

            $get_vroute = array_search('vroute', $data);
            $route_name = $data[$get_vroute+1];

            $get_preference = array_search('preference', $data);
            $preference = $data[$get_preference + 1];

            $interfaceto = '';
            $get_vrouter = array_search('vrouter', $data);
            $gateway = $data[$get_vrouter+1];
            $gateway = str_replace('"', "", $gateway);

            $route_name = "Route " . $x;
            $x++;

            //INSERT INTO routes_static (destination,nexthop,nexthop_value,tointerface,metric,name,source,vr_id,vsys,template)
            $add_route[] = "('$network_and_mask','next-vr','$gateway','$interfaceto','$preference','$route_name','$source','$vr_id','$vsys','$template')";
        }

        elseif (($isvrouter == true) AND ( ( preg_match("/^set route /i", $names_line)) OR
                ( preg_match("/^set vrouter $vr route /i", $names_line)) ) AND ( preg_match("/ gateway /i", $names_line)) AND ( !preg_match("/^set route source/i", $names_line))) {
            $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
            #set route 0.0.0.0/0 interface ethernet1/1.1:1 gateway 166.14.132.57
            #set route 199.12.0.162/32 interface ethernet1/2.21:1 gateway 199.12.6.205 preference 20


            $get_gateway = array_search('gateway', $data);
            $gateway = $data[$get_gateway + 1];
            $get_network = array_search('route', $data);
            if ($get_network) {
                $network_and_mask = $data[$get_network + 1];
            } else {
                $network_and_mask = $data[2];
            }

            $get_preference = array_search('preference', $data);
            $preference = $data[$get_preference + 1];
            $get_interface = array_search('interface', $data);
            if ($get_interface !== FALSE) {
                $interfaceto1 = $data[$get_interface + 1];
                $int = explode(":", $interfaceto1);
                $interfaceto = $int[0];
            } else {
                $interfaceto = "";
            }

            if (!is_numeric($preference)) {
                $preference = "1";
            }

            if ($network_and_mask == "0.0.0.0/0") {
                if ($count == 0) {
                    $add_route[] = "('$network_and_mask','ip-address','$gateway','$interfaceto','$preference','default','$source','$vr_id','$vsys','$template')";
                    $count++;
                } else {
                    $routeNewName = 'default ' . $count;
                    $add_route[] = "('$network_and_mask','ip-address','$gateway','$interfaceto','$preference','$routeNewName','$source','$vr_id','$vsys','$template')";
                    $count++;
                }
            } else {
                $route_name = "Route " . $x;
                if (preg_match("/\bgateway\b/", $names_line)) {
                    $route_type = "ip-address";
                    $nexthop_value = $gateway;
                } else {
                    $route_type = "None";
                    $nexthop_value = "";
                }
                $add_route[] = "('$network_and_mask','$route_type','$nexthop_value','$interfaceto','$preference','$route_name','$source','$vr_id','$vsys','$template')";
                $x++;
            }
        }
        elseif (($isvrouter == true) AND ( ( preg_match("/^set route /i", $names_line)) OR ( preg_match("/^set vrouter $vr route /i", $names_line)) ) AND ( preg_match("/ interface /i", $names_line))) {
            #set route 55.128.17.56/32 interface ethernet0/0 preference 20 description "txt"
            $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
            $get_network = array_search('route', $data);
            if ($get_network) {
                $network_and_mask = $data[$get_network + 1];
            } else {
                $network_and_mask = $data[2];
            }
            $get_interface = array_search('interface', $data);
            if ($get_interface !== FALSE) {
                $interfaceto1 = $data[$get_interface + 1];
                $int = explode(":", $interfaceto1);
                $interfaceto = $int[0];
            } else {
                $interfaceto = "";
            }
            $get_preference = array_search('preference', $data);
            $preference = $data[$get_preference + 1];
            if (!is_numeric($preference)) {
                $preference = "1";
            }
            if ($network_and_mask == "0.0.0.0/0") {
                if ($count == 0) {
                    $add_route[] = "('$network_and_mask','ip-address','$gateway','$interfaceto','$preference','default','$source','$vr_id','$vsys','$template')";
                    $count++;
                } else {
                    $routeNewName = 'default ' . $count;
                    $add_route[] = "('$network_and_mask','ip-address','$gateway','$interfaceto','$preference','$routeNewName','$source','$vr_id','$vsys','$template')";
                    $count++;
                }
            } else {
                $route_name = "Route " . $x;
                if (preg_match("/\bgateway\b/", $names_line)) {
                    $route_type = "ip-address";
                    $nexthop_value = $gateway;
                } else {
                    $route_type = "None";
                    $nexthop_value = "";
                }
                $add_route[] = "('$network_and_mask','$route_type','$nexthop_value','$interfaceto','$preference','$route_name','$source','$vr_id','$vsys','$template')";
                $x++;
            }
        }

    }
    if (count($add_route) > 0) {
        $projectdb->query("INSERT INTO routes_static (destination,nexthop,nexthop_value,tointerface,metric,name,source,vr_id,vsys,template) VALUES " . implode(",", $add_route) . ";");
        unset($add_route);
    }
    #Map zones to routes by interface
    $getGW = $projectdb->query("SELECT id,tointerface FROM routes_static WHERE source='$source' AND template='$template';");
    if ($getGW->num_rows > 0) {
        while ($data = $getGW->fetch_assoc()) {
            $tointerface = $data['tointerface'];
            $routeid = $data['id'];
            #Compare agains what interface is
            $getZone = $projectdb->query("SELECT zone FROM interfaces WHERE unitname='$tointerface' AND source='$source';");
            if ($getZone->num_rows > 0) {
                $getZoneData = $getZone->fetch_assoc();
                $theZone = $getZoneData['zone'];
                $projectdb->query("UPDATE routes_static SET zone='$theZone' WHERE id='$routeid';");
            }
        }
    }
}
/**
 *
 * @global type $projectdb
 * @param type $screenos_config_file
 * @param type $source
 * @param type $vsys
 * @param type $ismultiornot
 * @param type $template
 */
function get_nat_MIP($screenos_config_file, $source, $vsys, $ismultiornot, $template) {
    global $projectdb;
    $interfaces = array();
    $zones = array();
    $vsys="root";
    $getPosition = $projectdb->query("SELECT max(position) as t FROM nat_rules WHERE vsys='$vsys' AND source='$source';");
    if ($getPosition->num_rows == 0) {
        $nat_position = 0;
    } else {
        $ddata = $getPosition->fetch_assoc();
        $position = intval($ddata['t']) + 1;
    }
//    if ($nat_lid == "") {
        $getlastlid = $projectdb->query("SELECT max(id) as max FROM nat_rules;");
        $getLID1 = $getlastlid->fetch_assoc();
        $nat_lid = intval($getLID1['max']) + 1;
//    }



    $addMIP = array();
    foreach ($screenos_config_file as $line => $names_line) {
        if (preg_match("/^set vsys /i", $names_line)) {
            $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
            $vsys = $data[2];
        }
        $addMIPFrom = array();
        if (preg_match("/^set vrouter /i", $names_line)) {

        }
        if (preg_match("/^set interface /i", $names_line)) {
            $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
            $int = explode(":", $data[2]);
            $interName = $int[0];

            if ($data[3] == "mip") {
                if ($data[5] == "host") {
                    $originalIP = $data[4];
                    $mappedIP = $data[6];
                    $mappedMask = $data[8];
                    $ip_version = ip_version($mappedIP);
                    if ($ip_version == "v4") {
                        $mappedCidr = mask2cidrv4($mappedMask);
                    }
                    $getZone = $projectdb->query("SELECT name FROM zones WHERE source='$source' AND vsys='$vsys' AND template='$template' AND interfaces='$interName';");
                    if ($getZone->num_rows == 1) {
                        $getZoneData = $getZone->fetch_assoc();
                        $zone = $getZoneData['name'];
                        $addMIPFrom[] = "('$source','$vsys','$nat_lid','$zone')";
                    } else {
                        $zone = "";
                    }

                    $getOriginal = $projectdb->query("SELECT id FROM address WHERE source='$source' AND vsys='$vsys' AND ipaddress='$originalIP' AND cidr='$mappedCidr' LIMIT 1;");
                    if ($getOriginal->num_rows == 1) {
                        $data = $getOriginal->fetch_assoc();
                        $member_lid = $data['id'];
                        $table_name = "address";
                    } else {
                        //$getOriginal = $projectdb->query("SELECT id FROM shared_address WHERE source='$source' AND ipaddress='$originalIP' AND cidr='$mappedCidr' LIMIT 1;");
                        $getOriginal = $projectdb->query("SELECT id FROM address WHERE source='$source' AND ipaddress='$originalIP' AND cidr='$mappedCidr' AND vsys = 'shared' LIMIT 1;");
                        if ($getOriginal->num_rows == 1) {
                            $data = $getOriginal->fetch_assoc();
                            $member_lid = $data['id'];
                            //$table_name = "shared_address";
                            $table_name = "address";
                        } else {
                            #Create it or find in shared first
                            add_log2('error', 'Reading Nat Policies', 'Nat RuleID [' . $nat_lid . '] is using an Address [' . $originalIP . '] that is not defined in my Database.', $source, 'Adding to the DB.', 'rules', $nat_lid, 'nat_rules');
                            if ($mappedCidr == "32") {
                                $name_int = "H-" . $originalIP . "-32";
                            } else {
                                $name_int = "N-" . $originalIP . "-" . $mappedCidr;
                            }

                            $projectdb->query("INSERT INTO address (name_ext,name,source,checkit,ipaddress,type,vsys,zone,cidr) values('$originalIP','$name_int','$source','1','$originalIP','ip-netmask','$vsys','$zone','$mappedCidr');");
                            $member_lid = $projectdb->insert_id;
                            $table_name = "address";
                        }
                    }

                    $addMIPTranslatedAddress[] = "('$source','$vsys','$nat_lid','$member_lid','$table_name')";
                    $ruleName = "MIP " . $originalIP;


                    $getMapped = $projectdb->query("SELECT id FROM address WHERE source='$source' AND vsys='$vsys' AND ipaddress='$mappedIP' AND cidr='$mappedCidr' LIMIT 1;");
                    if ($getMapped->num_rows == 1) {
                        $data = $getMapped->fetch_assoc();
                        $dst_lid = $data['id'];
                        $dst_table = "address";
                    } else {
                        //$getMapped = $projectdb->query("SELECT id FROM shared_address WHERE source='$source' AND ipaddress='$mappedIP' AND cidr='$mappedCidr' LIMIT 1;");
                        $getMapped = $projectdb->query("SELECT id FROM address WHERE source='$source' AND ipaddress='$mappedIP' AND cidr='$mappedCidr' AND vsys = 'shared' LIMIT 1;");
                        if ($getMapped->num_rows == 1) {
                            $data = $getMapped->fetch_assoc();
                            $dst_lid = $data['id'];
                            //$dst_table = "shared_address";
                            $dst_table = "address";
                        } else {
                            #Create it or find in shared first
                            add_log2('error', 'Reading Nat Policies', 'Nat RuleID [' . $nat_lid . '] is using an Address [' . $mappedIP . '] that is not defined in my Database.', $source, 'Adding to the DB.', 'rules', $nat_lid, 'nat_rules');
                            if ($mappedCidr == "32") {
                                $name_int = "H-" . $mappedIP . "-32";
                            } else {
                                $name_int = "N-" . $mappedIP . "-" . $mappedCidr;
                            }
                            $projectdb->query("INSERT INTO address (name_ext,name,source,checkit,ipaddress,type,vsys,zone,cidr) values('$mappedIP','$name_int','$source','1','$mappedIP','ip-netmask','$vsys','$zone','$mappedCidr');");
                            $dst_lid = $projectdb->insert_id;
                            $dst_table = "address";
                        }
                    }
                    $addMIPDst[] = "('$source','$vsys','$nat_lid','$dst_lid','$dst_table')";

                    $addMIP[] = "('0','0','$source','$vsys','$nat_lid','$position','$ruleName','0','$zone','',0,'','','static-ip','translated-address','','',1,'','None','','')";
                    $nat_lid++;
                    $position++;
                }
            }
        }
    }

    if (count($addMIP) > 0) {
        $projectdb->query("INSERT INTO nat_rules (blocked,checkit,source,vsys,id,position,name,disabled,op_zone_to,op_to_interface,is_dat,op_service_lid,op_service_table,tp_sat_type,tp_sat_address_type,tp_sat_ipaddress,description,tp_sat_bidirectional,tp_sat_interface,tp_fallback_type,tp_sat_interface_fallback,tp_sat_ipaddress_fallback) "
            . "VALUES " . implode(",", $addMIP) . ";");
        if (count($addMIPFrom) > 0) {
            $projectdb->query("INSERT INTO nat_rules_from (source,vsys,rule_lid,name) VALUES " . implode(",", $addMIPFrom) . ";");
            unset($addMIPFrom);
        }
        if (count($addMIPTranslatedAddress) > 0) {
            $projectdb->query("INSERT INTO nat_rules_translated_address (source,vsys,rule_lid,member_lid,table_name) VALUES " . implode(",", $addMIPTranslatedAddress) . ";");
            unset($addMIPTranslatedAddress);
        }
        if (count($addMIPDst) > 0) {
            $projectdb->query("INSERT INTO nat_rules_src (source,vsys,rule_lid,member_lid,table_name) VALUES " . implode(",", $addMIPDst) . ";");
            unset($addMIPDst);
        }
        unset($addMIP);
    }
}
/** Updates the ZoneTo for the Security Rules based on the Destination Nats.
 *  It also corrects the ZoneTo of the Nat Rules. Screenos defined the ZoneTo after applying the NAT rule.
 *  However, in our destination NAT rules, we need to define the ZoneTo before applying NAT.
 *
 * @global type $projectdb
 * @param type $source
 * @param type $vsys
 */
function fix_destination_nat($source, $vsys) {
    global $projectdb;

#FIX the MIPs Static-ip where in the security policy we find a MIP as a destination
    $getDNAT = $projectdb->query("SELECT id FROM nat_rules WHERE tp_sat_type='static-ip' AND tp_sat_bidirectional='1' AND source='$source' AND vsys='$vsys';");
    if ($getDNAT->num_rows > 0) {

        while ($data = $getDNAT->fetch_assoc()) {
            $lid = $data['id'];
            # I need the Zone from the Source
            $getSource = $projectdb->query("SELECT member_lid,table_name FROM nat_rules_src WHERE rule_lid='$lid';");
            if ($getSource->num_rows == 1) {
                $getSourceData = $getSource->fetch_assoc();
                $member_lid = $getSourceData['member_lid'];
                $table_name = $getSourceData['table_name'];
                $zone = search_zone_address_one($member_lid, $vsys, $source, $table_name);
                $projectdb->query("UPDATE nat_rules_from SET name='$zone' WHERE rule_lid='$lid';");
            }

            $getTranslated = $projectdb->query("SELECT member_lid,table_name FROM nat_rules_translated_address WHERE rule_lid='$lid';");
            if ($getTranslated->num_rows > 0) {
                $getTranslatedData = $getTranslated->fetch_assoc();
                $member_lid = $getTranslatedData['member_lid'];
                $table_name = $getTranslatedData['table_name'];

                #Change the ZoneTo in all the rules where is
                $getRules = $projectdb->query("SELECT rule_lid FROM security_rules_dst WHERE member_lid='$member_lid' AND table_name='$table_name';");
                if ($getRules->num_rows > 0) {
                    while ($rulesData = $getRules->fetch_assoc()) {
                        $rule_lid = $rulesData['rule_lid'];
                        $projectdb->query("DELETE FROM security_rules_to WHERE rule_lid='$rule_lid' AND source='$source';");
                        $projectdb->query("INSERT INTO security_rules_to (source,vsys,name,rule_lid) VALUES ('$source','$vsys','$zone','$rule_lid');");
                        $projectdb->query("UPDATE security_rules SET blocked=1 WHERE id='$rule_lid';");
                        add_log2('warning', 'Fixing Destination Nats', 'Security RuleID [' . $rule_lid . '] has been modified by Nat RuleID [' . $lid . '], Replaced Destination Zone by [' . $zone . ']', $source, 'Check it manually', 'rules', $rule_lid, 'security_rules');
                    }
                }
            }
        }
    }

    // MT-364 Comment because nat dst zone to not necessary calculate
    /*$getDNAT = $projectdb->query("SELECT id FROM nat_rules WHERE is_dat='1' AND source='$source' AND vsys='$vsys';");
    if ($getDNAT->num_rows > 0) {
        while ($data = $getDNAT->fetch_assoc()) {
            $zones = array();
            $lid = $data['id'];
            # I need the Zone from the destination
            $getDestination = $projectdb->query("SELECT member_lid,table_name FROM nat_rules_dst WHERE rule_lid='$lid';");
            while ($getDestinationData = $getDestination->fetch_assoc()) {
                $member_lid = $getDestinationData['member_lid'];
                $table_name = $getDestinationData['table_name'];
                $zones[] = search_zone_address_one($member_lid, $vsys, $source, $table_name);
            }
            $number_of_zones = count($zones);
            if($number_of_zones==1){
                $zoneName=$zones[0];
                $projectdb->query('UPDATE nat_rules SET op_zone_to = "'.$zoneName.'" WHERE id='.$lid.';');
                //echo 'UPDATE nat_rules SET op_zone_to = "'.$zoneName.'" WHERE id='.$lid.';';
            }
            elseif($number_of_zones==0){
                add_log2('warning', 'Fixing NAT To Zone', 'NAT RuleID [' . $rule_lid . '] does not have Zone To defined.', $source, 'Check it manually', 'rules', $rule_lid, 'nat_rules');
            }
            else{
                $zoneName=$zones[0];
                $projectdb->query('UPDATE nat_rules SET op_zone_to = "'.$zoneName.'" WHERE id='.$lid.';');
                add_log2('warning', 'Fixing NAT To Zone', 'NAT RuleID [' . $rule_lid . '] has multiple Zone To defined. Split into multiple NAT Rules', $source, 'Check it manually', 'rules', $rule_lid, 'nat_rules');
            }

        }
    }*/
}

function get_interfaces($screenos_config_file, $source, $vsys, $ismultiornot, $template) {
    global $projectdb;
    $interfaces = array();
    $zones = array();
    $dip = array();
    $vsys="root";

    foreach ($screenos_config_file as $line => $names_line) {

        if (preg_match("/^set vsys /i", $names_line)) {
            $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
            $vsys = $data[2];
        }

        if (preg_match("/^set vrouter /i", $names_line)) {
            //TODO:
        }
        if (preg_match("/^set interface /i", $names_line)) {
            $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
            //echo "DATA: \n";
            //print_r($data);
            $dip_tp_sat_type="";
            $int = explode(":", $data[2]);
            $interName = $int[0];
            if ($data[3] == "zone") {
                $interfaces[$interName]["zone"] = $data[4];
                //echo "Data 4: " .$data[4]. "\n";
            }
            elseif (($data[3] == "ip") AND ( preg_match("/\//", $data[4]))) {
                if (isset($interfaces[$interName]["ip"])) {
                    $interfaces[$interName]["ip"] = $interfaces[$interName]["ip"] = $data[4].",".$data[4];
                } else {
                    $interfaces[$interName]["ip"] = $data[4];
                }
            }
            elseif (($data[3] == "ip") AND  filter_var($data[4], FILTER_VALIDATE_IP) AND filter_var($data[5], FILTER_VALIDATE_IP) ) {
                $cidr = mask2cidrv4($data[5]);
                $new_interface = $data[4]."/".$cidr;
                if (isset($interfaces[$interName]["ip"])) {
                    $interfaces[$interName]["ip"] = $interfaces[$interName]["ip"].",".$new_interface;
                } else {
                    $interfaces[$interName]["ip"] = $data[4];
                }
            }
            elseif($data[3] === "ipv6" && $data[4] === "ip" && isset($data[5])){
                if (isset($interfaces[$interName]["ip"])) {
                    $interfaces[$interName]["ip"] .= "," . $data[5];
                } else {
                    $interfaces[$interName]["ip"] = $data[5];
                }

            }
            elseif ($data[3] == "tag") {
                $interfaces[$interName]["tag"] = $data[4];
                $interfaces[$interName]["zone"] = $data[6];
                //echo "Data 6: " .$data[6]. "\n";
            }
            elseif (($data[3] == "ext") AND ( $data[7] == "dip")) {
                $dip_id = $data[8];
                if ($data[9] == "shift-from") {
                    # Alert ? Not supported by now
                }
                else {
                    $dip_startip = $data[9];
                    $dip_endip = $data[10];
                    if (isset($data[11])){
                        if ($data[11] == "fix-port") {
                            $dip_tp_sat_type = "dynamic-ip";
                        }
                    }
                    else {
                        $dip_tp_sat_type = "dynamic-ip-and-port";
                    }


                }
                $dip[] = "('$source','$vsys','$template','$dip_id','$interName','$dip_startip','$dip_endip','$dip_tp_sat_type')";
            }
            #MIP
            elseif ($data[3] == "dip") {
                $dip_id = $data[4];
                if ($data[5] == "shift-from") {
                    # Alert ? Not supported by now
                } else {
                    $dip_startip = $data[5];
                    $dip_endip = $data[6];
                    if (isset($data[7])){
                        if ($data[7] == "fix-port") {
                            $dip_tp_sat_type = "dynamic-ip";
                        }
                    }
                    else {
                        $dip_tp_sat_type = "dynamic-ip-and-port";
                    }
                }
                $dip[] = "('$source','$vsys','$template','$dip_id','$interName','$dip_startip','$dip_endip','$dip_tp_sat_type')";
            }
            elseif ($data[2] == "id") {
                $int = explode(":", $data[4]);
                $interName = $int[0];
                if($data[5] == "zone"){
                    $interfaces[$interName]["zone"] = $data[6];
                }
            }
        }

    }
    if (count($dip) > 0) {
        $projectdb->query("INSERT INTO netscreen_dip (source,vsys,template,dip,unitname,startip,endip,tp_sat_type) VALUES " . implode(",", $dip) . ";");
        unset($dip);
    }
    if (count($interfaces) > 0) {
        $outInterface = array();
        foreach ($interfaces as $key => $interface) {
            if (isset($interface["tag"])) {
                if (preg_match("/\./", $key)) {
                    $unitName = $key;
                } else {
                    $unitName = $key . "." . $interface["tag"];
                }

                $unitTag = $interface["tag"];
            } else {
                $unitName = $key;
                $unitTag = "0";
            }
            if (isset($interface["ip"])) {
                $all_ipaddress = $interface["ip"];
            } else {
                $all_ipaddress = "";
            }
            if (isset($interface["zone"])) {
                $zone = $interface["zone"];
                //echo "ZONA---->" .$zone. "\n";
                $zones[] = "('$source','$template','$vsys','$zone','layer3')";
            } else {
                $zone = "";
            }
            if (preg_match("/^tunnel/", $key)) {
                $outInterface[] = "('tunnel','$source','tunnel','layer3','','$unitName','$unitTag','$all_ipaddress','$template','$vsys','$zone')";
            } elseif (preg_match("/^loopback/", $key)) {
                $outInterface[] = "('loopback','$source','loopback','layer3','','$unitName','$unitTag','$all_ipaddress','$template','$vsys','$zone')";
            } else {
                if (preg_match("/\./", $key)) {
                    $removetags = explode(".", $key);
                    $key = $removetags[0];
                }
                $outInterface[] = "('ethernet','$source','$key','layer3','','$unitName','$unitTag','$all_ipaddress','$template','$vsys','$zone')";
            }
        }
        $projectdb->query("INSERT INTO interfaces (media,source,name,type,comment,unitname,unittag,unitipaddress,template,vsys,zone) VALUES " . implode(",", $outInterface) . ";");
        unset($outInterface);
        unset($interfaces);
    }
    if (count($zones) > 0) {
        //echo "ARRAY ZONES\n";
        //print_r($zones);
        $unique = array_unique($zones);
        $projectdb->query("INSERT INTO zones (source,template,vsys,name,type) VALUES " . implode(",", $unique) . ";");
        //echo "1. INSERT INTO zones (source,template,vsys,name,type) VALUES " . implode(",", $unique) . ";\n";
        unset($unique);
        unset($zones);
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
        $int = "";
    }

}

function get_services($screenos_config_file, $source, $vsys, $ismultiornot){
    global $projectdb;
    $getlastlid = $projectdb->query("SELECT max(id) as max FROM services;");
    $getLID1 = $getlastlid->fetch_assoc();
    $lid = intval($getLID1['max']) + 1;
    $vsys="root";
    $serviceObj=array();
    foreach ($screenos_config_file as $line => $names_line) {

        if (preg_match("/^set vsys /i", $names_line)) {
            $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
            $vsys = $data[2];
        }

        if (preg_match("/^set service /i", $names_line)) {
            $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);

            if (isset($data[3])) {
                $name_ext=$data[2];
                switch($data[3]){
                    case "protocol":
                        $serviceObj[$vsys][$name_ext]=new serviceObject($source,$vsys,$lid,$name_ext);
                        $lid++;

                        $protocol = $data[4];

                        if (($protocol=="tcp") OR ($protocol=="udp")){
                            $dport = $data[8];
                            $sport = $data[6];

                            $dportsplit = explode("-", $dport);
                            if ($dportsplit[0] == $dportsplit[1]) {
                                $dport = $dportsplit[0];
                            }
                            $sportsplit = explode("-", $sport);
                            if ($sportsplit[0] == $sportsplit[1]) {
                                $sport = $sportsplit[0];
                            }
                            if (($sport=="1-65535") OR ($sport=="0-65535")){
                                $sport="";
                            }
                        }
                        else{
                            $sport="";$dport="";
                        }



                        $serviceObj[$vsys][$name_ext]->addMembers($protocol,$sport,$dport);
                        if (isset($data[9])){
                            if ($data[9]=="timeout"){
                                $timeout=$data[10] * 60;
                                if ($timeout!="never" && $timeout != 3600){
                                    $serviceObj[$vsys][$name_ext]->setTimeout($timeout);
                                }
                                else{
                                    # Its never ToDo: Check what is the max tmout
                                }
                                $serviceObj[$vsys][$name_ext]->addLog('warning', 'Reading Services Objects and Groups', 'The Service [' . $name_ext . '] has a custom Time-Out [' . $timeout . ' sec ]','If you are migrating to PanOS 8.1 it will be applied if not you will have to AppOverride it.');
                                //add_log2('warning','Reading Services Objects and Groups' , 'The Service [' . $name_ext . '] has a custom Time-Out [' . $timeout . ']', $source, 'If you are migrating to PanOS 8.1 it will be applied if not you will have to AppOverride it.', 'objects', $lid, 'services');
                            }
                        }
                        break;
                    case "+":
                        if (isset($serviceObj[$vsys][$name_ext])){
                            $newProtocol=$data[4];
                            $thisLid = $serviceObj[$vsys][$name_ext]->getLid();
                            if ($newProtocol==$protocol or true){

                                if (($newProtocol=="tcp") OR ($newProtocol=="udp")){
                                    $dport = $data[8];
                                    $sport = $data[6];

                                    $dportsplit = explode("-", $dport);
                                    if ($dportsplit[0] == $dportsplit[1]) {
                                        $dport = $dportsplit[0];
                                    }
                                    $sportsplit = explode("-", $sport);
                                    if ($sportsplit[0] == $sportsplit[1]) {
                                        $sport = $sportsplit[0];
                                    }
                                    if (($sport=="1-65535") OR ($sport=="0-65535")){
                                        $sport="";
                                    }
                                }
                                else{
                                    $sport="";$dport="";
                                }

                                $serviceObj[$vsys][$name_ext]->addMembers($newProtocol,$sport,$dport);
                                if (isset($data[9])){
                                    if ($data[9]=="timeout"){
                                        $timeout=$data[10] * 60;
                                        if ($timeout!="never" && $timeout != 3600){
                                            $serviceObj[$vsys][$name_ext]->setTimeout($timeout);
                                        }
                                        else{
                                            # Its never ToDo: Check what is the max tmout
                                        }
                                        $serviceObj[$vsys][$name_ext]->addLog('warning', 'Reading Services Objects and Groups', 'The Service [' . $name_ext . '] has a custom Time-Out [' . $timeout . ' sec ]', 'If you are migrating to PanOS 8.1 it will be applied if not you will have to AppOverride it.');
                                        //add_log2('warning', 'Reading Services Objects and Groups', 'The Service [' . $name_ext . '] has a custom Time-Out [' . $timeout . ']', $source, 'If you are migrating to PanOS 8.1 it will be applied if not you will have to AppOverride it.', 'objects', $thisLid, 'services');
                                    }
                                }

                            }
                            else{
                                # Create a ServiceGroup
                                //echo "CREATE A GROUP for $name_ext".PHP_EOL;
                                $serviceObj[$vsys][$name_ext]->addLog("error",'Importing Services','The service called [' . $name_ext . '] is using different protocols', 'Replace the Service by the App-id or Create a ServiceGroup with the different services');
                                //add_log2("error",'Importing Services','The service called [' . $name_ext . '] is using different protocols',$source,'Replace the Service by the App-id or Create a ServiceGroup with the different services','objects',$thisLid,'services');
                                //echo $names_line.PHP_EOL;
                            }
                        }
                        else{
                            print "Error: Adding info to a ghost service ".$names_line.PHP_EOL;
                        }
                        break;
                    case "timeout":
                        $timeout=$data[4] * 60;
                        if ($timeout!="never" && $timeout != 3600){
                            if (isset($serviceObj[$vsys][$name_ext])){
                                $serviceObj[$vsys][$name_ext]->setTimeout($timeout);
                                $serviceObj[$vsys][$name_ext]->addLog('warning', 'Reading Services Objects and Groups', 'The Service [' . $name_ext . '] has a custom Time-Out [' . $timeout . ' sec]', 'If you are migrating to PanOS 8.1 it will be applied if not you will have to AppOverride it.');
                            }
                            else{
                                $getService=$projectdb->query("SELECT id FROM services WHERE source='$source' AND name_ext='$name_ext';");
                                if ($getService->num_rows==1){
                                    $getServiceData=$getService->fetch_assoc();
                                    $serviceLid=$getServiceData['id'];
                                    $projectdb->query("UPDATE services SET override='yes', timeout='$timeout' WHERE id='$serviceLid';");
                                    add_log2("warning",'Reading Services Objects and Groups','The Service [' . $name_ext . '] has a custom Time-Out [' . $timeout . ']',$source, 'If you are migrating to PanOS 8.1 it will be applied if not you will have to AppOverride it.','objects',$serviceLid,'services');
                                    //echo "SERVICE:".$name_ext ." Predefined Service new timeout: ".$timeout." LOG:".$names_line.PHP_EOL;
                                }
                                else{
                                    add_log("error",'Importing Services','The service called [' . $name_ext . '] is using a timeout',$source, "Invalid Service $name_ext, unable to apply new timeout: $timeout",'objects');
//                                    echo "Invalid Service $name_ext, unable to apply new timeout: $timeout".PHP_EOL;
                                }

                            }
                        }
                        else{
                            # Its never ToDo: Check what is the max tmout
                        }
                        //$serviceObj[$vsys][$name_ext]->addLog('warning', 'Reading Services Objects and Groups', 'The Service [' . $name_ext . '] has a custom Time-Out [' . $timeout . ']', 'If you are migrating to PanOS 8.1 it will be applied if not you will have to AppOverride it.');
                        //add_log2('warning', 'Reading Services Objects and Groups', 'The Service [' . $name_ext . '] has a custom Time-Out [' . $timeout . ']', $source, 'If you are migrating to PanOS 8.1 it will be applied if not you will have to AppOverride it.', 'objects', $lid, 'services');
                        break;
                    default:
                        break;
                }
            }
        }
    }


    $startID=intval($getLID1['max']) + 1;
    $serviceArray = array();
    $logs = array();
    foreach ($serviceObj as $name=>$array){
        foreach($array as $groupInfo){
            $addedServices =$groupInfo->getServices($startID);
            $numberOfServices = count($addedServices);
            foreach($groupInfo->getLogs() as $log){
                for($i=0; $i<$numberOfServices; $i++) {  //In the case that a service is split into multiple service instances because they have several combinations of protocol, sport and dport, we will add the logs to all the instances
                    $serviceID = $startID+$i;
                    $logs[] = "(".$log['type'].", ".$log['task'].", ".$log['message'].", $source, ".$log['action'].", 'objects', $serviceID,'services')";
                }
            }
            $startID += count($addedServices);
            $serviceArray=array_merge($serviceArray, $addedServices);
        }

    }
    if (count($serviceArray)>0){
        $projectdb->query("INSERT INTO services (id,name,type,name_ext,checkit,source,used,dport,sport,protocol,vsys,timeout,override) values ".implode(",",$serviceArray).";");
        unset($serviceArray);
    }

}

function get_services_groups($screenos_config_file, $source, $vsys, $ismultiornot){

    global $projectdb;

    $vsys="root";
    $comment = "";

    $getLid = $projectdb->query("SELECT max(id) as max FROM services_groups_id;");
    $getLidData=$getLid->fetch_assoc();
    $lid=$getLidData['max']+1;


    $getServices=$projectdb->query("SELECT id,name_ext,vsys FROM services WHERE source='$source';");
    if ($getServices->num_rows>0){
        $addressObj=array();
        while($getAddressData=$getServices->fetch_assoc()){
            $address=$getAddressData['name_ext'];
            $srv_vsys=$getAddressData['vsys'];
            $addressObj[$srv_vsys][$address]=$getAddressData['id'];
        }
    }

    $existingServiceGroupObj=array();
    $getServicesGroups=$projectdb->query("SELECT id,name_ext,vsys FROM services_groups_id WHERE source='$source';");
    if ($getServicesGroups->num_rows>0){
        $existingServiceGroupObj=array();
        while($getServiceGroupData=$getServicesGroups->fetch_assoc()){
            $name_ext=$getServiceGroupData['name_ext'];
            $srv_vsys=$getServiceGroupData['vsys'];
            $id=$getServiceGroupData['id'];
            $existingServiceGroupObj[$vsys][$name_ext]=new ObjectGroup($source,$srv_vsys,$id,'',$name_ext);
        }
    }

    $addrGroupObj=array();

    //Add SNMP Service as a group
    $querySNMP = "SELECT id from services WHERE name_ext LIKE '%-SNMP' AND source='$source' AND vsys='$vsys';";
    $resultSNMP = $projectdb->query($querySNMP);
    if(count($resultSNMP->num_rows>0)){
        $addrGroupObj[$vsys]['SNMP']=new ObjectGroup($source,$vsys,$lid,'','SNMP');
        $lid++;
        $addrGroupObj[$vsys]['SNMP']->addMember($addressObj[$vsys]['TCP-SNMP'], "services");
        $addrGroupObj[$vsys]['SNMP']->addMember($addressObj[$vsys]['UDP-SNMP'], "services");

        //$out = implode(",", $snmpIDs);
        //$projectdb->query("INSERT INTO services_groups (source,vsys,lid,table_name, member_lid) VALUES ".$out.";");
    }

    foreach ($screenos_config_file as $line => $names_line) {

        if (preg_match("/^set vsys /i", $names_line)) {
            $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
            $vsys=$data[2];
        }

        if (preg_match("/^set group service /i", $names_line)){
            $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);

            $name_ext = $data[3];

            if (!isset($addrGroupObj[$vsys][$name_ext])){
                $addrGroupObj[$vsys][$name_ext]=new ObjectGroup($source,$vsys,$lid,'',$name_ext);
                $lid++;
            }

            if (isset($data[4])){
                switch($data[4]){
                    case "comment":
                        $comment=$data[5];
                        $addrGroupObj[$vsys][$name_ext]->addComment=addslashes($comment);
                        break;

                    case "add":
                        $member = $data[5];
                        if (isset($existingServiceGroupObj[$vsys][$member])) {
                            /** @var ObjectGroup $this_group */
                            $addrGroupObj[$vsys][$name_ext]->addMember($existingServiceGroupObj[$vsys][$member]->getLid(), "services_groups_id");
                        }
                        elseif (isset($addressObj[$vsys][$member])) {
                            /** @var ObjectGroup $this_group */
                            $addrGroupObj[$vsys][$name_ext]->addMember($addressObj[$vsys][$member], "services");
                        }
                        elseif (isset($addrGroupObj[$vsys][$member])){
                            /** @var ObjectGroup $contains_member
                             *  @var ObjectGroup $this_group  */
                            $contains_member = $addrGroupObj[$vsys][$member];
                            $addrGroupObj[$vsys][$name_ext]->addMember($contains_member->getLid(),"services_groups_id");
                        }
                        elseif (isset($addressObj['shared'][$member])) {
                            /** @var ObjectGroup $this_group */
                            $addrGroupObj[$vsys][$name_ext]->addMember($addressObj['shared'][$member], "services");
                        }
                        elseif (isset($addrGroupObj['shared'][$member])){
                            /** @var ObjectGroup $contains_member
                             *  @var ObjectGroup $this_group  */
                            $contains_member = $addrGroupObj['shared'][$member];
                            $addrGroupObj[$vsys][$name_ext]->addMember($contains_member->getLid(),"services_groups_id");
                        }
                        else{
                            $projectdb->query("INSERT INTO services (source,vsys,name_ext,name,devicegroup,invalid,description,protocol,dport) VALUES ('$source','$vsys','$member','".normalizeNames($member)."','default',1,'Added by Expedition','','')");
                            $newLid=$projectdb->insert_id;
                            $addressObj[$vsys][$member]=$newLid;
                        }
                        break;

                    default:

                }
            }
        }

    }

    $addAddressGroups = array();
    foreach ($addrGroupObj as $name=>$array1){
        /**
         * @var  String $zone
         * @var  ObjectGroup $groupInfo
         */
        foreach ($array1 as $zone=>$groupInfo){
            $addAddressGroups[]=$groupInfo->getAddressGroup();

            $addMembers[]=$groupInfo->getMembers();
//            if ($addMembersraw!=""){
//                $addMembers[]=$addMembersraw;
//            }
            $addMembers = array_filter($addMembers);
        }
    }

    if (count($addAddressGroups)>0){
        $projectdb->query("INSERT INTO services_groups_id (id,name,name_ext,source,vsys,type,description) VALUES ".implode(",",$addAddressGroups).";");
        $projectdb->query("INSERT INTO services_groups (lid,member,source,vsys,member_lid,table_name) VALUES " . implode(",", $addMembers) . ";");
    }

}

function get_services_groups_old($screenos_config_file, $source, $vsys, $ismultiornot) {
    global $projectdb;
    $lid = 0;
    $oldname = "";
    $add_member = array();
    if ($ismultiornot == "singlevsys") {
        $START = TRUE;
    } else {
        $START = FALSE;
    }
    if ($vsys == "root") {
        $START = TRUE;
    }
    foreach ($screenos_config_file as $line => $names_line) {
        #set group service "ICMP-ALL" add "ICMP-INFO"
        if ($START == FALSE) {
            if (preg_match("/^set vsys \"$vsys\"/i", $names_line)) {
                $START = TRUE;
            }
        } else {
            if (preg_match("/^set vsys /i", $names_line)) {
                $START = FALSE;
            }
        }

        if ($START) {
            $comment="";
            if (preg_match("/^set group service /i", $names_line)) {
                $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);

                if (isset($data[5])) {
                    if ($data[4]=="comment"){
                        $comment=addslashes($data[5]);
                    }
                    if ($data[4] == "add") {
                        $name_ext = $data[3];
                        $name_int = truncate_names(normalizeNames($name_ext));
                        if ($oldname != $name_ext) {
                            $getDup = $projectdb->query("SELECT id FROM services_groups_id WHERE source='$source' AND BINARY name_ext='$name_ext' AND vsys='$vsys';");
                            if ($getDup->num_rows == 0) {
                                $projectdb->query("INSERT INTO services_groups_id (name,name_ext,source,vsys,description) VALUES ('$name_int','$name_ext','$source','$vsys','$comment');");
                                $lid = $projectdb->insert_id;
                            }
                        }
                        $member = $data[5];
                        $add_member[] = "('$lid','$member','$source','$vsys')";
                        $oldname = $name_ext;
                        $comment="";
                    }
                }
            }
        }
    }
    if (count($add_member) > 0) {
        $projectdb->query("INSERT INTO services_groups (lid,member,source,vsys) VALUES " . implode(",", $add_member) . ";");
        unset($add_member);
    }
}

function get_address_SCREENOS($screenos_config_file, $source, $vsys, $ismultiornot) {
    global $projectdb;
    $add_address = array();
    $vsys="root";
    foreach ($screenos_config_file as $line => $names_line) {
        if (preg_match("/^set vsys /i", $names_line)) {
            $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
            $vsys=$data[2];
        }
        if (preg_match("/^set address /i", $names_line)) {
                $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                if (isset($data[4])) {
                    $name_ext = $data[3];
                    $zone = $data[2];

                    $name_int = str_replace('/', '-', $name_ext);
                    $name_int = truncate_names(normalizeNames($name_int));

                    $ipaddressCheck = $data[4];
                    $ipversionCheck = ip_version($ipaddressCheck);
                    if ($ipversionCheck == "noip") {
                        if (isset($data[5])) {
                            $description = addslashes(trim($data[5]));
                        } else {
                            $description = "";
                        }
                        if (preg_match("/\//", $ipaddressCheck)) {
                            #Mode ip/mask
                            $ipnetmask = explode("/", $ipaddressCheck);
                            $ipaddress = $ipnetmask[0];
                            $ipversion = ip_version($ipaddress);
                            $cidr = $ipnetmask[1];
                            $add_address[] = "('ip-netmask','$name_ext','0','$source','0','$ipaddress','$cidr','$description','$name_int','$vsys','$zone')";
                        } else {
                            #Is FQDN
                            $valid = false;
                            if (isset($data[5])) {
                                $valid = filter_var($data[5], FILTER_VALIDATE_IP);
                            }
                            if ($valid) {
                                $ipaddress = $ipaddressCheck;
                                $netmask = $data[5];
                                $cidr = mask2cidrv4($netmask);
                                $add_address[] = "('ip-netmask','$name_ext','1','$source','0','1.1.1.1','$cidr','$description','$name_int','$vsys','$zone')";
                                add_log('error', 'Adding Address', 'Invalid IP address [' . $ipaddress . '] found in Object [' . $name_ext . ']', $source, 'Add right IP address to this Object');
                            } else {
                                $ipaddress = $ipaddressCheck;
                                $add_address[] = "('fqdn','$name_ext','0','$source','0','$ipaddress','32','$description','$name_int','$vsys','$zone')";
                            }
                        }
                    } else {
                        $ipaddress = $ipaddressCheck;
                        $netmask = $data[5];
                        if (isset($data[6])) {
                            $description = addslashes(trim($data[6]));
                        } else {
                            $description = "";
                        }
                        $cidr = mask2cidrv4($netmask);

                        $table = "address";
                        $add_address[] = "('ip-netmask','$name_ext','0','$source','0','$ipaddress','$cidr','$description','$name_int','$vsys','$zone')";
                    }
                }
            }
    }

    if (count($add_address) > 0) {
        $unique = array_unique($add_address);
        $projectdb->query("INSERT INTO address (type,name_ext,checkit,source,used,ipaddress,cidr,description,name,vsys,zone) VALUES " . implode(",", $unique) . ";");
        unset($add_address);
        unset($unique);
    }
}

function get_address_groups($screenos_config_file, $source, $vsys, $ismultiornot ) {

    global $projectdb;

    $vsys="root";
    $comment = "";

    $getLid = $projectdb->query("SELECT max(id) as max FROM address_groups_id;");
    $getLidData=$getLid->fetch_assoc();
    $lid=$getLidData['max']+1;


    $getAddress=$projectdb->query("SELECT id,name_ext,zone,ipaddress,cidr FROM address WHERE source='$source';");
    if ($getAddress->num_rows>0){
        $addressObj=array();
        while($getAddressData=$getAddress->fetch_assoc()){
            $zone=$getAddressData['zone'];
            $address=$getAddressData['name_ext'];
            $ipaddress=$getAddressData['ipaddress'];
            $cidr=$getAddressData['cidr'];
            if ( ($cidr==0) OR ($cidr==32) ) {$cidr="";}
            else{$cidr="/".$cidr;}
            $network=$ipaddress.$cidr;
            $addressObj[$address][$zone]=$getAddressData['id'];
            $addressObj[$network][$zone]=$getAddressData['id'];
        }
    }

    $addrGroupObj=array();

    foreach ($screenos_config_file as $line => $names_line) {

        if (preg_match("/^set vsys /i", $names_line)) {
            $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
            $vsys=$data[2];
        }

        if (preg_match("/^set group address /i", $names_line)){
            $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
            $zone = $data[3];
            $name_ext = $data[4];

            if (!isset($addrGroupObj[$name_ext][$zone])){
                $addrGroupObj[$name_ext][$zone]=new ObjectGroup($source,$vsys,$lid,$zone,$name_ext);
                $lid++;
            }

            if (isset($data[5])){
                switch($data[5]){
                    case "comment":
                        $comment=$data[6];
                        $addrGroupObj[$name_ext][$zone]->addComment=addslashes($comment);
                        break;

                    case "add":
                        $member = $data[6];
                        if (isset($addressObj[$member][$zone])) {
                            $addrGroupObj[$name_ext][$zone]->addMember($addressObj[$member][$zone], "address");
                        }
                        elseif (isset($addrGroupObj[$member][$zone])){
                            $addrGroupObj[$name_ext][$zone]->addMember($addrGroupObj[$member][$zone]->getLid(),"address_groups_id");
                        }
                         else{
                             $addrGroupObj_lid = "-1";
                             if(isset($addrGroupObj[$member][$zone])) {
                                 $addrGroupObj_lid = $addrGroupObj[$member][$zone]->getLid();
                             }
                             add_log2("error",'Importing Address groups','The address group called [' . $member . '] provides an unknwon '. $data[5].' action',$source, "Review address group $member",'objects',$addrGroupObj_lid,'address_groups_id');
//                             echo "ERROR ".$member.PHP_EOL;
                         }
                        break;
                    default:
                }
            }
        }

    }
    $addAddressGroups=array();
    foreach ($addrGroupObj as $name=>$array1){
        /**
         * @var  String $zone
         * @var  ObjectGroup $groupInfo
         */
        foreach ($array1 as $zone=>$groupInfo){
            $addAddressGroups[]=$groupInfo->getAddressGroup();
            $addMembers[]=$groupInfo->getMembers();
            $addMembers = array_filter($addMembers);
        }
    }

    if (count($addAddressGroups)>0){
        $projectdb->query("INSERT INTO address_groups_id (id,name,name_ext,source,vsys,zone,description) VALUES ".implode(",",$addAddressGroups).";");
        $query = "INSERT INTO address_groups (lid,member,source,vsys,member_lid,table_name) VALUES " . implode(",", $addMembers) . ";";
        $projectdb->query($query);
    }

}




function add_netscreen_services($source, $vsys, $ismultiornot) {
    global $projectdb;

    $table = "services";
    
    if ($ismultiornot == "multivsys") {
        $vsys = "shared";
        //$table = "shared_services";
    } 
    //else {$table = "services";}
    $exists = $projectdb->query("SELECT id FROM services WHERE source='$source' AND vsys='$vsys' AND name IN ('FTP-Put','GOPHER','SUN-RPC-PORTMAPPER');");
    if ($exists->num_rows == 0) {

        // Add predefined services and services groups
        ServicesMapping::addPredefinedSrvAndSrvGroups($projectdb, "netscreen-screenos", $source, $vsys);


//        $add_srv = array();
//        #$add_srv[]="('$source','$vsys','junos-ftp','junos-ftp','21','tcp')";
//        $add_srv[] = "('$source','$vsys','FTP','FTP','21','tcp')";
//        $add_srv[] = "('$source','$vsys','FTP-Get','FTP-Get','21','tcp')";
//        $add_srv[] = "('$source','$vsys','FTP-Put','FTP-Put','21','tcp')";
//        $add_srv[] = "('$source','$vsys','SSH','SSH','22','tcp')";
//        $add_srv[] = "('$source','$vsys','TELNET','TELNET','23','tcp')";
//        $add_srv[] = "('$source','$vsys','MAIL','MAIL','25','tcp')";
//        $add_srv[] = "('$source','$vsys','SMTP','SMTP','25','tcp')";
//        $add_srv[] = "('$source','$vsys','WHOIS','WHOIS','43','tcp')";
//        $add_srv[] = "('$source','$vsys','GOPHER','GOPHER','70','tcp')";
//        $add_srv[] = "('$source','$vsys','FINGER','FINGER','79','tcp')";
//        $add_srv[] = "('$source','$vsys','HTTP','HTTP','80','tcp')";
//        $add_srv[] = "('$source','$vsys','POP3','POP3','110','tcp')";
//        $add_srv[] = "('$source','$vsys','IDENT','IDENT','113','tcp')";
//        $add_srv[] = "('$source','$vsys','NNTP','NNTP','119','tcp')";
//        $add_srv[] = "('$source','$vsys','SMB','SMB','139','tcp')";
//        $add_srv[] = "('$source','$vsys','IMAP','IMAP','143','tcp')";
//        $add_srv[] = "('$source','$vsys','BGP','BGP','179','tcp')";
//        $add_srv[] = "('$source','$vsys','WAIS','WAIS','210','tcp')";
//        $add_srv[] = "('$source','$vsys','Internet Locator Service','Internet Locator Service','389','tcp')";
//        $add_srv[] = "('$source','$vsys','LDAP','LDAP','389','tcp')";
//        $add_srv[] = "('$source','$vsys','HTTPS','HTTPS','443','tcp')";
//        $add_srv[] = "('$source','$vsys','REXEC','REXEC','512','tcp')";
//        $add_srv[] = "('$source','$vsys','RLOGIN','RLOGIN','513','tcp')";
//        $add_srv[] = "('$source','$vsys','RSH','RSH','514','tcp')";
//        $add_srv[] = "('$source','$vsys','LPR','LPR','515','tcp')";
//        $add_srv[] = "('$source','$vsys','RTSP','RTSP','554','tcp')";
//        $add_srv[] = "('$source','$vsys','MS-SQL','MS-SQL','1433','tcp')";
//        $add_srv[] = "('$source','$vsys','WINFRAME','WINFRAME','1494','tcp')";
//        $add_srv[] = "('$source','$vsys','SQL*Net V2','SQL Net V2','1521','tcp')";
//        $add_srv[] = "('$source','$vsys','SQL*Net V1','SQL Net V1','1525','tcp')";
//        $add_srv[] = "('$source','$vsys','H.323','H.323','1720','tcp')";
//        $add_srv[] = "('$source','$vsys','NetMeeting','NetMeeting','1720','tcp')";
//        $add_srv[] = "('$source','$vsys','MSN','MSN','1863','tcp')";
//        $add_srv[] = "('$source','$vsys','SCCP','SCCP','2000','tcp')";
//        $add_srv[] = "('$source','$vsys','YMSG','YMSG','5050','tcp')";
//        $add_srv[] = "('$source','$vsys','VNC','VNC','5800','tcp')";
//        $add_srv[] = "('$source','$vsys','VNC_XH','VNC_XH','5901','tcp')";
//        $add_srv[] = "('$source','$vsys','VNC_guest','VNC_guest','5902','tcp')";
//        $add_srv[] = "('$source','$vsys','HTTP-EXT','HTTP-EXT','7001','tcp')";
//        $add_srv[] = "('$source','$vsys','Real Media','Real Media','7070','tcp')";
//        $add_srv[] = "('$source','$vsys','NS Global','NS Global','15397','tcp')";
//        $add_srv[] = "('$source','$vsys','NS Global PRO','NS Global PRO','15397','tcp')";
//        $add_srv[] = "('$source','$vsys','ECHO','ECHO','7','udp')";
//        $add_srv[] = "('$source','$vsys','DISCARD','DISCARD','9','udp')";
//        $add_srv[] = "('$source','$vsys','CHARGEN','CHARGEN','19','udp')";
//        $add_srv[] = "('$source','$vsys','DNS','DNS','53','udp')";
//        $add_srv[] = "('$source','$vsys','DHCP-Relay','DHCP-Relay','67','udp')";
//        $add_srv[] = "('$source','$vsys','NSM','NSM','69','udp')";
//        $add_srv[] = "('$source','$vsys','TFTP','TFTP','69','udp')";
//        $add_srv[] = "('$source','$vsys','NFS','NFS','111','udp')";
//        $add_srv[] = "('$source','$vsys','SUN-RPC-PORTMAPPER','SUN-RPC-PORTMAPPER','111','udp')";
//        $add_srv[] = "('$source','$vsys','NTP','NTP','123','udp')";
//        $add_srv[] = "('$source','$vsys','MS-RPC-EPM','MS-RPC-EPM','135','udp')";
//        $add_srv[] = "('$source','$vsys','MS-RPC-ANY','MS-RPC-ANY','','')";
//        $add_srv[] = "('$source','$vsys','NBNAME','NBNAME','137','udp')";
//        $add_srv[] = "('$source','$vsys','NBDS','NBDS','138','udp')";
//        $add_srv[] = "('$source','$vsys','UDP-SNMP','UDP-SNMP','161','udp')";
//        $add_srv[] = "('$source','$vsys','TCP-SNMP','TCP-SNMP','161','tcp')";
//        $add_srv[] = "('$source','$vsys','IKE','IKE','500','udp')";
//        $add_srv[] = "('$source','$vsys','IKE-NAT','IKE-NAT','500','udp')";
//        $add_srv[] = "('$source','$vsys','SYSLOG','SYSLOG','514','udp')";
//        $add_srv[] = "('$source','$vsys','RIP','RIP','520','udp')";
//        $add_srv[] = "('$source','$vsys','UUCP','UUCP','540','udp')";
//        $add_srv[] = "('$source','$vsys','SQL Monitor','SQL Monitor','1434','udp')";
//        $add_srv[] = "('$source','$vsys','L2TP','L2TP','1701','udp')";
//        $add_srv[] = "('$source','$vsys','GTP','GTP','2123','udp')";
//        $add_srv[] = "('$source','$vsys','MGCP-UA','MGCP-UA','2427','udp')";
//        $add_srv[] = "('$source','$vsys','MGCP-CA','MGCP-CA','2727','udp')";
//        $add_srv[] = "('$source','$vsys','SIP','SIP','5060','udp')";
//        $add_srv[] = "('$source','$vsys','PC-Anywhere','PC-Anywhere','5632','udp')";
//        $add_srv[] = "('$source','$vsys','MSRPC','MSRPC','135','tcp')";
//        $add_srv[] = "('$source','$vsys','SQL','SQL','1521','tcp')";
//        $add_srv[] = "('$source','$vsys','XING','XING','1558','udp')";
//        $add_srv[] = "('$source','$vsys','PING','PING','','icmp')";
//        $add_srv[] = "('$source','$vsys','TRACEROUTE','TRACEROUTE','','icmp')";
//        $add_srv[] = "('$source','$vsys','ICMP-ANY','ICMP-ANY','','icmp')";
//        $add_srv[] = "('$source','$vsys','ICMP-INFO','ICMP-INFO','','icmp')";
//        $add_srv[] = "('$source','$vsys','ICMP-TIMESTAMP','ICMP-TIMESTAMP','','icmp')";
//        $add_srv[] = "('$source','$vsys','ICMP Address Mask','ICMP Address Mask','','icmp')";
//        $add_srv[] = "('$source','$vsys','UDP-ANY','UDP-ANY','0-65535','udp')";
//        $add_srv[] = "('$source','$vsys','TCP-ANY','TCP-ANY','0-65535','tcp')";
//        $out = implode(",", $add_srv);
//        $projectdb->query("INSERT INTO $table (source,vsys,name_ext,name,dport,protocol) VALUES " . $out . ";");
//        unset($add_srv);



    }
}

/**
 *
 * @global type $projectdb
 * @param type $screenos_config_file
 * @param type $source
 * @param type $vsys
 * @param type $ismultiornot
 * @param type $template
 */
function get_nat_VIP($screenos_config_file, $source, $vsys, $ismultiornot, $template) {
    global $projectdb;
    $interfaces = array();
    $zones = array();

    $getPosition = $projectdb->query("SELECT max(position) as t FROM nat_rules WHERE vsys='$vsys' AND source='$source';");
    if ($getPosition->num_rows == 0) {
        $nat_position = 0;
    } else {
        $ddata = $getPosition->fetch_assoc();
        $position = intval($ddata['t']) + 1;
    }
//    if ($nat_lid == "") {
        $getlastlid = $projectdb->query("SELECT max(id) as max FROM nat_rules;");
        $getLID1 = $getlastlid->fetch_assoc();
        $nat_lid = intval($getLID1['max']) + 1;
//    }

    $vsys="root";

    $addVIP = array();

    foreach ($screenos_config_file as $line => $names_line) {
        if (preg_match("/^set vsys /i", $names_line)) {
            $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
            $vsys = $data[2];
        }

        if (preg_match("/^set vrouter /i", $names_line)) {

        }
        if (preg_match("/^set interface /i", $names_line)) {
            $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
            $int = explode(":", $data[2]);
            $interName = $int[0];
            if ($data[3] == "vip") {
                $getZone = $projectdb->query("SELECT zone,unitipaddress FROM interfaces WHERE source='$source' AND vsys='$vsys' AND template='$template' AND unitname='$interName';");
                if ($getZone->num_rows == 1) {
                    $getZoneData = $getZone->fetch_assoc();
                    $zone = $getZoneData['zone'];
                    $unitipaddress = $getZoneData['unitipaddress'];
                    $addVIPFrom[] = "('$source','$vsys','$nat_lid','$zone')";
                } else {
                    $zone = "";
                }

                if ($data[4] == "interface-ip") {
                    $interfacedata = explode("/", $unitipaddress);
                    $originalIP = $interfacedata[0];
                    $ip_version = ip_version($originalIP);
                } else {
                    $ip_version = ip_version($data[4]);
                    $originalIP = $data[4];
                }

                if ($data[5] == "+") {
                    $originalPort = $data[6];
                    $mappedPort = $data[7];
                    $mappedIP = $data[8];
                } else {
                    $originalPort = $data[5];
                    $mappedPort = $data[6];
                    $mappedIP = $data[7];
                }

                if ($ip_version == "v4") {
                    $mappedCidr = "32";
                } elseif ($ip_version == "v6") {
                    $mappedCidr = "128";
                }

                $getOriginal = $projectdb->query("SELECT id FROM address WHERE source='$source' AND vsys='$vsys' AND ipaddress='$originalIP' AND cidr='$mappedCidr' LIMIT 1;");
                if ($getOriginal->num_rows == 1) {
                    $data = $getOriginal->fetch_assoc();
                    $member_lid = $data['id'];
                    $table_name = "address";
                } else {
                    //$getOriginal = $projectdb->query("SELECT id FROM shared_address WHERE source='$source' AND ipaddress='$originalIP' AND cidr='$mappedCidr' LIMIT 1;");
                    $getOriginal = $projectdb->query("SELECT id FROM address WHERE source='$source' AND ipaddress='$originalIP' AND cidr='$mappedCidr' AND vsys = 'shared' LIMIT 1;");
                    if ($getOriginal->num_rows == 1) {
                        $data = $getOriginal->fetch_assoc();
                        $member_lid = $data['id'];
                        //$table_name = "shared_address";
                        $table_name = "address";
                    } else {
                        #Create it or find in shared first
                        #add_log2('error','Reading Nat Policies','Nat RuleID ['.$nat_lid.'] is using an Address ['.$originalIP.'] that is not defined in my Database.',$source,'Adding to the DB.','rules',$nat_lid,'nat_rules');
                        if ($mappedCidr == "32") {
                            $name_int = "H-" . $originalIP . "-32";
                        } else {
                            $name_int = "N-" . $originalIP . "-" . $mappedCidr;
                        }

                        $projectdb->query("INSERT INTO address (name_ext,name,source,checkit,ipaddress,type,vsys,zone,cidr) values('$originalIP','$name_int','$source','1','$originalIP','ip-netmask','$vsys','$zone','$mappedCidr');");
                        $member_lid = $projectdb->insert_id;
                        $table_name = "address";
                    }
                }

                $originalDestinationAddress[] = "('$source','$vsys','$nat_lid','$member_lid','$table_name')";
                $ruleName = "VIP " . $originalIP . " dPort " . $originalPort;

                #Calculate DZONE from the VIP address into the Security Rules
                $dzone = search_zone_address_one($member_lid, $vsys, $source, $table_name);

                # Translated Dport
                $getDport = $projectdb->query("SELECT id,dport,protocol FROM services WHERE BINARY name_ext='$mappedPort' AND source='$source' AND vsys='$vsys';");
                if ($getDport->num_rows == 1) {
                    $getDportData = $getDport->fetch_assoc();
                    $dport = $getDportData['dport'];
                    $protocol = $getDportData['protocol'];
                    if (preg_match("/-/", $dport)) {
                        $alldport = explode("-", $dport);
                        $dport = $alldport[0];
                    }
                } else {
                    # If doesnt exist what to do, error? Create it?
                }

                # Original Dport
                $getDport = $projectdb->query("SELECT id FROM services WHERE dport='$originalPort' AND protocol='$protocol' AND source='$source' AND vsys='$vsys';");
                if ($getDport->num_rows == 1) {
                    $getDportData = $getDport->fetch_assoc();
                    $OriginalPortid = $getDportData['id'];
                } else {
                    # Create the Service Object
                    $name = $protocol . "-" . $originalPort;
                    $projectdb->query("INSERT INTO services (name_ext,name,dport,protocol,source,vsys) VALUES ('$name','$name','$originalPort','$protocol','$source','$vsys');");
                    $OriginalPortid = $projectdb->insert_id;
                }

                $getMapped = $projectdb->query("SELECT id FROM address WHERE source='$source' AND vsys='$vsys' AND ipaddress='$mappedIP' AND cidr='$mappedCidr' LIMIT 1;");
                if ($getMapped->num_rows == 1) {
                    $data = $getMapped->fetch_assoc();
                    $dst_lid = $data['id'];
                    $dst_table = "address";
                } else {
                    //$getMapped = $projectdb->query("SELECT id FROM shared_address WHERE source='$source' AND ipaddress='$mappedIP' AND cidr='$mappedCidr' LIMIT 1;");
                    $getMapped = $projectdb->query("SELECT id FROM address WHERE source='$source' AND ipaddress='$mappedIP' AND cidr='$mappedCidr' AND vsys = 'shared' LIMIT 1;");
                    if ($getMapped->num_rows == 1) {
                        $data = $getMapped->fetch_assoc();
                        $dst_lid = $data['id'];
                        //$dst_table = "shared_address";
                        $dst_table = "address";
                    } else {
                        #Create it or find in shared first
                        #add_log2('error','Reading Nat Policies','Nat RuleID ['.$nat_lid.'] is using an Address ['.$mappedIP.'] that is not defined in my Database.',$source,'Adding to the DB.','rules',$nat_lid,'nat_rules');
                        if ($mappedCidr == "32") {
                            $name_int = "H-" . $mappedIP . "-32";
                        } else {
                            $name_int = "N-" . $mappedIP . "-" . $mappedCidr;
                        }
                        $projectdb->query("INSERT INTO address (name_ext,name,source,checkit,ipaddress,type,vsys,zone,cidr) values('$mappedIP','$name_int','$source','1','$mappedIP','ip-netmask','$vsys','$zone','$mappedCidr');");
                        $dst_lid = $projectdb->insert_id;
                        $dst_table = "address";
                    }
                }

                $addVIP[] = "('0','$source','$vsys','$nat_lid','$position','$ruleName','0','$dzone','',1,'$OriginalPortid','services','','$dport','$dst_lid','$dst_table')";
                $nat_lid++;
                $position++;
            }
        }

    }

    if (count($addVIP) > 0) {
        $projectdb->query("INSERT INTO nat_rules (checkit,source,vsys,id,position,name,disabled,op_zone_to,op_to_interface,is_dat,op_service_lid,op_service_table,description,tp_dat_port,tp_dat_address_lid,tp_dat_address_table) VALUES " . implode(",", $addVIP) . ";");
        if (count($addVIPFrom) > 0) {
            $projectdb->query("INSERT INTO nat_rules_from (source,vsys,rule_lid,name) VALUES " . implode(",", $addVIPFrom) . ";");
            unset($addVIPFrom);
        }
        if (count($originalDestinationAddress) > 0) {
            $projectdb->query("INSERT INTO nat_rules_dst (source,vsys,rule_lid,member_lid,table_name) VALUES " . implode(",", $originalDestinationAddress) . ";");
            unset($originalDestinationAddress);
        }
    }
}

/**
 *
 * @global type $projectdb
 * @global array $natdst_content
 * @param type $source
 * @param type $vsys
 * @param type $template
 */
function get_nat_DIP($source, $vsys, $template) {
    global $projectdb, $natdst_content;
    $nat_lid = "";
    $addNatRule = array();
    $addZonesFrom = array();
    $addSources = array();
    $addDestination = array();
    $addTranslatedAddress = array();

    $getMapping = $projectdb->query("SELECT rule_lid,dip_type,dip FROM netscreen_dip_mapping WHERE source='$source' AND vsys='$vsys';");
    if ($getMapping->num_rows > 0) {
        $getPosition = $projectdb->query("SELECT max(position) as t FROM nat_rules WHERE vsys='$vsys' AND source='$source';");
        if ($getPosition->num_rows == 0) {
            $position = 0;
        } else {
            $ddata = $getPosition->fetch_assoc();
            $position = intval($ddata['t']) + 1;
        }
        if ($nat_lid == "") {
            $getlastlid = $projectdb->query("SELECT max(id) as max FROM nat_rules;");
            $getLID1 = $getlastlid->fetch_assoc();
            $nat_lid = intval($getLID1['max']) + 1;
        }
        while ($data = $getMapping->fetch_assoc()) {
            //$rule_lid = ""; //Defined below
            //$dip_type = ""; //Defined below
            $dip_id = "";
            $zoneTo = "";
            $tp_sat_interface = "";
            $srv_table_name = "";
            $srv_member_lid = "";

            $rule_lid = $data['rule_lid'];
            $getRule = $projectdb->query("SELECT disabled,name FROM security_rules WHERE id='$rule_lid';");
            if ($getRule->num_rows == 1) {
                $getRuleData = $getRule->fetch_assoc();
                $disabled = $getRuleData['disabled'];
                $originalRuleName=$getRuleData['name'];

                $getZonesFrom = $projectdb->query("SELECT name FROM security_rules_from WHERE rule_lid='$rule_lid';");
                if ($getZonesFrom->num_rows > 0) {
                    while ($getZonesFromData = $getZonesFrom->fetch_assoc()) {
                        $zoneFrom = $getZonesFromData['name'];
                        $addZonesFrom[] = "('$nat_lid','$source','$vsys','$zoneFrom')";
                    }
                }

                $getSources = $projectdb->query("SELECT member_lid, table_name FROM security_rules_src WHERE rule_lid='$rule_lid';");
                if ($getSources->num_rows > 0) {
                    while ($getSourcesData = $getSources->fetch_assoc()) {
                        $table_name = $getSourcesData['table_name'];
                        $member_lid = $getSourcesData['member_lid'];
                        $addSources[] = "('$nat_lid','$source','$vsys','$table_name','$member_lid')";
                    }
                }

                $getZonesTo = $projectdb->query("SELECT name FROM security_rules_to WHERE rule_lid='$rule_lid';");
                if ($getZonesTo->num_rows > 0) {
                    while ($getZonesToData = $getZonesTo->fetch_assoc()) {
                        $zoneTo = $getZonesToData['name'];
                    }
                }

                $getService = $projectdb->query("SELECT member_lid,table_name FROM security_rules_srv WHERE rule_lid='$rule_lid';");
                if ($getService->num_rows == 1) {
                    $getServiceData = $getService->fetch_assoc();
                    $srv_table_name = $getServiceData['table_name'];
                    $srv_member_lid = $getServiceData['member_lid'];
                }
                elseif($getService->num_rows>1) {
                    $name = 'Srv_Group_Rule'.$rule_lid;
                    $originalname = 'Srv_Group_Rule'.$rule_lid;
                    $projectdb->query("INSERT INTO services_groups_id (name,name_ext,source,vsys) values ('$name','$originalname','$source','$vsys');");
                    $srvgrplid = $projectdb->insert_id;

                    while ($service = $getService->fetch_assoc()){
                        $serviceTable = $service['table_name'];
                        $serviceLid   = $service['member_lid'];
                        $projectdb->query("INSERT INTO services_groups (lid,member_lid,table_name,vsys,source) VALUES ('$srvgrplid','$serviceLid','$serviceTable','$vsys','$source')");

                    }
                    $srv_table_name = 'services_groups_id';
                    $srv_member_lid = $srvgrplid;
                }

                $getDestinations = $projectdb->query("SELECT member_lid, table_name FROM security_rules_dst WHERE rule_lid='$rule_lid';");
                if ($getDestinations->num_rows > 0) {
                    while ($getSourcesData = $getDestinations->fetch_assoc()) {
                        $table_name = $getSourcesData['table_name'];
                        $member_lid = $getSourcesData['member_lid'];
                        $addDestination[] = "('$nat_lid','$source','$vsys','$table_name','$member_lid')";
                    }
                }
            }


            $dip_type = $data['dip_type'];
            if ($dip_type == "dip-id") {
                $dip_id = $data['dip'];
                $RuleName = "Nat DIP " . $dip_id . " " . $originalRuleName;

                $getDip = $projectdb->query("SELECT tp_sat_type,unitname,startip,endip FROM netscreen_dip WHERE source='$source' AND vsys='$vsys' AND dip='$dip_id';");
                if ($getDip->num_rows == 1) {
                    $getDipData = $getDip->fetch_assoc();
                    $dip_tp_sat_type = $getDipData['tp_sat_type'];
                    $tp_sat_address_type = "translated-address";
                    $tp_sat_interface = "";
                    $tp_sat_ip_address = "";
                    $startip = $getDipData['startip'];
                    $endip = $getDipData['endip'];

                    if ($endip == $startip) {
                        $getAddress = $projectdb->query("SELECT id FROM address WHERE ipaddress='$startip' AND vsys='$vsys' AND source='$source';");
                        if ($getAddress->num_rows == 1) {
                            $getAddressData = $getAddress->fetch_assoc();
                            $table_name = "address";
                            $member_lid = $getAddressData['id'];
                            $addTranslatedAddress[] = "('$nat_lid','$source','$vsys','$table_name','$member_lid')";
                        }
                        else {
                            $name = "H-" . $startip;
                            $projectdb->query("INSERT INTO address (name_ext,name,ipaddress,cidr,source,vsys,type,used) VALUES ('$name','$name','$startip','32','$source','$vsys','ip-netmask','1')");
                            $member_lid = $projectdb->insert_id;
                            $table_name = "address";
                            $addTranslatedAddress[] = "('$nat_lid','$source','$vsys','$table_name','$member_lid')";
                        }
                    }
                    else {
                        # Its a Range
                        $getAddress = $projectdb->query("SELECT id FROM address WHERE ipaddress='$startip-$endip' AND vsys='$vsys' AND source='$source';");
                        if ($getAddress->num_rows == 1) {
                            $getAddressData = $getAddress->fetch_assoc();
                            $table_name = "address";
                            $member_lid = $getAddressData['id'];
                            $addTranslatedAddress[] = "('$nat_lid','$source','$vsys','$table_name','$member_lid')";
                        }
                        else {
                            $name = "R-" . $startip;
                            $projectdb->query("INSERT INTO address (name_ext,name,ipaddress,cidr,source,vsys,type,used) VALUES ('$name','$name','$startip-$endip','','$source','$vsys','ip-range','1')");
                            $member_lid = $projectdb->insert_id;
                            $table_name = "address";
                            $addTranslatedAddress[] = "('$nat_lid','$source','$vsys','$table_name','$member_lid')";
                        }
                    }
                }
            }
            else {
                #Calculate the Interface Ip address from the ZoneTO
                $RuleName = "Nat interface " . $originalRuleName;
                $dip_tp_sat_type = "dynamic-ip-and-port";
                $tp_sat_address_type = "interface-address";
                if ($zoneTo == "") {
                    $getDest = $projectdb->query("SELECT member_lid,table_name FROM security_rules_dst WHERE rule_lid='$rule_lid' LIMIT 1;");
                    if ($getDest->num_rows == 1) {
                        $getDestData = $getDest->fetch_assoc();
                        $member_lid = $getDestData['member_lid'];
                        $table_name = $getDestData['table_name'];
                        $zoneTo = search_zone_address_one($member_lid, $vsys, $source, $table_name);
                    }
                }
                $getInterface = $projectdb->query("SELECT name,unitname,unitipaddress FROM interfaces WHERE zone='$zoneTo' and unitipaddress!='' AND template='$template' LIMIT 1;");
                if ($getInterface->num_rows == 1) {
                    $getInterfaceData = $getInterface->fetch_assoc();
                    $tp_sat_interface = $getInterfaceData['unitname'];
                    $tp_sat_ip_address = $getInterfaceData['unitipaddress'];
                } else {
                    $tp_sat_interface = "";
                    $tp_sat_ip_address = "";
                }
            }

            if(count($natdst_content) > 0){
                //Checking is this NAT rule had complementary information in the NAT object array
                if(isset($natdst_content[$rule_lid])){
                    $natObject =  $natdst_content[$rule_lid];
                    $tp_dat_port = $natObject->natdst_port;
                    if(!isset($tp_dat_port)) $tp_dat_port='';
                    $tp_dat_address_lid = $natObject->natdst_address_lid;
                    $tp_dat_address_table = $natObject->natdst_address_table;

                    $addNatRule[] = "('$nat_lid','$RuleName','$position','$disabled','$vsys','$source','$zoneTo','$srv_member_lid','$srv_table_name','$dip_tp_sat_type','$tp_sat_address_type','$tp_sat_interface','$tp_sat_ip_address','1','$tp_dat_port','$tp_dat_address_lid','$tp_dat_address_table')";
                }
                else{
                    //This rule did not have Source & Destination NAT. Therefore, it was not into the Associative Array. Instead, it used the "netscreen_dip_mapping" table, and the srv information was collected there.
                    $addNatRule[] = "('$nat_lid','$RuleName','$position','$disabled','$vsys','$source','$zoneTo','$srv_member_lid','$srv_table_name','$dip_tp_sat_type','$tp_sat_address_type','$tp_sat_interface','$tp_sat_ip_address','0','','','')";
                }
            }
            else{
                $addNatRule[] = "('$nat_lid','$RuleName','$position','$disabled','$vsys','$source','$zoneTo','$srv_member_lid','$srv_table_name','$dip_tp_sat_type','$tp_sat_address_type','$tp_sat_interface','$tp_sat_ip_address','0','','','')";
            }
            $nat_lid++;
            $position++;
        }
    }

    if (count($addNatRule) > 0) {
        $projectdb->query("INSERT INTO nat_rules (id,name,position,disabled,vsys,source,op_zone_to,op_service_lid,op_service_table,tp_sat_type,tp_sat_address_type,tp_sat_interface,tp_sat_ipaddress,is_dat,tp_dat_port,tp_dat_address_lid,tp_dat_address_table) "
            . "VALUES " . implode(",", $addNatRule) . ";");
        unset($addNatRule);
        if (count($addZonesFrom) > 0) {
            $projectdb->query("INSERT INTO nat_rules_from (rule_lid,source,vsys,name) VALUES " . implode(",", $addZonesFrom) . ";");
            unset($addZonesFrom);
        }
        if (count($addSources) > 0) {
            $projectdb->query("INSERT INTO nat_rules_src (rule_lid,source,vsys,table_name,member_lid) VALUES " . implode(",", $addSources) . ";");
            unset($addSources);
        }
        if (count($addDestination) > 0) {
            $projectdb->query("INSERT INTO nat_rules_dst (rule_lid,source,vsys,table_name,member_lid) VALUES " . implode(",", $addDestination) . ";");
            unset($addDestination);
        }
        if (count($addTranslatedAddress) > 0) {
            $projectdb->query("INSERT INTO nat_rules_translated_address (rule_lid,source,vsys,table_name,member_lid) VALUES " . implode(",", $addTranslatedAddress) . ";");
            unset($addTranslatedAddress);
        }
    }
}

function generate_natdst($source, $vsys) {
    global $projectdb;
    $nat_lid = "";
    $addNatRule = array();
    $addZonesFrom = array();
    $addSources = array();
    $addDestination = array();
    $getNatDst = $projectdb->query("SELECT rule_lid,ipaddress,port FROM netscreen_natdst WHERE source='$source' AND vsys='$vsys'");
    if ($getNatDst->num_rows > 0) {
        $getPosition = $projectdb->query("SELECT max(position) as t FROM nat_rules WHERE vsys='$vsys' AND source='$source';");
        if ($getPosition->num_rows == 0) {
            $position = 0;
        } else {
            $ddata = $getPosition->fetch_assoc();
            $position = intval($ddata['t']) + 1;
        }
        if ($nat_lid == "") {
            $getlastlid = $projectdb->query("SELECT max(id) as max FROM nat_rules;");
            $getLID1 = $getlastlid->fetch_assoc();
            $nat_lid = intval($getLID1['max']) + 1;
        }
        while ($data = $getNatDst->fetch_assoc()) {
            $rule_lid = $data['rule_lid'];
            $ipaddress = $data['ipaddress'];
            $port = $data['port'];

            $getRule = $projectdb->query("SELECT disabled,name FROM security_rules WHERE id='$rule_lid';");
            if ($getRule->num_rows == 1) {
                $getRuleData = $getRule->fetch_assoc();
                $disabled = $getRuleData['disabled'];
                $originalRuleName=$getRuleData['name'];
                $RuleName = "Nat DST " . $originalRuleName;

                $getZonesFrom = $projectdb->query("SELECT name FROM security_rules_from WHERE rule_lid='$rule_lid';");
                if ($getZonesFrom->num_rows > 0) {
                    while ($getZonesFromData = $getZonesFrom->fetch_assoc()) {
                        $zoneFrom = $getZonesFromData['name'];
                        $addZonesFrom[] = "('$nat_lid','$source','$vsys','$zoneFrom')";
                    }
                }

                $getSources = $projectdb->query("SELECT member_lid, table_name FROM security_rules_src WHERE rule_lid='$rule_lid';");
                if ($getSources->num_rows > 0) {
                    while ($getSourcesData = $getSources->fetch_assoc()) {
                        $table_name = $getSourcesData['table_name'];
                        $member_lid = $getSourcesData['member_lid'];
                        $addSources[] = "('$nat_lid','$source','$vsys','$table_name','$member_lid')";
                    }
                }

                $getZonesTo = $projectdb->query("SELECT name FROM security_rules_to WHERE rule_lid='$rule_lid';");
                if ($getZonesTo->num_rows > 0) {
                    while ($getZonesToData = $getZonesTo->fetch_assoc()) {
                        $zoneTo = $getZonesToData['name'];
                    }
                } else {
                    $getDest = $projectdb->query("SELECT member_lid,table_name FROM security_rules_dst WHERE rule_lid='$rule_lid' LIMIT 1;");
                    if ($getDest->num_rows == 1) {
                        $getDestData = $getDest->fetch_assoc();
                        $member_lid = $getDestData['member_lid'];
                        $table_name = $getDestData['table_name'];
                        $zoneTo = search_zone_address_one($member_lid, $vsys, $source, $table_name);
                    }
                }

                $getService = $projectdb->query("SELECT member_lid,table_name FROM security_rules_srv WHERE rule_lid='$rule_lid';");
                if ($getService->num_rows == 1) {
                    $getServiceData = $getService->fetch_assoc();
                    $srv_table_name = $getServiceData['table_name'];
                    $srv_member_lid = $getServiceData['member_lid'];
                }
                elseif($getService->num_rows>1) {
                    $name = 'Srv_Group_Rule'.$rule_lid;
                    $originalname = 'Srv_Group_Rule'.$rule_lid;
                    $projectdb->query("INSERT INTO services_groups_id (name,name_ext,source,vsys) values ('$name','$originalname','$source','$vsys');");
                    $srvgrplid = $projectdb->insert_id;

                    while ($service = $getService->fetch_assoc()){
                        $serviceTable = $service['table_name'];
                        $serviceLid   = $service['member_lid'];
                        $projectdb->query("INSERT INTO services_groups (lid,member_lid,table_name,vsys,source) VALUES ('$srvgrplid','$serviceLid','$serviceTable','$vsys','$source')");

                    }
                    $srv_table_name = 'services_groups_id';
                    $srv_member_lid = $srvgrplid;
                }


                $getDestinations = $projectdb->query("SELECT member_lid, table_name FROM security_rules_dst WHERE rule_lid='$rule_lid';");
                if ($getDestinations->num_rows > 0) {
                    while ($getSourcesData = $getDestinations->fetch_assoc()) {
                        $table_name = $getSourcesData['table_name'];
                        $member_lid = $getSourcesData['member_lid'];
                        $addDestination[] = "('$nat_lid','$source','$vsys','$table_name','$member_lid')";
                    }
                }
            }

            $splitaddress = explode("-", $ipaddress);
            $startip = $splitaddress[0];
            if (isset($splitaddress[1])) {
                $endip = $splitaddress[1];
            } else {
                $endip = $splitaddress[0];
            }


            if ($endip == $startip) {
                $getAddress = $projectdb->query("SELECT id FROM address WHERE ipaddress='$startip' AND vsys='$vsys' AND source='$source';");
                if ($getAddress->num_rows == 1) {
                    $getAddressData = $getAddress->fetch_assoc();
                    $table_name = "address";
                    $member_lid = $getAddressData['id'];
                } else {
                    $name = "H-" . $startip;
                    $projectdb->query("INSERT INTO address (name_ext,name,ipaddress,cidr,source,vsys,type,used) VALUES ('$name','$name','$startip','32','$source','$vsys','ip-netmask','1')");
                    $member_lid = $projectdb->insert_id;
                    $table_name = "address";
                }
            } else {
                # Its a Range
                $getAddress = $projectdb->query("SELECT id FROM address WHERE ipaddress='$startip-$endip' AND vsys='$vsys' AND source='$source';");
                if ($getAddress->num_rows == 1) {
                    $getAddressData = $getAddress->fetch_assoc();
                    $table_name = "address";
                    $member_lid = $getAddressData['id'];
                } else {
                    $name = "R-" . $startip;
                    $projectdb->query("INSERT INTO address (name_ext,name,ipaddress,cidr,source,vsys,type,used) VALUES ('$name','$name','$startip-$endip','','$source','$vsys','ip-range','1')");
                    $member_lid = $projectdb->insert_id;
                    $table_name = "address";
                }
            }

            if ($port == 0) {
                $port = "";
            }

            $addNatRule[] = "('$nat_lid','$RuleName','$position','$disabled','$vsys','$source','$zoneTo','$srv_member_lid','$srv_table_name','1','$port','$member_lid','$table_name')";
            $nat_lid++;
            $position++;
        }
    }
    if (count($addNatRule) > 0) {
        $projectdb->query("INSERT INTO nat_rules (id,name,position,disabled,vsys,source,op_zone_to,op_service_lid,op_service_table,is_dat,tp_dat_port,tp_dat_address_lid,tp_dat_address_table) "
            . "VALUES " . implode(",", $addNatRule) . ";");
        unset($addNatRule);
        if (count($addZonesFrom) > 0) {
            $projectdb->query("INSERT INTO nat_rules_from (rule_lid,source,vsys,name) VALUES " . implode(",", $addZonesFrom) . ";");
            unset($addZonesFrom);
        }
        if (count($addSources) > 0) {
            $projectdb->query("INSERT INTO nat_rules_src (rule_lid,source,vsys,table_name,member_lid) VALUES " . implode(",", $addSources) . ";");
            unset($addSources);
        }
        if (count($addDestination) > 0) {
            $projectdb->query("INSERT INTO nat_rules_dst (rule_lid,source,vsys,table_name,member_lid) VALUES " . implode(",", $addDestination) . ";");
            unset($addDestination);
        }
    }
}

# OLD Functions

function get_services_old($screenos_config_file, $source, $vsys, $ismultiornot) {
    global $projectdb;

    $getlastlid = $projectdb->query("SELECT max(id) as max FROM services;");
    $getLID1 = $getlastlid->fetch_assoc();
    $lid = intval($getLID1['max']) + 1;

    $serviceArray=array();

    if ($ismultiornot == "singlevsys") {
        $START = TRUE;
    } else {
        $START = FALSE;
    }
    if ($vsys == "root") {
        $START = TRUE;
    }
    foreach ($screenos_config_file as $line => $names_line) {

        if ($START == FALSE) {
            if (preg_match("/^set vsys \"$vsys\"/i", $names_line)) {
                $START = TRUE;
            }
        } else {
            if (preg_match("/^set vsys /i", $names_line)) {
                $START = FALSE;
            }
        }

        if ($START) {
            if (preg_match("/^set service /i", $names_line)) {
                $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                if (isset($data[3])) {
                    if (($data[3] == "protocol") OR ( $data[3] == "+")) {
                        if (($data[4] == "tcp") or ( $data[4] == "udp")) {
                            #set service "sql" protocol tcp src-port 0-65535 dst-port 1433-1433
                            $dport = $data[8];
                            $sport = $data[6];
                            $protocol = $data[4];
                            $dportsplit = explode("-", $dport);
                            if ($dportsplit[0] == $dportsplit[1]) {
                                $dport = $dportsplit[0];
                            }
                            $sportsplit = explode("-", $sport);
                            if ($sportsplit[0] == $sportsplit[1]) {
                                $sport = $sportsplit[0];
                            }
                            $name_ext = $data[2];
                            $name_int = truncate_names(normalizeNames($name_ext));

                            if (isset($data[9])){
                                if ($data[9]=="timeout"){
                                    $timeout=$data[10] * 60;
                                    $override_tmout="yes";
                                    add_log2('warning', 'Reading Services Objects and Groups', 'The Service [' . $name_ext . '] has a custom Time-Out [' . $timeout . ']', $source, 'If you are migrating to PanOS 8.1 it will be applied if not you will have to AppOverride it.', 'objects', $lid, 'services');
                                }
                            }
                            else{
                                $timeout="";
                                $override_tmout="";
                            }

                            if (($sport=="1-65535") OR ($sport=="0-65535")){
                                $sport="";
                            }

                            $getDup = $projectdb->query("SELECT id,dport,sport,protocol FROM services WHERE source='$source' AND BINARY name_ext='$name_ext' AND vsys='$vsys' AND protocol='$protocol';");
                            if ($getDup->num_rows == 0) {
                                $serviceArray[]="('$lid','$name_int','','$name_ext','0','$source','0','$dport','$sport','$protocol','$vsys','$timeout','$override_tmout')";
                                $lid++;
                            }
                            else {
                                #EXISTS UPDATE IT
                                $myservice = $getDup->fetch_assoc();
                                $oldlid = $myservice['id'];
                                $olddport = $myservice['dport'];
                                $oldsport = $myservice['sport'];
                                $oldprotocol = $myservice['protocol'];
                                $newsport = $oldsport . "," . $sport;
                                $newdport = $olddport . "," . $dport;

                                if (preg_match("/$dport/i", $olddport)) {
                                    $adddport = ", dport='$olddport'";
                                } else {
                                    $adddport = ", dport='$newdport'";
                                }


                                if (preg_match("/$sport/i", $oldsport)) {
                                    $addsport = "sport='$oldsport'";
                                } else {
                                    $addsport = "sport='$newsport'";
                                }


                                $projectdb->query("UPDATE services SET $addsport $adddport WHERE source='$source' AND id='$oldlid' AND vsys='$vsys'");
                            }
                        }
                        else {
                            $name_ext = $data[2];
                            $name_int = truncate_names(normalizeNames($name_ext));
                            $protocol = $data[4];
                            $getDup = $projectdb->query("SELECT id,dport,sport,protocol FROM services WHERE source='$source' AND BINARY name_ext='$name_ext' AND protocol='$protocol' AND vsys='$vsys';");
                            if ($getDup->num_rows == 0) {
                                $serviceArray[]="('$lid','$name_int','','$name_ext','1','$source','0','','','$protocol','$vsys','','')";
                                $lid++;
                                add_log2('error', 'Reading Services Objects and Groups', 'The Service [' . $name_ext . '] has a Protocol is not TCP or UDP [' . $protocol . ']', $source, 'Assign the right Port/Protocol or Change by App-id in Rule', 'objects', $lid, 'services');
                            }
                        }
                    }
                }
            }
        }
    }
    if (count($serviceArray)>0){
        $projectdb->query("INSERT INTO services (id,name,type,name_ext,checkit,source,used,dport,sport,protocol,vsys,timeout,override) values ".implode(",",$serviceArray).";");
        unset($serviceArray);
    }
}
function get_address_groups_old($screenos_config_file, $source, $vsys, $ismultiornot) {
    global $projectdb;
    $lid = 0;
    $oldname = "";
    $add_member = array();
    if ($ismultiornot == "singlevsys") {
        $START = TRUE;
    } else {
        $START = FALSE;
    }
    if ($vsys == "root") {
        $START = TRUE;
    }
    foreach ($screenos_config_file as $line => $names_line) {

        if ($START == FALSE) {
            if (preg_match("/^set vsys \"$vsys\"/i", $names_line)) {
                $START = TRUE;
            }
        } else {
            if (preg_match("/^set vsys /i", $names_line)) {
                $START = FALSE;
            }
        }

        if ($START) {
            $comment = "";
            #set group address "Trust" "eurohub-ssl-users" add "eurohub-net-ssluser"
            if (preg_match("/^set group address /i", $names_line)) {
                $data = preg_split("/[\s ]*\\\"([^\\\"]+)\\\"[\s,]*|[\s,]+/", $names_line, 0, PREG_SPLIT_NO_EMPTY | PREG_SPLIT_DELIM_CAPTURE);
                if (isset($data[5])) {
                    if ($data[5] == "comment"){
                        $comment=addslashes($data[6]);
                    }
                    if ($data[5] == "add") {
                        $name_ext = $data[4];
                        $zone = $data[3];
                        $name_int = truncate_names(normalizeNames($name_ext));
                        if ($oldname != $name_ext) {
                            $getDup = $projectdb->query("SELECT id FROM address_groups_id WHERE source='$source' AND name_ext='$name_ext' AND vsys='$vsys' AND zone='$zone';");
                            if ($getDup->num_rows == 0) {
                                $projectdb->query("INSERT INTO address_groups_id (name,name_ext,source,vsys,zone,description) values ('$name_int','$name_ext','$source','$vsys','$zone','$comment');");
                                $lid = $projectdb->insert_id;
                            } else {
                                $getlid = $getDup->fetch_assoc();
                                $lid = $getlid['id'];
                                #print "Objeto Duplicado ".$names_line;
                            }
                        }
                        $member = $data[6];
                        $getDup = $projectdb->query("SELECT id FROM address_groups WHERE member='$member' AND lid='$lid';");
                        if ($getDup->num_rows == 0) {
                            $getAddr = $projectdb->query("SELECT id FROM address WHERE name_ext='$member' AND zone='$zone' AND source='$source' AND vsys='$vsys';");
                            if ($getAddr->num_rows == 1) {
                                $getAddrData = $getAddr->fetch_assoc();
                                $member_lid = $getAddrData['id'];
                                $table_name = "address";
                                $add_member[] = "('$lid','$member','$source','$vsys','$member_lid','$table_name')";
                            } else {
                                $getAddrg = $projectdb->query("SELECT id FROM address_groups_id WHERE name_ext='$member' AND zone='$zone' AND source='$source' AND vsys='$vsys'");
                                if ($getAddrg->num_rows == 1) {
                                    $getAddrgData = $getAddrg->fetch_assoc();
                                    $member_lid = $getAddrgData['id'];
                                    $table_name = "address_groups_id";
                                    $add_member[] = "('$lid','$member','$source','$vsys','$member_lid','$table_name')";
                                } else {
                                    #print $names_line;
                                }
                            }

                            $oldname = $name_ext;
                        }
                        $comment="";
                    }
                }
            }
        }
    }
    if (count($add_member) > 0) {
        $projectdb->query("INSERT INTO address_groups (lid,member,source,vsys,member_lid,table_name) VALUES " . implode(",", $add_member) . ";");
        unset($add_member);
    }
}