<?php

# Copyright (c) 2015 Palo Alto Networks, Inc.
# All rights reserved.
#HEADER
$debug=FALSE;

//Global Variables used for Policy Construction
//Global Variables used for Policy Construction
$rule=[];			//List of policy rules
$sources=[];		//List of sources used in general
$destinations=[];	//List of destinations used in general
$services=[];		//List of services used in general
$addTag=[];		//List of tags used in general
$tagids=[];   		//Set of tags used for a specific policy
$lid=null;			//ID of the last registered policy rule. Used for rule table relations
$position=null;		//Position of the last registered policy rule. Used to place the rules in order in the final policy

global $vrid;
//$vrid;

global $match_expressionsInMemory;
global $overrideSecurityZones;
$overrideSecurityZones = array();

global $overrideNatZones;
$overrideNatZones = array();

global $like_panorama;
global $devicegroup;
global $configFilenamePolicy;
global $is_first;
$is_first=true;

global $processed_policies;
$processed_policies = [];

global $processed_firewall_interfaces;
$processed_firewall_interfaces = [];

global $processed_firewall_staticRoutes;
$processed_firewall_staticRoutes= [];

global $shared_dg_name;

global $invalid_tag_id;
global $alias_id;
global $alias_tag_id;
global $expression_tag_id;



//Loads all global PHP definitions
//require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
require_once '/var/www/html/libs/common/definitions.php';

//User management control
//require_once INC_ROOT.'/userManager/start.php';
//include INC_ROOT.'/bin/authentication/sessionControl.php';

//Dependencies
require_once INC_ROOT.'/libs/database.php';
require_once INC_ROOT.'/libs/shared.php';
require_once INC_ROOT.'/libs/xmlapi.php';

require_once INC_ROOT.'/libs/common/MemberObject.php';
require_once INC_ROOT.'/libs/common/lib-rules.php';
require_once INC_ROOT.'/libs/objects/SecurityRulePANObject.php';

require_once INC_ROOT.'/libs/objects/tools/expressions/Expression.php';

require_once INC_ROOT.'/bin/configurations/parsers/ServicesMapping.php';
use PaloaltoNetworks\Parsers\Utils\ServicesMapping;

use PaloaltoNetworks\Policy\Objects\MemberObject;

require_once INC_ROOT.'/userManager/API/accessControl_CLI.php';
global $app;

$action = $project = $type = $signatureid = "";

//Capture request paramenters
include INC_ROOT.'/bin/configurations/parsers/readVars.php';

// Validations
if(!accessControl("any", ['project.admin', 'projectRole.'.$project.'.admin'])){
    http_response_code(401);
    header("HTTP/1.1 401 Unauthorized");
    header("Location: /401");
    exit;
}

if(isset($signatureid))
    $signatureid = str_replace(';',',',$signatureid);  //The IDs of policies to load came in ; separated, as readVars expected parameters separated by commas

if(isset($asPanorama)){
    $like_panorama = (int)$asPanorama;
}


class FwInterface {
    public $name;
    public $address;

    public $media;
    public $interfaceName;
    public $interfaceType;
    public $comment;
    public $unitName;
    public $vlan_tag;
    public $ipaddresses;
    public $zone;

    function __construct() 
    {   
        $a = func_get_args();
        $i = func_num_args();
        if (method_exists($this,$f='myConstruct'.$i)) {
            call_user_func_array(array($this,$f),$a);
        }
    }
    
    public function myConstruct2($name, $address)
    {
        $this->name = $name;
        $this->address = $address;
        $this->ipaddresses = array();
    }

    public function myConstruct7($media, $interfaceName, $interfaceType, $comment, $unitName, $vlan_tag, $ipaddresses){
        $this->media = $media;
        $this->interfaceName = $interfaceName;
        $this->interfaceType = $interfaceType;
        $this->comment = $comment;
        $this->unitName = $unitName;
        $this->vlan_tag = $vlan_tag;
        $this->ipaddresses = array();
        if(isset($ipaddresses) && strcmp($ipaddresses, "")!=0){  
            foreach ($ipaddresses as $ip){
                $this->ipaddresses[] = $ip;
            }
        }
    }

    public function setZone($zone){
        $this->zone = $zone;
    }

    public function addIPaddress($ipaddress){
        if(!in_array($ipaddress, $this->ipaddresses))
            $this->ipaddresses[]=$ipaddress;
    }
        
}



//Capture request paramenters in case we get a call from the browser
if(isset($_SERVER['REQUEST_METHOD'])) {
    switch ($_SERVER['REQUEST_METHOD']) {
        case 'GET':
            $action = (string)(isset($_GET['action']) ? $_GET['action'] : '');
            $type = (string)(isset($_GET['type']) ? $_GET['type'] : ''); // zip / xml / device
            $project = (string)(isset($_GET['project']) ? $_GET['project'] : '');
            $signatureid = (string)(isset($_GET['signatureid']) ? $_GET['signatureid'] : '');
            break;
        case 'POST':
            $action = (string)(isset($_POST['action']) ? $_POST['action'] : '');
            $type = (string)(isset($_POST['type']) ? $_POST['type'] : ''); // zip / xml / device
            $project = (string)(isset($_POST['project']) ? $_POST['project'] : '');
            $signatureid = (string)(isset($_POST['signatureid']) ? $_POST['signatureid'] : '');
            break;

        default:
            $action = (string)(isset($_POST['action']) ? $_POST['action'] : '');
            $type = (string)(isset($_POST['type']) ? $_POST['type'] : ''); // zip / xml / device
            $project = (string)(isset($_POST['project']) ? $_POST['project'] : '');
            $signatureid = (string)(isset($_POST['signatureid']) ? $_POST['signatureid'] : '');
            break;
    }
}


require_once INC_ROOT.'/libs/projectdb.php';

//list($project, $vendor, $action, $signatureid, $username, $password, $afa_hostname, $jobid, $checkpointName) = loadVars( $argv[1]);
global $projectdb;
renewDBConnection();

$action = $projectdb->real_escape_string($action);
$type = $projectdb->real_escape_string($type);
$project = $projectdb->real_escape_string($project);
$signatureid = $projectdb->real_escape_string($signatureid);

//---------------------------------------------
//        Parser Logic starts here
//----------------------------------------------

function time_elapsed_A($secs){
    $bit = array(
        'y' => $secs / 31556926 % 12,
        'w' => $secs / 604800 % 52,
        'd' => $secs / 86400 % 7,
        'h' => $secs / 3600 % 24,
        'm' => $secs / 60 % 60,
        's' => $secs % 60
    );

    foreach($bit as $k => $v)
        if($v > 0)$ret[] = $v . $k;

    return implode(' ', $ret);
}

function GroupMember2IDStonesoft(string $type, int $source,&$objectsInMemory){
    global $projectdb;
    global $invalid_tag_id;
//    $unresolvedAddresses_usedIn=array();
    $unresolved_object_names=array();
    $resolved_address_subquery=array();
    switch($type) {
        case "address":
            #Group Address Groups with Members
            $getVsys = $projectdb->query("SELECT vsys FROM address_groups_id WHERE source='$source' AND type='static' GROUP BY vsys");
            if ($getVsys->num_rows > 0) {
                # Objects need to be added
                $max = getLastId("address"); //Default position for a new object

                while ($getVsysData = $getVsys->fetch_assoc()) {
                    $current_vsys = $getVsysData['vsys'];
                    $getGroups = $projectdb->query("SELECT id FROM address_groups_id WHERE source='$source' AND vsys='$current_vsys' AND type='static';");
                    if ($getGroups->num_rows > 0) {
                        $address_groups_ids = array();
                        while ($getGroupData = $getGroups->fetch_assoc()) {
                            $address_groups_ids[] = $getGroupData['id'];
                        }
                        $vsyses = getVsyses($projectdb, $current_vsys, $source);

                        //Getting all the references to members of groups that do not resolve to a table_name and member_lid
                        $getUnresolvedAddresses = $projectdb->query("SELECT member, lid from address_groups WHERE lid IN (" . implode(",", $address_groups_ids) . ") AND member_lid=0;");
                        if ($getUnresolvedAddresses->num_rows > 0) {
                            $unresolvedAddresses_usedIn = array();
                            while ($getUnresolvedAddrData = $getUnresolvedAddresses->fetch_assoc()) {
                                $memberName = $getUnresolvedAddrData['member'];
                                $lid = $getUnresolvedAddrData['lid'];
                                $unresolvedAddresses_usedIn[$memberName][] = $lid;
                                $unresolved_object_names[] = $memberName;
                            }

                            $unresolved_object_names=array_unique($unresolved_object_names);

                            //Search for the objects location until there are no more $vsyses to check or objects to resolve
                            while (count($vsyses) > 0 && count($unresolved_object_names) > 0) {
                                $vsys = array_shift($vsyses);
                                $resolved_addresses = array();
                                foreach ($unresolved_object_names as $unresolved_object_name) {
                                    if (isset($objectsInMemory['address'][$vsys][$unresolved_object_name])){
                                        $resolved_addresses[] = $unresolved_object_name;
                                        foreach ($unresolvedAddresses_usedIn[$unresolved_object_name] as $group_id) {
                                            $resolved_address_subquery[] = "('$group_id','" . $objectsInMemory['address'][$vsys][$unresolved_object_name]['id'] . "','address')";
                                        }
                                    }
                                    elseif (isset($objectsInMemory['address_groups_id'][$vsys][$unresolved_object_name])) {
                                        $resolved_addresses[] = $unresolved_object_name;
                                        foreach ($unresolvedAddresses_usedIn[$unresolved_object_name] as $group_id) {
                                            $resolved_address_subquery[] = "('$group_id','" . $objectsInMemory['address_groups_id'][$vsys][$unresolved_object_name]['id'] . "','address_groups_id')";
                                        }
                                    }
                                }
                                $unresolved_object_names = array_diff($unresolved_object_names, $resolved_addresses);
                            }

                            $unresolved_object_names = array_filter($unresolved_object_names);
                            if (empty($unresolved_object_names)) {
                                $projectdb->query("DELETE FROM address_groups WHERE lid IN (" . implode(",", $address_groups_ids) . ") AND member_lid=0;");
                            }
                            else {
                                # Check by name_ext
                                print "ERROR SOME ADDRESS OBJECTS HAVE NOT BEEN CAPTURED when processing DG '$current_vsys'" . PHP_EOL;
                                print_r($unresolved_object_names);
                                # Objects doesnt exist and need to be added
                                $addHost = array();
                                foreach ($unresolved_object_names as $key => $member_name) {
                                    if ($member_name !== "") {
                                        $member_name = (string)$member_name;
                                        $ip_version0 = ip_version($member_name);
                                        if (($ip_version0 !== "noip") || (preg_match("/\//", $member_name))) {
                                            $member_A_Network = explode("/", $member_name);
                                            $ip_version = ip_version($member_A_Network[0]);
                                            if (!isset($member_A_Network[1])) {
                                                if ($ip_version === "v4") {
                                                    $member_A_mask = "32";
                                                } else {
                                                    $member_A_mask = "128";
                                                }
                                            }
                                            else {
                                                $member_A_mask = $member_A_Network[1];
                                            }
                                            if ($ip_version === "v4") {
                                                $addHost[] = "('$max','ip-netmask','$member_name','$member_name','0','$source','0','ip-netmask','$current_vsys',1,'MT_Panorama','$member_A_Network[0]','$member_A_mask',1,0)";
                                            } elseif ($ip_version === "v6") {
                                                $addHost[] = "('$max','ip-netmask','$member_name','$member_name','0','$source','0','ip-netmask','$current_vsys',1,'MT_Panorama','$member_A_Network[0]','$member_A_mask',0,1)";
                                            }
                                            foreach ($unresolvedAddresses_usedIn[$member_name] as $glid) {
                                                $resolved_address_subquery[] = "('$glid','$max','address')";
                                            }
                                            $objectsInMemory['address'][$current_vsys][$member_name]['id'] = $max;
                                            $objectsInMemory['address'][$current_vsys][$member_name]['ipaddress'] = $member_A_Network[0];
                                            $objectsInMemory['address'][$current_vsys][$member_name]['cidr'] = $member_A_mask;
                                            $max++;
                                        }
                                        else {
                                            $split = explode("-", $member_name);
                                            if ((ip_version($split[0]) !== "noip") && (ip_version($split[1]) !== "noip")) {
                                                $ip_version = ip_version($split[0]);
                                                if ($ip_version === "v4") {
                                                    $addHost[] = "('$max','ip-range','$member_name','$member_name','1','$source','0','Generated by Expedition','$current_vsys',0,'MT_Panorama','$member_name','',1,0)";
                                                } elseif ($ip_version === "v6") {
                                                    $addHost[] = "('$max','ip-range','$member_name','$member_name','1','$source','0','Generated by Expedition','$current_vsys',0,'MT_Panorama','$member_name','',0,1)";
                                                }
                                                foreach ($unresolvedAddresses_usedIn[$member_name] as $glid) {
                                                    $resolved_address_subquery[] = "('$glid','$max','address')";
                                                }
                                                $objectsInMemory['address'][$current_vsys][$member_name]['id'] = $max;
                                                $max++;
                                            } else {
                                                $ip_version="noip";
                                                preg_match('/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})_(\d+)/', $member_name, $matches);
                                                if(isset($matches[1])){
                                                    $ipAddress = $matches[1];
                                                    $subnetMask="";
                                                    if(isset($matches[2])) {
                                                        $subnetMask = $matches[2];
                                                    }
                                                    $ip_version = ip_version($ipAddress);
                                                }

                                                if($ip_version!="noip"){
                                                    $addHost[] = "('$max','ip-netmask','$member_name','$member_name','1','$source','0','ip-netmask','$current_vsys',0,'MT','$ipAddress','$subnetMask',1,0)";
                                                    foreach ($unresolvedAddresses_usedIn[$member_name] as $glid) {
                                                        $resolved_address_subquery[] = "('$glid','$max','address')";
                                                    }
                                                    add_log2('error', 'Address Object', 'The Address [' . $member_name . '] is not declared on the policy but it is used. Expedition created it.', $source, 'Check that the created object is correct', 'objects', $max, 'address');

                                                    $objectsInMemory['address'][$current_vsys][$member_name]['id'] = $max;
                                                    $objectsInMemory['address'][$current_vsys][$member_name]['ipaddress'] = $ipAddress;
                                                    $objectsInMemory['address'][$current_vsys][$member_name]['cidr'] = $subnetMask;
                                                    $max++;

                                                }else{

                                                    $addHost[] = "('$max','ip-netmask','$member_name','$member_name','1','$source','0','Generated by Expedition','$current_vsys',0,'MT_Panorama','','',1,0)";
                                                    foreach ($unresolvedAddresses_usedIn[$member_name] as $glid) {
                                                        $resolved_address_subquery[] = "('$glid','$max','address')";
                                                    }
                                                    $objectsInMemory['address'][$current_vsys][$member_name]['id'] = $max;
                                                    $objectsInMemory['address'][$current_vsys][$member_name]['ipaddress'] = '';
                                                    $objectsInMemory['address'][$current_vsys][$member_name]['cidr'] = '';
                                                    $max++;
                                                }
                                            }
                                        }
                                    }
                                }
                                $projectdb->query("DELETE FROM address_groups WHERE lid IN (" . implode(",", $address_groups_ids) . ") AND member_lid=0;");
                                if (count($addHost) > 0) {
                                    $projectdb->query("INSERT INTO address (id,type,name_ext,name,checkit,source,used,vtype,vsys,dummy,devicegroup,ipaddress,cidr,v4,v6) VALUES " . implode(",", $addHost) . ";");
                                    unset($addHost);
                                }

                            }
                            $unresolved_object_names = array();
                        }

                    }
                }
            }

            # Let's do inserts by vsys/dg
            if (count($resolved_address_subquery) > 0) {
                $unique = array_unique($resolved_address_subquery);
                $projectdb->query("INSERT INTO address_groups (lid,member_lid,table_name) VALUES " . implode(",", $unique) . ";");
                unset($resolved_address_subquery);
            }

            break;

        case "service":
            #Group Services Groups with Members
            $getVsys = $projectdb->query("SELECT vsys FROM services_groups_id WHERE source='$source' GROUP BY vsys");
            if ($getVsys->num_rows > 0) {
                $resolved_address_subquery = array();

                # Objects needs to be added
                $max = 1; //Default position for a new object
                $getMaxID = $projectdb->query("SELECT max(id) as max FROM services;");
                if ($getMaxID->num_rows === 1) {
                    $max1 = $getMaxID->fetch_assoc();
                    $max = $max1['max'];
                    $max++;
                }

                while ($getVsysData = $getVsys->fetch_assoc()) {
                    $current_vsys = $getVsysData['vsys'];
                    $getGroups = $projectdb->query("SELECT id FROM services_groups_id WHERE source='$source' AND vsys='$current_vsys';");
                    if ($getGroups->num_rows > 0) {
                        $service_groups_ids = array();
                        while ($getGroupData = $getGroups->fetch_assoc()) {
                            $service_groups_ids[] = $getGroupData['id'];
                        }
                        $vsyses = getVsyses($projectdb, $current_vsys, $source);
                        $getUnresolvedAddresses = $projectdb->query("SELECT * from services_groups WHERE lid IN (" . implode(",", $service_groups_ids) . ");");
                        $unresolved_object_names = [];
                        if ($getUnresolvedAddresses->num_rows > 0) {
                            $unresolvedAddresses_usedIn = array();
                            while ($getUnresolvedAddrData = $getUnresolvedAddresses->fetch_assoc()) {
                                if($getUnresolvedAddrData['member_lid'] == 0) {
                                    $memberName = $getUnresolvedAddrData['member'];
                                    $lid = $getUnresolvedAddrData['lid'];
                                    $unresolvedAddresses_usedIn[$memberName][] = $lid;
                                    $unresolved_object_names[] = $memberName;
                                }
                            }

                            $unresolved_object_names=array_unique($unresolved_object_names);

                            while (count($vsyses) > 0 && count($unresolved_object_names) > 0) { //Search for the objects location until there are no more $vsyses to check or objects to resolve
                                $vsys = array_shift($vsyses); //Remove the first element of the Array of vsyses

                                if (count($unresolved_object_names) > 0) {
                                    $services_array = array();
                                    foreach ($unresolved_object_names as $nameToCheck) {
                                        if (isset($objectsInMemory['services'][$vsys][$nameToCheck])) {
                                            $services_array[] = $nameToCheck;
                                            foreach ($unresolvedAddresses_usedIn[$nameToCheck] as $glid) {
                                                $resolved_service_subquery[] = "('$glid','" . $objectsInMemory['services'][$vsys][$nameToCheck]['id'] . "','services')";
                                            }
                                        }
                                        elseif (isset($objectsInMemory['services_groups_id'][$vsys][$nameToCheck])) {
                                            $services_array[] = $nameToCheck;
                                            foreach ($unresolvedAddresses_usedIn[$nameToCheck] as $glid) {
                                                $resolved_service_subquery[] = "('$glid','" . $objectsInMemory['services_groups_id'][$vsys][$nameToCheck]['id'] . "','services_groups_id')";
                                            }
                                        }
                                    }
                                    $unresolved_object_names = array_diff($unresolved_object_names, $services_array);
                                }
                            }
                            $unresolved_object_names = array_filter($unresolved_object_names);
                            if (empty($unresolved_object_names)) {
                                $projectdb->query("DELETE FROM services_groups WHERE lid IN (" . implode(",", $service_groups_ids) . ") AND member_lid=0;");
                            }
                            else {
                                print "ERROR SOME SERVICES OBJECTS HAVE NOT BEEN CAPTURED" . PHP_EOL;
                                print_r($unresolved_object_names);
                                # Objects doesnt exist and need to be added
                                $addService = array();
                                foreach ($unresolved_object_names as $member_name) {
                                    $member_name = (string)$member_name;
                                    if ($member_name !== '') {
                                        $addService[] = "('$max','$source','$current_vsys',0,'$member_name','$member_name', 'Expedition created 1', 'tcp','65000','1','1')";

                                        $query = "INSERT INTO tag_relations (table_name, member_lid, tag_id) VALUES ('services','$max','$invalid_tag_id')";
                                        $projectdb->query( "INSERT INTO tag_relations (table_name, member_lid, tag_id) VALUES ('services','$max','$invalid_tag_id')");
                                        //echo "LINE 422: $query\n";

                                        foreach ($unresolvedAddresses_usedIn[$member_name] as $glid) {
                                            $resolved_service_subquery[] = "('$glid','$max','services')";
                                        }
                                        $objectsInMemory['services'][$current_vsys][$member_name]['id'] = $max;
                                        $objectsInMemory['services'][$current_vsys][$member_name]['dport'] = "65000";
                                        $max++;
                                    }

                                }

                                $projectdb->query("DELETE FROM services_groups WHERE lid IN (" . implode(",", $service_groups_ids) . ") AND member_lid=0;");
                                if (count($addService) > 0) {
                                    $projectdb->query("INSERT INTO services (id,source,vsys,dummy,name_ext,name, devicegroup, protocol, dport, checkit, invalid) VALUES " . implode(",", $addService) . ";");
                                    unset($addService);
                                }
                                $unresolved_object_names = array();

                            }
                        }

                    }
                }
            }

            # Let's do inserts by vsys/dg
            if ( isset($resolved_service_subquery) && count($resolved_service_subquery) > 0) {
                $unique = array_unique($resolved_service_subquery);
                $projectdb->query("INSERT INTO services_groups (lid,member_lid,table_name) VALUES " . implode(",", $unique) . ";");
                unset($resolved_service_subquery);
            }

            break;
    }
}

function load_objects_byname(&$objectsInMemory,$data,$new_vsys=null){
    $projectdb = $data['projectdb'];
    $source=$data['source'];

    if ($new_vsys===null){
        $andVSYS="";
    }
    else{
        $andVSYS=" AND vsys='$new_vsys' ";
    }

    $loadApps=$projectdb->query("SELECT id,name,vsys,ipaddress,cidr,name_ext,invalid FROM address WHERE source='$source' $andVSYS;");
    if ($loadApps->num_rows>0){
        while($data=$loadApps->fetch_assoc()){
            $lid=$data['id'];
            $vsys=$data['vsys'];
            $ipaddress=$data['ipaddress'];
            $cidr=$data['cidr'];
            $name_ext=$data['name_ext'];
            $validity= !((boolean) $data['invalid']);
            $objectsInMemory['address'][$vsys][$name_ext]['id']=$lid;
            $objectsInMemory['address'][$vsys][$name_ext]['ipaddress']=$ipaddress;
            $objectsInMemory['address'][$vsys][$name_ext]['cidr']=$cidr;
            $objectsInMemory['address'][$vsys][$name_ext]['validity']=$validity;
        }
    }

    $loadApps=$projectdb->query("SELECT id,name,vsys,name_ext FROM address_groups_id WHERE source='$source' $andVSYS;");
    if ($loadApps->num_rows>0){
        while($data=$loadApps->fetch_assoc()){
            $lid=$data['id'];
            $vsys=$data['vsys'];
            $name_ext=$data['name_ext'];
            $objectsInMemory['address_groups_id'][$vsys][$name_ext]['id']=$lid;
        }
    }


    $loadApps=$projectdb->query("SELECT id,name,vsys,dport,name_ext FROM services WHERE source='$source' $andVSYS;");
    if ($loadApps->num_rows>0){
        while($data=$loadApps->fetch_assoc()){
            $lid=$data['id'];
            $vsys=$data['vsys'];
            $dport=$data['dport'];
            $name_ext=$data['name_ext'];
            $objectsInMemory['services'][$vsys][$name_ext]['id']=$lid;
            $objectsInMemory['services'][$vsys][$name_ext]['dport']=$dport;
        }
    }

    $loadApps=$projectdb->query("SELECT id,name,vsys,name_ext FROM services_groups_id WHERE source='$source' $andVSYS;");
    if ($loadApps->num_rows>0){
        while($data=$loadApps->fetch_assoc()){
            $lid=$data['id'];
            $vsys=$data['vsys'];
            $name_ext=$data['name_ext'];
            $objectsInMemory['services_groups_id'][$vsys][$name_ext]['id']=$lid;
        }
    }

}

function getVsysesDescIDs_local(mysqli $projectdb){
    $vsyses = array();
    $ALLvsysList = array();
    $root =0;

    $query = "SELECT dm.id, dm.vsys, dg.device_mapping_id as kidID, parent_dg as parentID
              FROM device_mapping dm, devicegroups dg 
              WHERE dm.id = dg.device_mapping_id";

    $result = $projectdb->query($query);
    if ($result->num_rows>0){
        while($data = $result->fetch_assoc()) {
            if($data['parentID']===0){
                $root = $data['kidID'];
            }
            $ALLvsysList[$data['kidID']] = [
                'id' => $data['kidID'],
                'name' => $data['vsys'],
                'parentID' => $data['parentID']
            ];
        }
    }

    $vsysItem = $ALLvsysList[$root];
    $vsyses[] = $vsysItem['id'];
    $vsyses = array_merge($vsyses, getVsysesUnderID($ALLvsysList, $vsysItem['id']));

    return $vsyses;
}

$sourcesAdded=array();
global $source;

if ($action === "import") {

    //$startTime = time();
    //echo $startTime;

    ini_set('max_execution_time', PARSER_max_execution_time);
    ini_set("memory_limit",PARSER_max_execution_memory);
    $path = USERSPACE_PATH."/projects/".$project."/";

    $i = 0;
    $dirrule = opendir($path);
    $source = 0;  //The source will be calculated when the first vsys / DG is created, during the device_mapping insert in ($this->import_config_FirstPart() )
    $vsys = 0;    //The vsys/dg will be calculated when the first vsys / DG is created, during the device_mapping insert in ($this->import_config_FirstPart() )


    //Update the relationship between Firewalls and Policies
    $ids_to_load = array();
    $policies = explode(',', $signatureid);
    foreach($policies as $policy){
        $tuple = explode('XPDT', $policy);
        if(count($tuple)==2) {
            $policyName = $tuple[1];
            $id = (int)$tuple[0];
            $ids_to_load[] = $id;
            $conn = get_pdo($project);
            $stmt = $conn->prepare("UPDATE policies_to_import SET policyname= ? WHERE id= ? ;");
            $stmt->bindParam(1, $policyName);
            $stmt->bindParam(2, $id);
            $stmt->execute();
        }

    }

    $ids_to_load = implode(',', $ids_to_load);

    update_progress($project,'0.00','Reading config files',$jobid);

    while ($config_filename = readdir($dirrule)) {
        $query = "SELECT id FROM device_mapping WHERE device = '$config_filename';";
        $knownPolicies = $projectdb->query($query);
        if(($knownPolicies->num_rows === 0) && checkFiles2Import($config_filename)) {
            $config_path = $path . $config_filename;
            $filename = $config_filename;
            if (isXML($config_path) === FALSE) {
                continue;
                //file is not an XML file, skip and get the next file
            }

            //Check the existence of known policies to load
            // For that, we need to read the values that signatureid got. These are the IDs of the entries in the table policies_to_import.

            $query = "SELECT id FROM policies_to_import WHERE id in ($ids_to_load);";
            $knownPolicies = $projectdb->query($query);

            if($knownPolicies->num_rows===0){
                get_FwNames($config_path, $config_filename);  //Update policies_to_import defining existing policies in the configuration
            }
            else{
                //Check which policies have been selected for importing, and have not been imported yet.
                $is_imported = $projectdb->query("SELECT id, filename, policyname, firewall FROM policies_to_import ".
                    "WHERE ID in ($ids_to_load) AND (processed IS NULL OR processed='');");
                $policies_to_load=[];
                $policies_names_to_load=[];
                while ($policy = $is_imported->fetch_assoc()){
                    $policies_to_load[] = $policy;
                    $policies_names_to_load[] = normalizeNames($policy['policyname']);
                }

                $xml = simplexml_load_string(file_get_contents($config_path));

                $policies = insert_DG_Structure($xml, $config_path, $project, $config_filename, $policies_names_to_load, $source, $vsys);

                $numberOfPoliciesToProcess = count($policies);
                $accumulatedProcess = 0.2;
                $internalSteps = 3;
                $stepSize = (0.9-0.2)/($internalSteps*$numberOfPoliciesToProcess);

                if ($source === -1) {
                    add_log('error', 'Start Parsing Files', 'Config could not be imported. Source could not created.', $source, 'Review the format.');
                    exit();
                }

                //$first_firewall = '';
                foreach ($policies as &$policy){
                    foreach ($policies_to_load as $policy_requested){
                        if($policy['policyname'] === $policy_requested['policyname']){
                            $policy['firewall'] = $policy_requested['firewall'];
                            $policy['leaf'] = true;
//                            $first_firewall = ($first_firewall !== '')?$first_firewall:$policy_requested['firewall'];
                            break;
                        }
//                        $policy['firewall'] = $first_firewall;
                    }
                    $policy['filename'] = $config_filename;
                }
                unset($policy);

                foreach ($policies as $policy){
//                    echo "New policy to load\n";
//                    print_r($policy);
                    renewDBConnection();
                    $policy_to_load = $policy['policyname'];
                    $is_first = true;

                    $vsys = $policy['policyname'];
                    update_progress($project, $accumulatedProcess, 'File:' . $filename . '('.$policy_to_load.') Phase 2 Loading address objects',$jobid);
                    $accumulatedProcess += $stepSize;

                    if((int)$policy['level']===1) {
                        //TODO: Loading Local Domain objects
                        renewDBConnection();
                        get_Address_Stonesoft($xml, $vsys, $source, (int)$policy['level']);
                        renewDBConnection();
                        get_Address_Group($xml, $vsys, $source, (int)$policy['level']);
                        renewDBConnection();
                        get_Alias($xml, $vsys, $source, (int)$policy['level']);

                    } elseif (count($policies)===1 && (int)$policy['level']===0){
                        renewDBConnection();
                        get_Address_Stonesoft($xml, $vsys, $source, 1);
                        renewDBConnection();
                        get_Address_Group($xml, $vsys, $source, 1);
                        renewDBConnection();
                        get_Alias($xml, $vsys, $source, 1);
                    }
                    if((int)$policy['level']===0) {
                        //This is our shared DG
                        renewDBConnection();
                        import_config_FirstPart_StonesoftTemplate($config_path, $project, $config_filename, $policy_to_load, $source, $vsys);
                        renewDBConnection();
                    }
                    if(isset($policy['leaf']) && (int)$policy['leaf']===1){
                        //This is the DG for the final FWs. We would have to import there the firewall addresses, template, etc
                        $firewall = $policy['firewall'];
                        import_config_Leaf_FirstPart($config_path, $project, $config_filename, $policy_to_load, $firewall, $source, $vsys);
                    }
                    //else{
                        //Those are middle DGs
                    //}

                    $sourcesAdded[] = $source;

//                    if((int)$policy['level']===0) {
                        # LOAD ALL OBJECTS TO INMEMORY
                        renewDBConnection();
                        $objectsInMemory = array();
                        $data = array("projectdb" => $projectdb, "source" => $source);
                        load_objects_byname($objectsInMemory, $data);

                        //I need this information complete before procesing the rules :(
                        $policy_case = "$config_filename--$policy_to_load";
                        update_progress($project, $accumulatedProcess, 'File:' . $filename . '(' . $policy_to_load . ') Phase 3 Referencing Groups', $jobid);
                        $accumulatedProcess += $stepSize;
                        #GroupMember2IdAddress_improved($policy_case);


//                    GroupMember2IDStonesoft("address",$source,$objectsInMemory);
//                    GroupMember2IDStonesoft("service",$source,$objectsInMemory);

//                    }
                    renewDBConnection();
                    GroupMember2IDStonesoft("address",$source,$objectsInMemory);
                    GroupMember2IDStonesoft("service",$source,$objectsInMemory);

                    if((int)$policy['level']===0) {
                        renewDBConnection();
                        import_config_SecondPart($config_path, $source, $vsys);
                    }

                    if(isset($policy['leaf']) && (int)$policy['leaf']===1){
                        $vsys_ = normalizeNamesNew($vsys, 9, 'vsys');
                        renewDBConnection();
                        calculate_expression_members($vsys_, $source);
                    }

                    $objectsInMemory = array();
                    renewDBConnection();
                    $data = array("projectdb" => $projectdb, "source" => $source);
                    load_objects_byname($objectsInMemory, $data);

                    #GroupMember2IdAddress_improved($policy_case);
                    #GroupMember2IdServices($policy_case);

                    //Importing the policies and subpolicies
                    update_progress($project, $accumulatedProcess, 'File:' . $filename . '('.$policy_to_load.') Phase 4 Reading Root and Nested policies',$jobid);
                    $accumulatedProcess += $stepSize;
                    renewDBConnection();
                    import_config_ThirdPart($config_path, $project, $config_filename,$policy_to_load, $source, $vsys,$objectsInMemory);
                    renewDBConnection();
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

                    //Update processed as completed
                    $projectdb->query("UPDATE policies_to_import SET processed=SYSDATE() WHERE filename='$config_filename' AND policyname='$policy_to_load';");
                    //$projectdb->query("DELETE FROM policies_to_import WHERE processed IS NULL;");
                }
                unlink($config_path);
                $projectdb->query("DELETE FROM policies_to_import WHERE processed IS NULL;");
            }
        }
    }

    renewDBConnection();
    // Auto split the address groups based on defined PARSER_max_number_address_per_group
    // for upgraded installations that does not have the variable in the /home/userSpace/userDefinition.php defined
    if (!defined('PARSER_max_number_address_per_group')) {
        define('PARSER_max_number_address_per_group', -1);
    }
    if(PARSER_max_number_address_per_group!=-1) {
        update_progress($project, '0.85', 'Project:' . $project . ' Split the address group members using as a limit defined value of '. PARSER_max_number_address_per_group . ' members', $jobid);
        splitMembersOnGroups();
    }

    #Check used
    renewDBConnection();
    update_progress($project, '0.90', 'Project:' . $project . ' Calculating Used Objects',$jobid);
    check_used_objects_new($sourcesAdded);
    renewDBConnection();
    if(count($sourcesAdded)>0){
        check_used_DAG_members($sourcesAdded);
    }
    update_progress($project, '1.00', 'Done.',$jobid);

    //$finishTime = time();
    //echo $finishTime;
    //echo "time_elapsed_A: ".time_elapsed_A($finishTime-$startTime)."\n";

    //sleep(4);
    //update_progress($project, '0', 'Ready');
}
elseif($action === "get"){
    //global $DBUser;
    //global $DBPass;

    ini_set('max_execution_time', 10000);
    ini_set("memory_limit", "1000M");
    $path = USERSPACE_PATH."/projects/" . $project . "/";

    $i = 0;
    $dirrule = opendir($path);

    $fwNames = array();
    if ($type === "existing_firewalls") {
        while ($config_filename = readdir($dirrule)) {
            $fileFullPath = $path.$config_filename;
            //Check that the file is not a ZIP/Rar
            $gestor = @fopen($fileFullPath, "r");
            $blob = fgets($gestor, 5);
            fclose($gestor);
            if (strpos($blob, 'Rar') !== false) {
                continue;
            }
            elseif (strpos($blob, 'PK') !== false) {
              continue;
            }

            if (checkFiles2Import($config_filename)){
                $config_path = $path . $config_filename;
                $filename = $config_filename;
                get_FwNames($config_path, $config_filename);  //Update policies_to_import defining existing policies in the configuration
                //get_DomainNames($config_path, $config_filename);  //Update the domain_names that are used in the policy
                $fwNames = get_PolicyNames($config_path, $config_filename);
            }
        }

        $getLimit = $projectdb->query("SELECT * FROM policies_to_import ORDER BY filename,policyname ASC;");
        if($getLimit){
            $count = $getLimit->num_rows;
            while ($data = $getLimit->fetch_object()) {
                $myData[] = $data;
            }
            if (!isset ($count) || is_null($count) ||$count == 0) {
                $count =0;
                $myData = "";
            }
        }else{
            $count =0;
            $myData = "";
        }

        $response = [
            'total'         => $count,
            'fwNames'      => $myData,
        ];
        echo json_encode($response);
    }
    elseif($type === "existing_policies"){
        $firewallID = $projectdb->real_escape_string($_GET['id']);
        $selectedFile = "";
        $query = "SELECT filename FROM policies_to_import WHERE id='$firewallID'";
        $result = $projectdb->query($query);
        if($result->num_rows>0){
            $data = $result->fetch_assoc();
            $selectedFile = $data['filename'];
        }
        while ($config_filename = readdir($dirrule)) {
            if($config_filename === $selectedFile) {
                $fileFullPath = $path . $config_filename;
                //Check that the file is not a ZIP/Rar
                $gestor = @fopen($fileFullPath, "r");
                $blob = fgets($gestor, 5);
                fclose($gestor);
                if (strpos($blob, 'Rar') !== false) {
                    continue;
                }

                if (strpos($blob, 'PK') !== false) {
                    continue;
                }

                if (checkFiles2Import($config_filename)){
                    $config_path = $path . $config_filename;
                    $filename = $config_filename;

                    $fwNames = array_merge($fwNames, get_PolicyNames($config_path, $config_filename));
                }
            }
        }
        $response = [
            'total'         => count($fwNames),
            'policies'       => $fwNames
        ];
        echo json_encode($response);
    }
    elseif($type === "existing_domain_names"){

        $getLimit = $projectdb->query("SELECT * FROM domain_names ORDER BY name ASC;");
        $count = $getLimit->num_rows;
        while ($data = $getLimit->fetch_object()) {
            $myData[] = $data;
        }
        if ($count == 0) {
            $myData = "";
        }
        echo '{"total":"' . $count . '","domainNames":' . json_encode($myData) . '}';
    }
}


function level_dgs(array &$structure, int $level =0){
    if($level === 0){
        foreach ($structure as &$item){
            if(!isset($item['parent_dg'])){
                $item['level'] = $level;
            }
        }
        unset($item);
    }
    else{
        $parents = [];
        foreach ($structure as $item){
            if(isset($item['level']) && $item['level']== ($level-1)){
                $parents[] = $item['device_mapping_id'];
            }
        }

        foreach ($structure as &$item){
            if(isset($item['parent_dg']) && in_array($item['parent_dg'], $parents)){
                $item['level']=$level;
            }
        }
        unset($item);
    }

    foreach ($structure as $item){
        if(!isset($item['level'])){
            level_dgs($structure, $level+1);
            break;
        }
    }

}
/***
 * Creates an array strcuture with the different DGs (Stonesoft representation) with their id and parents
 * @param array $fw_policies
 * @param string $config_name
 * @param SimpleXMLElement $configuration
 * @param array $policies_names_to_load
 * @param int $next_id
 * @param array $structure This will be an array structure that will define the existing DGs and their parents
 */
function add_in_dg_structure(array $fw_policies, string $config_name, SimpleXMLElement $configuration, array $policies_names_to_load, int $source, int $next_id, array &$structure = [] ){
//    echo "Create_dg_Structure called for:";
//    print_r($policies_names_to_load);

    foreach ($fw_policies as $fw_policy) {
        $policy_name = normalizeNames((string)$fw_policy['name']);
//        echo "Checking into $policy_name\n";
        $is_in_mapping = in_array($policy_name, $policies_names_to_load, false);
        $is_already_processed = array_key_exists($policy_name, $structure);
        if($is_in_mapping && !$is_already_processed){
//            echo "This one worked\n";
            $structure[$policy_name] = [
                'name' => $policy_name,
//                'name_ext' => $policy_name,

//                'config_name' => $config_name,
//                'active' => 1,
//                'version' => '9.0',
//                'baseconfig' => 0,
//                'vendor' => 'Stonesoft',
//                'urldb' => '',
//
//                'fw_devices' => '<devices/>',
//
//                'master_device' => 'None',
//                'description' => "$policy_name as a DG",
//                'dummy' => 0,
//                'internal_id' => 0,
//                'max_internal_id' => 0,
//
//                'parent_dg' => '',
//                'source' => '',

                'device_mapping_id' => $next_id+count($structure),
//                'devicegroups_id' => ""

            ];

            if (isset($fw_policy["template_policy_ref"])){
                $template_name = normalizeNames((string)$fw_policy["template_policy_ref"]);
//                echo "This one has template $template_name\n";
                add_in_dg_structure($fw_policies, $config_name, $configuration, [$template_name], $source, $next_id, $structure);
                if(isset($structure[$template_name]['device_mapping_id'])) {
                    $parent_dg_id = $structure[$template_name]['device_mapping_id'];
                    $structure[$policy_name]['parent_dg'] = $parent_dg_id;
                }else{
                    $msg = "Selected policy is referencing missing template named [" . $fw_policy["template_policy_ref"] . "]. Please check migrated configuration is complete.";
                    echo $msg . "\n";
                    add_log("warning", 'Reading Configuration', $msg, $source, 'Review');
                }
            }
        }
    }
}

/***
 * @param SimpleXMLElement $configuration
 * @param string $config_path
 * @param string $project
 * @param string $config_filename
 * @param array $policies_name_to_load
 * @param int $source
 * @param string $vsys
 * @return array
 */
function insert_DG_Structure(SimpleXMLElement $configuration, string $config_path, string $project, string $config_filename, array $policies_name_to_load , int &$source, string &$vsys): array{
    global $projectdb;
    global $like_panorama;
    global $shared_dg_name;
    $min_dg = INF;
    $xml = simplexml_load_string(file_get_contents($config_path));
    $version = $xml->version;

    $fw_policies = $configuration->xpath("//fw_policy");
    $fw_template_policies = $configuration->xpath("//fw_template_policy");
    $fw_policies = array_merge($fw_policies, $fw_template_policies);

    $getPosition = $projectdb->query("SELECT max(id) as t FROM device_mapping;");
    if ($getPosition->num_rows === 0) {
        $next_id = 1;
    } else {
        $ddata = $getPosition->fetch_assoc();
        $next_id = $ddata['t'] + 1;
    }

    $structure = [];
    $policies = [];
    add_in_dg_structure($fw_policies, $config_filename, $configuration, $policies_name_to_load, $source, $next_id, $structure);

    //Put the level where each DG is placed. Root is level 0, its childs will be level 1, and so on
    level_dgs($structure);
    usort($structure, static function ($a, $b) {     return $a["level"]>$b["level"]; });

    $device_mapping_entries = [];
    $devicegroups_entries = [];

    foreach ($structure as $entry){
        if ($entry['level'] === 0) {
            $shared_dg_name = $entry['name'];
        }
        $policies[] =[
            'policyname'    => $entry['name'],
            'parent'        => $entry['parent_dg']??0,
            'id'            => $entry['device_mapping_id'],
            'level'         => $entry['level']
        ];
        $min_dg = ($entry['device_mapping_id'] < $min_dg)? $entry['device_mapping_id']:$min_dg;
        $device_mapping_entries[] = "(".$entry['device_mapping_id'].",'$config_filename','$version', $like_panorama, 1,'$project','$config_filename','".$entry['name']."','Stonesoft')";
    }
    $query = "INSERT INTO device_mapping (id, device,version,ispanorama,active,project,filename,vsys,vendor) " .
        "VALUES ".implode(',', $device_mapping_entries);
    $projectdb->query($query);
    $source = $min_dg;

    foreach ($structure as $entry){
        $parent_dg = $entry['parent_dg'] ?? 0;
        $devicegroups_entries[] = "($source, ".$parent_dg.",'<devices/>','None','".$entry['name']." as DG','".$entry['name']."','".$entry['name']."',".$entry['device_mapping_id'].")";
    }
    $query = "INSERT INTO devicegroups (source, parent_dg, devices, master_device, description, name_ext, name, device_mapping_id)".
        "VALUES ".implode(",",$devicegroups_entries);
    $projectdb->query($query);

    return $policies;
}

function import_config_FirstPart_StonesoftTemplate(string $config_path, string $project, $config_filename, $policy_to_load, int $source, string $vsys)
{
    global $like_panorama;
    global $projectdb;
    global $match_expressionsInMemory;
    global $devicegroup;
    global $configFilenamePolicy;
    global $processed_firewall_interfaces;
    global $processed_firewall_staticRoutes;

    $filename = $config_filename;

    if (isXML($config_path) === TRUE) {
        $devicegroup = $config_filename;
        $xml = simplexml_load_string(file_get_contents($config_path));
        $version = $xml->version;
        if ($like_panorama) {
            $configFilenamePolicy = addslashes($config_filename);
        } else {
            $configFilenamePolicy = addslashes($config_filename . "--" . $policy_to_load);
        }

        add_default_alias_and_tags($source);
        add_default_services($source);
        add_default_profiles($source, $version);
        add_stonesoft_services($source, $vsys);  //Native defined services at the platform
        update_progress($project, '0.10', 'File:' . $filename . ' Phase 1 Loading Objects');

        get_Address_Stonesoft($xml, $vsys, $source);
        get_Address_Group($xml, $vsys, $source);
        get_Alias($xml, $vsys, $source);
        //get_alias_declarations($xml, $vsys, $source);


        get_Services($xml, $vsys, $source);
        get_ServicesGroups($xml, $vsys, $source);
        get_AddressExpressions($xml, $vsys, $source);
    }
    else {
        $source = -1;
        add_log('error', 'Start Parsing Files', 'Failed the file uploaded is not a Valid XML', $source, 'Review the format.');
        update_progress($project, '-1.00', 'XML is invalid.');
    }

}


function add_default_alias_and_tags($source){
    global $projectdb;
    global $invalid_tag_id;
    global $alias_id;
    global $alias_tag_id;
    global $expression_tag_id;

//    $exists = $projectdb->query("SELECT id FROM tag WHERE name IN ('Alias_Object') AND source='$source' AND vsys='shared';");
//    if ($exists->num_rows !== 1) {
//        $projectdb->query("INSERT INTO tag (name_ext,name,color,vsys,source,devicegroup, used) VALUES ('Alias_Object','Alias_Object','None','shared','$source','default',1);");
//        $alias_tag_id = $projectdb->insert_id;
//    }

//    $exists = $projectdb->query("SELECT id FROM tag WHERE name IN ('Expression Object') AND source='$source' AND vsys='shared';");
//    if ($exists->num_rows !== 1) {
//        $projectdb->query("INSERT INTO tag (name_ext,name,color,vsys,source,devicegroup, used) VALUES ('Expression Object','Expression Object','None','shared','$source','default',1);");
//        $expression_tag_id = $projectdb->insert_id;
//    }

    $exists = $projectdb->query("SELECT id FROM tag WHERE name IN ('Invalid Object') AND source='$source' AND vsys='shared';");
    if ($exists->num_rows !== 1) {
        $projectdb->query("INSERT INTO tag (name_ext,name,color,vsys,source,devicegroup, used) VALUES ('Invalid Object','Invalid Object','color6','shared','$source','default',1);");
        $invalid_tag_id = $projectdb->insert_id;
    }

    $exists = $projectdb->query("SELECT id FROM address WHERE name IN ('NONE') AND source='$source' AND vsys='shared';");
    if ($exists->num_rows !== 1) {
        $projectdb->query("INSERT INTO address (name_ext,name,description,type,ipaddress,vsys,source,devicegroup) VALUES ('NONE','NONE','Empty address object for Alias declarations','fqdn','none','shared','$source','default');");
        $alias_id = $projectdb->insert_id;
    }

    $query = "INSERT INTO tag_relations (table_name, member_lid, tag_id) VALUES ('address','$alias_id','$invalid_tag_id')";
    $projectdb->query("INSERT INTO tag_relations (table_name, member_lid, tag_id) VALUES ('address','$alias_id','$invalid_tag_id')");
    //echo "LINE 1095: $query\n";

}

//function get_Alias_old(SimpleXMLElement $configuration, string $vsys, string $source){
//    global $projectdb;
////    $addresses_groups_id = [];
////    $address_groups = [];
////    $addresses = [];
////
////    $lastAddressID = getLastId('address');
////    $lastAddressGroupsID = getLastId('address_groups_id');
//
//
//    $aliass = $configuration->xpath("//alias");
//    foreach($aliass as $alias){
//        $name_ext = trim(normalizeNames($alias['name']));
//        $name_int = truncate_names(normalizeNames($name_ext));
//        $referred = $alias->default_alias_value["ne_ref"];
//
//        $query = "INSERT INTO address (name_ext, name, description, ipaddress, cidr, v4, v6, type, vtype, source, vsys) ".
//            "SELECT '$name_ext' as 'name_ext', '$name_int' as 'name', concat('Alias of $referred. ',description), ipaddress, cidr, v4, v6, type, vtype, source, vsys ".
//            "FROM address ".
//            "WHERE name = '$referred' LIMIT 1;";
//        $projectdb->query($query);
//
//    }
//
////    //Done in the upper section, one by one
////    if (count($addresses_groups_id) > 0) {
////        $uniq = array_unique($addresses_groups_id);
////        $out = implode(",", $uniq);
////        $projectdb->query("INSERT INTO address_groups_id (id, name_ext,name,description, source,vsys) VALUES " . $out . ";");
////    }
////
////    //Insert all the Members
////    if (count($addresses) > 0) {
////        $uniq = array_unique($addresses);
////        $out = implode(",", $uniq);
////        $query = "INSERT INTO address (id, name_ext,name,description, ipaddress,cidr,v4,v6,type,vtype,source,vsys) VALUES " . $out . ";";
////        $projectdb->query($query);
////    }
////
////    //Insert all the relations
////    if (count($address_groups) > 0) {
////        $uniq = array_unique($address_groups);
////        $out = implode(",", $uniq);
////        $projectdb->query("INSERT INTO address_groups (lid, name_ext,name,member,source,vsys, member_lid, table_name) ".
////            "VALUES " . $out . ";");
////    }
//}

function get_Alias(SimpleXMLElement $configuration, string $vsys, string $source, int $level=0){
    global $projectdb;
    //global $alias_tag_id;
    $addresses_groups_id = [];
    $address_groups = [];
    $agi = array();

    $lastAddressGroupsID = getLastId('address_groups_id');

    $alias_tag_id = get_tag_id($projectdb, "Alias Object", $source, $vsys);
    $aliases = $configuration->xpath("//alias");
    foreach ($aliases as $alias){
        $name_ext = trim(normalizeNames($alias["name"]));
        if(!object_belongs_here($level, $name_ext)) {
            continue;
        }

        $name_int = truncate_names(normalizeNames($name_ext));
        $description = normalizeNames($alias["comment"]);
        $alias_value= normalizeNames($alias->default_alias_value["ne_ref"]);

        $addresses_groups_id[] = "($lastAddressGroupsID,'$name_ext','$name_int','$description','$source','$vsys')";
        $lid = $lastAddressGroupsID;
        $lastAddressGroupsID++;
        $agi[] = "('address_groups_id','$lastAddressGroupsID','$alias_tag_id')";


        $address_groups[] = "('$lid','$alias_value','$name_int','$alias_value','$source', '$vsys')";
        //$lastAddressID++;
    }


    if (count($addresses_groups_id) > 0) {
        $uniq = array_unique($addresses_groups_id);
        $out = implode(",", $uniq);
        $projectdb->query("INSERT INTO address_groups_id (id, name_ext,name,description, source,vsys) VALUES " . $out . ";");

        $uniq = array_unique($agi);
        $out = implode(",", $uniq);
        $query = "INSERT INTO tag_relations (table_name, member_lid, tag_id) VALUES ".$out.";";
        $projectdb->query("INSERT INTO tag_relations (table_name, member_lid, tag_id) VALUES ".$out.";");
        //echo "LINE 1187: $query\n";
    }

    //Insert all the relations
    if (count($address_groups) > 0) {
        $uniq = array_unique($address_groups);
        $out = implode(",", $uniq);
        $query = "INSERT INTO address_groups (lid, name_ext,name,member,source,vsys) VALUES " . $out . ";";
        $projectdb->query($query);
    }
}

function import_config_Leaf_FirstPart(string $config_path, string $project, $config_filename, $policy_to_load, $firewall , int $source, string $vsys) {
    //echo "Called firstPart with $firewall\n";
    global $like_panorama;
    global $projectdb;
    global $match_expressionsInMemory;
    global $devicegroup;
    global $configFilenamePolicy;
    global $processed_firewall_interfaces;
    global $processed_firewall_staticRoutes;

    $filename = $config_filename;

    if (isXML($config_path) === TRUE) {
        $devicegroup = $config_filename;
        $xml = simplexml_load_string(file_get_contents($config_path));
        $version = $xml->version;
        if($like_panorama){
            $configFilenamePolicy = addslashes($config_filename );
        }
        else {
            $configFilenamePolicy = addslashes($config_filename . "--" . $policy_to_load);
        }

        #Config Template
        $template_name = "template_" . $vsys;

        $projectdb->query("INSERT INTO templates_mapping (project,name,filename,source) ".
            "VALUES ('$project','$template_name','$configFilenamePolicy','$source');");
        $template = $projectdb->insert_id;

        $projectdb->query("INSERT INTO templates (name,source,default_vsys, templates_mapping_id, multi_vsys, operational_mode,vpn_disable_mode) ".
            "VALUES ('$template_name','$source', 'vsys1', '$template','','','');");
        //$template = $projectdb->insert_id;

        $query_template_stack = "INSERT INTO templates_stacks_id (name, devices, source, templates_mapping_id, default_vsys) 
                                 VALUES ('template_stack_1','<devices></devices>','$source',0,'vsys1')";
        $projectdb->query($query_template_stack);
        $template_stack = $projectdb->insert_id;

        $query_tem_stack = "INSERT INTO templates_stacks (name, source, templates_mapping_id, lid) 
                            VALUE ('$template_name','$source', '$template','$template_stack')";
        $projectdb->query($query_tem_stack);

        $query = "INSERT INTO virtual_systems(template, source, name) VALUES ($template, $source, '$policy_to_load');";
        $projectdb->query($query);


        //Get the cluster name for the current policy to load
//        if(!in_array($firewall, $processed_firewall_interfaces)) {
        //echo "Going to load interfaces for firewall '$firewall' in vsys '$vsys' in template '$template'\n";
            get_Interfaces($xml, $firewall, $vsys, $source, $template);
//            $processed_firewall_interfaces[] = $firewall;
//        }

        get_Firewall_Addresses($xml, $vsys, $source, $policy_to_load, $firewall, $template);
        //get_Alias($xml, $vsys, $source);

//        if(!in_array($firewall, $processed_firewall_staticRoutes)) {
            get_Static_Routes($xml, $firewall, $source, $vsys, $template);
//            $processed_firewall_staticRoutes[] = $firewall;
//        }
    }
}


/***
 * THis method will load the objects necessary for this policy, and will set up the parameters to identify the policy $source and $vsys
 * @param string $config_path
 * @param string $project
 * @param $config_filename
 * @param $policy_to_load
 * @param $firewall
 * @param int $source
 * @param string $vsys
 * @oaram mysqlConnection $config_filename
 */
//function import_config_FirstPart(string $config_path, string $project, $config_filename, $policy_to_load, $firewall , int $source, string $vsys) {
//    echo "Called firstPart with $firewall\n";
//    global $like_panorama;
//    global $projectdb;
//    global $match_expressionsInMemory;
//    global $devicegroup;
//    global $configFilenamePolicy;
//    global $processed_firewall_interfaces;
//    global $processed_firewall_staticRoutes;
//
//    $filename = $config_filename;
//
//    if (isXML($config_path) === TRUE) {
//        $devicegroup = $config_filename;
//        $xml = simplexml_load_string(file_get_contents($config_path));
//        $version = $xml->version;
//        if($like_panorama){
//            $configFilenamePolicy = addslashes($config_filename );
//        }
//        else {
//            $configFilenamePolicy = addslashes($config_filename . "--" . $policy_to_load);
//        }
//        #Add new $source and the default $vsys value.
////        $projectdb->query("INSERT INTO device_mapping (device,version,ispanorama,active,project,filename,vsys,vendor) " .
////            "VALUES ('$devicegroup','$version',$like_panorama,1,'$project','$configFilenamePolicy','vsys1','Stonesoft')");
////
////        if($like_panorama){
////            $vsys = "shared";
////            if($source === 0) {
////                $source = (int)$projectdb->insert_id;
////            }
////        }
////        else {
////            $source = (int)$projectdb->insert_id;
////            $vsys = "vsys1";
////        }
//        add_default_services($source);
//        add_default_profiles($source, $version);
//        echo "Getting default services 1273";
//        add_stonesoft_services($source, $vsys);  //Native defined services at the platform
//        update_progress($project, '0.10', 'File:' . $filename . ' Phase 1 Loading Objects');
//
//        #Config Template
//        $template_name = "template_" . $vsys;
//        $projectdb->query("INSERT INTO templates_mapping (project,name,filename,source) ".
//            "VALUES ('$project','$template_name','$configFilenamePolicy','$source');");
//        $template = $projectdb->insert_id;
//
//        //Get the cluster name for the current policy to load
//        if(!in_array($firewall, $processed_firewall_interfaces)) {
//            get_Interfaces($xml, $firewall, $vsys, $source, $template);
//            $processed_firewall_interfaces[] = $firewall;
//        }
////        $query = "SELECT firewall FROM policies_to_import WHERE policyname=\"$policy_to_load\" LIMIT 1 ";
////        $results = $projectdb->query($query);
////        if ($results->num_rows>0){
////            $data = $results->fetch_assoc();
////            $nameCluster = $data['firewall'];
////            get_Interfaces($xml, $nameCluster, $vsys, $source, $template);
////        }
////        else{
////            get_Interfaces($xml, $firewall, $vsys, $source, $template);
////            echo "QUERY FAILED: ".$query.PHP_EOL;
////        }
//
//
//
////         get_XML_Zones_Address($xml, $vsys, $source, $template);
//        get_Address_Stonesoft($xml, $vsys, $source);
//        get_Address_Group($xml, $vsys, $source);
//        get_Firewall_Addresses($xml, $vsys, $source, $policy_to_load, $firewall, $template);
//        get_Alias($xml, $vsys, $source);
//
//        if(!in_array($firewall, $processed_firewall_staticRoutes)) {
//            get_Static_Routes($xml, $firewall, $source, $vsys, $template);
//            $processed_firewall_staticRoutes[] = $firewall;
//        }
////        $query = "SELECT firewall FROM policies_to_import WHERE policyname=\"$policy_to_load\" LIMIT 1 ";
////        $results = $projectdb->query($query);
////        if ($results->num_rows>0){
////            while($data = $results->fetch_assoc()){
////                $nameCluster = $data['firewall'];
////                get_Static_Routes($xml, $nameCluster, $source, $vsys, $template);
////            }
////        }
////        else{
////            echo "QUERY FAILED: ".$query.PHP_EOL;
////        }
//
////         get_XML_Zones_Address_Global($xml, $vsys, $source, $template);
////         get_VR_static_routes($xml, $vsys, $source, $template);
////         get_XML_Applications($xml, $vsys, $source);
//        get_Services($xml, $vsys, $source);
//        get_ServicesGroups($xml, $vsys, $source);
//        get_AddressExpressions($xml, $vsys, $source);
//    }
//    else {
////        if ($source === 0) {
////            $source = 1;
////        }
//        $source = -1;
//        add_log('error', 'Start Parsing Files', 'Failed the file uploaded is not a Valid XML', $source, 'Review the format.');
//        update_progress($project, '-1.00', 'XML is invalid.');
//    }
//}

function import_config_SecondPart(STRING $config_path, STRING $source, STRING $vsys){
    if (isXML($config_path) === TRUE) {
        $xml = simplexml_load_string(file_get_contents($config_path));
        get_Expressions($xml, $vsys, $source);
    }
}

/***
 * @param STRING $config_path
 * @param STRING $project
 * @param STRING $config_filename
 * @param string $policy_to_load
 * @param STRING $source
 * @param STRING $vsys
 * @param array $objectsInMemory
 */
function import_config_ThirdPart(STRING $config_path, STRING $project, STRING $config_filename, string $policy_to_load, STRING $source, STRING $vsys, ARRAY &$objectsInMemory){
    global $projectdb;
    global $like_panorama;
    global $processed_policies;

    if (isXML($config_path) === TRUE) {
        $xml = simplexml_load_string(file_get_contents($config_path));
        if(!in_array($policy_to_load, $processed_policies)){
            get_Policy($xml, $policy_to_load, $source, $project,$objectsInMemory);
            if($like_panorama) {
                $projectdb->query("UPDATE devicegroups
                                     SET device_mapping_id =
                                           (SELECT device_mapping.id FROM device_mapping WHERE device_mapping.vsys = devicegroups.name_ext)
                                     WHERE devicegroups.device_mapping_id =0 and source=$source ;");
            }
            get_NATs($xml, $policy_to_load, $source, $project,$objectsInMemory);

            $processed_policies[] = $policy_to_load;
        }

//        get_VPN($xml, $vsys, $source, $project);

        // Call function to generate initial consumptions
        $template_name = "template_" . $vsys;
        deviceUsage("initial", "get", $project, "", "", $vsys, $source, $template_name);
    }
}

/**
 * This method looks for interfaces defined for the firewall that is going to be processed.
 *  A firewall could be defined as a single node or as a cluster. It seems that the firewaal/cluster
 *  shares the name of the policy that contains.
 *
 * @param SimpleXMLElement $configuration
 * @param STRING $firewallName
 * @param STRING $vsys
 * @param STRING $source
 * @param STRING $template
 */
function get_Interfaces(SimpleXMLElement $configuration, STRING $firewallName, STRING $vsys, STRING $source, STRING $template) {
    global $projectdb;

    $ipInterfaces = array();
    $add_interface = array();
    $zones = array();

    $vr = "vr_" . $vsys;
    $isDup = $projectdb->query("SELECT id FROM virtual_routers WHERE template='$template' AND name='$vr';");
    if ($isDup->num_rows == 0) {
        $projectdb->query("INSERT INTO virtual_routers (name,template,source,vsys) VALUES ('$vr','$template','$source','$vsys');");
        $vrid = $projectdb->insert_id;
    } else {
        $get = $isDup->fetch_assoc();
        $vrid = $get['id'];
    }

    //Cluster Firewalls adn Single Firewalls
    $fw_single = $configuration->xpath("//fw_single");
    $fw_clusters = $configuration->xpath("//fw_cluster");
    $fw_virtual = $configuration->xpath("//fw_virtual");
    $fw_cluster_and_single = array_merge($fw_single, $fw_clusters, $fw_virtual);
    foreach ($fw_cluster_and_single as $fw_cluster) {
        $clusterName = normalizeNames($fw_cluster['name']);
        if(strcasecmp($clusterName,$firewallName)==0){
            $ipInterfaces=array();
            foreach ($fw_cluster->physical_interface as $physical_interface){
                $comment = (isset($physical_interface['comment']))?$physical_interface['comment']:'';
                $interface_id = $physical_interface['interface_id']+1;
                $interfaceName = "ethernet1/$interface_id";
                $unitName = $interfaceName;

                $interface = new FwInterface("ethernet", $interfaceName, "layer3", $comment, $unitName, "", "");
                if(isset($physical_interface['zone_ref'])) {
                    $zone = $physical_interface['zone_ref'];
                    $interface->setZone($zone);
                }
                $ipInterfaces["$interface_id"]=$interface;
            }

            foreach ($fw_cluster->tunnel_interface as $tunnel_interface){
                $comment = (isset($physical_interface['comment']))?$physical_interface['comment']:'';
                $interface_id = $tunnel_interface['interface_id']+1;
                $interfaceName = "tunnel.$interface_id";
                $unitName = $interfaceName;
                $interface = new FwInterface("tunnel", $interfaceName, "layer3", $comment, $unitName, $interface_id, "");
                $ipInterfaces["$interface_id"]=$interface;
            }

            foreach ($fw_cluster->virtual_physical_interface as $physical_interface){
                $comment = (isset($physical_interface['comment']))?$physical_interface['comment']:'';
                $interface_id = $physical_interface['interface_id']+1;
                $interfaceName = "ethernet1/$interface_id";
                $unitName = $interfaceName;

                $interface = new FwInterface("ethernet", $interfaceName, "layer3", $comment, $unitName, "", "");
                if(isset($physical_interface['zone_ref'])) {
                    $zone = $physical_interface['zone_ref'];
                    $interface->setZone($zone);
                }
                $ipInterfaces["$interface_id"]=$interface;
            }

            foreach ($fw_cluster->cluster_virtual_interface as $cluster_virtual_interface){
                $nicid = $cluster_virtual_interface['nicid'];
                $nicid2 = explode(".", $nicid);
                $interface_id = $nicid2[0]+1;

                $network_value = $cluster_virtual_interface['network_value'];
                $network_value_cidr = explode("/", $network_value);

                if(isset($nicid2[1])){
                    //This is a VLAN
                    $vlan_tag = $nicid2[1];
                    $interface_id = $nicid2[0]+1;
                    $unitName = "ethernet1/$interface_id";
                    $VunitName = "$unitName.$vlan_tag";
                    $new_interface = clone $ipInterfaces["$interface_id"];

                    $new_interface->interfaceName = $unitName;
                    $new_interface->unitName = $VunitName;
                    $new_interface->vlan_tag = $vlan_tag;

                    foreach ($cluster_virtual_interface->mvia_address as $mvia_address){
                        $new_interface->addIPaddress($mvia_address['address']."/".$network_value_cidr[1]);
                    }
                    $ipInterfaces["$VunitName"] = $new_interface;
                }
                else{
                    $tmp_interface = $ipInterfaces["$interface_id"];
                    if(!is_null($tmp_interface)) {
                        foreach ($cluster_virtual_interface->mvia_address as $mvia_address) {
                            $tmp_interface->addIPaddress($mvia_address['address'] . "/" . $network_value_cidr[1]);
                        }
                        $ipInterfaces["$interface_id"] = $tmp_interface;
                    }
                }
            }

            foreach ($fw_cluster->firewall_node as $firewall_node){
                if(strcmp($firewall_node['disabled'],'false')==0){
                    foreach ($firewall_node->node_interface as $node_interface){
                        $nicid = $node_interface['nicid'];
                        $nicid2 = explode(".", $nicid);
                        $interface_id = $nicid2[0]+1;

                        $network_value = explode("/",$node_interface['network_value']);
                        $cidr = $network_value[1];

                        if(isset($nicid2[1])){
                            //This is a VLAN
                            $vlan_tag = $nicid2[1];
                            $interface_id = $nicid2[0]+1;
                            $unitName = "ethernet1/$interface_id";
                            $VunitName = "$unitName.$vlan_tag";

//                            echo print_r($nicid, true);
//                            echo "$VunitName\n";
//                            echo print_r($ipInterfaces, true);

                            /* @var FwInterface $ipInterfaces["$VunitName"] */
                            if(!isset($ipInterfaces["$VunitName"])) {
                                $tmp_interface = clone $ipInterfaces["$interface_id"];

                                $tmp_interface->interfaceName = $unitName;
                                $tmp_interface->unitName = $VunitName;
                                $tmp_interface->vlan_tag = $vlan_tag;
                                $tmp_interface->warning = 'Interface ['.$VunitName.'] was not defined in the cluster';
                                $ipInterfaces["$VunitName"] = $tmp_interface;
                            }

                            foreach ($node_interface->mvia_address as $mvia_address){
                                $ipInterfaces["$VunitName"]->addIPaddress($mvia_address['address']."/".$cidr);
                            }
                        }
                        else{
                            if(!isset($ipInterfaces["$interface_id"])) {
                                $interfaceName = "ethernet1/$interface_id";
                                $unitName = $interfaceName;
                                $interface = new FwInterface("ethernet", "ethernet1/$interface_id", "layer3", "Review this interface", $unitName, "", "");
                                $ipInterfaces["$interface_id"]=$interface;
                            }

                            if(isset($node_interface['network_value'])){
                                $ipInterfaces["$interface_id"]->addIPaddress($node_interface['network_value']);
                            }

                            foreach ($node_interface->mvia_address as $mvia_address){
                                $ipInterfaces["$interface_id"]->addIPaddress($mvia_address['address']."/".$cidr);
                            }
                        }
                    }
                }
            }

            foreach ($fw_cluster->fw_single_interface as $fw_single_interface){
                $nicid = $fw_single_interface['nicid'];
                $nicid2 = explode(".", $nicid);
                $interface_id = $nicid2[0]+1;

                $network_value = explode("/",$fw_single_interface['network_value']);
                $cidr = $network_value[1];

                if(isset($nicid2[1])){
                    //This is a VLAN
                    $vlan_tag = $nicid2[1];
                    $interface_id = $nicid2[0]+1;
                    $unitName = "ethernet1/$interface_id";
                    $VunitName = "$unitName.$vlan_tag";

//                            echo print_r($nicid, true);
//                            echo "$VunitName\n";
//                            echo print_r($ipInterfaces, true);

                    if(isset($ipInterfaces["$VunitName"])) {
                        $tmp_interface = $ipInterfaces["$VunitName"];
                    }
                    else{
                        echo "$VunitName was not defined\n";
                        echo print_r($fw_single_interface, true);
                        $tmp_interface = clone $ipInterfaces["$interface_id"];

                        $tmp_interface->interfaceName = $unitName;
                        $tmp_interface->unitName = $VunitName;
                        $tmp_interface->vlan_tag = $vlan_tag;
                        $tmp_interface->warning = 'Interface ['.$VunitName.'] was not defined in the cluster';
                        $ipInterfaces["$VunitName"] = $tmp_interface;

                    }

                    foreach ($fw_single_interface->mvia_address as $mvia_address){
                        $tmp_interface->addIPaddress($mvia_address['address']."/".$cidr);
                    }
                    $ipInterfaces["$VunitName"] = $tmp_interface;
                }
                else{
                    $tmp_interface = $ipInterfaces["$interface_id"];
                    foreach ($fw_single_interface->mvia_address as $mvia_address){
                        $tmp_interface->addIPaddress($mvia_address['address']."/".$cidr);
                    }
                    $ipInterfaces["$interface_id"] = $tmp_interface;
                }
            }

            $zoneNumber=1;
            $query ="SELECT max(id) as t FROM interfaces";
            $result = $projectdb->query($query);
            if($result->num_rows>0){
                $data = $result->fetch_assoc();
                $interfaceID = $data['t']+1;
            }
            else{
                $interfaceID = 1;
            }

            foreach ($ipInterfaces as $interfaceName=>$ipInterface){
                if(is_null($ipInterface->zone)){
                    $ipInterface->setZone("Zone$zoneNumber");
                }
                $ipaddresses = array_unique($ipInterface->ipaddresses);
                $all_ipaddress = implode(",", $ipaddresses);
                //(media,source,name,type,comment,unitname,unittag,unitipaddress,template,vsys, zone)
                $add_interface[] = "($interfaceID,'$vrid','$ipInterface->media','$source','$ipInterface->interfaceName','$ipInterface->interfaceType',"
                    . "'$ipInterface->comment','$ipInterface->unitName','$ipInterface->vlan_tag','$all_ipaddress','$template','$vsys','$ipInterface->zone')";
                if(isset($ipInterface->warning)){
                    add_log2("warning", 'Reading Device Interfaces', $ipInterface->warning, $source, 'Review','interfaces',$interfaceID,'interfaces');
                }
                $interfaceID++;

                //Add zones with Interface name
                //(source,name,vsys,type,interfaces,template)
                $zones[] = "('$source','$ipInterface->zone','$vsys','$ipInterface->interfaceType','$ipInterface->unitName','$template')";
                $zoneNumber++;
            }
        }
    }

    if (count($add_interface) > 0) {
        $out = implode(",", $add_interface);
        $projectdb->query("INSERT INTO interfaces (id, vr_id, media,source,name,type,comment,unitname,unittag,unitipaddress,template,vsys, zone) VALUES " . $out . ";");
    }

    if (count($zones)>0){
        $out = implode(",", $zones);
        $projectdb->query("INSERT INTO zones (source,name,vsys,type,interfaces,template) VALUES " . $out . ";");
    }

    //Check if the tunnel interface is needed.
    $tunnelData = $projectdb->query("SELECT id FROM interfaces WHERE type='tunnel' AND unittag ='' AND name='tunnel' AND vr_id='$vrid' AND source='$source' AND vsys='$vsys'");
    if($tunnelData->num_rows==0) {
        $projectdb->query("INSERT INTO interfaces (vr_id, media,source,name,type,comment,unitname,unittag,unitipaddress,template,vsys, zone) VALUES 
                                                     ('$vrid','tunnel','$source','tunnel','tunnel','','tunnel','','','$template','$vsys','')");
    }
}

/***
 * @param SimpleXMLElement $configuration
 * @param STRING $policyName
 * @param STRING $source
 * @param STRING $vsys
 * @param STRING $template
 */
function get_static_routes(SimpleXMLElement $configuration, STRING $policyName, STRING $source, STRING $vsys, STRING $template) {
    global $projectdb;
    global $vrid;

    if(!isset($objectsInMemory)){
        $objectsInMemory = [];
    }


    $addRoutes = array();
    $used_interfaces = array();

    $routing_nodes = $configuration->xpath("//routing_node");
    foreach ($routing_nodes as $routing_node) {
        if(strcasecmp($policyName, normalizeNames($routing_node['name']))==0){

            $addRoutes = array();
            $vr = "vr_" . $vsys;
            $normalized_vsys = normalizeNamesNew($vsys, 8,'vsys');
            $isDup = $projectdb->query("SELECT id FROM virtual_routers WHERE template='$template' AND name='$vr' AND source='$source' AND vsys='$normalized_vsys';");
            if ($isDup->num_rows == 0) {
                $projectdb->query("INSERT INTO virtual_routers (name,template,source,vsys) VALUES ('$vr','$template','$source','$vsys');");
                $vrid = $projectdb->insert_id;
            } else {
                $get = $isDup->fetch_assoc();
                $vrid = $get['id'];
            }

            $x = 1;
            $count="";

            $used_interfaces = array();

            //Loading the routes defined for each interface
            foreach($routing_node->interface_rn_level as $interface_rn_level){
                $interfaceI = explode (".", $interface_rn_level['nicid']);
                $interfaceNumber = $interfaceI[0]+1;
                $interfaceID = "ethernet1/$interfaceNumber";

                if(isset($interfaceI[1])){
                    $interfaceID= "$interfaceID.$interfaceI[1]";
                }
                $used_interfaces[$vrid][] = $interfaceID;


                foreach ($interface_rn_level->network_rn_level as $network_rn_level){
//                    $network_source = $network_rn_level['ne_ref'];
                    foreach ($network_rn_level->gateway_rn_level as $gateway_rn_level){
                        $ip_gateway = $gateway_rn_level['ipaddress'];
                        foreach ($gateway_rn_level->any_rn_level as $any_rn_level){
                            $destination = $any_rn_level['ne_ref'];
                            if(strcasecmp($destination, "Any network")==0){
                                $member = new MemberObject();
                                $member->value = "0.0.0.0";
                                $member->cidr = "0";
                                $found=1;
                            }else {
                                $member = new MemberObject();
                                if (isset($destination, $vsys, $source, $objectsInMemory)) {
                                    $found = searchAddressIPandCIDR($destination, $vsys, $source, $member, $objectsInMemory);
                                }else{
                                    $found = 0;
                                }
                            }

                            if($found){
//                                $routename = "";
                                $metric = "10";

                                //Default routes
                                if (($member->value === "0.0.0.0") && ( $member->cidr === "0")) {
                                    $routename = "default ".$count;
                                    $count++;
                                    $route_network = "0.0.0.0/0";
                                }
                                //Specific routes
                                else {
                                    $routename = "Route " . $x;
                                    $x++;
                                    $route_network = "$member->value/$member->cidr";
                                }
                                $ip_version = ip_version($member->value);

                                //Create a static_route
                                $zoneName = '';
                                $route_text = "('$zoneName','$source','$vrid','$template','$ip_version','$routename','$route_network','$interfaceID','ip-address','$ip_gateway','$metric','$vsys' )";
                                //$used_interfaces[$vrid][]=$interfaceID;
                                $addRoutes[] = $route_text;
                            }
                        }
                        foreach ($gateway_rn_level->ipaddress_behind_router as $ipaddress_behind_router) {
                            $metric = '';
                            $ip_gateway = $ipaddress_behind_router['gateway'];
                            $network = $ipaddress_behind_router['ipaddress'];
                            $routename = "Route " . $x;
                            $x++;
                            $zoneName = '';
                            $ip_version = ip_version($network);
                            $route_text = "('$zoneName','$source','$vrid','$template','$ip_version','$routename','$network','$interfaceID','ip-address','$ip_gateway','$metric','$vsys' )";
                            $addRoutes[] = $route_text;
                        }
                    }
                }
            }
        }
    }

    //Insert all the static routes we have found so far
    if (count($addRoutes) > 0) {
        $unique = array_unique($addRoutes);
        $query = "INSERT INTO routes_static (zone,source,vr_id,template,ip_version,name,destination,tointerface,nexthop,nexthop_value,metric,vsys) "
            . "VALUES " . implode(",", $unique) . ";";
        $projectdb->query($query);
        unset($addRoutes);
    }

    if(count($used_interfaces)) {
        foreach ($used_interfaces as $key => $interfaces) {
            $unique = array_unique($interfaces);
            $query = "UPDATE virtual_routers SET interfaces = CONCAT('" . implode(",", $unique) . "',interfaces) WHERE id='$key';";
            $projectdb->query($query);
        }
        unset($used_interfaces);
    }


}

/**
 * Method to identify the existing policies in the configuration file that are candidates to be imported
 * @param String $config_filename Name of the configuration file that we will process to look for policies
 */
function get_FwNames(STRING $config_path, STRING $config_filename){
    global $projectdb;

    $filename = $config_filename;

    if (isXML($config_path) === TRUE) {
        //Create the table policies_to_import if it doesn't exist
        $res = $projectdb->query("SHOW tables LIKE 'policies_to_import'");
        if($res->num_rows==0){
            $query= "CREATE TABLE `policies_to_import` ( 
                `id` INT NOT NULL AUTO_INCREMENT, 
                `filename` VARCHAR(255) NOT NULL,
                `firewall` VARCHAR(255) NOT NULL, 
                `policyname` VARCHAR(255), 
                `selected` INT(1) NOT NULL DEFAULT 0, 
                `processed` TIMESTAMP NULL, 
                PRIMARY KEY (`id`));";
            $projectdb->query($query);
        }

        //$devicegroup = $config_filename;
        $xml = simplexml_load_string(file_get_contents($config_path));
        $fw_single = $xml->xpath("//fw_single");
        $fw_clusters = $xml->xpath("//fw_cluster");
        $fw_virtual = $xml->xpath("//fw_virtual");
        $fw_cluster_and_single = array_merge($fw_single, $fw_clusters, $fw_virtual);
        foreach ($fw_cluster_and_single as $fw_policy){
            $fwName = normalizeNames($fw_policy["name"]); //normalize the FW name as it could contain special characters
            //Check if this policy was already loaded before
            $query = "SELECT id FROM policies_to_import WHERE filename='$filename' AND firewall='$fwName';";
            $isDup = $projectdb->query($query);
            if ($isDup->num_rows == 0) {
                $query = "INSERT into policies_to_import (filename, firewall, selected) VALUES ('$filename','$fwName','0');";
            }
            $projectdb->query($query);
        }
    }
}

function get_PolicyNames(STRING $config_path, STRING $config_filename){
    global $projectdb;

    $filename = $config_filename;
    $policies = array();

    if (isXML($config_path) === TRUE) {
        $xml = simplexml_load_string(file_get_contents($config_path));
        $fw_policies = $xml->xpath("//fw_policy");
        foreach ($fw_policies as $fw_policy){
            $policies[] = [
                'name'=> normalizeNames($fw_policy["name"]->__toString())
            ];
        }
    }

    return $policies;
}

/**
 * Method to identify the existing domain_names that may be required in the policy
 */
function get_DomainNames($config_path, $config_filename){
    global $projectdb;
    //$filename = $config_filename;

    if (isXML($config_path) === TRUE) {
        //Create the table policies_to_import is it doesn't exist
        $res = $projectdb->query("SHOW tables LIKE 'domain_names'");
        if($res->num_rows==0){
            $query= "CREATE TABLE `domain_names` ( "
                . "`id` INT NOT NULL AUTO_INCREMENT, "
                . "`name` VARCHAR(255) NOT NULL, "
                . "`ipaddress` VARCHAR(255) NOT NULL, "
                . "`description` VARCHAR(255) NOT NULL, "
                . "PRIMARY KEY (`id`));";
            $projectdb->query($query);
        }
        //$devicegroup = $config_filename;
        $xml = simplexml_load_string(file_get_contents($config_path));
        $domain_names = $xml->xpath("//domain_name");

        foreach ($domain_names as $domain_name){
            $name = $domain_name["name"];
            $description = normalizeNames($domain_name["comment"]);
            //Get the main IP
            //$ipaddress = gethostbyname($name);
            $ipaddress = $name;
            $query = "INSERT INTO domain_names (name, ipaddress, description) VALUES ('$name','$ipaddress','$description');";
            $projectdb->query($query);
        }
    }


}

/**
 *
 * @param string $object_name name of the object being searched
 * @param int $lid ID of the found object
 * @param string $table table wher ethe object has been found
 * @param string $vsys Virtual system used
 * @param int $source Source used
 *@global mysqli $projectdb
 */
function searchAddress_orCreate(string $valueNorm, string $vsys, int $source, int &$lid, string &$table, array &$objectsInMemory, string &$member_cidr="", string &$member_ipaddress=""){
    global $projectdb;

    $vsyses = getVsyses($projectdb, $vsys, $source);

    foreach($vsyses as $localVsys){
        $localVsys = normalizeNamesNew($localVsys, 9, 'vsys');
        //print_r($objectsInMemory['address'][$localVsys]);

        if (isset($objectsInMemory['address'][$localVsys][$valueNorm])) {
            $lid = $objectsInMemory['address'][$localVsys][$valueNorm]['id'];
            if(isset($objectsInMemory['address'][$localVsys][$valueNorm]['ipaddress'])) {
                $member_ipaddress = $objectsInMemory['address'][$localVsys][$valueNorm]['ipaddress'];
            }
            if(isset($objectsInMemory['address'][$localVsys][$valueNorm]['cidr'])) {
                $member_cidr = $objectsInMemory['address'][$localVsys][$valueNorm]['cidr'];
            }
            $table = 'address';
            if(isset($objectsInMemory['address'][$localVsys][$valueNorm]['validity'])){
                return $objectsInMemory['address'][$localVsys][$valueNorm]['validity'];
            }
            return true;
        }

        if (isset($objectsInMemory['address_groups_id'][$localVsys][$valueNorm])) {
            $lid = $objectsInMemory['address_groups_id'][$localVsys][$valueNorm]['id'];
            $table = 'address_groups_id';
            return true;
        }
    }

    //Check if we can get the ipaddress from the name
    $ipaddress_version="noip";
    $ipAddress=$subnetMask="";
    preg_match('/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})_(\d+)/', $valueNorm, $matches);
    if(isset($matches[1])){
        $ipAddress = $matches[1];
        if(isset($matches[2])) {
            $subnetMask = $matches[2];
        }
    }

    //The object was not found. Let's create it with a warning
    $query = "INSERT INTO address (name, name_ext, used, checkit, devicegroup, vsys, type, ipaddress, cidr, description, fqdn, v4, v6, vtype, source, tag, zone, invalid, modified, dummy, disable_override, merge_as_primary) 
                VALUE ('$valueNorm','$valueNorm',1,1,'MT','$vsys','ip-address','$ipAddress','$subnetMask','Object automatically generated because was not found',0,1,0,'',$source,'','',1,0,0,0,0)";
    $projectdb->query($query);
    $lid = $projectdb->insert_id;
    add_log2('error', 'Address Object', 'The Address [' . $valueNorm . '] is not declared on the policy but it is used. Expedition created it.', $source, 'Check that the created object is correct', 'objects', $lid, 'address');
    $objectsInMemory['address'][$localVsys][$valueNorm]['id'] = $lid;
    $objectsInMemory['address'][$localVsys][$valueNorm]['validity'] = false;
    $table = 'address';

    return false;

   /* $getAddress = $projectdb->query("SELECT id FROM address WHERE BINARY name_ext='$object_name' AND source='$source' AND vsys='$vsys';");
    if ($getAddress->num_rows > 0){
        $myData = $getAddress->fetch_assoc();
        $lid = $myData['id'];
        $table = 'address';
        return true;
    }

    else{
        $getAddress = $projectdb->query( "SELECT id FROM address_groups_id WHERE BINARY name_ext='$object_name' AND source='$source' AND vsys='$vsys';");
        if ($getAddress->num_rows > 0){
            $myData = $getAddress->fetch_assoc();
            $lid = $myData['id'];
            $table = 'address_groups_id';
            return true;
        }
    }
    return false;*/
}

function searchAddressIPandCIDR(string $valueNorm, string $vsys, int $source, &$member, array &$objectsInMemory){
    global $projectdb;

    if (isset($objectsInMemory['address'][$vsys][$valueNorm])){
        $member = new MemberObject($valueNorm, 'address', $objectsInMemory['address'][$vsys][$valueNorm]['ipaddress'], $objectsInMemory['address'][$vsys][$valueNorm]['cidr']);
        return 1;
    }

    /*$query = "SELECT id, ipaddress, cidr FROM address WHERE BINARY name_ext='$object_name' AND source='$source' AND vsys='$vsys';";
    $getAddress = $projectdb->query($query);
    if ($getAddress->num_rows > 0){
        $myData = $getAddress->fetch_assoc();
        $member = new MemberObject($object_name, 'address', $myData['ipaddress'], $myData['cidr']);
        return 1;
    }*/
//    
//    else{
//        $getAddress = $projectdb->query( "SELECT id FROM address_groups_id WHERE BINARY name='$object_name' AND source='$source' AND vsys='$vsys';");
//        if ($getAddress->num_rows > 0){
//            $myData = $getAddress->fetch_assoc();
//            $lid = $myData['id'];
//            $table = 'address_groups_id';
//            return true;
//        }
//    }
    return 0;
}

///**
// * Looks for a service or servicegroup name in the resources. First will check the memory space and if it is not provided, will check the database
// * @global mysqli $projectdb
// * @param string $object_name
// * @param string $vsys
// * @param int $source
// * @param int $lid
// * @param string $table
// */
//function searchService_orCreate(string $valueNorm, string $vsys, int $source, int &$lid, string &$table, array &$objectsInMemory){
//    /* @var $projectdb mysqli*/
//    global $projectdb;
//
//    $vsyses = getVsyses($projectdb, $vsys, $source);
//    $valueNorm = normalizeNames($valueNorm);
//
//    //Look for the service in objects in memory
//    foreach ($vsyses as $localVsys){
//        $localVsys = normalizeNamesNew($localVsys, 9, 'vsys');
//        if (isset($objectsInMemory['services'][$localVsys][$valueNorm])) {
//            $lid = $objectsInMemory['services'][$localVsys][$valueNorm]['id'];
//            $table = 'services';
//            return true;
//        }
//
//        if (isset($objectsInMemory['services_groups_id'][$localVsys][$valueNorm])) {
//            $lid = $objectsInMemory['services_groups_id'][$localVsys][$valueNorm]['id'];
//            $table = 'services_groups_id';
//            return true;
//        }
//    }
//
//    //Maybe it is not in objects in memory, but it is in the database. Search for it and complete the objectsInMemory
//    foreach($vsyses as $localVsys){
//        $query = "SELECT id, dport FROM services WHERE source = '$source' AND vsys='$localVsys' AND name = '$valueNorm' LIMIT 1";
//        $result = $projectdb->query($query);
//        if($result->num_rows == 0){
//            continue;
//        }
//        $data = $result->fetch_assoc();
//        $objectsInMemory['services'][$localVsys][$valueNorm]= [
//            'id' => $data['id'],
//            'dport' => $data['dport']
//        ];
//        $lid = $data['id'];
//        $table = 'services';
//        return true;
//    }
//
//
//    //The object was not found. Let's create it with a warning
//    $query = "INSERT INTO services (name, name_ext, checkit, used, vsys, devicegroup, type, description, sport, dport, protocol, source,invalid, modified, dummy )
//              VALUE ('$valueNorm','$valueNorm',1,1,'$vsys','MT1','service','Object automatically generated because was not found','','65000','tcp',$source,1,0,0)";
//    $projectdb->query($query);
//    $lid = $projectdb->insert_id;
//    $objectsInMemory['services'][$localVsys][$valueNorm]['id'] = $lid;
//    $objectsInMemory['services'][$localVsys][$valueNorm]['validity'] = false;
//    $table ="services";
//
//    return false;
//}

/**
 *
 * @global mysqli $projectdb
 * @param SimpleXMLElement $configuration  XML file with the configuration
 * @param STRING $policy_to_load Name of the policy to load
 * @param STRING $vsys
 * @param int $source
 * @param STRING $project
 */
function get_NATs(SimpleXMLElement $configuration, STRING $policy_to_load, STRING $source, STRING $project, ARRAY &$objectsInMemory) {
    global $like_panorama;
    global $shared_dg_name;
    global $projectdb;
    global $vrid;
    global $match_expressionsInMemory;
    global $overrideNatZones;

    global $invalid_tag_id;

    $vsys = normalizeNames($policy_to_load);

    $Natcounter = 0;
    $nat_lid = "";
    $nat_position = "";

    $nat_sources = array();
    $nat_destinations=  array();
    $add_nat_translated_source_address = array();

    renewDBConnection();
    #Get Last lid from Profiles
    $getPosition = $projectdb->query("SELECT max(position) as t FROM nat_rules;");
    if ($getPosition->num_rows === 0) {
        $nat_position = 1;
    } else {
        $ddata = $getPosition->fetch_assoc();
        $nat_position = $ddata['t'] + 1;
    }
    if ($nat_lid === "") {
        $getlastlid = $projectdb->query("SELECT max(id) as max FROM nat_rules;");
        if ($getlastlid->num_rows === 1) {
            $getLID1 = $getlastlid->fetch_assoc();
            $nat_lid = (int)$getLID1['max'] + 1;
        } else {
            $nat_lid = 1;
        }
    }


    $mappings = getPolicyMappings($configuration, $policy_to_load, "firewall");

    $fw_policies = $configuration->xpath("//fw_policy");
    $fw_template_policies = $configuration->xpath("//fw_template_policy");
    $fw_policies = array_merge($fw_policies, $fw_template_policies);
    foreach ($fw_policies as $fw_policy){
//        $isInMapping = in_array((string)$fw_policy['name'], $mappings, false);
//        if(strcasecmp($fw_policy["name"],$policy_to_load)===0 || $isInMapping){
        if((string)$fw_policy['name'] === $policy_to_load){
            if($like_panorama){
//                $common_vsys = $shared_dg_name;
                $common_vsys = $vsys;
            }
            else{
                $common_vsys = $vsys;
            }
//            //Check if this NAT policy has a template
//            if (isset($fw_policy["template_policy_ref"])){
//                $template_name = $fw_policy["template_policy_ref"];
//                get_NATs($configuration, $template_name, $vsys, $source, $project,$objectsInMemory);
//
//                $getPosition = $projectdb->query("SELECT max(position) as t FROM nat_rules WHERE vsys='$vsys' AND source='$source';");
//                if ($getPosition->num_rows === 0) {
//                    $nat_position = 1;
//                } else {
//                    $ddata = $getPosition->fetch_assoc();
//                    $nat_position = $ddata['t'] + 1;
//                }
//
//                $getlastlid = $projectdb->query("SELECT max(id) as max FROM nat_rules;");
//                if ($getlastlid->num_rows === 1) {
//                    $getLID1 = $getlastlid->fetch_assoc();
//                    $nat_lid = (int)$getLID1['max'] + 1;
//                } else {
//                    $nat_lid = 1;
//                }
//            }

            $nat = array();

            $addTag = array();
            $comments = array();
            $tagids = array();

            $done_with_tags=true;
            foreach ($fw_policy->nat_entry->rule_entry as $rule_entry){
                $localtag="";
                $is_nat_disabled = strcmp($rule_entry["is_disabled"], "true")===0 ? 1 : 0;

                $rule_tag     = $rule_entry["tag"];
                $name_int = "";
                $description = "";

                // rule_entry 's can be descriptions/tag of rules or rules themselves
                // Tags come consecutively before the tagged rules
                $done_with_tags = true;

                //LOOKING FOR TAGS IN THE RULES
                // Empty rule_entry (empty meaning they do not have access_rule child) are threated as tags
                if(isset($rule_entry->comment_rule)){
                    //echo "This is a covering COMMENT. It may be defining it, or removing the comment\n";
                    if($done_with_tags==true) {
                        $done_with_tags=false;
                        unset($tagids); //Reset the tag(s) used until now
                        unset($comments);
                    }

                    $comment=addslashes($rule_entry["comment"]);
                    if(isset($comment) && strcmp($comment,"")!==0) {
                        $comments[] = $comment;
                    }

                }

                // NAT CONTENT
                else{
                    $done_with_tags=true; //We found a rule with content. Therefore, we are done parsing tags

                    $nat_rule = $rule_entry->nat_rule;
                    $action = $nat_rule->action;
                    if(!isset($action)){
                        //TODO: "This rule is VPN\n";
                        continue;
                    }

                    // "This rule is NOT a covering Comment, but may have a comment\n";
                    $comment = addslashes($rule_entry["comment"]);
                    if(isset($comment) && strcmp($comment, "")!==0){
                        $localComment = $comment;
                    }
                    else{
                        $localComment = '';
                    }

                    $action_type = $nat_rule->action["type"];

                    if(!isset($nat_rule->match_part)) {
                        //TODO: "Sorry, this NAT does not have rule to do a match. Something can't be right"
                    }
                    else{
                        $match_part = $nat_rule->match_part;

                        $member_lid = 0;
                        $table_name = "";
                        //NAT matching sources
                        foreach ($match_part->match_sources->match_source_ref as $match_source) {
                            $source_type = trim($match_source["type"]);
                            $expressionName = $match_source["value"];
                            $value = trim(normalizeNames((string)$match_source["value"]));
                            if($source_type === "match_expression"){
                                if(isset($match_expressionsInMemory["$expressionName"]['zones'])){
                                    //There is a Source Zone override
                                    $overrideNatZones[(string)$nat_lid]['from'] = $match_expressionsInMemory[(string)$expressionName]['zones'];
                                }
                                foreach ($match_expressionsInMemory["$expressionName"]['objects'] as $member) {
                                    $nat_sources[] = $member;
                                }
                            }
                            else {
                                if(strcmp($value, "ANY")!==0 && strcmp($value, "none")!==0){
                                    //$found = searchAddress($value, $common_vsys, $source, $member_lid, $table_name,$objectsInMemory);
                                    if(!searchAddress_orCreate($value, $common_vsys, $source, $member_lid, $table_name,$objectsInMemory)){
//                                        $is_nat_disabled = 1;
                                        add_log2("warning", 'Reading NAT Policy', 'Rule[' . $nat_lid . ']. Source address not recognized: ['.$value.']', $source, 'Consider removing rule if only valid for Palo Alto Networks configurations','rules',$nat_lid,'nat_rules');
                                    }
//                                    else {
//                                        echo "Nat $nat_lid uses the source $value and has been found in $table_name - $member_lid\n";
//                                        $nat_sources[] = "('$source','$common_vsys','$table_name','$member_lid','$nat_lid')";
//                                    }
                                    $nat_sources[] = "('$source','$common_vsys','$table_name','$member_lid','$nat_lid')";

                                }
                            }
                        }

                        //NAT matching destinations
                        foreach ($match_part->match_destinations->match_destination_ref as $match_destination) {
                            $source_type = trim($match_destination["type"]);
                            $expressionName = $match_destination["value"];
                            $value = trim(normalizeNames($match_destination["value"]));
                            if($source_type === "match_expression"){
                                if(isset($match_expressionsInMemory["$expressionName"]['zones'])){
                                    //There is a Source Zone override
                                    $overrideNatZones["$nat_lid"]['to']=$match_expressionsInMemory["$expressionName"]['zones'];
                                }
                                foreach ($match_expressionsInMemory["$expressionName"]['objects'] as $member) {
                                    $nat_destinations[] = $member;
                                }
                            }
                            else {
                                if(strcmp($value, "ANY")!==0 && strcmp($value, "none")!==0){
                                    if(!searchAddress_orCreate($value, $common_vsys, $source, $member_lid, $table_name,$objectsInMemory)){
//                                        $is_nat_disabled = 1;
                                        add_log2("warning", 'Reading NAT Policy', 'Rule[' . $nat_lid . ']. Destination address not recognized: ['.$value.']', $source, 'Consider removing rule if only valid for Palo Alto Networks configurations','rules',$nat_lid,'nat_rules');
                                    }
//                                    else {
//                                        $nat_destinations[] = "('$source','$common_vsys','$table_name','$member_lid','$nat_lid')";
//                                    }
                                    $nat_destinations[] = "('$source','$common_vsys','$table_name','$member_lid','$nat_lid')";
                                }
                            }
                        }

                        $nat_services = array();
                        //NAT matching services
                        foreach ($match_part->match_services->match_service_ref as $match_service) {
                            $value = trim(normalizeNames($match_service["value"]));
                            if(strcmp($value,"ANY")===0){
                                //Set here an empty Service
                                $member = new MemberObject('', '','');
                                $nat_services[] = $member;
                            }
                            else{
                                //$found = searchService_orCreate($value, $common_vsys, $source, $member_lid, $table_name,$objectsInMemory);
                                //if(!searchService_orCreate($value, $common_vsys, $source, $member_lid, $table_name,$objectsInMemory)){
                                if(!ServicesMapping::searchOrCreateService($projectdb, $value, $common_vsys, $source, $member_lid, $table_name,$objectsInMemory)){
                                    $member = new MemberObject($value,$table_name,$member_lid);
                                    $nat_services[] = $member;//"('$source','$common_vsys','$table_name','$member_lid','$nat_lid')";
                                }
                                else {
                                    add_log2("warning", 'Reading NAT Policy', 'Rule[' . $nat_lid . ']. Service not recognized: ['.$value.']', $source, 'Consider removing rule if only valid for Palo Alto Networks configurations','rules',$nat_lid,'nat_rules');

//                                    $service_name_ext = $value;
//                                    $service_name_int = truncate_names(normalizeNames($service_name_ext));
//                                    $description = $service_name_ext;
//                                    //Adding the service in the system as an invalid service
//                                    $query ="INSERT INTO services (type,name_ext,name,protocol,dport,checkit,description,source,sport,vsys, invalid, devicegroup)
//                                            VALUES ('','$service_name_ext','$service_name_int','tcp','65000','1','$description','$source','','$common_vsys', '1','Expedition created 2');";
//                                    $projectdb->query($query);
//                                    $member_lid = $projectdb->insert_id;
//                                    $projectdb->query( "INSERT INTO tag_relations (table_name, member_lid, tag_id) VALUES ('services','$member_lid','$invalid_tag_id')");
//                                    $member = new MemberObject($value, 'services',$member_lid);
//                                    $nat_services[] = $member; //"('$source','$common_vsys','services','$member_lid','$nat_lid')";
//                                    $valueNorm=normalizeNames($service_name_ext);
//                                    $objectsInMemory['services'][$common_vsys][$valueNorm]['id']=$member_lid;
//                                    $objectsInMemory['services'][$common_vsys][$valueNorm]['dport']="65000";
                                }
                                $member = new MemberObject($value,$table_name,$member_lid);
                                $nat_services[] = $member;//"('$source','$common_vsys','$table_name','$member_lid','$nat_lid')";

                            }
                        }

                        if(count($nat_services)>1){
                            renewDBConnection();
                            //TODO: Make a group of services, and get the lid. This will be the op_service_lid and  op_service_table
                            //      will be services_groups_id
                            $groupNumber = (int)$Natcounter+1;
                            $Nat_Servicename_ext = normalizeNames("NAT-$nat_lid-ServiceGroup($groupNumber)");
                            $Nat_Servicename_int = truncate_names(normalizeNames($Nat_Servicename_ext));
                            $valueNorm=normalizeNames($Nat_Servicename_ext);

                            $query = "INSERT INTO services_groups_id (name_ext,name,checkit,source,vsys) values('$Nat_Servicename_ext','$Nat_Servicename_int','0','$source','$common_vsys');";
                            $projectdb->query($query);
                            $op_service_lid = $projectdb->insert_id;
                            $op_service_table = "services_groups_id";

                            $objectsInMemory['services_groups_id'][$common_vsys][$valueNorm]['id']=$op_service_lid;

                            foreach ($nat_services as $nat_service){
                                $query = "INSERT INTO services_groups (lid,member,source,member_lid,table_name,vsys) VALUES ('$op_service_lid','$nat_service->name','$source','$nat_service->value','$nat_service->location','$common_vsys');";
                                $projectdb->query($query);
                            }

                            $Natcounter++;
                        }
                        else{
                            $op_service_lid=$nat_services[0]->value;
                            $op_service_table=$nat_services[0]->location;
                        }

                        //NAT options
                        if(isset($nat_rule->option)){
                            $invalid_content=1;
                            //Initialization of variables
                            $new_dest_member_lid=0;
                            $new_dest_table_name="";

                            $table_name="";
                            $member_lid=0;
                            $tp_sat_type="";
                            $is_dat=0;
                            $op_zone_to="";
                            $tp_dat_port="";
                            $name_int="";
                            $tp_sat_address_type="";
                            $tp_sat_bidirectional=0;

                            $nat_option = $nat_rule->option;

                            //NAT Source
                            $nat_src = $nat_option->nat_src;

                            //Static source NAT, typically used for translating the internal (“real”) IP address of an internal host to a different
                            //IP address in the external network.
                            if(isset($nat_src->static_nat)){
                                $invalid_content=0;
                                $static_nat = $nat_src->static_nat;
                                //$generate_arp = $static_nat['$generate_arp'];

                                //$packet_description = $static_nat->packet_description['ne_ref'];
                                //searchAddress($packet_description, $common_vsys, $source, $member_lid, $table_name);
                                //$add_nat_src[]="('$source','$common_vsys','$nat_lid','$member_lid','$table_name')";

                                //The outside IP may be defined as a hardcoded value
                                if(isset($static_nat->packet_description_new['min_ip'])){
                                    $min_ip = $static_nat->packet_description_new['min_ip'];
                                    $netmask=$static_nat->packet_description['netmask'];
                                    $cidr = mask2cidrv4($netmask);
                                    if($cidr==0){$cidr=32;}
                                    $packet_description_new = $min_ip;
                                    $name = "$packet_description_new/$cidr";
                                    $query ="INSERT INTO address (name_ext,name,ipaddress,cidr, v4,v6,type,vtype,description, source,vsys,dummy) VALUES ('$name', '$name', '$packet_description_new', '$cidr', 1, 0, 'ip-netmask', '', '', '$source','$common_vsys','1');";
                                    $projectdb->query($query);
                                    $member_lid = $projectdb->insert_id;
                                    $tp_sat_type ="static-ip";
                                    $add_nat_translated_source_address[]="('$source','$common_vsys','$nat_lid','$member_lid','address')";

                                    $objectsInMemory['address'][$common_vsys][$name]['id']=$member_lid;
                                    $objectsInMemory['address'][$common_vsys][$name]['ipaddress']=$packet_description_new;
                                    $objectsInMemory['address'][$common_vsys][$name]['cidr']=$cidr;
                                }
                                //The outside IP may be defined as an address already registered
                                else{
                                    $packet_description_new = trim(normalizeNames($static_nat->packet_description_new['ne_ref']));
                                    $tp_sat_type ="static-ip";
                                    $tp_sat_address_type ="translated_address";
                                    searchAddress_orCreate($packet_description_new,  $common_vsys, $source, $member_lid, $table_name,$objectsInMemory);
                                    $add_nat_translated_source_address[]="('$source','$common_vsys','$nat_lid','$member_lid','$table_name')";
                                }
                            }

                            //Dynamic source NAT, typically used to translate the internal IP addresses of several internal hosts to one or a few external
                            //IP addresses to hide the internal network structure from outsiders and to avoid acquiring a separate public IP address for each of the hosts.
                            if(isset($nat_src->dynamic_nat)){
                                $invalid_content=0;
                                $dynamic_nat=$nat_src->dynamic_nat;
                                //$generate_arp = $dynamic_nat['$generate_arp'];

                                if(!isset($dynamic_nat->packet_description['first_port'])){
                                    $tp_sat_type = "dynamic-ip";
                                    $packet_description_new = trim(normalizeNames($dynamic_nat->packet_description['ne_ref']));
                                    searchAddress_orCreate($packet_description_new,  $common_vsys, $source, $member_lid, $table_name,$objectsInMemory);
                                    $add_nat_translated_source_address[]="('$source','$common_vsys','$nat_lid','$member_lid','$table_name')";
                                }
                                else{
                                    $first_port = $dynamic_nat->packet_description['first_port'];
                                    $last_port  = $dynamic_nat->packet_description['last_port'];
                                    $tp_sat_type = "dynamic-ip-and-port";
                                    $tp_sat_address_type ="translated-address";
                                    //$tp_dat_port = $first_port."-".$last_port;

                                    if(isset($dynamic_nat->packet_description['min_ip'])){
                                        $min_ip = $dynamic_nat->packet_description['min_ip'];
                                        $netmask=$dynamic_nat->packet_description['netmask'];
                                        $cidr = mask2cidrv4($netmask);
                                        if($cidr==0){$cidr=32;}
                                        $packet_description_new = $min_ip;
                                        $name = "$packet_description_new/$cidr";
                                        //Insert the new object into the address table
                                        $query ="INSERT INTO address (name_ext,name,ipaddress,cidr, v4,v6,type,vtype,description, source,vsys,dummy) VALUES ('$name', '$name', '$packet_description_new', '$cidr', 1, 0, 'ip-netmask', '', '', '$source','$common_vsys','1');";
                                        $projectdb->query($query);
                                        $member_lid = $projectdb->insert_id;
                                        $add_nat_translated_source_address[]="('$source','$common_vsys','$nat_lid','$member_lid','address')";
                                        $objectsInMemory['address'][$common_vsys][$name]['id']=$member_lid;
                                        $objectsInMemory['address'][$common_vsys][$name]['ipaddress']=$packet_description_new;
                                        $objectsInMemory['address'][$common_vsys][$name]['cidr']=$cidr;

                                    }
                                    else{
                                        $packet_description_new = trim(normalizeNames($dynamic_nat->packet_description['ne_ref']));
                                        searchAddress_orCreate($packet_description_new,  $common_vsys, $source, $member_lid, $table_name,$objectsInMemory);
                                        $add_nat_translated_source_address[]="('$source','$common_vsys','$nat_lid','$member_lid','$table_name')";
                                    }
                                }
                            }


                            //NAT Destination
                            $nat_dst = $nat_option->nat_dst;
                            if(isset($nat_dst->static_nat)){
                                $invalid_content=0;
                                $static_nat = $nat_dst->static_nat;
                                $is_dat=1;
                                //$generate_arp = $static_nat['$generate_arp'];
                                //$packet_description = $static_nat->packet_description['ne_ref'];
                                //searchAddress($packet_description, $common_vsys, $source, $member_lid, $table_name);
                                //$add_nat_dst[]="('$source','$common_vsys','$nat_lid','$member_lid','$table_name')";

                                if(isset($static_nat->packet_description_new['ne_ref'])){
                                    $packet_description_new = trim(normalizeNames($static_nat->packet_description_new['ne_ref']));
                                    searchAddress_orCreate($packet_description_new, $common_vsys, $source, $new_dest_member_lid, $new_dest_table_name,$objectsInMemory);
                                    //$first_port = $static_nat->packet_description['first_port'];
                                    //$last_port = $static_nat->packet_description['last_port'];
                                    $first_new_port = $static_nat->packet_description_new['first_port'];
                                    //$last_new_port = $static_nat->packet_description_new['last_port'];
                                    $tp_dat_port = $first_new_port;
                                }
                                else{
                                    $min_ip = $static_nat->packet_description_new['min_ip'];
                                    $netmask=$static_nat->packet_description['netmask'];
                                    $cidr = mask2cidrv4($netmask);
                                    if($cidr==0){$cidr=32;}
                                    $packet_description_new = $min_ip;
                                    $name = "$packet_description_new/$cidr";

                                    $query ="INSERT INTO address (name_ext,name,ipaddress,cidr, v4,v6,type,vtype,description, source,vsys,dummy) VALUES ('$name', '$name', '$packet_description_new', '$cidr', 1, 0, 'ip-netmask', '', '', '$source','$common_vsys','1');";
                                    $projectdb->query($query);
                                    $new_dest_member_lid = $projectdb->insert_id;
                                    $new_dest_table_name = "address";

                                    $objectsInMemory['address'][$common_vsys][$name]['id']=$new_dest_member_lid;
                                    $objectsInMemory['address'][$common_vsys][$name]['ipaddress']=$packet_description_new;
                                    $objectsInMemory['address'][$common_vsys][$name]['cidr']=$cidr;

                                    //$first_port = $static_nat->packet_description['first_port'];
                                    //$last_port = $static_nat->packet_description['last_port'];
                                    $first_new_port = $static_nat->packet_description_new['first_port'];
                                    //$last_new_port = $static_nat->packet_description_new['last_port'];
                                    $tp_dat_port = $first_new_port;
                                }

                                //$add_nat_translated_destination_address[]="('$source','$common_vsys','$nat_lid','$member_lid','$table_name')";
                            }

//                                if($invalid_content){
//                                    $is_nat_disabled = 1;
//                                    $nat_tag = $rule_entry['tag'];
//                                    //add_log2("warning", 'Reading NAT Policy', 'Rule[' . $nat_lid . ']. Does not have NAT information. Please verify NAT rule with original tag="'. $nat_tag. '"', $source, 'Remove rule','rules',$nat_lid,'nat_rules');
//                                }

                            $natDescription = 'Tag['.$rule_tag.']';
                            if(isset($comments) && count($comments)>0) {
                                $natDescription .= ' '. implode('. ', $comments);
                                $natDescription .= '. ' . $localComment;
                            }

                            $nat[] = "('$is_nat_disabled','$nat_lid','$nat_position','$source','$common_vsys','$op_zone_to','NAT $nat_lid','$tp_sat_type','$tp_sat_address_type', '$op_service_lid','$op_service_table','$is_dat','$tp_dat_port','$new_dest_member_lid','$new_dest_table_name','$tp_sat_bidirectional','$natDescription')";
                            $nat_lid++;
                            $nat_position++;
                        }

                        //Convert from Array of Tag-strings to SQL string value
                        if(isset($tagids)){
                            foreach ($tagids as $tagid){
                                $addTag[] = "('$source','$common_vsys','$nat_lid','$tagid','tag')";
                            }
                        }
                        if(isset($localtag) && strcmp($localtag,"")!=0){
                            $addTag[] = "('$source','$common_vsys','$nat_lid','$localtag','tag')";
                        }

                    }
                }
            }


            //Insert NAT matching Rules
            renewDBConnection();
            if (count($nat)>0){
                $query ="INSERT INTO nat_rules (disabled,id,position,source,vsys,op_zone_to,name,tp_sat_type,tp_sat_address_type,"
                    . "op_service_lid,op_service_table,is_dat,tp_dat_port,tp_dat_address_lid,tp_dat_address_table,tp_sat_bidirectional, description) "
                    . "VALUES ".implode(",",$nat).";";
                $projectdb->query($query);
                $nat="";

                if (count($addTag)>0) {
                    $query = "INSERT INTO nat_rules_tag (source,vsys,rule_lid,member_lid, table_name) VALUES ".implode(",",$addTag).";";
                    $projectdb->query($query);
                    $addTag="";
                }

                if (count($nat_sources) > 0){
                    $query ="INSERT INTO nat_rules_src (source,vsys,table_name,member_lid,rule_lid) VALUES " . implode(",", $nat_sources) . ";";
                    $projectdb->query($query);
                }

                if (count($nat_destinations) > 0){
                    $query="INSERT INTO nat_rules_dst (source,vsys,table_name,member_lid,rule_lid) VALUES " . implode(",", $nat_destinations) . ";";
                    $projectdb->query($query);
                }

                if (count($add_nat_translated_source_address)>0){
                    $query = "INSERT INTO nat_rules_translated_address (source,vsys,rule_lid,member_lid,table_name) VALUES ". implode(",",$add_nat_translated_source_address).";";
                    $projectdb->query($query);
//                    $add_nat_translated_source_address="";
                }

//                if (count($add_nat_translated_destination_address)>0){
//                    $query = "INSERT INTO nat_rules_translated_address (source,vsys,rule_lid,member_lid,table_name) VALUES ". implode(",",$add_nat_translated_destination_address).";";
//                    $projectdb->query($query);
//                    $add_nat_translated_destination_address="";
//                }
            }
        }
    }

    set_Zones_Nat($project, $source, $vsys,$vrid);

    //apply Overriden zones
    if(count($overrideNatZones)>0) {
        foreach ($overrideNatZones as $lid => $overrideZone) {
            if (isset($overrideZone['from'])) {
                $zonesFrom = $overrideZone['from'];
                $query = "DELETE FROM nat_rules_from WHERE rule_lid = '$lid'";
                $projectdb->query($query);
                $zoneQuery = array();
                foreach ($zonesFrom as $zone) {
                    $zoneQuery[] = "('$zone','$lid')";
                }
                $query = "INSERT into nat_rules_from (name, rule_lid) VALUES " . implode(',', $zoneQuery);
                $projectdb->query($query);
            }

            if (isset($overrideZone['to'])) {
                $zonesTo = $overrideZone['to'];
                $zone = $zonesTo[0];
                $query = "UPDATE nat_rules SET op_zone_to='$zone' WHERE id = '$lid'";
                $projectdb->query($query);
            }
        }
    }

    fix_Zones_Policies($project, $source, $vsys,$vrid);
}

function set_Zones_Security_Rules($source, $vsys, $vr){
    global $projectdb;

    //$ipMapping = getIPtoZoneRouteMapping($vsys, $source, $vr);
    $ipMapping = getIPtoZoneRouteMapping($vsys, $source, $vr);

    $vsys_normalized = normalizeNamesNew($vsys, 9, 'vsys');
    //$ids_rules = getSecurityIdsBySourceVsys($source, $vsys);
    $ids_rules = getIdsBySourceVsys("security_rules", $source, $vsys_normalized);
//    $query = "SELECT id FROM security_rules WHERE source=$source AND vsys='$vsys_normalized'";
//    echo $query.PHP_EOL;
//    $rules_query = $projectdb->query($query);
//    $ids_rules = [];
//    if($rules_query->num_rows>0){
//        while($rule = $rules_query->fetch_assoc()){
//            $ids_rules[] = $rule['id'];
//        }
//    }


    if (count($ids_rules)>0){
        //Zones FROM
        $getSRC = $projectdb->query("SELECT rule_lid,member_lid,table_name FROM security_rules_src WHERE rule_lid IN (".implode(',', $ids_rules).");");
        if ($getSRC->num_rows > 0) {
            while ($getSRCData = $getSRC->fetch_assoc()) {
                $member_lid = $getSRCData['member_lid'];
                $table_name = $getSRCData['table_name'];
                $rule_lid = $getSRCData['rule_lid'];

                $getDeviceGroup = $projectdb->query("SELECT devicegroup FROM security_rules WHERE id = '$rule_lid';");
                if ($getDeviceGroup->num_rows > 0) {
                    $getINData = $getDeviceGroup->fetch_assoc();
                    $devicegroup = $getINData['devicegroup'];
                }

                $negate_source=0;

                $zones = getAutoZone($ipMapping['ipv4'], $member_lid, $table_name, $negate_source);
                //$zones = getAutoZoneToVR($vr, $member_lid, $table_name, $vsys, $source);

                foreach ($zones as $zone) {
                    $getZone = $projectdb->query("SELECT id FROM security_rules_from WHERE name = '$zone' AND rule_lid = '$rule_lid';");
                    if ($getZone->num_rows == 0) {
                        $projectdb->query("INSERT INTO security_rules_from (rule_lid, name, source, vsys, devicegroup) "
                            . " VALUES ('$rule_lid', '$zone', '$source', '$vsys', '$devicegroup');");
                    }
                }
            }
        }

        //Zones TO
        $getDST = $projectdb->query("SELECT rule_lid,member_lid,table_name FROM security_rules_dst WHERE rule_lid IN (".implode(',', $ids_rules).");");
        if ($getDST->num_rows > 0) {
            while ($getDSTData = $getDST->fetch_assoc()) {
                $member_lid = $getDSTData['member_lid'];
                $table_name = $getDSTData['table_name'];
                $rule_lid = $getDSTData['rule_lid'];

                $getDeviceGroup = $projectdb->query("SELECT devicegroup FROM security_rules WHERE id = '$rule_lid';");
                if ($getDeviceGroup->num_rows > 0) {
                    $getINData = $getDeviceGroup->fetch_assoc();
                    $devicegroup = $getINData['devicegroup'];
                }

                $negate_source=0;

                $zones = getAutoZone($ipMapping['ipv4'], $member_lid, $table_name, $negate_source);
                //$zones = getAutoZoneToVR($vr, $member_lid, $table_name, $vsys, $source);
                foreach ($zones as $zone) {
                    $getZone = $projectdb->query("SELECT id FROM security_rules_to WHERE name = '$zone' AND rule_lid = '$rule_lid' ;");
                    if ($getZone->num_rows == 0) {
                        $projectdb->query("INSERT INTO security_rules_to (rule_lid, name, source, vsys, devicegroup) "
                            . " VALUES ('$rule_lid', '$zone', '$source', '$vsys', '$devicegroup');");
                    }
                }
            }
        }
    }
}

/**
 * Method to identify Members that belong to two groups. A group can be a Member
 * @param MemberObject[] $childMembers.
 * @param MemberObject[] $parentMembers
 * @param mysqli $projectdb
 * @param int $source
 * @param string $vsys
 * @return MemberObject[]
 */
function getCommonMembers($childMembers, $parentMembers, $projectdb, $source, $vsys):array{
    $childMembers = array_sort($childMembers);
    $parentMembers = array_sort($parentMembers);

    //Easy parts. Either childMembers or parentMembers are ANY, or they both have the same members
    //No parent of children sources were defined, so they are ANY
    $tmp_Members = array();

    if((!isset($parentMembers) || count($parentMembers)===0) &&
        (!isset($childMembers) || count($childMembers)===0)     ){
        $member = new MemberObject('ANY', '', '0.0.0.0', '0');
        $tmp_Members=[$member];
    }
    //The Parent policy has an ANY. We use the Child's Sources's members
    elseif(!isset($parentMembers) || count($parentMembers)===0 || strcmp($parentMembers[0]->name, "ANY")===0){
        $tmp_Members=$childMembers;
    }
    //The Child policy has an ANY. We use the Parent's members.
    elseif(!isset($childMembers) || count($childMembers)===0 || strcmp($childMembers[0]->name, "ANY")===0){  //The subpolicy has ANY as a source. We use the Parents source
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
                    if($way===1){
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
                if(!in_array($child, $tmp_Members, false)){
                    $replace_childGroup = false;
                    break;
                }
            }
            foreach ($exploded_parentMembers as $parent){
                if(!in_array($parent, $tmp_Members, false)){
                    $replace_parentGroup = false;
                    break;
                }
            }

            if($replace_childGroup){
                foreach($exploded_childMembers as $child){
                    $key = array_search($child,$tmp_Members, false);
                    if($key!==false){
                        unset($tmp_Members[$key]);
                    }
                }
                $tmp_Members=$childMembers;
            }
            if($replace_parentGroup){
                foreach($exploded_parentMembers as $parent){
                    $key = array_search($parent, $tmp_Members, false);
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
 * @param mysqli $projectdb
 * @param string $source
 * @param string $vsys
 * @return MemberObject[]
 */
function getCommonServices($childServices, $parentServices, mysqli $projectdb, string $source, string $vsys):array{
    //Easy parts. Either childMembers or parentMembers are ANY, or they both have the same members
    //The Parent policy has an ANY. We use the Child's Sources's members

    $tmp_Services = array();
    if( (!isset($parentServices) || count($parentServices)===0) &&
        (!isset($childServices)  || count($childServices)===0)     ){
        $member = new MemberObject('ANY', '', '', '');
        $tmp_Services=[$member];
    }
    elseif(!isset($parentServices) || count($parentServices)===0 || strcmp($parentServices[0]->name, "ANY")===0){
        $tmp_Services=$childServices;
    }
    //The Child policy has an ANY. We use the Parent's members.
    elseif(!isset($childServices) || count($childServices)===0 || strcmp($childServices[0]->name, "ANY")===0){  //The subpolicy has ANY as a source. We use the Parents source
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

/***
 * @param $configuration
 * @param $fwName
 * @param $type
 * @return array String of policy names
 */
function getPolicyMappingsOld($configuration, $fwName, $type){
    $foundPolicies = array();
    $isThereMapping = false;

    //Some Configurations have a granted_policy_ref node that gives a mapping between firewalls and policies
    $mappings = $configuration->xpath("//granted_policy_ref");
    foreach($mappings as $mapNode){
        $isThereMapping = true;
        if (strcasecmp(normalizeNames($mapNode['engine_ref']), normalizeNames($fwName)) === 0){
            foreach($mapNode->list->list_entry as $policyEntry){
                $pol = $policyEntry["value"];
                $foundPolicies[] = $pol;
            }
        }
    }

    //Some Configurations have, for each firewall, a location_ref attribute that specifies the policy that is to be applied to that firewall
    $fw_policies = $configuration->xpath("//fw_policy");
    foreach ($fw_policies as $fw_policy) {
        if (strcasecmp(normalizeNames($fw_policy["name"]), normalizeNames($fwName)) === 0) {
            if (isset($fw_policy['location_ref'])){
                $foundPolicies[] = $fw_policy['location_ref'];
            }
        }
    }

    if (!$isThereMapping){
        //Check whether there is only one policy in the whole exported_data.xml configuration file. Is so, return this one to be applied to all the defined FWs in the config file.
        $policies = $configuration->xpath("//fw_policy");
        if (count($policies) == 1){
            $policy = $policies[0];
            $pol = $policy["name"];
            $foundPolicies[] = $pol;
        }
    }

    return $foundPolicies;

}

function getPolicyMappings($configuration, $policyName, $type){
    global $projectdb;
    $listFirewalls = array();
    $query = "SELECT firewall FROM policies_to_import WHERE policyname='$policyName'";
    $results = $projectdb->query($query);
    if ($results->num_rows>0){
        while($data = $results->fetch_assoc()){
            $listFirewalls[] = $data['firewall'];
        }
    }
    return $listFirewalls;
}

/***
 * @param SimpleXMLElement $configuration
 * @param string $policy_to_load
 * @param string $vsys
 * @param int $source
 * @param $project
 * @param $objectsInMemory
 */
function get_Policy(SimpleXMLElement $configuration, string $policy_to_load, int $source, $project, &$objectsInMemory) {
    global $like_panorama;
    global $devicegroup;
    global $configFilenamePolicy;
    global $shared_dg_name;

    global $projectdb;
    global $match_expressionsInMemory;

    global $lid;
    global $position;

    global $vrid;

    global $invalid_tag_id;

    $vsys = normalizeNames($policy_to_load);

    $validActions = array("allow", "deny", "drop", "reset", "reset-both", "reset-client","reset-server");  //we are missing he continue optio, which sets some parameters/settings for future connections that also match this one. For instance, timeouts for service


    #Get Last lid from Profiles
    $getlastlid = $projectdb->query("SELECT max(id) as max FROM security_rules;");
    $getLID1 = $getlastlid->fetch_assoc();
    $lid = (int)$getLID1['max'] + 1;
    $getlastlid2 = $projectdb->query("SELECT max(position) as max FROM security_rules;");
    $getLID2 = $getlastlid2->fetch_assoc();
    $position = (int)$getLID2['max'] + 1;

    /*
     * Cleaning the variables for starting the policy collection
     */
    unset($rule);
    $rule = array();
    $rules_to_check = array();
    $sources = array();
    $destinations = array();
    $services = array();
    $addTag = array();
    $tag_ids = null;
    $comments = array();
    $overrideSecurityZones = array();

    $fw_policies = $configuration->xpath("//fw_policy");
    $fw_template_policies = $configuration->xpath("//fw_template_policy");
    $fw_policies = array_merge($fw_policies, $fw_template_policies);
    foreach ($fw_policies as $fw_policy){
        //$isInMapping = in_array((string)$fw_policy['name'], $policy_to_load, false);

        if(normalizeNames((string)$fw_policy['name']) === normalizeNames($policy_to_load)){
            $policy_name = normalizeNames($fw_policy["name"]);
            if($like_panorama){
                $common_vsys = normalizeNamesNew($shared_dg_name,9, "vsys");
            }
            else{
                $common_vsys = normalizeNamesNew($vsys, 9,"vsys");
            }

            $done_with_globalComments = True;
            foreach ($fw_policy->access_entry->rule_entry as $rule_entry){
                $is_fw_policy_disabled = strcmp($rule_entry["is_disabled"], "true")===0 ? 1 : 0;

                $rule_name = (isset($rule_entry['name']))? $rule_entry['name'] : "";

                // rule_entry's can be descriptions/tag of rules or rules themselves
                // Tags come consecutively before the tagged rules

                //LOOKING FOR TAGS IN THE RULES
                // Empty rule_entry (empty meaning they do not have access_rule child) are threaded as tags
                if(isset($rule_entry->comment_rule)){
                    // "This is a covering COMMENT. It may be defining it, or removing the comment\n";
                    if($done_with_globalComments==True) {
                        $done_with_globalComments=False;
//                        unset($comments); //Reset the comment(s) used until now
                        $comments = array();
//                        unset($tag_ids); //Reset the tag(s) used until now
                        $tag_ids = array();
                    }

                    $comment=addslashes($rule_entry["comment"]);
                    if(isset($comment) && strcmp($comment,"")!=0){
                        $comments[] = $comment;
                    }
                }

                // RULE CONTENT
                else{
                    $done_with_globalComments=True; //We found a rule with content. Therefore, we are done parsing tags

                    $access_rule = $rule_entry->access_rule;
                    $action = $access_rule->action;

                    $rule_tag = $rule_entry["tag"];

                    $comment = addslashes($rule_entry["comment"]);
                    if(isset($comment) && strcmp($comment, "")!=0){
                        $localComment = $comment;
                    }
                    else{
                        $localComment = '';
                    }

                    if(isset($access_rule->vpn_action)) {
                        $vpn_action = $access_rule->vpn_action;

                        if (count($vpn_action) > 0) {
                            $action_type = "allow";
                            $vpn_name = normalizeNames($access_rule->vpn_action->vpn_ref['ref']);
                            $getTag = $projectdb->query("SELECT id FROM tag WHERE name='$vpn_name' AND source='$source' AND vsys='$common_vsys';");
                            if ($getTag->num_rows == 0) {
                                $projectdb->query("INSERT INTO tag (name,color,comments,source,vsys) VALUES ('$vpn_name','color7','VPN $vpn_name','$source','$common_vsys');");
                                $local_tag = $projectdb->insert_id;
                            } else {
                                $getTagData = $getTag->fetch_assoc();
                                $local_tag = $getTagData['id'];
                            }
                            add_log2("warning", 'Reading Security Policy', 'Rule[' . $lid . ']. Rule related to VPN '.$vpn_name, $source, 'Check.','rules',$lid,'security_rules');
                        }
                    }
                    else {
                        $action_type = $access_rule->action["type"];
                    }

                    if(!isset($access_rule->match_part)) {
                        //TODO: echo "Sorry, $action_type. Please, check me later\n";
                    }
                    else{
                        $match_part = $access_rule->match_part;
//                        unset($rule_origins);
                        $rule_origins = array();
//                        unset($rule_destinations);
                        $rule_destinations=  array();
//                        unset($rule_services);
                        $rule_services = array();

                        //Checking sources
                        foreach ($match_part->match_sources->match_source_ref as $match_source) {
                            $source_type = trim($match_source["type"]);
                            $expressionName = $match_source["value"];
                            $value = trim(normalizeNames($match_source["value"]));
                            if($source_type === "match_expression"){
                                if(isset($match_expressionsInMemory["$expressionName"]['zones'])){
                                    //There is a Source Zone override
                                    $overrideSecurityZones["$lid"]['from']=$match_expressionsInMemory["$expressionName"]['zones'];
                                }
                                foreach ($match_expressionsInMemory["$expressionName"]['objects'] as $member) {
                                    $rule_origins[] = $member;
                                }
                            }
                            else {
                                if($value === "NOT Loopback network" || $value === "Loopback network"){
                                    add_log2("warning", 'Reading Security Policy', 'Rule[' . $lid . ']. Source "'.$value.'" not supported', $source, 'Source '.$value.' not supported. Calculate the required objects','rules',$lid,'security_rules');
                                }
                                elseif ($value !== "ANY") {
                                    $valueNorm=trim(normalizeNames($value));

                                    if ($valueNorm==="none"){
                                        add_log2("warning", 'Reading Security Policy', 'Rule[' . $lid . ']. Rule is using NONE as Source ', $source, 'Check it.','rules',$lid,'security_rules');
                                    }

                                    $member_lid = 0;
                                    $table_name = "";
                                    if(!searchAddress_orCreate($valueNorm, $vsys, $source, $member_lid, $table_name,$objectsInMemory)){
                                        add_log2("warning", 'Reading Security Policy', 'Rule[' . $lid . ']. Source address not recognized: ['.$value.']', $source, 'Consider removing rule if only valid for Palo Alto Networks configurations','rules',$lid,'security_rules');
                                    }

                                    $member = new MemberObject($member_lid, $table_name);
                                    $rule_origins[] = $member;

//                                    if (isset($objectsInMemory['address'][$common_vsys][$valueNorm])){
//                                        $member_lid = $objectsInMemory['address'][$common_vsys][$valueNorm]['id'];
//                                        $member_ipaddress = $objectsInMemory['address'][$common_vsys][$valueNorm]['ipaddress'];
//                                        $member_cidr = $objectsInMemory['address'][$common_vsys][$valueNorm]['cidr'];
//                                        $member = new MemberObject($member_lid, "address", $member_ipaddress, $member_cidr);
//
//                                        $rule_origins[] = $member;
//                                    }
//                                    elseif(isset($objectsInMemory['address_groups_id'][$common_vsys][$valueNorm])){
//                                        $member_lid = $objectsInMemory['address_groups_id'][$common_vsys][$valueNorm]['id'];
//                                        $member = new MemberObject($member_lid, "address_groups_id");
//
//                                        $rule_origins[] = $member;
//                                    }
//                                    else{
//                                        add_log2("warning", 'Reading Security Policy', 'Rule[' . $lid . ']. Source "'.$value.'" not supported', $source, 'Source '.$value.' not supported. Calculate the required objects','rules',$lid,'security_rules');
//                                    }
                                }
                            }
                        }

                        //Checking destinations
                        foreach ($match_part->match_destinations->match_destination_ref as $match_destination) {
                            $source_type = trim($match_destination["type"]);
                            $expressionName = $match_destination["value"];
                            $value = trim(normalizeNames($match_destination["value"]));
                            if($source_type === "match_expression"){
                                if(isset($match_expressionsInMemory["$expressionName"]['zones'])){
                                    //There is a Source Zone override
                                    $overrideSecurityZones["$lid"]['to']=$match_expressionsInMemory["$expressionName"]['zones'];
                                }
                                foreach ($match_expressionsInMemory["$expressionName"]['objects'] as $member) {
                                    $rule_destinations[] = $member;
                                }
                            }
                            else {
                                if($value === "NOT Loopback network" || $value === "Loopback network"){
                                    add_log2("warning", 'Reading Security Policy', 'Rule[' . $lid . ']. Destination "'.$value.'" not supported', $source, 'Destination '.$value.' not supported. Calculate the required objects','rules',$lid,'security_rules');
                                }
                                elseif ($value !== "ANY") {
                                    $valueNorm=normalizeNames($value);

                                    if ($valueNorm==="none"){
                                        add_log2("warning", 'Reading Security Policy', 'Rule[' . $lid . ']. Rule is using NONE as Destination ', $source, 'Check it.','rules',$lid,'security_rules');
                                    }

                                    $member_lid = 0;
                                    $table_name = "";
                                    if(!searchAddress_orCreate($valueNorm, $vsys, $source, $member_lid, $table_name,$objectsInMemory)){
                                        add_log2("warning", 'Reading Security Policy', 'Rule[' . $lid . ']. Source address not recognized: ['.$value.']', $source, 'Consider removing rule if only valid for Palo Alto Networks configurations','rules',$lid,'security_rules');
                                    }

                                    $member = new MemberObject($member_lid, $table_name);
                                    $rule_destinations[] = $member;

//                                    if (isset($objectsInMemory['address'][$common_vsys][$valueNorm])){
//                                        $member_lid = $objectsInMemory['address'][$common_vsys][$valueNorm]['id'];
//                                        $member_ipaddress = $objectsInMemory['address'][$common_vsys][$valueNorm]['ipaddress'];
//                                        $member_cidr = $objectsInMemory['address'][$common_vsys][$valueNorm]['cidr'];
//                                        $member = new MemberObject($member_lid, "address", $member_ipaddress, $member_cidr);
//
//                                        $rule_destinations[] = $member;
//                                    }
//                                    elseif(isset($objectsInMemory['address_groups_id'][$common_vsys][$valueNorm])){
//                                        $member_lid = $objectsInMemory['address_groups_id'][$common_vsys][$valueNorm]['id'];
//                                        $member = new MemberObject($member_lid, "address_groups_id");
//
//                                        $rule_destinations[] = $member;
//                                    }
//                                    else{
//                                        add_log2("warning", 'Reading Security Policy', 'Rule[' . $lid . ']. Destination "'.$value.'" not supported', $source, 'Destination '.$value.' not supported. Calculate the required objects','rules',$lid,'security_rules');
//                                    }
                                }
                            }
                        }

                        //Services
                        foreach ($match_part->match_services->match_service_ref as $match_service) {
                            $value = normalizeNames($match_service["value"]);
                            if(strcmp($value,"ANY")===0){
                                $service = new MemberObject("ANY",'','','');
                                $rule_services[] = $service;
                            }
                            else{
                                $valueNorm=normalizeNames($value);
                                if (isset($objectsInMemory['services'][$common_vsys][$valueNorm])){
                                    $service_lid = $objectsInMemory['services'][$common_vsys][$valueNorm]['id'];
                                    $service_port = $objectsInMemory['services'][$common_vsys][$valueNorm]['dport'];
                                    $member = new MemberObject($service_lid, "services",$service_port);
                                    $rule_services[] = $member;
                                }
                                elseif(isset($objectsInMemory['services_groups_id'][$common_vsys][$valueNorm])){
                                    $member_lid = $objectsInMemory['services_groups_id'][$common_vsys][$valueNorm]['id'];
                                    $member = new MemberObject($member_lid, "services_groups_id");
                                    $rule_services[] = $member;
                                }
                                else{
                                    echo "Service '$value' was not found in '$common_vsys' using name '$valueNorm'\n";
                                    //print_r($objectsInMemory['services']);
                                    $service_name_ext = normalizeNames($value);
                                    $service_name_int = truncate_names(normalizeNames($service_name_ext));
                                    $serv_description = $service_name_ext;
                                    //Adding the service in the system as an invalid service
                                    $query = "INSERT INTO services (type,name_ext,name,protocol,dport,checkit,description,source,sport,vsys, invalid, devicegroup) ".
                                        "VALUES('','$service_name_ext','$service_name_int','tcp','65000','1','$serv_description','$source','','$common_vsys', '1','Expedition created 3');";
//                                        echo $query.PHP_EOL;
//                                        echo "Line 1978\n";
                                    $projectdb->query($query);
                                    $member_lid = $projectdb->insert_id;
                                    $query = "INSERT INTO tag_relations (table_name, member_lid, tag_id) VALUES ('services','$member_lid','$invalid_tag_id')";
                                    $projectdb->query( "INSERT INTO tag_relations (table_name, member_lid, tag_id) VALUES ('services','$member_lid','$invalid_tag_id')");
                                    //echo "LINE 3234: $query\n";
                                    $member = new MemberObject($member_lid, "services");
                                    $rule_services[] = $member;
                                    $objectsInMemory['services'][$common_vsys][$service_name_ext]['id']=$member_lid;
                                    $objectsInMemory['services'][$common_vsys][$service_name_ext]['dport']="65000";
                                }
                            }
                        }

                        switch ($action_type){
                            case "allow":
                                $action = "allow";
                                break;

                            case "discard":
                                $action = "drop";
                                break;

                            case "reject":
                            case "refuse":
                                $action = "reset-both";
                                break;

                            case "jump":
//                                $action = "allow";
//                                break;
                                $debug = 0;
//                                if($localComment === 'A comment that we are going to use to identify the rule') {
//                                    echo "Going to jump for rule $localComment\n";
//                                    $debug=1;
//                                }
                                $subrule_ref= $access_rule->action["subrule_ref"];
                                //Call get_sub_policy looking for the entry that matches this call, and recalculate the sources, destinations and services given the parent rule
                                $feedback_messages = [];
//                                echo "Jumping into $subrule_ref\n";
                                get_sub_policy($configuration, $subrule_ref, $is_fw_policy_disabled, $tag_ids, $vsys,
                                    $source, $project, $rule_origins, $rule_destinations, $rule_services,
                                    $rule, $rules_to_check, $sources, $destinations, $services, $addTag, $comments,$objectsInMemory, [], $debug, $feedback_messages);

//                                print_r($feedback_messages);
//                                die();

                                break;

                            case "continue":
                                $action = "allow";
                                add_log2("warning", 'Reading Security Policy', 'Rule[' . $lid . ']. Using an action "continue', $source, 'Using an action '.$action.' that is not supported yet','rules',$lid,'security_rules');
                                $continue_tag = get_tag_id($projectdb,"Continue Rule", $source, $vsys);
                                $query = "INSERT INTO security_rules_tag(source, member_lid, table_name, rule_lid, vsys) VALUES ('$source','$continue_tag','tag','$lid', '$vsys') ";
                                $is_fw_policy_disabled = true;
                                //echo "$query";
                                $projectdb->query($query);
                                break;

                            case "terminate":
                            default:
                                $action = "deny";
                                $is_fw_policy_disabled = true;
                                add_log2("warning", 'Reading Security Policy', 'Rule[' . $lid . ']. Using an action "'.$action_type.'" that is unknown', $source, 'Using an action '.$action.' that is unknown','rules',$lid,'security_rules');

                        }

                        //These rules can be directly input in the database
                        if(in_array($action, $validActions)){
                            foreach($rule_origins as $rule_origin){
                                if(strcmp($rule_origin->name, "ANY")!=0){
                                    $sources[] = "('$source','$vsys','$rule_origin->location','$rule_origin->name','$lid')";
                                }
                            }

                            foreach ($rule_destinations as $rule_destination){
                                if(strcmp($rule_destination->name, "ANY")!=0){
                                    $destinations[] = "('$source','$vsys','$rule_destination->location','$rule_destination->name','$lid')";
                                }
                            }

                            foreach ($rule_services as $rule_service){
                                if(strcmp($rule_service->name, "ANY")!=0){
                                    $services[] = "('$source','$vsys','$rule_service->location','$rule_service->name','$lid')";
                                }
                            }

                            $ruleDescription = 'Tag['.$rule_tag.']';
                            if(count($comments)>0) {
                                $ruleDescription .= ' '. implode('. ', $comments);
                                $ruleDescription .= '. ' . $localComment;
                                $ruleDescription=truncate_descriptions($ruleDescription);
                            }

                            $rule_name = ($rule_name == "")? "Rule $lid": "Rule $lid ".truncate_rulenames(normalizeNames($rule_name));
                            $rule[] = "('$lid','$position','$rule_name','$ruleDescription','$action','$is_fw_policy_disabled','$vsys','$source')";
                            if(isset($tag_ids)){
                                foreach ($tag_ids as $tag_id){
                                    $addTag[] = "('$source','$vsys','$lid','$tag_id','tag')";
                                }
                            }
                            if(isset($local_tag) && strcmp($local_tag,"")!=0){
                                $addTag[] = "('$source','$vsys','$lid','$local_tag','tag')";
                            }
                            $lid++;
                            $position++;
                        }
                        else{
                            add_log2("warning", 'Reading Security Policy', 'Rule[' . $lid . ']. It has not been included because the action is not supported yet', $source, 'Using an action '.$action.' that is unknown','rules',$lid,'security_rules');
                            $lid++;
                            $position++;
                        }
                    }
                }
            }

            renewDBConnection();

            //Insert Rules and its Objects
            if (count($rule) > 0) {
                $query = "INSERT INTO security_rules (id,position,name,description,action,disabled,vsys,source) VALUES " . implode(",", $rule) . ";";
                $projectdb->query($query);
                if(count($rules_to_check)>0){
                    $query = "UPDATE security_rules set checkit = '1' where id in (". implode(",",$rules_to_check) .")";
                    $projectdb->query($query);
                }
                if(is_error_db($projectdb)){return false;}

            }

            if (count($services) > 0){
                $query = "INSERT INTO security_rules_srv (source,vsys,table_name,member_lid,rule_lid) VALUES " . implode(",", $services) . ";";
                $projectdb->query($query);
                if(is_error_db($projectdb)){return false;}
            }

            if (count($destinations) > 0){
                $query="INSERT INTO security_rules_dst (source,vsys,table_name,member_lid,rule_lid) VALUES " . implode(",", $destinations) . ";";
                $projectdb->query($query);
                if(is_error_db($projectdb)){return false;}
            }

            if (count($sources) > 0){
                $query ="INSERT INTO security_rules_src (source,vsys,table_name,member_lid,rule_lid) VALUES " . implode(",", $sources) . ";";
                $projectdb->query($query);
                if(is_error_db($projectdb)){return false;}
            }

            if (count($addTag)>0) {
                $query = "INSERT INTO security_rules_tag (source,vsys,rule_lid,member_lid, table_name) VALUES ".implode(",",$addTag).";";
                $projectdb->query($query);
                if(is_error_db($projectdb)){return false;}
            }

            unset($addTag);
        }
    }

    set_Zones_Security_Rules($source, $vsys, $vrid);

    //apply Overriden zones
    if(count($overrideSecurityZones)>0) {
        foreach ($overrideSecurityZones as $lid => $overrideZone) {
            if (isset($overrideZone['from'])) {
                $zonesFrom = $overrideZone['from'];
                $query = "DELETE FROM security_rules_from WHERE rule_lid = '$lid'";
                $projectdb->query($query);
                $zoneQuery = array();
                foreach ($zonesFrom as $zone) {
                    $zoneQuery[] = "('$source','$vsys','$zone','$lid')";
                }
                $query = "INSERT into security_rules_from (source, vsys, name, rule_lid) VALUES " . implode(',', $zoneQuery);
                $projectdb->query($query);
            }

            if (isset($overrideZone['to'])) {
                $zonesTo = $overrideZone['to'];
                $query = "DELETE FROM security_rules_to WHERE rule_lid = '$lid'";
                $projectdb->query($query);
                $zoneQuery = array();
                foreach ($zonesTo as $zone) {
                    $zoneQuery[] = "('$source','$vsys','$zone','$lid')";
                }
                $query = "INSERT into security_rules_to (source, vsys, name, rule_lid) VALUES " . implode(',', $zoneQuery);
                $projectdb->query($query);
            }
        }
    }
}


//function get_Policy_old($configuration, $policy_to_load, $vsys, $source, $project,&$objectsInMemory) {
//    global $like_panorama;
//    global $devicegroup;
//    global $configFilenamePolicy;
//    global $myParent;
//    global $is_first;
//
//    global $project;
//    global $projectdb;
//    global $match_expressionsInMemory;
//    //global $DBUser;
//    //global $DBPass;
//
//    global $lid;
//    global $position;
//    global $debug;
//    global $shared_dg_name;
//
//    global $vrid;
//
//    $validActions = array("allow", "deny", "drop", "reset", "reset-both", "reset-client","reset-server");  //we are missing he continue optio, which sets some parameters/settings for future connections that also match this one. For instance, timeouts for service
//
//
//    #Get Last lid from Profiles
//    $getlastlid = $projectdb->query("SELECT max(id) as max FROM security_rules;");
//    $getLID1 = $getlastlid->fetch_assoc();
//    $lid = (int)$getLID1['max'] + 1;
//    $getlastlid2 = $projectdb->query("SELECT max(position) as max FROM security_rules;");
//    $getLID2 = $getlastlid2->fetch_assoc();
//    $position = (int)$getLID2['max'] + 1;
//
//    /*
//     * Cleaning the variables for starting the policy collection
//     */
//    unset($rule);
//    $rule = array();
//    $sources = array();
//    $destinations = array();
//    $services = array();
//    $addTag = array();
//    $tagids = null;
//    $comments = array();
//    $overrideSecurityZones = array();
//
//    $mappings = getPolicyMappings($configuration, $policy_to_load, "firewall");
//
//    $fw_policies = $configuration->xpath("//fw_policy");
//    $fw_template_policies = $configuration->xpath("//fw_template_policy");
//    $fw_policies = array_merge($fw_policies, $fw_template_policies);
//    foreach ($fw_policies as $fw_policy){
//        $isInMapping = in_array((string)$fw_policy['name'], $mappings, false);
//
//        if($isInMapping || strcasecmp($fw_policy['name'], $policy_to_load)===0 ){
//            $policy_name = $fw_policy["name"];
//            $vsys = normalizeNames($policy_name);
//            if($like_panorama){
//                $common_vsys = $shared_dg_name;
//            }
//            else{
//                $common_vsys = $vsys;
//            }
//
//            if($is_first){
//                $is_first=false;
//                echo "UPDATE device_mapping SET vsys = '$vsys' WHERE vsys='vsys1' AND id=$source;";
//                $projectdb->query("UPDATE device_mapping SET vsys = '$vsys' WHERE vsys='vsys1' AND id=$source;");
//            }
//            else{
//                echo "NOT UPDATE device_mapping SET vsys = '$vsys' WHERE vsys='vsys1' AND id=$source;";
//            }
//
//            //Check if this policy has a template
//            if (isset($fw_policy["template_policy_ref"])){
//                $template_name = $fw_policy["template_policy_ref"];
//
//                //Check if this template has been already processed before
//                $query_template = "SELECT * FROM device_mapping WHERE device ='$devicegroup' AND vsys='$template_name' LIMIT 1";
//                $response_template = $projectdb->query($query_template);
//                if($response_template->num_rows === 0){  //This template has not been processed before
//                    if($like_panorama){
//                        get_Policy($configuration, $template_name, $source, $project,$objectsInMemory);
//                        $projectdb->query(
//                            "INSERT INTO device_mapping (device,version,ispanorama,active,project,filename,vsys,vendor) ".
//                                   "VALUES ('$devicegroup','8.1',$like_panorama,1,'$project','$configFilenamePolicy','$template_name','Stonesoft')");
//                        $this_device_mapping = $projectdb->insert_id;
//
//                        $dg_name = normalizeNames($policy_name);
//                        $projectdb->query(
//                            "INSERT INTO devicegroups (source, parent_dg, devices, master_device, description, name_ext, name)".
//                                   "VALUES ($source,$this_device_mapping,'<devices/>','None','$policy_name as a DG','$policy_name','$dg_name')");
//                    }
//                    else{
//                        get_Policy($configuration, $template_name, $source, $project,$objectsInMemory);
//                    }
//                }
//
//                //Renew the MySQL connection, as it may have dropped after all this time
//                renewDBConnection();
//
//                $getlastlid = $projectdb->query("SELECT max(id) as max FROM security_rules;");
//                $getLID1 = $getlastlid->fetch_assoc();
//                $lid = intval($getLID1['max']) + 1;
//                $getlastlid2 = $projectdb->query("SELECT max(position) as max FROM security_rules;");
//                $getLID2 = $getlastlid2->fetch_assoc();
//                $position = intval($getLID2['max']) + 1;
//            }
//            elseif($like_panorama){ //This is the top template
//                $projectdb->query("INSERT INTO devicegroups (source, parent_dg, devices, master_device, description, name_ext, name)".
//                    "VALUES ($source,0,'<devices/>','None','$policy_name as Shared','$policy_name','$vsys')");
//            }
//
//            $done_with_globalComments = True;
//            foreach ($fw_policy->access_entry->rule_entry as $rule_entry){
//                $is_fw_policy_disabled = strcmp($rule_entry["is_disabled"], "true")===0 ? 1 : 0;
//
//                $rule_name = (isset($rule_entry['name']))? $rule_entry['name'] : "";
//
//                // rule_entry's can be descriptions/tag of rules or rules themselves
//                // Tags come consecutively before the tagged rules
//
//                //LOOKING FOR TAGS IN THE RULES
//                // Empty rule_entry (empty meaning they do not have access_rule child) are threated as tags
//                if(isset($rule_entry->comment_rule)){
//                    // "This is a covering COMMENT. It may be defining it, or removing the comment\n";
//                    if($done_with_globalComments==True) {
//                        $done_with_globalComments=False;
////                        unset($comments); //Reset the comment(s) used until now
//                        $comments = array();
////                        unset($tag_ids); //Reset the tag(s) used until now
//                        $tag_ids = array();
//                    }
//
//                    $comment=addslashes($rule_entry["comment"]);
//                    if(isset($comment) && strcmp($comment,"")!=0){
//                        $comments[] = $comment;
//                    }
//                }
//
//                // RULE CONTENT
//                else{
//                    $done_with_globalComments=True; //We found a rule with content. Therefore, we are done parsing tags
//
//                    $access_rule = $rule_entry->access_rule;
//                    $action = $access_rule->action;
//
//                    $rule_tag = $rule_entry["tag"];
//
//                    $comment = addslashes($rule_entry["comment"]);
//                    if(isset($comment) && strcmp($comment, "")!=0){
//                        $localComment = $comment;
//                    }
//                    else{
//                        $localComment = '';
//                    }
//
//                    if(isset($access_rule->vpn_action)) {
//                        $vpn_action = $access_rule->vpn_action;
//
//                        if (count($vpn_action) > 0) {
//                            $action_type = "allow";
//                            $vpn_name = normalizeNames($access_rule->vpn_action->vpn_ref['ref']);
//                            $getTag = $projectdb->query("SELECT id FROM tag WHERE name='$vpn_name' AND source='$source' AND vsys='$common_vsys';");
//                            if ($getTag->num_rows == 0) {
//                                $projectdb->query("INSERT INTO tag (name,color,comments,source,vsys) VALUES ('$vpn_name','color7','VPN $vpn_name','$source','$common_vsys');");
//                                $local_tag = $projectdb->insert_id;
//                            } else {
//                                $getTagData = $getTag->fetch_assoc();
//                                $local_tag = $getTagData['id'];
//                            }
//                            add_log2("warning", 'Reading Security Policy', 'Rule[' . $lid . ']. Rule related to VPN '.$vpn_name, $source, 'Check.','rules',$lid,'security_rules');
//                        }
//                    }
//                    else {
//                        $action_type = $access_rule->action["type"];
//                    }
//
//                    if(!isset($access_rule->match_part)) {
//                        //TODO: echo "Sorry, $action_type. Please, check me later\n";
//                    }
//                    else{
//                        $match_part = $access_rule->match_part;
////                        unset($rule_origins);
//                        $rule_origins = array();
////                        unset($rule_destinations);
//                        $rule_destinations=  array();
////                        unset($rule_services);
//                        $rule_services = array();
//
//                        //Checking sources
//                        foreach ($match_part->match_sources->match_source_ref as $match_source) {
//                            $source_type = trim($match_source["type"]);
//                            $expressionName = $match_source["value"];
//                            $value = trim(normalizeNames($match_source["value"]));
//                            if($source_type === "match_expression"){
//                                if(isset($match_expressionsInMemory["$expressionName"]['zones'])){
//                                    //There is a Source Zone override
//                                    $overrideSecurityZones["$lid"]['from']=$match_expressionsInMemory["$expressionName"]['zones'];
//                                }
//                                foreach ($match_expressionsInMemory["$expressionName"]['objects'] as $member) {
//                                    $rule_origins[] = $member;
//                                }
//                            }
//                            else {
//                                if($value === "NOT Loopback network" || $value === "Loopback network"){
//                                    add_log2("warning", 'Reading Security Policy', 'Rule[' . $lid . ']. Source "'.$value.'" not supported', $source, 'Source '.$value.' not supported. Calculate the required objects','rules',$lid,'security_rules');
//                                }
//                                elseif ($value !== "ANY") {
//                                    $valueNorm=normalizeNames($value);
//
//                                    if ($valueNorm==="none"){
//                                        add_log2("warning", 'Reading Security Policy', 'Rule[' . $lid . ']. Rule is using NONE as Source ', $source, 'Check it.','rules',$lid,'security_rules');
//                                    }
//
//                                    if (isset($objectsInMemory['address'][$common_vsys][$valueNorm])){
//                                        $member_lid = $objectsInMemory['address'][$common_vsys][$valueNorm]['id'];
//                                        $member_ipaddress = $objectsInMemory['address'][$common_vsys][$valueNorm]['ipaddress'];
//                                        $member_cidr = $objectsInMemory['address'][$common_vsys][$valueNorm]['cidr'];
//                                        $member = new MemberObject($member_lid, "address", $member_ipaddress, $member_cidr);
//
//                                        $rule_origins[] = $member;
//                                    }
//                                    elseif(isset($objectsInMemory['address_groups_id'][$common_vsys][$valueNorm])){
//                                        $member_lid = $objectsInMemory['address_groups_id'][$common_vsys][$valueNorm]['id'];
//                                        $member = new MemberObject($member_lid, "address_groups_id");
//
//                                        $rule_origins[] = $member;
//                                    }
//                                    else{
//                                        add_log2("warning", 'Reading Security Policy', 'Rule[' . $lid . ']. Source "'.$value.'" not supported', $source, 'Source '.$value.' not supported. Calculate the required objects','rules',$lid,'security_rules');
//                                    }
//                                }
//                            }
//                        }
//
//                        //Checking destinations
//                        foreach ($match_part->match_destinations->match_destination_ref as $match_destination) {
//                            $source_type = trim($match_destination["type"]);
//                            $expressionName = $match_destination["value"];
//                            $value = trim(normalizeNames($match_destination["value"]));
//                            if($source_type === "match_expression"){
//                                if(isset($match_expressionsInMemory["$expressionName"]['zones'])){
//                                    //There is a Source Zone override
//                                    $overrideSecurityZones["$lid"]['to']=$match_expressionsInMemory["$expressionName"]['zones'];
//                                }
//                                foreach ($match_expressionsInMemory["$expressionName"]['objects'] as $member) {
//                                    $rule_destinations[] = $member;
//                                }
//                            }
//                            else {
//                                if($value === "NOT Loopback network" || $value === "Loopback network"){
//                                    add_log2("warning", 'Reading Security Policy', 'Rule[' . $lid . ']. Destination "'.$value.'" not supported', $source, 'Destination '.$value.' not supported. Calculate the required objects','rules',$lid,'security_rules');
//                                }
//                                elseif ($value !== "ANY") {
//                                    $valueNorm=normalizeNames($value);
//
//                                    if ($valueNorm==="none"){
//                                        add_log2("warning", 'Reading Security Policy', 'Rule[' . $lid . ']. Rule is using NONE as Destination ', $source, 'Check it.','rules',$lid,'security_rules');
//                                    }
//
//                                    if (isset($objectsInMemory['address'][$common_vsys][$valueNorm])){
//                                        $member_lid = $objectsInMemory['address'][$common_vsys][$valueNorm]['id'];
//                                        $member_ipaddress = $objectsInMemory['address'][$common_vsys][$valueNorm]['ipaddress'];
//                                        $member_cidr = $objectsInMemory['address'][$common_vsys][$valueNorm]['cidr'];
//                                        $member = new MemberObject($member_lid, "address", $member_ipaddress, $member_cidr);
//
//                                        $rule_destinations[] = $member;
//                                    }
//                                    elseif(isset($objectsInMemory['address_groups_id'][$common_vsys][$valueNorm])){
//                                        $member_lid = $objectsInMemory['address_groups_id'][$common_vsys][$valueNorm]['id'];
//                                        $member = new MemberObject($member_lid, "address_groups_id");
//
//                                        $rule_destinations[] = $member;
//                                    }
//                                    else{
//                                        add_log2("warning", 'Reading Security Policy', 'Rule[' . $lid . ']. Destination "'.$value.'" not supported', $source, 'Destination '.$value.' not supported. Calculate the required objects','rules',$lid,'security_rules');
//                                    }
//                                }
//                            }
//                        }
//
//                        //Services
//                        foreach ($match_part->match_services->match_service_ref as $match_service) {
//                            $value = normalizeNames($match_service["value"]);
//                            if(strcmp($value,"ANY")===0){
//                                $service = new MemberObject("ANY",'','','');
//                                $rule_services[] = $service;
//                            }
//                            else{
//                                $valueNorm=normalizeNames($value);
//                                if (isset($objectsInMemory['services'][$common_vsys][$valueNorm])){
//                                    $service_lid = $objectsInMemory['services'][$common_vsys][$valueNorm]['id'];
//                                    $service_port = $objectsInMemory['services'][$common_vsys][$valueNorm]['dport'];
//                                    $member = new MemberObject($service_lid, "services",$service_port);
//                                    $rule_services[] = $member;
//                                }
//                                elseif(isset($objectsInMemory['services_groups_id'][$common_vsys][$valueNorm])){
//                                    $member_lid = $objectsInMemory['services_groups_id'][$common_vsys][$valueNorm]['id'];
//                                    $member = new MemberObject($member_lid, "services_groups_id");
//                                    $rule_services[] = $member;
//                                }
//                                else{
//                                    $service_name_ext = normalizeNames($value);
//                                    $service_name_int = truncate_names(normalizeNames($service_name_ext));
//                                    $serv_description = $service_name_ext;
//                                    //Adding the service in the system as an invalid service
//                                    $query = "INSERT INTO services (type,name_ext,name,protocol,dport,checkit,description,source,sport,vsys, invalid) ".
//                                        "VALUES('','$service_name_ext','$service_name_int','','65000','1','$serv_description','$common_vsys','','$common_vsys', '1');";
////                                        echo $query.PHP_EOL;
////                                        echo "Line 1978\n";
//                                    $projectdb->query($query);
//                                    $member_lid = $projectdb->insert_id;
//                                    $member = new MemberObject($member_lid, "services");
//                                    $rule_services[] = $member;
//                                    $objectsInMemory['services'][$common_vsys][$service_name_ext]['id']=$member_lid;
//                                    $objectsInMemory['services'][$common_vsys][$service_name_ext]['dport']="65000";
//                                }
//                            }
//                        }
//
//                        switch ($action_type){
//                            case "allow":
//                                $action = "allow";
//                                break;
//
//                            case "discard":
//                                $action = "drop";
//                                break;
//
//                            case "reject":
//                            case "refuse":
//                                $action = "reset-both";
//                                break;
//
//                            case "jump":
//                                $subrule_ref= $access_rule->action["subrule_ref"];
//                                //Call get_sub_policy looking for the entry that matches this call, and recalculate the sources, destinations and services given the parent rule
//                                get_sub_policy($configuration, $subrule_ref, $is_fw_policy_disabled, $tag_ids, $vsys,
//                                    $source, $project, $rule_origins, $rule_destinations, $rule_services,
//                                    $rule, $sources, $destinations, $services, $addTag, $comments,$objectsInMemory, []);
//
//                                break;
//
//                            case "continue":
//                                $action = "continue";
//                                add_log2("warning", 'Reading Security Policy', 'Rule[' . $lid . ']. Using an action "continue', $source, 'Using an action '.$action.' that is not supported yet','rules',$lid,'security_rules');
//                                break;
//
//                            case "terminate":
//                            default:
//                                $action = "deny";
//                                $is_fw_policy_disabled = true;
//                                add_log2("warning", 'Reading Security Policy', 'Rule[' . $lid . ']. Using an action "'.$action_type.'" that is unknown', $source, 'Using an action '.$action.' that is unknown','rules',$lid,'security_rules');
//
//                        }
//
//                        //These rules can be directly input in the database
//                        if(in_array($action, $validActions)){
//                            foreach($rule_origins as $rule_origin){
//                                if(strcmp($rule_origin->name, "ANY")!=0){
//                                    $sources[] = "('$source','$vsys','$rule_origin->location','$rule_origin->name','$lid')";
//                                }
//                            }
//
//                            foreach ($rule_destinations as $rule_destination){
//                                if(strcmp($rule_destination->name, "ANY")!=0){
//                                    $destinations[] = "('$source','$vsys','$rule_destination->location','$rule_destination->name','$lid')";
//                                }
//                            }
//
//                            foreach ($rule_services as $rule_service){
//                                if(strcmp($rule_service->name, "ANY")!=0){
//                                    $services[] = "('$source','$vsys','$rule_service->location','$rule_service->name','$lid')";
//                                }
//                            }
//
//                            $ruleDescription = 'Tag['.$rule_tag.']';
//                            if(count($comments)>0) {
//                                $ruleDescription .= ' '. implode('. ', $comments);
//                                $ruleDescription .= '. ' . $localComment;
//                                $ruleDescription=truncate_descriptions($ruleDescription);
//                            }
//
//                            $rule_name = ($rule_name == "")? "Rule $lid": truncate_rulenames(normalizeNames($rule_name));
//                            $rule[] = "('$lid','$position','$rule_name','$ruleDescription','$action','$is_fw_policy_disabled','$vsys','$source')";
//                            if(isset($tag_ids)){
//                                foreach ($tag_ids as $tag_id){
//                                    $addTag[] = "('$source','$vsys','$lid','$tag_id','tag')";
//                                }
//                            }
//                            if(isset($local_tag) && strcmp($local_tag,"")!=0){
//                                $addTag[] = "('$source','$vsys','$lid','$local_tag','tag')";
//                            }
//                            $lid++;
//                            $position++;
//                        }
//                        else{
//                            add_log2("warning", 'Reading Security Policy', 'Rule[' . $lid . ']. It has not been included because the action is not supported yet', $source, 'Using an action '.$action.' that is unknown','rules',$lid,'security_rules');
//                            $lid++;
//                            $position++;
//                        }
//                    }
//                }
//            }
//
//            //Insert Rules and its Objects
//            if (count($rule) > 0) {
//                $query = "INSERT INTO security_rules (id,position,name,description,action,disabled,vsys,source) VALUES " . implode(",", $rule) . ";";
//                $projectdb->query($query);
//            }
//
//            if (count($services) > 0){
//                $query = "INSERT INTO security_rules_srv (source,vsys,table_name,member_lid,rule_lid) VALUES " . implode(",", $services) . ";";
//                $projectdb->query($query);
//            }
//
//            if (count($destinations) > 0){
//                $query="INSERT INTO security_rules_dst (source,vsys,table_name,member_lid,rule_lid) VALUES " . implode(",", $destinations) . ";";
//                $projectdb->query($query);
//            }
//
//            if (count($sources) > 0){
//                $query ="INSERT INTO security_rules_src (source,vsys,table_name,member_lid,rule_lid) VALUES " . implode(",", $sources) . ";";
//                $projectdb->query($query);
//            }
//
//            if (count($addTag)>0) {
//                $query = "INSERT INTO security_rules_tag (source,vsys,rule_lid,member_lid, table_name) VALUES ".implode(",",$addTag).";";
//                $projectdb->query($query);
//            }
//            unset($addTag);
//        }
//    }
//
//    set_Zones_Security_Rules($source, $vsys, $vr_id);
//
//    //apply Overriden zones
//    if(count($overrideSecurityZones)>0) {
//        foreach ($overrideSecurityZones as $lid => $overrideZone) {
//            if (isset($overrideZone['from'])) {
//                $zonesFrom = $overrideZone['from'];
//                $query = "DELETE FROM security_rules_from WHERE rule_lid = '$lid'";
//                $projectdb->query($query);
//                $zoneQuery = array();
//                foreach ($zonesFrom as $zone) {
//                    $zoneQuery[] = "('$zone','$lid')";
//                }
//                $query = "INSERT into security_rules_from (name, rule_lid) VALUES " . implode(',', $zoneQuery);
//                $projectdb->query($query);
//            }
//
//            if (isset($overrideZone['to'])) {
//                $zonesTo = $overrideZone['to'];
//                $query = "DELETE FROM security_rules_to WHERE rule_lid = '$lid'";
//                $projectdb->query($query);
//                $zoneQuery = array();
//                foreach ($zonesTo as $zone) {
//                    $zoneQuery[] = "('$zone','$lid')";
//                }
//                $query = "INSERT into security_rules_to (name, rule_lid) VALUES " . implode(',', $zoneQuery);
//                $projectdb->query($query);
//            }
//        }
//    }
//}

/***
 * @param mysqli $projectdb
 * @param $sub_rule_ref
 * @param $source
 * @param $vsys
 * @return int
 */
function get_tag_id(mysqli $projectdb, $sub_rule_ref, $source, $vsys): int{
    $vsyses = getVsyses($projectdb, $vsys, $source, 'quoted');
    $query = "SELECT id FROM tag WHERE name = '$sub_rule_ref' AND vsys in (".implode(",", $vsyses).") AND source='$source' LIMIT 1";
    $result = $projectdb->query($query);
    if($result->num_rows === 1){
        $data = $result->fetch_assoc();
        return $data['id'];
    }

    $query = "INSERT INTO tag(name, name_ext, vsys, source) VALUES ('$sub_rule_ref','$sub_rule_ref', '$vsys','$source')";
    $projectdb->query($query);
    return $projectdb->insert_id;

}
/**
 * This method should include additional changes in $rule, and define the new origins, destinations, services and tag-ids for the new included rules
 * @param SimpleXMLElement $configuration
 * @param String $sub_rule_ref
 * @param int $is_fw_policy_disabled
 * @param MemberObject
 */
function get_sub_policy(SimpleXMLElement $configuration, $sub_rule_ref, $is_fw_policy_disabled, &$tag_ids, $vsys, $source, $project,
                                         &$rule_origins, &$rule_destinations, &$rule_services, &$rule, &$rules_to_check, &$sources, &$destinations, &$services, &$addTag,
                                         &$comments, &$objectsInMemory, $sub_policy_tag_id=[], int $debug=0, array &$feedback_messages=[]){

    global $lid;
    global $position;
    global $projectdb;
    global $match_expressionsInMemory;
    global $like_panorama;
    global $shared_dg_name;
    global $invalid_tag_id;

    if($like_panorama){
        $objects_vsys = normalizeNamesNew($shared_dg_name,9, "vsys");
    }
    else{
        $objects_vsys = normalizeNamesNew($vsys, 9,"vsys");
    }

    $validActions = array("allow", "deny", "drop", "reset", "reset-both","reset-client","reset-server", "jump");

    $description = '';

    //Defining variables I will globally use in this function
    $resultingSourceMembers = null;
    $resultingDestinationMembers = null;
    $resultingServices = null;

    /*
     * Here are the subpolicies that could be called from the fw_policy element
     */
    //$search_xpath="//fw_sub_policy[@name='0_DMZ_Proxy']";
    //$name=$fw_sub_policy["name"]
    //echo "The fw_sub_policy $name has rules with the options . . .\n";

    if(strcasecmp($sub_rule_ref, "DHCP Relay")===0){
        foreach($rule_origins as $rule_origin){
            if(strcmp($rule_origin->name, "ANY")!==0){
                $sources[] = "('$source','$vsys','$rule_origin->location','$rule_origin->name','$lid')";
            }
        }

        foreach ($rule_destinations as $rule_destination){
            if(strcmp($rule_destination->name, "ANY")!==0){
                $destinations[] = "('$source','$vsys','$rule_destination->location','$rule_destination->name','$lid')";
            }
        }

        $query = "SELECT id, dport  FROM services WHERE source='$source' AND BINARY name_ext='DHCP TCP' AND vsys='$objects_vsys';";
        $getService = $projectdb->query($query);
        if ($getService->num_rows > 0) {
            $myData = $getService->fetch_assoc();
            $service_lid = $myData['id'];
            $service_port = $myData['dport'];
            $member = new MemberObject($service_lid, "services",$service_port);
            $sub_services[] = $member;
        }
        $query = "SELECT id, dport  FROM services WHERE source='$source' AND BINARY name_ext='DHCP UDP' AND vsys='$objects_vsys';";
        $getService = $projectdb->query($query);
        if ($getService->num_rows > 0) {
            $myData = $getService->fetch_assoc();
            $service_lid = $myData['id'];
            $service_port = $myData['dport'];
            $member = new MemberObject($service_lid, "services",$service_port);
            $sub_services[] = $member;
        }

        foreach ($sub_services as $rule_service){
            if(strcmp($rule_service->name, "ANY")!==0){
                $services[] = "('$source','$vsys','$rule_service->location','$rule_service->name','$lid')";
            }
        }
        $result_is_sub_rule_disabled = ($is_fw_policy_disabled===1) ? 1 : 0;
        $rule[] = "('$lid','$position','Rule $lid','$description','allow','$result_is_sub_rule_disabled','$vsys','$source')";
        add_log2("warning", 'Reading Security Policy', 'Rule[' . $lid . ']. DHCP Relay rule applied.', $source, 'Check.','rules',$lid,'security_rules');
        $lid++;
        $position++;
    }
    else{
        $fw_sub_policies = $configuration->xpath("//fw_sub_policy");
//        $fw_sub_policies = $configuration->xpath("//fw_sub_policy" or "//fw_template_policy");
        foreach ($fw_sub_policies as $fw_sub_policy){
            if(strcmp($fw_sub_policy["name"], $sub_rule_ref)===0){
                $sub_policy_tag_id[] = get_tag_id($projectdb, $sub_rule_ref, $source, $vsys);
                $disabled_subpolicy_tag_id = get_tag_id($projectdb, 'Disabled Subpolicy', $source, $vsys);
//                if($debug) {
//                    echo "\nSUB_POLICY $subrule_ref found\n";
//                }
                $feedback_messages['sub_rules'] = [];
                $feedback_messages['general']['total_subrules'] = $feedback_messages['general']['total_subrules'] ?? 0;
                //$i=0;
                foreach ($fw_sub_policy->access_entry as $access_entry){
                    //echo "\n - ACCESS ENTRY $i \n"; $i++;
                    $subRulePosition=0;

                    $done_with_tags = true;
                    foreach ($access_entry->rule_entry as $rule_entry){
                        $is_subrule_disabled = strcmp($rule_entry["is_disabled"], "true")===0 ? 1 : 0;
                        $result_is_sub_rule_disabled = ($is_subrule_disabled===1 || $is_fw_policy_disabled===1) ? 1 : 0;  //If either the parent of the child are disabled, we disable the resulting rule
//                        if($debug){
//                            echo "Rule ".$rule_entry['tag']."\t";
//                            echo "Initially, this rule is enabled? $is_subrule_disabled or $is_fw_policy_disabled --> $result_is_sub_rule_disabled\n";
//                        }

                        //Resetting the local variables for sub_rule definition
                        unset($sub_sources);
                        unset($sub_destinations);
                        unset($sub_services);
                        $sub_sources = array();
                        $sub_destinations = array();
                        $sub_services = array();
                        //unset($additionalTags);

                        //Is this entry does not have an access_rule inside, this can be considered as a Comment.
                        //$k=0;
                        if(isset($rule_entry->comment_rule)){
                            if($done_with_tags==true) {
                                $done_with_tags=false;
                                unset($additionalTags); //Reset the tag(s) used until now
                            }
                            //echo "    Rule Entry $subRulePosition:         Check that this is a rule entry for access, it could be for NAT, or VPN\n";$subRulePosition++;

                            $comment=addslashes($rule_entry["comment"]);
                            if(isset($comment) && strcmp($comment, "")!==0){
                                $comments[] = $comment;
                            }
                        }

                        else{
                            $rule_tag = (string)$rule_entry["tag"];
                            $feedback_messages['general']['total_subrules'] += 1;
                            $feedback_messages['general']['names'][] = $rule_tag;

                            $done_with_tags=true; //We found a rule with content. Therefore, we are done parsing tags
                            //echo "    Rule Entry $subRulePosition:         Done with the comments\n";
                            $subRulePosition++;


                            $comment = addslashes($rule_entry["comment"]);
                            if(isset($comment) && strcmp($comment, "")!==0){
                                $localComment = $comment;
                            }
                            else{
                                $localComment = '';
                            }

                            foreach($rule_entry->access_rule as $access_rule){
                                //Checking the action of this code
                                $action_type = $access_rule->action["type"];
                                if(isset($action_type)){
                                    switch ($action_type){
                                        case "allow":
                                            $action = "allow";
                                            break;

                                        case "discard":
                                            $action = "drop";
                                            break;

                                        case "reject":
                                        case "refuse":
                                            $action = "reset-both";
                                            break;

                                        case "jump":
                                            $action = "jump";
                                            $subrule_ref2 = $access_rule->action["subrule_ref"];
                                            echo "We have a second jump here to $subrule_ref2\n";
                                            add_log2("info", 'Reading Security Policy', 'Rule[' . $lid . ']. Using an action *jump* of a second or deeper level.', $source, 'Using an action *jump* in a subpolicy. It is suggested to review multiple-level rule intersection','rules',$lid,'security_rules');
                                            break;

                                        case "":
                                            //TODO "This may be a VPN rule. Let's leave it for a later version";
                                            break;

                                        case "terminate":
                                        default:
                                            $action = "deny";
                                            add_log2("warning", 'Reading Security Policy', 'Rule[' . $lid . ']. Using an action "'.$action_type.'" that is unknown', $source, 'Using an action '.$action.' that is unknown','rules',$lid,'security_rules');
                                    }
                                }
                                $vpn_action = $access_rule->vpn_action;
                                if(count($vpn_action)>0){
                                    $action = "allow";
                                    $getTag=$projectdb->query("SELECT id FROM tag WHERE name='vpn' AND source='$source' AND vsys='$objects_vsys';");
                                    if ($getTag->num_rows===0){
                                        $projectdb->query("INSERT INTO tag (name,color,comments,source,vsys) VALUES ('vpn','color7','vpn','$source','$objects_vsys');");
                                        $additionalTags[$lid]=$projectdb->insert_id;
                                    }
                                    else {
                                        $getTagData=$getTag->fetch_assoc();
                                        $additionalTags[$lid]=$getTagData['id'];
                                    }
                                }

                                if (!isset($action)){
                                    $action ='';
                                }
                                //These rules can be directly input in the database
                                if(!in_array($action, $validActions)){
                                    echo "$rule_tag skipped because of no action\n";
                                    add_feedback_message($rule_tag,"does not have an action. Skipped." , $feedback_messages);
                                }
                                else{

                                    //Checking the source
                                    //echo "           ORIGINS\n";
                                    foreach($access_rule->match_part->match_sources->match_source_ref as $match_source){
                                        $source_type = trim($match_source["type"]);
                                        $expressionName = $match_source["value"];
                                        $value = trim(normalizeNames($match_source["value"]));
                                        if($source_type === "match_expression"){
                                            if(isset($match_expressionsInMemory["$expressionName"]['zones'])){
                                                //There is a Source Zone override
                                                $overrideSecurityZones["$lid"]['from']=$match_expressionsInMemory["$expressionName"]['zones'];
                                            }
                                            foreach ($match_expressionsInMemory["$expressionName"]['objects'] as $member) {
                                                $sub_sources[] = $member;
                                            }
                                        }
                                        else {

                                            $valueNorm=normalizeNames($value);

                                            if ($valueNorm==="none"){
                                                add_log2("warning", 'Reading Security Policy', 'Rule[' . $lid . ']. Rule is using NONE as Source ', $source, 'Check it.','rules',$lid,'security_rules');
                                            }

                                            if (strcmp($value, "ANY") === 0) {
                                                $member = new MemberObject("ANY", '', '0.0.0.0', '0');
                                                $sub_sources[] = $member;
                                            }
                                            else{

                                                $member_lid = 0;
                                                $table_name = "";
                                                $member_cidr = "";
                                                $member_ipaddress = "";
                                                if(!searchAddress_orCreate($valueNorm, $vsys, $source, $member_lid, $table_name,$objectsInMemory, $member_cidr, $member_ipaddress)){
                                                    add_feedback_message($rule_tag,"uses an invalid source $value" , $feedback_messages);
                                                    add_log2("warning", 'Reading Security Policy', 'Rule[' . $lid . ']. Source "'.$value.'" not supported', $source, 'Source '.$value.' not supported. Calculate the required objects','rules',$lid,'security_rules');
                                                } else {

                                                    $member = new MemberObject($member_lid, $table_name, $member_ipaddress, $member_cidr);
                                                    $sub_sources[] = $member;
                                                }
/*                                                if (isset($objectsInMemory['address'][$objects_vsys][$valueNorm])){
                                                    $member_lid = $objectsInMemory['address'][$objects_vsys][$valueNorm]['id'];
                                                    $member_ipaddress = $objectsInMemory['address'][$objects_vsys][$valueNorm]['ipaddress'];
                                                    $member_cidr = $objectsInMemory['address'][$objects_vsys][$valueNorm]['cidr'];
                                                    $member = new MemberObject($member_lid, "address", $member_ipaddress, $member_cidr);

                                                    $sub_sources[] = $member;
                                                }
                                                elseif(isset($objectsInMemory['address_groups_id'][$objects_vsys][$valueNorm])){
                                                    $member_lid = $objectsInMemory['address_groups_id'][$objects_vsys][$valueNorm]['id'];
                                                    $member = new MemberObject($member_lid, "address_groups_id");

                                                    $sub_sources[] = $member;
                                                }
                                                else{
                                                    add_feedback_message($rule_tag,"uses an invalid source $value" , $feedback_messages);
                                                    add_log2("warning", 'Reading Security Policy', 'Rule[' . $lid . ']. Source "'.$value.'" not supported', $source, 'Source '.$value.' not supported. Calculate the required objects','rules',$lid,'security_rules');
                                                }*/
                                            }
                                        }
                                    }
                                    $resultingSourceMembers = getCommonMembers($sub_sources, $rule_origins, $projectdb, $source, $vsys);

                                    //If the sources of Parent and Child do not overlap, we can disable this rule :)
                                    if(!isset($resultingSourceMembers) || count($resultingSourceMembers)===0){
                                        $result_is_sub_rule_disabled = 1;
                                        $sub_rule_tag = $rule_entry['tag'];
                                        add_feedback_message($rule_tag,"sources does not intersect with parent sources" , $feedback_messages);
                                        add_log2("warning", 'Reading Security Policy. Disabled Jump', 'Rule[' . $lid . ']. The rule in subpolicy "'.$sub_rule_ref.'" position='.$subRulePosition.' with original tag="'.$sub_rule_tag.'" does not have sources matching the parent rule.  Disabled for precaution.', $source, 'Determine whether this rule can be deleted','rules',$lid,'security_rules');
                                        $resultingSourceMembers = $sub_sources;
                                        $rules_to_check[] =  $lid;
                                        //break 1;  //This could speed up the parsing, if we don't want to load rules that are invalid and disabled
                                    }

                                    //Checking the destination
                                    //echo "           DESTINATIONS\n";
                                    $sub_destinations = array();
                                    foreach($access_rule->match_part->match_destinations->match_destination_ref as $match_destination){
                                        $source_type = trim($match_destination["type"]);
                                        $expressionName = $match_destination["value"];
                                        $value = trim(normalizeNames($match_destination["value"]));
                                        if($source_type === "match_expression"){
                                            if(isset($match_expressionsInMemory["$expressionName"]['zones'])){
                                                //There is a Source Zone override
                                                $overrideSecurityZones["$lid"]['to']=$match_expressionsInMemory["$expressionName"]['zones'];
                                            }
                                            foreach ($match_expressionsInMemory["$expressionName"]['objects'] as $member) {
                                                $sub_destinations[] = $member;
                                            }
                                        }
                                        else {
                                            $valueNorm=normalizeNames($value);

                                            if ($valueNorm==="none"){
                                                add_log2("warning", 'Reading Security Policy', 'Rule[' . $lid . ']. Rule is using NONE as Source ', $source, 'Check it.','rules',$lid,'security_rules');
                                            }

                                            if (strcmp($value, "ANY") === 0) {
                                                $member = new MemberObject("ANY", '', '0.0.0.0', '0');
                                                //echo "              get_sub_policy: The children are ANY\n";
                                                $sub_destinations[] = $member;
                                            }
                                            else{

                                                $member_lid = 0;
                                                $table_name = "";
                                                $member_cidr = "";
                                                $member_ipaddress = "";
                                                if(!searchAddress_orCreate($valueNorm, $vsys, $source, $member_lid, $table_name,$objectsInMemory, $member_cidr, $member_ipaddress)){
                                                    add_feedback_message($rule_tag,"uses an invalid destination $value" , $feedback_messages);
                                                    add_log2("warning", 'Reading Security Policy', 'Rule[' . $lid . ']. Destination "'.$value.'" not supported', $source, 'Destination '.$value.' not supported. Calculate the required objects','rules',$lid,'security_rules');
                                                } else {

                                                    $member = new MemberObject($member_lid, $table_name, $member_ipaddress, $member_cidr);
                                                    $sub_destinations[] = $member;
                                                }
                                                /*
                                                if (isset($objectsInMemory['address'][$objects_vsys][$valueNorm])){
                                                    $member_lid = $objectsInMemory['address'][$objects_vsys][$valueNorm]['id'];
                                                    $member_ipaddress = $objectsInMemory['address'][$objects_vsys][$valueNorm]['ipaddress'];
                                                    $member_cidr = $objectsInMemory['address'][$objects_vsys][$valueNorm]['cidr'];
                                                    $member = new MemberObject($member_lid, "address", $member_ipaddress, $member_cidr);

                                                    $sub_destinations[] = $member;
                                                }
                                                elseif(isset($objectsInMemory['address_groups_id'][$objects_vsys][$valueNorm])){
                                                    $member_lid = $objectsInMemory['address_groups_id'][$objects_vsys][$valueNorm]['id'];
                                                    $member = new MemberObject($member_lid, "address_groups_id");

                                                    $sub_destinations[] = $member;
                                                }
                                                else{
                                                    add_feedback_message($rule_tag,"uses an invalid destination $value" , $feedback_messages);
                                                    add_log2("warning", 'Reading Security Policy', 'Rule[' . $lid . ']. Destination "'.$value.'" not supported', $source, 'Destination '.$value.' not supported. Calculate the required objects','rules',$lid,'security_rules');
                                                }
                                                */
                                            }
                                        }
                                    }
                                    $resultingDestinationMembers = getCommonMembers($sub_destinations, $rule_destinations, $projectdb, $source, $vsys);

                                    //If the destinations of Parent and Child do not overlap, we can disable this rule :)
                                    if(!isset($resultingDestinationMembers) || count($resultingDestinationMembers)==0){
                                        $result_is_sub_rule_disabled = 1;
                                        $sub_rule_tag = $rule_entry['tag'];
                                        add_feedback_message($rule_tag,"destinations does not intersect with parent destinations" , $feedback_messages);
                                        add_log2("warning", 'Reading Security Policy. Disabled Jump', 'Rule[' . $lid . ']. The rule in sub-policy "'.$sub_rule_ref.'" position='.$subRulePosition.' with original tag="'.$sub_rule_tag.'" does not have destinations matching the parent rule.  Disabled for precaution.', $source, 'Determine whether this rule can be deleted','rules',$lid,'security_rules');
                                        $rules_to_check[] =  $lid;
                                        $resultingDestinationMembers = $sub_destinations;
                                        //break 1;   //This could speed up the parsing, if we don't want to load rules that are invalid and disabled
                                    }


                                    //Checking the service
                                    //echo "           SERVICES\n";
                                    foreach ($access_rule->match_part->match_services->match_service_ref as $match_service) {
                                        $value = normalizeNames($match_service["value"]);
                                        if(strcmp($value,"ANY")===0){
                                            $service = new MemberObject("ANY",'','','');
                                            $sub_services[] = $service;
                                        }
                                        else{
                                            $valueNorm=$value;
                                            if (isset($objectsInMemory['services'][$objects_vsys][$valueNorm])){
                                                $service_lid = $objectsInMemory['services'][$objects_vsys][$valueNorm]['id'];
                                                $service_port = $objectsInMemory['services'][$objects_vsys][$valueNorm]['dport'];
                                                $member = new MemberObject($service_lid, "services",$service_port);
                                                $sub_services[] = $member;
                                            }
                                            elseif(isset($objectsInMemory['services_groups_id'][$objects_vsys][$valueNorm])){
                                                $member_lid = $objectsInMemory['services_groups_id'][$objects_vsys][$valueNorm]['id'];
                                                $member = new MemberObject($member_lid, "services_groups_id");
                                                $sub_services[] = $member;
                                            }
                                            else{
                                                echo "XX Service '$value' was not found in '$objects_vsys' using name '$valueNorm'\n";
                                                $service_name_ext = $value;
                                                $service_name_int = truncate_names(normalizeNames($service_name_ext));
                                                $serv_description = $service_name_ext;
                                                //Adding the service in the system as an invalid service
                                                $query = "INSERT INTO services (type,name_ext,name,protocol,dport,checkit,description,source,sport,vsys, invalid, devicegroup) ".
                                                    "VALUES('','$service_name_ext','$service_name_int','tcp','65000','1','$serv_description','$source','','$objects_vsys', '1','Expedition created 4');";
//                                        echo $query.PHP_EOL;
//                                        echo "Line 1978\n";
                                                $projectdb->query($query);
                                                $member_lid = $projectdb->insert_id;
                                                $query = "INSERT INTO tag_relations (table_name, member_lid, tag_id) VALUES ('services','$member_lid','$invalid_tag_id')";
                                                $projectdb->query( "INSERT INTO tag_relations (table_name, member_lid, tag_id) VALUES ('services','$member_lid','$invalid_tag_id')");
                                                //echo "LINE 4267: $query\n";
                                                $member = new MemberObject($member_lid, "services");
                                                $sub_services[] = $member;
                                                $objectsInMemory['services'][$objects_vsys][$valueNorm]['id']=$member_lid;
                                                $objectsInMemory['services'][$objects_vsys][$valueNorm]['dport']="65000";
                                                add_feedback_message($rule_tag,"uses an invalid service $value" , $feedback_messages);
                                                add_log2("warning", 'Reading Security Policy', 'Rule[' . $lid . ']. Service "'.$value.'" not recognized', $source, 'Service '.$value.' not recognized. Calculate the required objects','rules',$lid,'security_rules');
                                            }
                                        }
                                    }
                                    $resultingServices = getCommonServices($sub_services, $rule_services, $projectdb, $source, $vsys);

                                    //If the Services of Parent and Child do not overlap, we can disable this rule :)
                                    if(!isset($resultingServices) || count($resultingServices)==0){
                                        $result_is_sub_rule_disabled = 1;
                                        $sub_rule_tag = $rule_entry['tag'];
                                        add_feedback_message($rule_tag,"services does not intersect with parent services" , $feedback_messages);
                                        add_log2("info", 'Reading Security Policy. Disabled Jump', 'Rule[' . $lid . ']. The rule in subpolicy "'.$sub_rule_ref.'" position='.$subRulePosition.' with original tag="'.$sub_rule_tag.'" does not have services matching the parent rule.  Disabled for precaution.', $source, 'Determine whether this rule can be deleted','rules',$lid,'security_rules');
                                        $resultingServices = $sub_services;
                                        $rules_to_check[] =  $lid;
                                        //break 1;   //This could speed up the parsing, if we don't want to load rules that are invalid and disabled
                                    }
                                }


                                //If we managed to find IPs that satisfy the parent rule and child rule, then we should create a new Rule entry
                                if(count($resultingSourceMembers)>0 && count($resultingDestinationMembers)>0 && count($resultingServices)>0){
                                    if($action === "jump"){
                                        get_sub_policy($configuration, $subrule_ref2, $result_is_sub_rule_disabled, $tag_ids, $vsys,
                                            $source, $project, $resultingSourceMembers, $resultingDestinationMembers, $resultingServices,
                                            $rule,$rules_to_check, $sources, $destinations, $services, $addTag, $comments,$objectsInMemory, $sub_policy_tag_id, $debug, $feedback_messages);
                                    }
                                    else{

                                        //Add the sources
                                        foreach($resultingSourceMembers as $rule_origin){
                                            if(strcmp($rule_origin->name, "ANY")!==0){
                                                $sources[] = "('$source','$vsys','$rule_origin->location','$rule_origin->name','$lid')";
                                            }
                                        }

                                        //Add the destinations
                                        foreach ($resultingDestinationMembers as $rule_destination){

                                            if(strcmp($rule_destination->name, "ANY")!==0){
                                                //TODO: Fix the comparision, because the $rule_destination is null at some cases.
                                                $destinations[] = "('$source','$vsys','$rule_destination->location','$rule_destination->name','$lid')";
                                            }
                                        }

                                        //Add the services
                                        foreach ($resultingServices as $rule_service){
                                            if(strcmp($rule_service->name, "ANY")!==0){
                                                $services[] = "('$source','$vsys','$rule_service->location','$rule_service->name','$lid')";
                                            }
                                        }

                                        $ruleDescription = 'Tag['.$rule_tag.']';
                                        if(count($comments)>0) {
                                            $ruleDescription .= ' '. implode('. ', $comments);
                                            $ruleDescription .= '. ' . $localComment;
                                        }

                                        //Add the new rules
                                        if($debug){
                                            echo "Final decision is $result_is_sub_rule_disabled\n";
                                        }

                                        $rule[] = "('$lid','$position','Rule $lid','$ruleDescription','$action','$result_is_sub_rule_disabled','$vsys','$source')";

                                        //Add the tags
                                        if(isset($tag_ids)){
                                            foreach ($tag_ids as $tag_id){
                                                $addTag[] = "('$source','$vsys','$lid','$tag_id','tag')";
                                            }
                                        }
                                        if(isset($additionalTags) && count($additionalTags)>0){
                                             foreach ($additionalTags as $tag_id){
                                                $addTag[] = "('$source','$vsys','$lid','$tag_id','tag')";
                                            }
                                            unset($additionalTags);//="";
                                        }
                                        if(isset($sub_policy_tag_id) && count($sub_policy_tag_id)>0){
                                            foreach ($sub_policy_tag_id as $tag_id){
                                                $addTag[] = "('$source','$vsys','$lid','$tag_id','tag')";
                                            }
                                            //unset($sub_policy_tag_id);//="";
                                        }

                                        if($result_is_sub_rule_disabled){
                                            $addTag[] = "('$source','$vsys','$lid','$disabled_subpolicy_tag_id','tag')";
                                        }

                                        //Increment the rule counters
                                        $lid++;
                                        $position++;
                                    }
                                }
                                else{
                                    $result_is_sub_rule_disabled = 1;
                                }
                            }
                        }
                    }
                }
                break;  //We found the sub_policy, so we do not need searching for it
            }
        }
    }

}

/**
 * Method to perform SQL Inserts into the services table. One Insert per service, tho.
 * @param unknown $projectdb
 * @param unknown $source
 * @param unknown $name_ext
 * @param unknown $name_int
 * @param unknown $vsys
 * @param unknown $protocol
 * @param unknown $sport
 * @param unknown $dport
 * @param unknown $description
 */
function services_insert($projectdb, $source, $name_ext, $name_int, $vsys, $protocol, $sport, $dport, $description){

    $getDup = $projectdb->query("SELECT id FROM services WHERE source='$source' AND name_ext='$name_ext' AND vsys='$vsys';");
    $service_type = null;
    if ($getDup->num_rows == 0) {
        if (preg_match("#([0-9]+)\-([0-9]+)#", $dport)) {
            $service_type = "range";
        }
        else {
            $service_type = "service";
        }
        if ($sport == "1-65535") {
            $sport = "";
        }
        $query = "INSERT INTO services (type,name_ext,name,protocol,dport,checkit,description,source,sport,vsys) VALUES('$service_type','$name_ext','$name_int','$protocol','$dport','0','$description','$source','$sport','$vsys');";
//        echo $query.PHP_EOL;
//        echo "Line 2553\n";
        $projectdb->query($query);
    }
}

function get_Services($configuration, $vsys, $source) {

    global $projectdb;
    global $like_panorama;

    //TCP services
    /*
     * Sample:
     *    	<service_tcp min_dst_port="1" max_dst_port="2" name="0_TCP-1and2" protocol_agent_ref="AnAgent" protocol_agent_ref_key="1">
                  <pa_value param_description="Allow related connections" value="true"/>
                  <pa_value param_description="Max. length allowed for one TNS packet" value="4096"/>
                  <pa_value param_description="Netmask for allowed server addresses" value="255.255.255.255"/>
                  <pa_value param_description="Set checksum to zero for modified TNS packets" value="Yes"/>
                  <pa_value param_description="Bytes allowed from client before Server ID" value="0"/>
                  <pa_value param_description="Bytes allowed from server before Client ID" value="0"/>
                  <pa_value param_description="Bytes allowed from server before Server ID" value="0"/>
                <pa_value param_description="Make protocol validation" value="true"/>
                  <pa_value param_description="Allow active mode" value="Yes"/>
                  <pa_value param_description="Allow passive mode" value="Yes"/>
                  <pa_value param_description="Allow related connections" value="true"/>
                  <pa_value param_description="Control data inspection mode" value="Loose"/>
                  <pa_value param_description="Highest allowed source port for Active data connection" value="0"/>
                  <pa_value param_description="Lowest allowed source port for Active data connection" value="0"/>
                  <pa_value cisserver_name="none" param_description="Redirect connections to CIS"/>
               </service_tcp>
     */
    $services_tcp = $configuration->xpath("//service_tcp");

    foreach($services_tcp as $service_tcp){
        $attributes = $service_tcp->attributes();
        $name_ext = normalizeNames($attributes["name"]);
        $name_int = truncate_names(normalizeNames($name_ext));
        $protocol = "tcp";
        $dport = $attributes["min_dst_port"];
        $service_type="service";
        if(isset($attributes["max_dst_port"]) && (int)$attributes["max_dst_port"]!==(int)$dport){ //Checking is a range of ports is defined
            $dport .= "-" . $attributes["max_dst_port"];
            $service_type="range";
        }

        $description = addslashes($attributes["comment"]);
        $sport = $attributes["min_src_port"]??'';
        if(isset($attributes["max_src_port"]) && (int)$attributes["max_src_port"]!==(int)$sport){ //Checking is a range of ports is defined
            $sport .= "-" . $attributes["max_src_port"];
        }

        $srv[] = "('$service_type','$name_ext','$name_int','$protocol','$dport','0','$description','$source','$sport','$vsys')";
    }



    //UDP services
    /*
     * Sample:
     * 		   <service_udp max_dst_port="33" max_src_port="54" min_dst_port="22" min_src_port="1" name="UDP_service_1"/>
     */
    $services_udp = $configuration->xpath("//service_udp");

    foreach($services_udp as $service_udp){
        $attributes = $service_udp->attributes();
        $name_ext = normalizeNames($attributes["name"]);
        $name_int = truncate_names(normalizeNames($name_ext));
        $protocol = "udp";
        $dport = $attributes["min_dst_port"];
        $service_type="service";
        if(isset($attributes["max_dst_port"]) && (int)$attributes["max_dst_port"]!==(int)$dport){ //Checking is a range of ports is defined
            $dport .= "-" . $attributes["max_dst_port"];
            $service_type="range";
        }

        $description = addslashes($attributes["comment"]);
        $sport = $attributes["min_src_port"]??'';
        if(isset($attributes["max_src_port"]) && (int)$attributes["max_src_port"]!==(int)$sport){ //Checking is a range of ports is defined
            $sport .= "-" . $attributes["max_src_port"];
        }

        $srv[] = "('$service_type','$name_ext','$name_int','$protocol','$dport','0','$description','$source','$sport','$vsys')";
    }

    //IP services
    /*
     * Sample:
     * 			<service_ip name="ICMP inspection" protocol_agent_ref="ICMP" protocol_agent_ref_key="4343" protocol_number="1"/>
     */
    $service_ips = $configuration->xpath("//service_ip");

    foreach($service_ips as $service_ip){
        $attributes = $service_ip->attributes();
        $name_ext = normalizeNames($attributes["name"]);
        $name_int = truncate_names(normalizeNames($name_ext));

        //Probably we would have to know the list of protocol numbers, and do the matching based on it.
        $protocol = $attributes["protocol_number"];

        $dport = $attributes["min_dst_port"];
        $service_type=null;
        if(isset($attributes["max_dst_port"]) && (int)$attributes["max_dst_port"]!==(int)$dport){ //Checking is a range of ports is defined
            $dport .= "-" . $attributes["max_dst_port"];
            $service_type="range";
            if ($dport === "1-65535") {
                $dport = "";
            }
        }else{
            $service_type = "service";
        }

        $checkit="0";
        $description = addslashes($attributes["comment"]);
        $sport = $attributes["min_src_port"]??'';
        if(isset($attributes["max_src_port"]) && (int)$attributes["max_src_port"]!=(int)$sport){ //Checking is a range of ports is defined
            $sport .= "-" . $attributes["max_src_port"];
            if ($sport === "1-65535") {
                $sport = "";
            }
        }

        $srv[] = "('$service_type','$name_ext','$name_int','$protocol','$dport','$checkit','$description','$source','$sport','$vsys')";
    }

    if (count($srv) > 0) {
        $uniq = array_unique($srv);
//        print_r($uniq);
        $out = implode(",", $uniq);
        $query = "INSERT INTO services (type,name_ext,name,protocol,dport,checkit,description,source,sport,vsys) VALUES " . $out . ";";
//        echo $query.PHP_EOL;
//        echo "Line 2687\n";
        $projectdb->query($query);
    }
}

function get_ServicesGroups(SimpleXMLElement $configuration, STRING $vsys, STRING $source) {

    global $projectdb;
    $vsys = normalizeNamesNew($vsys, 9, 'vsys');

    $gen_service_groups = $configuration->xpath("//gen_service_group");
    $tcp_service_groups = $configuration->xpath("//tcp_service_group");
    $udp_service_groups = $configuration->xpath("//udp_service_group");

    $merge_arrays=array_merge($gen_service_groups,$tcp_service_groups,$udp_service_groups);

    $srv = array();
    foreach ($merge_arrays as $service_group) {
        $name_ext = trim(normalizeNames($service_group["name"]));
        $name_int = truncate_names(normalizeNames($name_ext));

        $getDup = $projectdb->query("SELECT id FROM services_groups_id WHERE source='$source' AND vsys='$vsys' AND name_ext='$name_ext';");
        if ($getDup->num_rows === 0) {
            $projectdb->query("INSERT INTO services_groups_id (name_ext,name,source,vsys) VALUES ('$name_ext','$name_int','$source','$vsys');");
            $lid = $projectdb->insert_id;
            foreach ($service_group->service_ref as $service) {
//                $member = normalizeNames($service["ref"]);
                $member = normalizeNames($service["ref"]);
                if($member!==$name_int)
                {
                    $getDup = $projectdb->query("SELECT id FROM services_groups WHERE lid='$lid' AND member='$member'; ");
                    if ($getDup->num_rows === 0) {
                        $srv[] = "('$lid','$member','$source','$vsys')";
                    }
                    //Looking for predefined services
                    $exist = $projectdb->query("SELECT id FROM services WHERE name_ext in ('$member')");
                    if($exist->num_rows === 0){
                        //TODO: echo "The service $member should be added by default\n";
                    }
                }else{
                    echo "Service group $name_int has itself as member - not adding itself as member to skip the loop \n";
                    add_log('warning', 'Reading Services Objects and Groups', 'Service group '. $name_int . ' has itself as member - not adding itself as member to skip the loop', $source, 'No Action Required');
                }
            }
        }
    }
    if (count($srv) > 0) {
        $uniq = array_unique($srv);
        $out = implode(",", $uniq);
        $projectdb->query("INSERT INTO services_groups (lid, member, source, vsys) VALUES " . $out . ";");
    }
}

function get_Firewall_Addresses(SimpleXMLElement $configuration, STRING $vsys, STRING $source, STRING $policy_to_load, STRING $firewall, $template){
    global $projectdb;
    global $project;
    $address_groups = array();
    $agi = array();

    renewDBConnection();
    $alias_tag_id = get_tag_id($projectdb, "Alias Object", $source, $vsys);


    //$firewall_alias_value = $configuration->xpath("//fw_cluster[@name='".$firewall."']/alias_value");

    $all_clusters = $configuration->xpath("//fw_cluster");
    foreach ($all_clusters as $cluster){
        if(normalizeNames($cluster['name']) == $firewall){
            if(isset(get_object_vars($cluster)['alias_value'])) {
                $firewall_alias_value = get_object_vars($cluster)['alias_value'];
            }
            break;
        }
    }


//    $aliases = $configuration->xpath("//alias");
//    foreach ($aliases as $alias){
    if(isset($firewall_alias_value)) {
        foreach ($firewall_alias_value as $alias) {
            $name_ext = trim(normalizeNames($alias["alias_ref"]));
            $node = dom_import_simplexml($alias);
            $description = normalizeNames(isset($alias["comment"]) ? $alias["comment"] : 'Line ' . $node->getLineNo());
            $name_int = truncate_names(normalizeNames($name_ext));

            $projectdb->query("INSERT INTO address_groups_id (name_ext,name,description, source,vsys) VALUES ('$name_ext','$name_int','$description','$source','$vsys');");
            $lid = $projectdb->insert_id;

            $agi[] = "('address_groups_id','$lid','$alias_tag_id')";

            foreach ($alias->ne_list as $ne_list) {
                $member = trim(normalizeNames($ne_list["ref"]));
                $name_int = truncate_names(normalizeNames($member));
                $address_groups[] = "('$lid','$member','$name_int','$member','$source', '$vsys')";
            }
        }
    }
    //Insert all the relations
    if (count($address_groups) > 0) {
        $uniq = array_unique($address_groups);
        $out = implode(",", $uniq);
        $query = "INSERT INTO address_groups (lid, name_ext,name,member,source,vsys) VALUES " . $out . ";";
        $projectdb->query($query);

        $uniq = array_unique($agi);
        $out = implode(",", $uniq);
        $query = "INSERT INTO tag_relations (table_name, member_lid, tag_id) VALUES ".$out.";";
        $projectdb->query("INSERT INTO tag_relations (table_name, member_lid, tag_id) VALUES ".$out.";");
    }
}

function get_Address_Group(SimpleXMLElement $configuration, STRING $vsys, STRING $source, int $level=0) {
//function get_Address_Group(SimpleXMLElement $configuration, STRING $vsys, STRING $source, STRING $policy_to_load, STRING $firewall, $template) {
    global $projectdb;
    $address_groups = array();

    $lastAddressID = getLastId("address");
//    $query = "SELECT max(id) as lastID FROM address";
//    $result = $projectdb->query($query);
//    if($result->num_rows===1){
//        $data = $result->fetch_assoc();
//        $lastAddressID = $data['lastID'];
//    }
//    else{
//        $lastAddressID = 1;
//    }

    $lastAddress_groupsID = getLastId("address_groups_id");
//    $query = "SELECT max(id) as lastID FROM address_groups_id";
//    $result = $projectdb->query($query);
//    if($result->num_rows===1){
//        $data = $result->fetch_assoc();
//        $lastAddress_groupsID = $data['lastID'];
//    }
//    else{
//        $lastAddress_groupsID = 1;
//    }

    $groups = $configuration->xpath("//group");
    foreach ($groups as $group){
        $name_ext = trim(normalizeNames($group["name"]));
        if(!object_belongs_here($level, $name_ext)) {
            continue;
        }
        $description = normalizeNames($group["comment"]);
        $name_int = truncate_names(normalizeNames($name_ext));

        $projectdb->query("INSERT INTO address_groups_id (name_ext,name,description, source,vsys) " .
            "VALUES ('$name_ext','$name_int','$description','$source','$vsys');");
        $lid = $projectdb->insert_id;

        foreach ($group->ne_list as $member) {
            $ip_address = trim(normalizeNames($member["ref"]));
            $name_int = truncate_names(normalizeNames($ip_address));
            $address_groups[] = "('$lid','$ip_address','$name_int','$ip_address','$source', '$vsys')";
        }
    }


    /*
     * Loading server_pools
     */
    $server_pools = $configuration->xpath("//server_pool");
    foreach ($server_pools as $server_pool){
        $name_ext = trim(normalizeNames($server_pool["name"]));
        if(!object_belongs_here($level, $name_ext)) {
            continue;
        }
        $description = normalizeNames($server_pool["comment"]);
        $name_int = truncate_names(normalizeNames($name_ext));

        $projectdb->query("INSERT INTO address_groups_id (name_ext,name,description, source,vsys) VALUES ('$name_ext','$name_int','$description','$source','$vsys');");
        $lid = $projectdb->insert_id;

        foreach($server_pool->ne_list as $ne_list){
            $ip_address = trim(normalizeNames($ne_list["ref"]));
            $name_int = truncate_names(normalizeNames($ip_address));
            $address_groups[] = "('$lid','$ip_address','$name_int','$ip_address','$source', '$vsys')";
        }

    }


    /*
     * Loading log_servers
     */
    $log_servers = $configuration->xpath("//log_server");
    foreach ($log_servers as $log_server){
        $name_ext = trim(normalizeNames($log_server["name"]));
        if(!object_belongs_here($level, $name_ext)) {
            continue;
        }
        $name_int = truncate_names(normalizeNames($name_ext));

        $projectdb->query("INSERT INTO address_groups_id (name_ext,name, source,vsys) VALUES ('$name_ext','$name_int','$source','$vsys');");
        $lid = $projectdb->insert_id;

        //Get the primary IP
        $log_server_i=1;
        foreach($log_server->multi_contact_mvia as $ne_list){
            $ip_address = trim(normalizeNames($ne_list["address"]));
            $name_address = trim(truncate_names($name_ext, 60)."_".$log_server_i);
            $log_server_i++;
            $name_internal = truncate_names(normalizeNames($name_address));

            //Search for the AddressObject
            $query = "SELECT id FROM address WHERE source = '$source' AND vsys='$vsys' AND name = '$name_address' LIMIT 1";
            $result_address = $projectdb->query($query);
            if($result_address->num_rows === 1){
                $data = $result_address->fetch_assoc();
                $member_lid = $data['id'];
                $projectdb->query("INSERT INTO address_groups (name, name_ext, member, member_lid,table_name,lid, source,vsys) VALUES ('$name_address','$name_address','$name_address','$member_lid','address','$lid','$source','$vsys');");
            }
            else{
                $query_Insert_address = "INSERT INTO address (name, name_ext, devicegroup, ipaddress, cidr, source, vsys,vtype) VALUES ('$name_address','$name_internal','default','$ip_address','32','$source', '$vsys','ip-netmask');";
                $projectdb->query($query_Insert_address);
                $address_lid = $projectdb->insert_id;
                $projectdb->query("INSERT INTO address_groups (name, name_ext, member, member_lid,table_name,lid, source,vsys) VALUES ('$name_address','$name_address','$name_address','$address_lid','address','$lid','$source','$vsys');");
            }
        }

        //Get the secondary servers IPs
        foreach ($log_server->secondary_log_server_ref as $secondary){
            $secondary_Name = $secondary['value'];
            $secondary_servers = $configuration->xpath("//log_server[@name='".$secondary_Name."']");
            foreach ($secondary_servers as $secondary_server) {
                $secondaryIP = $secondary_server->multi_contact_mvia["address"];

                $name_address = trim(truncate_names($name_ext, 60)."_".$log_server_i);
                $log_server_i++;
                $name_internal = truncate_names(normalizeNames($name_address));

                //Search for the AddressObject
                $query = "SELECT id FROM address WHERE source='$source' AND vsys='$vsys' AND name='$name_address' LIMIT 1";
                $result_address = $projectdb->query($query);
                if($result_address->num_rows === 1){
                    $data = $result_address->fetch_assoc();
                    $member_lid = $data['id'];
                    $projectdb->query("INSERT INTO address_groups (name, name_ext, member, member_lid,table_name,lid, source,vsys) VALUES ('$name_address','$name_address','$name_address','$member_lid','address','$lid','$source','$vsys');");
                }
                else{
                    $query_Insert_address = "INSERT INTO address (name, name_ext, devicegroup, ipaddress, cidr, source, vsys,vtype) VALUES ('$name_address','$name_internal','default','$ip_address','32', '$source','$vsys','ip-netmask');";
                    $projectdb->query($query_Insert_address);
                    $address_lid = $projectdb->insert_id;
                    $projectdb->query("INSERT INTO address_groups (name, name_ext, member, member_lid,table_name,lid, source,vsys) VALUES ('$name_address','$name_address','$name_address','$address_lid','address','$lid','$source','$vsys');");
                }
            }
        }
    }



    /*
     * Loading aliases
     */
    //<fw_cluster
//    $fw_policies = $configuration->xpath("//fw_policy");
//    $fw_template_policies = $configuration->xpath("//fw_template_policy");
//    $fw_policies = array_merge($fw_policies, $fw_template_policies);
//    foreach ($fw_policies as $fw_policy){
//        $isInMapping = in_array(strval($fw_policy['name']), $mappings);

    /*
    // MOVED TO get_Firewall_Addresses()
    $firewall_alias_value = $configuration->xpath("//fw_cluster[@name='".$firewall."']/alias_value");

//    die;
//    $aliases = $configuration->xpath("//alias");
//    foreach ($aliases as $alias){
    foreach ($firewall_alias_value as $alias){
        $name_ext = trim(normalizeNames($alias["alias_ref"]));
        $node = dom_import_simplexml($alias);
        $description = normalizeNames(isset($alias["comment"])?$alias["comment"]:'Line '.$node->getLineNo());
        $name_int = truncate_names(normalizeNames($name_ext));

        $projectdb->query("INSERT INTO address_groups_id (name_ext,name,description, source,vsys) VALUES ('$name_ext','$name_int','$description','$source','$vsys');");
        $lid = $projectdb->insert_id;

        foreach($alias->ne_list as $ne_list){
            $member = trim(normalizeNames($ne_list["ref"]));
            $name_int = truncate_names(normalizeNames($ip_address));
            $address_groups[] = "('$lid','$member','$name_int','$member','$source', '$vsys')";
        }
    }
    */

    //Insert all the relations
    if (count($address_groups) > 0) {
        $uniq = array_unique($address_groups);
        $out = implode(",", $uniq);
        $query = "INSERT INTO address_groups (lid, name_ext,name,member,source,vsys) VALUES " . $out . ";";
        $projectdb->query($query);
    }
}

function get_Exclusion_members(SimpleXMLElement $element, array &$warnings=[]):array{
    $local_members = [];
    foreach ($element->expression_value as $expression_value){
        if(isset($expression_value['ne_ref'])){
            $local_members[] = normalizeNames((string)$expression_value['ne_ref']);
        }

        if(isset($expression_value['operator'])){
            if((string)$expression_value['operator'] === 'union'){
                $inner_members = get_Exclusion_members($expression_value, $warnings);
                $local_members = array_merge($local_members, $inner_members);
            }
            elseif ((string)$expression_value['operator'] === 'intersection'){
                $warnings[] = 'Includes an inner '.(string)$expression_value['operator'];
                $inner_members = get_Exclusion_members($expression_value,$warnings);
                $local_members = array_merge($local_members, $inner_members);
            }
            elseif ((string)$expression_value['operator'] === 'exclusion'){
                $warnings[] = 'Includes an inner '.(string)$expression_value['operator'];
                $inner_members = get_Exclusion_members($expression_value, $warnings);
                $local_members = array_merge($local_members, $inner_members);
            }
            else{
                $warnings[] = 'Includes an inner '.(string)$expression_value['operator'];
            }
        }
    }

    return $local_members;
}


function calculate_expression_members(STRING $vsys, INT $source){
    global $projectdb;

    $new_members = [];
    $new_tags = [];
    $lid = getLastId('address');

    $vsyses = getVsyses($projectdb, $vsys, $source, 'quoted');

    $query = "SELECT id, name, expression FROM address_groups_id WHERE expression !='' and source ='$source' and vsys in (".implode(",",$vsyses).")";
    $result = $projectdb->query($query);

    while($data = $result->fetch_assoc()){
        $address_groups_id = $data['id'];
        $name = $data['name'];
        $expression = json_decode($data['expression'], true);
//        print_r($expression);
        $members = get_members_in_expression($expression, $vsyses, $source);
//        echo "For $name:\n";
//        print_r($members);
//        echo "\n\n";
        $i=0;
        $filter_name = addslashes("'G_". $address_groups_id ." members'");
        $projectdb->query("INSERT INTO tag (name,color,comments,source,vsys) VALUES ('$filter_name','color7','Dynamic members for $name in $vsys','$source','$vsys');");
        $tag_id = $projectdb->insert_id;
        $lengh = count($members);

        foreach ($members as $member) {
            // if expression is returning a valid member then proceed it
            if(isset($member['start'],$member['end'])) {
                list($type, $ip_range) = Expression::toRange($member);
                $member_name = sprintf('G_%2$s member_%1$04d', $i, $address_groups_id);
                $new_members[] = "('$lid','$member_name','$member_name', 1, '$vsys', '$type','$ip_range',32,'Calculated member for $name in $vsys', 1, 0, '$type', $source)";
                $new_tags[] = "('address',$lid,$tag_id)";
                $lid++;
                $i++;
            }
            else {
                echo "member for name:$name , expression:$expression was not found on the scope of vsys:$vsys and source:$source\n";
            }
        }
        $update_to_dynamic_query = "UPDATE address_groups_id SET filter='$filter_name', type ='dynamic' WHERE id='$address_groups_id'";
        $projectdb->query($update_to_dynamic_query);
    }

    if(count($new_members)>0){
        $new_members = array_unique($new_members);
        $query = "INSERT INTO address (id, name, name_ext, used, vsys, type, ipaddress, cidr, description, v4, v6, vtype, source) VALUES ".implode(",",$new_members). ";";
        $projectdb->query($query);

        $new_tags = array_unique($new_tags);
        $query = "INSERT INTO tag_relations (table_name, member_lid, tag_id) VALUES ".implode(",",$new_tags).";";
        $projectdb->query($query);
       // echo "LINE 4888: $query\n";
    }

}

function get_members_in_expression(array $expression, array $vsyses, int $source):array{

    if(!isset($expression['operator'])) {
        if (isset($expression[0])) {
            return get_object_ranges($expression[0], $vsyses, $source);
        } else {
            return [];
        }
    }
    $operator = $expression['operator'];
    $operand1 = isset($expression['operand1'])?$expression['operand1']:[];
    $operand2 = isset($expression['operand2'])?$expression['operand2']:[];

    switch($operator){
        case '∩':
            return Expression::intersect(
                get_members_in_expression($operand1, $vsyses, $source),
                get_members_in_expression($operand2, $vsyses, $source)
            );
        case '∪':
            return Expression::union(
                get_members_in_expression($operand1, $vsyses, $source),
                get_members_in_expression($operand2, $vsyses, $source)
            );

        case '~':
            return Expression::negate(
                get_members_in_expression($operand1, $vsyses, $source)
            );

        default:
            return [];
    }
}

/***
 * Looks for the reference for an object given its name and the priorities in DGs
 * @param $name
 * @param $vsyses
 * @param $source
 * @return array|null[] [member_lid, table_name]
 */
function get_object_reference(string $name, array $vsyses, int $source):array{
    global $projectdb;
    $name = truncate_names(normalizeNames($name));
    $query = "SELECT id, vsys FROM address WHERE name = '$name' AND source = $source AND vsys in (".implode(",", $vsyses).")";
    $result = $projectdb->query($query);
    if($result->num_rows>0){
        $matches = [];
        while($data = $result->fetch_assoc()){
            $matches[$data['vsys']] = $data['id'];
        }

        foreach ($vsyses as $vsys){
            $vsys = trim($vsys, "'");
            if(isset($matches[$vsys])){
                return [
                    $matches[$vsys],
                    'address'
                ];
            }
        }
        return [null, null];
    }

    $query = "SELECT id, vsys FROM address_groups_id WHERE name = '$name' AND source = $source AND vsys in (".implode(",", $vsyses).")";
    $result = $projectdb->query($query);
    if($result->num_rows>0){
        $matches = [];
        while($data = $result->fetch_assoc()){
            $matches[$data['vsys']] = $data['id'];
        }

        foreach ($vsyses as $vsys){
            $vsys = trim($vsys, "'");
            if(isset($matches[$vsys])){
                return [
                    $matches[$vsys],
                    'address_groups_id'
                ];
            }
        }
        return [null, null];
    }

    echo "$name object was not found on the scope of ".implode(",", $vsyses)."\n";

    return [null, null];
}

function get_object_ranges(string $object_name, array $vsyses, int $source): array{
    global $projectdb;

    list($member_id, $table_name) = get_object_reference($object_name, $vsyses, $source);

    if ($table_name === 'address') {
        $res = resolveIP_Start_End('',$member_id, $table_name);
        return [$res];
    }

    if($table_name === 'address_groups_id') {
        $members = explodeGroups2Members([new MemberObject($member_id, $table_name)], $projectdb, $source, $vsyses[0]);
        $ip_values = [];
        foreach ($members as $member){
            $ip_values[] = resolveIP_Start_End('', $member->name, $member->location);
        }
        return $ip_values;
    }
    return [];
}


/**
 *
 */
function get_Expressions(SimpleXMLElement $configuration, STRING $vsys, STRING $source){
    global $projectdb;
    global $expression_tag_id;

    //echo "GETTING EXCLUSIONS FOR vsys $vsys\n";
    $ip_address_ranges = array();
    $address_groups = array();

    $expression_tag_id = get_tag_id($projectdb, "Expression Object", $source, $vsys);
    $expressions = $configuration->xpath("//expression");
    foreach ($expressions as $expression){
        $name_ext = trim(normalizeNames($expression["name"]));
        $name_int = truncate_names(normalizeNames($name_ext));

        $description = normalizeNames($expression["comment"]);
        $expression_string = addslashes(expression_interpreter($expression));

        $query = "INSERT INTO address_groups_id (name_ext,name,description, expression, filter, source,vsys) ".
            "VALUES ('$name_ext','$name_int','$description','$expression_string','exclusion-group','$source','$vsys');";
        $projectdb->query($query);
        $lid = $projectdb->insert_id;

        $addTag[] = "('address_groups_id','$lid','$expression_tag_id')";


//        if((string)$expression["operator"]==="exclusion"){
//            add_log2('warning', 'Exclusion expression found. ', 'Review this object is only used in Negated rules and not combined with not-negated objects', $source, 'Review', 'objects', $lid, 'address_groups_id');
//
//            $addTag[] = "('address_groups_id','$lid','$negated_tag_id')";
//
//            $warnings = [];
//            $members = get_Exclusion_members($expression, $warnings);
//            //print_r($members);
//            //print_r($warnings);
//            $query_update_to_invalid = "UPDATE address_groups_id SET invalid=1 WHERE id=$lid;";
//            if(count($warnings)>0) {
//                $projectdb->query($query_update_to_invalid);
//                $warnings = array_unique($warnings);
//                foreach ($warnings as $warning) {
//                    add_log2('warning', 'Exclusion expression found. ', "$warning", $source, 'Review', 'objects', $lid, 'address_groups_id');
//                }
//            }
//        }
//        elseif((string)$expression["operator"]==="intersection"){
//            add_log2('warning', 'Exclusion expression found. ', 'Review this object is only used in Negated rules and not combined with not-negated objects', $source, 'Review', 'objects', $lid, 'address_groups_id');
//            $projectdb->query($query_update_to_invalid);
//            $addTag[] = "('address_groups_id','$lid','$negated_tag_id')";
//
//            $warnings = [];
//            $members = get_Exclusion_members($expression, $warnings);
//            //print_r($members);
//            //print_r($warnings);
//            $query_update_to_invalid = "UPDATE address_groups_id SET invalid=1 WHERE id=$lid;";
//            if(count($warnings)>0) {
//                foreach ($warnings as $warning) {
//                    add_log2('warning', 'Exclusion expression found. ', "$warning", $source, 'Review', 'objects', $lid, 'address_groups_id');
//                }
//            }
//        }

//        foreach($members as $member_name){
//            $getInfoMembers = $projectdb->query("SELECT id FROM address WHERE name_ext = '$member_name' AND source='$source';");
//            if ($getInfoMembers->num_rows > 0) {
//                $dataM = $getInfoMembers->fetch_assoc();
//                $member_lid = $dataM['id'];
//                $table_name = "address";
//                $address_groups[] = "('$lid','$member_lid','$table_name','$source', '$vsys')";
//            }
//            else{
//                $getInfoMembers = $projectdb->query("SELECT id FROM address_groups_id WHERE name_ext = '$member_name' AND source='$source';");
//                if ($getInfoMembers->num_rows > 0) {
//                    $dataM = $getInfoMembers->fetch_assoc();
//                    $member_lid = $dataM['id'];
//                    $table_name = "address_groups_id";
//                    $address_groups[] = "('$lid','$member_lid','$table_name','$source', '$vsys')";
//                    //echo "              $member_name found as an address-group!!!\n";
//
//                }
//                else{
//                    $projectdb->query($query_update_to_invalid);
//                    echo "              $member_name Not found!!!\n";
//                    add_log2(
//                        'warning',
//                        'Exclusion expression found. ',
//                        'Review this object. It should include the member '.$member_name.', which may be an Exclusion object itself.',
//                        $source,
//                        'Review',
//                        'objects',
//                        $lid,
//                        'address_groups_id');
//                }
//            }
//        }
    }

    //Insert members relations
//    if (count($address_groups) > 0) {
//        $uniq = array_unique($address_groups);
//        $out = implode(",", $uniq);
//        $query = "INSERT INTO address_groups (lid, member_lid,table_name, source,vsys) VALUES " . $out . ";";
////        echo "\n$query\n\n";
//        $projectdb->query($query);
////        echo mysqli_error($projectdb);
////        echo "affected rows: ".$projectdb->affected_rows;
//    }

    if(isset($addTag) && count($addTag)>0){
        $uniq = array_unique($addTag);
        $out = implode(",", $uniq);
        $query = "INSERT INTO tag_relations (table_name, member_lid, tag_id) VALUES " . $out . ";";
        $projectdb->query("INSERT INTO tag_relations (table_name, member_lid, tag_id) VALUES " . $out . ";");
        //echo "LINE 5115: $query\n";
    }
}


/***
 * Evaluates an expression formula and translates it into a new syntax for Palo Alto Networks
 * @param SimpleXMLElement $expression
 * @return string
 */
function expression_interpreter(SimpleXMLElement $expression):string{
    $operator = (string) $expression['operator'];
    $operands = [];
    foreach($expression->children() as $operand){
        $operands[] = $operand;
    }

    switch($operator){
        case 'intersection':
            if(count($operands)!==2){
                echo "Intersection requires two operands";
            }
            return json_encode([
                'operator'  => "∩",
                'operand1'  => json_decode(expression_interpreter($operands[1])),
                'operand2'  => json_decode(expression_interpreter($operands[0]))
            ]);
                //"(".expression_interpreter($operands[1])." ∩ ".expression_interpreter($operands[0]).")";

        case 'exclusion':
            if(count($operands)!==1){
                echo "Intersection requires two operands";
            }
            return json_encode([
                'operator' => '~',
                'operand1' => json_decode(expression_interpreter($operands[0]))
            ]);

                //"(~".expression_interpreter($operands[0]).")";

        case 'union':
            if(count($operands)!==2){
                echo "Intersection requires two operands";
            }
            return json_encode([
                'operator'  => "∪",
                'operand1'  => json_decode(expression_interpreter($operands[1])),
                'operand2'  => json_decode(expression_interpreter($operands[0]))
            ]);
            // "(".expression_interpreter($operands[1])." ∪ ".expression_interpreter($operands[0]).")";

        default:
            return json_encode($expression['ne_ref']);

            // "'".$expression['ne_ref']."'";
    }
}

/**
 *
 */
function get_Exclusions_old(SimpleXMLElement $configuration, STRING $vsys, STRING $source){
    global $projectdb;

    echo "GETTING EXCLUSIONS FOR vsys $vsys\n";
    $ip_address_ranges = array();
    $address_groups = array();
    /*
    * We start looking for exclusion groups
    * We will have to check whether a group is excluded or not during the rule creation
    */
    $expressions = $configuration->xpath("//expression");
    foreach ($expressions as $expression){
        if((string)$expression["operator"]==="exclusion"){
            $name_ext = trim(normalizeNames($expression["name"]));
            echo "   Need to process $name_ext\n";
            $description = normalizeNames($expression["comment"]);
            $name_int = truncate_names(normalizeNames($name_ext));

            $projectdb->query("INSERT INTO address_groups_id (name_ext,name,description, filter, source,vsys) ".
                "VALUES ('$name_ext','$name_int','$description','exclusion-group','$source','$vsys');");
            $lid = $projectdb->insert_id;

            $fakeMapping['map'][] = Array('start' => 0, 'end' => ip2long('255.255.255.255'));


            foreach ($expression->expression_value as $expression_value){
                $value = normalizeNames($expression_value["ne_ref"]);
                echo "        Contains $value\n";

                //Look for this member ONLY for IPv4 by now
                $getInfoMembers = $projectdb->query("SELECT id FROM address WHERE name_ext = '$value' AND v4=1;");
                if ($getInfoMembers->num_rows > 0) {
                    $dataM = $getInfoMembers->fetch_assoc();
                    $member_lid = $dataM['id'];
                    $table_name = "address";
                }
                else{
                    $getInfoMembers = $projectdb->query("SELECT id FROM address_groups_id WHERE name_ext = '$value';");
                    if ($getInfoMembers->num_rows > 0) {
                        $dataM = $getInfoMembers->fetch_assoc();
                        $member_lid = $dataM['id'];
                        $table_name = "address_groups_id";
                    }
                    else{
                        $member_lid = '';
                        $table_name = "address_groups_id";
                    }
                }

                $objectsMapping = getIP4Mapping("", $member_lid, $table_name);

                foreach ($objectsMapping['map'] as $entry){
                    removeNetworkFromIP4Mapping($fakeMapping['map'], $entry);
                    //$objectsMapping = $fakeMapping;
                }
            }

            $descriptionRange = normalizeNames("Automatically generated from $name_ext. $description");
            foreach ($fakeMapping['map'] as $fakeRange){
                $ipRange = long2ip($fakeRange['start'])."-".long2ip($fakeRange['end']);
                $nameRange = "$name_ext-Range_$ipRange";
                $name_int = truncate_names(normalizeNames($nameRange));
                $ip_address_ranges[] = "('$nameRange','$name_int', '$ipRange','', 1, 0, 'ip-range', 'ip-range', '$descriptionRange','$source', '$vsys')";
                $address_groups[] = "('$lid','$nameRange','$name_int','$nameRange','$source', '$vsys')";
            }

            //Insert all the ranges
            if (count($ip_address_ranges) > 0) {
                $uniq = array_unique($ip_address_ranges);
                $out = implode(",", $uniq);
                $projectdb->query("INSERT INTO address (name_ext,name,ipaddress,cidr, v4,v6,type,vtype,description, source,vsys) VALUES " . $out . ";");
                $uniq = array_unique($address_groups);        $out = implode(",", $uniq);
                $projectdb->query("INSERT INTO address_groups (lid, name_ext,name,member,source,vsys) VALUES " . $out . ";");
            }
        }
    }
}

function get_AddressExpressions(SimpleXMLElement $configuration, STRING $vsys, STRING $source){
//function get_AddressExpressions(SimpleXMLElement $configuration, STRING $vsys, STRING $source, $template){
    global $projectdb;
    global $match_expressionsInMemory;
    global $expression_tag_id;

    $inMemory = array();
    $query = "SELECT * FROM address WHERE vsys='$vsys' AND source='$source'";
    $result = $projectdb->query($query);
    if($result->num_rows > 0){
        while($data = $result->fetch_assoc()){
            $nombre = $data['name'];
            $inMemory['address'][$nombre] = $data;
        }
    }

    $query = "SELECT * FROM address_groups_id WHERE vsys='$vsys' AND source='$source'";
    $result = $projectdb->query($query);
    if($result->num_rows > 0){
        while($data = $result->fetch_assoc()){
            $nombre =$data['name'];
            $inMemory['address_groups_id'][$nombre] = $data;
        }
    }

    $query = "SELECT * FROM zones WHERE vsys='$vsys' AND source='$source'";
    $result = $projectdb->query($query);
    if($result->num_rows > 0){
        while($data = $result->fetch_assoc()){
            $nombre = $data['name'];
            $inMemory['zones'][$nombre] = $data;
        }
    }

    $interface_zones = $configuration->xpath("//interface_zone");  //TODO: expression
    foreach ($interface_zones as $interface_zone){
        if(isset($interface_zone['name'])) {
            $zone_name = $interface_zone['name']->__toString();
            $inMemory['zones'][$zone_name] = $zone_name;
        }
    }

    $match_expressions = $configuration->xpath("//match_expression");  //TODO: expression
    foreach ($match_expressions as $match_expression){
        $name = $match_expression['name'];
        foreach ($match_expression->match_element_entry as $element_entry){
            $reference = $element_entry['ref'];
            if(isset($inMemory['zones']["$reference"])){
                $match_expressionsInMemory["$name"]['zones'][] = $reference->__toString();
            }
            else {
                if (isset($inMemory['address']["$reference"])) {
                    $id = $inMemory['address']["$reference"]['id'];
                    $ip = $inMemory['address']["$reference"]['ipaddress'];
                    $cidr= $inMemory['address']["$reference"]['cidr'];
                    $member = new MemberObject($id, "address", $ip, $cidr);
                }
                elseif (isset($inMemory['address_groups_id']["$reference"])) {
                    $id = $inMemory['address_groups_id']["$reference"]['id'];
                    $member = new MemberObject($id, "address_groups_id");
                }
                else{
                    $member = null;
                }
                $match_expressionsInMemory["$name"]['objects'][] = $member;
            }
        }
    }

}

function getLastId($type){
    global $projectdb;
    $query = "SELECT max(id) as lastID FROM $type";
    $result = $projectdb->query($query);
    if($result->num_rows===1){
        $data = $result->fetch_assoc();
        return (int) $data['lastID']+1;
    }

    return 1;
}


function is_SharedDomain(String $name):bool{
    if (0 === strpos($name, "Shared Domain-")){
        return true;
    }
    return false;
}

/***
 * Verifies that Shared Domain objects are placed under the Shared Domain DG
 * @param int $level
 * @param string $name
 * @return bool
 */
function object_belongs_here(int $level, string $name):bool{
    if( (($level === 0) && (is_SharedDomain($name))) ||
        (($level !== 0) && (!is_SharedDomain($name)))
    ) {
        return true;
    }

    return false;
}

/*
 * This method is parsing the following objects:
 * 		address_range
 * 		host (it may include groups)
 * 		network
 */
function get_Address_Stonesoft(SimpleXMLElement $configuration, STRING $vsys, STRING $source, int $level=0) {
//function get_Address_Stonesoft(SimpleXMLElement $configuration, STRING $vsys, STRING $source, $template) {
    global $projectdb;

    $ip_networks = array();
    $ip_address_ranges = array();
    $addresses = array();
    $address_groups = array();
    $addresses_groups_id = array();
    $tags = array();
    $addTag = array();
    $expectedTags = array('mgt_server', 'dns_server', 'dhcp_server', 'router', 'fw');

    $tags['mgt_server'] = get_tag_id($projectdb, "mgt_server", $source, $vsys);
    $tags['dns_server'] = get_tag_id($projectdb, "dns_server", $source, $vsys);
    $tags['dhcp_server'] = get_tag_id($projectdb, "dhcp_server", $source, $vsys);
    $tags['router'] = get_tag_id($projectdb, "router", $source, $vsys);
    $tags['fw'] = get_tag_id($projectdb, "fw", $source, $vsys);

    $tagRelations = array();

    $query = "SELECT max(id) as lastID FROM tag";
    $result = $projectdb->query($query);
    if($result->num_rows===1){
        $data = $result->fetch_assoc();
        $lastTagID = $data['lastID']+1;
    }
    else{
        $lastTagID = 1;
    }

    $query = "SELECT max(id) as lastID FROM address";
    $result = $projectdb->query($query);
    if($result->num_rows===1){
        $data = $result->fetch_assoc();
        $lastAddressID = $data['lastID']+1;
    }
    else{
        $lastAddressID = 1;
    }

    $query = "SELECT max(id) as lastID FROM address_groups_id";
    $result = $projectdb->query($query);
    if($result->num_rows===1){
        $data = $result->fetch_assoc();
        $lastAddressGroupsID = $data['lastID']+1;
    }
    else{
        $lastAddressGroupsID = 1;
    }

    $query = "SELECT id, name FROM tag WHERE NAME in ('".implode("','", $expectedTags)."') AND vsys='$vsys' AND source='$source'";
    $result = $projectdb->query($query);
    while($data = $result->fetch_assoc()){
        $tagId = $data['id'];
        $tagName = $data['name'];
        $tags[$tagName] = $tagId;
    }

//    foreach ($expectedTags as $expectedTag){
//        if(!array_key_exists($expectedTag, $tags)){
//            $addTag[] = "('$expectedTag', '$expectedTag', 'color6','$expectedTag from Stonesoft','$source', '$vsys','','0','','','','','','1')";
//            $tags[$expectedTag] = $lastTagID;
//            $lastTagID++;
//        }
//    }

    $mgt_servers = $configuration->xpath("//mgt_server");
    $mgt_serverTag = $tags['mgt_server'];
    foreach($mgt_servers as $mgt_server){
        $name_ext = trim(normalizeNames($mgt_server['name']));
        if(!object_belongs_here($level, $name_ext)) {
            continue;
        }
        $name_int = truncate_names(normalizeNames($name_ext));
        $description = "";
        $ip_address = $mgt_server->multi_contact_mvia["address"];

        $addresses[] = "($lastAddressID,'$name_ext','$name_int', '$description', '$ip_address', '32', 1, 0, 'ip-netmask', 'ip-netmask', '$source', '$vsys')";
        $tagRelations[] = "('address', $lastAddressID, $mgt_serverTag)";
        $lastAddressID++;
    }

    /*
     * We look for defined ranges
     */
    $address_ranges = $configuration->xpath("//address_range");
    foreach ($address_ranges as $address_range){
        $name_ext = trim(normalizeNames($address_range["name"]));
        if(!object_belongs_here($level, $name_ext)) {
            continue;
        }
        $name_int = truncate_names(normalizeNames($name_ext));
        $value = $address_range["ip_range"];
        $description = normalizeNames($address_range["comment"]);
        $addresses[] = "($lastAddressID,'$name_ext','$name_int', '$description', '$value', '', 1, 0,'ip-range', 'ip-range', '$source', '$vsys')";
        $lastAddressID++;
    }


    /*
     * We look for networks
     */
    $networks = $configuration->xpath("//network");
    foreach ($networks as $network){
        $name_ext = trim(normalizeNames($network["name"]));
        if(!object_belongs_here($level, $name_ext)) {
            continue;
        }

        $name_int = truncate_names(normalizeNames($name_ext));
        if (isset($network["ipv4_network"])) {
            $value = $network["ipv4_network"];
            $is_ipv4 = 1;
            $is_ipv6 = 0;
        } else {
            if (isset($network["ipv6_network"])) {
                $value = $network["ipv6_network"];
                $is_ipv6 = 1;
                $is_ipv4 = 0;
            } else {
                $value = '';
                $is_ipv4 = 1;
                $is_ipv6 = 0;
            }
        }
        $description = normalizeNames($network["comment"]);
        $broadcast_included = $network["broadcast"];

        list($network_address, $cidr) = explode("/", $value);

        if ($broadcast_included == "true") {
            $addresses[] = "($lastAddressID,'$name_ext','$name_int', '$description', '$network_address', '$cidr', '$is_ipv4', '$is_ipv6', 'ip-netmask', 'ip-netmask', '$source', '$vsys')";
            $lastAddressID++;
        } else {
            //We should remove the broadcast in this range/group of IPs
            $addresses[] = "($lastAddressID,'$name_ext','$name_int', '$description', '$network_address', '$cidr', '$is_ipv4', '$is_ipv6', 'ip-netmask', 'ip-netmask', '$source', '$vsys')";
            $lastAddressID++;
        }
    }

    /*
     * Host could be single IP-ed or multiple IP-ed
     */
    $hosts = $configuration->xpath("//host");
    foreach ($hosts as $host){
        $name_ext = trim(normalizeNames($host["name"]));
        if(!object_belongs_here($level, $name_ext)) {
            continue;
        }
        $description = normalizeNames($host["comment"]);
        //Get the main IP
        $address_array = array($host->mvia_address["address"]);
        //If it has multiple IPs, these should be defined and grouped
        foreach ($host->secondary as $secondary_ip) {
            if ($secondary_ip["value"] !== "0.0.0.0") {
                $address_array[] = $secondary_ip["value"];
            }
        }

        //We have a group of IPs, so we should create the group and add the IPs later
        if (count($address_array) > 1) {
            $name_int = truncate_names(normalizeNames($name_ext));
//            $projectdb->query("INSERT INTO address_groups_id (name_ext,name,description, source,vsys) VALUES ('$name_ext','$name_int','$description','$source','$vsys');");
            $addresses_groups_id[] = "($lastAddressGroupsID,'$name_ext','$name_int','$description','$source','$vsys')";
            $lid = $lastAddressGroupsID;
            $lastAddressGroupsID++;

            $member_i = 1;
            foreach ($address_array as $ip_address) {
                $pre_name = truncate_names($name_ext, 60);
                $name_int = truncate_names($pre_name . "_" . $member_i);
                $member_i++;

                $ip_version = ip_version($ip_address);
                if ($ip_version === "v4") {
                    $ipv4 = 1;
                    $ipv6 = 0;
                    $netmask = "32";
                }
                elseif ($ip_version === "v6") {
                    $ipv6 = 1;
                    $ipv4 = 0;
                    $netmask = "128";
                }
                else {
                    $ipv4 = 1;
                    $ipv6 = 0;
                    $netmask = "32";
                }

                $addresses[] = "($lastAddressID, '$name_int','$name_int', '','$ip_address', '$netmask', '$ipv4', '$ipv6', 'ip-netmask', 'ip-netmask', '$source', '$vsys')";
                $address_groups[] = "('$lid','$name_int','$name_int','$ip_address','$source', '$vsys', $lastAddressID, 'address')";
                $lastAddressID++;
            }
        }
        else {  //It is one single host.
            $array_values = array_values($address_array);
            $ip_address = $array_values[0];

            $ip_version = ip_version($ip_address);
            if ($ip_version === "v4") {
                $ipv4 = 1;
                $ipv6 = 0;
                $netmask = "32";
            } elseif ($ip_version === "v6") {
                $ipv6 = 1;
                $ipv4 = 0;
                $netmask = "128";
            } else {
                $ipv4 = 1;
                $ipv6 = 0;
                $netmask = "32";
            }

            $name_int = truncate_names(normalizeNames($name_ext));
            $addresses[] = "($lastAddressID, '$name_ext','$name_int', '$description', '$ip_address', '$netmask', '$ipv4', '$ipv6', 'ip-netmask', 'ip-netmask', '$source', '$vsys')";
            $lastAddressID++;
        }
    }

    
    /*
     * IP_lists could be single IP-ed or multiple IP-ed
     */
    $ip_lists = $configuration->xpath("//ip_list");
    foreach ($ip_lists as $ip_list){
        $name_ext = trim(normalizeNames($ip_list["name"]));
        if(!object_belongs_here($level, $name_ext)) {
            continue;
        }
        $description = normalizeNames($ip_list["comment"]);
        //If it has multiple IPs, these should be defined and grouped
        $address_array = [];
        foreach ($ip_list->ip as $ip_in_list) {
            if ($ip_in_list["value"] !== "0.0.0.0") {
                $address_array[] = $ip_in_list["value"];
            }
        }

        //We have a group of IPs, so we should create the group and add the IPs later
        if (count($address_array) > 1) {
            $name_int = truncate_names(normalizeNames($name_ext));
//            $projectdb->query("INSERT INTO address_groups_id (name_ext,name,description, source,vsys) VALUES ('$name_ext','$name_int','$description','$source','$vsys');");
            $addresses_groups_id[] = "($lastAddressGroupsID,'$name_ext','$name_int','$description','$source','$vsys')";
            $lid = $lastAddressGroupsID;
            $lastAddressGroupsID++;

            $member_i = 1;
            foreach ($address_array as $ip_address) {
                $pre_name = truncate_names($name_ext, 60);
                $name_int = truncate_names($pre_name . "_" . $member_i);
                $member_i++;

                $ip_address_parts = explode("/",$ip_address);
                if(isset($ip_address_parts[1])){
                    $ip_address = $ip_address_parts[0];
                    $ip_version = ip_version($ip_address);
                    if ($ip_version === "v4") {
                        $ipv4 = 1;
                        $ipv6 = 0;
                        $netmask = $ip_address_parts[1];
                    }elseif ($ip_version === "v6") {
                        $ipv4 = 0;
                        $ipv6 = 1;
                        $netmask = $ip_address_parts[1];
                    }else {
                        $ipv4 = 1;
                        $ipv6 = 0;
                        $netmask = $ip_address_parts[1];
                    }
                }
                else {
                    $ip_version = ip_version($ip_address);
                    if ($ip_version === "v4") {
                        $ipv4 = 1;
                        $ipv6 = 0;
                        $netmask = "32";
                    } elseif ($ip_version === "v6") {
                        $ipv6 = 1;
                        $ipv4 = 0;
                        $netmask = "128";
                    } else {
                        $ipv4 = 1;
                        $ipv6 = 0;
                        $netmask = "32";
                    }
                }

                $addresses[] = "($lastAddressID, '$name_int','$name_int', '','$ip_address', '$netmask', '$ipv4', '$ipv6', 'ip-netmask', 'ip-netmask', '$source', '$vsys')";
                $address_groups[] = "('$lid','$name_int','$name_int','$ip_address','$source', '$vsys', $lastAddressID, 'address')";
                $lastAddressID++;
            }
        }
        else {  //It is one single host.
            $array_values = array_values($address_array);
            if(!isset($array_values[0])){
                $ip_address = "0.0.0.0";
                add_log2('error', 'Address Object', 'The Address [' . $name_ext . '] has not an static IP. Consider using an EDL instead.', $source, 'Check that the created object is correct (consider using an EDL)', 'objects', $lastAddressID, 'address');
            }else {
                $ip_address = $array_values[0];
            }
            $ip_version = ip_version($ip_address);
            if ($ip_version === "v4") {
                $ipv4 = 1;
                $ipv6 = 0;
                $netmask = "32";
            } elseif ($ip_version === "v6") {
                $ipv6 = 1;
                $ipv4 = 0;
                $netmask = "128";
            } else {
                $ipv4 = 1;
                $ipv6 = 0;
                $netmask = "32";
            }

            $name_int = truncate_names(normalizeNames($name_ext));
            $addresses[] = "($lastAddressID, '$name_ext','$name_int', '$description', '$ip_address', '$netmask', '$ipv4', '$ipv6', 'ip-netmask', 'ip-netmask', '$source', '$vsys')";
            $lastAddressID++;
        }
    }

    /*
     * DNS-Servers could be single IP-ed or multiple IP-ed
     */
    $dnsServers = $configuration->xpath("//dns_server");
    $dns_serverTag = $tags['dns_server'];
    foreach ($dnsServers as $dnsServer){
        $name_ext = trim(normalizeNames($dnsServer["name"]));
        if(!object_belongs_here($level, $name_ext)) {
            continue;
        }
        $description = normalizeNames($dnsServer["comment"]);
        //Get the main IP
        $address_array= array($dnsServer->mvia_address["address"]);
        //If it has multiple IPs, these should be defined and grouped
        foreach($dnsServer->secondary as $secondary_ip){
            if($secondary_ip["value"] !== "0.0.0.0") {
                $address_array[] = $secondary_ip["value"];
            }
        }

        //We have a group of IPs, so we should create the group and add the IPs later
        if(count($address_array)>1){
            $name_int = truncate_names(normalizeNames($name_ext));
//            $projectdb->query("INSERT INTO address_groups_id (name_ext,name,description, source,vsys) VALUES ('$name_ext','$name_int','$description','$source','$vsys');");
            $addresses_groups_id[] = "($lastAddressGroupsID,'$name_ext','$name_int','$description','$source','$vsys')";
            $lid = $lastAddressGroupsID;
            $lastAddressGroupsID++;
            $tagRelations[] = "('address_groups_id', $lid, $dns_serverTag)";

            foreach($address_array as $ip_address){
                $name_int = truncate_names(normalizeNames($ip_address));

                $ip_version=ip_version($ip_address);
                if ($ip_version==="v4"){
                    $ipv4=1;$ipv6=0;$netmask="32";
                }
                elseif($ip_version==="v6"){
                    $ipv6=1;$ipv4=0;$netmask="128";
                }
                else{
                    $ipv4=1;$ipv6=0;$netmask="32";
                }

                $addresses[] = "($lastAddressID, '$ip_address','$name_int', '','$ip_address', '$netmask', '$ipv4', '$ipv6', 'ip-netmask', 'ip-netmask', '$source', '$vsys')";
                $address_groups[] = "('$lid','$ip_address','$name_int','$ip_address','$source', '$vsys', $lastAddressID, 'address')";
                $tagRelations[] = "('address', $lastAddressID, $dns_serverTag)";
                $lastAddressID++;
            }
        }
        else{  //It is one single dns_server.
            $array_values = array_values($address_array);
            $ip_address = $array_values[0];

            $ip_version=ip_version($ip_address);
            if ($ip_version==="v4"){
                $ipv4=1;$ipv6=0;$netmask="32";
            }
            elseif($ip_version==="v6"){
                $ipv6=1;$ipv4=0;$netmask="128";
            }
            else{
                $ipv4=1;$ipv6=0;$netmask="32";
            }

            $name_int = truncate_names(normalizeNames($name_ext));
            $addresses[] = "($lastAddressID, '$name_ext','$name_int', '$description', '$ip_address', '$netmask', '$ipv4', '$ipv6', 'ip-netmask', 'ip-netmask', '$source', '$vsys')";
            $tagRelations[] = "('address', $lastAddressID, $dns_serverTag)";
            $lastAddressID++;
        }
    }

    /*
     * DHCP-Servers could be single IP-ed or multiple IP-ed
     */
    $dhcpServers = $configuration->xpath("//dhcp_server");
    $dhcp_serverTag = $tags['dhcp_server'];
    foreach ($dhcpServers as $dhcpServer){
        $name_ext = trim(normalizeNames($dhcpServer["name"]));
        if(!object_belongs_here($level, $name_ext)) {
            continue;
        }
        $description = normalizeNames($dhcpServer["comment"]);
        //Get the main IP
        $address_array= array($dhcpServer->mvia_address["address"]);
        //If it has multiple IPs, these should be defined and grouped
        foreach($dhcpServer->secondary as $secondary_ip){
            if($secondary_ip["value"] != "0.0.0.0") {
                $address_array[] = $secondary_ip["value"];
            }
        }

        //We have a group of IPs, so we should create the group and add the IPs later
        if(count($address_array)>1){
            $name_int = truncate_names(normalizeNames($name_ext));
//            $projectdb->query("INSERT INTO address_groups_id (name_ext,name,description, source,vsys) VALUES ('$name_ext','$name_int','$description','$source','$vsys');");
//            $lid = $projectdb->insert_id;
            $addresses_groups_id[] = "($lastAddressGroupsID,'$name_ext','$name_int','$description','$source','$vsys')";
            $lid = $lastAddressGroupsID;
            $lastAddressGroupsID++;
            $tagRelations[] = "('address_groups_id',$lid,$dhcp_serverTag)";

            foreach($address_array as $ip_address){
                $name_int = truncate_names(normalizeNames($ip_address));

                $ip_version=ip_version($ip_address);
                if ($ip_version==="v4"){
                    $ipv4=1;$ipv6=0;$netmask="32";
                }
                elseif($ip_version==="v6"){
                    $ipv6=1;$ipv4=0;$netmask="128";
                }
                else{
                    $ipv4=1;$ipv6=0;$netmask="32";
                }
                $addresses[] = "($lastAddressID, '$ip_address','$name_int', '','$ip_address', '$netmask', '$ipv4', '$ipv6', 'ip-netmask', 'ip-netmask', '$source', '$vsys')";
                $address_groups[] = "('$lid','$ip_address','$name_int','$ip_address','$source', '$vsys',$lastAddressID, 'address')";
                $tagRelations[] = "('address',$lastAddressID,$dhcp_serverTag)";
                $lastAddressID++;
            }
        }
        else{  //It is one single dhcp_server.
            $array_values = array_values($address_array);
            $ip_address = $array_values[0];

            $ip_version=ip_version($ip_address);
            if ($ip_version==="v4"){
                $ipv4=1;$ipv6=0;$netmask="32";
            }
            elseif($ip_version==="v6"){
                $ipv6=1;$ipv4=0;$netmask="128";
            }
            else{
                $ipv4=1;$ipv6=0;$netmask="32";
            }

            $name_int = truncate_names(normalizeNames($name_ext));
            $addresses[] = "($lastAddressID, '$name_ext','$name_int', '$description', '$ip_address', '$netmask', '$ipv4', '$ipv6', 'ip-netmask', 'ip-netmask', '$source', '$vsys')";
            $tagRelations[] = "('address', $lastAddressID, $dhcp_serverTag)";
            $lastAddressID++;
        }
    }

    /*
     * Loading domain_names
     */
    $domain_names = $configuration->xpath("//domain_name");
    foreach ($domain_names as $domain_name){
        $name_ext = trim($domain_name["name"]);
        if(!object_belongs_here($level, $name_ext)) {
            continue;
        }
        $name_int = truncate_names(normalizeNames($name_ext));
        $description = normalizeNames($domain_name["comment"]);
        //Get the main IP
        //$ip_address = gethostbyname($name);
        $ip_address = $name_ext;
        $addresses[] = "($lastAddressID, '$name_ext','$name_int', '$description', '$ip_address', '', 1, 0, 'fqdn', '', '$source', '$vsys')";
        $lastAddressID++;
    }

    /*
     * Loading routers
     */
    $routers = $configuration->xpath("//router");
    $routerTag = $tags['router'];
    foreach ($routers as $router){
        $name_ext = trim(normalizeNames($router["name"]));
        if(!object_belongs_here($level, $name_ext)) {
            continue;
        }
        $name_int = truncate_names(normalizeNames($name_ext));
        $description = normalizeNames($router["comment"]);
        //Get the main IP
        $ip_address = $router->mvia_address["address"];

        $ip_version=ip_version($ip_address);
        if ($ip_version==="v4"){
            $ipv4=1;$ipv6=0;$netmask="32";
        }
        elseif($ip_version==="v6"){
            $ipv6=1;$ipv4=0;$netmask="128";
        }
        else{
            $ipv4=1;$ipv6=0;$netmask="32";
        }

        $addresses[] = "($lastAddressID, '$name_ext','$name_int', '$description', '$ip_address', '$netmask', '$ipv4', '$ipv6', 'ip-netmask', 'ip-netmask', '$source', '$vsys')";
        $tagRelations[] = "('address',$lastAddressID,$routerTag)";
        $lastAddressID++;
    }

    /*
     * Loading FW_CLUSTERs
     */
    $fw_clusters = $configuration->xpath("//fw_cluster");
    $fwTag = $tags['fw'];
    foreach ($fw_clusters as $fw_cluster){
        $name_ext = trim(normalizeNames($fw_cluster["name"]));
        if(!object_belongs_here($level, $name_ext)) {
            continue;
        }
        $name_int = truncate_names(normalizeNames($name_ext));
        $description = "";

        //Creating a group that represents the FW_cluster
//        $projectdb->query("INSERT INTO address_groups_id (name_ext,name,description, source,vsys) VALUES ('$name_ext','$name_int','$description','$source','$vsys');");
//        $lid = $projectdb->insert_id;
        $addresses_groups_id[] = "($lastAddressGroupsID,'$name_ext','$name_int','$description','$source','$vsys')";
        $lid = $lastAddressGroupsID;
        $lastAddressGroupsID++;
        $tagRelations[] = "('address_groups_id',$lid,$fwTag)";

        $address_array = array();


        //Adding the IPs of the cluster virtual interfaces
        foreach ($fw_cluster->cluster_virtual_interface as $cluster_virtual_interface){
            $fw_interface = new FwInterface($cluster_virtual_interface["name"],$cluster_virtual_interface->mvia_address["address"]);
            $address_array[] = $fw_interface;
        }

        //Adding the IPs of the firewall node interfaces
        foreach ($fw_cluster->firewall_node as $firewall_node){
            foreach ($firewall_node->node_interface as $node_interface){
                $fw_interface = new FwInterface($node_interface["name"],$node_interface->mvia_address["address"]);
                $address_array[] = $fw_interface;
            }
        }

        //Insert the different interfaces of the fw_cluster
        foreach($address_array as $interface){
            $name_ext = trim($interface->name);
            $name_int = truncate_names(normalizeNames($name_ext));
            $ip_address = $interface->address;

            $ip_version=ip_version($ip_address);
            if ($ip_version==="v4"){
                $ipv4=1;$ipv6=0;$netmask="32";
            }
            elseif($ip_version==="v6"){
                $ipv6=1;$ipv4=0;$netmask="128";
            }
            else{
                $ipv4=1;$ipv6=0;$netmask="32";
            }

            // (name_ext,name,description, ipaddress,cidr,v4,v6,type,vtype,source,vsys)
            $addresses[] = "($lastAddressID, '$name_ext','$name_int', '$description','$ip_address', '$netmask', '$ipv4', '$ipv6', 'ip-netmask', 'ip-netmask', '$source', '$vsys')";
            $tagRelations[] = "('address',$lastAddressID,$fwTag)";

            //(lid, name_ext,name,member,source,vsys)
            $address_groups[] = "('$lid','$name_ext','$name_int','$name_ext','$source', '$vsys', $lastAddressID, 'address')";
            $lastAddressID++;
        }
    }

    /*
     * Loading FW_SINGLE
     */
    $fw_singles = $configuration->xpath("//fw_single");
    $fwTag = $tags['fw'];
    foreach ($fw_singles as $fw_single){
        $name_ext = trim(normalizeNames($fw_single["name"]));
        if(!object_belongs_here($level, $name_ext)) {
            continue;
        }
        $name_int = truncate_names(normalizeNames($name_ext));
        $description = "";

//        $projectdb->query("INSERT INTO address_groups_id (name_ext,name,description, source,vsys) VALUES ('$name_ext','$name_int','$description','$source','$vsys');");
//        $lid = $projectdb->insert_id;
        $addresses_groups_id[] = "($lastAddressGroupsID,'$name_ext','$name_int','$description','$source','$vsys')";
        $lid = $lastAddressGroupsID;
        $lastAddressGroupsID++;
        $tagRelations[] = "('address_groups_id',$lid,$fwTag)";

        $address_array = array();

        foreach ($fw_single->fw_single_interface as $fw_single_interface){
            $fw_interface = new FwInterface($fw_single_interface["name"], $fw_single_interface->mvia_address["address"]);
            $address_array[] = $fw_interface;
        }

        //Insert the different interfaces of the fw_single
        foreach($address_array as $interface){
            $name_ext = trim(normalizeNames($interface->name));
            $name_int = truncate_names(normalizeNames($name_ext));
            $ip_address = $interface->address;
            $ip_version=ip_version($ip_address);
            if ($ip_version==="v4"){
                $ipv4=1;$ipv6=0;$netmask="32";
            }
            elseif($ip_version==="v6"){
                $ipv6=1;$ipv4=0;$netmask="128";
            }
            else{
                $ipv4=1;$ipv6=0;$netmask="32";
            }
            // (name_ext,name,description, ipaddress,cidr,v4,v6,type,vtype,source,vsys)
            $addresses[] = "($lastAddressID, '$name_ext','$name_int', '$description','$ip_address', '$netmask', '$ipv4', '$ipv6', 'ip-netmask', 'ip-netmask', '$source', '$vsys')";
            $tagRelations[] = "('address',$lastAddressID,$fwTag)";

            //(lid, name_ext,name,member,source,vsys)
            $address_groups[] = "('$lid','$name_ext','$name_int','$name_ext','$source', '$vsys',$lastAddressID, 'address')";
            $lastAddressID++;
        }

    }

    //Insert all the Tags
    if (count($addTag)>0){
        $uniq = array_unique($addTag);
        $out = implode(",", $uniq);
        $query = "INSERT INTO tag (name, name_ext, color, comments, source, vsys, devicegroup, modified, vtype, dummy, checkit, disable_override, merge_as_primary, used) VALUES " . $out .";";
        $projectdb->query($query);
    }

    //Done in the upper section, one by one
    if (count($addresses_groups_id) > 0) {
        $uniq = array_unique($addresses_groups_id);
        $out = implode(",", $uniq);
        $projectdb->query("INSERT INTO address_groups_id (id, name_ext,name,description, source,vsys) VALUES " . $out . ";");
    }

    //Insert all the Members
    if (count($addresses) > 0) {
        $uniq = array_unique($addresses);
        $out = implode(",", $uniq);
        $query = "INSERT INTO address (id, name_ext,name,description, ipaddress,cidr,v4,v6,type,vtype,source,vsys) VALUES " . $out . ";";
        $projectdb->query($query);
    }

    //Insert all the relations
    if (count($address_groups) > 0) {
        $uniq = array_unique($address_groups);
        $out = implode(",", $uniq);
        $query = "INSERT INTO address_groups (lid, name_ext,name,member,source,vsys, member_lid, table_name) ".
            "VALUES " . $out . ";";
        $projectdb->query("INSERT INTO address_groups (lid, name_ext,name,member,source,vsys, member_lid, table_name) ".
            "VALUES " . $out . ";");
    }

    if(count($tagRelations) > 0){
        $uniq = array_unique($tagRelations);
        $out = implode(",", $uniq);
        $query = "INSERT INTO tag_relations (table_name, member_lid, tag_id) VALUES " . $out . ";";
        $projectdb->query($query);
        //echo "LINE 6035: $query\n";

    }
}

function add_stonesoft_services(STRING $source, STRING $vsys) {
    global $projectdb;
    $exists = $projectdb->query("SELECT id FROM services WHERE source='$source' AND vsys='$vsys' AND name_ext IN ('FTP','SSH','SMTP');");
    if ($exists->num_rows == 0) {
        // Add predefined services and services groups
        ServicesMapping::addPredefinedSrvAndSrvGroups($projectdb, "stonesoft", $source, $vsys);

//        #Get Last lid from Services
//        $getMaxSrv=$projectdb->query("SELECT max(id) as max FROM services;");
//        $getMaxSrvData=$getMaxSrv->fetch_assoc();
//        $srvLid= (int)$getMaxSrvData['max'] + 1;
//
//        #Get Last lid from ServicesGroups
//        $getlastlid = $projectdb->query("SELECT max(id) as max FROM services_groups_id;");
//        $getLID1 = $getlastlid->fetch_assoc();
//        $i = (int)$getLID1['max'] + 1;
//
//        $add_srv = array();
//        $nameNorm=normalizeNames("DHCP (TCP)");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '67','predefined')";  //Used for the DHCP Relay. Do not delete
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- DHCP TCP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '67','predefined')";  //Used for the DHCP Relay. Do not delete
//        $srvLid++;
//
//        $nameNorm=normalizeNames("DHCP (UDP)");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '67','predefined')";  //Used for the DHCP Relay. Do not delete
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- DHCP UDP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '67','predefined')";  //Used for the DHCP Relay. Do not delete
//        $srvLid++;
//
//        $nameNorm=normalizeNames("FTP (Data)");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '20','predefined')";
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- FTP Data");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '20','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("FTP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '21','predefined')";
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- FTP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '21','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("TFTP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '69','predefined')";
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- TFTP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '69','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("SSH");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '22','predefined')";
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- SSH");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '22','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("Telnet");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '23','predefined')";
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- Telnet");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '23','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("SMTP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '25','predefined')";
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- SMTP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '25','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("TACACS (TCP)");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '49','predefined')";
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- TACACS");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '49','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("TACACS (UDP)");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '49','predefined')";
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- TACACS UDP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '49','predefined')";
//        $srvLid++;
//
//        $projectdb->query("INSERT INTO services_groups_id (source,vsys,id, name_ext,name,type) VALUES ('$source', '$vsys','$i','DNS','DNS','static');");
//        $nameNorm=normalizeNames("DNS (TCP)");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '53','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- DNS TCP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '53','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $nameNorm=normalizeNames("DNS (UDP)");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '53','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- DNS UDP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '53','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $i++;
//        $projectdb->query("INSERT INTO services_groups_id (source,vsys,id, name_ext,name,type) VALUES ('$source', '$vsys','$i','Shared Domain- DNS','Shared Domain- DNS','static');");
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services_groups_id',($i-1));");
//        $i++;
//
//        $nameNorm=normalizeNames("HTTP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '80','predefined')";
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- HTTP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '80','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("HTTP (with URL Logging)");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '80','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("POP3");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '110','predefined')";
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- POP3");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '110','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("POP3S");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '995','predefined')";
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- POP3S");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '995','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("X11");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '6000-6063','predefined')";
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- X11");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '6000-6063','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("NNTP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '119','predefined')";
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- NNTP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '119','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("NTP (UDP)");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '123','predefined')";
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- NTP (UDP)");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '123','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("NTP (TCP)");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '123','predefined')";
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- NTP (TCP)");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '123','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("MSRPC Endpoint Mapper (TCP)");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm','tcp', '135','predefined')";
//        $srvLid++;
//
//        $projectdb->query("INSERT INTO services_groups_id (source,vsys,id, name_ext,name,type) VALUES ('$source', '$vsys','$i','NetBIOS','NetBIOS','static');");
//        $nameNorm=normalizeNames("NetBIOS-NS (TCP)");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '137','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- NetBIOS-NS TCP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '137','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $nameNorm=normalizeNames("NetBIOS-NS (UDP)");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '137','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- NetBIOS-NS UDP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '137','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $nameNorm=normalizeNames("NetBIOS Datagram");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '138','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- NetBIOS Datagram");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '138','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $nameNorm=normalizeNames("NetBIOS-SSN");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '139','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- NetBIOS-SSN");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '139','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $i++;
//        $projectdb->query("INSERT INTO services_groups_id (source,vsys,id, name_ext,name,type) VALUES ('$source', '$vsys','$i','Shared Domain- NetBIOS','Shared Domain- NetBIOS','static');");
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services_groups_id',($i-1));");
//        $i++;
//
//        $nameNorm=normalizeNames("IMAP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '143','predefined')";
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- IMAP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '143','predefined')";
//        $srvLid++;
//
//        $projectdb->query("INSERT INTO services_groups_id (source,vsys,id, name_ext,name,type) VALUES ('$source', '$vsys','$i','SNMP','SNMP','static');");
//        $nameNorm=normalizeNames("SNMP (UDP)");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '161','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- SNMP UDP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '161','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $nameNorm=normalizeNames("SNMP (TCP)");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '161','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- SNMP TCP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '161','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $nameNorm=normalizeNames("SNMP Trap (UDP)");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '162','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- SNMP Trap TCP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '162','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $nameNorm=normalizeNames("SNMP Trap (TCP)");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '162','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- SNMP Trap UDP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '162','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $i++;
//
//        $projectdb->query("INSERT INTO services_groups_id (source,vsys,id, name_ext,name,type) VALUES ('$source', '$vsys','$i','LDAP','LDAP','static');");
//        $nameNorm=normalizeNames("LDAP (TCP)");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '389','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- LDAP TCP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '389','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $nameNorm=normalizeNames("LDAP (UDP)");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '389','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- LDAP UDP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '389','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- LDAPS TCP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '636','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- LDAPS UDP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '636','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $i++;
//
//        $nameNorm=normalizeNames("Shared Domain- Microsoft Global Catalog LDAP TCP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '3268','predefined')";
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- Microsoft Global Catalog LDAPS TCP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '3269','predefined')";
//        $srvLid++;
//
//        $projectdb->query("INSERT INTO services_groups_id (source,vsys,id, name_ext,name,type) VALUES ('$source', '$vsys','$i','LDAPS','LDAPS','static');");
//        $nameNorm=normalizeNames("LDAPS (TCP)");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '636','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $nameNorm=normalizeNames("LDAPS (UDP)");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '636','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $i++;
//
//        $projectdb->query("INSERT INTO services_groups_id (source,vsys,id, name_ext,name,type) VALUES ('$source', '$vsys','$i','Shared Domain- LDAPS','Shared Domain- LDAPS','static');");
//        $nameNorm=normalizeNames("Shared Domain- LDAPS TCP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '636','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- LDAPS UDP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '636','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $i++;
//
//        $nameNorm=normalizeNames("Shared Domain- Kpasswd");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '464','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("HTTPS");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '443','predefined')";
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- HTTPS");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '443','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("Microsoft-DS");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '445','predefined')";
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- Microsoft-DS");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '445','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("ISAKMP (UDP)");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '500','predefined')";
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- ISAKMP UDP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '500','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("Exec");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '512','predefined')";
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- Exec");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '512','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("Rlogin");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '513','predefined')";
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- Rlogin");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '513','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("Shell (cmd)");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '514','predefined')";
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- Shell cmd");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '514','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("Syslog (UDP)");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '514','predefined')";
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- Syslog UDP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '514','predefined')";
//        $srvLid++;
//        $nameNorm=normalizeNames("Syslog (TCP)");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '514','predefined')";
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- Syslog TCP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '514','predefined')";
//        $srvLid++;
//
//        $projectdb->query("INSERT INTO services_groups_id (source,vsys,id, name_ext,name,type) VALUES ('$source', '$vsys','$i','Kerberos','Kerberos','static');");
//        $nameNorm=normalizeNames("Kerberos-88 (TCP)");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '88','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $nameNorm=normalizeNames("Kerberos-88 (UDP)");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '88','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $nameNorm=normalizeNames("Kerberos-464 (TCP)");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '464','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $nameNorm=normalizeNames("Kerberos-464 (UDP)");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '464','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $nameNorm=normalizeNames("Kerberos-749 (TCP)");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '749','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $nameNorm=normalizeNames("Kerberos-749 (UDP)");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '749','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $nameNorm=normalizeNames("Kerberos-750 (TCP)");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '750','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $nameNorm=normalizeNames("Kerberos-750 (UDP)");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '750','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $i++;
//
//        $projectdb->query("INSERT INTO services_groups_id (source,vsys,id, name_ext,name,type) VALUES ('$source', '$vsys','$i','Shared Domain- Kerberos','Shared Domain- Kerberos','static');");
//        $nameNorm=normalizeNames("Shared Domain- Kerberos-88 TCP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '88','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- Kerberos-88 UDP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '88','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- Kerberos-464 TCP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '464','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- Kerberos-464 UDP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '464','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- Kerberos-749 TCP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '749','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- Kerberos-749 UDP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '749','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- Kerberos-750 TCP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '750','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- Kerberos-750 UDP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '750','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $i++;
//
//        $nameNorm=normalizeNames("IMAPS");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '993','predefined')";
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- IMAPS");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '993','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("MSSQL (TCP)");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '1433','predefined')";
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- MSSQL TCP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '1433','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("MSSQL (UDP)");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '1433','predefined')";
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- MSSQL UDP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '1433','predefined')";
//        $srvLid++;
//
//        $projectdb->query("INSERT INTO services_groups_id (source,vsys,id, name_ext,name,type) VALUES ('$source', '$vsys','$i','T.120','T.120','static');");
//        $nameNorm=normalizeNames("T.120 (TCP)");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '1503','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $nameNorm=normalizeNames("T.120 (UDP)");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '1503','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $i++;
//
//        $projectdb->query("INSERT INTO services_groups_id (source,vsys,id, name_ext,name,type) VALUES ('$source', '$vsys','$i','Shared Domain- T.120','Shared Domain- T.120','static');");
//        $nameNorm=normalizeNames("Shared Domain- T.120 TCP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '1503','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- T.120 UDP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '1503','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $i++;
//
//        $nameNorm=normalizeNames("Oracle TNS");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '1521','predefined')";
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- Oracle TNS");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '1521','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("H.323 (Call Signaling)");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '1720','predefined')";
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- H.323 Call Signaling");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '1720','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("MySQL");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '3306','predefined')";
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- MySQL");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '3306','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("RDP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '3389','predefined')";
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- RDP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '3389','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("NAT-T (Destination)");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '4500','predefined')";
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- NAT-T Destination");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '4500','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("Any TCP Service");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '1-65535','predefined')";
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- Any TCP Service");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '1-65535','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("Shared Domain- Any UDP Service");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '1-65535','predefined')";
//        $srvLid++;
//        $nameNorm=normalizeNames("Ping");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'icmp', '0','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("Shared Domain- Ping");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'icmp', '0','predefined')";
//        $srvLid++;
//        $nameNorm=normalizeNames("Echo Request (No Code)");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'icmp', '0','predefined')";
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- Echo Request No Code");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'icmp', '0','predefined')";
//        $srvLid++;
//        $nameNorm=normalizeNames("Echo Request (Any Code)");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'icmp', '0','predefined')";
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- Echo Request Any Code");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'icmp', '0','predefined')";
//        $srvLid++;
//        $nameNorm=normalizeNames("ICMP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'icmp', '0','predefined')";
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- ICMP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'icmp', '0','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("ICMP-0");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'icmp', '0','predefined')";
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- ICMP-0");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'icmp', '0','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("ICMP-8");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'icmp', '0','predefined')";
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- ICMP-8");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'icmp', '0','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("ICMP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'icmp', '0','predefined')";
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- ICMP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'icmp', '0','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("HTTP proxy");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '8080','predefined')";
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- HTTP proxy");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '8080','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("MS-Streaming (ms-streaming)");
//        $projectdb->query("INSERT INTO services_groups_id (source,vsys,id, name_ext,name,type) VALUES ('$source', '$vsys','$i','$nameNorm','$nameNorm','static');");
//        $nameNorm=normalizeNames("MS-Streaming (ms-streaming) (TCP)");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm','$nameNorm', 'tcp', '1755','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $nameNorm=normalizeNames("MS-Streaming (ms-streaming) (UDP)");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm','$nameNorm', 'udp', '1755','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $i++;
//
//        $nameNorm=normalizeNames("Shared Domain- MS-Streaming");
//        $projectdb->query("INSERT INTO services_groups_id (source,vsys,id, name_ext,name,type) VALUES ('$source', '$vsys','$i','$nameNorm','$nameNorm','static');");
//        $nameNorm=normalizeNames("Shared Domain- MS-Streaming TCP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm','$nameNorm', 'tcp', '1755','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- MS-Streaming UDP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm','$nameNorm', 'udp', '1755','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $i++;
//
//        $nameNorm=normalizeNames("SIP");
//        $projectdb->query("INSERT INTO services_groups_id (source,vsys,id, name_ext,name,type) VALUES ('$source', '$vsys','$i','$nameNorm','$nameNorm','static');");
//        $nameNorm=normalizeNames("SIP (TCP)");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '5060','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $nameNorm=normalizeNames("SIP (UDP)");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '5060','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $i++;
//
//        $nameNorm=normalizeNames("Shared Domain- SIP");
//        $projectdb->query("INSERT INTO services_groups_id (source,vsys,id, name_ext,name,type) VALUES ('$source', '$vsys','$i','$nameNorm','$nameNorm','static');");
//        $nameNorm=normalizeNames("Shared Domain- SIP TCP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '5060','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- SIP UDP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '5060','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $i++;
//
//        $nameNorm=normalizeNames("FTPS (Control)");
//        $projectdb->query("INSERT INTO services_groups_id (source,vsys,id, name_ext,name,type) VALUES ('$source', '$vsys','$i','$nameNorm','$nameNorm','static');");
//        $nameNorm=normalizeNames("FTPS (Control) (TCP)");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '990','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $nameNorm=normalizeNames("FTPS (Control) (UDP)");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '990','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $i++;
//
//        $nameNorm=normalizeNames("Shared Domain- FTPS Control");
//        $projectdb->query("INSERT INTO services_groups_id (source,vsys,id, name_ext,name,type) VALUES ('$source', '$vsys','$i','$nameNorm','$nameNorm','static');");
//        $nameNorm=normalizeNames("Shared Domain- FTPS Control TCP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '990','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- FTPS Control UDP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '990','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $i++;
//
//        $nameNorm=normalizeNames("MSRPC");
//        $projectdb->query("INSERT INTO services_groups_id (source,vsys,id, name_ext,name,type) VALUES ('$source', '$vsys','$i','$nameNorm ','$nameNorm','static');");
//        $nameNorm=normalizeNames("MSRPC (TCP)");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '1025-65535','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $nameNorm=normalizeNames("MSRPC (UDP)");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '1025-65535','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $i++;
//
//        $nameNorm=normalizeNames("Shared Domain- MSRPC");
//        $projectdb->query("INSERT INTO services_groups_id (source,vsys,id, name_ext,name,type) VALUES ('$source', '$vsys','$i','$nameNorm ','$nameNorm','static');");
//        $nameNorm=normalizeNames("Shared Domain- MSRPC TCP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '1025-65535','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- MSRPC UDP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '1025-65535','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $i++;
//
//        $nameNorm=normalizeNames("SIP Control");
//        $projectdb->query("INSERT INTO services_groups_id (source,vsys,id, name_ext,name,type) VALUES ('$source', '$vsys','$i','$nameNorm','$nameNorm','static');");
//        $nameNorm=normalizeNames("SIP Control (TCP)");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '5060','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $nameNorm=normalizeNames("SIP Control (UDP)");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '5060','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $i++;
//
//        $nameNorm=normalizeNames("Shared Domain- SIP Control");
//        $projectdb->query("INSERT INTO services_groups_id (source,vsys,id, name_ext,name,type) VALUES ('$source', '$vsys','$i','$nameNorm','$nameNorm','static');");
//        $nameNorm=normalizeNames("Shared Domain- SIP Control TCP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '5060','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- SIP Control UDP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '5060','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $i++;
//
//        $nameNorm=normalizeNames("Remote Desktop");
//        $projectdb->query("INSERT INTO services_groups_id (source,vsys,id, name_ext,name,type) VALUES ('$source', '$vsys','$i','$nameNorm','$nameNorm','static');");
//        $nameNorm=normalizeNames("Remote Desktop (TCP)");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '3389','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $nameNorm=normalizeNames("Remote Desktop (UDP)");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '3389','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $i++;
//
//        $nameNorm=normalizeNames("Shared Domain- Remote Desktop");
//        $projectdb->query("INSERT INTO services_groups_id (source,vsys,id, name_ext,name,type) VALUES ('$source', '$vsys','$i','$nameNorm','$nameNorm','static');");
//        $nameNorm=normalizeNames("Shared Domain- Remote Desktop TCP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '3389','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- Remote Desktop UDP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '3389','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $i++;
//
//
//        //Own SG services
//
//        $nameNorm=normalizeNames("SG Analyzer to Engine");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm',   '$nameNorm', 'tcp', '15000','predefined')";
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- SG Authentication");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm',   '$nameNorm', 'tcp', '8990','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("SG Blacklisting");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '15000','predefined')";
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- SG Blacklisting");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '15000','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("BGP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '179','predefined')";
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- BGP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '179','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("BrightCloud Service");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '2316','predefined')";
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- BrightCloud Service");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '2316','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("BrightStor Backup TCP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '6071','predefined')";
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- BrightStor Backup TCP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '6071','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("BrightStor Engines TCP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '6502','predefined')";
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- BrightStor Engines TCP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '6502','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("CCSO TCP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '105','predefined')";
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- CCSO TCP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '105','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("SG Client to Log");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '8914-8918','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("SG Client to Management");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '8902-8913','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("SG Commands");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '4987','predefined')";
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- SG Commands");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '4987','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("Computer Associates ARCserve");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '1900','predefined')";
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- Computer Associates ARCserve");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '1900','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("CVS");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '2401','predefined')";
//        $srvLid++;
//        $nameNorm=normalizeNames("Shared Domain- CVS");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '2401','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("SG Dynamic Control");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp','8906','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("Shared Domain- SG Dynamic Control");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp','8906','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("SG Dynamic Control Firewall to Management");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm','$nameNorm','tcp','8906','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("SG Dynamic Firewall to Management");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm','$nameNorm','tcp','8906','predefined')";
//        $srvLid++;
//
//        $projectdb->query("INSERT INTO services_groups_id (source,vsys,id, name_ext,name,type) VALUES ('$source', '$vsys','$i','SG Engine to Log','SG Engine to Log','static');");
//        $nameNorm=normalizeNames("SG Engine to Engine");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '8902-8913','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $nameNorm=normalizeNames("SG Engine to Log1");
//        $add_srv[] = "('$srvLid','$source','$vsys',    '$nameNorm',       'SG Engine to Log1',            'tcp',      '8916-8917','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $i++;
//
//        $nameNorm=normalizeNames("SG Engine to Management");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '8902-8913','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("Shared Domain- SG Engine to User Agent");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '16661','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("SG Firewall to Server Pool");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm','$nameNorm', 'udp', '7777','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("SG Initial Contact");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '3021','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("Shared Domain- SG Initial Contact");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '3021','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("SG Log");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '3020','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("Shared Domain- SG Log");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '3020','predefined')";
//        $srvLid++;
//
//        $projectdb->query("INSERT INTO services_groups_id (source,vsys,id, name_ext,name,type) VALUES ('$source', '$vsys','$i','SG Log to Log','SG Log to Log','static');");
//        $nameNorm=normalizeNames("SG Log to Log1");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '514','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $nameNorm=normalizeNames("SG Log to Log2");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '5514','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $i++;
//
//        $nameNorm=normalizeNames("SG Log to Log Server");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '3020','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("SG Log to Management");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm',    '$nameNorm', 'tcp', '8902-8913','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("SG Management to Firewall");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm','$nameNorm', 'tcp', '636','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("SG Management to Log");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '8914-8918','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("SG Management to Management");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm','$nameNorm','tcp', '8902-8913','predefined')";
//        $srvLid++;
//
//        $projectdb->query("INSERT INTO services_groups_id (source,vsys,id, name_ext,name,type) VALUES ('$source', '$vsys','$i','SG Management to Sensor','SG Management to Sensor','static');");
//        $nameNorm=normalizeNames("SG Management to Sensor1','SG Management to Sensor1");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '4950','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $nameNorm=normalizeNames("SG Management to Sensor2','SG Management to Sensor2");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '18888','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $nameNorm=normalizeNames("SG Management to Sensor3','SG Management to Sensor3");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '15000','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $i++;
//
//        $nameNorm=normalizeNames("SG Management to Stonesoft");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm','$nameNorm', 'tcp', '443','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("SG Monitoring Client to Monitoring Server");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm','$nameNorm', 'udp', '161','predefined')";
//        $srvLid++;
//
//        TODO: Add the source port 4500 into NAT-T
//        $nameNorm=normalizeNames("Shared Domain- NAT-T Source");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm','$nameNorm', 'udp', '1-65535','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("Shared Domain- RADIUS Authentication");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '1812','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("Shared Domain- RADIUS Old");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '1645','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("SG Reverse Monitoring");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '3023','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("SG Remote Upgrade");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '4950','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("Shared Domain- SG Remote Upgrade");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '4950','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("SG Sensor to Analyzer");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '18890','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("Shared Domain- SG Server Pool Monitoring");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'udp', '7777','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("SG SOHO Firewall to Log");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '3020','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("SG SOHO Firewall to Management");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm','$nameNorm','tcp','3021','predefined')";
//        $srvLid++;
//
//        TODO: Add the source port 500 into Source Port ISAKMP
//        $nameNorm=normalizeNames("Shared Domain- Source Port ISAKMP");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm','$nameNorm','udp','1-65535','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("SG Status Monitoring");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '3023','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("Shared Domain- SG Status Monitoring");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm', '$nameNorm', 'tcp', '3023','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("Shared Domain- SG UDP Encapsulation");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm','$nameNorm','udp', '2746','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("SG VPN Client to Firewall");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm','$nameNorm','udp', '500','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("SG Web Portal Server to Log");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm','$nameNorm','tcp', '3020','predefined')";
//        $srvLid++;
//
//        $nameNorm=normalizeNames("SG Web Portal Server to Management");
//        $add_srv[] = "('$srvLid','$source','$vsys', '$nameNorm','$nameNorm', 'tcp', '3021','predefined')";
//        $srvLid++;
//
//        $projectdb->query("INSERT INTO services_groups_id (source,vsys,id, name_ext,name,type) VALUES ('$source', '$vsys','$i','SG Management to Analyzer','SG Management to Analyzer','static');");
//        $nameNorm=normalizeNames("SG Management to Analyzer1");
//        $add_srv[] = "('$srvLid','$source','$vsys',    '$nameNorm','$nameNorm',   'tcp',      '4950','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $nameNorm=normalizeNames("SG Management to Analyzer2");
//        $add_srv[] = "('$srvLid','$source','$vsys',    '$nameNorm','$nameNorm',   'tcp',      '18889','predefined')";
//        $projectdb->query("INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES ('$source', '$vsys','$i','$nameNorm','services','$srvLid');");
//        $srvLid++;
//        $i++;
//
//
//        $out = implode(",", $add_srv);
//        $query = "INSERT INTO services (id,source,vsys, name_ext,name,protocol,dport,devicegroup) VALUES " . $out . ";";
//        $projectdb->query($query);
//        unset($add_srv);
//
//        $nameNorm=normalizeNames("Printer Spooler (TCP)");
//        $projectdb->query("INSERT INTO services (source,vsys, name_ext,name,protocol,dport) VALUES ('$source', '$vsys', '$nameNorm', '$nameNorm','tcp','1023-65535');");
//        $service_id = $projectdb->insert_id;
//        add_log2("warning", 'Reading Security Policy', 'Service[' . $service_id . ']. The service Printer Spooler TCP may be too permissive', $source, 'Manually check','services',$service_id,'services');
//        $nameNorm=normalizeNames("Printer Spooler (UDP)");
//        $projectdb->query("INSERT INTO services (source,vsys, name_ext,name,protocol,dport) VALUES ('$source', '$vsys', '$nameNorm', '$nameNorm','udp','1023-65535');");
//        $service_id = $projectdb->insert_id;
//        add_log2("warning", 'Reading Security Policy', 'Service[' . $service_id . ']. The service Printer Spooler UDP may be too permissive', $source, 'Manually check','services',$service_id,'services');



    }
}

//function add_stonesoft_services_1(string $source, string $vsys, int &$srvLid){
//    global $projectdb;
//
//    $service_list = get_predefined_services_array();
//
//    $add_srv = [];
//    foreach ($service_list as $item){
//        $name = normalizeNames($item['name']);
//        $shared_name = remove_parenthesis("Shared Domain- ".$name);
//        $sport = trim($item['sport'] ?? '');
//        $dport = trim($item['dport']);
//        $protocol= trim($item['protocol']);
//        $add_srv[] = "('".$srvLid++ ."',
//                        '$source',
//                        '$vsys',
//                        '$name',
//                        '$name',
//                        '$protocol',
//                        '$sport',
//                        '$dport',
//                        'default'
//                       )";
//
//        $add_srv[] = "('".$srvLid++ ."',
//                        '$source',
//                        '$vsys',
//                        '$shared_name',
//                        '$shared_name',
//                        '$protocol',
//                        '$sport',
//                        '$dport',
//                        'default'
//                       )";
//    }
//
//
//    $out = implode(",", $add_srv);
//    $query = "INSERT INTO services (id,source,vsys, name_ext,name,protocol,sport,dport,devicegroup) VALUES " . $out . ";";
//    $projectdb->query($query);
//    unset($add_srv);
//    ServicesMapping::addPredefinedServices($projectdb,"stonesoft", $source , $vsys , $srvLid);
//}

//function add_stonesoft_service_groups(string $source, string $vsys, int &$srvLid, int &$srvGroupRel, array &$objectsInMemory=[]){
//    global $projectdb;
//
//    $service_group_list = ServicesMapping::get_predefined_service_groups_array("stonesoft");
//
//    $add_group = [];
//    $add_group_relation = [];
//
//    foreach ($service_group_list as $item) {
//        $name = normalizeNames($item[0]);
//
//        $members = explode(",", $item[1]);
//        $add_group[] = "('" . $srvLid . "',
//                        '$source',
//                        '$vsys',
//                        '" . $name . "',
//                        '" . $name . "',
//                        'default'
//                       )";
//
//        foreach ($members as $member_name) {
//            $member_name = trim($member_name);
//            $member_id = 0;
//            $table_name = '';
//
//            if (!searchService_orCreate($member_name, $vsys, $source, $member_id, $table_name, $objectsInMemory)) {
//
//            }
//            $add_group_relation[] = "('$source', '$vsys','$srvLid','$name','$table_name','$member_id')";
//        }
//
//        $srvLid++;
//
//        $shared_name = ServicesMapping::remove_parenthesis("Shared Domain- " . $name);
//        $add_group[] = "('" . $srvLid . "',
//                        '$source',
//                        '$vsys',
//                        '" . $shared_name . "',
//                        '" . $shared_name . "',
//                        'default'
//                       )";
//
//        foreach ($members as $member_name) {
//            $member_name = trim($member_name);
//            $member_name = ServicesMapping::remove_parenthesis("Shared Domain- " . $member_name);
//            $member_id = 0;
//            $table_name = '';
//
//            if (!searchService_orCreate($member_name, $vsys, $source, $member_id, $table_name, $objectsInMemory)) {
//
//            }
//            $add_group_relation[] = "('$source', '$vsys','$srvLid','$name','$table_name','$member_id')";
//        }
//        $srvLid++;
//
//    }
//
//
//    $out = implode(",", $add_group);
//    $query = "INSERT INTO services_groups_id (id,source,vsys, name_ext,name,devicegroup) VALUES " . $out . ";";
//    $projectdb->query($query);
//    unset($add_srv);
//
//    $out = implode(",", $add_group_relation);
//    $query = "INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES " . $out . ";";
//    $projectdb->query($query);
//    unset($add_group_relation);
//}

function add_feedback_message(string $rule_id, string $message, array &$feedback_messages){

    if(!isset($feedback_messages['sub_rules']['tag']["$rule_id"])){
        $feedback_messages['sub_rules']['tag']["$rule_id"]['messages'] = [];
    }
    $feedback_messages['sub_rules']['tag']["$rule_id"]['messages'][]=$message;
}

function renewDBConnection(){
    global $projectdb;
    global $project;
    $projectdb = selectDatabase($project);
}

function check_used_DAG_members($sourcesAdded){
    global $projectdb;

    $sourcesAdded = array_unique($sourcesAdded);

    $dag_ids = [];
    $query_dag = "SELECT * FROM address_groups_id WHERE source in (".implode(",",$sourcesAdded).") AND type='dynamic' AND used=1;";
    $dag_data = $projectdb->query($query_dag);
    if($dag_data->num_rows>0){
        while ($entry = $dag_data->fetch_assoc()){
            $dag_ids[] = $entry['id'];
        }
    }

    $query_set_dag_members_used =
        "UPDATE address SET used=1 WHERE id in 
            (SELECT * FROM (
                            SELECT address.id 
                            FROM address, tag_relations, tag 
                            WHERE address.id =tag_relations.member_lid and tag_relations.table_name = 'address' AND
	                                tag_relations.tag_id = tag.id AND
                                    tag.name in (
		                                    SELECT distinct filter
                                            FROM address_groups_id 
                                            WHERE address_groups_id.used = 1 AND 
			                                        address_groups_id.type = 'dynamic' AND
			                                        address_groups_id.source in (".implode(",",$sourcesAdded).")
                                    )
                            ) as ad2
                );";

    //echo $query_set_dag_members_used;

    $projectdb->query($query_set_dag_members_used);

}

?>
