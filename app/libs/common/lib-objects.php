<?php

/* 
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 */
//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

define('NAMEPANLenght', 63);
define('NAMELenght', 255);

require_once 'definitions.php';

require_once INC_ROOT.'/libs/common/MemberObject.php';
require_once INC_ROOT.'/libs/shared.php';

use PaloaltoNetworks\Policy\Objects\MemberObject;

/**
 * Method to explode Groups into its Members. A group can be a Member
 * @param array $members
 * @param mysqli $projectdb
 * @param STRING $source
 * @param STRING $vsys
 * @param INT|NULL $level
 * @param array $processedGroups
 * @param array $listAddress
 * @param array $listGroups
 * @return array
 */

function load_default_objects_byname(&$objectsInMemory,$data,$new_vsys=null){
    $projectdb = $data['projectdb'];
    $source=$data['source'];

    if ($new_vsys==null){
        $andVSYS="";
        $mytablesNoSource=array(
            "default_url_categories",
            "default_regions",
            "default_applications"
        );

        foreach($mytablesNoSource as $key=>$table_name){
            $loadApps=$projectdb->query("SELECT id,name FROM $table_name;");
            if ($loadApps->num_rows>0){
                while($data=$loadApps->fetch_assoc()){
                    $lid=$data['id'];
                    $name=$data['name'];
                    $objectsInMemory[$table_name][$name]=$lid;
                }
            }
        }
    }
    else{
        $andVSYS=" AND vsys='$new_vsys' ";
    }

    $mytablesSource=array(
        "address",
        "address_groups_id",
        "services",
        "services_groups_id",
        "applications",
        "applications_groups_id",
        "applications_filters",
        "external_list",
        "tag",
        "regions",
        "schedules",
        "profiles_groups"
    );

    foreach($mytablesSource as $key=>$table_name){
        $loadApps=$projectdb->query("SELECT id,name,vsys FROM $table_name WHERE source='$source' $andVSYS;");
        if ($loadApps->num_rows>0){
            while($data=$loadApps->fetch_assoc()){
                $lid=$data['id'];
                $name=$data['name'];
                $vsys=$data['vsys'];
                $objectsInMemory[$table_name][$vsys][$name]=$lid;
            }
        }
    }

    # Log Settings Profiles
    $mytablesSource=array("log_settings");
    foreach($mytablesSource as $key=>$table_name){
        $loadApps=$projectdb->query("SELECT id,name,vsys FROM $table_name WHERE source='$source' AND type='profiles'  $andVSYS;");
        if ($loadApps->num_rows>0){
            while($data=$loadApps->fetch_assoc()){
                $lid=$data['id'];
                $name=$data['name'];
                $vsys=$data['vsys'];
                $objectsInMemory[$table_name][$vsys][$name]=$lid;
            }
        }
    }

    # Security Profiles
    $mytablesSource=array("profiles");
    foreach($mytablesSource as $key=>$table_name){
        $loadApps=$projectdb->query("SELECT id,name,vsys,type FROM $table_name WHERE source='$source' $andVSYS;");
        if ($loadApps->num_rows>0){
            while($data=$loadApps->fetch_assoc()){
                $lid=$data['id'];
                $name=$data['name'];
                $vsys=$data['vsys'];
                $type=$data['type'];
                $objectsInMemory[$table_name][$type][$vsys][$name]=$lid;
            }
        }
    }

}

function explodeGroups2Members(ARRAY $members, mysqli $projectdb, STRING $source, STRING $vsys, INT $level=NULL, ARRAY &$processedGroups = array(),  ARRAY $listAddress=array(), ARRAY $listGroups=array()){

    if(is_null($members)) {
        $members = array();
    }
    if(is_null($level)){
        $level=0;
    }
    $tmp_members=array();
    foreach($members as $member){
        //Not a group. Let's add it directly
        if(strcmp($member->location, 'address')===0){
            //Check if we already have this member
            if(!in_array($member->name, $listAddress, false)){
                $name = $member->name.'_'.$member->location;
                if(isset($processedGroups[$name])){
                    $tmp_members[] = $processedGroups[$name];
                    $listAddress[] = $member->name;
                }
                else {
                    if (!isset($member->value, $member->cidr)) {
                        $query = "SELECT id, ipaddress, cidr FROM address WHERE id=$member->name "; //."AND source='$source' AND vsys='$vsys';";
                        $getMember = $projectdb->query($query);
                        if ($getMember->num_rows == 1) {
                            $row = $getMember->fetch_assoc();
                            $member->cidr = $row['cidr'];
                            $member->value = $row['ipaddress'];
                        }
                    }
                    $processedGroups[$name] = $member;
                    $tmp_members[] = $member;
                    $listAddress[] = $member->name;
                }
            }
            else{
            }
        }

        elseif(strcmp($member->location, 'default_regions')===0){
            //Check if we already have this member
            if(!in_array($member->name, $listAddress, false)){
                $name = $member->name.'_'.$member->location;
                if(isset($processedGroups[$name])){
                    $tmp_members[] = $processedGroups[$name];
                    $listAddress[] = $member->name;
                }
                else {
                    if (!isset($member->value, $member->cidr)) {
                        $member->cidr = '32';
                        $member->value = '0.0.0.0';
                    }
                    $processedGroups[$name] = $member;
                    $tmp_members[] = $member;
                    $listAddress[] = $member->name;
                }
            }
            else{
            }
        }

        //This is a group. Let's expand it
        else{
            //Check if the group has already been checked for this current group explode
            if(!in_array($member->name, $listGroups, false)){
                $name = $member->name.'_'.$member->location;

                if (isset($processedGroups[$name])){
//                    $tmp_members = array_merge($tmp_members,$processedGroups[$name]); //WARNING, $processedGroups[$name] may be an ARRAY!  //TODO: This may not be necessary, those have already been included
                }
                else {
                    $query = "SELECT member_lid, table_name " .
                             "FROM   address_groups adg " .
                             "WHERE ".
                               // "adg.source='$source' AND adg.vsys='$vsys' AND BINARY" .
                             "       adg.lid='$member->name' ";
                    //echo "$query";
                    $getMember = $projectdb->query($query);
                    $member2 = array();
                    while ($row = $getMember->fetch_assoc()) {
                        $member_id = $row['member_lid'];
                        $member_location = $row['table_name'];
                        $member2[] = new MemberObject($member_id, $member_location);
                    }
                    $listGroups[] = $member->name;
                    $membersIn_member2 = explodeGroups2Members($member2, $projectdb, $source, $vsys, $level+1, $processedGroups,  $listAddress, $listGroups);
                    $tmp_members = array_merge($tmp_members, $membersIn_member2);
                    if(!isset($processedGroups[$name])){
                        $processedGroups[$name] = $membersIn_member2;
                    }
                }
            }
            else{
            }
         }
    }
    
    return $tmp_members;
}

function explodeGroups2ServicesInMemory(ARRAY $services, ARRAY $inMemoryObjects, $level=NULL){
    if(is_null($services)){
        $services = array();
    }
    if(is_null($level)){
        $level=0;
    }
    $tmp_services=array();

    foreach($services as $service){
        //Not a group. Let's add it directly
        if(strcmp($service->name, 'any')==0 && strcmp($service->location, '')==0){
            //This is the ANY service
            return array($service); //No need to look for more, this service covers all

        }
        elseif(strcmp($service->location, 'services')==0){
            if(!isset($service->value) || !isset($service->cidr)){
                $query ="SELECT id, dport, protocol FROM services WHERE id=$service->name ;";//AND source='$source' AND vsys='$vsys'
                $getService = $projectdb->query($query);
                if($getService->num_rows == 1){
                    $row=$getService->fetch_assoc();
                    $service->value=$row['dport'];
                    $service->cidr= $row['protocol'];
                }
            }

            $tmp_services[]=$service;
        }

        //This is a group. Let's expand it
        else{
            $query = "SELECT member_lid, table_name FROM services_groups sg WHERE sg.lid='$service->name' "; //sg.source='$source' AND sg.vsys='$vsys' AND
            $getService = $projectdb->query($query);
            $member2 = array();
            while($row = $getService->fetch_assoc()) {
                $service_id= $row['member_lid'];
                $service_location = $row['table_name'];
                $member2[] = new MemberObject($service_id, $service_location);
            }
            $tmp_services = array_merge($tmp_services, explodeGroups2Services($member2, $inMemoryObjects, $level+1));
        }
    }

    return $tmp_services;
}

/**
 * Method to explode Groups into its Services. A group can be a Service
 * @param array $services
 * @param mysqli $projectdb
 * @param String $source
 * @param String $vsys
 * @param int|null $level
 * @return MemberObject[]
 */
function explodeGroups2Services(ARRAY $services, mysqli $projectdb, STRING $source, STRING $vsys, $level=NULL){
    if(is_null($services)){
        $services = array();
    }
    if(is_null($level)){
        $level=0;
    }
    $tmp_services=array();

    foreach($services as $service){
        //Not a group. Let's add it directly
        if(strcmp($service->name, 'any')===0 && strcmp($service->location, '')===0){
            //This is the ANY service
            return array($service); //No need to look for more, this service covers all

        }
        elseif(strcmp($service->location, 'services')===0){
            if(!isset($service->value) || !isset($service->cidr)){
                $query ="SELECT id, dport, protocol FROM services WHERE id=$service->name ;";//AND source='$source' AND vsys='$vsys'
                $getService = $projectdb->query($query);
                if($getService->num_rows == 1){
                    $row=$getService->fetch_assoc();
                    $service->value=$row['dport'];
                    $service->cidr= $row['protocol'];
                }
            }

            $tmp_services[]=$service;
        }

        //This is a group. Let's expand it
        else{
            $query = "SELECT member_lid, table_name FROM services_groups sg WHERE sg.lid='$service->name' "; //sg.source='$source' AND sg.vsys='$vsys' AND
            $getService = $projectdb->query($query);
            $member2 = array();
            while($row = $getService->fetch_assoc()) {
                $service_id= $row['member_lid'];
                $service_location = $row['table_name'];
                $member2[] = new MemberObject($service_id, $service_location);
            }
            $tmp_services = array_merge($tmp_services, explodeGroups2Services($member2, $projectdb, $source, $vsys, $level+1));
        }
    }

    return $tmp_services;
}

function isAinB_Zones(ARRAY $groupA, ARRAY $groupB, ARRAY &$foundZones=null){

    if(count($groupB)==0 || in_array("any", $groupB) || in_array("Any", $groupB)){
        if(count($groupA)== 0 || in_array("any", $groupA) || in_array("Any", $groupA)) {
            $foundZones = $groupA;
            return 1;
        }
        else{
            $foundZones = $groupA;
            return 2;
        }
    }
    elseif(count($groupA)== 0 || in_array("any", $groupA) || in_array("Any", $groupA)){
        $foundZones = $groupB;
        return 2;
    }
    else {
        $foundZones = array_intersect($groupA, $groupB);
    }

    if (count($foundZones) == 0) {
        return 0;
    }
    if (count($foundZones) == count($groupA)) {
        return 1;
    }
    return 2;
}

/**
 * This method checks whether the members in groupA are in the groupB. 
 * @param array(MemberObject) $groupA
 * @param array(MemberObject) $groupB
 * @param String $debugText
 * @return int
 */
function isAinB($groupA, $groupB, &$foundMembers=null, $debugText=NULL){
    if(isset($debugText)){
        echo "$debugText\n";
    }
    $foundMembers = array();
    $allChildrenFound = true;
    $someChildrenFound = false;

    foreach($groupA as $childMember){
//        echo "Child:";  print_r($childMember);

        if(ip_version($childMember->value)!='v4'){
            $allChildrenFound = false;
        }
        else {
            $childMember_is_found = false;
            foreach ($groupB as $parentMember) {

                $result = -1;

                if (ip_version($parentMember->value) != 'v4') {
                    $newMatch = -1;
                } else {
//                    echo "Parent:";  print_r($parentMember);
                    $newMatch = netMatchObjects2Ways($childMember, $parentMember, $result);
//            echo "Result: $result\n\n";
                }

                if ($result == 1) { //if one of the members in the groupA is not in groupB, then A is not in B
//                $isChildPartiallyFound = 1;
                    $someChildrenFound = true;
                    $childMember_is_found = true;
                    $foundMembers[] = $childMember;
                    break;
                } elseif ($result == 2) {
                    //$allChildrenFound = false;
                    $someChildrenFound = true;
                    $foundMembers[] = $newMatch;
                } else {
                    //$allChildrenFound = false;
                }
            }

            if(!$childMember_is_found){
                $allChildrenFound = false;
            }
        }
    }

    if($allChildrenFound) {
//        echo "Final result 1\n";
        return 1;
    }
    if($someChildrenFound) {
//        echo "Final result 2\n";
        return 2;
    }
//    echo "Final result 0\n";
    return 0;
}

function isAinB_service($groupA, $groupB, &$foundServices=null,$debugText=null){
    if(isset($debugText)){
        echo "$debugText\n";
    }

    $all_found = true;
    $some_found = false;

    foreach($groupA as $groupAMember){
        $childMember_is_found = false;
        foreach($groupB as $groupBMember){
            $result=-1;
            $newMatch = serviceMatchObjects2Ways($groupAMember, $groupBMember, $result);
            if ($result == 1) { //if one of the members in the groupA is not in groupB, then A is not in B
                $some_found = true;
                $foundServices[] = $newMatch;
                $childMember_is_found = true;
                break;
            } elseif($result == -1) {
                //$all_found = false;
            } elseif ($result == 2) {
                //$all_found = false;
                $some_found = true;
                $foundServices[] = $newMatch;
            }
        }
        if(!$childMember_is_found){
            $all_found = false;
        }
    }

    if($all_found) {
        return 1;
    }
    if($some_found) {
        return 2;
    }
    //echo "Service Full GroupA Match: 1\n";
    return 0;
}

function isAinBbinary($memberA, $memberB){
//    $binaryA; $binaryB;
    
    $binaryA = cidr2networkLong($memberA->value,$memberB->cidr) ;
    $binaryB = cidr2networkLong($memberB->value,$memberB->cidr) ;
    if($binaryA === $binaryB) return true;
    return false;
}

function cidr2networkLong($ip, $cidr) {
    $network = (ip2long($ip)) & ((-1 << (32 - (int) $cidr)));
    return $network;
}

function initTag(){
    $tag = array();
    $tag['checkit']=0;
    $tag['id']=$tag['name']=$tag['name_ext']=$tag['color']=$tag['comments']=$tag['modified']=$tag['vtype']=$tag['dummy'] = '';
    return $tag;
}

function initProfileGroup(){
    $profile = array();
    $tag['checkit']=0;
    $profile['id']=$profile['source']=$profile['name']=$profile['name_ext']=$profile['xml']=$profile['type']=
    $profile['vsys']=$profile['devicegroup']=$profile['modified']=$profile['vtype']=
    $profile['dummy']="";

    return $profile;
}

function initProfile(){
    $profile = array();
    $profile['checkit']=0;
    $profile['id']=$profile['name']=$profile['name_ext']=$profile['xml']=$profile['type']=$profile['modified']=$profile['vtype']=$profile['dummy'] = '';
    return $profile;
}

function initApp(){
    $app = array();
    $app['modified']=0;
    $app['checkit']=0;
    $app['dummy']=$app['vtype=']=$app['vtype']=
    $app['value']=$app['default_type']=$app['timeout']=$app['code']=$app['type']=$app['tunnel_applications']=$app['parent_app']=$app['name']=$app['name_ext']=
    $app['tcp_timeout']=$app['tcp_halp_closed_timeout']=$app['tcp_time_wait_timeout']=$app['breaks_decryption']=$app['udp_timeout']=$app['application_container']=
    $app['ottawa_name']=$app['decode']=$app['icon_min_ver']=$app['icon']=$app['is_saas']=$app['file_forward']=$app['file_type_ident']=$app['spyware_ident']=
    $app['virus_ident']=$app['url_category']=$app['data_ident']=$app['preview']=$app['risk']=$app['can_disable']=$app['cachable']=$app['run_decoder']=
    $app['deny_action']=$app['per_direction_regex']=$app['pervasive_use']=$app['prone_to_misuse']=$app['tunnel_other_application']=$app['has_known_vulnerability']=
    $app['able_to_transfer_file']=$app['category']=$app['subcategory']=$app['technology']=$app['description']=$app['alg']=$app['appident']=$app['vulnerability_ident']=
    $app['evasive_behavior']=$app['consume_big_bandwidth']=$app['used_by_malware'] = '';
    return $app;
}

function initHipProfile(){
    $hipID = array();
    $hipID['source']=$hipID['name']=$hipID['name_ext']=$hipID['xml']=$hipID['type']=$hipID['vsys']=$hipID['devicegroup']=$hipID['vtype']=$hipID['dummy']="";
    $hipID['modified']=0;
    $hipID['checkit']=0;

    return $hipID;
}

function initAppGroup(){
    $appGroup = array();
    $appGroup['modified']=$appGroup['used']=0;
    $appGroup['name']=$appGroup['name_ext']=$appGroup['devicegroup']=$appGroup['vsys']=$appGroup['source']=$appGroup['invalid']="";
    $appGroup['members']=array();

    return $appGroup;
}

function initServiceMember(){
    $service=array();
    $service['name']=$service['name_ext']=$service['checkit']=$service['used']=
    $service['vsys']=$service['devicegroup']=$service['type']=$service['description']=
    $service['sport']=$service['dport']=$service['protocol']=$service['icmp']=$service['source']=
    $service['tag']=$service['invalid']=$service['modified']=$service['vtype']=$service['dummy']="";
    return $service;
}

function initAddressMember(){
    // name, name_ext, used, checkit, devicegroup, vsys, type, ipaddress, cidr, description, fqdn, v4, v6, vtype, source, tag, zone, invalid, modified, dummy
    $address=array();
    $address['modified']=0;
    $address['checkit']=0;
    $address['name']=$address['name_ext']=$address['used']=
    $address['devicegroup']=$address['vsys']=$address['type']=$address['ipaddress']=$address['cidr']=
    $address['description']=$address['fqdn']=$address['v4']=$address['v6']=
    $address['vtype']=$address['source']=$address['tag']=
    $address['zone']=$address['invalid']=$address['dummy']="";
    return $address;
}

function deleteIpAddressNetmask(mysqli $projectdb, MemberObject $address, STRING $type, STRING $ip, STRING $cidr){
    $query = "UPDATE $address->location SET ipaddress='', cidr='' WHERE id='$address->name' AND ipaddress='$ip' AND cidr='$cidr' AND type='$type' ;";
    $projectdb->query($query);
}

function deleteAddressDescription(mysqli $projectdb, MemberObject $address){
    $query = "UPDATE $address->location SET description='' WHERE id='$address->name';";
    $projectdb->query($query);
}

function setAddressDescription(mysqli $projectdb, MemberObject $address, STRING $description){
    $query = "UPDATE $address->location SET description='$description' WHERE id='$address->name';";
    $projectdb->query($query);
}

function setIpAddressNetmask(mysqli $projectdb, MemberObject $address, STRING $type, STRING $ip, STRING $cidr, STRING $ipv){
    if ($ipv == 'v6') {
        $query = "UPDATE $address->location SET type='$type', ipaddress='$ip', cidr='$cidr', v4='0', v6='1' WHERE id='$address->name' ;";
    }
    else{
        $query = "UPDATE $address->location SET type='$type', ipaddress='$ip', cidr='$cidr', v4='1', v6='0' WHERE id='$address->name' ;";
    }
    $projectdb->query($query);
}

function prepareNameForClone(STRING $field, STRING $value, INT $extraLength){
    switch($field){
        case "name":
            $result = substr($value, 0, NAMELenght-$extraLength);
            break;
        case "name_ext":
            $result = substr($value, 0, NAMEPANLenght-$extraLength);
            break;
        default:
            $result = substr($value, 0, NAMELenght-$extraLength);
            break;
    }
    return $result;
}

function cloneAddressMemberId(mysqli $projectdb, MemberObject $memberToModify){
    return cloneMemberId($projectdb, $memberToModify);
}

function cloneMemberId(mysqli $projectdb, MemberObject $memberToModify){
    $tableName = $memberToModify->location;
    switch($tableName){
        case "address":
            $query = "SELECT name, name_ext FROM $tableName WHERE id = '$memberToModify->name'";
            $result = $projectdb->query($query);
            $row = $result->fetch_assoc();
            $name = prepareNameForClone("name",$row['name'],3)."_CL";
            $name_ext = prepareNameForClone("name_ext",$row['name_ext'],3)."_CL";
            $query =    "INSERT INTO $tableName (name, name_ext, used, checkit, devicegroup, vsys, type, ipaddress, cidr, description, fqdn, v4, v6, vtype, source, tag, zone, invalid, modified, dummy) ".
                        "SELECT '".$name."', '".$name_ext."', used, checkit, devicegroup, vsys, type, ipaddress, cidr, description, fqdn, v4, v6, vtype, source, tag, zone, invalid, modified, dummy ".
                        "FROM address ".
                        "WHERE id='$memberToModify->name';";
            break;

        default:
            echo "cloneMemberId: We do not support cloning an object of type $tableName\n";
            return null;
    }

    $projectdb->query($query);
    $clonedMember = new MemberObject($projectdb->insert_id, $memberToModify->location);
    return $clonedMember;
}

function getVsysesUnderID(ARRAY $ALLvsysList, INT $vsysid){
    $children = array();

    foreach ($ALLvsysList as $vsysObj){
        if($vsysObj['parentID'] == $vsysid){
            $children[] = $vsysObj['id'];
            $myChildren = getVsysesUnderID($ALLvsysList, $vsysObj['id']);
            if(count($myChildren)>0){
                $children = array_merge($children, $myChildren);
            }
        }
    }

    return $children;
}

function getVsysesDescIDs(mysqli $projectdb, STRING $vsys, INT $vsysID){
    $vsyses = array();
    $ALLvsysList = array();

    $query = "SELECT dm.id, dm.vsys, dg.device_mapping_id as kidID, parent_dg as parentID
              FROM device_mapping dm, devicegroups dg 
              WHERE dm.id = dg.device_mapping_id";

    $result = $projectdb->query($query);
    if ($result->num_rows>0){
        while($data = $result->fetch_assoc()) {
            $ALLvsysList[$data['kidID']] = [
                'id' => $data['kidID'],
                'name' => $data['vsys'],
                'parentID' => $data['parentID']
            ];
        }
    }

    $vsysItem = $ALLvsysList[$vsysID];
    $vsyses[] = $vsysItem['id'];
    $vsyses = array_merge($vsyses, getVsysesUnderID($ALLvsysList, $vsysItem['id']));

    return $vsyses;
}

function getVsysesIDs(mysqli $projectdb, STRING $vsys){
    $vsyses = array();
    $ALLvsysList = array();

    $query = "SELECT dm.id, dm.vsys, dg.device_mapping_id as kidID, parent_dg as parentID
              FROM device_mapping dm, devicegroups dg 
              WHERE dm.id = dg.device_mapping_id";

    $result = $projectdb->query($query);
    if ($result->num_rows>0){
        while($data = $result->fetch_assoc()) {
            $ALLvsysList[$data['kidID']] = [
                'id' => $data['kidID'],
                'name' => $data['vsys'],
                'parentID' => $data['parentID']
            ];
        }
    }

    $parentID = 0;
    foreach ($ALLvsysList as $key=>$vsysItem){
        if($vsysItem['name'] == $vsys) {
            $vsyses[] = $vsysItem['id'];
            $parentID = $vsysItem['parentID'];
            break;
        }
    }

    while ($parentID != 0){
        $vsyses[] = $ALLvsysList[$parentID]['id'];
        $parentID = $ALLvsysList[$parentID]['parentID'];

    }

    if(!in_array(0, $vsyses)) {
        $vsyses[] = 0;
    }
    return $vsyses;
}

/***
 * @param mysqli $projectdb
 * @param STRING $vsys
 * @param INT $source
 * @param STRING|null $format
 * @return array
 */
function getVsyses(mysqli $projectdb, STRING $vsys, INT $source, STRING $format=null):array{
    $vsys = normalizeNamesNew($vsys, 9, 'vsys');
    $vsyses = array();
    $ALLvsysList = array();

    $query = "SELECT dm.vsys, dg.device_mapping_id as kidID, parent_dg as parentID
              FROM device_mapping dm, devicegroups dg 
              WHERE dm.id = dg.device_mapping_id AND dg.source = '$source'; ";

    $result = $projectdb->query($query);
    if ($result->num_rows>0){
        while($data = $result->fetch_assoc()) {
            $ALLvsysList[$data['kidID']] = [
                'id' => $data['kidID'],
                'name' => $data['vsys'],
                'parentID' => (int)$data['parentID']
            ];
        }
    }

    $parentID = 0;
    foreach ($ALLvsysList as $vsysItem){
        if($vsysItem['name'] === $vsys) {
            $parentID = $vsysItem['parentID'];
            break;
        }
    }

    //Check it is not a NON PANOS device. In such a case, we will return all the vsys, but not the vsys all, so they are correctly sorted
    if($vsys==='all' && count($ALLvsysList)===0){
        {
            $query = "select vsys from device_mapping;";
            $vsysResult = $projectdb->query($query);
            while($data = $vsysResult->fetch_assoc()){
                $vsyses[] = $data['vsys'];
            }
        }
    }

    else {
        if (isset($format) && $format = 'quoted') {
            $vsyses[] = "'$vsys'";
        } else {
            $vsyses[] = $vsys;
        }


        while ($parentID !== 0) {
            if (isset($format) && $format = 'quoted') {
                $vsyses[] = "'" . $ALLvsysList[$parentID]['name'] . "'";
            } else {
                $vsyses[] = $ALLvsysList[$parentID]['name'];
            }
            $parentID = $ALLvsysList[$parentID]['parentID'];

        }

        if (!in_array('shared', $vsyses)) {
            if (isset($format) && $format = 'quoted') {
                $vsyses[] = "'shared'";
            } else {
                $vsyses[] = 'shared';
            }
        }
    }
    return $vsyses;
}

function getMemberId(mysqli $projectdb, $source, ARRAY $vsyses, STRING $memberName){
    global $projectdb;

    $member = null;

    foreach($vsyses as $vsys) {

        if($vsys == ""){
            $query_vsys = "";
        }else{
            $query_vsys = " AND vsys='$vsys' ";
        }

        //$query = "SELECT id FROM regions WHERE name='$memberName' AND source='$source' AND vsys='$vsys'";
        $query = "SELECT id FROM regions WHERE name='$memberName' AND source='$source' $query_vsys ;";
        $matchingAddress = $projectdb->query($query);
        if ($matchingAddress->num_rows != 0) {
            $get = (ARRAY)$matchingAddress->fetch_assoc();
            $id = $get['id'];
            $location = "regions";
            $value = '';
            $cidr = '';
            $member = new MemberObject($id, $location, $value, $cidr);
            break;
        }
        else {
            $query = "SELECT id FROM default_regions WHERE name='$memberName';";
            $matchingAddress = $projectdb->query($query);
            if ($matchingAddress->num_rows != 0) {
                $get = (ARRAY)$matchingAddress->fetch_assoc();
                $id = $get['id'];
                $location = "default_regions";
                $value = '';
                $cidr = '';
                $member = new MemberObject($id, $location, $value, $cidr);
                break;
            }
            else {
                //$query = "SELECT id, ipaddress, cidr FROM address WHERE BINARY name='$memberName' AND source='$source' AND vsys='$vsys';";
                $query = "SELECT id, ipaddress, cidr FROM address WHERE BINARY name='$memberName' AND source='$source' $query_vsys ;";
                $matchingAddress = $projectdb->query($query);
                if ($matchingAddress->num_rows != 0) {
                    $get = (ARRAY)$matchingAddress->fetch_assoc();
                    $id = $get['id'];
                    $location = "address";
                    $value = $get['ipaddress'];
                    $cidr = $get['cidr'];
                    $member = new MemberObject($id, $location, $value, $cidr);
                    break;
                }
                else {
                    //$query = "SELECT id FROM address_groups_id WHERE BINARY name='$memberName' AND source='$source' AND vsys='$vsys';";
                    $query = "SELECT id FROM address_groups_id WHERE BINARY name='$memberName' AND source='$source' $query_vsys ;";
                    $matchingAddress = $projectdb->query($query);
                    if ($matchingAddress->num_rows != 0) {
                        $get = (ARRAY)$matchingAddress->fetch_assoc();
                        $id = $get['id'];
                        $location = "address_groups_id";
                        $value = '';
                        $cidr = '';
                        $member = new MemberObject($id, $location, $value, $cidr);
                        break;
                    }
                    else{
                        //$query = "SELECT id FROM external_list WHERE BINARY name='$memberName' AND source='$source' AND vsys='$vsys';";
                        $query = "SELECT id FROM external_list WHERE BINARY name='$memberName' AND source='$source' $query_vsys ;";
                        $matchingAddress = $projectdb->query($query);
                        if ($matchingAddress->num_rows != 0) {
                            $get = (ARRAY)$matchingAddress->fetch_assoc();
                            $id = $get['id'];
                            $location = "external_list";
                            $value = '';
                            $cidr = '';
                            $member = new MemberObject($id, $location, $value, $cidr);
                            break;
                        }
                    }
                }
            }
        }
    }
    return $member;
}

function getServiceIdbyVsys(mysqli $projectdb, $source, STRING $vsys, STRING $serviceName, ARRAY &$servicesArray){

    global $projectdb;

    if (count($servicesArray)==0){
        // Init it
        $getVsysAll=getVsyses($projectdb, $vsys, $source, 'quoted');
        $getServices=$projectdb->query("SELECT id, dport, protocol,vsys,source,name FROM services WHERE source='$source' AND vsys IN (".implode(",",$getVsysAll).");");
        if ($getServices->num_rows>0){
            while($getServicesData=$getServices->fetch_assoc()){
                $servicesArray["services"][$getServicesData['vsys']][$getServicesData['name']]=$getServicesData['id'];
            }
        }
        $getServices=$projectdb->query("SELECT id,vsys,source,name FROM services_groups_id WHERE source='$source' AND vsys IN (".implode(",",$getVsysAll).");");
        if ($getServices->num_rows>0){
            while($getServicesData=$getServices->fetch_assoc()){
                $servicesArray["services_groups_id"][$getServicesData['vsys']][$getServicesData['name']]=$getServicesData['id'];
            }
        }
    }

    // Run
    $vsyses=getVsyses($projectdb, $vsys, $source);
    foreach($vsyses as $checkvsys) {
        if (isset($servicesArray['services'][$checkvsys][$serviceName])){
            return array("table_name"=>"services","member_lid"=>$servicesArray['services'][$checkvsys][$serviceName]);
        }
        if (isset($servicesArray['services_groups_id'][$checkvsys][$serviceName])){
            return array("table_name"=>"services_groups_id","member_lid"=>$servicesArray['services_groups_id'][$checkvsys][$serviceName]);
        }
    }

    #If its not already created as Service or ServiceGroup will be created as dummy understanding this is a firewall and this service was defined in Panorama
    $projectdb->query("INSERT INTO services (source,vsys,dummy,name,name_ext,vtype, devicegroup) VALUES ('$source','shared',1,'$serviceName','$serviceName','dummy', 'MT_Panorama');");
    $servicesArray["services"]["shared"][$serviceName]=$projectdb->insert_id;
    return array("table_name"=>"services","member_lid"=>$projectdb->insert_id);

}

function getServiceId(mysqli $projectdb, $source, ARRAY $vsyses, STRING $serviceName){
    global $projectdb;

    $member = null;

    foreach($vsyses as $vsys) {
        $query = "SELECT id, dport, protocol FROM services WHERE BINARY name='$serviceName' AND source='$source' AND vsys='$vsys';";
        $matchingAddress = $projectdb->query($query);
        if ($matchingAddress->num_rows != 0) {
            $get = (ARRAY)$matchingAddress->fetch_assoc();
            $id = $get['id'];
            $location = "services";
            $port = $get['dport'];
            $protocol = $get['protocol'];
            $member = new MemberObject($id, $location, $port, $protocol);
            break;
        }
        else {
            $query = "SELECT id FROM services_groups_id WHERE BINARY name='$serviceName' AND source='$source' AND vsys='$vsys';";
            $matchingAddress = $projectdb->query($query);
            if ($matchingAddress->num_rows != 0) {
                $get = (ARRAY)$matchingAddress->fetch_assoc();
                $id = $get['id'];
                $location = "services_groups_id";
                $port = '';
                $protocol = '';
                $member = new MemberObject($id, $location, $port, $protocol);
                break;
            }
        }
    }

    return $member;
}

function getTagId(mysqli $projectdb, $source, ARRAY $vsyses, STRING $tagName){
    global $projectdb;

    $member = null;

    $tagName = normalizeTagNames($tagName);

    foreach($vsyses as $vsys) {
        $query = "SELECT id FROM tag WHERE BINARY name='$tagName' AND source='$source' AND vsys='$vsys';";
        $matchingAddress = $projectdb->query($query);
        if ($matchingAddress->num_rows != 0) {
            $get = (ARRAY)$matchingAddress->fetch_assoc();
            $id = $get['id'];
            $location = "tag";
            $member = new MemberObject($id, $location);
            break;
        }
    }

    return $member;
}

function getProfileGroupId(mysqli $projectdb, $source, ARRAY $vsyses, STRING $name){
    global $projectdb;

    $member = null;

    foreach ($vsyses as $vsys) {
        $query = "SELECT id FROM profiles_groups WHERE BINARY name='$name' AND source='$source' AND vsys='$vsys';";
        $matchingAddress = $projectdb->query($query);
        if ($matchingAddress->num_rows != 0) {
            $get = (ARRAY)$matchingAddress->fetch_assoc();
            $id = $get['id'];
            $location = "profiles_groups";
            $member = new MemberObject($id, $location);
            break;
        }
    }

    return $member;
}

function getProfileId(mysqli $projectdb, $source, ARRAY $vsyses, STRING $type, STRING $name){
    global $projectdb;

    $member = null;

    foreach ($vsyses as $vsys) {
        $query = "SELECT id FROM profiles WHERE type='$type' AND BINARY name='$name' AND source='$source' AND vsys='$vsys';";
        $matchingAddress = $projectdb->query($query);
        if ($matchingAddress->num_rows != 0) {
            $get = (ARRAY)$matchingAddress->fetch_assoc();
            $id = $get['id'];
            $location = "profiles";
            $member = new MemberObject($id, $location);
            break;
        }
    }

    return $member;
}

function getAppId(mysqli $projectdb, $source, ARRAY $vsyses, STRING $appName){
    global $projectdb;

    $member = null;
    $found = false;

    $query = "SELECT id FROM default_applications WHERE BINARY name='$appName';";
    $matchingAddress = $projectdb->query($query);
    if ($matchingAddress->num_rows != 0) {
        $get = (ARRAY)$matchingAddress->fetch_assoc();
        $id = $get['id'];
        $location = "default_applications";
        $member = new MemberObject($id, $location);
        $found = true;
    }

    if (!$found) {
        foreach ($vsyses as $vsys) {
            $query = "SELECT id FROM applications WHERE BINARY name='$appName' AND source='$source' AND vsys='$vsys';";
            $matchingAddress = $projectdb->query($query);
            if ($matchingAddress->num_rows != 0) {
                $get = (ARRAY)$matchingAddress->fetch_assoc();
                $id = $get['id'];
                $location = "applications";
                $member = new MemberObject($id, $location);
                break;
            }
            else {

                $query = "SELECT id FROM applications_groups_id WHERE BINARY name='$appName' AND source='$source' AND vsys='$vsys';";
                $matchingAddress = $projectdb->query($query);
                if ($matchingAddress->num_rows != 0) {
                    $get = (ARRAY)$matchingAddress->fetch_assoc();
                    $id = $get['id'];
                    $location = "applications_groups_id";
                    $member = new MemberObject($id, $location);
                    break;
                }
                else{
                    $query = "SELECT id FROM applications_filters WHERE BINARY name='$appName' AND source='$source' AND vsys='$vsys';";
                    $matchingAddress = $projectdb->query($query);
                    if ($matchingAddress->num_rows != 0) {
                        $get = (ARRAY)$matchingAddress->fetch_assoc();
                        $id = $get['id'];
                        $location = "applications_filters";
                        $member = new MemberObject($id, $location);
                        break;
                    }
                }
            }
        }
    }

    return $member;
}

function getZoneId(mysqli $projectdb, $source, ARRAY $vsyses, STRING $zoneName){
    global $projectdb;

    $member = null;

    foreach ($vsyses as $vsys) {
        $query = "SELECT id FROM zones WHERE BINARY name='$zoneName'AND source='$source' AND vsys='$vsys';";
        $matchingAddress = $projectdb->query($query);
        if ($matchingAddress->num_rows != 0) {
            $get = (ARRAY)$matchingAddress->fetch_assoc();
            $id = $get['id'];
            $location = "default_applications";
            $member = new MemberObject($id, $location);
            break;
        }
    }

    return $member;
}

function updateTagId(mysqli $projectdb, $tag){
    $query = "UPDATE tag SET";
    foreach ($tag as $key=>$value){
        if ($tag[$key]!= '' && $key!='id'){
            $query =$query . " $key = '$value', ";
        }
    }
    $query=$query." id=id WHERE id='".$tag['id']."';";

    $projectdb->query($query);
}

function createTagId(mysqli $projectdb, $source, $devicegroup, $vsys, $tag){
    //name, color, comments, source, vsys, devicegroup, modified, vtype, dummy
    $query = "INSERT INTO tag (name, name_ext, color, comments, source, vsys, devicegroup, modified, vtype, dummy, checkit) ".
        "VALUES     ('".$tag['name']."','".$tag['name_ext']."', '".$tag['color']."', '".$tag['comments']."', '$source', '$vsys', '$devicegroup', '".$tag['modified']."', '".$tag['vtype']."', '".$tag['dummy']."', '".$tag['checkit']."') ".
        ";";
    $projectdb->query($query);
    $tagObject_1 = new MemberObject($projectdb->insert_id, 'tag');
    return $tagObject_1;
}

function createAppGroupId(mysqli $projectdb, $source, $devicegroup, $vsys, $member){
    $memberApps = array();
    $used=0;
    $xml="";
    $modified = 1;

    $query = "INSERT INTO applications_groups_id (name, name_ext, used, devicegroup, vsys, source, invalid, modified) VALUES ".
             "('".$member['name']."','".$member['name_ext']."', ".$member['used'].", '".$member['devicegroup']."', '".$member['vsys']."', '".$member['source']."', '".$member['invalid']."', '".$member['modified']."' )";
    $projectdb->query($query);
    $groupAppId = new MemberObject($projectdb->insert_id, 'applications_groups_id');

    foreach ($member['members'] as $memberApp){
        //source, vsys, devicegroup, name, used, xml, member, member_lid, table_name, lid, type,  modified
        $memberApps[] = "('$source', '$vsys', '$devicegroup', '$used','$xml','','$memberApp->name', '$memberApp->location', '$groupAppId->name', '', '$modified')";
    }

    if (count($memberApps) > 0){
        $query="INSERT INTO applications_groups (source, vsys, devicegroup, used, xml, member, member_lid, table_name, lid, type,  modified) VALUES " . implode(",", $memberApps) . ";";
        $projectdb->query($query);
    }

    return $groupAppId;

}

function createHIPProfile(mysqli $projectdb, $source, $devicegroup, $vsys, $hipId){
    $query = " INSERT INTO profiles (source, name, name_ext, xml, type, vsys, devicegroup, modified, vtype, dummy, checkit)".
        " VALUES ('".$source."', '".$hipId['name']."', '".$hipId['name_ext']."', '".$hipId['xml']."','".$hipId['type']."','".$vsys."','".$devicegroup."','".$hipId['modified']."','".$hipId['vtype']."','".$hipId['dummy']."','".$hipId['checkit']."')";

    $projectdb->query($query);
    $tagObject_1 = new MemberObject($projectdb->insert_id, 'profiles');
    return $tagObject_1;
}

function createAppId(mysqli $projectdb, $source, $devicegroup, $vsys, $appId){
    $query = " INSERT INTO applications (".
        "source, devicegroup, vsys, name, name_ext, description, category, subcategory, parent_app, risk,".
        "technology, evasive_behavior, consume_big_bandwidth, used_by_malware, able_to_transfer_file,".
        "has_known_vulnerability, tunnel_other_application, tunnel_applications, prone_to_misuse, pervasive_use,".
        "file_type_ident, virus_ident, data_ident, default_type, value, type, code, timeout, tcp_timeout, udp_timeout,".
        "tcp_half_closed_timeout, tcp_time_wait_timeout, spyware_ident, modified, vtype, dummy, checkit)".
        " VALUES ".
        "('".$source."', '".$devicegroup."', '".$vsys."', '".$appId['name']."','".$appId['name_ext']."', '".$appId['description']."','".$appId['category']."','".$appId['subcategory']."','".$appId['parent_app']."','".$appId['risk']."',".
         "'".$appId['technology']."','".$appId['evasive_behavior']."','".$appId['consume_big_bandwidth']."','".$appId['used_by_malware']."','".$appId['able_to_transfer_file']."',".
         "'".$appId['has_known_vulnerability']."','".$appId['tunnel_other_application']."','".$appId['tunnel_applications']."','".$appId['prone_to_misuse']."','".$appId['pervasive_use']."',".
         "'".$appId['file_type_ident']."','".$appId['virus_ident']."','".$appId['data_ident']."','".$appId['default_type']."','".$appId['value']."','".$appId['type']."','".$appId['code']."','".$appId['timeout']."','".$appId['tcp_timeout']."','".$appId['udp_timeout']."',".
         "'".$appId['tcp_halp_closed_timeout']."','".$appId['tcp_time_wait_timeout']."','".$appId['spyware_ident']."','".$appId['modified']."','".$appId['vtype']."','".$appId['dummy']."','".$appId['checkit']."')".
        ";";

//    echo "$query\n";
    $projectdb->query($query);
    $tagObject_1 = new MemberObject($projectdb->insert_id, 'tag');
    return $tagObject_1;
}

function createAddressMemberId(mysqli $projectdb, $source, $devicegroup, $vsys, $addressArray){
    $query = "INSERT INTO address (source, vsys, devicegroup, name, name_ext, used, ".
        "checkit, type, ipaddress, cidr, description, ".
        "fqdn, v4, v6, vtype,  tag, ".
        "zone, invalid, modified, dummy) ".
             "VALUES ('$source', '$vsys', '$devicegroup', '".$addressArray['name']."', '".$addressArray['name_ext']."','".$addressArray['used']."',".
        "'".$addressArray['checkit']."', '".$addressArray['type']."', '".$addressArray['ipaddress']."', '".$addressArray['cidr']."', '".addslashes($addressArray['description'])."',".
        "'".$addressArray['fqdn']."', '".$addressArray['v4']."', '".$addressArray['v6']."', '".$addressArray['vtype']."', '".$addressArray['tag']."',".
        "'".$addressArray['zone']."', '".$addressArray['invalid']."', '".$addressArray['modified']."', '".$addressArray['dummy']."');";
    $projectdb->query($query);
    $tagObject_1 = new MemberObject($projectdb->insert_id, 'address');
    return $tagObject_1;
}

function createServiceMemberId(mysqli $projectdb, $source, $devicegroup, $vsys, $serviceArray){
    $query = "
    INSERT INTO services (name, name_ext, checkit, used, vsys, devicegroup, type, description, sport, dport, protocol, icmp, source, tag, invalid, modified, vtype, dummy)
    VALUES ('".$serviceArray['name']."','".$serviceArray['name_ext']."','".$serviceArray['checkit']."','".$serviceArray['used']."',$vsys,$devicegroup,'".$serviceArray['type']."',
            '".$serviceArray['description']."''".$serviceArray['sport']."''".$serviceArray['dport']."''".$serviceArray['protocol']."''".$serviceArray['icmp']."',$source,
            '".$serviceArray['tag']."''".$serviceArray['invalid']."''".$serviceArray['modified']."''".$serviceArray['vtype']."''".$serviceArray['dummy']."')";
    $projectdb->query($query);
    $serviceObject_1 = new MemberObject($projectdb->insert_id,'services');
    return $serviceObject_1;
}

function createProfileId(mysqli $projectdb, $source, $devicegroup, $vsys, $profile){
    //name, color, comments, source, vsys, devicegroup, modified, vtype, dummy
    $query = "INSERT INTO profiles (source, name, name_ext, xml, type, vsys, devicegroup, modified, vtype, dummy, checkit) ".
        "VALUES     ('$source', '".$profile['name']."','".$profile['name_ext']."', '".$profile['xml']."', '".$profile['type']."', '$vsys', '$devicegroup', '".$profile['modified']."', '".$profile['vtype']."', '".$profile['dummy']."','".$profile['checkit']."') ".
        ";";
    $projectdb->query($query);
    $tagObject_1 = new MemberObject($projectdb->insert_id, 'profiles');
    return $tagObject_1;
}

function createProfileGroupId(mysqli $projectdb, $source, $devicegroup, $vsys, $profile){
    $query = "INSERT INTO profiles_groups (source,name, name_ext,xml,type,vsys, devicegroup, modified, vtype, dummy, checkit) 
              VALUES ('$source', '".$profile['name']."', '".$profile['name_ext']."','".$profile['xml']."','".$profile['type']."','$vsys',
                      '$devicegroup','".$profile['modified']."','".$profile['vtype']."','".$profile['dummy']."','".$profile['checkit']."')";
    $projectdb->query($query);
    $tagObject_1 = new MemberObject($projectdb->insert_id, 'profiles');
    return $tagObject_1;
}

//$a = new MemberObject("","","10.110.0.1","24");
//$b = new MemberObject("","","10.11.0.1","8");
//$result = isAinBbinary($a, $b);
//if ($result) echo "yes";
//else echo "no";
function negateAddress(mysqli $connection, ARRAY $addresses){
    global $projectdb;
    $projectdb = $connection;
    $fakeMapping['map'][] = Array('start' => 0, 'end' => ip2long('255.255.255.255'));

    foreach ($addresses as $address) {
        $objectsMapping = getIP4Mapping("", $address->name, $address->location);

        foreach ($objectsMapping['map'] as $entry) {
            removeNetworkFromIP4Mapping($fakeMapping['map'], $entry);
            //$objectsMapping = $fakeMapping;
        }
    }

    return $fakeMapping;
}

function negateAddressMemberObject(mysqli $connection, ARRAY $addresses){
    $fakeMapping = negateAddress($connection, $addresses);
//    print_r($fakeMapping);

    $negatedAddress = array();
    foreach ($fakeMapping['map'] as &$startEndAddress){
        $startEndAddress['start'] = long2ip($startEndAddress['start']);
        $startEndAddress['end'] = long2ip($startEndAddress['end']);
        $member = new MemberObject('', '', $startEndAddress['start']."-".$startEndAddress['end'], '32');
        $negatedAddress[] = $member;
    }
//    print_r($fakeMapping);
//    print_r($negatedAddress);

    return $negatedAddress;

}
