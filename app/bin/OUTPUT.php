<?php

# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';
require_once INC_ROOT.'/bin/Authentication.php';
require_once INC_ROOT.'/libs/shared.php';
require_once INC_ROOT.'/libs/database.php';
require_once INC_ROOT.'/libs/xmlapi.php';

include INC_ROOT.'/bin/middleware_sanitizer.php';

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $action     = (string)  (isset($_GET['action'])     ? $_GET['action'] : '');
        $type       = (string)  (isset($_GET['type'])       ? $_GET['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_GET['project'])    ? $_GET['project'] : '');
        break;
    case 'POST':
        $action     = (string)  (isset($_POST['action'])    ? $_POST['action'] : '');
        $type       = (string)  (isset($_POST['type'])      ? $_POST['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_POST['project'])   ? $_POST['project'] : '');
        break;

    default:
        $action     = (string)  (isset($_POST['action'])    ? $_POST['action'] : '');
        $type       = (string)  (isset($_POST['type'])      ? $_POST['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_POST['project'])   ? $_POST['project'] : '');
        break;
}

//$action = (string) (isset($_POST['action']) ? $_POST['action'] : $_GET['action']); // upload  / get  /
//$type = (string) (isset($_POST['type']) ? $_POST['type'] : $_GET['type']); // zip / xml / device
//$project = (string) (isset($_POST['project']) ? $_POST['project'] : $_GET['project']);

#DEBUG
//$project="test";
//$action="generate";
//$type="XML";
#DEBUG

require_once INC_ROOT.'/libs/projectdb.php';
$projectdb = selectDatabase($project);

$action = $projectdb->real_escape_string($action);
$type = $projectdb->real_escape_string($type);
$project = $projectdb->real_escape_string($project);

if ($action == "generate") {
    if ($type == "XML") {
        $getBC = $projectdb->query("SELECT id,ispanorama,version,filename FROM device_mapping WHERE active=1 AND baseconfig=1 GROUP BY filename;");
        if ($getBC->num_rows == 1) {
            #PHP VARS
            ini_set('max_execution_time', 10000);
            ini_set("memory_limit", "1000M");

            $dataBC = $getBC->fetch_assoc();
            $version = $dataBC['version'];

            if (preg_match("/^6\.0/", $version)) {
                $version = 6;
            } elseif (preg_match("/^6\.1/", $version)) {
                $version = 6.1;
            } elseif (preg_match("/^5\./", $version)) {
                $version = 5;
            } elseif (preg_match("/^7\./", $version)) {
                $version = 7;
            }
            $ispanorama = $dataBC['ispanorama'];
            $filename = $dataBC['filename'];
            $source = $dataBC['id'];
            add_progress($project, '0.00', 'Loading Base Config');
            #LOAD BC
            $OUTPUTPATH = USERSPACE_PATH."/projects/" . $project . "/" . $filename;
            $xml_str = file_get_contents($OUTPUTPATH);
            $xml = new SimpleXMLElement($xml_str);

            update_progress($project, '0.10', 'Loading Shared Objects');

            #ADD SHARED OBJECTS
            $existSHARED = $xml->xpath("/config/shared");
            if (empty($existSHARED)) {
                $root = $xml->xpath("/config");
                $root[0]->addChild('shared');
            }

            # SHARED ADDRESS
            $getShared = $projectdb->query("SELECT name,type,ipaddress,cidr,description,fqdn,v4,v6,tag FROM shared_address WHERE source='$source' AND dummy=0;");
            if ($getShared->num_rows > 0) {
                #SHARED ADDRESS
                if (!isset($xml->shared->address)) {
                    $xml->shared->addChild('address');
                } else {
                    #DELETE SHARED ADDRESS
                    $SA = $xml->xpath("/config/shared/address");
                    unset($SA[0][0]);
                    $xml->shared->addChild('address');
                }
                while ($Data = $getShared->fetch_assoc()) {
                    $myname = $Data['name'];
                    if ($xml->xpath("/config/shared/address/entry[@name='$myname']") == null) {
                        $address = $xml->shared->address->addChild('entry');
                        $address->addAttribute('name', $Data['name']);
                        if ($Data['type'] == "ip-netmask") {
                            $address->addChild('ip-netmask', $Data['ipaddress'] . '/' . $Data['cidr']);
                        } elseif ($Data['type'] == "ip-range") {
                            $address->addChild('ip-range', $Data['ipaddress']);
                        } elseif ($Data['type'] == "fqdn") {
                            $address->addChild('fqdn', $Data['ipaddress']);
                        } elseif ($Data['type'] == "dynamic") {
                            if ($version == 5) {
                                $address->addChild('dynamic', $Data['ipaddress']);
                            } elseif ($version >= 6) {
                                add_log('error', 'Exporting Shared Address', 'Dynamic Address Not supported in Panos 6.x [' . $myname . ']', $source, 'Object was Not Migrated');
                            }
                        }
                        if ($Data['description'] != "") {
                            $address->addChild('description');
                            $address->description = $Data['description'];
                        }
                        if (($Data['tag'] != "") AND ( $version >= 6)) {
                            $tags = $address->addChild('tag');
                            $mytags = explode(",", $Data['tag']);
                            foreach ($mytags as $key => $value) {
                                $tags->addChild('member', $value);
                            }
                        }
                    } else {
                        add_log('warning', 'Exporting Shared Address', 'Object Duplicated in Destination [' . $myname . ']', $source, 'Object was Not Migrated');
                    }
                }
            } 
            else {
                #DELETE SHARED ADDRESS
                $SA = $xml->xpath("/config/shared/address");
                unset($SA[0][0]);
                //$xml->shared->addChild('address');
            }

            # SHARED SCHEDULES
            $getShared = $projectdb->query("SELECT name,xml FROM shared_schedules WHERE source='$source' AND dummy = 0 ORDER BY id;");
            if ($getShared->num_rows > 0) {
                if (!isset($xml->shared->schedule)) {
                    $xml->shared->addChild('schedule');
                } else {
                    #DELETE SHARED SCHEDULES
                    $SA = $xml->xpath("/config/shared/schedule");
                    unset($SA[0][0]);
                    $xml->shared->addChild('schedule');
                }
                $theProfiles2 = $xml->xpath("/config/shared/schedule");
                $theProfiles = $theProfiles2[0];
                while ($data2 = $getShared->fetch_assoc()) {
                    $xmlfield = $data2['xml'];
                    $xmlname = $data2['name'];
                    
                    if ($version >= 7) {
                        if (strpos($xmlfield,"<schedule-type>")==false){
                            if (strpos($xmlfield,"<recurring>")!== false){
                                $xmlfield = str_replace("<recurring>", "<schedule-type><recurring>", $xmlfield);
                            }
                            if (strpos($xmlfield,"</recurring>")!== false){
                                $xmlfield = str_replace("</recurring>", "</recurring></schedule-type>", $xmlfield);
                            }
                            if (strpos($xmlfield,"<non-recurring>")!== false){
                                $xmlfield = str_replace("<non-recurring>", "<schedule-type><non-recurring>", $xmlfield);
                            }
                            if (strpos($xmlfield,"</non-recurring>")!== false){
                                $xmlfield = str_replace("</non-recurring>", "</non-recurring></schedule-type>", $xmlfield);
                            }
                        }
                            
                    }
                            
                    $xml_append = simplexml_load_string($xmlfield);
                    if ($theProfiles->xpath("//entry[@name='$xmlname']") != null) {
                        add_log('warning', 'Exporting Shared Schedules', 'Object Duplicated in Destination [' . $xmlname . ']', $source, 'Object was Not Migrated');
                    } else {
                        SimpleXMLElement_append($theProfiles, $xml_append);
                    }
                }
            } 
            else {
                #DELETE SHARED SCHEDULES
                $SA = $xml->xpath("/config/shared/schedule");
                unset($SA[0][0]);
                //$xml->shared->addChild('schedule');
            }

            # SHARED LOG SETTINGS
            if ($ispanorama==1){
                $getShared = $projectdb->query("SELECT type FROM shared_log_settings WHERE source='$source' AND type='profiles' AND dummy = 0 GROUP BY type ORDER BY id;");
                if ($getShared->num_rows > 0) {
                    if (!isset($xml->shared->{'log-settings'})) {
                        $xml->shared->addChild('log-settings');
                    } else {
                        #DELETE SHARED LOG SETTINGS
                        $SA = $xml->xpath("/config/shared/log-settings");
                        unset($SA[0][0]);
                        $xml->shared->addChild('log-settings');
                    }
                    $theProfiles = $xml->shared->{'log-settings'};
                    while ($Data = $getShared->fetch_assoc()) {
                        $type = $Data['type'];
                        $thetype = $theProfiles->{$type};
                        if (empty($thetype)) {
                            $thetype = $theProfiles->addChild($type);
                        }
                        $getbyType = $projectdb->query("SELECT xml,name FROM shared_log_settings WHERE source='$source' AND type='$type' AND dummy = 0 ORDER BY id;");
                        if ($getbyType->num_rows > 0) {
                            while ($data2 = $getbyType->fetch_assoc()) {
                                $xmlfield = $data2['xml'];
                                $xmlname = $data2['name'];
                                $xml_append = simplexml_load_string($xmlfield);
                                if ($xml->xpath("/config/shared/log-settings/$type/entry[@name='$xmlname']") != null) {
                                    add_log('warning', 'Exporting Shared Log Settings', 'Object Duplicated in Destination [' . $xmlname . ']', $source, 'Object was Not Migrated');
                                } else {
                                    SimpleXMLElement_append($xml->shared->{'log-settings'}->$type, $xml_append);
                                }
                            }
                        }
                    }
                } else {
                    #DELETE SHARED LOG SETTINGS
                    $SA = $xml->xpath("/config/shared/log-settings");
                    unset($SA[0][0]);
                    //$xml->shared->addChild('log-settings');
                }
            }
            else{
                $getShared = $projectdb->query("SELECT type FROM shared_log_settings WHERE source='$source' AND dummy = 0 GROUP BY type ORDER BY id;");
                if ($getShared->num_rows > 0) {
                    if (!isset($xml->shared->{'log-settings'})) {
                        $xml->shared->addChild('log-settings');
                    } else {
                        #DELETE SHARED LOG SETTINGS
                        $SA = $xml->xpath("/config/shared/log-settings");
                        unset($SA[0][0]);
                        $xml->shared->addChild('log-settings');
                    }
                    $theProfiles = $xml->shared->{'log-settings'};
                    while ($Data = $getShared->fetch_assoc()) {
                        $type = $Data['type'];
                        $thetype = $theProfiles->{$type};
                        if (empty($thetype)) {
                            $thetype = $theProfiles->addChild($type);
                        }
                        $getbyType = $projectdb->query("SELECT xml,name FROM shared_log_settings WHERE source='$source' AND type='$type' AND dummy = 0 ORDER BY id;");
                        if ($getbyType->num_rows > 0) {
                            while ($data2 = $getbyType->fetch_assoc()) {
                                $xmlfield = $data2['xml'];
                                $xmlname = $data2['name'];
                                
                                if($version >= 7){
                                    if($type == "snmptrap"){
                                        // En versión 7, el campo member tiene que ser una IP sino da error
                                        // Check if is IP
                                        $xmlfield2 = $xmlfield;
                                        $search_member = explode ("<manager>", $xmlfield2);
                                        $search_member2 = explode ("</manager>", $search_member[1]);
                                        $member = $search_member2[0];
                                        $is_ip = validateIpAddress($member, "v4");
                                        // Return 1: ip correct
                                        // si da error, añadir mensaje de error en el output mapping
                                    }
                                }
                                
                                $xml_append = simplexml_load_string($xmlfield);
                                if ($xml->xpath("/config/shared/log-settings/$type/entry[@name='$xmlname']") != null) {
                                    add_log('warning', 'Exporting Shared Log Settings', 'Object Duplicated in Destination [' . $xmlname . ']', $source, 'Object was Not Migrated');
                                } else {
                                    SimpleXMLElement_append($xml->shared->{'log-settings'}->$type, $xml_append);
                                }
                            }
                        }
                    }
                } else {
                    #DELETE SHARED LOG SETTINGS
                    $SA = $xml->xpath("/config/shared/log-settings");
                    unset($SA[0][0]);
                    //$xml->shared->addChild('log-settings');
                }
            }
                

            # SHARED PROFILES
            $getShared = $projectdb->query("SELECT type FROM shared_profiles WHERE source='$source' AND (name!='strict') AND (name!='default') AND dummy = 0 GROUP BY type ORDER BY id;");
            if ($getShared->num_rows > 0) {
                if (!isset($xml->shared->{'profiles'})) {
                    $xml->shared->addChild('profiles');
                } else {
                    #DELETE SHARED LOG SETTINGS
                    $SA = $xml->xpath("/config/shared/profiles");
                    unset($SA[0][0]);
                    $xml->shared->addChild('profiles');
                }
                $theProfiles = $xml->shared->profiles;
                while ($Data = $getShared->fetch_assoc()) {
                    $type = $Data['type'];
                    $thetype = $theProfiles->{$type};
                    if (empty($thetype)) {
                        $thetype = $theProfiles->addChild($type);
                    }
                    $getbyType = $projectdb->query("SELECT xml,name FROM shared_profiles WHERE source='$source' AND (name!='strict') AND (name!='default') AND type='$type' ORDER BY id;");
                    if ($getbyType->num_rows > 0) {
                        while ($data2 = $getbyType->fetch_assoc()) {
                            $xmlfield = $data2['xml'];
                            $xmlname = $data2['name'];
                            if ($version > 5) {
                                if ((strpos($xmlfield,"<packet-capture>yes</packet-capture>")!== false) AND ($type!="virus")){
                                    $xmlfield = str_replace("<packet-capture>yes</packet-capture>", "<packet-capture>single-packet</packet-capture>", $xmlfield);
                                }
                                if ((strpos($xmlfield,"<packet-capture>no</packet-capture>")!== false) AND ($type!="virus")){
                                    $xmlfield = str_replace("<packet-capture>no</packet-capture>", "<packet-capture>disable</packet-capture>", $xmlfield);
                                }
                            }
                            if ($version >= 7) {
                                if ((strpos($xmlfield,"<action>block</action>")!== false) AND ($type == "virus")){
                                    $xmlfield = str_replace("<action>block</action>", "<action>drop</action>", $xmlfield);
                                }
                                if ((strpos($xmlfield,"<wildfire-action>block</wildfire-action>")!== false) AND ($type == "virus")){
                                    $xmlfield = str_replace("<wildfire-action>block</wildfire-action>", "<wildfire-action>drop</wildfire-action>", $xmlfield);
                                }
                                //if ((strpos($xmlfield,"<block/>")!== false) AND ($type == "spyware")){
                                //    $xmlfield = str_replace("<block/>", "<drop/>", $xmlfield);
                                //}
                                if ((strpos($xmlfield,"<block/>")!== false) AND ($type == "vulnerability")){
                                    $xmlfield = str_replace("<block/>", "<drop/>", $xmlfield);
                                }
                                /* SE TENDRÁ QUE HACER INSERT EN LA TABLA DE OUTPUT MAPPING EN EL CAMPO ERROR MESSAGE Y QUE SALGA EN EL + --> PENSAR COMO HACERLO */
                                if ((strpos($xmlfield,"<action>forward</action>")!== false) AND ($type == "file-blocking")){
                                    $xmlfield = str_replace("<action>forward</action>", "", $xmlfield);
                                }
                                if ((strpos($xmlfield,"<action>continue-and-forward</action>")!== false) AND ($type == "file-blocking")){
                                    $xmlfield = str_replace("<action>continue-and-forward</action>", "", $xmlfield);
                                }

                            }
                            $xml_append = simplexml_load_string($xmlfield);
                            if ($xml->xpath("/config/shared/profiles/entry[@name='$xmlname']") != null) {
                                add_log('warning', 'Exporting Shared Profiles', 'Object Duplicated in Destination [' . $xmlname . ']', $source, 'Object was Not Migrated');
                            } else {
                                SimpleXMLElement_append($xml->shared->profiles->$type, $xml_append);
                            }
                        }
                    }
                }
            } 
            else {
                #DELETE SHARED LOG SETTINGS
                $SA = $xml->xpath("/config/shared/profiles");
                unset($SA[0][0]);
                //$xml->shared->addChild('profiles');
            }

            # SHARED PROFILES GROUPS
            $getShared = $projectdb->query("SELECT name,xml FROM shared_profiles_groups WHERE source='$source' AND dummy = 0 ORDER BY id;");
            if ($getShared->num_rows > 0) {

                if (!isset($xml->shared->{'profile-group'})) {
                    $xml->shared->addChild('profile-group');
                } else {
                    #DELETE SHARED APPLICATIONS FILTERS
                    $SA = $xml->xpath("/config/shared/profile-group");
                    unset($SA[0][0]);
                    $xml->shared->addChild('profile-group');
                }
                $theProfiles2 = $xml->xpath("/config/shared/profile-group");
                $theProfiles = $theProfiles2[0];
                while ($data2 = $getShared->fetch_assoc()) {
                    $xmlfield = $data2['xml'];
                    $xmlname = $data2['name'];
                    $xml_append = simplexml_load_string($xmlfield);
                    SimpleXMLElement_append($theProfiles, $xml_append);
                    
                }
            } 
            else {
                #DELETE SHARED APPLICATIONS FILTERS
                $SA = $xml->xpath("/config/shared/profile-group");
                unset($SA[0][0]);
                //$xml->shared->addChild('profile-group');
            }

            # SHARED ADDRESS GROUPS
            $getShared = $projectdb->query("SELECT name,id,tag,filter,type,description FROM shared_address_groups_id WHERE source='$source';");
            if ($getShared->num_rows > 0) {
                if (!isset($xml->shared->{'address-group'})) {
                    $xml->shared->addChild('address-group');
                } else {
                    #DELETE SHARED ADDRESS GROUPS
                    $SA = $xml->xpath("/config/shared/address-group");
                    unset($SA[0][0]);
                    $xml->shared->addChild('address-group');
                }
                while ($Data = $getShared->fetch_assoc()) {
                    $groupName = $Data['name'];
                    $lid = $Data['id'];
                    $myname = $Data['name'];
                    if ($xml->xpath("/config/shared/address-group/entry[@name='$myname']") == null) {
                        $getMembers = $projectdb->query("SELECT table_name,member_lid FROM shared_address_groups WHERE source='$source' and lid='$lid'");

                        if ($getMembers->num_rows > 0) {
                            $service = $xml->shared->{'address-group'}->addChild('entry');
                            $service->addAttribute('name', $Data['name']);
                            if (($version >= 6) AND ( $Data['type'] == "static")) {
                                $service2 = $service->addChild('static');
                            } elseif ($version < 6) {
                                $service2 = $service;
                            }
                            while ($Datas = $getMembers->fetch_assoc()) {
                                $table_name = $Datas['table_name'];
                                $member_lid = $Datas['member_lid'];
                                $getName = $projectdb->query("SELECT name FROM $table_name WHERE source='$source' and id='$member_lid'");
                                if ($getName->num_rows==1){
                                    $Datas2 = $getName->fetch_assoc();
                                    $member = $service2->addChild('member', $Datas2['name']);
                                }    
                            }
                        } else {
                            $service = $xml->shared->{'address-group'}->addChild('entry');
                            $service->addAttribute('name', $Data['name']);
                            if (($version >= 6) AND ( $Data['type'] == "dynamic")) {
                                $service2 = $service->addChild('dynamic');
                                $filter = str_replace("<br>", "\n", $Data['filter']);
                                $service2 = $service->dynamic->addChild('filter', $filter);
                            }
                        }
                        if ($Data['description'] != "") {
                            $service->addChild('description');
                            $service->description = $Data['description'];
                        }
                        if ($Data['tag'] != "") {
                            $tags = explode(",", $Data['tag']);
                            $shtag = $service->addChild('tag');
                            foreach ($tags as $kkey => $vvalue) {
                                $shtag->addChild('member', $vvalue);
                            }
                        }
                    } else {
                        add_log('warning', 'Exporting Shared Address Groups', 'Object Duplicated in Destination [' . $myname . ']', $source, 'Object was Not Migrated');
                    }
                }
            } 
            else {
                #DELETE SHARED ADDRESS GROUPS
                $SA = $xml->xpath("/config/shared/address-group");
                unset($SA[0][0]);
                //$xml->shared->addChild('address-group');
            }

            # SHARED TAGS
            $getShared = $projectdb->query("SELECT name,color,comments FROM shared_tag WHERE source='$source' AND dummy = 0;");
            if (($version >= 6) AND ( $getShared->num_rows > 0)) {
                if (!isset($xml->shared->tag)) {
                    $xml->shared->addChild('tag');
                } else {
                    #DELETE SHARED TAGS
                    $SA = $xml->xpath("/config/shared/tag");
                    unset($SA[0][0]);
                    $xml->shared->addChild('tag');
                }
                $theProfiles = $xml->shared->tag;
                while ($tag = $getShared->fetch_assoc()) {
                    $tagName = $tag['name'];
                    $newtag = $theProfiles->addChild('entry');
                    $newtag->addAttribute('name', $tagName);
                    if (($tag['color'] != "") AND ( $tag['color'] != "None")) {
                        $newtag->addChild('color', $tag['color']);
                    }
                    if ($tag['comments'] != "") {
                        $newtag->addChild('comments', $tag['comments']);
                    }
                }
            } 
            elseif (($version >= 6) AND ( $getShared->num_rows == 0)) {
                #DELETE SHARED TAGS
                $SA = $xml->xpath("/config/shared/tag");
                unset($SA[0][0]);
                //$xml->shared->addChild('tag');
            }

            # SHARED SERVICES
            $getShared = $projectdb->query("SELECT name,dport,sport,protocol,tag,description FROM shared_services WHERE source='$source' AND dummy=0 AND (protocol = 'tcp' or protocol = 'udp') AND (name <> 'application-default' AND name <> 'service-http' AND name <> 'service-https');");
            if ($getShared->num_rows > 0) {
                if (!isset($xml->shared->service)) {
                    $xml->shared->addChild('service');
                } else {
                    #DELETE SHARED SERVICES
                    $SA = $xml->xpath("/config/shared/service");
                    unset($SA[0][0]);
                    $xml->shared->addChild('service');
                }
                while ($Data = $getShared->fetch_assoc()) {
                    $myname = $Data['name'];
                    if ($xml->xpath("/config/shared/service/entry[@name='$myname']") == null) {
                        $service = $xml->shared->service->addChild('entry');
                        $service->addAttribute('name', $Data['name']);
                        $protocol = $service->addChild('protocol');
                        $port = $protocol->addChild($Data['protocol']);
                        $port->addChild('port', $Data['dport']);
                        if (($Data['sport'] != NULL) or ( $Data['sport'] != "")) {
                            $port->addChild('source-port', $Data['sport']);
                        }
                        if ($Data['description'] != "") {
                            $protocol = $service->addChild('description');
                            $service->description = $Data['description'];
                        }
                        if (($version >= 6) AND ( $Data['tag'] != "")) {
                            $tags = $service->addChild('tag');
                            $mytags = explode(",", $Data['tag']);
                            foreach ($mytags as $key => $value) {
                                $tags->addChild('member', $value);
                            }
                        }
                    } else {
                        add_log('warning', 'Exporting Shared Services', 'Object Duplicated in Destination [' . $myname . ']', $source, 'Object was Not Migrated');
                    }
                }
            } 
            else {
                #DELETE SHARED SERVICES
                $SA = $xml->xpath("/config/shared/service");
                unset($SA[0][0]);
                //$xml->shared->addChild('service');
            }

            # SHARED SERVICES GROUPS
            $getShared = $projectdb->query("SELECT name,id,tag FROM shared_services_groups_id WHERE source='$source';");
            if ($getShared->num_rows > 0) {
                if (!isset($xml->shared->{'service-group'})) {
                    $xml->shared->addChild('service-group');
                } else {
                    #DELETE SHARED ADDRESS GROUPS
                    $SA = $xml->xpath("/config/shared/service-group");
                    unset($SA[0][0]);
                    $xml->shared->addChild('service-group');
                }
                while ($Data = $getShared->fetch_assoc()) {
                    $groupName = $Data['name'];
                    $lid = $Data['id'];
                    $myname = $Data['name'];
                    if ($xml->xpath("/config/shared/service-group/entry[@name='$myname']") == null) {
                        $getMembers = $projectdb->query("SELECT table_name,member_lid FROM shared_services_groups WHERE source='$source' and lid='$lid'");
                        if ($getMembers->num_rows > 0) {
                            $service = $xml->shared->{'service-group'}->addChild('entry');
                            $service->addAttribute('name', $Data['name']);
                            if ($version >= 6) {
                                $service2 = $service->addChild('members');
                            } elseif ($version < 6) {
                                $service2 = $service;
                            }
                            while ($Datas = $getMembers->fetch_assoc()) {
                                $table_name = $Datas['table_name'];
                                $member_lid = $Datas['member_lid'];
                                $getName = $projectdb->query("SELECT name FROM $table_name WHERE id='$member_lid'");
                                if ($getName->num_rows==1){
                                    $Datas2 = $getName->fetch_assoc();
                                    $member = $service2->addChild('member', $Datas2['name']);
                                }    
                            }
                            if (($version >= 6) AND ( $Data['tag'] != "")) {
                                $tags = $service->addChild('tag');
                                $mytags = explode(",", $Data['tag']);
                                foreach ($mytags as $key => $value) {
                                    $tags->addChild('member', $value);
                                }
                            }
                        }
                    } else {
                        add_log('warning', 'Exporting Shared Services Groups', 'Object Duplicated in Destination [' . $myname . ']', $source, 'Object was Not Migrated');
                    }
                }
            } 
            else {
                #DELETE SHARED ADDRESS GROUPS
                $SA = $xml->xpath("/config/shared/service-group");
                unset($SA[0][0]);
                //$xml->shared->addChild('service-group');
            }

            # SHARED EXTERNAL-LISTS
            $getShared = $projectdb->query("SELECT name,xml FROM shared_external_list WHERE source='$source' GROUP BY name ORDER BY id;");
            if ($getShared->num_rows > 0) {

                if (!isset($xml->shared->{'external-list'})) {
                    $xml->shared->addChild('external-list');
                } else {
                    #DELETE SHARED EXTERNAL-LISTS
                    $SA = $xml->xpath("/config/shared/external-list");
                    unset($SA[0][0]);
                    $xml->shared->addChild('external-list');
                }
                $theProfiles2 = $xml->xpath("/config/shared/external-list");
                $theProfiles = $theProfiles2[0];
                while ($data2 = $getShared->fetch_assoc()) {
                    $xmlfield = $data2['xml'];
                    $xmlname = $data2['name'];
                    $xml_append = simplexml_load_string($xmlfield);
                    SimpleXMLElement_append($theProfiles, $xml_append);
                }
            } 
            else {
                #DELETE SHARED EXTERNAL-LISTS
                $SA = $xml->xpath("/config/shared/external-list");
                unset($SA[0][0]);
                //$xml->shared->addChild('external-list');
            }

            # SHARED REGIONS
            $getShared = $projectdb->query("SELECT name,xml,address,latitude,longitude FROM shared_regions WHERE source='$source' ORDER BY id;");
            if ($getShared->num_rows > 0) {

                if (!isset($xml->shared->region)) {
                    $xml->shared->addChild('region');
                } else {
                    #DELETE SHARED EXTERNAL-LISTS
                    $SA = $xml->xpath("/config/shared/region");
                    unset($SA[0][0]);
                    $xml->shared->addChild('region');
                }
                $theProfiles2 = $xml->xpath("/config/shared/region");
                $theProfiles = $theProfiles2[0];
                while ($data2 = $getShared->fetch_assoc()) {
                    $xmlfield = $data2['xml'];
                    $xmlname = $data2['name'];
                    $regionMembers=$data2['address'];
                    $latitude=$data2['latitude'];
                    $longitude=$data2['longitude'];
                    if ($theProfiles->xpath("//entry[@name='$xmlname']") != null) {
                        add_log('warning', 'Exporting Shared Regions', 'Object Duplicated in Destination [' . $xmlname . ']', $source, 'Object was Not Migrated');
                    } else {
                        $newRegion=$theProfiles->addChild("entry");
                        $newRegion->addAttribute('name', $xmlname);
                        if ($regionMembers!=""){
                            $newRegion->addChild("address");
                            $regionMembersArray=explode(",",$regionMembers);
                            foreach ($regionMembersArray as $regionMembersValue){
                                $newRegion->address->addChild("member",$regionMembersValue);
                            }
                        }
                        if (($longitude!="") AND ($latitude!="")){
                            $newRegion->addChild("geo-location");
                            $newRegion->{'geo-location'}->addChild("latitude",$latitude);
                            $newRegion->{'geo-location'}->addChild("longitude",$longitude);
                        }
                        //SimpleXMLElement_append($theProfiles, $xml_append);
                    }
                }
            } 
            else {
                #DELETE SHARED REGIONS
                $SA = $xml->xpath("/config/shared/region");
                unset($SA[0][0]);
                //$xml->shared->addChild('region');
            }

            # SHARED APPLICATIONS
            $getShared = $projectdb->query("SELECT id,name,description,spyware_ident,category,subcategory,parent_app,risk,technology,evasive_behavior,consume_big_bandwidth,used_by_malware,able_to_transfer_file,has_known_vulnerability,tunnel_other_application,tunnel_applications,prone_to_misuse,pervasive_use,file_type_ident,virus_ident,data_ident,default_type,value,type,code,timeout,tcp_timeout,udp_timeout,tcp_half_closed_timeout,tcp_time_wait_timeout FROM shared_applications WHERE source='$source' AND dummy=0 ORDER BY id;");
            if ($getShared->num_rows > 0) {
                if (!isset($xml->shared->application)) {
                    $xml->shared->addChild('application');
                } else {
                    #DELETE SHARED EXTERNAL-LISTS
                    $SA = $xml->xpath("/config/shared/application");
                    unset($SA[0][0]);
                    $xml->shared->addChild('application');
                }

                while ($data2 = $getShared->fetch_object()) {
                    $appid = $data2->id;
                    $myname = $data2->name;
                    if ($xml->xpath("/config/shared/application/entry[@name='$myname']") == null) {
                        $application = $xml->shared->application->addChild('entry');
                        $application->addAttribute('name', $myname);
                        if ($data2->description != "") {
                            $application->addChild('description');
                            $application->description = $data2->description;
                        }
                        if ($data2->category != "") {
                            $application->addChild('category', $data2->category);
                        }
                        if ($data2->subcategory != "") {
                            $application->addChild('subcategory', $data2->subcategory);
                        }
                        if ($data2->risk != "") {
                            $application->addChild('risk', $data2->risk);
                        }
                        if ($data2->technology != "") {
                            $application->addChild('technology', $data2->technology);
                        }
                        if ($data2->evasive_behavior != "") {
                            $application->addChild('evasive-behavior', $data2->evasive_behavior);
                        }
                        if ($data2->consume_big_bandwidth != "") {
                            $application->addChild('consume-big-bandwidth', $data2->consume_big_bandwidth);
                        }
                        if ($data2->used_by_malware != "") {
                            $application->addChild('used-by-malware', $data2->used_by_malware);
                        }
                        if ($data2->able_to_transfer_file != "") {
                            $application->addChild('able-to-transfer-file', $data2->able_to_transfer_file);
                        }
                        if ($data2->has_known_vulnerability != "") {
                            $application->addChild('has-known-vulnerability', $data2->has_known_vulnerability);
                        }
                        if ($data2->tunnel_other_application != "") {
                            $application->addChild('tunnel-other-application', $data2->tunnel_other_application);
                        }
                        if ($data2->tunnel_applications != "") {
                            $application->addChild('tunnel-applications', $data2->tunnel_applications);
                        }
                        if ($data2->prone_to_misuse != "") {
                            $application->addChild('prone-to-misuse', $data2->prone_to_misuse);
                        }
                        if ($data2->pervasive_use != "") {
                            $application->addChild('pervasive-use', $data2->pervasive_use);
                        }
                        if ($data2->file_type_ident != "") {
                            $application->addChild('file-type-ident', $data2->file_type_ident);
                        }
                        if ($data2->virus_ident != "") {
                            $application->addChild('virus-ident', $data2->virus_ident);
                        }
                        if ($data2->data_ident != "") {
                            $application->addChild('data-ident', $data2->data_ident);
                        }
                        if ($version < 6) {
                            if ($data2->spyware_ident != "") {
                                $application->addChild('spyware-ident', $data2->spyware_ident);
                            }
                        }
                        if (($data2->parent_app != "None") AND ($data2->parent_app!="")){
                            $application->addChild('parent-app', $data2->parent_app);
                        }
                        if ($data2->timeout > 0) {
                            $application->addChild('timeout', $data2->timeout);
                        }
                        if ($data2->tcp_timeout > 0) {
                            $application->addChild('tcp-timeout', $data2->tcp_timeout);
                        }
                        if ($data2->udp_timeout > 0) {
                            $application->addChild('udp-timeout', $data2->udp_timeout);
                        }
                        if($version >= 6){
                            if ($data2->tcp_half_closed_timeout > 0) {
                                $application->addChild('tcp-half-closed-timeout', $data2->tcp_half_closed_timeout);
                            }
                            if ($data2->tcp_time_wait_timeout > 0) {
                                $application->addChild('tcp-time-wait-timeout', $data2->tcp_time_wait_timeout);
                            }
                        }
                        if ($data2->default_type == "port") {
                            $default = $application->addChild('default');
                            $port = $default->addChild('port');
                            $ports = explode(",", $data2->value);
                            foreach ($ports as $kkey => $vvalue) {
                                $port->addChild('member', $vvalue);
                            }
                        } elseif ($data2->default_type == "ident-by-ip-protocol") {
                            $default = $application->addChild('default');
                            $port = $default->addChild('ident-by-ip-protocol', $data2->value);
                        } elseif ($data2->default_type == "ident-by-icmp-type") {
                            if($version < 7){
                                $default = $application->addChild('default');
                                $port = $default->addChild('ident-by-icmp-type', $data2->type);
                            }else{
                                $default = $application->addChild('default');
                                $port = $default->addChild('ident-by-icmp-type');
                                $port->addChild('type', $data2->type);
                                $port->addChild('code', $data2->code);
                            }
                        } elseif ($data2->default_type == "ident-by-icmp6-type") {
                            $default = $application->addChild('default');
                            $port = $default->addChild('ident-by-icmp6-type');
                            $port->addChild('code', $data2->code);
                            $port->addChild('type', $data2->type);
                        } elseif ($data2->default_type == "None") {
                            
                        }

                        $getSignature = $projectdb->query("SELECT signature FROM applications_signatures WHERE source='$source' AND member_lid='$appid' AND table_name='shared_applications';");
                        if ($getSignature->num_rows > 0) {
                            $application->addChild('signature');
                            $sig = $application->signature;
                            while ($data3 = $getSignature->fetch_assoc()) {
                                $xml_append = simplexml_load_string($data3['signature']);
                                SimpleXMLElement_append($sig, $xml_append);
                            }
                        }
                    }
                }
            } 
            else {
                #DELETE SHARED EXTERNAL-LISTS
                $SA = $xml->xpath("/config/shared/application");
                unset($SA[0][0]);
                //$xml->shared->addChild('application');
            }

            # APPLICATIONS FILTERS
            $getShared = $projectdb->query("SELECT id,name,category,subcategory,risk,technology,evasive_behavior,consume_big_bandwidth,used_by_malware,able_to_transfer_file,has_known_vulnerability,tunnel_other_application,prone_to_misuse,pervasive_use FROM shared_applications_filters WHERE source='$source' ORDER BY id;");
            if ($getShared->num_rows > 0) {

                if (!isset($xml->shared->{'application-filter'})) {
                    $xml->shared->addChild('application-filter');
                } else {
                    #DELETE SHARED EXTERNAL-LISTS
                    $SA = $xml->xpath("/config/shared/application-filter");
                    unset($SA[0][0]);
                    $xml->shared->addChild('application-filter');
                }
                
                while ($data2 = $getShared->fetch_object()) {
                    $appid = $data2->id;
                    $myname = $data2->name;
                    
                    if ($xml->xpath("/config/shared/application-filter/entry[@name='$myname']") == null) {
                        $application_filters = $xml->shared->{'application-filter'}->addChild('entry');
                        $application_filters->addAttribute('name', $myname);
                        if ($data2->description != "") {
                            $application_filters->addChild('description');
                            $application_filters->description = $data2->description;
                        }
                        if($data2->category != ""){
                            $category = $application_filters->addChild('category');
                            $category_s = explode(",", $data2->category);
                            foreach ($category_s as $kkey => $vvalue) {
                                $category->addChild('member', $vvalue);
                            }
                        }
                        if($data2->subcategory != ""){
                            $subcategory = $application_filters->addChild('subcategory');
                            $subcategory_s = explode(",", $data2->subcategory);
                            foreach ($subcategory_s as $kkey => $vvalue) {
                                $subcategory->addChild('member', $vvalue);
                            }
                        }
                        if($data2->risk != ""){
                            $risk = $application_filters->addChild('risk');
                            $risk_s = explode(",", $data2->risk);
                            foreach ($risk_s as $kkey => $vvalue) {
                                $risk->addChild('member', $vvalue);
                            }
                        }
                        if($data2->technology != ""){
                            $technology = $application_filters->addChild('technology');
                            $technology_s = explode(",", $data2->technology);
                            foreach ($technology_s as $kkey => $vvalue) {
                                $technology->addChild('member', $vvalue);
                            }
                        }
                        if ($data2->evasive_behavior != "") {
                            $application_filters->addChild('evasive', $data2->evasive_behavior);
                        }
                        if ($data2->consume_big_bandwidth != "") {
                            $application_filters->addChild('excessive-bandwidth-use', $data2->consume_big_bandwidth);
                        }
                        if ($data2->used_by_malware != "") {
                            $application_filters->addChild('used-by-malware', $data2->used_by_malware);
                        }
                        if ($data2->able_to_transfer_file != "") {
                            $application_filters->addChild('transfers-files', $data2->able_to_transfer_file);
                        }
                        if ($data2->has_known_vulnerability != "") {
                            $application_filters->addChild('has-known-vulnerabilities', $data2->has_known_vulnerability);
                        }
                        if ($data2->tunnel_other_application != "") {
                            $application_filters->addChild('tunnels-other-apps', $data2->tunnel_other_application);
                        }
                        if ($data2->prone_to_misuse != "") {
                            $application_filters->addChild('prone-to-misuse', $data2->prone_to_misuse);
                        }
                        if ($data2->pervasive_use != "") {
                            $application_filters->addChild('pervasive', $data2->pervasive_use);
                        }
                    }
                }
            } else {
                
                $SA = $xml->xpath("/config/shared/application-filter");
                unset($SA[0][0]);
                
            }

            # SHARED APPLICATIONS GROUPS
            $getShared = $projectdb->query("SELECT name,id FROM shared_applications_groups_id WHERE source='$source';");
            if ($getShared->num_rows > 0) {
                if (!isset($xml->shared->{'application-group'})) {
                    $xml->shared->addChild('application-group');
                } else {
                    #DELETE SHARED ADDRESS GROUPS
                    $SA = $xml->xpath("/config/shared/application-group");
                    unset($SA[0][0]);
                    $xml->shared->addChild('application-group');
                }
                while ($Data = $getShared->fetch_assoc()) {
                    $groupName = $Data['name'];
                    $lid = $Data['id'];
                    $myname = $Data['name'];
                    if ($xml->xpath("/config/shared/application-group/entry[@name='$myname']") == null) {
                        $getMembers = $projectdb->query("SELECT table_name,member_lid FROM shared_applications_groups WHERE source='$source' and lid='$lid'");
                        if ($getMembers->num_rows > 0) {
                            $service = $xml->shared->{'application-group'}->addChild('entry');
                            $service->addAttribute('name', $Data['name']);
                            if ($version >= 7) {
                                $service2 = $service->addChild('members');
                            } elseif ($version < 7) {
                                $service2 = $service;
                            }
                            while ($Datas = $getMembers->fetch_assoc()) {
                                $table_name = $Datas['table_name'];
                                $member_lid = $Datas['member_lid'];
                                $getName = $projectdb->query("SELECT name FROM $table_name WHERE id='$member_lid'");
                                if ($getName->num_rows==1){
                                    $Datas2 = $getName->fetch_assoc();
                                    $member = $service2->addChild('member', $Datas2['name']);
                                }    
                            }
                        }
                    } else {
                        add_log('warning', 'Exporting Shared Applications Groups', 'Object Duplicated in Destination [' . $myname . ']', $source, 'Object was Not Migrated');
                    }
                }
            } 
            else {
                #DELETE SHARED ADDRESS GROUPS
                $SA = $xml->xpath("/config/shared/application-group");
                unset($SA[0][0]);
                //$xml->shared->addChild('service-group');
            }
                    
            # RESPONSE-PAGES
            if ($ispanorama==0){
                $getShared = $projectdb->query("SELECT name,type,html FROM shared_response_pages WHERE source='$source' ORDER BY id;");
                if ($getShared->num_rows > 0) {
                    if (!isset($xml->shared->{'response-page'})) {
                        $xml->shared->addChild('response-page');
                    }
                    $theProfiles2 = $xml->shared->xpath("response-page");
                    $theProfiles = $theProfiles2[0];
                    while ($data2 = $getShared->fetch_assoc()) {
                        $xmlfield = $data2['html'];
                        $xmlname = $data2['type'];
                        $reportname = $data2['name'];
                        if ($reportname != "") {
                            if (!isset($theProfiles->$xmlname)) {
                                $theProfiles->addChild($xmlname);
                                $newrp = $theProfiles->$xmlname->addChild("entry");
                                $newrp->addAttribute('name', $reportname);
                                $newrp->addChild("page");
                                $newrp->page = $xmlfield;
                            } else {
                                if ($theProfiles->$xmlname->xpath("entry[@name='$reportname']") !== null) {
                                    $SA = $theProfiles->$xmlname->xpath("entry[@name='$reportname']");
                                    unset($SA[0][0]);
                                }
                                $newrp = $theProfiles->$xmlname->addChild("entry");
                                $newrp->addAttribute('name', $reportname);
                                $newrp->addChild("page");
                                $newrp->page = $xmlfield;
                            }
                        } else {
                            $SA = $xml->shared->xpath("response-page/$xmlname");
                            unset($SA[0][0]);
                            #$xml_append = simplexml_load_string($xmlfield);
                            $xml_append = simplexml_load_string("<$xmlname>$xmlfield</$xmlname>");
                            SimpleXMLElement_append($theProfiles, $xml_append);
                        }
                    }
                }
                else {
                    $SA = $xml->xpath("/config/shared/response-page");
                    unset($SA[0][0]);
                }
            }
            # SHARED REPORTS
            $getShared = $projectdb->query("SELECT id,name,type,period,topn,topm,caption,starttime,endtime,query,frequency FROM reports WHERE source='$source' AND vsys='shared' ORDER BY id;");
            if ($getShared->num_rows > 0) {
                if (!isset($xml->shared->reports)) {
                    $xml->shared->addChild('reports');
                }
                $theProfiles2 = $xml->shared->xpath("reports");
                $theProfiles = $theProfiles2[0];
                while ($data2 = $getShared->fetch_assoc()) {
                    $reportname = $data2['name'];
                    $reporttype=$data2['type'];
                    $reportperiod=$data2['period'];
                    $reporttopn=$data2['topn'];
                    $reporttopm=$data2['topm'];
                    $reportcaption=$data2['caption'];
                    $reportstarttime=$data2['starttime'];
                    $reportendtime=$data2['endtime'];
                    $reportquery=$data2['query'];
                    $reportfrequency=$data2['frequency'];
                    
                    if ($reportname != "") {
                        if ($theProfiles->xpath("//entry[@name='$reportname']") == null) {
                            $report = $theProfiles->addChild('entry');
                            $report->addAttribute('name', $reportname);
                            if ($reporttype!=""){
                                $xml_append = simplexml_load_string($reporttype);
                                SimpleXMLElement_append($report, $xml_append);
                            }
                            if ($reportcaption!=""){
                                $report->addChild("caption");
                                $report->caption=$reportcaption;
                            }
                            if ($reportperiod!=""){
                                $report->addChild("period");
                                $report->period=$reportperiod;
                            }
                            else{
                                $report->addChild("start-time");
                                $report->{'start-time'}=$reportstarttime;
                                $report->addChild("end-time");
                                $report->{'end-time'}=$reportendtime;
                            }
                            if ($reporttopn!=""){
                                $report->addChild("topn");
                                $report->topn=$reporttopn;
                            }
                            if ($reporttopm!=""){
                                $report->addChild("topm");
                                $report->topm=$reporttopm;
                            }
                            if ($reportquery!=""){
                                $report->addChild("query");
                                $report->query=$reportquery;
                            }
                            if ($reportfrequency!=""){
                                $report->addChild("frequency");
                                $report->frequency=$reportfrequency;
                            }
                        }
                        
                        
                        
                    } 
                    
                }
            }
            else{
                $SA = $xml->xpath("/config/shared/reports");
                unset($SA[0][0]);
            }
            
            # SHARED POLICIES
            if ($ispanorama == 1) {
                update_progress($project, '0.20', 'Loading Shared Rules');
                #POLICIES
                $policies = array("pre-rulebase", "post-rulebase");
                $vsys = "shared";
                foreach ($policies as $pkey => $pvalue) {
                    if (($pvalue == "pre-rulebase") OR ( $pvalue == "rulebase")) {
                        $preorpost = 0;
                    } elseif ($pvalue == "post-rulebase") {
                        $preorpost = 1;
                    }

                    $xpath0 = $xml->xpath("/config/shared");
                    $xpath = $xpath0[0];

                    # SECURITY

                    $getPolicies = $projectdb->query("SELECT icmp_unreachable,rule_type,id,position,name,negate_source,negate_destination,description,action,schedule,disabled,log_start,log_end,log_forwarding,lid,dsri,target,qos,profile_type,qos_value,tag FROM security_rules WHERE source='$source' AND vsys='$vsys' AND preorpost='$preorpost' ORDER BY position ASC;");
                    if ($getPolicies->num_rows > 0) {
                        if (!isset($xpath->{$pvalue})) {
                            $xpath->addChild($pvalue);
                        }

                        if (!isset($xpath->{$pvalue}->security)) {
                            $xpath->{$pvalue}->addChild('security');
                        }
                        
                        if (!isset($xpath->{$pvalue}->security->rules)) {
                            $xpath->{$pvalue}->security->addChild('rules');
                        } else {
                            #DELETE RULES
                            $SA = $xpath->$pvalue->security->xpath("rules");
                            unset($SA[0][0]);
                            $xpath->{$pvalue}->security->addChild('rules');
                        }

                        while ($data2 = $getPolicies->fetch_object()) {
                            $myname = $data2->name;
                            $lid = $data2->id;
                            if ($xpath->xpath("/$pvalue/security/rules/entry[@name='$myname']") == null) {
                                $rule = $xpath->$pvalue->security->rules->addChild('entry');
                                $rule->addAttribute('name', $myname);
                                if ($version > 6.0) {
                                    if ($data2->rule_type != "universal") {
                                        $rule->addChild("rule-type", $data2->rule_type);
                                    }
                                }
                                if ($data2->dsri == 0) {
                                    $dsri = "no";
                                } else {
                                    $dsri = "yes";
                                }
                                if ($dsri!="no"){
                                    $rule->addChild('option');
                                    $rule->option->addChild('disable-server-response-inspection', $dsri);
                                }
                                if ($version>=7){
                                    if ($data2->icmp_unreachable!=""){
                                        $rule->addChild('icmp-unreachable',$data2->icmp_unreachable);
                                    }
                                }
                                $getFrom = $projectdb->query("SELECT name FROM security_rules_from WHERE rule_lid='$lid';");
                                if ($getFrom->num_rows > 0) {
                                    $rule->addChild('from');
                                    while ($k = $getFrom->fetch_object()) {
                                        $rule->from->addChild('member', $k->name);
                                    }
                                } else {
                                    $rule->addChild('from');
                                    $rule->from->addChild('member', 'any');
                                }
                                $getTo = $projectdb->query("SELECT name FROM security_rules_to WHERE rule_lid='$lid';");
                                if ($getTo->num_rows > 0) {
                                    $rule->addChild('to');
                                    while ($k = $getTo->fetch_object()) {
                                        $rule->to->addChild('member', $k->name);
                                    }
                                } else {
                                    $rule->addChild('to');
                                    $rule->to->addChild('member', 'any');
                                }
                                $getSource = $projectdb->query("SELECT member_lid,table_name FROM security_rules_src WHERE rule_lid='$lid';");
                                if ($getSource->num_rows > 0) {
                                    $rule->addChild('source');
                                    while ($k = $getSource->fetch_object()) {
//                                        if (($k->table_name == "regions") OR ( $k->table_name == "shared_regions") OR ( $k->table_name == "default_regions") OR ( $k->table_name == "external_list") OR ( $k->table_name == "shared_external_list")) {
//                                            $thename = "name";
//                                        } else {
//                                            $thename = "name";
//                                        }
//                                        if ($k->table_name == "default_regions") {
//                                            $getMember = $projectdb->query("SELECT $thename FROM $k->table_name WHERE id='$k->member_lid';");
//                                        } else {
//                                            $getMember = $projectdb->query("SELECT $thename FROM $k->table_name WHERE id='$k->member_lid';");
//                                        }
                                        $getMember = $projectdb->query("SELECT name FROM $k->table_name WHERE id='$k->member_lid';");
                                        if ($getMember->num_rows > 0) {
                                            while ($kk = $getMember->fetch_object()) {
                                                $rule->source->addChild('member', $kk->name);
                                            }
                                        }
                                    }
                                } else {
                                    $rule->addChild('source');
                                    $rule->source->addChild('member', 'any');
                                }
                                $getDestination = $projectdb->query("SELECT member_lid,table_name FROM security_rules_dst WHERE rule_lid='$lid' ;");
                                if ($getDestination->num_rows > 0) {
                                    $rule->addChild('destination');
                                    while ($k = $getDestination->fetch_object()) {
                                        $getMember = $projectdb->query("SELECT name FROM $k->table_name WHERE id='$k->member_lid';");
                                        if ($getMember->num_rows > 0) {
                                            while ($kk = $getMember->fetch_object()) {
                                                $rule->destination->addChild('member', $kk->name);
                                            }
                                        }
                                    }
                                } else {
                                    $rule->addChild('destination');
                                    $rule->destination->addChild('member', 'any');
                                }
                                $getUser = $projectdb->query("SELECT name FROM security_rules_usr WHERE rule_lid='$lid';");
                                if ($getUser->num_rows > 0) {
                                    $rule->addChild('source-user');
                                    while ($k = $getUser->fetch_object()) {
                                        $rule->{'source-user'}->addChild('member',htmlentities($k->name));
                                        //$rule_user->member = addslashes($k['name']);
                                        //$rule_user0 = $k['name'];
                                    }
                                } else {
                                    $rule->addChild('source-user');
                                    $rule->{'source-user'}->addChild('member', 'any');
                                }
                                $getAPP = $projectdb->query("SELECT member_lid,table_name FROM security_rules_app WHERE rule_lid='$lid';");
                                if ($getAPP->num_rows > 0) {
                                    $rule->addChild('application');
                                    while ($k = $getAPP->fetch_object()) {
                                        $thesql = "SELECT name FROM " . $k->table_name . " WHERE id='" . $k->member_lid . "';";
                                        $getMember = $projectdb->query($thesql);
                                        if ($getMember->num_rows > 0) {
                                            while ($kk = $getMember->fetch_object()) {
                                                $rule->{'application'}->addChild('member', $kk->name);
                                            }
                                        }
                                    }
                                } else {
                                    $rule->addChild('application');
                                    $rule->{'application'}->addChild('member', 'any');
                                }
                                $getSRV = $projectdb->query("SELECT member_lid,table_name FROM security_rules_srv WHERE rule_lid='$lid';");
                                if ($getSRV->num_rows > 0) {
                                    $rule->addChild('service');
                                    while ($k = $getSRV->fetch_object()) {
                                        $getMember = $projectdb->query("SELECT name FROM $k->table_name WHERE id='$k->member_lid';");
                                        if ($getMember->num_rows > 0) {
                                            while ($kk = $getMember->fetch_object()) {
                                                $rule->{'service'}->addChild('member', $kk->name);
                                            }
                                        }
                                    }
                                } else {
                                    $rule->addChild('service');
                                    $rule->{'service'}->addChild('member', 'any');
                                }
                                $getHIP = $projectdb->query("SELECT member_lid,table_name,name FROM security_rules_hip WHERE rule_lid='$lid';");
                                if ($getHIP->num_rows > 0) {
                                    $rule->addChild('hip-profiles');
                                    while ($k = $getHIP->fetch_object()) {
                                        if (($k->member_lid == 0) AND ( $k->table_name == "default")) {
                                            $rule->{'hip-profiles'}->addChild('member', $k->name);
                                        } else {
                                            $getMember = $projectdb->query("SELECT name FROM $k->table_name WHERE id='$k->member_lid' AND type='hip-profiles';");
                                            if ($getMember->num_rows > 0) {
                                                while ($kk = $getMember->fetch_object()) {
                                                    $rule->{'hip-profiles'}->addChild('member', $kk->name);
                                                }
                                            }
                                        }
                                    }
                                } else {
                                    $rule->addChild('hip-profiles');
                                    $rule->{'hip-profiles'}->addChild('member', 'any');
                                }
                                $getCategory = $projectdb->query("SELECT name FROM security_rules_categories WHERE rule_lid='$lid';");
                                if ($getCategory->num_rows > 0) {
                                    $rule->addChild('category');
                                    while ($k = $getCategory->fetch_object()) {
                                        $rule->category->addChild('member', $k->name);
                                    }
                                } else {
                                    $rule->addChild('category');
                                    $rule->category->addChild('member', 'any');
                                }
                                $rule->addChild('action', $data2->action);
                                if ($data2->log_start == 1) {
                                    $rule->addChild('log-start', 'yes');
                                }
                                if ($data2->log_end == 1) {
                                    $rule->addChild('log-end', 'yes');
                                }
                                else{
                                    $rule->addChild('log-end', 'no');
                                }
                                if ($data2->disabled == 1) {
                                    $rule->addChild('disabled', 'yes');
                                } else {
                                    //$rule->addChild('disabled', 'no');
                                }
                                if ($data2->negate_source == 1) {
                                    $rule->addChild('negate-source', 'yes');
                                } else {
                                    //$rule->addChild('negate-source', 'no');
                                }
                                if ($data2->negate_destination == 1) {
                                    $rule->addChild('negate-destination', 'yes');
                                } else {
                                    //$rule->addChild('negate-destination', 'no');
                                }
                                if ($data2->description != "") {
                                    $rule->addChild('description');
                                    $rule->description = $data2->description;
                                }
                                if ($data2->schedule != "") {
                                    $rule->addChild('schedule', $data2->schedule);
                                }
                                if ($data2->log_forwarding != "") {
                                    $rule->addChild('log-setting', $data2->log_forwarding);
                                }
                                if ($data2->qos != "None") {
                                    if($version >=7){
                                        $rule->addChild('qos');
                                        $rule->qos->addChild('marking');
                                        $rule->qos->marking->addChild($data2->qos, $data2->qos_value);
                                    }elseif($data2->qos == "ip-dscp" || $data2->qos == "ip-precedence"){
                                        $rule->addChild('qos');
                                        $rule->qos->addChild('marking');
                                        $rule->qos->marking->addChild($data2->qos, $data2->qos_value);
                                    }
                                }
                                if ($data2->profile_type != "None") {
                                    $rule->addChild('profile-setting');
                                    if ($data2->profile_type == "group") {
                                        $profile = $rule->{'profile-setting'}->addChild('group');
                                        $getProfiles = $projectdb->query("SELECT member_lid,table_name FROM security_rules_profiles WHERE rule_lid='$lid';");
                                        if ($getProfiles->num_rows > 0) {
                                            while ($k = $getProfiles->fetch_object()) {
                                                $getMember = $projectdb->query("SELECT name FROM $k->table_name WHERE id='$k->member_lid';");
                                                if ($getMember->num_rows > 0) {
                                                    while ($kk = $getMember->fetch_object()) {
                                                        $profile->addChild('member', $kk->name);
                                                    }
                                                }
                                            }
                                        }
                                    } else {
                                        $profile = $rule->{'profile-setting'}->addChild('profiles');
                                        $getProfiles = $projectdb->query("SELECT member_lid,table_name FROM security_rules_profiles WHERE rule_lid='$lid';");
                                        if ($getProfiles->num_rows > 0) {
                                            while ($k = $getProfiles->fetch_object()) {
                                                $getMember = $projectdb->query("SELECT name,type FROM $k->table_name WHERE id='$k->member_lid';");
                                                if ($getMember->num_rows > 0) {
                                                    while ($kk = $getMember->fetch_object()) {
                                                        $thetype = $kk->{'type'};
                                                        $theprofiles = $profile->addChild($thetype);
                                                        $theprofiles->addChild('member', $kk->name);
                                                    }
                                                } else {
                                                    $getMember = $projectdb->query("SELECT name,type FROM $k->table_name WHERE source=0 AND id='$k->member_lid';");
                                                    if ($getMember->num_rows > 0) {
                                                        while ($kk = $getMember->fetch_object()) {
                                                            $thetype = $kk->{'type'};
                                                            $theprofiles = $profile->addChild($thetype);
                                                            $theprofiles->addChild('member', $kk->name);
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                $getTAG = $projectdb->query("SELECT member_lid,table_name FROM security_rules_tag WHERE rule_lid='$lid';");
                                if ($getTAG->num_rows > 0) {
                                    $rule->addChild('tag');
                                    while ($k = $getTAG->fetch_object()) {
                                        $getMember = $projectdb->query("SELECT name FROM $k->table_name WHERE id='$k->member_lid';");
                                        if ($getMember->num_rows > 0) {
                                            while ($kk = $getMember->fetch_object()) {
                                                $rule->{'tag'}->addChild('member', $kk->name);
                                            }
                                        }
                                    }
                                }
                                if ($data2->target != "") {
                                    libxml_use_internal_errors(true);
                                    $xml_append = simplexml_load_string($data2->target);
                                    if ($xml_append) {
                                        SimpleXMLElement_append($rule, $xml_append);
                                    }
                                }
                            }
                        }
                    } 
                    else {
                        #DELETE RULES
                        if (isset($xpath->{$pvalue}->security)) {
                            $SA = $xpath->$pvalue->xpath("security");
                            unset($SA[0][0]);
                        }
                    }

                    # NAT
                    $getPolicies = $projectdb->query("SELECT id,position,name,description,target,disabled,vsys,lid,tp_sat_bidirectional,op_zone_to,op_to_interface,is_dat,op_service_lid,op_service_table,tp_sat_type,tp_sat_address_type,tp_sat_interface,tp_sat_ipaddress,tp_dat_port,tp_dat_address_lid,tp_dat_address_table,preorpost,tag,active_active_device_binding,nat_type,tp_sat_interface_fallback,tp_sat_ipaddress_fallback,tp_fallback_type FROM nat_rules WHERE source='$source' AND vsys='$vsys' AND preorpost='$preorpost' ORDER BY position ASC;");
                    if ($getPolicies->num_rows > 0) {
                        if (!isset($xpath->{$pvalue})) {
                            $xpath->addChild($pvalue);
                        }
                        if (!isset($xpath->{$pvalue}->nat)) {
                            $xpath->{$pvalue}->addChild('nat');
                        }
                        if (!isset($xpath->$pvalue->nat->rules)) {
                            $xpath->$pvalue->nat->addChild('rules');
                        } else {
                            #DELETE RULES
                            $SA = $xpath->$pvalue->nat->xpath("rules");
                            unset($SA[0][0]);
                            $xpath->$pvalue->nat->addChild('rules');
                        }
                        while ($data2 = $getPolicies->fetch_object()) {
                            $myname = $data2->name;
                            $lid = $data2->id;
                            if ($xpath->xpath("/$pvalue/nat/rules/entry[@name='$myname']") == null) {
                                $rule = $xpath->$pvalue->nat->rules->addChild('entry');
                                $rule->addAttribute('name', $myname);
                                if ($data2->tp_sat_type == "dynamic-ip") {
                                    $rule->addChild('source-translation');
                                    $stnat = $rule->{'source-translation'}->addChild('dynamic-ip');
                                    if ($data2->tp_fallback_type == "translated-address") {
                                        $getAddr = $projectdb->query("SELECT member_lid,table_name FROM nat_rules_translated_address_fallback WHERE rule_lid='$lid' ;");
                                        if ($getAddr->num_rows > 0) {
                                            $stnat->addChild('fallback');
                                            $stnat->fallback->addChild('translated-address');
                                            while ($getAddrData = $getAddr->fetch_object()) {
                                                $getAddrName = $projectdb->query("SELECT name FROM $getAddrData->table_name WHERE id='$getAddrData->member_lid';");
                                                if ($getAddrName->num_rows == 1) {
                                                    $getAddrNameData = $getAddrName->fetch_object();
                                                    $stnat->fallback->{'translated-address'}->addChild('member', $getAddrNameData->name);
                                                }
                                            }
                                        }
                                    } elseif ($data2->tp_fallback_type == "interface-address") {
                                        $stnat->addChild('fallback');
                                        $stnat->fallback->addChild('interface-address');
                                        if ($data2->tp_sat_interface_fallback != "") {
                                            $stnat->fallback->{'interface-address'}->addChild('interface', $data2->tp_sat_interface_fallback);
                                        }
                                        if ($data2->tp_sat_ipaddress_fallback != "") {
                                            $stnat->fallback->{'interface-address'}->addChild('ip', $data2->tp_sat_ipaddress_fallback);
                                        }
                                    }
                                    $getAddr = $projectdb->query("SELECT member_lid,table_name FROM nat_rules_translated_address WHERE rule_lid='$lid' ;");
                                    if ($getAddr->num_rows > 0) {
                                        $stnat->addChild('translated-address');
                                        while ($getAddrData = $getAddr->fetch_object()) {
                                            $getAddrName = $projectdb->query("SELECT name FROM $getAddrData->table_name WHERE id='$getAddrData->member_lid';");
                                            if ($getAddrName->num_rows == 1) {
                                                $getAddrNameData = $getAddrName->fetch_object();
                                                $stnat->{'translated-address'}->addChild('member', $getAddrNameData->name);
                                            }
                                        }
                                    }
                                } elseif ($data2->tp_sat_type == "dynamic-ip-and-port") {
                                    $rule->addChild('source-translation');
                                    $stnat = $rule->{'source-translation'}->addChild('dynamic-ip-and-port');
                                    if ($data2->tp_sat_address_type == "interface-address") {
                                        $stnat->addChild('interface-address');
                                        $stnat->{'interface-address'}->addChild('interface', $data2->tp_sat_interface);
                                        if (($data2->tp_sat_ipaddress != "") AND ($data2->tp_sat_ipaddress != "None")){
                                            $stnat->{'interface-address'}->addChild('ip', $data2->tp_sat_ipaddress);
                                        }
                                    } else {
                                        $getAddr = $projectdb->query("SELECT member_lid,table_name FROM nat_rules_translated_address WHERE rule_lid='$lid' ;");
                                        if ($getAddr->num_rows > 0) {
                                            $stnat->addChild('translated-address');
                                            while ($getAddrData = $getAddr->fetch_object()) {
                                                $getAddrName = $projectdb->query("SELECT name FROM $getAddrData->table_name WHERE id='$getAddrData->member_lid';");
                                                if ($getAddrName->num_rows == 1) {
                                                    $getAddrNameData = $getAddrName->fetch_object();
                                                    $stnat->{'translated-address'}->addChild('member', $getAddrNameData->name);
                                                }
                                            }
                                        }
                                    }
                                } elseif ($data2->tp_sat_type == "static-ip") {
                                    $rule->addChild('source-translation');
                                    $stnat = $rule->{'source-translation'}->addChild('static-ip');
                                    if ($data2->tp_sat_bidirectional == 1) {
                                        $stnat->addChild('bi-directional', 'yes');
                                    } else {
                                        $stnat->addChild('bi-directional', 'no');
                                    }
                                    $getAddr = $projectdb->query("SELECT table_name,member_lid FROM nat_rules_translated_address WHERE rule_lid='$lid';");
                                    if ($getAddr->num_rows == 1) {
                                        $getAddrData = $getAddr->fetch_object();
                                        $getAddrName = $projectdb->query("SELECT name FROM $getAddrData->table_name WHERE id='$getAddrData->member_lid';");
                                        if ($getAddrName->num_rows == 1) {
                                            $getAddrNameData = $getAddrName->fetch_assoc();
                                            $stnat->addChild('translated-address', $getAddrNameData['name']);
                                        }
                                    }
                                }
                                if ($data2->is_dat == 1) {
                                    $dtnat = $rule->addChild('destination-translation');
                                    if (($data2->tp_dat_address_lid == 0) AND ( $data2->tp_dat_address_table == "")) {
                                        
                                    } else {
                                        $getAddr = $projectdb->query("SELECT name FROM $data2->tp_dat_address_table WHERE id='$data2->tp_dat_address_lid';");
                                        if ($getAddr->num_rows == 1) {
                                            $getAddrData = $getAddr->fetch_object();
                                            $dtnat->addChild('translated-address', $getAddrData->name);
                                        }
                                    }
                                    if ($data2->tp_dat_port != 0) {
                                        $dtnat->addChild('translated-port', $data2->tp_dat_port);
                                    }
                                }
                                if ($data2->op_zone_to != "") {
                                    $rule->addChild('to');
                                    $rule->to->addChild('member', $data2->op_zone_to);
                                } else {
                                    $rule->addChild('to');
                                    $rule->to->addChild('member', 'any');
                                }
                                $getFrom = $projectdb->query("SELECT name FROM nat_rules_from WHERE rule_lid='$lid';");
                                if ($getFrom->num_rows > 0) {
                                    $rule->addChild('from');
                                    while ($k = $getFrom->fetch_object()) {
                                        $rule->from->addChild('member', $k->name);
                                    }
                                } else {
                                    $rule->addChild('from');
                                    $rule->from->addChild('member', 'any');
                                }
                                $getSource = $projectdb->query("SELECT member_lid,table_name FROM nat_rules_src WHERE rule_lid='$lid';");
                                if ($getSource->num_rows > 0) {
                                    $rule->addChild('source');
                                    while ($k = $getSource->fetch_object()) {
//                                        if (($k->table_name == "regions") OR ( $k->table_name == "shared_regions") OR ( $k->table_name == "default_regions") OR ( $k->table_name == "external_list") OR ( $k->table_name == "shared_external_list")) {
//                                            $thename = "name";
//                                        } else {
//                                            $thename = "name_ext";
//                                        }
//                                        if ($k->table_name == "default_regions") {
//                                            $getMember = $projectdb->query("SELECT $thename FROM $k->table_name WHERE id='$k->member_lid';");
//                                        } else {
//                                            $getMember = $projectdb->query("SELECT $thename FROM $k->table_name WHERE id='$k->member_lid';");
//                                        }
                                        $getMember = $projectdb->query("SELECT name FROM $k->table_name WHERE id='$k->member_lid';");
                                        if ($getMember->num_rows > 0) {
                                            while ($kk = $getMember->fetch_object()) {
                                                $rule->source->addChild('member', $kk->name);
                                            }
                                        }
                                    }
                                } else {
                                    $rule->addChild('source');
                                    $rule->source->addChild('member', 'any');
                                }
                                $getDestination = $projectdb->query("SELECT member_lid,table_name FROM nat_rules_dst WHERE rule_lid='$lid' ;");
                                if ($getDestination->num_rows > 0) {
                                    $rule->addChild('destination');
                                    while ($k = $getDestination->fetch_object()) {
//                                        if (($k->table_name == "regions") OR ( $k->table_name == "shared_regions") OR ( $k->table_name == "default_regions") OR ( $k->table_name == "external_list") OR ( $k->table_name == "shared_external_list")) {
//                                            $thename = "name";
//                                        } else {
//                                            $thename = "name_ext";
//                                        }
//                                        if ($k->table_name == "default_regions") {
//                                            $getMember = $projectdb->query("SELECT $thename FROM $k->table_name WHERE id='$k->member_lid';");
//                                        } else {
//                                            $getMember = $projectdb->query("SELECT $thename FROM $k->table_name WHERE id='$k->member_lid';");
//                                        }
                                        $getMember = $projectdb->query("SELECT $thename FROM $k->table_name WHERE id='$k->member_lid';");
                                        if ($getMember->num_rows > 0) {
                                            while ($kk = $getMember->fetch_object()) {
                                                $rule->destination->addChild('member', $kk->name);
                                            }
                                        }
                                    }
                                } else {
                                    $rule->addChild('destination');
                                    $rule->destination->addChild('member', 'any');
                                }
                                if (($data2->op_service_table != "") AND ( $data2->op_service_lid != "")) {
                                    $getsrv = $projectdb->query("SELECT name FROM $data2->op_service_table WHERE id='$data2->op_service_lid';");
                                    if ($getsrv->num_rows ==1){
                                        $getsrvdata = $getsrv->fetch_assoc();
                                        $rule->addChild('service', $getsrvdata['name']);
                                    }
                                } else {
                                    $rule->addChild('service', 'any');
                                }
                                if ($data2->op_to_interface != "") {
                                    $rule->addChild('to-interface', $data2->op_to_interface);
                                }
                                if ($data2->disabled == 1) {
                                    $rule->addChild('disabled', 'yes');
                                } else {
                                    //$rule->addChild('disabled', 'no');
                                }
                                if ($data2->nat_type != "") {
                                    $rule->addChild('nat-type', $data2->nat_type);
                                } else {
                                    $rule->addChild('nat-type', 'ipv4');
                                }
                                $getTAG = $projectdb->query("SELECT member_lid,table_name FROM nat_rules_tag WHERE rule_lid='$lid';");
                                if ($getTAG->num_rows > 0) {
                                    $rule->addChild('tag');
                                    while ($k = $getTAG->fetch_object()) {
                                        $getMember = $projectdb->query("SELECT name FROM $k->table_name WHERE source='$source' AND id='$k->member_lid';");
                                        if ($getMember->num_rows > 0) {
                                            while ($kk = $getMember->fetch_object()) {
                                                $rule->{'tag'}->addChild('member', $kk->name);
                                            }
                                        }
                                    }
                                }
                                if ($data2->target != "") {
                                    libxml_use_internal_errors(true);
                                    $xml_append = simplexml_load_string($data2->target);
                                    if ($xml_append) {
                                        SimpleXMLElement_append($rule, $xml_append);
                                    }
                                }
                                if ($data2->description != "") {
                                    $rule->addChild('description');
                                    $rule->description = $data2->description;
                                }
                                if ($data2->active_active_device_binding != "") {
                                    $rule->addChild('active-active-device-binding', $data2->active_active_device_binding);
                                }
                            }
                        }
                    } 
                    else {
                        #DELETE RULES
                        if (isset($xpath->$pvalue->nat)) {
                            $SA = $xpath->$pvalue->xpath("nat");
                            unset($SA[0][0]);
                        }
                    }

                    # APPLICATION OVERRIDE
                    $getPolicies = $projectdb->query("SELECT position,name,negate_source,negate_destination,description,disabled,id,target,protocol,app_id,app_table,port FROM appoverride_rules WHERE source='$source' AND vsys='$vsys' AND preorpost='$preorpost' ORDER BY position ASC;");
                    if ($getPolicies->num_rows > 0) {
                        if (!isset($xpath->{$pvalue})) {
                            $xpath->addChild($pvalue);
                        }

                        if (!isset($xpath->{$pvalue}->{'application-override'})) {
                            $xpath->{$pvalue}->addChild('application-override');
                        }

                        if (!isset($xpath->{$pvalue}->{'application-override'}->rules)) {
                            $xpath->{$pvalue}->{'application-override'}->addChild('rules');
                        } else {
                            #DELETE RULES
                            $SA = $xpath->$pvalue->{'application-override'}->xpath("rules");
                            unset($SA[0][0]);
                            $xpath->{$pvalue}->{'application-override'}->addChild('rules');
                        }

                        while ($data2 = $getPolicies->fetch_object()) {
                            $myname = $data2->name;
                            $lid = $data2->id;
                            if ($xpath->xpath("/$pvalue/application-override/rules/entry[@name='$myname']") == null) {
                                $rule = $xpath->$pvalue->{'application-override'}->rules->addChild('entry');
                                $rule->addAttribute('name', $myname);
                                $getFrom = $projectdb->query("SELECT name FROM appoverride_rules_from WHERE rule_lid='$lid';");
                                if ($getFrom->num_rows > 0) {
                                    $rule->addChild('from');
                                    while ($k = $getFrom->fetch_object()) {
                                        $rule->from->addChild('member', $k->name);
                                    }
                                } else {
                                    $rule->addChild('from');
                                    $rule->from->addChild('member', 'any');
                                }
                                $getTo = $projectdb->query("SELECT name FROM appoverride_rules_to WHERE source='$source' AND rule_lid='$lid' AND vsys='$vsys';");
                                if ($getTo->num_rows > 0) {
                                    $rule->addChild('to');
                                    while ($k = $getTo->fetch_object()) {
                                        $rule->to->addChild('member', $k->name);
                                    }
                                } else {
                                    $rule->addChild('to');
                                    $rule->to->addChild('member', 'any');
                                }
                                $getSource = $projectdb->query("SELECT member_lid,table_name FROM appoverride_rules_src WHERE source='$source' AND rule_lid='$lid' AND vsys='$vsys';");
                                if ($getSource->num_rows > 0) {
                                    $rule->addChild('source');
                                    while ($k = $getSource->fetch_object()) {
//                                        if (($k->table_name == "regions") OR ( $k->table_name == "shared_regions") OR ( $k->table_name == "default_regions") OR ( $k->table_name == "external_list") OR ( $k->table_name == "shared_external_list")) {
//                                            $thename = "name";
//                                        } else {
//                                            $thename = "name_ext";
//                                        }
//                                        if ($k->table_name == "default_regions") {
//                                            $getMember = $projectdb->query("SELECT $thename FROM $k->table_name WHERE id='$k->member_lid';");
//                                        } else {
//                                            $getMember = $projectdb->query("SELECT $thename FROM $k->table_name WHERE id='$k->member_lid';");
//                                        }
                                        $getMember = $projectdb->query("SELECT name FROM $k->table_name WHERE id='$k->member_lid';");
                                        if ($getMember->num_rows > 0) {
                                            while ($kk = $getMember->fetch_object()) {
                                                $rule->source->addChild('member', $kk->name);
                                            }
                                        }
                                    }
                                } else {
                                    $rule->addChild('source');
                                    $rule->source->addChild('member', 'any');
                                }
                                $getDestination = $projectdb->query("SELECT member_lid,table_name FROM appoverride_rules_dst WHERE source='$source' AND rule_lid='$lid' AND vsys='$vsys';");
                                if ($getDestination->num_rows > 0) {
                                    $rule->addChild('destination');
                                    while ($k = $getDestination->fetch_object()) {
//                                        if (($k->table_name == "regions") OR ( $k->table_name == "shared_regions") OR ( $k->table_name == "default_regions") OR ( $k->table_name == "external_list") OR ( $k->table_name == "shared_external_list")) {
//                                            $thename = "name";
//                                        } else {
//                                            $thename = "name_ext";
//                                        }
//                                        if ($k->table_name == "default_regions") {
//                                            $getMember = $projectdb->query("SELECT $thename FROM $k->table_name WHERE id='$k->member_lid';");
//                                        } else {
//                                            $getMember = $projectdb->query("SELECT $thename FROM $k->table_name WHERE id='$k->member_lid';");
//                                        }
                                        $getMember = $projectdb->query("SELECT name FROM $k->table_name WHERE id='$k->member_lid';");
                                        if ($getMember->num_rows > 0) {
                                            while ($kk = $getMember->fetch_object()) {
                                                $rule->destination->addChild('member', $kk->name);
                                            }
                                        }
                                    }
                                } else {
                                    $rule->addChild('destination');
                                    $rule->destination->addChild('member', 'any');
                                }

                                $getAPP = $projectdb->query("SELECT name FROM $data2->app_table WHERE id='$data2->app_id';");
                                if ($getAPP->num_rows == 1) {
                                    $k = $getAPP->fetch_object();
                                    $rule->addChild('application', $k->name);
                                }


                                if ($data2->disabled == 1) {
                                    $rule->addChild('disabled', 'yes');
                                } else {
                                    //$rule->addChild('disabled', 'no');
                                }
                                if ($data2->negate_source == 1) {
                                    $rule->addChild('negate-source', 'yes');
                                } else {
                                    //$rule->addChild('negate-source', 'no');
                                }
                                if ($data2->negate_destination == 1) {
                                    $rule->addChild('negate-destination', 'yes');
                                } else {
                                    //$rule->addChild('negate-destination', 'no');
                                }
                                if ($data2->description != "") {
                                    $rule->addChild('description');
                                    $rule->description = $data2->description;
                                }
                                $rule->addChild('protocol', $data2->protocol);
                                $rule->addChild('port', $data2->port);
                                $getTAG = $projectdb->query("SELECT member_lid,table_name FROM security_rules_tag WHERE source='$source' AND vsys='$vsys' AND rule_lid='$lid';");
                                if ($getTAG->num_rows > 0) {
                                    $rule->addChild('tag');
                                    while ($k = $getTAG->fetch_object()) {
                                        $getMember = $projectdb->query("SELECT name FROM $k->table_name WHERE id='$k->member_lid';");
                                        if ($getMember->num_rows > 0) {
                                            while ($kk = $getMember->fetch_object()) {
                                                $rule->{'tag'}->addChild('member', $kk->name);
                                            }
                                        }
                                    }
                                }
                                if ($data2->target != "") {
                                    libxml_use_internal_errors(true);
                                    $xml_append = simplexml_load_string($data2->target);
                                    if ($xml_append) {
                                        SimpleXMLElement_append($rule, $xml_append);
                                    }
                                }
                            }
                        }
                    } 
                    else {
                        #DELETE RULES
                        if (isset($xpath->{$pvalue}->{'application-override'})) {
                            $SA = $xpath->$pvalue->xpath("application-override");
                            unset($SA[0][0]);
                        }
                    }


                    # OTHER RULES
                    $getPolicies = $projectdb->query("SELECT id,type,xml FROM other_rules WHERE source='$source' AND vsys='$vsys' AND preorpost='$preorpost' ORDER BY id ASC;");
                    if ($getPolicies->num_rows > 0) {
                        if (!isset($xpath->{$pvalue})) {
                            $xpath->addChild($pvalue);
                        }
                        while ($data2 = $getPolicies->fetch_assoc()) {
                            $lid = $data2['id'];
                            $mytype = $data2['type'];
                            $xmlfield = $data2['xml'];

                            if (!isset($xpath->{$pvalue}->{$mytype})) {
                                $xpath->{$pvalue}->addChild($mytype);
                            }

                            if (!isset($xpath->{$pvalue}->{$mytype}->rules)) {
                                
                            } else {
                                #DELETE RULES
                                $SA = $xpath->$pvalue->{$mytype}->xpath("rules");
                                unset($SA[0][0]);
                            }
                            $xml_append = simplexml_load_string($xmlfield);
                            $theProfiles = $xpath->{$pvalue}->{$mytype};
                            SimpleXMLElement_append($theProfiles, $xml_append);
                        }
                    }
                    
                    #Check if the pre or post are empty to remove it
                    if ( (!isset($xpath->$pvalue->security->rules)) AND (!isset($xpath->$pvalue->nat->rules)) AND (!isset($xpath->$pvalue->{'default-security-rules'}->rules)) AND (!isset($xpath->$pvalue->{'application-override'}->rules)) AND (!isset($xpath->$pvalue->decryption->rules)) AND (!isset($xpath->$pvalue->pbf)) AND (!isset($xpath->$pvalue->dos)) AND (!isset($xpath->$pvalue->qos)) AND (!isset($xpath->$pvalue->{'captive-portal'}->rules)) ){
                        unset($xpath->$pvalue);
                    }
                }
            
                # ------
                update_progress($project, '0.25', 'Shared Objects Loaded');
            
                #Panorama
                $getDG = $projectdb->query("SELECT devices,master_device,description,device_mapping_id FROM devicegroups WHERE source='$source';");
                if ($getDG->num_rows > 0) {
                    #Check if DG root Exists
                    $existDGroot = $xml->xpath("//devices/entry[@name='localhost.localdomain']/device-group");
                    if (empty($existDGroot)) {
                        $root = $xml->xpath("//devices/entry[@name='localhost.localdomain']");
                        $root[0]->addChild('device-group');
                    }

                    $allDG = array();
                    $platform = "device-group";
                    $policies = array("pre-rulebase", "post-rulebase");
                    while ($DG = $getDG->fetch_assoc()) {
                        $device_mapping_id = $DG['device_mapping_id'];
                        $getDGname = $projectdb->query("SELECT vsys FROM device_mapping WHERE id='$device_mapping_id';");
                        if ($getDGname->num_rows == 1) {
                            $getDGnameData = $getDGname->fetch_assoc();
                            $DGName = $getDGnameData['vsys'];
                        }
                        $allDG[] = $DGName; # To be used after this process to do a loop
                        $thedevicegroup1 = $xml->xpath("//devices/entry[@name='localhost.localdomain']/device-group/entry[@name='$DGName']");
                        if (empty($thedevicegroup1)) {
                            $thedevicegroupPath = $xml->xpath("//devices/entry[@name='localhost.localdomain']/device-group");
                            $thedevicegroup = $thedevicegroupPath[0]->addChild('entry');
                            $thedevicegroup->addAttribute('name', $DGName);
                            if ($DG['devices'] != "") {
                                $xml_append = simplexml_load_string($DG['devices']);
                                SimpleXMLElement_append($thedevicegroup, $xml_append);
                            } else {
                                $thedevicegroup->addChild('devices');
                            }

                            if (($DG['master_device'] == "") OR ( $DG['master_device'] == "None") OR ( $DG['master_device'] == null)) {
                                
                            } else {
                                $xml_append = simplexml_load_string($DG['master_device']);
                                SimpleXMLElement_append($thedevicegroup, $xml_append);
                            }
                            if ($DG['description'] != "") {
                                $thedevicegroup->addChild('description');
                                $thedevicegroup->description = $DG['description'];
                            }
                        } 
                        else {
                            $thedevicegroup = $thedevicegroup1[0];
                            if ($DG['description'] != "") {
                                if (!isset($thedevicegroup->description)) {
                                    $thedevicegroup->addChild('description');
                                    $thedevicegroup->description = $DG['description'];
                                } else {
                                    $thedevicegroup->description = $DG['description'];
                                }
                            }
                        }
                    }
                }

                # Templates
                $getTemplate = $projectdb->query("SELECT id,name FROM templates_mapping WHERE source='$source';");
                if ($getTemplate->num_rows > 0) {
                    $existTemplateroot = $xml->xpath("//devices/entry[@name='localhost.localdomain']/template");
                    if (empty($existTemplateroot)) {
                        $rootTemplate1 = $xml->xpath("//devices/entry[@name='localhost.localdomain']");
                        $rootTemplate = $rootTemplate1[0]->addChild('template');
                    } else {
                        $SA = $xml->xpath("//devices/entry[@name='localhost.localdomain']/template");
                        #unset($SA[0][0]);
                        $rootTemplate = $SA[0];
                    }
                    while ($getTemplateData = $getTemplate->fetch_assoc()) {
                        $template = $getTemplateData['id'];
                        $template_name = $getTemplateData['name'];
                        $getTemplateInfo = $projectdb->query("SELECT description,multi_vsys,operational_mode,vpn_disable_mode,devices FROM templates WHERE templates_mapping_id='$template';");
                        if ($getTemplateInfo->num_rows == 1) {
                            $getTemplateInfoData = $getTemplateInfo->fetch_assoc();
                            #$template_name = $getTemplateInfoData['name'];
                            $template_description = $getTemplateInfoData['description'];
                            $template_multi_vsys = $getTemplateInfoData['multi_vsys'];
                            $template_operational_mode = strtolower($getTemplateInfoData['operational_mode']);
                            $template_vpn_disable_mode = $getTemplateInfoData['vpn_disable_mode'];
                            $template_devices = $getTemplateInfoData['devices'];
                            
                            $existTemplate = $xml->xpath("//devices/entry[@name='localhost.localdomain']/template/entry[@name='$template_name']");
                            if (empty($existTemplate)){
                                $myTemplate = $rootTemplate->addChild("entry");
                                $myTemplate->addAttribute('name', $template_name);
                                $myTemplate->addChild("settings");
                                if ($template_vpn_disable_mode != "") {
                                    $myTemplate->settings->addChild("vpn-disable-mode", $template_vpn_disable_mode);
                                }
                                if ($template_operational_mode != "") {
                                    $myTemplate->settings->addchild("operational-mode", $template_operational_mode);
                                }
                                if ($template_multi_vsys == "yes") {
                                    $myTemplate->settings->addchild("multi-vsys", "yes");
                                }
                                if ($template_devices != "") {
                                    $xml_append = simplexml_load_string($template_devices);
                                    SimpleXMLElement_append($myTemplate, $xml_append);
                                }

                                $myTemplate->addChild("config");
                                # Template - Shared
                                
                            }
                            else{
                                $myTemplate=$existTemplate[0];
                                if (empty($myTemplate->config)){
                                    $myTemplate->addChild("config");
                                }
                            }
                            
                            
                            if (!isset($myTemplate->config->shared)){
                                $myTemplateShared = $myTemplate->config->addChild("shared");
                            }
                            else {
                                $myTemplateShared = $myTemplate->config->shared;
                            }
                            
                            # RESPONSE-PAGES
                            if (isset($myTemplateShared->{'response-page'})){
                                $SA = $myTemplateShared->xpath("response-page");
                                unset($SA[0][0]);
                            }
                            $getShared = $projectdb->query("SELECT name,type,html FROM shared_response_pages WHERE source='$source' AND template='$template' ORDER BY id;");
                            if ($getShared->num_rows > 0) {
                                $myTemplateShared->addChild('response-page');
                                while ($data2 = $getShared->fetch_assoc()) {
                                    $xmlfield = $data2['html'];
                                    $xmlname = $data2['type'];
                                    $reportname = $data2['name'];
                                    if ($reportname != "") {
                                        if (!isset($myTemplateShared->{'response-page'}->$xmlname)) {
                                            $myTemplateShared->{'response-page'}->addChild($xmlname);
                                            $newrp = $myTemplateShared->{'response-page'}->$xmlname->addChild("entry");
                                            $newrp->addAttribute('name', $reportname);
                                            $newrp->addChild("page");
                                            $newrp->page = $xmlfield;
                                        } else {
                                            if ($myTemplateShared->{'response-page'}->$xmlname->xpath("entry[@name='$reportname']") !== null) {
                                                $SA = $myTemplateShared->{'response-page'}->$xmlname->xpath("entry[@name='$reportname']");
                                                unset($SA[0][0]);
                                            }
                                            $newrp = $myTemplateShared->{'response-page'}->$xmlname->addChild("entry");
                                            $newrp->addAttribute('name', $reportname);
                                            $newrp->addChild("page");
                                            $newrp->page = $xmlfield;
                                        }
                                    } else {
                                        $SA = $myTemplateShared->xpath("response-page/$xmlname");
                                        unset($SA[0][0]);
                                        #$xml_append = simplexml_load_string($xmlfield);
                                        $xml_append = simplexml_load_string("<$xmlname>$xmlfield</$xmlname>");
                                        SimpleXMLElement_append($myTemplateShared->{'response-page'}, $xml_append);
                                    }
                                }
                            }
                            
                            # SHARED SERVER PROFILES
                            if (isset($myTemplateShared->{'server-profile'})){
                                $SA = $myTemplateShared->xpath("server-profile");
                                unset($SA[0][0]);
                            }
                            $getShared = $projectdb->query("SELECT server_type FROM shared_server_profile WHERE source='$source' AND template='$template' GROUP BY server_type;");
                            if ($getShared->num_rows>0){
                                if (!isset($myTemplateShared->{'server-profile'})){
                                    $myTemplateShared->addChild('server-profile');
                                }
                                $serverProfile=$myTemplateShared->{'server-profile'};
                                while ($getSharedData=$getShared->fetch_assoc()){
                                    $server_type=$getSharedData['server_type'];
                                    if (!isset($serverProfile->$server_type)){
                                        $serverProfile->addChild($server_type);
                                    }
                                    $getSPMember=$projectdb->query("SELECT name,xml FROM shared_server_profile WHERE source='$source' AND template='$template' AND server_type='$server_type';");
                                    if ($getSPMember->num_rows>0){
                                        while ($getSPMemberData=$getSPMember->fetch_assoc()){
                                            $myname=$getSPMemberData['name'];
                                            $xmlfield=$getSPMemberData['xml'];
                                            
                                            //echo "ANTES: " .$xmlfield. "\n";
                                            if($version >= 7){
                                                if($server_type == "radius"){
                                                    $xmlfield = preg_replace('#<domain>+[^\s]+</domain>#', '', $xmlfield);
                                                }
                                                if($server_type == "ldap"){
                                                    $xmlfield = preg_replace('#<domain>+[^\s]+</domain>#', '', $xmlfield);
                                                }
                                                if($server_type == "kerberos"){
                                                    $xmlfield2 = preg_replace('#<domain>+[^\s]+</domain>#', '', $xmlfield);
                                                    $xmlfield = preg_replace('#<realm>+[^\s]+</realm>#', '', $xmlfield2);
                                                    
                                                }
                                            }
                                                //echo "DESPUES: " .$xmlfield. "\n";
                                            
                                            if ($serverProfile->xpath("$server_type/entry[@name='$myname']") == null) {
                                                $xml_append = simplexml_load_string($xmlfield);
                                                SimpleXMLElement_append($serverProfile->$server_type, $xml_append);
                                            }
                                        }
                                    }
                                }
                            }
                            
                            
                            # Template - Devices
                            if (!isset($myTemplate->config->devices)){
                                $myTemplate->config->addChild("devices");
                            }
                            if (!isset($myTemplate->config->devices->entry)){
                                $myTemplateDevice = $myTemplate->config->devices->addChild("entry");
                                $myTemplateDevice->addAttribute('name', 'localhost.localdomain');
                            }
                            else{
                                $myTemplateDevice0 = $myTemplate->xpath("config/devices/entry[@name='localhost.localdomain']");
                                $myTemplateDevice = $myTemplateDevice0[0];
                            }
                            

                            

                            # VSYS
                            $getDG = $projectdb->query("SELECT * FROM virtual_systems WHERE source='$source' AND template='$template';");
                            if ($getDG->num_rows > 0) {
                                #$platform="vsys";
                                if (!isset($myTemplateDevice->vsys)){
                                    # Template - Devices - Vsys
                                    $myTemplateDevice->addChild('vsys');
                                }
                                
                                while ($DG = $getDG->fetch_assoc()) {
                                    $DGName = $DG['name'];
                                    if ($myTemplateDevice->xpath("vsys/entry[@name='$DGName']") == null){
                                        $thedevicegroup = $myTemplateDevice->vsys->addChild('entry');
                                        $thedevicegroup->addAttribute('name', $DGName);
                                    }
                                    else {
                                        $thedevicegroup0=$myTemplateDevice->xpath("vsys/entry[@name='$DGName']");
                                        $thedevicegroup=$thedevicegroup0[0];
                                    }
                                    
                                    if (!isset($thedevicegroup->import)){
                                        $thedevicegroup->addChild('import');
                                    }
                                    if (!isset($thedevicegroup->import->network)){
                                        $thedevicegroup->import->addChild('network');
                                    }
                                    else{
                                        $SA=$thedevicegroup->xpath("import/network");
                                        unset($SA[0][0]);
                                        $thedevicegroup->import->addChild('network');
                                    }
                                    
                                    #Interface
                                    if ($DG['interfaces'] != "") {
                                        $thedevicegroup->import->network->addChild('interface');
                                        $interfaces = explode(",", $DG['interfaces']);
                                        foreach ($interfaces as $key => $value) {
                                            if ($value != "") {
                                                $thedevicegroup->import->network->interface->addChild('member', $value);
                                            }
                                        }
                                    }
                                    if ($DG['virtual_router'] != "") {
                                        $thedevicegroup->import->network->addChild('virtual-router');
                                        $interfaces = explode(",", $DG['virtual_router']);
                                        foreach ($interfaces as $key => $value) {
                                            if ($value != "") {
                                                $thedevicegroup->import->network->{'virtual-router'}->addChild('member', $value);
                                            }
                                        }
                                    }
                                    if ($DG['virtual_wire'] != "") {
                                        $thedevicegroup->import->network->addChild('virtual-wire');
                                        $interfaces = explode(",", $DG['virtual_wire']);
                                        foreach ($interfaces as $key => $value) {
                                            if ($value != "") {
                                                $thedevicegroup->import->network->{'virtual-wire'}->addChild('member', $value);
                                            }
                                        }
                                    }
                                    if ($DG['vlan'] != "") {
                                        $thedevicegroup->import->network->addChild('vlan');
                                        $interfaces = explode(",", $DG['vlan']);
                                        foreach ($interfaces as $key => $value) {
                                            if ($value != "") {
                                                $thedevicegroup->import->network->{'vlan'}->addChild('member', $value);
                                            }
                                        }
                                    }
                                    if ($DG['visible_vsys'] != "") {
                                        $thedevicegroup->import->network->addChild('visible-vsys');
                                        $interfaces = explode(",", $DG['visible_vsys']);
                                        foreach ($interfaces as $key => $value) {
                                            if ($value != "") {
                                                $thedevicegroup->import->network->{'visible-vsys'}->addChild('member', $value);
                                            }
                                        }
                                    }
                                    
                                    if (isset($thedevicegroup->import->resource)){
                                        $SA=$thedevicegroup->xpath("import/resource");
                                        unset($SA[0][0]);
                                    }
                                    $thedevicegroup->import->addChild('resource');
                                    $DGresource = $thedevicegroup->import->resource;
                                    $max_application_override_rules = $DG['max_application_override_rules'];
                                    if ($max_application_override_rules != "0") {
                                        $DGresource->addChild('max-application-override-rules', $max_application_override_rules);
                                    }
                                    $max_concurrent_ssl_vpn_tunnels = $DG['max_concurrent_ssl_vpn_tunnels'];
                                    if ($max_concurrent_ssl_vpn_tunnels != "0") {
                                        $DGresource->addChild('max-concurrent-ssl-vpn-tunnels', $max_concurrent_ssl_vpn_tunnels);
                                    }
                                    $max_cp_rules = $DG['max_cp_rules'];
                                    if ($max_cp_rules != "0") {
                                        $DGresource->addChild('max-cp-rules', $max_cp_rules);
                                    }
                                    $max_dos_rules = $DG['max_dos_rules'];
                                    if ($max_dos_rules != "0") {
                                        $DGresource->addChild('max-dos-rules', $max_dos_rules);
                                    }
                                    $max_nat_rules = $DG['max_nat_rules'];
                                    if ($max_nat_rules != "0") {
                                        $DGresource->addChild('max-nat-rules', $max_nat_rules);
                                    }
                                    $max_pbf_rules = $DG['max_pbf_rules'];
                                    if ($max_pbf_rules != "0") {
                                        $DGresource->addChild('max-pbf-rules', $max_pbf_rules);
                                    }
                                    $max_qos_rules = $DG['max_qos_rules'];
                                    if ($max_qos_rules != "0") {
                                        $DGresource->addChild('max-qos-rules', $max_qos_rules);
                                    }
                                    $max_security_rules = $DG['max_security_rules'];
                                    if ($max_security_rules != "0") {
                                        $DGresource->addChild('max-security-rules', $max_security_rules);
                                    }
                                    $max_sessions = $DG['max_sessions'];
                                    if ($max_sessions != "0") {
                                        $DGresource->addChild('max-sessions', $max_sessions);
                                    }
                                    $max_site_to_site_vpn_tunnels = $DG['max_site_to_site_vpn_tunnels'];
                                    if ($max_site_to_site_vpn_tunnels != "0") {
                                        $DGresource->addChild('max-site-to-site-vpn-tunnels', $max_site_to_site_vpn_tunnels);
                                    }
                                    $max_ssl_decryption_rules = $DG['max_ssl_decryption_rules'];
                                    if ($max_ssl_decryption_rules != "0") {
                                        $DGresource->addChild('max-ssl-decryption-rules', $max_ssl_decryption_rules);
                                    }
                                    $dns_proxy = $DG['dns_proxy'];
                                    if (($dns_proxy != "") AND ( $dns_proxy != "None")) {
                                        $thedevicegroup->import->addChild('dns-proxy');
                                        $thedevicegroup->import->{'dns-proxy'}->addChild($dns_proxy);
                                    }
                                    $allow_forward_decrypted_content = $DG['allow_forward_decrypted_content'];
                                    if ($allow_forward_decrypted_content == "") {
                                        $allow_forward_decrypted_content = "no";
                                    }
                                    
                                    if (($max_application_override_rules==0) AND ($max_concurrent_ssl_vpn_tunnels==0) AND ($max_cp_rules==0) AND ($max_dos_rules==0) 
                                            AND ($max_nat_rules==0) AND ($max_pbf_rules==0) AND ($max_qos_rules==0) AND ($max_security_rules==0) AND ($max_ssl_decryption_rules==0)
                                            AND ($dns_proxy==0) AND ($max_sessions==0) AND ($max_site_to_site_vpn_tunnels==0)) {
                                        if ($thedevicegroup->xpath("import/resource")){
                                            $SA = $thedevicegroup->xpath("import/resource");
                                            unset($SA[0][0]);
                                        }

                                    }
                                    
                                    if (isset($thedevicegroup->setting->{'ssl-decrypt'})) {

                                        $SA = $thedevicegroup->xpath("/setting/ssl-decrypt");
                                        unset($SA[0][0]);
                                        #$thedevicegroup->addChild('setting');
                                        #$thedevicegroup->setting->addChild('ssl-decrypt');
                                        #$thedevicegroup->setting->{'ssl-decrypt'}->addChild('allow-forward-decrypted-content',$allow_forward_decrypted_content);
                                    }

                                    # Add content Under the VSYS and TEMPLATE
                                    # ZONES
                                    if (isset($thedevicegroup->zone)){
                                        $SA=$thedevicegroup->xpath("zone");
                                        unset($SA[0][0]);
                                    }
                                    $getShared = $projectdb->query("SELECT id,name,type,interfaces,zone_protection_profile,log_setting_id,include_list,exclude_list,enable_user_identification,log_setting_table_name FROM zones WHERE source='$source' AND vsys='$DGName' AND template='$template' ORDER BY id;");
                                    if ($getShared->num_rows > 0) {
                                        $thedevicegroup->addChild('zone');
                                        while ($data = $getShared->fetch_assoc()) {
                                            $myname = $data['name'];
                                            $type = $data['type'];
                                            $interfaces = $data['interfaces'];
                                            $zone_protection_profile = $data['zone_protection_profile'];
                                            $log_setting_id = $data['log_setting_id'];
                                            $log_setting_table_name = $data['log_setting_table_name'];
                                            $include_list = $data['include_list'];
                                            $exclude_list = $data['exclude_list'];
                                            $enable_user_identification = $data['enable_user_identification'];

                                            $zone = $thedevicegroup->zone->addChild('entry');
                                            $zone->addAttribute('name', $myname);
                                            $zone->addChild('network');

                                            $zone->network->addChild($type);
                                            if ($interfaces != "") {
                                                $allinterfaces = explode(",", $interfaces);
                                                foreach ($allinterfaces as $key => $vvvalue) {
                                                    $zone->network->{$type}->addChild('member', $vvvalue);
                                                }
                                            }

                                            if (($zone_protection_profile != "") AND ( $zone_protection_profile != "None")) {
                                                $zone->network->addChild('zone-protection-profile', $zone_protection_profile);
                                            }
                                            if (($log_setting_id != "") AND ( $log_setting_table_name != "")) {
                                                $getLP = $projectdb->query("SELECT name FROM $log_setting_table_name WHERE id='$log_setting_id';");
                                                if ($getLP->num_rows == 1) {
                                                    $LPData = $getLP->fetch_assoc();
                                                    $zone->network->addChild('log-setting', $LPData['name']);
                                                }
                                            }
                                            if (($include_list != "") OR ( $exclude_list != "")) {
                                                $zone->addChild('user-acl');
                                            }
                                            if ($include_list != "") {
                                                $allinclude = explode(",", $include_list);
                                                $zone->{'user-acl'}->addChild('include-list');
                                                foreach ($allinclude as $key => $vvvalue) {
                                                    $zone->{'user-acl'}->{'include-list'}->addChild('member', $vvvalue);
                                                }
                                            }
                                            if ($exclude_list != "") {
                                                $allinclude = explode(",", $exclude_list);
                                                $zone->{'user-acl'}->addChild('exclude-list');
                                                foreach ($allinclude as $key => $vvvalue) {
                                                    $zone->{'user-acl'}->{'exclude-list'}->addChild('member', $vvvalue);
                                                }
                                            }
                                            if ($enable_user_identification == "yes") {
                                                $zone->addChild('enable-user-identification', $enable_user_identification);
                                            }
                                        }
                                    }
                                }
                            }


                            # Template - Network
                            if (!isset($myTemplateDevice->network)){
                                $myTemplateDeviceNetwork = $myTemplateDevice->addChild("network");
                            }
                            else{
                               $myTemplateDeviceNetwork = $myTemplateDevice->network;
                            }
                            #DHCP
                            if (isset($myTemplateDeviceNetwork->dhcp)){
                                $SA=$myTemplateDeviceNetwork->xpath("dhcp");
                                unset($SA[0][0]);
                            }
                            $getDHCP = $projectdb->query("SELECT name,dhcp_type,xml FROM dhcp WHERE source='$source' AND template='$template';");
                            if ($getDHCP->num_rows > 0) {
                                $myTemplateDeviceNetwork->addChild("dhcp");
                                $myTemplateDeviceNetwork->dhcp->addChild("interface");

                                while ($getDHCPData = $getDHCP->fetch_assoc()) {
                                    $myname = $getDHCPData['name'];
                                    $xmlfield = $getDHCPData['xml'];
                                    $xml_append = simplexml_load_string($xmlfield);
                                    if ($myTemplateDeviceNetwork->dhcp->interface->xpath("//entry[@name='$xmlname']") != null) {
                                        add_log('warning', 'Exporting Schedules [' . $vsys . ']', 'Object Duplicated in Destination [' . $xmlname . ']', $source, 'Object was Not Migrated');
                                    } else {
                                        SimpleXMLElement_append($myTemplateDeviceNetwork->dhcp->interface, $xml_append);
                                    }
                                }
                            }

                            # DNS-PROXY
                            if (isset($myTemplateDeviceNetwork->{'dns-proxy'})){
                                $SA=$myTemplateDeviceNetwork->xpath("dns-proxy");
                                unset($SA[0][0]);
                            }
                            $getDHCP = $projectdb->query("SELECT name,xml FROM dns_proxy WHERE source='$source' AND template='$template';");
                            if ($getDHCP->num_rows > 0) {
                                $myTemplateDeviceNetwork->addChild("dns-proxy");

                                while ($getDHCPData = $getDHCP->fetch_assoc()) {
                                    $myname = $getDHCPData['name'];
                                    $xmlfield = $getDHCPData['xml'];
                                    $xml_append = simplexml_load_string($xmlfield);
                                    if ($myTemplateDeviceNetwork->{'dns-proxy'}->xpath("//entry[@name='$xmlname']") != null) {
                                        add_log('warning', 'Exporting Schedules [' . $vsys . ']', 'Object Duplicated in Destination [' . $xmlname . ']', $source, 'Object was Not Migrated');
                                    } else {
                                        SimpleXMLElement_append($myTemplateDeviceNetwork->{'dns-proxy'}, $xml_append);
                                    }
                                }
                            }
                            
                            # Template - Device - Network - Profiles
                            if (!isset($myTemplateDeviceNetwork->profiles)){
                                $myTemplateDeviceNetworkProfiles = $myTemplateDeviceNetwork->addChild("profiles");
                            }
                            else {
                                $myTemplateDeviceNetworkProfiles = $myTemplateDeviceNetwork->profiles;
                            }
                            
                            
                            # MONITOR PROFILE
                            if (isset($myTemplateDeviceNetworkProfiles->{'monitor-profile'})){
                                $SA=$myTemplateDeviceNetworkProfiles->xpath("monitor-profile");
                                unset($SA[0][0]);
                            }
                            $getMonitor = $projectdb->query("SELECT name,m_action,interva,threshold FROM monitor_profile WHERE source='$source' AND template='$template' AND name != '' GROUP BY name;");
                            if ($getMonitor->num_rows>0){
                                if (!isset($myTemplateDeviceNetworkProfiles->{'monitor-profile'})){
                                    $myTemplateDeviceNetworkProfiles->addChild("monitor-profile");
                                }
                                $MPXpath=$myTemplateDeviceNetworkProfiles->{'monitor-profile'};
                                while ($getMonitorData=$getMonitor->fetch_assoc()){
                                    $myname = $getMonitorData['name'];
                                    $MPAction=$getMonitorData['m_action'];
                                    $MPInterval=$getMonitorData['interva'];
                                    $MPThreshold=$getMonitorData['threshold'];

                                    //if (count($MPXpath->xpath("//entry[@name='$myname']"))==0) {
                                    $monitorProfile = $MPXpath->addChild('entry');
                                    $monitorProfile->addAttribute('name', $getMonitorData['name']);
                                    if (($MPInterval!=0) AND ($MPInterval!="")){
                                        $monitorProfile->addChild("interval");
                                        $monitorProfile->interval=$MPInterval;
                                    }
                                    if (($MPThreshold!=0) AND ($MPThreshold!="")){
                                        $monitorProfile->addChild("threshold");
                                        $monitorProfile->threshold=$MPThreshold;
                                    }
                                    if ($MPAction!=""){
                                        $monitorProfile->addChild("action");
                                        $monitorProfile->action=$MPAction;
                                    }
                                    //}
                                }
                            }
                            else{
                                $SA = $xml->xpath("/config/devices/entry/network/profiles/monitor-profile");
                                unset($SA[0][0]);
                            }

                            # management Profiles
                            if (isset($myTemplateDeviceNetworkProfiles->{'interface-management-profile'})){
                                $SA=$myTemplateDeviceNetworkProfiles->xpath("interface-management-profile");
                                unset($SA[0][0]);
                            }
                            $getMP = $projectdb->query("SELECT name,permitted_ip,http,https,http_ocsp,ssh,snmp,userid_service,userid_syslog_listener_ssl,userid_syslog_listener_udp,ping,response_pages,telnet FROM interface_management_profile WHERE source='$source' AND template='$template' AND name != '';");
                            if ($getMP->num_rows > 0) {
                                $myTemplateDeviceNetworkProfiles->addChild('interface-management-profile');

                                while ($getMPData = $getMP->fetch_assoc()) {
                                    $myname = $getMPData['name'];
                                    $mgmprofile = $myTemplateDeviceNetworkProfiles->{'interface-management-profile'}->addChild('entry');
                                    $mgmprofile->addAttribute('name', $myname);

                                    if ($getMPData['http'] != "") {
                                        $mgmprofile->addChild("http", $getMPData['http']);
                                    }
                                    if ($getMPData['https'] != "") {
                                        $mgmprofile->addChild("https", $getMPData['https']);
                                    }
                                    if ($getMPData['http_ocsp'] != "") {
                                        $mgmprofile->addChild("http-ocsp", $getMPData['http_ocsp']);
                                    }
                                    if ($getMPData['ssh'] != "") {
                                        $mgmprofile->addChild("ssh", $getMPData['ssh']);
                                    }
                                    if ($getMPData['snmp'] != "") {
                                        $mgmprofile->addChild("snmp", $getMPData['snmp']);
                                    }
                                    if ($getMPData['userid_service'] != "") {
                                        $mgmprofile->addChild("userid-service", $getMPData['userid_service']);
                                    }
                                    if ($getMPData['ping'] != "") {
                                        $mgmprofile->addChild("ping", $getMPData['ping']);
                                    }
                                    if ($getMPData['telnet'] != "") {
                                        $mgmprofile->addChild("telnet", $getMPData['telnet']);
                                    }
                                    if ($getMPData['response_pages'] != "") {
                                        $mgmprofile->addChild("response-pages", $getMPData['response_pages']);
                                    }
                                    if ($version > 5) {
                                        if ($getMPData['userid_syslog_listener_ssl'] != "") {
                                            $mgmprofile->addChild("userid-syslog-listener-ssl", $getMPData['userid_syslog_listener_ssl']);
                                        }
                                        if ($getMPData['userid_syslog_listener_udp'] != "") {
                                            $mgmprofile->addChild("userid-syslog-listener-udp", $getMPData['userid_syslog_listener_udp']);
                                        }
                                    }
                                    if ($getMPData['permitted_ip'] != "") {
                                        $interfaces_all = explode(",", $getMPData['permitted_ip']);
                                        $mgmprofile->addChild("permitted-ip");
                                        foreach ($interfaces_all as $key => $int_value) {
                                            $newInt = $mgmprofile->{'permitted-ip'}->addChild("entry");
                                            $newInt->addAttribute('name', $int_value);
                                        }
                                    }
                                }
                            }

                            # Template - Device - Network - IKE 
                            if (!isset($myTemplateDeviceNetwork->ike)){
                                $myTemplateDeviceNetworkIKE_only = $myTemplateDeviceNetwork->addChild("ike");
                            }
                            else {
                                $myTemplateDeviceNetworkIKE_only = $myTemplateDeviceNetwork->ike;
                            }
                            
                            # Template - Device - Network - IKE - Crypto Profiles
                            if (!isset($myTemplateDeviceNetworkIKE_only->{'crypto-profiles'})){
                                $myTemplateDeviceNetworkIKE = $myTemplateDeviceNetworkIKE_only->addChild("crypto-profiles");
                            }
                            else {
                                $myTemplateDeviceNetworkIKE = $myTemplateDeviceNetworkIKE_only->{'crypto-profiles'};
                            }
                            
                            # IKE CRYPTO
                            
                            if (isset($myTemplateDeviceNetworkIKE->{'ike-crypto-profiles'})){
                                $SA = $myTemplateDeviceNetworkIKE->xpath("ike-crypto-profiles");
                                unset($SA[0][0]);
                            }
                            $getIKECrypto = $projectdb->query("SELECT name, encryption, hash, dh_group, seconds, minutes, hours, days, authentication_multiple FROM ike_crypto_profiles WHERE source='$source' AND template='$template' AND name != '';");
                            if ($getIKECrypto->num_rows > 0){
                                if (!isset($myTemplateDeviceNetworkIKE->{'ike-crypto-profiles'})){
                                    $myTemplateDeviceNetworkIKE->addChild("ike-crypto-profiles");
                                }
                                $ike_crypto_path = $myTemplateDeviceNetworkIKE->{'ike-crypto-profiles'};
                                
                                while ($dataIKEC = $getIKECrypto->fetch_assoc()){
                                    $myname = $dataIKEC['name'];
                                    $ike_encryption = $dataIKEC['encryption'];
                                    $ike_hash = $dataIKEC['hash'];
                                    $ike_dh_group = $dataIKEC['dh_group'];
                                    $ike_seconds = $dataIKEC['seconds'];
                                    $ike_minutes = $dataIKEC['minutes'];
                                    $ike_hours = $dataIKEC['hours'];
                                    $ike_days = $dataIKEC['days'];
                                    $ike_authentication_multiple = $dataIKEC['authentication_multiple'];

                                    $ike_crypto = $ike_crypto_path->addChild('entry');
                                    $ike_crypto->addAttribute('name', $dataIKEC['name']);
                                    
                                    if ($ike_encryption != ""){
                                        $ike_crypto->addChild("encryption");
                                        $ike_encryption_array = explode(",", $ike_encryption);
                                        foreach($ike_encryption_array as $member_ike){
                                            $ike_crypto->encryption->addChild("member", $member_ike);
                                        }
                                    }
                                    if ($ike_hash != ""){
                                        $ike_crypto->addChild("hash");
                                        $ike_hash_array = explode(",", $ike_hash);
                                        foreach($ike_hash_array as $member_ike){
                                            $ike_crypto->hash->addChild("member", $member_ike);
                                        }
                                    }
                                    if ($ike_dh_group != ""){
                                        $ike_crypto->addChild("dh-group");
                                        $ike_dh_group_array = explode(",", $ike_dh_group);
                                        foreach($ike_dh_group_array as $member_ike){
                                            $ike_crypto->{'dh-group'}->addChild("member", $member_ike);
                                        }
                                    }
                                    if ($ike_seconds != 0){
                                        $ike_crypto->addChild("lifetime");
                                        $ike_crypto->{'lifetime'}->seconds = $ike_seconds;
                                    }
                                    if ($ike_minutes != 0){
                                        $ike_crypto->addChild("lifetime");
                                        $ike_crypto->{'lifetime'}->minutes = $ike_minutes;
                                    }
                                    if ($ike_hours != 0){
                                        $ike_crypto->addChild("lifetime");
                                        $ike_crypto->{'lifetime'}->hours = $ike_hours;
                                    }
                                    if ($ike_days != 0){
                                        $ike_crypto->addChild("lifetime");
                                        $ike_crypto->{'lifetime'}->days = $ike_days;
                                    }
                                }
                            }
                            else{
                                $SA = $xml->xpath("/config/devices/entry/network/ike/crypto-profiles/ike-crypto-profiles");
                                unset($SA[0][0]);
                            }
                            
                            # IPSEC CRYPTO
                            
                            if (isset($myTemplateDeviceNetworkIKE->{'ipsec-crypto-profiles'})){
                                $SA = $myTemplateDeviceNetworkIKE->xpath("ipsec-crypto-profiles");
                                unset($SA[0][0]);
                            }
                            $getIPSECCrypto = $projectdb->query("SELECT name, encryption, hash, dh_group, protocol, seconds, minutes, hours, days, kb, mb, gb, tb FROM ipsec_crypto_profiles WHERE source = '$source' AND template = '$template' AND name != '';");
                            if ($getIPSECCrypto->num_rows > 0){
                                if (!isset($myTemplateDeviceNetworkIKE->{'ipsec-crypto-profiles'})){
                                    $myTemplateDeviceNetworkIKE->addChild("ipsec-crypto-profiles");
                                }
                                $ipsec_crypto_xpath = $myTemplateDeviceNetworkIKE->{'ipsec-crypto-profiles'};
                                
                                while ($dataIPSECC = $getIPSECCrypto->fetch_assoc()){
                                    $myname = $dataIPSECC['name'];
                                    $ipsec_encryption = $dataIPSECC['encryption'];
                                    $ipsec_hash = $dataIPSECC['hash'];
                                    $ipsec_dh_group = $dataIPSECC['dh_group'];
                                    $ipsec_protocol = $dataIPSECC['protocol'];
                                    $ipsec_seconds = $dataIPSECC['seconds'];
                                    $ipsec_minutes = $dataIPSECC['minutes'];
                                    $ipsec_hours = $dataIPSECC['hours'];
                                    $ipsec_days = $dataIPSECC['days'];
                                    $ipsec_kb = $dataIPSECC['kb'];
                                    $ipsec_mb = $dataIPSECC['mb'];
                                    $ipsec_gb = $dataIPSECC['gb'];
                                    $ipsec_tb = $dataIPSECC['tb'];

                                    $ipsec_crypto = $ipsec_crypto_xpath->addChild('entry');
                                    $ipsec_crypto->addAttribute('name', $dataIPSECC['name']);
                                    
                                    if($ipsec_protocol == "ESP"){
                                        $ipsec_crypto->addChild("esp");

                                        if ($ipsec_encryption != ""){
                                            $ipsec_crypto->esp->addChild("encryption");
                                            $ipsec_encryption_array = explode(",", $ipsec_encryption);
                                            foreach($ipsec_encryption_array as $member_ike){
                                                $ipsec_crypto->esp->encryption->addChild("member", $member_ike);
                                            }
                                        }
                                        if ($ipsec_hash != ""){
                                            $ipsec_crypto->esp->addChild("authentication");
                                            $ipsec_hash_array = explode(",", $ipsec_hash);
                                            foreach($ipsec_hash_array as $member_ike){
                                                $ipsec_crypto->esp->authentication->addChild("member", $member_ike);
                                            }
                                        }
                                    }

                                    if($ipsec_protocol == "AH"){
                                        $ipsec_crypto->addChild("ah");

                                        if ($ipsec_hash != ""){
                                            $ipsec_crypto->ah->addChild("authentication");
                                            $ipsec_hash_array = explode(",", $ipsec_hash);
                                            foreach($ipsec_hash_array as $member_ike){
                                                $ipsec_crypto->ah->authentication->addChild("member", $member_ike);
                                            }
                                        }
                                    }

                                    if ($ipsec_dh_group != ""){
                                        $ipsec_crypto->addChild("dh-group");
                                        $ipsec_crypto->{'dh-group'} = $ipsec_dh_group;
                                    }
                                    if ($ipsec_seconds != 0){
                                        $ipsec_crypto->addChild("lifetime");
                                        $ipsec_crypto->{'lifetime'}->seconds = $ipsec_seconds;
                                    }
                                    if ($ipsec_minutes != 0){
                                        $ipsec_crypto->addChild("lifetime");
                                        $ipsec_crypto->{'lifetime'}->minutes = $ipsec_minutes;
                                    }
                                    if ($ipsec_hours != 0){
                                        $ipsec_crypto->addChild("lifetime");
                                        $ipsec_crypto->{'lifetime'}->hours = $ipsec_hours;
                                    }
                                    if ($ipsec_days != 0){
                                        $ipsec_crypto->addChild("lifetime");
                                        $ipsec_crypto->{'lifetime'}->days = $ipsec_days;
                                    }

                                    if ($ipsec_kb != 0){
                                        $ipsec_crypto->addChild("lifesize");
                                        $ipsec_crypto->{'lifesize'}->kb = $ipsec_kb;
                                    }
                                    if ($ipsec_mb != 0){
                                        $ipsec_crypto->addChild("lifesize");
                                        $ipsec_crypto->{'lifesize'}->mb = $ipsec_mb;
                                    }
                                    if ($ipsec_gb != 0){
                                        $ipsec_crypto->addChild("lifesize");
                                        $ipsec_crypto->{'lifesize'}->gb = $ipsec_gb;
                                    }
                                    if ($ipsec_tb != 0){
                                        $ipsec_crypto->addChild("lifesize");
                                        $ipsec_crypto->{'lifesize'}->tb = $ipsec_tb;
                                    }
                                }
                            }
                            else{
                                $SA = $xml->xpath("/config/devices/entry/network/ike/crypto-profiles/ipsec-crypto-profiles");
                                unset($SA[0][0]);
                            }

                            # GLOBAL PROTECT IPSEC CRYPTO
                            
                            if (isset($myTemplateDeviceNetworkIKE->{'global-protect-app-crypto-profiles'})){
                                $SA = $myTemplateDeviceNetworkIKE->xpath("global-protect-app-crypto-profiles");
                                unset($SA[0][0]);
                            }
                            $getIKECrypto = $projectdb->query("SELECT name, encryption, hash FROM global_protect_app_ipsec_crypto_profiles WHERE source='$source' AND template='$template' AND name != '';");
                            if ($getIKECrypto->num_rows > 0){
                                if (!isset($myTemplateDeviceNetworkIKE->{'global-protect-app-crypto-profiles'})){
                                    $myTemplateDeviceNetworkIKE->addChild("global-protect-app-crypto-profiles");
                                }
                                $ike_crypto_path = $myTemplateDeviceNetworkIKE->{'global-protect-app-crypto-profiles'};
                                
                                while ($dataIKEC = $getIKECrypto->fetch_assoc()){
                                    $myname = $dataIKEC['name'];
                                    $ike_encryption = $dataIKEC['encryption'];
                                    $ike_hash = $dataIKEC['hash'];
                                    
                                    $ike_crypto = $ike_crypto_path->addChild('entry');
                                    $ike_crypto->addAttribute('name', $dataIKEC['name']);
                                    
                                    if ($ike_encryption != ""){
                                        $ike_crypto->addChild("encryption");
                                        $ike_encryption_array = explode(",", $ike_encryption);
                                        foreach($ike_encryption_array as $member_ike){
                                            $ike_crypto->encryption->addChild("member", $member_ike);
                                        }
                                    }
                                    if ($ike_hash != ""){
                                        $ike_crypto->addChild("authentication");
                                        $ike_hash_array = explode(",", $ike_hash);
                                        foreach($ike_hash_array as $member_ike){
                                            $ike_crypto->authentication->addChild("member", $member_ike);
                                        }
                                    }
                                }
                            }
                            else{
                                $SA = $xml->xpath("/config/devices/entry/network/ike/crypto-profiles/global-protect-app-crypto-profiles");
                                unset($SA[0][0]);
                            }

                            
                            # IKE GATEWAYS
                            
                            if (isset($myTemplateDeviceNetworkIKE_only->gateway)){
                                $SA = $myTemplateDeviceNetworkIKE_only->xpath("gateway");
                                unset($SA[0][0]);
                            }
                            $getIKEGateways = $projectdb->query("SELECT name, version, dpd_ikev1, ike_interval_ikev1, retry_ikev1, ike_crypto_profile_ikev1, exchange_mode_ikev1, dpd_ikev2, ike_interval_ikev2, ike_crypto_profile_ikev2, require_cookie_ikev2, local_address_ip, interface, type_authentication, pre_shared_key, allow_id_payload_mismatch, local_certificate, certificate_profile, strict_validation_revocation, hash_and_url, base_url, nat_traversal, passive_mode, fragmentation, peer_ip_type, peer_ip_address, local_id, local_id_type, peer_id, peer_id_type, peer_id_matching, address_type  FROM ike_gateways_profiles WHERE source = '$source' AND template = '$template' AND name != '';");
                            if ($getIKEGateways->num_rows > 0){
                                if (!isset($myTemplateDeviceNetworkIKE_only->gateway)){
                                    $myTemplateDeviceNetworkIKE_only->addChild("gateway");
                                }
                                $ike_gateways_xpath = $myTemplateDeviceNetworkIKE_only->gateway;
                                
                                while ($dataIKEGat = $getIKEGateways->fetch_assoc()){
                                    $myname = $dataIKEGat['name'];
                                    $ike_gat_version = $dataIKEGat['version'];
                                    $ike_gat_dpd_ikev1 = $dataIKEGat['dpd_ikev1'];
                                    $ike_gat_ike_interval_ikev1 = $dataIKEGat['ike_interval_ikev1'];
                                    $ike_gat_retry_ikev1 = $dataIKEGat['retry_ikev1'];
                                    $ike_gat_ike_crypto_profile_ikev1 = $dataIKEGat['ike_crypto_profile_ikev1'];
                                    $ike_gat_exchange_mode_ikev1 = $dataIKEGat['exchange_mode_ikev1'];
                                    $ike_gat_dpd_ikev2 = $dataIKEGat['dpd_ikev2'];
                                    $ike_gat_ike_interval_ikev2 = $dataIKEGat['ike_interval_ikev2'];
                                    $ike_gat_ike_crypto_profile_ikev2 = $dataIKEGat['ike_crypto_profile_ikev2'];
                                    $ike_gat_require_cookie_ikev2 = $dataIKEGat['require_cookie_ikev2'];
                                    $ike_gat_local_address_ip = $dataIKEGat['local_address_ip'];
                                    $ike_gat_interface = $dataIKEGat['interface'];
                                    $ike_gat_type_authentication = $dataIKEGat['type_authentication'];
                                    $ike_gat_pre_shared_key = $dataIKEGat['pre_shared_key'];
                                    $ike_gat_allow_id_payload_mismatch = $dataIKEGat['allow_id_payload_mismatch'];
                                    $ike_gat_local_certificate = $dataIKEGat['local_certificate'];
                                    $ike_gat_certificate_profile = $dataIKEGat['certificate_profile'];
                                    $ike_gat_strict_validation_revocation = $dataIKEGat['strict_validation_revocation'];
                                    $ike_gat_hash_and_url = $dataIKEGat['hash_and_url'];
                                    $ike_gat_base_url = $dataIKEGat['base_url'];
                                    $ike_gat_nat_traversal = $dataIKEGat['nat_traversal'];
                                    $ike_gat_passive_mode = $dataIKEGat['passive_mode'];
                                    $ike_gat_fragmentation = $dataIKEGat['fragmentation'];
                                    $ike_gat_peer_ip_type = $dataIKEGat['peer_ip_type'];
                                    $ike_gat_peer_ip_address = $dataIKEGat['peer_ip_address'];
                                    $ike_gat_local_id = $dataIKEGat['local_id'];
                                    $ike_gat_local_id_type = $dataIKEGat['local_id_type'];
                                    $ike_gat_peer_id = $dataIKEGat['peer_id'];
                                    $ike_gat_peer_id_type = $dataIKEGat['peer_id_type'];
                                    $ike_gat_peer_id_matching = $dataIKEGat['peer_id_matching'];
                                    $ike_gat_address_type = $dataIKEGat['address_type'];

                                    $ike_gateways = $ike_gateways_xpath->addChild('entry');
                                    $ike_gateways->addAttribute('name', $dataIKEGat['name']);
                                    
                                    if($ike_gat_dpd_ikev1 != ""){
                                        $ike_gateways->addChild("protocol");
                                        $ike_gateways->protocol->addChild("ikev1");
                                        $ike_gateways->protocol->ikev1->addChild("dpd");
                                        $ike_gateways->protocol->ikev1->dpd->enable = $ike_gat_dpd_ikev1;

                                        if($ike_gat_dpd_ikev1 == "yes"){
                                            //$ike_gateways->protocol->ikev1->dpd->addChild("interval", $ike_gat_ike_interval_ikev1);
                                            $ike_gateways->protocol->ikev1->dpd->interval = $ike_gat_ike_interval_ikev1;
                                            $ike_gateways->protocol->ikev1->dpd->retry = $ike_gat_retry_ikev1;
                                        }

                                        if(($ike_gat_ike_crypto_profile_ikev1 != "") && ($ike_gat_ike_crypto_profile_ikev1 != "default")){
                                            $ike_gateways->protocol->ikev1->{'ike-crypto-profile'} = $ike_gat_ike_crypto_profile_ikev1;
                                        }

                                        if($ike_gat_exchange_mode_ikev1 != ""){
                                            $ike_gateways->protocol->ikev1->{'exchange-mode'} = $ike_gat_exchange_mode_ikev1;
                                        }
                                    }

                                    // IKE V2 PARA LA VERSIÓN 7
                                    if($version >= 7){
                                        if($ike_gat_dpd_ikev2 != ""){

                                            $ike_gateways->protocol->ikev2->dpd->enable = $ike_gat_dpd_ikev2;
                                            $ike_gateways->protocol->ikev2->dpd->interval = $ike_gat_ike_interval_ikev2;

                                            if($ike_gat_ike_crypto_profile_ikev2 != ""){
                                                $ike_gateways->protocol->ikev2->{'ike-crypto-profile'} = $ike_gat_ike_crypto_profile_ikev2;
                                            }

                                            if($ike_gat_require_cookie_ikev2 != ""){
                                                $ike_gateways->protocol->ikev2->{'require-cookie'} = $ike_gat_require_cookie_ikev2;
                                            }

                                            if($ike_gat_version != ""){
                                                $ike_gateways->protocol->version = $ike_gat_version;
                                            }

                                        }
                                    }
                            
                                    if($ike_gat_interface != ""){
                                        $ike_gateways->addChild("local-address");
                                        $ike_gateways->{'local-address'}->interface = $ike_gat_interface;
                                        if($ike_gat_local_address_ip != ""){
                                            $ike_gateways->{'local-address'}->ip = $ike_gat_local_address_ip;
                                        }
                                    }

                                    if($ike_gat_type_authentication == "pre-shared-key"){
                                        $ike_gateways->addChild("authentication");
                                        $ike_gateways->authentication->{'pre-shared-key'}->key = $ike_gat_pre_shared_key;
                                    }
                                    elseif($ike_gat_type_authentication == "certificate"){
                                        if($version < 7){
                                    
                                            $ike_gateways->addChild("authentication");

                                            if($ike_gat_allow_id_payload_mismatch == "yes"){
                                                $ike_gateways->authentication->certificate->{'allow-id-payload-mismatch'} = $ike_gat_allow_id_payload_mismatch;
                                            }
                                            $ike_gateways->authentication->certificate->{'local-certificate'} = $ike_gat_local_certificate;
                                            $ike_gateways->authentication->certificate->{'certificate-profile'} = $ike_gat_certificate_profile;

                                            if($ike_gat_strict_validation_revocation == "yes"){
                                                $ike_gateways->authentication->certificate->{'strict-validation-revocation'} = $ike_gat_strict_validation_revocation;
                                            }
                                        }
                                        else{
                                            // Version 7
                                            $ike_gateways->addChild("authentication");

                                            if($ike_gat_local_certificate != ""){
                                                $ike_gateways->authentication->certificate->{'local-certificate'}->name = $ike_gat_local_certificate;

                                                if($ike_gat_hash_and_url == "yes"){
                                                    $ike_gateways->authentication->certificate->{'local-certificate'}->{'hash-and-url'}->enable = $ike_gat_hash_and_url;
                                                    $ike_gateways->authentication->certificate->{'local-certificate'}->{'hash-and-url'}->{'base-url'} = $ike_gat_base_url;
                                                }
                                            }
                                            if($ike_gat_allow_id_payload_mismatch == "yes"){
                                                $ike_gateways->authentication->certificate->{'allow-id-payload-mismatch'} = $ike_gat_allow_id_payload_mismatch;
                                            }
                                            $ike_gateways->authentication->certificate->{'certificate-profile'} = $ike_gat_certificate_profile;

                                            if($ike_gat_strict_validation_revocation == "yes"){
                                                $ike_gateways->authentication->certificate->{'strict-validation-revocation'} = $ike_gat_strict_validation_revocation;
                                            }
                                        }
                                    }

                                    if($ike_gat_nat_traversal != ""){
                                        $ike_gateways->addChild("protocol-common");
                                        $ike_gateways->{'protocol-common'}->{'nat-traversal'}->enable = $ike_gat_nat_traversal;
                                        if($ike_gat_passive_mode == "yes"){
                                            $ike_gateways->{'protocol-common'}->{'passive-mode'} = $ike_gat_passive_mode;
                                        }
                                        if ($version > 5) {
                                            if($ike_gat_fragmentation == ""){
                                                $ike_gat_fragmentation = "no";
                                            }
                                            $ike_gateways->{'protocol-common'}->fragmentation->enable = $ike_gat_fragmentation;
                                        }
                                        
                                    }

                                    if($ike_gat_peer_ip_type == "static"){
                                        $ike_gateways->addChild("peer-address");
                                        $ike_gateways->{'peer-address'}->ip = $ike_gat_peer_ip_address;
                                    }else{
                                        $ike_gateways->addChild("peer-address");
                                        $ike_gateways->{'peer-address'}->addChild("dynamic");
                                    }

                                    if($ike_gat_local_id != ""){
                                        $ike_gateways->addChild("local-id");
                                        $ike_gateways->{'local-id'}->id = $ike_gat_local_id;
                                        $ike_gateways->{'local-id'}->type = $ike_gat_local_id_type;
                                    }

                                    if($ike_gat_peer_id != ""){
                                        $ike_gateways->addChild("peer-id");
                                        $ike_gateways->{'peer-id'}->id = $ike_gat_peer_id;
                                        $ike_gateways->{'peer-id'}->type = $ike_gat_peer_id_type;
                                        if($ike_gat_peer_id_matching != ""){
                                            $ike_gateways->{'peer-id'}->matching = $ike_gat_peer_id_matching;
                                        }
                                    }
                                    
                                    // Version 7
                                    if($ike_gat_address_type == "ipv6"){
                                        $ike_gateways->ipv6 = "yes";
                                    }
                                }
                            }
                            else{
                                $SA = $xml->xpath("/config/devices/entry/network/ike/gateway");
                                unset($SA[0][0]);
                            }

                            # Template - Device - Network - TUNNEL
                            if (!isset($myTemplateDeviceNetwork->tunnel)){
                                $myTemplateDeviceNetworkTunnel = $myTemplateDeviceNetwork->addChild("tunnel");
                            }
                            else {
                                $myTemplateDeviceNetworkTunnel = $myTemplateDeviceNetwork->tunnel;
                            }
                            
                            # IPSEC TUNNEL
                
                            if (isset($myTemplateDeviceNetworkTunnel->ipsec)){
                                $SA = $myTemplateDeviceNetworkTunnel->xpath("ipsec");
                                unset($SA[0][0]);
                            }
                            $getIPSecTunnel = $projectdb->query("SELECT id, name, anti_replay, copy_tos, tunnel_monitor, destination_ip, tunnel_monitor_profile, tunnel_interface, address_type, type_tunnel, ike_gateway, ipsec_crypto_profile, protocol, authentication, key_auth, encryption, key_encry, local_address_ip, interface, peer_ip_address, local_spi, remote_spi, external_ca, certificate_profile, local_certificate, publish_connected_routes, portal_address, publish_routes FROM ipsec_tunnel WHERE source = '$source' AND template = '$template' AND name != '';");
                            if ($getIPSecTunnel->num_rows > 0){
                                if (!isset($myTemplateDeviceNetworkTunnel->ipsec)){
                                    $myTemplateDeviceNetworkTunnel->addChild("ipsec");
                                }
                                $ike_ipsec_tunnel_xpath = $myTemplateDeviceNetworkTunnel->ipsec;
                                
                                while ($dataIPSecTunnel = $getIPSecTunnel->fetch_assoc()){
                                    
                                    $myname = $dataIPSecTunnel['name'];
                                    $ipsec_tun_id = $dataIPSecTunnel['id'];
                                    $ipsec_tun_anti_replay = $dataIPSecTunnel['anti_replay'];
                                    $ipsec_tun_copy_tos = $dataIPSecTunnel['copy_tos'];
                                    $ipsec_tun_tunnel_monitor = $dataIPSecTunnel['tunnel_monitor'];
                                    $ipsec_tun_destination_ip = $dataIPSecTunnel['destination_ip'];
                                    $ipsec_tun_tunnel_monitor_profile = $dataIPSecTunnel['tunnel_monitor_profile'];
                                    $ipsec_tun_tunnel_interface = $dataIPSecTunnel['tunnel_interface'];
                                    $ipsec_tun_address_type = $dataIPSecTunnel['address_type'];
                                    $ipsec_tun_type_tunnel = $dataIPSecTunnel['type_tunnel'];
                                    $ipsec_tun_ike_gateway = $dataIPSecTunnel['ike_gateway'];
                                    $ipsec_tun_ipsec_crypto_profile = $dataIPSecTunnel['ipsec_crypto_profile'];
                                    $ipsec_tun_protocol = $dataIPSecTunnel['protocol'];
                                    $ipsec_tun_authentication = $dataIPSecTunnel['authentication'];
                                    $ipsec_tun_key_auth = $dataIPSecTunnel['key_auth'];
                                    $ipsec_tun_encryption = $dataIPSecTunnel['encryption'];
                                    $ipsec_tun_key_encry = $dataIPSecTunnel['key_encry'];
                                    $ipsec_tun_local_address_ip = $dataIPSecTunnel['local_address_ip'];
                                    $ipsec_tun_interface = $dataIPSecTunnel['interface'];
                                    $ipsec_tun_peer_ip_address = $dataIPSecTunnel['peer_ip_address'];
                                    $ipsec_tun_local_spi = $dataIPSecTunnel['local_spi'];
                                    $ipsec_tun_remote_spi = $dataIPSecTunnel['remote_spi'];
                                    $ipsec_tun_external_ca = $dataIPSecTunnel['external_ca'];
                                    $ipsec_tun_certificate_profile = $dataIPSecTunnel['certificate_profile'];
                                    $ipsec_tun_local_certificate = $dataIPSecTunnel['local_certificate'];
                                    $ipsec_tun_publish_connected_routes = $dataIPSecTunnel['publish_connected_routes'];
                                    $ipsec_tun_portal_address = $dataIPSecTunnel['portal_address'];
                                    $ipsec_tun_publish_routes = $dataIPSecTunnel['publish_routes'];

                                    $ipsec_tunnel = $ike_ipsec_tunnel_xpath->addChild('entry');
                                    $ipsec_tunnel->addAttribute('name', $dataIPSecTunnel['name']);
                                    
                                    # Auto Key
                                    if($ipsec_tun_type_tunnel == "auto-key"){

                                        $ipsec_tunnel->addChild("auto-key");

                                        if($ipsec_tun_ike_gateway != ""){
                                            $ipsec_tunnel->{'auto-key'}->addChild("ike-gateway");
                                            $ipsec_tunnel->{'auto-key'}->{'ike-gateway'}->addChild('entry')->addAttribute('name', $ipsec_tun_ike_gateway);
                                        }

                                        // Mirar si hay Proxy ID type = v4
                                        $getProxyID = $projectdb->query("SELECT name, protocol, local_port, remote_port, number, local, remote, type FROM proxy_id_ipsec_tunnel WHERE ipsec_tunnel_id = '$ipsec_tun_id' AND name != '' AND type = 'v4' AND template = '$template' AND source = '$source';");
                                        if ($getProxyID->num_rows > 0){

                                            $ipsec_tunnel->{'auto-key'}->addChild("proxy-id");
                                            $ike_ipsec_tunnel_xpath_proxy_id = $ipsec_tunnel->{'auto-key'}->{'proxy-id'};

                                            while($dataPI = $getProxyID->fetch_assoc()){

                                                $name_proxy_id = $dataPI['name'];
                                                $protocol_proxy_id = $dataPI['protocol'];
                                                $local_port_proxy_id = $dataPI['local_port'];
                                                $remote_port_proxy_id = $dataPI['remote_port'];
                                                $number_proxy_id = $dataPI['number'];
                                                $local_proxy_id = $dataPI['local'];
                                                $remote_proxy_id = $dataPI['remote'];
                                                $type_proxy_id = $dataPI['type'];

                                                $ipsec_tunnel_proxy_id = $ike_ipsec_tunnel_xpath_proxy_id->addChild('entry');
                                                $ipsec_tunnel_proxy_id->addAttribute('name', $name_proxy_id);

                                                if ($protocol_proxy_id == "TCP"){
                                                    $ipsec_tunnel_proxy_id->addChild("protocol");
                                                    $ipsec_tunnel_proxy_id->protocol->addChild("tcp");
                                                    //$ipsec_tunnel->{'auto-key'}->{'proxy-id'}->protocol->addChild("tcp");
                                                    if($local_port_proxy_id == ""){
                                                        $local_port_proxy_id = 0;
                                                    }
                                                    if($remote_port_proxy_id == ""){
                                                        $remote_port_proxy_id = 0;
                                                    }
                                                    $ipsec_tunnel_proxy_id->protocol->tcp->{'local-port'} = $local_port_proxy_id;
                                                    $ipsec_tunnel_proxy_id->protocol->tcp->{'remote-port'} = $remote_port_proxy_id;
                                                }
                                                elseif($protocol_proxy_id == "Number"){
                                                    $ipsec_tunnel_proxy_id->addChild("protocol");
                                                    $ipsec_tunnel_proxy_id->protocol->addChild("number");
                                                    $ipsec_tunnel_proxy_id->protocol->number = $number_proxy_id;
                                                }
                                                elseif($protocol_proxy_id == "Any"){
                                                    $ipsec_tunnel_proxy_id->addChild("protocol");
                                                    $ipsec_tunnel_proxy_id->protocol->addChild("any");;
                                                }
                                                elseif($protocol_proxy_id == "UDP"){
                                                    $ipsec_tunnel_proxy_id->addChild("protocol");
                                                    $ipsec_tunnel_proxy_id->protocol->addChild("udp");
                                                    if($local_port_proxy_id == ""){
                                                        $local_port_proxy_id = 0;
                                                    }
                                                    if($remote_port_proxy_id == ""){
                                                        $remote_port_proxy_id = 0;
                                                    }
                                                    $ipsec_tunnel_proxy_id->protocol->udp->{'local-port'} = $local_port_proxy_id;
                                                    $ipsec_tunnel_proxy_id->protocol->udp->{'remote-port'} = $remote_port_proxy_id;
                                                }

                                                if($local_proxy_id != ""){
                                                    $ipsec_tunnel_proxy_id->addChild("local");
                                                    $ipsec_tunnel_proxy_id->local = $local_proxy_id;
                                                }
                                                if($remote_proxy_id != ""){
                                                    $ipsec_tunnel_proxy_id->addChild("remote");
                                                    $ipsec_tunnel_proxy_id->remote = $remote_proxy_id;
                                                }
                                            }
                                        }

                                        // Mirar si hay Proxy ID type = v6
                                        $getProxyID = $projectdb->query("SELECT name, protocol, local_port, remote_port, number, local, remote, type FROM proxy_id_ipsec_tunnel WHERE ipsec_tunnel_id = '$ipsec_tun_id' AND name != '' AND type = 'v6' AND template = '$template' AND source = '$source';");
                                        if ($getProxyID->num_rows > 0){

                                            $ipsec_tunnel->{'auto-key'}->addChild("proxy-id-v6");
                                            $ike_ipsec_tunnel_xpath_proxy_id_v6 = $ipsec_tunnel->{'auto-key'}->{'proxy-id-v6'};

                                            while($dataPI = $getProxyID->fetch_assoc()){

                                                $name_proxy_id = $dataPI['name'];
                                                $protocol_proxy_id = $dataPI['protocol'];
                                                $local_port_proxy_id = $dataPI['local_port'];
                                                $remote_port_proxy_id = $dataPI['remote_port'];
                                                $number_proxy_id = $dataPI['number'];
                                                $local_proxy_id = $dataPI['local'];
                                                $remote_proxy_id = $dataPI['remote'];
                                                $type_proxy_id = $dataPI['type'];

                                                $ipsec_tunnel_proxy_id_v6 = $ike_ipsec_tunnel_xpath_proxy_id_v6->addChild('entry');
                                                $ipsec_tunnel_proxy_id_v6->addAttribute('name', $name_proxy_id);

                                                if ($protocol_proxy_id == "TCP"){
                                                    $ipsec_tunnel_proxy_id_v6->addChild("protocol");
                                                    $ipsec_tunnel_proxy_id_v6->protocol->addChild("tcp");
                                                    //$ipsec_tunnel->{'auto-key'}->{'proxy-id'}->protocol->addChild("tcp");
                                                    if($local_port_proxy_id == ""){
                                                        $local_port_proxy_id = 0;
                                                    }
                                                    if($remote_port_proxy_id == ""){
                                                        $remote_port_proxy_id = 0;
                                                    }
                                                    $ipsec_tunnel_proxy_id_v6->protocol->tcp->{'local-port'} = $local_port_proxy_id;
                                                    $ipsec_tunnel_proxy_id_v6->protocol->tcp->{'remote-port'} = $remote_port_proxy_id;
                                                }
                                                elseif($protocol_proxy_id == "Number"){
                                                    $ipsec_tunnel_proxy_id_v6->addChild("protocol");
                                                    $ipsec_tunnel_proxy_id_v6->protocol->addChild("number");
                                                    $ipsec_tunnel_proxy_id_v6->protocol->number = $number_proxy_id;
                                                }
                                                elseif($protocol_proxy_id == "Any"){
                                                    $ipsec_tunnel_proxy_id_v6->addChild("protocol");
                                                    $ipsec_tunnel_proxy_id_v6->protocol->addChild("any");;
                                                }
                                                elseif($protocol_proxy_id == "UDP"){
                                                    $ipsec_tunnel_proxy_id_v6->addChild("protocol");
                                                    $ipsec_tunnel_proxy_id_v6->protocol->addChild("udp");
                                                    if($local_port_proxy_id == ""){
                                                        $local_port_proxy_id = 0;
                                                    }
                                                    if($remote_port_proxy_id == ""){
                                                        $remote_port_proxy_id = 0;
                                                    }
                                                    $ipsec_tunnel_proxy_id_v6->protocol->udp->{'local-port'} = $local_port_proxy_id;
                                                    $ipsec_tunnel_proxy_id_v6->protocol->udp->{'remote-port'} = $remote_port_proxy_id;
                                                }

                                                if($local_proxy_id != ""){
                                                    $ipsec_tunnel_proxy_id_v6->addChild("local");
                                                    $ipsec_tunnel_proxy_id_v6->local = $local_proxy_id;
                                                }
                                                if($remote_proxy_id != ""){
                                                    $ipsec_tunnel_proxy_id_v6->addChild("remote");
                                                    $ipsec_tunnel_proxy_id_v6->remote = $remote_proxy_id;
                                                }
                                            }
                                        }

                                        if($ipsec_tun_ipsec_crypto_profile != ""){
                                            $ipsec_tunnel->{'auto-key'}->addChild("ipsec-crypto-profile");
                                            $ipsec_tunnel->{'auto-key'}->{'ipsec-crypto-profile'} = $ipsec_tun_ipsec_crypto_profile;
                                        }
                                    } # Manual Key
                                    elseif ($ipsec_tun_type_tunnel == "manual-key"){

                                        $ipsec_tunnel->addChild("manual-key");

                                        if($ipsec_tun_protocol == "ESP"){

                                            $ipsec_tunnel->{'manual-key'}->addChild("esp");

                                            if($ipsec_tun_authentication == "none"){
                                                $ipsec_tunnel->{'manual-key'}->esp->addChild("authentication");
                                                $ipsec_tunnel->{'manual-key'}->esp->authentication->addChild("none");
                                            }else{
                                                //authentication->md5->key
                                                $ipsec_tunnel->{'manual-key'}->esp->addChild("authentication");
                                                $ipsec_tunnel->{'manual-key'}->esp->authentication->addChild($ipsec_tun_authentication);
                                                $ipsec_tunnel->{'manual-key'}->esp->authentication->$ipsec_tun_authentication->key = $ipsec_tun_key_auth;
                                            }

                                            if($ipsec_tun_encryption != ""){
                                                $ipsec_tunnel->{'manual-key'}->esp->addChild("encryption");
                                                $ipsec_tunnel->{'manual-key'}->esp->encryption->algorithm = $ipsec_tun_encryption;

                                                if($ipsec_tun_key_encry != ""){
                                                    $ipsec_tunnel->{'manual-key'}->esp->encryption->key = $ipsec_tun_key_encry;
                                                }
                                            }
                                        }

                                        if($ipsec_tun_protocol == "AH"){

                                            $ipsec_tunnel->{'manual-key'}->addChild("ah");

                                            if($ipsec_tun_authentication == "none"){
                                                $ipsec_tunnel->{'manual-key'}->ah->addChild("authentication");
                                                $ipsec_tunnel->{'manual-key'}->ah->authentication->addChild("none");
                                            }else{
                                                //authentication->md5->key
                                                $ipsec_tunnel->{'manual-key'}->ah->addChild("authentication");
                                                $ipsec_tunnel->{'manual-key'}->ah->authentication->addChild($ipsec_tun_authentication);
                                                $ipsec_tunnel->{'manual-key'}->ah->authentication->$ipsec_tun_authentication->key = $ipsec_tun_key_auth;
                                            }
                                        }

                                        if($ipsec_tun_interface != ""){
                                            $ipsec_tunnel->{'manual-key'}->addChild("local-address");
                                            if(($ipsec_tun_local_address_ip != "") && ($ipsec_tun_local_address_ip != "None")){
                                                $ipsec_tunnel->{'manual-key'}->{'local-address'}->ip = $ipsec_tun_local_address_ip;
                                            }
                                            $ipsec_tunnel->{'manual-key'}->{'local-address'}->interface = $ipsec_tun_interface;
                                        }

                                        if($ipsec_tun_peer_ip_address != ""){
                                            $ipsec_tunnel->{'manual-key'}->addChild("peer-address");
                                            $ipsec_tunnel->{'manual-key'}->{'peer-address'}->ip = $ipsec_tun_peer_ip_address;
                                        }

                                        if($ipsec_tun_local_spi != ""){
                                            $ipsec_tunnel->{'manual-key'}->{'local-spi'} = $ipsec_tun_local_spi;
                                        }

                                        if($ipsec_tun_remote_spi != ""){
                                            $ipsec_tunnel->{'manual-key'}->{'remote-spi'} = $ipsec_tun_remote_spi;
                                        }

                                    } # Global Protect Satellite
                                    elseif ($ipsec_tun_type_tunnel == "global-protect-satellite"){

                                        $ipsec_tunnel->addChild("global-protect-satellite");

                                        if($ipsec_tun_publish_connected_routes == "yes"){
                                            $ipsec_tunnel->{'global-protect-satellite'}->addChild("publish-connected-routes");
                                            $ipsec_tunnel->{'global-protect-satellite'}->{'publish-connected-routes'}->enable = $ipsec_tun_publish_connected_routes;
                                        }

                                        if($ipsec_tun_interface != ""){
                                            $ipsec_tunnel->{'global-protect-satellite'}->addChild("local-address");
                                            if(($ipsec_tun_local_address_ip != "") && ($ipsec_tun_local_address_ip != "None")){
                                                $ipsec_tunnel->{'global-protect-satellite'}->{'local-address'}->ip = $ipsec_tun_local_address_ip;
                                            }
                                            $ipsec_tunnel->{'global-protect-satellite'}->{'local-address'}->interface = $ipsec_tun_interface;
                                        }

                                        if($ipsec_tun_portal_address != ""){
                                            $ipsec_tunnel->{'global-protect-satellite'}->{'portal-address'} = $ipsec_tun_portal_address;
                                        }

                                        if($ipsec_tun_publish_routes != ""){
                                            $ipsec_tunnel->{'global-protect-satellite'}->addChild("publish-routes");
                                            $ipsec_tun_publish_routes_array = explode(",", $ipsec_tun_publish_routes);
                                            foreach($ipsec_tun_publish_routes_array as $member_publish){
                                                $ipsec_tunnel->{'global-protect-satellite'}->{'publish-routes'}->addChild("member", $member_publish);
                                            }
                                        }

                                        if($ipsec_tun_external_ca == "yes"){
                                            $ipsec_tunnel->{'global-protect-satellite'}->addChild("external-ca");
                                            if($ipsec_tun_certificate_profile != ""){
                                                $ipsec_tunnel->{'global-protect-satellite'}->{'external-ca'}->{'certificate-profile'} = $ipsec_tun_certificate_profile;
                                            }
                                            if($ipsec_tun_local_certificate != ""){
                                                $ipsec_tunnel->{'global-protect-satellite'}->{'external-ca'}->{'local-certificate'} = $ipsec_tun_local_certificate;
                                            }
                                        }

                                    }

                                    if($ipsec_tun_tunnel_monitor != ""){
                                        $ipsec_tunnel->addChild("tunnel-monitor");
                                        $ipsec_tunnel->{'tunnel-monitor'}->enable = $ipsec_tun_tunnel_monitor;

                                        if($ipsec_tun_destination_ip != ""){
                                            $ipsec_tunnel->{'tunnel-monitor'}->{'destination-ip'} = $ipsec_tun_destination_ip;
                                        }

                                        if($ipsec_tun_tunnel_monitor_profile != ""){
                                            $ipsec_tunnel->{'tunnel-monitor'}->{'tunnel-monitor-profile'} = $ipsec_tun_tunnel_monitor_profile;
                                        }
                                    }

                                    if($ipsec_tun_copy_tos == "yes"){
                                        $ipsec_tunnel->{'copy-tos'} = $ipsec_tun_copy_tos;
                                    }

                                    // Version 7
                                    if($ipsec_tun_address_type == "ipv6"){
                                        $ipsec_tunnel->ipv6 = "yes";
                                    }

                                    if($ipsec_tun_tunnel_interface != ""){
                                        $ipsec_tunnel->{'tunnel-interface'} = $ipsec_tun_tunnel_interface;
                                    }

                                    if($ipsec_tun_anti_replay == "yes"){
                                        $ipsec_tunnel->{'anti-replay'} = $ipsec_tun_anti_replay;
                                    }
                                }
                            }
                            else{
                                $SA = $xml->xpath("/config/devices/entry/network/tunnel/ipsec");
                                unset($SA[0][0]);
                            }
                            
                            # Template - Device - Network - Interfaces
                            if (isset($myTemplateDeviceNetwork->interface)){
                                $SA=$myTemplateDeviceNetwork->xpath("interface");
                                unset($SA[0][0]);
                            }
                            $myTemplateDeviceNetwork->addChild("interface");
                            $theINT = $myTemplateDeviceNetwork->interface;

       
                            #Interfaces
                            $getInterfaces = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' LIMIT 1;");
                            if ($getInterfaces->num_rows > 0) {
                                #Aggregate-Ethernet
                                $getIntEthernet = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='aggregate-ethernet' AND unittag='0' AND name=unitname GROUP BY name ORDER BY name");
                                if ($getIntEthernet->num_rows > 0) {
                                    $theINT->addChild("aggregate-ethernet");
                                    while ($getIntEthernetData = $getIntEthernet->fetch_assoc()) {
                                        $myname = $getIntEthernetData['name'];
                                        $int2 = $theINT->{'aggregate-ethernet'}->addChild('entry');
                                        $int2->addAttribute('name', $myname);

                                        if ($getIntEthernetData['comment'] != "") {
                                            $int2->addChild("comment");
                                            $int2->comment = $getIntEthernetData['comment'];
                                        }

                                        if ($getIntEthernetData['type'] == "virtual-wire") {
                                            $int2->addChild("virtual-wire");
                                            if ($getIntEthernetData['netflow_profile'] != "") {
                                                $int2->{'virtual-wire'}->addChild("netflow-profile", $getIntEthernetData['netflow_profile']);
                                            }
                                            $getUnits = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='aggregate-ethernet' AND unitname!='$myname' AND name='$myname';");
                                            if ($getUnits->num_rows > 0) {
                                                $int2->{'virtual-wire'}->addChild("units");
                                                while ($getUnitsData = $getUnits->fetch_assoc()) {
                                                    $myname1 = $getUnitsData['unitname'];
                                                    $VWUnit = $int2->{'virtual-wire'}->units->addChild('entry');
                                                    $VWUnit->addAttribute('name', $myname1);
                                                    if ($getUnitsData['comment'] != "") {
                                                        $VWUnit->addChild("comment");
                                                        $VWUnit->comment = $getUnitsData['comment'];
                                                    }
                                                    if ($getUnitsData['netflow_profile'] != "") {
                                                        $VWUnit->addChild("netflow-profile", $getUnitsData['netflow_profile']);
                                                    }

                                                    $VWUnit->addChild("tag", $getUnitsData['unittag']);

                                                    if ($getUnitsData['ip_classifier'] != "") {
                                                        $interfaces_all = explode(",", $getUnitsData['ip_classifier']);
                                                        $VWUnit->addChild("ip-classifier");
                                                        foreach ($interfaces_all as $key => $int_value) {
                                                            $VWUnit->{'ip-classifier'}->addChild("member", $int_value);
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        if ($getIntEthernetData['type'] == "layer2") {
                                            $int2->addChild("layer2");
                                            if ($getIntEthernetData['netflow_profile'] != "") {
                                                $int2->layer2->addChild("netflow-profile", $getIntEthernetData['netflow_profile']);
                                            }
                                            if ($version>=7){
                                                if ($getIntEthernetData['lldp'] != "") {
                                                    $xml_append = simplexml_load_string($getIntEthernetData['lldp']);
                                                    SimpleXMLElement_append($int2->layer2, $xml_append);
                                                }
                                            }
                                            $getUnits = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='aggregate-ethernet' AND unitname!='$myname' AND name='$myname';");
                                            if ($getUnits->num_rows > 0) {
                                                $int2->{'layer2'}->addChild("units");
                                                while ($getUnitsData = $getUnits->fetch_assoc()) {
                                                    $myname1 = $getUnitsData['unitname'];
                                                    $VWUnit = $int2->{'layer2'}->units->addChild('entry');
                                                    $VWUnit->addAttribute('name', $myname1);
                                                    if ($getUnitsData['netflow_profile'] != "") {
                                                        $VWUnit->addChild("netflow-profile", $getUnitsData['netflow_profile']);
                                                    }
                                                    if ($getUnitsData['comment'] != "") {
                                                        $VWUnit->addChild("comment");
                                                        $VWUnit->comment = $getUnitsData['comment'];
                                                    }
                                                    $VWUnit->addChild("tag", $getUnitsData['unittag']);
                                                }
                                            }
                                        } 
                                        elseif ($getIntEthernetData['type'] == "ha") {
                                            $int2->addChild("ha");
                                        } 
                                        elseif ($getIntEthernetData['type'] == "layer3") {
                                            $int2->addChild("layer3");
                                            if ($getIntEthernetData['netflow_profile'] != "") {
                                                $int2->layer3->addChild("netflow-profile", $getIntEthernetData['netflow_profile']);
                                            }
                                            if (($getIntEthernetData['mtu'] != "") AND ( $getIntEthernetData['mtu'] != "0")) {
                                                $int2->layer3->addChild("mtu", $getIntEthernetData['mtu']);
                                            }
                                            if (($getIntEthernetData['interface_management_profile'] != "") AND ( $getIntEthernetData['interface_management_profile'] != "None")) {
                                                $int2->layer3->addChild("interface-management-profile", $getIntEthernetData['interface_management_profile']);
                                            }

                                            if ($getIntEthernetData['untagged_sub_interface'] != "") {
                                                $int2->layer3->addChild("untagged-sub-interface", $getIntEthernetData['untagged_sub_interface']);
                                            }
                                            if ($getIntEthernetData['arp'] != "") {
                                                $xml_append = simplexml_load_string($getIntEthernetData['arp']);
                                                SimpleXMLElement_append($int2->layer3, $xml_append);
                                            }
                                            if ($version>=7){
                                                if ($getIntEthernetData['lldp'] != "") {
                                                    $xml_append = simplexml_load_string($getIntEthernetData['lldp']);
                                                    SimpleXMLElement_append($int2->layer3, $xml_append);
                                                }
                                                if ($getIntEthernetData['ndpproxy'] != "") {
                                                    $xml_append = simplexml_load_string($getIntEthernetData['ndpproxy']);
                                                    SimpleXMLElement_append($int2->layer3, $xml_append);
                                                }
                                            }
                                            if ($getIntEthernetData['ipv4_type'] == "static") {
                                                if ($getIntEthernetData['ipv6'] != "") {
                                                    $xml_append = simplexml_load_string($getIntEthernetData['ipv6']);
                                                    SimpleXMLElement_append($int2->layer3, $xml_append);
                                                }
                                                if ($getIntEthernetData['unitipaddress'] != "") {
                                                    $interfaces_all = explode(",", $getIntEthernetData['unitipaddress']);
                                                    $int2->layer3->addChild("ip");
                                                    foreach ($interfaces_all as $key => $int_value) {
                                                        $newInt = $int2->layer3->ip->addChild("entry");
                                                        $newInt->addAttribute('name', $int_value);
                                                    }
                                                }
                                                if ($getIntEthernetData['adjust_tcp_mss'] != "") {
                                                    $int2->layer3->addChild("adjust-tcp-mss", $getIntEthernetData['adjust_tcp_mss']);
                                                }
                                            } 
                                            elseif ($getIntEthernetData['ipv4_type'] == "dhcp-client") {
                                                $int2->layer3->addChild("dhcp-client");
                                                if ($getIntEthernetData['ipv6'] != "") {
                                                    $xml_append = simplexml_load_string($getIntEthernetData['ipv6']);
                                                    SimpleXMLElement_append($int2->layer3, $xml_append);
                                                }
                                                if ($getIntEthernetData['dhcp_client_enable'] == "no") {
                                                    $int2->layer3->{"dhcp-client"}->addChild("enable", "no");
                                                }
                                                if ($getIntEthernetData['dhcp_client_default_route_metric'] != "0") {
                                                    $int2->layer3->{"dhcp-client"}->addChild("default-route-metric", $getIntEthernetData['dhcp_client_default_route_metric']);
                                                }
                                                if ($getIntEthernetData['dhcp_client_create_default_route'] == "no") {
                                                    $int2->layer3->{"dhcp-client"}->addChild("create-default-route", "no");
                                                }
                                                if ($getIntEthernetData['adjust_tcp_mss'] != "") {
                                                    $int2->layer3->addChild("adjust-tcp-mss", $getIntEthernetData['adjust_tcp_mss']);
                                                }
                                            }
                                            # UNITS
                                            $getUnits = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='aggregate-ethernet' AND unitname!='$myname' AND name='$myname';");
                                            if ($getUnits->num_rows > 0) {
                                                $unit = $int2->layer3->addChild("units");
                                                while ($getUnitsData = $getUnits->fetch_assoc()) {
                                                    $myname1 = $getUnitsData['unitname'];
                                                    $UnitInt = $unit->addChild('entry');
                                                    $UnitInt->addAttribute('name', $myname1);
                                                    if ($getUnitsData['netflow_profile'] != "") {
                                                        $UnitInt->addChild("netflow-profile", $getUnitsData['netflow_profile']);
                                                    }
                                                    if ($getUnitsData['unittag']!=0){
                                                        $UnitInt->addChild("tag", $getUnitsData['unittag']);
                                                    }
                                                    if ($getUnitsData['comment'] != "") {
                                                        $UnitInt->addChild("comment");
                                                        $UnitInt->comment = $getUnitsData['comment'];
                                                    }
                                                    if ($getUnitsData['ipv6'] != "") {
                                                        $xml_append = simplexml_load_string($getUnitsData['ipv6']);
                                                        SimpleXMLElement_append($UnitInt, $xml_append);
                                                    }
                                                    if (($getUnitsData['mtu'] != "") AND ( $getUnitsData['mtu'] != "0")) {
                                                        $UnitInt->addChild("mtu", $getUnitsData['mtu']);
                                                    }
                                                    if (($getUnitsData['interface_management_profile'] != "") AND ( $getUnitsData['interface_management_profile'] != "None")) {
                                                        $UnitInt->addChild("interface-management-profile", $getUnitsData['interface_management_profile']);
                                                    }
                                                    if ($getUnitsData['adjust_tcp_mss'] != "") {
                                                        $UnitInt->addChild("adjust-tcp-mss", $getUnitsData['adjust_tcp_mss']);
                                                    }
                                                    if ($getUnitsData['arp'] != "") {
                                                        $xml_append = simplexml_load_string($getUnitsData['arp']);
                                                        SimpleXMLElement_append($UnitInt, $xml_append);
                                                    }
                                                    if ($getUnitsData['ipv4_type'] == "static") {
                                                        if ($getUnitsData['unitipaddress'] != "") {
                                                            $interfaces_all = explode(",", $getUnitsData['unitipaddress']);
                                                            $UnitInt->addChild("ip");
                                                            foreach ($interfaces_all as $key => $int_value) {
                                                                $newInt = $UnitInt->ip->addChild("entry");
                                                                $newInt->addAttribute('name', $int_value);
                                                            }
                                                        }
                                                    } elseif ($getUnitsData['ipv4_type'] == "dhcp-client") {
                                                        $UnitInt->addChild("dhcp-client");

                                                        if ($getUnitsData['dhcp_client_enable'] == "no") {
                                                            $UnitInt->{"dhcp-client"}->addChild("enable", "no");
                                                        }
                                                        if ($getUnitsData['dhcp_client_default_route_metric'] != "0") {
                                                            $UnitInt->{"dhcp-client"}->addChild("default-route-metric", $getUnitsData['dhcp_client_default_route_metric']);
                                                        }
                                                        if ($getUnitsData['dhcp_client_create_default_route'] == "no") {
                                                            $UnitInt->{"dhcp-client"}->addChild("create-default-route", "no");
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        elseif ($getIntEthernetData['type'] == "decrypt-mirror"){
                                            $int2->addChild("decrypt-mirror");
                                        }
                                        
                                        if ($getIntEthernetData['lacp'] != "") {
                                            $xml_append = simplexml_load_string($getIntEthernetData['lacp']);
                                            SimpleXMLElement_append($int2->$getIntEthernetData['type'], $xml_append);
                                        }
                                    }
                                }
                                #Ethernet
                                $getIntEthernet = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='ethernet' AND unittag='0' AND name=unitname GROUP BY name ORDER BY name");
                                if ($getIntEthernet->num_rows > 0) {
                                    $theINT->addChild("ethernet");
                                    while ($getIntEthernetData = $getIntEthernet->fetch_assoc()) {
                                        $myname = $getIntEthernetData['name'];
                                        $int = $theINT->ethernet->addChild('entry');
                                        $int->addAttribute('name', $myname);
                                        
                                        if ($version>=7){
                                            if ($getIntEthernetData['link_speed'] != "") {
                                                $int->addChild("link-speed", $getIntEthernetData['link_speed']);
                                            }
                                            if ($getIntEthernetData['link_duplex'] != "") {
                                                $int->addChild("link-duplex", $getIntEthernetData['link_duplex']);
                                            }
                                            if ($getIntEthernetData['link_state'] != "")  {
                                                $int->addChild("link-state", $getIntEthernetData['link_state']);
                                            }
                                        }
                                        else{
                                            if (($getIntEthernetData['link_speed'] != "") AND ( $getIntEthernetData['link_speed'] != "auto")) {
                                                $int->addChild("link-speed", $getIntEthernetData['link_speed']);
                                            }
                                            if (($getIntEthernetData['link_duplex'] != "") AND ( $getIntEthernetData['link_duplex'] != "auto")) {
                                                $int->addChild("link-duplex", $getIntEthernetData['link_duplex']);
                                            }
                                            if (($getIntEthernetData['link_state'] != "") AND ( $getIntEthernetData['link_state'] != "auto")) {
                                                $int->addChild("link-state", $getIntEthernetData['link_state']);
                                            }
                                        }
                                            

                                        if ($getIntEthernetData['comment'] != "") {
                                            $int->addChild("comment");
                                            $int->comment = $getIntEthernetData['comment'];
                                        }
                                        if ($getIntEthernetData['type'] == "tap") {
                                            $int->addChild("tap");
                                            if ($getIntEthernetData['netflow_profile'] != "") {
                                                $int->tap->addChild("netflow-profile", $getIntEthernetData['netflow_profile']);
                                            }
                                        }
                                        if ($getIntEthernetData['type'] == "log-card") {
                                            $xml_append = simplexml_load_string($getIntEthernetData['log_card']);
                                            SimpleXMLElement_append($int, $xml_append);
                                        }
                                        if ($getIntEthernetData['type'] == "virtual-wire") {
                                            $int->addChild("virtual-wire");
                                            if ($getIntEthernetData['netflow_profile'] != "") {
                                                $int->{'virtual-wire'}->addChild("netflow-profile", $getIntEthernetData['netflow_profile']);
                                            }
                                            $getUnits = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='ethernet' AND unitname!='$myname' AND name='$myname';");
                                            if ($getUnits->num_rows > 0) {
                                                $int->{'virtual-wire'}->addChild("units");
                                                while ($getUnitsData = $getUnits->fetch_assoc()) {
                                                    $myname1 = $getUnitsData['unitname'];
                                                    $VWUnit = $int->{'virtual-wire'}->units->addChild('entry');
                                                    $VWUnit->addAttribute('name', $myname1);
                                                    if ($getUnitsData['comment'] != "") {
                                                        $VWUnit->addChild("comment");
                                                        $VWUnit->comment = $getUnitsData['comment'];
                                                    }
                                                    if ($getUnitsData['netflow_profile'] != "") {
                                                        $VWUnit->addChild("netflow-profile", $getUnitsData['netflow_profile']);
                                                    }

                                                    $VWUnit->addChild("tag", $getUnitsData['unittag']);

                                                    if ($getUnitsData['ip_classifier'] != "") {
                                                        $interfaces_all = explode(",", $getUnitsData['ip_classifier']);
                                                        $VWUnit->addChild("ip-classifier");
                                                        foreach ($interfaces_all as $key => $int_value) {
                                                            $VWUnit->{'ip-classifier'}->addChild("member", $int_value);
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        if ($getIntEthernetData['type'] == "layer2") {
                                            $int->addChild("layer2");
                                            if ($getIntEthernetData['netflow_profile'] != "") {
                                                $int->layer2->addChild("netflow-profile", $getIntEthernetData['netflow_profile']);
                                            }
                                            if ($version>=7){
                                                if ($getIntEthernetData['lldp'] != "") {
                                                    $xml_append = simplexml_load_string($getIntEthernetData['lldp']);
                                                    SimpleXMLElement_append($int->layer2, $xml_append);
                                                }
                                            }
                                            $getUnits = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='ethernet' AND unitname!='$myname' AND name='$myname';");
                                            if ($getUnits->num_rows > 0) {
                                                $int->{'layer2'}->addChild("units");
                                                while ($getUnitsData = $getUnits->fetch_assoc()) {
                                                    $myname1 = $getUnitsData['unitname'];
                                                    $VWUnit = $int->{'layer2'}->units->addChild('entry');
                                                    $VWUnit->addAttribute('name', $myname1);
                                                    if ($getUnitsData['netflow_profile'] != "") {
                                                        $VWUnit->addChild("netflow-profile", $getUnitsData['netflow_profile']);
                                                    }
                                                    if ($getUnitsData['comment'] != "") {
                                                        $VWUnit->addChild("comment");
                                                        $VWUnit->comment = $getUnitsData['comment'];
                                                    }
                                                    $VWUnit->addChild("tag", $getUnitsData['unittag']);
                                                }
                                            }
                                        } 
                                        elseif ($getIntEthernetData['type'] == "ha") {
                                            $int->addChild("ha");
                                        } 
                                        elseif ($getIntEthernetData['type'] == "layer3") {
                                            $int->addChild("layer3");
                                            if ($getIntEthernetData['netflow_profile'] != "") {
                                                $int->layer3->addChild("netflow-profile", $getIntEthernetData['netflow_profile']);
                                            }
                                            if (($getIntEthernetData['mtu'] != "") AND ( $getIntEthernetData['mtu'] != "0")) {
                                                $int->layer3->addChild("mtu", $getIntEthernetData['mtu']);
                                            }
                                            if (($getIntEthernetData['interface_management_profile'] != "") AND ( $getIntEthernetData['interface_management_profile'] != "None")) {
                                                $int->layer3->addChild("interface-management-profile", $getIntEthernetData['interface_management_profile']);
                                            }

                                            if ($getIntEthernetData['untagged_sub_interface'] != "") {
                                                $int->layer3->addChild("untagged-sub-interface", $getIntEthernetData['untagged_sub_interface']);
                                            }
                                            if ($getIntEthernetData['arp'] != "") {
                                                $xml_append = simplexml_load_string($getIntEthernetData['arp']);
                                                SimpleXMLElement_append($int->layer3, $xml_append);
                                            }
                                            if ($version>=7){
                                                if ($getIntEthernetData['lldp'] != "") {
                                                    $xml_append = simplexml_load_string($getIntEthernetData['lldp']);
                                                    SimpleXMLElement_append($int->layer3, $xml_append);
                                                }
                                                if ($getIntEthernetData['ndpproxy'] != "") {
                                                    $xml_append = simplexml_load_string($getIntEthernetData['ndpproxy']);
                                                    SimpleXMLElement_append($int->layer3, $xml_append);
                                                }
                                            }
                                            if ($getIntEthernetData['ipv4_type'] == "static") {
                                                if ($getIntEthernetData['ipv6'] != "") {
                                                    $xml_append = simplexml_load_string($getIntEthernetData['ipv6']);
                                                    SimpleXMLElement_append($int->layer3, $xml_append);
                                                }
                                                if ($getIntEthernetData['unitipaddress'] != "") {
                                                    $interfaces_all = explode(",", $getIntEthernetData['unitipaddress']);
                                                    $int->layer3->addChild("ip");
                                                    foreach ($interfaces_all as $key => $int_value) {
                                                        $newInt = $int->layer3->ip->addChild("entry");
                                                        $newInt->addAttribute('name', $int_value);
                                                    }
                                                }
                                                if ($getIntEthernetData['adjust_tcp_mss'] != "") {
                                                    $int->layer3->addChild("adjust-tcp-mss", $getIntEthernetData['adjust_tcp_mss']);
                                                }
                                            } elseif ($getIntEthernetData['ipv4_type'] == "dhcp-client") {
                                                $int->layer3->addChild("dhcp-client");
                                                if ($getIntEthernetData['ipv6'] != "") {
                                                    $xml_append = simplexml_load_string($getIntEthernetData['ipv6']);
                                                    SimpleXMLElement_append($int->layer3, $xml_append);
                                                }
                                                if ($getIntEthernetData['dhcp_client_enable'] == "no") {
                                                    $int->layer3->{"dhcp-client"}->addChild("enable", "no");
                                                }
                                                if ($getIntEthernetData['dhcp_client_default_route_metric'] != "0") {
                                                    $int->layer3->{"dhcp-client"}->addChild("default-route-metric", $getIntEthernetData['dhcp_client_default_route_metric']);
                                                }
                                                if ($getIntEthernetData['dhcp_client_create_default_route'] == "no") {
                                                    $int->layer3->{"dhcp-client"}->addChild("create-default-route", "no");
                                                }
                                                if ($getIntEthernetData['adjust_tcp_mss'] != "") {
                                                    $int->layer3->addChild("adjust-tcp-mss", $getIntEthernetData['adjust_tcp_mss']);
                                                }
                                            }
                                            # UNITS
                                            $getUnits = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='ethernet' AND unitname!='$myname' AND name='$myname';");
                                            if ($getUnits->num_rows > 0) {
                                                $unit = $int->layer3->addChild("units");
                                                while ($getUnitsData = $getUnits->fetch_assoc()) {
                                                    $myname1 = $getUnitsData['unitname'];
                                                    $UnitInt = $unit->addChild('entry');
                                                    $UnitInt->addAttribute('name', $myname1);
                                                    if ($getUnitsData['netflow_profile'] != "") {
                                                        $UnitInt->addChild("netflow-profile", $getUnitsData['netflow_profile']);
                                                    }
                                                    if ($getUnitsData['unittag']!=0){
                                                        $UnitInt->addChild("tag", $getUnitsData['unittag']);
                                                    }
                                                    if ($getUnitsData['comment'] != "") {
                                                        $UnitInt->addChild("comment");
                                                        $UnitInt->comment = $getUnitsData['comment'];
                                                    }
                                                    if ($getUnitsData['ipv6'] != "") {
                                                        $xml_append = simplexml_load_string($getUnitsData['ipv6']);
                                                        SimpleXMLElement_append($UnitInt, $xml_append);
                                                    }
                                                    if (($getUnitsData['mtu'] != "") AND ( $getUnitsData['mtu'] != "0")) {
                                                        $UnitInt->addChild("mtu", $getUnitsData['mtu']);
                                                    }
                                                    if (($getUnitsData['interface_management_profile'] != "") AND ( $getUnitsData['interface_management_profile'] != "None")) {
                                                        $UnitInt->addChild("interface-management-profile", $getUnitsData['interface_management_profile']);
                                                    }
                                                    if ($getUnitsData['adjust_tcp_mss'] != "") {
                                                        $UnitInt->addChild("adjust-tcp-mss", $getUnitsData['adjust_tcp_mss']);
                                                    }
                                                    if ($getUnitsData['arp'] != "") {
                                                        $xml_append = simplexml_load_string($getUnitsData['arp']);
                                                        SimpleXMLElement_append($UnitInt, $xml_append);
                                                    }
                                                    if ($version>=7){
                                                        if ($getUnitsData['ndpproxy'] != "") {
                                                            $xml_append = simplexml_load_string($getUnitsData['ndpproxy']);
                                                            SimpleXMLElement_append($UnitInt, $xml_append);
                                                        }
                                                    }
                                                    if ($getUnitsData['ipv4_type'] == "static") {
                                                        if ($getUnitsData['unitipaddress'] != "") {
                                                            $interfaces_all = explode(",", $getUnitsData['unitipaddress']);
                                                            $UnitInt->addChild("ip");
                                                            foreach ($interfaces_all as $key => $int_value) {
                                                                $newInt = $UnitInt->ip->addChild("entry");
                                                                $newInt->addAttribute('name', $int_value);
                                                            }
                                                        }
                                                    } elseif ($getUnitsData['ipv4_type'] == "dhcp-client") {
                                                        $UnitInt->addChild("dhcp-client");

                                                        if ($getUnitsData['dhcp_client_enable'] == "no") {
                                                            $UnitInt->{"dhcp-client"}->addChild("enable", "no");
                                                        }
                                                        if ($getUnitsData['dhcp_client_default_route_metric'] != "0") {
                                                            $UnitInt->{"dhcp-client"}->addChild("default-route-metric", $getUnitsData['dhcp_client_default_route_metric']);
                                                        }
                                                        if ($getUnitsData['dhcp_client_create_default_route'] == "no") {
                                                            $UnitInt->{"dhcp-client"}->addChild("create-default-route", "no");
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        elseif ($getIntEthernetData['type'] == "decrypt-mirror"){
                                            $int->addChild("decrypt-mirror");
                                        }
                                        if ($getIntEthernetData['type'] == "aggregate-group"){
                                            $int->addChild("aggregate-group",$getIntEthernetData['aggregate_group']);
                                        }
                                        
                                    }
                                }
                                # Vlan
                                $getIntEthernet = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='vlan' AND name='vlan' GROUP BY name ORDER BY name");
                                if ($getIntEthernet->num_rows > 0) {
                                    $vlanint = $theINT->addChild("vlan");
                                    while ($getIntEthernetData = $getIntEthernet->fetch_assoc()) {
                                        if ($getIntEthernetData['ipv6'] != "") {
                                            $xml_append = simplexml_load_string($getIntEthernetData['ipv6']);
                                            SimpleXMLElement_append($vlanint, $xml_append);
                                        }
                                        if (($getIntEthernetData['mtu'] != "") AND ( $getIntEthernetData['mtu'] != "0")) {
                                            $vlanint->addChild("mtu", $getIntEthernetData['mtu']);
                                        }
                                        if ($getIntEthernetData['adjust_tcp_mss'] != "") {
                                            $vlanint->addChild("adjust-tcp-mss", $getIntEthernetData['adjust_tcp_mss']);
                                        }
                                        if (($getIntEthernetData['interface_management_profile'] != "") AND ( $getIntEthernetData['interface_management_profile'] != "None")) {
                                            $vlanint->addChild("interface-management-profile", $getIntEthernetData['interface_management_profile']);
                                        }
                                        if ($getIntEthernetData['arp'] != "") {
                                            $xml_append = simplexml_load_string($getIntEthernetData['arp']);
                                            SimpleXMLElement_append($vlanint, $xml_append);
                                        }
                                        if ($getIntEthernetData['comment'] != "") {
                                            $vlanint->addChild("comment");
                                            $vlanint->comment = $getIntEthernetData['comment'];
                                        }
                                        if ($version>=7){
                                            if ($getIntEthernetData['ndpproxy'] != "") {
                                                $xml_append = simplexml_load_string($getIntEthernetData['ndpproxy']);
                                                SimpleXMLElement_append($vlanint, $xml_append);
                                            }
                                        }
                                        if ($getIntEthernetData['ipv4_type'] == "static") {
                                            if ($getIntEthernetData['unitipaddress'] != "") {
                                                $interfaces_all = explode(",", $getIntEthernetData['unitipaddress']);
                                                $vlanint->addChild("ip");
                                                foreach ($interfaces_all as $key => $int_value) {
                                                    $newInt = $vlanint->ip->addChild("entry");
                                                    $newInt->addAttribute('name', $int_value);
                                                }
                                            }
                                        } elseif ($getIntEthernetData['ipv4_type'] == "dhcp-client") {
                                            $vlanint->addChild("dhcp-client");
                                            if ($getIntEthernetData['dhcp_client_enable'] == "no") {
                                                $vlanint->{"dhcp-client"}->addChild("enable", "no");
                                            }
                                            if ($getIntEthernetData['dhcp_client_default_route_metric'] != "0") {
                                                $vlanint->{"dhcp-client"}->addChild("default-route-metric", $getIntEthernetData['dhcp_client_default_route_metric']);
                                            }
                                            if ($getIntEthernetData['dhcp_client_create_default_route'] == "no") {
                                                $vlanint->{"dhcp-client"}->addChild("create-default-route", "no");
                                            }
                                        }
                                        $getUnits = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='vlan' AND unitname!='vlan';");
                                        if ($getUnits->num_rows > 0) {
                                            $vlanint->addChild("units");
                                            while ($getUnitsData = $getUnits->fetch_assoc()) {
                                                $myname1 = $getUnitsData['unitname'];
                                                $UnitInt = $vlanint->units->addChild('entry');
                                                $UnitInt->addAttribute('name', $myname1);
                                                if ($getUnitsData['ipv6'] != "") {
                                                    $xml_append = simplexml_load_string($getUnitsData['ipv6']);
                                                    SimpleXMLElement_append($UnitInt, $xml_append);
                                                }
                                                $UnitInt->addChild("tag", $getUnitsData['unittag']);
                                                if ($getUnitsData['comment'] != "") {
                                                    $UnitInt->addChild("comment");
                                                    $UnitInt->comment = $getUnitsData['comment'];
                                                }
                                                if (($getUnitsData['mtu'] != "") AND ( $getUnitsData['mtu'] != "0")) {
                                                    $UnitInt->addChild("mtu", $getUnitsData['mtu']);
                                                }
                                                if ($getUnitsData['adjust_tcp_mss'] != "") {
                                                    $UnitInt->addChild("adjust-tcp-mss", $getUnitsData['adjust_tcp_mss']);
                                                }
                                                if (($getUnitsData['interface_management_profile'] != "") AND ( $getUnitsData['interface_management_profile'] != "None")) {
                                                    $UnitInt->addChild("interface-management-profile", $getUnitsData['interface_management_profile']);
                                                }
                                                if ($getUnitsData['arp'] != "") {
                                                    $xml_append = simplexml_load_string($getUnitsData['arp']);
                                                    SimpleXMLElement_append($UnitInt, $xml_append);
                                                }
                                                if ($getUnitsData['ipv4_type'] == "static") {
                                                    if ($getUnitsData['unitipaddress'] != "") {
                                                        $interfaces_all = explode(",", $getUnitsData['unitipaddress']);
                                                        $UnitInt->addChild("ip");
                                                        foreach ($interfaces_all as $key => $int_value) {
                                                            $newInt = $UnitInt->ip->addChild("entry");
                                                            $newInt->addAttribute('name', $int_value);
                                                        }
                                                    }
                                                } elseif ($getUnitsData['ipv4_type'] == "dhcp-client") {
                                                    $UnitInt->addChild("dhcp-client");
                                                    if ($getUnitsData['dhcp_client_enable'] == "no") {
                                                        $UnitInt->{"dhcp-client"}->addChild("enable", "no");
                                                    }
                                                    if ($getUnitsData['dhcp_client_default_route_metric'] != "0") {
                                                        $UnitInt->{"dhcp-client"}->addChild("default-route-metric", $getUnitsData['dhcp_client_default_route_metric']);
                                                    }
                                                    if ($getUnitsData['dhcp_client_create_default_route'] == "no") {
                                                        $UnitInt->{"dhcp-client"}->addChild("create-default-route", "no");
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                # Loopback
                                $getIntEthernet = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='loopback' AND name='loopback' GROUP BY name ORDER BY name");
                                if ($getIntEthernet->num_rows > 0) {
                                    $loopackint = $theINT->addChild("loopback");
                                    while ($getIntEthernetData = $getIntEthernet->fetch_assoc()) {
                                        if ($getIntEthernetData['ipv6'] != "") {
                                            $xml_append = simplexml_load_string($getIntEthernetData['ipv6']);
                                            SimpleXMLElement_append($loopackint, $xml_append);
                                        }
                                        if (($getIntEthernetData['mtu'] != "") AND ( $getIntEthernetData['mtu'] != "0")) {
                                            $loopackint->addChild("mtu", $getIntEthernetData['mtu']);
                                        }
                                        if ($getIntEthernetData['adjust_tcp_mss'] != "") {
                                            $loopackint->addChild("adjust-tcp-mss", $getIntEthernetData['adjust_tcp_mss']);
                                        }
                                        if ($getIntEthernetData['comment'] != "") {
                                            $loopackint->addChild("comment");
                                            $loopackint->comment = $getIntEthernetData['comment'];
                                        }
                                        if (($getIntEthernetData['interface_management_profile'] != "") AND ( $getIntEthernetData['interface_management_profile'] != "None")) {
                                            $loopackint->addChild("interface-management-profile", $getIntEthernetData['interface_management_profile']);
                                        }
                                        if ($getIntEthernetData['ipv4_type'] == "static") {
                                            if ($getIntEthernetData['unitipaddress'] != "") {
                                                $interfaces_all = explode(",", $getIntEthernetData['unitipaddress']);
                                                $loopackint->addChild("ip");
                                                foreach ($interfaces_all as $key => $int_value) {
                                                    $newInt = $loopackint->ip->addChild("entry");
                                                    $newInt->addAttribute('name', $int_value);
                                                }
                                            }
                                        }
                                        $getUnits = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='loopback' AND unitname!='loopback';");
                                        if ($getUnits->num_rows > 0) {
                                            $unit = $loopackint->addChild("units");
                                            while ($getUnitsData = $getUnits->fetch_assoc()) {
                                                $myname1 = $getUnitsData['unitname'];
                                                $UnitInt = $unit->addChild('entry');
                                                $UnitInt->addAttribute('name', $myname1);
                                                if ($getUnitsData['ipv6'] != "") {
                                                    $xml_append = simplexml_load_string($getUnitsData['ipv6']);
                                                    SimpleXMLElement_append($UnitInt, $xml_append);
                                                }
                                                if (($getUnitsData['mtu'] != "") AND ( $getUnitsData['mtu'] != "0")) {
                                                    $UnitInt->addChild("mtu", $getUnitsData['mtu']);
                                                }
                                                if ($getUnitsData['comment'] != "") {
                                                    $UnitInt->addChild("comment");
                                                    $UnitInt->comment = $getUnitsData['comment'];
                                                }
                                                if ($getUnitsData['adjust_tcp_mss'] != "") {
                                                    $UnitInt->addChild("adjust-tcp-mss", $getUnitsData['adjust_tcp_mss']);
                                                }
                                                if (($getUnitsData['interface_management_profile'] != "") AND ( $getUnitsData['interface_management_profile'] != "None")) {
                                                    $UnitInt->addChild("interface-management-profile", $getUnitsData['interface_management_profile']);
                                                }
                                                if ($getUnitsData['ipv4_type'] == "static") {
                                                    if ($getUnitsData['unitipaddress'] != "") {
                                                        $interfaces_all = explode(",", $getUnitsData['unitipaddress']);
                                                        $UnitInt->addChild("ip");
                                                        foreach ($interfaces_all as $key => $int_value) {
                                                            $newInt = $UnitInt->ip->addChild("entry");
                                                            $newInt->addAttribute('name', $int_value);
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                # Tunnel
                                $getIntEthernet = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='tunnel' AND name='tunnel' GROUP BY name ORDER BY name");
                                if ($getIntEthernet->num_rows > 0) {
                                    $tunnelint = $theINT->addChild("tunnel");
                                    while ($getIntEthernetData = $getIntEthernet->fetch_assoc()) {
                                        if ($getIntEthernetData['ipv6'] != "") {
                                            $xml_append = simplexml_load_string($getIntEthernetData['ipv6']);
                                            SimpleXMLElement_append($tunnelint, $xml_append);
                                        }
                                        if (($getIntEthernetData['mtu'] != "") AND ( $getIntEthernetData['mtu'] != "0")) {
                                            $tunnelint->addChild("mtu", $getIntEthernetData['mtu']);
                                        }
                                        if ($getIntEthernetData['comment'] != "") {
                                            $tunnelint->addChild("comment");
                                            $tunnelint->comment = $getIntEthernetData['comment'];
                                        }
                                        if ($getIntEthernetData['adjust_tcp_mss'] != "") {
                                            $tunnelint->addChild("adjust-tcp-mss", $getIntEthernetData['adjust_tcp_mss']);
                                        }
                                        if (($getIntEthernetData['interface_management_profile'] != "") AND ( $getIntEthernetData['interface_management_profile'] != "None")) {
                                            $tunnelint->addChild("interface-management-profile", $getIntEthernetData['interface_management_profile']);
                                        }
                                        if ($getIntEthernetData['ipv4_type'] == "static") {
                                            if ($getIntEthernetData['unitipaddress'] != "") {
                                                $interfaces_all = explode(",", $getIntEthernetData['unitipaddress']);
                                                $tunnelint->addChild("ip");
                                                foreach ($interfaces_all as $key => $int_value) {
                                                    $newInt = $tunnelint->ip->addChild("entry");
                                                    $newInt->addAttribute('name', $int_value);
                                                }
                                            }
                                        }
                                        $getUnits = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='tunnel' AND unitname!='tunnel';");
                                        if ($getUnits->num_rows > 0) {
                                            $unit = $tunnelint->addChild("units");
                                            while ($getUnitsData = $getUnits->fetch_assoc()) {
                                                $myname1 = $getUnitsData['unitname'];
                                                $UnitInt = $unit->addChild('entry');
                                                $UnitInt->addAttribute('name', $myname1);
                                                if ($getUnitsData['ipv6'] != "") {
                                                    $xml_append = simplexml_load_string($getUnitsData['ipv6']);
                                                    SimpleXMLElement_append($UnitInt, $xml_append);
                                                }
                                                if ($getUnitsData['comment'] != "") {
                                                    $UnitInt->addChild("comment");
                                                    $UnitInt->comment = $getUnitsData['comment'];
                                                }
                                                if (($getUnitsData['mtu'] != "") AND ( $getUnitsData['mtu'] != "0")) {
                                                    $UnitInt->addChild("mtu", $getUnitsData['mtu']);
                                                }
                                                if ($getUnitsData['adjust_tcp_mss'] != "") {
                                                    $UnitInt->addChild("adjust-tcp-mss", $getUnitsData['adjust_tcp_mss']);
                                                }
                                                if (($getUnitsData['interface_management_profile'] != "") AND ( $getUnitsData['interface_management_profile'] != "None")) {
                                                    $UnitInt->addChild("interface-management-profile", $getUnitsData['interface_management_profile']);
                                                }
                                                if ($getUnitsData['ipv4_type'] == "static") {
                                                    if ($getUnitsData['unitipaddress'] != "") {
                                                        $interfaces_all = explode(",", $getUnitsData['unitipaddress']);
                                                        $UnitInt->addChild("ip");
                                                        foreach ($interfaces_all as $key => $int_value) {
                                                            $newInt = $UnitInt->ip->addChild("entry");
                                                            $newInt->addAttribute('name', $int_value);
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            
                            #Virtual Wire
                            if (isset($myTemplateDeviceNetwork->{"virtual-wire"})){
                                $SA=$myTemplateDeviceNetwork->xpath("virtual-wire");
                                unset($SA[0][0]);
                            }
                            $getVW = $projectdb->query("SELECT id,name,multicast_firewalling,tag_allowed,link_state_pass_through,interface1,interface2 FROM virtual_wires WHERE source='$source' AND template='$template';");
                            if ($getVW->num_rows > 0) {
                                $xml0 = $xml->xpath("//devices/entry[@name='localhost.localdomain']/network/virtual-wire");
                                $myTemplateDeviceNetwork->addChild("virtual-wire");
                                $theVW = $myTemplateDeviceNetwork->{'virtual-wire'};
                                while ($getVRData = $getVW->fetch_assoc()) {
                                    $myname = $getVRData['name'];
                                    $multicast_firewalling = $getVRData['multicast_firewalling'];
                                    $tag_allowed = $getVRData['tag_allowed'];
                                    $link_state_pass_through = $getVRData['link_state_pass_through'];
                                    $interface1 = $getVRData['interface1'];
                                    $interface2 = $getVRData['interface2'];

                                    $vwire = $theVW->addChild('entry');
                                    $vwire->addAttribute('name', $myname);
                                    if ($link_state_pass_through != "") {
                                        $vwire->addChild("link-state-pass-through");
                                        $vwire->{'link-state-pass-through'}->addChild("enable", $link_state_pass_through);
                                    }
                                    if ($multicast_firewalling != "") {
                                        $vwire->addChild("multicast-firewalling");
                                        $vwire->{'multicast-firewalling'}->addChild("enable", $multicast_firewalling);
                                    }
                                    if ($tag_allowed != "") {
                                        $vwire->addchild("tag-allowed", $tag_allowed);
                                    }
                                    if ($interface1 != "") {
                                        $vwire->addChild("interface1", $interface1);
                                    }
                                    if ($interface2 != "") {
                                        $vwire->addChild("interface2", $interface2);
                                    }
                                }
                            }

                            #VLANS
                            if (isset($myTemplateDeviceNetwork->vlan)){
                                $SA=$myTemplateDeviceNetwork->xpath("vlan");
                                unset($SA[0][0]);
                            }
                            $getVW = $projectdb->query("SELECT id, name, interface, mac, virtual_interface, mac_interfaces, l3_forwarding FROM vlans WHERE source='$source' AND template='$template' AND name != '';");
                            if ($getVW->num_rows > 0) {
                                $myTemplateDeviceNetwork->addChild('vlan');
                                $theVW = $myTemplateDeviceNetwork->vlan;
                                while ($getVRData = $getVW->fetch_assoc()) {
                                    $myname = $getVRData['name'];
                                    $interface = $getVRData['interface'];
                                    $mac = $getVRData['mac'];
                                    $mac_interfaces = $getVRData['mac_interfaces'];
                                    $virtual_interface = $getVRData['virtual_interface'];
                                    $l3_forwarding = $getVRData['l3_forwarding'];

                                    $vwire = $theVW->addChild('entry');
                                    $vwire->addAttribute('name', $myname);
                                    if ($interface != "") {
                                        $vwire->addChild("interface");
                                        foreach (explode(",", $interface) as $key => $value) {
                                            $vwire->interface->addChild("member", $value);
                                        }
                                    }

                                    if ($mac != "") {
                                        //$xml_append = simplexml_load_string($mac);
                                        //SimpleXMLElement_append($vwire, $xml_append);
                                        $index_array = 0;
                                        $interfaces_mac_array = explode(",", $mac_interfaces);

                                        $vlan_pad = $vwire->addChild("mac");

                                        foreach (explode(",", $mac) as $key => $value) {
                                            $vlan_mac = $vlan_pad->addChild('entry');
                                            $vlan_mac->addAttribute('name', $value);

                                            $vlan_mac->interface = $interfaces_mac_array[$index_array];
                                            $index_array ++;
                                        }
                                    }
                                    
                                    if($version > 5){
                                        if ($virtual_interface != "") {
                                            $vwire->addChild("virtual-interface");
                                            $vwire->{'virtual-interface'}->addChild("interface", $virtual_interface);
                                        }
                                    }
                                    else{
                                        $vwire->addChild("virtual-interface");
                                        $vwire->{'virtual-interface'}->addChild("l3-forwarding", $l3_forwarding);
                                        if ($virtual_interface != "") {
                                            $vwire->{'virtual-interface'}->addChild("interface", $virtual_interface);
                                        }
                                    }
                                }
                            }

                            #Virtual Router
                            if (isset($myTemplateDeviceNetwork->{"virtual-router"})){
                                $SA=$myTemplateDeviceNetwork->xpath("virtual-router");
                                unset($SA[0][0]);
                            }
                            $getVR = $projectdb->query("SELECT id,name,map_name,interfaces,admin_dist_static,admin_dist_ospf_int,admin_dist_ospf_ext,admin_dist_ibgp,admin_dist_ebgp,admin_dist_rip,protocol,multicast,admin_dist_static_ipv6,admin_dist_ospfv3_int,admin_dist_ospfv3_ext,ecmp FROM virtual_routers WHERE source='$source' AND template='$template';");
                            if ($getVR->num_rows > 0) {
                                $myTemplateDeviceNetwork->addChild('virtual-router');
                                $theVR = $myTemplateDeviceNetwork->{'virtual-router'};

                                while ($getVRData = $getVR->fetch_assoc()) {
                                    $vr_id = $getVRData['id'];
                                    $myname = $getVRData['name'];
                                    $map_name = $getVRData['map_name'];
                                    $interfaces = $getVRData['interfaces'];
                                    $admin_dist_static = $getVRData['admin_dist_static'];
                                    $admin_dist_ospf_int = $getVRData['admin_dist_ospf_int'];
                                    $admin_dist_ospf_ext = $getVRData['admin_dist_ospf_ext'];
                                    $admin_dist_ibgp = $getVRData['admin_dist_ibgp'];
                                    $admin_dist_ebgp = $getVRData['admin_dist_ebgp'];
                                    $admin_dist_rip = $getVRData['admin_dist_rip'];
                                    $protocol = $getVRData['protocol'];
                                    $multicast = $getVRData['multicast'];
                                    $admin_dist_static_ipv6 = $getVRData['admin_dist_static_ipv6'];
                                    $admin_dist_ospfv3_int = $getVRData['admin_dist_ospfv3_int'];
                                    $admin_dist_ospfv3_ext = $getVRData['admin_dist_ospfv3_ext'];
                                    $ecmp= $getVRData['ecmp'];

                                    $vr = $theVR->addChild('entry');
                                    $vr->addAttribute('name', $myname);

                                    $vr->addChild("interface");
                                    $interface = $vr->interface;
                                    if ($interfaces != "") {
                                        foreach (explode(",", $interfaces) as $key => $value) {
                                            $interface->addChild("member", $value);
                                        }
                                    }

                                    if ($protocol != "") {
                                        $xml_append = simplexml_load_string($protocol);
                                        SimpleXMLElement_append($vr, $xml_append);
                                        //$myvrprotocol=$vr->addChild("protocol");
                                        //$xml_append = simplexml_load_string($protocol);
                                        //SimpleXMLElement_append($myvrprotocol, $xml_append);
                                    }
                                    
                                    if ($version>=7){
                                        if ($ecmp != "") {
                                            $xml_append = simplexml_load_string($ecmp);
                                            SimpleXMLElement_append($vr, $xml_append);
                                        }
                                    }
                                    
                                    if ($multicast != "") {
                                        $vr->addChild("multicast");
                                        $multicastxml = $vr->multicast;
                                        $xml_append = simplexml_load_string($multicast);
                                        SimpleXMLElement_append($multicastxml, $xml_append);
                                    }

                                    #Metrics
                                    $vr->addChild("admin-dists");
                                    if ( ( $admin_dist_static == "") OR ( $admin_dist_static == "0")) {
                                        
                                    } else {
                                        $vr->{'admin-dists'}->addChild("static", $admin_dist_static);
                                    }

                                    if (( $admin_dist_ospf_int == "") OR ( $admin_dist_ospf_int == "0")) {
                                        
                                    } else {
                                        $vr->{'admin-dists'}->addChild("ospf-int", $admin_dist_ospf_int);
                                    }

                                    if (( $admin_dist_ospf_ext == "") OR ( $admin_dist_ospf_ext == "0")) {
                                        
                                    } else {
                                        $vr->{'admin-dists'}->addChild("ospf-ext", $admin_dist_ospf_ext);
                                    }

                                    if (( $admin_dist_ibgp == "") OR ( $admin_dist_ibgp == "0")) {
                                        
                                    } else {
                                        $vr->{'admin-dists'}->addChild("ibgp", $admin_dist_ibgp);
                                    }

                                    if (( $admin_dist_ebgp == "") OR ( $admin_dist_ebgp == "0")) {
                                        
                                    } else {
                                        $vr->{'admin-dists'}->addChild("ebgp", $admin_dist_ebgp);
                                    }

                                    if (( $admin_dist_rip == "") OR ( $admin_dist_rip == "0")) {
                                        
                                    } else {
                                        $vr->{'admin-dists'}->addChild("rip", $admin_dist_rip);
                                    }

                                    if ($version >= 6) {
                                        if (( $admin_dist_static_ipv6 == "") OR ( $admin_dist_static_ipv6 == "0")) {
                                            
                                        } else {
                                            $vr->{'admin-dists'}->addChild("static-ipv6", $admin_dist_static_ipv6);
                                        }

                                        if (( $admin_dist_ospfv3_int == "") OR ( $admin_dist_ospfv3_int == "0")) {
                                            
                                        } else {
                                            $vr->{'admin-dists'}->addChild("ospfv3-int", $admin_dist_ospfv3_int);
                                        }

                                        if (( $admin_dist_ospfv3_ext == "") OR ( $admin_dist_ospfv3_ext == "0")) {
                                            
                                        } else {
                                            $vr->{'admin-dists'}->addChild("ospfv3-ext", $admin_dist_ospfv3_ext);
                                        }
                                    }

                                    # Static Routing
                                    $exist = $projectdb->query("SELECT id FROM routes_static WHERE template='$template' AND source='$source' AND vr_id='$vr_id';");
                                    if ($exist->num_rows > 0) {
                                        $vr->addChild("routing-table");
                                        # IPV4
                                        $getStatic = $projectdb->query("SELECT name,destination,tointerface,nexthop,nexthop_value,metric,admin_dist,option_no_install,zone FROM routes_static WHERE vr_id='$vr_id' AND ip_version='v4' AND source='$source' AND template='$template';");
                                        if ($getStatic->num_rows > 0) {
                                            $vr->{'routing-table'}->addChild("ip");
                                            $vr->{'routing-table'}->ip->addChild("static-route");
                                            $routes = $vr->{'routing-table'}->ip->{'static-route'};
                                            while ($getStaticData = $getStatic->fetch_assoc()) {
                                                $name = $getStaticData['name'];
                                                $destination = $getStaticData['destination'];
                                                $tointerface = $getStaticData['tointerface'];
                                                $nexthop = $getStaticData['nexthop'];
                                                $nexthop_value = $getStaticData['nexthop_value'];
                                                $metric = $getStaticData['metric'];
                                                $admin_dist = $getStaticData['admin_dist'];
                                                $option_no_install = $getStaticData['option_no_install'];
                                                $zone = $getStaticData['zone'];

                                                $route = $routes->addChild("entry");
                                                $route->addAttribute('name', $name);

                                                if ($destination != "") {
                                                    $route->addChild("destination", $destination);
                                                }

                                                if ($option_no_install == 1) {
                                                    $route->addChild("option");
                                                    $route->option->addChild("no-install");
                                                }

                                                if (($metric != "") AND ( $metric != "0")) {
                                                    $route->addChild("metric", $metric);
                                                }

                                                if (($admin_dist != "") AND ( $admin_dist != "0")) {
                                                    $route->addChild("admin-dist", $admin_dist);
                                                }

                                                if ($tointerface != "") {
                                                    $route->addChild("interface", $tointerface);
                                                }

                                                if ($nexthop != "None") {
                                                    $route->addChild("nexthop");
                                                    if ($nexthop_value != "") {
                                                        $route->nexthop->addChild($nexthop, $nexthop_value);
                                                    } else {
                                                        $route->nexthop->addChild($nexthop);
                                                    }
                                                }
                                            }
                                        }

                                        #IPV6
                                        $getStatic = $projectdb->query("SELECT name,destination,tointerface,nexthop,nexthop_value,metric,admin_dist,option_no_install,zone FROM routes_static WHERE vr_id='$vr_id' AND ip_version='v6' AND source='$source' AND template='$template';");
                                        if ($getStatic->num_rows > 0) {
                                            $vr->{'routing-table'}->addChild("ipv6");
                                            $vr->{'routing-table'}->ipv6->addChild("static-route");
                                            $routes = $vr->{'routing-table'}->ipv6->{'static-route'};
                                            while ($getStaticData = $getStatic->fetch_assoc()) {
                                                $name = $getStaticData['name'];
                                                $destination = $getStaticData['destination'];
                                                $tointerface = $getStaticData['tointerface'];
                                                $nexthop = $getStaticData['nexthop'];
                                                $nexthop_value = $getStaticData['nexthop_value'];
                                                $metric = $getStaticData['metric'];
                                                $admin_dist = $getStaticData['admin_dist'];
                                                $option_no_install = $getStaticData['option_no_install'];
                                                $zone = $getStaticData['zone'];

                                                $route = $routes->addChild("entry");
                                                $route->addAttribute('name', $name);

                                                if ($destination != "") {
                                                    $route->addChild("destination", $destination);
                                                }

                                                if ($option_no_install == 1) {
                                                    $route->addChild("option");
                                                    $route->option->addChild("no-install");
                                                }

                                                if ($metric != "") {
                                                    $route->addChild("metric", $metric);
                                                }

                                                if ($admin_dist != "") {
                                                    $route->addChild("admin-dist", $admin_dist);
                                                }

                                                if ($tointerface != "") {
                                                    $route->addChild("interface", $tointerface);
                                                }

                                                if ($nexthop != "None") {
                                                    $route->addChild("nexthop");
                                                    if ($nexthop_value != "") {
                                                        $route->nexthop->addChild($nexthop, $nexthop_value);
                                                    } else {
                                                        $route->nexthop->addChild($nexthop);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            } 
            else {
                #Firewall
                $getDG = $projectdb->query("SELECT * FROM virtual_systems WHERE source='$source';");
                if ($getDG->num_rows > 0) {
                    #Check if VSYS root Exists
                    $existDGroot = $xml->xpath("//devices/entry[@name='localhost.localdomain']/vsys");
                    if (empty($existDGroot)) {
                        $root = $xml->xpath("//devices/entry[@name='localhost.localdomain']");
                        $root[0]->addChild('vsys');
                    }
                    $allDG = array();
                    $platform = "vsys";
                    $policies = array("rulebase");
                    while ($DG = $getDG->fetch_assoc()) {
                        $DGName = $DG['name'];
                        $allDG[] = $DGName; # To be used after this process to do a loop
                        $thedevicegroup1 = $xml->xpath("//devices/entry[@name='localhost.localdomain']/vsys/entry[@name='$DGName']");
                        if (empty($thedevicegroup1)) {
                            $thedevicegroupPath = $xml->xpath("//devices/entry[@name='localhost.localdomain']/vsys");
                            $thedevicegroup = $thedevicegroupPath[0]->addChild('entry');
                            $thedevicegroup->addAttribute('name', $DGName);

                            if ($DG['display_name'] != "") {
                                $thedevicegroup->addChild("display-name", $DG['display_name']);
                            }
                        } else {
                            $thedevicegroup = $thedevicegroup1[0];
                            if ($DG['display_name'] != "") {
                                if (isset($thedevicegroup->{"display-name"})){
                                    $thedevicegroup->{"display-name"}=$DG['display_name'];
                                }
                                else {
                                    $thedevicegroup->addChild("display-name", $DG['display_name']);
                                }
                            }
                        }

                        #Import Network
                        $thedevicegroup1 = $xml->xpath("//devices/entry[@name='localhost.localdomain']/vsys/entry[@name='$DGName']/import");
                        if (empty($thedevicegroup1)) {
                            $thedevicegroup->addChild('import');
                            $thedevicegroup->import->addChild('network');
                        }
                        #Interface
                        if ($DG['interfaces'] != "") {
                            if (isset($thedevicegroup->import->network->interface)) {
                                $SA = $thedevicegroup->xpath("import/network/interface");
                                unset($SA[0][0]);
                            }
                            $myinterface=$thedevicegroup->import->network->addChild('interface');
                            $interfaces = explode(",", $DG['interfaces']);
                            foreach ($interfaces as $key => $value) {
                                if ($value != "") {
                                    $myinterface->addChild('member', $value);
                                }
                            }
                        }

                        if ($DG['virtual_router'] != "") {
                            if (isset($thedevicegroup->import->network->{'virtual-router'})) {
                                $SA = $thedevicegroup->xpath("import/network/virtual-router");
                                unset($SA[0][0]);
                            }
                            $myvirtualrouter=$thedevicegroup->import->network->addChild('virtual-router');
                            $interfaces = explode(",", $DG['virtual_router']);
                            foreach ($interfaces as $key => $value) {
                                if ($value != "") {
                                    $myvirtualrouter->addChild('member', $value);
                                }
                            }
                        }

                        if ($DG['virtual_wire'] != "") {
                            if (isset($thedevicegroup->import->network->{'virtual-wire'})) {
                                $SA = $thedevicegroup->xpath("import/network/virtual-wire");
                                unset($SA[0][0]);
                            }
                            $myvirtualwire=$thedevicegroup->import->network->addChild('virtual-wire');
                            $interfaces = explode(",", $DG['virtual_wire']);
                            foreach ($interfaces as $key => $value) {
                                if ($value != "") {
                                    $myvirtualwire->addChild('member', $value);
                                }
                            }
                        }

                        if ($DG['vlan'] != "") {
                            if (isset($thedevicegroup->import->network->{'vlan'})) {
                                $SA = $thedevicegroup->xpath("import/network/vlan");
                                unset($SA[0][0]);
                            }
                            $myvlan=$thedevicegroup->import->network->addChild('vlan');
                            $interfaces = explode(",", $DG['vlan']);
                            foreach ($interfaces as $key => $value) {
                                if ($value != "") {
                                    $myvlan->addChild('member', $value);
                                }
                            }
                        }

                        if ($DG['visible_vsys'] != "") {
                            if (isset($thedevicegroup->import->network->{'visible-vsys'})) {
                                $SA = $thedevicegroup->xpath("import/network/visible-vsys");
                                unset($SA[0][0]);
                            }
                            $myvisible=$thedevicegroup->import->network->addChild('visible-vsys');
                            $interfaces = explode(",", $DG['visible_vsys']);
                            foreach ($interfaces as $key => $value) {
                                if ($value != "") {
                                    $myvisible->addChild('member', $value);
                                }
                            }
                        }

                        if (isset($thedevicegroup->import->resource)) {
                            $SA = $thedevicegroup->xpath("import/resource");
                            unset($SA[0][0]);
                        }
                        $thedevicegroup->import->addChild('resource');
                        $DGresource = $thedevicegroup->import->resource;
                        $max_application_override_rules = $DG['max_application_override_rules'];
                        if ($max_application_override_rules != "0") {
                            $DGresource->addChild('max-application-override-rules', $max_application_override_rules);
                        }
                        $max_concurrent_ssl_vpn_tunnels = $DG['max_concurrent_ssl_vpn_tunnels'];
                        if ($max_concurrent_ssl_vpn_tunnels != "0") {
                            $DGresource->addChild('max-concurrent-ssl-vpn-tunnels', $max_concurrent_ssl_vpn_tunnels);
                        }
                        $max_cp_rules = $DG['max_cp_rules'];
                        if ($max_cp_rules != "0") {
                            $DGresource->addChild('max-cp-rules', $max_cp_rules);
                        }
                        $max_dos_rules = $DG['max_dos_rules'];
                        if ($max_dos_rules != "0") {
                            $DGresource->addChild('max-dos-rules', $max_dos_rules);
                        }
                        $max_nat_rules = $DG['max_nat_rules'];
                        if ($max_nat_rules != "0") {
                            $DGresource->addChild('max-nat-rules', $max_nat_rules);
                        }
                        $max_pbf_rules = $DG['max_pbf_rules'];
                        if ($max_pbf_rules != "0") {
                            $DGresource->addChild('max-pbf-rules', $max_pbf_rules);
                        }
                        $max_qos_rules = $DG['max_qos_rules'];
                        if ($max_qos_rules != "0") {
                            $DGresource->addChild('max-qos-rules', $max_qos_rules);
                        }
                        $max_security_rules = $DG['max_security_rules'];
                        if ($max_security_rules != "0") {
                            $DGresource->addChild('max-security-rules', $max_security_rules);
                        }
                        $max_sessions = $DG['max_sessions'];
                        if ($max_sessions != "0") {
                            $DGresource->addChild('max-sessions', $max_sessions);
                        }
                        $max_site_to_site_vpn_tunnels = $DG['max_site_to_site_vpn_tunnels'];
                        if ($max_site_to_site_vpn_tunnels != "0") {
                            $DGresource->addChild('max-site-to-site-vpn-tunnels', $max_site_to_site_vpn_tunnels);
                        }
                        $max_ssl_decryption_rules = $DG['max_ssl_decryption_rules'];
                        if ($max_ssl_decryption_rules != "0") {
                            $DGresource->addChild('max-ssl-decryption-rules', $max_ssl_decryption_rules);
                        }
                        $dns_proxy = $DG['dns_proxy'];
                        if (($dns_proxy != "") AND ( $dns_proxy != "None")) {
                            $thedevicegroup->import->addChild('dns-proxy');
                            $thedevicegroup->import->{'dns-proxy'}->addChild($dns_proxy);
                        }
                        $allow_forward_decrypted_content = $DG['allow_forward_decrypted_content'];
                        if ($allow_forward_decrypted_content == "") {
                            $allow_forward_decrypted_content = "no";
                        }
                        
                        if (($max_application_override_rules==0) AND ($max_concurrent_ssl_vpn_tunnels==0) AND ($max_cp_rules==0) AND ($max_dos_rules==0) 
                                AND ($max_nat_rules==0) AND ($max_pbf_rules==0) AND ($max_qos_rules==0) AND ($max_security_rules==0) AND ($max_ssl_decryption_rules==0)
                                AND ($dns_proxy==0) AND ($max_sessions==0) AND ($max_site_to_site_vpn_tunnels==0)) {
                            if ($thedevicegroup->xpath("import/resource")){
                                $SA = $thedevicegroup->xpath("import/resource");
                                unset($SA[0][0]);
                            }
                                
                        }
                        
                        if (isset($thedevicegroup->setting->{'ssl-decrypt'})) {

                            $SA = $thedevicegroup->xpath("/setting/ssl-decrypt");
                            unset($SA[0][0]);
                            #$thedevicegroup->addChild('setting');
                            #$thedevicegroup->setting->addChild('ssl-decrypt');
                            #$thedevicegroup->setting->{'ssl-decrypt'}->addChild('allow-forward-decrypted-content',$allow_forward_decrypted_content);
                        }
                    }
                }

                #Networking
                $getTemplate = $projectdb->query("SELECT id FROM templates_mapping WHERE source='$source';");
                if ($getTemplate->num_rows == 1) {
                    $getTemplateData = $getTemplate->fetch_assoc();
                    $template = $getTemplateData['id'];
                }
                if ($template != "") {
                    
                    # MONITOR PROFILE
                    
                    $getMonitor = $projectdb->query("SELECT name,m_action,interva,threshold FROM monitor_profile WHERE source='$source' AND template='$template' AND name != '' GROUP BY name;");
                    if ($getMonitor->num_rows >0){
                        /*if (!isset($xml->devices->entry[0]->network->profiles->{'monitor-profile'})){
                            $xml->devices->entry[0]->network->profiles->addChild("monitor-profile");
                        }
                        else{
                            unset($xml->devices->entry[0]->network->profiles->{'monitor-profile'});
                            $xml->devices->entry[0]->network->profiles->addChild("monitor-profile");
                        }*/
                        
                        if (!isset($xml->devices->entry[0]->network->profiles->{'monitor-profile'})) {
                            if (!isset($xml->devices->entry[0]->network->profiles)) {
                                $xml->devices->entry[0]->network->addChild('profiles');
                            }
                            $xml->devices->entry[0]->network->profiles->addChild('monitor-profile');
                        } else {
                            #DELETE monitor-profile
                            $SA = $xml->xpath("/config/devices/entry/network/profiles/monitor-profile");
                            unset($SA[0][0]);
                            $xml->devices->entry[0]->network->profiles->addChild('monitor-profile');
                        }
                        
                        $MPXpath = $xml->devices->entry[0]->network->profiles->{'monitor-profile'};
                        while ($getMonitorData=$getMonitor->fetch_assoc()){
                            $myname = $getMonitorData['name'];
                            $MPAction=$getMonitorData['m_action'];
                            $MPInterval=$getMonitorData['interva'];
                            $MPThreshold=$getMonitorData['threshold'];
                                    
                            //if (count($MPXpath->xpath("//entry[@name='$myname']"))==0) {
                            $monitorProfile = $MPXpath->addChild('entry');
                            $monitorProfile->addAttribute('name', $getMonitorData['name']);
                            if (($MPInterval!=0) AND ($MPInterval!="")){
                                $monitorProfile->addChild("interval");
                                $monitorProfile->interval=$MPInterval;
                            }
                            if (($MPThreshold!=0) AND ($MPThreshold!="")){
                                $monitorProfile->addChild("threshold");
                                $monitorProfile->threshold=$MPThreshold;
                            }
                            if ($MPAction!=""){
                                $monitorProfile->addChild("action");
                                $monitorProfile->action=$MPAction;
                            }
                            //}
                        }
                    }
                    else{
                        $SA = $xml->xpath("/config/devices/entry/network/profiles/monitor-profile");
                        unset($SA[0][0]);
                    }
                    
                    $create_branch_ike_crypto_profile = 0;
                    
                    # IKE CRYPTO
                    $getIKECrypto = $projectdb->query("SELECT name, encryption, hash, dh_group, seconds, minutes, hours, days, authentication_multiple FROM ike_crypto_profiles WHERE source = '$source' AND template = '$template' AND name != '';");
                    if ($getIKECrypto->num_rows > 0){
                        
                        if($create_branch_ike_crypto_profile == 0){
                            if (!isset($xml->devices->entry[0]->network->ike->{'crypto-profiles'})){
                                if (!isset($xml->devices->entry[0]->network->ike)) {
                                    $xml->devices->entry[0]->network->addChild('ike');
                                }
                                $xml->devices->entry[0]->network->ike->addChild("crypto-profiles");
                                $create_branch_ike_crypto_profile = 1;
                            }else{
                                unset($xml->devices->entry[0]->network->ike->{'crypto-profiles'});
                                $xml->devices->entry[0]->network->ike->addChild("crypto-profiles");
                                $create_branch_ike_crypto_profile = 1;
                            }
                        }
                        
                        if (!isset($xml->devices->entry[0]->network->ike->{'crypto-profiles'}->{'ike-crypto-profiles'})){
                            $xml->devices->entry[0]->network->ike->{'crypto-profiles'}->addChild("ike-crypto-profiles");
                        }
                        else{
                            unset($xml->devices->entry[0]->network->ike->{'crypto-profiles'}->{'ike-crypto-profiles'});
                            $xml->devices->entry[0]->network->ike->{'crypto-profiles'}->addChild("ike-crypto-profiles");
                        }
                        
                        $ike_crypto_xpath = $xml->devices->entry[0]->network->ike->{'crypto-profiles'}->{'ike-crypto-profiles'};
                        while ($dataIKEC = $getIKECrypto->fetch_assoc()){
                            $myname = $dataIKEC['name'];
                            $ike_encryption = $dataIKEC['encryption'];
                            $ike_hash = $dataIKEC['hash'];
                            $ike_dh_group = $dataIKEC['dh_group'];
                            $ike_seconds = $dataIKEC['seconds'];
                            $ike_minutes = $dataIKEC['minutes'];
                            $ike_hours = $dataIKEC['hours'];
                            $ike_days = $dataIKEC['days'];
                            $ike_authentication_multiple = $dataIKEC['authentication_multiple'];
                                    
                            $ike_crypto = $ike_crypto_xpath->addChild('entry');
                            $ike_crypto->addAttribute('name', $dataIKEC['name']);
                            if ($ike_encryption != ""){
                                $ike_crypto->addChild("encryption");
                                $ike_encryption_array = explode(",", $ike_encryption);
                                foreach($ike_encryption_array as $member_ike){
                                    $ike_crypto->encryption->addChild("member", $member_ike);
                                }
                            }
                            if ($ike_hash != ""){
                                $ike_crypto->addChild("hash");
                                $ike_hash_array = explode(",", $ike_hash);
                                foreach($ike_hash_array as $member_ike){
                                    $ike_crypto->hash->addChild("member", $member_ike);
                                }
                            }
                            if ($ike_dh_group != ""){
                                $ike_crypto->addChild("dh-group");
                                $ike_dh_group_array = explode(",", $ike_dh_group);
                                foreach($ike_dh_group_array as $member_ike){
                                    $ike_crypto->{'dh-group'}->addChild("member", $member_ike);
                                }
                            }
                            if ($ike_seconds != 0){
                                $ike_crypto->addChild("lifetime");
                                $ike_crypto->{'lifetime'}->seconds = $ike_seconds;
                            }
                            if ($ike_minutes != 0){
                                $ike_crypto->addChild("lifetime");
                                $ike_crypto->{'lifetime'}->minutes = $ike_minutes;
                            }
                            if ($ike_hours != 0){
                                $ike_crypto->addChild("lifetime");
                                $ike_crypto->{'lifetime'}->hours = $ike_hours;
                            }
                            if ($ike_days != 0){
                                $ike_crypto->addChild("lifetime");
                                $ike_crypto->{'lifetime'}->days = $ike_days;
                            }
                        }
                    }
                    else{
                        $SA = $xml->xpath("/config/devices/entry/network/ike/crypto-profiles/ike-crypto-profiles");
                        unset($SA[0][0]);
                    }
                    
                    
                    # IPSEC CRYPTO
                    $getIPSECCrypto = $projectdb->query("SELECT name, encryption, hash, dh_group, protocol, seconds, minutes, hours, days, kb, mb, gb, tb FROM ipsec_crypto_profiles WHERE source = '$source' AND template = '$template' AND name != '';");
                    if ($getIPSECCrypto->num_rows > 0){
                        
                        if($create_branch_ike_crypto_profile == 0){
                            if (!isset($xml->devices->entry[0]->network->ike->{'crypto-profiles'})){
                                if (!isset($xml->devices->entry[0]->network->ike)) {
                                    $xml->devices->entry[0]->network->addChild('ike');
                                }
                                $xml->devices->entry[0]->network->ike->addChild("crypto-profiles");
                                $create_branch_ike_crypto_profile = 1;
                            }else{
                                unset($xml->devices->entry[0]->network->ike->{'crypto-profiles'});
                                $xml->devices->entry[0]->network->ike->addChild("crypto-profiles");
                                $create_branch_ike_crypto_profile = 1;
                            }
                        }
                        
                        if (!isset($xml->devices->entry[0]->network->ike->{'crypto-profiles'}->{'ipsec-crypto-profiles'})){
                            $xml->devices->entry[0]->network->ike->{'crypto-profiles'}->addChild("ipsec-crypto-profiles");
                        }
                        else{
                            unset($xml->devices->entry[0]->network->ike->{'crypto-profiles'}->{'ipsec-crypto-profiles'});
                            $xml->devices->entry[0]->network->ike->{'crypto-profiles'}->addChild("ipsec-crypto-profiles");
                        }
                        $ipsec_crypto_xpath = $xml->devices->entry[0]->network->ike->{'crypto-profiles'}->{'ipsec-crypto-profiles'};
                        
                        while ($dataIPSECC = $getIPSECCrypto->fetch_assoc()){
                            $myname = $dataIPSECC['name'];
                            $ipsec_encryption = $dataIPSECC['encryption'];
                            $ipsec_hash = $dataIPSECC['hash'];
                            $ipsec_dh_group = $dataIPSECC['dh_group'];
                            $ipsec_protocol = $dataIPSECC['protocol'];
                            $ipsec_seconds = $dataIPSECC['seconds'];
                            $ipsec_minutes = $dataIPSECC['minutes'];
                            $ipsec_hours = $dataIPSECC['hours'];
                            $ipsec_days = $dataIPSECC['days'];
                            $ipsec_kb = $dataIPSECC['kb'];
                            $ipsec_mb = $dataIPSECC['mb'];
                            $ipsec_gb = $dataIPSECC['gb'];
                            $ipsec_tb = $dataIPSECC['tb'];
                                 
                            $ipsec_crypto = $ipsec_crypto_xpath->addChild('entry');
                            $ipsec_crypto->addAttribute('name', $dataIPSECC['name']);
                                    
                            if($ipsec_protocol == "ESP"){
                                $ipsec_crypto->addChild("esp");

                                if ($ipsec_encryption != ""){
                                    $ipsec_crypto->esp->addChild("encryption");
                                    $ipsec_encryption_array = explode(",", $ipsec_encryption);
                                    foreach($ipsec_encryption_array as $member_ike){
                                        $ipsec_crypto->esp->encryption->addChild("member", $member_ike);
                                    }
                                }
                                if ($ipsec_hash != ""){
                                    $ipsec_crypto->esp->addChild("authentication");
                                    $ipsec_hash_array = explode(",", $ipsec_hash);
                                    foreach($ipsec_hash_array as $member_ike){
                                        $ipsec_crypto->esp->authentication->addChild("member", $member_ike);
                                    }
                                }
                            }

                            if($ipsec_protocol == "AH"){
                                $ipsec_crypto->addChild("ah");

                                if ($ipsec_hash != ""){
                                    $ipsec_crypto->ah->addChild("authentication");
                                    $ipsec_hash_array = explode(",", $ipsec_hash);
                                    foreach($ipsec_hash_array as $member_ike){
                                        $ipsec_crypto->ah->authentication->addChild("member", $member_ike);
                                    }
                                }
                            }

                            if ($ipsec_dh_group != ""){
                                $ipsec_crypto->addChild("dh-group");
                                $ipsec_crypto->{'dh-group'} = $ipsec_dh_group;
                            }
                            if ($ipsec_seconds != 0){
                                $ipsec_crypto->addChild("lifetime");
                                $ipsec_crypto->{'lifetime'}->seconds = $ipsec_seconds;
                            }
                            if ($ipsec_minutes != 0){
                                $ipsec_crypto->addChild("lifetime");
                                $ipsec_crypto->{'lifetime'}->minutes = $ipsec_minutes;
                            }
                            if ($ipsec_hours != 0){
                                $ipsec_crypto->addChild("lifetime");
                                $ipsec_crypto->{'lifetime'}->hours = $ipsec_hours;
                            }
                            if ($ipsec_days != 0){
                                $ipsec_crypto->addChild("lifetime");
                                $ipsec_crypto->{'lifetime'}->days = $ipsec_days;
                            }

                            if ($ipsec_kb != 0){
                                $ipsec_crypto->addChild("lifesize");
                                $ipsec_crypto->{'lifesize'}->kb = $ipsec_kb;
                            }
                            if ($ipsec_mb != 0){
                                $ipsec_crypto->addChild("lifesize");
                                $ipsec_crypto->{'lifesize'}->mb = $ipsec_mb;
                            }
                            if ($ipsec_gb != 0){
                                $ipsec_crypto->addChild("lifesize");
                                $ipsec_crypto->{'lifesize'}->gb = $ipsec_gb;
                            }
                            if ($ipsec_tb != 0){
                                $ipsec_crypto->addChild("lifesize");
                                $ipsec_crypto->{'lifesize'}->tb = $ipsec_tb;
                            }
                        }
                    }
                    else{
                        $SA = $xml->xpath("/config/devices/entry/network/ike/crypto-profiles/ipsec-crypto-profiles");
                        unset($SA[0][0]);
                    }
                    
                    # GLOBAL PROTECT IPSEC CRYPTO
                    
                    $getIKECrypto = $projectdb->query("SELECT name, encryption, hash FROM global_protect_app_ipsec_crypto_profiles WHERE source = '$source' AND template = '$template' AND name != '';");
                    if ($getIKECrypto->num_rows > 0){
                        
                        if($create_branch_ike_crypto_profile == 0){
                            if (!isset($xml->devices->entry[0]->network->ike->{'crypto-profiles'})){
                                if (!isset($xml->devices->entry[0]->network->ike)) {
                                    $xml->devices->entry[0]->network->addChild('ike');
                                }
                                $xml->devices->entry[0]->network->ike->addChild("crypto-profiles");
                                $create_branch_ike_crypto_profile = 1;
                            }else{
                                unset($xml->devices->entry[0]->network->ike->{'crypto-profiles'});
                                $xml->devices->entry[0]->network->ike->addChild("crypto-profiles");
                                $create_branch_ike_crypto_profile = 1;
                            }
                        }
                        
                        if (!isset($xml->devices->entry[0]->network->ike->{'crypto-profiles'}->{'global-protect-app-crypto-profiles'})){
                            $xml->devices->entry[0]->network->ike->{'crypto-profiles'}->addChild("global-protect-app-crypto-profiles");
                        }
                        else{
                            unset($xml->devices->entry[0]->network->ike->{'crypto-profiles'}->{'global-protect-app-crypto-profiles'});
                            $xml->devices->entry[0]->network->ike->{'crypto-profiles'}->addChild("global-protect-app-crypto-profiles");
                        }
                        
                        $ike_crypto_xpath = $xml->devices->entry[0]->network->ike->{'crypto-profiles'}->{'global-protect-app-crypto-profiles'};
                        while ($dataIKEC = $getIKECrypto->fetch_assoc()){
                            $myname = $dataIKEC['name'];
                            $ike_encryption = $dataIKEC['encryption'];
                            $ike_hash = $dataIKEC['hash'];
                                    
                            $ike_crypto = $ike_crypto_xpath->addChild('entry');
                            $ike_crypto->addAttribute('name', $dataIKEC['name']);
                            if ($ike_encryption != ""){
                                $ike_crypto->addChild("encryption");
                                $ike_encryption_array = explode(",", $ike_encryption);
                                foreach($ike_encryption_array as $member_ike){
                                    $ike_crypto->encryption->addChild("member", $member_ike);
                                }
                            }
                            if ($ike_hash != ""){
                                $ike_crypto->addChild("authentication");
                                $ike_hash_array = explode(",", $ike_hash);
                                foreach($ike_hash_array as $member_ike){
                                    $ike_crypto->authentication->addChild("member", $member_ike);
                                }
                            }
                        }
                    }
                    else{
                        $SA = $xml->xpath("/config/devices/entry/network/ike/crypto-profiles/global-protect-app-crypto-profiles");
                        unset($SA[0][0]);
                    }
                    
                    # IKE GATEWAYS
                    $getIKEGateways = $projectdb->query("SELECT name, version, dpd_ikev1, ike_interval_ikev1, retry_ikev1, ike_crypto_profile_ikev1, exchange_mode_ikev1, dpd_ikev2, ike_interval_ikev2, ike_crypto_profile_ikev2, require_cookie_ikev2, local_address_ip, interface, type_authentication, pre_shared_key, allow_id_payload_mismatch, local_certificate, certificate_profile, strict_validation_revocation, hash_and_url, base_url, nat_traversal, passive_mode, fragmentation, peer_ip_type, peer_ip_address, local_id, local_id_type, peer_id, peer_id_type, peer_id_matching, address_type  FROM ike_gateways_profiles WHERE source = '$source' AND template = '$template' AND name != '';");
                    if ($getIKEGateways->num_rows > 0){
                        
                        if (!isset($xml->devices->entry[0]->network->ike->gateway)){
                            if (!isset($xml->devices->entry[0]->network->ike)) {
                                $xml->devices->entry[0]->network->addChild('ike');
                            }
                            $xml->devices->entry[0]->network->ike->addChild("gateway");
                        }else{
                            unset($xml->devices->entry[0]->network->ike->gateway);
                            $xml->devices->entry[0]->network->ike->addChild("gateway");
                        }
                        
                        $ike_gateways_xpath = $xml->devices->entry[0]->network->ike->gateway;
                        
                        while ($dataIKEGat = $getIKEGateways->fetch_assoc()){
                            $myname = $dataIKEGat['name'];
                            $ike_gat_version = $dataIKEGat['version'];
                            $ike_gat_dpd_ikev1 = $dataIKEGat['dpd_ikev1'];
                            $ike_gat_ike_interval_ikev1 = $dataIKEGat['ike_interval_ikev1'];
                            $ike_gat_retry_ikev1 = $dataIKEGat['retry_ikev1'];
                            $ike_gat_ike_crypto_profile_ikev1 = $dataIKEGat['ike_crypto_profile_ikev1'];
                            $ike_gat_exchange_mode_ikev1 = $dataIKEGat['exchange_mode_ikev1'];
                            $ike_gat_dpd_ikev2 = $dataIKEGat['dpd_ikev2'];
                            $ike_gat_ike_interval_ikev2 = $dataIKEGat['ike_interval_ikev2'];
                            $ike_gat_ike_crypto_profile_ikev2 = $dataIKEGat['ike_crypto_profile_ikev2'];
                            $ike_gat_require_cookie_ikev2 = $dataIKEGat['require_cookie_ikev2'];
                            $ike_gat_local_address_ip = $dataIKEGat['local_address_ip'];
                            $ike_gat_interface = $dataIKEGat['interface'];
                            $ike_gat_type_authentication = $dataIKEGat['type_authentication'];
                            $ike_gat_pre_shared_key = $dataIKEGat['pre_shared_key'];
                            $ike_gat_allow_id_payload_mismatch = $dataIKEGat['allow_id_payload_mismatch'];
                            $ike_gat_local_certificate = $dataIKEGat['local_certificate'];
                            $ike_gat_certificate_profile = $dataIKEGat['certificate_profile'];
                            $ike_gat_strict_validation_revocation = $dataIKEGat['strict_validation_revocation'];
                            $ike_gat_hash_and_url = $dataIKEGat['hash_and_url'];
                            $ike_gat_base_url = $dataIKEGat['base_url'];
                            $ike_gat_nat_traversal = $dataIKEGat['nat_traversal'];
                            $ike_gat_passive_mode = $dataIKEGat['passive_mode'];
                            $ike_gat_fragmentation = $dataIKEGat['fragmentation'];
                            $ike_gat_peer_ip_type = $dataIKEGat['peer_ip_type'];
                            $ike_gat_peer_ip_address = $dataIKEGat['peer_ip_address'];
                            $ike_gat_local_id = $dataIKEGat['local_id'];
                            $ike_gat_local_id_type = $dataIKEGat['local_id_type'];
                            $ike_gat_peer_id = $dataIKEGat['peer_id'];
                            $ike_gat_peer_id_type = $dataIKEGat['peer_id_type'];
                            $ike_gat_peer_id_matching = $dataIKEGat['peer_id_matching'];
                            $ike_gat_address_type = $dataIKEGat['address_type'];

                            $ike_gateways = $ike_gateways_xpath->addChild('entry');
                            $ike_gateways->addAttribute('name', $dataIKEGat['name']);
                                    
                            if($ike_gat_dpd_ikev1 != ""){
                                $ike_gateways->addChild("protocol");
                                $ike_gateways->protocol->addChild("ikev1");
                                $ike_gateways->protocol->ikev1->addChild("dpd");
                                $ike_gateways->protocol->ikev1->dpd->enable = $ike_gat_dpd_ikev1;
                                
                                if($ike_gat_dpd_ikev1 == "yes"){
                                    //$ike_gateways->protocol->ikev1->dpd->addChild("interval", $ike_gat_ike_interval_ikev1);
                                    $ike_gateways->protocol->ikev1->dpd->interval = $ike_gat_ike_interval_ikev1;
                                    $ike_gateways->protocol->ikev1->dpd->retry = $ike_gat_retry_ikev1;
                                }
                                
                                if(($ike_gat_ike_crypto_profile_ikev1 != "") && ($ike_gat_ike_crypto_profile_ikev1 != "default")){
                                    $ike_gateways->protocol->ikev1->{'ike-crypto-profile'} = $ike_gat_ike_crypto_profile_ikev1;
                                }
                                
                                if($ike_gat_exchange_mode_ikev1 != ""){
                                    $ike_gateways->protocol->ikev1->{'exchange-mode'} = $ike_gat_exchange_mode_ikev1;
                                }
                            }
                            
                            // IKE V2 PARA LA VERSIÓN 7
                            if($version >= 7){
                                if($ike_gat_dpd_ikev2 != ""){

                                    $ike_gateways->protocol->ikev2->dpd->enable = $ike_gat_dpd_ikev2;
                                    $ike_gateways->protocol->ikev2->dpd->interval = $ike_gat_ike_interval_ikev2;

                                    if($ike_gat_ike_crypto_profile_ikev2 != ""){
                                        $ike_gateways->protocol->ikev2->{'ike-crypto-profile'} = $ike_gat_ike_crypto_profile_ikev2;
                                    }

                                    if($ike_gat_require_cookie_ikev2 != ""){
                                        $ike_gateways->protocol->ikev2->{'require-cookie'} = $ike_gat_require_cookie_ikev2;
                                    }

                                    if($ike_gat_version != ""){
                                        $ike_gateways->protocol->version = $ike_gat_version;
                                    }

                                }
                            }
                            
                            if($ike_gat_interface != ""){
                                $ike_gateways->addChild("local-address");
                                $ike_gateways->{'local-address'}->interface = $ike_gat_interface;
                                if($ike_gat_local_address_ip != ""){
                                    $ike_gateways->{'local-address'}->ip = $ike_gat_local_address_ip;
                                }
                            }
                            
                            $ike_gat_strict_validation_revocation = $dataIKEGat['strict_validation_revocation'];

                            if($ike_gat_type_authentication == "pre-shared-key"){
                                $ike_gateways->addChild("authentication");
                                $ike_gateways->authentication->{'pre-shared-key'}->key = $ike_gat_pre_shared_key;
                            }
                            elseif($ike_gat_type_authentication == "certificate"){
                                if($version < 7){
                                    
                                    $ike_gateways->addChild("authentication");
                                
                                    if($ike_gat_allow_id_payload_mismatch == "yes"){
                                        $ike_gateways->authentication->certificate->{'allow-id-payload-mismatch'} = $ike_gat_allow_id_payload_mismatch;
                                    }
                                    $ike_gateways->authentication->certificate->{'local-certificate'} = $ike_gat_local_certificate;
                                    $ike_gateways->authentication->certificate->{'certificate-profile'} = $ike_gat_certificate_profile;

                                    if($ike_gat_strict_validation_revocation == "yes"){
                                        $ike_gateways->authentication->certificate->{'strict-validation-revocation'} = $ike_gat_strict_validation_revocation;
                                    }
                                }
                                else{
                                    // Version 7
                                    $ike_gateways->addChild("authentication");
                                    
                                    if($ike_gat_local_certificate != ""){
                                        $ike_gateways->authentication->certificate->{'local-certificate'}->name = $ike_gat_local_certificate;
                                        
                                        if($ike_gat_hash_and_url == "yes"){
                                            $ike_gateways->authentication->certificate->{'local-certificate'}->{'hash-and-url'}->enable = $ike_gat_hash_and_url;
                                            $ike_gateways->authentication->certificate->{'local-certificate'}->{'hash-and-url'}->{'base-url'} = $ike_gat_base_url;
                                        }
                                    }
                                    if($ike_gat_allow_id_payload_mismatch == "yes"){
                                        $ike_gateways->authentication->certificate->{'allow-id-payload-mismatch'} = $ike_gat_allow_id_payload_mismatch;
                                    }
                                    $ike_gateways->authentication->certificate->{'certificate-profile'} = $ike_gat_certificate_profile;

                                    if($ike_gat_strict_validation_revocation == "yes"){
                                        $ike_gateways->authentication->certificate->{'strict-validation-revocation'} = $ike_gat_strict_validation_revocation;
                                    }
                                }
                            }
                            
                            if($ike_gat_nat_traversal != ""){
                                $ike_gateways->addChild("protocol-common");
                                $ike_gateways->{'protocol-common'}->{'nat-traversal'}->enable = $ike_gat_nat_traversal;
                                if($ike_gat_passive_mode == "yes"){
                                    $ike_gateways->{'protocol-common'}->{'passive-mode'} = $ike_gat_passive_mode;
                                }
                                if ($version > 5) {
                                    if($ike_gat_fragmentation == ""){
                                        $ike_gat_fragmentation = "no";
                                    }
                                    $ike_gateways->{'protocol-common'}->fragmentation->enable = $ike_gat_fragmentation;
                                }
                                
                            }
                            
                            if($ike_gat_peer_ip_type == "static"){
                                $ike_gateways->addChild("peer-address");
                                $ike_gateways->{'peer-address'}->ip = $ike_gat_peer_ip_address;
                            }else{
                                $ike_gateways->addChild("peer-address");
                                $ike_gateways->{'peer-address'}->addChild("dynamic");
                            }
                            
                            if($ike_gat_local_id != ""){
                                $ike_gateways->addChild("local-id");
                                $ike_gateways->{'local-id'}->id = $ike_gat_local_id;
                                $ike_gateways->{'local-id'}->type = $ike_gat_local_id_type;
                            }
                            
                            if($ike_gat_peer_id != ""){
                                $ike_gateways->addChild("peer-id");
                                $ike_gateways->{'peer-id'}->id = $ike_gat_peer_id;
                                $ike_gateways->{'peer-id'}->type = $ike_gat_peer_id_type;
                                if($ike_gat_peer_id_matching != ""){
                                    $ike_gateways->{'peer-id'}->matching = $ike_gat_peer_id_matching;
                                }
                            }
                            
                            // Version 7
                            if($ike_gat_address_type == "ipv6"){
                                $ike_gateways->ipv6 = "yes";
                            }
                        }
                    }
                    else{
                        $SA = $xml->xpath("/config/devices/entry/network/ike/gateway");
                        unset($SA[0][0]);
                    }
                    
                    
                    # IPSEC TUNNEL
                
                    $getIPSecTunnel = $projectdb->query("SELECT id, name, anti_replay, copy_tos, tunnel_monitor, destination_ip, tunnel_monitor_profile, tunnel_interface, address_type, type_tunnel, ike_gateway, ipsec_crypto_profile, protocol, authentication, key_auth, encryption, key_encry, local_address_ip, interface, peer_ip_address, local_spi, remote_spi, external_ca, certificate_profile, local_certificate, publish_connected_routes, portal_address, publish_routes FROM ipsec_tunnel WHERE source = '$source' AND template = '$template' AND name != '';");
                    if ($getIPSecTunnel->num_rows > 0){
                        
                        /*if (!isset($xml->devices->entry[0]->network->tunnel->ipsec)){
                            $xml->devices->entry[0]->network->tunnel->addChild("ipsec");
                        }else{
                            unset($xml->devices->entry[0]->network->tunnel->ipsec);
                            $xml->devices->entry[0]->network->tunnel->addChild("ipsec");
                        }*/
                        
                        if (!isset($xml->devices->entry[0]->network->tunnel->ipsec)) {
                            if (!isset($xml->devices->entry[0]->network->tunnel)) {
                                $xml->devices->entry[0]->network->addChild('tunnel');
                            }
                            $xml->devices->entry[0]->network->tunnel->addChild('ipsec');
                        } else {
                            #DELETE Tunnel IPSec
                            $SA = $xml->xpath("/config/devices/entry/network/tunnel/ipsec");
                            unset($SA[0][0]);
                            $xml->devices->entry[0]->network->tunnel->addChild('ipsec');
                        }
                        
                        $ike_ipsec_tunnel_xpath = $xml->devices->entry[0]->network->tunnel->ipsec;
                        
                        while ($dataIPSecTunnel = $getIPSecTunnel->fetch_assoc()){

                            $myname = $dataIPSecTunnel['name'];
                            $ipsec_tun_id = $dataIPSecTunnel['id'];
                            $ipsec_tun_anti_replay = $dataIPSecTunnel['anti_replay'];
                            $ipsec_tun_copy_tos = $dataIPSecTunnel['copy_tos'];
                            $ipsec_tun_tunnel_monitor = $dataIPSecTunnel['tunnel_monitor'];
                            $ipsec_tun_destination_ip = $dataIPSecTunnel['destination_ip'];
                            $ipsec_tun_tunnel_monitor_profile = $dataIPSecTunnel['tunnel_monitor_profile'];
                            $ipsec_tun_tunnel_interface = $dataIPSecTunnel['tunnel_interface'];
                            $ipsec_tun_address_type = $dataIPSecTunnel['address_type'];
                            $ipsec_tun_type_tunnel = $dataIPSecTunnel['type_tunnel'];
                            $ipsec_tun_ike_gateway = $dataIPSecTunnel['ike_gateway'];
                            $ipsec_tun_ipsec_crypto_profile = $dataIPSecTunnel['ipsec_crypto_profile'];
                            $ipsec_tun_protocol = $dataIPSecTunnel['protocol'];
                            $ipsec_tun_authentication = $dataIPSecTunnel['authentication'];
                            $ipsec_tun_key_auth = $dataIPSecTunnel['key_auth'];
                            $ipsec_tun_encryption = $dataIPSecTunnel['encryption'];
                            $ipsec_tun_key_encry = $dataIPSecTunnel['key_encry'];
                            $ipsec_tun_local_address_ip = $dataIPSecTunnel['local_address_ip'];
                            $ipsec_tun_interface = $dataIPSecTunnel['interface'];
                            $ipsec_tun_peer_ip_address = $dataIPSecTunnel['peer_ip_address'];
                            $ipsec_tun_local_spi = $dataIPSecTunnel['local_spi'];
                            $ipsec_tun_remote_spi = $dataIPSecTunnel['remote_spi'];
                            $ipsec_tun_external_ca = $dataIPSecTunnel['external_ca'];
                            $ipsec_tun_certificate_profile = $dataIPSecTunnel['certificate_profile'];
                            $ipsec_tun_local_certificate = $dataIPSecTunnel['local_certificate'];
                            $ipsec_tun_publish_connected_routes = $dataIPSecTunnel['publish_connected_routes'];
                            $ipsec_tun_portal_address = $dataIPSecTunnel['portal_address'];
                            $ipsec_tun_publish_routes = $dataIPSecTunnel['publish_routes'];

                            $ipsec_tunnel = $ike_ipsec_tunnel_xpath->addChild('entry');
                            $ipsec_tunnel->addAttribute('name', $dataIPSecTunnel['name']);

                            # Auto Key
                            if($ipsec_tun_type_tunnel == "auto-key"){

                                $ipsec_tunnel->addChild("auto-key");

                                if($ipsec_tun_ike_gateway != ""){
                                    $ipsec_tunnel->{'auto-key'}->addChild("ike-gateway");
                                    $ipsec_tunnel->{'auto-key'}->{'ike-gateway'}->addChild('entry')->addAttribute('name', $ipsec_tun_ike_gateway);
                                }

                                // Mirar si hay Proxy ID type = v4
                                $getProxyID = $projectdb->query("SELECT name, protocol, local_port, remote_port, number, local, remote, type FROM proxy_id_ipsec_tunnel WHERE ipsec_tunnel_id = '$ipsec_tun_id' AND name != '' AND type = 'v4' AND template = '$template' AND source = '$source';");
                                if ($getProxyID->num_rows > 0){

                                    $ipsec_tunnel->{'auto-key'}->addChild("proxy-id");
                                    $ike_ipsec_tunnel_xpath_proxy_id = $ipsec_tunnel->{'auto-key'}->{'proxy-id'};

                                    while($dataPI = $getProxyID->fetch_assoc()){

                                        $name_proxy_id = $dataPI['name'];
                                        $protocol_proxy_id = $dataPI['protocol'];
                                        $local_port_proxy_id = $dataPI['local_port'];
                                        $remote_port_proxy_id = $dataPI['remote_port'];
                                        $number_proxy_id = $dataPI['number'];
                                        $local_proxy_id = $dataPI['local'];
                                        $remote_proxy_id = $dataPI['remote'];
                                        $type_proxy_id = $dataPI['type'];

                                        $ipsec_tunnel_proxy_id = $ike_ipsec_tunnel_xpath_proxy_id->addChild('entry');
                                        $ipsec_tunnel_proxy_id->addAttribute('name', $name_proxy_id);

                                        if ($protocol_proxy_id == "TCP"){
                                            $ipsec_tunnel_proxy_id->addChild("protocol");
                                            $ipsec_tunnel_proxy_id->protocol->addChild("tcp");
                                            //$ipsec_tunnel->{'auto-key'}->{'proxy-id'}->protocol->addChild("tcp");
                                            if($local_port_proxy_id == ""){
                                                $local_port_proxy_id = 0;
                                            }
                                            if($remote_port_proxy_id == ""){
                                                $remote_port_proxy_id = 0;
                                            }
                                            $ipsec_tunnel_proxy_id->protocol->tcp->{'local-port'} = $local_port_proxy_id;
                                            $ipsec_tunnel_proxy_id->protocol->tcp->{'remote-port'} = $remote_port_proxy_id;
                                        }
                                        elseif($protocol_proxy_id == "Number"){
                                            $ipsec_tunnel_proxy_id->addChild("protocol");
                                            $ipsec_tunnel_proxy_id->protocol->addChild("number");
                                            $ipsec_tunnel_proxy_id->protocol->number = $number_proxy_id;
                                        }
                                        elseif($protocol_proxy_id == "Any"){
                                            $ipsec_tunnel_proxy_id->addChild("protocol");
                                            $ipsec_tunnel_proxy_id->protocol->addChild("any");;
                                        }
                                        elseif($protocol_proxy_id == "UDP"){
                                            $ipsec_tunnel_proxy_id->addChild("protocol");
                                            $ipsec_tunnel_proxy_id->protocol->addChild("udp");
                                            if($local_port_proxy_id == ""){
                                                $local_port_proxy_id = 0;
                                            }
                                            if($remote_port_proxy_id == ""){
                                                $remote_port_proxy_id = 0;
                                            }
                                            $ipsec_tunnel_proxy_id->protocol->udp->{'local-port'} = $local_port_proxy_id;
                                            $ipsec_tunnel_proxy_id->protocol->udp->{'remote-port'} = $remote_port_proxy_id;
                                        }

                                        if($local_proxy_id != ""){
                                            $ipsec_tunnel_proxy_id->addChild("local");
                                            $ipsec_tunnel_proxy_id->local = $local_proxy_id;
                                        }
                                        if($remote_proxy_id != ""){
                                            $ipsec_tunnel_proxy_id->addChild("remote");
                                            $ipsec_tunnel_proxy_id->remote = $remote_proxy_id;
                                        }
                                    }
                                }

                                // Mirar si hay Proxy ID type = v6
                                $getProxyID = $projectdb->query("SELECT name, protocol, local_port, remote_port, number, local, remote, type FROM proxy_id_ipsec_tunnel WHERE ipsec_tunnel_id = '$ipsec_tun_id' AND name != '' AND type = 'v6' AND template = '$template' AND source = '$source';");
                                if ($getProxyID->num_rows > 0){

                                    $ipsec_tunnel->{'auto-key'}->addChild("proxy-id-v6");
                                    $ike_ipsec_tunnel_xpath_proxy_id_v6 = $ipsec_tunnel->{'auto-key'}->{'proxy-id-v6'};

                                    while($dataPI = $getProxyID->fetch_assoc()){

                                        $name_proxy_id = $dataPI['name'];
                                        $protocol_proxy_id = $dataPI['protocol'];
                                        $local_port_proxy_id = $dataPI['local_port'];
                                        $remote_port_proxy_id = $dataPI['remote_port'];
                                        $number_proxy_id = $dataPI['number'];
                                        $local_proxy_id = $dataPI['local'];
                                        $remote_proxy_id = $dataPI['remote'];
                                        $type_proxy_id = $dataPI['type'];

                                        $ipsec_tunnel_proxy_id_v6 = $ike_ipsec_tunnel_xpath_proxy_id_v6->addChild('entry');
                                        $ipsec_tunnel_proxy_id_v6->addAttribute('name', $name_proxy_id);

                                        if ($protocol_proxy_id == "TCP"){
                                            $ipsec_tunnel_proxy_id_v6->addChild("protocol");
                                            $ipsec_tunnel_proxy_id_v6->protocol->addChild("tcp");
                                            //$ipsec_tunnel->{'auto-key'}->{'proxy-id'}->protocol->addChild("tcp");
                                            if($local_port_proxy_id == ""){
                                                $local_port_proxy_id = 0;
                                            }
                                            if($remote_port_proxy_id == ""){
                                                $remote_port_proxy_id = 0;
                                            }
                                            $ipsec_tunnel_proxy_id_v6->protocol->tcp->{'local-port'} = $local_port_proxy_id;
                                            $ipsec_tunnel_proxy_id_v6->protocol->tcp->{'remote-port'} = $remote_port_proxy_id;
                                        }
                                        elseif($protocol_proxy_id == "Number"){
                                            $ipsec_tunnel_proxy_id_v6->addChild("protocol");
                                            $ipsec_tunnel_proxy_id_v6->protocol->addChild("number");
                                            $ipsec_tunnel_proxy_id_v6->protocol->number = $number_proxy_id;
                                        }
                                        elseif($protocol_proxy_id == "Any"){
                                            $ipsec_tunnel_proxy_id_v6->addChild("protocol");
                                            $ipsec_tunnel_proxy_id_v6->protocol->addChild("any");;
                                        }
                                        elseif($protocol_proxy_id == "UDP"){
                                            $ipsec_tunnel_proxy_id_v6->addChild("protocol");
                                            $ipsec_tunnel_proxy_id_v6->protocol->addChild("udp");
                                            if($local_port_proxy_id == ""){
                                                $local_port_proxy_id = 0;
                                            }
                                            if($remote_port_proxy_id == ""){
                                                $remote_port_proxy_id = 0;
                                            }
                                            $ipsec_tunnel_proxy_id_v6->protocol->udp->{'local-port'} = $local_port_proxy_id;
                                            $ipsec_tunnel_proxy_id_v6->protocol->udp->{'remote-port'} = $remote_port_proxy_id;
                                        }

                                        if($local_proxy_id != ""){
                                            $ipsec_tunnel_proxy_id_v6->addChild("local");
                                            $ipsec_tunnel_proxy_id_v6->local = $local_proxy_id;
                                        }
                                        if($remote_proxy_id != ""){
                                            $ipsec_tunnel_proxy_id_v6->addChild("remote");
                                            $ipsec_tunnel_proxy_id_v6->remote = $remote_proxy_id;
                                        }
                                    }
                                }

                                if($ipsec_tun_ipsec_crypto_profile != ""){
                                    $ipsec_tunnel->{'auto-key'}->addChild("ipsec-crypto-profile");
                                    $ipsec_tunnel->{'auto-key'}->{'ipsec-crypto-profile'} = $ipsec_tun_ipsec_crypto_profile;
                                }
                            } # Manual Key
                            elseif ($ipsec_tun_type_tunnel == "manual-key"){

                                $ipsec_tunnel->addChild("manual-key");

                                if($ipsec_tun_protocol == "ESP"){

                                    $ipsec_tunnel->{'manual-key'}->addChild("esp");

                                    if($ipsec_tun_authentication == "none"){
                                        $ipsec_tunnel->{'manual-key'}->esp->addChild("authentication");
                                        $ipsec_tunnel->{'manual-key'}->esp->authentication->addChild("none");
                                    }else{
                                        //authentication->md5->key
                                        $ipsec_tunnel->{'manual-key'}->esp->addChild("authentication");
                                        $ipsec_tunnel->{'manual-key'}->esp->authentication->addChild($ipsec_tun_authentication);
                                        $ipsec_tunnel->{'manual-key'}->esp->authentication->$ipsec_tun_authentication->key = $ipsec_tun_key_auth;
                                    }

                                    if($ipsec_tun_encryption != ""){
                                        $ipsec_tunnel->{'manual-key'}->esp->addChild("encryption");
                                        $ipsec_tunnel->{'manual-key'}->esp->encryption->algorithm = $ipsec_tun_encryption;

                                        if($ipsec_tun_key_encry != ""){
                                            $ipsec_tunnel->{'manual-key'}->esp->encryption->key = $ipsec_tun_key_encry;
                                        }
                                    }
                                }

                                if($ipsec_tun_protocol == "AH"){

                                    $ipsec_tunnel->{'manual-key'}->addChild("ah");

                                    if($ipsec_tun_authentication == "none"){
                                        $ipsec_tunnel->{'manual-key'}->ah->addChild("authentication");
                                        $ipsec_tunnel->{'manual-key'}->ah->authentication->addChild("none");
                                    }else{
                                        //authentication->md5->key
                                        $ipsec_tunnel->{'manual-key'}->ah->addChild("authentication");
                                        $ipsec_tunnel->{'manual-key'}->ah->authentication->addChild($ipsec_tun_authentication);
                                        $ipsec_tunnel->{'manual-key'}->ah->authentication->$ipsec_tun_authentication->key = $ipsec_tun_key_auth;
                                    }
                                }

                                if($ipsec_tun_interface != ""){
                                    $ipsec_tunnel->{'manual-key'}->addChild("local-address");
                                    if(($ipsec_tun_local_address_ip != "") && ($ipsec_tun_local_address_ip != "None")){
                                        $ipsec_tunnel->{'manual-key'}->{'local-address'}->ip = $ipsec_tun_local_address_ip;
                                    }
                                    $ipsec_tunnel->{'manual-key'}->{'local-address'}->interface = $ipsec_tun_interface;
                                }

                                if($ipsec_tun_peer_ip_address != ""){
                                    $ipsec_tunnel->{'manual-key'}->addChild("peer-address");
                                    $ipsec_tunnel->{'manual-key'}->{'peer-address'}->ip = $ipsec_tun_peer_ip_address;
                                }

                                if($ipsec_tun_local_spi != ""){
                                    $ipsec_tunnel->{'manual-key'}->{'local-spi'} = $ipsec_tun_local_spi;
                                }

                                if($ipsec_tun_remote_spi != ""){
                                    $ipsec_tunnel->{'manual-key'}->{'remote-spi'} = $ipsec_tun_remote_spi;
                                }

                            } # Global Protect Satellite
                            elseif ($ipsec_tun_type_tunnel == "global-protect-satellite"){

                                $ipsec_tunnel->addChild("global-protect-satellite");

                                if($ipsec_tun_publish_connected_routes == "yes"){
                                    $ipsec_tunnel->{'global-protect-satellite'}->addChild("publish-connected-routes");
                                    $ipsec_tunnel->{'global-protect-satellite'}->{'publish-connected-routes'}->enable = $ipsec_tun_publish_connected_routes;
                                }

                                if($ipsec_tun_interface != ""){
                                    $ipsec_tunnel->{'global-protect-satellite'}->addChild("local-address");
                                    if(($ipsec_tun_local_address_ip != "") && ($ipsec_tun_local_address_ip != "None")){
                                        $ipsec_tunnel->{'global-protect-satellite'}->{'local-address'}->ip = $ipsec_tun_local_address_ip;
                                    }
                                    $ipsec_tunnel->{'global-protect-satellite'}->{'local-address'}->interface = $ipsec_tun_interface;
                                }

                                if($ipsec_tun_portal_address != ""){
                                    $ipsec_tunnel->{'global-protect-satellite'}->{'portal-address'} = $ipsec_tun_portal_address;
                                }

                                if($ipsec_tun_publish_routes != ""){
                                    $ipsec_tunnel->{'global-protect-satellite'}->addChild("publish-routes");
                                    $ipsec_tun_publish_routes_array = explode(",", $ipsec_tun_publish_routes);
                                    foreach($ipsec_tun_publish_routes_array as $member_publish){
                                        $ipsec_tunnel->{'global-protect-satellite'}->{'publish-routes'}->addChild("member", $member_publish);
                                    }
                                }

                                if($ipsec_tun_external_ca == "yes"){
                                    $ipsec_tunnel->{'global-protect-satellite'}->addChild("external-ca");
                                    if($ipsec_tun_certificate_profile != ""){
                                        $ipsec_tunnel->{'global-protect-satellite'}->{'external-ca'}->{'certificate-profile'} = $ipsec_tun_certificate_profile;
                                    }
                                    if($ipsec_tun_local_certificate != ""){
                                        $ipsec_tunnel->{'global-protect-satellite'}->{'external-ca'}->{'local-certificate'} = $ipsec_tun_local_certificate;
                                    }
                                }

                            }

                            if($ipsec_tun_tunnel_monitor != ""){
                                $ipsec_tunnel->addChild("tunnel-monitor");
                                $ipsec_tunnel->{'tunnel-monitor'}->enable = $ipsec_tun_tunnel_monitor;

                                if($ipsec_tun_destination_ip != ""){
                                    $ipsec_tunnel->{'tunnel-monitor'}->{'destination-ip'} = $ipsec_tun_destination_ip;
                                }

                                if($ipsec_tun_tunnel_monitor_profile != ""){
                                    $ipsec_tunnel->{'tunnel-monitor'}->{'tunnel-monitor-profile'} = $ipsec_tun_tunnel_monitor_profile;
                                }
                            }

                            if($ipsec_tun_copy_tos == "yes"){
                                $ipsec_tunnel->{'copy-tos'} = $ipsec_tun_copy_tos;
                            }

                            // Version 7
                            if($ipsec_tun_address_type == "ipv6"){
                                $ipsec_tunnel->ipv6 = "yes";
                            }

                            if($ipsec_tun_tunnel_interface != ""){
                                $ipsec_tunnel->{'tunnel-interface'} = $ipsec_tun_tunnel_interface;
                            }

                            if($ipsec_tun_anti_replay == "yes"){
                                $ipsec_tunnel->{'anti-replay'} = $ipsec_tun_anti_replay;
                            }
                        }
                    }
                    else{
                        $SA = $xml->xpath("/config/devices/entry/network/tunnel/ipsec");
                        unset($SA[0][0]);
                    }
                    
                    
                    #DHCP
                    $getDHCP = $projectdb->query("SELECT name,dhcp_type,xml FROM dhcp WHERE source='$source' AND template='$template';");
                    if ($getDHCP->num_rows > 0) {
                        if (!isset($xml->devices->entry[0]->network->dhcp->interface)) {
                            if (!isset($xml->devices->entry[0]->network->dhcp)) {
                                $xml->devices->entry[0]->network->addChild('dhcp');
                            }
                            $xml->devices->entry[0]->network->dhcp->addChild('interface');
                        } else {
                            # DELETE DHCP
                            $SA = $xml->xpath("/config/devices/entry/network/dhcp/interface");
                            unset($SA[0][0]);
                            $xml->devices->entry[0]->network->dhcp->addChild('interface');
                        }

                        while ($getDHCPData = $getDHCP->fetch_assoc()) {
                            $myname = $getDHCPData['name'];
                            $xmlfield = $getDHCPData['xml'];
                            $xml_append = simplexml_load_string($xmlfield);
                            if ($xml->devices->entry[0]->network->dhcp->interface->xpath("//entry[@name='$xmlname']") != null) {
                                add_log('warning', 'Exporting Schedules [' . $vsys . ']', 'Object Duplicated in Destination [' . $xmlname . ']', $source, 'Object was Not Migrated');
                            } else {
                                SimpleXMLElement_append($xml->devices->entry[0]->network->dhcp->interface, $xml_append);
                            }
                        }
                    } 
                    else {
                        #DELETE DHCP
                        $SA = $xml->xpath("/config/devices/entry/network/dhcp");
                        unset($SA[0][0]);
                    }

                    # DNS-PROXY
                    $getDHCP = $projectdb->query("SELECT name,xml FROM dns_proxy WHERE source='$source' AND template='$template';");
                    if ($getDHCP->num_rows > 0) {
                        if (!isset($xml->devices->entry[0]->network->{'dns-proxy'})) {
                            $xml->devices->entry[0]->network->addChild('dns-proxy');
                        } else {
                            #DELETE DNS-PROXY
                            $SA = $xml->xpath("/config/devices/entry/network/dns-proxy");
                            unset($SA[0][0]);
                            $xml->devices->entry[0]->network->addChild('dns-proxy');
                        }

                        while ($getDHCPData = $getDHCP->fetch_assoc()) {
                            $myname = $getDHCPData['name'];
                            $xmlfield = $getDHCPData['xml'];
                            $xml_append = simplexml_load_string($xmlfield);
                            if ($xml->devices->entry[0]->network->{'dns-proxy'}->xpath("//entry[@name='$xmlname']") != null) {
                                add_log('warning', 'Exporting Schedules [' . $vsys . ']', 'Object Duplicated in Destination [' . $xmlname . ']', $source, 'Object was Not Migrated');
                            } else {
                                SimpleXMLElement_append($xml->devices->entry[0]->network->{'dns-proxy'}, $xml_append);
                            }
                        }
                    } 
                    else {
                        #DELETE DNS-PROXY
                        $SA = $xml->xpath("/config/devices/entry/network/dns-proxy");
                        unset($SA[0][0]);
                    }

                    # management Profiles
                    $getMP = $projectdb->query("SELECT name,permitted_ip,http,https,http_ocsp,ssh,snmp,userid_service,userid_syslog_listener_ssl,userid_syslog_listener_udp,ping,response_pages,telnet FROM interface_management_profile WHERE source='$source' AND template='$template' AND name != '';");
                    if ($getMP->num_rows > 0) {
                        if (!isset($xml->devices->entry[0]->network->profiles->{'interface-management-profile'})) {
                            if (!isset($xml->devices->entry[0]->network->profiles)) {
                                $xml->devices->entry[0]->network->addChild('profiles');
                            }
                            $xml->devices->entry[0]->network->profiles->addChild('interface-management-profile');
                        } else {
                            #DELETE Interface-Managment-Profiles
                            $SA = $xml->xpath("/config/devices/entry/network/profiles/interface-management-profile");
                            unset($SA[0][0]);
                            $xml->devices->entry[0]->network->profiles->addChild('interface-management-profile');
                        }

                        while ($getMPData = $getMP->fetch_assoc()) {
                            $myname = $getMPData['name'];
                            $mgmprofile = $xml->devices->entry[0]->network->profiles->{'interface-management-profile'}->addChild('entry');
                            $mgmprofile->addAttribute('name', $myname);

                            if ($getMPData['http'] != "") {
                                $mgmprofile->addChild("http", $getMPData['http']);
                            }
                            if ($getMPData['https'] != "") {
                                $mgmprofile->addChild("https", $getMPData['https']);
                            }
                            if ($getMPData['http_ocsp'] != "") {
                                $mgmprofile->addChild("http-ocsp", $getMPData['http_ocsp']);
                            }
                            if ($getMPData['ssh'] != "") {
                                $mgmprofile->addChild("ssh", $getMPData['ssh']);
                            }
                            if ($getMPData['snmp'] != "") {
                                $mgmprofile->addChild("snmp", $getMPData['snmp']);
                            }
                            if ($getMPData['userid_service'] != "") {
                                $mgmprofile->addChild("userid-service", $getMPData['userid_service']);
                            }
                            if ($getMPData['ping'] != "") {
                                $mgmprofile->addChild("ping", $getMPData['ping']);
                            }
                            if ($getMPData['telnet'] != "") {
                                $mgmprofile->addChild("telnet", $getMPData['telnet']);
                            }
                            if ($getMPData['response_pages'] != "") {
                                $mgmprofile->addChild("response-pages", $getMPData['response_pages']);
                            }
                            if ($version > 5) {
                                if ($getMPData['userid_syslog_listener_ssl'] != "") {
                                    $mgmprofile->addChild("userid-syslog-listener-ssl", $getMPData['userid_syslog_listener_ssl']);
                                }
                                if ($getMPData['userid_syslog_listener_udp'] != "") {
                                    $mgmprofile->addChild("userid-syslog-listener-udp", $getMPData['userid_syslog_listener_udp']);
                                }
                            }
                            if ($getMPData['permitted_ip'] != "") {
                                $interfaces_all = explode(",", $getMPData['permitted_ip']);
                                $mgmprofile->addChild("permitted-ip");
                                foreach ($interfaces_all as $key => $int_value) {
                                    $newInt = $mgmprofile->{'permitted-ip'}->addChild("entry");
                                    $newInt->addAttribute('name', $int_value);
                                }
                            }
                        }
                    } 
                    else {
                        #DELETE Interface-Managment-Profiles
                        $SA = $xml->xpath("/config/devices/entry/network/profiles/interface-management-profile");
                        unset($SA[0][0]);
                    }

                    #Interfaces
                    $getInterfaces = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' LIMIT 1;");
                    if ($getInterfaces->num_rows > 0) {
                        $xml0 = $xml->xpath("//devices/entry[@name='localhost.localdomain']/network/interface");
                        if (empty($xml0)) {
                            $VRPath = $xml->xpath("//devices/entry[@name='localhost.localdomain']/network");
                            $VRPath[0]->addChild('interface');
                            $theINT = $VRPath[0]->{'interface'};
                        } else {
                            unset($xml0[0][0]);
                            $VRPath = $xml->xpath("//devices/entry[@name='localhost.localdomain']/network");
                            $VRPath[0]->addChild('interface');
                            $theINT = $VRPath[0]->{'interface'};
                        }
                        #Aggregate-Ethernet
                        $getIntEthernet = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='aggregate-ethernet' AND unittag='0' AND name=unitname GROUP BY name ORDER BY name");
                        if ($getIntEthernet->num_rows > 0) {
                            $theINT->addChild("aggregate-ethernet");
                            while ($getIntEthernetData = $getIntEthernet->fetch_assoc()) {
                                $myname = $getIntEthernetData['name'];
                                $int2 = $theINT->{'aggregate-ethernet'}->addChild('entry');
                                $int2->addAttribute('name', $myname);

                                if ($getIntEthernetData['comment'] != "") {
                                    $int2->addChild("comment");
                                    $int2->comment = $getIntEthernetData['comment'];
                                }
                                
                                if ($getIntEthernetData['type'] == "virtual-wire") {
                                    $int2->addChild("virtual-wire");
                                    if ($getIntEthernetData['netflow_profile'] != "") {
                                        $int2->{'virtual-wire'}->addChild("netflow-profile", $getIntEthernetData['netflow_profile']);
                                    }
                                    $getUnits = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='aggregate-ethernet' AND unitname!='$myname' AND name='$myname';");
                                    if ($getUnits->num_rows > 0) {
                                        $int2->{'virtual-wire'}->addChild("units");
                                        while ($getUnitsData = $getUnits->fetch_assoc()) {
                                            $myname1 = $getUnitsData['unitname'];
                                            $VWUnit = $int2->{'virtual-wire'}->units->addChild('entry');
                                            $VWUnit->addAttribute('name', $myname1);
                                            if ($getUnitsData['comment'] != "") {
                                                $VWUnit->addChild("comment");
                                                $VWUnit->comment = $getUnitsData['comment'];
                                            }
                                            if ($getUnitsData['netflow_profile'] != "") {
                                                $VWUnit->addChild("netflow-profile", $getUnitsData['netflow_profile']);
                                            }

                                            $VWUnit->addChild("tag", $getUnitsData['unittag']);

                                            if ($getUnitsData['ip_classifier'] != "") {
                                                $interfaces_all = explode(",", $getUnitsData['ip_classifier']);
                                                $VWUnit->addChild("ip-classifier");
                                                foreach ($interfaces_all as $key => $int_value) {
                                                    $VWUnit->{'ip-classifier'}->addChild("member", $int_value);
                                                }
                                            }
                                        }
                                    }
                                }
                                if ($getIntEthernetData['type'] == "layer2") {
                                    $int2->addChild("layer2");
                                    if ($getIntEthernetData['netflow_profile'] != "") {
                                        $int2->layer2->addChild("netflow-profile", $getIntEthernetData['netflow_profile']);
                                    }
                                    if ($version>=7){
                                        if ($getIntEthernetData['lldp'] != "") {
                                            $xml_append = simplexml_load_string($getIntEthernetData['lldp']);
                                            SimpleXMLElement_append($int2->layer2, $xml_append);
                                        }
                                    }
                                    $getUnits = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='aggregate-ethernet' AND unitname!='$myname' AND name='$myname';");
                                    if ($getUnits->num_rows > 0) {
                                        $int2->{'layer2'}->addChild("units");
                                        while ($getUnitsData = $getUnits->fetch_assoc()) {
                                            $myname1 = $getUnitsData['unitname'];
                                            $VWUnit = $int2->{'layer2'}->units->addChild('entry');
                                            $VWUnit->addAttribute('name', $myname1);
                                            if ($getUnitsData['netflow_profile'] != "") {
                                                $VWUnit->addChild("netflow-profile", $getUnitsData['netflow_profile']);
                                            }
                                            if ($getUnitsData['comment'] != "") {
                                                $VWUnit->addChild("comment");
                                                $VWUnit->comment = $getUnitsData['comment'];
                                            }
                                            $VWUnit->addChild("tag", $getUnitsData['unittag']);
                                        }
                                    }
                                } 
                                elseif ($getIntEthernetData['type'] == "ha") {
                                    $int2->addChild("ha");
                                } 
                                elseif ($getIntEthernetData['type'] == "layer3") {
                                    $int2->addChild("layer3");
                                    if ($getIntEthernetData['netflow_profile'] != "") {
                                        $int2->layer3->addChild("netflow-profile", $getIntEthernetData['netflow_profile']);
                                    }
                                    if (($getIntEthernetData['mtu'] != "") AND ( $getIntEthernetData['mtu'] != "0")) {
                                        $int2->layer3->addChild("mtu", $getIntEthernetData['mtu']);
                                    }
                                    if (($getIntEthernetData['interface_management_profile'] != "") AND ( $getIntEthernetData['interface_management_profile'] != "None")) {
                                        $int2->layer3->addChild("interface-management-profile", $getIntEthernetData['interface_management_profile']);
                                    }

                                    if ($getIntEthernetData['untagged_sub_interface'] != "") {
                                        $int2->layer3->addChild("untagged-sub-interface", $getIntEthernetData['untagged_sub_interface']);
                                    }
                                    if ($getIntEthernetData['arp'] != "") {
                                        $xml_append = simplexml_load_string($getIntEthernetData['arp']);
                                        SimpleXMLElement_append($int2->layer3, $xml_append);
                                    }
                                    if ($version>=7){
                                        if ($getIntEthernetData['lldp'] != "") {
                                            $xml_append = simplexml_load_string($getIntEthernetData['lldp']);
                                            SimpleXMLElement_append($int2->layer3, $xml_append);
                                        }
                                        if ($getIntEthernetData['ndpproxy'] != "") {
                                            $xml_append = simplexml_load_string($getIntEthernetData['ndpproxy']);
                                            SimpleXMLElement_append($int2->layer3, $xml_append);
                                        }
                                    }    
                                    if ($getIntEthernetData['ipv4_type'] == "static") {
                                        if ($getIntEthernetData['ipv6'] != "") {
                                            $xml_append = simplexml_load_string($getIntEthernetData['ipv6']);
                                            SimpleXMLElement_append($int2->layer3, $xml_append);
                                        }
                                        if ($getIntEthernetData['unitipaddress'] != "") {
                                            $interfaces_all = explode(",", $getIntEthernetData['unitipaddress']);
                                            $int2->layer3->addChild("ip");
                                            foreach ($interfaces_all as $key => $int_value) {
                                                $newInt = $int2->layer3->ip->addChild("entry");
                                                $newInt->addAttribute('name', $int_value);
                                            }
                                        }
                                        if ($getIntEthernetData['adjust_tcp_mss'] != "") {
                                            $int2->layer3->addChild("adjust-tcp-mss", $getIntEthernetData['adjust_tcp_mss']);
                                        }
                                    } elseif ($getIntEthernetData['ipv4_type'] == "dhcp-client") {
                                        $int2->layer3->addChild("dhcp-client");
                                        if ($getIntEthernetData['ipv6'] != "") {
                                            $xml_append = simplexml_load_string($getIntEthernetData['ipv6']);
                                            SimpleXMLElement_append($int2->layer3, $xml_append);
                                        }
                                        if ($getIntEthernetData['dhcp_client_enable'] == "no") {
                                            $int2->layer3->{"dhcp-client"}->addChild("enable", "no");
                                        }
                                        if ($getIntEthernetData['dhcp_client_default_route_metric'] != "0") {
                                            $int2->layer3->{"dhcp-client"}->addChild("default-route-metric", $getIntEthernetData['dhcp_client_default_route_metric']);
                                        }
                                        if ($getIntEthernetData['dhcp_client_create_default_route'] == "no") {
                                            $int2->layer3->{"dhcp-client"}->addChild("create-default-route", "no");
                                        }
                                        if ($getIntEthernetData['adjust_tcp_mss'] != "") {
                                            $int2->layer3->addChild("adjust-tcp-mss", $getIntEthernetData['adjust_tcp_mss']);
                                        }
                                    }
                                    # UNITS
                                    $getUnits = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='aggregate-ethernet' AND unitname!='$myname' AND name='$myname';");
                                    if ($getUnits->num_rows > 0) {
                                        $unit = $int2->layer3->addChild("units");
                                        while ($getUnitsData = $getUnits->fetch_assoc()) {
                                            $myname1 = $getUnitsData['unitname'];
                                            $UnitInt = $unit->addChild('entry');
                                            $UnitInt->addAttribute('name', $myname1);
                                            if ($getUnitsData['netflow_profile'] != "") {
                                                $UnitInt->addChild("netflow-profile", $getUnitsData['netflow_profile']);
                                            }
                                            if ($getUnitsData['unittag']!=0){
                                                $UnitInt->addChild("tag", $getUnitsData['unittag']);
                                            }
                                            if ($getUnitsData['comment'] != "") {
                                                $UnitInt->addChild("comment");
                                                $UnitInt->comment = $getUnitsData['comment'];
                                            }
                                            if ($getUnitsData['ipv6'] != "") {
                                                $xml_append = simplexml_load_string($getUnitsData['ipv6']);
                                                SimpleXMLElement_append($UnitInt, $xml_append);
                                            }
                                            if ($version>=7){
                                                if ($getUnitsData['ndpproxy'] != "") {
                                                    $xml_append = simplexml_load_string($getUnitsData['ndpproxy']);
                                                    SimpleXMLElement_append($UnitInt, $xml_append);
                                                }
                                            }    
                                            if (($getUnitsData['mtu'] != "") AND ( $getUnitsData['mtu'] != "0")) {
                                                $UnitInt->addChild("mtu", $getUnitsData['mtu']);
                                            }
                                            if (($getUnitsData['interface_management_profile'] != "") AND ( $getUnitsData['interface_management_profile'] != "None")) {
                                                $UnitInt->addChild("interface-management-profile", $getUnitsData['interface_management_profile']);
                                            }
                                            if ($getUnitsData['adjust_tcp_mss'] != "") {
                                                $UnitInt->addChild("adjust-tcp-mss", $getUnitsData['adjust_tcp_mss']);
                                            }
                                            if ($getUnitsData['arp'] != "") {
                                                $xml_append = simplexml_load_string($getUnitsData['arp']);
                                                SimpleXMLElement_append($UnitInt, $xml_append);
                                            }
                                            if ($getUnitsData['ipv4_type'] == "static") {
                                                if ($getUnitsData['unitipaddress'] != "") {
                                                    $interfaces_all = explode(",", $getUnitsData['unitipaddress']);
                                                    $UnitInt->addChild("ip");
                                                    foreach ($interfaces_all as $key => $int_value) {
                                                        $newInt = $UnitInt->ip->addChild("entry");
                                                        $newInt->addAttribute('name', $int_value);
                                                    }
                                                }
                                            } elseif ($getUnitsData['ipv4_type'] == "dhcp-client") {
                                                $UnitInt->addChild("dhcp-client");

                                                if ($getUnitsData['dhcp_client_enable'] == "no") {
                                                    $UnitInt->{"dhcp-client"}->addChild("enable", "no");
                                                }
                                                if ($getUnitsData['dhcp_client_default_route_metric'] != "0") {
                                                    $UnitInt->{"dhcp-client"}->addChild("default-route-metric", $getUnitsData['dhcp_client_default_route_metric']);
                                                }
                                                if ($getUnitsData['dhcp_client_create_default_route'] == "no") {
                                                    $UnitInt->{"dhcp-client"}->addChild("create-default-route", "no");
                                                }
                                            }
                                        }
                                    }
                                }
                                
                                if ($getIntEthernetData['lacp'] != "") {
                                    $xml_append = simplexml_load_string($getIntEthernetData['lacp']);
                                    SimpleXMLElement_append($int2->$getIntEthernetData['type'], $xml_append);
                                }
                            }
                        }
                        #Ethernet
                        $getIntEthernet = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='ethernet' AND unittag='0' AND unitname=name GROUP BY name ORDER BY name");
                        if ($getIntEthernet->num_rows > 0) {
                            $theINT->addChild("ethernet");
                            while ($getIntEthernetData = $getIntEthernet->fetch_assoc()) {
                                $myname = $getIntEthernetData['name'];
                                $int = $theINT->ethernet->addChild('entry');
                                $int->addAttribute('name', $myname);

                                if ($version>=7){
                                    if ($getIntEthernetData['link_speed'] != "")  {
                                        $int->addChild("link-speed", $getIntEthernetData['link_speed']);
                                    }
                                    if ($getIntEthernetData['link_duplex'] != "") {
                                        $int->addChild("link-duplex", $getIntEthernetData['link_duplex']);
                                    }
                                    if ($getIntEthernetData['link_state'] != "")  {
                                        $int->addChild("link-state", $getIntEthernetData['link_state']);
                                    }
                                }   
                                else{
                                    if (($getIntEthernetData['link_speed'] != "") AND ( $getIntEthernetData['link_speed'] != "auto")) {
                                        $int->addChild("link-speed", $getIntEthernetData['link_speed']);
                                    }
                                    if (($getIntEthernetData['link_duplex'] != "") AND ( $getIntEthernetData['link_duplex'] != "auto")) {
                                        $int->addChild("link-duplex", $getIntEthernetData['link_duplex']);
                                    }
                                    if (($getIntEthernetData['link_state'] != "") AND ( $getIntEthernetData['link_state'] != "auto")) {
                                        $int->addChild("link-state", $getIntEthernetData['link_state']);
                                    }
                                }

                                if ($getIntEthernetData['comment'] != "") {
                                    $int->addChild("comment");
                                    $int->comment = $getIntEthernetData['comment'];
                                }
                                if ($getIntEthernetData['type'] == "tap") {
                                    $int->addChild("tap");
                                    if ($getIntEthernetData['netflow_profile'] != "") {
                                        $int->tap->addChild("netflow-profile", $getIntEthernetData['netflow_profile']);
                                    }
                                }
                                if ($getIntEthernetData['type'] == "log-card") {
                                    $xml_append = simplexml_load_string($getIntEthernetData['log_card']);
                                    SimpleXMLElement_append($int, $xml_append);
                                }
                                if ($getIntEthernetData['type'] == "virtual-wire") {
                                    $int->addChild("virtual-wire");
                                    if ($getIntEthernetData['netflow_profile'] != "") {
                                        $int->{'virtual-wire'}->addChild("netflow-profile", $getIntEthernetData['netflow_profile']);
                                    }
                                    $getUnits = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='ethernet' AND unitname!='$myname' AND name='$myname';");
                                    if ($getUnits->num_rows > 0) {
                                        $int->{'virtual-wire'}->addChild("units");
                                        while ($getUnitsData = $getUnits->fetch_assoc()) {
                                            $myname1 = $getUnitsData['unitname'];
                                            $VWUnit = $int->{'virtual-wire'}->units->addChild('entry');
                                            $VWUnit->addAttribute('name', $myname1);
                                            if ($getUnitsData['comment'] != "") {
                                                $VWUnit->addChild("comment");
                                                $VWUnit->comment = $getUnitsData['comment'];
                                            }
                                            if ($getUnitsData['netflow_profile'] != "") {
                                                $VWUnit->addChild("netflow-profile", $getUnitsData['netflow_profile']);
                                            }

                                            $VWUnit->addChild("tag", $getUnitsData['unittag']);

                                            if ($getUnitsData['ip_classifier'] != "") {
                                                $interfaces_all = explode(",", $getUnitsData['ip_classifier']);
                                                $VWUnit->addChild("ip-classifier");
                                                foreach ($interfaces_all as $key => $int_value) {
                                                    $VWUnit->{'ip-classifier'}->addChild("member", $int_value);
                                                }
                                            }
                                        }
                                    }
                                }
                                if ($getIntEthernetData['type'] == "layer2") {
                                    $int->addChild("layer2");
                                    if ($getIntEthernetData['netflow_profile'] != "") {
                                        $int->layer2->addChild("netflow-profile", $getIntEthernetData['netflow_profile']);
                                    }
                                    if ($version>=7){
                                        if ($getIntEthernetData['lldp'] != "") {
                                            $xml_append = simplexml_load_string($getIntEthernetData['lldp']);
                                            SimpleXMLElement_append($int->layer2, $xml_append);
                                        }
                                    }
                                    $getUnits = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='ethernet' AND unitname!='$myname' AND name='$myname';");
                                    if ($getUnits->num_rows > 0) {
                                        $int->{'layer2'}->addChild("units");
                                        while ($getUnitsData = $getUnits->fetch_assoc()) {
                                            $myname1 = $getUnitsData['unitname'];
                                            $VWUnit = $int->{'layer2'}->units->addChild('entry');
                                            $VWUnit->addAttribute('name', $myname1);
                                            if ($getUnitsData['netflow_profile'] != "") {
                                                $VWUnit->addChild("netflow-profile", $getUnitsData['netflow_profile']);
                                            }
                                            if ($getUnitsData['comment'] != "") {
                                                $VWUnit->addChild("comment");
                                                $VWUnit->comment = $getUnitsData['comment'];
                                            }
                                            $VWUnit->addChild("tag", $getUnitsData['unittag']);
                                        }
                                    }
                                } 
                                elseif ($getIntEthernetData['type'] == "ha") {
                                    $int->addChild("ha");
                                } 
                                elseif ($getIntEthernetData['type'] == "layer3") {
                                    $int->addChild("layer3");
                                    if ($getIntEthernetData['netflow_profile'] != "") {
                                        $int->layer3->addChild("netflow-profile", $getIntEthernetData['netflow_profile']);
                                    }
                                    if (($getIntEthernetData['mtu'] != "") AND ( $getIntEthernetData['mtu'] != "0")) {
                                        $int->layer3->addChild("mtu", $getIntEthernetData['mtu']);
                                    }
                                    if (($getIntEthernetData['interface_management_profile'] != "") AND ( $getIntEthernetData['interface_management_profile'] != "None")) {
                                        $int->layer3->addChild("interface-management-profile", $getIntEthernetData['interface_management_profile']);
                                    }

                                    if ($getIntEthernetData['untagged_sub_interface'] != "") {
                                        $int->layer3->addChild("untagged-sub-interface", $getIntEthernetData['untagged_sub_interface']);
                                    }
                                    if ($getIntEthernetData['arp'] != "") {
                                        $xml_append = simplexml_load_string($getIntEthernetData['arp']);
                                        SimpleXMLElement_append($int->layer3, $xml_append);
                                    }
                                    if ($version>=7){
                                        if ($getIntEthernetData['ndpproxy'] != "") {
                                            $xml_append = simplexml_load_string($getIntEthernetData['ndpproxy']);
                                            SimpleXMLElement_append($int->layer3, $xml_append);
                                        }
                                        if ($getIntEthernetData['lldp'] != "") {
                                            $xml_append = simplexml_load_string($getIntEthernetData['lldp']);
                                            SimpleXMLElement_append($int->layer3, $xml_append);
                                        }
                                    }
                                    if ($getIntEthernetData['ipv4_type'] == "static") {
                                        if ($getIntEthernetData['ipv6'] != "") {
                                            $xml_append = simplexml_load_string($getIntEthernetData['ipv6']);
                                            SimpleXMLElement_append($int->layer3, $xml_append);
                                        }
                                        if ($getIntEthernetData['unitipaddress'] != "") {
                                            $interfaces_all = explode(",", $getIntEthernetData['unitipaddress']);
                                            $int->layer3->addChild("ip");
                                            foreach ($interfaces_all as $key => $int_value) {
                                                $newInt = $int->layer3->ip->addChild("entry");
                                                $newInt->addAttribute('name', $int_value);
                                            }
                                        }
                                        if ($getIntEthernetData['adjust_tcp_mss'] != "") {
                                            $int->layer3->addChild("adjust-tcp-mss", $getIntEthernetData['adjust_tcp_mss']);
                                        }
                                    } elseif ($getIntEthernetData['ipv4_type'] == "dhcp-client") {
                                        $int->layer3->addChild("dhcp-client");
                                        if ($getIntEthernetData['ipv6'] != "") {
                                            $xml_append = simplexml_load_string($getIntEthernetData['ipv6']);
                                            SimpleXMLElement_append($int->layer3, $xml_append);
                                        }
                                        if ($getIntEthernetData['dhcp_client_enable'] == "no") {
                                            $int->layer3->{"dhcp-client"}->addChild("enable", "no");
                                        }
                                        if ($getIntEthernetData['dhcp_client_default_route_metric'] != "0") {
                                            $int->layer3->{"dhcp-client"}->addChild("default-route-metric", $getIntEthernetData['dhcp_client_default_route_metric']);
                                        }
                                        if ($getIntEthernetData['dhcp_client_create_default_route'] == "no") {
                                            $int->layer3->{"dhcp-client"}->addChild("create-default-route", "no");
                                        }
                                        if ($getIntEthernetData['adjust_tcp_mss'] != "") {
                                            $int->layer3->addChild("adjust-tcp-mss", $getIntEthernetData['adjust_tcp_mss']);
                                        }
                                    }
                                    # UNITS
                                    $getUnits = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='ethernet' AND unitname!='$myname' AND name='$myname';");
                                    if ($getUnits->num_rows > 0) {
                                        $unit = $int->layer3->addChild("units");
                                        while ($getUnitsData = $getUnits->fetch_assoc()) {
                                            $myname1 = $getUnitsData['unitname'];
                                            $UnitInt = $unit->addChild('entry');
                                            $UnitInt->addAttribute('name', $myname1);
                                            if ($getUnitsData['netflow_profile'] != "") {
                                                $UnitInt->addChild("netflow-profile", $getUnitsData['netflow_profile']);
                                            }
                                            if ($getUnitsData['unittag']!=0){
                                                $UnitInt->addChild("tag", $getUnitsData['unittag']);
                                            }
                                            if ($getUnitsData['comment'] != "") {
                                                $UnitInt->addChild("comment");
                                                $UnitInt->comment = $getUnitsData['comment'];
                                            }
                                            if ($getUnitsData['ipv6'] != "") {
                                                $xml_append = simplexml_load_string($getUnitsData['ipv6']);
                                                SimpleXMLElement_append($UnitInt, $xml_append);
                                            }
                                            if ($version>=7){
                                                if ($getUnitsData['ndpproxy'] != "") {
                                                    $xml_append = simplexml_load_string($getUnitsData['ndpproxy']);
                                                    SimpleXMLElement_append($UnitInt, $xml_append);
                                                }
                                            }    
                                            if (($getUnitsData['mtu'] != "") AND ( $getUnitsData['mtu'] != "0")) {
                                                $UnitInt->addChild("mtu", $getUnitsData['mtu']);
                                            }
                                            if (($getUnitsData['interface_management_profile'] != "") AND ( $getUnitsData['interface_management_profile'] != "None")) {
                                                $UnitInt->addChild("interface-management-profile", $getUnitsData['interface_management_profile']);
                                            }
                                            if ($getUnitsData['adjust_tcp_mss'] != "") {
                                                $UnitInt->addChild("adjust-tcp-mss", $getUnitsData['adjust_tcp_mss']);
                                            }
                                            if ($getUnitsData['arp'] != "") {
                                                $xml_append = simplexml_load_string($getUnitsData['arp']);
                                                SimpleXMLElement_append($UnitInt, $xml_append);
                                            }
                                            if ($getUnitsData['ipv4_type'] == "static") {
                                                if ($getUnitsData['unitipaddress'] != "") {
                                                    $interfaces_all = explode(",", $getUnitsData['unitipaddress']);
                                                    $UnitInt->addChild("ip");
                                                    foreach ($interfaces_all as $key => $int_value) {
                                                        $newInt = $UnitInt->ip->addChild("entry");
                                                        $newInt->addAttribute('name', $int_value);
                                                    }
                                                }
                                            } elseif ($getUnitsData['ipv4_type'] == "dhcp-client") {
                                                $UnitInt->addChild("dhcp-client");

                                                if ($getUnitsData['dhcp_client_enable'] == "no") {
                                                    $UnitInt->{"dhcp-client"}->addChild("enable", "no");
                                                }
                                                if ($getUnitsData['dhcp_client_default_route_metric'] != "0") {
                                                    $UnitInt->{"dhcp-client"}->addChild("default-route-metric", $getUnitsData['dhcp_client_default_route_metric']);
                                                }
                                                if ($getUnitsData['dhcp_client_create_default_route'] == "no") {
                                                    $UnitInt->{"dhcp-client"}->addChild("create-default-route", "no");
                                                }
                                            }
                                        }
                                    }
                                }
                                elseif ($getIntEthernetData['type'] == "decrypt-mirror"){
                                    $int->addChild("decrypt-mirror");
                                }
                                if ($getIntEthernetData['type'] == "aggregate-group"){
                                    $int->addChild("aggregate-group",$getIntEthernetData['aggregate_group']);
                                }
                            }
                        }
                        # Vlan
                        $getIntEthernet = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='vlan' AND name='vlan' GROUP BY name ORDER BY name");
                        if ($getIntEthernet->num_rows > 0) {
                            $vlanint = $theINT->addChild("vlan");
                            while ($getIntEthernetData = $getIntEthernet->fetch_assoc()) {
                                if ($getIntEthernetData['ipv6'] != "") {
                                    $xml_append = simplexml_load_string($getIntEthernetData['ipv6']);
                                    SimpleXMLElement_append($vlanint, $xml_append);
                                }
                                if (($getIntEthernetData['mtu'] != "") AND ( $getIntEthernetData['mtu'] != "0")) {
                                    $vlanint->addChild("mtu", $getIntEthernetData['mtu']);
                                }
                                if ($getIntEthernetData['adjust_tcp_mss'] != "") {
                                    $vlanint->addChild("adjust-tcp-mss", $getIntEthernetData['adjust_tcp_mss']);
                                }
                                if (($getIntEthernetData['interface_management_profile'] != "") AND ( $getIntEthernetData['interface_management_profile'] != "None")) {
                                    $vlanint->addChild("interface-management-profile", $getIntEthernetData['interface_management_profile']);
                                }
                                if ($getIntEthernetData['comment'] != "") {
                                    $vlanint->addChild("comment");
                                    $vlanint->comment = $getIntEthernetData['comment'];
                                }
                                if ($getIntEthernetData['arp'] != "") {
                                    $xml_append = simplexml_load_string($getIntEthernetData['arp']);
                                    SimpleXMLElement_append($vlanint, $xml_append);
                                }
                                if ($version>=7){
                                    if ($getIntEthernetData['ndpproxy'] != "") {
                                        $xml_append = simplexml_load_string($getIntEthernetData['ndpproxy']);
                                        SimpleXMLElement_append($vlanint, $xml_append);
                                    }
                                }
                                if ($getIntEthernetData['ipv4_type'] == "static") {
                                    if ($getIntEthernetData['unitipaddress'] != "") {
                                        $interfaces_all = explode(",", $getIntEthernetData['unitipaddress']);
                                        $vlanint->addChild("ip");
                                        foreach ($interfaces_all as $key => $int_value) {
                                            $newInt = $vlanint->ip->addChild("entry");
                                            $newInt->addAttribute('name', $int_value);
                                        }
                                    }
                                } elseif ($getIntEthernetData['ipv4_type'] == "dhcp-client") {
                                    $vlanint->addChild("dhcp-client");
                                    if ($getIntEthernetData['dhcp_client_enable'] == "no") {
                                        $vlanint->{"dhcp-client"}->addChild("enable", "no");
                                    }
                                    if ($getIntEthernetData['dhcp_client_default_route_metric'] != "0") {
                                        $vlanint->{"dhcp-client"}->addChild("default-route-metric", $getIntEthernetData['dhcp_client_default_route_metric']);
                                    }
                                    if ($getIntEthernetData['dhcp_client_create_default_route'] == "no") {
                                        $vlanint->{"dhcp-client"}->addChild("create-default-route", "no");
                                    }
                                }
                                $getUnits = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='vlan' AND unitname!='vlan';");
                                if ($getUnits->num_rows > 0) {
                                    $vlanint->addChild("units");
                                    while ($getUnitsData = $getUnits->fetch_assoc()) {
                                        $myname1 = $getUnitsData['unitname'];
                                        $UnitInt = $vlanint->units->addChild('entry');
                                        $UnitInt->addAttribute('name', $myname1);
                                        if ($getUnitsData['ipv6'] != "") {
                                            $xml_append = simplexml_load_string($getUnitsData['ipv6']);
                                            SimpleXMLElement_append($UnitInt, $xml_append);
                                        }
                                        if (($getUnitsData['mtu'] != "") AND ( $getUnitsData['mtu'] != "0")) {
                                            $UnitInt->addChild("mtu", $getUnitsData['mtu']);
                                        }
                                        if ($getUnitsData['adjust_tcp_mss'] != "") {
                                            $UnitInt->addChild("adjust-tcp-mss", $getUnitsData['adjust_tcp_mss']);
                                        }
                                        if (($getUnitsData['interface_management_profile'] != "") AND ( $getUnitsData['interface_management_profile'] != "None")) {
                                            $UnitInt->addChild("interface-management-profile", $getUnitsData['interface_management_profile']);
                                        }
                                        if ($getUnitsData['arp'] != "") {
                                            $xml_append = simplexml_load_string($getUnitsData['arp']);
                                            SimpleXMLElement_append($UnitInt, $xml_append);
                                        }
                                        if ($getUnitsData['comment'] != "") {
                                            $UnitInt->addChild("comment");
                                            $UnitInt->comment = $getUnitsData['comment'];
                                        }
                                        if ($getUnitsData['ipv4_type'] == "static") {
                                            if ($getUnitsData['unitipaddress'] != "") {
                                                $interfaces_all = explode(",", $getUnitsData['unitipaddress']);
                                                $UnitInt->addChild("ip");
                                                foreach ($interfaces_all as $key => $int_value) {
                                                    $newInt = $UnitInt->ip->addChild("entry");
                                                    $newInt->addAttribute('name', $int_value);
                                                }
                                            }
                                        } elseif ($getUnitsData['ipv4_type'] == "dhcp-client") {
                                            $UnitInt->addChild("dhcp-client");
                                            if ($getUnitsData['dhcp_client_enable'] == "no") {
                                                $UnitInt->{"dhcp-client"}->addChild("enable", "no");
                                            }
                                            if ($getUnitsData['dhcp_client_default_route_metric'] != "0") {
                                                $UnitInt->{"dhcp-client"}->addChild("default-route-metric", $getUnitsData['dhcp_client_default_route_metric']);
                                            }
                                            if ($getUnitsData['dhcp_client_create_default_route'] == "no") {
                                                $UnitInt->{"dhcp-client"}->addChild("create-default-route", "no");
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        # Loopback
                        $getIntEthernet = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='loopback' AND name='loopback' GROUP BY name ORDER BY name");
                        if ($getIntEthernet->num_rows > 0) {
                            $loopackint = $theINT->addChild("loopback");
                            while ($getIntEthernetData = $getIntEthernet->fetch_assoc()) {
                                if ($getIntEthernetData['ipv6'] != "") {
                                    $xml_append = simplexml_load_string($getIntEthernetData['ipv6']);
                                    SimpleXMLElement_append($loopackint, $xml_append);
                                }
                                if (($getIntEthernetData['mtu'] != "") AND ( $getIntEthernetData['mtu'] != "0")) {
                                    $loopackint->addChild("mtu", $getIntEthernetData['mtu']);
                                }
                                if ($getIntEthernetData['adjust_tcp_mss'] != "") {
                                    $loopackint->addChild("adjust-tcp-mss", $getIntEthernetData['adjust_tcp_mss']);
                                }
                                if ($getIntEthernetData['comment'] != "") {
                                    $loopackint->addChild("comment");
                                    $loopackint->comment = $getIntEthernetData['comment'];
                                }
                                if (($getIntEthernetData['interface_management_profile'] != "") AND ( $getIntEthernetData['interface_management_profile'] != "None")) {
                                    $loopackint->addChild("interface-management-profile", $getIntEthernetData['interface_management_profile']);
                                }
                                if ($getIntEthernetData['ipv4_type'] == "static") {
                                    if ($getIntEthernetData['unitipaddress'] != "") {
                                        $interfaces_all = explode(",", $getIntEthernetData['unitipaddress']);
                                        $loopackint->addChild("ip");
                                        foreach ($interfaces_all as $key => $int_value) {
                                            $newInt = $loopackint->ip->addChild("entry");
                                            $newInt->addAttribute('name', $int_value);
                                        }
                                    }
                                }
                                $getUnits = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='loopback' AND unitname!='loopback';");
                                if ($getUnits->num_rows > 0) {
                                    $unit = $loopackint->addChild("units");
                                    while ($getUnitsData = $getUnits->fetch_assoc()) {
                                        $myname1 = $getUnitsData['unitname'];
                                        $UnitInt = $unit->addChild('entry');
                                        $UnitInt->addAttribute('name', $myname1);
                                        if ($getUnitsData['ipv6'] != "") {
                                            $xml_append = simplexml_load_string($getUnitsData['ipv6']);
                                            SimpleXMLElement_append($UnitInt, $xml_append);
                                        }
                                        if (($getUnitsData['mtu'] != "") AND ( $getUnitsData['mtu'] != "0")) {
                                            $UnitInt->addChild("mtu", $getUnitsData['mtu']);
                                        }
                                        if ($getUnitsData['adjust_tcp_mss'] != "") {
                                            $UnitInt->addChild("adjust-tcp-mss", $getUnitsData['adjust_tcp_mss']);
                                        }
                                        if (($getUnitsData['interface_management_profile'] != "") AND ( $getUnitsData['interface_management_profile'] != "None")) {
                                            $UnitInt->addChild("interface-management-profile", $getUnitsData['interface_management_profile']);
                                        }
                                        if ($getUnitsData['comment'] != "") {
                                            $UnitInt->addChild("comment");
                                            $UnitInt->comment = $getUnitsData['comment'];
                                        }
                                        if ($getUnitsData['ipv4_type'] == "static") {
                                            if ($getUnitsData['unitipaddress'] != "") {
                                                $interfaces_all = explode(",", $getUnitsData['unitipaddress']);
                                                $UnitInt->addChild("ip");
                                                foreach ($interfaces_all as $key => $int_value) {
                                                    $newInt = $UnitInt->ip->addChild("entry");
                                                    $newInt->addAttribute('name', $int_value);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        # Tunnel
                        $getIntEthernet = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='tunnel' AND name='tunnel' GROUP BY name ORDER BY name");
                        if ($getIntEthernet->num_rows > 0) {
                            $tunnelint = $theINT->addChild("tunnel");
                            while ($getIntEthernetData = $getIntEthernet->fetch_assoc()) {
                                if ($getIntEthernetData['ipv6'] != "") {
                                    $xml_append = simplexml_load_string($getIntEthernetData['ipv6']);
                                    SimpleXMLElement_append($tunnelint, $xml_append);
                                }
                                if (($getIntEthernetData['mtu'] != "") AND ( $getIntEthernetData['mtu'] != "0")) {
                                    $tunnelint->addChild("mtu", $getIntEthernetData['mtu']);
                                }
                                if ($getIntEthernetData['adjust_tcp_mss'] != "") {
                                    $tunnelint->addChild("adjust-tcp-mss", $getIntEthernetData['adjust_tcp_mss']);
                                }
                                if (($getIntEthernetData['interface_management_profile'] != "") AND ( $getIntEthernetData['interface_management_profile'] != "None")) {
                                    $tunnelint->addChild("interface-management-profile", $getIntEthernetData['interface_management_profile']);
                                }
                                if ($getIntEthernetData['comment'] != "") {
                                    $tunnelint->addChild("comment");
                                    $tunnelint->comment = $getIntEthernetData['comment'];
                                }
                                if ($getIntEthernetData['ipv4_type'] == "static") {
                                    if ($getIntEthernetData['unitipaddress'] != "") {
                                        $interfaces_all = explode(",", $getIntEthernetData['unitipaddress']);
                                        $tunnelint->addChild("ip");
                                        foreach ($interfaces_all as $key => $int_value) {
                                            $newInt = $tunnelint->ip->addChild("entry");
                                            $newInt->addAttribute('name', $int_value);
                                        }
                                    }
                                }
                                $getUnits = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='tunnel' AND unitname!='tunnel';");
                                if ($getUnits->num_rows > 0) {
                                    $unit = $tunnelint->addChild("units");
                                    while ($getUnitsData = $getUnits->fetch_assoc()) {
                                        $myname1 = $getUnitsData['unitname'];
                                        $UnitInt = $unit->addChild('entry');
                                        $UnitInt->addAttribute('name', $myname1);
                                        if ($getUnitsData['ipv6'] != "") {
                                            $xml_append = simplexml_load_string($getUnitsData['ipv6']);
                                            SimpleXMLElement_append($UnitInt, $xml_append);
                                        }
                                        if (($getUnitsData['mtu'] != "") AND ( $getUnitsData['mtu'] != "0")) {
                                            $UnitInt->addChild("mtu", $getUnitsData['mtu']);
                                        }
                                        if ($getUnitsData['adjust_tcp_mss'] != "") {
                                            $UnitInt->addChild("adjust-tcp-mss", $getUnitsData['adjust_tcp_mss']);
                                        }
                                        if (($getUnitsData['interface_management_profile'] != "") AND ( $getUnitsData['interface_management_profile'] != "None")) {
                                            $UnitInt->addChild("interface-management-profile", $getUnitsData['interface_management_profile']);
                                        }
                                        if ($getUnitsData['comment'] != "") {
                                            $UnitInt->addChild("comment");
                                            $UnitInt->comment = $getUnitsData['comment'];
                                        }
                                        if ($getUnitsData['ipv4_type'] == "static") {
                                            if ($getUnitsData['unitipaddress'] != "") {
                                                $interfaces_all = explode(",", $getUnitsData['unitipaddress']);
                                                $UnitInt->addChild("ip");
                                                foreach ($interfaces_all as $key => $int_value) {
                                                    $newInt = $UnitInt->ip->addChild("entry");
                                                    $newInt->addAttribute('name', $int_value);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    else{
                        $SA = $xml->xpath("/config/devices/entry/network/interface");
                        unset($SA[0][0]); 
                    }

                    #Virtual Wire
                    $getVW = $projectdb->query("SELECT id,name,multicast_firewalling,tag_allowed,link_state_pass_through,interface1,interface2 FROM virtual_wires WHERE source='$source' AND template='$template';");
                    if ($getVW->num_rows > 0) {
                        $xml0 = $xml->xpath("//devices/entry[@name='localhost.localdomain']/network/virtual-wire");
                        if (empty($xml0)) {
                            $VWPath = $xml->xpath("//devices/entry[@name='localhost.localdomain']/network");
                            $VWPath[0]->addChild('virtual-wire');
                            $theVW = $VWPath[0]->{'virtual-wire'};
                        } else {
                            unset($xml0[0][0]);
                            $VWPath = $xml->xpath("//devices/entry[@name='localhost.localdomain']/network");
                            $VWPath[0]->addChild('virtual-wire');
                            $theVW = $VWPath[0]->{'virtual-wire'};
                        }
                        while ($getVRData = $getVW->fetch_assoc()) {
                            $myname = $getVRData['name'];
                            $multicast_firewalling = $getVRData['multicast_firewalling'];
                            $tag_allowed = $getVRData['tag_allowed'];
                            $link_state_pass_through = $getVRData['link_state_pass_through'];
                            $interface1 = $getVRData['interface1'];
                            $interface2 = $getVRData['interface2'];

                            $vwire = $theVW->addChild('entry');
                            $vwire->addAttribute('name', $myname);
                            if ($link_state_pass_through != "") {
                                $vwire->addChild("link-state-pass-through");
                                $vwire->{'link-state-pass-through'}->addChild("enable", $link_state_pass_through);
                            }
                            if ($multicast_firewalling != "") {
                                $vwire->addChild("multicast-firewalling");
                                $vwire->{'multicast-firewalling'}->addChild("enable", $multicast_firewalling);
                            }
                            if ($tag_allowed != "") {
                                $vwire->addchild("tag-allowed", $tag_allowed);
                            }
                            if ($interface1 != "") {
                                $vwire->addChild("interface1", $interface1);
                            }
                            if ($interface2 != "") {
                                $vwire->addChild("interface2", $interface2);
                            }
                        }
                    }
                    else{
                        $SA = $xml->xpath("/config/devices/entry/network/virtual-wire");
                        unset($SA[0][0]); 
                    }

                    #VLANS
                    $getVW = $projectdb->query("SELECT id, name, interface, mac, virtual_interface, mac_interfaces, l3_forwarding FROM vlans WHERE source='$source' AND template='$template' AND name != '';");
                    if ($getVW->num_rows > 0) {
                        $xml0 = $xml->xpath("//devices/entry[@name='localhost.localdomain']/network/vlan");
                        if (empty($xml0)) {
                            $VWPath = $xml->xpath("//devices/entry[@name='localhost.localdomain']/network");
                            $VWPath[0]->addChild('vlan');
                            $theVW = $VWPath[0]->{'vlan'};
                        } else {
                            unset($xml0[0][0]);
                            $VWPath = $xml->xpath("//devices/entry[@name='localhost.localdomain']/network");
                            $VWPath[0]->addChild('vlan');
                            $theVW = $VWPath[0]->{'vlan'};
                        }
                        while ($getVRData = $getVW->fetch_assoc()) {
                            $myname = $getVRData['name'];
                            $interface = $getVRData['interface'];
                            $mac = $getVRData['mac'];
                            $mac_interfaces = $getVRData['mac_interfaces'];
                            $virtual_interface = $getVRData['virtual_interface'];
                            $l3_forwarding = $getVRData['l3_forwarding'];

                            $vwire = $theVW->addChild('entry');
                            $vwire->addAttribute('name', $myname);
                            if ($interface != "") {
                                $vwire->addChild("interface");
                                foreach (explode(",", $interface) as $key => $value) {
                                    $vwire->interface->addChild("member", $value);
                                }
                            }

                            if ($mac != "") {
                                //$xml_append = simplexml_load_string($mac);
                                //SimpleXMLElement_append($vwire, $xml_append);
                                $index_array = 0;
                                $interfaces_mac_array = explode(",", $mac_interfaces);

                                $vlan_pad = $vwire->addChild("mac");

                                foreach (explode(",", $mac) as $key => $value) {
                                    $vlan_mac = $vlan_pad->addChild('entry');
                                    $vlan_mac->addAttribute('name', $value);

                                    $vlan_mac->interface = $interfaces_mac_array[$index_array];
                                    $index_array ++;
                                }
                            }
                            
                            if($version > 5){
                                if ($virtual_interface != "") {
                                    $vwire->addChild("virtual-interface");
                                    $vwire->{'virtual-interface'}->addChild("interface", $virtual_interface);
                                }
                            }
                            else{
                                $vwire->addChild("virtual-interface");
                                $vwire->{'virtual-interface'}->addChild("l3-forwarding", $l3_forwarding);
                                if ($virtual_interface != "") {
                                    $vwire->{'virtual-interface'}->addChild("interface", $virtual_interface);
                                }
                            }
                            
                        }
                    }
                    else{
                        $SA = $xml->xpath("/config/devices/entry/network/vlan");
                        unset($SA[0][0]); 
                    }

                    #Virtual Router
                    $getVR = $projectdb->query("SELECT id,name,map_name,interfaces,admin_dist_static,admin_dist_ospf_int,admin_dist_ospf_ext,admin_dist_ibgp,admin_dist_ebgp,admin_dist_rip,protocol,multicast,admin_dist_static_ipv6,admin_dist_ospfv3_int,admin_dist_ospfv3_ext,ecmp FROM virtual_routers WHERE source='$source' AND template='$template';");
                    if ($getVR->num_rows > 0) {
                        $xml0 = $xml->xpath("//devices/entry[@name='localhost.localdomain']/network/virtual-router");
                        if (empty($xml0)) {
                            $VRPath = $xml->xpath("//devices/entry[@name='localhost.localdomain']/network");
                            $theVR = $VRPath[0]->addChild('virtual-router');
                            $theVR = $VRPath[0]->{'virtual-router'};
                        } else {
                            unset($xml0[0][0]);
                            $VRPath = $xml->xpath("//devices/entry[@name='localhost.localdomain']/network");
                            $theVR = $VRPath[0]->addChild('virtual-router');
                            $theVR = $VRPath[0]->{'virtual-router'};
                        }

                        while ($getVRData = $getVR->fetch_assoc()) {
                            $vr_id = $getVRData['id'];
                            $myname = $getVRData['name'];
                            $map_name = $getVRData['map_name'];
                            $interfaces = $getVRData['interfaces'];
                            $admin_dist_static = $getVRData['admin_dist_static'];
                            $admin_dist_ospf_int = $getVRData['admin_dist_ospf_int'];
                            $admin_dist_ospf_ext = $getVRData['admin_dist_ospf_ext'];
                            $admin_dist_ibgp = $getVRData['admin_dist_ibgp'];
                            $admin_dist_ebgp = $getVRData['admin_dist_ebgp'];
                            $admin_dist_rip = $getVRData['admin_dist_rip'];
                            $protocol = $getVRData['protocol'];
                            $multicast = $getVRData['multicast'];
                            $admin_dist_static_ipv6 = $getVRData['admin_dist_static_ipv6'];
                            $admin_dist_ospfv3_int = $getVRData['admin_dist_ospfv3_int'];
                            $admin_dist_ospfv3_ext = $getVRData['admin_dist_ospfv3_ext'];
                            $ecmp=$getVRData['ecmp'];


                            $vr = $theVR->addChild('entry');
                            $vr->addAttribute('name', $myname);

                            $vr->addChild("interface");
                            $interface = $vr->interface;
                            if ($interfaces != "") {
                                foreach (explode(",", $interfaces) as $key => $value) {
                                    $interface->addChild("member", $value);
                                }
                            }

                            if ($protocol != "") {
                                $xml_append = simplexml_load_string($protocol);
                                SimpleXMLElement_append($vr, $xml_append);
                            }
                            
                            if ($version>=7){
                                if ($ecmp != "") {
                                    $xml_append = simplexml_load_string($ecmp);
                                    SimpleXMLElement_append($vr, $xml_append);
                                }
                            }
                            
                            if ($multicast != "") {
                                $vr->addChild("multicast");
                                $multicastxml = $vr->multicast;
                                $xml_append = simplexml_load_string($multicast);
                                SimpleXMLElement_append($multicastxml, $xml_append);
                            }

                            #Metrics
                            $vr->addChild("admin-dists");
                            if (( $admin_dist_static == "") OR ( $admin_dist_static == "0")) {
                                
                            } else {
                                $vr->{'admin-dists'}->addChild("static", $admin_dist_static);
                            }

                            if (( $admin_dist_ospf_int == "") OR ( $admin_dist_ospf_int == "0")) {
                                
                            } else {
                                $vr->{'admin-dists'}->addChild("ospf-int", $admin_dist_ospf_int);
                            }

                            if (( $admin_dist_ospf_ext == "") OR ( $admin_dist_ospf_ext == "0")) {
                                
                            } else {
                                $vr->{'admin-dists'}->addChild("ospf-ext", $admin_dist_ospf_ext);
                            }

                            if (( $admin_dist_ibgp == "") OR ( $admin_dist_ibgp == "0")) {
                                
                            } else {
                                $vr->{'admin-dists'}->addChild("ibgp", $admin_dist_ibgp);
                            }

                            if (( $admin_dist_ebgp == "") OR ( $admin_dist_ebgp == "0")) {
                                
                            } else {
                                $vr->{'admin-dists'}->addChild("ebgp", $admin_dist_ebgp);
                            }

                            if (( $admin_dist_rip == "") OR ( $admin_dist_rip == "0")) {
                                
                            } else {
                                $vr->{'admin-dists'}->addChild("rip", $admin_dist_rip);
                            }

                            if ($version >= 6) {
                                if (( $admin_dist_static_ipv6 == "") OR ( $admin_dist_static_ipv6 == "0")) {
                                    
                                } else {
                                    $vr->{'admin-dists'}->addChild("static-ipv6", $admin_dist_static_ipv6);
                                }

                                if (( $admin_dist_ospfv3_int == "") OR ( $admin_dist_ospfv3_int == "0")) {
                                    
                                } else {
                                    $vr->{'admin-dists'}->addChild("ospfv3-int", $admin_dist_ospfv3_int);
                                }

                                if (( $admin_dist_ospfv3_ext == "") OR ( $admin_dist_ospfv3_ext == "0")) {
                                    
                                } else {
                                    $vr->{'admin-dists'}->addChild("ospfv3-ext", $admin_dist_ospfv3_ext);
                                }
                            }

                            # Static Routing
                            $exist = $projectdb->query("SELECT id FROM routes_static WHERE template='$template' AND source='$source' AND vr_id='$vr_id';");
                            if ($exist->num_rows > 0) {
                                $vr->addChild("routing-table");
                                # IPV4
                                $getStatic = $projectdb->query("SELECT name,destination,tointerface,nexthop,nexthop_value,metric,admin_dist,option_no_install,zone FROM routes_static WHERE vr_id='$vr_id' AND ip_version='v4' AND source='$source' AND template='$template';");
                                if ($getStatic->num_rows > 0) {
                                    $vr->{'routing-table'}->addChild("ip");
                                    $vr->{'routing-table'}->ip->addChild("static-route");
                                    $routes = $vr->{'routing-table'}->ip->{'static-route'};
                                    while ($getStaticData = $getStatic->fetch_assoc()) {
                                        $name = $getStaticData['name'];
                                        $destination = $getStaticData['destination'];
                                        $tointerface = $getStaticData['tointerface'];
                                        $nexthop = $getStaticData['nexthop'];
                                        $nexthop_value = $getStaticData['nexthop_value'];
                                        $metric = $getStaticData['metric'];
                                        $admin_dist = $getStaticData['admin_dist'];
                                        $option_no_install = $getStaticData['option_no_install'];
                                        $zone = $getStaticData['zone'];

                                        $route = $routes->addChild("entry");
                                        $route->addAttribute('name', $name);

                                        if ($destination != "") {
                                            $route->addChild("destination", $destination);
                                        }

                                        if ($option_no_install == 1) {
                                            $route->addChild("option");
                                            $route->option->addChild("no-install");
                                        }

                                        if (($metric != "") AND ( $metric != "0")) {
                                            $route->addChild("metric", $metric);
                                        }

                                        if (($admin_dist != "") AND ( $admin_dist != "0")) {
                                            $route->addChild("admin-dist", $admin_dist);
                                        }

                                        if ($tointerface != "") {
                                            $route->addChild("interface", $tointerface);
                                        }

                                        if ($nexthop != "None") {
                                            $route->addChild("nexthop");
                                            if ($nexthop_value != "") {
                                                $route->nexthop->addChild($nexthop, $nexthop_value);
                                            } else {
                                                $route->nexthop->addChild($nexthop);
                                            }
                                        }
                                    }
                                }

                                #IPV6
                                $getStatic = $projectdb->query("SELECT name,destination,tointerface,nexthop,nexthop_value,metric,admin_dist,option_no_install,zone FROM routes_static WHERE vr_id='$vr_id' AND ip_version='v6' AND source='$source' AND template='$template';");
                                if ($getStatic->num_rows > 0) {
                                    $vr->{'routing-table'}->addChild("ipv6");
                                    $vr->{'routing-table'}->ipv6->addChild("static-route");
                                    $routes = $vr->{'routing-table'}->ipv6->{'static-route'};
                                    while ($getStaticData = $getStatic->fetch_assoc()) {
                                        $name = $getStaticData['name'];
                                        $destination = $getStaticData['destination'];
                                        $tointerface = $getStaticData['tointerface'];
                                        $nexthop = $getStaticData['nexthop'];
                                        $nexthop_value = $getStaticData['nexthop_value'];
                                        $metric = $getStaticData['metric'];
                                        $admin_dist = $getStaticData['admin_dist'];
                                        $option_no_install = $getStaticData['option_no_install'];
                                        $zone = $getStaticData['zone'];

                                        $route = $routes->addChild("entry");
                                        $route->addAttribute('name', $name);

                                        if ($destination != "") {
                                            $route->addChild("destination", $destination);
                                        }

                                        if ($option_no_install == 1) {
                                            $route->addChild("option");
                                            $route->option->addChild("no-install");
                                        }

                                        if ($metric != "") {
                                            $route->addChild("metric", $metric);
                                        }

                                        if ($admin_dist != "") {
                                            $route->addChild("admin-dist", $admin_dist);
                                        }

                                        if ($tointerface != "") {
                                            $route->addChild("interface", $tointerface);
                                        }

                                        if ($nexthop != "None") {
                                            $route->addChild("nexthop");
                                            if ($nexthop_value != "") {
                                                $route->nexthop->addChild($nexthop, $nexthop_value);
                                            } else {
                                                $route->nexthop->addChild($nexthop);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    else{
                        $SA = $xml->xpath("/config/devices/entry/network/virtual-router");
                        unset($SA[0][0]); 
                    }
                }
            }

            if (count($allDG) > 0) {
                foreach ($allDG as $kkey => $vvalue) {
                    $vsys = $vvalue;
                    $xpath0 = $xml->xpath("/config/devices/entry[@name='localhost.localdomain']/$platform/entry[@name='$vsys']");
                    $xpath = $xpath0[0];

                    # ADDRESS
                    $getShared = $projectdb->query("SELECT name,type,ipaddress,cidr,description,fqdn,v4,v6,tag FROM address WHERE source='$source' AND vsys='$vsys'  AND dummy=0;");
                    if ($getShared->num_rows > 0) {
                        # ADDRESS
                        if (!isset($xpath->address)) {
                            $xpath->addChild('address');
                        } else {
                            #DELETE ADDRESS
                            $SA = $xpath->xpath("address");
                            unset($SA[0][0]);
                            $xpath->addChild('address');
                        }
                        while ($Data = $getShared->fetch_assoc()) {
                            $myname = $Data['name'];
                            if ($xpath->xpath("/address/entry[@name='$myname']") == null) {
                                $address = $xpath->address->addChild('entry');
                                $address->addAttribute('name', $Data['name']);
                                if ($Data['type'] == "ip-netmask") {
                                    $address->addChild('ip-netmask', $Data['ipaddress'] . '/' . $Data['cidr']);
                                } elseif ($Data['type'] == "ip-range") {
                                    $address->addChild('ip-range', $Data['ipaddress']);
                                } elseif ($Data['type'] == "fqdn") {
                                    $address->addChild('fqdn', $Data['ipaddress']);
                                } elseif ($Data['type'] == "dynamic") {
                                    if ($version == 5) {
                                        $address->addChild('dynamic', $Data['ipaddress']);
                                    } elseif ($version >= 6) {
                                        add_log('error', 'Exporting Address [' . $vsys . ']', 'Dynamic Address Not supported in Panos 6.x [' . $myname . ']', $source, 'Object was Not Migrated');
                                    }
                                }
                                if ($Data['description'] != "") {
                                    $address->addChild('description');
                                    $address->description = $Data['description'];
                                }
                                if (($Data['tag'] != "") AND ( $version >= 6)) {
                                    $tags = $address->addChild('tag');
                                    $mytags = explode(",", $Data['tag']);
                                    foreach ($mytags as $key => $value) {
                                        $tags->addChild('member', $value);
                                    }
                                }
                            } else {
                                add_log('warning', 'Exporting Address [' . $vsys . ']', 'Object Duplicated in Destination [' . $myname . ']', $source, 'Object was Not Migrated');
                            }
                        }
                    } else {
                        if (isset($xpath->address)) {
                            $SA = $xpath->xpath("address");
                            unset($SA[0][0]);
                        }
                    }

                    # SCHEDULES
                    $getShared = $projectdb->query("SELECT name,xml FROM schedules WHERE source='$source' AND vsys='$vsys' AND dummy = 0 ORDER BY id;");
                    if ($getShared->num_rows > 0) {
                        if (!isset($xpath->schedule)) {
                            $xpath->addChild('schedule');
                        } else {
                            #DELETE SCHEDULES
                            $SA = $xpath->xpath("schedule");
                            unset($SA[0][0]);
                            $xpath->addChild('schedule');
                        }
                        $theProfiles2 = $xpath->xpath("schedule");
                        $theProfiles = $theProfiles2[0];
                        while ($data2 = $getShared->fetch_assoc()) {
                            $xmlfield = $data2['xml'];
                            $xmlname = $data2['name'];
                            
                            if ($version >= 7) {
                                if (strpos($xmlfield,"<schedule-type>")==false){
                                    if (strpos($xmlfield,"<recurring>")!== false){
                                        $xmlfield = str_replace("<recurring>", "<schedule-type><recurring>", $xmlfield);
                                    }
                                    if (strpos($xmlfield,"</recurring>")!== false){
                                        $xmlfield = str_replace("</recurring>", "</recurring></schedule-type>", $xmlfield);
                                    }
                                    if (strpos($xmlfield,"<non-recurring>")!== false){
                                        $xmlfield = str_replace("<non-recurring>", "<schedule-type><non-recurring>", $xmlfield);
                                    }
                                    if (strpos($xmlfield,"</non-recurring>")!== false){
                                        $xmlfield = str_replace("</non-recurring>", "</non-recurring></schedule-type>", $xmlfield);
                                    }
                                }
                                    
                            }
                            
                            $xml_append = simplexml_load_string($xmlfield);
                            if ($theProfiles->xpath("//entry[@name='$xmlname']") != null) {
                                add_log('warning', 'Exporting Schedules [' . $vsys . ']', 'Object Duplicated in Destination [' . $xmlname . ']', $source, 'Object was Not Migrated');
                            } else {
                                SimpleXMLElement_append($theProfiles, $xml_append);
                            }
                        }
                    } else {
                        #DELETE SHARED SCHEDULES
                        if (isset($xpath->schedule)) {
                            $SA = $xpath->xpath("schedule");
                            unset($SA[0][0]);
                        }
                    }

                    # LOG SETTINGS
                    $getShared = $projectdb->query("SELECT type FROM log_settings WHERE source='$source' AND (type!='system') AND (type!='config')  AND vsys='$vsys' AND dummy = 0 GROUP BY type ORDER BY id;");
                    if ($getShared->num_rows > 0) {
                        if (!isset($xpath->{'log-settings'})) {
                            $xpath->addChild('log-settings');
                        } else {
                            #DELETE SHARED LOG SETTINGS
                            $SA = $xpath->xpath("log-settings");
                            unset($SA[0][0]);
                            $xpath->addChild('log-settings');
                        }
                        $theProfiles = $xpath->{'log-settings'};
                        while ($Data = $getShared->fetch_assoc()) {
                            $type = $Data['type'];
                            $thetype = $theProfiles->{$type};
                            if (empty($thetype)) {
                                $thetype = $theProfiles->addChild($type);
                            }
                            $getbyType = $projectdb->query("SELECT xml,name FROM log_settings WHERE source='$source' AND type='$type' AND vsys='$vsys' AND dummy = 0 ORDER BY id;");
                            if ($getbyType->num_rows > 0) {
                                while ($data2 = $getbyType->fetch_assoc()) {
                                    $xmlfield = $data2['xml'];
                                    $xmlname = $data2['name'];
                                    
                                    if($version >= 7){
                                        if($type == "snmptrap"){
                                            // En versión 7, el campo member tiene que ser una IP sino da error
                                            // Check if is IP
                                            $xmlfield2 = $xmlfield;
                                            $search_member = explode ("<manager>", $xmlfield2);
                                            $search_member2 = explode ("</manager>", $search_member[1]);
                                            $member = $search_member2[0];
                                            $is_ip = validateIpAddress($member, "v4");
                                            // Return 1: ip correct
                                            // si da error, añadir mensaje de error en el output mapping
                                        }
                                    }
                                    
                                    $xml_append = simplexml_load_string($xmlfield);
                                    if ($xpath->xpath("/log-settings/entry[@name='$xmlname']") != null) {
                                        add_log('warning', 'Exporting Log Settings [' . $vsys . ']', 'Object Duplicated in Destination [' . $xmlname . ']', $source, 'Object was Not Migrated');
                                    } else {
                                        SimpleXMLElement_append($xpath->{'log-settings'}->$type, $xml_append);
                                    }
                                }
                            }
                        }
                    } else {
                        #DELETE SHARED LOG SETTINGS
                        if (isset($xpath->{'log-settings'})) {
                            $SA = $xpath->xpath("log-settings");
                            unset($SA[0][0]);
                        }
                    }

                    # PROFILES
                    $getShared = $projectdb->query("SELECT type FROM profiles WHERE source='$source' AND (name!='strict') AND (name!='default') AND vsys='$vsys' AND dummy = 0 GROUP BY type ORDER BY id;");
                    if ($getShared->num_rows > 0) {
                        if (!isset($xpath->{'profiles'})) {
                            $xpath->addChild('profiles');
                        } else {
                            #DELETE LOG SETTINGS
                            $SA = $xpath->xpath("profiles");
                            unset($SA[0][0]);
                            $xpath->addChild('profiles');
                        }
                        $theProfiles = $xpath->profiles;
                        while ($Data = $getShared->fetch_assoc()) {
                            $type = $Data['type'];
                            $thetype = $theProfiles->{$type};
                            if (empty($thetype)) {
                                $thetype = $theProfiles->addChild($type);
                            }
                            $getbyType = $projectdb->query("SELECT xml,name FROM profiles WHERE source='$source' AND (name!='strict') AND (name!='default') AND type='$type' AND vsys='$vsys' AND dummy = 0 ORDER BY id;");
                            if ($getbyType->num_rows > 0) {
                                while ($data2 = $getbyType->fetch_assoc()) {
                                    $xmlfield = $data2['xml'];
                                    $xmlname = $data2['name'];
                                    if ($version > 5) {
                                        if ((strpos($xmlfield,"<packet-capture>yes</packet-capture>")!== false) AND ($type!="virus")){
                                            $xmlfield = str_replace("<packet-capture>yes</packet-capture>", "<packet-capture>single-packet</packet-capture>", $xmlfield);
                                        }
                                        if ((strpos($xmlfield,"<packet-capture>no</packet-capture>")!== false) AND ($type!="virus")){
                                            $xmlfield = str_replace("<packet-capture>no</packet-capture>", "<packet-capture>disable</packet-capture>", $xmlfield);
                                        }
                                    }
                                    if ($version >= 7) {
                                        if ((strpos($xmlfield,"<action>block</action>")!== false) AND ($type == "virus")){
                                            $xmlfield = str_replace("<action>block</action>", "<action>drop</action>", $xmlfield);
                                        }
                                        if ((strpos($xmlfield,"<wildfire-action>block</wildfire-action>")!== false) AND ($type == "virus")){
                                            $xmlfield = str_replace("<wildfire-action>block</wildfire-action>", "<wildfire-action>drop</wildfire-action>", $xmlfield);
                                        }
                                        //if ((strpos($xmlfield,"<block/>")!== false) AND ($type == "spyware")){
                                        //    $xmlfield = str_replace("<block/>", "<drop/>", $xmlfield);
                                        //}
                                        if ((strpos($xmlfield,"<block/>")!== false) AND ($type == "vulnerability")){
                                            $xmlfield = str_replace("<block/>", "<drop/>", $xmlfield);
                                        }
                                        /* SE TENDRÁ QUE HACER INSERT EN LA TABLA DE OUTPUT MAPPING EN EL CAMPO ERROR MESSAGE Y QUE SALGA EN EL + --> PENSAR COMO HACERLO */
                                        if ((strpos($xmlfield,"<action>forward</action>")!== false) AND ($type == "file-blocking")){
                                            $xmlfield = str_replace("<action>forward</action>", "", $xmlfield);
                                        }
                                        if ((strpos($xmlfield,"<action>continue-and-forward</action>")!== false) AND ($type == "file-blocking")){
                                            $xmlfield = str_replace("<action>continue-and-forward</action>", "", $xmlfield);
                                        }

                                    }
                                    $xml_append = simplexml_load_string($xmlfield);
                                    if ($xpath->xpath("/profiles/entry[@name='$xmlname']") != null) {
                                        add_log('warning', 'Exporting Profiles [' . $vsys . ']', 'Object Duplicated in Destination [' . $xmlname . ']', $source, 'Object was Not Migrated');
                                    } else {
                                        SimpleXMLElement_append($xpath->profiles->$type, $xml_append);
                                    }
                                }
                            }
                        }
                    } else {
                        #DELETE SHARED LOG SETTINGS
                        if (isset($xpath->{'profiles'})) {
                            $SA = $xpath->xpath("profiles");
                            unset($SA[0][0]);
                        }
                    }

                    # PROFILES GROUPS

                    $getShared = $projectdb->query("SELECT name,xml FROM profiles_groups WHERE source='$source' AND vsys='$vsys' AND dummy = 0 GROUP BY name;");
                    if ($getShared->num_rows > 0) {
                        if (!isset($xpath->{'profile-group'})) {
                            $xpath->addChild('profile-group');
                        } else {
                            #DELETE PROFILE GROUPS
                            $SA = $xpath->xpath("profile-group");
                            unset($SA[0][0]);
                            $xpath->addChild('profile-group');
                        }
                        $theProfiles2 = $xpath->xpath("profile-group");
                        $theProfiles = $theProfiles2[0];
                        while ($data2 = $getShared->fetch_assoc()) {
                            $xmlfield = $data2['xml'];
                            $xmlname = $data2['name'];
                            $xml_append = simplexml_load_string($xmlfield);
                            SimpleXMLElement_append($theProfiles, $xml_append);
                            
                        }
                    } else {
                        #DELETE SHARED EXTERNAL-LISTS
                        if (isset($xpath->{'profile-group'})) {
                            $SA = $xpath->xpath("profile-group");
                            unset($SA[0][0]);
                        }
                    }

                    # ADDRESS GROUPS
                    $getShared = $projectdb->query("SELECT name,id,tag,filter,type,description FROM address_groups_id WHERE source='$source' AND vsys='$vsys';");
                    if ($getShared->num_rows > 0) {
                        if (!isset($xpath->{'address-group'})) {
                            $xpath->addChild('address-group');
                        } else {
                            #DELETE SHARED ADDRESS GROUPS
                            $SA = $xpath->xpath("address-group");
                            unset($SA[0][0]);
                            $xpath->addChild('address-group');
                        }
                        while ($Data = $getShared->fetch_assoc()) {
                            $groupName = $Data['name'];
                            $lid = $Data['id'];
                            $myname = $Data['name'];
                            if ($xpath->xpath("/address-group/entry[@name='$myname']") == null) {
                                $getMembers = $projectdb->query("SELECT table_name,member_lid FROM address_groups WHERE source='$source' and lid='$lid' AND vsys='$vsys'");

                                if ($getMembers->num_rows > 0) {
                                    $service = $xpath->{'address-group'}->addChild('entry');
                                    $service->addAttribute('name', $Data['name']);
                                    if (($version >= 6) AND ( $Data['type'] == "static")) {
                                        $service2 = $service->addChild('static');
                                    } elseif ($version < 6) {
                                        $service2 = $service;
                                    }
                                    while ($Datas = $getMembers->fetch_assoc()) {
                                        $table_name = $Datas['table_name'];
                                        $member_lid = $Datas['member_lid'];
                                        $getName = $projectdb->query("SELECT name FROM $table_name WHERE source='$source' and id='$member_lid'");
                                        if ($getName->num_rows==1){
                                            $Datas2 = $getName->fetch_assoc();
                                            $member = $service2->addChild('member', $Datas2['name']);
                                        }    
                                    }
                                } else {
                                    $service = $xpath->{'address-group'}->addChild('entry');
                                    $service->addAttribute('name', $Data['name']);
                                    if (($version >= 6) AND ( $Data['type'] == "dynamic")) {
                                        $service2 = $service->addChild('dynamic');
                                        $filter = str_replace("<br>", "\n", $Data['filter']);
                                        $service2 = $service->dynamic->addChild('filter', $filter);
                                    }
                                }
                                if ($Data['description'] != "") {
                                    $service->addChild('description');
                                    $service->description = $Data['description'];
                                }
                                if ($Data['tag'] != "") {
                                    $tags = explode(",", $Data['tag']);
                                    $shtag = $service->addChild('tag');
                                    foreach ($tags as $kkey => $vvalue) {
                                        $shtag->addChild('member', $vvalue);
                                    }
                                }
                            } else {
                                add_log('warning', 'Exporting Address Groups [' . $vsys . ']', 'Object Duplicated in Destination [' . $myname . ']', $source, 'Object was Not Migrated');
                            }
                        }
                    } else {
                        #DELETE SHARED ADDRESS GROUPS
                        if (isset($xpath->{'address-group'})) {
                            $SA = $xpath->xpath("address-group");
                            unset($SA[0][0]);
                        }
                    }

                    # TAGS 6.X
                    $getShared = $projectdb->query("SELECT name,color,comments FROM tag WHERE source='$source' AND vsys='$vsys' AND dummy = 0;");
                    if (($version >= 6) AND ( $getShared->num_rows > 0)) {
                        if (!isset($xpath->tag)) {
                            $xpath->addChild('tag');
                        } else {
                            #DELETE SHARED TAGS
                            $SA = $xpath->xpath("tag");
                            unset($SA[0][0]);
                            $xpath->addChild('tag');
                        }
                        $theProfiles = $xpath->tag;
                        while ($tag = $getShared->fetch_assoc()) {
                            $tagName = $tag['name'];
                            $newtag = $theProfiles->addChild('entry');
                            $newtag->addAttribute('name', $tagName);
                            if (($tag['color'] != "") AND ( $tag['color'] != "None")) {
                                $newtag->addChild('color', $tag['color']);
                            }
                            if ($tag['comments'] != "") {
                                $newtag->addChild('comments', $tag['comments']);
                            }
                        }
                    } elseif (($version >= 6) AND ( $getShared->num_rows == 0)) {
                        #DELETE SHARED TAGS
                        if (isset($xpath->{'tag'})) {
                            $SA = $xpath->xpath("tag");
                            unset($SA[0][0]);
                        }
                    }

                    # SERVICES
                    $getShared = $projectdb->query("SELECT name,dport,sport,protocol,tag,description FROM services WHERE source='$source' AND dummy=0 AND (protocol = 'tcp' or protocol = 'udp') AND (name <> 'application-default' AND name <> 'service-http' AND name <> 'service-https') AND vsys='$vsys';");
                    if ($getShared->num_rows > 0) {
                        if (!isset($xpath->service)) {
                            $xpath->addChild('service');
                        } else {
                            #DELETE SERVICES
                            $SA = $xpath->xpath("service");
                            unset($SA[0][0]);
                            $xpath->addChild('service');
                        }
                        while ($Data = $getShared->fetch_assoc()) {
                            $myname = $Data['name'];
                            if ($xpath->xpath("/service/entry[@name='$myname']") == null) {
                                $service = $xpath->service->addChild('entry');
                                $service->addAttribute('name', $Data['name']);
                                $protocol = $service->addChild('protocol');
                                $port = $protocol->addChild($Data['protocol']);
                                $port->addChild('port', $Data['dport']);
                                if (($Data['sport'] != NULL) or ( $Data['sport'] != "")) {
                                    $port->addChild('source-port', $Data['sport']);
                                }
                                if ($Data['description'] != "") {
                                    $protocol = $service->addChild('description');
                                    $service->description = $Data['description'];
                                }
                                if (($version >= 6) AND ( $Data['tag'] != "")) {
                                    $tags = $service->addChild('tag');
                                    $mytags = explode(",", $Data['tag']);
                                    foreach ($mytags as $key => $value) {
                                        $tags->addChild('member', $value);
                                    }
                                }
                            } else {
                                add_log('warning', 'Exporting Services [' . $vsys . ']', 'Object Duplicated in Destination [' . $myname . ']', $source, 'Object was Not Migrated');
                            }
                        }
                    } else {
                        #DELETE SERVICES
                        if (isset($xpath->{'servicep'})) {
                            $SA = $xpath->xpath("service");
                            unset($SA[0][0]);
                        }
                    }

                    # SERVICES GROUPS
                    $getShared = $projectdb->query("SELECT name,id,tag FROM services_groups_id WHERE source='$source' AND vsys='$vsys';");
                    if ($getShared->num_rows > 0) {
                        if (!isset($xpath->{'service-group'})) {
                            $xpath->addChild('service-group');
                        } else {
                            #DELETE SHARED SERVICES GROUPS
                            $SA = $xpath->xpath("service-group");
                            unset($SA[0][0]);
                            $xpath->addChild('service-group');
                        }
                        while ($Data = $getShared->fetch_assoc()) {
                            $groupName = $Data['name'];
                            $lid = $Data['id'];
                            $myname = $Data['name'];
                            if ($xpath->xpath("/service-group/entry[@name='$myname']") == null) {
                                $getMembers = $projectdb->query("SELECT table_name,member_lid FROM services_groups WHERE source='$source' and lid='$lid' AND vsys='$vsys'");
                                if ($getMembers->num_rows > 0) {
                                    $service = $xpath->{'service-group'}->addChild('entry');
                                    $service->addAttribute('name', $Data['name']);
                                    if ($version >= 6) {
                                        $service2 = $service->addChild('members');
                                    } elseif ($version < 6) {
                                        $service2 = $service;
                                    }
                                    while ($Datas = $getMembers->fetch_assoc()) {
                                        $table_name = $Datas['table_name'];
                                        $member_lid = $Datas['member_lid'];
                                        $getName = $projectdb->query("SELECT name FROM $table_name WHERE id='$member_lid'");
                                        if ($getName->num_rows==1){
                                            $Datas2 = $getName->fetch_assoc();
                                            $member = $service2->addChild('member', $Datas2['name']);
                                        }
                                    }
                                    if (($version >= 6) AND ( $Data['tag'] != "")) {
                                        $tags = $service->addChild('tag');
                                        $mytags = explode(",", $Data['tag']);
                                        foreach ($mytags as $key => $value) {
                                            $tags->addChild('member', $value);
                                        }
                                    }
                                }
                            } else {
                                add_log('warning', 'Exporting Services Groups [' . $vsys . ']', 'Object Duplicated in Destination [' . $myname . ']', $source, 'Object was Not Migrated');
                            }
                        }
                    } else {
                        if (isset($xpath->{'service-group'})) {
                            $SA = $xpath->xpath("service-group");
                            unset($SA[0][0]);
                        }
                    }

                    # EXTERNAL-LISTS
                    $getShared = $projectdb->query("SELECT name,xml FROM external_list WHERE source='$source' AND vsys='$vsys' GROUP BY name ORDER BY id;");
                    if ($getShared->num_rows > 0) {
                        if (!isset($xpath->{'external-list'})) {
                            $xpath->addChild('external-list');
                        } else {
                            #DELETE EXTERNAL-LISTS
                            $SA = $xpath->xpath("external-list");
                            unset($SA[0][0]);
                            $xpath->addChild('external-list');
                        }
                        $theProfiles2 = $xpath->xpath("external-list");
                        $theProfiles = $theProfiles2[0];
                        while ($data2 = $getShared->fetch_assoc()) {
                            $xmlfield = $data2['xml'];
                            $xmlname = $data2['name'];
                            $xml_append = simplexml_load_string($xmlfield);
                            SimpleXMLElement_append($theProfiles, $xml_append);
                        }
                    } else {
                        if (isset($xpath->{'external-list'})) {
                            $SA = $xpath->xpath("external-list");
                            unset($SA[0][0]);
                        }
                    }

                    # REGIONS
                    $getShared = $projectdb->query("SELECT name,xml,address,latitude,longitude FROM regions WHERE source='$source' AND vsys='$vsys' ORDER BY id;");
                    if ($getShared->num_rows > 0) {
                        if (!isset($xpath->region)) {
                            $xpath->addChild('region');
                        } else {
                            #DELETE EXTERNAL-LISTS
                            $SA = $xpath->xpath("region");
                            unset($SA[0][0]);
                            $xpath->addChild('region');
                        }
                        $theProfiles2 = $xpath->xpath("region");
                        $theProfiles = $theProfiles2[0];
                        while ($data2 = $getShared->fetch_assoc()) {
                            $xmlfield = $data2['xml'];
                            $xmlname = $data2['name'];
                            $latitude=$data2['latitude'];
                            $longitude=$data2['longitude'];
                            $regionMembers=$data2['address'];
                            if ($theProfiles->xpath("//entry[@name='$xmlname']") != null) {
                                add_log('warning', 'Exporting Regions [' . $vsys . ']', 'Object Duplicated in Destination [' . $xmlname . ']', $source, 'Object was Not Migrated');
                            } else {
                                $newRegion=$theProfiles->addChild("entry");
                                $newRegion->addAttribute('name', $xmlname);
                                if ($regionMembers!=""){
                                    $newRegion->addChild("address");
                                    $regionMembersArray=explode(",",$regionMembers);
                                    foreach ($regionMembersArray as $regionMembersValue){
                                        $newRegion->address->addChild("member",$regionMembersValue);
                                    }
                                }
                                if (($longitude!="") AND ($latitude!="")){
                                    $newRegion->addChild("geo-location");
                                    $newRegion->{'geo-location'}->addChild("latitude",$latitude);
                                    $newRegion->{'geo-location'}->addChild("longitude",$longitude);
                                }
                            }
                        }
                    } else {
                        if (isset($xpath->{'region'})) {
                            $SA = $xpath->xpath("region");
                            unset($SA[0][0]);
                        }
                    }

                    # APPLICATIONS
                    $getShared = $projectdb->query("SELECT id,name,description,spyware_ident,category,subcategory,parent_app,risk,technology,evasive_behavior,consume_big_bandwidth,used_by_malware,able_to_transfer_file,has_known_vulnerability,tunnel_other_application,tunnel_applications,prone_to_misuse,pervasive_use,file_type_ident,virus_ident,data_ident,default_type,value,type,code,timeout,tcp_timeout,udp_timeout,tcp_half_closed_timeout,tcp_time_wait_timeout FROM applications WHERE source='$source' AND vsys='$vsys' AND dummy=0 ORDER BY id;");
                    if ($getShared->num_rows > 0) {
                        if (!isset($xpath->application)) {
                            $xpath->addChild('application');
                        } else {
                            #DELETE APPLICATIONS
                            $SA = $xpath->xpath("application");
                            unset($SA[0][0]);
                            $xpath->addChild('application');
                        }

                        while ($data2 = $getShared->fetch_object()) {
                            $appid = $data2->id;
                            $myname = $data2->name;
                            if ($xpath->xpath("/application/entry[@name='$myname']") == null) {
                                $application = $xpath->application->addChild('entry');
                                $application->addAttribute('name', $myname);
                                if ($data2->description != "") {
                                    $application->addChild('description');
                                    $application->description = $data2->description;
                                }
                                if ($data2->category != "") {
                                    $application->addChild('category', $data2->category);
                                }
                                if ($data2->subcategory != "") {
                                    $application->addChild('subcategory', $data2->subcategory);
                                }
                                if ($data2->risk != "") {
                                    $application->addChild('risk', $data2->risk);
                                }
                                if ($data2->technology != "") {
                                    $application->addChild('technology', $data2->technology);
                                }
                                if ($data2->evasive_behavior != "") {
                                    $application->addChild('evasive-behavior', $data2->evasive_behavior);
                                }
                                if ($data2->consume_big_bandwidth != "") {
                                    $application->addChild('consume-big-bandwidth', $data2->consume_big_bandwidth);
                                }
                                if ($data2->used_by_malware != "") {
                                    $application->addChild('used-by-malware', $data2->used_by_malware);
                                }
                                if ($data2->able_to_transfer_file != "") {
                                    $application->addChild('able-to-transfer-file', $data2->able_to_transfer_file);
                                }
                                if ($data2->has_known_vulnerability != "") {
                                    $application->addChild('has-known-vulnerability', $data2->has_known_vulnerability);
                                }
                                if ($data2->tunnel_other_application != "") {
                                    $application->addChild('tunnel-other-application', $data2->tunnel_other_application);
                                }
                                if ($data2->tunnel_applications != "") {
                                    $application->addChild('tunnel-applications', $data2->tunnel_applications);
                                }
                                if ($data2->prone_to_misuse != "") {
                                    $application->addChild('prone-to-misuse', $data2->prone_to_misuse);
                                }
                                if ($data2->pervasive_use != "") {
                                    $application->addChild('pervasive-use', $data2->pervasive_use);
                                }
                                if ($data2->file_type_ident != "") {
                                    $application->addChild('file-type-ident', $data2->file_type_ident);
                                }
                                if ($data2->virus_ident != "") {
                                    $application->addChild('virus-ident', $data2->virus_ident);
                                }
                                if ($data2->data_ident != "") {
                                    $application->addChild('data-ident', $data2->data_ident);
                                }
                                if ($version < 6) {
                                    if ($data2->spyware_ident != "") {
                                        $application->addChild('spyware-ident', $data2->spyware_ident);
                                    }
                                }
                                if (($data2->parent_app != "None") AND ($data2->parent_app!="")) {
                                    $application->addChild('parent-app', $data2->parent_app);
                                }
                                if ($data2->timeout > 0) {
                                    $application->addChild('timeout', $data2->timeout);
                                }
                                if ($data2->tcp_timeout > 0) {
                                    $application->addChild('tcp-timeout', $data2->tcp_timeout);
                                }
                                if ($data2->udp_timeout > 0) {
                                    $application->addChild('udp-timeout', $data2->udp_timeout);
                                }
                                if($version >= 6){
                                    if ($data2->tcp_half_closed_timeout > 0) {
                                        $application->addChild('tcp-half-closed-timeout', $data2->tcp_half_closed_timeout);
                                    }
                                    if ($data2->tcp_time_wait_timeout > 0) {
                                        $application->addChild('tcp-time-wait-timeout', $data2->tcp_time_wait_timeout);
                                    }
                                }
                                if ($data2->default_type == "port") {
                                    $default = $application->addChild('default');
                                    $port = $default->addChild('port');
                                    $ports = explode(",", $data2->value);
                                    foreach ($ports as $kkey => $vvalue) {
                                        $port->addChild('member', $vvalue);
                                    }
                                } elseif ($data2->default_type == "ident-by-ip-protocol") {
                                    $default = $application->addChild('default');
                                    $port = $default->addChild('ident-by-ip-protocol', $data2->value);
                                } elseif ($data2->default_type == "ident-by-icmp-type") {
                                    //$port = $default->addChild('ident-by-icmp-type', $data2->value);
                                    if($version < 7){
                                        $default = $application->addChild('default');
                                        $port = $default->addChild('ident-by-icmp-type', $data2->type);
                                    }else{
                                        $default = $application->addChild('default');
                                        $port = $default->addChild('ident-by-icmp-type');
                                        $port->addChild('type', $data2->type);
                                        $port->addChild('code', $data2->code);
                                    }
                                } elseif ($data2->default_type == "ident-by-icmp6-type") {
                                    $default = $application->addChild('default');
                                    $port = $default->addChild('ident-by-icmp6-type');
                                    $port->addChild('code', $data2->code);
                                    $port->addChild('type', $data2->type);
                                } elseif ($data2->default_type == "None") {
                                    
                                }

                                $getSignature = $projectdb->query("SELECT signature FROM applications_signatures WHERE source='$source' AND member_lid='$appid' AND table_name='applications' AND vsys='$vsys';");
                                if ($getSignature->num_rows > 0) {
                                    $application->addChild('signature');
                                    $sig = $application->signature;
                                    while ($data3 = $getSignature->fetch_assoc()) {
                                        $xml_append = simplexml_load_string($data3['signature']);
                                        SimpleXMLElement_append($sig, $xml_append);
                                    }
                                }
                            }
                        }
                    } else {
                        if (isset($xpath->{'application'})) {
                            $SA = $xpath->xpath("application");
                            unset($SA[0][0]);
                        }
                    }

                    # APPLICATIONS FILTERS
                    $getShared = $projectdb->query("SELECT id,name,category,subcategory,risk,technology,evasive_behavior,consume_big_bandwidth,used_by_malware,able_to_transfer_file,has_known_vulnerability,tunnel_other_application,prone_to_misuse,pervasive_use,disable_override FROM applications_filters WHERE source='$source' AND vsys='$vsys' ORDER BY id;");
                    if ($getShared->num_rows > 0) {
                        
                        if (!isset($xpath->{'application-filter'})) {
                            $xpath->addChild('application-filter');
                        } else {
                            #DELETE APPLICATIONS FILTERS
                            $SA = $xpath->xpath("application-filter");
                            unset($SA[0][0]);
                            $xpath->addChild('application-filter');
                        }
                        $theProfiles2 = $xpath->xpath("application-filter");
                        $theProfiles = $theProfiles2[0];
                        
                        while ($data2 = $getShared->fetch_object()) {
                            $appid = $data2->id;
                            $myname = $data2->name;
                            if ($xpath->xpath("/application-filter/entry[@name='$myname']") == null) {
                                $application_filters = $xpath->{'application-filter'}->addChild('entry');
                                $application_filters->addAttribute('name', $myname);
                                if (($data2->disable_override!="") AND ($version>=7)){
                                    $disable_override=$application_filters->addChild('disable-override',$data2->disable_override);
                                }
                                if($data2->category != ""){
                                    $category = $application_filters->addChild('category');
                                    $category_s = explode(",", $data2->category);
                                    foreach ($category_s as $kkey => $vvalue) {
                                        $category->addChild('member', $vvalue);
                                    }
                                }
                                if($data2->subcategory != ""){
                                    $subcategory = $application_filters->addChild('subcategory');
                                    $subcategory_s = explode(",", $data2->subcategory);
                                    foreach ($subcategory_s as $kkey => $vvalue) {
                                        $subcategory->addChild('member', $vvalue);
                                    }
                                }
                                if($data2->risk != ""){
                                    $risk = $application_filters->addChild('risk');
                                    $risk_s = explode(",", $data2->risk);
                                    foreach ($risk_s as $kkey => $vvalue) {
                                        $risk->addChild('member', $vvalue);
                                    }
                                }
                                if($data2->technology != ""){
                                    $technology = $application_filters->addChild('technology');
                                    $technology_s = explode(",", $data2->technology);
                                    foreach ($technology_s as $kkey => $vvalue) {
                                        $technology->addChild('member', $vvalue);
                                    }
                                }
                                if ($data2->evasive_behavior != "") {
                                    $application_filters->addChild('evasive', $data2->evasive_behavior);
                                }
                                if ($data2->consume_big_bandwidth != "") {
                                    $application_filters->addChild('excessive-bandwidth-use', $data2->consume_big_bandwidth);
                                }
                                if ($data2->used_by_malware != "") {
                                    $application_filters->addChild('used-by-malware', $data2->used_by_malware);
                                }
                                if ($data2->able_to_transfer_file != "") {
                                    $application_filters->addChild('transfers-files', $data2->able_to_transfer_file);
                                }
                                if ($data2->has_known_vulnerability != "") {
                                    $application_filters->addChild('has-known-vulnerabilities', $data2->has_known_vulnerability);
                                }
                                if ($data2->tunnel_other_application != "") {
                                    $application_filters->addChild('tunnels-other-apps', $data2->tunnel_other_application);
                                }
                                if ($data2->prone_to_misuse != "") {
                                    $application_filters->addChild('prone-to-misuse', $data2->prone_to_misuse);
                                }
                                if ($data2->pervasive_use != "") {
                                    $application_filters->addChild('pervasive', $data2->pervasive_use);
                                }
                            }
                        }
                    } else {
                        if (isset($xpath->{'application-filter'})) {
                            $SA = $xpath->xpath("application-filter");
                            unset($SA[0][0]);
                        }
                    }

                    # APPLICATIONS GROUPS
                    $getShared = $projectdb->query("SELECT name,id FROM applications_groups_id WHERE source='$source' AND vsys='$vsys';");
                    if ($getShared->num_rows > 0) {
                        if (!isset($xpath->{'application-group'})) {
                            $xpath->addChild('application-group');
                        } else {
                            #DELETE SHARED SERVICES GROUPS
                            $SA = $xpath->xpath("application-group");
                            unset($SA[0][0]);
                            $xpath->addChild('application-group');
                        }
                        while ($Data = $getShared->fetch_assoc()) {
                            $groupName = $Data['name'];
                            $lid = $Data['id'];
                            $myname = $Data['name'];
                            if ($xpath->xpath("/application-group/entry[@name='$myname']") == null) {
                                $getMembers = $projectdb->query("SELECT table_name,member_lid FROM applications_groups WHERE source='$source' and lid='$lid' AND vsys='$vsys'");
                                if ($getMembers->num_rows > 0) {
                                    $service = $xpath->{'application-group'}->addChild('entry');
                                    $service->addAttribute('name', $Data['name']);
                                    if ($version >= 7) {
                                        $service2 = $service->addChild('members');
                                    } elseif ($version < 7) {
                                        $service2 = $service;
                                    }
                                    while ($Datas = $getMembers->fetch_assoc()) {
                                        $table_name = $Datas['table_name'];
                                        $member_lid = $Datas['member_lid'];
                                        $getName = $projectdb->query("SELECT name FROM $table_name WHERE id='$member_lid'");
                                        if ($getName->num_rows==1){
                                            $Datas2 = $getName->fetch_assoc();
                                            $member = $service2->addChild('member', $Datas2['name']);
                                        }
                                    }
                                }
                            } else {
                                add_log('warning', 'Exporting Applications Groups [' . $vsys . ']', 'Object Duplicated in Destination [' . $myname . ']', $source, 'Object was Not Migrated');
                            }
                        }
                    } else {
                        if (isset($xpath->{'application-group'})) {
                            $SA = $xpath->xpath("application-group");
                            unset($SA[0][0]);
                        }
                    }


                    #ZONES
                    if ($ispanorama == 0) {
                        $getShared = $projectdb->query("SELECT id,name,type,interfaces,zone_protection_profile,log_setting_id,include_list,exclude_list,enable_user_identification,log_setting_table_name FROM zones WHERE source='$source' AND vsys='$vsys' ORDER BY id;");
                        if ($getShared->num_rows > 0) {
                            if (!isset($xpath->zone)) {
                                $xpath->addChild('zone');
                            } else {
                                #DELETE zone
                                $SA = $xpath->xpath("zone");
                                unset($SA[0][0]);
                                $xpath->addChild('zone');
                            }
                            while ($data = $getShared->fetch_assoc()) {
                                $myname = $data['name'];
                                $type = $data['type'];
                                $interfaces = $data['interfaces'];
                                $zone_protection_profile = $data['zone_protection_profile'];
                                $log_setting_id = $data['log_setting_id'];
                                $log_setting_table_name = $data['log_setting_table_name'];
                                $include_list = $data['include_list'];
                                $exclude_list = $data['exclude_list'];
                                $enable_user_identification = $data['enable_user_identification'];

                                $zone = $xpath->zone->addChild('entry');
                                $zone->addAttribute('name', $myname);
                                $zone->addChild('network');

                                $zone->network->addChild($type);
                                if ($interfaces != "") {
                                    $allinterfaces = explode(",", $interfaces);
                                    foreach ($allinterfaces as $key => $vvvalue) {
                                        $zone->network->{$type}->addChild('member', $vvvalue);
                                    }
                                }

                                if (($zone_protection_profile != "") AND ( $zone_protection_profile != "None")) {
                                    $zone->network->addChild('zone-protection-profile', $zone_protection_profile);
                                }
                                if (($log_setting_id != "") AND ( $log_setting_table_name != "")) {
                                    $getLP = $projectdb->query("SELECT name FROM $log_setting_table_name WHERE id='$log_setting_id';");
                                    if ($getLP->num_rows == 1) {
                                        $LPData = $getLP->fetch_assoc();
                                        $zone->network->addChild('log-setting', $LPData['name']);
                                    }
                                }
                                if (($include_list != "") OR ( $exclude_list != "")) {
                                    $zone->addChild('user-acl');
                                }
                                if ($include_list != "") {
                                    $allinclude = explode(",", $include_list);
                                    $zone->{'user-acl'}->addChild('include-list');
                                    foreach ($allinclude as $key => $vvvalue) {
                                        $zone->{'user-acl'}->{'include-list'}->addChild('member', $vvvalue);
                                    }
                                }
                                if ($exclude_list != "") {
                                    $allinclude = explode(",", $exclude_list);
                                    $zone->{'user-acl'}->addChild('exclude-list');
                                    foreach ($allinclude as $key => $vvvalue) {
                                        $zone->{'user-acl'}->{'exclude-list'}->addChild('member', $vvvalue);
                                    }
                                }
                                if ($enable_user_identification == "yes") {
                                    $zone->addChild('enable-user-identification', $enable_user_identification);
                                }
                            }
                        } else {
                            #DELETE ZONES
                            if (isset($xpath->{'zone'})) {
                                $SA = $xpath->xpath("zone");
                                unset($SA[0][0]);
                            }
                        }
                    }

                    #POLICIES
                    foreach ($policies as $pkey => $pvalue) {
                        if ($pvalue == "pre-rulebase"){
                            $preorpost = 0;
                            $getPolicies = $projectdb->query("SELECT icmp_unreachable,rule_type,id,position,name,negate_source,negate_destination,description,action,schedule,disabled,log_start,log_end,log_forwarding,lid,dsri,target,qos,profile_type,qos_value,tag FROM security_rules WHERE source='$source' AND vsys='$vsys' AND preorpost='$preorpost' ORDER BY position ASC;");
                        } elseif ($pvalue == "post-rulebase") {
                            $preorpost = 1;
                            $getPolicies = $projectdb->query("SELECT icmp_unreachable,rule_type,id,position,name,negate_source,negate_destination,description,action,schedule,disabled,log_start,log_end,log_forwarding,lid,dsri,target,qos,profile_type,qos_value,tag FROM security_rules WHERE source='$source' AND vsys='$vsys' AND preorpost='$preorpost' ORDER BY position ASC;");
                        } elseif ( $pvalue == "rulebase"){
                            $getPolicies = $projectdb->query("SELECT icmp_unreachable,rule_type,id,position,name,negate_source,negate_destination,description,action,schedule,disabled,log_start,log_end,log_forwarding,lid,dsri,target,qos,profile_type,qos_value,tag FROM security_rules WHERE source='$source' AND vsys='$vsys' ORDER BY position ASC;");
                        }

                        # SECURITY
                        #$getPolicies = $projectdb->query("SELECT rule_type,id,position,name,negate_source,negate_destination,description,action,schedule,disabled,log_start,log_end,log_forwarding,lid,dsri,target,qos,profile_type,qos_value,tag FROM security_rules WHERE source='$source' AND vsys='$vsys' AND preorpost='$preorpost' ORDER BY position ASC;");
                        if ($getPolicies->num_rows > 0) {
                            if (!isset($xpath->{$pvalue})) {
                                $xpath->addChild($pvalue);
                            }

                            if (!isset($xpath->{$pvalue}->security)) {
                                $xpath->{$pvalue}->addChild('security');
                            }

                            if (!isset($xpath->{$pvalue}->security->rules)) {
                                $xpath->{$pvalue}->security->addChild('rules');
                            } else {
                                #DELETE RULES
                                $SA = $xpath->$pvalue->security->xpath("rules");
                                unset($SA[0][0]);
                                $xpath->{$pvalue}->security->addChild('rules');
                            }

                            while ($data2 = $getPolicies->fetch_object()) {
                                $myname = $data2->name;
                                $lid = $data2->id;
                                if ($xpath->xpath("/$pvalue/security/rules/entry[@name='$myname']") == null) {
                                    $rule = $xpath->$pvalue->security->rules->addChild('entry');
                                    $rule->addAttribute('name', $myname);
                                    if ($version > 6.0) {
                                        if ($data2->rule_type != "universal") {
                                            $rule->addChild("rule-type", $data2->rule_type);
                                        }
                                    }
                                    if ($data2->dsri == 0) {
                                        $dsri = "no";
                                    } else {
                                        $dsri = "yes";
                                    }
                                    if ($dsri!="no"){
                                        $rule->addChild('option');
                                        $rule->option->addChild('disable-server-response-inspection', $dsri);
                                    }
                                    if ($version>=7){
                                        if ($data2->icmp_unreachable!=""){
                                            $rule->addChild('icmp-unreachable',$data2->icmp_unreachable);
                                        }
                                    }    
                                    $getFrom = $projectdb->query("SELECT name FROM security_rules_from WHERE rule_lid='$lid' ;");
                                    if ($getFrom->num_rows > 0) {
                                        $rule->addChild('from');
                                        while ($k = $getFrom->fetch_object()) {
                                            $rule->from->addChild('member', $k->name);
                                        }
                                    } else {
                                        $rule->addChild('from');
                                        $rule->from->addChild('member', 'any');
                                    }
                                    $getTo = $projectdb->query("SELECT name FROM security_rules_to WHERE rule_lid='$lid';");
                                    if ($getTo->num_rows > 0) {
                                        $rule->addChild('to');
                                        while ($k = $getTo->fetch_object()) {
                                            $rule->to->addChild('member', $k->name);
                                        }
                                    } else {
                                        $rule->addChild('to');
                                        $rule->to->addChild('member', 'any');
                                    }
                                    $getSource = $projectdb->query("SELECT member_lid,table_name FROM security_rules_src WHERE rule_lid='$lid';");
                                    if ($getSource->num_rows > 0) {
                                        $rule->addChild('source');
                                        while ($k = $getSource->fetch_object()) {
                                            $getMember = $projectdb->query("SELECT name FROM $k->table_name WHERE id='$k->member_lid';");
                                            if ($getMember->num_rows > 0) {
                                                while ($kk = $getMember->fetch_object()) {
                                                    $rule->source->addChild('member', $kk->name);
                                                }
                                            }
                                        }
                                    } else {
                                        $rule->addChild('source');
                                        $rule->source->addChild('member', 'any');
                                    }
                                    $getDestination = $projectdb->query("SELECT member_lid,table_name FROM security_rules_dst WHERE rule_lid='$lid';");
                                    if ($getDestination->num_rows > 0) {
                                        $rule->addChild('destination');
                                        while ($k = $getDestination->fetch_object()) {
                                            $getMember = $projectdb->query("SELECT name FROM $k->table_name WHERE id='$k->member_lid';");
                                            if ($getMember->num_rows > 0) {
                                                while ($kk = $getMember->fetch_object()) {
                                                    $rule->destination->addChild('member', $kk->name);
                                                }
                                            }
                                        }
                                    } else {
                                        $rule->addChild('destination');
                                        $rule->destination->addChild('member', 'any');
                                    }
                                    $getUser = $projectdb->query("SELECT name FROM security_rules_usr WHERE rule_lid='$lid' ;");
                                    if ($getUser->num_rows > 0) {
                                        $rule->addChild('source-user');
                                        while ($k = $getUser->fetch_object()) {
                                            $rule->{'source-user'}->addChild('member',  htmlentities($k->name));
                                            //$rule_user->member = addslashes($k['name']);
                                            //$rule_user->member = $k['name'];
                                        }
                                    } else {
                                        $rule->addChild('source-user');
                                        $rule->{'source-user'}->addChild('member', 'any');
                                    }
                                    $getAPP = $projectdb->query("SELECT member_lid,table_name FROM security_rules_app WHERE rule_lid='$lid';");
                                    if ($getAPP->num_rows > 0) {
                                        $rule->addChild('application');
                                        while ($k = $getAPP->fetch_object()) {
                                            $thesql = "SELECT name FROM " . $k->table_name . " WHERE id='" . $k->member_lid . "';";
                                            $getMember = $projectdb->query($thesql);
                                            if ($getMember->num_rows > 0) {
                                                while ($kk = $getMember->fetch_object()) {
                                                    $rule->{'application'}->addChild('member', $kk->name);
                                                }
                                            }
                                        }
                                    } else {
                                        $rule->addChild('application');
                                        $rule->{'application'}->addChild('member', 'any');
                                    }
                                    $getSRV = $projectdb->query("SELECT member_lid,table_name FROM security_rules_srv WHERE rule_lid='$lid';");
                                    if ($getSRV->num_rows > 0) {
                                        $rule->addChild('service');
                                        while ($k = $getSRV->fetch_object()) {
                                            $getMember = $projectdb->query("SELECT name FROM $k->table_name WHERE source='$source' AND id='$k->member_lid';");
                                            if ($getMember->num_rows > 0) {
                                                while ($kk = $getMember->fetch_object()) {
                                                    $rule->{'service'}->addChild('member', $kk->name);
                                                }
                                            } else {
                                                $getMember = $projectdb->query("SELECT name FROM $k->table_name WHERE id='$k->member_lid';");
                                                if ($getMember->num_rows > 0) {
                                                    while ($kk = $getMember->fetch_object()) {
                                                        $rule->{'service'}->addChild('member', $kk->name);
                                                    }
                                                }
                                            }
                                        }
                                    } else {
                                        $rule->addChild('service');
                                        $rule->{'service'}->addChild('member', 'any');
                                    }
                                    $getHIP = $projectdb->query("SELECT member_lid,table_name,name FROM security_rules_hip WHERE rule_lid='$lid';");
                                    if ($getHIP->num_rows > 0) {
                                        $rule->addChild('hip-profiles');
                                        while ($k = $getHIP->fetch_object()) {
                                            if (($k->member_lid == 0) AND ( $k->table_name == "default")) {
                                                $rule->{'hip-profiles'}->addChild('member', $k->name);
                                            } else {
                                                $getMember = $projectdb->query("SELECT name FROM $k->table_name WHERE id='$k->member_lid' AND type='hip-profiles';");
                                                if ($getMember->num_rows > 0) {
                                                    while ($kk = $getMember->fetch_object()) {
                                                        $rule->{'hip-profiles'}->addChild('member', $kk->name);
                                                    }
                                                }
                                            }
                                        }
                                    } else {
                                        $rule->addChild('hip-profiles');
                                        $rule->{'hip-profiles'}->addChild('member', 'any');
                                    }
                                    $getCategory = $projectdb->query("SELECT name FROM security_rules_categories WHERE rule_lid='$lid';");
                                    if ($getCategory->num_rows > 0) {
                                        $rule->addChild('category');
                                        while ($k = $getCategory->fetch_object()) {
                                            $rule->category->addChild('member', $k->name);
                                        }
                                    } else {
                                        $rule->addChild('category');
                                        $rule->category->addChild('member', 'any');
                                    }
                                    $rule->addChild('action', $data2->action);
                                    if ($data2->log_start == 1) {
                                        $rule->addChild('log-start', 'yes');
                                    }
                                    if ($data2->log_end == 1) {
                                        $rule->addChild('log-end', 'yes');
                                    }
                                    else{
                                        $rule->addChild('log-end', 'no');
                                    }
                                    if ($data2->disabled == 1) {
                                        $rule->addChild('disabled', 'yes');
                                    } else {
                                        //$rule->addChild('disabled', 'no');
                                    }
                                    if ($data2->negate_source == 1) {
                                        $rule->addChild('negate-source', 'yes');
                                    } else {
                                        //$rule->addChild('negate-source', 'no');
                                    }
                                    if ($data2->negate_destination == 1) {
                                        $rule->addChild('negate-destination', 'yes');
                                    } else {
                                        //$rule->addChild('negate-destination', 'no');
                                    }
                                    if ($data2->description != "") {
                                        $rule->addChild('description');
                                        $rule->description = $data2->description;
                                    }
                                    if ($data2->schedule != "") {
                                        $rule->addChild('schedule', $data2->schedule);
                                    }
                                    if ($data2->log_forwarding != "") {
                                        $rule->addChild('log-setting', $data2->log_forwarding);
                                    }
                                    if ($data2->qos != "None") {
                                        if($version >=7){
                                            $rule->addChild('qos');
                                            $rule->qos->addChild('marking');
                                            $rule->qos->marking->addChild($data2->qos, $data2->qos_value);
                                        }elseif($data2->qos == "ip-dscp" || $data2->qos == "ip-precedence"){
                                            $rule->addChild('qos');
                                            $rule->qos->addChild('marking');
                                            $rule->qos->marking->addChild($data2->qos, $data2->qos_value);
                                        }
                                    }
                                    if ($data2->profile_type != "None") {
                                        $rule->addChild('profile-setting');
                                        if ($data2->profile_type == "group") {
                                            $profile = $rule->{'profile-setting'}->addChild('group');
                                            $getProfiles = $projectdb->query("SELECT member_lid,table_name FROM security_rules_profiles WHERE rule_lid='$lid';");
                                            if ($getProfiles->num_rows > 0) {
                                                while ($k = $getProfiles->fetch_object()) {
                                                    $getMember = $projectdb->query("SELECT name FROM $k->table_name WHERE id='$k->member_lid';");
                                                    if ($getMember->num_rows > 0) {
                                                        while ($kk = $getMember->fetch_object()) {
                                                            $profile->addChild('member', $kk->name);
                                                        }
                                                    }
                                                }
                                            }
                                        } else {
                                            $profile = $rule->{'profile-setting'}->addChild('profiles');
                                            $getProfiles = $projectdb->query("SELECT member_lid,table_name FROM security_rules_profiles WHERE rule_lid='$lid';");
                                            if ($getProfiles->num_rows > 0) {
                                                while ($k = $getProfiles->fetch_object()) {
                                                    $getMember = $projectdb->query("SELECT name,type FROM $k->table_name WHERE id='$k->member_lid';");
                                                    if ($getMember->num_rows > 0) {
                                                        while ($kk = $getMember->fetch_object()) {
                                                            $thetype = $kk->{'type'};
                                                            $theprofiles = $profile->addChild($thetype);
                                                            $theprofiles->addChild('member', $kk->name);
                                                        }
                                                    } else {
                                                        $getMember = $projectdb->query("SELECT name,type FROM $k->table_name WHERE source=0 AND id='$k->member_lid';");
                                                        if ($getMember->num_rows > 0) {
                                                            while ($kk = $getMember->fetch_object()) {
                                                                $thetype = $kk->{'type'};
                                                                $theprofiles = $profile->addChild($thetype);
                                                                $theprofiles->addChild('member', $kk->name);
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    $getTAG = $projectdb->query("SELECT member_lid,table_name FROM security_rules_tag WHERE rule_lid='$lid';");
                                    if ($getTAG->num_rows > 0) {
                                        $rule->addChild('tag');
                                        while ($k = $getTAG->fetch_object()) {
                                            $getMember = $projectdb->query("SELECT name FROM $k->table_name WHERE id='$k->member_lid';");
                                            if ($getMember->num_rows > 0) {
                                                while ($kk = $getMember->fetch_object()) {
                                                    $rule->{'tag'}->addChild('member', $kk->name);
                                                }
                                            }
                                        }
                                    }
                                    if ($data2->target != "") {
                                        libxml_use_internal_errors(true);
                                        $xml_append = simplexml_load_string($data2->target);
                                        if ($xml_append) {
                                            SimpleXMLElement_append($rule, $xml_append);
                                        }
                                    }
                                }
                            }
                        } else {
                            #DELETE RULES
                            if (isset($xpath->{$pvalue}->security)) {
                                $SA = $xpath->$pvalue->xpath("security");
                                unset($SA[0][0]);
                            }
                        }

                        # NAT
                        $getPolicies = $projectdb->query("SELECT id,position,name,description,target,disabled,vsys,lid,tp_sat_bidirectional,op_zone_to,op_to_interface,is_dat,op_service_lid,op_service_table,tp_sat_type,tp_sat_address_type,tp_sat_interface,tp_sat_ipaddress,tp_dat_port,tp_dat_address_lid,tp_dat_address_table,preorpost,tag,active_active_device_binding,nat_type,tp_sat_interface_fallback,tp_sat_ipaddress_fallback,tp_fallback_type FROM nat_rules WHERE source='$source' AND vsys='$vsys' AND preorpost='$preorpost' ORDER BY position ASC;");
                        if ($getPolicies->num_rows > 0) {
                            if (!isset($xpath->{$pvalue})) {
                                $xpath->addChild($pvalue);
                            }
                            if (!isset($xpath->{$pvalue}->nat)) {
                                $xpath->{$pvalue}->addChild('nat');
                            }
                            if (!isset($xpath->$pvalue->nat->rules)) {
                                $xpath->$pvalue->nat->addChild('rules');
                            } else {
                                #DELETE RULES
                                $SA = $xpath->$pvalue->nat->xpath("rules");
                                unset($SA[0][0]);
                                $xpath->$pvalue->nat->addChild('rules');
                            }
                            while ($data2 = $getPolicies->fetch_object()) {
                                $myname = $data2->name;
                                $lid = $data2->id;
                                if ($xpath->xpath("/$pvalue/nat/rules/entry[@name='$myname']") == null) {
                                    $rule = $xpath->$pvalue->nat->rules->addChild('entry');
                                    $rule->addAttribute('name', $myname);
                                    if ($data2->tp_sat_type == "dynamic-ip") {
                                        $rule->addChild('source-translation');
                                        $stnat = $rule->{'source-translation'}->addChild('dynamic-ip');
                                        if ($data2->tp_fallback_type == "translated-address") {
                                            $getAddr = $projectdb->query("SELECT member_lid,table_name FROM nat_rules_translated_address_fallback WHERE rule_lid='$lid' ;");
                                            if ($getAddr->num_rows > 0) {
                                                $stnat->addChild('fallback');
                                                $stnat->fallback->addChild('translated-address');
                                                while ($getAddrData = $getAddr->fetch_object()) {
                                                    $getAddrName = $projectdb->query("SELECT name FROM $getAddrData->table_name WHERE id='$getAddrData->member_lid';");
                                                    if ($getAddrName->num_rows == 1) {
                                                        $getAddrNameData = $getAddrName->fetch_object();
                                                        $stnat->fallback->{'translated-address'}->addChild('member', $getAddrNameData->name);
                                                    }
                                                }
                                            }
                                        } elseif ($data2->tp_fallback_type == "interface-address") {
                                            $stnat->addChild('fallback');
                                            $stnat->fallback->addChild('interface-address');
                                            if ($data2->tp_sat_interface_fallback != "") {
                                                $stnat->fallback->{'interface-address'}->addChild('interface', $data2->tp_sat_interface_fallback);
                                            }
                                            if ($data2->tp_sat_ipaddress_fallback != "") {
                                                $stnat->fallback->{'interface-address'}->addChild('ip', $data2->tp_sat_ipaddress_fallback);
                                            }
                                        }
                                        $getAddr = $projectdb->query("SELECT member_lid,table_name FROM nat_rules_translated_address WHERE rule_lid='$lid';");
                                        if ($getAddr->num_rows > 0) {
                                            $stnat->addChild('translated-address');
                                            while ($getAddrData = $getAddr->fetch_object()) {
                                                $getAddrName = $projectdb->query("SELECT name FROM $getAddrData->table_name WHERE id='$getAddrData->member_lid';");
                                                if ($getAddrName->num_rows == 1) {
                                                    $getAddrNameData = $getAddrName->fetch_object();
                                                    $stnat->{'translated-address'}->addChild('member', $getAddrNameData->name);
                                                }
                                            }
                                        }
                                    } elseif ($data2->tp_sat_type == "dynamic-ip-and-port") {
                                        $rule->addChild('source-translation');
                                        $stnat = $rule->{'source-translation'}->addChild('dynamic-ip-and-port');
                                        if ($data2->tp_sat_address_type == "interface-address") {
                                            $stnat->addChild('interface-address');
                                            $stnat->{'interface-address'}->addChild('interface', $data2->tp_sat_interface);
                                            if (($data2->tp_sat_ipaddress != "") AND ($data2->tp_sat_ipaddress != "None")) {
                                                $stnat->{'interface-address'}->addChild('ip', $data2->tp_sat_ipaddress);
                                            }
                                        } else {
                                            $getAddr = $projectdb->query("SELECT member_lid,table_name FROM nat_rules_translated_address WHERE rule_lid='$lid';");
                                            if ($getAddr->num_rows > 0) {
                                                $stnat->addChild('translated-address');
                                                while ($getAddrData = $getAddr->fetch_object()) {
                                                    $getAddrName = $projectdb->query("SELECT name FROM $getAddrData->table_name WHERE id='$getAddrData->member_lid';");
                                                    if ($getAddrName->num_rows == 1) {
                                                        $getAddrNameData = $getAddrName->fetch_object();
                                                        $stnat->{'translated-address'}->addChild('member', $getAddrNameData->name);
                                                    }
                                                }
                                            }
                                        }
                                    } elseif ($data2->tp_sat_type == "static-ip") {
                                        $rule->addChild('source-translation');
                                        $stnat = $rule->{'source-translation'}->addChild('static-ip');
                                        if ($data2->tp_sat_bidirectional == 1) {
                                            $stnat->addChild('bi-directional', 'yes');
                                        } else {
                                            $stnat->addChild('bi-directional', 'no');
                                        }
                                        $getAddr = $projectdb->query("SELECT table_name,member_lid FROM nat_rules_translated_address WHERE rule_lid='$lid';");
                                        if ($getAddr->num_rows == 1) {
                                            $getAddrData = $getAddr->fetch_object();
                                            $getAddrName = $projectdb->query("SELECT name FROM $getAddrData->table_name WHERE id='$getAddrData->member_lid';");
                                            if ($getAddrName->num_rows == 1) {
                                                $getAddrNameData = $getAddrName->fetch_assoc();
                                                $stnat->addChild('translated-address', $getAddrNameData['name']);
                                            }
                                        }
                                    }
                                    if ($data2->is_dat == 1) {
                                        $dtnat = $rule->addChild('destination-translation');
                                        if (($data2->tp_dat_address_lid == 0) AND ( $data2->tp_dat_address_table == "")) {
                                            
                                        } else {
                                            $getAddr = $projectdb->query("SELECT name FROM $data2->tp_dat_address_table WHERE id='$data2->tp_dat_address_lid';");
                                            if ($getAddr->num_rows == 1) {
                                                $getAddrData = $getAddr->fetch_object();
                                                $dtnat->addChild('translated-address', $getAddrData->name);
                                            }
                                        }
                                        if ($data2->tp_dat_port != 0) {
                                            $dtnat->addChild('translated-port', $data2->tp_dat_port);
                                        }
                                    }
                                    if ($data2->op_zone_to != "") {
                                        $rule->addChild('to');
                                        $rule->to->addChild('member', $data2->op_zone_to);
                                    } else {
                                        $rule->addChild('to');
                                        $rule->to->addChild('member', 'any');
                                    }
                                    $getFrom = $projectdb->query("SELECT name FROM nat_rules_from WHERE rule_lid='$lid';");
                                    if ($getFrom->num_rows > 0) {
                                        $rule->addChild('from');
                                        while ($k = $getFrom->fetch_object()) {
                                            $rule->from->addChild('member', $k->name);
                                        }
                                    } else {
                                        $rule->addChild('from');
                                        $rule->from->addChild('member', 'any');
                                    }
                                    $getSource = $projectdb->query("SELECT member_lid,table_name FROM nat_rules_src WHERE rule_lid='$lid';");
                                    if ($getSource->num_rows > 0) {
                                        $rule->addChild('source');
                                        while ($k = $getSource->fetch_object()) {
//                                            if (($k->table_name == "regions") OR ( $k->table_name == "shared_regions") OR ( $k->table_name == "default_regions") OR ( $k->table_name == "external_list") OR ( $k->table_name == "shared_external_list")) {
//                                                $thename = "name";
//                                            } else {
//                                                $thename = "name_ext";
//                                            }
//                                            if ($k->table_name == "default_regions") {
//                                                $getMember = $projectdb->query("SELECT $thename FROM $k->table_name WHERE id='$k->member_lid';");
//                                            } else {
//                                                $getMember = $projectdb->query("SELECT $thename FROM $k->table_name WHERE id='$k->member_lid';");
//                                            }
                                            $getMember = $projectdb->query("SELECT name FROM $k->table_name WHERE id='$k->member_lid';");
                                            if ($getMember->num_rows > 0) {
                                                while ($kk = $getMember->fetch_object()) {
                                                    $rule->source->addChild('member', $kk->name);
                                                }
                                            }
                                        }
                                    } else {
                                        $rule->addChild('source');
                                        $rule->source->addChild('member', 'any');
                                    }
                                    $getDestination = $projectdb->query("SELECT member_lid,table_name FROM nat_rules_dst WHERE rule_lid='$lid';");
                                    if ($getDestination->num_rows > 0) {
                                        $rule->addChild('destination');
                                        while ($k = $getDestination->fetch_object()) {
//                                            if (($k->table_name == "regions") OR ( $k->table_name == "shared_regions") OR ( $k->table_name == "default_regions") OR ( $k->table_name == "external_list") OR ( $k->table_name == "shared_external_list")) {
//                                                $thename = "name";
//                                            } else {
//                                                $thename = "name_ext";
//                                            }
//                                            if ($k->table_name == "default_regions") {
//                                                $getMember = $projectdb->query("SELECT $thename FROM $k->table_name WHERE id='$k->member_lid';");
//                                            } else {
//                                                $getMember = $projectdb->query("SELECT $thename FROM $k->table_name WHERE id='$k->member_lid';");
//                                            }
                                            $getMember = $projectdb->query("SELECT name FROM $k->table_name WHERE id='$k->member_lid';");
                                            if ($getMember->num_rows > 0) {
                                                while ($kk = $getMember->fetch_object()) {
                                                    $rule->destination->addChild('member', $kk->name);
                                                }
                                            }
                                        }
                                    } else {
                                        $rule->addChild('destination');
                                        $rule->destination->addChild('member', 'any');
                                    }
                                    if (($data2->op_service_table != "") AND ( $data2->op_service_lid != "")) {
                                        $getsrv = $projectdb->query("SELECT name FROM $data2->op_service_table WHERE id='$data2->op_service_lid';");
                                        if ($getsrv->num_rows==1){
                                            $getsrvdata = $getsrv->fetch_assoc();
                                            $rule->addChild('service', $getsrvdata['name']);
                                        }
                                    } else {
                                        $rule->addChild('service', 'any');
                                    }
                                    if ($data2->op_to_interface != "") {
                                        $rule->addChild('to-interface', $data2->op_to_interface);
                                    }
                                    if ($data2->disabled == 1) {
                                        $rule->addChild('disabled', 'yes');
                                    } else {
                                        //$rule->addChild('disabled', 'no');
                                    }
                                    if ($data2->nat_type != "") {
                                        $rule->addChild('nat-type', $data2->nat_type);
                                    } else {
                                        $rule->addChild('nat-type', 'ipv4');
                                    }
                                    $getTAG = $projectdb->query("SELECT member_lid,table_name FROM nat_rules_tag WHERE rule_lid='$lid';");
                                    if ($getTAG->num_rows > 0) {
                                        $rule->addChild('tag');
                                        while ($k = $getTAG->fetch_object()) {
                                            $getMember = $projectdb->query("SELECT name FROM $k->table_name WHERE id='$k->member_lid';");
                                            if ($getMember->num_rows > 0) {
                                                while ($kk = $getMember->fetch_object()) {
                                                    $rule->{'tag'}->addChild('member', $kk->name);
                                                }
                                            }
                                        }
                                    }
                                    if ($data2->target != "") {
                                        libxml_use_internal_errors(true);
                                        $xml_append = simplexml_load_string($data2->target);
                                        if ($xml_append) {
                                            SimpleXMLElement_append($rule, $xml_append);
                                        }
                                    }
                                    if ($data2->description != "") {
                                        $rule->addChild('description');
                                        $rule->description = $data2->description;
                                    }
                                    if ($data2->active_active_device_binding != "") {
                                        $rule->addChild('active-active-device-binding', $data2->active_active_device_binding);
                                    }
                                }
                            }
                        } else {
                            #DELETE RULES
                            if (isset($xpath->$pvalue->nat)) {
                                $SA = $xpath->$pvalue->xpath("nat");
                                unset($SA[0][0]);
                            }
                        }

                        # APPLICATION OVERRIDE
                        $getPolicies = $projectdb->query("SELECT position,name,negate_source,negate_destination,description,disabled,id,target,protocol,app_id,app_table,port FROM appoverride_rules WHERE source='$source' AND vsys='$vsys' AND preorpost='$preorpost' ORDER BY position ASC;");
                        if ($getPolicies->num_rows > 0) {
                            if (!isset($xpath->{$pvalue})) {
                                $xpath->addChild($pvalue);
                            }

                            if (!isset($xpath->{$pvalue}->{'application-override'})) {
                                $xpath->{$pvalue}->addChild('application-override');
                            }

                            if (!isset($xpath->{$pvalue}->{'application-override'}->rules)) {
                                $xpath->{$pvalue}->{'application-override'}->addChild('rules');
                            } else {
                                #DELETE RULES
                                $SA = $xpath->$pvalue->{'application-override'}->xpath("rules");
                                unset($SA[0][0]);
                                $xpath->{$pvalue}->{'application-override'}->addChild('rules');
                            }

                            while ($data2 = $getPolicies->fetch_object()) {
                                $myname = $data2->name;
                                $lid = $data2->id;
                                if ($xpath->xpath("/$pvalue/application-override/rules/entry[@name='$myname']") == null) {
                                    $rule = $xpath->$pvalue->{'application-override'}->rules->addChild('entry');
                                    $rule->addAttribute('name', $myname);
                                    $getFrom = $projectdb->query("SELECT name FROM appoverride_rules_from WHERE rule_lid='$lid';");
                                    if ($getFrom->num_rows > 0) {
                                        $rule->addChild('from');
                                        while ($k = $getFrom->fetch_object()) {
                                            $rule->from->addChild('member', $k->name);
                                        }
                                    } else {
                                        $rule->addChild('from');
                                        $rule->from->addChild('member', 'any');
                                    }
                                    $getTo = $projectdb->query("SELECT name FROM appoverride_rules_to WHERE rule_lid='$lid' ;");
                                    if ($getTo->num_rows > 0) {
                                        $rule->addChild('to');
                                        while ($k = $getTo->fetch_object()) {
                                            $rule->to->addChild('member', $k->name);
                                        }
                                    } else {
                                        $rule->addChild('to');
                                        $rule->to->addChild('member', 'any');
                                    }
                                    $getSource = $projectdb->query("SELECT member_lid,table_name FROM appoverride_rules_src WHERE rule_lid='$lid';");
                                    if ($getSource->num_rows > 0) {
                                        $rule->addChild('source');
                                        while ($k = $getSource->fetch_object()) {
//                                            if (($k->table_name == "regions") OR ( $k->table_name == "shared_regions") OR ( $k->table_name == "default_regions") OR ( $k->table_name == "external_list") OR ( $k->table_name == "shared_external_list")) {
//                                                $thename = "name";
//                                            } else {
//                                                $thename = "name_ext";
//                                            }
//                                            if ($k->table_name == "default_regions") {
//                                                $getMember = $projectdb->query("SELECT $thename FROM $k->table_name WHERE id='$k->member_lid';");
//                                            } else {
//                                                $getMember = $projectdb->query("SELECT $thename FROM $k->table_name WHERE id='$k->member_lid';");
//                                            }
                                            $getMember = $projectdb->query("SELECT name FROM $k->table_name WHERE id='$k->member_lid';");
                                            if ($getMember->num_rows > 0) {
                                                while ($kk = $getMember->fetch_object()) {
                                                    $rule->source->addChild('member', $kk->name);
                                                }
                                            }
                                        }
                                    } else {
                                        $rule->addChild('source');
                                        $rule->source->addChild('member', 'any');
                                    }
                                    $getDestination = $projectdb->query("SELECT member_lid,table_name FROM appoverride_rules_dst WHERE rule_lid='$lid' ;");
                                    if ($getDestination->num_rows > 0) {
                                        $rule->addChild('destination');
                                        while ($k = $getDestination->fetch_object()) {
//                                            if (($k->table_name == "regions") OR ( $k->table_name == "shared_regions") OR ( $k->table_name == "default_regions") OR ( $k->table_name == "external_list") OR ( $k->table_name == "shared_external_list")) {
//                                                $thename = "name";
//                                            } else {
//                                                $thename = "name_ext";
//                                            }
//                                            if ($k->table_name == "default_regions") {
//                                                $getMember = $projectdb->query("SELECT $thename FROM $k->table_name WHERE id='$k->member_lid';");
//                                            } else {
//                                                $getMember = $projectdb->query("SELECT $thename FROM $k->table_name WHERE id='$k->member_lid';");
//                                            }
                                            $getMember = $projectdb->query("SELECT name FROM $k->table_name WHERE id='$k->member_lid';");
                                            if ($getMember->num_rows > 0) {
                                                while ($kk = $getMember->fetch_object()) {
                                                    $rule->destination->addChild('member', $kk->name);
                                                }
                                            }
                                        }
                                    } else {
                                        $rule->addChild('destination');
                                        $rule->destination->addChild('member', 'any');
                                    }

                                    $getAPP = $projectdb->query("SELECT name FROM $data2->app_table WHERE id='$data2->app_id';");
                                    if ($getAPP->num_rows == 1) {
                                        $k = $getAPP->fetch_object();
                                        $rule->addChild('application', $k->name);
                                    }


                                    if ($data2->disabled == 1) {
                                        $rule->addChild('disabled', 'yes');
                                    } else {
                                        //$rule->addChild('disabled', 'no');
                                    }
                                    if ($data2->negate_source == 1) {
                                        $rule->addChild('negate-source', 'yes');
                                    } else {
                                        //$rule->addChild('negate-source', 'no');
                                    }
                                    if ($data2->negate_destination == 1) {
                                        $rule->addChild('negate-destination', 'yes');
                                    } else {
                                        //$rule->addChild('negate-destination', 'no');
                                    }
                                    if ($data2->description != "") {
                                        $rule->addChild('description');
                                        $rule->description = $data2->description;
                                    }
                                    $rule->addChild('protocol', $data2->protocol);
                                    $rule->addChild('port', $data2->port);
                                    $getTAG = $projectdb->query("SELECT member_lid,table_name FROM security_rules_tag WHERE rule_lid='$lid';");
                                    if ($getTAG->num_rows > 0) {
                                        $rule->addChild('tag');
                                        while ($k = $getTAG->fetch_object()) {
                                            $getMember = $projectdb->query("SELECT name FROM $k->table_name WHERE id='$k->member_lid';");
                                            if ($getMember->num_rows > 0) {
                                                while ($kk = $getMember->fetch_object()) {
                                                    $rule->{'tag'}->addChild('member', $kk->name);
                                                }
                                            }
                                        }
                                    }
                                    if ($data2->target != "") {
                                        libxml_use_internal_errors(true);
                                        $xml_append = simplexml_load_string($data2->target);
                                        if ($xml_append) {
                                            SimpleXMLElement_append($rule, $xml_append);
                                        }
                                    }
                                }
                            }
                        } else {
                            #DELETE RULES
                            if (isset($xpath->{$pvalue}->{'application-override'})) {
                                $SA = $xpath->$pvalue->xpath("application-override");
                                unset($SA[0][0]);
                            }
                        }


                        # OTHER RULES
                        $getPolicies = $projectdb->query("SELECT id,type,xml FROM other_rules WHERE source='$source' AND vsys='$vsys' AND preorpost='$preorpost' ORDER BY id ASC;");
                        if ($getPolicies->num_rows > 0) {
                            if (!isset($xpath->{$pvalue})) {
                                $xpath->addChild($pvalue);
                            }
                            while ($data2 = $getPolicies->fetch_assoc()) {
                                $lid = $data2['id'];
                                $mytype = $data2['type'];
                                $xmlfield = $data2['xml'];

                                if (!isset($xpath->$pvalue->$mytype)) {
                                    $xpath->$pvalue->addChild($mytype);
                                }

                                if (!isset($xpath->$pvalue->$mytype->rules)) {
                                    
                                } else {
                                    #DELETE RULES
                                    $SA = $xpath->$pvalue->$mytype->xpath("rules");
                                    unset($SA[0][0]);
                                }
                                $xml_append = simplexml_load_string($xmlfield);
                                $theProfiles = $xpath->$pvalue->$mytype;
                                SimpleXMLElement_append($theProfiles, $xml_append);
                            }
                        }
                        
                        #Check if the pre or post are empty to remove it
                        if ( (!isset($xpath->$pvalue->security->rules)) AND (!isset($xpath->$pvalue->{'default-security-rules'}->rules)) AND (!isset($xpath->$pvalue->nat->rules)) AND (!isset($xpath->$pvalue->{'application-override'}->rules)) AND (!isset($xpath->$pvalue->decryption->rules)) AND (!isset($xpath->$pvalue->pbf)) AND (!isset($xpath->$pvalue->dos)) AND (!isset($xpath->$pvalue->qos)) AND (!isset($xpath->$pvalue->{'captive-portal'}->rules)) ){
                            unset($xpath->$pvalue);
                        }
                    }

                    # Fi
                }
            }

            #Print Output
            header('Content-Type: text/xml');
            $dom = new DOMDocument('1.0');
            $dom->preserveWhiteSpace = false;
            $dom->formatOutput = true;
            $dom->loadXML($xml->asXML());
            $fileOut = USERSPACE_PATH."/projects/" . $project . "/MT-" . $project . ".xml";
            $dom->save($fileOut);
            #Remove first line
            $contents = file_get_contents($fileOut);
            $first_line = substr($contents, 0, 32);
            file_put_contents($fileOut, substr($contents, 22));

            # Set commands
            if (file_exists($fileOut)) {
                $setfile = USERSPACE_PATH."/projects/" . $project . "/MT-" . $project . "-set.txt";
                shell_exec(INC_ROOT."/libs/pan-python/bin/panconf.py --config " . escapeshellarg($fileOut) . " --set >" . escapeshellarg($setfile));
            }

            #Create ZIP File
            if (file_exists(USERSPACE_PATH."/projects/" . $project . "/MT-" . $project . ".zip")) {
                unlink(USERSPACE_PATH."/projects/" . $project . "/MT-" . $project . ".zip");
            }
            $files_to_zip = array($fileOut, $setfile);
            $result = create_zip($files_to_zip, USERSPACE_PATH."/projects/" . $project . "/MT-" . $project . ".zip");

            update_progress($project, '1.00', 'Done.');

            echo json_encode(array("success" => true));
        }
    }
} 
elseif ($action == "get") {
    if ($type == "downloads") {
        $path = USERSPACE_PATH."/projects/" . $project . "/";
        $dirrule = opendir($path);
        $files = array();
        while ($config_filename = readdir($dirrule)) {
            if (preg_match("/^MT/", $config_filename)) {
                $config_path = $path . $config_filename;
                $filename = $config_filename;
                $files[] = '{"name":"' . $filename . '","filename":"' . $config_path . '"}';
            }
        }
        echo '{downloads:[' . implode(",", $files) . ']}';
    }
}
?>