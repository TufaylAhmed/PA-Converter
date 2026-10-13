<?php

# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

//require_once INC_ROOT.'/bin/Authentication.php';
//User management control
require_once INC_ROOT.'/userManager/start.php';
include INC_ROOT.'/bin/authentication/sessionControl.php';

require_once INC_ROOT.'/libs/shared.php';
require_once INC_ROOT.'/libs/xmlapi.php';
require_once INC_ROOT.'/libs/database.php';
require_once INC_ROOT.'/userManager/API/projects/manageSettings.php';
require_once INC_ROOT.'/libs/projectdb.php';

require_once INC_ROOT.'/bin/messaging/MessageSender.php';

$filtersrc = "";
$filterbcDG = "";
$filterbcTemplate = "";

include INC_ROOT.'/bin/middleware_sanitizer.php';

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $action     = (string)  (isset($_GET['action'])     ? $_GET['action'] : '');
        $type       = (string)  (isset($_GET['type'])       ? $_GET['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_GET['project'])    ? $_GET['project'] : '');
        $filtersrc  = (string)  (isset($_GET['filtersrc'])  ? $_GET['filtersrc'] : '');
        $filterbcDG  = (string)  (isset($_GET['filterbcDG'])  ? $_GET['filterbcDG'] : '');
        $filterbcTemplate  = (string)  (isset($_GET['filterbcTemplate'])  ? $_GET['filterbcTemplate'] : '');
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

$projectdb = selectDatabase($project);

$action = $projectdb->real_escape_string($action);
$type = $projectdb->real_escape_string($type);
$project = $projectdb->real_escape_string($project);
$filtersrc = $projectdb->real_escape_string($filtersrc);
$filterbcDG = $projectdb->real_escape_string($filterbcDG);
$filterbcTemplate = $projectdb->real_escape_string($filterbcTemplate);

$params['project'] = $project;

global $app;
$user = $app->container->sentinel->getUser();
$user_id = $user->id;

if ($action == "get") {
    if(!checkProjectRights($project,'view')){
        echo '{"total":"0","rows":' . json_encode(array()) . '}';
        return;
    }
    if ($type == "views") {

        $getDM = $projectdb->query("SELECT vsys, id, ispanorama, version FROM device_mapping GROUP BY filename");
        if ($getDM->num_rows == 1) {
            $getDMData = $getDM->fetch_assoc();
            if ($getDMData['ispanorama'] == 0) {
                $newsource = $getDMData['id'];
                $projectdb->query("UPDATE config_views SET source='$newsource';");
            } else {
                $newsource = $getDMData['id'];
                $projectdb->query("UPDATE config_views SET source='$newsource';");
            }
            $version = $getDMData['version'];
            $version_parser = getVersion($version);
            $projectdb->query("UPDATE config_views SET version = '$version_parser';");
        }
        
        $getAll = $projectdb->query("SELECT id, view, panorama_devicegroup, panorama_rules, panos_vsys, source, panorama_template, version FROM config_views;");
        $count = $getAll->num_rows;
        if ($getAll->num_rows>0){
            while ($data = $getAll->fetch_object()) {
                $myData[] = $data;
            }
        }
        if ($count == 0) {
           $myData = "";
        }    
        echo '{"total":"' . $count . '","rows":' . json_encode($myData) . '}';
    } 
    elseif ($type == "device_mapping") {
        $getAll = $projectdb->query("SELECT id,device,ispanorama,active,version,vsys,filename,map_devicegroup,map_vsys FROM device_mapping;");
        $count = $getAll->num_rows;
        while ($data = $getAll->fetch_object()) {
            $myData[] = $data;
        }
        if ($count == 0) {
            $myData = "";
        }
        echo '{"total":"' . $count . '","rows":' . json_encode($myData) . '}';
    } 
    elseif ($type == "sources_tree") {
        $x = 0;
        $exec = array();

        if ( (isset($filtersrc)) AND ($filtersrc!="all") ){
            $getAll = $projectdb->query("SELECT id,device,ispanorama,active,version,vsys,filename,map_devicegroup,map_vsys,vendor FROM device_mapping WHERE  baseconfig=0 AND map_vsys='' AND map_devicegroup='' AND filename='$filtersrc' GROUP BY filename;");
        }
        else{
            $getAll = $projectdb->query("SELECT id,device,ispanorama,active,version,vsys,filename,map_devicegroup,map_vsys,vendor FROM device_mapping WHERE  baseconfig=0 AND map_vsys='' AND map_devicegroup='' GROUP BY filename;");
            //echo "1. SELECT id,device,ispanorama,active,version,vsys,filename,map_devicegroup,map_vsys,vendor FROM device_mapping WHERE  baseconfig=0 AND map_vsys='' AND map_devicegroup='' GROUP BY filename;\n";
        }
        if ($getAll->num_rows > 0) {
            $exec = array();
            while ($data = $getAll->fetch_assoc()) {
                $onlyone = true;
                $filename = $data['filename'];
                $vendor = $data['vendor'];
                $source = $data['id'];
                $devicegroup = $data['device'];
                $isPanorama = $data['ispanorama'];
                $active = $data['active'];
                if ($vendor == "Paloalto Networks") {
                    $vendor_icon = "icon-panw";
                }
                elseif ($vendor == "Checkpoint") {
                    $vendor_icon = "icon-chkpt";
                }
                elseif ($vendor == "Juniper") {
                    $vendor_icon = "icon-juniper";
                }
                elseif ($vendor == "Screenos") {
                    $vendor_icon = "icon-juniper";
                }
                elseif ($vendor == "Snort") {
                    $vendor_icon = "icon-snort";
                }
                elseif ($vendor == "Sidewinder") {
                    $vendor_icon = "icon-sidewinder";
                }
                elseif ($vendor == "Cisco") {
                    $vendor_icon = "icon-cisco";
                }
                elseif ($vendor == "Fortinet") {
                    $vendor_icon = "icon-fortinet";
                }
                elseif ($vendor == "Watchguard") {
                    $vendor_icon = "icon-watchguard";
                }
                else{
                    $vendor_icon = "icon-panw";
                }

                $x++;

                if ($active == 0) {
                    $text = $filename . "<font color=red> (deactivated)</font>";
//                    $master = "{id:" . $x . ",text:'" . $text . "', value:'" . $filename . "', iconCls:'" . $vendor_icon . "',leaf:true, filename:'" . $filename . "'}";
                    $master = [
                        "id"        =>$x,
                        "text"      =>$text,
                        "value"     =>$filename,
                        "iconCls"   =>$vendor_icon,
                        "leaf"      =>true,
                        "filename"  =>$filename,
                        "isConfigRoot" => true
                    ];
                }
                else {
                    $text = $filename;
//                    $master = "{expanded:true, id:" . $x . ",text:'" . $text . "', value:'" . $filename . "', iconCls:'" . $vendor_icon . "',leaf:false, filename:'" . $filename . "', children:[";
                    $master = [
                        "expanded"=>true,
                        "id"=>$x,
                        "text"=>$text,
                        "value"=>$filename,
                        "iconCls"=>$vendor_icon,
                        "leaf"=>true,
                        "filename"=>$filename,
                        "isConfigRoot" => true

                    ];
                }

                if($isPanorama == 1){
                    //PANORAMA
                    //New

                    #Start to read configs
                    $echo1 = array();
                    $echo1_template = array();
                    $echo2_shared = array();
                    $shared_objects = array();
                    $shared_profiles = array();

                    # DEVICE GROUPS
                    $getVsys = $projectdb->query("SELECT vsys FROM devicegroups dg, device_mapping dm WHERE dg.device_mapping_id=dm.id AND filename='$filename' AND vsys!='shared';");
                    //echo "SELECT id, vsys FROM devicegroups dg, device_mapping dm WHERE dg.device_mapping_id=dm.id AND filename='$filename'";

                    if($getVsys->num_rows > 0){
                        while ($data2 = $getVsys->fetch_assoc()) {
                            $vsys = $data2['vsys'];
                            // $vsysid = $data2['id'];

                            $policies = array();
                            $objects = array();
                            $network = array();
                            $interfaces = array();
                            $zones = array();
                            $profiles = array();
                            $interface_management_profile = array();
                            $ipsec_tunnel = array();
                            $ike_gateways = array();
                            $ipsec_crypto_profiles = array();
                            $ike_crypto_profiles = array();
                            $monitor_profile = array();
                            $global_protect_app_ipsec_crypto_profiles = array();
                            $vlans = array();
                            $virtual_wires = array();

                            $echo2 = array();
                            $echo3 = array();

                            $responsepage = array();

                            # Objects
                            #Schedules
                            $getAddress = $projectdb->query("SELECT id FROM schedules WHERE source='$source' AND vsys='$vsys' LIMIT 1");
                            //echo "7. SELECT id FROM schedules WHERE source='$source' AND vsys='$vsys' LIMIT 1\n";
                            if ($getAddress->num_rows == 1) {
                                $x++;
                                $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='object' AND element='schedules' AND map_filename!='';");
                                if ($getTask->num_rows == 0) {
                                    $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='object' AND element='schedules';");
                                    $exec[] = "('$filename','$vsys','object','schedules','')";
//                                $objects[] = "{vsys:'" . $vsys . "',type:'object',element:'schedules', text:'Schedules', value:'schedules',leaf:true, iconCls:'icon-schedules',filename:'" . $filename . "'}";
                                    $objects[] = [
                                        "vsys"      =>$vsys,
                                        "type"      =>'object',
                                        "element"   =>'schedules',
                                        "text"      =>'Schedules',
                                        "value"     =>'schedules',
                                        "leaf"      =>true,
                                        "iconCls"   =>'icon-schedules',
                                        "filename"  =>$filename,
                                        "id"        =>$x
                                    ];
                                    $getAddress->free();
                                }
                            }
                            $getProfiles = $projectdb->query("SELECT name FROM profiles WHERE source='$source' AND vsys='$vsys' AND name!='strict' AND name!='default';");
                            if ($getProfiles->num_rows > 0) {
                                $x++;
                                $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='profiles' AND element='profiles' AND map_filename!='';");
                                if ($getTask->num_rows == 0) {
                                    $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='profiles' AND element='profiles';");
                                    $exec[] = "('$filename','$vsys','profiles','profiles','')";
//                                $profiles[] = "{vsys:'" . $vsys . "',type:'object',element:'profiles', text:'Security', value:'profiles',leaf:true, iconCls:'icon-profile_group',filename:'" . $filename . "'}";
                                    $profiles[] = [
                                        "vsys"      =>$vsys,
                                        "type"      =>'object',
                                        "element"   =>'profiles',
                                        "text"      =>'Security/Content',
                                        "value"     =>'profiles',
                                        "leaf"      =>true,
                                        "iconCls"   =>'icon-profile_group',
                                        "filename"  =>$filename,
                                        "id"        =>$x
                                    ];
                                    $getProfiles->free();
                                }
                            }
                            $getProfiles = $projectdb->query("SELECT name FROM log_settings WHERE source='$source' AND vsys='$vsys' AND type='profiles';");
                            if ($getProfiles->num_rows > 0) {
                                $x++;
                                $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='log_settings' AND element='log_settings' AND map_filename!='';");
                                if ($getTask->num_rows == 0) {
                                    $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='log_settings' AND element='log_settings';");
                                    $exec[] = "('$filename','$vsys','log_settings','log_settings','')";
//                                $profiles[] = "{vsys:'" . $vsys . "',type:'object',element:'log_settings', text:'Log Forwarding', value:'log_settings',leaf:true, iconCls:'icon-log_forwarding',filename:'" . $filename . "'}";
                                    $profiles[] = [
                                        "vsys"      =>$vsys,
                                        "type"      =>'object',
                                        "element"   =>'log_settings',
                                        "text"      =>'Log Forwarding',
                                        "value"     =>'log_settings',
                                        "leaf"      =>true,
                                        "iconCls"   =>'icon-log_forwarding',
                                        "filename"  =>$filename,
                                        "id"        =>$x
                                    ];
                                    $getProfiles->free();
                                }
                            }
                            $getProfiles = $projectdb->query("SELECT name FROM profiles_groups WHERE source='$source' AND vsys='$vsys';");
                            if ($getProfiles->num_rows > 0) {
                                $x++;
                                $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='profiles_groups' AND element='profiles_groups' AND map_filename!='';");
                                if ($getTask->num_rows == 0) {
                                    $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='profiles_groups' AND element='profiles_groups';");
                                    $exec[] = "('$filename','$vsys','profiles_groups','profiles_groups','')";
//                                $profiles[] = "{vsys:'" . $vsys . "',type:'object',element:'profiles_groups', text:'Security Group', value:'profiles_groups',leaf:true, iconCls:'icon-profile_group',filename:'" . $filename . "'}";
                                    $profiles[] = [
                                        "vsys"      =>$vsys,
                                        "type"      =>'object',
                                        "element"   =>'profiles_groups',
                                        "text"      =>'Security Group',
                                        "value"     =>'profiles_groups',
                                        "leaf"      =>true,
                                        "iconCls"   =>'icon-profile_group',
                                        "filename"  =>$filename,
                                        "id"        =>$x
                                    ];
                                    $getProfiles->free();
                                }
                            }
                            # Address
                            $getAddress = $projectdb->query("SELECT id FROM address WHERE source='$source' AND vsys='$vsys' LIMIT 1");
                            if ($getAddress->num_rows == 1) {
                                $x++;
                                $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='object' AND element='address' AND map_filename!='';");
                                if ($getTask->num_rows == 0) {
                                    $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='object' AND element='address';");
                                    $exec[] = "('$filename','$vsys','object','address','')";
//                                $objects[] = "{vsys:'" . $vsys . "',type:'object',element:'address', text:'Address', value:'address',leaf:true, iconCls:'icon-address',filename:'" . $filename . "'}";
                                    $objects[] = [
                                        "vsys"      =>$vsys,
                                        "type"      =>'object',
                                        "element"   =>'address',
                                        "text"      =>'Address',
                                        "value"     =>'address',
                                        "leaf"      =>true,
                                        "iconCls"   =>'icon-address',
                                        "filename"  =>$filename,
                                        "id"        =>$x
                                    ];
                                    $getAddress->free();
                                }
                            }
                            # Address Groups
                            $getAddressGroups = $projectdb->query("SELECT id FROM address_groups_id WHERE source='$source' AND vsys='$vsys' LIMIT 1");
                            if ($getAddressGroups->num_rows == 1) {
                                $x++;
                                $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='object' AND element='address_groups' AND map_filename!='';");
                                if ($getTask->num_rows == 0) {
                                    $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='object' AND element='address_groups';");
                                    $exec[] = "('$filename','$vsys','object','address_groups','')";
//                                $objects[] = "{vsys:'" . $vsys . "',type:'object',element:'address_groups', text:'Address-Groups', value:'address_groups_id',leaf:true,filename:'" . $filename . "', iconCls:'icon-address_groups'}";
                                    $objects[] = [
                                        "vsys"      =>$vsys,
                                        "type"      =>'object',
                                        "element"   =>'address_groups',
                                        "text"      =>'Address-Groups',
                                        "value"     =>'address_groups_id',
                                        "leaf"      =>true,
                                        "filename"  =>$filename,
                                        "iconCls"   =>'icon-address_groups',
                                        "id"        =>$x
                                    ];
                                    $getAddressGroups->free();
                                }
                            }
                            # Services
                            $getServices = $projectdb->query("SELECT id FROM services WHERE source='$source' AND vsys='$vsys' LIMIT 1");
                            if ($getServices->num_rows == 1) {
                                $x++;
                                $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='object' AND element='services' AND map_filename!='';");
                                if ($getTask->num_rows == 0) {
                                    $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='object' AND element='services';");
                                    $exec[] = "('$filename','$vsys','object','services','')";
//                                $objects[] = "{vsys:'" . $vsys . "',type:'object',element:'services', text:'Services', value:'services',leaf:true,filename:'" . $filename . "', iconCls:'icon-services'}";
                                    $objects[] = [
                                        "vsys"      =>$vsys,
                                        "type"      =>'object',
                                        "element"   =>'services',
                                        "text"      =>'Services',
                                        "value"     =>'services',
                                        "leaf"      =>true,
                                        "filename"  =>$filename,
                                        "iconCls"   =>'icon-services',
                                        "id"        =>$x
                                    ];
                                    $getServices->free();
                                }
                            }
                            # Services Groups
                            $getServicesGroups = $projectdb->query("SELECT id FROM services_groups_id WHERE source='$source' AND vsys='$vsys' LIMIT 1");
                            if ($getServicesGroups->num_rows == 1) {
                                $x++;
                                $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='object' AND element='services_groups' AND map_filename!='';");
                                if ($getTask->num_rows == 0) {
                                    $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='object' AND element='services_groups';");
                                    $exec[] = "('$filename','$vsys','object','services_groups','')";
//                                $objects[] = "{vsys:'" . $vsys . "',type:'object',element:'services_groups', text:'Services-Groups', value:'services_groups_id',leaf:true,filename:'" . $filename . "', iconCls:'icon-services_groups'}";
                                    $objects[] = [
                                        "vsys"      =>$vsys,
                                        "type"      =>'object',
                                        "element"   =>'services_groups',
                                        "text"      =>'Services-Groups',
                                        "value"     =>'services_groups_id',
                                        "leaf"      =>true,
                                        "filename"  =>$filename,
                                        "iconCls"   =>'icon-services_groups',
                                        "id"        =>$x
                                    ];
                                    $getServicesGroups->free();
                                }
                            }
                            # Regions
                            $getServicesGroups = $projectdb->query("SELECT id FROM regions WHERE source='$source' AND vsys='$vsys' LIMIT 1");
                            if ($getServicesGroups->num_rows == 1) {
                                $x++;
                                $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='object' AND element='regions' AND map_filename!='';");
                                if ($getTask->num_rows == 0) {
                                    $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='object' AND element='regions';");
                                    $exec[] = "('$filename','$vsys','object','regions','')";
//                                $objects[] = "{vsys:'" . $vsys . "',type:'object',element:'regions', text:'Regions', value:'regions',leaf:true,filename:'" . $filename . "', iconCls:'icon-regions'}";
                                    $objects[] = [
                                        "vsys"      =>$vsys,
                                        "type"      =>'object',
                                        "element"   =>'regions',
                                        "text"      =>'Regions',
                                        "value"     =>'regions',
                                        "leaf"      =>true,
                                        "filename"  =>$filename,
                                        "iconCls"   =>'icon-regions',
                                        "id"        =>$x
                                    ];
                                    $getServicesGroups->free();
                                }
                            }
                            # Applications
                            $getApps = $projectdb->query("SELECT id FROM applications WHERE source='$source' AND vsys='$vsys' LIMIT 1");
                            if ($getApps->num_rows == 1) {
                                $x++;
                                $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='object' AND element='applications' AND map_filename!='';");
                                if ($getTask->num_rows == 0) {
                                    $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='object' AND element='applications';");
                                    $exec[] = "('$filename','$vsys','object','applications','')";
//                                $objects[] = "{vsys:'" . $vsys . "',type:'object',element:'applications', text:'Applications', value:'applications',leaf:true,filename:'" . $filename . "', iconCls:'icon-applications'}";
                                    $objects[] = [
                                        "vsys"      =>$vsys,
                                        "type"      =>'object',
                                        "element"   =>'applications',
                                        "text"      =>'Applications',
                                        "value"     =>'applications',
                                        "leaf"      =>true,
                                        "filename"  =>$filename,
                                        "iconCls"   =>'icon-applications',
                                        "id"        =>$x
                                    ];
                                    $getApps->free();
                                }
                            }
                            # Application Filters
                            $getApps = $projectdb->query("SELECT id FROM applications_filters WHERE source='$source' AND vsys='$vsys' LIMIT 1");
                            if ($getApps->num_rows == 1) {
                                $x++;
                                $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='object' AND element='applications_filters' AND map_filename!='';");
                                if ($getTask->num_rows == 0) {
                                    $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='object' AND element='applications_filters';");
                                    $exec[] = "('$filename','$vsys','object','applications_filters','')";
//                                $objects[] = "{vsys:'" . $vsys . "',type:'object',element:'applications_filters', text:'Applications Filters', value:'applications_filters',leaf:true,filename:'" . $filename . "', iconCls:'icon-applications_filter'}";
                                    $objects[] = [
                                        "vsys"      =>$vsys,
                                        "type"      =>'object',
                                        "element"   =>'applications_filters',
                                        "text"      =>'Applications Filters',
                                        "value"     =>'applications_filters',
                                        "leaf"      =>true,
                                        "filename"  =>$filename,
                                        "iconCls"   =>'icon-applications_filter',
                                        "id"        =>$x
                                    ];
                                    $getApps->free();
                                }
                            }
                            # Applications Groups
                            $getApps = $projectdb->query("SELECT id FROM applications_groups_id WHERE source='$source' AND vsys='$vsys' LIMIT 1");
                            if ($getApps->num_rows == 1) {
                                $x++;
                                $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='object' AND element='applications_groups' AND map_filename!='';");
                                if ($getTask->num_rows == 0) {
                                    $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='object' AND element='applications_groups';");
                                    $exec[] = "('$filename','$vsys','object','applications_groups','')";
//                                $objects[] = "{vsys:'" . $vsys . "',type:'object',element:'applications_groups', text:'Applications-Groups', value:'applications_groups',leaf:true,filename:'" . $filename . "', iconCls:'icon-applications_groups'}";
                                    $objects[] = [
                                        "vsys"      =>$vsys,
                                        "type"      =>'object',
                                        "element"   =>'applications_groups',
                                        "text"      =>'Applications-Groups',
                                        "value"     =>'applications_groups_id',
                                        "leaf"      =>true,
                                        "filename"  =>$filename,
                                        "iconCls"   =>'icon-applications_groups',
                                        "id"        =>$x
                                    ];
                                    $getApps->free();
                                }
                            }
                            # Tags
                            $getApps = $projectdb->query("SELECT id FROM tag WHERE source='$source' AND vsys='$vsys' LIMIT 1");
                            if ($getApps->num_rows == 1) {
                                $x++;
                                $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='object' AND element='tag' AND map_filename!='';");
                                if ($getTask->num_rows == 0) {
                                    $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='object' AND element='tag';");
                                    $exec[] = "('$filename','$vsys','object','tag','')";
//                                $objects[] = "{vsys:'" . $vsys . "',type:'object',element:'tag', text:'Tags', value:'tag',leaf:true,filename:'" . $filename . "', iconCls:'icon-tags'}";
                                    $objects[] = [
                                        "vsys"      =>$vsys,
                                        "type"      =>'object',
                                        "element"   =>'tag',
                                        "text"      =>'Tags',
                                        "value"     =>'tag',
                                        "leaf"      =>true,
                                        "filename"  =>$filename,
                                        "iconCls"   =>'icon-tags',
                                        "id"        =>$x
                                    ];
                                    $getApps->free();
                                }
                            }

                            # Policies
                            # Security Rules
                            $getSecurity = $projectdb->query("SELECT id FROM security_rules WHERE source='$source' AND vsys='$vsys' LIMIT 1");
                            if ($getSecurity->num_rows == 1) {
                                $x++;
                                $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='policy' AND element='security' AND map_filename!='';");
                                if ($getTask->num_rows == 0) {
                                    $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='policy' AND element='security';");
                                    $exec[] = "('$filename','$vsys','policy','security','')";
//                                $policies[] = "{vsys:'" . $vsys . "',type:'policy',element:'security', text:'Security', value:'security',leaf:true,filename:'" . $filename . "', iconCls:'icon-securityrule'}";
                                    $policies[] = [
                                        "vsys"      =>$vsys,
                                        "type"      =>'policy',
                                        "element"   =>'security',
                                        "text"      =>'Security',
                                        "value"     =>'security',
                                        "leaf"      =>true,
                                        "filename"  =>$filename,
                                        "iconCls"   =>'icon-securityrule',
                                        "id"        =>$x
                                    ];
                                    $getSecurity->free();
                                }
                            }

                            # Nat Rules
                            $getNat = $projectdb->query("SELECT id FROM nat_rules WHERE source='$source' AND vsys='$vsys' LIMIT 1;");
                            if ($getNat->num_rows == 1) {
                                $x++;
                                $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='policy' AND element='nat' AND map_filename!='';");
                                if ($getTask->num_rows == 0) {
                                    $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='policy' AND element='nat';");
                                    $exec[] = "('$filename','$vsys','policy','nat','')";
//                                $policies[] = "{vsys:'" . $vsys . "',type:'policy',element:'nat', text:'Nat', value:'nat',leaf:true, filename:'" . $filename . "',iconCls:'icon-rulenat'}";
                                    $policies[] = [
                                        "vsys"      =>$vsys,
                                        "type"      =>'policy',
                                        "element"   =>'nat',
                                        "text"      =>'Nat',
                                        "value"     =>'nat',
                                        "leaf"      =>true,
                                        "filename"  =>$filename,
                                        "iconCls"   =>'icon-rulenat',
                                        "id"        =>$x
                                    ];
                                    $getNat->free();
                                }
                            }

                            # Application Override Rules
                            $getAppOverride = $projectdb->query("SELECT id FROM appoverride_rules WHERE source='$source' AND vsys='$vsys' LIMIT 1;");
                            if ($getAppOverride->num_rows == 1) {
                                $x++;
                                $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='policy' AND element='appoverride' AND map_filename!='';");
                                if ($getTask->num_rows == 0) {
                                    $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='policy' AND element='appoverride';");
                                    $exec[] = "('$filename','$vsys','policy','appoverride','')";
//                                $policies[] = "{vsys:'" . $vsys . "',type:'policy',element:'appoverride', text:'App Override', value:'appoverride',leaf:true, filename:'" . $filename . "',iconCls:'icon-appoverride'}";
                                    $policies[] = [
                                        "vsys"      =>$vsys,
                                        "type"      =>'policy',
                                        "element"   =>'appoverride',
                                        "text"      =>'App Override',
                                        "value"     =>'appoverride',
                                        "leaf"      =>true,
                                        "filename"  =>$filename,
                                        "iconCls"   =>'icon-appoverride',
                                        "id"        =>$x
                                    ];
                                    $getAppOverride->free();
                                }
                            }

                            /*$getOthers = $projectdb->query("SELECT id FROM other_rules WHERE source='$source' AND vsys='$vsys' LIMIT 1;");
                            if ($getOthers->num_rows == 1) {
                                $x++;
                                $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='policy' AND element='others' AND map_filename!='';");
                                if ($getTask->num_rows == 0) {
                                    $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='policy' AND element='others';");
                                    $exec[] = "('$filename','$vsys','policy','others','')";
//                                $policies[] = "{vsys:'" . $vsys . "',type:'policy',element:'others', text:'Other Policies', value:'others',leaf:true, filename:'" . $filename . "',iconCls:'icon-decryption'}";
                                    $policies[] = [
                                        "vsys"      =>$vsys,
                                        "type"      =>'policy',
                                        "element"   =>'others',
                                        "text"      =>'Other Policies',
                                        "value"     =>'others',
                                        "leaf"      =>true,
                                        "filename"  =>$filename,
                                        "iconCls"   =>'icon-decryption',
                                        "id"        =>$x
                                    ];
                                    $getOthers->free();
                                }
                            }*/

                            # Authentication Rules ( > version 8)
                            $getAuthentication = $projectdb->query("SELECT id FROM authentication_rules WHERE source='$source' AND vsys='$vsys' LIMIT 1;");
                            if ($getAuthentication->num_rows == 1) {
                                $x++;
                                $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='policy' AND element='authentication' AND map_filename!='';");
                                if ($getTask->num_rows == 0) {
                                    $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='policy' AND element='authentication';");
                                    $exec[] = "('$filename','$vsys','policy','authentication','')";
                                    $policies[] = [
                                        "vsys"      =>$vsys,
                                        "type"      =>'policy',
                                        "element"   =>'authentication',
                                        "text"      =>'Authentication',
                                        "value"     =>'authentication',
                                        "leaf"      =>true,
                                        "filename"  =>$filename,
                                        "iconCls"   =>'icon-authentication',
                                        "id"        =>$x
                                    ];
                                    $getAuthentication->free();
                                }
                            }

                            # Captive Protal Rules (version 7)
                            $getCaptivePortal = $projectdb->query("SELECT id FROM captiveportal_rules WHERE source='$source' AND vsys='$vsys' LIMIT 1;");
                            if ($getCaptivePortal->num_rows == 1) {
                                $x++;
                                $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='policy' AND element='captiveportal' AND map_filename!='';");
                                if ($getTask->num_rows == 0) {
                                    $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='policy' AND element='captiveportal';");
                                    $exec[] = "('$filename','$vsys','policy','captiveportal','')";
                                    $policies[] = [
                                        "vsys"      =>$vsys,
                                        "type"      =>'policy',
                                        "element"   =>'captiveportal',
                                        "text"      =>'Captive Portal',
                                        "value"     =>'captiveportal',
                                        "leaf"      =>true,
                                        "filename"  =>$filename,
                                        "iconCls"   =>'icon-authentication',
                                        "id"        =>$x
                                    ];
                                    $getCaptivePortal->free();
                                }
                            }

                            # Decryption Rules
                            $getDecryption = $projectdb->query("SELECT id FROM decryption_rules WHERE source='$source' AND vsys='$vsys' LIMIT 1;");
                            if ($getDecryption->num_rows == 1) {
                                $x++;
                                $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='policy' AND element='decryption' AND map_filename!='';");
                                if ($getTask->num_rows == 0) {
                                    $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='policy' AND element='decryption';");
                                    $exec[] = "('$filename','$vsys','policy','decryption','')";
                                    $policies[] = [
                                        "vsys"      =>$vsys,
                                        "type"      =>'policy',
                                        "element"   =>'decryption',
                                        "text"      =>'Decryption',
                                        "value"     =>'decryption',
                                        "leaf"      =>true,
                                        "filename"  =>$filename,
                                        "iconCls"   =>'icon-decryption',
                                        "id"        =>$x
                                    ];
                                    $getDecryption->free();
                                }
                            }

                            # DoS Rules
                            $getDoS = $projectdb->query("SELECT id FROM dos_rules WHERE source='$source' AND vsys='$vsys' LIMIT 1;");
                            if ($getDoS->num_rows == 1) {
                                $x++;
                                $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='policy' AND element='dos' AND map_filename!='';");
                                if ($getTask->num_rows == 0) {
                                    $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='policy' AND element='dos';");
                                    $exec[] = "('$filename','$vsys','policy','dos','')";
                                    $policies[] = [
                                        "vsys"      =>$vsys,
                                        "type"      =>'policy',
                                        "element"   =>'dos',
                                        "text"      =>'DoS Protection',
                                        "value"     =>'dos',
                                        "leaf"      =>true,
                                        "filename"  =>$filename,
                                        "iconCls"   =>'icon-dos_protection',
                                        "id"        =>$x
                                    ];
                                    $getDoS->free();
                                }
                            }

                            # Policy Based Forwarding Rules
                            $getPBF = $projectdb->query("SELECT id FROM pbf_rules WHERE source='$source' AND vsys='$vsys' LIMIT 1;");
                            if ($getPBF->num_rows == 1) {
                                $x++;
                                $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='policy' AND element='pbf' AND map_filename!='';");
                                if ($getTask->num_rows == 0) {
                                    $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='policy' AND element='pbf';");
                                    $exec[] = "('$filename','$vsys','policy','pbf','')";
                                    $policies[] = [
                                        "vsys"      =>$vsys,
                                        "type"      =>'policy',
                                        "element"   =>'pbf',
                                        "text"      =>'Policy Based Forwarding',
                                        "value"     =>'pbf',
                                        "leaf"      =>true,
                                        "filename"  =>$filename,
                                        "iconCls"   =>'icon-pbf',
                                        "id"        =>$x
                                    ];
                                    $getPBF->free();
                                }
                            }

                            # QoS Rules
                            $getQoS = $projectdb->query("SELECT id FROM qos_rules WHERE source='$source' AND vsys='$vsys' LIMIT 1;");
                            if ($getQoS->num_rows == 1) {
                                $x++;
                                $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='policy' AND element='qos' AND map_filename!='';");
                                if ($getTask->num_rows == 0) {
                                    $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='policy' AND element='qos';");
                                    $exec[] = "('$filename','$vsys','policy','qos','')";
                                    $policies[] = [
                                        "vsys"      =>$vsys,
                                        "type"      =>'policy',
                                        "element"   =>'qos',
                                        "text"      =>'QoS',
                                        "value"     =>'qos',
                                        "leaf"      =>true,
                                        "filename"  =>$filename,
                                        "iconCls"   =>'icon-qos',
                                        "id"        =>$x
                                    ];
                                    $getQoS->free();
                                }
                            }

                            # Tunnel Inspection Rules
                            $getTunnelInsp = $projectdb->query("SELECT id FROM tunnel_inspect_rules WHERE source='$source' AND vsys='$vsys' LIMIT 1;");
                            if ($getTunnelInsp->num_rows == 1) {
                                $x++;
                                $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='policy' AND element='tunnel_inspect' AND map_filename!='';");
                                if ($getTask->num_rows == 0) {
                                    $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='policy' AND element='tunnel_inspect';");
                                    $exec[] = "('$filename','$vsys','policy','tunnel_inspect','')";
                                    $policies[] = [
                                        "vsys"      =>$vsys,
                                        "type"      =>'policy',
                                        "element"   =>'tunnel_inspect',
                                        "text"      =>'Tunnel Inspection',
                                        "value"     =>'tunnel_inspect',
                                        "leaf"      =>true,
                                        "filename"  =>$filename,
                                        "iconCls"   =>'icon-tunnelinspection',
                                        "id"        =>$x
                                    ];
                                    $getTunnelInsp->free();
                                }
                            }

                            if (!empty($objects)) {
                                $x++;
                                $echo2[] = [
                                    "vsys"      =>$vsys,
                                    "type"      =>'object',
                                    "element"   =>'all',
                                    "text"      =>'Objects',
                                    "value"     =>'objects',
                                    "iconCls"   =>'',
                                    "leaf"      =>false,
                                    "filename"  =>$filename,
                                    "children"  =>$objects,
                                    "id"        =>$x
                                ];
                            }
                            if (!empty($profiles)) {
                                $x++;
                                $echo2[] = [
                                    "vsys"      =>$vsys,
                                    "type"      =>'profiles',
                                    "element"   =>'all',
                                    "text"      =>'Profiles',
                                    "value"     =>'profiles',
                                    "leaf"      =>false,
                                    "filename"  => $filename,
                                    "iconCls"   =>'icon-profile_group',
                                    "children"  => $profiles,
                                    "id"        =>$x
                                ];
                            }
                            if (!empty($policies)) {
                                $x++;
                                $echo2[] = [
                                    "vsys"      =>$vsys,
                                    "type"      =>'policy',
                                    "element"   =>'all',
                                    "text"      =>'Policies',
                                    "value"     =>'objects',
                                    "iconCls"   =>'',
                                    "leaf"      =>false,
                                    "filename"  => $filename,
                                    "children"  => $policies,
                                    "id"        =>$x
                                ];
                            }

                            if (!empty($echo2)) {
                                $x++;
                                //Aquí están toda la lista de devicegroups
                                $echo1[] = [
                                    "vsys"      =>$vsys,
                                    "text"      =>$vsys,
                                    "value"     =>$vsys,
                                    "iconCls"   =>'icon-device_groups',
                                    "leaf"      =>false,
                                    "filename"  =>$filename,
                                    "children"  =>$echo2,
                                    "id"        =>$x
                                ];
                            }
                        }// Fin devicegroups while principal
                    }

                    if (!empty($echo1)) {
                        $x++;
                        // Ale: Add to see DeviceGroups Tree
                        $echo_all[] = [
                            "expanded"  =>true,
                            "filename"  =>$filename,
                            "iconCls"   =>'icon-device_groups',
                            "text"      =>'Device-Groups',
                            "value"     =>'devicegroups',
                            "element"   =>'all',
                            "type"      =>'devicegroups',
                            "leaf"      =>false,
                            "children"  =>$echo1,
                            "id"        =>$x
                        ];
                    }

                    # TEMPLATES
                    //$getTemplate = $projectdb->query("SELECT id FROM templates_mapping WHERE filename='$filename' AND source='$source' AND project='$project';");
                    $getTemplate = $projectdb->query("SELECT tm.name, tm.id as template FROM templates_mapping tm, templates t WHERE t.templates_mapping_id=tm.id AND t.source='$source';");
                    $template = "";
                    //echo "3. SELECT id FROM templates_mapping WHERE filename='$filename' AND source='$source' AND project='$project';\n";
                    if ($getTemplate->num_rows > 0) {
                        while($getTemplateData = $getTemplate->fetch_assoc()){

                            $template = $getTemplateData['template'];
                            $template_name = $getTemplateData['name'];

                            $network = array();
                            $interfaces = array();
                            $interface_management_profile = array();
                            $ipsec_tunnel = array();
                            $ike_gateways_profiles = array();
                            $ipsec_crypto_profiles = array();
                            $ike_crypto_profiles = array();
                            $monitor_profile = array();
                            $global_protect_app_ipsec_crypto_profiles = array();
                            $vlans = array();
                            $virtual_wires = array();
                            $zones = array();
                            $responsepage = array();
                            $devices = array();
                            $shared_responsepage = array();

                            $echo2 = array();
                            $echo3 = array();
                            $echo4 = array();

                            $echo1_network = array();

                            # Template Based (Network, Interfaces)

                            $getNetwork = $projectdb->query("SELECT name FROM virtual_routers WHERE source='$source' AND template='$template';");
                            if ($getNetwork->num_rows > 0) {
                                while ($vrs = $getNetwork->fetch_assoc()) {
                                    $vrname = $vrs['name'];
                                    $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND template='$template' AND type='virtual_router' AND element='$vrname' AND map_filename!='';");
                                    if ($getTask->num_rows == 0) {
                                        $x++;
                                        $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND template='$template' AND type='virtual_router' AND element='$vrname';");
                                        $exec[] = "('$filename','','virtual_router','$vrname','$template')";
//                                        $network[] = "{template:'" . $template . "',type:'virtual_router',element:'$vrname', text:'$vrname', value:'$vrname',leaf:true, filename:'" . $filename . "',iconCls:'icon-vr'}";
                                        $network[] = [
                                            "template"  =>$template,
                                            "type"      =>'virtual_router',
                                            "element"   =>$vrname,
                                            "text"      =>$vrname,
                                            "value"     =>$vrname,
                                            "leaf"      =>true,
                                            "filename"  =>$filename,
                                            "iconCls"   =>'icon-vr',
                                            "id"        =>$x
                                        ];
                                    }
                                }
                                $getNetwork->free();
                            }
                            #Interfaces
                            $getNetwork = $projectdb->query("SELECT name FROM interfaces WHERE source='$source' AND template='$template' GROUP BY name;");
                            if ($getNetwork->num_rows > 0) {
                                while ($vrs = $getNetwork->fetch_assoc()) {
                                    $vrname = $vrs['name'];
                                    $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND template='$template' AND type='interfaces' AND element='$vrname' AND map_filename!='';");
                                    if ($getTask->num_rows == 0) {
                                        $x++;
                                        $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND template='$template' AND type='interfaces' AND element='$vrname';");
                                        $exec[] = "('$filename','','interfaces','$vrname','$template')";
//                                        $interfaces[] = "{template:'" . $template . "',type:'interfaces',element:'$vrname', text:'$vrname', value:'$vrname',leaf:true, filename:'" . $filename . "',iconCls:'icon-interfaces'}";
                                        $interfaces[] = [
                                            "template"  =>$template,
                                            "type"      =>'interfaces',
                                            "element"   =>$vrname,
                                            "text"      =>$vrname,
                                            "value"     =>$vrname,
                                            "leaf"      =>true,
                                            "filename"  =>$filename,
                                            "iconCls"   =>'icon-interfaces',
                                            "id"        =>$x
                                        ];
                                    }
                                }
                                $getNetwork->free();
                            }

                            # Interface Management Profile
                            $getNetwork = $projectdb->query("SELECT name FROM interface_management_profile WHERE source='$source' AND template='$template' AND name != '' GROUP BY name;");
                            //echo "1. SELECT name FROM interface_management_profile WHERE source='$source' AND template='$template' AND name != '' GROUP BY name;\n";
                            if ($getNetwork->num_rows > 0) {
                                while ($vrs = $getNetwork->fetch_assoc()) {
                                    $vrname = $vrs['name'];
                                    $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND template='$template' AND type='interface_management_profile' AND element='$vrname' AND map_filename!='';");
                                    //echo "2. SELECT id FROM pending_tasks WHERE filename='$filename' AND template='$template' AND type='interface_management_profile' AND element='$vrname' AND map_filename!='';\n";
                                    if ($getTask->num_rows == 0) {
                                        $x++;
                                        $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND template='$template' AND type='interface_management_profile' AND element='$vrname';");
                                        //echo "3. DELETE FROM pending_tasks WHERE filename='$filename' AND template='$template' AND type='interface_management_profile' AND element='$vrname';\n";
                                        $exec[] = "('$filename','','interface_management_profile','$vrname','$template')";
//                                        $interface_management_profile[] = "{template:'" . $template . "',type:'interface_management_profile',element:'$vrname', text:'$vrname', value:'$vrname',leaf:true, filename:'" . $filename . "',iconCls:'icon-interface-mgmt'}";
                                        $interface_management_profile[] = [
                                            "template"  =>$template,
                                            "type"      =>'interface_management_profile',
                                            "element"   =>$vrname,
                                            "text"      =>$vrname,
                                            "value"     =>$vrname,
                                            "leaf"      =>true,
                                            "filename"  =>$filename,
                                            "iconCls"   =>'icon-interface-mgmt',
                                            "id"        =>$x
                                        ];
                                        //print_r($interface_management_profile);
                                    }
                                }
                                $getNetwork->free();
                            }

                            # IPSec Tunnels
                            $getNetwork = $projectdb->query("SELECT name FROM ipsec_tunnel WHERE source='$source' AND template='$template' AND name != '' GROUP BY name;");
                            if ($getNetwork->num_rows > 0) {
                                while ($vrs = $getNetwork->fetch_assoc()) {
                                    $vrname = $vrs['name'];
                                    $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND template='$template' AND type='ipsec_tunnel' AND element='$vrname' AND map_filename!='';");
                                    if ($getTask->num_rows == 0) {
                                        $x++;
                                        $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND template='$template' AND type='ipsec_tunnel' AND element='$vrname';");
                                        $exec[] = "('$filename','','ipsec_tunnel','$vrname','$template')";
//                                        $ipsec_tunnel[] = "{template:'" . $template . "',type:'ipsec_tunnel',element:'$vrname', text:'$vrname', value:'$vrname',leaf:true, filename:'" . $filename . "',iconCls:'icon-ipsec-tunnels'}";
                                        $ipsec_tunnel[] = [
                                            "template"  =>$template,
                                            "type"      =>'ipsec_tunnel',
                                            "element"   =>$vrname,
                                            "text"      =>$vrname,
                                            "value"     =>$vrname,
                                            "leaf"      =>true,
                                            "filename"  =>$filename,
                                            "iconCls"   =>'icon-ipsec-tunnels',
                                            "id"        =>$x
                                        ];
                                    }
                                }
                                $getNetwork->free();
                            }

                            # IKE Gateways
                            $getNetwork = $projectdb->query("SELECT name FROM ike_gateways_profiles WHERE source='$source' AND template='$template' AND name != '' GROUP BY name;");
                            if ($getNetwork->num_rows > 0) {
                                while ($vrs = $getNetwork->fetch_assoc()) {
                                    $vrname = $vrs['name'];
                                    $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND template='$template' AND type='ike_gateways_profiles' AND element='$vrname' AND map_filename!='';");
                                    if ($getTask->num_rows == 0) {
                                        $x++;
                                        $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND template='$template' AND type='ike_gateways_profiles' AND element='$vrname';");
                                        $exec[] = "('$filename','','ike_gateways_profiles','$vrname','$template')";
//                                        $ike_gateways_profiles[] = "{template:'" . $template . "',type:'ike_gateways_profiles',element:'$vrname', text:'$vrname', value:'$vrname',leaf:true, filename:'" . $filename . "',iconCls:'icon-ike-gateways'}";
                                        $ike_gateways_profiles[] = [
                                            "template"  =>$template,
                                            "type"      =>'ike_gateways_profiles',
                                            "element"   =>$vrname,
                                            "text"      =>$vrname,
                                            "value"     =>$vrname,
                                            "leaf"      =>true,
                                            "filename"  =>$filename,
                                            "iconCls"   =>'icon-ike-gateways',
                                            "id"        =>$x
                                        ];
                                    }
                                }
                                $getNetwork->free();
                            }

                            # IPSec Crypto
                            $getNetwork = $projectdb->query("SELECT name FROM ipsec_crypto_profiles WHERE source='$source' AND template='$template' AND name != '' GROUP BY name;");
                            if ($getNetwork->num_rows > 0) {
                                while ($vrs = $getNetwork->fetch_assoc()) {
                                    $vrname = $vrs['name'];
                                    $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND template='$template' AND type='ipsec_crypto_profiles' AND element='$vrname' AND map_filename!='';");
                                    if ($getTask->num_rows == 0) {
                                        $x++;
                                        $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND template='$template' AND type='ipsec_crypto_profiles' AND element='$vrname';");
                                        $exec[] = "('$filename','','ipsec_crypto_profiles','$vrname','$template')";
//                                        $ipsec_crypto_profiles[] = "{template:'" . $template . "',type:'ipsec_crypto_profiles',element:'$vrname', text:'$vrname', value:'$vrname',leaf:true, filename:'" . $filename . "',iconCls:'icon-ipsec-crypto'}";
                                        $ipsec_crypto_profiles[] = [
                                            "template"  =>$template,
                                            "type"      =>'ipsec_crypto_profiles',
                                            "element"   =>$vrname,
                                            "text"      =>$vrname,
                                            "value"     =>$vrname,
                                            "leaf"      =>true,
                                            "filename"  =>$filename,
                                            "iconCls"   =>'icon-ipsec-crypto',
                                            "id"        =>$x
                                        ];
                                    }
                                }
                                $getNetwork->free();
                            }

                            # IKE Crypto
                            $getNetwork = $projectdb->query("SELECT name FROM ike_crypto_profiles WHERE source='$source' AND template='$template' AND name != '' GROUP BY name;");
                            if ($getNetwork->num_rows > 0) {
                                while ($vrs = $getNetwork->fetch_assoc()) {
                                    $vrname = $vrs['name'];
                                    $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND template='$template' AND type='ike_crypto_profiles' AND element='$vrname' AND map_filename!='';");
                                    if ($getTask->num_rows == 0) {
                                        $x++;
                                        $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND template='$template' AND type='ike_crypto_profiles' AND element='$vrname';");
                                        $exec[] = "('$filename','','ike_crypto_profiles','$vrname','$template')";
//                                        $ike_crypto_profiles[] = "{template:'" . $template . "',type:'ike_crypto_profiles',element:'$vrname', text:'$vrname', value:'$vrname',leaf:true, filename:'" . $filename . "',iconCls:'icon-ipsec-crypto'}";
                                        $ike_crypto_profiles[] = [
                                            "template"  =>$template,
                                            "type"      =>'ike_crypto_profiles',
                                            "element"   =>$vrname,
                                            "text"      =>$vrname,
                                            "value"     =>$vrname,
                                            "leaf"      =>true,
                                            "filename"  =>$filename,
                                            "iconCls"   =>'icon-ipsec-crypto',
                                            "id"        =>$x
                                        ];
                                    }
                                }
                                $getNetwork->free();
                            }

                            # Monitor Profile
                            $getNetwork = $projectdb->query("SELECT name FROM monitor_profile WHERE source='$source' AND template='$template' AND name != '' GROUP BY name;");
                            if ($getNetwork->num_rows > 0) {
                                while ($vrs = $getNetwork->fetch_assoc()) {
                                    $vrname = $vrs['name'];
                                    $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND template='$template' AND type='monitor_profile' AND element='$vrname' AND map_filename!='';");
                                    if ($getTask->num_rows == 0) {
                                        $x++;
                                        $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND template='$template' AND type='monitor_profile' AND element='$vrname';");
                                        $exec[] = "('$filename','','monitor_profile','$vrname','$template')";
//                                        $monitor_profile[] = "{template:'" . $template . "',type:'monitor_profile',element:'$vrname', text:'$vrname', value:'$vrname',leaf:true, filename:'" . $filename . "',iconCls:'icon-monitor'}";
                                        $monitor_profile[] = [
                                            "template"  =>$template,
                                            "type"      =>'monitor_profile',
                                            "element"   =>$vrname,
                                            "text"      =>$vrname,
                                            "value"     =>$vrname,
                                            "leaf"      =>true,
                                            "filename"  =>$filename,
                                            "iconCls"   =>'icon-monitor',
                                            "id"        =>$x
                                        ];
                                    }
                                }
                                $getNetwork->free();
                            }

                            # GlobalProtect IPSec Crypto
                            $getNetwork = $projectdb->query("SELECT name FROM global_protect_app_ipsec_crypto_profiles WHERE source='$source' AND template='$template' AND name != '' GROUP BY name;");
                            if ($getNetwork->num_rows > 0) {
                                while ($vrs = $getNetwork->fetch_assoc()) {
                                    $vrname = $vrs['name'];
                                    $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND template='$template' AND type='global_protect_app_ipsec_crypto_profiles' AND element='$vrname' AND map_filename!='';");
                                    if ($getTask->num_rows == 0) {
                                        $x++;
                                        $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND template='$template' AND type='global_protect_app_ipsec_crypto_profiles' AND element='$vrname';");
                                        $exec[] = "('$filename','','global_protect_app_ipsec_crypto_profiles','$vrname','$template')";
//                                        $global_protect_app_ipsec_crypto_profiles[] = "{template:'" . $template . "',type:'global_protect_app_ipsec_crypto_profiles',element:'$vrname', text:'$vrname', value:'$vrname',leaf:true, filename:'" . $filename . "',iconCls:'icon-ipsec-crypto'}";
                                        $global_protect_app_ipsec_crypto_profiles[] = [
                                            "template"  =>$template ,
                                            "type"      =>'global_protect_app_ipsec_crypto_profiles',
                                            "element"   =>$vrname,
                                            "text"      =>$vrname,
                                            "value"     =>$vrname,
                                            "leaf"      =>true,
                                            "filename"  =>$filename,
                                            "iconCls"   =>'icon-ipsec-crypto',
                                            "id"        =>$x
                                        ];
                                    }
                                }
                                $getNetwork->free();
                            }

                            # Vlans
                            $getNetwork = $projectdb->query("SELECT name FROM vlans WHERE source='$source' AND template='$template' AND name != '' GROUP BY name;");
                            if ($getNetwork->num_rows > 0) {
                                while ($vrs = $getNetwork->fetch_assoc()) {
                                    $vrname = $vrs['name'];
                                    $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND template='$template' AND type='vlans' AND element='$vrname' AND map_filename!='';");
                                    //echo "5. SELECT id FROM pending_tasks WHERE filename='$filename' AND template='$template' AND type='vlans' AND element='$vrname' AND map_filename!='';\n";
                                    if ($getTask->num_rows == 0) {
                                        $x++;
                                        $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND template='$template' AND type='vlans' AND element='$vrname';");
                                        //echo "6. DELETE FROM pending_tasks WHERE filename='$filename' AND template='$template' AND type='vlans' AND element='$vrname';\n";
                                        $exec[] = "('$filename','','vlans','$vrname','$template')";
//                                        $vlans[] = "{template:'" . $template . "',type:'vlans',element:'$vrname', text:'$vrname', value:'$vrname',leaf:true, filename:'" . $filename . "',iconCls:'icon-vlans'}";
                                        $vlans[] = [
                                            "template"  =>$template ,
                                            "type"      =>'vlans',
                                            "element"   =>$vrname,
                                            "text"      =>$vrname,
                                            "value"     =>$vrname,
                                            "leaf"      =>true,
                                            "filename"  =>$filename,
                                            "iconCls"   =>'icon-vlans',
                                            "id"        =>$x
                                        ];

                                        //print_r($vlans);
                                    }
                                }
                                $getNetwork->free();
                            }

                            # Virtual Wires
                            $getNetwork = $projectdb->query("SELECT name FROM virtual_wires WHERE source='$source' AND template='$template' AND name != '' GROUP BY name;");
                            if ($getNetwork->num_rows > 0) {
                                while ($vrs = $getNetwork->fetch_assoc()) {
                                    $vrname = $vrs['name'];
                                    $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND template='$template' AND type='virtual_wires' AND element='$vrname' AND map_filename!='';");
                                    if ($getTask->num_rows == 0) {
                                        $x++;
                                        $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND template='$template' AND type='virtual_wires' AND element='$vrname';");
                                        $exec[] = "('$filename','','virtual_wires','$vrname','$template')";
//                                        $virtual_wires[] = "{template:'" . $template . "',type:'virtual_wires',element:'$vrname', text:'$vrname', value:'$vrname',leaf:true, filename:'" . $filename . "',iconCls:'icon-vwire'}";
                                        $virtual_wires[] = [
                                            "template"  =>$template,
                                            "type"      =>'virtual_wires',
                                            "element"   =>$vrname,
                                            "text"      =>$vrname,
                                            "value"     =>$vrname,
                                            "leaf"      =>true,
                                            "filename"  =>$filename,
                                            "iconCls"   =>'icon-vwire',
                                            "id"        =>$x
                                        ];
                                    }
                                }
                                $getNetwork->free();
                            }

                            $getTemplateVsys = $projectdb->query("SELECT name FROM virtual_systems WHERE source='$source' AND template='$template';");
                            if ($getTemplateVsys->num_rows > 0) {
                                $devices = array();
                                while ($getTemplateVsysData = $getTemplateVsys->fetch_assoc()) {
                                    $vsys_template = $getTemplateVsysData['name'];
                                    $iconCls2 = "icon-device";
                                    $zones = array();
                                    $echo2 = array();
                                    $responsepage = array();

                                    # Response Pages
                                    $getNetwork = $projectdb->query("SELECT type FROM response_pages WHERE source='$source' AND template='$template' AND vsys='$vsys_template';");
                                    if ($getNetwork->num_rows > 0) {
                                        while ($vrs = $getNetwork->fetch_assoc()) {
                                            $vrname = $vrs['type'];
                                            $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND template='$template' AND type='response_pages' AND element='$vrname' AND map_filename!='' AND vsys='$vsys_template';");
                                            if ($getTask->num_rows == 0) {
                                                $x++;
                                                $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND template='$template' AND type='response_pages' AND element='$vrname' AND vsys='$vsys_template';");
                                                $exec[] = "('$filename','$vsys_template','response_pages','$vrname','$template')";
                                                $responsepage[] = [
                                                    "template"  =>$template,
                                                    "type"      =>'response_pages',
                                                    "element"   =>$vrname,
                                                    "text"      =>$vrname,
                                                    "value"     =>$vrname,
                                                    "leaf"      =>true,
                                                    "filename"  =>$filename,
                                                    "iconCls"   =>'icon-response_page',
                                                    "vsys"      =>$vsys_template,
                                                    "id"        =>$x
                                                ];
                                            }
                                        }
                                        $getNetwork->free();
                                    }

                                    $getNetwork = $projectdb->query("SELECT name FROM zones WHERE source='$source' AND vsys='$vsys_template' AND template='$template';");
                                    if ($getNetwork->num_rows > 0) {
                                        while ($vrs = $getNetwork->fetch_assoc()) {
                                            $vrname = $vrs['name'];
                                            $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys_template' AND type='zones' AND element='$vrname' AND map_filename!='';");
                                            if ($getTask->num_rows == 0) {
                                                $x++;
                                                $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND template='$template' AND type='zones' AND element='$vrname' AND vsys='$vsys_template';");
                                                $exec[] = "('$filename','$vsys_template','zones','$vrname','$template')";
                                                $zones[] = [
                                                    "vsys" => $vsys_template,
                                                    "template" => $template,
                                                    "type" => 'zones',
                                                    "element" => $vrname,
                                                    "text" => $vrname,
                                                    "value" => $vrname,
                                                    "leaf" => true,
                                                    "filename" => $filename,
                                                    "iconCls" => 'icon-zone',
                                                    "id" => $x
                                                ];
                                            }
                                        }
                                        $getNetwork->free();
                                    }
                                    
                                    if (!empty($zones)) {
                                        $x++;
                                        $echo2[] = [
                                            "vsys"      =>$vsys_template,
                                            "template"  =>$template,
                                            "type"      =>'zones',
                                            "element"   =>'all',
                                            "text"      =>'Zones',
                                            "value"     =>'zone',
                                            "iconCls"   =>'icon-zone',
                                            "leaf"      =>false,
                                            "filename"  =>$filename,
                                            "children"  =>$zones,
                                            "id"        =>$x
                                        ];
                                    }
                                    if (!empty($responsepage)) {
                                        $x++;
                                        $echo2[] = [
                                            "vsys"      =>$vsys,
                                            "template"  =>$template,
                                            "type"      =>'response_pages',
                                            "element"   =>'all',
                                            "text"      =>'Response Pages',
                                            "value"     =>'network',
                                            "iconCls"   =>'icon-response_page',
                                            "leaf"      =>false,
                                            "filename"  =>$filename,
                                            "children"  =>$responsepage,
                                            "id"        =>$x
                                        ];
                                    }

                                    if (!empty($echo2)){
//                                        $devices[] = "{template:'" . $template . "',expanded:true,vsys:'" . $vsys_template . "',filename:'" . $filename . "',text:'" . $vsys_template . "',value:'" . $vsys_template . "',iconCls:'" . $iconCls2 . "', leaf:false, children:[" . implode(",", $zones) . "]}";
                                        $x++;
                                        $devices[] = [
                                            "template"  =>$template ,
                                            "expanded"  =>true,
                                            "vsys"      =>$vsys_template ,
                                            "filename"  =>$filename ,
                                            "text"      =>$vsys_template ,
                                            "value"     =>$vsys_template ,
                                            "iconCls"   =>$iconCls2 ,
                                            "leaf"      =>false,
                                            "children"  =>$echo2,
                                            "id"        =>$x
                                        ];

                                    }

                                }
                            }

                            if (!empty($network)) {
                                $x++;
                                $echo3[] = [
                                    "template"  =>$template,
                                    "type"      =>'virtual_router',
                                    "element"   =>'all',
                                    "text"      =>'Virtual Routers',
                                    "value"     =>'network',
                                    "iconCls"   =>'icon-vr',
                                    "leaf"      =>false,
                                    "filename"  =>$filename,
                                    "children"  =>$network,
                                    "id"        =>$x
                                ];
                            }
                            if (!empty($interfaces)) {
                                $x++;
                                $echo3[] = [
                                    "template"  =>$template,
                                    "type"      =>'interfaces',
                                    "element"   =>'all',
                                    "text"      =>'Interfaces',
                                    "value"     =>'network',
                                    "iconCls"   =>'icon-interfaces',
                                    "leaf"      =>false,
                                    "filename"  =>$filename,
                                    "children"  =>$interfaces,
                                    "id"        =>$x
                                ];
                            }
                            if (!empty($interface_management_profile)) {
                                $x++;
                                $echo3[] = [
                                    "template"  =>$template,
                                    "type"      =>'interface_management_profile',
                                    "element"   =>'all',
                                    "text"      =>'Interface Mgmt',
                                    "value"     =>'network',
                                    "iconCls"   =>'icon-interface-mgmt',
                                    "leaf"      =>false,
                                    "filename"  =>$filename,
                                    "children"  =>$interface_management_profile,
                                    "id"        =>$x
                                ];
                            }
                            if (!empty($ipsec_tunnel)) {
                                $x++;
                                $echo3[] = [
                                    "template"  =>$template,
                                    "type"      =>'ipsec_tunnel',
                                    "element"   =>'all',
                                    "text"      =>'IPSec Tunnels',
                                    "value"     =>'network',
                                    "iconCls"   =>'icon-ipsec-tunnels',
                                    "leaf"      =>false,
                                    "filename"  =>$filename,
                                    "children"  =>$ipsec_tunnel,
                                    "id"        =>$x
                                ];
                            }
                            if (!empty($ike_gateways_profiles)) {
                                $x++;
                                $echo3[] = [
                                    "template"  =>$template,
                                    "type"      =>'ike_gateways_profiles',
                                    "element"   =>'all',
                                    "text"      =>'IKE Gateways',
                                    "value"     =>'network',
                                    "iconCls"   =>'icon-ike-gateways',
                                    "leaf"      =>false,
                                    "filename"  =>$filename,
                                    "children"  =>$ike_gateways_profiles,
                                    "id"        =>$x
                                ];
                            }
                            if (!empty($ipsec_crypto_profiles)) {
                                $x++;
                                $echo3[] = [
                                    "template"  =>$template,
                                    "type"      =>'ipsec_crypto_profiles',
                                    "element"   =>'all',
                                    "text"      =>'IPSec Crypto',
                                    "value"     =>'network',
                                    "iconCls"   =>'icon-ipsec-crypto',
                                    "leaf"      =>false,
                                    "filename"  =>$filename,
                                    "children"  =>$ipsec_crypto_profiles,
                                    "id"        =>$x
                                ];
                            }
                            if (!empty($ike_crypto_profiles)) {
                                $x++;
                                $echo3[] = [
                                    "template"  =>$template,
                                    "type"      =>'ike_crypto_profiles',
                                    "element"   =>'all',
                                    "text"      =>'IKE Crypto',
                                    "value"     =>'network',
                                    "iconCls"   =>'icon-ipsec-crypto',
                                    "leaf"      =>false,
                                    "filename"  =>$filename,
                                    "children"  =>$ike_crypto_profiles,
                                    "id"        =>$x
                                ];
                            }
                            if (!empty($monitor_profile)) {
                                $x++;
                                $echo3[] = [
                                    "template"  =>$template,
                                    "type"      =>'monitor_profile',
                                    "element"   =>'all',
                                    "text"      =>'Monitor Profile',
                                    "value"     =>'network',
                                    "iconCls"   =>'icon-monitor',
                                    "leaf"      =>false,
                                    "filename"  =>$filename,
                                    "children"  =>$monitor_profile,
                                    "id"        =>$x
                                ];
                            }
                            if (!empty($global_protect_app_ipsec_crypto_profiles)) {
                                $x++;
                                $echo3[] = [
                                    "template"  =>$template,
                                    "type"      =>'global_protect_app_ipsec_crypto_profiles',
                                    "element"   =>'all',
                                    "text"      =>'GlobalProtect IPSec Crypto',
                                    "value"     =>'network',
                                    "iconCls"   =>'icon-ipsec-crypto',
                                    "leaf"      =>false,
                                    "filename"  =>$filename,
                                    "children"  =>$global_protect_app_ipsec_crypto_profiles,
                                    "id"        =>$x
                                ];
                            }
                            if (!empty($vlans)) {
                                $x++;
                                $echo3[] = [
                                    "template"  =>$template,
                                    "type"      =>'vlans',
                                    "element"   =>'all',
                                    "text"      =>'VLANs',
                                    "value"     =>'network',
                                    "iconCls"   =>'icon-vlans',
                                    "leaf"      =>false,
                                    "filename"  =>$filename,
                                    "children"  =>$vlans,
                                    "id"        =>$x
                                ];
                            }
                            if (!empty($virtual_wires)) {
                                $x++;
                                $echo3[] = [
                                    "template"  =>$template,
                                    "type"      =>'virtual_wires',
                                    "element"   =>'all',
                                    "text"      =>'Virtual Wires',
                                    "value"     =>'network',
                                    "iconCls"   =>'icon-vwire',
                                    "leaf"      =>false,
                                    "filename"  =>$filename ,
                                    "children"  =>$virtual_wires,
                                    "id"        =>$x
                                ];
                            }

                            # Add Shared
                            # Response Pages
                            $getNetwork = $projectdb->query("SELECT type FROM response_pages WHERE source='$source' AND template='$template' AND vsys='shared';");
                            if ($getNetwork->num_rows > 0) {
                                while ($vrs = $getNetwork->fetch_assoc()) {
                                    $vrname = $vrs['type'];
                                    $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND template='$template' AND type='shared_response_pages' AND element='$vrname' AND map_filename!='' AND vsys='shared';");
                                    if ($getTask->num_rows == 0) {
                                        $x++;
                                        $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND template='$template' AND type='shared_response_pages' AND element='$vrname' AND vsys='shared';");
                                        $exec[] = "('$filename','shared','shared_response_pages','$vrname','$template')";
                                        $shared_responsepage[] = [
                                            "template"  =>$template,
                                            "type"      =>'shared_response_pages',
                                            "element"   =>$vrname,
                                            "text"      =>$vrname,
                                            "value"     =>$vrname,
                                            "leaf"      =>true,
                                            "filename"  =>$filename,
                                            "iconCls"   =>'icon-response_page',
                                            "vsys"      =>'shared',
                                            "id"        =>$x
                                        ];
                                    }
                                }
                                $getNetwork->free();
                            }


                            if (!empty($echo3)) {
                                $x++;
                                $echo1_network[] = [
                                    "template"  =>$template,
                                    "text"      =>'Network',
                                    "value"     =>'network',
                                    "iconCls"   =>'icon-network',
                                    "leaf"      =>false,
                                    "filename"  =>$filename,
                                    "children"  =>$echo3,
                                    "id"        =>$x
                                ];
                            }

                            if (!empty($devices)) {
                                $x++;
                                $echo1_network[] = [
                                    "template"  =>$template,
                                    "text"      =>'Device',
                                    "value"     =>'device',
                                    "iconCls"   =>'icon-device',
                                    "leaf"      =>false,
                                    "filename"  =>$filename,
                                    "children"  =>$devices,
                                    "id"        =>$x
                                ];
                            }

                            if (!empty($shared_responsepage)) {
                                $x++;

                                $echo4[] = [
                                    "template"  =>$template,
                                    "type"      =>'shared_response_pages',
                                    "element"   =>'all',
                                    "text"      =>'Response-Pages',
                                    "value"     =>'shared_response_pages',
                                    "iconCls"   =>'icon-response_page',
                                    "leaf"      =>false,
                                    "filename"  =>$filename ,
                                    "children"  =>$shared_responsepage,
                                    "id"        =>$x
                                ];
                            }

                            if (!empty($echo4)) {
                                $x++;
                                $echo1_network[] = [
                                    "template"  =>$template,
                                    "text"      =>'shared',
                                    "value"     =>'shared',
                                    "vsys"      =>'shared',
                                    "iconCls"   =>'icon-shared_device',
                                    "leaf"      =>false,
                                    "filename"  =>$filename,
                                    "children"  =>$echo4,
                                    "id"        =>$x
                                ];
                            }

                            if (!empty($echo1_network)) {
                                $x++;

                                $echo1_template[] = [
                                    "template"  =>$template,
                                    "text"      =>$template_name,
                                    "value"     =>'template',
                                    "iconCls"   =>'icon-templates',
                                    "leaf"      =>false,
                                    "filename"  =>$filename,
                                    "children"  =>$echo1_network,
                                    "id"        =>$x
                                ];
                            }



                        }//fin while Templates

                    }

                    if (!empty($echo1_template)) {
//                        $echo = implode(",", $echo1);
//                        $echo_all[] = $echo;
                        //$echo_all = $echo1;
                        $x++;
                        // Ale: Add to see Templates Tree
                        $echo_all[] = [
                            "expanded" => true,
                            "filename" => $filename,
                            "iconCls" => 'icon-templates',
                            "text" => 'Templates',
                            "value" => 'templates',
                            "element" => 'all',
                            "type" => 'templates',
                            "leaf" => false,
                            "children" => $echo1_template,
                            "id" => $x
                        ];
                    }

                    # SHARED
                    #Shared Profiles
                    $getProfiles = $projectdb->query("SELECT name FROM profiles WHERE source='$source' AND vsys = 'shared' AND name!='strict' AND name!='default';");
                    if ($getProfiles->num_rows > 0) {
                        $x++;
                        $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='shared' AND type='shared_profiles' AND element='shared_profiles' AND map_filename!='';");
                        if ($getTask->num_rows == 0) {
                            $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='shared' AND type='shared_profiles' AND element='shared_profiles';");
                            $exec[] = "('$filename','shared','shared_profiles','shared_profiles','')";
                            $shared_profiles[] = [
                                "vsys"      =>'shared',
                                "type"      =>'shared_profiles',
                                "element"   =>'shared_profiles',
                                "text"      =>'Security',
                                "value"     =>'shared_profiles',
                                "leaf"      =>true,
                                "iconCls"   =>'icon-profile_group',
                                "filename"  =>$filename,
                                "id"        =>$x
                            ];
                            $getProfiles->free();
                        }
                    }
                    #Shared Profiles Groups
                    $getProfiles = $projectdb->query("SELECT name FROM profiles_groups WHERE source='$source' AND vsys = 'shared' ;");
                    if ($getProfiles->num_rows > 0) {
                        $x++;
                        $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='shared' AND type='shared_profiles_groups' AND element='shared_profiles_groups' AND map_filename!='';");
                        if ($getTask->num_rows == 0) {
                            $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='shared' AND type='shared_profiles_groups' AND element='shared_profiles_groups';");
                            $exec[] = "('$filename','shared','shared_profiles_groups','shared_profiles_groups','')";
//                                $shared_profiles[] = "{vsys:'" . $vsys . "',type:'shared_profiles_groups',element:'shared_profiles_groups', text:'Security Group', value:'shared_profiles_groups',leaf:true, iconCls:'icon-profile_group',filename:'" . $filename . "'}";
                            $shared_profiles[] = [
                                "vsys"      =>'shared',
                                "type"      =>'shared_profiles_groups',
                                "element"   =>'shared_profiles_groups',
                                "text"      =>'Security Group',
                                "value"     =>'shared_profiles_groups',
                                "leaf"      =>true,
                                "iconCls"   =>'icon-profile_group',
                                "filename"  =>$filename,
                                "id"        =>$x
                            ];
                            $getProfiles->free();
                        }
                    }
                    #Shared Log Settings
                    $getProfiles = $projectdb->query("SELECT name FROM log_settings WHERE source='$source' AND vsys = 'shared' AND type='profiles';");
                    if ($getProfiles->num_rows > 0) {
                        $x++;
                        $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='shared' AND type='shared_log_settings' AND element='shared_log_settings' AND map_filename!='';");
                        if ($getTask->num_rows == 0) {
                            $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='shared' AND type='shared_log_settings' AND element='shared_log_settings';");
                            $exec[] = "('$filename','shared','shared_log_settings','shared_log_settings','')";
//                                $shared_profiles[] = "{vsys:'" . $vsys . "',type:'shared_profiles',element:'shared_profiles', text:'Log Forwarding', value:'shared_log_settings',leaf:true, iconCls:'icon-log_forwarding',filename:'" . $filename . "'}";
                            $shared_profiles[] = [
                                "vsys"      =>'shared',
                                "type"      =>'shared_profiles',
                                "element"   =>'shared_profiles',
                                "text"      =>'Log Forwarding',
                                "value"     =>'shared_log_settings',
                                "leaf"      =>true,
                                "iconCls"   =>'icon-log_forwarding',
                                "filename"  =>$filename,
                                "id"        =>$x
                            ];
                            $getProfiles->free();
                        }
                    }
                    # Reports
                    $getAddress = $projectdb->query("SELECT id FROM reports WHERE source='$source' AND vsys = 'shared' LIMIT 1");
                    if ($getAddress->num_rows == 1) {
                        $x++;
                        $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='shared' AND type='object' AND element='shared_reports' AND map_filename!='';");
                        if ($getTask->num_rows == 0) {
                            $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='shared' AND type='object' AND element='shared_reports';");
                            $exec[] = "('$filename','shared','object','shared_reports','')";
//                                $shared_objects[] = "{vsys:'" . $vsys . "',type:'object',element:'shared_schedules', text:'Schedules', value:'shared_schedules',leaf:true, iconCls:'icon-schedules',filename:'" . $filename . "'}";
                            $shared_objects[] = [
                                "vsys"      =>'shared',
                                "type"      =>'object',
                                "element"   =>'shared_reports',
                                "text"      =>'Reports',
                                "value"     =>'shared_reports',
                                "leaf"      =>true,
                                "iconCls"   =>'icon-reports',
                                "filename"  =>$filename,
                                "id"        =>$x
                            ];
                            $getAddress->free();
                        }
                    }
                    #Schedules
                    $getAddress = $projectdb->query("SELECT id FROM schedules WHERE source='$source' AND vsys = 'shared' LIMIT 1");
                    if ($getAddress->num_rows == 1) {
                        $x++;
                        $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='shared' AND type='object' AND element='shared_schedules' AND map_filename!='';");
                        if ($getTask->num_rows == 0) {
                            $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='shared' AND type='object' AND element='shared_schedules';");
                            $exec[] = "('$filename','shared','object','shared_schedules','')";
//                                $shared_objects[] = "{vsys:'" . $vsys . "',type:'object',element:'shared_schedules', text:'Schedules', value:'shared_schedules',leaf:true, iconCls:'icon-schedules',filename:'" . $filename . "'}";
                            $shared_objects[] = [
                                "vsys"      =>'shared',
                                "type"      =>'object',
                                "element"   =>'shared_schedules',
                                "text"      =>'Schedules',
                                "value"     =>'shared_schedules',
                                "leaf"      =>true,
                                "iconCls"   =>'icon-schedules',
                                "filename"  =>$filename,
                                "id"        =>$x
                            ];
                            $getAddress->free();
                        }
                    }
                    # Address
                    $getAddress = $projectdb->query("SELECT id FROM address WHERE source='$source' AND vsys = 'shared' LIMIT 1");
                    if ($getAddress->num_rows == 1) {
                        $x++;
                        $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='shared' AND type='object' AND element='shared_address' AND map_filename!='';");
                        if ($getTask->num_rows == 0) {
                            $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='shared' AND type='object' AND element='shared_address';");
                            $exec[] = "('$filename','shared','object','shared_address','')";
                            $shared_objects[] = [
                                "vsys"      =>'shared',
                                "type"      =>'object',
                                "element"   =>'shared_address',
                                "text"      =>'Address',
                                "value"     =>'shared_address',
                                "leaf"      =>true,
                                "iconCls"   =>'icon-shared_address',
                                "filename"  =>$filename,
                                "id"        =>$x
                            ];
                            $getAddress->free();
                        }
                    }
                    # Address Groups
                    $getAddressGroups = $projectdb->query("SELECT id FROM address_groups_id WHERE source='$source' AND vsys = 'shared' LIMIT 1");
                    if ($getAddressGroups->num_rows == 1) {
                        $x++;
                        $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='shared' AND type='object' AND element='shared_address_groups' AND map_filename!='';");
                        if ($getTask->num_rows == 0) {
                            $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='shared' AND type='object' AND element='shared_address_groups';");
                            $exec[] = "('$filename','shared','object','shared_address_groups','')";
//                                $shared_objects[] = "{vsys:'" . $vsys . "',type:'object',element:'shared_address_groups', text:'Address-Groups', value:'shared_address_groups_id',leaf:true,filename:'" . $filename . "', iconCls:'icon-shared_address_groups'}";
                            $shared_objects[] = [
                                "vsys"      =>'shared',
                                "type"      =>'object',
                                "element"   =>'shared_address_groups',
                                "text"      =>'Address-Groups',
                                "value"     =>'shared_address_groups_id',
                                "leaf"      =>true,
                                "filename"  =>$filename,
                                "iconCls"   =>'icon-shared_address_groups',
                                "id"        =>$x
                            ];
                            $getAddressGroups->free();
                        }
                    }
                    # Services
                    $getServices = $projectdb->query("SELECT id FROM services WHERE source='$source' AND vsys = 'shared' AND name!='application-default' AND name!='service-http' AND name!='service-https' LIMIT 1");
                    if ($getServices->num_rows == 1) {
                        $x++;
                        $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='shared' AND type='object' AND element='shared_services' AND map_filename!='';");
                        if ($getTask->num_rows == 0) {
                            $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='shared' AND type='object' AND element='shared_services';");
                            $exec[] = "('$filename','shared','object','shared_services','')";
                            $shared_objects[] = [
                                "vsys"      =>'shared',
                                "type"      =>'object',
                                "element"   =>'shared_services',
                                "text"      =>'Services',
                                "value"     =>'shared_services',
                                "leaf"      =>true,
                                "filename"  =>$filename,
                                "iconCls"   =>'icon-shared_services',
                                "id"        =>$x
                            ];
                            $getServices->free();
                        }
                    }
                    # Services Groups
                    $getServicesGroups = $projectdb->query("SELECT id FROM services_groups_id WHERE source='$source' AND vsys = 'shared' LIMIT 1");
                    if ($getServicesGroups->num_rows == 1) {
                        $x++;
                        $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='shared' AND type='object' AND element='shared_services_groups' AND map_filename!='';");
                        if ($getTask->num_rows == 0) {
                            $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='shared' AND type='object' AND element='shared_services_groups';");
                            $exec[] = "('$filename','shared','object','shared_services_groups','')";
//                                $shared_objects[] = "{vsys:'" . $vsys . "',type:'object',element:'shared_services_groups', text:'Services-Groups', value:'shared_services_groups_id',leaf:true,filename:'" . $filename . "', iconCls:'icon-shared_services_groups'}";
                            $shared_objects[] = [
                                "vsys"      =>'shared',
                                "type"      =>'object',
                                "element"   =>'shared_services_groups',
                                "text"      =>'Services-Groups',
                                "value"     =>'shared_services_groups_id',
                                "leaf"      =>true,
                                "filename"  =>$filename,
                                "iconCls"   =>'icon-shared_services_groups',
                                "id"        =>$x
                            ];
                            $getServicesGroups->free();
                        }
                    }
                    # Regions
                    $getServicesGroups = $projectdb->query("SELECT id FROM regions WHERE source='$source' AND vsys = 'shared' LIMIT 1");
                    if ($getServicesGroups->num_rows == 1) {
                        $x++;
                        $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='shared' AND type='object' AND element='shared_regions' AND map_filename!='';");
                        if ($getTask->num_rows == 0) {
                            $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='shared' AND type='object' AND element='shared_regions';");
                            $exec[] = "('$filename','shared','object','shared_regions','')";
//                                $objects[] = "{vsys:'" . $vsys . "',type:'object',element:'shared_regions', text:'Regions', value:'shared_regions',leaf:true,filename:'" . $filename . "', iconCls:'icon-regions'}";
                            $shared_objects[] = [
                                "vsys"      =>'shared',
                                "type"      =>'object',
                                "element"   =>'shared_regions',
                                "text"      =>'Regions',
                                "value"     =>'shared_regions',
                                "leaf"      =>true,
                                "filename"  =>$filename,
                                "iconCls"   =>'icon-regions',
                                "id"        =>$x
                            ];
                            $getServicesGroups->free();
                        }
                    }
                    # Applications
                    $getApps = $projectdb->query("SELECT id FROM applications WHERE source='$source' AND vsys = 'shared' LIMIT 1");
                    if ($getApps->num_rows == 1) {
                        $x++;
                        $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='shared' AND type='object' AND element='shared_applications' AND map_filename!='';");
                        if ($getTask->num_rows == 0) {
                            $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='shared' AND type='object' AND element='shared_applications';");
                            $exec[] = "('$filename','shared','object','shared_applications','')";
//                                $shared_objects[] = "{vsys:'" . $vsys . "',type:'object',element:'shared_applications', text:'Applications', value:'shared_applications',leaf:true,filename:'" . $filename . "', iconCls:'icon-shared_applications'}";
                            $shared_objects[] = [
                                "vsys"      =>'shared',
                                "type"      =>'object',
                                "element"   =>'shared_applications',
                                "text"      =>'Applications',
                                "value"     =>'shared_applications',
                                "leaf"      =>true,
                                "filename"  =>$filename,
                                "iconCls"   =>'icon-shared_applications',
                                "id"        =>$x
                            ];
                            $getApps->free();
                        }
                    }
                    # Application Filters
                    $getApps = $projectdb->query("SELECT id FROM applications_filters WHERE source='$source' AND vsys = 'shared' LIMIT 1");
                    if ($getApps->num_rows == 1) {
                        $x++;
                        $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='shared' AND type='object' AND element='shared_applications_filters' AND map_filename!='';");
                        if ($getTask->num_rows == 0) {
                            $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='shared' AND type='object' AND element='shared_applications_filters';");
                            $exec[] = "('$filename','shared','object','shared_applications_filters','')";
//                                $shared_objects[] = "{vsys:'" . $vsys . "',type:'object',element:'shared_applications_filters', text:'Applications Filters', value:'shared_applications_filters',leaf:true,filename:'" . $filename . "', iconCls:'icon-shared_applications_filter'}";
                            $shared_objects[] = [
                                "vsys"      =>'shared',
                                "type"      =>'object',
                                "element"   =>'shared_applications_filters',
                                "text"      =>'Applications Filters',
                                "value"     =>'shared_applications_filters',
                                "leaf"      =>true,
                                "filename"  =>$filename ,
                                "iconCls"   =>'icon-shared_applications_filter',
                                "id"        =>$x
                            ];
                            $getApps->free();
                        }
                    }
                    # Applications Groups
                    $getApps = $projectdb->query("SELECT id FROM applications_groups_id WHERE source='$source' AND vsys = 'shared' LIMIT 1");
                    if ($getApps->num_rows == 1) {
                        $x++;
                        $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='shared' AND type='object' AND element='shared_applications_groups' AND map_filename!='';");
                        if ($getTask->num_rows == 0) {
                            $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='shared' AND type='object' AND element='shared_applications_groups';");
                            $exec[] = "('$filename','shared','object','shared_applications_groups','')";
//                                $shared_objects[] = "{vsys:'" . $vsys . "',type:'object',element:'shared_applications_groups', text:'Applications-Groups', value:'shared_applications_groups',leaf:true,filename:'" . $filename . "', iconCls:'icon-shared_applications_groups'}";
                            $shared_objects[] = [
                                "vsys"      =>'shared',
                                "type"      =>'object',
                                "element"   =>'shared_applications_groups',
                                "text"      =>'Applications-Groups',
                                "value"     =>'shared_applications_groups_id',
                                "leaf"      =>true,
                                "filename"  =>$filename,
                                "iconCls"   =>'icon-shared_applications_groups',
                                "id"        =>$x
                            ];
                            $getApps->free();
                        }
                    }
                    # Tags
                    $getApps = $projectdb->query("SELECT id FROM tag WHERE source='$source' AND vsys = 'shared' LIMIT 1;");
                    if ($getApps->num_rows == 1) {
                        $x++;
                        $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='shared' AND type='object' AND element='shared_tag' AND map_filename!='';");
                        if ($getTask->num_rows == 0) {
                            $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='shared' AND type='object' AND element='shared_tag';");
                            $exec[] = "('$filename','shared','object','shared_tag','')";
                            $shared_objects[] = [
                                "vsys"      =>'shared',
                                "type"      =>'object',
                                "element"   =>'shared_tag',
                                "text"      =>'Tags',
                                "value"     =>'shared_tag',
                                "leaf"      =>true,
                                "filename"  =>$filename,
                                "iconCls"   =>'icon-shared_tags',
                                "id"        =>$x
                            ];
                            $getApps->free();
                        }
                    }
                    # Response Pages
                    /*$shared_response_pages = array();
                    $getNetwork = $projectdb->query("SELECT type FROM response_pages WHERE source='$source' AND vsys = 'shared';");
                    if ($getNetwork->num_rows > 0) {
                        while ($vrs = $getNetwork->fetch_assoc()) {
                            $vrname = $vrs['type'];
                            $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND template='$template' AND type='shared_response_pages' AND element='$vrname' AND map_filename!='';");
                            if ($getTask->num_rows == 0) {
                                $x++;
                                $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND template='$template' AND type='shared_response_pages' AND element='$vrname';");
                                $exec[] = "('$filename','shared','shared_response_pages','$vrname','$template')";
//                                    $shared_response_pages[] = "{vsys:'" . $vsys . "',type:'shared_response_pages',element:'$vrname', text:'$vrname', value:'$vrname',leaf:true, filename:'" . $filename . "',iconCls:'icon-response_page'}";
                                $shared_response_pages[] = [
                                    "vsys"      =>$vsys,
                                    "type"      =>'shared_response_pages',
                                    "element"   =>'$vrname',
                                    "text"      =>$vrname,
                                    "value"     =>$vrname,
                                    "leaf"      =>true,
                                    "filename"  =>$filename,
                                    "iconCls"   =>'icon-response_page',
                                    "id"        =>$x
                                ];
                            }
                        }
                        //if (count($shared_response_pages>0)){
                        //	$shared_objects[]="{template:'".$template."',type:'shared_response_pages',element:'all', text:'Response-Pages', value:'network',leaf:false, filename:'".$filename."',iconCls:'icon-response_page',children:[".implode(",",$shared_response_pages)."]}";
                        //	unset($shared_response_pages);
                        //}
                        $getNetwork->free();
                    }
                    if (!empty($shared_response_pages)) {
                        //$echo2[]="{vsys:'".$vsys."',type:'object',element:'all', text:'Objects', value:'objects', iconCls:'', leaf:false,filename:'".$filename."', children:[".implode(",",$shared_objects)."]}";
//                        $echo2[] = "{vsys:'" . $vsys . "',type:'shared_response_pages',element:'all', text:'Response-Pages', value:'network',leaf:false, filename:'" . $filename . "',iconCls:'icon-response_page',children:[" . implode(",", $shared_response_pages) . "]}";
                        $x++;
                        $echo2[] = [
                            "vsys"      =>$vsys,
                            "type"      =>'shared_response_pages',
                            "element"   =>'all',
                            "text"      =>'Response-Pages',
                            "value"     =>'network',
                            "leaf"      =>false,
                            "filename"  =>$filename,
                            "iconCls"   =>'icon-response_page',
                            "children"  =>$shared_response_pages,
                            "id"        =>$x
                        ];
                        unset($shared_response_pages);
                    }*/

                    if (!empty($shared_profiles)) {
                        $x++;
                        $echo2_shared[] = [
                            "vsys"      =>'shared',
                            "type"      =>'shared_profiles',
                            "element"   =>'all',
                            "text"      =>'Profiles',
                            "value"     =>'shared_profiles',
                            "leaf"      =>false,
                            "filename"  =>$filename,
                            "iconCls"   =>'icon-profile_group',
                            "children"  =>$shared_profiles,
                            "id"        =>$x
                        ];
                        unset($shared_profiles);
                    }

                    if (!empty($shared_objects)) {
                        $x++;
                        $echo2_shared[] = [
                            "vsys"      =>'shared',
                            "type"      =>'object',
                            "element"   =>'all',
                            "text"      =>'Objects',
                            "value"     =>'objects',
                            "iconCls"   =>'',
                            "leaf"      =>false,
                            "filename"  =>$filename,
                            "children"  =>$shared_objects,
                            "id"        =>$x
                        ];
                    }

                    if (!empty($echo2_shared)) {
                        $x++;
                        // Ale: Add to see Shared Tree
                        $echo_all[] = [
                            "expanded" => true,
                            "filename" => $filename,
                            "iconCls" => 'icon-shared_device',
                            "text" => 'shared',
                            "value" => 'shared',
                            "element" => 'all',
                            "type" => 'shared',
                            "leaf" => false,
                            "children" => $echo2_shared,
                            "id" => $x
                        ];
                    }

                }
                else {
                    //FIREWALL

                    # GEt Template or Device Config
                    $getTemplate = $projectdb->query("SELECT id FROM templates_mapping WHERE filename='$filename' AND source='$source';");
                    if ($getTemplate->num_rows == 1) {
                        $getTemplateData = $getTemplate->fetch_assoc();
                        $template = $getTemplateData['id'];
                    } else {
                        $template = "";
                    }
                    #Start to read configs
                    $echo1 = array();

                    $getVsys = $projectdb->query("SELECT id,vsys FROM device_mapping WHERE filename='$filename';");
                    
                    //echo "4. SELECT id,vsys FROM device_mapping WHERE filename='$filename';\n";

                    while ($data2 = $getVsys->fetch_assoc()) {
                        $vsys = $data2['vsys'];
                        $vsysid = $data2['id'];

                        $policies = array();
                        $objects = array();
                        $shared_objects = array();
                        $network = array();
                        $interfaces = array();
                        $zones = array();
                        $profiles = array();
                        $interface_management_profile = array();
                        $ipsec_tunnel = array();
                        $ike_gateways_profiles = array();
                        $ipsec_crypto_profiles = array();
                        $ike_crypto_profiles = array();
                        $monitor_profile = array();
                        $global_protect_app_ipsec_crypto_profiles = array();
                        $vlans = array();
                        $virtual_wires = array();

                        $echo2 = array();
                        $echo3 = array();

                        $responsepage = array();

                        if ($vsys == "shared") {

                            #Shared Profiles
                            $getProfiles = $projectdb->query("SELECT name FROM profiles WHERE source='$source' AND vsys = 'shared' AND name!='strict' AND name!='default';");
                            if ($getProfiles->num_rows > 0) {
                                $x++;
                                $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='shared_profiles' AND element='shared_profiles' AND map_filename!='';");
                                if ($getTask->num_rows == 0) {
                                    $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='shared_profiles' AND element='shared_profiles';");
                                    $exec[] = "('$filename','$vsys','shared_profiles','shared_profiles','')";
                                    $shared_profiles[] = [
                                        "vsys" => $vsys,
                                        "type" => 'shared_profiles',
                                        "element" => 'shared_profiles',
                                        "text" => 'Security',
                                        "value" => 'shared_profiles',
                                        "leaf" => true,
                                        "iconCls" => 'icon-profile_group',
                                        "filename" => $filename,
                                        "id" => $x
                                    ];
                                    $getProfiles->free();
                                }
                            }
                            #Shared Profiles Groups
                            $getProfiles = $projectdb->query("SELECT name FROM profiles_groups WHERE source='$source' AND vsys = 'shared' ;");
                            if ($getProfiles->num_rows > 0) {
                                $x++;
                                $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='shared_profiles_groups' AND element='shared_profiles_groups' AND map_filename!='';");
                                if ($getTask->num_rows == 0) {
                                    $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='shared_profiles_groups' AND element='shared_profiles_groups';");
                                    $exec[] = "('$filename','$vsys','shared_profiles_groups','shared_profiles_groups','')";
//                                $shared_profiles[] = "{vsys:'" . $vsys . "',type:'shared_profiles_groups',element:'shared_profiles_groups', text:'Security Group', value:'shared_profiles_groups',leaf:true, iconCls:'icon-profile_group',filename:'" . $filename . "'}";
                                    $shared_profiles[] = [
                                        "vsys" => $vsys,
                                        "type" => 'shared_profiles_groups',
                                        "element" => 'shared_profiles_groups',
                                        "text" => 'Security Group',
                                        "value" => 'shared_profiles_groups',
                                        "leaf" => true,
                                        "iconCls" => 'icon-profile_group',
                                        "filename" => $filename,
                                        "id" => $x
                                    ];
                                    $getProfiles->free();
                                }
                            }
                            #Shared Log Settings
                            $getProfiles = $projectdb->query("SELECT name FROM log_settings WHERE source='$source' AND vsys = 'shared' AND type='profiles';");
                            if ($getProfiles->num_rows > 0) {
                                $x++;
                                $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='shared_log_settings' AND element='shared_log_settings' AND map_filename!='';");
                                if ($getTask->num_rows == 0) {
                                    $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='shared_log_settings' AND element='shared_log_settings';");
                                    $exec[] = "('$filename','$vsys','shared_log_settings','shared_log_settings','')";
//                                $shared_profiles[] = "{vsys:'" . $vsys . "',type:'shared_profiles',element:'shared_profiles', text:'Log Forwarding', value:'shared_log_settings',leaf:true, iconCls:'icon-log_forwarding',filename:'" . $filename . "'}";
                                    $shared_profiles[] = [
                                        "vsys" => $vsys,
                                        "type" => 'shared_profiles',
                                        "element" => 'shared_profiles',
                                        "text" => 'Log Forwarding',
                                        "value" => 'shared_log_settings',
                                        "leaf" => true,
                                        "iconCls" => 'icon-log_forwarding',
                                        "filename" => $filename,
                                        "id" => $x
                                    ];
                                    $getProfiles->free();
                                }
                            }
                            # Reports
                            $getAddress = $projectdb->query("SELECT id FROM reports WHERE source='$source' AND vsys = 'shared' LIMIT 1");
                            if ($getAddress->num_rows == 1) {
                                $x++;
                                $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='object' AND element='shared_reports' AND map_filename!='';");
                                if ($getTask->num_rows == 0) {
                                    $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='object' AND element='shared_reports';");
                                    $exec[] = "('$filename','$vsys','object','shared_reports','')";
//                                $shared_objects[] = "{vsys:'" . $vsys . "',type:'object',element:'shared_schedules', text:'Schedules', value:'shared_schedules',leaf:true, iconCls:'icon-schedules',filename:'" . $filename . "'}";
                                    $shared_objects[] = [
                                        "vsys" => $vsys,
                                        "type" => 'object',
                                        "element" => 'shared_reports',
                                        "text" => 'Reports',
                                        "value" => 'shared_reports',
                                        "leaf" => true,
                                        "iconCls" => 'icon-schedules',
                                        "filename" => $filename,
                                        "id" => $x
                                    ];
                                    $getAddress->free();
                                }
                            }
                            #Schedules
                            $getAddress = $projectdb->query("SELECT id FROM schedules WHERE source='$source' AND vsys = 'shared' LIMIT 1");
                            if ($getAddress->num_rows == 1) {
                                $x++;
                                $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='object' AND element='shared_schedules' AND map_filename!='';");
                                if ($getTask->num_rows == 0) {
                                    $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='object' AND element='shared_schedules';");
                                    $exec[] = "('$filename','$vsys','object','shared_schedules','')";
//                                $shared_objects[] = "{vsys:'" . $vsys . "',type:'object',element:'shared_schedules', text:'Schedules', value:'shared_schedules',leaf:true, iconCls:'icon-schedules',filename:'" . $filename . "'}";
                                    $shared_objects[] = [
                                        "vsys" => $vsys,
                                        "type" => 'object',
                                        "element" => 'shared_schedules',
                                        "text" => 'Schedules',
                                        "value" => 'shared_schedules',
                                        "leaf" => true,
                                        "iconCls" => 'icon-schedules',
                                        "filename" => $filename,
                                        "id" => $x
                                    ];
                                    $getAddress->free();
                                }
                            }
                            $getAddress = $projectdb->query("SELECT id FROM address WHERE source='$source' AND vsys = 'shared' LIMIT 1");
                            if ($getAddress->num_rows == 1) {
                                $x++;
                                $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='object' AND element='shared_address' AND map_filename!='';");
                                if ($getTask->num_rows == 0) {
                                    $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='object' AND element='shared_address';");
                                    $exec[] = "('$filename','$vsys','object','shared_address','')";
                                    $shared_objects[] = [
                                        "vsys" => $vsys,
                                        "type" => 'object',
                                        "element" => 'shared_address',
                                        "text" => 'Address',
                                        "value" => 'shared_address',
                                        "leaf" => true,
                                        "iconCls" => 'icon-shared_address',
                                        "filename" => $filename,
                                        "id" => $x
                                    ];
                                    $getAddress->free();
                                }
                            }
                            # Address Groups
                            $getAddressGroups = $projectdb->query("SELECT id FROM address_groups_id WHERE source='$source' AND vsys = 'shared' LIMIT 1");
                            if ($getAddressGroups->num_rows == 1) {
                                $x++;
                                $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='object' AND element='shared_address_groups' AND map_filename!='';");
                                if ($getTask->num_rows == 0) {
                                    $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='object' AND element='shared_address_groups';");
                                    $exec[] = "('$filename','$vsys','object','shared_address_groups','')";
//                                $shared_objects[] = "{vsys:'" . $vsys . "',type:'object',element:'shared_address_groups', text:'Address-Groups', value:'shared_address_groups_id',leaf:true,filename:'" . $filename . "', iconCls:'icon-shared_address_groups'}";
                                    $shared_objects[] = [
                                        "vsys" => $vsys,
                                        "type" => 'object',
                                        "element" => 'shared_address_groups',
                                        "text" => 'Address-Groups',
                                        "value" => 'shared_address_groups_id',
                                        "leaf" => true,
                                        "filename" => $filename,
                                        "iconCls" => 'icon-shared_address_groups',
                                        "id" => $x
                                    ];
                                    $getAddressGroups->free();
                                }
                            }
                            # Services
                            $getServices = $projectdb->query("SELECT id FROM services WHERE source='$source' AND vsys = 'shared' AND name!='application-default' AND name!='service-http' AND name!='service-https' LIMIT 1");
                            if ($getServices->num_rows == 1) {
                                $x++;
                                $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='object' AND element='shared_services' AND map_filename!='';");
                                if ($getTask->num_rows == 0) {
                                    $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='object' AND element='shared_services';");
                                    $exec[] = "('$filename','$vsys','object','shared_services','')";
                                    $shared_objects[] = [
                                        "vsys" => $vsys,
                                        "type" => 'object',
                                        "element" => 'shared_services',
                                        "text" => 'Services',
                                        "value" => 'shared_services',
                                        "leaf" => true,
                                        "filename" => $filename,
                                        "iconCls" => 'icon-shared_services',
                                        "id" => $x
                                    ];
                                    $getServices->free();
                                }
                            }
                            # Services Groups
                            $getServicesGroups = $projectdb->query("SELECT id FROM services_groups_id WHERE source='$source' AND vsys = 'shared' LIMIT 1");
                            if ($getServicesGroups->num_rows == 1) {
                                $x++;
                                $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='object' AND element='shared_services_groups' AND map_filename!='';");
                                if ($getTask->num_rows == 0) {
                                    $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='object' AND element='shared_services_groups';");
                                    $exec[] = "('$filename','$vsys','object','shared_services_groups','')";
//                                $shared_objects[] = "{vsys:'" . $vsys . "',type:'object',element:'shared_services_groups', text:'Services-Groups', value:'shared_services_groups_id',leaf:true,filename:'" . $filename . "', iconCls:'icon-shared_services_groups'}";
                                    $shared_objects[] = [
                                        "vsys" => $vsys,
                                        "type" => 'object',
                                        "element" => 'shared_services_groups',
                                        "text" => 'Services-Groups',
                                        "value" => 'shared_services_groups_id',
                                        "leaf" => true,
                                        "filename" => $filename,
                                        "iconCls" => 'icon-shared_services_groups',
                                        "id" => $x
                                    ];
                                    $getServicesGroups->free();
                                }
                            }
                            # Regions
                            $getServicesGroups = $projectdb->query("SELECT id FROM regions WHERE source='$source' AND vsys = 'shared' LIMIT 1");
                            if ($getServicesGroups->num_rows == 1) {
                                $x++;
                                $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='shared' AND type='object' AND element='shared_regions' AND map_filename!='';");
                                if ($getTask->num_rows == 0) {
                                    $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='shared' AND type='object' AND element='shared_regions';");
                                    $exec[] = "('$filename','$vsys','object','shared_regions','')";
//                                $objects[] = "{vsys:'" . $vsys . "',type:'object',element:'shared_regions', text:'Regions', value:'shared_regions',leaf:true,filename:'" . $filename . "', iconCls:'icon-regions'}";
                                    $objects[] = [
                                        "vsys" => $vsys,
                                        "type" => 'object',
                                        "element" => 'shared_regions',
                                        "text" => 'Regions',
                                        "value" => 'shared_regions',
                                        "leaf" => true,
                                        "filename" => $filename,
                                        "iconCls" => 'icon-regions',
                                        "id" => $x
                                    ];
                                    $getServicesGroups->free();
                                }
                            }
                            # Applications
                            $getApps = $projectdb->query("SELECT id FROM applications WHERE source='$source' AND vsys = 'shared' LIMIT 1");
                            if ($getApps->num_rows == 1) {
                                $x++;
                                $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='object' AND element='shared_applications' AND map_filename!='';");
                                if ($getTask->num_rows == 0) {
                                    $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='object' AND element='shared_applications';");
                                    $exec[] = "('$filename','$vsys','object','shared_applications','')";
//                                $shared_objects[] = "{vsys:'" . $vsys . "',type:'object',element:'shared_applications', text:'Applications', value:'shared_applications',leaf:true,filename:'" . $filename . "', iconCls:'icon-shared_applications'}";
                                    $shared_objects[] = [
                                        "vsys" => $vsys,
                                        "type" => 'object',
                                        "element" => 'shared_applications',
                                        "text" => 'Applications',
                                        "value" => 'shared_applications',
                                        "leaf" => true,
                                        "filename" => $filename,
                                        "iconCls" => 'icon-shared_applications',
                                        "id" => $x
                                    ];
                                    $getApps->free();
                                }
                            }
                            # Application Filters
                            $getApps = $projectdb->query("SELECT id FROM applications_filters WHERE source='$source' AND vsys = 'shared' LIMIT 1");
                            if ($getApps->num_rows == 1) {
                                $x++;
                                $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='object' AND element='shared_applications_filters' AND map_filename!='';");
                                if ($getTask->num_rows == 0) {
                                    $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='object' AND element='shared_applications_filters';");
                                    $exec[] = "('$filename','$vsys','object','shared_applications_filters','')";
//                                $shared_objects[] = "{vsys:'" . $vsys . "',type:'object',element:'shared_applications_filters', text:'Applications Filters', value:'shared_applications_filters',leaf:true,filename:'" . $filename . "', iconCls:'icon-shared_applications_filter'}";
                                    $shared_objects[] = [
                                        "vsys" => $vsys,
                                        "type" => 'object',
                                        "element" => 'shared_applications_filters',
                                        "text" => 'Applications Filters',
                                        "value" => 'shared_applications_filters',
                                        "leaf" => true,
                                        "filename" => $filename,
                                        "iconCls" => 'icon-shared_applications_filter',
                                        "id" => $x
                                    ];
                                    $getApps->free();
                                }
                            }
                            # Applications Groups
                            $getApps = $projectdb->query("SELECT id FROM applications_groups_id WHERE source='$source' AND vsys = 'shared' LIMIT 1");
                            if ($getApps->num_rows == 1) {
                                $x++;
                                $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='object' AND element='shared_applications_groups' AND map_filename!='';");
                                if ($getTask->num_rows == 0) {
                                    $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='object' AND element='shared_applications_groups';");
                                    $exec[] = "('$filename','$vsys','object','shared_applications_groups','')";
//                                $shared_objects[] = "{vsys:'" . $vsys . "',type:'object',element:'shared_applications_groups', text:'Applications-Groups', value:'shared_applications_groups',leaf:true,filename:'" . $filename . "', iconCls:'icon-shared_applications_groups'}";
                                    $shared_objects[] = [
                                        "vsys" => $vsys,
                                        "type" => 'object',
                                        "element" => 'shared_applications_groups',
                                        "text" => 'Applications-Groups',
                                        "value" => 'shared_applications_groups_id',
                                        "leaf" => true,
                                        "filename" => $filename,
                                        "iconCls" => 'icon-shared_applications_groups',
                                        "id" => $x
                                    ];
                                    $getApps->free();
                                }
                            }
                            # Tags
                            $getApps = $projectdb->query("SELECT id FROM tag WHERE source='$source' AND vsys = 'shared' LIMIT 1;");
                            if ($getApps->num_rows == 1) {
                                $x++;
                                $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='object' AND element='shared_tag' AND map_filename!='';");
                                if ($getTask->num_rows == 0) {
                                    $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='object' AND element='shared_tag';");
                                    $exec[] = "('$filename','$vsys','object','shared_tag','')";
//                                $shared_objects[] = "{vsys:'" . $vsys . "',type:'object',element:'shared_tag', text:'Tags', value:'shared_tag',leaf:true,filename:'" . $filename . "', iconCls:'icon-shared_tags'}";
                                    $shared_objects[] = [
                                        "vsys" => $vsys,
                                        "type" => 'object',
                                        "element" => 'shared_tag',
                                        "text" => 'Tags',
                                        "value" => 'shared_tag',
                                        "leaf" => true,
                                        "filename" => $filename,
                                        "iconCls" => 'icon-shared_tags',
                                        "id" => $x
                                    ];
                                    $getApps->free();
                                }
                            }
                            # Response Pages
                            $shared_response_pages = array();
                            $getNetwork = $projectdb->query("SELECT type FROM response_pages WHERE source='$source' AND vsys = 'shared' AND template='$template';");
                            if ($getNetwork->num_rows > 0) {
                                while ($vrs = $getNetwork->fetch_assoc()) {
                                    $vrname = $vrs['type'];
                                    $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND template='$template' AND type='shared_response_pages' AND element='$vrname' AND map_filename!='';");
                                    if ($getTask->num_rows == 0) {
                                        $x++;
                                        $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND template='$template' AND type='shared_response_pages' AND element='$vrname';");
                                        $exec[] = "('$filename','$vsys','shared_response_pages','$vrname','$template')";
//                                    $shared_response_pages[] = "{vsys:'" . $vsys . "',type:'shared_response_pages',element:'$vrname', text:'$vrname', value:'$vrname',leaf:true, filename:'" . $filename . "',iconCls:'icon-response_page'}";
                                        $shared_response_pages[] = [
                                            "vsys" => $vsys,
                                            "template"  =>$template,
                                            "type" => 'shared_response_pages',
                                            "element" => '$vrname',
                                            "text" => $vrname,
                                            "value" => $vrname,
                                            "leaf" => true,
                                            "filename" => $filename,
                                            "iconCls" => 'icon-response_page',
                                            "id" => $x
                                        ];
                                    }
                                }
                                //if (count($shared_response_pages>0)){
                                //	$shared_objects[]="{template:'".$template."',type:'shared_response_pages',element:'all', text:'Response-Pages', value:'network',leaf:false, filename:'".$filename."',iconCls:'icon-response_page',children:[".implode(",",$shared_response_pages)."]}";
                                //	unset($shared_response_pages);
                                //}
                                $getNetwork->free();
                            }
                            # Policies
                            # Security Rules
                            $getSecurity = $projectdb->query("SELECT id FROM security_rules WHERE source='$source' AND vsys='$vsys' LIMIT 1");
                            if ($getSecurity->num_rows == 1) {
                                $x++;
                                $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='policy' AND element='security' AND map_filename!='';");
                                if ($getTask->num_rows == 0) {
                                    $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='policy' AND element='security';");
                                    $exec[] = "('$filename','$vsys','policy','security','')";
//                                $policies[] = "{vsys:'" . $vsys . "',type:'policy',element:'security', text:'Security', value:'security',leaf:true,filename:'" . $filename . "', iconCls:'icon-securityrule'}";
                                    $policies[] = [
                                        "vsys" => $vsys,
                                        "type" => 'policy',
                                        "element" => 'security',
                                        "text" => 'Security',
                                        "value" => 'security',
                                        "leaf" => true,
                                        "filename" => $filename,
                                        "iconCls" => 'icon-securityrule',
                                        "id" => $x
                                    ];
                                    $getSecurity->free();
                                }
                            }
                            # Nat Rules
                            $getNat = $projectdb->query("SELECT id FROM nat_rules WHERE source='$source' AND vsys='$vsys' LIMIT 1;");
                            if ($getNat->num_rows == 1) {
                                $x++;
                                $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='policy' AND element='nat' AND map_filename!='';");
                                if ($getTask->num_rows == 0) {
                                    $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='policy' AND element='nat';");
                                    $exec[] = "('$filename','$vsys','policy','nat','')";
//                                $policies[] = "{vsys:'" . $vsys . "',type:'policy',element:'nat', text:'Nat', value:'nat',leaf:true, filename:'" . $filename . "',iconCls:'icon-rulenat'}";
                                    $policies[] = [
                                        "vsys" => $vsys,
                                        "type" => 'policy',
                                        "element" => 'nat',
                                        "text" => 'Nat',
                                        "value" => 'nat',
                                        "leaf" => true,
                                        "filename" => $filename,
                                        "iconCls" => 'icon-rulenat',
                                        "id" => $x
                                    ];
                                    $getNat->free();
                                }
                            }
                        }
                        else {
                            # Objects
                            # Reports
                            $getAddress = $projectdb->query("SELECT id FROM reports WHERE source='$source' AND vsys='$vsys' LIMIT 1");
                            //echo "7. SELECT id FROM schedules WHERE source='$source' AND vsys='$vsys' LIMIT 1\n";
                            if ($getAddress->num_rows == 1) {
                                $x++;
                                $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='object' AND element='reports' AND map_filename!='';");
                                if ($getTask->num_rows == 0) {
                                    $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='object' AND element='reports';");
                                    $exec[] = "('$filename','$vsys','object','reports','')";
//                                $objects[] = "{vsys:'" . $vsys . "',type:'object',element:'schedules', text:'Schedules', value:'schedules',leaf:true, iconCls:'icon-schedules',filename:'" . $filename . "'}";
                                    $objects[] = [
                                        "vsys" => $vsys,
                                        "type" => 'object',
                                        "element" => 'reports',
                                        "text" => 'Reports',
                                        "value" => 'reports',
                                        "leaf" => true,
                                        "iconCls" => 'icon-schedules',
                                        "filename" => $filename,
                                        "id" => $x
                                    ];
                                    $getAddress->free();
                                }
                            }
                            #Schedules
                            $getAddress = $projectdb->query("SELECT id FROM schedules WHERE source='$source' AND vsys='$vsys' LIMIT 1");
                            //echo "7. SELECT id FROM schedules WHERE source='$source' AND vsys='$vsys' LIMIT 1\n";
                            if ($getAddress->num_rows == 1) {
                                $x++;
                                $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='object' AND element='schedules' AND map_filename!='';");
                                if ($getTask->num_rows == 0) {
                                    $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='object' AND element='schedules';");
                                    $exec[] = "('$filename','$vsys','object','schedules','')";
//                                $objects[] = "{vsys:'" . $vsys . "',type:'object',element:'schedules', text:'Schedules', value:'schedules',leaf:true, iconCls:'icon-schedules',filename:'" . $filename . "'}";
                                    $objects[] = [
                                        "vsys" => $vsys,
                                        "type" => 'object',
                                        "element" => 'schedules',
                                        "text" => 'Schedules',
                                        "value" => 'schedules',
                                        "leaf" => true,
                                        "iconCls" => 'icon-schedules',
                                        "filename" => $filename,
                                        "id" => $x
                                    ];
                                    $getAddress->free();
                                }
                            }
                            $getProfiles = $projectdb->query("SELECT name FROM profiles WHERE source='$source' AND vsys='$vsys' AND name!='strict' AND name!='default';");
                            if ($getProfiles->num_rows > 0) {
                                $x++;
                                $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='profiles' AND element='profiles' AND map_filename!='';");
                                if ($getTask->num_rows == 0) {
                                    $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='profiles' AND element='profiles';");
                                    $exec[] = "('$filename','$vsys','profiles','profiles','')";
//                                $profiles[] = "{vsys:'" . $vsys . "',type:'object',element:'profiles', text:'Security', value:'profiles',leaf:true, iconCls:'icon-profile_group',filename:'" . $filename . "'}";
                                    $profiles[] = [
                                        "vsys" => $vsys,
                                        "type" => 'object',
                                        "element" => 'profiles',
                                        "text" => 'Secuirty/Content',
                                        "value" => 'profiles',
                                        "leaf" => true,
                                        "iconCls" => 'icon-profile_group',
                                        "filename" => $filename,
                                        "id" => $x
                                    ];
                                    $getProfiles->free();
                                }
                            }
                            $getProfiles = $projectdb->query("SELECT name FROM log_settings WHERE source='$source' AND vsys='$vsys' AND type='profiles';");
                            if ($getProfiles->num_rows > 0) {
                                $x++;
                                $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='log_settings' AND element='log_settings' AND map_filename!='';");
                                if ($getTask->num_rows == 0) {
                                    $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='log_settings' AND element='log_settings';");
                                    $exec[] = "('$filename','$vsys','log_settings','log_settings','')";
//                                $profiles[] = "{vsys:'" . $vsys . "',type:'object',element:'log_settings', text:'Log Forwarding', value:'log_settings',leaf:true, iconCls:'icon-log_forwarding',filename:'" . $filename . "'}";
                                    $profiles[] = [
                                        "vsys" => $vsys,
                                        "type" => 'object',
                                        "element" => 'log_settings',
                                        "text" => 'Log Forwarding',
                                        "value" => 'log_settings',
                                        "leaf" => true,
                                        "iconCls" => 'icon-log_forwarding',
                                        "filename" => $filename,
                                        "id" => $x
                                    ];
                                    $getProfiles->free();
                                }
                            }
                            $getProfiles = $projectdb->query("SELECT name FROM profiles_groups WHERE source='$source' AND vsys='$vsys';");
                            if ($getProfiles->num_rows > 0) {
                                $x++;
                                $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='profiles_groups' AND element='profiles_groups' AND map_filename!='';");
                                if ($getTask->num_rows == 0) {
                                    $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='profiles_groups' AND element='profiles_groups';");
                                    $exec[] = "('$filename','$vsys','profiles_groups','profiles_groups','')";
//                                $profiles[] = "{vsys:'" . $vsys . "',type:'object',element:'profiles_groups', text:'Security Group', value:'profiles_groups',leaf:true, iconCls:'icon-profile_group',filename:'" . $filename . "'}";
                                    $profiles[] = [
                                        "vsys" => $vsys,
                                        "type" => 'object',
                                        "element" => 'profiles_groups',
                                        "text" => 'Security Group',
                                        "value" => 'profiles_groups',
                                        "leaf" => true,
                                        "iconCls" => 'icon-profile_group',
                                        "filename" => $filename,
                                        "id" => $x
                                    ];
                                    $getProfiles->free();
                                }
                            }
                            # Address
                            $getAddress = $projectdb->query("SELECT id FROM address WHERE source='$source' AND vsys='$vsys' LIMIT 1");
                            if ($getAddress->num_rows == 1) {
                                $x++;
                                $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='object' AND element='address' AND map_filename!='';");
                                if ($getTask->num_rows == 0) {
                                    $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='object' AND element='address';");
                                    $exec[] = "('$filename','$vsys','object','address','')";
//                                $objects[] = "{vsys:'" . $vsys . "',type:'object',element:'address', text:'Address', value:'address',leaf:true, iconCls:'icon-address',filename:'" . $filename . "'}";
                                    $objects[] = [
                                        "vsys" => $vsys,
                                        "type" => 'object',
                                        "element" => 'address',
                                        "text" => 'Address',
                                        "value" => 'address',
                                        "leaf" => true,
                                        "iconCls" => 'icon-address',
                                        "filename" => $filename,
                                        "id" => $x
                                    ];
                                    $getAddress->free();
                                }
                            }
                            # Address Groups
                            $getAddressGroups = $projectdb->query("SELECT id FROM address_groups_id WHERE source='$source' AND vsys='$vsys' LIMIT 1");
                            if ($getAddressGroups->num_rows == 1) {
                                $x++;
                                $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='object' AND element='address_groups' AND map_filename!='';");
                                if ($getTask->num_rows == 0) {
                                    $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='object' AND element='address_groups';");
                                    $exec[] = "('$filename','$vsys','object','address_groups','')";
//                                $objects[] = "{vsys:'" . $vsys . "',type:'object',element:'address_groups', text:'Address-Groups', value:'address_groups_id',leaf:true,filename:'" . $filename . "', iconCls:'icon-address_groups'}";
                                    $objects[] = [
                                        "vsys" => $vsys,
                                        "type" => 'object',
                                        "element" => 'address_groups',
                                        "text" => 'Address-Groups',
                                        "value" => 'address_groups_id',
                                        "leaf" => true,
                                        "filename" => $filename,
                                        "iconCls" => 'icon-address_groups',
                                        "id" => $x
                                    ];
                                    $getAddressGroups->free();
                                }
                            }
                            # Services
                            $getServices = $projectdb->query("SELECT id FROM services WHERE source='$source' AND vsys='$vsys' LIMIT 1");
                            if ($getServices->num_rows == 1) {
                                $x++;
                                $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='object' AND element='services' AND map_filename!='';");
                                if ($getTask->num_rows == 0) {
                                    $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='object' AND element='services';");
                                    $exec[] = "('$filename','$vsys','object','services','')";
//                                $objects[] = "{vsys:'" . $vsys . "',type:'object',element:'services', text:'Services', value:'services',leaf:true,filename:'" . $filename . "', iconCls:'icon-services'}";
                                    $objects[] = [
                                        "vsys" => $vsys,
                                        "type" => 'object',
                                        "element" => 'services',
                                        "text" => 'Services',
                                        "value" => 'services',
                                        "leaf" => true,
                                        "filename" => $filename,
                                        "iconCls" => 'icon-services',
                                        "id" => $x
                                    ];
                                    $getServices->free();
                                }
                            }
                            # Services Groups
                            $getServicesGroups = $projectdb->query("SELECT id FROM services_groups_id WHERE source='$source' AND vsys='$vsys' LIMIT 1");
                            if ($getServicesGroups->num_rows == 1) {
                                $x++;
                                $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='object' AND element='services_groups' AND map_filename!='';");
                                if ($getTask->num_rows == 0) {
                                    $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='object' AND element='services_groups';");
                                    $exec[] = "('$filename','$vsys','object','services_groups','')";
//                                $objects[] = "{vsys:'" . $vsys . "',type:'object',element:'services_groups', text:'Services-Groups', value:'services_groups_id',leaf:true,filename:'" . $filename . "', iconCls:'icon-services_groups'}";
                                    $objects[] = [
                                        "vsys" => $vsys,
                                        "type" => 'object',
                                        "element" => 'services_groups',
                                        "text" => 'Services-Groups',
                                        "value" => 'services_groups_id',
                                        "leaf" => true,
                                        "filename" => $filename,
                                        "iconCls" => 'icon-services_groups',
                                        "id" => $x
                                    ];
                                    $getServicesGroups->free();
                                }
                            }
                            # Regions
                            $getServicesGroups = $projectdb->query("SELECT id FROM regions WHERE source='$source' AND vsys='$vsys' LIMIT 1");
                            if ($getServicesGroups->num_rows == 1) {
                                $x++;
                                $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='object' AND element='regions' AND map_filename!='';");
                                if ($getTask->num_rows == 0) {
                                    $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='object' AND element='regions';");
                                    $exec[] = "('$filename','$vsys','object','regions','')";
//                                $objects[] = "{vsys:'" . $vsys . "',type:'object',element:'regions', text:'Regions', value:'regions',leaf:true,filename:'" . $filename . "', iconCls:'icon-regions'}";
                                    $objects[] = [
                                        "vsys" => $vsys,
                                        "type" => 'object',
                                        "element" => 'regions',
                                        "text" => 'Regions',
                                        "value" => 'regions',
                                        "leaf" => true,
                                        "filename" => $filename,
                                        "iconCls" => 'icon-regions',
                                        "id" => $x
                                    ];
                                    $getServicesGroups->free();
                                }
                            }
                            # Applications
                            $getApps = $projectdb->query("SELECT id FROM applications WHERE source='$source' AND vsys='$vsys' LIMIT 1");
                            if ($getApps->num_rows == 1) {
                                $x++;
                                $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='object' AND element='applications' AND map_filename!='';");
                                if ($getTask->num_rows == 0) {
                                    $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='object' AND element='applications';");
                                    $exec[] = "('$filename','$vsys','object','applications','')";
//                                $objects[] = "{vsys:'" . $vsys . "',type:'object',element:'applications', text:'Applications', value:'applications',leaf:true,filename:'" . $filename . "', iconCls:'icon-applications'}";
                                    $objects[] = [
                                        "vsys" => $vsys,
                                        "type" => 'object',
                                        "element" => 'applications',
                                        "text" => 'Applications',
                                        "value" => 'applications',
                                        "leaf" => true,
                                        "filename" => $filename,
                                        "iconCls" => 'icon-applications',
                                        "id" => $x
                                    ];
                                    $getApps->free();
                                }
                            }
                            # Application Filters
                            $getApps = $projectdb->query("SELECT id FROM applications_filters WHERE source='$source' AND vsys='$vsys' LIMIT 1");
                            if ($getApps->num_rows == 1) {
                                $x++;
                                $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='object' AND element='applications_filters' AND map_filename!='';");
                                if ($getTask->num_rows == 0) {
                                    $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='object' AND element='applications_filters';");
                                    $exec[] = "('$filename','$vsys','object','applications_filters','')";
//                                $objects[] = "{vsys:'" . $vsys . "',type:'object',element:'applications_filters', text:'Applications Filters', value:'applications_filters',leaf:true,filename:'" . $filename . "', iconCls:'icon-applications_filter'}";
                                    $objects[] = [
                                        "vsys" => $vsys,
                                        "type" => 'object',
                                        "element" => 'applications_filters',
                                        "text" => 'Applications Filters',
                                        "value" => 'applications_filters',
                                        "leaf" => true,
                                        "filename" => $filename,
                                        "iconCls" => 'icon-applications_filter',
                                        "id" => $x
                                    ];
                                    $getApps->free();
                                }
                            }
                            # Applications Groups
                            $getApps = $projectdb->query("SELECT id FROM applications_groups_id WHERE source='$source' AND vsys='$vsys' LIMIT 1");
                            if ($getApps->num_rows == 1) {
                                $x++;
                                $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='object' AND element='applications_groups' AND map_filename!='';");
                                if ($getTask->num_rows == 0) {
                                    $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='object' AND element='applications_groups';");
                                    $exec[] = "('$filename','$vsys','object','applications_groups','')";
//                                $objects[] = "{vsys:'" . $vsys . "',type:'object',element:'applications_groups', text:'Applications-Groups', value:'applications_groups',leaf:true,filename:'" . $filename . "', iconCls:'icon-applications_groups'}";
                                    $objects[] = [
                                        "vsys" => $vsys,
                                        "type" => 'object',
                                        "element" => 'applications_groups',
                                        "text" => 'Applications-Groups',
                                        "value" => 'applications_groups_id',
                                        "leaf" => true,
                                        "filename" => $filename,
                                        "iconCls" => 'icon-applications_groups',
                                        "id" => $x
                                    ];
                                    $getApps->free();
                                }
                            }
                            # Tags
                            $getApps = $projectdb->query("SELECT id FROM tag WHERE source='$source' AND vsys='$vsys' LIMIT 1");
                            if ($getApps->num_rows == 1) {
                                $x++;
                                $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='object' AND element='tag' AND map_filename!='';");
                                if ($getTask->num_rows == 0) {
                                    $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='object' AND element='tag';");
                                    $exec[] = "('$filename','$vsys','object','tag','')";
//                                $objects[] = "{vsys:'" . $vsys . "',type:'object',element:'tag', text:'Tags', value:'tag',leaf:true,filename:'" . $filename . "', iconCls:'icon-tags'}";
                                    $objects[] = [
                                        "vsys" => $vsys,
                                        "type" => 'object',
                                        "element" => 'tag',
                                        "text" => 'Tags',
                                        "value" => 'tag',
                                        "leaf" => true,
                                        "filename" => $filename,
                                        "iconCls" => 'icon-tags',
                                        "id" => $x
                                    ];
                                    $getApps->free();
                                }
                            }

                            if ($isPanorama == 0) {
                                #zones
                                $getNetwork = $projectdb->query("SELECT name FROM zones WHERE source='$source' AND vsys='$vsys';");
                                if ($getNetwork->num_rows > 0) {
                                    while ($vrs = $getNetwork->fetch_assoc()) {
                                        $vrname = $vrs['name'];
                                        $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='zones' AND element='$vrname' AND map_filename!='';");
                                        if ($getTask->num_rows == 0) {
                                            $x++;
                                            $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND template='$template' AND type='zones' AND element='$vrname';");
                                            $exec[] = "('$filename','$vsys','zones','$vrname','$template')";
//                                        $zones[] = "{vsys:'" . $vsys . "',template:'" . $template . "',type:'zones',element:'$vrname', text:'$vrname', value:'$vrname',leaf:true, filename:'" . $filename . "',iconCls:'icon-zone'}";
                                            $zones[] = [
                                                "vsys" => $vsys,
                                                "template" => $template,
                                                "type" => 'zones',
                                                "element" => $vrname,
                                                "text" => $vrname,
                                                "value" => $vrname,
                                                "leaf" => true,
                                                "filename" => $filename,
                                                "iconCls" => 'icon-zone',
                                                "id" => $x
                                            ];
                                        }
                                    }
                                    $getNetwork->free();
                                }
                            }

                            # Policies
                            # Security Rules
                            $getSecurity = $projectdb->query("SELECT id FROM security_rules WHERE source='$source' AND vsys='$vsys' LIMIT 1");
                            if ($getSecurity->num_rows == 1) {
                                $x++;
                                $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='policy' AND element='security' AND map_filename!='';");
                                if ($getTask->num_rows == 0) {
                                    $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='policy' AND element='security';");
                                    $exec[] = "('$filename','$vsys','policy','security','')";
//                                $policies[] = "{vsys:'" . $vsys . "',type:'policy',element:'security', text:'Security', value:'security',leaf:true,filename:'" . $filename . "', iconCls:'icon-securityrule'}";
                                    $policies[] = [
                                        "vsys" => $vsys,
                                        "type" => 'policy',
                                        "element" => 'security',
                                        "text" => 'Security',
                                        "value" => 'security',
                                        "leaf" => true,
                                        "filename" => $filename,
                                        "iconCls" => 'icon-securityrule',
                                        "id" => $x
                                    ];
                                    $getSecurity->free();
                                }
                            }
                            # Nat Rules
                            $getNat = $projectdb->query("SELECT id FROM nat_rules WHERE source='$source' AND vsys='$vsys' LIMIT 1;");
                            if ($getNat->num_rows == 1) {
                                $x++;
                                $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='policy' AND element='nat' AND map_filename!='';");
                                if ($getTask->num_rows == 0) {
                                    $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='policy' AND element='nat';");
                                    $exec[] = "('$filename','$vsys','policy','nat','')";
//                                $policies[] = "{vsys:'" . $vsys . "',type:'policy',element:'nat', text:'Nat', value:'nat',leaf:true, filename:'" . $filename . "',iconCls:'icon-rulenat'}";
                                    $policies[] = [
                                        "vsys" => $vsys,
                                        "type" => 'policy',
                                        "element" => 'nat',
                                        "text" => 'Nat',
                                        "value" => 'nat',
                                        "leaf" => true,
                                        "filename" => $filename,
                                        "iconCls" => 'icon-rulenat',
                                        "id" => $x
                                    ];
                                    $getNat->free();
                                }
                            }
                            # Application Override
                            $getAppOverride = $projectdb->query("SELECT id FROM appoverride_rules WHERE source='$source' AND vsys='$vsys' LIMIT 1;");
                            if ($getAppOverride->num_rows == 1) {
                                $x++;
                                $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='policy' AND element='appoverride' AND map_filename!='';");
                                if ($getTask->num_rows == 0) {
                                    $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='policy' AND element='appoverride';");
                                    $exec[] = "('$filename','$vsys','policy','appoverride','')";
//                                $policies[] = "{vsys:'" . $vsys . "',type:'policy',element:'appoverride', text:'App Override', value:'appoverride',leaf:true, filename:'" . $filename . "',iconCls:'icon-appoverride'}";
                                    $policies[] = [
                                        "vsys" => $vsys,
                                        "type" => 'policy',
                                        "element" => 'appoverride',
                                        "text" => 'App Override',
                                        "value" => 'appoverride',
                                        "leaf" => true,
                                        "filename" => $filename,
                                        "iconCls" => 'icon-appoverride',
                                        "id" => $x
                                    ];
                                    $getAppOverride->free();
                                }
                            }

                            /*$getOthers = $projectdb->query("SELECT id FROM other_rules WHERE source='$source' AND vsys='$vsys' LIMIT 1;");
                            if ($getOthers->num_rows == 1) {
                                $x++;
                                $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='policy' AND element='others' AND map_filename!='';");
                                if ($getTask->num_rows == 0) {
                                    $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='policy' AND element='others';");
                                    $exec[] = "('$filename','$vsys','policy','others','')";
//                                $policies[] = "{vsys:'" . $vsys . "',type:'policy',element:'others', text:'Other Policies', value:'others',leaf:true, filename:'" . $filename . "',iconCls:'icon-decryption'}";
                                    $policies[] = [
                                        "vsys" => $vsys,
                                        "type" => 'policy',
                                        "element" => 'others',
                                        "text" => 'Other Policies',
                                        "value" => 'others',
                                        "leaf" => true,
                                        "filename" => $filename,
                                        "iconCls" => 'icon-decryption',
                                        "id" => $x
                                    ];
                                    $getOthers->free();
                                }
                            }*/

                            # Authentication Rules ( > version 8)
                            $getAuthentication = $projectdb->query("SELECT id FROM authentication_rules WHERE source='$source' AND vsys='$vsys' LIMIT 1;");
                            if ($getAuthentication->num_rows == 1) {
                                $x++;
                                $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='policy' AND element='authentication' AND map_filename!='';");
                                if ($getTask->num_rows == 0) {
                                    $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='policy' AND element='authentication';");
                                    $exec[] = "('$filename','$vsys','policy','authentication','')";
                                    $policies[] = [
                                        "vsys" => $vsys,
                                        "type" => 'policy',
                                        "element" => 'authentication',
                                        "text" => 'Authentication',
                                        "value" => 'authentication',
                                        "leaf" => true,
                                        "filename" => $filename,
                                        "iconCls" => 'icon-authentication',
                                        "id" => $x
                                    ];
                                    $getAuthentication->free();
                                }
                            }

                            # Captive Portal Rules (version 7)
                            $getCaptivePortal = $projectdb->query("SELECT id FROM captiveportal_rules WHERE source='$source' AND vsys='$vsys' LIMIT 1;");
                            if ($getCaptivePortal->num_rows == 1) {
                                $x++;
                                $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='policy' AND element='captiveportal' AND map_filename!='';");
                                if ($getTask->num_rows == 0) {
                                    $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='policy' AND element='captiveportal';");
                                    $exec[] = "('$filename','$vsys','policy','captiveportal','')";
                                    $policies[] = [
                                        "vsys" => $vsys,
                                        "type" => 'policy',
                                        "element" => 'captiveportal',
                                        "text" => 'Captive Portal',
                                        "value" => 'captiveportal',
                                        "leaf" => true,
                                        "filename" => $filename,
                                        "iconCls" => 'icon-authentication',
                                        "id" => $x
                                    ];
                                    $getCaptivePortal->free();
                                }
                            }

                            # Decryption Rules
                            $getDecryption = $projectdb->query("SELECT id FROM decryption_rules WHERE source='$source' AND vsys='$vsys' LIMIT 1;");
                            if ($getDecryption->num_rows == 1) {
                                $x++;
                                $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='policy' AND element='decryption' AND map_filename!='';");
                                if ($getTask->num_rows == 0) {
                                    $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='policy' AND element='decryption';");
                                    $exec[] = "('$filename','$vsys','policy','decryption','')";
                                    $policies[] = [
                                        "vsys"      =>$vsys,
                                        "type"      =>'policy',
                                        "element"   =>'decryption',
                                        "text"      =>'Decryption',
                                        "value"     =>'decryption',
                                        "leaf"      =>true,
                                        "filename"  =>$filename,
                                        "iconCls"   =>'icon-decryption',
                                        "id"        =>$x
                                    ];
                                    $getDecryption->free();
                                }
                            }

                            # DoS Rules
                            $getDoS = $projectdb->query("SELECT id FROM dos_rules WHERE source='$source' AND vsys='$vsys' LIMIT 1;");
                            if ($getDoS->num_rows == 1) {
                                $x++;
                                $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='policy' AND element='dos' AND map_filename!='';");
                                if ($getTask->num_rows == 0) {
                                    $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='policy' AND element='dos';");
                                    $exec[] = "('$filename','$vsys','policy','dos','')";
                                    $policies[] = [
                                        "vsys"      =>$vsys,
                                        "type"      =>'policy',
                                        "element"   =>'dos',
                                        "text"      =>'DoS Protection',
                                        "value"     =>'dos',
                                        "leaf"      =>true,
                                        "filename"  =>$filename,
                                        "iconCls"   =>'icon-dos_protection',
                                        "id"        =>$x
                                    ];
                                    $getDoS->free();
                                }
                            }

                            # Policy Based Forwarding Rules
                            $getPBF = $projectdb->query("SELECT id FROM pbf_rules WHERE source='$source' AND vsys='$vsys' LIMIT 1;");
                            if ($getPBF->num_rows == 1) {
                                $x++;
                                $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='policy' AND element='pbf' AND map_filename!='';");
                                if ($getTask->num_rows == 0) {
                                    $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='policy' AND element='pbf';");
                                    $exec[] = "('$filename','$vsys','policy','pbf','')";
                                    $policies[] = [
                                        "vsys"      =>$vsys,
                                        "type"      =>'policy',
                                        "element"   =>'pbf',
                                        "text"      =>'Policy Based Forwarding',
                                        "value"     =>'pbf',
                                        "leaf"      =>true,
                                        "filename"  =>$filename,
                                        "iconCls"   =>'icon-pbf',
                                        "id"        =>$x
                                    ];
                                    $getPBF->free();
                                }
                            }

                            # QoS Rules
                            $getQoS = $projectdb->query("SELECT id FROM qos_rules WHERE source='$source' AND vsys='$vsys' LIMIT 1;");
                            if ($getQoS->num_rows == 1) {
                                $x++;
                                $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='policy' AND element='qos' AND map_filename!='';");
                                if ($getTask->num_rows == 0) {
                                    $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='policy' AND element='qos';");
                                    $exec[] = "('$filename','$vsys','policy','qos','')";
                                    $policies[] = [
                                        "vsys"      =>$vsys,
                                        "type"      =>'policy',
                                        "element"   =>'qos',
                                        "text"      =>'QoS',
                                        "value"     =>'qos',
                                        "leaf"      =>true,
                                        "filename"  =>$filename,
                                        "iconCls"   =>'icon-qos',
                                        "id"        =>$x
                                    ];
                                    $getQoS->free();
                                }
                            }

                            # Tunnel Inspection Rules
                            $getTunnelInsp = $projectdb->query("SELECT id FROM tunnel_inspect_rules WHERE source='$source' AND vsys='$vsys' LIMIT 1;");
                            if ($getTunnelInsp->num_rows == 1) {
                                $x++;
                                $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='policy' AND element='tunnel_inspect' AND map_filename!='';");
                                if ($getTask->num_rows == 0) {
                                    $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND vsys='$vsys' AND type='policy' AND element='tunnel_inspect';");
                                    $exec[] = "('$filename','$vsys','policy','tunnel_inspect','')";
                                    $policies[] = [
                                        "vsys"      =>$vsys,
                                        "type"      =>'policy',
                                        "element"   =>'tunnel_inspect',
                                        "text"      =>'Tunnel Inspection',
                                        "value"     =>'tunnel_inspect',
                                        "leaf"      =>true,
                                        "filename"  =>$filename,
                                        "iconCls"   =>'icon-tunnelinspection',
                                        "id"        =>$x
                                    ];
                                    $getTunnelInsp->free();
                                }
                            }

                            # Template Based (Network, Interfaces)
                            if (($template != "") AND ($onlyone == true)) {
                                if ($isPanorama == 1) {
                                    $onlyone = true;
                                } else {
                                    $onlyone = false;
                                }
                                $getNetwork = $projectdb->query("SELECT name FROM virtual_routers WHERE source='$source' AND template='$template';");
                                if ($getNetwork->num_rows > 0) {
                                    while ($vrs = $getNetwork->fetch_assoc()) {
                                        $vrname = $vrs['name'];
                                        $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND template='$template' AND type='virtual_router' AND element='$vrname' AND map_filename!='';");
                                        if ($getTask->num_rows == 0) {
                                            $x++;
                                            $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND template='$template' AND type='virtual_router' AND element='$vrname';");
                                            $exec[] = "('$filename','','virtual_router','$vrname','$template')";
                                            $network[] = [
                                                "template" => $template,
                                                "type" => 'virtual_router',
                                                "element" => $vrname,
                                                "text" => $vrname,
                                                "value" => $vrname,
                                                "leaf" => true,
                                                "filename" => $filename,
                                                "iconCls" => 'icon-vr',
                                                "id" => $x
                                            ];
                                        }
                                    }
                                    $getNetwork->free();
                                }
                                #Interfaces
                                $getNetwork = $projectdb->query("SELECT name FROM interfaces WHERE source='$source' AND template='$template' GROUP BY name;");
                                if ($getNetwork->num_rows > 0) {
                                    while ($vrs = $getNetwork->fetch_assoc()) {
                                        $vrname = $vrs['name'];
                                        $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND template='$template' AND type='interfaces' AND element='$vrname' AND map_filename!='';");
                                        if ($getTask->num_rows == 0) {
                                            $x++;
                                            $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND template='$template' AND type='interfaces' AND element='$vrname';");
                                            $exec[] = "('$filename','','interfaces','$vrname','$template')";
                                            $interfaces[] = [
                                                "template" => $template,
                                                "type" => 'interfaces',
                                                "element" => $vrname,
                                                "text" => $vrname,
                                                "value" => $vrname,
                                                "leaf" => true,
                                                "filename" => $filename,
                                                "iconCls" => 'icon-interfaces',
                                                "id" => $x
                                            ];
                                        }
                                    }
                                    $getNetwork->free();
                                }

                                # Interface Management Profile
                                $getNetwork = $projectdb->query("SELECT name FROM interface_management_profile WHERE source='$source' AND template='$template' AND name != '' GROUP BY name;");
                                if ($getNetwork->num_rows > 0) {
                                    while ($vrs = $getNetwork->fetch_assoc()) {
                                        $vrname = $vrs['name'];
                                        $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND template='$template' AND type='interface_management_profile' AND element='$vrname' AND map_filename!='';");
                                        if ($getTask->num_rows == 0) {
                                            $x++;
                                            $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND template='$template' AND type='interface_management_profile' AND element='$vrname';");
                                            $exec[] = "('$filename','','interface_management_profile','$vrname','$template')";
                                            $interface_management_profile[] = [
                                                "template" => $template,
                                                "type" => 'interface_management_profile',
                                                "element" => $vrname,
                                                "text" => $vrname,
                                                "value" => $vrname,
                                                "leaf" => true,
                                                "filename" => $filename,
                                                "iconCls" => 'icon-interface-mgmt',
                                                "id" => $x
                                            ];
                                        }
                                    }
                                    $getNetwork->free();
                                }

                                # IPSec Tunnels
                                $getNetwork = $projectdb->query("SELECT name FROM ipsec_tunnel WHERE source='$source' AND template='$template' AND name != '' GROUP BY name;");
                                if ($getNetwork->num_rows > 0) {
                                    while ($vrs = $getNetwork->fetch_assoc()) {
                                        $vrname = $vrs['name'];
                                        $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND template='$template' AND type='ipsec_tunnel' AND element='$vrname' AND map_filename!='';");
                                        if ($getTask->num_rows == 0) {
                                            $x++;
                                            $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND template='$template' AND type='ipsec_tunnel' AND element='$vrname';");
                                            $exec[] = "('$filename','','ipsec_tunnel','$vrname','$template')";
                                            $ipsec_tunnel[] = [
                                                "template" => $template,
                                                "type" => 'ipsec_tunnel',
                                                "element" => $vrname,
                                                "text" => $vrname,
                                                "value" => $vrname,
                                                "leaf" => true,
                                                "filename" => $filename,
                                                "iconCls" => 'icon-ipsec-tunnels',
                                                "id" => $x
                                            ];
                                        }
                                    }
                                    $getNetwork->free();
                                }

                                # IKE Gateways
                                $getNetwork = $projectdb->query("SELECT name FROM ike_gateways_profiles WHERE source='$source' AND template='$template' AND name != '' GROUP BY name;");
                                if ($getNetwork->num_rows > 0) {
                                    while ($vrs = $getNetwork->fetch_assoc()) {
                                        $vrname = $vrs['name'];
                                        $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND template='$template' AND type='ike_gateways_profiles' AND element='$vrname' AND map_filename!='';");
                                        if ($getTask->num_rows == 0) {
                                            $x++;
                                            $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND template='$template' AND type='ike_gateways_profiles' AND element='$vrname';");
                                            $exec[] = "('$filename','','ike_gateways_profiles','$vrname','$template')";
                                            $ike_gateways_profiles[] = [
                                                "template" => $template,
                                                "type" => 'ike_gateways_profiles',
                                                "element" => $vrname,
                                                "text" => $vrname,
                                                "value" => $vrname,
                                                "leaf" => true,
                                                "filename" => $filename,
                                                "iconCls" => 'icon-ike-gateways',
                                                "id" => $x
                                            ];
                                        }
                                    }
                                    $getNetwork->free();
                                }

                                # IPSec Crypto
                                $getNetwork = $projectdb->query("SELECT name FROM ipsec_crypto_profiles WHERE source='$source' AND template='$template' AND name != '' GROUP BY name;");
                                if ($getNetwork->num_rows > 0) {
                                    while ($vrs = $getNetwork->fetch_assoc()) {
                                        $vrname = $vrs['name'];
                                        $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND template='$template' AND type='ipsec_crypto_profiles' AND element='$vrname' AND map_filename!='';");
                                        if ($getTask->num_rows == 0) {
                                            $x++;
                                            $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND template='$template' AND type='ipsec_crypto_profiles' AND element='$vrname';");
                                            $exec[] = "('$filename','','ipsec_crypto_profiles','$vrname','$template')";
                                            $ipsec_crypto_profiles[] = [
                                                "template" => $template,
                                                "type" => 'ipsec_crypto_profiles',
                                                "element" => $vrname,
                                                "text" => $vrname,
                                                "value" => $vrname,
                                                "leaf" => true,
                                                "filename" => $filename,
                                                "iconCls" => 'icon-ipsec-crypto',
                                                "id" => $x
                                            ];
                                        }
                                    }
                                    $getNetwork->free();
                                }

                                # IKE Crypto
                                $getNetwork = $projectdb->query("SELECT name FROM ike_crypto_profiles WHERE source='$source' AND template='$template' AND name != '' GROUP BY name;");
                                if ($getNetwork->num_rows > 0) {
                                    while ($vrs = $getNetwork->fetch_assoc()) {
                                        $vrname = $vrs['name'];
                                        $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND template='$template' AND type='ike_crypto_profiles' AND element='$vrname' AND map_filename!='';");
                                        if ($getTask->num_rows == 0) {
                                            $x++;
                                            $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND template='$template' AND type='ike_crypto_profiles' AND element='$vrname';");
                                            $exec[] = "('$filename','','ike_crypto_profiles','$vrname','$template')";
                                            $ike_crypto_profiles[] = [
                                                "template" => $template,
                                                "type" => 'ike_crypto_profiles',
                                                "element" => $vrname,
                                                "text" => $vrname,
                                                "value" => $vrname,
                                                "leaf" => true,
                                                "filename" => $filename,
                                                "iconCls" => 'icon-ipsec-crypto',
                                                "id" => $x
                                            ];
                                        }
                                    }
                                    $getNetwork->free();
                                }

                                # Monitor Profile
                                $getNetwork = $projectdb->query("SELECT name FROM monitor_profile WHERE source='$source' AND template='$template' AND name != '' GROUP BY name;");
                                if ($getNetwork->num_rows > 0) {
                                    while ($vrs = $getNetwork->fetch_assoc()) {
                                        $vrname = $vrs['name'];
                                        $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND template='$template' AND type='monitor_profile' AND element='$vrname' AND map_filename!='';");
                                        if ($getTask->num_rows == 0) {
                                            $x++;
                                            $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND template='$template' AND type='monitor_profile' AND element='$vrname';");
                                            $exec[] = "('$filename','','monitor_profile','$vrname','$template')";
                                            $monitor_profile[] = [
                                                "template" => $template,
                                                "type" => 'monitor_profile',
                                                "element" => $vrname,
                                                "text" => $vrname,
                                                "value" => $vrname,
                                                "leaf" => true,
                                                "filename" => $filename,
                                                "iconCls" => 'icon-monitor',
                                                "id" => $x
                                            ];
                                        }
                                    }
                                    $getNetwork->free();
                                }

                                # GlobalProtect IPSec Crypto
                                $getNetwork = $projectdb->query("SELECT name FROM global_protect_app_ipsec_crypto_profiles WHERE source='$source' AND template='$template' AND name != '' GROUP BY name;");
                                if ($getNetwork->num_rows > 0) {
                                    while ($vrs = $getNetwork->fetch_assoc()) {
                                        $vrname = $vrs['name'];
                                        $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND template='$template' AND type='global_protect_app_ipsec_crypto_profiles' AND element='$vrname' AND map_filename!='';");
                                        if ($getTask->num_rows == 0) {
                                            $x++;
                                            $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND template='$template' AND type='global_protect_app_ipsec_crypto_profiles' AND element='$vrname';");
                                            $exec[] = "('$filename','','global_protect_app_ipsec_crypto_profiles','$vrname','$template')";
                                            $global_protect_app_ipsec_crypto_profiles[] = [
                                                "template" => $template,
                                                "type" => 'global_protect_app_ipsec_crypto_profiles',
                                                "element" => $vrname,
                                                "text" => $vrname,
                                                "value" => $vrname,
                                                "leaf" => true,
                                                "filename" => $filename,
                                                "iconCls" => 'icon-ipsec-crypto',
                                                "id" => $x
                                            ];
                                        }
                                    }
                                    $getNetwork->free();
                                }

                                # Vlans
                                $getNetwork = $projectdb->query("SELECT name FROM vlans WHERE source='$source' AND template='$template' AND name != '' GROUP BY name;");
                                if ($getNetwork->num_rows > 0) {
                                    while ($vrs = $getNetwork->fetch_assoc()) {
                                        $vrname = $vrs['name'];
                                        $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND template='$template' AND type='vlans' AND element='$vrname' AND map_filename!='';");
                                        if ($getTask->num_rows == 0) {
                                            $x++;
                                            $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND template='$template' AND type='vlans' AND element='$vrname';");
                                            $exec[] = "('$filename','','vlans','$vrname','$template')";
                                            $vlans[] = [
                                                "template" => $template,
                                                "type" => 'vlans',
                                                "element" => $vrname,
                                                "text" => $vrname,
                                                "value" => $vrname,
                                                "leaf" => true,
                                                "filename" => $filename,
                                                "iconCls" => 'icon-vlans',
                                                "id" => $x
                                            ];
                                        }
                                    }
                                    $getNetwork->free();
                                }

                                # Virtual Wires
                                $getNetwork = $projectdb->query("SELECT name FROM virtual_wires WHERE source='$source' AND template='$template' AND name != '' GROUP BY name;");
                                if ($getNetwork->num_rows > 0) {
                                    while ($vrs = $getNetwork->fetch_assoc()) {
                                        $vrname = $vrs['name'];
                                        $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND template='$template' AND type='virtual_wires' AND element='$vrname' AND map_filename!='';");
                                        if ($getTask->num_rows == 0) {
                                            $x++;
                                            $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND template='$template' AND type='virtual_wires' AND element='$vrname';");
                                            $exec[] = "('$filename','','virtual_wires','$vrname','$template')";
                                            $virtual_wires[] = [
                                                "template" => $template,
                                                "type" => 'virtual_wires',
                                                "element" => $vrname,
                                                "text" => $vrname,
                                                "value" => $vrname,
                                                "leaf" => true,
                                                "filename" => $filename,
                                                "iconCls" => 'icon-vwire',
                                                "id" => $x
                                            ];
                                        }
                                    }
                                    $getNetwork->free();
                                }

                            }

                            #Response Pages
                            $getNetwork = $projectdb->query("SELECT type FROM response_pages WHERE source='$source' AND template='$template' AND vsys='$vsys';");
                            if ($getNetwork->num_rows > 0) {
                                while ($vrs = $getNetwork->fetch_assoc()) {
                                    $vrname = $vrs['type'];
                                    $getTask = $projectdb->query("SELECT id FROM pending_tasks WHERE filename='$filename' AND template='$template' AND type='response_pages' AND element='$vrname' AND map_filename!='' AND vsys='$vsys';");
                                    if ($getTask->num_rows == 0) {
                                        $x++;
                                        $projectdb->query("DELETE FROM pending_tasks WHERE filename='$filename' AND template='$template' AND type='response_pages' AND element='$vrname' AND vsys='$vsys';");
                                        $exec[] = "('$filename','$vsys','response_pages','$vrname','$template')";
                                        $responsepage[] = [
                                            "template" => $template,
                                            "type" => 'response_pages',
                                            "element" => $vrname,
                                            "text" => $vrname,
                                            "value" => $vrname,
                                            "leaf" => true,
                                            "filename" => $filename,
                                            "iconCls" => 'icon-response_page',
                                            "vsys" => $vsys,
                                            "id" => $x
                                        ];
                                    }
                                }
                                $getNetwork->free();
                            }
                        }

                        if (!empty($shared_profiles)) {
                            $x++;
                            $echo2[] = [
                                "vsys" => $vsys,
                                "type" => 'shared_profiles',
                                "element" => 'all',
                                "text" => 'Profiles',
                                "value" => 'shared_profiles',
                                "leaf" => false,
                                "filename" => $filename,
                                "iconCls" => 'icon-profile_group',
                                "children" => $shared_profiles,
                                "id" => $x
                            ];
                            unset($shared_profiles);
                        }
                        if (!empty($shared_response_pages)) {
                            $x++;
                            $echo2[] = [
                                "vsys" => $vsys,
                                "template"  =>$template,
                                "type" => 'shared_response_pages',
                                "element" => 'all',
                                "text" => 'Response-Pages',
                                "value" => 'network',
                                "leaf" => false,
                                "filename" => $filename,
                                "iconCls" => 'icon-response_page',
                                "children" => $shared_response_pages,
                                "id" => $x
                            ];
                            unset($shared_response_pages);
                        }
                        if (!empty($shared_objects)) {
                            $x++;
                            $echo2[] = [
                                "vsys" => $vsys,
                                "type" => 'object',
                                "element" => 'all',
                                "text" => 'Objects',
                                "value" => 'objects',
                                "iconCls" => '',
                                "leaf" => false,
                                "filename" => $filename,
                                "children" => $shared_objects,
                                "id" => $x
                            ];
                        }
                        if (!empty($objects)) {
                            $x++;
                            $echo2[] = [
                                "vsys" => $vsys,
                                "type" => 'object',
                                "element" => 'all',
                                "text" => 'Objects',
                                "value" => 'objects',
                                "iconCls" => '',
                                "leaf" => false,
                                "filename" => $filename,
                                "children" => $objects,
                                "id" => $x
                            ];
                        }
                        if (!empty($profiles)) {
                            $x++;
                            $echo2[] = [
                                "vsys" => $vsys,
                                "type" => 'profiles',
                                "element" => 'all',
                                "text" => 'Profiles',
                                "value" => 'profiles',
                                "leaf" => false,
                                "filename" => $filename,
                                "iconCls" => 'icon-profile_group',
                                "children" => $profiles,
                                "id" => $x
                            ];
                        }
                        if (!empty($policies)) {
                            $x++;
                            $echo2[] = [
                                "vsys" => $vsys,
                                "type" => 'policy',
                                "element" => 'all',
                                "text" => 'Policies',
                                "value" => 'objects',
                                "iconCls" => '',
                                "leaf" => false,
                                "filename" => $filename,
                                "children" => $policies,
                                "id" => $x
                            ];
                        }
                        if (!empty($network)) {
                            $x++;
                            $echo3[] = [
                                "template" => $template,
                                "type" => 'virtual_router',
                                "element" => 'all',
                                "text" => 'Virtual Routers',
                                "value" => 'network',
                                "iconCls" => 'icon-vr',
                                "leaf" => false,
                                "filename" => $filename,
                                "children" => $network,
                                "id" => $x
                            ];
                        }
                        if (!empty($responsepage)) {
                            $x++;
                            $echo2[] = [
                                "vsys" => $vsys,
                                "template" => $template,
                                "type" => 'response_pages',
                                "element" => 'all',
                                "text" => 'Response Pages',
                                "value" => 'network',
                                "iconCls" => 'icon-response_page',
                                "leaf" => false,
                                "filename" => $filename,
                                "children" => $responsepage,
                                "id" => $x
                            ];
                        }
                        if (!empty($interfaces)) {
                            $x++;
                            $echo3[] = [
                                "template" => $template,
                                "type" => 'interfaces',
                                "element" => 'all',
                                "text" => 'Interfaces',
                                "value" => 'network',
                                "iconCls" => 'icon-interfaces',
                                "leaf" => false,
                                "filename" => $filename,
                                "children" => $interfaces,
                                "id" => $x
                            ];
                        }
                        if (!empty($interface_management_profile)) {
                            $x++;
                            $echo3[] = [
                                "template" => $template,
                                "type" => 'interface_management_profile',
                                "element" => 'all',
                                "text" => 'Interface Mgmt',
                                "value" => 'network',
                                "iconCls" => 'icon-interface-mgmt',
                                "leaf" => false,
                                "filename" => $filename,
                                "children" => $interface_management_profile,
                                "id" => $x
                            ];
                        }
                        if (!empty($ipsec_tunnel)) {
                            $x++;
                            $echo3[] = [
                                "template" => $template,
                                "type" => 'ipsec_tunnel',
                                "element" => 'all',
                                "text" => 'IPSec Tunnels',
                                "value" => 'network',
                                "iconCls" => 'icon-ipsec-tunnels',
                                "leaf" => false,
                                "filename" => $filename,
                                "children" => $ipsec_tunnel,
                                "id" => $x
                            ];
                        }
                        if (!empty($ike_gateways_profiles)) {
                            $x++;
                            $echo3[] = [
                                "template" => $template,
                                "type" => 'ike_gateways_profiles',
                                "element" => 'all',
                                "text" => 'IKE Gateways',
                                "value" => 'network',
                                "iconCls" => 'icon-ike-gateways',
                                "leaf" => false,
                                "filename" => $filename,
                                "children" => $ike_gateways_profiles,
                                "id" => $x
                            ];
                        }
                        if (!empty($ipsec_crypto_profiles)) {
                            $x++;
                            $echo3[] = [
                                "template" => $template,
                                "type" => 'ipsec_crypto_profiles',
                                "element" => 'all',
                                "text" => 'IPSec Crypto',
                                "value" => 'network',
                                "iconCls" => 'icon-ipsec-crypto',
                                "leaf" => false,
                                "filename" => $filename,
                                "children" => $ipsec_crypto_profiles,
                                "id" => $x
                            ];
                        }
                        if (!empty($ike_crypto_profiles)) {
                            $x++;
                            $echo3[] = [
                                "template" => $template,
                                "type" => 'ike_crypto_profiles',
                                "element" => 'all',
                                "text" => 'IKE Crypto',
                                "value" => 'network',
                                "iconCls" => 'icon-ipsec-crypto',
                                "leaf" => false,
                                "filename" => $filename,
                                "children" => $ike_crypto_profiles,
                                "id" => $x
                            ];
                        }
                        if (!empty($monitor_profile)) {
                            $x++;
                            $echo3[] = [
                                "template" => $template,
                                "type" => 'monitor_profile',
                                "element" => 'all',
                                "text" => 'Monitor Profile',
                                "value" => 'network',
                                "iconCls" => 'icon-monitor',
                                "leaf" => false,
                                "filename" => $filename,
                                "children" => $monitor_profile,
                                "id" => $x
                            ];
                        }
                        if (!empty($global_protect_app_ipsec_crypto_profiles)) {
                            $x++;
                            $echo3[] = [
                                "template" => $template,
                                "type" => 'global_protect_app_ipsec_crypto_profiles',
                                "element" => 'all',
                                "text" => 'GlobalProtect IPSec Crypto',
                                "value" => 'network',
                                "iconCls" => 'icon-ipsec-crypto',
                                "leaf" => false,
                                "filename" => $filename,
                                "children" => $global_protect_app_ipsec_crypto_profiles,
                                "id" => $x
                            ];
                        }
                        if (!empty($vlans)) {
                            $x++;
                            $echo3[] = [
                                "template" => $template,
                                "type" => 'vlans',
                                "element" => 'all',
                                "text" => 'VLANs',
                                "value" => 'network',
                                "iconCls" => 'icon-vlans',
                                "leaf" => false,
                                "filename" => $filename,
                                "children" => $vlans,
                                "id" => $x
                            ];
                        }
                        if (!empty($virtual_wires)) {
                            $x++;
                            $echo3[] = [
                                "template" => $template,
                                "type" => 'virtual_wires',
                                "element" => 'all',
                                "text" => 'Virtual Wires',
                                "value" => 'network',
                                "iconCls" => 'icon-vwire',
                                "leaf" => false,
                                "filename" => $filename,
                                "children" => $virtual_wires,
                                "id" => $x
                            ];
                        }
                        if (!empty($zones)) {
                            $x++;
                            $echo2[] = [
                                "vsys" => $vsys,
                                "template" => $template,
                                "type" => 'zones',
                                "element" => 'all',
                                "text" => 'Zones',
                                "value" => 'network',
                                "iconCls" => 'icon-zone',
                                "leaf" => false,
                                "filename" => $filename,
                                "children" => $zones,
                                "id" => $x
                            ];
                        }
                        if (!empty($echo3)) {
                            $x++;
                            $echo1[] = [
                                "template" => $template,
                                "text" => 'Network',
                                "value" => 'network',
                                "iconCls" => 'icon-network',
                                "leaf" => false,
                                "filename" => $filename,
                                "children" => $echo3,
                                "id" => $x
                            ];
                        }
                        if (!empty($echo2)) {
                            if ($vsys == "shared") {
                                $icon = "icon-shared_device";
                            } else {
                                $icon = "icon-device";
                            }
                            $x++;
                            $echo1[] = [
                                "vsys" => $vsys,
                                "text" => $vsys,
                                "value" => $vsys,
                                "iconCls" => $icon,
                                "leaf" => false,
                                "filename" => $filename,
                                "children" => $echo2,
                                "id" => $x
                            ];
                        }
                        if (!empty($echo1)) {
                            $echo_all = $echo1;
                        }
                    }
                    // Fin while getVsys
                }

                //if (($active == 1) AND ($isPanorama==0)){
                if ($active == 1){
                    if (isset($echo_all)) {
                        $master["children"] = $echo_all;
                        $master["leaf"] = false;
                    }
                }
                $echo_all = array();
                $master_all[] = $master;
            }
            $root = [
                'text'      =>'Root',
                'expanded'  =>true,
                'children'  =>$master_all,
                'id'        =>0
            ];

            echo json_encode($root);
        }

        $getAll->free();
        //print "[{id:1,value:'Filename1',text:'Filename 1',leaf:false, iconCls:'icon-chkpt',children: [{value:'vsys1',text:'vsys1',iconCls:'icon-device',leaf:false, children:[{text:'Security Policy', value:'security',leaf:true, iconCls:'icon-securityrule'}] }]}]";
        if (count($exec) > 0) {
            #INSERT ALL TASKS
            $out = implode(",", $exec);
            $projectdb->query("INSERT INTO pending_tasks (filename,vsys,type,element,template) VALUES " . $out . ";");
        }
    } 
    elseif ($type == "baseconfig_tree") {
        $getAll = $projectdb->query("SELECT id,device,ispanorama,active,version,vsys,filename,map_devicegroup,map_vsys,vendor FROM device_mapping WHERE baseconfig=1 GROUP BY filename;");
        $x = 0;
        if ($getAll->num_rows > 0) {
            while ($data = $getAll->fetch_assoc()) {
                $filename = $data['filename'];
                $vendor = $data['vendor'];
                $source = $data['id'];
                $devicegroup = $data['device'];
                $isPanorama = $data['ispanorama'];
                $version = $data['version'];

                //TODO: Export this $version calculation into a separate php
                if (preg_match("/^6\.0/", $version)) {
                    $version = 6;
                }
                elseif (preg_match("/^6\.1/", $version)) {
                    $version = 6.1;
                }
                elseif (preg_match("/^5\./", $version)) {
                    $version = 5;
                }
                elseif (preg_match("/^7\.0/", $version)) {
                    $version = 7;
                }
                elseif (preg_match("/^7\.1/", $version)) {
                    $version = 7.1;
                }
                elseif (preg_match("/^8\.0/", $version)) {
                    $version = 8;
                }
                elseif (preg_match("/^8\.1/", $version)) {
                    $version = 8.1;
                }
                elseif (preg_match("/^9\.0/", $version)) {
                    $version = 9;
                }
                elseif (preg_match("/^9\.1/", $version)) {
                    $version = 9.1;
                }
                if ($vendor == "Paloalto Networks") {
                    $vendor_icon = "icon-panw";
                }

                $x++;

                if ($isPanorama == 1) {
                    #Panorama
                    $echo = array();
                    $objects_tree = array();
                    $object=array();
                    $devicegroup_tree = array();
                    #Add Shared
                    $vsys = "shared";
                    $getObjects = $projectdb->query("SELECT filename,element FROM pending_tasks WHERE map_filename='$filename' AND map_vsys='$vsys' AND type='object'");
                    if ($getObjects->num_rows > 0) {
                        $object = array();
                        $echo_shared = array();
                        while ($mydata = $getObjects->fetch_assoc()) {
                            $src_filename = $mydata['filename'];
                            $element = $mydata['element'];

                            list($element_text, $iconCls) = getElementIcon($element);

                            $x++;

//                            $object[] = "{vsys:'" . $vsys . "',type:'object',element:'" . $element . "', text:'" . $element_text . " [" . $src_filename . "] <font style=text-decoration:underline; color=blue>(pending)</font></s>" . "', value:'" . $element . "',leaf:true, iconCls:'" . $iconCls . "',filename:'" . $filename . "'}";
                            $object[] = [
                                "vsys"      =>$vsys,
                                "type"      =>'object',
                                "element"   =>$element ,
                                "text"      =>$element_text . " [" . $src_filename . "] <font style=text-decoration:underline; color=blue>(pending)</font></s>" ,
                                "value"     =>$element ,
                                "leaf"      =>true,
                                "iconCls"   =>$iconCls,
                                "filename"  =>$filename,
                                "id"        =>$x
                            ];
                        }
                        $x++;
//                        $objects_tree[] = "{expanded:false, vsys:'" . $vsys . "',filename:'" . $filename . "',text:'Objects',value:'objects', element:'all', type:'object', leaf:false,children:[" . implode(",", $object) . "]}";
                        $objects_tree[] = [
                            "expanded"  =>false,
                            "vsys"      =>$vsys,
                            "filename"  =>$filename,
                            "text"      =>'Objects',
                            "value"     =>'objects',
                            "element"   =>'all',
                            "type"      =>'object',
                            "leaf"      =>false,
                            "children"  =>$object,
                            "id"        =>$x
                        ];
                    }

                    # Profiles
                    $getObjects = $projectdb->query("SELECT filename,element,type FROM pending_tasks WHERE map_filename='$filename' AND map_vsys='$vsys' AND (type='shared_profiles' OR type='shared_profiles_groups' OR type='shared_log_settings' OR type = 'profiles_groups' OR type = 'profiles')");
                    if ($getObjects->num_rows > 0) {
                        $object = array();
                        $echo_shared = array();
                        while ($mydata = $getObjects->fetch_assoc()) {
                            $src_filename = $mydata['filename'];
                            $element = $mydata['element'];
                            $thetype=$mydata['type'];

                            list($element_text, $iconCls) = getElementIcon($element);

//                            $object[] = "{vsys:'" . $vsys . "',type:'".$thetype."',element:'" . $element . "', text:'" . $element_text . " [" . $src_filename . "] <font style=text-decoration:underline; color=blue>(pending)</font></s>" . "', value:'" . $element . "',leaf:true, iconCls:'" . $iconCls . "',filename:'" . $filename . "'}";
                            $x++;
                            $object[] = [
                                "vsys"      =>$vsys,
                                "type"      =>$thetype,
                                "element"   =>$element,
                                "text"      =>$element_text."[".$src_filename."] <font style=text-decoration:underline; color=blue>(pending)</font></s>",
                                "value"     =>$element,
                                "leaf"      =>true,
                                "iconCls"   =>$iconCls,
                                "filename"  =>$filename,
                                "id"        =>$x
                            ];
                        }
                        //$devicegroup_tree_main[] = "{expanded:true,vsys:'" . $vsys . "',filename:'" . $filename . "',text:'Profiles',value:'shared_profiles', element:'all', type:'profiles', leaf:false,children:[" . implode(",", $object) . "], iconCls:'icon-shared_profile_group'}";
//                        $objects_tree[] = "{expanded:true,vsys:'" . $vsys . "',filename:'" . $filename . "',text:'Profiles',value:'shared_profiles', element:'all', type:'profiles', leaf:false,children:[" . implode(",", $object) . "], iconCls:'icon-shared_profile_group'}";
                        /*$objects_tree[] = [
                            "expanded"=>true,
                            "vsys"=> $vsys ,
                            "filename"=> $filename ,
                            "text"=>'Profiles',
                            "value"=>'shared_profiles',
                            "element"=>'all',
                            "type"=>'profiles',
                            "leaf"=>false,
                            "children"=>$object,
                            "iconCls"=>'icon-shared_profile_group'
                        ];
                        */
                        $x++;
//                        $objects_tree[] = "{expanded:false, vsys:'" . $vsys . "',filename:'" . $filename . "',text:'Objects',value:'objects', element:'all', type:'object', leaf:false,children:[" . implode(",", $object) . "]}";
                        $objects_tree[] = [
                            "expanded"  =>false,
                            "vsys"      =>$vsys,
                            "filename"  =>$filename,
                            "text"      =>'Profiles',
                            "value"     =>'shared_profiles',
                            "element"   =>'all',
                            "type"      =>'shared_profiles',
                            "iconCls"   =>'icon-profile_group',
                            "leaf"      =>false,
                            "children"  =>$object,
                            "id"        =>$x
                        ];
                        unset($objects);
                    }

                    $iconCls2 = "icon-shared_device";
                    if ( (isset($objects_tree)) AND (count($objects_tree) > 0) ) {
//                        $devicegroup_tree_main[] = "{expanded:true,vsys:'shared',filename:'" . $filename . "',text:'shared',value:'shared',iconCls:'" . $iconCls2 . "', leaf:false,children:[" . implode(",", $objects_tree) . "]}";
                        $x++;
                        $devicegroup_tree_main[] = [
                            "expanded"  =>true,
                            "vsys"      =>'shared',
                            "filename"  =>$filename,
                            "text"      =>'shared',
                            "value"     =>'shared',
                            "iconCls"   =>$iconCls2,
                            "leaf"      =>false,
                            "children"  =>$objects_tree,
                            "id"        =>$x
                        ];
                        unset($objects_tree);
                        unset($object);
                    }
                    else {
                        $iconCls2 = "icon-shared_device";
                        $text = "shared";
//                        $devicegroup_tree_main[] = "{expanded:true,vsys:'" . $vsys . "',filename:'" . $filename . "',text:'" . $text . "',value:'" . $vsys . "',iconCls:'" . $iconCls2 . "', leaf:true}";
                        $x++;
                        $devicegroup_tree_main[] = [
                            "expanded"  =>true,
                            "vsys"      =>$vsys,
                            "filename"  =>$filename,
                            "text"      =>$text,
                            "value"     =>$vsys,
                            "iconCls"   =>$iconCls2,
                            "leaf"      =>true,
                            "id"        =>$x
                        ];
                    }
                    if ((isset($filterbcDG)) AND ($filterbcDG !="all")){
                        $getVsys = $projectdb->query("SELECT vsys FROM devicegroups dg, device_mapping dm WHERE dg.device_mapping_id=dm.id AND dg.source='$source' AND dm.vsys='$filterbcDG';");
                        //echo "1. SELECT vsys FROM devicegroups dg, device_mapping dm WHERE dg.device_mapping_id=dm.id AND dg.source='$source' AND dm.vsys='$filterbcDG';\n";
                    }
                    else{
                        $getVsys = $projectdb->query("SELECT vsys FROM devicegroups dg, device_mapping dm WHERE dg.device_mapping_id=dm.id AND dg.source='$source';");
                        //echo "2. SELECT vsys FROM devicegroups dg, device_mapping dm WHERE dg.device_mapping_id=dm.id AND dg.source='$source';\n";
                    }

                    while ($data2 = $getVsys->fetch_assoc()) {
                        $vsys = $data2['vsys'];
                        $text = $vsys;
                        $iconCls2 = "icon-device_groups";
                        $getObjects = $projectdb->query("SELECT filename,element FROM pending_tasks WHERE map_filename='$filename' AND map_vsys='$vsys' AND type='object'");
                        if ($getObjects->num_rows > 0) {
                            $object = array();
                            $echo_shared = array();
                            while ($mydata = $getObjects->fetch_assoc()) {
                                $src_filename = $mydata['filename'];
                                $element = $mydata['element'];

                                list($element_text, $iconCls) = getElementIcon($element);

                                $x++;
//                                $object[] = "{vsys:'" . $vsys . "',type:'object',element:'" . $element . "', text:'" . $element_text . " [" . $src_filename . "] <font style=text-decoration:underline; color=blue>(pending)</font></s>" . "', value:'" . $element . "',leaf:true, iconCls:'" . $iconCls . "',filename:'" . $filename . "'}";
                                $object[] = [
                                    "vsys"      =>$vsys,
                                    "type"      =>'object',
                                    "element"   =>$element ,
                                    "text"      =>$element_text . " [" . $src_filename . "] <font style=text-decoration:underline; color=blue>(pending)</font></s>",
                                    "value"     =>$element,
                                    "leaf"      =>true,
                                    "iconCls"   =>$iconCls,
                                    "filename"  =>$filename,
                                    "id"        =>$x
                                ];
                            }
//                            $objects_tree[] = "{expanded:false, vsys:'" . $vsys . "',filename:'" . $filename . "',text:'Objects',value:'objects', element:'all', type:'object', leaf:false,children:[" . implode(",", $object) . "]}";
                            if (count($object)>0){
                                $x++;
                                $objects_tree[] = [
                                    "expanded"  =>false,
                                    "vsys"      =>$vsys ,
                                    "filename"  =>$filename,
                                    "text"      =>'Objects',
                                    "value"     =>'objects',
                                    "element"   =>'all',
                                    "type"      =>'object',
                                    "leaf"      =>false,
                                    "children"  =>$object,
                                    "id"        =>$x
                                ];
                            }
                        }
                        
                        $getProfiles= $projectdb->query("SELECT filename,element,type FROM pending_tasks WHERE map_filename='$filename' AND map_vsys='$vsys' AND (type='profiles' OR type='profiles_groups');");
                        if ($getProfiles->num_rows > 0){
                            $object = array();
                            while ($mydata=$getProfiles->fetch_assoc()){
                                $src_filename = $mydata['filename'];
                                $element = $mydata['element'];
                                $iconCls="icon-profile_group";
                                $type2=$mydata['type'];
                                $x++;
                                if ($type2=="profiles"){
//                                    $object[]="{vsys:'" . $vsys . "',type:'profiles',element:'" . $element . "', text:'Security [" . $src_filename . "] <font style=text-decoration:underline; color=blue>(pending)</font></s>" . "', value:'" . $element . "',leaf:true, iconCls:'" . $iconCls . "',filename:'" . $filename . "'}";
                                    $object[]=[
                                        "vsys"      =>$vsys,
                                        "type"      =>'profiles',
                                        "element"   =>$element,
                                        "text"      =>"Security/Content [" . $src_filename . "] <font style=text-decoration:underline; color=blue>(pending)</font></s>",
                                        "value"     =>$element,
                                        "leaf"      =>true,
                                        "iconCls"   =>$iconCls,
                                        "filename"  =>$filename,
                                        "id"        =>$x
                                    ];
                                }
                                else{
//                                    $object[]="{vsys:'" . $vsys . "',type:'profiles',element:'" . $element . "', text:'Security Group [" . $src_filename . "] <font style=text-decoration:underline; color=blue>(pending)</font></s>" . "', value:'" . $element . "',leaf:true, iconCls:'" . $iconCls . "',filename:'" . $filename . "'}";
                                    $object[]=[
                                        "vsys"      =>$vsys,
                                        "type"      =>'profiles',
                                        "element"   =>$element,
                                        "text"      =>"Security Group [" . $src_filename . "] <font style=text-decoration:underline; color=blue>(pending)</font></s>" ,
                                        "value"     =>$element,
                                        "leaf"      =>true,
                                        "iconCls"   =>$iconCls,
                                        "filename"  =>$filename,
                                        "id"        =>$x
                                    ];
                                }
                            }
//                            $objects_tree[] = "{expanded:true,vsys:'" . $vsys . "',filename:'" . $filename . "',text:'Profiles',value:'profiles', element:'all', type:'profiles', leaf:false,children:[" . implode(",", $object) . "]}";
                            if (count($object)>0){
                                $x++;
                                $objects_tree[] = [
                                    "expanded"  =>true,
                                    "vsys"      =>$vsys,
                                    "filename"  =>$filename,
                                    "text"      =>'Profiles',
                                    "value"     =>'profiles',
                                    "element"   =>'all',
                                    "type"      =>'profiles',
                                    "leaf"      =>false,
                                    "children"  =>$object,
                                    "id"        =>$x
                                ];
                            }


                        }
                        unset($object);
                        
                        $getObjects = $projectdb->query("SELECT filename,element FROM pending_tasks WHERE map_filename='$filename' AND map_vsys='$vsys' AND type='policy'");
                        if ($getObjects->num_rows > 0) {
                            $object = array();
                            while ($mydata = $getObjects->fetch_assoc()) {
                                $src_filename = $mydata['filename'];
                                $element = $mydata['element'];

                                list($element_text, $iconCls) = getElementIcon($element);

//                                $object[] = "{vsys:'" . $vsys . "',type:'policy',element:'" . $element . "', text:'" . $element_text . " [" . $src_filename . "] <font style=text-decoration:underline; color=blue>(pending)</font></s>" . "', value:'" . $element . "',leaf:true, iconCls:'" . $iconCls . "',filename:'" . $filename . "'}";
                                $x++;
                                $object[] = [
                                    "vsys"      =>$vsys,
                                    "type"      =>'policy',
                                    "element"   =>$element,
                                    "text"      =>$element_text . " [" . $src_filename . "] <font style=text-decoration:underline; color=blue>(pending)</font></s>",
                                    "value"     =>$element,
                                    "leaf"      =>true,
                                    "iconCls"   =>$iconCls,
                                    "filename"  =>$filename,
                                    "id"        =>$x
                                ];
                            }
//                            $objects_tree[] = "{expanded:false, vsys:'" . $vsys . "',filename:'" . $filename . "',text:'Policies',value:'policies', element:'all', type:'policy', leaf:false,children:[" . implode(",", $object) . "]}";
                            if (count($object)>0){
                                $x++;
                                $objects_tree[] = [
                                    "expanded"  =>false,
                                    "vsys"      =>$vsys,
                                    "filename"  =>$filename,
                                    "text"      =>'Policies',
                                    "value"     =>'policies',
                                    "element"   =>'all',
                                    "type"      =>'policy',
                                    "leaf"      =>false,
                                    "children"  =>$object,
                                    "id"        =>$x
                                ];
                            }

                        }
                        unset($object);


                        if ( (isset($objects_tree)) AND (count($objects_tree) > 0) ) {
//                            $devicegroup_tree[] = "{expanded:true,vsys:'" . $vsys . "',filename:'" . $filename . "',text:'" . $text . "',value:'" . $vsys . "',iconCls:'" . $iconCls2 . "', leaf:false,children:[" . implode(",", $objects_tree) . "]}";
                            $x++;
                            $devicegroup_tree[] = [
                                "expanded"  =>true,
                                "vsys"      =>$vsys,
                                "filename"  =>$filename,
                                "text"      =>$text,
                                "value"     =>$vsys,
                                "iconCls"   =>$iconCls2 ,
                                "leaf"      =>false,
                                "children"  =>$objects_tree,
                                "id"        =>$x
                            ];
                            unset($objects_tree);
                            unset($object);
                        }
                        else {
//                            $devicegroup_tree[] = "{expanded:true,vsys:'" . $vsys . "',filename:'" . $filename . "',text:'" . $text . "',value:'" . $vsys . "',iconCls:'" . $iconCls2 . "', leaf:true}";
                            $x++;
                            $devicegroup_tree[] = [
                                "expanded"  =>true,
                                "vsys"      =>$vsys,
                                "filename"  =>$filename,
                                "text"      =>$text,
                                "value"     =>$vsys,
                                "iconCls"   =>$iconCls2,
                                "leaf"      =>true,
                                "id"        =>$x
                            ];
                        }
                    }

                    if (count($devicegroup_tree) > 0) {
//                        $devicegroup_tree_main[] = "{expanded:true,vsys:'" . $vsys . "',filename:'" . $filename . "',iconCls:'icon-device_groups',text:'Device-Groups',value:'devicegroups', element:'all', type:'devicegroups', leaf:false,children:[" . implode(",", $devicegroup_tree) . "]}";
                        $x++;
                        $devicegroup_tree_main[] = [
                            "expanded"  =>true,
                            "vsys"      =>$vsys,
                            "filename"  =>$filename,
                            "iconCls"   =>'icon-device_groups',
                            "text"      =>'Device-Groups',
                            "value"     =>'devicegroups',
                            "element"   =>'all',
                            "type"      =>'devicegroups',
                            "leaf"      =>false,
                            "children"  =>$devicegroup_tree,
                            "id"        =>$x
                        ];
                    }
                    else {
//                        $devicegroup_tree_main[] = "{expanded:true,vsys:'" . $vsys . "',filename:'" . $filename . "',iconCls:'icon-device_groups',text:'Device-Groups',value:'devicegroups', element:'all', type:'devicegroups', leaf:true}";
                        $x++;
                        $devicegroup_tree_main[] = [
                            "expanded"  =>true,
                            "vsys"      => $vsys ,
                            "filename"  => $filename ,
                            "iconCls"   =>'icon-device_groups',
                            "text"      =>'Device-Groups',
                            "value"     =>'devicegroups',
                            "element"   =>'all',
                            "type"      =>'devicegroups',
                            "leaf"      =>true,
                            "id"        =>$x
                        ];
                    }

                    #Templates
                    if ((isset($filterbcTemplate)) AND ($filterbcTemplate!="all")){
                        $getTemplates = $projectdb->query("SELECT tm.name, tm.id as template FROM templates_mapping tm, templates t WHERE t.templates_mapping_id=tm.id AND t.source='$source' AND tm.name='$filterbcTemplate';");
                    }
                    else{
                        $getTemplates = $projectdb->query("SELECT tm.name, tm.id as template FROM templates_mapping tm, templates t WHERE t.templates_mapping_id=tm.id AND t.source='$source';");
                    }
                    $devices=array();
                    if ($getTemplates->num_rows > 0) {
                        while ($getTemplatesData = $getTemplates->fetch_assoc()) {
                            $template_name = $getTemplatesData['name'];
                            $template = $getTemplatesData['template'];
                            $virtual_routers = array();
                            $interfaces = array();
                            $iconCls2 = "icon-device_groups";
                            $echo = array();
                            $network = array();
                            $network_tree = array();
                            $object = array();

                            $getObjects = $projectdb->query("SELECT filename,element FROM pending_tasks WHERE map_filename='$filename' AND map_template='$template' AND type='virtual_router'");
                            if ($getObjects->num_rows > 0) {
                                $network1 = array();
                                $template_all = array();
                                while ($mydata = $getObjects->fetch_assoc()) {
                                    $src_filename = $mydata['filename'];
                                    $element = $mydata['element'];
                                    $iconCls = "icon-vr";
//                                    $network1[] = "{vsys:'" . $vsys . "',type:'network',element:'" . $element . "', text:'" . $element . " [" . $src_filename . "] <font style=text-decoration:underline; color=blue>(pending)</font></s>" . "', value:'" . $element . "',leaf:true, iconCls:'" . $iconCls . "',filename:'" . $filename . "'}";
                                    $x++;
                                    $network1[] = [
                                        "vsys"      =>$vsys,
                                        "type"      =>'network',
                                        "element"   =>$element ,
                                        "text"      =>$element . " [" . $src_filename . "] <font style=text-decoration:underline; color=blue>(pending)</font></s>" ,
                                        "value"     =>$element,
                                        "leaf"      =>true,
                                        "iconCls"   =>$iconCls,
                                        "filename"  =>$filename,
                                        "id"        =>$x
                                    ];
                                }
//                                $network[] = "{expanded:false,template:'" . $template . "',type:'virtual_router',element:'all', text:'Virtual Routers', value:'network',leaf:false, filename:'" . $filename . "',iconCls:'icon-vr',children:[" . implode(",", $network1) . "]}";
                                $x++;
                                $network[] = [
                                    "expanded"  =>false,
                                    "template"  =>$template,
                                    "type"      =>'virtual_router',
                                    "element"   =>'all',
                                    "text"      =>'Virtual Routers',
                                    "value"     =>'network',
                                    "leaf"      =>false,
                                    "filename"  =>$filename,
                                    "iconCls"   =>'icon-vr',
                                    "children"  =>$network1,
                                    "id"        =>$x
                                ];
                                unset($network1);
                            }
                            /*else {
//                                $network[] = "{template:'" . $template . "',type:'virtual_router',element:'all', text:'Virtual Routers', value:'network',leaf:true, filename:'" . $filename . "',iconCls:'icon-vr'}";
                                $network[] = [
                                    "template"=> $template ,
                                    "type"=>'virtual_router',
                                    "element"=>'all',
                                    "text"=>'Virtual Routers',
                                    "value"=>'network',
                                    "leaf"=>true,
                                    "filename"=> $filename ,
                                    "iconCls"=>'icon-vr'
                                ];
                            }*/

                            $getObjects = $projectdb->query("SELECT filename,element FROM pending_tasks WHERE map_filename='$filename' AND map_template='$template' AND type='interfaces'");
                            if ($getObjects->num_rows > 0) {
                                $network1 = array();
                                $template_all = array();
                                while ($mydata = $getObjects->fetch_assoc()) {
                                    $src_filename = $mydata['filename'];
                                    $element = $mydata['element'];
                                    $iconCls = "icon-interfaces";
//                                    $network1[] = "{vsys:'" . $vsys . "',type:'network',element:'" . $element . "', text:'" . $element . " [" . $src_filename . "] <font style=text-decoration:underline; color=blue>(pending)</font></s>" . "', value:'" . $element . "',leaf:true, iconCls:'" . $iconCls . "',filename:'" . $filename . "'}";
                                    $x++;
                                    $network1[] = [
                                        "vsys"      =>$vsys,
                                        "type"      =>'network',
                                        "element"   =>$element ,
                                        "text"      =>$element . " [" . $src_filename . "] <font style=text-decoration:underline; color=blue>(pending)</font></s>" ,
                                        "value"     =>$element,
                                        "leaf"      =>true,
                                        "iconCls"   =>$iconCls ,
                                        "filename"  =>$filename,
                                        "id"        =>$x
                                    ];
                                }
//                                $network[] = "{expanded:false,template:'" . $template . "',type:'interfaces',element:'all', text:'Interfaces', value:'network', iconCls:'icon-interfaces', leaf:false,filename:'" . $filename . "', children:[" . implode(",", $network1) . "]}";
                                $x++;
                                $network[] = [
                                    "expanded"  =>false,
                                    "template"  =>$template ,
                                    "type"      =>'interfaces',
                                    "element"   =>'all',
                                    "text"      =>'Interfaces',
                                    "value"     =>'network',
                                    "iconCls"   =>'icon-interfaces',
                                    "leaf"      =>false,
                                    "filename"  =>$filename,
                                    "children"  =>$network1,
                                    "id"        =>$x
                                ];
                                unset($network1);
                            }
                           /* else {
//                                $network[] = "{template:'" . $template . "',type:'interfaces',element:'all', text:'Interfaces', value:'network', iconCls:'icon-interfaces', leaf:true,filename:'" . $filename . "'}";
                                $network[] = [
                                    "template"=> $template ,
                                    "type"=>'interfaces',
                                    "element"=>'all',
                                    "text"=>'Interfaces',
                                    "value"=>'network',
                                    "iconCls"=>'icon-interfaces',
                                    "leaf"=>true,
                                    "filename"=> $filename
                                ];
                            }*/

                            $getObjects = $projectdb->query("SELECT filename,element FROM pending_tasks WHERE map_filename='$filename' AND map_template='$template' AND type='interface_management_profile'");
                            if ($getObjects->num_rows > 0) {
                                $network1 = array();
                                $template_all = array();
                                while ($mydata = $getObjects->fetch_assoc()) {
                                    $src_filename = $mydata['filename'];
                                    $element = $mydata['element'];
                                    $iconCls = "icon-interface-mgmt";
//                                    $network1[] = "{vsys:'" . $vsys . "',type:'network',element:'" . $element . "', text:'" . $element . " [" . $src_filename . "] <font style=text-decoration:underline; color=blue>(pending)</font></s>" . "', value:'" . $element . "',leaf:true, iconCls:'" . $iconCls . "',filename:'" . $filename . "'}";
                                    $x++;
                                    $network1[] = [
                                        "vsys"      =>$vsys,
                                        "type"      =>'network',
                                        "element"   =>$element,
                                        "text"      =>$element . " [" . $src_filename . "] <font style=text-decoration:underline; color=blue>(pending)</font></s>" ,
                                        "value"     =>$element,
                                        "leaf"      =>true,
                                        "iconCls"   =>$iconCls,
                                        "filename"  =>$filename,
                                        "id"        =>$x
                                    ];
                                }
//                                $network[] = "{expanded:false,template:'" . $template . "',type:'interface_management_profile',element:'all', text:'Interface Mgmt', value:'network', iconCls:'icon-interface-mgmt', leaf:false,filename:'" . $filename . "', children:[" . implode(",", $network1) . "]}";
                                $x++;
                                $network[] = [
                                    "expanded"  =>false,
                                    "template"  =>$template,
                                    "type"      =>'interface_management_profile',
                                    "element"   =>'all',
                                    "text"      =>'Interface Mgmt',
                                    "value"     =>'network',
                                    "iconCls"   =>'icon-interface-mgmt',
                                    "leaf"      =>false,
                                    "filename"  =>$filename,
                                    "children"  =>$network1,
                                    "id"        =>$x
                                ];
                                unset($network1);
                            }
                            /*else {
//                                $network[] = "{template:'" . $template . "',type:'interface_management_profile',element:'all', text:'Interface Mgmt', value:'network', iconCls:'icon-interface-mgmt', leaf:true,filename:'" . $filename . "'}";
                                $network[] = [
                                    "template"=> $template ,
                                    "type"=>'interface_management_profile',
                                    "element"=>'all',
                                    "text"=>'Interface Mgmt',
                                    "value"=>'network',
                                    "iconCls"=>'icon-interface-mgmt',
                                    "leaf"=>true,
                                    "filename"=> $filename
                                ];
                            }*/

                            # IPSec Tunnel
                            $getObjects = $projectdb->query("SELECT filename,element FROM pending_tasks WHERE map_filename='$filename' AND map_template='$template' AND type='ipsec_tunnel'");
                            if ($getObjects->num_rows > 0) {
                                $network1 = array();
                                $template_all = array();
                                while ($mydata = $getObjects->fetch_assoc()) {
                                    $src_filename = $mydata['filename'];
                                    $element = $mydata['element'];
                                    $iconCls = "icon-ipsec-tunnels";
//                                    $network1[] = "{vsys:'" . $vsys . "',type:'network', element:'" . $element . "', text:'" . $element . " [" . $src_filename . "] <font style=text-decoration:underline; color=blue>(pending)</font></s>" . "', value:'" . $element . "',leaf:true, iconCls:'" . $iconCls . "',filename:'" . $filename . "'}";
                                    $x++;
                                    $network1[] = [
                                        "vsys"      =>$vsys,
                                        "type"      =>'network',
                                        "element"   =>$element,
                                        "text"      =>$element . " [" . $src_filename . "] <font style=text-decoration:underline; color=blue>(pending)</font></s>" ,
                                        "value"     =>$element,
                                        "leaf"      =>true,
                                        "iconCls"   =>$iconCls,
                                        "filename"  =>$filename,
                                        "id"        =>$x
                                    ];
                                }
//                                $network[] = "{expanded:false,template:'" . $template . "',type:'ipsec_tunnel',element:'all', text:'IPSec Tunnels', value:'network', iconCls:'icon-ipsec-tunnels', leaf:false,filename:'" . $filename . "', children:[" . implode(",", $network1) . "]}";
                                $x++;
                                $network[] = [
                                    "expanded"  =>false,
                                    "template"  =>$template ,
                                    "type"      =>'ipsec_tunnel',
                                    "element"   =>'all',
                                    "text"      =>'IPSec Tunnels',
                                    "value"     =>'network',
                                    "iconCls"   =>'icon-ipsec-tunnels',
                                    "leaf"      =>false,
                                    "filename"  =>$filename,
                                    "children"  =>$network1,
                                    "id"        =>$x
                                ];
                                unset($network1);
                            }
                           /* else {
//                                $network[] = "{template:'" . $template . "',type:'ipsec_tunnel',element:'all', text:'IPSec Tunnels', value:'network', iconCls:'icon-ipsec-tunnels', leaf:true,filename:'" . $filename . "'}";
                                $network[] = [
                                    "template"=> $template ,
                                    "type"=>'ipsec_tunnel',
                                    "element"=>'all',
                                    "text"=>'IPSec Tunnels',
                                    "value"=>'network',
                                    "iconCls"=>'icon-ipsec-tunnels',
                                    "leaf"=>true,
                                    "filename"=> $filename
                                ];
                            }*/
                            # IKE Gateways
                            $getObjects = $projectdb->query("SELECT filename,element FROM pending_tasks WHERE map_filename='$filename' AND map_template='$template' AND type='ike_gateways_profiles'");
                            if ($getObjects->num_rows > 0) {
                                $network1 = array();
                                $template_all = array();
                                while ($mydata = $getObjects->fetch_assoc()) {
                                    $src_filename = $mydata['filename'];
                                    $element = $mydata['element'];
                                    $iconCls = "icon-ike-gateways";
//                                    $network1[] = "{vsys:'" . $vsys . "',type:'network',element:'" . $element . "', text:'" . $element . " [" . $src_filename . "] <font style=text-decoration:underline; color=blue>(pending)</font></s>" . "', value:'" . $element . "',leaf:true, iconCls:'" . $iconCls . "',filename:'" . $filename . "'}";
                                    $x++;
                                    $network1[] = [
                                        "vsys"      =>$vsys,
                                        "type"      =>'network',
                                        "element"   =>$element,
                                        "text"      =>$element . "[".$src_filename."] <font style=text-decoration:underline; color=blue>(pending)</font></s>",
                                        "value"     =>$element,
                                        "leaf"      =>true,
                                        "iconCls"   =>$iconCls,
                                        "filename"  =>$filename,
                                        "id"        =>$x
                                    ];
                                }
//                                $network[] = "{expanded:false,template:'" . $template . "',type:'ike_gateways_profiles',element:'all', text:'IKE Gateways', value:'network', iconCls:'icon-ike-gateways', leaf:false,filename:'" . $filename . "', children:[" . implode(",", $network1) . "]}";
                                $x++;
                                $network[] = [
                                    "expanded"  =>false,
                                    "template"  =>$template,
                                    "type"      =>'ike_gateways_profiles',
                                    "element"   =>'all',
                                    "text"      =>'IKE Gateways',
                                    "value"     =>'network',
                                    "iconCls"   =>'icon-ike-gateways',
                                    "leaf"      =>false,
                                    "filename"  =>$filename ,
                                    "children"  =>$network1,
                                    "id"        =>$x
                                ];
                                unset($network1);
                            }
                            /*else {
//                                $network[] = "{template:'" . $template . "',type:'ike_gateways_profiles',element:'all', text:'IKE Gateways', value:'network', iconCls:'icon-ike-gateways', leaf:true,filename:'" . $filename . "'}";
                                $network[] = [
                                    "template"=> $template ,
                                    "type"=>'ike_gateways_profiles',
                                    "element"=>'all',
                                    "text"=>'IKE Gateways',
                                    "value"=>'network',
                                    "iconCls"=>'icon-ike-gateways',
                                    "leaf"=>true,
                                    "filename"=>  $filename
                                ];
                            }*/

                            # IPSec Crypto
                            $getObjects = $projectdb->query("SELECT filename,element FROM pending_tasks WHERE map_filename='$filename' AND map_template='$template' AND type='ipsec_crypto_profiles'");
                            if ($getObjects->num_rows > 0) {
                                $network1 = array();
                                $template_all = array();
                                while ($mydata = $getObjects->fetch_assoc()) {
                                    $src_filename = $mydata['filename'];
                                    $element = $mydata['element'];
                                    $iconCls = "icon-ipsec-crypto";
//                                    $network1[] = "{vsys:'" . $vsys . "',type:'network',element:'" . $element . "', text:'" . $element . " [" . $src_filename . "] <font style=text-decoration:underline; color=blue>(pending)</font></s>" . "', value:'" . $element . "',leaf:true, iconCls:'" . $iconCls . "',filename:'" . $filename . "'}";
                                    $x++;
                                    $network1[] = [
                                        "vsys"      =>$vsys,
                                        "type"      =>'network',
                                        "element"   =>$element,
                                        "text"      =>$element ."[".$src_filename . "] <font style=text-decoration:underline; color=blue>(pending)</font></s>" ,
                                        "value"     =>$element,
                                        "leaf"      =>true,
                                        "iconCls"   =>$iconCls,
                                        "filename"  =>$filename,
                                        "id"        =>$x
                                    ];
                                }
//                                $network[] = "{expanded:false,template:'" . $template . "',type:'ipsec_crypto_profiles',element:'all', text:'IPSec Crypto', value:'network', iconCls:'icon-ipsec-crypto', leaf:false,filename:'" . $filename . "', children:[" . implode(",", $network1) . "]}";
                                $x++;
                                $network[] = [
                                    "expanded"  =>false,
                                    "template"  =>$template,
                                    "type"      =>'ipsec_crypto_profiles',
                                    "element"   =>'all',
                                    "text"      =>'IPSec Crypto',
                                    "value"     =>'network',
                                    "iconCls"   =>'icon-ipsec-crypto',
                                    "leaf"      =>false,
                                    "filename"  =>$filename,
                                    "children"  =>$network1,
                                    "id"        =>$x
                                ];
                                unset($network1);
                            }
                           /* else {
//                                $network[] = "{template:'" . $template . "',type:'ipsec_crypto_profiles',element:'all', text:'IPSec Crypto', value:'network', iconCls:'icon-ipsec-crypto', leaf:true,filename:'" . $filename . "'}";
                                $network[] = [
                                    "template"=> $template ,
                                    "type"=>'ipsec_crypto_profiles',
                                    "element"=>'all',
                                    "text"=>'IPSec Crypto',
                                    "value"=>'network',
                                    "iconCls"=>'icon-ipsec-crypto',
                                    "leaf"=>true,
                                    "filename"=> $filename
                                ];
                            }*/

                            # IKE Crypto
                            $getObjects = $projectdb->query("SELECT filename,element FROM pending_tasks WHERE map_filename='$filename' AND map_template='$template' AND type='ike_crypto_profiles'");
                            if ($getObjects->num_rows > 0) {
                                $network1 = array();
                                $template_all = array();
                                while ($mydata = $getObjects->fetch_assoc()) {
                                    $src_filename = $mydata['filename'];
                                    $element = $mydata['element'];
                                    $iconCls = "icon-ipsec-crypto";
//                                    $network1[] = "{vsys:'" . $vsys . "',type:'network',element:'" . $element . "', text:'" . $element . " [" . $src_filename . "] <font style=text-decoration:underline; color=blue>(pending)</font></s>" . "', value:'" . $element . "',leaf:true, iconCls:'" . $iconCls . "',filename:'" . $filename . "'}";
                                    $x++;
                                    $network1[] = [
                                        "vsys"      =>$vsys,
                                        "type"      =>'network',
                                        "element"   =>$element ,
                                        "text"      =>$element . " [" . $src_filename . "] <font style=text-decoration:underline; color=blue>(pending)</font></s>" ,
                                        "value"     =>$element,
                                        "leaf"      =>true,
                                        "iconCls"   =>$iconCls,
                                        "filename"  =>$filename,
                                        "id"        =>$x
                                    ];
                                }
//                                $network[] = "{expanded:false,template:'" . $template . "',type:'ike_crypto_profiles',element:'all', text:'IKE Crypto', value:'network', iconCls:'icon-ipsec-crypto', leaf:false,filename:'" . $filename . "', children:[" . implode(",", $network1) . "]}";
                                $x++;
                                $network[] = [
                                    "expanded"  =>false,
                                    "template"  =>$template,
                                    "type"      =>'ike_crypto_profiles',
                                    "element"   =>'all',
                                    "text"      =>'IKE Crypto',
                                    "value"     =>'network',
                                    "iconCls"   =>'icon-ipsec-crypto',
                                    "leaf"      =>false,
                                    "filename"  =>$filename,
                                    "children"  =>$network1,
                                    "id"        =>$x
                                ];
                                unset($network1);
                            }
                           /* else {
//                                $network[] = "{template:'" . $template . "',type:'ike_crypto_profiles',element:'all', text:'IKE Crypto', value:'network', iconCls:'icon-ipsec-crypto', leaf:true,filename:'" . $filename . "'}";
                                $network[] = [
                                    "template"=> $template ,
                                    "type"=>'ike_crypto_profiles',
                                    "element"=>'all',
                                    "text"=>'IKE Crypto',
                                    "value"=>'network',
                                    "iconCls"=>'icon-ipsec-crypto',
                                    "leaf"=>true,
                                    "filename"=> $filename
                                ];
                            }*/

                            # Monitor Profile
                            $getObjects = $projectdb->query("SELECT filename,element FROM pending_tasks WHERE map_filename='$filename' AND map_template='$template' AND type='monitor_profile'");
                            if ($getObjects->num_rows > 0) {
                                $network1 = array();
                                $template_all = array();
                                while ($mydata = $getObjects->fetch_assoc()) {
                                    $src_filename = $mydata['filename'];
                                    $element = $mydata['element'];
                                    $iconCls = "icon-monitor";
//                                    $network1[] = "{vsys:'" . $vsys . "',type:'network',element:'" . $element . "', text:'" . $element . " [" . $src_filename . "] <font style=text-decoration:underline; color=blue>(pending)</font></s>" . "', value:'" . $element . "',leaf:true, iconCls:'" . $iconCls . "',filename:'" . $filename . "'}";
                                    $x++;
                                    $network1[] = [
                                        "vsys"      =>$vsys,
                                        "type"      =>'network',
                                        "element"   =>$element ,
                                        "text"      =>$element . " [" . $src_filename . "] <font style=text-decoration:underline; color=blue>(pending)</font></s>" ,
                                        "value"     =>$element ,
                                        "leaf"      =>true,
                                        "iconCls"   =>$iconCls,
                                        "filename"  =>$filename,
                                        "id"        =>$x
                                    ];
                                }
//                                $network[] = "{expanded:false,template:'" . $template . "',type:'monitor_profile',element:'all', text:'Monitor Profile', value:'network', iconCls:'icon-monitor', leaf:false,filename:'" . $filename . "', children:[" . implode(",", $network1) . "]}";
                                $x++;
                                $network[] = [
                                    "expanded"  =>false,
                                    "template"  => $template ,
                                    "type"      =>'monitor_profile',
                                    "element"   =>'all',
                                    "text"      =>'Monitor Profile',
                                    "value"     =>'network',
                                    "iconCls"   =>'icon-monitor',
                                    "leaf"      =>false,
                                    "filename"  =>$filename,
                                    "children"  =>$network1,
                                    "id"        =>$x
                                ];
                                unset($network1);
                            }
                           /* else {
//                                $network[] = "{template:'" . $template . "',type:'monitor_profile',element:'all', text:'Monitor Profile', value:'network', iconCls:'icon-monitor', leaf:true,filename:'" . $filename . "'}";
                                $network[] = [
                                    "template"=> $template ,
                                    "type"=>'monitor_profile',
                                    "element"=>'all',
                                    "text"=>'Monitor Profile',
                                    "value"=>'network',
                                    "iconCls"=>'icon-monitor',
                                    "leaf"=>true,
                                    "filename"=> $filename
                                ];
                            }*/

                            # GlobalProtect IPSec Crypto (Only Version > 7)
                            if($version >= 7){
                                $getObjects = $projectdb->query("SELECT filename,element FROM pending_tasks WHERE map_filename='$filename' AND map_template='$template' AND type='global_protect_app_ipsec_crypto_profiles'");
                                if ($getObjects->num_rows > 0) {
                                    $network1 = array();
                                    $template_all = array();
                                    while ($mydata = $getObjects->fetch_assoc()) {
                                        $src_filename = $mydata['filename'];
                                        $element = $mydata['element'];
                                        $iconCls = "icon-ipsec-crypto";
//                                        $network1[] = "{vsys:'" . $vsys . "',type:'network',element:'" . $element . "', text:'" . $element . " [" . $src_filename . "] <font style=text-decoration:underline; color=blue>(pending)</font></s>" . "', value:'" . $element . "',leaf:true, iconCls:'" . $iconCls . "',filename:'" . $filename . "'}";
                                        $x++;
                                        $network1[] = [
                                            "vsys"      =>$vsys,
                                            "type"      =>'network',
                                            "element"   =>$element,
                                            "text"      =>$element . " [" . $src_filename . "] <font style=text-decoration:underline; color=blue>(pending)</font></s>" ,
                                            "value"     =>$element,
                                            "leaf"      =>true,
                                            "iconCls"   =>$iconCls,
                                            "filename"  =>$filename,
                                            "id"        =>$x
                                        ];
                                    }
//                                    $network[] = "{expanded:false,template:'" . $template . "',type:'global_protect_app_ipsec_crypto_profiles',element:'all', text:'GlobalProtect IPSec Crypto', value:'network', iconCls:'icon-ipsec-crypto', leaf:false,filename:'" . $filename . "', children:[" . implode(",", $network1) . "]}";
                                    $x++;
                                    $network[] = [
                                        "expanded"  =>false,
                                        "template"  => $template ,
                                        "type"      =>'global_protect_app_ipsec_crypto_profiles',
                                        "element"   =>'all',
                                        "text"      =>'GlobalProtect IPSec Crypto',
                                        "value"     =>'network',
                                        "iconCls"   =>'icon-ipsec-crypto',
                                        "leaf"      =>false,
                                        "filename"  =>$filename ,
                                        "children"  =>$network1,
                                        "id"        =>$x
                                    ];
                                    unset($network1);
                                }
                               /* else {
//                                    $network[] = "{template:'" . $template . "',type:'global_protect_app_ipsec_crypto_profiles',element:'all', text:'GlobalProtect IPSec Crypto', value:'network', iconCls:'icon-ipsec-crypto', leaf:true,filename:'" . $filename . "'}";
                                    $network[] = [
                                        "template"=> $template ,
                                        "type"=>'global_protect_app_ipsec_crypto_profiles',
                                        "element"=>'all',
                                        "text"=>'GlobalProtect IPSec Crypto',
                                        "value"=>'network',
                                        "iconCls"=>'icon-ipsec-crypto',
                                        "leaf"=>true,
                                        "filename"=> $filename
                                    ];
                                }*/
                            }

                            # VLANs
                            $getObjects = $projectdb->query("SELECT filename,element FROM pending_tasks WHERE map_filename='$filename' AND map_template='$template' AND type='vlans'");
                            if ($getObjects->num_rows > 0) {
                                $network1 = array();
                                $template_all = array();
                                while ($mydata = $getObjects->fetch_assoc()) {
                                    $src_filename = $mydata['filename'];
                                    $element = $mydata['element'];
                                    $iconCls = "icon-vlans";
//                                    $network1[] = "{vsys:'" . $vsys . "',type:'network',element:'" . $element . "', text:'" . $element . " [" . $src_filename . "] <font style=text-decoration:underline; color=blue>(pending)</font></s>" . "', value:'" . $element . "',leaf:true, iconCls:'" . $iconCls . "',filename:'" . $filename . "'}";
                                    $x++;
                                    $network1[] = [
                                        "vsys"      =>$vsys ,
                                        "type"      =>'network',
                                        "element"   =>$element ,
                                        "text"      =>$element . " [" . $src_filename . "] <font style=text-decoration:underline; color=blue>(pending)</font></s>" ,
                                        "value"     =>$element ,
                                        "leaf"      =>true,
                                        "iconCls"   =>$iconCls ,
                                        "filename"  =>$filename,
                                        "id"        =>$x
                                    ];
                                }
//                                $network[] = "{expanded:false,template:'" . $template . "',type:'vlans',element:'all', text:'VLANs', value:'network', iconCls:'icon-vlans', leaf:false,filename:'" . $filename . "', children:[" . implode(",", $network1) . "]}";
                                $x++;
                                $network[] = [
                                    "expanded"  =>false,
                                    "template"  =>$template ,
                                    "type"      =>'vlans',
                                    "element"   =>'all',
                                    "text"      =>'VLANs',
                                    "value"     =>'network',
                                    "iconCls"   =>'icon-vlans',
                                    "leaf"      =>false,
                                    "filename"  =>$filename ,
                                    "children"  =>$network1,
                                    "id"        =>$x
                                ];
                                unset($network1);
                            }
                            /*else {
//                                $network[] = "{template:'" . $template . "',type:'vlans',element:'all', text:'VLANs', value:'network', iconCls:'icon-vlans', leaf:true,filename:'" . $filename . "'}";
                                $network[] = [
                                    "template"=> $template ,
                                    "type"=>'vlans',
                                    "element"=>'all',
                                    "text"=>'VLANs',
                                    "value"=>'network',
                                    "iconCls"=>'icon-vlans',
                                    "leaf"=>true,
                                    "filename"=> $filename ,
                                ];
                            }*/

                            # Virtual Wires
                            $getObjects = $projectdb->query("SELECT filename,element FROM pending_tasks WHERE map_filename='$filename' AND map_template='$template' AND type='virtual_wires'");
                            if ($getObjects->num_rows > 0) {
                                $network1 = array();
                                $template_all = array();
                                while ($mydata = $getObjects->fetch_assoc()) {
                                    $src_filename = $mydata['filename'];
                                    $element = $mydata['element'];
                                    $iconCls = "icon-vwire";
//                                    $network1[] = "{vsys:'" . $vsys . "',type:'network',element:'" . $element . "', text:'" . $element . " [" . $src_filename . "] <font style=text-decoration:underline; color=blue>(pending)</font></s>" . "', value:'" . $element . "',leaf:true, iconCls:'" . $iconCls . "',filename:'" . $filename . "'}";
                                    $x++;
                                    $network1[] = [
                                        "vsys"      =>$vsys,
                                        "type"      =>'network',
                                        "element"   =>$element ,
                                        "text"      =>$element . " [" . $src_filename . "] <font style=text-decoration:underline; color=blue>(pending)</font></s>" ,
                                        "value"     =>$element ,
                                        "leaf"      =>true,
                                        "iconCls"   =>$iconCls ,
                                        "filename"  =>$filename,
                                        "id"        =>$x
                                    ];
                                }
//                                $network[] = "{expanded:false,template:'" . $template . "',type:'virtual_wires',element:'all', text:'Virtual Wires', value:'network', iconCls:'icon-vwire', leaf:false,filename:'" . $filename . "', children:[" . implode(",", $network1) . "]}";
                                $x++;
                                $network[] = [
                                    "expanded"  =>false,
                                    "template"  =>$template ,
                                    "type"      =>'virtual_wires',
                                    "element"   =>'all',
                                    "text"      =>'Virtual Wires',
                                    "value"     =>'network',
                                    "iconCls"   =>'icon-vwire',
                                    "leaf"      =>false,
                                    "filename"  =>$filename ,
                                    "children"  =>$network1,
                                    "id"        =>$x
                                ];
                                unset($network1);
                            }
                            /*else {
//                                $network[] = "{template:'" . $template . "',type:'virtual_wires',element:'all', text:'Virtual Wires', value:'network', iconCls:'icon-vwire', leaf:true,filename:'" . $filename . "'}";
                                $network[] = [
                                    "template"=> $template ,
                                    "type"=>'virtual_wires',
                                    "element"=>'all',
                                    "text"=>'Virtual Wires',
                                    "value"=>'network',
                                    "iconCls"=>'icon-vwire',
                                    "leaf"=>true,
                                    "filename"=> $filename ,
                                ];
                            }*/

                            if ( (isset($network)) AND (count($network) > 0)) {
//                                $network_tree[] = "{expanded:true,template:'" . $template . "',vsys:'" . $vsys . "',filename:'" . $filename . "',text:'Network',value:'network', element:'all', iconCls:'icon-network', type:'network', leaf:false,children:[" . implode(",", $network) . "]}";
                                $x++;
                                $network_tree[] = [
                                    "expanded"  =>true,
                                    "template"  =>$template ,
                                    "vsys"      =>$vsys ,
                                    "filename"  =>$filename ,
                                    "text"      =>'Network',
                                    "value"     =>'network',
                                    "element"   =>'all',
                                    "iconCls"   =>'icon-network',
                                    "type"      =>'network',
                                    "leaf"      =>false,
                                    "children"  =>$network,
                                    "id"        =>$x
                                ];
                                unset($network);
                            }
                            else{
                                $x++;
                                $network_tree[] = [
                                    "expanded"  =>true,
                                    "template"  =>$template ,
                                    "vsys"      =>$vsys ,
                                    "filename"  =>$filename ,
                                    "text"      =>'Network',
                                    "value"     =>'network',
                                    "element"   =>'all',
                                    "iconCls"   =>'icon-network',
                                    "type"      =>'network',
                                    "leaf"      =>true,
                                    "id"        =>$x
                                ];
                            }

                            # Add Vsys
                            # Add Shared
                            $getObjects = $projectdb->query("SELECT filename,element FROM pending_tasks WHERE map_filename='$filename' AND map_vsys='shared' AND map_template='$template' AND type='shared_response_pages'");
                            //echo "SELECT filename,element FROM pending_tasks WHERE map_filename='$filename' AND map_vsys='shared' AND map_template='$template' AND type='shared_response_pages'\n";
                            if ($getObjects->num_rows > 0) {
                                $object = array();
                                while ($mydata = $getObjects->fetch_assoc()) {
                                    $src_filename = $mydata['filename'];
                                    $element = $mydata['element'];
                                    $element_text = "Response-Pages";
                                    $iconCls = "icon-response_page";
//                                    $object[] = "{template:'" . $template . "',vsys:'" . $vsys . "',type:'shared_response_pages',element:'" . $element . "', text:'" . $element . " [" . $src_filename . "] <font style=text-decoration:underline; color=blue>(pending)</font></s>" . "', value:'" . $element . "',leaf:true, iconCls:'" . $iconCls . "',filename:'" . $filename . "'}";
                                    $x++;
                                    $object[] = [
                                        "template"  =>$template ,
                                        "vsys"      =>$vsys ,
                                        "type"      =>'shared_response_pages',
                                        "element"   =>$element ,
                                        "text"      =>$element . " [" . $src_filename . "] <font style=text-decoration:underline; color=blue>(pending)</font></s>" ,
                                        "value"     =>$element ,
                                        "leaf"      =>true,
                                        "iconCls"   =>$iconCls,
                                        "filename"  =>$filename,
                                        "id"        =>$x
                                    ];
                                }
//                                $shared_things[] = "{template:'" . $template . "',type:'shared_response_pages',element:'all', text:'Response-Pages', value:'shared_response_pages',leaf:false, filename:'" . $filename . "',iconCls:'icon-response_page', children:[" . implode(",", $object) . "]}";
                                $x++;
                                $shared_things[] = [
                                    "template"  =>$template ,
                                    "type"      =>'shared_response_pages',
                                    "element"   =>'all',
                                    "text"      =>'Response-Pages',
                                    "value"     =>'shared_response_pages',
                                    "leaf"      =>false,
                                    "filename"  =>$filename ,
                                    "iconCls"   =>'icon-response_page',
                                    "children"  =>$object,
                                    "id"        =>$x
                                ];
                            }
                           /* else {
//                                $shared_things[] = "{template:'" . $template . "',type:'shared_response_pages',element:'all', text:'Response-Pages', value:'shared_response_pages',leaf:true, filename:'" . $filename . "',iconCls:'icon-response_page'}";
                                $shared_things[] = [
                                    "template"=> $template ,
                                    "type"=>'shared_response_pages',
                                    "element"=>'all',
                                    "text"=>'Response-Pages',
                                    "value"=>'shared_response_pages',
                                    "leaf"=>true,
                                    "filename"=> $filename ,
                                    "iconCls"=>'icon-response_page',
                                ];
                            }*/
                            unset($object);

//                            $network_tree[] = "{template:'" . $template . "',expanded:true,vsys:'shared',filename:'" . $filename . "',text:'shared',value:'shared', element:'all', type:'shared', iconCls:'icon-shared_device',leaf:false, children:[" . implode(",", $shared_things) . "]}";
                            if ( (isset($shared_things)) AND (count($shared_things)>0)){
                                $x++;
                                $network_tree[] = [
                                    "template"  =>$template ,
                                    "expanded"  =>true,
                                    "vsys"      =>'shared',
                                    "filename"  =>$filename ,
                                    "text"      =>'shared',
                                    "value"     =>'shared',
                                    "element"   =>'all',
                                    "type"      =>'shared',
                                    "iconCls"   =>'icon-shared_device',
                                    "leaf"      =>false,
                                    "children"  =>$shared_things,
                                    "id"        =>$x
                                ];

                                unset($shared_things);
                            }
                            else{
                                $x++;
                                $network_tree[] = [
                                    "template"  =>$template ,
                                    "expanded"  =>true,
                                    "vsys"      =>'shared',
                                    "filename"  =>$filename ,
                                    "text"      =>'shared',
                                    "value"     =>'shared',
                                    "element"   =>'all',
                                    "type"      =>'shared',
                                    "iconCls"   =>'icon-shared_device',
                                    "leaf"      =>true,
                                    "id"        =>$x
                                ];
                            }

                            $getTemplateVsys = $projectdb->query("SELECT name FROM virtual_systems WHERE template='$template' AND source='$source';");
                            if ($getTemplateVsys->num_rows > 0) {
                                $devices=array();
                                while ($getTemplateVsysData = $getTemplateVsys->fetch_assoc()) {
                                    $vsys_template = $getTemplateVsysData['name'];
                                    $iconCls2 = "icon-device";
                                    #Read Zones
                                    $zones = array();
                                    $getObjects = $projectdb->query("SELECT filename,element FROM pending_tasks WHERE map_filename='$filename' AND map_vsys='$vsys_template' AND map_template='$template' AND type='zones'");
                                    if ($getObjects->num_rows > 0) {
                                        $network1 = array();
                                        $template_all = array();
                                        while ($mydata = $getObjects->fetch_assoc()) {
                                            $src_filename = $mydata['filename'];
                                            $element = $mydata['element'];
                                            $iconCls = "icon-zone";
//                                            $object[] = "{template:'" . $template . "',vsys:'" . $vsys_template . "',type:'network',element:'" . $element . "', text:'" . $element . " [" . $src_filename . "] <font style=text-decoration:underline; color=blue>(pending)</font></s>" . "', value:'" . $element . "',leaf:true, iconCls:'" . $iconCls . "',filename:'" . $filename . "'}";
                                            $x++;
                                            $object[] = [
                                                "template"  =>$template ,
                                                "vsys"      =>$vsys_template ,
                                                "type"      =>'network',
                                                "element"   =>$element ,
                                                "text"      =>$element . " [" . $src_filename . "] <font style=text-decoration:underline; color=blue>(pending)</font></s>" ,
                                                "value"     =>$element ,
                                                "leaf"      =>true,
                                                "iconCls"   =>$iconCls ,
                                                "filename"  =>$filename,
                                                "id"        =>$x
                                            ];
                                        }
//                                        $zones[] = "{expanded:false,template:'" . $template . "',vsys:'" . $vsys . "',type:'zones',element:'all', text:'Zones', value:'network', iconCls:'icon-zone', leaf:false,filename:'" . $filename . "', children:[" . implode(",", $object) . "]}";
                                        if ((isset($object)) AND (count($object)>0)){
                                            $x++;
                                            $zones[] = [
                                                "expanded"  =>false,
                                                "template"  =>$template ,
                                                "vsys"      =>$vsys,
                                                "type"      =>'zones',
                                                "element"   =>'all',
                                                "text"      =>'Zones',
                                                "value"     =>'network',
                                                "iconCls"   =>'icon-zone',
                                                "leaf"      =>false,
                                                "filename"  =>$filename ,
                                                "children"  =>$object,
                                                "id"        =>$x
                                            ];
                                        }
                                        else{
                                            $x++;
                                            $zones[] = [
                                                "expanded"  =>false,
                                                "template"  =>$template ,
                                                "vsys"      =>$vsys,
                                                "type"      =>'zones',
                                                "element"   =>'all',
                                                "text"      =>'Zones',
                                                "value"     =>'network',
                                                "iconCls"   =>'icon-zone',
                                                "leaf"      =>true,
                                                "filename"  =>$filename,
                                                "id"        =>$x
                                            ];
                                        }

                                        unset($object);
                                    }

                                    #Read Response Pages
                                    $getObjects = $projectdb->query("SELECT filename,element FROM pending_tasks WHERE map_filename='$filename' AND map_vsys='$vsys_template' AND map_template='$template' AND type='response_pages'");
                                    if ($getObjects->num_rows > 0) {
                                        $network1 = array();
                                        $template_all = array();
                                        while ($mydata = $getObjects->fetch_assoc()) {
                                            $src_filename = $mydata['filename'];
                                            $element = $mydata['element'];
                                            $iconCls = "icon-response_page";
//                                            $object[] = "{template:'" . $template . "',vsys:'" . $vsys_template . "',type:'network',element:'" . $element . "', text:'" . $element . " [" . $src_filename . "] <font style=text-decoration:underline; color=blue>(pending)</font></s>" . "', value:'" . $element . "',leaf:true, iconCls:'" . $iconCls . "',filename:'" . $filename . "'}";
                                            $x++;
                                            $object[] = [
                                                "template"  =>$template ,
                                                "vsys"      =>$vsys_template,
                                                "type"      =>'network',
                                                "element"   =>$element ,
                                                "text"      =>$element . " [" . $src_filename . "] <font style=text-decoration:underline; color=blue>(pending)</font></s>",
                                                "value"     =>$element ,
                                                "leaf"      =>true,
                                                "iconCls"   =>$iconCls,
                                                "filename"  =>$filename,
                                                "id"        =>$x
                                            ];
                                        }
//                                        $zones[] = "{expanded:true,template:'" . $template . "',vsys:'" . $vsys . "',type:'response_pages',element:'all', text:'Response-Pages', value:'response_pages', iconCls:'icon-response_page', leaf:false,filename:'" . $filename . "', children:[" . implode(",", $object) . "]}";
                                        $x++;
                                        $zones[] = [
                                            "expanded"  =>true,
                                            "template"  =>$template ,
                                            "vsys"      =>$vsys ,
                                            "type"      =>'response_pages',
                                            "element"   =>'all',
                                            "text"      =>'Response-Pages',
                                            "value"     =>'response_pages',
                                            "iconCls"   =>'icon-response_page',
                                            "leaf"      =>false,
                                            "filename"  =>$filename ,
                                            "children"  =>$object,
                                            "id"        =>$x
                                        ];
                                        unset($object);
                                    }
                                    
                                    if ((isset($zones)) AND (count($zones) > 0) ){
//                                        $devices[] = "{template:'" . $template . "',expanded:true,vsys:'" . $vsys_template . "',filename:'" . $filename . "',text:'" . $vsys_template . "',value:'" . $vsys_template . "',iconCls:'" . $iconCls2 . "', leaf:false, children:[" . implode(",", $zones) . "]}";
                                        $x++;
                                        $devices[] = [
                                            "template"  =>$template ,
                                            "expanded"  =>true,
                                            "vsys"      =>$vsys_template ,
                                            "filename"  =>$filename ,
                                            "text"      =>$vsys_template ,
                                            "value"     =>$vsys_template ,
                                            "iconCls"   =>$iconCls2 ,
                                            "leaf"      =>false,
                                            "children"  =>$zones,
                                            "id"        =>$x
                                        ];
                                        unset($zones);
                                    }
                                    else {
//                                        $devices[] = "{template:'" . $template . "',expanded:true,vsys:'" . $vsys_template . "',filename:'" . $filename . "',text:'" . $vsys_template . "',value:'" . $vsys_template . "',iconCls:'" . $iconCls2 . "', leaf:false, children:[]}";
                                        $x++;
                                        $devices[] = [
                                            "template"  =>$template ,
                                            "expanded"  =>true,
                                            "vsys"      =>$vsys_template,
                                            "filename"  =>$filename ,
                                            "text"      =>$vsys_template ,
                                            "value"     =>$vsys_template ,
                                            "iconCls"   =>$iconCls2 ,
                                            "leaf"      =>true,
                                            "id"        =>$x
                                        ];
                                    }
                                }
                            }

                            if ( (isset($devices)) AND (count($devices) > 0)) {
//                                $network_tree[] = "{expanded:true,template:'" . $template . "',vsys:'" . $vsys . "',filename:'" . $filename . "',text:'Device',value:'device', element:'all', iconCls:'icon-device', type:'device', leaf:false,children:[" . implode(",", $devices) . "]}";
                                $x++;
                                $network_tree[] = [
                                    "expanded"  =>true,
                                    "template"  =>$template ,
                                    "vsys"      =>$vsys ,
                                    "filename"  =>$filename ,
                                    "text"      =>'Device',
                                    "value"     =>'device',
                                    "element"   =>'all',
                                    "iconCls"   =>'icon-device',
                                    "type"      =>'device',
                                    "leaf"      =>false,
                                    "children"  =>$devices,
                                    "id"        =>$x
                                ];
                            }
                            else {
//                                $network_tree[] = "{template:'" . $template . "',vsys:'" . $vsys . "',filename:'" . $filename . "',text:'Device',value:'device', element:'all', iconCls:'icon-device', type:'device', leaf:true}";
                                $x++;
                                $network_tree[] = [
                                    "template"  =>$template ,
                                    "vsys"      =>$vsys ,
                                    "filename"  =>$filename ,
                                    "text"      =>'Device',
                                    "value"     =>'device',
                                    "element"   =>'all',
                                    "iconCls"   =>'icon-device',
                                    "type"      =>'device',
                                    "leaf"      =>true,
                                    "id"        =>$x
                                ];
                            }

                            if ((isset($network_tree)) AND (count($network_tree) > 0)) {
//                                $template_tree[] = "{expanded:true,template:'" . $template . "',expanded:true,vsys:'" . $vsys . "',filename:'" . $filename . "',text:'" . $template_name . "',value:'" . $template_name . "',iconCls:'icon-templates', leaf:false,children:[" . implode(",", $network_tree) . "]}";
                                $x++;
                                $template_tree[] = [
                                    "expanded"  =>true,
                                    "template"  =>$template ,
                                    "expanded"  =>true,
                                    "vsys"      =>$vsys ,
                                    "filename"  =>$filename ,
                                    "text"      =>$template_name ,
                                    "value"     =>$template_name,
                                    "iconCls"   =>'icon-templates',
                                    "leaf"      =>false,
                                    "children"  =>$network_tree,
                                    "id"        =>$x
                                ];
                            }
                            else {
                                $x++;
                                $template_tree[] =  [
                                    "template"  =>$template ,
                                    "expanded"  =>true,
                                    "vsys"      =>$vsys ,
                                    "filename"  =>$filename ,
                                    "text"      =>$template_name ,
                                    "value"     =>$template_name ,
                                    "iconCls"   =>'icon-templates',
                                    "leaf"      =>true,
                                    "id"        =>$x
                                ];
                            }
                        }
                    }

                    if ( (isset($template_tree)) AND (count($template_tree) > 0) ) {
                        $x++;
                        $devicegroup_tree_main[] = [
                            "expanded"  =>true,
                            "iconCls"   =>'icon-templates',
                            "template"  =>$template ,
                            "filename"  =>$filename ,
                            "text"      =>'Templates',
                            "value"     =>'templates',
                            "element"   =>'all',
                            "type"      =>'templates',
                            "leaf"      =>false,
                            "children"  =>$template_tree,
                            "id"        =>$x
                        ];
                    }
                    else {
                        $x++;
                        $devicegroup_tree_main[] = [
                            "iconCls"   =>'icon-templates',
                            "template"  =>0 ,
                            "filename"  =>$filename,
                            "text"      =>'Templates',
                            "value"     =>'templates',
                            "element"   =>'all',
                            "type"      =>'templates',
                            "leaf"      =>true,
                            "id"        =>$x
                        ];
                    }

//                    echo "[{expanded:true,filename:'" . $filename . "', id:" . $x . ",text:'" . $devicegroup . "', value:'" . $devicegroup . "', iconCls:'" . $vendor_icon . "',leaf:false, children:[" . implode(",", $devicegroup_tree_main) . "]}]";
                    $x++;
                    $vendor = [
                        "expanded"  =>true,
                        "filename"  =>$filename,
                        "id"        =>$x,
                        "text"      =>$devicegroup,
                        "value"     =>$devicegroup ,
                        "iconCls"   =>$vendor_icon ,
                        "leaf"      =>false,
                        "children"  =>$devicegroup_tree_main,
                        "id"        =>$x
                    ];
                    $root = [
                        'text'      =>'myroot',
                        'expanded'  =>true,
                        'children'  =>$vendor,
                        'id'        =>0
                    ];
                    echo json_encode($root);
//                    echo json_encode($vendor);
                } 
                else {
                    #Firewall
                    $echo = array();
                    $objects_tree = array();
                    #Add Shared
                    $vsys = "shared";

                    # Objects
                    $getObjects = $projectdb->query("SELECT filename,element FROM pending_tasks WHERE map_filename='$filename' AND map_vsys='$vsys' AND type='object'");
                    if ($getObjects->num_rows > 0) {
                        $object = array();
                        $echo_shared = array();
                        while ($mydata = $getObjects->fetch_assoc()) {
                            $src_filename = $mydata['filename'];
                            $element = $mydata['element'];

                            list($element_text, $iconCls) = getElementIcon($element);

//                            $object[] = "{vsys:'" . $vsys . "',type:'object',element:'" . $element . "', text:'" . $element_text . " [" . $src_filename . "] <font style=text-decoration:underline; color=blue>(pending)</font></s>" . "', value:'" . $element . "',leaf:true, iconCls:'" . $iconCls . "',filename:'" . $filename . "'}";
                            $x++;
                            $object[] = [
                                "vsys"      =>$vsys ,
                                "type"      =>'object',
                                "element"   =>$element ,
                                "text"      =>$element_text . " [" . $src_filename . "] <font style=text-decoration:underline; color=blue>(pending)</font></s>" ,
                                "value"     =>$element ,
                                "leaf"      =>true,
                                "iconCls"   =>$iconCls ,
                                "filename"  =>$filename,
                                "id"        =>$x
                            ];
                        }
//                        $objects_tree[] = "{expanded:false, vsys:'" . $vsys . "',filename:'" . $filename . "',text:'Objects',value:'objects', element:'all', type:'object', leaf:false,children:[" . implode(",", $object) . "]}";
                        $x++;
                        $objects_tree[] = [
                            "expanded"  =>false,
                            "vsys"      =>$vsys ,
                            "filename"  =>$filename ,
                            "text"      =>'Objects',
                            "value"     =>'objects',
                            "element"   =>'all',
                            "type"      =>'object',
                            "leaf"      =>false,
                            "children"  =>$object,
                            "id"        =>$x
                        ];
                        unset($object);
                    }

                    # Profiles
                    $getObjects = $projectdb->query("SELECT filename,element,type FROM pending_tasks WHERE map_filename='$filename' AND map_vsys='$vsys' AND (type='shared_profiles' OR type='profiles' OR type='shared_profiles_groups' OR type='profiles_groups' OR type='shared_log_settings' OR type='log_settings')");
                    if ($getObjects->num_rows > 0) {
                        $object = array();
                        $echo_shared = array();
                        while ($mydata = $getObjects->fetch_assoc()) {
                            $src_filename = $mydata['filename'];
                            $element = $mydata['element'];
                            $thetype=$mydata['type'];

                            list($element_text, $iconCls) = getElementIcon($element);

//                            $object[] = "{vsys:'" . $vsys . "',type:'".$thetype."',element:'" . $element . "', text:'" . $element_text . " [" . $src_filename . "] <font style=text-decoration:underline; color=blue>(pending)</font></s>" . "', value:'" . $element . "',leaf:true, iconCls:'" . $iconCls . "',filename:'" . $filename . "'}";
                            $x++;
                            $object[] = [
                                "vsys"      =>$vsys ,
                                "type"      =>$thetype,
                                "element"   =>$element,
                                "text"      =>$element_text . " [" . $src_filename . "] <font style=text-decoration:underline; color=blue>(pending)</font></s>" ,
                                "value"     =>$element ,
                                "leaf"      =>true,
                                "iconCls"   =>$iconCls ,
                                "filename"  =>$filename,
                                "id"        =>$x
                            ];
                        }
//                        $objects_tree[] = "{expanded:false, vsys:'" . $vsys . "',filename:'" . $filename . "',text:'Profiles',value:'shared_profiles', element:'all', type:'profiles', leaf:false,children:[" . implode(",", $object) . "], iconCls:'icon-shared_profile_group'}";
                        if ((isset($object)) AND (count($object)>0)){
                            $x++;
                            $objects_tree[] = [
                                "expanded"  =>false,
                                "vsys"      =>$vsys ,
                                "filename"  =>$filename ,
                                "text"      =>'Profiles',
                                "value"     =>'shared_profiles',
                                "element"   =>'all',
                                "type"      =>'profiles',
                                "leaf"      =>false,
                                "children"  =>$object,
                                "iconCls"   =>'icon-shared_profile_group',
                                "id"        =>$x
                            ];
                        }
                        unset($objects);
                    }

                    # Response Pages
                    $getObjects = $projectdb->query("SELECT filename,element,type FROM pending_tasks WHERE map_filename='$filename' AND map_vsys='$vsys' AND type='shared_response_pages';");
                    if ($getObjects->num_rows > 0) {
                        $object = array();
                        $echo_shared = array();
                        while ($mydata = $getObjects->fetch_assoc()) {
                            $src_filename = $mydata['filename'];
                            $element = $mydata['element'];
                            $thetype=$mydata['type'];
                            $element_text = "Response-Pages";
                            $iconCls = "icon-response_page";
                            $x++;
                            $object[] = [
                                "vsys"      =>$vsys ,
                                "type"      =>$thetype,
                                "element"   =>$element,
                                "text"      =>$element_text . " [" . $src_filename . "] <font style=text-decoration:underline; color=blue>(pending)</font></s>" ,
                                "value"     =>$element ,
                                "leaf"      =>true,
                                "iconCls"   =>$iconCls ,
                                "filename"  =>$filename,
                                "id"        =>$x
                            ];
                        }
//                        $objects_tree[] = "{expanded:false, vsys:'" . $vsys . "',filename:'" . $filename . "',text:'Profiles',value:'shared_profiles', element:'all', type:'profiles', leaf:false,children:[" . implode(",", $object) . "], iconCls:'icon-shared_profile_group'}";
                        if ((isset($object)) AND (count($object)>0)){
                            $x++;
                            $objects_tree[] = [
                                "expanded"  =>false,
                                "vsys"      =>$vsys ,
                                "filename"  =>$filename ,
                                "text"      =>'Response-Pages',
                                "value"     =>'shared_response_pages',
                                "element"   =>'all',
                                "type"      =>'shared_response_pages',
                                "leaf"      =>false,
                                "children"  =>$object,
                                "iconCls"   =>'icon-response_page',
                                "id"        =>$x
                            ];
                        }
                        unset($objects);
                    }
                    
                    $iconCls2 = "icon-shared_device";
                    if ( (isset($objects_tree)) AND (count($objects_tree) > 0) ) {
//                        $devicegroup_tree_main[] = "{expanded:true,vsys:'shared',filename:'" . $filename . "',text:'shared',value:'shared',iconCls:'" . $iconCls2 . "', leaf:false,children:[" . implode(",", $objects_tree) . "]}";
                        $x++;
                        $devicegroup_tree_main[] = [
                            "expanded"  =>true,
                            "vsys"      =>'shared',
                            "filename"  =>$filename ,
                            "text"      =>'shared',
                            "value"     =>'shared',
                            "iconCls"   =>$iconCls2 ,
                            "leaf"      =>false,
                            "children"  =>$objects_tree,
                            "id"        =>$x
                        ];
                        unset($objects_tree);
                        unset($object);
                    }
                    else {
                        $iconCls2 = "icon-shared_device";
                        $text = "shared";
//                        $devicegroup_tree_main[] = "{expanded:true,vsys:'" . $vsys . "',filename:'" . $filename . "',text:'" . $text . "',value:'" . $vsys . "',iconCls:'" . $iconCls2 . "', leaf:true}";
                        $x++;
                        $devicegroup_tree_main[] = [
                            "expanded"  =>true,
                            "vsys"      =>$vsys ,
                            "filename"  =>$filename ,
                            "text"      =>$text ,
                            "value"     =>$vsys ,
                            "iconCls"   =>$iconCls2 ,
                            "leaf"      =>true,
                            "id"        =>$x
                        ];
                    }

                    if ((isset($filterbcDG)) AND ($filterbcDG !="all")){
                        $getVsys = $projectdb->query("SELECT name as vsys FROM virtual_systems WHERE source='$source' AND name='$filterbcDG';");
                    }
                    else{
                        $getVsys = $projectdb->query("SELECT name as vsys FROM virtual_systems WHERE source='$source' AND name!='shared';");
                    }
                    while ($data2 = $getVsys->fetch_assoc()) {
                        $vsys = $data2['vsys'];
                        $text = $vsys;
                        $iconCls2 = "icon-device";
                        $getObjects = $projectdb->query("SELECT filename,element FROM pending_tasks WHERE map_filename='$filename' AND map_vsys='$vsys' AND type='object'");
                        if ($getObjects->num_rows > 0) {
                            $object = array();
                            $echo_shared = array();
                            while ($mydata = $getObjects->fetch_assoc()) {
                                $src_filename = $mydata['filename'];
                                $element = $mydata['element'];

                                list($element_text, $iconCls) = getElementIcon($element);

//                                $object[] = "{vsys:'" . $vsys . "',type:'object',element:'" . $element . "', text:'" . $element_text . " [" . $src_filename . "] <font style=text-decoration:underline; color=blue>(pending)</font></s>" . "', value:'" . $element . "',leaf:true, iconCls:'" . $iconCls . "',filename:'" . $filename . "'}";
                                $x++;
                                $object[] = [
                                    "vsys"      =>$vsys ,
                                    "type"      =>'object',
                                    "element"   =>$element ,
                                    "text"      =>$element_text . " [" . $src_filename . "] <font style=text-decoration:underline; color=blue>(pending)</font></s>" ,
                                    "value"     =>$element,
                                    "leaf"      =>true,
                                    "iconCls"   =>$iconCls ,
                                    "filename"  =>$filename,
                                    "id"        =>$x
                                ];
                            }
//                            $objects_tree[] = "{expanded:false, vsys:'" . $vsys . "',filename:'" . $filename . "',text:'Objects',value:'objects', element:'all', type:'object', leaf:false,children:[" . implode(",", $object) . "]}";
                            $x++;
                            $objects_tree[] = [
                                "expanded"  =>false,
                                "vsys"      =>$vsys ,
                                "filename"  =>$filename ,
                                "text"      =>'Objects',
                                "value"     =>'objects',
                                "element"   =>'all',
                                "type"      =>'object',
                                "leaf"      =>false,
                                "children"  =>$object,
                                "id"        =>$x
                            ];
                            unset($object);
                        }
                        
                        $getObjects = $projectdb->query("SELECT filename,element,type FROM pending_tasks WHERE map_filename='$filename' AND map_vsys='$vsys' AND (type='shared_profiles' OR type='profiles' OR type='shared_profiles_groups' OR type='profiles_groups' OR type='shared_log_settings' OR type='log_settings')");
                        if ($getObjects->num_rows > 0) {
                            $object = array();
                            $echo_shared = array();
                            while ($mydata = $getObjects->fetch_assoc()) {
                                $src_filename = $mydata['filename'];
                                $element = $mydata['element'];
                                $thetype=$mydata['type'];

                                list($element_text, $iconCls) = getElementIcon($element);

//                                $object[] = "{vsys:'" . $vsys . "',type:'".$thetype."',element:'" . $element . "', text:'" . $element_text . " [" . $src_filename . "] <font style=text-decoration:underline; color=blue>(pending)</font></s>" . "', value:'" . $element . "',leaf:true, iconCls:'" . $iconCls . "',filename:'" . $filename . "'}";
                                $x++;
                                $object[] = [
                                    "vsys"      =>$vsys ,
                                    "type"      =>$thetype,
                                    "element"   =>$element ,
                                    "text"      =>$element_text . " [" . $src_filename . "] <font style=text-decoration:underline; color=blue>(pending)</font></s>" ,
                                    "value"     =>$element ,
                                    "leaf"      =>true,
                                    "iconCls"   =>$iconCls ,
                                    "filename"  =>$filename,
                                    "id"        =>$x
                                ];
                            }
//                            $objects_tree[] = "{expanded:false, vsys:'" . $vsys . "',filename:'" . $filename . "',text:'Profiles',value:'shared_profiles', element:'all', type:'profiles', leaf:false,children:[" . implode(",", $object) . "], iconCls:'icon-shared_profile_group'}";
                            $x++;
                            $objects_tree[] = [
                                "expanded"  =>false,
                                "vsys"      =>$vsys ,
                                "filename"  =>$filename ,
                                "text"      =>'Profiles',
                                "value"     =>'shared_profiles',
                                "element"   =>'all',
                                "type"      =>'profiles',
                                "leaf"      =>false,
                                "children"  =>$object,
                                "iconCls"   =>'icon-shared_profile_group',
                                "id"        =>$x
                            ];
                            unset($objects);
                        }

                        $getObjects = $projectdb->query("SELECT filename,element FROM pending_tasks WHERE map_filename='$filename' AND map_vsys='$vsys' AND type='zones'");
                        if ($getObjects->num_rows > 0) {
                            $network1 = array();
                            $template_all = array();
                            while ($mydata = $getObjects->fetch_assoc()) {
                                $src_filename = $mydata['filename'];
                                $element = $mydata['element'];
                                $iconCls = "icon-zone";
//                                $object[] = "{vsys:'" . $vsys . "',type:'network',element:'" . $element . "', text:'" . $element . " [" . $src_filename . "] <font style=text-decoration:underline; color=blue>(pending)</font></s>" . "', value:'" . $element . "',leaf:true, iconCls:'" . $iconCls . "',filename:'" . $filename . "'}";
                                $x++;
                                $object[] = [
                                    "vsys"      =>$vsys ,
                                    "type"      =>'network',
                                    "element"   =>$element ,
                                    "text"      =>$element . " [" . $src_filename . "] <font style=text-decoration:underline; color=blue>(pending)</font></s>" ,
                                    "value"     =>$element ,
                                    "leaf"      =>true,
                                    "iconCls"   =>$iconCls ,
                                    "filename"  =>$filename,
                                    "id"        =>$x
                                ];
                            }
//                            $objects_tree[] = "{expanded:false, vsys:'" . $vsys . "',type:'zones',element:'all', text:'Zones', value:'network', iconCls:'icon-zone', leaf:false,filename:'" . $filename . "', children:[" . implode(",", $object) . "]}";
                            $x++;
                            $objects_tree[] = [
                                "expanded"  =>false,
                                "vsys"      =>$vsys ,
                                "type"      =>'zones',
                                "element"   =>'all',
                                "text"      =>'Zones',
                                "value"     =>'network',
                                "iconCls"   =>'icon-zone',
                                "leaf"      =>false,
                                "filename"  =>$filename ,
                                "children"  =>$object,
                                "id"        =>$x
                                ];
                            unset($object);
                        }

                        $getObjects = $projectdb->query("SELECT filename,element FROM pending_tasks WHERE map_filename='$filename' AND map_vsys='$vsys' AND type='policy'");
                        if ($getObjects->num_rows > 0) {
                            $object = array();
                            while ($mydata = $getObjects->fetch_assoc()) {
                                $src_filename = $mydata['filename'];
                                $element = $mydata['element'];

                                list($element_text, $iconCls) = getElementIcon($element);

//                                $object[] = "{vsys:'" . $vsys . "',type:'policy',element:'" . $element . "', text:'" . $element_text . " [" . $src_filename . "] <font style=text-decoration:underline; color=blue>(pending)</font></s>" . "', value:'" . $element . "',leaf:true, iconCls:'" . $iconCls . "',filename:'" . $filename . "'}";
                                $x++;
                                $object[] = [
                                    "vsys"      =>$vsys ,
                                    "type"      =>'policy',
                                    "element"   =>$element ,
                                    "text"      =>$element_text . " [" . $src_filename . "] <font style=text-decoration:underline; color=blue>(pending)</font></s>" ,
                                    "value"     =>$element ,
                                    "leaf"      =>true,
                                    "iconCls"   =>$iconCls ,
                                    "filename"  =>$filename,
                                    "id"        =>$x
                                ];
                            }
//                            $objects_tree[] = "{expanded:false, vsys:'" . $vsys . "',filename:'" . $filename . "',text:'Policies',value:'policies', element:'all', type:'policy', leaf:false,children:[" . implode(",", $object) . "]}";
                            $x++;
                            $objects_tree[] = [
                                "expanded"  =>false,
                                "vsys"      =>$vsys ,
                                "filename"  =>$filename ,
                                "text"      =>'Policies',
                                "value"     =>'policies',
                                "element"   =>'all',
                                "type"      =>'policy',
                                "leaf"      =>false,
                                "children"  =>$object,
                                "id"        =>$x
                            ];
                        }
                        unset($object);

                        if ( (isset($objects_tree)) AND (count($objects_tree) > 0) ) {
//                            $devicegroup_tree[] = "{expanded:true,vsys:'" . $vsys . "',filename:'" . $filename . "',text:'" . $text . "',value:'" . $vsys . "',iconCls:'" . $iconCls2 . "', leaf:false,children:[" . implode(",", $objects_tree) . "]}";
                            $x++;
                            $devicegroup_tree[] = [
                                "expanded"  =>true,
                                "vsys"      =>$vsys ,
                                "filename"  =>$filename ,
                                "text"      =>$text ,
                                "value"     =>$vsys ,
                                "iconCls"   =>$iconCls2 ,
                                "leaf"      =>false,
                                "children"  =>$objects_tree,
                                "id"        =>$x
                            ];
                            unset($objects_tree);
                            unset($object);
                        }
                        else {
//                            $devicegroup_tree[] = "{expanded:true,vsys:'" . $vsys . "',filename:'" . $filename . "',text:'" . $text . "',value:'" . $vsys . "',iconCls:'" . $iconCls2 . "', leaf:true}";
                            $x++;
                            $devicegroup_tree[] = [
                                "expanded"  =>true,
                                "vsys"      =>$vsys ,
                                "filename"  =>$filename ,
                                "text"      =>$text ,
                                "value"     =>$vsys ,
                                "iconCls"   =>$iconCls2 ,
                                "leaf"      =>true,
                                "id"        =>$x
                            ];
                        }
                    }

                    if ((isset($devicegroup_tree)) AND (count($devicegroup_tree) > 0)) {
//                        $devicegroup_tree_main[] = "{expanded:true,vsys:'" . $vsys . "',filename:'" . $filename . "',iconCls:'icon-device',text:'Device',value:'vsys', element:'all', type:'vsys', leaf:false,children:[" . implode(",", $devicegroup_tree) . "]}";
                        $x++;
                        $devicegroup_tree_main[] = [
                            "expanded"  =>true,
                            "vsys"      =>$vsys ,
                            "filename"  =>$filename ,
                            "iconCls"   =>'icon-device',
                            "text"      =>'Device',
                            "value"     =>'vsys',
                            "element"   =>'all',
                            "type"      =>'vsys',
                            "leaf"      =>false,
                            "children"  =>$devicegroup_tree,
                            "id"        =>$x
                        ];
                    }
                    else {
//                        $devicegroup_tree_main[] = "{expanded:true,vsys:'" . $vsys . "',filename:'" . $filename . "',iconCls:'icon-device',text:'Device',value:'vsys', element:'all', type:'vsys', leaf:true}";
                        $x++;
                        $devicegroup_tree_main[] = [
                            "expanded"  =>true,
                            "vsys"      =>$vsys ,
                            "filename"  =>$filename ,
                            "iconCls"   =>'icon-device',
                            "text"      =>'Device',
                            "value"     =>'vsys',
                            "element"   =>'all',
                            "type"      =>'vsys',
                            "leaf"      =>true,
                            "id"        =>$x
                        ];
                    }

                    # Network
                    $getTemplates = $projectdb->query("SELECT id,name FROM templates_mapping WHERE filename='$filename';");
                    if ($getTemplates->num_rows > 0) {
                        while ($getTemplatesData = $getTemplates->fetch_assoc()) {
                            $template_name = $getTemplatesData['name'];
                            $template = $getTemplatesData['id'];
                            $virtual_routers = array();
                            $interfaces = array();
                            $iconCls2 = "icon-device";
                            $echo = array();
                            $network = array();

                            $getObjects = $projectdb->query("SELECT filename,element FROM pending_tasks WHERE map_filename='$filename' AND map_template='$template' AND type='virtual_router'");
                            if ($getObjects->num_rows > 0) {
                                $network1 = array();
                                $template_all = array();
                                while ($mydata = $getObjects->fetch_assoc()) {
                                    $src_filename = $mydata['filename'];
                                    $element = $mydata['element'];
                                    $iconCls = "icon-vr";
//                                    $network1[] = "{vsys:'" . $vsys . "',type:'network',element:'" . $element . "', text:'" . $element . " [" . $src_filename . "] <font style=text-decoration:underline; color=blue>(pending)</font></s>" . "', value:'" . $element . "',leaf:true, iconCls:'" . $iconCls . "',filename:'" . $filename . "'}";
                                    $x++;
                                    $network1[] = [
                                        "vsys"      =>$vsys,
                                        "type"      =>'network',
                                        "element"   =>$element,
                                        "text"      =>$element."[".$src_filename."] <font style=text-decoration:underline; color=blue>(pending)</font></s>",
                                        "value"     =>$element,
                                        "leaf"      =>true,
                                        "iconCls"   =>$iconCls,
                                        "filename"  =>$filename,
                                        "id"        =>$x
                                    ];
                                }
//                                $network[] = "{expanded:false,template:'" . $template . "',type:'virtual_router',element:'all', text:'Virtual Routers', value:'network',leaf:false, filename:'" . $filename . "',iconCls:'icon-vr',children:[" . implode(",", $network1) . "]}";
                                $x++;
                                $network[] = [
                                    "expanded"      => false,
                                    "template"      => $template,
                                    "type"          =>"virtual_router",
                                    "element"       =>'all',
                                    "text"          =>'Virtual Routers',
                                    "value"         =>'network',
                                    "leaf"          => false,
                                    "filename"      => $filename,
                                    "iconCls"       =>'icon-vr',
                                    "children"      =>$network1,
                                    "id"            =>$x
                                ];
                                unset($network1);
                            }
                            /*else {
//                                $network[] = "{template:'" . $template . "',type:'virtual_router',element:'all', text:'Virtual Routers', value:'network',leaf:true, filename:'" . $filename . "',iconCls:'icon-vr'}";
                                $network[] = [
                                    "template"      =>$template,
                                    "type"          =>'virtual_router',
                                    "element"       =>'all',
                                    "text"          =>'Virtual Routers',
                                    "value"         =>'network',
                                    "leaf"          =>true,
                                    "filename"      =>$filename,
                                    "iconCls"       =>'icon-vr'
                                ];
                            }*/
                            $getObjects = $projectdb->query("SELECT filename,element FROM pending_tasks WHERE map_filename='$filename' AND map_template='$template' AND type='interfaces'");
                            if ($getObjects->num_rows > 0) {
                                $network1 = array();
                                $template_all = array();
                                while ($mydata = $getObjects->fetch_assoc()) {
                                    $src_filename = $mydata['filename'];
                                    $element = $mydata['element'];
                                    $iconCls = "icon-interfaces";
//                                    $network1[] = "{vsys:'" . $vsys . "',type:'network',element:'" . $element . "', text:'" . $element . " [" . $src_filename . "] <font style=text-decoration:underline; color=blue>(pending)</font></s>" . "', value:'" . $element . "',leaf:true, iconCls:'" . $iconCls . "',filename:'" . $filename . "'}";
                                    $x++;
                                    $network1[] = [
                                        "vsys"      =>$vsys,
                                        "type"      =>'network',
                                        "element"   =>$element,
                                        "text"      =>$element."[".$src_filename."] <font style=text-decoration:underline; color=blue>(pending)</font></s>",
                                        "value"     =>$element,
                                        "leaf"      =>true,
                                        "iconCls"   =>$iconCls,
                                        "filename"  =>$filename,
                                        "id"        =>$x
                                    ];
                                }
//                                $network[] = "{expanded:false,template:'" . $template . "',type:'interfaces',element:'all', text:'Interfaces', value:'network', iconCls:'icon-interfaces', leaf:false,filename:'" . $filename . "', children:[" . implode(",", $network1) . "]}";
                                $x++;
                                $network[] = [
                                    "expanded"      =>false,
                                    "template"      =>$template,
                                    "type"          =>'interfaces',
                                    "element"       =>'all',
                                    "text"          =>'Interfaces',
                                    "value"         =>'network',
                                    "iconCls"       =>'icon-interfaces',
                                    "leaf"          =>false,
                                    "filename"      =>$filename,
                                    "children"      =>$network1,
                                    "id"            =>$x
                                ];
                                unset($network1);
                            }
                           /* else {
//                                $network[] = "{template:'" . $template . "',type:'interfaces',element:'all', text:'Interfaces', value:'network', iconCls:'icon-interfaces', leaf:true,filename:'" . $filename . "'}";
                                $network[] = [
                                    "template"      =>$template,
                                    "type"          =>'interfaces',
                                    "element"       =>'all',
                                    "text"          =>'Interfaces',
                                    "value"         =>'network',
                                    "iconCls"       =>'icon-interfaces',
                                    "leaf"          =>true,
                                    "filename"      =>$filename,
                                ];
                            }*/
                            $getObjects = $projectdb->query("SELECT filename,element FROM pending_tasks WHERE map_filename='$filename' AND map_template='$template' AND type='interface_management_profile'");
                            if ($getObjects->num_rows > 0) {
                                $network1 = array();
                                $template_all = array();
                                while ($mydata = $getObjects->fetch_assoc()) {
                                    $src_filename = $mydata['filename'];
                                    $element = $mydata['element'];
                                    $iconCls = "icon-interface-mgmt";
//                                    $network1[] = "{vsys:'" . $vsys . "',type:'network',element:'" . $element . "', text:'" . $element . " [" . $src_filename . "] <font style=text-decoration:underline; color=blue>(pending)</font></s>" . "', value:'" . $element . "',leaf:true, iconCls:'" . $iconCls . "',filename:'" . $filename . "'}";
                                    $x++;
                                    $network1[] = [
                                        "vsys"      =>$vsys,
                                        "type"      =>'network',
                                        "element"   =>$element,
                                        "text"      =>$element."[".$src_filename."] <font style=text-decoration:underline; color=blue>(pending)</font></s>",
                                        "value"     =>$element,
                                        "leaf"      =>true,
                                        "iconCls"   =>$iconCls,
                                        "filename"  =>$filename,
                                        "id"        =>$x
                                    ];
                                }
//                                $network[] = "{expanded:false,template:'" . $template . "',type:'interface_management_profile',element:'all', text:'Interface Mgmt', value:'network', iconCls:'icon-interface-mgmt', leaf:false,filename:'" . $filename . "', children:[" . implode(",", $network1) . "]}";
                                $x++;
                                $network[] = [
                                    "expanded"          =>false,
                                    "template"          =>$template,
                                    "type"              =>'interface_management_profile',
                                    "element"           =>'all',
                                    "text"              =>'Interface Mgmt',
                                    "value"             =>'network', 
                                    "iconCls"           =>'icon-interface-mgmt', 
                                    "leaf"              =>false,
                                    "filename"          =>$filename,
                                    "children"          =>$network1,
                                    "id"                =>$x
                                ];
                                unset($network1);
                            }
                            /*else {
//                                $network[] = "{template:'" . $template . "',type:'interface_management_profile',element:'all', text:'Interface Mgmt', value:'network', iconCls:'icon-interface-mgmt', leaf:true,filename:'" . $filename . "'}";
                                $network[] = [
                                    "template"      =>$template,
                                    "type"          =>'interface_management_profile',
                                    "element"       =>'all',
                                    "text"          =>'Interface Mgmt',
                                    "value"         =>'network',
                                    "iconCls"       =>'icon-interface-mgmt',
                                    "leaf"          =>true,
                                    "filename"      =>$filename,
                                ];
                            }*/

                            # IPSec Tunnels
                            $getObjects = $projectdb->query("SELECT filename,element FROM pending_tasks WHERE map_filename='$filename' AND map_template='$template' AND type='ipsec_tunnel'");
                            if ($getObjects->num_rows > 0) {
                                $network1 = array();
                                $template_all = array();
                                while ($mydata = $getObjects->fetch_assoc()) {
                                    $src_filename = $mydata['filename'];
                                    $element = $mydata['element'];
                                    $iconCls = "icon-ipsec-tunnels";
//                                    $network1[] = "{vsys:'" . $vsys . "',type:'network',element:'" . $element . "', text:'" . $element . " [" . $src_filename . "] <font style=text-decoration:underline; color=blue>(pending)</font></s>" . "', value:'" . $element . "',leaf:true, iconCls:'" . $iconCls . "',filename:'" . $filename . "'}";
                                    $x++;
                                    $network1[] = [
                                        "vsys"          =>$vsys,
                                        "type"          =>'network',
                                        "element"       =>$element,
                                        "text"          =>$element."[".$src_filename."] <font style=text-decoration:underline; color=blue>(pending)</font></s>",
                                        "value"         =>$element,
                                        "leaf"          =>true,
                                        "iconCls"       =>$iconCls,
                                        "filename"      =>$filename,
                                        "id"            =>$x
                                    ];
                                }
//                                $network[] = "{expanded:false,template:'" . $template . "',type:'ipsec_tunnel',element:'all', text:'IPSec Tunnels', value:'network', iconCls:'icon-ipsec-tunnels', leaf:false,filename:'" . $filename . "', children:[" . implode(",", $network1) . "]}";
                                $x++;
                                $network[] = [
                                    "expanded"          =>false,
                                    "template"          =>$template,
                                    "type"              =>'ipsec_tunnel',
                                    "element"           =>'all',
                                    "text"              =>'IPSec Tunnels',
                                    "value"             =>'network',
                                    "iconCls"           =>'icon-ipsec-tunnels',
                                    "leaf"              =>false,
                                    "filename"          =>$filename,
                                    "children"          =>$network1,
                                    "id"                =>$x
                                ];
                                unset($network1);
                            }
                           /* else {
//                                $network[] = "{template:'" . $template . "',type:'ipsec_tunnel',element:'all', text:'IPSec Tunnels', value:'network', iconCls:'icon-ipsec-tunnels', leaf:true,filename:'" . $filename . "'}";
                                $network[] = [
                                    "template"          =>$template,
                                    "type"              =>'ipsec_tunnel',
                                    "element"           =>'all',
                                    "text"              =>'IPSec Tunnels',
                                    "value"             =>'network',
                                    "iconCls"           =>'icon-ipsec-tunnels',
                                    "leaf"              =>true,
                                    "filename"          =>$filename,
                                ];
                            }*/

                            # IKE Gateways
                            $getObjects = $projectdb->query("SELECT filename,element FROM pending_tasks WHERE map_filename='$filename' AND map_template='$template' AND type='ike_gateways_profiles'");
                            if ($getObjects->num_rows > 0) {
                                $network1 = array();
                                $template_all = array();
                                while ($mydata = $getObjects->fetch_assoc()) {
                                    $src_filename = $mydata['filename'];
                                    $element = $mydata['element'];
                                    $iconCls = "icon-ike-gateways";
//                                    $network1[] = "{vsys:'" . $vsys . "',type:'network',element:'" . $element . "', text:'" . $element . " [" . $src_filename . "] <font style=text-decoration:underline; color=blue>(pending)</font></s>" . "', value:'" . $element . "',leaf:true, iconCls:'" . $iconCls . "',filename:'" . $filename . "'}";
                                    $x++;
                                    $network1[] = [
                                        "vsys"      =>$vsys,
                                        "type"      =>'network',
                                        "element"   =>$element,
                                        "text"      =>$element."[".$src_filename."] <font style=text-decoration:underline; color=blue>(pending)</font></s>",
                                        "value"     =>$element,
                                        "leaf"      =>true,
                                        "iconCls"   =>$iconCls,
                                        "filename"  =>$filename,
                                        "id"        =>$x
                                    ];
                                }
//                                $network[] = "{expanded:false,template:'" . $template . "',type:'ike_gateways_profiles',element:'all', text:'IKE Gateways', value:'network', iconCls:'icon-ike-gateways', leaf:false,filename:'" . $filename . "', children:[" . implode(",", $network1) . "]}";
                                $x++;
                                $network[] = [
                                    "expanded"      =>false,
                                    "template"      =>$template,
                                    "type"          =>'ike_gateways_profiles',
                                    "element"       =>'all',
                                    "text"          =>'IKE Gateways',
                                    "value"         =>'network',
                                    "iconCls"       =>'icon-ike-gateways',
                                    "leaf"          =>false,
                                    "filename"      =>$filename,
                                    "children"      =>$network1,
                                    "id"            =>$x
                                ];
                                unset($network1);
                            }
                            /*else {
//                                $network[] = "{template:'" . $template . "',type:'ike_gateways_profiles',element:'all', text:'IKE Gateways', value:'network', iconCls:'icon-ike-gateways', leaf:true,filename:'" . $filename . "'}";
                                $network[] = [
                                    "template"      =>$template,
                                    "type"          =>'ike_gateways_profiles',
                                    "element"       =>'all',
                                    "text"          =>'IKE Gateways',
                                    "value"         =>'network',
                                    "iconCls"       =>'icon-ike-gateways',
                                    "leaf"          =>true,
                                    "filename"      =>$filename,
                                ];
                            }*/
                            # IPSec Crypto
                            $getObjects = $projectdb->query("SELECT filename,element FROM pending_tasks WHERE map_filename='$filename' AND map_template='$template' AND type='ipsec_crypto_profiles'");
                            if ($getObjects->num_rows > 0) {
                                $network1 = array();
                                $template_all = array();
                                while ($mydata = $getObjects->fetch_assoc()) {
                                    $src_filename = $mydata['filename'];
                                    $element = $mydata['element'];
                                    $iconCls = "icon-ipsec-crypto";
//                                    $network1[] = "{vsys:'" . $vsys . "',type:'network',element:'" . $element . "', text:'" . $element . " [" . $src_filename . "] <font style=text-decoration:underline; color=blue>(pending)</font></s>" . "', value:'" . $element . "',leaf:true, iconCls:'" . $iconCls . "',filename:'" . $filename . "'}";
                                    $x++;
                                    $network1[] = [
                                        "vsys"      =>$vsys,
                                        "type"      =>'network',
                                        "element"   =>'" . $element . "',
                                        "text"      =>$element."[".$src_filename."] <font style=text-decoration:underline; color=blue>(pending)</font></s>",
                                        "value"     =>$element,
                                        "leaf"      =>true,
                                        "iconCls"   =>$iconCls,
                                        "filename"  =>$filename,
                                        "id"        =>$x
                                    ];
                                }
//                                $network[] = "{expanded:false,template:'" . $template . "',type:'ipsec_crypto_profiles',element:'all', text:'IPSec Crypto', value:'network', iconCls:'icon-ipsec-crypto', leaf:false,filename:'" . $filename . "', children:[" . implode(",", $network1) . "]}";
                                $x++;
                                $network[] = [
                                    "expanded"  =>false,
                                    "template"  =>$template,
                                    "type"      =>'ipsec_crypto_profiles',
                                    "element"   =>'all',
                                    "text"      =>'IPSec Crypto',
                                    "value"     =>'network',
                                    "iconCls"   =>'icon-ipsec-crypto',
                                    "leaf"      =>false,
                                    "filename"  =>$filename,
                                    "children"  =>$network1,
                                    "id"        =>$x
                                    ];
                                unset($network1);
                            }
                           /* else {
//                                $network[] = "{template:'" . $template . "',type:'ipsec_crypto_profiles',element:'all', text:'IPSec Crypto', value:'network', iconCls:'icon-ipsec-crypto', leaf:true,filename:'" . $filename . "'}";
                                $network[] = [
                                    "template"  =>$template,
                                    "type"      =>'ipsec_crypto_profiles',
                                    "element"   =>'all',
                                    "text"      =>'IPSec Crypto',
                                    "value"     =>'network',
                                    "iconCls"   =>'icon-ipsec-crypto',
                                    "leaf"      =>true,
                                    "filename"  =>$filename,
                                ];
                            }*/

                            # IKE Crypto
                            $getObjects = $projectdb->query("SELECT filename,element FROM pending_tasks WHERE map_filename='$filename' AND map_template='$template' AND type='ike_crypto_profiles'");
                            if ($getObjects->num_rows > 0) {
                                $network1 = array();
                                $template_all = array();
                                while ($mydata = $getObjects->fetch_assoc()) {
                                    $src_filename = $mydata['filename'];
                                    $element = $mydata['element'];
                                    $iconCls = "icon-ipsec-crypto";
//                                    $network1[] = "{vsys:'" . $vsys . "',type:'network',element:'" . $element . "', text:'" . $element . " [" . $src_filename . "] <font style=text-decoration:underline; color=blue>(pending)</font></s>" . "', value:'" . $element . "',leaf:true, iconCls:'" . $iconCls . "',filename:'" . $filename . "'}";
                                    $x++;
                                    $network1[] = [
                                        "vsys"      =>$vsys,
                                        "type"      =>'network',
                                        "element"   =>$element,
                                        "text"      =>$element . " [" . $src_filename . "] <font style=text-decoration:underline; color=blue>(pending)</font></s>",
                                        "value"     =>$element,
                                        "leaf"      =>true,
                                        "iconCls"   =>$iconCls,
                                        "filename"  =>$filename,
                                        "id"        =>$x
                                    ];
                                }
//                                $network[] = "{expanded:false,template:'" . $template . "',type:'ike_crypto_profiles',element:'all', text:'IKE Crypto', value:'network', iconCls:'icon-ipsec-crypto', leaf:false,filename:'" . $filename . "', children:[" . implode(",", $network1) . "]}";
                                $x++;
                                $network[] = [
                                    "expanded"  =>false,
                                    "template"  =>$template,
                                    "type"      =>'ike_crypto_profiles',
                                    "element"   =>'all',
                                    "text"      =>'IKE Crypto',
                                    "value"     =>'network',
                                    "iconCls"   =>'icon-ipsec-crypto',
                                    "leaf"      =>false,
                                    "filename"  =>$filename,
                                    "children"  =>$network1,
                                    "id"        =>$x
                                ];
                                unset($network1);
                            }
                            /*else {
//                                $network[] = "{template:'" . $template . "',type:'ike_crypto_profiles',element:'all', text:'IKE Crypto', value:'network', iconCls:'icon-ipsec-crypto', leaf:true,filename:'" . $filename . "'}";
                                $network[] = [
                                    "template"  =>$template,
                                    "type"      =>'ike_crypto_profiles',
                                    "element"   =>'all',
                                    "text"      =>'IKE Crypto',
                                    "value"     =>'network',
                                    "iconCls"   =>'icon-ipsec-crypto',
                                    "leaf"      =>true,
                                    "filename"  =>$filename
                                ];
                            }*/

                            # Monitor Profile
                            $getObjects = $projectdb->query("SELECT filename,element FROM pending_tasks WHERE map_filename='$filename' AND map_template='$template' AND type='monitor_profile'");
                            if ($getObjects->num_rows > 0) {
                                $network1 = array();
                                $template_all = array();
                                while ($mydata = $getObjects->fetch_assoc()) {
                                    $src_filename = $mydata['filename'];
                                    $element = $mydata['element'];
                                    $iconCls = "icon-monitor";
//                                    $network1[] = "{vsys:'" . $vsys . "',type:'network',element:'" . $element . "', text:'" . $element . " [" . $src_filename . "] <font style=text-decoration:underline; color=blue>(pending)</font></s>" . "', value:'" . $element . "',leaf:true, iconCls:'" . $iconCls . "',filename:'" . $filename . "'}";
                                    $x++;
                                    $network1[] = [
                                        "vsys"      =>$vsys,
                                        "type"      =>'network',
                                        "element"   =>$element,
                                        "text"      =>$element."[" . $src_filename . "] <font style=text-decoration:underline; color=blue>(pending)</font></s>",
                                        "value"     =>$element,
                                        "leaf"      =>true,
                                        "iconCls"   =>$iconCls,
                                        "filename"  =>$filename,
                                        "id"        =>$x
                                    ];
                                }
//                                $network[] = "{expanded:false,template:'" . $template . "',type:'monitor_profile',element:'all', text:'Monitor Profile', value:'network', iconCls:'icon-monitor', leaf:false,filename:'" . $filename . "', children:[" . implode(",", $network1) . "]}";
                                $x++;
                                $network[] = [
                                    "expanded"  =>false,
                                    "template"  =>$template,
                                    "type"      =>'monitor_profile',
                                    "element"   =>'all',
                                    "text"      =>'Monitor Profile',
                                    "value"     =>'network',
                                    "iconCls"   =>'icon-monitor',
                                    "leaf"      =>false,
                                    "filename"  =>$filename ,
                                    "children"  =>$network1,
                                    "id"        =>$x
                                ];
                                unset($network1);
                            }
                            /*else {
//                                $network[] = "{template:'" . $template . "',type:'monitor_profile',element:'all', text:'Monitor Profile', value:'network', iconCls:'icon-monitor', leaf:true,filename:'" . $filename . "'}";
                                $network[] = [
                                    "template"  =>$template,
                                    "type"      =>'monitor_profile',
                                    "element"   =>'all',
                                    "text"      =>'Monitor Profile',
                                    "value"     =>'network',
                                    "iconCls"   =>'icon-monitor',
                                    "leaf"      =>true,
                                    "filename"  =>$filename
                                ];
                            }*/

                            # GlobalProtect IPSec Crypto (Only Version > 7)
                            if($version >= 7){
                                $getObjects = $projectdb->query("SELECT filename,element FROM pending_tasks WHERE map_filename='$filename' AND map_template='$template' AND type='global_protect_app_ipsec_crypto_profiles'");
                                if ($getObjects->num_rows > 0) {
                                    $network1 = array();
                                    $template_all = array();
                                    while ($mydata = $getObjects->fetch_assoc()) {
                                        $src_filename = $mydata['filename'];
                                        $element = $mydata['element'];
                                        $iconCls = "icon-ipsec-crypto";
//                                        $network1[] = "{vsys:'" . $vsys . "',type:'network',element:'" . $element . "', text:'" . $element . " [" . $src_filename . "] <font style=text-decoration:underline; color=blue>(pending)</font></s>" . "', value:'" . $element . "',leaf:true, iconCls:'" . $iconCls . "',filename:'" . $filename . "'}";
                                        $x++;
                                        $network1[] = [
                                            "vsys"      =>$vsys ,
                                            "type"      =>'network',
                                            "element"   =>$element ,
                                            "text"      =>$element . " [" . $src_filename . "] <font style=text-decoration:underline; color=blue>(pending)</font></s>" ,
                                            "value"     =>$element ,
                                            "leaf"      =>true,
                                            "iconCls"   =>$iconCls ,
                                            "filename"  =>$filename,
                                            "id"        =>$x
                                        ];
                                    }
//                                    $network[] = "{expanded:false,template:'" . $template . "',type:'global_protect_app_ipsec_crypto_profiles',element:'all', text:'GlobalProtect IPSec Crypto', value:'network', iconCls:'icon-ipsec-crypto', leaf:false,filename:'" . $filename . "', children:[" . implode(",", $network1) . "]}";
                                    $x++;
                                    $network[] = [
                                        "expanded"  =>false,
                                        "template"  =>$template ,
                                        "type"      =>'global_protect_app_ipsec_crypto_profiles',
                                        "element"   =>'all',
                                        "text"      =>'GlobalProtect IPSec Crypto',
                                        "value"     =>'network',
                                        "iconCls"   =>'icon-ipsec-crypto',
                                        "leaf"      =>false,
                                        "filename"  =>$filename ,
                                        "children"  =>$network1,
                                        "id"        =>$x
                                    ];
                                    unset($network1);
                                }
                               /* else {
//                                    $network[] = "{template:'" . $template . "',type:'global_protect_app_ipsec_crypto_profiles',element:'all', text:'GlobalProtect IPSec Crypto', value:'network', iconCls:'icon-ipsec-crypto', leaf:true,filename:'" . $filename . "'}";
                                    $network[] = [
                                        "template"=> $template ,
                                        "type"=>'global_protect_app_ipsec_crypto_profiles',
                                        "element"=>'all',
                                        "text"=>'GlobalProtect IPSec Crypto',
                                        "value"=>'network',
                                        "iconCls"=>'icon-ipsec-crypto',
                                        "leaf"=>true,
                                        "filename"=> $filename
                                    ];
                                }*/
                            }

                            # VLANs
                            $getObjects = $projectdb->query("SELECT filename,element FROM pending_tasks WHERE map_filename='$filename' AND map_template='$template' AND type='vlans'");
                            if ($getObjects->num_rows > 0) {
                                $network1 = array();
                                $template_all = array();
                                while ($mydata = $getObjects->fetch_assoc()) {
                                    $src_filename = $mydata['filename'];
                                    $element = $mydata['element'];
                                    $iconCls = "icon-vlans";
//                                    $network1[] = "{vsys:'" . $vsys . "',type:'network',element:'" . $element . "', text:'" . $element . " [" . $src_filename . "] <font style=text-decoration:underline; color=blue>(pending)</font></s>" . "', value:'" . $element . "',leaf:true, iconCls:'" . $iconCls . "',filename:'" . $filename . "'}";
                                    $x++;
                                    $network1[] = [
                                        "vsys"      =>$vsys ,
                                        "type"      =>'network',
                                        "element"   =>$element ,
                                        "text"      =>$element . " [" . $src_filename . "] <font style=text-decoration:underline; color=blue>(pending)</font></s>" ,
                                        "value"     =>$element ,
                                        "leaf"      =>true,
                                        "iconCls"   =>$iconCls ,
                                        "filename"  =>$filename,
                                        "id"        =>$x
                                    ];
                                }
//                                $network[] = "{expanded:false,template:'" . $template . "',type:'vlans',element:'all', text:'VLANs', value:'network', iconCls:'icon-vlans', leaf:false,filename:'" . $filename . "', children:[" . implode(",", $network1) . "]}";
                                $x++;
                                $network[] = [
                                    "expanded"  =>false,
                                    "template"  =>$template ,
                                    "type"      =>'vlans',
                                    "element"   =>'all',
                                    "text"      =>'VLANs',
                                    "value"     =>'network',
                                    "iconCls"   =>'icon-vlans',
                                    "leaf"      =>false,
                                    "filename"  =>$filename ,
                                    "children"  =>$network1,
                                    "id"        =>$x
                                ];
                                unset($network1);
                            }
                            /*else {
//                                $network[] = "{template:'" . $template . "',type:'vlans',element:'all', text:'VLANs', value:'network', iconCls:'icon-vlans', leaf:true,filename:'" . $filename . "'}";
                                $network[] = [
                                    "template"=> $template ,
                                    "type"=>'vlans',
                                    "element"=>'all',
                                    "text"=>'VLANs',
                                    "value"=>'network',
                                    "iconCls"=>'icon-vlans',
                                    "leaf"=>true,
                                    "filename"=> $filename
                                ];
                            }*/

                            # Virtual Wires
                            $getObjects = $projectdb->query("SELECT filename,element FROM pending_tasks WHERE map_filename='$filename' AND map_template='$template' AND type='virtual_wires'");
                            if ($getObjects->num_rows > 0) {
                                $network1 = array();
                                $template_all = array();
                                while ($mydata = $getObjects->fetch_assoc()) {
                                    $src_filename = $mydata['filename'];
                                    $element = $mydata['element'];
                                    $iconCls = "icon-vwire";
//                                    $network1[] = "{vsys:'" . $vsys . "',type:'network',element:'" . $element . "', text:'" . $element . " [" . $src_filename . "] <font style=text-decoration:underline; color=blue>(pending)</font></s>" . "', value:'" . $element . "',leaf:true, iconCls:'" . $iconCls . "',filename:'" . $filename . "'}";
                                    $x++;
                                    $network1[] = [
                                        "vsys"      =>$vsys ,
                                        "type"      =>'network',
                                        "element"   =>$element ,
                                        "text"      =>$element . " [" . $src_filename . "] <font style=text-decoration:underline; color=blue>(pending)</font></s>" ,
                                        "value"     =>$element ,
                                        "leaf"      =>true,
                                        "iconCls"   =>$iconCls ,
                                        "filename"  =>$filename,
                                        "id"        =>$x
                                    ];
                                }
//                                $network[] = "{expanded:false,template:'" . $template . "',type:'virtual_wires',element:'all', text:'Virtual Wires', value:'network', iconCls:'icon-vwire', leaf:false,filename:'" . $filename . "', children:[" . implode(",", $network1) . "]}";
                                $x++;
                                $network[] = [
                                    "expanded"  =>false,
                                    "template"  =>$template ,
                                    "type"      =>'virtual_wires',
                                    "element"   =>'all',
                                    "text"      =>'Virtual Wires',
                                    "value"     =>'network',
                                    "iconCls"   =>'icon-vwire',
                                    "leaf"      =>false,
                                    "filename"  =>$filename ,
                                    "children"  =>$network1,
                                    "id"        =>$x
                                ];
                                unset($network1);
                            }
                            /*else {
//                                $network[] = "{template:'" . $template . "',type:'virtual_wires',element:'all', text:'Virtual Wires', value:'network', iconCls:'icon-vwire', leaf:true,filename:'" . $filename . "'}";
                                $network[] = [
                                    "template"=> $template ,
                                    "type"=>'virtual_wires',
                                    "element"=>'all',
                                    "text"=>'Virtual Wires',
                                    "value"=>'network',
                                    "iconCls"=>'icon-vwire',
                                    "leaf"=>true,
                                    "filename"=> $filename
                                ];
                            }*/
                            
                            if ((isset($network)) AND (count($network) > 0)) {
//                                $devicegroup_tree_main[] = "{expanded:true,template:'" . $template . "',vsys:'" . $vsys . "',filename:'" . $filename . "',text:'Network',value:'network', element:'all', iconCls:'icon-network', type:'network', leaf:false,children:[" . implode(",", $network) . "]}";
                                $x++;
                                $devicegroup_tree_main[] = [
                                    "expanded"  =>true,
                                    "template"  =>$template ,
                                    "vsys"      =>$vsys ,
                                    "filename"  =>$filename ,
                                    "text"      =>'Network',
                                    "value"     =>'network',
                                    "element"   =>'all',
                                    "iconCls"   =>'icon-network',
                                    "type"      =>'network',
                                    "leaf"      =>false,
                                    "children"  =>$network,
                                    "id"        =>$x
                                ];
                                unset($network);
                            }
                            else {
//                                $devicegroup_tree_main[] = "{expanded:true,template:'" . $template . "',vsys:'" . $vsys . "',filename:'" . $filename . "',text:'Network',value:'network', element:'all', iconCls:'icon-network', type:'network', leaf:true}";
                                $x++;
                                $devicegroup_tree_main[] = [
                                    "expanded"  =>true,
                                    "template"  =>$template ,
                                    "vsys"      =>$vsys ,
                                    "filename"  =>$filename,
                                    "text"      =>'Network',
                                    "value"     =>'network',
                                    "element"   =>'all',
                                    "iconCls"   =>'icon-network',
                                    "type"      =>'network',
                                    "leaf"      =>true,
                                    "id"        =>$x
                                ];
                            }
                        }
                    }

//                    echo "[{expanded:true,filename:'" . $filename . "', id:" . $x . ",text:'" . $devicegroup . "', value:'" . $devicegroup . "', iconCls:'" . $vendor_icon . "',leaf:false, children:[" . implode(",", $devicegroup_tree_main) . "]}]";
                    $x++;
                    $vendor = [
                        "expanded"  =>true,
                        "filename"  =>$filename,
                        "id"        =>$x,
                        "text"      =>$devicegroup,
                        "value"     =>$devicegroup ,
                        "iconCls"   =>$vendor_icon ,
                        "leaf"      =>false,
                        "children"  =>$devicegroup_tree_main,
                        "id"        =>$x
                    ];
                    $x++;
                    $root = [
                        'text'      =>'Root',
                        'expanded'  =>true,
                        'children'  =>$vendor,
                        "id"        =>$x
                    ];
                    echo json_encode($root);
//                    echo json_encode($vendor);
                }
            }
        }
    } 
    elseif ($type == "settings") {

        #commit
        $getCommit = $projectdb->query("SELECT id FROM pending_tasks WHERE map_filename!='';");
        if ($getCommit->num_rows > 0) {
            $commit = 1;
        } else {
            $commit = 0;
        }
        // User ID via log
        $getUserId = $projectdb->query("SELECT id FROM userid_from_log;");
        if ($getUserId->num_rows > 0) {
            $userid = 1;
        } else {
            $userid = 0;
        }
        // App ID via log
        $getAppId = $projectdb->query("SELECT id FROM applications_from_log;");
        if ($getAppId->num_rows > 0) {
            $appid = 1;
        } else {
            $appid = 0;
        }
        echo '{"commit":"' . $commit . '", "userid":"' . $userid . '", "appid":"' . $appid . '"}';
    } 
    elseif ($type == "sources") {
        $getAll = $projectdb->query("SELECT id,filename,vendor,version FROM device_mapping GROUP BY filename ORDER BY id;");
        $myData = array();
        if ($getAll->num_rows==0){
            $myData[] = array("id" => "0", "filename" => "None");
        }
        else{
            while ($data = $getAll->fetch_object()) {
                $myData[] = $data;
            }
        }
        $count = count($myData);
        echo '{"total":"' . $count . '","rows":' . json_encode($myData) . '}';
    }
    elseif ($type == "sources_no_bc") {
        $getAll = $projectdb->query("SELECT id,filename,vendor,version FROM device_mapping WHERE baseconfig=0 GROUP BY filename ORDER BY id;");
        $count = $getAll->num_rows;
        $myData = array();
        while ($data = $getAll->fetch_object()) {
            $myData[] = $data;
        }
        $myData[] = array("id" => "0", "filename" => "all");
        $count = count($myData);
        echo '{"total":"' . $count . '","rows":' . json_encode($myData) . '}';
    }
    elseif ($type == "sources_not_all") {
        $getAll = $projectdb->query("SELECT id,filename,vendor,version FROM device_mapping GROUP BY filename ORDER BY id;");
        $myData = array();
        $count = $getAll->num_rows;
        while ($data = $getAll->fetch_object()) {
            $myData[] = $data;
        }
//        if ($count > 1) {
//            //$myData[] = array("id" => "0", "filename" => "all");
//        }
        $count = count($myData);
        echo '{"total":"' . $count . '","rows":' . json_encode($myData) . '}';
    }
    elseif ($type == "vsysbysource") {
        switch($_SERVER['REQUEST_METHOD'])
        {
            case 'GET':
                $source = (integer) (isset($_GET['source']) ? $_GET['source'] : '');
                //$template = (integer) (isset($_GET['template']) ? $_GET['template'] : '');
                break;
            case 'POST':
                $source = (integer) (isset($_POST['source']) ? $_POST['source'] : '');
                //$template = (integer) (isset($_POST['template']) ? $_POST['template'] : '');
                break;
            default:
                $source = (integer) (isset($_POST['source']) ? $_POST['source'] : '');
                //$template = (integer) (isset($_POST['template']) ? $_POST['template'] : '');
                break;
        }

        $source = $projectdb->real_escape_string($source);

        $myData = array();

        $getFilenanme = $projectdb->query("SELECT filename, vendor, ispanorama FROM device_mapping WHERE id='$source';");
        if ($getFilenanme->num_rows == 1) {

            $alldata = $getFilenanme->fetch_assoc();
            $filename = $alldata['filename'];
            $vendor = $alldata['vendor'];
            $ispanorama = $alldata['ispanorama'];

            //if (isset($filename) && $filename != "") {
            //    $addQuery = "WHERE filename='$filename'";
            //} else {
            //    $addQuery = "GROUP BY vsys";
            //}


            if($vendor == "Paloalto Networks"){

                if($ispanorama == "1"){
                    $getAll = $projectdb->query("SELECT dm.vsys, dg.source, dm.version, dm.vendor, dm.filename 
                        FROM devicegroups dg, device_mapping dm WHERE dm.id = dg.device_mapping_id AND source = '$source' ORDER BY dm.vsys;");
                    //echo "Is panorama1: SELECT dm.vsys, dg.source, dm.version, dm.vendor, dm.filename
                    //    FROM devicegroups dg, device_mapping dm WHERE dm.id = dg.device_mapping_id AND source = '$source' ;";
                    $myData[] = array("id" => "-1", "vsys" => "all");
                   // $myData[] = array("id" => "0", "vsys" => "shared");
                }
                else{
                    //$getAll = $projectdb->query("SELECT id,vsys,version,vendor FROM device_mapping $addQuery;");
                    $getAll = $projectdb->query("SELECT vs.name AS vsys, vs.template, vs.source, dm.version, dm.vendor 
                        FROM virtual_systems vs, device_mapping dm WHERE vs.name = dm.vsys AND source = '$source' GROUP BY vsys;");
                    $myData[] = array("id" => "-1", "vsys" => "all");
                    $myData[] = array("id" => "0", "vsys" => "shared");
                    // O A DEVICE MAPPING???
                    //echo "is panorama 0: SELECT vs.name, vs.template, vs.source, dm.version, dm.vendor
                    //    FROM virtual_systems vs, device_mapping dm WHERE vs.name = dm.vsys AND source = '$source' $query ;";
                }

                while ($data = $getAll->fetch_object()) {
                    $myData[] = $data;
                }

            }
            else{
                $getFilename=$projectdb->query("SELECT filename FROM device_mapping WHERE id='$source';");
                if ($getFilename->num_rows==1){
                    $getFilenameData=$getFilename->fetch_assoc();
                    $filename=$getFilenameData['filename'];
                    $getAll = $projectdb->query("SELECT id,vsys,version,vendor FROM device_mapping WHERE filename='$filename' AND vsys!='shared' ORDER BY vsys;");
                    $myData[] = array("id" => "-1", "vsys" => "all");
                    $myData[] = array("id" => "0", "vsys" => "shared");
                    while ($data = $getAll->fetch_object()) {
                        $myData[] = $data;
                    }
                }
                else{
                    $myData[] = array("id" => "-1", "vsys" => "all");
                    $myData[] = array("id" => "0", "vsys" => "shared");
                }
            }
        }


        //$getAll = $projectdb->query("SELECT id,vsys,version,vendor FROM device_mapping $addQuery;");
        //$myData = array();
        //$myData[] = array("id" => "0", "vsys" => "all");
        //while ($data = $getAll->fetch_object()) {
        //    $myData[] = $data;
        //}

        $count = count($myData);
        echo '{"total":"' . $count . '","rows":' . json_encode($myData) . '}';

    }
    elseif ($type == "vsysbysource_by_template") {
        switch($_SERVER['REQUEST_METHOD'])
        {
            case 'GET':
                $source = (integer) (isset($_GET['source']) ? $_GET['source'] : '');
                $template = (integer) (isset($_GET['template']) ? $_GET['template'] : '');
                break;
            case 'POST':
                $source = (integer) (isset($_POST['source']) ? $_POST['source'] : '');
                $template = (integer) (isset($_POST['template']) ? $_POST['template'] : '');
                break;
            default:
                $source = (integer) (isset($_POST['source']) ? $_POST['source'] : '');
                $template = (integer) (isset($_POST['template']) ? $_POST['template'] : '');
                break;
        }

        $source = $projectdb->real_escape_string($source);
        $template = $projectdb->real_escape_string($template);

        $myData = array();

        $getFilenanme = $projectdb->query("SELECT filename, vendor, ispanorama FROM device_mapping WHERE id = '$source';");
        if ($getFilenanme->num_rows == 1) {

            $alldata = $getFilenanme->fetch_assoc();
            $filename = $alldata['filename'];
            $vendor = $alldata['vendor'];
            $ispanorama = $alldata['ispanorama'];

            if(($template == "all") || ($template == "") || ($template == "0") || ($template == "templates-all")){
                $query = "";
            }
            else{
                $query = "AND template = '$template' ";
            }

            if($vendor == "Paloalto Networks"){

                $getAll = $projectdb->query("SELECT vs.name AS vsys, vs.template, vs.source, dm.version, dm.vendor 
                        FROM virtual_systems vs, device_mapping dm WHERE vs.name = dm.vsys AND dm.filename = '$filename' $query GROUP BY vsys ORDER BY vsys;");
                //echo "SELECT vs.name AS vsys, vs.template, vs.source, dm.version, dm.vendor
                //        FROM virtual_systems vs, device_mapping dm WHERE vs.name = dm.vsys AND source = '$source' $query ;";

                $myData[] = array("id" => "-1", "vsys" => "all");
                $myData[] = array("id" => "0", "vsys" => "shared");
                while ($data = $getAll->fetch_object()) {
                    if($data->vsys =='shared'){
                        $myData[1] = $data;
                    } else {
                        $myData[] = $data;
                    }
                }

            }
            else{
                $getAll = $projectdb->query("SELECT id,vsys,version,vendor FROM device_mapping WHERE filename='$filename' ORDER BY vsys;");
                $myData[] = array("id" => "-1", "vsys" => "all");
                $myData[] = array("id" => "0", "vsys" => "shared");
                while ($data = $getAll->fetch_object()) {
                    if($data->vsys =='shared'){
                        $myData[1] = $data;
                    } else {
                        $myData[] = $data;
                    }
                }
            }
        }


        //$getAll = $projectdb->query("SELECT id,vsys,version,vendor FROM device_mapping $addQuery;");
        //$myData = array();
        //$myData[] = array("id" => "0", "vsys" => "all");
        //while ($data = $getAll->fetch_object()) {
        //    $myData[] = $data;
        //}

        $count = count($myData);
        echo '{"total":"' . $count . '","rows":' . json_encode($myData) . '}';

    }
    elseif ($type == "vsysbysource_with_all") {
        switch($_SERVER['REQUEST_METHOD'])
        {
            case 'GET':
                $source = (integer) (isset($_GET['source']) ? $_GET['source'] : '');
                break;
            case 'POST':
                $source = (integer) (isset($_POST['source']) ? $_POST['source'] : '');
                break;
            default:
                $source = (integer) (isset($_POST['source']) ? $_POST['source'] : '');
                break;
        }

        $source = $projectdb->real_escape_string($source);

        $getFilenanme = $projectdb->query("SELECT filename FROM device_mapping WHERE id='$source';");
        if ($getFilenanme->num_rows == 1) {
            $alldata = $getFilenanme->fetch_assoc();
            $filename = $alldata['filename'];
        }
        if (isset($filename) && $filename != "") {
            $addQuery = "WHERE filename='$filename'";
        } else {
            $addQuery = "GROUP BY vsys";
        }
        $getAll = $projectdb->query("SELECT id,vsys,version,vendor FROM device_mapping $addQuery ORDER BY vsys;");
        $myData = array();
        $myData[] = array("id" => "0", "vsys" => "all");
        while ($data = $getAll->fetch_object()) {
            $myData[] = $data;
        }
        $count = count($myData);
        echo '{"total":"' . $count . '","rows":' . json_encode($myData) . '}';
    }
    elseif ($type == "vsysbysource_not_all") {
        switch($_SERVER['REQUEST_METHOD'])
        {
            case 'GET':
                $source = (integer) (isset($_GET['source']) ? $_GET['source'] : '');
                break;
            case 'POST':
                $source = (integer) (isset($_POST['source']) ? $_POST['source'] : '');
                break;
            default:
                $source = (integer) (isset($_POST['source']) ? $_POST['source'] : '');
                break;
        }

        $source = $projectdb->real_escape_string($source);

//        $source = (integer) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        $getFilenanme = $projectdb->query("SELECT filename FROM device_mapping WHERE id='$source';");
        $filename = "";
        if ($getFilenanme->num_rows == 1) {
            $alldata = $getFilenanme->fetch_assoc();
            $filename = $alldata['filename'];
        }
        if ($filename != "") {
            $addQuery = "WHERE filename='$filename'";
        } else {
            $addQuery = "GROUP BY vsys";
        }
        $getAll = $projectdb->query("SELECT id,vsys,version,vendor FROM device_mapping $addQuery;");
        $count = $getAll->num_rows;
//        if ($count > 1) {
//            //$myData[] = array("id" => "0", "vsys" => "all");
//        }
        while ($data = $getAll->fetch_object()) {
            $myData[] = $data;
        }

        $count = count($myData);
        echo '{"total":"' . $count . '","rows":' . json_encode($myData) . '}';
    }
    elseif ($type == "baseconfig_vsys") {
        $getBC=$projectdb->query("SELECT id,ispanorama FROM device_mapping WHERE baseconfig=1 GROUP by filename");
        $myData = array();
        if ($getBC->num_rows==1){
            $getBCdata=$getBC->fetch_assoc();
            $source=$getBCdata['id'];
            $ispanorama=$getBCdata['ispanorama'];

            if ($ispanorama==1){
                # Panorama goes to devicegroups
                $getVsys = $projectdb->query("SELECT dg.id,vsys FROM devicegroups dg, device_mapping dm WHERE dg.device_mapping_id=dm.id AND dg.source='$source' ORDER BY vsys;");
            }
            else{
                # Firewall goes to virtual_systems
                $getVsys = $projectdb->query("SELECT id,name as vsys FROM virtual_systems WHERE source='$source' AND name!='shared' ORDER BY vsys;");
            }

            //$count = $getVsys->num_rows;

            while ($data = $getVsys->fetch_object()) {
                $myData[] = $data;
            }

            //$myData[] = array("id" => "90000", "vsys" => "shared");
            $myData[] = array("id" => "90001", "vsys" => "all");

        }
        else{
            $myData[] = array("id" => "90001", "vsys" => "all");
        }

        $count = count($myData);
        echo '{"total":"' . $count . '","rows":' . json_encode($myData) . '}';
    }
    elseif ($type == "baseconfig_template") {
        $getBC=$projectdb->query("SELECT id FROM device_mapping WHERE baseconfig=1 GROUP by filename");
        $myData = array();
        if ($getBC->num_rows==1){
            $getBCdata=$getBC->fetch_assoc();
            $source=$getBCdata['id'];
            $getAll = $projectdb->query("SELECT id,name FROM templates WHERE source='$source';");
            while ($data = $getAll->fetch_object()) {
                $myData[] = $data;
            }
        }
        $myData[] = array("id" => "0", "name" => "all");
        $count = count($myData);
        echo '{"total":"' . $count . '","templates":' . json_encode($myData) . '}';
    }
    elseif ($type == "sources_vsys") {
        $getAll = $projectdb->query("SELECT id,vsys,version,vendor FROM device_mapping WHERE baseconfig=0 ORDER BY vsys;");
        $count = $getAll->num_rows;
        $myData = array();
        while ($data = $getAll->fetch_object()) {
            $myData[] = $data;
        }
        if ($count > 1) {
            $myData[] = array("id" => "0", "vsys" => "all");
        }
        $count = count($myData);
        echo '{"total":"' . $count . '","rows":' . json_encode($myData) . '}';
    }
    elseif ($type == "templates") {
        switch($_SERVER['REQUEST_METHOD'])
        {
            case 'GET':
                $source = (integer) (isset($_GET['source']) ? $_GET['source'] : '');
                break;
            case 'POST':
                $source = (integer) (isset($_POST['source']) ? $_POST['source'] : '');
                break;
            default:
                $source = (integer) (isset($_POST['source']) ? $_POST['source'] : '');
                break;
        }

        $source = $projectdb->real_escape_string($source);

//        $source = (integer) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        if ($source == 0) {
            $addQuery = "";
        } else {
            $addQuery = "WHERE source='$source'";
        }
        $getAll = $projectdb->query("SELECT id,name,filename,source FROM templates_mapping $addQuery ORDER BY id;");
        $count = $getAll->num_rows;
        $myData[] = array("id" => "0", "name" => "all");
        while ($data = $getAll->fetch_object()) {
            $myData[] = $data;
        }
        if ($count == 0) {
            $myData=array();
            $count=1;
            $myData[] = array("id" => "0", "name" => "all");
        }
        echo '{"total":"' . $count . '","templates":' . json_encode($myData) . '}';
    }
    
} 
elseif ($action == "set") {
    if(!checkProjectRights($project,'view')){
        echo '{"success":false,"msg":"You do not have rights to manage this project"}';
        return;
    }
    if ($type == "views") {
        switch($_SERVER['REQUEST_METHOD'])
        {
            case 'GET':
                $view = (string) (isset($_GET['view']) ? $_GET['view'] : '');
                $panorama_devicegroup   = (string) (isset($_GET['panorama_devicegroup'])   ? $_GET['panorama_devicegroup'] : '');
                $panorama_rules         = (string) (isset($_GET['panorama_rules'])         ? $_GET['panorama_rules'] : '');
                $panos_vsys             = (string) (isset($_GET['panos_vsys'])             ? $_GET['panos_vsys'] : '');
                $panorama_template      = (string) (isset($_GET['panorama_template'])      ? $_GET['panorama_template'] : '');
                $source                 = (string) (isset($_GET['source'])                 ? $_GET['source'] : '');
                break;
            case 'POST':
                $view = (string) (isset($_POST['view']) ? $_POST['view'] : '');
                $panorama_devicegroup   = (string) (isset($_POST['panorama_devicegroup'])   ? $_POST['panorama_devicegroup'] : '');
                $panorama_rules         = (string) (isset($_POST['panorama_rules'])         ? $_POST['panorama_rules'] : '');
                $panos_vsys             = (string) (isset($_POST['panos_vsys'])             ? $_POST['panos_vsys'] : '');
                $panorama_template      = (string) (isset($_POST['panorama_template'])      ? $_POST['panorama_template'] : '');
                $source                 = (string) (isset($_POST['source'])                 ? $_POST['source'] : '');
                break;
            default:
                $view = (string) (isset($_POST['view']) ? $_POST['view'] : '');
                $panorama_devicegroup   = (string) (isset($_POST['panorama_devicegroup'])   ? $_POST['panorama_devicegroup'] : '');
                $panorama_rules         = (string) (isset($_POST['panorama_rules'])         ? $_POST['panorama_rules'] : '');
                $panos_vsys             = (string) (isset($_POST['panos_vsys'])             ? $_POST['panos_vsys'] : '');
                $panorama_template      = (string) (isset($_POST['panorama_template'])      ? $_POST['panorama_template'] : '');
                $source                 = (string) (isset($_POST['source'])                 ? $_POST['source'] : '');
                break;
        }

        $view = $projectdb->real_escape_string($view);
        $panorama_devicegroup = $projectdb->real_escape_string($panorama_devicegroup);
        $panorama_rules = $projectdb->real_escape_string($panorama_rules);
        $panos_vsys = $projectdb->real_escape_string($panos_vsys);
        $panorama_template = $projectdb->real_escape_string($panorama_template);
        $source = $projectdb->real_escape_string($source);

        if ($view != "") {
            $projectdb->query("UPDATE config_views SET view='$view';");
        }
        if ($panorama_devicegroup != "") {
            $projectdb->query("UPDATE config_views SET panorama_devicegroup='$panorama_devicegroup';");
            $projectdb->query("UPDATE config_views SET panos_vsys='$panorama_devicegroup';");
        }
        if ($panorama_rules != "") {
            $projectdb->query("UPDATE config_views SET panorama_rules='$panorama_rules';");
        }
        if ($panos_vsys != "") {
            $projectdb->query("UPDATE config_views SET panos_vsys='$panos_vsys';");
        }
        if (is_numeric($source)) {
            $projectdb->query("UPDATE config_views SET source='$source';");
            $getVersion = $projectdb->query("SELECT version FROM device_mapping WHERE id = '$source';");
            if ($getVersion->num_rows > 0) {
                $dataV = $getVersion->fetch_assoc();
                $version = $dataV['version'];
                $version_parser = getVersion($version);
                $projectdb->query("UPDATE config_views SET version = '$version_parser';");
            }
        }
        if ($panorama_template != "") {
            $projectdb->query("UPDATE config_views SET panorama_template='$panorama_template';");
        }
        echo json_encode(array('success' => true));
    } 
    elseif ($type == "activate") {
        switch($_SERVER['REQUEST_METHOD'])
        {
            case 'GET':
                $ids = (string) (isset($_GET['ids']) ? $_GET['ids'] : '');
                break;
            case 'POST':
                $ids = (string) (isset($_POST['ids']) ? $_POST['ids'] : '');
                break;

            default:
                $ids = (string) (isset($_POST['ids']) ? $_POST['ids'] : '');
                break;
        }

        $ids = $projectdb->real_escape_string($ids);

//        $ids = (string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']);
        $result = $projectdb->query("SELECT filename FROM device_mapping WHERE id IN (" . $ids . ") GROUP BY filename;");
        while ($data = $result->fetch_assoc()) {
            $filename = $data['filename'];
            $projectdb->query("UPDATE device_mapping SET active='1' WHERE filename='$filename';");
        }
        $result->close();
        echo json_encode(array('success' => true));
    } 
    elseif ($type == "deactivate") {
        switch($_SERVER['REQUEST_METHOD'])
        {
            case 'GET':
                $filenames = (string) (isset($_GET['filenames']) ? $_GET['filenames'] : '');
                break;
            case 'POST':
                $filenames = (string) (isset($_POST['filenames']) ? $_POST['filenames'] : '');
                break;
            default:
                $filenames = (string) (isset($_POST['filenames']) ? $_POST['filenames'] : '');
                break;
        }

        $filenames = $projectdb->real_escape_string($filenames);

//        $filenames = (string) (isset($_POST['filenames']) ? $_POST['filenames'] : $_GET['filenames']);
        take_snapshot_last($project);
        $explode = explode(",", $filenames);
        $out = array();
        foreach ($explode as $key => $values) {
            $out[] = "'$values'";
        }
        echo $out2 = implode(",", $out);
        $projectdb->query("UPDATE device_mapping SET active=0 WHERE filename IN ($out2);");
        $result = $projectdb->query("SELECT id FROM device_mapping WHERE filename IN ($out2) GROUP BY filename;");
        if ($result->num_rows > 0) {
            while ($data = $result->fetch_assoc()) {
                $source = $data['id'];
                #Delete by Source
                $getTables = $projectdb->query("SHOW TABLES;");
                $tables_list = array();
                while ($data = $getTables->fetch_array()) {
                    if ($data[0] != "") {
                        $tables_list[] = $data[0];
                    }
                }
                foreach ($tables_list as $key => $value) {
                    $projectdb->query("DELETE FROM $value WHERE source='$source';");
                }
            }
        }
        echo json_encode(array('success' => true));
    } 
    elseif ($type == "remove_source") {
        switch($_SERVER['REQUEST_METHOD'])
        {
            case 'GET':
                $filenames = (string) (isset($_GET['filenames']) ? $_GET['filenames'] : '');
                break;
            case 'POST':
                $filenames = (string) (isset($_POST['filenames']) ? $_POST['filenames'] : '');
                break;
            default:
                $filenames = (string) (isset($_POST['filenames']) ? $_POST['filenames'] : '');
                break;
        }

        $filenames = $projectdb->real_escape_string($filenames);

//        $filenames = (string) (isset($_POST['filenames']) ? $_POST['filenames'] : $_GET['filenames']);
        take_snapshot_last($project);

        if ($filenames==""){
            $getF=$projectdb->query("SELECT filename FROM device_mapping WHERE baseconfig=0;");
            if ($getF->num_rows>0){
                $explode=array();
                while($getFData=$getF->fetch_assoc()){
                    $explode[]=$getFData['filename'];
                }
            }
        }
        else{
            $explode = explode(",", $filenames);
        }


        $out = array();
        foreach ($explode as $key => $values) {
            $out2[] = "'$values'";
            #Remove File
            if (file_exists(USERSPACE_PATH."/projects/" . $project . "/" . $values)){
                unlink(USERSPACE_PATH."/projects/" . $project . "/" . $values);
            }
            if (file_exists(USERSPACE_PATH."/projects/" . $project . "/" . $values.".dat")){
                unlink(USERSPACE_PATH."/projects/" . $project . "/" . $values.".dat");
            }
        }
//        echo $out2 = implode(",", $out);
        $projectdb->query("UPDATE device_mapping SET active=0 WHERE filename IN (".implode(",",$out2).");");
        $result = $projectdb->query("SELECT id FROM device_mapping WHERE filename IN (".implode(",",$out2).") GROUP BY filename;");
        if ($result->num_rows > 0) {
            while ($data = $result->fetch_assoc()) {
                $source = $data['id'];
                #Delete by Source
                $getTables = $projectdb->query("SHOW TABLES;");
                $tables_list = array();
                while ($data = $getTables->fetch_array()) {
                    if ($data[0] != "") {
                        if (($data[0] == "config_views")
                            || preg_match("/security_rules/",$data[0])
                            || preg_match("/nat_rules/",$data[0])
                            || preg_match("/appoverride_rules/",$data[0])
                            || preg_match("/decryption_rules/",$data[0])
                            || preg_match("/pbf_rules/",$data[0])
                            || preg_match("/qos_rules/",$data[0])
                            || preg_match("/tunnel_inspect_rules/",$data[0])
                            || preg_match("/authentication_rules/",$data[0])
                            || preg_match("/captiveportal_rules/",$data[0])
                            || ($data[0] == "tag")
                        ){}
                        else {
                            $tables_list[] = $data[0];
                        }
                    }
                }
                foreach ($tables_list as $key => $value) {
                    $projectdb->query("DELETE FROM $value WHERE source='$source';");
                }

                #Remove tag and relations
                $getRules=$projectdb->query("SELECT id FROM tag WHERE source='$source';");
                if ($getRules->num_rows>0){
                    $ruleids=array();
                    while($getRulesData=$getRules->fetch_assoc()){
                        $ruleids[]=$getRulesData['id'];
                    }
                    # Remove dependencies
                    $projectdb->query("DELETE FROM tag_relations WHERE tag_id IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM tag WHERE id IN (".implode(",",$ruleids).")");
                }

                #Remove Security Rules
                $getRules=$projectdb->query("SELECT id FROM security_rules WHERE source='$source';");
                if ($getRules->num_rows>0){
                    $ruleids=array();
                    while($getRulesData=$getRules->fetch_assoc()){
                        $ruleids[]=$getRulesData['id'];
                    }
                    # Remove dependencies
                    $projectdb->query("DELETE FROM security_rules_app WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM security_rules_categories WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM security_rules_dst WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM security_rules_from WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM security_rules_hip WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM security_rules_profiles WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM security_rules_src WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM security_rules_srv WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM security_rules_tag WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM security_rules_target WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM security_rules_to WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM security_rules_usr WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM security_rules WHERE id IN (".implode(",",$ruleids).")");
                }

                #Remove Nat Rules
                $getRules=$projectdb->query("SELECT id FROM nat_rules WHERE source='$source';");
                if ($getRules->num_rows>0){
                    $ruleids=array();
                    while($getRulesData=$getRules->fetch_assoc()){
                        $ruleids[]=$getRulesData['id'];
                    }
                    # Remove dependencies
                    $projectdb->query("DELETE FROM nat_rules_dst WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM nat_rules_from WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM nat_rules_src WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM nat_rules_tag WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM nat_rules_target WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM nat_rules_translated_address WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM nat_rules_translated_address_fallback WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM nat_rules WHERE id IN (".implode(",",$ruleids).")");
                }

                #Remove Appoverride Rules
                $getRules=$projectdb->query("SELECT id FROM appoverride_rules WHERE source='$source';");
                if ($getRules->num_rows>0){
                    $ruleids=array();
                    while($getRulesData=$getRules->fetch_assoc()){
                        $ruleids[]=$getRulesData['id'];
                    }
                    # Remove dependencies
                    $projectdb->query("DELETE FROM appoverride_rules_dst WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM appoverride_rules_from WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM appoverride_rules_src WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM appoverride_rules_tag WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM appoverride_rules_to WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM appoverride_rules_target WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM appoverride_rules WHERE id IN (".implode(",",$ruleids).")");
                }

                #Remove QoS Rules
                $getRules=$projectdb->query("SELECT id FROM qos_rules WHERE source='$source';");
                if ($getRules->num_rows>0){
                    $ruleids=array();
                    while($getRulesData=$getRules->fetch_assoc()){
                        $ruleids[]=$getRulesData['id'];
                    }
                    # Remove dependencies
                    $projectdb->query("DELETE FROM qos_rules_app WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM qos_rules_categories WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM qos_rules_dst WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM qos_rules_from WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM qos_rules_src WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM qos_rules_srv WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM qos_rules_tag WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM qos_rules_to WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM qos_rules_usr WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM qos_rules_target WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM qos_rules WHERE id IN (".implode(",",$ruleids).")");
                }

                #Remove PBF Rules
                $getRules=$projectdb->query("SELECT id FROM pbf_rules WHERE source='$source';");
                if ($getRules->num_rows>0){
                    $ruleids=array();
                    while($getRulesData=$getRules->fetch_assoc()){
                        $ruleids[]=$getRulesData['id'];
                    }
                    # Remove dependencies
                    $projectdb->query("DELETE FROM pbf_rules_app WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM pbf_rules_dst WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM pbf_rules_from WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM pbf_rules_nal WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM pbf_rules_src WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM pbf_rules_srv WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM pbf_rules_tag WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM pbf_rules_usr WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM pbf_rules_target WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM pbf_rules WHERE id IN (".implode(",",$ruleids).")");
                }

                #Remove Decryption Rules
                $getRules=$projectdb->query("SELECT id FROM decryption_rules WHERE source='$source';");
                if ($getRules->num_rows>0){
                    $ruleids=array();
                    while($getRulesData=$getRules->fetch_assoc()){
                        $ruleids[]=$getRulesData['id'];
                    }
                    # Remove dependencies
                    $projectdb->query("DELETE FROM decryption_rules_categories WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM decryption_rules_dst WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM decryption_rules_from WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM decryption_rules_src WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM decryption_rules_srv WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM decryption_rules_tag WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM decryption_rules_to WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM decryption_rules_usr WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM decryption_rules_target WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM decryption_rules WHERE id IN (".implode(",",$ruleids).")");
                }

                #Remove Tunnel Inspection Rules
                $getRules=$projectdb->query("SELECT id FROM tunnel_inspect_rules WHERE source='$source';");
                if ($getRules->num_rows>0){
                    $ruleids=array();
                    while($getRulesData=$getRules->fetch_assoc()){
                        $ruleids[]=$getRulesData['id'];
                    }
                    # Remove dependencies
                    $projectdb->query("DELETE FROM tunnel_inspect_rules_app WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM tunnel_inspect_rules_dst WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM tunnel_inspect_rules_from WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM tunnel_inspect_rules_src WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM tunnel_inspect_rules_tag WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM tunnel_inspect_rules_target WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM tunnel_inspect_rules_to WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM tunnel_inspect_rules_usr WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM tunnel_inspect_rules WHERE id IN (".implode(",",$ruleids).")");
                }

                #Remove Authentication Rules
                $getRules=$projectdb->query("SELECT id FROM authentication_rules WHERE source='$source';");
                if ($getRules->num_rows>0){
                    $ruleids=array();
                    while($getRulesData=$getRules->fetch_assoc()){
                        $ruleids[]=$getRulesData['id'];
                    }
                    # Remove dependencies
                    $projectdb->query("DELETE FROM authentication_rules_categories WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM authentication_rules_dst WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM authentication_rules_from WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM authentication_rules_hip WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM authentication_rules_src WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM authentication_rules_srv WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM authentication_rules_tag WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM authentication_rules_target WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM authentication_rules_to WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM authentication_rules_usr WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM authentication_rules WHERE id IN (".implode(",",$ruleids).")");
                }

                #Remove Captive Portal Rules
                $getRules=$projectdb->query("SELECT id FROM captiveportal_rules WHERE source='$source';");
                if ($getRules->num_rows>0){
                    $ruleids=array();
                    while($getRulesData=$getRules->fetch_assoc()){
                        $ruleids[]=$getRulesData['id'];
                    }
                    # Remove dependencies
                    $projectdb->query("DELETE FROM captiveportal_rules_categories WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM captiveportal_rules_dst WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM captiveportal_rules_from WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM captiveportal_rules_src WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM captiveportal_rules_srv WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM captiveportal_rules_tag WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM captiveportal_rules_target WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM captiveportal_rules_to WHERE rule_lid IN (".implode(",",$ruleids).")");
                    $projectdb->query("DELETE FROM captiveportal_rules WHERE id IN (".implode(",",$ruleids).")");
                }

                #Remove BPAT TABLES DATA
                $projectdb->query("TRUNCATE bpat_topic;");
                $projectdb->query("TRUNCATE bpat_bpcheck;");
            }
        }
        $projectdb->query("DELETE FROM device_mapping WHERE filename IN (".implode(",",$out2).");");
        $projectdb->query("DELETE FROM pending_tasks WHERE filename IN (".implode(",",$out2).");");
        $projectdb->query("UPDATE config_views source=0;");
        echo json_encode(array('success' => true));
    } 
    elseif ($type == "baseconfig") {
        switch($_SERVER['REQUEST_METHOD'])
        {
            case 'GET':
                $node = (string) (isset($_GET['node']) ? $_GET['node'] : '');
                break;
            case 'POST':
                $node = (string) (isset($_POST['node']) ? $_POST['node'] : '');
                break;
            default:
                $node = (string) (isset($_POST['node']) ? $_POST['node'] : '');
                break;
        }

        $node = $projectdb->real_escape_string($node);

//        $node = (string) (isset($_POST['node']) ? $_POST['node'] : $_GET['node']);
        take_snapshot_last($project);
        if ($node != "") {
            $isPan = $projectdb->query("SELECT id FROM device_mapping WHERE filename='$node' AND vendor='Paloalto Networks';");
            if ($isPan->num_rows > 0) {
                $projectdb->query("UPDATE device_mapping SET baseconfig=0 WHERE baseconfig=1;");
                $projectdb->query("UPDATE device_mapping SET baseconfig=1 WHERE filename='$node';");
                $get = $projectdb->query("SELECT ispanorama FROM device_mapping WHERE filename='$node' GROUP BY filename;");
                $data = $get->fetch_assoc();
                if ($data['ispanorama'] == 1) {
                    $projectdb->query("UPDATE config_views SET view='panorama';");
                } else {
                    $projectdb->query("UPDATE config_views SET view='panos';");
                }
                echo json_encode(array('success' => true));
            } else {
                echo json_encode(array("success" => false, "msg" => "The File selected is not from Paloalto Networks."));
            }
        }
    } 
    elseif ($type == "drop_baseconfig") {
        switch($_SERVER['REQUEST_METHOD'])
        {
            case 'GET':
                $changes      = (string) (isset($_GET['changes'])          ? $_GET['changes'] : '');
                $map_vsys     = (string) (isset($_GET['map_vsys'])         ? $_GET['map_vsys'] : '');
                $map_template = (integer)(isset($_GET['map_template'])     ? $_GET['map_template'] : '');
                $map_filename = (string) (isset($_GET['map_filename'])     ? $_GET['map_filename'] : '');
                break;
            case 'POST':
                $changes      = (string) (isset($_POST['changes'])          ? $_POST['changes'] : '');
                $map_vsys     = (string) (isset($_POST['map_vsys'])         ? $_POST['map_vsys'] : '');
                $map_template = (integer) (isset($_POST['map_template'])    ? $_POST['map_template'] : '');
                $map_filename = (string) (isset($_POST['map_filename'])     ? $_POST['map_filename'] : '');
                break;
            default:
                $changes      = (string) (isset($_POST['changes'])          ? $_POST['changes'] : '');
                $map_vsys     = (string) (isset($_POST['map_vsys'])         ? $_POST['map_vsys'] : '');
                $map_template = (integer) (isset($_POST['map_template'])    ? $_POST['map_template'] : '');
                $map_filename = (string) (isset($_POST['map_filename'])     ? $_POST['map_filename'] : '');
                break;
        }

        $changes = $projectdb->real_escape_string($changes);
        $map_vsys = $projectdb->real_escape_string($map_vsys);
        $map_template = $projectdb->real_escape_string($map_template);
        $map_filename = $projectdb->real_escape_string($map_filename);

//        $changes = (string) (isset($_POST['changes']) ? $_POST['changes'] : $_GET['changes']);
//        $map_vsys = (string) (isset($_POST['map_vsys']) ? $_POST['map_vsys'] : $_GET['map_vsys']);
//        $map_template = (integer) (isset($_POST['map_template']) ? $_POST['map_template'] : $_GET['map_template']);
//        $map_filename = (string) (isset($_POST['map_filename']) ? $_POST['map_filename'] : $_GET['map_filename']);

        $data = explode(",", $changes);

        $getModel = $projectdb->query("SELECT ispanorama FROM device_mapping WHERE filename='$map_filename' GROUP BY filename");
        if ($getModel->num_rows == 1) {
            $getModelData = $getModel->fetch_assoc();
            $isPanorama = $getModelData['ispanorama'];
        }

        foreach ($data as $key => $value) {
            $data2 = explode(";", $value);
            $filename = $data2[0];//candidate-config (7) copy.xml
            $type = $data2[1];//virtual_router
            $element = $data2[2];//all
            $vsys = $data2[3];//undefined
            $template = $data2[4];//4

            if (($map_vsys == "") AND ( $map_template == "")) {
                
                
            }
            else {
                
                if($map_template == "" || $map_template == 0){
                    $getTemplate = $projectdb->query("SELECT id FROM templates_mapping WHERE filename='$map_filename';");
                    if ($getTemplate->num_rows == 1) {
                        $dataT = $getTemplate->fetch_assoc();
                        $map_template = $dataT['id'];
                    }
                }
                
                if ($type == "object") {
                    if ($element == "all") {
                        #All elements
                        $projectdb->query("UPDATE pending_tasks SET map_vsys='$map_vsys', map_filename='$map_filename' WHERE filename='$filename' AND type='$type' AND vsys='$vsys';");
                    } else {
                        #specific
                        $projectdb->query("UPDATE pending_tasks SET map_vsys='$map_vsys', map_filename='$map_filename' WHERE filename='$filename' AND type='$type' AND element='$element' AND vsys='$vsys';");
                        $sql = "UPDATE pending_tasks SET map_vsys='$map_vsys', map_filename='$map_filename' WHERE filename='$filename' AND type='$type' AND element='$element' AND vsys='$vsys';";
                        //echo "SQL: " .$sql. "\n";
                    }
                } 
                elseif (($type == "profiles") OR ($type == "profiles_groups")) {
                    if ($element == "all") {
                        #All elements
                        //echo "UPDATE pending_tasks SET map_vsys='$map_vsys', map_filename='$map_filename' WHERE filename='$filename' AND type='$type' AND vsys='$vsys';";
                        $projectdb->query("UPDATE pending_tasks SET map_vsys='$map_vsys', map_filename='$map_filename' WHERE filename='$filename' AND type='log_settings' AND vsys='$vsys';");
                        $projectdb->query("UPDATE pending_tasks SET map_vsys='$map_vsys', map_filename='$map_filename' WHERE filename='$filename' AND type='$type' AND vsys='$vsys';");
                        $projectdb->query("UPDATE pending_tasks SET map_vsys='$map_vsys', map_filename='$map_filename' WHERE filename='$filename' AND type='profiles_groups' AND vsys='$vsys';");
                    } else {
                        #specific
                        $projectdb->query("UPDATE pending_tasks SET map_vsys='$map_vsys', map_filename='$map_filename' WHERE filename='$filename' AND type='$type' AND element='$element' AND vsys='$vsys';");
                        $sql = "UPDATE pending_tasks SET map_vsys='$map_vsys', map_filename='$map_filename' WHERE filename='$filename' AND type='$type' AND element='$element' AND vsys='$vsys';";
                        //echo "SQL: " .$sql. "\n";
                    }
                }
                elseif (($type == "shared_profiles") OR ($type == "shared_profiles_groups")) {
                    if ($element == "all") {
                        #All elements
                        $projectdb->query("UPDATE pending_tasks SET map_vsys='$map_vsys', map_filename='$map_filename' WHERE filename='$filename' AND type='$type' AND vsys='$vsys';");
                        //echo "1. UPDATE pending_tasks SET map_vsys='$map_vsys', map_filename='$map_filename' WHERE filename='$filename' AND type='$type' AND vsys='$vsys';\n";
                        $projectdb->query("UPDATE pending_tasks SET map_vsys='$map_vsys', map_filename='$map_filename' WHERE filename='$filename' AND type='shared_profiles_groups' AND vsys='$vsys';");
                        //echo "2. UPDATE pending_tasks SET map_vsys='$map_vsys', map_filename='$map_filename' WHERE filename='$filename' AND type='shared_profiles_groups' AND vsys='$vsys';\n";
                        $projectdb->query("UPDATE pending_tasks SET map_vsys='$map_vsys', map_filename='$map_filename' WHERE filename='$filename' AND type='shared_log_settings' AND vsys='$vsys';");
                        //echo "3. UPDATE pending_tasks SET map_vsys='$map_vsys', map_filename='$map_filename' WHERE filename='$filename' AND type='shared_log_settings' AND vsys='$vsys';\n";
                    } else {
                        #specific
                        $projectdb->query("UPDATE pending_tasks SET map_vsys='$map_vsys', map_filename='$map_filename' WHERE filename='$filename' AND type='$type' AND element='$element' AND vsys='$vsys';");
                        $sql = "UPDATE pending_tasks SET map_vsys='$map_vsys', map_filename='$map_filename' WHERE filename='$filename' AND type='$type' AND element='$element' AND vsys='$vsys';";
                        //echo "SQL: " .$sql. "\n";
                    }
                }
                elseif ($type == "policy") {
                    if ($element == "all") {
                        #All elements
                        if($map_vsys != "shared"){
                            $projectdb->query("UPDATE pending_tasks SET map_vsys='$map_vsys', map_filename='$map_filename' WHERE filename='$filename' AND type='$type' AND vsys='$vsys';");
                        }
                    } else {
                        #specific
                        if($map_vsys != "shared"){
                            $projectdb->query("UPDATE pending_tasks SET map_vsys='$map_vsys', map_filename='$map_filename' WHERE filename='$filename' AND type='$type' AND element='$element' AND vsys='$vsys';");
                        }
                    }
                } 
                elseif ($type == "interfaces") {
                    if ($element == "all") {
                        $projectdb->query("UPDATE pending_tasks SET map_template='$map_template', map_filename='$map_filename' WHERE filename='$filename' AND type='$type' AND template = '$template';");
                    } else {
                        #specific
                        $projectdb->query("UPDATE pending_tasks SET map_template='$map_template', map_filename='$map_filename' WHERE filename='$filename' AND type='$type' AND element='$element' AND template = '$template';");
                    }
                } 
                elseif ($type == "virtual_router") {
                    if ($element == "all") {
                        $projectdb->query("UPDATE pending_tasks SET map_template='$map_template', map_filename='$map_filename' WHERE filename='$filename' AND type='$type' AND template = '$template';");
                    } else {
                        #specific
                        $projectdb->query("UPDATE pending_tasks SET map_template='$map_template', map_filename='$map_filename' WHERE filename='$filename' AND type='$type' AND element='$element' AND template = '$template';");
                    }
                } 
                elseif ($type == "zones") {
                    if ($element == "all") {
                        $projectdb->query("UPDATE pending_tasks SET map_template='$map_template', map_filename='$map_filename',map_vsys='$map_vsys' WHERE filename='$filename' AND type='$type' AND vsys='$vsys' AND template = '$template';");
                        //echo "UPDATE pending_tasks SET map_template='$map_template', map_filename='$map_filename',map_vsys='$map_vsys' WHERE filename='$filename' AND type='$type' AND vsys='$vsys' AND template = '$template';\n";
                    } else {
                        #specific
                        $projectdb->query("UPDATE pending_tasks SET map_template='$map_template', map_filename='$map_filename',map_vsys='$map_vsys' WHERE filename='$filename' AND type='$type' AND element='$element' AND vsys='$vsys' AND template = '$template';");
                    }
                } 
                elseif ($type == "interface_management_profile") {
                    if ($element == "all") {
                        $projectdb->query("UPDATE pending_tasks SET map_template='$map_template', map_filename='$map_filename',map_vsys='$map_vsys' WHERE filename='$filename' AND type='$type' AND template = '$template';");
                    } else {
                        #specific
                        $projectdb->query("UPDATE pending_tasks SET map_template='$map_template', map_filename='$map_filename',map_vsys='$map_vsys' WHERE filename='$filename' AND type='$type' AND element='$element' AND template = '$template';");
                    }
                }
                elseif ($type == "ipsec_tunnel") {
                    if ($element == "all") {
                        $projectdb->query("UPDATE pending_tasks SET map_template='$map_template', map_filename='$map_filename',map_vsys='$map_vsys' WHERE filename='$filename' AND type='$type' AND template = '$template';");
                    } else {
                        #specific
                        $projectdb->query("UPDATE pending_tasks SET map_template='$map_template', map_filename='$map_filename',map_vsys='$map_vsys' WHERE filename='$filename' AND type='$type' AND element='$element' AND template = '$template';");
                    }
                }
                elseif ($type == "ike_gateways_profiles") {
                    if ($element == "all") {
                        $projectdb->query("UPDATE pending_tasks SET map_template='$map_template', map_filename='$map_filename',map_vsys='$map_vsys' WHERE filename='$filename' AND type='$type' AND template = '$template';");
                    } else {
                        #specific
                        $projectdb->query("UPDATE pending_tasks SET map_template='$map_template', map_filename='$map_filename',map_vsys='$map_vsys' WHERE filename='$filename' AND type='$type' AND element='$element' AND template = '$template';");
                    }
                }
                elseif ($type == "ipsec_crypto_profiles") {
                    if ($element == "all") {
                        $projectdb->query("UPDATE pending_tasks SET map_template='$map_template', map_filename='$map_filename',map_vsys='$map_vsys' WHERE filename='$filename' AND type='$type' AND template = '$template';");
                    } else {
                        #specific
                        $projectdb->query("UPDATE pending_tasks SET map_template='$map_template', map_filename='$map_filename',map_vsys='$map_vsys' WHERE filename='$filename' AND type='$type' AND element='$element' AND template = '$template';");
                    }
                }
                elseif ($type == "ike_crypto_profiles") {
                    if ($element == "all") {
                        $projectdb->query("UPDATE pending_tasks SET map_template='$map_template', map_filename='$map_filename',map_vsys='$map_vsys' WHERE filename='$filename' AND type='$type' AND template = '$template';");
                    } else {
                        #specific
                        $projectdb->query("UPDATE pending_tasks SET map_template='$map_template', map_filename='$map_filename',map_vsys='$map_vsys' WHERE filename='$filename' AND type='$type' AND element='$element' AND template = '$template';");
                    }
                }
                elseif ($type == "monitor_profile") {
                    if ($element == "all") {
                        $projectdb->query("UPDATE pending_tasks SET map_template='$map_template', map_filename='$map_filename',map_vsys='$map_vsys' WHERE filename='$filename' AND type='$type' AND template = '$template';");
                    } else {
                        #specific
                        $projectdb->query("UPDATE pending_tasks SET map_template='$map_template', map_filename='$map_filename',map_vsys='$map_vsys' WHERE filename='$filename' AND type='$type' AND element='$element' AND template = '$template';");
                    }
                }
                elseif ($type == "global_protect_app_ipsec_crypto_profiles") {
                    if ($element == "all") {
                        $projectdb->query("UPDATE pending_tasks SET map_template='$map_template', map_filename='$map_filename',map_vsys='$map_vsys' WHERE filename='$filename' AND type='$type' AND template = '$template';");
                    } else {
                        #specific
                        $projectdb->query("UPDATE pending_tasks SET map_template='$map_template', map_filename='$map_filename',map_vsys='$map_vsys' WHERE filename='$filename' AND type='$type' AND element='$element' AND template = '$template';");
                    }
                }
                elseif ($type == "vlans") {
                    if ($element == "all") {
                        $projectdb->query("UPDATE pending_tasks SET map_template='$map_template', map_filename='$map_filename',map_vsys='$map_vsys' WHERE filename='$filename' AND type='$type' AND template = '$template';");
                    } else {
                        #specific
                        $projectdb->query("UPDATE pending_tasks SET map_template='$map_template', map_filename='$map_filename',map_vsys='$map_vsys' WHERE filename='$filename' AND type='$type' AND element='$element' AND template = '$template';");
                    }
                }
                elseif ($type == "virtual_wires") {
                    if ($element == "all") {
                        $projectdb->query("UPDATE pending_tasks SET map_template='$map_template', map_filename='$map_filename',map_vsys='$map_vsys' WHERE filename='$filename' AND type='$type' AND template = '$template';");
                    } else {
                        #specific
                        $projectdb->query("UPDATE pending_tasks SET map_template='$map_template', map_filename='$map_filename',map_vsys='$map_vsys' WHERE filename='$filename' AND type='$type' AND element='$element' AND template = '$template';");
                    }
                }
                elseif ($type == "shared_response_pages") {

                    if ($element == "all") {
                        #All elements

                        if (intval($map_template) > 0) {
                            $projectdb->query("UPDATE pending_tasks SET map_template='$map_template', map_filename='$map_filename', map_vsys='$map_vsys' WHERE filename='$filename' AND type='$type' AND template = '$template';");
                            //echo "1. UPDATE pending_tasks SET map_template='$map_template', map_filename='$map_filename', map_vsys='$map_vsys' WHERE filename='$filename' AND type='$type' AND template = '$template';\n";
                        } else {
                            $projectdb->query("UPDATE pending_tasks SET map_vsys='$map_vsys', map_filename='$map_filename' WHERE filename='$filename' AND type='$type' AND vsys='$vsys';");
                            //echo "2. UPDATE pending_tasks SET map_vsys='$map_vsys', map_filename='$map_filename' WHERE filename='$filename' AND type='$type' AND vsys='$vsys';\n";
                        }
                    } else {
                        #specific
                        if (intval($map_template) > 0) {
                            $projectdb->query("UPDATE pending_tasks SET map_template='$map_template', map_filename='$map_filename', map_vsys='$map_vsys' WHERE filename='$filename' AND type='$type' AND element='$element' AND template = '$template';");
                        } else {
                            $projectdb->query("UPDATE pending_tasks SET map_vsys='$map_vsys', map_filename='$map_filename' WHERE filename='$filename' AND type='$type' AND element='$element' AND vsys='$vsys';");
                        }
                    }
                } 
                elseif ($type == "response_pages") {

                    if ($element == "all") {
                        #All elements

                        if (intval($map_template) > 0) {
                            $projectdb->query("UPDATE pending_tasks SET map_template='$map_template', map_filename='$map_filename', map_vsys='$map_vsys' WHERE filename='$filename' AND type='$type' AND template = '$template';");
                        } else {
                            $projectdb->query("UPDATE pending_tasks SET map_vsys='$map_vsys', map_filename='$map_filename' WHERE filename='$filename' AND type='$type' AND vsys='$vsys';");
                        }
                    } else {
                        #specific
                        if (intval($map_template) > 0) {
                            $projectdb->query("UPDATE pending_tasks SET map_template='$map_template', map_filename='$map_filename', map_vsys='$map_vsys' WHERE filename='$filename' AND type='$type' AND element='$element' AND template = '$template';");
                        } else {
                            $projectdb->query("UPDATE pending_tasks SET map_vsys='$map_vsys', map_filename='$map_filename' WHERE filename='$filename' AND type='$type' AND element='$element' AND vsys='$vsys';");
                        }
                    }
                } 
                elseif ($type == "") {
                    # Move Policies and Objects ALL
                    $projectdb->query("UPDATE pending_tasks SET map_vsys='$map_vsys', map_filename='$map_filename' WHERE filename='$filename' AND type='policy' AND vsys='$vsys';");
                    $projectdb->query("UPDATE pending_tasks SET map_vsys='$map_vsys', map_filename='$map_filename' WHERE filename='$filename' AND type='object' AND vsys='$vsys';");
                }
            }
        }
    } 
    elseif ($type == "remove_baseconfig") {
        switch($_SERVER['REQUEST_METHOD'])
        {
            case 'GET':
                $changes      = (string) (isset($_GET['changes'])          ? $_GET['changes'] : '');
                break;
            case 'POST':
                $changes      = (string) (isset($_POST['changes'])          ? $_POST['changes'] : '');
                break;
            default:
                $changes      = (string) (isset($_POST['changes'])          ? $_POST['changes'] : '');
                break;
        }

        $changes = $projectdb->real_escape_string($changes);

//        $changes = (string) (isset($_POST['changes']) ? $_POST['changes'] : $_GET['changes']);
        $data = explode(",", $changes);
        foreach ($data as $key => $value) {
            $data2 = explode(";", $value);
            $filename = $data2[0];
            $type = $data2[1];
            $element = $data2[2];
            $vsys = $data2[3];

            $projectdb->query("UPDATE pending_tasks SET map_vsys='', map_filename='';");
            $projectdb->query("UPDATE device_mapping SET baseconfig=0 WHERE baseconfig=1;");
            /*
            if ($vsys == "") {
                if (($type == "") AND ( $element == "")) {
                    # Move Policies and Objects ALL
                    $projectdb->query("UPDATE pending_tasks SET map_vsys='', map_filename='';");
                    $projectdb->query("UPDATE device_mapping SET baseconfig=0 WHERE baseconfig=1;");
                }
            } else {
                if ($type == "object") {
                    if ($element == "all") {
                        #All elements
                        $projectdb->query("UPDATE pending_tasks SET map_vsys='', map_filename='' WHERE map_filename='$filename' AND type='$type' AND map_vsys='$vsys';");
                    } else {
                        #specific
                        $projectdb->query("UPDATE pending_tasks SET map_vsys='', map_filename='' WHERE map_filename='$filename' AND type='$type' AND element='$element' AND map_vsys='$vsys';");
                    }
                } elseif ($type == "policy") {
                    if ($element == "all") {
                        #All elements
                        $projectdb->query("UPDATE pending_tasks SET map_vsys='', map_filename='' WHERE map_filename='$filename' AND type='$type' AND map_vsys='$vsys';");
                    } else {
                        #specific
                        $projectdb->query("UPDATE pending_tasks SET map_vsys='', map_filename='' WHERE map_filename='$filename' AND type='$type' AND element='$element' AND map_vsys='$vsys';");
                    }
                } elseif ($type == "") {
                    # Move Policies and Objects ALL
                    $projectdb->query("UPDATE pending_tasks SET map_vsys='', map_filename='' WHERE map_filename='$filename' AND type='policy' AND map_vsys='$vsys';");
                    $projectdb->query("UPDATE pending_tasks SET map_vsys='', map_filename=''  WHERE map_filename='$filename' AND type='object' AND map_vsys='$vsys';");
                }
            }
            */
        }
    } 
    elseif ($type == "commit") {

        $user = $app->container->sentinel->getUser();
        $api_key= getUserApiKey($user->getAttribute("api_key")??"", $user->getAttribute("valid_til")??"",$user->getAttribute("id"));
        $userID = $user->id;
        $project = $app->project->where('name', '=', $project)->get()->first();

        $params['user_id'] = $user->id;
        $params['key'] = $api_key;

        $jobID = registerJob($params, $user, 'Merge Export');
        $taskID = registerTask($params, $user, $jobID, "ExportMerge", "Merge Export");
        send_APICallMessage($params, $user, $taskID, "ExportMerge");

        $message = [
            'code'  => true,
            'jobid' => $jobID,
            'msg'   => 'Merge Export Job Registered'
        ];
        //return $message;

        echo json_encode(array('success' => $message['code'], 'jobid'=>$message['jobid']));

    } 
    elseif ($type == "reset_baseconfig") {
        //$projectdb->query("UPDATE pending_tasks SET map_filename='', map_template='0' , map_vsys='';");
        $projectdb->query("TRUNCATE pending_tasks;");
        echo json_encode(array("success" => true));
    }
    elseif ($type == "remove_edit_table"){
        $getTruncate = $projectdb->query("DELETE FROM edit_table WHERE user_id = '$user_id';");
        echo json_encode(array('success' => true));
    }
} 
elseif ($action == "del_progress") {
    del_progress($project);
}


function addNameConfig($text_suffix, $name){
    
    $name_fin = $name;
    
    $name = $name_fin;
    $name_fin = $name_fin."_".$text_suffix;
    if (strlen($name_fin) > 63){
        $total_name_fin = strlen($name_fin);
        $total_subs = $total_name_fin - 63;
        $name = substr($name, 0, -$total_subs);
        $name_fin = $name.$text_suffix;
    }
    
    return $name_fin;
}

function createXMLNode($template, $vsys, $filename, $text, $value, $element, $iconCls, $type, $children){
    if (count($children) > 0){
        $node = [
            "expanded"=>true,
            "template"=> $template ,
            "vsys"=> $vsys ,
            "filename"=> $filename ,
            "text"=>$text,
            "value"=>$value,
            "element"=>$element,
            "iconCls"=>$iconCls,
            "type"=>$type,
            "leaf"=>false,
            "children"=> $children
        ];
    }
    else{
        $node = [
            "template"=> $template ,
            "vsys"=> $vsys ,
            "filename"=> $filename ,
            "text"=>$text,
            "value"=>$value,
            "element"=>$element,
            "iconCls"=>$iconCls,
            "type"=>$type,
            "leaf"=>true,
        ];
    }

    return $node;
}


function getElementIcon($element){

    if ($element == "address") {
        $element_text = "Address";
        $iconCls = "icon-address";
    } elseif ($element == "address_groups") {
        $element_text = "Address-Groups";
        $iconCls = "icon-address_groups";
    } elseif ($element == "services") {
        $element_text = "Services";
        $iconCls = "icon-services";
    } elseif ($element == "services_groups") {
        $element_text = "Services-Groups";
        $iconCls = "icon-services_groups";
    } elseif ($element == "applications") {
        $element_text = "Applications";
        $iconCls = "icon-applications";
    } elseif ($element == "applications_filters") {
        $element_text = "Applications Filters";
        $iconCls = "icon-applications_filter";
    } elseif ($element == "applications_groups") {
        $element_text = "Applications-Groups";
        $iconCls = "icon-applications_groups";
    } elseif ($element == "tag") {
        $element_text = "Tags";
        $iconCls = "icon-tags";
    } elseif ($element == "shared_tag") {
        $element_text = "Tags";
        $iconCls = "icon-shared_tags";
    } elseif ($element == "external_list") {
        $element_text = "External-List";
        $iconCls = "icon-external_lists";
    } elseif ($element == "regions") {
        $element_text = "Regions";
        $iconCls = "icon-regions";
    } elseif ($element == "shared_address") {
        $element_text = "Address";
        $iconCls = "icon-shared_address";
    } elseif ($element == "shared_address_groups") {
        $element_text = "Address-Groups";
        $iconCls = "icon-shared_address_groups";
    } elseif ($element == "shared_services") {
        $element_text = "Services";
        $iconCls = "icon-shared_services";
    } elseif ($element == "shared_services_groups") {
        $element_text = "Services-Groups";
        $iconCls = "icon-shared_services_groups";
    } elseif ($element == "shared_applications") {
        $element_text = "Applications";
        $iconCls = "icon-shared_applications";
    } elseif ($element == "shared_applications_filters") {
        $element_text = "Applications Filters";
        $iconCls = "icon-shared_applications_filter";
    } elseif ($element == "shared_applications_groups") {
        $element_text = "Applications-Groups";
        $iconCls = "icon-shared_applications_groups";
    } elseif ($element == "shared_tag") {
        $element_text = "Tags";
        $iconCls = "icon-tags";
    } elseif ($element == "shared_external_list") {
        $element_text = "External-List";
        $iconCls = "icon-external_lists";
    } elseif ($element == "shared_regions") {
        $element_text = "Regions";
        $iconCls = "icon-regions";
    } elseif ($element == "shared_schedules") {
        $element_text = "Schedules";
        $iconCls = "icon-schedules";
    } elseif ($element == "schedules") {
        $element_text = "Schedules";
        $iconCls = "icon-shared_schedules";
    } elseif ($element == "reports") {
        $element_text = "Reports";
        $iconCls = "icon-schedules";
    } elseif ($element == "shared_reports") {
        $element_text = "Reports";
        $iconCls = "icon-shared_schedules";
    }elseif ($element == "shared_profiles") {
        $element_text = "Security";
        $iconCls = "icon-shared_profile_group";
    } elseif ($element == "shared_profiles_groups") {
        $element_text = "Security Group";
        $iconCls = "icon-shared_profile_group";
    } elseif ($element == "shared_log_settings") {
        $element_text = "Log Forwarding";
        $iconCls = "icon-shared_log_forwarding";
    } elseif ($element == "profiles") {
        $element_text = "Security/Content";
        $iconCls = "icon-profile_group";
    } elseif ($element == "profiles_groups") {
        $element_text = "Security Group";
        $iconCls = "icon-profile_group";
    } elseif ($element == "security") {
        $element_text = "Security";
        $iconCls = "icon-securityrule";
    } elseif ($element == "nat") {
        $element_text = "Nat";
        $iconCls = "icon-rulenat";
    } elseif ($element == "appoverride") {
        $element_text = "App Override";
        $iconCls = "icon-appoverride";
    } elseif ($element == "others") {
        $element_text = "Other Policies";
        $iconCls = "icon-decryption";
    } elseif ($element == "log_settings") {
        $element_text = "Log Forwarding";
        $iconCls = "icon-log_forwarding";
    } elseif ($element == "authentication") {
        $element_text = "Authentication";
        $iconCls = "icon-authentication";
    } elseif ($element == "captiveportal") {
        $element_text = "CaptivePortal";
        $iconCls = "icon-authentication";
    } elseif ($element == "decryption") {
        $element_text = "Decryption";
        $iconCls = "icon-decryption";
    } elseif ($element == "dos") {
        $element_text = "DoS Protection";
        $iconCls = "icon-dos_protection";
    } elseif ($element == "pbf") {
        $element_text = "Policy Based Forwarding";
        $iconCls = "icon-pbf";
    } elseif ($element == "qos") {
        $element_text = "QoS";
        $iconCls = "icon-qos";
    } elseif ($element == "tunnel_inspect") {
        $element_text = "Tunnel Inspection";
        $iconCls = "icon-tunnelinspection";
    }

    return array($element_text, $iconCls);

}




function registerTask(ARRAY $data, $user, INT $jobID, STRING $processCode, STRING $processName){
    global $app;

    if(!isset($data['params'])){
        $data['params'] = '';
    }
    $data['userId'] = $user->id;

    $params = [
        'job_id'        => $jobID,
        'taskType'      => 'Export Merge',
        'taskName'      => $processName,
        'processCode'   => $processCode,
        'statusMessage' => 'Pending...',
        'statusCode'    => '0',
        'params'        => json_encode($data),
    ];

    if(!$task = $app->task->create($params)){
        return -1;
    }

    $job = $app->job->where('id', $jobID)->first();
    $jobParams = [
        'tasks' => $job->tasks + 1,
    ];
    $job->update($jobParams);

    if($job->parentJob != ''){
        $parentJob = $app->job->where('id', $job->parentJob)->first();
        $parentJobParams = [
            'tasks' => $parentJob->tasks + 1,
        ];
        $parentJob->update($parentJobParams);
    }
    return $task->id;
}

function send_APICallMessage(ARRAY $data, $user, INT $taskID, STRING $process){

    $data['taskId'] = $taskID;

    $message = [
        'sender'        => $user->id,
        'proccessCode'  => $process,
        'params'        => $data
    ];

    sendMessage($message);

    $message = array();
    $message['code'] = true;
    $message['msg'] = 'Done';
    return $message;
}

function sendMessage($message){
    $messageSender = new MessageSender($message);
    $messageSender->send();
}

function registerJob(ARRAY $data, $user, STRING $description, INT $parentJob=null){
    global $app;

    $params = [
        'user_id'       => $user->id,
        'parentType'    => 'Project',
        'parentId'      => $data['project'],
        'description'   => $description,
        'parentJob'     => $parentJob,
    ];
    if(!$job = $app->job->create($params)){
        return -1;
    }

    return $job->id;
}


?>