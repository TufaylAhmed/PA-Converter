<?php

# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
//Loads all global PHP definitions
//require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';
require_once INC_ROOT.'/libs/database.php';
require_once INC_ROOT.'/libs/shared.php';
require_once INC_ROOT.'/libs/xmlapi.php';
//require_once '../libs/database.php';
//include('../libs/database.php');
//include('../libs/projectdb.php');

include INC_ROOT.'/bin/middleware_sanitizer.php';

global $pandb;

$argv = array_map("escapeStringMiddleWareSanitizer", $argv);

$cron_id = $argv[1];

$getCronJobs = $pandb->query("SELECT id, name, type, log_connector, filename, vsys, source, project, rules_lid, disable FROM cronjobs WHERE id = '$cron_id' AND disable = '0';");
            
if ($getCronJobs->num_rows > 0){
    
    while ($data = $getCronJobs->fetch_assoc()){

        $name_cron = $data['name'];
        $type = $data['type'];
        $log_connector = $data['log_connector'];
        $vsys = $data['vsys'];
        $source = $data['source'];
        $project = $data['project'];
        $rules_lid = $data['rules_lid'];
        
        if($rules_lid == ""){
            $rules_sql = "";
        }else{
            $rules_sql = " AND id IN ($rules_lid) ";
        }
    
        if ($project != ""){
            require_once INC_ROOT.'/libs/projectdb.php';
            $projectdb = selectDatabase($project);
        }

        $getConn = $projectdb->query("SELECT id FROM connectors WHERE name = '$log_connector';");
        if ($getConn->num_rows == 1) {
            $dataC = $getConn->fetch_assoc();
            $connector_id = $dataC['id'];
        }

        $getNameRules = $projectdb->query("SELECT id, name, vsys, source FROM security_rules WHERE vsys = '$vsys' AND source = '$source' $rules_sql ;");
        
        $rule_array = array();
        $rules_data = "";

        if ($getNameRules->num_rows > 0){
            while ($dataRN = $getNameRules->fetch_assoc()){
                $rule_id = $dataRN['id'];
                $rule_name = $dataRN['name'];
                $vsys_rule = $dataRN['vsys'];
                $source_rule = $dataRN['source'];

                if (($vsys == $vsys_rule) && ($source == $source_rule)){
                    $rule_array[] = $rule_id.";".$rule_name;
                }
            }
            $rules_data = implode(",", $rule_array);
            //print_r($rule_array);
            //echo "Rules data: " .$rules_data. "\n";
        }


        if($connector_id != ""){
            
            add_log_pandb('ok', 'Cron Jobs', 'Cron Job '.$type.': [' . $name_cron . '] has started on the', 'No Action Required', '2');
            
            if ($type == "App-ID Adoption"){
                
                getRetrieveAppId($connector_id, $source, $rules_data, $project);
            
            }elseif($type == "User-ID Adoption"){

                getRetrieveUserId($connector_id, $source, $rules_data, $project);

            }
            
            add_log_pandb('ok', 'Cron Jobs', 'Cron Job '.$type.': [' . $name_cron . '] has finished on the', 'No Action Required', '2');
        }
        else{
            add_log_pandb('ok', 'Cron Jobs', 'Cron Job '.$type.': [' . $name_cron . '] has failed on the', 'No Action Required', '2');
        }
    }
}

function getRetrieveAppId($connector, $source, $rules_to_cron, $project){
    
    global $projectdb;
    global $pandb;
    
    $panorama = false;

    #check if the Source is panorama but the logs has to be retrieved from the Firewall isntead of Panorama
    $isPanoramaSource = $projectdb->query("SELECT ispanorama FROM device_mapping WHERE id='$source';");
    if ($isPanoramaSource->num_rows == 1) {
        $getPanoramaSource = $isPanoramaSource->fetch_assoc();
        if ($getPanoramaSource['ispanorama'] == 1) {
            $sourcePanorma = true;
        } else {
            $sourcePanorma = false;
        }
    }

    $getConn = $projectdb->query("SELECT vendor,device,vsys,panorama,period,startdate,starttime,enddate,endtime,top FROM connectors WHERE id='$connector';");
    if ($getConn->num_rows == 1) {
        $data = $getConn->fetch_assoc();
        $ConnVendor = $data['vendor'];
        $ConnDevice = $data['device'];
        $ConnVsys = $data['vsys'];
        $ConnPanorama = $data['panorama'];
        $ConnPeriod = $data['period'];
        $ConnStart = $data['startdate'] . " " . $data['starttime'];
        $ConnEnd = $data['enddate'] . " " . $data['endtime'];
        $ConnTop = $data['top'];

        #Get Device
        $getDevice = $pandb->query("SELECT id,api_key,hostname,ispanorama,port,serial,device,type,management FROM devices WHERE id='$ConnDevice';");
        if ($getDevice->num_rows == 1) {
            $datadevice = $getDevice->fetch_assoc();
            $device_api_key = $datadevice['api_key'];
            $device_hostname = $datadevice['hostname'];
            $device_ispanorama = $datadevice['ispanorama'];
            $device_port = $datadevice['port'];
            $device_serial = $datadevice['serial'];
            $device_id = $datadevice['id'];
            $device = $datadevice['device'];
            $model = $datadevice['type'];
            $device_management = $datadevice['management'];
            
            /*if ($ConnPanorama != "") {
                $getPanorama = $pandb->query("SELECT name,api_key,hostname,port FROM devices WHERE id='$ConnPanorama';");
                if ($getPanorama->num_rows == 1) {
                    $datapanorama = $getPanorama->fetch_assoc();
                    $device_api_key = $datapanorama['api_key'];
                    $device_hostname = $datapanorama['hostname'];
                    $device_port = $datapanorama['port'];
                    $device = $datapanorama['name'];
                    $panorama = true;
                }
            }*/
            
            if ($ConnPanorama == "1") {
                $panorama=TRUE;
                $getDG=$projectdb->query("SELECT serial,vsys FROM connectors_dg_devices WHERE connector_id='$connector' AND devicegroup='$ConnVsys' AND active=1;");
                if ($getDG->num_rows>0){
                    $dg_query=array();
                    while ($getDGData=$getDG->fetch_assoc()){
                        $dg_serial=$getDGData['serial'];
                        $dg_vsys=$getDGData['vsys'];
                        $dg_query[]="(serial eq '$dg_serial' and vsys eq '$dg_vsys')";
                    }
                    $dg_query_all="(".implode(" OR ", $dg_query).")";
                }
                else{
                    $dg_query_all="";
                }
            }
            else {
                # Check if we have the API key or we need to use Panorama as a PROXY
                if ($device_api_key==""){
                    $getPanorama=$pandb->query("SELECT name,hostname,port,api_key FROM devices WHERE name='$device_management';");
                    if ($getPanorama->num_rows==1){
                        $getPanoramaData=$getPanorama->fetch_assoc();
                        $device_hostname=$getPanoramaData['hostname'];
                        $device_port=$getPanoramaData['port'];
                        $panorama_devicename=$getPanoramaData['name'];
                        $device_api_key=$getPanoramaData['api_key'];
                        $target=$device_serial;
                    }
                }
                if ($ConnVsys=="all"){
                    $dg_query_all="";
                }
                else{
                    $dg_query_all="(vsys eq '$ConnVsys')";
                }
            }
            
        }
        
        $projectdb->query("TRUNCATE TABLE project_status;");
        add_progress($project, '0.00', 'Retrieving Reports');
 
        //take_snapshot_last($project);
        #Retrieve Active and Allowed Rules
        #This is to retrieve logs without vsys because the source is panorama vys=devicegroup but the collector is a vsys
        if (($sourcePanorma == true) AND ( $ConnPanorama == "")) {
            $addVsys = "";
        } else { 
            $addVsys = "AND vsys='$ConnVsys'";
        }

        if ($rules_to_cron != "") {
            
            $rules = explode(",", $rules_to_cron);
            $tuCurl = curl_init();
            $theRules = array();
            $theRulesTotal = array();
            $delete = array();
            $allrules = count($rules);
            $x = 0;
            
            foreach ($rules as $key => $value) {
                
                $thedata2 = explode(";", $value);
                $rule_lid = $thedata2[0];
                $rulename = $thedata2[1];

                $projectdb->query("DELETE FROM split_rules_unknown WHERE source='$source' AND rule_lid='$rule_lid';");
                
                $x++;
                if ($panorama == FALSE) {
                    
                    //$theRules = get_dynamic_report_appsbyrule_panos($tuCurl, $device_hostname, $device_api_key, $ConnVsys, $device_serial, $ConnPeriod, $device_port, $source, $rulename, $rule_lid, $ConnStart, $ConnEnd);

                    if ($target!=""){
                        # USe Panorama as a Proxy to retrueve the reports.
                        if ($model=="pa7000"){
                            $theRules = get_dynamic_report_appsbyrule_pa7000($tuCurl, $device_hostname, $device_api_key, $ConnVsys, $device_serial, $ConnPeriod, $device_port, $source, $rulename, $rule_lid, $ConnStart, $ConnEnd,$dg_query_all, "",$target, $ConnTop);
                        }
                        else{
                            $theRules = get_dynamic_report_appsbyrule_panos($tuCurl, $device_hostname, $device_api_key, $ConnVsys, $device_serial, $ConnPeriod, $device_port, $source, $rulename, $rule_lid, $ConnStart, $ConnEnd,$dg_query_all,$target, $ConnTop);
                        }
                    }
                    else{
                        if ($model=="pa7000"){
                            $theRules = get_dynamic_report_appsbyrule_pa7000($tuCurl, $device_hostname, $device_api_key, $ConnVsys, $device_serial, $ConnPeriod, $device_port, $source, $rulename, $rule_lid, $ConnStart, $ConnEnd,$dg_query_all,$target, $ConnTop);
                        }
                        else {
                            $theRules = get_dynamic_report_appsbyrule_panos($tuCurl, $device_hostname, $device_api_key, $ConnVsys, $device_serial, $ConnPeriod, $device_port, $source, $rulename, $rule_lid, $ConnStart, $ConnEnd,$dg_query_all,$target, $ConnTop);
                        }
                    }
                    
                    
                    if (count($theRules) > 0) {
                        $sql = "INSERT INTO applications_from_log (source, vsys, rule_lid, app, dport, bytes, packets, proto, date_retrieve) VALUES ";
                        $out = $sql . implode(",", $theRules);
                        $projectdb->query($out);
                    }
                } 
                else {
                    //$theRules = get_dynamic_report_appsbyrule_panorama($ConnVsys, $tuCurl, $device_hostname, $device_api_key, $ConnVsys, $device_serial, $ConnPeriod, $device_port, $source, $rulename, $rule_lid, $ConnStart, $ConnEnd);
                    $theRules = get_dynamic_report_appsbyrule_panorama($ConnVsys, $tuCurl, $device_hostname, $device_api_key, $ConnVsys, $device_serial, $ConnPeriod, $device_port, $source, $rulename, $rule_lid, $ConnStart, $ConnEnd,$dg_query_all, "",$target, $ConnTop);

                    if (count($theRules) > 0) {
                        $sql = "INSERT INTO applications_from_log (source,vsys,rule_lid,app,dport,bytes,packets,proto, date_retrieve) VALUES ";
                        $out = $sql . implode(",", $theRules);
                        $projectdb->query($out);
                    }
                }
                $progress = $x / $allrules;
                
                if ($progress == 1) {
                    $pandb->query("UPDATE projects SET progress='1' WHERE name='$project';");
                    update_progress($project, '1.00', 'Finished.');
                } else {
                    update_progress($project, $progress, 'Retrieved Report ' . $x . ' from ' . $allrules);
                }
            }
            curl_close($tuCurl);
        } else {
            $pandb->query("UPDATE projects SET progress='1' WHERE name='$project';");
            update_progress($project, '1.00', 'Finished.');
        }
    } 
    
}

 
function getRetrieveUserId($connector, $source, $rules_to_cron, $project){
    
    global $projectdb;
    global $pandb;
    
    $panorama = false;

    #check if the Source is panorama but the logs has to be retrieved from the Firewall isntead of Panorama
    $isPanoramaSource = $projectdb->query("SELECT ispanorama FROM device_mapping WHERE id='$source';");
    if ($isPanoramaSource->num_rows == 1) {
        $getPanoramaSource = $isPanoramaSource->fetch_assoc();
        if ($getPanoramaSource['ispanorama'] == 1) {
            $sourcePanorma = true;
        } else {
            $sourcePanorma = false;
        }
    }

    $getConn = $projectdb->query("SELECT vendor,device,vsys,panorama,period,startdate,starttime,enddate,endtime FROM connectors WHERE id='$connector';");
    if ($getConn->num_rows == 1) {
        $data = $getConn->fetch_assoc();
        $ConnVendor = $data['vendor'];
        $ConnDevice = $data['device'];
        $ConnVsys = $data['vsys'];
        $ConnPanorama = $data['panorama'];
        $ConnPeriod = $data['period'];
        $ConnStart = $data['startdate'] . " " . $data['starttime'];
        $ConnEnd = $data['enddate'] . " " . $data['endtime'];

        #Get Device
        $getDevice = $pandb->query("SELECT id,api_key,hostname,ispanorama,port,serial,device,type,management FROM devices WHERE id='$ConnDevice';");
        if ($getDevice->num_rows == 1) {
            $datadevice = $getDevice->fetch_assoc();
            $device_api_key = $datadevice['api_key'];
            $device_hostname = $datadevice['hostname'];
            $device_ispanorama = $datadevice['ispanorama'];
            $device_port = $datadevice['port'];
            $device_serial = $datadevice['serial'];
            $device_id = $datadevice['id'];
            $device = $datadevice['device'];
            $model = $datadevice['type'];
            $device_management = $datadevice['management'];

            /*if ($ConnPanorama != "") {
                $getPanorama = $pandb->query("SELECT name,api_key,hostname,port FROM devices WHERE id='$ConnPanorama';");
                if ($getPanorama->num_rows == 1) {
                    $datapanorama = $getPanorama->fetch_assoc();
                    $device_api_key = $datapanorama['api_key'];
                    $device_hostname = $datapanorama['hostname'];
                    $device_port = $datapanorama['port'];
                    $device = $datapanorama['name'];
                    $panorama = true;
                }
            }*/
            
            if ($ConnPanorama == "1") {
                $panorama=TRUE;
                $getDG=$projectdb->query("SELECT serial,vsys FROM connectors_dg_devices WHERE connector_id='$connector' AND devicegroup='$ConnVsys' AND active=1;");
                if ($getDG->num_rows>0){
                    $dg_query=array();
                    while ($getDGData=$getDG->fetch_assoc()){
                        $dg_serial=$getDGData['serial'];
                        $dg_vsys=$getDGData['vsys'];
                        $dg_query[]="(serial eq '$dg_serial' and vsys eq '$dg_vsys')";
                    }
                    $dg_query_all="(".implode(" OR ", $dg_query).")";
                }
                else{
                    $dg_query_all="";
                }
            }
            else {
                # Check if we have the API key or we need to use Panorama as a PROXY
                if ($device_api_key==""){
                    $getPanorama=$pandb->query("SELECT name,hostname,port,api_key FROM devices WHERE name='$device_management';");
                    if ($getPanorama->num_rows==1){
                        $getPanoramaData=$getPanorama->fetch_assoc();
                        $device_hostname=$getPanoramaData['hostname'];
                        $device_port=$getPanoramaData['port'];
                        $panorama_devicename=$getPanoramaData['name'];
                        $device_api_key=$getPanoramaData['api_key'];
                        $target=$device_serial;
                    }
                }
                if ($ConnVsys=="all"){
                    $dg_query_all="";
                }
                else{
                    $dg_query_all="(vsys eq '$ConnVsys')";
                }
            }
            
        }
        
        $projectdb->query("TRUNCATE TABLE project_status;");
        add_progress($project, '0.00', 'Retrieving Reports');
 
        //take_snapshot_last($project);
        #Retrieve Active and Allowed Rules
        #This is to retrieve logs without vsys because the source is panorama vys=devicegroup but the collector is a vsys
        if (($sourcePanorma == true) AND ( $ConnPanorama == "")) {
            $addVsys = "";
        } else { 
            $addVsys = "AND vsys='$ConnVsys'";
        }

        if ($rules_to_cron != "") {
            
            $rules = explode(",", $rules_to_cron);
            $tuCurl = curl_init();
            $theRules = array();
            $theRulesTotal = array();
            $delete = array();
            $allrules = count($rules);
            $x = 0;
            
            foreach ($rules as $key => $value) {
                
                $thedata2 = explode(";", $value);
                $rule_lid = $thedata2[0];
                $rulename = $thedata2[1];

                $x++;
                if ($panorama == FALSE) {
                    
                    //$theRules = get_dynamic_report_usersbyrule_panos($tuCurl, $device_hostname, $device_api_key, $ConnVsys, $device_serial, $ConnPeriod, $device_port, $source, $rulename, $rule_lid, $ConnStart, $ConnEnd);
                    
                    if ($model=="pa7000"){
                        $theRules = get_dynamic_report_usersbyrule_pa7000($tuCurl, $device_hostname, $device_api_key, $ConnVsys, $device_serial, $ConnPeriod, $device_port, $source, $rulename, $rule_lid, $ConnStart, $ConnEnd,$dg_query_all,$target);
                    }
                    else{
                        $theRules = get_dynamic_report_usersbyrule_panos($tuCurl, $device_hostname, $device_api_key, $ConnVsys, $device_serial, $ConnPeriod, $device_port, $source, $rulename, $rule_lid, $ConnStart, $ConnEnd,$dg_query_all,$target);
                    }
                    
                    if (count($theRules) > 0) {
                        $sql = "INSERT INTO userid_from_log (source, vsys, rule_lid, name, bytes, sessions, date_retrieve) VALUES ";
                        $out = $sql . implode(",", $theRules);
                        $projectdb->query($out);
                    }
                } else {
                    
                    //$theRules = get_dynamic_report_usersbyrule_panorama($ConnVsys, $tuCurl, $device_hostname, $device_api_key, $ConnVsys, $device_serial, $ConnPeriod, $device_port, $source, $rulename, $rule_lid, $ConnStart, $ConnEnd);
                    $theRules = get_dynamic_report_usersbyrule_panorama($ConnVsys, $tuCurl, $device_hostname, $device_api_key, $ConnVsys, $device_serial, $ConnPeriod, $device_port, $source, $rulename, $rule_lid, $ConnStart, $ConnEnd,$dg_query_all,$target);
                    
                    if (count($theRules) > 0) {
                        $sql = "INSERT INTO userid_from_log (source, vsys, rule_lid, name, bytes, sessions, date_retrieve) VALUES ";
                        $out = $sql . implode(",", $theRules);
                        $projectdb->query($out);
                    }
                }
                $progress = $x / $allrules;
                
                if ($progress == 1) {
                    $pandb->query("UPDATE projects SET progress='1' WHERE name='$project';");
                    update_progress($project, '1.00', 'Finished.');
                    //sleep(4); update_progress($project,'0.00','Ready.');
                } else {
                    update_progress($project, $progress, 'Retrieved Report ' . $x . ' from ' . $allrules);
                }
            }
            curl_close($tuCurl);
        } else {
            $pandb->query("UPDATE projects SET progress='1' WHERE name='$project';");
            update_progress($project, '1.00', 'Finished.');
            
        }
    } 
    
}





