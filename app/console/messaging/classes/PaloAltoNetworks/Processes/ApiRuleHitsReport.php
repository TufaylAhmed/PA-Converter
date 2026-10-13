<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 10/6/16 - 15:45
 */

require_once INC_ROOT.'/libs/projectdb.php';
require_once (INC_ROOT.'/libs/database.php');
require_once INC_ROOT.'/libs/shared.php';
require_once INC_ROOT.'/libs/common/device/device.php';
require_once INC_ROOT.'/libs/backups.php';

class ApiRuleHitsReport
    extends AbstractProcess
{

    public function __construct(ARRAY $params){
        parent::__construct($params);
    }

    public function execute()
    {
        if(!parent::execute()){
            return;
        }

        $this->setStarted();

        $projectname = $this->params['project'];
        $project=$projectname;
        global $projectdb;
        $projectdb = selectDatabase($projectname);

        $source = $this->params['source'];
        $MTvsys    =$this->params['vsys'];
        $ruleIdsString = $this->params['data'];
        $action = $this->params['action'];

        $ruleIdsArray = explode(',',$ruleIdsString);

        $connector=$this->params['connector'];


        //Collect the API call
        $role = 'admin';

        require_once (INC_ROOT.'/libs/database.php'); //getConfigBackup will require access to $pandb
        require_once (INC_ROOT.'/libs/xmlapi.php'); //We have the getApplications implementation inside
        require_once (INC_ROOT.'/libs/projectdb.php'); //getConfigBackup will require access to $pandb

        global $app;
        global $pandbRBAC;
        $pandbRBAC = selectDatabase('pandbRBAC');

        $reportAPICallID = array();
        $errorAPI = array();

        $userID = $this->params['userId'];

        if($user = $app->user->where('id',$userID)->where('api_key',$this->params['key'])->where('valid_til', '>',date("Y-m-d H:i:s"))->get()->first()) {
            $app->sentinel->login($user);
        }

        if(!$app->container->sentinel->check() || !isset($user)){
            $className = get_class($this);
            $this->log($className. " - Invalid Credentials to execute the process");
            $this->setFailed("Invalid Credentials to execute the process", "Export Cancelled by user invalid credentials");
            return;
        }

        $getConn = $projectdb->query("SELECT vendor,device,vsys,panorama,period,startdate,starttime,enddate,endtime,top FROM connectors WHERE id='$connector';");
        if ($getConn->num_rows == 1) {
            $data = $getConn->fetch_assoc();
            $ConnVendor = $data['vendor'];
            $ConnDevice = $data['device'];
            $ConnPanorama = $data['panorama'];
            $ConnPeriod = $data['period'];
            $ConnStart = $data['startdate'] . " " . $data['starttime'];
            $ConnEnd = $data['enddate'] . " " . $data['endtime'];
            $ConnTop = $data['top'];

            #Add fix to convert 2018-04-04 00:00:00 to 2018/04/04 00:00:00
            $ConnStart= str_replace("-","/",$ConnStart);
            $ConnEnd= str_replace("-","/",$ConnEnd);

            $ConnVsys = $data['vsys'];
            $getVsysname=$projectdb->query("SELECT vsys FROM device_mapping WHERE id='$ConnVsys'");
            if ($getVsysname->num_rows==1){
                $getVsysnameData=$getVsysname->fetch_assoc();
                $ConnVsys = $getVsysnameData['vsys'];
            }

        }
        else{
            $this->setFailed("There is not a connector with the given code", "[Log connector $connector does not have assigned devices]");
            return;
        }

        $getDevice = $pandbRBAC->query("SELECT id,hostname,ispanorama,port,serial,device,type,management FROM devices WHERE id='$ConnDevice';");
        if ($getDevice->num_rows == 1) {
            $datadevice = $getDevice->fetch_assoc();
            $device_serial = $datadevice['serial'];
        }
        else{
            $this->setFailed("This log connector does not have a PANOS device assigned", "[Log connector $ConnDevice does not have assigned devices]");
            return;
        }

        $this->log("Action:\t\tRequesting Rule hits\nConnector:\t\t". $ConnDevice."\nTarget:\t\t" . $device_serial . "\nRule IDs:\t$ruleIdsString\nUserID:\t\t". $userID ."\nKey:\t\t" . $role);

        if ($deviceObj = $app->device->where('serial', '=', $device_serial)->get()->first()) {
            $management = $deviceObj->management;
            if ($management != "") {
                $isProxy = true;
                if ($panoramaObj = $app->device->where('serial', '=', $management)->get()->first()) {
                    $hostname = $panoramaObj->hostname;
                    $target=$device_serial;
                    $isPanorama = $deviceObj->ispanorama;
                    $port = $panoramaObj->port;
                    if ($port == "") {
                        $port = "443";
                    }

                    $api_message = getApiKey($projectname, $panoramaObj->serial, $userID);
                    if (!$api_message['code']) {
                        $reportAPICallID[] = -2;
                        $errorAPI[] = '(Device '.$deviceObj->devicename.', '.$device_serial.') You do not have access to the device. Check with your Admin.';
                    }
                    $api_key = $api_message['msg'];
                }
                else {
                    $reportAPICallID[] = -2;
                    $errorAPI[] = '(Device '.$deviceObj->devicename.' '.$device_serial.') Failed retrieving the API KEY.';
                }
            }
            else {
                $isProxy = false;
                $hostname   = $deviceObj->hostname;
                $isPanorama = $deviceObj->ispanorama;
                $target = "";
                $port = $deviceObj->port;
                if ($port == "") {
                    $port = "443";
                }
                $api_message = getApiKey($projectname, $deviceObj->serial, $userID);
                if (!$api_message['code']) {
                    $reportAPICallID[] = -2;
                    $errorAPI[] = '(Device '.$deviceObj->devicename.','.$device_serial.') You do not have access to the device. Check with your Admin.';
                }
                $api_key = $api_message['msg'];
            }
        }

        $dg_query_all = '';
        $dg_query_device_group = '';

        $version = calcVersion($source);

        if($isPanorama==1){
            $getDG = $projectdb->query("SELECT serial,vsys FROM connectors_dg_devices WHERE connector_id='$connector' AND active=1;");
            if ($getDG->num_rows > 0) {
                $dg_query = array();
                while ($getDGData = $getDG->fetch_assoc()) {
                    $dg_serial = $getDGData['serial'];
                    $dg_vsys = $getDGData['vsys'];
                    $dg_query[] = "(serial eq '$dg_serial' and vsys eq '$dg_vsys')";
                }
                $dg_query_all = "(" . implode(" OR ", $dg_query) . ")";
            }


            // Get DeviceGroup MT-1133 only version 9
            if($version >= 9){

                $getDGPanorama = $projectdb->query("SELECT e.vsys as vsysnameDG FROM connectors c, device_mapping e WHERE c.vsys=e.id ");
                if($getDGPanorama->num_rows > 0){
                    $dataDGPanorama = $getDGPanorama->fetch_assoc();
                    $device_group_pano = $dataDGPanorama['vsysnameDG'];

                    $dg_query_device_group = " AND (device-group eq '$device_group_pano')";
                }
            }


        }
        else {
            if ($ConnVsys != "all") {
                $dg_query_all = "(vsys eq '$ConnVsys')";
            }
        }

        //disabled=0 AND action='allow' AND

        $array_rules = array();
        $query = "SELECT id, name FROM security_rules WHERE source='$source' AND vsys='$MTvsys';";
        $result = $projectdb->query($query);
        $numberOfRules = $result->num_rows;
        if($numberOfRules >= 0){
            while($dataRules = $result->fetch_assoc()){
                $rule_name = $dataRules['name'];
                $rule_lid = $dataRules['id'];

                $array_rules[$rule_lid] = $rule_name;
            }

        }
        if($numberOfRules == 0){
            $this->setFailed("There are no security rules to Analyze", "There are no security rules to Analyze");
            return;
        }

        //Taking backup of the project in the current state
        take_snapshot_last($projectname);

        $rulesProcessed = 0;
        $tuCurl = curl_init();
        if($isPanorama){
            if($action == "retrieve_rulehits"){
                $seenApplications = get_dynamic_report_rulehits_panorama($MTvsys, $tuCurl, $hostname, $api_key, $MTvsys, $device_serial, $ConnPeriod, $port, $source, '', '', $ConnStart, $ConnEnd, $dg_query_all, $dg_query_device_group, $target, $ConnTop, $array_rules);
            }

        }
        else{
            if($action == "retrieve_rulehits"){
                $seenApplications = get_dynamic_report_rulehits_pa7000($tuCurl, $hostname, $api_key, $MTvsys, $device_serial, $ConnPeriod, $port, $source, $ConnStart, $ConnEnd, $dg_query_all, $target, $ConnTop, $array_rules);
            }
        }

        if (count($seenApplications) > 0) {
                $projectdb->query("DELETE FROM security_rules_hits WHERE vsys='$MTvsys' AND source='$source';");
                $sql = "INSERT INTO security_rules_hits (source,vsys,rule_name,rule_lid,hit_count,hit_last,hit_first,last_reset,created_at) VALUES ";
                $out = $sql . implode(",", $seenApplications);
                $projectdb->query($out);
            }

        $this->increaseCompleted();

        if(count($reportAPICallID) == 0) {
            $this->setCompletedSilent('');
        }
        else {
            $this->setFailedSilent("There were problems sending the API calls with ids [".implode(';', $reportAPICallID)."]", "[".implode(';', $errorAPI)."]");
        }
    }
}
