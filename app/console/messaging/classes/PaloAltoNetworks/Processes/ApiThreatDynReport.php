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

class apiThreatDynReport
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
        $dynamicLogConnector = false;

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

        $pandbRBAC = selectDatabase('pandbRBAC');

        $reportAPICallID = array();
        $errorAPI = array();

        $userID = $this->params['userId'];
        $getConn = $projectdb->query("SELECT vendor,device,vsys,panorama,period,startdate,starttime,enddate,endtime,top, type FROM connectors WHERE id='$connector';");
        if ($getConn->num_rows == 1) {
            $data = $getConn->fetch_assoc();
            $ConnVendor = $data['vendor'];
            $ConnDevice = $data['device'];
            $ConnPanorama = $data['panorama'];
            $ConnPeriod = $data['period'];
            $ConnStart = $data['startdate'] . " " . $data['starttime'];
            $ConnEnd = $data['enddate'] . " " . $data['endtime'];
            $ConnTop = $data['top'];
            $dynamicLogConnector = $data['type']=='Dynamic'?true:false;

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
            $this->log("There is not a connector with the given code $connector");
            $this->setFailed("There is not a connector with the given code", "[Log connector $connector does not have assigned devices]");
            return;
        }

        if(!$dynamicLogConnector) {
            $getDevice = $pandbRBAC->query("SELECT id,hostname,ispanorama,port,serial,device,type,management FROM devices WHERE id='$ConnDevice';");
            if ($getDevice->num_rows == 1) {
                $datadevice = $getDevice->fetch_assoc();
                $device_serial = $datadevice['serial'];
            } else {
                $this->log("This log connector does not have a PANOS device assigned");
                $this->setFailed("This log connector does not have a PANOS device assigned", "[Log connector $ConnDevice does not have assigned devices]");
                return;
            }
            $this->log("Action:\t\tGenerating Dynamic Reports\nConnector:\t\t". $ConnDevice."\nTarget:\t\t" . $device_serial . "\nRule IDs:\t$ruleIdsString\nUserID:\t\t". $userID ."\nKey:\t\t" . $role);
        }
        else{
            $this->log("Action:\t\tGenerating Dynamic Reports\nConnector:\t\t". $ConnDevice."\nTarget:\t\tDynamic\nRule IDs:\t$ruleIdsString\nUserID:\t\t". $userID ."\nKey:\t\t" . $role);
        }


        if(!$dynamicLogConnector){
            if(in_array("0", $ruleIdsArray)){
//                $query = "SELECT id, name FROM security_rules WHERE disabled=0 AND action='allow' AND source='$source' AND vsys='$MTvsys';";
                $query = "SELECT id, name FROM security_rules WHERE source='$source' AND vsys='$MTvsys';";
            }
            else{
//                $query = "SELECT id, name FROM security_rules WHERE disabled=0 AND action='allow' AND source='$source' AND vsys='$MTvsys' AND id IN (".$ruleIdsString.") ;";
                $query = "SELECT id, name FROM security_rules WHERE source='$source' AND vsys='$MTvsys' AND id IN (".$ruleIdsString.");";
            }
            $result = $projectdb->query($query);
            $numberOfRules = $result->num_rows;
            if($numberOfRules == 0){
                $this->setFailed("There are no security rules to Analyze", "There are no security rules to Analyze");
                return;
            }
        }
        else{
            if(in_array("0", $ruleIdsArray)) {
                $query = "SELECT id, name, vsys, position FROM security_rules WHERE source='$source' ORDER BY vsys, position;";
            }
            else{
                $query = "SELECT id, name, vsys, position FROM security_rules WHERE source='$source' AND id IN (".$ruleIdsString.") ORDER BY vsys, position;";
            }
            $result = $projectdb->query($query);
            $numberOfRules = $result->num_rows;
            if($numberOfRules == 0){
                $this->log("There are no security rules to Analyze");
                $this->setFailed("There are no security rules to Analyze", "There are no security rules to Analyze");
                return;
            }
        }



        //Taking backup of the project in the current state
        take_snapshot_last($projectname);

        $rulesProcessed = 0;
        $tuCurl = curl_init();
        if(!$dynamicLogConnector) {
            list($isPanorama, $hostname, $api_key, $port, $dg_query_all, $dg_query_device_group, $target, $errorAPI) = $this->getDeviceConnectorSettings($userID, $projectdb, $connector, $dynamicLogConnector, $projectname, $device_serial, $source, $ConnVsys);
        }

        while($ruledata=$result->fetch_assoc()){
            //Check if the job is cancelled
            if($this->isCancelled()){
                $this->setFailed("Report Cancelled by the user", "Report Cancelled by the user");
                return;
            }

            $rulename = $ruledata['name'];
            $rule_lid = $ruledata['id'];

            if($dynamicLogConnector){
                //Given this rule, let's get the information needed to create the log connector
                list($device_serial, $source, $ConnVsys) = $this->getSourceByRuleID($projectdb, $rule_lid);
                list($isPanorama, $hostname, $api_key, $port, $dg_query_all, $dg_query_device_group, $target, $errorAPI) = $this->getDeviceConnectorSettings($userID, $projectdb, $connector, $dynamicLogConnector, $projectname, $device_serial, $source, $ConnVsys);
            }

            $this->log("Processing rule $rule_lid ($device_serial $MTvsys)");

            if($isPanorama){
                if($action == "retrieve_threats_by_rule"){
                    $seenApplications = get_dynamic_report_threatsbyrule_panorama($MTvsys, $tuCurl, $hostname, $api_key, $MTvsys, $device_serial, $ConnPeriod, $port, $source, $rulename, $rule_lid, $ConnStart, $ConnEnd, $dg_query_all, $dg_query_device_group, $target, $ConnTop);
                }
                elseif($action == "retrieve_threats_by_rule_fast"){
                    $seenApplications = get_dynamic_report_threatsbyrule_panorama($MTvsys, $tuCurl, $hostname, $api_key, $MTvsys, $device_serial, $ConnPeriod, $port, $source, $rulename, $rule_lid, $ConnStart, $ConnEnd, $dg_query_all, $dg_query_device_group, $target, $ConnTop);
                }
                else{
                    $seenApplications = get_dynamic_report_threatsbyrule_panorama($MTvsys, $tuCurl, $hostname, $api_key, $MTvsys, $device_serial, $ConnPeriod, $port, $source, $rulename, $rule_lid, $ConnStart, $ConnEnd, $dg_query_all, $dg_query_device_group, $target, $ConnTop);
                }
            }
            else{
                # With this we force to make all the reports with async=yes

//                if ( ($deviceObj->type == "pa7000") || ($deviceObj->type == "pa5200") || ($deviceObj->type == "pa5000") ) {
//                if($action == "retrieve_appid_by_rule"){
//                    $seenApplications = get_dynamic_report_appsbyrule_pa7000($tuCurl, $hostname, $api_key, $MTvsys, $device_serial, $ConnPeriod, $port, $source, $rulename, $rule_lid, $ConnStart, $ConnEnd, $dg_query_all, $target, $ConnTop);
//                }
//                else
                if($action == "retrieve_appid_by_rule_fast"){
                    $seenApplications = get_dynamic_report_threatsbyrule_pa7000($tuCurl, $hostname, $api_key, $MTvsys, $device_serial, $ConnPeriod, $port, $source, $rulename, $rule_lid, $ConnStart, $ConnEnd, $dg_query_all, $target, $ConnTop);
                }
                else{
                    $seenApplications = get_dynamic_report_threatsbyrule_pa7000($tuCurl, $hostname, $api_key, $MTvsys, $device_serial, $ConnPeriod, $port, $source, $rulename, $rule_lid, $ConnStart, $ConnEnd, $dg_query_all, $target, $ConnTop);
                }

//                } else {
//                    $seenApplications = get_dynamic_report_appsbyrule_panos($tuCurl, $hostname, $api_key, $MTvsys, $device_serial, $ConnPeriod, $port, $source, $rulename, $rule_lid, $ConnStart, $ConnEnd, $dg_query_all, $target);
//
//                }
            }

            if (count($seenApplications) > 0) {
                $sql = "INSERT INTO threats_from_log (source,vsys,rule_lid,app,threatid,tid,category_of_threatid,subtype,date_retrieve,severity_of_threatid,count,action) VALUES ";
                $out = $sql . implode(",", $seenApplications);
                $projectdb->query($out);
            }

            $this->increaseCompleted();
        }
        curl_close($tuCurl);

        if(count($reportAPICallID) == 0) {
            $this->setCompletedSilent('');
        }
        else {
            $this->setFailedSilent("There were problems sending the API calls with ids [".implode(';', $reportAPICallID)."]", "[".implode(';', $errorAPI)."]");
        }
    }

    private function getDeviceConnectorSettings(int $userID, mysqli $projectdb, int $connector, bool $dynamicLogConnector, string $projectname, string $device_serial, int $source, $ConnVsys){
        global $app;
        $errorAPI = array();

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
                        $this->log('(Device '.$deviceObj->devicename.', '.$device_serial.') You do not have access to the device. Check with your Admin.');
                        $errorAPI[] = '(Device '.$deviceObj->devicename.', '.$device_serial.') You do not have access to the device. Check with your Admin.';
                    }
                    $api_key = $api_message['msg'];
                }
                else {
                    $reportAPICallID[] = -2;
                    $this->log('(Device '.$deviceObj->devicename.' '.$device_serial.') Failed retrieving the API KEY.');
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
                    $this->log('(Device '.$deviceObj->devicename.','.$device_serial.') You do not have access to the device. Check with your Admin.');
                }
                $api_key = $api_message['msg'];
            }
        }

        $dg_query_all = '';
        $dg_query_device_group = '';

        $version = calcVersion($source);

        if($isPanorama==1){
            if(!$dynamicLogConnector) {
                $getDG = $projectdb->query("SELECT serial,vsys FROM connectors_dg_devices WHERE connector_id='$connector' AND active=1;");
            }
            else{
                //We did not get serials selected, let's get all the serials that are under this DG (also check children DGs)
                require_once INC_ROOT.'/libs/common/lib-objects.php';
                $query = "SELECT id FROM device_mapping WHERE vsys='$ConnVsys' AND device= (SELECT device FROM device_mapping WHERE id='$source');";
                $result = $projectdb->query($query);
                if($result->num_rows==1){
                    $data = $result->fetch_object();
                    $ConnVsysID = $data->id;
                }
                else{
                    $ConnVsysID = 0;
                }
                $vsyses = getVsysesDescIDs($projectdb, "", $ConnVsysID);

                $query = "SELECT distinct dgm.serial,dgm.vsys 
                            FROM devicegroup_mapping dgm, device_mapping dm 
                            WHERE dgm.device_mapping_id in (".implode(",",$vsyses).") AND dm.device= (SELECT device FROM device_mapping WHERE id='$source')";
                $getDG = $projectdb->query($query);
            }
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
//                $getDGPanorama = $projectdb->query("SELECT e.vsys as vsysnameDG FROM connectors c, device_mapping e WHERE c.vsys=e.id ");
//                if($getDGPanorama->num_rows > 0){
//                    $dataDGPanorama = $getDGPanorama->fetch_assoc();
//                    $device_group_pano = $dataDGPanorama['vsysnameDG'];
//                    $dg_query_device_group = " AND (device-group eq '$device_group_pano')";
//                }

                $dg_query_device_group = " AND (device-group eq '$ConnVsys')";
            }
        }
        else {
            if ($ConnVsys != "all") {
                $dg_query_all = "(vsys eq '$ConnVsys')";
            }
        }

        return [$isPanorama, $hostname,$api_key,$port,$dg_query_all,$dg_query_device_group,$target, $errorAPI];
    }


    private function getSourceByRuleID(mysqli $projectdb, int $rule_lid){
        $query = "SELECT source, vsys FROM security_rules WHERE id='$rule_lid';";
        $results = $projectdb->query($query);
        if($results->num_rows==1){
            $data = $results->fetch_object();
            $source = $data->source;
            $ConnVsys = $data->vsys;
        }

        $query = "SELECT filename FROM device_mapping WHERE id='$source'";
        $results = $projectdb->query($query);
        if($results->num_rows==1){
            $data = $results->fetch_object();
            $fileName = $data->filename;
            preg_match('/(.*)_(?<serial>.*)(_(.*))?.xml/', $fileName, $output_array);
            $device_serial = $output_array['serial'];
        }

        return [$device_serial, $source, $ConnVsys];
    }

}