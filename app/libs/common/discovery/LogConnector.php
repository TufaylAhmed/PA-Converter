<?php
/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: $today.year.hour.minute
 ******************************************************************************/

namespace PaloAltoNetworks\Expedition\Discovery;

require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
require_once INC_ROOT.'/libs/projectdb.php';
require_once INC_ROOT.'/userManager/start.php';
require_once INC_ROOT.'/userManager/API/projects/UserSettings.php';

class LogConnectorDBEntry{
    public $id;
    public $name;
    public $vendor;
    public $image;
    public $device;
    public $vsys;
    public $panorama;
    public $period;
    public $starttime;
    public $endtime;
    public $startdate;
    public $enddate;
    public $serial;
}

class ConnectorDGDevices{
    public $vsys;
    public $serial;
}

class LogConnector
{

    private $project;

    public function __construct(STRING $project)
    {
        $this->project = $project;
    }

    public function getDevices(){
        return $this->getDevicesToLearnFrom();
    }

    public function getRules(){
        return $this->getRulesToLearnFrom();
    }

    public function getLearningRules(){
        return $this->getRulesToLearnFrom("learning");
    }

    public function getEnrichmentRules(){
        return $this->getRulesToLearnFrom("enrichment");
    }

    /***
     * This method returns a list of the current devices that have been selected for learning from.
     * Considers the selected LogConnector.
     *
     * @return array
     */
    private function getDevicesToLearnFrom():array{
        global $app;
        $pandbRBAC = selectDatabase('pandbRBAC');
        $projectDB = selectDatabase($this->project);

        $devicesList = array();

        $dataConnector = $this->getMyLogConnector();

        if(!is_null($dataConnector)){
            $isPanorama = $dataConnector->panorama;

            if($isPanorama==1){
                $query = "select serial, vsys from connectors_dg_devices WHERE connector_id=".$dataConnector->id;
                $resultDGDevices = $projectDB->query($query);
                while($dataDGConnector = $resultDGDevices->fetch_assoc()){
                    $devicesList[] = $dataDGConnector['serial'].":".$dataDGConnector['vsys'];
                }
            }
            else{
                $query = "SELECT vsys from device_mapping WHERE id=".$dataConnector->vsys;
                $resultVsys = $projectDB->query($query);
                $vsysRow = $resultVsys->fetch_assoc();
                $deviceID =  $dataConnector->device;
//                $query = "SELECT serial, serialHA FROM devices WHERE id=$deviceID";
//                $result = $pandbRBAC->query($query);
//                $dataDevice = $result->fetch_object();
                if(!$device= $app->device->where('id',$deviceID)->get(['serial','serialHA'])->first()){
                    return array();
                }
                $devicesList[] = $device->serial.":".$vsysRow['vsys'];
                if($device->serialHA != ''){
                    $devicesList[] = $device->serialHA.":".$vsysRow['vsys'];
                }
            }
        }

        return $devicesList;
    }

    /***
     * This method returns a list of the current security rules that have been activated for learning.
     * Considers the selected LogConnector, the source it refers to and the vsys/Device_Group
     *
     * @param STRING|null $mode learning / enrichment
     * @return array Array of the active Rules for a current Connector: Source, Vsys
     */
    private function getRulesToLearnFrom(STRING $mode = null){
        $projectDB = selectDatabase($this->project);
        $rules = array();

        $dataConnector = $this->getMyLogConnector();
        if(!is_null($dataConnector)){
            $query = "SELECT vsys, filename FROM device_mapping WHERE id='".$dataConnector->vsys."'";
//            echo $query.PHP_EOL;
            $resultVsysSelected = $projectDB->query($query); //Check the name of the vsys that this connector is using
            $dataVsysSelected = $resultVsysSelected->fetch_assoc();
            $filename = $dataVsysSelected['filename'];

            $query = "SELECT id FROM device_mapping WHERE filename='$filename' GROUP BY filename LIMIT 1";
//            echo $query;
            $resultSourceSelected = $projectDB->query($query);
            $dataSourceSelected = $resultSourceSelected->fetch_assoc();
            $source = $dataSourceSelected['id'];

            $vsyses = getVsyses($projectDB, $dataVsysSelected['vsys'], $source, "quoted");  //Array with the list of Vsys from where we need to learn from

            switch($mode){
                case "enrichment":
                    $query ="SELECT id FROM security_rules WHERE RE=1 AND source=$source AND vsys in (".implode(",", $vsyses).")";
                    break;

                case "learning":
                default:
                    //Get the security rules that have the ML flag on from the selected source and vsys
                    $query ="SELECT id FROM security_rules WHERE ML=1 AND source=$source AND vsys in (".implode(",", $vsyses).")";
                    break;
            }
//            echo $query.PHP_EOL;
            $resultRules = $projectDB->query($query);
            if($resultRules->num_rows>0){
                while($dataRules = $resultRules->fetch_assoc()){
                    $rules[] = $dataRules['id'];
                }
            }
        }
        else{  //This user does not have a LogConnector. So we can't know which rules to learn from
            $rules = [];
        }

        return $rules;
    }

    /***
     * Collects startDate and endDate considered in a LogCollector
     * @return array
     */
    public function getTimeFrame(){
        $myLogConnectorObj = $this->getMyLogConnector();
        return [
            'startDate' => $this->getInitialDate($myLogConnectorObj),
            'endDate'   => $this->getEndDate($myLogConnectorObj),
        ];
    }

    private function getInitialDate($myLogConnectorObj){
        $period = $myLogConnectorObj->period;
        $nowString = date("Y-m-d H:i:s");
        $now = new \DateTime($nowString);

        switch ($period){
            case 'last-60-seconds':
                $ago60Secs = $now->sub(date_interval_create_from_date_string('last 60 seconds'));
                $startDay = $ago60Secs->format('Y-m-d');
                break;

            case 'last-15-minutes':
                $ago15mins = $now->sub(date_interval_create_from_date_string('last 15 minutes'));
                $startDay = $ago15mins->format('Y-m-d');
                break;

            case 'last-hour':
                $ago1hour = $now->sub(date_interval_create_from_date_string('last hour'));
                $startDay = $ago1hour->format('Y-m-d');
                break;

            case 'last-6-hrs':
                $ago6hour = $now->sub(date_interval_create_from_date_string('last 6 hours'));
                $startDay = $ago6hour->format('Y-m-d');
                break;

            case 'last-12-hrs':
                $ago12hour = $now->sub(date_interval_create_from_date_string('last 12 hours'));
                $startDay = $ago12hour->format('Y-m-d');
                break;

            case 'last-24-hrs':
            case 'last-calendar-day':
                $ago24hour = $now->sub(date_interval_create_from_date_string('last day'));
                $startDay = $ago24hour->format('Y-m-d');
                break;

            case 'last-7-days':
                $ago7days = $now->sub(date_interval_create_from_date_string('last 7 days'));
                $startDay = $ago7days->format('Y-m-d');
                break;

            case 'last-7-calendar-days':
            case 'last-calendar-week':
                //Check last Saturday
                $today = date('Y-m-d H:i:s', strtotime("last Saturday"));
                $lastSaturday = new \DateTime($today);
                //Check the Sunday before last Sunday
                $priorSunday = $lastSaturday->sub(date_interval_create_from_date_string('6 days'));
                $startDay = $priorSunday->format('Y-m-d');
                break;

            case 'last-calendar-month':
                //Calculate today's month
                $firstDayStr =  date("Y-n-j", strtotime("first day of previous month"));
                $firstDay = new \DateTime($firstDayStr);
                $startDay = $firstDay->format('Y-m-d');
                break;

            case 'last-30-days':
                $ago30days = $now->sub(date_interval_create_from_date_string('last 30 days'));
                $startDay = $ago30days->format('Y-m-d');
                break;

            case 'custom':
                $startDay = $myLogConnectorObj->startdate;
                break;

            default:
                $beginningOfTimes = new \DateTime('1970-01-01');
                $startDay = $beginningOfTimes->format('Y-m-d');
                break;
        }

        return $startDay;
    }

    private function getEndDate($myLogConnectorObj){
        $period = $myLogConnectorObj->period;
        $nowString = date("Y-m-d H:i:s");
        $now = new \DateTime($nowString);
        $endDay = $now->format('Y-m-d');
        switch ($period){
            case 'last-calendar-day':
                $ago1day = $now->sub(new \DateInterval('PT24H'));
                $endDay = $ago1day->format('Y-m-d');
                break;

            case 'last-7-calendar-days':
            case 'last-calendar-week':
                $endDay = date('Y-m-d', strtotime("last Saturday"));
                break;

            case 'last-calendar-month':
                $lastDayStr = date("Y-n-j", strtotime("last day of previous month"));
                $lastDay = new \DateTime($lastDayStr);
                $endDay = $lastDay->format('Y-m-d');
                break;

            case 'custom':
                $endDay = $myLogConnectorObj->enddate;
                break;


            default:
                break;
        }

        return $endDay;
    }

//    private function getRecurringDate($myLogConnectorID){
//
//    }

    public function getMyLogConnectorID(){
        $mySettings = new \UserSettings();
        $mySettings = $mySettings->getUserSettings($this->project);

        $logConnector = $mySettings['msg']['selectedLogConnector'];

        return $logConnector;
    }

    /***
     * @return LogConnectorDBEntry
     */
    public function getMyLogConnector(){
        $logConnector = $this->getMyLogConnectorID();
        if ($logConnector==""){$logConnector="''";}
        $query = "select * from connectors WHERE id='$logConnector'";
        $projectDB = selectDatabase($this->project);
        $resultConnector = $projectDB->query($query);

        $logConnectorObj = null;
        if($resultConnector->num_rows>0){
            $logConnectorObj = $resultConnector->fetch_object();
        }

        return $logConnectorObj;
    }

}