<?php
/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: $today.year.hour.minute
 ******************************************************************************/

namespace PaloAltoNetworks\Sentinel\Devices;

require_once INC_ROOT.'/libs/settings/ML_Settings.php';
require_once INC_ROOT.'/libs/common/device/CSFilesStates.php';
require_once INC_ROOT.'/libs/projectdb.php';

require_once INC_ROOT.'/libs/cpu_status_functions.php';
getEnvironmentParameters();
//require_once '/home/userSpace/environmentParameters.php';

class CsvFilesLister
{
    private $serial;
    private $path;

    public function __construct(STRING $serial, STRING $path=null){
        $this->serial = $serial;
        $this->path = $path;
    }


    private function isTodaysFile($fileObject):bool{
        $today = date("Y_m_d");
        $date = preg_match("/.*_".$today."_last_calendar.*/", $fileObject->name, $date_array);
        return $date?true:false;
    }

    /***
     * @return array
     */
    public function list_LogFiles(){
        global $app;

        $serial = $this->serial;
        $path=$this->path;
        if(!is_null($path)){
            $path = trim($path);
        }

        $news = array();
        $processed = array();
        $ignored = array();

//        if(!accessControl("any", ['device.*', 'device.create'])){
//            $message = array();
//            $message['code'] = false;
//            $message['msg'] = 'Your account does not have the rights to view logs from this device';
//            $message["news"]      = array();
//            $message["ignored"]   = array();
//            $message["processed"] = array();
//            return $message;
//        }

        $pandbRBAC = selectDatabase('pandbRBAC');

        /** @var $device Device */
        $device = null;
        if (isset($serial) & $serial!= ''){
            if (!$device = $app->device
                ->where('serial','=',$serial)
                ->where(function($query) {
                    $query->where('logtype','=','csv')
                        ->orWhere('logtype','=','');
                    })
                ->get()->first())
            {
                return [
                    "code"  => true,
                    "errorMessage" => "device not found",
                    'news'  => array(),
                    'ignored'   => array(),
                    'processed' => array(),
                    "msg" => []
                ];
            }
        }

        // Get ML settings to be able to request existing logs in filesystem
        $mlSettings = new \ML_Settings($pandbRBAC);
        $message = $mlSettings->get();
        $mlParams_arr = $message['msg'];
        if(count($mlParams_arr)>0)          $ExpeditionML = $mlParams_arr[0]['server'];
        else                                $ExpeditionML = $_SERVER['SERVER_ADDR'];

        //Before making the listing request. Check that ML is alive
        $connectionStatus = $mlSettings->checkAlive();
        if(!isset($connectionStatus->alive) || $connectionStatus->alive!=true) {
            return [
                "code"      => true,
                "msg"       => array(),
                "news"      => $news,
                "ignored"   => $ignored,
                "processed" => $processed,
                "errorMessage" => 'ML server not alive. Verify IP on the connection settings',
            ];
        }

        $filesObjectsArray = array();
        $errorMessages = array();

        if(!is_null($device)){
            if($device->logtype == "csv" || $device->logtype == ""){


                if(!isset($path)) {
                    $path = $device->getCSV_Path();
                    //$url = "https://$ExpeditionML/API/listFiles.php?path=".$device->getCSV_Path();
                }
                else{
                    //$url = "https://$ExpeditionML/API/listFiles.php?path=".$path;
                }

               if(!isset($path) || $path==""){
                    return [
                        "code"  => true,
                        "errorMessage" => "path not found",
                        'news'  => array(),
                        'ignored'   => array(),
                        'processed' => array(),
                        "msg" => []
                    ];
               }

                require_once INC_ROOT.'/API/listFiles.php';
                $params = ['path' => $path];
                $paths_in_folder = json_decode(json_encode(listFiles($params)), false);

                $errorMessages[] = $paths_in_folder->errorMessage;

                if(!defined('SparkRAM')){
                    define('SparkRAM','1024m');
                }

                $ram = $this->ramInMB(SparkRAM);

                if(isset($paths_in_folder->msg) && count($paths_in_folder->msg)>0) {
                    $filesObjectsArray = $this->convertIntoAssociative($paths_in_folder->msg, $ram); //Convert the Int Array into an Associative Array
                }
                foreach ($filesObjectsArray as $key => $fileObject){
                    if(!isset($fileObject->serial)){
                        unset($filesObjectsArray[$key]);
                    }
                }

                //print_r($filesObjectsArray);

                $serials = array();
                if($device->ispanorama){
                    $manageds = $app->device->where('management',$device->serial)->get(['devicename','serial']);
                    foreach ($manageds as $managed){
                        $serials[$managed->serial] = ($managed->serial!='')?$managed->devicename:null;
                        $serials[$managed->serialHA] = ($managed->serialHA!='')?$managed->devicename:null;
                    }
                }
                $serials[$device->serial] = ($device->serial!='')?$device->devicename:null;
                $serials[$device->serialHA] = ($device->serialHA!='')?$device->devicename:null;

                $serials = array_filter($serials);


                //Setting all the default parameters for the seen files in the path
                foreach ($filesObjectsArray as &$fileObject){
                    if(isset($fileObject->serial)) {
                        if (!array_key_exists($fileObject->serial, $serials)) { //This log is in the path, but does not belong to this device. So, do not list this file
                            unset($filesObjectsArray[$fileObject->log_name_noExt]);
                        } else {
                            $fileObject->devicename = $serials[$fileObject->serial];
                            $fileObject->log_name = $fileObject->name;
                            $fileObject->processed = "";
                            $date = preg_match("/.*_([0-9][0-9][0-9][0-9])_([0-9][0-9])_([0-9][0-9])_last_calendar.*/", $fileObject->name, $date_array);
                            if ($date == 1) { //THe file has a name format that states the date. Do not use the modified file date, but the one used in it's name
                                $fileObject->date = $date_array[1] . "-" . $date_array[2] . "-" . $date_array[3] . "";
                            }
//                            else{
//                                //$date_array = [0000 - 00 - 00, "0000", "00", "00"];
//                            }

                            if ($device->avoidToday() && $this->isTodaysFile($fileObject)) {
                                $fileObject->status = IGNORED;
                                $fileObject->comment = "Today's file (in progress)";
                            } else {
                                $fileObject->status = NEW_ED;
                                $version = $fileObject->version;
                                if ($version == 'unknown') {
                                    $version = "<font color='red'>Unsupported</font>";
                                }
                                $fileObject->comment = "New file. PANOS Ver. " . $version;
                            }
                        }
                    }
                }

                //Get all the logs that have already been processed for the given firewall or have been ignored
                $reportedLogs = $this->getProcessedLogsInDevice($pandbRBAC, $device);
                foreach ($reportedLogs as $reportedLog){
                    $fileName_noExt = $reportedLog['log_name'];
                    if(isset($filesObjectsArray[$fileName_noExt])){  //Update the file info. This file was already processed  or ignored in the past
                        $status    = ((strpos($reportedLog['comment'], 'DISABLED')!== false) ? IGNORED : PROCESSED);
                        $filesObjectsArray[$fileName_noExt]->comment = $reportedLog['comment'];
                        $filesObjectsArray[$fileName_noExt]->processed = $reportedLog['processed'];
                        $filesObjectsArray[$fileName_noExt]->status = $status;
                        $filesObjectsArray[$fileName_noExt]->devicename = $reportedLog['devicename'];
                    }
                    else{ //This file is not existing anymore, but we should show the decision is was taken about it
                        $status    = ((strpos($reportedLog['comment'], 'DISABLED')!== false) ? IGNORED : PROCESSED);
                        $newFile = [
                            'name'      => $reportedLog['log_name'],
                            'size'      => 'Unknown',
                            'version'   => 'unknown',
                            'serial'    => $reportedLog['serial'],
                            'devicename'=> $reportedLog['devicename'],
                            'log_name_nonExt' => $reportedLog['log_name'],
                            'comment'   => $reportedLog['comment'],
                            'log_name'  => $reportedLog['log_name'],
                            'processed' => $reportedLog['processed'],
                            'date'      => $reportedLog['date'],
                            'status'    => $status
                        ];
                        $newFile = json_decode(json_encode($newFile));

                        $filesObjectsArray[$reportedLog['log_name']] = $newFile;
                    }
                }
            }
        }

        $files = array();
        foreach ($filesObjectsArray as $filesObject){

            $files[] = $filesObject;
            if(isset($filesObject->status)) {
                switch ($filesObject->status) {
                    case "Ignored":
                        $ignored[] = $filesObject->name;
                        break;
                    case "Processed":
                        $processed[] = $filesObject->name;
                        break;
                    case "New":
                        $news[] = $filesObject->name;
                        break;
                    default:
                        break;
                }
            }

        }

        return [
            "code"          => true,
            "msg"           => $files,
            "news"          => $news,
            "ignored"       => $ignored,
            "processed"     => $processed,
            "errorMessage"  => implode(",", $errorMessages)
        ];
    }

    /***
     * @param array $files
     * @return array
     */
    private function getNamesWithoutExtension(ARRAY $files){
        $files_without_extension = array();

        if(count($files)>0) {
            foreach ($files->files as $fileObj) {
                $file = $fileObj->name;
                $file = str_replace(".csv", "", $file);
                $file = str_replace(".gz", "", $file);
                $files_without_extension[] = "'" . $file . "'";
            }
        }

        return $files_without_extension;
    }

    /***
     * @param $files array
     * @param $RAM integer
     * @return array
     */
    private function convertIntoAssociative($files, int $RAM=1024){
        $filesAssociative = array();
//        print_r($files);
        if(count($files)>0) {
            foreach ($files as &$fileObj) {
                $file = $fileObj->name;
//                echo $file;
//                echo $fileObj->size;
                if(!isset($fileObj->size)){
                    $fileObj['size']='0 MB';
                }
                $size = $this->ramInMB($fileObj->size);
//                echo $size;
                if(strpos($file, '.gz') !== false && $size * 10 > $RAM*0.8) {  //May fail in expanding the GZ to memory
                        $fileObj->warning = 1;
                }
                else{
                    $fileObj->warning = 0;
                }
                $file = str_replace(".csv", "", $file);
                $file = str_replace(".gz", "", $file);

                $fileObj->log_name_noExt = $file;
                $filesAssociative[$file] = $fileObj;
            }
        }

        return $filesAssociative;
    }

    /***
     * Given a device serial, checks the reported logs that have been processed or ignored. If the Serial belongs to a Panorama, it checks also it's managed devices
     * @param \MySqli $pandbRBAC
     * @param Device $device
     * @return array
     */
    private function getProcessedLogsInDevice(\MySqli $pandbRBAC, Device $device){

        global $app;


        $serials = array();
        if($device->ispanorama){
            $manageds = $app->device->where('management',$device->serial)->get(['devicename','serial','serialHA']);
            foreach ($manageds as $managed){
                if($managed->serial!='')
                    $serials[] = $managed->serial;
                if($managed->serialHA!='')
                    $serials[] = $managed->serialHA;
            }
        }

        if($device->serial!='')
            $serials[] = $device->serial;
        if($device->serialHA!='')
            $serials[] = $device->serialHA;


        $serialsList = implode("', '",array_filter($serials));
        $processedLogs = array();
        $query = "SELECT device_logs.log_name, device_logs.date, device_logs.processed, device_logs.comment, device_logs.created_at, device_logs.device_serial, devices.devicename  FROM device_logs, devices WHERE device_serial in ('$serialsList') AND devices.serial in ('$serialsList')";

        $result = $pandbRBAC->query($query);
        if ($result->num_rows > 0) {
            while ($row = $result->fetch_object()) {
                $date_array = explode(" ",$row->date);
                $date = '';
                if(count($date_array)>=0){
                    $date = $date_array[0];
                }
                $status    = ((strpos($row->comment, 'DISABLED')!== false) ? IGNORED : PROCESSED);
                $processedLogs[] = [
                    'log_name'  => $row->log_name,
                    'date'      => $date,
                    'processed' => 'on '.$row->processed,
                    'comment'   => $row->comment,
                    'status'    => $status,
                    'serial'    => $row->device_serial ,
                    'devicename'=> $row->devicename
                ];
            }
        }

        return $processedLogs;
    }

    /***
     * @param \MySqli $pandbRBAC
     * @param array $filesNamesArray
     * @return array
     */
    private function getProcessedLogs(\MySqli $pandbRBAC, ARRAY $filesNamesArray){
        $generalProcessedLogs = array();
        if(count($filesNamesArray)>0) {
            $query = "SELECT log_name, date, processed, comment, created_at  FROM device_logs WHERE log_name IN (" . implode(',', $filesNamesArray) . ")"; // AND device_id=" . $device->id;
            $result = $pandbRBAC->query($query);
            $generalProcessedLogs = array();
            $generalProcessedLogsObj = array();
            if ($result->num_rows > 0) {
                while ($row = $result->fetch_object()) {
                    $date_array = explode(" ",$row->date);
                    $date = '';
                    if(count($date_array)>=0){
                        $date = $date_array[0];
                    }
                    $status    = ((strpos($row->comment, 'DISABLED')!== false) ? IGNORED : PROCESSED);
                    $generalProcessedLogsObj[] = [
                        'log_name'  => $row->log_name,
                        'date'      => $date,
                        'processed' => 'on '.$row->processed,
                        'comment'   => $row->comment,
                        'status'    => $status
                    ];
                    $generalProcessedLogs[] = $row->log_name;
                }
            }
        }

        return $generalProcessedLogs;
    }

    public function setStateLogFile(STRING $serial, STRING $files, INT $state){
        global $app;

        $user    = $app->container->sentinel->getUser();

        if($serial == ''){
            return [
                "code"  => false,
                "msg"   => "Device Serial Number not provided"
            ];
        }

        $device = null;
        if (!$device = $app->device->where('serial','=',$serial)->where('logtype','=','csv')->get()->first())
            return [
                "code"  => false,
                "msg"   => "Device Serial Number not set up as a CSV Traffic Log reporter"
            ];

        if(!accessControl("any", ['device.'.$device.'.admin', 'device.create', 'device.admin'])){
            return [
                "code"  => false,
                "msg"   => 'Your account does not have the rights to view logs from this device'
            ];
        }

        $logs = $files!='' ? explode(',',$files): null;

        if(!is_null($logs)) {
            foreach ($logs as $log) {
                $logname = str_replace(".csv","",$log);
                $logname = str_replace(".gz","",$logname);
                $date = preg_match("/.*_([0-9][0-9][0-9][0-9])_([0-9][0-9])_([0-9][0-9])_last_calendar.*/", $logname, $date_array);
                if($date!=1){
                    $date_array = [0000-00-00,"0000","00","00"];
                }
                if($state == IGNORE) {
                    $params = [
                        'log_name'  => $logname,
                        'device_serial' => $serial,
                        'processed' => date("Y-m-d H:i:s"),
                        'date'      => $date_array[1]."-".$date_array[2]."-".$date_array[3]."",
                        'comment'   => "DISABLED by User <b>" . $user->email."</b>",
                    ];
                    if(!$report = $app->devicelog->where("log_name", $logname)->first()) {  //Make sure a file is not re-ignored or already processed creating duplicated entries of ignored file
                        $app->devicelog->create($params);
                    }
                }
                if($state == PROCESS) {
                    /** @var  $reportedLog */
                    if($reportedLog = $app->devicelog->where("log_name", $logname)->where('comment','not like', 'Processed %')->first()){
                        $reportedLog->delete();
                    }
                }
            }
        }

        if($state == IGNORE) {
            $message = [
                "code" => true,
                "msg" => "Files Disabled from Processing"
            ];
        }
        else{
            $message = [
                "code" => true,
                "msg" => "Files Enabled for Processing"
            ];
        }

        return $message;
    }

    private function ramInMB(string $ram='0 MB'):int{
        preg_match('/([0-9]*)([a-z]*)/', $ram, $output_array);
        switch($output_array[2]){
            case 'm':
            case 'MB':
                $result = (int) $output_array[1];
                break;
            case 'g':
            case 'GB':
                $result = (int) $output_array[1]*1024;
                break;
            case 't':
                $result = (int) $output_array[1]*1024*1024;
                break;
            default:
                $result = 0;
                break;
        }

        return $result;
    }
}