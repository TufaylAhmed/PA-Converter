<?php
/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: $today.year.hour.minute
 ******************************************************************************/

namespace PaloAltoNetworks\Sentinel\Devices;

//Loads all global PHP definitions
//require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
//require_once INC_ROOT.'/bin/authentication/sessionControl.php';

//require_once INC_ROOT.'/userManager/start.php';


include_once INC_ROOT.'/libs/definitions/taskDefinitions.php';
require_once INC_ROOT.'/libs/database.php';
require_once INC_ROOT.'/libs/shared.php';
require_once INC_ROOT.'/libs/settings/ML_Settings.php';
require_once INC_ROOT.'/userManager/API/projects/manageDevices.php';
require_once INC_ROOT.'/libs/objects/Response.php';
require_once INC_ROOT.'/libs/objects/Messages.php';
require_once INC_ROOT.'/libs/common/device/CsvFilesLister.php';

use \PaloAltoNetworks\HealthCheck\MLSettingsCheck;
use \ML_Settings;
use \Messages;
use \Response;

//TODO: Rename to CsvFilesProcessor
class CsvFilesProcesser
{
//    private $serial;
    private $project;
    private $mode;
    private $debug;
    private $parentJobID;
//    private $afterProcess;
    private $ram;
    private $parameters;

//    public function __construct($project, $ram, $serial, $mode, STRING $afterProcess=null, $parentJobID=null,  $debug='false' ){
    public function __construct(string $project, string $ram, string $parameters, int $parentJobID=null,  $debug='false' ){
        $this->project = $project;
//        $this->serial = $serial;
        $this->mode = isset($parameters['mode']) ? $parameters['mode'] : 'false';
        $this->parentJobID = $parentJobID;
        $this->debug = $debug;
//
//        $this->afterProcess = $afterProcess;
        $this->ram = $ram;
        $this->parameters = json_decode($parameters);
    }

    private function isTodaysFile($fileObject):bool{
        $today = date("Y_m_d");
        $date = preg_match("/.*_".$today."_last_calendar.*/", $fileObject->name, $date_array);
        return $date?true:false;
    }


    private function endsWith($haystack, $needle):bool
    {
        $length = strlen($needle);
        if ($length == 0) {
            return true;
        }

        return (substr($haystack, -$length) === $needle);
    }

    private function isZip($file):bool
    {
        return $this->endsWith($file->name, 'gz');
    }

    private function getSizeInMB($file):float
    {
        preg_match('/(.*) (.*)/', $file->size, $output_array);
        if($this->isZip($file)){
            //CSV compressed files take 1/10th, therefore, once uncompressed, they will take 10 times more
            $multiplierFactor=12.5;
        }
        else{
            $multiplierFactor=1;
        }

        $value1 =str_replace(',', '.', $output_array[1]);
        switch($output_array[2]){
            case "KB":
            case "K":
                $value = ceil(number_format($value1,0)/1024.0);
                break;

            case "GB":
            case "G":
                $value = ceil(number_format($value1,2)* 1024) ;
                break;

            case 'MB':
            case 'M':
            default:
                $value = ceil(number_format($value1,0));
                break;
        }

        return $value*$multiplierFactor;
    }

    public function execute(){
        return $this->processCSVLogs();
    }

    public function processCSVLogs(int $userID=null):Response{
        $project = $this->project;
//        $deviceSerial = $this->serial;
        $mode = $this->mode;
        $parentJobID=$this->parentJobID;
        $debug=$this->debug;

        $panReadOrders_fileResource = fopen("/home/userSpace/panReadOrders.log","a+");
        global $app;

        if(isset($userID)){
            $user = $app->sentinel->findById($userID);  //Provided user for CLI executions
            $app->sentinel->login($user);
        }else {
            $user = $app->container->sentinel->getUser();  //Get it from the Sentinel session, if coming from a browser.
        }
        $userName = $user->email;

        if(!accessControl("any", ['device.*', 'device.create'], $userID)){
            $message = new Response(false, -1, new Messages(['Your account does not have the rights to view logs from devices.']));
            fwrite($panReadOrders_fileResource,"No rights to access\n");
            return $message;
        }

        $pandbRBAC = selectDatabase('pandbRBAC');

        //Verify the settings for ML are correctly defined
        $checkMLSettings= new MLSettingsCheck();
        $result = $checkMLSettings->check()->toArray();

        if(!isset($result['success'])){
            $message = new Response(false, -2, new Messages(['Verify your ML settings are correct.']));
            fwrite($panReadOrders_fileResource,"Incorrect ML settings". $result['msg']. "\n");
            return $message;
        }
        elseif($result['success']!=1){
            $message = new Response(false,  $result['code'], new Messages(['Verify your ML settings are correct.', $result['msg']]));
            fwrite($panReadOrders_fileResource,"Incorrect ML settings". $result['msg']. "\n");
            return $message;
        }

        $mlSettings = new ML_Settings($pandbRBAC);
        $message = $mlSettings->get();
        $mlParams_arr = $message['msg'];
        if(count($mlParams_arr)>0){
            $ExpeditionML = $mlParams_arr[0]['server'];
            $parquetPath  = $mlParams_arr[0]['parquetPath'];
            $tempPath     = $mlParams_arr[0]['tempDataPath'];
        }
        else{
            $ExpeditionML = $_SERVER['SERVER_ADDR'];
            $parquetPath  = "/tmp";
            $tempPath  = "/tmp";
        }

        //Verify that we can reach the Spark module for execution
        fwrite($panReadOrders_fileResource,"    Checking ML server is alive\n");
        $connectionStatus = $mlSettings->checkAlive();

        if(isset($connectionStatus->alive) && $connectionStatus->alive==true) {
            fwrite($panReadOrders_fileResource,"    ML Server is alive\n");

            $API_URI = "https://$ExpeditionML/API/convertCSVtoParquet.php";

            $tuCurl = curl_init();

            //For each device, look for valid CSV files to process.
            $devicesData = array();
            $serialsAndPaths = array();
            fwrite($panReadOrders_fileResource, "    Collecting device(s) serial(s)\n");

            foreach ($this->parameters->devices as $deviceData) {
                /** @var $device Device */
                if(!$device = $app->device->where("serial", $deviceData->serial)->get()->first()){
                    continue;
                }
                $isPanorama = $device->ispanorama;

                fwrite($panReadOrders_fileResource, "    ". $device->serial." added\n");
                $devicesData[] = $deviceData;
                //$serialsAndPaths = array();
                $serialsAndPaths[] = [
                    'serial' => $device->serial,
                    'path'   =>$device->getCSV_Path()
                ];

                //It is a Panorama, check if any of the managed devices has a different path
                if($isPanorama==1){
                    fwrite($panReadOrders_fileResource, "    ".$deviceData->serial." is a panorama device. Adding managed devices:\n");
                    if($managedDevices = $app->device->where("management",$deviceData->serial)->get()) {
                        foreach ($managedDevices as $managedDevice) {
                            //These conditions mark that a device specifies a different path to be checked
                            if($managedDevice->csv_path != $device->csv_path && $managedDevice->csv_path!='') {
                                $serialsAndPaths[] = [
                                    'serial' => $managedDevice->serial,
                                    'path'   =>$managedDevice->csv_path
                                ];
                                $devicesData[] = json_decode(json_encode([
                                    'serial' => $managedDevice->serial,
                                    'afterProcess' => $managedDevice->afterProcess,
                                    'mode' => 'false',
                                    'pathOverride' => null
                                ]));
                            }
                        }
                    }
                    fwrite($panReadOrders_fileResource, "        ". json_encode($serialsAndPaths)."\n");
                }
            }

            fwrite($panReadOrders_fileResource, "devicesData\n");
            fwrite($panReadOrders_fileResource, print_r($devicesData, true));
            fwrite($panReadOrders_fileResource, "serialsAndData\n");
            fwrite($panReadOrders_fileResource, print_r($serialsAndPaths, true));

            $files = array();
            foreach ($serialsAndPaths as $serialsAndPath) {
                $filesLister = new CsvFilesLister($serialsAndPath['serial'], $serialsAndPath['path']);
                $localFiles = $filesLister->list_LogFiles();
                $files = array_merge($files, $localFiles['msg']);
            }

            if (count($files) == 0) {
                $message = new Response(false, -1, new Messages(['No supported new files to process']));
                fwrite($panReadOrders_fileResource,"    No supported new files to process\n");
            }
            else {
                $mtserver = isset($_SERVER['SERVER_ADDR'])? $_SERVER['SERVER_ADDR'] . ":3306" : 'localhost:3306';

                $jobParameters['files'] = $files;

                $paths = array();
                foreach ($files as $file){
                    if($file->status == "New") {
                        $size = $this->getSizeInMB($file);
                        $afterProcess = "Nothing";
                        if ($device = $app->device->where("serial", $file->serial)->get()->first()) {
                            $afterProcess = $device->afterProcess;
                        }
                        if(!isset($device)){
                            if ($device = $app->device->where("serialHA", $file->serial)->get()->first()) {
                                $afterProcess = $device->afterProcess;
                            }
                        }
                        //015558000001880:8.1.0:/data/rawlogs/data2/syslog_data/dl1-splunk04.pan.local/2019-10-25-07/PANW_Traffic/ADI-PROD-US-W1-FW2/panw_traffic.log:1:Nothing
                        $paths[] = $file->serial . ":" . $file->version . ":" . $file->log_name . ":" . $size . ":" . $afterProcess;
                    }
                }

                if(count($paths)==0){
                    $message = new Response(false, -1, new Messages(['No supported new files to process']));
                    fwrite($panReadOrders_fileResource,"    No supported new files to process\n");
                }
                else {
                    //Register Parent Job if it is not provided
                    if ($parentJobID == null) {
                        $parentJobID = $this->registerParentJob($jobParameters, $user, "Spark: Process CSV files to Parquet (" . implode(",", $paths) . ")");
                    }

                    $jobID = $this->registerJob($jobParameters, $user, "Spark: Process CSV files to Parquet (" . implode(",", $paths) . ")", $parentJobID);

                    //Get number of Spark CPUs
                    require_once INC_ROOT . "/libs/cpu_status_functions.php";
                    $MLstatus = getMLStatus();
                    $sparkCPUs = 8; //Default value for Spark CPUs
                    foreach ($MLstatus as $stat) {
                        if ($stat->item == 'CPUs') {
                            $sparkCPUs = $stat->spark;
                            break;
                        }
                    }
                    $MASTERLOCATION = "local[$sparkCPUs]";

                    $params = [
                        'debug' => isset($debug) ? $debug : 'false',
                        "user" => $userName,
                        'master' => $MASTERLOCATION,
                        'mtserver' => $mtserver,
                        'mlserver' => $ExpeditionML,
                        'mtuser' => DBUser,
                        'mtpassword' => DBPass,
                        'path' => implode(',', $paths),
                        'parquetPath' => $parquetPath,
                        'tempPath' => $tempPath,
                        "ram" => $this->ram,
                        "api_key" => getUserApiKey($user->getAttribute("api_key")??"", $user->getAttribute("valid_til")??"",$user->getAttribute("id"))
                    ];
                    $taskID = $this->registerTask($params, $user, $jobID, "$API_URI", "Spark: Process CSV files to Parquet (" . implode(',', $paths) . ")");
                    $this->params['taskId'] = $taskID;
                    $url = "https://$ExpeditionML/API/convertCSVtoParquet.php";
                    $curlParams = [
                        "debug" => isset($debug) ? $debug : 'false',
                        "taskID" => $taskID,
                        "user" => $userName,
                        'master' => $MASTERLOCATION,
                        "mtserver" => $mtserver,
                        "mlserver" => $ExpeditionML,
                        "mtuser" => DBUser,
                        "mtpassword" => urlencode(DBPass),
                        "path" => implode(',', $paths),
                        "parquetPath" => $parquetPath,
                        "tempPath" => $tempPath,
                        "ram" => $this->ram,
                        "api_key" => getUserApiKey($user->getAttribute("api_key")??"", $user->getAttribute("valid_til")??"",$user->getAttribute("id"))
                    ];

                    curl_setopt($tuCurl, CURLOPT_URL, $url);
                    curl_setopt($tuCurl, CURLOPT_POST, 1);
                    curl_setopt($tuCurl, CURLOPT_POSTFIELDS, http_build_query($curlParams));
                    curl_setopt($tuCurl, CURLOPT_RETURNTRANSFER, true);
                    curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, 0);
                    curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, 0);
//            $output = json_decode(curl_exec($tuCurl));
                    curl_exec($tuCurl);
                    $line = curl_multi_getcontent($tuCurl);
                    $result = json_decode($line, true);

                    fwrite($panReadOrders_fileResource, "\n    Convert CSV to Parquet called with the following files\n");
                    fwrite($panReadOrders_fileResource, "      " . json_encode($paths) . "\n");

                    $success = true;
                    $message = new Response($success, $jobID, new Messages([$jobID]));

                    if(filter_var($result['success'], FILTER_VALIDATE_BOOLEAN)==false){
                        $this->setFailed($taskID,"Spark: Process CSV files to Parquet", "Process failed . " . $result['msg']);
                        fwrite($panReadOrders_fileResource, "      " . json_encode($result) . "\n");
                        $success = false;
                        $message = new Response($success, $jobID, new Messages([$result['msg']]));
                    }

                    curl_close($tuCurl);

                }
            }
        }
        else{
            $message = new Response(false, -10, new Messages(['MLServer not reachable']));
        }

        fwrite($panReadOrders_fileResource, "\n\n");
        return $message;

    }

    /***
     * //Look for valid CSV files to process.
     * @param \mysqli $pandbRBAC
     * @param string $ExpeditionML
     * @param $panReadOrders_fileResource
     * @param $tuCurl
     * @param $deviceData
     * @return array
     */
//    private function getDeviceFiles(\mysqli $pandbRBAC, string $ExpeditionML, $panReadOrders_fileResource, $tuCurl, $deviceData):array{
//        global $app;
//        $paths = array();
//        $deviceSerial = $deviceData->serial;
//        $afterProcess = $deviceData->afterProcess;
//        fwrite($panReadOrders_fileResource, "    Checking for device with serial $deviceSerial\n");
//
//        /** @var $device Device */
//        if (isset($deviceSerial) && $deviceSerial != '') {
//            if (!$device = $app->device->where('serial', '=', $deviceSerial)
//                ->where(function ($query) {
//                    $query->where('logtype', '=', 'csv')
//                        ->orWhere('logtype', '=', '');
//                })
//                ->get()->first()) {
//                //Device not found
//                fwrite($panReadOrders_fileResource,"Could not find device with serial $deviceSerial\n");
//                return $paths;
//            }
//        }
//        else {
//            //Device not found
//            fwrite($panReadOrders_fileResource,"Device not provided\n");
//            return $paths;
//        }
//
//        fwrite($panReadOrders_fileResource, print_r($this->parameters, true));
//        if ($this->parameters->pathOverride && $this->parameters->pathOverride != null) {
//            $url = "https://$ExpeditionML/API/listFiles.php?path=" . $this->parameters->pathOverride;
//            fwrite($panReadOrders_fileResource,"        We have an override path provided by the user:\t$url \n");
//        }
//        else {
//            $url = "https://$ExpeditionML/API/listFiles.php?path=" . $device->getCSV_Path();
//            fwrite($panReadOrders_fileResource,"        Default path:\t$url\n");
//        }
//
//        curl_setopt($tuCurl, CURLOPT_URL, $url);
//        curl_setopt($tuCurl, CURLOPT_RETURNTRANSFER, true);
//        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, 0);
//        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, 0);
//        $output = curl_exec($tuCurl);
//
//        $paths_device = json_decode($output);
//
//        $files_device = array();
//        foreach ($paths_device->files as $fileObj) {
//            $file = $pandbRBAC->real_escape_string($fileObj->name);
//            $file = str_replace(".csv", "", $file);
//            $file = str_replace(".gz", "", $file);
//            $files_device[] = "'" . $file . "'";
//        }
//
//        if(count($files_device)>0) {
//            $query = "SELECT log_name FROM device_logs WHERE log_name IN (" . implode(',', $files_device) . ") AND id='" . $device->id . "'";
//            $result = $pandbRBAC->query($query);
//            $processedLogs = array();
//            if ($result->num_rows > 0) {
//                while ($row = $result->fetch_assoc()) {
//                    $processedLogs[] = $row['log_name'];
//                }
//            }
//
//            foreach ($paths_device->files as $fileObj) {
//                if ($fileObj->size != "0 KB") {
//                    if ($fileObj->serial == $device->serial || $fileObj->serial == $device->serialHA) {
//                        $file = $fileObj->name;
//                        fwrite($panReadOrders_fileResource,"      File found ".$fileObj->name." (".$fileObj->size.")\n");
//                        $fileSize = $this->getSizeInMB($fileObj);
//                        $file_name = str_replace(".csv", "", $file);
//                        $file_name = str_replace(".gz", "", $file_name);
//                        if (!in_array($file_name, $processedLogs)) {
//                            $id = str_replace(".csv", "", $file);
//                            $id = str_replace(".gz", "", $id);
//                            if ($fileObj->version != 'unknown') {
//                                if (!($device->avoidToday() && $this->isTodaysFile($fileObj))) {
//                                    $paths[$id] = $device->serial . ":" . $fileObj->version . ":" . $file . ":". $fileSize.":".$afterProcess;
//                                }
//                            }
//                        }
//                    }
//                }
//            }
//        }
//
//        $query = "SELECT log_name FROM device_logs";
//        $result = $pandbRBAC->query($query);
//        if ($result->num_rows > 0) {
//            while ($row = $result->fetch_assoc()) {
//                $processedFile = $row['log_name'];
//                if (isset($paths[$processedFile])) {
//                    unset($paths[$processedFile]);
//                }
//            }
//        }
//
//        return $paths;
//    }


    private function registerJob(ARRAY $data, $user, STRING $description, INT $parentJob=null){
        global $app;

        //$device = $app->device->where('serial',$data['serial'])->first();
        $params = [
            'user_id'       => $user->id,
            'parentType'    => 'devices',
            'parentId'      => 0,
            'description'   => $description,
            'parentJob'     => $parentJob,
        ];
        if(!$job = $app->job->create($params)){
            return -1;
        }

        return $job->id;
    }

    private function registerParentJob(ARRAY $data, $user, STRING $description){
        global $app;

        //$device = $app->device->where('serial',$data['serial'])->first();
        $params = [
            'user_id'       => $user->id,
            'parentType'    => 'devices',
            'parentId'      => '',
            'description'   => $description,
        ];
        if(!$job = $app->job->create($params)){
            return -1;
        }

        return $job->id;
    }

    private function registerTask(ARRAY $data=null, $user, INT $jobID, STRING $processCode, STRING $processName){
        global $app;

        if(!isset($data['params'])){
            $data['params'] = '';
        }
        $data['userId'] = $user->id;

        $params = [
            'job_id'        => $jobID,
            'taskType'      => 'ConvertCSV2Parquet',
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
            'tasks' => $job->tasks +1,
        ];
        $job->update($jobParams);

        if($job->parentJob != ''){
            $parentJob = $app->job->where('id', $job->parentJob)->first();
            $parentJobParams = [
                'tasks' => $parentJob->tasks +1,
            ];
            $parentJob->update($parentJobParams);
        }

        return $task->id;
    }

    private function setFailed(STRING $task_id, STRING $submessage=NULL, STRING $resultCode=NULL){
        global $app;
        $submessage = is_null($submessage) ? '': $submessage;
        $resultCode = is_null($resultCode) ? '': $resultCode;
        $taskParams = [
            'statusCode'    => FAILED,
            'statusMessage' => 'Completed. '.$submessage,
            'resultCode'    => $resultCode,
        ];

        /** @var $task \PaloAltoNetworks\MTJobs\Tasks\Task */
        if (!($task = $app->task->where('id', $task_id)->first())) {
            //Log there was a problem
            return;
        }
        $task->update($taskParams);

        if (!$job = $task->job){
            //Log there was a problem finding the job
            echo "Job not found\n";
            return;
        }

        $jobParams = [
            'completed' => $job->completed +1,
            'failed' => $job->failed +1,
        ];
        $job->update($jobParams);

        if($job->parentJob != ''){
            $parentJob = $app->job->where('id',$job->parentJob)->get()->first();
            $parentJobParams = [
                'completed' => $parentJob->completed +1,
                'failed' => $parentJob->failed +1,
            ];
            $parentJob->update($parentJobParams);
        }
    }
}