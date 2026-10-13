<?php
/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: $today.year.hour.minute
 ******************************************************************************/

namespace PaloAltoNetworks\Expedition\Spark;

require_once INC_ROOT.'/API/process/TaskUpdater.php';
require_once INC_ROOT.'/API/SparkJobs/SparkJob.php';
require_once INC_ROOT.'/libs/database.php';
require_once INC_ROOT.'/libs/settings/ML_Settings.php';

use ML_Settings;

class CSVProcesser extends SparkJob
{
    /***
     * @var string
     */
    protected $project;

    /***
     * @var bool
     */
    protected $saveServer;

    /***
     * @var string
     */

    protected $mode;
    protected $user;
    protected $tempPath;
    protected $parquetPath;
    protected $connection;

    public function __construct(ARRAY $params=null)
    {
        parent::__construct($params);
        global $pandbRBAC;
        $this->connection = $pandbRBAC;
        $this->paramNames = array_merge($this->paramNames,[
            //ParamName  => Default_Value
            'mode'          => 'Expedition',
            'input'         => '',
            'tempPath'      => '/tmp',
            'parquetPath'   => '/tmp',
            'user'          => ''
        ]);

        $this->mandatoryFields = array_merge($this->mandatoryFields, ['mode','input','tempPath','parquetPath']);

        foreach ($this->paramNames as $paramName=>$default){
            $this->{$paramName} = isset($params[$paramName])? $params[$paramName]:$default;
        }
    }

    protected function internalExecute()
    {

        // Check the master is a valid master
        $pattern = '/^local\[\d+\]$/';
        if (preg_match($pattern, $this->master)) {
            $master = $this->master;
        } else {
            $master = "local[8]";
        }

        // Check the Expedition server
        $mlSettings = new ML_Settings($this->connection);
        $message = $mlSettings->get();
        $mlParams_arr = $message['msg'];
        if(count($mlParams_arr)>0){
            $mlserver = $mlParams_arr[0]['server'];
            $parquetPath  = $mlParams_arr[0]['parquetPath'];
            $tempPath     = $mlParams_arr[0]['tempDataPath'];
            $mtserver     = $mlserver.":3306";
        } else {
            $message['code'] = false;
            $message['msg'] = "Invalid Server to execute the process";
            echo json_encode($message);
            exit();
        }


        $MODE           ="Expedition";
        $OUTPUT 		= $parquetPath."/connections.parquet";

        $clusterMode = false;
        $inputFileList = $this->input;
        $inputFileList = str_replace(",","\n", $inputFileList);
        $inputFileList = str_replace(":",",", $inputFileList);
        $thisTime = time();
        $fileName = "/tmp/".$thisTime."_traffic_files.csv";
        $inputFileList_Resource = fopen($fileName,"w");
        fwrite($inputFileList_Resource, "fwSerial,panosver,csvpath,size,afterProcess\n");
        fwrite($inputFileList_Resource, $inputFileList);
        fclose($inputFileList_Resource);





        if($clusterMode) {
            $command = "/opt/Spark/spark/bin/spark-submit --master spark://machineLearning-v1:7077 --class com.paloaltonetworks.tbd.LogCollectorCompacter " .
                "--deploy-mode client --supervise /var/www/html/OS/spark/packages/ML-LogCoCo-".Module_version_ML_LogCoCo."-SNAPSHOT.jar " .
                "MLServer=".escapeshellarg($mlserver).", " . "master=".escapeshellarg($master).", " . "debug=".escapeshellarg($this->debug).", " .
                "taskID=".escapeshellarg($this->taskID).", user=".escapeshellarg($this->user).", ".
                "dbUser=".escapeshellarg($this->mtuser).", dbPass=".escapeshellarg($this->mtpassword).", dbServer=".escapeshellarg($mtserver).", " .
                "timeZone=".escapeshellarg($this->timezone).", ".
                "mode=".escapeshellarg($this->mode).", ".
                "input=".escapeshellarg($this->mode).", output=".escapeshellarg($OUTPUT);
        }
        else {
            $command = "/opt/Spark/spark/bin/spark-submit --class com.paloaltonetworks.tbd.LogCollectorCompacter --master localhost --deploy-mode client --driver-memory ".escapeshellarg($this->ram)." " .
                "--supervise /var/www/html/OS/spark/packages/ML-LogCoCo-".Module_version_ML_LogCoCo."-SNAPSHOT.jar " .
                "MLServer=".escapeshellarg($mlserver).", master=".escapeshellarg($master) . ", debug=".escapeshellarg($this->debug).", ".
                "taskID=".escapeshellarg($this->taskID).", user=" . escapeshellarg($this->user) . ", ".
                "dbUser=".escapeshellarg($this->mtuser).", dbPass=".escapeshellarg($this->mtpassword).", dbServer=".escapeshellarg($mtserver).", ".
                "timeZone=".escapeshellarg($this->timezone).", ".
                "mode=".escapeshellarg($MODE).", ".
                "input=".escapeshellarg($fileName).", output=".escapeshellarg($OUTPUT).", tempFolder=".escapeshellarg($tempPath);
        }

//        $command = "/opt/Spark/spark/bin/spark-submit --class com.paloaltonetworks.tbd.RuleAutoCompleter --master localhost --deploy-mode client --driver-memory ".$this->ram." ".
//            "/var/www/html/OS/spark/packages/RuleAutoCompleter-" . Module_version_SecurityRuleEnrichment . "-SNAPSHOT.jar " .
//            "master=" . escapeshellarg($this->master) . ", debug=" . escapeshellarg($this->debug) . ", " .
//            "taskID=" . escapeshellarg($this->taskID) . ", MLServer=" . escapeshellarg($this->mlserver) .
//            ", MTServer=" . escapeshellarg($this->mtserver) .
//            ", timeZone=" . escapeshellarg($this->timezone) .
//            ", DBUser=" . escapeshellarg($this->mtuser) . ", DBPass=" . escapeshellarg($this->mtpassword) . ", project=" . escapeshellarg($this->project) . ", " .
//            "input=" . escapeshellarg($this->input) . ", devices=" . escapeshellarg($this->devices) . ", rules=" . escapeshellarg($this->rules) .
//            ", initDate=" . escapeshellarg($this->initDate) . ", endDate=" . escapeshellarg($this->endDate) . ", " .
//            "mask=" . escapeshellarg($this->mask) . ", accuracy=" . escapeshellarg($this->accuracy) . ", saveServers=" . escapeshellarg($this->saveServer) . ", regions=" . escapeshellarg($this->regions);
        $this->logCommand($command);

        //IF PROCESS IS CORRECT Delete Files / Compress Files / Do nothing
        $compressCommands = array();
        $deleteCommands = array();
        $echoCommands = array();
        $files = getFilesAndAction(escapeshellcmd($this->input));
        $toDelete = array();
        $toZip=array();
        foreach ($files as $filePath){
            //012801096217:9.0.0:/PALogs/myFW/PA220-Mauri63_traffic_2019_07_25_last_calendar_day.csv:0.0029296875:delete
            //$filePathParts = explode(":", $filePath);
            switch($filePath['afterProcess']){
                case "Delete":
                    $toDelete[] = $filePath['file'];
                    $deleteCommands[] = "rm -f ".$filePath['file']."; ";
                    break;
                case "Compress":
                    $toZip[] = $filePath['file'];
                    $compressCommands[] = "gzip ".$filePath['file']."; ";
                    break;
                default:
                    $echoCommands[] = "echo ".$filePath['file']."; ";
                    break;
            }
        }

        $fileName = "/tmp/".$thisTime."_afterProcess.csv";
        $inputFileList_Resource = fopen($fileName,"w");
        fwrite($inputFileList_Resource, "{deletePaths:".implode(",",$toDelete).";zipPaths:".implode(",",$toZip)."}");
        fclose($inputFileList_Resource);
        if(file_exists($fileName)) {
            $secondCommand = "php /var/www/html/API/convertCSVtoParquet_afterProcess.php $fileName";
            $superCommand = "($command; $secondCommand)>> \"/tmp/error_logCoCo\" 2>>/tmp/error_logCoCo &";
//        if(count($deleteCommands)>0)     $superCommand = $superCommand.implode(" ",$deleteCommands);
//        if(count($compressCommands)>0)   $superCommand = $superCommand.implode(" ",$compressCommands);
//        if(count($echoCommands)>0)       $superCommand = $superCommand.implode(" ",$echoCommands);
//        $superCommand = $superCommand.")>> \"/tmp/error_logCoCo\" 2>>/tmp/error_logCoCo &";

            $my = fopen("/tmp/command_actions.spark", "a");
            fwrite($my, $superCommand . "\n");
            fclose($my);

            $pid = exec($superCommand . " echo $!;", $output);

            return $pid;
        }else{
            return 0;
        }

    }

}