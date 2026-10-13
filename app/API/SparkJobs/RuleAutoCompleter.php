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

class RuleAutoCompleter extends SparkJob
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
    protected $initDate;
    protected $endDate;

    protected $devices;
    protected $rules;
    protected $regions;

    protected $mask;
    protected $accuracy;

    protected $hits;
    protected $bytes;
    protected $bytesSent;
    protected $bytesReceived;
    protected $connection;


    public function __construct(ARRAY $params=null)
    {
        parent::__construct($params);
        global $pandbRBAC;
        $this->connection = $pandbRBAC;
        $this->paramNames = array_merge($this->paramNames,[
            //ParamName  => Default_Value
            'project'    => '',
            'initDate'   => '1970-01-01',
            'endDate'    => '',
            'devices'    => '',
            'rules'      => '',
            'regions'    => '',
            'mask'       => 32,
            'accuracy'   => 1.0,
            'saveServer' => true,
            'hits'              => 1,
            'bytes'             => 1,
            'bytesSent'         => 0,
            'bytesReceived'     => 0

        ]);

        $this->mandatoryFields = array_merge($this->mandatoryFields, ['project','rules','devices']);

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
            $mtserver     = $mlserver.":3306";
        } else {
            $message['code'] = false;
            $message['msg'] = "Invalid Server to execute the process";
            echo json_encode($message);
            exit();
        }

        $command = "/opt/Spark/spark/bin/spark-submit --class com.paloaltonetworks.tbd.RuleAutoCompleter --master localhost --deploy-mode client --driver-memory ".escapeshellarg($this->ram)." ".
            "/var/www/html/OS/spark/packages/ML-LogCoCo-" . Module_version_ML_LogCoCo . "-SNAPSHOT.jar " .
            "master=" . escapeshellarg($master) . ", debug=" . escapeshellarg($this->debug) . ", " .
            "taskID=" . escapeshellarg($this->taskID) . ", MLServer=" . escapeshellarg($mlserver) .
            ", MTServer=" . escapeshellarg($mtserver) .
            ", timeZone=" . escapeshellarg($this->timezone) .
            ", DBUser=" . escapeshellarg($this->mtuser) . ", DBPass=" . escapeshellarg($this->mtpassword) . ", project=" . escapeshellarg($this->project) .
            ", input=" . escapeshellarg($this->input) . ", devices=" . escapeshellarg($this->devices) . ", rules=" . escapeshellarg($this->rules) .
            ", initDate=" . escapeshellarg($this->initDate) . ", endDate=" . escapeshellarg($this->endDate) .
            ", mask=" . escapeshellarg($this->mask) . ", accuracy=" . escapeshellarg($this->accuracy) . ", saveServers=" . escapeshellarg($this->saveServer) . ", regions=" . escapeshellarg($this->regions) .
            ", minHits=" . escapeshellarg($this->hits) . ", minBytes=" . escapeshellarg($this->bytes) . ", minBytesOut=" . escapeshellarg($this->bytesSent) .  ", minBytesIn=". escapeshellarg($this->bytesReceived);
        $this->logCommand($command);

        $pid = exec("$command > /tmp/error_SecRulesEnrich 2>/tmp/error_SecRulesEnrich2 & echo $!;", $output);

        return $pid;
    }

}