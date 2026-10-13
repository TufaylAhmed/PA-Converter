<?php
/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: $today.year.hour.minute
 ******************************************************************************/

namespace PaloAltoNetworks\Expedition\Spark;

abstract class SparkJob
{

    /***
     * @var bool
     */
    protected $invalid;

    /***
     * @var array
     */
    protected $missingFields;

    /***
     * @var string
     */
    protected $master;
    protected $timezone;

    protected $debug;

    protected $mlserver;
    protected $mtserver;
    protected $mtuser;
    protected $mtpassword;

    protected $input;
    /***
     * @var int
     */
    protected $taskID;

    protected $paramNames;
    protected $mandatoryFields;

    public function __construct(ARRAY $params=null)
    {
        $this->invalid = false;

        $this->paramNames = [
            //ParamName  => Default_Value
            'master'        => '',
            'ram'           => '4g',
            'timezone'      => 'Europe/Helsinki',
            'debug'         => false,
            'mlserver'      => '',
            'mtserver'      => '',
            'mtuser'        => '',
            'mtpassword'    => '',
            'input'         => '',
            'taskID'        => '',
        ];

        $this->mandatoryFields = ['master','timezone','debug','mlserver','mtserver','mtuser','mtpassword','taskID'];

    }

    protected function validateFields(){
        foreach ($this->mandatoryFields as $mandatoryField) {
            if (!isset($this->{$mandatoryField})) {
                $this->invalid = true;
                $this->missingFields[] = $mandatoryField;
            }
        }
    }

    abstract protected function internalExecute();

    public function execute(){
        $this->validateFields();
        if(!$this->invalid){
            $pid = $this->internalExecute();
            $message = '';

        }
        else{
            $pid = -1;
            $message = "Data missing: ".implode(", ",$this->missingFields);
            $this->logCommand("Error. Missing the following mandatory fields: ".implode(", ",$this->missingFields));
        }
        $msg = $this->reportTask($pid, $message);
        return $msg;
    }

    protected function reportTask(int $pid, String $message=null){
        $mysqlServer = explode(":", $this->mtserver);
        $serverIP = $mysqlServer[0];
        $serverPort = isset($mysqlServer[1]) ? $mysqlServer[1] : '3306';
        $taskUpdater = new \TaskUpdater($this->taskID, $serverIP, $this->mtuser, $this->mtpassword, $serverPort);
        if($pid > 0) {
            $reported = $taskUpdater->updateTaskPid($pid);

            $msg = [
                "code" => true,
                "msg" => "Started",
                "reported" => $reported,
                "pid" => $pid
            ];
        }
        else{
            $reported = $taskUpdater->reportFailedTask($message);

            $msg = [
                "code" => false,
                "msg" => "$message",
                "reported" => $reported,
                "pid" => $pid
            ];
        }

        return $msg;
    }

    protected function logCommand(String $command){
        $my = fopen("/tmp/command.spark", "a");
        fwrite($my, "$command\n");
        fclose($my);
    }
}