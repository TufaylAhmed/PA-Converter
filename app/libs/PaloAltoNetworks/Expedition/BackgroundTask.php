<?php

namespace PaloAltoNetworks\Expedition;

class BackgroundTask
{
    public $output;

    /* @var array */
    protected $input;

    protected $reporterType;
    protected $reporterResource;

    protected $pid;
    protected $isRunning;
    protected $napTime=2;
    protected $startedAt;
    protected $completedAt;
    protected $filename;

    protected $description;

    public function start(){
        $this->startedAt = microtime(true);
        $this->run();
    }

    public function run() {
        /* Processing here, use $output for... well... outputting data */

        // Here you would implement your for() loops, for example, using $this->input as their data

        // Some dumb value to demonstrate
        $output = "SOME DATA!";
    }

    public function __construct($input_data) {
        $this->input = $input_data;
        $this->setReporterSettings();
        $this->setDescription();
        $this->setNapTime();
        $this->filename="/home/userSpace/".floor(microtime(true) * 1000)."_mysql.cnf";
    }

    protected function setDescription(){
        $this->description = (isset($this->input['description']))?$this->input['description']: '';
    }

    protected function setNapTime(){
        $this->napTime = (isset($this->input['napTime']))?$this->input['napTime']: 2;
    }

    private function setReporterSettings(){
        if(isset($this->input['logType'])){
            switch($this->input['logType']){
                case 'file':
                default:
                    $this->reporterType='file';
            }
        }
        else{
            $this->reporterType='file';
        }

        if(isset($this->input['logResource'])){
            switch ($this->reporterType){
                case 'file':
                default:
                    $this->reporterResource = $this->input['logResource'];
            }
        }
        else{
            $this->reporterType = 'file';
            $this->reporterResource = '/tmp/backgroundTasks.log';
        }
    }

    protected function log(STRING $text){

    }

    public function getResult(){
        return $this->output;
    }

    public function report(){

    }

    //Updates the status of the running process
    protected function updateState(){
        # Cleaning
        $basepath = '/proc/';
        $realBase = realpath($basepath);

        $userpath = $basepath . $this->pid;
        $realUserPath = realpath($userpath);

        $isRunning = false;

        if ($realUserPath === false || strpos($realUserPath, $realBase) !== 0) {
            $this->isRunning = $isRunning;
        }
        else {
            if (file_exists( "/proc/".$this->pid )){
                $isRunning = true;
            }
            else{
                $isRunning = false;
            }
            $this->isRunning=  $isRunning;
        }
    }

    //Blocks the execution until the this process is completed
    public function join(){
        while(true) {
            $this->updateState();
            if (!$this->isRunning) {
                $this->completedAt = microtime(true);
                echo "$this->description completed with ".($this->completedAt - $this->startedAt)." seconds\n";
                delete_mysql_dump_file($this->filename);
                return;
            }
            echo "$this->description is still running\n";
            sleep($this->napTime);
        }
    }
}