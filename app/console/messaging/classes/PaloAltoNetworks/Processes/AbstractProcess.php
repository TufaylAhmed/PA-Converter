<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 3/6/16 - 13:14
 */

//namespace PaloAltoNetworks\Processes;

include_once INC_ROOT.'/libs/definitions/taskDefinitions.php';
include_once INC_ROOT.'/libs/projectdb.php';

abstract class AbstractProcess{

    /** @var bool */
    protected $loggable;

    /** @var string */
    protected $logPath;

    /** @var mixed|null */
    protected $sender;

    protected $params;


    public function __construct(ARRAY $params)
    {
        global $pandbRABC;
        $pandbRABC = selectDatabase('pandbRBAC');
        $this->loggable = (isset($params['loggable']))  ? $params['loggable']   : false;
        $this->logPath  = (isset($params['logPath']))   ? $params['logPath']    : '';
        $this->sender   = (isset($params['sender']))    ? $params['sender']     : null;
        $this->params   = $params;
    }

    public function log(String $msg, $level=1){
        require_once INC_ROOT.'/libs/common/MTLogger.php';
        $logger = (new MTLogger)->getInstance();
        $logger->log($msg, $level);
    }

    public function getSender(){
        return $this->sender;
    }

    public function start(){
        $this->log(date(DATE_RFC2822)." Start Task", 0);
        $this->execute();
        $this->log(date(DATE_RFC2822)." End Task\n\n", 0);
    }

    public function execute(){
        global $app;
        if ($this->isCancelled()){
            return false;
        }

        if (!($task = $app->task->where('id', $this->params['taskId'])->first())) {
            //Log there was a problem
            return false;
        }
        //Check if this task has been executed in a further task call
        $futureTask = $app->task
            ->where('id','>', $task->id)
            ->where('taskType', $task->taskType)
            ->where('processCode', $task->processCode)
            ->where('params',$task->params)
            ->first();

        if($futureTask){
            echo "Skip. This task has been added again further in the future\n";
            $this->setCompleted('Skipped task. Re-requested in the future');
            return false;
        }
        return true;
    }

    function isCancelled(){
        global $app;

        if (!($task = $app->task->where('id', $this->params['taskId'])->first())) {
            //Log there was a problem
            return true;
        }

        if ($task->statusCode < 0){
            return true;
        }
        return false;
    }

    function setStarted(){
        global $app;
        $taskParams = [
            'statusCode'    => STARTED,
        ];

        /**
         * @var $task \PaloAltoNetworks\MTJobs\Tasks\Task
         */
        if (!($task = $app->task->where('id', $this->params['taskId'])->first())) {
            //Log there was a problem
            return;
        }
        $task->update($taskParams);
    }

    function setToRelaunch(STRING $metric, INT $units, STRING $submessage){
        global $app;
        switch ($metric){
            case "days":
                $time = $units * 24 * 360;
                break;
            case "hours":
                $time = $units * 360;
                break;
            case "minutes":
                $time = $units * 60;
                break;
            case 'seconds':
            default:
                $time = $units;
                break;
                
        }

        $taskParams = [
            'statusCode'    => TO_RELAUNCH,
            'statusMessage' => 'Completed. '.$submessage,
            'retry'         => $time,
        ];

        //TODO: Implement the updated time for the new launching moment
        return $taskParams;

    }

    function setCompleted(STRING $submessage=NULL, STRING $resultCode=NULL){
        global $app;
        $submessage = is_null($submessage) ? '': $submessage;
        $resultCode = is_null($resultCode) ? '': $resultCode;

        $taskParams = [
            'statusCode'    => COMPLETED,
            'statusMessage' => 'Completed. '.$submessage,
            'resultCode'    => $resultCode,
        ];

        /** @var $task \PaloAltoNetworks\MTJobs\Tasks\Task */
        if (!($task = $app->task->where('id', $this->params['taskId'])->first())) {
            //Log there was a problem
            return;
        }
        $task->update($taskParams);

        if (!$job = $task->job){
            //Log there was a problem finding the job
            echo "Job not found\n";
            return;
        }

        $this->notifyCompletedTaskJob($job);
    }

    function increaseFailed(){
        global $app;
        if (!($task = $app->task->where('id', $this->params['taskId'])->first())) {
            //Log there was a problem
            return;
        }
        if (!$job = $task->job){
            //Log there was a problem finding the job
            echo "Job not found\n";
            return;
        }
        $this->notifyFailedTaskJob($job);
    }

    function increaseCompleted(){
        global $app;
        if (!($task = $app->task->where('id', $this->params['taskId'])->first())) {
            //Log there was a problem
            return;
        }
        if (!$job = $task->job){
            //Log there was a problem finding the job
            echo "Job not found\n";
            return;
        }
        $this->notifyCompletedTaskJob($job);
    }

    function updateTaskStatus(STRING $submessage=NULL,STRING $resultCode=NULL, STRING $percentage, BOOL $correct){
        global $app;
        $submessage = is_null($submessage) ? '': $submessage;
        $resultCode = is_null($resultCode) ? '': $resultCode;
        if($correct){
            if($percentage=='1.00') {
                $taskParams = [
                    'statusCode' => COMPLETED,
                    'statusMessage' => 'Completed. ' . $submessage,
                    'resultCode' => $resultCode,
                ];
            }
            else{
                $taskParams = [
                    'statusMessage' => $submessage,
                    'resultCode' => $resultCode,
                ];
            }
        }
        else{
            $taskParams = [
                'statusCode' => FAILED,
                'statusMessage' => 'Failed. ' . $submessage,
                'resultCode' => $resultCode,
            ];
        }

        /** @var $task \PaloAltoNetworks\MTJobs\Tasks\Task */
        if (!($task = $app->task->where('id', $this->params['taskId'])->first())) {
            //Log there was a problem
            return;
        }
        $task->update($taskParams);

        if (!$job = $task->job){
            //Log there was a problem finding the job
            echo "Job not found\n";
            return;
        }
        else{
            if($correct) {
                $jobParams = [
                    'completed' => $percentage,
                ];
            }
            else{
                $jobParams = [
                    'completed' => $percentage,
                    'failed'    => $percentage
                ];
            }
            $job->update($jobParams);

        }
    }

    function setCompletedSilent(STRING $submessage=NULL, STRING $resultCode=NULL){
        global $app;
        $submessage = is_null($submessage) ? '': $submessage;
        $resultCode = is_null($resultCode) ? '': $resultCode;

        $taskParams = [
            'statusCode'    => COMPLETED,
            'statusMessage' => 'Completed. '.$submessage,
            'resultCode'    => $resultCode,
        ];

        /** @var $task \PaloAltoNetworks\MTJobs\Tasks\Task */
        if (!($task = $app->task->where('id', $this->params['taskId'])->first())) {
            //Log there was a problem
            return;
        }
        $task->update($taskParams);

        if (!$job = $task->job){
            //Log there was a problem finding the job
            echo "Job not found\n";
            return;
        }
    }

    function setFailed(STRING $submessage=NULL, STRING $resultCode=NULL){
        global $app;
        $submessage = is_null($submessage) ? '': $submessage;
        $resultCode = is_null($resultCode) ? '': $resultCode;
        $taskParams = [
            'statusCode'    => FAILED,
            'statusMessage' => 'Completed. '.$submessage,
            'resultCode'    => $resultCode,
        ];

        /** @var $task \PaloAltoNetworks\MTJobs\Tasks\Task */
        if (!($task = $app->task->where('id', $this->params['taskId'])->first())) {
            //Log there was a problem
            return;
        }
        $task->update($taskParams);

        if (!$job = $task->job){
            //Log there was a problem finding the job
            echo "Job not found\n";
            return;
        }

        $this->notifyFailedTaskJob($job);
    }

    function setFailedSilent(STRING $submessage=NULL, STRING $resultCode=NULL){
        global $app;
        $submessage = is_null($submessage) ? '': $submessage;
        $resultCode = is_null($resultCode) ? '': $resultCode;

        $taskParams = [
            'statusCode'    => FAILED,
            'statusMessage' => 'Completed. '.$submessage,
            'resultCode'    => $resultCode,
        ];

        /** @var $task \PaloAltoNetworks\MTJobs\Tasks\Task */
        if (!($task = $app->task->where('id', $this->params['taskId'])->first())) {
            //Log there was a problem
            return;
        }
        $task->update($taskParams);

        if (!$job = $task->job){
            //Log there was a problem finding the job
            echo "Job not found\n";
            return;
        }
    }

    function notifyCompletedTaskJob($job){
        global $app;
        /** @var $job \PaloAltoNetworks\MTJobs\Jobs\Job */
        /** @var $parentJob \PaloAltoNetworks\MTJobs\Jobs\Job */

        $jobParams = [
            'completed' => $job->completed +1,
        ];
        $job->update($jobParams);

        if($job->parentJob != ''){
            $parentJob = $app->job->where('id',$job->parentJob)->get()->first();
            $parentJobParams = [
                'completed' => $parentJob->completed +1,
            ];
            $parentJob->update($parentJobParams);
        }
    }

    function notifyFailedTaskJob($job){
        global $app;
        /** @var $job \PaloAltoNetworks\MTJobs\Jobs\Job */
        /** @var $parentJob \PaloAltoNetworks\MTJobs\Jobs\Job */

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