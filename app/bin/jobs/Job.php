<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 15/6/16 - 15:26
 */

namespace PaloAltoNetworks\Expedition\Jobs;

//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

//User management control
require_once INC_ROOT.'/userManager/start.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/libs/projectdb.php';


class Job{

    protected $jobID;

    public function __construct($jobID)
    {
        $this->jobID = $jobID;
    }

    function getJobStatus(STRING $mode){
        global $app;

        if ($this->jobID == ''){
            //All the jobs
            if(!accessControl("any", ['project.create','project.admin'])){
                $message = array();
                $message['code'] = false;
                $message['msg'] = 'Your account does not have the rights to see pending Jobs';
                return $message;
            }

            switch ($mode){
                case 'allSummary':
                    if(!$jobs = $app->job->get()){
                        $message = array();
                        $message['code'] = false;
                        $message['msg'] = 'No pending jobs';
                        return $message;
                    }
                    $message = array();
                    $message['code'] = true;
                    $message['msg'] = $jobs;
                    break;
                case "all":
                    $jobsArray = array();
                    if(!$jobs = $app->job->get(['id','completed','tasks'])){
                        $message = array();
                        $message['code'] = false;
                        $message['msg'] = 'No pending jobs';
                        return $message;
                    }
                    $message = array();
                    $message['code'] = true;
                    foreach ($jobs as $job){
                        $job = new Job($job->id);
                        $status = $job->getJobStatus('');
                        $jobsArray[] =  $status['msg'];
                    }
                    $message['msg'] = $jobsArray;
                    break;
                case "completeSummary":
                    if(!$jobs = $app->job->whereColumn('completed','>=','tasks')->get()){
                        $message = array();
                        $message['code'] = false;
                        $message['msg'] = 'No pending jobs';
                        return $message;
                    }
                    $message = array();
                    $message['code'] = true;
                    $message['msg'] = $jobs;
                    break;
                case "complete":
                    $jobsArray = array();
                    if(!$jobs = $app->job->whereColumn('completed','>=','tasks')->get(['id','completed','tasks'])){
                        $message = array();
                        $message['code'] = false;
                        $message['msg'] = 'No pending jobs';
                        return $message;
                    }
                    $message = array();
                    $message['code'] = true;
                    foreach ($jobs as $job){
                        $job = new Job($job->id);
                        $status = $job->getJobStatus('');
                        $jobsArray[] =  $status['msg'];
                    }
                    $message['msg'] = $jobsArray;
                    break;
                case "cancelledSummary":
                    if(!$jobs = $app->job->where('tasks','0')->get()){
                        $message = array();
                        $message['code'] = false;
                        $message['msg'] = 'No pending jobs';
                        return $message;
                    }
                    $message = array();
                    $message['code'] = true;
                    $message['msg'] = $jobs;
                    break;
                case "cancelled":
                    $jobsArray = array();
                    if(!$jobs = $app->job->where('tasks','0')->get(['id','completed','tasks'])){
                        $message = array();
                        $message['code'] = false;
                        $message['msg'] = 'No pending jobs';
                        return $message;
                    }
                    $message = array();
                    $message['code'] = true;
                    foreach ($jobs as $job){
                        $job = new Job($job->id);
                        $status = $job->getJobStatus('');
                        $jobsArray[] =  $status['msg'];
                    }
                    $message['msg'] = $jobsArray;
                    break;
                case "pendingSummary":
                    if(!$jobs = $app->job->whereColumn('completed','<','tasks')->get()){
                        $message = array();
                        $message['code'] = false;
                        $message['msg'] = 'No pending jobs';
                        return $message;
                    }
                    $message = array();
                    $message['code'] = true;
                    $message['msg'] = $jobs;
                    break;
                case "pending":
                    $jobsArray = array();
                    if(!$jobs = $app->job->whereColumn('completed','<','tasks')->get(['id','completed','tasks'])){
                        $message = array();
                        $message['code'] = false;
                        $message['msg'] = 'No pending jobs';
                        return $message;
                    }
                    $message = array();
                    $message['code'] = true;
                    foreach ($jobs as $job){
                        $job = new Job($job->id);
                        $status = $job->getJobStatus('');
                        $jobsArray[] =  $status['msg'];
                    }
                    $message['msg'] = $jobsArray;
                    break;

                default:
                    $message = array();
                    $message['code'] = true;
                    $message['msg'] = '';
                    break;
            }
            return $message;
        }

        if(!$job = $app->job->where('id', $this->jobID)->first()){
            $message = array();
            $message['code'] = false;
            $message['msg'] = 'Job does not exist';
            return $message;
        }

        $message = array();
        $message['code'] = false;
        $message['msg'] = '';
        switch($mode){
            case "":
                $message['code'] = true;
                $msg = array();
                $msg['job-id'] = $this->jobID;
                if( $job->tasks == 0){
                    $state = 1;
                    $msg['state'] = $state;
                    $msg['JobMsg'] = [
                        'job_id'            => $this->jobID,
                        'statusCode'        => 1,
                        'statusMessage'     => 'Cancelled',
                        'feedback'          => array(),
                    ];
                }
                else {
                    $state = ($job->completed / $job->tasks);
                    $msg['state'] = $state;
//                    if ($state == 1){
                        $msg['JobMsg'] = $this->getJobInfoStatus();
//                        $msg['JobMsg']['statusMessage'] = ($job->failed==0)?'Completed': 'Failed';
                        $msg['JobMsg']['statusCode'] = $state;
                        if($state == 1){
                            $msg['JobMsg']['statusMessage'] = ($job->failed==0)?'Completed': 'Failed';
                        }
//                        $msg['JobMsg'] = [
//                            'job_id'            => $this->jobID,
//                            'statusCode'        => 1,
//                            'statusMessage'     => ($job->failed==0)?'Completed': 'Failed',
//                            'feedback'          => $this->getJobInfoStatus()
//                            //'feedback'          => isset($job->feedback)?$job->feedback:''
//                        ];
//                    }
//                    else {
//                        $msg['JobMsg'] = $this->getJobInfoStatus();
//                    }
                }
                $message['msg'] = $msg;
                break;

            case "complete":
                $message['code'] = true;
                $msg = array();
                if( $job->tasks == 0){
                    $state = 1;
                }
                else {
                    $state = ($job->completed / $job->tasks);
                }
                $msg['state'] = $state;
                if ($state == 1){
                    $msg['JobMsg'] = [
                        'job_id'            => $this->jobID,
                        'statusCode'        => 1,
                        'statusMessage'     => 'Completed'
                    ];
                }
                else {
                    $msg['JobMsg'] = $this->getJobInfoStatus($this->jobID);
                }
                $msg['TotalTasks'] = $this->getNumberOfTasksInJob($this->jobID);
                $msg['TasksMsg'] = $this->getTasksInJobStatus($this->jobID);
                $message['msg'] = $msg;
                break;

            case "summary":
                $message['code'] = true;
                if( $job->tasks == 0){
                    $state = 1;
                }
                else {
                    $state = ($job->completed / $job->tasks);
                }
                $msg['state'] = $state;
                $message['msg'] = $msg;
                break;
        }

        return $message;
    }

    function getJobInfoStatus(){
        global $app;
        $pandbRBAC = selectDatabase('pandbRBAC');

        if(!$job = $app->job->where('id', $this->jobID)->get()->first()){
            return 'Job not found';
        }

        //Check if this is a ParentJob or not
        $subJobs = $job->jobs()->get();
        if(count($subJobs) >0){
            //Update the number of completed and failed tasks
            $completed = 0;
            $failed = 0;
            foreach ($subJobs as $subJob){
                $completed += $subJob->completed;
                $failed    += $subJob->failed;
            }
            $query ="UPDATE jobs SET completed=least($completed, tasks), failed=least($failed, tasks) WHERE id='$this->jobID'";
            $pandbRBAC->query($query);

            foreach ($subJobs as $subJob){
                //If this is not a parentJob, check the
                if($task = $subJob->tasks()->where('statusCode','!=', '1')->first()){
                    if ($task = $job->tasks()->where('statusCode', '=', '1')->get()->last())
                        return $task->print();
                    else
                        return "";
                }
            }
            return "";
        }
        else { //This is a job without subjobs
            if (!$task = $job->tasks()->where('statusCode', '!=', '1')->first()) {
                //There is no unfinished task in this job
                if ($task = $job->tasks()->where('statusCode', '=', '1')->get()->last())
                    return $task->print();
                else
                    return '';
            }
        }

        if(isset($task->pid)){
            //Verify that the pid is running
            $taskName = $task->taskName;

            //Check if this task is being executed localy or on the remote ML server
            if(substr( $taskName, 0, 5 ) === "Spark"){
                //This is a process executed in the ML server
                require_once INC_ROOT.'/libs/settings/ML_Settings.php';
                $mlSettings = new \ML_Settings($pandbRBAC);
                $message = $mlSettings->get();
                $mlParams_arr = $message['msg'];
                $ExpeditionML = count($mlParams_arr)>0 ? $mlParams_arr[0]['server']: $_SERVER['SERVER_ADDR'];

                $curlParams = [
                    'pid'   => $task->pid
                ];
                $tuCurl = curl_init();
                $url = "https://$ExpeditionML/API/process/checkPidStatus.php";

                curl_setopt($tuCurl, CURLOPT_URL, $url);
                curl_setopt($tuCurl, CURLOPT_POST, 1);
                curl_setopt($tuCurl, CURLOPT_POSTFIELDS, http_build_query($curlParams));
                curl_setopt($tuCurl, CURLOPT_RETURNTRANSFER, true);
                curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, 0);
                curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, 0);

                $response = curl_exec($tuCurl);
                $responseJson = json_decode($response);
                curl_close($tuCurl);
                $isRunning = $responseJson->isRunning? true: false;
            }
            else{
                //This is a local process
                if (file_exists( "/proc/".$task->pid )){
                    $isRunning = true;
                }
                else{
                    $isRunning = false;
                }
            }

            if(!$isRunning){
                $params = [
                    'completed' => ($job->completed+1)>$job->tasks?$job->tasks:$job->completed+1,
                    'failed'    => ($job->failed   +1)>$job->tasks?$job->tasks:$job->failed+1,
                ];
                $job->update($params);

                //Check parent job if existing
                if ($parentJob = $app->job->where('id', $job->parentJob)->get()->first()){
                    $params = [
                        'completed' => ($parentJob->completed+1)>$parentJob->tasks?$parentJob->tasks:$parentJob->completed+1,
                        'failed'    => ($parentJob->failed   +1)>$parentJob->tasks?$parentJob->tasks:$parentJob->failed+1,
                    ];
                    $parentJob->update($params);
                }

                $params = [
                    'resultCode'    => -1,
                    'statusCode'    => -1,
                    'statusMessage' => 'Process failed'
                ];
                $task->update($params);
            }
        }

        return $task->print();
    }

    function getNumberOfTasksInJob(){
        global $app;

        if(!$job = $app->job->where('id', $this->jobID)->first()){
            return '0';
        }

        if(!$tasks = $job->tasks()->get()){
            return '0';
        }

        return count($tasks);
    }

    function getTasksInJobStatus(){
        global $app;

        if(!$job = $app->job->where('id', $this->jobID)->first()){
            return '';
        }

        if(!$tasks = $job->tasks()->orderBy('id')->get()){
            return '';
        }

        return $tasks;

    }

    function delete(){
        global $app;


        if(!$job = $app->job->where('id', $this->jobID)->first()){
            $message = array();
            $message['code'] = false;
            $message['msg'] = 'Job '.$this->jobID.' does not exist';
            return $message;
        }

        //Get all the tasks under this job
        $taskParams = [
            'statusCode'    => -1,
            'statusMessage' => 'Cancelled'
        ];

        //Update the tasks under this job
        $tasks = $job->tasks()->get();
        foreach ($tasks as $task){
            $task->update($taskParams);
        }

        //Update the status of this job
        $failed = $job->failed;
        $cancelled = $job->tasks -  ($job->completed + $job->failed);
        $jobParams = [
            'failed' => $failed + $cancelled,
            'completed' => $job->tasks
        ];
        $job->update($jobParams);

        //Update my parent Status
        if($parentJob = $app->job->where('id', $job->parentJob)->first()){
            $parentJobParams = [
                'failed' => $parentJob->failed + $cancelled,
                'completed' => $parentJob->completed + $cancelled,
            ];
            $parentJob->update($parentJobParams);
        }

        $message = array();
        $message['code'] = true;
        $message['msg'] = "Pending tasks in Job have been cancelled";
        return $message;
    }

}


