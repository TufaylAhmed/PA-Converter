<?php
/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: $today.year.hour.minute
 ******************************************************************************/

namespace PaloAltoNetworks\Expedition\Jobs;

require_once INC_ROOT.'/libs/database.php';
require_once INC_ROOT.'/libs/projectdb.php';
require_once INC_ROOT.'/libs/definitions/taskDefinitions.php';

require_once INC_ROOT.'/bin/jobs/Job.php';


class JobsController
{
    private $days;

    protected $queryNumberOfPendingJobs = "select count(distinct job_id) as number from tasks where  (statusCode =".PENDING." or statusCode=".TO_RELAUNCH.")";
    protected $queryNumberOfFailedJobs = "select count(distinct job_id) as number from tasks where  (statusCode =".FAILED." or statusCode=".TO_RELAUNCH.")";
    protected $queryNumberOfCompletedJobs = "select count(*) as number from jobs where  completed = tasks and description not like 'Bundle %' and failed = 0 ";
    protected $queryNumberOfJobs = "select count(*) as number from jobs where description not like 'Bundle %'";

    protected $queryHistoCompleted = "select 'completed' as status, count(*) as total, date(updated_at) as timeframe            
             from jobs 
             where  completed = tasks and description not like 'Bundle %' and failed = 0 and 
             updated_at between '__start' and now() 
             group by timeframe";

    protected $queryHistoFailed = "select 'failed' as status, count(*) as total, date(updated_at) as timeframe 
             from jobs 
             where  completed = tasks and description not like 'Bundle %' and failed != 0 and
             updated_at between '__start' and now() 
             group by timeframe";

    protected $queryHistoPending = "select 'pending' as status, count(*) as total, date(updated_at) as timeframe 
             from jobs 
             where  completed < tasks and description not like 'Bundle %' and
             updated_at between '__start' and now() 
             group by timeframe";

    public function __construct(INT $limit=7)
    {
        $this->days = $limit;
    }

    public function getJobsInfo(STRING $mode, $page=1, $limit=25){
        global $app;
        $message = array();
        $message['msg']['statistics']['pending'] = $this->getNumberOfPendingJobs();
        $message['msg']['statistics']['failed'] = $this->getNumberOfFailedJobs();
        $message['msg']['statistics']['completed'] = $this->getNumberOfCompletedJobs();
        $message['msg']['statistics']['all'] = $this->getNumberOfJobs();

        switch ($mode) {
            case "failed":
                $failedJobs = $this->getFailedTasks();
                if (!$jobs = $app->job
                    ->whereIn('id', $failedJobs)
                    ->orderBy('id','desc')
                    ->select('*')
                    ->selectRaw('completed/tasks as state')
                    ->simplePaginate($limit, ['*'],'',$page)) {
                    $message = array();
                    $message['code'] = false;
                    $message['msg'] = ['job-id' => 'No job',];
                    return $message;
                }
                $message['count'] = $message['msg']['statistics']['failed'];
                break;


            case "pending":
                $pendingJobs = $this->getPendingTasks();
                if (!$jobs = $app->job
                    ->whereIn('id', $pendingJobs)
                    ->orderBy('id','desc')
                    ->select('*')
                    ->selectRaw('completed/tasks as state')
                    ->simplePaginate($limit, ['*'],'',$page)) {
                    $message = array();
                    $message['code'] = false;
                    $message['msg'] = ['job-id' => 'No job',];
                    return $message;
                }
                $message['count'] = $message['msg']['statistics']['pending'];
                break;


            case 'all':
                if (!$jobs = $app->job
                    ->where('description','not like','Bundle %')
                    ->orderBy('id','desc')
                    ->select('*')
                    ->selectRaw('completed/tasks as state')
                    ->simplePaginate($limit, ['*'],'',$page)) {
                    $message = array();
                    $message['code'] = false;
                    $message['msg'] = ['job-id' => 'No job',];
                    return $message;
                }
                $message['count'] = $message['msg']['statistics']['all'];
                break;

            case "completed":
            default:
                $failedJobs = $this->getFailedTasks();
                if (!$jobs = $app->job
                    ->whereColumn('completed', '=', 'tasks')
                    ->whereNotIn('id', $failedJobs)
                    ->where('description','not like','Bundle %')
                    ->orderBy('id','desc')
                    ->select('*')
                    ->selectRaw('completed/tasks as state')
                    ->simplePaginate($limit, ['*'],'',$page)) {
                    $message = array();
                    $message['code'] = false;
                    $message['msg'] = ['job-id' => 'No job',];
                    return $message;
                }
                $message['count'] = $message['msg']['statistics']['completed'];
                break;
        }

        $message['code'] = true;
        $message['msg']['jobs'] = $jobs;

        return $message;
    }

    public function getJobsHistogram(){
        $pandbRBAC = selectDatabase('pandbRBAC');
        $histogram = array();

        # Init the histogram
        $start = $day = strtotime("-".$this->days." days");
        $end = strtotime('tomorrow');
        while($day <= $end)
        {
            $date = date('Y-m-d', $day);
            $histogram["$date"]['completed']=0;
            $histogram["$date"]['failed']=0;
            $histogram["$date"]['pending']=0;
            $histogram["$date"]['weekday']=date('D', $day);
            $day = strtotime("+1 day", $day);
        }


        $start= date('Y-m-d',$start);

        $competedQuery = str_replace('__start',$start,$this->queryHistoCompleted);
        $result = $pandbRBAC->query($competedQuery);
        if($result->num_rows>0){
            while($data = $result->fetch_assoc()){
                $histogram[$data['timeframe']]['completed'] = $data['total'];
            }
        }

        $competedFailed = str_replace('__start',$start,$this->queryHistoFailed);
        $result = $pandbRBAC->query($competedFailed);
        if($result->num_rows>0){
            while($data = $result->fetch_assoc()){
                $histogram[$data['timeframe']]['failed'] = $data['total'];
            }
        }
        $competedPending = str_replace('__start',$start,$this->queryHistoPending);
        $result = $pandbRBAC->query($competedPending);
        if($result->num_rows>0){
            while($data = $result->fetch_assoc()){
                $histogram[$data['timeframe']]['pending'] = $data['total'];
            }
        }

        $rawData = array();
        foreach ($histogram as $day=>$dayValues){
            $rawData[] = [
                'day' => $day,
                'weekday' => $dayValues['weekday'],
                'completed' => $dayValues['completed'],
                'failed' => $dayValues['failed'],
                'pending' => $dayValues['pending'],

            ];
        }

        $msg = [
            'code' => true,
            'msg' => $rawData
        ];
        return $msg;
    }

    public function getFailedTasks(){
        global $app;

        $failedTasks = $app->task
            ->where('statusCode',FAILED)
            ->orWhere('statusCode', TO_RELAUNCH)
            ->get(['job_id']);
        return $failedTasks;
    }

    public function getPendingTasks(){
        global $app;

        $pendingTasks = $app->task
//            ->where('taskName','not like','Spark: %')
            ->where('statusCode',PENDING)
            ->orWhere('statusCode', TO_RELAUNCH)
            ->orWhere('statusCode', STARTED)
            ->get(['job_id']);
        return $pendingTasks;
    }

    public function getNumberOfPendingJobs(){
        return $this->getNumberOf($this->queryNumberOfPendingJobs);
    }

    public function getNumberOfFailedJobs(){
        return $this->getNumberOf($this->queryNumberOfFailedJobs);
    }

    public function getNumberOfCompletedJobs(){
        return $this->getNumberOf($this->queryNumberOfCompletedJobs);
    }

    public function getNumberOfJobs(){
        return $this->getNumberOf($this->queryNumberOfJobs);
    }

    private function getNumberOf(STRING $query){
        $pandbRBAC = selectDatabase('pandbRBAC');
        $data = $pandbRBAC->query($query);
        $row = $data->fetch_assoc();
        return $row['number'];
    }

    public function deleteJob(INT $job_id){
        $job = new Job($job_id);
        return $job->delete();
    }
}