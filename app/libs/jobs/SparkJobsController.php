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


class SparkJobsController extends JobsController
{
    protected $queryNumberOfPendingJobs = "select count(distinct job_id) as number 
            from tasks 
            where  (statusCode =".PENDING." or statusCode=".TO_RELAUNCH.")
            and taskName LIKE 'Spark: %'";

    protected $queryNumberOfFailedJobs = "select count(distinct job_id) as number 
            from tasks 
            where  (statusCode =".FAILED." or statusCode=".TO_RELAUNCH.")
            and taskName LIKE 'Spark: %'";

    protected $queryNumberOfCompletedJobs = "select count(*) as number 
            from jobs 
            where  completed = tasks and description not like 'Bundle %' and failed = 0 
            and description LIKE 'Spark: %'";

    protected $queryNumberOfJobs = "select count(*) as number 
            from jobs 
            where description not like 'Bundle %'
            and description LIKE 'Spark: %'";


    protected $queryHistoCompleted = "select 'completed' as status, count(*) as total, date(updated_at) as timeframe            
             from jobs 
             where  completed = tasks and description not like 'Bundle %' and failed = 0 and 
             updated_at between '__start' and now() 
             and description LIKE 'Spark: %'
             group by timeframe";

    protected $queryHistoFailed = "select 'failed' as status, count(*) as total, date(updated_at) as timeframe 
             from jobs 
             where  completed = tasks and description not like 'Bundle %' and failed != 0 and
             updated_at between '__start' and now() 
             and description LIKE 'Spark: %'
             group by timeframe";

    protected $queryHistoPending = "select 'pending' as status, count(*) as total, date(updated_at) as timeframe 
             from jobs 
             where  completed < tasks and description not like 'Bundle %' and
             updated_at between '__start' and now() 
             and description LIKE 'Spark: %'
             group by timeframe";


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
                    ->where('description','like','Spark: %')
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
                    ->where('description','like','Spark: %')
                    ->whereIn('id', $pendingJobs)
                    ->orderBy('id','desc')
                    ->select('*')
                    ->selectRaw('completed/tasks as state')
                    ->simplePaginate($limit, ['*'],'',$page)
                ) {
                    $message = array();
                    $message['code'] = false;
                    $message['msg'] = ['job-id' => 'No job',];
                    return $message;
                }
                $message['count'] = $message['msg']['statistics']['pending'];
                break;


            case 'all':
                if (!$jobs = $app->job
                    ->where('description','like','Spark: %')
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
                    ->where('description','like','Spark: %')
                    ->whereColumn('completed', '=', 'tasks')
                    ->whereNotIn('id', $failedJobs)
                    ->where('description','not like','Bundle %')
                    ->orderBy('id','desc')
                    ->select('*')
                    ->selectRaw('completed/tasks as state')
                    ->simplePaginate($limit, ['*'],'',$page)
                ){
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

    public function getFailedTasks(){
        global $app;
        $failedTasks = $app->task
            ->where('taskName','like','Spark: %')
            ->where('statusCode',FAILED)
            ->orWhere('statusCode', TO_RELAUNCH)
            ->get(['job_id']);
        return $failedTasks;
    }

    public function getPendingTasks(){
        global $app;
        $failedTasks = $app->task
            ->where('taskName','not like','Spark: %')
            ->where('statusCode',PENDING)
            ->orWhere('statusCode', TO_RELAUNCH)
            ->get(['job_id']);
        return $failedTasks;
    }

    public function deleteJob(INT $job_id){
        $job = new Job($job_id);
        return $job->delete();
    }
}