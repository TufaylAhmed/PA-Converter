<?php
/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: $today.year.hour.minute
 ******************************************************************************/

namespace PaloAltoNetworks\HealthCheck;

use PaloAltoNetworks\MTJobs\Tasks\Task;

require_once INC_ROOT.'/libs/PaloAltoNetworks/HealthCheck/HealthCheck.php';

require_once INC_ROOT.'/libs/definitions/taskDefinitions.php';

require_once INC_ROOT.'/libs/projectdb.php';



class MisreportedCompletedTasksCheck extends HealthCheck
{

    public function getDescription(): string
    {
        return "Verify that there are no misreported completed/failed tasks";
    }

    public function getCategory(): string
    {
        return "Expedition Status";
    }

    public function check(): CheckResponse
    {
        global $app;

        $taskMessages = array();
        $remediationMessages = array();


//        if($unfinishedTasks = $app->container->task->whereIn('statusCode',[PENDING,TO_RELAUNCH,STARTED])->get(["id","processCode","updated_at","statusMessage","retry","pid"])){
////            print_r($unfinishedTasks);
//        }

        $oneMonthAgo = date("Y-m-d H:i:s", strtotime(  date("Y-m-d") . "-1 months" ) );
        $oldUnfinishedTasks = $app->task
            ->whereIn('statusCode',[PENDING,TO_RELAUNCH,STARTED])
            ->where('updated_at','<',$oneMonthAgo)
            ->get(["id","processCode","updated_at","statusMessage","retry","pid"]);

        $numOldUnfinishedTasks = count($oldUnfinishedTasks);
        if($numOldUnfinishedTasks > 0) {
            $taskMessages[] = "$numOldUnfinishedTasks pending tasks older than 1 month.";
            $remediationMessages[] = "<i>(Assisted)</i> Cancel pending tasks older than 1 month.";
        }

        $misreportedJobs = array();
        if($jobs= $app->job->whereRaw('completed < tasks')->get(["id","completed","tasks","failed"])){
            //Check that the device exist
            foreach ($jobs as $job){
                $evaluatingJobs=array();
                $jobID = $job->id;
                $evaluatingJobs[]=$jobID;
                //Get all the child Jobs
                if($subJobs= $app->job->where('parentJob', $jobID)->get(["id","completed","tasks","failed"])) {
                    foreach ($subJobs as $subJob) {
                        $evaluatingJobs[]=$subJob->id;
                    }
                }

                if($tasks = $app->task->whereIn('job_id', $evaluatingJobs)->whereNotIn('statusCode',[PENDING,TO_RELAUNCH,STARTED])->get(["id","statusCode","job_id"])){
                    foreach ($tasks as $task){
                        $misreportedJobs[] = $task->job_id;
                    }
                }
            }
        }

        $misreportedJobs = array_unique($misreportedJobs);
        $nummisreportedTasks = count($misreportedJobs);
        if($nummisreportedTasks >0){
            if($nummisreportedTasks == 1)
                $taskMessages[] = "$nummisreportedTasks 'incomplete' job that is actually complete.";
            else
                $taskMessages[] = "$nummisreportedTasks 'incomplete' job(s) that are actually complete.";
            $remediationMessages[] = "<i>(Assisted)</i> Set the tasks as completed.";

        }

        $code = 0;
        $msg = 'No misreported tasks';
        $remediation = 'N/A';
        $success = count($taskMessages)==0?true:false;
        if(!$success){
            $code = -1;
            $msg = implode("<br>", $taskMessages);
            $remediation = implode("<br>", $remediationMessages);
        }

        $response = new CheckResponse($this,$success,$code, $msg, $remediation);
        return $response;
    }

    public function repair(): CheckResponse
    {
        global $app;

        $taskMessages = array();
        $remediationMessages = array();

        $oneMonthAgo = date("Y-m-d H:i:s", strtotime(  date("Y-m-d") . "-1 months" ) );
        /* @var $oldUnfinishedTasks Task*/
        if($oldUnfinishedTasks = $app->task
            ->whereIn('statusCode',[PENDING,TO_RELAUNCH,STARTED])
            ->where('updated_at','<',$oneMonthAgo)
            ){
            $params = [
                'statusCode' => CANCELLED
            ];
            $oldUnfinishedTasks->update($params);
        }

        $misreportedJobs = array();
        if($jobs= $app->job->whereRaw('completed < tasks')->get(["id","completed","tasks","failed"])){
            //Check that the device exist
            foreach ($jobs as $job){
                $evaluatingJobs=array();
                $jobID = $job->id;
                $evaluatingJobs[]=$jobID;
                //Get all the child Jobs
                if($subJobs= $app->job->where('parentJob', $jobID)->get(["id","completed","tasks","failed"])) {
                    foreach ($subJobs as $subJob) {
                        $evaluatingJobs[]=$subJob->id;
                    }
                }

                if($tasks = $app->task->whereIn('job_id', $evaluatingJobs)->whereNotIn('statusCode',[PENDING,TO_RELAUNCH,STARTED])->get(["id","statusCode","job_id"])){
                    foreach ($tasks as $task){
                        $misreportedJobs[] = $task->job_id;
                    }
                }
            }
        }

        //Fixing the jobs that do not have Pending tasks directly assigned
        $misreportedJobs = array_unique($misreportedJobs);
        $nummisreportedJobs = count($misreportedJobs);
        if($nummisreportedJobs >0){
            $query = "UPDATE jobs set completed=tasks WHERE id in (".implode(",", $misreportedJobs).")";
            $pandbRBAC = selectDatabase('pandbRBAC');
            $pandbRBAC->query($query);
            if($nummisreportedJobs == 1)
                $taskMessages[] = "$nummisreportedJobs 'incomplete' task that is actually complete.";
            else
                $taskMessages[] = "$nummisreportedJobs 'incomplete' task(s) that are actually complete.";
            $remediationMessages[] = "<i>(Assisted)</i> Set the tasks as completed.";
        }

        //Now we should check if there are parentJobs that need to be fixed
        $misreportedJobs=array();
        if($jobs = $app->job->selectRaw("jobs.*, if(childJobs.completed=childJobs.tasks,1,0 ) as toFix")
            ->leftJoin('pandbRBAC.jobs as childJobs','childJobs.parentJob','=','jobs.id')
            ->whereRaw('jobs.completed < jobs.tasks')
            ->whereNull('jobs.parentJob')
            ->having('toFix',1)
            ->get(['id']) ){
            foreach ($jobs as $job){
                $misreportedJobs[] = $job->id;
            }
        }

        $misreportedJobs = array_unique($misreportedJobs);
        $nummisreportedJobs = count($misreportedJobs);
        if($nummisreportedJobs >0) {
            $query = "UPDATE jobs set completed=tasks WHERE id in (" . implode(",", $misreportedJobs) . ")";
            echo $query;
            $pandbRBAC = selectDatabase('pandbRBAC');
            $pandbRBAC->query($query);
        }


        $code = 0;
        $msg = 'No misreported tasks';
        $remediation = 'N/A';
        $success = count($taskMessages)==0?true:false;
        if(!$success){
            $code = -1;
            $msg = implode("<br>", $taskMessages);
            $remediation = implode("<br>", $remediationMessages);
        }

        $response = new CheckResponse($this,$success,$code, $msg, $remediation);
        return $response;
    }


}