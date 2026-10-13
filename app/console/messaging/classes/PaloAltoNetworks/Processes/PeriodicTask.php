<?php

namespace PaloAltoNetworks\Processes;

require_once INC_ROOT.'/libs/projectdb.php';

class PeriodicTask
{

    private function registerJob(ARRAY $data, $user, STRING $description, INT $parentJob=null){
        global $app;

        $params = [
            'user_id'       => $user->id,
            'parentType'    => 'Scheduled', //TODO: define the kind of object that it is being processed
            'parentId'      => 0,  //TODO: we do not know here the ID of the potential object that it is being processed. etiher a device, or a job, or...
            'description'   => $description,
            'parentJob'     => $parentJob,
        ];
        if(!$job = $app->job->create($params)){
            return -1;
        }

        return $job->id;
    }

    private function registerTask(ARRAY $data, $user, INT $jobID, STRING $processCode, STRING $processName){
        global $app;

        if(!isset($data['params'])){
            $data['params'] = '';
        }
        $data['userId'] = $user->id;

        $params = [
            'job_id'        => $jobID,
            'taskType'      => 'Scheduled task',
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
            'tasks' => $job->tasks + 1,
        ];
        $job->update($jobParams);

        if($job->parentJob != ''){
            $parentJob = $app->job->where('id', $job->parentJob)->first();
            $parentJobParams = [
                'tasks' => $parentJob->tasks + 1,
            ];
            $parentJob->update($parentJobParams);
        }
        return $task->id;
    }

    public function executePending(){
        require_once INC_ROOT.'/userManager/start_CLI.php';
        global $app;
        foreach (json_decode($this->getPendingTasks()) as $pendingTask){
            $user = $app->container->user->where('id',$pendingTask->sender)->first();

//            print ("Periodic Task ExecutePending: pendingTask ->");
//            print_r($pendingTask);
            /* @var $task \PaloAltoNetworks\MTJobs\Tasks\Task */
            if(!$task = $app->periodicTask->where('id',$pendingTask->periodicTaskId)->first()){
                //For some reason, there was no taskID created for this task. So do not try to process it
                print ("The task #".$pendingTask->periodicTaskId." does not exist");
                return;
            }

            $jobID = $this->registerJob(json_decode($pendingTask->params, true), $user, 'Scheduled Job');
            $pendingTask->params = json_decode($pendingTask->params);
            $pendingTask->params->parentJobID = $jobID;
            $pendingTask->sender=$user;

            $this->flagPendingTaskStarted($pendingTask->periodicTaskId);
            $loader = new ClassLoader($pendingTask);  //This will load the class if not loaded and call the start() method.
//            while(!$task->isCompleted()){
//                sleep(10);
//            }
            $this->flagPendingTaskCompleted($pendingTask->periodicTaskId);
        }
    }

    private function flagPendingTaskStarted(int $taskID){
        $query ="UPDATE pandbRBAC.periodicTasks SET started_at=now() WHERE id='$taskID';";
        $this->updateTask($query);
    }

    private function flagPendingTaskCompleted(int $taskID){
        $query ="UPDATE pandbRBAC.periodicTasks SET completed_at=now() WHERE id='$taskID';";
        $this->updateTask($query);
    }

    private function updateTask(string $query){
        $pandbRBAC = selectDatabase("pandbRBAC");
        $pandbRBAC->query($query);
    }

    private function getPendingTasks(){
        $tasks = array();
        $pandbRBAC = selectDatabase("pandbRBAC");
        $query = '
            SELECT distinct id, processCode, params, createdBy FROM
            (   SELECT  id, processCode, params, createdBy, completed_at, -- Check those scheduled tasks that are to be executed even the last execution became completed less than 24h ago
                        date_add(concat(date(started_at)," ",time(executionTime)), interval 1 day) as next_execution_time 
                FROM pandbRBAC.periodicTasks
                WHERE frequency="daily" AND (started_at <= completed_at OR started_at = "0000-00-00 00:00:00" OR started_at = "")
                HAVING next_execution_time < now()
    
                    UNION
                
                SELECT  id, processCode, params, createdBy, started_at, -- Those daily tasks that have been more than 24h since last execution
                        date_add(concat(date(started_at)," ",time(executionTime)), interval 1 day) as next_execution_time
                FROM pandbRBAC.periodicTasks
                WHERE frequency="daily" 
                --        AND (started_at <= completed_at OR started_at = "0000-00-00 00:00:00" OR started_at = "")
                HAVING hour(timediff(started_at,now()))>24
            ) as jobs;';

        $result = $pandbRBAC->query($query);
        if($result->num_rows>0){
            while($data = $result->fetch_assoc()){
                $task = array();
                $task['proccessCode']   = $data['processCode'];
                $task['params']         = $data['params'];
                $task['sender']         = $data['createdBy'];
                $task['periodicTaskId'] = $data['id'];
//                $params->loggable = (isset($message->loggable))  ? $message->loggable   : false;
//                $params->logPath  = (isset($message->logPath))   ? $message->logPath    : '';
                $tasks[]=$task;
            }
        }

        return json_encode($tasks);
    }
}