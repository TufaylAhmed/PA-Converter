<?php
/*******************************************************************************
 * Copyright (c) 2019 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 ******************************************************************************/

class TaskUpdater{
    /***
     * @var string
     */
    private $serverIP;
    private $user;
    private $password;

    /***
     * @var int
     */
    private $serverPort;
    private $taskId;

    public function __construct(int $taskID, String $serverIP, String $user, String $passw, int $port)
    {
        $this->taskId = $taskID;
        $this->serverIP = $serverIP;
        $this->user = $user;
        $this->password = $passw;
        $this->serverPort = $port;
    }

    private function safeUpdateTaskPid(int $pid, string $message=null): bool{
        $connection = new mysqli($this->serverIP, $this->user, $this->password, 'pandbRBAC', $this->serverPort);
        if($connection->connect_error){
            return false;
        }
        $query = "UPDATE tasks set pid='$pid', statusMessage='$message' WHERE id='$this->taskId'";
        $result = $connection->query($query);
        $connection->close();  //Close the SQL connection to avoid memory leaks
        return $result;
    }

    private function safeReportFailedTask(string $message):bool
    {
        $connection = new mysqli($this->serverIP, $this->user, $this->password, 'pandbRBAC', $this->serverPort);
        if ($connection->connect_error) {
            return false;
        }
        $query = "UPDATE tasks set statusCode=-1, statusMessage='$message' WHERE id='$this->taskId'";
        $result = $connection->query($query);

        if ($result == true) {
            //Check job_id
            $query = "UPDATE jobs set completed=completed+1, failed=failed+1 WHERE id=(select job_id FROM tasks where id='$this->taskId')";
            $result = $connection->query($query);
        }
        $connection->close();  //Close the SQL connection to avoid memory leaks
        return $result;
    }


    public function updateTaskPid(int $pid, string $message=null, int $attempts=5):bool {
        $succedded = false;

        while(!$succedded && $attempts>0){
            $attempts--;
            $succedded = $this->safeUpdateTaskPid($pid, $message);
        }

        return $succedded;
    }

    public function reportFailedTask(string $message=null, int $attempts=5){
        $succedded = false;

        while(!$succedded && $attempts>0){
            $attempts--;
            $succedded = $this->safeReportFailedTask($message);
        }

        return $succedded;
    }
}