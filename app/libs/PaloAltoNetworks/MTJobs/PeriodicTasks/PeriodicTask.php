<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 13/6/16 - 11:38
 */

namespace PaloAltoNetworks\MTJobs\PeriodicTasks;

use Illuminate\Database\Eloquent\Model as Eloquent;

class PeriodicTask extends Eloquent
{
    /**
     * {@inheritDoc}
     */
    protected $table = 'periodicTasks';
    protected $fillable = [
        'id', 'createdBy', 'processCode', 'params', 'description', 'frequency', 'executionTime', 'active', 'created_at', 'updated_at', 'pid', 'started_at', 'completed_at'
    ];



    private function isJson($string) {
        json_decode($string);
        return (json_last_error() == JSON_ERROR_NONE);
    }

    /***
     * @return Task The statusMessage field in the database may be a JSON. If so, get the mainMessage and feedback messages and separate them into two fields
     */
    public function print():PeriodicTask{
        if (! $this->isJson($this->statusMessage)){
            $temp = $this;
            $temp->feedbackList = [$this->statusMessage];
            return $temp;
        }
        else{
            $temp = $this;
            $feedbackList = json_decode($this->statusMessage);
            $temp->statusMessage = $feedbackList->mainMessage;
            $temp->feedbackList = $feedbackList->feedback;
            return $temp;
        }
    }

    public function isCompleted():bool{
        //print_r($this->statusCode);
        return isset($this->statusCode);
    }

    public function isRunning():bool{

    }
}
