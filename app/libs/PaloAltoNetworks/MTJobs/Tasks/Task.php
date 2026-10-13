<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 13/6/16 - 11:38
 */

namespace PaloAltoNetworks\MTJobs\Tasks;

use Illuminate\Database\Eloquent\Model as Eloquent;

class Task extends Eloquent
{
    /**
     * {@inheritDoc}
     */
    protected $table = 'tasks';
    protected $fillable = [
        'job_id',
        'taskType',
        'taskName',
        'processCode',
        'params',
        'statusCode',
        'statusMessage',
        'resultCode',
        'retry',
        
        'created_at',
        'updated_at',
    ];

    /**
     * The users model name.
     *
     * @var string
     */
    protected static $jobsModel = 'PaloAltoNetworks\MTJobs\Jobs\Job';

    /**
     * {@inheritDoc}
     */
    public function job()
    {
        return $this->belongsTo(static::$jobsModel);
    }

    /**
     * Get the users model.
     *
     * @return string
     */
    public static function getJobsModel()
    {
        return static::$jobsModel;
    }

    /**
     * Set the users model.
     *
     * @param  string  $usersModel
     * @return void
     */
    public static function setJobsModel($jobsModel)
    {
        static::$jobsModel = $jobsModel;
    }

    private function isJson($string) {
        json_decode($string);
        return (json_last_error() == JSON_ERROR_NONE);
    }

    /***
     * @return Task The statusMessage field in the database may be a JSON. If so, get the mainMessage and feedback messages and separate them into two fields
     */
    public function print():Task{
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
