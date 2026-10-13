<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 13/6/16 - 10:56
 */

namespace PaloAltoNetworks\MTJobs\Jobs;

use Illuminate\Database\Eloquent\Model as Eloquent;

class Job extends Eloquent
{
    protected $table = 'jobs';
    protected $fillable = [
        'user_id',
        'created_at',
        'updated_at',
        'completed',
        'tasks',
        'parentType',
        'parentId',
        'description',
        'parentJob',
        'failed',
    ];


    /**
     * The Eloquent task model name.
     *
     * @var string
     */
    protected static $tasksModel = 'PaloAltoNetworks\MTJobs\Tasks\Task';

    /**
     * The Eloquent job model name.
     *
     * @var string
     */
    protected static $jobsModel = 'PaloAltoNetworks\MTJobs\Jobs\Job';

    /**
     * The Eloquent user model name.
     *
     * @var string
     */
    protected static $usersModel = 'PaloAltoNetworks\Sentinel\User\User';

    /**
     * The Users relationship.
     *
     * @return \Illuminate\Database\Eloquent\Relations\BelongsTo
     */
    public function projects()
    {
        return $this->belongsTo(static::$usersModel, 'user_id')->withTimestamps();
    }

    /**
     * {@inheritDoc}
     */
    public static function getJobModel()
    {
        return static::$jobsModel;
    }

    public function tasks()
    {
        return $this->hasMany(static::$tasksModel, 'job_id');
    }

    public function getTasks()
    {
        return $this->tasks;
    }

    /***
     * Gets all the subjobs that hang from this job
     * @return \Illuminate\Database\Eloquent\Relations\HasMany
     */

    public function jobs()
    {
        return $this->hasMany(static::$jobsModel, 'parentJob');
    }

    /**
     * {@inheritDoc}
     */
    public function delete()
    {
        if ($this->exists) {
            $this->tasks()->delete();
        }

        parent::delete();
    }

}