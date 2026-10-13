<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 13/6/16 - 11:33
 */

namespace PaloAltoNetworks\MTJobs\Jobs;

use Cartalyst\Support\Traits\RepositoryTrait;
use PaloAltoNetworks\MTJobs\Jobs\JobRepositoryInterface;

class IlluminateJobRepository implements JobRepositoryInterface
{
    use RepositoryTrait;

    /**
     * The Eloquent device model name.
     *
     * @var string
     */
    protected $model = 'PaloAltoNetworks\MTJobs\Jobs\Job';

    /**
     * Create a new Illuminate device repository.
     *
     * @param  string  $model
     * @return void
     */
    public function __construct($model = null)
    {
        if (isset($model)) {
            $this->model = $model;
        }
    }

    /**
     * {@inheritDoc}
     */
    public function findById($id)
    {
        return $this
            ->createModel()
            ->newQuery()
            ->find($id);
    }

    /**
     * {@inheritDoc}
     */
    public function findByName($name)
    {
        return findById($name);
    }
}
