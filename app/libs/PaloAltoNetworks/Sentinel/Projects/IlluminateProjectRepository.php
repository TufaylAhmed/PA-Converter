<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 23/5/16 - 10:08
 */

namespace PaloAltoNetworks\Sentinel\Projects;

use Cartalyst\Support\Traits\RepositoryTrait;

class IlluminateProjectRepository implements ProjectRepositoryInterface
{
    use RepositoryTrait;

    /**
     * The Eloquent project model name.
     *
     * @var string
     */
    protected $model = 'PaloAltoNetworks\Project\Project';

    /**
     * Create a new Illuminate project repository.
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
        return $this
            ->createModel()
            ->newQuery()
            ->where('name', $name)
            ->first();
    }
}
