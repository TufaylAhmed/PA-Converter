<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 23/5/16 - 10:02
 */

namespace PaloAltoNetworks\Sentinel\UserSettingsInProject;

use Cartalyst\Support\Traits\RepositoryTrait;

class IlluminateUserSettingsInUserSettingsInProjectRepository implements UserSettingsInProjectInterface
{
    use RepositoryTrait;

    /**
     * The Eloquent device model name.
     *
     * @var string
     */
    protected $model = 'PaloAltoNetworks\ProjectRelation';

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
        return $this
            ->createModel()
            ->newQuery()
            ->find($name);
    }
}
