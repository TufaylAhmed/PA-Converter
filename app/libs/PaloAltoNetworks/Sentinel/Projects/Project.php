<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 18/5/16 - 16:23
 */

namespace PaloAltoNetworks\Sentinel\Projects;

use Illuminate\Database\Eloquent\Model as Eloquent;

class Project extends Eloquent
{
    protected $table = 'projects';

    protected $fillable = [
        'name',
        'vendors',
        'tag',
        'progress',
        'active',
        'appversion',
        'panos',
        'purpose',

        'created_at',
        'updated_at',

    ];

    /**
     * The Eloquent users model name.
     *
     * @var string
     */
    protected static $usersModel    = 'Cartalyst\Sentinel\Users\EloquentUser';
    protected static $devicesModel  = 'PaloAltoNetworks\Sentinel\Devices\Device';
    protected static $settingsModel = 'PaloAltoNetworks\Sentinel\UserSettingsInProject\UserSettingsInProject';

    /**
     * The Users relationship.
     *
     * @return \Illuminate\Database\Eloquent\Relations\BelongsToMany
     */
    public function users()
    {
        return $this->belongsToMany(static::$usersModel, 'project_users', 'project_id', 'user_id')->withTimestamps();
    }

    /**
     * The Devices relationship.
     *
     * @return \Illuminate\Database\Eloquent\Relations\BelongsToMany
     */
    public function devices()
    {
        return $this->belongsToMany(static::$devicesModel, 'project_devices', 'project_name', 'device_id')->withTimestamps();
    }

    /**
     * The UserSettings relationship.
     *
     * @return \Illuminate\Database\Eloquent\Relations\BelongsToMany
     */
    public function settings(){
        return $this->belongsToMany(static::$settingsModel, 'user_settings', 'project_id', 'user_id')->withTimestamps();
    }

    /**
     * {@inheritDoc}
     */
    public function getUsers()
    {
        return $this->users;
    }

    /**
     * {@inheritDoc}
     */
    public function getDevices()
    {
        return $this->devices;
    }

    public function getSettings(){
        return $this->settings;
    }
    
}