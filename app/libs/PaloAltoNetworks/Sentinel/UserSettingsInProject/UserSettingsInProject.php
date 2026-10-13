<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 18/5/16 - 16:07
 */

namespace PaloAltoNetworks\Sentinel\UserSettingsInProject;

use Illuminate\Database\Eloquent\Model as Eloquent;

class UserSettingsInProject extends Eloquent
{
    protected $table = 'user_settings';
    protected $fillable = [
        'id', 'user_id', 'project_id', 'selectedDevices', 'panos_vsys', 'source', 'panorama_template', 'view', 'panorama_rules', 'selectedLogConnector', 'selectedUIDConnector','version',
        'created_at', 'updated_at',
    ];

    /**
     * The Eloquent device model name.
     *
     * @var string
     */
    protected static $devicesModel = 'PaloAltoNetworks\Sentinel\Devices\Device';


    protected static $UserSettingsModel = 'PaloAltoNetworks\Sentinel\UserSettingsInProject\UserSettingsInProject';

    /**
     * {@inheritDoc}
     */
    public function device()
    {
        return $this->belongsTo(static::$devicesModel);
    }

    /**
     * Get the device model.
     *
     * @return string
     */
    public static function getDevicesModel()
    {
        return static::$devicesModel;
    }

    /**
     * Set the device model.
     *
     * @param  string  $devicesModel
     * @return void
     */
    public static function setDevicesModel($devicesModel)
    {
        static::$devicesModel = $devicesModel;
    }

    /**
     * {@inheritDoc}
     */
    public static function getUserSettingsModel()
    {
        return static::$UserSettingsModel;
    }

}