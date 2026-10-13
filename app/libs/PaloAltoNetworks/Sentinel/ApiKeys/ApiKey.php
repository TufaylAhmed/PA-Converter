<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 23/5/16 - 16:01
 */

namespace PaloAltoNetworks\Sentinel\ApiKeys;

use Illuminate\Database\Eloquent\Model as Eloquent;

class ApiKey extends Eloquent
{
    /**
     * {@inheritDoc}
     */
    protected $table = 'device_keys';
    protected $fillable = [
        'device_id', 'key_name', 'api_key', 'user_name', 'user_password', 'created_at', 'updated_at', 'role', 
    ];

    /**
     * The device model name.
     *
     * @var string
     */
    protected static $devicesModel = 'PaloAltoNetworks\Sentinel\Devices\Device';

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
}
