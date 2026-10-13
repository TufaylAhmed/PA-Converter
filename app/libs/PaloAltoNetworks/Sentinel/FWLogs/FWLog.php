<?php
/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: $today.year.hour.minute
 ******************************************************************************/

namespace PaloAltoNetworks\Sentinel\FWLogs;

use Illuminate\Database\Eloquent\Model as Eloquent;

class FWLog extends Eloquent
{
    /**
     * {@inheritDoc}
     */
    protected $table = 'device_logs';
    protected $fillable = [
        'device_serial', 'log_name', 'date', 'processed', 'comment', 'created_at', 'updated_at',
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
        return $this->belongsTo(static::$devicesModel, 'device_serial', 'serial');
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
