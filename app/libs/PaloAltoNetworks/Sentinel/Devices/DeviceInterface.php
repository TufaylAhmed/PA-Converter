<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 23/5/16 - 10:05
 */

namespace PaloAltoNetworks\Sentinel\Devices;

interface DeviceInterface
{
    /**
     * Returns the device's primary key.
     *
     * @return int
     */
    public function getDeviceId();


    /**
     * Returns the devices model.
     *
     * @return string
     */
    public static function getDevicesModel();

    /**
     * Sets the devices model.
     *
     * @param  string  $devicesModel
     * @return void
     */
    public static function setDevicesModel($usersModel);
}
