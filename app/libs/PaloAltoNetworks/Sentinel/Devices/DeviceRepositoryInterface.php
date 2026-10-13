<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 23/5/16 - 10:05
 */
namespace PaloAltoNetworks\Sentinel\Devices;

interface DeviceRepositoryInterface
{
    /**
     * Finds a device by the given primary key.
     *
     * @param  int  $id
     * @return \PaloAltoNetworks\Sentinel\Devices\DeviceInterface
     */
    public function findById($id);


    /**
     * Finds a device by the given name.
     *
     * @param  string  $name
     * @return \PaloAltoNetworks\Sentinel\Devices\DeviceInterface
     */
    public function findByName($name);
}
