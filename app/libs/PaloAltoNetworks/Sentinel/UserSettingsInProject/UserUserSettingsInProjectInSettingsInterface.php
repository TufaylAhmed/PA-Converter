<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 23/5/16 - 10:05
 */

namespace PaloAltoNetworks\Sentinel\UserSettingsInProject;

interface UserSettingsInProject
{
    /**
     * Returns the devices model.
     *
     * @return string
     */
    public static function getUserSettingsInProjectModel();

    /**
     * Sets the devices model.
     *
     * @param  string  $devicesModel
     * @return void
     */
    public static function setUserSettingsInProjectModel($usersModel);
}
