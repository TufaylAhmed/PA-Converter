<?php
/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: $today.year.hour.minute
 ******************************************************************************/

namespace PaloAltoNetworks\Sentinel\User;

interface UserInterface
{
    /**
     * Returns the project's primary key.
     *
     * @return int
     */
    public function getUserId();

    /**
     * Returns all the settings related to the project.
     *
     * @return \IteratorAggregate
     */
    public function getSettings();

    /**
     * Returns the users model.
     *
     * @return string
     */
    public static function getSettingsModel();

    /**
     * Sets the userSettings model.
     *
     * @param  string  $settingsModel
     * @return void
     */
    public static function setSettingsModel($settingsModel);

    public function getGravatarUrl();
    public function getFullNameOrUsername();


}
