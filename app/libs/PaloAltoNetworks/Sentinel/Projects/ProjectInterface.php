<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 23/5/16 - 10:08
 */

namespace PaloAltoNetworks\Sentinel\Projects;

interface ProjectInterface
{
    /**
     * Returns the project's primary key.
     *
     * @return int
     */
    public function getProjectId();

    /**
     * Returns all users for the role.
     *
     * @return \IteratorAggregate
     */
    public function getUsers();

    /**
     * Returns all devicess for the project.
     *
     * @return \IteratorAggregate
     */
    public function getDevices();

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
    public static function getUsersModel();

    /**
     * Sets the users model.
     *
     * @param  string  $usersModel
     * @return void
     */
    public static function setUsersModel($usersModel);

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
    public static function setDevicesModel($devicesModel);

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
}
