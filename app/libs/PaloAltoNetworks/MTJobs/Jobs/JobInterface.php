<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 13/6/16 - 11:29
 */

namespace PaloAltoNetworks\MTJobs\Jobs;

interface JobInterface
{
    /**
     * Returns the device's primary key.
     *
     * @return int
     */
    public function getJobId();


    /**
     * Returns the devices model.
     *
     * @return string
     */
    public static function getJobsModel();

    /**
     * Sets the devices model.
     *
     * @param  string  $jobsModel
     * @return void
     */
    public static function setJobsModel($jobsModel);
}
