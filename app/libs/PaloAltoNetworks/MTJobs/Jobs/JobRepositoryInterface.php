<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 13/6/16 - 11:31
 */

namespace PaloAltoNetworks\MTJobs\Jobs;

interface JobRepositoryInterface
{
    /**
     * Finds a job by the given primary key.
     *
     * @param  int  $id
     * @return \PaloAltoNetworks\MTJobs\Jobs\JobInterface
     */
    public function findById($id);


    /**
     * Finds a job by the given name.
     *
     * @param  string  $name
     * @return \PaloAltoNetworks\MTJobs\Jobs\JobInterface
     */
    public function findByName($name);
}
