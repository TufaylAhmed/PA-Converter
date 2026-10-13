<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 23/5/16 - 10:08
 */

namespace PaloAltoNetworks\Sentinel\Projects;

interface ProjectRepositoryInterface
{
    /**
     * Finds a project by the given primary key.
     *
     * @param  int  $id
     * @return \PaloAltoNetworks\Sentinel\Projects\ProjectInterface
     */
    public function findById($id);


    /**
     * Finds a project by the given name.
     *
     * @param  string  $name
     * @return \PaloAltoNetworks\Sentinel\Projects\ProjectInterface
     */
    public function findByName($name);
}
