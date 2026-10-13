<?php
/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: $today.year.hour.minute
 ******************************************************************************/

namespace PaloAltoNetworks\HealthCheck;

require_once INC_ROOT.'/console/messaging/readOrdersCheck.php';

class DiskUserSpaceCheck extends DiskSpaceCheck
{

    function getPath(): string
    {
        return "/home/userSpace";
    }

    public function getDescription(): string
    {
        return "Verify there is enough Space in the /home/userSpace unit";
    }


}