<?php
/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: $today.year.hour.minute
 ******************************************************************************/

namespace PaloAltoNetworks\HealthCheck;

require_once INC_ROOT.'/libs/PaloAltoNetworks/HealthCheck/HealthCheck.php';

class HostNameCheck extends HealthCheck
{

    public function __construct()
    {
        parent::__construct();
    }

    public function getDescription(): string
    {
       return "Verify hostname format to avoid Spark issues";
    }

    public function getCategory(): string
    {
        return "OS Settings";
    }

    public function check(): CheckResponse
    {
        $hostname = gethostname();

        if (strpos($hostname, '_') !== false) {
            $success = false;
            $code = -1;
            $msg = 'This Expedition has a conflictive hostname. Avoid having the following characters: ("_")';
            $remediation = 'Modify your hostname (/etc/hostname) and restart the machine';
        }else{
            $success = true;
            $code = 0;
            $msg = 'This Expedition has valid hostname';
            $remediation = 'N/A';
        }

        $remediation = $remediation==""?"N/A":$remediation;
        return new CheckResponse($this,$success, $code, $msg, $remediation);
    }

    public function repair(): CheckResponse    {
        return $this->check();
    }


}