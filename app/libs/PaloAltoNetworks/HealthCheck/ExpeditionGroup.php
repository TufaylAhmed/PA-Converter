<?php
/*******************************************************************************
 * Copyright (c) 2018 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: 2/14/19 3:50 PM
 ******************************************************************************/

namespace PaloAltoNetworks\HealthCheck;

require_once INC_ROOT.'/console/messaging/readOrdersCheck.php';

class ExpeditionGroup extends HealthCheck
{
    public function __construct()
    {
        parent::__construct();
    }

    public function getCategory(): string
    {
        return "OS Settings";
    }

    public function getDescription(): string
    {
        return "Verify that Expedition will be able to compress/delete CSV logs reported by \"expedition\" user.";
    }

    public function check(): CheckResponse
    {
        exec("groups | grep expedition | wc -l", $output);

        if ($output[0] == 0) {
            $success = false;
            $code = -1;
            $msg = 'www-data may not have rights to compress/delete CSV files';
            $remediation = 'Include www-data into expedition via "sudo usermod -a -G expedition www-data", restart the Task Manager and restart apache via "sudo service apache2 restart".';
        }else{
            $success = true;
            $code = 0;
            $msg = 'www-data already belongs to expedition group';
            $remediation = 'N/A';
        }

        $remediation = $remediation==""?"N/A":$remediation;
        return new CheckResponse($this,$success, $code, $msg, $remediation);
    }

    public function repair(): CheckResponse    {
        return $this->check();
    }

}