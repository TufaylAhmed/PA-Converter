<?php
/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: $today.year.hour.minute
 ******************************************************************************/

namespace PaloAltoNetworks\HealthCheck;
require_once INC_ROOT.'/libs/settings/ML_Settings.php';



class MLCheckAlive extends HealthCheck
{
    private $invalid_paths = [
        "/root",
        "/tmp",
        "/var/tmp"
    ];

    public function getDescription(): string
    {
        return "Verify the Provided ML IP is Up";
    }

    public function getCategory(): string
    {
        return "Expedition Settings";
    }

    public function check(): CheckResponse
    {
        require_once INC_ROOT.'/libs/projectdb.php';
        $pandbRBAC = selectDatabase('pandbRBAC');
        $mlSettings = new \ML_Settings($pandbRBAC);
        $result = $mlSettings->get();

        if($result['code']!=1){
            $success = false;
            $code    = -1;
            $msg     = 'There are not settings defined for ML. ';
            $remediation = "Set the ML Settings";
        }
        else {

            $connectionStatus = $mlSettings->checkAlive();
            $settings = $result['msg']['0'];
            $mlIP = $settings['server'];

            if (isset($connectionStatus->alive) && $connectionStatus->alive == true) {

                $msg = 'ML module is Up and Listening at ' . $mlIP;
                $remediation = 'N/A';
                $success = true;
                $code = 0;
            } else {
                $success = false;
                $code = -1;
                $msg = 'ML module is unreachable at ' . $mlIP;
                $remediation = 'Please, verify that the ML address is correct and reachable';
            }
        }
        return new CheckResponse($this, $success, $code, $msg, $remediation);
    }

    public function repair(): CheckResponse
    {
        return $this->check();
    }

}