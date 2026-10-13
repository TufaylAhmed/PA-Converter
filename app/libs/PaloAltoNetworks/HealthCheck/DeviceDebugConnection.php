<?php
/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: $today.year.hour.minute
 ******************************************************************************/

namespace PaloAltoNetworks\HealthCheck;
use ExpeditionSettingsParameter;

require_once INC_ROOT . '/libs/settings/ML_Settings.php';
require_once $_SERVER['DOCUMENT_ROOT'] . '/libs/common/definitions.php';
require_once INC_ROOT.'/libs/settings/ExpeditionSettingsParameter.php';


class DeviceDebugConnection extends HealthCheck
{

    public function getDescription(): string
    {
        return "Verify the Device Debug Connection is disabled by default (enable it only for troubleshooting purposes) and DELETE debug file after troubleshooting";
    }

    public function getCategory(): string
    {
        return "Expedition Settings";
    }

    public function check(): CheckResponse
    {

        if (DEVICE_DEBUG_CONNECTION_ENABLED == 1) {
            $success = false;
            $code = -1;
            $msg = 'Device Debug Connection should be only enabled for troubleshooting purposes. Please consider to disable it.';
            $remediation = "Set the custom setting DEVICE_DEBUG_CONNECTION_ENABLED to 0 (disabled) and DELETE debug file.";
        } else {

            $success = true;
            $code = 0;
            $msg = 'Device Debug Connection is disabled.';
            $remediation = "N/A";

        }
        return new CheckResponse($this, $success, $code, $msg, $remediation);
    }

    public function repair(): CheckResponse
    {
        ExpeditionSettingsParameter::updateVariable("DEVICE_DEBUG_CONNECTION_ENABLED", 0);
        unlink("/home/userSpace/devices/debug.txt");
        //restart the agent
        exec('sh /var/www/html/OS/startup/pan-readOrders restart');
        return $this->check();
    }

}