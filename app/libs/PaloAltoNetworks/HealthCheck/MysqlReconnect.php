<?php
/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: $today.year.hour.minute
 ******************************************************************************/

namespace PaloAltoNetworks\HealthCheck;


class MysqlReconnect extends HealthCheck
{

    public function getDescription(): string
    {
        return "Verify that the PHP settings are defined to reconnect MariaDB connections if lost";
    }

    public function getCategory(): string
    {
        return "OS Settings";
    }

    public function check(): CheckResponse
    {
        require_once INC_ROOT.'/libs/projectdb.php';
        $value= ini_get("mysqli.reconnect");

        if(strtoupper($value) != '1' ){
            $remediation = "(see <a href=\"https://live.paloaltonetworks.com/t5/Expedition-Articles/Modifying-mysqli-reconnect-value/ta-p/219223\" target='_blank'>Modifying mysqli.reconnect parameter</a>)";
            $response = new CheckResponse($this, false, -1, "mysqli.reconnect is OFF", 'Set mysqli.reconnect to ON. '.$remediation);
        }
        else{
            $response = new CheckResponse($this, true, 0, "mysqli.reconnect is ON", 'N/A');
        }

        return $response;
    }

    public function repair(): CheckResponse
    {
        return $this->check();
    }
}