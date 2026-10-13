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

class MariaDBSettings extends HealthCheck
{

    function getPath(): string
    {
        return "/boot";
    }

    public function getCategory(): string
    {
        return "OS Settings";
    }

    public function getDescription(): string
    {
        return "Verify the DataBase settings are valid.";
    }

    public function check(): CheckResponse
    {

        // Containerized installs use a remote MariaDB service (DBServer != localhost).
        if (defined('DBServer') && DBServer !== 'localhost' && DBServer !== '127.0.0.1' && DBServer !== '') {
            $errno = 0;
            $errstr = '';
            $fp = @fsockopen(DBServer, 3306, $errno, $errstr, 2);
            if ($fp) {
                fclose($fp);
                $success = true;
                $code = 0;
                $msg = "Your database is reachable at ".DBServer.":3306 (containerized)";
                $remediation = "N/A";
            } else {
                $success = false;
                $code = -1;
                $msg = "Cannot reach database at ".DBServer.":3306 ($errstr)";
                $remediation = "Verify DB_HOST / MariaDB container is running and accepting connections.";
            }
        } else {
            $command = "netstat -pnuat | grep 3306 | grep LISTEN | awk '{ print $4 }'";
            $response = exec($command);

            if($response == ":::3306" || $response == "0.0.0.0:3306"){
                $success = true;
                $code = 0;
                $msg = "Your database is listening for incomming connections from 0.0.0.0:3306";
                $remediation = "N/A";
            }
            else{
                $success = false;
                $code = -1;
                $msg ="Your database is listening for incomming connections from only '$response' (IP:port)";
                $remediation = "Verify you have proper settings for database connections. (see <a href=\"https://live.paloaltonetworks.com/t5/Expedition-Discussions/ML-gets-stuck-at-quot-Pending-quot/m-p/225706#M346\" target='_blank'>ML gets stuck at \"Pending\" </a>)";
            }
        }

        $response = new CheckResponse($this,$success, $code, $msg, $remediation);
        return $response;
    }

    public function repair(): CheckResponse    {
        return $this->check();
    }

}