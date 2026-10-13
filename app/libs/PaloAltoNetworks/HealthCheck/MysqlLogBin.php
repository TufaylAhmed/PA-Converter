<?php
/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: $today.year.hour.minute
 ******************************************************************************/

namespace PaloAltoNetworks\HealthCheck;


class MysqlLogBin extends HealthCheck
{

    public function getDescription(): string
    {
        return "Verify that the Log_bin flag in MariaDB is set to off";
    }

    public function getCategory(): string
    {
        return "OS Settings";
    }

    public function check(): CheckResponse
    {
        require_once INC_ROOT.'/libs/projectdb.php';
        $conn = selectDatabase('pandbRBAC');
        $query = "SHOW variables like 'log_bin'";
        $result = $conn->query($query);

        if($result->num_rows>0){
            $data = $result->fetch_assoc();
            $value = $data['Value'];

            if($value != 'OFF'){
                $response = new CheckResponse($this, false, -1, "Log_bin is ON", 'Set log_bin to OFF');
            }
            else{
                $response = new CheckResponse($this, true, 0, "Log_bin is OFF", 'N/A');
            }
        }else{
            $response = new CheckResponse($this, true, 0, "Could not check log_bin state", 'Verify log_bin is OFF');
        }

        return $response;
    }

    public function repair(): CheckResponse
    {
        require_once INC_ROOT.'/libs/projectdb.php';
        $conn = selectDatabase('pandbRBAC');
        $query = "SHOW variables like '%log_bin%'";
        $result = $conn->query($query);

        if($result->num_rows>0){
            $data = $result->fetch_assoc();
            $value = $data['Value'];

            if($value != 'OFF'){
                $response = new CheckResponse($this, false, -1, "Log_bin is ON", 'Set log_bin to OFF');
            }
            else{
                $response = new CheckResponse($this, true, 0, "Log_bin is OFF", 'N/A');
            }
        }else{
            $response = new CheckResponse($this, true, 0, "Could not check log_bin state", 'Verify log_bin is OFF');
        }

        return $response;
    }
}