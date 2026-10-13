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

class DiskBootSpaceCheck extends DiskSpaceCheck
{

    function getPath(): string
    {
        return "/boot";
    }

    public function getDescription(): string
    {
        return "Verify there is enough Space in the /boot unit.";
    }

    public function check(): CheckResponse
    {
        if($this->getPath() == ""){
            $response = new CheckResponse($this,false, -1, "Path not provided","Set a valid path");
            return $response;
        }
        if(!file_exists($this->getPath())){
            $response = new CheckResponse($this,false, -1, "Path not valid","Set a valid path");
            return $response;
        }
        $diskStatus = new \DiskStatus($this->getPath());
        $freeSpace = $diskStatus->freeSpace(true);
        $freeSpaceGB = $diskStatus->freeSpace();
        $usedPercentage = ($diskStatus->usedSpace()/100);

        if($usedPercentage>0.6 || $freeSpace < 50*1024*1024){
            $success = false;
            $code = -1;
            $msg = $this->getPath()." is running out of space. Only $freeSpaceGB free";
            $remediation = "Execute 'sudo apt-get autoremove' to free space";
        }
        else{
            $success = true;
            $code = 0;
            $msg = $this->getPath()." is consuming ".$usedPercentage*100 ."% of the unit space($freeSpaceGB free)";
            $remediation = "N/A";
        }

        $response = new CheckResponse($this,$success, $code, $msg, $remediation);
        return $response;
    }

}