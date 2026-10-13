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
require_once INC_ROOT.'/libs/DiskStatus.class.php';

abstract class DiskSpaceCheck extends HealthCheck
{

    public function __construct()
    {
        parent::__construct();
    }

    abstract function getPath():string;

    public function getDescription(): string
    {
        return "Verify there is Disk Space";
    }

    public function getCategory(): string
    {
        return "Disk Space";
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

        if($usedPercentage>0.8 || $freeSpace < 50*1024*1024){
            $success = false;
            $code = -1;
            $msg = $this->getPath()." is running out of space. Only $freeSpaceGB free";
            $remediation = "Consider deleting not useful files or extend the unit (see <a href=\"https://live.paloaltonetworks.com/t5/Expedition-Discussions/Best-Easiest-way-to-expand-the-storage/td-p/231956\" target='_blank'>Best/Easiest way to expand the storage? </a>)";
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

    public function repair(): CheckResponse
    {
        $diskStatus = new \DiskStatus($this->getPath());
        $freeSpace = $diskStatus->freeSpace(true);
        $freeSpaceGB = $diskStatus->freeSpace();
        $usedPercentage = ($diskStatus->usedSpace()/100);

        if($usedPercentage>0.8 || $freeSpace < 50*1024*1024){
            $success = false;
            $code = -1;
            $msg = $this->getPath()." is running out of space. Only $freeSpaceGB free. ";
            $remediation = "Consider deleting not useful files or extend the unit (see <a href=\"https://live.paloaltonetworks.com/t5/Expedition-Discussions/Best-Easiest-way-to-expand-the-storage/td-p/231956\" target='_blank'>Best/Easiest way to expand the storage? </a>)";
        }
        else{
            $success = true;
            $code = 0;
            $remediation = "N/A";
            $msg = $this->getPath()." is consuming ".$usedPercentage*100 ."% of the unit space($freeSpaceGB free)";
        }

        $response = new CheckResponse($this,$success, $code, $msg, $remediation);
        return $response;
    }

}