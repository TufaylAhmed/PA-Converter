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

class DiskSparkTempSpaceCheck extends DiskSpaceCheck
{

    function getPath(): string
    {
        require_once INC_ROOT.'/libs/projectdb.php';
        $pandbRBAC = selectDatabase('pandbRBAC');
        $mlSettings = new \ML_Settings($pandbRBAC);
        $result = $mlSettings->get();
        $settings = $result['msg']['0'];
        if(!$settings['tempDataPath']){
            return "";
        }
        return $settings['tempDataPath'];
    }

    public function getDescription(): string
    {
        return "Verify there is enough Space for the Spark Temporary Data Structure";
    }


    public function repair(): CheckResponse
    {
        require_once INC_ROOT.'/libs/projectdb.php';
        $pandbRBAC = selectDatabase('pandbRBAC');

        if($this->getPath() == ""){
            $response = new CheckResponse($this,false, -1, "Temporary Data Structure path not provided","Please, define a ML Temporary Data Structure path");
            return $response;
        }
        if(!file_exists($this->getPath())){
            $response = new CheckResponse($this,false, -1, "Temporary Data Structure path not valid","Please, define a ML Temporary Data Structure path");
            return $response;
        }
        $diskStatus = new \DiskStatus($this->getPath());
        $freeSpace = $diskStatus->freeSpace(true);
        $freeSpaceGB = $diskStatus->freeSpace();
        $usedPercentage = ($diskStatus->usedSpace()/100);

        if($usedPercentage>0.8 || $freeSpace < 50*1024*1024){
            $success = false;
            $code = -1;
            $msg = $this->getPath()." is running out of space. Only $freeSpaceGB free. Consider deleting not useful files.";
        }
        else{
            $success = true;
            $code = 0;
            $msg = $this->getPath()." is consuming ".$usedPercentage*100 ."% of the unit space($freeSpaceGB free)";
        }

        $response = new CheckResponse($this,$success, $code, '',$msg);
        return $response;
    }

}