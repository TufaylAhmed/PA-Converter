<?php
/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: $today.year.hour.minute
 ******************************************************************************/

function getMLStatus(){
    $pandbRBAC = selectDatabase('pandbRBAC');
    $mlSettings = new ML_Settings($pandbRBAC);
    $message = $mlSettings->get();
    $mlParams_arr = $message['msg'];
    if(count($mlParams_arr)>0){
        $ExpeditionML = $mlParams_arr[0]['server'];
        $parquetPath  = $mlParams_arr[0]['parquetPath'];
    }
    else{
        $ExpeditionML = $_SERVER['SERVER_ADDR'];
        $parquetPath  = "/tmp";
    }

    $connectionStatus = $mlSettings->checkAlive();
    
    if(isset($connectionStatus->alive) && $connectionStatus->alive==true)
    {
        $url = "https://$ExpeditionML/API/checkSystemStatus.php?path=".$parquetPath;
        $tuCurl = curl_init();
        curl_setopt($tuCurl,CURLOPT_URL,$url);
        curl_setopt($tuCurl,CURLOPT_RETURNTRANSFER,true);
        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, 0);
        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, 0);
        $output=curl_exec($tuCurl);

    }
    else{
        $output = null;
    }

    if(is_null($output) || $output=='' || !$output){
        $output[] = [

                "item"=>"CPUs",
                "pct"=>0,
                "used"=>"ML server unreachable",
                "spark"=>0,
                "total"=>0
            ];
        $output[] = [
                "item"=>"CPU usage",
                "pct"=>0,
                "used"=>"ML server unreachable"
            ];
        $output[] = [
                "item"=>"RAM usage",
                "pct"=>0,
                "used"=>"ML server unreachable"
            ];
        $output[] =[
                "item"=>"DISK usage",
                "pct"=>0,
                "used"=>"ML server unreachable"
            ];
        $output = json_encode($output);

    }
    $MLStatus = json_decode($output);

    return $MLStatus;
}

function getSystemStatus(){
    $out = [];

    $load = sys_getloadavg();
    $cpu_lastminute = $load[0];
    $cpu_latminute_pct = $cpu_lastminute * 100;

    $numCpus = getEnvironmentParameters();
    $out[] = [
        "item"  =>"CPUs",
        "pct"   =>$numCpus['TotalCPUs'],
        "used"  =>$numCpus['TotalCPUs']." CPU(s)",
    ];

    $out[] = [
        "item" => "CPU usage",
        "pct" => $cpu_lastminute / $numCpus['TotalCPUs'],
        "used" => $cpu_latminute_pct* $numCpus['TotalCPUs']." out of ". 100 * $numCpus['TotalCPUs']."%"
    ];

    $RamStatus = getSystemMemInfo();

    $totalSpace = $RamStatus["MemTotal"];
    $memFree = $RamStatus["MemAvailable"];
    $used = $totalSpace - $memFree;
    $percentage = ($used * 100) / $totalSpace;
    $barWidth = ($percentage / 100);

    $out[] = [
        "item" => "RAM usage",
        "pct" => $barWidth,
        "used" => round($used/pow(2,20), 2) ." out of ". round($totalSpace/pow(2,20),2) ." GB",
    ];


    try {
        $path = '/';
        $diskStatus = new DiskStatus($path);
        $totalSpace = $diskStatus->totalSpace();
        $barWidth = ($diskStatus->usedSpace() / 100);
        $out[] = [
            "item" => "DISK usage",
            "pct" => $barWidth,
            "used" => round($diskStatus->usedSpace()/100*$totalSpace, 2). " out of ".$totalSpace ." at $path"
        ];


    } catch (Exception $e) {
        echo 'Error on getSystemStatus';
        exit();
    }

    return $out;
}

function getEnvironmentParameters(){
    $fileEnvironmentParameters = USERSPACE_PATH."/environmentParameters.php";
    if(!file_exists($fileEnvironmentParameters)){
        exec("/bin/bash ". INC_ROOT."/OS/spark/scripts/getCPUs.sh");
    }

    include_once $fileEnvironmentParameters;

    $parameters = [
        'numCPUs'   => NumCPUs,
        'TotalCPUs' => TotalCPUs
    ];
    return $parameters;
}

function getSystemMemInfo()
{
    $data = explode("\n", file_get_contents("/proc/meminfo"));
    $meminfo = array();
    foreach ($data as $line) {
        //list($key, $val) = explode(":", $line);
        $newdata=explode(":",$line);
        if (isset($newdata[1])){
            $key=$newdata[0];
            $val=$newdata[1];
            $meminfo[$key] = trim($val);
        }

    }
    return $meminfo;
}