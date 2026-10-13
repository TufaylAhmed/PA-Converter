<?php
/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: $today.year.hour.minute
 ******************************************************************************/

require_once '/var/www/html/libs/common/definitions.php';
require_once '/var/www/html/libs/DiskStatus.class.php';

include INC_ROOT.'/bin/middleware_sanitizer.php';

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

$status = array();

//CPU LOAD CHECK
$numCpus = getEnvironmentParameters();
$status[] = [
    "item"  =>"CPUs",
    "pct"   =>$numCpus['numCPUs']/$numCpus['TotalCPUs'],
    "used"  =>$numCpus['numCPUs']." out of ".$numCpus['TotalCPUs']." CPU(s)",
    "spark" =>$numCpus['numCPUs'],
    "total" =>$numCpus['TotalCPUs']
];

$load = sys_getloadavg();
$cpu_lastminute=$load[0];
$cpu_latminute_pct=$cpu_lastminute*100;
//if ($cpu_lastminute>1){$cpu_lastminute="1";}
//if ($cpu_latminute_pct>100){$cpu_latminute_pct="100";}

$status[] = [
    "item"  =>"CPU usage",
    "pct"   =>$cpu_lastminute / $numCpus['TotalCPUs'],
    "used"  =>$cpu_latminute_pct." out of ". 100 * $numCpus['TotalCPUs']."%"
];



//RAM USAGE CHECK
$RamStatus = getSystemMemInfo();
$totalSpace = $RamStatus["MemTotal"];
$memFree = $RamStatus["MemAvailable"];
$used=$totalSpace-$memFree;
$percentage=($used*100)/$totalSpace;
$barWidth = ($percentage/100);

$status[]= [
    "item"  =>"RAM usage",
    "pct"   =>$barWidth,
    "used"  =>round($used/pow(2,20), 2) ." out of ". round($totalSpace/pow(2,20),2) ." GB",
];

//DISK SPACE CHECK
$path = check_sanitize(isset($_GET['path'])? $_GET['path']: "/tmp");
if (is_dir($path)){
    $diskStatus = new DiskStatus($path);
    $totalSpace = $diskStatus->totalSpace();
    $barWidth = ($diskStatus->usedSpace()/100);
    $status[] = [
        "item"  =>"DISK usage",
        "pct"   =>$barWidth,
        "used"  =>round($diskStatus->usedSpace()/100*$totalSpace, 2). " out of ".$totalSpace. " at $path"
    ];
}
else{
    $status[] = [
        "item"  =>"DISK usage",
        "pct"   =>1,
        "used"  => "Disk Unit is unreachable"
    ];
}

echo json_encode($status);