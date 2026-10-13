<?php
# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
$RamStatus = getSystemMemInfo();

$totalSpace = $RamStatus["MemTotal"];
$memFree = $RamStatus["MemFree"];
$used=$totalSpace-$memFree;
$percentage=($used*100)/$totalSpace;
$barWidth = ($percentage/100);
$other=100-$percentage;
echo '[{"used":"'.$barWidth.'","pct":"'.$percentage.'"}]';



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
?>
