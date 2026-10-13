#!/bin/bash
filePath=/home/userSpace/tempEnvironmentParameters.php

CPUFreq=`lscpu | grep "^CPU MHz:" | awk '{print $3}'`
NumCPUs=`lscpu | grep "^CPU(s):"  | awk '{print $2}'`
TotalRAM=`grep MemTotal /proc/meminfo | awk '{print $2}'  `

SuggCPUs=`echo "scale=0;$NumCPUs*0.8/1;" | bc`
if [ $SuggCPUs -eq 0 ]; then SuggCPUs=1; fi

SuggRAM=`echo "scale=0;$TotalRAM*0.8/1024/1;" | bc`

if [ ! -f $filePath ];
then
    echo "Creating $filePath to use $SuggCPUs CPUs";
    echo "<?php" >> $filePath;
    echo "" >> $filePath;
    echo "\$suggestedEnvironmentParameters = [ " >> $filePath;
    echo " 'NumCPUs'=> $SuggCPUs, " >> $filePath;
    echo " 'TotalCPUs'=> $NumCPUs, " >> $filePath;
    echo " 'SparkRAM'=> '${SuggRAM}m'," >> $filePath;
    echo "];" >> $filePath;
else
    echo "Creating $filePath to use $SuggCPUs CPUs";
    lineToChange=`grep -n "'NumCPUs'=>" $filePath | awk -F ':' '{print $1}'`
    sed -i "${lineToChange}s/.*/ 'NumCPUs'=>$SuggCPUs,/" $filePath;

    lineToChange=`grep -n "'TotalCPUs'=>" $filePath | awk -F ':' '{print $1}'`
    sed -i "${lineToChange}s/.*/ 'TotalCPUs'=>$NumCPUs,/" $filePath;

    lineToChange=`grep -n "'SparkRAM'=>" $filePath | awk -F ':' '{print $1}'`
    sed -i "${lineToChange}s/.*/ 'SparkRAM'=>'${SuggRAM}m',/" $filePath;
fi;

#sed -i -E "s/(define \('NumCPUs'.+)(.+<\/username>)/\1something\2/" file.xml
#define ('NumCPUs',$SuggCPUs)
