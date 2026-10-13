<?php

$_SERVER['DOCUMENT_ROOT'] = '/var/www/html';
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
require_once INC_ROOT.'/libs/projectdb.php';
require_once INC_ROOT .'/userManager/API/accessControl_CLI.php';
require_once INC_ROOT.'/libs/common/tools/tools.php';

// CODE STARTS HERE
// Read the log file
$logFile = "/PALogs/LABO-MXDR-exampleCSV.csv";
$logFileFixed = $logFile. "_fixed.csv";
$lines = file($logFile, FILE_IGNORE_NEW_LINES);
$new_lines = [];
// Loop through each line of the log
$i=0;
foreach ($lines as $index => $line) {
    if($i===0){
        // Update the modified line
        $new_lines[$index] = $line;
    } else {
        // Split the line into columns using the comma delimiter
        $columns = explode(",", $line);

        // Access column 2 (Receive Time) and convert the date and time format
        $receive_time = DateTime::createFromFormat('m/d/Y H:i', $columns[1]);
        $formatted_receive_time = $receive_time->format('Y/m/d H:i');
        // Modify column 2 in the log
        $columns[1] = $formatted_receive_time;

        // Access column 6 (Generate Time) and convert the date and time format
        $generate_time = DateTime::createFromFormat('m/d/Y H:i', $columns[6]);
        $formatted_generate_time = $generate_time->format('Y/m/d H:i');

        // Modify column 6 in the log
        $columns[6] = $formatted_generate_time;

        // Access column 21 (Time Logged) and convert the date and time format
        $time_logged = DateTime::createFromFormat('m/d/Y H:i', $columns[21]);
        $formatted_time_logged = $time_logged->format('Y/m/d H:i');

        // Modify column 6 in the log
        $columns[21] = $formatted_time_logged;

        // Update the modified line
        $new_lines[$index] = implode(",", $columns);
    }
    $i++;
}

// Write the modified log back to the file
file_put_contents($logFileFixed, implode(PHP_EOL, $new_lines));




