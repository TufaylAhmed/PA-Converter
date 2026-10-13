<?php
/*******************************************************************************
 * Copyright (c) 2018 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: 2018-03-13 12:22
 ******************************************************************************/

//Loads all global PHP definitions
require_once '/var/www/html/libs/common/definitions.php';

//Dependencies
require_once INC_ROOT.'/libs/projectdb.php';
require_once INC_ROOT.'/libs/database.php';

$databasesToCheck = [
    "pandb", "pandbRBAC", "RealTimeUpdates", "project_schema", "BestPractices", "BestPracticesInternal"
];
$globalConnector = selectDatabase("mysql");
$databases = array();

//Listing the list of databases
$query = "SELECT SCHEMA_NAME AS `Database` FROM INFORMATION_SCHEMA.SCHEMATA";
$results = $globalConnector->query($query);

if($results->num_rows>0){
    while($entry = $results->fetch_assoc()){
        $databases[] = $entry['Database'];
    }

    $mask = "| %-25.24s | %-15.15s | %-22.22s |\n";
    printf($mask, "- - - - - - - - - - - - - - - - -", '- - - - - - - - ','- - - - - - - - - - -');
    printf($mask, 'DATABASE', 'CHECK RESULT','ACTION');
    printf($mask, "- - - - - - - - - - - - - - - - -", '- - - - - - - - ','- - - - - - - - - - -');
    foreach ($databasesToCheck as $databaseToCheck) {
        if (!in_array("$databaseToCheck", $databases)) {
            //Create the pandbRBAC database
            $sql = "CREATE DATABASE " . $databaseToCheck;
            $globalConnector->query($sql);

            $mysql_file = create_mysql_file();
            //$Command = "mysql -u".DBUser." -p".DBPass." $databaseToCheck < ".INC_ROOT."/OS/SQL/".$databaseToCheck.".sql";
            $Command = "mysql --defaults-extra-file=$mysql_file $databaseToCheck < ".INC_ROOT."/OS/SQL/".$databaseToCheck.".sql";
            exec($Command);
            delete_mysql_dump_file($mysql_file);

            printf($mask, $databaseToCheck, 'missing',' Database created');
        }
        else {
            printf($mask, $databaseToCheck, 'passed','');
        }
    }
    printf($mask, "- - - - - - - - - - - - - - - - -", '- - - - - - - - ','- - - - - - - - - - -');


}
else{
    echo "Error connecting to DB Server\n";
}
