<?php

/***
 * This scrip performs the following tasks:
 * Step 1- Read given CSV file with named objects
 * Step 2- Get the ids from the given named objects
 * Step 3- Create or get the TAG id
 * Step 4- Assign the TAG to the loaded objects in step 2
 */
$_SERVER['DOCUMENT_ROOT'] = '/var/www/html';
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
require_once INC_ROOT.'/libs/projectdb.php';
require_once INC_ROOT .'/userManager/API/accessControl_CLI.php';
require_once INC_ROOT.'/libs/common/tools/tools.php';


$string_csv = "Entity name;Table name;Column name;Operator name\n";

// get all possible tables
$projectDB = selectDatabase("cisco");
$tools_where = $projectDB->query("SELECT * FROM tools_where;");
while($table = $tools_where->fetch_assoc()){
    //$table['name'];
    $columns =  explode("," , $table['tools_where_columns_id']);
    // get all columns for that table
    foreach ($columns as $field){
        $tools_where_columns = $projectDB->query("SELECT * FROM tools_where_columns where id = '$field';");
        while($table_column = $tools_where_columns->fetch_assoc()){
            $table_column["name"];
            $operators =  explode("," , $table['tools_operator_id']);
            foreach ($operators as $operator){
                $tools_operator = $projectDB->query("SELECT * FROM tools_operator where id = '$operator';");
                while($table_column_operator = $tools_operator->fetch_assoc()){
                    $table_column_operator["name"];
                    $string_csv.= "". $table['name'] . ";" . $table['table_name'] .";".$table_column["name"] . ";". $table_column_operator["name"] ."\n";
                }
            }
        }
    }
}

file_put_contents("/tmp/csv", $string_csv);





