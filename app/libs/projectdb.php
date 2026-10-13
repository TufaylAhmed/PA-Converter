<?php
# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.

//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

if (! defined('DBSQL_LOG_BIN')) {
    define('DBSQL_LOG_BIN', 1);
}

//if ($project!=""){
//    $projectdb=new mysqli(DBServer, DBUser, DBPass, $project);
//    if ($projectdb->connect_error) {
//        trigger_error('Database connection failed: '  . $projectdb->connect_error, E_USER_ERROR);
//    }
//}
//else {
//    echo json_encode(array('success'=>false,'message'=>'No Project Selected')); exit(0);
//}

function selectDatabase($project){

    $project = htmlspecialchars($project);
    if(strtoupper($project)!="PANDB" && strtoupper($project)!="PANDBRBAC" && strtoupper($project)!="BESTPRACTICES" && strtoupper($project)!="REALTIMEUPDATES") {
        if (!is_dir("/home/userSpace/projects/" . $project)) {
            echo json_encode(array('success'=>false,'message'=>'Invalid Project Selected'));
            exit;
        }
    }

    if(defined('DBSERVER') && DBServer == 'localhost'){
        define('DBServer','127.0.0.1');
    }

    if($project!="") {
//        $projectdb = new mysqli('p:'.DBServer, DBUser, DBPass, $project);
        $projectdb = new mysqli(DBServer, DBUser, DBPass, $project);

        $projectdb->ping();
//        echo $projectdb->host_info;
        // Maybe the mysqli connection is being recycled. Check that it is stil alive. If not, close it an try to open again
//        if (!$projectdb->ping()) {
//            echo "SelectDatabase: ".$projectdb->connect_error."\n";
//            echo "Closing the connection\n";
//            $projectdb = mysqli_init();
//            echo "Opening it again\n";
//            $projectdb = $projectdb->real_connect(DBServer, DBUser, DBPass, $project);
//            echo "SelectDatabase: ".$projectdb->connect_error."\n";
//        }

        if ($projectdb->connect_error) {
            trigger_error('Database connection failed', E_USER_ERROR);
        }
        $projectdb->query("set sql_log_bin = ".DBSQL_LOG_BIN);

        // Below overrides on default configs are useful when running large migrations
        if (!defined('GLOBAL_connect_timeout')) {
            define('GLOBAL_connect_timeout','10');
        }
        $projectdb->query("SET @@GLOBAL.connect_timeout = ". GLOBAL_connect_timeout);

        if (!defined('GLOBAL_wait_timeout')) {
            define('GLOBAL_wait_timeout','28800');
        }
        $projectdb->query("SET @@GLOBAL.wait_timeout = ". GLOBAL_wait_timeout);

        if (!defined('GLOBAL_interactive_timeout')) {
            define('GLOBAL_interactive_timeout','28800');
        }
        $projectdb->query("SET @@GLOBAL.interactive_timeout = ". GLOBAL_interactive_timeout);

        if (!defined('GLOBAL_max_allowed_packet')) {
            define('GLOBAL_max_allowed_packet','104857600');
        }
        $projectdb->query("SET @@GLOBAL.max_allowed_packet = ". GLOBAL_max_allowed_packet);

        if (!defined('GLOBAL_max_connections')) {
            define('GLOBAL_max_connections','200');
        }
        $projectdb->query("SET @@GLOBAL_max_connections = ". GLOBAL_max_connections);

        return $projectdb;
    }
    else {
        echo json_encode(array('success'=>false,'message'=>'No Project Selected')); exit(0);
    }
}

function get_pdo($project)
{
    try {
        // Create a new PDO instance
        $conn = new PDO("mysql:host=".DBServer.";dbname=$project", DBUser, DBPass);

        // Set PDO error mode to exception
        $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        return $conn;
    } catch (PDOException $e) {
        echo "Connection failed while getting the pdo";
    }
}
//global $projectdb;
//$projectdb = selectDatabase($project);

function is_error_db($project_db, $print_error=true)
{
    $error_list = $project_db->error_list;
    if (isset($error_list) && count($error_list)>0) {
        if($print_error) {
            $error_list_unique = array_unique($error_list, SORT_REGULAR);
            foreach ($error_list_unique as $error_item) {
                echo "MySQL error:[".$error_item['errno']."] " . $error_item['error'] . "\n";
            }
        }
        return true;
    }
    return false;
}

function renew_DBConnection(){
    global $projectdb;
    global $project;
    if(isset($project)) {
        $projectdb = selectDatabase($project);
    }
}