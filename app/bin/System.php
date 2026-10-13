<?php

# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
require_once('./Authentication.php');
require_once INC_ROOT.'/libs/database.php';
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';
require_once INC_ROOT.'/libs/shared.php';

include INC_ROOT.'/bin/middleware_sanitizer.php';

$action = $pandb->real_escape_string((string) (isset($_POST['action']) ? $_POST['action'] : $_GET['action']));
$type = $pandb->real_escape_string((string) (isset($_POST['type']) ? $_POST['type'] : $_GET['type']));

//session_start();

if ($action == "restart") {
    
    unset($_SESSION['authenticated']);
    unset($_SESSION['username']);
    unset($_SESSION['timezone']);
    session_destroy();
    
    //shell_exec("sudo systemctl reboot");
} 
elseif ($action == "shutdown") {
    
    unset($_SESSION['authenticated']);
    unset($_SESSION['username']);
    unset($_SESSION['timezone']);
    session_destroy();
    
    //shell_exec("sudo systemctl poweroff");
} 
elseif ($action == "clean_system_logs") {
    #shell_exec("rm -rf /var/log/httpd/*");
    #shell_exec("rm -rf /var/log/messages");
    echo json_encode(array('success' => true));
} 
elseif ($action == "restart_database") {
    $out = shell_exec("(sudo systemctl restart mariadb.service)&");
    echo json_encode(array('success' => true));
} 
elseif ($action == "get") {
    if ($type == "timezone") {
        
        if (function_exists("timezone_identifiers_list")){
            //$arr_timez_id_lst4 = DateTimeZone::listIdentifiers(DateTimeZone::EUROPE);
            $arr_timez_id_lst4 = DateTimeZone::listIdentifiers(DateTimeZone::ALL);

            $arr_time_zone = array();
            foreach($arr_timez_id_lst4 as $timz4) {
                $arr_time_zone[]["name"] = $timz4;
            }
            $count = count($arr_timez_id_lst4);
            
            echo '{"total":"'.$count.'","timezone":'.json_encode($arr_time_zone).'}';

        }
        
    }elseif($type == "date"){
        
        $getDate = $pandb->query("SELECT NOW() AS time, timezone FROM users LIMIT 1 ;");
        
        if ($getDate->num_rows == 1){
            $getDateData = $getDate->fetch_object();
            $myData[] = $getDateData;
        }
        $count = $getDate->num_rows;
       
        echo '{"total":"'.$count.'","date":'.json_encode($myData).'}';
        
        
        
    }
}
elseif ($action == "set") {
    if ($type == "date") {
        
        $start_date = $pandb->real_escape_string((string) (isset($_POST['start_date_today']) ? $_POST['start_date_today'] : $_GET['start_date_today']));
        $start_time = $pandb->real_escape_string((string) (isset($_POST['start_time_today']) ? $_POST['start_time_today'] : $_GET['start_time_today']));
        $timezone = $pandb->real_escape_string((string) (isset($_POST['timezone']) ? $_POST['timezone'] : $_GET['timezone']));
        
        if($timezone == ""){
            
            $getDate = $pandb->query("SELECT timezone FROM users LIMIT 1 ;");
        
            if ($getDate->num_rows == 1){
                $getDateData = $getDate->fetch_assoc();
                $timezone = $getDateData['timezone'];
            }
            if($timezone == ""){
                $timezone = 'America/Los_Angeles';
            }
        }
        $pandb->query("UPDATE users SET timezone = '$timezone';");
        
        $_SESSION['timezone'] = $timezone;
           
        date_default_timezone_set($_SESSION['timezone']);
        
        $date_today = explode("/", $start_date);
        $time_today = explode(":", $start_time);
        //echo "Fecha parseada: ".$date_today[0]." " .$date_today[1]. " " .$date_today[2]."\n";
        
        $parser_date = escapeshellarg($date_today[1].$date_today[2].$time_today[0].$time_today[1].$date_today[0]);
        //echo "Paser day: " .$parser_date. "\n";
        //shell_exec("sudo date 061710082015");

        shell_exec("sudo date " . $parser_date);
        shell_exec("sudo hwclock --systohc");
        
        //echo "Dentro de system: " .date_default_timezone_get()."\n";
        
        $pandb->query("UPDATE users SET timezone = '$timezone';");
        $pandb->query("UPDATE users SET last_session = NOW() WHERE user = 'admin';");
        
        //$now = date("F j, Y, H:i");
        //$now = date();
        
        $user = $_SESSION['username'];
        
        add_log_pandb('ok', 'Date Configuration', 'User: [' . $user . '] has changed the date on the', 'No Action Required', '2');
        
        echo json_encode(array("success" => true));
        
        
        
        
    }
}
?>
