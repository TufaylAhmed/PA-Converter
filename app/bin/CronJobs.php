<?php

function validate_array_is_number($to_validate_array){
    if(isset($to_validate_array) && count($to_validate_array)>0) {
        foreach ($to_validate_array as $validate_number) {
            if ($validate_number!=='' && !is_numeric($validate_number)) {
                exit;
            }
        }
    }
}

function is_day_week($day_of_week){
    if($day_of_week!=="") {
        $days_of_week_list = array("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday");
        if (!in_array($day_of_week, $days_of_week_list, true)) {
            exit();
        }
    }
}

# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';
require_once INC_ROOT.'/bin/Authentication.php';
require_once INC_ROOT.'/libs/shared.php';

include INC_ROOT.'/bin/middleware_sanitizer.php';

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $action     = (string)  (isset($_GET['action'])    ? $_GET['action'] : ''); // upload  / get  /
        $type       = (string)  (isset($_GET['type'])      ? $_GET['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_GET['project'])   ? $_GET['project'] : '');
        //$start      = (integer) (isset($_GET['start'])     ? $_GET['start'] : '');
        //$limit      = (integer) (isset($_GET['limit'])     ? $_GET['limit'] : '');
        $vsys       =           (isset($_GET['vsys'])      ? $_GET['vsys'] : '');
        $source     =           (isset($_GET['source'])    ? $_GET['source'] : '');

        $cron       = (string) (isset($_GET['cron'])       ? $_GET['cron'] : '');
        $type_cron  = (string) (isset($_GET['type_cron'])  ? $_GET['type_cron'] : '');
        $cron_id    = (string) (isset($_GET['cron_id'])    ? $_GET['cron_id'] : '');
        $name_cron  = (string) (isset($_GET['name'])       ? $_GET['name'] : '');

        $rule_lid   = (string) (isset($_GET['rule_lid'])   ? $_GET['rule_lid'] : '');
        //$rule_name  = (string) (isset($_GET['rule_name'])  ? $_GET['rule_name'] : '');

        $id_rule_old= (string) (isset($_GET['id'])         ? $_GET['id'] : '');
        $id         = (string) (isset($_GET['id'])         ? $_GET['id'] : '');
        $ids        =          (isset($_GET['ids'])        ? $_GET['ids'] : '');

        $search     = (string) (isset($_GET['search'])     ? $_GET['search'] : '');

        $filename   = (string) (isset($_GET['filename_file']) ? $_GET['filename_file'] : '');
        $start_date = (string) (isset($_GET['start_date']) ? $_GET['start_date'] : '');
        $start_time = (string) (isset($_GET['start_time']) ? $_GET['start_time'] : '');
        $recurrence = (string) (isset($_GET['recurrence']) ? $_GET['recurrence'] : '');
        $day_of_week= (string) (isset($_GET['day_of_week'])? $_GET['day_of_week'] : '');
        $connector  = (string) (isset($_GET['log_connector']) ? $_GET['log_connector'] : '');
        $disable    = (string) (isset($_GET['disable'])    ? $_GET['disable'] : '');
        break;
    case 'POST':
        $action     = (string)  (isset($_POST['action'])    ? $_POST['action'] : ''); // upload  / get  /
        $type       = (string)  (isset($_POST['type'])      ? $_POST['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_POST['project'])   ? $_POST['project'] : '');
        //$start      = (integer) (isset($_POST['start'])     ? $_POST['start'] : '');
        //$limit      = (integer) (isset($_POST['limit'])     ? $_POST['limit'] : '');
        $vsys       =           (isset($_POST['vsys'])      ? $_POST['vsys'] : '');
        $source     =           (isset($_POST['source'])    ? $_POST['source'] : '');

        $cron       = (string) (isset($_POST['cron'])       ? $_POST['cron'] : '');
        $type_cron  = (string) (isset($_POST['type_cron'])  ? $_POST['type_cron'] : '');
        $cron_id    = (string) (isset($_POST['cron_id'])    ? $_POST['cron_id'] : '');
        $name_cron  = (string) (isset($_POST['name'])       ? $_POST['name'] : '');

        $rule_lid   = (string) (isset($_POST['rule_lid'])   ? $_POST['rule_lid'] : '');
        //$rule_name  = (string) (isset($_POST['rule_name'])  ? $_POST['rule_name'] : '');

        $id_rule_old= (string) (isset($_POST['id'])         ? $_POST['id'] : '');
        $id         = (string) (isset($_POST['id'])         ? $_POST['id'] : '');
        $ids        =          (isset($_POST['ids'])        ? $_POST['ids'] : '');

        $search     = (string) (isset($_POST['search'])     ? $_POST['search'] : '');

        $filename   = (string) (isset($_POST['filename_file']) ? $_POST['filename_file'] : '');
        $start_date = (string) (isset($_POST['start_date']) ? $_POST['start_date'] : '');
        $start_time = (string) (isset($_POST['start_time']) ? $_POST['start_time'] : '');
        $recurrence = (string) (isset($_POST['recurrence']) ? $_POST['recurrence'] : '');
        $day_of_week= (string) (isset($_POST['day_of_week'])? $_POST['day_of_week'] : '');
        $connector  = (string) (isset($_POST['log_connector']) ? $_POST['log_connector'] : '');
        $disable    = (string) (isset($_POST['disable'])    ? $_POST['disable'] : '');
        break;
    default:
        $action     = (string)  (isset($_POST['action'])    ? $_POST['action'] : ''); // upload  / get  /
        $type       = (string)  (isset($_POST['type'])      ? $_POST['type'] : ''); // zip / xml / device
        $project    = (string)  (isset($_POST['project'])   ? $_POST['project'] : '');
        //$start      = (integer) (isset($_POST['start'])     ? $_POST['start'] : '');
        //$limit      = (integer) (isset($_POST['limit'])     ? $_POST['limit'] : '');
        $vsys       =           (isset($_POST['vsys'])      ? $_POST['vsys'] : '');
        $source     =           (isset($_POST['source'])    ? $_POST['source'] : '');

        $cron       = (string) (isset($_POST['cron'])       ? $_POST['cron'] : '');
        $type_cron  = (string) (isset($_POST['type_cron'])  ? $_POST['type_cron'] : '');
        $cron_id    = (string) (isset($_POST['cron_id'])    ? $_POST['cron_id'] : '');
        $name_cron  = (string) (isset($_POST['name'])       ? $_POST['name'] : '');

        $rule_lid   = (string) (isset($_POST['rule_lid'])   ? $_POST['rule_lid'] : '');
        //$rule_name  = (string) (isset($_POST['rule_name'])  ? $_POST['rule_name'] : '');

        $id_rule_old= (string) (isset($_POST['id'])         ? $_POST['id'] : '');
        $id         = (string) (isset($_POST['id'])         ? $_POST['id'] : '');
        $ids        =          (isset($_POST['ids'])        ? $_POST['ids'] : '');

        $search     = (string) (isset($_POST['search'])     ? $_POST['search'] : '');

        $filename   = (string) (isset($_POST['filename_file']) ? $_POST['filename_file'] : '');
        $start_date = (string) (isset($_POST['start_date']) ? $_POST['start_date'] : '');
        $start_time = (string) (isset($_POST['start_time']) ? $_POST['start_time'] : '');
        $recurrence = (string) (isset($_POST['recurrence']) ? $_POST['recurrence'] : '');
        $day_of_week= (string) (isset($_POST['day_of_week'])? $_POST['day_of_week'] : '');
        $connector  = (string) (isset($_POST['log_connector']) ? $_POST['log_connector'] : '');
        $disable    = (string) (isset($_POST['disable'])    ? $_POST['disable'] : '');
        break;
}

//$action = (string) (isset($_POST['action']) ? $_POST['action'] : $_GET['action']); // upload  / get  /
//$type = (string) (isset($_POST['type']) ? $_POST['type'] : $_GET['type']); // zip / xml / device
//$project = (string) (isset($_POST['project']) ? $_POST['project'] : $_GET['project']);
//
//$start = (integer) (isset($_POST['start']) ? $_POST['start'] : $_GET['start']);
//$limit = (integer) (isset($_POST['limit']) ? $_POST['limit'] : $_GET['limit']);
$project = check_sanitize($project);
if ($project != ""){
    require_once INC_ROOT.'/libs/projectdb.php';
}

require_once INC_ROOT.'/libs/database.php';

$vsys = $pandb->real_escape_string($vsys);
$source = $pandb->real_escape_string($source);
$cron = $pandb->real_escape_string($cron);
$type_cron = $pandb->real_escape_string($type_cron);
$name_cron = $pandb->real_escape_string($name_cron);
$search = $pandb->real_escape_string($search);
$filename = $pandb->real_escape_string($filename);
$recurrence = $pandb->real_escape_string($recurrence);
$connector = $pandb->real_escape_string($connector);
$disable = $pandb->real_escape_string($disable);
if(!is_numeric($cron_id)){exit;}
validate_array_is_number(explode(",", $rule_lid));
validate_array_is_number(explode(",", $id_rule_old));
validate_array_is_number(explode(",", $id));
validate_array_is_number(explode(",", $ids));
validate_array_is_number(explode("/", $start_date));
validate_array_is_number(explode(":", $start_time));
is_day_week($day_of_week);

if ($action == "get") {
    if ($type == "cron_jobs") {
//        $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
//        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        /*if($project != ""){
            $sql_project = " WHERE project = '$project'";
        }else{
            $sql_project = "";
        }*/
        
        $getExistCronJobs = $pandb->query("SELECT id, name, type, log_connector, recurrence, day_of_week, start_date, start_time, date_created, date_modification, filename, vsys, source, project, disable FROM cronjobs WHERE project = '$project' AND vsys = '$vsys' AND source = '$source';");
            
        if ($getExistCronJobs->num_rows > 0){
            while($data = $getExistCronJobs->fetch_object()){
                $myData[] = $data;
            }
        }else{
            $myData="";
        } 
        $count = $getExistCronJobs->num_rows;
        echo '{"total":"'.$count.'","cronjobs":'.json_encode($myData).'}';
    }
    elseif($type == "cron_jobs_all"){
        $getExistCronJobs = $pandb->query("SELECT id, name, type, log_connector, recurrence, day_of_week, start_date, start_time, date_created, date_modification, filename, vsys, source, project, disable FROM cronjobs;");
            
        if ($getExistCronJobs->num_rows > 0){
            while($data = $getExistCronJobs->fetch_object()){
                $myData[] = $data;
            }
        }else{
            $myData="";
        } 
        $count = $getExistCronJobs->num_rows;
        echo '{"total":"'.$count.'","cronjobs":'.json_encode($myData).'}';
    }
    elseif($type == "rules_by_cron"){
//        $cron_id = (string) (isset($_POST['cron_id']) ? $_POST['cron_id'] : $_GET['cron_id']);
//        $search = (string) (isset($_POST['search']) ? $_POST['search'] : $_GET['search']);
        
        $getRulesCronJobs = $pandb->query("SELECT rules_lid FROM cronjobs WHERE id = '$cron_id';");
            
        if ($getRulesCronJobs->num_rows > 0){
            
            $dataRC = $getRulesCronJobs->fetch_assoc();
            $rules_lid = $dataRC['rules_lid'];
             
            if($rules_lid != ""){
                if($search == ""){
                    $getNameRules = $projectdb->query("SELECT id, name FROM security_rules WHERE id IN ($rules_lid);");
                    
                    if ($getNameRules->num_rows > 0){
                        while($data = $getNameRules->fetch_object()){
                            $myData[] = $data;
                        }
                    }
                }
                else{
                    $search = str_replace("*", "", $search);
                    $getNameRules = $projectdb->query("SELECT id, name FROM security_rules WHERE id IN ($rules_lid) AND name LIKE '%$search%';");

                    if ($getNameRules->num_rows > 0){
                        while($data = $getNameRules->fetch_object()){
                            $myData[] = $data;
                        }
                    }
                }
            }   
        }
        else{
            $myData="";
        }
        
        $count = $getNameRules->num_rows;
        echo '{"total":"'.$count.'","cronjobs_rule":'.json_encode($myData).'}';
    }
    elseif($type == "all_rules_by_cron"){
//        $vsys = (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
//        $source = (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
        
        if($project){
            $getNameRules = $projectdb->query("SELECT id, name FROM security_rules WHERE source = '$source' AND vsys = '$vsys';");
            
            if ($getNameRules->num_rows > 0){
                while($data = $getNameRules->fetch_object()){
                    $myData[] = $data;
                }
            }
            else{
                $myData="";
            }

            $count = $getNameRules->num_rows;
        }
        else{
            $myData="";
            $count = 0;
        }
        echo '{"total":"'.$count.'","cronjobs_rule_all":'.json_encode($myData).'}';
    }
}
elseif ($action == "set") {
    if ($type == "cron_jobs") {
//        $id = (string) (isset($_POST['id']) ? $_POST['id'] : $_GET['id']);
//        $cron_id = (string) (isset($_POST['cron_id']) ? $_POST['cron_id'] : $_GET['cron_id']);
//        $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
//        $filename = (string) (isset($_POST['filename_file']) ? $_POST['filename_file'] : $_GET['filename_file']);
//        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
//        $name_cron = (string) (isset($_POST['name']) ? $_POST['name'] : $_GET['name']);
//        $start_date = (string) (isset($_POST['start_date']) ? $_POST['start_date'] : $_GET['start_date']);
//        $start_time = (string) (isset($_POST['start_time']) ? $_POST['start_time'] : $_GET['start_time']);
//        $recurrence = (string) (isset($_POST['recurrence']) ? $_POST['recurrence'] : $_GET['recurrence']);
//        $day_of_week = (string) (isset($_POST['day_of_week']) ? $_POST['day_of_week'] : $_GET['day_of_week']);
//        $connector  = (string) (isset($_POST['log_connector']) ? $_POST['log_connector'] : $_GET['log_connector']);
//        $disable = (string) (isset($_POST['disable']) ? $_POST['disable'] : $_GET['disable']);
//        $type_cron = (string) (isset($_POST['type_cron']) ? $_POST['type_cron'] : $_GET['type_cron']);
        
        $getCronExist = $pandb->query("SELECT id, name FROM cronjobs WHERE name = '$name_cron' AND id != '$cron_id';");
        if ($getCronExist->num_rows == 1){
            echo json_encode(array("success"=>false));
        }
        else{
            if($disable == "on"){
                $disable = 1;
            }
            else{
                $disable = 0;
            }
            
            $php_exec = "CronJobsScript.php";
            
            /*if($type_cron == "App-ID Adoption"){
                $php_exec = "CronJobsScript.php";
            }elseif($type_cron == "User-ID Adoption"){
                $php_exec = "CronJobsScript.php";
            }*/
            
            // Add to crontab
            // 1 2 3 4 5 /path/file 
            // 1 (m: 0-59) 
            // 2 (h: 0-23)
            // 3 (d: 1-31)
            // 4 (m: 1-12)
            // 5 (d: 0-6)
            
            $time_today = explode(":", $start_time);
            $date_start = explode("/", $start_date);

            if($time_today[0] == "00"){
                $time_today[0] = "0";
            }
            if($time_today[1] == "00"){
                $time_today[1] = "0";
            }
            if($recurrence == "Daily"){
                
                $command = "$time_today[1] $time_today[0] * * * php -f /var/www/html/bin/$php_exec $cron_id";
            
            }
            elseif($recurrence == "Weekly"){
                if($day_of_week == "Monday"){
                    $day = "1";
                }elseif($day_of_week == "Tuesday"){
                    $day = "2";
                }elseif($day_of_week == "Wednesday"){
                    $day = "3";
                }elseif($day_of_week == "Thursday"){
                    $day = "4";
                }elseif($day_of_week == "Friday"){
                    $day = "5";
                }elseif($day_of_week == "Saturday"){
                    $day = "6";
                }elseif($day_of_week == "Sunday"){
                    $day = "0";
                }
                
                $command = "$time_today[1] $time_today[0] * * $day php -f /var/www/html/bin/$php_exec $cron_id";
                //$command = "*/$time_today[1] $time_today[0] * * $day php -f /var/www/html/bin/CronJobsAppId.php";
                
            }
            elseif($recurrence == "Monthly"){
                $command = "$time_today[1] $time_today[0] $date_start[2] * * php -f /var/www/html/bin/$php_exec $cron_id";
            }
            elseif($recurrence == "Non-recurring"){
                $command = "$time_today[1] $time_today[0] $date_start[2] $date_start[1] * php -f /var/www/html/bin/$php_exec $cron_id";
            }
            
            $pandb->query("UPDATE cronjobs SET name = '$name_cron', log_connector = '$connector', recurrence = '$recurrence', day_of_week = '$day_of_week', start_date = '$start_date', start_time = '$start_time', date_modification = NOW(), filename = '$filename', command = '$command', vsys = '$vsys', source = '$source', project = '$project', disable = '$disable' WHERE id = '$cron_id' ;");
            
            $getTypeCron = $pandb->query("SELECT type FROM cronjobs WHERE id = '$cron_id';");
            if ($getTypeCron->num_rows == 1){
                $dataTC = $getTypeCron->fetch_assoc();
                $type_cron = $dataTC['type'];
            }
            
            add_log_pandb('ok', 'Cron Jobs', 'Cron Job '.$type_cron.': [' . $name_cron . '] has created/modificated on the', 'No Action Required', '2');
    
            $getCrons = $pandb->query("SELECT id, name, command FROM cronjobs WHERE disable = '0';");
            
            if ($getCrons->num_rows >= 1){
                $all_command = "";
                while($getCData = $getCrons->fetch_assoc()){
                    
                    $name = $getCData['name'];
                    $command = $getCData['command'];
                    
                    $all_command .= $command . "\n";
                    //$all_command .= "cd /var/www/html; " . $command . "\n";
                }

                echo $all_command;

                exec('echo -e "`crontab -u apache -l`\n'.$all_command.'" | crontab -', $output);
                //exec('echo -e "`crontab -u apache -l`\n*/1 * * * * php -f /var/www/html/bin/CronJobsAppId.php" | crontab -', $output);
                //exec('echo -e "`crontab -u apache -l`\n*/1 * * * * curl -s https://172.16.200.128/bin/CronJobsAppId.php" | crontab -', $output);
                //exec('echo -e "`crontab -u apache -l`\n*/1 * * * * wget --no-check-certificate https://172.16.200.128/bin/CronJobsAppId.php" | crontab -', $output);
            }
        }
    }
    elseif($type == "rule_lid"){
        $rule_lid = (string) (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']);
        validate_array_is_number(explode(",", $rule_lid));

//        $vsys = (string) (isset($_POST['vsys']) ? $_POST['vsys'] : $_GET['vsys']);
//        $source = (string) (isset($_POST['source']) ? $_POST['source'] : $_GET['source']);
//        $project = (string) (isset($_POST['project']) ? $_POST['project'] : $_GET['project']);
//        $cron = (string) (isset($_POST['cron']) ? $_POST['cron'] : $_GET['cron']);
        
        if($cron != ""){
            $getRulesCron = $pandb->query("SELECT rules_lid FROM cronjobs WHERE name = '$cron';");
        
            $rules_lid_array = array();
            $ids_to_add_array = array();
            $result_rules_lid = array();

            if ($getRulesCron->num_rows == 1){

                $getRCData = $getRulesCron->fetch_assoc();
                $rules_lid = $getRCData['rules_lid'];

                if($rules_lid != ""){
                    $rules_lid_array = explode(",", $rules_lid);
                }

                $ids_to_add_array = explode(",", $rule_lid);

                $result_rules_lid = array_merge($rules_lid_array, $ids_to_add_array);
                $result_rules_lid2 = array_unique($result_rules_lid);

                $ids_result = implode(",", $result_rules_lid2);

                $pandb->query("UPDATE cronjobs SET rules_lid = '$ids_result' WHERE name = '$cron'; ");

                echo json_encode(array("success" => true));
            }
            //$pandb->query("UPDATE cronjobs SET rules_lid = '$ids' WHERE name = '$cron'; ");
        }
    }
}
elseif ($action == "add") {
    if($type == "new_cronjob"){
//        $type_cron = (string) (isset($_POST['type_cron']) ? $_POST['type_cron'] : $_GET['type_cron']);

        $pandb->query("INSERT INTO cronjobs (id, name, type, log_connector, recurrence, day_of_week, start_date, start_time, date_created, date_modification, filename, command, vsys, source, project, disable) values (NULL, '', '$type_cron', '', '', '', '', '00:00', NOW(), NOW(), '', '', '', '', '', '0');");
        $cron_id = $pandb->insert_id;
        
        //echo json_encode(array("success" => $cron_id));
        echo json_encode(array("success"=>true, "msg"=>$cron_id));
    }
    elseif($type == "rules_by_cron"){
//        $rule_lid = (string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']);
//        $rule_name = (string) (isset($_POST['rule_name']) ? $_POST['rule_name'] : $_GET['rule_name']);
//        $cron_id = (string) (isset($_POST['cron_id']) ? $_POST['cron_id'] : $_GET['cron_id']);
        
        $getRulesCron = $pandb->query("SELECT rules_lid FROM cronjobs WHERE id = '$cron_id';");
        
        $rules_lid_array = array();
        $ids_to_add_array = array();
        $result_rules_lid = array();
        
        if ($getRulesCron->num_rows == 1){
            
            $getRCData = $getRulesCron->fetch_assoc();
            $rules_lid = $getRCData['rules_lid'];
            
            if($rules_lid != ""){
                $rules_lid_array = explode(",", $rules_lid);
            }
            
            $ids_to_add_array = explode(",", $rule_lid);
            
            $result_rules_lid = array_merge($rules_lid_array, $ids_to_add_array);
            
            $result_rules_lid2 = array_unique($result_rules_lid);
            $ids_result = implode(",", $result_rules_lid2);
            
            $pandb->query("UPDATE cronjobs SET rules_lid = '$ids_result' WHERE id = '$cron_id'; ");
            
            echo json_encode(array("success" => true));
        }
        
    }
}
elseif ($action == "remove") {
    if($type == "cron_jobs"){
//        $ids = (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']);
        
        $getExistUser = $pandb->query("SELECT id, name FROM cronjobs WHERE id IN ($ids);");
        
        if ($getExistUser->num_rows >= 1){
            while($getEUData = $getExistUser->fetch_assoc()){
                $id = $getEUData['id'];
                $name_cron = $getEUData['name'];
                $pandb->query("DELETE FROM cronjobs WHERE id = '$id';");
                $now = date("F j, Y, g:i a"); 
                add_log_pandb('ok', 'Cron Jobs', 'Cron Job: [' . $name_cron . '] has removed on the '.$now.' ', 'No Action Required', '2');
            }
            
            $getCrons = $pandb->query("SELECT id, name, command FROM cronjobs WHERE disable = '0';");
            
            if ($getCrons->num_rows >= 1){
                $all_command = "";
                while($getCData = $getCrons->fetch_assoc()){
                    $name = $getCData['name'];
                    $command = $getCData['command'];

                    $all_command .= $command . "\n";
                    //$all_command .= "cd /var/www/html; " . $command . "\n";
                }
                exec('echo -e "`crontab -u apache -l`\n'.$all_command.'" | crontab -', $output);
            }else{
                // Delete all cron
                exec('echo -e "`crontab -r -u apache`" | crontab -', $output);
            }
            
            echo json_encode(array("success" => true));
        }
    }
    elseif($type == "rules_by_cron"){
//        $ids = (isset($_POST['ids']) ? $_POST['ids'] : $_GET['ids']);
//        $cron_id = (isset($_POST['cron_id']) ? $_POST['cron_id'] : $_GET['cron_id']);
        
        $getRulesCron = $pandb->query("SELECT rules_lid FROM cronjobs WHERE id = '$cron_id';");
        
        if ($getRulesCron->num_rows == 1){
            $getRCData = $getRulesCron->fetch_assoc();
            $rules_lid = $getRCData['rules_lid'];
            
            $rules_lid_array = explode(",", $rules_lid);
            $ids_remove_array = explode(",", $ids);
            
            $result_rules_lid = array_diff($rules_lid_array, $ids_remove_array);
            
            $ids_result = implode(",", $result_rules_lid);
            
            $pandb->query("UPDATE cronjobs SET rules_lid = '$ids_result' WHERE id = '$cron_id'; ");
            
            echo json_encode(array("success" => true));
        }
    }
}
elseif($action == "update"){
    if($type == "rules_by_cron"){
//        $id_rule_old = (string) (isset($_POST['id']) ? $_POST['id'] : $_GET['id']);
//        $rule_lid = (string) (isset($_POST['rule_lid']) ? $_POST['rule_lid'] : $_GET['rule_lid']);
//        $rule_name = (string) (isset($_POST['rule_name']) ? $_POST['rule_name'] : $_GET['rule_name']);
//        $cron_id = (string) (isset($_POST['cron_id']) ? $_POST['cron_id'] : $_GET['cron_id']);
        
        $getRulesCron = $pandb->query("SELECT rules_lid FROM cronjobs WHERE id = '$cron_id';");
        
        if ($getRulesCron->num_rows == 1){
            $getRCData = $getRulesCron->fetch_assoc();
            $rules_lid = $getRCData['rules_lid'];
            
            if($rules_lid != ""){
                $rules_lid_array = explode(",", $rules_lid);
                if (in_array($rule_lid, $rules_lid_array)){
                    
                    $rules_lid_array = explode(",", $rules_lid);
                    $ids_remove_array = explode(",", $id_rule_old);

                    $result_rules_lid = array_diff($rules_lid_array, $ids_remove_array);

                    $ids_result = implode(",", $result_rules_lid);
                }
                else{
                    $ids_result = str_replace($id_rule_old, $rule_lid, $rules_lid);
                }

                $pandb->query("UPDATE cronjobs SET rules_lid = '$ids_result' WHERE id = '$cron_id'; ");
                echo json_encode(array("success" => true));
            }
        }
    }
}