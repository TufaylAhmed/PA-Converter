<?php

# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';

require_once INC_ROOT.'/libs/database.php';

global $pandb;

include INC_ROOT.'/bin/middleware_sanitizer.php';
    
//append_cronjob('*/5 * * * * php /var/www/html/bin/CronJobsReports.php '.$name_cron.' > /dev/null 2>&1');
//exec("crontab -r -u apache");


$pandb->query("UPDATE cronjobs SET disable = '1' ;");


//$getCronAll = $pandb->query("SELECT id, name, type, log_connector, recurrence, day_of_week, start_date, DATEDIFF(NOW(), start_date) AS days, start_time, date_created, date_modification, NOW() AS now, filename, vsys, source, project FROM cronjobs WHERE disable = '0' AND checked = '0';");
$getCronAll = $pandb->query("SELECT id, name, type, log_connector, recurrence, day_of_week, start_date, DATEDIFF(NOW(), start_date) AS days, start_time, date_created, date_modification, NOW() AS now, filename, vsys, source, project FROM cronjobs WHERE disable = '0' AND checked = '0';");

//$command = "5 * * * * php /var/www/html/bin/CronJobsDemon.php > /dev/null 2>&1";

if ($getCronAll->num_rows >= 1){
    
    while($getCAData = $getCronAll->fetch_assoc()){
    
        $id = $getCAData['id'];
        $name_cron = $getCAData['name'];
        $recurrence = $getCAData['recurrence'];
        $day_of_week = $getCAData['day_of_week'];
        $start_date = $getCAData['start_date'];
        $start_time = $getCAData['start_time'];
        $days = $getCAData['days'];
        $type = $getCAData['type'];
        $log_connector = $getCAData['log_connector'];
        $filename = $getCAData['filename'];
        $vsys = $getCAData['vsys'];
        $source = $getCAData['source'];
        $project = $getCAData['project'];

        if($recurrence == "Daily"){
            
            if($days >= "0"){
                
                // Add to crontab
                // 1 2 3 4 5 /path/file 
                // 1 (m: 0-59) 
                // 2 (h: 0-23)
                // 3 (d: 1-31)
                // 4 (m: 1-12)
                // 5 (d: 0-6)
                $time_today = explode(":", $start_time);
                
                $command = "$time_today[1] $time_today[0] * * * php /var/www/html/bin/CronJobsTask.php $name_cron";
                
                // TE HAS QUEDADO AQUÍ --> NO SÉ PQ NO ACTUALIZA EL CRON!!
                
                //echo "Command: " .$command. "\n";

               
                $command = "5 * * * * php /var/www/html/bin/CronJobsDemon.php > /dev/null 2>&1"
 
                        . "\n*/5 * * * * php /var/www/html/bin/CronJobsReports33.php CronAle2 >/dev/null 2>&1 "
                        . "\n*/5 * * * * php /var/www/html/bin/CronJobsReports2.php CronAle2 >/dev/null 2>&1";
                

                //exec('echo -e "`crontab -u apache -l`\n'.$command.'" | crontab -', $output); 
                //exec('echo -e "`crontab -u apache -l`\n*/* * * * * php /var/www/html/bin/CronJobsTask.php" | crontab -', $output);
                

                $pandb->query("UPDATE cronjobs SET checked = '1' WHERE id = '$id' ;");

            }
            
        }

    }
    // ESTE FUNCIONA!!!!!
       


}


//$command = "*/5 * * * * php /var/www/html/bin/CronJobsReports33.php CronAle2 >/dev/null 2>&1 "
//        . "\n*/5 * * * * php /var/www/html/bin/CronJobsReports2.php CronAle2 >/dev/null 2>&1";




 //$fp = fopen("/var/www/html/crontab.txt","a");
//fwrite($fp, "*/5 * * * * php /var/www/html/bin/CronJobsReports.php CronAle2 > /var/www/html/cron_mt.txt" . PHP_EOL);
//fwrite($fp, "hola" . PHP_EOL);
//fclose($fp);
//$cmd = "crontab -u apache /var/www/html/crontab.txt";
//exec($cmd);
//echo "Apped cron file: " .$append_cronfile."\n";
//$out = shell_exec($append_cronfile);
//shell_exec("echo '*/5 * * * * php /var/www/html/bin/CronJobsReports.php CronAle2 > /var/www/html/cron_mt.txt'  >> /var/www/html/crontab.txt");
//$output = shell_exec('sudo crontab -l');
//echo "Output: ".$output;
//file_put_contents('/var/www/html/crontab.txt', $output.'*/5 * * * * php /var/www/html/bin/CronJobsReports.php CronAle2'.PHP_EOL);
//$install_cron = "crontab $cron_file";
//echo "Install cron file: " .$install_cron."\n";
//shell_exec($install_cron);
//shell_exec('crontab /var/www/html/crontab.txt');
//$output = shell_exec('crontab -l');
//file_put_contents('/tmp/crontab.txt', $output.'* * * * * NEW_CRON'.PHP_EOL);
//echo exec('crontab /tmp/crontab.txt');
    





