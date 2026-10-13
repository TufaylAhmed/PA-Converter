<?php

// v4.  Fix the order of the order of the fields.
// v3.  Now the script is calculating the average by the day of the week. So each day of the week has its own average.
// v2.  Fixing duplicated lines
//      Adding column day of the week but also skipping weekends from potential traffic lost per day

$_SERVER['DOCUMENT_ROOT'] = '/var/www/html';
require_once $_SERVER['DOCUMENT_ROOT'] . '/libs/common/definitions.php';
require_once INC_ROOT . '/libs/projectdb.php';
require_once INC_ROOT . '/userManager/API/accessControl_CLI.php';
require_once INC_ROOT . '/libs/common/tools/tools.php';

// ***************                   USER VARIABLES                   ***************
$user = "admin"; // user to execute the script

// CODE STARTS HERE

class LogAnalysisStatus
{
    /* @var $projectName String */
    protected $projectName = 'pandbRBAC';

    /* @var mysqli $projectDB */
    protected $projectDB = null;

    protected $error = false;
    protected $errorMessage = '';


    public function __construct(string $name, array $params)
    {
        global $app;

        if ($user = $app->container->sentinel->findByCredentials(['email' => $params['user']])) {
            $app->sentinel->login($user);
        } else {
            $this->error = true;
            $this->errorMessage = 'User not found';
        }


        if($name!="") {
            $this->projectName = $name;
        }
        $this->projectDB = selectDatabase($this->projectName);
        //echo "\n Auto saving snapshot\n";
        //take_snapshot_last($this->projectName);

    }

    private function get_missing_days($dates){

        sort($dates);

        $filledDates = array();

        for ($i = 0; $i < count($dates) - 1; $i++) {
            $currentDate = strtotime($dates[$i]);
            $nextDate = strtotime($dates[$i + 1]);

            while ($currentDate < $nextDate) {
                $filledDates[] = date('Y-m-d', $currentDate);
                $currentDate = strtotime('+1 day', $currentDate);
            }
        }

        $filledDates[] = $dates[count($dates) - 1]; // Add the last date from the original array

        return $filledDates;

    }

    public function execute()
    {

        if ($this->error) {
            echo $this->errorMessage . "\n";
            exit(-1);
        }

        echo "Gathering disk space data:" . PHP_EOL;
        // Execute the shell command
        $command = 'df -h';
        $output = shell_exec($command);

        // Split the output into lines
        $lines = explode("\n", trim($output));

        // Create a new CSV file
        $csvFile = fopen('/tmp/df_status_'.date('Y-m-d').'.csv', 'w');

        $is_header = true;
        // Write the output to the CSV file
        foreach ($lines as $line) {
            // Split each line into columns
            $columns = preg_split('/\s+/', $line);

            if($is_header){
                // remove the last field for header column
                array_pop($columns);
                $is_header = false;
            }

            // Write the columns to the CSV file
            fputcsv($csvFile, $columns);
        }

        // Close the CSV file
        fclose($csvFile);

        echo "\tWriting CSV file: /tmp/df_status_".date('Y-m-d').".csv". PHP_EOL;

        echo "Gathering log analysis data:" . PHP_EOL;

        // defining dictionary
        $daysOfWeekDic = [
            0 => 'Sunday',
            1 => 'Monday',
            2 => 'Tuesday',
            3 => 'Wednesday',
            4 => 'Thursday',
            5 => 'Friday',
            6 => 'Saturday'
        ];

        // get the devices
        $query = "SELECT * from devices where active = 1;";
        $devices_data = $this->projectDB->query($query);
        $devices_map = array();

        // prepare devices map
        while ($device_fetch = $devices_data->fetch_assoc()) {
            $devices_map[] = $device_fetch;
        }

        $logs_map = array();
        $csv = "log_missing,log_date,device_name,hits,avg_hits,day_of_week,potential_daily_traffic_lost" . PHP_EOL;

        // foreach device get the latest 30d analysed logs
        foreach ($devices_map as $device){

            $query= "SELECT serial, date, sum(hits) as hits FROM device_logsPerDay 
                        where serial in ('".$device['serial']."','".$device['serialHA']."')
                        group by date
                        order by date desc
                        LIMIT 30";
            $logs_data = $this->projectDB->query($query);

            // Preparing structure to save the hits per week day
            $hits[0] = 0;
            $hits[1] = 0;
            $hits[2] = 0;
            $hits[3] = 0;
            $hits[4] = 0;
            $hits[5] = 0;
            $hits[6] = 0;

            // Preparing structure to save the days per week day
            $days_per_day[0] = 0;
            $days_per_day[1] = 0;
            $days_per_day[2] = 0;
            $days_per_day[3] = 0;
            $days_per_day[4] = 0;
            $days_per_day[5] = 0;
            $days_per_day[6] = 0;

            $days= 0;

            while ($logs_fetch = $logs_data->fetch_assoc()) {
                $logs_map[$device['devicename']]['data'][date("Y-m-d",strtotime($logs_fetch['date']))] = [$logs_fetch['date'],$logs_fetch['hits']];
                $dayOfWeek = date('w', strtotime(date("Y-m-d",strtotime($logs_fetch['date']))));
                $days++;
                $hits[$dayOfWeek]+=$logs_fetch['hits']; // sum the hits per day week
                $days_per_day[$dayOfWeek]++; // sum the number of days per week
            }

            if(isset($logs_map[$device['devicename']]['data'])) {

                $logs_map[$device['devicename']]['days'] = $days;
                $logs_map[$device['devicename']]['total_hits'] = array_sum(array_values($hits));
                //$logs_map[$device['devicename']]['avg_hits'] = round($hits / $days, 0);

                $logs_range = array_keys($logs_map[$device['devicename']]['data']);

                $all_days = $this->get_missing_days($logs_range);
                sort($all_days);
                //print_r($logs_range);
                //print_r($all_days);

                foreach ($all_days as $log_day){

                    $device_name_l = $device['devicename'];
                    $day_l = $log_day;
                    $dayOfWeek = date('w', strtotime($day_l));
                    $log_missing_l = isset($logs_map[$device['devicename']]['data'][$day_l])?0:1;
                    if(!$log_missing_l){
                        $log_hits_l =  $logs_map[$device['devicename']]['data'][$day_l][1];
                        $avg_per_day_l = round($hits[$dayOfWeek] / $days_per_day[$dayOfWeek], 0);
                        //$avg_per_day_l = $logs_map[$device['devicename']]['avg_hits'];
                    }else{
                        $log_hits_l = 0;
                        $avg_per_day_l = 1;
                    }

                    $tolerance = 0.3; // % tolerance
                    $upperLimit = $avg_per_day_l * (1 + $tolerance);
                    $lowerLimit = $avg_per_day_l * (1 - $tolerance);

                    if ($log_hits_l > $upperLimit || $log_hits_l < $lowerLimit) {
                        $potential_traffic_lost = 1;
                    } else {
                        $potential_traffic_lost = 0;
                    }


                    $csv.=$log_missing_l.",".$day_l.",".$device_name_l.",".$log_hits_l.",".$avg_per_day_l.",".$daysOfWeekDic[$dayOfWeek].",".$potential_traffic_lost.PHP_EOL;

                }

            }

        }
        echo "\tWriting CSV file: /tmp/log_analysis_status_".date('Y-m-d').".csv" . PHP_EOL;
        // echo $csv;
        file_put_contents("/tmp/log_analysis_status_".date('Y-m-d').".csv", $csv);

        if ($this->error) {
            echo PHP_EOL . PHP_EOL . $this->errorMessage;
        }
        echo PHP_EOL . PHP_EOL . "Script finished" . PHP_EOL . PHP_EOL;
        exit(1);

    }

}

global $app;


echo "Script started " . PHP_EOL . PHP_EOL;
$params = [
    'user' => $user,
];
$executor = new LogAnalysisStatus('', $params);
$executor->execute();

echo "Done " . PHP_EOL;