<?php

class ML_Settings
{
    public $connection = null;

    public function __construct(MySQLi $connection)
    {
        // @var MySQLi
        $this->connection = $connection;
    }

    private function updateCredentials(MySQLi $mysqlDB, string $ml_server, string $oldIP=null){
        // In containerized installs DBServer is a service hostname (e.g. "db") with root@'%'.
        // Creating root@<container-ip> without durable grants breaks subsequent logins (USAGE-only user).
        if (defined('DBServer') && DBServer !== 'localhost' && DBServer !== '127.0.0.1') {
            return;
        }

        //Delete prior credentials to access the MySQL Database from the old ML server
        if(!is_null($oldIP)){
            $mysqlDB->query("DROP USER IF EXISTS '" . DBUser . "'@'$oldIP'; ");
        }

        //Create a user to access to the MySQL Database from the ML server
        $mysqlDB->query("CREATE USER IF NOT EXISTS '".DBUser."'@'$ml_server' IDENTIFIED BY '".DBPass."'; ");
        $mysqlDB->query("GRANT ALL PRIVILEGES ON *.* TO '".DBUser."'@'$ml_server' WITH GRANT OPTION; ");

        //Create a user to access to the MySQL Database from the Published Expedition IP
        if (!empty($_SERVER['SERVER_ADDR'])) {
            $mysqlDB->query("CREATE USER IF NOT EXISTS '".DBUser."'@'".$_SERVER['SERVER_ADDR']."' IDENTIFIED BY '".DBPass."'; ");
            $mysqlDB->query("GRANT ALL PRIVILEGES ON *.* TO '".DBUser."'@'".$_SERVER['SERVER_ADDR']."' WITH GRANT OPTION; ");
        }

        $mysqlDB->query("FLUSH PRIVILEGES;");
    }

    public function get()
    {
        $Data = array();
        //print_r($this->connection, true);
        $getSettings = $this->connection->query("SELECT * FROM ml_settings;");
        if ($getSettings->num_rows > 0) {
            while ($getSettingsData = $getSettings->fetch_assoc()) {
                $Data[] = $getSettingsData;
            }
            //Update the SQL user credentials to connect from the server!
            if(isset($_SERVER['SERVER_ADDR'])) {
                $mysqlDB = new mysqli(DBServer, DBUser, DBPass, "mysql");
                $this->updateCredentials($mysqlDB, $_SERVER['SERVER_ADDR']);
            }
        }
        else{
            $Data[] = [
                "id"            => 0,
                "server"        => $_SERVER['SERVER_ADDR'],
                "parquetPath"   => '/data'
            ];

            $query = "INSERT INTO ml_settings(server) values('".$_SERVER['SERVER_ADDR']."')";
            $this->connection->query($query);
            //Update the SQL user credentials to connect from the server!
            $mysqlDB = new mysqli(DBServer, DBUser, DBPass, "mysql");
            $this->updateCredentials($mysqlDB, $_SERVER['SERVER_ADDR']);
        }

        $getSchedulerSettings = $this->connection->query("SELECT * FROM periodicTasks WHERE processCode='PeriodicLogCollectorCompacter';");
        if ($getSchedulerSettings->num_rows > 0) {
            while ($getSettingsData = $getSchedulerSettings->fetch_assoc()) {
                foreach ($getSettingsData as $key=>$value){
                    $Data[0][$key] = $value;

                }
            }
        }
        else{
            $Data[0]['frequency'] = 'daily';
            $Data[0]['executionTime'] = '00:00';
        }

        $date = new DateTime();
        $timeZone = $date->getTimezone();
        //echo $timeZone->getName();
        $Data[0]['currentTimeZone'] = $timeZone->getName() ; //timedatectl status | grep "Time zone" | awk '{print $3}';
        $time = exec("date | awk '{print $4}'");
        $Data[0]['currentTime'] = $time; //date | awk '{print $4}'

        if(!isset($Data[0]['server']) || $Data[0]['server']=='' || $Data[0]['server']=='127.0.0.1'){
            $Data[0]['server']=trim($_SERVER['SERVER_ADDR']);
            $query = "UPDATE ml_settings SET server='".$this->connection->real_escape_string($Data[0]['server'])."'";
            $this->connection->query($query);
        }

        $message = array();
        $message['code'] = true;
        $message['count'] = count($Data);
        $message['msg'] = $Data;
        return $message;
    }


    public function set(ARRAY $params)
    {
        global $app;

        $mysqlDB = new mysqli(DBServer, DBUser, DBPass, "mysql");
        $message = array();
        $ml_server = (!isset($params['ml_server']) || $params['ml_server']=="" OR $params['ml_server']=="localhost" || $params['ml_server']=="127.0.0.1")? $_SERVER['SERVER_ADDR']: trim($params['ml_server']);
        $parquetPath =  (!isset($params['parquetPath'])  || $params['parquetPath']=="")?  "/data": $this->clean_path($params['parquetPath']);
        $tempDataPath = (!isset($params['tempDataPath']) || $params['tempDataPath']=="")? $parquetPath: $this->clean_path($params['tempDataPath']);

        $oldIP = null;

        $exists = $this->connection->query("SELECT * FROM ml_settings;");
        if ($exists->num_rows == 0) {
            $this->connection->query("INSERT INTO ml_settings (server, parquetPath, tempDataPath) VALUES ('$ml_server','$parquetPath','$tempDataPath')");
        }
        else {
            $existsData = $exists->fetch_assoc();
            $id = $existsData['id'];
            $oldIP = $existsData['server'];
            $this->connection->query("UPDATE ml_settings SET server='$ml_server', parquetPath='$parquetPath', tempDataPath='$tempDataPath' WHERE id='$id';");
        }

        $this->updateCredentials($mysqlDB, $ml_server, $oldIP);

        //Update the schedule settings
        $exists = $this->connection->query("SELECT * FROM periodicTasks WHERE processCode='PeriodicLogCollectorCompacter';");
        $autoProcessFrequency = isset($params['frequency']) ? $params['frequency'] : "daily";
        $executionTime = isset($params['executionTime']) ? $params['executionTime'] : "2008-01-01T09:00:00.000Z";
        $myDateTime = new DateTime($executionTime);

        //Get System's timezone
        $timezone = 'UTC';
        if (is_link('/etc/localtime')) {
            // Mac OS X (and older Linuxes)
            // /etc/localtime is a symlink to the
            // timezone in /usr/share/zoneinfo.
            $filename = readlink('/etc/localtime');
            if (strpos($filename, '/usr/share/zoneinfo/') === 0) {
                $timezone = substr($filename, 20);
            }
        }
        elseif (file_exists('/etc/timezone')) {
            // Ubuntu / Debian.
            $data = file_get_contents('/etc/timezone');
            if ($data) {
                $timezone = $data;
            }
        }
        elseif (file_exists('/etc/sysconfig/clock')) {
            // RHEL / CentOS
            $data = parse_ini_file('/etc/sysconfig/clock');
            if (!empty($data['ZONE'])) {
                $timezone = $data['ZONE'];
            }
        }
        $timezone = trim(trim(preg_replace('/\s\s+/', '', $timezone)));
        date_default_timezone_set($timezone);
        $system_TimeZone = new DateTimeZone($timezone);

        $gmtTimezone = new DateTimeZone('GMT');
        $date = new DateTime($executionTime,$gmtTimezone);
        $date->setTimezone($system_TimeZone);
        $execTime = $date->format('H:i:s');

        $me = $app->sentinel->getUser();
        $userID=$me->id;

        if ($exists->num_rows == 0) {
            $this->connection->query("INSERT INTO periodicTasks (frequency, processCode, params, description, executionTime, active, createdBy, created_At, updated_at) 
                                                                VALUES ('$autoProcessFrequency','PeriodicLogCollectorCompacter','{}','Convert CSV to parquet on a scheduled basis','$execTime',1,$userID,now(), now())");
        }
        else {
            $query = "UPDATE pandbRBAC.periodicTasks 
                                            SET frequency='$autoProcessFrequency', 
                                                executionTime='$execTime', 
                                                active=1, 
                                                createdBy=$userID,
                                                updated_at=now(),
                                                started_at='',
                                                completed_at='';";
            $this->connection->query($query);
        }

        $message['code'] = true;
        $message['msg'] = "Saved OK.";
        return $message;
    }

    private function clean_path(String $path){
        $string = rtrim($path, DIRECTORY_SEPARATOR); //Removes "//" at the end of the string.
        $string = trim($string);
        return $string;
    }


    public function checkAlive(){
        $Data = array();
        $getSettings = $this->connection->query("SELECT * FROM ml_settings;");
        if ($getSettings->num_rows > 0) {
            while ($getSettingsData = $getSettings->fetch_assoc()) {
                $Data[] = $getSettingsData;
            }
        }

        if(!isset($Data[0]['server']) || $Data[0]['server']=='' || $Data[0]['server']=='127.0.0.1'){
            $message = [

            ];
        }
        else{
            $ExpeditionML = $Data[0]['server'];
            $url = "https://$ExpeditionML/API/process/checkAlive.php";
            $tuCurl = curl_init();
            curl_setopt($tuCurl,CURLOPT_URL,$url);
            curl_setopt($tuCurl,CURLOPT_RETURNTRANSFER,true);
            curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, 0);
            curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, 0);
            curl_setopt($tuCurl, CURLOPT_CONNECTTIMEOUT, 2);
            $output=curl_exec($tuCurl);
            $message = json_decode($output);
        }

        return $message;
    }

}

