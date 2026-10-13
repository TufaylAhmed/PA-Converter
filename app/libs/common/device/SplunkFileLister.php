<?php
/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: $today.year.hour.minute
 ******************************************************************************/

namespace PaloAltoNetworks\Sentinel\Devices;

require_once INC_ROOT.'/libs/settings/ML_Settings.php';
require_once INC_ROOT.'/libs/common/device/CSFilesStates.php';
require_once INC_ROOT.'/libs/projectdb.php';

require_once INC_ROOT.'/bin/messaging/MessageSender.php';

require_once INC_ROOT.'/libs/cpu_status_functions.php';
getEnvironmentParameters();

class SplunkFileLister
{
    private $serials;
    private $deviceName;
    private $path;

    public function __construct(STRING $serials, STRING $path=null){
        $this->serials = explode(",",$serials);
        $this->path = $path;
    }


    /***
     * @return array
     */
    public function list_Files()
    {
        global $app;

        $new = [];
        $processed = [];
        $ignored = [];
        $files = [];

        $pandbRBAC = selectDatabase('pandbRBAC');

        /** @var $device Device */
        $device = null;
        $knownDevices = [];
        $unknownDevices = [];
        foreach ($this->serials as $serial) {
            if ($serial != '') {
                if (!$device = $app->device->where('serial', '=', $serial)->where(function ($query) {
                        $query->where('logtype', '=', 'csv')->orWhere('logtype', '=', '');
                    })->get()->first()) {
                    $unknownDevices[] = $serial;
                }
                else {
                    $knownDevices[] = $device;
                }
            }
        }

        if (count($knownDevices) == 0) {
            return [
                "code" => true,
                "errorMessage" => "Devices not found",
                'news' => array(),
                'ignored' => array(),
                'processed' => array(),
                "msg" => []
            ];
        }

        $errorMessages = array();

        foreach ($knownDevices as $device) {
            if (!is_null($device)) {
                if ($device->logtype == "csv" || $device->logtype == "") {
                    $query = "SELECT id, log_name, DATE_FORMAT(date,'%Y-%m-%d') as date, status, device_serial, DATE_FORMAT(updated_at,'%Y-%m-%d') as processed, comment FROM splunk_files WHERE device_serial in ('" . implode("','", $this->serials) . "') ORDER BY date;";
                    $results = $pandbRBAC->query($query);
                    if ($results->num_rows > 0) {
                        while ($data = $results->fetch_assoc()) {
                            $data['devicename'] = $device->devicename;
                            $files[] = $data;
                            switch ($data['processed']) {
                                case 'processed':
                                    $processed[] = $data;
                                    break;
                                default:
                                    $new[] = $data;
                                    break;
                            }
                        }
                    }

                }
            }
        }

        return [
            "code"          => true,
            "msg"           => $files,
            "news"          => $new,
            "ignored"       => $ignored,
            "processed"     => $processed,
            "errorMessage"  => implode(",", $errorMessages)
        ];
    }

    public function create(STRING $ip, STRING $port, STRING $userName, STRING $password, ARRAY $dates, STRING $path ='/tmp', STRING $index="", STRING $version=""){
        global $app;
        if ($index!=''){
            $indexOption = "index=$index";
        }
        else{
            $indexOption = '';
        }

        if($path != '/tmp'){
            preg_match('/(.*)\/(.*)\*(.*)/', $path, $output_array);
            $path = $output_array[1];
        }

        //Verify the path is writeable
        if (!is_dir($path)) {
            return [
                'success'   => false,
                'affected_rows' => "$path is not existing or writeable",
            ];
        }


        $inserts = [];
        foreach ($this->serials as $serial) {
            if (!$device = $app->device
                ->where('serial', '=', $serial)
                ->where(function ($query) {
                    $query->where('logtype', '=', 'csv')
                        ->orWhere('logtype', '=', '');
                })
                ->get()->first()) {
            }
            else {
                $deviceName = $device->devicename;
                foreach ($dates as $date) {
                    $dateObject = new \DateTime(($date));
                    $date_underscores = $dateObject->format("Y_m_d");
                    $name = $deviceName . "_traffic_" . $date_underscores . "_last_calendar_day.csv";
                    $filePath = $path."/".$name;
                    //$query = '\'curl -u admin:paloalto -k https://' . $ip . ':' . $port . '/services/search/jobs -d search="search ' . $indexOption . ' sourcetype="pan:traffic" | eval generated_date=substr(generated_time,1,10) | where generated_date="' . $date . '" |  where serial_number="' . $serial . '" | stats sum(bytes) as bytes, sum(bytes_in) as bytes_in, sum(bytes_out) as bytes_out, sum(packets) as packets, sum(packets_in) as packets_in, sum(packets_out) as packets_out, count as hits by generated_date, serial_number, vsys, action, src_zone, src_ip, src_port, user, dest_ip, dest_zone, dest_port, app, rule"\'';
                    $query = [
                        'user'      => $userName,
                        'password'  => base64_encode($password),
                        'splunkIP'  => $ip,
                        'splunkPort'=> $port,
                        'index'     => $indexOption,
                        'date'      => $date,
                        'serial'    => $serial,
                        'path'      => $filePath,
                        'version'   => $version
                    ];
                    $inserts[] = "('$serial','$name','$date','','','','".json_encode($query)."','Pending')";
                }
            }
        }

        if(count($inserts)) {
            $insertQuery = "INSERT INTO splunk_files(device_serial, log_name, date, comment, created_at, updated_at, query_string, status) VALUES " . implode(',', $inserts) . ";";
            $pandbRBAC = selectDatabase('pandbRBAC');
            $pandbRBAC->query($insertQuery);

            if ($pandbRBAC->affected_rows > 0) {
                return [
                    'success' => true,
                    'affected_rows' => $pandbRBAC->affected_rows,
                ];
            } else {
                return [
                    'success' => false,
                    'affected_rows' => $pandbRBAC->affected_rows,
                ];
            }
        }
        else{
            return [
                'success' => false,
                'affected_rows' => "Incomplete data to create Splunk requests. Verify the device ID is valid and the user has rights on it.",
            ];
        }
    }

    public function remove($id){
        $query = "DELETE FROM splunk_files WHERE id='$id' AND device_serial in ('".implode("','",$this->serials)."');";
        $pandbRBAC = selectDatabase('pandbRBAC');
        $pandbRBAC->query($query);

        if ($pandbRBAC->affected_rows>0){
            return [
                'success'   => true,
                'affected_rows' => $pandbRBAC->affected_rows,
            ];
        }
        else{
            return [
                'success'   => false,
                'affected_rows' => $pandbRBAC->affected_rows,
            ];
        }
    }

    public function request(){
        global $app;
        $jobs = [];
        $pandbRBAC = selectDatabase('pandbRBAC');

        $panReadOrders_fileResource = fopen("/home/userSpace/panReadOrders.log","a+");

        if(isset($userID)){
            $user = $app->sentinel->findById($userID);  //Provided user for CLI executions
        }else {
            $user = $app->container->sentinel->getUser();  //Get it from the Sentinel session, if coming from a browser.
        }
        $userName = $user->email;
        $userID = $user->id;

        if(!accessControl("any", ['device.*', 'device.create'], $userID)){
            $message = new Response(false, -1, new Messages(['Your account does not have the rights to view logs from devices.']));
            fwrite($panReadOrders_fileResource,"No rights to access\n");
            return $message;
        }

        //Register Parent Job if it is not provided
        $jobParameters= [
            'serials' => $this->serials
        ];

        $knownDevices = [];
        $unknownDevices = [];
        foreach ($this->serials as $serial) {
            if ($serial != '') {
                if (!$device = $app->device
                    ->where('serial', '=', $serial)
                    ->where(function ($query) {
                        $query->where('logtype', '=', 'csv')
                            ->orWhere('logtype', '=', '');
                    })
                    ->get()->first()) {
                    $unknownDevices[] = $serial;
                }
                else {
                    $knownDevices[] = $serial;
                }
            }
        }

        if(count($knownDevices)>0){
            foreach ($knownDevices as $device){
                $query = "SELECT id, log_name, DATE_FORMAT(date,'%Y-%m-%d') as date, status, device_serial, DATE_FORMAT(updated_at,'%Y-%m-%d') as processed, path FROM splunk_files WHERE device_serial = '$device' and status = 'Pending';";
                $results = $pandbRBAC->query($query);
                $dates = [];
                $entries = [];
                $ids = [];
                if($device->serialHA != ''){
                    $deviceHA = ":".$device->serialHA;
                }
                else{
                    $deviceHA = '';
                }
                while($data = $results->fetch_assoc()){
                    $entries[] = [
                        'device'=> $serial.$deviceHA,
                        'date'  => $data['date'],
                        'id'    => $data['id'],
                        'path'  => $data['path']
                    ];
                    $dates[] = $data['date'];
                    $ids[] = $data['id'];
                }

                if(count($entries)>0) {
                    //$jobID = $this->registerJob($jobParameters, $user, "Splunk: Request logs from $device for dates (" . implode(", ", $dates) . ")", $parentJobID);
                    $tasks = [];
                    foreach ($entries as $request) {
                        $params = [
                            'serial' => $request['device'],
                            'date' => $request['date'],
                            'id' => $request['id'],
                            'path' => $request['path']
                        ];
                        $tasks[] = [
                            'device' => $request['device'],
                            'date'  => $request['date'],
                            'params' => $params
                        ];

//                        $taskID = $this->registerTask($params, $user, $jobID, "RetrieveFromSplunk", "Splunk: Retrive CSV traffic log files from $device for the date " . $request['date'] . ".");
//
//                        $this->requestSplunkFiles($params, $user, $taskID, "RetrieveFromSplunk");
                    }
                    $jobs[] = [
                        'device'=> $device,
                        'dates' => $dates,
                        'tasks' => $tasks,
                    ];


                }
            }
        }

        if(count($jobs)>0){
            $parentJobID = $this->registerParentJob($jobParameters, $user, "Splunk: Retrive CSV traffic log files (" . implode(",", $this->serials) . ")");

            foreach($jobs as $job) {
                $device = $job['device'];
                $dates = $job['dates'];

                $jobID = $this->registerJob($jobParameters, $user, "Splunk: Request logs from $device for dates (" . implode(", ", $dates) . ")", $parentJobID);

                foreach ($tasks as $task) {
                    $device = $task['device'];
                    $date = $task['date'];
                    $params = $task['params'];

                    $taskID = $this->registerTask($params, $user, $jobID, "RetrieveFromSplunk", "Splunk: Retrive CSV traffic log files from $device for the date " . $date . ".");

                    $this->requestSplunkFiles($params, $user, $taskID, "RetrieveFromSplunk");
                    sleep(2);

                }
            }

            //$query = "UPDATE splunk_files SET status = 'Requesting...' WHERE id in (" . implode(",", $ids) . ")";
            //$pandbRBAC->query($query);

            return [
                'success' => true,
                'msg'     => implode(",", $ids)." are being retrieved"
            ];

        }


        return [
            'success' => true,
            'msg'     => "No new requests to submit to Splunk"
        ];

    }

    private function registerJob(ARRAY $data, $user, STRING $description, INT $parentJob=null){
        global $app;

        //$device = $app->device->where('serial',$data['serial'])->first();
        $params = [
            'user_id'       => $user->id,
            'parentType'    => 'devices',
            'parentId'      => 0,
            'description'   => $description,
            'parentJob'     => $parentJob,
        ];
        if(!$job = $app->job->create($params)){
            return -1;
        }

        return $job->id;
    }

    private function registerParentJob(ARRAY $data, $user, STRING $description){
        global $app;

        //$device = $app->device->where('serial',$data['serial'])->first();
        $params = [
            'user_id'       => $user->id,
            'parentType'    => 'devices',
            'parentId'      => '',
            'description'   => $description,
        ];
        if(!$job = $app->job->create($params)){
            return -1;
        }

        return $job->id;
    }

    private function registerTask(ARRAY $data=null, $user, INT $jobID, STRING $processCode, STRING $processName){
        global $app;

        if(!isset($data['params'])){
            $data['params'] = '';
        }
        $data['userId'] = $user->id;

        $params = [
            'job_id'        => $jobID,
            'taskType'      => 'Retrieve Log from Splunk',
            'taskName'      => $processName,
            'processCode'   => $processCode,
            'statusMessage' => 'Pending...',
            'statusCode'    => '0',
            'params'        => json_encode($data),
        ];

        if(!$task = $app->task->create($params)){
            return -1;
        }

        $job = $app->job->where('id', $jobID)->first();
        $jobParams = [
            'tasks' => $job->tasks +1,
        ];
        $job->update($jobParams);

        if($job->parentJob != ''){
            $parentJob = $app->job->where('id', $job->parentJob)->first();
            $parentJobParams = [
                'tasks' => $parentJob->tasks +1,
            ];
            $parentJob->update($parentJobParams);
        }

        return $task->id;
    }

    private function sendMessage($message){
        $messageSender = new \MessageSender($message);
        $messageSender->send();
    }

    private function requestSplunkFiles(ARRAY $data, $user, INT $taskID, STRING $process){
        $message = [
            'sender'        => $user->id,
            'proccessCode'  => $process,
            'params'        => [
                'serial'    => $data['serial'],
                'id'        => $data['id'],
                'taskId'    => $taskID,
                'path'      => $data['path'],
                'date'      => $data['date']
            ]
        ];

        $this->sendMessage($message);

        $message = array();
        $message['code'] = true;
        $message['msg'] = 'Done';
        return $message;
    }

}