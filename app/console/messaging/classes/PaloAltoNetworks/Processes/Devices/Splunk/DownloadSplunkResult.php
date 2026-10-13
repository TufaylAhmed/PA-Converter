<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 10/6/16 - 15:45
 */

class DownloadSplunkResult
    extends AbstractProcess
{

    public function __construct(ARRAY $params){
        parent::__construct($params);
    }

    public function execute()
    {
        if(!parent::execute()){
            return;
        }

        $this->setStarted();

        $pandbRBAC = selectDatabase('pandbRBAC');

        $deviceSerial = $this->params['serial'];
        $requestID = $this->params['id'];
        $logDate = $this->params['date'];

        require_once (INC_ROOT.'/libs/database.php'); //getConfigBackup will require access to $pandb
        require_once (INC_ROOT.'/libs/xmlapi.php'); //We have the getApplications implementation inside

        global $app;
        $errors = array();
        $errorDev = array();

        $this->log("Action:\tDownload\nTraffic Log from Splunk:\t\nTarget:\t" . $deviceSerial."\nDate:\t".$logDate );

        //Get info from device!
        if ($deviceObj = $app->container->device->where('serial', '=', $deviceSerial)->get()->first()) {
//                $success = true;
//                if ($deviceObj->management == '') {
//                    $hostname = $deviceObj->hostname;
//                    $port = $deviceObj->port;
//
//                    $key_name = $deviceSerial . "_" . $role;
//                    if ($key = $app->apikey->where('key_name', '=', $key_name)->get()->first()) {
//                        $this->log("Connection:\tDirect");
//                        $success = getApplications($hostname, $deviceSerial, $key->api_key, $port);
//                    }
//                    if ($success<0) {
//                        $errors[] = $success;
//                        $errorDev[] = $deviceSerial;
//                    }
//                }
//                else {
//                    $panorama = $deviceObj->management;
//                    $this->log("Connection:\tVia $panorama");
//                    $this->log("\tAborted, not a direct connection");
//                    $errors[] = getErrorCode(ERROR_ActionNotPossible);
//                    $errorDev[] = $deviceSerial;
//                }
            //Check the logs that are supposed to be retrieved
            $query = "SELECT id, log_name, DATE_FORMAT(date,'%Y-%m-%d') as date, status, device_serial, DATE_FORMAT(updated_at,'%Y-%m-%d') as processed, query_string FROM splunk_files WHERE device_serial = '$deviceSerial' and status = 'Pending' and id='$requestID';";
            $results = $pandbRBAC->query($query);
            if($results->num_rows>0){
                $data = $results->fetch_assoc();
                $params = json_decode($data['query_string']);
                $ip = $params['splunkIP'];
                $port = $params['splunkPort'];
                $index = $params['index'];
                $query = '\'curl -u admin:paloalto -k https://' . $ip . ':' . $port . '/services/search/jobs -d search="search ' . $indexOption . ' sourcetype="pan:traffic" | eval generated_date=substr(generated_time,1,10) | where generated_date="' . $date . '" |  where serial_number="' . $serial . '" | stats sum(bytes) as bytes, sum(bytes_in) as bytes_in, sum(bytes_out) as bytes_out, sum(packets) as packets, sum(packets_in) as packets_in, sum(packets_out) as packets_out, count as hits by generated_date, serial_number, vsys, action, src_zone, src_ip, src_port, user, dest_ip, dest_zone, dest_port, app, rule"\'';
                exec();
                $datatopost = array(
                    "type" => "config",
                    "action" => 'get',
                    "key" => $api_key,
                    "xpath" => "/config/predefined/application"
                );
                $tuCurl = curl_init();
                $params = [
                    'url'  => 'https://'.$ip.':'.$port.'/services/search/jobs/'.$jobID,
                    'port'  => $port,
                    'postfields' =>$datatopost,
                    'timeout' => 1500,
                ];
                $curlObj = new CurlConnect($tuCurl, $params);
                $curlObj->close();
            }
            else{

            }
        }
        if(count($errors) == 0) {
            $this->setCompleted('');
        }
        else {
            $this->setFailed("There were problems downloading the Applications from [".implode(',', $errorDev)."]", implode(',', $errors));
        }
    }
}