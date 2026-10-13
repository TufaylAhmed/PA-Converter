<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 10/6/16 - 15:45
 */

$_SERVER['DOCUMENT_ROOT'] = '/var/www/html';
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

class SplunkCurlConnect{

    protected $tuCurl;

    protected $headerOut = 0;
    protected $stderr;
    protected $url = '';
    protected $port = 443;
    protected $password = '';
    protected $verbose = DEVICE_DEBUG_CONNECTION_ENABLED;
    protected $header = 0;
    protected $post = 1;
    protected $sslVerify = 0;
    protected $verifyHost = 0;
    protected $returnTransfer = 1;
    protected $connectTimeout = 50;
    protected $postfields = '';
    protected $timeout = 60;
    protected $valid = false;
    protected $httpheader;

    public function __construct($tuCurl, $params){
        if (!$this->fill_fields($tuCurl, $params)){
            return null;
        }
        if (!$this->setopt()) {
            return null;
        }
        $this->valid=true;
        return $this;
    }

    private function setopt(){
        if(isset($this->headerOut)){
            if (!curl_setopt($this->tuCurl, CURLINFO_HEADER_OUT, $this->headerOut)){
                $this->valid = false;
                return false;
            }
        }

        if(isset($this->stderr)){
            if(!curl_setopt($this->tuCurl, CURLOPT_STDERR, $this->stderr)){
                $this->valid = false;
                return false;
            }
        }

        if(isset($this->url)){
            if(!curl_setopt($this->tuCurl, CURLOPT_URL, $this->url)){
                $this->valid = false;
                return false;
            }
        }

        if(isset($this->port)){
            if(!curl_setopt($this->tuCurl, CURLOPT_PORT, $this->port)){
                $this->valid = false;
                return false;
            }
        }

        if(isset($this->password)){
            if(!curl_setopt($this->tuCurl, CURLOPT_USERPWD, $this->password)){
                $this->valid = false;
                return false;
            }
        }

        if(isset($this->verbose)){
            if(!curl_setopt($this->tuCurl, CURLOPT_VERBOSE, $this->verbose)){
                $this->valid = false;
                return false;
            }
        }

        if(isset($this->header)){
            if(!curl_setopt($this->tuCurl, CURLOPT_HEADER, $this->header)){
                $this->valid = false;
                return false;
            }
        }

        if(isset($this->post)){
            if(!curl_setopt($this->tuCurl, CURLOPT_POST, $this->post)){
                $this->valid = false;
                return false;
            }
        }

        if(isset($this->sslVerify)){
            if(!curl_setopt($this->tuCurl, CURLOPT_SSL_VERIFYPEER, $this->sslVerify)){
                $this->valid = false;
                return false;
            }
        }

        if(isset($this->verifyHost)){
            if(!curl_setopt($this->tuCurl, CURLOPT_SSL_VERIFYHOST, $this->verifyHost)){
                $this->valid = false;
                return false;
            }
        }

        if(isset($this->returnTransfer)){
            if(!curl_setopt($this->tuCurl, CURLOPT_RETURNTRANSFER, $this->returnTransfer)){
                $this->valid = false;
                return false;
            }
        }

        if(isset($this->connectTimeout)){
            if(!curl_setopt($this->tuCurl, CURLOPT_CONNECTTIMEOUT, $this->connectTimeout) ){
                $this->valid = false;
                return false;
            }
        }

        if(isset($this->httpheader)){
            if(!curl_setopt($this->tuCurl, CURLOPT_HTTPHEADER, $this->httpheader)){
                $this->valid = false;
                return false;
            }
        }

        if(isset($this->postfields)){
            if(!curl_setopt($this->tuCurl, CURLOPT_POSTFIELDS, $this->postfields)){
                $this->valid = false;
                return false;
            }
        }

        if(isset($this->timeout)){
            if(!curl_setopt($this->tuCurl, CURLOPT_TIMEOUT, $this->timeout)){
                $this->valid = false;
                return false;
            }
        }

        $this->valid = true;
        return true;
    }

    function checkFolderExists(STRING $folder){

        if (!file_exists($folder)) {
            mkdir($folder, 0777, true);
        }
    }

    private function fill_fields($tuCurl, $params){
        if (isset($tuCurl)) {
            $this->tuCurl = $tuCurl;
        }
        else{
            return false;
        }

        if (isset($params['headerOut'])) {
            $this->headerOut = 0;
        }
        if (isset($params['stderr'])) {
            $this->stderr = fopen($params['stderr'], 'a+');
        }
        else{
            $this->checkFolderExists(USERSPACE_PATH."/devices/");
            $this->stderr = fopen(USERSPACE_PATH."/devices/debug.txt", 'a+');
        }

        if (isset($params['url'])) {
            $this->url = $params['url'];
        }
        if (isset($params['port'])) {
            $this->port = $params['port'];
        }
        if (isset($params['password'])) {
            $this->password = $params['password'];
        }
        if (isset($params['verbose'])) {
            $this->verbose = $params['verbose'];
        }
        if (isset($params['header'])) {
            $this->header = $params['header'];
        }
        if (isset($params['post'])) {
            $this->post = $params['post'];
        }
        if (isset($params['sslVerify'])) {
            $this->sslVerify = $params['sslVerify'];
        }
        if (isset($params['verifyHost'])) {
            $this->verifyHost = $params['verifyHost'];
        }
        if (isset($params['returnTransfer'])) {
            $this->returnTransfer = $params['returnTransfer'];
        }
        if (isset($params['connectTimeout'])) {
            $this->connectTimeout = $params['connectTimeout'];
        }
        if (isset($params['postfields'])) {
            $this->postfields = $params['postfields'];
        }
        if (isset($params['timeout'])) {
            $this->timeout = $params['timeout'];
        }
        if (isset($params['httpheader'])) {
            $this->httpheader = $params['httpheader'];
        }

        return true;
    }

    public function exec(){
        return curl_exec($this->tuCurl);
    }

    public function close(){
        if (isset($this->stderr)){
            fclose($this->stderr);
        }
    }
}

/*function checkConnectionErrors($e){
    switch ($e){
        case 0:
            return true;
            break;

        case 6:
            $logger = MTLogger::getInstance();
            $logger->log( json_encode(array('success' => false, 'msg' => "Error Code $e: The HostName could not be resolved")));
            return false;;
            break;

        case 7:
            $logger = MTLogger::getInstance();
            $logger->log( json_encode(array('success' => false, 'msg' => "Error Code $e: The connection with the device cannot be established. Please, revise your connection parameters")));
            return false;;
            break;

        case 21:
        case 22:
        case 23:
        case 24:
        case 25:
        case 26:
            $logger = MTLogger::getInstance();
            $logger->log( json_encode(array('success' => false, 'msg' => "Error Code $e: The connection with the device returned an error. Please try again")));
            return false;
            break;

        case 27:
            $logger = MTLogger::getInstance();
            $logger->log( json_encode(array('success' => false, 'msg' => "Error Code $e: The connection with the device returned an error. Out of memory. Please, report this error for improvement")));
            return false;
            break;

        case 28:
            $logger = MTLogger::getInstance();
            $logger->log( json_encode(array('success' => false, 'msg' => "Error Code $e: The connection with the device cannot be established. Connection timeout")));
            return false;
            break;

        default:
            $logger = MTLogger::getInstance();
            $logger->log( json_encode(array('success' => false, 'msg' => "Error Code $e: The connection with the device cannot be established. Please, report Error Code for improvement")));
            return false;
            break;
    }
}
*/

class RetrieveFromSplunk
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

        //print_r($this->params);
        $deviceSerial = $this->params['serial'];
        $requestID = $this->params['id'];
        $logDate = $this->params['date'];

        require_once (INC_ROOT.'/libs/database.php'); //getConfigBackup will require access to $pandb
        //require_once (INC_ROOT.'/libs/xmlapi.php'); //We have the getApplications implementation inside

        global $app;
        $errors = array();
        $errorDev = array();

        $this->log("Action:\tRequest\nTraffic Log from Splunk:\t\nTarget:\t" . $deviceSerial."\nDate:\t".$logDate );

        //Get info from device!
        if ($deviceObj = $app->container->device->where('serial', '=', $deviceSerial)->get()->first()) {
            //Check the logs that are supposed to be retrieved
            $query = "SELECT id, log_name, DATE_FORMAT(date,'%Y-%m-%d') as date, status, device_serial, DATE_FORMAT(updated_at,'%Y-%m-%d') as processed, query_string FROM splunk_files WHERE device_serial = '$deviceSerial' and (status = 'Pending' or status='Requesting...') and id='$requestID';";
            $results = $pandbRBAC->query($query);
            if($results->num_rows>0){
                $data = $results->fetch_assoc();
                $params = json_decode($data['query_string']);

                $ip = $params->splunkIP;
                $port = $params->splunkPort;
                $date = $params->date;
                $serial = $params->serial;
                $userName = $params->user;
                $password = $params->password; // addslashes(base64_decode($params->password))
                $path = $params->path;
                $rowID = $data['id'];
                $version = isset($params->version)?$params->version:0;

                $index = $params->index;
                if($version=='7.3'){
                    $indexOption = ($index != '')? "$index" : '';
                }
                else{
                    $indexOption = ($index != '')? "index:$index" : '';
                }

                $dateObject = new DateTime($date);
                $earliest=$dateObject->format('m/d/Y').":0:0:0"; // 05/24/2020:0:0:0
                $latest= $dateObject->modify( '+1 day' )->format('m/d/Y').":0:0:0"; // 05/25/2020:0:0:0

                $url  = 'https://'.$ip.':'.$port.'/services/search/jobs -d'.
                        ' search="search '.$indexOption.' earliest='.$earliest.' latest='.$latest.'  sourcetype="pan:traffic" serial_number=\"'.$serial.'\" | fillnull value="" src_user dest_user | eval generated_date=substr(generated_time,1,10) |'.
                        ' where generated_date=\"'.$date.'\" |'.
//                        ' where serial_number=\"'.$serial.'\" |'.
                        ' stats sum(bytes) as bytes, sum(bytes_in) as bytes_in, sum(bytes_out) as bytes_out, sum(packets) as packets, sum(packets_in) as packets_in, sum(packets_out) as packets_out, count as hits '.
                        ' by '.
                        ' log_type, generated_date, serial_number, log_subtype, vsys, action, src_zone, src_ip, src_location, src_port, src_user, dest_ip, dest_zone, dest_location, dest_port, dest_user, app, rule, transport, app:category"';

                $datatopost = array(
                    'search' => '"search '.$indexOption.' earliest='.$earliest.' latest='.$latest.' sourcetype="pan:traffic" | eval generated_date=substr(generated_time,1,10) |'.
                        ' where generated_date="'.$date.'" |'.
                        ' where serial_number="'.$serial.'" |'.
                        ' stats sum(bytes) as bytes, sum(bytes_in) as bytes_in, sum(bytes_out) as bytes_out, sum(packets) as packets, sum(packets_in) as packets_in, sum(packets_out) as packets_out, count as hits '.
                        ' by '.
                        ' log_type, generated_date, serial_number, log_subtype, vsys, action, src_zone, src_ip, src_location, src_port, src_user, dest_ip, dest_zone, dest_location, dest_port, dest_user, app, rule, transport, app:category"'
                );
                $pwd = addslashes(base64_decode($password));
                $command = "curl -u $userName:$pwd -k $url";
                unset($pwd);
                $response = exec($command, $line);
                //echo $command."\n";
                //$this->log($command);
                //print_r($line);

                $xml = simplexml_load_string(implode("",$line));
                //print_r($xml);
                if(isset($xml->sid)){
                    $jobID = $xml->sid;
                    $SplunkPath = '/var/www/html/console/messaging/classes/PaloAltoNetworks/Processes/Devices/Splunk';

                    if (XDEBUG===true) {
                        $retrieveCommand = "export PHP_IDE_CONFIG=\"serverName=Expedition1\"; php " . $SplunkPath . "/collectSplunkCSV.php '{\"user\":\"$userName\",\"passw\":\"$params->password\",\"ip\":\"$ip\",\"port\":\"$port\",\"jobid\":\"$jobID\",\"path\":\"$path\",\"rowID\":\"$rowID\"}'";
                    }else {
                        $retrieveCommand = "php " . $SplunkPath . "/collectSplunkCSV.php '{\"user\":\"$userName\",\"passw\":\"$params->password\",\"ip\":\"$ip\",\"port\":\"$port\",\"jobid\":\"$jobID\",\"path\":\"$path\",\"rowID\":\"$rowID\"}'";
                        //echo $retrieveCommand."\n";
                    }
                    exec("$retrieveCommand >> /tmp/retrieveSplunkJob.log &");

                }
                else{
                    echo implode("",$line);
                    echo "The xml:\n";
                    echo $xml."\n";
                }


//                $tuCurl = curl_init();
//                $curlParams = [
//                    'url'  => "$url",
//                    'port'  => $port,
//                    'postfields' =>$datatopost,
//                    'password' => "$userName:$password"
//                ];
//                $curlObj = new CurlConnect($tuCurl, $curlParams);
//
//                $tuData = $curlObj->exec();
//                $e = curl_errno($tuCurl);
//                if(!checkConnectionErrors($e)){
//                    $curlObj->close();
//                    return getErrorCode(ERROR_ConnectionNotEstablished);
//                }
//
//                $line = curl_multi_getcontent($tuCurl);
//                $curlObj->close();
//                $this->log(print_r($line) );

                //$line should have the JobID
                //return $line;
//                //$query = '\'curl -u admin:paloalto -k https://' . $ip . ':' . $port . '/services/search/jobs -d search="search ' . $indexOption . ' sourcetype="pan:traffic" | eval generated_date=substr(generated_time,1,10) | where generated_date="' . $date . '" |  where serial_number="' . $serial . '" | stats sum(bytes) as bytes, sum(bytes_in) as bytes_in, sum(bytes_out) as bytes_out, sum(packets) as packets, sum(packets_in) as packets_in, sum(packets_out) as packets_out, count as hits by generated_date, serial_number, vsys, action, src_zone, src_ip, src_port, user, dest_ip, dest_zone, dest_port, app, rule"\'';
//                $datatopost = array(
//                    "type" => "config",
//                    "action" => 'get',
//                    "key" => $api_key,
//                    "xpath" => "/config/predefined/application"
//                );
//                $tuCurl = curl_init();
//                $params = [
//                    'url'  => 'https://'.$ip.':'.$port.'/services/search/jobs -d'.
//                                 ' search="search '.$indexOption.' sourcetype="pan:traffic" | eval generated_date=substr(generated_time,1,10) |'.
//                                 ' where generated_date="'.$date.'" |'.
//                                 ' where serial_number="'.$serial.'" |'.
//                                 ' stats sum(bytes) as bytes, sum(bytes_in) as bytes_in, sum(bytes_out) as bytes_out, sum(packets) as packets, sum(packets_in) as packets_in, sum(packets_out) as packets_out, count as hits '.
//                                 ' by '.
//                                 ' type, generated_date, serial_number, log_subtype, vsys, action, src_zone, src_ip, src_location, src_port, src_user, dest_ip, dest_zone, dest_location, dest_port, dest_user, app, rule, transport, app:category',
////                               ' type, generated_date, serial_number,              vsys, action, src_zone, src_ip,               src_port,     user, dest_ip, dest_zone,                dest_port,            app, rule"',
//                    'port'  => $port,
////                    'postfields' =>$datatopost,
//                    'timeout' => 1500,
//                ];
//                $curlObj = new CurlConnect($tuCurl, $params);
//                $curlObj->close();
//
//                $ch = curl_init();
//                curl_setopt($ch, CURLOPT_URL, $params['url']);
//                curl_setopt($ch, CURLOPT_HEADER, TRUE);
//                curl_setopt($ch, CURLOPT_NOBODY, TRUE);
//                //curl_setopt($ch, CURLOPT_USERNAME, $userName);
//                curl_setopt($ch, CURLOPT_USERPWD, "$userName:$password");
//                $head = curl_exec($ch);
//                $line = curl_multi_getcontent($ch);

            }
            else{
                //echo "\n\n did not gave any result:\n$query\n";
            }
            $pandbRBAC->close();
        }
        if(count($errors) == 0) {
            $this->setCompleted('');
        }
        else {
            $this->setFailed("There were problems downloading the Applications from [".implode(',', $errorDev)."]", implode(',', $errors));
        }
    }
}