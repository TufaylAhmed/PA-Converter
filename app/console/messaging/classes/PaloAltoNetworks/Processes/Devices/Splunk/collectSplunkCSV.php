<?php

$_SERVER['DOCUMENT_ROOT'] = '/var/www/html';
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
require_once INC_ROOT.'/libs/projectdb.php';

class CurlConnect{

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

function checkConnectionErrors($e){
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

/***
 * Check if a given Splunk job has completed. If so, will save the result in a defined path. If not, will update the state in the database
 *
 * @param STRING $ip
 * @param STRING $port
 * @param STRING $userName
 * @param STRING $password
 * @param STRING $jobID
 * @return mixed|string
 */
function checkCompleted(STRING $ip, STRING $port, STRING $userName, STRING $password, STRING $jobID){
    // curl -u admin:paloalto      -k https://10.11.29.9:8089/services/search/jobs/1588974227.18318
    $url = "https://$ip:$port/services/search/jobs/$jobID";

//    $ch = curl_init();
//    curl_setopt($ch, CURLOPT_URL, $url);
//    curl_setopt($ch, CURLOPT_HEADER, TRUE);
//    curl_setopt($ch, CURLOPT_NOBODY, TRUE);
//    //curl_setopt($ch, CURLOPT_USERNAME, $userName);
//    curl_setopt($ch, CURLOPT_USERPWD, "$userName:$password");
//    $head = curl_exec($ch);
//    $line = curl_multi_getcontent($ch);

    $datatopost = array(
    );

    $pwd = base64_decode($password);
    $tuCurl = curl_init();
    $params = [
        'url'  => "$url",
        'port'  => $port,
        'postfields' =>$datatopost,
        'password' => "$userName:$pwd"
    ];
    unset($pwd);
    $curlObj = new CurlConnect($tuCurl, $params);

    $tuData = $curlObj->exec();
    $e = curl_errno($tuCurl);
    if(!checkConnectionErrors($e)){
        $curlObj->close();
        return getErrorCode(ERROR_ConnectionNotEstablished);
    }

    $line = curl_multi_getcontent($tuCurl);
    $curlObj->close();

    return $line;

}

/***
 * Opens a CURL connection to Splunk to download a resulting CSV traffic file
 *
 * @param STRING $ip
 * @param STRING $port
 * @param STRING $userName
 * @param STRING $password
 * @param STRING $jobID
 * @param STRING $path
 * @return bool Whether the download created a file successfully or not
 */
function downloadLogFile(STRING $ip, STRING $port, STRING $userName, STRING $password, STRING $jobID, STRING $path){

    // Splunk has an internal limit that restricts the number of records returned on each API call
    // default limit is set to 50000k records and Splunk does not recommend increasing it
    // we need to go over all query records getting them over the pagination - flag offset
    $pwd = addslashes(base64_decode($password));
    // Get the number of records to be downloaded
    $resultCount_command = "curl -u $userName:$pwd -k https://$ip:$port/services/search/jobs/".$jobID." | grep resultCount";
    // command returns something like: <s:key name="resultCount">5344</s:key>
    $resultCount_output = exec($resultCount_command);

    preg_match('/(\D+)("resultCount")(\D+)(\d+)(\D+)/', $resultCount_output, $output_array);
    // on $output_array[4] we have the total number of records

    if(isset($output_array[4]) && $output_array[4] > 0){
        $resultCount = $output_array[4]; // total number of records
        $lines = 0; // number of downloaded records + 1 line that is the header line
        $offset = 0; // pagination
        $count = 0; // number of records to be got for each call
        $iterations = 1; // number of iterations or calls

        echo "Splunk result records: $resultCount\n";

        // while not all records are downloaded
        while( ($lines - 1 ) < $resultCount) {

            if($iterations === 1) {
                // if it's the first iteration we want to write also the header line
                $command = "curl -u $userName:$pwd -k https://$ip:$port/services/search/jobs/" . $jobID . "/results/ --get -d output_mode=csv -d offset=" . $offset . " -d count=" . $count . " >> " . $path;
            }else{
                // header line (sed '1d') is not needed
                $command = "curl -u $userName:$pwd -k https://$ip:$port/services/search/jobs/" . $jobID . "/results/ --get -d output_mode=csv -d offset=" . $offset . " -d count=" . $count . " | sed '1d' >> " . $path;
            }

            exec($command);
            $lines = count(file($path));
            $offset = $lines - 1;
            echo "Downloaded lines: $offset\n";
            if($offset<0) {$offset = 0;}
            $iterations++;
        }
    } else {
        echo "Splunk not returning total number of query records\n";
    }
    unset($pwd);
    //Verify the file has been created
    if(file_exists($path)){
        return true;
    }
    return false;
}


if(isset($argv)) {
    $clean = str_replace("}", "", str_replace("{", "", $argv[1]));
    $argv = explode(",", $clean);

    foreach ($argv as $arg) {
        $tupla = explode(':', $arg);
        $tupla[0] = str_replace('"', '', $tupla[0]);
        $tupla[1] = str_replace('"', '', $tupla[1]);

        switch (strtolower($tupla[0])) {
            case "rowid":
                $rowID = $tupla[1];
                break;

            case "jobid":
            case "job_id":
                $jobID = $tupla[1];
                break;

            case "ip":
            case "splunkip":
            case "splunk_ip":
                $ip = $tupla[1];
                break;

            case "port":
            case "splunkport":
            case "splunk_port":
                $port = $tupla[1];
                break;

            case "user":
            case "username":
            case "user_name":
                $username = $tupla[1];
                break;

            case "password":
            case "passw":
                $password = $tupla[1];
                break;

            case "path":
                $path = $tupla[1];
                break;

            default:
                break;
        }
    }
}

$i=1;
$sleepTime = 20;
$pandbRBAC = selectDatabase("pandbRBAC");
while(true){  //Loop to check every X seconds if the Job is done and download the file if so
    $response = checkCompleted($ip, $port, $username, $password, $jobID);

    $parser = xml_parser_create();
    xml_parse_into_struct($parser, $response, $vals, $index);
    //print_r($vals);

    foreach ($vals as $element){
        if(isset($element['attributes']) && isset($element['attributes']['NAME']) && $element['attributes']['NAME']== "dispatchState"){
            echo $element['value']."\n";
            if(isset($element['value']) && $element['value'] == "DONE" ){
                $query = "UPDATE splunk_files SET status='Waiting', comment = 'Downloading files. Splunk report finished.', updated_at = now() WHERE id = '$rowID'; ";
                $pandbRBAC->query($query);
                $attempts = 0;
                $success = false;
                do{
                    $success = downloadLogFile($ip, $port, $username, $password, $jobID, $path);
                    $attempts++;
                } while(!$success && $attempts < 5);
                //while (!$success = downloadLogFile($ip, $port, $username, $password, $jobID, $path) && $attempts < 5){
                //    $attempts++;
                //}

                if($success){
                    //All fine
                    echo "Downloaded\n";
                    $query = "UPDATE splunk_files SET status='Completed', comment = 'File successfully downloaded', updated_at = now() WHERE id = '$rowID';";
                    $pandbRBAC->query($query);
                    break 2;
                }
                else{
                    //We could not get the file
                    echo "We could not download the file\n";
                    break 2;
                }
            }
            else{
                $notCompleted =true;
            }
        }
        elseif(isset($element['value']) && $element['value']== "Unknown sid."){
            //The job does not exist
            echo "\tThe job ".$jobID." does not exist\n";
            break 2;
        }
        else{
            //Those are other elements in the XML that we currently do not care about.
        }
    }

    if($notCompleted){
        $diskUsage = 0;
        $progress = 0;
        foreach ($vals as $element){
            if(isset($element['attributes']) && isset($element['attributes']['NAME']) && $element['attributes']['NAME']== "diskUsage"){
                $diskUsage = $element['value'];
            }
            elseif(isset($element['attributes']) && isset($element['attributes']['NAME']) && $element['attributes']['NAME']== "dispatchState"){
                $jobStatus = $element['value'];
            }
            elseif(isset($element['attributes']) && isset($element['attributes']['NAME']) && $element['attributes']['NAME']== "doneProgress"){
                $progress = $element['value'];
            }
        }
        echo "\tJob status reported as: ".$jobStatus." at ".round($progress*100.0, 1) . "% (Disk Usage: $diskUsage)\n";
        echo "\t\tElapsed time: ".($i-1)*$sleepTime." sec.";
        echo "\t\tRechecking in $sleepTime secs.\n";
        $query = "UPDATE splunk_files SET status='Waiting', comment = 'Splunk reports as $jobStatus at ".round($progress*100.0, 1)."% (Disk Usage: $diskUsage) ', updated_at = now() WHERE id = '$rowID'; ";
        //echo $query."\n";
        $pandbRBAC->query($query);
    }

    echo "\n";
    $i++;

    sleep($sleepTime);
}
