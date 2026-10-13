<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 10/6/16 - 15:45
 */
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
require_once INC_ROOT.'/libs/projectdb.php';
require_once INC_ROOT.'/libs/common/device/device.php';

class SendAPICall
    extends AbstractProcess
{

    public function __construct(ARRAY $params){
        parent::__construct($params);
    }

    private function updateAPICallOutputBulk(STRING $project, STRING $id, STRING $device, STRING $status, STRING $text){
        global $projectdb;
        global $app;

        $projectdb = selectDatabase($project);

        if($deviceEntity = $app->device->where('id', '=', $device)->get()->first()){
            $query = "SELECT output, xml_initial FROM output_mapping WHERE id='$id'";
            $resultQuery = $projectdb->query($query);
            $dataQuery = $resultQuery->fetch_assoc();
            $output = $dataQuery['output'];
            $ids = $dataQuery['xml_initial'];
            $outputJson = json_decode($output);
            if(!isset($outputJson)){
                $outputJson = ((object) null);
            }
            $outputJson->$device = [
                'device'    => $deviceEntity->devicename,
                'status'    => $status,
                'text'      => addslashes($text),
                'date'      => date("Y-m-d H:i:s"),
            ];
            $updateQuery = "UPDATE output_mapping SET output='".addslashes(json_encode($outputJson))."' WHERE id IN ($ids);";
            $projectdb->query($updateQuery);
        }
    }

    private function updateAPICallOutput(STRING $project, STRING $id, STRING $device, STRING $status, STRING $text){
        global $projectdb;
        global $app;

        $projectdb = selectDatabase($project);

        if($deviceEntity = $app->device->where('id', '=', $device)->get()->first()){
            $query = "SELECT output FROM output_mapping WHERE id='$id'";
            $resultQuery = $projectdb->query($query);
            $dataQuery = $resultQuery->fetch_assoc();
            $output = $dataQuery['output'];
            $outputJson = json_decode($output);
            if(!isset($outputJson)){
                $outputJson = ((object) null);
            }
            $outputJson->$device = [
                'device'    => $deviceEntity->devicename,
                'status'    => $status,
                'text'      => addslashes($text),
                'date'      => date("Y-m-d H:i:s"),
            ];
            $updateQuery = "UPDATE output_mapping SET output='".addslashes(json_encode($outputJson))."' WHERE id='$id';";
            $projectdb->query($updateQuery);
        }
    }


    public function execute()
    {
        if(!parent::execute()){
            return;
        }

        $this->setStarted();

        $projectname = $this->params['project'];
        global $projectdb;
        $projectdb = selectDatabase($projectname);

        $ids = $this->params['params'];
        //Collect the API call
        $role = 'admin';

        require_once (INC_ROOT.'/libs/database.php'); //getConfigBackup will require access to $pandb
        require_once (INC_ROOT.'/libs/xmlapi.php'); //We have the getApplications implementation inside

        global $app;

        $userID = $this->params['userId'];

        if($user = $app->user->where('id',$userID)->where('api_key',$this->params['key'])->where('valid_til', '>',date("Y-m-d H:i:s"))->get()->first()) {
            $app->sentinel->login($user);
        }

        if(!$app->container->sentinel->check() || !isset($user)){
            $className = get_class($this);
            $this->log($className. " - Invalid Credentials to execute the process");
            $this->setFailed("Invalid Credentials to execute the process", "Export Cancelled by user invalid credentials");
            return;
        }


        $apiCallID = array();
        $errorAPI = array();
        $api_key="";

        $deviceSerial = $this->params['serial'];
        $userID = $this->params['userId'];

        $this->log("Action:\t\tSend API Call\nTarget:\t\t" . $deviceSerial . "\nAPI Requests:\t$ids\nUserID:\t\t". $userID ."\nKey:\t\t" . $role);

        if ($deviceEntity = $app->device->where('serial', '=', $deviceSerial)->get()->first()) {
            $management = $deviceEntity->management;
            if ($management != "") {
                if ($panoramaEntity = $app->device->where('serial', '=', $management)->get()->first()) {
                    $hostname = $panoramaEntity->hostname;
                    $serial=$deviceSerial;
                    $port = $panoramaEntity->port;
                    if ($port == "") {
                        $port = "443";
                    }
                    $isProxy = true;
                    $api_message = getApiKey($projectname, $panoramaEntity->serial, $userID);
                    if (!$api_message['code']) {
                        $apiCallID[] = -2;
                        $errorAPI[] = '(Device '.$deviceEntity->devicename.', '.$deviceSerial.') You do not have access to the device. Check with your Admin.';
                    }
                    $api_key = $api_message['msg'];
                }
                else {
                    $apiCallID[] = -2;
                    $errorAPI[] = '(Device '.$deviceEntity->devicename.' '.$deviceSerial.') Failed retrieving the API KEY.';
                }
            }
            else {
                $isProxy = false;
                $hostname = $deviceEntity->hostname;
                $serial = $deviceEntity->serial;
                $port = $deviceEntity->port;
                if ($port == "") {
                    $port = "443";
                }
                $api_message = getApiKey($projectname, $deviceEntity->serial, $userID);
                if (!$api_message['code']) {
                    $apiCallID[] = -2;
                    $errorAPI[] = '(Device '.$deviceEntity->devicename.','.$deviceSerial.') You do not have access to the device. Check with your Admin.';
                }
                $api_key = $api_message['msg'];
            }
        }

        if($api_key==""){
            $this->setFailedSilent("There were problems sending the API calls - API KEY is not defined", "API KEY is not defined");
            return;
        }

        //Loop for each one of the API calls to send
        $order=" ORDER BY id ASC";
        $getOrder=$projectdb->query("SELECT action FROM output_mapping GROUP BY action;");
        if ($getOrder->num_rows==1){
            $getOrderData=$getOrder->fetch_assoc();
            if ($getOrderData['action']!=null){
                if ($getOrderData['action']=="delete"){
                    $order=" ORDER BY id DESC";
                }
            }
        }
        if ($ids == "") {
            $getCalls = $projectdb->query("SELECT id,xpath,action,xml_final,whereto,dst FROM output_mapping $order;");
        }
        else {
            $getCalls = $projectdb->query("SELECT id,xpath,action,xml_final,whereto,dst FROM output_mapping WHERE id IN ($ids) $order;");
        }

        $allrules = $getCalls->num_rows;
        $x = 0;


        if ($getCalls->num_rows > 0) {

            # Send the API CALL to the DEVICE
            $devicePath = $hostname . "/api";
            $tuCurl = curl_init();
            while ($getCallsData = $getCalls->fetch_assoc()) {
                $error = false;
                $errorText = '';
                $x++;
                $id = $getCallsData['id'];
                $xpath = $getCallsData['xpath'];
                $action = $getCallsData['action'];
                $element = $getCallsData['xml_final'];
                if ($isProxy == true) {
                    if ($action == "move") {
                        $whereto = $getCallsData['whereto'];
                        $dst = $getCallsData['dst'];
                        $datatopost = array(
                            "type" => "config",
                            "action" => $action,
                            "target" => $serial,
                            "xpath" => $xpath,
                            "where" => $whereto,
                            "dst" => $dst
                        );
                    }
                    elseif ($action=="op"){
                        $datatopost = array(
                            "type" => "op",
                            "cmd" => $element,
                            "target" => $serial
                        );
                    }
                    else {
                        $datatopost = array(
                            "type" => "config",
                            "action" => $action,
                            "target" => $serial,
                            "xpath" => $xpath,
                            "element" => $element
                        );
                    }
                }
                else {
                    if ($action == "move") {
                        $whereto = $getCallsData['whereto'];
                        $dst = $getCallsData['dst'];
                        $datatopost = array(
                            "type" => "config",
                            "action" => $action,
                            "xpath" => $xpath,
                            "where" => $whereto,
                            "dst" => $dst
                        );
                    }
                    elseif ($action=="op"){
                        $datatopost = array(
                            "type" => "op",
                            "cmd" => $element
                        );
                    }
                    else {
                        $datatopost = array(
                            "type" => "config",
                            "action" => $action,
                            "xpath" => $xpath,
                            "element" => $element
                        );
                    }
                }

                if (!is_dir(USERSPACE_PATH . "/devices") && !mkdir($concurrentDirectory = USERSPACE_PATH . "/devices", 0766) && !is_dir($concurrentDirectory)) {
                    throw new \RuntimeException(sprintf('Directory "%s" was not created', $concurrentDirectory));
                }

                $debugapi = USERSPACE_PATH . "/devices/debug.txt";

                $curl_log = fopen($debugapi, 'a+');
                /*$fields_string = array();

                foreach ($datatopost as $key1 => $value1) {
                    if ($key1 != "key") {
                        $fields_string[] = $key1 . '=' . $value1;
                    }
                }
                $url0 = "https://" . $devicePath . "?" . implode("&", $fields_string);
                $url = '<a href="' . $url0 . '" target=_blank>' . $url0 . '</a><br>';
                fwrite($curl_log, $url);*/

                // Custom headers to be added
                $headers = array(
                    'X-PAN-KEY: ' . $api_key,
                    'Content-Type: application/x-www-form-urlencoded'
                );
                curl_setopt($tuCurl, CURLOPT_HTTPHEADER, $headers);
                curl_setopt($tuCurl, CURLOPT_URL, "https://$devicePath");
                curl_setopt($tuCurl, CURLOPT_PORT, $port);
                curl_setopt($tuCurl, CURLOPT_STDERR, $curl_log);
                curl_setopt($tuCurl, CURLOPT_VERBOSE, DEVICE_DEBUG_CONNECTION_ENABLED==1);
                curl_setopt($tuCurl, CURLOPT_POST, 1);
                curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, 0);
                curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, 0);
                curl_setopt($tuCurl, CURLOPT_RETURNTRANSFER, 1);
                curl_setopt($tuCurl, CURLOPT_CONNECTTIMEOUT, 15);
                curl_setopt($tuCurl, CURLOPT_POSTFIELDS, http_build_query($datatopost));
                curl_setopt($tuCurl, CURLOPT_TIMEOUT, 0);
                sleep(1); // give time to start all job process in case the API is too fast
                $tuData = curl_exec($tuCurl);
                $e = curl_errno($tuCurl);

                switch ($e){
                    case 0:
                        $line = curl_multi_getcontent($tuCurl);
                        $xml = simplexml_load_string($line);
                        if (preg_match("/Not authorized to access/i", $line)) {
                            $apiCallID[] = $id;
                            $errorAPI[] = 'You do not have access to the device.';
                            $error = true;
                            $errorText = 'You do not have access to the device.';
                            $this->updateAPICallOutput($projectname, $id, $deviceEntity->id, 'fail', $errorText);
                        }
                        if (preg_match("/Invalid credentials./i", $line)) {
                            $apiCallID[] = $id;
                            $errorAPI[] = $line;
                            $error = true;
                            $errorText = $line;
                            $this->updateAPICallOutput($projectname, $id, $deviceEntity->id, 'fail',$errorText);
                        }
                        elseif (preg_match("/Authentication failed: Invalid username or password/i", $line)) {
                            $apiCallID[] = $id;
                            $errorAPI[] = 'Authentication failed: Invalid username or password.';
                            $error = true;
                            $errorText = 'Authentication failed: Invalid username or password.';
                            $this->updateAPICallOutput($projectname, $id, $deviceEntity->id, 'fail',$errorText);
                        }
                        else {
                            $arr = $xml->attributes();
                            if ($arr["status"] == "success") {
                                $this->updateAPICallOutput($projectname, $id, $deviceEntity->id, 'success',$xml->msg->asXML());
                                //Check if this was a bulk API call, and if so, update also the members
                                $query_ids = "SELECT xml_initial as ids FROM output_mapping WHERE id = '$id' AND table_name = 'grouping'";
                                $result_ids = $projectdb->query($query_ids);
                                if($result_ids->num_rows>0){
                                    $this->updateAPICallOutputBulk($projectname, $id, $deviceEntity->id, 'success',$xml->msg->asXML());
                                }
//                                $projectdb->query("UPDATE output_mapping SET output='$newline',state='success' WHERE id='$id';");

                                //TODO: Check how the modified should be defined and if "source" should be provided
//                                //Update modified a '0'
//                                $tables_to_modify = array("address", "address_groups_id", "services", "services_groups_id",
//                                    "applications", "applications_filters", "applications_groups",
//                                    "appoverride_rules", "external_list", "interface_management_profile",
//                                    "interfaces", "log_settings", "nat_rules", "profiles", "profiles_groups",
//                                    "regions", "reports", "response_pages", "schedules", "security_rules",
//                                    "tag", "routes_static", "zones");
//
//                                $getTable = $projectdb->query("SELECT table_name FROM output_mapping WHERE id = '$id' ;");
//                                if ($getTable->num_rows > 0) {
//                                    $getTableData = $getTable->fetch_assoc();
//                                    $table_name_mod = $getTableData['table_name'];
//                                    if ($table_name_mod == "address_groups") {
//                                        $table_name_mod = "address_groups_id";
//                                    }
//                                    if ($table_name_mod == "services_groups") {
//                                        $table_name_mod = "services_groups_id";
//                                    }
//
//                                    if (in_array($table_name_mod, $tables_to_modify)) {
//                                        $getAlterTable = $projectdb->query("UPDATE $table_name_mod SET modified = '2';");
//                                    }
//                                }
                            }
                            else {
                                $apiCallID[] = $id;
                                echo $xml->asXML();
                                $errorAPI[] = $xml->msg->asXML();
                                $error = true;
                                $errorText = $xml->msg->asXML();
//                                $projectdb->query("UPDATE output_mapping SET output='$newline',state='fail' WHERE id='$id';");
                                $this->updateAPICallOutput($projectname, $id, $deviceEntity->id, 'fail',$xml->msg->asXML());
                            }
                        }

                        break;

                    case 6:
                        $apiCallID[] =$id;
                        $error = true;
                        $errorText = 'Error Code '.$e.': The HostName could not be resolved';
                        $this->updateAPICallOutput($projectname, $id, $deviceEntity->id, 'fail',$errorText);
                        $errorAPI[] = $errorText;
                        break;

                    case 7:
                        $apiCallID[] =$id;
                        $error = true;
                        $errorText = 'Error Code '.$e.': The connection with the device cannot be established. Please, revise your connection parameters';
                        $this->updateAPICallOutput($projectname, $id, $deviceEntity->id, 'fail',$errorText);
                        $errorAPI[] = $errorText;
                        break;

                    case 21:
                    case 22:
                    case 23:
                    case 24:
                    case 25:
                    case 26:
                        $apiCallID[] =$id;
                        $error = true;
                        $errorText = 'Error Code '.$e.': The connection with the device returned an error. Please try again';
                        $this->updateAPICallOutput($projectname, $id, $deviceEntity->id, 'fail',$errorText);
                        $errorAPI[] = $errorText;
                        break;

                    case 27:
                        $apiCallID[] =$id;
                        $error = true;
                        $errorText = 'Error Code '.$e.': The connection with the device returned an error. Out of memory. Please, report this error for improvement';
                        $this->updateAPICallOutput($projectname, $id, $deviceEntity->id, 'fail',$errorText);
                        $errorAPI[] = $errorText;
                        break;

                    case 28:
                        $apiCallID[] =$id;
                        $error = true;
                        $errorText = 'The connection with the device cannot be established.';
                        $this->updateAPICallOutput($projectname, $id, $deviceEntity->id, 'fail',$errorText);
                        $errorAPI[] = $errorText;
                        break;

                    default:
                        $apiCallID[] =$id;
                        $error = true;
                        $errorText = 'Error Code '.$e.': The connection with the device cannot be established. Please, report Error Code for improvement';
                        $this->updateAPICallOutput($projectname, $id, $deviceEntity->id, 'fail',$errorText);
                        $errorAPI[] = $errorText;
                        break;
                }

                if($error){
                    $this->increaseFailed();
                }
                else{
                    $this->increaseCompleted();
                }
            }
            curl_close($tuCurl);
            fclose($curl_log);
        }

        if(count($apiCallID) == 0) {
            $this->setCompletedSilent('');
        }
        else {
            $this->setFailedSilent("There were problems sending the API calls with ids [".implode(';', $apiCallID)."]", "[".implode(';', $errorAPI)."]");
        }
    }
}
