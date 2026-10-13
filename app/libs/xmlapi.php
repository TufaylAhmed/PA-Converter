<?php
# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
#require_once('../bin/Authentication.php');

require_once $_SERVER['DOCUMENT_ROOT'] . '/libs/common/definitions.php';
require_once INC_ROOT . '/libs/common/MTLogger.php';

require_once INC_ROOT . '/libs/Security/OpenSSLTools.php';
require_once INC_ROOT . '/libs/common/ForceUTF8/Encoding.php';

use PaloAltoNetworks\Expedition\Security\OpenSSLTools;
use Cartalyst\Sentinel\Native\Facades\Sentinel;


class CurlConnect
{

    protected $tuCurl;
    protected $headerOut = 0;
    protected $stderr;
    protected $url = '';
    protected $port = 443;
    protected $verbose = DEVICE_DEBUG_CONNECTION_ENABLED;
    protected $header = 0;
    protected $post = 1;
    protected $sslVerify = 0;
    protected $verifyHost = 0;
    protected $returnTransfer = 1;
    protected $connectTimeout = 50;
    protected $postfields = '';
    protected $timeout = DEVICE_CONNECTION_TIMEOUT;
    protected $valid = false;
    protected $httpheader;

    public function __construct($tuCurl, $params)
    {
        if (!$this->fill_fields($tuCurl, $params)) {
            return null;
        }
        if (!$this->setopt()) {
            return null;
        }
        $this->valid = true;
        return $this;
    }

    private function setopt()
    {
        if (isset($this->headerOut)) {
            if (!curl_setopt($this->tuCurl, CURLINFO_HEADER_OUT, $this->headerOut)) {
                $this->valid = false;
                return false;
            }
        }

        if (isset($this->stderr)) {
            if (!curl_setopt($this->tuCurl, CURLOPT_STDERR, $this->stderr)) {
                $this->valid = false;
                return false;
            }
        }

        if (isset($this->url)) {
            if (!curl_setopt($this->tuCurl, CURLOPT_URL, $this->url)) {
                $this->valid = false;
                return false;
            }
        }

        if (isset($this->port)) {
            if (!curl_setopt($this->tuCurl, CURLOPT_PORT, $this->port)) {
                $this->valid = false;
                return false;
            }
        }

        if (isset($this->verbose)) {
            if (!curl_setopt($this->tuCurl, CURLOPT_VERBOSE, $this->verbose)) {
                $this->valid = false;
                return false;
            }
        }

        if (isset($this->header)) {
            if (!curl_setopt($this->tuCurl, CURLOPT_HEADER, $this->header)) {
                $this->valid = false;
                return false;
            }
        }

        if (isset($this->post)) {
            if (!curl_setopt($this->tuCurl, CURLOPT_POST, $this->post)) {
                $this->valid = false;
                return false;
            }
        }

        if (isset($this->sslVerify)) {
            if (!curl_setopt($this->tuCurl, CURLOPT_SSL_VERIFYPEER, $this->sslVerify)) {
                $this->valid = false;
                return false;
            }
        }

        if (isset($this->verifyHost)) {
            if (!curl_setopt($this->tuCurl, CURLOPT_SSL_VERIFYHOST, $this->verifyHost)) {
                $this->valid = false;
                return false;
            }
        }

        if (isset($this->returnTransfer)) {
            if (!curl_setopt($this->tuCurl, CURLOPT_RETURNTRANSFER, $this->returnTransfer)) {
                $this->valid = false;
                return false;
            }
        }

        if (isset($this->connectTimeout)) {
            if (!curl_setopt($this->tuCurl, CURLOPT_CONNECTTIMEOUT, $this->connectTimeout)) {
                $this->valid = false;
                return false;
            }
        }

        if (isset($this->httpheader)) {
            if (!curl_setopt($this->tuCurl, CURLOPT_HTTPHEADER, $this->httpheader)) {
                $this->valid = false;
                return false;
            }
        }

        if (isset($this->postfields)) {
            if (!curl_setopt($this->tuCurl, CURLOPT_POSTFIELDS, $this->postfields)) {
                $this->valid = false;
                return false;
            }
        }

        if (isset($this->timeout)) {
            if (!curl_setopt($this->tuCurl, CURLOPT_TIMEOUT, $this->timeout)) {
                $this->valid = false;
                return false;
            }
        }

        $this->valid = true;
        return true;
    }

    private function fill_fields($tuCurl, $params)
    {
        if (isset($tuCurl)) {
            $this->tuCurl = $tuCurl;
        } else {
            return false;
        }

        if (isset($params['headerOut'])) {
            $this->headerOut = 0;
        }
        if (isset($params['stderr'])) {
            $this->stderr = fopen($params['stderr'], 'a+');
        } else {
            checkFolderExists(USERSPACE_PATH . "/devices/");
            $this->stderr = fopen(USERSPACE_PATH . "/devices/debug.txt", 'a+');
        }

        if (isset($params['url'])) {
            $this->url = $params['url'];
        }
        if (isset($params['port'])) {
            $this->port = $params['port'];
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

    public function exec()
    {
        return curl_exec($this->tuCurl);
    }

    public function close()
    {
        if (isset($this->stderr)) {
            fclose($this->stderr);
        }
    }
}

function getConfigBackup_Target($hostname, $devicename, $api_key, $port, $target = '', $target_device = '')
{
    if ($api_key != "") {
//        global $pandb;
        global $app;

        // define params for the query
        $type = "config";
        $action = "show";
        $xpath ="/config/predefined/url-categories";

        $debug_api = USERSPACE_PATH . "/devices/debug.txt";
        $curl_log = fopen($debug_api, 'a+');

        //$devicePath = $hostname . "/api";
        $devicePath = "https://" . $hostname . ":". $port . "/api?type=". $type ."&action=". $action;
        if($target!==""){
            $devicePath .= "&target=" . $target;
        }

        $tuCurl = curl_init();

        // Custom headers to be added
        $headers = array(
            'X-PAN-KEY: ' . $api_key
        );
        curl_setopt($tuCurl, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($tuCurl, CURLOPT_URL, $devicePath);
        curl_setopt($tuCurl, CURLOPT_TIMEOUT, DEVICE_CONNECTION_TIMEOUT); // number of seconds prior to a timeout
        curl_setopt($tuCurl, CURLOPT_VERBOSE, DEVICE_DEBUG_CONNECTION_ENABLED==1);
        curl_setopt($tuCurl, CURLOPT_STDERR, $curl_log);
        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($tuCurl, CURLOPT_RETURNTRANSFER, true);

        $tuData = curl_exec($tuCurl);


//        $devicePath = $hostname . "/api";
//        if ($target != '') {
//            $datatopost = array(
//                "type" => "config",
//                "action" => 'show',
//                "key" => $api_key,
//                "target" => $target
//            );
//        } else {
//            $datatopost = array(
//                "type" => "config",
//                "action" => 'show',
//                "key" => $api_key
//            );
//        }
//
//        $tuCurl = curl_init();
//        checkFolderExists(USERSPACE_PATH . "/devices/");
//        $debugapi = USERSPACE_PATH . "/devices/debug.txt";
////        $curl_log = fopen($debugapi, 'a+');
//        $params = [
//            'url' => "https://$devicePath",
//            'port' => $port,
//            'stderr' => $debugapi,
//            'postfields' => $datatopost,
//        ];
//        $curlObj = new CurlConnect($tuCurl, $params);
//        $tuData = $curlObj->exec();

        $e = curl_errno($tuCurl);
        if (!checkConnectionErrors($e)) {
            //$curlObj->close();
            curl_close($tuCurl);
            return getErrorCode(ERROR_ConnectionNotEstablished);
        }

        $line = curl_multi_getcontent($tuCurl);
        //$curlObj->close();
        curl_close($tuCurl);
        unset($devicePath, $api_key);

        //Check the output is an XML
        $result = simplexml_load_string($line, 'SimpleXmlElement', LIBXML_NOERROR | LIBXML_ERR_FATAL | LIBXML_ERR_NONE);
        if (false == $result) {
            $logger = MTLogger::getInstance();
            $logger->log(json_encode(array('success' => false, 'message' => getErrorCode(ERROR_NotExpectedFileFormat, 'description'))));
            return getErrorCode(ERROR_NotExpectedFileFormat);
            exit(0);
        }

        $xml1 = simplexml_load_string($line);

        if (!isset($xml1) || $xml1->attributes()->status === "error"
            || preg_match('/response status="error"/', $line) || preg_match("/response status = 'error'/i", $tuData)) {
            if(isset($xml1->result->msg)) {
                $msg = $xml1->result->msg;
            }else{
                $msg = $xml1->msg->line;
            }
            $logger = MTLogger::getInstance();
            $logger->log(json_encode(array('success' => false, 'message' => "$msg")));
            return getErrorCode(ERROR_SpecificPANOS);
            exit;
        } else {

            $newline = str_replace(array("<response status=\"success\"><result>", "</result></response>"), "", $line);
            $xml = simplexml_load_string($newline);

            //Update the properties of the device

            $getPanos = $xml->attributes()->version;
            if (isset($xml->devices->entry->deviceconfig->system->hostname)) {
                $device = $xml->devices->entry->deviceconfig->system->hostname;
            }

            #Update with the PANOS Version
            $params = array();
            if ($getPanos != "") {
                #$pandb->query("UPDATE devices set panos='$getPanos' where hostname='$hostname' and name='$devicename'");
                $params = [
                    'panos' => $getPanos,
                ];
            }
            /*if ($device != "") {
                $params = [
                    'device' => $device,
                ];
                #$pandb->query("UPDATE devices set device='$device' where hostname='$hostname' and name='$devicename'");
                //TODO Update the correct device
            }*/

            $deviceObj = $app->device->where('serial', $target_device)->first();
            $deviceObj->update($params);

            if (!is_dir(USERSPACE_PATH . "/devices") && !mkdir($concurrentDirectory = USERSPACE_PATH . "/devices", 0766) && !is_dir($concurrentDirectory)) {
                $logger = MTLogger::getInstance();
                $logger->log(json_encode(array('success' => false, 'message' => sprintf('Directory "%s" was not created', $concurrentDirectory))));
                return getErrorCode(FileNotCreated);
            }

            if ($target_device != '') {
                $deviceFolder = USERSPACE_PATH . "/devices/$target_device/";
                $File = USERSPACE_PATH . "/devices/$target_device/ConfigBackup.xml";
            } else {
                $deviceFolder = USERSPACE_PATH . "/devices/$devicename/";
                $File = USERSPACE_PATH . "/devices/$devicename/ConfigBackup.xml";
            }
            if (!file_exists($deviceFolder) && !mkdir((string)$deviceFolder, 0777) && !is_dir((string)$deviceFolder)) {
                $logger = MTLogger::getInstance();
                $logger->log(json_encode(array('success' => false, 'message' => sprintf('Directory "%s" was not created', $deviceFolder))));
                return getErrorCode(FileNotCreated);
            }

//            $Handle = fopen($File, 'w');
//            fwrite($Handle, $newline);
//            fclose($Handle);
//
//            if ((file_exists($File)) and ( filesize($File) != 0)) {
//                $params = ['config'=>1];
//                $deviceObj->update($params);
////                    $pandb->query("UPDATE devices SET config='1' WHERE name='$target_device'");
//            }

            //Encrypt the config file
            if (!$deviceObj) {
                echo("Device not found in our registry");
            } else {
                if (!$keyObj = $app->accessKey->where("type", "device")->where("lid", $deviceObj->id)->get()->first()) {
                    echo "We do not have keys\n";
                    require_once INC_ROOT . '/userManager/API/devices/manageEncryptionKeys.php';
                    generateEncryptionKeys($deviceObj);
                    $keyObj = $app->accessKey->where("type", "device")->where("lid", $deviceObj->id)->get()->first();
                }
                $encrypter = new OpenSSLTools($keyObj->key, $keyObj->iv);
                $result = $encrypter->encryptToFile($newline, "$File.dat");
                if ($result['code']) {
                    $params = ['config' => '1'];
                    $deviceObj->update($params);
                    return getErrorCode(Correct);
                } else {
                    $params = ['config' => '0'];
                    $deviceObj->update($params);
                    return getErrorCode(ERROR_FileNotCreated);
                }
            }

            #Save as a Template
            //if($target_device != '') {
            //    checkFolderExists(USERSPACE_PATH."/Templates/");
            //    $File = USERSPACE_PATH."/Templates/$target_device-$getPanos.xml";
            //    $Handle = fopen($File, 'w');
            //    fwrite($Handle, $newline);
            //    fclose($Handle);
            //}

            return getErrorCode(Correct);
        }

    }
}

//function getPushedSharedPolicy_Target($hostname, $devicename, $api_key, $port, $target, $target_device, $vsys)
//{
//    global $app;
//    if ($api_key != "") {
//        global $pandb;
//        if ($vsys == "") {
//            $vsys = "vsys1";
//        }
//        $devicePath = $hostname . "/api";
//        $datatopost = array(
//            "type" => "op",
//            "cmd" => '<show><config><pushed-shared-policy><vsys>' . $vsys . '</vsys></pushed-shared-policy></config></show>',
//            "key" => $api_key,
//            "target" => $target
//        );
//
////        $tuCurl = curl_init();
////        curl_setopt($tuCurl, CURLOPT_URL, "https://$devicePath");
////        curl_setopt($tuCurl, CURLOPT_PORT, $port);
////        curl_setopt($tuCurl, CURLOPT_VERBOSE, 0);
////        curl_setopt($tuCurl, CURLOPT_HEADER, 0);
////        curl_setopt($tuCurl, CURLOPT_POST, 1);
////        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, 0);
////        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, 0);
////        curl_setopt($tuCurl, CURLOPT_RETURNTRANSFER, 1);
////        curl_setopt($tuCurl, CURLOPT_CONNECTTIMEOUT, 1500);
////        curl_setopt($tuCurl, CURLOPT_POSTFIELDS, $datatopost);
////        curl_setopt($tuCurl, CURLOPT_TIMEOUT, 0);
////        $tuData = curl_exec($tuCurl);
//
//        $tuCurl = curl_init();
//        checkFolderExists(USERSPACE_PATH . "/devices/");
//        $debugapi = USERSPACE_PATH . "/devices/debug.txt";
////        $curl_log = fopen($debugapi, 'a+');
//        $params = [
//            'url' => "https://$devicePath",
//            'port' => $port,
//            'stderr' => $debugapi,
//            'postfields' => $datatopost,
//        ];
//        $curlObj = new CurlConnect($tuCurl, $params);
//        $tuData = $curlObj->exec();
//
//        $e = curl_errno($tuCurl);
//        if (!checkConnectionErrors($e)) {
//            return getErrorCode(ERROR_ConnectionNotEstablished);
//        }
//
//        $line = curl_multi_getcontent($tuCurl);
//        curl_close($tuCurl);
//        $xml1 = simplexml_load_string($line);
//        if (preg_match("/response status = 'error'/i", $line)) {
//            $msg = $xml1->result->msg;
//            $logger = MTLogger::getInstance();
//            $logger->log(json_encode(array('success' => false, 'message' => "$msg")));
//            exit;
//
//            /*if (preg_match("/Not authorized to access/i", $newline)) {
//                echo json_encode(array('success' => false, 'message' => 'You do not have access to the device'));
//                exit;
//            } elseif (preg_match("/Authentication failed: Invalid username or password/i", $newline)) {
//                echo json_encode(array('success' => false, 'message' => 'Authentication failed: Invalid username or password'));
//                exit;
//            */
//        } else {
//            $newline = str_replace(array("<response status=\"success\"><result>", "</result></response>"), "", $line);
//            if (is_dir(USERSPACE_PATH . "/devices")) {
//
//            } else {
//                mkdir(USERSPACE_PATH . "/devices", 0766);
//            }
//            $deviceFolder = USERSPACE_PATH . "/devices/$target_device/";
//            if (file_exists($deviceFolder)) {
//
//            } else {
//                mkdir("$deviceFolder", 0777);
//            }
//            $File = USERSPACE_PATH . "/devices/$target_device/SharedPushedPolicy_" . $vsys . ".xml";
//            if (!preg_match("/No shared policy pushed to device/i", $newline)) {
//                $deviceObj = $app->device->where("serial", $target_device)->first();
//                $keyObj = $app->accessKey->where("type", "device")->where("lid", $deviceObj->id)->first();
//                $encryptor = new OpenSSLTools($keyObj->key, $keyObj->iv);
//                $encryptor->encryptToFile($newline, "$File.dat");
////                $Handle = fopen($File, 'w');
////                fwrite($Handle, $newline);
////                fclose($Handle);
//            }
//
//        }
//
//    }
//}

//function getPushedSharedPolicy($hostname, $api_key, $port, $target_device, $vsys)
//{
//    if ($api_key != "") {
//        global $pandb;
//        if ($vsys == "") {
//            $vsys = "vsys1";
//        }
//        $devicePath = $hostname . "/api";
//        $datatopost = array(
//            "type" => "op",
//            "cmd" => '<show><config><pushed-shared-policy><vsys>' . $vsys . '</vsys></pushed-shared-policy></config></show>',
//            "key" => $api_key
//        );
//
////        $tuCurl = curl_init();
////        curl_setopt($tuCurl, CURLOPT_URL, "https://$devicePath");
////        curl_setopt($tuCurl, CURLOPT_PORT , $port);
////        curl_setopt($tuCurl, CURLOPT_VERBOSE, 0);
////        curl_setopt($tuCurl, CURLOPT_HEADER, 0);
////        curl_setopt($tuCurl, CURLOPT_POST, 1);
////        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, 0);
////        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, 0);
////        curl_setopt($tuCurl, CURLOPT_RETURNTRANSFER, 1);
////        curl_setopt($tuCurl, CURLOPT_CONNECTTIMEOUT ,1500);
////        curl_setopt ($tuCurl, CURLOPT_POSTFIELDS, $datatopost);
////        curl_setopt($tuCurl, CURLOPT_TIMEOUT, 0);
////        $tuData = curl_exec($tuCurl);
////
////        ///
//
//        $tuCurl = curl_init();
//        checkFolderExists(USERSPACE_PATH . "/devices/");
//        $debugapi = USERSPACE_PATH . "/devices/debug.txt";
////        $curl_log = fopen($debugapi, 'a+');
//        $params = [
//            'url' => "https://$devicePath",
//            'port' => $port,
//            'stderr' => $debugapi,
//            'postfields' => $datatopost,
//        ];
//        $curlObj = new CurlConnect($tuCurl, $params);
//        $tuData = $curlObj->exec();
//
//        $e = curl_errno($tuCurl);
//        if (!checkConnectionErrors($e)) {
//            $curlObj->close();
//            curl_close($tuCurl);
//            return getErrorCode(ERROR_ConnectionNotEstablished);
//        }
//
//        $line = curl_multi_getcontent($tuCurl);
//        curl_close($tuCurl);
//        $xml1 = simplexml_load_string($line);
//
//        if (preg_match("/response status = 'error'/i", $tuData)) {
//            $msg = $xml1->result->msg;
//            $logger = MTLogger::getInstance();
//            $logger->log(json_encode(array('success' => false, 'message' => "$msg")));
//            exit;
//
//            /*if (preg_match("/Not authorized to access/i",$newline)){
//                echo json_encode(array('success'=>false,'message'=>'You do not have access to the device'));
//                exit;
//            } elseif (preg_match("/Authentication failed: Invalid username or password/i",$newline)){
//                echo json_encode(array('success'=>false,'message'=>'Authentication failed: Invalid username or password'));
//                exit;
//            } elseif (preg_match("/No shared policy pushed to device/i",$newline)){
//            */
//
//        } else {
//
//            $newline = str_replace(array("<response status=\"success\"><result>", "</result></response>"), "", $line);
//            if (!is_dir(USERSPACE_PATH . "/devices")) {
//                mkdir(USERSPACE_PATH . "/devices", 0766);
//            }
//            $deviceFolder = USERSPACE_PATH . "/devices/$target_device/";
//            if (!file_exists($deviceFolder)) {
//                mkdir("$deviceFolder", 0777);
//            }
//            $File = USERSPACE_PATH . "/devices/$target_device/SharedPushedPolicy_" . $vsys . ".xml";
//            if (!preg_match("/No shared policy pushed to device/i", $newline)) {
//                $Handle = fopen($File, 'w');
//                fwrite($Handle, $newline);
//                fclose($Handle);
//            }
//        }
//    }
//
//}

//function getPanoramaDevicesConnected($hostname, $devicename, $api_key, $port) {
//    if ($api_key != "") {
//        global $pandb;
//        $devicePath = $hostname . "/esp/restapi.esp";
//        $datatopost = array(
//            "type" => "op",
//            "cmd" => '<show><devices><connected></connected></devices></show>',
//            "key" => $api_key
//        );
//
//        $tuCurl = curl_init();
//        curl_setopt($tuCurl, CURLOPT_URL, "https://$devicePath");
//        curl_setopt($tuCurl, CURLOPT_PORT, $port);
//        curl_setopt($tuCurl, CURLOPT_VERBOSE, 0);
//        curl_setopt($tuCurl, CURLOPT_HEADER, 0);
//        curl_setopt($tuCurl, CURLOPT_POST, 1);
//        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, 0);
//        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, 0);
//        curl_setopt($tuCurl, CURLOPT_RETURNTRANSFER, 1);
//        curl_setopt($tuCurl, CURLOPT_CONNECTTIMEOUT, 1500);
//        curl_setopt($tuCurl, CURLOPT_POSTFIELDS, $datatopost);
//        curl_setopt($tuCurl, CURLOPT_TIMEOUT, 0);
//        $tuData = curl_exec($tuCurl);
//
//        if (curl_errno($tuCurl) == 28) {
//            echo json_encode(array('success' => false, 'message' => 'The connection with the device cannot be established. Changes Saved'));
//            exit(0);
//        } else {
//            $line = curl_multi_getcontent($tuCurl);
//            curl_close($tuCurl);
//            $xml1 = simplexml_load_string($line);
//
//            if (preg_match("/response status = 'error'/i", $tuData)) {
//                $msg = $xml1->result->msg;
//                echo json_encode(array('success' => false, 'message' => "$msg"));
//                exit;
//
//            /*if (preg_match("/Not authorized to access/i", $newline)) {
//                echo json_encode(array('success' => false, 'message' => 'You do not have access to the device'));
//                exit;
//            } elseif (preg_match("/Authentication failed: Invalid username or password/i", $newline)) {
//                echo json_encode(array('success' => false, 'message' => 'Authentication failed: Invalid username or password'));
//                exit;
//            */
//            }
//            else {
//                $newline = str_replace(array("<response status=\"success\"><result>", "</result></response>"), "", $line);
//                $xml = simplexml_load_string($newline);
//                $panorama_hostname = $hostname;
//                $panorama_devicename = $devicename;
//                $panorama_port = $port;
//                if (isset($xml)) {
//                    $add_device = array();
//                    foreach ($xml->entry as $child => $data) {
//                        $serial = $data->attributes()->name;
//                        foreach ($data as $key => $value) {
//                            if ($key == "serial") {
//                                $serial = $value;
//                            }
//                            if ($key == "app-version") {
//                                $appversion = $value;
//                            }
//                            if ($key == "app-release-date") {
//                                $appreleasedate = $value;
//                            }
//                            if ($key == "threat-version") {
//                                $threatversion = $value;
//                            }
//                            if ($key == "threat-release-date") {
//                                $threatreleasedate = $value;
//                            }
//                            if ($key == "family") {
//                                if ($value == "vm") {
//                                    $model = "vm-series";
//                                } elseif (($value == "200") OR ( $value == "500") OR ( $value == "2000") OR ( $value == "3000") OR ( $value == "4000") OR ( $value == "5000") OR ( $value == "7000")) {
//                                    $model = "pa" . $value;
//                                } elseif ($value == "pc") {
//                                    $model = "vm-panorama";
//                                } elseif ($value == "m") {
//                                    $model = "m100";
//                                } else {
//                                    $model = $value;
//                                }
//                            }
//                            if ($key == "hostname") {
//                                $name = $value;
//                            }
//                            if ($key == "ip-address") {
//                                $hostname = $value;
//                            }
//                            if ($key == "sw-version") {
//                                $version = $value;
//                            }
//                            $ispanorama = 0;
//                        }
//
//                        $isDup = $pandb->query("SELECT id FROM devices WHERE name='$name';");
//                        //TODO Update the correct device
//                        if ($isDup->num_rows == 0) {
//                            $add_device[] = "('$name','$version','$threatversion','$threatreleasedate','$appversion','$appreleasedate','$hostname','$ispanorama','$model','$serial','$name','$panorama_devicename')";
//                        } else {
//                            #Update
//                            $pandb->query("UPDATE devices SET panos='$version', threatversion='$threatversion', threatreleasedate='$threatreleasedate',appversion='$appversion',appreleasedate='$appreleasedate',hostname='$hostname',ispanorama='$ispanorama',type='$model',serial='$serial',device='$name',management='$panorama_devicename' WHERE name='$name';");
//                            //TODO Update the correct device
//                        }
//                        getConfigBackup_Target($panorama_hostname, $panorama_devicename, $api_key, $panorama_port, $serial, $name);
//                        if (file_exists(USERSPACE_PATH."/devices/" . $name . "/ConfigBackup.xml")) {
//                            $xml1 = simplexml_load_file(USERSPACE_PATH."/devices/" . $name . "/ConfigBackup.xml");
//                            $vsys1 = $xml1->xpath("//vsys/entry");
//                            foreach ($vsys1 as $key => $val) {
//                                $getDGVsys = $val->attributes()->name;
//                                getPushedSharedPolicy_Target($panorama_hostname, $panorama_devicename, $api_key, $panorama_port, $serial, $name, $getDGVsys);
//                            }
//                        }
//                    }
//                    if (count($add_device) > 0) {
//                        $pandb->query("INSERT INTO devices (name,panos,threatversion,threatreleasedate,appversion,appreleasedate,hostname,ispanorama,type,serial,device,management) VALUES " . implode(",", $add_device) . ";");
//                        //TODO Update the correct device
//                    }
//                }
//            }
//        }
//    }
//}
function checkConnectionErrors($e)
{
    switch ($e) {
        case 0:
            return true;
            break;

        case 6:
            $logger = MTLogger::getInstance();
            $logger->log(json_encode(array('success' => false, 'msg' => "Error Code $e: The HostName could not be resolved")));
            return false;;
            break;

        case 7:
            $logger = MTLogger::getInstance();
            $logger->log(json_encode(array('success' => false, 'msg' => "Error Code $e: The connection with the device cannot be established. Please, revise your connection parameters")));
            return false;;
            break;

        case 21:
        case 22:
        case 23:
        case 24:
        case 25:
        case 26:
            $logger = MTLogger::getInstance();
            $logger->log(json_encode(array('success' => false, 'msg' => "Error Code $e: The connection with the device returned an error. Please try again")));
            return false;
            break;

        case 27:
            $logger = MTLogger::getInstance();
            $logger->log(json_encode(array('success' => false, 'msg' => "Error Code $e: The connection with the device returned an error. Out of memory. Please, report this error for improvement")));
            return false;
            break;

        case 28:
            $logger = MTLogger::getInstance();
            $logger->log(json_encode(array('success' => false, 'msg' => "Error Code $e: The connection with the device cannot be established. Connection timeout")));
            return false;
            break;

        default:
            $logger = MTLogger::getInstance();
            $logger->log(json_encode(array('success' => false, 'msg' => "Error Code $e: The connection with the device cannot be established. Please, report Error Code for improvement")));
            return false;
            break;
    }
}

function getPanoramaDevicesConnected($hostname, $devicename, $api_key, $port)
{
    global $app;

    require_once INC_ROOT . '/libs/PaloAltoNetworks/Connections/connection.php';
    require_once INC_ROOT . '/libs/definitions/deviceDefinitions.php';

    if ($api_key != "") {
        $pandbRBAC = selectDatabase('pandbRBAC');

        // check for already connected devices
        $connected_devices = [];
        $query_connected_devices = "SELECT serial FROM devices WHERE management = '$devicename';";
        $get_connected_devices = $pandbRBAC->query($query_connected_devices);
        if($get_connected_devices->num_rows>0) {
            while ($device = $get_connected_devices->fetch_assoc()) {
                $connected_devices[] = $device['serial'];
            }
        }

        // define params for the query
        $type = "op";
        $cmd = "<show><devices><all></all></devices></show>";
        $action = "show";

        $debug_api = USERSPACE_PATH . "/devices/debug.txt";
        $curl_log = fopen($debug_api, 'a+');

        $devicePath = "https://" . $hostname . ":". $port . "/api?type=". $type . "&action=". $action . "&cmd=". $cmd;

        $panorama = $hostname;

//        $devicePath = $hostname . "/api";
//        $datatopost = array(
//            "type" => "op",
//            "cmd" => '<show><devices><all></all></devices></show>',
//            "key" => $api_key
//        );

        $tuCurl = curl_init();
//        $curlConnection = registerConnection('', $hostname);

        // Custom headers to be added
        $headers = array(
            'X-PAN-KEY: ' . $api_key
        );
        curl_setopt($tuCurl, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($tuCurl, CURLOPT_URL, $devicePath);
        curl_setopt($tuCurl, CURLOPT_TIMEOUT, DEVICE_CONNECTION_TIMEOUT); // number of seconds prior to a timeout
        curl_setopt($tuCurl, CURLOPT_VERBOSE, DEVICE_DEBUG_CONNECTION_ENABLED==1);
        curl_setopt($tuCurl, CURLOPT_STDERR, $curl_log);
        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($tuCurl, CURLOPT_RETURNTRANSFER, true);

        $tuData = curl_exec($tuCurl);

//        $tuCurl = $curlConnection->curlConnection;
//
//        $params = [
//            'url' => "https://$devicePath",
//            'port' => $port,
//            'postfields' => $datatopost,
//        ];
//        $curlObj = new CurlConnect($tuCurl, $params);
//        $tuData = $curlObj->exec();

        $e = curl_errno($tuCurl);
        if (!checkConnectionErrors($e)) {
            //$curlObj->close();
            return getErrorCode(ERROR_ConnectionNotEstablished);
        }

        $line = curl_multi_getcontent($tuCurl);


        $result = simplexml_load_string($line, 'SimpleXmlElement', LIBXML_NOERROR | LIBXML_ERR_FATAL | LIBXML_ERR_NONE);
        if (false == $result) {
            $logger = MTLogger::getInstance();
            $logger->log(json_encode(array('success' => false, 'message' => getErrorCode(ERROR_NotExpectedFileFormat, 'description'))));
            return getErrorCode(ERROR_NotExpectedFileFormat);
            exit(0);
        }

        $xml1 = simplexml_load_string($line);

        if (!isset($xml1) || $xml1->attributes()->status === "error"
            || preg_match('/response status="error"/', $line) || preg_match("/response status = 'error'/i", $tuData)) {
            if(isset($xml1->result->msg)) {
                $msg = $xml1->result->msg;
            }else{
                $msg = $xml1->msg->line;
            }
            $logger = MTLogger::getInstance();
            $logger->log(json_encode(array('success' => false, 'message' => "$msg")));
            return getErrorCode(ERROR_SpecificPANOS);
            exit;
        } else {

            $newline = str_replace(array("<response status=\"success\"><result>", "</result></response>"), "", $line);
            $xml = simplexml_load_string($newline);
            $panorama_devicename = $devicename;
            if (isset($xml)) {
                $newDevices = array();
                foreach ($xml->entry as $child => $data) {
                    $serial = $data->attributes()->name;
                    $serial = ForceUTF8\Encoding::fixUTF8($serial);

                    // remove $serial from $connected_devices
                    if (($key = array_search($serial, $connected_devices)) !== false) {
                        array_splice($connected_devices, $key, 1);
                    }

                    $urlfilteringversion = $avversion = $wildfireversion = $deactivated = $connected = $uptime = $appversion = $appreleasedate = $threatversion = $threatreleasedate = $model = $name = $hostname = $urldb = $ispanorama = '';
                    foreach ($data as $key => $value) {
                        //if ($key == "serial") {
                        //    $serial = $value;
                        //}
                        $version = '';
                        if ($key == "app-version") {
                            $appversion = $value;
                        }
                        if ($key == "app-release-date") {
                            $appreleasedate = $value;
                        }
                        if ($key == "threat-version") {
                            $threatversion = $value;
                        }
                        if ($key == "threat-release-date") {
                            $threatreleasedate = $value;
                        }
                        if ($key == "family") {
                            if ($value == "vm") {
                                $model = "vm-series";
                            } elseif (in_array($value, getPanFwNumbers()))
//                                ($value == "200") OR ($value == "220") OR ( $value == "500") OR
//                                ( $value == "2000") OR ( $value == "3000") OR
//                                ( $value == "4000") OR ( $value == "5000") OR
//                                ( $value == "7000"))
                            {
                                $model = "pa" . $value;
                            } elseif ($value == "pc") {
                                $model = "vm-panorama";
                            } elseif ($value == "m") {
                                $model = "m100";
                            } else {
                                $model = $value;
                            }
                        }
                        if ($key == "hostname") {
                            $name = $value;
                        }
                        if ($key == "ip-address") {
                            $hostname = $value;
                        }
                        if ($key == "sw-version") {
                            $version = $value;
                        }
                        if ($key == "uptime") {
                            $uptime = $value;
                        }
                        if ($key == "connected") {
                            $connected = $value;
                        }
                        if ($key == "deactivated") {
                            $deactivated = $value;
                        }
                        if ($key == "wildfire-version") {
                            $wildfireversion = $value;
                        }
                        if ($key == "url-db") {
                            $urldb = $value;
                        }
                        if ($key == "av-version") {
                            $avversion = $value;
                        }
                        if ($key == "url-filtering-version") {
                            $urlfilteringversion = $value;
                        }
                        $ispanorama = 0;
                    }

                    $isDup = $pandbRBAC->query("SELECT id FROM devices WHERE serial='$serial';");
                    if ($isDup->num_rows == 0) {
                        $newDevices[] = [
                            'devicename' => ($name != '') ? $name : "Serial_" . $serial,
                            'panos' => $version,
                            'threatversion' => $threatversion,
                            'threatreleasedate' => $threatreleasedate,
                            'appversion' => $appversion,
                            'appreleasedate' => $appreleasedate,
                            'hostname' => $hostname,
                            'ispanorama' => $ispanorama,
                            'type' => $model,
                            'logtype' => 'csv',
                            'serial' => $serial,
                            'device' => $name,
                            'management' => $panorama_devicename,
                            'uptime' => $uptime,
                            'connected' => $connected,
                            'deactivated' => $deactivated,
                            'wildfireversion' => $wildfireversion,
                            'urldb' => $urldb,
                            'avversion' => $avversion,
                            'urlfilteringversion' => $urlfilteringversion
                        ];
                    } else {
                        #Update
                        if ($connected == "no") {
                            $params = [
                                'connected' => $connected,
                                'management' => $panorama_devicename,
                            ];
                        } else {
                            $params = [
                                'panos' => $version,
                                'threatversion' => $threatversion,
                                'threatreleasedate' => $threatreleasedate,
                                'appversion' => $appversion,
                                'appreleasedate' => $appreleasedate,
                                'hostname' => $hostname,
                                'ispanorama' => $ispanorama,
                                'type' => $model,
                                'devicename' => ($name != '') ? $name : "Serial_" . $serial,
                                'device' => $name,
                                'management' => $panorama_devicename,
                                'uptime' => $uptime,
                                'connected' => $connected,
                                'deactivated' => $deactivated,
                                'wildfireversion' => $wildfireversion,
                                'urldb' => $urldb,
                                'avversion' => $avversion,
                                'urlfilteringversion' => $urlfilteringversion
                            ];
                        }
                        $app->device->where('serial', $serial)->update($params);
                    }

                    // Go for Licenses
                    if (($connected == "yes")) {
                        $logger = MTLogger::getInstance();
                        $logger->log("Retrieving Licenses from: " . $serial . " Using " . $panorama . " as a Proxy.");
                        getLicenses_Target($panorama, $panorama_devicename, $api_key, $port, $serial, $tuCurl);

                        $logger = MTLogger::getInstance();
                        $logger->log("Retrieving Support from: " . $serial . " Using " . $panorama . " as a Proxy.");
                        getSupport_Target($panorama, $panorama_devicename, $api_key, $port, $serial, $tuCurl);
                    }

                }
                if (count($newDevices) > 0) {
                    foreach ($newDevices as $newDevice) {
//                        $app->device->insert([$newDevice]);
                        //create the roles
                        if (generate_device_roles($newDevice)) {
                            $app->device->insert([$newDevice]);
                        }
                    }
                }
                if (count($connected_devices) > 0) {
                    foreach ($connected_devices as $connected_device) {
                        $update_query= "UPDATE devices SET management = '' WHERE serial = '$connected_device';";
                        $pandbRBAC->query($update_query);
                    }
                }

            }

            return getErrorCode(Correct);
        }

//        unregisterConnection($curlConnection->name);
//        $curlObj->close();
    }
}

function generate_device_roles(array $firewall): bool
{
    global $app;

    $devicename = $firewall['serial'];
    $slug = "PANDevice_" . $devicename;

    if ($role_admin = Sentinel::findRoleBySlug($slug . '_admin')) {
        return false;
    }
    if ($role_admin = Sentinel::findRoleBySlug($slug . '_user')) {
        return false;
    }
    if ($role_admin = Sentinel::findRoleBySlug($slug . '_viewer')) {
        return false;
    }

    //Create the admin role for the device
    if (!$role_admin = $app->container->sentinel->getRoleRepository()->createModel()->create(array(
        'name' => "admin",
        'slug' => $slug . "_admin",
        'permissions' => array(
            'deviceRole.' . $devicename . '.admin' => true,
            'deviceRole.' . $devicename . '.delete' => true,
            'deviceRole.' . $devicename . '.update' => true,
            'deviceRole.' . $devicename . '.view' => true,
        ),
    ))) {
        return false;
    }

    //Create the user role for the device
    if (!$role_user = $app->container->sentinel->getRoleRepository()->createModel()->create(array(
        'name' => "user",
        'slug' => $slug . "_user",
        'permissions' => array(
            'deviceRole.' . $devicename . '.admin' => false,
            'deviceRole.' . $devicename . '.delete' => false,
            'deviceRole.' . $devicename . '.update' => true,
            'deviceRole.' . $devicename . '.view' => true,
        ),
    ))) {
        return false;
    }

    //Create the viewer role for the device
    if (!$role_viewer = $app->container->sentinel->getRoleRepository()->createModel()->create(array(
        'name' => "viewer",
        'slug' => $slug . "_viewer",
        'permissions' => array(
            'deviceRole.' . $devicename . '.admin' => false,
            'deviceRole.' . $devicename . '.delete' => false,
            'deviceRole.' . $devicename . '.update' => false,
            'deviceRole.' . $devicename . '.view' => true,
        ),
    ))) {
        return false;
    }

    return true;

}

function getLicenses_Target($hostname, $deviceSerial, $api_key, $port, $target)
{
    global $app;
    $pandbRBAC = selectDatabase('pandbRBAC');
    if ($api_key != "") {

        // define params for the query
        $type = "op";
        $cmd = "<request><license><info></info></license></request>";
        $action = "show";

        $debug_api = USERSPACE_PATH . "/devices/debug.txt";
        $curl_log = fopen($debug_api, 'a+');

        //$devicePath = $hostname . "/api";
        $devicePath = "https://" . $hostname . ":". $port . "/api?type=". $type . "&action=". $action . "&cmd=". $cmd;
        if ($target !== '') {
            $devicePath.= "&target=" . $target;
        } else {
            $target = $deviceSerial;
        }

        $tuCurl = curl_init();
        // Custom headers to be added
        $headers = array(
            'X-PAN-KEY: ' . $api_key
        );
        curl_setopt($tuCurl, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($tuCurl, CURLOPT_URL, $devicePath);
        curl_setopt($tuCurl, CURLOPT_TIMEOUT, DEVICE_CONNECTION_TIMEOUT); // number of seconds prior to a timeout
        curl_setopt($tuCurl, CURLOPT_VERBOSE, DEVICE_DEBUG_CONNECTION_ENABLED==1);
        curl_setopt($tuCurl, CURLOPT_STDERR, $curl_log);
        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($tuCurl, CURLOPT_RETURNTRANSFER, true);

//        $devicePath = $hostname . "/api";

//        if ($target != '') {
//            $datatopost = array(
//                "type" => "op",
//                "cmd" => '<request><license><info></info></license></request>',
//                "key" => $api_key,
//                "target" => $target
//            );
//        } else {
//            $target = $deviceSerial;
//            $datatopost = array(
//                "type" => "op",
//                "cmd" => '<request><license><info></info></license></request>',
//                "key" => $api_key
//            );
//        }


//        if ($tuCurl == "") {
//            $tuCurl = curl_init();
//        }
//        $params = [
//            'url' => "https://$devicePath",
//            'port' => $port,
//            'postfields' => $datatopost,
//        ];
//        $curlObj = new CurlConnect($tuCurl, $params);

//        $tuData = $curlObj->exec();

        $tuData = curl_exec($tuCurl);
        $e = curl_errno($tuCurl);
        if (!checkConnectionErrors($e)) {
            // $curlObj->close();
            return getErrorCode(ERROR_ConnectionNotEstablished);
        }

        $line = curl_multi_getcontent($tuCurl);
        //$curlObj->close();
        curl_close($tuCurl);

        //Check the output is an XML
        $result = simplexml_load_string($line, 'SimpleXmlElement', LIBXML_NOERROR | LIBXML_ERR_FATAL | LIBXML_ERR_NONE);
        if (false == $result) {
            $logger = MTLogger::getInstance();
            $logger->log(json_encode(array('success' => false, 'message' => 'The connection with the device cannot be established. Changes Saved')));
            return false;
            exit(0);
        }

        $xml1 = simplexml_load_string($line);

        if (!isset($xml1) || $xml1->attributes()->status === "error"
            || preg_match('/response status="error"/', $line) || preg_match("/response status = 'error'/i", $tuData)) {
            if(isset($xml1->result->msg)) {
                $msg = $xml1->result->msg;
            }else{
                $msg = $xml1->msg->line;
            }
            $logger = MTLogger::getInstance();
            $logger->log(json_encode(array('success' => false, 'message' => "$msg")));
            return false;
            exit;

        } else {
            $logger = MTLogger::getInstance();

            try {
                $newline = str_replace(array("<response status=\"success\"><result>", "</result></response>"), "", $line);
                $xml = simplexml_load_string($newline);
                $myxpath = $xml->xpath("//licenses/entry");
                $pandbRBAC->query("DELETE FROM licenses WHERE serial='$target';");
                $license = array();
                foreach ($myxpath as $key => $value) {
                    $timestamp = strtotime($value->issued);
                    $issued = date('Y-m-d 00:00:00', $timestamp);
                    $timestamp = strtotime($value->expires);
                    $expires = date('Y-m-d 00:00:00', $timestamp);
                    $license[] = "('$target','$value->feature','$issued','$expires','$value->expired','" . $value->{'base-license-name'} . "','$value->authcode')";
                }
                if (count($license) > 0) {
                    $query = "INSERT INTO licenses (serial,feature,issued,expires,expired,baselicensename,authcode) VALUES " . implode(",", $license);
                    $pandbRBAC->query("INSERT INTO licenses (serial,feature,issued,expires,expired,baselicensename,authcode) VALUES " . implode(",", $license));
                    //$logger->log("$query\n");
                }
            }catch(Exception $ex){
                $logger->log("Error while reading Licenses information from device. Debug information: ". PHP_EOL . $line . PHP_EOL);
            }

            return true;
        }

    }
    return false;
}

function getSupport_Target($hostname, $deviceSerial, $api_key, $port, $target)
{
    $logger = MTLogger::getInstance();
    global $app;
    $pandbRBAC = selectDatabase('pandbRBAC');
    if ($api_key != "") {

        // define params for the query
        $type = "op";
        $cmd = "<request><support><check/></support></request>";
        $action = "show";

        $debug_api = USERSPACE_PATH . "/devices/debug.txt";
        $curl_log = fopen($debug_api, 'a+');

        //$devicePath = $hostname . "/api";
        $devicePath = "https://" . $hostname . ":". $port . "/api?type=". $type . "&action=". $action . "&cmd=". $cmd;
        if ($target !== '') {
            $devicePath.= "&target=" . $target;
        } else {
            $target = $deviceSerial;
        }

        $tuCurl = curl_init();
        // Custom headers to be added
        $headers = array(
            'X-PAN-KEY: ' . $api_key
        );
        curl_setopt($tuCurl, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($tuCurl, CURLOPT_URL, $devicePath);
        curl_setopt($tuCurl, CURLOPT_TIMEOUT, DEVICE_CONNECTION_TIMEOUT); // number of seconds prior to a timeout
        curl_setopt($tuCurl, CURLOPT_VERBOSE, DEVICE_DEBUG_CONNECTION_ENABLED==1);
        curl_setopt($tuCurl, CURLOPT_STDERR, $curl_log);
        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($tuCurl, CURLOPT_RETURNTRANSFER, true);

        $tuData = curl_exec($tuCurl);

//        $devicePath = $hostname . "/api";
//
//        if ($target != '') {
//            $datatopost = array(
//                "type" => "op",
//                "cmd" => '<request><support><check/></support></request>',
//                "key" => $api_key,
//                "target" => $target
//            );
//        } else {
//            $target = $deviceSerial;
//            $datatopost = array(
//                "type" => "op",
//                "cmd" => '<request><support><check/></support></request>',
//                "key" => $api_key
//            );
//        }
//
//        if ($tuCurl == "") {
//            $tuCurl = curl_init();
//        }
//        $params = [
//            'url' => "https://$devicePath",
//            'port' => $port,
//            'postfields' => $datatopost,
//        ];
//
//        $curlObj = new CurlConnect($tuCurl, $params);
//
//        $tuData = $curlObj->exec();
        $e = curl_errno($tuCurl);


        if (!checkConnectionErrors($e)) {
            //$curlObj->close();
            return getErrorCode(ERROR_ConnectionNotEstablished);
        }

        $line = curl_multi_getcontent($tuCurl);
        //$curlObj->close();
        curl_close($tuCurl);

        //Check the output is an XML
        $result = simplexml_load_string($line, 'SimpleXmlElement', LIBXML_NOERROR | LIBXML_ERR_FATAL | LIBXML_ERR_NONE);
        if (false == $result) {
            $logger = MTLogger::getInstance();
            $logger->log(json_encode(array('success' => false, 'message' => 'The connection with the device cannot be established. Changes Saved')));
            return false;
            exit(0);
        }

        $xml1 = simplexml_load_string($line);

        if (!isset($xml1) || $xml1->attributes()->status === "error"
            || preg_match('/response status="error"/', $line) || preg_match("/response status = 'error'/i", $tuData)) {
            if(isset($xml1->result->msg)) {
                $msg = $xml1->result->msg;
            }else{
                $msg = $xml1->msg->line;
            }
            $logger = MTLogger::getInstance();
            $logger->log(json_encode(array('success' => false, 'message' => "$msg")));
            return false;
            exit;

        } else {
            //$newline = str_replace(array("<response status=\"success\"><result>", "</result></response>"), "", $line);
            $xml = simplexml_load_string($line);
            $logger = MTLogger::getInstance();

            try {
                $license = array();
                foreach ($xml->result->SupportInfoResponse->Support as $key => $value) {
                    $ExpiryDate = strtotime($value->ExpiryDate);
                    $ExpiryDatet = date('Y-m-d 00:00:00', $ExpiryDate);
                    $SupportLevel = (string)$value->SupportLevel;
                    $SupportDescription = (string)$value->SupportDescription;

                    if ($ExpiryDatet < date("Y-m-d H:m:s")) {
                        $expired = "yes";
                    } else {
                        $expired = "no";
                    }
                    $pandbRBAC->query("DELETE FROM licenses WHERE serial='$target' AND feature='$SupportLevel';");
                    $license[] = "('$target','$SupportLevel','','$ExpiryDatet','$expired','$SupportDescription','')";
                }
                if (count($license) > 0) {
                    $query = "INSERT INTO licenses (serial,feature,issued,expires,expired,baselicensename,authcode) VALUES " . implode(",", $license);
                    $pandbRBAC->query("INSERT INTO licenses (serial,feature,issued,expires,expired,baselicensename,authcode) VALUES " . implode(",", $license));
                    //$logger->log("$query\n");
                }
            }catch(Exception $ex){
                $logger->log("Error while reading Support information from device. Debug information: ". PHP_EOL . $line . PHP_EOL);
            }

            return true;
        }

    }
    return false;
}

//function getSystemInfo($hostname, $devicename, $api_key, $port)
//{
//    global $app;
//    if ($api_key != "") {
////        global $pandb;
////        global $pandbRBAC;
//        $devicePath = $hostname . "/api";
//        $datatopost = array(
//            "type" => "op",
//            "cmd" => '<show><system><info></info></system></show>',
//            "key" => $api_key
//        );
//
//        $tuCurl = curl_init();
//        $params = [
//            'url' => "https://$devicePath",
//            'port' => $port,
//            'postfields' => $datatopost,
//        ];
//        $curlObj = new CurlConnect($tuCurl, $params);
//        $tuData = $curlObj->exec();
//        $e = curl_errno($tuCurl);
//        if (!checkConnectionErrors($e)) {
//            $curlObj->close();
//            return getErrorCode(ERROR_ConnectionNotEstablished);
//        }
//
//        $line = curl_multi_getcontent($tuCurl);
//        $curlObj->close();
//        curl_close($tuCurl);
//
//        /*if (preg_match("/Not authorized to access/i", $newline)) {
//            echo json_encode(array('success' => false, 'message' => 'You do not have access to the device'));
//            exit;
//        } elseif (preg_match("/Authentication failed: Invalid username or password/i", $newline)) {
//            echo json_encode(array('success' => false, 'message' => 'Authentication failed: Invalid username or password'));
//            exit;
//        } else {*/
//
//        //Check the output is an XML
//        $result = simplexml_load_string($line, 'SimpleXmlElement', LIBXML_NOERROR | LIBXML_ERR_FATAL | LIBXML_ERR_NONE);
//        if (false == $result) {
//            $logger = MTLogger::getInstance();
//            $logger->log(json_encode(array('success' => false, 'message' => 'The connection with the device cannot be established. Changes Saved')));
//            return false;
//            exit(0);
//        }
//
//        $xml1 = simplexml_load_string($line);
//        if (preg_match("/response status = 'error'/i", $tuData)) {
//            $msg = $xml1->result->msg;
//            $logger = MTLogger::getInstance();
//            $logger->log(json_encode(array('success' => false, 'message' => "$msg")));
//            return false;
//            exit;
//        } else {
//            $newline = str_replace(array("<response status=\"success\"><result>", "</result></response>"), "", $line);
//            $xml = simplexml_load_string($newline);
//            $appversion = $appreleasedate = $threatversion = $threatreleasedate = $model = $swversion = $urldb = '';
//            foreach ($xml as $key => $value) {
//                if ($key == "serial") {
//                    $serial = $value;
//                }
//                if ($key == "app-version") {
//                    $appversion = $value;
//                }
//                if ($key == "app-release-date") {
//                    $appreleasedate = $value;
//                }
//                if ($key == "threat-version") {
//                    $threatversion = $value;
//                }
//                if ($key == "threat-release-date") {
//                    $threatreleasedate = $value;
//                }
//                if ($key == "family") {
//                    if ($value == "vm") {
//                        $model = "vm-series";
//                    } elseif ($value == "pc") {
//                        $model = "vm-panorama";
//                    } elseif ($value == "m") {
//                        $model = "m100";
//                    } else {
//                        $model = "pa" . $value;
//                    }
//                }
//                if ($key == "sw-version") {
//                    $swversion = $value;
//                }
//                if ($key == "url-db") {
//                    $urldb = $value;
//                }
//            }
//
//            #Update with the PANOS Version
////                $pandb->query("UPDATE devices set type='$model',serial='$serial',appversion='$appversion',appreleasedate='$appreleasedate',threatversion='$threatversion',threatreleasedate='$threatreleasedate' where hostname='$hostname' and name='$devicename'");
//            $deviceObject = $app->device->where('devicename', $devicename)->where('hostname', $hostname)->first();
//            $params = [
//                'type' => $model,
//                'serial' => $serial,
//                'appversion' => $appversion,
//                'appreleasedate' => $appreleasedate,
//                'threatversion' => $threatversion,
//                'threatreleasedate' => $threatreleasedate,
//                'panos' => $swversion,
//                'urldb' => $urldb
//            ];
//            $deviceObject->update($params);
////                $pandbRBAC->query("UPDATE devices set type='$model',serial='$serial',appversion='$appversion',appreleasedate='$appreleasedate',threatversion='$threatversion',threatreleasedate='$threatreleasedate' where hostname='$hostname' and devicename='$devicename'");
//            return true;
//        }
//
//    }
//    return false;
//}

function getSystemInfo_Target($hostname, $deviceSerial, $api_key, $port, $target = '')
{
    global $app;
    if ($api_key != "") {
        $devicePath = "https://" . $hostname . ":" . $port . "/api?type=op&action=show&cmd=<show><system><info></info></system></show>";

//        if ($target != '') {
//            $datatopost = array(
//                "type" => "op",
//                "cmd" => '<show><system><info></info></system></show>',
//                "target" => $target,
//                "key" => $api_key
//            );
//        } else {
//            $datatopost = array(
//                "type" => "op",
//                "cmd" => '<show><system><info></info></system></show>',
//                "key" => $api_key
//            );
//        }

        $tuCurl = curl_init();

//        $params = [
//            'url' => "https://$devicePath",
//            'port' => $port,
//            'postfields' => $datatopost,
//        ];

        checkFolderExists(USERSPACE_PATH . "/devices/");

        $debug_api = USERSPACE_PATH . "/devices/debug.txt";
        $curl_log = fopen($debug_api, 'a+');
        // Custom headers to be added
        $headers = array(
            'X-PAN-KEY: ' . $api_key
        );
        curl_setopt($tuCurl, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($tuCurl, CURLOPT_URL, $devicePath);
        curl_setopt($tuCurl, CURLOPT_TIMEOUT, DEVICE_CONNECTION_TIMEOUT);
        curl_setopt($tuCurl, CURLOPT_VERBOSE, DEVICE_DEBUG_CONNECTION_ENABLED==1);
        curl_setopt($tuCurl, CURLOPT_STDERR, $curl_log);
        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($tuCurl, CURLOPT_RETURNTRANSFER, true);

        $tuData = curl_exec($tuCurl);

        $e = curl_errno($tuCurl);

        if (!checkConnectionErrors($e)) {
            curl_close($tuCurl);
            return getErrorCode(ERROR_ConnectionNotEstablished);
        }

        $line = curl_multi_getcontent($tuCurl);
        // $curlObj->close();
        curl_close($tuCurl);

        //Check the output is an XML
        $result = simplexml_load_string($line, 'SimpleXmlElement', LIBXML_NOERROR | LIBXML_ERR_FATAL | LIBXML_ERR_NONE);
        if (false == $result) {
            $logger = MTLogger::getInstance();
            $logger->log(json_encode(array('success' => false, 'message' => getErrorCode(ERROR_NotExpectedFileFormat, 'description'))));
            return getErrorCode(ERROR_NotExpectedFileFormat);
            exit(0);
        }

        $xml1 = simplexml_load_string($line);
        if(!isset($xml1) || $xml1->attributes()->status === "error"
            || preg_match('/response status="error"/', $line) || preg_match("/response status = 'error'/i", $tuData)){
            if(isset($xml1->result->msg)) {
                $msg = $xml1->result->msg;
            }else{
                $msg = $xml1->msg->line;
            }
            $logger = MTLogger::getInstance();
            $logger->log(json_encode(array('success' => false, 'message' => "$msg")));
            return getErrorCode(ERROR_SpecificPANOS);
            exit(0);

        } else {
            if (!is_dir(USERSPACE_PATH . "/devices") && !mkdir($concurrentDirectory = USERSPACE_PATH . "/devices", 0766) && !is_dir($concurrentDirectory)) {
                $logger = MTLogger::getInstance();
                $logger->log(json_encode(array('success' => false, 'message' => sprintf('Directory "%s" was not created', $concurrentDirectory))));
                return getErrorCode(FileNotCreated);
            }
            if ($target == "") {
                $deviceFolder = USERSPACE_PATH . "/devices/$deviceSerial/";
                if (!file_exists($deviceFolder) && !mkdir((string)$deviceFolder, 0777) && !is_dir((string)$deviceFolder)) {
                    $logger = MTLogger::getInstance();
                    $logger->log(json_encode(array('success' => false, 'message' => sprintf('Directory "%s" was not created', $deviceFolder))));
                    return getErrorCode(FileNotCreated);
                }
            } else {
                $deviceFolder = USERSPACE_PATH . "/devices/$target/";
                if (!file_exists($deviceFolder) && !mkdir("$deviceFolder", 0777) && !is_dir("$deviceFolder")) {
                    $logger = MTLogger::getInstance();
                    $logger->log(json_encode(array('success' => false, 'message' => sprintf('Directory "%s" was not created', $deviceFolder))));
                    return getErrorCode(FileNotCreated);
                }
            }

            //If the firewall is not connected, do not update it's info
            if (strpos($line, "<response status=\"success\"><result>") === false) {
                $params = [
                    'connected' => 'no'
                ];
                if ($target != '') {
                    $deviceObject = $app->device->where('serial', $target)->first();
                } else {
                    $deviceObject = $app->device->where('serial', $deviceSerial)->first();
                }
                $deviceObject->update($params);
                return getErrorCode(ERROR_ConnectionNotEstablished);
            } else {
                $newline = str_replace(array("<response status=\"success\"><result>", "</result></response>"), "", $line);
                $xml = simplexml_load_string($newline);
                $threatversion = $threatreleasedate = "";
                $logger = MTLogger::getInstance();

                foreach ($xml as $key => $value) {
                    if ($key == "serial") {
                        $serial = $value;
                    }
                    if ($key == "app-version") {
                        $appversion = $value;
                    }
                    if ($key == "app-release-date") {
                        $appreleasedate = $value;
                    }
                    if ($key == "threat-version") {
                        $threatversion = $value;
                    }
                    if ($key == "threat-release-date") {
                        $threatreleasedate = $value;
                    }
                    if ($key == "family") {
                        if ($value == "vm") {
                            $model = "vm-series";
                        } elseif ($value == "pc") {
                            $model = "vm-panorama";
                        } elseif ($value == "m") {
                            $model = "m100";
                        } else {
                            $model = "pa" . $value;
                        }
                    }
                    if ($key == "sw-version") {
                        $swversion = $value;
                        $logger->log("VERSION: " . $swversion);
                    }
                    if ($key == "url-db") {
                        $urldb = $value;
                    }
                }

                #Update with the PANOS Version
                if ($target != '') {
                    $deviceObject = $app->device->where('serial', $target)->first();
                } else {
                    $deviceObject = $app->device->where('serial', $deviceSerial)->first();
                }
                $params = [
                    'type' => $model,
                    'appversion' => $appversion,
                    'appreleasedate' => $appreleasedate,
                    'threatversion' => $threatversion,
                    'threatreleasedate' => $threatreleasedate,
                    'panos' => $swversion,
                    'urldb' => $urldb,
                    'connected' => 'yes'
                ];
                $deviceObject->update($params);
                return getErrorCode(Correct);
            }
        }
    }
    return getErrorCode(ERROR_NotGivenAPIKEY);
}

function checkFolderExists(STRING $folder)
{

    if (!file_exists($folder)) {
        if (!mkdir($folder, 0777, true) && !is_dir($folder)) {
            throw new \RuntimeException(sprintf('Directory "%s" was not created', $folder));
        }
    }
}

function generate_key($hostname, $username, $password, $port)
{
    $devicePath = "https://" . $hostname . ":". $port . "/api" . "?type=keygen&user=$username&password=$password";

    $to_curl = curl_init();
    checkFolderExists(USERSPACE_PATH . "/devices/");

    $debug_api = USERSPACE_PATH . "/devices/debug.txt";
    $curl_log = fopen($debug_api, 'a+');

    curl_setopt($to_curl, CURLOPT_URL, $devicePath);
    curl_setopt($to_curl, CURLOPT_TIMEOUT, DEVICE_CONNECTION_TIMEOUT);
    curl_setopt($to_curl, CURLOPT_VERBOSE, DEVICE_DEBUG_CONNECTION_ENABLED==1);
    curl_setopt($to_curl, CURLOPT_STDERR, $curl_log);
    curl_setopt($to_curl, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($to_curl, CURLOPT_SSL_VERIFYHOST, false);
    curl_setopt($to_curl, CURLOPT_RETURNTRANSFER, true);

    $to_data = curl_exec($to_curl);

    $e = curl_errno($to_curl);
    curl_close($to_curl);

    switch ($e) {
        case 0:
//            echo "tuData: ".$tuData;
            if (preg_match("/response status = 'success'/i", $to_data)) {
                //echo "SUCCESS\n";
                // $line = curl_multi_getcontent($tuCurl);
                $xml = simplexml_load_string($to_data);
                $key = $xml->result->key;
                return $key;
            } elseif (preg_match("/response status = 'error'/i", $to_data)) {
                //echo "ERROR\n";
                //$line = curl_multi_getcontent($tuCurl);
                $xml = simplexml_load_string($to_data);
                $msg = $xml->result->msg;
                echo json_encode(array('success' => false, 'msg' => "$msg"));
                exit;
            } else {
                // In case they try to connect to another server handling HTTP(S) requests, we may get an HTML response, a JSON response, an XML response, etc.
                // Hopefully, it won't have the "response status =" string.
                echo json_encode(array('success' => false, 'msg' => 'Unexpected content in server response. Revise you are connecting to a Palo Alto Networks Device'));
                exit(0);
            }
            break;

        case 6:
            echo json_encode(array('success' => false, 'msg' => "Error Code $e: The HostName could not be resolved"));
            exit(0);
            break;

        case 7:
            echo json_encode(array('success' => false, 'msg' => "Error Code $e: The connection with the device cannot be established. Please, revise your connection parameters"));
            exit(0);
            break;

        case 21:
        case 22:
        case 23:
        case 24:
        case 25:
        case 26:
            echo json_encode(array('success' => false, 'msg' => "Error Code $e: The connection with the device returned an error. Please try again"));
            exit(0);
            break;

        case 27:
            echo json_encode(array('success' => false, 'msg' => "Error Code $e: The connection with the device returned an error. Out of memory. Please, report this error for improvement"));
            exit(0);
            break;

        case 28:
            echo json_encode(array('success' => false, 'msg' => "Error Code $e: The connection with the device cannot be established. Connection timeout"));
            exit(0);
            break;

        default:
            echo json_encode(array('success' => false, 'msg' => "Error Code $e: The connection with the device cannot be established. Please, report Error Code for improvement"));
            exit(0);
            break;
    }
//    if      ($e==28) {
////        echo json_encode(array('success' => false, 'message' => 'The connection with the device cannot be established. Changes Saved'));
//        echo json_encode(array('success' => false, 'message' => 'The connection with the device cannot be established. Connection timeout'));
//        exit(0);
//    }
//    else {
//        $line = curl_multi_getcontent($tuCurl);
////        echo "Line $line";
//        $xml = simplexml_load_string($line);
//
//        if (preg_match("/response status = 'error'/i", $tuData)) {
//            //echo "ERROR\n";
//            $msg = $xml->result->msg;
//            echo json_encode(array('success' => false, 'message' => "$msg"));
//            exit;
//        }else{
//            //echo "SUCCESS\n";
//            $key = $xml->result->key;
//            return $key;
//        }
//
//        /*if (preg_match("/Not authorized to access/i", $line)) {
//            echo json_encode(array('success' => false, 'message' => 'You do not have access to the device'));
//            exit;
//        } elseif (preg_match("/Authentication failed: Invalid username or password/i", $line)) {
//            echo json_encode(array('success' => false, 'message' => 'Authentication failed: Invalid username or password'));
//            exit;
//        } else {
//            $key = $xml->result->key;
//            return $key;
//        }*/
//
//    }
}

function getUrlCategories($hostname, $deviceSerial, $api_key, $port)
{
    if ($api_key != "") {
        global $app;
        global $pandb;

        // define params for the query
        $type = "config";
        $action = "get";

        $deviceObject = $app->device->where('serial', $deviceSerial)->get(['urldb'])->first();
        if ($deviceObject->urldb == 'brightcloud') {
//            $datatopost = array(
//                "type" => "config",
//                "action" => 'get',
//                "key" => $api_key,
//                "xpath" => "/config/predefined/url-categories"
//            );
            $xpath ="/config/predefined/url-categories";
        } else {
//            $datatopost = array(
//                "type" => "config",
//                "action" => 'get',
//                "key" => $api_key,
//                "xpath" => "/config/predefined/pan-url-categories"
//            );
            $xpath ="/config/predefined/pan-url-categories";
        }

        $debug_api = USERSPACE_PATH . "/devices/debug.txt";
        $curl_log = fopen($debug_api, 'a+');

        //$devicePath = $hostname . "/api";
        $devicePath = "https://" . $hostname . ":". $port . "/api?type=". $type ."&action=". $action . "&xpath=" . $xpath;

        $tuCurl = curl_init();
        // Custom headers to be added
        $headers = array(
            'X-PAN-KEY: ' . $api_key
        );
        curl_setopt($tuCurl, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($tuCurl, CURLOPT_URL, $devicePath);
        curl_setopt($tuCurl, CURLOPT_TIMEOUT, DEVICE_CONNECTION_TIMEOUT); // number of seconds prior to a timeout
        curl_setopt($tuCurl, CURLOPT_VERBOSE, DEVICE_DEBUG_CONNECTION_ENABLED==1);
        curl_setopt($tuCurl, CURLOPT_STDERR, $curl_log);
        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($tuCurl, CURLOPT_RETURNTRANSFER, true);

        $tuData = curl_exec($tuCurl);


//        $params = [
//            'url' => "https://$devicePath",
//            'port' => $port,
//            'postfields' => $datatopost,
//        ];
//        $curlObj = new CurlConnect($tuCurl, $params);
//        $tuData = $curlObj->exec();

//        curl_setopt($tuCurl, CURLOPT_URL, "https://$devicePath");
//        curl_setopt($tuCurl, CURLOPT_PORT, $port);
//        curl_setopt($tuCurl, CURLOPT_VERBOSE, 0);
//        curl_setopt($tuCurl, CURLOPT_HEADER, 0);
//        curl_setopt($tuCurl, CURLOPT_POST, 1);
//        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, 0);
//        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, 0);
//        curl_setopt($tuCurl, CURLOPT_RETURNTRANSFER, 1);
//        curl_setopt($tuCurl, CURLOPT_CONNECTTIMEOUT, 1500);
//        curl_setopt($tuCurl, CURLOPT_POSTFIELDS, $datatopost);
//        curl_setopt($tuCurl, CURLOPT_TIMEOUT, 0);
//        $tuData = curl_exec($tuCurl);

        $e = curl_errno($tuCurl);
        if (!checkConnectionErrors($e)) {
            //$curlObj->close();
            curl_close($tuCurl);
            return getErrorCode(ERROR_ConnectionNotEstablished);
        }

        $line = curl_multi_getcontent($tuCurl);
        //$curlObj->close();
        curl_close($tuCurl);
        $xml = simplexml_load_string($line);
        if(!isset($xml) || $xml->attributes()->status === "error"
            || preg_match('/response status="error"/', $line) || preg_match("/response status = 'error'/i", $tuData)){
            if(isset($xml->result->msg)) {
                $msg = $xml->result->msg;
            }else{
                $msg = $xml->msg->line;
            }
            $logger = MTLogger::getInstance();
            $logger->log(json_encode(array('success' => false, 'message' => "$msg")));
            return getErrorCode(ERROR_SpecificPANOS);
        } else {
            if (!is_dir(USERSPACE_PATH . "/devices") && !mkdir($concurrentDirectory = USERSPACE_PATH . "/devices", 0766) && !is_dir($concurrentDirectory)) {
                $logger = MTLogger::getInstance();
                $logger->log(json_encode(array('success' => false, 'message' => sprintf('Directory "%s" was not created', $concurrentDirectory))));
                return getErrorCode(FileNotCreated);
            }
            $deviceFolder = USERSPACE_PATH . "/devices/$deviceSerial/";
            if (!file_exists($deviceFolder) && !mkdir($deviceFolder, 0777) && !is_dir($deviceFolder)) {
                $logger = MTLogger::getInstance();
                $logger->log(json_encode(array('success' => false, 'message' => sprintf('Directory "%s" was not created', $deviceFolder))));
                return getErrorCode(FileNotCreated);
            }
            $File = USERSPACE_PATH . "/devices/$deviceSerial/url_categories.xml";
            $Handle = fopen($File, 'w');
            fwrite($Handle, $line);
            fclose($Handle);
            return getErrorCode(Correct);
        }
    }

}

function getConfigBackup($hostname, $deviceSerial, $api_key, $port, $configtype, $filename = 'ConfigBackup.xml', bool $doBackup = NULL)
{

    global $app;
    $encrypt = true;

    if (is_null($doBackup)) {
        $doBackup = false;
    }

    // API call for candidate config:
    if ($api_key != "") {
        $pandbRBAC = selectDatabase('pandbRBAC');

        // $devicePath = $hostname . "/api";
        $devicePath = "https://" . $hostname . ":". $port . "/api?type=op&action=show&cmd=<show><config><$configtype></$configtype></config></show>";


//        if ($configtype == "candidate") {
//            $datatopost = array(
//                "cmd" => '<show><config><candidate></candidate></config></show>',
//                "type" => "op",
//                "action" => 'show',
//                "key" => $api_key
//            );
//        } else {
//            $datatopost = array(
//                "cmd" => '<show><config><running></running></config></show>',
//                //"type" => "config",
//                "type" => "op",
//                "action" => 'show',
//                "key" => $api_key
//            );
//        }
        //$parameters = "type=op&action=show&key=$api_key&cmd=<show><config><$configtype></$configtype></config></show>";
        $tuCurl = curl_init();
//        $params = [
//            'url' => "https://$devicePath",
//            'port' => $port,
//            'postfields' => $datatopost
//            //'timeout' => 20
//        ];

        checkFolderExists(USERSPACE_PATH . "/devices/");
        $debug_api = USERSPACE_PATH . "/devices/debug.txt";
        $curl_log = fopen($debug_api, 'a+');

        // Custom headers to be added
        $headers = array(
            'X-PAN-KEY: ' . $api_key
        );
        curl_setopt($tuCurl, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($tuCurl, CURLOPT_URL, $devicePath);
        curl_setopt($tuCurl, CURLOPT_TIMEOUT, DEVICE_CONNECTION_TIMEOUT); // number of seconds prior to a timeout
        curl_setopt($tuCurl, CURLOPT_VERBOSE, DEVICE_DEBUG_CONNECTION_ENABLED==1);
        curl_setopt($tuCurl, CURLOPT_STDERR, $curl_log);
        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($tuCurl, CURLOPT_RETURNTRANSFER, true);

        // $curlObj = new CurlConnect($tuCurl, $params);
        // $tuData = $curlObj->exec();
        $tuData = curl_exec($tuCurl);

        $e = curl_errno($tuCurl);
        if (!checkConnectionErrors($e)) {
            // $curlObj->close();
            curl_close($tuCurl);
            return getErrorCode(ERROR_ConnectionNotEstablished);
        }

        $line = curl_multi_getcontent($tuCurl);
        // $curlObj->close();
        curl_close($tuCurl);

        //Check the output is an XML
        $result = simplexml_load_string($line, 'SimpleXmlElement', LIBXML_NOERROR | LIBXML_ERR_FATAL | LIBXML_ERR_NONE);
        if (false == $result) {
            $logger = MTLogger::getInstance();
            $logger->log(json_encode(array('success' => false, 'message' => getErrorCode(ERROR_NotExpectedFileFormat, 'description'))));
            return getErrorCode(ERROR_NotExpectedFileFormat);
        }

        $xml1 = simplexml_load_string($line);
        if(!isset($xml1) || $xml1->attributes()->status === "error"
            || preg_match('/response status="error"/', $line) || preg_match("/response status = 'error'/i", $tuData)){
            if(isset($xml1->result->msg)) {
                $msg = $xml1->result->msg;
            }else{
                $msg = $xml1->msg->line;
            }
            $logger = MTLogger::getInstance();
            $logger->log(json_encode(array('success' => false, 'message' => "$msg")));
            return getErrorCode(ERROR_SpecificPANOS);
        } else {
            $newline = str_replace(array("<response status=\"success\"><result>", "</result></response>"), "", $line);

            $xml = simplexml_load_string($newline);
            $getPanos = $xml->attributes()->version;
            $geturldb = $xml->attributes()->urldb;
            $device = '';
            if (isset($xml->devices->entry->deviceconfig->system->hostname)) {
                $device = $xml->devices->entry->deviceconfig->system->hostname;
            }

            if (!is_dir(USERSPACE_PATH . "/devices") && !mkdir($concurrentDirectory = USERSPACE_PATH . "/devices", 0766) && !is_dir($concurrentDirectory)) {
                $logger = MTLogger::getInstance();
                $logger->log(json_encode(array('success' => false, 'message' => sprintf('Directory "%s" was not created', $concurrentDirectory))));
                return getErrorCode(FileNotCreated);
            }
            $deviceFolder = USERSPACE_PATH . "/devices/$deviceSerial/";
            if (!file_exists($deviceFolder) && !mkdir($deviceFolder, 0777) && !is_dir($deviceFolder)) {
                $logger = MTLogger::getInstance();
                $logger->log(json_encode(array('success' => false, 'message' => sprintf('Directory "%s" was not created', $deviceFolder))));
                return getErrorCode(FileNotCreated);
            }
            $File = USERSPACE_PATH . "/devices/$deviceSerial/" . $filename;
            if (file_exists($File) && $doBackup) {
                $destinationPath = USERSPACE_PATH . "/devices/$deviceSerial/" . $filename . ".old";
                copy($File, $destinationPath);
            }
            $Handle = fopen($File, 'w');
            fwrite($Handle, $newline);
//            if (file_exists($File) && $doBackup){ //TODO: Why this condition?
            $destinationPath = USERSPACE_PATH . "/devices/$deviceSerial/ConfigBackup.xml";
            copy($File, $destinationPath);
//            }
            fclose($Handle);

            if (file_exists($File) && $encrypt) {
                //Encrypt the config file
                if (!$deviceObj = $app->device->where("serial", $deviceSerial)->get()->first()) {
                    echo("Device not found in our registry");
                } else {
                    $keyObj = $app->accessKey->where("type", "device")->where("lid", $deviceObj->id)->get()->first();
                    //$api_key = new OpenSSLTools($user->password, $user->token);
                    $encrypter = new OpenSSLTools($keyObj->key, $keyObj->iv);
                    $result = $encrypter->encryptToFile($newline, "$File.dat");
                    if ($result['code']) {
                        //Delete the original contents file
                        unlink($File);
                        $query = "UPDATE devices set device='$device', panos='$getPanos', urldb='$geturldb', config='1' where serial='$deviceSerial'";
                        $pandbRBAC->query($query);
                        return getErrorCode(Correct);
                    } else {
                        echo "Problems encrypting the file";
                        unlink($File);
                        $query = "UPDATE devices set device='$device', panos='$getPanos', urldb='$geturldb', config='0' where serial='$deviceSerial'";
                        $pandbRBAC->query($query);
                        return getErrorCode(ERROR_FileNotCreated);
                    }
                }
            }

            $File = "$File.dat";
        }
    }
}


function SimpleXMLElement_append($key, $value)
{
    // check class
    //echo "DENTRO DE LA FUNCIÓN \n";
    //echo "Key: \n";
    //print_r($key);
    //echo "Value \n";
    //print_r($value);
    //echo "-------- \n";

    if ((get_class($key) == 'SimpleXMLElement') && (get_class($value) == 'SimpleXMLElement')) {
        // check if the value is string value / data
        if (trim((string)$value) == '') {
            // add element and attributes
            $element = $key->addChild($value->getName());
            foreach ($value->attributes() as $attKey => $attValue) {
                $element->addAttribute($attKey, $attValue);
            }
            // add children
            foreach ($value->children() as $child) {
                SimpleXMLElement_append($element, $child);
            }
        } else {
            // set the value of this item
            $element = $key->addChild($value->getName(), trim((string)htmlspecialchars($value)));
            //print $value->getName()=$value;
        }
    } else {
        // throw an error
        throw new Exception('Wrong type of input parameters, expected SimpleXMLElement key:' . var_dump($key) . ', value:' . var_dump($value));
    }
}

//function getVsys($hostname, $devicename, $api_key, $port)
//{
//
//    if ($api_key != "") {
//        global $pandb;
//        $timeout = 120;
//        $xpath = "/api?type=config&action=show&xpath=devices/entry/vsys";
//        $devicePath = "https://" . $hostname . ":". $port . $xpath;
//
//        $tuCurl = curl_init();
//        /*$params = [
//            'url' => "https://$devicePath",
//            'port' => $port,
////            'postfields' =>$datatopost,
//        ];
//        $curlObj = new CurlConnect($tuCurl, $params);
//        $tuData = $curlObj->exec();
//        */
//        // Custom headers to be added
//        $headers = array(
//            'X-PAN-KEY: ' . $api_key
//        );
//        curl_setopt($tuCurl, CURLOPT_HTTPHEADER, $headers);
//        curl_setopt($tuCurl, CURLOPT_URL, $devicePath);
//        curl_setopt($tuCurl, CURLOPT_TIMEOUT, 400000); // number of seconds prior to a timeout
//        curl_setopt($tuCurl, CURLOPT_VERBOSE, DEVICE_DEBUG_CONNECTION_ENABLED==1);
//        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, false);
//        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, false);
//        curl_setopt($tuCurl, CURLOPT_RETURNTRANSFER, true);
//
//        $line = curl_multi_getcontent($tuCurl);
//        curl_close($tuCurl);
//
//        //print $results;
//        $xml = simplexml_load_string($line);
//
//        foreach ($xml->result->vsys->children() as $child) {
//            $mm = $child->attributes()->name;
//            $vsyses[] = $mm;
//        }
//
//        foreach ($vsyses as $key => $value) {
//            if (($value != "vsys1") or ($value != "")) {
//                $searchDup = $pandb->query("select id from devices where hostname='$hostname' and vsys='$value'");
//                //TODO Update the correct device
//                if ($searchDup->num_rows == 0) {
//                    $newName = $devicename . "-" . $value;
//                    $pandb->query("insert into devices (hostname,vsys,name) values ('$hostname','$value','$newName');");
//                    //TODO Update the correct device
//                }
//            }
//        }
//    }
//}

function getThreats($hostname, $devicename, $api_key, $port)
{
    if ($api_key != "") {
        global $pandb;
        $devicePath = "https://" . $hostname . ":". $port . "/api?type=config&action=get&xpath=/config/predefined/threats";

        $tuCurl = curl_init();

        checkFolderExists(USERSPACE_PATH . "/devices/");
        $debug_api = USERSPACE_PATH . "/devices/debug.txt";
        $curl_log = fopen($debug_api, 'a+');

        // Custom headers to be added
        $headers = array(
            'X-PAN-KEY: ' . $api_key
        );
        curl_setopt($tuCurl, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($tuCurl, CURLOPT_URL, $devicePath);
        curl_setopt($tuCurl, CURLOPT_TIMEOUT, DEVICE_CONNECTION_TIMEOUT); // number of seconds prior to a timeout
        curl_setopt($tuCurl, CURLOPT_VERBOSE, DEVICE_DEBUG_CONNECTION_ENABLED==1);
        curl_setopt($tuCurl, CURLOPT_STDERR, $curl_log);
        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($tuCurl, CURLOPT_RETURNTRANSFER, true);

        $tuData = curl_exec($tuCurl);
//        curl_setopt($tuCurl, CURLOPT_URL, "https://$devicePath");
//        curl_setopt($tuCurl, CURLOPT_PORT, $port);
//        curl_setopt($tuCurl, CURLOPT_VERBOSE, 0);
//        curl_setopt($tuCurl, CURLOPT_HEADER, 0);
//        curl_setopt($tuCurl, CURLOPT_POST, 1);
//        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, 0);
//        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, 0);
//        curl_setopt($tuCurl, CURLOPT_RETURNTRANSFER, 1);
//        curl_setopt($tuCurl, CURLOPT_CONNECTTIMEOUT, 1500);
//        curl_setopt($tuCurl, CURLOPT_POSTFIELDS, $datatopost);
//        curl_setopt($tuCurl, CURLOPT_TIMEOUT, 0);
//        $tuData = curl_exec($tuCurl);

        $line = curl_multi_getcontent($tuCurl);
        //print $line;
        $e = curl_errno($tuCurl);
        if (!checkConnectionErrors($e)) {
            //$curlObj->close();
            curl_close($tuCurl);
            return getErrorCode(ERROR_ConnectionNotEstablished);
        }

        //$curlObj->close();
        curl_close($tuCurl);

        #Strip the result and response tags
        $newline = str_replace(array("<response status=\"success\"><result>", "</result></response>"), "", $line);
        if (!is_dir(USERSPACE_PATH . "/devices")) {
            mkdir(USERSPACE_PATH . "/devices", 0766);
        }
        $deviceFolder = USERSPACE_PATH . "/devices/$devicename/";
        if (!file_exists($deviceFolder)) {
            mkdir("$deviceFolder", 0777);
        }
        $File = USERSPACE_PATH . "/devices/$devicename/threats.xml";
        $Handle = fopen($File, 'w');

        fwrite($Handle, $line);
        fclose($Handle);

        if ((file_exists($File)) and (filesize($File) != 0)) {
            $pandb->query("UPDATE devices set threats='1' where hostname='$hostname' and name='$devicename'");
            //TODO Update the correct device
        }
    }
}

function getApplications($hostname, $deviceSerial, $api_key, $port)
{
    if ($api_key != "") {
        global $pandb;
        $pandbRBAC = selectDatabase('pandbRBAC');
//        global $pandbRBAC;

        // define params for the query
        $type = "config";
        $action = "get";
        $xpath ="/config/predefined/application";

        $debug_api = USERSPACE_PATH . "/devices/debug.txt";
        $curl_log = fopen($debug_api, 'a+');

        //$devicePath = $hostname . "/api";
        $devicePath = "https://" . $hostname . ":". $port . "/api?type=". $type ."&action=". $action . "&xpath=" . $xpath;

//        $datatopost = array(
//            "type" => "config",
//            "action" => 'get',
//            "key" => $api_key,
//            "xpath" => "/config/predefined/application"
//        );

        $tuCurl = curl_init();

        // Custom headers to be added
        $headers = array(
            'X-PAN-KEY: ' . $api_key
        );
        curl_setopt($tuCurl, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($tuCurl, CURLOPT_URL, $devicePath);
        curl_setopt($tuCurl, CURLOPT_TIMEOUT, DEVICE_CONNECTION_TIMEOUT); // number of seconds prior to a timeout
        curl_setopt($tuCurl, CURLOPT_VERBOSE, DEVICE_DEBUG_CONNECTION_ENABLED==1);
        curl_setopt($tuCurl, CURLOPT_STDERR, $curl_log);
        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($tuCurl, CURLOPT_RETURNTRANSFER, true);

//        $params = [
//            'url' => "https://$devicePath",
//            'port' => $port,
//            'postfields' => $datatopost,
//            'timeout' => 1500,
//        ];

//         $curlObj = new CurlConnect($tuCurl, $params);
//        $tuData = $curlObj->exec();
//        curl_setopt($tuCurl, CURLOPT_URL, "https://$devicePath");
//        curl_setopt($tuCurl, CURLOPT_PORT, $port);
//        curl_setopt($tuCurl, CURLOPT_VERBOSE, 0);
//        curl_setopt($tuCurl, CURLOPT_HEADER, 0);
//        curl_setopt($tuCurl, CURLOPT_POST, 1);
//        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, 0);
//        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, 0);
//        curl_setopt($tuCurl, CURLOPT_RETURNTRANSFER, 1);
//        curl_setopt($tuCurl, CURLOPT_CONNECTTIMEOUT, 1500);
//        curl_setopt($tuCurl, CURLOPT_POSTFIELDS, $datatopost);
//        curl_setopt($tuCurl, CURLOPT_TIMEOUT, 0);

        $tuData = curl_exec($tuCurl);

        //$curlObj->close();
        $line = curl_multi_getcontent($tuCurl);
        //print $line;
        $e = curl_errno($tuCurl);
        if (!checkConnectionErrors($e)) {
            curl_close($tuCurl);
            return getErrorCode(ERROR_ConnectionNotEstablished);
        }
        curl_close($tuCurl);

        //Check the output is an XML
        $xml1 = simplexml_load_string($line);
        if (!isset($xml1) || $xml1->attributes()->status === "error"
            || preg_match('/response status="error"/', $line) || preg_match("/response status = 'error'/i", $tuData)) {
            if(isset($xml1->result->msg)) {
                $msg = $xml1->result->msg;
            }else{
                $msg = $xml1->msg->line;
            }
            $logger = MTLogger::getInstance();
            $logger->log(json_encode(array('success' => false, 'message' => "$msg")));
            return getErrorCode(ERROR_SpecificPANOS);
        } else {
//            $newline = str_replace(array("<response status=\"success\"><result>", "</result></response>"), "", $line);
            $result = simplexml_load_string($line, 'SimpleXmlElement', LIBXML_NOERROR | LIBXML_ERR_FATAL | LIBXML_ERR_NONE);
            if ($result == false) {
                $logger = MTLogger::getInstance();
                $logger->log(json_encode(array('success' => false, 'message' => getErrorCode(ERROR_NotExpectedFileFormat, 'description'))));
                return getErrorCode(ERROR_NotExpectedFileFormat);
                exit(0);
            }

            #Strip the result and response tags
//            $newline = str_replace(array("<response status=\"success\"><result>", "</result></response>"), "", $line);
            if (!is_dir(USERSPACE_PATH . "/devices") && !mkdir($concurrentDirectory = USERSPACE_PATH . "/devices", 0766) && !is_dir($concurrentDirectory)) {
                $logger = MTLogger::getInstance();
                $logger->log(json_encode(array('success' => false, 'message' => sprintf('Directory "%s" was not created', $concurrentDirectory))));
                return getErrorCode(FileNotCreated);
            }
            $deviceFolder = USERSPACE_PATH . "/devices/$deviceSerial/";
            if (!file_exists($deviceFolder) && !mkdir((string)$deviceFolder, 0777) && !is_dir((string)$deviceFolder)) {
                $logger = MTLogger::getInstance();
                $logger->log(json_encode(array('success' => false, 'message' => sprintf('Directory "%s" was not created', $deviceFolder))));
                return getErrorCode(FileNotCreated);
            }
            $File = USERSPACE_PATH . "/devices/$deviceSerial/applications.xml";
            $Handle = fopen($File, 'w');

            fwrite($Handle, $line);
            fclose($Handle);

            if ((file_exists($File)) && (filesize($File) != 0)) {
                $pandbRBAC->query("UPDATE devices set apps='1' where hostname='$hostname' and serial='$deviceSerial'");
                return getErrorCode(Correct);
            }
            return getErrorCode(ERROR_FileNotCreated);
        }
    }
}

function getApplications_container($hostname, $deviceSerial, $api_key, $port)
{
    if ($api_key != "") {
        global $pandb;

        // define params for the query
        $type = "config";
        $action = "get";
        $xpath ="/config/predefined/application-container";

        $debug_api = USERSPACE_PATH . "/devices/debug.txt";
        $curl_log = fopen($debug_api, 'a+');

        //$devicePath = $hostname . "/api";
        $devicePath = "https://" . $hostname . ":". $port . "/api?type=". $type ."&action=". $action . "&xpath=" . $xpath;


//        $devicePath = $hostname . "/api";
//        $datatopost = array(
//            "type" => "config",
//            "action" => 'get',
//            "key" => $api_key,
//            "xpath" => "/config/predefined/application-container"
//        );

        $tuCurl = curl_init();
//        $params = [
//            'url' => "https://$devicePath",
//            'port' => $port,
//            'postfields' => $datatopost,
//        ];
//        $curlObj = new CurlConnect($tuCurl, $params);
//        $tuData = $curlObj->exec();

//        curl_setopt($tuCurl, CURLOPT_URL, "https://$devicePath");
//        curl_setopt($tuCurl, CURLOPT_PORT, $port);
//        curl_setopt($tuCurl, CURLOPT_VERBOSE, 0);
//        curl_setopt($tuCurl, CURLOPT_HEADER, 0);
//        curl_setopt($tuCurl, CURLOPT_POST, 1);
//        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, 0);
//        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, 0);
//        curl_setopt($tuCurl, CURLOPT_RETURNTRANSFER, 1);
//        curl_setopt($tuCurl, CURLOPT_CONNECTTIMEOUT, 1500);
//        curl_setopt($tuCurl, CURLOPT_POSTFIELDS, $datatopost);
//        curl_setopt($tuCurl, CURLOPT_TIMEOUT, 0);
//        $tuData = curl_exec($tuCurl);

        // Custom headers to be added
        $headers = array(
            'X-PAN-KEY: ' . $api_key
        );
        curl_setopt($tuCurl, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($tuCurl, CURLOPT_URL, $devicePath);
        curl_setopt($tuCurl, CURLOPT_TIMEOUT, DEVICE_CONNECTION_TIMEOUT); // number of seconds prior to a timeout
        curl_setopt($tuCurl, CURLOPT_VERBOSE, DEVICE_DEBUG_CONNECTION_ENABLED==1);
        curl_setopt($tuCurl, CURLOPT_STDERR, $curl_log);
        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($tuCurl, CURLOPT_RETURNTRANSFER, true);

        $tuData = curl_exec($tuCurl);

        //$curlObj->close();
        $line = curl_multi_getcontent($tuCurl);
        //print $line;
        $e = curl_errno($tuCurl);
        if (!checkConnectionErrors($e)) {
            curl_close($tuCurl);
            return getErrorCode(ERROR_ConnectionNotEstablished);
        }
        curl_close($tuCurl);

        //Check the output is an XML
        $result = simplexml_load_string($line, 'SimpleXmlElement', LIBXML_NOERROR | LIBXML_ERR_FATAL | LIBXML_ERR_NONE);
        if (false == $result) {
            $logger = MTLogger::getInstance();
            $logger->log(json_encode(array('success' => false, 'message' => getErrorCode(ERROR_NotExpectedFileFormat, 'description'))));
            return getErrorCode(ERROR_NotExpectedFileFormat);
            exit(0);
        }

        $xml1 = simplexml_load_string($line);
        if (!isset($xml1) || $xml1->attributes()->status === "error"
            || preg_match('/response status="error"/', $line) || preg_match("/response status = 'error'/i", $tuData)) {
            if(isset($xml1->result->msg)) {
                $msg = $xml1->result->msg;
            }else{
                $msg = $xml1->msg->line;
            }
            $logger = MTLogger::getInstance();
            $logger->log(json_encode(array('success' => false, 'message' => "$msg")));
            return getErrorCode(ERROR_SpecificPANOS);
        } else {
            #Strip the result and response tags
//            $newline = str_replace(array("<response status=\"success\"><result>", "</result></response>"), "", $line);
            if (!is_dir(USERSPACE_PATH . "/devices") && !mkdir($concurrentDirectory = USERSPACE_PATH . "/devices", 0766) && !is_dir($concurrentDirectory)) {
                $logger = MTLogger::getInstance();
                $logger->log(json_encode(array('success' => false, 'message' => sprintf('Directory "%s" was not created', $concurrentDirectory))));
                return getErrorCode(FileNotCreated);
            }
            $deviceFolder = USERSPACE_PATH . "/devices/$deviceSerial/";
            if (!file_exists($deviceFolder) && !mkdir((string)$deviceFolder, 0777) && !is_dir((string)$deviceFolder)) {
                $logger = MTLogger::getInstance();
                $logger->log(json_encode(array('success' => false, 'message' => sprintf('Directory "%s" was not created', $deviceFolder))));
                return getErrorCode(FileNotCreated);
            }
            $File = USERSPACE_PATH . "/devices/$deviceSerial/applications-container.xml";
            $Handle = fopen($File, 'w');

            fwrite($Handle, $line);
            fclose($Handle);

            if ((file_exists($File)) and (filesize($File) != 0)) {
//            $pandbRBAC->query("UPDATE devices set apps='1' where hostname='$hostname' and devicename='$deviceSerial'");
                return getErrorCode(Correct);
            }
            return getErrorCode(ERROR_FileNotCreated);
        }
    }
}

function getRegions($hostname, $deviceSerial, $api_key, $port)
{
    if ($api_key != "") {
        global $pandb;

        // define params for the query
        $type = "config";
        $action = "get";
        $xpath ="/config/predefined/region";

        $debug_api = USERSPACE_PATH . "/devices/debug.txt";
        $curl_log = fopen($debug_api, 'a+');

        //$devicePath = $hostname . "/api";
        $devicePath = "https://" . $hostname . ":". $port . "/api?type=". $type ."&action=". $action . "&xpath=" . $xpath;

        $tuCurl = curl_init();
        // Custom headers to be added
        $headers = array(
            'X-PAN-KEY: ' . $api_key
        );
        curl_setopt($tuCurl, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($tuCurl, CURLOPT_URL, $devicePath);
        curl_setopt($tuCurl, CURLOPT_TIMEOUT, DEVICE_CONNECTION_TIMEOUT); // number of seconds prior to a timeout
        curl_setopt($tuCurl, CURLOPT_VERBOSE, DEVICE_DEBUG_CONNECTION_ENABLED==1);
        curl_setopt($tuCurl, CURLOPT_STDERR, $curl_log);
        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($tuCurl, CURLOPT_RETURNTRANSFER, true);

        $tuData = curl_exec($tuCurl);


//        $devicePath = $hostname . "/api";
//        $datatopost = array(
//            "type" => "config",
//            "action" => 'get',
//            "key" => $api_key,
//            "xpath" => "/config/predefined/region"
//        );
//
//        $tuCurl = curl_init();
//        $params = [
//            'url' => "https://$devicePath",
//            'port' => $port,
//            'postfields' => $datatopost,
//        ];
//        $curlObj = new CurlConnect($tuCurl, $params);
//        $tuData = $curlObj->exec();


//        curl_setopt($tuCurl, CURLOPT_URL, "https://$devicePath");
//        curl_setopt($tuCurl, CURLOPT_PORT, $port);
//        curl_setopt($tuCurl, CURLOPT_VERBOSE, 0);
//        curl_setopt($tuCurl, CURLOPT_HEADER, 0);
//        curl_setopt($tuCurl, CURLOPT_POST, 1);
//        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, 0);
//        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, 0);
//        curl_setopt($tuCurl, CURLOPT_RETURNTRANSFER, 1);
//        curl_setopt($tuCurl, CURLOPT_CONNECTTIMEOUT, 1500);
//        curl_setopt($tuCurl, CURLOPT_POSTFIELDS, $datatopost);
//        curl_setopt($tuCurl, CURLOPT_TIMEOUT, 0);
//        $tuData = curl_exec($tuCurl);
//        $curlObj->close();

        $line = curl_multi_getcontent($tuCurl);

        //print $line;
        $e = curl_errno($tuCurl);
        if (!checkConnectionErrors($e)) {
            return getErrorCode(ERROR_ConnectionNotEstablished);
        }

        curl_close($tuCurl);

        //Check the output is an XML
        $result = simplexml_load_string($line, 'SimpleXmlElement', LIBXML_NOERROR | LIBXML_ERR_FATAL | LIBXML_ERR_NONE);
        if (false == $result) {
            $logger = MTLogger::getInstance();
            $logger->log(json_encode(array('success' => false, 'message' => getErrorCode(ERROR_NotExpectedFileFormat, 'description'))));
            return getErrorCode(ERROR_NotExpectedFileFormat);
            exit(0);
        }

        $xml1 = simplexml_load_string($line);
        if (!isset($xml1) || $xml1->attributes()->status === "error"
            || preg_match('/response status="error"/', $line) || preg_match("/response status = 'error'/i", $tuData)) {
            if(isset($xml1->result->msg)) {
                $msg = $xml1->result->msg;
            }else{
                $msg = $xml1->msg->line;
            }
            $logger = MTLogger::getInstance();
            $logger->log(json_encode(array('success' => false, 'message' => "$msg")));
            return getErrorCode(ERROR_SpecificPANOS);
        } else {
            if (!is_dir(USERSPACE_PATH . "/devices") && !mkdir($concurrentDirectory = USERSPACE_PATH . "/devices", 0766) && !is_dir($concurrentDirectory)) {
                $logger = MTLogger::getInstance();
                $logger->log(json_encode(array('success' => false, 'message' => sprintf('Directory "%s" was not created', $concurrentDirectory))));
                return getErrorCode(FileNotCreated);
            }
            $deviceFolder = USERSPACE_PATH . "/devices/$deviceSerial/";
            if (!file_exists($deviceFolder) && !mkdir((string)$deviceFolder, 0777) && !is_dir((string)$deviceFolder)) {
                $logger = MTLogger::getInstance();
                $logger->log(json_encode(array('success' => false, 'message' => sprintf('Directory "%s" was not created', $deviceFolder))));
                return getErrorCode(FileNotCreated);
            }
            $File = USERSPACE_PATH . "/devices/$deviceSerial/region.xml";
            $Handle = fopen($File, 'w');

            fwrite($Handle, $line);
            fclose($Handle);

            if ((file_exists($File)) and (filesize($File) != 0)) {
//            $pandbRBAC->query("UPDATE devices set apps='1' where hostname='$hostname' and devicename='$devicename'");
                return getErrorCode(Correct);
            }
            return getErrorCode(ERROR_FileNotCreated);
        }
    }
}

function get_dynamic_report_appsbyrule_destination_panos($tuCurl, $pan_hostname, $api_key, $vsys, $serial, $period, $port, $source, $rulename, $rule_lid, $app, $dport, $ConnStart, $ConnEnd, $dg_query_all, $target)
{
    $report = "<type><traffic><aggregate-by><member>dst</member><member>dport</member><member>proto</member></aggregate-by><values><member>packets</member><member>bytes</member></values></traffic></type>";
    if ($period == "custom") {
        $report_period = "<start-time>" . $ConnStart . "</start-time><end-time>" . $ConnEnd . "</end-time>";
    } else {
        $report_period = "<period>" . $period . "</period>";
    }
    $report_top = "<topn>500</topn>";
    #$query = "<query>( rule eq '" . $rulename . "' ) AND (app eq '" . $app . "') AND (dport eq '" . $dport . "')</query>";
    if ($dg_query_all != "") {
        $query = "<query>(( rule eq '" . $rulename . "' ) AND (app eq '" . $app . "') AND (dport eq '" . $dport . "')) AND " . $dg_query_all . "</query>";
    } else {
        $query = "<query>( rule eq '" . $rulename . "' ) AND (app eq '" . $app . "') AND (dport eq '" . $dport . "')</query>";
    }
    $cmd = $report . $report_period . $report_top . $query;
    $array = array();
    if ($api_key != "") {
        //$timeout = 120;
        //$devicePath = $pan_hostname . "/api";
        if ($target == "") {
            $type = "report";
            $reporttype = "dynamic";
            $reportname = "custom-dynamic-report";
            $cmd = "&cmd=". urlencode($cmd);
            $async = "no";

            /*$datatopost = array(
                "type" => "report",
                "reporttype" => "dynamic",
                "key" => $api_key,
                "reportname" => "custom-dynamic-report",
                "cmd" => $cmd,
                "async" => "no"
            );*/
        } else {

            $type = "report";
            $reporttype = "dynamic";
            $reportname = "custom-dynamic-report";
            $cmd = "&cmd=".urlencode($cmd)."&target=".$target;
            $async = "no";

            /*$datatopost = array(
                "type" => "report",
                "reporttype" => "dynamic",
                "key" => $api_key,
                "reportname" => "custom-dynamic-report",
                "cmd" => $cmd,
                "target" => $target,
                "async" => "no"
            );*/
        }

        $devicePath = "https://" . $pan_hostname . ":". $port . "/api?type=". $type ."&reporttype=". $reporttype . "&reportname=" . $reportname . "&async=" . $async . $cmd;

        checkFolderExists(USERSPACE_PATH . "/devices/");
        $debugapi = USERSPACE_PATH . "/devices/debug.txt";

        $curl_log = fopen($debugapi, 'a+');
        /*$url0 = $devicePath;
        $url = '<a href="' . $url0 . '" target=_blank>' . $url0 . '</a><br>';
        fwrite($curl_log, $url);*/


//        $fields_string=array();


        // Custom headers to be added
        $headers = array(
            'X-PAN-KEY: ' . $api_key,
            'Expect:'
        );
        curl_setopt($tuCurl, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($tuCurl, CURLOPT_URL, $devicePath);
        curl_setopt($tuCurl, CURLOPT_TIMEOUT, 400000); // number of seconds prior to a timeout
        curl_setopt($tuCurl, CURLOPT_VERBOSE, DEVICE_DEBUG_CONNECTION_ENABLED==1);
        curl_setopt($tuCurl, CURLOPT_STDERR, $curl_log);
        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($tuCurl, CURLOPT_RETURNTRANSFER, true);

        $tuData = curl_exec($tuCurl);

        /*$params = [
            'url' => "https://$devicePath",
            'stderr' => $debugapi,
            'port' => $port,
            'postfields' => $datatopost,
            'timeout' => 400000,
            'httpheader' => array('Expect:')
        ];
        $curlObj = new CurlConnect($tuCurl, $params);
        $tuData = $curlObj->exec();

        $curlObj->close();
        */
        $line = curl_multi_getcontent($tuCurl);
        $xml = simplexml_load_string($line);
        $entry = $xml->xpath("//entry");
        foreach ($entry as $key => $value) {
            $array[] = "('$source', '$vsys', '$rule_lid', '$app', '$value->dport', '$value->dst','$value->proto', '$value->packets' ,'$value->bytes')";
        }
        if ($array) {
            return $array;
        }

        fclose($curl_log);
    }
}

function get_dynamic_report_appsbyrule_destination_panorama($ConnVsys, $tuCurl, $pan_hostname, $api_key, $vsys, $serial, $period, $port, $source, $rulename, $rule_lid, $app, $dport, $ConnStart, $ConnEnd, $dg_query_all, $target)
{
    $report = "<type><panorama-traffic><aggregate-by><member>dst</member><member>dport</member><member>proto</member></aggregate-by><values><member>packets</member><member>bytes</member></values></panorama-traffic></type>";
    if ($period == "custom") {
        $report_period = "<start-time>" . $ConnStart . "</start-time><end-time>" . $ConnEnd . "</end-time>";
    } else {
        $report_period = "<period>" . $period . "</period>";
    }
    $report_top = "<topn>500</topn>";
    #$query = "<query>(serial eq '" . $serial . "') and (vsys eq '" . $vsys . "') AND ( rule eq '" . $rulename . "' ) AND (app eq '" . $app . "') AND (dport eq '" . $dport . "')</query>";
    if ($dg_query_all != "") {
        $query = "<query>(( rule eq '" . $rulename . "' ) AND (app eq '" . $app . "') AND (dport eq '" . $dport . "')) AND " . $dg_query_all . "</query>";
    } else {
        $query = "<query>( rule eq '" . $rulename . "' ) AND (app eq '" . $app . "') AND (dport eq '" . $dport . "')</query>";
    }
    $cmd = urlencode($report . $report_period . $report_top . $query);
    $array = array();
    if ($api_key != "") {
        /*$timeout = 120;
        $devicePath = $pan_hostname . "/api";
        $datatopost = array(
            "type" => "report",
            "reporttype" => "dynamic",
            "key" => $api_key,
            "reportname" => "custom-dynamic-report",
            "cmd" => $cmd
        );*/

        $devicePath = "https://" . $pan_hostname . ":". $port . "/api?type=report&reporttype=dynamic&reportname=custom-dynamic-report&cmd=".$cmd;

        checkFolderExists(USERSPACE_PATH . "/devices/");
        $debugapi = USERSPACE_PATH . "/devices/debug.txt";

        $curl_log = fopen($debugapi, 'a+');
        /*$url0 = $devicePath;
        $url = '<a href="' . $url0 . '" target=_blank>' . $url0 . '</a><br>';
        fwrite($curl_log, $url);*/


//        $fields_string=array();

        /*$params = [
            'url' => "https://$devicePath",
            'stderr' => $debugapi,
            'port' => $port,
            'postfields' => $datatopost,
            'timeout' => 400000,
            'httpheader' => array('Expect:'),
        ];*/

        // Custom headers to be added
        $headers = array(
            'X-PAN-KEY: ' . $api_key,
            'Expect:'
        );
        curl_setopt($tuCurl, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($tuCurl, CURLOPT_URL, $devicePath);
        curl_setopt($tuCurl, CURLOPT_TIMEOUT, 400000); // number of seconds prior to a timeout
        curl_setopt($tuCurl, CURLOPT_VERBOSE, DEVICE_DEBUG_CONNECTION_ENABLED==1);
        curl_setopt($tuCurl, CURLOPT_STDERR, $curl_log);
        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($tuCurl, CURLOPT_RETURNTRANSFER, true);

        $tuData = curl_exec($tuCurl);

        fclose($curl_log);

        //$curlObj->close();

        $line = curl_multi_getcontent($tuCurl);
        $xml = simplexml_load_string($line);
        $arr = $xml->attributes();

        if ($arr["status"] == "success") {
            $job = $xml->result->job;
            if ($job != "") {
                $finish = FALSE;
                //sleep(2);

                while ($finish == FALSE) {
                    /*$timeout = 120;
                    $devicePath = $pan_hostname . "/api";
                    $datatopost = array(
                        "type" => "report",
                        "action" => "get",
                        "key" => $api_key,
                        "job-id" => $job
                    );*/

                    $devicePath = "https://" . $pan_hostname . ":". $port . "/api?type=report&action=get&job-id=".$job;

                    /*$params = [
                        'url' => "https://$devicePath",
                        'port' => $port,
                        'postfields' => $datatopost,
                        'timeout' => 400000,
                    ];
                    $curlObj = new CurlConnect($tuCurl, $params);
                    $tuData = $curlObj->exec();*/

                    // Custom headers to be added
                    $headers = array(
                        'X-PAN-KEY: ' . $api_key
                    );
                    curl_setopt($tuCurl, CURLOPT_HTTPHEADER, $headers);
                    curl_setopt($tuCurl, CURLOPT_URL, $devicePath);
                    curl_setopt($tuCurl, CURLOPT_TIMEOUT, 400000); // number of seconds prior to a timeout
                    curl_setopt($tuCurl, CURLOPT_VERBOSE, DEVICE_DEBUG_CONNECTION_ENABLED==1);
                    curl_setopt($tuCurl, CURLOPT_STDERR, $curl_log);
                    curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, false);
                    curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, false);
                    curl_setopt($tuCurl, CURLOPT_RETURNTRANSFER, true);

                    $tuData = curl_exec($tuCurl);
//                    curl_setopt($tuCurl, CURLOPT_URL, "https://$devicePath");
//                    curl_setopt($tuCurl, CURLOPT_PORT, $port);
//                    curl_setopt($tuCurl, CURLOPT_VERBOSE, 0);
//                    curl_setopt($tuCurl, CURLOPT_HEADER, 0);
//                    //curl_setopt($tuCurl, CURLOPT_SSLVERSION, 3); 
//                    curl_setopt($tuCurl, CURLOPT_POST, 1);
//                    curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, 0);
//                    curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, 0);
//                    curl_setopt($tuCurl, CURLOPT_RETURNTRANSFER, 1);
//                    curl_setopt($tuCurl, CURLOPT_CONNECTTIMEOUT, 0);
//                    curl_setopt($tuCurl, CURLOPT_POSTFIELDS, $datatopost);
//                    curl_setopt($tuCurl, CURLOPT_TIMEOUT, 400000);
//                    $tuData2 = curl_exec($tuCurl);
                    $line2 = curl_multi_getcontent($tuCurl);
                    $xmlcheck = simplexml_load_string($line2);
                    $status = $xmlcheck->result->job->status;
                    if ($status == "FIN") {
                        $finish = TRUE;
                    } else {
                        sleep(2);
                    }
                }

                $xml = simplexml_load_string($line2);
                $entry = $xml->xpath("//entry");
                foreach ($entry as $key => $value) {
                    if ($value->dst != "") {
                        $array[] = "('$source', '$vsys', '$rule_lid', '$app', '$value->dport', '$value->dst', '$value->proto', '$value->packets' ,'$value->bytes')";
                    }
                }
                if ($array) {
                    return $array;
                }
            }
        }
    }
}

function get_dynamic_report_appsbyrule_destination_pa7000($tuCurl, $pan_hostname, $api_key, $vsys, $serial, $period, $port, $source, $rulename, $rule_lid, $app, $dport, $ConnStart, $ConnEnd, $dg_query_all, $target)
{
    $report = "<type><traffic><aggregate-by><member>dst</member><member>dport</member><member>proto</member></aggregate-by><values><member>packets</member><member>bytes</member></values></traffic></type>";
    if ($period == "custom") {
        $report_period = "<start-time>" . $ConnStart . "</start-time><end-time>" . $ConnEnd . "</end-time>";
    } else {
        $report_period = "<period>" . $period . "</period>";
    }
    $report_top = "<topn>500</topn>";
    #$query = "<query>( rule eq '" . $rulename . "' ) AND (app eq '" . $app . "') AND (dport eq '" . $dport . "')</query>";
    if ($dg_query_all != "") {
        $query = "<query>(( rule eq '" . $rulename . "' ) AND (app eq '" . $app . "') AND (dport eq '" . $dport . "')) AND " . $dg_query_all . "</query>";
    } else {
        $query = "<query>( rule eq '" . $rulename . "' )AND (app eq '" . $app . "') AND (dport eq '" . $dport . "')</query>";
    }
    $cmd = urlencode($report . $report_period . $report_top . $query);
    $array = array();
    if ($api_key != "") {
        //$timeout = 120;
        //$devicePath = $pan_hostname . "/api";
        if ($target == "") {

            $cmd = "&cmd=".$cmd;

            /*$datatopost = array(
                "type" => "report",
                "reporttype" => "dynamic",
                "key" => $api_key,
                "report-name" => "custom-dynamic-report",
                "cmd" => $cmd,
                "async" => "yes"
            );*/
        } else {

            $cmd = "&cmd=".$cmd."&target=".$target;

            /*$datatopost = array(
                "type" => "report",
                "reporttype" => "dynamic",
                "key" => $api_key,
                "report-name" => "custom-dynamic-report",
                "cmd" => $cmd,
                "target" => $target,
                "async" => "yes"
            );*/
        }

        $devicePath = "https://" . $pan_hostname . ":". $port . "/api?type=report&async=yes&reporttype=dynamic&reportname=custom-dynamic-report".$cmd;


        checkFolderExists(USERSPACE_PATH . "/devices/");
        $debugapi = USERSPACE_PATH . "/devices/debug.txt";

        $curl_log = fopen($debugapi, 'a+');

        /*$url0 = $devicePath;
        $url = '<a href="' . $url0 . '" target=_blank>' . $url0 . '</a><br>';
        fwrite($curl_log, $url);*/

//        $fields_string=array();

        /*$params = [
            'url' => "https://$devicePath",
            'stderr' => $debugapi,
            'port' => $port,
            'postfields' => $datatopost,
            'timeout' => 400000,
            'httpheader' => array('Expect:'),
        ];
        $curlObj = new CurlConnect($tuCurl, $params);
        $tuData = $curlObj->exec();*/

        // Custom headers to be added
        $headers = array(
            'X-PAN-KEY: ' . $api_key,
            'Expect:'
        );
        curl_setopt($tuCurl, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($tuCurl, CURLOPT_URL, $devicePath);
        curl_setopt($tuCurl, CURLOPT_TIMEOUT, 400000); // number of seconds prior to a timeout
        curl_setopt($tuCurl, CURLOPT_VERBOSE, DEVICE_DEBUG_CONNECTION_ENABLED==1);
        curl_setopt($tuCurl, CURLOPT_STDERR, $curl_log);
        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($tuCurl, CURLOPT_RETURNTRANSFER, true);

        $tuData = curl_exec($tuCurl);

        fclose($curl_log);

        //$curlObj->close();
        $line = curl_multi_getcontent($tuCurl);
        $xml = simplexml_load_string($line);
        $arr = $xml->attributes();

        if ($arr["status"] == "success") {
            $job = $xml->result->job;
            if ($job != "") {
                $finish = FALSE;
                //sleep(2);

                while ($finish == FALSE) {
                    $timeout = 120;
                    $devicePath = $pan_hostname . "/api";
                    if ($target == "") {
                        /*$datatopost = array(
                            "type" => "report",
                            "action" => "get",
                            "key" => $api_key,
                            "job-id" => $job
                        );*/
                    } else {
                        $target="&target=".$target;
                        /*$datatopost = array(
                            "type" => "report",
                            "action" => "get",
                            "key" => $api_key,
                            "job-id" => $job,
                            "target" => $target
                        );*/
                    }

                    /*$params = [
                        'url' => "https://$devicePath",
                        'stderr' => $debugapi,
                        'port' => $port,
                        'postfields' => $datatopost,
                        'timeout' => 400000,
                    ];
                    $curlObj = new CurlConnect($tuCurl, $params);
                    $tuData = $curlObj->exec();*/

                    $devicePath = "https://" . $pan_hostname . ":". $port . "/api?type=report&action=get&job-id=".$job.$target;
                    $tuCurl = curl_init();
                    // Custom headers to be added
                    $headers = array(
                        'X-PAN-KEY: ' . $api_key
                    );
                    curl_setopt($tuCurl, CURLOPT_HTTPHEADER, $headers);
                    curl_setopt($tuCurl, CURLOPT_URL, $devicePath);
                    curl_setopt($tuCurl, CURLOPT_TIMEOUT, 400000); // number of seconds prior to a timeout
                    curl_setopt($tuCurl, CURLOPT_VERBOSE, DEVICE_DEBUG_CONNECTION_ENABLED==1);
                    curl_setopt($tuCurl, CURLOPT_STDERR, $curl_log);
                    curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, false);
                    curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, false);
                    curl_setopt($tuCurl, CURLOPT_RETURNTRANSFER, true);

                    $tuData2 = curl_exec($tuCurl);


//                    curl_setopt($tuCurl, CURLOPT_URL, "https://$devicePath");
//                    curl_setopt($tuCurl, CURLOPT_PORT, $port);
//                    curl_setopt($tuCurl, CURLOPT_VERBOSE, 0);
//                    curl_setopt($tuCurl, CURLOPT_HEADER, 0);
//                    //curl_setopt($tuCurl, CURLOPT_SSLVERSION, 3); 
//                    curl_setopt($tuCurl, CURLOPT_POST, 1);
//                    curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, 0);
//                    curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, 0);
//                    curl_setopt($tuCurl, CURLOPT_RETURNTRANSFER, 1);
//                    curl_setopt($tuCurl, CURLOPT_CONNECTTIMEOUT, 0);
//                    curl_setopt($tuCurl, CURLOPT_POSTFIELDS, $datatopost);
//                    curl_setopt($tuCurl, CURLOPT_TIMEOUT, 400000);
//                    $tuData2 = curl_exec($tuCurl);
                    //$curlObj->close();
                    $line2 = curl_multi_getcontent($tuCurl);
                    $xmlcheck = simplexml_load_string($line2);
                    $status = $xmlcheck->result->job->status;
                    if ($status == "FIN") {
                        $finish = TRUE;
                    } else {
                        sleep(2);
                    }
                }

                $xml = simplexml_load_string($line2);
                $entry = $xml->xpath("//entry");
                foreach ($entry as $key => $value) {
                    if ($value->dst != "") {
                        $array[] = "('$source', '$vsys', '$rule_lid', '$app', '$value->dport', '$value->dst', '$value->proto', '$value->packets' ,'$value->bytes')";
                    }
                }
                if ($array) {
                    return $array;
                }
            }
        }
    }
}

//function get_pcap_list_by_unknownapp_dest_port_panos($tuCurl, $pan_hostname, $api_key, $vsys, $serial, $period, $port, $source, $rulename, $rule_lid, $app, $dport, $dg_query_all, $target)
//{
//    $report = "<type><traffic><aggregate-by><member>day-of-receive_time</member><member>dst</member><member>dport</member><member>sessionid</member></aggregate-by></traffic></type>";
//    $report_period = "<period>" . $period . "</period>";
//    $report_top = "<topn>500</topn>";
//    $query = "<query>( rule eq '" . $rulename . "' ) AND (app eq '" . $app . "') AND (port.dst eq " . $dport . ") AND ( flags has pcap )</query>";
//    $cmd = $report . $report_period . $report_top . $query;
//    $array = array();
//    if ($api_key != "") {
//        $timeout = 120;
//        $devicePath = $pan_hostname . "/api";
//        $datatopost = array(
//            "type" => "report",
//            "reporttype" => "dynamic",
//            "key" => $api_key,
//            "reportname" => "custom-dynamic-report",
//            "cmd" => $cmd
//        );
//        //$tuCurl = curl_init();
//        $params = [
//            'url' => "https://$devicePath",
//            'port' => $port,
//            'postfields' => $datatopost,
//            'timeout' => 400000,
//            'httpheader' => array('Expect:'),
//        ];
//        $curlObj = new CurlConnect($tuCurl, $params);
//        $tuData = $curlObj->exec();
////        curl_setopt($tuCurl, CURLOPT_URL, "https://$devicePath");
////        curl_setopt($tuCurl, CURLOPT_PORT, $port);
////        curl_setopt($tuCurl, CURLOPT_VERBOSE, 0);
////        curl_setopt($tuCurl, CURLOPT_HEADER, 0);
////        curl_setopt($tuCurl, CURLOPT_POST, 1);
////        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, 0);
////        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, 0);
////        curl_setopt($tuCurl, CURLOPT_RETURNTRANSFER, 1);
////        curl_setopt($tuCurl, CURLOPT_HTTPHEADER, array('Expect:'));
////        curl_setopt($tuCurl, CURLOPT_POSTFIELDS, $datatopost);
////        curl_setopt($tuCurl, CURLOPT_TIMEOUT, 400000);
////
////        $tuData = curl_exec($tuCurl);
//
//        $line = curl_multi_getcontent($tuCurl);
//        $xml = simplexml_load_string($line);
//        $entry = $xml->xpath("//entry");
//        foreach ($entry as $key => $value) {
//            $array[] = "('$source', '$vsys', '$rule_lid', '$value->app', '$value->dport', '$value->bytes', '$value->packets')";
//        }
//        return $array;
//    }
//}

function get_dynamic_report_appsbyrule_panos($tuCurl, $pan_hostname, $api_key, $vsys, $serial, $period, $port, $source, $rulename, $rule_lid, $ConnStart, $ConnEnd, $dg_query_all, $target, $ConnTop)
{
    global $project;
    $report = "<type><traffic><aggregate-by><member>app</member><member>dport</member><member>proto</member></aggregate-by><values><member>bytes</member><member>packets</member></values></traffic></type>";
    if ($period == "custom") {
        $report_period = "<start-time>" . $ConnStart . "</start-time><end-time>" . $ConnEnd . "</end-time>";
    } else {
        $report_period = "<period>" . $period . "</period>";
    }

    $report_top = "<topn>" . $ConnTop . "</topn>";

    if ($dg_query_all != "") {
//        $query = "<query>(( rule eq '" . $rulename . "' ) AND (app neq 'incomplete') AND (app neq 'insufficient-data')) AND ".$dg_query_all."</query>";
        $query = "<query>(( rule eq '" . $rulename . "' ) ) AND " . $dg_query_all . "</query>";
    } else {
//        $query = "<query>( rule eq '" . $rulename . "' ) AND (app neq 'incomplete') AND (app neq 'insufficient-data')</query>";
        $query = "<query>( rule eq '" . $rulename . "' ) </query>";
    }

    $cmd = urlencode($report . $report_period . $report_top . $query);
    $array = array();
    if ($api_key != "") {
        //$timeout = 120;
        //$devicePath = $pan_hostname . "/api";
        if ($target == "") {

            $cmd = "&cmd=".$cmd;

            /*$datatopost = array(
                "type" => "report",
                "reporttype" => "dynamic",
                "key" => $api_key,
                "reportname" => "custom-dynamic-report",
                "cmd" => $cmd,
                "async" => "no"
            );*/
        } else {

            $cmd = "&cmd=".$cmd."&target=".$target;

            /*$datatopost = array(
                "type" => "report",
                "reporttype" => "dynamic",
                "key" => $api_key,
                "reportname" => "custom-dynamic-report",
                "cmd" => $cmd,
                "target" => $target,
                "async" => "no"
            );*/
        }

        $devicePath = "https://" . $pan_hostname . ":". $port . "/api?type=report&async=no&reporttype=dynamic&reportname=custom-dynamic-report".$cmd;

        checkFolderExists(USERSPACE_PATH . "/devices/");
        $debugapi = USERSPACE_PATH . "/devices/debug.txt";

        $curl_log = fopen($debugapi, 'a+');
        /*$url0 = $devicePath;
        $url = '<a href="' . $url0 . '" target=_blank>' . $url0 . '</a><br>';
        fwrite($curl_log, $url);*/

//        $fields_string=array();

        /*$params = [
            'url' => "https://$devicePath",
            'stderr' => $debugapi,
            'port' => $port,
            'postfields' => $datatopost,
            'timeout' => 400000,
            'httpheader' => array('Expect:'),
        ];
        $curlObj = new CurlConnect($tuCurl, $params);
        $tuData = $curlObj->exec();*/

        // Custom headers to be added
        $headers = array(
            'X-PAN-KEY: ' . $api_key,
            'Expect:'
        );
        curl_setopt($tuCurl, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($tuCurl, CURLOPT_URL, $devicePath);
        curl_setopt($tuCurl, CURLOPT_TIMEOUT, 400000); // number of seconds prior to a timeout
        curl_setopt($tuCurl, CURLOPT_VERBOSE, DEVICE_DEBUG_CONNECTION_ENABLED==1);
        curl_setopt($tuCurl, CURLOPT_STDERR, $curl_log);
        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($tuCurl, CURLOPT_RETURNTRANSFER, true);

        $tuData = curl_exec($tuCurl);

        fclose($curl_log);

        //$curlObj->close();
        $line = curl_multi_getcontent($tuCurl);
//        if (is_dir(USERSPACE_PATH."/projects/$project/Reports")) {
//        //if (is_dir(INC_ROOT."/projects/$project/Reports")) {
//
//        } else {
//            //mkdir(INC_ROOT."/projects/$project/Reports", 0766);
//            mkdir(USERSPACE_PATH."/projects/$project/Reports", 0766);
//        }
//        //$deviceFolder = INC_ROOT."/projects/$project/Reports/";
//        $deviceFolder = USERSPACE_PATH."/projects/$project/Reports/";
//        if (file_exists($deviceFolder)) {
//
//        } else {
//            mkdir("$deviceFolder", 0777);
//        }
//        //$File = INC_ROOT."/projects/$project/Reports/report_$rulename.xml";
//        $File = USERSPACE_PATH."/projects/$project/Reports/report_$rulename.xml";
//        $Handle = fopen($File, 'w');
//        fwrite($Handle, $line);
//        fclose($Handle);

        if ($line != "") {
            $xml = simplexml_load_string($line);
            $entry = $xml->xpath("//entry");
            foreach ($entry as $key => $value) {
                $array[] = "('$source', '$vsys', '$rule_lid', '$value->app', '$value->dport', '$value->bytes', '$value->packets','$value->proto', NOW())";
            }
            return $array;
        } else {
            return $array;
        }
    }
}

function get_dynamic_report_appsbyrule_panorama($ConnVsys, $tuCurl, $pan_hostname, $api_key, $vsys, $serial, $period, $port, $source, $rulename, $rule_lid, $ConnStart, $ConnEnd, $dg_query_all, $dg_query_device_group, $target, $ConnTop)
{
    $report = "<type><panorama-traffic><aggregate-by><member>app</member><member>dport</member><member>proto</member></aggregate-by><values><member>bytes</member><member>packets</member></values></panorama-traffic></type>";
    if ($period == "custom") {
        $report_period = "<start-time>" . $ConnStart . "</start-time><end-time>" . $ConnEnd . "</end-time>";
    } else {
        $report_period = "<period>" . $period . "</period>";
    }
    $report_top = "<topn>" . $ConnTop . "</topn>";

    //echo "DG query all: " .$dg_query_all. "\n";

    /*if ($dg_query_all!=""){
        //$query = "<query>(( rule eq '" . $rulename . "' ) AND (app neq 'incomplete') AND (app neq 'insufficient-data'))  AND ".$dg_query_all."</query>";
        $query = "<query>(( rule eq '" . $rulename . "' ) AND (app neq 'incomplete') AND (app neq 'insufficient-data')  AND ".$dg_query_all." )</query>";
    }
    else{
        $query = "<query>( rule eq '" . $rulename . "' ) AND (app neq 'incomplete') AND (app neq 'insufficient-data')</query>";
    }*/

    // MT-1133
    if ($dg_query_all != "") {
        //$query = "<query>(( rule eq '" . $rulename . "' ) AND (app neq 'incomplete') AND (app neq 'insufficient-data'))  AND ".$dg_query_all."</query>";
//        $query = "<query>(( rule eq '" . $rulename . "' ) AND (app neq 'incomplete') AND (app neq 'insufficient-data')  AND ".$dg_query_all." $dg_query_device_group )</query>";
        $query = "<query>(( rule eq '" . $rulename . "' )  AND " . $dg_query_all . " $dg_query_device_group )</query>";
    } else {
//        $query = "<query>( rule eq '" . $rulename . "' ) AND (app neq 'incomplete') AND (app neq 'insufficient-data') $dg_query_device_group</query>";
        $query = "<query>( rule eq '" . $rulename . "' )  $dg_query_device_group</query>";
    }

    $cmd = urlencode($report . $report_period . $report_top . $query);

    //echo "Cmd: " .$cmd. "\n";
    $array = array();
    if ($api_key != "") {

        $devicePath = "https://". $pan_hostname .":". $port . "/api?type=report&reporttype=dynamic&reportname=custom-dynamic-report";
        $devicePath.= "&cmd=" . $cmd;

//        $timeout = 120;
//        $devicePath = $pan_hostname . "/api";
//        $datatopost = array(
//            "type" => "report",
//            "reporttype" => "dynamic",
//            "key" => $api_key,
//            "report-name" => "custom-dynamic-report",
//            "cmd" => $cmd
//        );

        checkFolderExists(USERSPACE_PATH . "/devices/");
        $debugapi = USERSPACE_PATH . "/devices/debug.txt";

        $curl_log = fopen($debugapi, 'a+');
//        foreach ($datatopost as $key1 => $value1) {
//            if ($key1 == "key") {
//
//            } else {
//                $fields_string[] = $key1 . '=' . $value1;
//            }
//        }
//        $url0 = "https://" . $devicePath . "?" . implode("&", $fields_string);
//        $url = '<a href="' . $url0 . '" target=_blank>' . $url0 . '</a><br>';
        /*$url = '<a href="' . $devicePath . '" target=_blank>' . $devicePath . '</a><br>';
        fwrite($curl_log, $url);*/

//        $fields_string=array();

//        $params = [
//            'url' => "https://$devicePath",
//            'stderr' => $debugapi,
//            'port' => $port,
//            'postfields' => $datatopost,
//            'timeout' => 400000,
//            'httpheader' => array('Expect:'),
//        ];
//        $curlObj = new CurlConnect($tuCurl, $params);
        // Custom headers to be added
        $headers = array(
            'X-PAN-KEY: ' . $api_key,
            'Expect:'
        );
        curl_setopt($tuCurl, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($tuCurl, CURLOPT_URL, $devicePath);
        curl_setopt($tuCurl, CURLOPT_TIMEOUT, 400000);
        curl_setopt($tuCurl, CURLOPT_VERBOSE, DEVICE_DEBUG_CONNECTION_ENABLED==1);
        curl_setopt($tuCurl, CURLOPT_STDERR, $curl_log);
        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($tuCurl, CURLOPT_RETURNTRANSFER, true);
        $tuData = curl_exec($tuCurl);
        fclose($curl_log);
//        $tuData = $curlObj->exec();
//        curl_setopt($tuCurl, CURLOPT_STDERR, $curl_log);
//        curl_setopt($tuCurl, CURLOPT_URL, "https://$devicePath");
//        curl_setopt($tuCurl, CURLOPT_PORT, $port);
//        curl_setopt($tuCurl, CURLOPT_VERBOSE, 1);
//        curl_setopt($tuCurl, CURLOPT_HEADER, 0);
//        curl_setopt($tuCurl, CURLOPT_POST, 1);
//        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, 0);
//        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, 0);
//        curl_setopt($tuCurl, CURLOPT_RETURNTRANSFER, 1);
//        curl_setopt($tuCurl, CURLOPT_HTTPHEADER, array('Expect:'));
//        curl_setopt($tuCurl, CURLOPT_POSTFIELDS, $datatopost);
//        curl_setopt($tuCurl, CURLOPT_TIMEOUT, 400000);
//        $tuData = curl_exec($tuCurl);

//        $curlObj->close(); //TODO: Moved to after the under-loop

        $line = curl_multi_getcontent($tuCurl);
        //echo "Line: \n";
        //print_r($line);
        $xml = simplexml_load_string($line);
        //echo "Xml: \n";
        //print_r($xml);
        $arr = $xml->attributes();

        if ($arr["status"] == "success") {
            $job = $xml->result->job;
            if ($job != "") {
                $finish = FALSE;
                //sleep(2);
                $cancel = 150;
                while ($finish == FALSE) {

//                    $timeout = 120;
//                    $devicePath = $pan_hostname . "/api";
//                    $datatopost = array(
//                        "type" => "report",
//                        "action" => "get",
//                        "key" => $api_key,
//                        "job-id" => $job
//                    );
//
//                    curl_setopt($tuCurl, CURLOPT_URL, "https://$devicePath");
//                    curl_setopt($tuCurl, CURLOPT_PORT, $port);
//                    curl_setopt($tuCurl, CURLOPT_VERBOSE, 1);
//                    curl_setopt($tuCurl, CURLOPT_HEADER, 0);
//                    curl_setopt($tuCurl, CURLOPT_POST, 1);
//                    curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, 0);
//                    curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, 0);
//                    curl_setopt($tuCurl, CURLOPT_RETURNTRANSFER, 1);
//                    curl_setopt($tuCurl, CURLOPT_CONNECTTIMEOUT, 0);
//                    curl_setopt($tuCurl, CURLOPT_POSTFIELDS, $datatopost);
//                    curl_setopt($tuCurl, CURLOPT_TIMEOUT, 400000);

                    $devicePath = "https://" . $pan_hostname . ":" . $port . "/api?type=report&action=get";
                    $devicePath.= "&job-id=" . $job;

                    // Custom headers to be added
                    $headers = array(
                        'X-PAN-KEY: ' . $api_key
                    );
                    curl_setopt($tuCurl, CURLOPT_HTTPHEADER, $headers);
                    curl_setopt($tuCurl, CURLOPT_URL, $devicePath);
                    curl_setopt($tuCurl, CURLOPT_TIMEOUT, 400000);
                    curl_setopt($tuCurl, CURLOPT_VERBOSE, DEVICE_DEBUG_CONNECTION_ENABLED==1);
                    curl_setopt($tuCurl, CURLOPT_STDERR, $curl_log);
                    curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, false);
                    curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, false);
                    curl_setopt($tuCurl, CURLOPT_RETURNTRANSFER, true);

                    $tuData2 = curl_exec($tuCurl);
                    $line2 = curl_multi_getcontent($tuCurl);
                    $xmlcheck = simplexml_load_string($line2);
                    if (!isset($xmlcheck->result->job->status)) {
                        $finish = TRUE;
                        $status = "FIN";
                    } else {
                        $status = $xmlcheck->result->job->status;
                    }

                    if ($status == "FIN") {
                        $finish = TRUE;
                    } else {
                        sleep(2);
                        $cancel--;
                        if ($cancel == 0) {
                            $finish = FALSE;
                        }
                    }
                }
                $xml = simplexml_load_string($line2);
                $entry = $xml->xpath("//entry");
                foreach ($entry as $key => $value) {
                    if ($value->app != "") {
                        $array[] = "('$source', '$ConnVsys', '$rule_lid', '$value->app', '$value->dport', '$value->bytes', '$value->packets','$value->proto', NOW())";
                    }
                }
                if (isset($array)) {
                    return $array;
                }
            }
        }
//        $curlObj->close();
    }
}


function get_dynamic_report_appsbyrule_panorama_fast($ConnVsys, $tuCurl, $pan_hostname, $api_key, $vsys, $serial, $period, $port, $source, $rulename, $rule_lid, $ConnStart, $ConnEnd, $dg_query_all, $dg_query_device_group, $target, $ConnTop)
{
    //$report = "<type><panorama-trsum><aggregate-by><member>app</member><member>dport</member></aggregate-by><values><member>bytes</member></values></panorama-trsum></type>";
    $report = "<type><panorama-trsum><aggregate-by><member>app</member></aggregate-by><values><member>nunique-of-apps</member></values></panorama-trsum></type>";

    if ($period == "custom") {
        $report_period = "<start-time>" . $ConnStart . "</start-time><end-time>" . $ConnEnd . "</end-time>";
    } else {
        $report_period = "<period>" . $period . "</period>";
    }
    $report_top = "<topn>" . $ConnTop . "</topn>";

    /*if ($dg_query_all != ""){
        $query = "<query>(( rule eq '" . $rulename . "' ) AND (app neq 'incomplete') AND (app neq 'insufficient-data'))  AND ".$dg_query_all."</query>";
    }
    else{
        $query = "<query>( rule eq '" . $rulename . "' ) AND (app neq 'incomplete') AND (app neq 'insufficient-data') </query>";
    }*/

    // With DG Panorama MT-1133
    if ($dg_query_all != "") {
//        $query = "<query>(( rule eq '" . $rulename . "' ) AND (app neq 'incomplete') AND (app neq 'insufficient-data'))  AND ".$dg_query_all." $dg_query_device_group</query>";
        $query = "<query>(( rule eq '" . $rulename . "' ))  AND " . $dg_query_all . " $dg_query_device_group</query>";
    } else {
//        $query = "<query>( rule eq '" . $rulename . "' ) AND (app neq 'incomplete') AND (app neq 'insufficient-data') $dg_query_device_group</query>";
        $query = "<query>( rule eq '" . $rulename . "' ) $dg_query_device_group</query>";
    }

    //echo "Query: " .$query. "\n";

    $cmd = urlencode($report . $report_period . $report_top . $query);

    //echo "CMD: " .$cmd. "\n";

    $array = array();
    if ($api_key != "") {

//        $timeout = 120;
//        $devicePath = $pan_hostname . "/api";
//        $datatopost = array(
//            "type" => "report",
//            "reporttype" => "dynamic",
//            "key" => $api_key,
//            "report-name" => "custom-dynamic-report",
//            "cmd" => $cmd
//        );

        $devicePath = "https://". $pan_hostname .":". $port . "/api?type=report&reporttype=dynamic&reportname=custom-dynamic-report";
        $devicePath.= "&cmd=" . $cmd;


        checkFolderExists(USERSPACE_PATH . "/devices/");
        $debugapi = USERSPACE_PATH . "/devices/debug.txt";

        $curl_log = fopen($debugapi, 'a+');
//        foreach ($datatopost as $key1 => $value1) {
//            if ($key1 == "key") {
//
//            } else {
//                $fields_string[] = $key1 . '=' . $value1;
//            }
//        }
//        $url0 = "https://" . $devicePath . "?" . implode("&", $fields_string);
//        $url = '<a href="' . $url0 . '" target=_blank>' . $url0 . '</a><br>';
        //$url = '<a href="' . $devicePath . '" target=_blank>' . $devicePath . '</a><br>';
        //fwrite($curl_log, $url);
//        fclose($curl_log);
//        $fields_string=array();

//        $params = [
//            'url' => "https://$devicePath",
//            'stderr' => $debugapi,
//            'port' => $port,
//            'postfields' => $datatopost,
//            'timeout' => 400000,
//            'httpheader' => array('Expect:'),
//        ];
//        $curlObj = new CurlConnect($tuCurl, $params);
//        $tuData = $curlObj->exec();

        // Custom headers to be added
        $headers = array(
            'X-PAN-KEY: ' . $api_key,
            'Expect:'
        );
        curl_setopt($tuCurl, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($tuCurl, CURLOPT_URL, $devicePath);
        curl_setopt($tuCurl, CURLOPT_TIMEOUT, 400000);
        curl_setopt($tuCurl, CURLOPT_VERBOSE, DEVICE_DEBUG_CONNECTION_ENABLED==1);
        curl_setopt($tuCurl, CURLOPT_STDERR, $curl_log);
        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($tuCurl, CURLOPT_RETURNTRANSFER, true);

        $tuData = curl_exec($tuCurl);
        $line = curl_multi_getcontent($tuCurl);
        $xml = simplexml_load_string($line);
        $arr = $xml->attributes();

        if ($arr["status"] == "success") {
            $job = $xml->result->job;
            if ($job != "") {
                $finish = FALSE;
                //sleep(2);
                $cancel = 150;
                while ($finish == FALSE) {
//                    $timeout = 120;
//                    $devicePath = $pan_hostname . "/api";
//                    $datatopost = array(
//                        "type" => "report",
//                        "action" => "get",
//                        "key" => $api_key,
//                        "job-id" => $job
//                    );
//                    curl_setopt($tuCurl, CURLOPT_URL, "https://$devicePath");
//                    curl_setopt($tuCurl, CURLOPT_PORT, $port);
//                    curl_setopt($tuCurl, CURLOPT_VERBOSE, 1);
//                    curl_setopt($tuCurl, CURLOPT_HEADER, 0);
//                    curl_setopt($tuCurl, CURLOPT_POST, 1);
//                    curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, 0);
//                    curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, 0);
//                    curl_setopt($tuCurl, CURLOPT_RETURNTRANSFER, 1);
//                    curl_setopt($tuCurl, CURLOPT_CONNECTTIMEOUT, 0);
//                    curl_setopt($tuCurl, CURLOPT_POSTFIELDS, $datatopost);
//                    curl_setopt($tuCurl, CURLOPT_TIMEOUT, 400000);

                    $devicePath = "https://" . $pan_hostname . ":" . $port . "/api?type=report&action=get";
                    $devicePath.= "&job-id=" . $job;
                    // Custom headers to be added
                    $headers = array(
                        'X-PAN-KEY: ' . $api_key
                    );
                    curl_setopt($tuCurl, CURLOPT_HTTPHEADER, $headers);
                    curl_setopt($tuCurl, CURLOPT_URL, $devicePath);
                    curl_setopt($tuCurl, CURLOPT_TIMEOUT, 400000);
                    curl_setopt($tuCurl, CURLOPT_VERBOSE, DEVICE_DEBUG_CONNECTION_ENABLED==1);
                    curl_setopt($tuCurl, CURLOPT_STDERR, $curl_log);
                    curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, false);
                    curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, false);
                    curl_setopt($tuCurl, CURLOPT_RETURNTRANSFER, true);

                    $tuData2 = curl_exec($tuCurl);
                    $line2 = curl_multi_getcontent($tuCurl);
                    $xmlcheck = simplexml_load_string($line2);
                    $status = $xmlcheck->result->job->status;
                    if ($status == "FIN") {
                        $finish = TRUE;
                    } else {
                        sleep(2);
                        $cancel--;
                        if ($cancel == 0) {
                            $finish = FALSE;
                        }
                    }
                }
                $xml = simplexml_load_string($line2);
                $entry = $xml->xpath("//entry");
                foreach ($entry as $key => $value) {
                    if ($value->app != "") {
                        $array[] = "('$source', '$ConnVsys', '$rule_lid', '$value->app', '$value->dport', '$value->bytes', '','', NOW())";
                    }
                }
                if (isset($array)) {
                    return $array;
                }
            }
        }
//        $curlObj->close();
    }
}


function get_dynamic_report_threatsbyrule_panorama($ConnVsys, $tuCurl, $pan_hostname, $api_key, $vsys, $serial, $period, $port, $source, $rulename, $rule_lid, $ConnStart, $ConnEnd, $dg_query_all, $dg_query_device_group, $target, $ConnTop)
{
    //$report = "<type><panorama-trsum><aggregate-by><member>app</member><member>dport</member></aggregate-by><values><member>bytes</member></values></panorama-trsum></type>";
    //$report = "<type><panorama-trsum><aggregate-by><member>app</member></aggregate-by><values><member>nunique-of-apps</member></values></panorama-trsum></type>";
    $report = "<type>
          <panorama-thsum>
            <aggregate-by>
              <member>app</member>
              <member>category-of-threatid</member>
              <member>subtype</member>
              <member>severity</member>
              <member>action</member>
              <member>threatid</member>
            </aggregate-by>
            <values>
              <member>count</member>
            </values>
          </panorama-thsum>
        </type>";
    if ($period == "custom") {
        $report_period = "<start-time>" . $ConnStart . "</start-time><end-time>" . $ConnEnd . "</end-time>";
    } else {
        $report_period = "<period>" . $period . "</period>";
    }
    $report_top = "<topn>" . $ConnTop . "</topn>";

    /*if ($dg_query_all != ""){
        $query = "<query>(( rule eq '" . $rulename . "' ) AND (app neq 'incomplete') AND (app neq 'insufficient-data'))  AND ".$dg_query_all."</query>";
    }
    else{
        $query = "<query>( rule eq '" . $rulename . "' ) AND (app neq 'incomplete') AND (app neq 'insufficient-data') </query>";
    }*/

    // With DG Panorama MT-1133
    if ($dg_query_all != "") {
//        $query = "<query>(( rule eq '" . $rulename . "' ) AND (app neq 'incomplete') AND (app neq 'insufficient-data'))  AND ".$dg_query_all." $dg_query_device_group</query>";
        $query = "<query>(( rule eq '" . $rulename . "' ))  AND " . $dg_query_all . " $dg_query_device_group</query>";
    } else {
//        $query = "<query>( rule eq '" . $rulename . "' ) AND (app neq 'incomplete') AND (app neq 'insufficient-data') $dg_query_device_group</query>";
        $query = "<query>( rule eq '" . $rulename . "' ) $dg_query_device_group</query>";
    }

    //echo "Query: " .$query. "\n";

    $cmd = urlencode($report . $report_period . $report_top . $query);

    //echo "CMD: " .$cmd. "\n";

    $array = array();
    if ($api_key != "") {
        /*$timeout = 120;
        $devicePath = $pan_hostname . "/api";
        $datatopost = array(
            "type" => "report",
            "reporttype" => "dynamic",
            "key" => $api_key,
            "report-name" => "custom-dynamic-report",
            "cmd" => $cmd
        );*/

        $devicePath = "https://" . $pan_hostname . ":". $port . "/api?type=report&reporttype=dynamic&reportname=custom-dynamic-report&cmd=".$cmd;

        checkFolderExists(USERSPACE_PATH . "/devices/");
        $debugapi = USERSPACE_PATH . "/devices/debug.txt";

        $curl_log = fopen($debugapi, 'a+');
        $url0 = $devicePath;
        //$url = '<a href="' . $url0 . '" target=_blank>' . $url0 . '</a><br>';
        //fwrite($curl_log, $url);

//        $fields_string=array();

        /*$params = [
            'url' => "https://$devicePath",
            'stderr' => $debugapi,
            'port' => $port,
            'postfields' => $datatopost,
            'timeout' => 400000,
            'httpheader' => array('Expect:'),
        ];
        $curlObj = new CurlConnect($tuCurl, $params);
        $tuData = $curlObj->exec();*/

        // Custom headers to be added
        $headers = array(
            'X-PAN-KEY: ' . $api_key,
            'Expect:'
        );
        curl_setopt($tuCurl, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($tuCurl, CURLOPT_URL, $devicePath);
        curl_setopt($tuCurl, CURLOPT_TIMEOUT, DEVICE_CONNECTION_TIMEOUT); // number of seconds prior to a timeout
        curl_setopt($tuCurl, CURLOPT_VERBOSE, DEVICE_DEBUG_CONNECTION_ENABLED==1);
        curl_setopt($tuCurl, CURLOPT_STDERR, $curl_log);
        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($tuCurl, CURLOPT_RETURNTRANSFER, true);

        $tuData = curl_exec($tuCurl);

        fclose($curl_log);

        $line = curl_multi_getcontent($tuCurl);
        $xml = simplexml_load_string($line);
        $arr = $xml->attributes();

        if ($arr["status"] == "success") {
            $job = $xml->result->job;
            if ($job != "") {
                $finish = FALSE;
                //sleep(2);
                $cancel = 150;
                while ($finish == FALSE) {
                    $timeout = 120;
                    $devicePath = $pan_hostname . "/api";
                    $datatopost = array(
                        "type" => "report",
                        "action" => "get",
                        "key" => $api_key,
                        "job-id" => $job
                    );

                    $devicePath = "https://" . $pan_hostname . ":". $port . "/api?type=report&action=get&job-id=".$job;

                    // Custom headers to be added
                    $headers = array(
                        'X-PAN-KEY: ' . $api_key
                    );
                    curl_setopt($tuCurl, CURLOPT_HTTPHEADER, $headers);
                    curl_setopt($tuCurl, CURLOPT_URL, $devicePath);
                    curl_setopt($tuCurl, CURLOPT_TIMEOUT, 400000); // number of seconds prior to a timeout
                    curl_setopt($tuCurl, CURLOPT_VERBOSE, DEVICE_DEBUG_CONNECTION_ENABLED==1);
                    curl_setopt($tuCurl, CURLOPT_STDERR, $curl_log);
                    curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, false);
                    curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, false);
                    curl_setopt($tuCurl, CURLOPT_RETURNTRANSFER, true);
                    $tuData2 = curl_exec($tuCurl);

                    $line2 = curl_multi_getcontent($tuCurl);
                    $xmlcheck = simplexml_load_string($line2);
                    $status = $xmlcheck->result->job->status;
                    if ($status == "FIN") {
                        $finish = TRUE;
                    } else {
                        sleep(2);
                        $cancel--;
                        if ($cancel == 0) {
                            $finish = FALSE;
                        }
                    }
                }
                $xml = simplexml_load_string($line2);
                $entry = $xml->xpath("//entry");
                foreach ($entry as $key => $value) {
                    if ($value->app != "") {
                        $array[] = "('$source', '$vsys', '$rule_lid', '$value->app', '$value->threatid', '$value->tid', '" . $value->{'category-of-threatid'} . "','$value->subtype', NOW() , '" . $value->{'severity-of-threatid'} . "', '$value->count', '$value->action')";
                    }
                }
                if (isset($array)) {
                    return $array;
                }
            }
        }
        //$curlObj->close();
    }
}


function get_dynamic_report_appsbyrule_pa7000($tuCurl, $pan_hostname, $api_key, $vsys, $serial, $period, $port, $source, $rulename, $rule_lid, $ConnStart, $ConnEnd, $dg_query_all, $target, $ConnTop)
{
    $report = "<type><traffic><aggregate-by><member>app</member><member>dport</member><member>proto</member></aggregate-by><values><member>bytes</member><member>packets</member></values></traffic></type>";
    if ($period == "custom") {
        $report_period = "<start-time>" . $ConnStart . "</start-time><end-time>" . $ConnEnd . "</end-time>";
    } else {
        $report_period = "<period>" . $period . "</period>";
    }
    $report_top = "<topn>" . $ConnTop . "</topn>";

    //echo "DG query all: ".$dg_query_all ."\n";

    if ($dg_query_all != "") {
        //$query = "<query>(( rule eq '" . $rulename . "' ) AND (app neq 'incomplete') AND (app neq 'insufficient-data')) AND ".$dg_query_all."</query>";
//        $query = "<query>(( rule eq '" . $rulename . "' ) AND (app neq 'incomplete') AND (app neq 'insufficient-data') AND ".$dg_query_all.")</query>";
        $query = "<query>(( rule eq '" . $rulename . "' ) AND " . $dg_query_all . ")</query>";
    } else {
//        $query = "<query>( rule eq '" . $rulename . "' ) AND (app neq 'incomplete') AND (app neq 'insufficient-data')</query>";
        $query = "<query>( rule eq '" . $rulename . "' ) </query>";
    }
    $cmd = urlencode($report . $report_period . $report_top . $query);

    //echo "Cmd: " .$cmd. "\n";

    $array = array();
    if ($api_key != "") {

        $devicePath = "https://". $pan_hostname .":". $port . "/api?type=report&reporttype=dynamic&reportname=custom-dynamic-report&async=yes";
        $devicePath.= "&cmd=" . $cmd;
        if($target != ""){
            $devicePath.= "&target=" . $target;
        }

//        if ($target == "") {
//            $datatopost = array(
//                "type" => "report",
//                "reporttype" => "dynamic",
//                "key" => $api_key,
//                "report-name" => "custom-dynamic-report",
//                "cmd" => $cmd,
//                "async" => "yes"
//            );
//        } else {
//            $datatopost = array(
//                "type" => "report",
//                "reporttype" => "dynamic",
//                "key" => $api_key,
//                "report-name" => "custom-dynamic-report",
//                "cmd" => $cmd,
//                "target" => $target,
//                "async" => "yes"
//            );
//        }

        checkFolderExists(USERSPACE_PATH . "/devices/");
        $debugapi = USERSPACE_PATH . "/devices/debug.txt";
        $curl_log = fopen($debugapi, 'a+');
//        foreach ($datatopost as $key1 => $value1) {
//            if ($key1 == "key") {
//            } else {
//                $fields_string[] = $key1 . '=' . $value1;
//            }
//        }
//        $url0 = "https://" . $devicePath . "?" . implode("&", $fields_string);
        //$url = '<a href="' . $devicePath . '" target=_blank>' . $devicePath . '</a><br>';
        //fwrite($curl_log, $url);
//        $fields_string = array();

        // Custom headers to be added
        $headers = array(
            'X-PAN-KEY: ' . $api_key,
            'Expect:'
        );
        curl_setopt($tuCurl, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($tuCurl, CURLOPT_URL, $devicePath);
        curl_setopt($tuCurl, CURLOPT_TIMEOUT, 400000);
        curl_setopt($tuCurl, CURLOPT_VERBOSE, DEVICE_DEBUG_CONNECTION_ENABLED==1);
        curl_setopt($tuCurl, CURLOPT_STDERR, $curl_log);
        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($tuCurl, CURLOPT_RETURNTRANSFER, true);
//        curl_setopt($tuCurl, CURLOPT_PORT, $port);
//        curl_setopt($tuCurl, CURLOPT_HEADER, 0);
//        curl_setopt($tuCurl, CURLOPT_POST, 1);
//        curl_setopt($tuCurl, CURLOPT_HTTPHEADER, array('Expect:'));
//        curl_setopt($tuCurl, CURLOPT_POSTFIELDS, $datatopost);

        $tuData = curl_exec($tuCurl);
        $line = curl_multi_getcontent($tuCurl);

        $xml = simplexml_load_string($line);
        $arr = $xml->attributes();

        //echo "Line: \n";
        //print_r($line);
        $xml = simplexml_load_string($line);
        //echo "Xml: \n";
        //print_r($xml);

        if ($arr["status"] == "success") {
            $job = $xml->result->job;
            if ($job != "") {
                $finish = FALSE;
                $cancel = 150;
                //sleep(2);
                while ($finish == FALSE) {

                    $devicePath = "https://" . $pan_hostname . ":" . $port . "/api?type=report&action=get";
                    $devicePath.= "&job-id=" . $job;
                    if($target != ""){
                        $devicePath.= "&target=" . $target;
                    }

//                    if ($target == "") {
//                        $datatopost = array(
//                            "type" => "report",
//                            "action" => "get",
//                            "key" => $api_key,
//                            "job-id" => $job
//                        );
//                    } else {
//                        $datatopost = array(
//                            "type" => "report",
//                            "action" => "get",
//                            "key" => $api_key,
//                            "job-id" => $job,
//                            "target" => $target
//                        );
//                    }
//                    curl_setopt($tuCurl, CURLOPT_URL, $devicePath);
//                    curl_setopt($tuCurl, CURLOPT_PORT, $port);
//                    curl_setopt($tuCurl, CURLOPT_VERBOSE, 1);
//                    curl_setopt($tuCurl, CURLOPT_HEADER, 0);
//                    curl_setopt($tuCurl, CURLOPT_POST, 1);
//                    curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, 0);
//                    curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, 0);
//                    curl_setopt($tuCurl, CURLOPT_RETURNTRANSFER, 1);
//                    curl_setopt($tuCurl, CURLOPT_CONNECTTIMEOUT, 0);
//                    curl_setopt($tuCurl, CURLOPT_POSTFIELDS, $datatopost);
//                    curl_setopt($tuCurl, CURLOPT_TIMEOUT, DEVICE_CONNECTION_TIMEOUT);

                    // Custom headers to be added
                    $headers = array(
                        'X-PAN-KEY: ' . $api_key
                    );
                    curl_setopt($tuCurl, CURLOPT_HTTPHEADER, $headers);
                    curl_setopt($tuCurl, CURLOPT_URL, $devicePath);
                    curl_setopt($tuCurl, CURLOPT_TIMEOUT, 400000);
                    curl_setopt($tuCurl, CURLOPT_VERBOSE, DEVICE_DEBUG_CONNECTION_ENABLED==1);
                    curl_setopt($tuCurl, CURLOPT_STDERR, $curl_log);
                    curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, false);
                    curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, false);
                    curl_setopt($tuCurl, CURLOPT_RETURNTRANSFER, true);

                    $tuData2 = curl_exec($tuCurl);
                    $line2 = curl_multi_getcontent($tuCurl);
                    $xmlcheck = simplexml_load_string($line2);
                    $status = $xmlcheck->result->job->status;
                    if ($status == "FIN") {
                        $finish = TRUE;
                    } else {
                        sleep(2);
                        $cancel--;
                        if ($cancel == 0) {
                            $finish = FALSE;
                        }
                    }
                }
                $xml = simplexml_load_string($line2);
                $entry = $xml->xpath("//entry");
                foreach ($entry as $key => $value) {
                    if ($value->app != "") {
                        $array[] = "('$source', '$vsys', '$rule_lid', '$value->app', '$value->dport', '$value->bytes', '$value->packets','$value->proto', NOW())";
                    }
                }
                if (isset($array)) {
                    return $array;
                }
            }
        }
        fclose($curl_log);
    }
}


function get_dynamic_report_appsbyrule_pa7000_fast($tuCurl, $pan_hostname, $api_key, $vsys, $serial, $period, $port, $source, $rulename, $rule_lid, $ConnStart, $ConnEnd, $dg_query_all, $target, $ConnTop)
{
    //$report = "<type><trsum><aggregate-by><member>app</member><member>dport</member></aggregate-by><values><member>bytes</member></values></trsum></type>";
    $report = "<type><trsum><aggregate-by><member>app</member></aggregate-by><values><member>nunique-of-apps</member></values></trsum></type>";

    if ($period == "custom") {
        $report_period = "<start-time>" . $ConnStart . "</start-time><end-time>" . $ConnEnd . "</end-time>";
    } else {
        $report_period = "<period>" . $period . "</period>";
    }
    $report_top = "<topn>" . $ConnTop . "</topn>";
    if ($dg_query_all != "") {
//        $query = "<query>(( rule eq '" . $rulename . "' ) AND (app neq 'incomplete') AND (app neq 'insufficient-data')) AND ".$dg_query_all."</query>";
        $query = "<query>(( rule eq '" . $rulename . "' ) ) AND " . $dg_query_all . "</query>";
    } else {
//        $query = "<query>( rule eq '" . $rulename . "' ) AND (app neq 'incomplete') AND (app neq 'insufficient-data')</query>";
        $query = "<query>( rule eq '" . $rulename . "' ) </query>";
    }
    $cmd = urlencode($report . $report_period . $report_top . $query);

    //echo "CMD: " .$cmd. "\n";

    $array = array();
    if ($api_key != "") {

        $devicePath = "https://". $pan_hostname .":". $port . "/api?type=report&reporttype=dynamic&reportname=custom-dynamic-report&async=yes";
        $devicePath.= "&cmd=" . $cmd;
        if($target != ""){
            $devicePath.= "&target=" . $target;
        }


//        $timeout = 120;
//        $devicePath = $pan_hostname . "/api";
//        if ($target == "") {
//            $datatopost = array(
//                "type" => "report",
//                "reporttype" => "dynamic",
//                "key" => $api_key,
//                "report-name" => "custom-dynamic-report",
//                "cmd" => $cmd,
//                "async" => "yes"
//            );
//        } else {
//            $datatopost = array(
//                "type" => "report",
//                "reporttype" => "dynamic",
//                "key" => $api_key,
//                "report-name" => "custom-dynamic-report",
//                "cmd" => $cmd,
//                "target" => $target,
//                "async" => "yes"
//            );
//        }

        checkFolderExists(USERSPACE_PATH . "/devices/");
        $debugapi = USERSPACE_PATH . "/devices/debug.txt";
        $curl_log = fopen($debugapi, 'a+');
//        foreach ($datatopost as $key1 => $value1) {
//            if ($key1 == "key") {
//            } else {
//                $fields_string[] = $key1 . '=' . $value1;
//            }
//        }
//        $url0 = "https://" . $devicePath . "?" . implode("&", $fields_string);
//        $url = '<a href="' . $url0 . '" target=_blank>' . $url0 . '</a><br>';
        //$url = '<a href="' . $devicePath . '" target=_blank>' . $devicePath . '</a><br>';
        //fwrite($curl_log, $url);

        // Custom headers to be added
        $headers = array(
            'X-PAN-KEY: ' . $api_key,
            'Expect:'
        );
        curl_setopt($tuCurl, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($tuCurl, CURLOPT_URL, $devicePath);
        curl_setopt($tuCurl, CURLOPT_TIMEOUT, 400000);
        curl_setopt($tuCurl, CURLOPT_VERBOSE, DEVICE_DEBUG_CONNECTION_ENABLED==1);
        curl_setopt($tuCurl, CURLOPT_STDERR, $curl_log);
        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($tuCurl, CURLOPT_RETURNTRANSFER, true);
//        $fields_string = array();
//        curl_setopt($tuCurl, CURLOPT_STDERR, $curl_log);
//        curl_setopt($tuCurl, CURLOPT_URL, "https://$devicePath");
//        curl_setopt($tuCurl, CURLOPT_PORT, $port);
//        curl_setopt($tuCurl, CURLOPT_VERBOSE, 1);
//        curl_setopt($tuCurl, CURLOPT_HEADER, 0);
//        curl_setopt($tuCurl, CURLOPT_POST, 1);
//        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, 0);
//        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, 0);
//        curl_setopt($tuCurl, CURLOPT_RETURNTRANSFER, 1);
//        curl_setopt($tuCurl, CURLOPT_HTTPHEADER, array('Expect:'));
//        curl_setopt($tuCurl, CURLOPT_POSTFIELDS, $datatopost);
//        curl_setopt($tuCurl, CURLOPT_TIMEOUT, 400000);
        $tuData = curl_exec($tuCurl);
        $line = curl_multi_getcontent($tuCurl);

        $xml = simplexml_load_string($line);
        $arr = $xml->attributes();

        if ($arr["status"] == "success") {
            $job = $xml->result->job;
            if ($job != "") {
                $finish = FALSE;
                $cancel = 150;
                //sleep(2);
                while ($finish == FALSE) {

                    $devicePath = "https://" . $pan_hostname . ":" . $port . "/api?type=report&action=get";
                    $devicePath.= "&job-id=" . $job;
                    if($target != ""){
                        $devicePath.= "&target=" . $target;
                    }
                    // Custom headers to be added
                    $headers = array(
                        'X-PAN-KEY: ' . $api_key
                    );
                    curl_setopt($tuCurl, CURLOPT_HTTPHEADER, $headers);
                    curl_setopt($tuCurl, CURLOPT_URL, $devicePath);
                    curl_setopt($tuCurl, CURLOPT_TIMEOUT, 400000);
                    curl_setopt($tuCurl, CURLOPT_VERBOSE, DEVICE_DEBUG_CONNECTION_ENABLED==1);
                    curl_setopt($tuCurl, CURLOPT_STDERR, $curl_log);
                    curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, false);
                    curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, false);
                    curl_setopt($tuCurl, CURLOPT_RETURNTRANSFER, true);

//                    $timeout = 120;
//                    $devicePath = $pan_hostname . "/api";
//                    if ($target == "") {
//                        $datatopost = array(
//                            "type" => "report",
//                            "action" => "get",
//                            "key" => $api_key,
//                            "job-id" => $job
//                        );
//                    } else {
//                        $datatopost = array(
//                            "type" => "report",
//                            "action" => "get",
//                            "key" => $api_key,
//                            "job-id" => $job,
//                            "target" => $target
//                        );
//                    }
//                    curl_setopt($tuCurl, CURLOPT_URL, "https://$devicePath");
//                    curl_setopt($tuCurl, CURLOPT_PORT, $port);
//                    curl_setopt($tuCurl, CURLOPT_VERBOSE, 1);
//                    curl_setopt($tuCurl, CURLOPT_HEADER, 0);
//                    curl_setopt($tuCurl, CURLOPT_POST, 1);
//                    curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, 0);
//                    curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, 0);
//                    curl_setopt($tuCurl, CURLOPT_RETURNTRANSFER, 1);
//                    curl_setopt($tuCurl, CURLOPT_CONNECTTIMEOUT, 0);
//                    curl_setopt($tuCurl, CURLOPT_POSTFIELDS, $datatopost);
//                    curl_setopt($tuCurl, CURLOPT_TIMEOUT, 400000);
                    $tuData2 = curl_exec($tuCurl);
                    $line2 = curl_multi_getcontent($tuCurl);
                    $xmlcheck = simplexml_load_string($line2);
                    $status = $xmlcheck->result->job->status;
                    if ($status == "FIN") {
                        $finish = TRUE;
                    } else {
                        sleep(2);
                        $cancel--;
                        if ($cancel == 0) {
                            $finish = FALSE;
                        }
                    }
                }
                $xml = simplexml_load_string($line2);
                $entry = $xml->xpath("//entry");
                foreach ($entry as $key => $value) {
                    if ($value->app != "") {
                        $array[] = "('$source', '$vsys', '$rule_lid', '$value->app', '$value->dport', '$value->bytes', '','', NOW())";
                    }
                }
                if (isset($array)) {
                    return $array;
                }
            }
        }
        fclose($curl_log);
    }
}

# Threats by Rule
function get_dynamic_report_threatsbyrule_pa7000($tuCurl, $pan_hostname, $api_key, $vsys, $serial, $period, $port, $source, $rulename, $rule_lid, $ConnStart, $ConnEnd, $dg_query_all, $target, $ConnTop)
{
    $report = "<type>
          <thsum>
            <aggregate-by>
              <member>app</member>
              <member>category-of-threatid</member>
              <member>subtype</member>
              <member>severity</member>
              <member>action</member>
              <member>threatid</member>
            </aggregate-by>
            <values>
              <member>count</member>
            </values>
          </thsum>
        </type>";
    if ($period == "custom") {
        $report_period = "<start-time>" . $ConnStart . "</start-time><end-time>" . $ConnEnd . "</end-time>";
    } else {
        $report_period = "<period>" . $period . "</period>";
    }
    $report_top = "<topn>" . $ConnTop . "</topn>";

    //echo "DG query all: ".$dg_query_all ."\n";

    if ($dg_query_all != "") {
        //$query = "<query>(( rule eq '" . $rulename . "' ) AND (app neq 'incomplete') AND (app neq 'insufficient-data')) AND ".$dg_query_all."</query>";
//        $query = "<query>(( rule eq '" . $rulename . "' ) AND (app neq 'incomplete') AND (app neq 'insufficient-data') AND ".$dg_query_all.")</query>";
        $query = "<query>(( rule eq '" . $rulename . "' ) AND " . $dg_query_all . ")</query>";
    } else {
//        $query = "<query>( rule eq '" . $rulename . "' ) AND (app neq 'incomplete') AND (app neq 'insufficient-data')</query>";
        $query = "<query>( rule eq '" . $rulename . "' ) </query>";
    }
    $cmd = urlencode($report . $report_period . $report_top . $query);

    //echo "Cmd: " .$cmd. "\n";

    $array = array();
    if ($api_key != "") {
        //$timeout = 120;
        //$devicePath = $pan_hostname . "/api";
        if ($target == "") {

            $cmd = "&cmd=".$cmd;

            /*$datatopost = array(
                "type" => "report",
                "reporttype" => "dynamic",
                "key" => $api_key,
                "report-name" => "custom-dynamic-report",
                "cmd" => $cmd,
                "async" => "yes"
            );*/
        } else {

            $cmd = "&cmd=".$cmd."&target=".$target;

            /*$datatopost = array(
                "type" => "report",
                "reporttype" => "dynamic",
                "key" => $api_key,
                "report-name" => "custom-dynamic-report",
                "cmd" => $cmd,
                "target" => $target,
                "async" => "yes"
            );*/
        }

        $devicePath = "https://" . $pan_hostname . ":". $port . "/api?type=report&async=yes&reporttype=dynamic&reportname=custom-dynamic-report".$cmd;

        checkFolderExists(USERSPACE_PATH . "/devices/");
        $debugapi = USERSPACE_PATH . "/devices/debug.txt";
        $curl_log = fopen($debugapi, 'a+');
        //$url0 = $devicePath;
        //$url = '<a href="' . $url0 . '" target=_blank>' . $url0 . '</a><br>';
        //fwrite($curl_log, $url);

        // Custom headers to be added
        $headers = array(
            'X-PAN-KEY: ' . $api_key,
            'Expect:'
        );
        curl_setopt($tuCurl, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($tuCurl, CURLOPT_URL, $devicePath);
        curl_setopt($tuCurl, CURLOPT_TIMEOUT, 400000); // number of seconds prior to a timeout
        curl_setopt($tuCurl, CURLOPT_VERBOSE, DEVICE_DEBUG_CONNECTION_ENABLED==1);
        curl_setopt($tuCurl, CURLOPT_STDERR, $curl_log);
        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($tuCurl, CURLOPT_RETURNTRANSFER, true);
        $tuData = curl_exec($tuCurl);
        $line = curl_multi_getcontent($tuCurl);

        $xml = simplexml_load_string($line);
        $arr = $xml->attributes();

        //echo "Line: \n";
        //print_r($line);
        $xml = simplexml_load_string($line);
        //echo "Xml: \n";
        //print_r($xml);

        if ($arr["status"] == "success") {
            $job = $xml->result->job;
            if ($job != "") {
                $finish = FALSE;
                $cancel = 150;
                //sleep(2);
                while ($finish == FALSE) {
                    //$timeout = 120;
                    //$devicePath = $pan_hostname . "/api";
                    if ($target == "") {
                        /*$datatopost = array(
                            "type" => "report",
                            "action" => "get",
                            "key" => $api_key,
                            "job-id" => $job
                        );*/
                    } else {
                        $target = "&target=".$target;
                        /*$datatopost = array(
                            "type" => "report",
                            "action" => "get",
                            "key" => $api_key,
                            "job-id" => $job,
                            "target" => $target
                        );*/
                    }

                    $devicePath = "https://" . $pan_hostname . ":". $port . "/api?type=report&action=get&job-id=".$job . $target;

                    // Custom headers to be added
                    $headers = array(
                        'X-PAN-KEY: ' . $api_key
                    );
                    curl_setopt($tuCurl, CURLOPT_HTTPHEADER, $headers);
                    curl_setopt($tuCurl, CURLOPT_URL, $devicePath);
                    curl_setopt($tuCurl, CURLOPT_TIMEOUT, 400000); // number of seconds prior to a timeout
                    curl_setopt($tuCurl, CURLOPT_VERBOSE, DEVICE_DEBUG_CONNECTION_ENABLED==1);
                    curl_setopt($tuCurl, CURLOPT_STDERR, $curl_log);
                    curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, false);
                    curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, false);
                    curl_setopt($tuCurl, CURLOPT_RETURNTRANSFER, true);
                    $tuData2 = curl_exec($tuCurl);
                    $line2 = curl_multi_getcontent($tuCurl);
                    $xmlcheck = simplexml_load_string($line2);
                    $status = $xmlcheck->result->job->status;
                    if ($status == "FIN") {
                        $finish = TRUE;
                    } else {
                        sleep(2);
                        $cancel--;
                        if ($cancel == 0) {
                            $finish = FALSE;
                        }
                    }
                }
                $xml = simplexml_load_string($line2);
                $entry = $xml->xpath("//entry");
                foreach ($entry as $key => $value) {
                    if ($value->app != "") {
                        $array[] = "('$source', '$vsys', '$rule_lid', '$value->app', '$value->threatid', '$value->tid', '" . $value->{'category-of-threatid'} . "','$value->subtype', NOW() , '" . $value->{'severity-of-threatid'} . "', '$value->count', '$value->action')";
                    }
                }
                if (isset($array)) {
                    return $array;
                }
            }
        }
        fclose($curl_log);
    }
}


function get_dynamic_report_usersbyrule_panos($tuCurl, $pan_hostname, $api_key, $vsys, $serial, $period, $port, $source, $rulename, $rule_lid, $ConnStart, $ConnEnd, $dg_query_all, $target)
{
    global $project;
    $report = "<type><trsum><aggregate-by><member>srcuser</member></aggregate-by><values><member>sessions</member><member>bytes</member></values></trsum></type>";
    if ($period == "custom") {
        $report_period = "<start-time>" . $ConnStart . "</start-time><end-time>" . $ConnEnd . "</end-time>";
    } else {
        $report_period = "<period>" . $period . "</period>";
    }

    $report_top = "<topn>500</topn>";
    #$query="<query>( rule eq '".$rulename."' ) AND (app neq 'incomplete') AND (app neq 'insufficient-data')</query>";
    if ($dg_query_all != "") {
//        $query = "<query>(( rule eq '" . $rulename . "' ) AND (app neq 'incomplete') AND (app neq 'insufficient-data'))  AND ".$dg_query_all."</query>";
        $query = "<query>(( rule eq '" . $rulename . "' ) )  AND " . $dg_query_all . "</query>";
    } else {
//        $query = "<query>( rule eq '" . $rulename . "' ) AND (app neq 'incomplete') AND (app neq 'insufficient-data')</query>";
        $query = "<query>( rule eq '" . $rulename . "' ) </query>";
    }
    $cmd = urlencode($report . $report_period . $report_top . $query);
    $array = array();
    if ($api_key != "") {
        //$timeout = 120;
        //$devicePath = $pan_hostname . "/api";
        if ($target == "") {

            $cmd = "&cmd=".$cmd;

            /*$datatopost = array(
                "type" => "report",
                "reporttype" => "dynamic",
                "key" => $api_key,
                "reportname" => "custom-dynamic-report",
                "cmd" => $cmd,
                "async" => "no"
            );*/
        } else {

            $cmd = "&cmd=".$cmd."&target=".$target;

            /*$datatopost = array(
                "type" => "report",
                "reporttype" => "dynamic",
                "key" => $api_key,
                "reportname" => "custom-dynamic-report",
                "cmd" => $cmd,
                "target" => $target,
                "async" => "no"
            );*/
        }

        $devicePath = "https://" . $pan_hostname . ":". $port . "/api?type=report&async=no&reporttype=dynamic&reportname=custom-dynamic-report".$cmd;

        checkFolderExists(USERSPACE_PATH . "/devices/");
        $debugapi = USERSPACE_PATH . "/devices/debug.txt";
        $curl_log = fopen($debugapi, 'a+');
        //$url0 = $devicePath;
        //$url = '<a href="' . $url0 . '" target=_blank>' . $url0 . '</a><br>';
        //fwrite($curl_log, $url);

        // Custom headers to be added
        $headers = array(
            'X-PAN-KEY: ' . $api_key,
            'Expect:'
        );
        curl_setopt($tuCurl, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($tuCurl, CURLOPT_URL, $devicePath);
        curl_setopt($tuCurl, CURLOPT_TIMEOUT, 400000); // number of seconds prior to a timeout
        curl_setopt($tuCurl, CURLOPT_VERBOSE, DEVICE_DEBUG_CONNECTION_ENABLED==1);
        curl_setopt($tuCurl, CURLOPT_STDERR, $curl_log);
        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($tuCurl, CURLOPT_RETURNTRANSFER, true);

        $tuData = curl_exec($tuCurl);
        $line = curl_multi_getcontent($tuCurl);

        //echo "Line: " .$line. "\n";

        fclose($curl_log);

        if ($line != "") {
            $xml = simplexml_load_string($line);
            $entry = $xml->xpath("//entry");
            foreach ($entry as $key => $value) {
                if ($value->srcuser == "") {
                    $value->srcuser = "unknown";
                }
                $name_srcuser = addslashes($value->srcuser);
                $array[] = "('$source', '$vsys', '$rule_lid', '$name_srcuser', '$value->bytes', '$value->sessions', NOW())";
            }
            return $array;
        } else {
            return $array;
        }
    }

}

function get_dynamic_report_usersbyrule_panorama($ConnVsys, $tuCurl, $pan_hostname, $api_key, $vsys, $serial, $period, $port, $source, $rulename, $rule_lid, $ConnStart, $ConnEnd, $dg_query_all, $target)
{
    $report = "<type><trsum><aggregate-by><member>srcuser</member></aggregate-by><values><member>sessions</member><member>bytes</member></values></trsum></type>";
    if ($period == "custom") {
        $report_period = "<start-time>" . $ConnStart . "</start-time><end-time>" . $ConnEnd . "</end-time>";
    } else {
        $report_period = "<period>" . $period . "</period>";
    }
    $report_top = "<topn>500</topn>";
    #$query = "<query>(serial eq '" . $serial . "') and (vsys eq '" . $vsys . "') AND ( rule eq '" . $rulename . "' ) AND (app neq 'incomplete') AND (app neq 'insufficient-data')</query>";
    if ($dg_query_all != "") {
//        $query = "<query>(( rule eq '" . $rulename . "' ) AND (app neq 'incomplete') AND (app neq 'insufficient-data'))  AND ".$dg_query_all."</query>";
        $query = "<query>(( rule eq '" . $rulename . "' ) )  AND " . $dg_query_all . "</query>";
    } else {
//        $query = "<query>( rule eq '" . $rulename . "' ) AND (app neq 'incomplete') AND (app neq 'insufficient-data')</query>";
        $query = "<query>( rule eq '" . $rulename . "' ) </query>";
    }
    $cmd = urlencode($report . $report_period . $report_top . $query);
    $array = array();
    if ($api_key != "") {
        /*$timeout = 120;
        $devicePath = $pan_hostname . "/api";
        $datatopost = array(
            "type" => "report",
            "reporttype" => "dynamic",
            "key" => $api_key,
            "report-name" => "custom-dynamic-report",
            "cmd" => $cmd
        );*/
        $devicePath = "https://" . $pan_hostname . ":". $port . "/api?type=report&reporttype=dynamic&reportname=custom-dynamic-report&cmd=".$cmd;
        checkFolderExists(USERSPACE_PATH . "/devices/");
        $debugapi = USERSPACE_PATH . "/devices/debug.txt";
        $curl_log = fopen($debugapi, 'a+');

        //$url0 = $devicePath;
        //$url = '<a href="' . $url0 . '" target=_blank>' . $url0 . '</a><br>';
        //fwrite($curl_log, $url);

        // Custom headers to be added
        $headers = array(
            'X-PAN-KEY: ' . $api_key,
            'Expect:'
        );
        curl_setopt($tuCurl, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($tuCurl, CURLOPT_URL, $devicePath);
        curl_setopt($tuCurl, CURLOPT_TIMEOUT, 400000); // number of seconds prior to a timeout
        curl_setopt($tuCurl, CURLOPT_VERBOSE, DEVICE_DEBUG_CONNECTION_ENABLED==1);
        curl_setopt($tuCurl, CURLOPT_STDERR, $curl_log);
        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($tuCurl, CURLOPT_RETURNTRANSFER, true);

        $tuData = curl_exec($tuCurl);
        $line = curl_multi_getcontent($tuCurl);
        $xml = simplexml_load_string($line);
        $arr = $xml->attributes();

        if ($arr["status"] == "success") {
            $job = $xml->result->job;
            if ($job != "") {
                $finish = FALSE;
                //sleep(2);

                while ($finish == FALSE) {
                    //$timeout = 120;
                    //$devicePath = $pan_hostname . "/api";
                    /*$datatopost = array(
                        "type" => "report",
                        "action" => "get",
                        "key" => $api_key,
                        "job-id" => $job
                    );*/

                    $devicePath = "https://" . $pan_hostname . ":". $port . "/api?type=report&action=get&job-id=".$job;
                    // Custom headers to be added
                    $headers = array(
                        'X-PAN-KEY: ' . $api_key
                    );
                    curl_setopt($tuCurl, CURLOPT_HTTPHEADER, $headers);
                    curl_setopt($tuCurl, CURLOPT_URL, $devicePath);
                    curl_setopt($tuCurl, CURLOPT_TIMEOUT, 400000); // number of seconds prior to a timeout
                    curl_setopt($tuCurl, CURLOPT_VERBOSE, DEVICE_DEBUG_CONNECTION_ENABLED==1);
                    curl_setopt($tuCurl, CURLOPT_STDERR, $curl_log);
                    curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, false);
                    curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, false);
                    curl_setopt($tuCurl, CURLOPT_RETURNTRANSFER, true);
                    $tuData2 = curl_exec($tuCurl);
                    $line2 = curl_multi_getcontent($tuCurl);
                    $xmlcheck = simplexml_load_string($line2);
                    $status = $xmlcheck->result->job->status;
                    if ($status == "FIN") {
                        $finish = TRUE;
                    } else {
                        sleep(2);
                    }
                }
                $xml = simplexml_load_string($line2);
                $entry = $xml->xpath("//entry");
                foreach ($entry as $key => $value) {
                    if ($value->srcuser == "") {
                        $value->srcuser = "unknown";
                    }
                    $name_srcuser = addslashes($value->srcuser);
                    $array[] = "('$source', '$vsys', '$rule_lid', '$name_srcuser', '$value->bytes', '$value->sessions', NOW())";
                }
                if (isset($array)) {
                    return $array;
                }
            }
        }
    }
}

function get_dynamic_report_usersbyrule_pa7000($tuCurl, $pan_hostname, $api_key, $vsys, $serial, $period, $port, $source, $rulename, $rule_lid, $ConnStart, $ConnEnd, $dg_query_all, $target)
{
    $report = "<type><trsum><aggregate-by><member>srcuser</member></aggregate-by><values><member>sessions</member><member>bytes</member></values></trsum></type>";
    if ($period == "custom") {
        $report_period = "<start-time>" . $ConnStart . "</start-time><end-time>" . $ConnEnd . "</end-time>";
    } else {
        $report_period = "<period>" . $period . "</period>";
    }
    $report_top = "<topn>500</topn>";
    #$query = "<query>( rule eq '" . $rulename . "' ) AND (app neq 'incomplete') AND (app neq 'insufficient-data') AND (app neq 'non-syn-tcp')</query>";
    if ($dg_query_all != "") {
//        $query = "<query>(( rule eq '" . $rulename . "' ) AND (app neq 'incomplete') AND (app neq 'insufficient-data'))  AND ".$dg_query_all."</query>";
        $query = "<query>(( rule eq '" . $rulename . "' ) )  AND " . $dg_query_all . "</query>";
    } else {
//        $query = "<query>( rule eq '" . $rulename . "' ) AND (app neq 'incomplete') AND (app neq 'insufficient-data')</query>";
        $query = "<query>( rule eq '" . $rulename . "' ) </query>";
    }
    $cmd = urlencode($report . $report_period . $report_top . $query);
    $array = array();
    if ($api_key != "") {
        //$timeout = 120;
        //$devicePath = $pan_hostname . "/api";
        if ($target == "") {
            $cmd = "&cmd=".$cmd;
            /*$datatopost = array(
                "type" => "report",
                "reporttype" => "dynamic",
                "key" => $api_key,
                "report-name" => "custom-dynamic-report",
                "cmd" => $cmd,
                "async" => "yes"
            );*/
        } else {
            $cmd = "&cmd=".$cmd."&target=".$target;
            /*$datatopost = array(
                "type" => "report",
                "reporttype" => "dynamic",
                "key" => $api_key,
                "report-name" => "custom-dynamic-report",
                "cmd" => $cmd,
                "target" => $target,
                "async" => "yes"
            );*/
        }

        $devicePath = "https://" . $pan_hostname . ":". $port . "/api?type=report&async=yes&reporttype=dynamic&reportname=custom-dynamic-report".$cmd;

        checkFolderExists(USERSPACE_PATH . "/devices/");
        $debugapi = USERSPACE_PATH . "/devices/debug.txt";
        $curl_log = fopen($debugapi, 'a+');

        //$url0 = $devicePath;
        //$url = '<a href="' . $url0 . '" target=_blank>' . $url0 . '</a><br>';
        //fwrite($curl_log, $url);

        // Custom headers to be added
        $headers = array(
            'X-PAN-KEY: ' . $api_key,
            'Expect:'
        );
        curl_setopt($tuCurl, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($tuCurl, CURLOPT_URL, $devicePath);
        curl_setopt($tuCurl, CURLOPT_TIMEOUT, 400000); // number of seconds prior to a timeout
        curl_setopt($tuCurl, CURLOPT_VERBOSE, DEVICE_DEBUG_CONNECTION_ENABLED==1);
        curl_setopt($tuCurl, CURLOPT_STDERR, $curl_log);
        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($tuCurl, CURLOPT_RETURNTRANSFER, true);

        $tuData = curl_exec($tuCurl);
        $line = curl_multi_getcontent($tuCurl);
        $xml = simplexml_load_string($line);
        $arr = $xml->attributes();

        if ($arr["status"] == "success") {
            $job = $xml->result->job;
            if ($job != "") {
                $finish = FALSE;
                //sleep(2);

                while ($finish == FALSE) {
                    //$timeout = 120;
                    //$devicePath = $pan_hostname . "/api";
                    if ($target == "") {
                        /*$datatopost = array(
                            "type" => "report",
                            "action" => "get",
                            "key" => $api_key,
                            "job-id" => $job
                        );*/
                    } else {
                        /*$datatopost = array(
                            "type" => "report",
                            "action" => "get",
                            "key" => $api_key,
                            "job-id" => $job,
                            "target" => $target
                        );*/
                        $target='&target='.$target;
                    }

                    $devicePath = "https://" . $pan_hostname . ":". $port . "/api?type=report&action=get&job-id=".$job.$target;

                    // Custom headers to be added
                    $headers = array(
                        'X-PAN-KEY: ' . $api_key
                    );
                    curl_setopt($tuCurl, CURLOPT_HTTPHEADER, $headers);
                    curl_setopt($tuCurl, CURLOPT_URL, $devicePath);
                    curl_setopt($tuCurl, CURLOPT_TIMEOUT, 400000); // number of seconds prior to a timeout
                    curl_setopt($tuCurl, CURLOPT_VERBOSE, DEVICE_DEBUG_CONNECTION_ENABLED==1);
                    curl_setopt($tuCurl, CURLOPT_STDERR, $curl_log);
                    curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, false);
                    curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, false);
                    curl_setopt($tuCurl, CURLOPT_RETURNTRANSFER, true);
                    $tuData2 = curl_exec($tuCurl);
                    $line2 = curl_multi_getcontent($tuCurl);
                    $xmlcheck = simplexml_load_string($line2);
                    $status = $xmlcheck->result->job->status;
                    if ($status == "FIN") {
                        $finish = TRUE;
                    } else {
                        sleep(2);
                    }
                }
                $xml = simplexml_load_string($line2);
                $entry = $xml->xpath("//entry");
                foreach ($entry as $key => $value) {
                    if ($value->srcuser == "") {
                        $value->srcuser = "unknown";
                    }
                    $name_srcuser = addslashes($value->srcuser);
                    $array[] = "('$source', '$vsys', '$rule_lid', '$name_srcuser', '$value->bytes', '$value->sessions', NOW())";
                }
                if (isset($array)) {
                    return $array;
                }
            }
        }
    }
}

//function get_dynamic_report_appsbyrule_x50_panorama($ConnVsys, $tuCurl, $pan_hostname, $api_key, $vsys, $serial, $period, $port, $source, $rules50, $rule_lid)
//{
//    $report = "<type><panorama-traffic><aggregate-by><member>app</member><member>dport</member><member>proto</member></aggregate-by><values><member>bytes</member><member>packets</member></values></panorama-traffic></type>";
//    $report_period = "<period>" . $period . "</period>";
//    $report_top = "<topn>500</topn>";
////    $query = "<query>(serial eq '" . $serial . "') and (vsys eq '" . $vsys . "') AND ( " . $rules50 . " ) AND (app neq 'incomplete') AND (app neq 'insufficient-data')</query>";
//    $query = "<query>(serial eq '" . $serial . "') and (vsys eq '" . $vsys . "') AND ( " . $rules50 . " ) </query>";
//    $cmd = $report . $report_period . $report_top . $query;
//    $array = array();
//    if ($api_key != "") {
//        $timeout = 120;
//        $devicePath = $pan_hostname . "/api";
//        $datatopost = array(
//            "type" => "report",
//            "reporttype" => "dynamic",
//            "key" => $api_key,
//            "report-name" => "custom-dynamic-report",
//            "cmd" => $cmd
//        );
//
//        curl_setopt($tuCurl, CURLOPT_URL, "https://$devicePath");
//        curl_setopt($tuCurl, CURLOPT_PORT, $port);
//        curl_setopt($tuCurl, CURLOPT_VERBOSE, DEVICE_DEBUG_CONNECTION_ENABLED==1);
//        curl_setopt($tuCurl, CURLOPT_HEADER, 0);
//        curl_setopt($tuCurl, CURLOPT_POST, 1);
//        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, 0);
//        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, 0);
//        curl_setopt($tuCurl, CURLOPT_RETURNTRANSFER, 1);
//        curl_setopt($tuCurl, CURLOPT_HTTPHEADER, array('Expect:'));
//        curl_setopt($tuCurl, CURLOPT_POSTFIELDS, $datatopost);
//        curl_setopt($tuCurl, CURLOPT_TIMEOUT, 400000);
//        $tuData = curl_exec($tuCurl);
//        $line = curl_multi_getcontent($tuCurl);
//        $xml = simplexml_load_string($line);
//        $arr = $xml->attributes();
//
//        if ($arr["status"] == "success") {
//            $job = $xml->result->job;
//            if ($job != "") {
//                $finish = FALSE;
//                //sleep(2);
//
//                while ($finish == FALSE) {
//                    /*$timeout = 120;
//                    $devicePath = $pan_hostname . "/api";
//                    $datatopost = array(
//                        "type" => "report",
//                        "action" => "get",
//                        "key" => $api_key,
//                        "job-id" => $job
//                    );*/
//                    $devicePath = "https://" . $pan_hostname . ":". $port . "/api?type=report&action=get&job-id".$job;
//
//                    // Custom headers to be added
//                    $headers = array(
//                        'X-PAN-KEY: ' . $api_key
//                    );
//                    curl_setopt($tuCurl, CURLOPT_HTTPHEADER, $headers);
//                    curl_setopt($tuCurl, CURLOPT_URL, $devicePath);
//                    curl_setopt($tuCurl, CURLOPT_TIMEOUT, 400000); // number of seconds prior to a timeout
//                    curl_setopt($tuCurl, CURLOPT_VERBOSE, DEVICE_DEBUG_CONNECTION_ENABLED==1);
//                    curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, false);
//                    curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, false);
//                    curl_setopt($tuCurl, CURLOPT_RETURNTRANSFER, true);
//                    $tuData2 = curl_exec($tuCurl);
//                    $line2 = curl_multi_getcontent($tuCurl);
//                    $xmlcheck = simplexml_load_string($line2);
//                    $status = $xmlcheck->result->job->status;
//                    if ($status == "FIN") {
//                        $finish = TRUE;
//                    } else {
//                        sleep(2);
//                    }
//                }
//                $xml = simplexml_load_string($line2);
//                $entry = $xml->xpath("//entry");
//                foreach ($entry as $key => $value) {
//                    if ($value->app != "") {
//                        #search rule_lid by $value->rule
//                        $array[] = "('$source', '$ConnVsys', '$rule_lid', '$value->app', '$value->dport', '$value->bytes', '$value->packets','$value->proto')";
//                    }
//                }
//                if (isset($array)) {
//                    return $array;
//                }
//            }
//        }
//    }
//}

function get_dynamic_report_user_id_groups($tuCurl, $pan_hostname, $api_key, $vsys, $port, $target)
{

    if ($api_key != "") {
        //$timeout = 120;
        //$devicePath = $pan_hostname . "/api";
        $cmd="<show><user><group><list></list></group></user></show>";
        if ($target == "") {
            $cmd = "&cmd=".$cmd;
            /*$datatopost = array(
                "type" => "op",
                "key" => $api_key,
                "cmd" => "<show><user><group><list></list></group></user></show>"
            );*/
        } else {
            $cmd = "&cmd=".$cmd."&target=".$target;
            /*$datatopost = array(
                "type" => "op",
                "key" => $api_key,
                "cmd" => "<show><user><group><list></list></group></user></show>",
                "target" => $target
            );*/
        }

        $devicePath = "https://" . $pan_hostname . ":". $port . "/api?type=op".$cmd;

        checkFolderExists(USERSPACE_PATH . "/devices/");
        $debugapi = USERSPACE_PATH . "/devices/debug.txt";
        $curl_log = fopen($debugapi, 'a+');

        //$url0 = $devicePath;
        //$url = '<a href="' . $url0 . '" target=_blank>' . $url0 . '</a><br>';

        //fwrite($curl_log, $url);

        // Custom headers to be added
        $headers = array(
            'X-PAN-KEY: ' . $api_key,
            'Expect:'
        );
        curl_setopt($tuCurl, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($tuCurl, CURLOPT_URL, $devicePath);
        curl_setopt($tuCurl, CURLOPT_TIMEOUT, 400000); // number of seconds prior to a timeout
        curl_setopt($tuCurl, CURLOPT_VERBOSE, DEVICE_DEBUG_CONNECTION_ENABLED==1);
        curl_setopt($tuCurl, CURLOPT_STDERR, $curl_log);
        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($tuCurl, CURLOPT_RETURNTRANSFER, true);

        $tuData = curl_exec($tuCurl);
        $line = curl_multi_getcontent($tuCurl);

        $xml = simplexml_load_string($line);
        #$xml0=$xml->xpath("//result");

        fclose($curl_log);

        return $xml->result;

    }

}

function get_dynamic_report_user_id_groups_members($tuCurl, $pan_hostname, $api_key, $vsys, $port, $group, $target)
{

    $array = array();
    if ($api_key != "") {
        //$timeout = 120;
        //$devicePath = $pan_hostname . "/api";
        $cmd="<show><user><group><name>$group</name></group></user></show>";
        if ($target == "") {
            $cmd = "&cmd=".$cmd;
            /*$datatopost = array(
                "type" => "op",
                "key" => $api_key,
                "cmd" => "<show><user><group><name>$group</name></group></user></show>"
            );*/

        } else {
            $cmd = "&cmd=".$cmd."&target=".$target;
            /*$datatopost = array(
                "type" => "op",
                "key" => $api_key,
                "cmd" => "<show><user><group><name>$group</name></group></user></show>",
                "target" => $target
            );*/
        }
        $devicePath = "https://" . $pan_hostname . ":". $port . "/api?type=op".$cmd;
        checkFolderExists(USERSPACE_PATH . "/devices/");
        $debugapi = USERSPACE_PATH . "/devices/debug.txt";
        $curl_log = fopen($debugapi, 'a+');


        //$url0 = $devicePath;
        //$url = '<a href="' . $url0 . '" target=_blank>' . $url0 . '</a><br>';
        //fwrite($curl_log, $url);
        $fields_string = array();

        // Custom headers to be added
        $headers = array(
            'X-PAN-KEY: ' . $api_key,
            'Expect:'
        );
        curl_setopt($tuCurl, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($tuCurl, CURLOPT_URL, $devicePath);
        curl_setopt($tuCurl, CURLOPT_TIMEOUT, 400000); // number of seconds prior to a timeout
        curl_setopt($tuCurl, CURLOPT_VERBOSE, DEVICE_DEBUG_CONNECTION_ENABLED==1);
        curl_setopt($tuCurl, CURLOPT_STDERR, $curl_log);
        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($tuCurl, CURLOPT_RETURNTRANSFER, true);

        $tuData = curl_exec($tuCurl);
        $line = curl_multi_getcontent($tuCurl);

        $xml = simplexml_load_string($line);
        #$xml0=$xml->xpath("//result");

        fclose($curl_log);

        return $xml->result;


    }

}

//function send_api_call(STRING $projectName, STRING $ids)
//{
//    global $app;
//    ini_set('max_execution_time', 10000);
//    ini_set("memory_limit", "1000M");
//    $isProxy = false;
//
////    global $pandb;
//    $projectdb = selectDatabase($projectName);
//
//    //Get selected devices
//    $user = $app->container->sentinel->getUser();
//    $userID = $user->id;
//    $project = $app->project->where('name', '=', $projectName)->get()->first();
//    $userSettings = $app->userSettings->where('user_id', '=', $userID)->where('project_id', '=', $project->id)->first();
//    $devices = explode(',', $userSettings->selectedDevices);
//
//    foreach ($devices as $device) {
//        if ($deviceEntity = $app->device->where('id', '=', $device)->get()->first()) {
////            echo $deviceEntity->devicename;
////    $getDevice = $pandb->query("SELECT hostname,port,serial,ispanorama,api_key,management FROM devices WHERE id='$device';");
////    if ($getDevice->num_rows==1){
////        $deviceData = $getDevice->fetch_assoc();
//
////        $api_key = $deviceData['api_key'];
//            $managementSerial = $deviceEntity->management;
//            if ($managementSerial != "") {
//                if ($panoramaEntity = $app->device->where('serial', '=', $managementSerial)->get()->first()) {
//                    $hostname = $panoramaEntity->hostname;
//                    $serial = $panoramaEntity->serial;
//                    $port = $panoramaEntity->port;
//                    if ($port == "") {
//                        $port = "443";
//                    }
//                    $isProxy = true;
//                    $api_key = getApiKey($project->name, $panoramaEntity->serial, $userID);
//                    if (!$api_key['code']) {
//                        update_progress($project->name, '1.00', 'Done with errors');
//                        echo json_encode(array('success' => false, 'msg' => '(Device ' . $deviceEntity->hostname . ', ' . $managementSerial . ') You do not have access to the device. Check with your Admin.'));
////                        exit;
//                        continue;
//                    }
//                } else {
//                    update_progress($project->name, '1.00', 'Failed retrieving the API KEY.');
//                    echo json_encode(array("success" => false));
////                    exit(0);
//                    continue;
//                }
//            } else {
//                $hostname = $deviceEntity->hostname;
//                $serial = $deviceEntity->serial;
//                $port = $deviceEntity->port;
//                if ($port == "") {
//                    $port = "443";
//                }
//                $api_key = getApiKey($project->name, $deviceEntity->serial, $userID);
//                if (!$api_key['code']) {
//                    update_progress($project->name, '1.00', 'Done with errors');
//                    echo json_encode(array('success' => false, 'msg' => '(Device ' . $deviceEntity->hostname . ', ' . $deviceEntity->serial . ') You do not have access to the device. Check with your Admin.'));
////                    exit;
//                    continue;
//                }
//            }
//
//
//            if ($ids == "") {
//                $getCalls = $projectdb->query("SELECT id,xpath,action,xml_final,whereto,dst FROM output_mapping ORDER BY id ASC;");
//            } else {
//                $getCalls = $projectdb->query("SELECT id,xpath,action,xml_final,whereto,dst FROM output_mapping WHERE id IN ($ids) ORDER BY id ASC;");
//            }
//            $allrules = $getCalls->num_rows;
//            $x = 0;
//            add_progress($project->name, '0.00', 'Reading API Calls');
//
//            if ($getCalls->num_rows > 0) {
//                # Send the API CALL to the DEVICE
//                $devicePath = $hostname . "/api";
//                $tuCurl = curl_init();
//                while ($getCallsData = $getCalls->fetch_assoc()) {
//                    $x++;
//                    $id = $getCallsData['id'];
//                    $xpath = $getCallsData['xpath'];
//                    $action = $getCallsData['action'];
//                    $element = $getCallsData['xml_final'];
//
//                    if ($isProxy == true) {
//                        if ($action == "move") {
//                            $whereto = $getCallsData['whereto'];
//                            $dst = $getCallsData['dst'];
//                            $datatopost = array(
//                                "type" => "config",
//                                "action" => $action,
//                                "key" => $api_key,
//                                "target" => $serial,
//                                "xpath" => $xpath,
//                                "where" => $whereto,
//                                "dst" => $dst
//                            );
//                        } else {
//                            $datatopost = array(
//                                "type" => "config",
//                                "action" => $action,
//                                "key" => $api_key,
//                                "target" => $serial,
//                                "xpath" => $xpath,
//                                "element" => $element
//                            );
//                        }
//                    } else {
//                        if ($action == "move") {
//                            $whereto = $getCallsData['whereto'];
//                            $dst = $getCallsData['dst'];
//                            $datatopost = array(
//                                "type" => "config",
//                                "action" => $action,
//                                "key" => $api_key,
//                                "xpath" => $xpath,
//                                "where" => $whereto,
//                                "dst" => $dst
//                            );
//                        } else {
//                            $datatopost = array(
//                                "type" => "config",
//                                "action" => $action,
//                                "key" => $api_key,
//                                "xpath" => $xpath,
//                                "element" => $element
//                            );
//                        }
//                    }
//                    $debugapi = USERSPACE_PATH . "/devices/debug.txt";
//                    $curl_log = fopen($debugapi, 'a+');
//                    foreach ($datatopost as $key1 => $value1) {
//                        if ($key1 != "key") {
////                    if ($key1=="key"){
////
////                    }
////                    else{
//                            $fields_string[] = $key1 . '=' . $value1;
//                        }
//                    }
//                    $url0 = "https://" . $devicePath . "?" . implode("&", $fields_string);
//                    $url = '<a href="' . $url0 . '" target=_blank>' . $url0 . '</a><br>';
//                    fwrite($curl_log, $url);
//                    $fields_string = array();
//
//                    curl_setopt($tuCurl, CURLOPT_URL, "https://$devicePath");
//                    curl_setopt($tuCurl, CURLOPT_PORT, $port);
//                    curl_setopt($tuCurl, CURLOPT_STDERR, $curl_log);
//                    curl_setopt($tuCurl, CURLOPT_VERBOSE, DEVICE_DEBUG_CONNECTION_ENABLED==1);
//                    curl_setopt($tuCurl, CURLOPT_HEADER, 0);
//                    curl_setopt($tuCurl, CURLOPT_POST, 1);
//                    curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, 0);
//                    curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, 0);
//                    curl_setopt($tuCurl, CURLOPT_RETURNTRANSFER, 1);
//                    curl_setopt($tuCurl, CURLOPT_CONNECTTIMEOUT, 15);
//                    curl_setopt($tuCurl, CURLOPT_POSTFIELDS, $datatopost);
//                    curl_setopt($tuCurl, CURLOPT_TIMEOUT, 0);
//                    $tuData = curl_exec($tuCurl);
//
//                    if (curl_errno($tuCurl) == 28) {
//                        echo json_encode(array('success' => false, 'msg' => '(Device ' . $deviceEntity->hostname . ', ' . $deviceEntity->serial . ') The connection with the device cannot be established.'));
////                        exit(0);
//                        continue;
//                    } else {
//                        $line = curl_multi_getcontent($tuCurl);
//
//                        $newline = str_replace(array("<response status=\"success\"><result>", "</result></response>"), "", $line);
//                        $xml = simplexml_load_string($newline);
//                        if (preg_match("/Not authorized to access/i", $newline)) {
//                            echo json_encode(array('success' => false, 'msg' => 'You do not have access to the device'));
////                            exit;
//                            continue;
//                        }
//                        if (preg_match("/Invalid credentials./i", $newline)) {
//                            $message['code'] = false;
//                            $message['msg'] = $newline;
//                            return $message;
//                        } elseif (preg_match("/Authentication failed: Invalid username or password/i", $newline)) {
//                            echo json_encode(array('success' => false, 'msg' => '(Device ' . $deviceEntity->hostname . ', ' . $deviceEntity->serial . ') Authentication failed: Invalid username or password'));
////                            exit;
//                            continue;
//                        } else {
//                            $arr = $xml->attributes();
//                            if ($arr["status"] == "success") {
//                                $newline = addslashes($newline);
//                                $projectdb->query("UPDATE output_mapping SET output='$newline',state='success' WHERE id='$id';");
//
//                                //Update modified a '0'
////                            $tables_to_modify = array("address", "address_groups_id", "shared_address", "shared_address_groups_id",
////                                "services", "services_groups_id", "shared_services", "shared_services_groups_id",
////                                "applications", "applications_filters", "applications_groups", "shared_applications", "shared_applications_filters", "shared_applications_groups",
////                                "appoverride_rules", "external_list", "shared_external_list","interface_management_profile",
////                                "interfaces", "log_settings", "shared_log_settings", "nat_rules", "profiles", "shared_profiles", "profiles_groups", "shared_profiles_groups",
////                                "regions", "shared_regions","reports", "response_pages", "shared_response_pages","schedules", "shared_schedules","security_rules",
////                                "tag", "shared_tag", "routes_static","zones");
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
////                                if($table_name_mod == "shared_address_groups"){
////                                    $table_name_mod = "shared_address_groups_id";
////                                }
//                                    if ($table_name_mod == "services_groups") {
//                                        $table_name_mod = "services_groups_id";
//                                    }
////                                if($table_name_mod == "shared_services_groups"){
////                                    $table_name_mod = "shared_services_groups_id";
////                                }
//
//                                    if (in_array($table_name_mod, $tables_to_modify)) {
//                                        $getAlterTable = $projectdb->query("UPDATE $table_name_mod SET modified = '2';");
//                                    }
//                                }
//
//                            } else {
//                                $newline = addslashes($newline);
//                                $message = $xml->msg->asXML();
//                                $projectdb->query("UPDATE output_mapping SET output='$newline',state='fail' WHERE id='$id';");
//                            }
//                        }
//                    }
//                    $progress = $x / $allrules;
//                    if ($progress == 1) {
//                        update_progress($project->name, '1.00', 'Done.');
//                    } else {
//                        update_progress($project->name, $progress, 'Sending Request ' . $x . ' from ' . $allrules);
//                    }
//                }
//                curl_close($tuCurl);
//                fclose($curl_log);
//            }
//            echo json_encode(array("success" => true, 'msg' => '(Device ' . $deviceEntity->hostname . ') Completed successfully.'));
//        }
//    }
//    update_progress($project->name, '1.00', 'Done.');
//}

# rule-hits Reports
function get_dynamic_report_rulehits_panorama($ConnVsys, $tuCurl, $pan_hostname, $api_key, $vsys, $serial, $period, $port, $source, $rulename, $rule_lid, $ConnStart, $ConnEnd, $dg_query_all, $dg_query_device_group, $target, $ConnTop)
{

    $array = array();

    if ($api_key != "") {
        //$timeout = 120;
        //$devicePath = $pan_hostname . "/api";
        $cmd= "&cmd=" . urlencode('<show><rule-use><rule-base>security</rule-base><device-group>' . $vsys . '</device-group><type>used</type></rule-use></show>');
        if ($target == "") {
            /*$datatopost = array(
                "type" => "op",
                "cmd" => '<show><rule-use><rule-base>security</rule-base><device-group>' . $vsys . '</device-group><type>used</type></rule-use></show>',
                "key" => $api_key,
                "async" => "yes"
            );*/
        } else {
            $cmd .= "&target=" . $target;
            /*$datatopost = array(
                "type" => "op",
                "cmd" => '<show><rule-use><rule-base>security</rule-base><device-group>' . $vsys . '</device-group><type>used</type></rule-use></show>',
                "key" => $api_key,
                "target" => $target,
                "async" => "yes"
            );*/
        }

        $devicePath = "https://" . $pan_hostname . ":". $port . "/api?type=op&async=yes".$cmd;

        checkFolderExists(USERSPACE_PATH . "/devices/");
        $debugapi = USERSPACE_PATH . "/devices/debug.txt";

        $curl_log = fopen($debugapi, 'a+');
        //$url0 = $devicePath;
        //$url = '<a href="' . $url0 . '" target=_blank>' . $url0 . '</a><br>';
        //fwrite($curl_log, $url);


        /*$params = [
            'url' => "https://$devicePath",
            'stderr' => $debugapi,
            'port' => $port,
            'postfields' => $datatopost,
            'timeout' => 400000,
            'httpheader' => array('Expect:'),
        ];


        $curlObj = new CurlConnect($tuCurl, $params);
        $tuData = $curlObj->exec();*/

        // Custom headers to be added
        $headers = array(
            'X-PAN-KEY: ' . $api_key,
            'Expect:'
        );
        curl_setopt($tuCurl, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($tuCurl, CURLOPT_URL, $devicePath);
        curl_setopt($tuCurl, CURLOPT_TIMEOUT, 400000); // number of seconds prior to a timeout
        curl_setopt($tuCurl, CURLOPT_VERBOSE, DEVICE_DEBUG_CONNECTION_ENABLED==1);
        curl_setopt($tuCurl, CURLOPT_STDERR, $curl_log);
        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($tuCurl, CURLOPT_RETURNTRANSFER, true);

        $tuData = curl_exec($tuCurl);

        fclose($curl_log);

        $line = curl_multi_getcontent($tuCurl);
        $xml = simplexml_load_string($line);

        $arr = $xml->attributes();

        if ($arr["status"] == "success") {
            $job = $xml->result->job;
            if ($job != "") {
                $finish = FALSE;
                //sleep(2);
                $cancel = 150;
                while ($finish == FALSE) {
                    $timeout = 120;
                    $devicePath = $pan_hostname . "/api";
                    $datatopost = array(
                        "type" => "report",
                        "action" => "get",
                        "key" => $api_key,
                        "job-id" => $job
                    );
                    $devicePath = "https://" . $pan_hostname . ":". $port . "/api?type=report&action=get&job-id=".$job;
                    // Custom headers to be added
                    $headers = array(
                        'X-PAN-KEY: ' . $api_key
                    );
                    curl_setopt($tuCurl, CURLOPT_HTTPHEADER, $headers);
                    curl_setopt($tuCurl, CURLOPT_URL, $devicePath);
                    curl_setopt($tuCurl, CURLOPT_TIMEOUT, 400000); // number of seconds prior to a timeout
                    curl_setopt($tuCurl, CURLOPT_VERBOSE, DEVICE_DEBUG_CONNECTION_ENABLED==1);
                    curl_setopt($tuCurl, CURLOPT_STDERR, $curl_log);
                    curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, false);
                    curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, false);
                    curl_setopt($tuCurl, CURLOPT_RETURNTRANSFER, true);
                    $tuData2 = curl_exec($tuCurl);
                    $line2 = curl_multi_getcontent($tuCurl);
                    $xmlcheck = simplexml_load_string($line2);
                    $status = $xmlcheck->result->job->status;
                    if ($status == "FIN") {
                        $finish = TRUE;
                    } else {
                        sleep(2);
                        $cancel--;
                        if ($cancel == 0) {
                            $finish = FALSE;
                        }
                    }
                }
                $xml = simplexml_load_string($line2);
                $entry = $xml->xpath("//entry");
                foreach ($entry as $key => $value) {
                    if ($value->app != "") {
                        $array[] = "('$source', '$ConnVsys', '$rule_lid', '$value->app', '$value->dport', '$value->bytes', '$value->packets','$value->proto', NOW())";
                    }
                }
                if (isset($array)) {
                    return $array;
                }
            }
        }
        //$curlObj->close();
    }
}

function get_dynamic_report_rulehits_pa7000($tuCurl, $pan_hostname, $api_key, $vsys, $serial, $period, $port, $source, $ConnStart, $ConnEnd, $dg_query_all, $target, $ConnTop, $array_rules)
{

    $array = array();
    if ($api_key != "") {
        //$timeout = 120;
        //$devicePath = $pan_hostname . "/api";
        $cmd="&cmd=" . urlencode("<show><rule-hit-count><vsys><vsys-name><entry name='" . $vsys . "'><rule-base><entry name='security'><rules><all/></rules></entry></rule-base></entry></vsys-name></vsys></rule-hit-count></show>");
        if ($target == "") {
            /*$datatopost = array(
                "type" => "op",
                "cmd" => '<show><rule-hit-count><vsys><vsys-name><entry name="' . $vsys . '"><rule-base><entry name="security"><rules><all/></rules></entry></rule-base></entry></vsys-name></vsys></rule-hit-count></show>',
                //"cmd" => '<show><running><rule-use><hit-count><rule-base>security</rule-base><rules><all/></rules><vsys>' . $vsys . '</vsys></hit-count></rule-use></running></show>',
                "key" => $api_key,
                "async" => "yes"
            );*/
        } else {
            $cmd .= "&target=" . $target;
            /*$datatopost = array(
                "type" => "op",
                "cmd" => '<show><rule-hit-count><vsys><vsys-name><entry name="' . $vsys . '""><rule-base><entry name="security"><rules><all/></rules></entry></rule-base></entry></vsys-name></vsys></rule-hit-count></show>',
                "key" => $api_key,
                "target" => $target,
                "async" => "yes"
            );*/
        }
        $devicePath = "https://" . $pan_hostname . ":". $port . "/api?type=op&async=yes".$cmd;
        checkFolderExists(USERSPACE_PATH . "/devices/");
        $debugapi = USERSPACE_PATH . "/devices/debug.txt";
        $curl_log = fopen($debugapi, 'a+');

        //$url0 = $devicePath;
        //$url = '<a href="' . $url0 . '" target=_blank>' . $url0 . '</a><br>';
        //fwrite($curl_log, $url);


        // Custom headers to be added
        $headers = array(
            'X-PAN-KEY: ' . $api_key,
            'Expect:'
        );
        curl_setopt($tuCurl, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($tuCurl, CURLOPT_URL, $devicePath);
        curl_setopt($tuCurl, CURLOPT_TIMEOUT, 400000); // number of seconds prior to a timeout
        curl_setopt($tuCurl, CURLOPT_VERBOSE, DEVICE_DEBUG_CONNECTION_ENABLED==1);
        curl_setopt($tuCurl, CURLOPT_STDERR, $curl_log);
        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($tuCurl, CURLOPT_RETURNTRANSFER, true);

        $tuData = curl_exec($tuCurl);
        $line = curl_multi_getcontent($tuCurl);

        $xml = simplexml_load_string($line);
        $arr = $xml->attributes();

        $entry = $xml->xpath("//entry");
        unset($entry[0]);
        unset($entry[1]);

        foreach ($entry as $key => $value) {
            $rulename = $entry[$key]->attributes()->name;

            $rule_lid = array_search($rulename, $array_rules);

            if ($rule_lid != "") {
                $rulehits = $value->{'hit-count'};
                $firsthit = toDateTime(intval($value->{'first-hit-timestamp'}));
                $lastreset = toDateTime(intval($value->{'last-reset-timestamp'}));
                $lasthit = toDateTime(intval($value->{'last-hit-timestamp'}));

                $array[] = "('$source', '$vsys', '$rulename', '$rule_lid' , '$rulehits', '$lasthit', '$firsthit' , '$lastreset' ,NOW())";
            }

        }
        if (isset($array)) {
            return $array;
        }

        fclose($curl_log);
    }
}

function toDateTime($unixTimestamp)
{
    return date("Y-m-d H:m:s", $unixTimestamp);
}

?>