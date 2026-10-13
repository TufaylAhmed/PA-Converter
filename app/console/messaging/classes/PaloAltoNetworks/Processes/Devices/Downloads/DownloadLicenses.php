<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 9/6/16 - 12:23
 */

class DownloadLicenses
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

        if (is_array($this->params['serial'])){
            $deviceSerials = $this->params['serial'];
        }
        else{
            $deviceSerials[] = $this->params['serial'];
        }

        $role = 'admin';

        require_once (INC_ROOT.'/libs/database.php'); //getConfigBackup will require access to $pandb
        require_once (INC_ROOT.'/libs/xmlapi.php'); //We have the getSystemInfo implementation inside

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

        $errors = array();
        $errorDev = array();

        foreach ($deviceSerials as $deviceSerial) {
            $this->log("Action:\tRetrieve\nObject:\tLicenses\nTarget:\t" . $deviceSerial . "\nKey:\t" . $role);
            //Get info from device!
            if ($deviceObj = $app->container->device->where('serial', '=', $deviceSerial)->get()->first()) {
                $success = true;
                if($deviceObj->management == '') {
                    $hostname = $deviceObj->hostname;
                    $port = $deviceObj->port;

                    $key_name = $deviceObj->serial . "_" . $role;
                    if ($key = $app->apikey->where('key_name', '=', $key_name)->get()->first()) {
                        $this->log("Connection:\tDirect");
                        //$success = getLicenses($hostname, $deviceSerial, $key->api_key, $port);
                        $success = getLicenses_Target($hostname, $deviceSerial, $key->api_key, $port,'');
                    }
                    if (!$success) {
                        $errors[] = $success;
                        $errorDev[] = $deviceSerial;
                    }

                }
                else{
                    $panorama = $deviceObj->management;
                    $this->log("Connection:\tVia $panorama");
                    $panoramaObj = $app->device->where('serial',$panorama)->get()->first();
                    $hostname = $panoramaObj->hostname;
                    $port = $panoramaObj->port;

                    $key_name = $panoramaObj->serial . "_" . $role;
                    if ($key = $app->apikey->where('key_name', '=', $key_name)->get()->first()) {
                        $success = getLicenses_Target($hostname, $panorama, $key->api_key, $port, $deviceObj->serial);
                    }
                    if (!$success) {
                        $errors[] = $success;
                        $errorDev[] = $deviceSerial;
                    }
                }
            }

            // Support
            $this->log("Action:\tRetrieve\nObject:\tSupport\nTarget:\t" . $deviceSerial . "\nKey:\t" . $role);
            //Get info from device!
            if ($deviceObj = $app->container->device->where('serial', '=', $deviceSerial)->get()->first()) {
                $success = true;
                if($deviceObj->management == '') {
                    $hostname = $deviceObj->hostname;
                    $port = $deviceObj->port;

                    $key_name = $deviceObj->serial . "_" . $role;
                    if ($key = $app->apikey->where('key_name', '=', $key_name)->get()->first()) {
                        $this->log("Connection:\tDirect");
                        //$success = getLicenses($hostname, $deviceSerial, $key->api_key, $port);
                        $success = getSupport_Target($hostname, $deviceSerial, $key->api_key, $port,'');
                    }
                    if (!$success) {
                        $errors[] = $success;
                        $errorDev[] = $deviceSerial;
                    }

                }
                else{
                    $panorama = $deviceObj->management;
                    $this->log("Connection:\tVia $panorama");
                    $panoramaObj = $app->device->where('serial',$panorama)->get()->first();
                    $hostname = $panoramaObj->hostname;
                    $port = $panoramaObj->port;

                    $key_name = $panoramaObj->serial . "_" . $role;
                    if ($key = $app->apikey->where('key_name', '=', $key_name)->get()->first()) {
                        $success = getSupport_Target($hostname, $panorama, $key->api_key, $port, $deviceObj->serial);
                    }
                    if (!$success) {
                        $errors[] = $success;
                        $errorDev[] = $deviceSerial;
                    }
                }
            }
        }
        if(count($errors) == 0){
            $this->setCompleted('');
        }
        else{
            $this->setFailed("There were problems downloading the Licenses from [".implode(',', $errorDev)."]", implode(',', $errors));
        }
    }
}