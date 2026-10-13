<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 15/6/16 - 10:41
 */

class DownloadConnectedDevices
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
        require_once (INC_ROOT.'/libs/xmlapi.php');

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
            $this->log("Action:\tRetrieve\nObject:\tConnect Devices\nTarget:\t" . $deviceSerial . "\nKey:\t" . $role);

            //Get info from device!
            if ($deviceObj = $app->container->device->where('serial', '=', $deviceSerial)->get()->first()) {
                $success = true;
                if ($deviceObj->management == '') {
                    $hostname = $deviceObj->hostname;
                    $port = $deviceObj->port;

                    $key_name = $deviceObj->serial . "_" . $role;
                    if ($key = $app->apikey->where('key_name', '=', $key_name)->get()->first()) {
                        $this->log("Connection:\tDirect");
                        $success = getPanoramaDevicesConnected($hostname, $deviceSerial, $key->api_key, $port);
                    }
                    if ($success<0) {
                        $errors[] = $success;
                        $errorDev[] = $deviceSerial;
                    }
                }
                else {
                    $panorama = $deviceObj->management;
                    $this->log("Connection:\tVia $panorama");
                    $this->log("\tAborted, not a direct connection");
                    $errors[] = getErrorCode(ERROR_ActionNotPossible);
                    $errorDev[] = $deviceSerial;
                }
            }
        }
        if (count($errors) == 0) {
            $this->setCompleted('');
        }
        else {
            $this->setFailed("There were problems downloading the list of connected devices from [".implode(',', $errorDev)."]", implode(',', $errors));
        }
    }
}