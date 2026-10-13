<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 10/6/16 - 15:45
 */

require_once INC_ROOT.'/libs/projectdb.php';
require_once INC_ROOT.'/libs/backups.php';
require_once INC_ROOT.'/libs/common/discovery/import.php';
require_once INC_ROOT.'/libs/common/lib-objects.php';
require_once INC_ROOT.'/libs/shared.php';

class discoveryImportRules
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

        $projectname = $this->params['project'];
        global $projectdb;
        global $app;

        $userID = $this->params['user_id'];

        if($user = $app->user->where('id',$userID)->where('api_key',$this->params['key'])->where('valid_til', '>',date("Y-m-d H:i:s"))->get()->first()) {
            $app->sentinel->login($user);
        }

        if(!$app->container->sentinel->check() || !isset($user)){
            $className = get_class($this);
            $this->log($className. " - Invalid Credentials to execute the process");
            $this->setFailed("Invalid Credentials to execute the process", "Export Cancelled by user invalid credentials");
            return;
        }

        $projectdb = selectDatabase($projectname);
        $source = $this->params['source'];

        $this->log("Action:\t\tImporting Discovered Rules\nConvert to Shared:\t".$this->params['shared']."\nvsys:\t".$this->params['vsys']."\nsource Density:\t".$this->params['sourceDensity']."\ndest. Density:\t".$this->params['destinationDensity']."\n");

        //Taking backup of the project in the current state
        take_snapshot_last($projectname);

        //Check if the job is cancelled
        if($this->isCancelled()){
            $this->setFailed("Report Cancelled by the user", "Report Cancelled by the user");
            return;
        }

        if ($this->params['address']=="true"){
            $message=import_discovered_address($projectname,$this->params);
        }
        if(!$message['code']) {
            $this->setFailed($message['msg'],-1);
            return;
        }

        if ($this->params['services']=="true"){
            $message=import_discovered_services($projectname,$this->params);
        }
        if(!$message['code']) {
            $this->setFailed($message['msg'],-1);
            return;
        }

        if ($this->params['rules']=="true"){
            $message=import_discovered_rules($projectname,$this->params,$this);
        }
        if(!$message['code']) {
            $this->setFailed($message['msg'],-1);
            return;
        }

        $this->setCompleted();

//        if(count($reportAPICallID) == 0) {
//            $this->setCompletedSilent('');
//        }
//        else {
//            $this->setFailedSilent("There were problems sending the API calls with ids [".implode(';', $reportAPICallID)."]", "[".implode(';', $errorAPI)."]");
//        }
    }
}