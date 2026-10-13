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
require_once INC_ROOT.'/libs/common/discovery/importRuleEnrichment.php';
//require_once INC_ROOT.'/libs/common/lib-objects.php';
//require_once INC_ROOT.'/libs/shared.php';

class RuleEnrichment
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

        $this->log("Action:\t\tImporting Enrichment Rules:\tvsys:\t".$this->params['vsys']."\n");

        take_snapshot_last($projectname);

        //Check if the job is cancelled
        if($this->isCancelled()){
            $this->setFailed("Import Cancelled by the user", "Import Cancelled by the user");
            return;
        }

        //echo "PASA\n";
        $message = import_rule_enrichment_all($projectname, $this->params);

        if ($message['code']==false){
            $this->setFailed("Import Failed", "Import Failed");
            return;
        }

        //check_used_objects_new();

        $this->setCompleted();

    }
}