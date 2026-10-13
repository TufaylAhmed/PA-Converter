<?php
/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: 08/01/2018 11:55
 ******************************************************************************/

require_once INC_ROOT.'/libs/common/MemberObject.php';
require_once INC_ROOT.'/libs/common/lib-objects.php';
require_once INC_ROOT.'/libs/common/lib-rules.php';
require_once INC_ROOT.'/libs/projectdb.php';
require_once INC_ROOT.'/libs/shared.php';

use PaloaltoNetworks\Policy\Objects\MemberObject;

class AutoZonePolicy_NAT
    extends AbstractProcess
{

    public function __construct(ARRAY $params){
        parent::__construct($params);
    }

    public function execute(){
        //Set max execution times
        ini_set('max_execution_time', PARSER_max_execution_time);
        ini_set("memory_limit",PARSER_max_execution_memory);

        global $projectdb;
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

        $params = $this->params;
        $taskId = $params['taskId'];
        $data = $params['data'];
//        Echo "Parameters for the Autonat:";
//        print_r($data);
        $projectName = $data->project;
        $projectdb = selectDatabase($projectName);

        $vsys = $data->vsys;
        $source = $data->source;
        $vr = $data->vr;
        $template = isset($data->templateID)? $data->templateID : null;

        $ruleIds = $data->ruleIds;

        $tags = $data->tags;

        $applyNat = $data->applyNat;
        $doFrom = $data->doFrom;
        $doTo = $data->doTo;

        $this->log("Action:\t\tAutozone on NATs\n".
            "Do From:\t$doFrom\n".
            "Do To:\t\t$doTo\n".
            "Project:\t$projectName\n".
            "Source:\t\t$source\n".
            "Vsys:\t\t$vsys\n".
            "Vir.Rout:\t$vr\n".
            "Template:\t$template\n".
            "Rules:\t\t".implode(',',$ruleIds)."\n".
            "Tags:\t\t".implode(',',$tags)." ");

        $ipMapping = getIPtoZoneRouteMapping($vsys, $source, $vr, $template);
//        $ipMapping = array();


        //Check we have routing information to be able to calculate Zones
//        if(count($ipMapping['ipv4'])==0){
////            update_progress($projectName, '-1.00', 'Routing information is missing. Not possible to calculate policy Zones',$jobid);
//            $this->updateTaskStatus('Routing information is missing. Not possible to calculate policy Zones','-1','1', false);
//            return;
//        }

        if(count($ruleIds)>0) {
            $conditionIds = " AND id IN (".implode(',', $ruleIds).")";
            $conditionRelaIds = " AND rule_lid IN ('".implode(',', $ruleIds)."')";
        }
        else{
            $conditionIds ='';
            $conditionRelaIds ='';
        }

        if(count($tags)>0) {
            $partial_conditionTags = array();
            foreach ($tags as $tag){
                $partial_conditionTags[] = " (tag LIKE '$tag') ";
            }
            $conditionTags = implode(' OR ', $partial_conditionTags);
            $conditionTags = ' AND '.$conditionTags;
        }
        else{
            $conditionTags='';
        }

        if($vsys == 'all'){
            $conditionVsys = '';
        }
        else{
            $conditionVsys = " AND vsys='$vsys' ";
        }

        /***
         * COLLECT THE NAT RULES IDs
         */
        $query = "SELECT id,vsys  FROM nat_rules WHERE source='$source' $conditionVsys $conditionIds $conditionTags ORDER BY position;";
        $rules = $projectdb->query($query);
        $number_of_rules = $rules->num_rows;
        if ($number_of_rules > 0) {
            $targetRuleIds = array();
            while ($getINData = $rules->fetch_assoc()){
                $targetRuleIds[] = $getINData['id'];
                $vsysLocal=$getINData['vsys'];
            }
            fix_Nat_Policy(null, $projectName, $source, $vsysLocal, $vr, $ipMapping, $targetRuleIds, $doFrom, $doTo, $template);
        }
        else{
            $this->updateTaskStatus('No rules fit the criteria','1','1', true);
            return;
        }

        $this->updateTaskStatus('Finished.','0','1.00', true);
    }

}