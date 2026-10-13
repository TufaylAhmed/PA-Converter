<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 10/6/16 - 15:45
 */

require_once INC_ROOT.'/libs/projectdb.php';
require_once (INC_ROOT.'/libs/database.php');
require_once INC_ROOT.'/libs/backups.php';

class Rename
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

        global $projectdb;
        global $app;

        $project = $this->params['project'];
        $source = $this->params['source'];
        $ruleIdsArray = $this->params['ids'];
        $userID=$this->params['userId'];

        if(!accessControl("any", ['projectRole.'.$project.'.update'], $userID)){
            $message = array();
            $message['code'] = false;
            $message['msg'] = 'Your account does not have the rights to edit this project contents';
            return $message;
        }

        $this->log("Action:\t\tProject:\t\t".$project."\nDNS Resolver\nUserID:\t\t". $userID ."\n");

        require_once (INC_ROOT.'/libs/database.php'); //getConfigBackup will require access to $pandb
        require_once (INC_ROOT.'/libs/common/tools/tools.php');

        $projectdb = selectDatabase($project);
        $getAddress=$projectdb->query("SELECT id as lid,ipaddress,name, 'address' as table_name,fqdn FROM address WHERE id IN (". implode(',',$ruleIdsArray).");");
        $this->log("SELECT id as lid,ipaddress,name, 'address' as table_name,fqdn FROM address WHERE id IN (". implode(',',$ruleIdsArray).");");
        if ($getAddress->num_rows>0){
            $projectdb->query("DELETE FROM tools_rename WHERE user='$userID' AND lid IN (". implode(',',$ruleIdsArray).");");
            while($getAddressData=$getAddress->fetch_assoc()){
                $error = false;
                $reverse = gethostbyaddr($getAddressData['ipaddress']);
                if ($reverse!=$getAddressData['ipaddress']){
                    $getAddressData['reverse']=$reverse;
                    $error = false;
                }
                else{
                    $getAddressData['reverse']='';
                    $error = true;
                }
                $Data[]="('".$getAddressData['lid']."','".$getAddressData['table_name']."','".$getAddressData['name']."','".$getAddressData['reverse']."','".$getAddressData['ipaddress']."','','$userID','$source','')";

                if($error){
                    $this->increaseFailed();
                }
                else{
                    $this->increaseCompleted();
                }
            }

            if (count($Data)>0){
                $projectdb->query("INSERT INTO tools_rename (lid,table_name,name,reverse,ipaddress,extra,user,source,vsys) VALUES ".implode(",",$Data).";");
            }
        }

        $this->setCompletedSilent('');

    }
}