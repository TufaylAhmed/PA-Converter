<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 126/11/19 - 15:45
 */

require_once INC_ROOT.'/libs/projectdb.php';  //to be able to set a DB connection
require_once INC_ROOT.'/libs/database.php';
require_once INC_ROOT.'/libs/backups.php';
require_once INC_ROOT.'/libs/shared.php';

class RemoveUnusedObjects extends CalculateUnusedObjects
{

    public function execute(){
        /* @var $app \Slim\Slim */
        global $app;
        $successful = true;

        $this->log(json_encode($this->params));

        //Set a session with the user provided
        if(isset($this->sender)){
            //$user = $app->sentinel->findById($this->sender);  //Provided user for CLI executions
            $userID = $this->params['userId'];

            if($user = $app->user->where('id',$userID)->where('api_key',$this->params['key'])->where('valid_til', '>',date("Y-m-d H:i:s"))->get()->first()) {
                $app->sentinel->login($user);
            }
        }
        else {
            $user = $app->container->sentinel->getUser();  //Get it from the Sentinel session, if coming from a browser.
            $app->sentinel->login($user);
        }

        if(!$app->container->sentinel->check() || !isset($user)){
            $className = get_class($this);
            $this->log($className. " - Invalid Credentials to execute the process");
            $this->setFailed("Invalid Credentials to execute the process", "Export Cancelled by user invalid credentials");
            return;
        }


        $this->setStarted();
        $this->log("Action:\t\tRemove Unused Objects\n".
            "User:\t\t".$user->email."\n".
            "Project:\t".$this->params['project']."\n".
            "Source:\t\t".$this->params['source']
        );
        $this->take_snapshot();
        $this->check_used_objects_new();
        //$this->increaseCompleted();
        $this->delete_unused();
        //


        if(!$successful){
            $this->setFailedSilent();
        }
        else {
            $this->setCompletedSilent();
        }
    }

    private function delete_unused(){

        global $projectdb;
        $source = $this->params['source'];
        $vsys= $this->params['vsys'];


        if ($source == 0) {

            if ($vsys == "all") {
                $this->deleting('');
            }
            else{
                $this->deleting(" AND vsys = '$vsys'");
            }
        }
        else {
            if ($vsys == "all") {
                $this->deleting(" AND source = '$source'");
            }
            else{
                $this->deleting(" AND source = '$source' AND vsys = '$vsys'");
            }
        }
    }

    private function deleting(string $selected){
        global $projectdb;

        $projectdb->query("DELETE FROM address WHERE used = 0 AND dummy = '0' $selected;");
        $projectdb->query("DELETE FROM services WHERE used = 0 AND dummy = '0' $selected AND name NOT IN ('application-default', 'service-http', 'service-https') ;");
        $projectdb->query("DELETE FROM regions WHERE used = 0 $selected;");

        $getGRP = $projectdb->query("SELECT id FROM address_groups_id WHERE used = 0 $selected;");
        if ($getGRP->num_rows > 0) {
            while ($data = $getGRP->fetch_assoc()) {
                $lid[] = $data['id'];
            }
            $projectdb->query("DELETE FROM address_groups_id WHERE id IN (" . implode(",", $lid) . ");");
            $projectdb->query("DELETE FROM address_groups WHERE lid IN (" . implode(",", $lid) . ");");
        }
        unset($lid);

        $getGRP = $projectdb->query("SELECT id FROM services_groups_id WHERE used=0 $selected;");
        if ($getGRP->num_rows > 0) {
            while ($data = $getGRP->fetch_assoc()) {
                $lid[] = $data['id'];
            }
            $projectdb->query("DELETE FROM services_groups_id WHERE id IN (" . implode(",", $lid) . ");");
            $projectdb->query("DELETE FROM services_groups WHERE lid IN (" . implode(",", $lid) . ");");
        }
        unset($lid);

        $getGRP = $projectdb->query("SELECT id FROM applications_groups_id WHERE used = 0 $selected;");
        if ($getGRP->num_rows > 0) {
            while ($data = $getGRP->fetch_assoc()) {
                $lid[] = $data['id'];
            }
            $projectdb->query("DELETE FROM applications_groups_id WHERE id IN (" . implode(",", $lid) . ");");
            $projectdb->query("DELETE FROM applications_groups WHERE lid IN (" . implode(",", $lid) . ");");
        }
        unset($lid);

        $projectdb->query("DELETE FROM applications_filters WHERE used = 0 AND dummy = '0' $selected;");
        $projectdb->query("DELETE FROM applications WHERE used = 0 AND dummy = '0' $selected;");
        $projectdb->query("DELETE FROM tag WHERE used = 0 AND dummy = '0' $selected;");

        $this->increaseCompleted();
    }
}