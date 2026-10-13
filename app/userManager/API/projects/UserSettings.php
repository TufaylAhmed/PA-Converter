<?php
/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: $today.year.hour.minute
 ******************************************************************************/

class UserSettings
{
    public function __construct()
    {
    }

    public function getUserSettings(STRING $project){
        global $app;
        $user = $app->container->sentinel->getUser();
        $userID = $user->id;
        $message = $this->get_UserSettings($project, $userID);
        return $message;
    }


    public function updateUserSettings(ARRAY $data){
        global $app;
        $user = $app->container->sentinel->getUser();
        $userID = $user->id;
        $message = $this->update_UserSettings($data, $userID);
        return $message;
    }

    private function get_UserSettings(STRING $projectName, $userID){
        require_once INC_ROOT.'/libs/shared.php';  //Method "getVersion(STRING)"
        global $app;
        $message = array();

        if (!($project = $app->project->where('name', '=', $projectName)->get()->first() )) {
            $message['code'] = false;
            $message['msg'] = 'Project not found in our registry';
            return $message;
        }

        $update = false;
        if($userSettings = $app->userSettings->where('user_id','=',$userID)->where('project_id','=',$project->id)->first()){
            $message['code'] = true;

            if(!isset($userSettings['source'])){
                $userSettings->source = 0;
                $newSettings['source'] = 0;
                $update =true;
            }
            else{
                $source = $userSettings['source'];
                $query = "SELECT version FROM device_mapping WHERE id='$source' GROUP BY device";
                $projectdb = selectDatabase($projectName);
                $data = $projectdb->query($query)->fetch_assoc();
                $version_parser = getVersion($data['version']);
                $userSettings->version = $version_parser;
            }

            if($userSettings['panos_vsys'] == 1){
                $userSettings['panos_vsys'] = "all";
            }
            if(!isset($userSettings['panorama_template'])){
                $userSettings->panorama_template = 0;
                $newSettings['panorama_template'] = 0;
                $update =true;
            }
            if(!isset($userSettings['panos_vsys'])){
                $userSettings->panos_vsys = 'all';
                $newSettings['panos_vsys'] = 'all';
                $update =true;
            }
            if(!isset($userSettings['panos_vsys'])){
                $userSettings->panos_vsys = 0;
                $newSettings['panos_vsys'] = 0;
                $update =true;
            }
            if(!isset($userSettings['view'])){
                $userSettings->view = 'panos';
                $newSettings['view'] = 'panos';
                $update =true;
            }
            if(!isset($userSettings['panorama_rules'])){
                $userSettings->panorama_rules = 'all';
                $newSettings['panorama_rules'] = 'all';
                $update =true;
            }

            if($update){
                $newSettings['project'] = $projectName;
                update_UserSettings($newSettings, $userID);
            }

            //echo "Panosvsys: ".$userSettings['panos_vsys']."\n";
            $message['msg'] = $userSettings;
        }
        else{
            $newCredentials = [
                'user_id' =>$userID,
                'project_id' =>$project->id,
                'source' => 0,
                'panorama_template' => 0,
                'panos_vsys' => 'all',
                'view' => 'panos',
                'panorama_rules' => 'all',
            ];
            //print_r($newCredentials);
            $app->container->userSettings->create($newCredentials);

            $message['code'] = true;
            $message['msg'] = $newCredentials;
        }

        return $message;
    }


    private function update_UserSettings(ARRAY $data, $userID){
        global $app;

        require_once INC_ROOT.'/libs/projectdb.php';

        $projectName = $data['project'];
        $message = array();

        if (!($project = $app->project->where('name', '=', $projectName)->get()->first() )) {
            $message['code'] = false;
            $message['msg'] = 'Project not found in our registry';
            return $message;
        }

        if($userSettings = $app->userSettings->where('user_id','=',$userID)->where('project_id','=',$project->id)->first()){

            if(isset($userSettings['source'])) {
                //Calcular el ispanorama
                $source = $userSettings['source'];
                if ($source != '0') {
                    $projectdb2 = selectDatabase($projectName);
                    $result = $projectdb2->query("SELECT ispanorama FROM device_mapping WHERE id='$source'");
                    if ($result->num_rows == 1) {
                        $resultData = $result->fetch_array();
                        if ($resultData['ispanorama'] == '1') {
                            $data['view'] = 'panorama';
                        } else {
                            $data['view'] = 'panos';
                        }
                    }
                }
            }

            $userSettings->update($data);
            $message['code'] = true;
            $message['msg'] = "Settings updated successfully for the project $projectName";
        }
        else{
            $message['code'] = false;
            $message['msg'] = 'Project not found in our registry';
        }

        return $message;
    }
}