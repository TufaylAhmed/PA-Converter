<?php
/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: $today.year.hour.minute
 ******************************************************************************/

namespace PaloAltoNetworks\HealthCheck;

require_once INC_ROOT.'/libs/PaloAltoNetworks/HealthCheck/HealthCheck.php';

class OrphanDeviceRolesCheck extends HealthCheck
{

    public function getDescription(): string
    {
        return "Verify that there are not orphan Device roles";
    }

    public function getCategory(): string
    {
        return "Authentication and Authorization";
    }

    public function check(): CheckResponse
    {
        global $app;

        $rolesToRemove = array();

        if($roles= $app->container->sentinel->getRoleRepository()->where("slug",'LIKE',"PANDevice_%")->get(["slug"])){
            //Check that the device exist
            foreach ($roles as $role){
                $roleID = $role->slug;
                $fields = explode("_", $roleID);
                if(isset($fields[1])) {
                    $serial = $fields[1];
                    if(!$device = $app->device->where("serial", $serial)->get()->first()){
                        $rolesToRemove[] = $serial;
                    }
                }
                else{
                    //This role is not normal. Warn about it
                    $rolesToRemove[] = $roleID;
                }
            }
        }

        $code = 0;
        $msg = 'Device Roles: Satisfied';
        $remediation = 'N/A';
        $success = count($rolesToRemove)==0?true:false;
        if(!$success){
            $code = -1;
            $msg = "There are orphan roles for the devices (serial): ".implode(", ",$rolesToRemove);
            $remediation = "Remove the orphan roles for devices (serial): ".implode(", ",$rolesToRemove);
        }

        $response = new CheckResponse($this,$success,$code, $msg, $remediation);
        return $response;
    }

    public function repair(): CheckResponse
    {
        global $app;

        $rolesToRemove = array();

        if ($roles = $app->container->sentinel->getRoleRepository()->where("slug", 'LIKE', "PANDevice_%")->get(["slug"])) {
            //Check that the device exist
            foreach ($roles as $role) {
                $roleID = $role->slug;
                $fields = explode("_", $roleID);
                if (isset($fields[1])) {
                    $serial = $fields[1];
                    if (!$device = $app->device->where("serial", $serial)->get()->first()) {
                        $roleToDelete = $app->container->sentinel->getRoleRepository()->where("slug",$roleID)->get()->first();
                        $roleToDelete->delete();
                        $rolesToRemove[] = $serial;
                    }
                } else {
                    //This role is not normal. Warn about it
                    $rolesToRemove[] = $roleID;
                }
            }
        }

        $code = 0;
        $msg = 'Device Roles: Satisfied';
        $remediation = 'N/A';
        $success = count($rolesToRemove) == 0 ? true : false;
        if (!$success) {
            $code = -1;
            $msg = "There were orphan roles for the devices (serial): " . implode(", ", $rolesToRemove);
            $remediation = "The roles were removed (serial): " . implode(", ", $rolesToRemove);
        }

        $response = new CheckResponse($this, $success, $code, $msg, $remediation);
        return $response;
    }


}