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

class DeviceRolesCheck extends HealthCheck
{
    public function getDescription(): string
    {
        return "Verify that Device roles are not corrupted";
    }

    public function getCategory(): string
    {
        return "Authentication and Authorization";
    }

    public function check(): CheckResponse
    {
        global $app;

        $missingSlugs = array();

        //List first the existing projects
        $devices = $app->device->get();

        foreach ($devices as $device){
            $serial = $device->serial;
            //Check AdminRole
            if(!$role_admin = $app->container->sentinel->getRoleRepository()->where("slug","PANDevice_".$serial."_admin")->get(["slug"])->first()){
                $missingSlugs[$serial][] = "admin";
            }
            if(!$role_admin = $app->container->sentinel->getRoleRepository()->where("slug","PANDevice_".$serial."_user")->get(["slug"])->first()){
                $missingSlugs[$serial][] = "user";
            }
            if(!$role_admin = $app->container->sentinel->getRoleRepository()->where("slug","PANDevice_".$serial."_viewer")->get(["slug"])->first()){
                $missingSlugs[$serial][] = "viewer";
            }

        }

        $code = 0;
        $msg = 'Roles in devices: Satisfied';
        $remediation = 'N/A';
        $success = count($missingSlugs)==0?true:false;

        if(!$success){
            $code = -1;
            $msg = "The following devices are missing roles: ".implode(",",array_keys($missingSlugs));
            $remediation = "Add missing roles to the following devices: ".implode(",",array_keys($missingSlugs));
        }

        $response = new CheckResponse($this,$success,$code, $msg, $remediation);
        return $response;
    }

    public function repair(): CheckResponse
    {
        global $app;

        $missingSlugs = array();

        //List first the existing projects
        $devices = $app->device->get();

        foreach ($devices as $device){
            $serial = $device->serial;
            $slug = "PANDevice_".$serial;
            //Check AdminRole
            if(!$role_admin = $app->container->sentinel->getRoleRepository()->where("slug","PANDevice_".$serial."_admin")->get(["slug"])->first()){
                //Create the admin role for the project
                $missingSlugs[$serial][] = "admin";
                $app->container->sentinel->getRoleRepository()->createModel()->create(array(
                    'name' => "admin",
                    'slug' => $slug."_admin",
                    'permissions' => array(
                        'deviceRole.'.$serial.'.admin'  => true,
                        'deviceRole.'.$serial.'.delete' => true,
                        'deviceRole.'.$serial.'.update' => true,
                        'deviceRole.'.$serial.'.view'   => true,
                    ),
                ));
            }
            if(!$role_admin = $app->container->sentinel->getRoleRepository()->where("slug","PANDevice_".$serial."_user")->get(["slug"])->first()){
                $missingSlugs[$serial][] = "user";
                $app->container->sentinel->getRoleRepository()->createModel()->create(array(
                    'name' => "user",
                    'slug' => $slug."_user",
                    'permissions' => array(
                        'deviceRole.'.$serial.'.admin'  => false,
                        'deviceRole.'.$serial.'.delete' => false,
                        'deviceRole.'.$serial.'.update' => true,
                        'deviceRole.'.$serial.'.view'   => true,
                    ),
                ));
            }
            if(!$role_admin = $app->container->sentinel->getRoleRepository()->where("slug","PANDevice_".$serial."_viewer")->get(["slug"])->first()){
                $missingSlugs[$serial][] = "viewer";
                $app->container->sentinel->getRoleRepository()->createModel()->create(array(
                    'name' => "viewer",
                    'slug' => $slug."_viewer",
                    'permissions' => array(
                        'deviceRole.'.$serial.'.admin'  => false,
                        'deviceRole.'.$serial.'.delete' => false,
                        'deviceRole.'.$serial.'.update' => false,
                        'deviceRole.'.$serial.'.view'   => true,
                    ),
                ));
            }

        }

        $code = 0;
        $remediation = '';
        $success = true;
        if(count($missingSlugs)>0){
            $remediation = "The following devices have been complemented with missing roles: ".implode(",",array_keys($missingSlugs));
        }

        $response = new CheckResponse($this,$success,$code, '', $remediation);
        return $response;
    }


}