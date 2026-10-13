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

class ProjectRolesCheck extends HealthCheck
{
    public function getDescription(): string
    {
        return "Verify that Project roles are not corrupted";
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
        $projects = $app->project->get();

        foreach ($projects as $project){
            $name = $project->name;
            //Check AdminRole
            if(!$role_admin = $app->container->sentinel->getRoleRepository()->where("slug","PANProject_".$name."_admin")->get(["slug"])->first()){
                $missingSlugs[$name][] = "admin";
            }
            if(!$role_admin = $app->container->sentinel->getRoleRepository()->where("slug","PANProject_".$name."_user")->get(["slug"])->first()){
                $missingSlugs[$name][] = "user";
            }
            if(!$role_admin = $app->container->sentinel->getRoleRepository()->where("slug","PANProject_".$name."_viewer")->get(["slug"])->first()){
                $missingSlugs[$name][] = "viewer";
            }

        }

        $code = 0;
        $msg = 'Roles in projects: Satisfied';
        $remediation = "N/A";
        $success = count($missingSlugs)==0?true:false;

        if(!$success){
            $code = -1;
            $msg = "The following projects are missing roles: ".implode(",",array_keys($missingSlugs));
            $remediation = "Add missing roles to the following project: ".implode(",",array_keys($missingSlugs));
        }

        $response = new CheckResponse($this,$success,$code, $msg, $remediation);
        return $response;
    }

    public function repair(): CheckResponse
    {
        global $app;

        $missingSlugs = array();

        //List first the existing projects
        $projects = $app->project->get();

        foreach ($projects as $project){
            $name = $project->name;
            $slug = "PANProject_".$name;
            //Check AdminRole
            if(!$role_admin = $app->container->sentinel->getRoleRepository()->where("slug","PANProject_".$name."_admin")->get(["slug"])->first()){
                //Create the admin role for the project
                $missingSlugs[$name][] = "admin";
                $app->container->sentinel->getRoleRepository()->createModel()->create(array(
                    'name' => "admin",
                    'slug' => $slug."_admin",
                    'permissions' => array(
                        'projectRole.'.$name.'.admin'  => true,
                        'projectRole.'.$name.'.delete' => true,
                        'projectRole.'.$name.'.update' => true,
                        'projectRole.'.$name.'.view'   => true,
                    ),
                ));
            }
            if(!$role_admin = $app->container->sentinel->getRoleRepository()->where("slug","PANProject_".$name."_user")->get(["slug"])->first()){
                $missingSlugs[$name][] = "user";
                $app->container->sentinel->getRoleRepository()->createModel()->create(array(
                    'name' => "user",
                    'slug' => $slug."_user",
                    'permissions' => array(
                        'projectRole.'.$name.'.admin'  => false,
                        'projectRole.'.$name.'.delete' => false,
                        'projectRole.'.$name.'.update' => true,
                        'projectRole.'.$name.'.view'   => true,
                    ),
                ));
            }
            if(!$role_admin = $app->container->sentinel->getRoleRepository()->where("slug","PANProject_".$name."_viewer")->get(["slug"])->first()){
                $missingSlugs[$name][] = "viewer";
                $app->container->sentinel->getRoleRepository()->createModel()->create(array(
                    'name' => "viewer",
                    'slug' => $slug."_viewer",
                    'permissions' => array(
                        'projectRole.'.$name.'.admin'  => false,
                        'projectRole.'.$name.'.delete' => false,
                        'projectRole.'.$name.'.update' => false,
                        'projectRole.'.$name.'.view'   => true,
                    ),
                ));
            }

        }

        $code = 0;
        $remediation = '';
        $success = true;
        if(count($missingSlugs)>0){
            $remediation = "The following projects have been complemented with missing roles: ".implode(",",array_keys($missingSlugs));
        }

        $response = new CheckResponse($this,$success,$code, '',$remediation);
        return $response;
    }


}