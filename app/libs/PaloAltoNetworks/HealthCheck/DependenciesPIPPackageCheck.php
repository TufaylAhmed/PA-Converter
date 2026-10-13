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

class DependenciesPIPPackageCheck extends HealthCheck
{

    private $dependencies;
    private $dependencies_versions;

    public function __construct(ARRAY $dependencies)
    {
        parent::__construct();
        foreach ($dependencies as $dependency){
            $this->dependencies_versions[$dependency] = $dependency;
            $dependencyArr = explode(";", $dependency);
            $this->dependencies[$dependency]['name'] = $dependencyArr[0];
            $this->dependencies[$dependency]['version'] = isset($dependencyArr[1])?$dependencyArr[1]:'';
            $this->dependencies[$dependency]['fix'] = isset($dependencyArr[2])?$dependencyArr[2]:'';
        }
    }

    private function getDependenciesNames():array{
        $dependencies = array();
        foreach ($this->dependencies as $dependency){
            $dependencies[] = $dependency['name'];
        }

        return $dependencies;
    }

    private function getDependencies():array{
        $dependencies = array();
        foreach ($this->dependencies as $dependency){
            $dependencies[$dependency['name']] = [
                'version' => $dependency['version'],
                'fix' => $dependency['fix'],
                ];
        }

        return $dependencies;
    }

    private function dependenciesToString():array{
        $dependencies = array();
        foreach ($this->dependencies as $dependency){
            $dependencies[] = $dependency['name']. "(".$dependency['version'].")";
        }

        return $dependencies;
    }

    public function getDescription(): string
    {
       return "Verify that Python Software Dependencies have been installed";
    }

    public function getCategory(): string
    {
        return "OS Software";
    }

    public function check(): CheckResponse
    {
        $missingDependencies = $this->getDependencies();

        //pip list | grep BPA
        foreach ($missingDependencies as $dependencyName => $dependencyInfo) {
            exec("pip3.7 list | grep $dependencyName ", $output2);
            //print_r($output2);
            if(count($output2)>0) {
                $splitLine = preg_split('/\s+/', $output2[0]);//explode(" ",$line);
                if (isset($dependencyInfo['version']) && $dependencyInfo['version'] != '') {
                    if (strcmp($dependencyInfo['version'], $splitLine[1]) <= 0) { //If the dependency is covered
                        unset($missingDependencies[$dependencyName]);
                        break;
                    }
                }
                else{ //If we do not have restrictions, then this is not a missing dependency
                    unset($missingDependencies[$dependencyName]);
                    break;
                }
            }
        }

        $code = 0;
        $msg = 'Dependencies installed';
        $remediation = "N/A";
        $success = count($missingDependencies)==0?true:false;
        if(!$success){
            $code = -1;
            $missingDependenciesString = array();
            $fixes = [];
            foreach ($missingDependencies as $missingDependencyKey => $missingDependencyInfo){
                $missingDependenciesString[] = $missingDependencyKey." (".$missingDependencyInfo['version'].")";
                $fixes[] = $missingDependencyInfo['fix'].";";
            }

            $msg = "The following dependencies for ML are missing : ".implode(",",$missingDependenciesString);
            $remediation = "Execute the following command in CLI:</br> <b>".implode("<br>",$fixes)."</b>";
        }

        $response = new CheckResponse($this, $success,$code, $msg, $remediation);
        return $response;
    }

    public function repair(): CheckResponse
    {
        return $this->check();
    }


}