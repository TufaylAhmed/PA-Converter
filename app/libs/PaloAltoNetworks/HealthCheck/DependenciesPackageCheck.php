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

class DependenciesPackageCheck extends HealthCheck
{

    private $dependencies;
    private $dependencies_versions;

    public function __construct(ARRAY $dependencies)
    {
        parent::__construct();
        foreach ($dependencies as $dependency){
            $this->dependencies_versions[$dependency] = $dependency;
            $dependencyArr = explode(" ", $dependency);
            $this->dependencies[$dependency]['name'] = $dependencyArr[0];
            $this->dependencies[$dependency]['version'] = isset($dependencyArr[1])?$dependencyArr[1]:'';
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
            $dependencies[$dependency['name']] = $dependency['version'];
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
       return "Verify that APT Software Dependencies have been installed";
    }

    public function getCategory(): string
    {
        return "OS Software";
    }

    public function check(): CheckResponse
    {
        $missingDependencies = $this->getDependencies();

//        print_r($this->getDependenciesNames());

        $output = array();
//        echo "dpkg -l ". implode(" ", $this->getDependenciesNames()). " | grep ii";
        exec("dpkg -l ". implode(" ", $this->getDependenciesNames()). " | grep 'i.\s'", $output);
        //print_r($output);
        //echo "dpkg -l ". implode(" ", $this->getDependenciesNames()). " | grep ii";
//        exec("apt list | grep -E '".implode("|", $this->dependencies)."'", $output);
        foreach ($output as $line){
            $splitLine =  preg_split('/\s+/', $line);//explode(" ",$line);
            //print_r($splitLine);
            foreach ($missingDependencies as $dependency => $required_version) {
                if($dependency==$splitLine[1]){  //Package found
                    if(isset($required_version) && $required_version!=''){ //If we have restrictions on the required_version
                        //echo "Requires: $required_version \tHas: ".$splitLine[2]." \tCompare Result:".version_compare($required_version, $splitLine[2])."\n";
                        if (version_compare($required_version, $splitLine[2])<=0){ //If the dependency is covered
                            unset($missingDependencies[$dependency]);
                            break;
                        }
                    }
                    else{ //If we do not have restrictions, then this is not a missing dependency
                        unset($missingDependencies[$dependency]);
                        break;
                    }
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
            foreach ($missingDependencies as $missingDependencyKey => $missingDependencyVersion){
                $missingDependenciesString[] = $missingDependencyKey." (".$missingDependencyVersion.")";
            }
            $msg = "The following dependencies for ML are missing : ".implode(",",$missingDependenciesString);
            $remediation = "Execute the following command in CLI : <b>sudo apt-get install ".implode(" ",array_keys($missingDependencies))."</b>";
        }

        $response = new CheckResponse($this, $success,$code, $msg, $remediation);
        return $response;
    }

    public function repair(): CheckResponse
    {
        $missingDependencies = $this->dependencies;

        $output = array();
        exec("apt list | grep -E '".implode("|", $this->dependencies)."'", $output);
        foreach ($output as $line){
            foreach ($missingDependencies as $dependency => &$version) {
                if(preg_match("/^$dependency\/.*$/", $line, $output_array)>0){
                    unset($missingDependencies[$dependency]);
                    break;
                }
            }
        }


        $code = 0;
        $remediation = 'Dependencies installed';
        $success = count($missingDependencies)==0?true:false;
        if(!$success){
            $code = -1;
            $remediation = "Execute the following command in CLI : <b>sudo apt-get install ".implode(" ",array_keys($missingDependencies))."</b>";
        }

        $response = new CheckResponse($this, $success,$code, '',$remediation);
        return $response;
    }


}