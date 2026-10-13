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

class HoldPackagesCheck extends HealthCheck
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
       return "Verify that Specific Software Dependencies are on Hold. Avoid <b>apt upgrade</b> issues";
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
        exec("apt-mark showhold", $output);
        foreach ($output as $line){
            //print_r($splitLine);
            foreach ($missingDependencies as $dependency => $version) {
                if($dependency==$line){  //Package found
                    //echo "$dependency $line\n";
                    unset($missingDependencies[$dependency]);
                    break;
                }
            }
        }


        $code = 0;
        $msg = 'Sensitive Dependencies on Hold';
        $remediation = "N/A";
        $success = count($missingDependencies)==0?true:false;
        if(!$success){
            $code = -1;
            $missingDependenciesString = array();
            foreach ($missingDependencies as $missingDependencyKey => $missingDependencyVersion){
                $missingDependenciesString[] = $missingDependencyKey;
            }
            $msg = "The software dependencies are not on Hold : ".implode(", ",$missingDependenciesString);
            $remediation = "Execute the following command in CLI : <b>sudo apt-mark hold ".implode(" ",array_keys($missingDependencies))."</b>";
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
        $remediation = 'Sensitive Dependencies on Hold';
        $success = count($missingDependencies)==0?true:false;
        if(!$success){
            $code = -1;
            $remediation = "Execute the following command in CLI : <b>sudo apt-get install ".implode(" ",array_keys($missingDependencies))."</b>";
        }

        $response = new CheckResponse($this, $success,$code, '',$remediation);
        return $response;
    }


}