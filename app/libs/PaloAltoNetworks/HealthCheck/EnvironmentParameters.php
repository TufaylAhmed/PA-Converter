<?php

namespace PaloAltoNetworks\HealthCheck;

require_once INC_ROOT.'/libs/cpu_status_functions.php';
getEnvironmentParameters();
//require '/home/userSpace/environmentParameters.php';
require_once INC_ROOT.'/libs/PaloAltoNetworks/HealthCheck/HealthCheck.php';

class Parameter{
    public $name;
    public $value;

    public function __construct($name, $value)
    {
        $this->name = $name;
        $this->value = $value;
    }
}

class EnvironmentParameters extends HealthCheck
{

    private $parameters = array();

    public function __construct()
    {
        parent::__construct();
        exec("/bin/bash ". INC_ROOT."/OS/spark/scripts/checkCPUs.sh");
        include_once ("/home/userSpace/tempEnvironmentParameters.php");
        $this->parameters = [
            new Parameter('SparkRAM',$suggestedEnvironmentParameters['SparkRAM']),
            new Parameter('NumCPUs',$suggestedEnvironmentParameters['NumCPUs']),
            new Parameter('TotalCPUs',$suggestedEnvironmentParameters['TotalCPUs']),
        ];
    }

    public function getDescription(): string
    {
        return "Verify that all required parameters are provided in /home/userSpace/environmentParameters.php";
    }

    public function getCategory(): string
    {
        return "Expedition Status";
    }

    public function check(): CheckResponse
    {
        $missingVariables = array();
        $modifiedVariables = array();




        /* @var \PaloAltoNetworks\HealthCheck\Parameter $parameter */
        foreach ($this->parameters as $key=>$parameter){
            if(!defined($parameter->name)){
                $missingVariables[] = $parameter->name;

            }
            else{
                if (constant($parameter->name) != $parameter->value){
                    $modifiedVariables[] = $parameter->name.": \"".constant($parameter->name)."\" suggested: \"$parameter->value\"";
                }
            }
        }

        $code = 0;
        $msg = 'All variables defined';
        if(count($modifiedVariables)==0){
            $remediation = "N/A";
        }
        else{
            $remediation = "The following variables <font color='red'>do not have</font> the default values:<br> ".implode("<br>",$modifiedVariables);
            $msg .= "<br>".$remediation;
        }

        $success = count($missingVariables)==0?true:false;
        if(!$success){
            $code = -1;
            $msg = "The following variables for Expedition are missing : ".implode(",",$missingVariables);
            $remediation = "Delete the /home/userSpace/environmentParameters.php to get it regenerated</b>";
        }

        $response = new CheckResponse($this, $success,$code, $msg, $remediation);
        return $response;
    }

    public function repair(): CheckResponse
    {
        $missingVariables = array();
        $modifiedVariables = array();




        /* @var \PaloAltoNetworks\HealthCheck\Parameter $parameter */
        foreach ($this->parameters as $key=>$parameter){
            if(!defined($parameter->name)){
                $missingVariables[] = $parameter->name;

            }
            else{
                if (constant($parameter->name) != $parameter->value){
                    $modifiedVariables[] = $parameter->name.": \"".constant($parameter->name)."\" suggested: \"$parameter->value\"";
                }
            }
        }

        $code = 0;
        $msg = 'All variables defined';
        if(count($modifiedVariables)==0){
            $remediation = "N/A";
        }
        else{
            $remediation = "The following variables <font color='red'>do not have</font> the default values:<br> ".implode("<br>",$modifiedVariables);
            $msg .= "<br>".$remediation;
        }

        $success = count($missingVariables)==0?true:false;
        if(!$success){
            $code = -1;
            $msg = "The following variables for Expedition are missing : ".implode(",",$missingVariables);
            $remediation = "Delete the /home/userSpace/environmentParameters.php to get it regenerated</b>";
        }

        $response = new CheckResponse($this, $success,$code, $msg, $remediation);
        return $response;
    }


}

