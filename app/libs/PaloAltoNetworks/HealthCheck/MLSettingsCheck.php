<?php
/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: $today.year.hour.minute
 ******************************************************************************/

namespace PaloAltoNetworks\HealthCheck;
require_once INC_ROOT.'/libs/settings/ML_Settings.php';



class MLSettingsCheck extends HealthCheck
{
    private $invalid_paths = [
        "/root",
        "/tmp",
        "/var/tmp"
    ];

    public function getDescription(): string
    {
        return "Verify the Machine Learning settings are valid";
    }

    public function getCategory(): string
    {
        return "Expedition Settings";
    }

    public function check(): CheckResponse
    {
        require_once INC_ROOT.'/libs/projectdb.php';
        $pandbRBAC = selectDatabase('pandbRBAC');
        $mlSettings = new \ML_Settings($pandbRBAC);
        $result = $mlSettings->get();

        if($result['code']!=1){
            $success = false;
            $code    = -1;
            $msg     = 'There are not settings defined for ML. ';
            $remediation = "Set the ML Settings";
        }
        else{
            $msg = '';
            $remediation = '';
            $success = true;
            $code    = 0;
            $settings = $result['msg']['0'];
            if(!$settings['server'] || $settings['server']=='' || $settings['server']=='127.0.0.1'){
                $success = false;
                $code    = -1;
                $msg     .= 'The ML server IP is incorrectly defined. ';
                $remediation .= 'Set up the IP address with your IP or an external ML IP<br>';
            }
            else{
                $msg     .= 'The ML server IP is defined as '.$settings['server'].'. ';
            }

            if(!$settings['parquetPath'] || $settings['parquetPath']=='' ){
                $success = false;
                $code    = -1;
                $msg     .= 'The ML connections.parquet Path is incorrectly defined. ';
                $remediation .= 'Please, change the connections.parquet Path. <br>The following paths are forbidden: '.implode(', ',$this->invalid_paths);
            }
            else{
                $path = $settings['parquetPath'];
                $isiInvalid = false;
                foreach ($this->invalid_paths as $invalid_path){
                    if(substr($path, 0, strlen($invalid_path)) === $invalid_path){
                        $isiInvalid = true;
                        break;
                    }
                }

                if($isiInvalid){
                    $success = false;
                    $code = -1;
                    $msg .= 'The ML connections.parquet Path is defined as "' . $settings['parquetPath'].'"';
                    $remediation = 'Please, change the connections.parquet Path. <br>The following paths are forbidden: '.implode(', ',$this->invalid_paths);
                }
                else {
                    if (!is_writable($settings['parquetPath'])) {
                        $success = false;
                        $code = -1;
                        $msg .= 'The ML connections.parquet Path is defined as "' . $settings['parquetPath'] . '", but it is not writeable. ';
                        $remediation .= 'The ML connections.parquet Path is defined as "' . $settings['parquetPath'] . '". <br>Verify the path or provide write permissions:<i> chown www-data ' . $settings['parquetPath'] . '; chmod +x ' . $settings['parquetPath'] . ' </i>';
                    } else {
                        $msg .= 'The ML connections.parquet Path is defined as "' . $settings['parquetPath'] . '". ';
                    }
                }
            }

            if(!$settings['tempDataPath'] || $settings['tempDataPath']=='' ){
                $success = false;
                $code    = -1;
                $msg     .= 'The ML Temporary Data Structures Path is incorrectly defined. ';
                $remediation .= 'Please, change the Temporary Data Structure Path. <br>The following paths are forbidden: '.implode(', ',$this->invalid_paths);
            }
            else{
                $path = $settings['tempDataPath'];
                $isiInvalid = false;
                foreach ($this->invalid_paths as $invalid_path){
                    if(substr($path, 0, strlen($invalid_path)) === $invalid_path){
                        $isiInvalid = true;
                        break;
                    }
                }

                if($isiInvalid){
                    $success = false;
                    $code = -1;
                    $msg .= 'The ML Temporary Data Structure Path is defined as "' . $settings['tempDataPath'].'"';
                    $remediation = 'Please, change the Temporary Data Structure Path. <br>The following paths are forbidden: '.implode(', ',$this->invalid_paths);
                }
                else {
                    if (!is_writable($settings['tempDataPath'])) {
                        $success = false;
                        $code = -1;
                        $msg .= 'The ML Temporary Data Structure Path is defined as "' . $settings['tempDataPath'] . '", but it is not writeable. ';
                        $remediation .= 'The ML Temporary Data Structure Path is defined as "' . $settings['tempDataPath'] . '". <br>Verify the path or provide write permissions:<i> chown www-data ' . $settings['tempDataPath'] . '; chmod +x ' . $settings['tempDataPath'] . ' </i>';
                    } else {
                        $msg .= 'The ML Temporary Data Structure Path is defined as "' . $settings['tempDataPath'] . '". ';
                    }
                }
            }
        }

        $remediation = $remediation==""?"N/A":$remediation;
        return new CheckResponse($this,$success, $code, $msg, $remediation);
    }

    public function repair(): CheckResponse
    {


        require_once INC_ROOT.'/libs/projectdb.php';
        $pandbRBAC = selectDatabase('pandbRBAC');
        $mlSettings = new \ML_Settings($pandbRBAC);
        $result = $mlSettings->get();

        if($result['code']!=1){
            $success = false;
            $code    = -1;
            $msg     = 'There are not settings defined for ML. ';
            $remediation = "N/A";
        }
        else{
            $msg = '';
            $remediation = '';
            $success = true;
            $code    = 0;
            $settings = $result['msg']['0'];
            if(!$settings['server'] || $settings['server']=='' || $settings['server']=='127.0.0.1'){
                $success = false;
                $code    = -1;
                $msg     .= 'The ML server IP is incorrectly defined. ';
                $remediation .= 'Please, change the parquet Path. The following paths are forbidden: '.implode(', ',$this->invalid_paths);
            }
            else{
                $msg     .= 'The ML server IP is defined as '.$settings['server'].'. ';
            }

            if(!$settings['parquetPath'] || $settings['parquetPath']=='' ){
                $success = false;
                $code    = -1;
                $msg     .= 'The ML parquet Path is incorrectly defined. ';
                $remediation .= 'Please, change the parquet Path. The following paths are forbidden: '.implode(', ',$this->invalid_paths);
            }
            else{
                $path = $settings['parquetPath'];
                $isInvalid = false;
                foreach ($this->invalid_paths as $invalid_path){
                    if(substr($path, 0, strlen($invalid_path)) === $invalid_path){
                        $isInvalid = true;
                        break;
                    }
                }

                if($isInvalid){
                    $success = false;
                    $code = -1;
                    $msg .= 'The ML parquet Path is defined as "' . $settings['parquetPath'] . '"';
                    $remediation .= ' Please, change this path. The following paths are forbidden: '.implode(', ',$this->invalid_paths);
                }
                else {
                    if (!is_writable($settings['parquetPath'])) {
                        $success = false;
                        $code = -1;
                        $msg .= 'The ML parquet Path is defined as "' . $settings['parquetPath'].'"';
                        $remediation .= 'Verify the path or provide write permissions:<i> chown www-data ' . $settings['parquetPath'] . '; chmod +x ' . $settings['parquetPath'] . ' </i>';
                    } else {
                        $msg .= 'The ML parquet Path is defined as "' . $settings['parquetPath'] . '". ';
                        $remediation .= "N/A";
                    }
                }
            }
        }

        return new CheckResponse($this,$success, $code, $msg, $remediation);
    }

}