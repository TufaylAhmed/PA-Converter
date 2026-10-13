<?php
/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: $today.year.hour.minute
 ******************************************************************************/

class PackageVersionChecker
{
    protected $expeditionVersion;
    protected $expeditionMLDependenciesVersion;


    public function __construct()
    {
    }

    public function getVersions():array{
        $response = array();
        $expedition = $this->getExpeditionVersion();
        $ml = $this->getExpeditionMLDependenciesVersion();
        $bpa = $this->getBPAVersion();
        $date = $this->getExpeditionDate();
        $response['Running'] = "Expedition VM";
        if(isset($date['Expedition Date'])){
            $response['Running'] = $response['Running'].". Installed at ".$date['Expedition Date'];
        }
        $response['Expedition'] = $expedition['Expedition'];
        $response['Spark Dependencies'] = $ml['Spark Dependencies'];
        $response['Best Practices'] = $bpa['Best Practices'];
        return $response;

    }

    public function getExpeditionVersion():array{
        $command = 'dpkg -s expedition-beta | grep Version';
        $response = exec($command, $output);
        $version = $output[0];
        $versionArr = explode(" ", $version);
        return ['Expedition' => $versionArr[1]];
        //Result:
        //  Version: 1.0.94
    }

    public function getExpeditionMLDependenciesVersion():array{
        $command = 'dpkg -s expeditionml-dependencies-beta | grep Version';
        $response = exec($command, $output);
        $version = $output[0];
        $versionArr = explode(" ", $version);
        return ['Spark Dependencies' => $versionArr[1]];
        //Result:
        //  Version: 0.1.1
    }

    public function getBPAVersion():array{
        $command = 'pip3.7 show BPA| grep Version';
        $response = exec($command, $output);
        if (!isset($output[0])){
            $command = 'pip3.7 show best-practice-assessment-ngfw-pano | grep Version';
            $response = exec($command, $output);
        }
        $version = $output[0];
        $versionArr = explode(" ", $version);
        return ['Best Practices' => $versionArr[1]];
        //Result:
        //  Version: 0.1.1
    }

    public function getExpeditionDate():array{
        $version = $this->getExpeditionVersion();
        $currentVersion=$version['Expedition'];
        $command = "grep installed /var/log/dpkg.* | grep expedition-beta | grep $currentVersion";
        $response = exec($command, $output);
        $version = $output[0];
        $versionArr = explode(" ", $version);
        if(str_contains($versionArr[0], ":")) {
            $dateArr = explode(":", $versionArr[0]);
            $installation_date = $dateArr[1];
        } else {
            $installation_date = $versionArr[0];
        }
        return ['Expedition Date' => $installation_date];
    }

}