<?php
/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: $today.year.hour.minute
 ******************************************************************************/
namespace PaloAltoNetworks\Expedition\Security;

require_once INC_ROOT.'/libs/Security/OpenSSLTools.php';
require_once INC_ROOT.'/libs/Security/SecureObject.php';


class SecureDevice extends SecureObject {

    public function secure(STRING $device){
        global $app;

        $deviceObj = $app->device->where("serial", $device)->first();

        if(! $keyObj = $keyObj = $app->accessKey->where("type", "device")->where("lid", $deviceObj->id)->first()){
            //There is no keys for this project, we need to encrypt this project

            //Create the keys for this project
            $random_password = $app->randomlib->generateString(128);
            $random_iv = $app->randomlib->generateString(16);
            $keyData = [
                "type"  => "device",
                "lid"   => $deviceObj->id,
                "key"   => $random_password,
                "iv"    => $random_iv
            ];
            $keyObj = $app->accessKey->create($keyData);

            //Check all the files that should be encrypted within this project
            $encryptor = new OpenSSLTools($keyObj->key, $keyObj->iv);

            $projectPath = USERSPACE_PATH.DIRECTORY_SEPARATOR.'device'.DIRECTORY_SEPARATOR.$device;
            $files = $this->dirToArray($projectPath);
            foreach ($files as $file){
                //Verify it is not an already encrypted file
                $encryptor->encryptFiletoFile($file, "$file.dat");
                unlink($file);
            }
        }
        else{
            //Verify that there are no files not encrypted
            $encryptor = new OpenSSLTools($keyObj->key, $keyObj->iv);

            $projectPath = USERSPACE_PATH.DIRECTORY_SEPARATOR.'devices'.DIRECTORY_SEPARATOR.$device;
            $files = $this->dirToArray($projectPath, ["*.dat", "region.xml", "applications-container.xml", "applications.xml", "url_categories.xml"]);

            foreach ($files as $file){
                //Verify it is not an already encrypted file
                $encryptor->encryptFiletoFile($file, "$file.dat");
                unlink($file);
            }
        }
    }
}


