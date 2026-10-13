<?php
/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: $today.year.hour.minute
 ******************************************************************************/

namespace PaloAltoNetworks\Expedition\Security;

require_once INC_ROOT.'/libs/Security/SecureObject.php';
require_once INC_ROOT.'/libs/Security/OpenSSLTools.php';

class SecureProject extends SecureObject{

    public function secure(STRING $project){
        global $app;

        $projectObj = $app->project->where("name", $project)->first();

        if(! $keyObj = $app->accessKey->where("type","project")->where("lid", $projectObj->id)->first()){
            //There is no keys for this project, we need to encrypt this project

            //Create the keys for this project
            $random_password = $app->randomlib->generateString(128);
            $random_iv = $app->randomlib->generateString(16);
            $keyData = [
                "type"  => "project",
                "lid"   => $projectObj->id,
                "key"   => $random_password,
                "iv"    => $random_iv
            ];
            $keyObj = $app->accessKey->create($keyData);

            //Check all the files that should be encrypted within this project
            $encryptor = new OpenSSLTools($keyObj->key, $keyObj->iv);

            $projectPath = USERSPACE_PATH.DIRECTORY_SEPARATOR.'projects'.DIRECTORY_SEPARATOR.$project;
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

            $projectPath = USERSPACE_PATH.DIRECTORY_SEPARATOR.'projects'.DIRECTORY_SEPARATOR.$project;
            $files = $this->dirToArray($projectPath, ["*.dat"]);
            foreach ($files as $file){
                //Verify it is not an already encrypted file
                $encryptor->encryptFiletoFile($file, "$file.dat");
                unlink($file);
            }
        }
    }
}




