<?php
/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: $today.year.hour.minute
 ******************************************************************************/

function generateEncryptionKeys($device)
{
    global $app;
//Create the keys for this device
    $random_password = $app->randomlib->generateString(128);
    $random_iv = $app->randomlib->generateString(16);
    $keyData = [
        "type" => "device",
        "lid" => $device->id,
        "key" => $random_password,
        "iv" => $random_iv
    ];
    $keys = $app->accessKey->create($keyData);
}