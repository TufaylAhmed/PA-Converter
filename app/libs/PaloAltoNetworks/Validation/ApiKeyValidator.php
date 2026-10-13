<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 27/5/16 - 13:07
 */

namespace PaloAltoNetworks\Validation;

use PaloAltoNetworks\Sentinel\ApiKeys\ApiKey;
use Violin\Violin;

class ApiKeyValidator extends Violin
{
    protected $project;

    public function __construct(ApiKey $apikey)
    {
        $this->apikey = $apikey;

        $this->addFieldMessages([
//            'device_id', 'key_name', 'api_key', 'user_name', 'user_password', 'created_at', 'updated_at', 'role',
            'key_name' => [
                'uniqueKeyNameInDevice' => 'This <b>Role</b> is already taken'
            ],
            'active' => [
                'isBoolean' => '<b>The Active</b> field should be a boolean'
            ],
        ]);
    }

    public function validate_uniqueKeyNameInDevice($value, $input, $args)
    {
        $id = $args[0];
        $key = $this->apikey->where('key_name', $value)->where('device_id',"!=",$id);
        return ($key->count()== 0) ? true: false;
    }

    public function validate_isBoolean($value, $input, $args)
    {
        if ($value==0) return true;
        if ($value==1) return true;
        return false;
    }


}