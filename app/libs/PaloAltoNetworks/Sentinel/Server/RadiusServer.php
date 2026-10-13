<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 22/3/16 - 16:01
 */

namespace PaloAltoNetworks\Sentinel\Server;

use Illuminate\Database\Eloquent\Model as Eloquent;
//use Cartalyst\Sentinel\Users\EloquentUser;

//class User extends Eloquent

class RadiusServer extends Eloquent
{
    protected $table = 'remote_Radius_server';
    protected $fillable = [
        'name',
        'address',
        'port',
        'shared_key',
        'active',
    ];

    public function getAddress()
    {
        if (!$this->address){
            return null;
        }

        return "{$this->address}";
    }

}