<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 9/3/16 - 14:12
 */

namespace PaloAltoNetworks\Sentinel\Role;

use Illuminate\Database\Eloquent\Model as Eloquent;

class Role extends Eloquent
{
    protected $table = 'roles';
    protected $fillable = [
        'slug',
        'name',
        'permissions',
        'created_at',
        'updated_at',
    ];

    public function getFullName()
    {
        if (!$this->name){
            return null;
        }

        return "{$this->name}";
    }

}