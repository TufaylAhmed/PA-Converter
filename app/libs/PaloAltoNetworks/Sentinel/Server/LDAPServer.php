<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 18/3/16 - 15:46
 */
namespace PaloAltoNetworks\Sentinel\Server;

use Illuminate\Database\Eloquent\Model as Eloquent;
//use Cartalyst\Sentinel\Users\EloquentUser;

class LDAPServer extends Eloquent
{
    protected $table = 'remote_LDAP_server';
    protected $fillable = [
        'name',
        'address',
        'port',
        'dn',
        'account_suffix',
        'account_prefix',
        'admin_user',
        'admin_password',
        'ldap_type',
        'uses_ssl',
        'uses_tls',
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