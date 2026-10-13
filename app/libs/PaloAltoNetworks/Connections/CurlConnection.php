<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 15/6/16 - 16:46
 */

namespace PaloAltoNetworks\Connections;

use Illuminate\Database\Eloquent\Model as Eloquent;

class CurlConnection extends Eloquent
{
    protected $table = 'curlConnections';
    protected $fillable = [
        'origin',
        'destination',
        'hostedConnections',
        'status',
        'created_at',
        'updated_at',
    ];

    public function getOrigin()
    {
        if (!$this->origin){
            return null;
        }

        return "{$this->origin}";
    }

    public function getDestination()
    {
        if (!$this->destination){
            return null;
        }

        return "{$this->destination}";
    }

}