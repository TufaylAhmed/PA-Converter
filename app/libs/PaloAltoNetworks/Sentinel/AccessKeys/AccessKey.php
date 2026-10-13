<?php
/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: 2017-Nov-28 11:24
 ******************************************************************************/

namespace PaloAltoNetworks\Sentinel\AccessKeys;

use Illuminate\Database\Eloquent\Model as Eloquent;

class AccessKey extends Eloquent
{
    /**
     * {@inheritDoc}
     */
    protected $table = 'security';
    protected $fillable = [
        'type', 'lid', 'key', 'iv', 'created_at', 'updated_at',
    ];

    /**
     * The accessKey model name.
     *
     * @var string
     */
    protected static $accessKeyModel = 'PaloAltoNetworks\Sentinel\AccessKeys\AccessKey';
}
