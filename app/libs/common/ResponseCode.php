<?php
/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: $today.year.hour.minute
 ******************************************************************************/

namespace PaloAltoNetworks\Expedition;

class ResponseCode
{
    /* @var $successful boolean */
    /* @var $code int */
    /* @var $msg string */
    public $successful;
    public $code;
    public $msg;

    public function __construct(BOOL $successful, INT $code, STRING $msg){
        $this->successful = $successful;
        $this->code = $code;
        $this->msg = $msg;
    }

}