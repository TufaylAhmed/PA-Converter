<?php
/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: $today.year.hour.minute
 ******************************************************************************/

namespace PaloAltoNetworks\Expedition\MemoryObjects;


class Response
{
    public $code;
    public $message;
    public $success;
    public $output;

    public function __construct(BOOL $success=true, INT $code=0, STRING $message='', ARRAY $output=array())
    {
        $this->code = $code;
        $this->message = $message;
        $this->success = $success;
        $this->output = $output;
    }

    public function getMessage(){
        return $this->message;
    }
}