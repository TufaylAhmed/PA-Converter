<?php
/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: $today.year.hour.minute
 ******************************************************************************/

namespace PaloAltoNetworks\Expedition\MemoryObjects;


class ResultItem
{
    /* @var array */
    public $parameters;

    /** @var array */
    public $ids;

    public function __construct($parameters, $items){
        $this->parameters = $parameters;
        $this->ids = $items;

    }

    public function addParamters(ARRAY $params){
        foreach ($params as $param=>$value){
            $this->parameters[$param] = $value;
        }
    }

}