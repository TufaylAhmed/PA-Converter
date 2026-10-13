<?php
/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: $today.year.hour.minute
 ******************************************************************************/

namespace PaloAltoNetworks\Expedition\MemoryObjects;

require_once INC_ROOT.'/libs/common/MemoryObjects/ResultItem.php';

class QueryResults
{
    public $results;

    public function __construct()
    {
        $this->results = array();
    }

    public function addResult($params, $items)
    {
        $newResult = new ResultItem($params, $items);
        $this->results[] = $newResult;
    }
}