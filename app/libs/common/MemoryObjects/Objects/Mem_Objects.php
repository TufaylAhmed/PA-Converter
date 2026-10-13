<?php
/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: $today.year.hour.minute
 ******************************************************************************/

namespace PaloAltoNetworks\Expedition\MemoryObjects;


abstract class Mem_Objects
{
    /* @var $ids array */
    public $ids;
    /* @var $byIP Mem_ObjectIndexer */
    public $bySource;
    /* @var $byVsys Mem_ObjectIndexer */
    public $byVsys;
    /** @var Mem_ObjectIndexer */
    public $byPrimary;

    public function __construct(){
        $this->ids = array();
        $this->bySource = new Mem_ObjectIndexer();
        $this->byVsys = new Mem_ObjectIndexer();
        $this->byPrimary = new Mem_ObjectIndexer();
    }

    public function print():string{
        return json_encode($this, true);
    }
}