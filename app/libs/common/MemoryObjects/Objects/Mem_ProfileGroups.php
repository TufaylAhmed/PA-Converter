<?php
/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: $today.year.hour.minute
 ******************************************************************************/

namespace PaloAltoNetworks\Expedition\MemoryObjects;

require_once INC_ROOT . '/libs/common/MemoryObjects/Objects/Mem_ObjectIndexer.php';
require_once INC_ROOT . '/libs/common/MemoryObjects/Objects/Mem_Objects.php';

class Mem_ProfileGroups extends Mem_Objects
{
    /* @var $byName Mem_ObjectIndexer */
    public $byName;
    /* @var $byName_ext Mem_ObjectIndexer */
    public $byName_ext;
    /* @var $byIP Mem_ObjectIndexer             */
    public $byIP;

    public function __construct(){
        parent::__construct();
        $this->byName = new Mem_ObjectIndexer();
    }

}