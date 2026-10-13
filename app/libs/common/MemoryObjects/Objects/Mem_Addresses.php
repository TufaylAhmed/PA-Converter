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

use PaloAltoNetworks\Policy\Objects\MemberObject as Member;

class Mem_Addresses extends Mem_Objects
{
    /* @var $byName Mem_ObjectIndexer */
    public $byName;
    /* @var $byName_ext Mem_ObjectIndexer */
    public $byName_ext;
    /* @var $byIP Mem_ObjectIndexer             */
    public $byIP;
    /* @var $byCidr Mem_ObjectIndexer             */
    public $byCidr;
    /* @var $byType Mem_ObjectIndexer  */
    public $byType;
    /* @var $byDummy Mem_ObjectIndexer  */
    public $byDummy;

    public function __construct(){
        parent::__construct();
        $this->byName           = new Mem_ObjectIndexer();
        $this->byName_ext       = new Mem_ObjectIndexer();
        $this->byIP             = new Mem_ObjectIndexer();
        $this->byCidr           = new Mem_ObjectIndexer();
        $this->byType           = new Mem_ObjectIndexer();
        $this->byDummy          = new Mem_ObjectIndexer();
    }


}