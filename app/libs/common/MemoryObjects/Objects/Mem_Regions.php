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

class Mem_Regions extends Mem_Objects
{
    /* @var $byName Mem_ObjectIndexer */
    public $byName;
    /* @var $byName_ext Mem_ObjectIndexer */
    public $byName_ext;
    /* @var $byLatitude Mem_ObjectIndexer             */
    public $byLatitude;
    /* @var $byLongitude Mem_ObjectIndexer             */
    public $byLongitude;
    /** @var $byAddress Mem_ObjectIndexer  */
    public $byAddress;

    public function __construct(){
        parent::__construct();
        $this->byName = new Mem_ObjectIndexer();
        $this->byName_ext= new Mem_ObjectIndexer();
        $this->byLatitude = new Mem_ObjectIndexer();
        $this->byLongitude = new Mem_ObjectIndexer();
        $this->byAddress = new Mem_ObjectIndexer();

    }


}