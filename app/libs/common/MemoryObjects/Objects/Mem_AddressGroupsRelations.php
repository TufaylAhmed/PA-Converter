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

class Mem_AddressGroupsRelations extends Mem_Objects
{
    /* @var $byGroup Mem_ObjectIndexer     */
    public $byGroup;
    /* @var $byMember Mem_ObjectIndexer     */
    public $byMember;

    public function __construct(){
        parent::__construct();
        $this->byGroup = new Mem_ObjectIndexer();
        $this->byMember = new Mem_ObjectIndexer();
    }
}