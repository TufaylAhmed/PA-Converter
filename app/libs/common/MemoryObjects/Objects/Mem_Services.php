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

class Mem_Services extends Mem_Objects
{
    /* @var $byName Mem_ObjectIndexer */
    public $byName;
    /* @var $byName_ext Mem_ObjectIndexer */
    public $byName_ext;
    /* @var $bySPort Mem_ObjectIndexer             */
    public $bySPort;
    /* @var $byDPort Mem_ObjectIndexer             */
    public $byDPort;
    /* @var $byProtocol Mem_ObjectIndexer             */
    public $byProtocol;
    /* @var $byProtocolDPort Mem_ObjectIndexer             */
    public $byProtocolDPort;
    /* @var $byTimeout Mem_ObjectIndexer             */
    public $byTimeout;
    /* @var $byHalfcloseTimeout Mem_ObjectIndexer             */
    public $byHalfcloseTimeout;
    /* @var $byTimewaitTimeout Mem_ObjectIndexer             */
    public $byTimewaitTimeout;

    public function __construct(){
        parent::__construct();
        $this->byName = new Mem_ObjectIndexer();
        $this->byName_ext= new Mem_ObjectIndexer();
        $this->bySPort = new Mem_ObjectIndexer();
        $this->byDPort = new Mem_ObjectIndexer();
        $this->byProtocol = new Mem_ObjectIndexer();
        $this->byProtocolDPort = new Mem_ObjectIndexer();
        $this->byTimeout = new Mem_ObjectIndexer();
        $this->byHalfcloseTimeout = new Mem_ObjectIndexer();
        $this->byTimewaitTimeout = new Mem_ObjectIndexer();
    }



}