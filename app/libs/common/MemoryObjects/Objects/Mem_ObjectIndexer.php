<?php
/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: $today.year.hour.minute
 ******************************************************************************/

namespace PaloAltoNetworks\Expedition\MemoryObjects;

class Mem_ObjectIndexer{
    /** @var array  */
    private $indexes;

    public function __construct()
    {
        $this->indexes = array();
    }

    public function addIndex($key, INT $index){
        $this->indexes[$key][] = $index;
    }

    public function searchByIndex($key):array{
        return $this->indexes[$key];
    }

    public function getIndexes():array{
        return array_keys($this->indexes);
    }

    public function exists(STRING $key):BOOL{
        return isset($this->indexes[$key]);
    }

    public function getDuplicates(){

    }

    public function getEmpty(){

    }

}