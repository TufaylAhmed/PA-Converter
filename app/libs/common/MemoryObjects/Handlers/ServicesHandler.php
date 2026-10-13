<?php
/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: $today.year.hour.minute
 ******************************************************************************/

namespace PaloAltoNetworks\Expedition\MemoryObjects\Handlers;

require_once INC_ROOT.'/libs/common/MemoryObjects/QueryResults.php';
use PaloAltoNetworks\Expedition\MemoryObjects\MemoryObjectsHandler;
use PaloAltoNetworks\Expedition\MemoryObjects\QueryResults;

class ServicesHandler
{
    private $memoryObjectsHanlder;

    public function __construct(MemoryObjectsHandler $memoryObjectsHandler)
    {
        $this->memoryObjectsHanlder = $memoryObjectsHandler;
    }

    public function groupBy(ARRAY $fields)
    {
        $results = array();
        $queryResult = new QueryResults();

        //$byNameIndexes = ($this->memoryObjectsHanlder->memorySpace()->services->byName->getIndexes());
        //$byProtocol = ($this->memoryObjectsHanlder->memorySpace()->services->byProtocol->getIndexes());
        //$byDPort = ($this->memoryObjectsHanlder->memorySpace()->services->byDPort->getIndexes());
        //$bySPort = ($this->memoryObjectsHanlder->memorySpace()->services->bySPort->getIndexes());
        //$byProtocolDPort = ($this->memoryObjectsHanlder->memorySpace()->services->byProtocolDPort->getIndexes());
        //$byTimeout = ($this->memoryObjectsHanlder->memorySpace()->services->byTimeout->getIndexes());
        //$byHalfcloseTimeout = ($this->memoryObjectsHanlder->memorySpace()->services->byHalfcloseTimeout->getIndexes());
        //$byTimewaitTimeout = ($this->memoryObjectsHanlder->memorySpace()->services->byTimewaitTimeout->getIndexes());

        $services = ($this->memoryObjectsHanlder->memorySpace()->services->ids);
        //echo "services:\n";
        //print_r($services);
        //echo "Fields: \n";
        //print_r($fields);
        foreach ($services as $id => $service){
            $subIndexes = array();

            foreach ($fields as $field){

                if (isset($service[$field])) {
                    $subIndexes[] = "\"$field\":\"" . $service[$field] . "\"";
                } else {
                    $subIndexes[] = "\"$field\":\"\"";
                }

            }
            $index = "{".implode(",",$subIndexes)."}";

            //echo "Index: " .$index. "\n";
            $results[$index][$service['id']] = $service;

        }

        foreach ($results as $paramsJSON => $services){
            $params = json_decode($paramsJSON,true);
            $queryResult->addResult($params, $services);
        }

        return $queryResult;
    }
}