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

class RegionsHandler
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

        //$byNameIndexes = ($this->memoryObjectsHanlder->memorySpace()->regions->byName->getIndexes());
        //$byLatitude = ($this->memoryObjectsHanlder->memorySpace()->regions->byLatitude->getIndexes());
        //$byLongitude = ($this->memoryObjectsHanlder->memorySpace()->regions->byLongitude->getIndexes());
        //$byAddress = ($this->memoryObjectsHanlder->memorySpace()->regions->byAddress->getIndexes());

        $regions = ($this->memoryObjectsHanlder->memorySpace()->regions->ids);
        //echo "regions:\n";
        //print_r($regions);
        //echo "Fields: \n";
        //print_r($fields);
        foreach ($regions as $id => $region){
            $subIndexes = array();

            foreach ($fields as $field){

                if (isset($region[$field])) {
                    $subIndexes[] = "\"$field\":\"" . $region[$field] . "\"";
                } else {
                    $subIndexes[] = "\"$field\":\"\"";
                }

            }
            $index = "{".implode(",",$subIndexes)."}";

            //echo "Index: " .$index. "\n";
            $results[$index][$region['id']] = $region;

        }

        foreach ($results as $paramsJSON => $regions){
            $params = json_decode($paramsJSON,true);
            $queryResult->addResult($params, $regions);
        }

        return $queryResult;
    }
}