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

class ApplicationsHandler
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

//        $byNameIndexes = ($this->memoryObjectsHanlder->memorySpace()->address->byName->getIndexes());

        $applications = ($this->memoryObjectsHanlder->memorySpace()->applications->ids);

        foreach ($applications as $id => $app){
            $subIndexes = array();

            foreach ($fields as $field){

                if (isset($app[$field])) {
                    $subIndexes[] = "\"$field\":\"" . $app[$field] . "\"";
                } else {
                    $subIndexes[] = "\"$field\":\"\"";
                }

            }
            $index = "{".implode(",",$subIndexes)."}";

            //echo "Index: " .$index. "\n";
            $results[$index][$app['id']] = $app;

        }

        foreach ($results as $paramsJSON => $applications){
            $params = json_decode($paramsJSON,true);
            $queryResult->addResult($params, $applications);
        }

        return $queryResult;
    }
}