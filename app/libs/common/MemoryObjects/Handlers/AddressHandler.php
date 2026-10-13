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

class AddressHandler
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
//        $byIp = ($this->memoryObjectsHanlder->memorySpace()->address->byIP->getIndexes());
//        $bYCidr = ($this->memoryObjectsHanlder->memorySpace()->address->byCidr->getIndexes());

        $addresses = ($this->memoryObjectsHanlder->memorySpace()->address->ids);

        foreach ($addresses as $id=>$address){
            $subIndexes = array();
            foreach ($fields as $field){
                if($field == 'cidr'){
                    $cidr = ($address[$field]==''||$address[$field]=='0')?'32':$address[$field];
                    $subIndexes[] = "\"cidr\":$cidr";
                }
                else {
                    if (isset($address[$field])) {
                        $subIndexes[] = "\"$field\":\"" . $address[$field] . "\"";
                    } else {
                        $subIndexes[] = "\"$field\":\"\"";
                    }
                }
            }
            $index = "{".implode(",",$subIndexes)."}";

            $results[$index][$address['id']] = $address;

        }

        foreach ($results as $paramsJSON=>$addresses){
            $params = json_decode($paramsJSON,true);
            $queryResult->addResult($params, $addresses);
        }

        return $queryResult;
    }
}