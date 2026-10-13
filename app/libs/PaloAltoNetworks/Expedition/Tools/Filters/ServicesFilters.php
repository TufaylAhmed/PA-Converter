<?php
/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: $today.year.hour.minute
 ******************************************************************************/

namespace PaloAltoNetworks\Expedition\Tools\Filters;

use PaloAltoNetworks\Expedition\MemoryObjects\Response;

class ServicesFilters extends ObjectFilters
{
    protected $groupByFields;

    public function __construct(STRING $project, INT $userID, STRING $source)
    {
        parent::__construct($project, $userID, $source);
        $this->queryGetRepresentativeID = "SELECT member_lid FROM tools_results WHERE table_name = 'services' AND source = '$this->source' AND user_id = '$this->userID';";
        $this->targetField = 'services';
    }

    protected function loadObjects(): bool
    {
        /** @var $response Response*/
        $response = $this->memoryObjectHandler->loadServices($this->projectdb,$this->selectedIDs);
        if($response->success) {
            $response = $this->memoryObjectHandler->loadTags($this->projectdb);
        }
        if($response->success) {
            $response = $this->memoryObjectHandler->loadTagRelations($this->projectdb);
        }

        if($response->success)       return true;
        else                         return false;
    }

    public function setMergerByFields(ARRAY $fields){
        $this->groupByFields = $fields;
    }


}