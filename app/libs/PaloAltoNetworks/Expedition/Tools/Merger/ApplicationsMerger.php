<?php
/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: $today.year.hour.minute
 ******************************************************************************/

namespace PaloAltoNetworks\Expedition\Tools\Merger;

use PaloAltoNetworks\Expedition\MemoryObjects\Response;

class ApplicationsMerger extends ObjectMerger
{
    protected $groupByFields;

    public function getInfoByIDs(array $ids):Response{
        return new Response(true, 0, json_encode($this->memoryObjectHandler->getApplications($ids)));
    }

    public function __construct(STRING $project, INT $userID, STRING $source)
    {
        parent::__construct($project, $userID, $source);
        $this->queryGetRepresentativeID = "SELECT member_lid FROM tools_results WHERE table_name = 'applications' AND source = '$this->source' AND user_id = '$this->userID';";
        $this->targetField = 'applications';
    }

    protected function loadObjects(): bool
    {
        /** @var $response Response*/
        $response = $this->memoryObjectHandler->loadApplications($this->projectdb, $this->selectedIDs);
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

    protected function updatePrimaries(): bool
    {
        // TODO: Implement updatePrimaries() method.
        foreach ($this->groups as &$group){
            if($group['mergeable']) {
                $primaryID = $group['primary'];

                //Collect the descriptions of all the members to be merged
                $description = array();

                $description[] = $group["$this->targetField"."_list"][$primaryID]['description']; //The description from the remaining object
                foreach ($group["$this->targetField"."_list"] as $memberID => $groupMember) {
                    if ($memberID != $primaryID) {
                        $description[] = $groupMember['description']; //The description for all the other members
                    }
                }

                //Check if any is used
                $used = 0;
                foreach ($group["$this->targetField"."_list"] as $memberID => $groupMember) {
                    if($groupMember['used'] == 1){
                        $used = 1;
                        continue;
                    }
                }

                //Collect the used tags

                $allDescription = array_filter(array_unique($description)); //Remove duplicate descriptions
                $final_description = implode(",", $allDescription);
                $final_description = truncate_descriptions($final_description, $this->version);

                $query = "UPDATE applications set vsys='" . $group['vsys'] . "', description='$final_description', used='$used' WHERE id='" . $primaryID . "';";
                $this->projectdb->query($query);
            }
        }

        $success = true;
        return $success;
    }

    protected function updateDuplicates(): bool
    {
        foreach ($this->groups as &$group){
            if($group['mergeable']) {
                $updateObjectsReferences = array();
                foreach ($group["$this->targetField"."_list"] as $memberID => $member) {
                    if ($memberID != $group['primary']) {
                        $updateObjectsReferences[] = $memberID;
                    }
                }
                updateMemberLidBulks($this->projectdb, $group['primary'], $updateObjectsReferences, "applications");
            }
        }
        $success = true;
        return $success;
    }

    protected function cleanDuplicatesUsages(): bool
    {
        cleanDuplicatedUsages("security_rules_app", "applications");
        cleanDuplicatedUsages("applications_groups", "applications");

        cleanDuplicatedUsages("pbf_rules_app", "applications");
        cleanDuplicatedUsages("qos_rules_app", "applications");
        cleanDuplicatedUsages("tunnel_inspect_rules_app", "applications");

        $success = true;
        return $success;
    }

}