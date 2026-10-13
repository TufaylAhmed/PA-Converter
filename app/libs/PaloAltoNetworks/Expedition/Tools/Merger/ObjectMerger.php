<?php
/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: $today.year.hour.minute
 ******************************************************************************/

namespace PaloAltoNetworks\Expedition\Tools\Merger;

require_once INC_ROOT.'/libs/common/MemoryObjects/MemoryObjectsHandler.php';
use PaloAltoNetworks\Expedition\MemoryObjects\MemoryObjectsHandler;
use PaloAltoNetworks\Expedition\MemoryObjects\Response;

require_once INC_ROOT . '/libs/projectdb.php';


abstract class ObjectMerger
{

    protected $memoryObjectHandler;

    /** @var \MySQLi */
    protected $projectdb;

    /** @var string */
    protected $projectName;

    /** @var int  */
    protected $userID;

    /** @var array */
    protected $selectedIDs;

    /** @var array */
    protected $groups;

    /** @var bool|float|int|string  */
    protected $version;

    /** @var STRING  */
    protected $source;

    /** @var INT */
    protected $representativeID;


    protected $queryGetRepresentativeID;

    /** @var array */
    protected $vsysesMapping;

    /** @var string */
    protected $targetField;

    protected $mergedTagId;

    public function __construct(STRING $project, INT $userID, STRING $source)
    {
        $this->memoryObjectHandler = new MemoryObjectsHandler();
        $this->projectName = $project;
        $this->projectdb = selectDatabase($project);
        $this->userID = $userID;
        $this->source = $source;

        $this->version = calcVersion($source);

        $this->init();
    }

    private function init(){
        $this->selectedIDs = array();
    }

    public function setSelection(ARRAY $selectedIDs){
        $this->selectedIDs = $selectedIDs;
    }

    public function take_snapshot(){
        take_snapshot_last($this->projectName);
    }

    public function merge(ARRAY $selection=null){

        $this->take_snapshot();
        $this->getSelectedIDs($selection);
        $this->loadObjects();
        $this->groupObjects();
        $this->getPrimaries();
        //echo "ObjectMerger.php 89 ".date("Y-m-d h:i:sa").": Update Primaries\n";
        $this->updatePrimaries();
        //echo "ObjectMerger.php 91 ".date("Y-m-d h:i:sa").": Update Duplicates\n";
        $this->updateDuplicates();
        //echo "ObjectMerger.php 93 ".date("Y-m-d h:i:sa").": Deleting duplicate objects\n";
        $this->deleteDuplicates();
        $this->cleanDuplicatesUsages();

        //TODO: Provide PANOSAddress that are dummy and have not been merged so we can give the feedback
//        $objectsInfo = $this->getInfoByIDs($this->getNonDeleteables());
//        print_r($objectsInfo);

//        return $objectsInfo;
    }

    protected function getMergedTag():int{
        if(!isset($this->mergedTagId))
        {
            $queryMergedTag = "SELECT id FROM tag WHERE name LIKE 'merged' AND source ='$this->source' AND vsys='shared' LIMIT 1";
            $resultMergedTag = $this->projectdb->query($queryMergedTag);
            if ($resultMergedTag->num_rows == 1) {
                $data = $resultMergedTag->fetch_assoc();
                $tagMergedID = $data['id'];
            } else {
                $this->projectdb->query("INSERT INTO tag (name, comments, source, vsys, dummy, used, devicegroup, color) VALUES ('merged', 'Objecte created from a Merge action', '$this->source', 'shared', '0', '1','Expedition','color1')");
                $tagMergedID = $this->projectdb->insert_id;
            }
            $this->mergedTagId = $tagMergedID;
        }

        return $this->mergedTagId;
    }

    abstract protected function loadObjects():bool;
    abstract protected function updatePrimaries():bool;
    abstract protected function updateDuplicates():bool;
    abstract protected function cleanDuplicatesUsages():bool;
    abstract protected function getInfoByIDs(array $ids):Response;

    protected function getNonDeleteables(){
        return [];
    }

    protected function deleteDuplicates(): bool
    {
        $exceptions = $this->getNonDeleteables();

        $removeObjects = array();
        if(isset($this->groups)) {
            foreach ($this->groups as &$group) {
                if ($group['mergeable']) {
                    foreach ($group["$this->targetField" . "_list"] as $memberID => $member) {
                        if ($memberID != $group['primary'] && !in_array($memberID, $exceptions)) {
                            $removeObjects[] = $memberID;
                        }
                    }

                }
            }
            $deleteQuery = "DELETE FROM $this->targetField where id in (" . implode(",", $removeObjects) . ")";
            $this->projectdb->query($deleteQuery);
        }
        $success = true;
        return $success;
    }

    protected function groupObjects():bool
    {
        //echo "Target field en la function groupObjects: " .$this->targetField. "\n";
        $results = $this->memoryObjectHandler->{$this->targetField}->groupBy($this->groupByFields);

        foreach ($results->results as $group){
            $this->groups[] = [
                "$this->targetField"."_list" => $group->ids
            ];
        }

        //echo "GROUPS: \n";
        //print_r($this->groups);
        if(count($this->groups)>0){
            $success = true;
        }
        else{
            $success = false;
        }
        return $success;

    }

    protected function getPrimaries(): bool
    {
        if (isset($this->groups)) {
            foreach ($this->groups as &$group) {
            //Check if we have one single primary
            $primariesID = array();
            foreach ($group["$this->targetField" . "_list"] as $member) {
                if ($member['merge_as_primary'] == 1) {
                    $primariesID[] = $member['id'];
                }
            }

            if (count($primariesID) == 1) {
                $primaryID = $primariesID[0];
            } else {
                $primaryID = null;
                $primaryLevel = INF;
                //foreach ($group["$this->targetField" . "_list"] as &$member) {
                foreach ($group["$this->targetField" . "_list"] as $member) {
                    //Check the vsyses
                    if (!isset($this->vsysesMapping[$member['vsys']])) {
                        $this->vsysesMapping[$member['vsys']] = getVsyses($this->projectdb, $member['vsys'], $member['source']);
                    }
                    $member['vsyses'] = $this->vsysesMapping[$member['vsys']];
                    $member['maxVsys'] = count($member['vsyses']);
                    //Check if this is the most global member
                    if ($member['maxVsys'] < $primaryLevel) {
                        $primaryLevel = $member['maxVsys'];
                        $primaryID = $member['id'];
                    }
                }
            }

            $group['primary'] = $primaryID;

            //Verify that the vsys is global to all the members
            $validVsys = $this->identifyTargetVsys($group["$this->targetField" . "_list"], $primaryID);

            if (!is_null($validVsys)) {
                $group['vsys'] = $validVsys;
                $group['mergeable'] = true;
            } else {
                $group['vsys'] = '';
                $group['mergeable'] = false;
            }
        }
        }
        $success = true;
        return $success;
    }

    protected function getSelectedIDs(ARRAY $selection=null):bool{
        if(!count($this->selectedIDs) > 0) {
            $getResultsTools = $this->projectdb->query($this->queryGetRepresentativeID);

            if ($getResultsTools->num_rows > 0) {
                while ($dataRT = $getResultsTools->fetch_assoc()){
                    if(!is_null($selection) && count($selection)>0) {
                        if ($dataRT['member_lid'] != "" && in_array($dataRT['member_lid'], $selection)) {
                            $this->selectedIDs[] = $dataRT['member_lid'];
                        }
                    }
                    else{
                        if($dataRT['member_lid'] != ""){
                            $this->selectedIDs[] = $dataRT['member_lid'];
                        }
                    }

                }
            }
        }

        if(isset($this->selectedIDs) && count($this->selectedIDs)>0){
            return true;
        }
        return false;
    }

    /**
     * @param array $members
     * @param INT $primaryID
     * @return null|string
     */
    protected function identifyTargetVsys(ARRAY $members, INT $primaryID){
        //Verify which DG is the target to host the address
        //Example
        /*                  shared                                                    shared
         *             ____/      \____                                          ____/      \____
         *         DG1                 DG2(a1)                               DG1 (a1)            DG2
         *        /                 __/   \__                               /                 __/   \__
         *    DG11              DG21(a2)     DG22(a3)                   DG11              DG21(a2)     DG22(a3)
         *
         *         we will use a1 as primary                          we will use a1 as primary, but moved to shared
         */

        //Collect the vsyses
        foreach ($members as &$member) {
            //Check the vsyses
            if (!isset($this->vsysesMapping[$member['vsys']])) {
                $this->vsysesMapping[$member['vsys']] = getVsyses($this->projectdb, $member['vsys'], $member['source']);
            }
            $member['vsyses'] = $this->vsysesMapping[$member['vsys']];
        }

        $inAllVsyses = false;
        $currentVsys ='';
        $empty = false;

        $vsyses = $members[$primaryID]['vsyses'];

        while(!$inAllVsyses && !$empty){
            $missing = false;
            $currentVsys = $vsyses[0];
            foreach ($members as &$member){
                if(!in_array($currentVsys, $member['vsyses'])){
                    array_shift($members[$primaryID]['vsyses']);
                    if(is_null(array_shift($vsyses))){
                        $empty = true;
                    }
                    $missing = true;
                    break;
                }
            }
            if(!$missing) {
                $inAllVsyses = true;
            }
        }

        if(!$inAllVsyses){
            return null;
        }

        return $currentVsys;
    }

}