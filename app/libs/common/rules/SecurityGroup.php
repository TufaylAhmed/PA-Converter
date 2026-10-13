<?php
/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: $today.year.hour.minute
 ******************************************************************************/

namespace PaloAltoNetworks\Policy\Objects;

class SecurityGroup
{
    /*
     * @var $name String
     * @var $securityRules array
     * @var $initialId int
     * @var $tag MemberObject
     * @var $used boolean
     * @var $zoneFrom array
     * @var $zoneTo array
     */
    protected $name;
    protected $securityRules;
    protected $initialID;
    protected $tag;
    protected $used;
    protected $zoneFrom;
    protected $zoneTo;

    public function __construct(STRING $name, BOOL $used = true, INT $initialID=null){
        $this->name = $name;
        $this->initialID = $initialID;
        $this->used = $used;
        $this->zoneFrom = array();
        $this->zoneTo = array();
    }

    public function setZoneFrom(ARRAY $value){
        $this->zoneFrom = $value;
    }

    public function addZoneFrom(STRING $value){
        $this->zoneFrom[] = $value;
    }

    public function setZoneTo(ARRAY $value){
        $this->zoneTo = $value;
    }

    public function addZoneTo(STRING $value){
        $this->zoneTo[] = $value;
    }


    public function getZoneFrom():array{
        return $this->zoneFrom;
    }

    public function getZoneTo():array{
        return $this->zoneTo;
    }

    public function setUsed(){
        $this->used = true;
    }

    public function setUnused(){
        $this->used=false;
    }

    public function getUsed():bool{
        return $this->used;
    }

    public function setInitialID(INT $initialID){
        $this->initialID = $initialID;
    }

    public function getInitialID():int{
        return $this->initialID;
    }

    public function setTag(MemberObject $value){
        if($value->location != '') {
            $this->tag = $value;
        }
    }

    public function getTag():MemberObject{
        return $this->tag;
    }

    public function addRule(SecurityRule $rule, INT $position=null):int{
        if(!isset($rule->comment)){
            $rule->setComment("");
        }


        if(isset($position)){
            $rule->setPosition($position);
            if(!isset($rule->name)){
                $rule->name = substr($this->name, 0, 15) . "_" . $rule->position;
            }
            array_splice($this->securityRules, $position, 0 , $rule);
            return $position;
        }
        else {
            $position = count($this->securityRules)+1;
            $rule->setPosition($position);
            if(!isset($rule->name)){
                $rule->name = substr($this->name, 0, 15) . "_" . $rule->position;
            }
            $this->securityRules[] = $rule;
            return $position+1;
        }
    }

    public function getRules():array {
        $rules = array();

        /* @var $rule SecurityRule */
        if(isset($this->securityRules)) {
            foreach ($this->securityRules as $rule) {
                $rule->globalPosition = $rule->position + $this->initialID;
                $rules[] = $rule;
            }
        }

        return $rules;
    }

    public function getLastRulePosition():int{
        return count($this->securityRules);
    }
}