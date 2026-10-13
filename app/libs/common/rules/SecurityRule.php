<?php
/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: $today.year.hour.minute
 ******************************************************************************/

namespace PaloAltoNetworks\Policy\Objects;

require_once INC_ROOT.'/libs/common/ResponseCode.php';
use \PaloAltoNetworks\Expedition\ResponseCode;

class SecurityRule
{
    /* @var $name string */
    /* @var $originalName string */
    /* @var $position int */
    /* @var $comment string */
    /* @var $action string */
    /* @var $protocol array */
    /* @var $source string */
    /* @var $destination string */
    /* @var $service string */
    /* @var $disabled boolean */
    /* @var $tag array */
    public $ruleString;
    public $name;
    public $originalName;
    public $position;
    public $globalPosition;
    public $comment;
    public $action;
    public $protocol;
    public $zoneFrom;
    public $user;
    public $userType;
    public $source;
    public $sourceType;
    public $sourcePort;
    public $sourcePortType;
    public $zoneTo;
    public $destination;
    public $destinationType;
    public $service;
    public $serviceTimeout;
    public $serviceType;
    public $application;
    public $disabled;
    public $tag;

    public $isFirepower=0;
    public $firepowerId;

    public $logs;

    protected $fields = ['name', 'user', 'source', 'destination', 'service', 'sourcePort', 'application', 'tag', 'comment', 'action', 'protocol','zoneFrom','zoneTo'];
    protected $cloningFields = ['ruleString','name','position','globalPosition','comment','action','protocol','zoneFrom','user','userType','source','sourceType','sourcePort','sourcePortType','zoneTo','destination','destinationType','service','serviceType','application','disabled','tag', ];


    public function __construct(){
        $this->disabled = 0;
    }

    public function __clone(){
        $this->name = $this->name."b";
    }

    public function addLog(STRING $logType, STRING $task, STRING $message, STRING $action){
//        add_log2('warning',
//            'Reading Security Policies',
//            'Security RuleID [' . $newRule->position . '] is using an interval field with value [' . $interval . ']. This field has not been migrated', $source,
//            'Interval logging is not ',
//            'rules',
//            $newRule->position,
//            'security_rules');
        $this->logs[] = [
            'logType'   => $logType,
            'task'      => $task,
            'message'   => $message,
            'action'    => $action
        ];
    }

//    function __clone(){
//        // Force a copy of this->object, otherwise it will point to same object.
//        foreach ($this->cloningFields as $field){
//            $this->{$field} = clone $this->{$field};
//        }
//    }

    public function addApplication(MemberObject $value){
        $this->application[] = $value;
    }

    public function addApplications(ARRAY $apps){
        $this->application = array_merge($this->application, $apps);
    }

    public function setApplications (ARRAY $values){
        $this->application = $values;
    }

    public function setIsFirepower(int $value){
        $this->isFirepower=$value;
    }

    public function setFirepowerId(STRING $value){
        $this->firepowerId = $value;
    }

    public function setRuleString(STRING $rule){
        $this->ruleString = $rule;
    }

    public function setUser(ARRAY $value){
        $this->user = $value;
        return new ResponseCode(true, 0, 'User filled in correctly');
    }

    public function setSourcePort(ARRAY $value){
        $this->sourcePort = $value;
        return new ResponseCode(true, 0, 'SourcePort filled in correctly');
    }

    public function setSource(MemberObject $value){
        $this->source = $value;
        return new ResponseCode(true, 0, 'Source filled in correctly');
    }

    public function setDestination(MemberObject $value){
        $this->destination = $value;
        return new ResponseCode(true, 0, 'Destination filled in correctly');
    }

    public function setTimeout(INT $timeout=null){
        $this->serviceTimeout = $timeout;
    }

    /***
     * Defines the value that the service should have for later being able to search it
     * @param array $value
     * @return ResponseCode
     */
    public function setService(ARRAY $value){
        $this->service = $value;
        return new ResponseCode(true, 0, 'Service filled in correctly');
    }

    public function addService(MemberObject $service){
        $this->service[] = $service;
        return new ResponseCode(true, 0, 'Service added correctly');
    }

    public function setName(STRING $name){
        $this->name = $name;
        return new ResponseCode(true, 0, 'Name filled in correctly');
    }

    public function setOriginalName(STRING $name){
        $this->originalName = $name;
        return new ResponseCode(true, 0, 'Name filled in correctly');
    }


    public function addTag(MemberObject $tag){
        if($tag->location != '') {
            $this->tag[] = $tag;
            return new ResponseCode(true, 0, 'Tag included correctly');
        }
        return new ResponseCode(false, -1, 'Not a valid tag');
    }

    public function setZoneFrom(ARRAY $name=null){
        $this->zoneFrom=$name;
        return new ResponseCode(true, 0, 'Zone From filled in correctly');
    }

    public function addZoneFrom(STRING $value){
        $this->zoneFrom[] = $value;
        return new ResponseCode(true, 0, 'Zone From added correctly');
    }

    public function setZoneTo(ARRAY $name=null){
        $this->zoneTo=$name;
        return new ResponseCode(true, 0, 'Zone To filled in correctly');
    }

    public function addZoneTo(STRING $value){
        $this->zoneTo[] = $value;
        return new ResponseCode(true, 0, 'Zone To added correctly');
    }

    public function getZoneFrom():array{
        return $this->zoneFrom;
    }

    public function getIsFirepower():int{
        return $this->isFirepower;
    }
    public function getFirepowerId():string{
        if ($this->firepowerId==null){
            $this->setFirepowerId('0');
        }
        else{
            return $this->firepowerId;
        }
    }

    public function getZoneTo():array{
        return $this->zoneTo;
    }

    public function setAction(STRING $action){
        $this->action = $action;
        return new ResponseCode(true, 0, 'Action filled in correctly');
    }

    public function setProtocol(ARRAY $protocols){
        $this->protocol = array();
//        if(is_null($protocols) || count($protocols)==0){
//            $this->protocol = array();
//        }
//        else {
            foreach ($protocols as $protocol) {
                $this->protocol[$protocol] = $protocol;
            }
//        }
        return new ResponseCode(true, 0, 'Protocol filled in correctly');
    }

    public function setPosition(INT $position){
        $this->position = $position;
        return new ResponseCode(true, 0, 'Position filled in correctly');
    }

    public function setComment(STRING $comment){
        if(!$comment == '') {
            if (!isset($this->comment)) {
                $this->comment = $comment;
                return new ResponseCode(true, 0, 'Comment filled in correctly');
            }
            else {
                $this->comment .= " " . $comment;
                return new ResponseCode(true, 0, 'Comment correctly extended');
            }
        }
        return new ResponseCode(true, 0, 'No Comment to add');
    }

    public function addComment(STRING $comment){
        return $this->setComment($comment);
    }

    public function setRemmark(STRING $comment){
        return $this->setComment($comment);
    }

    public function setDisabled(){
        $this->disabled = true;
        return new ResponseCode(true, 0,  'Disabled setted');
    }

    public function getRule() : array {
        return [
            'name'          => $this->name,
            'position'      => $this->position,
            'comment'       => $this->comment,
            'action'        => $this->action,
            'source'        => $this->source,
            'destination'   => $this->destination,
            'service'       => $this->service,
            'protocol'      => $this->protocol,
            'disabled'      => $this->disabled,
        ];
    }

    public function isValid(){
        if(!isset($this->source) ||
            !isset($this->destination) ||
//            !isset($this->protocol) ||
//            !isset($this->port) ||
            !isset($this->action)
        )
            return false;

        return true;
    }

    public function getMissingFields(){
        $missingFields = array();
        foreach ($this->fields as $field){
            if(!isset($this->{$field})){
                $missingFields[] = $field;
            }
        }
        return $missingFields;
    }


}