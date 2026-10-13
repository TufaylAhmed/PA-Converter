<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 18/4/16 - 11:34
 */

namespace PaloaltoNetworks\Policy\Objects;

use PaloAltoNetworks\Policy\Objects\MemberObject;

class CompleteSecRuleObject {   //FOR SEC or NAT RULES
    private $lid;        //rule_lid
    private $name;      //rule_name_int
    private $name_ext;
    private $position;  //position in the policy

    private $negate_source;
    private $negate_destination;
    private $description;
    private $action;
    private $schedule;
    private $disabled;
    private $log_start;
    private $log_end;
    private $log_forwarding;
    private $vsys;
    private $source;
    private $dsri;
    private $target;
    private $checkit;
    private $migrate;
    private $counter;
    private $qos;
    private $profile_type;
    private $profile_group;
    private $qos_value;
    private $tag;
    private $preorpost;
    private $devicegroup;
    private $blocked;
    private $rule_type;
    private $invalid;
    private $modified;
    private $icmp_unreachable;

    private $to=array();
    private $sourceMembers=array();
    private $service=array();
    private $application=array();
    private $category=array();
    private $source_user=array();
    private $destination=array();
    private $profileParameters=array();
    private $from=array();
    private $tags=array();

    public function printRuleObject() {
        var_dump(get_object_vars($this));
    }

    public function __construct()
    {
        $a = func_get_args();
        $i = func_num_args();
        if (method_exists($this,$f='__construct'.$i)) {
            call_user_func_array(array($this,$f),$a);
        }
    }

    private function __construct0()
    {
    }

    private function __construct1($id)
    {
        $this->lid = $id;
    }

    private function __construct2($id, $name)
    {
        $this->name = $name;
        $this->lid = $id;
    }

    public function setParamenters($parameters){
        foreach ($parameters as $key=>$value){
            $this->$key = $value;
        }
    }

    public function setParamenter(ARRAY $parameter){
        foreach ($parameter as $key=>$value){
            switch ($key){
                case "source":
                    $this->sourceMembers[] = $value;
                    break;
                case "tag":
                    $this->tags[] = $value;
                    break;

                case "url-filtering":
                case "file-blocking":
                case "wildfire-analysis":
                case "spyware":
                case "vulnerability":
                case "virus":
                    $this->profileParameters[$key]= $value;
                    break;

                case "source-user":
                    $key=str_replace("-","_",$key);

                case "category":
                case "service":
                case "destination":
                case "to":
                case "from":
                case "application":
                    $this->{$key}[] = $value;
                    break;
                default:
                    echo "Parameter $key is not supported in CompleteSecRuleObject.php@setParameter()\n";
            }
        }
    }

    public function getSourceMembers(){
        return $this->sourceMembers;
    }

    public function getDestinationMembers(){
        return $this->destination;
    }

    public function getServices(){
        return $this->service;
    }

    public function getCategories(){
        return $this->category;
    }

    public function getSourceUsers(){
        return $this->source_user;
    }

    public function getProfileParameters(){
        return $this->profileParameters;
    }

    public function getApplications(){
        return $this->application;
    }

    public function getFrom(){
        return $this->from;
    }

    public function getTo(){
        return $this->to;
    }

    public function getTags(){
        return $this->tags;
    }

    /**
     * @return mixed
     */
    public function getLid()
    {
        return $this->lid;
    }

    /**
     * @param mixed $lid
     */
    public function setLid($lid)
    {
        $this->lid = $lid;
    }

    /**
     * @return mixed
     */
    public function getName()
    {
        return $this->name;
    }

    /**
     * @param mixed $name
     */
    public function setName($name)
    {
        $this->name = $name;
    }

    /**
     * @return mixed
     */
    public function getPosition()
    {
        return $this->position;
    }

    /**
     * @param mixed $position
     */
    public function setPosition($position)
    {
        $this->position = $position;
    }

    /**
     * @return mixed
     */
    public function getNegateSource()
    {
        return $this->negate_source;
    }

    /**
     * @param mixed $negate_source
     */
    public function setNegateSource($negate_source)
    {
        $this->negate_source = $negate_source;
    }

    /**
     * @return mixed
     */
    public function getNegateDestination()
    {
        return $this->negate_destination;
    }

    /**
     * @param mixed $negate_destination
     */
    public function setNegateDestination($negate_destination)
    {
        $this->negate_destination = $negate_destination;
    }

    /**
     * @return mixed
     */
    public function getDescription()
    {
        return $this->description;
    }

    /**
     * @param mixed $description
     */
    public function setDescription($description)
    {
        $this->description = $description;
    }

    /**
     * @return mixed
     */
    public function getAction()
    {
        return $this->action;
    }

    /**
     * @param mixed $action
     */
    public function setAction($action)
    {
        $this->action = $action;
    }

    /**
     * @return mixed
     */
    public function getSchedule()
    {
        return $this->schedule;
    }

    /**
     * @param mixed $schedule
     */
    public function setSchedule($schedule)
    {
        $this->schedule = $schedule;
    }

    /**
     * @return mixed
     */
    public function getDisabled()
    {
        return $this->disabled;
    }

    /**
     * @param mixed $disabled
     */
    public function setDisabled($disabled)
    {
        $this->disabled = $disabled;
    }

    /**
     * @return mixed
     */
    public function getLogStart()
    {
        return $this->log_start;
    }

    /**
     * @param mixed $log_start
     */
    public function setLogStart($log_start)
    {
        $this->log_start = $log_start;
    }

    /**
     * @return mixed
     */
    public function getLogEnd()
    {
        return $this->log_end;
    }

    /**
     * @param mixed $log_end
     */
    public function setLogEnd($log_end)
    {
        $this->log_end = $log_end;
    }

    /**
     * @return mixed
     */
    public function getLogForwarding()
    {
        return $this->log_forwarding;
    }

    /**
     * @param mixed $log_forwarding
     */
    public function setLogForwarding($log_forwarding)
    {
        $this->log_forwarding = $log_forwarding;
    }

    /**
     * @return mixed
     */
    public function getVsys()
    {
        return $this->vsys;
    }

    /**
     * @param mixed $vsys
     */
    public function setVsys($vsys)
    {
        $this->vsys = $vsys;
    }

    /**
     * @return mixed
     */
    public function getSource()
    {
        return $this->source;
    }

    /**
     * @param mixed $source
     */
    public function setSource($source)
    {
        $this->source = $source;
    }

    /**
     * @return mixed
     */
    public function getDsri()
    {
        return $this->dsri;
    }

    /**
     * @param mixed $dsri
     */
    public function setDsri($dsri)
    {
        $this->dsri = $dsri;
    }

    /**
     * @return mixed
     */
    public function getTarget()
    {
        return $this->target;
    }

    /**
     * @param mixed $target
     */
    public function setTarget($target)
    {
        $this->target = $target;
    }

    /**
     * @return mixed
     */
    public function getCheckit()
    {
        return $this->checkit;
    }

    /**
     * @param mixed $checkit
     */
    public function setCheckit($checkit)
    {
        $this->checkit = $checkit;
    }

    /**
     * @return mixed
     */
    public function getMigrate()
    {
        return $this->migrate;
    }

    /**
     * @param mixed $migrate
     */
    public function setMigrate($migrate)
    {
        $this->migrate = $migrate;
    }

    /**
     * @return mixed
     */
    public function getCounter()
    {
        return $this->counter;
    }

    /**
     * @param mixed $counter
     */
    public function setCounter($counter)
    {
        $this->counter = $counter;
    }

    /**
     * @return mixed
     */
    public function getQos()
    {
        return $this->qos;
    }

    /**
     * @param mixed $qos
     */
    public function setQos($qos)
    {
        $this->qos = $qos;
    }

    /**
     * @return mixed
     */
    public function getProfileType()
    {
        return $this->profile_type;
    }

    /**
     * @param mixed $profile_type
     */
    public function setProfileType($profile_type)
    {
        $this->profile_type = $profile_type;
    }

    /**
     * @return mixed
     */
    public function getProfileGroup()
    {
        return $this->profile_group;
    }

    /**
     * @param mixed $profile_group
     */
    public function setProfileGroup($profile_group)
    {
        $this->profile_group = $profile_group;
    }

    /**
     * @return mixed
     */
    public function getQosValue()
    {
        return $this->qos_value;
    }

    /**
     * @param mixed $qos_value
     */
    public function setQosValue($qos_value)
    {
        $this->qos_value = $qos_value;
    }

    /**
     * @return mixed
     */
    public function getTag()
    {
        return $this->tag;
    }

    /**
     * @param mixed $tag
     */
    public function setTag($tag)
    {
        $this->tag = $tag;
    }

    /**
     * @return mixed
     */
    public function getPreorpost()
    {
        return $this->preorpost;
    }

    /**
     * @param mixed $preorpost
     */
    public function setPreorpost($preorpost)
    {
        $this->preorpost = $preorpost;
    }

    /**
     * @return mixed
     */
    public function getDevicegroup()
    {
        return $this->devicegroup;
    }

    /**
     * @param mixed $devicegroup
     */
    public function setDevicegroup($devicegroup)
    {
        $this->devicegroup = $devicegroup;
    }

    /**
     * @return mixed
     */
    public function getBlocked()
    {
        return $this->blocked;
    }

    /**
     * @param mixed $blocked
     */
    public function setBlocked($blocked)
    {
        $this->blocked = $blocked;
    }

    /**
     * @return mixed
     */
    public function getRuleType()
    {
        return $this->rule_type;
    }

    /**
     * @param mixed $rule_type
     */
    public function setRuleType($rule_type)
    {
        $this->rule_type = $rule_type;
    }

    /**
     * @return mixed
     */
    public function getInvalid()
    {
        return $this->invalid;
    }

    /**
     * @param mixed $invalid
     */
    public function setInvalid($invalid)
    {
        $this->invalid = $invalid;
    }

    /**
     * @return mixed
     */
    public function getModified()
    {
        return $this->modified;
    }

    /**
     * @param mixed $modified
     */
    public function setModified($modified)
    {
        $this->modified = $modified;
    }

    /**
     * @return mixed
     */
    public function getIcmpUnreachable()
    {
        return $this->icmp_unreachable;
    }

    /**
     * @param mixed $icmp_unreachable
     */
    public function setIcmpUnreachable($icmp_unreachable)
    {
        $this->icmp_unreachable = $icmp_unreachable;
    }





}