<?php

/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: $today.year.hour.minute
 ******************************************************************************/
require_once INC_ROOT.'/libs/objects/PANObject.php';
require_once INC_ROOT.'/libs/common/lib-objects.php';

class SecurityRuleObject extends Object{
    protected $id;
    protected $position;
    protected $name_ext;
    protected $name;
    protected $negate_source;
    protected $negate_destination;
    protected $description;
    protected $action;
    protected $schedule;
    protected $disabled;
    protected $log_start;
    protected $log_end;
    protected $log_forwarding;
    protected $vsys;
    protected $lid;
    protected $source;
    protected $dsri;
    protected $target;
    protected $checkit;
    protected $migrate;
    protected $counter;
    protected $qos;
    protected $profile_type;
    protected $profile_group;
    protected $qos_value;
    protected $tag;
    protected $preorpost;
    protected $devicegroup;
    protected $blocked;
    protected $rule_type;
    protected $invalid;
    protected $modified;
    protected $icmp_unreachable;
    protected $dummy;

    protected $secrulesfrom = array();
    protected $secrulesto = array();
    protected $secrulestag = array();
    protected $secrulesusr = array();
    protected $secrulescategories = array();
    protected $secruleship = array();
    protected $secrulessrc = array();
    protected $secrulesdst = array();
    protected $secrulesapp = array();
    protected $secrulessrv = array();
    protected $secrulesprofiles = array();

    /** @var \Mysqli */
    protected $projectDB;


    protected $table = 'security_rules';
    protected $dependent_tables = [
            'security_rules_app','security_rules_categories','security_rules_dst','security_rules_from','security_rules_hip','security_rules_profiles','security_rules_src','security_rules_srv', 'security_rules_tag','security_rules_to','security_rules_usr'
    ];
    protected $fillable = [
        'id','position','name_ext','name','negate_source','negate_destination','description','action','schedule','disabled','log_start','log_end','log_forwarding','vsys','lid','source','dsri','target','checkit','migrate','counter','qos','profile_type','profile_group','qos_value','tag','preorpost','devicegroup','blocked','rule_type','invalid','modified','icmp_unreachable','dummy',
        'secrulesfrom', 'secrulesto', 'secrulestag', 'secrulesusr', 'secrulescategories', 'secruleship', 'secrulessrc', 'secrulesdst', 'secrulesapp', 'secrulessrv', 'secrulesprofiles'
    ];

    public function setSource(STRING $source){
        $this->source = $source;
    }

    public function setVsys(STRING $vsys){
        $this->vsys = $vsys;
    }

    public function setDeviceGroup(STRING $devicegroup){
        $this->devicegroup = $devicegroup;
    }

    public function setPreOrPost($preOrPost){
        $this->preorpost = $preOrPost;
    }

    public function prepareXML(){
        //TODO
        $xml = new SimpleXMLElement('<rule></rule>');
        return $xml;

    }

    public function load(STRING $name_ext, SimpleXMLElement $element=null, STRING $source, STRING $vsys, STRING $devicegroup)
    {
        $this->source = $source;
        $this->vsys = $vsys;
        $this->devicegroup = $devicegroup;
        $this->name_ext = $name_ext;
        $this->name = normalizeNames($name_ext);

        if (is_null($element)) {
            $this->invalid='1';
            $this->dummy='1';
            $this->modified='0';
            $this->checkit='1';
        }
        else {
            $this->invalid = '0';
            $this->dummy = '0';
            $this->modified = '0';
            $this->checkit = '0';


//            $secrulesfrom = array();
//            $secrulesto = array();
//            $secrulestag = array();
//            $secrulesusr = array();
//            $secrulescategories = array();
//            $secruleship = array();
//            $secrulessrc = array();
//            $secrulesdst = array();
//            $secrulesapp = array();
//            $secrulessrv = array();
//            $secrulesprofiles = array();

            $this->qos = "None";
            $this->qos_value = "";
            $this->profile_type = "None";

            $this->action = $element->action;
            $this->icmp_unreachable = (isset($element->{'icmp-unreachable'})) ? $element->{'icmp-unreachable'} : '';
            $this->rule_type = (isset($element->{'rule-type'})) ? $element->{'rule-type'} : 'universal';
            $this->target = (isset($element->target)) ? addslashes($element->target->asXML()) : '';
            $this->negate_source = ($element->{'negate-source'} == "yes") ? 1 : 0;
            $this->negate_destination = ($element->{'negate-destination'} == "yes") ? 1 : 0;
            $this->log_start = ($element->{'log-start'} == "yes") ? 1 : 0;
            $this->log_end = (!isset($element->{'log-end'})) ? 1 : ($element->{'log-end'} == "yes") ? 1 : 0;
            $this->dsri = ($element->option->{'disable-server-response-inspection'} == "yes") ? 1 : 0;
            $this->description = (isset($element->description)) ? addslashes($element->description) : '';
            $this->log_forwarding = (isset($element->{'log-setting'})) ? $element->{'log-setting'} : '';
            $this->schedule = (isset($element->schedule)) ? $element->schedule : '';
            $this->disabled = ($element->disabled == "yes") ? "1" : '0';
            if (isset($element->qos->marking)) {
                foreach ($element->qos->marking as $k => $zone_member) {
                    foreach ($zone_member as $m => $memberA) {
                        if (!(($memberA == "") OR ($memberA == "any"))) {
                            $this->qos = $m;
                            $this->qos_value = $memberA;
                        }
                    }
                }
            }

            if (isset($element->{'profile-setting'})) {
                foreach ($element->{'profile-setting'} as $k => $zone_member) {
                    foreach ($zone_member as $kk => $more) {
                        if ($kk == "group") {
//                            $profile_type = $kk;
                            foreach ($more as $member => $membername) {
                                $this->secrulesprofiles[] = "profiles_groups,,$membername";
                            }
                        } elseif ($kk == "profiles") {
//                            $profile_type = $kk;
                            foreach ($more as $member => $membername) {
                                $type = $member;
                                foreach ($membername as $member2 => $profile) {
                                    $this->secrulesprofiles[] = "profiles,$type,$profile";
                                }
                            }
                        }
                    }
                }
            }

            if (isset($element->tag)) {
                foreach ($element->tag->member as $memberA) {
                    $memberA = (string)$memberA;
                    $this->secrulestag[] = $memberA;
                }
            }
            foreach ($element->from as $k => $zone_member) {
                foreach ($zone_member as $m => $memberA) {
                    $memberA = (string)$memberA;
                    if (($memberA != "") AND ($memberA != "any")) {
                        $this->secrulesfrom[] = $memberA;
                    }
                }
            }
            foreach ($element->to as $k => $zone_member) {
                foreach ($zone_member as $m => $memberA) {
                    $memberA = (string)$memberA;
                    $this->secrulesto[] = $memberA;
                }
            }
            foreach ($element->{'source-user'} as $k => $zone_member) {
                foreach ($zone_member as $m => $memberA) {
                    $memberA = (string)$memberA;
                    $memberB = addslashes($memberA);
                    $this->secrulesusr[] = $memberB;
                }
            }
            foreach ($element->category as $k => $zone_member) {
                foreach ($zone_member as $m => $memberA) {
                    $memberA = (string)$memberA;
                    $this->secrulescategories[] = $memberA;
                }
            }
            foreach ($element->{'hip-profiles'} as $k => $zone_member) {
                foreach ($zone_member as $m => $memberA) {
                    $memberA = (string)$memberA;
                    $this->secruleship[] = $memberA;
                }
            }
            foreach ($element->source->member as $k => $memberA) {
                $memberA = (string)$memberA;
                $this->secrulessrc[] = $memberA;
            }
            foreach ($element->destination->member as $k => $memberA) {
                $memberA = (string)$memberA;
                $this->secrulesdst[] = $memberA;
            }
            foreach ($element->application->member as $k => $memberA) {
                $memberA = (string)$memberA;
                $this->secrulesapp[] = $memberA;
            }
            foreach ($element->service->member as $k => $memberA) {
                $memberA = (string)$memberA;
                $this->secrulessrv[] = $memberA;
            }
//            print_r($this);
        }
    }

    public function loadFromProject(mysqli $connection, STRING $name_ext)
    {
        // TODO: Implement loadFromProject() method.
    }

    public function insert(mysqli $connection, STRING $name_ext){
        if($this->exists($connection, $name_ext)){
            $updateList = $this->fillable;
            foreach($this->ignoreList as $ignoreField) {
                if (($key = array_search($ignoreField, $updateList)) !== false) {
                    unset($updateList[$key]);
                }
            }
            return $this->update($connection, $name_ext, $updateList);
        }
        else {
            global $projectdb;
            $projectdb = $connection;

            $secrulesfrom = array();
            $secrulesto = array();
            $secrulestag = array();
            $secrulesusr = array();
            $secrulescategories = array();
            $secruleship = array();
            $secrulessrc = array();
            $secrulesdst = array();
            $secrulesapp = array();
            $secrulessrv = array();
            $secrulesprofiles = array();

            $getlastlid = $connection->query("SELECT max(id) as max FROM security_rules;")->fetch_assoc();
            $lid = intval($getlastlid['max']) + 1;
            $getlastlid = $connection->query("SELECT max(position) as max FROM security_rules WHERE source='$this->source' AND vsys='$this->vsys' AND preorpost='$this->preorpost';")->fetch_assoc();
            $position = intval($getlastlid['max']) + 1;

            $vsyses = getVsyses($connection, $this->vsys, $this->source);

            foreach ($this->secrulesfrom as $memberA) {
                if (($memberA != "") AND ($memberA != "any")) {
                    $secrulesfrom[] = "('$this->source','$this->vsys','$memberA','$lid','$this->devicegroup')";
                }
            }
            foreach ($this->secrulesto as $memberA) {
                if (($memberA != "") AND ($memberA != "any")) {
                    $secrulesto[] = "('$this->source','$this->vsys','$memberA','$lid','$this->devicegroup')";
                }
            }
            foreach ($this->secrulestag as $memberA) {
                $memberA = (string)$memberA;
                if (($memberA != "") AND ($memberA != "any")) {
                    if (!$tagObject = getTagId($connection, $this->source, $vsyses, $memberA)) {
                        $member = initTag();
                        $member['name_ext'] = $member;
                        $member['name'] = normalizeNames($member);
                        $member['checkit'] = 1;
                        $tagObject = createTagId($connection, $this->source, $this->devicegroup, $this->vsys, $member);
                    }
                    $secrulestag[] = "('$this->source','$this->vsys','$tagObject->location','$tagObject->name','$lid','$this->devicegroup')";
                }
            }
            foreach ($this->secrulesusr as $memberA) {
                if (($memberA != "") AND ($memberA != "any")) {
                    $memberB = addslashes($memberA);
                    $secrulesusr[] = "('$this->source','$this->vsys','$memberB','$lid','$this->devicegroup')";
                }
            }
            foreach ($this->secrulescategories as $memberA) {
                $memberA = (string)$memberA;
                if (($memberA == "") OR ($memberA == "any")) {
                } else {
                    $secrulescategories[] = "('$this->source','$this->vsys','$memberA','$lid','$this->devicegroup')";
                }
            }
            foreach ($this->secruleship as $memberA) {
                if (($memberA == "") OR ($memberA == "any")) {
                } elseif ($memberA == "no-hip") {
                    $secruleship[] = "('$this->source','0','default','$this->vsys','$lid','$this->devicegroup','no-hip')";
                } else {
                    if (!$secProfileObject = getProfileId($connection, $this->source, $vsyses, 'hip-profiles', $memberA)) {
                        $member = initProfile();
                        $member['name_ext'] = $member;
                        $member['name'] = normalizeNames($member);
                        $member['checkit'] = 1;
                        $secProfileObject = createProfileId($connection, $this->source, $this->devicegroup, $this->vsys, $member);
                    }
                    $secruleship[] = "('$this->source','$secProfileObject->name','$secProfileObject->location','$this->vsys','$lid','$this->devicegroup','hip-profiles')";
                }
            }
            foreach ($this->secrulessrc as $memberA) {
                $memberA = (string)$memberA;
                if (($memberA != "") AND ($memberA != "any")) {
                    if (!$memberObject = getMemberId($connection, $this->source, $vsyses, $memberA)) {
                        $member = initAddressMember();
                        $member['name_ext'] = $member;
                        $member['name'] = normalizeNames($member);
                        $member['checkit'] = 1;
                        $memberObject = createAddressMemberId($connection, $this->source, $this->devicegroup, $this->vsys, $member);
                    }
                    $secrulessrc[] = "('$this->source','$this->vsys','$memberObject->location','$memberObject->name','$lid','$this->devicegroup')";
                }
            }
            foreach ($this->secrulesdst as $memberA) {
                $memberA = (string)$memberA;
                if (($memberA != "") AND ($memberA != "any")) {
                    if (!$memberObject = getMemberId($connection, $this->source, $vsyses, $memberA)) {
                        $member = initAddressMember();
                        $member['name_ext'] = $member;
                        $member['name'] = normalizeNames($member);
                        $member['checkit'] = 1;
                        $memberObject = createAddressMemberId($connection, $this->source, $this->devicegroup, $this->vsys, $member);
                    }
                    $secrulesdst[] = "('$this->source','$this->vsys','$memberObject->location','$memberObject->name','$lid','$this->devicegroup')";
                }
            }
            foreach ($this->secrulesapp as $memberA) {
                $memberA = (string)$memberA;
                if (($memberA != "") AND ($memberA != "any")) {
                    if (!$applicationObject = getAppId($connection, $this->source, $vsyses, $memberA)) {
                        $member = initApp();
                        $member['name_ext'] = $member;
                        $member['name'] = normalizeNames($member);
                        $member['checkit'] = 1;
                        $applicationObject = createAppId($connection, $this->source, $this->devicegroup, $this->vsys, $member);
                    }
                    $secrulesapp[] = "('$this->source','$this->vsys','$applicationObject->location','$applicationObject->name','$lid','$this->devicegroup')";
                }
            }
            foreach ($this->secrulessrv as $memberA) {
                $memberA = (string)$memberA;
                if (($memberA != "") AND ($memberA != "any")) {
                    if (!$serviceObject = getServiceId($connection, $this->source, $vsyses, $memberA)) {
                        $member = initServiceMember();
                        $member['name_ext'] = $member;
                        $member['name'] = normalizeNames($member);
                        $member['checkit'] = 1;
                        $serviceObject = createServiceMemberId($connection, $this->source, $this->devicegroup, $this->vsys, $member);
                    }
                    $secrulessrv[] = "('$this->source','$this->vsys','$serviceObject->location','$serviceObject->name','$lid','$this->devicegroup')";
                }
            }
            foreach ($this->secrulesprofiles as $secprof) {
                $secProfArr = explode(',', $secprof);
                $this->profile_type = $secProfArr[0];
                if ($secProfArr[0] == 'profiles') {
                    $type = $secProfArr[1];
                    $profile = $secProfArr[2];
                    if (!$secProfileObject = getProfileId($connection, $this->source, $vsyses, $type, $profile)) {
                        $member = initProfile();
                        $member['name_ext'] = $member;
                        $member['name'] = normalizeNames($member);
                        $member['checkit'] = 1;
                        $secProfileObject = createProfileId($connection, $this->source, $this->devicegroup, $this->vsys, $member);
                    }
                    $secrulesprofiles[] = "('$this->source','$this->vsys','$secProfileObject->location','$secProfileObject->name','$lid','$type','$this->devicegroup')";
                } else {
                    $membername = $secProfArr[2];
                    if (!$secProfileObject = getProfileGroupId($connection, $this->source, $vsyses, $membername)) {
                        $member = initProfileGroup();
                        $member['name_ext'] = $member;
                        $member['name'] = normalizeNames($member);
                        $member['checkit'] = 1;
                        $secProfileObject = createProfileGroupId($connection, $this->source, $this->devicegroup, $this->vsys, $member);
                    }
                    $secrulesprofiles[] = "('$this->source','$this->vsys','$secProfileObject->location','$secProfileObject->name','$lid','','$this->devicegroup')";
                }
            }

            $query = "INSERT INTO security_rules (icmp_unreachable,rule_type,target,preorpost,position,id,negate_source,negate_destination,description,name_ext,name,action,schedule,disabled,log_start,log_end,log_forwarding,vsys,source,dsri,qos,qos_value,devicegroup,profile_type) 
              VALUES ('$this->icmp_unreachable','$this->rule_type','$this->target','$this->preorpost','$position','$lid','$this->negate_source','$this->negate_destination','$this->description','$name_ext','$name_ext','$this->action','$this->schedule','$this->disabled','$this->log_start','$this->log_end','$this->log_forwarding','$this->vsys','$this->source','$this->dsri','$this->qos','$this->qos_value','$this->devicegroup','$this->profile_type')";
            $connection->query($query);


            //Relate the parameters to the new SecurityRule
            if (count($secrulesfrom) > 0) {
                $query = "INSERT INTO security_rules_from (source,vsys,name,rule_lid,devicegroup) VALUES " . implode(",", $secrulesfrom) . ";";
                $connection->query($query);
            }
            if (count($secrulesto) > 0) {
                $query = "INSERT INTO security_rules_to (source,vsys,name,rule_lid,devicegroup) VALUES " . implode(",", $secrulesto) . ";";
                $connection->query($query);
            }
            if (count($secrulestag) > 0) {
                $query = "INSERT INTO security_rules_tag (source,vsys,table_name,member_lid,rule_lid,devicegroup) VALUES " . implode(",", $secrulestag) . ";";
                $connection->query($query);
            }
            if (count($secrulesusr) > 0) {
                $connection->query("INSERT INTO security_rules_usr (source,vsys,name,rule_lid,devicegroup) VALUES " . implode(",", $secrulesusr) . ";");
            }
            if (count($secrulescategories) > 0) {
                $connection->query("INSERT INTO security_rules_categories (source,vsys,name,rule_lid,devicegroup) VALUES " . implode(",", $secrulescategories) . ";");
            }
            if (count($secruleship) > 0) {
                $connection->query("INSERT INTO security_rules_hip (source,member_lid,table_name,vsys,rule_lid,devicegroup,name) VALUES " . implode(",", $secruleship) . ";");
            }
            if (count($secrulessrc) > 0) {
                $connection->query("INSERT INTO security_rules_src (source,vsys,table_name,member_lid,rule_lid,devicegroup) VALUES " . implode(",", $secrulessrc) . ";");
            }
            if (count($secrulesdst) > 0) {
                $connection->query("INSERT INTO security_rules_dst (source,vsys,table_name,member_lid,rule_lid,devicegroup) VALUES " . implode(",", $secrulesdst) . ";");
            }
            if (count($secrulesapp) > 0) {
                $connection->query("INSERT INTO security_rules_app (source,vsys,table_name,member_lid,rule_lid,devicegroup) VALUES " . implode(",", $secrulesapp) . ";");
            }
            if (count($secrulessrv) > 0) {
                $connection->query("INSERT INTO security_rules_srv (source,vsys,table_name,member_lid,rule_lid,devicegroup) VALUES " . implode(",", $secrulessrv) . ";");
            }
            if (count($secrulesprofiles) > 0) {
                $connection->query("INSERT INTO security_rules_profiles (source,vsys,member_lid,table_name,rule_lid,type,devicegroup) VALUES " . implode(",", $secrulesprofiles) . ";");
            }

            $msg = [
                'code' => true,
                'msg' => "Inserted correctly"
            ];
            return $msg;
        }
    }

    public function update(mysqli $connection, STRING $name_ext, ARRAY $fields, INT &$id=null){
        $vsyses = getVsyses($connection, $this->vsys, $this->source);
        if(!$this->exists($connection, $name_ext, $vsyses)) {
            return $this->insert($connection,$name_ext);
        }
        else {
            parent::update($connection, $name_ext, $fields);
            global $projectdb;
            $projectdb = $connection;

            $query = "SELECT id FROM $this->table WHERE source='$this->source' AND vsys='$this->vsys' AND name='$name_ext'";
            $data = $connection->query($query)->fetch_assoc();
            $lid = $data['id'];

            $vsyses = getVsyses($connection, $this->vsys, $this->source);

            if (in_array('secrulesfrom', $fields)) {
                $connection->query("DELETE FROM security_rules_from WHERE rule_lid='$lid'");
                $secrulesfrom = array();
                foreach ($this->secrulesfrom as $memberA) {
                    if (($memberA != "") AND ($memberA != "any")) {
                        $secrulesfrom[] = "('$this->source','$this->vsys','$memberA','$lid','$this->devicegroup')";
                    }
                }
                $query = "INSERT INTO security_rules_from (source,vsys,name,rule_lid,devicegroup) VALUES " . implode(",", $secrulesfrom) . ";";
                $connection->query($query);
            }
            if (in_array('secrulesto', $fields)) {
                $connection->query("DELETE FROM security_rules_to WHERE rule_lid='$lid'");
                $secrulesto = array();
                foreach ($this->secrulesto as $memberA) {
                    if (($memberA != "") AND ($memberA != "any")) {
                        $secrulesto[] = "('$this->source','$this->vsys','$memberA','$lid','$this->devicegroup')";
                    }
                }
                $query = "INSERT INTO security_rules_to (source,vsys,name,rule_lid,devicegroup) VALUES " . implode(",", $secrulesto) . ";";
                $connection->query($query);
            }
            if (in_array('secrulestag', $fields)) {
                $connection->query("DELETE FROM security_rules_tag WHERE rule_lid='$lid'");
                $secrulestag = array();
                foreach ($this->secrulestag as $memberA) {
                    $memberA = (string)$memberA;
                    if (($memberA != "") AND ($memberA != "any")) {
                        $vsyses = getVsyses($connection, $this->vsys, $this->source);
                        if (!$tagObject = getTagId($connection, $this->source, $vsyses, $memberA)) {
                            $member = initTag();
                            $member['name_ext'] = $member;
                            $member['name'] = normalizeNames($member);
                            $member['checkit'] = 1;
                            $tagObject = createTagId($connection, $this->source, $this->devicegroup, $this->vsys, $member);
                        }
                        $secrulestag[] = "('$this->source','$this->vsys','$tagObject->location','$tagObject->name','$lid','$this->devicegroup')";
                    }
                }
                $query = "INSERT INTO security_rules_tag (source,vsys,table_name,member_lid,rule_lid,devicegroup) VALUES " . implode(",", $secrulestag) . ";";
                $connection->query($query);
            }
            if (in_array('secrulesusr', $fields)) {
                $connection->query("DELETE FROM security_rules_usr WHERE rule_lid='$lid'");

                $secrulesusr = array();
                foreach ($this->secrulesusr as $memberA) {
                    if (($memberA != "") AND ($memberA != "any")) {
                        $memberB = addslashes($memberA);
                        $secrulesusr[] = "('$this->source','$this->vsys','$memberB','$lid','$this->devicegroup')";
                    }
                }
                $connection->query("INSERT INTO security_rules_usr (source,vsys,name,rule_lid,devicegroup) VALUES " . implode(",", $secrulesusr) . ";");
            }
            if (in_array('secrulescategories', $fields)) {
                $connection->query("DELETE FROM security_rules_categories WHERE rule_lid='$lid'");

                $secrulescategories = array();
                foreach ($this->secrulescategories as $memberA) {
                    $memberA = (string)$memberA;
                    if (($memberA == "") OR ($memberA == "any")) {
                    } else {
                        $secrulescategories[] = "('$this->source','$this->vsys','$memberA','$lid','$this->devicegroup')";
                    }
                }
                $connection->query("INSERT INTO security_rules_categories (source,vsys,name,rule_lid,devicegroup) VALUES " . implode(",", $secrulescategories) . ";");
            }
            if (in_array('secruleship', $fields)) {
                $connection->query("DELETE FROM security_rules_hip WHERE rule_lid='$lid'");

                $secruleship = array();
                foreach ($this->secruleship as $memberA) {
                    if (($memberA == "") OR ($memberA == "any")) {
                    } elseif ($memberA == "no-hip") {
                        $secruleship[] = "('$this->source','0','default','$this->vsys','$lid','$this->devicegroup','no-hip')";
                    } else {
                        if (!$secProfileObject = getProfileId($connection, $this->source, $vsyses, 'hip-profiles', $memberA)) {
                            $member = initProfile();
                            $member['name_ext'] = $member;
                            $member['name'] = normalizeNames($member);
                            $member['checkit'] = 1;
                            $secProfileObject = createProfileId($connection, $this->source, $this->devicegroup, $this->vsys, $member);
                        }
                        $secruleship[] = "('$this->source','$secProfileObject->name','$secProfileObject->location','$this->vsys','$lid','$this->devicegroup','hip-profiles')";
                    }
                }
                $connection->query("INSERT INTO security_rules_hip (source,member_lid,table_name,vsys,rule_lid,devicegroup,name) VALUES " . implode(",", $secruleship) . ";");
            }
            if (in_array('secrulessrc', $fields)) {
                $connection->query("DELETE FROM security_rules_src WHERE rule_lid='$lid'");

                $secrulessrc = array();
                foreach ($this->secrulessrc as $memberA) {
                    $memberA = (string)$memberA;
                    if (($memberA != "") AND ($memberA != "any")) {
                        if (!$memberObject = getMemberId($connection, $this->source, $vsyses, $memberA)) {
                            $member = initAddressMember();
                            $member['name_ext'] = $memberA;
                            $member['name'] = normalizeNames($memberA);
                            $member['checkit'] = 1;
                            $member['type'] = 'ip-netmask';
                            $memberObject = createAddressMemberId($connection, $this->source, $this->devicegroup, $this->vsys, $member);
                        }
                        $secrulessrc[] = "('$this->source','$this->vsys','$memberObject->location','$memberObject->name','$lid','$this->devicegroup')";
                    }
                }
                $connection->query("INSERT INTO security_rules_src (source,vsys,table_name,member_lid,rule_lid,devicegroup) VALUES " . implode(",", $secrulessrc) . ";");
            }
            if (in_array('secrulesdst', $fields)) {
                $connection->query("DELETE FROM security_rules_dst WHERE rule_lid='$lid'");

                $secrulesdst = array();
                foreach ($this->secrulesdst as $memberA) {
                    $memberA = (string)$memberA;
                    if (($memberA != "") AND ($memberA != "any")) {
                        if (!$memberObject = getMemberId($connection, $this->source, $vsyses, $memberA)) {
                            $member = initAddressMember();
                            $member['name_ext'] = $memberA;
                            $member['name'] = normalizeNames($memberA);
                            $member['checkit'] = 1;
                            $memberObject = createAddressMemberId($connection, $this->source, $this->devicegroup, $this->vsys, $member);
                        }
                        $secrulesdst[] = "('$this->source','$this->vsys','$memberObject->location','$memberObject->name','$lid','$this->devicegroup')";
                    }
                }
                $connection->query("INSERT INTO security_rules_dst (source,vsys,table_name,member_lid,rule_lid,devicegroup) VALUES " . implode(",", $secrulesdst) . ";");
            }
            if (in_array('secrulesapp', $fields)) {
                $connection->query("DELETE FROM security_rules_app WHERE rule_lid='$lid'");

                $secrulesapp = array();
                foreach ($this->secrulesapp as $memberA) {
                    $memberA = (string)$memberA;
                    if (($memberA != "") AND ($memberA != "any")) {
                        if (!$applicationObject = getAppId($connection, $this->source, $vsyses, $memberA)) {
                            $member = initApp();
                            $member['name_ext'] = $member;
                            $member['name'] = normalizeNames($member);
                            $member['checkit'] = 1;
                            $applicationObject = createAppId($connection, $this->source, $this->devicegroup, $this->vsys, $member);
                        }
                        $secrulesapp[] = "('$this->source','$this->vsys','$applicationObject->location','$applicationObject->name','$lid','$this->devicegroup')";
                    }
                }
                $connection->query("INSERT INTO security_rules_app (source,vsys,table_name,member_lid,rule_lid,devicegroup) VALUES " . implode(",", $secrulesapp) . ";");
            }
            if (in_array('secrulessrv', $fields)) {
                $connection->query("DELETE FROM security_rules_srv WHERE rule_lid='$lid'");
                $secrulessrv = array();
                foreach ($this->secrulessrv as $memberA) {
                    $memberA = (string)$memberA;
                    if (($memberA != "") AND ($memberA != "any")) {
                        if (!$serviceObject = getServiceId($connection, $this->source, $vsyses, $memberA)) {
                            $member = initServiceMember();
                            $member['name_ext'] = $member;
                            $member['name'] = normalizeNames($member);
                            $member['checkit'] = 1;
                            $serviceObject = createServiceMemberId($connection, $this->source, $this->devicegroup, $this->vsys, $member);
                        }
                        $secrulessrv[] = "('$this->source','$this->vsys','$serviceObject->location','$serviceObject->name','$lid','$this->devicegroup')";
                    }
                }
                $connection->query("INSERT INTO security_rules_srv (source,vsys,table_name,member_lid,rule_lid,devicegroup) VALUES " . implode(",", $secrulessrv) . ";");
            }
            if (in_array('secrulesprofiles', $fields)) {
                $connection->query("DELETE FROM security_rules_profiles WHERE rule_lid='$lid'");
                $secrulesprofiles = array();
                foreach ($this->secrulesprofiles as $secprof) {
                    $secProfArr = explode(',', $secprof);
                    $this->profile_type = $secProfArr[0];
                    if ($secProfArr[0] == 'profiles') {
                        $type = $secProfArr[1];
                        $profile = $secProfArr[2];
                        if (!$secProfileObject = getProfileId($connection, $this->source, $vsyses, $type, $profile)) {
                            $member = initProfile();
                            $member['name_ext'] = $member;
                            $member['name'] = normalizeNames($member);
                            $member['checkit'] = 1;
                            $secProfileObject = createProfileId($connection, $this->source, $this->devicegroup, $this->vsys, $member);
                        }
                        $secrulesprofiles[] = "('$this->source','$this->vsys','$secProfileObject->location','$secProfileObject->name','$lid','$type','$this->devicegroup')";
                    } else {
                        $membername = $secProfArr[2];
                        if (!$secProfileObject = getProfileGroupId($connection, $this->source, $vsyses, $membername)) {
                            $member = initProfileGroup();
                            $member['name_ext'] = $member;
                            $member['name'] = normalizeNames($member);
                            $member['checkit'] = 1;
                            $secProfileObject = createProfileGroupId($connection, $this->source, $this->devicegroup, $this->vsys, $member);
                        }
                        $secrulesprofiles[] = "('$this->source','$this->vsys','$secProfileObject->location','$secProfileObject->name','$lid','','$this->devicegroup')";
                    }
                }
                $connection->query("INSERT INTO security_rules_profiles (source,vsys,member_lid,rule_lid,table_name,type,devicegroup) VALUES " . implode(",", $secrulesprofiles) . ";");
                $connection->query("UPDATE security_rules_profiles SET profile_type='$this->$this->profile_type' WHERE id='$lid'");
            }

            $msg = [
                'code' => true,
                'msg' => "Updated correctly"
            ];
            return $msg;
        }
    }

    public function updateByID(mysqli $connection, INT $ruleID, ARRAY $fields){
        $vsyses = getVsyses($connection, $this->vsys, $this->source);
        if(!$this->existsByID($connection, $ruleID, $vsyses)) {
            return;
        }
        else {
            parent::updateByID($connection, $ruleID, $fields);
            global $projectdb;
            $projectdb = $connection;

            $vsyses = getVsyses($connection, $this->vsys, $this->source);

            if (in_array('secrulesfrom', $fields)) {
                $connection->query("DELETE FROM security_rules_from WHERE rule_lid='$ruleID'");
                $secrulesfrom = array();
                foreach ($this->secrulesfrom as $memberA) {
                    if (($memberA != "") AND ($memberA != "any")) {
                        $secrulesfrom[] = "('$this->source','$this->vsys','$memberA','$ruleID','$this->devicegroup')";
                    }
                }
                $query = "INSERT INTO security_rules_from (source,vsys,name,rule_lid,devicegroup) VALUES " . implode(",", $secrulesfrom) . ";";
                $connection->query($query);
            }
            if (in_array('secrulesto', $fields)) {
                $connection->query("DELETE FROM security_rules_to WHERE rule_lid='$ruleID'");
                $secrulesto = array();
                foreach ($this->secrulesto as $memberA) {
                    if (($memberA != "") AND ($memberA != "any")) {
                        $secrulesto[] = "('$this->source','$this->vsys','$memberA','$ruleID','$this->devicegroup')";
                    }
                }
                $query = "INSERT INTO security_rules_to (source,vsys,name,rule_lid,devicegroup) VALUES " . implode(",", $secrulesto) . ";";
                $connection->query($query);
            }
            if (in_array('secrulestag', $fields)) {
                $connection->query("DELETE FROM security_rules_tag WHERE rule_lid='$ruleID'");
                $secrulestag = array();
                foreach ($this->secrulestag as $memberA) {
                    $memberA = (string)$memberA;
                    if (($memberA != "") AND ($memberA != "any")) {
                        $vsyses = getVsyses($connection, $this->vsys, $this->source);
                        if (!$tagObject = getTagId($connection, $this->source, $vsyses, $memberA)) {
                            $member = initTag();
                            $member['name_ext'] = $member;
                            $member['name'] = normalizeNames($member);
                            $member['checkit'] = 1;
                            $tagObject = createTagId($connection, $this->source, $this->devicegroup, $this->vsys, $member);
                        }
                        $secrulestag[] = "('$this->source','$this->vsys','$tagObject->location','$tagObject->name','$ruleID','$this->devicegroup')";
                    }
                }
                $query = "INSERT INTO security_rules_tag (source,vsys,table_name,member_lid,rule_lid,devicegroup) VALUES " . implode(",", $secrulestag) . ";";
                $connection->query($query);
            }
            if (in_array('secrulesusr', $fields)) {
                $connection->query("DELETE FROM security_rules_usr WHERE rule_lid='$ruleID'");

                $secrulesusr = array();
                foreach ($this->secrulesusr as $memberA) {
                    if (($memberA != "") AND ($memberA != "any")) {
                        $memberB = addslashes($memberA);
                        $secrulesusr[] = "('$this->source','$this->vsys','$memberB','$ruleID','$this->devicegroup')";
                    }
                }
                $connection->query("INSERT INTO security_rules_usr (source,vsys,name,rule_lid,devicegroup) VALUES " . implode(",", $secrulesusr) . ";");
            }
            if (in_array('secrulescategories', $fields)) {
                $connection->query("DELETE FROM security_rules_categories WHERE rule_lid='$ruleID'");

                $secrulescategories = array();
                foreach ($this->secrulescategories as $memberA) {
                    $memberA = (string)$memberA;
                    if (($memberA == "") OR ($memberA == "any")) {
                    } else {
                        $secrulescategories[] = "('$this->source','$this->vsys','$memberA','$ruleID','$this->devicegroup')";
                    }
                }
                $connection->query("INSERT INTO security_rules_categories (source,vsys,name,rule_lid,devicegroup) VALUES " . implode(",", $secrulescategories) . ";");
            }
            if (in_array('secruleship', $fields)) {
                $connection->query("DELETE FROM security_rules_hip WHERE rule_lid='$ruleID'");

                $secruleship = array();
                foreach ($this->secruleship as $memberA) {
                    if (($memberA == "") OR ($memberA == "any")) {
                    } elseif ($memberA == "no-hip") {
                        $secruleship[] = "('$this->source','0','default','$this->vsys','$ruleID','$this->devicegroup','no-hip')";
                    } else {
                        if (!$secProfileObject = getProfileId($connection, $this->source, $vsyses, 'hip-profiles', $memberA)) {
                            $member = initProfile();
                            $member['name_ext'] = $member;
                            $member['name'] = normalizeNames($member);
                            $member['checkit'] = 1;
                            $secProfileObject = createProfileId($connection, $this->source, $this->devicegroup, $this->vsys, $member);
                        }
                        $secruleship[] = "('$this->source','$secProfileObject->name','$secProfileObject->location','$this->vsys','$ruleID','$this->devicegroup','hip-profiles')";
                    }
                }
                $connection->query("INSERT INTO security_rules_hip (source,member_lid,table_name,vsys,rule_lid,devicegroup,name) VALUES " . implode(",", $secruleship) . ";");
            }
            if (in_array('secrulessrc', $fields)) {
                $connection->query("DELETE FROM security_rules_src WHERE rule_lid='$ruleID'");

                $secrulessrc = array();
                foreach ($this->secrulessrc as $memberA) {
                    $memberA = (string)$memberA;
                    if (($memberA != "") AND ($memberA != "any")) {
                        if (!$memberObject = getMemberId($connection, $this->source, $vsyses, $memberA)) {
                            $member = initAddressMember();
                            $member['name_ext'] = $memberA;
                            $member['name'] = normalizeNames($memberA);
                            $member['checkit'] = 1;
                            $member['type'] = 'ip-netmask';
                            $memberObject = createAddressMemberId($connection, $this->source, $this->devicegroup, $this->vsys, $member);
                        }
                        $secrulessrc[] = "('$this->source','$this->vsys','$memberObject->location','$memberObject->name','$ruleID','$this->devicegroup')";
                    }
                }
                $connection->query("INSERT INTO security_rules_src (source,vsys,table_name,member_lid,rule_lid,devicegroup) VALUES " . implode(",", $secrulessrc) . ";");
            }
            if (in_array('secrulesdst', $fields)) {
                $connection->query("DELETE FROM security_rules_dst WHERE rule_lid='$ruleID'");

                $secrulesdst = array();
                foreach ($this->secrulesdst as $memberA) {
                    $memberA = (string)$memberA;
                    if (($memberA != "") AND ($memberA != "any")) {
                        if (!$memberObject = getMemberId($connection, $this->source, $vsyses, $memberA)) {
                            $member = initAddressMember();
                            $member['name_ext'] = $memberA;
                            $member['name'] = normalizeNames($memberA);
                            $member['checkit'] = 1;
                            $memberObject = createAddressMemberId($connection, $this->source, $this->devicegroup, $this->vsys, $member);
                        }
                        $secrulesdst[] = "('$this->source','$this->vsys','$memberObject->location','$memberObject->name','$ruleID','$this->devicegroup')";
                    }
                }
                $connection->query("INSERT INTO security_rules_dst (source,vsys,table_name,member_lid,rule_lid,devicegroup) VALUES " . implode(",", $secrulesdst) . ";");
            }
            if (in_array('secrulesapp', $fields)) {
                $connection->query("DELETE FROM security_rules_app WHERE rule_lid='$ruleID'");

                $secrulesapp = array();
                foreach ($this->secrulesapp as $memberA) {
                    $memberA = (string)$memberA;
                    if (($memberA != "") AND ($memberA != "any")) {
                        if (!$applicationObject = getAppId($connection, $this->source, $vsyses, $memberA)) {
                            $member = initApp();
                            $member['name_ext'] = $member;
                            $member['name'] = normalizeNames($member);
                            $member['checkit'] = 1;
                            $applicationObject = createAppId($connection, $this->source, $this->devicegroup, $this->vsys, $member);
                        }
                        $secrulesapp[] = "('$this->source','$this->vsys','$applicationObject->location','$applicationObject->name','$ruleID','$this->devicegroup')";
                    }
                }
                $connection->query("INSERT INTO security_rules_app (source,vsys,table_name,member_lid,rule_lid,devicegroup) VALUES " . implode(",", $secrulesapp) . ";");
            }
            if (in_array('secrulessrv', $fields)) {
                $connection->query("DELETE FROM security_rules_srv WHERE rule_lid='$ruleID'");
                $secrulessrv = array();
                foreach ($this->secrulessrv as $memberA) {
                    $memberA = (string)$memberA;
                    if (($memberA != "") AND ($memberA != "any")) {
                        if (!$serviceObject = getServiceId($connection, $this->source, $vsyses, $memberA)) {
                            $member = initServiceMember();
                            $member['name_ext'] = $member;
                            $member['name'] = normalizeNames($member);
                            $member['checkit'] = 1;
                            $serviceObject = createServiceMemberId($connection, $this->source, $this->devicegroup, $this->vsys, $member);
                        }
                        $secrulessrv[] = "('$this->source','$this->vsys','$serviceObject->location','$serviceObject->name','$ruleID','$this->devicegroup')";
                    }
                }
                $connection->query("INSERT INTO security_rules_srv (source,vsys,table_name,member_lid,rule_lid,devicegroup) VALUES " . implode(",", $secrulessrv) . ";");
            }
            if (in_array('secrulesprofiles', $fields)) {
                $connection->query("DELETE FROM security_rules_profiles WHERE rule_lid='$ruleID'");
                $secrulesprofiles = array();
                foreach ($this->secrulesprofiles as $secprof) {
                    $secProfArr = explode(',', $secprof);
                    $this->profile_type = $secProfArr[0];
                    if ($secProfArr[0] == 'profiles') {
                        $type = $secProfArr[1];
                        $profile = $secProfArr[2];
                        if (!$secProfileObject = getProfileId($connection, $this->source, $vsyses, $type, $profile)) {
                            $member = initProfile();
                            $member['name_ext'] = $member;
                            $member['name'] = normalizeNames($member);
                            $member['checkit'] = 1;
                            $secProfileObject = createProfileId($connection, $this->source, $this->devicegroup, $this->vsys, $member);
                        }
                        $secrulesprofiles[] = "('$this->source','$this->vsys','$secProfileObject->location','$secProfileObject->name','$ruleID','$type','$this->devicegroup')";
                    } else {
                        $membername = $secProfArr[2];
                        if (!$secProfileObject = getProfileGroupId($connection, $this->source, $vsyses, $membername)) {
                            $member = initProfileGroup();
                            $member['name_ext'] = $member;
                            $member['name'] = normalizeNames($member);
                            $member['checkit'] = 1;
                            $secProfileObject = createProfileGroupId($connection, $this->source, $this->devicegroup, $this->vsys, $member);
                        }
                        $secrulesprofiles[] = "('$this->source','$this->vsys','$secProfileObject->location','$secProfileObject->name','$ruleID','','$this->devicegroup')";
                    }
                }
                $connection->query("INSERT INTO security_rules_profiles (source,vsys,member_lid,rule_lid,table_name,type,devicegroup) VALUES " . implode(",", $secrulesprofiles) . ";");
                $connection->query("UPDATE security_rules_profiles SET profile_type='$this->$this->profile_type' WHERE id='$ruleID'");
            }

            $msg = [
                'code' => true,
                'msg' => "Updated correctly"
            ];
            return $msg;
        }
    }

    public function compare(Object $objectB){
        return parent::compare($objectB);
    }

    public function move(mysqli $connection, STRING $ruleName, ARRAY $rulesUnder, STRING $source, STRING $vsys){
        $query = "SELECT position, preorpost FROM security_rules WHERE name='$ruleName' AND source='$source' AND vsys='$vsys'";
        $oldPositionResult = $connection->query($query)->fetch_assoc();
        $oldPosition = $oldPositionResult['position'];
        $preorpost = $oldPositionResult['preorpost'];

        $query = "SELECT max(position) as position FROM security_rules WHERE source='$source' AND vsys='$vsys' AND preorpost='$preorpost'";
        $data = $connection->query($query)->fetch_assoc();
        $newPosition = $data['position']+1; //The last rule in the policy

        foreach ($rulesUnder as $ruleUnder){
            $query = "SELECT position FROM security_rules WHERE name='$ruleUnder' AND source='$source' AND vsys='$vsys' AND preorpost='$preorpost'";
            $results = $connection->query($query);
            if($results->num_rows==1){
                $data = $results->fetch_assoc();
                $newPosition = $data['position']-1;
                break;
            }
        }

        if($newPosition < $oldPosition){
            $query = "UPDATE security_rules SET position=(position+1) WHERE position>=$newPosition AND position<$oldPosition AND source='$source' and vsys='$vsys'";
            $connection->query($query);
            $query = "UPDATE security_rules SET position=$newPosition WHERE name='$ruleName' AND source='$source' and vsys='$vsys'";
            $connection->query($query);
        }
        elseif($newPosition > $oldPosition){
            $query = "UPDATE security_rules SET position=(position-1) WHERE position>$oldPosition AND position<=$newPosition AND source='$source' and vsys='$vsys'";
            $connection->query($query);
            $query = "UPDATE security_rules SET position=$newPosition WHERE name='$ruleName' AND source='$source' and vsys='$vsys'";
            $connection->query($query);
        }
    }

    public function delete(mysqli $connection, STRING $name_ext){
        $query = "SELECT id FROM ".$this->table." WHERE source='$this->source' AND vsys='$this->vsys' AND name='$name_ext'";
        $data = $connection->query($query)->fetch_assoc();
        $id = $data['id'];

        foreach ($this->dependent_tables as $table){
            $query = "DELETE FROM ".$table." WHERE rule_lid='$id'";
            $connection->query($query);
        }

        $query = "DELETE FROM ".$this->table." WHERE id='$id'";
        $connection->query($query);

        $msg = [
            'code' => true,
            'msg'  => "$this->object \"$name_ext\" deleted"
        ];
        return $msg;

    }

    public function checkUsed(mysqli $connection, STRING $name_ext=null){
        return null;
    }

    public function exists(mysqli $connection, STRING $name_ext, ARRAY $vsyses = null)
    {
        return parent::exists($connection, $name_ext, $vsyses); // TODO: Change the autogenerated stub
    }

    public function existsByID(mysqli $connection, INT $id, ARRAY $vsyses = null)
    {
        return parent::existsByID($connection, $id, $vsyses); // TODO: Change the autogenerated stub
    }

    public function checkRuleLayer():int{

    }

    public function setRuleLayer(int $layer){
        $this->updateByID($this->projectDB, $this->id, ['layer'=> $layer]);
    }

    /***
     * Checks the rule's Applications and Services and identifies either it is a Layer4 rule or Layer7 rule
     */
    public function updateRuleLayer(){
        $this->setRuleLayer($this->checkRuleLayer());
    }
}