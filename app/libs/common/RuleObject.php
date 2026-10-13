<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 8/4/16 - 19:58
 */

namespace PaloaltoNetworks\Policy\Objects;

class RuleObject {   //FOR SEC or NAT RULES
    public $id;        //rule_lid
    public $location;  //table_where_located
    public $name;      //rule_name_int
    public $position;  //position in the policy

    public function printRuleObject() {
        var_dump(get_object_vars($this));
    }

    function __construct()
    {
        $a = func_get_args();
        $i = func_num_args();
        if (method_exists($this,$f='__construct'.$i)) {
            call_user_func_array(array($this,$f),$a);
        }
    }

    public function __construct2($id, $location)
    {
        $this->id = $id;
        $this->location = $location;
    }

    public function __construct3($id, $location, $name)
    {
        $this->name = $name;
        $this->location = $location;
        $this->id = $id;
    }

    public function __construct4($id, $location, $name, $position)
    {
        $this->name = $name;
        $this->location = $location;
        $this->id = $id;
        $this->position = $position;
    }

    public function contains($member, $memberArray){
        foreach($memberArray as $kwnonMember){
            if($kwnonMember.equal($member)){
                return true;
            }
        }
        return false;
    }

    public function contains_relaxed($member, $memberArray){
        foreach($memberArray as $kwnonMember){
            if($kwnonMember.equal_relaxed($member) > 0){
                return true;
            }
        }
        return false;
    }

    public function equal($otherMember){
        if( $this->id       != $otherMember->id) return false;
        if( $this->position != $otherMember->position) return false;
        if( $this->name     != $otherMember->name) return false;
        if( $this->location != $otherMember->location) return false;
        return true;
    }
    
    public function equal_relaxed($otherMember){
        if( $this->location != $otherMember->location) return -1;
        if( $this->name     != $otherMember->name) return -1;
        //It is the same rule for a PANOS
        return ( $this->id  != $otherMember->id) ? 1 : 2;
    }
}