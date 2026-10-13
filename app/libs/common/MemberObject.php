<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 8/4/16 - 17:58
 */

namespace PaloaltoNetworks\Policy\Objects;

class MemberObject {   //FOR ADDRESS                FOR SERVICES
    public $name;      //id                         //id
    public $location;  //table_where_located        //table_where_located
    public $value;     //IP                         //port
    public $cidr;      //CIDR                       //protocol


    public function printMemberObject() {
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

    public function __construct2($name, $location)
    {
        $this->name = $name;
        $this->location = $location;
    }

    public function __construct3($name, $location, $value)
    {
        $this->name = $name;
        $this->location = $location;
        $this->value = $value;
    }

    public function __construct4($name, $location, $value, $cidr)
    {
        $this->name = $name;
        $this->location = $location;
        $this->value = $value;
        $this->cidr = $cidr;
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
            if($kwnonMember.equal_relaxed($member)){
                return true;
            }
        }
        return false;
    }

    public function equal($otherMember){
        if( $this->cidr != $otherMember->cidr) return false;
        if( $this->location != $otherMember->location) return false;
        if( $this->name != $otherMember->name) return false;
        if( $this->value != $otherMember->value) return false;
        return true;
    }

    public function equal_relaxed($otherMember){
        if( $this->location != $otherMember->location) return false;
        if( $this->name != $otherMember->name) return false;
        return true;
    }

    public function equal_values($otherMember){
        if( $this->cidr != $otherMember->cidr) return false;
        if( $this->value != $otherMember->value) return false;
        return true;
    }
}