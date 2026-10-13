<?php
/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: $today.year.hour.minute
 ******************************************************************************/

namespace PaloAltoNetworks\Policy\Objects;
require_once INC_ROOT.'/libs/common/rules/SecurityRule.php';
require_once INC_ROOT.'/libs/common/rules/MemoryObjectsHandlerCisco.php';

require_once INC_ROOT.'/libs/common/MemberObject.php';
use PaloaltoNetworks\Policy\Objects\MemberObject;

use \PaloAltoNetworks\Expedition\ResponseCode;

class SecurityRuleCisco extends SecurityRule
{
    public function fillObject(MemberObject $value){
        if(!isset($this->source)){
            return parent::setSource($value);
        }
        elseif (!isset($this->destination)){
            return parent::setDestination($value);
        }
        elseif(!isset($this->service)){
            return parent::setService($value);
        }
        else{
            //We missed the sourcePort.
            parent::setSourcePort($this->destination);
            parent::setDestination($this->service);

            parent::setService($value);
            return new ResponseCode(false, -1, "Type Object not recognized. Source, Destination and Service already filled in");
        }
    }

    public function fillService(MemberObject $value){
        if(!isset($this->destination)){
            return parent::setSourcePort($value);
        }
        else{
            return parent::setService($value);
        }
    }

    public function fillAddress(MemberObject $value){
        if(!isset($this->source)){
            return parent::setSource($value);
        }
        elseif (!isset($this->destination)){
            return parent::setDestination($value);
        }
        else{
            return new ResponseCode(false, -1, "Type Object not recognized. Source, Destination and Service already filled in");
        }
    }

    public function setProtocol(ARRAY $value){
        switch($value){
            case 'ah':
                $this->application = 'ipsec-ah';
                break;
            case 'icmp':
                $this->application = 'icmp';
                break;
            case 'icmp6':
                $this->application = 'ipv6-icmp';
                break;
            case 'esp':
                $this->application = 'ipsec-esp';
                break;
            case 'igrp':
                $this->application = 'igp';
                break;
            case 'ipinip':
                $this->application = 'ip-in-ip';
                break;
            case 'nos':
                $this->application = 'ipip';
                break;
            case 'pcp':
                $this->application = 'ipcomp';
                break;
            default:
                break;
        }
        parent::setProtocol($value);
    }

    public function correctSourcePort(STRING $devicegroup, STRING $source, STRING $vsys, \MemoryObjectsHandlerCisco $inMemoryObjects, ARRAY $service){
        //Verify this is actually a TCP or UDP rule
        if(in_array('tcp',$this->protocol) OR in_array('udp',$this->protocol) OR in_array('ip',$this->protocol)) {
            //We missed the sourcePort.
            print_r($this);
            $incorrectDestination = $this->destination;
            $object = $inMemoryObjects->getServiceReference($devicegroup, $source, $vsys, $incorrectDestination->name);
            parent::setSourcePort($object);

            $incorrectService = $this->service;
            $object = $inMemoryObjects->getAddressReference($devicegroup, $source, $vsys, $incorrectService->name);
            parent::setDestination($object);

            parent::setService($service);
        }

    }

    public function correctServices(STRING $devicegroup, STRING $source, STRING $vsys, \MemoryObjectsHandlerCisco $inMemoryObjects, ARRAY $service){
        parent::setSourcePort($this->service);
        parent::setService($service);
    }
}