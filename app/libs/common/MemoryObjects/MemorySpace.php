<?php
/*******************************************************************************
 * Copyright (c) 2018 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: $today.year.hour.minute
 ******************************************************************************/

namespace PaloAltoNetworks\Expedition\MemoryObjects;

require_once INC_ROOT . '/libs/common/MemoryObjects/Objects/Mem_Addresses.php';
require_once INC_ROOT . '/libs/common/MemoryObjects/Objects/Mem_AddressGroups.php';
require_once INC_ROOT . '/libs/common/MemoryObjects/Objects/Mem_AddressGroupsRelations.php';
require_once INC_ROOT . '/libs/common/MemoryObjects/Objects/Mem_Applications.php';
require_once INC_ROOT . '/libs/common/MemoryObjects/Objects/Mem_ApplicationGroups.php';
require_once INC_ROOT . '/libs/common/MemoryObjects/Objects/Mem_ApplicationGroupsRelations.php';
require_once INC_ROOT . '/libs/common/MemoryObjects/Objects/Mem_Services.php';
require_once INC_ROOT . '/libs/common/MemoryObjects/Objects/Mem_ServiceGroups.php';
require_once INC_ROOT . '/libs/common/MemoryObjects/Objects/Mem_ServiceGroupsRelations.php';
require_once INC_ROOT . '/libs/common/MemoryObjects/Objects/Mem_Tags.php';
require_once INC_ROOT . '/libs/common/MemoryObjects/Objects/Mem_TagRelations.php';
require_once INC_ROOT . '/libs/common/MemoryObjects/Objects/Mem_Profiles.php';
require_once INC_ROOT . '/libs/common/MemoryObjects/Objects/Mem_ProfileGroups.php';
require_once INC_ROOT . '/libs/common/MemoryObjects/Objects/Mem_Categories.php';
require_once INC_ROOT . '/libs/common/MemoryObjects/Objects/Mem_Zones.php';
require_once INC_ROOT . '/libs/common/MemoryObjects/Objects/Mem_Regions.php';


class MemorySpace{
    /* @var $addresses Mem_Addresses */
    public $address;
    /* @var $addressesGroups Mem_AddressGroups */
    public $addressGroups;
    /* @var $addressesGroupsRelations Mem_AddressGroupsRelations */
    public $addressGroupsRelations;

    /* @var $application Mem_Applications */
    public $applications;
    /* @var $applicationGroups Mem_ApplicationGroups */
    public $applicationGroups;
    /* @var $applicationGroupsRelations Mem_ApplicationGroupsRelations */
    public $applicationGroupsRelations;

    /* @var $services Mem_Services */
    public $services;
    /* @var $serviceGroups Mem_ServiceGroups */
    public $serviceGroups;
    /* @var $serviceGroupsRelations Mem_ServiceGroupsRelations */
    public $serviceGroupsRelations;

    /* @var $application Mem_Tags */
    public $tag;
    /* @var $tagRelations Mem_TagRelations */
    public $tagRelations;

    /* @var $profile Mem_Profiles */
    public $profile;
    /* @var $profileGroups Mem_ProfileGroups */
    public $profileGroups;

    /* @var $category Mem_Categories */
    public $category;

    /* @var $zone Mem_Zones */
    public $zone;

    /* @var $regions Mem_Zones */
    public $regions;

    public function __construct(){

        $this->address = new Mem_Addresses();
        $this->addressGroups = new Mem_AddressGroups();
        $this->addressGroupsRelations = new Mem_AddressGroupsRelations();

        $this->applications = new Mem_Applications();
        $this->applicationGroups = new Mem_ApplicationGroups();
        $this->applicationGroupsRelations = new Mem_ApplicationGroupsRelations();

        $this->services = new Mem_Services();
        $this->serviceGroups = new Mem_ServiceGroups();
        $this->serviceGroupsRelations = new Mem_ServiceGroupsRelations();

        $this->tag = new Mem_Tags();
        $this->tagRelations = new Mem_TagRelations();

        $this->profile = new Mem_Profiles();
        $this->profileGroups = new Mem_ProfileGroups();

        $this->category = new Mem_Categories();

        $this->zone= new Mem_Zones();

        $this->regions = new Mem_Regions();
    }

    public function printAll(){
        return $this->address->print();
    }


}