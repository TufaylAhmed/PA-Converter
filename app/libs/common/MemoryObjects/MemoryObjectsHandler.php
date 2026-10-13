<?php
/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: $today.year.hour.minute
 ******************************************************************************/

namespace PaloAltoNetworks\Expedition\MemoryObjects;

require_once INC_ROOT.'/libs/common/MemoryObjects/MemorySpace.php';
require_once INC_ROOT.'/libs/common/MemoryObjects/Response.php';
require_once INC_ROOT.'/libs/common/MemberObject.php';
require_once INC_ROOT.'/libs/common/MemoryObjects/Handlers/AddressHandler.php';
require_once INC_ROOT.'/libs/common/MemoryObjects/Handlers/ServicesHandler.php';
require_once INC_ROOT.'/libs/common/MemoryObjects/Handlers/RegionsHandler.php';
require_once INC_ROOT.'/libs/common/MemoryObjects/Handlers/ApplicationsHandler.php';

use PaloAltoNetworks\Expedition\MemoryObjects\Handlers\AddressHandler;
use PaloAltoNetworks\Expedition\MemoryObjects\Handlers\ServicesHandler;
use PaloAltoNetworks\Expedition\MemoryObjects\Handlers\RegionsHandler;
use PaloAltoNetworks\Expedition\MemoryObjects\Handlers\ApplicationsHandler;

use PaloaltoNetworks\Policy\Objects\MemberObject;


class MemoryObjectsHandler
{
    /* @var $memorySpace MemorySpace */
    private $memorySpace;
    public  $address;
    public  $services;
    public  $regions;
    public  $applications;

    public function __construct(){
        $this->memorySpace = new MemorySpace();
        $this->address = new AddressHandler($this);
        $this->services = new ServicesHandler($this);
        $this->regions = new RegionsHandler($this);
        $this->applications = new ApplicationsHandler($this);
    }

    public function address(){

    }

    public function services(){

    }

    public function regions(){

    }

    public function applications(){

    }

    public function memorySpace():MemorySpace{
        return $this->memorySpace;
    }

    public function loadAll(\MySQLi $connection){

        $response = $this->loadAddress($connection);
        $response = $this->loadAddressGroup($connection);
        $response = $this->loadAddressGroupRelations($connection);

        $response = $this->loadApplications($connection);
        $response = $this->loadApplicationGroup($connection);
        $response = $this->loadApplicationGroupRelations($connection);

        $response = $this->loadServices($connection);
        $response = $this->loadServiceGroup($connection);
        $response = $this->loadServiceGroupRelations($connection);

        $response = $this->loadTags($connection);
        $response = $this->loadTagRelations($connection);

        $response = $this->loadProfiles($connection);
        $response = $this->loadProfileGroup($connection);

        $response = $this->loadCategories($connection);

        $response = $this->loadRegions($connection);

    }

    /***
     * @param int $id
     * @return array
     */
    public function getAddress(int $id){
        return $this->memorySpace->address->ids[$id];
    }

    /***
     * Returns an array of Address data(an array)
     * @param array $ids
     * @return array
     */
    public function getAddresses(array $ids){
        $addresses = array();

        foreach($ids as $id){
            $addresses[] = $this->getAddress($id);
        }

        return $addresses;
    }

    public function getService(int $id){
        return $this->memorySpace->services->ids[$id];
    }

    public function getServices(array $ids){
        $services = array();

        foreach($ids as $id){
            $services[] = $this->getService($id);
        }

        return $services;
    }

    public function getApplication(int $id){
        return $this->memorySpace->applications->ids[$id];
    }

    public function getApplications(array $ids){
        $applications = array();

        foreach($ids as $id){
            $applications[] = $this->getApplication($id);
        }

        return $applications;
    }

    public function getRegion(int $id){
        return $this->memorySpace->regions->ids[$id];
    }

    public function getRegions(array $ids){
        $regions = array();

        foreach($ids as $id){
            $regions[] = $this->getRegion($id);
        }

        return $regions;
    }

    public function loadAddress(\MySQLi $connection, ARRAY $ids=null):Response{
        if(!is_null($ids) && count($ids)>0){
            $whereConditions = " WHERE id IN (" . implode(",", $ids) . ") ";
        }
        else{
            $whereConditions = " WHERE 1=0 ";
        }
        $query = "SELECT id,name,name_ext,ipaddress,cidr,v4,v6,vsys,source,type,vtype, devicegroup, description, merge_as_primary, used, dummy FROM address $whereConditions";
        $loadData=$connection->query($query);
        if ($loadData->num_rows>0){
            while($data=$loadData->fetch_assoc()){
                //Addresses indexed by id
                $cidr = ($data['cidr']==''||$data['cidr']==0)?'32':$data['cidr'];
                $id = $data['id'];
                $this->memorySpace->address->ids[$id] = $data;

                $this->memorySpace->address->byName->addIndex($data['name'], $id);
                $this->memorySpace->address->byName_ext->addIndex($data['name_ext'], $id);
                $this->memorySpace->address->byIP->addIndex($data['ipaddress'], $id);
                $this->memorySpace->address->bySource->addIndex($data['source'], $id);
                $this->memorySpace->address->byVsys->addIndex($data['vsys'], $id);
                $this->memorySpace->address->byCidr->addIndex($cidr, $id);
                $this->memorySpace->address->byType->addIndex($data['type'], $id);
                $this->memorySpace->address->byPrimary->addIndex($data['merge_as_primary'], $id);
                $this->memorySpace->address->byDummy->addIndex($data['dummy'], $id);
            }
        }
        else{
            $this->memorySpace->address->ids = array();
        }

        //print_r($this->memorySpace->address);

        return new Response();
    }

    public function loadAddressGroup(\MySQLi $connection):Response{
        $loadData=$connection->query("SELECT id, name, name_ext, used, checkit, devicegroup, vsys, type, source, description, tag, filter, zone, invalid, modified, dummy, disable_override, merge_as_primary description FROM address_groups_id");
        if ($loadData->num_rows>0){
            while($data=$loadData->fetch_assoc()){
                //AddressGroups indexed by id
                $id = $data['id'];
                $this->memorySpace->addressGroups->ids[$id] = $data;

                $this->memorySpace->addressGroups->byName->addIndex($data['name'], $id);
                $this->memorySpace->addressGroups->byName_ext->addIndex($data['name_ext'], $id);
                $this->memorySpace->addressGroups->bySource->addIndex($data['source'], $id);
                $this->memorySpace->addressGroups->byVsys->addIndex($data['vsys'], $id);
                $this->memorySpace->addressGroups->byPrimary->addIndex($data['merge_as_primary'], $id);

            }
        }

        return new Response();
    }

    public function loadAddressGroupRelations(\MySQLi $connection):Response{
        $loadData=$connection->query("SELECT id, name, name_ext, used, checkit, devicegroup, vsys, member, member_lid, table_name, lid, source FROM address_groups");
        if ($loadData->num_rows>0){
            while($data=$loadData->fetch_assoc()){
                $id = $data['id'];
                $this->memorySpace->addressGroupsRelations->ids[$id] = $data;

                $this->memorySpace->addressGroupsRelations->bySource->addIndex($data['source'], $id);
                $this->memorySpace->addressGroupsRelations->byVsys->addIndex($data['vsys'], $id);
                $this->memorySpace->addressGroupsRelations->byGroup->addIndex($data['lid'], $id);
                $this->memorySpace->addressGroupsRelations->byMember->addIndex($data['table_name']."_".$data['member_lid'], $id);
            }
        }

        return new Response();
    }

    public function loadApplications(\MySQLi $connection):Response{
        $loadData=$connection->query("SELECT id, source, devicegroup, vsys, name, name_ext, description, category, subcategory, parent_app, risk, technology, evasive_behavior, consume_big_bandwidth, used_by_malware, able_to_transfer_file, has_known_vulnerability, tunnel_other_application, tunnel_applications, prone_to_misuse, pervasive_use, file_type_ident, virus_ident, data_ident, default_type, value, type, code, timeout, tcp_timeout, udp_timeout, tcp_half_closed_timeout, tcp_time_wait_timeout, spyware_ident, modified, vtype, dummy, checkit, disable_override, merge_as_primary, used FROM applications");
        if ($loadData->num_rows>0){
            while($data=$loadData->fetch_assoc()){
                //Applications indexed by id
                $id = $data['id'];
                $this->memorySpace->applications->ids[$id] = $data;

                $this->memorySpace->applications->byName->addIndex($data['name'], $id);
                $this->memorySpace->applications->bySource->addIndex($data['source'], $id);
                $this->memorySpace->applications->byVsys->addIndex($data['vsys'], $id);
                $this->memorySpace->applications->byPrimary->addIndex($data['merge_as_primary'], $id);

            }
        }
        else{
            $this->memorySpace->applications->ids = array();
        }

        return new Response();
    }

    public function loadApplicationGroup(\MySQLi $connection):Response{
        $loadData=$connection->query("SELECT id, name, name_ext, used, checkit, devicegroup, vsys, type, source, description, tag, filter, zone, invalid, modified, dummy, disable_override, merge_as_primary description FROM address_groups_id");
        if ($loadData->num_rows>0){
            while($data=$loadData->fetch_assoc()){
                //AddressGroups indexed by id
                $id = $data['id'];
                $this->memorySpace->applicationGroups->ids[$id] = $data;

                $this->memorySpace->applicationGroups->byName->addIndex($data['name'], $id);
                $this->memorySpace->applicationGroups->byType->addIndex($data['type'], $id);
                $this->memorySpace->applicationGroups->bySource->addIndex($data['source'], $id);
                $this->memorySpace->applicationGroups->byVsys->addIndex($data['vsys'], $id);
                $this->memorySpace->applicationGroups->byPrimary->addIndex($data['merge_as_primary'], $id);

            }
        }

        return new Response();
    }

    public function loadApplicationGroupRelations(\MySQLi $connection):Response{
        $loadData=$connection->query("SELECT id, name, name_ext, used, checkit, devicegroup, vsys, member, member_lid, table_name, lid, source FROM address_groups");
        if ($loadData->num_rows>0){
            while($data=$loadData->fetch_assoc()){
                $id = $data['id'];
                $this->memorySpace->applicationGroupsRelations->ids[$id] = $data;

                $this->memorySpace->applicationGroupsRelations->bySource->addIndex($data['source'], $id);
                $this->memorySpace->applicationGroupsRelations->byVsys->addIndex($data['vsys'], $id);
                $this->memorySpace->applicationGroupsRelations->byGroup->addIndex($data['lid'], $id);
                $this->memorySpace->applicationGroupsRelations->byMember->addIndex($data['table_name']."_".$data['member_lid'], $id);
            }
        }

        return new Response();
    }

    public function loadServices(\MySQLi $connection, ARRAY $ids=null):Response{
        if(!is_null($ids) && count($ids)>0){
            $whereConditions = " WHERE id IN (" . implode(",", $ids) . ") ";
        }
        else{
            $whereConditions = " WHERE 1=0 ";
        }
        $query = "SELECT id, name, name_ext, checkit, used, vsys, devicegroup, type, description, sport, dport, protocol, icmp, source, tag, invalid, modified, vtype, dummy, disable_override, app, merge_as_primary, override, timeout, halfclose_timeout, timewait_timeout FROM services $whereConditions";
        //echo "Query: " .$query. "\n";
        $loadData=$connection->query($query);
        if ($loadData->num_rows>0){
            while($data=$loadData->fetch_assoc()){
                //Services indexed by id

                $id = $data['id'];
                $this->memorySpace->services->ids[$id] = $data;

                //echo "ids service: \n";
                //print_r($this->memorySpace->services->ids[$id]);

                $this->memorySpace->services->byName->addIndex($data['name'], $id);
                $this->memorySpace->services->bySource->addIndex($data['source'], $id);
                $this->memorySpace->services->byVsys->addIndex($data['vsys'], $id);
                $this->memorySpace->services->byDPort->addIndex($data['dport'], $id);
                $this->memorySpace->services->bySPort->addIndex($data['sport'], $id);
                $this->memorySpace->services->byProtocol->addIndex($data['protocol'], $id);
                $this->memorySpace->services->byProtocolDPort->addIndex($data['protocol']."/".$data['dport'], $id);

                $this->memorySpace->services->byTimeout->addIndex($data['timeout'], $id);
                $this->memorySpace->services->byHalfcloseTimeout->addIndex($data['halfclose_timeout'], $id);
                $this->memorySpace->services->byTimewaitTimeout->addIndex($data['timewait_timeout'], $id);

                $this->memorySpace->services->byPrimary->addIndex($data['merge_as_primary'], $id);
            }
        }
        else{
            $this->memorySpace->services->ids = array();
        }

        return new Response();
    }

    public function loadServiceGroup(\MySQLi $connection):Response{
        $loadData=$connection->query("SELECT id, name, name_ext, used, checkit, devicegroup, vsys, type, source, description, tag, filter, invalid, modified, dummy, disable_override, merge_as_primary FROM services_groups_id");
        if ($loadData->num_rows>0){
            while($data=$loadData->fetch_assoc()){
                //AddressGroups indexed by id
                $id = $data['id'];
                $this->memorySpace->serviceGroups->ids[$id] = $data;

                $this->memorySpace->serviceGroups->byName->addIndex($data['name'], $id);
                $this->memorySpace->serviceGroups->byName_ext->addIndex($data['name_ext'], $id);
                $this->memorySpace->serviceGroups->bySource->addIndex($data['source'], $id);
                $this->memorySpace->serviceGroups->byVsys->addIndex($data['vsys'], $id);
                $this->memorySpace->serviceGroups->byPrimary->addIndex($data['merge_as_primary'], $id);
            }
        }

        return new Response();
    }

    public function loadServiceGroupRelations(\MySQLi $connection):Response{
        $loadData=$connection->query("SELECT id, name, name_ext, used, checkit, devicegroup, vsys, member, member_lid, table_name, lid, source FROM services_groups");
        if ($loadData->num_rows>0){
            while($data=$loadData->fetch_assoc()){
                $id = $data['id'];
                $this->memorySpace->serviceGroupsRelations->ids[$id] = $data;

                $this->memorySpace->serviceGroupsRelations->bySource->addIndex($data['source'], $id);
                $this->memorySpace->serviceGroupsRelations->byVsys->addIndex($data['vsys'], $id);
                $this->memorySpace->serviceGroupsRelations->byGroup->addIndex($data['lid'], $id);
                $this->memorySpace->serviceGroupsRelations->byMember->addIndex($data['table_name']."_".$data['member_lid'], $id);
            }
        }

        return new Response();
    }

    public function loadTags(\MySQLi $connection):Response{
        $loadData=$connection->query("SELECT id, name, name_ext, color, comments, source, vsys, devicegroup, modified, vtype, dummy, checkit, disable_override, merge_as_primary, used FROM tag");
        if ($loadData->num_rows>0){
            while($data=$loadData->fetch_assoc()){
                $id = $data['id'];
                $this->memorySpace->tag->ids[$id] = $data;

                $this->memorySpace->tag->bySource->addIndex($data['source'], $id);
                $this->memorySpace->tag->byVsys->addIndex($data['vsys'], $id);
                $this->memorySpace->tag->byName->addIndex($data['name'], $id);
            }
        }

        return new Response();
    }

    public function loadTagRelations(\MySQLi $connection):Response{
        $loadData=$connection->query("SELECT id, table_name, member_lid, tag_id FROM tag_relations");
        if ($loadData->num_rows>0){
            while($data=$loadData->fetch_assoc()){
                $id = $data['id'];
                $this->memorySpace->tagRelations->ids[$id] = $data;

                $this->memorySpace->tagRelations->byGroup->addIndex($data['id'], $id);
                $this->memorySpace->tagRelations->byMember->addIndex($data['table_name']."_".$data['member_lid'], $id);
            }
        }

        return new Response();
    }

    public function loadProfiles(\MySQLi $connection):Response{
        $loadData=$connection->query("SELECT id, source, name, name_ext, xml, type, vsys, devicegroup, modified, vtype, dummy, checkit, disable_override FROM profiles");
        if ($loadData->num_rows>0){
            while($data=$loadData->fetch_assoc()){
                $id = $data['id'];
                $this->memorySpace->profile->ids[$id] = $data;

                $this->memorySpace->profile->bySource->addIndex($data['source'], $id);
                $this->memorySpace->profile->byVsys->addIndex($data['vsys'], $id);
                $this->memorySpace->profile->byName->addIndex($data['name'], $id);
                $this->memorySpace->profile->byType->addIndex($data['type'], $id);
            }
        }

        return new Response();
    }

    public function loadProfileGroup(\MySQLi $connection):Response{
        $loadData=$connection->query("SELECT id, source, name, name_ext, xml, type, vsys, devicegroup, modified, vtype, dummy, checkit, disable_override FROM profiles_groups");
        if ($loadData->num_rows>0){
            while($data=$loadData->fetch_assoc()){
                $id = $data['id'];
                $this->memorySpace->profileGroups->ids[$id] = $data;

                $this->memorySpace->profileGroups->bySource->addIndex($data['source'], $id);
                $this->memorySpace->profileGroups->byVsys->addIndex($data['vsys'], $id);
                $this->memorySpace->profileGroups->byName->addIndex($data['name'], $id);
            }
        }

        return new Response();
    }

    public function loadCategories(\MySQLi $connection):Response{
        $loadData=$connection->query("SELECT id, name FROM category");
        if ($loadData->num_rows>0){
            while($data=$loadData->fetch_assoc()){
                $id = $data['id'];
                $this->memorySpace->profile->ids[$id] = $data;

                $this->memorySpace->profile->byName->addIndex($data['name'], $id);
            }
        }

        return new Response();
    }

    public function loadRegions(\MySQLi $connection, ARRAY $ids=null):Response{
        if(!is_null($ids) && count($ids)>0){
            $whereConditions = " WHERE id IN (" . implode(",", $ids) . ") ";
        }
        else{
            $whereConditions = " WHERE 1=0 ";
        }
        $query = "SELECT id, name, name_ext, checkit, used, vsys, source, devicegroup, type, latitude, longitude, address, modified, dummy, disable_override, merge_as_primary FROM regions $whereConditions";
        //echo "Query: " .$query. "\n";
        $loadData=$connection->query($query);
        if ($loadData->num_rows>0){
            while($data=$loadData->fetch_assoc()){
                //Services indexed by id

                $id = $data['id'];
                $this->memorySpace->regions->ids[$id] = $data;

                //echo "ids service: \n";
                //print_r($this->memorySpace->regions->ids[$id]);

                $this->memorySpace->regions->byName->addIndex($data['name'], $id);
                $this->memorySpace->regions->bySource->addIndex($data['source'], $id);
                $this->memorySpace->regions->byVsys->addIndex($data['vsys'], $id);
                $this->memorySpace->regions->byLatitude->addIndex($data['latitude'], $id);
                $this->memorySpace->regions->byLongitude->addIndex($data['longitude'], $id);
                $this->memorySpace->regions->byAddress->addIndex($data['address'], $id);

                $this->memorySpace->regions->byPrimary->addIndex($data['merge_as_primary'], $id);
            }
        }
        else{
            $this->memorySpace->regions->ids = array();
        }

        return new Response();
    }

    public function print():string{
        return json_encode($this->memorySpace, true);
    }
}