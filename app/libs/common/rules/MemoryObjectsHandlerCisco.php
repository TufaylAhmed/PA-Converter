<?php
/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: $today.year.hour.minute
 ******************************************************************************/

require_once INC_ROOT.'/libs/common/MemberObject.php';
use PaloaltoNetworks\Policy\Objects\MemberObject;

class MemoryObjectsHandlerCisco
{
    private $memorySpace;

    public function __construct()
    {

    }

    public function createAllPortServices(STRING $devicegroup, MySQLi $projectdb, STRING $source, STRING $vsys){
        // (name, name_ext, source, vsys, type, description, dport, protocol)
        $query = "INSERT INTO services (name, name_ext, source, vsys, type, description, dport, protocol, devicegroup)
                  VALUES 
                  ('all_TCP_ports','all_TCP_ports','$source','$vsys','range','All TCP ports','1-65535','tcp', '$devicegroup'), 
                  ('all_UDP_ports','all_UDP_ports','$source','$vsys','range','All UDP ports','1-65535','udp', '$devicegroup')
                  ";
        $projectdb->query($query);
    }

    public function getMemorySpace(){
        return $this->memorySpace;
    }
    public function getTag(STRING $source, STRING $vsys, STRING $name):MemberObject{

        if(isset($this->memorySpace[$source][$vsys]['tags']['objects'][$name])) {
            $tablename = 'tag';
            $memberlid = $this->memorySpace[$source][$vsys]['tags']['objects'][$name]['id'];
            $member = new MemberObject($memberlid, $tablename, '', '');
        }
        else{
            $member = new MemberObject();
        }

        return $member;
    }

    /***
     * Given a port number and a set of protocols, get the Objects that represent such service. It may
     * return more than 1 service (for TCP and for UDP)
     * NOTE: Only look for the services that can be TCP and UDP
     * @param STRING $source
     * @param STRING $vsys
     * @param STRING $port
     * @param array|null $protocols
     * @return array
     */
    public function getServicePortReference(STRING $devicegroup, STRING $source, STRING $vsys, INT $port, ARRAY $protocols=null){
        $tablename = '';
        $memberlid = '';
        $types = ['services', ];

//        $port = normalizeNames($port);
        $memberObjects = array();

        foreach ($protocols as $protocol){
            if($protocol != 'tcp' && $protocol != 'udp'){
                continue;
            }
            else {
                $objectName = "${protocol}_${port}";
                foreach ($types as $type) {
                    if (isset($this->memorySpace[$source][$vsys][$type]['objectsPorts'][$objectName])) {
                        $tablename = $type;
                        $memberlid = $this->memorySpace[$source][$vsys][$type]['objectsPorts'][$objectName]['id'];
                    }
                }

                if ($tablename == '') {
                    $memberObject = $this->addService($devicegroup, $source, $vsys, $objectName, $protocol, $port);
                }
                else {
                    $memberObject = new MemberObject($memberlid, $tablename, $port, $protocol);
                }
                $memberObjects[] = $memberObject;
            }
        }

        return $memberObjects;
    }

    public function addAddressGroup(ARRAY $data){
        $missingFields = array();
        if(!isset($data['name'])){
            $missingFields[] = 'name';
        }
        else{
            $name = $data['name'];
        }

        if(!isset($data['id'])){
            $missingFields[] = 'id';
        }
        else{
            $id = $data['id'];
        }

        if(!isset($data['source'])){
            $missingFields[] = 'source';
        }
        else{
            $source = $data['source'];
        }

        if(!isset($data['vsys'])){
            $missingFields[] = 'vsys';
        }
        else{
            $vsys = $data['vsys'];
        }

        if(!isset($data['type'])){
            $missingFields[] = 'type';
        }
        else{
            $type = $data['type'];
        }

        if(!isset($data['devicegroup'])){
            $devicegroup = 'default';
        }
        else{
            $devicegroup = $data['devicegroup'];
        }

        if(count($missingFields)>0){
            return [
                'success'   => false,
                'msg'       => "Missing fields ".implode(',',$missingFields),
            ];
        }
        else{
            $this->memorySpace[$source][$vsys]['address_groups_id']['objects'][$name] = [
                'name' => $name,
                'id' => $id,
                'vsys' => $vsys,
                'source' => $source,
                'type' => $type,
                'devicegroup' => $devicegroup
            ];

            return [
                'success'   => true,
                'msg'       => "Address Group registered in Memory"
            ];
        }

    }

    //TODO

    public function getServiceByID(STRING $source, STRING $vsys, INT $id){
        if (isset($this->memorySpace[$source][$vsys]['services']['ids'][$id])){
            return $this->memorySpace[$source][$vsys]['services']['ids'][$id];
        }
        return null;
    }

    public function getServiceWithTimeout(STRING $devicegroup, STRING $source, STRING $vsys, STRING $name, INT $timeout){
        if(isset($this->memorySpace[$source][$vsys]['services']['objects'][$name])){
            $serviceObject = $this->memorySpace[$source][$vsys]['services']['objects'][$name];
            if($serviceObject['timeout'] == $timeout){
                $memberlid = $serviceObject['id'];
                $tablename = $tablename = 'services';
                return $memberObject = new MemberObject($memberlid, $tablename);
            }
            else{
                $serviceName = $serviceObject['name'] . "_t$timeout";
                if(isset($this->memorySpace[$source][$vsys]['services']['objects'][$serviceName])){
                    $serviceObject = $this->memorySpace[$source][$vsys]['services']['objects'][$serviceName];
                    $memberlid = $serviceObject['id'];
                    $tablename = $tablename = 'services';
                    return $memberObject = new MemberObject($memberlid, $tablename);
                }
                else {
                    $serviceName = $serviceObject['name'] . "_t$timeout";
                    $port = $serviceObject['dport'];
                    $protocol = $serviceObject['protocol'];
                    $newService = $this->addService($devicegroup, $source, $vsys, $serviceName, $protocol, $port, $timeout);
                    return $newService;
                }
            }
        }
        elseif(isset($this->memorySpace[$source][$vsys]['services']['objects'][$name."_t$timeout"])){
            $serviceObject = $this->memorySpace[$source][$vsys]['services']['objects'][$name."_t$timeout"];
            $memberlid = $serviceObject['id'];
            $tablename = $tablename = 'services';
            return $memberObject = new MemberObject($memberlid, $tablename);
        }
        else{
            $newService = $this->addService($devicegroup, $source, $vsys, $name, '', '65535', $timeout);
            return $newService;
        }
    }

    public function getServiceReference(STRING $devicegroup, STRING $source, STRING $vsys, STRING $name, ARRAY $protocols=null, BOOL $insertIfMissing = true): array
    {
        $tablename = '';
        $memberlid = '';
        $memberObjects = array();

//        $name = normalizeNames($name);
        //echo "Name service: " .$name. "\n";
        $objectName = $name;

//        echo "Los protocols: \n";
//        print_r($protocols);

        if(is_null($protocols) || count($protocols)==0){
            //echo "memorySpace name: \n";
            //print_r($this->memorySpace[$source][$vsys]['services']['objects'][$objectName]);
            if (isset($this->memorySpace[$source][$vsys]['services']['objects'][$objectName])) {
                $tablename = 'services';
                $memberlid = $this->memorySpace[$source][$vsys]['services']['objects'][$objectName]['id'];
                $memberObject = new MemberObject($memberlid, $tablename);
            }else{
                if ($insertIfMissing) {
                    $memberObject = $this->addService($devicegroup, $source, $vsys, $objectName, 'tcp');
                }
            }
            //echo "Member_lid FUERA: " .$memberlid. "\n";

            $memberObjects[] = $memberObject;
        }
        else {
            foreach ($protocols as $protocol) {
                if (isset($this->memorySpace[$source][$vsys]['services']['objects'][$objectName])) {
                    $tablename = 'services';
                    $memberlid = $this->memorySpace[$source][$vsys]['services']['objects'][$objectName]['id'];
                }
                $memberObject = new MemberObject($memberlid, $tablename);
                $memberObjects[] = $memberObject;

                if($tablename == '') {
                    if (isset($this->memorySpace[$source][$vsys]['services']['objectsPorts'][$protocol . "_" . $objectName])) {
                        $tablename = 'services';
                        $memberlid = $this->memorySpace[$source][$vsys]['services']['objectsPorts'][$protocol . "_" . $objectName]['id'];
                    }
                    $memberObject = new MemberObject($memberlid, $tablename);
                    $memberObjects[] = $memberObject;
                }

                if ($tablename == '') {
                    if (isset($this->memorySpace[$source][$vsys]['services']['objects'][$protocol . "_" . $objectName])) {
                        $tablename = 'services';
                        $memberlid = $this->memorySpace[$source][$vsys]['services']['objects'][$objectName]['id'];
                        $memberObject = new MemberObject($memberlid, $tablename);
                    } else {
                        if ($insertIfMissing) {
                            $memberObject = $this->addService($devicegroup, $source, $vsys, $objectName, $protocol);
                        }
                    }
                    $memberObjects[] = $memberObject;
                }
            }
        }
        return $memberObjects;
    }


    private function addService(STRING $devicegroup, STRING $source, STRING $vsys, STRING $objectName, STRING $protocol, $port=null, $timeout=''): MemberObject{
        $tablename = 'services';
        $memberlid = $this->memorySpace['maxIds']['services']['maxID']+1;
        $this->memorySpace['maxIds']['services']['maxID'] = $memberlid;

        if(is_null($port)){
            //Let's discover first the port number based on the $objectName
            $serviceSiblings = $this->getServiceReference($devicegroup, $source, $vsys, $objectName, ['tcp','udp'], false);
            foreach ($serviceSiblings as $sibling){
                if(isset($sibling->value)){
                    $port = $sibling->value;
                }
            }
        }

        if(isset($this->memorySpace[$source][$vsys]['new-services']['objectsPorts'][$objectName])){
            $memberlid = $this->memorySpace[$source][$vsys]['new-services']['objectsPorts'][$objectName]['id'];
            $tablename = 'services';
            $port = $this->memorySpace[$source][$vsys]['new-services']['objectsPorts'][$objectName]['dport'];
            $protocol =$this->memorySpace[$source][$vsys]['new-services']['objectsPorts'][$objectName]['protocol'];
        }
        else {

            $this->memorySpace[$source][$vsys]['services']['objects'][$objectName] = [
                'name' => $objectName,
                'id' => $memberlid,
                'protocol' => $protocol,
                'sport' => '',
                'dport' => $port,
                'vsys' => $vsys,
                'source' => $source,
                'type' => '',   //It could be "range"
                'timeout'       => $timeout,
                'devicegroup' => $devicegroup
            ];

            $this->memorySpace[$source][$vsys]['services']['objectsPorts'][$objectName] = [
                'name' => $objectName,
                'id' => $memberlid,
                'protocol' => $protocol,
                'sport' => '',
                'dport' => $port,
                'vsys' => $vsys,
                'source' => $source,
                'type' => '',   //It could be "range"
                'timeout'       => $timeout,
                'devicegroup' => $devicegroup
            ];

            $this->memorySpace[$source][$vsys]['services']['ids'][$memberlid] = [
                'name' => $objectName,
                'id' => $memberlid,
                'protocol' => $protocol,
                'sport' => '',
                'dport' => $port,
                'vsys' => $vsys,
                'source' => $source,
                'type' => '',   //It could be "range"
                'timeout'       => $timeout,
                'devicegroup' => $devicegroup
            ];

            $this->memorySpace[$source][$vsys]['new-services']['objectsPorts'][$objectName] = [
                'name' => $objectName,
                'id' => $memberlid,
                'protocol' => $protocol,
                'sport' => '',
                'dport' => $port,
                'vsys' => $vsys,
                'source' => $source,
                'type' => '',   //It could be "range"
                'timeout'   => $timeout,
                'devicegroup' => $devicegroup
            ];
        }

        return new MemberObject($memberlid, $tablename, $port, $protocol);
    }

    private function addNegatedService(STRING $devicegroup, STRING $source, STRING $vsys, STRING $objectName, STRING $protocol, $port=null): MemberObject{
        echo "addServiceCalled\n";
        $tablename = 'services';
        $memberlid = $this->memorySpace['maxIds']['services']['maxID']+1;
        $this->memorySpace['maxIds']['services']['maxID'] = $memberlid;
        $protocols = ['tcp', 'udp', 'sctp'];

        if(is_null($port)){
            //Let's discover first the port number based on the $objectName
            foreach ($protocols as $siblingProtocol) {
                $siblingName = "neq_".$siblingProtocol."_".$objectName;
                if (isset($this->memorySpace[$source][$vsys]['services']['objects'][$siblingName])) {
                    $port = $this->memorySpace[$source][$vsys]['services']['objects'][$siblingName]['dport'];
                }
            }
        }

        $objectName = "neq_".$protocol."_".$objectName;
        $this->memorySpace[$source][$vsys]['services']['objectsPorts'][$objectName] = [
            'name' => $objectName,
            'id' => $memberlid,
            'protocol' => $protocol,
            'sport' => '',
            'dport' => $port,
            'vsys' => $vsys,
            'source' => $source,
            'type' => '',   //It could be "range".
            'timeout'   => '',
            'devicegroup'   => $devicegroup
        ];

        $this->memorySpace[$source][$vsys]['new-services']['objectsPorts'][$objectName] = [
            'name' => $objectName,
            'id' => $memberlid,
            'protocol' => $protocol,
            'sport' => '',
            'dport' => $port,
            'vsys' => $vsys,
            'source' => $source,
            'type' => '',   //It could be "range"
            'timemout'  => '',
            'devicegroup' => $devicegroup
        ];

        return new MemberObject($memberlid, $tablename, $port, $protocol);
    }

    public function getServiceEQ(STRING $devicegroup, STRING $source, STRING $vsys, $service, ARRAY $protocols){
//        $tablename = '';
//        $memberlid = '';
        $memberObjects = array();

        foreach ($protocols as $protocol) {
            $found = false;
            $eqName = $protocol . "_" . $service;
            if (!is_numeric($service)) {
                if (isset($this->memorySpace[$source][$vsys]['services']['objects'][$service])) {
                    //First we check if the service exists in its current name, for instance dns
                    if($this->memorySpace[$source][$vsys]['services']['objects'][$service]['protocol'] == $protocol) {
                        //We check that it is actually the service with the protocol we are looking for
                        $memberlid = $this->memorySpace[$source][$vsys]['services']['objects'][$service]['id'];
                        $tablename = 'services';
                        $memberObject = new MemberObject($memberlid, $tablename, $service, $protocol);
                        $found = true;
                    }
                }
                if(!$found) {
                    if (isset($this->memorySpace[$source][$vsys]['services']['objects'][$eqName])) {
                        //First we check if the service exists in its current name, for instance dns
                        if ($this->memorySpace[$source][$vsys]['services']['objects'][$eqName]['protocol'] == $protocol) {
                            //We check that it is actually the service with the protocol we are looking for
                            $memberlid = $this->memorySpace[$source][$vsys]['services']['objects'][$eqName]['id'];
                            $tablename = 'services';
                            $memberObject = new MemberObject($memberlid, $tablename, $service, $protocol);
                            $found = true;
                        }
                    }
                }
                if(!$found){
                    if (isset($this->memorySpace[$source][$vsys]['services']['objects'][$service])) {
                        //Collect the port value
                        $dport = $this->memorySpace[$source][$vsys]['services']['objects'][$service]['dport'];
                        $memberObject = $this->addService($devicegroup, $source, $vsys, $eqName, $protocol, $dport);
                    }
                    else {
                        $memberObject = $this->addService($devicegroup, $source, $vsys, $eqName, $protocol, '65535');
                    }
                }
                $memberObjects[] = $memberObject;
            }
            else{
                $eqName = $service ."-" . $protocol;
                if (isset($this->memorySpace[$source][$vsys]['services']['objectsPorts'][$eqName])) {
                    $memberlid = $this->memorySpace[$source][$vsys]['services']['objectsPorts'][$eqName]['id'];
                    $tablename = 'services';
                    $memberObject = new MemberObject($memberlid, $tablename, $eqName, $protocol);
                }
                elseif(isset($this->memorySpace[$source][$vsys]['services']['objects'][$service])) {
                    $memberlid = $this->memorySpace[$source][$vsys]['services']['objects'][$service]['id'];
                    $tablename = 'services';
                    $memberObject = new MemberObject($memberlid, $tablename, $eqName, $protocol);
                }
                else{
                    $memberObject = $this->addService($devicegroup, $source, $vsys, $eqName, $protocol, $service);
                }
                $memberObjects[] = $memberObject;
            }
        }

        return $memberObjects;
    }

    public function getServiceNEQ(STRING $devicegroup, STRING $source, STRING $vsys, $service, ARRAY $protocols){
        $tablename = '';
        $memberlid = '';
        $memberObjects = array();

        foreach ($protocols as $protocol){
            $neqName = "neq_".$protocol."_".$service;
            if(!is_numeric($service)){
                //First we check if the service exists in its current name, for instance neq_tcp_dns
                // NOTICE that negated ports are not supported with PANOS, therefore we will have created ourselves
                //   a new service object with our own nomenclature neq_<protocol>_<service>
                if (isset($this->memorySpace[$source][$vsys]['services']['objects'][$neqName])) {
                    //No need to check the protocol, because it should be in its name "$neqName"
                    $memberObject = new MemberObject($memberlid, $tablename, $neqName, $protocol);
                }
                else{
                    $memberObject = $this->addNegatedService($devicegroup, $source, $vsys, $service, $protocol);
                }
                $memberObjects[] = $memberObject;
            }
            else{
                if (isset($this->memorySpace[$source][$vsys]['services']['objectsPorts'][$neqName])) {
                    $memberObject = new MemberObject($memberlid, $tablename, $neqName, $protocol);
                }
                else{
                    $memberObject = $this->addService($devicegroup, $source, $vsys, $neqName, $protocol, $service);
                }
                $memberObjects[] = $memberObject;
            }
        }

        return $memberObjects;
    }

    public function getServiceLT(STRING $devicegroup, STRING $source, STRING $vsys, $port, ARRAY $protocols){
        $tablename = '';
        $memberlid = '';
        $memberObjects = array();


        if(!is_numeric($port)){
            if (isset($this->memorySpace[$source][$vsys]['services']['objects'][$port])) {
                $port = $this->memorySpace[$source][$vsys]['services']['objects'][$port]['dport'];
            }
        }
        $objectName = "0-".($port-1);

        foreach ($protocols as $protocol) {
            if (isset($this->memorySpace[$source][$vsys]['services']['objects'][$protocol."_".$objectName])) {
                $tablename = 'services';
                $memberlid = $this->memorySpace[$source][$vsys]['services']['objects'][$protocol."_".$objectName]['id'];
                $memberObject = new MemberObject($memberlid, $tablename, $objectName, $protocol);
            }
            else{
                $memberObject = $this->addService($devicegroup, $source, $vsys, $protocol."_".$objectName, $protocol, $objectName);
            }

            $memberObjects[] = $memberObject;
        }
        return $memberObjects;
    }

    public function getServiceGT(STRING $devicegroup, STRING $source, STRING $vsys, $port, ARRAY $protocols){
        $tablename = '';
        $memberlid = '';
        $types = ['services',];
        $memberObjects = array();


        if(!is_numeric($port)){
            if (isset($this->memorySpace[$source][$vsys]['services']['objects'][$port])) {
                $port = $this->memorySpace[$source][$vsys]['services']['objects'][$port]['dport'];
            }
        }
        $objectName = ($port+1)."-65535";

        foreach ($protocols as $protocol) {
            if (isset($this->memorySpace[$source][$vsys]['services']['objects'][$protocol."_".$objectName])) {
                $tablename = 'services';
                $memberlid = $this->memorySpace[$source][$vsys]['services']['objects'][$protocol."_".$objectName]['id'];
                $memberObject = new MemberObject($memberlid, $tablename, $objectName, $protocol);
            }
            else{
                $memberObject = $this->addService($devicegroup, $source, $vsys, $protocol."_".$objectName, $protocol, $objectName);
            }

            $memberObjects[] = $memberObject;
        }
        return $memberObjects;
    }

    public function getServiceRangeReference(STRING $devicegroup, STRING $source, STRING $vsys, $first, $second, ARRAY $protocols=null): array{
        $tablename = '';
        $memberlid = '';
        $types = ['services',];
        $memberObjects = array();


        if(!is_numeric($first)){
            foreach ($protocols as $protocol) {
                $first_array_names = [$first, $protocol."_".$first];
                foreach ($first_array_names as $first_name) {
                    if (isset($this->memorySpace[$source][$vsys]['services']['objects'][$first_name])) {
                        $first = $this->memorySpace[$source][$vsys]['services']['objects'][$first_name]['dport'];
                        break;
                    }
                }
            }
        }

        if(!is_numeric($second)){
            foreach ($protocols as $protocol) {
                $second_array_names = [$second, $protocol . "_" . $second];
                foreach ($second_array_names as $second_name) {
                    if (isset($this->memorySpace[$source][$vsys]['services']['objects'][$second_name])) {
                        $second = $this->memorySpace[$source][$vsys]['services']['objects'][$second_name]['dport'];
                        break;
                    }
                }
            }
        }

        $objectName = $first."-".$second;


        foreach ($protocols as $protocol) {
            if (isset($this->memorySpace[$source][$vsys]['services']['objectsPorts'][$protocol."_".$objectName])) {
                $tablename = 'services';
                $memberlid = $this->memorySpace[$source][$vsys]['services']['objectsPorts'][$protocol."_".$objectName]['id'];
                $memberObject = new MemberObject($memberlid, $tablename, $objectName, $protocol);
            }
            elseif(isset($this->memorySpace[$source][$vsys]['services']['objects'][$protocol."_".$objectName])){
                $tablename = 'services';
                $memberlid = $this->memorySpace[$source][$vsys]['services']['objects'][$protocol."_".$objectName]['id'];
                $memberObject = new MemberObject($memberlid, $tablename, $objectName, $protocol);
            }
            else{
                $memberObject = $this->addService($devicegroup, $source, $vsys, $protocol."_".$objectName, $protocol, $objectName);
            }

            $memberObjects[] = $memberObject;
        }
        return $memberObjects;
    }

    public function getServiceGroupReference(STRING $devicegroup, STRING $source, STRING $vsys, STRING $name):array{
        $tablename = '';
        $memberlid = '';
        $types = ['services_groups_id', ];

//        $name = normalizeNames($name);

        $objectName = $name;

        foreach ($types as $type) {
            if (isset($this->memorySpace[$source][$vsys][$type]['objects'][$objectName])) {
                $tablename = $type;
                $memberlid = $this->memorySpace[$source][$vsys][$type]['objects'][$objectName]['id'];
            }
        }

        $memberObject = new MemberObject($memberlid, $tablename, $name, 'service_group');
        return [$memberObject];
    }

    public function getProtocolGroupReference(STRING $devicegroup, STRING $source, STRING $vsys, STRING $name):array {
        $tablename = '';
        $memberlid = '';
        $types = ['cisco_protocol_groups','services_groups_id', ];

//        $name = normalizeNames($name);
        $objectName = $name;

        if (isset($this->memorySpace[$source][$vsys]['cisco_protocol_groups']['objects'][$objectName])) {
            $tablename = 'cisco_protocol_groups';
            $memberlid = $this->memorySpace[$source][$vsys]['cisco_protocol_groups']['objects'][$objectName]['id'];
            $name = $objectName;
            $protocols = $this->memorySpace[$source][$vsys]['cisco_protocol_groups']['objects'][$objectName]['members'];
            $member = [
                'type'  => 'cisco_protocol_groups',
                'value' => $protocols
            ];
        }
        else{
            if (isset($this->memorySpace[$source][$vsys]['services_groups_id']['objects'][$objectName])) {
                $tablename = 'services_groups_id';
                $memberlid = $this->memorySpace[$source][$vsys]['services_groups_id']['objects'][$objectName]['id'];
            }

            $member = [
                'type'  => 'services_groups_id',
                'value' => [new MemberObject($memberlid, $tablename, $name, 'service_group')]
            ];
        }


        return $member;
    }

    public function getObjectReference(STRING $devicegroup, STRING $source, STRING $vsys, STRING $name, INT $cidr=null){
        $tablename = '';
        $memberlid = '';
        $types = ['object-address', 'services', ];

//        $name = normalizeNames($name);
        $objectName = $name;
        if(!is_null($cidr)){
            $objectName .= "-$cidr";
        }

        foreach ($types as $type) {
            if (isset($this->memorySpace[$source][$vsys][$type]['objects'][$objectName])) {
                if($type == 'object-address') {
                    $tablename = 'address';
                }
                else {
                    $tablename = $type;
                }
                $memberlid = $this->memorySpace[$source][$vsys][$type]['objects'][$objectName]['id'];
            }
        }

        if($tablename==''){
            if ( isset($this->memorySpace[$source][$vsys]['object-address']['objects'][$name]) &&
                $this->memorySpace[$source][$vsys]['object-address']['objects'][$name]['cidr']==$cidr ) {

                $tablename = 'address';
                $memberlid = $this->memorySpace[$source][$vsys]['object-address']['objects'][$name]['id'];
            }
            else{
                //TODO we need to look for the label and create and object if necessary
                echo "TODO we need to look for the label and create and object if necessary\n";
            }
        }

        $memberObject = new MemberObject($memberlid, $tablename);
        return $memberObject;
    }

    public function getObjectGroupReference(STRING $devicegroup, STRING $source, STRING $vsys, STRING $name, INT $cidr=null){
        $tablename = '';
        $memberlid = '';
        $types = ['address-groups-id', 'services-groups-id', ];

//        $name = normalizeNames($name);
        $objectName = $name;
        if(!is_null($cidr)){
            $objectName .= "-$cidr";
        }

        foreach ($types as $type) {
            if (isset($this->memorySpace[$source][$vsys][$type]['objects'][$objectName])) {
                $tablename = $type;
                $memberlid = $this->memorySpace[$source][$vsys][$type]['objects'][$objectName]['id'];
            }
        }

        $memberObject = new MemberObject($memberlid, $tablename);
        return $memberObject;
    }

    public function getIPAddressReference(STRING $devicegroup, STRING $source, STRING $vsys, STRING $name, INT $cidr=null){
        $tablename = '';
        $memberlid = '';
        $types = ['object-address'];

//        $name = normalizeNames($name);
        $objectName = $name;
        $name_normalized = normalizeNames($name);

        foreach ($types as $type) {
            if (isset($this->memorySpace[$source][$vsys][$type]['objectsips'][$objectName])) {
                if($type == 'object-address') {
                    $tablename = 'address';
                }
                else {
                    $tablename = $type;
                }
                $memberlid = $this->memorySpace[$source][$vsys][$type]['objectsips'][$objectName]['id'];
            }
        }

        if($tablename == ''){
            $tablename='address';
            $memberlid = $this->memorySpace['maxIds']['object-address']['maxID']+1;
            $this->memorySpace['maxIds']['object-address']['maxID'] = $memberlid;

            $this->memorySpace[$source][$vsys]['object-address']['objectsips'][$objectName] = [
                'name'          => "H-".$name_normalized."-".$cidr,
                'id'            => $memberlid,
                'ipaddress'     => $objectName,
                'cidr'          => $cidr,
                'v4'            => 1,
                'v6'            => 0,
                'vsys'          => $vsys,
                'source'        => $source,
                'type'          => 'ip-netmask',
                'vtype'         => 'object',
                'devicegroup'   => $devicegroup,
                'description'   => ''
            ];

            $this->memorySpace[$source][$vsys]['new-address']['objectsips'][$objectName] = [
                'name'          => "H-".$name_normalized."-".$cidr,
                'id'            => $memberlid,
                'ipaddress'     => $objectName,
                'cidr'          => $cidr,
                'v4'            => 1,
                'v6'            => 0,
                'vsys'          => $vsys,
                'source'        => $source,
                'type'          => 'ip-netmask',
                'vtype'         => 'object',
                'devicegroup'   => $devicegroup,
                'description'   => ''
            ];
        }

        $memberObject = new MemberObject($memberlid, $tablename, $objectName, $cidr);
        return $memberObject;
    }

    public function getIPv6AddressReference(STRING $devicegroup, STRING $source, STRING $vsys, STRING $name, INT $cidr=null){
        $tablename = '';
        $memberlid = '';
        $types = ['object-address'];

//        $name = normalizeNames($name);
        $objectName = $name;
        $name_normalized = normalizeNames($name);

        foreach ($types as $type) {
            if (isset($this->memorySpace[$source][$vsys][$type]['objectsips'][$objectName])) {
                if($type == 'object-address') {
                    $tablename = 'address';
                }
                else {
                    $tablename = $type;
                }
                $memberlid = $this->memorySpace[$source][$vsys][$type]['objectsips'][$objectName]['id'];
            }
        }

        if($tablename == ''){
            $tablename='address';
            $memberlid = $this->memorySpace['maxIds']['object-address']['maxID']+1;
            $this->memorySpace['maxIds']['object-address']['maxID'] = $memberlid;

            $this->memorySpace[$source][$vsys]['object-address']['objectsips'][$objectName] = [
                'name'          => "H-".$name_normalized."-".$cidr,
                'id'            => $memberlid,
                'ipaddress'     => $objectName,
                'cidr'          => $cidr,
                'v4'            => 0,
                'v6'            => 1,
                'vsys'          => $vsys,
                'source'        => $source,
                'type'          => 'ip-netmask',
                'vtype'         => 'object',
                'devicegroup'   => $devicegroup,
                'description'   => ''
            ];

            $this->memorySpace[$source][$vsys]['new-address']['objectsips'][$objectName] = [
                'name'          => "H-".$name_normalized."-".$cidr,
                'id'            => $memberlid,
                'ipaddress'     => $objectName,
                'cidr'          => $cidr,
                'v4'            => 0,
                'v6'            => 1,
                'vsys'          => $vsys,
                'source'        => $source,
                'type'          => 'ip-netmask',
                'vtype'         => 'object',
                'devicegroup'   => $devicegroup,
                'description'   => ''
            ];
        }

        $memberObject = new MemberObject($memberlid, $tablename, $objectName, $cidr);
        return $memberObject;
    }

    public function getAddressReference(STRING $devicegroup, STRING $source, STRING $vsys, STRING $name, INT $cidr=null){
        $tablename = '';
        $memberlid = '';
        $types = ['object-address'];


//        $name = normalizeNames($name);
        $objectName = $name;
        if(!is_null($cidr)){
            $objectName .= "-$cidr";
        }

        foreach ($types as $type) {
            if (isset($this->memorySpace[$source][$vsys][$type]['objects'][$objectName])) {
                if($type == 'object-address'){
                    $tablename = 'address';
                }
                else {
                    $tablename = $type;
                }
                $memberlid = $this->memorySpace[$source][$vsys][$type]['objects'][$objectName]['id'];
            }
        }

        if($tablename == ''){
            $tablename='address';
            $memberlid = $this->memorySpace['maxIds']['object-address']['maxID']+1;
            $this->memorySpace['maxIds']['object-address']['maxID'] = $memberlid;

            $ver = ip_version($name);
            $name_normalized = normalizeNames($name);
            if($ver == 'v4' || $ver == 'v6'){
//                $addressName = "H-".$name."-".$cidr;
                $ipvalue = $name;
                $description = '';
                if(!is_null($cidr) && $cidr!='') {
                    $addressName = ($cidr=='32' || $cidr=='128')?"H-".$name_normalized . "-" . $cidr : "N-".$name_normalized . "-" . $cidr;
                }
                else{
                    $addressName = "H-".$name_normalized."-32";
                }
            }
            else{
                if(!is_null($cidr) && $cidr!='') {
                    $addressName = $name_normalized . "-" . $cidr;
                }
                else{
                    $cidr = 32;
                    $addressName = $name_normalized."-32";
                }
                if(isset($this->memorySpace[$source][$vsys]['label-address']['objects'][$name])){
                    $ipvalue = $this->memorySpace[$source][$vsys]['label-address']['objects'][$name]['ipaddress'];
                    $description = $this->memorySpace[$source][$vsys]['label-address']['objects'][$name]['description'] . " (with CIDR $cidr)";
                }
                else{
                    $ipvalue = '1.1.1.1';
                    $description = "Name not found";
//                    print_r(debug_backtrace());
                }
            }

            $this->memorySpace[$source][$vsys]['object-address']['objects'][$objectName] = [
                'name'          => $addressName,
                'id'            => $memberlid,
                'ipaddress'     => $ipvalue,
                'cidr'          => $cidr,
                'v4'            => 1,
                'v6'            => 0,
                'vsys'          => $vsys,
                'source'        => $source,
                'type'          => 'ip-netmask',
                'vtype'         => 'object',
                'devicegroup'   => $devicegroup,
                'description'   => $description
            ];

            $this->memorySpace[$source][$vsys]['new-address']['objects'][$objectName] = [
                'name'          => $addressName,
                'id'            => $memberlid,
                'ipaddress'     => $ipvalue,
                'cidr'          => $cidr,
                'v4'            => 1,
                'v6'            => 0,
                'vsys'          => $vsys,
                'source'        => $source,
                'type'          => 'ip-netmask',
                'vtype'         => 'object',
                'devicegroup'   => $devicegroup,
                'description'   => $description
            ];
        }

        $memberObject = new MemberObject($memberlid, $tablename, $objectName, $cidr);
        return $memberObject;
    }

    public function getAddressGroupReference(STRING $devicegroup, STRING $source, STRING $vsys, STRING $name, INT $cidr=null){
        $tablename = '';
        $memberlid = '';
        $types = ['address_groups_id'];
        $found = false;

//        $name = normalizeNames($name);
        $objectName = $name;
        if(!is_null($cidr)){
            $objectName .= "-$cidr";
        }

        foreach ($types as $type) {
            if (isset($this->memorySpace[$source][$vsys][$type]['objects'][$objectName])) {
                $tablename = $type;
                $memberlid = $this->memorySpace[$source][$vsys][$type]['objects'][$objectName]['id'];
                $found = true;
                break;
            }
        }

        if(!$found){
            return null;
        }

        $memberObject = new MemberObject($memberlid, $tablename, $objectName, $cidr);
        return $memberObject;
    }

    public function getUsers(STRING $devicegroup, STRING $source, STRING $vsys, STRING $name):array{
        $users = array();
        if(isset($this->memorySpace[$source][$vsys]['userGroups'][$name])){
            $users = $this->memorySpace[$source][$vsys]['userGroups'][$name];
        }

        return $users;

    }

    public function load_addresses_inMemory($data){
        /* @var $projectdb MySQLi*/
        $projectdb = $data['projectdb'];
        $source=$data['source'];

        # Address
        $loadData=$projectdb->query("SELECT id,name_ext,ipaddress,cidr,v4,v6,vsys,source,type,vtype, devicegroup, description FROM address WHERE source='$source' ORDER BY id;");
        if ($loadData->num_rows>0){
            while($data=$loadData->fetch_assoc()){
                $vtype = ($data['vtype']=='object')?'object-':'label-';
                //Addresses indexed by name
                $this->memorySpace[$source][$data['vsys']][$vtype.'address']['objects'][$data['name_ext']]=[
                    'name'          => $data['name_ext'],
                    'id'            => $data['id'],
                    'ipaddress'     => $data['ipaddress'],
                    'cidr'          => $data['cidr'],
                    'v4'            => $data['v4'],
                    'v6'            => $data['v6'],
                    'vsys'          => $data['vsys'],
                    'source'        => $data['source'],
                    'type'          => $data['type'],
                    'devicegroup'   => $data['devicegroup'],
                    'description'   => $data['description'],
                ];

                //Index to search for id. Given an id, returns the object name so we can search by name
                $this->memorySpace[$source][$data['vsys']][$vtype.'address']['ids'][$data['id']]=[
                    'name'          => $data['name_ext'],
                ];

                $this->memorySpace[$source][$data['vsys']][$vtype.'address']['objectsips'][$data['ipaddress']."-".$data['cidr']]=[
                    'name'          => $data['name_ext'],
                    'id'            => $data['id'],
                    'ipaddress'     => $data['ipaddress'],
                    'cidr'          => $data['cidr'],
                    'v4'            => $data['v4'],
                    'v6'            => $data['v6'],
                    'vsys'          => $data['vsys'],
                    'source'        => $data['source'],
                    'type'          => $data['type'],
                    'devicegroup'   => $data['devicegroup'],
                    'description'   => $data['description'],
                ];

            }
        }
        $loadMaxAddress=$projectdb->query("SELECT max(id) as lastID FROM address;");
        if($loadMaxAddress->num_rows >0){
            $data = $loadMaxAddress->fetch_assoc();
            $this->memorySpace['maxIds']['object-address']['maxID']=$data['lastID'];
        }else{
            $this->memorySpace['maxIds']['object-address']['maxID']=0;
        }
    }

    public function load_services_inMemory($data){
        /* @var $projectdb MySQLi*/
        $projectdb = $data['projectdb'];
        $source=$data['source'];

        # Service
        $loadData=$projectdb->query("SELECT id,name_ext,protocol, sport, dport, vsys, source, type, devicegroup, timeout FROM services WHERE source='$source' ORDER BY id;");
        if ($loadData->num_rows>0){
            while($data=$loadData->fetch_assoc()){
                //Services indexed by name
                $this->memorySpace[$source][$data['vsys']]['services']['objects'][$data['name_ext']]=[
                    'name'          => $data['name_ext'],
                    'id'            => $data['id'],
                    'protocol'      => $data['protocol'],
                    'sport'         => $data['sport'],
                    'dport'         => $data['dport'],
                    'vsys'          => $data['vsys'],
                    'source'        => $data['source'],
                    'type'          => $data['type'],
                    'timeout'       => $data['timeout'],
                    'devicegroup'   => $data['devicegroup']
                ];

                //Index to search for id. Given an id, returns the object name so we can search by name
                $this->memorySpace[$source][$data['vsys']]['services']['ids'][$data['id']]=[
                    'name'          => $data['name_ext'],
                    'id'            => $data['id'],
                    'protocol'      => $data['protocol'],
                    'sport'         => $data['sport'],
                    'dport'         => $data['dport'],
                    'vsys'          => $data['vsys'],
                    'source'        => $data['source'],
                    'type'          => $data['type'],
                    'timeout'       => $data['timeout'],
                    'devicegroup'   => $data['devicegroup']
                ];

                $this->memorySpace[$source][$data['vsys']]['services']['objectsPorts'][$data['dport'].'-'.$data['protocol']]=[
                    'name'          => $data['name_ext'],
                    'id'            => $data['id'],
                    'protocol'      => $data['protocol'],
                    'sport'         => $data['sport'],
                    'dport'         => $data['dport'],
                    'vsys'          => $data['vsys'],
                    'source'        => $data['source'],
                    'type'          => $data['type'],
                    'timeout'       => $data['timeout'],
                    'devicegroup'   => $data['devicegroup']
                ];
            }
        }

        $loadMaxService=$projectdb->query("SELECT max(id) as lastID FROM services;");
        if($loadMaxService->num_rows >0){
            $data = $loadMaxService->fetch_assoc();
            $this->memorySpace['maxIds']['services']['maxID']=$data['lastID'];
        }else{
            $this->memorySpace['maxIds']['services']['maxID']=0;
        }

        # Protocol-Groups
        $loadData=$projectdb->query("SELECT id,name,vsys,source,member FROM cisco_protocol_groups WHERE source='$source' ORDER BY id;");
        if ($loadData->num_rows>0){
            while($data=$loadData->fetch_assoc()){
                if(!isset($this->memorySpace[$source][$data['vsys']]['cisco_protocol_groups']['objects'][$data['name']])) {
                    $this->memorySpace[$source][$data['vsys']]['cisco_protocol_groups']['objects'][$data['name']] = [
                        'name' => $data['name'],
                        'members' => array($data['member']),
                        'id' => $data['id'],
                        'vsys' => $data['vsys'],
                        'source' => $data['source'],
                    ];
                }
                else{
                    $this->memorySpace[$source][$data['vsys']]['cisco_protocol_groups']['objects'][$data['name']]['members'][] = $data['member'];
                }
            }
        }
        $loadMaxCiscoProtocols=$projectdb->query("SELECT max(id) as lastID FROM cisco_protocol_groups;");
        if($loadMaxCiscoProtocols->num_rows >0){
            $data = $loadMaxCiscoProtocols->fetch_assoc();
            $this->memorySpace['maxIds']['cisco_protocol_groups']['maxID']=$data['lastID'];
        }else{
            $this->memorySpace['maxIds']['cisco_protocol_groups']['maxID']=0;
        }

    }

    public function load_AllObjects_inMemory($data){
        /* @var $projectdb MySQLi*/
        $projectdb = $data['projectdb'];
        $source=$data['source'];

        # Address
        $loadData=$projectdb->query("SELECT id,name_ext,ipaddress,cidr,v4,v6,vsys,source,type,vtype, devicegroup, description FROM address WHERE source='$source' ORDER BY id;");
        if ($loadData->num_rows>0){
            while($data=$loadData->fetch_assoc()){
                $vtype = ($data['vtype']=='object')?'object-':'label-';
                //Addresses indexed by name
                $this->memorySpace[$source][$data['vsys']][$vtype.'address']['objects'][$data['name_ext']]=[
                    'name'          => $data['name_ext'],
                    'id'            => $data['id'],
                    'ipaddress'     => $data['ipaddress'],
                    'cidr'          => $data['cidr'],
                    'v4'            => $data['v4'],
                    'v6'            => $data['v6'],
                    'vsys'          => $data['vsys'],
                    'source'        => $data['source'],
                    'type'          => $data['type'],
                    'devicegroup'   => $data['devicegroup'],
                    'description'   => $data['description'],
                ];

                //Index to search for id. Given an id, returns the object name so we can search by name
                $this->memorySpace[$source][$data['vsys']][$vtype.'address']['ids'][$data['id']]=[
                    'name'          => $data['name_ext'],
                ];

                $this->memorySpace[$source][$data['vsys']][$vtype.'address']['objectsips'][$data['ipaddress']]=[
                    'name'          => $data['name_ext'],
                    'id'            => $data['id'],
                    'ipaddress'     => $data['ipaddress'],
                    'cidr'          => $data['cidr'],
                    'v4'            => $data['v4'],
                    'v6'            => $data['v6'],
                    'vsys'          => $data['vsys'],
                    'source'        => $data['source'],
                    'type'          => $data['type'],
                    'devicegroup'   => $data['devicegroup'],
                    'description'   => $data['description'],
                ];

            }
        }
        $loadMaxAddress=$projectdb->query("SELECT max(id) as lastID FROM address;");
        if($loadMaxAddress->num_rows >0){
            $data = $loadMaxAddress->fetch_assoc();
            $this->memorySpace['maxIds']['object-address']['maxID']=$data['lastID'];
        }else{
            $this->memorySpace['maxIds']['object-address']['maxID']=0;
        }

        # Address-Groups
        $loadData=$projectdb->query("SELECT id,name_ext,vsys,source,type FROM address_groups_id WHERE source='$source' ORDER BY id;");
        if ($loadData->num_rows>0){
            while($data=$loadData->fetch_assoc()){
                //Address-groups indexed by name
                $this->memorySpace[$source][$data['vsys']]['address_groups_id']['objects'][$data['name_ext']]=[
                    'name'          => $data['name_ext'],
                    'id'            => $data['id'],
                    'vsys'          => $data['vsys'],
                    'source'        => $data['source'],
                    'type'          => $data['type'],
                ];

                //Index to search for id. Given an id, returns the object name so we can search by name
                $this->memorySpace[$source][$data['vsys']]['address_groups_id']['ids'][$data['id']]=[
                    'name'          => $data['name_ext'],
                ];
            }
        }
        $loadMaxAddressGrID=$projectdb->query("SELECT max(id) as lastID FROM address_groups_id;");
        if($loadMaxAddressGrID->num_rows >0){
            $data = $loadMaxAddressGrID->fetch_assoc();
            $this->memorySpace['maxIds']['address_groups_id']['maxID']=$data['lastID'];
        }else{
            $this->memorySpace['maxIds']['address_groups_id']['maxID']=0;
        }

        # Address-Groups and Address relations
        $loadData=$projectdb->query("SELECT lid, member_lid, table_name, vsys,source,member FROM address_groups WHERE source='$source' ORDER BY id;");
        if ($loadData->num_rows>0){
            while($data=$loadData->fetch_assoc()){
                if($data['table_name']==''){
                    //We need to collect its member_lid and table_name given the objects name
                    //Check first if it is a object or a label
                    //"_mt_object"
                    if(substr( $data['member'], 0, 7 ) === "_mtobj_"){
                        $data['member'] = substr($data['member'],7);
                        if(isset($this->memorySpace[$data['source']][$data['vsys']]['object-address']['objects'][$data['member']])){
                            $data['table_name'] = 'address';
                            $data['member_lid'] = $this->memorySpace[$data['source']][$data['vsys']]['object-address']['objects'][$data['member']]['id'];

                        }
                        else{
                            //TODO: Write a warning
                            echo "And we didn't find ".$data['member']."\n";

                        }
                    }
                    elseif(isset($this->memorySpace[$data['source']][$data['vsys']]['object-address']['objects'][$data['member']])){
                        $data['table_name'] = 'address';
                        $data['member_lid'] = $this->memorySpace[$data['source']][$data['vsys']]['object-address']['objects'][$data['member']]['id'];
                    }
                    elseif(isset($this->memorySpace[$data['source']][$data['vsys']]['label-address']['objects'][$data['member']])){
                        $data['table_name'] = 'address';
                        $data['member_lid'] = $this->memorySpace[$data['source']][$data['vsys']]['address']['objects'][$data['member']]['id'];
                        echo "The group ".$data['lid']." contains ".$data['table_name']."-".$data['member_lid'];
                        //TODO
                    }
                    elseif(isset($this->memorySpace[$data['source']][$data['vsys']]['address_groups_id']['objects'][$data['member']])){
                        $data['table_name'] = 'address_groups_id';
                        $data['member_lid'] = $this->memorySpace[$data['source']][$data['vsys']]['address_groups_id']['objects'][$data['member']]['id'];
                    }
                    else{
                        //TODO: Write a warning
                        echo "Address ".$data['member']." not found to be inserted in group ".$data['lid']."\n";
                    }
                }
                $this->memorySpace[$source][$data['vsys']]['address_groups']['objects'][$data['lid']][]=[
                    'lid'           => $data['lid'],
                    'member_lid'    => $data['member_lid'],
                    'table_name'    => $data['table_name'],
                    'vsys'          => $data['vsys'],
                    'source'        => $data['source'],
                ];
            }
        }

        # Service
        $loadData=$projectdb->query("SELECT id,name_ext,protocol, sport, dport, vsys, source, type, devicegroup, timeout FROM services WHERE source='$source' ORDER BY id;");
        if ($loadData->num_rows>0){
            while($data=$loadData->fetch_assoc()){
                //Services indexed by name
                $this->memorySpace[$source][$data['vsys']]['services']['objects'][$data['name_ext']]=[
                    'name'          => $data['name_ext'],
                    'id'            => $data['id'],
                    'protocol'      => $data['protocol'],
                    'sport'         => $data['sport'],
                    'dport'         => $data['dport'],
                    'vsys'          => $data['vsys'],
                    'source'        => $data['source'],
                    'type'          => $data['type'],
                    'timeout'       => $data['timeout'],
                    'devicegroup'   => $data['devicegroup']
                ];

                //Index to search for id. Given an id, returns the object name so we can search by name
                $this->memorySpace[$source][$data['vsys']]['services']['ids'][$data['id']]=[
                    'name'          => $data['name_ext'],
                    'id'            => $data['id'],
                    'protocol'      => $data['protocol'],
                    'sport'         => $data['sport'],
                    'dport'         => $data['dport'],
                    'vsys'          => $data['vsys'],
                    'source'        => $data['source'],
                    'type'          => $data['type'],
                    'timeout'       => $data['timeout'],
                    'devicegroup'   => $data['devicegroup']
                ];

                $this->memorySpace[$source][$data['vsys']]['services']['objectsPorts'][$data['dport'].'-'.$data['protocol']]=[
                    'name'          => $data['name_ext'],
                    'id'            => $data['id'],
                    'protocol'      => $data['protocol'],
                    'sport'         => $data['sport'],
                    'dport'         => $data['dport'],
                    'vsys'          => $data['vsys'],
                    'source'        => $data['source'],
                    'type'          => $data['type'],
                    'timeout'       => $data['timeout'],
                    'devicegroup'   => $data['devicegroup']
                ];
            }
        }
        $loadMaxService=$projectdb->query("SELECT max(id) as lastID FROM services;");
        if($loadMaxService->num_rows >0){
            $data = $loadMaxService->fetch_assoc();
            $this->memorySpace['maxIds']['services']['maxID']=$data['lastID'];
        }else{
            $this->memorySpace['maxIds']['services']['maxID']=0;
        }

        # Service-Groups_id
        $loadData=$projectdb->query("SELECT id,name_ext,vsys,source, type, devicegroup FROM services_groups_id WHERE source='$source' ORDER BY id;");
        if ($loadData->num_rows>0){
            while($data=$loadData->fetch_assoc()){
                //Service groups indexed by name
                $this->memorySpace[$source][$data['vsys']]['services_groups_id']['objects'][$data['name_ext']]=[
                    'name'          => $data['name_ext'],
                    'id'            => $data['id'],
                    'vsys'          => $data['vsys'],
                    'source'        => $data['source'],
                    'type'          => $data['type'],
                    'devicegroup'   => $data['devicegroup']
                ];

                //Index to search for id. Given an id, returns the object name so we can search by name
                $this->memorySpace[$source][$data['vsys']]['services_groups_id']['ids'][$data['id']]=[
                    'name'          => $data['name_ext'],
                ];
            }
        }
        $loadMaxServiceGrID=$projectdb->query("SELECT max(id) as lastID FROM services_groups_id;");
        if($loadMaxServiceGrID->num_rows >0){
            $data = $loadMaxServiceGrID->fetch_assoc();
            $this->memorySpace['maxIds']['services_groups_id']['maxID']=$data['lastID'];
        }else{
            $this->memorySpace['maxIds']['services_groups_id']['maxID']=0;
        }

        # Service-Groups and Service relations
        $loadData=$projectdb->query("SELECT lid, member_lid, table_name, vsys,source,member, devicegroup FROM services_groups WHERE source='$source' ORDER BY id;");
        if ($loadData->num_rows>0){
            while($data=$loadData->fetch_assoc()){
                if($data['table_name']==''){
                    //We need to collect its member_lid and table_name given the objects name
                    if(isset($this->memorySpace[$data['source']][$data['vsys']]['services']['objects'][$data['member']])){
                        $data['table_name'] = 'services';
                        $data['member_lid'] = $this->memorySpace[$data['source']][$data['vsys']]['services']['objects'][$data['member']]['id'];
                    }
                    elseif(isset($this->memorySpace[$data['source']][$data['vsys']]['services_groups_id']['objects'][$data['member']])){
                        $data['table_name'] = 'services_groups_id';
                        $data['member_lid'] = $this->memorySpace[$data['source']][$data['vsys']]['services_groups_id']['objects'][$data['member']]['id'];
                    }
                    else{
                        echo "Service ".$data['member']." not found to be inserted in group ".$data['lid']."\n";
                    }
                }
                $this->memorySpace[$source][$data['vsys']]['services_groups']['objects'][$data['lid']][]=[
                    'lid'           => $data['lid'],
                    'member_lid'    => $data['member_lid'],
                    'table_name'    => $data['table_name'],
                    'vsys'          => $data['vsys'],
                    'source'        => $data['source'],
                    'devicegroup'   => $data['devicegroup']
                ];
            }
        }

        # Protocol-Groups
        $loadData=$projectdb->query("SELECT id,name,vsys,source,member FROM cisco_protocol_groups WHERE source='$source' ORDER BY id;");
        if ($loadData->num_rows>0){
            while($data=$loadData->fetch_assoc()){
                if(!isset($this->memorySpace[$source][$data['vsys']]['cisco_protocol_groups']['objects'][$data['name']])) {
                    $this->memorySpace[$source][$data['vsys']]['cisco_protocol_groups']['objects'][$data['name']] = [
                        'name' => $data['name'],
                        'members' => array($data['member']),
                        'id' => $data['id'],
                        'vsys' => $data['vsys'],
                        'source' => $data['source'],
                    ];
                }
                else{
                    $this->memorySpace[$source][$data['vsys']]['cisco_protocol_groups']['objects'][$data['name']]['members'][] = $data['member'];
                }
            }
        }
        $loadMaxCiscoProto=$projectdb->query("SELECT max(id) as lastID FROM cisco_protocol_groups;");
        if($loadMaxCiscoProto->num_rows >0){
            $data = $loadMaxCiscoProto->fetch_assoc();
            $this->memorySpace['maxIds']['cisco_protocol_groups']['maxID']=$data['lastID'];
        }else{
            $this->memorySpace['maxIds']['cisco_protocol_groups']['maxID']=0;
        }

        $loadData = $projectdb->query("SELECT id,name FROM default_applications ORDER BY id;");
        if ($loadData->num_rows>0){
            while($data=$loadData->fetch_assoc()){
                $this->memorySpace['default_applications']['objects'][$data['name']] = [
                    'name' => $data['name'],
                    'id' => $data['id'],
                ];
            }
        }
    }

    public function reloadTags(MySQLi $projectdb, STRING $source, STRING $vsys){
        $loadData = $projectdb->query("SELECT id,name FROM tag WHERE source='$source' AND vsys='$vsys' ORDER BY id;");
        if ($loadData->num_rows>0){
            while($data=$loadData->fetch_assoc()){
                $this->memorySpace[$source][$vsys]['tags']['objects'][$data['name']] = [
                    'name' => $data['name'],
                    'id' => $data['id'],
                ];
            }
        }
    }

    public function addUsers(STRING $devicegroup, STRING $source, STRING $vsys, ARRAY $usersObj){
        foreach ($usersObj as $key => $userGroup){
            $this->memorySpace[$source][$vsys]['userGroups'][$key] = $userGroup;
        }
    }

    public function getDefaultApplication(STRING $name):MemberObject{
        $application = null;
        if(isset($this->memorySpace['default_applications']['objects'][$name])){
            $id = $this->memorySpace['default_applications']['objects'][$name]['id'];
            $application = new MemberObject($id, 'default_applications', $name, '');
        }

        return $application;
    }

    public function insertNewAddresses(MySQLi $projectdb){
        $address = array();
        $address2 = array();
        foreach($this->memorySpace as $source=>$sourceContent){
            foreach ($sourceContent as $vsys=>$vsysContent){
                if(isset($vsysContent['new-address'])){
                    if(isset($vsysContent['new-address']['objects'])) {
                        foreach ($vsysContent['new-address']['objects'] as $newAddress) {
                            // (id, name, name_ext, vsys, type, ipaddress, cidr, description, v4, v6, source, tag, vtype)
                            $name = $newAddress['name'];
                            $id = $newAddress['id'];
                            $ipaddress = $newAddress['ipaddress'];
                            $cidr = $newAddress['cidr'];
                            $v4 = $newAddress['v4'];
                            $v6 = $newAddress['v6'];
                            $type = $newAddress['type'];
                            $deviceGroup = $newAddress['devicegroup'];
                            $description = $newAddress['description'];
                            $address[] = "($id,'$name','$name','$vsys','$type','$ipaddress','$cidr','$description',$v4,$v6,'$source','','object','$deviceGroup')";
                        }
                    }
                    if(isset($vsysContent['new-address']['objectsips'])) {
                        foreach ($vsysContent['new-address']['objectsips'] as $newAddress) {
                            // (id, name, name_ext, vsys, type, ipaddress, cidr, description, v4, v6, source, tag)
                            $name = $newAddress['name'];
                            $id = $newAddress['id'];
                            $ipaddress = $newAddress['ipaddress'];
                            $cidr = $newAddress['cidr'];
                            $v4 = $newAddress['v4'];
                            $v6 = $newAddress['v6'];
                            $type = $newAddress['type'];
                            $deviceGroup = $newAddress['devicegroup'];
                            $description = $newAddress['description'];
                            $address[] = "($id,'$name','$name','$vsys','$type','$ipaddress','$cidr','$description',$v4,$v6,'$source','','object','$deviceGroup')";
                        }
                    }
                }
            }
        }
        if(count($address)>0){
            $address = array_unique($address);
            $query = "INSERT INTO address (id, name, name_ext, vsys, type, ipaddress, cidr, description, v4, v6, source, tag, vtype, devicegroup) VALUES ".implode(",",$address).";";
            $projectdb->query($query);
        }

        foreach ($this->memorySpace as $source=>$sourceContent){
            foreach ($sourceContent as $vsys=>$vsysContent){
                unset($this->memorySpace[$source][$vsys]['new-address']);
            }
        }

//        print_r($this->memorySpace);
    }

    public function insertNewServices(MySQLi $projectdb){
        $srv = array();
        foreach($this->memorySpace as $source=>$sourceContent){
            foreach ($sourceContent as $vsys=>$vsysContent){
                if(isset($vsysContent['new-services'])){
                    foreach ($vsysContent['new-services']['objectsPorts'] as $newService){
                            //(id, name, name_ext, vsys, type, description, sport, dport, protocol, source, devicegroup)
                            $id = $newService['id'];
                            $name = $newService['name'];
                            $protocol = $newService['protocol'];
                            $dport = $newService['dport'];
                            $sport = $newService['sport'];
                            $devicegroup = $newService['devicegroup'];
                            $timeout = '';
                            $override = 'no';
                            if (isset($newService['timeout']) && !empty(trim($newService['timeout']))) {
                                $timeout = $newService['timeout'];
                                $override = 'yes';
                            }
                            $srv[] = "($id,'$name','$name','$vsys','','','$sport','$dport','$protocol','$source','$devicegroup', '$timeout','$override')";
                    }
                }
            }
        }
        if(count($srv)>0){
            $query = "INSERT INTO services (id, name, name_ext, vsys, type, description, sport, dport, protocol, source, devicegroup, timeout, override) VALUES ".implode(",",$srv).";";
            $projectdb->query($query);
        }

        foreach($this->memorySpace as $source=>$sourceContent){
            foreach ($sourceContent as $vsys=>$vsysContent) {
                unset($this->memorySpace[$source][$vsys]['new-services']);
            }
        }

    }

    public function updateServiceGroupReferences(MySQLi $projectdb, STRING $source, STRING $vsys){
        $newRelations = array();
        if(isset($this->memorySpace[$source][$vsys]['services_groups'])) {
            foreach ($this->memorySpace[$source][$vsys]['services_groups']['objects'] as $groupID => $members) {
                foreach ($members as $member) {
                    // (devicegroup, source, vsys, member_lid, table_name, lid)
                    $member_lid = $member['member_lid'];
                    $table_name = $member['table_name'];
                    $newRelations[] = "('','$source','$vsys','$member_lid','$table_name',$groupID)";
                }
            }
        }

        if (count($newRelations) > 0) {
            $query = "DELETE from services_groups WHERE source='$source' AND vsys='$vsys'";
            $projectdb->query($query);
            $query2 = "INSERT INTO services_groups (devicegroup, source, vsys, member_lid, table_name, lid) VALUES " . implode(",", $newRelations) . ";";
            $projectdb->query($query2);
        }
    }

    public function explodeAllGroups2Services(STRING $source, STRING $vsys){
        if(isset($this->memorySpace[$source][$vsys]['services_groups_id'])) {
            foreach ($this->memorySpace[$source][$vsys]['services_groups_id']['objects'] as $groupInfo) {
                $name = $groupInfo['id'];
                $location = 'services_groups_id';
                $groupObj = new MemberObject($name, $location);
                $this->explodeGroup2Services([$groupObj], $source, $vsys);
            }
        }
    }

    public function explodeGroup2Services(ARRAY $services, STRING $source, STRING $vsys, INT $level=0, BOOL $debug=false){
        $explodedServices = array();
        if(is_null($services)){
            $services = array();
        }

        /* @var $service MemberObject */
        foreach ($services as $service){
            if($service->location=='services_groups_id' && $service->name=='9999'){
                $debug=true;
            }
            if($debug==true){
                print_r($service);
            }
            //Not a group. Let's add it directly
            if(strcmp($service->name, 'any')==0 && strcmp($service->location, '')==0){
                //This is the ANY service
                return array($service); //No need to look for more, this service covers all

            }
            elseif(strcmp($service->location, 'services')==0){
                if(!isset($service->value) || !isset($service->cidr)){
                    //Complementing information about this service
                    if(!isset($this->memorySpace[$source][$vsys]['services']['ids'][$service->name]['name'])){
                        //We do not have this service in memory, so we skip its information
                        //TODO: Write a warning regarding this object
                        break;
                    }
                    $serviceName = $this->memorySpace[$source][$vsys]['services']['ids'][$service->name]['name'];
                    $serviceData = $this->memorySpace[$source][$vsys]['services']['objects'][$serviceName];
                    $service->value=$serviceData['dport'];
                    $service->cidr= $serviceData['protocol'];
                }

                $explodedServices[]=$service;
            }

            //This is a group. Let's expand it
            else{
                if(!isset($this->memorySpace[$source][$vsys]['services_groups_id']['ids'][$service->name]['name'])){
                    //We do not have this service in memory, so we skip its information
                    //TODO: Write a warning regarding this object
                    echo "Service Group $service->name $service->location not found in ExplodeGroup2Services\n";
                    break;
                }
                $groupName = $this->memorySpace[$source][$vsys]['services_groups_id']['ids'][$service->name]['name'];
                if(isset($this->memorySpace[$source][$vsys]['services_groups']['objects'][$service->name])) {
                    $members = $this->memorySpace[$source][$vsys]['services_groups']['objects'][$service->name];
                    $member2 = array();
                    /* @var $member MemberObject */
                    foreach ($members as $member) {
                        $service_id = $member['member_lid'];
                        $service_location = $member['table_name'];
                        $member2[] = new MemberObject($service_id, $service_location);
                    }
                    $subServices = $this->explodeGroup2Services($member2, $source, $vsys, $level + 1, $debug);
                }
                else{
                    $subServices = array();
                }
                $explodedServices = array_merge($explodedServices, $subServices);
            }
        }

        return $explodedServices;
    }

    public function updateAddressGroupReferences(MySQLi $projectdb, STRING $source, STRING $vsys){
        $newRelations = array();
        if(isset($this->memorySpace[$source][$vsys]['address_groups'])) {
            foreach ($this->memorySpace[$source][$vsys]['address_groups']['objects'] as $groupID => $members) {
                foreach ($members as $member) {
                    // (devicegroup, source, vsys, member_lid, table_name, lid)
                    $member_lid = $member['member_lid'];
                    $table_name = $member['table_name'];
                    $newRelations[] = "('','$source','$vsys','$member_lid','$table_name',$groupID)";
                }
            }
        }

        if (count($newRelations) > 0) {
            $query = "DELETE from address_groups WHERE source='$source' AND vsys='$vsys'";
            $projectdb->query($query);
            $query2 = "INSERT INTO address_groups (devicegroup, source, vsys, member_lid, table_name, lid) VALUES " . implode(",", $newRelations) . ";";
            $projectdb->query($query2);
        }
    }

    public function explodeAllGroups2Addresses(STRING $source, STRING $vsys){
        if(isset($this->memorySpace[$source][$vsys]['address_groups_id'])) {
            foreach ($this->memorySpace[$source][$vsys]['address_groups_id']['objects'] as $groupInfo) {
                $name = $groupInfo['id'];
                $location = 'address_groups_id';
                $groupObj = new MemberObject($name, $location);
                $this->explodeGroup2Addresses([$groupObj], $source, $vsys);
            }
        }
    }

    public function explodeGroup2Addresses(ARRAY $addresses, STRING $source, STRING $vsys, INT $level=0){
        $explodedAddresses = array();
        if(is_null($addresses)){
            $addresses = array();
        }

        /* @var $address MemberObject */
        foreach ($addresses as $address){
            //Not a group. Let's add it directly
            if(strcmp($address->name, 'any')==0 && strcmp($address->location, '')==0){
                //This is the ANY address
                return array($address); //No need to look for more, this address covers all

            }
            elseif(strcmp($address->location, 'address')==0){
                if(!isset($address->value) || !isset($address->cidr)){
                    //Complementing information about this address
                    if(!isset($this->memorySpace[$source][$vsys]['object-address']['ids'][$address->name]['name'])){
                        //We do not have this address in memory, so we skip its information
                        //TODO: Write a warning regarding this object
                        break;
                    }
                    $addressName = $this->memorySpace[$source][$vsys]['object-address']['ids'][$address->name]['name'];
                    $addressData = $this->memorySpace[$source][$vsys]['object-address']['objects'][$addressName];
                    $address->value=$addressData['ipaddress'];
                    $address->cidr= $addressData['cidr'];
                }

                $explodedAddresses[]=$address;
            }

            //This is a group. Let's expand it
            else{
                if(!isset($this->memorySpace[$source][$vsys]['address_groups_id']['ids'][$address->name]['name'])){
                    //We do not have this address in memory, so we skip its information
                    //TODO: Write a warning regarding this object
                    echo "Address ".$address->name." not found\n";
                    break;
                }
                $members = isset($this->memorySpace[$source][$vsys]['address_groups']['objects'][$address->name])?
                    $this->memorySpace[$source][$vsys]['address_groups']['objects'][$address->name]:
                    array();
                $member2 = array();
                foreach ($members as $member){
                    $service_id       = $member['member_lid'];
                    $service_location = $member['table_name'];
                    $member2[] = new MemberObject($service_id, $service_location);
                }
                $explodedAddresses = array_merge($explodedAddresses, $this->explodeGroup2Addresses($member2, $source, $vsys, $level+1));
            }
        }

        return $explodedAddresses;
    }
}