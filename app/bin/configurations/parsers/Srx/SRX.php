<?php

# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
#HEADER
//Loads all global PHP definitions
require_once '/var/www/html/libs/common/definitions.php';

require_once INC_ROOT.'/bin/configurations/parsers/ServicesMapping.php';
use PaloaltoNetworks\Parsers\Utils\ServicesMapping;

//User management control
//require_once INC_ROOT.'/userManager/start.php';
//include INC_ROOT.'/bin/authentication/sessionControl.php';

require_once INC_ROOT.'/libs/database.php';
require_once INC_ROOT.'/libs/shared.php';
require_once INC_ROOT.'/libs/xmlapi.php';
require_once INC_ROOT.'/libs/projectdb.php';
require_once INC_ROOT.'/libs/objects/SecurityRulePANObject.php';
require_once INC_ROOT.'/libs/common/lib-rules.php';

require_once INC_ROOT.'/libs/common/MemberObject.php';
use PaloAltoNetworks\Policy\Objects\MemberObject;

require_once INC_ROOT.'/userManager/API/accessControl_CLI.php';
global $app;
//Capture request paramenters
include INC_ROOT.'/bin/configurations/parsers/readVars.php';

// Validations
if(!accessControl("any", ['project.admin', 'projectRole.'.$project.'.admin'])){
    http_response_code(401);
    header("HTTP/1.1 401 Unauthorized");
    header("Location: /401");
    exit;
}

global $projectdb;
$projectdb = selectDatabase($project);

//---------------------------------------------
//        Parser Logic starts here
//----------------------------------------------


class SRXNatRule {
    //public $position, $name, $target, $disabled, $vsys, $lid, $checkit, $migrate, $tp_sat_bidirectional, $op_zone_to, $is_dat, 
    //        $op_service_lid, $op_service_table, $tp_sat_type, $tp_sat_interface, $tp_sat_ipaddress, $tp_dat_port, $tp_dat_address_lid, $tp_dat_address_table;
    public $rulelid, $is_dat;
    /**
     * @var MemberObject[]
     */
    public $source;

    /**
     * @var MemberObject[]
     */
    public $destination_orig;
    /**
     * @var MemberObject[]
     */
    public $destination_nat;

    /**
     * @var MemberObject[]
     */
    public $source_nat;
    /**
     * @var MemberObject[]
     */
    public $service;  //expected to be MemberObject(s)
            
    public function printMemberObject() {
        var_dump(get_object_vars($this));
    }

    function __construct(){
        $a = func_get_args();
        $i = func_num_args();
        if (method_exists($this,$f='__construct'.$i)) {
            call_user_func_array(array($this,$f),$a);
        }
    }

    public function __construct1($rulelid){
        $this->rulelid = $rulelid;
        $this->is_dat = 0; //by default we could set the NAT as a source NAT
        $this->service          = array();
        $this->source           = array();
        $this->destination_orig = array();
        $this->destination_nat  = array();
        $this->source_nat       = array();
    }
    
    public function __construct2($rulelid, $is_dat){
        $this->rulelid = $rulelid;
        $this->is_dat = $is_dat;
        $this->service          = array();
        $this->source           = array();
        $this->destination_orig = array();
        $this->destination_nat  = array();
        $this->source_nat       = array();
    }
    
    public function addSource(MemberObject $object){
            $this->source[] = $object;
    }

    public function addSourceNat(MemberObject $object){
        $this->source_nat[] = $object;
    }

    public function addDestinationOrig(MemberObject $object){
            $this->destination_orig[] = $object;
    }
    
    public function addDestinationNat(MemberObject $object){
            $this->destination_nat[] = $object;
    }
    
    public function addService(MemberObject $object){
            $this->service[] = $object;
    }

    public function getHash(String $field): String{
        if(isset($this->{$field})) {
            return md5(serialize($this->{$field}));
        }
        return '';
    }
}

if ($action == "import") {
    ini_set('max_execution_time', PARSER_max_execution_time);
    ini_set("memory_limit",PARSER_max_execution_memory);
    
    $path = USERSPACE_PATH."/projects/" . $project . "/";
    $i = 0;
    $dirrule = opendir($path);

    update_progress($project, '0.00', 'Reading config files',$jobid);

    $addedSources = array();
    while ($config_filename = readdir($dirrule)) {
        global $source;

       // if (($config_filename != ".") && ($config_filename != "..") && ($config_filename != "parsers.txt") && ($config_filename != "Backups") && ($config_filename != "Pcaps") && ($config_filename != "Reports") AND ( $config_filename != "CPviewer.html") AND ( !preg_match("/^MT-/", $config_filename)) AND (!preg_match("/^\._/",$config_filename))) {
        if (checkFiles2Import($config_filename)){
            $config_path = $path . $config_filename;
            $filename = $config_filename;
            $filenameParts = pathinfo($config_filename);
            $verificationName = $filenameParts['filename'];
            $isUploaded = $projectdb->query("SELECT id FROM device_mapping WHERE filename='$verificationName';");
//            $isUploaded = $projectdb->query("SELECT id FROM device_mapping WHERE filename='$config_filename';");
            $worked = false;
            if ($isUploaded->num_rows == 0) {
                $worked = import_config($config_path, $project, $config_filename,$jobid); //This may create a new source
                $addedSources[] = $source;

            } else {
                update_progress($project, '0.00', 'This filename '.$filename.' its already uploaded. Skipping...',$jobid);
            }
        }
    }
    if(isset($worked) && $worked) {

        // Auto split the address groups based on defined PARSER_max_number_address_per_group
        // for upgraded installations that does not have the variable in the /home/userSpace/userDefinition.php defined
        if (!defined('PARSER_max_number_address_per_group')) {
            define('PARSER_max_number_address_per_group', -1);
        }
        if(PARSER_max_number_address_per_group!=-1) {
            update_progress($project, '0.85', 'File:' . $filename . ' Split the address group members using as a limit defined value of '. PARSER_max_number_address_per_group . ' members', $jobid);
            splitMembersOnGroups();
        }

        #Check used
        update_progress($project, '0.90', 'File:' . $filename . ' Calculating Used Objects', $jobid);
        check_used_objects_new($addedSources);
        update_progress($project, '1.00', 'Done.', $jobid);
    }
    unlink($config_path);
}

function remove_utf8_bom($text)
{
    $bom = pack('H*','EFBBBF');
    $text = preg_replace("/^$bom/", '', $text);
    return $text;
}

function import_config($config_path, $project, $config_filename,$jobid):bool {
    global $projectdb;
    global $source;
    $filename = $config_filename;
    #Clean the config first
    $str = file_get_contents($config_path);
    $str = str_replace("junos:", "junos_", $str);
    $str = str_replace("/*", "", $str);
    $str = str_replace("*/", "", $str);
    file_put_contents($config_path, $str);

    $objectsInMemory=array();

    //Remove BOM
    $content = file_get_contents($config_path, "r");

//    for ( $pos=0; $pos < 10; $pos ++ ) {
//        $byte = $content[$pos];
//        echo 'Byte ' . $pos . ' of $str has value ' . ord($byte) . PHP_EOL;
//    }

    $modified = false;
    while (0 === strpos(bin2hex($content), 'efbbbf')){
        $content = remove_utf8_bom($content);
        $modified = true;
    }

    if($modified) {
        $fileHandle = fopen($config_path, "w");
        fwrite($fileHandle, $content);
        fclose($fileHandle);
    }


    if (isXML($config_path) === TRUE) {
        $multivsys = false;
        $devicegroup = $config_filename;
        $xml = simplexml_load_file($config_path);
        $version = $xml->version;
        $vsys = "vsys1";

        $logical_systems = $xml->xpath("/configuration/logical-systems");
        $vsys_count = 1;
        if(isset($logical_systems) && count($logical_systems)>0){
            $multivsys = true;
            $vsys_count = count($logical_systems);
        }

        $do_import = true;
        $iteration = 0;


        do {

            #Add Default VSYS1
            $projectdb->query("INSERT INTO device_mapping (device,version,ispanorama,active,project,filename,vsys,vendor) VALUES ('$devicegroup','$version',0,1,'$project','$config_filename','$vsys','Juniper')");
            if($vsys=="vsys1") {
                $source = $projectdb->insert_id;
                checkExistShared($source); //add shared vsys
                add_default_services($source);
                //add_default_profiles($source);
                update_progress($project, '0.10', 'File:' . $filename . ' Phase 1 Loading Objects', $jobid);
                add_junos_services($source,$objectsInMemory,$multivsys);

                #Config Template
                $template_name = "default_template" . $source;
                $projectdb->query("INSERT INTO templates_mapping (project,name,filename,source) VALUES ('$project','$template_name','$config_filename','$source');");
                $template = $projectdb->insert_id;
            }
            get_Interfaces($xml, $vsys, $source, $template);
            get_XML_Zones_Address_All_new($xml, $vsys, $source, $template, $objectsInMemory);
            update_progress($project, '0.20', 'File:' . $filename . ' Phase 2 Referencing Groups', $jobid);
            $vrid = get_VR_static_routes($xml, $vsys, $source, $template);
            get_XML_Applications($xml, $vsys, $source, $objectsInMemory);
            get_XML_ServicesGroups($xml, $vsys, $source, $objectsInMemory);
            update_progress($project, '0.30', 'File:' . $filename . ' Phase 3 Loading Security Policies', $jobid);

            get_Policy($xml, $vsys, $source, $project, $objectsInMemory);
            update_progress($project, '0.40', 'File:' . $filename . ' Phase 4 Importing Nat rules', $jobid);

            get_Nat($xml, $vsys, $source, $project, $objectsInMemory);
            //$vrid = 1;
            update_progress($project, '0.50', 'File:' . $filename . ' Phase 5 Calculating Zones', $jobid);
            set_Zones_Nat_srx($source, $vsys, $vrid);
            update_progress($project, '0.60', 'File:' . $filename . ' Phase 6 Consolidating dual Nats', $jobid);

            consolidate_dual_NATs($source, $vsys, $filename, $jobid, $project);
            update_progress($project, '0.70', 'File:' . $filename . ' Phase 7 Fixing Destination Zones based on Nat rules', $jobid);
            //fix_destination_nat('', $source, $vsys);
            recalculate_Dst_basedOn_NAT($projectdb, $source, $vsys, $vrid, $project, 'SRX');

            update_progress($project, '0.90', 'File:' . $filename . ' Phase 8 Consolidating Twice Nats', $jobid);
            consolidate_twice_NATs($source, $vsys, $filename, $jobid, $project);

            #Calculate Layer4-7
            $queryRuleIds = "SELECT id from security_rules WHERE source = $source;";
            $resultRuleIds = $projectdb->query($queryRuleIds);
            if ($resultRuleIds->num_rows > 0) {
                $rules = array();
                while ($dataRuleIds = $resultRuleIds->fetch_assoc()) {
                    $rules[] = $dataRuleIds['id'];
                }
                $rulesString = implode(",", $rules);
                $securityRulesMan = new \SecurityRulePANObject();
                $securityRulesMan->updateLayerLevel($projectdb, $rulesString, $source);
            }


            // Call function to generate initial consumptions
            deviceUsage("initial", "get", $project, "", "", $vsys, $source, $template_name);

            if($multivsys && $iteration < $vsys_count){
                $vsys =   truncate_names(normalizeNames((string) $logical_systems[$iteration]->name));
                $parent = new SimpleXMLElement('<configuration/>');
                foreach ($logical_systems[$iteration]->children() as $child) {
                    simplexml_import_simplexml($parent, $child);
                }
                $xml = $parent;
                $iteration++;
            } else {
                $do_import = false;
            }

        } while ($do_import);

        return true;
    }
    else {
        if (!isset($source)) {
            $source = 1;
        }
        add_log('error', 'Start Parsing Files', 'Failed the file uploaded is not a Valid XML', $source, 'Review the format.');
        update_progress($project, '-1.00', 'XML is invalid. (Tip:Remove attributes from configuration tag <configuration> and verify there are no invalid invisible chars before the XML)',$jobid);
        return false;
    }
}


/**
 * Insert XML into a SimpleXMLElement
 *
 * @param SimpleXMLElement $parent
 * @param string $xml
 * @param bool $before
 * @return bool XML string added
 */
function simplexml_import_xml(SimpleXMLElement $parent, $xml, $before = false)
{
    $xml = (string)$xml;

    // check if there is something to add
    if ($nodata = !strlen($xml) or $parent[0] == NULL) {
        return $nodata;
    }

    // add the XML
    $node     = dom_import_simplexml($parent);
    $fragment = $node->ownerDocument->createDocumentFragment();
    $fragment->appendXML($xml);

    if ($before) {
        return (bool)$node->parentNode->insertBefore($fragment, $node);
    }

    return (bool)$node->appendChild($fragment);
}

/**
 * Insert SimpleXMLElement into SimpleXMLElement
 *
 * @param SimpleXMLElement $parent
 * @param SimpleXMLElement $child
 * @param bool $before
 * @return bool SimpleXMLElement added
 */
function simplexml_import_simplexml(SimpleXMLElement $parent, SimpleXMLElement $child, $before = false)
{
    // check if there is something to add
    if ($child[0] == NULL) {
        return true;
    }

    // if it is a list of SimpleXMLElements default to the first one
    $child = $child[0];

    // insert attribute
    if ($child->xpath('.') != array($child)) {
        $parent[$child->getName()] = (string)$child;
        return true;
    }

    $xml = $child->asXML();

    // remove the XML declaration on document elements
    if ($child->xpath('/*') == array($child)) {
        $pos = strpos($xml, "\n");
        $xml = substr($xml, $pos + 1);
    }

    return simplexml_import_xml($parent, $xml, $before);
}

#Local Functions

function get_VR_static_routes($configuration, $vsys, $source, $template) {
    global $projectdb;

    if (isset($configuration->{'routing-instances'}->instance)) {
        $vr = $configuration->xpath("//configuration/routing-instances/instance");
        foreach ($vr as $key => $vrArray) {
            $vrName = $vrArray->name;
            $interfaceName = array();
            $interfaceNameQuery = array();
            $all_interfaces = "";
            if (isset($vrArray->interface)) {
                $interfaces = $vrArray->xpath("interface");
                foreach ($interfaces as $key => $value) {
                    preg_match('/(?<inter>(st0)|(lo0))\.(?<subint>.*)/', $value->name, $output_array);
                    if(isset($output_array['inter'])) {
                        switch($output_array['inter']){
                            case 'lo0':
                                $valueName = 'loopback.'.$output_array['subint'];
                                break;
                            case 'st0':
                                $valueName = 'tunnel.'.$output_array['subint'];
                                break;
                            default:
                                break;
                        }
                    }
                    else{
                        $valueName = $value->name;
                    }
                    $interfaceName[] = $valueName;
                    $interfaceNameQuery[] = "'" . $valueName . "'";
                }
            }
            $all_interfaces = implode(",", $interfaceName);
            $all_interfaces_query = implode(",", $interfaceNameQuery);
            $projectdb->query("INSERT INTO virtual_routers (source,name,interfaces,template,vsys) VALUES ('$source','$vrName','$all_interfaces','$template','$vsys')");
            $vr_id = $projectdb->insert_id;
            $projectdb->query("UPDATE interfaces SET vr_id='$vr_id' WHERE source='$source' AND vsys='$vsys' AND unitname IN (" . $all_interfaces_query . ");");
            unset($interfaceName);
            unset($interfaceNameQuery);

            if (isset($vrArray->{'routing-options'}->static)) {
                $routing = $vrArray->{'routing-options'}->static;
                $x = 0;
                $routes = array();
                $count = 0;
                foreach ($routing->route as $id => $arraydata) {
                    $destination = $arraydata->name;
                    if (isset($arraydata->{'next-hop'})) {
                        $nexthop_value = $arraydata->{'next-hop'};
                        preg_match('/(?<inter>(st0)|(lo0))\.(?<subint>.*)/', $nexthop_value, $output_array);
                        $ip_version = ip_version($nexthop_value);
                        if ($ip_version == "noip") {
                            $nexthop = "";
                            if(isset($output_array['inter'])) {
                                switch($output_array['inter']){
                                    case 'lo0':
                                        $interface = 'loopback.'.$output_array['subint'];
                                        break;
                                    case 'st0':
                                        $interface = 'tunnel.'.$output_array['subint'];
                                        break;
                                    default:
                                        break;
                                }
                            }
                            else{
                                $interface = $nexthop_value;
                            }
                            $nexthop_value = "";
                        } else {
                            $interface = "";
                            $nexthop = "ip-address";
                        }
                    } elseif (isset($arraydata->{'discard'})) {
                        $nexthop = "discard";
                        $nexthop_value = "";
                    }
                    $x++;
                    $name = "static " . $x;
                    if (($ip_version == "v4") AND ( $destination == "0.0.0.0/0")) {
                        if ($count == 0) {
                            $name = "default";
                            $count++;
                        } else {
                            $name = "default " . $count;
                            $count++;
                        }
                    }
                    $metric = 10;
                    $routes[] = "('$source','$vr_id','$template','$ip_version','$name','$destination','$interface','$nexthop','$nexthop_value','$metric','$vsys')";
                }
                if (count($routes) > 0) {
                    $out = implode(",", $routes);
                    $projectdb->query("INSERT INTO routes_static (source,vr_id,template,ip_version,name,destination,tointerface,nexthop,nexthop_value,metric,vsys) VALUES " . $out . ";");
                    unset($routes);
                }
            }
        }

        return $vr_id;
    }

    if (isset($configuration->{'routing-options'}->static)) {
        $all_interfaces_query = "";
        $interfaceNameQuery = array();
        $interfaceName = array();
        $all_interfaces = "";
        $getInterface = $projectdb->query("SELECT unitname FROM interfaces WHERE template='$template' AND source='$source' AND vr_id = '';");
        if ($getInterface->num_rows > 0) {
            while ($getInterfaceData = $getInterface->fetch_assoc()) {
                $interfaceName[] = $getInterfaceData['unitname'];
                $interfaceNameQuery[] = "'" . $getInterfaceData['unitname'] . "'";
            }
            $all_interfaces_query = implode(",", $interfaceNameQuery);
            $all_interfaces = implode(",", $interfaceName);
        }


        $projectdb->query("INSERT INTO virtual_routers (source,name,interfaces,template,vsys) VALUES ('$source','vr1','$all_interfaces','$template','$vsys')");
        $vr_id = $projectdb->insert_id;
        //echo "UPDATE interfaces SET vr_id='$vr_id' WHERE source='$source' AND vsys='$vsys' AND name IN (" . $all_interfaces_query . ");";
        $projectdb->query("UPDATE interfaces SET vr_id='$vr_id' WHERE source='$source' AND vsys='$vsys' AND unitname IN (" . $all_interfaces_query . ");");
        unset($interfaceName);
        unset($interfaceNameQuery);

        if (isset($configuration->{'routing-options'}->static)) {
            $routing = $configuration->{'routing-options'}->static;
            $x = 0;
            $routes = array();
            foreach ($routing->route as $id => $arraydata) {
                $destination = $arraydata->name;
                if (isset($arraydata->{'next-hop'})) {
                    $nexthop_value = $arraydata->{'next-hop'};
                    $ip_version = ip_version($nexthop_value);
                    if ($ip_version == "noip") {
                        $nexthop = "";
                        // rename interface if needed
                        if(str_contains($nexthop_value,"st0")) {
                            $interface = str_replace("st0", "tunnel", $nexthop_value);
                        } elseif (str_contains($nexthop_value,"lo0")) {
                            $interface = str_replace("lo0", "loopback", $nexthop_value);
                        }
                        $nexthop_value = "";
                    } else {
                        $interface = "";
                        $nexthop = "ip-address";
                    }
                } elseif (isset($arraydata->{'discard'})) {
                    $ip_version = ip_version("noip");
                    $nexthop = "discard";
                    $nexthop_value = "";
                    $interface = "";
                }
                $x++;
                $name = "static " . $x;
                if (($ip_version == "v4") AND ( $destination == "0.0.0.0/0")) {
                    $name = "default";
                }
                $metric = 10;
                $routes[] = "('$source','$vr_id','$template','$ip_version','$name','$destination','$interface','$nexthop','$nexthop_value','$metric','$vsys')";
            }
            if (count($routes) > 0) {
                $out = implode(",", $routes);
                $projectdb->query("INSERT INTO routes_static (source,vr_id,template,ip_version,name,destination,tointerface,nexthop,nexthop_value,metric,vsys) VALUES " . $out . ";");
                unset($routes);
            }
        }
        return $vr_id;
    }

    return 0;

}

function get_Interfaces($configuration, $vsys, $source, $template) {
    global $projectdb;

    $add_interface = array();
    $interfaces = $configuration->xpath("//configuration/interfaces/interface");
    $interfaces2 = $configuration->xpath("//configuration/groups/interfaces/interface");
    $interfaces = array_merge($interfaces, $interfaces2);
    foreach ($interfaces as $key => $interfaceArray) {
        $interfaceName = $interfaceArray->name;
        switch ($interfaceName){
            case 'st0':
                $interfaceName = 'tunnel';
                break;
            case 'lo0':
                $interfaceName = 'loopback';
                break;
            default:
                break;
        }
        if (isset($interfaceArray->description)) {
            $comment = $interfaceArray->description;
        } else {
            $comment = "";
        }
        if (isset($interfaceArray->unit)) {
            $unit = $interfaceArray->xpath("unit");
            foreach ($unit as $key => $value) {
                $unitName = $value->name;

                if (isset($value->description)){
                    $comment=addslashes($value->description);
                }
                //$unitTag = isset($value->{'vlan-id'})?$value->{'vlan-id'}:$unitName;
                $unitTag = isset($value->{'vlan-id'})?$value->{'vlan-id'}:'';

                switch($interfaceName){
                    case 'tunnel':
                        $media = 'tunnel';
                        break;
                    case 'loopback':
                        $media = 'loopback';
                        break;
                    default:
                        $media = 'ethernet';
                        break;
                }

                $unitName = $interfaceName . "." . $unitName;

                if (isset($value->family->inet->address) || isset($value->family->inet6->address) ) {
                    $ipaddress = array();
                    $interfaceType = "layer3";

                    if(isset($value->family->inet->address)) {
                        foreach ($value->family->inet->address as $kkey => $vvalue) {
                            $ipaddress[] = $vvalue->name;
                        }
                    }
                    // adding support for ipv6
                    if(isset($value->family->inet6->address)) {
                        foreach ($value->family->inet6->address as $kkey => $vvalue) {
                            $ipaddress[] = $vvalue->name;
                        }
                    }

                    //$media = ($interfaceName == 'tunnel')?'tunnel':"ethernet";
                    $all_ipaddress = implode(",", $ipaddress);

//                    if (preg_match("/^lo/", $unitName)) {
//                        $media = "loopback";
//                    }

                    $add_interface[] = "('$media','$source','$interfaceName','$interfaceType','$comment','$unitName','$unitTag','$all_ipaddress','$template','$vsys')";
                } else{
                    if($media == 'loopback' || $media == 'tunnel') {
                        $add_interface[] = "('$media','$source','$interfaceName','','$comment','$unitName','$unitTag','','$template','$vsys')";
                    }
                }
            }
        }
    }
    if (count($add_interface) > 0) {
        $out = implode(",", $add_interface);
        $projectdb->query("INSERT INTO interfaces (media,source,name,type,comment,unitname,unittag,unitipaddress,template,vsys) VALUES " . $out . ";");
    }
}

function get_Policy($configuration, $vsys, $source, $project,&$objectsInMemory) {
    global $projectdb;

    #Get Last lid from Profiles
    $getlastlid = $projectdb->query("SELECT max(id) as max FROM security_rules;");
    $getLID1 = $getlastlid->fetch_assoc();
    $lid = intval($getLID1['max']) + 1;
    $getlastlid = $projectdb->query("SELECT max(position) as max FROM security_rules;");
    $getLID1 = $getlastlid->fetch_assoc();
    $position = intval($getLID1['max']) + 1;
    $tofile = array();
    $tofilefrom=array();
    $tofileto=array();
    $addTag=array();
    #Read Global Shared Policies
    $address = $configuration->xpath("/configuration/security/policies/global");
    $address2 = $configuration->xpath("/configuration/group/security/policies/global");
    $address = array_merge($address, $address2);
    $getTag=$projectdb->query("SELECT id FROM tag WHERE name='global' AND source='$source' AND vsys='$vsys';");
    if ($getTag->num_rows==0){
        $projectdb->query("INSERT INTO tag (name,color,comments,source,vsys) VALUES ('global','color3','Global Rules','$source','$vsys');");
        $tagid=$projectdb->insert_id;
        $tagtable="tag";
    }
    else {
        $getTagData=$getTag->fetch_assoc();
        $tagid=$getTagData['id'];
        $tagtable="tag";
    }
    foreach ($address as $child => $data) {
        $log_end = "0";
        $log_start = "1";
        $zone_src = "global";
        $zone_dst = "global";

        foreach ($data->policy as $key => $data2) {
            $zone_dst_local = $zone_dst;
            $zone_src_local = $zone_src;
            if (isset($data2->attributes()->inactive)){$disabled=1;}
            else{$disabled=0;}
            $name_ext = (string) $data2->name;
            $name_int = truncate_names(normalizeNames($name_ext));
            $description = addslashes($data2->description);
            $action1 = (string) $data2->then;

            $action = "deny";
            foreach ($data2->then as $action2 => $kk) {
                foreach ($kk as $theaction => $kk2) {
                    if ($theaction == "permit") {
                        $action = "allow";
                    }
                    //else {$action="deny";}

                    if ($theaction == "log") {
                        foreach ($kk2 as $log => $value) {
                            if ($log == "session-init") {
                                $log_start = "1";
                            }
                            if ($log == "session-close") {
                                $log_end = "1";
                            }
                        }
                    }
                }
            }

            $tofile[] = "('$disabled','$log_end','$log_start','$position','$name_int','$description','$action','$vsys','$lid','$source')";
            $log_start = "0";

            foreach ($data2->match as $keyA => $valueA) {
                foreach ($valueA as $mytype => $newArray) {
                    $newArray=(string) $newArray;
                    if ($mytype == "from-zone"){
                        $zone_src_local = (string)$newArray;
                        $tofilefrom[] = "('$source','$vsys','$zone_src_local','$lid')";
                    }
                    if ($mytype == "to-zone"){
                        $zone_dst_local = (string)$newArray;
                        $tofileto[] = "('$source','$vsys','$zone_dst_local','$lid')";
                    }
                    if ($mytype == "application") {
                        if (($newArray == "any") OR ( $newArray == "any-ip") OR ( $newArray == "any-ipv4") OR ( $newArray == "any-ip6")) {
                            #Do nothing
                        }
                        elseif (isset($objectsInMemory[$vsys]['services'][$newArray])){
                            $member_lid = $objectsInMemory[$vsys]['services'][$newArray];
                            $tofilesrv[] = "('$source','$vsys','services','$member_lid','$lid')";
                        }elseif (isset($objectsInMemory['shared']['services'][$newArray])){ // looking into shared services
                            add_log('warning', 'Reading Security Policy', 'Service not found in DB [vsys:'. $vsys . ',service:' . $newArray . '] at Rule[' . $lid . ']', $source, 'Using predefined service in shared');
                            $member_lid = $objectsInMemory['shared']['services'][$newArray];
                            $tofilesrv[] = "('$source','$vsys','services','$member_lid','$lid')";
                        }elseif (isset($objectsInMemory[$vsys]['services_groups_id'][$newArray])){
                            $member_lid = $objectsInMemory[$vsys]['services_groups_id'][$newArray];
                            $tofilesrv[] = "('$source','$vsys','services_groups_id','$member_lid','$lid')";
                        }elseif (isset($objectsInMemory['shared']['services_groups_id'][$newArray])){ // looking into shared service_groups
                            add_log('warning', 'Reading Security Policy', 'Service not found in DB [vsys:'. $vsys . ',service_group:' . $newArray . '] at Rule[' . $lid . ']', $source, 'Using predefined service_group in shared');
                            $member_lid = $objectsInMemory['shared']['services_groups_id'][$newArray];
                            $tofilesrv[] = "('$source','$vsys','services_groups_id','$member_lid','$lid')";
                        }else {
                            add_log('error', 'Reading Security Policy', 'Service not found in DB [' . $newArray . '] at Rule[' . $lid . ']', $source, 'Generating the Object, add the Protocol/Port');
                            $newservice=  truncate_names(normalizeNames($newArray));
                            $projectdb->query("INSERT INTO services (name_ext,name,checkit,source,used,vsys) values ('$newArray','$newservice','1','$source','1','$vsys');");
                            $flid = $projectdb->insert_id;
                            $tofilesrv[] = "('$source','$vsys','services','$flid','$lid')";
                        }
                    }
                    if ($mytype == "destination-address") {
                        $newArray = str_replace('/', '-', $newArray);

                        if (($newArray == "any") OR ( $newArray == "any-ip") OR ( $newArray == "any-ipv4") OR ( $newArray == "any-ip6") ) {
                            #Do nothing
                        }
                        elseif(isset($objectsInMemory[$zone_dst_local]['address'][$newArray])){
                            $member_lid = $objectsInMemory[$zone_dst_local]['address'][$newArray];
                            $tofiledst[] = "('$source','$vsys','address','$member_lid','$lid')";
                        }
                        elseif(isset($objectsInMemory[$zone_dst_local]['address_groups_id'][$newArray])){
                            $member_lid = $objectsInMemory[$zone_dst_local]['address_groups_id'][$newArray];
                            $tofiledst[] = "('$source','$vsys','address_groups_id','$member_lid','$lid')";
                        }

                        else {
//                            if($newArray == "student-block-list") {
//                                echo "Not found $newArray in $zone_dst_local\n";
//                                print_r($objectsInMemory[$zone_dst_local]);
//                                die();
//                            }
                            add_log('error', 'Reading Security Policy', 'Destination Address not found in DB [' . $newArray . '] at Rule[' . $lid . ']', $source, 'Generating the Object, add the IP/CIDR');
                            $projectdb->query("INSERT INTO address (name_ext,name,checkit,source,used,vsys, devicegroup) values('$newArray','$newArray','1','$source','1','$vsys','Expedition');");
                            $flid = $projectdb->insert_id;
                            $tofiledst[] = "('$source','$vsys','address','$flid','$lid')";
                            $objectsInMemory[$zone_dst_local]['address'][$newArray]=$flid;
                        }

//                        $getDST = $projectdb->query("SELECT id FROM address WHERE source='$source' AND BINARY name='$newArray' AND vsys='$vsys' AND zone='$zone_dst' LIMIT 1;");
//                        if ($getDST->num_rows == 1) {
//                            $myData = $getDST->fetch_assoc();
//                            $member_lid = $myData['id'];
//                            $tofiledst[] = "('$source','$vsys','address','$member_lid','$lid')";
//                        }
//                        else {
//                            $getGRP = $projectdb->query("SELECT id FROM address_groups_id WHERE source='$source' AND BINARY name='$newArray' AND vsys='$vsys' AND zone='$zone_dst' LIMIT 1;");
//                            if ($getGRP->num_rows == 1) {
//                                $myData = $getGRP->fetch_assoc();
//                                $member_lid = $myData['id'];
//                                $tofiledst[] = "('$source','$vsys','address_groups_id','$member_lid','$lid')";
//                            } else {
//                                #Doesnt exist
//                                if (($newArray == "any") OR ( $newArray == "any-ip") OR ( $newArray == "any-ipv4") OR ( $newArray == "any-ip6") ) {
//                                    #Do nothing
//                                } else {
//                                    $getDST = $projectdb->query("SELECT id FROM address WHERE source='$source' AND BINARY name='$newArray' AND vsys='$vsys' LIMIT 1;");
//                                    if ($getDST->num_rows == 1) {
//                                        $myData = $getDST->fetch_assoc();
//                                        $member_lid = $myData['id'];
//                                        $tofiledst[] = "('$source','$vsys','address','$member_lid','$lid')";
//                                        #add_log2("error", 'Reading Security Policy', 'Destination Address [' . $newArray . '] found in wrong AddressBook  at Rule[' . $lid . ']', $source, 'Using Object from a different Book but with same Name','rules',$lid,'security_rules');
//                                    } else {
//                                        $getGRP = $projectdb->query("SELECT id FROM address_groups_id WHERE source='$source' AND BINARY name='$newArray' AND vsys='$vsys' LIMIT 1;");
//                                        if ($getGRP->num_rows == 1) {
//                                            $myData = $getGRP->fetch_assoc();
//                                            $member_lid = $myData['id'];
//                                            $tofiledst[] = "('$source','$vsys','address_groups_id','$member_lid','$lid')";
//                                        } else {
//                                            add_log('error', 'Reading Security Policy', 'Destination Address not found in DB [' . $newArray . '] at Rule[' . $lid . ']', $source, 'Generating the Object, add the IP/CIDR');
//                                            $projectdb->query("INSERT INTO address (name_ext,name,checkit,source,used,vsys) values('$newArray','$newArray','1','$source','1','$vsys');");
//                                            $flid = $projectdb->insert_id;
//                                            $tofiledst[] = "('$source','$vsys','address','$flid','$lid')";
//                                        }
//                                    }
//                                }
//                            }
//                        }
                    }
                    if ($mytype == "source-address") {
                        $newArray = str_replace('/', '-', $newArray);
                        if (($newArray == "any") OR ( $newArray == "any-ip") OR ( $newArray == "any-ipv4") OR ( $newArray == "any-ip6")) {
                            #Do nothing
                        }

                        elseif(isset($objectsInMemory[$zone_src_local]['address'][$newArray])){
                            $member_lid = $objectsInMemory[$zone_src_local]['address'][$newArray];
                            $tofilesrc[] = "('$source','$vsys','address','$member_lid','$lid')";
                        }
                        elseif(isset($objectsInMemory[$zone_src_local]['address_groups_id'][$newArray])){
                            $member_lid = $objectsInMemory[$zone_src_local]['address_groups_id'][$newArray];
                            $tofilesrc[] = "('$source','$vsys','address_groups_id','$member_lid','$lid')";
                        }
                        else {
                            add_log('error', 'Reading Security Policy', 'Source Address not found in DB [' . $newArray . '] at Rule[' . $lid . ']', $source, 'Generating the Object, add the IP/CIDR');
                            $projectdb->query("INSERT INTO address (name_ext,name,checkit,source,used,vsys) values('$newArray','$newArray','1','$source','1','$vsys');");
                            $flid = $projectdb->insert_id;
                            $tofilesrc[] = "('$source','$vsys','address','$flid','$lid')";
                            $objectsInMemory[$zone_src_local]['address'][$newArray]=$flid;
                        }
//                        $getDST = $projectdb->query("SELECT id FROM address WHERE source='$source' AND BINARY name='$newArray' AND vsys='$vsys' AND zone='$zone_src' LIMIT 1;");
//                        if ($getDST->num_rows == 1) {
//                            $myData = $getDST->fetch_assoc();
//                            $member_lid = $myData['id'];
//                            $tofilesrc[] = "('$source','$vsys','address','$member_lid','$lid')";
//                        }
//                        else {
//                            $getGRP = $projectdb->query("SELECT id FROM address_groups_id WHERE source='$source' AND BINARY name='$newArray' AND vsys='$vsys' AND zone='$zone_src' LIMIT 1;");
//                            if ($getGRP->num_rows == 1) {
//                                $myData = $getGRP->fetch_assoc();
//                                $member_lid = $myData['id'];
//                                $tofilesrc[] = "('$source','$vsys','address_groups_id','$member_lid','$lid')";
//                            } else {
//                                #Doesnt exist
//                                if (($newArray == "any") OR ( $newArray == "any-ip") OR ( $newArray == "any-ipv4") OR ( $newArray == "any-ip6")) {
//                                    #Do nothing
//                                } else {
//                                    #check if the Object is in the wrong address-book
//                                    $getDST = $projectdb->query("SELECT id FROM address WHERE source='$source' AND BINARY name='$newArray' AND vsys='$vsys' LIMIT 1;");
//                                    if ($getDST->num_rows == 1) {
//                                        $myData = $getDST->fetch_assoc();
//                                        $member_lid = $myData['id'];
//                                        $tofilesrc[] = "('$source','$vsys','address','$member_lid','$lid')";
//                                        #add_log2("error", 'Reading Security Policy', 'Source Address [' . $newArray . '] found in wrong AddressBook  at Rule[' . $lid . ']', $source, 'Using Object from a different Book but with same Name','rules',$lid,'security_rules');
//                                    } else {
//                                        $getGRP = $projectdb->query("SELECT id FROM address_groups_id WHERE source='$source' AND BINARY name='$newArray' AND vsys='$vsys' LIMIT 1;");
//                                        if ($getGRP->num_rows == 1) {
//                                            $myData = $getGRP->fetch_assoc();
//                                            $member_lid = $myData['id'];
//                                            $tofilesrc[] = "('$source','$vsys','address_groups_id','$member_lid','$lid')";
//                                        } else {
//                                            add_log('error', 'Reading Security Policy', 'Source Address not found in DB [' . $newArray . '] at Rule[' . $lid . ']', $source, 'Generating the Object, add the IP/CIDR');
//                                            $projectdb->query("INSERT INTO address (name_ext,name,checkit,source,used,vsys) values('$newArray','$newArray','1','$source','1','$vsys');");
//                                            $flid = $projectdb->insert_id;
//                                            $tofilesrc[] = "('$source','$vsys','address','$flid','$lid')";
//                                        }
//                                    }
//                                }
//                            }
//                        }
                    }

                }
            }

            # Add Globa Tag
            $addTag[]="('$source','$vsys','$lid','$tagid','$tagtable')";

            $lid++;
            $position++;
        }
    }

    $address = $configuration->xpath("/configuration/security/policies/policy");
    $address2 = $configuration->xpath("/configuration/groups/security/policies/policy");
    $address = array_merge($address, $address2);
    foreach ($address as $child => $data) {
        $log_end = "0";
        $log_start = "1";
        if(isset($data->{'from-zone-name'})) {
            $zone_src = (string)$data->{'from-zone-name'};
        }
        elseif($data->{'from-zone'}){
            $zone_src = (string)$data->{'from-zone'};
        }
        if(isset($data->{'to-zone-name'})) {
            $zone_dst = (string)$data->{'to-zone-name'};
        }elseif(isset($data->{'to-zone'})){
            $zone_dst = (string)$data->{'to-zone'};
        }

        foreach ($data->policy as $key => $data2) {

            $name_ext = (string) $data2->name;
            if (isset($data2->attributes()->inactive)){$disabled=1;}
            else{$disabled=0;}
            $name_int = truncate_names(normalizeNames($name_ext));
            $description = addslashes($data2->description);
            $action1 = (string) $data2->then;

            $action = "deny";
            foreach ($data2->then as $action2 => $kk) {
                foreach ($kk as $theaction => $kk2) {
                    if ($theaction == "permit") {
                        $action = "allow";
                    }
                    //else {$action="deny";}

                    if ($theaction == "log") {
                        foreach ($kk2 as $log => $value) {
                            if ($log == "session-init") {
                                $log_start = "1";
                            }
                            if ($log == "session-close") {
                                $log_end = "1";
                            }
                        }
                    }
                }
            }

            $tofile[] = "('$disabled','$log_end','$log_start','$position','$name_int','$description','$action','$vsys','$lid','$source')";
            $tofilefrom[] = "('$source','$vsys','$zone_src','$lid')";
            $tofileto[] = "('$source','$vsys','$zone_dst','$lid')";
            $log_start = "0";

            foreach ($data2->match as $keyA => $valueA) {
                foreach ($valueA as $mytype => $newArray) {
                    $newArray=(string)$newArray;
                    if ($mytype == "application") {
                        if (($newArray == "any") OR ( $newArray == "any-ip") OR ( $newArray == "any-ipv4") OR ( $newArray == "any-ip6")) {
                            #Do nothing
                        }
                        elseif (isset($objectsInMemory[$vsys]['services'][$newArray])){
                            $member_lid = $objectsInMemory[$vsys]['services'][$newArray];
                            $tofilesrv[] = "('$source','$vsys','services','$member_lid','$lid')";
                        }elseif (isset($objectsInMemory['shared']['services'][$newArray])) { // looking into shared services
                            add_log('warning', 'Reading Security Policy', 'Service not found in DB [vsys:'. $vsys . ',service:' . $newArray . '] at Rule[' . $lid . ']', $source, 'Using predefined service in shared');
                            $member_lid = $objectsInMemory['shared']['services'][$newArray];
                            $tofilesrv[] = "('$source','$vsys','services','$member_lid','$lid')";
                        }elseif (isset($objectsInMemory[$vsys]['services_groups_id'][$newArray])){
                            $member_lid = $objectsInMemory[$vsys]['services_groups_id'][$newArray];
                            $tofilesrv[] = "('$source','$vsys','services_groups_id','$member_lid','$lid')";
                        }elseif (isset($objectsInMemory['shared']['services_groups_id'][$newArray])){ // looking into shared service_groups
                            add_log('warning', 'Reading Security Policy', 'Service not found in DB [vsys:'. $vsys . ',service_group:' . $newArray . '] at Rule[' . $lid . ']', $source, 'Using predefined service_group in shared');
                            $member_lid = $objectsInMemory['shared']['services_groups_id'][$newArray];
                            $tofilesrv[] = "('$source','$vsys','services_groups_id','$member_lid','$lid')";
                        }
                        else {
                            add_log('error', 'Reading Security Policy', 'Service not found in DB [' . $newArray . '] at Rule[' . $lid . ']', $source, 'Generating the Object, add the Protocol/Port');
                            $newservice=  truncate_names(normalizeNames($newArray));
                            $projectdb->query("INSERT INTO services (name_ext,name,checkit,source,used,vsys) values ('$newArray','$newservice','1','$source','1','$vsys');");
                            $flid = $projectdb->insert_id;
                            $tofilesrv[] = "('$source','$vsys','services','$flid','$lid')";
                            $objectsInMemory[$vsys]['services'][$newArray]=$flid;
                        }
//
//
//                        $getSRV = $projectdb->query("SELECT id FROM services WHERE source='$source' AND name='$newArray' AND vsys='$vsys' LIMIT 1;");
//                        if ($getSRV->num_rows == 1) {
//                            $myData = $getSRV->fetch_assoc();
//                            $member_lid = $myData['id'];
//                            $tofilesrv[] = "('$source','$vsys','services','$member_lid','$lid')";
//                        } else {
//                            $getGRP = $projectdb->query("SELECT id FROM services_groups_id WHERE source='$source' AND name='$newArray' AND vsys='$vsys' LIMIT 1;");
//                            if ($getGRP->num_rows == 1) {
//                                $myData = $getGRP->fetch_assoc();
//                                $member_lid = $myData['id'];
//                                $tofilesrv[] = "('$source','$vsys','services_groups_id','$member_lid','$lid')";
//                            } else {
//                                #Doesnt exist
//                                if (($newArray == "any") OR ( $newArray == "any-ip") OR ( $newArray == "any-ip6")) {
//                                    #Do nothing
//                                } else {
//                                    add_log('error', 'Reading Security Policy', 'Service not found in DB [' . $newArray . '] at Rule[' . $lid . ']', $source, 'Generating the Object, add the Protocol/Port');
//                                    $newservice=  truncate_names(normalizeNames($newArray));
//                                    $projectdb->query("INSERT INTO services (name_ext,name,checkit,source,used,vsys) values ('$newArray','$newservice','1','$source','1','$vsys');");
//                                    $flid = $projectdb->insert_id;
//                                    $tofilesrv[] = "('$source','$vsys','services','$flid','$lid')";
//                                }
//                            }
//                        }
                    }
                    if ($mytype == "destination-address") {
                        $newArray = str_replace('/', '-', $newArray);
                        if (($newArray == "any") OR ( $newArray == "any-ip") OR ( $newArray == "any-ipv4") OR ( $newArray == "any-ip6") ) {
                            #Do nothing
                        }
                        elseif(isset($objectsInMemory[$zone_dst]['address'][$newArray])){
                            $member_lid = $objectsInMemory[$zone_dst]['address'][$newArray];
                            $tofiledst[] = "('$source','$vsys','address','$member_lid','$lid')";
                        }
                        elseif(isset($objectsInMemory[$zone_dst]['address_groups_id'][$newArray])){
                            $member_lid = $objectsInMemory[$zone_dst]['address_groups_id'][$newArray];
                            $tofiledst[] = "('$source','$vsys','address_groups_id','$member_lid','$lid')";
                        }
                        elseif(isset($objectsInMemory['global']['address'][$newArray])){
                            $member_lid = $objectsInMemory['global']['address'][$newArray];
                            $tofiledst[] = "('$source','$vsys','address','$member_lid','$lid')";
                        }
                        elseif(isset($objectsInMemory['global']['address_groups_id'][$newArray])){
                            $member_lid = $objectsInMemory['global']['address_groups_id'][$newArray];
                            $tofiledst[] = "('$source','$vsys','address_groups_id','$member_lid','$lid')";
                        }
                        else {
                            add_log('error', 'Reading Security Policy', 'Destination Address not found in DB [' . $newArray . '] at Rule[' . $lid . ']', $source, 'Generating the Object, add the IP/CIDR');
                            $projectdb->query("INSERT INTO address (name_ext,name,checkit,source,used,vsys) values('$newArray','$newArray','1','$source','1','$vsys');");
                            $flid = $projectdb->insert_id;
                            $tofiledst[] = "('$source','$vsys','address','$flid','$lid')";
                            $objectsInMemory['global']['address'][$newArray]=$flid;
                        }


//                        $getDST = $projectdb->query("SELECT id FROM address WHERE source='$source' AND BINARY name='$newArray' AND vsys='$vsys' AND zone='$zone_dst' LIMIT 1;");
//                        if ($getDST->num_rows == 1) {
//                            $myData = $getDST->fetch_assoc();
//                            $member_lid = $myData['id'];
//                            $tofiledst[] = "('$source','$vsys','address','$member_lid','$lid')";
//                        }
//                        else {
//                            $getGRP = $projectdb->query("SELECT id FROM address_groups_id WHERE source='$source' AND BINARY name='$newArray' AND vsys='$vsys' AND zone='$zone_dst' LIMIT 1;");
//                            if ($getGRP->num_rows == 1) {
//                                $myData = $getGRP->fetch_assoc();
//                                $member_lid = $myData['id'];
//                                $tofiledst[] = "('$source','$vsys','address_groups_id','$member_lid','$lid')";
//                            } else {
//                                #Doesnt exist
//                                if (($newArray == "any") OR ( $newArray == "any-ip") OR ( $newArray == "any-ip6")) {
//                                    #Do nothing
//                                } else {
//                                    $getDST = $projectdb->query("SELECT id FROM address WHERE source='$source' AND BINARY name='$newArray' AND vsys='$vsys' LIMIT 1;");
//                                    if ($getDST->num_rows == 1) {
//                                        $myData = $getDST->fetch_assoc();
//                                        $member_lid = $myData['id'];
//                                        $tofiledst[] = "('$source','$vsys','address','$member_lid','$lid')";
//                                        #add_log2("error", 'Reading Security Policy', 'Destination Address [' . $newArray . '] found in wrong AddressBook  at Rule[' . $lid . ']', $source, 'Using Object from a different Book but with same Name','rules',$lid,'security_rules');
//                                    } else {
//                                        $getGRP = $projectdb->query("SELECT id FROM address_groups_id WHERE source='$source' AND BINARY name='$newArray' AND vsys='$vsys' LIMIT 1;");
//                                        if ($getGRP->num_rows == 1) {
//                                            $myData = $getGRP->fetch_assoc();
//                                            $member_lid = $myData['id'];
//                                            $tofiledst[] = "('$source','$vsys','address_groups_id','$member_lid','$lid')";
//                                        } else {
//                                            add_log('error', 'Reading Security Policy', 'Destination Address not found in DB [' . $newArray . '] at Rule[' . $lid . ']', $source, 'Generating the Object, add the IP/CIDR');
//                                            $projectdb->query("INSERT INTO address (name_ext,name,checkit,source,used,vsys) values('$newArray','$newArray','1','$source','1','$vsys');");
//                                            $flid = $projectdb->insert_id;
//                                            $tofiledst[] = "('$source','$vsys','address','$flid','$lid')";
//                                        }
//                                    }
//                                }
//                            }
//                        }
                    }
                    if ($mytype == "source-address") {
                        $newArray = str_replace('/', '-', $newArray);
                        if (($newArray == "any") OR ( $newArray == "any-ip") OR ( $newArray == "any-ipv4") OR ( $newArray == "any-ip6")) {
                            #Do nothing
                        }
                        elseif(isset($objectsInMemory[$zone_src]['address'][$newArray])){
                            $member_lid = $objectsInMemory[$zone_src]['address'][$newArray];
                            $tofilesrc[] = "('$source','$vsys','address','$member_lid','$lid')";
                        }
                        elseif(isset($objectsInMemory[$zone_src]['address_groups_id'][$newArray])){
                            $member_lid = $objectsInMemory[$zone_src]['address_groups_id'][$newArray];
                            $tofilesrc[] = "('$source','$vsys','address_groups_id','$member_lid','$lid')";
                        }
                        elseif(isset($objectsInMemory['global']['address'][$newArray])){
                            $member_lid = $objectsInMemory['global']['address'][$newArray];
                            $tofilesrc[] = "('$source','$vsys','address','$member_lid','$lid')";
                        }
                        elseif(isset($objectsInMemory['global']['address_groups_id'][$newArray])){
                            $member_lid = $objectsInMemory['global']['address_groups_id'][$newArray];
                            $tofilesrc[] = "('$source','$vsys','address_groups_id','$member_lid','$lid')";
                        }
                        else {
                            add_log('error', 'Reading Security Policy', 'Source Address not found in DB [' . $newArray . '] at Rule[' . $lid . ']', $source, 'Generating the Object, add the IP/CIDR');
                            $projectdb->query("INSERT INTO address (name_ext,name,checkit,source,used,vsys) values('$newArray','$newArray','1','$source','1','$vsys');");
                            $flid = $projectdb->insert_id;
                            $tofilesrc[] = "('$source','$vsys','address','$flid','$lid')";
                            $objectsInMemory['global']['address'][$newArray]=$flid;
                        }
//                        $getDST = $projectdb->query("SELECT id FROM address WHERE source='$source' AND BINARY name_ext='$newArray' AND vsys='$vsys' AND zone='$zone_src' LIMIT 1;");
//                        if ($getDST->num_rows == 1) {
//                            $myData = $getDST->fetch_assoc();
//                            $member_lid = $myData['id'];
//                            $tofilesrc[] = "('$source','$vsys','address','$member_lid','$lid')";
//                        }
//                        else {
//                            $getGRP = $projectdb->query("SELECT id FROM address_groups_id WHERE source='$source' AND BINARY name_ext='$newArray' AND vsys='$vsys' AND zone='$zone_src' LIMIT 1;");
//                            if ($getGRP->num_rows == 1) {
//                                $myData = $getGRP->fetch_assoc();
//                                $member_lid = $myData['id'];
//                                $tofilesrc[] = "('$source','$vsys','address_groups_id','$member_lid','$lid')";
//                            } else {
//                                #Doesnt exist
//                                if (($newArray == "any") OR ( $newArray == "any-ip") OR ( $newArray == "any-ip6")) {
//                                    #Do nothing
//                                } else {
//                                    #check if the Object is in the wrong address-book
//                                    $getDST = $projectdb->query("SELECT id FROM address WHERE source='$source' AND BINARY name_ext='$newArray' AND vsys='$vsys' LIMIT 1;");
//                                    if ($getDST->num_rows == 1) {
//                                        $myData = $getDST->fetch_assoc();
//                                        $member_lid = $myData['id'];
//                                        $tofilesrc[] = "('$source','$vsys','address','$member_lid','$lid')";
//                                        #add_log2("error", 'Reading Security Policy', 'Source Address [' . $newArray . '] found in wrong AddressBook  at Rule[' . $lid . ']', $source, 'Using Object from a different Book but with same Name','rules',$lid,'security_rules');
//                                    } else {
//                                        $getGRP = $projectdb->query("SELECT id FROM address_groups_id WHERE source='$source' AND BINARY name_ext='$newArray' AND vsys='$vsys' LIMIT 1;");
//                                        if ($getGRP->num_rows == 1) {
//                                            $myData = $getGRP->fetch_assoc();
//                                            $member_lid = $myData['id'];
//                                            $tofilesrc[] = "('$source','$vsys','address_groups_id','$member_lid','$lid')";
//                                        } else {
//                                            add_log('error', 'Reading Security Policy', 'Source Address not found in DB [' . $newArray . '] at Rule[' . $lid . ']', $source, 'Generating the Object, add the IP/CIDR');
//                                            $projectdb->query("INSERT INTO address (name_ext,name,checkit,source,used,vsys) values('$newArray','$newArray','1','$source','1','$vsys');");
//                                            $flid = $projectdb->insert_id;
//                                            $tofilesrc[] = "('$source','$vsys','address','$flid','$lid')";
//                                        }
//                                    }
//                                }
//                            }
//                        }
                    }
                }
            }

            $lid++;
            $position++;
        }
    }
    if (isset($tofile) && count($tofile) > 0) {
        $unique=array_unique($tofile);
        $out = implode(",", $unique);
        $projectdb->query("INSERT INTO security_rules (disabled,log_end,log_start,position,name,description,action,vsys,id,source) VALUES " . $out . ";");
        unset($out);unset($unique);unset($tofile);
    }
    if (isset($tofilefrom) && count($tofilefrom) > 0) {
        $unique=array_unique($tofilefrom);
        $out = implode(",", $unique);
        $projectdb->query("INSERT INTO security_rules_from (source,vsys,name,rule_lid) VALUES " . $out . ";");
        unset($tofilefrom);unset($out);unset($unique);
    }
    if (isset($tofileto) && count($tofileto) > 0) {
        $unique=array_unique($tofileto);
        $out = implode(",", $unique);
        $projectdb->query("INSERT INTO security_rules_to (source,vsys,name,rule_lid) VALUES  " . $out . ";");
        unset($tofileto);unset($out);unset($unique);
    }
    if (isset($tofilesrv) && count($tofilesrv) > 0) {
        $unique=array_unique($tofilesrv);
        $out = implode(",", $unique);
        $projectdb->query("INSERT INTO security_rules_srv (source,vsys,table_name,member_lid,rule_lid) VALUES " . $out . ";");
        unset($tofilesrv);unset($out);unset($unique);
    }
    if (isset($tofiledst) && count($tofiledst) > 0) {
        $unique=array_unique($tofiledst);
        $out = implode(",", $unique);
        $projectdb->query("INSERT INTO security_rules_dst (source,vsys,table_name,member_lid,rule_lid) VALUES " . $out . ";");
        unset($tofiledst);unset($out);unset($unique);
    }
    if (isset($tofilesrc) &&  count($tofilesrc) > 0) {
        $unique=array_unique($tofilesrc);
        $out = implode(",", $unique);
        $projectdb->query("INSERT INTO security_rules_src (source,vsys,table_name,member_lid,rule_lid) VALUES " . $out . ";");
        unset($tofilesrc);unset($out);unset($unique);
    }
    if (isset($addTag) &&  count($addTag)>0){
        $projectdb->query("INSERT INTO security_rules_tag (source,vsys,rule_lid,member_lid,table_name) VALUES ".implode(",",$addTag).";");
        unset($addTag);
    }
}

function get_XML_Applications($configuration, $vsys, $source,&$objectsInMemory) {

    global $projectdb;

    # Load all the Services
    $getAddress=$projectdb->query("SELECT * FROM services WHERE source='$source';");
    if ($getAddress->num_rows>0){
        while($getAddressD=$getAddress->fetch_assoc()){
            $objvsys=$getAddressD['vsys'];
            $objectsInMemory[$objvsys]['services'][$getAddressD['name_ext']]=$getAddressD['id'];
        }
    }
    # Load all the Services Groups
    $getAddress=$projectdb->query("SELECT * FROM services_groups_id WHERE source='$source';");
    if ($getAddress->num_rows>0){
        while($getAddressD=$getAddress->fetch_assoc()){
            $objvsys=$getAddressD['vsys'];
            $objectsInMemory[$objvsys]['services_groups_id'][$getAddressD['name_ext']]=$getAddressD['id'];
        }
    }

    # Generate IDs for Services
    $getMax=$projectdb->query("SELECT max(id) as max FROM services;");
    if ($getMax->num_rows==1){
        $getMaxData=$getMax->fetch_assoc();
        $alid=$getMaxData['max'] + 1;
    }

    # Generate IDs for Groups
    $getMax=$projectdb->query("SELECT max(id) as max FROM services_groups_id;");
    if ($getMax->num_rows==1){
        $getMaxData=$getMax->fetch_assoc();
        $aglid=$getMaxData['max'] + 1;
    }

    $add_service=array();
    $add_service_group_member=array();
    $add_service_group=array();

    # this path is for vsys1 only for other vsys consider logical-systems
    $application = $configuration->xpath("/configuration/applications/application");
    foreach ($application as $data) {
        $name = (string)$data->name;
        if (empty($name)) {
            $name = (string)$data->{'address-name'};
        }
        $description = addslashes($data->description);
        $protocol = (string)$data->protocol;
        $uuid = $data->{'uuid'} ?? '';
        $source_port = (string)$data->{'source-port'};
        $destination_port = (string)$data->{'destination-port'};
        $inactivity_timeout = (string)$data->{'inactivity-timeout'};
        $inactivity_timeout = $inactivity_timeout!=='never'?$inactivity_timeout:'604800';

        if ($protocol === "icmp") {
            $icmp_type = (string)$data->{'icmp-type'};
            $icmp_code = (string)$data->{'icmp-code'};
        } elseif ($protocol === "icmp6") {
            $icmp_type6 = (string)$data->{'icmp6-type'};
            $icmp_code6 = (string)$data->{'icmp6-code'};
        }

        if($inactivity_timeout === ""){$override = "no";
        }else{$override = "yes";}

        $name_int = truncate_names(normalizeNames($name));

        if (!empty($inactivity_timeout)) {
            add_log('warning', 'Reading Services Objects and Groups', 'Service [' . $name . '] has inactivity-timeout [' . $inactivity_timeout . '] assigned.', $source, 'Create a New APP with the custom Timeout and create an app-override rule or Upgrade to PanOS 8.1');
        }

        if (!empty($data->term)) {

            if (!isset($objectsInMemory[$vsys]['services_groups_id'][$name])){
                $add_service_group[]="('$aglid','$name','$name_int','0','$source','$vsys')";
                $objectsInMemory[$vsys]['services_groups_id'][$name]=$aglid;
                $currentLid=$aglid;
                $aglid++;
            }
            else{
                $currentLid=$objectsInMemory[$vsys]['services_groups_id'][$name];
            }

            foreach ($data->term as $data2) {
                $name2 = (string)$data2->name;
                if (empty($name2)) {
                    $name2 = (string)$data2->{'address-name'};
                }
                $description2 = addslashes($data2->description);
                $protocol2 = (string)$data2->protocol;
                $source_port2 = (string)$data2->{'source-port'};
                $destination_port2 = (string)$data2->{'destination-port'};
                $app_uuid = $data2->{'uuid'}??'';
                $inactivity_timeout2 = (string)$data2->{'inactivity-timeout'};
                $inactivity_timeout2 = $inactivity_timeout2!=='never'?$inactivity_timeout2:'604800';
                $name2 = "$protocol2-$destination_port2-$app_uuid";

                if($inactivity_timeout2 === ""){$override = "no";
                }else{$override = "yes";}

                if (isset($objectsInMemory[$vsys]['services'][$name])){
                    $member_lid=$objectsInMemory[$vsys]['services'][$name];
                    $add_service_group_member[]="('$currentLid','$name2','$source','$member_lid','services','$vsys')";
                }
                elseif (isset($objectsInMemory['shared']['services'][$name])){
                    $member_lid=$objectsInMemory['shared']['services'][$name];
                    $add_service_group_member[]="('$currentLid','$name2','$source','$member_lid','services','shared')";
                }
                else{
                    if (preg_match("#([0-9]+)\-([0-9]+)#", $destination_port2)) {
                        $service_type2 = "range";
                    } else {
                        $service_type2 = "service";
                    }
                    if ($source_port2 === "1-65535") {
                        $source_port2 = "";
                    }
                    $add_service[]="('$alid','$service_type2','$name2','$name2','$protocol2','$destination_port2','0','$description2','$source','$source_port2','$vsys','$inactivity_timeout2','$override')";
                    $objectsInMemory[$vsys]['services'][$name2]=$alid;
                    $add_service_group_member[]="('$currentLid','$name2','$source','$alid','services','$vsys')";
                    $alid++;
                }
            }
        }
        else {
            if (!isset($objectsInMemory[$vsys]['services'][$name])){
                if (preg_match("#([0-9]+)\-([0-9]+)#", $destination_port)) {
                    $service_type = "range";
                } else {
                    $service_type = "service";
                }
                if ($source_port == "1-65535") {
                    $source_port = "";
                }
                $add_service[]="('$alid','$service_type','$name','$name_int','$protocol','$destination_port','0','$description','$source','$source_port','$vsys','$inactivity_timeout','$override')";
                $objectsInMemory[$vsys]['services'][$name]=$alid;
                $alid++;
            }
        }
    }

    if (count($add_service)){
        $projectdb->query("INSERT INTO services (id,type,name_ext,name,protocol,dport,checkit,description,source,sport,vsys,timeout,override) VALUES ". implode(",",$add_service).";");
    }
    if (count($add_service_group)>0){
        $projectdb->query("INSERT INTO services_groups_id (id,name_ext,name,checkit,source,vsys) VALUES " .implode(",",$add_service_group).";");
        $projectdb->query("INSERT INTO services_groups (lid,member,source,member_lid,table_name,vsys) VALUES ".implode(",",$add_service_group_member).";");
    }
}

function get_XML_ServicesGroups($configuration, $vsys, $source,&$objectsInMemory) {

    global $projectdb;
    $add_service_group=array();
    # Generate IDs for Services
    $getMax=$projectdb->query("SELECT max(id) as max FROM services;");
    if ($getMax->num_rows==1){
        $getMaxData=$getMax->fetch_assoc();
        $alid=$getMaxData['max'] + 1;
    }

    # Generate IDs for Groups
    $getMax=$projectdb->query("SELECT max(id) as max FROM services_groups_id;");
    if ($getMax->num_rows==1){
        $getMaxData=$getMax->fetch_assoc();
        $aglid=$getMaxData['max'] + 1;
    }

    $address = $configuration->xpath("/configuration/applications/application-set");
    //Declaring all the groups to have knowledge on their existence
    foreach ($address as $data) {
        $name = (string)$data->name;
        if (empty($name)) {
            $name = (string)$data->{'address-name'};
        }
        $name_int = truncate_names(normalizeNames($name));

        if (!isset($objectsInMemory[$vsys]['services_groups_id'][$name])){
            $add_service_group[]="('$aglid','$name','$name_int',0,'$source','$vsys')";
            $objectsInMemory[$vsys]['services_groups_id'][$name]=$aglid;
            $aglid++;
        }
    }

    //Iterating on all the groups to set their members. Notice that now we should have knowledge
    // of all the existing groups
    foreach ($address as $data) {
        $name = (string)$data->name;
        if (empty($name)) {
            $name = (string)$data->{'address-name'};
        }
        $name_int = truncate_names(normalizeNames($name));

        if (!isset($objectsInMemory[$vsys]['services_groups_id'][$name])){  //This should not happen, as the group should have been defined above
            $add_service_group[]="('$aglid','$name','$name_int',0,'$source','$vsys')";
            $objectsInMemory[$vsys]['services_groups_id'][$name]=$aglid;
            $CurrentLid=$aglid;
            $aglid++;
        }
        else{
            $CurrentLid=$objectsInMemory[$vsys]['services_groups_id'][$name];
        }

        if (isset($data->application)){
            foreach ($data->application as $value) {
                $member = (string)$value->name;
                //echo "Member dentro de application: " .$member. "\n";

                if (isset($objectsInMemory[$vsys]['services'][$member])){
                    $member_lid=$objectsInMemory[$vsys]['services'][$member];
                    $add_service_group_member[]="('$CurrentLid','$member','$source','$member_lid','services','$vsys')";
                }
                elseif (isset($objectsInMemory['shared']['services'][$member])){
                    $member_lid=$objectsInMemory['shared']['services'][$member];
                    $add_service_group_member[]="('$CurrentLid','$member','$source','$member_lid','services','shared')";
                }
                // New to read if they have a member as a group
                elseif (isset($objectsInMemory[$vsys]['services_groups_id'][$member])){
                    $member_lid=$objectsInMemory[$vsys]['services_groups_id'][$member];
                    $add_service_group_member[]="('$CurrentLid','$member','$source','$member_lid','services_groups_id','$vsys')";
                }
                elseif (isset($objectsInMemory['shared']['services_groups_id'][$member])){
                    $member_lid=$objectsInMemory['shared']['services_groups_id'][$member];
                    $add_service_group_member[]="('$CurrentLid','$member','$source','$member_lid','services_groups_id','shared')";
                }
                else{
                    add_log2("error",'Reading ApplicationGroups','Application '.$member.' was not found in the database.',$source,'Add '.$member.' to the ServiceGroup '.$name,'objects',$CurrentLid,'services_groups_id');
                    print "Unable to find the member ($member) of applicationgroup ($name) on vsys($vsys)".PHP_EOL;
                }

            }
        }
        if (isset($data->{'application-set'})){
            foreach ($data->{'application-set'} as $value) {
                $member = (string)$value->name;
                echo "Member dentro de application-set for $name: " .$member. "\n";

                if (isset($objectsInMemory[$vsys]['services_groups_id'][$member])){
                    $member_lid=$objectsInMemory[$vsys]['services_groups_id'][$member];
                    $add_service_group_member[]="('$CurrentLid','$member','$source','$member_lid','services_groups_id','$vsys')";
                }
                elseif (isset($objectsInMemory['shared']['services_groups_id'][$member])){
                    $member_lid=$objectsInMemory['shared']['services_groups_id'][$member];
                    $add_service_group_member[]="('$CurrentLid','$member','$source','$member_lid','services_groups_id','shared')";
                }
                else{
                    add_log2("error",'Reading ApplicationGroups','ApplicationGroup '.$member.' was not found in the database and used in '.$name, $source,'Add '.$member.' to the ServiceGroup '.$name,'objects',$CurrentLid,'services_groups_id');
                    print "Unable to find the member ($member) of applicationgroup ($name) on vsys($vsys)".PHP_EOL;
                }
            }
        }


    }

    if (count($add_service_group)>0){
        $projectdb->query("INSERT INTO services_groups_id (id,name_ext,name,checkit,source,vsys) VALUES " .implode(",",$add_service_group).";");
        $projectdb->query("INSERT INTO services_groups (lid,member,source,member_lid,table_name,vsys) VALUES ".implode(",",$add_service_group_member).";");
    }
}

function get_XML_Zones_Address($configuration, $vsys, $source, $template) {
    global $projectdb;

    $allzones = $configuration->xpath("//zones/security-zone");
    $add_address_group =array();
    $zones = array();
    foreach ($allzones as $child => $data2) {
        if (isset($data2->attach->zone->name)){
            $zoneName = $data2->attach->zone->name;
        }
        else{
            $zoneName = $data2->name;
        }
        #Can be dynamic?
        $type = "layer3";
        if ($zoneName != "") {
            #Read Address and Groups and Assign the Zone to it.
            //$address=$data2->{'address-book'}->address; 

            $address = $data2->xpath("address-book/address");
            $add_address = array();

            foreach ($address as $child => $data) {
                $name = $data->name;

                #Fix if the object was named as 1.1.1.1/30 then replace / by - => 1.1.1.1-30
                $name = str_replace('/', '-', $name);

                if (empty($name)) {
                    $name = $data->{'address-name'};
                }
                $description = addslashes($data->description);

                $name_int = truncate_names(normalizeNames($name));

                if (!empty($data->{'ip-prefix'})) {
                    $prefix = $data->{'ip-prefix'};
                    list($ip, $mask) = explode("/", $prefix); #ip address
                    #Gotcha if the object comes without mask set to 32 bits			
                    $ipversion = ip_version($ip);
                    if ($ipversion == "v4") {
                        if ($mask == "") {
                            $mask = "32";
                        }
                    } elseif ($ipversion == "v6") {
                        if ($mask == "") {
                            $mask = "128";
                        }
                    }
                    else{
                        $ipversion="v4";
                        if ($mask == "") {
                            $mask = "32";
                        }
                    }
                    $getDup = $projectdb->query("SELECT name_ext FROM address WHERE source='$source' AND BINARY name_ext='$name' AND ipaddress='$ip' AND vsys='$vsys' AND zone='$zoneName';");

                    if ($getDup->num_rows == 0) {
                        $add_address[$ipversion][] = "('$name','$name_int','$vsys','ip-netmask','ip-netmask','$ip','$mask','1','$source','$description','$zoneName')";
                    } else {
                        add_log('warning', 'Reading Address Objects and Groups', 'An Object with this name already exists [' . $name . ']', $source, 'Object no imported');
                    }
                } elseif (!empty($data->{'address-range'})) {
                    $value1 = (string)$data->{'address-range'}->low;
                    $value2 = (string)$data->{'address-range'}->high;
                    $value=$value1."-".$value2;
                    $getDup = $projectdb->query("SELECT name_ext FROM address WHERE source='$source' AND BINARY name_ext='$name' AND vsys='$vsys' AND zone='$zoneName';");
                    if ($getDup->num_rows == 0) {
                        $projectdb->query("INSERT INTO address (name_ext,name,vsys,type,vtype,ipaddress,source,description,zone) VALUES ('$name','$name_int','$vsys','ip-range','ip-range','$value','$source','$description','$zoneName')");
                    } else {
                        add_log('warning', 'Reading Address Objects and Groups', 'An Object with this name already exists [' . $name . ']', $source, 'Object no imported');
                    }
                }
                elseif (!empty($data->{'range-address'})) {
                    $value1=(string)$data->{'range-address'}->name;
                    $value2=(string)$data->{'range-address'}->to->{'range-high'};
                    $value = $value1."-".$value2;
                    $getDup = $projectdb->query("SELECT name_ext FROM address WHERE source='$source' AND BINARY name_ext='$name' AND vsys='$vsys' AND zone='$zoneName';");
                    if ($getDup->num_rows == 0) {
                        $projectdb->query("INSERT INTO address (name_ext,name,vsys,type,vtype,ipaddress,source,description,zone) VALUES ('$name','$name_int','$vsys','ip-range','ip-range','$value','$source','$description','$zoneName')");
                    } else {
                        add_log('warning', 'Reading Address Objects and Groups', 'An Object with this name already exists [' . $name . ']', $source, 'Object no imported');
                    }
                }
                elseif (!empty($data->{'dns-name'})) {
                    $value = $data->{'dns-name'};
                    $valueName=(string)$value->name;
                    $getDup = $projectdb->query("SELECT name_ext FROM address WHERE source='$source' AND BINARY name_ext='$name' AND vsys='$vsys' AND zone='$zoneName';");
                    if ($getDup->num_rows == 0) {
                        $projectdb->query("INSERT INTO address (name_ext,name,vsys,type,vtype,fqdn,source,ipaddress,description,zone) VALUES ('$name','$name_int','$vsys','fqdn','fqdn','$valueName','$source','$valueName','$description','$zoneName')");
                    } else {
                        add_log('warning', 'Reading Address Objects and Groups', 'An Object with this name already exists [' . $name . ']', $source, 'Object no imported');
                    }
                }
            }
            if ( (isset($add_address['v4'])) AND (count($add_address['v4']) > 0) ){
                $unique=array_unique($add_address['v4']);
                $out = implode(",", $unique);
                $sql = $projectdb->query("INSERT INTO address (name_ext,name,vsys,type,vtype,ipaddress,cidr,v4,source,description,zone) VALUES " . $out.";");
            }
            if ( (isset($add_address['v6'])) AND (count($add_address['v6']) > 0) ){
                $unique=array_unique($add_address['v6']);
                $out = implode(",", $unique);
                $sql = $projectdb->query("INSERT INTO address (name_ext,name,vsys,type,vtype,ipaddress,cidr,v6,source,description,zone) VALUES " . $out.";");
                $projectdb->query("UPDATE address set v4=0 WHERE v6=1;");
            }
            unset($add_address);unset($unique);unset($out);

            #ADDRESS GROUPS
            $address = $data2->xpath("address-book/address-set");
            foreach ($address as $child => $data) {
                $name = $data->name;
                $name = str_replace('/', '-', $name);
                if (empty($name)) {
                    $name = $data->{'address-name'};
                }
                $name_int = truncate_names(normalizeNames($name));
                $getDup = $projectdb->query("SELECT id FROM address_groups_id WHERE source='$source' AND vsys='$vsys' AND BINARY name_ext='$name' AND zone='$zoneName';");
                if ($getDup->num_rows == 0) {
                    $projectdb->query("INSERT INTO address_groups_id (name_ext,name,source,vsys,zone) VALUES ('$name','$name_int','$source','$vsys','$zoneName');");
                    $lid = $projectdb->insert_id;

                    foreach ($data->{'address-set'} as $field => $value) {
                        $member = $value->name;
                        $member = str_replace('/', '-', $member);
                        $add_address_group[] = "('$lid','$member','$source','$vsys')";
                    }

                    foreach ($data->address as $field => $value) {
                        $member = $value->name;
                        $member = str_replace('/', '-', $member);
                        $add_address_group[] = "('$lid','$member','$source','$vsys')";
                    }
                }
            }

            #MAP Zone with Interfaces
            $interfacesin = $data2->xpath("interfaces");
            $getInterface = array();
            $getinterfacesall = "";
            foreach ($interfacesin as $kkkey => $vvvalue) {
                $intName = $vvvalue->name;
                $exist = $projectdb->query("SELECT id FROM interfaces WHERE unitname='$intName' AND source='$source';");
                if ($exist->num_rows > 0) {
                    $projectdb->query("UPDATE interfaces SET zone='$zoneName' WHERE source='$source' AND unitname='$intName'");
                }
                $getInterface[] = $vvvalue->name;
            }
            $getinterfacesall = implode(",", $getInterface);
            $zones[] = "('$source','$zoneName','$vsys','$type','$getinterfacesall','$template')";
        }
    }

    if (count($zones) > 0) {
        $out = implode(",", $zones);
        $projectdb->query("INSERT INTO zones (source,name,vsys,type,interfaces,template) VALUES " . $out . ";");
    }

    if (count($add_address_group) > 0) {

        $uniq = array_unique($add_address_group);
        $out = implode(",", $uniq);
        $projectdb->query("INSERT INTO address_groups (lid,member,source,vsys) VALUES " . $out . ";");
    }
}

function get_XML_Zones_Address_Global($configuration, $vsys, $source, $template) {
    global $projectdb;
    $add_address_group = array();
    $allzones = $configuration->xpath("//security/address-book");

    $zones = array();
    foreach ($allzones as $child => $data2) {
        #The zone will be calles global
        if (isset($data2->attach->zone->name)){
            $zoneName = $data2->attach->zone->name;
        }
        else{
            $zoneName = $data2->name;
        }
        #Can be dynamic?
        $type = "layer3";
        if ($zoneName != "") {
            #Read Address and Groups and Assign the Zone to it.
            //$address=$data2->{'address-book'}->address; 

            $address = $data2->xpath("address");
            $add_address = array();

            foreach ($address as $child => $data) {
                $name = $data->name;

                #Fix if the object was named as 1.1.1.1/30 then replace / by - => 1.1.1.1-30
                $name = str_replace('/', '-', $name);

                if (empty($name)) {
                    $name = $data->{'address-name'};
                }
                $description = addslashes($data->description);

                $name_int = truncate_names(normalizeNames($name));

                if (!empty($data->{'ip-prefix'})) {
                    $prefix = $data->{'ip-prefix'};
                    $theipaddress = explode("/", $prefix); #ip address
                    $ip=$theipaddress[0];
                    $mask=$theipaddress[1];
                    #Gotcha if the object comes without mask set to 32 bits			
                    $ipversion = ip_version($ip);
                    if ($ipversion == "v4") {
                        if ($mask == "") {
                            $mask = "32";
                        }
                    } elseif ($ipversion == "v6") {
                        if ($mask == "") {
                            $mask = "128";
                        }
                    }
                    else{
                        $ipversion="v4";
                        if ($mask == "") {
                            $mask = "32";
                        }
                    }
                    $getDup = $projectdb->query("SELECT name_ext FROM address WHERE source='$source' AND BINARY name_ext='$name' AND ipaddress='$ip' AND vsys='$vsys' AND zone='$zoneName';");

                    if ($getDup->num_rows == 0) {
                        $add_address[$ipversion][] = "('$name','$name_int','$vsys','ip-netmask','ip-netmask','$ip','$mask','1','$source','$description','$zoneName')";
                    } else {
                        add_log('warning', 'Reading Address Objects and Groups', 'An Object with this name already exists [' . $name . ']', $source, 'Object no imported');
                    }
                }
                elseif (!empty($data->{'address-range'})) {
                    $value1 = $data->{'address-range'}->low;
                    $value2 = $data->{'address-range'}->high;
                    $value=$value1."-".$value2;
                    $getDup = $projectdb->query("SELECT name_ext FROM address WHERE source='$source' AND BINARY name_ext='$name' AND vsys='$vsys' AND zone='$zoneName';");
                    if ($getDup->num_rows == 0) {
                        $projectdb->query("INSERT INTO address (name_ext,name,vsys,type,vtype,ipaddress,source,description,zone) VALUES ('$name','$name_int','$vsys','ip-range','ip-range','$value','$source','$description','$zoneName')");
                    } else {
                        add_log('warning', 'Reading Address Objects and Groups', 'An Object with this name already exists [' . $name . ']', $source, 'Object no imported');
                    }
                }
                elseif (!empty($data->{'range-address'})) {
                    $value1=$data->{'range-address'}->name;
                    $value2=$data->{'range-address'}->to->{'range-high'};
                    $value = $value1."-".$value2;
                    $getDup = $projectdb->query("SELECT name_ext FROM address WHERE source='$source' AND BINARY name_ext='$name' AND vsys='$vsys' AND zone='$zoneName';");
                    if ($getDup->num_rows == 0) {
                        $projectdb->query("INSERT INTO address (name_ext,name,vsys,type,vtype,ipaddress,source,description,zone) VALUES ('$name','$name_int','$vsys','ip-range','ip-range','$value','$source','$description','$zoneName')");
                    } else {
                        add_log('warning', 'Reading Address Objects and Groups', 'An Object with this name already exists [' . $name . ']', $source, 'Object no imported');
                    }
                }
                elseif (!empty($data->{'dns-name'})) {
                    $value = $data->{'dns-name'};
                    $valueName=(string)$value->name;
                    $getDup = $projectdb->query("SELECT name_ext FROM address WHERE source='$source' AND BINARY name_ext='$name' AND vsys='$vsys' AND zone='$zoneName';");
                    if ($getDup->num_rows == 0) {
                        $projectdb->query("INSERT INTO address (name_ext,name,vsys,type,vtype,fqdn,source,ipaddress,description,zone) VALUES ('$name','$name_int','$vsys','fqdn','fqdn','$valueName','$source','$valueName','$description','$zoneName')");
                    } else {
                        add_log('warning', 'Reading Address Objects and Groups', 'An Object with this name already exists [' . $name . ']', $source, 'Object no imported');
                    }
                }
            }
            if ( (isset($add_address['v4'])) AND (count($add_address['v4']) > 0) ){
                $unique=array_unique($add_address['v4']);
                $out = implode(",", $unique);
                $projectdb->query("INSERT INTO address (name_ext,name,vsys,type,vtype,ipaddress,cidr,v4,source,description,zone) VALUES " . $out.";");
            }
            if ( (isset($add_address['v6'])) AND (count($add_address['v6']) > 0) ){
                $unique=array_unique($add_address['v6']);
                $out = implode(",", $unique);
                $projectdb->query("INSERT INTO address (name_ext,name,vsys,type,vtype,ipaddress,cidr,v6,source,description,zone) VALUES " . $out.";");
                $projectdb->query("UPDATE address set v4=0 WHERE v6=1;");
            }

            unset($add_address);

            #ADDRESS GROUPS
            $address = $data2->xpath("address-set");
            foreach ($address as $child => $data) {
                $name = $data->name;
                $name = str_replace('/', '-', $name);
                if (empty($name)) {
                    $name = $data->{'address-name'};
                }
                $name_int = truncate_names(normalizeNames($name));
                $getDup = $projectdb->query("SELECT id FROM address_groups_id WHERE source='$source' AND vsys='$vsys' AND BINARY name_ext='$name' AND zone='$zoneName';");
                if ($getDup->num_rows == 0) {
                    $projectdb->query("INSERT INTO address_groups_id (name_ext,name,source,vsys,zone) VALUES ('$name','$name_int','$source','$vsys','$zoneName');");
                    $lid = $projectdb->insert_id;

                    foreach ($data->{'address-set'} as $field => $value) {
                        $member = $value->name;
                        $member = str_replace('/', '-', $member);
                        $getDup=$projectdb->query("SELECT id FROM address_groups_id WHERE source='$source' AND BINARY name_ext='$member' AND vsys='$vsys' AND zone='$zoneName';");
                        if($getDup->num_rows==1) {
                            $getAddrData = $getDup->fetch_assoc();
                            $member_lid = $getAddrData['id'];
                            $table_name = "address_groups_id";
                            $add_address_group[] = "('$lid','$member','$source','$vsys','$member_lid','$table_name')";
                        }
                        elseif($getDup->num_rows==0){
                            //$getDup=$projectdb->query("SELECT id FROM shared_address_groups_id WHERE source='$source' AND BINARY name='$member';");
                            $getDup=$projectdb->query("SELECT id FROM address_groups_id WHERE source='$source' AND BINARY name_ext='$member' AND vsys = 'shared';");
                            if ($getDup->num_rows==1){
                                $getAddrData = $getDup->fetch_assoc();
                                $member_lid = $getAddrData['id'];
                                //$table_name = "shared_address_groups_id";
                                $table_name = "address_groups_id";
                                $add_address_group[] = "('$lid','$member','$source','$vsys','$member_lid','$table_name')";
                            }
                            elseif($getDup->num_rows==0){
                                # TODO: Object doesnt exits then
                                $add_address_group[] = "('$lid','$member','$source','$vsys','','')";
                            }
                        }
                    }

                    foreach ($data->address as $field => $value) {
                        $member = $value->name;
                        $member = str_replace('/', '-', $member);
                        $getDup=$projectdb->query("SELECT id FROM address WHERE source='$source' AND BINARY name_ext='$member' AND vsys='$vsys' AND zone='$zoneName';");
                        if($getDup->num_rows==1) {
                            $getAddrData = $getDup->fetch_assoc();
                            $member_lid = $getAddrData['id'];
                            $table_name = "address";
                            $add_address_group[] = "('$lid','$member','$source','$vsys','$member_lid','$table_name')";
                        }
                        elseif($getDup->num_rows==0){
                            //$getDup=$projectdb->query("SELECT id FROM shared_address WHERE source='$source' AND BINARY name='$member';");
                            $getDup=$projectdb->query("SELECT id FROM address WHERE source='$source' AND BINARY name_ext='$member' AND vsys = 'shared';");
                            if ($getDup->num_rows==1){
                                $getAddrData = $getDup->fetch_assoc();
                                $member_lid = $getAddrData['id'];
                                //$table_name = "shared_address";
                                $table_name = "address";
                                $add_address_group[] = "('$lid','$member','$source','$vsys','$member_lid','$table_name')";
                            }
                            elseif($getDup->num_rows==0){
                                # TODO: Object doesnt exits then
                            }
                        }
                    }
                }
            }
        }
    }

    if (count($add_address_group) > 0) {

        $uniq = array_unique($add_address_group);
        $out = implode(",", $uniq);
        $projectdb->query("INSERT INTO address_groups (lid,member,source,vsys,member_lid,table_name) VALUES " . $out . ";");
    }
}

function get_XML_Zones_Address_All_new($configuration, $vsys, $source, $template, &$objectsInMemory) {
    global $projectdb;


    if (count($objectsInMemory)==0){
        # Load all the Address
        $getAddress=$projectdb->query("SELECT * FROM address WHERE source='$source';");
        if ($getAddress->num_rows>0){
            while($getAddressD=$getAddress->fetch_assoc()){
                $objectsInMemory[$getAddressD['zone']]['address'][$getAddressD['name_ext']]=$getAddressD['id'];
            }
        }
        # Load all the Address Groups
        $getAddress=$projectdb->query("SELECT * FROM address_groups_id WHERE source='$source';");
        if ($getAddress->num_rows>0){
            while($getAddressD=$getAddress->fetch_assoc()){
                $objectsInMemory[$getAddressD['zone']]['address_groups_id'][$getAddressD['name_ext']]=$getAddressD['id'];
            }
        }
    }

    # Generate IDs for Address
    $getMax=$projectdb->query("SELECT max(id) as max FROM address;");
    if ($getMax->num_rows==1){
        $getMaxData=$getMax->fetch_assoc();
        $alid=$getMaxData['max'] + 1;
    }

    # Generate IDs for Groups
    $add_address = array();
    $add_address_group = array();
    $add_address_group_member = array();
    $getMax=$projectdb->query("SELECT max(id) as max FROM address_groups_id;");
    if ($getMax->num_rows==1){
        $getMaxData=$getMax->fetch_assoc();
        $aglid=$getMaxData['max'] + 1;
    }

    # Load the new address-books like Globals
    $allzones = $configuration->xpath("/configuration/security/address-book");
    $allzones2 = $configuration->xpath("/configuration/groups/security/address-book");
    $allzones = array_merge($allzones, $allzones2);
    foreach ($allzones as $child => $data2) {
        #The zone will be calles global
        if (isset($data2->attach->zone->name)){
            $zoneName = (string)  $data2->attach->zone->name;
        }
        else{
            $zoneName = (string) $data2->name;
        }
        #Can be dynamic?
        $type = "layer3";
        if ($zoneName != "") {
            #Read Address and Groups and Assign the Zone to it.

            if (!isset($objectsInMemory[$zoneName])){
                $objectsInMemory[$zoneName]['address']=array();
                $objectsInMemory[$zoneName]['address_groups_id']=array();
            }

            $address = $data2->xpath("address");
            foreach ($address as $child => $data) {
                $name = (string) $data->name;

                #Fix if the object was named as 1.1.1.1/30 then replace / by - => 1.1.1.1-30
                $name = str_replace('/', '-', $name);

                if (empty($name)) {
                    $name = (string) $data->{'address-name'};
                }
                $description = addslashes($data->description);

                $name_int = truncate_names(normalizeNames($name));

                if (!empty($data->{'ip-prefix'})) {
                    $prefix = (string)$data->{'ip-prefix'};
                    $theipaddress = explode("/", $prefix); #ip address
                    $ip=$theipaddress[0];
                    $mask=$theipaddress[1];
                    #Gotcha if the object comes without mask set to 32 bits
                    $ipversion = ip_version($ip);
                    if ($ipversion == "v4") {
                        if ($mask == "") {
                            $mask = "32";
                        }
                    } elseif ($ipversion == "v6") {
                        if ($mask == "") {
                            $mask = "128";
                        }
                    }
                    else{
                        $ipversion="v4";
                        if ($mask == "") {
                            $mask = "32";
                        }
                    }

                    if (!isset($objectsInMemory[$zoneName]['address'][$name])){
                        $add_address[$ipversion][] = "('$alid','$name','$name_int','$vsys','ip-netmask','ip-netmask','$ip','$mask','1','$source','$description','$zoneName')";
                        $objectsInMemory[$zoneName]['address'][$name]=$alid;
                        if($zoneName == "global"){
                            $objectsInMemory["any"]['address'][$name]=$alid;
                        }
                        $alid++;
                    }

                }
                elseif (!empty($data->{'address-range'})) {
                    $value1 = (string)$data->{'address-range'}->low;
                    $value2 = (string)$data->{'address-range'}->high;
                    $value=$value1."-".$value2;

                    $ipversion = ip_version($value1);
                    if ($ipversion=="noip"){
                        $ipversion="v4";
                    }

                    if (!isset($objectsInMemory[$zoneName]['address'][$name])){
                        $add_address[$ipversion][] = "('$alid','$name','$name_int','$vsys','ip-range','ip-range','$value','','1','$source','$description','$zoneName')";
                        $objectsInMemory[$zoneName]['address'][$name]=$alid;
                        if($zoneName == "global"){
                            $objectsInMemory["any"]['address'][$name]=$alid;
                        }
                        $alid++;
                    }
                }
                elseif (!empty($data->{'range-address'})) {
                    $value1=(string)$data->{'range-address'}->name;
                    $value2=(string)$data->{'range-address'}->to->{'range-high'};
                    $value = $value1."-".$value2;

                    $ipversion = ip_version($value1);
                    if ($ipversion=="noip"){
                        $ipversion="v4";
                    }

                    if (!isset($objectsInMemory[$zoneName]['address'][$name])){
                        $add_address[$ipversion][] = "('$alid','$name','$name_int','$vsys','ip-range','ip-range','$value','','1','$source','$description','$zoneName')";
                        $objectsInMemory[$zoneName]['address'][$name]=$alid;
                        if($zoneName == "global"){
                            $objectsInMemory["any"]['address'][$name]=$alid;
                        }
                        $alid++;
                    }
                }
                elseif (!empty($data->{'dns-name'})) {
                    $value = $data->{'dns-name'};
                    $valueName=(string)$value->name;
                    $ipversion="v4";
                    if (!isset($objectsInMemory[$zoneName]['address'][$name])){
                        $add_address[$ipversion][] = "('$alid','$name','$name_int','$vsys','fqdn','fqdn','$valueName','','1','$source','$description','$zoneName')";
                        $objectsInMemory[$zoneName]['address'][$name]=$alid;
                        if($zoneName == "global"){
                            $objectsInMemory["any"]['address'][$name]=$alid;
                        }
                        $alid++;
                    }
                }
            }

            # ADDRESS GROUPS
            $address = $data2->xpath("address-set");
            #First read all the GRoups and assign a lid
            foreach ($address as $child => $data) {
                $name = (string)$data->name;
                $name = str_replace('/', '-', $name);
                if (empty($name)) {
                    $name = (string)$data->{'address-name'};
                }
                $name_int = truncate_names(normalizeNames($name));

                if (!isset($objectsInMemory[$zoneName]['address_groups_id'][$name])){
                    $add_address_group[] = "('$aglid','$name','$name_int','$source','$vsys','$zoneName')";
                    $objectsInMemory[$zoneName]['address_groups_id'][$name]=$aglid;
                    if($zoneName == "global"){
                        $objectsInMemory["any"]['address_groups_id'][$name]=$aglid;
                    }
                    $aglid++;
                }
            }

            foreach ($address as $child => $data) {
                $name = (string)$data->name;
                $name = str_replace('/', '-', $name);
                if (empty($name)) {
                    $name = (string)$data->{'address-name'};
                }
                $name_int = truncate_names(normalizeNames($name));

                if (isset($objectsInMemory[$zoneName]['address_groups_id'][$name])){
                    $currentLid=$objectsInMemory[$zoneName]['address_groups_id'][$name];
                }
                else{
                    $add_address_group[] = "('$aglid','$name','$name_int','$source','$vsys','$zoneName')";
                    $objectsInMemory[$zoneName]['address_groups_id'][$name]=$aglid;
                    if($zoneName == "global"){
                        $objectsInMemory["any"]['address_groups_id'][$name]=$aglid;
                    }
                    $currentLid=$aglid;
                    $aglid++;
                }

                if (isset($data->address)){
                    foreach ($data->address as $field => $value) {
                        $member = (string)$value->name;
                        $member = str_replace('/', '-', $member);
                        if (isset($objectsInMemory[$zoneName]['address'][$member])){
                            $member_lid=$objectsInMemory[$zoneName]['address'][$member];
                            $table_name="address";
                            $add_address_group_member[] = "('$currentLid','$member','$source','$vsys','$member_lid','$table_name')";
                        }
                        elseif (isset($objectsInMemory['global']['address'][$member])){
                            $member_lid=$objectsInMemory['global']['address'][$member];
                            $table_name="address";
                            $add_address_group_member[] = "('$currentLid','$member','$source','$vsys','$member_lid','$table_name')";
                        }
                        else{
                            print "Unable to find this Member Object (address): $member on a Group: $name".PHP_EOL;
                        }
                    }
                }

                if (isset($data->{'address-set'})){
                    foreach ($data->{'address-set'} as $field => $value) {
                        $member = (string)$value->name;
                        $member = str_replace('/', '-', $member);
                        if (isset($objectsInMemory[$zoneName]['address_groups_id'][$member])){
                            $member_lid=$objectsInMemory[$zoneName]['address_groups_id'][$member];
                            $table_name="address_groups_id";
                            $add_address_group_member[] = "('$currentLid','$member','$source','$vsys','$member_lid','$table_name')";
                        }
                        elseif (isset($objectsInMemory['global']['address_groups_id'][$member])){
                            $member_lid=$objectsInMemory['global']['address_groups_id'][$member];
                            $table_name="address_groups_id";
                            $add_address_group_member[] = "('$currentLid','$member','$source','$vsys','$member_lid','$table_name')";
                        }
                        else{
                            print "Unable to find this Member Object (Group): $member on a Group: $name".PHP_EOL;
                        }
                    }
                }
            }

        }
    }

    $allzones = $configuration->xpath("/configuration/groups/security/zones/security-zone");
    foreach ($allzones as $child => $data2) {
        #The zone will be calles global
        $zoneName = (string) $data2->name;

        if ($zoneName == "&lt;*&gt;" || $zoneName == "<*>") { $zoneName = "global";}

        #Can be dynamic?
        $type = "layer3";
        if ($zoneName != "") {
            #Read Address and Groups and Assign the Zone to it.

            if (!isset($objectsInMemory[$zoneName])){
                $objectsInMemory[$zoneName]['address']=array();
                $objectsInMemory[$zoneName]['address_groups_id']=array();
            }

            $address = $data2->xpath("address-book/address");

            foreach ($address as $child2 => $data) {
                $name = (string) $data->name;

                #Fix if the object was named as 1.1.1.1/30 then replace / by - => 1.1.1.1-30
                $name = str_replace('/', '-', $name);

                if (empty($name)) {
                    $name = (string) $data->{'address-name'};
                }
                $description = addslashes($data->description);

                $name_int = truncate_names(normalizeNames($name));

                if (!empty($data->{'ip-prefix'})) {
                    $prefix = (string)$data->{'ip-prefix'};
                    $theipaddress = explode("/", $prefix); #ip address
                    $ip=$theipaddress[0];
                    $mask=$theipaddress[1];
                    #Gotcha if the object comes without mask set to 32 bits
                    $ipversion = ip_version($ip);
                    if ($ipversion == "v4") {
                        if ($mask == "") {
                            $mask = "32";
                        }
                    } elseif ($ipversion == "v6") {
                        if ($mask == "") {
                            $mask = "128";
                        }
                    }
                    else{
                        $ipversion="v4";
                        if ($mask == "") {
                            $mask = "32";
                        }
                    }

                    if (!isset($objectsInMemory[$zoneName]['address'][$name])){
                        $add_address[$ipversion][] = "('$alid','$name','$name_int','$vsys','ip-netmask','ip-netmask','$ip','$mask','1','$source','$description','$zoneName')";
                        $objectsInMemory[$zoneName]['address'][$name]=$alid;
                        if($zoneName == "global"){
                            $objectsInMemory["any"]['address'][$name]=$alid;
                        }
                        $alid++;
                    }

                }
                elseif (!empty($data->{'address-range'})) {
                    $value1 = (string)$data->{'address-range'}->low;
                    $value2 = (string)$data->{'address-range'}->high;
                    $value=$value1."-".$value2;

                    $ipversion = ip_version($value1);
                    if ($ipversion=="noip"){
                        $ipversion="v4";
                    }

                    if (!isset($objectsInMemory[$zoneName]['address'][$name])){
                        $add_address[$ipversion][] = "('$alid','$name','$name_int','$vsys','ip-range','ip-range','$value','','1','$source','$description','$zoneName')";
                        $objectsInMemory[$zoneName]['address'][$name]=$alid;
                        if($zoneName == "global"){
                            $objectsInMemory["any"]['address'][$name]=$alid;
                        }
                        $alid++;
                    }
                }
                elseif (!empty($data->{'range-address'})) {
                    $value1=(string)$data->{'range-address'}->name;
                    $value2=(string)$data->{'range-address'}->to->{'range-high'};
                    $value = $value1."-".$value2;

                    $ipversion = ip_version($value1);
                    if ($ipversion=="noip"){
                        $ipversion="v4";
                    }

                    if (!isset($objectsInMemory[$zoneName]['address'][$name])){
                        $add_address[$ipversion][] = "('$alid','$name','$name_int','$vsys','ip-range','ip-range','$value','','1','$source','$description','$zoneName')";
                        $objectsInMemory[$zoneName]['address'][$name]=$alid;
                        if($zoneName == "global"){
                            $objectsInMemory["any"]['address'][$name]=$alid;
                        }
                        $alid++;
                    }
                }
                elseif (!empty($data->{'dns-name'})) {
                    $value = $data->{'dns-name'};
                    $valueName=(string)$value->name;
                    $ipversion="v4";
                    if (!isset($objectsInMemory[$zoneName]['address'][$name])){
                        $add_address[$ipversion][] = "('$alid','$name','$name_int','$vsys','fqdn','fqdn','$valueName','','1','$source','$description','$zoneName')";
                        $objectsInMemory[$zoneName]['address'][$name]=$alid;
                        if($zoneName == "global"){
                            $objectsInMemory["any"]['address'][$name]=$alid;
                        }
                        $alid++;
                    }
                }
            }

            # ADDRESS GROUPS
            $address = $data2->xpath("address-set");

            #First read all the GRoups and assign a lid
            foreach ($address as $child => $data) {
                $name = (string)$data->name;
                $name = str_replace('/', '-', $name);
                if (empty($name)) {
                    $name = (string)$data->{'address-name'};
                }
                $name_int = truncate_names(normalizeNames($name));

                if (!isset($objectsInMemory[$zoneName]['address_groups_id'][$name])){
                    $add_address_group[] = "('$aglid','$name','$name_int','$source','$vsys','$zoneName')";
                    $objectsInMemory[$zoneName]['address_groups_id'][$name]=$aglid;
                    if($zoneName == "global"){
                        $objectsInMemory["any"]['address_groups_id'][$name]=$aglid;
                    }
                    $aglid++;
                }
            }

            foreach ($address as $child => $data) {
                $name = (string)$data->name;
                $name = str_replace('/', '-', $name);
                if (empty($name)) {
                    $name = (string)$data->{'address-name'};
                }
                $name_int = truncate_names(normalizeNames($name));

                if (isset($objectsInMemory[$zoneName]['address_groups_id'][$name])){
                    $currentLid=$objectsInMemory[$zoneName]['address_groups_id'][$name];
                }
                else{
                    $add_address_group[] = "('$aglid','$name','$name_int','$source','$vsys','$zoneName')";
                    $objectsInMemory[$zoneName]['address_groups_id'][$name]=$aglid;
                    if($zoneName == "global"){
                        $objectsInMemory["any"]['address_groups_id'][$name]=$aglid;
                    }
                    $currentLid=$aglid;
                    $aglid++;
                }

                if (isset($data->address)){
                    foreach ($data->address as $field => $value) {
                        $member = (string)$value->name;
                        $member = str_replace('/', '-', $member);
                        if (isset($objectsInMemory[$zoneName]['address'][$member])){
                            $member_lid=$objectsInMemory[$zoneName]['address'][$member];
                            $table_name="address";
                            $add_address_group_member[] = "('$currentLid','$member','$source','$vsys','$member_lid','$table_name')";
                        }
                        elseif (isset($objectsInMemory['global']['address'][$member])){
                            $member_lid=$objectsInMemory['global']['address'][$member];
                            $table_name="address";
                            $add_address_group_member[] = "('$currentLid','$member','$source','$vsys','$member_lid','$table_name')";
                        }
                        else{
                            print "Unable to find this Member Object (address): $member on a Group: $name".PHP_EOL;
                        }
                    }
                }

                if (isset($data->{'address-set'})){
                    foreach ($data->{'address-set'} as $field => $value) {
                        $member = (string)$value->name;
                        $member = str_replace('/', '-', $member);
                        if (isset($objectsInMemory[$zoneName]['address_groups_id'][$member])){
                            $member_lid=$objectsInMemory[$zoneName]['address_groups_id'][$member];
                            $table_name="address_groups_id";
                            $add_address_group_member[] = "('$currentLid','$member','$source','$vsys','$member_lid','$table_name')";
                        }
                        elseif (isset($objectsInMemory['global']['address_groups_id'][$member])){
                            $member_lid=$objectsInMemory['global']['address_groups_id'][$member];
                            $table_name="address_groups_id";
                            $add_address_group_member[] = "('$currentLid','$member','$source','$vsys','$member_lid','$table_name')";
                        }
                        else{
                            print "Unable to find this Member Object (Group): $member on a Group: $name".PHP_EOL;
                        }
                    }
                }
            }

            #MAP Zone with Interfaces
            $interfacesin = $data2->xpath("interfaces");
            $getInterface = array();
            foreach ($interfacesin as $kkkey => $vvvalue) {
                $intName = (string)$vvvalue->name;
                // rename interface if needed
                if(str_contains($intName,"st0")) {
                    $intName = str_replace("st0", "tunnel", $intName);
                } elseif (str_contains($intName,"lo0")) {
                    $intName = str_replace("lo0", "loopback", $intName);
                }
                $exist = $projectdb->query("SELECT id FROM interfaces WHERE unitname='$intName' AND source='$source';");
                if ($exist->num_rows > 0) {
                    $projectdb->query("UPDATE interfaces SET zone='$zoneName' WHERE source='$source' AND unitname='$intName'");
                }
                $getInterface[] = $intName; //(string)$vvvalue->name;
            }
            $getinterfacesall = implode(",", $getInterface);
            $zones[] = "('$source','$zoneName','$vsys','$type','$getinterfacesall','$template')";
        }
    }

    # Load all the old address-books from zones
    //$zones=array();
    $allzones = $configuration->xpath("/configuration/security/zones/security-zone");

    //$zones = array();
    foreach ($allzones as $child => $data2) {
        if (isset($data2->attach->zone->name)){
            $zoneName = (string)$data2->attach->zone->name;
        }
        else{
            $zoneName = (string)$data2->name;
        }
        #Can be dynamic?
        $type = "layer3";
        if ($zoneName != "") {
            #Read Address and Groups and Assign the Zone to it.
            //$address=$data2->{'address-book'}->address;

            if (!isset($objectsInMemory[$zoneName])){
                $objectsInMemory[$zoneName]['address']=array();
                $objectsInMemory[$zoneName]['address_groups_id']=array();
            }

            $address = $data2->xpath("address-book/address");
            foreach ($address as $child => $data) {
                $name = (string)$data->name;

                #Fix if the object was named as 1.1.1.1/30 then replace / by - => 1.1.1.1-30
                $name = str_replace('/', '-', $name);

                if (empty($name)) {
                    $name = (string)$data->{'address-name'};
                }
                $description = addslashes($data->description);

                $name_int = truncate_names(normalizeNames($name));

                if (!empty($data->{'ip-prefix'})) {
                    $prefix = (string)$data->{'ip-prefix'};
                    $theipaddress = explode("/", $prefix); #ip address
                    $ip=$theipaddress[0];
                    $mask=$theipaddress[1];
                    #Gotcha if the object comes without mask set to 32 bits
                    $ipversion = ip_version($ip);
                    if ($ipversion == "v4") {
                        if ($mask == "") {
                            $mask = "32";
                        }
                    } elseif ($ipversion == "v6") {
                        if ($mask == "") {
                            $mask = "128";
                        }
                    }
                    else{
                        $ipversion="v4";
                        if ($mask == "") {
                            $mask = "32";
                        }
                    }

                    if (!isset($objectsInMemory[$zoneName]['address'][$name])){
                        $add_address[$ipversion][] = "('$alid','$name','$name_int','$vsys','ip-netmask','ip-netmask','$ip','$mask','1','$source','$description','$zoneName')";
                        $objectsInMemory[$zoneName]['address'][$name]=$alid;
                        if($zoneName == "global"){
                            $objectsInMemory["any"]['address'][$name]=$alid;
                        }
                        $alid++;
                    }

                }
                elseif (!empty($data->{'address-range'})) {
                    $value1 = (string)$data->{'address-range'}->low;
                    $value2 = (string)$data->{'address-range'}->high;
                    $value=$value1."-".$value2;

                    $ipversion = ip_version($value1);
                    if ($ipversion=="noip"){
                        $ipversion="v4";
                    }

                    if (!isset($objectsInMemory[$zoneName]['address'][$name])){
                        $add_address[$ipversion][] = "('$alid','$name','$name_int','$vsys','ip-range','ip-range','$value','','1','$source','$description','$zoneName')";
                        $objectsInMemory[$zoneName]['address'][$name]=$alid;
                        if($zoneName == "global"){
                            $objectsInMemory["any"]['address'][$name]=$alid;
                        }
                        $alid++;
                    }
                }
                elseif (!empty($data->{'range-address'})) {
                    $value1=(string)$data->{'range-address'}->name;
                    $value2=(string)$data->{'range-address'}->to->{'range-high'};
                    $value = $value1."-".$value2;

                    $ipversion = ip_version($value1);
                    if ($ipversion=="noip"){
                        $ipversion="v4";
                    }

                    if (!isset($objectsInMemory[$zoneName]['address'][$name])){
                        $add_address[$ipversion][] = "('$alid','$name','$name_int','$vsys','ip-range','ip-range','$value','','1','$source','$description','$zoneName')";
                        $objectsInMemory[$zoneName]['address'][$name]=$alid;
                        if($zoneName == "global"){
                            $objectsInMemory["any"]['address'][$name]=$alid;
                        }
                        $alid++;
                    }
                }
                elseif (!empty($data->{'dns-name'})) {
                    $value = $data->{'dns-name'};
                    $valueName=(string)$value->name;
                    $ipversion="v4";
                    if (!isset($objectsInMemory[$zoneName]['address'][$name])){
                        $add_address[$ipversion][] = "('$alid','$name','$name_int','$vsys','fqdn','fqdn','$valueName','','1','$source','$description','$zoneName')";
                        $objectsInMemory[$zoneName]['address'][$name]=$alid;
                        if($zoneName == "global"){
                            $objectsInMemory["any"]['address'][$name]=$alid;
                        }
                        $alid++;
                    }
                }
            }


            #ADDRESS GROUPS
            $address = $data2->xpath("address-book/address-set");

            foreach ($address as $child => $data) {
                $name = (string)$data->name;
                $name = str_replace('/', '-', $name);
                if (empty($name)) {
                    $name = (string)$data->{'address-name'};
                }
                $name_int = truncate_names(normalizeNames($name));

                if (!isset($objectsInMemory[$zoneName]['address_groups_id'][$name])){
                    $add_address_group[] = "('$aglid','$name','$name_int','$source','$vsys','$zoneName')";
                    $objectsInMemory[$zoneName]['address_groups_id'][$name]=$aglid;
                    if($zoneName == "global"){
                        $objectsInMemory["any"]['address_groups_id'][$name]=$aglid;
                    }
                    $aglid++;
                }
            }


            foreach ($address as $child => $data) {
                $name = (string)$data->name;
                $name = str_replace('/', '-', $name);
                if (empty($name)) {
                    $name = (string)$data->{'address-name'};
                }
                $name_int = truncate_names(normalizeNames($name));

                if (isset($objectsInMemory[$zoneName]['address_groups_id'][$name])){
                    $currentLid=$objectsInMemory[$zoneName]['address_groups_id'][$name];
                }
                else{
                    $add_address_group[] = "('$aglid','$name','$name_int','$source','$vsys','$zoneName')";
                    $objectsInMemory[$zoneName]['address_groups_id'][$name]=$aglid;
                    if($zoneName == "global"){
                        $objectsInMemory["any"]['address_groups_id'][$name]=$aglid;
                    }
                    $currentLid=$aglid;
                    $aglid++;
                }

                if (isset($data->address)){
                    foreach ($data->address as $field => $value) {
                        $member = (string)$value->name;
                        $member = str_replace('/', '-', $member);

                        if (isset($objectsInMemory[$zoneName]['address'][$member])){
                            $member_lid=$objectsInMemory[$zoneName]['address'][$member];
                            $table_name="address";
                            $add_address_group_member[] = "('$currentLid','$member','$source','$vsys','$member_lid','$table_name')";
                        }
                        elseif (isset($objectsInMemory['global']['address'][$member])){
                            $member_lid=$objectsInMemory['global']['address'][$member];
                            $table_name="address";
                            $add_address_group_member[] = "('$currentLid','$member','$source','$vsys','$member_lid','$table_name')";
                        }
                        else{
                            print "Unable to find this Member Object (address): $member on a Group: $name".PHP_EOL;
                        }
                    }
                }

                if (isset($data->{'address-set'})){
                    foreach ($data->{'address-set'} as $field => $value) {
                        $member = (string)$value->name;
                        $member = str_replace('/', '-', $member);
                        if (isset($objectsInMemory[$zoneName]['address_groups_id'][$member])){
                            $member_lid=$objectsInMemory[$zoneName]['address_groups_id'][$member];
                            $table_name="address_groups_id";
                            $add_address_group_member[] = "('$currentLid','$member','$source','$vsys','$member_lid','$table_name')";
                        }
                        elseif (isset($objectsInMemory['global']['address_groups_id'][$member])){
                            $member_lid=$objectsInMemory['global']['address_groups_id'][$member];
                            $table_name="address_groups_id";
                            $add_address_group_member[] = "('$currentLid','$member','$source','$vsys','$member_lid','$table_name')";
                        }
                        else{
                            print "Unable to find this Member Object (Group): $member on a Group: $name".PHP_EOL;
                        }
                    }
                }
            }

            #MAP Zone with Interfaces
            $interfacesin = $data2->xpath("interfaces");
            $getInterface = array();
            $getinterfacesall = "";
            foreach ($interfacesin as $kkkey => $vvvalue) {
                $intName = (string)$vvvalue->name;
                // rename interface if needed
                if(str_contains($intName,"st0")) {
                    $intName = str_replace("st0", "tunnel", $intName);
                } elseif (str_contains($intName,"lo0")) {
                    $intName = str_replace("lo0", "loopback", $intName);
                }
                $exist = $projectdb->query("SELECT id FROM interfaces WHERE unitname='$intName' AND source='$source';");
                if ($exist->num_rows > 0) {
                    $projectdb->query("UPDATE interfaces SET zone='$zoneName' WHERE source='$source' AND unitname='$intName'");
                }
                $getInterface[] = $intName ; //(string)$vvvalue->name;
            }
            $getinterfacesall = implode(",", $getInterface);
            $zones[] = "('$source','$zoneName','$vsys','$type','$getinterfacesall','$template')";
        }
    }


    if ( (isset($add_address['v4'])) AND (count($add_address['v4']) > 0) ){
        $unique=array_unique($add_address['v4']);
        $out = implode(",", $unique);
        $projectdb->query("INSERT INTO address (id,name_ext,name,vsys,type,vtype,ipaddress,cidr,v4,source,description,zone) VALUES " . $out.";");
    }
    if ( (isset($add_address['v6'])) AND (count($add_address['v6']) > 0) ){
        $unique=array_unique($add_address['v6']);
        $out = implode(",", $unique);
        $projectdb->query("INSERT INTO address (id,name_ext,name,vsys,type,vtype,ipaddress,cidr,v6,source,description,zone) VALUES " . $out.";");
        $projectdb->query("UPDATE address set v4=0 WHERE v6=1;");
    }

    unset($add_address);

    if (count($add_address_group) > 0) {

        $uniq = array_unique($add_address_group);
        $out = implode(",", $uniq);
        $projectdb->query("INSERT INTO address_groups_id (id,name_ext,name,source,vsys,zone) VALUES ". $out .";");

        if (count($add_address_group_member)>0){
            $uniq = array_unique($add_address_group_member);
            $out = implode(",", $uniq);
            $projectdb->query("INSERT INTO address_groups (lid,member,source,vsys,member_lid,table_name) VALUES ". $out .";");
        }
    }

    if (count($zones) > 0) {
        $out = implode(",", $zones);
        $projectdb->query("INSERT INTO zones (source,name,vsys,type,interfaces,template) VALUES " . $out . ";");
    }
}

function add_junos_services($source,&$objectsInMemory,$multivsys) {
    global $projectdb;

    $exists = $projectdb->query("SELECT id FROM services WHERE source='$source' AND vsys='shared' AND name_ext IN ('junos-ftp','junos-xnm-clear-text','junos-sun-rpc-status-udp');");
    if ($exists->num_rows == 0) {
        // Add predefined services and services groups
        $vsys='vsys1';
        if($multivsys){
            $vsys='shared';
        }
        ServicesMapping::addPredefinedSrvAndSrvGroups($projectdb, "junos-srx", $source, $vsys);

        $array_tables = ['services', 'services_groups_id'];
        foreach ($array_tables as $table){
            $shared_services = $projectdb->query("SELECT id, name FROM ". $table . " where vsys='$vsys';");
            if($shared_services->num_rows>0) {
                while ($shared_services_data = $shared_services->fetch_assoc()) {
                    $id = $shared_services_data['id'];
                    $name = $shared_services_data['name'];
                    $objectsInMemory[$vsys][$table][$name] = $id;
                }
            }
        }



//        $add_srv = array();
//        $add_srv[] = "('$source','$vsys','junos-ftp','junos-ftp','21','tcp')";
//        $add_srv[] = "('$source','$vsys','junos-tftp','junos-tftp','69','udp')";
//        $add_srv[] = "('$source','$vsys','junos-rtsp','junos-rtsp','554','tcp')";
//        $add_srv[] = "('$source','$vsys','junos-netbios-session','junos-netbios-session','139','tcp')";
//        $add_srv[] = "('$source','$vsys','junos-ssh','junos-ssh','22','tcp')";
//        $add_srv[] = "('$source','$vsys','junos-telnet','junos-telnet','23','tcp')";
//        $add_srv[] = "('$source','$vsys','junos-smtp','junos-smtp','25','tcp')";
//        $add_srv[] = "('$source','$vsys','junos-tacacs','junos-tacacs','49','tcp')";
//        $add_srv[] = "('$source','$vsys','junos-tacacs-ds','junos-tacacs-ds','65','tcp')";
//        $add_srv[] = "('$source','$vsys','junos-dhcp-client','junos-dhcp-client','68','udp')";
//        $add_srv[] = "('$source','$vsys','junos-dhcp-server','junos-dhcp-server','67','udp')";
//        $add_srv[] = "('$source','$vsys','junos-bootpc','junos-bootpc','68','udp')";
//        $add_srv[] = "('$source','$vsys','junos-bootps','junos-bootps','67','udp')";
//        $add_srv[] = "('$source','$vsys','junos-finger','junos-finger','79','tcp')";
//        $add_srv[] = "('$source','$vsys','junos-http','junos-http','80','tcp')";
//        $add_srv[] = "('$source','$vsys','junos-https','junos-https','443','tcp')";
//        $add_srv[] = "('$source','$vsys','junos-pop3','junos-pop3','110','tcp')";
//        $add_srv[] = "('$source','$vsys','junos-ident','junos-ident','113','tcp')";
//        $add_srv[] = "('$source','$vsys','junos-nntp','junos-nntp','119','tcp')";
//        $add_srv[] = "('$source','$vsys','junos-ntp','junos-ntp','123','udp')";
//        $add_srv[] = "('$source','$vsys','junos-imap','junos-imap','143','tcp')";
//        $add_srv[] = "('$source','$vsys','junos-imaps','junos-imaps','993','tcp')";
//        $add_srv[] = "('$source','$vsys','junos-bgp','junos-bgp','179','tcp')";
//        $add_srv[] = "('$source','$vsys','junos-ldap','junos-ldap','389','tcp')";
//        $add_srv[] = "('$source','$vsys','junos-snpp','junos-snpp','444','tcp')";
//        $add_srv[] = "('$source','$vsys','junos-biff','junos-biff','512','udp')";
//        $add_srv[] = "('$source','$vsys','junos-who','junos-who','513','udp')";
//        $add_srv[] = "('$source','$vsys','junos-syslog','junos-syslog','514','udp')";
//        $add_srv[] = "('$source','$vsys','junos-printer','junos-printer','515','tcp')";
//        $add_srv[] = "('$source','$vsys','junos-rip','junos-rip','520','udp')";
//        $add_srv[] = "('$source','$vsys','junos-radius','junos-radius','1812','udp')";
//        $add_srv[] = "('$source','$vsys','junos-radacct','junos-radacct','1813','udp')";
//        $add_srv[] = "('$source','$vsys','junos-nfsd-tcp','junos-nfsd-tcp','2049','tcp')";
//        $add_srv[] = "('$source','$vsys','junos-nfsd-udp','junos-nfsd-udp','2049','udp')";
//        $add_srv[] = "('$source','$vsys','junos-cvspserver','junos-cvspserver','2401','tcp')";
//        $add_srv[] = "('$source','$vsys','junos-ldp-tcp','junos-ldp-tcp','646','tcp')";
//        $add_srv[] = "('$source','$vsys','junos-ldp-udp','junos-ldp-udp','646','udp')";
//        $add_srv[] = "('$source','$vsys','junos-xnm-ssl','junos-xnm-ssl','3220','tcp')";
//        $add_srv[] = "('$source','$vsys','junos-xnm-clear-text','junos-xnm-clear-text','3221','tcp')";
//        $add_srv[] = "('$source','$vsys','junos-ike','junos-ike','500','udp')";
//        $add_srv[] = "('$source','$vsys','junos-aol','junos-aol','5190-5193','tcp')";
//        $add_srv[] = "('$source','$vsys','junos-chargen','junos-chargen','19','udp')";
//        $add_srv[] = "('$source','$vsys','junos-dhcp-relay','junos-dhcp-relay','67','udp')";
//        $add_srv[] = "('$source','$vsys','junos-discard','junos-discard','9','udp')";
//        $add_srv[] = "('$source','$vsys','junos-dns-udp','junos-dns-udp','53','udp')";
//        $add_srv[] = "('$source','$vsys','junos-dns-tcp','junos-dns-tcp','53','tcp')";
//        $add_srv[] = "('$source','$vsys','junos-echo','junos-echo','7','udp')";
//        $add_srv[] = "('$source','$vsys','junos-gopher','junos-gopher','70','tcp')";
//        $add_srv[] = "('$source','$vsys','junos-gtp','junos-gtp','2123','udp')";
//        $add_srv[] = "('$source','$vsys','junos-gnutella','junos-gnutella','6346-6347','udp')";
//        $add_srv[] = "('$source','$vsys','junos-http-ext','junos-http-ext','7001','tcp')";
//        $add_srv[] = "('$source','$vsys','junos-internet-locator-service','junos-internet-locator-service','389','tcp')";
//        $add_srv[] = "('$source','$vsys','junos-ike-nat','junos-ike-nat','4500','udp')";
//        $add_srv[] = "('$source','$vsys','junos-irc','junos-irc','6660-6669','tcp')";
//        $add_srv[] = "('$source','$vsys','junos-l2tp','junos-l2tp','1701','udp')";
//        $add_srv[] = "('$source','$vsys','junos-lpr','junos-lpr','515','tcp')";
//        $add_srv[] = "('$source','$vsys','junos-mail','junos-mail','25','tcp')";
//        $add_srv[] = "('$source','$vsys','junos-h323','junos-h323','1720','tcp')";
//        $add_srv[] = "('$source','$vsys','junos-mgcp-ua','junos-mgcp-ua','2427','udp')";
//        $add_srv[] = "('$source','$vsys','junos-mgcp-ca','junos-mgcp-ca','2727','udp')";
//        $add_srv[] = "('$source','$vsys','junos-msn','junos-msn','1863','tcp')";
//        $add_srv[] = "('$source','$vsys','junos-ms-rpc-tcp','junos-ms-rpc-tcp','135','tcp')";
//        $add_srv[] = "('$source','$vsys','junos-ms-rpc-udp','junos-ms-rpc-udp','135','udp')";
//        $add_srv[] = "('$source','$vsys','junos-ms-sql','junos-ms-sql','1433','tcp')";
//        $add_srv[] = "('$source','$vsys','junos-nbname','junos-nbname','137','udp')";
//        $add_srv[] = "('$source','$vsys','junos-nbds','junos-nbds','138','udp')";
//        $add_srv[] = "('$source','$vsys','junos-nfs','junos-nfs','111','udp')";
//        $add_srv[] = "('$source','$vsys','junos-ns-global','junos-ns-global','15397','tcp')";
//        $add_srv[] = "('$source','$vsys','junos-ns-global-pro','junos-ns-global-pro','15397','tcp')";
//        $add_srv[] = "('$source','$vsys','junos-nsm','junos-nsm','69','udp')";
//        $add_srv[] = "('$source','$vsys','junos-pc-anywhere','junos-pc-anywhere','5632','udp')";
//        $add_srv[] = "('$source','$vsys','junos-pptp','junos-pptp','1723','tcp')";
//        $add_srv[] = "('$source','$vsys','junos-realaudio','junos-realaudio','554','tcp')";
//        $add_srv[] = "('$source','$vsys','junos-sccp','junos-sccp','2000','tcp')";
//        $add_srv[] = "('$source','$vsys','junos-sip','junos-sip','5060','udp')";
//        $add_srv[] = "('$source','$vsys','junos-rsh','junos-rsh','514','tcp')";
//        $add_srv[] = "('$source','$vsys','junos-smb','junos-smb','139','tcp')";
//        $add_srv[] = "('$source','$vsys','junos-sql-monitor','junos-sql-monitor','1434','udp')";
//        $add_srv[] = "('$source','$vsys','junos-sqlnet-v1','junos-sqlnet-v1','1525','tcp')";
//        $add_srv[] = "('$source','$vsys','junos-sqlnet-v2','junos-sqlnet-v2','1521','tcp')";
//        $add_srv[] = "('$source','$vsys','junos-sun-rpc-tcp','junos-sun-rpc-tcp','111','tcp')";
//        $add_srv[] = "('$source','$vsys','junos-sun-rpc-udp','junos-sun-rpc-udp','111','udp')";
//        $add_srv[] = "('$source','$vsys','junos-sun-rpc-portmap-tcp','junos-sun-rpc-portmap-tcp','100000','tcp')";
//        $add_srv[] = "('$source','$vsys','junos-sun-rpc-portmap-udp','junos-sun-rpc-portmap-udp','100000','udp')";
//        $add_srv[] = "('$source','$vsys','junos-sun-rpc-nfs-udp','junos-sun-rpc-nfs-udp','100003','udp')";
//        $add_srv[] = "('$source','$vsys','junos-sun-rpc-mountd-tcp','junos-sun-rpc-mountd-tcp','100005','tcp')";
//        $add_srv[] = "('$source','$vsys','junos-sun-rpc-mountd-udp','junos-sun-rpc-mountd-udp','100005','udp')";
//        $add_srv[] = "('$source','$vsys','junos-sun-rpc-ypbind-tcp','junos-sun-rpc-ypbind-tcp','100007','tcp')";
//        $add_srv[] = "('$source','$vsys','junos-sun-rpc-ypbind-udp','junos-sun-rpc-ypbind-udp','100007','udp')";
//        $add_srv[] = "('$source','$vsys','junos-sun-rpc-status-tcp','junos-sun-rpc-status-tcp','100024','tcp')";
//        $add_srv[] = "('$source','$vsys','junos-sun-rpc-status-udp','junos-sun-rpc-status-udp','100024','udp')";
//        $add_srv[] = "('$source','$vsys','junos-talk','junos-talk','517','udp')";
//        $add_srv[] = "('$source','$vsys','junos-ntalk','junos-ntalk','518','udp')";
//        $add_srv[] = "('$source','$vsys','junos-r2cp','junos-r2cp','28672','udp')";
//        $add_srv[] = "('$source','$vsys','junos-uucp','junos-uucp','540','udp')";
//        $add_srv[] = "('$source','$vsys','junos-vdo-live','junos-vdo-live','7000-7010','udp')";
//        $add_srv[] = "('$source','$vsys','junos-vnc','junos-vnc','5800','tcp')";
//        $add_srv[] = "('$source','$vsys','junos-wais','junos-wais','210','tcp')";
//        $add_srv[] = "('$source','$vsys','junos-whois','junos-whois','43','tcp')";
//        $add_srv[] = "('$source','$vsys','junos-winframe','junos-winframe','1494','tcp')";
//        $add_srv[] = "('$source','$vsys','junos-x-windows','junos-x-windows','6000-6063','tcp')";
//        $add_srv[] = "('$source','$vsys','junos-ymsg','junos-ymsg','5050','tcp')";
//        $add_srv[] = "('$source','$vsys','junos-wxcontrol','junos-wxcontrol','3578','tcp')";
//        $add_srv[] = "('$source','$vsys','junos-snmp-agentx','junos-snmp-agentx','705','tcp')";
//        $add_srv[] = "('$source','$vsys','junos-stun','junos-stun','3478-3479','udp')";
//        $add_srv[] = "('$source','$vsys','junos-persistent-nat','junos-persistent-nat','65535','255')";
//        $add_srv[] = "('$source','$vsys','junos-icmp-ping','junos-icmp-ping','','')";
//        $add_srv[] = "('$source','$vsys','junos-icmp-all','junos-icmp-all','','')";
//        $add_srv[] = "('$source','$vsys','junos-gre','junos-gre','','tcp')";
//        $add_srv[] = "('$source','$vsys','junos-tcp-any','junos-tcp-any','1-65535','tcp')";
//        $add_srv[] = "('$source','$vsys','junos-udp-any','junos-udp-any','1-65535','udp')";
//        $add_srv[] = "('$source','$vsys','junos-ping','junos-ping','','')";
//        $add_srv[] = "('$source','$vsys','junos-smb-session','junos-smb-session','','')";
//        $add_srv[] = "('$source','$vsys','junos-ms-rpc-wmic','junos-ms-rpc-wmic','','')";
//        $add_srv[] = "('$source','$vsys','junos-ms-rpc','junos-ms-rpc','','')";
//        $add_srv[] = "('$source','$vsys','junos-cifs','junos-cifs','','')";
//        $out = implode(",", $add_srv);
//        $projectdb->query("INSERT INTO services (source,vsys,name_ext,name,dport,protocol) VALUES " . $out . ";");
//        unset($add_srv);
    }
}

function get_Nat($configuration, $vsys, $source, $project,&$objectsInMemory) {
    global $projectdb;

    #Get Last lid from Profiles
    $getlastlid = $projectdb->query("SELECT max(id) as max FROM nat_rules;");
    if ($getlastlid->num_rows > 0) {
        $getLID1 = $getlastlid->fetch_assoc();
        $lid = intval($getLID1['max']) + 1;
    } else {
        $lid = 1;
    }

    $getlastlid = $projectdb->query("SELECT max(position) as max FROM nat_rules;");
    if ($getlastlid->num_rows > 0) {
        $getLID1 = $getlastlid->fetch_assoc();
        $position = intval($getLID1['max']) + 1;
    } else {
        $position = 1;
    }

    # Load all the Address by IP/cidr
    $getAddress=$projectdb->query("SELECT * FROM address WHERE source='$source';");
    if ($getAddress->num_rows>0){
        while($getAddressD=$getAddress->fetch_assoc()){
            $objectsInMemory[$getAddressD['vsys']]['address'][$getAddressD['ipaddress']][$getAddressD['cidr']]=array("id"=>$getAddressD['id'],"zone"=>$getAddressD['zone']);
            $objectsInMemory[$getAddressD['vsys']]['address'][$getAddressD['name_ext']]=array("id"=>$getAddressD['id'],"zone"=>$getAddressD['zone']);
        }
    }

    # Load all the Address Groups by vsys
    $getAddress=$projectdb->query("SELECT * FROM address_groups_id WHERE source='$source';");
    if ($getAddress->num_rows>0){
        while($getAddressD=$getAddress->fetch_assoc()){
            $objectsInMemory[$getAddressD['vsys']]['address_groups_id'][$getAddressD['name_ext']]=array("id"=>$getAddressD['id'],"zone"=>$getAddressD['zone']);
        }
    }

    # Generate IDs for Address
    $getMax=$projectdb->query("SELECT max(id) as max FROM address;");
    if ($getMax->num_rows==1){
        $getMaxData=$getMax->fetch_assoc();
        $alid=$getMaxData['max'] + 1;
    }

    $lastExistingAddress = $alid-1;

    $address = $configuration->xpath("/configuration/security/nat");
    $address2 = $configuration->xpath("/configuration/groups/security/nat");
    $address = array_merge($address, $address2);
    $add_nat_from=[];
    $add_nat_to=[];
    $add_nat_src=[];
    $add_nat_dst=[];
    $add_nat_rule=[];
    $xx=1;

    $disabledRules=array();
    $add_address=array();
    $add_address_pool = array();

    foreach ($address as $child => $data) {
        foreach($data->static as $key=>$data2){
            $to="";
            foreach ($data2->{'rule-set'} as $mkey=>$mvalue){
                $ruleSetNat=(string)$mvalue->name;
                if (isset($mvalue->from->zone)){
                    $to=(string)$mvalue->from->zone;
                }
                else{
                    $to="";
                }
                foreach ($mvalue->rule as $vvkey=>$vvalue){
                    unset($NatRuleName,$tp_sat_type,$tp_sat_address_type,$port_id,$port_table,$translated_port,$member_lid,$table_name);
                    if (isset($vvalue->attributes()->inactive)){$disabledRules[]=$lid;}
                    $NatRuleName=normalizeNames((string) $vvalue->name);
                    if ($NatRuleName==""){$NatRuleName="Rule ".$xx;$xx++;}
                    foreach ($vvalue->{'static-nat-rule-match'} as $mmkey=>$mmvalue){
                        # Needed?
                        $hasDport = false;
                        if ($mmvalue->{'destination-port'}){
                            $hasDport = true;
                            $dport="";
                            if ($mmvalue->{'destination-port'}->low){
                                $dport=$mmvalue->{'destination-port'}->low;
                            }
                            if ($mmvalue->{'destination-port'}->to->high){
                                if ($dport==""){
                                    $dport=$mmvalue->{'destination-port'}->to->high;
                                }
                                else{
                                    $dport=$dport."-".$mmvalue->{'destination-port'}->to->high;
                                }
                            }
                            if ($dport!=""){
                                $getPort=$projectdb->query("SELECT id FROM services WHERE source='$source' AND vsys='$vsys' AND dport='$dport' LIMIT 1;");
                                if ($getPort->num_rows==1){
                                    $getPortData=$getPort->fetch_assoc();
                                    $port_id=$getPortData['id'];
                                    $port_table="services";
                                }
                                else{
                                    $getSrv=$projectdb->query("SELECT id FROM services WHERE source='$source' AND vsys='$vsys' AND BINARY name='T$dport' LIMIT 1;");
                                    if ($getSrv->num_rows==1){
                                        $getSrvData=$getSrv->fetch_assoc();
                                        $port_id=$getSrvData['id'];
                                        $projectdb->query("UPDATE services SET dport='$dport', protocol='tcp' WHERE id='$port_id';");
                                        $port_table="services";
                                        add_log2('warning', 'Reading Nat Rules', 'Updated Service with dport ['.$dport.'] Object was defined without dport and protocol', $source, 'Updating with Protocol TCP', 'services', $port_id, 'services');
                                    }
                                    else{
                                        $projectdb->query("INSERT INTO services (source,vsys,name_ext,name,dport,protocol) VALUES ('$source','$vsys','T$dport','T$dport','$dport','tcp');");
                                        $port_id=$projectdb->insert_id;
                                        $port_table="services";
                                        add_log2('warning', 'Reading Nat Rules', 'Service with dport ['.$dport.'] Not found in the DB', $source, 'Creating with Protocol TCP', 'services', $port_id, 'services');
                                    }

                                }
                            }

                        }
                        else{
                            # How we disabled destination-port by now we have to devlar port_id and port_table
                            $port_id = "";
                            $port_table = "";
                        }


                        foreach($mmvalue->{'destination-address'} as $mmvalue_destination_address) {
                            {
                                $srcname = $mmvalue_destination_address->{'dst-addr'};
                                $split = explode("/", $srcname);
                                $ipaddress = $split[0];
                                $cidr = $split[1];
                                if ($srcname == "0.0.0.0/0") {
                                } else {
                                    if (isset($objectsInMemory[$vsys]['address'][$ipaddress][$cidr])) {
                                        $member_lid = $objectsInMemory[$vsys]['address'][$ipaddress][$cidr]['id'];
                                        $table_name = "address";
                                        $add_nat_translated_address[] = "('$source','$vsys','$lid','$member_lid','$table_name')";
                                        if ($to == "") {
                                            $to = $objectsInMemory[$vsys]['address'][$ipaddress][$cidr]['zone'];
                                        }
                                    } else {
                                        $srcNameParts = explode("/", $srcname);
                                        if (isset($srcNameParts[1])) {
                                            if ($srcNameParts[1] == '32' || $srcNameParts[1] == '128') {
                                                //No need to change it. let's leave it as a HW IP
                                                $srcname = str_replace("/", "-", $srcname);
                                                $srcname = "H-" . $srcname;
                                            } else {
                                                $srcname = str_replace("/", "-", $srcname);
                                                $srcname = "N-" . $srcname;
                                            }
                                        } else {
                                            $srcname = str_replace("/", "-", $srcname);
                                            $srcname = "H-" . $srcname;
                                        }
                                        $add_address[] = "('$alid','$source','$vsys','$srcname','$srcname',0,'$ipaddress','$cidr')";
                                        //$projectdb->query("INSERT INTO address (source,vsys,name_ext,name,dummy,ipaddress,cidr) VALUES ('$source','$vsys','$srcname','$srcname',0,'$ipaddress','$cidr');");
                                        $member_lid = $alid;
                                        $objectsInMemory[$vsys]['address'][$ipaddress][$cidr]['id'] = $alid;
                                        $alid++;
                                        $table_name = "address";
                                        $add_nat_translated_address[] = "('$source','$vsys','$lid','$member_lid','$table_name')";
                                    }
                                }

                                if ($hasDport) {  //This is a Destination for a MIP that translates port. In such case, we have two NAT rules, and the second includes the incoming DNAT with port translation. Therefore $lid+1
                                    $nextLid = $lid + 1;
                                    $add_nat_dst[] = "('$source','$vsys','$nextLid','$member_lid','$table_name')";
                                }

                            }
                        }
                        foreach($mmvalue->{'destination-address-name'} as $destination_address_name){
                            //$srcname=(string) $mmvalue->{'destination-address-name'}->{'dst-addr-name'};
                            $srcname = $destination_address_name->{'dst-addr-name'};
                            $srcname = str_replace('/', '-', $srcname);
                            if (isset($objectsInMemory[$vsys]['address'][$srcname])){
                                $member_lid=$objectsInMemory[$vsys]['address'][$srcname]['id'];
                                $table_name="address";
                                $add_nat_translated_address[]="('$source','$vsys','$lid','$member_lid','$table_name')";
                                if ($to==""){$to=$objectsInMemory[$vsys]['address'][$srcname]['zone'];}
                            }
                            elseif(isset($objectsInMemory[$vsys]['address_groups_id'][$srcname])){
                                $member_lid=$objectsInMemory[$vsys]['address_groups_id'][$srcname]['id'];
                                $table_name="address_groups_id";
                                $add_nat_translated_address[]="('$source','$vsys','$lid','$member_lid','$table_name')";
                                if ($to==""){$to=$objectsInMemory[$vsys]['address_groups_id'][$srcname]['zone'];}
                            }
                            else{
                                add_log2('warning', 'Reading Nat Rules', 'Destination Address ['.$srcname.'] Not found in the DB', $source, 'Create the Object and add it to Rule ['.$lid.']', 'policy', $lid, 'nat_rules');
                            }

                            if($hasDport){  //This is a Destination for a MIP that translates port. In such case, we have two NAT rules, and the second includes the incoming DNAT with port translation. Therefore $lid+1
                                $nextLid = $lid+1;
                                $add_nat_dst[] = "('$source','$vsys','$nextLid','$member_lid','$table_name')";
                            }
                        }

                        foreach($mmvalue->{'source-address'} as $mmvalue_source_address){
                            // looks like in newer version the source is stored on tag source-address instead of src-addr, let's check it
                            if(isset($mmvalue_source_address->{'src-addr'})){
                                $srcname=$mmvalue_source_address->{'src-addr'};
                            } else {
                                $srcname = $mmvalue_source_address;
                            }
                            $split=explode("/",$srcname);
                            $ipaddress=$split[0];
                            $cidr=$split[1];
                            if ($srcname=="0.0.0.0/0"){}
                            else{
                                if (isset($objectsInMemory[$vsys]['address'][$ipaddress][$cidr])){
                                    $member_lid=$objectsInMemory[$vsys]['address'][$ipaddress][$cidr]['id'];
                                    $table_name="address";
                                    $add_nat_translated_address[]="('$source','$vsys','$lid','$member_lid','$table_name')";
                                    if ($to==""){$to=$objectsInMemory[$vsys]['address'][$ipaddress][$cidr]['zone'];}
                                }
                                else{
                                    $srcNameParts = explode("/", $srcname);
                                    if(isset($srcNameParts[1])){
                                        if($srcNameParts[1] == '32' || $srcNameParts[1] == '128'){
                                            //No need to change it. let's leave it as a HW IP
                                            $srcname=str_replace("/","-",$srcname);
                                            $srcname = "H-".$srcname;
                                        }
                                        else{
                                            $srcname=str_replace("/","-",$srcname);
                                            $srcname = "N-".$srcname;
                                        }
                                    }
                                    else{
                                        $srcname=str_replace("/","-",$srcname);
                                        $srcname = "H-".$srcname;
                                    }
                                    $add_address[]="('$alid','$source','$vsys','$srcname','$srcname',0,'$ipaddress','$cidr')";
                                    //$projectdb->query("INSERT INTO address (source,vsys,name_ext,name,dummy,ipaddress,cidr) VALUES ('$source','$vsys','$srcname','$srcname',0,'$ipaddress','$cidr');");
                                    $member_lid=$alid;
                                    $objectsInMemory[$vsys]['address'][$ipaddress][$cidr]['id']=$alid;
                                    $alid++;
                                    $table_name="address";
                                    $add_nat_translated_address[]="('$source','$vsys','$lid','$member_lid','$table_name')";
                                }
                            }

                            if($hasDport){  //This is a Destination for a MIP that translates port. In such case, we have two NAT rules, and the second includes the incoming DNAT with port translation. Therefore $lid+1
                                $nextLid = $lid+1;
                                $add_nat_dst[] = "('$source','$vsys','$nextLid','$member_lid','$table_name')";
                            }

                        }
                        foreach($mmvalue->{'source-address-name'} as $srcname){
                            $srcname = str_replace('/', '-', $srcname);
                            if (isset($objectsInMemory[$vsys]['address'][$srcname])){
                                $member_lid=$objectsInMemory[$vsys]['address'][$srcname]['id'];
                                $table_name="address";
                                $add_nat_dst[]="('$source','$vsys','$lid','$member_lid','$table_name')";
                                if ($to==""){$to=$objectsInMemory[$vsys]['address'][$srcname]['zone'];}
                            }
                            elseif(isset($objectsInMemory[$vsys]['address_groups_id'][$srcname])){
                                $member_lid=$objectsInMemory[$vsys]['address_groups_id'][$srcname]['id'];
                                $table_name="address_groups_id";
                                $add_nat_dst[]="('$source','$vsys','$lid','$member_lid','$table_name')";
                                if ($to==""){$to=$objectsInMemory[$vsys]['address_groups_id'][$srcname]['zone'];}
                            }
                            else{
                                add_log2('warning', 'Reading Nat Rules', 'Destination Address ['.$srcname.'] Not found in the DB', $source, 'Create the Object and add it to Rule ['.$lid.']', 'policy', $lid, 'nat_rules');
                            }

                            if($hasDport){  //This is a Destination for a MIP that translates port. In such case, we have two NAT rules, and the second includes the incoming DNAT with port translation. Therefore $lid+1
                                $nextLid = $lid+1;
                                $add_nat_dst[] = "('$source','$vsys','$nextLid','$member_lid','$table_name')";
                            }
                        }
                    }



                    if ($vvalue->then->{'static-nat'}->prefix->{'addr-prefix'}){
                        $srcname=(string)$vvalue->then->{'static-nat'}->prefix->{'addr-prefix'};
                        $split=explode("/",$srcname);
                        $ipaddress=$split[0];
                        $cidr=$split[1];
                        if ($srcname=="0.0.0.0/0"){}
                        else{

                            if (isset($objectsInMemory[$vsys]['address'][$ipaddress][$cidr])){
                                $member_lid=$objectsInMemory[$vsys]['address'][$ipaddress][$cidr]['id'];
                                $table_name="address";
                                $add_nat_src[]="('$source','$vsys','$lid','$member_lid','$table_name')";
                            }
                            else{
                                $srcname=str_replace("/","-",$srcname);
                                $add_address[]="('$alid','$source','$vsys','$srcname','$srcname',1,'$ipaddress','$cidr')";
                                //$projectdb->query("INSERT INTO address (source,vsys,name_ext,name,dummy,ipaddress,cidr) VALUES ('$source','$vsys','$srcname','$srcname',0,'$ipaddress','$cidr');");
                                $member_lid=$alid;
                                $objectsInMemory[$vsys]['address'][$ipaddress][$cidr]['id']=$alid;
                                $alid++;
                                $table_name="address";
                                $add_nat_src[]="('$source','$vsys','$lid','$member_lid','$table_name')";
                            }

                            if($hasDport){
                                $tp_dat_address_lid = $member_lid;
                                $tp_dat_address_table = $table_name;
                            }
                            else{
                                $tp_dat_address_lid = '';
                                $tp_dat_address_table ='';
                            }
                        }
                        $tp_sat_type="static-ip";
                        $tp_sat_address_type="translated-address";

                        $DATPort="";
                        if($vvalue->then->{'static-nat'}->prefix->{'mapped-port'}){
                            $DATPortElement = $vvalue->then->{'static-nat'}->prefix->{'mapped-port'};
                            if ($DATPortElement->low){
                                $DATPort=$DATPortElement->low;
                            }
                            if ($DATPortElement->to->high){
                                if ($DATPort==""){
                                    $DATPort=$DATPortElement->to->high;
                                }
                                else{
                                    $DATPort=$DATPort."-".$DATPortElement->to->high;
                                }
                            }
                        }
                        if($hasDport) {
                            //This is the outside SourceNat
                            $add_nat_rule[] = "('$lid','$position','$source','$vsys','$to','$NatRuleName','$tp_sat_type','$tp_sat_address_type','','',0,'','','',0)";
                            $lid++;
                            //This is the incoming DNat with port
                            //id,position,source,vsys,op_zone_to,name,tp_sat_type,tp_sat_address_type,op_service_lid,op_service_table,is_dat, tp_dat_port, tp_dat_address_lid, tp_dat_address_table, tp_sat_bidirectional
                            $add_nat_rule[] = "('$lid+1','$position','$source','$vsys','$to','$NatRuleName-2','$tp_sat_type','$tp_sat_address_type','$port_id','$port_table',1,'$DATPort','$tp_dat_address_lid','$tp_dat_address_table',0)";

                        }
                        else{
                            $add_nat_rule[] = "('$lid','$position','$source','$vsys','$to','$NatRuleName','$tp_sat_type','$tp_sat_address_type','$port_id','$port_table',0,'','','',1)";
                        }
                        $lid++;
                        $position++;
                    }
                    elseif ($vvalue->then->{'static-nat'}->{'prefix-name'}->{'addr-prefix-name'})
                    {
                        $srcname=(string) $vvalue->then->{'static-nat'}->{'prefix-name'}->{'addr-prefix-name'};
                        $srcname = str_replace('/', '-', $srcname);
                        if (isset($objectsInMemory[$vsys]['address'][$srcname])){
                            $member_lid=$objectsInMemory[$vsys]['address'][$srcname]['id'];
                            $table_name="address";
                            $add_nat_src[]="('$source','$vsys','$lid','$member_lid','$table_name')";

                        }
                        elseif(isset($objectsInMemory[$vsys]['address_groups_id'][$srcname])){
                            $member_lid=$objectsInMemory[$vsys]['address_groups_id'][$srcname]['id'];
                            $table_name="address_groups_id";
                            $add_nat_src[]="('$source','$vsys','$lid','$member_lid','$table_name')";

                        }
                        else{
                            add_log2('warning', 'Reading Nat Rules', 'Source Address ['.$srcname.'] Not found in the DB', $source, 'Create the Object and add it to Rule ['.$lid.']', 'policy', $lid, 'nat_rules');
                        }

//                        $getDup=$projectdb->query("SELECT id FROM address WHERE source='$source' AND vsys='$vsys' AND name_ext='$srcname' LIMIT 1;");
//                        if ($getDup->num_rows==1){
//                            $getDupData=$getDup->fetch_assoc();
//                            $member_lid=$getDupData['id'];
//                            $table_name="address";
//                            $add_nat_src[]="('$source','$vsys','$lid','$member_lid','$table_name')";
//                        }
//                        else{
//                            $getDup=$projectdb->query("SELECT id FROM address_groups_id WHERE source='$source' AND vsys='$vsys' AND name_ext='$srcname' LIMIT 1;");
//                            if ($getDup->num_rows==1){
//                                $getDupData=$getDup->fetch_assoc();
//                                $member_lid=$getDupData['id'];
//                                $table_name="address_groups_id";
//                                $add_nat_src[]="('$source','$vsys','$lid','$member_lid','$table_name')";
//                            }
//                            else{
//                                add_log2('warning', 'Reading Nat Rules', 'Source Address ['.$srcname.'] Not found in the DB', $source, 'Create the Object and add it to Rule ['.$lid.']', 'policy', $lid, 'nat_rules');
//                            }
//                        }
                        $tp_sat_type="static-ip";
                        $tp_sat_address_type="translated-address";
                        $add_nat_rule[]="('$lid','$position','$source','$vsys','$to','$NatRuleName','$tp_sat_type','$tp_sat_address_type','$port_id','$port_table',0,'','','',1)";
                        $lid++;
                        $position++;
                    }

                }
            }
        }

        foreach($data->source as $key => $data2) {
            foreach($data2->pool as $mkey=>$mvalue){
                $poolName=(string)$mvalue->name;
                $poolNamePan=normalizeNames($poolName);
                $pool_start=(string) $mvalue->address->name;
                if (isset($mvalue->address->to)){
                    $pool_end=$mvalue->address->to->ipaddr;
                    $ipaddress0=$pool_start."-".$pool_end;
                    $ipaddress=str_replace("/32","",$ipaddress0);
                    $add_address_pool[$poolNamePan]="('$alid','$source','$vsys','ip-range','$poolName','$poolNamePan','$ipaddress','')";
                    $objectsInMemory[$vsys]['address'][$poolName]['id']=$alid;
                    $alid++;
                    //$projectdb->query("INSERT INTO address (source,vsys,type,name_ext,name,ipaddress) VALUES ('$source','$vsys','ip-range','$poolName','$poolNamePan','$ipaddress')");
                }
                else{
                    $ipaddress=str_replace("/32","",$pool_start);
                    $add_address_pool[$poolNamePan]="('$alid','$source','$vsys','ip-netmask','$poolName','$poolNamePan','$ipaddress','32')";
                    $objectsInMemory[$vsys]['address'][$poolName]['id']=$alid;
                    $alid++;
                    //$projectdb->query("INSERT INTO address (source,vsys,type,name_ext,name,ipaddress,cidr) VALUES ('$source','$vsys','ip-netmask','$poolName','$poolNamePan','$ipaddress','32')");
                }
            }

            if (count($add_address_pool)>0){
                $projectdb->query("INSERT INTO address (id,source,vsys,type,name_ext,name,ipaddress,cidr) VALUES ". implode(",",$add_address_pool).";");
                unset($add_address_pool);
            }
            /*  A Rule-set will contain a set of:
             *  - source (from) zones; one or more
             *  - destination (to) zones; zero, one or more than one
             *  NOTE: PaloAlto only allow one destination (to) zone so we will need to clone rules for each destination (to) zone.
             *  - rules; one or more than one containing address, nat information, ...
            */

            // foreach rule-set
            foreach($data2->{'rule-set'} as $mkey=>$mvalue){
                $ruleTag=normalizeNames((string)$mvalue->name);
                $from_zones = [];
                $to_zones = [];

                // get all source (from) zones to create them
                foreach($mvalue->from->zone as $from_zone){
                    $from_zones[]=$from_zone;
                }

                // get all destination (to) zones to iterate over them and clone the rules
                if(count($mvalue->to->zone)>0) {
                    foreach ($mvalue->to->zone as $to_zone) {
                        $to_zones[] = $to_zone;
                    }
                }else{
                    // to zone can be not defined, so default value is empty string
                    $to_zones[] = "";
                }

                // foreach rule
                foreach($mvalue->rule as $kkey => $vvalue){
                    unset($NatRuleName,$tp_sat_type,$tp_sat_address_type,$port_id,$port_table,$translated_port,$member_lid,$table_name);
                    $suffix_duplicated_name = 0; // suffix for cloned rules with different destination (to) zones.
                    // and foreach zone
                    foreach ( $to_zones as $to_zone) {
                        $suffix_duplicated_name++;
                        $port_id = "";
                        $port_table = "";
                        if (isset($vvalue->attributes()->inactive)) {$disabledRules[]=$lid;}
                        $NatRuleName = normalizeNames($vvalue->name);
                        if ($NatRuleName == "") {
                            $NatRuleName = "Rule " . $xx;
                            $xx++;
                        }else if( count($to_zones) > 1) {
                            // for this rule-set there are more one destination (to) zone defined
                            $NatRuleName.= "_". $suffix_duplicated_name;
                            add_log2('warning', 'Reading Nat Rules', 'Cloned NAT rule as it has more than 1 destination Zones.', $source, 'Review the proper zone to be used in Rule [' . $lid . ']', 'rules', $lid, 'nat_rules');
                        }

                        foreach ($vvalue->{'src-nat-rule-match'} as $mmkey => $mmvalue) {
//                        if ($from!=""){
//                           $add_nat_from[]="('$source','$vsys','$from','$lid')";
//                        }

                            foreach ($from_zones as $from_zone) {
                                $add_nat_from[] = "('$source','$vsys','$from_zone','$lid')";
                            }

                            if ($mmvalue->{'source-address'}) {
                                foreach ($mmvalue->{'source-address'} as $avalue) {
                                    $srcname = $avalue;
                                    $split = explode("/", $avalue);
                                    $ipaddress = $split[0];
                                    $cidr = $split[1];
                                    if ($srcname == "0.0.0.0/0") {
                                    } else {
                                        $getDup = $projectdb->query("SELECT id FROM address WHERE source='$source' AND vsys='$vsys' AND ipaddress='$ipaddress' AND cidr='$cidr' LIMIT 1;");
                                        if ($getDup->num_rows == 1) {
                                            $getDupData = $getDup->fetch_assoc();
                                            $member_lid = $getDupData['id'];
                                            $table_name = "address";
                                            $add_nat_src[] = "('$source','$vsys','$lid','$member_lid','$table_name')";

                                        } else {
                                            $add_address[] = "('$alid','$source','$vsys','$srcname','$srcname',1,'$ipaddress','$cidr')";
                                            //$projectdb->query("INSERT INTO address (source,vsys,name_ext,name,dummy,ipaddress,cidr) VALUES ('$source','$vsys','$srcname','$srcname',1,'$ipaddress','$cidr');");
                                            //$member_lid=$projectdb->insert_id;
                                            $member_lid = $alid;
                                            $objectsInMemory[$vsys]['address'][$ipaddress][$cidr]['id'] = $alid;
                                            $alid++;
                                            $table_name = "address";
                                            $add_nat_src[] = "('$source','$vsys','$lid','$member_lid','$table_name')";

                                        }
                                    }
                                }

                            }

                            if ($mmvalue->{'source-address-name'}) {
                                foreach ($mmvalue->{'source-address-name'} as $avalue) {
                                    $srcname = str_replace("/", "-", $avalue);
                                    $getDup = $projectdb->query("SELECT id FROM address WHERE source='$source' AND vsys='$vsys' AND name_ext='$srcname' LIMIT 1;");
                                    if ($getDup->num_rows == 1) {
                                        $getDupData = $getDup->fetch_assoc();
                                        $member_lid = $getDupData['id'];
                                        $table_name = "address";
                                        $add_nat_src[]="('$source','$vsys','$lid','$member_lid','$table_name')";

                                    } else {
                                        $getDup = $projectdb->query("SELECT id FROM address_groups_id WHERE source='$source' AND vsys='$vsys' AND name_ext='$srcname' LIMIT 1;");
                                        if ($getDup->num_rows == 1) {
                                            $getDupData = $getDup->fetch_assoc();
                                            $member_lid = $getDupData['id'];
                                            $table_name = "address_groups_id";
                                            $add_nat_src[]="('$source','$vsys','$lid','$member_lid','$table_name')";

                                        } else {
                                            add_log2('warning', 'Reading Nat Rules', 'Source Address [' . $srcname . '] Not found in the DB', $source, 'Create the Object and add it to Rule [' . $lid . ']', 'policy', $lid, 'nat_rules');
                                        }
                                    }
                                }

                            }

                            if ($mmvalue->{'destination-address'}) {
                                foreach ($mmvalue->{'destination-address'} as $avalue) {
                                    $srcname = $avalue;
                                    $split = explode("/", $avalue);
                                    $ipaddress = $split[0];
                                    $cidr = $split[1];
                                    if ($srcname == "0.0.0.0/0") {
                                    } else {
                                        $getDup = $projectdb->query("SELECT id FROM address WHERE source='$source' AND vsys='$vsys' AND ipaddress='$ipaddress' AND cidr='$cidr' LIMIT 1;");
                                        if ($getDup->num_rows == 1) {
                                            $getDupData = $getDup->fetch_assoc();
                                            $member_lid = $getDupData['id'];
                                            $table_name = "address";
                                            $add_nat_dst[]="('$source','$vsys','$lid','$member_lid','$table_name')";

                                        } else {
                                            $add_address[] = "('$alid','$source','$vsys','$srcname','$srcname',1,'$ipaddress','$cidr')";
                                            //$projectdb->query("INSERT INTO address (source,vsys,name_ext,name,dummy,ipaddress,cidr) VALUES ('$source','$vsys','$srcname','$srcname',1,'$ipaddress','$cidr');");
                                            //$member_lid=$projectdb->insert_id;
                                            $member_lid = $alid;
                                            $objectsInMemory[$vsys]['address'][$ipaddress][$cidr]['id'] = $alid;
                                            $alid++;
                                            $table_name = "address";
                                            $add_nat_dst[]="('$source','$vsys','$lid','$member_lid','$table_name')";

                                        }
                                    }

                                }


                            }

                            if ($mmvalue->{'destination-address-name'}) {
                                foreach ($mmvalue->{'destination-address-name'} as $avalue) {
                                    $srcname = $avalue;
                                    $srcname = str_replace('/', '-', $srcname);
                                    $getDup = $projectdb->query("SELECT id FROM address WHERE source='$source' AND vsys='$vsys' AND name_ext='$srcname' LIMIT 1;");
                                    if ($getDup->num_rows == 1) {
                                        $getDupData = $getDup->fetch_assoc();
                                        $member_lid = $getDupData['id'];
                                        $table_name = "address";
                                        $add_nat_dst[]="('$source','$vsys','$lid','$member_lid','$table_name')";

                                    } else {
                                        $getDup = $projectdb->query("SELECT id FROM address_groups_id WHERE source='$source' AND vsys='$vsys' AND name_ext='$srcname' LIMIT 1;");
                                        if ($getDup->num_rows == 1) {
                                            $getDupData = $getDup->fetch_assoc();
                                            $member_lid = $getDupData['id'];
                                            $table_name = "address_groups_id";
                                            $add_nat_dst[]="('$source','$vsys','$lid','$member_lid','$table_name')";

                                        } else {
                                            add_log2('warning', 'Reading Nat Rules', 'Destination Address [' . $srcname . '] Not found in the DB', $source, 'Create the Object and add it to Rule [' . $lid . ']', 'policy', $lid, 'nat_rules');
                                        }
                                    }
                                }

                            }

                            if ($mmvalue->{'destination-port'}) {
                                $dport = "";
                                if ($mmvalue->{'destination-port'}->low) {
                                    $dport = $mmvalue->{'destination-port'}->low;
                                }
                                if ($mmvalue->{'destination-port'}->to->high) {
                                    if ($dport == "") {
                                        $dport = $mmvalue->{'destination-port'}->to->high;
                                    } else {
                                        $dport = $dport . "-" . $mmvalue->{'destination-port'}->to->high;
                                    }
                                }
                                if ($dport != "") {
                                    $getPort = $projectdb->query("SELECT id FROM services WHERE source='$source' AND vsys='$vsys' AND dport='$dport' LIMIT 1;");
                                    if ($getPort->num_rows == 1) {
                                        $getPortData = $getPort->fetch_assoc();
                                        $port_id = $getPortData['id'];
                                        $port_table = "services";
                                    } else {
                                        $getSrv = $projectdb->query("SELECT id FROM services WHERE source='$source' AND vsys='$vsys' AND BINARY name_ext='T$dport' LIMIT 1;");
                                        if ($getSrv->num_rows == 1) {
                                            $getSrvData = $getSrv->fetch_assoc();
                                            $port_id = $getSrvData['id'];
                                            $projectdb->query("UPDATE services SET dport='$dport', protocol='tcp' WHERE id='$port_id';");
                                            $port_table = "services";
                                            add_log2('warning', 'Reading Nat Rules', 'Updated Service with dport [' . $dport . '] Object was defined without dport and protocol', $source, 'Updating with Protocol TCP', 'services', $port_id, 'services');
                                        } else {
                                            $projectdb->query("INSERT INTO services (source,vsys,name_ext,name,dport,protocol) VALUES ('$source','$vsys','T$dport','T$dport','$dport','tcp');");
                                            $port_id = $projectdb->insert_id;
                                            $port_table = "services";
                                            add_log2('warning', 'Reading Nat Rules', 'Service with dport [' . $dport . '] Not found in the DB', $source, 'Creating with Protocol TCP', 'services', $port_id, 'services');
                                        }

                                    }
                                }

                            }

                        }
                        if (isset($vvalue->then->{'source-nat'}->pool)) {
                            $srcname = $vvalue->then->{'source-nat'}->pool->{'pool-name'};
                            $getDup = $projectdb->query("SELECT id FROM address WHERE source='$source' AND vsys='$vsys' AND name_ext='$srcname' LIMIT 1;");
                            if ($getDup->num_rows == 1) {
                                $getDupData = $getDup->fetch_assoc();
                                $member_lid = $getDupData['id'];
                                $table_name = "address";

                                $add_nat_translated_address[]="('$source','$vsys','$lid','$member_lid','$table_name')";

                            } else {
                                $getDup = $projectdb->query("SELECT id FROM address_groups_id WHERE source='$source' AND vsys='$vsys' AND name_ext='$srcname' LIMIT 1;");
                                if ($getDup->num_rows == 1) {
                                    $getDupData = $getDup->fetch_assoc();
                                    $member_lid = $getDupData['id'];
                                    $table_name = "address_groups_id";
                                    $add_nat_translated_address[]="('$source','$vsys','$lid','$member_lid','$table_name')";

                                } else {
                                    add_log2('warning', 'Reading Nat Rules', 'Source Nat Pool [' . $srcname . '] Not found in the DB', $source, 'Create the Object and add it to Rule [' . $lid . ']', 'policy', $lid, 'nat_rules');
                                }
                            }
                            $tp_sat_type = "dynamic-ip-and-port";
                            $tp_sat_address_type = "translated-address";
                            $add_nat_rule[] = "('$lid','$position','$source','$vsys','$to_zone','$NatRuleName','$tp_sat_type','$tp_sat_address_type','$port_id','$port_table',0,'','','',0)";
                            $lid++;
                            $position++;

                        } elseif (isset($vvalue->then->{'source-nat'}->interface)) {

                            $getInt = $projectdb->query("SELECT unitipaddress FROM interfaces WHERE zone='$to_zone' AND source='$source' LIMIT 1;");
                            if ($getInt->num_rows == 1) {
                                $getIntData = $getInt->fetch_assoc();
                                $interface_all = explode("/", $getIntData['unitipaddress']);
                                $interface_ip = $interface_all[0];
                                $interface_cidr = 32;
                                $add_address[] = "('$alid','$source','$vsys','$interface_ip','$interface_ip',1,'$interface_ip','$interface_cidr')";
                                //$projectdb->query("INSERT INTO address (source,vsys,name_ext,name,ipaddress,cidr,dummy) VALUES ('$source','$vsys','$interface_ip','$interface_ip','$interface_ip','$interface_cidr','1')");
                                //$member_lid=$projectdb->insert_id;
                                $member_lid = $alid;
                                $objectsInMemory[$vsys]['address'][$ipaddress][$cidr]['id'] = $alid;
                                $alid++;
                                $add_nat_translated_address[] = "('$source','$vsys','$lid','$member_lid','address')";
                            }
                            $tp_sat_type = "dynamic-ip-and-port";
                            $tp_sat_address_type = "translated-address";
                            $add_nat_rule[] = "('$lid','$position','$source','$vsys','$to_zone','$NatRuleName','$tp_sat_type','$tp_sat_address_type','$port_id','$port_table',0,'','','',0)";
                            $lid++;
                            $position++;

                        } elseif (isset($vvalue->then->{'source-nat'}->off)) {

                            $tp_sat_type = "";
                            $tp_sat_address_type = "";
                            $add_nat_rule[] = "('$lid','$position','$source','$vsys','$to_zone','$NatRuleName','$tp_sat_type','$tp_sat_address_type','$port_id','$port_table',0,'','','',0)";
                            $lid++;
                            $position++;

                        }

                    }
                }
                unset($from_zones);

            }
        }

        foreach($data->destination as $key=>$data2){
            foreach($data2->pool as $mkey=>$mvalue){
                $poolName=(string)$mvalue->name;
                $poolNamePan=normalizeNames($poolName);
                if (isset($mvalue->address)){
                    $ipaddress0=$mvalue->address->ipaddr;
                    $ipaddress=str_replace("/32","",$ipaddress0);
                    $ipaddress_split=explode("/",$ipaddress);
                    if (isset($ipaddress_split[1])){$cidr=$ipaddress_split[1];}else{$cidr="32";}

                    if (isset($mvalue->address->port)){
                        $myport=$mvalue->address->port;
                    }
                    else{
                        $myport="";
                    }

                    $add_address_pool[$poolNamePan]="('$alid','$source','$vsys','ip-netmask','$poolName','$poolNamePan','$ipaddress_split[0]','$myport','$cidr')";
                    $objectsInMemory[$vsys]['address'][$poolName]=array("id"=>$alid);
                    $alid++;


                    //$projectdb->query("INSERT INTO address (source,vsys,type,name_ext,name,ipaddress,vtype,cidr) VALUES ('$source','$vsys','ip-netmask','$poolName','$poolNamePan','$ipaddress_split[0]','$myport','$cidr')");
                }
            }

            if (count($add_address_pool)>0){
                $projectdb->query("INSERT INTO address (id,source,vsys,type,name_ext,name,ipaddress,vtype,cidr) VALUES ". implode(",",$add_address_pool).";");
                unset($add_address_pool);
            }

            foreach($data2->{'rule-set'} as $mkey=>$mvalue){
                $ruleTag=normalizeNames((string)$mvalue->name);
                $froms = array();
                foreach ($mvalue->from->zone as $zoneElement){
                    $froms[] = $zoneElement;
                }

                $from=$mvalue->from->zone;
                $to="";
                foreach ($mvalue->rule as $kkey=>$vvalue){
                    unset($NatRuleName,$tp_sat_type,$tp_sat_address_type,$port_id,$port_table,$translated_port,$member_lid,$table_name);
                    if (isset($vvalue->attributes()->inactive)){$disabledRules[]=$lid;}
                    $NatRuleName=normalizeNames($vvalue->name);

                    if ($NatRuleName==""){$NatRuleName="Rule ".$xx;$xx++;}
                    foreach ($vvalue->{'dest-nat-rule-match'} as $mmkey=>$mmvalue){
                        //if ($from!=""){
                        //    $add_nat_from[]="('$source','$vsys','$from','$lid')";
                        //}

                        foreach ($froms as $fromZone){
                            $add_nat_from[]="('$source','$vsys','$fromZone','$lid')";
                        }

                        if ($mmvalue->{'source-address'}){
                            foreach ($mmvalue->{'source-address'} as $avalue){
                                //$srcname=$avalue->{'src-addr'};
                                $srcname=$avalue;
                                $split=explode("/",$avalue);
                                $ipaddress=$split[0];
                                $cidr=$split[1];
                                if ($srcname=="0.0.0.0/0"){}
                                else{
                                    $getDup=$projectdb->query("SELECT id FROM address WHERE source='$source' AND vsys='$vsys' AND ipaddress='$ipaddress' AND cidr='$cidr' LIMIT 1;");
                                    if ($getDup->num_rows==1){
                                        $getDupData=$getDup->fetch_assoc();
                                        $member_lid=$getDupData['id'];
                                        $table_name="address";
                                        $add_nat_src[]="('$source','$vsys','$lid','$member_lid','$table_name')";
                                    }
                                    else{
                                        $add_address[]="('$alid','$source','$vsys','$srcname','$srcname',1,'$ipaddress','$cidr')";
                                        //$projectdb->query("INSERT INTO address (source,vsys,name_ext,name,dummy,ipaddress,cidr) VALUES ('$source','$vsys','$srcname','$srcname',1,'$ipaddress','$cidr');");
                                        //$member_lid=$projectdb->insert_id;
                                        $member_lid=$alid;
                                        $objectsInMemory[$vsys]['address'][$ipaddress][$cidr]['id']=$alid;
                                        $alid++;
                                        $table_name="address";
                                        $add_nat_src[]="('$source','$vsys','$lid','$member_lid','$table_name')";
                                    }
                                }
                            }

                        }

                        if ($mmvalue->{'source-address-name'}){
                            foreach ($mmvalue->{'source-address-name'} as $avalue){
                                //$srcname=$avalue->{'src-addr-name'};
                                $srcname=  str_replace("/","-",$avalue);
                                $getDup=$projectdb->query("SELECT id FROM address WHERE source='$source' AND vsys='$vsys' AND name_ext='$srcname' LIMIT 1;");
                                if ($getDup->num_rows==1){
                                    $getDupData=$getDup->fetch_assoc();
                                    $member_lid=$getDupData['id'];
                                    $table_name="address";
                                    $add_nat_src[]="('$source','$vsys','$lid','$member_lid','$table_name')";
                                }
                                else{
                                    $getDup=$projectdb->query("SELECT id FROM address_groups_id WHERE source='$source' AND vsys='$vsys' AND name_ext='$srcname' LIMIT 1;");
                                    if ($getDup->num_rows==1){
                                        $getDupData=$getDup->fetch_assoc();
                                        $member_lid=$getDupData['id'];
                                        $table_name="address_groups_id";
                                        $add_nat_src[]="('$source','$vsys','$lid','$member_lid','$table_name')";
                                    }
                                    else{
                                        add_log2('warning', 'Reading Nat Rules', 'Source Address ['.$srcname.'] Not found in the DB', $source, 'Create the Object and add it to Rule ['.$lid.']', 'policy', $lid, 'nat_rules');
                                    }
                                }
                            }

                        }

                        if ($mmvalue->{'destination-address'}){
                            foreach ($mmvalue->{'destination-address'} as $avalue){
                                $srcname=$avalue->{'dst-addr'};
                                $split=explode("/",$avalue->{'dst-addr'});
                                $ipaddress=$split[0];
                                $cidr=$split[1];
                                if ($srcname=="0.0.0.0/0"){}
                                else{
                                    $getDup=$projectdb->query("SELECT id FROM address WHERE source='$source' AND vsys='$vsys' AND ipaddress='$ipaddress' AND cidr='$cidr' LIMIT 1;");
                                    if ($getDup->num_rows==1){
                                        $getDupData=$getDup->fetch_assoc();
                                        $member_lid=$getDupData['id'];
                                        $table_name="address";
                                        $to=search_zone_address_one($member_lid,$vsys,$source,$table_name);
                                        $add_nat_dst[]="('$source','$vsys','$lid','$member_lid','$table_name')";
                                    }
                                    else{
                                        $add_address[]="('$alid','$source','$vsys','$srcname','$srcname',1,'$ipaddress','$cidr')";
                                        //$projectdb->query("INSERT INTO address (source,vsys,name_ext,name,dummy,ipaddress,cidr) VALUES ('$source','$vsys','$srcname','$srcname',1,'$ipaddress','$cidr');");
                                        //$member_lid=$projectdb->insert_id;
                                        $member_lid=$alid;
                                        $objectsInMemory[$vsys]['address'][$ipaddress][$cidr]['id']=$alid;
                                        $alid++;
                                        $table_name="address";
                                        $to=search_zone_address_one($member_lid,$vsys,$source,$table_name);
                                        $add_nat_dst[]="('$source','$vsys','$lid','$member_lid','$table_name')";
                                    }
                                }

                            }
                        }

                        if ($mmvalue->{'destination-address-name'}){
                            foreach ($mmvalue->{'destination-address-name'} as $avalue){
                                $srcname=$avalue->{'dst-addr-name'};
                                $srcname = str_replace('/', '-', $srcname);
                                $getDup=$projectdb->query("SELECT id FROM address WHERE source='$source' AND vsys='$vsys' AND name_ext='$srcname' LIMIT 1;");
                                if ($getDup->num_rows==1){
                                    $getDupData=$getDup->fetch_assoc();
                                    $member_lid=$getDupData['id'];
                                    $table_name="address";
                                    $to=search_zone_address_one($member_lid,$vsys,$source,$table_name);
                                    $add_nat_dst[]="('$source','$vsys','$lid','$member_lid','$table_name')";
                                }
                                else{
                                    $getDup=$projectdb->query("SELECT id FROM address_groups_id WHERE source='$source' AND vsys='$vsys' AND name_ext='$srcname' LIMIT 1;");
                                    if ($getDup->num_rows==1){
                                        $getDupData=$getDup->fetch_assoc();
                                        $member_lid=$getDupData['id'];
                                        $table_name="address_groups_id";
                                        $to=search_zone_address_one($member_lid,$vsys,$source,$table_name);
                                        $add_nat_dst[]="('$source','$vsys','$lid','$member_lid','$table_name')";
                                    }
                                    else{
                                        add_log2('warning', 'Reading Nat Rules', 'Destination Address ['.$srcname.'] Not found in the DB', $source, 'Create the Object and add it to Rule ['.$lid.']', 'policy', $lid, 'nat_rules');
                                    }
                                }
                            }

                        }

                        if ($mmvalue->{'destination-port'}){
                            $dport="";

                            # Consider protocol still not implemented

                            if ($mmvalue->{'destination-port'}->{'dst-port'}){
                                $dport=$mmvalue->{'destination-port'}->{'dst-port'};
                            }
                            if ($dport!=""){
                                $getPort=$projectdb->query("SELECT id FROM services WHERE source='$source' AND vsys='$vsys' AND dport='$dport' LIMIT 1;");
                                if ($getPort->num_rows==1){
                                    $getPortData=$getPort->fetch_assoc();
                                    $port_id=$getPortData['id'];
                                    $port_table="services";
                                }
                                else{
                                    $getSrv=$projectdb->query("SELECT id FROM services WHERE source='$source' AND vsys='$vsys' AND BINARY name_ext='T$dport' LIMIT 1;");
                                    if ($getSrv->num_rows==1){
                                        $getSrvData=$getSrv->fetch_assoc();
                                        $port_id=$getSrvData['id'];
                                        $projectdb->query("UPDATE services SET dport='$dport', protocol='tcp' WHERE id='$port_id';");
                                        $port_table="services";
                                        add_log2('warning', 'Reading Nat Rules', 'Updated Service with dport ['.$dport.'] Object was defined without dport and protocol', $source, 'Updating with Protocol TCP', 'services', $port_id, 'services');
                                    }
                                    else{
                                        $projectdb->query("INSERT INTO services (source,vsys,name_ext,name,dport,protocol) VALUES ('$source','$vsys','T$dport','T$dport','$dport','tcp');");
                                        $port_id=$projectdb->insert_id;
                                        $port_table="services";
                                        add_log2('warning', 'Reading Nat Rules', 'Service with dport ['.$dport.'] Not found in the DB', $source, 'Creating with Protocol TCP', 'services', $port_id, 'services');
                                    }

                                }
                            }
                        }else{
                            $port_id="";
                            $port_table="";
                        }

                    }
                    if (isset($vvalue->then->{'destination-nat'}->pool)){
                        $srcname=$vvalue->then->{'destination-nat'}->pool->{'pool-name'};
                        $getDup=$projectdb->query("SELECT id,vtype FROM address WHERE source='$source' AND vsys='$vsys' AND name_ext='$srcname' LIMIT 1;");
                        $translated_port="";
                        if ($getDup->num_rows==1){
                            $getDupData=$getDup->fetch_assoc();
                            $member_lid=$getDupData['id'];
                            $myport=$getDupData['vtype'];
                            $table_name="address";
                            if ($myport!=""){
                                if ($myport>0){
                                    $translated_port=$myport;
                                }
                                else{
                                    $translated_port="";
                                }
                            }
                            else{
                                $translated_port="";
                            }
                        }
                        else{
                            $getDup=$projectdb->query("SELECT id FROM address_groups_id WHERE source='$source' AND vsys='$vsys' AND name_ext='$srcname' LIMIT 1;");
                            if ($getDup->num_rows==1){
                                $getDupData=$getDup->fetch_assoc();
                                $member_lid=$getDupData['id'];
                                $table_name="address_groups_id";

                            }
                            else{
                                add_log2('warning', 'Reading Nat Rules', 'Destination Nat Pool ['.$srcname.'] Not found in the DB', $source, 'Create the Object and add it to Rule ['.$lid.']', 'policy', $lid, 'nat_rules');
                            }
                        }
                        $tp_sat_type="";
                        $tp_sat_address_type="";
                        $add_nat_rule[]="('$lid','$position','$source','$vsys','$to','$NatRuleName','$tp_sat_type','$tp_sat_address_type','$port_id','$port_table','1','$translated_port','$member_lid','$table_name',0)";
                        $lid++;
                        $position++;
                    }

                }
            }
        }


    }

    if (count($add_nat_rule)>0){
        if (count($add_address)>0){
            $query = "INSERT INTO address (id,source,vsys,name_ext,name,dummy,ipaddress,cidr) VALUES ".implode(",",$add_address).";";
//            echo $query.PHP_EOL;
            $projectdb->query($query);
        }
        if ($add_nat_rule!=""){
            $projectdb->query("INSERT INTO nat_rules (id,position,source,vsys,op_zone_to,name,tp_sat_type,tp_sat_address_type,op_service_lid,op_service_table,is_dat,tp_dat_port,tp_dat_address_lid,tp_dat_address_table,tp_sat_bidirectional) "
                . "VALUES ".implode(",",$add_nat_rule).";");
            $add_nat_rule="";
            if (count($add_nat_from)>0){
                $projectdb->query("INSERT INTO nat_rules_from (source,vsys,name,rule_lid) VALUES ".implode(",",$add_nat_from).";");
                $add_nat_from=array();
            }
            if (count($add_nat_src)>0){
                $projectdb->query("INSERT INTO nat_rules_src (source,vsys,rule_lid,member_lid,table_name) VALUES ".implode(",",$add_nat_src).";");
                $add_nat_src="";
            }
            if (count($add_nat_dst)>0){
                $projectdb->query("INSERT INTO nat_rules_dst (source,vsys,rule_lid,member_lid,table_name) VALUES ".implode(",",$add_nat_dst).";");
                $add_nat_dst="";
            }
            if (count($add_nat_translated_address)>0){
                $projectdb->query("INSERT INTO nat_rules_translated_address (source,vsys,rule_lid,member_lid,table_name) VALUES ". implode(",",$add_nat_translated_address).";");
                $add_nat_translated_address="";
            }
            # Update the disabled Rules
            if (count($disabledRules)>0){
                $projectdb->query("UPDATE nat_rules SET disabled='1' WHERE id IN (".implode(",",$disabledRules).");");
            }
        }
        //print_r($add_nat_dst);
    }


}

function set_Zones_Nat_srx($source, $vsys, $vr){
    global $projectdb;

    $ipMapping = getIPtoZoneRouteMapping($vsys, $source, $vr);

    //$ids_rules = getNatIdsBySourceVsys($source, $vsys);
    $ids_rules = getIdsBySourceVsys("nat_rules", $source, $vsys);
    // if vsys has NAT rules
    if(count($ids_rules)>0){
        //Zones TO
        $to_zones = array();
        $getDST = $projectdb->query("SELECT rule_lid,member_lid,table_name FROM nat_rules_dst WHERE rule_lid IN (".implode(',', $ids_rules).");");
        if ($getDST->num_rows > 0) {
            while ($getDSTData = $getDST->fetch_assoc()) {
                $member_lid = $getDSTData['member_lid'];
                $table_name = $getDSTData['table_name'];
                $rule_lid = $getDSTData['rule_lid'];

                # Check if its IPV4
                if ($table_name=="address"){
                    $getcheck=$projectdb->query("SELECT id FROM address WHERE id='$member_lid' AND v6=0;");
                    if ($getcheck->num_rows==0){
                        continue;
                    }
                }

                $negate_source=0;

                $zones = getAutoZone($ipMapping['ipv4'], $member_lid, $table_name, $negate_source);
                foreach($zones as $zone){
                    $to_zones[$rule_lid][]=$zone;
                }
            }

            if(count($to_zones)>0){
                foreach($to_zones as $key=>$zones){
                    $unique = array_unique($zones);
                    $all_zones = implode(",",$unique);
                    $query="UPDATE nat_rules SET op_zone_to = '$all_zones' WHERE id ='$key';";
                    $projectdb->query($query);
                }
            }
        }
    }
}

/***
 * Very limited Sec Rule correction based on NAT. Objects need to be the same!
 * @param $config_path
 * @param $source
 * @param $vsys
 */
function fix_destination_nat($config_path, $source, $vsys) {
    global $projectdb;

    $getDNAT = $projectdb->query("SELECT id,tp_dat_address_lid,tp_dat_address_table FROM nat_rules WHERE is_dat=1 AND source='$source' AND vsys='$vsys' AND tp_dat_address_table!='';");
    if ($getDNAT->num_rows > 0) {

        while ($data = $getDNAT->fetch_assoc()) {
            $zoneFROM = "";
            $rule_lid = $data['id'];
            $tp_dat_address_lid = $data['tp_dat_address_lid'];
            $tp_dat_address_table = $data['tp_dat_address_table'];
            #get Address name
            $getname = $projectdb->query("SELECT name_ext FROM $tp_dat_address_table WHERE id='$tp_dat_address_lid'");
            $getnameData = $getname->fetch_assoc();
            $datName = $getnameData['name_ext'];
            #Get Source Zone from Nat Rule
            $getFROM = $projectdb->query("SELECT name FROM nat_rules_from WHERE rule_lid='$rule_lid' ;");
            if ($getFROM->num_rows == 1) {
                $dataFrom = $getFROM->fetch_assoc();
                $zoneFROM = $dataFrom['name'];
            }
            #Get Destination from OP
            $getDST = $projectdb->query("SELECT member_lid,table_name FROM nat_rules_dst WHERE rule_lid='$rule_lid' ;");
            if ($getDST->num_rows == 1) {
                $data2 = $getDST->fetch_assoc();
                $dst_member_lid = $data2['member_lid'];
                $dst_table_name = $data2['table_name'];
                #get Address name
                $getname = $projectdb->query("SELECT name_ext FROM $dst_table_name WHERE id='$dst_member_lid'");
                $getnameData = $getname->fetch_assoc();
                $dstName = $getnameData['name_ext'];
            }

            $getSecurityDST = $projectdb->query("SELECT rule_lid FROM security_rules_dst WHERE member_lid='$tp_dat_address_lid' AND table_name='$tp_dat_address_table';");
            if ($getSecurityDST->num_rows > 0) {
                while ($data4 = $getSecurityDST->fetch_assoc()) {
                    $security_rule = $data4['rule_lid'];
                    #Check the ZONE, has to be the same from ZoneFROM
                    $getSecurityZone = $projectdb->query("SELECT name FROM security_rules_from WHERE rule_lid='$security_rule';");
                    if ($getSecurityZone->num_rows == 1) {
                        $data5 = $getSecurityZone->fetch_assoc();
                        $security_from = $data5['name'];
                        if ($security_from == $zoneFROM) {
                            $projectdb->query("UPDATE security_rules_dst SET table_name='$dst_table_name', member_lid='$dst_member_lid' WHERE rule_lid='$security_rule' AND member_lid='$tp_dat_address_lid' AND table_name='$tp_dat_address_table';");
                            //$projectdb->query("UPDATE security_rules SET blocked=1 WHERE id='$security_rule';");
                            add_log2('warning', 'Fixing Destination Nats', 'Security RuleID [' . $security_rule . '] has been modified by Nat RuleID [' . $rule_lid . '], Replaced Destination Address old[' . $datName . '] by new[' . $dstName . ']', $source, 'Check it manually', 'rules', $security_rule, 'security_rules');
                        }
                    } else {
                        #No source ZONE maybe is ANY :-)
                        $exist = $projectdb->query("SELECT id FROM security_rules_dst WHERE table_name='$tp_dat_address_table' ANd member_lid='$tp_dat_address_lid' AND rule_lid='$security_rule';");
                        if ($exist->num_rows == 1) {
                            //$projectdb->query("UPDATE security_rules SET blocked=1 WHERE id='$security_rule';");
                            $projectdb->query("UPDATE security_rules_dst SET table_name='$dst_table_name', member_lid='$dst_member_lid' WHERE rule_lid='$security_rule' AND member_lid='$tp_dat_address_lid' AND table_name='$tp_dat_address_table';");
                        } else {
                            //$projectdb->query("UPDATE security_rules SET blocked=1 WHERE id='$security_rule';");
                            $projectdb->query("INSERT INTO security_rules_dst (rule_lid,member_lid,table_name,source,vsys) VALUES ('$security_rule','$dst_member_lid','$dst_table_name','$source','$vsys');");
                        }
                        add_log2('warning', 'Fixing Destination Nats', 'Security RuleID [' . $security_rule . '] has been modified by Nat RuleID [' . $rule_lid . '], Replaced Destination Address old[' . $datName . '] by new[' . $dstName . ']', $source, 'Check it manually', 'rules', $security_rule, 'security_rules');
                    }
                }
            }
        }
    }

    # Change rules TO where static-ip nat has the TP -source equal as a security rule destination
    $getStatic=$projectdb->query("SELECT id,op_zone_to FROM nat_rules WHERE tp_sat_type='static-ip' AND source='$source' AND vsys='$vsys';");
    if ($getStatic->num_rows>0){
        while ($getStaticData=$getStatic->fetch_assoc()){
            $nat_lid=$getStaticData['id'];
            #get TO Zone
            $getZoneTo=$getStaticData['op_zone_to'];

            $getTP=$projectdb->query("SELECT member_lid,table_name FROM nat_rules_src WHERE rule_lid='$nat_lid' LIMIT 1;");
            if ($getTP->num_rows==1){
                while ($getTPData=$getTP->fetch_assoc()){
                    $ori_member_lid=$getTPData['member_lid'];
                    $ori_table_name=$getTPData['table_name'];
                    $getOriName=$projectdb->query("SELECT name FROM $ori_table_name WHERE id='$ori_member_lid';");
                    if ($getOriName->num_rows==1){
                        $getOriNameData=$getOriName->fetch_assoc();
                        $datName=$getOriNameData['name'];
                    }
                    # Read the Translated packet
                    $getStaticObj=$projectdb->query("SELECT member_lid,table_name FROM nat_rules_translated_address WHERE rule_lid='$nat_lid' LIMIT 1;");
                    if ($getStaticObj->num_rows==1){
                        $getStaticObjData=$getStaticObj->fetch_assoc();
                        $trans_member_lid=$getStaticObjData['member_lid'];
                        $trans_table_name=$getStaticObjData['table_name'];
                        $getOriName=$projectdb->query("SELECT name FROM $trans_table_name WHERE id='$trans_member_lid';");
                        if ($getOriName->num_rows==1){
                            $getOriNameData=$getOriName->fetch_assoc();
                            $dstName=$getOriNameData['name'];
                        }
                        #Exact object Match, future check if its inside
                        $getRulesDst=$projectdb->query("SELECT rule_lid FROM security_rules_dst WHERE member_lid='$ori_member_lid' AND table_name='$ori_table_name';");
                        if ($getRulesDst->num_rows>0){
                            while ($getRulesDstData=$getRulesDst->fetch_assoc()){
                                $rule_lid=$getRulesDstData['rule_lid'];
                                $getZoneDst=$projectdb->query("SELECT id,name FROM security_rules_from WHERE rule_lid='$rule_lid' LIMIT 1;");
                                if ($getZoneDst->num_rows==1){
                                    $getZoneDstData=$getZoneDst->fetch_assoc();
                                    $zoneid=$getZoneDstData['id'];
                                    $zonename=$getZoneDstData['name'];
                                    if ($getZoneTo!=$zonename){}
                                    else{
                                        #Update Nat Rule FROM with the TO from the Security Rule
                                        $getZoneRuleTo=$projectdb->query("SELECT id,name FROM security_rules_to WHERE rule_lid='$rule_lid' LIMIT 1;");
                                        if ($getZoneRuleTo->num_rows==1){
                                            $getZoneRuleToData=$getZoneRuleTo->fetch_assoc();
                                            $getZoneRuleToFinal=$getZoneRuleToData['name'];
                                            $projectdb->query("DELETE FROM nat_rules_from WHERE rule_lid='$nat_lid';");
                                            $projectdb->query("INSERT INTO nat_rules_from (source,vsys,rule_lid,name) VALUES ('$source','$vsys','$nat_lid','$getZoneRuleToFinal');");
                                        }
                                        $projectdb->query("UPDATE security_rules_dst SET table_name='$trans_table_name', member_lid='$trans_member_lid' WHERE rule_lid='$rule_lid' AND member_lid='$ori_member_lid' AND table_name='$ori_table_name';");
                                        //$projectdb->query("UPDATE security_rules SET blocked=1 WHERE id='$rule_lid';");
                                        add_log2('warning', 'Fixing Destination Nats', 'Security RuleID [' . $rule_lid . '] has been modified by Nat RuleID [' . $nat_lid . '], Replaced Destination Address old[' . $datName . '] by new[' . $dstName . ']', $source, 'Check it manually', 'rules', $rule_lid, 'security_rules');
                                    }
                                }
                            }
                        }
                        # Case Ori object is on a Group and the Group is used as a DST in the rules
                    }
                }
            }
        }
    }

    # CLEAN DUPLICATED ENTRIES
    $projectdb->query("DELETE from security_rules_dst where id not in ( SELECT * from (select max(id) from security_rules_dst WHERE source='$source' group by rule_lid,member_lid,table_name) as t1) AND source='$source';");
}

/**
 * This method looks for dual NATs. The process is the following.
 *   For each Source NAT, checks where there is a Destination NAT that would have been applied for the same connection and updates the Destination NAT information to complement the
 *   Source NAT.
 *   Source and Destination NAT can be combined when:
 *     - FROM Zone in Source NAT is within FROM Zones in Destination NAT
 *     - Source in Source NAT is within Sources in Destination NAT
 *     - Destination in Source NAT is within the Translated destinations in Destination NAT
 *     - Service in Source NAT is within the Translated port (if defined) in the Destination NAT
 *     - Service in Source NAT is within the Service (if Translated Port is not defined) in the Destination NAT
 *
 *   Notice that a Destination NAT may apply to multiple Source NAT, therefore we cannot delete the Destination NATs. However, destination NATs are defined under Source NAT, so this
 *   does not imply issues.
 *
 * @global type $projectdb
 * @param type $source
 * @param type $vsys
 */
function consolidate_dual_NATs($source, $vsys,$filename,$jobid,$project){
    global $projectdb;

    $nats_src = array();
    $nats_dst = array();
    $myMembersMap=array();

    $getAllNats=$projectdb->query("SELECT id,is_dat, op_service_lid, op_service_table, tp_dat_address_lid, tp_dat_address_table, tp_dat_port FROM nat_rules WHERE source='$source' AND vsys='$vsys';");
    if ($getAllNats->num_rows>0){
        $NatID=array();
        $myMembersMap=array();
        while($getAllNatsData=$getAllNats->fetch_assoc()){
            $NatID[]=$getAllNatsData['id'];
            $myMembersMap[$getAllNatsData['id']]=[
                "is_dat"                =>$getAllNatsData['is_dat'],
                "op_service_lid"        =>$getAllNatsData['op_service_lid'],
                "op_service_table"      =>$getAllNatsData['op_service_table'],
                "tp_dat_address_lid"    =>$getAllNatsData['tp_dat_address_lid'],
                "tp_dat_address_table"  =>$getAllNatsData['tp_dat_address_table'],
                "tp_dat_port"           =>$getAllNatsData['tp_dat_port'],
                "src"                   =>array(),
                "dst"                   =>array()
            ];
        }
        # Create an Array with all the member_lids and table_names
        $getMems=$projectdb->query("SELECT rule_lid,member_lid,table_name FROM nat_rules_src WHERE rule_lid IN (".implode(",",$NatID).");");
        if ($getMems->num_rows>0){
            while($getMemsData=$getMems->fetch_assoc()){
                $myMembersMap[$getMemsData['rule_lid']]['src'][]=array("member_lid"=>$getMemsData['member_lid'],"table_name"=>$getMemsData['table_name']);
            }
        }
        $getMems=$projectdb->query("SELECT rule_lid,member_lid,table_name FROM nat_rules_dst WHERE rule_lid IN (".implode(",",$NatID).");");
        if ($getMems->num_rows>0){
            while($getMemsData=$getMems->fetch_assoc()){
                $myMembersMap[$getMemsData['rule_lid']]['dst'][]=array("member_lid"=>$getMemsData['member_lid'],"table_name"=>$getMemsData['table_name']);
            }
        }
    }


    foreach($myMembersMap as $rule=>$ruleDataArray){
        $tmp_natRule = new SRXNatRule($rule, $ruleDataArray['is_dat']);

        foreach($ruleDataArray['src'] as $ruleSRCArray){
            $member_lid = $ruleSRCArray['member_lid'];
            $table_name = $ruleSRCArray['table_name'];
            $sourceObject = new MemberObject($member_lid,$table_name);
            $tmp_natRule->addSource($sourceObject);
        }

        if($tmp_natRule->is_dat == '0'){   //This is a source NAT
            //Destination

            foreach($ruleDataArray['dst'] as $ruleSRCArray){
                $member_lid = $ruleSRCArray['member_lid'];
                $table_name = $ruleSRCArray['table_name'];
                $destinationObject = new MemberObject($member_lid,$table_name);
                $tmp_natRule->addDestinationOrig($destinationObject);
            }

            //Service
            $op_service_lid    = $ruleDataArray['op_service_lid'];
            $op_service_table  = $ruleDataArray['op_service_table'];
            if(isset($op_service_table) && !is_null($op_service_table) && $op_service_table!=''){
                $serviceObject = new MemberObject($op_service_lid,$op_service_table);
                $tmp_natRule->addService($serviceObject);
            }

            $nats_src[] = $tmp_natRule;

        }
        elseif($tmp_natRule->is_dat == '1'){  //This is a destination NAT
            //Destination
            $member_lid = $ruleDataArray['tp_dat_address_lid'];
            $table_name = $ruleDataArray['tp_dat_address_table'];
            $destinationObject = new MemberObject($member_lid,$table_name);
            $tmp_natRule->addDestinationNat($destinationObject);

            //Service
            $op_service_port = $ruleDataArray['tp_dat_port'];
            if($op_service_port!=0){
                $serviceObject = new MemberObject('dummy','services',$op_service_port,'');
                $tmp_natRule->addService($serviceObject);
            }
            else{
                $op_service_lid    = $ruleDataArray['op_service_lid'];
                $op_service_table  = $ruleDataArray['op_service_table'];
                if(isset($op_service_table) && !is_null($op_service_table) && $op_service_table!=''){
                    $serviceObject = new MemberObject($op_service_lid,$op_service_table);
                    $tmp_natRule->addService($serviceObject);
                }
            }

            $nats_dst[] = $tmp_natRule;
        }
        else{
            //TODO: Maybe for future options
        }
        unset($tmp_natRule);

    }


//    //Collecting information from the NAT rules to perform matchings
//    $getNatRules=$projectdb->query("SELECT id, is_dat, op_service_lid, op_service_table, tp_dat_address_lid, tp_dat_address_table, tp_dat_port FROM nat_rules WHERE source='$source' AND vsys='$vsys';");
//    while ($natRule=$getNatRules->fetch_assoc()){
//        $tmp_natRule = new NatRule($natRule['id'], $natRule['is_dat']);
//
//        //Source
//        $getSources = $projectdb->query("SELECT member_lid, table_name FROM nat_rules_src WHERE rule_lid ='".$tmp_natRule->rulelid."' ;");
//        while($sourceNAT = $getSources->fetch_assoc()){
//            $member_lid = $sourceNAT['member_lid'];
//            $table_name = $sourceNAT['table_name'];
//            $sourceObject = new MemberObject($member_lid,$table_name);
//            $tmp_natRule->addSource($sourceObject);
//        }
//
//        if($tmp_natRule->is_dat == '0'){   //This is a source NAT
//            //Destination
//            $getDestinations = $projectdb->query("SELECT member_lid, table_name FROM nat_rules_dst WHERE rule_lid ='".$tmp_natRule->rulelid."' ;");
//            while($destinationNAT = $getDestinations->fetch_assoc()){
//                $member_lid = $destinationNAT['member_lid'];
//                $table_name = $destinationNAT['table_name'];
//                $destinationObject = new MemberObject($member_lid,$table_name);
//                $tmp_natRule->addDestinationOrig($destinationObject);
//            }
//
//            //Service
//            $op_service_lid    = $natRule['op_service_lid'];
//            $op_service_table  = $natRule['op_service_table'];
//            if(isset($op_service_table) && !is_null($op_service_table) && $op_service_table!=''){
//                $serviceObject = new MemberObject($op_service_lid,$op_service_table);
//                $tmp_natRule->addService($serviceObject);
//            }
//
//            $nats_src[] = $tmp_natRule;
//
//        }
//        elseif($tmp_natRule->is_dat == '1'){  //This is a destination NAT
//            //Destination
//            $member_lid = $natRule['tp_dat_address_lid'];
//            $table_name = $natRule['tp_dat_address_table'];
//            $destinationObject = new MemberObject($member_lid,$table_name);
//            $tmp_natRule->addDestinationNat($destinationObject);
//
//            //Service
//            $op_service_port = $natRule['tp_dat_port'];
//            if($op_service_port!=0){
//                $serviceObject = new MemberObject('dummy','services',$op_service_port,'');
//                $tmp_natRule->addService($serviceObject);
//            }
//            else{
//                $op_service_lid    = $natRule['op_service_lid'];
//                $op_service_table  = $natRule['op_service_table'];
//                if(isset($op_service_table) && !is_null($op_service_table) && $op_service_table!=''){
//                    $serviceObject = new MemberObject($op_service_lid,$op_service_table);
//                    $tmp_natRule->addService($serviceObject);
//                }
//            }
//
//            $nats_dst[] = $tmp_natRule;
//        }
//        else{
//            //TODO: Maybe for future options
//        }
//        unset($tmp_natRule);
//    }
    //Transforming ANY addresses into 0.0.0.0/0. Necessary for the isAinB method
    /**
     * @var $nat_src SRXNatRule
     */
    $anyAddress = new MemberObject('ANY','address','0.0.0.0','0');
    $anyService = new MemberObject('ANY','services','0-65535','');

    foreach($nats_src as $nat_src){
        if (count($nat_src->source)==0){
            $nat_src->addSource($anyAddress);
        }
        else{
            foreach ($nat_src->source as $member){
                if(!isset($member->value) || !isset($member->cidr)){
                    $query ="SELECT id, ipaddress, cidr FROM address WHERE id=$member->name AND source='$source' AND vsys='$vsys';";
                    $getMember = $projectdb->query($query);
                    if($getMember->num_rows == 1){
                        $row=$getMember->fetch_assoc();
                        $member->cidr=$row['cidr'];
                        $member->value=$row['ipaddress'];
                    }
                }
            }
        }

        if (count($nat_src->destination_orig)==0){
            $nat_src->addDestinationOrig($anyAddress);
        }
        else{
            foreach ($nat_src->destination_orig as $member){
                if(!isset($member->value) || !isset($member->cidr)){
                    $query ="SELECT id, ipaddress, cidr FROM address WHERE id=$member->name AND source='$source' AND vsys='$vsys';";
                    $getMember = $projectdb->query($query);
                    if($getMember->num_rows == 1){
                        $row=$getMember->fetch_assoc();
                        $member->cidr=$row['cidr'];
                        $member->value=$row['ipaddress'];
                    }
                }
            }
        }


        if (count($nat_src->service)==0){
            $nat_src->addService($anyService);
        }
        else{
            foreach ($nat_src->service as $service) {
                if (!isset($service->value) || !isset($service->cidr)) {
                    $query = "SELECT id, dport, protocol FROM services WHERE id=$service->name AND source='$source' AND vsys='$vsys';";
                    $getService = $projectdb->query($query);
                    if ($getService->num_rows == 1) {
                        $row = $getService->fetch_assoc();
                        $service->value = $row['dport'];
                        $service->cidr = $row['protocol'];
                    }
                }
            }
        }

    }

    foreach($nats_dst as $nat_dst){
        if (count($nat_dst->source)==0){
            $nat_dst->addSource($anyAddress);
        }
        else{
            foreach ($nat_dst->source as $member){
                if(!isset($member->value) || !isset($member->cidr)){
                    $query ="SELECT id, ipaddress, cidr FROM address WHERE id=$member->name AND source='$source' AND vsys='$vsys';";
                    $getMember = $projectdb->query($query);
                    if($getMember->num_rows == 1){
                        $row=$getMember->fetch_assoc();
                        $member->cidr=$row['cidr'];
                        $member->value=$row['ipaddress'];
                    }
                }
            }
        }

        if (count($nat_dst->destination_nat)==0){
            $nat_dst->addDestinationNat($anyAddress);
        }
        else{
            foreach ($nat_dst->destination_nat as $member){
                if(!isset($member->value) || !isset($member->cidr)){
                    $query ="SELECT id, ipaddress, cidr FROM address WHERE id=$member->name AND source='$source' AND vsys='$vsys';";
                    $getMember = $projectdb->query($query);
                    if($getMember->num_rows == 1){
                        $row=$getMember->fetch_assoc();
                        $member->cidr=$row['cidr'];
                        $member->value=$row['ipaddress'];
                    }
                }
            }
        }

        if (count($nat_dst->service)==0){
            $nat_dst->addService($anyService);
        }
        else{
            foreach ($nat_dst->service as $service) {
                if (!isset($service->value) || !isset($service->cidr)) {
                    $query = "SELECT id, dport, protocol FROM services WHERE id=$service->name AND source='$source' AND vsys='$vsys';";
                    $getService = $projectdb->query($query);
                    if ($getService->num_rows == 1) {
                        $row = $getService->fetch_assoc();
                        $service->value = $row['dport'];
                        $service->cidr = $row['protocol'];
                    }
                }
            }
        }
    }


    //Checking consolidation calculated here.
    $totalRulesCount=count($nats_src);
    $totalDstRulesCount=count($nats_dst);
    $totalCounter=0;
    $totalCounterDst=0;

    $knownExplodeGroups = array();
    $knownAinB_Relations = array();

    /**
     * @var $nat_src SRXNatRule
     */
    foreach($nats_src as $nat_src){
        if(!isset($knownExplodeGroups[$nat_src->getHash("source")])){
            $knownExplodeGroups[$nat_src->getHash("source")] = explodeGroups2Members_srx($nat_src->source,$projectdb, $source, $vsys);
        }
        $exploded_Snat_src_Members = $knownExplodeGroups[$nat_src->getHash("source")];

        if(!isset($knownExplodeGroups[$nat_src->getHash("destination_orig")])){
            $knownExplodeGroups[$nat_src->getHash("destination_orig")] = explodeGroups2Members_srx($nat_src->destination_orig,$projectdb, $source, $vsys);
        }
        $exploded_Snat_dst_Members = $knownExplodeGroups[$nat_src->getHash("destination_orig")];

        if(!isset($knownExplodeGroups[$nat_src->getHash("service")])){
            $knownExplodeGroups[$nat_src->getHash("service")] = explodeGroups2Services_srx($nat_src->service,$projectdb, $source, $vsys);
        }
        $exploded_Snat_service_Members = $knownExplodeGroups[$nat_src->getHash("service")];

        $progress=($totalCounter/$totalRulesCount)*100;

        if ($progress==0 || $progress==10 || $progress==20 || $progress==30 ||$progress==40 || $progress==50 || $progress ==60 || $progress==70 || $progress==80 || $progress==90 || $progress==99){
            update_progress($project, '0.80', 'File:' . $filename . ' Phase 6 Consolidating dual Nats Percentage done ('.$progress.') current Nat Rule:'.$nat_src->rulelid,$jobid);
        }
        $totalCounter++;


        $totalCounterDst=0;

        /**
         * @var $nat_dst SRXNatRule
         */
        foreach ($nats_dst as $nat_dst){

            //Are destinations in nat_src included in translated destinations of nat_dst?
            if(!isset($knownExplodeGroups[$nat_dst->getHash("destination_nat")])){
                $knownExplodeGroups[$nat_dst->getHash("destination_nat")] = explodeGroups2Members_srx($nat_dst->destination_nat,$projectdb, $source, $vsys);
            }
            $exploded_Dnat_dst_Members = $knownExplodeGroups[$nat_dst->getHash("destination_nat")];
            $matchDestinations  = isAinB_srx($exploded_Snat_dst_Members, $exploded_Dnat_dst_Members);
            if($matchDestinations!=1) {
                continue;
            }

            //Are sources in nat_src included in sources of nat_dst?
            if(!isset($knownExplodeGroups[$nat_dst->getHash("source")])){
                $knownExplodeGroups[$nat_dst->getHash("source")] = explodeGroups2Members_srx($nat_dst->source,$projectdb, $source, $vsys);
            }
            $exploded_Dnat_src_Members = $knownExplodeGroups[$nat_dst->getHash("source")];
            $matchSources       = isAinB_srx($exploded_Snat_src_Members, $exploded_Dnat_src_Members);
            if($matchSources!=1) continue;

            //Are services in nat_src included in services / translated services of nat_dst?
            if(!isset($knownExplodeGroups[$nat_dst->getHash("service")])){
                $knownExplodeGroups[$nat_dst->getHash("service")] = explodeGroups2Services_srx($nat_dst->service,$projectdb, $source, $vsys);
            }
            $exploded_Dnat_service_Members = $knownExplodeGroups[$nat_dst->getHash("service")];
            $matchServices      = isAinBService_srx($exploded_Snat_service_Members, $exploded_Dnat_service_Members);
            if($matchServices!=1) continue;


            if ($matchSources && $matchDestinations  && $matchServices){
                //echo "Rule SRC $nat_src->rulelid FITS with DST $nat_dst->rulelid\n";
                //update the dat
                $dest = $nat_dst->destination_nat[0];
                $destname = $dest->name;
                $destlocation = $dest->location;
                $serv = $nat_dst->service[0]->value;
                $query = "UPDATE nat_rules SET tp_dat_address_lid ='$destname', tp_dat_address_table='$destlocation', tp_dat_port='$serv', id_sat=1 WHERE id = '$nat_src->rulelid';";
                $projectdb->query($query);
                add_log2("ok","Consolidating dual Nats",'Added DNAT to Nat Rule '.$nat_src->rulelid,$source,'Review the Nat Rule '.$nat_src->rulelid,'rules',$nat_src->rulelid,'nat_rules');
                break;
            }
            $totalCounterDst++;
        }
    }
}


/***
 * Looks for twice NAT and merges them if found. IN SRX, first DNAT is evaluated, and on the translated Dest package, the NAT policy is again evaluated to check if a Source NAT should apply.
 * This means that both Source and Dest Nat rules would have the same pre-nat source and
 * post-nat destination in the DNAT would be pre-nat destination in the SNAT
 *
 * Example:
 * SRX
 *    192.168.0.202 - 10.0.0.85     ---> 172.195.1.33 - ___________
 *    192.168.0.202 - 172.195.1.34  ---> ____________ - 10.0.0.85
 *
 * would become the following in PANOS
 *    192.168.0.202 - 172.195.1.34  ---> 10.0.0.85 - 10.0.0.85
 *
 * @param int $source
 * @param string $vsys
 * @param string $filename
 * @param int $jobid
 * @param string $project
 */
function consolidate_twice_NATs($source, $vsys,$filename,$jobid,$project){
    global $projectdb;

    $nats_src = array();
    $nats_dst = array();
    $myMembersMap=array();

    //Collect all the information from the NAT rules
    $getAllNats=$projectdb->query("SELECT id,is_dat, op_service_lid, op_service_table, tp_dat_address_lid, tp_dat_address_table, tp_dat_port FROM nat_rules WHERE source='$source' AND vsys='$vsys';");
    if ($getAllNats->num_rows>0){
        $NatID=array();
        $myMembersMap=array();
        while($getAllNatsData=$getAllNats->fetch_assoc()){
            $NatID[]=$getAllNatsData['id'];
            $myMembersMap[$getAllNatsData['id']]=[
                "is_dat"                =>$getAllNatsData['is_dat'],
                "op_service_lid"        =>$getAllNatsData['op_service_lid'],
                "op_service_table"      =>$getAllNatsData['op_service_table'],
                "tp_dat_address_lid"    =>$getAllNatsData['tp_dat_address_lid'],
                "tp_dat_address_table"  =>$getAllNatsData['tp_dat_address_table'],
                "tp_dat_port"           =>$getAllNatsData['tp_dat_port'],
                "src"                   =>array(),
                "dst"                   =>array(),
                "tad"                   =>array()
            ];
        }
        # Create an Array with all the member_lids and table_names
        $getMems=$projectdb->query("SELECT rule_lid,member_lid,table_name FROM nat_rules_src WHERE rule_lid IN (".implode(",",$NatID).");");
        if ($getMems->num_rows>0){
            while($getMemsData=$getMems->fetch_assoc()){
                $myMembersMap[$getMemsData['rule_lid']]['src'][]=array("member_lid"=>$getMemsData['member_lid'],"table_name"=>$getMemsData['table_name']);
            }
        }
        $getMems=$projectdb->query("SELECT rule_lid,member_lid,table_name FROM nat_rules_dst WHERE rule_lid IN (".implode(",",$NatID).");");
        if ($getMems->num_rows>0){
            while($getMemsData=$getMems->fetch_assoc()){
                $myMembersMap[$getMemsData['rule_lid']]['dst'][]=array("member_lid"=>$getMemsData['member_lid'],"table_name"=>$getMemsData['table_name']);
            }
        }

        $getMems=$projectdb->query("SELECT rule_lid,member_lid,table_name FROM nat_rules_translated_address WHERE rule_lid IN (".implode(",",$NatID).");");
        if ($getMems->num_rows>0){
            while($getMemsData=$getMems->fetch_assoc()){
                $myMembersMap[$getMemsData['rule_lid']]['tad'][]=array("member_lid"=>$getMemsData['member_lid'],"table_name"=>$getMemsData['table_name']);
            }
        }
    }


    foreach($myMembersMap as $rule=>$ruleDataArray){
        $tmp_natRule = new SRXNatRule($rule, $ruleDataArray['is_dat']);

        foreach($ruleDataArray['src'] as $ruleSRCArray){
            $member_lid = $ruleSRCArray['member_lid'];
            $table_name = $ruleSRCArray['table_name'];
            $sourceObject = new MemberObject($member_lid,$table_name);
            $tmp_natRule->addSource($sourceObject);
        }

        if($tmp_natRule->is_dat == '0'){   //This is a source NAT
            //Destination
            foreach($ruleDataArray['dst'] as $ruleSRCArray){
                $member_lid = $ruleSRCArray['member_lid'];
                $table_name = $ruleSRCArray['table_name'];
                $destinationObject = new MemberObject($member_lid,$table_name);
                $tmp_natRule->addDestinationOrig($destinationObject);
            }

            //Service
            $op_service_lid    = $ruleDataArray['op_service_lid'];
            $op_service_table  = $ruleDataArray['op_service_table'];
            if(isset($op_service_table) && !is_null($op_service_table) && $op_service_table!=''){
                $serviceObject = new MemberObject($op_service_lid,$op_service_table);
                $tmp_natRule->addService($serviceObject);
            }

            //Translated Address
            foreach($ruleDataArray['tad'] as $ruleSRCArray){
                $member_lid = $ruleSRCArray['member_lid'];
                $table_name = $ruleSRCArray['table_name'];
                $destinationObject = new MemberObject($member_lid,$table_name);
                $tmp_natRule->addSourceNat($destinationObject);
            }

            $nats_src[] = $tmp_natRule;

        }
        elseif($tmp_natRule->is_dat == '1'){  //This is a destination NAT
            foreach($ruleDataArray['dst'] as $ruleSRCArray){
                $member_lid = $ruleSRCArray['member_lid'];
                $table_name = $ruleSRCArray['table_name'];
                $destinationObject = new MemberObject($member_lid,$table_name);
                $tmp_natRule->addDestinationOrig($destinationObject);
            }

            //DestinationNat
            $member_lid = $ruleDataArray['tp_dat_address_lid'];
            $table_name = $ruleDataArray['tp_dat_address_table'];
            $destinationObject = new MemberObject($member_lid,$table_name);
            $tmp_natRule->addDestinationNat($destinationObject);

            //Service
            $op_service_port = $ruleDataArray['tp_dat_port'];
            if($op_service_port!=0){
                $serviceObject = new MemberObject('dummy','services',$op_service_port,'');
                $tmp_natRule->addService($serviceObject);
            }
            else{
                $op_service_lid    = $ruleDataArray['op_service_lid'];
                $op_service_table  = $ruleDataArray['op_service_table'];
                if(isset($op_service_table) && !is_null($op_service_table) && $op_service_table!=''){
                    $serviceObject = new MemberObject($op_service_lid,$op_service_table);
                    $tmp_natRule->addService($serviceObject);
                }
            }

            $nats_dst[] = $tmp_natRule;
        }
        else{
            //TODO: Maybe for future options
        }
        unset($tmp_natRule);

    }


    //Transforming ANY addresses into 0.0.0.0/0. Necessary for the isAinB method
    /**
     * @var $nat_src SRXNatRule
     */
    $anyAddress = new MemberObject('ANY','address','0.0.0.0','0');
    $anyService = new MemberObject('ANY','services','0-65535','');

    foreach($nats_src as $nat_src){
        if (count($nat_src->source)==0){
            $nat_src->addSource($anyAddress);
        }
        else{
            foreach ($nat_src->source as $member){
                if(!isset($member->value) || !isset($member->cidr)){
                    $query ="SELECT id, ipaddress, cidr FROM address WHERE id=$member->name AND source='$source' AND vsys='$vsys';";
                    $getMember = $projectdb->query($query);
                    if($getMember->num_rows == 1){
                        $row=$getMember->fetch_assoc();
                        $member->cidr=$row['cidr'];
                        $member->value=$row['ipaddress'];
                    }
                }
            }
        }

        if (count($nat_src->destination_orig)==0){
            $nat_src->addDestinationOrig($anyAddress);
        }
        else{
            foreach ($nat_src->destination_orig as $member){
                if(!isset($member->value) || !isset($member->cidr)){
                    $query ="SELECT id, ipaddress, cidr FROM address WHERE id=$member->name AND source='$source' AND vsys='$vsys';";
                    $getMember = $projectdb->query($query);
                    if($getMember->num_rows == 1){
                        $row=$getMember->fetch_assoc();
                        $member->cidr=$row['cidr'];
                        $member->value=$row['ipaddress'];
                    }
                }
            }
        }


        if (count($nat_src->service)==0){
            $nat_src->addService($anyService);
        }
        else{
            foreach ($nat_src->service as $service) {
                if (!isset($service->value) || !isset($service->cidr)) {
                    $query = "SELECT id, dport, protocol FROM services WHERE id=$service->name AND source='$source' AND vsys='$vsys';";
                    $getService = $projectdb->query($query);
                    if ($getService->num_rows == 1) {
                        $row = $getService->fetch_assoc();
                        $service->value = $row['dport'];
                        $service->cidr = $row['protocol'];
                    }
                }
            }
        }

    }

    /**
     * @var $nats_dst SRXNatRule[]
     */
    foreach($nats_dst as $nat_dst){
        if (count($nat_dst->source)==0){
            $nat_dst->addSource($anyAddress);
        }
        else{
            foreach ($nat_dst->source as $member){
                if(!isset($member->value) || !isset($member->cidr)){
                    $query ="SELECT id, ipaddress, cidr FROM address WHERE id=$member->name AND source='$source' AND vsys='$vsys';";
                    $getMember = $projectdb->query($query);
                    if($getMember->num_rows == 1){
                        $row=$getMember->fetch_assoc();
                        $member->cidr=$row['cidr'];
                        $member->value=$row['ipaddress'];
                    }
                }
            }
        }

        if (count($nat_dst->destination_nat)==0){
            $nat_dst->addDestinationNat($anyAddress);
        }
        else{
            foreach ($nat_dst->destination_nat as $member){
                if(!isset($member->value) || !isset($member->cidr)){
                    $query ="SELECT id, ipaddress, cidr FROM address WHERE id=$member->name AND source='$source' AND vsys='$vsys';";
                    $getMember = $projectdb->query($query);
                    if($getMember->num_rows == 1){
                        $row=$getMember->fetch_assoc();
                        $member->cidr=$row['cidr'];
                        $member->value=$row['ipaddress'];
                    }
                }
            }
        }

        if (count($nat_dst->destination_orig)==0){
            $nat_dst->addDestinationOrig($anyAddress);
        }
        else{
            foreach ($nat_dst->destination_orig as $member){
                if(!isset($member->value) || !isset($member->cidr)){
                    $query ="SELECT id, ipaddress, cidr FROM address WHERE id=$member->name AND source='$source' AND vsys='$vsys';";
                    $getMember = $projectdb->query($query);
                    if($getMember->num_rows == 1){
                        $row=$getMember->fetch_assoc();
                        $member->cidr=$row['cidr'];
                        $member->value=$row['ipaddress'];
                    }
                }
            }
        }

        if (count($nat_dst->service)==0){
            $nat_dst->addService($anyService);
        }
        else{
            foreach ($nat_dst->service as $service) {
                if (!isset($service->value) || !isset($service->cidr)) {
                    $query = "SELECT id, dport, protocol FROM services WHERE id=$service->name AND source='$source' AND vsys='$vsys';";
                    $getService = $projectdb->query($query);
                    if ($getService->num_rows == 1) {
                        $row = $getService->fetch_assoc();
                        $service->value = $row['dport'];
                        $service->cidr = $row['protocol'];
                    }
                }
            }
        }
    }


    //Checking consolidation calculated here.
    $totalRulesCount=count($nats_src);
    $totalDstRulesCount=count($nats_dst);
    $totalCounter=0;
    $totalCounterDst=0;

    $knownExplodeGroups = array();
    $knownAinB_Relations = array();

    /**
     * @var SRXNatRule $nat_dst
     */
    foreach ($nats_dst as $nat_dst){
        if(!isset($knownExplodeGroups[$nat_dst->getHash("source")])){
            $knownExplodeGroups[$nat_dst->getHash("source")] = explodeGroups2Members_srx($nat_dst->source,$projectdb, $source, $vsys);
        }
        $exploded_Dnat_src_Members = $knownExplodeGroups[$nat_dst->getHash("source")];

        if(!isset($knownExplodeGroups[$nat_dst->getHash("destination_nat")])){
            $knownExplodeGroups[$nat_dst->getHash("destination_nat")] = explodeGroups2Members_srx($nat_dst->destination_nat,$projectdb, $source, $vsys);
        }
        $exploded_Dnat_tap_Members = $knownExplodeGroups[$nat_dst->getHash("destination_nat")];

        if(!isset($knownExplodeGroups[$nat_dst->getHash("service")])){
            $knownExplodeGroups[$nat_dst->getHash("service")] = explodeGroups2Services_srx($nat_dst->service,$projectdb, $source, $vsys);
        }
        $exploded_Dnat_service_Members = $knownExplodeGroups[$nat_dst->getHash("service")];


        /**
         * @var SRXNatRule $nat_src
         */
        foreach ($nats_src as $nat_src){

            //Check that translated destination is the dest_orig
            if(!isset($knownExplodeGroups[$nat_src->getHash("destination_orig")])){
                $knownExplodeGroups[$nat_src->getHash("destination_orig")] = explodeGroups2Members_srx($nat_src->destination_orig,$projectdb, $source, $vsys);
            }
            $exploded_Snat_dst_Members = $knownExplodeGroups[$nat_src->getHash("destination_orig")];
            $matchDestinations  = isAinB_srx($exploded_Snat_dst_Members, $exploded_Dnat_tap_Members);
            if($matchDestinations!=1) {
                continue;
            }

            //Check both sources match
            if(!isset($knownExplodeGroups[$nat_src->getHash("source")])){
                $knownExplodeGroups[$nat_src->getHash("source")] = explodeGroups2Members_srx($nat_src->source,$projectdb, $source, $vsys);
            }
            $exploded_Snat_src_Members = $knownExplodeGroups[$nat_src->getHash("source")];
            $matchSources  = isAinB_srx($exploded_Snat_src_Members, $exploded_Dnat_src_Members);
            if($matchSources!=1) {
                continue;
            }

            //Check that services match
            if(!isset($knownExplodeGroups[$nat_src->getHash("service")])){
                $knownExplodeGroups[$nat_src->getHash("service")] = explodeGroups2Services_srx($nat_src->service,$projectdb, $source, $vsys);
            }
            $exploded_Snat_service_Members = $knownExplodeGroups[$nat_src->getHash("service")];
            $matchServices  = isAinB_srx($exploded_Snat_service_Members, $exploded_Dnat_service_Members);
            if($matchServices!=1) {
                continue;
            }

            if($matchSources && $matchDestinations && $matchServices){
                // The Destination Nat should now include the NAT Source
                // We should set a monitor entry for both rules
                $translated_source_address = array();
                foreach($nat_src->source_nat as $memberObject){
                    $translated_source_address[] = "('$source','$vsys', $nat_dst->rulelid, $memberObject->name, '$memberObject->location')";
                }

                if(count($translated_source_address)>0) {
                    $queryUpdate = "INSERT INTO nat_rules_translated_address (source, vsys, rule_lid, member_lid, table_name) VALUES " . implode(",", $translated_source_address) . ";";
                    $projectdb->query($queryUpdate);
                }
                add_log2("ok","Consolidating Twice Nats",'Added Twice to DNat Rule '.$nat_dst->rulelid.' with SNat Rule '.$nat_src->rulelid,$source,'Nothing','rules',$nat_dst->rulelid,'nat_rules');
                add_log2("warning","Consolidating Twice Nats",'SNat rule '.$nat_src->rulelid.' has been integrated into DNat Rule '.$nat_dst->rulelid,$source,'Review the SNat Rule '.$nat_src->rulelid.' in case it can be removed','rules',$nat_src->rulelid,'nat_rules');
            }
        }
    }
}

/**
 * Check that all the objects existing in the groupA are present in the groupB
 *
 * @param MemberObject[] $groupA
 * @param MemberObject[] $groupB
 * @return int
 */
function isAinB_srx($groupA, $groupB){

    foreach($groupA as $childMember){
        $isChildFound = 0;
        foreach($groupB as $parentMember){
            $result=-1;
            netMatchObjects2Ways($childMember, $parentMember, $result);
            if($result == 1){ //if one of the members in the groupA is not in groupB, then A is not in B
                $isChildFound=1;
                break;
            }
        }
        if($isChildFound == 0){
            return 0;
        }
    }
    return 1;
}

/**
 * Check that all the objects existing in the groupA are present in the groupB
 *
 * @param MemberObject[] $groupA
 * @param MemberObject[] $groupB
 * @return int
 */
function isAinBService_srx($groupA, $groupB){
    if(!isset($groupB) || count($groupB)==0){
        return 1;
    }
    if(strcmp($groupB[0]->name, "ANY")==0){
        return 1;
    }
    if(!isset($groupA) || count($groupA)==0){
        return 0;
    }
    if(strcmp($groupA[0]->name, "ANY")==0){
        return 0;
    }

    foreach($groupA as $childMember){
        $isChildFound = 0;
        foreach($groupB as $parentMember){
            $result=-1;
            serviceMatchObjects2Ways($childMember, $parentMember, $result);
            if($result == 1){ //if one of the members in the groupA is not in groupB, then A is not in B
                $isChildFound=1;
                break;
            }
        }
        if($isChildFound == 0){
            return 0;
        }
    }
    return 1;
}


/**
 * Method to explode Groups into its Members. A group can be a Member
 * @param MemberObject[] $members
 * @param MySQLi $projectdb
 * @param int $source
 * @param string $vsys
 * @return MemberObject[]
 */
function explodeGroups2Members_srx($members,$projectdb, $source, $vsys){
    $tmp_members=array();

    foreach($members as $member){

        //Not a group. Let's add it directly
        if(strcmp($member->location, 'address')==0){
            if(!isset($member->value) || !isset($member->cidr)){
                $query ="SELECT id, ipaddress, cidr FROM address WHERE id=$member->name AND source='$source' AND vsys='$vsys';";
                $getMember = $projectdb->query($query);
                if($getMember->num_rows == 1){
                    $row=$getMember->fetch_assoc();
                    $member->cidr=$row['cidr'];
                    $member->value=$row['ipaddress'];
                }
            }
            $tmp_members[]=$member;
        }

        //This is a group. Let's expand it
        else{
            $query = "SELECT member_lid, table_name 
                FROM address_groups adg 
                WHERE BINARY adg.lid='$member->name' ";
            $getMember = $projectdb->query($query);
            while($row = $getMember->fetch_assoc()) {
                $member_id= $row['member_lid'];
                $member_location = $row['table_name'];
                $member2[] = new MemberObject($member_id, $member_location);
            }
            $tmp_members = array_merge($tmp_members, explodeGroups2Members_srx($member2, $projectdb, $source, $vsys));
        }
    }

    return $tmp_members;
}

/**
 * Method to identify Members that belong to two groups. A group can be a Member
 * @param MemberObject[] $childMembers.
 * @param MemberObject[] $parentMembers
 * @param unknown $projectdb
 * @param unknown $source
 * @param unknown $vsys
 * @return MemberObject[]
 */
function getCommonMembers($childMembers, $parentMembers, $projectdb, $source, $vsys){
    //Easy parts. Either childMembers or parentMembers are ANY, or they both have the same members
    //No parent of children sources were defined, so they are ANY
    if((!isset($parentMembers) || count($parentMembers)==0) &&
        (!isset($childMembers) || count($childMembers)==0)     ){
        $member = new MemberObject('ANY', 'address', '0.0.0.0', '0');
        $tmp_Members=$member;
    }
    //The Parent policy has an ANY. We use the Child's Sources's members
    elseif(!isset($parentMembers) || count($parentMembers)==0 || strcmp($parentMembers[0]->name, "ANY")==0){
        $tmp_Members=$childMembers;
    }
    //The Child policy has an ANY. We use the Parent's members.
    elseif(!isset($childMembers) || count($childMembers)==0 || strcmp($childMembers[0]->name, "ANY")==0){  //The subpolicy has ANY as a source. We use the Parents source
        $tmp_Members=$parentMembers;
    }
    //Parent and Child are equal. Therefore, these are the common members.
    elseif($parentMembers == $childMembers){  //TODO: test with array_diff instead, because order of the members could be different
        $tmp_Members = $parentMembers;
    }

    //Both the parent policy and the child have members that are not equal. We need to calculate matchings
    else{

        //To make it simple, we will explode all groups into its Members.
        $exploded_childMembers = explodeGroups2Members_srx($childMembers,$projectdb, $source, $vsys);
        $exploded_parentMembers = explodeGroups2Members_srx($parentMembers,$projectdb, $source, $vsys);

        foreach ($exploded_childMembers as $childNode){

            foreach ($exploded_parentMembers as $parentMember){
                $result = netMatchObjects2Ways($childNode, $parentMember, $way=-1);
                if(isset($result)){
                    $tmp_Members[]=$result;
                    if($way==1){
                        break 1;
                    }
                }
            }
        }

        //In case $childMembers was a group and all its members were selected, substitute the members by the group
        //In case $parentMembers was a group and all its members were selected, substitute the members by the group
        if(isset($tmp_Members)){
            $replace_childGroup = true;
            $replace_parentGroup = true;
            foreach ($exploded_childMembers as $child){
                if(!in_array($child, $tmp_Members)){
                    $replace_childGroup = false;
                    break;
                }
            }
            foreach ($exploded_parentMembers as $parent){
                if(!in_array($parent, $tmp_Members)){
                    $replace_parentGroup = false;
                    break;
                }
            }

            if($replace_childGroup){
                foreach($exploded_childMembers as $child){
                    $key = array_search($child,$tmp_Members);
                    if($key!==false){
                        unset($tmp_Members[$key]);
                    }
                }
                $tmp_Members=$childMembers;
            }
            if($replace_parentGroup){
                foreach($exploded_parentMembers as $parent){
                    $key = array_search($parent, $tmp_Members);
                    if($key!==false){
                        unset($tmp_Members[$key]);
                    }
                }
                $tmp_Members=$parentMembers;
            }
        }
    }

    return $tmp_Members;
}

/**
 * Method to explode Groups into its Services. A group can be a Service
 * @param MemberObject[] $services
 * @param MySQLi $projectdb
 * @param int $source
 * @param string $vsys
 * @return MemberObject[]
 */
function explodeGroups2Services_srx($services, MySQLi $projectdb, int $source, String $vsys){
    $tmp_services=array();

    foreach($services as $service){

        //Not a group. Let's add it directly
        if(strcmp($service->location, 'services')==0){
            if(strcmp($service->name, 'dummy')==0){}
            elseif(!isset($service->value) || !isset($service->cidr)){
                $query ="SELECT id, dport, protocol FROM services WHERE id=$service->name AND source='$source' AND vsys='$vsys';";
                $getService = $projectdb->query($query);
                if($getService->num_rows == 1){
                    $row=$getService->fetch_assoc();
                    $service->value=$row['dport'];
                    $service->cidr= $row['protocol'];
                }
            }

            $tmp_services[]=$service;
        }

        //This is a group. Let's expand it
        else{
            $member2=array();
            $query = "SELECT member_lid, table_name 
                FROM services_groups sg                 
                WHERE sg.lid='$service->name' ";
            $getService = $projectdb->query($query);
            while($row = $getService->fetch_assoc()) {
                $service_id= $row['member_lid'];
                $service_location = $row['table_name'];
                $member2[] = new MemberObject($service_id, $service_location);
            }
            if (count($member2)>0){
                $tmp_services = array_merge($tmp_services, explodeGroups2Services_srx($member2, $projectdb, $source, $vsys));
            }
        }
    }

    return $tmp_services;
}

/**
 * Method to identify Services that belong to two groups. A group can be a Service
 * @param MemberObject[] $childServices.
 * @param MemberObject[] $parentServices
 * @param unknown $projectdb
 * @param unknown $source
 * @param unknown $vsys
 * @return MemberObject[]
 */
function getCommonServices($childServices, $parentServices, $projectdb, $source, $vsys){
    //Easy parts. Either childMembers or parentMembers are ANY, or they both have the same members
    //The Parent policy has an ANY. We use the Child's Sources's members
    $tmp_Services = null;
    if((!isset($parentServices) || count($parentServices)==0) &&
        (!isset($childServices) || count($childServices)==0)     ){
        $member = new MemberObject('ANY', '', '', '');
        $tmp_Services=$member;
    }
    elseif(!isset($parentServices) || count($parentServices)==0 || strcmp($parentServices[0]->name, "ANY")==0){
        $tmp_Services=$childServices;
    }
    //The Child policy has an ANY. We use the Parent's members.
    elseif(!isset($childServices) || count($childServices)==0 || strcmp($childServices[0]->name, "ANY")==0){  //The subpolicy has ANY as a source. We use the Parents source
        $tmp_Services=$parentServices;
    }
    //Parent and Child are equal. Therefore, these are the common members.
    elseif($parentServices == $childServices){
        $tmp_Services = $parentServices;
    }

    //Both the parent policy and the child have members that are not equal. We need to calculate matchings
    else{

        //To make it simple, we will explode all groups into its Members.
        $exploded_childServices = explodeGroups2Services_srx($childServices,$projectdb, $source, $vsys);
        $exploded_parentServices = explodeGroups2Services_srx($parentServices,$projectdb, $source, $vsys);

        foreach ($exploded_childServices as $childService){
            foreach ($exploded_parentServices as $parentService){
                $result = serviceMatchObjects2Ways($childService, $parentService, $way=-1);
                if(isset($result)){
                    $tmp_Services[]=$result;
                    if($way==1){
                        break 1;
                    }
                }
            }

        }

        //In case $childMembers was a group and all its members were selected, substitute the members by the group
        //In case $parentMembers was a group and all its members were selected, substitute the members by the group
        if(isset($tmp_Services)){
            $replace_childGroup = true;
            $replace_parentGroup = true;
            foreach ($exploded_childServices as $child){
                if(!in_array($child, $tmp_Services)){
                    $replace_childGroup = false;
                    break;
                }
            }
            foreach ($exploded_parentServices as $parent){
                if(!in_array($parent, $tmp_Services)){
                    $replace_parentGroup = false;
                    break;
                }
            }

            if($replace_childGroup){
                foreach($exploded_childServices as $child){
                    $key = array_search($child,$tmp_Services);
                    if($key!==false){
                        unset($tmp_Services[$key]);
                    }
                }
                $tmp_Services[]=$childServices;
            }
            if($replace_parentGroup){
                foreach($exploded_parentServices as $parent){
                    $key = array_search($parent, $tmp_Services);
                    if($key!==false){
                        unset($tmp_Services[$key]);
                    }
                }
                $tmp_Services[]=$parentServices;
            }
            //All clean now with the common Services
        }

    }

    return $tmp_Services;
}


?>
