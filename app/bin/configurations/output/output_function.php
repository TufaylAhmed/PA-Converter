<?php

# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
//Loads all global PHP definitions
use PaloAltoNetworks\Expedition\Security\OpenSSLTools;

require_once '/var/www/html/libs/common/definitions.php';

//Dependencies
//User management control

require_once INC_ROOT.'/libs/shared.php';
require_once INC_ROOT.'/libs/common/xml/panosxml.php';
require_once INC_ROOT.'/libs/xmlapi.php';
require_once INC_ROOT.'/libs/database.php';
//Capture request paramenters

require_once INC_ROOT.'/libs/projectdb.php';
require_once INC_ROOT.'/userManager/API/accessControl_CLI.php';
global $app;
include INC_ROOT.'/bin/configurations/parsers/readVars.php';

// Validations
if(!accessControl("any", ['project.admin', 'projectRole.'.$project.'.admin'])){
    http_response_code(401);
    header("HTTP/1.1 401 Unauthorized");
    header("Location: /401");
    exit;
}

if (($project!="") AND ($jobid!="")){
    $data['project']=$project;
    $data['api_call']=$api_call;
    generate_xml($data,$jobid);
}

function generate_xml($data,$jobid){
    global $app;
    $project=$data['project'];
    $projectdb = selectDatabase($project);
    $objectsInMemory=array();
    $getBC = $projectdb->query("SELECT id,ispanorama,version,filename FROM device_mapping WHERE active=1 AND baseconfig=1 GROUP BY filename;");
    if ($getBC->num_rows === 1) {
        #PHP VARS
        ini_set('max_execution_time', PARSER_max_execution_time);
        ini_set("memory_limit", PARSER_max_execution_memory);
        $progressCounter=10;
        $dataBC = $getBC->fetch_assoc();

        $version=getVersion($dataBC['version']);

        $is_panorama = (int)$dataBC['ispanorama'];
        $filename = $dataBC['filename'];
        $source = $dataBC['id'];
        $data["source"]=$source;
        $data["ispanorama"]=$is_panorama;
        $data['version']=$version;
        $data['projectdb']=$projectdb;

        #LOAD BaseConfig
        if (!file_exists(USERSPACE_PATH."/projects/" . $project . "/" . $filename.".dat")){
            update_progress($project, '-1.00', 'Imposible to load Base configuration, probably was removed. Remove your BC from the GUI and import it again.',$jobid);
            add_log("error","Generating XML from Base Configuration","Imposible to load Base configuration, probably was removed.",$source,'Remove your BC from the GUI and import it again.');
            exit(0);
        }
        $output_path = USERSPACE_PATH."/projects/" . $project . "/" . $filename;
        $projectObj = $app->project->where("name", $project)->first();
        $keyObj = $app->accessKey->where("type","project")->where("lid",$projectObj->id)->first();

        $encryptor = new OpenSSLTools($keyObj->key, $keyObj->iv);
        $contents = $encryptor->decryptFromFile("$output_path.dat");
        $xml = simplexml_load_string($contents);
        //file_put_contents("/tmp/file", $contents);

        if (isset($xml->result)){
            $xml1 = $xml->result->config;
            $xml = $xml1;
            $dom = new DOMDocument('1.0');
            $dom->preserveWhiteSpace = false;
            $dom->formatOutput = true;
            $dom->loadXML($xml->asXML());
            $xml_out = $dom->saveXML($dom->documentElement);
            $xml = simplexml_load_string($xml_out);
        }

//        $xml_str = file_get_contents($OUTPUTPATH);
//        $xml = new SimpleXMLElement($xml_str);

        # Remove all the Api-Calls if called
        if (isset($data['api_call'])){
            $projectdb->query("truncate table output_mapping;");
        }
        else{$data["api_call"]='';}
        $api_call=$data['api_call'];

        # devices use the default template so have an id if its panorama the panorama tab is template=0
        $allDG[]="shared";
        $allTemplate=array();

        #Load into ObjectsInMemory default_applications and default_regions
        load_default_objects($objectsInMemory,$data);

        if ($is_panorama===0){
            # Firewall
            $getDG = $projectdb->query("SELECT * FROM virtual_systems WHERE source='$source';");
            if ($getDG->num_rows > 0) {
                while ($DG = $getDG->fetch_assoc()) {
                    $allDG[] = $DG['name'];
                }
            }
            $getTemplate = $projectdb->query("SELECT id FROM templates_mapping WHERE source='$source' LIMIT 1;");
            if ($getTemplate->num_rows === 1) {
                $getTemplateData = $getTemplate->fetch_assoc();
                $template = $getTemplateData['id'];
            }
            $allTemplate[]=$template;
            $data['template']=$template;
//            $allTemplate[]=0;
//            $data['template']=0;
            $template_name="";
            $data['template_name']=$template_name;
            //$data['template_extra'][$template]["name"]=$template_name;
        }
        else{
            # Panorama
            $getDG = $projectdb->query(
                "SELECT a.id as id, a.vsys AS vsys 
                        FROM device_mapping a, devicegroups b 
                        WHERE a.id=b.device_mapping_id AND b.source='$source' AND a.vsys!='shared' 
                        GROUP BY a.vsys 
                        ORDER BY a.id;");
            if ($getDG->num_rows > 0) {
                while ($DG = $getDG->fetch_assoc()) {
                    $allDG[] = $DG['vsys'];
                    $data['devicegroup']=$DG['vsys'];
                    $data['devicegroupid']=$DG['id'];
                    xml_devicegroup($xml,$data);
                }
                # Generate Panorama readonly
                update_progress($project,'0.'.$progressCounter, 'Generating Panorama Readonly information', $jobid);
                $progressCounter++;
                xml_panorama_readonly($xml,$data);
            }
            $allTemplate[]=0;
            #Add all other Templates
            $getTemplate = $projectdb->query("SELECT id,name FROM templates_mapping WHERE source='$source';");
            if ($getTemplate->num_rows > 0) {
                while($getTemplateData = $getTemplate->fetch_assoc()){
                    $template = $getTemplateData['id'];
                    $template_name=$getTemplateData['name'];
                    $allTemplate[]=$template;
                    $data['template']=$template;
                    $data['template_extra'][$template]["name"]=$template_name;
                    $data['template_name']=$template_name;
                    xml_template($xml,$data);
                }
            }
        }

        //get Device-Groups (s) that should remain
        $required_dgs = array();
        foreach($allDG as $newvsys){
            $required_dgs[] = $newvsys;
        }

        //get Template (s) that should remain
        $required_templates = array();
        foreach($allTemplate as $newTemplate){
            $data['template']=$newTemplate;
            if ($newTemplate!=0 && isset($data['template_extra'])){
                $data['template_name']=$data['template_extra'][$newTemplate]["name"];
                $required_templates[]=$data['template_name'];
            }
        }

        //get Template-Stack (s) that should remain
        $existing_device_groups = [];
        if (isset($xml->{'mgt-config'}->devices)) {
            $ispanorama=1;
            $device_groups = $xml->xpath("/config/devices/entry[@name='localhost.localdomain']/device-group/entry");
            if (count($device_groups) > 0) {
                foreach ($device_groups as $existing_device_group) {
                    $existing_device_group_name = $existing_device_group->attributes()->name;
                    $existing_device_groups[] = (string)$existing_device_group_name;
                }
            }
        }
        $expired_dgs = array_diff($existing_device_groups, $required_dgs);


        /* TODO: Complete the Delete template and template stacks
        $existing_templates = [];
        if (isset($xml->{'mgt-config'}->devices)) {
            $ispanorama=1;
            $templates = $xml->xpath("/config/devices/entry[@name='localhost.localdomain']/template/entry");
            if (count($templates) > 0) {
                foreach ($templates as $existing_template) {
                    $existing_template_name = $existing_template->attributes()->name;
                    $existing_templates[] = (string)$existing_template_name;
                }
            }
        }
        $expired_templates = array_diff($existing_templates, $required_templates);

        $existing_templates_stack = [];
        if (isset($xml->{'mgt-config'}->devices)) {
            $ispanorama=1;
            $templates = $xml->xpath("/config/devices/entry[@name='localhost.localdomain']/template-stack/entry");
            if (count($templates) > 0) {
                foreach ($templates as $existing_template) {
                    $existing_template_name = $existing_template->attributes()->name;
                    $existing_templates_stack[] = (string)$existing_template_name;
                }
            }
        }
        $expired_template_stacks = array_diff($existing_templates_stack, $required_template_stasks);
        */


        #Delete the Device Group section
        $toDeleteDGs = [];
        $device_groups = $xml->xpath("/config/devices/entry[@name='localhost.localdomain']/device-group/entry");
        if (count($device_groups) > 0) {
            foreach ($device_groups as  $existing_device_group) {
                if(in_array($existing_device_group['name'], $expired_dgs)) {
                    $toDeleteDGs[] = $existing_device_group;
                }
            }
        }
        foreach ($toDeleteDGs as $item) {
            $dom = dom_import_simplexml($item);
            $dom->parentNode->removeChild($dom);
        }

        #Delete the Device Group READONLY section
        $toDeleteReadOnlyDGs = [];
        $device_groups = $xml->xpath("/config/readonly/devices/entry[@name='localhost.localdomain']/device-group/entry");
        if (count($device_groups) > 0) {
            foreach ($device_groups as  $existing_device_group) {
                if(in_array($existing_device_group['name'], $expired_dgs)) {
                    $toDeleteReadOnlyDGs[] = $existing_device_group;
                }
            }
        }
        foreach ($toDeleteReadOnlyDGs as $item) {
            $dom = dom_import_simplexml($item);
            $dom->parentNode->removeChild($dom);
        }



        /* TODO: Complete the Delete template and template stacks
        #Delete the Template section
        $toDeleteTemplates = [];
        $templates = $xml->xpath("/config/devices/entry[@name='localhost.localdomain']/template/entry");
        if (count($templates) > 0) {
            foreach ($templates as  $existing_template) {
                if(in_array($existing_template['name'], $expired_templates)) {
                    $toDeleteTemplates[] = $existing_template;
                }
            }
        }

        foreach ($toDeleteTemplates as $item) {
            $dom = dom_import_simplexml($item);
            $dom->parentNode->removeChild($dom);
        }
        */


        //echo $xml->asXML("/tmp/result.xml");

        foreach($allTemplate as $newTemplate){

            $data['template']=$newTemplate;
            if ($newTemplate!=0 && isset($data['template_extra'])){
                $data['template_name']=$data['template_extra'][$newTemplate]["name"];
                $template_name=$data['template_name'];
            }

            # Read the vsys from the template
            $allTemplateVsys=array();
            $allTemplateVsys[]="shared";
            $getTemplateVsys=$projectdb->query("SELECT name FROM virtual_systems WHERE source='$source' AND template='$newTemplate';");
            if ($getTemplateVsys->num_rows>0){
                while($getTemplateVsysData=$getTemplateVsys->fetch_assoc()){
                    $allTemplateVsys[]=$getTemplateVsysData['name'];
                }
            }
            # No VSYS Needed

            # DeviceConfig
            update_progress($project, '0.'.$progressCounter, 'Loading deviceconfig Objects',$jobid);$progressCounter++;
            xml_deviceconfig($xml,$data);

            # Mgt-Config
            # Password Complexity
            update_progress($project, '0.'.$progressCounter, 'Loading mgt-config',$jobid);$progressCounter++;
            xml_mgt_config($xml,$data);

            # Network

            //# Vlans Definido abajo
            //update_progress($project, '0.'.$progressCounter, 'Generating VLANS',$jobid);$progressCounter++;
            //xml_network_vlan($xml,$data);

            # Interfaces
            update_progress($project,'0.'.$progressCounter, 'Generating Network Interfaces Ethernet information', $jobid);$progressCounter++;
            xml_network_interface_ethernet($xml,$data);
            update_progress($project,'0.'.$progressCounter, 'Generating Network Interfaces Aggregate Ethernet information', $jobid);$progressCounter++;
            xml_network_interface_aggregate_ethernet($xml,$data);
            update_progress($project,'0.'.$progressCounter, 'Generating Network Interfaces Vlan information', $jobid);$progressCounter++;
            xml_network_interface_vlan($xml,$data);
            update_progress($project,'0.'.$progressCounter, 'Generating Network Interfaces Loopback information', $jobid);$progressCounter++;
            xml_network_interface_loopback($xml,$data);
            update_progress($project,'0.'.$progressCounter, 'Generating Network Interfaces Tunnel information', $jobid);$progressCounter++;
            xml_network_interface_tunnel($xml,$data);

            # Virtual Router
            xml_virtual_routers($xml,$data);

            # DHCP And DHCP Relay
            update_progress($project, '0.'.$progressCounter, 'Generating DHCP Server and Relays',$jobid);$progressCounter++;
            xml_network_dhcp($xml,$data);

            # Zone Protection Profile
            update_progress($project, '0.'.$progressCounter, 'Generating Zone Protection Profiles',$jobid);$progressCounter++;
            xml_network_zone_protection($xml,$data);

            # Monitor
            update_progress($project, '0.'.$progressCounter, 'Generating Monitor',$jobid);$progressCounter++;
            xml_network_monitor($xml,$data);

            # Management interface
            update_progress($project, '0.'.$progressCounter, 'Generating Management Interface',$jobid);$progressCounter++;
            xml_network_management_interface($xml,$data);

            # IKE GlobalProtect IPSec Crypto global-protect-app-crypto-profiles
            update_progress($project, '0.'.$progressCounter, 'Generating GlobalProtect IPSec Crypto',$jobid);$progressCounter++;
            xml_network_global_protect_app_crypto_profiles($xml,$data);

            # IKE IKE Crypto Profiles
            update_progress($project, '0.'.$progressCounter, 'Generating IKE Crypto Profiles',$jobid);$progressCounter++;
            xml_network_ike_crypto_profiles($xml,$data);

            # IKE IPSEC Crypto Profiles
            update_progress($project, '0.'.$progressCounter, 'Generating IPSEC Crypto Profiles',$jobid);$progressCounter++;
            xml_network_ipsec_crypto_profiles($xml,$data);

            # GATEWAY IKE
            update_progress($project, '0.'.$progressCounter, 'Generating IKE Gateways',$jobid);$progressCounter++;
            xml_network_gateway_ike($xml,$data);

            # TUNNEL IPSEC
            update_progress($project, '0.'.$progressCounter, 'Generating Tunnel IPSEC',$jobid);$progressCounter++;
            xml_network_tunnel_ipsec($xml,$data);

            # TUNNEL GRE
            update_progress($project, '0.'.$progressCounter, 'Generating Tunnel IPSEC',$jobid);$progressCounter++;
            xml_network_tunnel_gre($xml,$data);

            # Virtual-Wires
            update_progress($project, '0.'.$progressCounter, 'Generating Virtual-Wires',$jobid);$progressCounter++;
            xml_network_vwire($xml,$data);

            # Vlans
            update_progress($project, '0.'.$progressCounter, 'Generating VLANS',$jobid);$progressCounter++;
            xml_network_vlan($xml,$data);

            # Based on VSYS
            foreach($allTemplateVsys as $newTemplateVsys){
                $data['vsys']=$newTemplateVsys;

                # Virtual Systems
                xml_vsys($xml,$data);

                # Log-settings
                update_progress($project,'0.'.$progressCounter, 'Generating Log Settings :: vsys:'.$newTemplateVsys, $jobid);$progressCounter++;
                xml_log_settings($xml,$data);
                xml_log_settings_profiles($xml,$data);

                # Server Profiles
                update_progress($project,'0.'.$progressCounter, 'Loading Server Profiles :: vsys:'.$newTemplateVsys, $jobid);$progressCounter++;
                xml_server_profiles($xml,$data);

                # Response Pages
                update_progress($project,'0.'.$progressCounter, 'Loading Response-pages :: vsys:'.$newTemplateVsys, $jobid);$progressCounter++;
                xml_response_pages($xml,$data);

                # Zones
                update_progress($project,'0.'.$progressCounter, 'Loading Zones :: vsys:'.$newTemplateVsys, $jobid);$progressCounter++;
                xml_zones($xml,$data);

                # Network -> DNS-PROXY
                update_progress($project,'0.'.$progressCounter, 'Generating DNS-PROXY :: vsys:'.$newTemplateVsys, $jobid);$progressCounter++;
                xml_network_dnsproxy($xml,$data);
            }

            if (($api_call==="mega") && ($is_panorama==1) && ($newTemplate!=0)){
                $xpath0="/config/devices/entry[@name='localhost.localdomain']";
                $xpath2 = addslashes($xpath0."/template/entry[@name='$template_name']");
                $element=$xml->xpath($xpath0."/template/entry[@name='$template_name']");
                $xml_final = addslashes($element[0]->asXML());
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$template_name','Template','Template','$xml_final','$xpath2','edit');");
            }
        }
        // fin foreach allTemplates

        foreach($allDG as $newvsys){
            $data['vsys']=$newvsys;

            # Reports Only in Shared
            update_progress($project,'0.'.$progressCounter, 'Generating Reports vsys/dg:'.$newvsys, $jobid); $progressCounter++;
            xml_reports($xml,$data);

            # Profiles
            update_progress($project,'0.'.$progressCounter, 'Generating Profiles vsys/dg:'.$newvsys, $jobid); $progressCounter++;
            xml_profiles($xml,$data,$objectsInMemory);
            xml_profiles_groups($xml,$data,$objectsInMemory);

            # Schedules
            update_progress($project,'0.'.$progressCounter, 'Generating Schedules vsys/dg:'.$newvsys, $jobid);$progressCounter++;
            xml_schedules($xml,$data,$objectsInMemory);

            # Tags
            update_progress($project,'0.'.$progressCounter, 'Generating Tags vsys/dg:'.$newvsys, $jobid);$progressCounter++;
            xml_tags($xml,$data,$objectsInMemory);

            # External Lists
            update_progress($project,'0.'.$progressCounter, 'Generating External Lists vsys/dg:'.$newvsys, $jobid);$progressCounter++;
            xml_external_lists($xml,$data,$objectsInMemory);

            # Regions
            update_progress($project,'0.'.$progressCounter, 'Generating Regions vsys/dg:'.$newvsys, $jobid);$progressCounter++;
            xml_regions($xml,$data,$objectsInMemory);

            # Applications
            update_progress($project,'0.'.$progressCounter, 'Generating Applications vsys/dg:'.$newvsys, $jobid);$progressCounter++;
            xml_applications($xml,$data,$objectsInMemory);

            # Applications filters
            update_progress($project,'0.'.$progressCounter, 'Generating Applications Filters vsys/dg:'.$newvsys, $jobid);$progressCounter++;
            xml_applications_filters($xml,$data,$objectsInMemory);

            # Applications Groups
            update_progress($project,'0.'.$progressCounter, 'Generating Applications Groups vsys/dg:'.$newvsys, $jobid);$progressCounter++;
            xml_applications_groups($xml,$data,$objectsInMemory);

            # Address
            update_progress($project,'0.'.$progressCounter, 'Generating Address vsys/dg:'.$newvsys, $jobid);$progressCounter++;
            xml_address($xml,$data,$objectsInMemory);

            # Address Groups
            update_progress($project,'0.'.$progressCounter, 'Generating Address Groups vsys/dg:'.$newvsys, $jobid);$progressCounter++;
            xml_address_groups($xml,$data,$objectsInMemory);

            # Services
            update_progress($project,'0.'.$progressCounter, 'Generating Services vsys/dg:'.$newvsys, $jobid);$progressCounter++;
            xml_services($xml,$data,$objectsInMemory);

            # Services Groups
            update_progress($project,'0.'.$progressCounter, 'Generating Services Groups vsys/dg:'.$newvsys, $jobid);$progressCounter++;
            xml_services_groups($xml,$data,$objectsInMemory);

            # Security Rules
            update_progress($project,'0.'.$progressCounter, 'Generating Security Rules vsys/dg:'.$newvsys, $jobid);$progressCounter++;
            xml_security_rules($xml,$data,$objectsInMemory);

            # Nat Rules
            update_progress($project,'0.'.$progressCounter, 'Generating Nat Rules vsys/dg:'.$newvsys, $jobid);$progressCounter++;
            xml_nat_rules($xml,$data,$objectsInMemory);

            # Application Override Rules
            update_progress($project,'0.'.$progressCounter, 'Generating Application Override Rules vsys/dg:'.$newvsys, $jobid);$progressCounter++;
            xml_appoverride_rules($xml,$data,$objectsInMemory);

            # Authentication Rules
            update_progress($project,'0.'.$progressCounter, 'Generating Authentication Rules vsys/dg:'.$newvsys, $jobid);$progressCounter++;
            xml_authentication_rules($xml,$data,$objectsInMemory);

            # Captive Portal Rules
            update_progress($project,'0.'.$progressCounter, 'Generating Captive Portal Rules vsys/dg:'.$newvsys, $jobid);$progressCounter++;
            xml_captiveportal_rules($xml,$data,$objectsInMemory);

            # Decryption Rules
            update_progress($project,'0.'.$progressCounter, 'Generating Decryption Rules vsys/dg:'.$newvsys, $jobid);$progressCounter++;
            xml_decryption_rules($xml,$data,$objectsInMemory);

            # DoS Rules
            update_progress($project,'0.'.$progressCounter, 'Generating DoS Rules vsys/dg:'.$newvsys, $jobid);$progressCounter++;
            xml_dos_rules($xml,$data,$objectsInMemory);

            # PBF Rules
            update_progress($project,'0.'.$progressCounter, 'Generating PBF Rules vsys/dg:'.$newvsys, $jobid);$progressCounter++;
            xml_pbf_rules($xml,$data,$objectsInMemory);

            # QoS Rules
            update_progress($project,'0.'.$progressCounter, 'Generating QoS Rules vsys/dg:'.$newvsys, $jobid);$progressCounter++;
            xml_qos_rules($xml,$data,$objectsInMemory);

            # Tunnel Inspect Rules
            update_progress($project,'0.'.$progressCounter, 'Generating Tunnel Inspect Rules vsys/dg:'.$newvsys, $jobid);$progressCounter++;
            xml_tunnel_inspect_rules($xml,$data,$objectsInMemory);

            # Other Rules
            //update_progress($project,'0.'.$progressCounter, 'Generating Other Rules vsys/dg:'.$newvsys, $jobid);$progressCounter++;
            //xml_other_rules($xml,$data);

            # Log-settings
            update_progress($project,'0.'.$progressCounter, 'Generating Log Settings :: vsys:'.$newvsys, $jobid);$progressCounter++;
            xml_log_settings_dg($xml,$data);
            xml_log_settings_profiles($xml,$data);

            if (($api_call==="mega") && ($is_panorama===1) && ($newvsys!=="shared")){
                $xpath0="/config/devices/entry[@name='localhost.localdomain']";
                $xpath2 = addslashes($xpath0."/device-group/entry[@name='$newvsys']");
                $element=$xml->xpath($xpath0."/device-group/entry[@name='$newvsys']");
                $xml_final = addslashes($element[0]->asXML());
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$newvsys','Device-Group','Device-Group','$xml_final','$xpath2','edit');");
            }

            if (($api_call==="mega") && ($is_panorama===1) && ($newvsys==="shared")){
                $xpath0="/config";
                $xpath2 = addslashes($xpath0."/shared");
                $element=$xml->xpath($xpath0."/shared");
                $xml_final = addslashes($element[0]->asXML());
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$newvsys','Device-Group','Device-Group','$xml_final','$xpath2','edit');");
            }
        }


        //Verify if we need to remove DGs and Templates



        #Print OUTPUT
//        $dom = new DOMDocument('1.0');
//        $dom->preserveWhiteSpace = false;
//        $dom->formatOutput = true;
//        $dom->loadXML(html_entity_decode($xml->asXML(),null,'UTF-8'));

        $fileOut = USERSPACE_PATH."/projects/" . $project . "/MT-" . $project . ".xml";

//        $xml_out = $dom->saveXML($dom->documentElement);
//        $encryptor->encryptToFile($xml_out, $fileOut.".dat");
//
//        $dom->save($fileOut);
        #Remove first line
        $contents_orig=$xml->asXML();
        $contents=substr($contents_orig, 22);
        file_put_contents($fileOut, $contents);


        //Remove the extra DGs



        $encryptor->encryptToFile($contents, $fileOut.".dat");
        //$contents = file_get_contents($fileOut);
        //$kk=file_put_contents($fileOut, substr($contents, 22));

        /*
        $ansiblefile="";
        # Create Ansible Output EXPERIMENTAL
        if (file_exists($fileOut)){
            $ansiblefile = USERSPACE_PATH."/projects/" . $project . "/MT-" . $project . "-ansible.txt";
            $out=shell_exec("export PYTHONIOENCODING=utf8;export LANG=en_US.UTF-8;export LC_ALL=en_US.UTF-8;python3 ".INC_ROOT."/libs/ansible/xml-to-ansible.py \"./devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']\" \"" . $fileOut . "\"  > " . $ansiblefile);
        }
        */

        # Set commands
        if (file_exists($fileOut)) {
            $setfile = USERSPACE_PATH."/projects/" . $project . "/MT-" . $project . "-set.txt";
            $command = "PYTHONIOENCODING=utf8  python3 ".INC_ROOT."/libs/pan-python/bin/panconf.py --config " . escapeshellarg($fileOut) . " --set > " . escapeshellarg($setfile);
            $out=shell_exec($command);
            #Create ZIP File
            $zipFile = USERSPACE_PATH."/projects/" . $project . "/MT-" . $project . ".zip";
            if (file_exists($zipFile)) {
                unlink($zipFile);
            }

            # Create XML Pretty
            $xmlDocument2 = new DOMDocument('1.0');
            $xmlDocument2->preserveWhiteSpace = false;
            $xmlDocument2->formatOutput = true;
            $xmlDocument2->loadXML($xml->asXML());
            $fileOut2 = USERSPACE_PATH."/projects/" . $project . "/MT-" . $project . "-pretty.xml";
            $xmlContent=$xmlDocument2->saveXML();
            $kk=file_put_contents($fileOut2, $xmlContent);


            /*if (filesize($ansiblefile)>0){
                $files_to_zip = array($fileOut, $setfile, $ansiblefile,$fileOut2);
            }
            else{
                $files_to_zip = array($fileOut, $setfile,$fileOut2);
            }*/
            $files_to_zip = array($fileOut, $setfile,$fileOut2);

            if( create_zip($files_to_zip, $zipFile)) {
                $encryptor->encryptFiletoFile($zipFile, $zipFile . ".dat");
                unlink($zipFile);
            }
        }


        unlink($fileOut2);
        unlink($fileOut);
        unlink($setfile);

        /*
        if ($ansiblefile!=""){
            unlink($ansiblefile);
        }
        */

        update_progress($project, '1.00', 'Done.',$jobid);

    }
    else{
        //$message["code"]=false;
        //$message["msg"]="No Base Configuration found";
    }
    //return $message;
}