<?php
# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
function clean_xml(string $data_input){
    //$xml_to_return = preg_replace('/>n\s</', '><', preg_replace('/\\\\+/', '', preg_replace('/\\\n\s*/', '', $xml_input)));
    //$xml_to_return = preg_replace('/\\\\+/', '', $xml_to_return);
    //$xml_to_return = preg_replace('/>n\s</', '><', $xml_to_return);
    $data_input = preg_replace('/\\\n\s*/', '', $data_input);
    $data_input = preg_replace('/\n\s*/', '', $data_input);
    $data_input = preg_replace('/\\\\+/', '', $data_input);
    $data_input = preg_replace('/>n\s*</', '><', $data_input);

    return $data_input;
}

function load_default_objects(&$objectsInMemory,$data){
    $projectdb = $data['projectdb'];
    $source=$data['source'];

    $mytablesNoSource=array(
        "default_url_categories",
        "default_regions",
        "default_applications"
    );

    foreach($mytablesNoSource as $key=>$table_name){
        $loadApps=$projectdb->query("SELECT id,name FROM $table_name;");
        if ($loadApps->num_rows>0){
            while($data=$loadApps->fetch_assoc()){
                $lid=$data['id'];
                $name=$data['name'];
                $objectsInMemory[$table_name][$lid]['name']=$name;
            }
        }
    }

    $mytablesSource=array(
        "address",
        "address_groups_id",
        "services",
        "services_groups_id",
        "applications",
        "applications_groups_id",
        "applications_filters",
        "external_list",
        "tag",
        "regions",
        "schedules",
        "profiles",
        "profiles_groups"
    );

    foreach($mytablesSource as $key=>$table_name){
        //$loadApps=$projectdb->query("SELECT id,name FROM $table_name WHERE source='$source';");
        $loadApps=$projectdb->query("SELECT id,name FROM $table_name;");
        if ($loadApps->num_rows>0){
            while($data=$loadApps->fetch_assoc()){

                $lid = $data['id'];
                $name = $data['name'];
                $objectsInMemory[$table_name][$lid]['name']=$name;
            }
        }
    }
}

function xml_deviceconfig($xml,$data){
    $project=$data['project'];
    $ispanorama=$data['ispanorama'];
    $version=$data['version'];
    $api_call=$data['api_call'];
    $projectdb=$data['projectdb'];
    $source=$data['source'];
    $template=$data['template'];
    $template_name=$data['template_name'];

    $getBanner=$projectdb->query("SELECT xml FROM deviceconfig WHERE source='$source' AND template='$template';");
    if ($getBanner->num_rows==1) {
        if ($template!=0){
            if ($ispanorama==0){
                $xpath0="/config/devices/entry[@name='localhost.localdomain']";
            }
            else{
                $xpath0="/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='".$template_name."']/config/devices/entry[@name='localhost.localdomain']";
            }
        }
        else{
            $xpath0="/config/devices/entry[@name='localhost.localdomain']";
        }
        $getBannerData = $getBanner->fetch_assoc();
        if ($getBannerData['xml']!=""){
            $myBannerRaw=simplexml_load_string(clean_xml($getBannerData['xml']));

            #Remove from the BaseConfig
            if (!empty($xml->xpath($xpath0.'/deviceconfig'))){
                //$deviceconfig=$xml->xpath($xpath0.'/deviceconfig');
                $deviceconfig=$xml->xpath($xpath0);
                unset($deviceconfig[0]->deviceconfig);
                //$deviceconfig=$deviceconfig[0];
                SimpleXMLElement_append($deviceconfig[0], $myBannerRaw);
            }
            if ( (isset($api_call)) and ($api_call=="single") ){
                if (isset($myBannerRaw->system->{'login-banner'})){
                    $myBanner=$myBannerRaw->system->{'login-banner'}->asXML();
                    $xpath = addslashes($xpath0."/deviceconfig/system/login-banner");
                    $xml_final = addslashes($myBanner);
                    $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Login Banner','DeviceConfig','deviceconfig','$xml_final','$xpath','edit');");
                }
                if (isset($myBannerRaw->setting->wildfire)){
                    $myBanner=$myBannerRaw->setting->wildfire->asXML();
                    $xpath = addslashes($xpath0."/deviceconfig/setting/wildfire");
                    $xml_final = addslashes($myBanner);
                    $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Wildfire','DeviceConfig','deviceconfig','$xml_final','$xpath','edit');");
                }
                if (isset($myBannerRaw->setting->management)){
                    $myBanner=$myBannerRaw->setting->management->asXML();
                    $xpath = addslashes($xpath0."/deviceconfig/setting/management");
                    $xml_final = addslashes($myBanner);
                    $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Management','DeviceConfig','deviceconfig','$xml_final','$xpath','edit');");
                }
            }
            elseif ((isset($api_call)) and ($api_call=="atomic")){
                $xpath = addslashes($xpath0."/deviceconfig");
                $xml_final = addslashes($getBannerData['xml']);
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('DeviceConfig','DeviceConfig','deviceconfig','$xml_final','$xpath','edit');");
            }
        }
        $message['code']=true;
        $message['msg']="DeviceConfig Added";
    }
    else{
        $message['code']=false;
        $message['msg']="deviceconfig xml not found for source: $source and Template $template";
    }
    return $message;
}

function xml_devicegroup($xml,$data){
    $project = $data['project'];
    $ispanorama = $data['ispanorama'];
    $version = $data['version'];
    $api_call= $data['api_call'];
    $projectdb = $data['projectdb'];
    $source = $data['source'];
    $devicegroup = $data['devicegroup'];
    $devicegroupid=$data['devicegroupid'];

    if ($ispanorama==1){
        $tmp = $projectdb->query("SELECT * FROM devicegroups WHERE device_mapping_id='$devicegroupid';");
        if ($tmp->num_rows == 1) {
            $tmpData = $tmp->fetch_assoc();
            $dg_devices = $tmpData['devices'];
            $dg_description=$tmpData['description'];
            $dg_master_device=$tmpData['master_device'];

            $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']";
            $xpath0=$data['xpath0'];

            if (empty($xml->xpath($xpath0."/device-group"))){
                $devicegroup0=$xml->xpath($xpath0);
                $devicegroup0[0]->addChild("device-group");
            }

            if (empty($xml->xpath($xpath0."/device-group/entry[@name='$devicegroup']"))){
                $devicegroup0=$xml->xpath($xpath0."/device-group");
                $myDG = $devicegroup0[0]->addChild("entry");
                $myDG->addAttribute('name', $devicegroup);
            }
            else{
                $devicegroup0=$xml->xpath($xpath0."/device-group/entry[@name='$devicegroup']");
                $myDG = $devicegroup0[0];
            }

            if ((!isset($myDG->description)) AND ($dg_description!="") ){
                $myDG->addChild("description");
                $myDG->description=$dg_description;
            }
            if ($dg_description!=""){
                $myDG->description=$dg_description;
            }

            if ($dg_devices != "")  {
               $xml_append = simplexml_load_string(clean_xml($dg_devices));
                if (isset($myDG->devices)){
                    unset($myDG->devices);
                    //$SA=$myDG->xpath("/devices");
                    //unset($SA[0]);
                    SimpleXMLElement_append($myDG, $xml_append);
                }
                else{
                    $myDG->addChild("devices");
                    SimpleXMLElement_append($myDG, $xml_append);
                }
            }

            if (($dg_master_device != "") AND ($dg_master_device!="None")) {
                $xml_append = simplexml_load_string(clean_xml($dg_master_device));
                if (isset($myDG->{'master-device'})){
                    unset($myDG->{'master-device'});
                    SimpleXMLElement_append($myDG, $xml_append);
                }
                else{
                    $myDG->addChild("master-device");
                    SimpleXMLElement_append($myDG, $xml_append);
                }
            }

            if ($api_call=="single"){
                $myDGFake = new SimpleXMLElement("<entry/>");
                $myDGFake->addAttribute('name', $devicegroup);

                if ((!isset($myDGFake->description)) AND ($dg_description!="") ){
                    $myDGFake->addChild("description");
                    $myDGFake->description=$dg_description;
                }
                if ($dg_description!=""){
                    $myDGFake->description=$dg_description;
                }

                if ($dg_devices != "")  {
                    $xml_append = simplexml_load_string(clean_xml($dg_devices));
                    if (isset($myDGFake->devices)){
                        unset($myDGFake->devices);
                        SimpleXMLElement_append($myDGFake, $xml_append);
                    }
                    else{
                        $myDGFake->addChild("devices");
                        SimpleXMLElement_append($myDGFake, $xml_append);
                    }
                }

                if (($dg_master_device != "") AND ($dg_master_device!="None")) {
                    $xml_append = simplexml_load_string(clean_xml($dg_master_device));
                    if (isset($myDGFake->{'master-device'})){
                        unset($myDGFake->{'master-device'});
                        SimpleXMLElement_append($myDGFake, $xml_append);
                    }
                    else{
                        $myDGFake->addChild("master-device");
                        SimpleXMLElement_append($myDGFake, $xml_append);
                    }
                }

                $xpath2 = addslashes($xpath0."/device-group");
                $element=$myDGFake;
                $xml_final = $element[0]->asXML();
                $xml_final0=str_replace("<?xml version=\"1.0\"?>","",$xml_final);
                $xml_final=addslashes($xml_final0);
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$devicegroup','Device-Group Definition','Device-Group Definition','$xml_final','$xpath2','set');");
            }

        } else {
            $message['code'] = false;
            $message['msg'] = "Invalid Device-Group Name: $devicegroup";
            return $message;
        }
    }
    else{
        $message['code'] = false;
        $message['msg'] = "It's not a Panorama config.";
        return $message;
    }
}

function xml_template($xml,$data){
    $project = $data['project'];
    $ispanorama = $data['ispanorama'];
    $version = $data['version'];
    $api_call=$data['api_call'];
    $projectdb = $data['projectdb'];
    $source = $data['source'];
    $template = $data['template'];
    $template_name=$data['template_name'];

    if ($ispanorama==1){

        $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']";
        $xpath0=$data['xpath0'];

        $getTemplateInfo = $projectdb->query("SELECT * FROM templates WHERE templates_mapping_id='$template';");
        if ($getTemplateInfo->num_rows == 1) {
            $getTemplateInfoData = $getTemplateInfo->fetch_assoc();
            $template_description = $getTemplateInfoData['description'];
            $template_multi_vsys = $getTemplateInfoData['multi_vsys'];
            $template_operational_mode = strtolower($getTemplateInfoData['operational_mode']);
            $template_vpn_disable_mode = $getTemplateInfoData['vpn_disable_mode'];
            $template_devices = $getTemplateInfoData['devices'];
            $default_vsys=$getTemplateInfoData['default_vsys'];

            if (empty($xml->xpath($xpath0."/template"))){
                $devicegroup0=$xml->xpath($xpath0);
                $devicegroup0[0]->addChild("template");
            }

            if (empty($xml->xpath($xpath0."/template/entry[@name='$template_name']"))){
                $devicegroup0=$xml->xpath($xpath0."/template");
                $myTemplate = $devicegroup0[0]->addChild("entry");
                $myTemplate->addAttribute('name', $template_name);
            }
            else{
                $devicegroup0=$xml->xpath($xpath0."/template/entry[@name='$template_name']");
                $myTemplate = $devicegroup0[0];
            }

            if (!isset($myTemplate->settings)){
                $myTemplate->addChild("settings");
            }

            //MT-1613 Issues with API output manager. Warning: SimpleXMLElement::xpath(): xmlXPathEval: evaluation failed in /var/www/html/libs/common/xml/panosxml.php on line 300
            if($default_vsys != ""){
                if (!empty($xml->xpath($xpath0."/template/entry[@name='$template_name']/config/devices/entry[@name='localhost.localdomain']/vsys/$default_vsys"))){
                    if (!isset($myTemplate->settings->{'default-vsys'})){
                        $myTemplate->settings->addChild("default-vsys");
                    }
                    $myTemplate->settings->{'default-vsys'}=$default_vsys;
                }
            }

            if ($template_devices != "")  {
                $xml_append = simplexml_load_string(clean_xml($template_devices));
                if (isset($myTemplate->devices)){
                    unset($myTemplate->devices);
                    SimpleXMLElement_append($myTemplate, $xml_append);
                }
                else{
                    $myTemplate->addChild("devices");
                    SimpleXMLElement_append($myTemplate, $xml_append);
                }
            }

            if (empty($xml->xpath($xpath0."/template/entry[@name='$template_name']/config"))){
                $myTemplate->addChild("config");
                $myTemplate->config->addChild("devices");
                $templateEntry=$myTemplate->config->devices->addChild("entry");
                $templateEntry->addAttribute("name","localhost.localdomain");
            }

            if ((!isset($myTemplate->description)) AND ($template_description!="") ){
                $myTemplate->addChild("description");
                $myTemplate->description=$template_description;
            }
            if ($template_description!=""){
                $myTemplate->description=$template_description;
            }

            if ($version<7){
                if ($template_vpn_disable_mode != "") {
                    $myTemplate->settings->addChild("vpn-disable-mode", $template_vpn_disable_mode);
                }
                if ($template_operational_mode != "") {
                    $myTemplate->settings->addchild("operational-mode", $template_operational_mode);
                }
                if ($template_multi_vsys == "yes") {
                    $myTemplate->settings->addchild("multi-vsys", "yes");
                }
            }


            if ($api_call=="single"){
                $myTemplateFake = new SimpleXMLElement("<entry/>");
                $myTemplateFake->addAttribute('name', $template_name);
                /*if (!isset($myTemplateFake->settings)) {
                    $myTemplateFake->addChild("settings");
                    if (!isset($myTemplateFake->settings->{'default-vsys'})) {
                        $myTemplateFake->settings->addChild("default-vsys");
                    }
                }
                $myTemplateFake->settings->{'default-vsys'}=$default_vsys;
                */
                if ((!isset($myTemplateFake->description)) AND ($template_description!="") ){
                    $myTemplateFake->addChild("description");
                    $myTemplateFake->description=$template_description;
                }
                if ($template_description!=""){
                    $myTemplateFake->description=$template_description;
                }


                if ($version<7){
                    if ($template_vpn_disable_mode != "") {
                        $myTemplateFake->settings->addChild("vpn-disable-mode", $template_vpn_disable_mode);
                    }
                    if ($template_operational_mode != "") {
                        $myTemplateFake->settings->addchild("operational-mode", $template_operational_mode);
                    }
                    if ($template_multi_vsys == "yes") {
                        $myTemplateFake->settings->addchild("multi-vsys", "yes");
                    }
                }

                if ($template_devices != "")  {
                    $xml_append = simplexml_load_string(clean_xml($template_devices));
                    if (isset($myTemplateFake->devices)){
                        unset($myTemplateFake->devices);
                        SimpleXMLElement_append($myTemplateFake, $xml_append);
                    }
                    else{
                        $myTemplateFake->addChild("devices");
                        SimpleXMLElement_append($myTemplateFake, $xml_append);
                    }
                }
                $xpath2 = addslashes($xpath0."/template");
                $element=$myTemplateFake;
                $xml_final = $element[0]->asXML();
                $xml_final0=str_replace("<?xml version=\"1.0\"?>","",$xml_final);
                $xml_final=addslashes($xml_final0);
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$template_name','Template Definition','Template Definition','$xml_final','$xpath2','set');");


            }
        }
       /* if ($api_call=="mega"){
            $xpath2 = addslashes($xpath0."/template/entry[@name='$template_name']");
            $element=$myTemplate;
            $xml_final = addslashes($element[0]->asXML());
            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$template_name','Template','Template','$xml_final','$xpath2','edit');");
        } */
    }
    else{
        $message['code'] = false;
        $message['msg'] = "It's not a Panorama config.";
        return $message;
    }
}

function xml_mgt_config_password_complexity($xml,$data){
    $project = $data['project'];
    $ispanorama = $data['ispanorama'];
    $version = $data['version'];
    $api_call=$data['api_call'];
    $projectdb = $data['projectdb'];
    $source = $data['source'];
    $template = $data['template'];
    $xpath0=$data['xpath0'];
    $xpath_parent=$data['xpath_parent'];
    if ($ispanorama==0){
        $getBanner=$projectdb->query("SELECT xml FROM password_complexity WHERE source='$source' AND template='0';");
    }
    else{
        $getBanner=$projectdb->query("SELECT xml FROM password_complexity WHERE source='$source' AND template='$template';");
    }

    if ($getBanner->num_rows==1) {
        $getBannerData = $getBanner->fetch_assoc();
        if ($getBannerData['xml']!=""){
            $myBannerRaw=simplexml_load_string(clean_xml($getBannerData['xml']));
            #Remove from the BaseConfig

            $test=$xml->xpath($xpath0);
            if (count($test)==0){
                $base=$xml->xpath($xpath_parent);
                if (!isset($base->config)){
                    $base[0]->addChild("config");
                }
                if (!isset($base->config->{'mgt-config'})){
                    $base[0]->config->addChild("mgt-config");
                }
            }
            if ($xml->xpath($xpath0.'/password-complexity')){
                $deviceconfig=$xml->xpath($xpath0.'/password-complexity');
                unset($deviceconfig[0][0]);
                $deviceconfig=$xml->xpath($xpath0);
                SimpleXMLElement_append($deviceconfig[0], $myBannerRaw);
            }
            else{
                $temp=$xml->xpath($xpath0);
                SimpleXMLElement_append($temp[0], $myBannerRaw);
            }

            #Api-Call
            if ( (isset($api_call)) and ($api_call=="single") ){
                $xpath = addslashes($xpath0."/password-complexity");
                $xml_final = addslashes($getBannerData['xml']);
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Password Complexity','Config MGT','Config MGT','$xml_final','$xpath','edit');");
            }
        }
        $message['code']=true;
        $message['msg']="Password Complexity Added";
    }
    else{
        $message['code']=false;
        $message['msg']="Password Complexity xml not found for source: $source and Template $template";
    }
    return $message;
}

function xml_mgt_config($xml,$data){
    $project = $data['project'];
    $ispanorama = $data['ispanorama'];
    $version = $data['version'];
    $api_call=$data['api_call'];
    $projectdb = $data['projectdb'];
    $source = $data['source'];
    $template = $data['template'];
    $template_name=$data['template_name'];

    if ($template!=0){
        if ($ispanorama==0){
            $data['xpath0']='/config/mgt-config';
            $data['xpath_parent']="";
        }
        else{
            $data['xpath0']="/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='".$template_name."']/config/mgt-config";
            $data['xpath_parent']="/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='".$template_name."']";
        }
    }
    else{
        $data['xpath0']='/config/mgt-config';
        $data['xpath_parent']="";
    }
    # Apply all changes
    xml_mgt_config_password_complexity($xml,$data);

    if ((isset($api_call)) AND ($api_call=="atomic")){
        $xml_final = $xml->xpath($data['xpath0']);
        if (count($xml_final)>0){
            $xmlpath=addslashes($data['xpath0']);
            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Config MGT','Config MGT','Config MGT','".addslashes($xml_final[0]->asXML())."','$xmlpath','edit');");
        }
    }
}

function xml_response_pages($xml,$data){
    $project = $data['project'];
    $ispanorama = $data['ispanorama'];
    $version = $data['version'];
    $api_call=$data['api_call'];
    $projectdb = $data['projectdb'];
    $source = $data['source'];
    $template = $data['template'];
    $vsys=$data['vsys'];
    $template_name=$data['template_name'];

    if ($template!=0){
        if ($vsys=="shared"){
            if ($ispanorama==0){
                $data['xpath0']="/config/shared";
            }
            else{
                $data['xpath0']="/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='".$template_name."']/config/shared";
            }
        }
        else{
            if ($ispanorama==0){
                $data['xpath0']="/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='".$vsys."']";
            }
            else{
                $data['xpath0']="/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='".$template_name."']/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='".$vsys."']";
            }
        }
    }
    else{
        if ($vsys=="shared"){
            $data['xpath0']="/config/shared";
        }
        else{
            $data['xpath0']="/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='".$vsys."']";
        }
    }

    $xpath0=$data['xpath0'];

    $getBanner=$projectdb->query("SELECT name,type,html FROM response_pages WHERE source='$source' AND vsys = '$vsys' AND template='$template' ORDER BY id;");
    if ($getBanner->num_rows>0) {
        while($getBannerData = $getBanner->fetch_assoc()){
            if ($getBannerData['html']!=""){
                $xmlfield = $getBannerData['html'];
                $xmlname = $getBannerData['type'];
                $reportname = $getBannerData['name'];
                $xpath1=$data['xpath0'].'/response-page/'.$xmlname;
                #Remove from the Response-Page
                if ($reportname != "") {
                    $responsepage=$xml->xpath($xpath1);
                    if (!isset($responsepage[0])) {
                        $testxml=$xml->xpath($xpath0."/response-page");
                        if(!isset($testxml[0])){
                            $testxml=$xml->xpath($xpath0);
                            $testxml[0]->addChild('response-page');
                        }
                        $testxml[0]->{'response-page'}->addChild($xmlname);
                        $newrp = $testxml[0]->{'response-page'}->{$xmlname}->addChild("entry");
                        $newrp->addAttribute('name', $reportname);
                        $newrp->addChild("page");
                        $newrp->page = $xmlfield;
                    } else {

                        $SA = $responsepage[0]->xpath("entry[@name='$reportname']");
                        unset($SA[0][0]);

                        $newrp = $responsepage[0]->addChild("entry");
                        $newrp->addAttribute('name', $reportname);
                        $newrp->addChild("page");
                        $newrp->page = $xmlfield;
                    }

                    #Api-Call
                    if ( (isset($api_call)) and ($api_call=="single") ){
                        $xpath = addslashes($xpath1."/entry[@name='".$reportname."']");
                        $xml_final = addslashes('<entry name="'.$reportname.'"><page>'.$xmlfield.'</page></entry>');
                        $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$reportname','Response Page','Response Page','$xml_final','$xpath','edit');");
                    }
                }
                else {
                    $SA=$xml->xpath($xpath1);
                    unset($SA[0][0]);
                    $xmlfield = clean_xml($xmlfield);
                    $xml_append = simplexml_load_string("<$xmlname>$xmlfield</$xmlname>");
                    $responsepage=$xml->xpath($xpath0);
                    SimpleXMLElement_append($responsepage[0]->{'response-page'}, $xml_append);

                    #Api-Call
                    if ( (isset($api_call)) and ($api_call=="single") ){
                        $xpath = addslashes($xpath1);
                        $xml_final = addslashes("<$xmlname>$xmlfield</$xmlname>");
                        $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$xmlname','Reponse Page','Reponse Page','$xml_final','$xpath','edit');");
                    }
                }


            }
            $message['code']=true;
            $message['msg']="Response-page Template $template and vsys $vsys added";
        }

        if ((isset($api_call)) AND ($api_call=="atomic")){
            $xml_final = $xml->xpath($data['xpath0']."/response-page");
            $xmlpath=addslashes($data['xpath0']."/response-page");
            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Response Pages','Response Pages','Response Pages','".addslashes($xml_final[0]->asXML())."','$xmlpath','edit');");
        }
    }
    else{
        $message['code']=false;
        $message['msg']="Response-page html not found for source: $source and Template $template on vsys $vsys";
    }
    return $message;



}

function xml_panorama_readonly($xml,$data){
    $project = $data['project'];
    $ispanorama = $data['ispanorama'];
    $version = $data['version'];
    $api_call=$data['api_call'];
    $projectdb = $data['projectdb'];
    $source = $data['source'];
    $CreateReadOnly=true;

    if (($ispanorama==1) AND ($version>=8)){
        $getMax=$projectdb->query("SELECT b.max_internal_id as max_internal_id, a.vsys as dgname, b.internal_id as internal_id, a.id as device_mapping_id, b.parent_dg as parent_dg 
            FROM device_mapping a, devicegroups b 
            WHERE a.id=b.device_mapping_id AND b.source='$source' AND a.vsys!='shared';");
        if ($getMax->num_rows>0){
            while($getMaxData=$getMax->fetch_assoc()) {
                $dgname=$getMaxData['dgname'];
                $max_internal_id = $getMaxData['max_internal_id'];
                $device_mapping_id=$getMaxData['device_mapping_id'];
                $parent_dg=$getMaxData['parent_dg'];
                $internal_id=$getMaxData['internal_id'];
                $parent_dg_name="";


                if ($max_internal_id==0){
                    $CreateReadOnly=false;
                }


                if ($CreateReadOnly===true){
                    $getParent=$projectdb->query("SELECT vsys FROM device_mapping WHERE id='$parent_dg';");
                    if ($getParent->num_rows==1){
                        $getParentData=$getParent->fetch_assoc();
                        $parent_dg_name=$getParentData['vsys'];
                    }

                    $readonlyExists=$xml->xpath("/config/readonly");
                    if (count($readonlyExists)==0){
                        $myreadonly=$xml->xpath("/config");
                        $myreadonly[0]->addChild("readonly");
                        $myreadonly[0]->readonly->addChild("devices");
                        $readonlyentry=$myreadonly[0]->readonly->devices->addChild("entry");
                        $readonlyentry->addAttribute('name', 'localhost.localdomain');
                        $readonlyentry->addChild('device-group');
                    }


                    $readonly=$xml->xpath("/config/readonly/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='".$dgname."']");
                    $isnew=0;
                    if (count($readonly)>0){
                        $newdg=$readonly[0];
                        if(!isset($newdg->id)){
                            $newdg->addChild("id",$internal_id);
                        }
                        else{
                            $newdg->id=$internal_id;
                        }

                        # This never should be executed but we found a case where it came
                        if (isset($newdg->{'parent-dg'}) AND ($newdg->{'parent-dg'}=="shared")){
                            unset($newdg->{'parent-dg'});
                        }

                        if ($parent_dg_name!="shared"){
                            if (!isset($newdg->{'parent-dg'})){
                                $newdg->addChild("parent-dg",$parent_dg_name);
                            }
                            else{
                                $newdg->{'parent-dg'}=$parent_dg_name;
                            }
                        }
                    }
                    else{
                        $isnew=1;
                        $readonly=$xml->xpath("/config/readonly/devices/entry[@name='localhost.localdomain']/device-group");
                        $newdg=$readonly[0]->addChild("entry");
                        $newdg->addAttribute('name', $dgname);

                        $newdg->addChild("id",$internal_id);
                        if ($parent_dg_name!="shared"){
                            $newdg->addChild("parent-dg",$parent_dg_name);
                        }
                    }


                    #Prepare Api calls
                    $parentdg="";
                    $xml_final0="";
                    if ($parent_dg_name!="shared"){
                        $parentdg="<new-parent-dg>$parent_dg_name</new-parent-dg>";
                    }
                    if ($isnew==1){
                        $xml_final0 = '<entry name="'.$dgname.'"><create-dg>yes</create-dg>'.$parentdg.'</entry>';
                    }
                    else{
                        if ($parent_dg_name!="shared"){$xml_final0 = '<entry name="'.$dgname.'">'.$parentdg.'</entry>';}
                        else{
                            $xml_final0 = '<entry name="'.$dgname.'"/>';
                        }
                    }

                    if((($api_call=="single") OR ($api_call=="atomic")) AND ($xml_final0!="")){
                        $xml_final="<request><move-dg>".$xml_final0."</move-dg></request>";
                        $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('readOnly','Device Group hierarchy','Device Group hierarchy','".addslashes($xml_final)."','$dgname','op');");
                    }
                    $readonly=$xml->xpath('/config/readonly');
                    $readonly[0]->{'max-internal-id'}=$max_internal_id;
                }
                else{
                    $readonlyExists=$xml->xpath("/config/readonly");
                    $SA=$xml->xpath($readonlyExists);
                    unset($SA[0][0]);
                }

            }

            $message['code']=true;
            $message['msg']="ReadOnly generated.";
        }
    }
    elseif (($ispanorama==1) AND ($version>=7)){
        $getMax=$projectdb->query("SELECT b.max_internal_id as max_internal_id, a.vsys as dgname, b.internal_id as internal_id, a.id as device_mapping_id, b.parent_dg as parent_dg 
            FROM device_mapping a, devicegroups b WHERE a.id=b.device_mapping_id AND b.source='$source';");
        if ($getMax->num_rows>0){
            while($getMaxData=$getMax->fetch_assoc()) {
                $dgname=$getMaxData['dgname'];
                $max_internal_id = $getMaxData['max_internal_id'];
                $device_mapping_id=$getMaxData['device_mapping_id'];
                $parent_dg=$getMaxData['parent_dg'];
                $internal_id=$getMaxData['internal_id'];
                $parent_dg_name="";
                if ($parent_dg!=0){
                    $getParent=$projectdb->query("SELECT vsys FROM device_mapping WHERE id='$parent_dg';");
                    if ($getParent->num_rows==1){
                        $getParentData=$getParent->fetch_assoc();
                        $parent_dg_name=$getParentData['vsys'];
                    }
                }
                $readonly=$xml->xpath("/config/readonly/dg-meta-data/dginfo/entry[@name='".$dgname."']");
                $isnew=0;
                if (count($readonly)>0){$domRef = dom_import_simplexml($readonly[0]);$domRef->parentNode->removeChild($domRef);}else{$isnew=1;}
                $readonly=$xml->xpath('/config/readonly/dg-meta-data/dginfo');
                $newdg=$readonly[0]->addChild("entry");
                $newdg->addAttribute('name', $dgname);
                $newdg->addChild("dg-id",$internal_id);
                if ($parent_dg_name!=""){
                    $newdg->addChild("parent-dg",$parent_dg_name);
                }
                #Prepare Api calls
                $parentdg="";
                $xml_final0="";
                if ($parent_dg_name!=""){
                    $parentdg="<new-parent-dg>$parent_dg_name</new-parent-dg>";
                }
                if ($isnew==1){
                    $xml_final0 = '<entry name="'.$dgname.'"><create-dg>yes</create-dg>'.$parentdg.'</entry>';
                }
                else{
                    if ($parent_dg_name!=""){$xml_final0 = '<entry name="'.$dgname.'">'.$parentdg.'</entry>';}
                }

                if((($api_call=="single") OR ($api_call=="atomic")) AND ($xml_final0!="")){
                    $xml_final="<request><move-dg>".$xml_final0."</move-dg></request>";
                    $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('readOnly','Device Group hierarchy','Device Group hierarchy','".addslashes($xml_final)."','$dgname','op');");
                }
            }
            $readonly=$xml->xpath('/config/readonly/dg-meta-data');
            $readonly[0]->{'max-dg-id'}=$max_internal_id;

            $message['code']=true;
            $message['msg']="ReadOnly generated.";
        }
    }
    else{
        $message['code']=false;
        $message['msg']="Readonly only applies to Panorama devices and Panos 7 and above. Skipping...";
    }
    return $message;

}

function xml_reports($xml,$data){
    $project = $data['project'];
    $ispanorama = $data['ispanorama'];
    $version = $data['version'];
    $api_call=$data['api_call'];
    $projectdb = $data['projectdb'];
    $source = $data['source'];
    $vsys=$data['vsys'];
    #$data['xpath0']="/config/shared";
    #$xpath0=$data['xpath0'];


    if ($vsys=="shared"){
        $data['xpath0']="/config/shared";
    }
    else{
        if ($ispanorama==1){
            $data['xpath0']="/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='".$vsys."']";
        }
        else{
            $data['xpath0']="/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='".$vsys."']";
        }
    }
    $xpath0=$data['xpath0'];


    if ($vsys!=""){
        $getShared = $projectdb->query("SELECT * FROM reports WHERE source='$source' AND vsys='$vsys' ORDER BY id;");
        if ($getShared->num_rows > 0) {
            # Remove all Reports from Base config
            $SA = $xml->xpath($xpath0."/reports");
            unset($SA[0][0]);

            $testxml=$xml->xpath($xpath0."/reports");
            if(!isset($testxml[0])){
                $testxml=$xml->xpath($xpath0);
                $testxml[0]->addChild('reports');
            }

            $theProfiles2 = $xml->xpath($xpath0."/reports");
            $theProfiles = $theProfiles2[0];
            while ($data2 = $getShared->fetch_assoc()) {
                $reportname = $data2['name'];
                $reporttype=$data2['type'];
                $reportperiod=$data2['period'];
                $reporttopn=$data2['topn'];
                $reporttopm=$data2['topm'];
                $reportcaption=$data2['caption'];
                $reportstarttime=$data2['starttime'];
                $reportendtime=$data2['endtime'];
                $reportquery=$data2['query'];
                $reportfrequency=$data2['frequency'];
                $reportdescription=$data2['description'];

                if ($reportname != "") {

                    $report = $theProfiles->addChild('entry');
                    $report->addAttribute('name', $reportname);
                    if ($reporttype!=""){
                        $xml_append = simplexml_load_string(clean_xml($reporttype));
                        SimpleXMLElement_append($report, $xml_append);
                    }
                    if ($reportcaption!=""){
                        $report->addChild("caption");
                        $report->caption=$reportcaption;
                    }
                    if ($reportperiod!=""){
                        $report->addChild("period");
                        $report->period=$reportperiod;
                    }
                    else{
                        $report->addChild("start-time");
                        $report->{'start-time'}=$reportstarttime;
                        $report->addChild("end-time");
                        $report->{'end-time'}=$reportendtime;
                    }
                    if ($reporttopn!=""){
                        $report->addChild("topn");
                        $report->topn=$reporttopn;
                    }
                    if ($reporttopm!=""){
                        $report->addChild("topm");
                        $report->topm=$reporttopm;
                    }
                    if ($reportquery!=""){
                        $report->addChild("query");
                        $report->query=$reportquery;
                    }
                    if ($reportfrequency!=""){
                        $report->addChild("frequency");
                        $report->frequency=$reportfrequency;
                    }
                    if ($version>=8){
                        if ($reportdescription!=""){
                            $report->addChild("description");
                            $report->description=$reportdescription;
                        }
                    }

                    #Api-Call
                    if ( (isset($api_call)) and ($api_call=="single") ){
                        $xpath = addslashes($xpath0."/reports/entry[@name='".$reportname."']");
                        $xml_final = addslashes($report->asXML());
                        $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$reportname','Reports','Reports','$xml_final','$xpath','edit');");
                    }




                }

            }
            if ((isset($api_call)) AND ($api_call=="atomic")){
                $xml_final = $xml->xpath($data['xpath0']."/reports");
                $xmlpath=addslashes($data['xpath0']."/reports");
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Reports','Reports','Reports','".addslashes($xml_final[0]->asXML())."','$xmlpath','edit');");
            }
            $message['code']=true;
            $message['msg']="Reports Added";
        }
        else{
            $SA = $xml->xpath($xpath0."/reports");
            unset($SA[0][0]);
            $message['code']=true;
            $message['msg']="Removed all Reports since there is no one on the database";
        }
    }
    else{
        $message['code']=false;
        $message['msg']="Reports must be placed only in Shared. ".$vsys." Received instead. Skipping...";
    }
    return $message;
}

function xml_log_settings($xml,$data){
    # log-settings in the device can be stored as shared or per vsys
    # In panorama de local log-settings are stored under panorama tag then per template can be under shared or per vsys

    $project = $data['project'];
    $ispanorama = $data['ispanorama'];
    $version = $data['version'];
    $api_call=$data['api_call'];
    $projectdb = $data['projectdb'];
    $source = $data['source'];
    $template = $data['template'];
    $vsys=$data['vsys'];
    $template_name=$data['template_name'];

//    if ($template!=0){
        if ($vsys=="shared"){
            if ($ispanorama==0){
                $data['xpath0']="/config/shared";
            }
            else{
                $data['xpath0']="/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='".$template_name."']/config/shared";
            }
        }
        else{
            if ($ispanorama==0){
                $data['xpath0']="/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='".$vsys."']";
            }
            else{
                $data['xpath0']="/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='".$template_name."']/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='".$vsys."']";
            }
        }
//    }
//    else{
//        $message['code']=false;
//        $message['msg']="Log-settings for Panorama are under the Panorama tag. Skipping...";
//        return $message;
//    }

    $xpath0=$data['xpath0'];


    $getShared = $projectdb->query("SELECT type FROM log_settings WHERE source='$source' AND vsys = '$vsys'  AND template='$template' AND type!='profiles' AND dummy = 0 GROUP BY type ORDER BY id;");
    if ($getShared->num_rows > 0) {
        $check=$xml->xpath($xpath0."/log-settings");
        if (count($check)==0) {
            $SA=$xml->xpath($xpath0);
            if (count($SA)>0){
                $SA[0]->addChild('log-settings');
            }
            else{
                $message['code']=false;
                $message['msg']="No Template";
                return $message;
            }

        } else {
//            #DELETE SHARED LOG SETTINGS
//            #Save the profiles
//            if (count($xml->xpath($xpath0."/log-settings/profiles"))>0){
//                $saveProfiles=$xml->xpath($xpath0."/log-settings/profiles");
//            }
//
//
//            $SA = $xml->xpath($xpath0."/log-settings");
//            unset($SA[0]);
//
//            if (count($saveProfiles[0])>0){
//                $theProfiles = $xml->xpath($xpath0."/log-settings");
//                $theProfiles1=$theProfiles[0]->addChild("profiles");
//                SimpleXMLElement_append($theProfiles1[0], $saveProfiles[0]);
//            }

            //$SA = $xml->xpath($xpath0);
            //$SA[0]->addChild('log-settings');
        }
        $theProfiles = $xml->xpath($xpath0."/log-settings");
        while ($Data = $getShared->fetch_assoc()) {
            $type = $Data['type'];
            unset($theProfiles[0]->{$type});
            $thetype = $theProfiles[0]->{$type};
            if (empty($thetype)) {
                $thetype = $theProfiles[0]->addChild($type);
            }

            $getbyType = $projectdb->query("SELECT xml,name FROM log_settings WHERE source='$source' AND vsys = '$vsys' AND type='$type' AND template='$template' AND dummy = 0 ORDER BY id;");
            if ($getbyType->num_rows > 0) {
                while ($data2 = $getbyType->fetch_assoc()) {
                    $xmlfield = $data2['xml'];
                    $xmlname = $data2['name'];
                    $xml_append = simplexml_load_string(clean_xml($xmlfield));
                    if ($xml->xpath($xpath0."/log-settings/$type/entry[@name='$xmlname']") != null) {
                        //add_log('warning', 'Exporting Shared Log Settings', 'Object Duplicated in Destination [' . $xmlname . ']', $source, 'Object was Not Migrated');
                    } else {
                        SimpleXMLElement_append($thetype, $xml_append);
                        #Api-Call
                        if ( (isset($api_call)) and ($api_call=="single") ){
                            if (($type == "config") OR ($type=="system") OR ($type=="hipmatch") OR ($type=="traffic") OR ($type=="threat") OR ($type=="wildfire") OR ($type=="correlation") OR ($type=="userid") OR ($type=="iptag") OR ($type=="globalprotect") ){
                                $xmlname=$type;
                                $xpath = addslashes($xpath0."/log-settings/$type");
                                $xml_final = addslashes($thetype->asXML());
                            }
                            else{
                                $xpath = addslashes($xpath0."/log-settings/$type/entry[@name='$xmlname']");
                                $temp = $thetype->xpath($xpath0."/log-settings/$type/entry[@name='$xmlname']");
                                $xml_final = addslashes($temp[0]->asXML());
                            }
                            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$xmlname','Log Settings','Log Settings','$xml_final','$xpath','edit');");
                        }
                    }
                }
            }
        }

        if ((isset($api_call)) AND ($api_call=="atomic")){
            $xml_final = $xml->xpath($data['xpath0']."/log-settings");
            $xmlpath=addslashes($data['xpath0']."/log-settings");
            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Log Settings','Log Settings','Log Settings','".addslashes($xml_final[0]->asXML())."','$xmlpath','edit');");
        }

        $message['code']=true;
        $message['msg']="All Log-settings Updated.";
        return $message;
    }
    else {
        #DELETE LOG SETTINGS
        $SA = $xml->xpath($xpath0."/log-settings");
        foreach ($SA as $item => $code){
            if ($item!="profiles"){
                unset($code[0]);
            }
        }
        //unset($SA[0][0]);
        $message['code']=true;
        $message['msg']="All Log-settings Removed";
        return $message;
    }
}

function xml_log_settings_profiles($xml,$data){
    # log-settings in the device can be stored as shared or per vsys
    # In panorama de local log-settings are stored under panorama tag then per template can be under shared or per vsys

    $project = $data['project'];
    $ispanorama = $data['ispanorama'];
    $version = $data['version'];
    $api_call=$data['api_call'];
    $projectdb = $data['projectdb'];
    $source = $data['source'];
    $template = $data['template'];
    $vsys=$data['vsys'];
    $template_name=$data['template_name'];

    if ($vsys=="shared"){
        $data['xpath0']="/config/shared";
    }
    else{
        if ($ispanorama==0){
            $data['xpath0']="/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='".$vsys."']";
        }
        else{
            $data['xpath0']="/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='".$vsys."']";
        }
    }

    $xpath0=$data['xpath0'];


    $getShared = $projectdb->query("SELECT type FROM log_settings WHERE source='$source' AND vsys = '$vsys'  AND template='$template' AND dummy = 0 AND type='profiles' GROUP BY type ORDER BY id;");
    if ($getShared->num_rows > 0) {
        $check=$xml->xpath($xpath0."/log-settings/profiles");

        if (count($check)==0) {
            $SA=$xml->xpath($xpath0."/log-settings");
            if (count($SA)>0){
                $SA[0]->addChild('profiles');
            }
            else{
                $message['code']=false;
                $message['msg']="No Template";
                return $message;
            }

        } else {
            #DELETE SHARED LOG SETTINGS
//            $SA = $xml->xpath($xpath0."/log-settings/profiles");
//            unset($SA[0]);
            //$SA = $xml->xpath($xpath0);
            //$SA[0]->addChild('log-settings');
        }
        $theProfiles = $xml->xpath($xpath0."/log-settings");
        while ($Data = $getShared->fetch_assoc()) {
            $type = $Data['type'];
            unset($theProfiles[0]->{$type});
            $thetype = $theProfiles[0]->{$type};
            if (empty($thetype)) {
                $thetype = $theProfiles[0]->addChild($type);
            }

            $getbyType = $projectdb->query("SELECT xml,name FROM log_settings WHERE source='$source' AND vsys = '$vsys' AND type='$type' AND template='$template' AND dummy = 0 ORDER BY id;");
            if ($getbyType->num_rows > 0) {
                while ($data2 = $getbyType->fetch_assoc()) {
                    $xmlfield = $data2['xml'];
                    $xmlname = $data2['name'];
                    $xml_append = simplexml_load_string(clean_xml($xmlfield));
                    if ($xml->xpath($xpath0."/log-settings/$type/entry[@name='$xmlname']") != null) {
                        //add_log('warning', 'Exporting Shared Log Settings', 'Object Duplicated in Destination [' . $xmlname . ']', $source, 'Object was Not Migrated');
                    } else {
                        SimpleXMLElement_append($thetype, $xml_append);
                        #Api-Call
                        if ( (isset($api_call)) and ($api_call=="single") ){

                            if (($type == "config") OR ($type=="system") OR ($type=="hipmatch") OR ($type=="traffic") OR ($type=="threat") OR ($type=="wildfire") OR ($type=="correlation") OR ($type=="userid") OR ($type=="iptag")){
                                $xmlname = $type;
                                $xpath = addslashes($xpath0."/log-settings/$type");
                                $xml_final = addslashes($thetype->asXML());
                            }
                            else{
                                //echo "XMLNAME 2:" .$xmlname. "\n";
                                $xpath = addslashes($xpath0."/log-settings/$type/entry[@name='$xmlname']");
                                //echo "The type\n";
                                //print_r($thetype);
                                $temp = $thetype->xpath($xpath0."/log-settings/$type/entry[@name='$xmlname']");
                                //echo "El temp \n";
                                //print_r($temp);
                                $xml_final = addslashes($temp[0]->asXML());
                            }
                            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$xmlname','Log Settings','Log Settings','$xml_final','$xpath','edit');");
                            //echo "1. INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$xmlname','Log Settings','Log Settings','$xml_final','$xpath','edit');\n";
                        }
                    }
                }
            }
        }

        if ((isset($api_call)) AND ($api_call=="atomic")){
            $xml_final = $xml->xpath($data['xpath0']."/log-settings");
            $xmlpath=addslashes($data['xpath0']."/log-settings");
            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Log Settings','Log Settings','Log Settings','".addslashes($xml_final[0]->asXML())."','$xmlpath','edit');");
        }

        $message['code']=true;
        $message['msg']="All Log-settings Updated.";
        return $message;
    }
    else {
        #DELETE LOG SETTINGS
        if ($template==0){
            $SA = $xml->xpath($xpath0."/log-settings/profiles");
            unset($SA[0][0]);
            $message['code']=true;
            $message['msg']="All Log-settings Removed";
            return $message;
        }

    }
}

function xml_log_settings_dg($xml,$data){
    # log-settings in the device can be stored as shared or per vsys
    # In panorama de local log-settings are stored under panorama tag then per template can be under shared or per vsys

    $project = $data['project'];
    $ispanorama = $data['ispanorama'];
    $version = $data['version'];
    $api_call=$data['api_call'];
    $projectdb = $data['projectdb'];
    $source = $data['source'];
    $template = 0;
    $vsys=$data['vsys'];
    $template_name=$data['template_name'];

    if ($vsys=="shared"){
        $data['xpath0']="/config/shared";
    }
    else{
        if ($ispanorama==0){
            $data['xpath0']="/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='".$vsys."']";
        }
        else{
            $data['xpath0']="/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='".$vsys."']";
        }
    }

    $xpath0=$data['xpath0'];

    $getShared = $projectdb->query("SELECT type FROM log_settings WHERE source='$source' AND vsys = '$vsys' AND template='$template' AND type!='profiles' AND dummy = 0 GROUP BY type ORDER BY id;");
    //echo "1. SELECT type FROM log_settings WHERE source='$source' AND vsys = '$vsys' AND template='$template' AND type!='profiles' AND dummy = 0 GROUP BY type ORDER BY id;\n";
    if ($getShared->num_rows > 0) {

        $check=$xml->xpath($xpath0."/log-settings");
        if (count($check)==0) {
            //echo "ENTRA: " .count($check). "\n";
            $SA=$xml->xpath($xpath0);
            $SA[0]->addChild('log-settings');
        } else {
            #DELETE SHARED LOG SETTINGS

//            #Save the profiles
//            if (count($xml->xpath($xpath0."/log-settings/profiles"))>0){
//                $saveProfiles=$xml->xpath($xpath0."/log-settings/profiles");
//            }
//
//
//            $SA = $xml->xpath($xpath0."/log-settings");
//            unset($SA[0]);
//
//            if (count($saveProfiles[0])>0){
//                $theProfiles = $xml->xpath($xpath0."/log-settings");
//                $theProfiles1=$theProfiles[0]->addChild("profiles");
//                SimpleXMLElement_append($theProfiles1[0], $saveProfiles[0]);
//            }
            //$SA = $xml->xpath($xpath0);
            //$SA[0]->addChild('log-settings');
        }
        $theProfiles = $xml->xpath($xpath0."/log-settings");
        while ($Data = $getShared->fetch_assoc()) {
            $type = $Data['type'];
            $getbyType = $projectdb->query("SELECT xml,name FROM log_settings WHERE source='$source' AND vsys = '$vsys' AND type='$type' AND template='$template' AND dummy = 0 ORDER BY id;");
            //echo "2. SELECT xml,name FROM log_settings WHERE source='$source' AND vsys = '$vsys' AND type='$type' AND template='$template' AND dummy = 0 ORDER BY id;\n";
            if ($getbyType->num_rows > 0) {
                unset($theProfiles[0]->{$type});
                $thetype = $theProfiles[0]->{$type};
                if (empty($thetype)) {
                    $thetype = $theProfiles[0]->addChild($type);
                }
                while ($data2 = $getbyType->fetch_assoc()) {
                    $xmlfield = $data2['xml'];
                    $xmlname = $data2['name'];
                    $xml_append = simplexml_load_string(clean_xml($xmlfield));
                    if ($xml->xpath($xpath0."/log-settings/$type/entry[@name='$xmlname']") != null) {
                        //add_log('warning', 'Exporting Shared Log Settings', 'Object Duplicated in Destination [' . $xmlname . ']', $source, 'Object was Not Migrated');
                    } else {
                        SimpleXMLElement_append($thetype, $xml_append);
                        #Api-Call
                        if ( (isset($api_call)) and ($api_call=="single") ){
                            if (($type == "config") OR ($type=="system") OR ($type=="hipmatch") OR ($type=="traffic") OR ($type=="threat") OR ($type=="wildfire") OR ($type=="correlation") OR ($type=="userid") OR ($type=="globalprotect") OR ($type=="syslog") OR ($type=="iptag") OR ($type=="snmptrap")){
                                $xmlname=$type;
                                $xpath = addslashes($xpath0."/log-settings/$type");
                                $xml_final = addslashes($thetype->asXML());
                            }
                            else{
                                $xpath = addslashes($xpath0."/log-settings/$type/entry[@name='$xmlname']");
                                $temp=$thetype->xpath($xpath0."/log-settings/$type/entry[@name='$xmlname']");
                                if(isset($temp[0])) {
                                    $xml_final = addslashes($temp[0]->asXML());
                                }else{
                                    add_log('warning', 'Exporting Shared Log Settings', 'Object not found at path:' . $xpath, $source, 'Object was Not Migrated');
                                }
                            }

                            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$xmlname','Log Settings','Log Settings','$xml_final','$xpath','edit');");
                        }
                    }
                }
            }
        }

        if ((isset($api_call)) AND ($api_call=="atomic")){
            $xml_final = $xml->xpath($data['xpath0']."/log-settings");
            $xmlpath=addslashes($data['xpath0']."/log-settings");
            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Log Settings','Log Settings','Log Settings','".addslashes($xml_final[0]->asXML())."','$xmlpath','edit');");
        }

        $message['code']=true;
        $message['msg']="All Log-settings Updated.";
        return $message;
    }
    else {
        #DELETE LOG SETTINGS
        $SA = $xml->xpath($xpath0."/log-settings");

        foreach ($SA as $item => $code){
            if ($item!="profiles"){
                unset($code[0]);
            }
        }
        //unset($SA[0][0]);
        //unset($SA[0][0]);
        $message['code']=true;
        $message['msg']="All Log-settings Removed";
        return $message;
    }
}

function xml_server_profiles($xml,$data){
    # log-settings in the device can be stored as shared or per vsys
    # In panorama de local log-settings are stored under panorama tag then per template can be under shared or per vsys
    $project = $data['project'];
    $ispanorama = $data['ispanorama'];
    $version = $data['version'];
    $api_call=$data['api_call'];
    $projectdb = $data['projectdb'];
    $source = $data['source'];
    $template = $data['template'];
    $vsys=$data['vsys'];
    $template_name=$data['template_name'];

//    if ($template!=0){
        if ($vsys=="shared"){
            if ($ispanorama==0){
                $template=0;
                $data['xpath0']="/config/shared";
            }
            else{
                $data['xpath0']="/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='".$template_name."']/config/shared";
            }
        }
        else{
            if ($ispanorama==0){
                $data['xpath0']="/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='".$vsys."']";
            }
            else{
                $data['xpath0']="/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='".$template_name."']/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='".$vsys."']";
            }
        }
//    }
//    else{
//        $message['code']=false;
//        $message['msg']="Log-settings for Panorama are under the Panorama tag. Skipping...";
//        return $message;
//    }

    $xpath0=$data['xpath0'];
    $getShared = $projectdb->query("SELECT type FROM server_profile WHERE source='$source' AND vsys = '$vsys' AND template='$template' GROUP BY type;");
    if ($getShared->num_rows>0){
        if (empty($xml->xpath($xpath0."/server-profile"))) {
            $SA=$xml->xpath($xpath0);
            $SA[0]->addChild('server-profile');
        }
        //else {
        //    $SA = $xml->xpath($xpath0."/server-profile");
        //    unset($SA[0]);
        //    $SA=$xml->xpath($xpath0);
        //    $SA[0]->addChild('server-profile');
        //}
        $serverProfile0=$xml->xpath($xpath0."/server-profile");
        $serverProfile=$serverProfile0[0];

        while ($getSharedData=$getShared->fetch_assoc()){
            $server_type=$getSharedData['type'];
            if (!isset($serverProfile->$server_type)){
                $serverProfile->addChild($server_type);
            }
            else{
                $SA=$xml->xpath($xpath0."/server-profile");
                unset($SA[0]->{$server_type});
                $SA[0]->addChild($server_type);
            }

            $getSPMember=$projectdb->query("SELECT name,xml FROM server_profile WHERE source='$source' AND vsys = '$vsys' AND template='$template' AND type='$server_type';");
            if ($getSPMember->num_rows>0){
                while ($getSPMemberData=$getSPMember->fetch_assoc()){
                    $myname=$getSPMemberData['name'];
                    $xmlfield=$getSPMemberData['xml'];

                    if($version >= 7){
                        if($server_type == "radius"){
                            $xmlfield = preg_replace('#<domain>+[^\s]+</domain>#', '', $xmlfield);
                        }
                        if($server_type == "ldap"){
                            $xmlfield = preg_replace('#<domain>+[^\s]+</domain>#', '', $xmlfield);
                        }
                        if($server_type == "kerberos"){
                            $xmlfield2 = preg_replace('#<domain>+[^\s]+</domain>#', '', $xmlfield);
                            $xmlfield = preg_replace('#<realm>+[^\s]+</realm>#', '', $xmlfield2);
                        }
                    }

                    $xml_append = simplexml_load_string(clean_xml($xmlfield));
                    SimpleXMLElement_append($serverProfile->$server_type, $xml_append);

                    if((isset($api_call)) AND ($api_call=="single")){
                        $xpath = addslashes($xpath0."/server-profile/$server_type/entry[@name='$myname']");
                        $xml_final = addslashes($xmlfield);
                        $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','Server Profiles $server_type','Server Profiles $server_type','$xml_final','$xpath','edit');");
                    }
                }
            }

        }
        if ((isset($api_call)) AND ($api_call=="atomic")){
            $xml_final = $xml->xpath($data['xpath0']."/server-profile");
            $xmlpath=addslashes($data['xpath0']."/server-profile");
            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Server Profiles - $vsys','Server Profiles','Server Profiles','".addslashes($xml_final[0]->asXML())."','$xmlpath','edit');");
        }
    }
    else{
        $SA = $xml->xpath($xpath0."/server-profile");
        unset($SA[0][0]);

        if ($api_call=="clean"){
            $xpath = addslashes($xpath0."/server-profile");
            $xml_final = "";
            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Remove All Server Profiles $vsys','Server Profiles','Server Profiles','$xml_final','$xpath','delete');");
        }
        $message['code']=true;
        $message['msg']="Removing all Server Profiles ".$vsys;
        return $message;
    }
}

function xml_profiles($xml,$data,ARRAY &$objectsInMemory=null){
    $project = $data['project'];
    $ispanorama = $data['ispanorama'];
    $version = $data['version'];
    $api_call=$data['api_call'];
    $projectdb = $data['projectdb'];
    $source = $data['source'];
    $vsys=$data['vsys'];

    if ($vsys=="shared"){
        $data['xpath0']="/config/shared";
    }
    else{
        if ($ispanorama==1){
            $data['xpath0']="/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='".$vsys."']";
        }
        else{
            $data['xpath0']="/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='".$vsys."']";
        }
    }
    $xpath0=$data['xpath0'];


    $getShared = $projectdb->query("SELECT type FROM profiles WHERE source='$source' AND vsys = '$vsys' AND  (devicegroup!='predefined' AND devicegroup !='MT_Panorama') GROUP BY type ORDER BY id;");
    if ($getShared->num_rows > 0) {
        $check = $xml->xpath($xpath0."/profiles");
        if (count($check)==0) {
            $SA=$xml->xpath($xpath0);
            $SA[0]->addChild('profiles');
        } else {
            #DELETE SHARED LOG SETTINGS
            $SA = $xml->xpath($xpath0."/profiles");
            unset($SA[0][0]);
            $SA=$xml->xpath($xpath0);
            $SA[0]->addChild('profiles');
        }

        $theProfiles = $xml->xpath($xpath0."/profiles");
        while ($Data = $getShared->fetch_assoc()) {
            $type = $Data['type'];
            $thetype = $theProfiles[0]->{$type};
            if (empty($thetype)) {
                $thetype = $theProfiles[0]->addChild($type);
            }
            $getbyType = $projectdb->query("SELECT id,xml,name FROM profiles WHERE source='$source' AND vsys = '$vsys'  AND (devicegroup!='predefined' AND devicegroup !='MT_Panorama') AND type='$type'  ORDER BY id;");
            if ($getbyType->num_rows > 0) {
                while ($data2 = $getbyType->fetch_assoc()) {
                    $xmlfield = $data2['xml'];
                    $xmlname = $data2['name'];
                    //$objectsInMemory['profiles'][$data2['id']]['name']=$xmlname;
                    if ($version > 5) {
                        if ((strpos($xmlfield, "<packet-capture>yes</packet-capture>") !== false) AND ( $type != "virus")) {
                            $xmlfield = str_replace("<packet-capture>yes</packet-capture>", "<packet-capture>single-packet</packet-capture>", $xmlfield);
                        }
                        if ((strpos($xmlfield, "<packet-capture>no</packet-capture>") !== false) AND ( $type != "virus")) {
                            $xmlfield = str_replace("<packet-capture>no</packet-capture>", "<packet-capture>disable</packet-capture>", $xmlfield);
                        }
                    }

                    if ($version >= 7) {
                        if ((strpos($xmlfield,"<action>block</action>")!== false) AND ($type == "virus")){
                            $xmlfield = str_replace("<action>block</action>", "<action>drop</action>", $xmlfield);
                        }
                        if ((strpos($xmlfield,"<wildfire-action>block</wildfire-action>")!== false) AND ($type == "virus")){
                            $xmlfield = str_replace("<wildfire-action>block</wildfire-action>", "<wildfire-action>drop</wildfire-action>", $xmlfield);
                        }
                        if ((strpos($xmlfield,"<block/>")!== false) AND ($type == "vulnerability")){
                            $xmlfield = str_replace("<block/>", "<drop/>", $xmlfield);
                        }
                        if ((strpos($xmlfield,"<action>forward</action>")!== false) AND ($type == "file-blocking")){
                            $xmlfield = str_replace("<action>forward</action>", "", $xmlfield);
                        }
                        if ((strpos($xmlfield,"<action>continue-and-forward</action>")!== false) AND ($type == "file-blocking")){
                            $xmlfield = str_replace("<action>continue-and-forward</action>", "", $xmlfield);
                        }

                    }
//                    print "XML".PHP_EOL;
//                    print_r($xmlfield);
//                    print "END XML".PHP_EOL;

                    try {
                        $xml_append = simplexml_load_string(clean_xml($xmlfield));
                        SimpleXMLElement_append($thetype, $xml_append);
                    }
                    catch(Exception $e ){
                       //echo $e->getMessage().PHP_EOL;
                       echo "Failed on xml_profiles field:" .$xmlfield;
                       echo "END".PHP_EOL; die();
                    }


                    if ($api_call == "single") {
                        $xpath = addslashes($xpath0."/profiles/$type/entry[@name='$xmlname']");
                        $xml_final = addslashes($xmlfield);
                        $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$xmlname','Profiles','Profiles','$xml_final','$xpath','edit');");
                    }
                }
            }
        }
        if ($api_call == "atomic") {
            $xpath = addslashes($xpath0."/profiles");
            $theProfiles=$xml->xpath($xpath0."/profiles");
            $xml_final = addslashes($theProfiles[0]->asXML());
            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Profiles','Profiles','Profiles','$xml_final','$xpath','edit');");
        }
    }
    else{
        $SA = $xml->xpath($xpath0."/profiles");
        unset($SA[0][0]);

        if ($api_call=="clean"){
            $xpath = addslashes($xpath0."/profiles");
            $xml_final = "";
            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Remove All Profiles $vsys','Profiles','Profiles','$xml_final','$xpath','delete');");
        }
        $message['code']=true;
        $message['msg']="Removing all Profiles Groups";
        return $message;
    }

}

function xml_profiles_groups($xml,$data,ARRAY &$objectsInMemory=null){
    $project = $data['project'];
    $ispanorama = $data['ispanorama'];
    $version = $data['version'];
    $api_call=$data['api_call'];
    $projectdb = $data['projectdb'];
    $source = $data['source'];
    $vsys = $data['vsys'];

    if ($vsys == "shared") {
        $data['xpath0'] = "/config/shared";
    } else {
        if ($ispanorama == 1) {
            $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='" . $vsys . "']";
        } else {
            $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='" . $vsys . "']";
        }
    }
    $xpath0 = $data['xpath0'];

    $getShared = $projectdb->query("SELECT id,name,xml FROM profiles_groups WHERE source='$source' AND vsys = '$vsys' AND dummy = 0 ORDER BY id;");
    if ($getShared->num_rows > 0) {
        $check = $xml->xpath($xpath0."/profile-group");
        if (count($check)==0) {
            $theProfiles2=$xml->xpath($xpath0);
            $theProfiles2[0]->addChild('profile-group');
        } else {
            #DELETE SHARED LOG SETTINGS
            $SA = $xml->xpath($xpath0."/profile-group");
            unset($SA[0][0]);
            $theProfiles2=$xml->xpath($xpath0);
            $theProfiles2[0]->addChild('profile-group');
        }

        $theProfiles = $theProfiles2[0];
        while ($data2 = $getShared->fetch_assoc()) {
            $xmlfield = $data2['xml'];
            $xmlname = $data2['name'];
            //$objectsInMemory['profiles_groups'][$data2['id']]['name']=$xmlname;
            $xml_append = simplexml_load_string(clean_xml($xmlfield));
            SimpleXMLElement_append($theProfiles->{'profile-group'}, $xml_append);
            if ($api_call == "single") {
                $xpath = addslashes($xpath0."/profile-group/entry[@name='$xmlname']");
                $xml_final = addslashes($xmlfield);
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$xmlname','Profile Group','Profile Group','$xml_final','$xpath','edit');");
            }
        }
        if ($api_call == "atomic") {
            $xpath = addslashes($xpath0."/profile-group");
            $theProfiles=$xml->xpath($xpath0."/profile-group");
            $xml_final = addslashes($theProfiles[0]->asXML());
            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Profile Group','Profile Group','Profile Group','$xml_final','$xpath','edit');");
        }
        $message['code']=true;
        $message['msg']="All Profiles Groups Added";
        return $message;
    }
    else {
        $SA = $xml->xpath($xpath0."/profile-group");
        unset($SA[0][0]);
        if ($api_call=="clean"){
            $xpath = addslashes($xpath0."/profile-group");
            $xml_final = "";
            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Remove All Profile Group $vsys','Profile Group','Profile Group','$xml_final','$xpath','delete');");
        }
        $message['code']=true;
        $message['msg']="Removing all Profiles Groups";
        return $message;
    }

}

function xml_schedules($xml,$data,ARRAY &$objectsInMemory=null)
{
    $project = $data['project'];
    $ispanorama = $data['ispanorama'];
    $version = $data['version'];
    $api_call=$data['api_call'];
    $projectdb = $data['projectdb'];
    $source = $data['source'];
    $vsys = $data['vsys'];

    if ($vsys == "shared") {
        $data['xpath0'] = "/config/shared";
    } else {
        if ($ispanorama == 1) {
            $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='" . $vsys . "']";
        } else {
            $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='" . $vsys . "']";
        }
    }
    $xpath0 = $data['xpath0'];

    $getShared = $projectdb->query("SELECT id,name,xml FROM schedules WHERE source='$source' AND vsys = '$vsys' AND dummy = 0 ORDER BY id;");
    if ($getShared->num_rows > 0) {
        $check = $xml->xpath($xpath0."/schedule");
        if (count($check)==0) {
            $theProfiles2=$xml->xpath($xpath0);
            $theProfiles2[0]->addChild('schedule');
        } else {
            $SA = $xml->xpath($xpath0."/schedule");
            unset($SA[0][0]);
            $theProfiles2=$xml->xpath($xpath0);
            $theProfiles2[0]->addChild('schedule');
        }

        $theProfiles = $theProfiles2[0];
        while ($data2 = $getShared->fetch_assoc()) {
            $xmlfield = $data2['xml'];
            $xmlname = $data2['name'];
            //$objectsInMemory['schedules'][$data2['id']]['name']=$xmlname;
            if ($version >= 7) {
                if (strpos($xmlfield,"<schedule-type")==false){
                    if (strpos($xmlfield,"<recurring>")!== false){
                        $xmlfield = str_replace("<recurring>", "<schedule-type><recurring>", $xmlfield);
                    }
                    if (strpos($xmlfield,"</recurring>")!== false){
                        $xmlfield = str_replace("</recurring>", "</recurring></schedule-type>", $xmlfield);
                    }
                    if (strpos($xmlfield,"<non-recurring>")!== false){
                        $xmlfield = str_replace("<non-recurring>", "<schedule-type><non-recurring>", $xmlfield);
                    }
                    if (strpos($xmlfield,"</non-recurring>")!== false){
                        $xmlfield = str_replace("</non-recurring>", "</non-recurring></schedule-type>", $xmlfield);
                    }
                }

            }
            $xml_append = simplexml_load_string(clean_xml($xmlfield));

            SimpleXMLElement_append($theProfiles->schedule, $xml_append);
            if ($api_call == "single") {
                $xpath = addslashes($xpath0."/schedule/entry[@name='$xmlname']");
                $xml_final = addslashes($xmlfield);
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$xmlname','Schedules','Schedules','$xml_final','$xpath','edit');");
            }

        }
        if ($api_call == "atomic") {
            $xpath = addslashes($xpath0."/schedule");
            $theProfiles=$xml->xpath($xpath0."/schedule");
            $xml_final = addslashes($theProfiles[0]->asXML());
            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Schedules','Schedules','Schedules','$xml_final','$xpath','edit');");
        }
        $message['code']=true;
        $message['msg']="All Schedules added.";
        return $message;
    }
    else {
        $SA = $xml->xpath($xpath0."/schedule");
        unset($SA[0][0]);
        if ($api_call=="clean"){
            $xpath = addslashes($xpath0."/schedule");
            $xml_final = "";
            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Remove All Schedules $vsys','Schedules','Schedules','$xml_final','$xpath','delete');");
        }
        $message['code']=true;
        $message['msg']="Removing all Schedules";
        return $message;
    }
}

function xml_tags($xml,$data,ARRAY &$objectsInMemory=null)
{
    $project = $data['project'];
    $ispanorama = $data['ispanorama'];
    $version = $data['version'];
    $api_call=$data['api_call'];
    $projectdb = $data['projectdb'];
    $source = $data['source'];
    $vsys = $data['vsys'];

    if ($vsys == "shared") {
        $data['xpath0'] = "/config/shared";
    } else {
        if ($ispanorama == 1) {
            $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='" . $vsys . "']";
        } else {
            $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='" . $vsys . "']";
        }
    }
    $xpath0 = $data['xpath0'];

    $getShared = $projectdb->query("SELECT id,name,color,comments FROM tag WHERE source='$source' AND vsys = '$vsys' AND devicegroup!='predefined' AND dummy = 0 ORDER BY id;");
    //echo "SELECT id,name,color,comments FROM tag WHERE source='$source' AND vsys = '$vsys' AND devicegroup!='predefined' AND dummy = 0 ORDER BY id;";
    if (($version >= 6) AND ( $getShared->num_rows > 0)) {
        $check = $xml->xpath($xpath0."/tag");
        if (count($check)==0) {
            $theProfiles2=$xml->xpath($xpath0);
            $theProfiles2[0]->addChild('tag');
        } else {
            $SA = $xml->xpath($xpath0."/tag");
            unset($SA[0][0]);
            $theProfiles2=$xml->xpath($xpath0);
            $theProfiles2[0]->addChild('tag');
        }

        $theProfiles = $theProfiles2[0]->tag;
        while ($tag = $getShared->fetch_assoc()) {
            $tagName = $tag['name'];
            //$objectsInMemory['tag'][$tag['id']]['name']=$tagName;
            $newtag = $theProfiles->addChild('entry');
            $newtag->addAttribute('name', $tagName);
            if (($tag['color'] != "") AND ( $tag['color'] != "None")) {
                $newtag->addChild('color', $tag['color']);
            }
            if ($tag['comments'] != "") {
                $newtag->addChild('comments', $tag['comments']);
            }
            if ($api_call == "single") {
                $xpath = addslashes($xpath0."/tag/entry[@name='$tagName']");
                $xml_final = addslashes($newtag->asXML());
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$tagName','Tag','Tag','$xml_final','$xpath','edit');");
            }
        }
        if ($api_call == "atomic") {
            $xpath = addslashes($xpath0."/tag");
            $theProfiles = $xml->xpath($xpath0."/tag");
            $xml_final = addslashes($theProfiles[0]->asXML());
            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Tag','Tag','Tag','$xml_final','$xpath','edit');");
        }
        $message['code']=true;
        $message['msg']="All Tags added.";
        return $message;
    }
    elseif (($version >= 6) AND ( $getShared->num_rows == 0)) {
        $SA = $xml->xpath($xpath0."/tag");
        unset($SA[0][0]);
        if ($api_call=="clean"){
            $xpath = addslashes($xpath0."/tag");
            $xml_final = "";
            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Remove All Tag $vsys','Tag','Tag','$xml_final','$xpath','delete');");
        }
        $message['code']=true;
        $message['msg']="Removing all Tags";
        return $message;
    }
}

function xml_external_lists($xml,$data,&$objectsInMemory=null){
    $project = $data['project'];
    $ispanorama = $data['ispanorama'];
    $version = $data['version'];
    $api_call=$data['api_call'];
    $projectdb = $data['projectdb'];
    $source = $data['source'];
    $vsys = $data['vsys'];

    if ($vsys == "shared") {
        $data['xpath0'] = "/config/shared";
    } else {
        if ($ispanorama == 1) {
            $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='" . $vsys . "']";
        } else {
            $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='" . $vsys . "']";
        }
    }
    $xpath0 = $data['xpath0'];

    $getShared = $projectdb->query("SELECT id,name,xml FROM external_list WHERE source='$source' AND vsys = '$vsys' AND devicegroup!='predefined' GROUP BY name ORDER BY id;");
    if ($getShared->num_rows > 0) {

        $check = $xml->xpath($xpath0."/external-list");
        if (count($check)==0) {
            $theProfiles2=$xml->xpath($xpath0);
            $theProfiles2[0]->addChild('external-list');
        } else {
            $SA = $xml->xpath($xpath0."/external-list");
            unset($SA[0][0]);
            $theProfiles2=$xml->xpath($xpath0);
            $theProfiles2[0]->addChild('external-list');
        }
        $theProfiles = $theProfiles2[0]->{'external-list'};
        while ($data2 = $getShared->fetch_assoc()) {
            $xmlfield = $data2['xml'];
            $xmlname = $data2['name'];
            //$objectsInMemory['external_list'][$data2['id']]['name']=$xmlname;
            $xml_append = simplexml_load_string(clean_xml($xmlfield));
            SimpleXMLElement_append($theProfiles, $xml_append);
            if ($api_call == "single") {
                $xpath = addslashes($xpath0."/external-list/entry[@name='$xmlname']");
                $xml_final = addslashes($xmlfield);
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$xmlname','External List','External List','$xml_final','$xpath','edit');");
            }
        }
        if ($api_call == "atomic") {
            $xpath = addslashes($xpath0."/external-list");
            $xml_final = addslashes($theProfiles->asXML());
            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('External List','External List','External List','$xml_final','$xpath','edit');");
        }
    }
    else {
        $SA = $xml->xpath($xpath0."/external-list");
        unset($SA[0][0]);
        if ($api_call=="clean"){
            $xpath = addslashes($xpath0."/external-list");
            $xml_final = "";
            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Remove All External List $vsys','External List','External List','$xml_final','$xpath','delete');");
        }
        $message['code']=true;
        $message['msg']="Removing all External Lists";
        return $message;
    }

}

function xml_regions($xml,$data){
    $project = $data['project'];
    $ispanorama = $data['ispanorama'];
    $version = $data['version'];
    $api_call=$data['api_call'];
    $projectdb = $data['projectdb'];
    $source = $data['source'];
    $vsys = $data['vsys'];

    if ($vsys == "shared") {
        $data['xpath0'] = "/config/shared";
    } else {
        if ($ispanorama == 1) {
            $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='" . $vsys . "']";
        } else {
            $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='" . $vsys . "']";
        }
    }
    $xpath0 = $data['xpath0'];

    $getShared = $projectdb->query("SELECT id,name,xml,address,latitude,longitude FROM regions WHERE source='$source' AND vsys = '$vsys' ORDER BY id;");
    if ($getShared->num_rows > 0) {

        $check = $xml->xpath($xpath0."/region");
        if (count($check)==0) {
            $theProfiles2=$xml->xpath($xpath0);
            $theProfiles2[0]->addChild('region');
        } else {
            $SA = $xml->xpath($xpath0."/region");
            unset($SA[0][0]);
            $theProfiles2=$xml->xpath($xpath0);
            $theProfiles2[0]->addChild('region');
        }
        $theProfiles = $theProfiles2[0]->{'region'};
        while ($data2 = $getShared->fetch_assoc()) {
            $xmlfield = $data2['xml'];
            $xmlname = $data2['name'];
            //$objectsInMemory['regions'][$data2['id']]['name']=$xmlname;
            $regionMembers=$data2['address'];
            $latitude=$data2['latitude'];
            $longitude=$data2['longitude'];

            $newRegion=$theProfiles->addChild("entry");
            $newRegion->addAttribute('name', $xmlname);
            if ($regionMembers!=""){
                $newRegion->addChild("address");
                $regionMembersArray=explode(",",$regionMembers);
                foreach ($regionMembersArray as $regionMembersValue){
                    $newRegion->address->addChild("member",$regionMembersValue);
                }
            }
            if (($longitude!="") AND ($latitude!="")){
                $newRegion->addChild("geo-location");
                $newRegion->{'geo-location'}->addChild("latitude",$latitude);
                $newRegion->{'geo-location'}->addChild("longitude",$longitude);
            }
            if ($api_call == "single") {
                $xpath = addslashes($xpath0."/region/entry[@name='$xmlname']");
                $newRegionXML=addslashes($newRegion->asXML());
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$xmlname','Regions','Regions','$newRegionXML','$xpath','edit');");
            }

        }
        if ($api_call == "atomic") {
            $xpath = addslashes($xpath0."/region");
            $xml_final = addslashes($theProfiles->asXML());
            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Regions','Regions','Regions','$xml_final','$xpath','edit');");
        }
    }
    else {
        $SA = $xml->xpath($xpath0."/region");
        unset($SA[0][0]);
        if ($api_call=="clean"){
            $xpath = addslashes($xpath0."/region");
            $xml_final = "";
            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Remove All Regions $vsys','Regions','Regions','$xml_final','$xpath','delete');");
        }
        $message['code']=true;
        $message['msg']="Removing all Regions";
        return $message;
    }
}

function xml_applications($xml,$data,&$objectsInMemory=null){

    $project = $data['project'];
    $ispanorama = $data['ispanorama'];
    $version = $data['version'];
    $api_call=$data['api_call'];
    $projectdb = $data['projectdb'];
    $source = $data['source'];
    $vsys = $data['vsys'];

    if ($vsys == "shared") {
        $data['xpath0'] = "/config/shared";
    } else {
        if ($ispanorama == 1) {
            $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='" . $vsys . "']";
        } else {
            $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='" . $vsys . "']";
        }
    }
    $xpath0 = $data['xpath0'];

    $getShared = $projectdb->query("SELECT * FROM applications WHERE source='$source' AND vsys = '$vsys' AND dummy=0 ORDER BY id;");
    if ($getShared->num_rows > 0) {
        $check = $xml->xpath($xpath0."/application");
        if (count($check)==0) {
            $theProfiles2=$xml->xpath($xpath0);
            $theProfiles2[0]->addChild('application');
        } else {
            $SA = $xml->xpath($xpath0."/application");
            unset($SA[0][0]);
            $theProfiles2=$xml->xpath($xpath0);
            $theProfiles2[0]->addChild('application');
        }
        $theProfiles = $theProfiles2[0]->{'application'};

        while ($data2 = $getShared->fetch_object()) {
            $appid = $data2->id;
            $myname = $data2->name;
            //$objectsInMemory['applications'][$data2->id]['name']=$myname;
            $application = $theProfiles->addChild('entry');
            $application->addAttribute('name', $myname);
            if ($data2->description != "") {
                $application->addChild('description');
                $application->description = $data2->description;
            }
            if ($data2->category != "") {
                $application->addChild('category', $data2->category);
            }
            if ($data2->subcategory != "") {
                $application->addChild('subcategory', $data2->subcategory);
            }
            if ($data2->risk != "") {
                $application->addChild('risk', $data2->risk);
            }
            if ($data2->technology != "") {
                $application->addChild('technology', $data2->technology);
            }
            if ($data2->evasive_behavior != "") {
                $application->addChild('evasive-behavior', $data2->evasive_behavior);
            }
            if ($data2->consume_big_bandwidth != "") {
                $application->addChild('consume-big-bandwidth', $data2->consume_big_bandwidth);
            }
            if ($data2->used_by_malware != "") {
                $application->addChild('used-by-malware', $data2->used_by_malware);
            }
            if ($data2->able_to_transfer_file != "") {
                $application->addChild('able-to-transfer-file', $data2->able_to_transfer_file);
            }
            if ($data2->has_known_vulnerability != "") {
                $application->addChild('has-known-vulnerability', $data2->has_known_vulnerability);
            }
            if ($data2->tunnel_other_application != "") {
                $application->addChild('tunnel-other-application', $data2->tunnel_other_application);
            }
            if ($data2->tunnel_applications != "") {
                $application->addChild('tunnel-applications', $data2->tunnel_applications);
            }
            if ($data2->prone_to_misuse != "") {
                $application->addChild('prone-to-misuse', $data2->prone_to_misuse);
            }
            if ($data2->pervasive_use != "") {
                $application->addChild('pervasive-use', $data2->pervasive_use);
            }
            if ($data2->file_type_ident != "") {
                $application->addChild('file-type-ident', $data2->file_type_ident);
            }
            if ($data2->virus_ident != "") {
                $application->addChild('virus-ident', $data2->virus_ident);
            }
            if ($data2->data_ident != "") {
                $application->addChild('data-ident', $data2->data_ident);
            }
            if ($version < 6) {
                if ($data2->spyware_ident != "") {
                    $application->addChild('spyware-ident', $data2->spyware_ident);
                }
            }
            if (($data2->parent_app != "None") AND ($data2->parent_app!="")){
                $application->addChild('parent-app', $data2->parent_app);
            }
            if ($data2->timeout !='') {
                $application->addChild('timeout', $data2->timeout);
            }
            if ($data2->tcp_timeout !='') {
                $application->addChild('tcp-timeout', $data2->tcp_timeout);
            }
            if ($data2->udp_timeout !='') {
                $application->addChild('udp-timeout', $data2->udp_timeout);
            }
            if($version >= 6){
                if ($data2->tcp_half_closed_timeout !='') {
                    $application->addChild('tcp-half-closed-timeout', $data2->tcp_half_closed_timeout);
                }
                if ($data2->tcp_time_wait_timeout !='') {
                    $application->addChild('tcp-time-wait-timeout', $data2->tcp_time_wait_timeout);
                }
            }
            if ($data2->default_type == "port") {
                $default = $application->addChild('default');
                $port = $default->addChild('port');

                $getPorts = $projectdb->query("SELECT ports FROM applications_ports WHERE member_lid='$appid' AND table_name='applications';");
                if ($getPorts->num_rows > 0) {
                    while ($data4 = $getPorts->fetch_assoc()) {
                        $ports = $data4['ports'];
                        $port->addChild('member', $ports);
                    }
                }
            }
            elseif ($data2->default_type == "ident-by-ip-protocol") {
                $default = $application->addChild('default');
                $port = $default->addChild('ident-by-ip-protocol', $data2->value);
            }
            elseif ($data2->default_type == "ident-by-icmp-type") {
                if($version < 7){
                    $default = $application->addChild('default');
                    $port = $default->addChild('ident-by-icmp-type', $data2->type);
                }else{
                    $default = $application->addChild('default');
                    $port = $default->addChild('ident-by-icmp-type');
                    $port->addChild('type', $data2->type);
                    $port->addChild('code', $data2->code);
                }
            }
            elseif ($data2->default_type == "ident-by-icmp6-type") {
                $default = $application->addChild('default');
                $port = $default->addChild('ident-by-icmp6-type');
                $port->addChild('code', $data2->code);
                $port->addChild('type', $data2->type);
            }
            elseif ($data2->default_type == "None") {

            }

            $getSignature = $projectdb->query("SELECT signature FROM applications_signatures WHERE member_lid='$appid' AND table_name='applications' AND signature != '';");
            if ($getSignature->num_rows > 0) {
                $sig = $application->addChild('signature');
                while ($data3 = $getSignature->fetch_assoc()) {
                    $signature = $data3['signature'];
                    $xml_append = simplexml_load_string(clean_xml($signature));
                    SimpleXMLElement_append($sig, $xml_append);
                }
            }

            if ($api_call == "single") {
                $xpath = addslashes($xpath0."/application/entry[@name='$myname']");
                $xml_final = addslashes($application->asXML());
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','Applications','Applications','$xml_final','$xpath','edit');");
            }

        }
        if ($api_call == "atomic") {
            $xpath = addslashes($xpath0."/application");
            $xml_final = addslashes($theProfiles->asXML());
            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Applications','Applications','Applications','$xml_final','$xpath','edit');");
        }
    }
    else {
        $SA = $xml->xpath($xpath0."/application");
        unset($SA[0][0]);
        if ($api_call=="clean"){
            $xpath = addslashes($xpath0."/application");
            $xml_final = "";
            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Remove All Application $vsys','Application','Application','$xml_final','$xpath','delete');");
        }
        $message['code']=true;
        $message['msg']="Removing all Applications";
        return $message;
    }


    # Add Tags from Applications: application-tag
    $getShared = $projectdb->query("SELECT a.name, a.id, t.tag_id FROM tag_relations t, applications a WHERE t.member_lid = a.id AND t.table_name = 'applications' GROUP BY a.id;");
    if ($getShared->num_rows > 0) {
        $check = $xml->xpath($xpath0."/application-tag");
        if (count($check)==0) {
            $theProfiles2=$xml->xpath($xpath0);
            $theProfiles2[0]->addChild('application-tag');
        } else {
            $SA = $xml->xpath($xpath0."/application-tag");
            unset($SA[0][0]);
            $theProfiles2=$xml->xpath($xpath0);
            $theProfiles2[0]->addChild('application-tag');
        }
        $theProfiles = $theProfiles2[0]->{'application-tag'};

        while ($data2 = $getShared->fetch_object()) {

            $appid = $data2->id;
            $myname = $data2->name;

            $application = $theProfiles->addChild('entry');
            $application->addAttribute('name', $myname);

            $getTags = $projectdb->query("SELECT tag.id, tag.name, t.tag_id FROM tag_relations t, tag tag WHERE t.tag_id = tag.id AND t.table_name = 'applications' AND t.member_lid = '$appid'; ");
            if ($getTags->num_rows > 0) {

                $tag = $application->addChild('tag');

                while ($data4 = $getTags->fetch_assoc()) {
                    $tag_name = $data4['name'];
                    $tag->addChild('member', htmlspecialchars($tag_name));
                }
            }

            if ($api_call == "single") {
                $xpath = addslashes($xpath0."/application-tag/entry[@name='$myname']");
                $xml_final = addslashes($application->asXML());
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','Applications','Applications Tags','$xml_final','$xpath','edit');");
            }


        }
        if ($api_call == "atomic") {
            $xpath = addslashes($xpath0."/application-tag");
            $xml_final = addslashes($theProfiles->asXML());
            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Applications','Applications','Applications Tags','$xml_final','$xpath','edit');");
        }
    }
    else {
        $SA = $xml->xpath($xpath0."/application-tag");
        unset($SA[0][0]);
        if ($api_call=="clean"){
            $xpath = addslashes($xpath0."/application-tag");
            $xml_final = "";
            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Remove All Application Tags $vsys','Application','Application Tags','$xml_final','$xpath','delete');");
        }
        $message['code']=true;
        $message['msg']="Removing all Applications Tags";
        return $message;
    }
}

function xml_applications_filters($xml,$data,&$objectsInMemory=null){
    $project = $data['project'];
    $ispanorama = $data['ispanorama'];
    $version = $data['version'];
    $api_call=$data['api_call'];
    $projectdb = $data['projectdb'];
    $source = $data['source'];
    $vsys = $data['vsys'];

    if ($vsys == "shared") {
        $data['xpath0'] = "/config/shared";
    } else {
        if ($ispanorama == 1) {
            $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='" . $vsys . "']";
        } else {
            $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='" . $vsys . "']";
        }
    }
    $xpath0 = $data['xpath0'];

    $getShared = $projectdb->query("SELECT * FROM applications_filters WHERE source='$source' AND vsys = '$vsys' ORDER BY id;");
    if ($getShared->num_rows > 0) {
        $check = $xml->xpath($xpath0."/application-filter");
        if (count($check)==0) {
            $theProfiles2=$xml->xpath($xpath0);
            $theProfiles2[0]->addChild('application-filter');
        } else {
            $SA = $xml->xpath($xpath0."/application-filter");
            unset($SA[0][0]);
            $theProfiles2=$xml->xpath($xpath0);
            $theProfiles2[0]->addChild('application-filter');
        }
        $theProfiles = $theProfiles2[0]->{'application-filter'};

        while ($data2 = $getShared->fetch_object()) {
            $appid = $data2->id;
            $myname = $data2->name;
            //$objectsInMemory['applications_filters'][$data2->id]['name']=$myname;
            $application_filters = $theProfiles->addChild('entry');
            $application_filters->addAttribute('name', $myname);

            if($data2->category != ""){
                $category = $application_filters->addChild('category');
                $category_s = explode(",", $data2->category);
                foreach ($category_s as $kkey => $vvalue) {
                    $category->addChild('member', $vvalue);
                }
            }
            if($data2->subcategory != ""){
                $subcategory = $application_filters->addChild('subcategory');
                $subcategory_s = explode(",", $data2->subcategory);
                foreach ($subcategory_s as $kkey => $vvalue) {
                    $subcategory->addChild('member', $vvalue);
                }
            }
            if($data2->risk != ""){
                $risk = $application_filters->addChild('risk');
                $risk_s = explode(",", $data2->risk);
                foreach ($risk_s as $kkey => $vvalue) {
                    $risk->addChild('member', $vvalue);
                }
            }
            if($data2->technology != ""){
                $technology = $application_filters->addChild('technology');
                $technology_s = explode(",", $data2->technology);
                foreach ($technology_s as $kkey => $vvalue) {
                    $technology->addChild('member', $vvalue);
                }
            }
            if ($data2->evasive_behavior != "") {
                $application_filters->addChild('evasive', $data2->evasive_behavior);
            }
            if ($data2->consume_big_bandwidth != "") {
                $application_filters->addChild('excessive-bandwidth-use', $data2->consume_big_bandwidth);
            }
            if ($data2->used_by_malware != "") {
                $application_filters->addChild('used-by-malware', $data2->used_by_malware);
            }
            if ($data2->able_to_transfer_file != "") {
                $application_filters->addChild('transfers-files', $data2->able_to_transfer_file);
            }
            if ($data2->has_known_vulnerability != "") {
                $application_filters->addChild('has-known-vulnerabilities', $data2->has_known_vulnerability);
            }
            if ($data2->tunnel_other_application != "") {
                $application_filters->addChild('tunnels-other-apps', $data2->tunnel_other_application);
            }
            if ($data2->prone_to_misuse != "") {
                $application_filters->addChild('prone-to-misuse', $data2->prone_to_misuse);
            }
            if ($data2->disable_override != "") {
                $application_filters->addChild('disable-override', $data2->disable_override);
            }
            if ($data2->tagging != "") {
                $tagging = $application_filters->addChild('tagging');
                $tag = $tagging->addChild('tag');
                $tagging_s = explode(",", $data2->tagging);
                foreach ($tagging_s as $kkey => $vvalue) {
                    $tag->addChild('member', $vvalue);
                }
            }
            if ($data2->pervasive_use != "") {
                $application_filters->addChild('pervasive', $data2->pervasive_use);
            }
            if ($api_call == "single") {
                $xpath = addslashes($xpath0."/application-filter/entry[@name='$myname']");
                $xml_final = addslashes($application_filters->asXML());
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','Applications Filters','Applications Filters','$xml_final','$xpath','edit');");
            }

        }
        if ($api_call == "atomic") {
            $xpath = addslashes($xpath0."/application-filter");
            $xml_final = addslashes($theProfiles->asXML());
            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Applications Filters','Applications Filters','Applications Filters','$xml_final','$xpath','edit');");
        }
    }
    else {
        $SA = $xml->xpath($xpath0."/application-filter");
        unset($SA[0][0]);
        if ($api_call=="clean"){
            $xpath = addslashes($xpath0."/application-filter");
            $xml_final = "";
            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Remove All Application Filters $vsys','Application Filters','Application Filters','$xml_final','$xpath','delete');");
        }
        $message['code']=true;
        $message['msg']="Removing all Application Filters";
        return $message;
    }

}

function xml_applications_groups($xml,$data,&$objectsInMemory=null){
    $project = $data['project'];
    $ispanorama = $data['ispanorama'];
    $version = $data['version'];
    $api_call=$data['api_call'];
    $projectdb = $data['projectdb'];
    $source = $data['source'];
    $vsys = $data['vsys'];

    if ($vsys == "shared") {
        $data['xpath0'] = "/config/shared";
    } else {
        if ($ispanorama == 1) {
            $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='" . $vsys . "']";
        } else {
            $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='" . $vsys . "']";
        }
    }
    $xpath0 = $data['xpath0'];

    $getShared = $projectdb->query("SELECT name,id FROM applications_groups_id WHERE source='$source' AND vsys = '$vsys' ORDER BY id;");
    if ($getShared->num_rows > 0) {
        $check = $xml->xpath($xpath0."/application-group");
        if (count($check)==0) {
            $theProfiles2=$xml->xpath($xpath0);
            $theProfiles2[0]->addChild('application-group');
        } else {
            $SA = $xml->xpath($xpath0."/application-group");
            unset($SA[0][0]);
            $theProfiles2=$xml->xpath($xpath0);
            $theProfiles2[0]->addChild('application-group');
        }
        $theProfiles = $theProfiles2[0]->{'application-group'};
        while ($Data = $getShared->fetch_assoc()) {
            $groupName = $Data['name'];
            $lid = $Data['id'];
            $myname = $Data['name'];
            //$objectsInMemory['applications_groupd_id'][$lid]['name']=$myname;
            $getMembers = $projectdb->query("SELECT table_name,member_lid FROM applications_groups WHERE lid='$lid' ORDER BY id");
            if ($getMembers->num_rows > 0) {
                $service = $theProfiles->addChild('entry');
                $service->addAttribute('name', $Data['name']);
                if ($version >= 7) {
                    $service2 = $service->addChild('members');
                } elseif ($version < 7) {
                    $service2 = $service;
                }
                while ($Datas = $getMembers->fetch_assoc()) {
                    $table_name = $Datas['table_name'];
                    $member_lid = $Datas['member_lid'];
                    $getName = $projectdb->query("SELECT name FROM $table_name WHERE id='$member_lid'");
                    if ($getName->num_rows==1){
                        $Datas2 = $getName->fetch_assoc();
                        $member = $service2->addChild('member', $Datas2['name']);
                    }
                }
            }
            if ($api_call == "single") {
                $xpath = addslashes($xpath0."/application-group/entry[@name='$myname']");
                $xml_final = addslashes($service->asXML());
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','Applications Groups','Applications Groups','$xml_final','$xpath','edit');");
            }

        }
        if ($api_call == "atomic") {
            $xpath = addslashes($xpath0."/application-group");
            $xml_final = addslashes($theProfiles->asXML());
            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Applications Groups','Applications Groups','Applications Groups','$xml_final','$xpath','edit');");
        }
    }
    else {
        $SA = $xml->xpath($xpath0."/application-group");
        unset($SA[0][0]);
        if ($api_call=="clean"){
            $xpath = addslashes($xpath0."/application-group");
            $xml_final = "";
            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Remove All Application Groups $vsys','Application Groups','Application Groups','$xml_final','$xpath','delete');");
        }
        $message['code']=true;
        $message['msg']="Removing all Application Groups";
        return $message;
    }

}

function xml_address($xml,$data,&$objectsInMemory=null){
    $project = $data['project'];
    $ispanorama = $data['ispanorama'];
    $version = $data['version'];
    $api_call=$data['api_call'];
    $projectdb = $data['projectdb'];
    $source = $data['source'];
    $vsys = $data['vsys'];

    if ($vsys == "shared") {
        $data['xpath0'] = "/config/shared";

        $checkSharedExists=$xml->xpath("/config/shared");
        if (count($checkSharedExists)==0){
            $addShared=$xml->addChild("shared");
        }

    } else {
        if ($ispanorama == 1) {
            $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='" . $vsys . "']";
        } else {
            $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='" . $vsys . "']";
        }
    }
    $xpath0 = $data['xpath0'];

    $getShared = $projectdb->query("SELECT * FROM address WHERE source='$source' AND vsys = '$vsys' AND dummy=0 ORDER BY id;");
    if ($getShared->num_rows > 0) {
        $check = $xml->xpath($xpath0."/address");
        if (count($check)==0) {
            $theProfiles2=$xml->xpath($xpath0);
            $theProfiles2[0]->addChild('address');
        } else {
            $SA = $xml->xpath($xpath0."/address");
            unset($SA[0][0]);
            $theProfiles2=$xml->xpath($xpath0);
            $theProfiles2[0]->addChild('address');
        }
        $theProfiles = $theProfiles2[0]->{'address'};
        while ($Data = $getShared->fetch_assoc()) {

            $myname = $Data['name'];
            $id = $Data['id'];

            switch($Data['type']){
                case "ip-address":
                case "ip-netmask":
                    $address = $theProfiles->addChild('entry');
                    $address->addAttribute('name', $Data['name']);

                    if ($Data['cidr']==""){
                        $address->addChild('ip-netmask', $Data['ipaddress']);
                    }
                    else{
                        if ($Data['cidr']=="") {$address->addChild('ip-netmask', $Data['ipaddress']);}
                        else{$address->addChild('ip-netmask', $Data['ipaddress'] . '/' . $Data['cidr']);}
                    }
                    break;

                case "ip-range":
                    $address = $theProfiles->addChild('entry');
                    $address->addAttribute('name', $Data['name']);
                    $address->addChild('ip-range', $Data['ipaddress']);
                    break;

                case "fqdn":
                    $address = $theProfiles->addChild('entry');
                    $address->addAttribute('name', $Data['name']);
                    $address->addChild('fqdn', $Data['ipaddress']);
                    break;

                case "dynamic":
                    if ($version == 5) {
                        $address = $theProfiles->addChild('entry');
                        $address->addAttribute('name', $Data['name']);
                        $address->addChild('dynamic', $Data['ipaddress']);
                    } elseif ($version >= 6) {
                        add_log('error', 'Exporting Shared Address', 'Dynamic Address Not supported in Panos 6.x [' . $myname . ']', $source, 'Object was Not Migrated');
                    }
                    break;

                case "ip-wildcard":
                    if ($version >= 9) {
                        $address = $theProfiles->addChild('entry');
                        $address->addAttribute('name', $Data['name']);
                        $address->addChild('ip-wildcard', $Data['ipaddress']);
                    }
                    break;
            }

            if ($Data['description'] != "") {
                $address->addChild('description');
                $address->description = $Data['description'];
            }

            if ($Data['disable_override'] != ""){
                $address->addChild("disable-override",$Data['disable_override']);
            }

            // New tag relations
            if($version >= 6){

                // Type ip-wildcard don't have tags.
                if($Data['type'] != "ip-wildcard"){
                    $getTags = $projectdb->query("SELECT tag.name as name, tag.id as id FROM tag, tag_relations 
                    WHERE tag_relations.member_lid=".$id." AND tag_relations.table_name='address' AND tag.id = tag_relations.tag_id;");
                    //echo "2. SELECT tag.name as name, tag.id as id FROM tag, tag_relations
                    //    WHERE tag_relations.member_lid=".$id." AND tag_relations.table_name='address' AND tag.id = tag_relations.tag_id;\n";

                    if ($getTags->num_rows > 0) {
                        $tags = $address->addChild('tag');
                        while($dataT = $getTags->fetch_assoc()){
                            //echo "Tag: ".$dataT['name']."\n";
                            //$tags->addChild('member', htmlentities($dataT['name'])); //7696
                            //MT-892
                            $tags->addChild('member', htmlspecialchars($dataT['name'])); //7696
                        }
                    }
                }
            }

            if ($api_call == "single") {
                $xpath = addslashes($xpath0."/address/entry[@name='$myname']");
                $xml_final = addslashes($address->asXML());
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','Address','Address','$xml_final','$xpath','edit');");
            }

        }
        if ($api_call == "atomic") {
            $xpath = addslashes($xpath0."/address");
            $xml_final = addslashes($theProfiles->asXML());
            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Address','Address','Address','$xml_final','$xpath','edit');");
        }
    }
    else {
        $SA = $xml->xpath($xpath0."/address");
        unset($SA[0][0]);
        if ($api_call=="clean"){
            $xpath = addslashes($xpath0)."/address";
            $xml_final = "";
            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Remove All Address $vsys','Address','Address','$xml_final','$xpath','delete');");
        }
        $message['code']=true;
        $message['msg']="Removing all Address";
        return $message;
    }
}

function xml_address_groups($xml,$data,&$objectsInMemory=null){
    $project = $data['project'];
    $ispanorama = $data['ispanorama'];
    $version = $data['version'];
    $api_call=$data['api_call'];
    $projectdb = $data['projectdb'];
    $source = $data['source'];
    $vsys = $data['vsys'];

    if ($vsys == "shared") {
        $data['xpath0'] = "/config/shared";
    } else {
        if ($ispanorama == 1) {
            $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='" . $vsys . "']";
        } else {
            $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='" . $vsys . "']";
        }
    }
    $xpath0 = $data['xpath0'];

    $getShared = $projectdb->query("SELECT name,id,tag,filter,type,description,disable_override FROM address_groups_id WHERE source='$source' AND vsys = '$vsys' ORDER BY id;");
    if ($getShared->num_rows > 0) {
        $check = $xml->xpath($xpath0."/address-group");
        if (count($check)==0) {
            $theProfiles2=$xml->xpath($xpath0);
            $theProfiles2[0]->addChild('address-group');
        } else {
            $SA = $xml->xpath($xpath0."/address-group");
            unset($SA[0][0]);
            $theProfiles2=$xml->xpath($xpath0);
            $theProfiles2[0]->addChild('address-group');
        }
        $theProfiles = $theProfiles2[0]->{'address-group'};
        while ($Data = $getShared->fetch_assoc()) {
            $groupName = $Data['name'];
            $lid = $Data['id'];
            $myname = $Data['name'];
            $disable_override=$Data['disable_override'];
            //$objectsInMemory['address_groups_id'][$lid]['name']=$myname;
            $getMembers = $projectdb->query("SELECT table_name,member_lid FROM address_groups WHERE lid='$lid' ORDER BY id;");
            if ($getMembers->num_rows > 0) {
                $service = $theProfiles->addChild('entry');
                $service->addAttribute('name', $Data['name']);
                if (($version >= 6) AND ($Data['type'] == "static") ) {
                    $service2 = $service->addChild('static');
                }
                elseif ($version < 6) {
                    $service2 = $service;
                }

                while ( $Datas = $getMembers->fetch_assoc() ) {
                    $table_name = $Datas['table_name'];
                    $member_lid = $Datas['member_lid'];
                    $member = $service2->addChild('member', $objectsInMemory[$table_name][$member_lid]['name']);
                }
            }
            else {
                $service = $theProfiles->addChild('entry');
                $service->addAttribute('name', $Data['name']);
                if (($version >= 6) AND ( $Data['type'] == "dynamic")) {
                    $service2 = $service->addChild('dynamic');
                    $filter = str_replace("<br>", "\n", $Data['filter']);
                    $service2 = $service->dynamic->addChild('filter', $filter);
                }
            }
            if ($ispanorama==1){
                if ($disable_override=="yes"){
                    $service->addChild('disable-override','yes');
                }
            }

            if ($Data['description'] != "") {
                $service->addChild('description');
                $service->description = $Data['description'];
            }

//            if ($Data['tag'] != "") {
//                $tags = explode(",", $Data['tag']);
//                $shtag = $service->addChild('tag');
//                foreach ($tags as $kkey => $vvalue) {
//                    $shtag->addChild('member', $vvalue);
//                }
//            }

            if($version >= 6){
                $getTags = $projectdb->query("SELECT tag.name as name, tag.id as id FROM tag, tag_relations 
                        WHERE tag_relations.member_lid=".$lid." AND tag_relations.table_name='address_groups_id' AND tag.id = tag_relations.tag_id;");

                if ($getTags->num_rows > 0) {
                    $tags = $service->addChild('tag');
                    while($dataT = $getTags->fetch_assoc()){
                        //$tags->addChild('member', htmlentities($dataT['name']));
                        // MT-892
                        $tags->addChild('member', htmlspecialchars($dataT['name']));

                    }
                }
            }

            if ($api_call == "single") {
                $xpath = addslashes($xpath0."/address-group/entry[@name='$myname']");
                $xml_final = addslashes($service->asXML());
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','Address Groups','Address Groups','$xml_final','$xpath','edit');");
            }

        }
        if ($api_call == "atomic") {
            $xpath = addslashes($xpath0."/address-group");
            $xml_final = addslashes($theProfiles->asXML());
            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Address Groups','Address Groups','Address Groups','$xml_final','$xpath','edit');");
        }
    }
    else {
        #DELETE SHARED ADDRESS GROUPS
        $SA = $xml->xpath($xpath0."/address-group");
        unset($SA[0][0]);
        if ($api_call=="clean"){
            $xpath = addslashes($xpath0."/address-group");
            $xml_final = "";
            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Remove All Address Groups $vsys','Address Groups','Address Groups','$xml_final','$xpath','delete');");
        }
        $message['code']=true;
        $message['msg']="Removing all Address Groups";
        return $message;
    }

}

function xml_services($xml,$data,&$objectsInMemory){
    $project = $data['project'];
    $ispanorama = $data['ispanorama'];
    $version = $data['version'];
    $api_call=$data['api_call'];
    $projectdb = $data['projectdb'];
    $source = $data['source'];
    $vsys = $data['vsys'];

    if ($vsys == "shared") {
        $data['xpath0'] = "/config/shared";
    } else {
        if ($ispanorama == 1) {
            $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='" . $vsys . "']";
        } else {
            $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='" . $vsys . "']";
        }
    }
    $xpath0 = $data['xpath0'];

    $getShared = $projectdb->query("SELECT id,name,dport,sport,protocol,tag,description, override, timeout, halfclose_timeout, timewait_timeout, disable_override 
      FROM services WHERE source='$source' AND vsys = '$vsys' AND dummy=0 AND (protocol = 'tcp' or protocol = 'udp' or protocol = 'sctp') AND (name <> 'application-default' AND name <> 'service-http' AND name <> 'service-https') ORDER BY id;");
    //echo "SELECT id,name,dport,sport,protocol,tag,description, override, timeout, halfclose_timeout, timewait_timeout, disable_override
    //  FROM services WHERE source='$source' AND vsys = '$vsys' AND dummy=0 AND (protocol = 'tcp' or protocol = 'udp' or protocol = 'sctp') AND (name <> 'application-default' AND name <> 'service-http' AND name <> 'service-https') ORDER BY id;";
    if ($getShared->num_rows > 0) {
        $check = $xml->xpath($xpath0."/service");
        if (count($check)==0) {
            $theProfiles2=$xml->xpath($xpath0);
            $theProfiles2[0]->addChild('service');
        } else {
            $SA = $xml->xpath($xpath0."/service");
            unset($SA[0][0]);
            $theProfiles2=$xml->xpath($xpath0);
            $theProfiles2[0]->addChild('service');
        }
        $theProfiles = $theProfiles2[0]->{'service'};
        while ($Data = $getShared->fetch_assoc()) {
            $myname = $Data['name'];
            $id = $Data['id'];
            //$objectsInMemory['services'][$Data['id']]['name']=$myname;
            $service = $theProfiles->addChild('entry');
            $service->addAttribute('name', $Data['name']);
            $protocol = $service->addChild('protocol');
            $port = $protocol->addChild(strtolower($Data['protocol']));
            $port->addChild('port', $Data['dport']);
            if (($Data['sport'] != NULL) AND ( $Data['sport'] != "") AND ( $Data['sport'] != "0")) {
                $port->addChild('source-port', $Data['sport']);
            }
            if ($Data['description'] != "") {
                $protocol = $service->addChild('description');
                $service->description = $Data['description'];
            }
//            if (($version >= 6) AND ( $Data['tag'] != "")) {
//                $tags = $service->addChild('tag');
//                $mytags = explode(",", $Data['tag']);
//                foreach ($mytags as $key => $value) {
//                    $tags->addChild('member', $value);
//                }
//            }

            if($version >= 6){
                $getTags = $projectdb->query("SELECT tag.name as name, tag.id as id FROM tag, tag_relations 
                        WHERE tag_relations.member_lid=".$id." AND tag_relations.table_name='services' AND tag.id = tag_relations.tag_id;");

                if ($getTags->num_rows > 0) {
                    $tags = $service->addChild('tag');
                    while($dataT = $getTags->fetch_assoc()){
                        //$tags->addChild('member', htmlentities($dataT['name']));
                        //MT-892
                        $tags->addChild('member', htmlspecialchars($dataT['name']));

                    }
                }
            }

            // New Version 8.1
            if($version >= "8.1"){
                if(strtolower($Data['protocol']) != "sctp"){
                    $override = $port->addChild('override');
                    if(($Data['override'] == "no") || ($Data['override'] == "")){
                        $override->addChild('no');
                    }
                    elseif($Data['override'] == "yes"){
                        if(strtolower($Data['protocol']) == "udp"){
                            $override_yes = $override->addChild('yes');
                            if($Data['timeout'] == ""){
                                $Data['timeout'] = "30";
                            }
                            $override_yes->addChild('timeout', $Data['timeout']);
                        }
                        elseif(strtolower($Data['protocol']) == "tcp"){
                            $override_yes = $override->addChild('yes');

                            if($Data['timeout'] == ""){
                                $Data['timeout'] = "3600";
                            }
                            if($Data['halfclose_timeout'] == ""){
                                $Data['halfclose_timeout'] = "120";
                            }
                            if($Data['timewait_timeout'] == ""){
                                $Data['timewait_timeout'] = "15";
                            }
                            $override_yes->addChild('timeout', $Data['timeout']);
                            $override_yes->addChild('halfclose-timeout', $Data['halfclose_timeout']);
                            $override_yes->addChild('timewait-timeout', $Data['timewait_timeout']);
                        }
                    }
                }

                if ($Data['disable_override'] == "yes") {
                    $service->addChild('disable-override', $Data['disable_override']);
                }

            }
            if ($api_call == "single") {
                $xpath = addslashes($xpath0."/service/entry[@name='$myname']");
                $xml_final = addslashes($service->asXML());
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','Services','Services','$xml_final','$xpath','edit');");
            }

        }
        if ($api_call == "atomic") {
            $xpath = addslashes($xpath0."/service");
            $xml_final = addslashes($theProfiles->asXML());
            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Services','Services','Services','$xml_final','$xpath','edit');");
        }
    }
    else {
        $SA = $xml->xpath($xpath0."/service");
        unset($SA[0][0]);
        if ($api_call=="clean"){
            $xpath = addslashes($xpath0."/service");
            $xml_final = "";
            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Remove All Services $vsys','Services','Services','$xml_final','$xpath','delete');");
        }
        $message['code']=true;
        $message['msg']="Removing all Services";
        return $message;
    }
}

function xml_services_groups($xml,$data,&$objectsInMemory){
    $project = $data['project'];
    $ispanorama = $data['ispanorama'];
    $version = $data['version'];
    $api_call=$data['api_call'];
    $projectdb = $data['projectdb'];
    $source = $data['source'];
    $vsys = $data['vsys'];

    if ($vsys == "shared") {
        $data['xpath0'] = "/config/shared";
    } else {
        if ($ispanorama == 1) {
            $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='" . $vsys . "']";
        } else {
            $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='" . $vsys . "']";
        }
    }
    $xpath0 = $data['xpath0'];

    $getShared = $projectdb->query("SELECT name,id,tag,disable_override FROM services_groups_id WHERE source='$source' AND vsys = '$vsys' ORDER BY id;");
    if ($getShared->num_rows > 0) {
        $check = $xml->xpath($xpath0."/service-group");
        if (count($check)==0) {
            $theProfiles2=$xml->xpath($xpath0);
            $theProfiles2[0]->addChild('service-group');
        } else {
            $SA = $xml->xpath($xpath0."/service-group");
            unset($SA[0][0]);
            $theProfiles2=$xml->xpath($xpath0);
            $theProfiles2[0]->addChild('service-group');
        }
        $theProfiles = $theProfiles2[0]->{'service-group'};
        while ($Data = $getShared->fetch_assoc()) {
            $groupName = $Data['name'];
            $lid = $Data['id'];
            $myname = $Data['name'];
            $disable_override=$Data['disable_override'];
            //$objectsInMemory['services_groups_id'][$lid]['name']=$myname;
            $getMembers = $projectdb->query("SELECT table_name,member_lid FROM services_groups WHERE lid='$lid' ORDER BY id");
            if ($getMembers->num_rows > 0) {
                $service = $theProfiles->addChild('entry');
                $service->addAttribute('name', $Data['name']);
                if ($version >= 6) {
                    $service2 = $service->addChild('members');
                } elseif ($version < 6) {
                    $service2 = $service;
                }
                while ($Datas = $getMembers->fetch_assoc()) {
                    $table_name = $Datas['table_name'];
                    $member_lid = $Datas['member_lid'];
                    $member = $service2->addChild('member', $objectsInMemory[$table_name][$member_lid]['name']);
                }

                if ($ispanorama==1){
                    if ($disable_override=="yes"){
                        $service->addChild('disable-override','yes');
                    }
                }

                if($version >= 6){
                    $getTags = $projectdb->query("SELECT tag.name as name, tag.id as id FROM tag, tag_relations 
                        WHERE tag_relations.member_lid=".$lid." AND tag_relations.table_name='services_groups_id' AND tag.id = tag_relations.tag_id;");

                    if ($getTags->num_rows > 0) {
                        $tags = $service->addChild('tag');
                        while($dataT = $getTags->fetch_assoc()){
                            //$tags->addChild('member', htmlentities($dataT['name']));
                            //MT-892
                            $tags->addChild('member', htmlspecialchars($dataT['name']));

                        }
                    }
                }

                if ($api_call == "single") {
                    $xpath = addslashes($xpath0."/service-group/entry[@name='$myname']");
                    $xml_final = addslashes($service->asXML());
                    $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','Services Groups','Services Groups','$xml_final','$xpath','edit');");
                }
            }
        }
        if ($api_call == "atomic") {
            $xpath = addslashes($xpath0."/service-group");
            $xml_final = addslashes($theProfiles->asXML());
            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Services Groups','Services Groups','Services Groups','$xml_final','$xpath','edit');");
        }
    }
    else {
        $SA = $xml->xpath($xpath0."/service-group");
        unset($SA[0][0]);
        if ($api_call=="clean"){
            $xpath = addslashes($xpath0."/service-group");
            $xml_final = "";
            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Remove All Services Groups $vsys','Services Groups','Services Groups','$xml_final','$xpath','delete');");
        }
        $message['code']=true;
        $message['msg']="Removing all Services Groups";
        return $message;
    }


}

function xml_security_rules($xml,$data,&$objectsInMemory){

    $project = $data['project'];
    $ispanorama = $data['ispanorama'];
    $version = $data['version'];
    $api_call=$data['api_call'];
    $projectdb = $data['projectdb'];
    $source = $data['source'];
    $vsys = $data['vsys'];

    if (($vsys=="shared") AND ($ispanorama==0)){
        $message['code'] = false;
        $message['msg'] = "Shared Policies only can be found in Panorama. skipping";
        return $message;
    }

    if ($vsys == "shared") {
        $data['xpath0'] = "/config/shared";
    } else {
        if ($ispanorama == 1) {
            $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='" . $vsys . "']";
            //Validate it exists
            $test_xpath0 = $data['xpath0'];
            $test_xpath1 = $xml->xpath($test_xpath0);
            if(!isset($test_xpath1[0])){
                echo "The $vsys does not exist in the base config. Creating it.\n";
                $new_vsyses = $xml->xpath("/config/devices/entry[@name='localhost.localdomain']/device-group");
                $new_vsys=$new_vsyses[0]->addChild('entry');
                $new_vsys->addAttribute('name', $vsys);
            }
        } else {
            $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='" . $vsys . "']";
            //Validate it exists
            $test_xpath0 = $data['xpath0'];
            $test_xpath1 = $xml->xpath($test_xpath0);
            if(!isset($test_xpath1[0])){
                echo "The $vsys does not exist in the base config. Creating it.\n";
                $new_vsyses = $xml->xpath("/config/devices/entry[@name='localhost.localdomain']/vsys");
                $new_vsys=$new_vsyses[0]->addChild('entry');
                $new_vsys->addAttribute('name', $vsys);
            }
        }
    }
    $xpath0 = $data['xpath0'];

    if ($ispanorama==1){
        $platform="device-group";
        $policies = array("pre-rulebase", "post-rulebase");
    }
    else{
        $platform = "vsys";
        $policies = array("rulebase");
    }

    foreach ($policies as $pkey => $pvalue) {
        if (($pvalue == "pre-rulebase") OR ( $pvalue == "rulebase")) {
            $preorpost = 0;
        } elseif ($pvalue == "post-rulebase") {
            $preorpost = 1;
        }

        $xpath1 = $xml->xpath($xpath0);
        $xpath = $xpath1[0];


        # SECURITY
        if ($ispanorama==1){
            $getPolicies = $projectdb->query("SELECT * FROM security_rules WHERE source='$source' AND vsys='$vsys' AND preorpost='$preorpost' ORDER BY position ASC;");
        }
        else{
            $getPolicies = $projectdb->query("SELECT * FROM security_rules WHERE source='$source' AND vsys='$vsys'  ORDER BY preorpost,position ASC;");
        }

        if ($getPolicies->num_rows > 0) {
            if (!isset($xpath->{$pvalue})) {
                $xpath->addChild($pvalue);
            }

            if (!isset($xpath->{$pvalue}->security)) {
                $xpath->{$pvalue}->addChild('security');
            }

            if (!isset($xpath->{$pvalue}->security->rules)) {
                $xpath->{$pvalue}->security->addChild('rules');
            } else {
                #DELETE RULES
                $SA = $xpath->{$pvalue}->security->xpath("rules");
                $xpath->{$pvalue}->security->rules="";
                //$xpath->{$pvalue}->security->addChild('rules');
            }
            $policy_order = array();
            while ($data2 = $getPolicies->fetch_object()) {
                $myname = $data2->name;
                $uuid = $data2->uuid;
                $policy_order[] = $data2->name;
                $target_negate=$data2->target_negate;
                $lid = $data2->id;

                $rule = $xpath->{$pvalue}->security->rules->addChild('entry');
                $rule->addAttribute('name', $myname);

                if($version >= 9){
                    $rule->addAttribute('uuid', $uuid);
                }

                if ($version > 6.0) {
                    if ($data2->rule_type != "universal") {
                        $rule->addChild("rule-type", $data2->rule_type);
                    }
                }
                if ($data2->dsri == 0) {
                    $dsri = "no";
                } else {
                    $dsri = "yes";
                }
                if ($dsri!="no"){
                    $rule->addChild('option');
                    $rule->option->addChild('disable-server-response-inspection', $dsri);
                }
                if ($version >= 7){
                    if ($data2->icmp_unreachable!=""){
                        $rule->addChild('icmp-unreachable',$data2->icmp_unreachable);
                    }
                }
                if ($data2->profile_type != "None") {
                    $rule->addChild('profile-setting');
                    if ($data2->profile_type == "group") {
                        $profile = $rule->{'profile-setting'}->addChild('group');
                        $getProfiles = $projectdb->query("SELECT member_lid,table_name FROM security_rules_profiles WHERE rule_lid='$lid';");
                        if ($getProfiles->num_rows > 0) {
                            while ($k = $getProfiles->fetch_object()) {
                                $getMember = $projectdb->query("SELECT name FROM $k->table_name WHERE id='$k->member_lid';");
                                if ($getMember->num_rows > 0) {
                                    while ($kk = $getMember->fetch_object()) {
                                        $profile->addChild('member', $kk->name);
                                    }
                                }
                            }
                        }
                        else{
                            add_log2('error','XML Generation','Unable to find Profile or Group was chosen but not selected',$source,'Review the XML check Rule Name:'.$myname,'rules',$lid,'security_rules');
                        }
                    }
                    else {
                        /** @var $profile SimpleXMLElement*/
                        $profile = $rule->{'profile-setting'}->addChild('profiles');
                        $getProfiles = $projectdb->query("SELECT member_lid,table_name FROM security_rules_profiles WHERE rule_lid='$lid';");
                        if ($getProfiles->num_rows > 0) {
                            while ($k = $getProfiles->fetch_object()) {
                                $getMember = $projectdb->query("SELECT name,type FROM $k->table_name WHERE id='$k->member_lid';");
                                if ($getMember->num_rows > 0) {
                                    while ($kk = $getMember->fetch_object()) {
                                        if($k->table_name == 'profiles_groups'){
                                            $thetype = 'group';
                                        }
                                        else{
                                            $thetype = $kk->{'type'};
                                        }

                                        if($thetype == 'group'){ //Verify there was no other profile already in this rule
                                          if($profile->count()==0) {
                                              $theprofiles = $profile->addChild($thetype);
                                              $theprofiles->addChild('member', $kk->name);
                                          }
                                        }
                                        else {
                                            //Verify that this rule does not have a group profile and that the specific profile type is not already in the rule either
                                            if (!isset($profile->{$thetype}) && !isset($profile->{'group'})) {
                                                $theprofiles = $profile->addChild($thetype);
                                                $theprofiles->addChild('member', $kk->name);
                                            }
                                        }
                                    }
                                } else {
                                    $getMember = $projectdb->query("SELECT name,type FROM $k->table_name WHERE source=0 AND id='$k->member_lid';");
                                    if ($getMember->num_rows > 0) {
                                        while ($kk = $getMember->fetch_object()) {
                                            $thetype = $kk->{'type'};
                                            $theprofiles = $profile->addChild($thetype);
                                            $theprofiles->addChild('member', $kk->name);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                $getFrom = $projectdb->query("SELECT name FROM security_rules_from WHERE rule_lid='$lid' ORDER BY id;");
                if ($getFrom->num_rows > 0) {
                    $rule->addChild('from');
                    while ($k = $getFrom->fetch_object()) {
                        $rule->from->addChild('member', $k->name);
                    }
                } else {
                    $rule->addChild('from');
                    $rule->from->addChild('member', 'any');
                }

                $getTo = $projectdb->query("SELECT name FROM security_rules_to WHERE rule_lid='$lid'  ORDER BY id;");
                if ($getTo->num_rows > 0) {
                    $rule->addChild('to');
                    while ($k = $getTo->fetch_object()) {
                        $rule->to->addChild('member', $k->name);
                    }
                } else {
                    $rule->addChild('to');
                    $rule->to->addChild('member', 'any');
                }

                $getSource = $projectdb->query("SELECT member_lid,table_name FROM security_rules_src WHERE rule_lid='$lid' ORDER BY id;");
                if ($getSource->num_rows > 0) {
                    $rule->addChild('source');
                    while ($k = $getSource->fetch_object()) {
                       $rule->source->addChild('member', $objectsInMemory[$k->table_name][$k->member_lid]['name']);
                    }
                } else {
                    $rule->addChild('source');
                    $rule->source->addChild('member', 'any');
                }
                $getDestination = $projectdb->query("SELECT member_lid,table_name FROM security_rules_dst WHERE rule_lid='$lid' ORDER BY id;");
                //echo "SELECT member_lid,table_name FROM security_rules_dst WHERE rule_lid='$lid' ORDER BY id;\n";
                if ($getDestination->num_rows > 0) {
                    $rule->addChild('destination');
                    while ($k = $getDestination->fetch_object()) {
                        //echo "Member: ".$objectsInMemory[$k->table_name][$k->member_lid]['name']."\n";
                        $rule->destination->addChild('member', $objectsInMemory[$k->table_name][$k->member_lid]['name']);
                    }
                } else {
                    $rule->addChild('destination');
                    $rule->destination->addChild('member', 'any');
                }
                $getUser = $projectdb->query("SELECT name FROM security_rules_usr WHERE rule_lid='$lid' ORDER BY id;");
                if ($getUser->num_rows > 0) {
                    $rule->addChild('source-user');
                    while ($k = $getUser->fetch_object()) {
                        //$rule->{'source-user'}->addChild('member',htmlentities($k->name));
                        //It got a weird character (Entity 'uuml' not defined in Entity) MT-892
                        //$rule->{'source-user'}->addChild('member',$k->name);
                        $rule->{'source-user'}->addChild('member',htmlspecialchars($k->name));
                        //$rule->{'source-user'}->addChild('member',html_entity_decode($k->name));
                        //echo "User: " .htmlentities($k->name). "\n";


                    }
                } else {
                    $rule->addChild('source-user');
                    $rule->{'source-user'}->addChild('member', 'any');
                }
                $getCategory = $projectdb->query("SELECT name FROM security_rules_categories WHERE rule_lid='$lid' ORDER BY id;");
                if ($getCategory->num_rows > 0) {
                    $rule->addChild('category');
                    while ($k = $getCategory->fetch_object()) {
                        $rule->category->addChild('member', $k->name);
                    }
                } else {
                    $rule->addChild('category');
                    $rule->category->addChild('member', 'any');
                }

                $getAPP = $projectdb->query("SELECT member_lid,table_name FROM security_rules_app WHERE rule_lid='$lid' ORDER BY id;");
                if ($getAPP->num_rows > 0) {
                    $rule->addChild('application');
                    while ($k = $getAPP->fetch_object()) {
                        $rule->{'application'}->addChild('member', $objectsInMemory[$k->table_name][$k->member_lid]['name']);
                    }
                } else {
                    $rule->addChild('application');
                    $rule->{'application'}->addChild('member', 'any');
                }
                $getSRV = $projectdb->query("SELECT member_lid,table_name FROM security_rules_srv WHERE rule_lid='$lid' ORDER BY id;");
                if ($getSRV->num_rows > 0) {
                    $rule->addChild('service');
                    while ($k = $getSRV->fetch_object()) {
                        if (isset($objectsInMemory[$k->table_name][$k->member_lid])){
                            $rule->{'service'}->addChild('member', $objectsInMemory[$k->table_name][$k->member_lid]['name']);
                        }
                        else{
                            $loadApps=$projectdb->query("SELECT id,name FROM $k->table_name WHERE id='$k->member_lid';");
                            if ($loadApps->num_rows==1){
                                $data=$loadApps->fetch_assoc();
                                $name=$data['name'];
                                $objectsInMemory[$k->table_name][$k->member_lid]['name']=$name;
                                $rule->{'service'}->addChild('member', $objectsInMemory[$k->table_name][$k->member_lid]['name']);
                            }
                        }

                    }
                } else {
                    $rule->addChild('service');
                    $rule->{'service'}->addChild('member', 'any');
                }
                $hipProfiles_field = ($version >= 10)?'source-hip':'hip-profiles';
                $getHIP = $projectdb->query("SELECT member_lid,table_name,name FROM security_rules_hip WHERE rule_lid='$lid' ORDER BY id;");
                if ($getHIP->num_rows > 0) {
                    $rule->addChild($hipProfiles_field);
                    while ($k = $getHIP->fetch_object()) {
                        if (($k->member_lid == 0) AND ( $k->table_name == "default")) {
                            $rule->{$hipProfiles_field}->addChild('member', $k->name);
                        }
                        else if (($k->member_lid == 0) AND ( $k->table_name == "profiles")) {
                            $rule->{$hipProfiles_field}->addChild('member', 'no-hip');
                        }
                        else {
                            $getMember = $projectdb->query("SELECT name FROM $k->table_name WHERE id='$k->member_lid' AND type='hip-profiles';");
                            if ($getMember->num_rows > 0) {
                                while ($kk = $getMember->fetch_object()) {
                                    $rule->{$hipProfiles_field}->addChild('member', $kk->name);
                                }
                            }
                        }
                    }
                } else {
                    $rule->addChild($hipProfiles_field);
                    $rule->{$hipProfiles_field}->addChild('member', 'any');
                }

                $rule->addChild('action', $data2->action);
                if ($data2->log_start == 1) {
                    $rule->addChild('log-start', 'yes');
                }
                if ($data2->log_end == 1) {
                    //$rule->addChild('log-end', 'yes');
                }
                else{
                    $rule->addChild('log-end', 'no');
                }
                if ($data2->disabled == 1) {
                    $rule->addChild('disabled', 'yes');
                } else {
                    //$rule->addChild('disabled', 'no');
                }
                if ($data2->negate_source == 1) {
                    $rule->addChild('negate-source', 'yes');
                } else {
                    //$rule->addChild('negate-source', 'no');
                }
                if ($data2->negate_destination == 1) {
                    $rule->addChild('negate-destination', 'yes');
                } else {
                    //$rule->addChild('negate-destination', 'no');
                }
                if ($data2->description != "") {
                    $rule->addChild('description');
                    $rule->description = truncate_descriptions($data2->description,$version);
                }
                if ($data2->schedule != "") {
                    $rule->addChild('schedule', $data2->schedule);
                }
                if ($data2->log_forwarding != "") {
                    $rule->addChild('log-setting', $data2->log_forwarding);
                }
                if ($data2->qos != "None") {
                    if($version >=7){
                        $rule->addChild('qos');
                        $rule->qos->addChild('marking');
                        $rule->qos->marking->addChild($data2->qos, $data2->qos_value);
                    }elseif($data2->qos == "ip-dscp" || $data2->qos == "ip-precedence"){
                        $rule->addChild('qos');
                        $rule->qos->addChild('marking');
                        $rule->qos->marking->addChild($data2->qos, $data2->qos_value);
                    }
                }

                if($version >= 9){
                    if($data2->group_tag_id != 0){
                        $getGroupTag = $projectdb->query("SELECT name FROM tag WHERE id = '$data2->group_tag_id';");
                        if ($getGroupTag->num_rows > 0) {
                            $k = $getGroupTag->fetch_object();
                            $rule->addChild('group-tag', htmlspecialchars($k->name));
                        }
                    }
                }

                $getTAG = $projectdb->query("SELECT member_lid,table_name FROM security_rules_tag WHERE rule_lid='$lid' ORDER BY id;");
                if ($getTAG->num_rows > 0) {
                    $rule->addChild('tag');
                    while ($k = $getTAG->fetch_object()) {
                        //$rule->{'tag'}->addChild('member', $objectsInMemory[$k->table_name][$k->member_lid]['name']);
                        //echo "Member: " .$objectsInMemory[$k->table_name][$k->member_lid]['name']. "\n";
                        //$rule->{'tag'}->addChild('member', htmlentities($objectsInMemory[$k->table_name][$k->member_lid]['name']));
                        //MT-892
                        $rule->{'tag'}->addChild('member', htmlspecialchars($objectsInMemory[$k->table_name][$k->member_lid]['name']));

                        //echo "Member htmlentities: " .htmlentities($objectsInMemory[$k->table_name][$k->member_lid]['name']). "\n";
                        //echo "Member htmlspecialchars: " .htmlspecialchars($objectsInMemory[$k->table_name][$k->member_lid]['name']). "\n";
                    }
                }
                if ($ispanorama==1){
                    $getTarget=$projectdb->query("SELECT * FROM security_rules_target WHERE rule_lid='$lid' ORDER BY id;");

                    if ($getTarget->num_rows>0){
                        $rule->addChild("target");
                        if ($target_negate!=""){
                            $rule->target->addChild("negate",$target_negate);
                        }
                        $rule->target->addChild("devices");
                        while($getTargetData=$getTarget->fetch_assoc()){
                            $device_vsys=$getTargetData['device_vsys'];
                            $name=$getTargetData['name'];
                            if (empty($rule->target->devices->xpath("./entry[@name='$name']"))){
                                $target=$rule->target->devices->addChild("entry");
                                $target->addAttribute("name",$name);
                            }
                            else{
                                $target0=$rule->target->devices->xpath("./entry[@name='$name']");
                                $target=$target0[0];
                            }

                            if ($device_vsys!=""){
                                if (!isset($target->vsys)){
                                    $target->addChild("vsys");
                                }
                                $target_vsys=$target->vsys->addChild("entry");
                                $target_vsys->addAttribute("name",$device_vsys);
                            }
                        }
                    }
                }


                if ($api_call == "single") {
                    $xpath2 = addslashes($xpath0."/$pvalue/security/rules/entry[@name='$myname']");
                    $xml_final = addslashes($rule->asXML());
                    $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','Security Rules','Security Rules','$xml_final','$xpath2','edit');");
                }

            }
            if ($api_call == "atomic") {
                $xpath2 = addslashes($xpath0."/$pvalue/security");
                $xml_final = addslashes($xpath->{$pvalue}->security->asXML());
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Security Rules $vsys','Security Rules','Security Rules','$xml_final','$xpath2','edit');");
            }
            if ((count($policy_order) > 0) AND ( $api_call == "single")) {
                $first = $policy_order[0];
                $last = $policy_order[count($policy_order) - 1];
                # Set first Rule
                $xpath = addslashes($xpath0."/$pvalue/security/rules/entry[@name='$first']");
                $where = "top";
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action,whereto,dst) VALUES ('$first to Top','Security Rules','order','','$xpath','move','$where','');");
                unset($policy_order[0]);
                foreach ($policy_order as $key => $value) {
                    $xpath = addslashes($xpath0."/$pvalue/security/rules/entry[@name='$value']");
                    $where = "after";
                    $dst = addslashes("$first");
                    $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action,whereto,dst) VALUES ('$value after $first','Security Rules','order','','$xpath','move','$where','$dst');");
                    $first = $value;
                }
                unset($policy_order);
            }
        }
        else {
            if (isset($xpath->{$pvalue}->security)) {
                $SA = $xpath->{$pvalue}->xpath("security");
                unset($SA[0][0]);
                $xpath->{$pvalue}->addChild("security");
                $xpath->{$pvalue}->security->addChild("rules");
            }
            if ($api_call == "clean") {
                $xpath2 = addslashes($xpath0."/$pvalue/security");
                $xml_final = "";
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Remove All Security Rules $vsys $pvalue','Security Rules','Security Rules','$xml_final','$xpath2','delete');");
            }
        }
    }


}

function xml_nat_rules($xml,$data,&$objectsInMemory=null){

    $project = $data['project'];
    $ispanorama = $data['ispanorama'];
    $version = $data['version'];
    $api_call=$data['api_call'];
    $projectdb = $data['projectdb'];
    $source = $data['source'];
    $vsys = $data['vsys'];

    if (($vsys=="shared") AND ($ispanorama==0)){
        $message['code'] = false;
        $message['msg'] = "Shared Policies only can be found in Panorama. skipping";
        return $message;
    }

    if ($vsys == "shared") {
        $data['xpath0'] = "/config/shared";
    }
    else {
        if ($ispanorama == 1) {
            $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='" . $vsys . "']";
        }
        else {
            $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='" . $vsys . "']";
        }
    }
    $xpath0 = $data['xpath0'];

    if ($ispanorama==1){
        $platform="device-group";
        $policies = array("pre-rulebase", "post-rulebase");
    }
    else{
        $platform = "vsys";
        $policies = array("rulebase");
    }
    foreach ($policies as $pkey => $pvalue) {
        if (($pvalue == "pre-rulebase") OR ($pvalue == "rulebase")) {
            $preorpost = 0;
        } elseif ($pvalue == "post-rulebase") {
            $preorpost = 1;
        }
        $xpath1 = $xml->xpath($xpath0);
        $xpath = $xpath1[0];

        # NAT
        if ($ispanorama==1){
            $getPolicies = $projectdb->query("SELECT * FROM nat_rules WHERE source='$source' AND vsys='$vsys' AND preorpost='$preorpost' ORDER BY position ASC;");
        }else{
            $getPolicies = $projectdb->query("SELECT * FROM nat_rules WHERE source='$source' AND vsys='$vsys'  ORDER BY preorpost,position ASC;");
        }

        if ($getPolicies->num_rows > 0) {
            if (!isset($xpath->{$pvalue})) {
                $xpath->addChild($pvalue);
            }
            if (!isset($xpath->{$pvalue}->nat)) {
                $xpath->{$pvalue}->addChild('nat');
            }
            if (!isset($xpath->{$pvalue}->nat->rules)) {
                $xpath->{$pvalue}->nat->addChild('rules');
            }
            else {
                #DELETE RULES
                $SA = $xpath->{$pvalue}->nat->xpath("rules");
                unset($SA[0][0]);
                $xpath->{$pvalue}->nat->addChild('rules');
            }
            $policy_order = array();
            while ($data2 = $getPolicies->fetch_object()) {
                $myname = $data2->name;
                $uuid = $data2->uuid;
                $policy_order[] = $data2->name;
                $lid = $data2->id;
                $target_negate = $data2->target_negate;

                $rule = $xpath->{$pvalue}->nat->rules->addChild('entry');
                $rule->addAttribute('name', $myname);

                if($version >= 9){
                    $rule->addAttribute('uuid', $uuid);
                }

                if ($data2->tp_sat_type == "dynamic-ip") {
                    $rule->addChild('source-translation');
                    $stnat = $rule->{'source-translation'}->addChild('dynamic-ip');
                    if ($data2->tp_fallback_type == "translated-address") {
                        $getAddr = $projectdb->query("SELECT member_lid,table_name FROM nat_rules_translated_address_fallback WHERE rule_lid='$lid';");
                        if ($getAddr->num_rows > 0) {
                            $stnat->addChild('fallback');
                            $stnat->fallback->addChild('translated-address');
                            while ($getAddrData = $getAddr->fetch_object()) {
                                $stnat->fallback->{'translated-address'}->addChild('member', $objectsInMemory[$getAddrData->table_name][$getAddrData->member_lid]['name']);
                            }
                        }
                    }
                    elseif ($data2->tp_fallback_type == "interface-address") {
                        $stnat->addChild('fallback');
                        $stnat->fallback->addChild('interface-address');
                        if ($data2->tp_sat_interface_fallback != "") {
                            $stnat->fallback->{'interface-address'}->addChild('interface', $data2->tp_sat_interface_fallback);
                        }
                        if ($data2->tp_sat_ipaddress_fallback != "") {
                            $stnat->fallback->{'interface-address'}->addChild('ip', $data2->tp_sat_ipaddress_fallback);
                        }
                    }
                    $getAddr = $projectdb->query("SELECT member_lid,table_name FROM nat_rules_translated_address WHERE rule_lid='$lid';");
                    if ($getAddr->num_rows > 0) {
                        $stnat->addChild('translated-address');
                        while ($getAddrData = $getAddr->fetch_object()) {
                            $stnat->{'translated-address'}->addChild('member', $objectsInMemory[$getAddrData->table_name][$getAddrData->member_lid]['name']);

                        }
                    }
                }
                elseif ($data2->tp_sat_type == "dynamic-ip-and-port") {
                    $rule->addChild('source-translation');
                    $stnat = $rule->{'source-translation'}->addChild('dynamic-ip-and-port');
                    if ($data2->tp_sat_address_type == "interface-address") {
                        $stnat->addChild('interface-address');
                        $stnat->{'interface-address'}->addChild('interface', $data2->tp_sat_interface);
                        if (($data2->tp_sat_ipaddress != "") AND ($data2->tp_sat_ipaddress != "None")) {
                            $stnat->{'interface-address'}->addChild('ip', $data2->tp_sat_ipaddress);
                        }
                    }
                    else {
                        $getAddr = $projectdb->query("SELECT member_lid,table_name FROM nat_rules_translated_address WHERE rule_lid='$lid';");
                        if ($getAddr->num_rows > 0) {
                            $stnat->addChild('translated-address');
                            while ($getAddrData = $getAddr->fetch_object()) {
                                $stnat->{'translated-address'}->addChild('member', $objectsInMemory[$getAddrData->table_name][$getAddrData->member_lid]['name']);
                            }
                        }
                    }
                }
                elseif ($data2->tp_sat_type == "static-ip") {
                    $rule->addChild('source-translation');
                    $stnat = $rule->{'source-translation'}->addChild('static-ip');
                    if ($data2->tp_sat_bidirectional == 1) {
                        $stnat->addChild('bi-directional', 'yes');
                    }
                    else {
                        $stnat->addChild('bi-directional', 'no');
                    }
                    $getAddr = $projectdb->query("SELECT table_name,member_lid FROM nat_rules_translated_address WHERE rule_lid='$lid';");
                    if ($getAddr->num_rows == 1) {
                        $getAddrData = $getAddr->fetch_object();
                        $stnat->addChild('translated-address', $objectsInMemory[$getAddrData->table_name][$getAddrData->member_lid]['name']);
                    }
                }
                if ($data2->is_dat == 1) {
                    $dtnat = $rule->addChild('destination-translation');
                    if (($data2->tp_dat_address_lid == 0) AND ($data2->tp_dat_address_table == "")) {}
                    else {
                        $dtnat->addChild('translated-address', $objectsInMemory[$data2->tp_dat_address_table][$data2->tp_dat_address_lid]['name']);
                    }
                    if ($data2->tp_dat_port != 0) {
                        $dtnat->addChild('translated-port', $data2->tp_dat_port);
                    }
                }
                if ($data2->is_dat == 2) {
                    $dtnat = $rule->addChild('dynamic-destination-translation');
                    if (($data2->tp_dat_address_lid == 0) AND ($data2->tp_dat_address_table == "")) {}
                    else {
                        $dtnat->addChild('translated-address', $objectsInMemory[$data2->tp_dat_address_table][$data2->tp_dat_address_lid]['name']);
                    }
                    if ($data2->tp_dat_port != 0) {
                        $dtnat->addChild('translated-port', $data2->tp_dat_port);
                    }
                }
                if ($data2->op_zone_to != "") {
                    $rule->addChild('to');
                    $rule->to->addChild('member', $data2->op_zone_to);
                }
                else {
                    $rule->addChild('to');
                    $rule->to->addChild('member', 'any');
                }
                $getFrom = $projectdb->query("SELECT name FROM nat_rules_from WHERE rule_lid='$lid';");
                if ($getFrom->num_rows > 0) {
                    $rule->addChild('from');
                    while ($k = $getFrom->fetch_object()) {
                        $rule->from->addChild('member', $k->name);
                    }
                }
                else {
                    $rule->addChild('from');
                    $rule->from->addChild('member', 'any');
                }
                $getSource = $projectdb->query("SELECT member_lid,table_name FROM nat_rules_src WHERE rule_lid='$lid';");
                //echo "1. SELECT member_lid,table_name FROM nat_rules_src WHERE rule_lid='$lid';\n";
                if ($getSource->num_rows > 0) {
                    $rule->addChild('source');
                    while ($k = $getSource->fetch_object()) {
                        $rule->source->addChild('member', $objectsInMemory[$k->table_name][$k->member_lid]['name']);
                        //echo "Member: " .$objectsInMemory[$k->table_name][$k->member_lid]['name']. "\n";
                    }
                }
                else {
                    $rule->addChild('source');
                    $rule->source->addChild('member', 'any');
                }
                $getDestination = $projectdb->query("SELECT member_lid,table_name FROM nat_rules_dst WHERE rule_lid='$lid';");
                //echo "2. SELECT member_lid,table_name FROM nat_rules_dst WHERE rule_lid='$lid';\n";
                if ($getDestination->num_rows > 0) {
                    $rule->addChild('destination');
                    while ($k = $getDestination->fetch_object()) {
                        //echo "Member on nats: " .$objectsInMemory[$k->table_name][$k->member_lid]['name']. "\n";
                        $rule->destination->addChild('member', $objectsInMemory[$k->table_name][$k->member_lid]['name']);
                    }
                }
                else {
                    $rule->addChild('destination');
                    $rule->destination->addChild('member', 'any');
                }
                
                if (($data2->op_service_table != "") AND ($data2->op_service_lid != "") AND ($data2->op_service_lid != "0") ) {
                    $rule->addChild('service', $objectsInMemory[$data2->op_service_table][$data2->op_service_lid]['name']);
                }
                else {
                    $rule->addChild('service', 'any');
                }
                if ($data2->op_to_interface != "") {
                    $rule->addChild('to-interface', $data2->op_to_interface);
                }
                if ($data2->disabled == 1) {
                    $rule->addChild('disabled', 'yes');
                }
                else {
                    //$rule->addChild('disabled', 'no');
                }
                if (($data2->nat_type != "") AND ($data2->nat_type!="ipv4") ){
                    $rule->addChild('nat-type', $data2->nat_type);
                }
                //else {
                //    $rule->addChild('nat-type', 'ipv4');
                //}
                $getTAG = $projectdb->query("SELECT member_lid,table_name FROM nat_rules_tag WHERE rule_lid='$lid';");
                if ($getTAG->num_rows > 0) {
                    $rule->addChild('tag');
                    while ($k = $getTAG->fetch_object()) {
                        //$rule->tag->addChild('member', htmlentities($objectsInMemory[$k->table_name][$k->member_lid]['name']));
                        //MT-892
                        $rule->tag->addChild('member', htmlspecialchars($objectsInMemory[$k->table_name][$k->member_lid]['name']));

                    }
                }

                if($version >= 9){
                    if($data2->group_tag_id != 0){
                        $getGroupTag = $projectdb->query("SELECT name FROM tag WHERE id = '$data2->group_tag_id';");
                        if ($getGroupTag->num_rows > 0) {
                            $k = $getGroupTag->fetch_object();
                            $rule->addChild('group-tag', htmlspecialchars($k->name));
                        }
                    }
                }

                if ($ispanorama==1){
                    $getTarget=$projectdb->query("SELECT * FROM nat_rules_target WHERE rule_lid='$lid' ORDER BY id;");

                    if ($getTarget->num_rows>0){
                        $rule->addChild("target");
                        if ($target_negate!=""){
                            $rule->target->addChild("negate",$target_negate);
                        }
                        $rule->target->addChild("devices");
                        while($getTargetData=$getTarget->fetch_assoc()){
                            $device_vsys=$getTargetData['device_vsys'];
                            $name=$getTargetData['name'];
                            if (empty($rule->target->devices->xpath("./entry[@name='$name']"))){
                                $target=$rule->target->devices->addChild("entry");
                                $target->addAttribute("name",$name);
                            }
                            else{
                                $target0=$rule->target->devices->xpath("./entry[@name='$name']");
                                $target=$target0[0];
                            }

                            if ($device_vsys!=""){
                                if (!isset($target->vsys)){
                                    $target->addChild("vsys");
                                }
                                $target_vsys=$target->vsys->addChild("entry");
                                $target_vsys->addAttribute("name",$device_vsys);
                            }
                        }
                    }
                }

                //if ($data2->target != "") {
                //    libxml_use_internal_errors(true);
                //    $xml_append = simplexml_load_string($data2->target);
                //    if ($xml_append) {
                //        SimpleXMLElement_append($rule, $xml_append);
                //    }
                //}

                if ($data2->description != "") {
                    $rule->addChild('description');
                    $rule->description = truncate_descriptions($data2->description,$version);
                }
                if ($data2->active_active_device_binding != "") {
                    $rule->addChild('active-active-device-binding', $data2->active_active_device_binding);
                }

                if ($api_call == "single") {
                    $xpath2 = addslashes("$xpath0/$pvalue/nat/rules/entry[@name='$myname']");
                    $xml_final = addslashes($rule->asXML());
                    $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','Nat Rules','Nat Rules','$xml_final','$xpath2','edit');");
                }

            }
            if ($api_call == "atomic") {
                $xpath2 = addslashes($xpath0."/$pvalue/nat");
                $xml_final = addslashes($xpath->{$pvalue}->nat->asXML());
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Nat Rules','Nat Rules','Nat Rules','$xml_final','$xpath2','edit');");
            }
            if ((count($policy_order) > 0) AND ( $api_call == "single")) {
                $first = $policy_order[0];
                $last = $policy_order[count($policy_order) - 1];
                # Set first Rule
                $xpath = addslashes($xpath0."/$pvalue/nat/rules/entry[@name='$first']");
                $where = "top";
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action,whereto,dst) VALUES ('$first to Top','Nat Rules','order','','$xpath','move','$where','');");
                unset($policy_order[0]);
                foreach ($policy_order as $key => $value) {
                    $xpath = addslashes($xpath0."/$pvalue/nat/rules/entry[@name='$value']");
                    $where = "after";
                    $dst = addslashes("$first");
                    $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action,whereto,dst) VALUES ('$value after $first','Nat Rules','order','','$xpath','move','$where','$dst');");
                    $first = $value;
                }
                unset($policy_order);
            }
        }
        else {
            if (isset($xpath->{$pvalue}->nat)) {
                $SA = $xpath->{$pvalue}->xpath("nat");
                unset($SA[0][0]);
                $xpath->{$pvalue}->addChild("nat");
                $xpath->{$pvalue}->nat->addChild("rules");
            }
            if ($api_call == "clean") {
                $xpath2 = addslashes($xpath0."/$pvalue/nat");
                $xml_final = "";
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Remove All Nat Rules $vsys $pvalue','Nat Rules','Nat Rules','$xml_final','$xpath2','delete');");
            }
        }
    }

}

function xml_appoverride_rules($xml,$data,&$objectsInMemory=null){

    $project = $data['project'];
    $ispanorama = $data['ispanorama'];
    $version = $data['version'];
    $api_call=$data['api_call'];
    $projectdb = $data['projectdb'];
    $source = $data['source'];
    $vsys = $data['vsys'];

    if (($vsys=="shared") AND ($ispanorama==0)){
        $message['code'] = false;
        $message['msg'] = "Shared Policies only can be found in Panorama. skipping";
        return $message;
    }

    if ($vsys == "shared") {
        $data['xpath0'] = "/config/shared";
    } else {
        if ($ispanorama == 1) {
            $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='" . $vsys . "']";
        } else {
            $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='" . $vsys . "']";
        }
    }
    $xpath0 = $data['xpath0'];

    if ($ispanorama==1){
        $platform="device-group";
        $policies = array("pre-rulebase", "post-rulebase");
    }
    else{
        $platform = "vsys";
        $policies = array("rulebase");
    }

    foreach ($policies as $pkey => $pvalue) {
        if (($pvalue == "pre-rulebase") OR ($pvalue == "rulebase")) {
            $preorpost = 0;
        } elseif ($pvalue == "post-rulebase") {
            $preorpost = 1;
        }
        $xpath1 = $xml->xpath($xpath0);
        $xpath = $xpath1[0];

        # APPLICATION OVERRIDE
        if ($ispanorama==1){
            $getPolicies = $projectdb->query("SELECT * FROM appoverride_rules WHERE source='$source' AND vsys='$vsys' AND preorpost='$preorpost' ORDER BY position ASC;");
        }
        else{
            $getPolicies = $projectdb->query("SELECT * FROM appoverride_rules WHERE source='$source' AND vsys='$vsys' ORDER BY preorpost,position ASC;");
        }

        if ($getPolicies->num_rows > 0) {
            if (!isset($xpath->{$pvalue})) {
                $xpath->addChild($pvalue);
            }

            if (!isset($xpath->{$pvalue}->{'application-override'})) {
                $xpath->{$pvalue}->addChild('application-override');
            }

            if (!isset($xpath->{$pvalue}->{'application-override'}->rules)) {
                $xpath->{$pvalue}->{'application-override'}->addChild('rules');
            } else {
                #DELETE RULES
                $SA = $xpath->{$pvalue}->{'application-override'}->xpath("rules");
                unset($SA[0][0]);
                $xpath->{$pvalue}->{'application-override'}->addChild('rules');
            }

            while ($data2 = $getPolicies->fetch_object()) {
                $myname = $data2->name;
                $uuid = $data2->uuid;
                $lid = $data2->id;
                $target_negate = $data2->target_negate;

                $rule = $xpath->{$pvalue}->{'application-override'}->rules->addChild('entry');
                $rule->addAttribute('name', $myname);

                if($version >= 9){
                    $rule->addAttribute('uuid', $uuid);
                }

                $getFrom = $projectdb->query("SELECT name FROM appoverride_rules_from WHERE rule_lid='$lid';");
                if ($getFrom->num_rows > 0) {
                    $rule->addChild('from');
                    while ($k = $getFrom->fetch_object()) {
                        $rule->from->addChild('member', $k->name);
                    }
                }
                else {
                    $rule->addChild('from');
                    $rule->from->addChild('member', 'any');
                }
                $getTo = $projectdb->query("SELECT name FROM appoverride_rules_to WHERE rule_lid='$lid';");
                if ($getTo->num_rows > 0) {
                    $rule->addChild('to');
                    while ($k = $getTo->fetch_object()) {
                        $rule->to->addChild('member', $k->name);
                    }
                } else {
                    $rule->addChild('to');
                    $rule->to->addChild('member', 'any');
                }
                $getSource = $projectdb->query("SELECT member_lid,table_name FROM appoverride_rules_src WHERE rule_lid='$lid';");
                if ($getSource->num_rows > 0) {
                    $rule->addChild('source');
                    while ($k = $getSource->fetch_object()) {
                        $rule->source->addChild('member', $objectsInMemory[$k->table_name][$k->member_lid]['name']);
                    }
                } else {
                    $rule->addChild('source');
                    $rule->source->addChild('member', 'any');
                }
                $getDestination = $projectdb->query("SELECT member_lid,table_name FROM appoverride_rules_dst WHERE rule_lid='$lid';");
                if ($getDestination->num_rows > 0) {
                    $rule->addChild('destination');
                    while ($k = $getDestination->fetch_object()) {
                        $rule->destination->addChild('member', $objectsInMemory[$k->table_name][$k->member_lid]['name']);
                    }
                } else {
                    $rule->addChild('destination');
                    $rule->destination->addChild('member', 'any');
                }

                if (isset($objectsInMemory[$data2->app_table][$data2->app_id]['name'])){
                    $rule->addChild('application', $objectsInMemory[$data2->app_table][$data2->app_id]['name']);
                }
                else{
                    $getAPP = $projectdb->query("SELECT name FROM $data2->app_table WHERE id='$data2->app_id';");
                    if ($getAPP->num_rows == 1) {
                        $k = $getAPP->fetch_object();
                        $rule->addChild('application', $k->name);
                    }
                }

                if ($data2->disabled == 1) {
                    $rule->addChild('disabled', 'yes');
                } else {
                    //$rule->addChild('disabled', 'no');
                }
                if ($data2->negate_source == 1) {
                    $rule->addChild('negate-source', 'yes');
                } else {
                    //$rule->addChild('negate-source', 'no');
                }
                if ($data2->negate_destination == 1) {
                    $rule->addChild('negate-destination', 'yes');
                } else {
                    //$rule->addChild('negate-destination', 'no');
                }
                if ($data2->description != "") {
                    $rule->addChild('description');
                    $rule->description = truncate_descriptions($data2->description,$version);
                }
                $rule->addChild('protocol', $data2->protocol);
                $rule->addChild('port', $data2->port);

                $getTAG = $projectdb->query("SELECT member_lid,table_name FROM appoverride_rules_tag WHERE rule_lid='$lid';");
                if ($getTAG->num_rows > 0) {
                    $rule->addChild('tag');
                    while ($k = $getTAG->fetch_object()) {
                        //$rule->tag->addChild('member', htmlentities($objectsInMemory[$k->table_name][$k->member_lid]['name']));
                        //MT-892
                        $rule->tag->addChild('member', htmlspecialchars($objectsInMemory[$k->table_name][$k->member_lid]['name']));

                    }
                }

                if($version >= 9){
                    if($data2->group_tag_id != 0){
                        $getGroupTag = $projectdb->query("SELECT name FROM tag WHERE id = '$data2->group_tag_id';");
                        if ($getGroupTag->num_rows > 0) {
                            $k = $getGroupTag->fetch_object();
                            $rule->addChild('group-tag', htmlspecialchars($k->name));
                        }
                    }
                }

                if ($ispanorama==1){
                    $getTarget=$projectdb->query("SELECT * FROM appoverride_rules_target WHERE rule_lid='$lid' ORDER BY id;");

                    if ($getTarget->num_rows>0){
                        $rule->addChild("target");
                        if ($target_negate!=""){
                            $rule->target->addChild("negate",$target_negate);
                        }
                        $rule->target->addChild("devices");
                        while($getTargetData=$getTarget->fetch_assoc()){
                            $device_vsys=$getTargetData['device_vsys'];
                            $name=$getTargetData['name'];
                            if (empty($rule->target->devices->xpath("./entry[@name='$name']"))){
                                $target=$rule->target->devices->addChild("entry");
                                $target->addAttribute("name",$name);
                            }
                            else{
                                $target0=$rule->target->devices->xpath("./entry[@name='$name']");
                                $target=$target0[0];
                            }

                            if ($device_vsys!=""){
                                if (!isset($target->vsys)){
                                    $target->addChild("vsys");
                                }
                                $target_vsys=$target->vsys->addChild("entry");
                                $target_vsys->addAttribute("name",$device_vsys);
                            }
                        }
                    }
                }

                //if ($data2->target != "") {
                //    libxml_use_internal_errors(true);
                //    $xml_append = simplexml_load_string($data2->target);
                //    if ($xml_append) {
                //        SimpleXMLElement_append($rule, $xml_append);
                //    }
                //}

                if ($api_call == "single") {
                    $xpath2 = addslashes($xpath0."/$pvalue/application-override/rules/entry[@name='$myname']");
                    $xml_final = addslashes($rule->asXML());
                    $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','App Override Rules','App Override Rules','$xml_final','$xpath2','edit');");
                }


            }
            if ($api_call == "atomic") {
                $xpath2 = addslashes($xpath0."/$pvalue/application-override");
                $xml_final = addslashes($xpath->{$pvalue}->{'application-override'}->asXML());
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('App Override Rules','App Override Rules','App Override Rules','$xml_final','$xpath2','edit');");
            }
        }
        else {
            #DELETE RULES
            if (isset($xpath->{$pvalue}->{'application-override'})) {
                $SA = $xpath->{$pvalue}->xpath("application-override");
                unset($SA[0][0]);
                $xpath->{$pvalue}->addChild("application-override");
                $xpath->{$pvalue}->{'application-override'}->addChild("rules");
            }
            if ($api_call=="clean"){
                $xpath2 = addslashes($xpath0."/$pvalue/application-override");
                $xml_final = "";
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Remove All App Override Rules $vsys','App Override Rule','App Override Rule','$xml_final','$xpath2','delete');");
            }
        }
    }
}


function xml_authentication_rules($xml,$data,&$objectsInMemory){

    $project = $data['project'];
    $ispanorama = $data['ispanorama'];
    $version = $data['version'];
    $api_call=$data['api_call'];
    $projectdb = $data['projectdb'];
    $source = $data['source'];
    $vsys = $data['vsys'];

    if (($vsys=="shared") AND ($ispanorama==0)){
        $message['code'] = false;
        $message['msg'] = "Shared Policies only can be found in Panorama. skipping";
        return $message;
    }

    if ($vsys == "shared") {
        $data['xpath0'] = "/config/shared";
    } else {
        if ($ispanorama == 1) {
            $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='" . $vsys . "']";
        } else {
            $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='" . $vsys . "']";
        }
    }
    $xpath0 = $data['xpath0'];

    if ($ispanorama==1){
        $platform="device-group";
        $policies = array("pre-rulebase", "post-rulebase");
    }
    else{
        $platform = "vsys";
        $policies = array("rulebase");
    }

    foreach ($policies as $pkey => $pvalue) {
        if (($pvalue == "pre-rulebase") OR ( $pvalue == "rulebase")) {
            $preorpost = 0;
        } elseif ($pvalue == "post-rulebase") {
            $preorpost = 1;
        }

        $xpath1 = $xml->xpath($xpath0);
        $xpath = $xpath1[0];

        # SECURITY
        if ($ispanorama==1){
            $getPolicies = $projectdb->query("SELECT * FROM authentication_rules WHERE source='$source' AND vsys='$vsys' AND preorpost='$preorpost' ORDER BY position ASC;");
        }
        else{
            $getPolicies = $projectdb->query("SELECT * FROM authentication_rules WHERE source='$source' AND vsys='$vsys'  ORDER BY preorpost,position ASC;");
        }

        if ($getPolicies->num_rows > 0) {
            if (!isset($xpath->{$pvalue})) {
                $xpath->addChild($pvalue);
            }

            if (!isset($xpath->{$pvalue}->authentication)) {
                $xpath->{$pvalue}->addChild('authentication');
            }

            if (!isset($xpath->{$pvalue}->authentication->rules)) {
                $xpath->{$pvalue}->authentication->addChild('rules');
            } else {
                #DELETE RULES
                $SA = $xpath->{$pvalue}->authentication->xpath("rules");
                $xpath->{$pvalue}->authentication->rules="";
            }
            $policy_order = array();
            while ($data2 = $getPolicies->fetch_object()) {
                $myname = $data2->name;
                $uuid = $data2->uuid;
                $policy_order[] = $data2->name;
                $target_negate=$data2->target_negate;
                $lid = $data2->id;

                $rule = $xpath->{$pvalue}->authentication->rules->addChild('entry');
                $rule->addAttribute('name', $myname);

                if($version >= 9){
                    $rule->addAttribute('uuid', $uuid);
                }

                $getFrom = $projectdb->query("SELECT name FROM authentication_rules_from WHERE rule_lid='$lid' ORDER BY id;");
                if ($getFrom->num_rows > 0) {
                    $rule->addChild('from');
                    while ($k = $getFrom->fetch_object()) {
                        $rule->from->addChild('member', $k->name);
                    }
                } else {
                    $rule->addChild('from');
                    $rule->from->addChild('member', 'any');
                }

                $getTo = $projectdb->query("SELECT name FROM authentication_rules_to WHERE rule_lid='$lid'  ORDER BY id;");
                if ($getTo->num_rows > 0) {
                    $rule->addChild('to');
                    while ($k = $getTo->fetch_object()) {
                        $rule->to->addChild('member', $k->name);
                    }
                } else {
                    $rule->addChild('to');
                    $rule->to->addChild('member', 'any');
                }

                $getSource = $projectdb->query("SELECT member_lid,table_name FROM authentication_rules_src WHERE rule_lid='$lid' ORDER BY id;");
                //echo "SELECT member_lid,table_name FROM authentication_rules_src WHERE rule_lid='$lid' ORDER BY id;\n";
                if ($getSource->num_rows > 0) {
                    $rule->addChild('source');
                    while ($k = $getSource->fetch_object()) {
                        $rule->source->addChild('member', $objectsInMemory[$k->table_name][$k->member_lid]['name']);
                    }
                } else {
                    $rule->addChild('source');
                    $rule->source->addChild('member', 'any');
                }
                $getDestination = $projectdb->query("SELECT member_lid,table_name FROM authentication_rules_dst WHERE rule_lid='$lid' ORDER BY id;");
                if ($getDestination->num_rows > 0) {
                    $rule->addChild('destination');
                    while ($k = $getDestination->fetch_object()) {
                        $rule->destination->addChild('member', $objectsInMemory[$k->table_name][$k->member_lid]['name']);
                    }
                } else {
                    $rule->addChild('destination');
                    $rule->destination->addChild('member', 'any');
                }
                $getUser = $projectdb->query("SELECT name FROM authentication_rules_usr WHERE rule_lid='$lid' ORDER BY id;");
                if ($getUser->num_rows > 0) {
                    $rule->addChild('source-user');
                    while ($k = $getUser->fetch_object()) {
                        //$rule->{'source-user'}->addChild('member',htmlentities($k->name));
                        //It got a weird character (Entity 'uuml' not defined in Entity) MT-892
                        $rule->{'source-user'}->addChild('member',htmlspecialchars($k->name));
                        //$rule->{'source-user'}->addChild('member',$k->name);
                    }
                } else {
                    $rule->addChild('source-user');
                    $rule->{'source-user'}->addChild('member', 'any');
                }
                $getCategory = $projectdb->query("SELECT name FROM authentication_rules_categories WHERE rule_lid='$lid' ORDER BY id;");
                if ($getCategory->num_rows > 0) {
                    $rule->addChild('category');
                    while ($k = $getCategory->fetch_object()) {
                        $rule->category->addChild('member', $k->name);
                    }
                } else {
                    $rule->addChild('category');
                    $rule->category->addChild('member', 'any');
                }

                $getSRV = $projectdb->query("SELECT member_lid,table_name FROM authentication_rules_srv WHERE rule_lid='$lid' ORDER BY id;");
                if ($getSRV->num_rows > 0) {
                    $rule->addChild('service');
                    while ($k = $getSRV->fetch_object()) {
                        if (isset($objectsInMemory[$k->table_name][$k->member_lid])){
                            $rule->{'service'}->addChild('member', $objectsInMemory[$k->table_name][$k->member_lid]['name']);
                        }
                        else{
                            $loadApps=$projectdb->query("SELECT id,name FROM $k->table_name WHERE id='$k->member_lid';");
                            if ($loadApps->num_rows==1){
                                $data=$loadApps->fetch_assoc();
                                $name=$data['name'];
                                $objectsInMemory[$k->table_name][$k->member_lid]['name']=$name;
                                $rule->{'service'}->addChild('member', $objectsInMemory[$k->table_name][$k->member_lid]['name']);
                            }
                        }

                    }
                } else {
                    $rule->addChild('service');
                    $rule->{'service'}->addChild('member', 'any');
                }

                $getHIP = $projectdb->query("SELECT member_lid,table_name,name FROM authentication_rules_hip WHERE rule_lid='$lid' ORDER BY id;");
                $hipProfiles_field = ($version >= 10)?'source-hip':'hip-profiles';
                if ($getHIP->num_rows > 0) {
                    $rule->addChild($hipProfiles_field);
                    while ($k = $getHIP->fetch_object()) {
                        if (($k->member_lid == 0) AND ( $k->table_name == "default")) {
                            $rule->{$hipProfiles_field}->addChild('member', $k->name);
                        }
                        else if (($k->member_lid == 0) AND ( $k->table_name == "profiles")) {
                            $rule->{$hipProfiles_field}->addChild('member', 'no-hip');
                        }
                        else {
                            $getMember = $projectdb->query("SELECT name FROM $k->table_name WHERE id='$k->member_lid' AND type='hip-profiles';");
                            if ($getMember->num_rows > 0) {
                                while ($kk = $getMember->fetch_object()) {
                                    $rule->{$hipProfiles_field}->addChild('member', $kk->name);
                                }
                            }
                        }
                    }
                } else {
                    $rule->addChild($hipProfiles_field);
                    $rule->{$hipProfiles_field}->addChild('member', 'any');
                }

                $rule->addChild('authentication-enforcement', $data2->authentication_enforcement);

                if($data2->log_authentication_timeout == "yes"){
                    $rule->addChild('log-authentication-timeout', $data2->log_authentication_timeout);
                }

                $rule->addChild('timeout', $data2->timeout);

                if ($data2->disabled == 1) {
                    $rule->addChild('disabled', 'yes');
                }
                if ($data2->negate_source == 1) {
                    $rule->addChild('negate-source', 'yes');
                }
                if ($data2->negate_destination == 1) {
                    $rule->addChild('negate-destination', 'yes');
                }
                if ($data2->description != "") {
                    $rule->addChild('description');
                    $rule->description = truncate_descriptions($data2->description,$version);
                }
                if ($data2->log_forwarding != "") {
                    $rule->addChild('log-setting', $data2->log_forwarding);
                }

                $getTAG = $projectdb->query("SELECT member_lid,table_name FROM authentication_rules_tag WHERE rule_lid='$lid' ORDER BY id;");
                if ($getTAG->num_rows > 0) {
                    $rule->addChild('tag');
                    while ($k = $getTAG->fetch_object()) {
                        //$rule->{'tag'}->addChild('member', htmlentities($objectsInMemory[$k->table_name][$k->member_lid]['name']));
                        //MT-892
                        $rule->{'tag'}->addChild('member', htmlspecialchars($objectsInMemory[$k->table_name][$k->member_lid]['name']));
                    }
                }

                if($version >= 9){
                    if($data2->group_tag_id != 0){
                        $getGroupTag = $projectdb->query("SELECT name FROM tag WHERE id = '$data2->group_tag_id';");
                        if ($getGroupTag->num_rows > 0) {
                            $k = $getGroupTag->fetch_object();
                            $rule->addChild('group-tag', htmlspecialchars($k->name));
                        }
                    }
                }

                if ($ispanorama==1){
                    $getTarget=$projectdb->query("SELECT * FROM authentication_rules_target WHERE rule_lid='$lid' ORDER BY id;");

                    if ($getTarget->num_rows>0){
                        $rule->addChild("target");
                        if ($target_negate!=""){
                            $rule->target->addChild("negate",$target_negate);
                        }
                        $rule->target->addChild("devices");
                        while($getTargetData=$getTarget->fetch_assoc()){
                            $device_vsys=$getTargetData['device_vsys'];
                            $name=$getTargetData['name'];
                            if (empty($rule->target->devices->xpath("./entry[@name='$name']"))){
                                $target=$rule->target->devices->addChild("entry");
                                $target->addAttribute("name",$name);
                            }
                            else{
                                $target0=$rule->target->devices->xpath("./entry[@name='$name']");
                                $target=$target0[0];
                            }

                            if ($device_vsys!=""){
                                if (!isset($target->vsys)){
                                    $target->addChild("vsys");
                                }
                                $target_vsys=$target->vsys->addChild("entry");
                                $target_vsys->addAttribute("name",$device_vsys);
                            }
                        }
                    }
                }

                if ($api_call == "single") {
                    $xpath2 = addslashes($xpath0."/$pvalue/authentication/rules/entry[@name='$myname']");
                    $xml_final = addslashes($rule->asXML());
                    $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','Authentication Rules','Aunthentication Rules','$xml_final','$xpath2','edit');");
                }

            }
            if ($api_call == "atomic") {
                $xpath2 = addslashes($xpath0."/$pvalue/authentication");
                $xml_final = addslashes($xpath->{$pvalue}->authentication->asXML());
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Authentication Rules $vsys','Authentication Rules','Authentication Rules','$xml_final','$xpath2','edit');");
            }
            if ((count($policy_order) > 0) AND ( $api_call == "single")) {
                $first = $policy_order[0];
                $last = $policy_order[count($policy_order) - 1];
                # Set first Rule
                $xpath = addslashes($xpath0."/$pvalue/authentication/rules/entry[@name='$first']");
                $where = "top";
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action,whereto,dst) VALUES ('$first to Top','Authentication Rules','order','','$xpath','move','$where','');");
                unset($policy_order[0]);
                foreach ($policy_order as $key => $value) {
                    $xpath = addslashes($xpath0."/$pvalue/authentication/rules/entry[@name='$value']");
                    $where = "after";
                    $dst = addslashes("$first");
                    $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action,whereto,dst) VALUES ('$value after $first','Authentication Rules','order','','$xpath','move','$where','$dst');");
                    $first = $value;
                }
                unset($policy_order);
            }
        }
        else {
            if (isset($xpath->{$pvalue}->authentication)) {
                $SA = $xpath->{$pvalue}->xpath("authentication");
                unset($SA[0][0]);
                $xpath->{$pvalue}->addChild("authentication");
                $xpath->{$pvalue}->authentication->addChild("rules");
            }
            if ($api_call == "clean") {
                $xpath2 = addslashes($xpath0."/$pvalue/authentication");
                $xml_final = "";
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Remove All Authentication Rules $vsys $pvalue','Authentication Rules','Authentication Rules','$xml_final','$xpath2','delete');");
            }
        }
    }
}


function xml_captiveportal_rules($xml,$data,&$objectsInMemory){

    $project = $data['project'];
    $ispanorama = $data['ispanorama'];
    $version = $data['version'];
    $api_call=$data['api_call'];
    $projectdb = $data['projectdb'];
    $source = $data['source'];
    $vsys = $data['vsys'];

    if (($vsys=="shared") AND ($ispanorama==0)){
        $message['code'] = false;
        $message['msg'] = "Shared Policies only can be found in Panorama. skipping";
        return $message;
    }

    if ($vsys == "shared") {
        $data['xpath0'] = "/config/shared";
    } else {
        if ($ispanorama == 1) {
            $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='" . $vsys . "']";
        } else {
            $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='" . $vsys . "']";
        }
    }
    $xpath0 = $data['xpath0'];

    if ($ispanorama==1){
        $platform="device-group";
        $policies = array("pre-rulebase", "post-rulebase");
    }
    else{
        $platform = "vsys";
        $policies = array("rulebase");
    }

    foreach ($policies as $pkey => $pvalue) {
        if (($pvalue == "pre-rulebase") OR ( $pvalue == "rulebase")) {
            $preorpost = 0;
        } elseif ($pvalue == "post-rulebase") {
            $preorpost = 1;
        }

        $xpath1 = $xml->xpath($xpath0);
        $xpath = $xpath1[0];

        # SECURITY
        if ($ispanorama==1){
            $getPolicies = $projectdb->query("SELECT * FROM captiveportal_rules WHERE source='$source' AND vsys='$vsys' AND preorpost='$preorpost' ORDER BY position ASC;");
        }
        else{
            $getPolicies = $projectdb->query("SELECT * FROM captiveportal_rules WHERE source='$source' AND vsys='$vsys'  ORDER BY preorpost,position ASC;");
        }

        if ($getPolicies->num_rows > 0) {
            if (!isset($xpath->{$pvalue})) {
                $xpath->addChild($pvalue);
            }

            if (!isset($xpath->{$pvalue}->{'captive-portal'})) {
                $xpath->{$pvalue}->addChild('captive-portal');
            }

            if (!isset($xpath->{$pvalue}->{'captive-portal'}->rules)) {
                $xpath->{$pvalue}->{'captive-portal'}->addChild('rules');
            } else {
                #DELETE RULES
                $SA = $xpath->{$pvalue}->{'captive-portal'}->xpath("rules");
                $xpath->{$pvalue}->{'captive-portal'}->rules="";
            }
            $policy_order = array();
            while ($data2 = $getPolicies->fetch_object()) {
                $myname = $data2->name;
                $uuid = $data2->uuid;
                $policy_order[] = $data2->name;
                $target_negate=$data2->target_negate;
                $lid = $data2->id;

                $rule = $xpath->{$pvalue}->{'captive-portal'}->rules->addChild('entry');
                $rule->addAttribute('name', $myname);

                if($version >= 9){
                    $rule->addAttribute('uuid', $uuid);
                }

                $getFrom = $projectdb->query("SELECT name FROM captiveportal_rules_from WHERE rule_lid='$lid' ORDER BY id;");
                if ($getFrom->num_rows > 0) {
                    $rule->addChild('from');
                    while ($k = $getFrom->fetch_object()) {
                        $rule->from->addChild('member', $k->name);
                    }
                } else {
                    $rule->addChild('from');
                    $rule->from->addChild('member', 'any');
                }

                $getTo = $projectdb->query("SELECT name FROM captiveportal_rules_to WHERE rule_lid='$lid'  ORDER BY id;");
                if ($getTo->num_rows > 0) {
                    $rule->addChild('to');
                    while ($k = $getTo->fetch_object()) {
                        $rule->to->addChild('member', $k->name);
                    }
                } else {
                    $rule->addChild('to');
                    $rule->to->addChild('member', 'any');
                }

                $getSource = $projectdb->query("SELECT member_lid,table_name FROM captiveportal_rules_src WHERE rule_lid='$lid' ORDER BY id;");
                //echo "SELECT member_lid,table_name FROM authentication_rules_src WHERE rule_lid='$lid' ORDER BY id;\n";
                if ($getSource->num_rows > 0) {
                    $rule->addChild('source');
                    while ($k = $getSource->fetch_object()) {
                        $rule->source->addChild('member', $objectsInMemory[$k->table_name][$k->member_lid]['name']);
                    }
                } else {
                    $rule->addChild('source');
                    $rule->source->addChild('member', 'any');
                }
                $getDestination = $projectdb->query("SELECT member_lid,table_name FROM captiveportal_rules_dst WHERE rule_lid='$lid' ORDER BY id;");
                if ($getDestination->num_rows > 0) {
                    $rule->addChild('destination');
                    while ($k = $getDestination->fetch_object()) {
                        $rule->destination->addChild('member', $objectsInMemory[$k->table_name][$k->member_lid]['name']);
                    }
                } else {
                    $rule->addChild('destination');
                    $rule->destination->addChild('member', 'any');
                }

                $getCategory = $projectdb->query("SELECT name FROM captiveportal_rules_categories WHERE rule_lid='$lid' ORDER BY id;");
                if ($getCategory->num_rows > 0) {
                    $rule->addChild('category');
                    while ($k = $getCategory->fetch_object()) {
                        $rule->category->addChild('member', $k->name);
                    }
                } else {
                    $rule->addChild('category');
                    $rule->category->addChild('member', 'any');
                }

                $getSRV = $projectdb->query("SELECT member_lid,table_name FROM captiveportal_rules_srv WHERE rule_lid='$lid' ORDER BY id;");
                if ($getSRV->num_rows > 0) {
                    $rule->addChild('service');
                    while ($k = $getSRV->fetch_object()) {
                        if (isset($objectsInMemory[$k->table_name][$k->member_lid])){
                            $rule->{'service'}->addChild('member', $objectsInMemory[$k->table_name][$k->member_lid]['name']);
                        }
                        else{
                            $loadApps=$projectdb->query("SELECT id,name FROM $k->table_name WHERE id='$k->member_lid';");
                            if ($loadApps->num_rows==1){
                                $data=$loadApps->fetch_assoc();
                                $name=$data['name'];
                                $objectsInMemory[$k->table_name][$k->member_lid]['name']=$name;
                                $rule->{'service'}->addChild('member', $objectsInMemory[$k->table_name][$k->member_lid]['name']);
                            }
                        }

                    }
                } else {
                    $rule->addChild('service');
                    $rule->{'service'}->addChild('member', 'any');
                }

                if ($data2->disabled == 1) {
                    $rule->addChild('disabled', 'yes');
                }
                if ($data2->negate_source == 1) {
                    $rule->addChild('negate-source', 'yes');
                }
                if ($data2->negate_destination == 1) {
                    $rule->addChild('negate-destination', 'yes');
                }
                if ($data2->description != "") {
                    $rule->addChild('description');
                    $rule->description = truncate_descriptions($data2->description,$version);
                }

                if ($data2->action != "") {
                    $rule->addChild('action', $data2->action);
                }

                $getTAG = $projectdb->query("SELECT member_lid,table_name FROM captiveportal_rules_tag WHERE rule_lid='$lid' ORDER BY id;");
                if ($getTAG->num_rows > 0) {
                    $rule->addChild('tag');
                    while ($k = $getTAG->fetch_object()) {
                        //$rule->{'tag'}->addChild('member', htmlentities($objectsInMemory[$k->table_name][$k->member_lid]['name']));
                        //MT-892
                        $rule->{'tag'}->addChild('member', htmlspecialchars($objectsInMemory[$k->table_name][$k->member_lid]['name']));

                    }
                }

                if ($ispanorama==1){
                    $getTarget=$projectdb->query("SELECT * FROM captiveportal_rules_target WHERE rule_lid='$lid' ORDER BY id;");

                    if ($getTarget->num_rows>0){
                        $rule->addChild("target");
                        if ($target_negate!=""){
                            $rule->target->addChild("negate",$target_negate);
                        }
                        $rule->target->addChild("devices");
                        while($getTargetData=$getTarget->fetch_assoc()){
                            $device_vsys=$getTargetData['device_vsys'];
                            $name=$getTargetData['name'];
                            if (empty($rule->target->devices->xpath("./entry[@name='$name']"))){
                                $target=$rule->target->devices->addChild("entry");
                                $target->addAttribute("name",$name);
                            }
                            else{
                                $target0=$rule->target->devices->xpath("./entry[@name='$name']");
                                $target=$target0[0];
                            }

                            if ($device_vsys!=""){
                                if (!isset($target->vsys)){
                                    $target->addChild("vsys");
                                }
                                $target_vsys=$target->vsys->addChild("entry");
                                $target_vsys->addAttribute("name",$device_vsys);
                            }
                        }
                    }
                }

                if ($api_call == "single") {
                    $xpath2 = addslashes($xpath0."/$pvalue/captive-portal/rules/entry[@name='$myname']");
                    $xml_final = addslashes($rule->asXML());
                    $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','Captive Portal Rules','Captive Portal Rules','$xml_final','$xpath2','edit');");
                }

            }
            if ($api_call == "atomic") {
                $xpath2 = addslashes($xpath0."/$pvalue/captive-portal");
                $xml_final = addslashes($xpath->{$pvalue}->{'captive-portal'}->asXML());
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Captive Portal Rules $vsys','Captive Portal Rules','Captive Portal Rules','$xml_final','$xpath2','edit');");
            }
            if ((count($policy_order) > 0) AND ( $api_call == "single")) {
                $first = $policy_order[0];
                $last = $policy_order[count($policy_order) - 1];
                # Set first Rule
                $xpath = addslashes($xpath0."/$pvalue/captive-portal/rules/entry[@name='$first']");
                $where = "top";
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action,whereto,dst) VALUES ('$first to Top','Captive Portal Rules','order','','$xpath','move','$where','');");
                unset($policy_order[0]);
                foreach ($policy_order as $key => $value) {
                    $xpath = addslashes($xpath0."/$pvalue/captive-portal/rules/entry[@name='$value']");
                    $where = "after";
                    $dst = addslashes("$first");
                    $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action,whereto,dst) VALUES ('$value after $first','Captive Portal Rules','order','','$xpath','move','$where','$dst');");
                    $first = $value;
                }
                unset($policy_order);
            }
        }
        else {
            if (isset($xpath->{$pvalue}->{'captive-portal'})) {
                $SA = $xpath->{$pvalue}->xpath("captive-portal");
                unset($SA[0][0]);
                $xpath->{$pvalue}->addChild("captive-portal");
                $xpath->{$pvalue}->{'captive-portal'}->addChild("rules");
            }
            if ($api_call == "clean") {
                $xpath2 = addslashes($xpath0."/$pvalue/captive-portal");
                $xml_final = "";
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Remove All Captive Portal Rules $vsys $pvalue','Captive Portal Rules','Captive Portal Rules','$xml_final','$xpath2','delete');");
            }
        }
    }
}


function xml_decryption_rules($xml,$data,&$objectsInMemory){

    $project = $data['project'];
    $ispanorama = $data['ispanorama'];
    $version = $data['version'];
    $api_call=$data['api_call'];
    $projectdb = $data['projectdb'];
    $source = $data['source'];
    $vsys = $data['vsys'];

    if (($vsys=="shared") AND ($ispanorama==0)){
        $message['code'] = false;
        $message['msg'] = "Shared Policies only can be found in Panorama. skipping";
        return $message;
    }

    if ($vsys == "shared") {
        $data['xpath0'] = "/config/shared";
    } else {
        if ($ispanorama == 1) {
            $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='" . $vsys . "']";
        } else {
            $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='" . $vsys . "']";
        }
    }
    $xpath0 = $data['xpath0'];

    if ($ispanorama==1){
        $platform="device-group";
        $policies = array("pre-rulebase", "post-rulebase");
    }
    else{
        $platform = "vsys";
        $policies = array("rulebase");
    }

    foreach ($policies as $pkey => $pvalue) {
        if (($pvalue == "pre-rulebase") OR ( $pvalue == "rulebase")) {
            $preorpost = 0;
        } elseif ($pvalue == "post-rulebase") {
            $preorpost = 1;
        }

        $xpath1 = $xml->xpath($xpath0);
        $xpath = $xpath1[0];

        # SECURITY
        if ($ispanorama==1){
            $getPolicies = $projectdb->query("SELECT * FROM decryption_rules WHERE source='$source' AND vsys='$vsys' AND preorpost='$preorpost' ORDER BY position ASC;");
        }
        else{
            $getPolicies = $projectdb->query("SELECT * FROM decryption_rules WHERE source='$source' AND vsys='$vsys'  ORDER BY preorpost,position ASC;");
        }

        if ($getPolicies->num_rows > 0) {
            if (!isset($xpath->{$pvalue})) {
                $xpath->addChild($pvalue);
            }

            if (!isset($xpath->{$pvalue}->decryption)) {
                $xpath->{$pvalue}->addChild('decryption');
            }

            if (!isset($xpath->{$pvalue}->decryption->rules)) {
                $xpath->{$pvalue}->decryption->addChild('rules');
            } else {
                #DELETE RULES
                $SA = $xpath->{$pvalue}->decryption->xpath("rules");
                $xpath->{$pvalue}->decryption->rules="";
            }
            $policy_order = array();
            while ($data2 = $getPolicies->fetch_object()) {
                $myname = $data2->name;
                $uuid = $data2->uuid;
                $policy_order[] = $data2->name;
                $target_negate=$data2->target_negate;
                $lid = $data2->id;

                $rule = $xpath->{$pvalue}->decryption->rules->addChild('entry');
                $rule->addAttribute('name', $myname);

                if($version >= 9){
                    $rule->addAttribute('uuid', $uuid);
                }

                $getFrom = $projectdb->query("SELECT name FROM decryption_rules_from WHERE rule_lid='$lid' ORDER BY id;");
                if ($getFrom->num_rows > 0) {
                    $rule->addChild('from');
                    while ($k = $getFrom->fetch_object()) {
                        $rule->from->addChild('member', $k->name);
                    }
                } else {
                    $rule->addChild('from');
                    $rule->from->addChild('member', 'any');
                }

                $getTo = $projectdb->query("SELECT name FROM decryption_rules_to WHERE rule_lid='$lid'  ORDER BY id;");
                if ($getTo->num_rows > 0) {
                    $rule->addChild('to');
                    while ($k = $getTo->fetch_object()) {
                        $rule->to->addChild('member', $k->name);
                    }
                } else {
                    $rule->addChild('to');
                    $rule->to->addChild('member', 'any');
                }

                $getSource = $projectdb->query("SELECT member_lid,table_name FROM decryption_rules_src WHERE rule_lid='$lid' ORDER BY id;");
                if ($getSource->num_rows > 0) {
                    $rule->addChild('source');
                    while ($k = $getSource->fetch_object()) {
                        $rule->source->addChild('member', $objectsInMemory[$k->table_name][$k->member_lid]['name']);
                    }
                } else {
                    $rule->addChild('source');
                    $rule->source->addChild('member', 'any');
                }
                $getDestination = $projectdb->query("SELECT member_lid,table_name FROM decryption_rules_dst WHERE rule_lid='$lid' ORDER BY id;");
                if ($getDestination->num_rows > 0) {
                    $rule->addChild('destination');
                    while ($k = $getDestination->fetch_object()) {
                        $rule->destination->addChild('member', $objectsInMemory[$k->table_name][$k->member_lid]['name']);
                    }
                } else {
                    $rule->addChild('destination');
                    $rule->destination->addChild('member', 'any');
                }
                $getUser = $projectdb->query("SELECT name FROM decryption_rules_usr WHERE rule_lid='$lid' ORDER BY id;");
                if ($getUser->num_rows > 0) {
                    $rule->addChild('source-user');
                    while ($k = $getUser->fetch_object()) {
                        //$rule->{'source-user'}->addChild('member',htmlentities($k->name));
                        //It got a weird character (Entity 'uuml' not defined in Entity) MT-892
                        $rule->{'source-user'}->addChild('member',htmlspecialchars($k->name));
                        //$rule->{'source-user'}->addChild('member',$k->name);
                    }
                } else {
                    $rule->addChild('source-user');
                    $rule->{'source-user'}->addChild('member', 'any');
                }
                $getCategory = $projectdb->query("SELECT name FROM decryption_rules_categories WHERE rule_lid='$lid' ORDER BY id;");
                if ($getCategory->num_rows > 0) {
                    $rule->addChild('category');
                    while ($k = $getCategory->fetch_object()) {
                        $rule->category->addChild('member', $k->name);
                    }
                } else {
                    $rule->addChild('category');
                    $rule->category->addChild('member', 'any');
                }

                $getSRV = $projectdb->query("SELECT member_lid,table_name FROM decryption_rules_srv WHERE rule_lid='$lid' ORDER BY id;");
                if ($getSRV->num_rows > 0) {
                    $rule->addChild('service');
                    while ($k = $getSRV->fetch_object()) {
                        if (isset($objectsInMemory[$k->table_name][$k->member_lid])){
                            $rule->{'service'}->addChild('member', $objectsInMemory[$k->table_name][$k->member_lid]['name']);
                        }
                        else{
                            $loadApps=$projectdb->query("SELECT id,name FROM $k->table_name WHERE id='$k->member_lid';");
                            if ($loadApps->num_rows==1){
                                $data=$loadApps->fetch_assoc();
                                $name=$data['name'];
                                $objectsInMemory[$k->table_name][$k->member_lid]['name']=$name;
                                $rule->{'service'}->addChild('member', $objectsInMemory[$k->table_name][$k->member_lid]['name']);
                            }
                        }

                    }
                } else {
                    $rule->addChild('service');
                    $rule->{'service'}->addChild('member', 'any');
                }

                if($data2->type == "ssl-inbound-inspection"){
                    $rule->addChild('type');
                    $rule->{'type'}->addChild('ssl-inbound-inspection', $data2->type_content);
                }else{
                    $rule->addChild('type');
                    $rule->{'type'}->addChild($data2->type);
                }

                $rule->addChild('action', $data2->action);

                if ($data2->disabled == 1) {
                    $rule->addChild('disabled', 'yes');
                }
                if ($data2->negate_source == 1) {
                    $rule->addChild('negate-source', 'yes');
                }
                if ($data2->negate_destination == 1) {
                    $rule->addChild('negate-destination', 'yes');
                }
                if ($data2->description != "") {
                    $rule->addChild('description');
                    $rule->description = truncate_descriptions($data2->description,$version);
                }

                if ($data2->profile != "") {
                    $rule->addChild('profile', $data2->profile);
                }

                if ($data2->log_forwarding != "") {
                    $rule->addChild('log-setting', $data2->log_forwarding);
                }

                $getTAG = $projectdb->query("SELECT member_lid,table_name FROM decryption_rules_tag WHERE rule_lid='$lid' ORDER BY id;");
                if ($getTAG->num_rows > 0) {
                    $rule->addChild('tag');
                    while ($k = $getTAG->fetch_object()) {
                        //$rule->{'tag'}->addChild('member', htmlentities($objectsInMemory[$k->table_name][$k->member_lid]['name']));
                        //MT-892
                        $rule->{'tag'}->addChild('member', htmlspecialchars($objectsInMemory[$k->table_name][$k->member_lid]['name']));

                    }
                }

                if($version >= 9){
                    if($data2->group_tag_id != 0){
                        $getGroupTag = $projectdb->query("SELECT name FROM tag WHERE id = '$data2->group_tag_id';");
                        if ($getGroupTag->num_rows > 0) {
                            $k = $getGroupTag->fetch_object();
                            $rule->addChild('group-tag', htmlspecialchars($k->name));
                        }
                    }
                }

                if ($ispanorama==1){
                    $getTarget=$projectdb->query("SELECT * FROM decryption_rules_target WHERE rule_lid='$lid' ORDER BY id;");

                    if ($getTarget->num_rows>0){
                        $rule->addChild("target");
                        if ($target_negate!=""){
                            $rule->target->addChild("negate",$target_negate);
                        }
                        $rule->target->addChild("devices");
                        while($getTargetData=$getTarget->fetch_assoc()){
                            $device_vsys=$getTargetData['device_vsys'];
                            $name=$getTargetData['name'];
                            if (empty($rule->target->devices->xpath("./entry[@name='$name']"))){
                                $target=$rule->target->devices->addChild("entry");
                                $target->addAttribute("name",$name);
                            }
                            else{
                                $target0=$rule->target->devices->xpath("./entry[@name='$name']");
                                $target=$target0[0];
                            }

                            if ($device_vsys!=""){
                                if (!isset($target->vsys)){
                                    $target->addChild("vsys");
                                }
                                $target_vsys=$target->vsys->addChild("entry");
                                $target_vsys->addAttribute("name",$device_vsys);
                            }
                        }
                    }
                }


                if ($api_call == "single") {
                    $xpath2 = addslashes($xpath0."/$pvalue/decryption/rules/entry[@name='$myname']");
                    $xml_final = addslashes($rule->asXML());
                    $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','Decryption Rules','Decryption Rules','$xml_final','$xpath2','edit');");
                }

            }
            if ($api_call == "atomic") {
                $xpath2 = addslashes($xpath0."/$pvalue/decryption");
                $xml_final = addslashes($xpath->{$pvalue}->decryption->asXML());
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Authentication Rules $vsys','Decryption Rules','Decryption Rules','$xml_final','$xpath2','edit');");
            }
            if ((count($policy_order) > 0) AND ( $api_call == "single")) {
                $first = $policy_order[0];
                $last = $policy_order[count($policy_order) - 1];
                # Set first Rule
                $xpath = addslashes($xpath0."/$pvalue/decryption/rules/entry[@name='$first']");
                $where = "top";
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action,whereto,dst) VALUES ('$first to Top','Decryption Rules','order','','$xpath','move','$where','');");
                unset($policy_order[0]);
                foreach ($policy_order as $key => $value) {
                    $xpath = addslashes($xpath0."/$pvalue/decryption/rules/entry[@name='$value']");
                    $where = "after";
                    $dst = addslashes("$first");
                    $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action,whereto,dst) VALUES ('$value after $first','Decryption Rules','order','','$xpath','move','$where','$dst');");
                    $first = $value;
                }
                unset($policy_order);
            }
        }
        else {
            if (isset($xpath->{$pvalue}->decryption)) {
                $SA = $xpath->{$pvalue}->xpath("decryption");
                unset($SA[0][0]);
                $xpath->{$pvalue}->addChild("decryption");
                $xpath->{$pvalue}->decryption->addChild("rules");
            }
            if ($api_call == "clean") {
                $xpath2 = addslashes($xpath0."/$pvalue/decryption");
                $xml_final = "";
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Remove All Decryption Rules $vsys $pvalue','Decryption Rules','Decryption Rules','$xml_final','$xpath2','delete');");
            }
        }
    }

}


function xml_dos_rules($xml,$data,&$objectsInMemory){

    $project = $data['project'];
    $ispanorama = $data['ispanorama'];
    $version = $data['version'];
    $api_call=$data['api_call'];
    $projectdb = $data['projectdb'];
    $source = $data['source'];
    $vsys = $data['vsys'];

    if (($vsys=="shared") AND ($ispanorama==0)){
        $message['code'] = false;
        $message['msg'] = "Shared Policies only can be found in Panorama. skipping";
        return $message;
    }

    if ($vsys == "shared") {
        $data['xpath0'] = "/config/shared";
    } else {
        if ($ispanorama == 1) {
            $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='" . $vsys . "']";
        } else {
            $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='" . $vsys . "']";
        }
    }
    $xpath0 = $data['xpath0'];

    if ($ispanorama==1){
        $platform="device-group";
        $policies = array("pre-rulebase", "post-rulebase");
    }
    else{
        $platform = "vsys";
        $policies = array("rulebase");
    }

    foreach ($policies as $pkey => $pvalue) {
        if (($pvalue == "pre-rulebase") OR ( $pvalue == "rulebase")) {
            $preorpost = 0;
        } elseif ($pvalue == "post-rulebase") {
            $preorpost = 1;
        }

        $xpath1 = $xml->xpath($xpath0);
        $xpath = $xpath1[0];

        # SECURITY
        if ($ispanorama==1){
            $getPolicies = $projectdb->query("SELECT * FROM dos_rules WHERE source='$source' AND vsys='$vsys' AND preorpost='$preorpost' ORDER BY position ASC;");
        }
        else{
            $getPolicies = $projectdb->query("SELECT * FROM dos_rules WHERE source='$source' AND vsys='$vsys'  ORDER BY preorpost,position ASC;");
        }

        if ($getPolicies->num_rows > 0) {
            if (!isset($xpath->{$pvalue})) {
                $xpath->addChild($pvalue);
            }

            if (!isset($xpath->{$pvalue}->dos)) {
                $xpath->{$pvalue}->addChild('dos');
            }

            if (!isset($xpath->{$pvalue}->dos->rules)) {
                $xpath->{$pvalue}->dos->addChild('rules');
            } else {
                #DELETE RULES
                $SA = $xpath->{$pvalue}->dos->xpath("rules");
                $xpath->{$pvalue}->dos->rules="";
                //$xpath->{$pvalue}->dos->addChild('rules');
            }
            $policy_order = array();
            while ($data2 = $getPolicies->fetch_object()) {
                $myname = $data2->name;
                $uuid = $data2->uuid;
                $policy_order[] = $data2->name;
                $target_negate=$data2->target_negate;
                $lid = $data2->id;

                $rule = $xpath->{$pvalue}->dos->rules->addChild('entry');
                $rule->addAttribute('name', $myname);

                if($version >= 9){
                    $rule->addAttribute('uuid', $uuid);
                }

                $getFrom = $projectdb->query("SELECT name, type FROM dos_rules_from WHERE rule_lid='$lid' ORDER BY id;");
                if ($getFrom->num_rows > 0) {
                    $rule->addChild('from');
                    $i = 0;
                    $type = "";
                    while ($k = $getFrom->fetch_object()) {
                        if($i == 0){
                            $type = $k->type;
                            $rule->from->addChild($type);
                            $i = 1;
                        }
                        $rule->from->{$type}->addChild('member', $k->name);
                    }
                } else {
                    $rule->addChild('from');
                    $rule->from->addChild('member', 'any');
                }

                $getTo = $projectdb->query("SELECT name, type FROM dos_rules_to WHERE rule_lid='$lid'  ORDER BY id;");
                if ($getTo->num_rows > 0) {
                    $rule->addChild('to');
                    $i = 0;
                    $type = "";
                    while ($k = $getTo->fetch_object()) {
                        if($i == 0){
                            $type = $k->type;
                            $rule->to->addChild($type);
                            $i = 1;
                        }
                        $rule->to->{$type}->addChild('member', $k->name);
                    }
                } else {
                    $rule->addChild('to');
                    $rule->to->addChild('member', 'any');
                }

                $getSource = $projectdb->query("SELECT member_lid,table_name FROM dos_rules_src WHERE rule_lid='$lid' ORDER BY id;");
                if ($getSource->num_rows > 0) {
                    $rule->addChild('source');
                    while ($k = $getSource->fetch_object()) {
                        $rule->source->addChild('member', $objectsInMemory[$k->table_name][$k->member_lid]['name']);
                    }
                } else {
                    $rule->addChild('source');
                    $rule->source->addChild('member', 'any');
                }
                $getDestination = $projectdb->query("SELECT member_lid,table_name FROM dos_rules_dst WHERE rule_lid='$lid' ORDER BY id;");
                if ($getDestination->num_rows > 0) {
                    $rule->addChild('destination');
                    while ($k = $getDestination->fetch_object()) {
                        $rule->destination->addChild('member', $objectsInMemory[$k->table_name][$k->member_lid]['name']);
                    }
                } else {
                    $rule->addChild('destination');
                    $rule->destination->addChild('member', 'any');
                }
                $getUser = $projectdb->query("SELECT name FROM dos_rules_usr WHERE rule_lid='$lid' ORDER BY id;");
                if ($getUser->num_rows > 0) {
                    $rule->addChild('source-user');
                    while ($k = $getUser->fetch_object()) {
                        //$rule->{'source-user'}->addChild('member',htmlentities($k->name));
                        //It got a weird character (Entity 'uuml' not defined in Entity) MT-892
                        $rule->{'source-user'}->addChild('member',htmlspecialchars($k->name));
                        //$rule->{'source-user'}->addChild('member',$k->name);
                    }
                } else {
                    $rule->addChild('source-user');
                    $rule->{'source-user'}->addChild('member', 'any');
                }

                $getSRV = $projectdb->query("SELECT member_lid,table_name FROM dos_rules_srv WHERE rule_lid='$lid' ORDER BY id;");
                if ($getSRV->num_rows > 0) {
                    $rule->addChild('service');
                    while ($k = $getSRV->fetch_object()) {
                        if (isset($objectsInMemory[$k->table_name][$k->member_lid])){
                            $rule->{'service'}->addChild('member', $objectsInMemory[$k->table_name][$k->member_lid]['name']);
                        }
                        else{
                            $loadApps=$projectdb->query("SELECT id,name FROM $k->table_name WHERE id='$k->member_lid';");
                            if ($loadApps->num_rows==1){
                                $data=$loadApps->fetch_assoc();
                                $name=$data['name'];
                                $objectsInMemory[$k->table_name][$k->member_lid]['name']=$name;
                                $rule->{'service'}->addChild('member', $objectsInMemory[$k->table_name][$k->member_lid]['name']);
                            }
                        }

                    }
                } else {
                    $rule->addChild('service');
                    $rule->{'service'}->addChild('member', 'any');
                }

                $rule->addChild('action');
                $rule->{'action'}->addChild($data2->action);
                $xml_append = simplexml_load_string(clean_xml($data2->protection));
                SimpleXMLElement_append($rule, $xml_append);

                if ($data2->disabled == 1) {
                    $rule->addChild('disabled', 'yes');
                }

                if ($data2->negate_source == 1) {
                    $rule->addChild('negate-source', 'yes');
                }

                if ($data2->negate_destination == 1) {
                    $rule->addChild('negate-destination', 'yes');
                }

                if ($data2->description != "") {
                    $rule->addChild('description');
                    $rule->description = truncate_descriptions($data2->description,$version);
                }
                if ($data2->schedule != "") {
                    $rule->addChild('schedule', $data2->schedule);
                }
                if ($data2->log_forwarding != "") {
                    $rule->addChild('log-setting', $data2->log_forwarding);
                }

                $getTAG = $projectdb->query("SELECT member_lid,table_name FROM dos_rules_tag WHERE rule_lid='$lid' ORDER BY id;");
                if ($getTAG->num_rows > 0) {
                    $rule->addChild('tag');
                    while ($k = $getTAG->fetch_object()) {
                        //$rule->{'tag'}->addChild('member', htmlentities($objectsInMemory[$k->table_name][$k->member_lid]['name']));
                        //MT-892
                        $rule->{'tag'}->addChild('member', htmlspecialchars($objectsInMemory[$k->table_name][$k->member_lid]['name']));

                    }
                }

                if($version >= 9){
                    if($data2->group_tag_id != 0){
                        $getGroupTag = $projectdb->query("SELECT name FROM tag WHERE id = '$data2->group_tag_id';");
                        if ($getGroupTag->num_rows > 0) {
                            $k = $getGroupTag->fetch_object();
                            $rule->addChild('group-tag', htmlspecialchars($k->name));
                        }
                    }
                }

                if ($ispanorama==1){
                    $getTarget=$projectdb->query("SELECT * FROM dos_rules_target WHERE rule_lid='$lid' ORDER BY id;");

                    if ($getTarget->num_rows>0){
                        $rule->addChild("target");
                        if ($target_negate!=""){
                            $rule->target->addChild("negate",$target_negate);
                        }
                        $rule->target->addChild("devices");
                        while($getTargetData=$getTarget->fetch_assoc()){
                            $device_vsys=$getTargetData['device_vsys'];
                            $name=$getTargetData['name'];
                            if (empty($rule->target->devices->xpath("./entry[@name='$name']"))){
                                $target=$rule->target->devices->addChild("entry");
                                $target->addAttribute("name",$name);
                            }
                            else{
                                $target0=$rule->target->devices->xpath("./entry[@name='$name']");
                                $target=$target0[0];
                            }

                            if ($device_vsys!=""){
                                if (!isset($target->vsys)){
                                    $target->addChild("vsys");
                                }
                                $target_vsys=$target->vsys->addChild("entry");
                                $target_vsys->addAttribute("name",$device_vsys);
                            }
                        }
                    }
                }


                if ($api_call == "single") {
                    $xpath2 = addslashes($xpath0."/$pvalue/dos/rules/entry[@name='$myname']");
                    $xml_final = addslashes($rule->asXML());
                    $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','DoS Rules','DoS Rules','$xml_final','$xpath2','edit');");
                }

            }
            if ($api_call == "atomic") {
                $xpath2 = addslashes($xpath0."/$pvalue/dos");
                $xml_final = addslashes($xpath->{$pvalue}->dos->asXML());
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('DoS Rules $vsys','DoS Rules','DoS Rules','$xml_final','$xpath2','edit');");
            }
            if ((count($policy_order) > 0) AND ( $api_call == "single")) {
                $first = $policy_order[0];
                $last = $policy_order[count($policy_order) - 1];
                # Set first Rule
                $xpath = addslashes($xpath0."/$pvalue/dos/rules/entry[@name='$first']");
                $where = "top";
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action,whereto,dst) VALUES ('$first to Top','DoS Rules','order','','$xpath','move','$where','');");
                unset($policy_order[0]);
                foreach ($policy_order as $key => $value) {
                    $xpath = addslashes($xpath0."/$pvalue/dos/rules/entry[@name='$value']");
                    $where = "after";
                    $dst = addslashes("$first");
                    $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action,whereto,dst) VALUES ('$value after $first','DoS Rules','order','','$xpath','move','$where','$dst');");
                    $first = $value;
                }
                unset($policy_order);
            }
        }
        else {
            if (isset($xpath->{$pvalue}->dos)) {
                $SA = $xpath->{$pvalue}->xpath("dos");
                unset($SA[0][0]);
                $xpath->{$pvalue}->addChild("dos");
                $xpath->{$pvalue}->dos->addChild("rules");
            }
            if ($api_call == "clean") {
                $xpath2 = addslashes($xpath0."/$pvalue/dos");
                $xml_final = "";
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Remove All DoS Rules $vsys $pvalue','DoS Rules','DoS Rules','$xml_final','$xpath2','delete');");
            }
        }
    }

}


function xml_pbf_rules($xml,$data,&$objectsInMemory){

    $project = $data['project'];
    $ispanorama = $data['ispanorama'];
    $version = $data['version'];
    $api_call=$data['api_call'];
    $projectdb = $data['projectdb'];
    $source = $data['source'];
    $vsys = $data['vsys'];

    if (($vsys=="shared") AND ($ispanorama==0)){
        $message['code'] = false;
        $message['msg'] = "Shared Policies only can be found in Panorama. skipping";
        return $message;
    }

    if ($vsys == "shared") {
        $data['xpath0'] = "/config/shared";
    } else {
        if ($ispanorama == 1) {
            $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='" . $vsys . "']";
        } else {
            $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='" . $vsys . "']";
        }
    }
    $xpath0 = $data['xpath0'];

    if ($ispanorama==1){
        $platform="device-group";
        $policies = array("pre-rulebase", "post-rulebase");
    }
    else{
        $platform = "vsys";
        $policies = array("rulebase");
    }

    foreach ($policies as $pkey => $pvalue) {
        if (($pvalue == "pre-rulebase") OR ( $pvalue == "rulebase")) {
            $preorpost = 0;
        } elseif ($pvalue == "post-rulebase") {
            $preorpost = 1;
        }

        $xpath1 = $xml->xpath($xpath0);
        $xpath = $xpath1[0];

        # SECURITY
        if ($ispanorama==1){
            $getPolicies = $projectdb->query("SELECT * FROM pbf_rules WHERE source='$source' AND vsys='$vsys' AND preorpost='$preorpost' ORDER BY position ASC;");
        }
        else{
            $getPolicies = $projectdb->query("SELECT * FROM pbf_rules WHERE source='$source' AND vsys='$vsys'  ORDER BY preorpost,position ASC;");
        }

        if ($getPolicies->num_rows > 0) {
            if (!isset($xpath->{$pvalue})) {
                $xpath->addChild($pvalue);
            }

            if (!isset($xpath->{$pvalue}->pbf)) {
                $xpath->{$pvalue}->addChild('pbf');
            }

            if (!isset($xpath->{$pvalue}->pbf->rules)) {
                $xpath->{$pvalue}->pbf->addChild('rules');
            } else {
                #DELETE RULES
                $SA = $xpath->{$pvalue}->pbf->xpath("rules");
                $xpath->{$pvalue}->pbf->rules="";

            }
            $policy_order = array();
            while ($data2 = $getPolicies->fetch_object()) {
                $myname = $data2->name;
                $uuid = $data2->uuid;
                $policy_order[] = $data2->name;
                $target_negate=$data2->target_negate;
                $lid = $data2->id;

                $rule = $xpath->{$pvalue}->pbf->rules->addChild('entry');
                $rule->addAttribute('name', $myname);

                if($version >= 9){
                    $rule->addAttribute('uuid', $uuid);
                }

                if($data2->action == "forward"){

                    $rule->addChild('action');
                    $rule->{'action'}->addChild($data2->action);

                    if ($data2->monitor_profile != ""){

                        $rule->action->forward->addChild('monitor');
                        $rule->action->forward->monitor->addChild('profile', $data2->monitor_profile);

                        if($data2->monitor_disable_if_unreachable != ""){
                            $rule->action->forward->monitor->addChild('disable-if-unreachable', $data2->monitor_disable_if_unreachable);
                        }

                        if($data2->monitor_ipaddress != ""){
                            $rule->action->forward->monitor->addChild('ip-address', $data2->monitor_ipaddress);
                        }
                    }

                    if ($data2->nexthop != ""){
                        $xml_append = simplexml_load_string(clean_xml($data2->nexthop));
                        SimpleXMLElement_append($rule->action->forward, $xml_append);
                    }

                    if ($data2->egress_interface != ""){
                        $rule->action->forward->addChild('egress-interface', $data2->egress_interface);
                    }
                }
                else{
                    $pbf_action = $data2->action;
                    if((strpos($pbf_action, "forward-to-vsys") === 0)){
                        $tuple = explode(";",$pbf_action);
                        $rule->addChild('action');
                        $rule->{'action'}->addChild("forward-to-vsys",$tuple[1]);
                    }
                    else {
                        $rule->addChild('action');
                        $rule->{'action'}->addChild($data2->action);
                    }
                }

                if ($data2->disabled == 1) {
                    $rule->addChild('disabled', 'yes');
                }
                if ($data2->negate_source == 1) {
                    $rule->addChild('negate-source', 'yes');
                }
                if ($data2->negate_destination == 1) {
                    $rule->addChild('negate-destination', 'yes');
                }
                if ($data2->description != "") {
                    $rule->addChild('description');
                    $rule->description = truncate_descriptions($data2->description,$version);
                }
                if ($data2->schedule != "") {
                    $rule->addChild('schedule', $data2->schedule);
                }

                if($data2->enforce_symmetric_return != ""){
                    $xml_append = simplexml_load_string(clean_xml($data2->enforce_symmetric_return));
                    SimpleXMLElement_append($rule, $xml_append);
                }

                $getFrom = $projectdb->query("SELECT name, type FROM pbf_rules_from WHERE rule_lid='$lid' ORDER BY id;");
                if ($getFrom->num_rows > 0) {
                    $rule->addChild('from');
                    $i = 0;
                    $type = "";
                    while ($k = $getFrom->fetch_object()) {
                        if($i == 0){
                            $type = $k->type;
                            $rule->from->addChild($type);
                            $i = 1;
                        }
                        $rule->from->{$type}->addChild('member', $k->name);
                    }
                } else {
                    $rule->addChild('from');
                    $rule->from->addChild('member', 'any');
                }

                $getSource = $projectdb->query("SELECT member_lid,table_name FROM pbf_rules_src WHERE rule_lid='$lid' ORDER BY id;");
                if ($getSource->num_rows > 0) {
                    $rule->addChild('source');
                    while ($k = $getSource->fetch_object()) {
                        $rule->source->addChild('member', $objectsInMemory[$k->table_name][$k->member_lid]['name']);
                    }
                } else {
                    $rule->addChild('source');
                    $rule->source->addChild('member', 'any');
                }

                $getDestination = $projectdb->query("SELECT member_lid,table_name FROM pbf_rules_dst WHERE rule_lid='$lid' ORDER BY id;");
                if ($getDestination->num_rows > 0) {
                    $rule->addChild('destination');
                    while ($k = $getDestination->fetch_object()) {
                        $rule->destination->addChild('member', $objectsInMemory[$k->table_name][$k->member_lid]['name']);
                    }
                } else {
                    $rule->addChild('destination');
                    $rule->destination->addChild('member', 'any');
                }

                $getUser = $projectdb->query("SELECT name FROM pbf_rules_usr WHERE rule_lid='$lid' ORDER BY id;");
                if ($getUser->num_rows > 0) {
                    $rule->addChild('source-user');
                    while ($k = $getUser->fetch_object()) {
                        //$rule->{'source-user'}->addChild('member',htmlentities($k->name));
                        //It got a weird character (Entity 'uuml' not defined in Entity) MT-892
                        $rule->{'source-user'}->addChild('member',htmlspecialchars($k->name));
                        //$rule->{'source-user'}->addChild('member',$k->name);
                    }
                } else {
                    $rule->addChild('source-user');
                    $rule->{'source-user'}->addChild('member', 'any');
                }

                $getSRV = $projectdb->query("SELECT member_lid,table_name FROM pbf_rules_srv WHERE rule_lid='$lid' ORDER BY id;");
                if ($getSRV->num_rows > 0) {
                    $rule->addChild('service');
                    while ($k = $getSRV->fetch_object()) {
                        if (isset($objectsInMemory[$k->table_name][$k->member_lid])){
                            $rule->{'service'}->addChild('member', $objectsInMemory[$k->table_name][$k->member_lid]['name']);
                        }
                        else{
                            $loadApps=$projectdb->query("SELECT id,name FROM $k->table_name WHERE id='$k->member_lid';");
                            if ($loadApps->num_rows==1){
                                $data=$loadApps->fetch_assoc();
                                $name=$data['name'];
                                $objectsInMemory[$k->table_name][$k->member_lid]['name']=$name;
                                $rule->{'service'}->addChild('member', $objectsInMemory[$k->table_name][$k->member_lid]['name']);
                            }
                        }

                    }
                } else {
                    $rule->addChild('service');
                    $rule->{'service'}->addChild('member', 'any');
                }

                $getAPP = $projectdb->query("SELECT member_lid,table_name FROM pbf_rules_app WHERE rule_lid='$lid' ORDER BY id;");
                if ($getAPP->num_rows > 0) {
                    $rule->addChild('application');
                    while ($k = $getAPP->fetch_object()) {
                        $rule->{'application'}->addChild('member', $objectsInMemory[$k->table_name][$k->member_lid]['name']);
                    }
                } else {
                    $rule->addChild('application');
                    $rule->{'application'}->addChild('member', 'any');
                }

                $getTAG = $projectdb->query("SELECT member_lid,table_name FROM pbf_rules_tag WHERE rule_lid='$lid' ORDER BY id;");
                if ($getTAG->num_rows > 0) {
                    $rule->addChild('tag');
                    while ($k = $getTAG->fetch_object()) {
                        //$rule->{'tag'}->addChild('member', htmlentities($objectsInMemory[$k->table_name][$k->member_lid]['name']));
                        //MT-892
                        $rule->{'tag'}->addChild('member', htmlspecialchars($objectsInMemory[$k->table_name][$k->member_lid]['name']));

                    }
                }

                if($version >= 9){
                    if($data2->group_tag_id != 0){
                        $getGroupTag = $projectdb->query("SELECT name FROM tag WHERE id = '$data2->group_tag_id';");
                        if ($getGroupTag->num_rows > 0) {
                            $k = $getGroupTag->fetch_object();
                            $rule->addChild('group-tag', htmlspecialchars($k->name));
                        }
                    }
                }

                if ($ispanorama==1){
                    $getTarget=$projectdb->query("SELECT * FROM pbf_rules_target WHERE rule_lid='$lid' ORDER BY id;");

                    if ($getTarget->num_rows>0){
                        $rule->addChild("target");
                        if ($target_negate!=""){
                            $rule->target->addChild("negate",$target_negate);
                        }
                        $rule->target->addChild("devices");
                        while($getTargetData=$getTarget->fetch_assoc()){
                            $device_vsys=$getTargetData['device_vsys'];
                            $name=$getTargetData['name'];
                            if (empty($rule->target->devices->xpath("./entry[@name='$name']"))){
                                $target=$rule->target->devices->addChild("entry");
                                $target->addAttribute("name",$name);
                            }
                            else{
                                $target0=$rule->target->devices->xpath("./entry[@name='$name']");
                                $target=$target0[0];
                            }

                            if ($device_vsys!=""){
                                if (!isset($target->vsys)){
                                    $target->addChild("vsys");
                                }
                                $target_vsys=$target->vsys->addChild("entry");
                                $target_vsys->addAttribute("name",$device_vsys);
                            }
                        }
                    }
                }


                if ($api_call == "single") {
                    $xpath2 = addslashes($xpath0."/$pvalue/pbf/rules/entry[@name='$myname']");
                    $xml_final = addslashes($rule->asXML());
                    $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','PBF Rules','PBF Rules','$xml_final','$xpath2','edit');");
                }

            }
            if ($api_call == "atomic") {
                $xpath2 = addslashes($xpath0."/$pvalue/pbf");
                $xml_final = addslashes($xpath->{$pvalue}->pbf->asXML());
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('PBF Rules $vsys','PBF Rules','PBF Rules','$xml_final','$xpath2','edit');");
            }
            if ((count($policy_order) > 0) AND ( $api_call == "single")) {
                $first = $policy_order[0];
                $last = $policy_order[count($policy_order) - 1];
                # Set first Rule
                $xpath = addslashes($xpath0."/$pvalue/pbf/rules/entry[@name='$first']");
                $where = "top";
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action,whereto,dst) VALUES ('$first to Top','PBF Rules','order','','$xpath','move','$where','');");
                unset($policy_order[0]);
                foreach ($policy_order as $key => $value) {
                    $xpath = addslashes($xpath0."/$pvalue/pbf/rules/entry[@name='$value']");
                    $where = "after";
                    $dst = addslashes("$first");
                    $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action,whereto,dst) VALUES ('$value after $first','PBF Rules','order','','$xpath','move','$where','$dst');");
                    $first = $value;
                }
                unset($policy_order);
            }
        }
        else {
            if (isset($xpath->{$pvalue}->pbf)) {
                $SA = $xpath->{$pvalue}->xpath("pbf");
                unset($SA[0][0]);
                $xpath->{$pvalue}->addChild("pbf");
                $xpath->{$pvalue}->pbf->addChild("rules");
            }
            if ($api_call == "clean") {
                $xpath2 = addslashes($xpath0."/$pvalue/pbf");
                $xml_final = "";
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Remove All PBF Rules $vsys $pvalue','PBF Rules','PBF Rules','$xml_final','$xpath2','delete');");
            }
        }
    }

}


function xml_qos_rules($xml,$data,&$objectsInMemory){

    $project = $data['project'];
    $ispanorama = $data['ispanorama'];
    $version = $data['version'];
    $api_call=$data['api_call'];
    $projectdb = $data['projectdb'];
    $source = $data['source'];
    $vsys = $data['vsys'];

    if (($vsys=="shared") AND ($ispanorama==0)){
        $message['code'] = false;
        $message['msg'] = "Shared Policies only can be found in Panorama. skipping";
        return $message;
    }

    if ($vsys == "shared") {
        $data['xpath0'] = "/config/shared";
    } else {
        if ($ispanorama == 1) {
            $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='" . $vsys . "']";
        } else {
            $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='" . $vsys . "']";
        }
    }
    $xpath0 = $data['xpath0'];

    if ($ispanorama==1){
        $platform="device-group";
        $policies = array("pre-rulebase", "post-rulebase");
    }
    else{
        $platform = "vsys";
        $policies = array("rulebase");
    }

    foreach ($policies as $pkey => $pvalue) {
        if (($pvalue == "pre-rulebase") OR ( $pvalue == "rulebase")) {
            $preorpost = 0;
        } elseif ($pvalue == "post-rulebase") {
            $preorpost = 1;
        }

        $xpath1 = $xml->xpath($xpath0);
        $xpath = $xpath1[0];

        # SECURITY
        if ($ispanorama==1){
            $getPolicies = $projectdb->query("SELECT * FROM qos_rules WHERE source='$source' AND vsys='$vsys' AND preorpost='$preorpost' ORDER BY position ASC;");
        }
        else{
            $getPolicies = $projectdb->query("SELECT * FROM qos_rules WHERE source='$source' AND vsys='$vsys'  ORDER BY preorpost,position ASC;");
        }

        if ($getPolicies->num_rows > 0) {
            if (!isset($xpath->{$pvalue})) {
                $xpath->addChild($pvalue);
            }

            if (!isset($xpath->{$pvalue}->qos)) {
                $xpath->{$pvalue}->addChild('qos');
            }

            if (!isset($xpath->{$pvalue}->qos->rules)) {
                $xpath->{$pvalue}->qos->addChild('rules');
            } else {
                #DELETE RULES
                $SA = $xpath->{$pvalue}->qos->xpath("rules");
                $xpath->{$pvalue}->qos->rules="";
            }
            $policy_order = array();
            while ($data2 = $getPolicies->fetch_object()) {
                $myname = $data2->name;
                $uuid = $data2->uuid;
                $policy_order[] = $data2->name;
                $target_negate=$data2->target_negate;
                $lid = $data2->id;

                $rule = $xpath->{$pvalue}->qos->rules->addChild('entry');
                $rule->addAttribute('name', $myname);

                if($version >= 9){
                    $rule->addAttribute('uuid', $uuid);
                }

                $getFrom = $projectdb->query("SELECT name FROM qos_rules_from WHERE rule_lid='$lid' ORDER BY id;");
                if ($getFrom->num_rows > 0) {
                    $rule->addChild('from');
                    while ($k = $getFrom->fetch_object()) {
                        $rule->from->addChild('member', $k->name);
                    }
                } else {
                    $rule->addChild('from');
                    $rule->from->addChild('member', 'any');
                }

                $getTo = $projectdb->query("SELECT name FROM qos_rules_to WHERE rule_lid='$lid'  ORDER BY id;");
                if ($getTo->num_rows > 0) {
                    $rule->addChild('to');
                    while ($k = $getTo->fetch_object()) {
                        $rule->to->addChild('member', $k->name);
                    }
                } else {
                    $rule->addChild('to');
                    $rule->to->addChild('member', 'any');
                }
                $getSource = $projectdb->query("SELECT member_lid,table_name FROM qos_rules_src WHERE rule_lid='$lid' ORDER BY id;");
                if ($getSource->num_rows > 0) {
                    $rule->addChild('source');
                    while ($k = $getSource->fetch_object()) {
                        $rule->source->addChild('member', $objectsInMemory[$k->table_name][$k->member_lid]['name']);
                    }
                } else {
                    $rule->addChild('source');
                    $rule->source->addChild('member', 'any');
                }
                $getDestination = $projectdb->query("SELECT member_lid,table_name FROM qos_rules_dst WHERE rule_lid='$lid' ORDER BY id;");
                if ($getDestination->num_rows > 0) {
                    $rule->addChild('destination');
                    while ($k = $getDestination->fetch_object()) {
                        $rule->destination->addChild('member', $objectsInMemory[$k->table_name][$k->member_lid]['name']);
                    }
                } else {
                    $rule->addChild('destination');
                    $rule->destination->addChild('member', 'any');
                }

                $getUser = $projectdb->query("SELECT name FROM qos_rules_usr WHERE rule_lid='$lid' ORDER BY id;");
                if ($getUser->num_rows > 0) {
                    $rule->addChild('source-user');
                    while ($k = $getUser->fetch_object()) {
                        //$rule->{'source-user'}->addChild('member',htmlentities($k->name));
                        //It got a weird character (Entity 'uuml' not defined in Entity) MT-892
                        $rule->{'source-user'}->addChild('member',htmlspecialchars($k->name));
                        //$rule->{'source-user'}->addChild('member',$k->name);
                    }
                } else {
                    $rule->addChild('source-user');
                    $rule->{'source-user'}->addChild('member', 'any');
                }

                $getCategory = $projectdb->query("SELECT name FROM qos_rules_categories WHERE rule_lid='$lid' ORDER BY id;");
                if ($getCategory->num_rows > 0) {
                    $rule->addChild('category');
                    while ($k = $getCategory->fetch_object()) {
                        $rule->category->addChild('member', $k->name);
                    }
                } else {
                    $rule->addChild('category');
                    $rule->category->addChild('member', 'any');
                }

                $getSRV = $projectdb->query("SELECT member_lid,table_name FROM qos_rules_srv WHERE rule_lid='$lid' ORDER BY id;");
                if ($getSRV->num_rows > 0) {
                    $rule->addChild('service');
                    while ($k = $getSRV->fetch_object()) {
                        if (isset($objectsInMemory[$k->table_name][$k->member_lid])){
                            $rule->{'service'}->addChild('member', $objectsInMemory[$k->table_name][$k->member_lid]['name']);
                        }
                        else{
                            $loadApps=$projectdb->query("SELECT id,name FROM $k->table_name WHERE id='$k->member_lid';");
                            if ($loadApps->num_rows==1){
                                $data=$loadApps->fetch_assoc();
                                $name=$data['name'];
                                $objectsInMemory[$k->table_name][$k->member_lid]['name']=$name;
                                $rule->{'service'}->addChild('member', $objectsInMemory[$k->table_name][$k->member_lid]['name']);
                            }
                        }

                    }
                } else {
                    $rule->addChild('service');
                    $rule->{'service'}->addChild('member', 'any');
                }

                $getAPP = $projectdb->query("SELECT member_lid,table_name FROM qos_rules_app WHERE rule_lid='$lid' ORDER BY id;");
                if ($getAPP->num_rows > 0) {
                    $rule->addChild('application');
                    while ($k = $getAPP->fetch_object()) {
                        $rule->{'application'}->addChild('member', $objectsInMemory[$k->table_name][$k->member_lid]['name']);
                    }
                } else {
                    $rule->addChild('application');
                    $rule->{'application'}->addChild('member', 'any');
                }

                $rule->addChild('action');
                $rule->{'action'}->addChild('class', $data2->action);

                if($data2->codepoints != ""){
                    $xml_append = simplexml_load_string(clean_xml($data2->codepoints));
                    SimpleXMLElement_append($rule, $xml_append);
                }

                if ($data2->disabled == 1) {
                    $rule->addChild('disabled', 'yes');
                }

                if ($data2->negate_source == 1) {
                    $rule->addChild('negate-source', 'yes');
                }

                if ($data2->negate_destination == 1) {
                    $rule->addChild('negate-destination', 'yes');
                }

                if ($data2->description != "") {
                    $rule->addChild('description');
                    $rule->description = truncate_descriptions($data2->description,$version);
                }
                if ($data2->schedule != "") {
                    $rule->addChild('schedule', $data2->schedule);
                }

                $getTAG = $projectdb->query("SELECT member_lid,table_name FROM qos_rules_tag WHERE rule_lid='$lid' ORDER BY id;");
                if ($getTAG->num_rows > 0) {
                    $rule->addChild('tag');
                    while ($k = $getTAG->fetch_object()) {
                        //$rule->{'tag'}->addChild('member', htmlentities($objectsInMemory[$k->table_name][$k->member_lid]['name']));
                        //MT-892
                        $rule->{'tag'}->addChild('member', htmlspecialchars($objectsInMemory[$k->table_name][$k->member_lid]['name']));

                    }
                }

                if($version >= 9){
                    if($data2->group_tag_id != 0){
                        $getGroupTag = $projectdb->query("SELECT name FROM tag WHERE id = '$data2->group_tag_id';");
                        if ($getGroupTag->num_rows > 0) {
                            $k = $getGroupTag->fetch_object();
                            $rule->addChild('group-tag', htmlspecialchars($k->name));
                        }
                    }
                }

                if ($ispanorama==1){
                    $getTarget=$projectdb->query("SELECT * FROM qos_rules_target WHERE rule_lid='$lid' ORDER BY id;");

                    if ($getTarget->num_rows>0){
                        $rule->addChild("target");
                        if ($target_negate!=""){
                            $rule->target->addChild("negate",$target_negate);
                        }
                        $rule->target->addChild("devices");
                        while($getTargetData=$getTarget->fetch_assoc()){
                            $device_vsys=$getTargetData['device_vsys'];
                            $name=$getTargetData['name'];
                            if (empty($rule->target->devices->xpath("./entry[@name='$name']"))){
                                $target=$rule->target->devices->addChild("entry");
                                $target->addAttribute("name",$name);
                            }
                            else{
                                $target0=$rule->target->devices->xpath("./entry[@name='$name']");
                                $target=$target0[0];
                            }

                            if ($device_vsys!=""){
                                if (!isset($target->vsys)){
                                    $target->addChild("vsys");
                                }
                                $target_vsys=$target->vsys->addChild("entry");
                                $target_vsys->addAttribute("name",$device_vsys);
                            }
                        }
                    }
                }


                if ($api_call == "single") {
                    $xpath2 = addslashes($xpath0."/$pvalue/qos/rules/entry[@name='$myname']");
                    $xml_final = addslashes($rule->asXML());
                    $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','QoS Rules','QoS Rules','$xml_final','$xpath2','edit');");
                }

            }
            if ($api_call == "atomic") {
                $xpath2 = addslashes($xpath0."/$pvalue/qos");
                $xml_final = addslashes($xpath->{$pvalue}->qos->asXML());
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('QoS Rules $vsys','QoS Rules','QoS Rules','$xml_final','$xpath2','edit');");
            }
            if ((count($policy_order) > 0) AND ( $api_call == "single")) {
                $first = $policy_order[0];
                $last = $policy_order[count($policy_order) - 1];
                # Set first Rule
                $xpath = addslashes($xpath0."/$pvalue/qos/rules/entry[@name='$first']");
                $where = "top";
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action,whereto,dst) VALUES ('$first to Top','QoS Rules','order','','$xpath','move','$where','');");
                unset($policy_order[0]);
                foreach ($policy_order as $key => $value) {
                    $xpath = addslashes($xpath0."/$pvalue/qos/rules/entry[@name='$value']");
                    $where = "after";
                    $dst = addslashes("$first");
                    $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action,whereto,dst) VALUES ('$value after $first','QoS Rules','order','','$xpath','move','$where','$dst');");
                    $first = $value;
                }
                unset($policy_order);
            }
        }
        else {
            if (isset($xpath->{$pvalue}->qos)) {
                $SA = $xpath->{$pvalue}->xpath("qos");
                unset($SA[0][0]);
                $xpath->{$pvalue}->addChild("qos");
                $xpath->{$pvalue}->qos->addChild("rules");
            }
            if ($api_call == "clean") {
                $xpath2 = addslashes($xpath0."/$pvalue/qos");
                $xml_final = "";
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Remove All QoS Rules $vsys $pvalue','QoS Rules','QoS Rules','$xml_final','$xpath2','delete');");
            }
        }
    }

}


function xml_tunnel_inspect_rules($xml,$data,&$objectsInMemory){

    $project = $data['project'];
    $ispanorama = $data['ispanorama'];
    $version = $data['version'];
    $api_call=$data['api_call'];
    $projectdb = $data['projectdb'];
    $source = $data['source'];
    $vsys = $data['vsys'];

    if (($vsys=="shared") AND ($ispanorama==0)){
        $message['code'] = false;
        $message['msg'] = "Shared Policies only can be found in Panorama. skipping";
        return $message;
    }

    if ($vsys == "shared") {
        $data['xpath0'] = "/config/shared";
    } else {
        if ($ispanorama == 1) {
            $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='" . $vsys . "']";
        } else {
            $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='" . $vsys . "']";
        }
    }
    $xpath0 = $data['xpath0'];

    if ($ispanorama==1){
        $platform="device-group";
        $policies = array("pre-rulebase", "post-rulebase");
    }
    else{
        $platform = "vsys";
        $policies = array("rulebase");
    }

    foreach ($policies as $pkey => $pvalue) {
        if (($pvalue == "pre-rulebase") OR ( $pvalue == "rulebase")) {
            $preorpost = 0;
        } elseif ($pvalue == "post-rulebase") {
            $preorpost = 1;
        }

        $xpath1 = $xml->xpath($xpath0);
        $xpath = $xpath1[0];

        # SECURITY
        if ($ispanorama==1){
            $getPolicies = $projectdb->query("SELECT * FROM tunnel_inspect_rules WHERE source='$source' AND vsys='$vsys' AND preorpost='$preorpost' ORDER BY position ASC;");
        }
        else{
            $getPolicies = $projectdb->query("SELECT * FROM tunnel_inspect_rules WHERE source='$source' AND vsys='$vsys' ORDER BY preorpost,position ASC;");
        }

        if ($getPolicies->num_rows > 0) {
            if (!isset($xpath->{$pvalue})) {
                $xpath->addChild($pvalue);
            }

            if (!isset($xpath->{$pvalue}->{'tunnel-inspect'})) {
                $xpath->{$pvalue}->addChild('tunnel-inspect');
            }

            if (!isset($xpath->{$pvalue}->{'tunnel-inspect'}->rules)) {
                $xpath->{$pvalue}->{'tunnel-inspect'}->addChild('rules');
            } else {
                #DELETE RULES
                $SA = $xpath->{$pvalue}->{'tunnel-inspect'}->xpath("rules");
                $xpath->{$pvalue}->{'tunnel-inspect'}->rules="";
            }
            $policy_order = array();
            while ($data2 = $getPolicies->fetch_object()) {
                $myname = $data2->name;
                $uuid = $data2->uuid;
                $policy_order[] = $data2->name;
                $target_negate=$data2->target_negate;
                $lid = $data2->id;

                $rule = $xpath->{$pvalue}->{'tunnel-inspect'}->rules->addChild('entry');
                $rule->addAttribute('name', $myname);

                if($version >= 9){
                    $rule->addAttribute('uuid', $uuid);
                }

                $getFrom = $projectdb->query("SELECT name FROM tunnel_inspect_rules_from WHERE rule_lid='$lid' ORDER BY id;");
                if ($getFrom->num_rows > 0) {
                    $rule->addChild('from');
                    while ($k = $getFrom->fetch_object()) {
                        $rule->from->addChild('member', $k->name);
                    }
                } else {
                    $rule->addChild('from');
                    $rule->from->addChild('member', 'any');
                }

                $getTo = $projectdb->query("SELECT name FROM tunnel_inspect_rules_to WHERE rule_lid='$lid'  ORDER BY id;");
                if ($getTo->num_rows > 0) {
                    $rule->addChild('to');
                    while ($k = $getTo->fetch_object()) {
                        $rule->to->addChild('member', $k->name);
                    }
                } else {
                    $rule->addChild('to');
                    $rule->to->addChild('member', 'any');
                }
                $getSource = $projectdb->query("SELECT member_lid,table_name FROM tunnel_inspect_rules_src WHERE rule_lid='$lid' ORDER BY id;");
                if ($getSource->num_rows > 0) {
                    $rule->addChild('source');
                    while ($k = $getSource->fetch_object()) {
                        $rule->source->addChild('member', $objectsInMemory[$k->table_name][$k->member_lid]['name']);
                    }
                } else {
                    $rule->addChild('source');
                    $rule->source->addChild('member', 'any');
                }
                $getDestination = $projectdb->query("SELECT member_lid,table_name FROM tunnel_inspect_rules_dst WHERE rule_lid='$lid' ORDER BY id;");
                if ($getDestination->num_rows > 0) {
                    $rule->addChild('destination');
                    while ($k = $getDestination->fetch_object()) {
                        $rule->destination->addChild('member', $objectsInMemory[$k->table_name][$k->member_lid]['name']);
                    }
                } else {
                    $rule->addChild('destination');
                    $rule->destination->addChild('member', 'any');
                }

                $getUser = $projectdb->query("SELECT name FROM tunnel_inspect_rules_usr WHERE rule_lid='$lid' ORDER BY id;");
                if ($getUser->num_rows > 0) {
                    $rule->addChild('source-user');
                    while ($k = $getUser->fetch_object()) {
                        //$rule->{'source-user'}->addChild('member',htmlentities($k->name));
                        //It got a weird character (Entity 'uuml' not defined in Entity) MT-892
                        $rule->{'source-user'}->addChild('member',htmlspecialchars($k->name));
                        //$rule->{'source-user'}->addChild('member',$k->name);
                    }
                } else {
                    $rule->addChild('source-user');
                    $rule->{'source-user'}->addChild('member', 'any');
                }

                $getAPP = $projectdb->query("SELECT member_lid,table_name FROM tunnel_inspect_rules_app WHERE rule_lid='$lid' ORDER BY id;");
                if ($getAPP->num_rows > 0) {
                    $rule->addChild('application');
                    while ($k = $getAPP->fetch_object()) {
                        $rule->{'application'}->addChild('member', $objectsInMemory[$k->table_name][$k->member_lid]['name']);
                    }
                } else {
                    $rule->addChild('application');
                    $rule->{'application'}->addChild('member', 'any');
                }

                //$rule->addChild('action');
                //$rule->{'action'}->addChild('class', $data2->action);

                if ($data2->enable_log_setting != "") {

                    $rule->addChild('monitor-options');

                    if ($data2->monitor_name_tunnel != "") {
                        $rule->{'monitor-options'}->addChild('monitor-name', $data2->monitor_name_tunnel);
                    }

                    if ($data2->monitor_id_tunnel != "") {
                        $rule->{'monitor-options'}->addChild('monitor-id', $data2->monitor_id_tunnel);
                    }

                    $rule->{'monitor-options'}->addChild('log-setting-override');
                    $rule->{'monitor-options'}->{'log-setting-override'}->addChild('enable', $data2->enable_log_setting);

                    if ($data2->log_forwarding != "") {
                        $rule->{'monitor-options'}->{'log-setting-override'}->addChild('log-setting', $data2->log_forwarding);
                    }

                    if($data2->log_start_log_setting != ""){
                        $rule->{'monitor-options'}->{'log-setting-override'}->addChild('log-start', $data2->log_start_log_setting);
                    }

                    if($data2->log_end_log_setting != ""){
                        $rule->{'monitor-options'}->{'log-setting-override'}->addChild('log-end', $data2->log_end_log_setting);
                    }
                }

                if($data2->inspect_options != ""){
                    $xml_append = simplexml_load_string(clean_xml($data2->inspect_options));
                    SimpleXMLElement_append($rule, $xml_append);
                }

                if ($data2->disabled == 1) {
                    $rule->addChild('disabled', 'yes');
                }

                if ($data2->negate_source == 1) {
                    $rule->addChild('negate-source', 'yes');
                }

                if ($data2->negate_destination == 1) {
                    $rule->addChild('negate-destination', 'yes');
                }

                if ($data2->description != "") {
                    $rule->addChild('description');
                    $rule->description = truncate_descriptions($data2->description,$version);
                }

                $getTAG = $projectdb->query("SELECT member_lid,table_name FROM tunnel_inspect_rules_tag WHERE rule_lid='$lid' ORDER BY id;");
                if ($getTAG->num_rows > 0) {
                    $rule->addChild('tag');
                    while ($k = $getTAG->fetch_object()) {
                        //$rule->{'tag'}->addChild('member', htmlentities($objectsInMemory[$k->table_name][$k->member_lid]['name']));
                        //MT-892
                        $rule->{'tag'}->addChild('member', htmlspecialchars($objectsInMemory[$k->table_name][$k->member_lid]['name']));

                    }
                }

                if($version >= 9){
                    if($data2->group_tag_id != 0){
                        $getGroupTag = $projectdb->query("SELECT name FROM tag WHERE id = '$data2->group_tag_id';");
                        if ($getGroupTag->num_rows > 0) {
                            $k = $getGroupTag->fetch_object();
                            $rule->addChild('group-tag', htmlspecialchars($k->name));
                        }
                    }
                }

                if ($ispanorama==1){
                    $getTarget=$projectdb->query("SELECT * FROM tunnel_inspect_rules_target WHERE rule_lid='$lid' ORDER BY id;");

                    if ($getTarget->num_rows>0){
                        $rule->addChild("target");
                        if ($target_negate!=""){
                            $rule->target->addChild("negate",$target_negate);
                        }
                        $rule->target->addChild("devices");
                        while($getTargetData=$getTarget->fetch_assoc()){
                            $device_vsys=$getTargetData['device_vsys'];
                            $name=$getTargetData['name'];
                            if (empty($rule->target->devices->xpath("./entry[@name='$name']"))){
                                $target=$rule->target->devices->addChild("entry");
                                $target->addAttribute("name",$name);
                            }
                            else{
                                $target0=$rule->target->devices->xpath("./entry[@name='$name']");
                                $target=$target0[0];
                            }

                            if ($device_vsys!=""){
                                if (!isset($target->vsys)){
                                    $target->addChild("vsys");
                                }
                                $target_vsys=$target->vsys->addChild("entry");
                                $target_vsys->addAttribute("name",$device_vsys);
                            }
                        }
                    }
                }

                if ($api_call == "single") {
                    $xpath2 = addslashes($xpath0."/$pvalue/tunnel-inspect/rules/entry[@name='$myname']");
                    $xml_final = addslashes($rule->asXML());
                    $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','Tunnel Inspection Rules','Tunnel Inspection Rules','$xml_final','$xpath2','edit');");
                }

            }
            if ($api_call == "atomic") {
                $xpath2 = addslashes($xpath0."/$pvalue/tunnel-inspect");
                $xml_final = addslashes($xpath->{$pvalue}->{'tunnel-inspect'}->asXML());
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Tunnel Inspection Rules $vsys','Tunnel Inspection Rules','Tunnel Inspection Rules','$xml_final','$xpath2','edit');");
            }
            if ((count($policy_order) > 0) AND ( $api_call == "single")) {
                $first = $policy_order[0];
                $last = $policy_order[count($policy_order) - 1];
                # Set first Rule
                $xpath = addslashes($xpath0."/$pvalue/tunnel-inspect/rules/entry[@name='$first']");
                $where = "top";
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action,whereto,dst) VALUES ('$first to Top','Tunnel Inspection Rules','order','','$xpath','move','$where','');");
                unset($policy_order[0]);
                foreach ($policy_order as $key => $value) {
                    $xpath = addslashes($xpath0."/$pvalue/tunnel-inspect/rules/entry[@name='$value']");
                    $where = "after";
                    $dst = addslashes("$first");
                    $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action,whereto,dst) VALUES ('$value after $first','Tunnel Inspection Rules','order','','$xpath','move','$where','$dst');");
                    $first = $value;
                }
                unset($policy_order);
            }
        }
        else {
            if (isset($xpath->{$pvalue}->{'tunnel-inspect'})) {
                $SA = $xpath->{$pvalue}->xpath("tunnel-inspect");
                unset($SA[0][0]);
                $xpath->{$pvalue}->addChild("tunnel-inspect");
                $xpath->{$pvalue}->{'tunnel-inspect'}->addChild("rules");
            }
            if ($api_call == "clean") {
                $xpath2 = addslashes($xpath0."/$pvalue/tunnel-inspect");
                $xml_final = "";
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Remove All Tunnel Inspection Rules $vsys $pvalue','Tunnel Inspection Rules','Tunnel Inspection Rules','$xml_final','$xpath2','delete');");
            }
        }
    }

}


function xml_vsys($xml,$data){
    $project = $data['project'];
    $ispanorama = $data['ispanorama'];
    $version = $data['version'];
    $api_call=$data['api_call'];
    $projectdb = $data['projectdb'];
    $source = $data['source'];
    $vsys = $data['vsys'];
    $template = $data['template'];
    $template_name=$data['template_name'];

    if ($vsys != "shared") {
        if ($ispanorama == 1) {

            $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='" . $template_name . "']/config/devices/entry[@name='localhost.localdomain']";
        }
        else {
            $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']";
        }

    }
    else{
        $message['code'] = false;
        $message['msg'] = "Invalid VSYS Name for Id:$vsys";
        return $message;
    }

    $xpath0 = $data['xpath0'];

    $myTemplateDevice0=$xml->xpath($xpath0);
    $myTemplateDevice=$myTemplateDevice0[0];

    $getDG = $projectdb->query("SELECT * FROM virtual_systems WHERE source='$source' AND template='$template' AND name='$vsys';");

    if ($getDG->num_rows > 0) {
        if (!isset($myTemplateDevice->vsys)) {
            $myTemplateDevice->addChild('vsys');
        }

        while ($DG = $getDG->fetch_assoc()) {
            $DGName = $DG['name'];
            if ($myTemplateDevice->xpath("vsys/entry[@name='$DGName']") == null) {
                $thedevicegroup = $myTemplateDevice->vsys->addChild('entry');
                $thedevicegroup->addAttribute('name', $DGName);
            } else {
                $thedevicegroup0 = $myTemplateDevice->xpath("vsys/entry[@name='$DGName']");
                $thedevicegroup = $thedevicegroup0[0];
            }
            if ($ispanorama==0){
                if ($DG['display_name'] != "") {
                    if (isset($thedevicegroup->{'display-name'})){
                        $thedevicegroup->{"display-name"} = $DG['display_name'];
                    }
                    else{
                        $thedevicegroup->addChild("display-name", $DG['display_name']);
                    }

                }
            }
            if (!isset($thedevicegroup->import)) {
                $thedevicegroup->addChild('import');
            }
            if (!isset($thedevicegroup->import->network)) {
                $thedevicegroup->import->addChild('network');
            }
            else {
                $SA = $thedevicegroup->xpath("import/network");
                unset($SA[0][0]);
                $thedevicegroup->import->addChild('network');
            }

            #Interface
            $getInterfaces = $projectdb->query("SELECT unitname FROM interfaces WHERE template='$template' AND source='$source' AND vsys='$vsys' AND type NOT IN ('ha', 'aggregate-group', 'log-card', 'decrypt-mirror') AND unitname NOT IN ('loopback', 'vlan', 'tunnel') ORDER BY unitname;");
            //echo "SELECT unitname FROM interfaces WHERE template='$template' AND source='$source' AND vsys='$vsys' AND type != 'ha' AND type NOT IN ('ha', 'aggregate-group', 'log-card', 'decrypt-mirror') AND unitname NOT IN ('loopback', 'vlan', 'tunnel') ORDER BY unitname;\n";
            if($getInterfaces->num_rows > 0){
                $thedevicegroup->import->network->addChild('interface');
                while($data = $getInterfaces->fetch_assoc()){
                    $thedevicegroup->import->network->interface->addChild('member', $data['unitname']);
                }
            }
            if ($DG['virtual_router'] != "") {
                $thedevicegroup->import->network->addChild('virtual-router');
                $interfaces = explode(",", $DG['virtual_router']);
                foreach ($interfaces as $key => $value) {
                    if ($value != "") {
                        $thedevicegroup->import->network->{'virtual-router'}->addChild('member', $value);
                    }
                }
            }
            if ($DG['virtual_wire'] != "") {
                $thedevicegroup->import->network->addChild('virtual-wire');
                $interfaces = explode(",", $DG['virtual_wire']);
                foreach ($interfaces as $key => $value) {
                    if ($value != "") {
                        $thedevicegroup->import->network->{'virtual-wire'}->addChild('member', $value);
                    }
                }
            }
            if ($DG['vlan'] != "") {
                $thedevicegroup->import->network->addChild('vlan');
                $interfaces = explode(",", $DG['vlan']);
                foreach ($interfaces as $key => $value) {
                    if ($value != "") {
                        $thedevicegroup->import->network->{'vlan'}->addChild('member', $value);
                    }
                }
            }
            if ($DG['visible_vsys'] != "") {
                if (!isset($thedevicegroup->import->{'visible-vsys'})){
                    $thedevicegroup->import->addChild('visible-vsys');
                }
                else{
                    $SA = $thedevicegroup->import->xpath("visible-vsys");
                    unset($SA[0][0]);
                    $thedevicegroup->import->addChild('visible-vsys');
                }
                $interfaces = explode(",", $DG['visible_vsys']);
                foreach ($interfaces as $key => $value) {
                    if ($value != "") {
                        $thedevicegroup->import->{'visible-vsys'}->addChild('member', $value);
                    }
                }
            }
            else{
                $SA = $thedevicegroup->import->xpath("visible-vsys");
                unset($SA[0][0]);
            }

            if (isset($thedevicegroup->import->resource)) {
                $SA = $thedevicegroup->xpath("import/resource");
                unset($SA[0][0]);
            }

            $thedevicegroup->import->addChild('resource');
            $DGresource = $thedevicegroup->import->resource;
            $max_application_override_rules = $DG['max_application_override_rules'];
            if ($max_application_override_rules != "0") {
                $DGresource->addChild('max-application-override-rules', $max_application_override_rules);
            }
            $max_concurrent_ssl_vpn_tunnels = $DG['max_concurrent_ssl_vpn_tunnels'];
            if ($max_concurrent_ssl_vpn_tunnels != "0") {
                $DGresource->addChild('max-concurrent-ssl-vpn-tunnels', $max_concurrent_ssl_vpn_tunnels);
            }
            if ($version>=8){
                $max_cp_rules = $DG['max_cp_rules'];
                if ($max_cp_rules != "0") {
                    $DGresource->addChild('max-auth-rules', $max_cp_rules);
                }
            }
            else{
                $max_cp_rules = $DG['max_cp_rules'];
                if ($max_cp_rules != "0") {
                    $DGresource->addChild('max-cp-rules', $max_cp_rules);
                }
            }
            $max_dos_rules = $DG['max_dos_rules'];
            if ($max_dos_rules != "0") {
                $DGresource->addChild('max-dos-rules', $max_dos_rules);
            }
            $max_nat_rules = $DG['max_nat_rules'];
            if ($max_nat_rules != "0") {
                $DGresource->addChild('max-nat-rules', $max_nat_rules);
            }
            $max_pbf_rules = $DG['max_pbf_rules'];
            if ($max_pbf_rules != "0") {
                $DGresource->addChild('max-pbf-rules', $max_pbf_rules);
            }
            $max_qos_rules = $DG['max_qos_rules'];
            if ($max_qos_rules != "0") {
                $DGresource->addChild('max-qos-rules', $max_qos_rules);
            }
            $max_security_rules = $DG['max_security_rules'];
            if ($max_security_rules != "0") {
                $DGresource->addChild('max-security-rules', $max_security_rules);
            }
            $max_sessions = $DG['max_sessions'];
            if ($max_sessions != "0") {
                $DGresource->addChild('max-sessions', $max_sessions);
            }
            $max_site_to_site_vpn_tunnels = $DG['max_site_to_site_vpn_tunnels'];
            if ($max_site_to_site_vpn_tunnels != "0") {
                $DGresource->addChild('max-site-to-site-vpn-tunnels', $max_site_to_site_vpn_tunnels);
            }
            $max_ssl_decryption_rules = $DG['max_ssl_decryption_rules'];
            if ($max_ssl_decryption_rules != "0") {
                $DGresource->addChild('max-ssl-decryption-rules', $max_ssl_decryption_rules);
            }
            $dns_proxy = $DG['dns_proxy'];
            if (($dns_proxy != "") AND ($dns_proxy != "None")) {
                if (isset($thedevicegroup->import->{'dns-proxy'})){
                    $thedevicegroup->import->{'dns-proxy'}=$dns_proxy;
                }
                else{
                    $thedevicegroup->import->addChild('dns-proxy',$dns_proxy);
                }
            }
            else{
                if (isset($thedevicegroup->import->{'dns-proxy'})){
                    unset($thedevicegroup->import->{'dns-proxy'});
                }
            }
            $allow_forward_decrypted_content = $DG['allow_forward_decrypted_content'];
            if (($allow_forward_decrypted_content == "") OR ($allow_forward_decrypted_content == "no")) {$allow_forward_decrypted_content="no";}
            else{$allow_forward_decrypted_content="yes";}
            if (isset($thedevicegroup->setting->{'ssl-decrypt'})) {
                $thedevicegroup->setting->{'ssl-decrypt'}->{'allow-forward-decrypted-content'}=$allow_forward_decrypted_content;
            }
            else{
                if (!isset($thedevicegroup->setting)){$thedevicegroup->addChild("setting");}
                $thedevicegroup->setting->addChild('ssl-decrypt');
                $thedevicegroup->setting->{'ssl-decrypt'}->addChild('allow-forward-decrypted-content',$allow_forward_decrypted_content);
            }
            if (($api_call == "single")  OR ($api_call=="atomic")){
                # Create the Vsys itself
                $xpath2 = addslashes($xpath0."/vsys");
                //$xml_final_setting = addslashes("<entry name='$DGName'></entry>");
                $xml_final_setting = addslashes($thedevicegroup->asXML());
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Virtual Systems $DGName','Virtual Systems','Virtual Systems','$xml_final_setting','$xpath2','set');");
                /*$xpath2 = addslashes($xpath0."/vsys/entry[@name='$DGName']/setting");
                $xml_final_setting = addslashes($thedevicegroup->setting->asXML());
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Setting $DGName','Virtual Systems','Virtual Systems','$xml_final_setting','$xpath2','edit');");
                $xpath2 = addslashes($xpath0."/vsys/entry[@name='$DGName']/import");
                $xml_final_setting = addslashes($thedevicegroup->import->asXML());
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Import $DGName','Virtual Systems','Virtual Systems','$xml_final_setting','$xpath2','edit');");
                */
            }
        }
    }
    else{
        if (isset($myTemplateDevice->vsys)) {
            $SA = $myTemplateDevice->xpath("vsys");
            unset($SA[0][0]);
        }
        if ($api_call == "clean") {
            $xpath2 = addslashes($xpath0."/vsys");
            $xml_final = "";
            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Remove All Virtual Systems $template_name','Virtual Systems','Virtual Systems','$xml_final','$xpath2','delete');");
        }
        $message['code'] = true;
        $message['msg'] = "Removed All Virtual Systems";
        return $message;
    }
}

function xml_zones($xml,$data){
    $project = $data['project'];
    $ispanorama = $data['ispanorama'];
    $version = $data['version'];
    $api_call=$data['api_call'];
    $projectdb = $data['projectdb'];
    $source = $data['source'];
    $vsys = $data['vsys'];
    $template = $data['template'];
    $template_name=$data['template_name'];

    if ($vsys != "shared") {
        if ($ispanorama == 1) {
            $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='" . $template_name . "']/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='$vsys']";
        }
        else {
            $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='$vsys']";
        }

    }
    else{
        $message['code'] = false;
        $message['msg'] = "Invalid VSYS Name for Id:$vsys";
        return $message;
    }

    $xpath0 = $data['xpath0'];

    if (empty($xml->xpath($xpath0."/zone"))){
        $thedevicegroup0=$xml->xpath($xpath0);
        //$thedevicegroup0[0]->addChild("zone");
    }
    else{
        $SA=$xml->xpath($xpath0."/zone");
        unset($SA[0][0]);
        $thedevicegroup0=$xml->xpath($xpath0);

    }
    $thedevicegroup = $thedevicegroup0[0];

    $getShared = $projectdb->query("SELECT * FROM zones WHERE source='$source' AND vsys='$vsys' AND template='$template' ORDER BY id;");

    if ($getShared->num_rows > 0) {
        $thedevicegroup->addChild('zone');

        while ($data = $getShared->fetch_assoc()) {
            $myname = $data['name'];
            $zones_lid = $data['id'];
            $type = strtolower($data['type']);
            $interfaces = $data['interfaces'];
            $zone_protection_profile = $data['zone_protection_profile'];
            $log_setting_id = $data['log_setting_id'];
            $log_setting_table_name = $data['log_setting_table_name'];
            $include_list = $data['include_list'];
            $exclude_list = $data['exclude_list'];
            $enable_user_identification = $data['enable_user_identification'];
            $enable_packet_buffer_protection = $data['enable_packet_buffer_protection'];
            $zone = $thedevicegroup->zone->addChild('entry');
            $zone->addAttribute('name', $myname);
            $zone->addChild('network');

            if($type != ""){
                $zone->network->addChild($type);
                if ($interfaces != "") {
                    $allinterfaces = explode(",", $interfaces);
                    foreach ($allinterfaces as $key => $vvvalue) {
                        $zone->network->{$type}->addChild('member', $vvvalue);
                    }
                }
            }

            if (($zone_protection_profile != "") AND ( $zone_protection_profile != "None")) {
                $zone->network->addChild('zone-protection-profile', $zone_protection_profile);
            }
            if (($log_setting_id != "") AND ( $log_setting_table_name != "")) {
                $getLP = $projectdb->query("SELECT name FROM $log_setting_table_name WHERE id='$log_setting_id';");
                if ($getLP->num_rows == 1) {
                    $LPData = $getLP->fetch_assoc();
                    $zone->network->addChild('log-setting', $LPData['name']);
                }
            }
            if (($include_list != "") OR ( $exclude_list != "")) {
                $zone->addChild('user-acl');
            }

            if ($version>=8){
                if ($enable_packet_buffer_protection=="yes"){
                    $zone->network->addChild("enable-packet-buffer-protection","yes");
                }
            }

            if ($include_list != "") {

                $zone->{'user-acl'}->addChild('include-list');

                $getIL = $projectdb->query("SELECT a.name FROM address a, zones_include_list z WHERE z.zones_lid = '$zones_lid' AND a.id = z.member_lid AND z.table_name = 'address'; ");

                if($getIL->num_rows > 0){
                    while($dataIL = $getIL->fetch_assoc()){
                        $zone->{'user-acl'}->{'include-list'}->addChild('member', $dataIL['name']);
                    }
                }

                $getIL = $projectdb->query("SELECT a.name FROM address_groups_id a, zones_include_list z WHERE z.zones_lid = '$zones_lid' AND a.id = z.member_lid AND z.table_name = 'address_groups_id'; ");

                if($getIL->num_rows > 0){
                    while($dataIL = $getIL->fetch_assoc()){
                        $zone->{'user-acl'}->{'include-list'}->addChild('member', $dataIL['name']);
                    }
                }

                $getILN = $projectdb->query("SELECT table_name AS name FROM zones_include_list WHERE zones_lid = '$zones_lid' AND member_lid = '0';");
                if($getILN->num_rows > 0){
                    while($dataILN = $getILN->fetch_assoc()){
                        $zone->{'user-acl'}->{'include-list'}->addChild('member', $dataILN['name']);
                    }
                }
            }

            if ($exclude_list != "") {

                $zone->{'user-acl'}->addChild('exclude-list');

                $getEL = $projectdb->query("SELECT a.name FROM address a, zones_exclude_list z WHERE z.zones_lid = '$zones_lid' AND a.id = z.member_lid AND z.table_name = 'address'; ");

                if($getEL->num_rows > 0){
                    while($dataEL = $getEL->fetch_assoc()){
                        $zone->{'user-acl'}->{'exclude-list'}->addChild('member', $dataEL['name']);
                    }
                }

                $getEL = $projectdb->query("SELECT a.name FROM address_groups_id a, zones_exclude_list z WHERE z.zones_lid = '$zones_lid' AND a.id = z.member_lid AND z.table_name = 'address_groups_id'; ");

                if($getEL->num_rows > 0){
                    while($dataEL = $getEL->fetch_assoc()){
                        $zone->{'user-acl'}->{'exclude-list'}->addChild('member', $dataEL['name']);
                    }
                }

                $getELN = $projectdb->query("SELECT table_name AS name FROM zones_exclude_list WHERE zones_lid = '$zones_lid' AND member_lid = '0';");
                if($getELN->num_rows > 0){
                    while($dataELN = $getELN->fetch_assoc()){
                        $zone->{'user-acl'}->{'exclude-list'}->addChild('member', $dataELN['name']);
                    }
                }
            }

            if ($enable_user_identification == "yes") {
                $zone->addChild('enable-user-identification', $enable_user_identification);
            }

            if ($api_call=="single"){
                $xpath2 = addslashes($xpath0."/zone/entry[@name='$myname']");
                $xml_final = addslashes($zone->asXML());
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','Zones','Zones','$xml_final','$xpath2','edit');");
            }
        }
        if ($api_call=="atomic"){
            $xpath2 = addslashes($xpath0."/zone");
            $xml_final = addslashes($thedevicegroup->zone->asXML());
            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Zones $vsys','Zones','Zones','$xml_final','$xpath2','edit');");
        }
    }
    else{
        if (isset($thedevicegroup->zone)){
            $SA = $xml->xpath($xpath0."/zone");
            unset($SA[0][0]);
        }

        if ($api_call=="clean"){
            $xpath2 = addslashes($xpath0."/zone");
            $xml_final = "";
            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Remove All Zones $vsys','Zones','Zones','$xml_final','$xpath2','delete');");
        }
        $message['code'] = true;
        $message['msg'] = "Removed All Zones : $vsys";
        return $message;
    }


}

function xml_network_interface_ethernet($xml,$data){
    $project = $data['project'];
    $ispanorama = $data['ispanorama'];
    $version = $data['version'];
    $api_call=$data['api_call'];
    $projectdb = $data['projectdb'];
    $source = $data['source'];
    $template = $data['template'];
    $template_name=$data['template_name'];

    //if ( ($template!=0) AND ($ispanorama==0)){
        if ($ispanorama==0){
            $data['xpath_parent']="/config/devices/entry[@name='localhost.localdomain']";
            $data['xpath_network']="/config/devices/entry[@name='localhost.localdomain']/network";
            $data['xpath0']="/config/devices/entry[@name='localhost.localdomain']/network/interface";
            $template_name="Device";
        }
        else{
            $data['xpath_parent']="/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='".$template_name."']/config/devices/entry[@name='localhost.localdomain']";
            $data['xpath_network']="/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='".$template_name."']/config/devices/entry[@name='localhost.localdomain']/network";
            $data['xpath0']="/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='".$template_name."']/config/devices/entry[@name='localhost.localdomain']/network/interface";
        }
        $getIntEthernet = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='ethernet' AND unittag='0' AND unitname=name GROUP BY name ORDER BY id");
        //echo "1. SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='ethernet' AND unittag='0' AND unitname=name GROUP BY name ORDER BY id\n";
        if ($getIntEthernet->num_rows > 0) {

            if (!empty($xml->xpath($data['xpath0']."/ethernet"))){
                $SA=$xml->xpath($data['xpath0']."/ethernet");
                unset($SA[0][0]);
            }
            if(empty($xml->xpath($data['xpath_network']))){
                $myTemplateDeviceNetwork0 = $xml->xpath($data['xpath_parent']);
                $myTemplateDeviceNetwork = $myTemplateDeviceNetwork0[0]->addChild("network");
            }
            if (empty($xml->xpath($data['xpath0']))){
                $myTemplateDeviceNetwork0 = $xml->xpath($data['xpath_network']);
                $myTemplateDeviceNetwork0[0]->addChild("interface");
            }
            $myTemplateDeviceNetwork0=$xml->xpath($data['xpath_network']);
            $myTemplateDeviceNetwork=$myTemplateDeviceNetwork0[0];

            $theINT = $myTemplateDeviceNetwork->interface;
            $theINT->addChild("ethernet");
            while ($getIntEthernetData = $getIntEthernet->fetch_assoc()) {
                $myname = $getIntEthernetData['name'];
                $int = $theINT->ethernet->addChild('entry');
                $int->addAttribute('name', $myname);

                if ($version>=7){
                    if ($getIntEthernetData['link_speed'] != "")  {
                        $int->addChild("link-speed", $getIntEthernetData['link_speed']);
                    }
                    if ($getIntEthernetData['link_duplex'] != "")  {
                        $int->addChild("link-duplex", $getIntEthernetData['link_duplex']);
                    }
                    if ($getIntEthernetData['link_state'] != "")  {
                        $int->addChild("link-state", $getIntEthernetData['link_state']);
                    }
                    if (($getIntEthernetData['lacp_port_priority'] != "") && ($getIntEthernetData['lacp_port_priority'] != "0"))  {
                        $int->addChild("lacp");
                        $int->lacp->addChild("port-priority",$getIntEthernetData['lacp_port_priority']);
                    }

                }
                else{
                    if (($getIntEthernetData['link_speed'] != "") AND ( $getIntEthernetData['link_speed'] != "auto")) {
                        $int->addChild("link-speed", $getIntEthernetData['link_speed']);
                    }
                    if (($getIntEthernetData['link_duplex'] != "") AND ( $getIntEthernetData['link_duplex'] != "auto")) {
                        $int->addChild("link-duplex", $getIntEthernetData['link_duplex']);
                    }
                    if (($getIntEthernetData['link_state'] != "") AND ( $getIntEthernetData['link_state'] != "auto")) {
                        $int->addChild("link-state", $getIntEthernetData['link_state']);
                    }
                }

                if ($getIntEthernetData['comment'] != "") {
                    $int->addChild("comment");
                    $int->comment = $getIntEthernetData['comment'];
                }
                if ($getIntEthernetData['type'] == "tap") {
                    $int->addChild("tap");
                    if ($getIntEthernetData['netflow_profile'] != "") {
                        $int->tap->addChild("netflow-profile", $getIntEthernetData['netflow_profile']);
                    }
                }
                if ($getIntEthernetData['type'] == "virtual-wire") {

                    $int->addChild("virtual-wire");
                    if ($getIntEthernetData['netflow_profile'] != "") {
                        $int->{'virtual-wire'}->addChild("netflow-profile", $getIntEthernetData['netflow_profile']);
                    }

                    if ($version>=7){
                        if ($getIntEthernetData['lldp'] != "") {
                            $xml_append = simplexml_load_string(clean_xml($getIntEthernetData['lldp']));
                            SimpleXMLElement_append($int->{'virtual-wire'}, $xml_append);
                        }
                    }

                    $getUnits = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='ethernet' AND unitname!='$myname' AND name='$myname';");
                    if ($getUnits->num_rows > 0) {
                        $int->{'virtual-wire'}->addChild("units");
                        while ($getUnitsData = $getUnits->fetch_assoc()) {
                            $myname1 = $getUnitsData['unitname'];
                            $VWUnit = $int->{'virtual-wire'}->units->addChild('entry');
                            $VWUnit->addAttribute('name', $myname1);
                            if ($getUnitsData['comment'] != "") {
                                $VWUnit->addChild("comment");
                                $VWUnit->comment = $getUnitsData['comment'];
                            }
                            if ($getUnitsData['netflow_profile'] != "") {
                                $VWUnit->addChild("netflow-profile", $getUnitsData['netflow_profile']);
                            }

                            $VWUnit->addChild("tag", $getUnitsData['unittag']);

                            if ($getUnitsData['ip_classifier'] != "") {
                                $interfaces_all = explode(",", $getUnitsData['ip_classifier']);
                                $VWUnit->addChild("ip-classifier");
                                foreach ($interfaces_all as $key => $int_value) {
                                    $VWUnit->{'ip-classifier'}->addChild("member", $int_value);
                                }
                            }
                        }
                    }
                }
                if ($getIntEthernetData['type'] == "layer2") {
                    $int->addChild("layer2");
                    if ($getIntEthernetData['netflow_profile'] != "") {
                        $int->layer2->addChild("netflow-profile", $getIntEthernetData['netflow_profile']);
                    }
                    if ($version>=7){
                        if ($getIntEthernetData['lldp'] != "") {
                            $xml_append = simplexml_load_string(clean_xml($getIntEthernetData['lldp']));
                            SimpleXMLElement_append($int->layer2, $xml_append);
                        }
                    }
                    $getUnits = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='ethernet' AND unitname!='$myname' AND name='$myname';");
                    if ($getUnits->num_rows > 0) {
                        $int->{'layer2'}->addChild("units");
                        while ($getUnitsData = $getUnits->fetch_assoc()) {
                            $myname1 = $getUnitsData['unitname'];
                            $VWUnit = $int->{'layer2'}->units->addChild('entry');
                            $VWUnit->addAttribute('name', $myname1);
                            if ($getUnitsData['netflow_profile'] != "") {
                                $VWUnit->addChild("netflow-profile", $getUnitsData['netflow_profile']);
                            }
                            if ($getUnitsData['comment'] != "") {
                                $VWUnit->addChild("comment");
                                $VWUnit->comment = $getUnitsData['comment'];
                            }
                            $VWUnit->addChild("tag", $getUnitsData['unittag']);
                        }
                    }
                }
                elseif ($getIntEthernetData['type'] == "ha") {
                    $int->addChild("ha");
                }
                elseif ($getIntEthernetData['type'] == "layer3") {
                    $int->addChild("layer3");
                    if ($getIntEthernetData['netflow_profile'] != "") {
                        $int->layer3->addChild("netflow-profile", $getIntEthernetData['netflow_profile']);
                    }
                    if (($getIntEthernetData['mtu'] != "") AND ( $getIntEthernetData['mtu'] != "0")) {
                        $int->layer3->addChild("mtu", $getIntEthernetData['mtu']);
                    }
                    if (($getIntEthernetData['interface_management_profile'] != "") AND ( $getIntEthernetData['interface_management_profile'] != "None")) {
                        $int->layer3->addChild("interface-management-profile", $getIntEthernetData['interface_management_profile']);
                    }

                    if ($getIntEthernetData['untagged_sub_interface'] != "") {
                        $int->layer3->addChild("untagged-sub-interface", $getIntEthernetData['untagged_sub_interface']);
                    }
                    if ($getIntEthernetData['arp'] != "") {
                        $xml_append = simplexml_load_string(clean_xml($getIntEthernetData['arp']));
                        SimpleXMLElement_append($int->layer3, $xml_append);
                    }
                    if ($version>=7){
                        if ($getIntEthernetData['lldp'] != "") {
                            $xml_append = simplexml_load_string(clean_xml($getIntEthernetData['lldp']));
                            SimpleXMLElement_append($int->layer3, $xml_append);
                        }
                        if ($getIntEthernetData['ndpproxy'] != "") {
                            $xml_append = simplexml_load_string(clean_xml($getIntEthernetData['ndpproxy']));
                            SimpleXMLElement_append($int->layer3, $xml_append);
                        }
                    }
                    if ($getIntEthernetData['ipv4_type'] == "static") {
                        if ($getIntEthernetData['ipv6'] != "") {
                            $xml_append = simplexml_load_string(clean_xml($getIntEthernetData['ipv6']));
                            SimpleXMLElement_append($int->layer3, $xml_append);
                        }
                        if ($getIntEthernetData['unitipaddress'] != "") {
                            $interfaces_all = explode(",", $getIntEthernetData['unitipaddress']);
                            $int->layer3->addChild("ip");
                            foreach ($interfaces_all as $key => $int_value) {
                                $newInt = $int->layer3->ip->addChild("entry");
                                $newInt->addAttribute('name', $int_value);
                            }
                        }
                        if ($version>=7){
                            if ($getIntEthernetData['adjust_tcp_mss'] != "") {
                                $int->layer3->addChild("adjust-tcp-mss");
                                $int->layer3->{'adjust-tcp-mss'}->addChild("enable",$getIntEthernetData['adjust_tcp_mss']);
                                if ($getIntEthernetData['ipv4_mss_adjustment']!=0){
                                    $int->layer3->{'adjust-tcp-mss'}->addChild("ipv4-mss-adjustment",$getIntEthernetData['ipv4_mss_adjustment']);
                                }
                                if ($getIntEthernetData['ipv6_mss_adjustment']!=0){
                                    $int->layer3->{'adjust-tcp-mss'}->addChild("ipv6-mss-adjustment",$getIntEthernetData['ipv6_mss_adjustment']);
                                }
                            }
                        }
                        else{
                            if ($getIntEthernetData['adjust_tcp_mss'] != "") {
                                $int->layer3->addChild("adjust-tcp-mss", $getIntEthernetData['adjust_tcp_mss']);
                            }
                        }
                    } elseif ($getIntEthernetData['ipv4_type'] == "dhcp-client") {
                        $int->layer3->addChild("dhcp-client");
                        if ($getIntEthernetData['ipv6'] != "") {
                            $xml_append = simplexml_load_string(clean_xml($getIntEthernetData['ipv6']));
                            SimpleXMLElement_append($int->layer3, $xml_append);
                        }
                        if ($getIntEthernetData['dhcp_client_enable'] == "no") {
                            $int->layer3->{"dhcp-client"}->addChild("enable", "no");
                        }
                        if ($getIntEthernetData['dhcp_client_default_route_metric'] != "0") {
                            $int->layer3->{"dhcp-client"}->addChild("default-route-metric", $getIntEthernetData['dhcp_client_default_route_metric']);
                        }
                        if ($getIntEthernetData['dhcp_client_create_default_route'] == "no") {
                            $int->layer3->{"dhcp-client"}->addChild("create-default-route", "no");
                        }
                        if ($version>=7){
                            if ($getIntEthernetData['adjust_tcp_mss'] != "") {
                                $int->layer3->addChild("adjust-tcp-mss");
                                $int->layer3->{'adjust-tcp-mss'}->addChild("enable",$getIntEthernetData['adjust_tcp_mss']);
                                if ($getIntEthernetData['ipv4_mss_adjustment']!=0){
                                    $int->layer3->{'adjust-tcp-mss'}->addChild("ipv4-mss-adjustment",$getIntEthernetData['ipv4_mss_adjustment']);
                                }
                                if ($getIntEthernetData['ipv6_mss_adjustment']!=0){
                                    $int->layer3->{'adjust-tcp-mss'}->addChild("ipv6-mss-adjustment",$getIntEthernetData['ipv6_mss_adjustment']);
                                }
                            }
                        }
                        else{
                            if ($getIntEthernetData['adjust_tcp_mss'] != "") {
                                $int->layer3->addChild("adjust-tcp-mss", $getIntEthernetData['adjust_tcp_mss']);
                            }
                        }

                    }
                    # UNITS
                    $getUnits = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='ethernet' AND unitname!='$myname' AND name='$myname';");
                    if ($getUnits->num_rows > 0) {
                        $unit = $int->layer3->addChild("units");
                        while ($getUnitsData = $getUnits->fetch_assoc()) {
                            $myname1 = $getUnitsData['unitname'];
                            $UnitInt = $unit->addChild('entry');
                            $UnitInt->addAttribute('name', $myname1);
                            if ($getUnitsData['netflow_profile'] != "") {
                                $UnitInt->addChild("netflow-profile", $getUnitsData['netflow_profile']);
                            }
                            if ($getUnitsData['unittag']!=0){
                                $UnitInt->addChild("tag", $getUnitsData['unittag']);
                            }
                            if ($getUnitsData['comment'] != "") {
                                $UnitInt->addChild("comment");
                                $UnitInt->comment = $getUnitsData['comment'];
                            }
                            if ($getUnitsData['ipv6'] != "") {
                                $xml_append = simplexml_load_string(clean_xml($getUnitsData['ipv6']));
                                SimpleXMLElement_append($UnitInt, $xml_append);
                            }
                            if ($version>=7){
                                if ($getUnitsData['ndpproxy'] != "") {
                                    $xml_append = simplexml_load_string(clean_xml($getUnitsData['ndpproxy']));
                                    SimpleXMLElement_append($UnitInt, $xml_append);
                                }
                            }
                            if (($getUnitsData['mtu'] != "") AND ( $getUnitsData['mtu'] != "0")) {
                                $UnitInt->addChild("mtu", $getUnitsData['mtu']);
                            }
                            if (($getUnitsData['interface_management_profile'] != "") AND ( $getUnitsData['interface_management_profile'] != "None")) {
                                $UnitInt->addChild("interface-management-profile", $getUnitsData['interface_management_profile']);
                            }
                            if ($version>=7){
                                if ($getUnitsData['adjust_tcp_mss'] != "") {
                                    $UnitInt->addChild("adjust-tcp-mss");
                                    $UnitInt->{'adjust-tcp-mss'}->addChild("enable",$getUnitsData['adjust_tcp_mss']);
                                    if ($getUnitsData['ipv4_mss_adjustment']!=0){
                                        $UnitInt->{'adjust-tcp-mss'}->addChild("ipv4-mss-adjustment",$getUnitsData['ipv4_mss_adjustment']);
                                    }
                                    if ($getUnitsData['ipv6_mss_adjustment']!=0){
                                        $UnitInt->{'adjust-tcp-mss'}->addChild("ipv6-mss-adjustment",$getUnitsData['ipv6_mss_adjustment']);
                                    }
                                }
                            }
                            else{
                                if ($getUnitsData['adjust_tcp_mss'] != "") {
                                    $UnitInt->addChild("adjust-tcp-mss", $getUnitsData['adjust_tcp_mss']);
                                }
                            }

                            if ($getUnitsData['arp'] != "") {
                                $xml_append = simplexml_load_string(clean_xml($getUnitsData['arp']));
                                SimpleXMLElement_append($UnitInt, $xml_append);
                            }
                            if ($getUnitsData['ipv4_type'] == "static") {
                                if ($getUnitsData['unitipaddress'] != "") {
                                    $interfaces_all = explode(",", $getUnitsData['unitipaddress']);
                                    $UnitInt->addChild("ip");
                                    foreach ($interfaces_all as $key => $int_value) {
                                        $newInt = $UnitInt->ip->addChild("entry");
                                        $newInt->addAttribute('name', $int_value);
                                    }
                                }
                            } elseif ($getUnitsData['ipv4_type'] == "dhcp-client") {
                                $UnitInt->addChild("dhcp-client");

                                if ($getUnitsData['dhcp_client_enable'] == "no") {
                                    $UnitInt->{"dhcp-client"}->addChild("enable", "no");
                                }
                                if ($getUnitsData['dhcp_client_default_route_metric'] != "0") {
                                    $UnitInt->{"dhcp-client"}->addChild("default-route-metric", $getUnitsData['dhcp_client_default_route_metric']);
                                }
                                if ($getUnitsData['dhcp_client_create_default_route'] == "no") {
                                    $UnitInt->{"dhcp-client"}->addChild("create-default-route", "no");
                                }
                            }
                        }
                    }
                }
                elseif ($getIntEthernetData['type'] == "decrypt-mirror"){
                    $int->addChild("decrypt-mirror");
                }
                if ($getIntEthernetData['type'] == "aggregate-group"){
                    $int->addChild("aggregate-group",$getIntEthernetData['aggregate_group']);
                }
                if ($getIntEthernetData['type'] == "log-card") {
                    $xml_append = simplexml_load_string(clean_xml($getIntEthernetData['log_card']));
                    SimpleXMLElement_append($int, $xml_append);
                }

                if ($api_call=="single"){
                    $xpath2 = addslashes($data['xpath0']."/ethernet/entry[@name='$myname']");
                    $xml_final = addslashes($int->asXML());
                    $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','Interface Ethernet','Interface Ethernet','$xml_final','$xpath2','edit');");
                }

            }
            if ($api_call=="atomic"){
                $xpath2 = addslashes($data['xpath0']."/ethernet");
                $xml_final = addslashes($theINT->ethernet->asXML());
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Interfaces Ethernet $template_name','Interfaces Ethernet','Interfaces Ethernet','$xml_final','$xpath2','edit');");
            }
        }
        else{
            if ($api_call=="clean"){
                $xpath2 = addslashes($data['xpath0']."/ethernet");
                $xml_final = "";
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Remove All Interfaces Ethernet','Interfaces Ethernet','Interfaces Ethernet','$xml_final','$xpath2','delete');");
            }
        }

//    }
//    else{
//        $message['code'] = false;
//        $message['msg'] = "Invalid Template Id:$template";
//        return $message;
//    }
}

function xml_network_interface_aggregate_ethernet($xml,$data){
    $project = $data['project'];
    $ispanorama = $data['ispanorama'];
    $version = $data['version'];
    $api_call=$data['api_call'];
    $projectdb = $data['projectdb'];
    $source = $data['source'];
    $template = $data['template'];
    $template_name=$data['template_name'];

//    if ($template!=0) {
        if ($ispanorama == 0) {
            $data['xpath_parent'] = "/config/devices/entry[@name='localhost.localdomain']";
            $data['xpath_network'] = "/config/devices/entry[@name='localhost.localdomain']/network";
            $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/network/interface";
            $template_name="Device";
        } else {
            $data['xpath_parent'] = "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='" . $template_name . "']/config/devices/entry[@name='localhost.localdomain']";
            $data['xpath_network'] = "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='" . $template_name . "']/config/devices/entry[@name='localhost.localdomain']/network";
            $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='" . $template_name . "']/config/devices/entry[@name='localhost.localdomain']/network/interface";
        }
        $getIntEthernet = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='aggregate-ethernet' AND unittag='0' AND unitname=name GROUP BY name ORDER BY name");
        //echo "SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='aggregate-ethernet' AND unittag='0' AND unitname=name GROUP BY name ORDER BY name\n";
        if ($getIntEthernet->num_rows > 0) {
            if (!empty($xml->xpath($data['xpath0']."/aggregate-ethernet"))){
                $SA=$xml->xpath($data['xpath0']."/aggregate-ethernet");
                unset($SA[0][0]);
            }
            if(empty($xml->xpath($data['xpath_network']))){
                $myTemplateDeviceNetwork0 = $xml->xpath($data['xpath_parent']);
                $myTemplateDeviceNetwork = $myTemplateDeviceNetwork0[0]->addChild("network");
            }
            if (empty($xml->xpath($data['xpath0']))){
                $myTemplateDeviceNetwork0 = $xml->xpath($data['xpath_network']);
                $myTemplateDeviceNetwork0[0]->addChild("interface");
            }

            $myTemplateDeviceNetwork0=$xml->xpath($data['xpath_network']);
            $myTemplateDeviceNetwork=$myTemplateDeviceNetwork0[0];

            $theINT = $myTemplateDeviceNetwork->interface;
            $theINT->addChild("aggregate-ethernet");

            while ($getIntEthernetData = $getIntEthernet->fetch_assoc()) {
                $myname = $getIntEthernetData['name'];
                $int2 = $theINT->{'aggregate-ethernet'}->addChild('entry');
                $int2->addAttribute('name', $myname);

                if ($getIntEthernetData['comment'] != "") {
                    $int2->addChild("comment");
                    $int2->comment = $getIntEthernetData['comment'];
                }

                if ($getIntEthernetData['type'] == "virtual-wire") {

                    $int2->addChild("virtual-wire");
                    if ($getIntEthernetData['netflow_profile'] != "") {
                        $int2->{'virtual-wire'}->addChild("netflow-profile", $getIntEthernetData['netflow_profile']);
                    }

                    if ($version>=7){
                        if ($getIntEthernetData['lldp'] != "") {
                            $xml_append = simplexml_load_string(clean_xml($getIntEthernetData['lldp']));
                            SimpleXMLElement_append($int2->{'virtual-wire'}, $xml_append);
                        }
                    }
                    $getUnits = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='aggregate-ethernet' AND unitname!='$myname' AND name='$myname';");
                    if ($getUnits->num_rows > 0) {
                        $int2->{'virtual-wire'}->addChild("units");
                        while ($getUnitsData = $getUnits->fetch_assoc()) {
                            $myname1 = $getUnitsData['unitname'];
                            $VWUnit = $int2->{'virtual-wire'}->units->addChild('entry');
                            $VWUnit->addAttribute('name', $myname1);
                            if ($getUnitsData['comment'] != "") {
                                $VWUnit->addChild("comment");
                                $VWUnit->comment = $getUnitsData['comment'];
                            }
                            if ($getUnitsData['netflow_profile'] != "") {
                                $VWUnit->addChild("netflow-profile", $getUnitsData['netflow_profile']);
                            }

                            $VWUnit->addChild("tag", $getUnitsData['unittag']);

                            if ($getUnitsData['ip_classifier'] != "") {
                                $interfaces_all = explode(",", $getUnitsData['ip_classifier']);
                                $VWUnit->addChild("ip-classifier");
                                foreach ($interfaces_all as $key => $int_value) {
                                    $VWUnit->{'ip-classifier'}->addChild("member", $int_value);
                                }
                            }
                        }
                    }
                }
                if ($getIntEthernetData['type'] == "layer2") {
                    $int2->addChild("layer2");
                    if ($getIntEthernetData['netflow_profile'] != "") {
                        $int2->layer2->addChild("netflow-profile", $getIntEthernetData['netflow_profile']);
                    }
                    if ($version>=7){
                        if ($getIntEthernetData['lldp'] != "") {
                            $xml_append = simplexml_load_string(clean_xml($getIntEthernetData['lldp']));
                            SimpleXMLElement_append($int2->layer2, $xml_append);
                        }
                    }
                    $getUnits = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='aggregate-ethernet' AND unitname!='$myname' AND name='$myname';");
                    if ($getUnits->num_rows > 0) {
                        $int2->{'layer2'}->addChild("units");
                        while ($getUnitsData = $getUnits->fetch_assoc()) {
                            $myname1 = $getUnitsData['unitname'];
                            $VWUnit = $int2->{'layer2'}->units->addChild('entry');
                            $VWUnit->addAttribute('name', $myname1);
                            if ($getUnitsData['netflow_profile'] != "") {
                                $VWUnit->addChild("netflow-profile", $getUnitsData['netflow_profile']);
                            }
                            if ($getUnitsData['comment'] != "") {
                                $VWUnit->addChild("comment");
                                $VWUnit->comment = $getUnitsData['comment'];
                            }
                            $VWUnit->addChild("tag", $getUnitsData['unittag']);
                        }
                    }
                }
                elseif ($getIntEthernetData['type'] == "ha") {
                    $int2->addChild("ha");
                }
                elseif ($getIntEthernetData['type'] == "layer3") {
                    $int2->addChild("layer3");
                    if ($getIntEthernetData['netflow_profile'] != "") {
                        $int2->layer3->addChild("netflow-profile", $getIntEthernetData['netflow_profile']);
                    }
                    if (($getIntEthernetData['mtu'] != "") AND ( $getIntEthernetData['mtu'] != "0")) {
                        $int2->layer3->addChild("mtu", $getIntEthernetData['mtu']);
                    }
                    if (($getIntEthernetData['interface_management_profile'] != "") AND ( $getIntEthernetData['interface_management_profile'] != "None")) {
                        $int2->layer3->addChild("interface-management-profile", $getIntEthernetData['interface_management_profile']);
                    }

                    if ($getIntEthernetData['untagged_sub_interface'] != "") {
                        $int2->layer3->addChild("untagged-sub-interface", $getIntEthernetData['untagged_sub_interface']);
                    }
                    if ($getIntEthernetData['arp'] != "") {
                        $xml_append = simplexml_load_string(clean_xml($getIntEthernetData['arp']));
                        SimpleXMLElement_append($int2->layer3, $xml_append);
                    }
                    if ($version>=7){
                        if ($getIntEthernetData['lldp'] != "") {
                            $xml_append = simplexml_load_string(clean_xml($getIntEthernetData['lldp']));
                            SimpleXMLElement_append($int2->layer3, $xml_append);
                        }
                        if ($getIntEthernetData['ndpproxy'] != "") {
                            $xml_append = simplexml_load_string(clean_xml($getIntEthernetData['ndpproxy']));
                            SimpleXMLElement_append($int2->layer3, $xml_append);
                        }
                    }
                    if ($getIntEthernetData['ipv4_type'] == "static") {
                        if ($getIntEthernetData['ipv6'] != "") {
                            $xml_append = simplexml_load_string(clean_xml($getIntEthernetData['ipv6']));
                            SimpleXMLElement_append($int2->layer3, $xml_append);
                        }
                        if ($getIntEthernetData['unitipaddress'] != "") {
                            $interfaces_all = explode(",", $getIntEthernetData['unitipaddress']);
                            $int2->layer3->addChild("ip");
                            foreach ($interfaces_all as $key => $int_value) {
                                $newInt = $int2->layer3->ip->addChild("entry");
                                $newInt->addAttribute('name', $int_value);
                            }
                        }
                        //echo "La version: ".$version."\n";
                        if ($version >= 7){
                            //echo "adjunt_tcp_mss: " .$getIntEthernetData['adjust_tcp_mss']. "\n";
                            if ($getIntEthernetData['adjust_tcp_mss'] != "") {
                                $int2->layer3->addChild("adjust-tcp-mss");
                                $int2->layer3->{'adjust-tcp-mss'}->addChild("enable",$getIntEthernetData['adjust_tcp_mss']);
                                //echo "ipv4_mss_adjustment: " .$getIntEthernetData['ipv4_mss_adjustment']. "\n";
                                if ($getIntEthernetData['ipv4_mss_adjustment']!=0){
                                    $int2->layer3->{'adjust-tcp-mss'}->addChild("ipv4-mss-adjustment",$getIntEthernetData['ipv4_mss_adjustment']);
                                }
                                if ($getIntEthernetData['ipv6_mss_adjustment']!=0){
                                    $int2->layer3->{'adjust-tcp-mss'}->addChild("ipv6-mss-adjustment",$getIntEthernetData['ipv6_mss_adjustment']);
                                }
                            }
                        }
                        else{
                            if ($getIntEthernetData['adjust_tcp_mss'] != "") {
                                $int2->layer3->addChild("adjust-tcp-mss", $getIntEthernetData['adjust_tcp_mss']);
                            }
                        }
                    }
                    elseif ($getIntEthernetData['ipv4_type'] == "dhcp-client") {
                        $int2->layer3->addChild("dhcp-client");
                        if ($getIntEthernetData['ipv6'] != "") {
                            $xml_append = simplexml_load_string(clean_xml($getIntEthernetData['ipv6']));
                            SimpleXMLElement_append($int2->layer3, $xml_append);
                        }
                        if ($getIntEthernetData['dhcp_client_enable'] == "no") {
                            $int2->layer3->{"dhcp-client"}->addChild("enable", "no");
                        }
                        if ($getIntEthernetData['dhcp_client_default_route_metric'] != "0") {
                            $int2->layer3->{"dhcp-client"}->addChild("default-route-metric", $getIntEthernetData['dhcp_client_default_route_metric']);
                        }
                        if ($getIntEthernetData['dhcp_client_create_default_route'] == "no") {
                            $int2->layer3->{"dhcp-client"}->addChild("create-default-route", "no");
                        }
                        if ($version>=7){
                            if ($getIntEthernetData['adjust_tcp_mss'] != "") {
                                $int2->layer3->addChild("adjust-tcp-mss");
                                $int2->layer3->{'adjust-tcp-mss'}->addChild("enable",$getIntEthernetData['adjust_tcp_mss']);
                                if ($getIntEthernetData['ipv4_mss_adjustment']!=0){
                                    $int2->layer3->{'adjust-tcp-mss'}->addChild("ipv4-mss-adjustment",$getIntEthernetData['ipv4_mss_adjustment']);
                                }
                                if ($getIntEthernetData['ipv6_mss_adjustment']!=0){
                                    $int2->layer3->{'adjust-tcp-mss'}->addChild("ipv6-mss-adjustment",$getIntEthernetData['ipv6_mss_adjustment']);
                                }
                            }
                        }
                        else{
                            if ($getIntEthernetData['adjust_tcp_mss'] != "") {
                                $int2->layer3->addChild("adjust-tcp-mss", $getIntEthernetData['adjust_tcp_mss']);
                            }
                        }
                    }
                    # UNITS
                    $queryUnits = "SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='aggregate-ethernet' AND unitname!='$myname' AND name='$myname';";
                    //echo "Query units: ". $queryUnits."\n";
                    $getUnits = $projectdb->query($queryUnits);
                    if ($getUnits->num_rows > 0) {
                        $unit = $int2->layer3->addChild("units");
                        while ($getUnitsData = $getUnits->fetch_assoc()) {
                            $myname1 = $getUnitsData['unitname'];
                            $UnitInt = $unit->addChild('entry');
                            $UnitInt->addAttribute('name', $myname1);
                            if ($getUnitsData['netflow_profile'] != "") {
                                $UnitInt->addChild("netflow-profile", $getUnitsData['netflow_profile']);
                            }
                            if ($getUnitsData['unittag']!=0){
                                $UnitInt->addChild("tag", $getUnitsData['unittag']);
                            }
                            if ($getUnitsData['comment'] != "") {
                                $UnitInt->addChild("comment");
                                $UnitInt->comment = $getUnitsData['comment'];
                            }

                            if ($version>=7){
                                if ($getUnitsData['ndpproxy'] != "") {
                                    $xml_append = simplexml_load_string(clean_xml($getUnitsData['ndpproxy']));
                                    SimpleXMLElement_append($UnitInt, $xml_append);
                                }
                            }
                            if ($getUnitsData['ipv6'] != "") {
                                $xml_append = simplexml_load_string(clean_xml($getUnitsData['ipv6']));
                                SimpleXMLElement_append($UnitInt, $xml_append);
                            }
                            if (($getUnitsData['mtu'] != "") AND ( $getUnitsData['mtu'] != "0")) {
                                $UnitInt->addChild("mtu", $getUnitsData['mtu']);
                            }
                            if (($getUnitsData['interface_management_profile'] != "") AND ( $getUnitsData['interface_management_profile'] != "None")) {
                                $UnitInt->addChild("interface-management-profile", $getUnitsData['interface_management_profile']);
                            }

                            //echo "Version2: ".$version. "\n";
                            if ($version>=7){
                                //echo "adjust_tcp_mss2: ".$getUnitsData['adjust_tcp_mss']."\n";
                                if ($getUnitsData['adjust_tcp_mss'] != "") {
                                    $UnitInt->addChild("adjust-tcp-mss");
                                    $UnitInt->{'adjust-tcp-mss'}->addChild("enable",$getUnitsData['adjust_tcp_mss']);
                                    //echo "ipv4_mss_adjustment: " .$getUnitsData['ipv4_mss_adjustment']. "\n";
                                    if ($getUnitsData['ipv4_mss_adjustment']!=0){
                                        $UnitInt->{'adjust-tcp-mss'}->addChild("ipv4-mss-adjustment",$getUnitsData['ipv4_mss_adjustment']);
                                    }
                                    if ($getUnitsData['ipv6_mss_adjustment']!=0){
                                        $UnitInt->{'adjust-tcp-mss'}->addChild("ipv6-mss-adjustment",$getUnitsData['ipv6_mss_adjustment']);
                                    }
                                }
                            }
                            else{
                                if ($getUnitsData['adjust_tcp_mss'] != "") {
                                    $UnitInt->addChild("adjust-tcp-mss", $getUnitsData['adjust_tcp_mss']);
                                }
                            }
                            if ($getUnitsData['arp'] != "") {
                                $xml_append = simplexml_load_string(clean_xml($getUnitsData['arp']));
                                SimpleXMLElement_append($UnitInt, $xml_append);
                            }
                            if ($getUnitsData['ipv4_type'] == "static") {
                                if ($getUnitsData['unitipaddress'] != "") {
                                    $interfaces_all = explode(",", $getUnitsData['unitipaddress']);
                                    $UnitInt->addChild("ip");
                                    foreach ($interfaces_all as $key => $int_value) {
                                        $newInt = $UnitInt->ip->addChild("entry");
                                        $newInt->addAttribute('name', $int_value);
                                    }
                                }
                            } elseif ($getUnitsData['ipv4_type'] == "dhcp-client") {
                                $UnitInt->addChild("dhcp-client");

                                if ($getUnitsData['dhcp_client_enable'] == "no") {
                                    $UnitInt->{"dhcp-client"}->addChild("enable", "no");
                                }
                                if ($getUnitsData['dhcp_client_default_route_metric'] != "0") {
                                    $UnitInt->{"dhcp-client"}->addChild("default-route-metric", $getUnitsData['dhcp_client_default_route_metric']);
                                }
                                if ($getUnitsData['dhcp_client_create_default_route'] == "no") {
                                    $UnitInt->{"dhcp-client"}->addChild("create-default-route", "no");
                                }
                            }
                        }
                    }
                }
                elseif ($getIntEthernetData['type'] == "decrypt-mirror"){
                    $int2->addChild("decrypt-mirror");
                }
                if ($getIntEthernetData['lacp'] != "") {
                    $xml_append = simplexml_load_string(clean_xml($getIntEthernetData['lacp']));
                    SimpleXMLElement_append($int2->{$getIntEthernetData['type']}, $xml_append);
                }

                if ($api_call=="single"){
                    $xpath2 = addslashes($data['xpath0']."/aggregate-ethernet/entry[@name='$myname']");
                    $xml_final = addslashes($int2->asXML());
                    $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','Interface Aggregate Ethernet','Interface Aggregate Ethernet','$xml_final','$xpath2','edit');");
                }
            }
            if ($api_call=="atomic"){
                $xpath2 = addslashes($data['xpath0']."/aggregate-ethernet");
                $xml_final = addslashes($theINT->{'aggregate-ethernet'}->asXML());
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Interfaces Aggregate Ethernet $template_name','Interfaces Aggregate Ethernet','Interfaces Aggregate Ethernet','$xml_final','$xpath2','edit');");
            }
        }
        else{
            if ($api_call=="clean"){
                $xpath2 = addslashes($data['xpath0']."/aggregate-ethernet");
                $xml_final = "";
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Remove All Interfaces Aggregate Ethernet','Interfaces Aggregate Ethernet','Interfaces Aggregate Ethernet','$xml_final','$xpath2','delete');");
            }
        }
//    }
//    else{
//        $message['code'] = false;
//        $message['msg'] = "Invalid Template Id:$template";
//        return $message;
//    }
}

function xml_network_interface_vlan($xml,$data){
    $project = $data['project'];
    $ispanorama = $data['ispanorama'];
    $version = $data['version'];
    $api_call=$data['api_call'];
    $projectdb = $data['projectdb'];
    $source = $data['source'];
    $template = $data['template'];
    $template_name=$data['template_name'];

//    if ($template!=0) {
        if ($ispanorama == 0) {
            $data['xpath_parent'] = "/config/devices/entry[@name='localhost.localdomain']";
            $data['xpath_network'] = "/config/devices/entry[@name='localhost.localdomain']/network";
            $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/network/interface";
            $template_name="Device";
        }
        else {
            $data['xpath_parent'] = "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='" . $template_name . "']/config/devices/entry[@name='localhost.localdomain']";
            $data['xpath_network'] = "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='" . $template_name . "']/config/devices/entry[@name='localhost.localdomain']/network";
            $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='" . $template_name . "']/config/devices/entry[@name='localhost.localdomain']/network/interface";
        }
        $getIntEthernet = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='vlan' AND name='vlan' GROUP BY name ORDER BY name");
        if ($getIntEthernet->num_rows > 0) {
            if (!empty($xml->xpath($data['xpath0']."/vlan"))){
                $SA=$xml->xpath($data['xpath0']."/vlan");
                unset($SA[0][0]);
            }
            if(empty($xml->xpath($data['xpath_network']))){
                $myTemplateDeviceNetwork0 = $xml->xpath($data['xpath_parent']);
                $myTemplateDeviceNetwork = $myTemplateDeviceNetwork0[0]->addChild("network");
            }
            if (empty($xml->xpath($data['xpath0']))){
                $myTemplateDeviceNetwork0 = $xml->xpath($data['xpath_network']);
                $myTemplateDeviceNetwork0[0]->addChild("interface");
            }

            $myTemplateDeviceNetwork0=$xml->xpath($data['xpath_network']);
            $myTemplateDeviceNetwork=$myTemplateDeviceNetwork0[0];

            $theINT = $myTemplateDeviceNetwork->interface;
            $vlanint = $theINT->addChild("vlan");
            while ($getIntEthernetData = $getIntEthernet->fetch_assoc()) {
                if ($getIntEthernetData['ipv6'] != "") {
                    $xml_append = simplexml_load_string(clean_xml($getIntEthernetData['ipv6']));
                    SimpleXMLElement_append($vlanint, $xml_append);
                }
                if (($getIntEthernetData['mtu'] != "") AND ( $getIntEthernetData['mtu'] != "0")) {
                    $vlanint->addChild("mtu", $getIntEthernetData['mtu']);
                }
                if ($version>=7){
                    if ($getIntEthernetData['adjust_tcp_mss'] != "") {
                        $vlanint->addChild("adjust-tcp-mss");
                        $vlanint->{'adjust-tcp-mss'}->addChild("enable",$getIntEthernetData['adjust_tcp_mss']);
                        if ($getIntEthernetData['ipv4_mss_adjustment']!=0){
                            $vlanint->{'adjust-tcp-mss'}->addChild("ipv4-mss-adjustment",$getIntEthernetData['ipv4_mss_adjustment']);
                        }
                        if ($getIntEthernetData['ipv6_mss_adjustment']!=0){
                            $vlanint->{'adjust-tcp-mss'}->addChild("ipv6-mss-adjustment",$getIntEthernetData['ipv6_mss_adjustment']);
                        }
                    }
                }
                else{
                    if ($getIntEthernetData['adjust_tcp_mss'] != "") {
                        $vlanint->addChild("adjust-tcp-mss", $getIntEthernetData['adjust_tcp_mss']);
                    }
                }
                if (($getIntEthernetData['interface_management_profile'] != "") AND ( $getIntEthernetData['interface_management_profile'] != "None")) {
                    $vlanint->addChild("interface-management-profile", $getIntEthernetData['interface_management_profile']);
                }
                if ($getIntEthernetData['arp'] != "") {
                    $xml_append = simplexml_load_string(clean_xml($getIntEthernetData['arp']));
                    SimpleXMLElement_append($vlanint, $xml_append);
                }
                if ($version>=7){
                    if ($getIntEthernetData['ndpproxy'] != "") {
                        $xml_append = simplexml_load_string(clean_xml($getIntEthernetData['ndpproxy']));
                        SimpleXMLElement_append($vlanint, $xml_append);
                    }
                }
                if ($getIntEthernetData['comment'] != "") {
                    $vlanint->addChild("comment");
                    $vlanint->comment = $getIntEthernetData['comment'];
                }
                if ($getIntEthernetData['ipv4_type'] == "static") {
                    if ($getIntEthernetData['unitipaddress'] != "") {
                        $interfaces_all = explode(",", $getIntEthernetData['unitipaddress']);
                        $vlanint->addChild("ip");
                        foreach ($interfaces_all as $key => $int_value) {
                            $newInt = $vlanint->ip->addChild("entry");
                            $newInt->addAttribute('name', $int_value);
                        }
                    }
                } elseif ($getIntEthernetData['ipv4_type'] == "dhcp-client") {
                    $vlanint->addChild("dhcp-client");
                    if ($getIntEthernetData['dhcp_client_enable'] == "no") {
                        $vlanint->{"dhcp-client"}->addChild("enable", "no");
                    }
                    if ($getIntEthernetData['dhcp_client_default_route_metric'] != "0") {
                        $vlanint->{"dhcp-client"}->addChild("default-route-metric", $getIntEthernetData['dhcp_client_default_route_metric']);
                    }
                    if ($getIntEthernetData['dhcp_client_create_default_route'] == "no") {
                        $vlanint->{"dhcp-client"}->addChild("create-default-route", "no");
                    }
                }
                $getUnits = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='vlan' AND unitname!='vlan';");
                if ($getUnits->num_rows > 0) {
                    $vlanint->addChild("units");
                    while ($getUnitsData = $getUnits->fetch_assoc()) {
                        $myname1 = $getUnitsData['unitname'];
                        $UnitInt = $vlanint->units->addChild('entry');
                        $UnitInt->addAttribute('name', $myname1);
                        if ($getUnitsData['ipv6'] != "") {
                            $xml_append = simplexml_load_string(clean_xml($getUnitsData['ipv6']));
                            SimpleXMLElement_append($UnitInt, $xml_append);
                        }
                        if (($getUnitsData['mtu'] != "") AND ( $getUnitsData['mtu'] != "0")) {
                            $UnitInt->addChild("mtu", $getUnitsData['mtu']);
                        }
                        if ($version>=7){
                            if ($getUnitsData['adjust_tcp_mss'] != "") {
                                $UnitInt->addChild("adjust-tcp-mss");
                                $UnitInt->{'adjust-tcp-mss'}->addChild("enable",$getUnitsData['adjust_tcp_mss']);
                                if ($getUnitsData['ipv4_mss_adjustment']!=0){
                                    $UnitInt->{'adjust-tcp-mss'}->addChild("ipv4-mss-adjustment",$getUnitsData['ipv4_mss_adjustment']);
                                }
                                if ($getUnitsData['ipv6_mss_adjustment']!=0){
                                    $UnitInt->{'adjust-tcp-mss'}->addChild("ipv6-mss-adjustment",$getUnitsData['ipv6_mss_adjustment']);
                                }
                            }
                        }
                        else{
                            if ($getUnitsData['adjust_tcp_mss'] != "") {
                                $UnitInt->addChild("adjust-tcp-mss", $getUnitsData['adjust_tcp_mss']);
                            }
                        }

                        if ($getUnitsData['comment'] != "") {
                            $UnitInt->addChild("comment");
                            $UnitInt->comment = $getUnitsData['comment'];
                        }
                        if (($getUnitsData['interface_management_profile'] != "") AND ( $getUnitsData['interface_management_profile'] != "None")) {
                            $UnitInt->addChild("interface-management-profile", $getUnitsData['interface_management_profile']);
                        }
                        if ($getUnitsData['arp'] != "") {
                            $xml_append = simplexml_load_string(clean_xml($getUnitsData['arp']));
                            SimpleXMLElement_append($UnitInt, $xml_append);
                        }
                        if ($getUnitsData['ipv4_type'] == "static") {
                            if ($getUnitsData['unitipaddress'] != "") {
                                $interfaces_all = explode(",", $getUnitsData['unitipaddress']);
                                $UnitInt->addChild("ip");
                                foreach ($interfaces_all as $key => $int_value) {
                                    $newInt = $UnitInt->ip->addChild("entry");
                                    $newInt->addAttribute('name', $int_value);
                                }
                            }
                        } elseif ($getUnitsData['ipv4_type'] == "dhcp-client") {
                            $UnitInt->addChild("dhcp-client");
                            if ($getUnitsData['dhcp_client_enable'] == "no") {
                                $UnitInt->{"dhcp-client"}->addChild("enable", "no");
                            }
                            if ($getUnitsData['dhcp_client_default_route_metric'] != "0") {
                                $UnitInt->{"dhcp-client"}->addChild("default-route-metric", $getUnitsData['dhcp_client_default_route_metric']);
                            }
                            if ($getUnitsData['dhcp_client_create_default_route'] == "no") {
                                $UnitInt->{"dhcp-client"}->addChild("create-default-route", "no");
                            }
                        }
                    }
                }

            }
            if (($api_call=="single") OR ($api_call=="atomic")){
                $xpath2 = addslashes($data['xpath0']."/vlan");
                $xml_final = addslashes($vlanint->asXML());
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('vlan','Interface vlan','Interface vlan','$xml_final','$xpath2','edit');");
            }
        }
        else{
            if ($api_call=="clean"){
                $xpath2 = addslashes($data['xpath0']);
                $xml_final = "<vlan/>";
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Remove All Interfaces vlan','Interfaces vlan','Interfaces vlan','$xml_final','$xpath2','set');");
            }
        }
//    }
//    else{
//        $message['code'] = false;
//        $message['msg'] = "Invalid Template Id:$template";
//        return $message;
//    }
}

function xml_network_interface_loopback($xml,$data){
    $project = $data['project'];
    $ispanorama = $data['ispanorama'];
    $version = $data['version'];
    $api_call=$data['api_call'];
    $projectdb = $data['projectdb'];
    $source = $data['source'];
    $template = $data['template'];
    $template_name=$data['template_name'];

//    if ($template!=0) {
        if ($ispanorama == 0) {
            $data['xpath_parent'] = "/config/devices/entry[@name='localhost.localdomain']";
            $data['xpath_network'] = "/config/devices/entry[@name='localhost.localdomain']/network";
            $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/network/interface";
            $template_name="Device";
        }
        else {
            $data['xpath_parent'] = "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='" . $template_name . "']/config/devices/entry[@name='localhost.localdomain']";
            $data['xpath_network'] = "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='" . $template_name . "']/config/devices/entry[@name='localhost.localdomain']/network";
            $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='" . $template_name . "']/config/devices/entry[@name='localhost.localdomain']/network/interface";
        }

        $getIntEthernet = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='loopback' AND name='loopback' GROUP BY name ORDER BY name");
        if ($getIntEthernet->num_rows > 0) {
            if (!empty($xml->xpath($data['xpath0']."/loopback"))){
                $SA=$xml->xpath($data['xpath0']."/loopback");
                unset($SA[0][0]);
            }
            if(empty($xml->xpath($data['xpath_network']))){
                $myTemplateDeviceNetwork0 = $xml->xpath($data['xpath_parent']);
                $myTemplateDeviceNetwork = $myTemplateDeviceNetwork0[0]->addChild("network");
            }
            if (empty($xml->xpath($data['xpath0']))){
                $myTemplateDeviceNetwork0 = $xml->xpath($data['xpath_network']);
                $myTemplateDeviceNetwork0[0]->addChild("interface");
            }

            $myTemplateDeviceNetwork0=$xml->xpath($data['xpath_network']);
            $myTemplateDeviceNetwork=$myTemplateDeviceNetwork0[0];

            $theINT = $myTemplateDeviceNetwork->interface;
            $loopackint = $theINT->addChild("loopback");
            while ($getIntEthernetData = $getIntEthernet->fetch_assoc()) {
                if ($getIntEthernetData['ipv6'] != "") {
                    $xml_append = simplexml_load_string(clean_xml($getIntEthernetData['ipv6']));
                    SimpleXMLElement_append($loopackint, $xml_append);
                }
                if (($getIntEthernetData['mtu'] != "") AND ( $getIntEthernetData['mtu'] != "0")) {
                    $loopackint->addChild("mtu", $getIntEthernetData['mtu']);
                }
                if ($version>=7){
                    if ($getIntEthernetData['adjust_tcp_mss'] != "") {
                        $loopackint->addChild("adjust-tcp-mss");
                        $loopackint->{'adjust-tcp-mss'}->addChild("enable",$getIntEthernetData['adjust_tcp_mss']);
                        if ($getIntEthernetData['ipv4_mss_adjustment']!=0){
                            $loopackint->{'adjust-tcp-mss'}->addChild("ipv4-mss-adjustment",$getIntEthernetData['ipv4_mss_adjustment']);
                        }
                        if ($getIntEthernetData['ipv6_mss_adjustment']!=0){
                            $loopackint->{'adjust-tcp-mss'}->addChild("ipv6-mss-adjustment",$getIntEthernetData['ipv6_mss_adjustment']);
                        }
                    }
                }
                else{
                    if ($getIntEthernetData['adjust_tcp_mss'] != "") {
                        $loopackint->addChild("adjust-tcp-mss", $getIntEthernetData['adjust_tcp_mss']);
                    }
                }

                if (($getIntEthernetData['interface_management_profile'] != "") AND ( $getIntEthernetData['interface_management_profile'] != "None")) {
                    $loopackint->addChild("interface-management-profile", $getIntEthernetData['interface_management_profile']);
                }
                if ($getIntEthernetData['comment'] != "") {
                    $loopackint->addChild("comment");
                    $loopackint->comment = $getIntEthernetData['comment'];
                }
                if ($getIntEthernetData['ipv4_type'] == "static") {
                    if ($getIntEthernetData['unitipaddress'] != "") {
                        $interfaces_all = explode(",", $getIntEthernetData['unitipaddress']);
                        $loopackint->addChild("ip");
                        foreach ($interfaces_all as $key => $int_value) {
                            $newInt = $loopackint->ip->addChild("entry");
                            $newInt->addAttribute('name', $int_value);
                        }
                    }
                }
                $getUnits = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='loopback' AND unitname!='loopback';");
                if ($getUnits->num_rows > 0) {
                    $unit = $loopackint->addChild("units");
                    while ($getUnitsData = $getUnits->fetch_assoc()) {
                        $myname1 = $getUnitsData['unitname'];
                        $UnitInt = $unit->addChild('entry');
                        $UnitInt->addAttribute('name', $myname1);
                        if ($getUnitsData['ipv6'] != "") {
                            $xml_append = simplexml_load_string(clean_xml($getUnitsData['ipv6']));
                            SimpleXMLElement_append($UnitInt, $xml_append);
                        }
                        if (($getUnitsData['mtu'] != "") AND ( $getUnitsData['mtu'] != "0")) {
                            $UnitInt->addChild("mtu", $getUnitsData['mtu']);
                        }
                        if ($getUnitsData['comment'] != "") {
                            $UnitInt->addChild("comment");
                            $UnitInt->comment = $getUnitsData['comment'];
                        }
                        if ($version>=7){
                            if ($getUnitsData['adjust_tcp_mss'] != "") {
                                $UnitInt->addChild("adjust-tcp-mss");
                                $UnitInt->{'adjust-tcp-mss'}->addChild("enable",$getUnitsData['adjust_tcp_mss']);
                                if ($getUnitsData['ipv4_mss_adjustment']!=0){
                                    $UnitInt->{'adjust-tcp-mss'}->addChild("ipv4-mss-adjustment",$getUnitsData['ipv4_mss_adjustment']);
                                }
                                if ($getUnitsData['ipv6_mss_adjustment']!=0){
                                    $UnitInt->{'adjust-tcp-mss'}->addChild("ipv6-mss-adjustment",$getUnitsData['ipv6_mss_adjustment']);
                                }
                            }
                        }
                        else{
                            if ($getUnitsData['adjust_tcp_mss'] != "") {
                                $UnitInt->addChild("adjust-tcp-mss", $getUnitsData['adjust_tcp_mss']);
                            }
                        }
                        if (($getUnitsData['interface_management_profile'] != "") AND ( $getUnitsData['interface_management_profile'] != "None")) {
                            $UnitInt->addChild("interface-management-profile", $getUnitsData['interface_management_profile']);
                        }
                        if ($getUnitsData['ipv4_type'] == "static") {
                            if ($getUnitsData['unitipaddress'] != "") {
                                $interfaces_all = explode(",", $getUnitsData['unitipaddress']);
                                $UnitInt->addChild("ip");
                                foreach ($interfaces_all as $key => $int_value) {
                                    $newInt = $UnitInt->ip->addChild("entry");
                                    $newInt->addAttribute('name', $int_value);
                                }
                            }
                        }
                    }
                }


            }
            if (($api_call=="single") OR ($api_call=="atomic")){
                $xpath2 = addslashes($data['xpath0']."/loopback");
                $xml_final = addslashes($loopackint->asXML());
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('loopback','Interface loopback','Interface loopback','$xml_final','$xpath2','edit');");
            }
        }
        else{
            if ($api_call=="clean"){
                $xpath2 = addslashes($data['xpath0']);
                $xml_final = "<loopback/>";
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Remove All Interfaces loopback','Interfaces loopback','Interfaces loopback','$xml_final','$xpath2','set');");
            }
        }
//    }
//    else{
//        $message['code'] = false;
//        $message['msg'] = "Invalid Template Id:$template";
//        return $message;
//    }
}

function xml_network_interface_tunnel($xml,$data){
    $project = $data['project'];
    $ispanorama = $data['ispanorama'];
    $version = $data['version'];
    $api_call=$data['api_call'];
    $projectdb = $data['projectdb'];
    $source = $data['source'];
    $template = $data['template'];
    $template_name=$data['template_name'];

//    if ($template!=0) {
        if ($ispanorama == 0) {
            $data['xpath_parent'] = "/config/devices/entry[@name='localhost.localdomain']";
            $data['xpath_network'] = "/config/devices/entry[@name='localhost.localdomain']/network";
            $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/network/interface";
            $template_name="Device";
        }
        else {
            $data['xpath_parent'] = "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='" . $template_name . "']/config/devices/entry[@name='localhost.localdomain']";
            $data['xpath_network'] = "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='" . $template_name . "']/config/devices/entry[@name='localhost.localdomain']/network";
            $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='" . $template_name . "']/config/devices/entry[@name='localhost.localdomain']/network/interface";
        }

        $getIntEthernet = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='tunnel' AND name='tunnel' GROUP BY name ORDER BY name");
        if ($getIntEthernet->num_rows > 0) {
            if (!empty($xml->xpath($data['xpath0']."/tunnel"))){
                $SA=$xml->xpath($data['xpath0']."/tunnel");
                unset($SA[0][0]);
            }
            if(empty($xml->xpath($data['xpath_network']))){
                $myTemplateDeviceNetwork0 = $xml->xpath($data['xpath_parent']);
                $myTemplateDeviceNetwork = $myTemplateDeviceNetwork0[0]->addChild("network");
            }
            if (empty($xml->xpath($data['xpath0']))){
                $myTemplateDeviceNetwork0 = $xml->xpath($data['xpath_network']);
                $myTemplateDeviceNetwork0[0]->addChild("interface");
            }

            $myTemplateDeviceNetwork0=$xml->xpath($data['xpath_network']);
            $myTemplateDeviceNetwork=$myTemplateDeviceNetwork0[0];

            $theINT = $myTemplateDeviceNetwork->interface;
            $tunnelint = $theINT->addChild("tunnel");
            while ($getIntEthernetData = $getIntEthernet->fetch_assoc()) {
                if ($getIntEthernetData['ipv6'] != "") {
                    $xml_append = simplexml_load_string(clean_xml($getIntEthernetData['ipv6']));
                    SimpleXMLElement_append($tunnelint, $xml_append);
                }
                if (($getIntEthernetData['mtu'] != "") AND ( $getIntEthernetData['mtu'] != "0")) {
                    $tunnelint->addChild("mtu", $getIntEthernetData['mtu']);
                }
//                if ($version>=7){
//                    if ($getIntEthernetData['adjust_tcp_mss'] != "") {
//                        $tunnelint->addChild("adjust-tcp-mss");
//                        $tunnelint->{'adjust-tcp-mss'}->addChild("enable",$getIntEthernetData['adjust_tcp_mss']);
//                        if ($getIntEthernetData['ipv4_mss_adjustment']!=0){
//                            $tunnelint->{'adjust-tcp-mss'}->addChild("ipv4-mss-adjustment",$getIntEthernetData['ipv4_mss_adjustment']);
//                        }
//                        if ($getIntEthernetData['ipv6_mss_adjustment']!=0){
//                            $tunnelint->{'adjust-tcp-mss'}->addChild("ipv6-mss-adjustment",$getIntEthernetData['ipv6_mss_adjustment']);
//                        }
//                    }
//                }
//                else{
//                    if ($getIntEthernetData['adjust_tcp_mss'] != "") {
//                        $tunnelint->addChild("adjust-tcp-mss", $getIntEthernetData['adjust_tcp_mss']);
//                    }
//                }
                if (($getIntEthernetData['interface_management_profile'] != "") AND ( $getIntEthernetData['interface_management_profile'] != "None")) {
                    $tunnelint->addChild("interface-management-profile", $getIntEthernetData['interface_management_profile']);
                }
                if ($getIntEthernetData['comment'] != "") {
                    $tunnelint->addChild("comment");
                    $tunnelint->comment = $getIntEthernetData['comment'];
                }
                if ($getIntEthernetData['ipv4_type'] == "static") {
                    if ($getIntEthernetData['unitipaddress'] != "") {
                        $interfaces_all = explode(",", $getIntEthernetData['unitipaddress']);
                        $tunnelint->addChild("ip");
                        foreach ($interfaces_all as $key => $int_value) {
                            $newInt = $tunnelint->ip->addChild("entry");
                            $newInt->addAttribute('name', $int_value);
                        }
                    }
                }
                $getUnits = $projectdb->query("SELECT * FROM interfaces WHERE template='$template' AND source='$source' AND media='tunnel' AND unitname!='tunnel';");
                if ($getUnits->num_rows > 0) {
                    $unit = $tunnelint->addChild("units");
                    while ($getUnitsData = $getUnits->fetch_assoc()) {
                        $myname1 = $getUnitsData['unitname'];
                        $UnitInt = $unit->addChild('entry');
                        $UnitInt->addAttribute('name', $myname1);
                        if ($getUnitsData['ipv6'] != "") {
                            $xml_append = simplexml_load_string(clean_xml($getUnitsData['ipv6']));
                            SimpleXMLElement_append($UnitInt, $xml_append);
                        }
                        if (($getUnitsData['mtu'] != "") AND ( $getUnitsData['mtu'] != "0")) {
                            $UnitInt->addChild("mtu", $getUnitsData['mtu']);
                        }
                        if ($getUnitsData['comment'] != "") {
                            $UnitInt->addChild("comment");
                            $UnitInt->comment = $getUnitsData['comment'];
                        }
//                        if ($version>=7){
//                            if ($getUnitsData['adjust_tcp_mss'] != "") {
//                                $UnitInt->addChild("adjust-tcp-mss");
//                                $UnitInt->{'adjust-tcp-mss'}->addChild("enable",$getUnitsData['adjust_tcp_mss']);
//                                if ($getUnitsData['ipv4_mss_adjustment']!=0){
//                                    $UnitInt->{'adjust-tcp-mss'}->addChild("ipv4-mss-adjustment",$getUnitsData['ipv4_mss_adjustment']);
//                                }
//                                if ($getUnitsData['ipv6_mss_adjustment']!=0){
//                                    $UnitInt->{'adjust-tcp-mss'}->addChild("ipv6-mss-adjustment",$getUnitsData['ipv6_mss_adjustment']);
//                                }
//                            }
//                        }
//                        else{
//                            if ($getUnitsData['adjust_tcp_mss'] != "") {
//                                $UnitInt->addChild("adjust-tcp-mss", $getUnitsData['adjust_tcp_mss']);
//                            }
//                        }
                        if (($getUnitsData['interface_management_profile'] != "") AND ( $getUnitsData['interface_management_profile'] != "None")) {
                            $UnitInt->addChild("interface-management-profile", $getUnitsData['interface_management_profile']);
                        }
                        if ($getUnitsData['ipv4_type'] == "static") {
                            if ($getUnitsData['unitipaddress'] != "") {
                                $interfaces_all = explode(",", $getUnitsData['unitipaddress']);
                                $UnitInt->addChild("ip");
                                foreach ($interfaces_all as $key => $int_value) {
                                    $newInt = $UnitInt->ip->addChild("entry");
                                    $newInt->addAttribute('name', $int_value);
                                }
                            }
                        }
                    }
                }

            }
            if (($api_call=="single") OR ($api_call=="atomic")){
                $xpath2 = addslashes($data['xpath0']."/tunnel");
                $xml_final = addslashes($tunnelint->asXML());
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('tunnel','Interface tunnel','Interface tunnel','$xml_final','$xpath2','edit');");
            }
        }
        else{
            if ($api_call=="clean"){
                $xpath2 = addslashes($data['xpath0']);
                $xml_final = "<tunnel/>";
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Remove All Interfaces tunnel','Interfaces tunnel','Interfaces tunnel','$xml_final','$xpath2','set');");
            }
        }
//    }
//    else{
//        $message['code'] = false;
//        $message['msg'] = "Invalid Template Id:$template";
//        return $message;
//    }
}

function xml_virtual_routers($xml,$data){
    $project = $data['project'];
    $ispanorama = $data['ispanorama'];
    $version = $data['version'];
    $api_call=$data['api_call'];
    $projectdb = $data['projectdb'];
    $source = $data['source'];
    $template = $data['template'];
    $template_name=$data['template_name'];

//    if ($template!=0) {
        if ($ispanorama == 0) {
            $data['xpath_parent'] = "/config/devices/entry[@name='localhost.localdomain']";
            $data['xpath_network'] = "/config/devices/entry[@name='localhost.localdomain']/network";
            $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/network/virtual-router";
            $template_name="Device";
        }
        else {
            $data['xpath_parent'] = "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='" . $template_name . "']/config/devices/entry[@name='localhost.localdomain']";
            $data['xpath_network'] = "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='" . $template_name . "']/config/devices/entry[@name='localhost.localdomain']/network";
            $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='" . $template_name . "']/config/devices/entry[@name='localhost.localdomain']/network/virtual-router";
        }

        $getVR = $projectdb->query("SELECT * FROM virtual_routers WHERE source='$source' AND template='$template';");
        //echo "1. SELECT * FROM virtual_routers WHERE source='$source' AND template='$template';\n";
        if ($getVR->num_rows > 0) {
            if (!empty($xml->xpath($data['xpath0']))){
                $SA=$xml->xpath($data['xpath0']);
                unset($SA[0][0]);
            }
            if(empty($xml->xpath($data['xpath_network']))){
                $myTemplateDeviceNetwork0 = $xml->xpath($data['xpath_parent']);
                $myTemplateDeviceNetwork = $myTemplateDeviceNetwork0[0]->addChild("network");
            }
            if (empty($xml->xpath($data['xpath0']))){
                $myTemplateDeviceNetwork0 = $xml->xpath($data['xpath_network']);
                $myTemplateDeviceNetwork0[0]->addChild("virtual-router");
            }
            $myTemplateDeviceNetwork0=$xml->xpath($data['xpath_network']);
            $myTemplateDeviceNetwork=$myTemplateDeviceNetwork0[0];
            $theVR = $myTemplateDeviceNetwork->{'virtual-router'};

            while ($getVRData = $getVR->fetch_assoc()) {
                $vr_id = $getVRData['id'];
                $myname = $getVRData['name'];
                $map_name = $getVRData['map_name'];
                $interfaces = $getVRData['interfaces'];
                $admin_dist_static = $getVRData['admin_dist_static'];
                $admin_dist_ospf_int = $getVRData['admin_dist_ospf_int'];
                $admin_dist_ospf_ext = $getVRData['admin_dist_ospf_ext'];
                $admin_dist_ibgp = $getVRData['admin_dist_ibgp'];
                $admin_dist_ebgp = $getVRData['admin_dist_ebgp'];
                $admin_dist_rip = $getVRData['admin_dist_rip'];
                $protocol = $getVRData['protocol'];
                $multicast = $getVRData['multicast'];
                $admin_dist_static_ipv6 = $getVRData['admin_dist_static_ipv6'];
                $admin_dist_ospfv3_int = $getVRData['admin_dist_ospfv3_int'];
                $admin_dist_ospfv3_ext = $getVRData['admin_dist_ospfv3_ext'];
                $ecmp=$getVRData['ecmp'];

                $vr = $theVR->addChild('entry');
                $vr->addAttribute('name', $myname);

                $vr->addChild("interface");
                $interface = $vr->interface;
                if ($interfaces != "") {
                    foreach (explode(",", $interfaces) as $key => $value) {
                        $interface->addChild("member", $value);
                    }
                }

                if ($protocol != "") {
                    //echo "PROTOCOL: \n";
                    //echo "" .$protocol. "\n";
                    //$protocol = stripslashes($protocol);
                    $protocol = str_replace('“', '"', $protocol);
                    $protocol = str_replace('”', '"', $protocol);
                    //echo "FIN PROTOCOL\n";
                    //echo "" .$protocol. "\n";
                    $xml_append = simplexml_load_string(clean_xml($protocol));
                    SimpleXMLElement_append($vr, $xml_append);
                }

                if ($version>=7){
                    if ($ecmp != "") {
                        $xml_append = simplexml_load_string(clean_xml($ecmp));
                        SimpleXMLElement_append($vr, $xml_append);
                    }
                }
                if ($multicast != "") {
                    $xml_append = simplexml_load_string(clean_xml($multicast));
                    SimpleXMLElement_append($vr, $xml_append);
                }

                #Metrics
                $vr->addChild("admin-dists");
                if (( $admin_dist_static == "") OR ( $admin_dist_static == "0")) {

                } else {
                    $vr->{'admin-dists'}->addChild("static", $admin_dist_static);
                }

                if (( $admin_dist_ospf_int == "") OR ( $admin_dist_ospf_int == "0")) {

                } else {
                    $vr->{'admin-dists'}->addChild("ospf-int", $admin_dist_ospf_int);
                }

                if (( $admin_dist_ospf_ext == "") OR ( $admin_dist_ospf_ext == "0")) {

                } else {
                    $vr->{'admin-dists'}->addChild("ospf-ext", $admin_dist_ospf_ext);
                }

                if ( ( $admin_dist_ibgp == "") OR ( $admin_dist_ibgp == "0")) {

                } else {
                    $vr->{'admin-dists'}->addChild("ibgp", $admin_dist_ibgp);
                }

                if (( $admin_dist_ebgp == "") OR ( $admin_dist_ebgp == "0")) {

                } else {
                    $vr->{'admin-dists'}->addChild("ebgp", $admin_dist_ebgp);
                }

                if (( $admin_dist_rip == "") OR ( $admin_dist_rip == "0")) {

                } else {
                    $vr->{'admin-dists'}->addChild("rip", $admin_dist_rip);
                }

                if ($version >= 6) {
                    if (( $admin_dist_static_ipv6 == "") OR ( $admin_dist_static_ipv6 == "0")) {

                    } else {
                        $vr->{'admin-dists'}->addChild("static-ipv6", $admin_dist_static_ipv6);
                    }

                    if (( $admin_dist_ospfv3_int == "") OR ( $admin_dist_ospfv3_int == "0")) {

                    } else {
                        $vr->{'admin-dists'}->addChild("ospfv3-int", $admin_dist_ospfv3_int);
                    }

                    if (( $admin_dist_ospfv3_ext == "") OR ( $admin_dist_ospfv3_ext == "0")) {

                    } else {
                        $vr->{'admin-dists'}->addChild("ospfv3-ext", $admin_dist_ospfv3_ext);
                    }
                }

                # Static Routing
                $exist = $projectdb->query("SELECT id FROM routes_static WHERE template='$template' AND source='$source' AND vr_id='$vr_id';");
                if ($exist->num_rows > 0) {
                    $vr->addChild("routing-table");
                    # IPV4
                    $getStatic = $projectdb->query("SELECT * FROM routes_static WHERE vr_id='$vr_id' AND (ip_version='v4' OR ip_version = 'noip')  AND source='$source' AND template='$template';");
                    if ($getStatic->num_rows > 0) {
                        $vr->{'routing-table'}->addChild("ip");
                        $vr->{'routing-table'}->ip->addChild("static-route");
                        $routes = $vr->{'routing-table'}->ip->{'static-route'};
                        while ($getStaticData = $getStatic->fetch_assoc()) {
                            $name = $getStaticData['name'];
                            $destination = $getStaticData['destination'];
                            $tointerface = $getStaticData['tointerface'];
                            $nexthop = $getStaticData['nexthop'];
                            $nexthop_value = $getStaticData['nexthop_value'];
                            $metric = $getStaticData['metric'];
                            $admin_dist = $getStaticData['admin_dist'];
                            $option_no_install = $getStaticData['option_no_install'];
                            $zone = $getStaticData['zone'];
                            $routeID=$getStaticData['id'];

                            $route = $routes->addChild("entry");
                            $route->addAttribute('name', $name);

                            if ($destination != "") {
                                $route->addChild("destination", $destination);
                            }

                            if (($option_no_install == 1) AND ($version<8) ){
                                $route->addChild("option");
                                $route->option->addChild("no-install");
                            }
                            if (($admin_dist != "") AND ( $admin_dist != "0")) {
                                if ($admin_dist == "10"){
                                    #Because is the default value
                                }
                                else{
                                    $route->addChild("admin-dist", $admin_dist);
                                }
                            }

                            if ($tointerface != "") {
                                $route->addChild("interface", $tointerface);
                            }

                            if ($nexthop != "None") {
                                $route->addChild("nexthop");
                                if ($nexthop_value != "") {
                                    $route->nexthop->addChild($nexthop, $nexthop_value);
                                } else {
                                    $route->nexthop->addChild($nexthop);
                                }
                            }
                            if (($metric != "") AND ( $metric != "0")) {
                                $route->addChild("metric", $metric);
                            }
                            if ($version>=8){
                                $route_table=$getStaticData['route_table'];
                                $bfd_profile=$getStaticData['bfd_profile'];
                                $pm_enable=$getStaticData['pm_enable'];
                                $pm_failure_condition=$getStaticData['pm_failure_condition'];
                                $pm_hold_time=$getStaticData['pm_hold_time'];
                                $path_monitor=$route->addChild("path-monitor");
                                $path_monitor->addChild("enable",$pm_enable);
                                $path_monitor->addChild("failure-condition",$pm_failure_condition);
                                $path_monitor->addChild("hold-time",$pm_hold_time);
                                $check_monitor_dest=$projectdb->query("SELECT * FROM routes_static_monitor_destinations WHERE route_id='$routeID';");
                                if ($check_monitor_dest->num_rows>0){
                                    $path_monitor->addChild("monitor-destinations");
                                    while($MD = $check_monitor_dest->fetch_assoc()){
                                        $MonitorDestinations=$path_monitor->{'monitor-destinations'}->addChild("entry");
                                        $MonitorDestinations->addAttribute('name', $MD['name']);
                                        $MonitorDestinations->addChild("enable",$MD['enable']);
                                        $MonitorDestinations->addChild("source",$MD['src']);
                                        if ($MD['dst_member_lid']!=0){
                                            $getMember=$projectdb->query("SELECT name FROM address WHERE id='".$MD['dst_member_lid']."'");
                                            if ($getMember->num_rows==1){
                                                $getMemberData=$getMember->fetch_assoc();
                                                $MD['dst']=$getMemberData['name'];
                                            }
                                        }
                                        $MonitorDestinations->addChild("destination",$MD['dst']);
                                        $MonitorDestinations->addChild("interval",$MD['mp_interval']);
                                        $MonitorDestinations->addChild("count",$MD['mp_count']);
                                    }
                                }
                                if ($bfd_profile!="None"){
                                    $bfd=$route->addChild("bfd");
                                    $bfd->addChild("profile",$bfd_profile);
                                }
                                $Rroute_table=$route->addChild("route-table");
                                $Rroute_table->addChild($route_table);
                            }
                        }
                    }

                    #IPV6
                    $getStatic = $projectdb->query("SELECT * FROM routes_static WHERE vr_id='$vr_id' AND ip_version='v6' AND source='$source' AND template='$template';");
                    if ($getStatic->num_rows > 0) {
                        $vr->{'routing-table'}->addChild("ipv6");
                        $vr->{'routing-table'}->ipv6->addChild("static-route");
                        $routes = $vr->{'routing-table'}->ipv6->{'static-route'};
                        while ($getStaticData = $getStatic->fetch_assoc()) {
                            $name = $getStaticData['name'];
                            $destination = $getStaticData['destination'];
                            $tointerface = $getStaticData['tointerface'];
                            $nexthop = $getStaticData['nexthop'];
                            $nexthop_value = $getStaticData['nexthop_value'];
                            $metric = $getStaticData['metric'];
                            $admin_dist = $getStaticData['admin_dist'];
                            $option_no_install = $getStaticData['option_no_install'];
                            $zone = $getStaticData['zone'];
                            $routeID=$getStaticData['id'];

                            $route = $routes->addChild("entry");
                            $route->addAttribute('name', $name);

                            if ($destination != "") {
                                $route->addChild("destination", $destination);
                            }

                            if ($option_no_install == 1) {
                                $route->addChild("option");
                                $route->option->addChild("no-install");
                            }
                            if ($admin_dist != "") {
                                $route->addChild("admin-dist", $admin_dist);
                            }

                            if ($tointerface != "") {
                                $route->addChild("interface", $tointerface);
                            }

                            if ($nexthop != "None") {
                                $route->addChild("nexthop");
                                if ($nexthop_value != "") {
                                    $route->nexthop->addChild($nexthop, $nexthop_value);
                                } else {
                                    $route->nexthop->addChild($nexthop);
                                }
                            }
                            if ($metric != "") {
                                $route->addChild("metric", $metric);
                            }
                            if ($version>=8){
                                $route_table=$getStaticData['route_table'];
                                $bfd_profile=$getStaticData['bfd_profile'];
                                $pm_enable=$getStaticData['pm_enable'];
                                $pm_failure_condition=$getStaticData['pm_failure_condition'];
                                $pm_hold_time=$getStaticData['pm_hold_time'];
                                $path_monitor=$route->addChild("path-monitor");
                                $path_monitor->addChild("enable",$pm_enable);
                                $path_monitor->addChild("failure-condition",$pm_failure_condition);
                                $path_monitor->addChild("hold-time",$pm_hold_time);
                                $check_monitor_dest=$projectdb->query("SELECT * FROM routes_static_monitor_destinations WHERE route_id='$routeID';");
                                if ($check_monitor_dest->num_rows>0){
                                    $path_monitor->addChild("monitor-destinations");
                                    while($MD=$check_monitor_dest->fetch_assoc()){
                                        $MonitorDestinations=$path_monitor->{'monitor-destinations'}->addChild("entry");
                                        $MonitorDestinations->addAttribute('name', $MD['name']);
                                        $MonitorDestinations->addChild("enable",$MD['enable']);
                                        $MonitorDestinations->addChild("source",$MD['src']);
                                        if ($MD['dst_member_lid']!=0){
                                            $getMember=$projectdb->query("SELECT name FROM address WHERE id='".$MD['dst_member_lid']."'");
                                            if ($getMember->num_rows==1){
                                                $getMemberData=$getMember->fetch_assoc();
                                                $MD['dst']=$getMemberData['name'];
                                            }
                                        }
                                        $MonitorDestinations->addChild("destination",$MD['dst']);
                                        $MonitorDestinations->addChild("interval",$MD['mp_interval']);
                                        $MonitorDestinations->addChild("count",$MD['mp_count']);
                                    }
                                }
                                if ($bfd_profile!="None"){
                                    $bfd=$route->addChild("bfd");
                                    $bfd->addChild("profile",$bfd_profile);
                                }
                                $Rroute_table=$route->addChild("route-table");
                                $Rroute_table->addChild($route_table);
                            }
                        }
                    }
                }

                if ($api_call=="single"){
                    $xpath2 = addslashes($data['xpath0']."/entry[@name='$myname']");
                    $xml_final = addslashes($vr->asXML());
                    $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','Virtual Router','Virtual Router','$xml_final','$xpath2','edit');");
                }
            }
            if ($api_call=="atomic"){
                $xpath2 = addslashes($data['xpath0']);
                $xml_final = addslashes($theVR->asXML());
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Virtual Router','Virtual Router','Virtual Router','$xml_final','$xpath2','edit');");
            }
        }
        else{
            if ($api_call=="clean"){
                $xpath2 = addslashes($data['xpath_network']."/virtual-router");
                $xml_final = "";
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Remove All Virtual Router','Virtual Router','Virtual Router','$xml_final','$xpath2','delete');");
            }
        }

//    }
//    else{
//        $message['code'] = false;
//        $message['msg'] = "Invalid Template Id:$template";
//        return $message;
//    }
}

function xml_network_dnsproxy($xml,$data){
    $project = $data['project'];
    $ispanorama = $data['ispanorama'];
    $version = $data['version'];
    $api_call=$data['api_call'];
    $projectdb = $data['projectdb'];
    $source = $data['source'];
    $vsys = $data['vsys'];
    $template = $data['template'];
    $template_name=$data['template_name'];

//    if ($template==0){
//        return "Invalid TemplateID";
//    }

    if ($ispanorama==1){
        if ($vsys != "shared"){
            if(empty($xml->xpath("/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='" . $template_name . "']/config"))){
                $config=$xml->xpath("/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='" . $template_name . "']");
                if (count($config)>0){
                    $config[0]->addChild("config");
                    $localhost=$config[0]->config->addChild("entry");
                    $localhost->addAttribute('name', 'localhost.localdomain');
                    $localhost->addChild("vsys");
                    $localhostvsys=$localhost->vsys->addChild("entry");
                    $localhostvsys->addAttribute("name",$vsys);
                }
                else{
                    $message['code'] = false;
                    $message['msg'] = "No Template.";
                    return $message;
                }

            }
            $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='" . $template_name . "']/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='$vsys']";
        }
        else{
            if(empty($xml->xpath("/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='" . $template_name . "']/config"))){
                $config=$xml->xpath("/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='" . $template_name . "']");
                if (count($config)>0){
                    $config[0]->addChild("config");
                    $localhost=$config[0]->config->addChild("entry");
                    $localhost->addAttribute('name', 'localhost.localdomain');
                    $localhost->addChild("network");
                }
                else{
                    $message['code'] = false;
                    $message['msg'] = "No Template";
                    return $message;
                }

            }
            $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='" . $template_name . "']/config/devices/entry[@name='localhost.localdomain']/network";
        }
    }
    else{
        if ($vsys != "shared") {
            $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='$vsys']";
        }
        else{
            $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/network";
        }
    }

    $xpath0 = $data['xpath0'];

    $getShared = $projectdb->query("SELECT * FROM dns_proxy WHERE source='$source' AND vsys='$vsys' AND template='$template' ORDER BY id;");
    if ($getShared->num_rows > 0) {
        if (empty($xml->xpath($xpath0."/dns-proxy"))){
            $thedevicegroup0=$xml->xpath($xpath0);
        }
        else{
            $SA=$xml->xpath($xpath0."/dns-proxy");
            unset($SA[0][0]);
            $thedevicegroup0=$xml->xpath($xpath0);

        }
        $thedevicegroup = $thedevicegroup0[0];
        $thedevicegroup->addChild('dns-proxy');
        while ($data = $getShared->fetch_assoc()) {
            $xmlfield = $data['xml'];
            $xmlname = $data['name'];
            $xml_append = simplexml_load_string(clean_xml($xmlfield));
            SimpleXMLElement_append($thedevicegroup->{'dns-proxy'}, $xml_append);

            if ($api_call=="single"){
                $xpath2 = addslashes($xpath0."/dns-proxy/entry[@name='$xmlname']");
                $element=$thedevicegroup->{'dns-proxy'}->xpath("entry[@name='$xmlname']");
                $xml_final = addslashes($element[0]->asXML());
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$xmlname','DNS PROXY','DNS PROXY','$xml_final','$xpath2','edit');");
            }
        }
        if ($api_call=="atomic"){
            $xpath2 = addslashes($xpath0."/dns-proxy");
            $xml_final = addslashes($thedevicegroup->{'dns-proxy'}->asXML());
            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('DNS PROXY $vsys','DNS PROXY','DNS PROXY','$xml_final','$xpath2','edit');");
        }
    }
    else{
        if (!empty($xml->xpath($xpath0."/dns-proxy"))){
            $thedevicegroup0=$xml->xpath($xpath0);
            $thedevicegroup = $thedevicegroup0[0];
            if (isset($thedevicegroup->{'dns-proxy'})){
                $SA = $xml->xpath($xpath0."/dns-proxy");
                unset($SA[0][0]);
            }
        }

        if ($api_call=="clean"){
            $xpath2 = addslashes($xpath0."/dns-proxy");
            $xml_final = "";
            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Remove All DNS PROXY $vsys','DNS PROXY','DNS PROXY','$xml_final','$xpath2','delete');");
        }
        $message['code'] = true;
        $message['msg'] = "Removed All DNS PROXY : $vsys";
        return $message;
    }
}

function xml_network_dhcp($xml,$data){
    $project = $data['project'];
    $ispanorama = $data['ispanorama'];
    $version = $data['version'];
    $api_call=$data['api_call'];
    $projectdb = $data['projectdb'];
    $source = $data['source'];
    $template = $data['template'];
    $template_name=$data['template_name'];

//    if ($template==0){
//        return "Invalid TemplateID";
//    }

    if ($ispanorama==1){
        if(empty($xml->xpath("/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='" . $template_name . "']/config"))){
            $config=$xml->xpath("/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='" . $template_name . "']");
            if (count($config)>0){
                $config[0]->addChild("config");
                $localhost=$config[0]->config->addChild("entry");
                $localhost->addAttribute('name', 'localhost.localdomain');
                $localhost->addChild("network");
            }
            else{
                $message['code'] = false;
                $message['msg'] = "No Template.";
                return $message;
            }
        }
        $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='" . $template_name . "']/config/devices/entry[@name='localhost.localdomain']/network";
    }
    else{
        $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/network";
    }

    $xpath0 = $data['xpath0'];

    $getDHCP = $projectdb->query("SELECT name,dhcp_type,xml FROM dhcp WHERE source='$source' AND template='$template';");
    if ($getDHCP->num_rows > 0) {
        if (empty($xml->xpath($xpath0."/dhcp"))){
            $thedevicegroup0=$xml->xpath($xpath0);
        }
        else{
            $SA=$xml->xpath($xpath0."/dhcp");
            unset($SA[0][0]);
            $thedevicegroup0=$xml->xpath($xpath0);

        }
        $thedevicegroup = $thedevicegroup0[0];

        $thedevicegroup->addChild("dhcp");
        $thedevicegroup->dhcp->addChild("interface");

        while ($getDHCPData = $getDHCP->fetch_assoc()) {
            $xmlname = $getDHCPData['name'];
            $xmlfield = $getDHCPData['xml'];
            $xml_append = simplexml_load_string(clean_xml($xmlfield));
            if ($thedevicegroup->dhcp->interface->xpath("entry[@name='$xmlname']") != null) {}
            else {
                SimpleXMLElement_append($thedevicegroup->dhcp->interface, $xml_append);
            }
            if ($api_call=="single"){
                $xpath2 = addslashes($xpath0."/dhcp/interface/entry[@name='$xmlname']");
                $element=$thedevicegroup->dhcp->interface->xpath("entry[@name='$xmlname']");
                $xml_final = addslashes($element[0]->asXML());
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$xmlname','DHCP','DHCP','$xml_final','$xpath2','edit');");
            }
        }
        if ($api_call=="atomic"){
            $xpath2 = addslashes($xpath0."/dhcp");
            $xml_final = addslashes($thedevicegroup->dhcp->asXML());
            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('DHCP','DHCP','DHCP','$xml_final','$xpath2','edit');");
        }
    }
    else{
        if (!empty($xml->xpath($xpath0."/dhcp"))){
            $thedevicegroup0=$xml->xpath($xpath0);
            $thedevicegroup = $thedevicegroup0[0];
            if (isset($thedevicegroup->dhcp)){
                $SA = $xml->xpath($xpath0."/dhcp");
                unset($SA[0][0]);
            }
        }

        if ($api_call=="clean"){
            $xpath2 = addslashes($xpath0."/dhcp");
            $xml_final = "";
            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Remove All DHCP','DHCP','DHCP','$xml_final','$xpath2','delete');");
        }
        $message['code'] = true;
        $message['msg'] = "Removed All DHCP.";
        return $message;
    }
}

# Network / Profiles
function xml_network_monitor($xml,$data){
    $project = $data['project'];
    $ispanorama = $data['ispanorama'];
    $version = $data['version'];
    $api_call=$data['api_call'];
    $projectdb = $data['projectdb'];
    $source = $data['source'];
    $template = $data['template'];
    $template_name=$data['template_name'];

//    if ($template==0){
//        return "Invalid TemplateID";
//    }

    if ($ispanorama==1){
        if(empty($xml->xpath("/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='" . $template_name . "']/config"))){
            $config=$xml->xpath("/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='" . $template_name . "']");
            if (count($config)>0){
                $config[0]->addChild("config");
                $localhost=$config[0]->config->addChild("entry");
                $localhost->addAttribute('name', 'localhost.localdomain');
                $localhost->addChild("network");
            }
            else{
                $message['code'] = false;
                $message['msg'] = "No Template.";
                return $message;
            }

        }
        $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='" . $template_name . "']/config/devices/entry[@name='localhost.localdomain']/network";
    }
    else{
        $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/network";
    }

    $xpath0 = $data['xpath0'];

    $getMonitor = $projectdb->query("SELECT * FROM monitor_profile WHERE source='$source' AND template='$template' AND name != '' GROUP BY name;");
    if ($getMonitor->num_rows>0){

        $thedevicegroup1=$xml->xpath($xpath0);
        if (!isset($thedevicegroup1[0]->profiles)){
            $thedevicegroup1[0]->addChild("profiles");
        }

//        if (empty($xml->xpath($xpath0."/profiles"))){
//            $thedevicegroup0=$xml->xpath($xpath0);
//        }
//        else{
//            $SA=$xml->xpath($xpath0."/profiles");
//            unset($SA[0][0]);
//            $thedevicegroup0=$xml->xpath($xpath0);
//
//        }
        $thedevicegroup = $thedevicegroup1[0]->profiles;

        # MONITOR PROFILE
        if (isset($thedevicegroup->{'monitor-profile'})){
            $SA=$thedevicegroup->xpath("monitor-profile");
            unset($SA[0][0]);
        }
        if (!isset($thedevicegroup->{'monitor-profile'})){
            $thedevicegroup->addChild("monitor-profile");
        }
        $MPXpath=$thedevicegroup->{'monitor-profile'};
        while ($getMonitorData=$getMonitor->fetch_assoc()){
            $myname = $getMonitorData['name'];
            $MPAction=$getMonitorData['m_action'];
            $MPInterval=$getMonitorData['interva'];
            $MPThreshold=$getMonitorData['threshold'];

            $monitorProfile = $MPXpath->addChild('entry');
            $monitorProfile->addAttribute('name', $myname);
            if (($MPInterval!=0) AND ($MPInterval!="")){
                $monitorProfile->addChild("interval");
                $monitorProfile->interval=$MPInterval;
            }
            if (($MPThreshold!=0) AND ($MPThreshold!="")){
                $monitorProfile->addChild("threshold");
                $monitorProfile->threshold=$MPThreshold;
            }
            if ($MPAction!=""){
                $monitorProfile->addChild("action");
                $monitorProfile->action=$MPAction;
            }
            if ($api_call=="single"){
                $xpath2 = addslashes($xpath0."/profiles/monitor-profile/entry[@name='$myname']");
                $element=$thedevicegroup->{'monitor-profile'}->xpath("entry[@name='$myname']");
                $xml_final = addslashes($element[0]->asXML());
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','Monitor Profile','Monitor Profile','$xml_final','$xpath2','edit');");
            }
        }
        if ($api_call=="atomic"){
            $xpath2 = addslashes($xpath0."/profiles/monitor-profile");
            $xml_final = addslashes($thedevicegroup->{'monitor-profile'}->asXML());
            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Monitor Profiles','Monitor Profiles','Monitor Profiles','$xml_final','$xpath2','edit');");
        }
    }
    else{
        if (!empty($xml->xpath($xpath0."/profiles"))){
            $thedevicegroup0=$xml->xpath($xpath0."/profiles");
            $thedevicegroup = $thedevicegroup0[0];
            if (isset($thedevicegroup->{'monitor-pofile'})){
                $SA = $xml->xpath($xpath0."/profiles/monitor-profile");
                unset($SA[0][0]);
            }
        }

        if ($api_call=="clean"){
            $xpath2 = addslashes($xpath0."/profiles/monitor-profile");
            $xml_final = "";
            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Remove All Monitor Profiles','Monitor Profile','Monitor Profile','$xml_final','$xpath2','delete');");
        }
        $message['code'] = true;
        $message['msg'] = "Removed All Monitor Profiles.";
        return $message;
    }
}

function xml_network_zone_protection($xml,$data){
    $project = $data['project'];
    $ispanorama = $data['ispanorama'];
    $version = $data['version'];
    $api_call=$data['api_call'];
    $projectdb = $data['projectdb'];
    $source = $data['source'];
    $template = $data['template'];
    $template_name=$data['template_name'];

//    if ($template==0){
//        return "Invalid TemplateID";
//    }

    if ($ispanorama==1){
        if(empty($xml->xpath("/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='" . $template_name . "']/config"))){
            $config=$xml->xpath("/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='" . $template_name . "']");
            if (count($config)>0){
                $config[0]->addChild("config");
                $localhost=$config[0]->config->addChild("entry");
                $localhost->addAttribute('name', 'localhost.localdomain');
                $localhost->addChild("network");
            }
            else{
                $message['code'] = false;
                $message['msg'] = "No Template.";
                return $message;
            }

        }
        $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='" . $template_name . "']/config/devices/entry[@name='localhost.localdomain']/network";
    }
    else{
        $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/network";
    }

    $xpath0 = $data['xpath0'];

    $getDHCP = $projectdb->query("SELECT * FROM zone_protection_profile WHERE source='$source' AND template='$template' ORDER BY id;");
    if ($getDHCP->num_rows > 0) {

        if (empty($xml->xpath($xpath0."/profiles"))){
            $thedevicegroup0=$xml->xpath($xpath0);
            $thedevicegroup0[0]->addChild('profiles');
        }

        if (empty($xml->xpath($xpath0."/profiles/zone-protection-profile"))){
            $thedevicegroup0=$xml->xpath($xpath0."/profiles");
        }
        else{
            $SA=$xml->xpath($xpath0."/profiles/zone-protection-profile");
            unset($SA[0][0]);
            $thedevicegroup0=$xml->xpath($xpath0."/profiles");

        }
        $thedevicegroup = $thedevicegroup0[0];

        $thedevicegroup->addChild("zone-protection-profile");

        while ($getDHCPData = $getDHCP->fetch_assoc()) {
            $xmlname = $getDHCPData['name'];
            $xmlfield = $getDHCPData['xml'];
            $xml_append = simplexml_load_string(clean_xml($xmlfield));
            if ($thedevicegroup->{'zone-protection-profile'}->xpath("entry[@name='$xmlname']") != null) {}
            else {
                SimpleXMLElement_append($thedevicegroup->{'zone-protection-profile'}, $xml_append);
            }
            if ($api_call=="single"){
                $xpath2 = addslashes($xpath0."/profiles/zone-protection-profile/entry[@name='$xmlname']");
                $element=$thedevicegroup->{'zone-protection-profile'}->xpath("entry[@name='$xmlname']");
                $xml_final = addslashes($element[0]->asXML());
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$xmlname','Zone Protection','Zone Protection','$xml_final','$xpath2','edit');");
            }
        }
        if ($api_call=="atomic"){
            $xpath2 = addslashes($xpath0."/profiles/zone-protection-profile");
            $xml_final = addslashes($thedevicegroup->{'zone-protection-profile'}->asXML());
            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Zone Protection','Zone Protection','Zone Protection','$xml_final','$xpath2','edit');");
        }
    }
    else{
        if (!empty($xml->xpath($xpath0."/profiles/zone-protection-profile"))){
            $thedevicegroup0=$xml->xpath($xpath0."/profiles");
            $thedevicegroup = $thedevicegroup0[0];
            if (isset($thedevicegroup->{'zone-protection-profile'})){
                $SA = $xml->xpath($xpath0."/profiles/zone-protection-profile");
                unset($SA[0][0]);
            }
        }

        if ($api_call=="clean"){
            $xpath2 = addslashes($xpath0."/profiles/zone-protection-profile");
            $xml_final = "";
            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Remove All DHCP','DHCP','DHCP','$xml_final','$xpath2','delete');");
        }
        $message['code'] = true;
        $message['msg'] = "Removed All Zone Protection Profiles.";
        return $message;
    }
}

function xml_network_management_interface($xml,$data){
    $project = $data['project'];
    $ispanorama = $data['ispanorama'];
    $version = $data['version'];
    $api_call=$data['api_call'];
    $projectdb = $data['projectdb'];
    $source = $data['source'];
    $template = $data['template'];
    $template_name=$data['template_name'];

//    if ($template==0){
//        return "Invalid TemplateID";
//    }

    if ($ispanorama==1){
        if(empty($xml->xpath("/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='" . $template_name . "']/config"))){
            $config=$xml->xpath("/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='" . $template_name . "']");
            if (count($config)>0){
                $config[0]->addChild("config");
                $localhost=$config[0]->config->addChild("entry");
                $localhost->addAttribute('name', 'localhost.localdomain');
                $localhost->addChild("network");
            }
            else{
                $message['code'] = false;
                $message['msg'] = "No Template";
                return $message;
            }

        }
        $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='" . $template_name . "']/config/devices/entry[@name='localhost.localdomain']/network";
    }
    else{
        $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/network";
    }
    $xpath0 = $data['xpath0'];

    $getMP = $projectdb->query("SELECT * FROM interface_management_profile WHERE source='$source' AND template='$template' AND name != '' GROUP BY name;");
    if ($getMP->num_rows > 0) {
        if (empty($xml->xpath($xpath0."/profiles"))){
            $thedevicegroup0=$xml->xpath($xpath0);
            $thedevicegroup0[0]->addChild("profiles");
        }
        else{
            $thedevicegroup0=$xml->xpath($xpath0."/profiles");

        }
        $thedevicegroup = $thedevicegroup0[0];

        if (isset($thedevicegroup->{'interface-management-profile'})){
            $SA=$thedevicegroup->xpath("interface-management-profile");
            unset($SA[0][0]);
        }

        $thedevicegroup->addChild('interface-management-profile');

        while ($getMPData = $getMP->fetch_assoc()) {
            $myname = $getMPData['name'];
            $mgmprofile = $thedevicegroup->{'interface-management-profile'}->addChild('entry');
            $mgmprofile->addAttribute('name', $myname);

            if ($getMPData['http'] != "") {
                $mgmprofile->addChild("http", $getMPData['http']);
            }
            if ($getMPData['https'] != "") {
                $mgmprofile->addChild("https", $getMPData['https']);
            }
            if ($getMPData['http_ocsp'] != "") {
                $mgmprofile->addChild("http-ocsp", $getMPData['http_ocsp']);
            }
            if ($getMPData['ssh'] != "") {
                $mgmprofile->addChild("ssh", $getMPData['ssh']);
            }
            if ($getMPData['snmp'] != "") {
                $mgmprofile->addChild("snmp", $getMPData['snmp']);
            }
            if ($getMPData['userid_service'] != "") {
                $mgmprofile->addChild("userid-service", $getMPData['userid_service']);
            }
            if ($getMPData['ping'] != "") {
                $mgmprofile->addChild("ping", $getMPData['ping']);
            }
            if ($getMPData['telnet'] != "") {
                $mgmprofile->addChild("telnet", $getMPData['telnet']);
            }
            if ($getMPData['response_pages'] != "") {
                $mgmprofile->addChild("response-pages", $getMPData['response_pages']);
            }
            if ($version > 5) {
                if ($getMPData['userid_syslog_listener_ssl'] != "") {
                    $mgmprofile->addChild("userid-syslog-listener-ssl", $getMPData['userid_syslog_listener_ssl']);
                }
                if ($getMPData['userid_syslog_listener_udp'] != "") {
                    $mgmprofile->addChild("userid-syslog-listener-udp", $getMPData['userid_syslog_listener_udp']);
                }
            }
            if ($getMPData['permitted_ip'] != "") {
                $interfaces_all = explode(",", $getMPData['permitted_ip']);
                $mgmprofile->addChild("permitted-ip");
                foreach ($interfaces_all as $key => $int_value) {
                    $newInt = $mgmprofile->{'permitted-ip'}->addChild("entry");
                    $newInt->addAttribute('name', $int_value);
                }
            }
            if ($api_call=="single"){
                $xpath2 = addslashes($xpath0."/profiles/interface-management-profile/entry[@name='$myname']");
                $element=$thedevicegroup->{'interface-management-profile'}->xpath("entry[@name='$myname']");
                $xml_final = addslashes($element[0]->asXML());
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','Management Profile','Management Profile','$xml_final','$xpath2','edit');");
            }
        }
        if ($api_call=="atomic"){
            $xpath2 = addslashes($xpath0."/profiles/interface-management-profile");
            $xml_final = addslashes($thedevicegroup->{'interface-management-profile'}->asXML());
            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Management Profiles','Management Profiles','Management Profiles','$xml_final','$xpath2','edit');");
        }
    }
    else{
        if (!empty($xml->xpath($xpath0."/profiles/interface-management-profile"))){
            $thedevicegroup0=$xml->xpath($xpath0."/profiles");
            $thedevicegroup = $thedevicegroup0[0];
            if (isset($thedevicegroup->{'interface-management-profile'})){
                $SA = $xml->xpath($xpath0."/profiles/interface-management-profile");
                unset($SA[0][0]);
            }
        }

        if ($api_call=="clean"){
            $xpath2 = addslashes($xpath0."/profiles/interface-management-profile");
            $xml_final = "";
            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Remove All Management Profiles','Management Profile','Management Profile','$xml_final','$xpath2','delete');");
        }
        $message['code'] = true;
        $message['msg'] = "Removed All Management Profiles.";
        return $message;
    }
}

# Network IKE
function xml_network_ike_crypto_profiles($xml,$data){
    $project = $data['project'];
    $ispanorama = $data['ispanorama'];
    $version = $data['version'];
    $api_call=$data['api_call'];
    $projectdb = $data['projectdb'];
    $source = $data['source'];
    $template = $data['template'];
    $template_name=$data['template_name'];

//    if ($template==0){
//        return "Invalid TemplateID";
//    }

    if ($ispanorama==1){
        if(empty($xml->xpath("/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='" . $template_name . "']/config"))){
            $config=$xml->xpath("/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='" . $template_name . "']");
            if (count($config)>0){
                $config[0]->addChild("config");
                $localhost=$config[0]->config->addChild("entry");
                $localhost->addAttribute('name', 'localhost.localdomain');
                $localhost->addChild("network");
            }
            else{
                $message['code'] = false;
                $message['msg'] = "No Template.";
                return $message;
            }

        }

        $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='" . $template_name . "']/config/devices/entry[@name='localhost.localdomain']/network";
    }
    else{
        $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/network";
    }

    $xpath0 = $data['xpath0'];


    $getIKECrypto = $projectdb->query("SELECT * FROM ike_crypto_profiles WHERE source='$source' AND template='$template' AND name != '';");
    if ($getIKECrypto->num_rows > 0){

        if (empty($xml->xpath($xpath0."/ike"))){
            $thedevicegroup0=$xml->xpath($xpath0);
            $thedevicegroup0[0]->addChild("ike");
        }

        if (empty($xml->xpath($xpath0."/ike/crypto-profiles"))){
            $thedevicegroup0=$xml->xpath($xpath0."/ike");
            $thedevicegroup0[0]->addChild("crypto-profiles");
        }

        if (empty($xml->xpath($xpath0."/ike/crypto-profiles/ike-crypto-profiles"))){
            $thedevicegroup0=$xml->xpath($xpath0."/ike/crypto-profiles");
        }
        else{
            $SA=$xml->xpath($xpath0."/ike/crypto-profiles/ike-crypto-profiles");
            unset($SA[0][0]);
            $thedevicegroup0=$xml->xpath($xpath0."/ike/crypto-profiles");
        }

        $thedevicegroup = $thedevicegroup0[0];


        if (!isset($thedevicegroup->{'ike-crypto-profiles'})){
            $thedevicegroup->addChild("ike-crypto-profiles");
        }
        $ike_crypto_path = $thedevicegroup->{'ike-crypto-profiles'};

        while ($dataIKEC = $getIKECrypto->fetch_assoc()){
            $myname = $dataIKEC['name'];
            $ike_encryption = $dataIKEC['encryption'];
            $ike_hash = $dataIKEC['hash'];
            $ike_dh_group = $dataIKEC['dh_group'];
            $ike_seconds = $dataIKEC['seconds'];
            $ike_minutes = $dataIKEC['minutes'];
            $ike_hours = $dataIKEC['hours'];
            $ike_days = $dataIKEC['days'];
            $ike_authentication_multiple = $dataIKEC['authentication_multiple'];

            $ike_crypto = $ike_crypto_path->addChild('entry');
            $ike_crypto->addAttribute('name', $dataIKEC['name']);

            if ($ike_encryption != ""){
                $ike_crypto->addChild("encryption");
                $ike_encryption_array = explode(",", $ike_encryption);
                foreach($ike_encryption_array as $member_ike){
                    $ike_crypto->encryption->addChild("member", $member_ike);
                }
            }
            if ($ike_hash != ""){
                $ike_crypto->addChild("hash");
                $ike_hash_array = explode(",", $ike_hash);
                foreach($ike_hash_array as $member_ike){
                    $ike_crypto->hash->addChild("member", $member_ike);
                }
            }
            if ($ike_dh_group != ""){
                $ike_crypto->addChild("dh-group");
                $ike_dh_group_array = explode(",", $ike_dh_group);
                foreach($ike_dh_group_array as $member_ike){
                    $ike_crypto->{'dh-group'}->addChild("member", $member_ike);
                }
            }
            if ($ike_seconds != 0){
                $ike_crypto->addChild("lifetime");
                $ike_crypto->{'lifetime'}->seconds = $ike_seconds;
            }
            if ($ike_minutes != 0){
                $ike_crypto->addChild("lifetime");
                $ike_crypto->{'lifetime'}->minutes = $ike_minutes;
            }
            if ($ike_hours != 0){
                $ike_crypto->addChild("lifetime");
                $ike_crypto->{'lifetime'}->hours = $ike_hours;
            }
            if ($ike_days != 0){
                $ike_crypto->addChild("lifetime");
                $ike_crypto->{'lifetime'}->days = $ike_days;
            }
            if ($api_call=="single"){
                $xpath2 = addslashes($xpath0."/ike/crypto-profiles/ike-crypto-profiles/entry[@name='$myname']");
                $element=$thedevicegroup->{'ike-crypto-profiles'}->xpath("entry[@name='$myname']");
                $xml_final = addslashes($element[0]->asXML());
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','IKE Crypto Profile','IKE Crypto Profile','$xml_final','$xpath2','edit');");
            }
        }
        if ($api_call=="atomic"){
            $xpath2 = addslashes($xpath0."/ike/crypto-profiles/ike-crypto-profiles");
            $xml_final = addslashes($thedevicegroup->{'ike-crypto-profiles'}->asXML());
            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('IKE Crypto Profiles','IKE Crypto Profiles','IKE Crypto Profiles','$xml_final','$xpath2','edit');");
        }
    }
    else{
        if (!empty($xml->xpath($xpath0."/ike/crypto-profiles"))){
            $thedevicegroup0=$xml->xpath($xpath0."/ike/crypto-profiles");
            $thedevicegroup = $thedevicegroup0[0];

            if (isset($thedevicegroup->{'ike-crypto-profiles'})){
                $SA = $xml->xpath($xpath0."/ike/crypto-profiles/ike-crypto-profiles");
                unset($SA[0][0]);
            }
        }

        if ($api_call=="clean"){
            $xpath2 = addslashes($xpath0."/ike/crypto-profiles/ike-crypto-profiles");
            $xml_final = "";
            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Remove All IKE Crypto Profiles','IKE Crypto Profile','IKE Crypto Profile','$xml_final','$xpath2','delete');");
        }
        $message['code'] = true;
        $message['msg'] = "Removed All IKE Crypto Profiles.";
        return $message;
    }
}


function xml_network_global_protect_app_crypto_profiles($xml,$data){

    $project = $data['project'];
    $ispanorama = $data['ispanorama'];
    $version = $data['version'];
    $api_call=$data['api_call'];
    $projectdb = $data['projectdb'];
    $source = $data['source'];
    $template = $data['template'];
    $template_name=$data['template_name'];

    if ($ispanorama==1){
        if(empty($xml->xpath("/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='" . $template_name . "']/config"))){
            $config=$xml->xpath("/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='" . $template_name . "']");
            if (count($config)>0){
                $config[0]->addChild("config");
                $localhost=$config[0]->config->addChild("entry");
                $localhost->addAttribute('name', 'localhost.localdomain');
                $localhost->addChild("network");
            }
            else{
                $message['code'] = false;
                $message['msg'] = "No Template.";
                return $message;
            }

        }

        $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='" . $template_name . "']/config/devices/entry[@name='localhost.localdomain']/network";
    }
    else{
        $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/network";
    }

    $xpath0 = $data['xpath0'];


    $getIKECrypto = $projectdb->query("SELECT * FROM global_protect_app_ipsec_crypto_profiles WHERE source='$source' AND template='$template' AND name != '';");
    if ($getIKECrypto->num_rows > 0){

        if (empty($xml->xpath($xpath0."/ike"))){
            $thedevicegroup0=$xml->xpath($xpath0);
            $thedevicegroup0[0]->addChild("ike");
        }

        if (empty($xml->xpath($xpath0."/ike/crypto-profiles"))){
            $thedevicegroup0=$xml->xpath($xpath0."/ike");
            $thedevicegroup0[0]->addChild("crypto-profiles");
        }

        if (empty($xml->xpath($xpath0."/ike/crypto-profiles/global-protect-app-crypto-profiles"))){
            $thedevicegroup0=$xml->xpath($xpath0."/ike/crypto-profiles");
        }
        else{
            $SA=$xml->xpath($xpath0."/ike/crypto-profiles/global-protect-app-crypto-profiles");
            unset($SA[0][0]);
            $thedevicegroup0=$xml->xpath($xpath0."/ike/crypto-profiles");
        }

        $thedevicegroup = $thedevicegroup0[0];

        if (!isset($thedevicegroup->{'global-protect-app-crypto-profiles'})){
            $thedevicegroup->addChild("global-protect-app-crypto-profiles");
        }
        $ike_crypto_path = $thedevicegroup->{'global-protect-app-crypto-profiles'};

        while ($dataIKEC = $getIKECrypto->fetch_assoc()){
            $myname = $dataIKEC['name'];
            $ike_encryption = $dataIKEC['encryption'];
            $ike_hash = $dataIKEC['hash'];

            $ike_crypto = $ike_crypto_path->addChild('entry');
            $ike_crypto->addAttribute('name', $dataIKEC['name']);

            if ($ike_encryption != ""){
                $ike_crypto->addChild("encryption");
                $ike_encryption_array = explode(",", $ike_encryption);
                foreach($ike_encryption_array as $member_ike){
                    $ike_crypto->encryption->addChild("member", $member_ike);
                }
            }
            if ($ike_hash != ""){
                $ike_crypto->addChild("authentication");
                $ike_hash_array = explode(",", $ike_hash);
                foreach($ike_hash_array as $member_ike){
                    $ike_crypto->authentication->addChild("member", $member_ike);
                }
            }

            if ($api_call=="single"){
                $xpath2 = addslashes($xpath0."/ike/crypto-profiles/global-protect-app-crypto-profiles/entry[@name='$myname']");
                $element=$thedevicegroup->{'global-protect-app-crypto-profiles'}->xpath("entry[@name='$myname']");
                $xml_final = addslashes($element[0]->asXML());
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','GlobalProtect IPSec Crypto','GlobalProtect IPSec Crypto','$xml_final','$xpath2','edit');");
            }
        }
        if ($api_call=="atomic"){
            $xpath2 = addslashes($xpath0."/ike/crypto-profiles/global-protect-app-crypto-profiles");
            $xml_final = addslashes($thedevicegroup->{'global-protect-app-crypto-profiles'}->asXML());
            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('GlobalProtect IPSec Crypto','GlobalProtect IPSec Crypto','GlobalProtect IPSec Crypto','$xml_final','$xpath2','edit');");
        }
    }
    else{
        if (!empty($xml->xpath($xpath0."/ike/crypto-profiles"))){
            $thedevicegroup0=$xml->xpath($xpath0."/ike/crypto-profiles");
            $thedevicegroup = $thedevicegroup0[0];

            if (isset($thedevicegroup->{'global-protect-app-crypto-profiles'})){
                $SA = $xml->xpath($xpath0."/ike/crypto-profiles/global-protect-app-crypto-profiles");
                unset($SA[0][0]);
            }
        }

        if ($api_call=="clean"){
            $xpath2 = addslashes($xpath0."/ike/crypto-profiles/global-protect-app-crypto-profiles");
            $xml_final = "";
            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Remove All GlobalProtect IPSec Crypto','GlobalProtect IPSec Crypto','GlobalProtect IPSec Crypto','$xml_final','$xpath2','delete');");
        }
        $message['code'] = true;
        $message['msg'] = "Removed All GlobalProtect IPSec Crypto.";
        return $message;
    }
}


function xml_network_ipsec_crypto_profiles($xml,$data){
    $project = $data['project'];
    $ispanorama = $data['ispanorama'];
    $version = $data['version'];
    $api_call=$data['api_call'];
    $projectdb = $data['projectdb'];
    $source = $data['source'];
    $template = $data['template'];
    $template_name=$data['template_name'];

//    if ($template==0){
//        return "Invalid TemplateID";
//    }

    if ($ispanorama==1){
        if(empty($xml->xpath("/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='" . $template_name . "']/config"))){
            $config=$xml->xpath("/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='" . $template_name . "']");
            if (count($config)>0){
                $config[0]->addChild("config");
                $localhost=$config[0]->config->addChild("entry");
                $localhost->addAttribute('name', 'localhost.localdomain');
                $localhost->addChild("network");
            }
            else{
                $message['code'] = false;
                $message['msg'] = "No Template.";
                return $message;
            }

        }
        $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='" . $template_name . "']/config/devices/entry[@name='localhost.localdomain']/network";
    }
    else{
        $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/network";
    }

    $xpath0 = $data['xpath0'];

    $getIPSECCrypto = $projectdb->query("SELECT * FROM ipsec_crypto_profiles WHERE source = '$source' AND template = '$template' AND name != '' GROUP BY name;");
    if ($getIPSECCrypto->num_rows > 0){

        if (empty($xml->xpath($xpath0))){
            // network node missing on the original config
            // we need to add it before adding any other child
            $xpath0_without_network = str_replace("/network","",$xpath0);
            $thedevicegroup0 = $xml->xpath($xpath0_without_network);
            $thedevicegroup0[0]->addChild("network");
        }

        if (empty($xml->xpath($xpath0."/ike"))){
            $thedevicegroup0 = $xml->xpath($xpath0);
            $thedevicegroup0[0]->addChild("ike");
        }

        if (empty($xml->xpath($xpath0."/ike/crypto-profiles"))){
            $thedevicegroup0=$xml->xpath($xpath0."/ike");
            $thedevicegroup0[0]->addChild("crypto-profiles");
        }

        if (empty($xml->xpath($xpath0."/ike/crypto-profiles/ipsec-crypto-profiles"))){
            $thedevicegroup0=$xml->xpath($xpath0."/ike/crypto-profiles");
        }
        else{
            $SA=$xml->xpath($xpath0."/ike/crypto-profiles/ipsec-crypto-profiles");
            unset($SA[0][0]);
            $thedevicegroup0=$xml->xpath($xpath0."/ike/crypto-profiles");
        }

        $thedevicegroup = $thedevicegroup0[0];

        if (!isset($thedevicegroup->{'ipsec-crypto-profiles'})){
            $thedevicegroup->addChild("ipsec-crypto-profiles");
        }
        $ipsec_crypto_xpath = $thedevicegroup->{'ipsec-crypto-profiles'};

        while ($dataIPSECC = $getIPSECCrypto->fetch_assoc()){
            $myname = $dataIPSECC['name'];
            $ipsec_encryption = $dataIPSECC['encryption'];
            $ipsec_hash = $dataIPSECC['hash'];
            $ipsec_dh_group = $dataIPSECC['dh_group'];
            $ipsec_protocol = $dataIPSECC['protocol'];
            $ipsec_seconds = $dataIPSECC['seconds'];
            $ipsec_minutes = $dataIPSECC['minutes'];
            $ipsec_hours = $dataIPSECC['hours'];
            $ipsec_days = $dataIPSECC['days'];
            $ipsec_kb = $dataIPSECC['kb'];
            $ipsec_mb = $dataIPSECC['mb'];
            $ipsec_gb = $dataIPSECC['gb'];
            $ipsec_tb = $dataIPSECC['tb'];

            $ipsec_crypto = $ipsec_crypto_xpath->addChild('entry');
            $ipsec_crypto->addAttribute('name', $myname);

            switch($ipsec_protocol){
                case 'ESP':
                    $ipsec_crypto->addChild("esp");
                    if ($ipsec_encryption != ""){
                        $ipsec_crypto->esp->addChild("encryption");
                        $ipsec_encryption_array = explode(",", $ipsec_encryption);
                        foreach($ipsec_encryption_array as $member_ike){
                            $ipsec_crypto->esp->encryption->addChild("member", $member_ike);
                        }
                    }
                    if ($ipsec_hash != ""){
                        $ipsec_crypto->esp->addChild("authentication");
                        $ipsec_hash_array = explode(",", $ipsec_hash);
                        foreach($ipsec_hash_array as $member_ike){
                            $ipsec_crypto->esp->authentication->addChild("member", $member_ike);
                        }
                    }
                    break;

                case 'AH':
                    $ipsec_crypto->addChild("ah");
                    if ($ipsec_hash != ""){
                        $ipsec_crypto->ah->addChild("authentication");
                        $ipsec_hash_array = explode(",", $ipsec_hash);
                        foreach($ipsec_hash_array as $member_ike){
                            $ipsec_crypto->ah->authentication->addChild("member", $member_ike);
                        }
                    }
                    break;
            }

            if ($ipsec_dh_group != ""){
                $ipsec_crypto->addChild("dh-group");
                $ipsec_crypto->{'dh-group'} = $ipsec_dh_group;
            }
            if ($ipsec_seconds != 0){
                $ipsec_crypto->addChild("lifetime");
                $ipsec_crypto->{'lifetime'}->seconds = $ipsec_seconds;
            }
            if ($ipsec_minutes != 0){
                $ipsec_crypto->addChild("lifetime");
                $ipsec_crypto->{'lifetime'}->minutes = $ipsec_minutes;
            }
            if ($ipsec_hours != 0){
                $ipsec_crypto->addChild("lifetime");
                $ipsec_crypto->{'lifetime'}->hours = $ipsec_hours;
            }
            if ($ipsec_days != 0){
                $ipsec_crypto->addChild("lifetime");
                $ipsec_crypto->{'lifetime'}->days = $ipsec_days;
            }

            if ($ipsec_kb != 0){
                $ipsec_crypto->addChild("lifesize");
                $ipsec_crypto->{'lifesize'}->kb = $ipsec_kb;
            }
            if ($ipsec_mb != 0){
                $ipsec_crypto->addChild("lifesize");
                $ipsec_crypto->{'lifesize'}->mb = $ipsec_mb;
            }
            if ($ipsec_gb != 0){
                $ipsec_crypto->addChild("lifesize");
                $ipsec_crypto->{'lifesize'}->gb = $ipsec_gb;
            }
            if ($ipsec_tb != 0){
                $ipsec_crypto->addChild("lifesize");
                $ipsec_crypto->{'lifesize'}->tb = $ipsec_tb;
            }
            if ($api_call=="single"){
                $xpath2 = addslashes($xpath0."/ike/crypto-profiles/ipsec-crypto-profiles/entry[@name='$myname']");
                $element=$thedevicegroup->{'ipsec-crypto-profiles'}->xpath("entry[@name='$myname']");
                $xml_final = addslashes($element[0]->asXML());
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','IPSEC Crypto Profile','IPSEC Crypto Profile','$xml_final','$xpath2','edit');");
            }
        }
        if ($api_call=="atomic"){
            $xpath2 = addslashes($xpath0."/ike/crypto-profiles/ipsec-crypto-profiles");
            $xml_final = addslashes($thedevicegroup->{'ipsec-crypto-profiles'}->asXML());
            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('IPSEC Crypto Profiles','IPSEC Crypto Profiles','IPSEC Crypto Profiles','$xml_final','$xpath2','edit');");
        }
    }
    else{
        if (!empty($xml->xpath($xpath0."/ike/crypto-profiles"))){
            $thedevicegroup0=$xml->xpath($xpath0."/ike/crypto-profiles");
            $thedevicegroup = $thedevicegroup0[0];
            if (isset($thedevicegroup->{'ipsec-crypto-profiles'})){
                $SA = $xml->xpath($xpath0."/ike/crypto-profiles/ipsec-crypto-profiles");
                unset($SA[0][0]);
            }
        }

        if ($api_call=="clean"){
            $xpath2 = addslashes($xpath0."/ike/crypto-profiles/ipsec-crypto-profiles");
            $xml_final = "";
            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Remove All IPSEC Crypto Profiles','IPSEC Crypto Profile','IPSEC Crypto Profile','$xml_final','$xpath2','delete');");
        }
        $message['code'] = true;
        $message['msg'] = "Removed All IPSEC Crypto Profiles.";
        return $message;
    }
}

# Network GATEWAY IKE
function xml_network_gateway_ike($xml,$data){
    $project = $data['project'];
    $ispanorama = $data['ispanorama'];
    $version = $data['version'];
    $api_call=$data['api_call'];
    $projectdb = $data['projectdb'];
    $source = $data['source'];
    $template = $data['template'];
    $template_name=$data['template_name'];

//    if ($template==0){
//        return "Invalid TemplateID";
//    }
    
    if ($ispanorama==1){
        if(empty($xml->xpath("/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='" . $template_name . "']/config"))){
            $config=$xml->xpath("/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='" . $template_name . "']");
            if (count($config)>0){
                $config[0]->addChild("config");
                $localhost=$config[0]->config->addChild("entry");
                $localhost->addAttribute('name', 'localhost.localdomain');
                $localhost->addChild("network");
            }
            else{
                $message['code'] = false;
                $message['msg'] = "No Template.";
                return $message;
            }

        }
        $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='" . $template_name . "']/config/devices/entry[@name='localhost.localdomain']/network";
    }
    else{
        $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/network";
    }

    $xpath0 = $data['xpath0'];

    $getIKEGateways = $projectdb->query("SELECT *  FROM ike_gateways_profiles WHERE source = '$source' AND template = '$template' AND name != '' GROUP BY name;");
    if ($getIKEGateways->num_rows > 0){

        if (empty($xml->xpath($xpath0."/ike"))){
            $thedevicegroup0=$xml->xpath($xpath0);
            $thedevicegroup0[0]->addChild("ike");
        }

        if (empty($xml->xpath($xpath0."/ike/gateway"))){
            $thedevicegroup0=$xml->xpath($xpath0."/ike");
        }
        else{
            $SA=$xml->xpath($xpath0."/ike/gateway");
            unset($SA[0][0]);
            $thedevicegroup0=$xml->xpath($xpath0."/ike");
        }

        $thedevicegroup = $thedevicegroup0[0];

        if (!isset($thedevicegroup->gateway)){
            $thedevicegroup->addChild("gateway");
        }
        $ike_gateways_xpath = $thedevicegroup->gateway;

        while ($dataIKEGat = $getIKEGateways->fetch_assoc()){
            $myname = $dataIKEGat['name'];
            $ike_gat_version = $dataIKEGat['version'];
            $ike_gat_dpd_ikev1 = $dataIKEGat['dpd_ikev1'];
            $ike_gat_ike_interval_ikev1 = $dataIKEGat['ike_interval_ikev1'];
            $ike_gat_retry_ikev1 = $dataIKEGat['retry_ikev1'];
            $ike_gat_ike_crypto_profile_ikev1 = $dataIKEGat['ike_crypto_profile_ikev1'];
            $ike_gat_exchange_mode_ikev1 = $dataIKEGat['exchange_mode_ikev1'];
            $ike_gat_dpd_ikev2 = $dataIKEGat['dpd_ikev2'];
            $ike_gat_ike_interval_ikev2 = $dataIKEGat['ike_interval_ikev2'];
            $ike_gat_ike_crypto_profile_ikev2 = $dataIKEGat['ike_crypto_profile_ikev2'];
            $ike_gat_require_cookie_ikev2 = $dataIKEGat['require_cookie_ikev2'];
            $ike_gat_local_address_ip = $dataIKEGat['local_address_ip'];
            $ike_gat_interface = $dataIKEGat['interface'];
            $ike_gat_type_authentication = $dataIKEGat['type_authentication'];
            $ike_gat_pre_shared_key = $dataIKEGat['pre_shared_key'];
            $ike_gat_allow_id_payload_mismatch = $dataIKEGat['allow_id_payload_mismatch'];
            $ike_gat_local_certificate = $dataIKEGat['local_certificate'];
            $ike_gat_certificate_profile = $dataIKEGat['certificate_profile'];
            $ike_gat_strict_validation_revocation = $dataIKEGat['strict_validation_revocation'];
            $ike_gat_hash_and_url = $dataIKEGat['hash_and_url'];
            $ike_gat_base_url = $dataIKEGat['base_url'];
            $ike_gat_nat_traversal = $dataIKEGat['nat_traversal'];
            $ike_gat_passive_mode = $dataIKEGat['passive_mode'];
            $ike_gat_fragmentation = $dataIKEGat['fragmentation'];
            $ike_gat_peer_ip_type = $dataIKEGat['peer_ip_type'];
            $ike_gat_peer_ip_address = $dataIKEGat['peer_ip_address'];
            $ike_gat_local_id = $dataIKEGat['local_id'];
            $ike_gat_local_id_type = $dataIKEGat['local_id_type'];
            $ike_gat_peer_id = $dataIKEGat['peer_id'];
            $ike_gat_peer_id_type = $dataIKEGat['peer_id_type'];
            $ike_gat_peer_id_matching = $dataIKEGat['peer_id_matching'];
            $ike_gat_address_type = $dataIKEGat['address_type'];

            $ike_gateways = $ike_gateways_xpath->addChild('entry');
            $ike_gateways->addAttribute('name', $myname);

            if($ike_gat_dpd_ikev1 != ""){
                $ike_gateways->addChild("protocol");
                $ike_gateways->protocol->addChild("ikev1");
                $ike_gateways->protocol->ikev1->addChild("dpd");
                $ike_gateways->protocol->ikev1->dpd->enable = $ike_gat_dpd_ikev1;

                if($ike_gat_dpd_ikev1 == "yes"){
                    $ike_gateways->protocol->ikev1->dpd->interval = $ike_gat_ike_interval_ikev1;
                    $ike_gateways->protocol->ikev1->dpd->retry = $ike_gat_retry_ikev1;
                }

                if(($ike_gat_ike_crypto_profile_ikev1 != "") && ($ike_gat_ike_crypto_profile_ikev1 != "default")){
                    $ike_gateways->protocol->ikev1->{'ike-crypto-profile'} = $ike_gat_ike_crypto_profile_ikev1;
                }

                if($ike_gat_exchange_mode_ikev1 != ""){
                    $ike_gateways->protocol->ikev1->{'exchange-mode'} = $ike_gat_exchange_mode_ikev1;
                }
            }

            // IKE V2 PARA LA VERSIÓN 7
            if($version >= 7){
                if($ike_gat_dpd_ikev2 != ""){

                    $ike_gateways->protocol->ikev2->dpd->enable = $ike_gat_dpd_ikev2;
                    $ike_gateways->protocol->ikev2->dpd->interval = $ike_gat_ike_interval_ikev2;

                    if($ike_gat_ike_crypto_profile_ikev2 != ""){
                        $ike_gateways->protocol->ikev2->{'ike-crypto-profile'} = $ike_gat_ike_crypto_profile_ikev2;
                    }

                    if($ike_gat_require_cookie_ikev2 != ""){
                        $ike_gateways->protocol->ikev2->{'require-cookie'} = $ike_gat_require_cookie_ikev2;
                    }

                    if($ike_gat_version != ""){
                        $ike_gateways->protocol->version = $ike_gat_version;
                    }

                }
            }

            if($ike_gat_interface != ""){
                $ike_gateways->addChild("local-address");
                $ike_gateways->{'local-address'}->interface = $ike_gat_interface;
                if($ike_gat_local_address_ip != ""){
                    $ike_gateways->{'local-address'}->ip = $ike_gat_local_address_ip;
                }
            }

            if($ike_gat_type_authentication == "pre-shared-key"){
                $ike_gateways->addChild("authentication");
                $ike_gateways->authentication->{'pre-shared-key'}->key = $ike_gat_pre_shared_key;
            }
            elseif($ike_gat_type_authentication == "certificate"){
                if($version < 7){

                    $ike_gateways->addChild("authentication");

                    if($ike_gat_allow_id_payload_mismatch == "yes"){
                        $ike_gateways->authentication->certificate->{'allow-id-payload-mismatch'} = $ike_gat_allow_id_payload_mismatch;
                    }
                    $ike_gateways->authentication->certificate->{'local-certificate'} = $ike_gat_local_certificate;
                    $ike_gateways->authentication->certificate->{'certificate-profile'} = $ike_gat_certificate_profile;

                    if($ike_gat_strict_validation_revocation == "yes"){
                        $ike_gateways->authentication->certificate->{'strict-validation-revocation'} = $ike_gat_strict_validation_revocation;
                    }
                }
                else{
                    // Version 7
                    $ike_gateways->addChild("authentication");

                    if($ike_gat_local_certificate != ""){
                        $ike_gateways->authentication->certificate->{'local-certificate'}->name = $ike_gat_local_certificate;

                        if($ike_gat_hash_and_url == "yes"){
                            $ike_gateways->authentication->certificate->{'local-certificate'}->{'hash-and-url'}->enable = $ike_gat_hash_and_url;
                            $ike_gateways->authentication->certificate->{'local-certificate'}->{'hash-and-url'}->{'base-url'} = $ike_gat_base_url;
                        }
                    }
                    if($ike_gat_allow_id_payload_mismatch == "yes"){
                        $ike_gateways->authentication->certificate->{'allow-id-payload-mismatch'} = $ike_gat_allow_id_payload_mismatch;
                    }
                    $ike_gateways->authentication->certificate->{'certificate-profile'} = $ike_gat_certificate_profile;

                    if($ike_gat_strict_validation_revocation == "yes"){
                        $ike_gateways->authentication->certificate->{'strict-validation-revocation'} = $ike_gat_strict_validation_revocation;
                    }
                }
            }

            if($ike_gat_nat_traversal != ""){
                $ike_gateways->addChild("protocol-common");
                $ike_gateways->{'protocol-common'}->{'nat-traversal'}->enable = $ike_gat_nat_traversal;
                if($ike_gat_passive_mode == "yes"){
                    $ike_gateways->{'protocol-common'}->{'passive-mode'} = $ike_gat_passive_mode;
                }
                if ($version > 5) {
                    if($ike_gat_fragmentation == ""){
                        $ike_gat_fragmentation = "no";
                    }
                    $ike_gateways->{'protocol-common'}->fragmentation->enable = $ike_gat_fragmentation;
                }

            }

            if($ike_gat_peer_ip_type == "static"){
                $ike_gateways->addChild("peer-address");
                $ike_gateways->{'peer-address'}->ip = $ike_gat_peer_ip_address;
            }else{
                $ike_gateways->addChild("peer-address");
                $ike_gateways->{'peer-address'}->addChild("dynamic");
            }

            if($ike_gat_local_id != ""){
                $ike_gateways->addChild("local-id");
                $ike_gateways->{'local-id'}->id = $ike_gat_local_id;
                $ike_gateways->{'local-id'}->type = $ike_gat_local_id_type;
            }

            if($ike_gat_peer_id != ""){
                $ike_gateways->addChild("peer-id");
                $ike_gateways->{'peer-id'}->id = $ike_gat_peer_id;
                $ike_gateways->{'peer-id'}->type = $ike_gat_peer_id_type;
                if($ike_gat_peer_id_matching != ""){
                    $ike_gateways->{'peer-id'}->matching = $ike_gat_peer_id_matching;
                }
            }

            // Version 7
            if($ike_gat_address_type == "ipv6"){
                $ike_gateways->ipv6 = "yes";
            }
            if ($api_call=="single"){
                $xpath2 = addslashes($xpath0."/ike/gateway/entry[@name='$myname']");
                $element=$thedevicegroup->gateway->xpath("entry[@name='$myname']");
                $xml_final = addslashes($element[0]->asXML());
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','IKE Gateway','IKE Gateway','$xml_final','$xpath2','edit');");
            }
        }
        if ($api_call=="atomic"){
            $xpath2 = addslashes($xpath0."/ike/gateway");
            $xml_final = addslashes($thedevicegroup->gateway->asXML());
            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('IKE Gateways','IKE Gateways','IKE Gateways','$xml_final','$xpath2','edit');");
        }
    }
    else {
        if (!empty($xml->xpath($xpath0 . "/ike"))) {
            $thedevicegroup0 = $xml->xpath($xpath0 . "/ike");
            $thedevicegroup = $thedevicegroup0[0];
            if (isset($thedevicegroup->gateway)) {
                $SA = $xml->xpath($xpath0 . "/ike/gateway");
                unset($SA[0][0]);
            }
        }
        if ($api_call=="clean"){
            $xpath2 = addslashes($xpath0."/ike/gateway");
            $xml_final = "";
            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Remove All IKE Gateways','IKE Gateways','IKE Gateways','$xml_final','$xpath2','delete');");
        }
        $message['code'] = true;
        $message['msg'] = "Removed All IKE Gateways.";
        return $message;
    }
}

# Network Tunnel IPSEC
function xml_network_tunnel_ipsec($xml,$data){
    $project = $data['project'];
    $ispanorama = $data['ispanorama'];
    $version = $data['version'];
    $api_call=$data['api_call'];
    $projectdb = $data['projectdb'];
    $source = $data['source'];
    $template = $data['template'];
    $template_name=$data['template_name'];

//    if ($template==0){
//        return "Invalid TemplateID";
//    }

    if ($ispanorama==1){
        if(empty($xml->xpath("/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='" . $template_name . "']/config"))){
            $config=$xml->xpath("/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='" . $template_name . "']");
            if (count($config)>0){
                $config[0]->addChild("config");
                $localhost=$config[0]->config->addChild("entry");
                $localhost->addAttribute('name', 'localhost.localdomain');
                $localhost->addChild("network");
            }
            else{
                $message['code'] = false;
                $message['msg'] = "No Template.";
                return $message;
            }

        }
        $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='" . $template_name . "']/config/devices/entry[@name='localhost.localdomain']/network";
    }
    else{
        $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/network";
    }

    $xpath0 = $data['xpath0'];

    $getIPSecTunnel = $projectdb->query("SELECT * FROM ipsec_tunnel WHERE source = '$source' AND template = '$template' AND name != '' GROUP BY name;");
    if ($getIPSecTunnel->num_rows > 0){

        if (empty($xml->xpath($xpath0."/tunnel"))){
            $thedevicegroup0=$xml->xpath($xpath0);
            $thedevicegroup0[0]->addChild("tunnel");
        }

        if (empty($xml->xpath($xpath0."/tunnel/ipsec"))){
            $thedevicegroup0=$xml->xpath($xpath0."/tunnel");
        }
        else{
            $SA=$xml->xpath($xpath0."/tunnel/ipsec");
            unset($SA[0][0]);
            $thedevicegroup0=$xml->xpath($xpath0."/tunnel");

        }
        $thedevicegroup = $thedevicegroup0[0];

        if (!isset($thedevicegroup->ipsec)){
            $thedevicegroup->addChild("ipsec");
        }
        $ike_ipsec_tunnel_xpath = $thedevicegroup->ipsec;

        while ($dataIPSecTunnel = $getIPSecTunnel->fetch_assoc()){

            $myname = $dataIPSecTunnel['name'];
            $ipsec_tun_id = $dataIPSecTunnel['id'];
            $ipsec_tun_anti_replay = $dataIPSecTunnel['anti_replay'];
            $ipsec_tun_copy_tos = $dataIPSecTunnel['copy_tos'];
            $ipsec_tun_tunnel_monitor = $dataIPSecTunnel['tunnel_monitor'];
            $ipsec_tun_destination_ip = $dataIPSecTunnel['destination_ip'];
            $ipsec_tun_tunnel_monitor_profile = $dataIPSecTunnel['tunnel_monitor_profile'];
            $ipsec_tun_tunnel_interface = $dataIPSecTunnel['tunnel_interface'];
            $ipsec_tun_address_type = $dataIPSecTunnel['address_type'];
            $ipsec_tun_type_tunnel = $dataIPSecTunnel['type_tunnel'];
            $ipsec_tun_ike_gateway = $dataIPSecTunnel['ike_gateway'];
            $ipsec_tun_ipsec_crypto_profile = $dataIPSecTunnel['ipsec_crypto_profile'];
            $ipsec_tun_protocol = $dataIPSecTunnel['protocol'];
            $ipsec_tun_authentication = $dataIPSecTunnel['authentication'];
            $ipsec_tun_key_auth = $dataIPSecTunnel['key_auth'];
            $ipsec_tun_encryption = $dataIPSecTunnel['encryption'];
            $ipsec_tun_key_encry = $dataIPSecTunnel['key_encry'];
            $ipsec_tun_local_address_ip = $dataIPSecTunnel['local_address_ip'];
            $ipsec_tun_interface = $dataIPSecTunnel['interface'];
            $ipsec_tun_peer_ip_address = $dataIPSecTunnel['peer_ip_address'];
            $ipsec_tun_local_spi = $dataIPSecTunnel['local_spi'];
            $ipsec_tun_remote_spi = $dataIPSecTunnel['remote_spi'];
            $ipsec_tun_external_ca = $dataIPSecTunnel['external_ca'];
            $ipsec_tun_certificate_profile = $dataIPSecTunnel['certificate_profile'];
            $ipsec_tun_local_certificate = $dataIPSecTunnel['local_certificate'];
            $ipsec_tun_publish_connected_routes = $dataIPSecTunnel['publish_connected_routes'];
            $ipsec_tun_portal_address = $dataIPSecTunnel['portal_address'];
            $ipsec_tun_publish_routes = $dataIPSecTunnel['publish_routes'];
            $ipsec_tun_disabled = $dataIPSecTunnel['disabled'];

            $ipsec_tunnel = $ike_ipsec_tunnel_xpath->addChild('entry');
            $ipsec_tunnel->addAttribute('name', $myname);

            if($ipsec_tun_disabled == "yes"){
                $ipsec_tunnel->addChild("disabled");
                $ipsec_tunnel->disabled="yes";
            }
            # Auto Key
            if($ipsec_tun_type_tunnel == "auto-key"){

                $ipsec_tunnel->addChild("auto-key");

                if($ipsec_tun_ike_gateway != ""){
                    $ipsec_tunnel->{'auto-key'}->addChild("ike-gateway");
                    $ipsec_tunnel->{'auto-key'}->{'ike-gateway'}->addChild('entry')->addAttribute('name', $ipsec_tun_ike_gateway);
                }

                // Mirar si hay Proxy ID type = v4
                $getProxyID = $projectdb->query("SELECT * FROM proxy_id_ipsec_tunnel WHERE ipsec_tunnel_id = '$ipsec_tun_id' AND name != '' AND type = 'v4' AND template = '$template' AND source = '$source';");
                if ($getProxyID->num_rows > 0){

                    $ipsec_tunnel->{'auto-key'}->addChild("proxy-id");
                    $ike_ipsec_tunnel_xpath_proxy_id = $ipsec_tunnel->{'auto-key'}->{'proxy-id'};

                    while($dataPI = $getProxyID->fetch_assoc()){

                        $name_proxy_id = $dataPI['name'];
                        $protocol_proxy_id = $dataPI['protocol'];
                        $local_port_proxy_id = $dataPI['local_port'];
                        $remote_port_proxy_id = $dataPI['remote_port'];
                        $number_proxy_id = $dataPI['number'];
                        $local_proxy_id = $dataPI['local'];
                        $remote_proxy_id = $dataPI['remote'];
                        $type_proxy_id = $dataPI['type'];

                        $ipsec_tunnel_proxy_id = $ike_ipsec_tunnel_xpath_proxy_id->addChild('entry');
                        $ipsec_tunnel_proxy_id->addAttribute('name', $name_proxy_id);

                        if ($protocol_proxy_id == "TCP"){
                            $ipsec_tunnel_proxy_id->addChild("protocol");
                            $ipsec_tunnel_proxy_id->protocol->addChild("tcp");
                            //$ipsec_tunnel->{'auto-key'}->{'proxy-id'}->protocol->addChild("tcp");
                            if($local_port_proxy_id == ""){
                                $local_port_proxy_id = 0;
                            }
                            if($remote_port_proxy_id == ""){
                                $remote_port_proxy_id = 0;
                            }
                            $ipsec_tunnel_proxy_id->protocol->tcp->{'local-port'} = $local_port_proxy_id;
                            $ipsec_tunnel_proxy_id->protocol->tcp->{'remote-port'} = $remote_port_proxy_id;
                        }
                        elseif($protocol_proxy_id == "Number"){
                            $ipsec_tunnel_proxy_id->addChild("protocol");
                            $ipsec_tunnel_proxy_id->protocol->addChild("number");
                            $ipsec_tunnel_proxy_id->protocol->number = $number_proxy_id;
                        }
                        elseif($protocol_proxy_id == "Any"){
                            $ipsec_tunnel_proxy_id->addChild("protocol");
                            $ipsec_tunnel_proxy_id->protocol->addChild("any");;
                        }
                        elseif($protocol_proxy_id == "UDP"){
                            $ipsec_tunnel_proxy_id->addChild("protocol");
                            $ipsec_tunnel_proxy_id->protocol->addChild("udp");
                            if($local_port_proxy_id == ""){
                                $local_port_proxy_id = 0;
                            }
                            if($remote_port_proxy_id == ""){
                                $remote_port_proxy_id = 0;
                            }
                            $ipsec_tunnel_proxy_id->protocol->udp->{'local-port'} = $local_port_proxy_id;
                            $ipsec_tunnel_proxy_id->protocol->udp->{'remote-port'} = $remote_port_proxy_id;
                        }

                        if($local_proxy_id != ""){
                            $ipsec_tunnel_proxy_id->addChild("local");
                            $ipsec_tunnel_proxy_id->local = $local_proxy_id;
                        }
                        if($remote_proxy_id != ""){
                            $ipsec_tunnel_proxy_id->addChild("remote");
                            $ipsec_tunnel_proxy_id->remote = $remote_proxy_id;
                        }
                    }
                }

                // Mirar si hay Proxy ID type = v6
                //$getProxyID = $projectdb->query("SELECT name, protocol, local_port, remote_port, number, local, remote, type FROM proxy_id_ipsec_tunnel WHERE ipsec_tunnel_id = '$ipsec_tun_id' AND name != '' AND type = 'v6' AND template = '$template' AND source = '$source';");
                $getProxyID = $projectdb->query("SELECT name, protocol, local_port, remote_port, number, local, remote, type FROM proxy_id_ipsec_tunnel WHERE ipsec_tunnel_id = '$ipsec_tun_id' AND name != '' AND type = 'v6' ;");
                if ($getProxyID->num_rows > 0){

                    $ipsec_tunnel->{'auto-key'}->addChild("proxy-id-v6");
                    $ike_ipsec_tunnel_xpath_proxy_id_v6 = $ipsec_tunnel->{'auto-key'}->{'proxy-id-v6'};

                    while($dataPI = $getProxyID->fetch_assoc()){

                        $name_proxy_id = $dataPI['name'];
                        $protocol_proxy_id = $dataPI['protocol'];
                        $local_port_proxy_id = $dataPI['local_port'];
                        $remote_port_proxy_id = $dataPI['remote_port'];
                        $number_proxy_id = $dataPI['number'];
                        $local_proxy_id = $dataPI['local'];
                        $remote_proxy_id = $dataPI['remote'];
                        $type_proxy_id = $dataPI['type'];

                        $ipsec_tunnel_proxy_id_v6 = $ike_ipsec_tunnel_xpath_proxy_id_v6->addChild('entry');
                        $ipsec_tunnel_proxy_id_v6->addAttribute('name', $name_proxy_id);

                        if ($protocol_proxy_id == "TCP"){
                            $ipsec_tunnel_proxy_id_v6->addChild("protocol");
                            $ipsec_tunnel_proxy_id_v6->protocol->addChild("tcp");
                            if($local_port_proxy_id == ""){
                                $local_port_proxy_id = 0;
                            }
                            if($remote_port_proxy_id == ""){
                                $remote_port_proxy_id = 0;
                            }
                            $ipsec_tunnel_proxy_id_v6->protocol->tcp->{'local-port'} = $local_port_proxy_id;
                            $ipsec_tunnel_proxy_id_v6->protocol->tcp->{'remote-port'} = $remote_port_proxy_id;
                        }
                        elseif($protocol_proxy_id == "Number"){
                            $ipsec_tunnel_proxy_id_v6->addChild("protocol");
                            $ipsec_tunnel_proxy_id_v6->protocol->addChild("number");
                            $ipsec_tunnel_proxy_id_v6->protocol->number = $number_proxy_id;
                        }
                        elseif($protocol_proxy_id == "Any"){
                            $ipsec_tunnel_proxy_id_v6->addChild("protocol");
                            $ipsec_tunnel_proxy_id_v6->protocol->addChild("any");;
                        }
                        elseif($protocol_proxy_id == "UDP"){
                            $ipsec_tunnel_proxy_id_v6->addChild("protocol");
                            $ipsec_tunnel_proxy_id_v6->protocol->addChild("udp");
                            if($local_port_proxy_id == ""){
                                $local_port_proxy_id = 0;
                            }
                            if($remote_port_proxy_id == ""){
                                $remote_port_proxy_id = 0;
                            }
                            $ipsec_tunnel_proxy_id_v6->protocol->udp->{'local-port'} = $local_port_proxy_id;
                            $ipsec_tunnel_proxy_id_v6->protocol->udp->{'remote-port'} = $remote_port_proxy_id;
                        }

                        if($local_proxy_id != ""){
                            $ipsec_tunnel_proxy_id_v6->addChild("local");
                            $ipsec_tunnel_proxy_id_v6->local = $local_proxy_id;
                        }
                        if($remote_proxy_id != ""){
                            $ipsec_tunnel_proxy_id_v6->addChild("remote");
                            $ipsec_tunnel_proxy_id_v6->remote = $remote_proxy_id;
                        }
                    }
                }

                if($ipsec_tun_ipsec_crypto_profile != ""){
                    $ipsec_tunnel->{'auto-key'}->addChild("ipsec-crypto-profile");
                    $ipsec_tunnel->{'auto-key'}->{'ipsec-crypto-profile'} = $ipsec_tun_ipsec_crypto_profile;
                }
            } # Manual Key
            elseif ($ipsec_tun_type_tunnel == "manual-key"){

                $ipsec_tunnel->addChild("manual-key");

                if($ipsec_tun_protocol == "ESP"){

                    $ipsec_tunnel->{'manual-key'}->addChild("esp");

                    if($ipsec_tun_authentication == "none"){
                        $ipsec_tunnel->{'manual-key'}->esp->addChild("authentication");
                        $ipsec_tunnel->{'manual-key'}->esp->authentication->addChild("none");
                    }else{
                        //authentication->md5->key
                        $ipsec_tunnel->{'manual-key'}->esp->addChild("authentication");
                        $ipsec_tunnel->{'manual-key'}->esp->authentication->addChild($ipsec_tun_authentication);
                        $ipsec_tunnel->{'manual-key'}->esp->authentication->$ipsec_tun_authentication->key = $ipsec_tun_key_auth;
                    }

                    if($ipsec_tun_encryption != ""){
                        $ipsec_tunnel->{'manual-key'}->esp->addChild("encryption");
                        $ipsec_tunnel->{'manual-key'}->esp->encryption->algorithm = $ipsec_tun_encryption;

                        if($ipsec_tun_key_encry != ""){
                            $ipsec_tunnel->{'manual-key'}->esp->encryption->key = $ipsec_tun_key_encry;
                        }
                    }
                }

                if($ipsec_tun_protocol == "AH"){

                    $ipsec_tunnel->{'manual-key'}->addChild("ah");

                    if($ipsec_tun_authentication == "none"){
                        $ipsec_tunnel->{'manual-key'}->ah->addChild("authentication");
                        $ipsec_tunnel->{'manual-key'}->ah->authentication->addChild("none");
                    }else{
                        //authentication->md5->key
                        $ipsec_tunnel->{'manual-key'}->ah->addChild("authentication");
                        $ipsec_tunnel->{'manual-key'}->ah->authentication->addChild($ipsec_tun_authentication);
                        $ipsec_tunnel->{'manual-key'}->ah->authentication->$ipsec_tun_authentication->key = $ipsec_tun_key_auth;
                    }
                }

                if($ipsec_tun_interface != ""){
                    $ipsec_tunnel->{'manual-key'}->addChild("local-address");
                    if(($ipsec_tun_local_address_ip != "") && ($ipsec_tun_local_address_ip != "None")){
                        $ipsec_tunnel->{'manual-key'}->{'local-address'}->ip = $ipsec_tun_local_address_ip;
                    }
                    $ipsec_tunnel->{'manual-key'}->{'local-address'}->interface = $ipsec_tun_interface;
                }

                if($ipsec_tun_peer_ip_address != ""){
                    $ipsec_tunnel->{'manual-key'}->addChild("peer-address");
                    $ipsec_tunnel->{'manual-key'}->{'peer-address'}->ip = $ipsec_tun_peer_ip_address;
                }

                if($ipsec_tun_local_spi != ""){
                    $ipsec_tunnel->{'manual-key'}->{'local-spi'} = $ipsec_tun_local_spi;
                }

                if($ipsec_tun_remote_spi != ""){
                    $ipsec_tunnel->{'manual-key'}->{'remote-spi'} = $ipsec_tun_remote_spi;
                }

            } # Global Protect Satellite
            elseif ($ipsec_tun_type_tunnel == "global-protect-satellite"){

                $ipsec_tunnel->addChild("global-protect-satellite");

                if($ipsec_tun_publish_connected_routes == "yes"){
                    $ipsec_tunnel->{'global-protect-satellite'}->addChild("publish-connected-routes");
                    $ipsec_tunnel->{'global-protect-satellite'}->{'publish-connected-routes'}->enable = $ipsec_tun_publish_connected_routes;
                }

                if($ipsec_tun_interface != ""){
                    $ipsec_tunnel->{'global-protect-satellite'}->addChild("local-address");
                    if(($ipsec_tun_local_address_ip != "") && ($ipsec_tun_local_address_ip != "None")){
                        $ipsec_tunnel->{'global-protect-satellite'}->{'local-address'}->ip = $ipsec_tun_local_address_ip;
                    }
                    $ipsec_tunnel->{'global-protect-satellite'}->{'local-address'}->interface = $ipsec_tun_interface;
                }

                if($ipsec_tun_portal_address != ""){
                    $ipsec_tunnel->{'global-protect-satellite'}->{'portal-address'} = $ipsec_tun_portal_address;
                }

                if($ipsec_tun_publish_routes != ""){
                    $ipsec_tunnel->{'global-protect-satellite'}->addChild("publish-routes");
                    $ipsec_tun_publish_routes_array = explode(",", $ipsec_tun_publish_routes);
                    foreach($ipsec_tun_publish_routes_array as $member_publish){
                        $ipsec_tunnel->{'global-protect-satellite'}->{'publish-routes'}->addChild("member", $member_publish);
                    }
                }

                if($ipsec_tun_external_ca == "yes"){
                    $ipsec_tunnel->{'global-protect-satellite'}->addChild("external-ca");
                    if($ipsec_tun_certificate_profile != ""){
                        $ipsec_tunnel->{'global-protect-satellite'}->{'external-ca'}->{'certificate-profile'} = $ipsec_tun_certificate_profile;
                    }
                    if($ipsec_tun_local_certificate != ""){
                        $ipsec_tunnel->{'global-protect-satellite'}->{'external-ca'}->{'local-certificate'} = $ipsec_tun_local_certificate;
                    }
                }

            }

            if($ipsec_tun_tunnel_monitor != ""){
                if($ipsec_tun_tunnel_monitor == "on"){
                    $ipsec_tun_tunnel_monitor = "yes";
                }
                $ipsec_tunnel->addChild("tunnel-monitor");
                $ipsec_tunnel->{'tunnel-monitor'}->enable = $ipsec_tun_tunnel_monitor;

                if($ipsec_tun_destination_ip != ""){
                    $ipsec_tunnel->{'tunnel-monitor'}->{'destination-ip'} = $ipsec_tun_destination_ip;
                }

                if($ipsec_tun_tunnel_monitor_profile != ""){
                    $ipsec_tunnel->{'tunnel-monitor'}->{'tunnel-monitor-profile'} = $ipsec_tun_tunnel_monitor_profile;
                }
            }

            if($ipsec_tun_copy_tos == "yes"){
                $ipsec_tunnel->{'copy-tos'} = $ipsec_tun_copy_tos;
            }

            // Version 7
            if($ipsec_tun_address_type == "ipv6"){
                $ipsec_tunnel->ipv6 = "yes";
            }

            if($ipsec_tun_tunnel_interface != ""){
                $ipsec_tunnel->{'tunnel-interface'} = $ipsec_tun_tunnel_interface;
            }

            if($ipsec_tun_anti_replay == "yes"){
                $ipsec_tunnel->{'anti-replay'} = $ipsec_tun_anti_replay;
            }
            if ($api_call=="single"){
                $xpath2 = addslashes($xpath0."/tunnel/ipsec/entry[@name='$myname']");
                $element=$thedevicegroup->ipsec->xpath("entry[@name='$myname']");
                $xml_final = addslashes($element[0]->asXML());
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','IPSEC Tunnel','IPSEC Tunnel','$xml_final','$xpath2','edit');");
            }
        }
        if ($api_call=="atomic"){
            $xpath2 = addslashes($xpath0."/tunnel/ipsec");
            $xml_final = addslashes($thedevicegroup->ipsec->asXML());
            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('IPSEC Tunnels','IPSEC Tunnels','IPSEC Tunnels','$xml_final','$xpath2','edit');");
        }
    }
    else{
        if (!empty($xml->xpath($xpath0."/tunnel"))){
            $thedevicegroup0=$xml->xpath($xpath0."/tunnel");
            $thedevicegroup = $thedevicegroup0[0];
            if (isset($thedevicegroup->ipsec)){
                $SA = $xml->xpath($xpath0."/tunnel/ipsec");
                unset($SA[0][0]);
            }
        }

        if ($api_call=="clean"){
            $xpath2 = addslashes($xpath0."/tunnel/ipsec");
            $xml_final = "";
            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Remove All IPSEC Tunnels','IPSEC Tunnels','IPSEC Tunnels','$xml_final','$xpath2','delete');");
        }
        $message['code'] = true;
        $message['msg'] = "Removed All IPSEC Tunnels.";
        return $message;
    }
}


# Network Tunnel IPSEC
function xml_network_tunnel_gre($xml,$data){
    $project = $data['project'];
    $ispanorama = $data['ispanorama'];
    $version = $data['version'];
    $api_call=$data['api_call'];
    $projectdb = $data['projectdb'];
    $source = $data['source'];
    $template = $data['template'];
    $template_name=$data['template_name'];

    if ($ispanorama==1){
        if(empty($xml->xpath("/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='" . $template_name . "']/config"))){
            $config=$xml->xpath("/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='" . $template_name . "']");
            if (count($config)>0){
                $config[0]->addChild("config");
                $localhost=$config[0]->config->addChild("entry");
                $localhost->addAttribute('name', 'localhost.localdomain');
                $localhost->addChild("network");
            }
            else{
                $message['code'] = false;
                $message['msg'] = "No Template.";
                return $message;
            }

        }
        $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='" . $template_name . "']/config/devices/entry[@name='localhost.localdomain']/network";
    }
    else{
        $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/network";
    }

    $xpath0 = $data['xpath0'];

    $getGRETunnel = $projectdb->query("SELECT * FROM gre_tunnel WHERE source = '$source' AND template = '$template' AND name != '' GROUP BY name;");
    if ($getGRETunnel->num_rows > 0){

        if (empty($xml->xpath($xpath0."/tunnel"))){
            $thedevicegroup0=$xml->xpath($xpath0);
            $thedevicegroup0[0]->addChild("tunnel");
        }

        if (empty($xml->xpath($xpath0."/tunnel/gre"))){
            $thedevicegroup0=$xml->xpath($xpath0."/tunnel");
        }
        else{
            $SA=$xml->xpath($xpath0."/tunnel/gre");
            unset($SA[0][0]);
            $thedevicegroup0=$xml->xpath($xpath0."/tunnel");

        }
        $thedevicegroup = $thedevicegroup0[0];

        if (!isset($thedevicegroup->gre)){
            $thedevicegroup->addChild("gre");
        }
        $gre_tunnel_xpath = $thedevicegroup->gre;

        while ($dataGRETunnel = $getGRETunnel->fetch_assoc()){

            $myname = $dataGRETunnel['name'];
            $ipsec_tun_id = $dataGRETunnel['id'];
            $local_address_ip = $dataGRETunnel['local_address_ip'];
            $interface = $dataGRETunnel['interface'];
            $peer_ip_address = $dataGRETunnel['peer_ip_address'];
            $keep_alive = $dataGRETunnel['keep_alive'];
            $keep_alive_interval = $dataGRETunnel['keep_alive_interval'];
            $keep_alive_retry = $dataGRETunnel['keep_alive_retry'];
            $keep_alive_hold_timer = $dataGRETunnel['keep_alive_hold_timer'];
            $tunnel_interface = $dataGRETunnel['tunnel_interface'];
            $copy_tos = $dataGRETunnel['copy_tos'];

            $gre_tunnel = $gre_tunnel_xpath->addChild('entry');
            $gre_tunnel->addAttribute('name', $myname);

            if($local_address_ip != ""){
                $gre_tunnel->addChild("local-address");
                $gre_tunnel->{'local-address'}->ip = $local_address_ip;
                $gre_tunnel->{'local-address'}->interface = $interface;
            }

            if($peer_ip_address != ""){
                $gre_tunnel->addChild("peer-address");
                $gre_tunnel->{'peer-address'}->ip = $peer_ip_address;
            }

            $gre_tunnel->addChild("keep-alive");
            $gre_tunnel->{'keep-alive'}->enable = $keep_alive;

            if($keep_alive == "yes"){
                $gre_tunnel->{'keep-alive'}->interval = $keep_alive_interval;
                $gre_tunnel->{'keep-alive'}->retry = $keep_alive_retry;
                $gre_tunnel->{'keep-alive'}->{'hold-timer'} = $keep_alive_hold_timer;
            }

            if($tunnel_interface != ""){
                $gre_tunnel->{'tunnel-interface'} = $tunnel_interface;
            }

            if($copy_tos == "yes"){
                $gre_tunnel->{'copy-tos'} = "yes";
            }

            if ($api_call=="single"){
                $xpath2 = addslashes($xpath0."/tunnel/gre/entry[@name='$myname']");
                $element = $thedevicegroup->gre->xpath("entry[@name='$myname']");
                $xml_final = addslashes($element[0]->asXML());
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','GRE Tunnel','GRE Tunnel','$xml_final','$xpath2','edit');");
            }
        }
        if ($api_call=="atomic"){
            $xpath2 = addslashes($xpath0."/tunnel/gre");
            $xml_final = addslashes($thedevicegroup->gre->asXML());
            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('GRE Tunnels','GRE Tunnels','GRE Tunnels','$xml_final','$xpath2','edit');");
        }
    }
    else{
        if (!empty($xml->xpath($xpath0."/tunnel"))){
            $thedevicegroup0 = $xml->xpath($xpath0."/tunnel");
            $thedevicegroup = $thedevicegroup0[0];
            if (isset($thedevicegroup->gre)){
                $SA = $xml->xpath($xpath0."/tunnel/gre");
                unset($SA[0][0]);
            }
        }

        if ($api_call=="clean"){
            $xpath2 = addslashes($xpath0."/tunnel/gre");
            $xml_final = "";
            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Remove All GRE Tunnels','GRE Tunnels','GRE Tunnels','$xml_final','$xpath2','delete');");
        }
        $message['code'] = true;
        $message['msg'] = "Removed All GRE Tunnels.";
        return $message;
    }
}

# Network Virtual-Wire
function xml_network_vwire($xml,$data){
    $project = $data['project'];
    $ispanorama = $data['ispanorama'];
    $version = $data['version'];
    $api_call=$data['api_call'];
    $projectdb = $data['projectdb'];
    $source = $data['source'];
    $template = $data['template'];
    $template_name=$data['template_name'];

//    if ($template==0){
//        return "Invalid TemplateID";
//    }

    if ($ispanorama==1){
        if(empty($xml->xpath("/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='" . $template_name . "']/config"))){
            $config=$xml->xpath("/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='" . $template_name . "']");
            if (count($config)>0){
                $config[0]->addChild("config");
                $localhost=$config[0]->config->addChild("entry");
                $localhost->addAttribute('name', 'localhost.localdomain');
                $localhost->addChild("network");
            }
            else{
                $message['code'] = false;
                $message['msg'] = "No Template.";
                return $message;
            }

        }
        $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='" . $template_name . "']/config/devices/entry[@name='localhost.localdomain']/network";
    }
    else{
        $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/network";
    }

    $xpath0 = $data['xpath0'];

    $getVW = $projectdb->query("SELECT * FROM virtual_wires WHERE source='$source' AND template='$template';");
    //echo "SELECT * FROM virtual_wires WHERE source='$source' AND template='$template';\n";
    if ($getVW->num_rows > 0) {
        if (empty($xml->xpath($xpath0."/virtual-wire"))){
            $thedevicegroup0=$xml->xpath($xpath0);
        }
        else{
            $SA=$xml->xpath($xpath0."/virtual-wire");
            unset($SA[0][0]);
            $thedevicegroup0=$xml->xpath($xpath0);

        }
        $thedevicegroup = $thedevicegroup0[0];
        if (!isset($thedevicegroup->{'virtual-wire'})){
            $thedevicegroup->addChild("virtual-wire");
        }
        $theVW = $thedevicegroup->{'virtual-wire'};

        while ($getVRData = $getVW->fetch_assoc()) {
            $myname = $getVRData['name'];
            $multicast_firewalling = $getVRData['multicast_firewalling'];
            $tag_allowed = $getVRData['tag_allowed'];
            $link_state_pass_through = $getVRData['link_state_pass_through'];
            $interface1 = $getVRData['interface1'];
            $interface2 = $getVRData['interface2'];

            $vwire = $theVW->addChild('entry');
            $vwire->addAttribute('name', $myname);
            if ($link_state_pass_through != "") {
                $vwire->addChild("link-state-pass-through");
                $vwire->{'link-state-pass-through'}->addChild("enable", $link_state_pass_through);
            }
            if ($multicast_firewalling != "") {
                $vwire->addChild("multicast-firewalling");
                $vwire->{'multicast-firewalling'}->addChild("enable", $multicast_firewalling);
            }
            if ($tag_allowed != "") {
                $vwire->addchild("tag-allowed", $tag_allowed);
            }
            if ($interface1 != "") {
                $vwire->addChild("interface1", $interface1);
            }
            if ($interface2 != "") {
                $vwire->addChild("interface2", $interface2);
            }
            if ($api_call=="single"){
                $xpath2 = addslashes($xpath0."/virtual-wire/entry[@name='$myname']");
                $element=$thedevicegroup->{'virtual-wire'}->xpath("entry[@name='$myname']");
                $xml_final = addslashes($element[0]->asXML());
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','Virtual-Wire','Virtual-Wire','$xml_final','$xpath2','edit');");
            }
        }
        if ($api_call=="atomic"){
            $xpath2 = addslashes($xpath0."/virtual-wire");
            $xml_final = addslashes($thedevicegroup->{'virtual-wire'}->asXML());
            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Virtual-Wires','Virtual-Wires','Virtual-Wires','$xml_final','$xpath2','edit');");
        }
    }
    else{
        if (!empty($xml->xpath($xpath0."/virtual-wire"))) {
            $thedevicegroup0 = $xml->xpath($xpath0);
            $thedevicegroup = $thedevicegroup0[0];
            if (isset($thedevicegroup->{'virtual-wire'})){
                $SA = $xml->xpath($xpath0."/virtual-wire");
                unset($SA[0][0]);
            }
        }

        if ($api_call=="clean"){
            $xpath2 = addslashes($xpath0."/virtual-wire");
            $xml_final = "";
            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Remove All Virtual-Wires','Virtual-Wires','Virtual-Wires','$xml_final','$xpath2','delete');");
        }
        $message['code'] = true;
        $message['msg'] = "Removed All Virtual-Wires.";
        return $message;
    }
}

# Network VLAN
function xml_network_vlan($xml,$data){
    $project = $data['project'];
    $ispanorama = $data['ispanorama'];
    $version = $data['version'];
    $api_call=$data['api_call'];
    $projectdb = $data['projectdb'];
    $source = $data['source'];
    $template = $data['template'];
    $template_name=$data['template_name'];

//    if ($template==0){
//        return "Invalid TemplateID";
//    }

    if ($ispanorama==1){
        if(empty($xml->xpath("/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='" . $template_name . "']/config"))){
            $config=$xml->xpath("/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='" . $template_name . "']");
            if (count($config)>0){
                $config[0]->addChild("config");
                $localhost=$config[0]->config->addChild("entry");
                $localhost->addAttribute('name', 'localhost.localdomain');
                $localhost->addChild("network");
            }
            else{
                $message['code'] = false;
                $message['msg'] = "No Template.";
                return $message;
            }

        }

        $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='" . $template_name . "']/config/devices/entry[@name='localhost.localdomain']/network";
    }
    else{
        $data['xpath0'] = "/config/devices/entry[@name='localhost.localdomain']/network";
    }

    $xpath0 = $data['xpath0'];

    $getVW = $projectdb->query("SELECT * FROM vlans WHERE source='$source' AND template='$template' AND name != '' GROUP BY name;");
    //echo "SELECT * FROM vlans WHERE source='$source' AND template='$template' AND name != '' GROUP BY name;\n";
    if ($getVW->num_rows > 0) {

        if (empty($xml->xpath($xpath0."/vlan"))){
            $thedevicegroup0=$xml->xpath($xpath0);
        }
        else{
            $SA=$xml->xpath($xpath0."/vlan");
            unset($SA[0][0]);
            $thedevicegroup0=$xml->xpath($xpath0);

        }
        $thedevicegroup = $thedevicegroup0[0];

        if (!isset($thedevicegroup->vlan)){
            $thedevicegroup->addChild("vlan");
        }

        $theVW = $thedevicegroup->{'vlan'};

        while ($getVRData = $getVW->fetch_assoc()) {
            $myname = $getVRData['name'];
            $interface = $getVRData['interface'];
            $mac = $getVRData['mac'];
            $mac_interfaces = $getVRData['mac_interfaces'];
            $virtual_interface = $getVRData['virtual_interface'];
            $l3_forwarding = $getVRData['l3_forwarding'];

            $vwire = $theVW->addChild('entry');
            $vwire->addAttribute('name', $myname);
            if ($interface != "") {
                $vwire->addChild("interface");
                foreach (explode(",", $interface) as $key => $value) {
                    $vwire->interface->addChild("member", $value);
                }
            }

            if ($mac != "") {
                $index_array = 0;
                $interfaces_mac_array = explode(",", $mac_interfaces);

                $vlan_pad = $vwire->addChild("mac");

                foreach (explode(",", $mac) as $key => $value) {
                    $vlan_mac = $vlan_pad->addChild('entry');
                    $vlan_mac->addAttribute('name', $value);

                    $vlan_mac->interface = $interfaces_mac_array[$index_array];
                    $index_array ++;
                }
            }

            if($version > 5){
                if ($virtual_interface != "") {
                    $vwire->addChild("virtual-interface");
                    $vwire->{'virtual-interface'}->addChild("interface", $virtual_interface);
                }
            }
            else{
                $vwire->addChild("virtual-interface");
                $vwire->{'virtual-interface'}->addChild("l3-forwarding", $l3_forwarding);
                if ($virtual_interface != "") {
                    $vwire->{'virtual-interface'}->addChild("interface", $virtual_interface);
                }
            }
            if ($api_call=="single"){
                $xpath2 = addslashes($xpath0."/vlan/entry[@name='$myname']");
                $element=$thedevicegroup->vlan->xpath("entry[@name='$myname']");
                $xml_final = addslashes($element[0]->asXML());
                $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('$myname','VLAN','VLAN','$xml_final','$xpath2','edit');");
            }
        }
        if ($api_call=="atomic"){
            $xpath2 = addslashes($xpath0."/vlan");
            $xml_final = addslashes($thedevicegroup->vlan->asXML());
            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('VLANS','VLANS','VLANS','$xml_final','$xpath2','edit');");
        }
    }
    else{
        if (!empty($xml->xpath($xpath0."/vlan"))){
            $thedevicegroup0=$xml->xpath($xpath0);
            $thedevicegroup = $thedevicegroup0[0];
            if (isset($thedevicegroup->{'vlan'})){
                $SA = $xml->xpath($xpath0."/vlan");
                unset($SA[0][0]);
            }
        }

        if ($api_call=="clean"){
            $xpath2 = addslashes($xpath0."/vlan");
            $xml_final = "";
            $projectdb->query("INSERT INTO output_mapping (name,object,table_name,xml_final,xpath,action) VALUES ('Remove All VLANS','VLANS','VLANS','$xml_final','$xpath2','delete');");
        }
        $message['code'] = true;
        $message['msg'] = "Removed All VLANS.";
        return $message;
    }
}
