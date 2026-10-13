<?php
/**
 * Created by PhpStorm.
 * User: aestevez
 * Date: 23/05/2017
 * Time: 19:27
 */

function remediate_wildfire($projectdb,$bpcheks,$template,$template_name,$ispanorama,$source,$topic_id,$version){

}

function remediate_mgt_config($projectdb,$bpcheks,$template,$template_name,$ispanorama,$source,$topic_id,$version){
    if ($ispanorama==0){
        $loadXML=$projectdb->query("SELECT id,xml FROM password_complexity WHERE source='$source'");
        $template=0;
    }
    else{
        # IS PANORAMA CHECK TEMPLATE
        $loadXML=$projectdb->query("SELECT id,xml FROM password_complexity WHERE source='$source' AND template='$template';");
    }

    if ($loadXML->num_rows==0){
        $projectdb->query("INSERT INTO password_complexity (template,source,xml) VALUES ('$template','$source','<password-complexity></password-complexity>')");
        if ($ispanorama==0){
            $loadXML=$projectdb->query("SELECT id,xml FROM password_complexity WHERE source='$source'");
            $template=0;
        }
        else{
            # IS PANORAMA CHECK TEMPLATE
            $loadXML=$projectdb->query("SELECT id,xml FROM password_complexity WHERE source='$source' AND template='$template';");
        }
    }

    if ($loadXML->num_rows>0) {
        $fixed=array();
        while ($loadXMLData = $loadXML->fetch_assoc()) {
            $deviceconfig_id = $loadXMLData['id'];
            $xml = simplexml_load_string($loadXMLData['xml']);

            foreach (explode(",",$bpcheks) as $key=>$value){
                switch ($value) {
                    case "103":
                        if (!isset($xml->enabled)){
                            $xml->addChild("enabled","yes");
                        }
                        else{
                            $xml->enabled="yes";
                        }
                        if (!isset($xml->{'minimum-length'})){
                            $xml->addChild("minimum-length",12);
                        }
                        else{
                            if ($xml->{'minimum-length'}<12) {
                                $xml->{'minimum-length'} = 12;
                            }
                        }
                        if (!isset($xml->{'minimum-uppercase-letters'})){
                            $xml->addChild("minimum-uppercase-letters",1);
                        }
                        else{
                            if ($xml->{'minimum-uppercase-letters'}==0){
                                $xml->{'minimum-uppercase-letters'}=1;
                            }
                        }
                        if (!isset($xml->{'minimum-lowercase-letters'})){
                            $xml->addChild("minimum-lowercase-letters",1);
                        }
                        else{
                            if ($xml->{'minimum-lowercase-letters'}==0){
                                $xml->{'minimum-lowercase-letters'}=1;
                            }
                        }
                        if (!isset($xml->{'minimum-numeric-letters'})){
                            $xml->addChild("minimum-numeric-letters",1);
                        }
                        else{
                            if ($xml->{'minimum-numeric-letters'}==0){
                                $xml->{'minimum-numeric-letters'}=1;
                            }
                        }
                        if (!isset($xml->{'minimum-special-characters'})){
                            $xml->addChild("minimum-special-characters",1);
                        }
                        else{
                            if ($xml->{'minimum-special-characters'}==0){
                                $xml->{'minimum-special-characters'}=1;
                            }
                        }
                        if (!isset($xml->{'block-username-inclusion'})){
                            $xml->addChild("block-username-inclusion","yes");
                        }
                        else{
                            $xml->{'block-username-inclusion'}="yes";
                        }
                        if (!isset($xml->{'password-history-count'})){
                            $xml->addChild("password-history-count",24);
                        }
                        else{
                            if ($xml->{'password-history-count'}<24){
                                $xml->{'password-history-count'}=24;
                            }
                        }
                        if (!isset($xml->{'new-password-differs-by-characters'})){
                            $xml->addChild("new-password-differs-by-characters",3);
                        }
                        else{
                            if ($xml->{'new-password-differs-by-characters'}<3){
                                $xml->{'new-password-differs-by-characters'}=3;
                            }
                        }

                        if (!isset($xml->{'password-change'})){
                            $xml->addChild("password-change");
                        }
                        if (!isset($xml->{'password-change'}->{'expiration-period'})){
                            $xml->{'password-change'}->addChild("expiration-period",90);
                        }
                        else{
                            if ($xml->{'password-change'}->{'expiration-period'}>90){
                                $xml->{'password-change'}->{'expiration-period'}=90;
                            }
                        }
                        $fixed[]=$value;
                        break;
                }

            }

            if (count($fixed)>0){
                $dom = dom_import_simplexml($xml);
                $projectdb->query("UPDATE password_complexity SET xml='" . addslashes($dom->ownerDocument->saveXML($dom->ownerDocument->documentElement)) . "' WHERE id='$deviceconfig_id';");
                $projectdb->query("UPDATE bpat_bpcheck SET result='pass' WHERE topic_id='$topic_id' AND check_id IN (".implode(",",$fixed).")");
            }

        }
    }

}

function remediate_deviceconfig($projectdb,$bpcheks,$template,$template_name,$ispanorama,$source,$topic_id,$version){

    if ($ispanorama==0){
        $loadXML=$projectdb->query("SELECT id,xml FROM deviceconfig WHERE source='$source'");
        $template=0;
    }
    else{
        # IS PANORAMA CHECK TEMPLATE
        $loadXML=$projectdb->query("SELECT id,xml FROM deviceconfig WHERE source='$source' AND template='$template';");
    }

    if ($loadXML->num_rows==0){
        $projectdb->query("INSERT INTO deviceconfig (source,template,xml) VALUES ('$source','$template','<deviceconfig><system><update-schedule></update-schedule></system><setting><wildfire></wildfire></setting></deviceconfig>');");
        if ($ispanorama==0){
            $loadXML=$projectdb->query("SELECT id,xml FROM deviceconfig WHERE source='$source'");
            $template=0;
        }
        else{
            # IS PANORAMA CHECK TEMPLATE
            $loadXML=$projectdb->query("SELECT id,xml FROM deviceconfig WHERE source='$source' AND template='$template';");
        }
    }

    if ($loadXML->num_rows>0){
        $fixed=array();
        while($loadXMLData=$loadXML->fetch_assoc()){
            $deviceconfig_id=$loadXMLData['id'];
            if ($loadXMLData['xml']==""){
                $xml = simplexml_load_string("<deviceconfig><system><update-schedule></update-schedule></system><setting><wildfire></wildfire></setting></deviceconfig>");
            }
            else{
                $xml = simplexml_load_string($loadXMLData['xml']);
            }

            $system0=$xml->xpath("//system");
            if (empty($system0)){
                $system=$xml->addChild("system");
            }
            else{
                $system=$system0[0];
            }


            $update0=$xml->xpath("//system/update-schedule");
            if (empty($update0)){
                $update=$xml->system->addChild("update-schedule");
            }
            else{
                $update=$update0[0];
            }

            $wildfire0=$xml->xpath("//setting/wildfire");
            if (empty($wildfire0)){
                if (!isset($xml->setting)){
                    $xml->addChild("setting");
                }
                $wildfire=$xml->setting->addChild("wildfire");
            }
            else{
                $wildfire=$wildfire0[0];
            }


            foreach (explode(",",$bpcheks) as $key=>$value){
                switch ($value) {
                    # Device Setup
                    case "88":
                        if (!isset($xml->setting->management)){
                            $xml->setting->addChild("management");
                        }
                        if (!isset($xml->setting->management->{'auto-acquire-commit-lock'})){
                            $xml->setting->management->addChild("auto-acquire-commit-lock","yes");
                        }
                        else{
                            $xml->setting->management->{'auto-acquire-commit-lock'}="yes";
                        }
                        $fixed[]=$value;
                        break;
                    case "!89":
                        if (!isset($xml->setting->management)){
                            $xml->setting->addChild("management");
                        }
                        if (!isset($xml->setting->management->{'enable-certificate-expiration-check'})){
                            $xml->setting->management->addChild("enable-certificate-expiration-check","yes");
                        }
                        else{
                            $xml->setting->management->{'enable-certificate-expiration-check'}="yes";
                        }
                        $fixed[]=$value;
                        break;

                    case "91":
                        $banner = "This system is for the use of authorized users only.Individuals using this computer system without authority, or in excess of their authority, are subjectto having all of their activities on this systemmonitored and recorded by system personnel.  In thecourse of monitoring individuals improperly using thissystem, or in the course of system maintenance, the activities of authorized users may also be monitored.Anyone using this system expressly consents to suchmonitoring and is advised that if such monitoringreveals possible evidence of criminal activity, systempersonnel may provide the evidence of such monitoringto law enforcement officials.";
                        if (!isset($system->{'login-banner'})){
                            $system->addChild("login-banner",$banner);
                        }
                        else{
                            $system->{'login-banner'}=$banner;
                        }

                        $fixed[]=$value;
                        break;

                    case "94":
                        if (!isset($xml->setting->management)){
                            $xml->setting->addChild("management");
                        }
                        if (!isset($xml->setting->management->{'idle-timeout'})){
                            $xml->setting->management->addChild("idle-timeout","10");
                        }
                        else{
                            $xml->setting->management->{'idle-timeout'}="10";
                        }
                        $fixed[]=$value;
                        break;
                    case "95":
                        if (!isset($xml->setting->management)){
                            $xml->setting->addChild("management");
                        }
                        if (!isset($xml->setting->management->{'admin-lockout'})){
                            $xml->setting->management->addChild("admin-lockout");
                        }
                        if (!isset($xml->setting->management->{'admin-lockout'}->{'failed-attempts'})){
                            $xml->setting->management->{'admin-lockout'}->addChild("failed-attempts","5");
                        }
                        else{
                            $xml->setting->management->{'admin-lockout'}->{'failed-attempts'}="5";
                        }
                        $fixed[]=$value;
                        break;
                    case "96":
                        if (!isset($xml->setting->management)){
                            $xml->setting->addChild("management");
                        }
                        if (!isset($xml->setting->management->{'admin-lockout'})){
                            $xml->setting->management->addChild("admin-lockout");
                        }
                        if (!isset($xml->setting->management->{'admin-lockout'}->{'lockout-time'})){
                            $xml->setting->management->{'admin-lockout'}->addChild("lockout-time","30");
                        }
                        else{
                            $xml->setting->management->{'admin-lockout'}->{'lockout-time'}="30";
                        }
                        $fixed[]=$value;
                        break;
                    case "97":
                        if (!isset($xml->setting->management)){
                            $xml->setting->addChild("management");
                        }
                        if (!isset($xml->setting->management->{'enable-log-high-dp-load'})){
                            $xml->setting->management->addChild("enable-log-high-dp-load","yes");
                        }
                        else{
                            $xml->setting->management->{'enable-log-high-dp-load'}="yes";
                        }
                        $fixed[]=$value;
                        break;

                    case "102":
                        if (!isset($system->service)){
                            $system->addChild("service");
                        }
                        if (!isset($system->service->{'disable-telnet'})){
                            $system->service->addChild("disable-telnet","yes");
                        }
                        else{
                            $system->service->{'disable-telnet'}="yes";
                        }
                        if (!isset($system->service->{'disable-http'})){
                            $system->service->addChild("disable-http","yes");
                        }
                        else{
                            $system->service->{'disable-http'}="yes";
                        }
                        $fixed[]=$value;
                        break;
                    case "104":
                        if (!isset($system->{'server-verification'})){
                            $system->addChild("server-verification","yes");
                        }
                        else{
                            $system->{'server-verification'}="yes";
                        }
                        $fixed[]=$value;
                        break;
                    case "105":
                        # Respect if already exists a ntp server.
                        $primary_ntp_server="0.pool.ntp.org";
                        $secondary_ntp_server="1.pool.ntp.org";
                        if (!isset($system->{'ntp-servers'})){
                            $system->addChild("ntp-servers");
                        }

                        if (!isset($system->{'ntp-servers'}->{'primary-ntp-server'})){
                            $system->{'ntp-servers'}->addChild("primary-ntp-server");
                        }

                        if (!isset($system->{'ntp-servers'}->{'primary-ntp-server'}->{'ntp-server-address'})){
                            $system->{'ntp-servers'}->{'primary-ntp-server'}->addChild("ntp-server-address",$primary_ntp_server);
                        }
//                        else{
//                            $system->{'ntp-servers'}->{'primary-ntp-server'}->{'ntp-server-address'}=$primary_ntp_server;
//                        }

                        if (!isset($system->{'ntp-servers'}->{'secondary-ntp-server'})){
                            $system->{'ntp-servers'}->addChild("secondary-ntp-server");
                        }

                        if (!isset($system->{'ntp-servers'}->{'secondary-ntp-server'}->{'ntp-server-address'})){
                            $system->{'ntp-servers'}->{'secondary-ntp-server'}->addChild("ntp-server-address",$secondary_ntp_server);
                        }
//                        else{
//                            $system->{'ntp-servers'}->{'secondary-ntp-server'}->{'ntp-server-address'}=$secondary_ntp_server;
//                        }

                        $fixed[]=$value;
                        break;
                    case "107":
                        if (!isset($xml->setting->ctd)){
                            $xml->setting->addChild("ctd");
                        }
                        if (!isset($xml->setting->ctd->{'x-forwarded-for'})){
                            $xml->setting->ctd->addChild("x-forwarded-for","yes");
                        }
                        else{
                            $xml->setting->ctd->{'x-forwarded-for'}="yes";
                        }
                        $fixed[]=$value;
                        break;
                    case "108":
                        if (!isset($xml->setting->ctd)){
                            $xml->setting->addChild("ctd");
                        }
                        if (!isset($xml->setting->ctd->{'strip-x-fwd-for'})){
                            $xml->setting->ctd->addChild("strip-x-fwd-for","yes");
                        }
                        else{
                            $xml->setting->ctd->{'strip-x-fwd-for'}="yes";
                        }
                        $fixed[]=$value;
                        break;

                    # Wildfire
                    case "109":
                        if (!isset($wildfire->{'file-size-limit'})) {
                            $wildfire->addChild("file-size-limit");
                        }
                        if (!empty($wildfire->xpath('//file-size-limit/entry[@name="pe"]'))) {
                            $SA = $wildfire->xpath('//file-size-limit/entry[@name="pe"]');
                            $SA[0]->{'size-limit'}=16;
                        }
                        else{
                            $tmp=$wildfire->{'file-size-limit'}->addChild("entry");
                            $tmp->addAttribute("name","pe");
                            $tmp->{'size-limit'}=16;
                        }
                        $fixed[]=$value;
                        break;
                    case "110":
                        if (!isset($wildfire->{'file-size-limit'})) {
                            $wildfire->addChild("file-size-limit");
                        }

                        if ( !empty($wildfire->xpath('file-size-limit/entry[@name="apk"]'))) {
                            $SA = $wildfire->xpath('file-size-limit/entry[@name="apk"]');
                            $SA[0]->{'size-limit'}=30;
                        }
                        else{
                            $tmp=$wildfire->{'file-size-limit'}->addChild("entry");
                            $tmp->addAttribute("name","apk");
                            $tmp->{'size-limit'}=30;
                        }
                        $fixed[]=$value;
                        break;
                    case "111":
                        if (!isset($wildfire->{'file-size-limit'})) {
                            $wildfire->addChild("file-size-limit");
                        }

                        if ( !empty($wildfire->xpath('file-size-limit/entry[@name="pdf"]'))) {
                            $SA = $wildfire->xpath('file-size-limit/entry[@name="pdf"]');
                            $SA[0]->{'size-limit'}=3072;
                        }
                        else{
                            $tmp=$wildfire->{'file-size-limit'}->addChild("entry");
                            $tmp->addAttribute("name","pdf");
                            $tmp->{'size-limit'}=3072;
                        }
                        $fixed[]=$value;
                        break;
                    case "112":
                        if (!isset($wildfire->{'file-size-limit'})) {
                            $wildfire->addChild("file-size-limit");
                        }

                        if ( !empty($wildfire->xpath('file-size-limit/entry[@name="ms-office"]'))) {
                            $SA = $wildfire->xpath('file-size-limit/entry[@name="ms-office"]');
                            $SA[0]->{'size-limit'}=16384;
                        }
                        else{
                            $tmp=$wildfire->{'file-size-limit'}->addChild("entry");
                            $tmp->addAttribute("name","ms-office");
                            $tmp->{'size-limit'}=16384;
                        }
                        $fixed[]=$value;
                        break;
                    case "113":
                        if (!isset($wildfire->{'file-size-limit'})) {
                            $wildfire->addChild("file-size-limit");
                        }

                        if ( !empty($wildfire->xpath('file-size-limit/entry[@name="jar"]'))) {
                            $SA = $wildfire->xpath('file-size-limit/entry[@name="jar"]');
                            $SA[0]->{'size-limit'}=5;
                        }
                        else{
                            $tmp=$wildfire->{'file-size-limit'}->addChild("entry");
                            $tmp->addAttribute("name","jar");
                            $tmp->{'size-limit'}=5;
                        }
                        $fixed[]=$value;
                        break;
                    case "114":
                        if (!isset($wildfire->{'file-size-limit'})) {
                            $wildfire->addChild("file-size-limit");
                        }

                        if ( !empty($wildfire->xpath('file-size-limit/entry[@name="flash"]'))) {
                            $SA = $wildfire->xpath('file-size-limit/entry[@name="flash"]');
                            $SA[0]->{'size-limit'}=5;
                        }
                        else{
                            $tmp=$wildfire->{'file-size-limit'}->addChild("entry");
                            $tmp->addAttribute("name","flash");
                            $tmp->{'size-limit'}=5;
                        }
                        $fixed[]=$value;
                        break;
                    case "115":
                        if (!isset($wildfire->{'file-size-limit'})) {
                            $wildfire->addChild("file-size-limit");
                        }

                        if ( !empty($wildfire->xpath('file-size-limit/entry[@name="MacOSX"]'))) {
                            $SA = $wildfire->xpath('file-size-limit/entry[@name="MacOSX"]');
                            $SA[0]->{'size-limit'}=10;
                        }
                        else{
                            $tmp=$wildfire->{'file-size-limit'}->addChild("entry");
                            $tmp->addAttribute("name","MacOSX");
                            $tmp->{'size-limit'}=10;
                        }
                        $fixed[]=$value;
                        break;
                    case "116":
                        if (!isset($wildfire->{'report-benign-file'})) {
                            $wildfire->addChild("report-benign-file");
                        }
                        $wildfire->{'report-benign-file'}="yes";
                        $fixed[]=$value;
                        break;
                    case "117":
                        if (!isset($wildfire->{'report-grayware-file'})) {
                            $wildfire->addChild("report-grayware-file");
                        }
                        $wildfire->{'report-grayware-file'}="yes";
                        $fixed[]=$value;
                        break;

                    case "119":
                        if (!isset($wildfire->{'public-cloud-server'})) {
                            $wildfire->addChild("public-cloud-server");
                        }
                        $wildfire->{'public-cloud-server'}="eu.wildfire.paloaltonetworks.com";
                        $fixed[]=$value;
                        break;
                    # Sessions
                    case "120":
                        if (!isset($xml->setting->config)){
                            $xml->setting->addChild("config");
                            $xml->setting->config->addChild("rematch","yes");
                        }
                        else{
                            if (!isset($xml->setting->config->rematch)){
                                $xml->setting->config->addChild("rematch","yes");
                            }
                            else{
                                $xml->setting->config->rematch="yes";
                            }
                        }
                        $fixed[]=$value;
                        break;

                    # Administrators

                        # Updates
                    case "188":
                        if (!isset($update->{'anti-virus'})){
                            $update->addChild("anti-virus");
                        }
                        if (!isset($update->{'anti-virus'}->recurring)){
                            $update->{'anti-virus'}->addChild("recurring");
                        }
                        $av0=$update->xpath("//anti-virus/recurring");
                        $av=$av0[0];

                        if (isset($av->daily)){
                            unset($av->daily);
                        }
                        elseif (isset($av->weekly)){
                            unset($av->weekly);
                        }
                        if (!isset($av->hourly)){
                            $av->addChild("hourly");
                        }
                        if (!isset($av->hourly->at)){
                            $av->hourly->addChild("at","30");
                        }
                        if (!isset($av->hourly->action)){
                            $av->hourly->addChild("action","download-and-install");
                        }
                        else{
                            $av->hourly->action="download-and-install";
                        }
                        if (isset($av->threshold)){
                            unset($av->threshold);
                        }
                        $fixed[]=$value;
                        break;
                    case "189":
                        $threshold=24;
                        if (!isset($update->{'threats'})){
                            $update->addChild("threats");
                        }

                        if (!isset($update->threats->recurring)){
                            $update->threats->addChild("recurring");
                        }
                        $av0=$update->xpath("//threats/recurring");
                        $av=$av0[0];


                        if ($version<8){
                            $time="daily";
                            $hour="20:00";
                            if (!isset($av->daily)){
                                if (isset($av->weekly)){
                                    unset($av->weekly);
                                }
                                $av->addChild("daily");
                            }
                            if (!isset($av->daily->at)){
                                $av->daily->addChild("at",$hour);
                            }
                            if (!isset($av->daily->action)){
                                $av->daily->addChild("action","download-and-install");
                            }
                            else{
                                $av->daily->action="download-and-install";
                            }
                            if ($version>=7.1){
                                if (!isset($av->daily->{'disable-new-content'})){
                                    $av->daily->addChild("disable-new-content","yes");
                                }
                                $av->daily->{'disable-new-content'}="yes";
                            }
                        }
                        else{
                            # Higher or equal 8
                            $time="daily";
                            $hour="00:30";
                            if (!isset($av->daily)){
                                if (isset($av->weekly)){
                                    unset($av->weekly);
                                }
                                $av->addChild("daily");
                            }
                            if (!isset($av->daily->at)){
                                $av->daily->addChild("at",$hour);
                            }
                            if (!isset($av->daily->action)){
                                $av->daily->addChild("action","download-and-install");
                            }
                            else{
                                $av->daily->action="download-and-install";
                            }
                            if ($version>=7.1){
                                if (!isset($av->daily->{'disable-new-content'})){
                                    $av->daily->addChild("disable-new-content","yes");
                                }
                                $av->daily->{'disable-new-content'}="yes";
                            }
                        }

                        if (!isset($av->threshold)){
                            $av->addChild("threshold",$threshold);
                        }
                        else{
                            $av->threshold=$threshold;
                        }

                        $fixed[]=$value;
                        break;
                    case "190":
                        if (isset($update->{'wildfire'})){
                            unset($update->wildfire->recurring);

                        }
                        else{
                            $update->addChild("wildfire");
                        }
                        $av0=$update->xpath("//wildfire");
                        $av=$av0[0];
                        if (!isset($av->recurring)){
                            $av->addChild("recurring");
                        }
                        if ($version <= 7.1){
                            $time="every-15-mins";
                        }
                        else{
                            $time="every-min";
                        }

                        $av->recurring->addChild($time);
                        $av->recurring->$time->addChild("action","download-and-install");

                        $fixed[]=$value;
                        break;

                    case "194":
                        if (isset($update->{'global-protect-datafile'})){
                            unset($update->{'global-protect-datafile'}->recurring);
                        }
                        else{
                            $update->addChild("global-protect-datafile");
                        }
                        $av0=$update->xpath("//global-protect-datafile");
                        $av=$av0[0];
                        if (!isset($av->recurring)){
                            $av->addChild("recurring");
                        }

                        $time="hourly";
                        $hour="40";

                        $av->recurring->addChild($time);
                        $av->recurring->$time->addChild("at",$hour);
                        $av->recurring->$time->addChild("action","download-and-install");

                        $fixed[]=$value;
                        break;
                    case "195":
                        if (isset($update->{'global-protect-clientless-vpn'})){
                            unset($update->{'global-protect-clientless-vpn'}->recurring);
                        }
                        else{
                            $update->addChild("global-protect-clientless-vpn");
                        }
                        $av0=$update->xpath("//global-protect-clientless-vpn");
                        $av=$av0[0];
                        if (!isset($av->recurring)){
                            $av->addChild("recurring");
                        }

                        $time="hourly";
                        $hour="50";

                        $av->recurring->addChild($time);
                        $av->recurring->$time->addChild("at",$hour);
                        $av->recurring->$time->addChild("action","download-and-install");

                        $fixed[]=$value;
                        break;
                    case "197":
                        if ($version>7.1){
                            if (!isset($update->{'statistics-service'})){
                                $update->addChild('statistics-service');
                                $update->{'statistics-service'}->addChild("application-reports","yes");
                                $update->{'statistics-service'}->addChild("threat-prevention-reports","yes");
                                $update->{'statistics-service'}->addChild("threat-prevention-pcap","yes");
                                $update->{'statistics-service'}->addChild("threat-prevention-information","yes");
                                $update->{'statistics-service'}->addChild("passive-dns-monitoring","yes");
                                $update->{'statistics-service'}->addChild("url-reports","yes");
                                $update->{'statistics-service'}->addChild("health-performance-reports","yes");
                                $update->{'statistics-service'}->addChild("file-identification-reports","yes");
                            }
                            else{
                                $update->{'statistics-service'}->{'application-reports'}="yes";
                                $update->{'statistics-service'}->{'threat-prevention-reports'}="yes";
                                $update->{'statistics-service'}->{'threat-prevention-pcap'}="yes";
                                $update->{'statistics-service'}->{'threat-prevention-information'}="yes";
                                $update->{'statistics-service'}->{'passive-dns-monitoring'}="yes";
                                $update->{'statistics-service'}->{'url-reports'}="yes";
                                $update->{'statistics-service'}->{'health-performance-reports'}="yes";
                                $update->{'statistics-service'}->{'file-identification-reports'}="yes";
                            }
                            $fixed[]=$value;
                        }

                        break;
                }

            }

            if (count($fixed)>0) {
                $dom = dom_import_simplexml($xml);
                $projectdb->query("UPDATE deviceconfig SET xml='" . addslashes($dom->ownerDocument->saveXML($dom->ownerDocument->documentElement)) . "' WHERE id='$deviceconfig_id';");
                $projectdb->query("UPDATE bpat_bpcheck SET result='pass' WHERE topic_id='$topic_id' AND check_id IN (" . implode(",", $fixed) . ")");
            }
        }
    }
}