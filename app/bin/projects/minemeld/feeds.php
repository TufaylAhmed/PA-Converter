<?php
# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';
require_once INC_ROOT.'/libs/projectdb.php';
require_once INC_ROOT.'/libs/shared.php';
require_once INC_ROOT.'/libs/database.php';

$request_body   = file_get_contents('php://input');
$params           = json_decode($request_body, true);

if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
}

include INC_ROOT.'/bin/middleware_sanitizer.php';

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $project=$pandb->real_escape_string(isset($_GET['project']) ? $_GET['project']:'');
        $nodeID=$pandb->real_escape_string(isset($_GET['nodeID']) ? $_GET['nodeID']:'');
        if ((isset($project)) AND ($project!='')){
            $message = list_feeds($project,$nodeID);
            if($message['code']) {
                echo json_encode(array('total' => $message['count'], 'feeds' => $message['msg']));
            }
            else{
                echo '{"total":"0","feeds":[]}';
            }
        }
        else{
            echo '{"total":"0","feeds":[]}';
        }

        break;

    case 'POST':
        $message = import_feed($params);
        echo json_encode(array('success' => $message['code'],'msg' => $message['msg']));
        break;

    case 'PUT':
        $message = update_feed($params);
        echo json_encode(array('success' => $message['code']));
        break;

    case 'DELETE':

        break;

    default:
        break;
}

function list_feeds(STRING $project,INT $nodeID){
    $message=array();
    $message['code']=false;
    if(!accessControl("any", ['projectRole.'.$project.'.view'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to view this project contents';
        return $message;
    }

    $projectdb = selectDatabase($project);
    $getMM=$projectdb->query("SELECT * FROM minemeld_feeds WHERE node_id='$nodeID';");
    if ($getMM->num_rows>0){
        $mm=array();
        while($data=$getMM->fetch_assoc()){
            $data['project']=$project;
            $mm[]=$data;
        }
        $message['code']=true;
        $message['msg']=$mm;
        $message['count']=count($mm);
    }
    return $message;
}

function import_feed(ARRAY $params){
    global $app;
    global $projectdb;

    $project = $params['project'];

    if(!accessControl("any", ['projectRole.'.$project.'.update'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to edit this project contents';
        return $message;
    }


    if (($params['source']==0) OR ($params['vsys']=="all")){
        $message['code']=false;
        $message['msg']='Invalid Source or Vsys';
        return $message;
    }

    $projectdb = selectDatabase($project);

    $getBaseConfig=$projectdb->query("SELECT id,version FROM device_mapping WHERE baseconfig=1 GROUP BY filename;");
    if ($getBaseConfig->num_rows==1){
        $getBaseConfigData=$getBaseConfig->fetch_assoc();
        $source=$getBaseConfigData['id'];
        $version0=$getBaseConfigData['version'];
        $version=getVersion($version0);
        $vsys=$params['vsys'];

        $nodes=explode(",",$params['nodeID']);
        foreach($nodes as $nodeID){
            $getNode=$projectdb->query("SELECT * FROM minemeld_feeds WHERE id='$nodeID';");
            if ($getNode->num_rows==1){
                $getNodeData=$getNode->fetch_assoc();
                $url=$getNodeData['feed'];
                $name=$getNodeData['name'];
                $type=$getNodeData['nodetype'];

                if ($version<8){
                    $xml='<entry name="'.$name.'">
                    <recurring>
                    <hourly>
                    <at>01</at>
                    </hourly>
                    </recurring>
                    <url>'.$url.'</url>
                    <type>ip</type>
                    <disable-override>yes</disable-override>   Panorama only
                    <description>MineMeld created from MT</description>
                    </entry>';
                }
                else{
                    # version 8
                    $xml='<entry name="'.$name.'">
                    <type>
                    <'.$type.'>
                    <recurring>
                    <hourly/>
                    </recurring>            
                    <description>MineMeld created from MT</description>
                    <url>'.$url.'</url>
                    </'.$type.'>
                    </type>
                    </entry>';
                }
                $checkDupe=$projectdb->query("SELECT id FROM external_list WHERE source='$source' AND vsys='$vsys' AND name='$name';");
                if ($checkDupe->num_rows==0){
                    $projectdb->query("INSERT INTO external_list (name,xml,type,vsys,source,devicegroup) VALUES ('$name','".addslashes($xml)."','external_lists','$vsys','$source','MT Created');");
                }

            }
        }

        $message['msg']="Imported into VSYS/DG ".$vsys;
        $message['code']=true;
        return $message;
    }
    else{
        $message['code']=false;
        $message['msg']='There is no Base Config loaded';
        return $message;
    }

    $message['code']=false;
    return $message;
}

function update_feed(ARRAY $params){
    global $app;
    global $projectdb;

    $project = $params['project'];

    if(!accessControl("any", ['projectRole.'.$project.'.update'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to edit this project contents';
        return $message;
    }


    $projectdb = selectDatabase($project);

    if ((isset($params['id']) AND (isset($params['nodetype'])))){
        $projectdb->query("UPDATE minemeld_feeds SET nodetype='".$params['nodetype']."' WHERE id='".$params['id']."';");
        $message['code']=true;
        $message['msg']='Update correctly';
        return $message;
    }

    $message['code']=false;
    return $message;
}
/*
 *  Panos 7
 <entry name="dbl1">
<recurring>
<hourly>
<at>01</at>
</hourly>
</recurring>
<url>http://1.1.1.1/feeds/php</url>
<type>ip</type>
<disable-override>yes</disable-override>   Panorama only
<description>asdsadasda</description>
</entry>

panos 8
<entry name="MM_HC">
<type>
<ip>
<recurring>
<hourly/>
</recurring>
<url>https://10.11.29.43/feeds/inboundfeedhc</url>
<exception-list>
<member>120.128.128.4</member>
</exception-list>
<auth>
<username>administrator</username>
<password>
-AQ==W6ph5Mm5Pz8GgiULbPgzG37mj9g=w2hP4BspAiin+j7uXWkGKA==
</password>
</auth>
<certificate-profile>CertificateProfileAle</certificate-profile>
<description>asddsada asdadasdsad</description>
</ip>
</type>
</entry>
<entry name="dbl1_domain_http">
<type>
<domain>
<recurring>
<hourly/>
</recurring>
<certificate-profile>None</certificate-profile>
<description>domain list</description>
<url>http://1.1.1.1/mer</url>
</domain>
</type>
</entry>
<entry name="dbl2_url_ssl">
<type>
<url>
<recurring>
<hourly/>
</recurring>
<certificate-profile>sslcertprofile</certificate-profile>
<description>asdasdsad</description>
<url>https://1.1.1.1</url>
</url>
</type>
</entry>
 *
 */