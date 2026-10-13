<?php
/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: $today.year.hour.minute
 ******************************************************************************/

/**
 * Function FileSizeConvert
 * Converts bytes into human readable file size.
 *
 * @param string $bytes
 * @return string human readable file size (2,87 Мб)
 * @author Mogilev Arseny
 */

require_once INC_ROOT.'/libs/common/ForceUTF8/Encoding.php';

use ForceUTF8\Encoding;

function FileSizeConvert($bytes){
    if(!is_numeric($bytes) || $bytes <= 0){
        return "0 B";
    }

    $bytes = floatval($bytes);
    $arBytes = array(
        0 => array(
            "UNIT" => "TB",
            "VALUE" => pow(1024, 4)
        ),
        1 => array(
            "UNIT" => "GB",
            "VALUE" => pow(1024, 3)
        ),
        2 => array(
            "UNIT" => "MB",
            "VALUE" => pow(1024, 2)
        ),
        3 => array(
            "UNIT" => "KB",
            "VALUE" => 1024
        ),
        4 => array(
            "UNIT" => "B",
            "VALUE" => 1
        ),
    );

    $result = "0 B";
    foreach($arBytes as $arItem)
    {
        if($bytes >= $arItem["VALUE"])
        {
            $result = $bytes / $arItem["VALUE"];
            $result = str_replace(".", "," , strval(round($result, 2)))." ".$arItem["UNIT"];
            break;
        }
    }
    return $result;
}


function FileLogVersion(STRING $filepath){
    $version7_x_x  = 'Domain,Receive Time,Serial #,Type,Threat/Content Type,Config Version,Generate Time,Source address,Destination address,NAT Source IP,NAT Destination IP,Rule,Source User,Destination User,Application,Virtual System,Source Zone,Destination Zone,Inbound Interface,Outbound Interface,Log Action,Time Logged,Session ID,Repeat Count,Source Port,Destination Port,NAT Source Port,NAT Destination Port,Flags,IP Protocol,Action,Bytes,Bytes Sent,Bytes Received,Packets,Start Time,Elapsed Time (sec),Category,Padding,seqno,actionflags,Source Country,Destination Country,cpadding,pkts_sent,pkts_received,session_end_reason,dg_hier_level_1,dg_hier_level_2,dg_hier_level_3,dg_hier_level_4,vsys_name,device_name,action_source';

    $version7_x_x2 = 'Domain,Receive Time,Serial #,Type,Threat/Content Type,Config Version,Generate Time,Source address,Destination address,NAT Source IP,NAT Destination IP,Rule,Source User,Destination User,Application,Virtual System,Source Zone,Destination Zone,Inbound Interface,Outbound Interface,Log Action,Time Logged,Session ID,Repeat Count,Source Port,Destination Port,NAT Source Port,NAT Destination Port,Flags,IP Protocol,Action,Bytes,Bytes Sent,Bytes Received,Packets,Start Time,Elapsed Time (sec),Category,Padding,Sequence Number,Action Flags,Source Country,Destination Country,cpadding,pkts_sent,pkts_received,session_end_reason,dg_hier_level_1,dg_hier_level_2,dg_hier_level_3,dg_hier_level_4,Virtual System Name,Device Name,action_source';

    //Log format valid for 8.0.2, 8.0.3, 8.0.5
    $version8_0_2    = 'Domain,Receive Time,Serial #,Type,Threat/Content Type,Config Version,Generate Time,Source address,Destination address,NAT Source IP,NAT Destination IP,Rule,Source User,Destination User,Application,Virtual System,Source Zone,Destination Zone,Inbound Interface,Outbound Interface,Log Action,Time Logged,Session ID,Repeat Count,Source Port,Destination Port,NAT Source Port,NAT Destination Port,Flags,IP Protocol,Action,Bytes,Bytes Sent,Bytes Received,Packets,Start Time,Elapsed Time (sec),Category,Padding,Sequence Number,Action Flags,Source Country,Destination Country,cpadding,pkts_sent,pkts_received,session_end_reason,dg_hier_level_1,dg_hier_level_2,dg_hier_level_3,dg_hier_level_4,Virtual System Name,Device Name,action_source,Source VM UUID,Destination VM UUID,Tunnel ID/IMSI,Monitor Tag/IMEI,Parent Session ID,parent_start_time,tunnel';

    $version8_1_0_b  = 'Domain,Receive Time,Serial #,Type,Threat/Content Type,Config Version,Generate Time,Source address,Destination address,NAT Source IP,NAT Destination IP,Rule,Source User,Destination User,Application,Virtual System,Source Zone,Destination Zone,Inbound Interface,Outbound Interface,Log Action,Time Logged,Session ID,Repeat Count,Source Port,Destination Port,NAT Source Port,NAT Destination Port,Flags,IP Protocol,Action,Bytes,Bytes Sent,Bytes Received,Packets,Start Time,Elapsed Time (sec),Category,Sequence Number,Action Flags,Source Country,Destination Country,cpadding,Packets Sent,Packtes Received,Session End Reason,DG Hierarchy Level 1,DG Hierarchy Level 2,DG Hierarchy Level 3,DG Hierarchy Level 4,Virtual System Name,Device Name,Action Source,Source VM UUID,Destination VM UUID,Tunnel ID/IMSI,Monitor Tag/IMEI,Parent Session ID,Parent Session Start Time,Tunnel,SCTP Association ID,SCTP Chunks,SCTP Chunks Sent,SCTP Chunks Received';
//    $version8_1_0  = 'Domain,Receive Time,Serial #,Type,Threat/Content Type,Config Version,Generate Time,Source address,Destination address,NAT Source IP,NAT Destination IP,Rule,Source User,Destination User,Application,Virtual System,Source Zone,Destination Zone,Inbound Interface,Outbound Interface,Log Action,Time Logged,Session ID,Repeat Count,Source Port,Destination Port,NAT Source Port,NAT Destination Port,Flags,IP Protocol,Action,Bytes,Bytes Sent,Bytes Received,Packets,Start Time,Elapsed Time (sec),Category,Padding,Sequence Number,Action Flags,Source Country,Destination Country,cpadding,Packets Sent,Packets Received,Session End Reason,DG Hierarchy Level 1,DG Hierarchy Level 2,DG Hierarchy Level 3,DG Hierarchy Level 4,Virtual System Name,Device Name,Action Source,Source VM UUID,Destination VM UUID,Tunnel ID/IMSI,Monitor Tag/IMEI,Parent Session ID,Parent Session Start Time,Tunnel,SCTP Association ID,SCTP Chunks,SCTP Chunks Sent,SCTP Chunks Received';
    $version8_1_0    = 'Domain,Receive Time,Serial #,Type,Threat/Content Type,Config Version,Generate Time,Source address,Destination address,NAT Source IP,NAT Destination IP,Rule,Source User,Destination User,Application,Virtual System,Source Zone,Destination Zone,Inbound Interface,Outbound Interface,Log Action,Time Logged,Session ID,Repeat Count,Source Port,Destination Port,NAT Source Port,NAT Destination Port,Flags,IP Protocol,Action,Bytes,Bytes Sent,Bytes Received,Packets,Start Time,Elapsed Time (sec),Category,tpadding,Sequence Number,Action Flags,Source Country,Destination Country,cpadding,Packets Sent,Packets Received,Session End Reason,DG Hierarchy Level 1,DG Hierarchy Level 2,DG Hierarchy Level 3,DG Hierarchy Level 4,Virtual System Name,Device Name,Action Source,Source VM UUID,Destination VM UUID,Tunnel ID/IMSI,Monitor Tag/IMEI,Parent Session ID,Parent Session Start Time,Tunnel,SCTP Association ID,SCTP Chunks,SCTP Chunks Sent,SCTP Chunks Received';
    $version8_1_0b49 = 'Domain,Receive Time,Serial #,Type,Threat/Content Type,Config Version,Generate Time,Source address,Destination address,NAT Source IP,NAT Destination IP,Rule,Source User,Destination User,Application,Virtual System,Source Zone,Destination Zone,Inbound Interface,Outbound Interface,Log Action,Time Logged,Session ID,Repeat Count,Source Port,Destination Port,NAT Source Port,NAT Destination Port,Flags,IP Protocol,Action,Bytes,Bytes Sent,Bytes Received,Packets,Start Time,Elapsed Time (sec),Category,$padding,Sequence Number,Action Flags,Source Country,Destination Country,cpadding,Packets Sent,Packets Received,Session End Reason,DG Hierarchy Level 1,DG Hierarchy Level 2,DG Hierarchy Level 3,DG Hierarchy Level 4,Virtual System Name,Device Name,Action Source,Source VM UUID,Destination VM UUID,Tunnel ID/IMSI,Monitor Tag/IMEI,Parent Session ID,Parent Session Start Time,Tunnel,SCTP Association ID,SCTP Chunks,SCTP Chunks Sent,SCTP Chunks Received';

    $version9_0_0    = 'Domain,Receive Time,Serial #,Type,Threat/Content Type,Config Version,Generate Time,Source address,Destination address,NAT Source IP,NAT Destination IP,Rule,Source User,Destination User,Application,Virtual System,Source Zone,Destination Zone,Inbound Interface,Outbound Interface,Log Action,Time Logged,Session ID,Repeat Count,Source Port,Destination Port,NAT Source Port,NAT Destination Port,Flags,IP Protocol,Action,Bytes,Bytes Sent,Bytes Received,Packets,Start Time,Elapsed Time (sec),Category,tpadding,Sequence Number,Action Flags,Source Country,Destination Country,cpadding,Packets Sent,Packets Received,Session End Reason,DG Hierarchy Level 1,DG Hierarchy Level 2,DG Hierarchy Level 3,DG Hierarchy Level 4,Virtual System Name,Device Name,Action Source,Source VM UUID,Destination VM UUID,Tunnel ID/IMSI,Monitor Tag/IMEI,Parent Session ID,Parent Session Start Time,Tunnel,SCTP Association ID,SCTP Chunks,SCTP Chunks Sent,SCTP Chunks Received,UUID for rule,HTTP/2 Connection';

    $version9_1_x    = 'Domain,Receive Time,Serial #,Type,Threat/Content Type,Config Version,Generate Time,Source address,Destination address,NAT Source IP,NAT Destination IP,Rule,Source User,Destination User,Application,Virtual System,Source Zone,Destination Zone,Inbound Interface,Outbound Interface,Log Action,Time Logged,Session ID,Repeat Count,Source Port,Destination Port,NAT Source Port,NAT Destination Port,Flags,IP Protocol,Action,Bytes,Bytes Sent,Bytes Received,Packets,Start Time,Elapsed Time (sec),Category,tpadding,Sequence Number,Action Flags,Source Country,Destination Country,cpadding,Packets Sent,Packets Received,Session End Reason,DG Hierarchy Level 1,DG Hierarchy Level 2,DG Hierarchy Level 3,DG Hierarchy Level 4,Virtual System Name,Device Name,Action Source,Source VM UUID,Destination VM UUID,Tunnel ID/IMSI,Monitor Tag/IMEI,Parent Session ID,Parent Session Start Time,Tunnel,SCTP Association ID,SCTP Chunks,SCTP Chunks Sent,SCTP Chunks Received,UUID for rule,HTTP/2 Connection,link_change_count,policy_id,link_switches,sdwan_cluster,sdwan_device_type,sdwan_cluster_type,sdwan_site,dynusergroup_name';

    $version9_1_0_b  = 'Domain,Receive Time,Serial #,Type,Threat/Content Type,Config Version,Generate Time,Source address,Destination address,NAT Source IP,NAT Destination IP,Rule,Source User,Destination User,Application,Virtual System,Source Zone,Destination Zone,Inbound Interface,Outbound Interface,Log Action,Time Logged,Session ID,Repeat Count,Source Port,Destination Port,NAT Source Port,NAT Destination Port,Flags,IP Protocol,Action,Bytes,Bytes Sent,Bytes Received,Packets,Start Time,Elapsed Time (sec),Category,tpadding,Sequence Number,Action Flags,Source Country,Destination Country,cpadding,Packets Sent,Packets Received,Session End Reason,DG Hierarchy Level 1,DG Hierarchy Level 2,DG Hierarchy Level 3,DG Hierarchy Level 4,Virtual System Name,Device Name,Action Source,Source VM UUID,Destination VM UUID,Tunnel ID/IMSI,Monitor Tag/IMEI,Parent Session ID,Parent Session Start Time,Tunnel,SCTP Association ID,SCTP Chunks,SCTP Chunks Sent,SCTP Chunks Received,UUID for rule,HTTP/2 Connection,link_change_count,policy_id,link_switches,sdwan_cluster,sdwan_device_type,sdwan_cluster_type,sdwan_site';

    $version10_0_0   = 'Domain,Receive Time,Serial #,Type,Threat/Content Type,Config Version,Generate Time,Source address,Destination address,NAT Source IP,NAT Destination IP,Rule,Source User,Destination User,Application,Virtual System,Source Zone,Destination Zone,Inbound Interface,Outbound Interface,Log Action,Time Logged,Session ID,Repeat Count,Source Port,Destination Port,NAT Source Port,NAT Destination Port,Flags,IP Protocol,Action,Bytes,Bytes Sent,Bytes Received,Packets,Start Time,Elapsed Time (sec),Category,tpadding,Sequence Number,Action Flags,Source Country,Destination Country,cpadding,Packets Sent,Packets Received,Session End Reason,DG Hierarchy Level 1,DG Hierarchy Level 2,DG Hierarchy Level 3,DG Hierarchy Level 4,Virtual System Name,Device Name,Action Source,Source VM UUID,Destination VM UUID,Tunnel ID/IMSI,Monitor Tag/IMEI,Parent Session ID,Parent Session Start Time,Tunnel,SCTP Association ID,SCTP Chunks,SCTP Chunks Sent,SCTP Chunks Received,UUID for rule,HTTP/2 Connection,link_change_count,policy_id,link_switches,sdwan_cluster,sdwan_device_type,sdwan_cluster_type,sdwan_site,dynusergroup_name,XFF address,Source Device Category,Source Device Profile,Source Device Model,Source Device Vendor,Source Device OS Family,Source Device OS Version,Source Hostname,Source Mac Address,Destination Device Category,Destination Device Profile,Destination Device Model,Destination Device Vendor,Destination Device OS Family,Destination Device OS Version,Destination Hostname,Destination Mac Address,Container ID,POD Namespace,POD Name,Source External Dynamic List,Destination External Dynamic List,Host ID,Serial Number,Source Dynamic Address Group,Destination Dynamic Address Group,session_owner,High Res Timestamp,nssai_sst,nssai_sd';

    $version10_1_0   = 'Domain,Receive Time,Serial #,Type,Threat/Content Type,Config Version,Generate Time,Source address,Destination address,NAT Source IP,NAT Destination IP,Rule,Source User,Destination User,Application,Virtual System,Source Zone,Destination Zone,Inbound Interface,Outbound Interface,Log Action,Time Logged,Session ID,Repeat Count,Source Port,Destination Port,NAT Source Port,NAT Destination Port,Flags,IP Protocol,Action,Bytes,Bytes Sent,Bytes Received,Packets,Start Time,Elapsed Time (sec),Category,'.     ',Sequence Number,Action Flags,Source Country,Destination Country,'.     ',Packets Sent,Packets Received,Session End Reason,DG Hierarchy Level 1,DG Hierarchy Level 2,DG Hierarchy Level 3,DG Hierarchy Level 4,Virtual System Name,Device Name,Action Source,Source VM UUID,Destination VM UUID,Tunnel ID/IMSI,Monitor Tag/IMEI,Parent Session ID,Parent Session Start Time,Tunnel,SCTP Association ID,SCTP Chunks,SCTP Chunks Sent,SCTP Chunks Received,UUID for rule,HTTP/2 Connection,link_change_count,policy_id,link_switches,sdwan_cluster,sdwan_device_type,sdwan_cluster_type,sdwan_site,dynusergroup_name,XFF address,Source Device Category,Source Device Profile,Source Device Model,Source Device Vendor,Source Device OS Family,Source Device OS Version,Source Hostname,Source Mac Address,Destination Device Category,Destination Device Profile,Destination Device Model,Destination Device Vendor,Destination Device OS Family,Destination Device OS Version,Destination Hostname,Destination Mac Address,Container ID,POD Namespace,POD Name,Source External Dynamic List,Destination External Dynamic List,Host ID,Serial Number,Source Dynamic Address Group,Destination Dynamic Address Group,session_owner,High Res Timestamp,nssai_sst,nssai_sd,Subcategory of app,Category of app,Technology of app,Risk of app,Characteristic of app,Container of app,Tunneled app,SaaS of app,Sanctioned State of app,offloaded';
    $version11_0_0   = 'Domain,Receive Time,Serial #,Type,Threat/Content Type,Config Version,Generate Time,Source address,Destination address,NAT Source IP,NAT Destination IP,Rule,Source User,Destination User,Application,Virtual System,Source Zone,Destination Zone,Inbound Interface,Outbound Interface,Log Action,Time Logged,Session ID,Repeat Count,Source Port,Destination Port,NAT Source Port,NAT Destination Port,Flags,IP Protocol,Action,Bytes,Bytes Sent,Bytes Received,Packets,Start Time,Elapsed Time (sec),Category,'.     ',Sequence Number,Action Flags,Source Country,Destination Country,'.     ',Packets Sent,Packets Received,Session End Reason,DG Hierarchy Level 1,DG Hierarchy Level 2,DG Hierarchy Level 3,DG Hierarchy Level 4,Virtual System Name,Device Name,Action Source,Source VM UUID,Destination VM UUID,Tunnel ID/IMSI,Monitor Tag/IMEI,Parent Session ID,Parent Session Start Time,Tunnel,SCTP Association ID,SCTP Chunks,SCTP Chunks Sent,SCTP Chunks Received,UUID for rule,HTTP/2 Connection,link_change_count,policy_id,link_switches,sdwan_cluster,sdwan_device_type,sdwan_cluster_type,sdwan_site,dynusergroup_name,XFF address,Source Device Category,Source Device Profile,Source Device Model,Source Device Vendor,Source Device OS Family,Source Device OS Version,Source Hostname,Source Mac Address,Destination Device Category,Destination Device Profile,Destination Device Model,Destination Device Vendor,Destination Device OS Family,Destination Device OS Version,Destination Hostname,Destination Mac Address,Container ID,POD Namespace,POD Name,Source External Dynamic List,Destination External Dynamic List,Host ID,Serial Number,Source Dynamic Address Group,Destination Dynamic Address Group,session_owner,High Res Timestamp,nssai_sst,nssai_sd,Subcategory of app,Category of app,Technology of app,Risk of app,Characteristic of app,Container of app,Tunneled app,SaaS of app,Sanctioned State of app,offloaded,flow_type,cluster_name';


    $version_splunk_v1 = 'type,"generated_date","serial_number","log_subtype",vsys,action,"src_zone","src_ip","src_location","src_port","src_user","dest_ip","dest_zone","dest_location","dest_port","dest_user",app,rule,transport,"app:category",bytes,"bytes_in","bytes_out",packets,"packets_in","packets_out",hits';
    $version_splunk_v2 = '"log_type","generated_date","serial_number","log_subtype",vsys,action,"src_zone","src_ip","src_location","src_port","src_user","dest_ip","dest_zone","dest_location","dest_port","dest_user",app,rule,transport,"app:category",bytes,"bytes_in","bytes_out",packets,"packets_in","packets_out",hits';

    $version_cdl_v1 = 'log_type,generated_date,serial_number,log_subtype,vsys,action,src_zone,src_ip,src_region,src_port,src_user,dest_ip,dest_zone,dest_region,dest_port,dest_user,rule,protocol,app,app_category,bytes,bytes_in,bytes_out,packets,packets_in,packets_out,hits';

    $line = null;
    $lineVersion = 'unknown';

//    $myFile = fopen("/tmp/testing", "w");
//    fwrite($myFile, "7.0 ".count(explode(",",$version7_x_x))."\n");
//    fwrite($myFile, "7.0 ".count(explode(",",$version7_x_x2))."\n");
//    fwrite($myFile, "8.0 ".count(explode(",",$version8_0_2))."\n");
//    fwrite($myFile, "8.1_0 ".count(explode(",",$version8_1_0))."\n");
//    fwrite($myFile, "8.1_0b ".count(explode(",",$version8_1_0_b))."\n");
//    fwrite($myFile, "8.1_0b49 ".count(explode(",",$version8_1_0b49))."\n");
//    fwrite($myFile, "9.0 ".count(explode(",",$version9_0_0))."\n");
//    fwrite($myFile, "9.1 ".count(explode(",",$version9_1_x))."\n");
//    fwrite($myFile, "9.1b ".count(explode(",",$version9_1_0_b))."\n");
//    fwrite($myFile, "10.0 ".count(explode(",",$version10_0_0))."\n");
//    fwrite($myFile, "10.1 ".print_r(explode(",",$version10_1_0), true));

    preg_match("/^(.*).(gz|gzip)$/", $filepath, $output_array);
    $isZip = false;
    if(count($output_array)>0){
        $line = trim(fgets(gzopen($filepath, 'r')));
        $isZip=true;
    }
    else{
        $line = trim(fgets(fopen($filepath, 'r')));
        $isZip=false;
    }

    $line = Encoding::removeBOM($line);

    switch ($line){
        case $version7_x_x:
        case $version7_x_x2:
        {
            $lineVersion = '7.0.x';
            break;
        }
        case $version8_0_2:
        {
            $lineVersion = '8.0.3';
            break;
        }
        case $version8_1_0_b:
        {
            $lineVersion = '8.1.0b';
            break;
        }
        case $version8_1_0b49:
        case $version8_1_0:
        {
            $lineVersion = '8.1.0';
            break;
        }
        case $version9_0_0:
        {
            $lineVersion = '9.0.0';
            break;
        }
        case $version9_1_x:
        {
            $lineVersion = '9.1.x';
            break;
        }
        case $version9_1_0_b:
        {
            $lineVersion = '9.1.0-beta';
            break;
        }
        case $version10_0_0:
        {
            $lineVersion = '10.0.0';
            break;
        }
        case $version10_1_0:
        {
            $lineVersion = '10.1.0';
            break;
        }
        case $version11_0_0:
        {
            $lineVersion = '11.0.0';
            break;
        }
        case $version_splunk_v1:
        case $version_splunk_v2:
        {
            $lineVersion = 'Splunk v1';
            break;
        }
        case $version_cdl_v1:
        {
            $lineVersion = 'Cortex DL 1.0';
            break;
        }
        default:
        {
            $firstLine = $line;
            if ($isZip) {
                //Sorry, we can't check the last line of a zipped file yet
                $lastLine = $firstLine;
            } else {
                $lastLine = shell_exec("tail -n 1 '$filepath'");
            }

            if (isset($firstLine, $lastLine)) {
                $lineVersion = discoverTrafficVersion($firstLine, $lastLine);
            }
            break;
        }
    }

    return $lineVersion;
}

function discoverTrafficVersion(STRING $sample1, STRING $sample2): string {
    #                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     X                     X                        X                        X                           X                                                                             X                 X                     X                     X                                                                                                                                   XX                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      X                                                                              X                            X                       X                          X
    # version7_x_x  = 'Domain,           Receive Time,                                         Serial #,         Type,       Threat/Content Type,Config Version,        Generate Time,                                         Source address,    Destination address,  NAT Source IP,      NAT Destination IP,        Rule,           Source User,         Destination User,          Application,       Virtual System,  Source Zone,        Destination Zone,           Inbound Interface,          Outbound Interface,          Log Action,          Time Logged,                                          Session ID,         Repeat Count,          Source Port,           Destination Port,         NAT Source Port,           NAT Destination Port,          Flags,         IP Protocol,       Action,          Bytes,           Bytes Sent,          Bytes Received,          Packets,          Start Time,                                         Elapsed Time (sec),     Category,          Padding,          seqno,               actionflags,            Source Country,          Destination Country,          cpadding,          pkts_sent,             pkts_received,             session_end_reason,          dg_hier_level_1,          dg_hier_level_2,          dg_hier_level_3,          dg_hier_level_4,          vsys_name,          device_name,         action_source';
    //$regex7_x_x    = "/^(?<domain>[^,]*),(?<receive_time>\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}),(?<serial>[^,]*),(?<type>[^,]*),(?<threat>[^,]*),(?<conf_version>[^,]*),(?<generated_time>\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}),(?<source>[^,]*),(?<destination>[^,]*),(?<nat_source>[^,]*),(?<nat_destination>[^,]*),(?<rule>[^,]*),(?<source_user>[^,]*),(?<destination_user>[^,]*),(?<application>[^,]*),(?<vsys>[^,]*),(?<from_zone>[^,]*),(?<destination_zone>[^,]*),(?<inbound_interface>[^,]*),(?<outbound_interface>[^,]*),(?<log_action>[^,]*),(?<time_logged>\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}),(?<session_id>[^,]*),(?<repeat_count>[\d]*),(?<source_port>[\d]*),(?<destination_port>[\d]*),(?<nat_source_port>[\d]*),(?<nat_destination_port>[\d]*),(?<flags>[^,]*),(?<protocol>[^,]*),(?<action>[^,]*),(?<bytes>[\d]*),(?<bytes_sent>[\d]*),(?<bytes_received>[\d]*),(?<packets>[\d]*),(?<start_time>\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}),(?<elapsed_time>[^,]*),(?<category>[^,]*),(?<tpadding>[^,]*),(?<seq_number>[\d]*),(?<action_flags>[^,]*),(?<source_country>[^,]*),(?<destination_country>[^,]*),(?<cpadding>[^,]*),(?<packets_sent>[^,]*),(?<packets_received>[^,]*),(?<session_end_reason>[^,]*),(?<dg_hier_level_1>[^,]*),(?<dg_hier_level_2>[^,]*),(?<dg_hier_level_3>[^,]*),(?<dg_hier_level_4>[^,]*),(?<vsys_name>[^,]*),(?<device_name>[^,]*),(?<action_source>[^,]*)$/";

    # version7_x_x2 = 'Domain,           Receive Time,                                          Serial #,        Type,         Threat/Content Type,Config Version,      Generate Time,                                           Source address,  Destination address,  NAT Source IP,       NAT Destination IP,       Rule,          Source User,          Destination User,          Application,       Virtual System,   Source Zone,        Destination Zone,          Inbound Interface,          Outbound Interface,          Log Action,          Time Logged,                                          Session ID,          Repeat Count,          Source Port,          Destination Port,          NAT Source Port,          NAT Destination Port,          Flags,          IP Protocol,       Action,          Bytes,          Bytes Sent,          Bytes Received,          Packets,          Start Time,                                          Elapsed Time (sec),    Category,          Padding,           Sequence Number,     Action Flags,          Source Country,          Destination Country,          cpadding,          pkts_sent,             pkts_received,             session_end_reason,          dg_hier_level_1,          dg_hier_level_2,          dg_hier_level_3,          dg_hier_level_4,       Virtual System Name,   Device Name,          action_source';
    //$regex7_x_x2 = "/^(?<domain>[^,]*),(?<receive_time>\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}),(?<serial>[^,]*),(?<type>[^,]*),(?<threat>[^,]*),(?<conf_version>[^,]*),(?<generated_time>\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}),(?<source>[^,]*),(?<destination>[^,]*),(?<nat_source>[^,]*),(?<nat_destination>[^,]*),(?<rule>[^,]*),(?<source_user>[^,]*),(?<destination_user>[^,]*),(?<application>[^,]*),(?<vsys>[^,]*),(?<from_zone>[^,]*),(?<destination_zone>[^,]*),(?<inbound_interface>[^,]*),(?<outbound_interface>[^,]*),(?<log_action>[^,]*),(?<time_logged>\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}),(?<session_id>[^,]*),(?<repeat_count>[\d]*),(?<source_port>[\d]*),(?<destination_port>[\d]*),(?<nat_source_port>[\d]*),(?<nat_destination_port>[\d]*),(?<flags>[^,]*),(?<protocol>[^,]*),(?<action>[^,]*),(?<bytes>[\d]*),(?<bytes_sent>[\d]*),(?<bytes_received>[\d]*),(?<packets>[\d]*),(?<start_time>\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}),(?<elapsed_time>[^,]*),(?<category>[^,]*),(?<tpadding>[^,]*),(?<seq_number>[\d]*),(?<action_flags>[^,]*),(?<source_country>[^,]*),(?<destination_country>[^,]*),(?<cpadding>[^,]*),(?<packets_sent>[^,]*),(?<packets_received>[^,]*),(?<session_end_reason>[^,]*),(?<dg_hier_level_1>[^,]*),(?<dg_hier_level_2>[^,]*),(?<dg_hier_level_3>[^,]*),(?<dg_hier_level_4>[^,]*),(?<vsys_name>[^,]*),(?<device_name>[^,]*),(?<action_source>[^,]*)$/";

    //Log format valid for 8.0.2, 8.0.3, 8.0.5                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                
    # version8_0_2  = 'Domain,           Receive Time,                                          Serial #,        Type,          Threat/Content Type,Config Version,     Generate Time,                                           Source address,  Destination address,  NAT Source IP,       NAT Destination IP,       Rule,          Source User,          Destination User,          Application,       Virtual System,   Source Zone,        Destination Zone,          Inbound Interface,          Outbound Interface,          Log Action,          Time Logged,                                          Session ID,          Repeat Count,          Source Port,          Destination Port,          NAT Source Port,          NAT Destination Port,          Flags,          IP Protocol,       Action,          Bytes,          Bytes Sent,          Bytes Received,          Packets,          Start Time,                                          Elapsed Time (sec),    Category,          Padding,           Sequence Number,     Action Flags,          Source Country,          Destination Country,          cpadding,          pkts_sent,             pkts_received,             session_end_reason,          dg_hier_level_1,          dg_hier_level_2,          dg_hier_level_3,          dg_hier_level_4,       Virtual System Name,   Device Name,          action_source,          Source VM UUID,          Destination VM UUID,          Tunnel ID/IMSI,     Monitor Tag/IMEI,     Parent Session ID,          parent_start_time,                   tunnel';
    //$regex8_0_2    = "/^(?<domain>[^,]*),(?<receive_time>\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}),(?<serial>[^,]*),(?<type>[^,]*),(?<threat>[^,]*),(?<conf_version>[^,]*),(?<generated_time>\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}),(?<source>[^,]*),(?<destination>[^,]*),(?<nat_source>[^,]*),(?<nat_destination>[^,]*),(?<rule>[^,]*),(?<source_user>[^,]*),(?<destination_user>[^,]*),(?<application>[^,]*),(?<vsys>[^,]*),(?<from_zone>[^,]*),(?<destination_zone>[^,]*),(?<inbound_interface>[^,]*),(?<outbound_interface>[^,]*),(?<log_action>[^,]*),(?<time_logged>\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}),(?<session_id>[^,]*),(?<repeat_count>[\d]*),(?<source_port>[\d]*),(?<destination_port>[\d]*),(?<nat_source_port>[\d]*),(?<nat_destination_port>[\d]*),(?<flags>[^,]*),(?<protocol>[^,]*),(?<action>[^,]*),(?<bytes>[\d]*),(?<bytes_sent>[\d]*),(?<bytes_received>[\d]*),(?<packets>[\d]*),(?<start_time>\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}),(?<elapsed_time>[^,]*),(?<category>[^,]*),(?<tpadding>[^,]*),(?<seq_number>[\d]*),(?<action_flags>[^,]*),(?<source_country>[^,]*),(?<destination_country>[^,]*),(?<cpadding>[^,]*),(?<packets_sent>[^,]*),(?<packets_received>[^,]*),(?<session_end_reason>[^,]*),(?<dg_hier_level_1>[^,]*),(?<dg_hier_level_2>[^,]*),(?<dg_hier_level_3>[^,]*),(?<dg_hier_level_4>[^,]*),(?<vsys_name>[^,]*),(?<device_name>[^,]*),(?<action_source>[^,]*),(?<source_vm_uuid>[^,]*),(?<destination_vm_uuid>[^,]*),(?<tunnel_id>[^,]*),(?<monitor_tag>[^,]*),(?<parent_session_id>[\d]*),(?<parent_session_tstart_time>[^,]*),(?<tunnel>[^,]*)$/";

    # version8_1_0_b= 'Domain,           Receive Time,                                          Serial #,        Type,         Threat/Content Type,Config Version,      Generate Time,                                           Source address,  Destination address,  NAT Source IP,       NAT Destination IP,       Rule,          Source User,          Destination User,          Application,       Virtual System,   Source Zone,        Destination Zone,          Inbound Interface,          Outbound Interface,          Log Action,          Time Logged,                                          Session ID,          Repeat Count,          Source Port,          Destination Port,          NAT Source Port,          NAT Destination Port,          Flags,          IP Protocol,       Action,          Bytes,          Bytes Sent,          Bytes Received,          Packets,          Start Time,                                          Elapsed Time (sec),    Category,          Sequence Number,                        Action Flags,          Source Country,           Destination Country,          cpadding,          Packets Sent,          Packtes Received,          Session End Reason,          DG Hierarchy Level 1,     DG Hierarchy Level 2,     DG Hierarchy Level 3,     DG Hierarchy Level 4,  Virtual System Name,   Device Name,          Action Source,          Source VM UUID,          Destination VM UUID,         Tunnel ID/IMSI,     Monitor Tag/IMEI,      Parent Session ID,          Parent Session Start Time,           Tunnel,          SCTP Association ID,          SCTP Chunks,          SCTP Chunks Sent,          SCTP Chunks Received';
    //$regex8_1_0beta= "/^(?<domain>[^,]*),(?<receive_time>\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}),(?<serial>[^,]*),(?<type>[^,]*),(?<threat>[^,]*),(?<conf_version>[^,]*),(?<generated_time>\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}),(?<source>[^,]*),(?<destination>[^,]*),(?<nat_source>[^,]*),(?<nat_destination>[^,]*),(?<rule>[^,]*),(?<source_user>[^,]*),(?<destination_user>[^,]*),(?<application>[^,]*),(?<vsys>[^,]*),(?<from_zone>[^,]*),(?<destination_zone>[^,]*),(?<inbound_interface>[^,]*),(?<outbound_interface>[^,]*),(?<log_action>[^,]*),(?<time_logged>\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}),(?<session_id>[^,]*),(?<repeat_count>[\d]*),(?<source_port>[\d]*),(?<destination_port>[\d]*),(?<nat_source_port>[\d]*),(?<nat_destination_port>[\d]*),(?<flags>[^,]*),(?<protocol>[^,]*),(?<action>[^,]*),(?<bytes>[\d]*),(?<bytes_sent>[\d]*),(?<bytes_received>[\d]*),(?<packets>[\d]*),(?<start_time>\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}),(?<elapsed_time>[^,]*),(?<category>[^,]*),(?<seq_number>[^,]*),".                "(?<action_flags>[^,]*),(?<source_country>[^,]*),(?<destination_country>[^,]*),(?<cpadding>[^,]*),(?<packets_sent>[^,]*),(?<packets_received>[^,]*),(?<session_end_reason>[^,]*),(?<dg_hier_level_1>[^,]*),(?<dg_hier_level_2>[^,]*),(?<dg_hier_level_3>[^,]*),(?<dg_hier_level_4>[^,]*),(?<vsys_name>[^,]*),(?<device_name>[^,]*),(?<action_source>[^,]*),(?<source_vm_uuid>[^,]*),(?<destination_vm_uuid>[^,]*),(?<tunnel_id>[^,]*),(?<monitor_tag>[^,]*),(?<parent_session_id>[\d]*),(?<parent_session_tstart_time>[^,]*),(?<tunnel>[^,]*),(?<sctp_association_id>[\d]*),(?<sctp_chunks>[\d]*),(?<sctp_chunks_sent>[\d]*),(?<sctp_chunks_received>[\d]*)$/";
    # version8_1_0  = 'Domain,           Receive Time,                                         Serial #,         Type,         Threat/Content Type,Config Version,      Generate Time,                                           Source address,  Destination address,  NAT Source IP,       NAT Destination IP,       Rule,          Source User,          Destination User,          Application,       Virtual System,   Source Zone,        Destination Zone,          Inbound Interface,          Outbound Interface,          Log Action,          Time Logged,                                          Session ID,          Repeat Count,          Source Port,          Destination Port,          NAT Source Port,          NAT Destination Port,          Flags,          IP Protocol,       Action,          Bytes,          Bytes Sent,          Bytes Received,          Packets,          Start Time,                                          Elapsed Time (sec),   Category,           tpadding,        Sequence Number,       Action Flags,          Source Country,          Destination Country,          cpadding,          Packets Sent,          Packets Received,          Session End Reason,          DG Hierarchy Level 1,     DG Hierarchy Level 2,     DG Hierarchy Level 3,     DG Hierarchy Level 4,  Virtual System Name,   Device Name,          Action Source,          Source VM UUID,          Destination VM UUID,          Tunnel ID/IMSI,     Monitor Tag/IMEI,     Parent Session ID,          Parent Session Start Time,           Tunnel,          SCTP Association ID,          SCTP Chunks,          SCTP Chunks Sent,          SCTP Chunks Received';
    //$regex8_1_0    = "/^(?<domain>[^,]*),(?<receive_time>\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}),(?<serial>[^,]*),(?<type>[^,]*),(?<threat>[^,]*),(?<conf_version>[^,]*),(?<generated_time>\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}),(?<source>[^,]*),(?<destination>[^,]*),(?<nat_source>[^,]*),(?<nat_destination>[^,]*),(?<rule>[^,]*),(?<source_user>[^,]*),(?<destination_user>[^,]*),(?<application>[^,]*),(?<vsys>[^,]*),(?<from_zone>[^,]*),(?<destination_zone>[^,]*),(?<inbound_interface>[^,]*),(?<outbound_interface>[^,]*),(?<log_action>[^,]*),(?<time_logged>\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}),(?<session_id>[^,]*),(?<repeat_count>[\d]*),(?<source_port>[\d]*),(?<destination_port>[\d]*),(?<nat_source_port>[\d]*),(?<nat_destination_port>[\d]*),(?<flags>[^,]*),(?<protocol>[^,]*),(?<action>[^,]*),(?<bytes>[\d]*),(?<bytes_sent>[\d]*),(?<bytes_received>[\d]*),(?<packets>[\d]*),(?<start_time>\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}),(?<elapsed_time>[^,]*),(?<category>[^,]*),(?<tpadding>[^,]*),(?<seq_number>[\d]*),(?<action_flags>[^,]*),(?<source_country>[^,]*),(?<destination_country>[^,]*),(?<cpadding>[^,]*),(?<packets_sent>[^,]*),(?<packets_received>[^,]*),(?<session_end_reason>[^,]*),(?<dg_hier_level_1>[^,]*),(?<dg_hier_level_2>[^,]*),(?<dg_hier_level_3>[^,]*),(?<dg_hier_level_4>[^,]*),(?<vsys_name>[^,]*),(?<device_name>[^,]*),(?<action_source>[^,]*),(?<source_vm_uuid>[^,]*),(?<destination_vm_uuid>[^,]*),(?<tunnel_id>[^,]*),(?<monitor_tag>[^,]*),(?<parent_session_id>[\d]*),(?<parent_session_tstart_time>[^,]*),(?<tunnel>[^,]*),(?<sctp_association_id>[\d]*),(?<sctp_chunks>[\d]*),(?<sctp_chunks_sent>[\d]*),(?<sctp_chunks_received>[\d]*)$/";

    //$regex9_0_0    = "/^(?<domain>[^,]*),(?<receive_time>\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}),(?<serial>[^,]*),(?<type>[^,]*),(?<threat>[^,]*),(?<conf_version>[^,]*),(?<generated_time>\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}),(?<source>[^,]*),(?<destination>[^,]*),(?<nat_source>[^,]*),(?<nat_destination>[^,]*),(?<rule>[^,]*),(?<source_user>[^,]*),(?<destination_user>[^,]*),(?<application>[^,]*),(?<vsys>[^,]*),(?<from_zone>[^,]*),(?<destination_zone>[^,]*),(?<inbound_interface>[^,]*),(?<outbound_interface>[^,]*),(?<log_action>[^,]*),(?<time_logged>\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}),(?<session_id>[^,]*),(?<repeat_count>[\d]*),(?<source_port>[\d]*),(?<destination_port>[\d]*),(?<nat_source_port>[\d]*),(?<nat_destination_port>[\d]*),(?<flags>[^,]*),(?<protocol>[^,]*),(?<action>[^,]*),(?<bytes>[\d]*),(?<bytes_sent>[\d]*),(?<bytes_received>[\d]*),(?<packets>[\d]*),(?<start_time>\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}),(?<elapsed_time>[^,]*),(?<category>[^,]*),(?<tpadding>[^,]*),(?<seq_number>[\d]*),(?<action_flags>[^,]*),(?<source_country>[^,]*),(?<destination_country>[^,]*),(?<cpadding>[^,]*),(?<packets_sent>[^,]*),(?<packets_received>[^,]*),(?<session_end_reason>[^,]*),(?<dg_hier_level_1>[^,]*),(?<dg_hier_level_2>[^,]*),(?<dg_hier_level_3>[^,]*),(?<dg_hier_level_4>[^,]*),(?<vsys_name>[^,]*),(?<device_name>[^,]*),(?<action_source>[^,]*),(?<source_vm_uuid>[^,]*),(?<destination_vm_uuid>[^,]*),(?<tunnel_id>[^,]*),(?<monitor_tag>[^,]*),(?<parent_session_id>[\d]*),(?<parent_session_tstart_time>[^,]*),(?<tunnel>[^,]*),(?<sctp_association_id>[\d]*),(?<sctp_chunks>[\d]*),(?<sctp_chunks_sent>[\d]*),(?<sctp_chunks_received>[\d]*),(?<rule_uuid>[^,]*),(?<http2>[^,]*)$/";

    //$regex9_1_x    = "/^(?<domain>[^,]*),(?<receive_time>\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}),(?<serial>[^,]*),(?<type>[^,]*),(?<threat>[^,]*),(?<conf_version>[^,]*),(?<generated_time>\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}),(?<source>[^,]*),(?<destination>[^,]*),(?<nat_source>[^,]*),(?<nat_destination>[^,]*),(?<rule>[^,]*),(?<source_user>[^,]*),(?<destination_user>[^,]*),(?<application>[^,]*),(?<vsys>[^,]*),(?<from_zone>[^,]*),(?<destination_zone>[^,]*),(?<inbound_interface>[^,]*),(?<outbound_interface>[^,]*),(?<log_action>[^,]*),(?<time_logged>\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}),(?<session_id>[^,]*),(?<repeat_count>[\d]*),(?<source_port>[\d]*),(?<destination_port>[\d]*),(?<nat_source_port>[\d]*),(?<nat_destination_port>[\d]*),(?<flags>[^,]*),(?<protocol>[^,]*),(?<action>[^,]*),(?<bytes>[\d]*),(?<bytes_sent>[\d]*),(?<bytes_received>[\d]*),(?<packets>[\d]*),(?<start_time>\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}),(?<elapsed_time>[^,]*),(?<category>[^,]*),(?<tpadding>[^,]*),(?<seq_number>[\d]*),(?<action_flags>[^,]*),(?<source_country>[^,]*),(?<destination_country>[^,]*),(?<cpadding>[^,]*),(?<packets_sent>[^,]*),(?<packets_received>[^,]*),(?<session_end_reason>[^,]*),(?<dg_hier_level_1>[^,]*),(?<dg_hier_level_2>[^,]*),(?<dg_hier_level_3>[^,]*),(?<dg_hier_level_4>[^,]*),(?<vsys_name>[^,]*),(?<device_name>[^,]*),(?<action_source>[^,]*),(?<source_vm_uuid>[^,]*),(?<destination_vm_uuid>[^,]*),(?<tunnel_id>[^,]*),(?<monitor_tag>[^,]*),(?<parent_session_id>[\d]*),(?<parent_session_tstart_time>[^,]*),(?<tunnel>[^,]*),(?<sctp_association_id>[\d]*),(?<sctp_chunks>[\d]*),(?<sctp_chunks_sent>[\d]*),(?<sctp_chunks_received>[\d]*),(?<rule_uuid>[^,]*),(?<http2>[^,]*),(?<link_change_count>[^,]*),(?<policy_id>[^,]*),(?<link_switches>[^,]*),(?<sdwan_cluster>[^,]*),(?<sdwan_device_type>[^,]*),(?<sdwan_cluster_type>[^,]*),(?<sdwan_site>[^,]*),(?<dynusergroup_name>[^,]*)$/";

    //$regex9_1_0_b  = "/^(?<domain>[^,]*),(?<receive_time>\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}),(?<serial>[^,]*),(?<type>[^,]*),(?<threat>[^,]*),(?<conf_version>[^,]*),(?<generated_time>\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}),(?<source>[^,]*),(?<destination>[^,]*),(?<nat_source>[^,]*),(?<nat_destination>[^,]*),(?<rule>[^,]*),(?<source_user>[^,]*),(?<destination_user>[^,]*),(?<application>[^,]*),(?<vsys>[^,]*),(?<from_zone>[^,]*),(?<destination_zone>[^,]*),(?<inbound_interface>[^,]*),(?<outbound_interface>[^,]*),(?<log_action>[^,]*),(?<time_logged>\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}),(?<session_id>[^,]*),(?<repeat_count>[\d]*),(?<source_port>[\d]*),(?<destination_port>[\d]*),(?<nat_source_port>[\d]*),(?<nat_destination_port>[\d]*),(?<flags>[^,]*),(?<protocol>[^,]*),(?<action>[^,]*),(?<bytes>[\d]*),(?<bytes_sent>[\d]*),(?<bytes_received>[\d]*),(?<packets>[\d]*),(?<start_time>\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}),(?<elapsed_time>[^,]*),(?<category>[^,]*),(?<tpadding>[^,]*),(?<seq_number>[\d]*),(?<action_flags>[^,]*),(?<source_country>[^,]*),(?<destination_country>[^,]*),(?<cpadding>[^,]*),(?<packets_sent>[^,]*),(?<packets_received>[^,]*),(?<session_end_reason>[^,]*),(?<dg_hier_level_1>[^,]*),(?<dg_hier_level_2>[^,]*),(?<dg_hier_level_3>[^,]*),(?<dg_hier_level_4>[^,]*),(?<vsys_name>[^,]*),(?<device_name>[^,]*),(?<action_source>[^,]*),(?<source_vm_uuid>[^,]*),(?<destination_vm_uuid>[^,]*),(?<tunnel_id>[^,]*),(?<monitor_tag>[^,]*),(?<parent_session_id>[\d]*),(?<parent_session_tstart_time>[^,]*),(?<tunnel>[^,]*),(?<sctp_association_id>[\d]*),(?<sctp_chunks>[\d]*),(?<sctp_chunks_sent>[\d]*),(?<sctp_chunks_received>[\d]*),(?<rule_uuid>[^,]*),(?<http2>[^,]*),(?<link_change_count>[^,]*),(?<policy_id>[^,]*),{(?<link_switches>[^,]*)},(?<sdwan_cluster>[^,]*),(?<sdwan_device_type>[^,]*),(?<sdwan_cluster_type>[^,]*),(?<sdwan_site>[^,]*)$/";

    //$regex10_0_0   = "/^(?<domain>[^,]*),(?<receive_time>\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}),(?<serial>[^,]*),(?<type>[^,]*),(?<threat>[^,]*),(?<conf_version>[^,]*),(?<generated_time>\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}),(?<source>[^,]*),(?<destination>[^,]*),(?<nat_source>[^,]*),(?<nat_destination>[^,]*),(?<rule>[^,]*),(?<source_user>[^,]*),(?<destination_user>[^,]*),(?<application>[^,]*),(?<vsys>[^,]*),(?<from_zone>[^,]*),(?<destination_zone>[^,]*),(?<inbound_interface>[^,]*),(?<outbound_interface>[^,]*),(?<log_action>[^,]*),(?<time_logged>\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}),(?<session_id>[^,]*),(?<repeat_count>[\d]*),(?<source_port>[\d]*),(?<destination_port>[\d]*),(?<nat_source_port>[\d]*),(?<nat_destination_port>[\d]*),(?<flags>[^,]*),(?<protocol>[^,]*),(?<action>[^,]*),(?<bytes>[\d]*),(?<bytes_sent>[\d]*),(?<bytes_received>[\d]*),(?<packets>[\d]*),(?<start_time>\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}),(?<elapsed_time>[^,]*),(?<category>[^,]*),(?<tpadding>[^,]*),(?<seq_number>[\d]*),(?<action_flags>[^,]*),(?<source_country>[^,]*),(?<destination_country>[^,]*),(?<cpadding>[^,]*),(?<packets_sent>[^,]*),(?<packets_received>[^,]*),(?<session_end_reason>[^,]*),(?<dg_hier_level_1>[^,]*),(?<dg_hier_level_2>[^,]*),(?<dg_hier_level_3>[^,]*),(?<dg_hier_level_4>[^,]*),(?<vsys_name>[^,]*),(?<device_name>[^,]*),(?<action_source>[^,]*),(?<source_vm_uuid>[^,]*),(?<destination_vm_uuid>[^,]*),(?<tunnel_id>[^,]*),(?<monitor_tag>[^,]*),(?<parent_session_id>[\d]*),(?<parent_session_tstart_time>[^,]*),(?<tunnel>[^,]*),(?<sctp_association_id>[\d]*),(?<sctp_chunks>[\d]*),(?<sctp_chunks_sent>[\d]*),(?<sctp_chunks_received>[\d]*),(?<rule_uuid>[^,]*),(?<http2>[^,]*),(?<link_change_count>[^,]*),(?<policy_id>[^,]*),(?<link_switches>[^,]*),(?<sdwan_cluster>[^,]*),(?<sdwan_device_type>[^,]*),(?<sdwan_cluster_type>[^,]*),(?<sdwan_site>[^,]*),(?<dynusergroup_name>[^,]*),(?<XFF_address>[^,]*),(?<SrcD_Cat>[^,]*),(?<SrcD_P>[^,]*),(?<SrcD_M>[^,]*),(?<SrcD_V>[^,]*),(?<SrcD_OS>[^,]*),(?<SrcD_OSV>[^,]*),(?<SrcD_Hostname>[^,]*),(?<SrcD_Mac>[^,]*),(?<DstD_Cat>[^,]*),(?<DstD_P>[^,]*),(?<DstD_M>[^,]*),(?<DstD_V>[^,]*),(?<DstD_OS>[^,]*),(?<DstD_OSV>[^,]*),(?<DstD_Hostname>[^,]*),(?<DstD_Mac>[^,]*),(?<Container_ID>[^,]*),(?<POD_Namespace>[^,]*),(?<POD_Name>[^,]*),(?<Src_EDL>[^,]*),(?<Dst_EDList>[^,]*),(?<Host_ID>[^,]*),(?<Serial_Number>[^,]*),(?<Src_DAG>[^,]*),(?<Dst_DAGroup>[^,]*),(?<session_owner>[^,]*),(?<High_Res_Timestamp>[^,]*),(?<nssai_sst>[^,]*),(?<nssai_sd>[^,]*)$/";

    //$regex10_1_0   = "/^(?<domain>[^,]*),(?<receive_time>\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}),(?<serial>[^,]*),(?<type>[^,]*),(?<threat>[^,]*),(?<conf_version>[^,]*),(?<generated_time>\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}),(?<source>[^,]*),(?<destination>[^,]*),(?<nat_source>[^,]*),(?<nat_destination>[^,]*),(?<rule>[^,]*),(?<source_user>[^,]*),(?<destination_user>[^,]*),(?<application>[^,]*),(?<vsys>[^,]*),(?<from_zone>[^,]*),(?<destination_zone>[^,]*),(?<inbound_interface>[^,]*),(?<outbound_interface>[^,]*),(?<log_action>[^,]*),(?<time_logged>\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}),(?<session_id>[^,]*),(?<repeat_count>[\d]*),(?<source_port>[\d]*),(?<destination_port>[\d]*),(?<nat_source_port>[\d]*),(?<nat_destination_port>[\d]*),(?<flags>[^,]*),(?<protocol>[^,]*),(?<action>[^,]*),(?<bytes>[\d]*),(?<bytes_sent>[\d]*),(?<bytes_received>[\d]*),(?<packets>[\d]*),(?<start_time>\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}),(?<elapsed_time>[^,]*),(?<category>[^,]*),(?<tpadding>[^,]*),(?<seq_number>[\d]*),(?<action_flags>[^,]*),(?<source_country>[^,]*),(?<destination_country>[^,]*),(?<cpadding>[^,]*),(?<packets_sent>[^,]*),(?<packets_received>[^,]*),(?<session_end_reason>[^,]*),(?<dg_hier_level_1>[^,]*),(?<dg_hier_level_2>[^,]*),(?<dg_hier_level_3>[^,]*),(?<dg_hier_level_4>[^,]*),(?<vsys_name>[^,]*),(?<device_name>[^,]*),(?<action_source>[^,]*),(?<source_vm_uuid>[^,]*),(?<destination_vm_uuid>[^,]*),(?<tunnel_id>[^,]*),(?<monitor_tag>[^,]*),(?<parent_session_id>[\d]*),(?<parent_session_tstart_time>[^,]*),(?<tunnel>[^,]*),(?<sctp_association_id>[\d]*),(?<sctp_chunks>[\d]*),(?<sctp_chunks_sent>[\d]*),(?<sctp_chunks_received>[\d]*),(?<rule_uuid>[^,]*),(?<http2>[^,]*),(?<link_change_count>[^,]*),(?<policy_id>[^,]*),(?<link_switches>[^,]*),(?<sdwan_cluster>[^,]*),(?<sdwan_device_type>[^,]*),(?<sdwan_cluster_type>[^,]*),(?<sdwan_site>[^,]*),(?<dynusergroup_name>[^,]*),(?<XFF_address>[^,]*),(?<SrcD_Cat>[^,]*),(?<SrcD_P>[^,]*),(?<SrcD_M>[^,]*),(?<SrcD_V>[^,]*),(?<SrcD_OS>[^,]*),(?<SrcD_OSV>[^,]*),(?<SrcD_Hostname>[^,]*),(?<SrcD_Mac>[^,]*),(?<DstD_Cat>[^,]*),(?<DstD_P>[^,]*),(?<DstD_M>[^,]*),(?<DstD_V>[^,]*),(?<DstD_OS>[^,]*),(?<DstD_OSV>[^,]*),(?<DstD_Hostname>[^,]*),(?<DstD_Mac>[^,]*),(?<Container_ID>[^,]*),(?<POD_Namespace>[^,]*),(?<POD_Name>[^,]*),(?<Src_EDL>[^,]*),(?<Dst_EDList>[^,]*),(?<Host_ID>[^,]*),(?<Serial_Number>[^,]*),(?<Src_DAG>[^,]*),(?<Dst_DAGroup>[^,]*),(?<session_owner>[^,]*),(?<High_Res_Timestamp>[^,]*),(?<nssai_sst>[^,]*),(?<nssai_sd>[^,]*),(?<appSubCategory>[^,]*),(?<appCategory>[^,]*),(?<appTechnology>[^,]*),(?<appRisk>[^,]*),(?<appCharac>[^,]*),(?<appContainer>[^,]*),(?<appTunnelId>[^,]*),(?<appSaaS>[^,]*),(?<appSanctState>[^,]*),(?<offloaded>[^,]*)$/";

    //$regex11_0_0   = "/^(?<domain>[^,]*),(?<receive_time>\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}),(?<serial>[^,]*),(?<type>[^,]*),(?<threat>[^,]*),(?<conf_version>[^,]*),(?<generated_time>\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}),(?<source>[^,]*),(?<destination>[^,]*),(?<nat_source>[^,]*),(?<nat_destination>[^,]*),(?<rule>[^,]*),(?<source_user>[^,]*),(?<destination_user>[^,]*),(?<application>[^,]*),(?<vsys>[^,]*),(?<from_zone>[^,]*),(?<destination_zone>[^,]*),(?<inbound_interface>[^,]*),(?<outbound_interface>[^,]*),(?<log_action>[^,]*),(?<time_logged>\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}),(?<session_id>[^,]*),(?<repeat_count>[\d]*),(?<source_port>[\d]*),(?<destination_port>[\d]*),(?<nat_source_port>[\d]*),(?<nat_destination_port>[\d]*),(?<flags>[^,]*),(?<protocol>[^,]*),(?<action>[^,]*),(?<bytes>[\d]*),(?<bytes_sent>[\d]*),(?<bytes_received>[\d]*),(?<packets>[\d]*),(?<start_time>\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}),(?<elapsed_time>[^,]*),(?<category>[^,]*),(?<tpadding>[^,]*),(?<seq_number>[\d]*),(?<action_flags>[^,]*),(?<source_country>[^,]*),(?<destination_country>[^,]*),(?<cpadding>[^,]*),(?<packets_sent>[^,]*),(?<packets_received>[^,]*),(?<session_end_reason>[^,]*),(?<dg_hier_level_1>[^,]*),(?<dg_hier_level_2>[^,]*),(?<dg_hier_level_3>[^,]*),(?<dg_hier_level_4>[^,]*),(?<vsys_name>[^,]*),(?<device_name>[^,]*),(?<action_source>[^,]*),(?<source_vm_uuid>[^,]*),(?<destination_vm_uuid>[^,]*),(?<tunnel_id>[^,]*),(?<monitor_tag>[^,]*),(?<parent_session_id>[\d]*),(?<parent_session_tstart_time>[^,]*),(?<tunnel>[^,]*),(?<sctp_association_id>[\d]*),(?<sctp_chunks>[\d]*),(?<sctp_chunks_sent>[\d]*),(?<sctp_chunks_received>[\d]*),(?<rule_uuid>[^,]*),(?<http2>[^,]*),(?<link_change_count>[^,]*),(?<policy_id>[^,]*),(?<link_switches>[^,]*),(?<sdwan_cluster>[^,]*),(?<sdwan_device_type>[^,]*),(?<sdwan_cluster_type>[^,]*),(?<sdwan_site>[^,]*),(?<dynusergroup_name>[^,]*),(?<XFF_address>[^,]*),(?<SrcD_Cat>[^,]*),(?<SrcD_P>[^,]*),(?<SrcD_M>[^,]*),(?<SrcD_V>[^,]*),(?<SrcD_OS>[^,]*),(?<SrcD_OSV>[^,]*),(?<SrcD_Hostname>[^,]*),(?<SrcD_Mac>[^,]*),(?<DstD_Cat>[^,]*),(?<DstD_P>[^,]*),(?<DstD_M>[^,]*),(?<DstD_V>[^,]*),(?<DstD_OS>[^,]*),(?<DstD_OSV>[^,]*),(?<DstD_Hostname>[^,]*),(?<DstD_Mac>[^,]*),(?<Container_ID>[^,]*),(?<POD_Namespace>[^,]*),(?<POD_Name>[^,]*),(?<Src_EDL>[^,]*),(?<Dst_EDList>[^,]*),(?<Host_ID>[^,]*),(?<Serial_Number>[^,]*),(?<Src_DAG>[^,]*),(?<Dst_DAGroup>[^,]*),(?<session_owner>[^,]*),(?<High_Res_Timestamp>[^,]*),(?<nssai_sst>[^,]*),(?<nssai_sd>[^,]*),(?<appSubCategory>[^,]*),(?<appCategory>[^,]*),(?<appTechnology>[^,]*),(?<appRisk>[^,]*),(?<appCharac>[^,]*),(?<appContainer>[^,]*),(?<appTunnelId>[^,]*),(?<appSaaS>[^,]*),(?<appSanctState>[^,]*),(?<offloaded>[^,]*),(?<flow_type>[^,]*),(?<cluster_name>[^,]*)$/";

    $result1 = preg_split('/(?:"[^"]*"|)\K\s*(,\s*|$)/', $sample1);
    $result2 = preg_split('/(?:"[^"]*"|)\K\s*(,\s*|$)/', trim($sample2));

    // Uncomment these lines to get the pattern size needed for
    // missing syslog log version (logs that does not include the header defining the fields)
    /*
        $myFile = fopen("/tmp/testing", "w");

        fwrite($myFile,"Sample log line:\n\n" . $sample1);
        fwrite($myFile,print_r($result1, true));
        fwrite($myFile,"\nPattern size for log:".(count($result1)+1));
    */

    // create and array based on the size of a log line
    $patterns_size = [
        '7.0.x' => 54,
        '8.0' => 61,
        '8.1.0' => 65,
        '8.1.0b' => 64,
        '9.0.0' => 67,
        '9.1.x' => 75,
        '9.1.0b' => 74,
        '10.0.0' => 105,
        '10.1.0' => 115,
        '11.0.0' => 117
    ];

    foreach ($patterns_size as $version => $size){
        // Check the number of fields in the traffic log and, if complies, check that the 2nd and 7th field are time formats
        // Improves performance and supports fields with quoted commas
        if( count($result1)=== $size+1 &&
            $result1[$size] === '' &&
            count($result2) === $size+1 &&
            $result2[$size] === '' &&
            preg_match('/\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}/',$result1[1], $output_array)===1 &&
            preg_match('/\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}/',$result1[6], $output_array)===1 &&
            preg_match('/\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}/',$result2[1], $output_array)===1 &&
            preg_match('/\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}/',$result2[6], $output_array)===1
        ){
            return $version;
        }
    }


//    $patterns = [
//        '8.1.0'  => $regex8_1_0,
//        '7.0.x'  => $regex7_x_x,
//        '8.0.3'  => $regex8_0_2,
//        '9.0.0'  => $regex9_0_0,
//        '9.1.x'  => $regex9_1_x,
//        '10.0.0'  => $regex10_0_0,
//        '10.1.0'  => $regex10_1_0,
//        '9.1.0b' => $regex9_1_0_b,
//        '8.1.0b' => $regex8_1_0beta,
//    ];
//
//    foreach ($patterns as $version => $pattern) {
//        if (preg_match($pattern, $sample1, $output_array) == 1 &&
//            preg_match($pattern, $sample2, $output_array) == 1
//        ) {
//            return $version;
//            break;
//        }
//    }

    return 'unknown';
}

function FileLogSerial(STRING $filepath, STRING $version){
    $serial = 'unknown';
    switch($version){
        case '7.0.x':
        case '8.0.3':
        case '8.1.0':
        case '8.1.0b':
        case '9.0.0':
        case '9.1.x':
        case '9.1.0b':
        case '10.0.0':
        case '10.1.0':
        default:
            preg_match("/(.*).[gz|gzip]/", $filepath, $output_array);
            if(count($output_array)>0){
                $file = gzopen($filepath, 'r');
            }
            else{
                $file = fopen($filepath, 'r');
            }
            trim(fgets($file)); //Move the pointer to the second line
            trim(fgets($file)); //Move the pointer to the third line
            $line = trim(fgets($file));
            $logFieldsData = explode(",", $line);

            $serial = isset($logFieldsData[2])?$logFieldsData[2]:'unknown';
            break;
    }
    return $serial;
}