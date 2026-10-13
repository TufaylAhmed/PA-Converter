#!/bin/bash

showHelp(){
    echo
    echo '   ./prepareTrafficLog.sh -i <INPUTFILE> -v <PANOS_VERSION> [options]'
    echo '   example:   ./prepareTrafficLog.sh -i myfile.csv -v 8.0.1 -vvv'
    echo
    echo '   options'
    echo '      -i, --input $INPUTFILE:        name of the CSV traffic file'
    echo '      -V, --version $PANOS_Version:  possible values are 7.0.1, 8.0.1 to 8.0.8, 8.1.0'
    echo '      -v, --verbose:                 verbose mode'
    echo '      -h, --help:                    give this help'
    echo
    exit
}

POSITIONAL=()
while [[ $# -gt 0 ]]
do
key="$1"

case $key in
    -h|--help)
    HELP=YES
    shift
    ;;
    -i|--input)
    INPUTFILE="$2"
    shift # past argument
    shift # past value
    ;;
    -V|--version)
    PANOSVER="$2"
    shift # past argument
    shift # past value
    ;;
    -v|--verbose)
    VERBOSE="y"
    shift # past argument
    ;;
    --default)
    DEFAULT=YES
    shift # past argument
    ;;
    *)    # unknown option
    echo "prepareTrafficLog.sh: invalid option -- '$1'"
    echo "Try 'prepareTrafficLog.sh --help' for more information."
    exit
    ;;
esac
done
set -- "${POSITIONAL[@]}" # restore positional parameters

if [[ $VERBOSE = 'y' ]]
then
    echo INPUT FILE      = "${INPUTFILE}"
    echo PANOSVER        = "${PANOSVER}"
    echo VERBOSE         = "${VERBOSE}"
    echo DEFAULT         = "${DEFAULT}"
fi

if [[ $PANOSVER == "" ]]; then
    showHelp
fi

if [[ $INPUTFILE == "" ]]; then
    showHelp
fi

if [[ $HELP == "YES" ]]; then
    showHelp
fi



version7_x_x='Domain,Receive Time,Serial #,Type,Threat/Content Type,Config Version,Generate Time,Source address,Destination address,NAT Source IP,NAT Destination IP,Rule,Source User,Destination User,Application,Virtual System,Source Zone,Destination Zone,Inbound Interface,Outbound Interface,Log Action,Time Logged,Session ID,Repeat Count,Source Port,Destination Port,NAT Source Port,NAT Destination Port,Flags,IP Protocol,Action,Bytes,Bytes Sent,Bytes Received,Packets,Start Time,Elapsed Time (sec),Category,Padding,seqno,actionflags,Source Country,Destination Country,cpadding,pkts_sent,pkts_received,session_end_reason,dg_hier_level_1,dg_hier_level_2,dg_hier_level_3,dg_hier_level_4,vsys_name,device_name,action_source';
version7_x_x2='Domain,Receive Time,Serial #,Type,Threat/Content Type,Config Version,Generate Time,Source address,Destination address,NAT Source IP,NAT Destination IP,Rule,Source User,Destination User,Application,Virtual System,Source Zone,Destination Zone,Inbound Interface,Outbound Interface,Log Action,Time Logged,Session ID,Repeat Count,Source Port,Destination Port,NAT Source Port,NAT Destination Port,Flags,IP Protocol,Action,Bytes,Bytes Sent,Bytes Received,Packets,Start Time,Elapsed Time (sec),Category,Padding,Sequence Number,Action Flags,Source Country,Destination Country,cpadding,pkts_sent,pkts_received,session_end_reason,dg_hier_level_1,dg_hier_level_2,dg_hier_level_3,dg_hier_level_4,Virtual System Name,Device Name,action_source';
#Log format valid for 8.0.2, 8.0.3, 8.0.5
version8_0_2='Domain,Receive Time,Serial #,Type,Threat/Content Type,Config Version,Generate Time,Source address,Destination address,NAT Source IP,NAT Destination IP,Rule,Source User,Destination User,Application,Virtual System,Source Zone,Destination Zone,Inbound Interface,Outbound Interface,Log Action,Time Logged,Session ID,Repeat Count,Source Port,Destination Port,NAT Source Port,NAT Destination Port,Flags,IP Protocol,Action,Bytes,Bytes Sent,Bytes Received,Packets,Start Time,Elapsed Time (sec),Category,Padding,Sequence Number,Action Flags,Source Country,Destination Country,cpadding,pkts_sent,pkts_received,session_end_reason,dg_hier_level_1,dg_hier_level_2,dg_hier_level_3,dg_hier_level_4,Virtual System Name,Device Name,action_source,Source VM UUID,Destination VM UUID,Tunnel ID/IMSI,Monitor Tag/IMEI,Parent Session ID,parent_start_time,tunnel';
version8_1_0_b='Domain,Receive Time,Serial #,Type,Threat/Content Type,Config Version,Generate Time,Source address,Destination address,NAT Source IP,NAT Destination IP,Rule,Source User,Destination User,Application,Virtual System,Source Zone,Destination Zone,Inbound Interface,Outbound Interface,Log Action,Time Logged,Session ID,Repeat Count,Source Port,Destination Port,NAT Source Port,NAT Destination Port,Flags,IP Protocol,Action,Bytes,Bytes Sent,Bytes Received,Packets,Start Time,Elapsed Time (sec),Category,Sequence Number,Action Flags,Source Country,Destination Country,cpadding,Packets Sent,Packtes Received,Session End Reason,DG Hierarchy Level 1,DG Hierarchy Level 2,DG Hierarchy Level 3,DG Hierarchy Level 4,Virtual System Name,Device Name,Action Source,Source VM UUID,Destination VM UUID,Tunnel ID/IMSI,Monitor Tag/IMEI,Parent Session ID,Parent Session Start Time,Tunnel,SCTP Association ID,SCTP Chunks,SCTP Chunks Sent,SCTP Chunks Received';
version8_1_0='Domain,Receive Time,Serial #,Type,Threat/Content Type,Config Version,Generate Time,Source address,Destination address,NAT Source IP,NAT Destination IP,Rule,Source User,Destination User,Application,Virtual System,Source Zone,Destination Zone,Inbound Interface,Outbound Interface,Log Action,Time Logged,Session ID,Repeat Count,Source Port,Destination Port,NAT Source Port,NAT Destination Port,Flags,IP Protocol,Action,Bytes,Bytes Sent,Bytes Received,Packets,Start Time,Elapsed Time (sec),Category,Padding,Sequence Number,Action Flags,Source Country,Destination Country,cpadding,Packets Sent,Packets Received,Session End Reason,DG Hierarchy Level 1,DG Hierarchy Level 2,DG Hierarchy Level 3,DG Hierarchy Level 4,Virtual System Name,Device Name,Action Source,Source VM UUID,Destination VM UUID,Tunnel ID/IMSI,Monitor Tag/IMEI,Parent Session ID,Parent Session Start Time,Tunnel,SCTP Association ID,SCTP Chunks,SCTP Chunks Sent,SCTP Chunks Received';
version9_0_0='Domain,Receive Time,Serial #,Type,Threat/Content Type,Config Version,Generate Time,Source address,Destination address,NAT Source IP,NAT Destination IP,Rule,Source User,Destination User,Application,Virtual System,Source Zone,Destination Zone,Inbound Interface,Outbound Interface,Log Action,Time Logged,Session ID,Repeat Count,Source Port,Destination Port,NAT Source Port,NAT Destination Port,Flags,IP Protocol,Action,Bytes,Bytes Sent,Bytes Received,Packets,Start Time,Elapsed Time (sec),Category,tpadding,Sequence Number,Action Flags,Source Country,Destination Country,cpadding,Packets Sent,Packets Received,Session End Reason,DG Hierarchy Level 1,DG Hierarchy Level 2,DG Hierarchy Level 3,DG Hierarchy Level 4,Virtual System Name,Device Name,Action Source,Source VM UUID,Destination VM UUID,Tunnel ID/IMSI,Monitor Tag/IMEI,Parent Session ID,Parent Session Start Time,Tunnel,SCTP Association ID,SCTP Chunks,SCTP Chunks Sent,SCTP Chunks Received,UUID for rule,HTTP/2 Connection,link_change_count,policy_id,link_switches,sdwan_cluster,sdwan_device_type,sdwan_cluster_type,sdwan_site,dynusergroup_name';


echo "Result:"
#Check whether the file already contains headers
commonHeader='Domain,Receive Time,Serial #,'
firstLine=$(head -n 1 $INPUTFILE)
if [[ $firstLine = *"$commonHeader"* ]]; then
  echo "         \"$INPUTFILE\" already contains headers"
  exit
fi

case $PANOSVER in
    7.0.1)          header=version7_x_x ;;

    8.0.0)          header=$version8_0_2  ;;
    8.0.1)          header=$version8_0_2  ;;
    8.0.2)          header=$version8_0_2  ;;
    8.0.3)          header=$version8_0_2  ;;
    8.0.3-h4)          header=$version8_0_2  ;;
    8.0.4)          header=$version8_0_2  ;;
    8.0.5)          header=$version8_0_2  ;;
    8.0.6)          header=$version8_0_2  ;;
    8.0.6-h3)          header=$version8_0_2  ;;
    8.0.7)          header=$version8_0_2  ;;
    8.0.8)          header=$version8_0_2  ;;

    8.1.0-beta)     header=$version8_1_0_b  ;;

    8.1.0)          header=$version8_1_0  ;;
    8.1.1)          header=$version8_1_0  ;;

    9.0.0)          header=$version9_0_0  ;;

    *)              header="INVALID";
esac

if [[ $header != "INVALID" ]]
then
#Verify whether the file has already the header
    `sed -i "1i $header" $INPUTFILE`
    echo "         Done";
else
    echo "         Invalid Panos version";
fi


