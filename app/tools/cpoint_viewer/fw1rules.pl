#!/usr/bin/perl

#############################################################################
# fw1rules.pl: Analyze and print a report of Firewall-1 rules and objects
#              Note: unsupported by Checkpoint or representatives.
#
# Copyright (C) 2000-2008 Volker Tanger
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# For bug reports and suggestions or if you just want to talk to me please
# contact me at volker.tanger@wyae.de
#
# Updates will be available at  http://www.wyae.de/software/
# please check there for updates prior to submitting patches!
#
# For list of changes please refer to the HISTORY file. Thanks.
#############################################################################


#
# Used modules
#
use Getopt::Long;
use File::Basename;

$VERSION	 = '7.3.44';   ###versioninformation###
$SCR_NAME	 = 'FW1rules';
$HTMLtitle	 = 'FireWall-1 Rule Base and Object Definitions';
$HTMLcssfile	 = 'fw1rules.css';

$FW1rules	 = 'Standard.W';
$FW1objects	 = 'objects.C';
$FW1user	 = 'fwauth.NDB';
$IconPathName	 = '/tools/cpoint_viewer/icons';

$Match_Logic = '(src && dst && svc && com)';

$LogFile	 = 'FW1Rules.log';
$DebugFile	 = 'FW1Rules.debug.log';
$TemplateINCLUDE = '';
$TemplateITEMSEP = ' ';


%colors =
  ( # NG colors included, now 36 colors
   'aquamarine1'	=> '#7BFFD6',
   'black'		=> '#000000',
   'blue'		=> '#0000FF',
   'blue1'		=> '#4241EF',
   'burlywood4'		=> '#8C7152',
   'cyan'		=> '#00FFFF',
   'dark green'		=> '#848200',
   'dark khaki'		=> '#BDB66B',
   'dark orchid'	=> '#840084',
   'darkorange3'	=> '#CE6500',
   'darkseagreen3'	=> '#9CCF9C',
   'deep pink'		=> '#FF1494',
   'deepskyblue1'	=> '#00BEFF',
   'dodgerblue3'	=> '#1875CE',
   'firebrick'		=> '#B52021',
   'foreground'		=> '#000000',
   'forest green'	=> '#218A21',
   'gold'		=> '#FFD700',
   'gold3'		=> '#CEAE00',
   'gray83'		=> '#D6D7D6',
   'gray90'		=> '#ADB2C6',
   'green'		=> '#00FF00',
   'lemonchiffon'	=> '#FFFBCE',
   'light coral'	=> '#F78284',
   'lightseagreen'	=> '#21B2AD',
   'lightskyblue4'	=> '#63798C',
   'magenta'		=> '#FF00FF',
   'medium orchid'	=> '#BD55D6',
   'medium slate blue'	=> '#7B69EF',
   'medium violet red'	=> '#C61484',
   'navy blue'		=> '#000084',
   'olive drab'		=> '#6B8E21',
   'orange'		=> '#FFA600',
   'red'		=> '#FF0000',
   'sienna'		=> '#A55129',
   'yellow'		=> '#FFFF00'
   );


%netmasktranslation = (
	'255.255.255.255'  => '32',
	'255.255.255.254'  => '31',
	'255.255.255.252'  => '30',
	'255.255.255.248'  => '29',
	'255.255.255.240'  => '28',
	'255.255.255.224'  => '27',
	'255.255.255.192'  => '26',
	'255.255.255.128'  => '25',
	'255.255.255.0'	   => '24',
	'255.255.254.0'	   => '23',
	'255.255.252.0'	   => '22',
	'255.255.248.0'	   => '21',
	'255.255.240.0'	   => '20',
	'255.255.224.0'	   => '19',
	'255.255.192.0'	   => '18',
	'255.255.128.0'	   => '17',
	'255.255.0.0'	   => '16',
	'255.254.0.0'	   => '15',
	'255.252.0.0'	   => '14',
	'255.248.0.0'	   => '13',
	'255.240.0.0'	   => '12',
	'255.224.0.0'	   => '11',
	'255.192.0.0'	   => '10',
	'255.128.0.0'	   => '9',
	'255.0.0.0'	   => '8',
	'254.0.0.0'	   => '7',
	'252.0.0.0'	   => '6',
	'248.0.0.0'	   => '5',
	'240.0.0.0'	   => '4',
	'224.0.0.0'	   => '3',
	'192.0.0.0'	   => '2',
	'128.0.0.0'	   => '1',
	'0.0.0.0'	   => '0'  );

%NATtranslation = (
	0 => 'hide',
	1 => 'static' );

$SynDefender[0] = 'None';
$SynDefender[1] = 'SYN Relay';
$SynDefender[2] = 'SYN Gateway';
$SynDefender[3] = 'Passive SYN Gateway';

%ICMPtranslate = (
	'icmp_type=ICMP_ECHOREPLY'	=> 0,
	'icmp_type=ICMP_UNREACH',	=> 3,
	'icmp_type=ICMP_SOURCEQUENCH',	=> 4,
	'icmp_type=ICMP_REDIRECT',	=> 5,
	'icmp_type=ICMP_ECHO',		=> 8,
	'icmp_type=ICMP_TIMXCEED'	=> 11,
	'icmp_type=ICMP_PARAMPROB',	=> 12,
	'icmp_type=ICMP_TSTAMP',	=> 13,
	'icmp_type=ICMP_TSTAMPREPLY',	=> 14,
	'icmp_type=ICMP_IREQ',		=> 15,
	'icmp_type=ICMP_IREQREPLY',	=> 16,
	'icmp_type=ICMP_MASKREQ',	=> 17,
	'icmp_type=ICMP_MASKREPLY',	=> 18,
);

##########################################################################
# print out Usage
sub Usage{
  print STDERR "

-----------------------------------------------------------------------
			FW1Rules   USAGE
-----------------------------------------------------------------------

   fw1rules.pl
	[--objects=<objects file>]
	[--rules=<rules file>]
	[--merge_SP3=<FWS rules file>]  or [--merge_AI=<FWS rules file>]
	[--all_objects] [--all_services]
	[--no_rules] [--no_objects] [--no_services]
	[--no_servers]
	[--with_implicit_rules] [--with_ip]
	[--with_interfaces] [--with_antispoofing]
	[--show_members]
	[--sort_by_type]
	[--match_comment=<string>]  [--match_installon=<string>]
	[--match_source=<string>] [--match_destination=<string>]
	[--match_service=<string>] [--match_case]
	[--match_logic=<string>]
	[--verbose] [--debug] [--version]

	[--dump_unused_objects=<text file>]
	[--dump_unused_objects_tsv=<text file>]

	[--use-css=<css file>]
	[--with_colors] [--icon_path=<path>]
	[--link_to=<directory>]
	[--title=<document title>]
	[--output_html=<html file>]


	[--template=<template file>]
	[--template_include=<template include filename>]

	[--unused_objects]
	[--hosts_only]
	[--gateways_only]
	[--networks_only]
	[--groups_only]
	[--expand_object_groups]
        [--expand_service_groups]

	[--output=<filled template file>]



Optional Parameters:
--------------------

   --rules=<rule file>: Location of FireWall-1 rule file.
	Default is 'Standard.W'

   --merge_SP3=<FWS rule file>  or
   --merge_AI=<FWS rule file>: Location of FireWall-1 SP3 rulebases file
	Merges <rule file> with comments of <FWS rule file>
	eg. 'rulebases_5_0.fws'

   --objects=<objects file>: Location of FireWall-1 objects file.
	  Default is 'objects.C' which is good for V4.1,
	  please use 'objects_5_0.C' if you are using CKP-NG

   --all_objects  /  --all_services :
	it will list ALL objects/services. By default only those
	in use will be listed.

   --no_rules / --no_objects / --no_services / --no_servers:
	it will NOT read nor list rules/objects/services/servers.
	Default disabled.
	--no_rules implies --all_objs and --all_services

   --with_implicit_rules: include the implicit rules into the tables

   --with_ip: prints IP addresses along with the object names into the
	access rule & objects dump for HTML.
	(Note: this does not affect templates or dumps - see below)

   --with_interfaces: prints interfaces per network object for HTML.
	(Note: this does not affect templates or dumps - see below)

   --with_antispoofing: prints antispoofing information in the comment
	fields of the network object for HTML.
	(Note: this does not affect templates or dumps - see below)

   --show_members: lists groups with their members in access/NAT rules.
	(Note: this does not affect templates or dumps - see below)

   --sort_by_type: use object and service type as primary sorting key
   	to group them. Secondary key is alphabetically then. Default
	sorting is just plain alphabetically (case ignore).

   --match_case: search case sensitive for all --match_options below

   --match_comment=<string>  /  --match_installon=<string>  /
   --match_source=<string>   /  --match_destination=<string>  /
   --match_service=<string>:
	Only those NAT and access rules will be printed that match the
	literal string (NOT RegEx!) given as parameter. The objects
	and services used will be limited accordingly unless the
	corresponding --all... switches are given.

   --match_logic=<string>: Match Pattern Logic (src/dst/svc/com)
	src = Source, dst = Destination, svc = Serivce, com = Comment
	Pattern Operator: && = AND, || = OR, ! = NOT
	eg.: --match_logic='com && ( !dst )\'
	or : --match_logic='com && ( src || dst )'
	Default: --match_logic='( src && dst && svc && com )'
	You will still have to give all the --match_... parameters!

   --with_colors: Add html color tags to network and service objects
	to reflect the colors used in the FW-1 GUI.  By default, this
	is OFF to enhance readability (e.g. on printouts).

   --icon_path=<path>: Location of the icon graphic files.
   	Defaults is './icons'

   --use-css=<css file>: include reference to the CSS file given (for
	nicer output). Default is './fw1rules.css'

   --title=<title>: Here you can set a custom document title.
	Defaults to the ruleset filename (as given or Standard.W).

   --link_to=<directory>: references put in [squarebrackets] into the
	comment field will be HTML-linked to the file
		<directory>/squarebrackets.html
	    or	<directory>/squarebrackets.pdf
	for easier rule/project/background documentation

   --verbose: prints debugging information to STDERR and FWrules.log

   --version: prints version and exists

   --expand_object_groups: checking a rulebase with groups or
        groups within groups can be a horrible job; this option
        expands object groups and removes duplicates

   --expand_service_groups: checking a rulebase with groups or
        groups within groups can be a horrible job; this option
        expands object groups and removes duplicates


To give an overall documentation of the ruleset (and used objects) you
can print the output into different file formats. Other formats will
be supported as soon as someone supplies according documentation or
patch. You can call any number of these options (okay, only one per
file type per program run):

   --output_html=<html file>


For cleaning up firewall rulesets a list of unused objects comes in
very handy, so these functions sort out the culprits for you:

   --dump_unused_objects=<text file>
   --dump_unused_objects_tsv=<text files>


To fill a custom template with the current firewall configuration you
have to give a template file and the name of the resulting file. You
only can give one template/output pair per program run.

A number of predefined templates is supplied with the tarball in the
subdirectory templates/

A special case is the option --template_include where one can set the
template variable <<<include>>> to be replaced with the command line
parameter. This comes in handy when defining files to be included e.g.
for producing complete documentations - see the template called
templates/fullconfig.txt

   --template=<template file>
   --template_include=<template include filename>
   --output=<filled template file>
   --unused_objects
   --hosts_only
   --gateways_only
   --networks_only
   --groups_only


!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!!!                    WARNING                           !!!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

The following functions to dump objects, service definitions or rules
into TabSeparated or TXT files will be removed from future versions of
FW1Rules. Please use the proper template files instead.


   --dump_nat_tsv=<tab separated NAT rules file>
   --dump_nat_txt=<NAT rules text file>
   --dump_objects_tsv=<tab separated objects file>
   --dump_objects_txt=<objects text file>
   --dump_rules_tsv=<tab separated rules file>
   --dump_rules_txt=<rules text file>
   --dump_services_tsv=<tab separated services file>
   --dump_services_txt=<services text file>
   --dump_unused_objects=<text file>
   --dump_unused_objects_tsv=<text files>
   --dump_properties=<properties text file>

!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!!!                    WARNING                           !!!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

\n";
}

##########################################################################
# correct Micro$oft stuff (line end, spaces)
sub fromdos {
    $line = $_[0];
    $line =~ s/\n//g;
    $line =~ s/\r//g;
    $line =~ s/        /\t/g;
    return $line;
}

##########################################################################
# print out comments / errors
sub PrintLog{
    my ($msg) = $_[0];
    if ($FLAG_verbose){
	print STDERR "$msg";
	print LOGFILE "$msg";
    }
}

##########################################################################
# print out comments / errors
sub DebugLog{
    my ($msg) = $_[0];
    if ($FLAG_debug){
	print DEBUGFILE "$msg\n";
    }
}

##########################################################################
# print only if second parameter not empty
sub PrintNonempty{
    my ($FILE)   = $_[0];
    my ($first)  = $_[1];
    my ($second) = $_[2];

    if ( "$second" ne '' ) {
	printf $FILE ("$first","$second");
    }
}

##########################################################################
# read all network entities/objects defined
#
# Object variables where obj_name equals the hash for each of these:
#
#	$obj_number 	= number of objects
#	@obj_name 	= names of all objects
#	%obj_type 	= host, network, gateway, group
#	%obj_location 	= 0=internal, 1=external
#	%obj_is_fw1 	= has FW1 installed? 0=false, 1=true
#	%obj_ipaddr 	= IP Address
#	%obj_netmask	= netmask
#	%obj_NATadr 	= NAT address for implicit NAT
#	%obj_NATtype 	= 0=hide, 1=static
#	%obj_members 	= members, if a group
#	%obj_comment 	= comment for the object
#	%obj_colour 	= colour the object is to be displayed with
#	%obj_used 	= count objects usage in the rulebase
#			  (set later when evaluating the ruleset)
#       %obj_if_number	= Number of interfaces added to an object
#
# Object variables where NICinterfacenumber.obj_name equals the hash
#   	%obj_if_name	= Name of the interface added
#	%obj_if_ipaddr	= IP Address of the interface added
#	%obj_if_netmask	= Netmask of the interface added

sub ReadNetworkObjects{
    my ($dummy)     = '';
    my ($name)      = '';
    my ($lineparam) = '';
    my ($amember)   = '';
    my ($members)   = '';

    $obj_number = 0;
    $mode_cluster_members = 0;
    while ( ($line = <INFILE> ) && ( fromdos("$line") ne "\t)" ) ) {
          $line = &fromdos($line);
    	  &DebugLog("Obj.READ1: $line");
          while ( $line !~ /\t\t\: \(/ )  {
                $line = <INFILE>;
                $line = &fromdos($line);
		&DebugLog("Obj.READ2: $line");
          }
          ($dummy,$name) = split(/\(/,$line,2) ;
	  $obj_if_number{$name} = 0;
          $amember = '';
          $members = '';
          while ( ($line = <INFILE>) && ( fromdos("$line") ne "\t\t)" ) ) {
                $line = &fromdos($line);
		&DebugLog("Obj.READ3: $line");
                ($dummy,$lineparam) = split(/\(/,$line,2) ;
                $lineparam =~ s/\)$//;
		if ( $line =~ /^\t\t\t:type \(/ ){
		   $obj_type{$name} = lc($lineparam);
                } elsif ( $line =~ /^\t\t\t:location \(/ ){
		   $obj_location{$name} = ("$lineparam" eq 'external') * 1;
                } elsif ( $line =~ /^\t\t\t:firewall \(/ ){
		   $obj_is_fw1{$name} = ("$lineparam" eq 'installed') * 1;
                } elsif ( $line =~ /^\t\t\t:ipaddr \(/ ){
		   if($obj_if_number{$name} == 0){
			$obj_if_number{$name} = -1;
		   }
 		   $obj_ipaddr{$name} = "$lineparam";
                } elsif ( $line =~ /^\t\t\t:ipaddr_first \(/ ){
 		   $obj_netmask{$name} = "$lineparam";
                } elsif ( $line =~ /^\t\t\t:ipaddr_last \(/ ){
 		   $obj_netmask{$name} = "$obj_netmask{$name} - $lineparam";
                } elsif ( $line =~ /^\t\t\t:netmask \(/ ){
                   $obj_netmask{$name} = $lineparam;
                } elsif ( $line =~ /^\t\t\t:valid_ipaddr \(/ ){
 		   $obj_NATadr{$name} = $lineparam;
 		   if ( $FLAG_implicitrules ) { &SetObjUsed("$name"); }
                } elsif ( $line =~ /^\t\t\t:netobj_adtr_method \(/ ){
		   $obj_NATtype{$name} = ("$lineparam" eq 'adtr_static') * 1;
                } elsif ( $line =~ /^\t\t\t:comments \(/ ){
 		   $obj_comment{$name} = $lineparam;
		   $obj_comment{$name} =~ s/^\"|\"$//g;		#--- remove " at beginning and end
		   $obj_comment{$name} =~ s/;/ /g;
                } elsif ( $line =~ /^\t\t\t:color \(/ ){
 		   $obj_colour{$name} = lc($lineparam);
                   $obj_colour{$name} =~ s/^\"|\"$//g;          #--- remove " at beginning and end
               } elsif ( $line =~ /^\t\t\t: \(ReferenceObject/ ){
		   while ( ($line = <INFILE>) && ( fromdos("$line") ne "\t\t\t)" ) ) {
		   	$line = &fromdos($line);
			&DebugLog("Obj.READ4: $line");
			if ( $line =~ /^\t\t\t\t:Name \(/) {
				($dummy,$lineparam) = split(/\(/,$line,2) ;
				$lineparam =~ s/\)$//;
                   		$members = "$members§$lineparam";
			}
		   }
# The 'if' clause adds the member to $members only if the current mode is 'cluster_members'.
# This prevents the 'cluster masters' from being added to $members.
		}elsif($line =~ /^\t\t\t\t:\S+ \(ReferenceObject/){
		    while(($line = <INFILE>) && (fromdos("$line") ne "\t\t\t\t)")){
			$line = fromdos($line);
			if($line =~ /^\t\t\t\t\t:Name \(/){
			    if($mode_cluster_members){
				($dummy,$lineparam) = split(/\(/,$line,2);
				$lineparam =~ s/\)$//;
				$members = "$members§$lineparam";
			    }
			}
		    }
		# process members of 'group_with_exclusion' objects.
		# First the base members :
		}elsif($line =~ /^\t\t\t:base \(ReferenceObject/){
			while(($line = <INFILE>) && (fromdos("$line") ne "\t\t\t)")){
			    $line = fromdos($line);
			    if($line =~ /^\t\t\t\t:Name \(/){
				($dummy,$lineparam) = split(/\(/,$line,2);
				$lineparam =~ s/\)$//;
				$obj_members_base{$name} = $lineparam;
				&SetObjUsed("$lineparam");
				last;
			    }
			}
		# Now the excluded members:
		}elsif($line =~ /^\t\t\t:exception \(ReferenceObject/){
			while(($line = <INFILE>) && (fromdos("$line") ne "\t\t\t)")){
		  	    $line = fromdos($line);
			    if($line =~ /^\t\t\t\t:Name \(/){
				($dummy,$lineparam) = split(/\(/,$line,2);
				$lineparam =~ s/\)$//;
				$obj_members_exception{$name} = $lineparam;
				&SetObjUsed("$lineparam");
				last;
			    }
			}
                } elsif ( $line =~ /^\t\t\t: / ){
                   ($dummy,$amember) = split(/: /,$line,2) ;
                   $members = "$members§$amember";
    		} elsif ( ($line =~ /^\t\t\t:if-(.|..) \(/ ) && ($FLAG_withinterface) ){
		    $obj_if_number{$name} = $1 + 1;
		    while  ( ($line = <INFILE>) && ( fromdos("$line") ne "\t\t\t)" ) ) {
			$line = &fromdos($line);
		        ($dummy,$lineparam) = split(/\(/,$line,2) ;
      	        	$lineparam =~ s/\)$//;
			if ( ($line =~ /^\t\t\t\t:iffullname \(/) || ($line =~ /^\t\t\t\t:officialname \(/) ){
				$obj_if_name{"NIC$obj_if_number{$name}\.$name"} = $lineparam;
			} elsif ( $line =~ /^\t\t\t\t:ipaddr \(/ ){
				$obj_if_ipaddr{"NIC$obj_if_number{$name}\.$name"} = $lineparam;
			} elsif ( $line =~ /^\t\t\t\t:netmask \(/ ){
				$obj_if_netmask{"NIC$obj_if_number{$name}\.$name"} = $lineparam;
			# process anti-spoofing settings for 4.1.
			}elsif($line =~ /^\t\t\t\t:netaccess \(Others/){
				$obj_if_spoof{"NIC$obj_if_number{$name}\.$name"} = "Others";
			}elsif($line =~ /^\t\t\t\t:netaccess \(\" \+ (.*)\"/){
				$accessobj = "$1";
				$obj_if_spoof{"NIC$obj_if_number{$name}\.$name"} = "Others + " . $accessobj;
				&SetObjUsed("$accessobj");
			}elsif($line =~ /^\t\t\t\t:netaccess \(\"This Net\"/){
				$obj_if_spoof{"NIC$obj_if_number{$name}\.$name"} = "ThisNet";
			}elsif($line =~ /^\t\t\t\t\t:refname \(\"\#_(.*)\"\)/){
				$accessobj = "$1";
				$obj_if_spoof{"NIC$obj_if_number{$name}\.$name"} = $accessobj;
				&SetObjUsed("$accessobj");
			}
		    }
                } elsif(($line =~ /^\t\t\t\t:([0-9]|[0-9][0-9]) \(/) && ($FLAG_withinterface)){
			$obj_if_number{$name} = $1 + 1;
			while(($line = <INFILE>) && (fromdos("$line") ne "\t\t\t\t)")){
				$line = fromdos($line);
				($dummy,$lineparam) = split(/\(/,$line,2);
				$lineparam =~ s/\)$//;
				if(($line =~ /^\t\t\t\t\t:iffullname \(/) || ($line =~ /^\t\t\t\t\t:officialname \(/)){
					$obj_if_name{"NIC$obj_if_number{$name}\.$name"} = $lineparam;
				}elsif($line =~ /^\t\t\t\t\t:ipaddr \(/){
					$obj_if_ipaddr{"NIC$obj_if_number{$name}\.$name"} = $lineparam;
				}elsif($line =~ /^\t\t\t\t\t:netmask \(/){
					$obj_if_netmask{"NIC$obj_if_number{$name}\.$name"} = $lineparam;
				# process anti-spoofing settings for NG.
                                }elsif($line =~ /^\t\t\t\t\t\t:access \(this/){
                                        $obj_if_spoof{"NIC$obj_if_number{$name}\.$name"} = "ThisNet";
				}elsif($line =~ /^\t\t\t\t\t\t\t:Name \((.*)\)/){
					$obj_if_spoof{"NIC$obj_if_number{$name}\.$name"} = $1;
					&SetObjUsed("$1");
				}
			}
		}
                if($line =~ /^\t\t\t:cluster_members \(/){
			$mode_cluster_members = 1;
		}elsif($line =~ /^\t\t\t:/){
			$mode_cluster_members = 0;
		}
          }
          if ( ("$obj_type{$name}" eq 'group') || ("$obj_type{$name}" eq 'gateway_cluster') ) {
             ($dummy,$members) = split (/§/, $members, 2);
             $obj_members{$name} = $members;
          } elsif ($FLAG_withinterface && ($obj_if_number{$name} > 0)) {
		@txt = ();
		for ($i = 1; $i <= $obj_if_number{$name}; $i++) {
		    $ref = "NIC$i.$name";
		    push(@txt, $obj_if_ipaddr{$ref});
		}
		$obj_members{$name} = "@txt";
	  }
	  $obj_name[$obj_number] = $name;
	  $obj_number += 1;
          &PrintLog('.');
    }
    $obj_type{'Any'} = 'any';
    if ($FLAG_sortbytype) {
    	@obj_name = sort { $obj_type{"$a"} cmp $obj_type{"$b"} or lc($a) cmp lc($b) } @obj_name;
    } else {
    	@obj_name = sort { lc($a) cmp lc($b) } @obj_name;
    }
}

#=====================================================================

sub ReadNetobjadtr{
    my ($dummy)     = '';
    my ($name)      = '';
    my ($lineparam) = '';
    my ($amember)   = '';
    my ($members)   = '';
    my ($eof_flag)  = 0;

    while ( ($line = <INFILE> ) && ( fromdos("$line") ne "\t)" ) ) {
          $line = &fromdos($line);
    	  &DebugLog("NetObj.READ1: $line");
	  $eof_flag = 0;
          while ( ($line !~ /\t\t\: \(/ ) && ( ! $eof_flag ) )  {
                $eof_flag = ($line = <INFILE>);
                $line = &fromdos($line);
		&DebugLog("NetObj.READ2: $line");
          }
          ($dummy,$name) = split(/\(/,$line,2) ;
          $amember = '';
          $members = '';
          while ( ($line = <INFILE>) && ( fromdos("$line") ne "\t\t)" ) ) {
                $line = &fromdos($line);
		&DebugLog("NetObj.READ3: $line");
                ($dummy,$lineparam) = split(/\(/,$line,2) ;
                $lineparam =~ s/\)$//;
		if ( $line =~ /^\t\t\t:type \(/ ){
		   $obj_type{$name} = lc($lineparam);
                } elsif ( $line =~ /^\t\t\t:ipaddr_first \(/ ){
 		   $obj_netmask{$name} = "$lineparam";
                } elsif ( $line =~ /^\t\t\t:ipaddr_last \(/ ){
 		   $obj_netmask{$name} = "$obj_netmask{$name} - $lineparam";
                } elsif ( $line =~ /^\t\t\t:valid_ipaddr \(/ ){
 		   $obj_NATadr{$name} = $lineparam;
                } elsif ( $line =~ /^\t\t\t:netobj_adtr_method \(/ ){
		   $obj_NATtype{$name} = ("$lineparam" eq 'adtr_static') * 1;
                } elsif ( $line =~ /^\t\t\t:comments \(/ ){
 		   $obj_comment{$name} = $lineparam;
		   $obj_comment{$name} =~ s/^\"|\"$//g;		#--- remove " at beginning and end
		   $obj_comment{$name} =~ s/;/ /g;
                } elsif ( $line =~ /^\t\t\t:color \(/ ){
 		   $obj_colour{$name} = lc($lineparam);
                   $obj_colour{$name} =~ s/^\"|\"$//g;          #--- remove " at beginning and end
		} elsif ( $line =~ /^\t\t\t: \(ReferenceObject/ ){
		   while ( ($line = <INFILE>) && ( fromdos("$line") ne "\t\t\t)" ) ) {
		   	$line = &fromdos($line);
			&DebugLog("NetObj.READ4: $line");
			if ( $line =~ /^\t\t\t\t:Name \(/) {
				($dummy,$lineparam) = split(/\(/,$line,2) ;
				$lineparam =~ s/\)$//;
                   		$members = "$members§$lineparam";
			}
		   }
                } elsif ( $line =~ /^\t\t\t: / ){
                   ($dummy,$amember) = split(/: /,$line,2) ;
                   $members = "$members§$amember";
                }
          }
	  $obj_name[$obj_number] = $name;
	  $obj_number += 1;
          &PrintLog('.');
    }
    $obj_type{'Any'} = 'any';
    if ($FLAG_sortbytype) {
    	@obj_name = sort { $obj_type{"$a"} cmp $obj_type{"$b"} or lc($a) cmp lc($b) } @obj_name;
    } else {
    	@obj_name = sort { lc($a) cmp lc($b) } @obj_name;
    }
}


##########################################################################
# read all network services defined
#
# service variables where svc_name equals the hash for each of these:
#
#	$svc_number 	= number of services read
#	@svc_name 	= names of all services
#	%svc_type 	= tcp, udp, icmp, rpc, group
#	%svc_protocol	= protocol for type other
#	%svc_dst_port 	= destination port
#	%svc_src_low 	= range source port from
#	%svc_src_high 	= range source port to
#	%svc_match	= if MATCH defines (for RPCs)
#	%svc_prolog	= RPC prolog
#	%svc_members 	= members, if a group
#	%svc_comment 	= comment for the service
#	%svc_colour 	= colour of the service
#	%svc_used 	= count service usage in the rulebase
#			  (set later when evaluating the ruleset)
#	%svc_timeout	= timeout of the service
sub ReadServices{
    my ($dummy)    = '';
    my ($name)     = '';
    my ($amember)  = '';
    my ($members)  = '';

    while ( ($line = <INFILE>) && ( fromdos("$line") ne "\t)" ) ) {
          $line = &fromdos($line);
    	  &DebugLog("Svc.READ1: $line");
          while ( $line !~ /\t\t\: \(/ )  {
                $line = <INFILE>;
                $line = &fromdos($line);
		&DebugLog("Svc.READ2: $line");
          }
          ($dummy,$name) = split(/\(/,$line,2) ;
          $amember  = '';
          $members  = '';
          while ( ($line = <INFILE>) && ( fromdos("$line") ne "\t\t)" ) ) {
                $line = &fromdos($line);
		&DebugLog("Svc.READ3: $line");
                ($dummy,$lineparam) = split(/\(/,$line,2) ;
                $lineparam =~ s/\)$//;
                if ( "$lineparam" =~ /"\>(.*)\"/ ){  # this stands for ports bigger than...
                   $lineparam = $1;
		   $lineparam++;
                   $lineparam = "$lineparam\:65535";
                   $svc_dst_port{$name} = $lineparam;
                } elsif ( "$lineparam" =~ /"\<(.*)\"/ ){  # this stands for ports smaller than...
                   $lineparam = $1;
		   $lineparam--;
                   $lineparam = "0\:$lineparam";
                   $svc_dst_port{$name} = $lineparam;
                } elsif ( $line =~ /^\t\t\t:type \(/ ){
                   $svc_type{$name} = lc($lineparam);
                } elsif ( $line =~ /^\t\t\t:protocol \(/ ){      # protocol for type other
                   $svc_protocol{$name} = $lineparam;
                } elsif ( $line =~ /^\t\t\t:exp \(/ ){           # ICMP extensions
                   $lineparam =~ s/\"//g;
                   if ($svc_type{$name} =~ /^other$/i) {
                       $lineparam =~ s/\"//g;
                       $svc_dst_port{$name} = $lineparam;
                   } else {
                       $lineparam =~ s/\"//g;
                       $svc_dst_port{$name} = $ICMPtranslate{$lineparam};
                   }
                   $svc_dst_port{$name} = $ICMPtranslate{$lineparam};
                } elsif ( $line =~ /^\t\t\t:port \(/ ){          # TCP/UDP destination port
                   $lineparam =~ tr/-/:/;
                   $svc_dst_port{$name} = $lineparam;
                } elsif ( $line =~ /^\t\t\t:src_port \(/ ){
                   $svc_src_low{$name} = $lineparam;
                   $svc_src_high{$name} = $lineparam;
                } elsif ( $line =~ /^\t\t\t:src_port_from \(/ ){
                   $svc_src_low{$name} = $lineparam;
                } elsif ( $line =~ /^\t\t\t:src_port_to \(/ ){
                   $svc_src_high{$name} = $lineparam;
                } elsif ( $line =~ /^\t\t\t:icmp_type \(/ ){
                   $svc_src_low{$name} = $lineparam;
                } elsif ( $line =~ /^\t\t\t:icmp_code \(/ ){
                   $svc_src_high{$name} = $lineparam;
                } elsif ( $line =~ /^\t\t\t:uuid \(/ ){
                   $svc_dst_port{$name} = $lineparam;
                } elsif ( $line =~ /^\t\t\t:prematch \(/ ){
                   $svc_match{$name} = $lineparam;
                } elsif ( $line =~ /^\t\t\t:prolog \(/ ){
                   $svc_prolog{$name} = $lineparam;
                } elsif ( $line =~ /^\t\t\t:comments \(/ ){
                   $svc_comment{$name} = $lineparam;
		   $svc_comment{$name} =~ s/^\"|\"$//g;		#--- remove " at beginning and end
		   $svc_comment{$name} =~ s/;/ /g;
		} elsif ( $line =~ /^\t\t\t:color \(/ ){
                   $svc_colour{$name} = lc($lineparam);
                   $svc_colour{$name} =~ s/^\"|\"$//g;          #--- remove " at beginning and end
                } elsif ( $line =~ /^\t\t\t:timeout \(/ ){
                   $svc_timeout{$name} = $lineparam;
                } elsif ( $line =~ /^\t\t\t: \(ReferenceObject/ ){
		   while ( ($line = <INFILE>) && ( fromdos("$line") ne "\t\t\t)" ) ) {
		   	$line = &fromdos($line);
			&DebugLog("Svc.READ4: $line");
			if ( $line =~ /^\t\t\t\t:Name \(/) {
				($dummy,$lineparam) = split(/\(/,$line,2) ;
				$lineparam =~ s/\)$//;
                   		$members = "$members§$lineparam";
			}
		   }
                } elsif ( $line =~ /^\t\t\t: / ){
                   ($dummy,$amember) = split(/:\x20/,$line,2) ;
                   $members = "$members§$amember";
                }
          }
	  $svc_name[$svc_number] = $name;
          if ( "$svc_type{$name}" eq 'group' ) {
                ($dummy,$members) = split (/§/, $members, 2);
                $svc_members{$name} = $members;
           }
           &PrintLog('.');
	   $svc_number += 1;
    }
    &PrintLog ("\n");
    $svc_type{'Any'} = 'any';
    if ($FLAG_sortbytype) {
    	@svc_name = sort { $svc_type{"$a"} cmp $svc_type{"$b"} or lc($a) cmp lc($b) } @svc_name;
    } else {
    	@svc_name = sort { lc($a) cmp lc($b) } @svc_name;
    }
}

##########################################################################
# read all network servers defined
#
# Object variables where srv_name equals the hash for each of these:
#
#	$srv_number 	= number of servers
#	@srv_name 	= names of all servers
#	%srv_type 	= radius, tacacs, ufp, cvp, group
#	%srv_members 	= members, if a group
#	%srv_priority 	= priority of the server
#	%srv_reference 	= reference of the server
#	%srv_comment 	= comment for the server
#	%srv_colour 	= colour the server is to be displayed with
#	%srv_version	= version of the server

sub ReadServers{
    my ($dummy)     = '';
    my ($name)      = '';
    my ($lineparam) = '';
    my ($amember)   = '';
    my ($members)   = '';

    $srv_number = 0;
    while ( ($line = <INFILE> ) && ( fromdos("$line") ne "\t)" )) {
          $line = &fromdos($line);
    	  &DebugLog("Srv.READ1: $line");
          while ( $line !~ /\t\t\: \(/ )  {
                $line = <INFILE>;
                $line = &fromdos($line);
 	   	&DebugLog("Srv.READ2: $line");
          }
          ($dummy,$name) = split(/\(/,$line,2) ;
          $amember = '';
          $members = '';
	  $srv_reference{$name} = '-';
	  $priority{$name} = '';
          while ( ($line = <INFILE>) && ( fromdos("$line") ne "\t\t)" )) {
                $line = &fromdos($line);
 	   	&DebugLog("Srv.READ2: $line");
                ($dummy,$lineparam) = split(/\(/,$line,2) ;
                $lineparam =~ s/\)$//;
	     	    if ( $line =~ /^\t\t\t:type \(/ ){
		   	$srv_type{$name} = lc($lineparam);
                } elsif ( $line =~ /^\t\t\t:color \(/ ){
 		   	$srv_colour{$name} = lc($lineparam);
                        $srv_colour{$name} =~ s/^\"|\"$//g;             #--- remove " at beginning and end
                } elsif ( $line =~ /^\t\t\t:comments \(/ ){
                         $srv_comment{$name} = $lineparam;
		   	 $srv_comment{$name} =~ s/^\"|\"$//g;		#--- remove " at beginning and end
		   	 $srv_comment{$name} =~ s/;/ /g;
		    } elsif ( $line =~ /^\t\t\t:priority \(/ ){
			 $srv_priority{$name} = lc($lineparam);
		    } elsif ( $line =~ /^\t\t\t:version \(/ ){
			 $srv_version{$name} = $lineparam;
		   	 $srv_version{$name} =~ s/^\"|\"$//g;		#--- remove " at beginning and end
		   	 $srv_version{$name} =~ s/;/ /g;
		    } elsif ( $line =~ /^\t\t\t:server \(/ ){
			 $line = &fromdos($line);
          		 while ( $line !~ /\t\t\t\t\:(refname|Name) \(/ )  {	# V4.1 | NG
			 	$line = <INFILE>;
				$line = &fromdos($line);
		 	   	&DebugLog("Srv.READ3: $line");
		       }
	             ($dummy,$lineparam) = split(/\(/,$line,2) ;
			 $srv_reference{$name} = $lineparam;
			 $srv_reference{$name} =~ s/^\"|\"\)$|\)$//g;		#--- remove " at beginning and end
			 $srv_reference{$name} =~ s/;/ /g;
                    } elsif ( $line =~ /^\t\t\t: \(ReferenceObject/ ){
		   	while ( ($line = <INFILE>) && ( fromdos("$line") ne "\t\t\t)" ) ) {
		   		$line = &fromdos($line);
		 	   	&DebugLog("Srv.READ4: $line");
				if ( $line =~ /^\t\t\t\t:Name \(/) {
					($dummy,$lineparam) = split(/\(/,$line,2) ;
					$lineparam =~ s/\)$//;
                   			$members = "$members§$lineparam";
				}
		   	}
 		    } elsif ( $line =~ /^\t\t\t: / ){
                   	($dummy,$amember) = split(/: /,$line,2) ;
                   	$members = "$members§$amember";
                    }
            }
	    if ( "$srv_type{$name}" eq 'group' ) {
             ($dummy,$members) = split (/§/, $members, 2);
             $srv_members{$name} = $members;
          }
	    $srv_name[$srv_number] = $name;
	    $srv_number += 1;
          &PrintLog('.');
    }
    $srv_type{'Any'} = 'any';
    if ($FLAG_sortbytype) {
    	@srv_name = sort { $srv_type{"$a"} cmp $srv_type{"$b"} or lc($a) cmp lc($b) } @srv_name;
    } else {
    	@srv_name = sort { lc($a) cmp lc($b) } @srv_name;
    }
}


##########################################################################
# read all resources defined
#
# resource variables where rsc_name equals the hash for each of these:
#
#	$rsc_number 	= number of ressources read
#	@rsc_name 	= names of all ressources
#	%rsc_maxsize 	= maximum size
#	%rsc_allowedchar= allowed characterset
#	%rsc_av_setting	= AntiVirus server handling
#	%rsc_av_server	= ...and it's server
#	%rsc_type	= smtp, http
#	%rsc_comment	= comment for the resource
#
#
sub ReadResources{
    my ($dummy)    = '';
    my ($name)     = '';
    my ($amember)  = '';
    my ($members)  = '';

    while ( ($line = <INFILE>) && ( fromdos("$line") ne "\t)" ) ) {
	$line = &fromdos($line);
	&DebugLog("Res.READ1: $line");
        while ( ($line = <INFILE>) && ( fromdos("$line") ne "\t\t)" ) ) {
		$line = &fromdos($line);
		&DebugLog("Res.READ2: $line");
	}
	&PrintLog('.');
	$rsc_number += 1;
    }
    &PrintLog ("\n");
}

##########################################################################
# read properties
#
#	%prop_setting{'XXX'}	= setting for XXX
#
#	of interest with respect to implicit rules:
#		rip, domain_udp, domain_tcp, established,
#		    icmpenable, fw1enable ==  true / false
#		rip_p, domain_udp_p, domain_tcp_p, established_p,
#		    icmpenable_p, fw1enable_p ==  first / "before last" / last
#
sub ReadProperties{
    my($line) = '';
    my($par)  = '';
    my($set)  = '';
    my($rest) = '';

    while ( ($line = <INFILE>) && ( fromdos("$line") ne "\t)" ) ) {
          $line = &fromdos($line);
	  &DebugLog("Prop.READ1: $line");
          &PrintLog('.');
          if ( "$line" =~ m/\t\t:.* \(.*\)$/ ){
	     ($par,$set) = split(/ \(/, $line, 2);
 	     $par =~ s/^\s+://;					#--- remove "    :" at the beginning
 	     $set =~ s/\)$//;					#--- remove ) at the end
 	     $set =~ s/^\"|\"$//g;				#--- remove " at beginning and end
             $prop_setting{"$par"} = "$set";
          }
    }
    &PrintLog("\n");
}


##########################################################################
# read users from exported file
#
# user variables where user_name equals the hash for each of these:
#
#	$user_number	= number of users read
#	@user_name	= names of all users
#	%user_type	= usrgroup, template, user
#	%user_members	= members, if a group
#	%user_comment	= comment for the user
#	%user_colour	= colour of the user
#	%user_used	= wether the user is used in the rulebase
#	                  (set later when evaluating the ruleset)
sub ReadDBExportUser {
    my ($filename) = $_[0];

    # open input and seek to start of data
    open (INFILE,"$filename")
	or die "Cannot open the userDBexport file $filename!\n\n";

    close (INFILE);
}

##########################################################################
# recursively set usage on objects
sub SetObjUsed{
    my ($index) = $_[0];
    my ($single) = '';
    my (@members);

    $obj_used{"$index"} += 1;
    if ( "$obj_type{$index}" eq 'group'){
    	@members = split (/§/,$obj_members{$index});
	foreach $single (@members) {
	    &SetObjUsed("$single");
	}
    }
}


##########################################################################
# recursively set usage on services
sub SetSvcUsed{
    my ($index) = $_[0];
    my ($single) = '';
    my (@members);

    $svc_used{"$index"} += 1;
    if ( "$svc_type{$index}" eq 'group'){
    	@members = split (/§/,$svc_members{$index});
	foreach $single (@members) {
	    &SetSvcUsed("$single");
	}
    }
}


##########################################################################
# recursively set usage on users
sub SetUserUsed{
    my ($index) = $_[0];
    my ($single) = '';
    my (@members);

    $user_used{"$index"} += 1;
    if ( "$user_type{$index}" eq 'usrgroup'){
	   @members = split (/ /,$user_members{$index});
	foreach $single (@members) {
	   &SetUserUsed("$single");
	}
    }
}


##########################################################################
# read NAT rules
#
#	$nat_number	 	= number of NAT rules read (array starting at zero)
#	@nat_disabled		= rule enabled=0, rule disabled=1
#	@nat_orig_from 		= original source object
#	@nat_orig_to 		= original destination object
#	@nat_orig_svc 		= original service object
#	@nat_transl_from 	= translated source object
#	@nat_transl_from_methd 	= translated source object method: 0=hide, 1=static
#	@nat_transl_to 		= translated destination object
#	@nat_transl_to_methd	= translated destination object method: 0=hide, 1=static
#	@nat_transl_svc 	= translated service object
#	@nat_transl_svc_methd 	= translated service object method: 0=hide, 1=static
#	@nat_install_on		= install rule on...
#	@nat_unmatched		= NAT rule does not match request
#
sub ReadNATrules{
    my ($mode)    = 'none';
    my ($param)   = '';
    my ($dummy)   = '';
    my ($wert)    = '';
    my ($user)    = '';
    my ($fileEOF) = 1;
    my ($allObjs) = '';
    my ($allSvc)  = '';
    my ($line)    = $_[0];

    while ( ( $line =~ /^\t:rule_adtr \(/ ) && ( $fileEOF ) ) {
 	    $line = &fromdos($line);
	    &DebugLog("NAT.READ1: $line");
	    $mode    = 'none';
	    $nat_number  += 1;
	    &PrintLog("\n\trule_adtr($nat_number)");

	    while ( ($line = <INFILE>) && ( fromdos("$line") ne "\t)" ) ) {
	       $line = &fromdos($line);
	       &DebugLog("NAT.READ2: $line");
	       &PrintLog('.');
	       if ( $line =~ /^\t\t:comments \(/ ){
	               ($dummy,$wert) = split(/\(/,$line,2) ;
		       $wert =~ s/\)$//;			#--- remove ) at the end
		       $wert =~ s/^\"|\"$//g;			#--- remove " at beginning and end
		       $wert =~ s/;/ /g;
		       $nat_comment[$nat_number] = $wert ;
	       } elsif ( $line =~ /^\t\t:disabled \(true\)/ ){
	               $nat_disabled[$nat_number] = 1;
	       } elsif ( $line =~ /^\t\t:(src_adtr|dst_adtr|services_adtr|src_adtr_translated|dst_adtr_translated|services_adtr_translated|install) \(/ ){
	               ($dummy,$wert) = split(/:/,$line,2) ;
	               ($mode,$dummy) = split(/ /,$wert,2) ;
	       } elsif ("$mode" eq 'src_adtr') {
	           if ($line =~ /^\t\t\t: /) {
	               ($dummy,$wert) = split(/: /,$line,2) ;
	               $wert=~s/^\(//;
	               $nat_orig_from[$nat_number] = "$wert";
		       $allObjs .= "$wert§";
	           }
	       } elsif ("$mode" eq 'dst_adtr') {
	           if ($line =~ /^\t\t\t: /) {
	               ($dummy,$wert) = split(/: /,$line,2) ;
	               $wert=~s/^\(//;
	               $nat_orig_to[$nat_number] = "$wert";
		       $allObjs .= "$wert§";
	           }
	       } elsif ("$mode" eq 'services_adtr') {
	           if ($line =~ /^\t\t\t: /) {
	               ($dummy,$wert) = split(/: /,$line,2) ;
	               $wert=~s/^\(//;
	               $nat_orig_svc[$nat_number] = "$wert";
		       $allSvc .= "$wert§";
	           }
	       } elsif ("$mode" eq 'src_adtr_translated') {
	           if ($line =~ /^\t\t\t: /) {
	               ($dummy,$wert) = split(/: /,$line,2) ;
	               $wert=~s/^\(//;
		       if ( lc("$wert") eq 'any' ) { $wert = 'Original'; }
	               $nat_transl_from[$nat_number] = "$wert";
		       $allObjs .= "$wert§";
	           } elsif ($line =~ /^\t\t\t:adtr_method/) {
	               if ( $line =~ m/adtr_method_static/ ) {
	                    $nat_transl_from_methd[$nat_number] = 1;
	               } else {
	                    $nat_transl_from_methd[$nat_number] = 0;
	               }
	           }
	       } elsif ("$mode" eq 'dst_adtr_translated') {
	           if ($line =~ /^\t\t\t: /) {
	               ($dummy,$wert) = split(/: /,$line,2) ;
	               $wert=~s/^\(//;
		       if ( lc("$wert") eq 'any' ) { $wert = 'Original'; }
	               $nat_transl_to[$nat_number] = "$wert";
		       $allObjs .= "$wert§";
	               $nat_transl_to_methd[$nat_number] = 1;
	           }
	       } elsif ("$mode" eq 'services_adtr_translated') {
	           if ($line =~ /^\t\t\t: /) {
	               ($dummy,$wert) = split(/: /,$line,2) ;
	               $wert=~s/^\(//;
		       if ( lc("$wert") eq 'any' ) { $wert = 'Original'; }
	               $nat_transl_svc[$nat_number] = "$wert";
		       $allSvc .= "$wert§";
	               $nat_transl_svc_methd[$nat_number] = 1;
	           }
	       } elsif ("$mode" eq 'install') {
	           if  ( $line =~ /^\t\t\t: / ) {
	               ($dummy,$wert) = split(/: /,$line,2) ;
	               $wert=~s/^\(//;
	               if ( "$nat_install_on[$nat_number]" eq '') {
	                   $nat_install_on[$nat_number] = "$wert";
	               } else {
	                   $nat_install_on[$nat_number] = "$nat_install_on[$nat_number]§$wert";
	               }
	           }
	        }
	    } #--- inner while, the complete rule
		# GT: match_strings
		$M_com = 0; $M_src = 0; $M_dst = 0; $M_svc = 0;

		if ($Match_Case)
			{
			$M_com = 1 if ( ("$Match_Comment"		eq '') || ("$nat_comment[$nat_number]"		=~ m/$Match_Comment/) );
			$M_src = 1 if ( ("$Match_Source"		eq '') || ("$nat_orig_from[$nat_number]"	=~ m/$Match_Source/) );
			$M_dst = 1 if ( ("$Match_Destination"	eq '') || ("$nat_orig_to[$nat_number]"		=~ m/$Match_Destination/) );
			$M_svc = 1 if ( ("$Match_Service"		eq '') || ("$nat_orig_svc[$nat_number]"		=~ m/$Match_Service/) );
			}
		  else {
			$M_com = 1 if ( ("$Match_Comment"		eq '') || ("$nat_comment[$nat_number]"		=~ m/$Match_Comment/i) );
			$M_src = 1 if ( ("$Match_Source"		eq '') || ("$nat_orig_from[$nat_number]"	=~ m/$Match_Source/i) );
			$M_dst = 1 if ( ("$Match_Destination"	eq '') || ("$nat_orig_to[$nat_number]"		=~ m/$Match_Destination/i) );
			$M_svc = 1 if ( ("$Match_Service"		eq '') || ("$nat_orig_svc[$nat_number]"		=~ m/$Match_Service/i) );
		  	}

		# GT: prepare match logic
		$Match_Logic_tmp = $Match_Logic;
		$Match_Logic_tmp =~ s/com/$M_com/;
		$Match_Logic_tmp =~ s/src/$M_src/;
		$Match_Logic_tmp =~ s/dst/$M_dst/;
		$Match_Logic_tmp =~ s/svc/$M_svc/;


		if ( (eval ($Match_Logic_tmp))					# GT
		 &&
		 ( ("$Match_InstallOn" eq '') ||
	           ("$nat_install_on[$nat_number]" eq '') ||
	           (lc("$nat_install_on[$nat_number]") eq 'any') ||
	           (lc("$nat_install_on[$nat_number]") eq 'gateways') ||
	           ("$nat_install_on[$nat_number]" =~ m/$Match_InstallOn/) ) ) {
		foreach $wert (split(/§/, $allObjs)) {
		    if ($wert) { &SetObjUsed("$wert"); } }
		foreach $wert (split(/§/, $allSvc)) {
		    if ($wert) { &SetSvcUsed("$wert"); } }
	    } else {
	        $nat_unmatched[$nat_number] = 1;
	    }
	    $allObjs = '';
	    $allSvc = '';
	    $fileEOF = ( $line = <INFILE> );
    } #--- outer while
}


##########################################################################
# read Access rules
#
#	$access_number	 	= number of access rules read (array starting at zero)
#	@access_disabled	= rule enabled=0, rule disabled=1
#	@access_from		= list of source objects, separated by space
#	@access_from_negated	= from-list negated=1, standard=0
#	@access_to		= list of destination objects, separated by space
#	@access_to_negated	= to-list negated=1, standard=0
#	@access_services	= list of services, separated by space
#	@access_services_negated= services-list negated=1, standard=0
#	@access_action		= action: deny, allow, encrypt, ...
#	@access_track		= log: long, short, account, ...
#	@access_time		= time object (not really implemented yet)
#	@access_install_on	= install rule on...
#	@access_header		= header above this particular rule
#	@access_comment		= comment on this particular rule
#	@access_unmatched	= rule does not match request
#	@access_clauth_to_hours = client auth timeout hours
#	@access_clauth_to_minutes       = client auth timeout minutes
#	@access_clauth_to_infinite      = client auth timeout infinity
#	@access_clauth_to       = actual client auth timeout value
#	@access_clauth_sessions = max client auth sessions
#	@access_clauth_sessions_infinite        = client auth sessions infinity
#	@access_clauth_sessions_value   = actual client auth max sessions
#
sub ReadAccessRules{
    my ($mode)    = 'none';
    my ($param)   = '';
    my ($dummy)   = '';
    my ($wert)    = '';
    my ($fileEOF) = 1;
    my ($allObjs) = '';
    my ($allSvc)  = '';
    my ($line)    = $_[0];

    &DebugLog("Access.READ1a: $line");
    $access_number = -1;

	#----------------------------	# GT: only for print, what you want to match
	$plogic = $Match_Logic;
	$plogic =~ s/com/ com=$Match_Comment /;
	$plogic =~ s/src/ src=$Match_Source /;
	$plogic =~ s/dst/ dst=$Match_Destination /;
	$plogic =~ s/svc/ svc=$Match_Service /;
	if ($Match_Case) { $plogic = $plogic . " /case sensitive"; }
	  else { $plogic = $plogic . " /ignore case"; }

	$HTMLtitle_ext = " (filtered) " 				if ($FLAG_match);
	$HTMLmatch = " rules filtered by: " . $plogic	if ($FLAG_match);


    while ( ( $line =~ /^\t:rule \(/ ) && $fileEOF ) {
	     &DebugLog("Access.READ1: $line");
             $mode    = 'none';
             $access_number  += 1;
             &PrintLog("\n\trule($access_number)");

	     $access_from_negated[$access_number] = 0;
	     $access_to_negated[$access_number] = 0;
             $access_services_negated[$access_number] = 0;

             while ( ($line = <INFILE>) && ( fromdos("$line") ne "\t)" ) ) {
		$line = &fromdos($line);
		&DebugLog("Access.READ2: $line");
		&PrintLog('.');
		if ( $line =~ /^\t\t:comments \(/ ){
			($dummy,$wert) = split(/\(/,$line,2) ;
			$wert =~ s/\)$//;			#--- remove ) at the end
			$wert =~ s/^\"|\"$//g;			#--- remove " at beginning and end
			$wert =~ s/;/ /g;
			$access_comment[$access_number] = $wert ;
		} elsif ( $line =~ /^\t\t:header_text \(/ ){
			($dummy,$wert) = split(/\(/,$line,2) ;
			$wert =~ s/\)$//;			#--- remove ) at the end
			$wert =~ s/^\"|\"$//g;			#--- remove " at beginning and end
			$wert =~ s/;/ /g;
			$access_header[$access_number] = $wert ;
		} elsif ( $line =~ /^\t\t:disabled \(true\)/ ){
			$access_disabled[$access_number] = 1;
        }elsif ( $line =~ /^\t\t:name \(/ ){      # Added for R65 compatiliby 2008-02-12 By Jacob
           ($dummy,$wert) = split(/\(/,$line,2) ; # Added for R65 compatiliby 2008-02-12 By Jacob
           $wert =~ s/\)$//;                      # Added for R65 compatiliby 2008-02-12 By Jacob
           $wert =~ s/^\"|\"$//g;                 # Added for R65 compatiliby 2008-02-12 By Jacob
           $wert =~ s/;/ /g;                      # Added for R65 compatiliby 2008-02-12 By Jacob
           $wert =~ s/^##//g;                     # Added for R65 compatiliby 2008-02-12 By Jacob
           $access_name[$access_number] = $wert ; # Added for R65 compatiliby 2008-02-12 By Jacob
		} elsif ( $line =~ /^\t\t:(src|dst|services|action|track|install|time) \(/ ){
			($dummy,$wert) = split(/:/,$line,2) ;
			($mode,$dummy) = split(/ /,$wert,2) ;
		} elsif ("$mode" eq 'src') {
                      if ($line =~ /^\t\t\t\t?:\s/) {
		        ###--- not overly clean: optional TAB is good for
			###--- normal and compound objects
			($dummy,$wert) = split(/:\s+\(*/,$line,2) ;
			$wert=~s/^\(//;		#--- remove ( at the beginning of user-rules
 			$wert=~s/^"|"$//g;		#--- remove \" from user-rules
			if ( "$access_from[$access_number]" eq '') {
			    $access_from[$access_number] = "$wert";
			} else {
			    $access_from[$access_number] = "$access_from[$access_number]§$wert";
			}
			# split 'user@location' into 'user' and 'location' then add 'location' only to $wert
                        $wert =~ s/^.*@(.*)$/$1/;
		        $allObjs .= "$wert§";
                      } elsif ($line =~ /^\t\t\t\t:\s\("([^"]+)"/) { # Auth-Regel
			$wert = $1 ;
			$wert=~s/^\(//;				#--- remove ( at the beginning of user-rules
			if ( "$access_from[$access_number]" eq '') {
			    $access_from[$access_number] = "$wert";
			} else {
			    $access_from[$access_number] = "$access_from[$access_number]§$wert";
			}
		        $allObjs .= "$wert§";
                      } elsif ($line =~ /^\t\t\t:op \(\"not in\"\)/) {
			$access_from_negated[$access_number] = 1;
                      }
		} elsif ("$mode" eq 'dst') {
                      if ($line =~ /^\t\t\t\t?: /) {
		        ###--- not overly clean: optional TAB is good for
			###--- normal and compound objects
			($dummy,$wert) = split(/:\s+\(*/,$line,2) ;
			if ( "$access_to[$access_number]" eq '') {
			    $access_to[$access_number] = "$wert";
			} else {
			    $access_to[$access_number] = "$access_to[$access_number]§$wert";
			}
		        $allObjs .= "$wert§";
                      } elsif ($line =~ /^\t\t\t:op \(\"not in\"\)/) {
			$access_to_negated[$access_number] = 1;
                      }
		} elsif ("$mode" eq 'services') {
		      ($dummy,$wert) = split(/\(\"/,$line,2) ;   #--- just for security servers
		      ($wert,$dummy) = split(/\"/,$wert,2) ;
                      if ($line =~ /^\t\t\t\t?: \(\"smtp-\>/) {
	 		if ( "$access_services[$access_number]" eq '') {
			    $access_services[$access_number] = "$wert";
			} else {
			    $access_services[$access_number] = "$access_services[$access_number]§$wert";
			}
                      } elsif ($line =~ /^\t\t\t\t?: \(\"(http-\>.*)\"/) {
                        if ( "$access_services[$access_number]" eq '') {
			    $access_services[$access_number] = "$wert";
			} else {
			    $access_services[$access_number] = "$access_services[$access_number]§$wert";
			}
                      } elsif ($line =~ /^\t\t\t\t?: \(\"(https-\>.*)\"/) {
                        if ( "$access_services[$access_number]" eq '') {
			    $access_services[$access_number] = "$wert";
			} else {
			    $access_services[$access_number] = "$access_services[$access_number]§$wert";
			}
		      } elsif ($line =~ /^\t\t\t\t?: \(\"ftp-\>/) {
	 		if ( "$access_services[$access_number]" eq '') {
			    $access_services[$access_number] = "$wert";
			} else {
			    $access_services[$access_number] = "$access_services[$access_number]§$wert";
			}
                      } elsif ($line =~ /^\t\t\t:\s+/) {		# PS	(Any trouble
			($dummy,$wert) = split(/:\s+\(*/,$line,2) ;	# PS	(Any trouble
			if ( "$access_services[$access_number]" eq '') {
			    $access_services[$access_number] = "$wert";
			} else {
			    $access_services[$access_number] = "$access_services[$access_number]§$wert";
			}
		        $allSvc .= "$wert§";
                      } elsif ($line =~ /^\t\t\t:op \(\"not in\"\)/) {
			$access_services_negated[$access_number] = 1;
                      }
		} elsif ("$mode" eq 'action') {
		      $wert =~ s/[\s\"]//g;		# PS
		      $wert = lc ($wert);		# PS
		      if  ( $line =~ /^\t\t\t:\s+\([a-z]*/ ) {	# PS
			($dummy,$wert) = split(/:\s+\(/,$line,2);	# PS
		     	$wert =~ s/[\s\"]//g;		# PS
		      	$wert = lc ($wert);		# PS
			$access_action[$access_number] = $wert;
                      }
		      # read client auth properties
		      while($line = <INFILE>){
			  fromdos($line);
			  if($line =~ /^\t\t\t\t:clauth_to_hours \(([0-9]+)\)/){
			      $access_clauth_to_hours[$access_number] = $1;
			  }elsif($line =~ /^\t\t\t\t:clauth_to_minutes \(([0-9]+)\)/){
			      $access_clauth_to_minutes[$access_number] = $1;
			  }elsif($line =~ /^\t\t\t\t:clauth_to_infinite \((false|true)\)/){
			      $access_clauth_to_infinite[$access_number] = $1;
			  }elsif($line =~ /^\t\t\t\t:sessions \(([0-9]+)\)/){
			      $access_sessions[$access_number] = $1;
			  }elsif($line =~ /^\t\t\t\t:sessions_infinite \((false|true)\)/){
			      $access_sessions_infinite[$access_number] = $1;
			  }elsif(fromdos("$line") eq "\t\t)"){
                              # set $access_clauth_to
			      $access_clauth_to[$access_number] =
				$access_clauth_to_infinite[$access_number] eq "false" ?
				$access_clauth_to_hours[$access_number] * 60 + $access_clauth_to_minutes[$access_number] :
				"infinite";

			     # set $access_sessions_value
			     $access_sessions_value[$access_number] =
				$access_sessions_infinite[$access_number] eq "false" ?
				$access_sessions[$access_number] :
                                "infinite";
			     $mode = 'none';
			     last;
			  }
		      }
		} elsif ("$mode" eq 'track') {
		      if  ( $line =~ /^\t\t\t: \"?[A-Z]([a-z]*)\"?/ ) {
			($dummy,$wert) = split(/: /,$line,2) ;
			$access_track[$access_number] = "$wert";
                      }
		} elsif ("$mode" eq 'install') {
		      if  ( $line =~ /^\t\t\t: / ) {
 			($dummy,$wert) = split(/:\s+\(*/,$line,2) ;		# PS left parenthesis
			$wert =~ s/\(//; # Handle Gateway object
		        $allObjs .= "$wert§";
			if ( "$access_install_on[$access_number]" eq '') {
			    $access_install_on[$access_number] = "$wert";
			} else {
			    $access_install_on[$access_number] = "$access_install_on[$access_number]§$wert";
			}
                      }
		} elsif ("$mode" eq 'time') {
		      if  ( $line =~ /^\t\t\t: .*/ ) {
			($dummy,$wert) = split(/:\s+\(*/,$line,2) ;
			if ( "$access_time[$access_number]" eq '') {
			    $access_time[$access_number] = "$wert";
			} else {
			    $access_time[$access_number] = "$access_time[$access_number] $wert";
			}
                      }
	 	}
	     } #--- inner while, i.e. one rule

		# GT: match_strings
		$M_com = 0; $M_src = 0; $M_dst = 0; $M_svc = 0;

		if ($Match_Case)
			{
			$M_com = 1 if ( ("$Match_Comment"		eq '') || ("$access_comment[$access_number]"	=~ m/$Match_Comment/) );
			$M_src = 1 if ( ("$Match_Source"		eq '') || ("$access_from[$access_number]"		=~ m/$Match_Source/) );
			$M_dst = 1 if ( ("$Match_Destination"	eq '') || ("$access_to[$access_number]"			=~ m/$Match_Destination/) );
			$M_svc = 1 if ( ("$Match_Service"		eq '') || ("$access_services[$access_number]"	=~ m/$Match_Service/) );
			}
		  else {
			$M_com = 1 if ( ("$Match_Comment"		eq '') || ("$access_comment[$access_number]"	=~ m/$Match_Comment/i) );
			$M_src = 1 if ( ("$Match_Source"		eq '') || ("$access_from[$access_number]"		=~ m/$Match_Source/i) );
			$M_dst = 1 if ( ("$Match_Destination"	eq '') || ("$access_to[$access_number]"			=~ m/$Match_Destination/i) );
			$M_svc = 1 if ( ("$Match_Service"		eq '') || ("$access_services[$access_number]"	=~ m/$Match_Service/i) );
			}

		# GT: prepare match logic
		$Match_Logic_tmp = $Match_Logic;
		$Match_Logic_tmp =~ s/com/$M_com/;
		$Match_Logic_tmp =~ s/src/$M_src/;
		$Match_Logic_tmp =~ s/dst/$M_dst/;
		$Match_Logic_tmp =~ s/svc/$M_svc/;


		if ( (eval ($Match_Logic_tmp))					# GT
	 	  &&
		 ( ("$Match_InstallOn" eq '') ||
	           ("$access_install_on[$access_number]" eq '') ||
	           (lc("$access_install_on[$access_number]") eq 'any') ||
	           (lc("$access_install_on[$access_number]") eq 'gateways') ||
	           ("$access_install_on[$access_number]" =~ m/$Match_InstallOn/) ) ) {
		foreach $wert (split(/§/, $allObjs)) {
		    if ($wert) { &SetObjUsed("$wert"); } }
		foreach $wert (split(/§/, $allSvc)) {
		    if ($wert) { &SetSvcUsed("$wert"); } }
	     } else {
	        $access_unmatched[$access_number] = 1;
	     }
	     $allObjs = '';
	     $allSvc = '';
 	     $fileEOF = ($line = <INFILE>);
	     $line = &fromdos($line);
	     &DebugLog("Access.READ1b: $line");
         # Below added for R65 features 2008-02-12 By Jacob
         if ($access_name[$access_number]){
              if ($access_comment[$access_number]) {
                 $access_comment[$access_number]="$access_name[$access_number] - $access_comment[$access_number]";
              } else {
                 $access_comment[$access_number]="$access_name[$access_number]";
              }
         }
    } #--- outer while
    return &fromdos("$line");
}



##########################################################################
##########################################################################
###   Dump into single files
##########################################################################
##########################################################################


##########################################################################
# dump properties into a TXT file
#	filename for the dump

sub DumpProperties{
    my ($filename) 	= $_[0];

    open (DUMPFILE,">$filename") ;
    print DUMPFILE "Security Policy\n";
    print DUMPFILE "---------------------------------------------------------\n";
    print DUMPFILE "Apply Gateway Rules to Interface Direction:  $prop_setting{'gatewaydir'}\n";
    print DUMPFILE "TCP Session Timeout (sec):                   $prop_setting{'tcptimeout'}\n";
    print DUMPFILE "Accept Firewall-1 Control Connections:       $prop_setting{'fw1enable'} / $prop_setting{'fw1enable_p'}\n";
    print DUMPFILE "Accept UDP Replies:                          $prop_setting{'udpreply'} /  $prop_setting{'udpreply_p'}\n";
    print DUMPFILE "UDP Reply Timeout (sec):                     $prop_setting{'udptimeout'}\n";
    print DUMPFILE "Accept Outgoing Packets:                     $prop_setting{'outgoing'} /  $prop_setting{'outgoing_p'}\n";
    print DUMPFILE "Enable Decryption on Accept:                 $prop_setting{'acceptdecrypt'}\n";
    print DUMPFILE "Use FASTPATH:                                $prop_setting{'enable_fastpath'}\n";
    print DUMPFILE "Accept RIP:                                  $prop_setting{'rip'} /  $prop_setting{'rip_p'}\n";
    print DUMPFILE "Accept Domain Name Queries (UDP):            $prop_setting{'domain_udp'} /  $prop_setting{'domain_udp_p'}\n";
    print DUMPFILE "Accept Domain Name Download (TCP):           $prop_setting{'domain_tcp'} /  $prop_setting{'domain_tcp_p'}\n";
    print DUMPFILE "Accept ICMP:                                 $prop_setting{'icmpenable'} / $prop_setting{'icmpenable_p'}\n";
    print DUMPFILE " \n";
    print DUMPFILE "Services\n";
    print DUMPFILE "---------------------------------------------------------\n";
    print DUMPFILE "Enable FTP PASV Connections:                 $prop_setting{'ftppasv'} / $prop_setting{'ftppasv_p'}\n";
    print DUMPFILE "Enable RSH/REXEC Reverse stderr Connections: $prop_setting{'rshstderr'} / $prop_setting{'rshstderr_p'}\n";
    print DUMPFILE "Enable RPC Control:                          $prop_setting{'rpcenable'} / $prop_setting{'rpcenable_p'}\n";
    print DUMPFILE "Enable Response of FTP Data Connections:     $prop_setting{'ftpdata'} / $prop_setting{'ftpdata_p'}\n";
    print DUMPFILE "Enable Real Audio Reverse Connections:       $prop_setting{'raudioenable'} / $prop_setting{'raudioenable_p'}\n";
    print DUMPFILE "Enable VDOLive Reverse Connections:          $prop_setting{'vdolivenable'} / $prop_setting{'vdolivenable_p'}\n";
    print DUMPFILE "Enable CoolTalk Data Connections (UDP):      $prop_setting{'cooltalkenable'}\n";
    print DUMPFILE "Enable H.323 Control and Data Connections:   $prop_setting{'iphoneenable'}\n";
    print DUMPFILE " \n";
    print DUMPFILE "Log and Alert\n";
    print DUMPFILE "---------------------------------------------------------\n";
    print DUMPFILE "Excessive Log Grace Period (sec):            $prop_setting{'loggrace'}\n";
    print DUMPFILE "PopUp Alert Command:                         $prop_setting{'alertcmd'}\n";
    print DUMPFILE "Mail Alert Command:                          $prop_setting{'mailcmd'}\n";
    print DUMPFILE "SNMP Trap Alert Command:                     $prop_setting{'snmptrapcmd'}\n";
    print DUMPFILE "User Defined Alert Command:                  $prop_setting{'useralertcmd'}\n";
    print DUMPFILE "Anti Spoof Alert Command:                    $prop_setting{'spoofalertcmd'}\n";
    print DUMPFILE "User Authentication Alert Command:           $prop_setting{'userauthalertcmd'}\n";
    print DUMPFILE "Log Established TCP Packets:                 $prop_setting{'log_established_tcp'}\n";
    print DUMPFILE "Enable Active Connections:                   $prop_setting{'liveconns'}\n";
    print DUMPFILE " \n";
    print DUMPFILE "Resolving\n";
    print DUMPFILE "---------------------------------------------------------\n";
    print DUMPFILE "Lookup Priorities:                        1. $prop_setting{'resolver_1'}\n";
    print DUMPFILE "                                          2. $prop_setting{'resolver_2'}\n";
    print DUMPFILE "                                          3. $prop_setting{'resolver_3'}\n";
    print DUMPFILE "                                          4. $prop_setting{'resolver_4'}\n";
    print DUMPFILE "BIND Timeout (sec):                          $prop_setting{'timeout'}\n";
    print DUMPFILE "BIND Retries:                                $prop_setting{'retries'}\n";
    print DUMPFILE "Log Viewer Resolver Properties:              $prop_setting{'pagetimeout'}\n";
    print DUMPFILE " \n";
    print DUMPFILE "Security Servers\n";
    print DUMPFILE "---------------------------------------------------------\n";
    print DUMPFILE "Telnet Welcome Message File:                 $prop_setting{'telnet_msg'}\n";
    print DUMPFILE "Rlogin Welcome Message File:                 $prop_setting{'rlogin_msg'}\n";
    print DUMPFILE "FTP Welcome Message File:                    $prop_setting{'ftp_msg'}\n";
    print DUMPFILE "Client Authentication Welcome Message File:  $prop_setting{'clnt_auth_msg'}\n";
    print DUMPFILE "HTTP Next Proxy:                             $prop_setting{'http_next_proxy_host'} : $prop_setting{'http_next_proxy_port'}\n";
    print DUMPFILE " \n";
    print DUMPFILE "Authentication\n";
    print DUMPFILE "---------------------------------------------------------\n";
    print DUMPFILE "User Authentication Session Timeout (min):   $prop_setting{'au_timeout'}\n";
    print DUMPFILE "AXENT Pathways Defender Server Setup:    IP: $prop_setting{'snk_server_ip'}\n";
    print DUMPFILE "                                   Agent ID: $prop_setting{'snk_agent_id'}\n";
    print DUMPFILE "                                  Agent Key: $prop_setting{'snk_agent_key'}\n";
    print DUMPFILE " \n";
    print DUMPFILE "SYNDefender\n";
    print DUMPFILE "---------------------------------------------------------\n";
    print DUMPFILE "Method:                                      $SynDefender[$prop_setting{'fwsynatk_method'}]\n";
    print DUMPFILE "Timeout:                                     $prop_setting{'fwsynatk_timeout'}\n";
    print DUMPFILE "Maximum Sessions:                            $prop_setting{'fwsynatk_max'}\n";
    print DUMPFILE "Display Warning Messages:                    $prop_setting{'fwsynatk_warning'}\n";
    print DUMPFILE "</table>\n";
    print DUMPFILE " \n";
    print DUMPFILE "Miscellaneous\n";
    print DUMPFILE "---------------------------------------------------------\n";
    print DUMPFILE "Load Agents Port:                            $prop_setting{'load_service_port'}\n";
    print DUMPFILE "Load Measurement Interval:                   $prop_setting{'lbalanced_period_wakeup_sec'}\n";
    print DUMPFILE " \n";
    print DUMPFILE "Access Lists\n";
    print DUMPFILE "---------------------------------------------------------\n";
    print DUMPFILE "Accept Established TCP Connections:          $prop_setting{'established'} / $prop_setting{'established_p'}\n";
    print DUMPFILE "Accept RIP:                                  $prop_setting{'rip'} / $prop_setting{'rip_p'}\n";
    print DUMPFILE "Accept Domain Name Queries (UDP):            $prop_setting{'domain_udp'} / $prop_setting{'domain_udp_p'}\n";
    print DUMPFILE "Accept Domain Name Download (TCP):           $prop_setting{'domain_tcp'} / $prop_setting{'domain_tcp_p'}\n";
    print DUMPFILE "Accept ICMP:                                 $prop_setting{'icmpenable'} / $prop_setting{'icmpenable_p'}\n";
    close (DUMPFILE);
}


##########################################################################
# print implicit rules in Text/TSV
#	file handle
#	location id ( first / "before last" / last
#	format string for output
sub subImplicit__Dump {
    my ($FILE)         = $_[0];
    my ($locstr)       = $_[1];
    my ($formstring)   = $_[2];

    if ( $FLAG_implicitrules ) {
      if ( ("$prop_setting{'fw1enable'}" eq 'true') &&
         (lc("$prop_setting{'fw1enable_p'}") eq "$locstr") ) {
	printf DUMPFILE ("$formstring",'FW1 Host','FW1 Host','FW1','FW1 Control Connections');
	&SetSvcUsed("FW1");
	printf DUMPFILE ("$formstring",'FW1 Host','FW1 Host','FW1_log','FW1 Control Connections');
	&SetSvcUsed("FW1_log");
	printf DUMPFILE ("$formstring",'gui_clients ','FW1 Management','FW1_mgmt','FW1 Control Connections');
	&SetSvcUsed("FW1_mgmt");
	printf DUMPFILE ("$formstring",'FloodGate-1 Host','FW1 Management','FW1_ela','FW1 Control Connections');
	&SetSvcUsed("FW1_ela");
	printf DUMPFILE ("$formstring",'Any ','FW1 Host','FW1_topo','FW1 Control Connections');
	&SetSvcUsed("FW1_topo");
	printf DUMPFILE ("$formstring",'Any ','FW1 Host','FW1_key','FW1 Control Connections');
	&SetSvcUsed("FW1_key");
	printf DUMPFILE ("$formstring",'Any ','FW1 Host','IKE','FW1 Control Connections');
	printf DUMPFILE ("$formstring",'FW1 Host','Any','IKE','FW1 Control Connections');
	&SetSvcUsed("IKE");
	printf DUMPFILE ("$formstring",'Any ','Any','RDP','FW1 Control Connections');
	&SetSvcUsed("RDP");
	printf DUMPFILE ("$formstring",'FW1 Host','CVP-Servers','FW1_cvp','FW1 Control Connections');
	&SetSvcUsed("FW1_cvp");
	printf DUMPFILE ("$formstring",'FW1 Host','UFP-Servers','FW1_ufp','FW1 Control Connections');
	&SetSvcUsed("FW1_ufp");
	printf DUMPFILE ("$formstring",'FW1 Host','Radius-Servers','RADIUS','FW1 Control Connections');
	&SetSvcUsed("RADIUS");
	printf DUMPFILE ("$formstring",'FW1 Host','Tacacs-Servers','TACACS','FW1 Control Connections');
	&SetSvcUsed("TACACS");
	printf DUMPFILE ("$formstring",'FW1 Host','Ldap-Servers','ldap','FW1 Control Connections');
	&SetSvcUsed("ldap");
	printf DUMPFILE ("$formstring",'FW1 Host','Logical-Servers','load_agent','FW1 Control Connections');
	&SetSvcUsed("load_agent");
      }
# outgoing
      if ( ("$prop_setting{'outgoing'}" eq 'true') &&
         (lc("$prop_setting{'outgoing_p'}") eq "$locstr") ) {
	printf DUMPFILE ("$formstring",'FW1 Module','Any','Any','Outgoing');
      }
# RIP
      if ( ("$prop_setting{'rip'}" eq 'true') &&
         (lc("$prop_setting{'rip_p'}") eq "$locstr") ) {
	printf DUMPFILE ("$formstring",'Any ','Any','RIP','RIP');
	&SetSvcUsed("RIP");
      }

# ICMP
      if ( ("$prop_setting{'icmpenable'}" eq 'true') &&
         (lc("$prop_setting{'icmpenable_p'}") eq "$locstr") ) {
	printf DUMPFILE ("$formstring",'Any ','Any','icmp','ICMP');
	&SetSvcUsed("icmp");
      }
# domain TCP
      if ( ("$prop_setting{'domain_tcp'}" eq 'true') &&
         (lc("$prop_setting{'domain_tcp_p'}") eq "$locstr") ) {

	printf DUMPFILE ("$formstring",'Any ','Any','domain_tcp','Domain-TCP');
	&SetSvcUsed("domain_tcp");
      }
# domain UDP
      if ( ("$prop_setting{'domain_udp'}" eq 'true') &&
         (lc("$prop_setting{'domain_udp_p'}") eq "$locstr") ) {
	printf DUMPFILE ("$formstring",'Any ','Any','domain_udp','Domain-UDP');
	&SetSvcUsed("domain_udp");
      }
    }
}

##########################################################################
# dump access rules into a TXT file
#	filename for the dump

sub DumpRulesTXT{
    my ($filename) 	= $_[0];
    my ($i);
    my ($txt);

    open (DUMPFILE,">$filename") ;
    #--- first the explicit ones ---
    for ( $i = 0; $i<=$access_number; $i++ ) {
	if ( $i == 0 ){
	    subImplicit__Dump (DUMPFILE, 'first', "\nImplicit Rule\n\tFrom:       %s\n\tTo:         %s\n\tService:    %s\n\tAction:     accept	    \n\tTrack:      (none)\n\tTime:       Any\n\tInstall on: Gateways\n\tComment:    Enable %s\n");
        } elsif ( $i == $access_number ){
	    subImplicit__Dump (DUMPFILE, 'before last', "\nImplicit Rule\n\tFrom:       %s\n\tTo:         %s\n\tService:    %s\n\tAction:     accept	    \n\tTrack:      (none)\n\tTime:       Any\n\tInstall on: Gateways\n\tComment:    Enable %s\n");
        }
	if ( ! $access_unmatched[$i]) {
	    print DUMPFILE "\n*** $access_header[$i] ***\n" if ($access_header[$i]);
	    print DUMPFILE "\nRule ";
	    print DUMPFILE $i+1;
	    if ( $access_disabled[$i] ) { print DUMPFILE " (disabled) "; }
	    print DUMPFILE "\n";

	    print DUMPFILE "\tFrom:       ";
	    if ( $access_from_negated[$i] ) { print DUMPFILE "(negated) "; }
	    $txt = "$access_from[$i]"; $txt =~ s/§/ /g;
	    print DUMPFILE "$txt\n";

	    print DUMPFILE "\tTo:         ";
	    if ( $access_to_negated[$i] ) { print DUMPFILE "(negated) "; }
	    $txt = "$access_to[$i]"; $txt =~ s/§/ /g;
	    print DUMPFILE "$txt\n";

	    print DUMPFILE "\tService:    ";
	    if ( $access_services_negated[$i] ) { print DUMPFILE "(negated) "; }
	    $txt = "$access_services[$i]"; $txt =~ s/§/ /g;
	    print DUMPFILE "$txt\n";

	    print DUMPFILE "\tAction:     $access_action[$i]\n";
	    print DUMPFILE "\tTrack:      $access_track[$i]\n";
	    print DUMPFILE "\tTime:       $access_time[$i]\n";
	    print DUMPFILE "\tInstall On: ";
	    $txt = "$access_install_on[$i]"; $txt =~ s/§/ /g;
	    print DUMPFILE "$txt\n";
	    &PrintNonempty(DUMPFILE,"\tComment:    %s\n",$access_comment[$i]);
	}
    }
    #--- now the implicit ones ---
    subImplicit__Dump (DUMPFILE, 'last', "\nImplicit Rule\n\tFrom:       %s\n\tTo:         %s\n\tService:    %s\n\tAction:     accept	    \n\tTrack:      (none)\n\tTime:       Any\n\tInstall on: Gateways\n\tComment:    Enable %s\n");

    close (DUMPFILE);
}


##########################################################################
# dump access rules into a TSV file
#	filename for the dump


sub DumpRulesTSV{
    my ($filename) 	= $_[0];
    my ($txt);

    open (DUMPFILE,">$filename") ;
    print DUMPFILE "number\tdisabled\tfrom neg.\tfrom\tto neg.\tto\tsvc.neg.\tservice\taction\ttrack\ttime\tinst.on\tcomment\n";
    print DUMPFILE "-----\t-----\t-----\t-----\t-----\t-----\t-----\t-----\t-----\t-----\t-----\t-----\t-----\n";
    #--- first the explicit ones ---
    for ( $i = 0; $i<=$access_number; $i++ ) {
	if ( $i == 0 ){
	    subImplicit__Dump (DUMPFILE, 'first', "(I)\t\t%s\t%s\t%s\taccept\t(none)\tAny\tGateways\tImplicit Rule: Enable %s\n");
	} elsif ( $i == $access_number ){
	    subImplicit__Dump (DUMPFILE, 'before last', "(I)\t\t%s\t%s\t%s\taccept\t(none)\tAny\tGateways\tImplicit Rule: Enable %s\n");
	}
	if ( ! $access_unmatched[$i]) {
	    print DUMPFILE $i+1;
	    print DUMPFILE "\t";
	    if ( $access_disabled[$i] ) { print DUMPFILE "(disabled)"; }
	    print DUMPFILE "\t";

	    if ( $access_from_negated[$i] ) { print DUMPFILE "(negated) "; }
	    print DUMPFILE "\t";
	    $txt = "$access_from[$i]"; $txt =~ s/§/ /g;
	    print DUMPFILE "$txt";
	    print DUMPFILE "\t";

	    if ( $access_to_negated[$i] ) { print DUMPFILE "(negated) "; }
	    print DUMPFILE "\t";
	    $txt = "$access_to[$i]"; $txt =~ s/§/ /g;
	    print DUMPFILE "$txt";
	    print DUMPFILE "\t";

	    if ( $access_services_negated[$i] ) { print DUMPFILE "(negated) "; }
	    print DUMPFILE "\t";
	    $txt = "$access_services[$i]"; $txt =~ s/§/ /g;
	    print DUMPFILE "$txt";
	    print DUMPFILE "\t";

	    print DUMPFILE "$access_action[$i]\t$access_track[$i]\t$access_time[$i]";
	    $txt = "$access_install_on[$i]"; $txt =~ s/§/ /g;
	    print DUMPFILE "\t$txt";
	    print DUMPFILE "\t$access_comment[$i]\n";
	}
    }
    #--- now the implicit ones ---
    subImplicit__Dump (DUMPFILE, 'last', "(I)\t\t%s\t%s\t%s\taccept\t(none)\tAny\tGateways\tImplicit Rule: Enable %s\n");
    close (DUMPFILE);
}


##########################################################################
# dump NAT rules into a TSV file
#	filename for the dump
sub DumpNatTSV{
    my ($filename) 	= $_[0];
    my ($i);

    open (DUMPFILE,">$filename") ;
    print DUMPFILE "number\timplicit\torig.from\torig.to\torig.service\ttrans.from\tmethod\ttrans.to\tmethod\ttrans.service\tinstall-on\tcomment\n";
    print DUMPFILE "-----\t-----\t-----\t-----\t-----\t-----\t-----\t-----\t-----\t-----\t-----\t-----\n";
    #--- first the explicit ones ---
    for ( $i = 0; $i<=$nat_number; $i++ ) {
	if ( ! $nat_unmatched[$i]) {
	    print DUMPFILE $i+1;
	    if ( $nat_disabled[$i] ) { print DUMPFILE " (disabled)"; }
	    print DUMPFILE "\tno\t$nat_orig_from[$i]\t$nat_orig_to[$i]\t$nat_orig_svc[$i]\t";
	    print DUMPFILE "$nat_transl_from[$i]\t$NATtranslation{$nat_transl_from_methd[$i]}\t";
	    print DUMPFILE "$nat_transl_to[$i]\t$NATtranslation{$nat_transl_to_methd[$i]}\t";
	    print DUMPFILE "$nat_transl_svc[$i]\t$NATtranslation{$nat_transl_svc_methd[$i]}\t";
	    $txt = "$nat_install_on[$i]"; $txt =~ s/§/ /g;
	    print DUMPFILE "$txt\t";
	    print DUMPFILE "$nat_comment[$i]\n";
	}
    }
    #--- now the implicit ones ---
    if ( $FLAG_implicitrules ) {
	foreach $name (@obj_name){
	    if ( ( $obj_used{$name} || $FLAG_allobjs ) &&
	         ( "$obj_NATadr{$name}" ne '' ) ) {
		#--- forward rule
	        $i++;
		print DUMPFILE "$i\tyes\t$name\tAny\tAny\t$obj_NATadr{$name}\t";
		print DUMPFILE "$NATtranslation{$obj_NATtype{$name}}\t";
		print DUMPFILE "Original\t\tOriginal\t\t\n";
		#--- backward rule
	        $i++;
		print DUMPFILE "$i\tyes\tAny\t$obj_NATadr{$name}\tAny\tOriginal\t\t$name\t";
		print DUMPFILE "$NATtranslation{$obj_NATtype{$name}}\t";
		print DUMPFILE "Original\t\t\t\n";
	    }
	}
    }
    close (DUMPFILE);
}


##########################################################################
# dump NAT rules into a TXT file
#	filename for the dump
#	switch:  1 = if with implicit rules,   0 = used only
#	switch:  1 = if all objects,   0 = used only

sub DumpNatTXT{
    my ($filename) 	= $_[0];
    my ($with_implicit) = $_[1];
    my ($if_used)  	= $_[2];
    my ($i);

    open (DUMPFILE,">$filename") ;
    #--- first the explicit ones ---
    for ( $i = 0; $i<=$nat_number; $i++ ) {
	if ( ! $nat_unmatched[$i]) {
	    print DUMPFILE "\nRule ";
	    print DUMPFILE $i+1;
	    if ( $nat_disabled[$i] ) { print DUMPFILE "(disabled)"; }
	    print DUMPFILE " (explicit)\n";
	    print DUMPFILE "\tInstalled On: ";
	    $txt = "$nat_install_on[$i]"; $txt =~ s/§/ /g;
	    print DUMPFILE "$txt\n";
	    print DUMPFILE "\tORIGINAL\n";
	    print DUMPFILE "\t\tFrom:    $nat_orig_from[$i]\n";
	    print DUMPFILE "\t\tTo:      $nat_orig_to[$i]\n";
	    print DUMPFILE "\t\tService: $nat_orig_svc[$i]\n";
	    print DUMPFILE "\tTRANSLATED\n";
	    print DUMPFILE "\t\tFrom:    $nat_transl_from[$i]";
	    print DUMPFILE " ($NATtranslation{$nat_transl_from_methd[$i]})\n";
	    print DUMPFILE "\t\tTo:      $nat_transl_to[$i]";
	    print DUMPFILE " ($NATtranslation{$nat_transl_to_methd[$i]})\n";
	    print DUMPFILE "\t\tService: $nat_transl_svc[$i]";
	    print DUMPFILE " ($NATtranslation{$nat_transl_svc_methd[$i]})\n";
	    &PrintNonempty(DUMPFILE,"\tComment: %s\n",$nat_comment[$i]);
	}
    }
    #--- now the implicit ones ---
    if ( $FLAG_implicitrules ) {
	foreach $name (@obj_name){
	    if ( ( $obj_used{$name} || $FLAG_allobjs ) &&
	         ( "$obj_NATadr{$name}" ne '' ) ) {
		#--- forward rule
	        $i++;
		print DUMPFILE "\nRule $i (implicit)\n";
		print DUMPFILE "\tORIGINAL\n";
		print DUMPFILE "\t\tFrom:    $name\n";
		print DUMPFILE "\t\tTo:      Any\n";
		print DUMPFILE "\t\tService: Any\n";
		print DUMPFILE "\tTRANSLATED\n";
		print DUMPFILE "\t\tFrom:    $obj_NATadr{$name}";
		print DUMPFILE " ($NATtranslation{$obj_NATtype{$name}})\n";
		print DUMPFILE "\t\tTo:      Original\n";
		print DUMPFILE "\t\tService: Original\n";
		#--- backward rule
	        $i++;
		print DUMPFILE "\nRule $i (implicit)\n";
		print DUMPFILE "\tORIGINAL\n";
		print DUMPFILE "\t\tFrom:    Any\n";
		print DUMPFILE "\t\tTo:      $obj_NATadr{$name}\n";
		print DUMPFILE "\t\tService: Any\n";
		print DUMPFILE "\tTRANSLATED\n";
		print DUMPFILE "\t\tFrom:    Original\n";
		print DUMPFILE "\t\tTo:      $name";
		print DUMPFILE " ($NATtranslation{$obj_NATtype{$name}})\n";
		print DUMPFILE "\t\tService: Original\n";
	    }
	}
    }
    close (DUMPFILE);
}


##########################################################################
# dump all objects into a TSV file
#	filename for the dump

sub DumpObjectsTSV{
    my ($filename) = $_[0];
    my ($name)     = '';

    open (DUMPFILE,">$filename") ;
    print DUMPFILE "name\ttype\tlocation\tis_fw1\tipaddr\tnetmask\tNATadr\tNATtype\tmembers\tcomment\tcolour\n";
    print DUMPFILE "-----\t-----\t-----\t-----\t-----\t-----\t-----\t-----\t-----\t-----\t-----\n";
    foreach $name (@obj_name){
	if ( $obj_used{$name} || $FLAG_allobjs ) {
	    $txt = "$obj_members{$name}"; $txt =~ s/§/ /g;
	    print DUMPFILE "$name\t$obj_type{$name}\t$obj_location{$name}\t$obj_is_fw1{$name}\t$obj_ipaddr{$name}\t$obj_netmask{$name}\t$obj_NATadr{$name}\t$obj_NATtype{$name}\t$txt\t$obj_comment{$name}\t$obj_colour{$name}\n";
	}
    }
    close (DUMPFILE);
}


##########################################################################
# dump all objects into a nice text file
#	filename for the dump

sub DumpObjectsTXT{
    my ($filename) = $_[0];
    my ($name)     = '';

    open (DUMPFILE,">$filename") ;
    foreach $name (@obj_name){
	if ( $obj_used{$name} || $FLAG_allobjs ) {
	    print DUMPFILE "\n$name\n";
	    print DUMPFILE "\tType: $obj_type{$name}\n";
	    if ( $obj_location{$name} ) {
		print DUMPFILE "\tLocation: external\n";
	    } else {
		print DUMPFILE "\tLocation: internal\n";
	    }
	    if ( $obj_is_fw1{$name} ) {
		print DUMPFILE "\tFirewall-1 is installed\n";
	    }
	    &PrintNonempty(DUMPFILE,"\tIP-Address: %s\n",$obj_ipaddr{$name});
	    &PrintNonempty(DUMPFILE,"\tNetmask: %s\n",$obj_netmask{$name});
	    &PrintNonempty(DUMPFILE,"\tNAT-Address: %s ($NATtranslation{$obj_NATtype{$name}})\n",$obj_NATadr{$name});
	    $txt = "$obj_members{$name}"; $txt =~ s/§/ /g;
	    &PrintNonempty(DUMPFILE,"\tMembers: %s\n",$txt);
	    &PrintNonempty(DUMPFILE,"\tComment: %s\n",$obj_comment{$name});
	}
    }
    close (DUMPFILE);
}


##########################################################################
# dump all services into a TSV file
#	filename for the dump

sub DumpServicesTSV{
    my ($filename) = $_[0];
    my ($name)     = '';

    open (DUMPFILE,">$filename") ;
    print DUMPFILE "name\ttype\tdst_port\tsrc_port_low\tsrc_port_high\tmatch\tprolog\tmembers\tcomment\tcolour\n";
    print DUMPFILE "-----\t-----\t-----\t-----\t-----\t-----\t-----\t-----\t-----\t-----\n";
    foreach $name (@svc_name){
	if ( $svc_used{$name} || $FLAG_allservices ) {
	    $txt = "$svc_members{$name}"; $txt =~ s/§/ /g;
	    print DUMPFILE "$name\t$svc_type{$name}\t$svc_dst_port{$name}\t$svc_src_low{$name}\t$svc_src_high{$name}\t$svc_match{$name}\t$svc_prolog{$name}\t$txt\t$svc_comment{$name}\t$svc_colour{$name}\n";
	}
    }
    close (DUMPFILE);
}

##########################################################################
# dump all services into a nice text file
#	filename for the dump

sub DumpServicesTXT{
    my ($filename) = $_[0];
    my ($name)     = '';

    open (DUMPFILE,">$filename") ;
    foreach $name (@svc_name){
	if ( $svc_used{$name} || $FLAG_allservices ) {
	    print DUMPFILE "\n$name\n";
	    print DUMPFILE "\tType: $svc_type{$name}\n";
	    &PrintNonempty(DUMPFILE,"\tDestination Port: %s\n",$svc_dst_port{$name});
	    &PrintNonempty(DUMPFILE,"\tSource Port (low): %s\n",$svc_src_low{$name});
	    &PrintNonempty(DUMPFILE,"\tSource Port (high): %s\n",$svc_src_high{$name});
	    &PrintNonempty(DUMPFILE,"\tpre-Match: %s\n",$svc_match{$name});
	    &PrintNonempty(DUMPFILE,"\tProlog: %s\n",$svc_prolog{$name});
	    $txt = "$svc_members{$name}"; $txt =~ s/§/ /g;
	    &PrintNonempty(DUMPFILE,"\tMembers: %s\n",$txt);
	    &PrintNonempty(DUMPFILE,"\tComment: %s\n",$svc_comment{$name});
	}
    }
    close (DUMPFILE);
}

##########################################################################
# dump all users into a TSV file
#	filename for the dump

sub DumpUsersTSV{
    my ($filename) = $_[0];
    my ($name)     = '';

    open (DUMPFILE,">$filename") ;
    print DUMPFILE "name\ttype\tfrom\tto\tauth\tday\texpires\tmembers\tcomment\tcolour\n";
    print DUMPFILE "-----\t-----\t-----\t-----\t-----\t-----\t-----\t-----\t-----\n";
    foreach $name (@user_name){
	next if($name =~ /^ *$/);
	next if($name =~ /All Users/);
	next if($name =~ /ALL_GROUPS/);
	next if($name =~ /ALL_KEYH/);
	next if($name =~ /ALL_TEMPLATES/);
	next if($user_type{$name} =~ /keyh/);
	next if($user_type{$name} =~ /template/);
	$txt = "user_members{$name}"; $txt =~ s/§/ /g;
	if ( $user_used{$name} || $FLAG_alluser ) {
	   print DUMPFILE "$name\t$user_type{$name}\t$user_from{$name}\t$user_to{$name}\t$user_auth{$name}\t$user_day{$name}\t$user_expires{$name}\t$txt\t$user_comment{$name}";
	}
    }
    close (DUMPFILE);
}


##########################################################################
# dump all users into a nice text file
#	filename for the dump

sub DumpUsersTXT{
    my ($filename) = $_[0];
    my ($name)     = '';

    open (DUMPFILE,">$filename") ;
    foreach $name (@user_name){
	next if($name =~ /^ *$/);
	next if($name =~ /All Users/);
	next if($name =~ /ALL_GROUPS/);
	next if($name =~ /ALL_KEYH/);
	next if($name =~ /ALL_TEMPLATES/);
	next if($user_type{$name} =~ /keyh/);
	next if($user_type{$name} =~ /template/);
	if ( $user_used{$name} || $FLAG_alluser ) {
	   print DUMPFILE "$name\n";
	   &PrintNonempty(DUMPFILE,"\tType:    %s\n",$user_type{$name});
	   &PrintNonempty(DUMPFILE,"\tFrom:    %s\n",$user_from{$name});
	   &PrintNonempty(DUMPFILE,"\tTo:      %s\n",$user_to{$name});
	   &PrintNonempty(DUMPFILE,"\tAuth:    %s\n",$user_auth{$name});
	   &PrintNonempty(DUMPFILE,"\tDay:     %s\n",$user_day{$name});
	   &PrintNonempty(DUMPFILE,"\tExpires: %s\n",$user_expires{$name});
	   $txt = "user_members{$name}"; $txt =~ s/§/ /g;
	   &PrintNonempty(DUMPFILE,"\tMembers: %s\n",$txt);
	   &PrintNonempty(DUMPFILE,"\tComment: %s\n",$user_comment{$name});
	}
    }
    close (DUMPFILE);
}


##########################################################################
# dump all unused objects and services into a nice text file
#	filename for the dump

sub DumpUnusedObjects{
    my ($filename) = $_[0];
    my ($name)     = '';

    open (DUMPFILE,">$filename") ;
    print DUMPFILE "\n----------------------\n";
    print DUMPFILE "Unused Network Objects\n";
    print DUMPFILE "----------------------\n";
    foreach $name (@obj_name){
	if ( ! $obj_used{$name} ) {
	    $txt = "$obj_members{$name}"; $txt =~ s/§/ /g;
	    print DUMPFILE "\n$name  \($obj_ipaddr{$name} / $obj_netmask{$name}\) $txt\n";
	}
    }
    print DUMPFILE "\n\n----------------------------------\n";
    print DUMPFILE "Unused Services (maybe predefined)\n";
    print DUMPFILE "----------------------------------\n";
    foreach $name (@svc_name){
	if ( ! $svc_used{$name} ) {
	    $txt = "$svc_members{$name}"; $txt =~ s/§/ /g;
	    print DUMPFILE "\n$name  \($svc_type{$name}/$svc_dst_port{$name}\) $txt : $svc_comment{$name}\n";
	}
    }
    print DUMPFILE "\n\n----------------------------------\n";
    print DUMPFILE "Unused Users\n";
    print DUMPFILE "----------------------------------\n";
    close (DUMPFILE);
    foreach $name (@user_name){
	next if($name =~ /^ *$/);
	next if($name =~ /All Users/);
	next if($name =~ /ALL_GROUPS/);
	next if($name =~ /ALL_KEYH/);
	next if($name =~ /ALL_TEMPLATES/);
	next if($user_type{$name} =~ /keyh/);
	next if($user_type{$name} =~ /template/);
	if ( ! $user_used{$name} ) {
	   print DUMPFILE "$name ($user_type{$name})  $user_comment{$name}\n";
	}
    }
}

##########################################################################
# dump all unused objects into a tsv file
#	filename for the dump

sub DumpUnusedObjectsTsv{
    my ($filename) = $_[0];
    my ($name)     = '';

    open (DUMPFILE,">unused_obj_${filename}") ;
    print DUMPFILE "name\ttype\tlocation\tipaddr\tnetmask\tmembers\tcomment\tcolour\n";
    foreach $name (@obj_name){
	if ( ! $obj_used{$name} ) {
	    $txt = "$obj_members{$name}"; $txt =~ s/§/ /g;
	    print DUMPFILE "$name\t$obj_type{$name}\t$obj_location{$name}\t$obj_ipaddr{$name}\t$obj_netmask{$name}\t$txt\t$obj_comment{$name}\t$obj_colour{$name}\n";
	}
    }
    close (DUMPFILE);

    open (DUMPFILE,">unused_svc_${filename}") ;
    print DUMPFILE "name\ttype\tlocation\tipaddr\tnetmask\tmembers\tcomment\tcolour\n";
    foreach $name (@svc_name){
	if ( ! $svc_used{$name} ) {
	    $txt = "$svc_members{$name}"; $txt =~ s/§/ /g;
	    print DUMPFILE "$name\t$svc_type{$name}\t$svc_dst_port{$name}\t$txt\t$svc_comment{$name}\n";
	}
    }
    close (DUMPFILE);
}



##########################################################################
##########################################################################
###   Print nice config files
##########################################################################
##########################################################################

##########################################################################
# give (translated) colour for HTML
#	color to set

sub HTMLcolour {
    my ($givencolour)   = $_[0];
    $givencolour =~ s/"//g;

    if ( $FLAG_withcolors ) {
	if ( $colors{"$givencolour"} ne '' ) {
	    $givencolour = $colors{"$givencolour"};
	}
	return("style=\"color:$givencolour\"");
    } else {
    	return ('');
    }
}


##########################################################################
# print object or dash
#	file handle
#	object string (maybe null, in which case a dash is printed

sub PrintOrDash {
    my ($FILE)         = $_[0];
    my ($object)       = $_[1];

    if ( "$object" eq '') {
	print $FILE '-';
    } else {
	print $FILE "$object";
    }
}

##########################################################################
# print object for HTML
#	file handle
#	switch:  1 = negated,   0 = normal
#	object string (maybe multiple instances)

sub subObject__Output_in_HTML {
    my ($FILE)         = $_[0];
    my ($if_negated)   = $_[1];
    my ($objects)      = $_[2];
    my ($indentation)  = $_[3];
    my (@obj_array);
    my ($iconname)     = '';
    my ($colr)         = '';
    my ($neg)          = '';

    @obj_array = split (/§/, $objects);
    foreach $name (@obj_array){
	print $FILE "&nbsp;&nbsp;&nbsp;" x $indentation if ($indentation);
	$colr = &HTMLcolour($obj_colour{$name});
	if ( $if_negated ) {
	    $iconname = lc("$IconPathName/negated$obj_type{$name}.png");
	    $neg = '!&nbsp;';
	} else {
	    $iconname = lc("$IconPathName/$obj_type{$name}.png");
	}
	if ( ( lc("$name") eq 'any' ) || ( lc("$name") eq 'original' ) ) {
	    print $FILE "\<img src=$IconPathName/any.png\>\&nbsp;$name<br>";
	} elsif ( lc("$name") eq 'gateways' ) {
	    print $FILE "\<img src=$IconPathName/gateways.png\>\&nbsp;\Gateways\<br>";
	} elsif ( lc("$name") eq 'dst' ) {
	    print $FILE "\<img src=$IconPathName/dst.png\>\&nbsp;\Destination\<br>";
	} elsif ( lc("$name") =~ /embedded devices/ ) {
	    print $FILE "\<img src=$IconPathName/embedded_devices.png\>\&nbsp;Embeddded Devices\<br>";
	} elsif ( lc("$name") =~ /ose devices/ ) {
	    print $FILE "\<img src=$IconPathName/ose_devices.png\>\&nbsp;OSE Devices\<br>";
	} elsif ( lc("$name") eq 'src' ) {
	    print $FILE "\<img src=$IconPathName/src.png\>\&nbsp;Source\<br>";
	} elsif ( $srv_reference{$name} ne "") {
	    $iconname = lc("$IconPathName/$srv_type{$name}.png");
	} else {
	    $addressinfo = "";
            if ( $FLAG_withip  && ($obj_ipaddr{$name} ne "") ) {
		if ($obj_netmask{$name} ne "") {
		   $addressinfo =  "<br> net  " .  $obj_ipaddr{$name} . " / " . $netmasktranslation{"$obj_netmask{$name}"};
		} else {
		   $addressinfo =  "<br> host  " .  $obj_ipaddr{$name};
		}
	    }
           # print $FILE "\<img src=$iconname\>\&nbsp;$neg\<a href=\#OBJ\_$name $colr\>$name\</A\> $addressinfo<BR>\n";
           # Modified for R65 compability 2008-11-02 by Jacob
           print $FILE "\<img src=$iconname\>\&nbsp;$neg\<a href=\#OBJ\_$name $colr\>$name\</A\> $addressinfo<BR>\n" unless "$name" eq "ReferenceObject";
	    if ($FLAG_showmembers && $obj_members{$name}) {      # object with members (group)?
		&subObject__Output_in_HTML($FILE, $if_negated, $obj_members{$name}, $indentation+1);    # recurse
	    }
#	    if ( $FLAG_withinterface && ( $obj_if_number{$name} > 0)) {
#		for ($k = 0; $k < $obj_if_number{$name}; $k++) {
#		    $ref = "NIC$k.$name";
#	   	    $addressinfo = "$addressinfo <br>" .
#			"$obj_if_name{$ref} \: $obj_if_ipaddr{$ref} / $obj_if_netmask{$ref}";
#		}
#	    } # if withinterface
	}   # if normal object
    }   # foreach
}

##########################################################################
# print service for HTML
#	file handle
#	switch:  1 = negated,   0 = normal
#	object string (maybe multiple instances)

sub subService__Output_in_HTML {
    my ($FILE)         = $_[0];
    my ($if_negated)   = $_[1];
    my ($services)     = $_[2];
    my ($indentation)  = $_[3];
    my (@serv_array);
    my ($iconname)     = '';
    my ($neg)          = '';
    my ($ressource)    = '';

    @serv_array = split (/§/, $services);
    foreach $name (@serv_array){
	print $FILE "&nbsp;&nbsp;&nbsp;" x $indentation if ($indentation);
	$colr = &HTMLcolour($svc_colour{$name});
    	$ressource = '';
	if ( $name =~ m/-\>/ ) {
	   ($name,$ressource) = split(/-\>/, $name, 2);
	   $colr = &HTMLcolour($svc_colour{$name}); # recalculate colour
	}
	if ( $if_negated ) {
	    if ( ( "$ressource" ne '' ) &&
	    	 ( "$name" =~ /(http|ftp|smtp)/ ) ){
		$iconname = lc("$IconPathName/negatedressource_$1.png");
	    } else {
		$iconname = lc("$IconPathName/negated$svc_type{$name}.png");
	    }
	    $neg = '!&nbsp;';
	} else {
	    if ( ( "$ressource" ne '' ) &&
	    	 ( "$name" =~ /(http|ftp|smtp)/ ) ){
		$iconname = lc("$IconPathName/ressource_$1.png");
	     } else {
		$iconname = lc("$IconPathName/$svc_type{$name}.png");
	     }
	}
	if ( ( lc("$name") eq 'any' ) || ( lc("$name") eq 'original' ) ) {
	    print $FILE "\<img src=$IconPathName/any.png\>\&nbsp;$name<br>";
	} else {
	    $aname = $name; $aname =~ s/>//g;
	    print $FILE "\<img src=$iconname\>\&nbsp;$neg\<a href=#SVC_$aname $colr\>$name";
	    if ( "$ressource" ne '' ) {
		print $FILE "-&gt;\<a href=#RES_$ressource\>$ressource\</a\>";
	    }
	    print $FILE "\</a\><br>";
	}
	if ($FLAG_showmembers && $svc_members{$name}) {      # service with members (group)?
	    &subService__Output_in_HTML($FILE, $if_negated, $svc_members{$name}, $indentation+1);    # recurse
	}
    }
}

##########################################################################
# print userobject for HTML
#	file handle
#	switch:  1 = negated,   0 = normal
#	object string (maybe multiple instances)

sub subUserObject__Output_in_HTML {
    my ($FILE)                = $_[0];
    my ($if_negated)   = $_[1];
    my ($objects)      = $_[2];
    my (@obj_array);
    my ($iconname)     = '';
    my ($colr)         = '';
    my ($neg)          = '';
    my ($obj)          = '';
    my ($user)          = '';

    @obj_array = split (/§/, $objects);
    foreach $obj (@obj_array){
	($user,$name)=split (/@/, $obj);
	if ( ! $FLAG_nousers ) {
	   $colr = &HTMLcolour($user_colour{$user});
	   if ( $if_negated ) {
	      $iconname = lc("$IconPathName/negated$user_type{$user}.png");
	      $neg = '!&nbsp;';
	   } else {
	      if ( lc("$user") eq '"all users' ) {
	  	$iconname = lc("$IconPathName/usrgroup.png");
	      } else {
	  	$iconname = lc("$IconPathName/$user_type{$user}.png");
	      }
	   }
	   if ( lc("$user") eq 'any' ) {
	      print $FILE "\<img src=$iconname\>\&nbsp;$neg$user@";
	   } else {
	      print $FILE "\<img src=$iconname\>\&nbsp;$neg\<a href=#$user $colr\>$user\</a\>@";
	   }
	   if ( lc("$name") eq 'any' ) {
	      print $FILE "$name\<br>";
	   } else {
	      print $FILE "\<a href=#OBJ_$name $colr\>$name\</a\><br>";
	   }
	} else {
	   if ( $if_negated ) {
	      $iconname = lc("$IconPathName/negatedusrgroup.png");
	      $neg = '!&nbsp;';
	   } else {
	      $iconname = lc("$IconPathName/usrgroup.png");
	   }
	   print $FILE "\<img src=$iconname\>\&nbsp;$neg$user@";
	   # print hyperlinks for 'location' in 'user@location' if it is not 'any'
	   if(lc("$name") eq 'any'){
	       print $FILE "$name\<br>";
	   }else{
	       print $FILE "\<a href=#OBJ_$name style=\"color: $colr\"\>$name\</a\><br>";
	   }
	}
    }
}

##########################################################################
# print user for HTML
#	file handle
#	object string (maybe multiple instances)

sub subUser__Output_in_HTML {
    my ($FILE)         = $_[0];
    my ($user)     = $_[1];
    my (@user_array);
    my ($iconname)     = '';
    @user_array = split (/ /, $user);
    foreach $name (@user_array){
	next if($name =~ /^ *$/);
	$colr = &HTMLcolour($user_colour{$name});
	$iconname = lc("$IconPathName/$user_type{$name}.png");
	if ( lc("$name") eq 'any' ) {
	   print $FILE "\<img src=$IconPathName/any.png\>\&nbsp;Any<br>";
	} else {
	   print $FILE "\<img src=$iconname\>\&nbsp;$neg\<a href=#$name $colr\>$name\</a\><br>";
	}
    }
}

##########################################################################
# print implicit rules in HTML
#	file handle
#	location id ( first / "before last" / last
sub subImplicit__Output_in_HTML {
  my ($FILE)         = $_[0];
  my ($locstr)       = $_[1];

  if ( $FLAG_implicitrules ) {
    print DUMPFILE "\n<!------- implicit rules ------->\n";
    if ( ("$prop_setting{'fw1enable'}" eq 'true') &&
         (lc("$prop_setting{'fw1enable_p'}") eq "$locstr") ) {
	# FW1_mgmt
	print DUMPFILE '<tr><td bgcolor=#ffff00> &nbsp; </td>';
	print DUMPFILE "<td bgcolor=#ffff00><img src=$IconPathName/group.png>\&nbsp;gui_clients</td><td bgcolor=#ffff00><img src=$IconPathName/gateway.png>\&nbsp;FW1 Management</td><td bgcolor=#ffff00><img src=$IconPathName/tcp.png>\&nbsp;FW1_mgmt</td>";  # svc
	print DUMPFILE "<td bgcolor=#ffff00><img src=$IconPathName/accept.png>\&nbsp;accept</td><td bgcolor=#ffff00> &nbsp; </td><td bgcolor=#ffff00><img src=$IconPathName/any.png>\&nbsp;Any</td><td bgcolor=#ffff00><img src=$IconPathName/gateways.png>\&nbsp;Gateways</td><td bgcolor=#ffff00>Implicit rule:  Enable FW1 </td><\/tr>\n";
	# FW1_ela
	print DUMPFILE '<tr><td bgcolor=#ffff00> &nbsp; </td>';
	print DUMPFILE "<td bgcolor=#ffff00><img src=$IconPathName/gateway.png>\&nbsp;FloodGate-1 Host</td><td bgcolor=#ffff00><img src=$IconPathName/gateway.png>\&nbsp;FW1 Management</td><td bgcolor=#ffff00><img src=$IconPathName/tcp.png>\&nbsp;FW1_ela</td>";  # svc
	print DUMPFILE "<td bgcolor=#ffff00><img src=$IconPathName/accept.png>\&nbsp;accept</td><td bgcolor=#ffff00> &nbsp; </td><td bgcolor=#ffff00><img src=$IconPathName/any.png>\&nbsp;Any</td><td bgcolor=#ffff00><img src=$IconPathName/gateways.png>\&nbsp;Gateways</td><td bgcolor=#ffff00>Implicit rule:  Enable FW1 </td><\/tr>\n";
	# RDP
	print DUMPFILE '<tr><td bgcolor=#ffff00> &nbsp; </td>';
	print DUMPFILE "<td bgcolor=#ffff00><img src=$IconPathName/any.png>\&nbsp;Any</td><td bgcolor=#ffff00><img src=$IconPathName/any.png>\&nbsp;Any</td><td bgcolor=#ffff00><img src=$IconPathName/udp.png>\&nbsp;RDP</td>";  # svc
	print DUMPFILE "<td bgcolor=#ffff00><img src=$IconPathName/accept.png>\&nbsp;accept</td><td bgcolor=#ffff00> &nbsp; </td><td bgcolor=#ffff00><img src=$IconPathName/any.png>\&nbsp;Any</td><td bgcolor=#ffff00><img src=$IconPathName/gateways.png>\&nbsp;Gateways</td><td bgcolor=#ffff00>Implicit rule:  Enable FW1 </td><\/tr>\n";
	# FW1_cvp
	print DUMPFILE '<tr><td bgcolor=#ffff00> &nbsp; </td>';
	print DUMPFILE "<td bgcolor=#ffff00><img src=$IconPathName/gateway.png>\&nbsp;FW1 Host</td><td bgcolor=#ffff00><img src=$IconPathName/any.png>\&nbsp;CVP-Servers</td><td bgcolor=#ffff00><img src=$IconPathName/tcp.png>\&nbsp;FW1_cvp</td>";  # svc
	print DUMPFILE "<td bgcolor=#ffff00><img src=$IconPathName/accept.png>\&nbsp;accept</td><td bgcolor=#ffff00> &nbsp; </td><td bgcolor=#ffff00><img src=$IconPathName/any.png>\&nbsp;Any</td><td bgcolor=#ffff00><img src=$IconPathName/gateways.png>\&nbsp;Gateways</td><td bgcolor=#ffff00>Implicit rule:  Enable FW1 </td><\/tr>\n";
	# FW1_ufp
	print DUMPFILE '<tr><td bgcolor=#ffff00> &nbsp; </td>';
	print DUMPFILE "<td bgcolor=#ffff00><img src=$IconPathName/gateway.png>\&nbsp;FW1 Host</td><td bgcolor=#ffff00><img src=$IconPathName/any.png>\&nbsp;UFP-Servers</td><td bgcolor=#ffff00><img src=$IconPathName/tcp.png>\&nbsp;FW1_ufp</td>";  # svc
	print DUMPFILE "<td bgcolor=#ffff00><img src=$IconPathName/accept.png>\&nbsp;accept</td><td bgcolor=#ffff00> &nbsp; </td><td bgcolor=#ffff00><img src=$IconPathName/any.png>\&nbsp;Any</td><td bgcolor=#ffff00><img src=$IconPathName/gateways.png>\&nbsp;Gateways</td><td bgcolor=#ffff00>Implicit rule:  Enable FW1 </td><\/tr>\n";
	# RADIUS
	print DUMPFILE '<tr><td bgcolor=#ffff00> &nbsp; </td>';
	print DUMPFILE "<td bgcolor=#ffff00><img src=$IconPathName/gateway.png>\&nbsp;FW1 Host</td><td bgcolor=#ffff00><img src=$IconPathName/any.png>\&nbsp;Radius-Servers</td><td bgcolor=#ffff00><img src=$IconPathName/udp.png>\&nbsp;RADIUS</td>";  # svc
	print DUMPFILE "<td bgcolor=#ffff00><img src=$IconPathName/accept.png>\&nbsp;accept</td><td bgcolor=#ffff00> &nbsp; </td><td bgcolor=#ffff00><img src=$IconPathName/any.png>\&nbsp;Any</td><td bgcolor=#ffff00><img src=$IconPathName/gateways.png>\&nbsp;Gateways</td><td bgcolor=#ffff00>Implicit rule:  Enable FW1 </td><\/tr>\n";
	# TACACS
	print DUMPFILE '<tr><td bgcolor=#ffff00> &nbsp; </td>';
	print DUMPFILE "<td bgcolor=#ffff00><img src=$IconPathName/gateway.png>\&nbsp;FW1 Host</td><td bgcolor=#ffff00><img src=$IconPathName/any.png>\&nbsp;TACACS-Servers</td><td bgcolor=#ffff00><img src=$IconPathName/udp.png>\&nbsp;TACACS</td>";  # svc
	print DUMPFILE "<td bgcolor=#ffff00><img src=$IconPathName/accept.png>\&nbsp;accept</td><td bgcolor=#ffff00> &nbsp; </td><td bgcolor=#ffff00><img src=$IconPathName/any.png>\&nbsp;Any</td><td bgcolor=#ffff00><img src=$IconPathName/gateways.png>\&nbsp;Gateways</td><td bgcolor=#ffff00>Implicit rule:  Enable FW1 </td><\/tr>\n";
	# ldap
	print DUMPFILE '<tr><td bgcolor=#ffff00> &nbsp; </td>';
	print DUMPFILE "<td bgcolor=#ffff00><img src=$IconPathName/gateway.png>\&nbsp;FW1 Host</td><td bgcolor=#ffff00><img src=$IconPathName/any.png>\&nbsp;LDAP-Servers</td><td bgcolor=#ffff00><img src=$IconPathName/tcp.png>\&nbsp;ldap</td>";  # svc
	print DUMPFILE "<td bgcolor=#ffff00><img src=$IconPathName/accept.png>\&nbsp;accept</td><td bgcolor=#ffff00> &nbsp; </td><td bgcolor=#ffff00><img src=$IconPathName/any.png>\&nbsp;Any</td><td bgcolor=#ffff00><img src=$IconPathName/gateways.png>\&nbsp;Gateways</td><td bgcolor=#ffff00>Implicit rule:  Enable FW1 </td><\/tr>\n";
	# load_agent
	print DUMPFILE '<tr><td bgcolor=#ffff00> &nbsp; </td>';
	print DUMPFILE "<td bgcolor=#ffff00><img src=$IconPathName/gateway.png>\&nbsp;FW1 Host</td><td bgcolor=#ffff00><img src=$IconPathName/any.png>\&nbsp;Logical-Servers</td><td bgcolor=#ffff00><img src=$IconPathName/other.png>\&nbsp;load_agent</td>";  # svc
	print DUMPFILE "<td bgcolor=#ffff00><img src=$IconPathName/accept.png>\&nbsp;accept</td><td bgcolor=#ffff00> &nbsp; </td><td bgcolor=#ffff00><img src=$IconPathName/any.png>\&nbsp;Any</td><td bgcolor=#ffff00><img src=$IconPathName/gateways.png>\&nbsp;Gateways</td><td bgcolor=#ffff00>Implicit rule:  Enable FW1 </td><\/tr>\n";
	# ike
	print DUMPFILE '<tr><td bgcolor=#ffff00> &nbsp; </td>';
	print DUMPFILE "<td bgcolor=#ffff00><img src=$IconPathName/gateway.png>\&nbsp;FW1 Host</td><td bgcolor=#ffff00><img src=$IconPathName/any.png>\&nbsp;Any</td><td bgcolor=#ffff00><img src=$IconPathName/udp.png>\&nbsp;IKE</td>";  # svc
	print DUMPFILE "<td bgcolor=#ffff00><img src=$IconPathName/accept.png>\&nbsp;accept</td><td bgcolor=#ffff00> &nbsp; </td><td bgcolor=#ffff00><img src=$IconPathName/any.png>\&nbsp;Any</td><td bgcolor=#ffff00><img src=$IconPathName/gateways.png>\&nbsp;Gateways</td><td bgcolor=#ffff00>Implicit rule:  Enable FW1 </td><\/tr>\n";
	# FW1_topo
	print DUMPFILE '<tr><td bgcolor=#ffff00> &nbsp; </td>';
	print DUMPFILE "<td bgcolor=#ffff00><img src=$IconPathName/any.png>\&nbsp;Any</td><td bgcolor=#ffff00><img src=$IconPathName/gateway.png>\&nbsp;FW1 Host</td><td bgcolor=#ffff00><img src=$IconPathName/tcp.png>\&nbsp;FW1_topo</td>";  # svc
	print DUMPFILE "<td bgcolor=#ffff00><img src=$IconPathName/accept.png>\&nbsp;accept</td><td bgcolor=#ffff00> &nbsp; </td><td bgcolor=#ffff00><img src=$IconPathName/any.png>\&nbsp;Any</td><td bgcolor=#ffff00><img src=$IconPathName/gateways.png>\&nbsp;Gateways</td><td bgcolor=#ffff00>Implicit rule:  Enable FW1 </td><\/tr>\n";
	# FW1_key
	print DUMPFILE '<tr><td bgcolor=#ffff00> &nbsp; </td>';
	print DUMPFILE "<td bgcolor=#ffff00><img src=$IconPathName/any.png>\&nbsp;Any</td><td bgcolor=#ffff00><img src=$IconPathName/gateway.png>\&nbsp;FW1 Host</td><td bgcolor=#ffff00><img src=$IconPathName/tcp.png>\&nbsp;FW1_key</td>";  # svc
	print DUMPFILE "<td bgcolor=#ffff00><img src=$IconPathName/accept.png>\&nbsp;accept</td><td bgcolor=#ffff00> &nbsp; </td><td bgcolor=#ffff00><img src=$IconPathName/any.png>\&nbsp;Any</td><td bgcolor=#ffff00><img src=$IconPathName/gateways.png>\&nbsp;Gateways</td><td bgcolor=#ffff00>Implicit rule:  Enable FW1 </td><\/tr>\n";
	# IKE
	print DUMPFILE '<tr><td bgcolor=#ffff00> &nbsp; </td>';
	print DUMPFILE "<td bgcolor=#ffff00><img src=$IconPathName/any.png>\&nbsp;Any</td><td bgcolor=#ffff00><img src=$IconPathName/gateway.png>\&nbsp;FW1 Host</td><td bgcolor=#ffff00><img src=$IconPathName/udp.png>\&nbsp;IKE</td>";  # svc
	print DUMPFILE "<td bgcolor=#ffff00><img src=$IconPathName/accept.png>\&nbsp;accept</td><td bgcolor=#ffff00> &nbsp; </td><td bgcolor=#ffff00><img src=$IconPathName/any.png>\&nbsp;Any</td><td bgcolor=#ffff00><img src=$IconPathName/gateways.png>\&nbsp;Gateways</td><td bgcolor=#ffff00>Implicit rule:  Enable FW1 </td><\/tr>\n";
	# FW1
	print DUMPFILE '<tr><td bgcolor=#ffff00> &nbsp; </td>';
	print DUMPFILE "<td bgcolor=#ffff00><img src=$IconPathName/gateway.png>\&nbsp;FW1 Host</td><td bgcolor=#ffff00><img src=$IconPathName/gateway.png>\&nbsp;FW1 Host</td><td bgcolor=#ffff00><img src=$IconPathName/tcp.png>\&nbsp;FW1</td>";  # svc
	print DUMPFILE "<td bgcolor=#ffff00><img src=$IconPathName/accept.png>\&nbsp;accept</td><td bgcolor=#ffff00> &nbsp; </td><td bgcolor=#ffff00><img src=$IconPathName/any.png>\&nbsp;Any</td><td bgcolor=#ffff00><img src=$IconPathName/gateways.png>\&nbsp;Gateways</td><td bgcolor=#ffff00>Implicit rule:  Enable FW1 </td><\/tr>\n";
	# FW1_log
	print DUMPFILE '<tr><td bgcolor=#ffff00> &nbsp; </td>';
	print DUMPFILE "<td bgcolor=#ffff00><img src=$IconPathName/gateway.png>\&nbsp;FW1 Host</td><td bgcolor=#ffff00><img src=$IconPathName/gateway.png>\&nbsp;FW1 Host</td><td bgcolor=#ffff00><img src=$IconPathName/tcp.png>\&nbsp;FW1_log</td>";  # svc
	print DUMPFILE "<td bgcolor=#ffff00><img src=$IconPathName/accept.png>\&nbsp;accept</td><td bgcolor=#ffff00> &nbsp; </td><td bgcolor=#ffff00><img src=$IconPathName/any.png>\&nbsp;Any</td><td bgcolor=#ffff00><img src=$IconPathName/gateways.png>\&nbsp;Gateways</td><td bgcolor=#ffff00>Implicit rule:  Enable FW1 </td><\/tr>\n";
    }
# outgoing
    if ( ("$prop_setting{'outgoing'}" eq 'true') &&
         (lc("$prop_setting{'outgoing_p'}") eq "$locstr") ) {
	print DUMPFILE '<tr><td bgcolor=#ffff00> &nbsp; </td>';
	print DUMPFILE "<td bgcolor=#ffff00><img src=$IconPathName/gateway.png>\&nbsp;FW1 Host</td><td bgcolor=#ffff00><img src=$IconPathName/any.png>\&nbsp;Any</td><td bgcolor=#ffff00><img src=$IconPathName/any.png>\&nbsp;Any</td>";  # svc
	print DUMPFILE "<td bgcolor=#ffff00><img src=$IconPathName/accept.png>\&nbsp;accept</td><td bgcolor=#ffff00> &nbsp; </td><td bgcolor=#ffff00><img src=$IconPathName/any.png>\&nbsp;Any</td><td bgcolor=#ffff00><img src=$IconPathName/gateways.png>\&nbsp;Gateways</td><td bgcolor=#ffff00>Implicit rule:  Enable Outgoing Connections </td><\/tr>\n";
    }
# RIP
    if ( ("$prop_setting{'rip'}" eq 'true') &&
         (lc("$prop_setting{'rip_p'}") eq "$locstr") ) {
	print DUMPFILE '<tr><td bgcolor=#ffff00> &nbsp; </td>';
	print DUMPFILE "<td bgcolor=#ffff00><img src=$IconPathName/any.png>\&nbsp;Any</td><td bgcolor=#ffff00><img src=$IconPathName/any.png>\&nbsp;Any</td><td bgcolor=#ffff00><img src=$IconPathName/udp.png>\&nbsp;RIP</td>";  # svc
	print DUMPFILE "<td bgcolor=#ffff00><img src=$IconPathName/accept.png>\&nbsp;accept</td><td bgcolor=#ffff00> &nbsp; </td><td bgcolor=#ffff00><img src=$IconPathName/any.png>\&nbsp;Any</td><td bgcolor=#ffff00><img src=$IconPathName/gateways.png>\&nbsp;Gateways</td><td bgcolor=#ffff00>Implicit rule:  Enable RIP </td><\/tr>\n";
    }

# ICMP
    if ( ("$prop_setting{'icmpenable'}" eq 'true') &&
         (lc("$prop_setting{'icmpenable_p'}") eq "$locstr") ) {
	print DUMPFILE '<tr><td bgcolor=#ffff00> &nbsp; </td>';
	print DUMPFILE "<td bgcolor=#ffff00><img src=$IconPathName/any.png>\&nbsp;Any</td><td bgcolor=#ffff00><img src=$IconPathName/any.png>\&nbsp;Any</td><td bgcolor=#ffff00><img src=$IconPathName/icmp.png>\&nbsp;ICMP</td>";  # svc
	print DUMPFILE "<td bgcolor=#ffff00><img src=$IconPathName/accept.png>\&nbsp;accept</td><td bgcolor=#ffff00> &nbsp; </td><td bgcolor=#ffff00><img src=$IconPathName/any.png>\&nbsp;Any</td><td bgcolor=#ffff00><img src=$IconPathName/gateways.png>\&nbsp;Gateways</td><td bgcolor=#ffff00>Implicit rule:  Enable ICMP </td><\/tr>\n";
    }
# domain TCP
    if ( ("$prop_setting{'domain_tcp'}" eq 'true') &&
         (lc("$prop_setting{'domain_tcp_p'}") eq "$locstr") ) {
	print DUMPFILE '<tr><td bgcolor=#ffff00> &nbsp; </td>';
	print DUMPFILE "<td bgcolor=#ffff00><img src=$IconPathName/any.png>\&nbsp;Any</td><td bgcolor=#ffff00><img src=$IconPathName/any.png>\&nbsp;Any</td><td bgcolor=#ffff00><img src=$IconPathName/tcp.png>\&nbsp;domain-tcp</td>";  # svc
	print DUMPFILE "<td bgcolor=#ffff00><img src=$IconPathName/accept.png>\&nbsp;accept</td><td bgcolor=#ffff00> &nbsp; </td><td bgcolor=#ffff00><img src=$IconPathName/any.png>\&nbsp;Any</td><td bgcolor=#ffff00><img src=$IconPathName/gateways.png>\&nbsp;Gateways</td><td bgcolor=#ffff00>Implicit rule:  Enable Domain-TCP </td><\/tr>\n";
    }
# domain UDP
    if ( ("$prop_setting{'domain_udp'}" eq 'true') &&
         (lc("$prop_setting{'domain_udp_p'}") eq "$locstr") ) {
	print DUMPFILE '<tr><td bgcolor=#ffff00> &nbsp; </td>';
	print DUMPFILE "<td bgcolor=#ffff00><img src=$IconPathName/any.png>\&nbsp;Any</td><td bgcolor=#ffff00><img src=$IconPathName/any.png>\&nbsp;Any</td><td bgcolor=#ffff00><img src=$IconPathName/udp.png>\&nbsp;domain-udp</td>";  # svc
	print DUMPFILE "<td bgcolor=#ffff00><img src=$IconPathName/accept.png>\&nbsp;accept</td><td bgcolor=#ffff00> &nbsp; </td><td bgcolor=#ffff00><img src=$IconPathName/any.png>\&nbsp;Any</td><td bgcolor=#ffff00><img src=$IconPathName/gateways.png>\&nbsp;Gateways</td><td bgcolor=#ffff00>Implicit rule: Enable Domain-UDP </td><\/tr>\n";
    }
  }
}


##########################################################################
# print configuration into HTML file
#	filename for the resulting file

sub Output_in_HTML {
    my ($filename)     = $_[0];
    my ($name)         = '';
    my ($linkto)       = '';
    my ($printcomment) = '';

    open (DUMPFILE,">$filename") ;
    print DUMPFILE '<html><head>'; print DUMPFILE "\n";

    print DUMPFILE '<style type="text/css">'; print DUMPFILE "\n";
    print DUMPFILE "<!--\n";

    if (!defined($optctl{'use-css'})) {
		$HTMLcssfile = dirname ($0)."/$HTMLcssfile";
    }

    open (CSS, "$HTMLcssfile") || warn "Could not open $HTMLcssfile";
    while (<CSS>) {
		print DUMPFILE $_;
    }
    close (CSS);

    print DUMPFILE "-->\n";
    print DUMPFILE "</style>\n";

    print DUMPFILE "<title>$HTMLtitle $HTMLtitle_ext</title>\n";
    print DUMPFILE '</head>'; print DUMPFILE "\n";
    print DUMPFILE '<body>'; print DUMPFILE "\n";
    print DUMPFILE '<h2>Firewall Policy: ';
    print DUMPFILE "$HTMLtitle";
    print DUMPFILE '</h2>'; print DUMPFILE "\n";
	print DUMPFILE "<b>$HTMLmatch</b>\n\n";
    if ( ! $FLAG_norules ) {
      print DUMPFILE '<table border=1 cellpadding=5 cellspacing=1>'; print DUMPFILE "\n";
      print DUMPFILE '<tr><th>RULE</th><th>SOURCE</th><th>DESTINATION</th><th>SERVICES</th><th>ACTION</th><th>TRACK</th><th>TIME</th><th>INSTALL ON</th><th>COMMENTS</th></tr>'; print DUMPFILE "\n";
      print DUMPFILE '<!---+++++++++++++++++++++++++++++++++++++++++++++--->'; print DUMPFILE "\n";
      for ( $i = 0; $i<=$access_number; $i++ ) {
	if ( $i == 0 ){
	    subImplicit__Output_in_HTML (DUMPFILE, 'first');
	} elsif ( $i == $access_number ){
	    subImplicit__Output_in_HTML (DUMPFILE, 'before last');
	}
	if ( ! $access_unmatched[$i]) {
	    if ( $access_header[$i] ) {
		print DUMPFILE "\n<tr style=\"background-color: #FFFF00\">";
		print DUMPFILE '<td></td><td class=header colspan=8>';
		print DUMPFILE "<font size=+1>$access_header[$i]</font>";
		print DUMPFILE '&nbsp;</td></tr>'."\n";
	    }
	    print DUMPFILE "\n<!------- Rule $i ------->\n";
            my $bgcolr = ($i % 2) ? '#ffffff' : '#eeeeee';
	    print DUMPFILE "<tr style=\"background-color: $bgcolr\">";
	    if ( $access_disabled[$i] ) {
		print DUMPFILE '<td class=disabled>';
		print DUMPFILE $i+1;
	    	print DUMPFILE '<BR><BR>DIS-<BR>ABLED</td>';
	    } else {
		print DUMPFILE '<td class=normal>';
		print DUMPFILE $i+1;
		print DUMPFILE '</td>';
	    }
	    print DUMPFILE '<td>';
	    if($access_from[$i]=~/@/) {
		&subUserObject__Output_in_HTML (DUMPFILE, $access_from_negated[$i], $access_from[$i]);
	    } else {
		&subObject__Output_in_HTML (DUMPFILE, $access_from_negated[$i], $access_from[$i]);
	    }

	    print DUMPFILE '<td>';
	    &subObject__Output_in_HTML (DUMPFILE, $access_to_negated[$i], $access_to[$i]);
	    print DUMPFILE '</td>';

	    print DUMPFILE '<td>';
	    &subService__Output_in_HTML (DUMPFILE, $access_services_negated[$i], $access_services[$i]);
	    print DUMPFILE '</td>';

	    print DUMPFILE '<td>';
	    print DUMPFILE "\<img src=$IconPathName/$access_action[$i].png\>\&nbsp;$access_action[$i]";
	    # print out client auth properties in 'action' column
	    if($access_action[$i] eq "clientauth"){
		print DUMPFILE "<br>t : $access_clauth_to[$i] min";
		print DUMPFILE "<br>s : $access_sessions_value[$i]";
	    }
	    print DUMPFILE '</td>';

	    print DUMPFILE '<td>';
	    if ( "$access_track[$i]" ne '' ){
		($name = lc("$access_track[$i].png")) =~ s/\s//g;
		print DUMPFILE "\<img src=$IconPathName/$name\>\&nbsp;$access_track[$i]";
	    }
	    print DUMPFILE '&nbsp;</td>';

	    print DUMPFILE '<td>';
	    #----- unclean, but we don't have TIME objects handled yet.
	    #----- so we do the type handling manually here.
	    if ( lc("$access_time[$i]") eq 'any' ) {
		print DUMPFILE "\<img src=$IconPathName/any.png\>\&nbsp;Any<br>";
	    } else{
		print DUMPFILE "\<img src=$IconPathName/timeobject.png\>\&nbsp;$access_time[$i]<br>";
	    }
	    print DUMPFILE '&nbsp;</td>';

	    print DUMPFILE '<td>';
	    &subObject__Output_in_HTML (DUMPFILE, 0, $access_install_on[$i]);
	    print DUMPFILE '&nbsp;</td>';

    	    #----- comments - with the "LinkTo" mechanism
	    print DUMPFILE '<td>';
 	    $printcomment="$access_comment[$i]";
	    if ( ($FLAG_linkto) && ($access_comment[$i]=~/\[(..*)\]/) ) {
	        $linkto = "$LinkToDIR/$1";
		if ( -f "$linkto.html" ) {
	 	    $printcomment =~ s/\[(..*)\]/<a href=$linkto.html>\[$1\]<\/a>/;
		}
		if ( -f "$linkto.pdf" ) {
	 	    $printcomment =~ s/\[(..*)\]/<a href=$linkto.pdf>\[$1\]<\/a>/;
		}
	    }
	    print DUMPFILE "$printcomment";
	    print DUMPFILE '&nbsp;</td></tr>';
	    print DUMPFILE "\n";
	}
      }
      subImplicit__Output_in_HTML (DUMPFILE, 'last');
      print DUMPFILE '<!--------------------------------------------------->'; print DUMPFILE "\n";
      print DUMPFILE '</table><p>'; print DUMPFILE "\n";
      print DUMPFILE ''; print DUMPFILE "\n";
      print DUMPFILE '<p>&nbsp;<p>'; print DUMPFILE "\n";
      print DUMPFILE '<h3>Address Translation Rules</h3>'; print DUMPFILE "\n";
      print DUMPFILE '<table border=1 cellpadding=5 cellspacing=1><tr><th rowspan=2>RULE</th><th colspan=3>ORIGINAL PACKET</th><th colspan=3>TRANSLATED PACKET</th><th rowspan=2>INSTALL ON</th><th rowspan=2>COMMENT</th></tr>'; print DUMPFILE "\n";
      print DUMPFILE '<tr><th>SOURCE</th><th>DESTINATION</th><th>SERVICE</th><th>SOURCE</th><th>DESTINATION</th><th>SERVICE</th></tr>'; print DUMPFILE "\n";
      print DUMPFILE '<!---+++++++++++++++++++++++++++++++++++++++++++++--->'; print DUMPFILE "\n";
      #--- first the explicit ones ---
      for ( $i = 0; $i<=$nat_number; $i++ ) {
	if ( ! $nat_unmatched[$i]) {
	    print DUMPFILE "\n<!------- NAT $i ------->\n";
            my $bgcolr = ($i % 2) ? '#ffffff' : '#eeeeee';
	    print DUMPFILE "<tr style=\"background-color: $bgcolr\">";
	    if ( $nat_disabled[$i] ) {
		print DUMPFILE '<td class=disabled>';
		print DUMPFILE $i+1;
	    	print DUMPFILE '<BR><BR>DIS-<BR>ABLED</td><td>';
	    } else {
		print DUMPFILE '<td class=normal>';
		print DUMPFILE $i+1;
		print DUMPFILE '</td><td>';
	    }
	    &subObject__Output_in_HTML (DUMPFILE, 0, $nat_orig_from[$i]);
	    DebugLog("NAT: $nat_orig_from[$i] - Typ $obj_type{$nat_orig_from[$i]}");
	    print DUMPFILE '</td><td>';
	    &subObject__Output_in_HTML (DUMPFILE, 0, $nat_orig_to[$i]);
	    print DUMPFILE '</td><td>';
	    &subService__Output_in_HTML (DUMPFILE, 0, $nat_orig_svc[$i]);
	    print DUMPFILE '</td><td>';
	    if ( $nat_transl_from_methd[$i] ) { print DUMPFILE 'S: '; } else { print DUMPFILE 'H: '; }
	    &subObject__Output_in_HTML (DUMPFILE, 0, $nat_transl_from[$i]);
	    print DUMPFILE '</td><td>';
	    if ( $nat_transl_from_methd[$i] ) { print DUMPFILE 'S: '; } else { print DUMPFILE 'H: '; }
	    &subObject__Output_in_HTML (DUMPFILE, 0, $nat_transl_to[$i]);
	    print DUMPFILE '</td><td>';
	    if ( $nat_transl_from_methd[$i] ) { print DUMPFILE 'S: '; } else { print DUMPFILE 'H: '; }
	    &subService__Output_in_HTML (DUMPFILE, 0, $nat_transl_svc[$i]);
	    print DUMPFILE '</td><td>';
	    &subObject__Output_in_HTML (DUMPFILE, 0, $nat_install_on[$i]);
    	    print DUMPFILE "\</td\>";
    	    #----- comments - with the "LinkTo" mechanism
	    print DUMPFILE '<td>';
 	    $printcomment="$nat_comment[$i]";
	    if ( ($FLAG_linkto) && ($nat_comment[$i]=~/\[(..*)\]/) ) {
	        $linkto = "$LinkToDIR/$1";
		if ( -f "$linkto.html" ) {
	 	    $printcomment =~ s/\[(..*)\]/<a href=$linkto.html>\[$1\]<\/a>/;
		}
		if ( -f "$linkto.pdf" ) {
	 	    $printcomment =~ s/\[(..*)\]/<a href=$linkto.pdf>\[$1\]<\/a>/;
		}
	    }
	    print DUMPFILE "$printcomment\&nbsp;\</td\>\</tr\>\n";
	}
      }
      #--- now the implicit ones ---
      if ( $FLAG_implicitrules ) {
	foreach $name (@obj_name){
	    if ( ( $obj_used{$name} || $FLAG_allobjs ) &&
	         ( "$obj_NATadr{$name}" ne '' ) ) {
		#--- forward rule
	        $i++;
		print DUMPFILE "\n<!------- implicit NAT forward $i ------->\n";
		print DUMPFILE '<tr><td bgcolor=#ffff00 align=center valign=middle><B>';
		print DUMPFILE $i;
		print DUMPFILE '</B></td><td bgcolor=#ffff00>';
		&subObject__Output_in_HTML (DUMPFILE, 0, $name);
		print DUMPFILE '</td>';
		print DUMPFILE "\<td bgcolor=#ffff00\>\<img src=$IconPathName/any.png\>\&nbsp;Any\</td\>";
		print DUMPFILE "\<td bgcolor=#ffff00\>\<img src=$IconPathName/any.png\>\&nbsp;Any\</td\>";
		print DUMPFILE '<td bgcolor=#ffff00>';
		if ( $obj_NATtype{$name} ) { print DUMPFILE 'S: '; } else { print DUMPFILE 'H: '; }
		print DUMPFILE "$obj_NATadr{$name}";
		print DUMPFILE '</td>';
		print DUMPFILE "\<td bgcolor=#ffff00\>\<img src=$IconPathName/any.png\>\&nbsp;Original\</td\>";
		print DUMPFILE "\<td bgcolor=#ffff00\>\<img src=$IconPathName/any.png\>\&nbsp;Original\</td\>";
		print DUMPFILE '<td bgcolor=#ffff00>&nbsp;</td>';
		print DUMPFILE "\<td bgcolor=#ffff00\>\(implicit rule set in object definition\)\</td\>\</tr\>\n";
		#--- backward rule
	        $i++;
		print DUMPFILE "\n<!------- implicit NAT backward $i ------->\n";
		print DUMPFILE '<tr><td bgcolor=#ffff00 align=center valign=middle><B>';
		print DUMPFILE $i;
		print DUMPFILE '</B></td>';
		print DUMPFILE "\<td bgcolor=#ffff00\>\<img src=$IconPathName/any.png\>\&nbsp;Any\</td\>";
		print DUMPFILE '<td bgcolor=#ffff00>';
		&subObject__Output_in_HTML (DUMPFILE, 0, $name);
		print DUMPFILE '</td>';
		print DUMPFILE "\<td bgcolor=#ffff00\>\<img src=$IconPathName/any.png\>\&nbsp;Any\</td\>";
		print DUMPFILE "\<td bgcolor=#ffff00\>\<img src=$IconPathName/any.png\>\&nbsp;Original\</td\>";
		print DUMPFILE '<td bgcolor=#ffff00>';
		if ( $obj_NATtype{$name} ) { print DUMPFILE 'S: '; } else { print DUMPFILE 'H: '; }
		print DUMPFILE "$obj_NATadr{$name}";
		print DUMPFILE '</td>';
		print DUMPFILE "\<td bgcolor=#ffff00\>\<img src=$IconPathName/any.png\>\&nbsp;Original\</td\>";
		print DUMPFILE "\<td bgcolor=#ffff00\>\&nbsp;\</td\>\<td bgcolor=#ffff00\>\(implicit rule set in object definition\)\</td\>\</tr\>\n";
	    }
	}
      }
      print DUMPFILE '<!--------------------------------------------------->'; print DUMPFILE "\n";
      print DUMPFILE '</table>'; print DUMPFILE "\n";
      print DUMPFILE '<br>LEGEND:  Address Translation Methods: S: Static, H: Hide<p>'; print DUMPFILE "\n";
      print DUMPFILE '<p>&nbsp;<p>'; print DUMPFILE "\n";
    }
    if ( ! $FLAG_noobjs ) {
      print DUMPFILE ''; print DUMPFILE "\n";
      print DUMPFILE '<h2>FireWall-1 Object Definitions</h2>'; print DUMPFILE "\n";
      print DUMPFILE ''; print DUMPFILE "\n";
      print DUMPFILE '<h3>Network Objects</h3>'; print DUMPFILE "\n";
      print DUMPFILE '<table border=1 cellpadding=5 cellspacing=1><tr><th>Name</th><th>Type</th><th>Location</th><th>FW-1</th><th>IP Address</th><th>Netmask</th><th>NAT Address</th><th>Members</th><th>Comment</th></tr>'; print DUMPFILE "\n";
      print DUMPFILE '<!---+++++++++++++++++++++++++++++++++++++++++++++--->'; print DUMPFILE "\n";
      $i = 0;
      foreach $name (@obj_name){
	if ( $obj_used{$name} || $FLAG_allobjs ) {
	    print DUMPFILE "\n<!------- Object $name ------->\n";
            my $bgcolr = ($i % 2) ? '#ffffff' : '#eeeeee';
	    $i += 1;
	    print DUMPFILE "<tr style=\"background-color: $bgcolr\">";
	    print DUMPFILE '<td><a NAME="OBJ_';
	    print DUMPFILE "$name";
	    print DUMPFILE '"></a>';
	    print DUMPFILE "$name\</td\>\<td\>";
	    print DUMPFILE "\<img src=$IconPathName/$obj_type{$name}.png\>\&nbsp;$obj_type{$name}";
	    print DUMPFILE '</td><td>';
	    if ( $obj_location{$name} ) {
		print DUMPFILE 'External</td><td>';
	    } else {
		print DUMPFILE 'Internal</td><td>';
	    }
	    if ( $obj_is_fw1{$name} ) {
		print DUMPFILE 'Yes</td><td>';
	    } else {
		print DUMPFILE 'No</td><td>';
	    }
	    &PrintOrDash(DUMPFILE,$obj_ipaddr{$name});
	    print DUMPFILE '</td><td>';
	    &PrintOrDash(DUMPFILE,$obj_netmask{$name});
	    print DUMPFILE '</td><td>';
            if ( "$obj_NATadr{$name}" ne '' ) {
		if ( $obj_NATtype{$name} ) {
 			print DUMPFILE 'S:';
		} else {
			print DUMPFILE 'H:';
 		}
                print DUMPFILE '&nbsp;';
                print DUMPFILE "$obj_NATadr{$name}";
 	    } else {
                print DUMPFILE '-';
            }
 	    print DUMPFILE '</td><td>';
	    if ( "$obj_members{$name}" eq '' ) {
		# If the type is not 'group_with_exclusion', prints out a blank space.
		if($obj_type{$name} ne "group_with_exclusion"){
			print DUMPFILE '&nbsp;';
		# If the type is 'group_with_exclusion', prints out 'base_member except exception_member'.
		}else{
			&subObject__Output_in_HTML (DUMPFILE, 0, $obj_members_base{$name});
			print DUMPFILE "except<br>";
			&subObject__Output_in_HTML (DUMPFILE, 0, $obj_members_exception{$name});
		}
	    } else {
		&subObject__Output_in_HTML (DUMPFILE, 0, $obj_members{$name});
	    }
	    print DUMPFILE "\</td\>\<td\>$obj_comment{$name}&nbsp;\</td\></tr>\n";
	    if ( $FLAG_withinterface && ( $obj_if_number{$name} > 0)) {
		for ($k = 1; $k <= $obj_if_number{$name}; $k++) {
		    	$ref = "NIC$k\.$name";
			print DUMPFILE "<tr style=\"background-color: $bgcolr\">";
			print DUMPFILE '<td>';
			print DUMPFILE "\<img src=$IconPathName/interface.png\>\&nbsp;";
			print DUMPFILE "$name \. $obj_if_name{$ref}\</td\>\<td\>";
			print DUMPFILE '</td><td>';
			print DUMPFILE '</td><td>';
			print DUMPFILE '</td><td>';
			&PrintOrDash(DUMPFILE,$obj_if_ipaddr{$ref});
			print DUMPFILE '</td><td>';
		    	&PrintOrDash(DUMPFILE,$obj_if_netmask{$ref});
			print DUMPFILE '</td><td>';
			print DUMPFILE '</td><td>';
			print DUMPFILE '</td><td>';
			# print out anti-spoofing setting for this interface as a comment.
			if ( $FLAG_withantispoofing ) {
			    print DUMPFILE "Antispoofing: ";
			    if($obj_if_spoof{$ref} eq ""){
				print DUMPFILE "Any<br>";
			    }elsif($obj_if_spoof{$ref} eq "Others" || $obj_if_spoof{$ref} eq "ThisNet"){
				print DUMPFILE $obj_if_spoof{$ref} . "<br>";
			    }elsif($obj_if_spoof{$ref} =~ /^Others \+ /){
				$obj_if_spoof{$ref} =~ s/^Others \+ //;
				print DUMPFILE "Others + ";
				&subObject__Output_in_HTML (DUMPFILE, 0, $obj_if_spoof{$ref});
			    }else{
				&subObject__Output_in_HTML (DUMPFILE, 0, $obj_if_spoof{$ref});
			    }
			}
			print DUMPFILE "\</td\></tr>\n";
		    }
	    }
	}
      }
      print DUMPFILE '<!--------------------------------------------------->'; print DUMPFILE "\n";
      print DUMPFILE '</table>'; print DUMPFILE "\n";
      print DUMPFILE '<br>LEGEND:  Address Translation Methods: S: Static, H: Hide<p>'; print DUMPFILE "\n";
    }
    if ( ! $FLAG_noservices ) {
      print DUMPFILE ''; print DUMPFILE "\n";
      print DUMPFILE '<p>'; print DUMPFILE "\n";
      print DUMPFILE '<h3>Service Objects</h3>'; print DUMPFILE "\n";
      print DUMPFILE '<table border=1 cellpadding=5 cellspacing=1><tr><th>Name</th><th>Type</th><th>Port/<br>Program</th><th>S_Port from</th><th>S_Port to:</th><th>Match</th><th>Prolog</th><th>Members</th><th>Comment</th></tr>'; print DUMPFILE "\n";
      print DUMPFILE '<!---+++++++++++++++++++++++++++++++++++++++++++++--->'; print DUMPFILE "\n";
      $i = 0;
      foreach $name (@svc_name){
	if ( $svc_used{$name} || $FLAG_allservices ) {
	    print DUMPFILE "\n<!------- Service $name ------->\n";
            my $bgcolr = ($i % 2) ? '#ffffff' : '#eeeeee';
	    $i += 1;
	    print DUMPFILE "<tr style=\"background-color: $bgcolr\">";
	    print DUMPFILE '<td><a NAME="SVC_';
	    print DUMPFILE "$name";
	    print DUMPFILE '"></a>';
	    print DUMPFILE "$name";
	    print DUMPFILE '</td><td>';
	    print DUMPFILE "\<img src=$IconPathName/$svc_type{$name}.png\>\&nbsp;$svc_type{$name}";
	    print DUMPFILE '</td><td>';
	    &PrintOrDash(DUMPFILE,$svc_dst_port{$name});
	    print DUMPFILE '</td><td>';
	    &PrintOrDash(DUMPFILE,$svc_src_low{$name});
	    print DUMPFILE '</td><td>';
	    &PrintOrDash(DUMPFILE,$svc_src_high{$name});
	    print DUMPFILE '</td><td>';
	    &PrintOrDash(DUMPFILE,$svc_match{$name});
	    print DUMPFILE '</td><td>';
	    &PrintOrDash(DUMPFILE,$svc_prolog{$name});
	    print DUMPFILE '</td><td>';
	    if ( "$svc_members{$name}" eq '' ) {
		print DUMPFILE '&nbsp;';
	    } else {
		&subService__Output_in_HTML (DUMPFILE, 0, $svc_members{$name});
	    }
	    print DUMPFILE "\</td\>\<td\>$svc_comment{$name}&nbsp;\</td\></tr>\n";
	}
      }
      print DUMPFILE '<!--------------------------------------------------->'; print DUMPFILE "\n";
      print DUMPFILE '</table>'; print DUMPFILE "\n";
    }
    if ( ! $FLAG_noservers ) {
      print DUMPFILE ''; print DUMPFILE "\n";
      print DUMPFILE '<p>'; print DUMPFILE "\n";
      print DUMPFILE '<h3>Server Objects</h3>'; print DUMPFILE "\n";
      print DUMPFILE '<table border=1 cellpadding=5 cellspacing=1><tr><th>Name</th><th>Type</th><th>Priority</th><th>Reference</th><th>Version</th><th>Members</th><th>Comment</th></tr>'; print DUMPFILE "\n";
      print DUMPFILE '<!---+++++++++++++++++++++++++++++++++++++++++++++--->'; print DUMPFILE "\n";
      $i = 0;
      foreach $name (@srv_name){
	    print DUMPFILE "\n<!------- Server $name ------->\n";
          my $bgcolr = ($i % 2) ? '#ffffff' : '#eeeeee';
	    $i += 1;
	    print DUMPFILE "<tr style=\"background-color: $bgcolr\">";
	    print DUMPFILE '<td><a NAME="';
	    print DUMPFILE "$name";
	    print DUMPFILE '"></a>';
	    print DUMPFILE "$name";
	    print DUMPFILE '</td><td>';
	    print DUMPFILE "\<img src=$IconPathName/$srv_type{$name}.png\>\&nbsp;$srv_type{$name}";
	    print DUMPFILE '</td><td>';
	    print DUMPFILE "$srv_priority{$name}";
	    print DUMPFILE '</td><td>';
	    print DUMPFILE "$srv_reference{$name}";
	    print DUMPFILE '</td><td>';
	    print DUMPFILE "$srv_version{$name}";
	    print DUMPFILE '</td><td>';
	    if ( "$srv_members{$name}" eq '' ) {
		print DUMPFILE '&nbsp;';
	    } else {
		&subObject__Output_in_HTML (DUMPFILE, 0, $srv_members{$name});
	    }
	    print DUMPFILE "\</td\>\<td\>$srv_comment{$name}&nbsp;\</td\></tr>\n";
      }
      print DUMPFILE '<!--------------------------------------------------->'; print DUMPFILE "\n";
      print DUMPFILE '</table>'; print DUMPFILE "\n";
    }
    if ( ! $FLAG_nousers ) {
      print DUMPFILE ''; print DUMPFILE "\n";
      print DUMPFILE '<p>'; print DUMPFILE "\n";
      print DUMPFILE '<h3>User Objects</h3>'; print DUMPFILE "\n";
      print DUMPFILE '<table border=2 cellpadding=5><tr><th>Name</th><th>Type</th><th>From</th><th>To</th><th>Auth</th><th>Day</th><th>Expires</th><th>Members</th><th>Comment</th></tr>'; print DUMPFILE "\n";
      print DUMPFILE '<!---+++++++++++++++++++++++++++++++++++++++++++++--->'; print DUMPFILE "\n";
      foreach $name (@user_name){
	next if($name =~ /^ *$/);
	next if($name =~ /All Users/);
	next if($name =~ /ALL_GROUPS/);
	next if($name =~ /ALL_KEYH/);
	next if($name =~ /ALL_TEMPLATES/);
	next if($user_type{$name} =~ /keyh/);
	next if($user_type{$name} =~ /template/);
	if ( $user_used{$name} || $FLAG_alluser ) {
	   print DUMPFILE "\n<!------- User $name ------->\n";
	   print DUMPFILE '<tr><td><a NAME="';
	   print DUMPFILE "$name";
	   print DUMPFILE '"></a>';
	   print DUMPFILE "$name";
	   print DUMPFILE '</td><td>';
	   print DUMPFILE "\<img src=$IconPathName/$user_type{$name}.png\>\&nbsp;$user_type{$name}";
	   print DUMPFILE '</td><td>';
	   &PrintOrDash(DUMPFILE,$user_from{$name});
	   print DUMPFILE '</td><td>';
	   &PrintOrDash(DUMPFILE,$user_to{$name});
	   print DUMPFILE '</td><td>';
	   &PrintOrDash(DUMPFILE,$user_auth{$name});
	   print DUMPFILE '</td><td>';
	   &PrintOrDash(DUMPFILE,$user_day{$name});
	   print DUMPFILE '</td><td>';
	   &PrintOrDash(DUMPFILE,$user_expires{$name});
	   print DUMPFILE '</td><td>';
	   if ( "$user_members{$name}" eq '' ) {
	       print DUMPFILE '&nbsp;';
	   } else {
	       &subUser__Output_in_HTML (DUMPFILE, $user_members{$name});
	   }
	   print DUMPFILE "\</td\>\<td\>$user_comment{$name}&nbsp;\</td\></tr>\n";
	}
      }
      print DUMPFILE '<!--------------------------------------------------->'; print DUMPFILE "\n";
      print DUMPFILE '</table>'; print DUMPFILE "\n";
      print DUMPFILE ''; print DUMPFILE "\n";
    }
    print DUMPFILE '<p>&nbsp;<p>'; print DUMPFILE "\n";
    print DUMPFILE '<h3>Property Settings</h3>'; print DUMPFILE "\n";
    print DUMPFILE '<!---+++++++++++++++++++++++++++++++++++++++++++++--->'; print DUMPFILE "\n";
    print DUMPFILE "<h4>Security Policy</h4><table border=2 cellpadding=5><tr><th>Property</th><th>Setting</th><th>Value</th></tr>\n";
    print DUMPFILE "<tr><td>Apply Gateway Rules to Interface Direction</td><td>&nbsp;</td><td>$prop_setting{'gatewaydir'}&nbsp;</td></tr>\n";
    print DUMPFILE "<tr><td>TCP Session Timeout (sec)</td><td>&nbsp;</td><td>$prop_setting{'tcptimeout'}&nbsp;</td></tr>\n";
    print DUMPFILE "<tr><td>Accept Firewall-1 Control Connections</td><td>$prop_setting{'fw1enable'}&nbsp;</td><td>$prop_setting{'fw1enable_p'}&nbsp;</td></tr>\n";
    print DUMPFILE "<tr><td>Accept UDP Replies</td><td>&nbsp;</td><td>$prop_setting{'udpreply'}&nbsp;</td></td></tr>\n";
    print DUMPFILE "<tr><td>UDP Reply Timeout (sec)</td><td>&nbsp;</td><td>$prop_setting{'udptimeout'}&nbsp;</td></tr>\n";
    print DUMPFILE "<tr><td>Accept Outgoing Packets</td><td>$prop_setting{'outgoing'}&nbsp;</td><td>$prop_setting{'outgoing_p'}&nbsp;</td></tr>\n";
    print DUMPFILE "<tr><td>Enable Decryption on Accept</td><td>&nbsp;</td><td>$prop_setting{'acceptdecrypt'}&nbsp;</td></tr>\n";
    print DUMPFILE "<tr><td>Use FASTPATH</td><td>&nbsp;</td><td>$prop_setting{'enable_fastpath'}&nbsp;</td></tr>\n";
    print DUMPFILE "<tr><td>Accept RIP</td><td>$prop_setting{'rip'}&nbsp;</td><td>$prop_setting{'rip_p'}&nbsp;</td></tr>\n";
    print DUMPFILE "<tr><td>Accept Domain Name Queries (UDP)</td><td>$prop_setting{'domain_udp'}&nbsp;</td><td>$prop_setting{'domain_udp_p'}&nbsp;</td></tr>\n";
    print DUMPFILE "<tr><td>Accept Domain Name Download (TCP)</td><td>$prop_setting{'domain_tcp'}&nbsp;</td><td>$prop_setting{'domain_tcp_p'}&nbsp;</td></tr>\n";
    print DUMPFILE "<tr><td>Accept ICMP</td><td>$prop_setting{'icmpenable'}&nbsp;</td><td>$prop_setting{'icmpenable_p'}&nbsp;</td></tr>\n";
    print DUMPFILE "</table>\n";
    print DUMPFILE "<h4>Services</h4><table border=2 cellpadding=5><tr><th>Property</th><th>Setting</th><th>Value</th></tr>\n";
    print DUMPFILE "<tr><td>Enable FTP PASV Connections:</td><td>$prop_setting{'ftppasv'}&nbsp;</td><td>$prop_setting{'ftppasv_p'}&nbsp;</td></tr>\n";
    print DUMPFILE "<tr><td>Enable RSH/REXEC Reverse stderr Connections</td><td>$prop_setting{'rshstderr'}&nbsp;</td><td>$prop_setting{'rshstderr_p'}&nbsp;</td></tr>\n";
    print DUMPFILE "<tr><td>Enable RPC Control</td><td>$prop_setting{'rpcenable'}&nbsp;</td><td>$prop_setting{'rpcenable_p'}&nbsp;</td></tr>\n";
    print DUMPFILE "<tr><td>Enable Response of FTP Data Connections:</td><td>$prop_setting{'ftpdata'}&nbsp;</td><td>$prop_setting{'ftpdata_p'}&nbsp;</td></tr>\n";
    print DUMPFILE "<tr><td>Enable Real Audio Reverse Connections:</td><td>$prop_setting{'raudioenable'}&nbsp;</td><td>$prop_setting{'raudioenable_p'}&nbsp;</td></tr>\n";
    print DUMPFILE "<tr><td>Enable VDOLive Reverse Connections</td><td>$prop_setting{'vdolivenable'}&nbsp;</td><td>$prop_setting{'vdolivenable_p'}&nbsp;</td></tr>\n";
    print DUMPFILE "<tr><td>Enable CoolTalk Data Connections (UDP)</td><td>$prop_setting{'cooltalkenable'}&nbsp;</td><td>&nbsp;</td></tr>\n";
    print DUMPFILE "<tr><td>Enable H.323 Control and Data Connections</td><td>$prop_setting{'iphoneenable'}&nbsp;</td><td>&nbsp;</td></tr>\n";
    print DUMPFILE "</table>\n";
    print DUMPFILE "<h4>Log and Alert</h4><table border=2 cellpadding=5><tr><th>Property</th><th>Setting</th></tr>\n";
    print DUMPFILE "<tr><td>Excessive Log Grace Period (sec)</td><td>$prop_setting{'loggrace'}&nbsp;</td></tr>\n";
    print DUMPFILE "<tr><td>PopUp Alert Command</td><td>$prop_setting{'alertcmd'}&nbsp;</td></tr>\n";
    print DUMPFILE "<tr><td>Mail Alert Command</td><td>$prop_setting{'mailcmd'}&nbsp;</td></tr>\n";
    print DUMPFILE "<tr><td>SNMP Trap Alert Command</td><td>$prop_setting{'snmptrapcmd'}&nbsp;</td></tr>\n";
    print DUMPFILE "<tr><td>User Defined Alert Command</td><td>$prop_setting{'useralertcmd'}&nbsp;</td></tr>\n";
    print DUMPFILE "<tr><td>Anti Spoof Alert Command</td><td>$prop_setting{'spoofalertcmd'}&nbsp;</td></tr>\n";
    print DUMPFILE "<tr><td>User Authentication Alert Command</td><td>$prop_setting{'userauthalertcmd'}&nbsp;</td></tr>\n";
    print DUMPFILE "<tr><td>Log Established TCP Packets</td><td>$prop_setting{'log_established_tcp'}&nbsp;</td></tr>\n";
    print DUMPFILE "<tr><td>Enable Active Connections</td><td>$prop_setting{'liveconns'}&nbsp;</td></tr>\n";
    print DUMPFILE "</table>\n";
    print DUMPFILE "<h4>Resolving</h4><table border=2 cellpadding=5><tr><th>Property</th><th>Setting</th></tr>\n";
    print DUMPFILE "<tr><td>Lookup Priorities</td><td>1. $prop_setting{'resolver_1'}<br>2. $prop_setting{'resolver_2'}<br>3. $prop_setting{'resolver_3'}<br>4. $prop_setting{'resolver_4'}&nbsp;</td></tr>\n";
    print DUMPFILE "<tr><td>BIND Timeout (sec)</td><td>$prop_setting{'timeout'}&nbsp;</td></tr>\n";
    print DUMPFILE "<tr><td>BIND Retries</td><td>$prop_setting{'retries'}&nbsp;</td></tr>\n";
    print DUMPFILE "<tr><td>Log Viewer Resolver Properties</td><td>$prop_setting{'pagetimeout'}&nbsp;</td></tr>\n";
    print DUMPFILE "</table>\n";
    print DUMPFILE "<h4>Security Servers</h4><table border=2 cellpadding=5><tr><th>Property</th><th>Setting</th></tr>\n";
    print DUMPFILE "<tr><td>Telnet Welcome Message File</td><td>$prop_setting{'telnet_msg'}&nbsp;</td></tr>\n";
    print DUMPFILE "<tr><td>Rlogin Welcome Message File</td><td>$prop_setting{'rlogin_msg'}&nbsp;</td></tr>\n";
    print DUMPFILE "<tr><td>FTP Welcome Message File</td><td>$prop_setting{'ftp_msg'}&nbsp;</td></tr>\n";
    print DUMPFILE "<tr><td>Client Authentication Welcome Message File</td><td>$prop_setting{'clnt_auth_msg'}&nbsp;</td></tr>\n";
    print DUMPFILE "<tr><td>HTTP Next Proxy</td><td>$prop_setting{'http_next_proxy_host'} : $prop_setting{'http_next_proxy_port'}&nbsp;</td></tr>\n";
    print DUMPFILE "</table>\n";
    print DUMPFILE "<h4>Authentication</h4><table border=2 cellpadding=5><tr><th>Property</th><th>Setting</th></tr>\n";
    print DUMPFILE "<tr><td>User Authentication Session Timeout (min)</td><td>$prop_setting{'au_timeout'}&nbsp;</td></tr>\n";
    print DUMPFILE "<tr><td>AXENT Pathways Defender Server Setup</td><td>Server IP: $prop_setting{'snk_server_ip'}<br>Agent ID: $prop_setting{'snk_agent_id'}<br>Agent Key: $prop_setting{'snk_agent_key'}&nbsp;</td></tr>\n";
    print DUMPFILE "</table>\n";
    print DUMPFILE "<h4>SYNDefender</h4><table border=2 cellpadding=5><tr><th>Property</th><th>Setting</th></tr>\n";
    print DUMPFILE "<tr><td>Method</td><td>$SynDefender[$prop_setting{'fwsynatk_method'}]&nbsp;</td></tr>\n";
    print DUMPFILE "<tr><td>Timeout</td><td>$prop_setting{'fwsynatk_timeout'}&nbsp;</td></tr>\n";
    print DUMPFILE "<tr><td>Maximum Sessions</td><td>$prop_setting{'fwsynatk_max'}&nbsp;</td></tr>\n";
    print DUMPFILE "<tr><td>Display Warning Messages</td><td>$prop_setting{'fwsynatk_warning'}&nbsp;</td></tr>\n";
    print DUMPFILE "</table>\n";
    print DUMPFILE "<h4>Miscellaneous</h4><table border=2 cellpadding=5><tr><th>Property</th><th>Setting</th></tr>\n";
    print DUMPFILE "<tr><td>Load Agents Port</td><td>$prop_setting{'load_service_port'}&nbsp;</td></tr>\n";
    print DUMPFILE "<tr><td>Load Measurement Interval</td><td>$prop_setting{'lbalanced_period_wakeup_sec'}&nbsp;</td></tr>\n";
    print DUMPFILE "</table>\n";
    print DUMPFILE "<h4>Access Lists</h4><table border=2 cellpadding=5><tr><th>Property</th><th>Setting</th><th>Value</th></tr>\n";
    print DUMPFILE "<tr><td>Accept Established TCP Connections</td><td>$prop_setting{'established'}&nbsp;</td><td>$prop_setting{'established_p'}&nbsp;</td></tr>\n";
    print DUMPFILE "<tr><td>Accept RIP</td><td>$prop_setting{'rip'}&nbsp;</td><td>$prop_setting{'rip_p'}&nbsp;</td></tr>\n";
    print DUMPFILE "<tr><td>Accept Domain Name Queries (UDP)</td><td>$prop_setting{'domain_udp'}&nbsp;</td><td>$prop_setting{'domain_udp_p'}&nbsp;</td></tr>\n";
    print DUMPFILE "<tr><td>Accept Domain Name Download (TCP)</td><td>$prop_setting{'domain_tcp'}&nbsp;</td><td>$prop_setting{'domain_tcp_p'}&nbsp;</td></tr>\n";
    print DUMPFILE "<tr><td>Accept ICMP</td><td>$prop_setting{'icmpenable'}&nbsp;</td><td>$prop_setting{'icmpenable_p'}&nbsp;</td></tr>\n";
    print DUMPFILE "</table>\n";
    print DUMPFILE '<!--------------------------------------------------->'; print DUMPFILE "\n";
    print DUMPFILE ''; print DUMPFILE "\n";
    print DUMPFILE ''; print DUMPFILE "\n";
    print DUMPFILE '<!------------------------>'; print DUMPFILE "\n";
    print DUMPFILE '<p><hr>'; print DUMPFILE "\n";
    $now = localtime();
    print DUMPFILE "Generated: \n\t$now\n\tby $SCR_NAME \($VERSION\)\n";
    print DUMPFILE '</body>'; print DUMPFILE "\n";
    print DUMPFILE '</html>'; print DUMPFILE "\n";
    close (DUMPFILE);
}


##########################################################################
### filling template stuff					       ###
##########################################################################

##########################################################################
# print implicit rules into template
#	file handle
#	location id ( first / "before last" / last )
#	template to be filled
sub subImplicit__Replace {
    my ($OUTFILE)      = $_[0];
    my ($locstr)       = $_[1];
    my ($safeline)     = $_[2];
    my ($sline)        = '';
    my ($line)         = '';

    $safeline =~ s/<<<action>>>/accept/g;
    $safeline =~ s/<<<track>>>//g;
    $safeline =~ s/<<<time>>>/Any/g;
    $safeline =~ s/<<<installon>>>/Gateways/g;
    $line = $safeline;
    if ( ("$prop_setting{'fw1enable'}" eq 'true') &&
         (lc("$prop_setting{'fw1enable_p'}") eq "$locstr") ) {
	$sline = $safeline;
	$sline =~ s/<<<comment>>>/Implicit rule: Enable FW1/g;
	# FW1
	$line = $sline;
	$line =~ s/<<<rule>>>/(implicit)/g;
	$line =~ s/<<<from>>>/FW1 Host/g;
	$line =~ s/<<<to>>>/FW1 Host/g;
	$line =~ s/<<<service>>>/FW1/g;
	print $OUTFILE "$line\n";
	# FW1_log
	$line = $sline;
	$line =~ s/<<<rule>>>/(implicit)/g;
	$line =~ s/<<<from>>>/FW1 Host/g;
	$line =~ s/<<<to>>>/FW1 Host/g;
	$line =~ s/<<<service>>>/FW1_log/g;
	print $OUTFILE "$line\n";
	# FW1_mgmt
	$line = $sline;
	$line =~ s/<<<rule>>>/(implicit)/g;
	$line =~ s/<<<from>>>/gui_clients/g;
	$line =~ s/<<<to>>>/FW1 Management/g;
	$line =~ s/<<<service>>>/FW1_mgmt/g;
	print $OUTFILE "$line\n";
	# FW1_ela
	$line = $sline;
	$line =~ s/<<<rule>>>/(implicit)/g;
	$line =~ s/<<<from>>>/FloodGate-1 Host/g;
	$line =~ s/<<<to>>>/FW1 Management/g;
	$line =~ s/<<<service>>>/FW1_ela/g;
	print $OUTFILE "$line\n";
	# FW1_topo
	$line = $sline;
	$line =~ s/<<<rule>>>/(implicit)/g;
	$line =~ s/<<<from>>>/Any/g;
	$line =~ s/<<<to>>>/FW1 Host/g;
	$line =~ s/<<<service>>>/FW1_topo/g;
	print $OUTFILE "$line\n";
	# FW1_key
	$line = $sline;
	$line =~ s/<<<rule>>>/(implicit)/g;
	$line =~ s/<<<from>>>/Any/g;
	$line =~ s/<<<to>>>/FW1 Host/g;
	$line =~ s/<<<service>>>/FW1_key/g;
	print $OUTFILE "$line\n";
	# IKE in
	$line = $sline;
	$line =~ s/<<<rule>>>/(implicit)/g;
	$line =~ s/<<<from>>>/Any/g;
	$line =~ s/<<<to>>>/FW1 Host/g;
	$line =~ s/<<<service>>>/IKE/g;
	print $OUTFILE "$line\n";
	# IKE out
	$line = $sline;
	$line =~ s/<<<rule>>>/(implicit)/g;
	$line =~ s/<<<from>>>/FW1 Host/g;
	$line =~ s/<<<to>>>/Any/g;
	$line =~ s/<<<service>>>/IKE/g;
	print $OUTFILE "$line\n";
	# RDP
	$line = $sline;
	$line =~ s/<<<rule>>>/(implicit)/g;
	$line =~ s/<<<from>>>/Any/g;
	$line =~ s/<<<to>>>/Any/g;
	$line =~ s/<<<service>>>/RDP/g;
	print $OUTFILE "$line\n";
	# CVP-Servers
	$line = $sline;
	$line =~ s/<<<rule>>>/(implicit)/g;
	$line =~ s/<<<from>>>/FW1 Host/g;
	$line =~ s/<<<to>>>/CVP-Servers/g;
	$line =~ s/<<<service>>>/FW1_cvp/g;
	print $OUTFILE "$line\n";
	# UFP-Servers
	$line = $sline;
	$line =~ s/<<<rule>>>/(implicit)/g;
	$line =~ s/<<<from>>>/FW1 Host/g;
	$line =~ s/<<<to>>>/UFP-Servers/g;
	$line =~ s/<<<service>>>/FW1_ufp/g;
	print $OUTFILE "$line\n";
	# Radius-Servers
	$line = $sline;
	$line =~ s/<<<rule>>>/(implicit)/g;
	$line =~ s/<<<from>>>/FW1 Host/g;
	$line =~ s/<<<to>>>/Radius-Servers/g;
	$line =~ s/<<<service>>>/RADIUS/g;
	print $OUTFILE "$line\n";
	# Tacacs-Servers
	$line = $sline;
	$line =~ s/<<<rule>>>/(implicit)/g;
	$line =~ s/<<<from>>>/FW1 Host/g;
	$line =~ s/<<<to>>>/Tacacs-Servers/g;
	$line =~ s/<<<service>>>/TACACS/g;
	print $OUTFILE "$line\n";
	# Ldap-Servers
	$line = $sline;
	$line =~ s/<<<rule>>>/(implicit)/g;
	$line =~ s/<<<from>>>/FW1 Host/g;
	$line =~ s/<<<to>>>/Ldap-Servers/g;
	$line =~ s/<<<service>>>/ldap/g;
	print $OUTFILE "$line\n";
	# Logical-Servers
	$line = $sline;
	$line =~ s/<<<rule>>>/(implicit)/g;
	$line =~ s/<<<from>>>/FW1 Host/g;
	$line =~ s/<<<to>>>/Logical-Servers/g;
	$line =~ s/<<<service>>>/load_agent/g;
	print $OUTFILE "$line\n";
    }
# outgoing
    if ( ("$prop_setting{'outgoing'}" eq 'true') &&
         (lc("$prop_setting{'outgoing_p'}") eq "$locstr") ) {
	$line = $safeline;
	$line =~ s/<<<comment>>>/Implicit rule: outgoing/g;
	$line =~ s/<<<rule>>>/(implicit)/g;
	$line =~ s/<<<from>>>/FW1 Module/g;
	$line =~ s/<<<to>>>/Any/g;
	$line =~ s/<<<service>>>/Any/g;
	print $OUTFILE "$line\n";
    }
# RIP
    if ( ("$prop_setting{'rip'}" eq 'true') &&
         (lc("$prop_setting{'rip_p'}") eq "$locstr") ) {
	$line = $safeline;
	$line =~ s/<<<comment>>>/Implicit rule: RIP/g;
	$line =~ s/<<<rule>>>/(implicit)/g;
	$line =~ s/<<<from>>>/Any/g;
	$line =~ s/<<<to>>>/Any/g;
	$line =~ s/<<<service>>>/RIP/g;
	print $OUTFILE "$line\n";
    }
# ICMP
    if ( ("$prop_setting{'icmpenable'}" eq 'true') &&
         (lc("$prop_setting{'icmpenable_p'}") eq "$locstr") ) {
	$line = $safeline;
	$line =~ s/<<<comment>>>/Implicit rule: ICMP/g;
	$line =~ s/<<<rule>>>/(implicit)/g;
	$line =~ s/<<<from>>>/Any/g;
	$line =~ s/<<<to>>>/Any/g;
	$line =~ s/<<<service>>>/icmp/g;
	print $OUTFILE "$line\n";
    }
# domain TCP
    if ( ("$prop_setting{'domain_tcp'}" eq 'true') &&
         (lc("$prop_setting{'domain_tcp_p'}") eq "$locstr") ) {
	$line = $safeline;
	$line =~ s/<<<comment>>>/Implicit rule: Domain TCP/g;
	$line =~ s/<<<rule>>>/(implicit)/g;
	$line =~ s/<<<from>>>/Any/g;
	$line =~ s/<<<to>>>/Any/g;
	$line =~ s/<<<service>>>/domain_tcp/g;
	print $OUTFILE "$line\n";
    }
# domain UDP
    if ( ("$prop_setting{'domain_udp'}" eq 'true') &&
         (lc("$prop_setting{'domain_udp_p'}") eq "$locstr") ) {
	$line = $safeline;
	$line =~ s/<<<comment>>>/Implicit rule: Domain UDP/g;
	$line =~ s/<<<rule>>>/(implicit)/g;
	$line =~ s/<<<from>>>/Any/g;
	$line =~ s/<<<to>>>/Any/g;
	$line =~ s/<<<service>>>/domain_udp/g;
	print $OUTFILE "$line\n";
    }
}



##########################################################################
# fill template with Rules
#	output file handle
#	line to noodle all the rules through

sub ReplaceTemplateRules{
    my ($OUTFILE)	= $_[0];
    my ($safeline)	= $_[1];
    my ($line)		= '';
    my ($i)		= 0;
    my ($rulenum)	= 0;
    my ($rulenegated)	= '';
    my ($ruleenabled)	= '';
    my ($txt);

    $line = "$safeline";
    for ( $i = 0; $i<=$access_number; $i++ ) {
	if ( $i == 0 ){
	    subImplicit__Replace ($OUTFILE, 'first', "$safeline");
	} elsif ( $i == $access_number ){
	    subImplicit__Replace ($OUTFILE, 'before last', "$safeline");
	}
	$rulenum = $i + 1;
	if ( $access_disabled[$i] ) { $ruleenabled = "$TemplateITEMSEP (disabled) "; } else { $ruleenabled = ''; }
	$line =~ s/<<<rule>>>/$rulenum$ruleenabled/g;

	if ( $access_from_negated[$i] ) { $rulenegated = ' (negated) '; } else { $rulenegated = ''; }
	$txt = "$access_from[$i]"; $txt =~ s/§/$TemplateITEMSEP/g;
	$line =~ s/<<<from>>>/$rulenegated$txt/g;

	if ( $access_to_negated[$i] ) { $rulenegated = ' (negated) '; } else { $rulenegated = ''; }
	$txt = "$access_to[$i]"; $txt =~ s/§/$TemplateITEMSEP/g;
	$line =~ s/<<<to>>>/$rulenegated$txt/g;

	if ( $access_services_negated[$i] ) { $rulenegated = ' (negated) '; } else { $rulenegated = ''; }
	$txt = "$access_services[$i]"; $txt =~ s/§/$TemplateITEMSEP/g;
	$line =~ s/<<<service>>>/$rulenegated$txt/g;

	$line =~ s/<<<action>>>/$access_action[$i]/g;
	$line =~ s/<<<track>>>/$access_track[$i]/g;
	$line =~ s/<<<time>>>/$access_time[$i]/g;
	$txt = "$access_install_on[$i]"; $txt =~ s/§/$TemplateITEMSEP/g;
	$line =~ s/<<<installon>>>/$txt/g;
	$line =~ s/<<<service>>>/$rulenegated$txt/g;
	$line =~ s/<<<comment>>>/$access_comment[$i]/g;
	if ( ! $access_unmatched[$i]) {
	    print $OUTFILE "$line\n";
	}
	$line = "$safeline";
    }
    subImplicit__Replace ($OUTFILE, 'last', "$safeline");
}


##########################################################################
# fill template with NAT
#	output file handle
#	line to noodle all the NAT rules through

sub ReplaceTemplateNat{
    my ($OUTFILE)	= $_[0];
    my ($safeline)	= $_[1];
    my ($line)		= '';
    my ($i);
    my ($iplus1);

    #--- first the explicit ones ---
    for ( $i = 0; $i<=$nat_number; $i++ ) {
	$line = $safeline;
	$iplus1 = $i + 1;
	$line =~ s/<<<rule>>>/$iplus1/g;
	if ( $nat_disabled[$i] ) {
		$line =~ s/<<<disabled>>>/\(disabled\)/g;
	} else {
		$line =~ s/<<<disabled>>>//g;
	}
	$txt = "$nat_install_on[$i]"; $txt =~ s/§/$TemplateITEMSEP/g;
	$line =~ s/<<<installon>>>/$txt/g;
	$line =~ s/<<<from>>>/$nat_orig_from[$i]/g;
	$line =~ s/<<<to>>>/$nat_orig_to[$i]/g;
	$line =~ s/<<<service>>>/$nat_orig_svc[$i]/g;
	$line =~ s/<<<tfrom>>>/$nat_transl_from[$i] ($NATtranslation{$nat_transl_from_methd[$i]})/g;
	$line =~ s/<<<tto>>>/$nat_transl_to[$i] ($NATtranslation{$nat_transl_to_methd[$i]})/g;
	$line =~ s/<<<tservice>>>/$nat_transl_svc[$i] ($NATtranslation{$nat_transl_svc_methd[$i]})/g;
	$line =~ s/<<<comment>>>/$nat_comment[$i]/g;
	if ( ! $nat_unmatched[$i]) {
	    print $OUTFILE "$line\n";
	}
    }
    #--- now the implicit ones ---
    $safeline =~ s/<<<comment>>>/inplicit NAT set in object definition/g;
    $safeline =~ s/<<<installon>>>/Gateways/g;
    $safeline =~ s/<<<service>>>/Any/g;
    $safeline =~ s/<<<tservice>>>/Original/g;
    $safeline =~ s/<<<disabled>>>//g;
    if ( $FLAG_implicitrules ) {
	foreach $name (@obj_name){
	    if ( ( $obj_used{$name} || $FLAG_allobjs ) &&
	         ( "$obj_NATadr{$name}" ne '' ) ) {
		#--- forward rule
	        $i++;
		$line = $safeline;
		$line =~ s/<<<rule>>>/$i (implicit)/g;
		$line =~ s/<<<from>>>/$name/g;
		$line =~ s/<<<to>>>/Any/g;
		$line =~ s/<<<tfrom>>>/$obj_NATadr{$name} ($NATtranslation{$obj_NATtype{$name}})/g;
		$line =~ s/<<<tto>>>/Original/g;
		print $OUTFILE "$line\n";

		#--- backward rule
	        $i++;
		$line = $safeline;
		$line =~ s/<<<rule>>>/$i (implicit)/g;
		$line =~ s/<<<from>>>/Any/g;
		$line =~ s/<<<to>>>/$obj_NATadr{$name}/g;
		$line =~ s/<<<tfrom>>>/Original/g;
		$line =~ s/<<<tto>>>/$name ($NATtranslation{$obj_NATtype{$name}})/g;
		print $OUTFILE "$line\n";
	    }
	}
    }
}


##########################################################################
# fill template with users
#	output file handle
#	line to noodle all the objects through

sub ReplaceTemplateUsers{
    my ($OUTFILE)	= $_[0];
    my ($safeline)	= $_[1];
    my ($line)		= '';

    $line = "$safeline";
    foreach $name (@user_name){
	next if($name =~ /^ *$/);
	next if($name =~ /All Users/);
	next if($name =~ /ALL_GROUPS/);
	next if($name =~ /ALL_KEYH/);
	next if($name =~ /ALL_TEMPLATES/);
	next if($user_type{$name} =~ /keyh/);
	next if($user_type{$name} =~ /template/);
	if ( $user_used{$name} || $FLAG_alluser ) {
	   $line =~ s/<<<name>>>/$name/g;
	   $line =~ s/<<<user_type>>>/$user_type{$name}/g;
	   $line =~ s/<<<user_from>>>/$user_from{$name}/g;
	   $line =~ s/<<<user_to>>>/$user_to{$name}/g;
	   $line =~ s/<<<user_auth>>>/$user_auth{$name}/g;
	   $line =~ s/<<<user_day>>>/$user_day{$name}/g;
	   $line =~ s/<<<user_expires>>>/$user_expires{$name}/g;
	   $txt = "$user_members{$name}"; $txt =~ s/§/$TemplateITEMSEP/g;
	   $line =~ s/<<<user_members>>>/$txt/g;
	   $line =~ s/<<<user_comment>>>/$user_comment{$name}/g;
	print $OUTFILE "$line\n";
	$line = "$safeline";
      }
    }
}


##########################################################################
# fill template with properties
#	output file handle
#	line to noodle all the objects through

sub ReplaceTemplateProperties{
    my ($OUTFILE)	= $_[0];
    my ($safeline)	= $_[1];
    my ($line)		= '';

    $line = "$safeline";

    $line =~ s/<<<include>>>/$TemplateINCLUDE/g;

    $line =~ s/<<<prop_gatewaydir>>>/$prop_setting{'gatewaydir'}/g;
    $line =~ s/<<<prop_tcptimeout>>>/$prop_setting{'tcptimeout'}/g;
    $line =~ s/<<<prop_fw1enable>>>/$prop_setting{'fw1enable'}/g;
    $line =~ s/<<<prop_fw1enable_p>>>/$prop_setting{'fw1enable_p'}/g;
    $line =~ s/<<<prop_udpreply>>>/$prop_setting{'udpreply'}/g;
    $line =~ s/<<<prop_udpreply_p>>>/$prop_setting{'udpreply_p'}/g;
    $line =~ s/<<<prop_udptimeout>>>/$prop_setting{'udptimeout'}/g;
    $line =~ s/<<<prop_outgoing>>>/$prop_setting{'outgoing'}/g;
    $line =~ s/<<<prop_outgoing_p>>>/$prop_setting{'outgoing_p'}/g;
    $line =~ s/<<<prop_acceptdecrypt>>>/$prop_setting{'acceptdecrypt'}/g;
    $line =~ s/<<<prop_enable_fastpath>>>/$prop_setting{'enable_fastpath'}/g;
    $line =~ s/<<<prop_rip>>>/$prop_setting{'rip'}/g;
    $line =~ s/<<<prop_rip_p>>>/$prop_setting{'rip_p'}/g;
    $line =~ s/<<<prop_domain_udp>>>/$prop_setting{'domain_udp'}/g;
    $line =~ s/<<<prop_domain_udp_p>>>/$prop_setting{'domain_udp_p'}/g;
    $line =~ s/<<<prop_domain_tcp>>>/$prop_setting{'domain_tcp'}/g;
    $line =~ s/<<<prop_domain_tcp_p>>>/$prop_setting{'domain_tcp_p'}/g;
    $line =~ s/<<<prop_icmpenable>>>/$prop_setting{'icmpenable'}/g;
    $line =~ s/<<<prop_icmpenable_p>>>/$prop_setting{'icmpenable_p'}/g;
    $line =~ s/<<<prop_ftppasv>>>/$prop_setting{'ftppasv'}/g;
    $line =~ s/<<<prop_ftppasv_p>>>/$prop_setting{'ftppasv_p'}/g;
    $line =~ s/<<<prop_rshstderr>>>/$prop_setting{'rshstderr'}/g;
    $line =~ s/<<<prop_rshstderr_p>>>/$prop_setting{'rshstderr_p'}/g;
    $line =~ s/<<<prop_rpcenable>>>/$prop_setting{'rpcenable'}/g;
    $line =~ s/<<<prop_rpcenable_p>>>/$prop_setting{'rpcenable_p'}/g;
    $line =~ s/<<<prop_ftpdata>>>/$prop_setting{'ftpdata'}/g;
    $line =~ s/<<<prop_ftpdata_p>>>/$prop_setting{'ftpdata_p'}/g;
    $line =~ s/<<<prop_raudioenable>>>/$prop_setting{'raudioenable'}/g;
    $line =~ s/<<<prop_raudioenable_p>>>/$prop_setting{'raudioenable_p'}/g;
    $line =~ s/<<<prop_vdolivenable>>>/$prop_setting{'vdolivenable'}/g;
    $line =~ s/<<<prop_vdolivenable_p>>>/$prop_setting{'vdolivenable_p'}/g;
    $line =~ s/<<<prop_cooltalkenable>>>/$prop_setting{'cooltalkenable'}/g;
    $line =~ s/<<<prop_iphoneenable>>>/$prop_setting{'iphoneenable'}/g;
    $line =~ s/<<<prop_loggrace>>>/$prop_setting{'loggrace'}/g;
    $line =~ s/<<<prop_alertcmd>>>/$prop_setting{'alertcmd'}/g;
    $line =~ s/<<<prop_mailcmd>>>/$prop_setting{'mailcmd'}/g;
    $line =~ s/<<<prop_snmptrapcmd>>>/$prop_setting{'snmptrapcmd'}/g;
    $line =~ s/<<<prop_useralertcmd>>>/$prop_setting{'useralertcmd'}/g;
    $line =~ s/<<<prop_spoofalertcmd>>>/$prop_setting{'spoofalertcmd'}/g;
    $line =~ s/<<<prop_userauthalertcmd<>>>/$prop_setting{'userauthalertcmd'}/g;
    $line =~ s/<<<prop_log_established_tcp>>>/$prop_setting{'log_established_tcp'}/g;
    $line =~ s/<<<prop_liveconns>>>/$prop_setting{'liveconns'}/g;
    $line =~ s/<<<prop_resolver_1>>>/$prop_setting{'resolver_1'}/g;
    $line =~ s/<<<prop_resolver_2>>>/$prop_setting{'resolver_2'}/g;
    $line =~ s/<<<prop_resolver_3>>>/$prop_setting{'resolver_3'}/g;
    $line =~ s/<<<prop_resolver_4>>>/$prop_setting{'resolver_4'}/g;
    $line =~ s/<<<prop_timeout>>>/$prop_setting{'timeout'}/g;
    $line =~ s/<<<prop_retries>>>/$prop_setting{'retries'}/g;
    $line =~ s/<<<prop_pagetimeout>>>/$prop_setting{'pagetimeout'}/g;
    $line =~ s/<<<prop_telnet_msg>>>/$prop_setting{'telnet_msg'}/g;
    $line =~ s/<<<prop_rlogin_msg>>>/$prop_setting{'rlogin_msg'}/g;
    $line =~ s/<<<prop_ftp_msg>>>/$prop_setting{'ftp_msg'}/g;
    $line =~ s/<<<prop_clnt_auth_msg>>>/$prop_setting{'clnt_auth_msg'}/g;
    $line =~ s/<<<prop_http_next_proxy_host>>>/$prop_setting{'http_next_proxy_host'}/g;
    $line =~ s/<<<prop_http_next_proxy_port>>>/$prop_setting{'http_next_proxy_port'}/g;
    $line =~ s/<<<prop_au_timeout>>>/$prop_setting{'au_timeout'}/g;
    $line =~ s/<<<prop_snk_server_ip>>>/$prop_setting{'snk_server_ip'}/g;
    $line =~ s/<<<prop_snk_agent_id>>>/$prop_setting{'snk_agent_id'}/g;
    $line =~ s/<<<prop_snk_agent_key>>>/$prop_setting{'snk_agent_key'}/g;
    $line =~ s/<<<prop_fwsynatk_method>>>/$prop_setting{'fwsynatk_method'}/g;
    $line =~ s/<<<prop_fwsynatk_timeout>>>/$prop_setting{'fwsynatk_timeout'}/g;
    $line =~ s/<<<prop_fwsynatk_max>>>/$prop_setting{'fwsynatk_max'}/g;
    $line =~ s/<<<prop_fwsynatk_warning>>>/$prop_setting{'fwsynatk_warning'}/g;
    $line =~ s/<<<prop_load_service_port>>>/$prop_setting{'load_service_port'}/g;
    $line =~ s/<<<prop_lbalanced_period_wakeup_sec>>>/$prop_setting{'lbalanced_period_wakeup_sec'}/g;
    $line =~ s/<<<prop_established>>>/$prop_setting{'established'}/g;
    $line =~ s/<<<prop_established_p>>>/$prop_setting{'established_p'}/g;
    $line =~ s/<<<prop_rip>>>/$prop_setting{'rip'}/g;
    $line =~ s/<<<prop_rip_p>>>/$prop_setting{'rip_p'}/g;
    $line =~ s/<<<prop_domain_udp>>>/$prop_setting{'domain_udp'}/g;
    $line =~ s/<<<prop_domain_udp_p>>>/$prop_setting{'domain_udp_p'}/g;
    $line =~ s/<<<prop_domain_tcp>>>/$prop_setting{'domain_tcp'}/g;
    $line =~ s/<<<prop_domain_tcp_p>>>/$prop_setting{'domain_tcp_p'}/g;
    $line =~ s/<<<prop_icmpenable>>>/$prop_setting{'icmpenable'}/g;
    $line =~ s/<<<prop_icmpenable_p>>>/$prop_setting{'icmpenable_p'}/g;
    print $OUTFILE "$line\n";
}


#BR start

##########################################################################
# fill template with objects
#	output file handle
#	line to noodle all the objects through

sub ReplaceTemplateObjects{
    my ($OUTFILE)	= $_[0];
    my ($safeline)	= $_[1];
    my ($line)		= '';

    $line = "$safeline";
    foreach $name (@obj_name){
      if ( $FLAG_unused_objects ) {
	if (  $obj_used{$name} == 0 ) {
	  if ( $FLAG_hosts_only || $FLAG_networks_only || $FLAG_groups_only || $FLAG_gateways_only ) {
            if ( $FLAG_gateways_only  && "$obj_type{$name}" eq 'gateway' ){
        	PrintTemplateObjects($OUTFILE,$line);
	    }
            if ( $FLAG_hosts_only  && "$obj_type{$name}" eq 'host' ){
        	PrintTemplateObjects($OUTFILE,$line);
	    }
	    if ( $FLAG_networks_only  && "$obj_type{$name}" eq 'network' ){
        	PrintTemplateObjects($OUTFILE,$line);
	    }
	    if ( $FLAG_groups_only  && "$obj_type{$name}" eq 'group' ){
          	PrintTemplateObjects($OUTFILE,$line);
	    }
          }
          else {
           PrintTemplateObjects($OUTFILE,$line);
          }
        }
      }
      else {
        if ( $obj_used{$name} || $FLAG_allobjs ) {
	  if ( $FLAG_hosts_only || $FLAG_networks_only || $FLAG_groups_only || $FLAG_gateways_only ) {
            if ( $FLAG_gateways_only  && "$obj_type{$name}" eq 'gateway' ){
        	PrintTemplateObjects($OUTFILE,$line);
	    }
            if ( $FLAG_hosts_only  && "$obj_type{$name}" eq 'host' ){
        	PrintTemplateObjects($OUTFILE,$line);
	    }
	    if ( $FLAG_networks_only  && "$obj_type{$name}" eq 'network' ){
        	PrintTemplateObjects($OUTFILE,$line);
	    }
	    if ( $FLAG_groups_only  && "$obj_type{$name}" eq 'group' ){
          	PrintTemplateObjects($OUTFILE,$line);
	    }
          }
          else {
           PrintTemplateObjects($OUTFILE,$line);
          }
        }
      }
    }
}


##########################################################################
# Print object according to object template
#	output file handle
#
sub PrintTemplateObjects{
    my ($OUTFILE)	= $_[0];
    my ($line)		= $_[1];
    my ($loc)		= '';
    my ($fw1)		= '';

    $line =~ s/<<<name>>>/$name/g;
    $line =~ s/<<<type>>>/$obj_type{$name}/g;
    if ( $obj_location{$name} ) { $loc = 'external'; } else { $loc = 'internal'; }
    $line =~ s/<<<location>>>/$loc/g;
    if ( $obj_is_fw1{$name} ) { $fw1 = 'FW1 installed'; } else { $fw1 = '---'; }
    $line =~ s/<<<fw1>>>/$fw1/g;
    $line =~ s/<<<ipaddress>>>/$obj_ipaddr{$name}/g;
    $line =~ s/<<<netmask>>>/$obj_netmask{$name}/g;
    $line =~ s/<<<masklen>>>/$netmasktranslation{$obj_netmask{$name}}/g;
    $line =~ s/<<<nataddress>>>/$obj_NATadr{$name}/g;
#BR start
    $line =~ s/<<<color>>>/$obj_colour{$name}/g;
#BR end
    $line =~ s/<<<nattype>>>/$NATtranslation{$obj_NATtype{$name}}/g;
    $txt = "$obj_members{$name}"; $txt =~ s/§/$TemplateITEMSEP/g;
    $line =~ s/<<<members>>>/$txt/g;
    $line =~ s/<<<comment>>>/$obj_comment{$name}/g;
    print $OUTFILE "$line\n";
}

#BR end

##########################################################################
# fill template with services
#	output file handle
#	line to noodle all the objects through

sub ReplaceTemplateServices{
    my ($OUTFILE)	= $_[0];
    my ($safeline)	= $_[1];
    my ($line)		= '';
    my ($svcmem)	= '';

    $line = "$safeline";
    foreach $name (@svc_name){
      if ( $svc_used{$name} || $FLAG_allservices ) {
	$line =~ s/<<<name>>>/$name/g;
	$line =~ s/<<<type>>>/$svc_type{$name}/g;
	$line =~ s/<<<protocol>>>/$svc_protocol{$name}/g;
	$line =~ s/<<<port>>>/$svc_dst_port{$name}/g;
	$line =~ s/<<<sportfrom>>>/$svc_src_low{$name}/g;
	$line =~ s/<<<sportto>>>/$svc_src_high{$name}/g;
	$line =~ s/<<<timeout>>>/$svc_timeout{$name}/g;
	$line =~ s/<<<match>>>/$svc_match{$name}/g;
	$line =~ s/<<<prolog>>>/$svc_prolog{$name}/g;
	$svcmem = "$svc_members{$name}"; $svcmem =~ s/§/$TemplateITEMSEP/g;
	$line =~ s/<<<members>>>/$svcmem/g;
#BR start
        $line =~ s/<<<color>>>/$svc_colour{$name}/g;
#BR end
	$line =~ s/<<<comment>>>/$svc_comment{$name}/g;
	print $OUTFILE "$line\n";
	$line = "$safeline";
      }
    }
}

#BR end

##########################################################################
# fill template and replace with current config
#	filename of the template
#	filename of the output file

sub Fill_Template {
    my ($template_filename)	= $_[0];
    my ($output_filename)	= $_[1];
    my ($dummy)			= '';
    my ($line)			= '';
    my ($safeline)		= '';

    open (INFILE,"<$template_filename")
    	or die "Can't read template $template_filename!\n";
    open (DUMPFILE,">$output_filename")
    	or die "Can't write template output file $output_filename!\n";
    $line = <INFILE>;
    if ( "$line" !~ m/^--------------*/ ) { die "Template has broken header (line 1)\n"; }
    $line = <INFILE>;
    ($dummy,$TemplateITEMSEP) = split(/=/, &fromdos($line), 2);
    &PrintLog("Template: $TemplateITEMSEP\n");
    if ( "$dummy" ne 'title'  ) { die "Template has broken header (line 2 not title)\n"; }
    $line = <INFILE>;
    ($dummy,$TemplateITEMSEP) = split(/=/, &fromdos($line), 2);
    $TemplateITEMSEP =~ s/<NEWLINE>/\n/g;
    $TemplateITEMSEP =~ s/<TAB>/\t/g;
    $TemplateITEMSEP =~ s/<SPACE>/ /g;
#BR start
    $TemplateITEMSEP =~ s/<COLON>/,/g;
    $TemplateITEMSEP =~ s/<SEMICOLON>/;/g;
    $TemplateITEMSEP =~ s/<PIPE>/|/g;
#BR end
    if ( "$dummy" ne 'separator'  ) { die "Template has broken header (line 3 not separator)\n"; }
    $line = <INFILE>;
    if ( "$line" !~ m/^--------------*/ ) { die "Template has broken header (line 4)\n"; }
    while ( "$line" ne '' ) {
        while ( ($line = <INFILE>) && ($line !~ m/<<<<<.*/x)){
		$line =~ s/\n//g; $line =~ s/\r//g;
		$now = localtime();
		$line =~ s/<<<<configset>>>>/$FW1rules/g;
		$line =~ s/<<<<date>>>>/$now/g;
		$line =~ s/<<<<fwrules>>>>/$SCR_NAME \($VERSION\)/g;
		$line =~ s/<<<include>>>/$TemplateINCLUDE/g;
		$line =~ s/<NEWLINE>/\n/g;
		$line =~ s/<TAB>/\t/g;
		$line =~ s/<SPACE>/ /g;
#BR start
                $line =~ s/<COLON>/,/g;
                $line =~ s/<SEMICOLON>/;/g;
                $line =~ s/<PIPE>/|/g;
#BR end

		&ReplaceTemplateProperties(DUMPFILE,$line);
        }
        # ------------ read loopline --------------
        $safeline = &fromdos("$line");
        while ( ($line = <INFILE>) && ($line =~ m/<<<<<.*/x)){
		$line =~ s/\n//g; $line =~ s/\r//g;
                $safeline = "$safeline\n$line";
		$line = '';
        }
	$safeline =~ s/<NEWLINE>/\n/g;
	$safeline =~ s/<TAB>/\t/g;
	$safeline =~ s/<SPACE>/ /g;
#BR start
        $safeline =~ s/<COLON>/,/g;
        $safeline =~ s/<SEMICOLON>/;/g;
        $safeline =~ s/<PIPE>/|/g;
#BR end
	if ( $safeline =~ m/<<<<<objects>>>>>.*/ ) {
	   $safeline =~ s/<<<<<objects>>>>>//g;
	   $safeline =~ s/<<<include>>>/$TemplateINCLUDE/g;
	   if ( ! $FLAG_noobjs ) {
		&ReplaceTemplateObjects(DUMPFILE,$safeline);
	   }
	}
	if ( $safeline =~ m/<<<<<rules>>>>>.*/ ) {
	   $safeline =~ s/<<<<<rules>>>>>//g;
	   $safeline =~ s/<<<include>>>/$TemplateINCLUDE/g;
	   if ( ! $FLAG_norules ) {
		&ReplaceTemplateRules(DUMPFILE,$safeline);
	   }
	}
	if ( $safeline =~ m/<<<<<services>>>>>.*/ ) {
	   $safeline =~ s/<<<<<services>>>>>//g;
	   $safeline =~ s/<<<include>>>/$TemplateINCLUDE/g;
	   if ( ! $FLAG_noservices ) {
		&ReplaceTemplateServices(DUMPFILE,$safeline);
	   }
	}
	if ( $safeline =~ m/<<<<<nat>>>>>.*/ ) {
	   $safeline =~ s/<<<<<nat>>>>>//g;
	   $safeline =~ s/<<<include>>>/$TemplateINCLUDE/g;
	   if ( ! $FLAG_norules ) {
		&ReplaceTemplateNat(DUMPFILE,$safeline);
           }
	}
	if ( $safeline =~ m/<<<<<user>>>>>.*/ ) {
	   $safeline =~ s/<<<<<user>>>>>//g;
	   $safeline =~ s/<<<include>>>/$TemplateINCLUDE/g;
	   if ( ! $FLAG_nousers ) {
		&ReplaceTemplateUsers(DUMPFILE,$safeline);
	   }
	}
	$line =~ s/<<<include>>>/$TemplateINCLUDE/g;
	&ReplaceTemplateProperties(DUMPFILE,$line);
    }
}


##########################################################################
##########################################################################
###   MAIN
##########################################################################
##########################################################################

# Parse and process options
if (!GetOptions(\%optctl,
	'objects=s', 'rules=s', 'users=s', 'userdbexport=s',
	'merge_SP3=s', 'merge_AI=s',
	'all_objects', 'all_services', 'all_users',
	'with_implicit_rules', 'with_ip',
	'with_interfaces', 'with_antispoofing', 'show_members',
	'no_rules', 'no_objects', 'no_services', 'no_users', 'no_servers',
	'with_colors', 'icon_path=s', 'use-css=s', 'title=s',
	'dump_nat_tsv=s', 'dump_nat_txt=s',
	'dump_objects_tsv=s', 'dump_objects_txt=s',
	'dump_rules_tsv=s', 'dump_rules_txt=s',
	'dump_services_tsv=s', 'dump_services_txt=s',
	'dump_users_tsv=s', 'dump_users_txt=s',
	'output_html=s', 'link_to=s',
	'match_comment=s', 'match_installon=s',
	'match_source=s', 'match_destination=s',								# GT
	'match_service=s', 'match_logic=s', 									# GT
	'match_case', 															# GT
	'template=s', 'template_include=s', 'output=s',
#BR start
        'unused_objects', 'hosts_only', 'networks_only', 'groups_only',
        'expand_object_groups', 'expand_service_groups', 'gateways_only',
        'no_title',
#BR end
	'verbose','sort_by_type', 'cis_fast_verbose', 'debug', 'version',
	'cis_fast_xml=s', 'cis_fast_benchmark=s', 'cis_fast_output=s',
	'dump_unused_objects=s','dump_properties=s','dump_unused_objects_tsv=s'
	)
	|| keys(%optctl) == 0 || $optctl{help} == 1 || $optctl{version} == 1 )
{
        if ($optctl{version} == 1)
        {
        } else {
                &Usage();
        }
        exit;
}


#--------------------------------------------------
# filename options
if (defined($optctl{'icon_path'})) { $IconPathName = $optctl{'icon_path'}; }
if (defined($optctl{'objects'})) { $FW1objects = $optctl{'objects'}; }
if (defined($optctl{'rules'})) { $FW1rules = $optctl{'rules'}; $HTMLtitle = "$FW1rules";}
if (defined($optctl{'merge_SP3'})) { $FWSrules = $optctl{'merge_SP3'};}							# GT
if (defined($optctl{'merge_AI'})) { $FWSrules = $optctl{'merge_AI'};}							# GT
if (defined($optctl{'users'})) { $FW1user = $optctl{'users'}; }


#--------------------------------------------------
# HTML / Template candy
if (defined($optctl{'use-css'})) { $HTMLcssfile = $optctl{'use-css'}; }
if (defined($optctl{'title'})) { $HTMLtitle = $optctl{'title'}; }

if (defined($optctl{'template_include'})) { $TemplateINCLUDE = $optctl{'template_include'}; }
if (defined($optctl{'link_to'})) { $LinkToDIR = $optctl{'link_to'}; }

#--------------------------------------------------
# switches / flags
$FLAG_withcolors = (defined($optctl{'with_colors'}));
$FLAG_withip = (defined($optctl{'with_ip'}));
$FLAG_allobjs = (defined($optctl{'all_objects'}));
$FLAG_allservices = (defined($optctl{'all_services'}));
$FLAG_alluser = (defined($optctl{'all_users'}));
$FLAG_implicitrules = (defined($optctl{'with_implicit_rules'}));
$FLAG_verbose = (defined($optctl{'verbose'}));
$FLAG_debug = (defined($optctl{'debug'}));
$FLAG_sortbytype = (defined($optctl{'sort_by_type'}));
$FLAG_norules = (defined($optctl{'no_rules'}));
$FLAG_noobjs = (defined($optctl{'no_objects'}));
$FLAG_noservices = (defined($optctl{'no_services'}));
$FLAG_noservers = (defined($optctl{'no_servers'}));
$FLAG_nousers = (defined($optctl{'no_users'}));
$FLAG_withinterface = (defined($optctl{'with_interfaces'}));
$FLAG_withantispoofing = (defined($optctl{'with_antispoofing'}));
$FLAG_showmembers = (defined($optctl{'show_members'}));
$FLAG_linkto = (defined($optctl{'link_to'}));

#BR start
$FLAG_unused_objects = (defined($optctl{'unused_objects'}));
$FLAG_hosts_only = (defined($optctl{'hosts_only'}));
$FLAG_gateways_only = (defined($optctl{'gateways_only'}));
$FLAG_networks_only = (defined($optctl{'networks_only'}));
$FLAG_groups_only = (defined($optctl{'groups_only'}));
$FLAG_expand_object_groups = (defined($optctl{'expand_object_groups'}));
$FLAG_expand_service_groups = (defined($optctl{'expand_service_groups'}));
#BR end



#--------------------------------------------------
# selections
if (defined($optctl{'match_comment'}))      { $Match_Comment      = $optctl{'match_comment'};	 $FLAG_match = 1; }
if (defined($optctl{'match_source'}))       { $Match_Source       = $optctl{'match_source'}; 	 $FLAG_match = 1; }		# GT
if (defined($optctl{'match_destination'}))  { $Match_Destination  = $optctl{'match_destination'};$FLAG_match = 1; }		# GT
if (defined($optctl{'match_service'}))	    { $Match_Service      = $optctl{'match_service'}; 	 $FLAG_match = 1; }		# GT
if (defined($optctl{'match_logic'}))	    { $Match_Logic        = $optctl{'match_logic'}; 	 $FLAG_match = 1; }		# GT
if (defined($optctl{'match_case'}))	    { $Match_Case    	  = $optctl{'match_case'}; }							# GT
if (defined($optctl{'match_installon'}))    { $Match_InstallOn    = $optctl{'match_installon'}; }

if (! $FLAG_verbose) {
}
#--------------------------------------------------
# check on parameter inconsistencies

$FLAG_nousers = 1;
if ( defined($optctl{'users'}) ||
     defined($optctl{'usersdbexport'}) ||
     defined($optctl{'dump_users_tsv'}) ||
     defined($optctl{'dump_users_txt'}) ) {
   die "\n
   	There are no user base handling routines in FW1Rules any more.\n
   	User base handling was dropped from FW1Rules since 7.3.7 due to \n
        undocumented changes in the user database format by CheckPoint.\n
	The routines provided only were able to read the user database\n
	up to V4.1 SP2. Maybe you could live with a simple exported\n
	file (done with CheckPoint routines)? We will happily include new\n
	routines that can read current user databases, though, if you can\n
	provide them.\n
	Aborting due to no-longer existing parameters. Sorry...\n";
}

if ( ( $FLAG_noobjs && $FLAG_allobjs ) ||
     ( $FLAG_noservices && $FLAG_allservices ) ||
     ( $FLAG_nousers && $FLAG_allusers ) ) {
   die "Conflicting  --all_*  and --no_* options. Aborting.";
}

if ( ( ! $FLAG_verbose ) && $FLAG_CISVERBOSE ) {
   die "Conflicting verbose options. Aborting.";
}

if ( ( $FLAG_noobjs && ( $optctl{'dump_objects_txt'} || $optctl{'dump_objects_tsv'} ) ) ||
     ( $FLAG_noservices && ( $optctl{'dump_services_txt'} || $optctl{'dump_services_tsv'} ) ) ) {
   die "Conflicting  --no_*  and --dump_* options. Aborting.";
}

if ( $FLAG_norules ) {
   $FLAG_allobjs = 1;
   $FLAG_allservices = 1;
}


if ( ( (defined($optctl{'template'})) &&
       (! defined($optctl{'output'})) )
       ||
     ( (! defined($optctl{'template'})) &&
       (defined($optctl{'output'})) ) ){
   die "ERROR: --output option needs --template - Aborting.";
}


if (defined($optctl{'cis_fast_verbose'}) |
    defined($optctl{'cis_fast_output'}) |
    defined($optctl{'cis_fast_xml'}) |
    defined($optctl{'cis_fast_benchmark'})) {
   die "Experimental CIS-FAST routines were removed after 7.3.37 - Aborting.";
}


if (defined($optctl{'merge_AI'}) &&
    defined($optctl{'merge_SP3'}) ) {
   die "Use only one of the --merge_ options  -  Aborting.";
}


#----------------------------------------------------------------

if ($FLAG_verbose) { open (LOGFILE,">$LogFile") or die "ERROR: Can't create logfile\n"; }
if ($FLAG_debug) { open (DEBUGFILE,">$DebugFile") or die "ERROR: Can't create debugfile\n"; }


#------ first the objects ------

open (INFILE,"$FW1objects")
	or die "Cannot open the object file $FW1objects!\n\n";

&PrintLog("skipping...");
while ($line = <INFILE>) {
    $line = &fromdos($line);
    &DebugLog("READ Objects.C = $line");
    #--------------------------------------------
    if ( ( $line =~ /^\t\:netobj \(netobj/ ) ||			 # V4.1 style
    	 ( $line =~ /^\t\:network_objects \(network_objects/ )|| # NG style
         ($line =~/^\t:network_objects \(/)                      # R65 style Added 2008-02-12 by Jacob
      ) {
	&PrintLog("\n\nReading network objects...");
	&ReadNetworkObjects;
	&PrintLog("\n\nskipping...");
    }
    #--------------------------------------------
    if (( $line =~ /^\t\:servers \(servers/ )||      # V4.1 = NG style
        ($line =~ /^\t\:servers \(/)                 # R65 style Added 2008-02-12 by Jacob
    ) {
	&PrintLog("\n\nReading servers objects...");
	if ($line !~ /^\t\:servers \(servers\)/ ) {
		&ReadServers;
	}
	&PrintLog("\n\nskipping...");
    }
    #--------------------------------------------
    if ( ( $line =~ /^\t\:servobj \(servobj/ ) ||	# V4.1 style
	( $line =~ /^\t\:services \(services/ ) ||	# NG style
	( $line =~ /^\t\:services \(/ )            	# R65 style Added 2008-02-12 by Jacob
       ) {
	&PrintLog("\n\nReading services...");
	&ReadServices;
	&PrintLog("\n\nskipping...");
    }
    #--------------------------------------------
    if ( ( $line =~ /^\t\:resourcesobj \(resourcesobj/ ) ||	# V4.1 style
	 ( $line =~ /^\t\:resources_types \(resources_types/ ) 	# NG style
       ) {
	&PrintLog("\n\nReading resources...");
	&ReadResources;
	&PrintLog("\n\nskipping...");
    }
    #--------------------------------------------
    if ( ( $line =~ /^\t\:props \(/ ) ||	# V4.1 style
         ( $line =~ /^\t\:properties \(/ ) 	# NG style
       ) {
	&PrintLog("\n\nReading properties...");
	&ReadProperties;
	&PrintLog("\n\nskipping...");
    }
    #--------------------------------------------
    if ( ( $line =~ /^\t\:netobjadtr \(/ )	# V4.1 style
       ) {
	&PrintLog("\n\nReading netobjadtr...");
	&ReadNetobjadtr;
	&PrintLog("\n\nskipping...");
    }
    #--------------------------------------------
    else {
	&PrintLog('.');
    }
}

&PrintLog(".\n");
close (INFILE);

#------ GT, 2003-02-06: Begin --------
if ( "$FWSrules" ne "" )
	{
	$wXfws_out = $FW1rules . "_FWS";

	open (INW, "$FW1rules") or die "ERROR: Can't open $FW1rules\n";
	open (INFWS, "$FWSrules") or die "ERROR: Can't open $FWSrules\n";
	open (OUT, "> $wXfws_out") or die "ERROR: Can't create $wXfws_out\n";

	# print "GT, 2003-02-06: merge $FW1rules with comments of $FWSrules into $wXfws_out\n";

	while (<INFWS>)
		{
		if (/:chkpf_uid \(\"\{(.+?)\}/)
			{
			$uid = $1;
			$com{$uid} = "";
			}
		if (/:comments \((.*)\)/)
			{
			s/^"|"$//;
			s/\t//;
			$comment = $_;
			$com{$ruleuid} = $comment;
			}
		if (/:header_text \((.*)\)/)
			{
			s/"//;
			s/\t//;
			$hdrtext = $_;
			}
		if (/:rule \(/)
			{
			$ruleuid="";
			}
		if (/^\t\)/ || /:rule_adtr \(/)
			{
			if ($hdrtext)
				{
				$TAILHEADER{$secuid}=$hdrtext;
				}
			$hdrtext="";
			}
		if (/:ClassName \(security_/ || /:ClassName \(address_/)
			{
			$ruleuid=$uid;
			}
		if (/:ClassName \(security_rule\)/)
                        {
                        $secuid=$uid;
                        if ($hdrtext)
                                {
                                $hdr{$ruleuid} = $hdrtext;
                                $hdrtext="";
                                }
                        }
		}

	while (<INW>)
		{
		if (/:chkpf_uid \(\"\{(.+?)\}/)
			{
			$uid = $1;
			}
		if (/:ClassName \(security_rule\)/ || /:ClassName \(address_/)
			{
			$ruleuid=$uid;
			}
		if (/^\)/ || /:rule_adtr /)
			{
			if ($TAILHEADER{$ruleuid})
				{
				print OUT "\t:rule (\n";
				print OUT "\t	:AdminInfo (\n";
				print OUT "\t		:chkpf_uid (\"00000000-0000-0000-0000-000000000001\")\n";
				print OUT "\t		:ClassName (security_header_rule)\n";
				print OUT "\t	)\n";
				print OUT "\t	:disabled (true)\n";
				print OUT $TAILHEADER{$ruleuid};
				print OUT "\t)\n";
				}
			}
		if (/:dst \(/ || /:dst_adtr_translated \(/)
			{
			print OUT $com{$ruleuid};
			print OUT $hdr{$ruleuid} if ($hdr{$ruleuid});
			}
		print OUT;
		}

	close INW;
	close INFWS;
	close OUT;

	$FW1rules = $wXfws_out;				# now change --rules to created file
	}
#------ GT, 2003-02-06: End   --------

#------ now the rulebase ------

if ( ! $FLAG_norules ) {

   $nat_number = -1;
   open (INFILE,"$FW1rules")
	or die "Cannot open the rules file $FW1rules!\n\n";

   &PrintLog("\n\nskipping...");
   while ( $line = <INFILE> ) {
        $line = &fromdos("$line");
	&DebugLog("Skipping Rules: $line \n");
	if ( $line =~ /^\t\:rule \(/ ) {
	    &PrintLog("\n\nReading access rules...");
	    $line = &ReadAccessRules($line);
	    &DebugLog("\n\nreturned $line");
	    &PrintLog("\n\nskipping...");
	}
	if ( $line =~ /^\t\:rule_adtr \(/ ) {
	    &PrintLog("\n\nReading NAT rules...");
	    &ReadNATrules($line);
	    &PrintLog("\n\nskipping...");
	} else {
	    &PrintLog('.');
	}
   }
#BR start
# expand objects
   if ( $FLAG_expand_object_groups ){
        for ( $i = 0; $i <= $access_number ; $i++ ) {
           $access_to[$i] = &ExpandedGroups ( "object", $access_to[$i] );
           $access_to_negated[$i] = &ExpandedGroups ( "object", $access_to_negated[$i], );
           $access_from[$i] = &ExpandedGroups ( "object", $access_from[$i] );
           $access_from_negated[$i] = &ExpandedGroups ( "object", $access_from_negated[$i] );
        }
   }
# expand service groups
   if ( $FLAG_expand_service_groups ){
        for ( $i = 0; $i <= $access_number ; $i++ ) {
           $access_services[$i] = &ExpandedGroups ( "service", $access_services[$i] );
           $access_services_negated[$i] = &ExpandedGroups ( "service", $access_services_negated[$i] );
        }
   }
#BR end

   close (INFILE);
}

#BR start
##########################################################################
# Expanded Object Groups
#       String of objects separated by §
#       sorted, no duplicates
#
sub ExpandedGroups{
    my $type = $_[0];
    my $memberlist = $_[1];
    my ( @my_sort_list );
    my ( $item );
    my ( $item_old );

    $memberlist = &ExpandGroups ( $type, $memberlist );

    @my_sort_list = sort ( split ( /§/, $memberlist ));
    $memberlist = "";
    $item_old = "";
    foreach $item ( @my_sort_list ){
      if( $item ne $item_old ){
        $memberlist .= $item . "§" ;
      };
      $item_old = $item;
    }
    $memberlist =~ s/§$//g;
    return ( $memberlist );
}


##########################################################################
# Expand Object Groups
#       String of objects separated by §
sub ExpandGroups{
    my $type = $_[0];
    my $memberlist = $_[1];
    my ($expanded_members);
    my (@members);
    my (@single);

    $depth += 1;

    @members = split (/§/,${memberlist});
    foreach $single (@members) {
        if ( $type eq "object" ){
           if ( "$obj_type{$single}" eq 'group'){
                $expanded_members .= "§" . &ExpandGroups($type, "$obj_members{$single}" );
            }
            else {
                $expanded_members = $expanded_members . "§" . $single;
            }
        }
        else {
            if ( "$svc_type{$single}" eq 'group'){
                $expanded_members .= "§" . &ExpandGroups($type, "$svc_members{$single}" );
            }
            else {
                $expanded_members = $expanded_members . "§" . $single;
            }
        }
    }
    $expanded_members =~ s/^§//g;
    return ( "$expanded_members" );

}
#BR end




#------ now the user ------

# if ( ! $FLAG_nousers ) {
#    &PrintLog("\n\nReading Users...");
#    if (defined($optctl{'usersdbexport'})) {
#	&ReadDBExportUser($optctl{'usersdbexport'});
#   } else {
#	&ReadUser;
#   }
# }
&PrintLog("\n\nReading Done.\n\n");

#--------------------------------------------------
# dump data into separate files
if (defined($optctl{'dump_nat_tsv'})) {
	&PrintLog("Dumping NAT in TSV format.\n");
	&DumpNatTSV ($optctl{'dump_nat_tsv'}); }
if (defined($optctl{'dump_nat_txt'})) {
	&PrintLog("Dumping NAT in TXT format.\n");
	&DumpNatTXT ($optctl{'dump_nat_txt'}); }

if (defined($optctl{'dump_rules_tsv'})) {
	&PrintLog("Dumping Rules in TSV format.\n");
	&DumpRulesTSV ($optctl{'dump_rules_tsv'}); }
if (defined($optctl{'dump_rules_txt'})) {
	&PrintLog("Dumping Rules in TXT format.\n");
	&DumpRulesTXT ($optctl{'dump_rules_txt'}); }

if (defined($optctl{'dump_objects_tsv'})) {
	&PrintLog("Dumping Objects in TSV format.\n");
	&DumpObjectsTSV ($optctl{'dump_objects_tsv'}); }
if (defined($optctl{'dump_objects_txt'})) {
	&PrintLog("Dumping Objects in TXT format.\n");
	&DumpObjectsTXT ($optctl{'dump_objects_txt'}); }

if (defined($optctl{'dump_services_tsv'})) {
	&PrintLog("Dumping Services in TSV format.\n");
	&DumpServicesTSV ($optctl{'dump_services_tsv'}); }
if (defined($optctl{'dump_services_txt'})) {
	&PrintLog("Dumping Services in TXT format.\n");
	&DumpServicesTXT ($optctl{'dump_services_txt'}); }

#if (defined($optctl{'dump_users_tsv'})) {
#	&PrintLog("Dumping Users in TSV format.\n");
#	&DumpUsersTSV ($optctl{'dump_users_tsv'}); }
#if (defined($optctl{'dump_users_txt'})) {
#	&PrintLog("Dumping Users in TXT format.\n");
#	&DumpUsersTXT ($optctl{'dump_users_txt'}); }

if (defined($optctl{'dump_unused_objects'})) {
	&PrintLog("Dumping unused objects in TXT file.\n");
	&DumpUnusedObjects ($optctl{'dump_unused_objects'}); }

if (defined($optctl{'dump_unused_objects_tsv'})) {
	&PrintLog("Dumping unused objects in TSV file.\n");
	&DumpUnusedObjectsTsv ($optctl{'dump_unused_objects_tsv'});
}

if (defined($optctl{'dump_properties'})) {
	&PrintLog("Dumping properties in TXT file.\n");
	&DumpProperties ($optctl{'dump_properties'}); }

#--------------------------------------------------
# print ruleset
if (defined($optctl{'output_html'})) {
	&PrintLog("Printing ruleset in HTML format.\n");
	&Output_in_HTML ($optctl{'output_html'}); }

if ( (defined($optctl{'template'})) && (defined($optctl{'output'})) ) {
	&PrintLog("Printing ruleset into template.\n");
	&Fill_Template ($optctl{'template'},$optctl{'output'}); }

#--------------------------------------------------
# subroutines for the "CIS Fast" benchmark

&PrintLog("\nDone.\n\n");

if ( defined($optctl{'dump_nat_txt'}) ) {
    &PrintLog("!! Warning!!\nThe use of the parameter --dump_nat_txt will be discontinued.\nPlease use the template NAT.TXT instead.\n\n");
    print STDERR "!! Warning!!\nThe use of the parameter --dump_nat_txt will be discontinued.\nPlease use the template NAT.TXT instead.\n\n";
    sleep 3;
}
if ( defined($optctl{'dump_nat_tsv'}) ) {
    &PrintLog("!! Warning!!\nThe use of the parameter --dump_nat_tsv will be discontinued.\nPlease use the template NAT.TSV instead.\n\n");
    print STDERR "!! Warning!!\nThe use of the parameter --dump_nat_tsv will be discontinued.\nPlease use the template NAT.TSV instead.\n\n";
    sleep 3;
}

if ( defined($optctl{'dump_rules_txt'}) ) {
    &PrintLog("!! Warning!!\nThe use of the parameter --dump_rules_txt will be discontinued.\nPlease use the template RULES.TXT instead.\n\n");
    print STDERR "!! Warning!!\nThe use of the parameter --dump_rules_txt will be discontinued.\nPlease use the template RULES.TXT instead.\n\n";
    sleep 3;
}
if ( defined($optctl{'dump_rules_tsv'}) ) {
    &PrintLog("!! Warning!!\nThe use of the parameter --dump_rules_tsv will be discontinued.\nPlease use the template RULES.TSV instead.\n\n");
    print STDERR "!! Warning!!\nThe use of the parameter --dump_rules_tsv will be discontinued.\nPlease use the template RULES.TSV instead.\n\n";
    sleep 3;
}

if ( defined($optctl{'dump_objects_txt'}) ) {
    &PrintLog("!! Warning!!\nThe use of the parameter --dump_objects_txt will be discontinued.\nPlease use the template OBJECTS.TXT instead.\n\n");
    print STDERR "!! Warning!!\nThe use of the parameter --dump_objects_txt will be discontinued.\nPlease use the template OBJECTS.TXT instead.\n\n";
    sleep 3;
}
if ( defined($optctl{'dump_objects_tsv'}) ) {
    &PrintLog("!! Warning!!\nThe use of the parameter --dump_objects_tsv will be discontinued.\nPlease use the template OBJECTS.TSV instead.\n\n");
    print STDERR "!! Warning!!\nThe use of the parameter --dump_objects_tsv will be discontinued.\nPlease use the template OBJECTS.TSV instead.\n\n";
    sleep 3;
}

if ( defined($optctl{'dump_services_txt'}) ) {
    &PrintLog("!! Warning !!\nThe use of the parameter --dump_services_txt will be discontinued.\nPlease use the template SERVICES.TXT instead.\n\n");
    print STDERR "!! Warning !!\nThe use of the parameter --dump_services_txt will be discontinued.\nPlease use the template SERVICES.TXT instead.\n\n";
    sleep 3;
}
if ( defined($optctl{'dump_services_tsv'}) ) {
    &PrintLog("!! Warning !!\nThe use of the parameter --dump_services_tsv will be discontinued.\nPlease use the template SERVICES.TSV instead.\n\n");
    print STDERR "!! Warning !!\nThe use of the parameter --dump_services_tsv will be discontinued.\nPlease use the template SERVICES.TSV instead.\n\n";
    sleep 3;
}

if ( defined($optctl{'dump_properties'}) ) {
    &PrintLog("!! Warning!!\nThe use of the parameter --dump_properties will be discontinued.\nPlease use the template PROPERTIES.TXT instead.\n\n");
    print STDERR "!! Warning!!\nThe use of the parameter --dump_properties will be discontinued.\nPlease use the template PROPERTIES.TXT instead.\n\n";
    sleep 3;
}

if ($FLAG_verbose) { close (LOGFILE); }
if ($FLAG_debug) { close (DEBUGFILE); }

#############################################################################

