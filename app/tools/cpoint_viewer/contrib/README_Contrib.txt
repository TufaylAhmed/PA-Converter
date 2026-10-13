-----------------------------------------------------------------------
 			FW1Rules - CONTRIB
-----------------------------------------------------------------------

FW1Rules is a Perl script to parse Checkpoint Firewall-1 configuration
files and produces a readable report mainly in HTML format plus some
more.

These are utilities to support firewall admins working with CheckPoint
FireWall-1 and FW1Rules.

Additional tools included in the contrib directory are:

    anon_objects.pl 
	Anonymizes the IP addresses of configuration files in case you
	want to send them for debugging. Please do check for proper
	anonymization prior to sending.

    cp2fwbuilder.txt
	Converts FW1 ruleset into a FWBUILDER configuration file
	(XML). This program was forked from fw1rules version 7.1.0 by
	Stefan Majer <stefan@x-cellent.de> and its homepage is located
	at SourceForge (http://cp2fwbuilder.sourceforge.net/).

    fwdbexport.pl
    	Exports user base with a number of options not given in
	FW1RULES, esp. for further processing.
	Supplied by Christian Port <christian.port@openadvice.de>

    make_mht (dir)
	by Brian Pothier  <pothier_brian@emc.com>
	Converts an exported FW1 ruleset HTML doc into a Microsoft
	Internet Explorer *.MHT file which includes all images, too.
	For this call  "./make_mht HTMLFILENAME"
	Requirements:
		- Unix shell script, under Win* maybe with Cygwin...
		- the browser LYNX
		- installed at /usr/local/bin
	

    ruleshistory.sh
	To be run daily as CRON script. Only keeps config files if
	they differ - thus building an change history (plus
	notification when a change is being detected).



The data aquisition is based on knowledge derived from reverse
engineering of well known configurations. The scripts are totally
unsupported by Checkpoint or representatives.

Updates will be available at   http://www.wyae.de/software/
Please check there for updates prior to submitting patches!

For bug reports and suggestions or if you just want to talk to me
please contact me at volker.tanger@wyae.de 



-----------------------------------------------------------------------
			anon_objects.pl 
		by Volker Tanger <volker.tanger@wyae.de>
-----------------------------------------------------------------------

Anonymizes the IP addresses of configuration files in case you want to
send them for debugging. Please do check for proper anonymization
prior to sending.

Called, it will transform the file 'objects.C' into the file
'anon_objects.C' where all IP addresses and netmasks will be replaced
with increasing (nonsense) numbers.



-----------------------------------------------------------------------
			fwdbexport.pl
	by Christian Port <christian.port@openadvice.de>
-----------------------------------------------------------------------

Exports user base with a number of options not given in FW1RULES, esp.
for further processing.


usage: $SCR_NAME [options]
       $SCR_NAME --help
       $SCR_NAME --version

options:
   --groups: print out groups instead of users

   --input=<input file>: Location of output file.
          Default is fwauth.NDB.

   --output=<output file>: Location of output file.
          Default is users.fws (as needed in *local mode).

   --attr=<attr-list>: List of attributes to include in the csv output.
          See also 'type-list' below.

   --delimiter=<delimiter>: specify delimiter

   all options can also be specifyed ba the first letter with one dash 

   attr-list: comma-separated list of attributes

   user attributes:
     name, color, groups, destinations, sources, auth_method, fromhour, tohour,
     expiration_date, days, accept_track, internal_password, SKEY_seed, SKEY_number,
     SKEY_passwd, SKEY_gateway, comments, radius_server, expire, SKEY_method

   group attributes:
     name, groups, color, comments



-----------------------------------------------------------------------
			cp2fwbuilder.txt
		by Stefan Majer <stefan@x-cellent.de>
	      (note: mail seems to be no loner working)
-----------------------------------------------------------------------

Converts FW1 ruleset into a FWBUILDER configuration file (XML). This
program was forked from fw1rules version 7.1.0 

Its homepage is located at SourceForge
(http://cp2fwbuilder.sourceforge.net/).



-----------------------------------------------------------------------
			ruleshistory.sh
		by Volker Tanger <volker.tanger@wyae.de>
-----------------------------------------------------------------------

If run daily from a CRON script the script automagically builds a
change history (plus notification when a change is being detected).

This shell script creates a HTML configuration output with a date
stamp and compares it to the "latest" configuration stored. If it does
not differ (i.e. no change) it is deleted. If it does differ, the
"latest" configuration is updated and the changed HTML dump is mailed
to the administrators.

To run, you will have to change the variable to your local setting and
create a directory (e.g. /etc/fw1config) for the dump history.

