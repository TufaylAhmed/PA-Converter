#!/usr/bin/perl

#############################################################################
# anon_objects.pl: anonymizes (kind of) Firewall-1 objects file
#
# Copyright (C) 2001 Volker Tanger
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# For bug reports and suggestions or if you just want to talk to me please
# contact me at volker.tanger@wyae.de
#
# This file is included into the FWrules package.
# Updates will be available at  http://www.wyae.de/software/
#
#############################################################################
#############################################################################
###                                                                       ###
###   Please double re-check that your file is anonymized enough!         ###
###                                                                       ###
#############################################################################
#############################################################################

#
# Defaults, Constants
#
$VERSION="0.3.0";
$DEFAULT_OBJ_FILE = 'objects.C';
$DEFAULT_ANON_FILE = 'anon_objects.C';

# ---------------------------------------------------------------
print ("ANONymize OBJECTS.c  V$VERSION - 2001 by Volker Tanger\n\n");
print ("Doing rough anonymization...");

$lfdNr = 1;

open (INFILE, $DEFAULT_OBJ_FILE)
    	or die "Error: can't read file $DEFAULT_OBJ_FILE";
open (OUTFILE, ">$DEFAULT_ANON_FILE")
    	or die "Error: can't write file $DEFAULT_ANON_FILE";
	
while ($line = <INFILE>) {
    	chomp($line);
	if ( ($line =~ m/.*:ipaddr.*/) || 
	     ($line =~ m/.*:netmask.*/) ||
	     ($line =~ m/.*:valid_ipaddr.*/) ) {
	     print "A";
	     ($left,$dummy) = split(/\(/,$line,2);
	     print OUTFILE "$left($lfdNr.$lfdNr.$lfdNr.$lfdNr)\n";
	     $lfdNr++;
	} else {
	     print ".";
	     print OUTFILE "$line\n";
	}
}
close(OUTFILE);
close(INFILE);
print "\n\nDone.\n";
print "All IP addresses and netmasks were replaced. \n";
print "Names and keys remain unchanged!\n";
print "\nPlease double-check that $DEFAULT_ANON_FILE is anonymous enough!\n";

# ============================================================



