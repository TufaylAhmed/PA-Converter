#!/bin/sh
#----------------------------------------------------------------------
# RULESHISTORY.SH - 2002 by Volker Tanger <volker.tanger@wyae.de>
#----------------------------------------------------------------------
# If run daily from a CRON script the script automagically builds a 
# change history (plus notification when a change is being detected).
# 
# This shell script creates a HTML configuration output with a date
# stamp and compares it to the "latest" configuration stored. If it 
# does not differ (i.e. no change) it is deleted. If it does differ, 
# the "latest" configuration is updated and the changes are mailed
# to the administrators.
# 
# To run, you will have to change the variable to your local setting
# and create a directory (e.g. /etc/fw1config) for the HTML dump
# history.
#----------------------------------------------------------------------

#----- email address of the admin(s)
ADMINS=root

#----- policy file (*.W)
POLICY=standard

#----- directory to keep the historical config dumps in
HISTORYDIR=/etc/fw1rules

#----- FULLCONFIG.TXT template file including full path
TEMPLATE=/usr/local/lib/fullconfig.txt


#---------------------------------
# no changes below here - probably
#---------------------------------


#---------------------------------
# generate a current HTML file
#---------------------------------
DAT=`date +%Y-%m-%d`

/usr/local/sbin/fw1rules.pl --with_ip \
        --with_implicit_rules --no_users \
        --objects=/etc/fw/conf/objects.C \
        --rules=/etc/fw/conf/$POLICY.W \
        --template=$TEMPLATE \
        --output=/tmp/currentconfig.txt \
        --output_html=$HISTORYDIR/$POLICY.$DAT.html  > /dev/null


#---------------------------------
# now compare those two
#---------------------------------

diff -c /tmp/currentconfig.txt $HISTORYDIR/latestconfig.txt > /tmp/diff.txt

#------ if differs, then keep - else remove
if [ "$?" = "1" ]; then
        cp /tmp/currentconfig.txt $HISTORYDIR/latestconfig.txt
        cat /tmp/diff.txt | mailx -s "Firewall Config $POLICY changed" $ADMINS
else
        rm $HISTORYDIR/$POLICY.$DAT.html
fi

#------ cleanup
rm /tmp/currentconfig.txt /tmp/diff.txt



# -----------------------------------------------------------------------
# Shortcut: Distributable under  GPL
# -----------------------------------------------------------------------
# Copyright (C) 2000-2002 Volker Tanger
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
# 
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307,
# USA. or on their website http://www.gnu.org/copyleft/gpl.html
# 
# -----------------------------------------------------------------------
