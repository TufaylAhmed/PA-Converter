------------------------------------------------------------------
title=RULES.SQL - access rules in a phpMyAdmin-style MySQL-Dump
separator=+
------------------------------------------------------------------
#  Firewall Configuration - phpMyAdmin-style MySQL-Dump
#  <<<<configset>>>>
#  Created by <<<<fwrules>>>> 
#  on <<<<date>>>>


#
# Table structure for table `accessrules`
# 

DROP TABLE IF EXISTS accessrules;
CREATE TABLE accessrules (
   nr INT NOT NULL,
   source TEXT NOT NULL,
   destination TEXT NOT NULL,
   service TEXT NOT NULL,
   processing TEXT NOT NULL,
   track TEXT,
   install_on TEXT NOT NULL,
   time TEXT NOT NULL,
   comment TEXT
);


#
# Dumping data for table `accessrules`
#

<<<<<rules>>>>>INSERT INTO accessrules (nr,source,destination,service,processing,track,install_on,time,comment) VALUES ( '<<<rule>>>','<<<from>>>','<<<to>>>','<<<service>>>','<<<action>>>','<<<track>>>','<<<installon>>>','<<<time>>>','<<<comment>>>');
<<<<<rules>>>>>
