------------------------------------------------------------------
title=OBJECTS.SQL - all objects in a phpMyAdmin-style MySQL-Dump
separator=+
------------------------------------------------------------------
#  Firewall Objects - phpMyAdmin-style MySQL-Dump
#  <<<<configset>>>>
#  Created by <<<<fwrules>>>> 
#  on <<<<date>>>>


#
# Table structure for table `objects`
# 

DROP TABLE IF EXISTS objects;
CREATE TABLE objects (
	name TEXT NOT NULL,
	type TEXT NOT NULL,
	location TEXT,
	fw1 TEXT,
	ipaddress TEXT,
	netmask TEXT,
	nataddress TEXT,
	nattype TEXT,
	members TEXT,
	comment TEXT
);


#
# Dumping data for table `objects`
#

<<<<<objects>>>>>INSERT INTO objects ('<<<name>>>','<<<type>>>','<<<location>>>','<<<fw1>>>','<<<ipaddress>>>','<<<netmask>>>','<<<nataddress>>>','<<<nattype>>>','<<<members>>>','<<<comment>>>');
<<<<<objects>>>>>
