------------------------------------------------------------------
title=SERVICES.SQL - access rules in a phpMyAdmin-style MySQL-Dump
separator=+
------------------------------------------------------------------
#  Firewall Configuration - phpMyAdmin-style MySQL-Dump
#  <<<<configset>>>>
#  Created by <<<<fwrules>>>> 
#  on <<<<date>>>>


#
# Table structure for table `services`
# 

DROP TABLE IF EXISTS services;
CREATE TABLE services (
	name TEXT NOT NULL,
	type TEXT NOT NULL,
	port INT, 
	sportfrom INT, 
	sportto INT, 
	match TEXT, 
	prolog TEXT, 
	members TEXT, 
	comment TEXT
);


#
# Dumping data for table `services`
#

<<<<<services>>>>>INSERT INTO services (name,type,port,sportfrom,sportto,match,prolog,members,comment) VALUES ('<<<name>>>','<<<type>>>','<<<port>>>','<<<sportfrom>>>','<<<sportto>>>','<<<match>>>','<<<prolog>>>','<<<members>>>','<<<comment>>>');
<<<<<services>>>>>


