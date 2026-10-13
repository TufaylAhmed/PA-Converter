<?php
/*******************************************************************************
 * Copyright (c) 2020 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: 2020/03/13
 ******************************************************************************/

define ('DBServer' , 'localhost');
define ('DBUser',  'root');
define ('DBPass', 'paloalto');
define ('DBName' ,'project_schema');
define ('PARSER_max_execution_time','10000');
define ('PARSER_max_execution_memory','1G');
define ('PARSER_max_number_address_per_group', -1);
define ('DBSQL_LOG_BIN', 0);
define ('MAXSUPERUSERS','3');
define ('MAX_RULES_TO_ANALYZE', 600);
define ('RECOMMENDED_PANOS_VERSION', 9.1);
define ('DEVICE_CONNECTION_TIMEOUT', 900);
define ('DEVICE_DEBUG_CONNECTION_ENABLED','0');
