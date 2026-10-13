<?php
/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: $today.year.hour.minute
 ******************************************************************************/

namespace PaloAltoNetworks\HealthCheck;
require_once INC_ROOT.'/libs/database.php';

class MysqlSQLLogBin extends HealthCheck
{

    public function getDescription(): string
    {
        return "Verify that the SQL_Log_bin flag in MariaDB is set to off";
    }

    public function getCategory(): string
    {
        return "OS Settings";
    }

    public function check(): CheckResponse
    {
        require_once INC_ROOT.'/libs/projectdb.php';
        $conn = selectDatabase('pandbRBAC');
        $query = "SHOW variables like 'sql_log_bin'";
        $result = $conn->query($query);

        if($result->num_rows>0){
            $data = $result->fetch_assoc();
            $value = $data['Value'];

            if($value != 'OFF'){
                $response = new CheckResponse($this, false, -1, "session sql_log_bin is ON", 'Consider Setting sql_log_bin to OFF. <br>Insert the following line "define (\'DBSQL_LOG_BIN\', 0);" in the file "/home/userSpace/userDefinitions.php"');
            }
            else{
                $response = new CheckResponse($this, true, 0, "session sql_log_bin is OFF", 'N/A');
            }
        }else{
            $response = new CheckResponse($this, true, 0, "Could not check sql_log_bin state", 'Verify log_bin is OFF');
        }

        return $response;
    }

    public function repair(): CheckResponse
    {
        require_once INC_ROOT.'/libs/projectdb.php';
        $conn = selectDatabase('pandbRBAC');
        $query = "SHOW variables like 'sql_log_bin'";
        $result = $conn->query($query);

        if($result->num_rows>0){
            $data = $result->fetch_assoc();
            $value = $data['Value'];

            if($value != 'OFF'){
                $mysql_file= create_mysql_file();
                $Command = "mysql --defaults-extra-file=$mysql_file -e \"set sql_log_bin = 0\" ";
                exec($Command);
                //exec("mysql -u".DBUser." -p".DBPass." -e \"set sql_log_bin = 0\" ");
                delete_mysql_dump_file($mysql_file);
                $response = new CheckResponse($this, false, -1, "session sql_log_bin is ON", 'Consider Setting sql_log_bin to OFF');
            }
            else{
                $response = new CheckResponse($this, true, 0, "SQL_Log_bin is OFF", 'N/A');
            }
        }else{
            $response = new CheckResponse($this, true, 0, "Could not check sql_log_bin state", 'Verify log_bin is OFF');
        }

        return $response;
    }
}