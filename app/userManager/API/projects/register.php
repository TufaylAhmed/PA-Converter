<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 29/3/16 - 10:35
 */

/** This method registers a set of roles for new projects and assignes the Admin role to the creator.
 *
 * @param STRING $project Name of the project being created. It is used to define the roles' name
 * @return bool True if the user had privileges and the project name is valid. False otherwise
 */

if(defined('CLI')){
    require_once INC_ROOT .'/userManager/API/accessControl_CLI.php';
}
else{
    require_once INC_ROOT .'/userManager/API/accessControl.php';
    require_once INC_ROOT.'/bin/authentication/sessionControl.php';
}

function registerProject(ARRAY $data){
    global $app;

    $name = $data['name'];

    $forbiddenNames = array("ACCESSIBLE","ACTION","ADD","AFTER","AGAINST","AGGREGATE","ALGORITHM","ALL","ALTER","ANALYZE","AND","ANY","AS","ASC","ASCII","ASENSITIVE","AT","AUTHORS",
        "AUTOEXTEND_SIZE","AUTO_INCREMENT","AVG","AVG_ROW_LENGTH","BACKUP","BEFORE","BEGIN","BETWEEN","BIGINT","BINARY","BINLOG","BIT","BLOB","BLOCK","BOOL","BOOLEAN","BOTH","BTREE","BY",
        "BYTE","CACHE","CALL","CASCADE","CASCADED","CASE","CATALOG_NAME","CHAIN","CHANGE","CHANGED","CHAR","CHARACTER","CHARSET","CHECK","CHECKSUM","CIPHER","CLASS_ORIGIN","CLIENT",
        "CLOSE","COALESCE","CODE","COLLATE","COLLATION","COLUMN","COLUMNS","COLUMN_NAME","COMMENT","COMMIT","COMMITTED","COMPACT","COMPLETION","COMPRESSED","CONCURRENT","CONDITION",
        "CONNECTION","CONSISTENT","CONSTRAINT","CONSTRAINT_CATALOG","CONSTRAINT_NAME","CONSTRAINT_SCHEMA","CONTAINS","CONTEXT","CONTINUE","CONTRIBUTORS","CONVERT","CPU","CREATE","CROSS",
        "CUBE","CURRENT_DATE","CURRENT_TIME","CURRENT_TIMESTAMP","CURRENT_USER","CURSOR","CURSOR_NAME","DATA","DATABASE","DATABASES","DATAFILE","DATE","DATETIME","DAY","DAY_HOUR",
        "DAY_MICROSECOND","DAY_MINUTE","DAY_SECOND","DEALLOCATE","DEC","DECIMAL","DECLARE","DEFAULT","DEFINER","DELAYED","DELAY_KEY_WRITE","DELETE","DESC","DESCRIBE","DES_KEY_FILE",
        "DETERMINISTIC","DIRECTORY","DISABLE","DISCARD","DISK","DISTINCT","DISTINCTROW","DIV","DO","DOUBLE","DROP","DUAL","DUMPFILE","DUPLICATE","DYNAMIC","EACH","ELSE","ELSEIF","ENABLE",
        "ENCLOSED","END","ENDS","ENGINE","ENGINES","ENUM","ERROR[a]","ERRORS","ESCAPE","ESCAPED","EVENT","EVENTS","EVERY","EXECUTE","EXISTS","EXIT","EXPANSION","EXPLAIN","EXTENDED",
        "EXTENT_SIZE","FALSE","FAST","FAULTS","FETCH","FIELDS","FILE","FIRST","FIXED","FLOAT","FLOAT4","FLOAT8","FLUSH","FOR","FORCE","FOREIGN","FOUND","FRAC_SECOND[b]","FROM","FULL",
        "FULLTEXT","FUNCTION","GENERAL[c]","GEOMETRY","GEOMETRYCOLLECTION","GET_FORMAT","GLOBAL","GRANT","GRANTS","GROUP","HANDLER","HASH","HAVING","HELP","HIGH_PRIORITY","HOST","HOSTS",
        "HOUR","HOUR_MICROSECOND","HOUR_MINUTE","HOUR_SECOND","IDENTIFIED","IF","IGNORE","IGNORE_SERVER_IDS[d]","IMPORT","IN","INDEX","INDEXES","INFILE","INITIAL_SIZE","INNER",
        "INNOBASE[e]","INNODB[f]","INOUT","INSENSITIVE","INSERT","INSERT_METHOD","INSTALL","INT","INT1","INT2","INT3","INT4","INT8","INTEGER","INTERVAL","INTO","INVOKER","IO","IO_THREAD",
        "IPC","IS","ISOLATION","ISSUER","ITERATE","JOIN","KEY","KEYS","KEY_BLOCK_SIZE","KILL","LANGUAGE","LAST","LEADING","LEAVE","LEAVES","LEFT","LESS","LEVEL","LIKE","LIMIT","LINEAR",
        "LINES","LINESTRING","LIST","LOAD","LOCAL","LOCALTIME","LOCALTIMESTAMP","LOCK","LOCKS","LOGFILE","LOGS","LONG","LONGBLOB","LONGTEXT","LOOP","LOW_PRIORITY","MASTER",
        "MASTER_CONNECT_RETRY","MASTER_HEARTBEAT_PERIOD[g]","MASTER_HOST","MASTER_LOG_FILE","MASTER_LOG_POS","MASTER_PASSWORD","MASTER_PORT","MASTER_SERVER_ID","MASTER_SSL","MASTER_SSL_CA",
        "MASTER_SSL_CAPATH","MASTER_SSL_CERT","MASTER_SSL_CIPHER","MASTER_SSL_KEY","MASTER_SSL_VERIFY_SERVER_CERT","MASTER_USER","MATCH","MAXVALUE","MAX_CONNECTIONS_PER_HOUR",
        "MAX_QUERIES_PER_HOUR","MAX_ROWS","MAX_SIZE","MAX_UPDATES_PER_HOUR","MAX_USER_CONNECTIONS","MEDIUM","MEDIUMBLOB","MEDIUMINT","MEDIUMTEXT","MEMORY","MERGE","MESSAGE_TEXT",
        "MICROSECOND","MIDDLEINT","MIGRATE","MINUTE","MINUTE_MICROSECOND","MINUTE_SECOND","MIN_ROWS","MOD","MODE","MODIFIES","MODIFY","MONTH","MULTILINESTRING","MULTIPOINT",
        "MULTIPOLYGON","MUTEX","MYSQL_ERRNO","NAME","NAMES","NATIONAL","NATURAL","NCHAR","NDB","NDBCLUSTER","NEW","NEXT","NO","NODEGROUP","NONE","NOT","NO_WAIT","NO_WRITE_TO_BINLOG",
        "NULL","NUMERIC","NVARCHAR","OFFSET","OLD_PASSWORD","ON","ONE","ONE_SHOT","OPEN","OPTIMIZE","OPTION","OPTIONALLY","OPTIONS","OR","ORDER","OUT","OUTER","OUTFILE","OWNER",
        "PACK_KEYS","PAGE","PARSER","PARTIAL","PARTITION","PARTITIONING","PARTITIONS","PASSWORD","PHASE","PLUGIN","PLUGINS","POINT","POLYGON","PORT","PRECISION","PREPARE","PRESERVE",
        "PREV","PRIMARY","PRIVILEGES","PROCEDURE","PROCESSLIST","PROFILE","PROFILES","PROXY[h]","PURGE","QUARTER","QUERY","QUICK","RANGE","READ","READS","READ_ONLY","READ_WRITE","REAL",
        "REBUILD","RECOVER","REDOFILE","REDO_BUFFER_SIZE","REDUNDANT","REFERENCES","REGEXP","RELAY[i]","RELAYLOG","RELAY_LOG_FILE","RELAY_LOG_POS","RELAY_THREAD","RELEASE","RELOAD",
        "REMOVE","RENAME","REORGANIZE","REPAIR","REPEAT","REPEATABLE","REPLACE","REPLICATION","REQUIRE","RESET","RESIGNAL","RESTORE","RESTRICT","RESUME","RETURN","RETURNS","REVOKE",
        "RIGHT","RLIKE","ROLLBACK","ROLLUP","ROUTINE","ROW","ROWS","ROW_FORMAT","RTREE","SAVEPOINT","SCHEDULE","SCHEMA","SCHEMAS","SCHEMA_NAME","SECOND","SECOND_MICROSECOND","SECURITY",
        "SELECT","SENSITIVE","SEPARATOR","SERIAL","SERIALIZABLE","SERVER","SESSION","SET","SHARE","SHOW","SHUTDOWN","SIGNAL","SIGNED","SIMPLE","SLAVE","SLOW[j]","SMALLINT","SNAPSHOT",
        "SOCKET","SOME","SONAME","SOUNDS","SOURCE","SPATIAL","SPECIFIC","SQL","SQLEXCEPTION","SQLSTATE","SQLWARNING","SQL_BIG_RESULT","SQL_BUFFER_RESULT","SQL_CACHE","SQL_CALC_FOUND_ROWS",
        "SQL_NO_CACHE","SQL_SMALL_RESULT","SQL_THREAD","SQL_TSI_DAY","SQL_TSI_FRAC_SECOND[k]","SQL_TSI_HOUR","SQL_TSI_MINUTE","SQL_TSI_MONTH","SQL_TSI_QUARTER","SQL_TSI_SECOND",
        "SQL_TSI_WEEK","SQL_TSI_YEAR","SSL","START","STARTING","STARTS","STATUS","STOP","STORAGE","STRAIGHT_JOIN","STRING","SUBCLASS_ORIGIN","SUBJECT","SUBPARTITION","SUBPARTITIONS",
        "SUPER","SUSPEND","SWAPS","SWITCHES","TABLE","TABLES","TABLESPACE","TABLE_CHECKSUM","TABLE_NAME","TEMPORARY","TEMPTABLE","TERMINATED","TEXT","THAN","THEN","TIME","TIMESTAMP",
        "TIMESTAMPADD","TIMESTAMPDIFF","TINYBLOB","TINYINT","TINYTEXT","TO","TRAILING","TRANSACTION","TRIGGER","TRIGGERS","TRUE","TRUNCATE","TYPE","TYPES","UNCOMMITTED","UNDEFINED",
        "UNDO","UNDOFILE","UNDO_BUFFER_SIZE","UNICODE","UNINSTALL","UNION","UNIQUE","UNKNOWN","UNLOCK","UNSIGNED","UNTIL","UPDATE","UPGRADE","USAGE","USE","USER","USER_RESOURCES",
        "USE_FRM","USING","UTC_DATE","UTC_TIME","UTC_TIMESTAMP","VALUE","VALUES","VARBINARY","VARCHAR","VARCHARACTER","VARIABLES","VARYING","VIEW","WAIT","WARNINGS","WEEK","WHEN",
        "WHERE","WHILE","WITH","WORK","WRAPPER","WRITE","X509","XA","XML","XOR","YEAR","YEAR_MONTH","ZEROFILL",
        "PANDBRBAC", "MYSQL", "PANDB", "BESTPRACTICES", "REALTIMEUUPDATES", "INFORMATION_SCHEMA", "PERFORMANCE_SCHEMA");

    if(in_array(strtoupper($name),$forbiddenNames)){
        $message = array();
        $message['code'] = false;
        $message['msg'] = '"'.$name.'" is not a valid name for a project';
        return $message;
    }

    if(is_numeric($name)){
        $message = array();
        $message['code'] = false;
        $message['msg'] = '"'.$name.'" is not a valid name for a project because is numeric';
        return $message;
    }

    if(!accessControl("any", ['project.create','project.admin'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to create projects';
        return $message;
    }

    $slug = "PANProject_".$name;

    $v = $app->projectValidation;
    $v->validate([
        'name'   => [$name, 'required|validName'],
    ]);
    if(!$v->passes()){
            $message = array();
            $message['code'] = false;
            $message['msg'] = $v->errors()->all();
            return $message;
    }

    $v = $app->roleValidation;
    $v->validate([
        'project'   => [$slug."_admin",     'required|alnumDash|max(240)|uniqueRoleSlug'],
    ]);

    if ($v->passes()){
        //Create project on the pandbRBAC
        if(!isset($data['progress']) OR $data['progress']==''){
            $data['progress'] = 0;
        }

        /* @var PaloAltoNetworks\Sentinel\Projects\Project $project*/
        $project = $app->project->create($data);
//        $project = $app->container->project->create(array(
//            'name' => $name,
//            'vendor' => $data['vendor'],
//            'active' => 1,
//            'tag' => $data['tag'],
//            'progress' => $data['progress'],
//        ));

        //Create the admin role for the project
        /* @var Cartalyst\Sentinel\Roles\EloquentRole $role_admin */
        $role_admin = $app->sentinel->getRoleRepository()->createModel()->create(array(
            'name' => "admin",
            'slug' => $slug."_admin",
            'permissions' => array(
                'projectRole.'.$name.'.admin'  => true,
                'projectRole.'.$name.'.delete' => true,
                'projectRole.'.$name.'.update' => true,
                'projectRole.'.$name.'.view'   => true,
            ),
        ));

        //Create the user role for the project
        //$role_user =
            $app->sentinel->getRoleRepository()->createModel()->create(array(
            'name' => "user",
            'slug' => $slug."_user",
            'permissions' => array(
                'projectRole.'.$name.'.admin'  => false,
                'projectRole.'.$name.'.delete' => false,
                'projectRole.'.$name.'.update' => true,
                'projectRole.'.$name.'.view'   => true,
            ),
        ));

        //Create the viewer role for the project
        //$role_viewer =
            $app->sentinel->getRoleRepository()->createModel()->create(array(
            'name' => "viewer",
            'slug' => $slug."_viewer",
            'permissions' => array(
                'projectRole.'.$name.'.admin'  => false,
                'projectRole.'.$name.'.delete' => false,
                'projectRole.'.$name.'.update' => false,
                'projectRole.'.$name.'.view'   => true,
            ),
        ));

        //Create the keys for this project
        $random_password = $app->randomlib->generateString(128);
        $random_iv = $app->randomlib->generateString(16);
        $keyData = [
            "type"  => "project",
            "lid"   => $project->id,
            "key"   => $random_password,
            "iv"    => $random_iv
        ];
        //$keys =
            $app->accessKey->create($keyData);

        $user = $app->sentinel->getUser();

        $role_admin->users()->attach($user);

        if($device = $app->device->where('serial',$data['source'])->first()){
            $project->devices()->attach($device);

            $params = [
                'panos'         => $device->panos,
                'appversion'    => $device->appversion
            ];
            $project->update($params);
        }

        $message = array();
        $message['code'] = true;
        $message['msg'] = 'Project created successfully';
        return $message;
    }
    else{



        $message = array();
        $message['code'] = false;
        $message['msg'] = $v->errors()->all();
        return $message;
    }
}