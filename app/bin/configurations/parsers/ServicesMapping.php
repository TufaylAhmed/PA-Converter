<?php

namespace PaloaltoNetworks\Parsers\Utils;

class ServicesMapping
{
    /**
     * Return a map with all predefined services for given vendor
     * Map contains an array of structure ['name' => $name, 'protocol' => $protocol, 'dport' => $port, 'sport' => $sport];
     * @param string $vendor
     * @return array
     */
    private static function getPredefinedServices(string $vendor): array
    {
        $service_list = [];
        $service_mapping_file_path = INC_ROOT . "/contents/parsers/$vendor - services.csv";
        $service_mapping_file_content = file_get_contents($service_mapping_file_path);
        $service_mapping_lines = explode(PHP_EOL, $service_mapping_file_content);
        foreach ($service_mapping_lines as $line) {
            //$fields = explode(",", $service);
            $fields = str_getcsv($line); // [name, protocol, dport, sport]

            foreach ($fields as &$field) {
                $field = trim($field);
                $field = self::removeQuotes($field);
            }

            if (!isset($fields[3])) {
                $fields[3] = '';
            }

            if (!isset($fields[4])) {
                $fields[4] = '';

            }

            if (!self::validateCSVRow($fields[0], $fields[1], $fields[2], $fields[3])) {
                continue;
            }
            $service_list[] = self::preparePredefinedService($fields[0], $fields[1], $fields[2], $fields[3]);
        }

        return $service_list;
    }

    /**
     * Return true if given string is a valid port
     * @param string $value
     * @return bool
     */
    private static function regexPortRule(string $value): bool
    {
        $valid = false;
        $expression = "/^([0-9]{1}([0-9]|[-]|[,])*)$/";
        if ((bool)preg_match($expression, $value)) {
            $valid = true;
            $expression2 = "/^(?<start>[0-9]{1}([0-9])*)-(?<end>[0-9]{1}([0-9])*)$/";
            if ((bool)preg_match($expression2, $value, $output_array)) {
                if ($output_array['start'] > $output_array['end']) {
                    $valid = false;
                }
            }
        }

        return $valid;
    }

    /**
     * Return true if given parameters could be added to the predefined services map
     * @param string $name
     * @param string $protocol
     * @param string $dport
     * @param string $sport
     * @param string $application
     * @return bool
     */
    private static function validateCSVRow(string $name, string $protocol, string $dport, string $sport = '', string $application = ''): bool
    {
        if (strtolower($name) === 'name') {
            // is header row
            return false;
        }

        if ($dport !== '') {
            // not valid port number
            return self::regexPortRule($dport);
        }

        if ($sport !== '') {
            // not valid port number
            return self::regexPortRule($sport);
        }

        return true;
    }

    /**
     * Return a prepared array given the predefined service values
     *
     * @param string $name
     * @param string $protocol
     * @param string $port
     * @param string $sport
     * @return string[]
     */
    private static function preparePredefinedService(string $name, string $protocol, string $port, string $sport = ''): array
    {
        return ['name' => $name, 'protocol' => $protocol, 'dport' => $port, 'sport' => $sport];
    }

    /**
     * Return the resulting normalized input string
     *
     * @param string $name_to_normalize
     * @param string $type
     * @return string
     */
    private static function normalizeNames(string $name_to_normalize, string $type):string
    {

        $name_to_normalize = preg_replace("/[\/]+/", "_", $name_to_normalize);
        $name_to_normalize = preg_replace("/[^a-zA-Z0-9-_. ]+/", "", $name_to_normalize);
        $name_to_normalize = preg_replace("/[\s]+/", " ", $name_to_normalize);

        if ($type === "vsys") {
            $length = strlen($name_to_normalize);
            $check = 31;

            if ($length <= $check) {
                return $name_to_normalize;
            }

            return substr($name_to_normalize, 0, $check);

        }
        return $name_to_normalize;
    }

    /**
     * Return a map with all predefined service groups for given vendor
     * Map contains an array of structure ["group_name", "member1, member2, member3"];
     * @param string $vendor
     * @return array
     */
    private static function getPredefinedServiceGroups(string $vendor): array
    {
        $service_array_list = [];

        $csv_data = file_get_contents(INC_ROOT . "/contents/parsers/$vendor - groups.csv");
        $lines = explode(PHP_EOL, $csv_data);
        foreach ($lines as $line) {

            $split_line = str_getcsv($line);
            if (strtolower($split_line[0]) === 'name') {
                // is the header line do not add to the $service_array_list
                continue;
            }
            $service_array_list[] = $split_line;
        }
        return $service_array_list;
    }

    /**
     * Return a normalized input string without parenthesis
     * @param string $value
     * @return string
     */
    private static function removeParenthesis(string $value): string
    {
        return str_replace(
            array('(', ')'),
            '',
            $value);
    }

    /**
     * Return a normalized input string without quotes
     * @param string $value
     * @return string
     */
    private static function removeQuotes(string $value): string
    {
        return str_replace('"', "", $value);
    }

    /***
     * @param \mysqli $project_db
     * @param STRING $vsys
     * @param INT $source
     * @param STRING|null $format
     * @return array
     */
    private static function getVsyses(\mysqli $project_db, STRING $vsys, INT $source, STRING $format=null):array{
        $vsys = self::normalizeNames($vsys,"vsys");
        $vsyses = array();
        $all_vsys_list = array();

        $query = "SELECT dm.vsys, dg.device_mapping_id as kidID, parent_dg as parentID
              FROM device_mapping dm, devicegroups dg 
              WHERE dm.id = dg.device_mapping_id AND dg.source = '$source'; ";

        $result = $project_db->query($query);
        if ($result->num_rows>0){
            while($device_mapping_data = $result->fetch_assoc()) {
                $all_vsys_list[$device_mapping_data['kidID']] = [
                    'id' => $device_mapping_data['kidID'],
                    'name' => $device_mapping_data['vsys'],
                    'parentID' => (int)$device_mapping_data['parentID']
                ];
            }
        }

        $parent_id = 0;
        foreach ($all_vsys_list as $vsysItem){
            if($vsysItem['name'] === $vsys) {
                $parent_id = $vsysItem['parentID'];
                break;
            }
        }

        //Check it is not a NON PANOS device. In such a case, we will return all the vsys, but not the vsys all, so they are correctly sorted
        if($vsys==='all' && count($all_vsys_list)===0){
            {
                $query = "select vsys from device_mapping;";
                $vsysResult = $project_db->query($query);
                while($device_mapping_data = $vsysResult->fetch_assoc()){
                    $vsyses[] = $device_mapping_data['vsys'];
                }
            }
        }

        else {
            if (isset($format) && $format = 'quoted') {
                $vsyses[] = "'$vsys'";
            } else {
                $vsyses[] = $vsys;
            }


            while ($parent_id !== 0) {
                if (isset($format) && $format = 'quoted') {
                    $vsyses[] = "'" . $all_vsys_list[$parent_id]['name'] . "'";
                } else {
                    $vsyses[] = $all_vsys_list[$parent_id]['name'];
                }
                $parent_id = $all_vsys_list[$parent_id]['parentID'];

            }

            if (!in_array('shared', $vsyses)) {
                if (isset($format) && $format = 'quoted') {
                    $vsyses[] = "'shared'";
                } else {
                    $vsyses[] = 'shared';
                }
            }
        }
        return $vsyses;
    }

    /**
     * Return a prepared statement insert query to load all predefined services for given vendor into the db
     * @param \mysqli $project_db
     * @param string $vendor
     * @param string $source
     * @param string $vsys
     * @param int $srv_lid
     * @return void
     */
    public static function addPredefinedServices(\mysqli $project_db, string $vendor, string $source, string $vsys, int &$srv_lid)
    {

        $service_list = self::getPredefinedServices($vendor);
        if (!empty($service_list)) {
            $add_srv = [];
            foreach ($service_list as $item) {
                $name = self::normalizeNames($item['name'], "");
                $sport = trim($item['sport'] ?? '');
                $dport = trim($item['dport']);
                $protocol = trim($item['protocol']);
                $add_srv[] = "('" . $srv_lid++ . "', 
                        '$source', 
                        '$vsys', 
                        '$name', 
                        '$name', 
                        '$protocol', 
                        '$sport',
                        '$dport',
                        'default'
                       )";

                // Stonesoft could have services by defined CSV service name or name could start by "Shared Domain *"
                // We are creating both services on the db
                if ($vendor === "stonesoft") {
                    $shared_name = self::removeParenthesis("Shared Domain- " . $name);
                    $add_srv[] = "('" . $srv_lid++ . "', 
                        '$source', 
                        '$vsys', 
                        '$shared_name', 
                        '$shared_name', 
                        '$protocol', 
                        '$sport',
                        '$dport',
                        'default'
                       )";
                    unset($shared_name);
                }
                unset($name, $sport, $dport);
            }

            $append_query = implode(",", $add_srv);
            $query = "INSERT INTO services (id,source,vsys, name_ext,name,protocol,sport,dport,devicegroup) VALUES " . $append_query . ";";
            $project_db->query($query);
            unset($add_srv, $service_list);
        }

    }

    /**
     * Return a prepared statement insert query to load all predefined service groups and their relationships for given vendor into the db
     * also creates missing member services to assure groups are correct
     * @param \mysqli $project_db
     * @param string $vendor
     * @param string $source
     * @param string $vsys
     * @param int $srv_group_id
     * @param array $objects_in_memory
     */
    public static function addPredefinedServiceGroups(\mysqli $project_db, string $vendor, string $source, string $vsys, int &$srv_group_id, array &$objects_in_memory = [])
    {

        $service_group_list = self::getPredefinedServiceGroups($vendor);

        if (!empty($service_group_list)) {

            $add_group = [];
            $add_group_relation = [];

            foreach ($service_group_list as $item) {
                $name = self::normalizeNames($item[0], "");

                $members = explode(",", $item[1]);
                $add_group[] = "('" . $srv_group_id . "', 
                        '$source', 
                        '$vsys', 
                        '" . $name . "', 
                        '" . $name . "',
                        'default'
                       )";

                foreach ($members as $member_name) {
                    $member_name = trim($member_name);
                    $service_id = 0;
                    $table_name = '';

                    if (!self::searchOrCreateService($project_db, $member_name, $vsys, $source, $service_id, $table_name, $objects_in_memory)) {
                        // search for an existing service and return the service_id or create it and return the created service_id
                    }
                    $add_group_relation[] = "('$source', '$vsys','$srv_group_id','$member_name','$table_name','$service_id')";
                }

                $srv_group_id++;

                if ($vendor === "stonesoft") {

                    $shared_name = self::removeParenthesis("Shared Domain- " . $name);
                    $add_group[] = "('" . $srv_group_id . "', 
                        '$source', 
                        '$vsys', 
                        '" . $shared_name . "', 
                        '" . $shared_name . "', 
                        'default'
                       )";

                    foreach ($members as $member_name) {
                        $member_name = trim($member_name);
                        $member_name = self::removeParenthesis("Shared Domain- " . $member_name);
                        $service_id = 0;
                        $table_name = '';

                        if (!self::searchOrCreateService($project_db, $member_name, $vsys, $source, $service_id, $table_name, $objects_in_memory)) {
                            // search for an existing service and return the service_id or create it and return the created service_id
                        }
                        $add_group_relation[] = "('$source', '$vsys','$srv_group_id','$member_name','$table_name','$service_id')";
                    }

                    $srv_group_id++;
                }

            }


            $append_query = implode(",", $add_group);
            // Insert into group definition table
            $query = "INSERT INTO services_groups_id (id,source,vsys, name_ext,name,devicegroup) VALUES " . $append_query . ";";
            $project_db->query($query);
            unset($append_query);

            $append_query = implode(",", $add_group_relation);
            // Insert into service_group_relation table
            $query = "INSERT INTO services_groups (source,vsys,lid,member,table_name,member_lid) VALUES " . $append_query . ";";
            $project_db->query($query);

            unset($add_group, $add_group_relation, $append_query);

        }
    }

    /**
     * Looks for a service or servicegroup name in the resources. First will check the memory space and if it is not provided, will check the database
     * @param string $object_name
     * @param string $vsys
     * @param int $source
     * @param int $lid
     * @param string $table
     * @global \mysqli $project_db
     */
    public static function searchOrCreateService(\mysqli $project_db, string $service_name, string $vsys, int $source, int &$lid, string &$table, array &$objects_in_memory): bool
    {

        $vsyses = self::getVsyses($project_db, $vsys, $source);
        $service_name = self::normalizeNames($service_name, "");

        //Look for the service in objects in memory
        foreach ($vsyses as $local_vsys) {
            $local_vsys = self::normalizeNames($local_vsys, "vsys");
            if (isset($objects_in_memory['services'][$local_vsys][$service_name])) {
                $lid = $objects_in_memory['services'][$local_vsys][$service_name]['id'];
                $table = 'services';
                return true;
            }

            if (isset($objects_in_memory['services_groups_id'][$local_vsys][$service_name])) {
                $lid = $objects_in_memory['services_groups_id'][$local_vsys][$service_name]['id'];
                $table = 'services_groups_id';
                return true;
            }
        }

        //Maybe it is not in objects in memory, but it is in the database. Search for it and complete the objectsInMemory
        foreach ($vsyses as $local_vsys) {
            $query = "SELECT id, dport FROM services WHERE source = '$source' AND vsys='$local_vsys' AND name = '$service_name' LIMIT 1";
            $result = $project_db->query($query);
            if ($result->num_rows == 0) {
                continue;
            }
            $service_data = $result->fetch_assoc();
            $objects_in_memory['services'][$local_vsys][$service_name] = [
                'id' => $service_data['id'],
                'dport' => $service_data['dport']
            ];
            $lid = $service_data['id'];
            $table = 'services';
            return true;
        }


        //The object was not found. Let's create it with a warning
        $query = "INSERT INTO services (name, name_ext, checkit, used, vsys, devicegroup, type, description, sport, dport, protocol, source,invalid, modified, dummy ) 
              VALUE ('$service_name','$service_name',1,1,'$vsys','MT1','service','Object automatically generated because was not found','','65000','tcp',$source,1,0,0)";
        $project_db->query($query);
        $lid = $project_db->insert_id;
        $objects_in_memory['services'][$vsys][$service_name]['id'] = $lid;
        $objects_in_memory['services'][$vsys][$service_name]['validity'] = false;
        $table = "services";

        return false;
    }


    /**
     * Create predefined services, services groups and their relations
     *
     * @param \mysqli $projectdb
     * @param string $vendor
     * @param string $source
     * @param string $vsys
     * @return void
     */
    public static function addPredefinedSrvAndSrvGroups(\mysqli $projectdb, string $vendor, string $source, string $vsys)
    {

        #Get Last lid from Services
        $max_query = $projectdb->query("SELECT max(id) as max FROM services;");
        $max_query_data = $max_query->fetch_assoc();
        $next_srv_id = (int)$max_query_data['max'] + 1;

        self::addPredefinedServices($projectdb, $vendor, $source, $vsys, $next_srv_id);

        #Get Last lid from Services_Groups
        $max_query = $projectdb->query("SELECT max(id) as max FROM services_groups_id;");
        $max_query_data = $max_query->fetch_assoc();
        $next_srv_grp_id = (int)$max_query_data['max'] + 1;

        self::addPredefinedServiceGroups($projectdb, $vendor, $source, $vsys, $next_srv_grp_id);


    }
}