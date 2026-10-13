<?php

class ServiceAnalysis
{
    public function print_entry(string $project):string {
        $total_count  = $changed_count = $dup_count = $unique_count =
            $protocol_port_count = $named_count = $dup_value_count = $dup_H_name_count =
                $unused = $dup_max = $dup_min = $dup_avg = $dup_std = $unique_used_count= 0;
        if($projectdb = selectDatabase($project)) {
            $total_count = $this->getTotal($projectdb);
            $protocol_port_count = $this->count_isProtocol_Port($projectdb);
            $changed_count = $this->count_isChanged($projectdb, "CHG");
            $dup_analysis = $this->count_DupEntries($projectdb);
            $dup_count = $dup_analysis['entries'];
            $dup_max = $dup_analysis['max'];
            $dup_min = $dup_analysis['min'];
            $dup_avg = $dup_analysis['average'];
            $dup_std = $dup_analysis['std'];
            $named_count = $this->count_isNamed($projectdb);
            $unique_count = $this->count_isUnique($projectdb);
            $unique_used_count = $this->count_isUniqueUsed($projectdb);
            $dup_value_count = $this->count_isDupValue($projectdb);
            $dup_H_name_count = $this->count_isPortProtocol_and_Named_Duplicate($projectdb);
            $unused = $this->count_isUnused($projectdb);
        }

        return json_encode([
                'Project'=> $project,
                'total' => $total_count,

                'are_unique' => $unique_count,
                'are_unique_perc' => $unique_count/$total_count*100,
                'are_unique_used' => $unique_used_count,
                'are_unique_used_perc' => $unique_used_count/$total_count*100,

                'are_protocol_port' => $protocol_port_count,
                'are_protocol_port_perc' => $protocol_port_count/$total_count*100,
                'are_named' => $named_count,
                'are_named_perc' => $named_count/$total_count*100,

                'are_changed' => $changed_count,
                'are_changed_perc' => $changed_count/$total_count*100,

                'are_duplicate_entries' => $dup_count,
                'are_duplicate_entries_perc' => $dup_count/$total_count*100,
                'redundant_max' => $dup_max,
                'redundant_min' => $dup_min,
                'redundant_avg' => $dup_avg,
                'redundant_std' => $dup_std,

                'cases_with_duplicate_value' => $dup_value_count,
                'cases_with_duplicate_Port_and_name' => $dup_H_name_count,

                'are_unused' => $unused,
                'are_unused_perc' => $unused/$total_count*100
            ]).PHP_EOL;
    }

    public function count_isUnused(mysqli $projectdb):int{
        $q_unused = "SELECT count(id) as entries FROM services WHERE used=0;";
        return $this->get_count($projectdb, $q_unused);
    }

    public function count_isChanged(mysqli $projectdb, string $change_name):int{
        //CHG
        $q_CHG_addresses = "SELECT count(*) as entries FROM services sr where description like '$change_name%';";
        return $this->get_count($projectdb, $q_CHG_addresses);

    }

    public function count_isProtocol_Port(mysqli $projectdb):int{
        $q_H_addresses = "SELECT count(*) as entries
                          FROM services 
                           WHERE 
                               name like 'TCP-%' OR name like 'TCP_%' OR name like 'TCP %' OR name like 'tcp-%' OR name like 'tcp_%' OR name like 'tcp %' OR 
                               name like 'UDP-%' OR name like 'UDP_%' OR name like 'UDP %' OR name like 'udp-%' OR name like 'udp_%' OR name like 'udp %' 
                          ;";

        return $this->get_count($projectdb, $q_H_addresses);
    }

    public function count_isPortProtocol_and_Named_Duplicate(mysqli $projectdb):int{
        $q_H_addresses = "SELECT count(value) as entries FROM (
                SELECT value, sum(is_Port) as is_Port, sum(is_not_Port) as is_not_Port
                FROM
                (
                SELECT name, concat(protocol,'/',dport) as value,
                       if(name like 'TCP-%' OR name like 'TCP_%' OR name like 'TCP %' OR name like 'tcp-%' OR name like 'tcp_%' OR name like 'tcp %' OR 
                               name like 'UDP-%' OR name like 'UDP_%' OR name like 'UDP %' OR name like 'udp-%' OR name like 'udp_%' OR name like 'udp %', 1,0) as is_Port,
                       if(name like 'TCP-%' OR name like 'TCP_%' OR name like 'TCP %' OR name like 'tcp-%' OR name like 'tcp_%' OR name like 'tcp %' OR 
                               name like 'UDP-%' OR name like 'UDP_%' OR name like 'UDP %' OR name like 'udp-%' OR name like 'udp_%' OR name like 'udp %', 0,1) as is_not_Port
                FROM services
                ) t 
                GROUP BY value
                ) t2 
                WHERE is_Port > 0 AND is_not_Port > 0";

        return $this->get_count($projectdb, $q_H_addresses);
    }

    public function getTotal(mysqli $projectb):int{
        $q_total_addresses = "SELECT count(*) as entries FROM services;";
        return $this->get_count($projectb, $q_total_addresses);
    }

    public function count_isNamed(mysqli $projectdb):int{
        $q_named = "SELECT count(*) as entries
                          FROM services 
                           WHERE 
                               name not like 'TCP-%' AND name not like 'TCP_%' AND name not like 'TCP %' AND name not like 'tcp-%' AND name not like 'tcp_%' AND name not like 'tcp %' AND 
                               name not like 'UDP-%' AND name not like 'UDP_%' AND name not like 'UDP %' AND name not like 'udp-%' AND name not like 'udp_%' AND name not like 'udp %' 
                          ;";
        return $this->get_count($projectdb, $q_named);
    }

    public function count_isDupValue(mysqli $projectdb):int{
        $q_dup_value = "SELECT count(*) as entries FROM (
                SELECT value, count(*) as amount FROM
                (SELECT concat(sport,'/',protocol,'/',dport) as value FROM services ) as t
                GROUP BY value
                HAVING amount > 1
                ) as duplicated_values;";

        return $this->get_count($projectdb, $q_dup_value);
    }

    public function count_DupEntries(mysqli $projectdb):array{
        $q_dup_entries = "SELECT count(*) as entries, max(amount) as max, min(amount) as min, avg(amount) as average, std(amount) as std 
FROM 
(SELECT value, amount FROM (
                SELECT value, count(*) as amount FROM
                (SELECT concat(sport,'/',protocol,'/',dport) as value FROM services ) as t
                GROUP BY value
                HAVING amount > 1
                ) as duplicated_values ) duplicates";

        $query_connection = $projectdb->query($q_dup_entries);
        if($query_connection->num_rows>0){
            return $query_connection->fetch_assoc();
        }

        return ['entries' => 0, 'max' => 0,'min'=> 0,'avg' => 0, 'std'=>0];

    }

    public function count_isUniqueUsed(mysqli $projectdb):int {
        $q_unique_used = "SELECT count(*) as entries FROM
                                    ( SELECT *, sum(used) as general_used FROM
                                         (SELECT concat(sport,'/',protocol,'/',dport) as value, used 
                                          FROM services ) as t
                                      GROUP BY value
                                      HAVING general_used > 0
                                    ) as unique_values;";
        return $this->get_count($projectdb, $q_unique_used);
    }

    public function count_isUnique(mysqli $projectdb): int{
        $q_unique_addresses = "SELECT count(*) as entries FROM
                                ( SELECT * FROM
                                (SELECT concat(sport,'/',protocol,'/',dport) as value FROM services ) as t
                                GROUP BY value) as unique_values;";
        return $this->get_count($projectdb, $q_unique_addresses);
    }

    public function count_isIp(mysqli $projectdb):int{
        $q_IP_addresses = "SELECT COUNT(*) as entries
                            FROM (
                            SELECT
                            name,
                            if( LOCATE('-',name)>0, SUBSTRING(name, 1, LOCATE('-', name)-1),
                            if( LOCATE('/',name)>0, SUBSTRING(name, 1, LOCATE('/', name)-1),
                            if( LOCATE('_',name)>0, SUBSTRING(name, 1, LOCATE('_', name)-1), name)
                            )
                            ) as cleaned,
                            is_ipv4(name)
                            FROM address
                            -- WHERE name not like 'H-%' and name not like 'H_%' and name not like 'N_%' and name not like 'N-%'
                            HAVING is_ipv4(cleaned)=1
                            ) as t;";

        return $this->get_count($projectdb, $q_IP_addresses);
    }

    private function get_count(mysqli $projectdb, string $query):int{
        $query_connection = $projectdb->query($query);
        if($query_connection->num_rows>0){
            $data_row = $query_connection->fetch_assoc();
            return $data_row['entries'];
        }

        return 0;
    }
}