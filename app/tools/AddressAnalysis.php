<?php

class AddressAnalysis
{
    public function print_entry(string $project, string $change_prefix):string{
        $total_count = $IP_count = $changed_count = $dup_count = $unique_count = $unique_used_count =
            $h_n_count = $named_count = $dup_value_count = $dup_H_name_count =
                $unused = $dup_max = $dup_min = $dup_avg = $dup_std = 0;
        if($projectdb = selectDatabase($project)) {
            $total_count = $this->getTotal($projectdb);
            $IP_count = $this->count_isIp($projectdb);
            $changed_count = $this->count_isChanged($projectdb, $change_prefix);
            $dup_analysis = $this->count_DupEntries($projectdb);
            $dup_count = $dup_analysis['entries'];
            $dup_max = $dup_analysis['max'];
            $dup_min = $dup_analysis['min'];
            $dup_avg = $dup_analysis['average'];
            $dup_std = $dup_analysis['std'];
            $named_count = $this->count_isNamed($projectdb);
            $h_n_count = $this->count_isH_N($projectdb);
            $unique_count = $this->count_isUnique($projectdb);
            $unique_used_count = $this->count_isUniqueUsed($projectdb);
            $dup_value_count = $this->count_isDupValue($projectdb);
            $dup_H_name_count = $this->count_isH_N_and_Named_Duplicate($projectdb);
            $unused = $this->count_isUnused($projectdb);
        }

        return json_encode([
                'Project'=> $project,
                'total' => $total_count,

                'are_unique' => $unique_count,
                'are_unique_perc' => $unique_count/$total_count*100,
                'are_unique_used' => $unique_used_count,
                'are_unique_used_perc' => $unique_used_count/$total_count*100,

                'are_ips' => $IP_count,
                'are_ips_perc' => $IP_count/$total_count*100,
                'are_h_n' => $h_n_count,
                'are_h_n_perc' => $h_n_count/$total_count*100,
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
                'cases_with_duplicate_H_and_name' => $dup_H_name_count,

                'are_unused' => $unused,
                'are_unused_perc' => $unused/$total_count*100
            ]).PHP_EOL;
    }


    public function count_isUnused(mysqli $projectdb):int{
        $q_unused = "SELECT count(id) as entries FROM address WHERE used=0;";
        return $this->get_count($projectdb, $q_unused);
    }


    public function count_isChanged(mysqli $projectdb, string $change_name):int{
        //CHG
        $q_CHG_addresses = "SELECT count(*) as entries FROM address sr where description like '$change_name%';";
        return $this->get_count($projectdb, $q_CHG_addresses);

    }

    public function count_isH_N(mysqli $projectdb):int{
        $q_H_addresses = "SELECT count(*) as entries 
                          FROM address 
                           WHERE 
                               name like 'H-%' OR name like 'H_%' OR name like 'N_%' OR name like 'N-%' OR
                               name like 'h-%' OR name like 'h_%' OR name like 'n_%' OR name like 'n-%'
                          ;";

        return $this->get_count($projectdb, $q_H_addresses);
    }

    public function count_isH_N_and_Named_Duplicate(mysqli $projectdb):int{
        $q_H_addresses = "SELECT count(value) as entries FROM (
                SELECT value, sum(is_H) as is_H, sum(is_not_H) as is_not_H
                FROM
                (
                SELECT name, concat(ipaddress,'/',cidr) as value,
                       if(name like 'H-%' OR name like 'H_%' OR name like 'N_%' OR name like 'N-%' OR name like 'h-%' OR name like 'h_%' OR name like 'n_%' OR name like 'n-%', 1,0) as is_H,
                       if(name like 'H-%' OR name like 'H_%' OR name like 'N_%' OR name like 'N-%' OR name like 'h-%' OR name like 'h_%' OR name like 'n_%' OR name like 'n-%', 0,1) as is_not_H
                FROM address
                ) t 
                GROUP BY value
                ) t2 
                WHERE is_H > 0 AND is_not_H > 0";

        return $this->get_count($projectdb, $q_H_addresses);
    }

    public function getTotal(mysqli $projectb):int{
        $q_total_addresses = "SELECT count(*) as entries FROM address;";
        return $this->get_count($projectb, $q_total_addresses);
    }

    public function count_isNamed(mysqli $projectdb):int{
        $q_named_addresses = "SELECT COUNT(*)  as entries FROM (
                SELECT
                name,
                if( LOCATE('-',name)>0, SUBSTRING(name, 1, LOCATE('-', name)-1),
                if( LOCATE('/',name)>0, SUBSTRING(name, 1, LOCATE('/', name)-1),
                if( LOCATE('_',name)>0, SUBSTRING(name, 1, LOCATE('_', name)-1), name)
                )
                ) as cleaned,
                is_ipv4(name)
                FROM address 
                WHERE 
                    name not like 'H-%' and name not like 'H_%' and name not like 'N_%' and name not like 'N-%' AND
                    name not like 'h-%' and name not like 'h_%' and name not like 'n_%' and name not like 'n-%' 
                HAVING is_ipv4(cleaned)=0
                ) as t;";
        return $this->get_count($projectdb, $q_named_addresses);
    }

    public function count_isDupValue(mysqli $projectdb):int{
        $q_dup_value_addresses = "SELECT count(*) as entries FROM (
                SELECT value, count(*) as amount FROM
                (SELECT concat(ipaddress,'/',cidr) as value FROM address ) as t
                GROUP BY value
                HAVING amount > 1
                ) as duplicated_values;";

        return $this->get_count($projectdb, $q_dup_value_addresses);
    }

    public function count_DupEntries(mysqli $projectdb):array{
        $q_dup_entries = "SELECT count(*) as entries, max(amount) as max, min(amount) as min, avg(amount) as average, std(amount) as std 
            FROM
            (
                            SELECT value, count(*) as amount FROM
                            (SELECT concat(ipaddress,'/',cidr) as value FROM address ) as t
                            GROUP BY value
                            HAVING amount > 1
                            ) as duplicates ";
        $query_connection = $projectdb->query($q_dup_entries);
        if($query_connection->num_rows>0){
            return $query_connection->fetch_assoc();
        }

        return ['entries' => 0, 'max' => 0,'min'=> 0,'avg' => 0, 'std'=>0];
    }

    public function count_isUniqueUsed(mysqli $projectdb):int{
        $q_unique_used = "SELECT count(*) as entries FROM
                                    ( SELECT *, sum(used) as general_used FROM
                                         (SELECT concat(ipaddress,'/',cidr) as value, used 
                                          FROM address ) as t
                                      GROUP BY value
                                      HAVING general_used > 0
                                    ) as unique_values;";
        return $this->get_count($projectdb, $q_unique_used);
    }

    public function count_isUnique(mysqli $projectdb): int{
        $q_unique_addresses = "SELECT count(*) as entries FROM
                                ( SELECT * FROM
                                (SELECT concat(ipaddress,'/',cidr) as value FROM address ) as t
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