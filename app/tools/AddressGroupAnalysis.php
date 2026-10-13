<?php

class AddressGroupAnalysis
{
    public function print_entry(string $project):string{
        $total_count = $contain_1_member = $changed_count = $dup_count = $unique_count =
        $dynamic_count  = $dup_cases_count = $unique_used_count =
                $unused = $dup_max = $dup_min = $dup_avg = $dup_std = 0;
        if($projectdb = selectDatabase($project)) {
            $total_count = $this->getTotal($projectdb);
            $contain_1_member = $this->count_contain_1_member($projectdb);
            $dynamic_count = $this->count_isDynamic($projectdb);
            $changed_count = $this->count_isChanged($projectdb, "CHG");
            $dup_analysis = $this->get_duplicates($projectdb);
            $unique_count = $dup_analysis['unique'];
            $unique_used_count = $dup_analysis['unique_used'];
            $dup_count = $dup_analysis['entries'];
            $dup_cases_count = $dup_analysis['cases'];
            $dup_max = $dup_analysis['max'];
            $dup_min = $dup_analysis['min'];
            $dup_avg = $dup_analysis['avg'];
            $dup_std = $dup_analysis['std'];
//            $unique_count = $this->count_isUnique($projectdb);
//            $dup_value_count = $this->count_isDupValue($projectdb);
            $unused = $this->count_isUnused($projectdb);
        }

        return json_encode([
                'Project'=> $project,
                'total' => $total_count,

                'are_unique' => $unique_count,
                'are_unique_pct' => $unique_count/$total_count*100,
                'are_unique_used' => $unique_used_count,
                'are_unique_used_perc' => $unique_used_count/$total_count*100,

                'contain_1_member' => $contain_1_member,
                'contain_1_member_pct' => $contain_1_member/$total_count*100,
                'are_dynamic' => $dynamic_count,
                'are_dynamic_pct' => $dynamic_count/$total_count*100,
                'are_changed' => $changed_count,
                'are_changed_pct' => $changed_count/$total_count*100,

                'are_duplicate_entries' => $dup_count,
                'are_duplicate_entries_pct' => $dup_count/$total_count*100,
                'redundant_max' => $dup_max,
                'redundant_min' => $dup_min,
                'redundant_avg' => $dup_avg,
                'redundant_std' => $dup_std,

                'cases_with_duplicate_value' => $dup_cases_count,

                'are_unused' => $unused,
                'are_unused_pct' => $unused/$total_count*100
            ]).PHP_EOL;
    }


    public function get_duplicates(mysqli $projectdb):array{
        //Collecting all the objects, so they can be referenced in groups
        $q_members = "(SELECT name, concat('address-',id) as location
                FROM address)
                UNION
                (SELECT name, concat('address_groups_id-',id) as location
                FROM address_groups_id)";
        $result = $projectdb->query($q_members);
        $members = [];
        while($data = $result->fetch_assoc()){
            $members[$data['location']] = $data;
        }

        //Collecting all the groups to be studied
        $q_groups = "SELECT ag.lid as lid, CONCAT(table_name,'-',member_lid) as member
            FROM address_groups ag
        ";

        $groups = [];
        $result = $projectdb->query($q_groups);
        while($data = $result->fetch_assoc()){
            $groups[$data['lid']]['members'][] = $data['member'];
        }

        //Collecting all the groups usage
        $used_groups = [];
        $q_groups_usage = "SELECT ag.id as lid, used
            FROM address_groups_id ag
            WHERE ag.used=1
        ";
        $result = $projectdb->query($q_groups_usage);
        while($data = $result->fetch_assoc()){
            $used_groups[] = $data['lid'];
        }


        //resolving the members in each group to their names
        foreach ($groups as $lid => &$group){
            $members_count = 0;
            foreach($group['members'] as $member){
                $group['members_names'][] = $members[$member]['name'];
                unset($group['members']);
                $members_count++;
            }

            sort($group['members_names']);
            $group['hash'] = md5(implode(',',$group['members_names']));
            $group['id'] = $lid;
        }
        unset($group);

        //Grouping by hash duplicates
        $groups_by_value = [];
        foreach ($groups as $group){
            $groups_by_value[$group['hash']][] = $group['id'];
        }

        $number_unique = count($groups_by_value);

        $have_duplicates = [];
        $num_members = [];
        $number_unique_used = 0;
        foreach ($groups_by_value as $hash=>$group){
            if(count($group)>1){
                $have_duplicates[$hash]=$group;
                $num_members[] = count($group);
            }
            foreach($group as $group_instance){
                if(in_array($group_instance, $used_groups)){
                    $number_unique_used++;
                    break;
                }
            }
        }

        if(count($num_members)>0) {
            $min = min($num_members);
            $max = max($num_members);
            $avg = array_sum($num_members) / count($num_members);
            $std = $this->stats_standard_deviation($num_members);
            $entries = array_sum($num_members);
        }
        else{
            $min = 0;
            $max = 0;
            $avg = 0;
            $std = 0;
            $entries = 0;
        }
        return [
            'unique' => $number_unique,
            'unique_used' => $number_unique_used,
            'cases' => count($have_duplicates),
            'entries' => $entries,
            'min' => $min,
            'max' => $max,
            'avg' => $avg,
            'std' => $std,
        ];
    }

    public function count_isDynamic(mysqli $projectdb):int{
        $q_unused = "SELECT count(id) as entries FROM address_groups_id WHERE type='dynamic';";
        return $this->get_count($projectdb, $q_unused);

    }

    public function count_isUnused(mysqli $projectdb):int{
        $q_unused = "SELECT count(id) as entries FROM address_groups_id WHERE used=0;";
        return $this->get_count($projectdb, $q_unused);
    }


    public function count_isChanged(mysqli $projectdb, string $change_name):int{
        $q_CHG_addresses = "SELECT count(*) as entries FROM address_groups_id sr where description like '$change_name%';";
        return $this->get_count($projectdb, $q_CHG_addresses);

    }

    public function getTotal(mysqli $projectb):int{
        $q_total_addresses = "SELECT count(*) as entries FROM address_groups_id;";
        return $this->get_count($projectb, $q_total_addresses);
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
                            ) as duplicates";
        $query_connection = $projectdb->query($q_dup_entries);
        if($query_connection->num_rows>0){
            return $query_connection->fetch_assoc();
        }

        return ['entries' => 0, 'max' => 'NAN','min'=> 'NAN','avg' => 'NAN', 'std'=>'NAN'];
    }

    public function count_isUnique(mysqli $projectdb): int{
        $q_unique_addresses = "SELECT count(*) as entries FROM
                                ( SELECT * FROM
                                (SELECT concat(ipaddress,'/',cidr) as value FROM address ) as t
                                GROUP BY value) as unique_values;";
        return $this->get_count($projectdb, $q_unique_addresses);
    }

    public function count_contain_1_member(mysqli $projectdb):int{
        $q_IP_addresses = "SELECT count(*) as entries FROM (
                    SELECT address_groups_id.id, count(*) as num_members 
                    FROM address_groups_id, address_groups
                    WHERE
                      address_groups_id.id = address_groups.lid
                    GROUP BY address_groups_id.id    
                    HAVING num_members = 1
                    ) t
                    ;";

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

    private function stats_standard_deviation(array $a, $sample = false) {
        $n = count($a);
        if ($n === 0) {
            trigger_error("The array has zero elements", E_USER_WARNING);
            return false;
        }
        if ($sample && $n === 1) {
            trigger_error("The array has only 1 element", E_USER_WARNING);
            return false;
        }
        $mean = array_sum($a) / $n;
        $carry = 0.0;
        foreach ($a as $val) {
            $d = ((double) $val) - $mean;
            $carry += $d * $d;
        };
        if ($sample) {
            --$n;
        }
        return sqrt($carry / $n);
    }
}