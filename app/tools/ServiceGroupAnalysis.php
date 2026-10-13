<?php

class ServiceGroupAnalysis
{
    public function print_entry(string $project):string{
        $total_count = $contain_1_member = $changed_count = $dup_count = $unique_count =
                $unused = $dup_max = $dup_min = $dup_avg = $dup_std = $dup_cases_count = $unique_used_count =0;
        if($projectdb = selectDatabase($project)) {
            $total_count = $this->getTotal($projectdb);
            $contain_1_member = $this->count_contain_1_member($projectdb);
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
            $unused = $this->count_isUnused($projectdb);
        }

        if($total_count>0){
            return json_encode([
                    'Project'=> $project,
                    'total' => $total_count,

                    'are_unique' => $unique_count,
                    'are_unique_pct' => $unique_count/$total_count*100,
                    'are_unique_used' => $unique_used_count,
                    'are_unique_used_perc' => $unique_used_count/$total_count*100,

                    'contain_1_member' => $contain_1_member,
                    'contain_1_member_pct' => $contain_1_member/$total_count*100,
                    'are_changed' => $changed_count,
                    'are_changed_pct' => $changed_count/$total_count*100,

                    'are_duplicate_entries' => $dup_count,
                    'are_duplicate_entries_pct' => $dup_count/$total_count*100,
                    'redundant_max' => $dup_max,
                    'redundant_min' => $dup_min,
                    'redundant_avg' => $dup_avg,
                    'redundant_std' => $dup_std,

                    'cases_with_duplicate_value' => $dup_cases_count,
                    'cases_with_duplicate_value_pct' => $dup_cases_count/$total_count*100,

                    'are_unused' => $unused,
                    'are_unused_pct' => $unused/$total_count*100
                ]).PHP_EOL;
        }

        return json_encode([
                'Project'=> $project,
                'total' => $total_count,

                'are_unique' => $unique_count,
                'are_unique_pct' => 0,
                'are_unique_used' => $unique_used_count,
                'are_unique_used_perc' => 0,

                'contain_1_member' => $contain_1_member,
                'contain_1_member_pct' => 0,
                'are_changed' => $changed_count,
                'are_changed_pct' => 0,

                'are_duplicate_entries' => $dup_count,
                'are_duplicate_entries_pct' => 0,
                'redundant_max' => $dup_max,
                'redundant_min' => $dup_min,
                'redundant_avg' => $dup_avg,
                'redundant_std' => $dup_std,

                'cases_with_duplicate_value' => $dup_cases_count,
                'cases_with_duplicate_value_pct' => 0,

                'are_unused' => $unused,
                'are_unused_pct' => 0
            ]).PHP_EOL;
    }


    public function get_duplicates(mysqli $projectdb):array{
        //Collecting all the objects, so they can be referenced in groups
        $q_members = "(SELECT name, concat('services-',id) as location
                FROM services)
                UNION
                (SELECT name, concat('services_groups_id-',id) as location
                FROM services_groups_id)";
        $result = $projectdb->query($q_members);
        $members = [];
        while($data = $result->fetch_assoc()){
            $members[$data['location']] = $data;
        }

        //Collecting all the groups to be studied
        $q_groups = "SELECT ag.lid as lid, CONCAT(table_name,'-',member_lid) as member
            FROM services_groups ag
        ";

        $groups = [];
        $result = $projectdb->query($q_groups);
        while($data = $result->fetch_assoc()){
            $groups[$data['lid']]['members'][] = $data['member'];
        }

        //Collecting all the groups usage
        $used_groups = [];
        $q_groups_usage = "SELECT ag.id as lid, used
            FROM services_groups_id ag
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

        if(!empty($num_members)) {
            return [
                'unique' => $number_unique,
                'unique_used' => $number_unique_used,
                'cases' => count($have_duplicates),
                'entries' => array_sum($num_members),
                'min' => min($num_members),
                'max' => max($num_members),
                'avg' => array_sum($num_members) / count($num_members),
                'std' => $this->stats_standard_deviation($num_members),
            ];
        }

        return [
            'unique' => $number_unique,
            'unique_used' => $number_unique_used,
            'cases' => 0,
            'entries' => 0,
            'min' => '0',
            'max' => '0',
            'avg' => '0',
            'std' => '0',
        ];

    }

    public function count_isUnused(mysqli $projectdb):int{
        $q_unused = "SELECT count(id) as entries FROM services_groups_id WHERE used=0;";
        return $this->get_count($projectdb, $q_unused);
    }


    public function count_isChanged(mysqli $projectdb, string $change_name):int{
        $q_CHG = "SELECT count(*) as entries FROM services_groups_id sr where description like '$change_name%';";
        return $this->get_count($projectdb, $q_CHG);

    }

    public function getTotal(mysqli $projectb):int{
        $q_total = "SELECT count(*) as entries FROM services_groups_id;";
        return $this->get_count($projectb, $q_total);
    }



    public function count_contain_1_member(mysqli $projectdb):int{
        $q_contain_1_member = "SELECT count(*) as entries FROM (
                    SELECT services_groups_id.id, count(*) as num_members 
                    FROM services_groups_id, services_groups
                    WHERE
                      services_groups_id.id = services_groups.lid
                    GROUP BY services_groups_id.id    
                    HAVING num_members = 1
                    ) t
                    ;";

        return $this->get_count($projectdb, $q_contain_1_member);
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