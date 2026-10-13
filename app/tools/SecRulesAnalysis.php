<?php

class SecRulesAnalysis
{
    public function print_entry(string $project, string $change_name):string{
        $total_count = $disabled_count = $l4_count = $duplicated_count = $dgs_with_dups_count = $changed_count = 0;
        if($projectdb = selectDatabase($project)) {
            $total_count = $this->get_total($projectdb);
            $disabled_count = $this->get_disabled($projectdb);
            $l4_count = $this->get_L4($projectdb);
            $duplicated_count = $this->get_dup_entries($projectdb);
            $dgs_with_dups_count = $this->get_DGs_with_dups($projectdb);
            $changed_count = $this->count_isChanged($projectdb, $change_name);
        }


        return json_encode([
                'Project'=> $project,
                'total' => $total_count,
                'are_l4' => $l4_count,
                'are_disabled' => $disabled_count,
                'are_duplicated' => $duplicated_count,
                'dgs_with_dups' => $dgs_with_dups_count,
                'are_changed' => $changed_count,
            ]).PHP_EOL;
    }

    public function count_isChanged(mysqli $projectdb, string $change_name):int{
        //CHG
        $q_CHG_addresses = "SELECT count(*) as entries FROM security_rules sr where description like '$change_name%';";
        return $this->get_count($projectdb, $q_CHG_addresses);

    }


    public function get_DGs_with_dups(mysqli $projectdb):int{
        //CHG
        $q_dgs_with_dups = "SELECT count(distinct vsys)  as entries FROM security_rules sr2 WHERE name in (
            SELECT name FROM (
            SELECT name, count(*) as amount FROM security_rules sr GROUP by name HAVING amount>1
            ) as duplicated_rules_names
            ) ;";
        return $this->get_count($projectdb, $q_dgs_with_dups);

    }


    public function get_disabled(mysqli $projectdb):int{
        //CHG
        $q_disabled = "SELECT count(*)  as entries FROM security_rules sr where disabled =1;";
        return $this->get_count($projectdb, $q_disabled);

    }

    public function get_total(mysqli $projectb):int{
        $q_total = "SELECT count(*)  as entries FROM security_rules sr;";
        return $this->get_count($projectb, $q_total);
    }

    public function get_L4(mysqli $projectdb):int{
        $q_l4 = "SELECT count(*)  as entries FROM security_rules sr WHERE id NOT in (SELECT rule_lid FROM security_rules_app sra);";
        return $this->get_count($projectdb, $q_l4);
    }

    public function get_dup_entries(mysqli $projectdb):int{
        $q_dup_entries = "SELECT count(*) as entries FROM (
                SELECT name, count(*) as amount FROM security_rules sr GROUP by name HAVING amount>1
                ) as duplicated_rules_names;";
        return $this->get_count($projectdb, $q_dup_entries);
    }

    private function get_count(mysqli $projectdb, string $query):int{
        $query_connection = $projectdb->query($query);
        if($query_connection->num_rows>0){
            $data_row = $query_connection->fetch_assoc();
            return $data_row['entries'];
        }

        return 0;
    }


    public function name_quality(mysqli $projectdb):int{
        $colors = ['#e6194b', '#3cb44b', '#ffe119', '#4363d8', '#f58231', '#911eb4', '#46f0f0', '#f032e6', '#bcf60c', '#fabebe', '#008080', '#e6beff', '#9a6324', '#fffac8', '#800000', '#aaffc3', '#808000', '#ffd8b1', '#000075', '#808080', '#ffffff', '#000000'];
        $nodes_file_name = "./nodes.csv";
        $nodes_file = fopen($nodes_file_name, "w");
        fwrite($nodes_file, "id,dg,rule_name,node_color\n");

        $connections_file_name = "./relations.csv";
        $connections_file = fopen($connections_file_name, "w");
        fwrite($connections_file, "id1,id2,cost\n");

        // Collect all the security rule names, and the DG they belong to.
        // We will study the name quality comparing rule names within the same DG
        $query = "SELECT name, vsys, id FROM security_rules ORDER BY vsys, position;";
        $connection = $projectdb->query($query);
        $rule_names = [];
        while($data = $connection->fetch_assoc()){
            $dg = $data['vsys'];
            $color = (hexdec( substr(md5($dg), 0, 5) )) % (count($colors)-1);
            $id = $data['id'];
            $name = strtoupper($data['name']);
            $rule_names[$dg][] = [
                'cleaned_name' =>str_replace(["-",".","_"],"",$name ),
                'name' =>$name,
                'id' => $id
            ];
            $line = "$id,$dg,$name,$colors[$color]\n";
            fwrite($nodes_file, $line);
        }
        fclose($nodes_file);

        foreach ($rule_names as $dg => $dg_rules){
            $total_rules_in_dg = count($dg_rules);
            foreach ($dg_rules as $name_index => $name){
                if($name_index === $total_rules_in_dg-1){
                    break;
                }
                for($next_name_index = $name_index+1; $next_name_index < $total_rules_in_dg; $next_name_index++ ){
                    $next_name = $dg_rules[$next_name_index];
                    $cost = levenshtein($name['cleaned_name'], $next_name['cleaned_name'], 1, 2, 1)/(strlen($name['name'])*2);
//                    if($cost< 0.3*2)
                        echo "DG: $dg              => ".$name['name']." and ".$next_name['name'].": $cost\n";
                        $line = $name['id'].",".$next_name['id'].",$cost\n";
                        fwrite($connections_file, $line);
                }
            }
        }

        return 0;
    }
}