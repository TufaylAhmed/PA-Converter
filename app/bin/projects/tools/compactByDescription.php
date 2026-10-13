<?php
# Copyright (c) 2019 Palo Alto Networks, Inc.
# All rights reserved.
//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
require_once INC_ROOT.'/userManager/start_CLI.php';
require_once INC_ROOT.'/libs/projectdb.php';

function compactByDescription($project,$source,$vsys,$table_name){
    require_once INC_ROOT.'/libs/common/tools/tools-rules.php';
    global $projectdb;
    global $app;
    $message=['code'=>false, 'msg'=>'Project is not defined' , 'jobid'=>0];

    $projectdb = selectDatabase($project);

    if  (isset($project)){
        $x=0;
        $hashArray=[];
//        $query = "SELECT ids, description, numb
//                    FROM (SELECT GROUP_CONCAT(id) as ids, count(*) as numb, description FROM $table_name WHERE source='$source' AND vsys='$vsys' GROUP BY description) t
//                    WHERE numb > 1 AND description!='';";
//        $getRules=$projectdb->query($query);


        //Get rules with tag DNAT, because these come from a cloning of an original rule
        $DNAT_rules = [];

        $query = "SELECT id FROM tag WHERE name = 'DNAT' AND source='$source' AND vsys='$vsys' LIMIT 1";
        $tag = $projectdb->query($query);
        if($tag->num_rows>0){
            $data = $tag->fetch_assoc();
            $tag_dnat_id = $data['id'];

            $query ="SELECT rule_lid FROM security_rules_tag WHERE member_lid=$tag_dnat_id";
            $dnat_rules = $projectdb->query($query);
            while ($dnat_rule = $dnat_rules->fetch_assoc()){
                $DNAT_rules[] = $dnat_rule['rule_lid'];
            }
        }

        $getRules=$projectdb->query("SELECT id, description FROM $table_name WHERE source='$source' AND vsys='$vsys' ORDER BY position;");
        if ($getRules->num_rows>0){
            $description = '';
            while($getRulesData=$getRules->fetch_assoc()){
//                if ($getRulesData['description']!=""){
//                    $x++;
//                }
                if (!in_array($getRulesData['id'], $DNAT_rules) && $getRulesData['description']!= ''){
                    $x++;
                 //   $description = $getRulesData['description'];
                }
                $hashArray[$x][]=$getRulesData['id'];
//                $hashArray[$getRulesData['description']]= [
//                    'ids' =>$getRulesData['ids'],
//                    'amount'=> $getRulesData['numb']
//                ];
            }

            $addHash = array();
            if (count($hashArray)>0){
                foreach ($hashArray as $hash => $caseIDs){
                    $filter_hash="Case ".$hash." (".count($caseIDs)." Rules)";
                    $addHash[]= "('".$hash."','".$filter_hash."','$vsys',$source,1,'$table_name','".implode(",",$caseIDs)."')";
                }

                $projectdb->query("TRUNCATE hash_rules;");

                if(count($addHash)>0){
                    $query = "INSERT INTO hash_rules (hash,filter_hash,vsys,source,visible,table_name,rules_lid) VALUES ".implode(",",$addHash).";";
                    $projectdb->query($query);

                    $queryLastHash = "SELECT MAX(id) as startHash FROM hash_rules";
                    $maxHash = $projectdb->query($queryLastHash);
                    $data = $maxHash->fetch_assoc();
                    $finalHash = $data['startHash'];

                    //to be separated from here and send as JOB
                    $params =[
                        'project'   =>$project,
                        'source'    =>$source,
                        'vsys'      =>$vsys,
                        'table_name'=>"security_rules",
                        'selection' =>[],
                        'id_cons'   =>implode(',',range(0,$finalHash))
                    ];
                    //print_r($params);
                    setMergeSecurityRules($project, $params, 'no');
                    $projectdb->query("TRUNCATE hash_rules;");
                }

            }
        }


    }

    return $message;
}