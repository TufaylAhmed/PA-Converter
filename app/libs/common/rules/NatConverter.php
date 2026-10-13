<?php
# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
function convert_snat_interface_translatedaddress($params){
    $project = $params['project'];
    $message['code']=false;
    $projectdb = selectDatabase($project);
//    if(!accessControl("any", ['projectRole.'.$project.'.view'])){
//        $message = array();
//        $message['code'] = false;
//        $message['msg'] = 'Your account does not have the rights to view this project contents';
//        return $message;
//    }
    $source=$params['source'];
    $vsys=$params['vsys'];

    if (isset($params['tagid'])){
        $tagid=$params['tagid'];
    }

    if (isset($params['ids'])){
        $ruleIds=$params['ids'];
    }
    $data=array();

    # Get NAT Rules with TAGID
    $getNatRulesbyTag=$projectdb->query("SELECT rule_lid FROM nat_rules_tag WHERE source='$source' AND member_lid='$tagid';");
    if($getNatRulesbyTag->num_rows>0){
        while($getNatRulesbyTagData=$getNatRulesbyTag->fetch_assoc()){
            $NatRulesIDS[]=$getNatRulesbyTagData['rule_lid'];
        }

        #getSourceAddress
        $getSourceAddress=$projectdb->query("SELECT rule_lid,member_lid FROM nat_rules_src WHERE table_name='address' AND rule_lid IN (".implode(",",$NatRulesIDS).")");
        if($getSourceAddress->num_rows>0){
            while($getSourceAddressData=$getSourceAddress->fetch_assoc()){
                $rule=$getSourceAddressData['rule_lid'];
                $member_lid=$getSourceAddressData['member_lid'];
                $members[$member_lid][]=$rule;
            }
            $memberLIDS=array();
            foreach($members as $memberlid=>$rulesArray){
                $memberLIDS[]=$member_lid;
            }
            $getAddress=$projectdb->query("SELECT id FROM address WHERE (cidr='32' OR cidr='') AND type='ip-netmask' AND id IN (".implode(",",$memberLIDS).");");
            if($getAddress->num_rows>0){
                $isIPAddressValid=array();
                while($getAddressData=$getAddress->fetch_assoc()){
                    $isIPAddressValid[]=$getAddressData['id'];
                }
            }

            foreach($isIPAddressValid as $ValidIP){
                $NatRules=implode($members[$ValidIP]);
                $projectdb->query("UPDATE nat_rules tp_sat_type='dynamic-ip' WHERE id IN (".$NatRules.")");
            }
        }
    }

}