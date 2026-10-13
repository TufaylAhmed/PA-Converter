<?php
# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.
function retrieve_output_nodes(INT $nodeID,$ssl_verify_peer=0,$ssl_verify_host=0){

    global $projectdb;

    $getNode=$projectdb->query("SELECT * FROM minemeld WHERE id='$nodeID';");
    if ($getNode->num_rows==1){
        $getNodeData=$getNode->fetch_assoc();

        $urlfull = $getNodeData['url']."/status/minemeld";
        $url= $getNodeData['url'];
        //$hash = base64_encode("admin:minemeld");
        $hash = $getNodeData['hash'];

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_HTTPHEADER, array("Authorization: Basic $hash"));
        curl_setopt($ch, CURLOPT_URL,$urlfull);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER,1);
        curl_setopt($ch, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, $ssl_verify_peer);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, $ssl_verify_host);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        $result = curl_exec($ch);
        curl_close($ch);

        if ($result!=""){
            $json=json_decode($result);
            foreach($json->result as $node){
                if ($node->class=="minemeld.ft.redis.RedisSet"){
                    $inputs=json_encode($node->inputs);
                    $statistics=json_encode($node->statistics);

                    $node_name= $projectdb->real_escape_string($node->name);
                    $node_length = $projectdb->real_escape_string($node->length);


                    $feed[]="('$nodeID','$node_name','$url/feeds/$node_name','$inputs','$node_length','$statistics')";
                }
            }
            if (count($feed)>0){
                $projectdb->query("INSERT INTO minemeld_feeds (node_id,name,feed,inputs,length,statistics) VALUES ".implode(",",$feed).";");
            }
        }
    }
}

