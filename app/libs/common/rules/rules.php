<?php

/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: $today.year.hour.minute
 ******************************************************************************/

//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';
require_once INC_ROOT.'/userManager/start.php';

/***
 * @param mysqli $connection
 * @param array|null $idsToMove
 * @param STRING|null $moveTo
 * @param INT|null $position
 * @param STRING|null $type OPTIONS: security, nat, appOverride
 * @return array
 */
function moveRules(mysqli $connection, STRING $project, STRING $source, STRING $vsys, STRING $type=null, ARRAY $ids=null, STRING $moveTo=null, STRING $ruleReference=null){


    if(is_null($ids) || count($ids)==0){
        $msg = [
            "success"   =>true,
            'msg'       =>'There were no rules to move'
        ];
    }
    elseif(is_null($moveTo) ) {
        $msg = [
            "success"   =>false,
            'msg'       =>'Missing target move'
        ];
    }
    elseif (is_null($type)){
        $msg = [
            "success"   =>false,
            'msg'       =>'Missing type of object to move: Security/Nat/Application Override'
        ];
    }
    else {
        switch($type){
            case "security_rules":
            case "security":
                $table = "security_rules";
                break;
            case "nat_rules":
                $table = "nat_rules";
                break;
            case "appoverride_rules":
                $table = "appoverride_rules";
                break;
            default:
                $msg = [
                    "success"   =>false,
                    'msg'       =>'Missing type of object to move: Security/Nat/Application Override'
                ];
                return $msg;
                break;

        }
        take_snapshot_last($project);

        //Filter the rules that do not belong to the source and vsys and order them by ID
        $query = "SELECT * FROM $table WHERE id in (".implode(',',$ids).") AND source='".$source."' AND vsys='".$vsys."' ORDER BY position";
        $result = $connection->query($query);
        if(!$result->num_rows>0){
            $msg = [
                "success"   =>true,
                'msg'       =>'There were no rules to move'
            ];
        }
        else {
            while($row = $result->fetch_assoc()){
                $idsToMove[] = $row['id'];
            }

            $newPositionValues = array();
            $modifiedRules = array();
            switch($moveTo){
                case "top":
                    //The selected Rules will get the top positions, the rest should be updated to go after
                    $position = 1;
                    foreach ($idsToMove as $id){
                        $newPositionValues[] = "WHEN id='".$id."' THEN '".$position."'";
                        $position++;
                    }

                    $query = "SELECT * FROM $table WHERE id NOT in (".implode(',',$ids).") AND source='".$source."' AND vsys='".$vsys."' ORDER BY position";
                    $result = $connection->query($query);
                    if($result->num_rows>0){
                        while($row = $result->fetch_assoc()){
                            $newPositionValues[] = "WHEN id='".$row['id']."' THEN '".$position."'";
                            $position++;
                        }
                    }

                    if(count($newPositionValues)){
                        $query = "UPDATE $table SET position = CASE ".implode(' ', $newPositionValues)." END where source='".$source."' AND vsys='".$vsys."';";
                        $connection->query($query);

                        $msg = ["success" => true];
                    }
                    break;


                case "bottom":
                    //The selected Rules will get the bottom positions, the rest should be updated to go before
                    $query = "SELECT * FROM $table WHERE id NOT in (".implode(',',$ids).") AND source='".$source."' AND vsys='".$vsys."' ORDER BY position";
                    $position = 1;
                    $result = $connection->query($query);
                    if($result->num_rows>0){
                        while($row = $result->fetch_assoc()){
                            $newPositionValues[] = "WHEN id='".$row['id']."' THEN '".$position."'";
                            $position++;
                        }
                    }
                    foreach ($idsToMove as $id){
                        $newPositionValues[] = "WHEN id='".$id."' THEN '".$position."'";
                        $position++;
                    }

                    if(count($newPositionValues)){
                        $query = "UPDATE $table SET position = CASE ".implode(' ', $newPositionValues)." END where source='".$source."' AND vsys='".$vsys."';";
                        $connection->query($query);

                        $msg = ["success" => true];
                    }
                    break;


                case "before":
                    //Get the needle to divide the rules that are before the reference.
                    $query = "SELECT position FROM $table WHERE id='$ruleReference' AND source='".$source."' AND vsys='".$vsys."'";
                    $result=$connection->query($query);
                    if($result->num_rows!=1){
                        $msg = [
                            "success"   =>false,
                            'msg'       =>'The reference is not valid'
                        ];
                        return $msg;
                    }
                    else{
                        $data = $result->fetch_assoc();
                        $needle = $data['position'];
                    }

                    $position = 1;
                    $query = "SELECT * FROM $table WHERE id NOT in (".implode(',',$ids).") AND source='".$source."' AND vsys='".$vsys."' AND position < '".$needle."' ORDER BY position";
                    $result = $connection->query($query);
                    if($result->num_rows>0){
                        while($row = $result->fetch_assoc()){
                            $newPositionValues[] = "WHEN id='".$row['id']."' THEN '".$position."'";
                            $modifiedRules[] = $row['id'];
                            $position++;
                        }
                    }

                    foreach ($idsToMove as $id){
                        $newPositionValues[] = "WHEN id='".$id."' THEN '".$position."'";
                        $modifiedRules[] = $id;
                        $position++;
                    }

                    $query = "SELECT * FROM $table WHERE id NOT in (".implode(',',$ids).") AND source='".$source."' AND vsys='".$vsys."' AND position >= '".$needle."' ORDER BY position";
                    $result = $connection->query($query);
                    if($result->num_rows>0){
                        while($row = $result->fetch_assoc()){
                            $newPositionValues[] = "WHEN id='".$row['id']."' THEN '".$position."'";
                            $modifiedRules[] = $row['id'];
                            $position++;
                        }
                    }

                    if(count($newPositionValues)){
                        $query = "UPDATE $table SET position = CASE ".implode(' ', $newPositionValues)." END WHERE id in (".implode(',',$modifiedRules).") AND source='".$source."' AND vsys='".$vsys."';";
                        $connection->query($query);

                        $msg = ["success" => true];
                    }
                    break;

                case "after":
                    //Get the needle to divide the rules that are before the reference.
                    $query = "SELECT position FROM $table WHERE id='$ruleReference' AND source='".$source."' AND vsys='".$vsys."'";
                    $result=$connection->query($query);
                    if($result->num_rows!=1){
                        $msg = [
                            "success"   =>false,
                            'msg'       =>'The reference is not valid'
                        ];
                        return $msg;
                    }
                    else{
                        $data = $result->fetch_assoc();
                        $needle = $data['position'];
                    }

                    $position = 1;
                    $query = "SELECT * FROM $table WHERE id NOT in (".implode(',',$ids).") AND source='".$source."' AND vsys='".$vsys."' AND position <= '".$needle."' ORDER BY position";
                    $result = $connection->query($query);
                    if($result->num_rows>0){
                        while($row = $result->fetch_assoc()){
                            $newPositionValues[] = "WHEN id='".$row['id']."' THEN '".$position."'";
                            $modifiedRules[] = $row['id'];
                            $position++;
                        }
                    }

                    foreach ($idsToMove as $id){
                        $newPositionValues[] = "WHEN id='".$id."' THEN '".$position."'";
                        $modifiedRules[] = $id;
                        $position++;
                    }

                    $query = "SELECT * FROM $table WHERE id NOT in (".implode(',',$ids).") AND source='".$source."' AND vsys='".$vsys."' AND position > '".$needle."' ORDER BY position";
                    $result = $connection->query($query);
                    if($result->num_rows>0){
                        while($row = $result->fetch_assoc()){
                            $newPositionValues[] = "WHEN id='".$row['id']."' THEN '".$position."'";
                            $modifiedRules[] = $row['id'];
                            $position++;
                        }
                    }

                    if(count($newPositionValues)){
                        $query = "UPDATE $table SET position = CASE ".implode(' ', $newPositionValues)." END WHERE id in (".implode(',',$modifiedRules).") AND source='".$source."' AND vsys='".$vsys."';";
                        $connection->query($query);

                        $msg = ["success" => true];
                    }
                    break;            }

        }
    }

    return $msg;
}

?>