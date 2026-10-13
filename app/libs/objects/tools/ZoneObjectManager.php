<?php
/*******************************************************************************
 * Copyright (c) 2018 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: 2/25/19 11:54 AM
 ******************************************************************************/

require_once INC_ROOT.'/libs/objects/Response.php';

require_once INC_ROOT.'/libs/database.php';
require_once INC_ROOT.'/libs/projectdb.php';
require_once INC_ROOT.'/libs/shared.php';

class ZoneObjectManager{

    /***
     * @param String $project
     * @param int $source
     * @param String $vsys
     * @param int $zoneID
     * @param String $table_name
     * @return Response
     */
    public function applyFilter(String $project,  int $source, String $vsys, array $zoneIDs, String $table_name): Response{

        $filterToApply = false;
        foreach ($zoneIDs as $zoneID) {
            $zoneNameQuery = "SELECT name FROM zones WHERE id='$zoneID' AND source='$source' LIMIT 1";
            $zoneNameResult = selectDatabase($project)->query($zoneNameQuery);
            if ($zoneNameResult->num_rows > 0) {
                $filterToApply = true;
            }
            $zoneNameData = $zoneNameResult->fetch_assoc();
            $zoneName = $zoneNameData['name'];

            switch ($table_name) {
                case "global":
                    $paramsDefineFilter = [
                        'project' => $project,
                        'vsys' => $vsys,
                        'source' => $source,
                        'tools_where_columns_id' => 'Name',
                        'tools_operator_id' => 'contains',
                        'search' => "$zoneName",
                        'tools_where_id' => Array(19),
                        'tools_advanced_columns_id' => '',
                        'mode' => 'set_filter',
                        'is_set_sql_filter' => 'yes',
                        'case_sensitive' => ''
                    ];
                    break;
                case "appoverride_rules_from":
                    $paramsDefineFilter = [
                        'project' => $project,
                        'vsys' => $vsys,
                        'source' => $source,
                        'tools_where_columns_id' => 98, //App Override From
                        'tools_operator_id' => 'contains',
                        'search' => "$zoneName",
                        'tools_where_id' => Array(4), //Applicatio Override
                        'tools_advanced_columns_id' => '',
                        'mode' => 'set_filter',
                        'is_set_sql_filter' => 'yes',
                        'case_sensitive' => ''
                    ];
                    break;

                case "appoverride_rules_to":
                    $paramsDefineFilter = [
                        'project' => $project,
                        'vsys' => $vsys,
                        'source' => $source,
                        'tools_where_columns_id' => 100, //App Override To
                        'tools_operator_id' => 'contains',
                        'search' => "$zoneName",
                        'tools_where_id' => Array(4), //Application Override
                        'tools_advanced_columns_id' => '',
                        'mode' => 'set_filter',
                        'is_set_sql_filter' => 'yes',
                        'case_sensitive' => ''
                    ];
                    break;

                case "interfaces":
                    $paramsDefineFilter = [
                        'project' => $project,
                        'vsys' => $vsys,
                        'source' => $source,
                        'tools_where_columns_id' => 51, //Zone field in the Interface
                        'tools_operator_id' => 'contains',
                        'search' => "$zoneName",
                        'tools_where_id' => Array(18), //Interface
                        'tools_advanced_columns_id' => '',
                        'mode' => 'set_filter',
                        'is_set_sql_filter' => 'yes',
                        'case_sensitive' => ''
                    ];
                    break;

                case "nat_rules_from":
                    $paramsDefineFilter = [
                        'project' => $project,
                        'vsys' => $vsys,
                        'source' => $source,
                        'tools_where_columns_id' => 68, //Nat Rules From
                        'tools_operator_id' => 'contains',
                        'search' => "$zoneName",
                        'tools_where_id' => Array(3), //Nat Rules
                        'tools_advanced_columns_id' => '',
                        'mode' => 'set_filter',
                        'is_set_sql_filter' => 'yes',
                        'case_sensitive' => ''
                    ];
                    break;

                case "nat_rules":
                    $paramsDefineFilter = [
                        'project' => $project,
                        'vsys' => $vsys,
                        'source' => $source,
                        'tools_where_columns_id' => 70, //Nat Rules to
                        'tools_operator_id' => 'contains',
                        'search' => "$zoneName",
                        'tools_where_id' => Array(3), //Nat Rules
                        'tools_advanced_columns_id' => '',
                        'mode' => 'set_filter',
                        'is_set_sql_filter' => 'yes',
                        'case_sensitive' => ''
                    ];
                    break;

                case "security_rules_from":
                    $paramsDefineFilter = [
                        'project' => $project,
                        'vsys' => $vsys,
                        'source' => $source,
                        'tools_where_columns_id' => 5, //Security Rules From
                        'tools_operator_id' => 'contains',
                        'search' => "$zoneName",
                        'tools_where_id' => Array(2), //Security Rules
                        'tools_advanced_columns_id' => '',
                        'mode' => 'set_filter',
                        'is_set_sql_filter' => 'yes',
                        'case_sensitive' => ''
                    ];
                    break;

                case "security_rules_to":
                    $paramsDefineFilter = [
                        'project' => $project,
                        'vsys' => $vsys,
                        'source' => $source,
                        'tools_where_columns_id' => 7, //Security Rules To
                        'tools_operator_id' => 'contains',
                        'search' => "$zoneName",
                        'tools_where_id' => Array(2), //Security Rules
                        'tools_advanced_columns_id' => '',
                        'mode' => 'set_filter',
                        'is_set_sql_filter' => 'yes',
                        'case_sensitive' => ''
                    ];
                    break;

                case "authentication_rules_from":
                case "authentication_rules_to":
                case "decryption_rules_from":
                case "decryption_rules_to":
                case "dos_rules_from":
                case "dos_rules_to":
                case "pbf_rules_from":
                case "qos_rules_from":
                case "qos_rules_to":
                case "tunnel_inspect_rules_to":
                case "tunnel_inspect_rules_from":
                    //TODO
                    return new Response(false, -1, new Messages(['Filter option not implemented yet']));

                    break;

                default:
                    return new Response(false, -1, new Messages(['Filter option not found']));
                    break;
            }

            setFilter($project, $paramsDefineFilter);
        }

        if($filterToApply) {
            $paramsExecuteFilter = [
                'project' => $project,
                'source' => $source,
            ];
            executeSQL($project, $paramsExecuteFilter);

            return new Response(true, 1, new Messages(['Filter applied']));
        }
        else {
            return new Response(false, -1, new Messages(['Zone not found']));
        }
    }

    public function forceDelete(String $project,  int $source, String $vsys, array $zoneIDs){
        global $projectdb;
        $projectdb = selectDatabase($project);

        $zoneDeleted = false;
        foreach ($zoneIDs as $zoneID) {
            $getZoneName = $projectdb->query("SELECT name,template,vsys FROM zones WHERE id='$zoneID';");
            if ($getZoneName->num_rows > 0) {
                $getZoneNameData = $getZoneName->fetch_assoc();
                $zoneName = $getZoneNameData['name'];
                $template = $getZoneNameData['template'];
                $vsys = $getZoneNameData['vsys'];

                # Check if another zone exists with the same name keep all the information in interfaces and rules
                $getAnother = $projectdb->query("SELECT id FROM zones WHERE template='$template' AND source='$source' AND name='$zoneName' AND id!='$zoneID';");
                if ($getAnother->num_rows == 0) {
                    #Clean From interfaces
                    $projectdb->query("UPDATE interfaces SET zone='' WHERE template='$template' AND zone='$zoneName' AND source='$source';");

                    #Clean From rules
                    $ids_rules = getIdsBySourceVsys("security_rules", $source, $vsys);
                    $projectdb->query("DELETE FROM security_rules_from WHERE name='$zoneName' AND rule_lid IN (" . implode(',', $ids_rules) . ");");
                    $projectdb->query("DELETE FROM security_rules_to WHERE name='$zoneName' AND rule_lid IN (" . implode(',', $ids_rules) . ");");

                    $ids_rules = getIdsBySourceVsys("nat_rules", $source, $vsys);
                    $projectdb->query("DELETE FROM nat_rules_from WHERE name='$zoneName' AND rule_lid IN (" . implode(',', $ids_rules) . ");");
                    $projectdb->query("UPDATE nat_rules SET op_zone_to='' WHERE source='$source' AND vsys='$vsys' AND op_zone_to='$zoneName';");

                    $ids_rules = getIdsBySourceVsys("appoverride_rules", $source, $vsys);
                    $projectdb->query("DELETE FROM appoverride_rules_from WHERE name='$zoneName' AND rule_lid IN (" . implode(',', $ids_rules) . ");");
                    $projectdb->query("DELETE FROM appoverride_rules_to WHERE name='$zoneName' AND rule_lid IN (" . implode(',', $ids_rules) . ");");

                    $ids_rules = getIdsBySourceVsys("authentication_rules", $source, $vsys);
                    $projectdb->query("DELETE FROM authentication_rules_from WHERE name='$zoneName' AND rule_lid IN (" . implode(',', $ids_rules) . ");");
                    $projectdb->query("DELETE FROM authentication_rules_to WHERE name='$zoneName' AND rule_lid IN (" . implode(',', $ids_rules) . ");");

                    $ids_rules = getIdsBySourceVsys("decryption_rules", $source, $vsys);
                    $projectdb->query("DELETE FROM decryption_rules_from WHERE name='$zoneName' AND rule_lid IN (" . implode(',', $ids_rules) . ");");
                    $projectdb->query("DELETE FROM decryption_rules_to WHERE name='$zoneName' AND rule_lid IN (" . implode(',', $ids_rules) . ");");

                    $ids_rules = getIdsBySourceVsys("dos_rules", $source, $vsys);
                    $projectdb->query("DELETE FROM dos_rules_from WHERE name='$zoneName' AND type = 'zone' AND rule_lid IN (" . implode(',', $ids_rules) . ");");
                    $projectdb->query("DELETE FROM dos_rules_to WHERE name='$zoneName' AND type = 'zone' AND rule_lid IN (" . implode(',', $ids_rules) . ");");

                    $ids_rules = getIdsBySourceVsys("qos_rules", $source, $vsys);
                    $projectdb->query("DELETE FROM qos_rules_from WHERE name='$zoneName' AND rule_lid IN (" . implode(',', $ids_rules) . ");");
                    $projectdb->query("DELETE FROM qos_rules_to WHERE name='$zoneName' AND rule_lid IN (" . implode(',', $ids_rules) . ");");

                    $ids_rules = getIdsBySourceVsys("pbf_rules", $source, $vsys);
                    $projectdb->query("DELETE FROM pbf_rules_from WHERE name='$zoneName' AND type = 'zone' AND rule_lid IN (" . implode(',', $ids_rules) . ");");

                    $ids_rules = getIdsBySourceVsys("tunnel_inspect_rules", $source, $vsys);
                    $projectdb->query("DELETE FROM tunnel_inspect_rules_from WHERE name='$zoneName' AND rule_lid IN (" . implode(',', $ids_rules) . ");");
                    $projectdb->query("DELETE FROM tunnel_inspect_rules_to WHERE name='$zoneName' AND rule_lid IN (" . implode(',', $ids_rules) . ");");

                }
                $projectdb->query("DELETE FROM zones WHERE id = '$zoneID';");
            }
            $zoneDeleted = true;
        }

        if($zoneDeleted){
            return new Response(true, 1, new Messages(['Zone Deleted']));
        }
        else{
            return new Response(true, 1, new Messages(['Zone Not Found']));
        }
    }

}