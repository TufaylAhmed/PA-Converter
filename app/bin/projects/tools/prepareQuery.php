<?php
/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: $today.year.hour.minute
 ******************************************************************************/


function prepareVsysQuery(MySQLi $connection, $vsys, $source):string
{
    if ($vsys == "all") {
        $vsys_query = "";
    }
    elseif ($vsys != "all") {
        require_once INC_ROOT . '/libs/common/lib-objects.php';
        $vsyses = getVsyses($connection, $vsys, $source, 'quoted');
        $vsys_query = "AND vsys in (" . implode(",", $vsyses) . ")";
    }

    return $vsys_query;
}

function prepareVsysQueryB(MySQLi $connection, $vsys, $source):string
{
    if ($vsys == "all") {
        $vsys_query = "";
    }
    elseif ($vsys != "all") {
        require_once INC_ROOT . '/libs/common/lib-objects.php';
        $vsyses = getVsyses($connection, $vsys, $source, 'quoted');
        $vsys_query = "AND b.vsys in (" . implode(",", $vsyses) . ")";
    }

    return $vsys_query;
}

function prepareVsysQuerySearch(MySQLi $connection, $vsys, $source, $table):string
{
    if ($vsys == "all") {
        $vsys_query = "";
    }
    elseif ($vsys != "all") {
        require_once INC_ROOT . '/libs/common/lib-objects.php';
        $vsyses = getVsyses($connection, $vsys, $source, 'quoted');
        if($table == "security_rules"){
            $vsys_query = "AND sr.vsys in (" . implode(",", $vsyses) . ")";
        }elseif($table == "nat_rules"){
            $vsys_query = "AND nr.vsys in (" . implode(",", $vsyses) . ")";
        }elseif($table == "appoverride_rules"){
            $vsys_query = "AND ar.vsys in (" . implode(",", $vsyses) . ")";
        }elseif($table == "groups"){
            $vsys_query = "AND agi.vsys in (" . implode(",", $vsyses) . ")";
        }

    }

    return $vsys_query;
}
