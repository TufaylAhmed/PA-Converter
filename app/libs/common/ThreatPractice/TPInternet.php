<?php
# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.

function calculate_filter(ARRAY $params){
    $message = array();
    $project = $params['project'];

    if(!accessControl("any", ['projectRole.'.$project.'.update'])){
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to update this project contents';
        return $message;
    }

    if ((isset($params['zones'])) AND (count($params['zones'])>0)){
        $zones=$params['zones'];
        $filter=array();
        $filterSRC=array();
        $filterExclude=array();
        $filterDST=array();

        # INBOUND
        foreach($zones as $zone){
            $filterSRC[]="(zone.src eq ".$zone.")";
        }
        $filter[]="(".implode(" OR ",$filterSRC).")";

        if ((isset($params['exclude'])) AND (count($params['exclude'])>0)){
            $exclude=$params['exclude'];
            foreach($exclude as $ex){
                $filterExclude[]="(addr.src neq ".$ex.")";
            }
            $filter[]="(".implode(" AND ",$filterExclude).")";
        }

        foreach($zones as $zone){
            $filterDST[]="(zone.dst neq ".$zone.")";
        }
        $filter[]="(".implode(" AND ",$filterDST).")";

        $filter="(".implode(" AND ",$filter).")";
        $message['code']=true;
        $message['msg']['inbound']=$filter;

        # INTERNAL
        // (
        //((zone.src neq Untrust) and (zone.src neq Untrust-1) and (zone.dst neq Untrust) and (zone.dst neq Untrust-1))
        //) or (((zone.src eq Untrust) or (zone.src eq Untrust-1)) and ((addr.src eq 10.0.0.0/8) or (addr.src eq 192.168.0.0))) or
        // (((zone.src neq Untrust) and (zone.src neq Untrust-1)) and ((zone.dst eq Untrust) or zone.dst eq Untrust-1)) and ((addr.dst eq 10.0.0.0/8) or addr.dst eq 192.168.0.0/16)))
        $filter=array();
        $filterSRC=array();
        $filterExclude=array();
        $filterDST=array();

        // 1) Zone.src neq InternetZones with ANDs
        foreach($zones as $zone){
            $filterSRC[]="(zone.src neq ".$zone.")";
        }
        $filter[]="(".implode(" AND ",$filterSRC).")";

        // 2) Zone.src eq Internet AND addr.src eq Exluded Networks AND zone.dst NEQ Internet Zones
        $filterSRC=array();
        $filtertmp=array();
        foreach($zones as $zone){
            $filterSRC[]="(zone.src eq ".$zone.")";
        }
        $filtertmp[]="(".implode(" OR ",$filterSRC).")";

        if ((isset($params['exclude'])) AND (count($params['exclude'])>0)){
            $exclude=$params['exclude'];
            foreach($exclude as $ex){
                $filterExclude[]="(addr.src eq ".$ex.")";
            }
            $filtertmp[]="(".implode(" OR ",$filterExclude).")";
        }
        $filterSRC=array();
        foreach($zones as $zone){
            $filterSRC[]="(zone.dst neq ".$zone.")";
        }
        $filtertmp[]="(".implode(" AND ",$filterSRC).")";
        $filter[]="(".implode(" AND ",$filtertmp).")";

        // 3)
        $filtertmp=array();
        $filterExclude=array();
        foreach($zones as $zone){
            $filterDST[]="(zone.src neq ".$zone.")";
        }
        $filtertmp[]="(".implode(" AND ",$filterDST).")";

        foreach($zones as $zone){
            $filterDST[]="(zone.dst eq ".$zone.")";
        }
        $filtertmp[]="(".implode(" OR ",$filterDST).")";

        if ((isset($params['exclude'])) AND (count($params['exclude'])>0)){
            $exclude=$params['exclude'];
            foreach($exclude as $ex){
                $filterExclude[]="(addr.dst eq ".$ex.")";
            }
            $filtertmp[]="(".implode(" OR ",$filterExclude).")";
        }
        $filter[]="(".implode(" AND ",$filtertmp).")";

        $filter="(".implode(" OR ",$filter).")";
        $message['code']=true;
        $message['msg']['internal']=$filter;


        # OUTBOUND
        $filter=array();
        $filterSRC=array();
        $filterExclude=array();
        $filterDST=array();
        foreach($zones as $zone){
            $filterSRC[]="(zone.src neq ".$zone.")";
        }
        $filter[]="(".implode(" AND ",$filterSRC).")";

        if ((isset($params['exclude'])) AND (count($params['exclude'])>0)){
            $exclude=$params['exclude'];
            foreach($exclude as $ex){
                $filterExclude[]="(addr.dst neq ".$ex.")";
            }
            $filter[]="(".implode(" AND ",$filterExclude).")";
        }

        foreach($zones as $zone){
            $filterDST[]="(zone.dst eq ".$zone.")";
        }
        $filter[]="(".implode(" OR ",$filterDST).")";

        $filter="(".implode(" AND ",$filter).")";
        $message['code']=true;
        $message['msg']['outbound']=$filter;



    }
    else{
        $message['code']=false;
        $message['msg']="";
    }


    return $message;

}

function list_zones(ARRAY $params){
    $project = $params['project'];
    $template = $params['template'];
    $projectdb = selectDatabase($project);
    if(!accessControl("any", ['projectRole.'.$project.'.view'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to view this project contents';
        return $message;
    }
    $source=$params['source'];

    $message['code']=false;
    $data=array();
    $getZones=$projectdb->query("SELECT id,name FROM TPInternetZones WHERE source='$source';");
    if ($getZones->num_rows>0){
        while ($getZonesData=$getZones->fetch_object()){
            $data[]=$getZonesData;
        }
        $message['code']=true;
    }
    else{
        # Try to calculate

    }

    $message['count']=count($data);
    $message['msg']=$data;

    return $message;
}

function list_excludedNetworks(ARRAY $params){
    $project = $params['project'];
    $projectdb = selectDatabase($project);
    if(!accessControl("any", ['projectRole.'.$project.'.view'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to view this project contents';
        return $message;
    }
    $source=$params['source'];

    $message['code']=false;
    $data=array();
    $getZones=$projectdb->query("SELECT id,name FROM TPInternetExcludedNetworks WHERE source='$source';");
    if ($getZones->num_rows>0){
        while ($getZonesData=$getZones->fetch_object()){
            $data[]=$getZonesData;
        }
        $message['code']=true;
    }

    $message['count']=count($data);
    $message['msg']=$data;

    return $message;
}

function list_tpReports(ARRAY $params){
    global $pandbRBAC;
    $project=$params['project'];
    $projectdb = selectDatabase($project);
    if(!accessControl("any", ['projectRole.'.$project.'.view'])){
        $message = array();
        $message['code'] = false;
        $message['msg'] = 'Your account does not have the rights to view this project contents';
        return $message;
    }
    $source=$params['source'];

    $message['code']=false;
    $data=array();
    $getReports=$pandbRBAC->query("SELECT * FROM TP_Reports;");
    if ($getReports->num_rows>0){
        while ($getReportsData=$getReports->fetch_assoc()){
            $getReportsData['data']=addslashes($getReportsData['data']);
            $data[]=$getReportsData;
        }
        $message['code']=true;
    }
    $message['count']=count($data);
    $message['msg']=$data;

    return $message;

}