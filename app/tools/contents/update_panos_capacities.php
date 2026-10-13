<?php
# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.

//Loads all global PHP definitions
# Platform Capacities by PANOS version
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

//User management control
require_once INC_ROOT.'/userManager/start.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';

# Define pandb
require_once INC_ROOT.'/libs/database.php';

# Clean Data Tables
$pandb->query("TRUNCATE TABLE platforms");
$pandb->query("TRUNCATE TABLE panos_capacity");

class Specs {
    private $specifications = array();

    public function __construct(){
        $this->specifications = [];
    }

    private function clean_specs(array $specs):array{
        //id, platform_id, panos, address_max, address_groups_max, members_address_groups_max, services_max, services_groups_max, members_services_groups_max, fqdn_max, security_rulebase_max, nat_rulebase_max, zones_max, virtual_routers_max, base_vsys, vsys_max, forwarding_table_max, security_profiles_max, appoverride_rulebase_max, custom_appid_max, sessions_max, ipsec_tunnels_max
        return [
            'id'                         => $specs['id']                            ?? '',
            'platform_id'                => $specs['platform_id']                   ?? 0,
            'panos'                      => $specs['panos']                         ?? '',
            'address_max'                => $specs['address_max']                   ?? 0,
            'address_groups_max'         => $specs['address_groups_max']            ?? 0,
            'members_address_groups_max' => $specs['members_address_groups_max']    ?? 0,
            'services_max'               => $specs['services_max']                  ?? 0,
            'services_groups_max'        => $specs['services_groups_max']           ?? 0,
            'members_services_groups_max'=> $specs['members_services_groups_max']   ?? 0,
            'fqdn_max'                   => $specs['fqdn_max']                      ?? 0,
            'security_rulebase_max'      => $specs['security_rulebase_max']         ?? 0,
            'nat_rulebase_max'           => $specs['nat_rulebase_max']              ?? 0,
            'zones_max'                  => $specs['zones_max']                     ?? 0,
            'virtual_routers_max'        => $specs['virtual_routers_max']           ?? 0,
            'base_vsys'                  => $specs['base_vsys']                     ?? 0,
            'vsys_max'                   => $specs['vsys_max']                      ?? 0,
            'forwarding_table_max'       => $specs['forwarding_table_max']          ?? 0,
            'security_profiles_max'       => $specs['security_profiles_max']          ?? 0,
            'appoverride_rulebase_max'   => $specs['appoverride_rulebase_max']      ?? 0,
            'custom_appid_max'           => $specs['custom_appid_max']              ?? 0,
            'sessions_max'               => $specs['sessions_max']                  ?? 0,
            'ipsec_tunnels_max'          => $specs['ipsec_tunnels_max']             ?? 0,
        ];
    }

    public function add_specs(array $specs){
        $this->specifications[] = $this->clean_specs($specs);
    }
}


$platform=1;
$platforms[]="('$platform','VM-50','vmseries.png')";
#Panos 8 plat_id address group   member servi   group    panos  member  fqdn   rules    nat    zone 	vr  vsys vsy fwd    profi appove appid  sessio vpn
$specs[]="('',	'$platform',	2500,	125,	2500,	1000,	250,	'8.0',	500,	2000,	250,	400,	15,		3,	1,	1,	2500,	38,	100,	6416,	65536,	250)";

$platform++;
$platforms[]="('$platform','VM-100','vmseries.png')";
$specs[]="('',	'$platform',	10000,	1000,	2500,	2000,	500,	'8.0',	500,	2000,	1500,	3000,	40,		3,	1,	1,	5000,	375,	1000,	6416,	256000,	1000)";

$platform++;
$platforms[]="('$platform','VM-300','vmseries.png')";
$specs[]="('',	'$platform',	10000,	1000,	2500,	2000,	500,	'8.0',	500,	2000,	10000,	5000,	40,		10,	1,	1,	10000,	375,	1000,	6416,	819200,	2000)";

$platform++;
$platforms[]="('$platform','VM-500','vmseries.png')";
$specs[]="('',	'$platform',	20000,	2500,	2500,	2000,	250,	'8.0',	500,	2000,	10000,	8000,	200,	20,	1,	1,	32000,	750,	1000,	6416,	2000002,	4000)";

$platform++;
$platforms[]="('$platform','VM-700','vmseries.png')";
$specs[]="('',	'$platform',	40000,	4000,	2500,	2000,	250,	'8.0',	500,	2000,	20000,	8000,	200,	125,	1,	1,	100000,	750,	2000,	6416,	10485760,	8000)";

$platform++;
$platforms[]="('$platform','PA-200','pa200.png')";
$specs[]="('',	'$platform',	2500,	125,	2500,	1000,	250,	'8.0',	500,	2000,	250,	160,	10,		3,	1,	1,	1000,	38,		100,	6416,	65536,	25)";

$platform++;
$platforms[]="('$platform','PA-220','pa200.png')";
$specs[]="('',	'$platform',	2500,	125,	2500,	1000,	250,	'8.0',	500,	2000,	250,	400,	15,		3,	1,	1,	2500,	38,		100,	6416,	65536,	1000)";

$platform++;
$platforms[]="('$platform','PA-410','pa500.png')";
$specs[]="('',	'$platform',	2500,	125,	2500,	1000,	250,	'8.0',	500,	2000,	1000,	160,	20,		3,	1,	1,	1250,	38,		100,	6416,	65536,	250)";

$platform++;
$platforms[]="('$platform','PA-440','pa500.png')";
$specs[]="('',	'$platform',	2500,	125,	2500,	1000,	250,	'8.0',	500,	2000,	1000,	160,	20,		3,	1,	1,	1250,	38,		100,	6416,	65536,	250)";

$platform++;
$platforms[]="('$platform','PA-450','pa500.png')";
$specs[]="('',	'$platform',	2500,	125,	2500,	1000,	250,	'8.0',	500,	2000,	1000,	160,	20,		3,	1,	1,	1250,	38,		100,	6416,	65536,	250)";

$platform++;
$platforms[]="('$platform','PA-460','pa500.png')";
$specs[]="('',	'$platform',	2500,	125,	2500,	1000,	250,	'8.0',	500,	2000,	1000,	160,	20,		3,	1,	1,	1250,	38,		100,	6416,	65536,	250)";

$platform++;
$platforms[]="('$platform','PA-500','pa500.png')";
$specs[]="('',	'$platform',	2500,	125,	2500,	1000,	250,	'8.0',	500,	2000,	1000,	160,	20,		3,	1,	1,	1250,	38,		100,	6416,	65536,	250)";

$platform++;
$platforms[]="('$platform','PA-820','pa500.png')";
$specs[]="('',	'$platform',	2500,	250,	2500,	1000,	250,	'8.0',	500,	2000,	1500,	3000,	30,		5,	1,	1,	10000,	100,		100,	6416,	131072,	2000)";

$platform++;
$platforms[]="('$platform','PA-850','pa500.png')";
$specs[]="('',	'$platform',	3500,	350,	2500,	1000,	250,	'8.0',	500,	2000,	1500,	3000,	40,		5,	1,	1,	10000,	150,		150,	6416,	196608,	2000)";

$platform++;
$platforms[]="('$platform','PA-3020','pa3000.png')";
$specs[]="('',	'$platform',	5000,	500,	2500,	1000,	250,	'8.0',	500,	2000,	2500,	3000,	40,		10,	1,	6,	5000,	150,		250,	6416,	262144,	1024)";

$platform++;
$platforms[]="('$platform','PA-3050','pa3000.png')";
$specs[]="('',	'$platform',	10000,	1000,	2500,	1000,	250,	'8.0',	500,	2000,	5000,	5000,	40,		10,	1,	6,	20000,	375,		500,	6416,	524288,	2048)";

$platform++;
$platforms[]="('$platform','PA-3060','pa3000.png')";
$specs[]="('',	'$platform',	10000,	1000,	2500,	1000,	250,	'8.0',	500,	2000,	5000,	5000,	40,		10,	1,	6,	20000,	375,		500,	6416,	524288,	2048)";

$platform++;
$platforms[]="('$platform','PA-5020','pa5000.png')";
$specs[]="('',	'$platform',	10000,	1000,	2500,	2000,	250,	'8.0',	500,	2000,	10000,	6000,	80,		10,	1,	6,	20000,	375,		1000,	6416,	1048576,		2048)";

$platform++;
$platforms[]="('$platform','PA-5050','pa5000.png')";
$specs[]="('',	'$platform',	40000,	2500,	2500,	2000,	250,	'8.0',	500,	2000,	20000,	8000,	500,	125,	25,	125,	65536,	750,		2000,	6416,	2000002,	4096)";

$platform++;
$platforms[]="('$platform','PA-5060','pa5000.png')";
$specs[]="('',	'$platform',	80000,	4000,	2500,	4000,	250,	'8.0',	500,	2000,	40000,	16000,	900,	225,	25,	225,	65536,	750,		4000,	6416,	4194304,	8000)";

$platform++;
$platforms[]="('$platform','PA-5220','pa5000.png')";
$specs[]="('',	'$platform',	40000,	4000,	2500,	2000,	250,	'8.0',	500,	2000,	20000,	6000,	80,		20,		10,	20,	200000,	750,		2000,	6416,	4194304,	10000)";

$platform++;
$platforms[]="('$platform','PA-5250','pa5000.png')";
$specs[]="('',	'$platform',	80000,	8000,	2500,	4000,	250,	'8.0',	500,	2000,	40000,	8000,	500,	125,	25,	125,	200000,	750,		4000,	6416,	8388608,	12000)";

$platform++;
$platforms[]="('$platform','PA-5260','pa5000.png')";
$specs[]="('',	'$platform',	80000,	8000,	2500,	4000,	250,	'8.0',	500,	2000,	40000,	16000,	900,	225,	25,	225,	200000,	750,		4000,	6416,	33000000,	15000)";

$platform++;
$platforms[]="('$platform','PA-7050','pa7000.png')";
$specs[]="('',	'$platform',	80000,	8000,	2500,	4000,	250,	'8.0',	500,	2000,	40000,	16000,	900,	225,	25,	225,	65536,	750,		4000,	6416,	24000000,	8000)";

$platform++;
$platforms[]="('$platform','PA-7080','pa7000.png')";
$specs[]="('',	'$platform',	80000,	8000,	2500,	4000,	250,	'8.0',	500,	2000,	40000,	16000,	900,	225,	25,	225,	65536,	750,		4000,	6416,	40000000,	8000)";

$pandb->query("INSERT INTO platforms (id,name,icon) VALUES ".implode(",",$platforms).";");
$pandb->query("INSERT INTO `panos_capacity` VALUES ".implode(",",$specs).";");