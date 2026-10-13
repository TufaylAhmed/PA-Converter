<?php
/*******************************************************************************
 * Copyright (c) 2018 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: 2/25/19 4:44 PM
 ******************************************************************************/

require_once INC_ROOT.'/libs/objects/tools/usage/locations/Location.php';

class ZoneLocations {

    private $interfaces;
    private $security_rules_from;
    private $security_rules_to;
    private $nat_rules_from;
    private $nat_rules;
    private $appoverride_rules_from;
    private $appoverride_rules_to;
    private $authentication_rules_from;
    private $authentication_rules_to;
    private $decryption_rules_from;
    private $decryption_rules_to;
    private $dos_rules_from;
    private $dos_rules_to;
    private $qos_rules_from;
    private $qos_rules_to;
    private $pbf_rules_from;
    private $tunnel_inspect_rules_from;
    private $tunnel_inspect_rules_to;

    public function getOptions():array{
        return [
            'interfaces',
            'security_rules_from',
            'security_rules_to',
            'nat_rules_from',
            'nat_rules',
            'appoverride_rules_from',
            'appoverride_rules_to',
            'authentication_rules_from',
            'authentication_rules_to',
            'decryption_rules_from',
            'decryption_rules_to',
            'dos_rules_from',
            'dos_rules_to',
            'qos_rules_from',
            'qos_rules_to',
            'pbf_rules_from',
            'tunnel_inspect_rules_from',
            'tunnel_inspect_rules_to',
        ];
    }

    public function __construct()
    {
        $this->interfaces = new Location("Interfaces", "interfaces");
        $this->security_rules_from = new Location("Security Rules: From", "security_rules_from");
        $this->security_rules_to = new Location("Security Rules: To", "security_rules_to");
        $this->nat_rules_from = new Location("Nat Rules: From", "nat_rules_from");
        $this->nat_rules = new Location("Nat Rules: To", "nat_rules");
        $this->appoverride_rules_from = new Location("Application Override Rules: From", "appoverride_rules_from");
        $this->appoverride_rules_to = new Location("Application Override Rules: To", "appoverride_rules_to");
        $this->authentication_rules_from = new Location("Authentication Rules: From", "authentication_rules_from");
        $this->authentication_rules_to = new Location("Authentication Rules: To", "authentication_rules_to");
        $this->decryption_rules_from = new Location("Decryption Rules: From", "decryption_rules_from");
        $this->decryption_rules_to = new Location("Decryption Rules: To", "decryption_rules_to");
        $this->dos_rules_from = new Location("DoS Rules: From", "dos_rules_from");
        $this->dos_rules_to = new Location("DoS Rules: To", "dos_rules_to");
        $this->qos_rules_from = new Location("QoS Rules: From", "qos_rules_from");
        $this->qos_rules_to = new Location("QoS Rules: To", "qos_rules_to");
        $this->pbf_rules_from = new Location("PBF Rules: From", "pbf_rules_from");
        $this->tunnel_inspect_rules_from = new Location("Tunnel Inspect Rules: From", "tunnel_inspect_rules_from");
        $this->tunnel_inspect_rules_to = new Location("Tunnel Inspect Rules: To", "tunnel_inspect_rules_to");
    }

    public function get(String $location):Location{
        return $this->{$location};
    }
}